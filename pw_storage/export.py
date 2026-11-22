"""Выгрузка на доверенную флэшку или внешний диск (Т28, Т29).

Архив zip с AES-256 (pyzipper) собирается в памяти и пишется сразу на носитель: открытых файлов нет ни на ПК,
ни на флэшке. Внутри папка PW_STORAGE: один файл-каталог со всеми записями, частью ключа восстановления и кодами
GitHub (они — обычные записи), и папки проектов с вложениями вроде .jks.

Доверенный носитель — том, который владелец отметил один раз: серийный номер тома и метка в settings.json.
Диск с Windows и диск с программой не годятся никогда. Пароль архива программа не хранит.
"""

from __future__ import annotations

import ctypes
import io
import json
import os
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import pyzipper

from .config import MIN_ARCHIVE_PASSWORD, RECOVERY_ENTRY
from .vault import ExportEntry, Vault, VaultError

ROOT = "PW_STORAGE"
FOLDER = "PW_STORAGE_BACKUP"  # папка на носителе: в корень внешнего диска Windows часто не даёт писать файлы
CATALOG_NAME = "catalog.txt"
SAFE_NAME = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
DRIVE_REMOVABLE, DRIVE_FIXED = 2, 3


class ExportError(VaultError):
    """Текст показывается владельцу в окне, как у ошибок хранилища."""


@dataclass(frozen=True)
class Volume:
    root: str  # «E:\»
    serial: str  # серийный номер тома, 8 шестнадцатеричных знаков
    label: str
    kind: str  # «съёмный» или «диск»

    @property
    def title(self) -> str:
        return f"{self.root} {self.label or 'без метки'} ({self.kind}, том {self.serial})"


def system_roots() -> set[str]:
    """Диск Windows и диск с программой: туда выгрузка не пишется никогда."""
    roots = {Path(__file__).resolve().anchor.upper()}
    roots.add((os.environ.get("SystemDrive", "C:") + "\\").upper())
    return roots


def list_volumes() -> list[Volume]:
    """Подключённые съёмные и внешние диски, кроме системных. Сетевые и оптические не берём."""
    kernel = ctypes.windll.kernel32
    mask = kernel.GetLogicalDrives()
    out = []
    for index in range(26):
        if not mask & (1 << index):
            continue
        root = f"{chr(65 + index)}:\\"
        if root in system_roots():
            continue
        kind = kernel.GetDriveTypeW(root)
        if kind not in (DRIVE_REMOVABLE, DRIVE_FIXED):
            continue
        label = ctypes.create_unicode_buffer(261)
        fs = ctypes.create_unicode_buffer(261)
        serial = ctypes.c_uint32()
        if not kernel.GetVolumeInformationW(root, label, 261, ctypes.byref(serial), None, None, fs, 261):
            continue  # например, кардридер без карты
        out.append(Volume(root, f"{serial.value:08X}", label.value, "съёмный" if kind == DRIVE_REMOVABLE else "диск"))
    return out


# Доверенные носители

def trusted(settings: Path) -> list[dict]:
    try:
        data = json.loads(Path(settings).read_text(encoding="utf-8"))
        items = data.get("trusted_media", []) if isinstance(data, dict) else []
    except (OSError, ValueError):
        return []
    return [item for item in items if isinstance(item, dict) and isinstance(item.get("serial"), str)]


def is_trusted(settings: Path, volume: Volume) -> bool:
    return any(item["serial"] == volume.serial for item in trusted(settings))


def trust(settings: Path, volume: Volume) -> None:
    """Остальные настройки сохраняются."""
    if volume.root.upper() in system_roots():
        raise ExportError("Системный диск нельзя сделать доверенным носителем")
    try:
        data = json.loads(Path(settings).read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            data = {}
    except (OSError, ValueError):
        data = {}
    items = [item for item in trusted(settings) if item["serial"] != volume.serial]
    items.append({"serial": volume.serial, "label": volume.label, "since": datetime.now().strftime("%Y-%m-%d")})
    data["trusted_media"] = items
    Path(settings).parent.mkdir(parents=True, exist_ok=True)
    Path(settings).write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")


# Содержимое

def _safe(name: str) -> str:
    name = SAFE_NAME.sub("_", name).strip(" .")
    if re.fullmatch(r"CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]", name.split(".")[0], re.IGNORECASE):
        name = "_" + name
    return name or "_"


def _safe_group_path(group: str) -> str:
    # / разделяет группы; имя вложения, напротив, всегда остаётся одним безопасным сегментом.
    return "/".join(_safe(segment) for segment in group.split("/"))


def attachment_path(entry: ExportEntry, name: str) -> str:
    return f"{ROOT}/{_safe_group_path(entry.group)}/{_safe(name)}"


TRASH_FOLDER = "_КОРЗИНА"


def trash_attachment_path(entry: ExportEntry, name: str) -> str:
    return f"{ROOT}/{TRASH_FOLDER}/{_safe_group_path(entry.group)}/{_safe(name)}"


def _entry_lines(e: ExportEntry, attachment,
                 attachment_paths: dict[tuple[bool, int, int], str] | None = None,
                 trashed: bool = False) -> list[str]:
    lines = ["", f"[{e.uid}] {e.comment.strip() or '(без комментария)'}",
             f"  Проекты: {', '.join(e.projects) or 'нет'}; ALL: {'да' if e.shared else 'нет'}",
             f"  Сервис: {e.service}", f"  Ключ: {e.key}"]
    value = e.value.splitlines() or [""]
    lines.append(f"  Значение: {value[0]}")
    lines += [f"           {line}" for line in value[1:]]
    # ASCII JSON сохраняет CR/LF, NUL, Unicode-разделители и завершающие переводы строк без потерь.
    lines.append(f"  Значение (JSON): {json.dumps(e.value, ensure_ascii=True)}")
    for index, (name, _) in enumerate(e.attachments):
        path = attachment(e, name) if attachment_paths is None else attachment_paths[trashed, id(e), index]
        lines.append(f"  Вложение: {path}")
    return lines


def catalog_text(entries: list[ExportEntry], recovery_part: str | None, when: datetime, test: bool,
                 trashed: list[ExportEntry] = (),
                 attachment_paths: dict[tuple[bool, int, int], str] | None = None) -> str:
    """Каталог; удалённые, но ещё не стёртые записи — отдельным разделом в конце."""
    text = _catalog_main(entries, recovery_part, when, test, attachment_paths)
    if not trashed:
        return text
    lines = ["", f"=== КОРЗИНА: удалены, но ещё не стёрты ({len(trashed)}) ==="]
    for e in sorted(trashed, key=lambda e: (e.group.lower(), e.service.lower(), e.key.lower())):
        lines += _entry_lines(e, trash_attachment_path, attachment_paths, trashed=True)
        lines.append(f"  Был в проекте: {e.group}")
    return text + "\n".join(lines) + "\n"


def _catalog_main(entries: list[ExportEntry], recovery_part: str | None, when: datetime, test: bool,
                  attachment_paths: dict[tuple[bool, int, int], str] | None = None) -> str:
    lines = [f"PW_STORAGE — выгрузка хранилища от {when:%d.%m.%Y %H:%M}" + (" (ТЕСТ)" if test else ""), ""]
    lines += ["ЧАСТЬ КЛЮЧА ВОССТАНОВЛЕНИЯ ХРАНИЛИЩА",
              recovery_part or "нет в хранилище: выпустите заново (admin reissue), затем выгрузите снова",
              "Для восстановления пароля нужны ещё ответ на контрольный вопрос и файл восстановления recovery.json.",
              "Он лежит на ПК рядом с хранилищем и в архив намеренно не входит: иначе архив и ответ на вопрос",
              "давали бы пароль хранилища. Если ПК утрачен, хранилище создаётся заново по этому каталогу.", ""]
    lines.append(f"ЗАПИСЕЙ: {len(entries)}")
    for group in sorted({e.group for e in entries}, key=str.lower):
        lines += ["", f"=== {group} ==="]
        for e in sorted((e for e in entries if e.group == group), key=lambda e: (e.service.lower(), e.key.lower())):
            lines += _entry_lines(e, attachment_path, attachment_paths)
    return "\n".join(lines) + "\n"


def build_archive(vault: Vault, password: str, when: datetime, test: bool) -> tuple[bytes, int]:
    """Архив целиком в памяти. Возвращает байты и число записей."""
    if len(password) < MIN_ARCHIVE_PASSWORD:
        raise ExportError(f"Пароль архива короче {MIN_ARCHIVE_PASSWORD} знаков")
    entries = vault.export_entries()
    trashed = vault.trashed()
    attachment_paths = {}
    files = []
    used = {f"{ROOT}/{CATALOG_NAME}".casefold()}
    directories = {ROOT.casefold()}
    parents = {}
    sections = ((False, entries, attachment_path), (True, trashed, trash_attachment_path))
    # Резервируем всю иерархию до файлов: вложение не должно занять путь папки или каталога.
    for deleted, rows, path_for in sections:
        for e in rows:
            if not e.attachments:
                continue
            requested = path_for(e, "_").rpartition("/")[0]
            parent = ROOT
            for segment in requested.split("/")[1:]:
                directory = f"{parent}/{segment}"
                number = 2
                while directory.casefold() in used:
                    directory = f"{parent}/{segment} ({number})"
                    number += 1
                directories.add(directory.casefold())
                parent = directory
            parents[deleted, id(e)] = parent
    for deleted, rows, path_for in sections:
        for e in rows:
            for index, (name, data) in enumerate(e.attachments):
                parent = parents[deleted, id(e)]
                filename = _safe(name)
                path = f"{parent}/{filename}"
                stem, dot, ext = filename.rpartition(".")
                number = 2
                while path.casefold() in used or path.casefold() in directories:
                    renamed = f"{stem} ({number}).{ext}" if dot else f"{filename} ({number})"
                    path = f"{parent}/{renamed}"
                    number += 1
                used.add(path.casefold())
                attachment_paths[deleted, id(e), index] = path
                files.append((path, data))
    text = catalog_text(entries, vault.system_value(RECOVERY_ENTRY), when, test, trashed, attachment_paths)
    buffer = io.BytesIO()
    with pyzipper.AESZipFile(buffer, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as z:
        z.setpassword(password.encode("utf-8"))
        z.setencryption(pyzipper.WZ_AES, nbits=256)
        z.writestr(f"{ROOT}/{CATALOG_NAME}", text.encode("utf-8"))
        for path, data in files:
            z.writestr(path, data)
    return buffer.getvalue(), len(entries)


def check_archive(path: Path, password: str) -> list[str]:
    """Открывает записанный архив паролем и читает каждый файл: битый архив не выдаём за готовый."""
    with pyzipper.AESZipFile(path) as z:
        z.setpassword(password.encode("utf-8"))
        names = z.namelist()
        bad = z.testzip()
        if bad is not None:
            raise ExportError(f"Архив не прошёл проверку: {bad}")
        for info in z.infolist():
            if not info.flag_bits & 0x1:
                raise ExportError(f"Файл в архиве не зашифрован: {info.filename}")
    return names


def archive_name(folder: Path, when: datetime) -> Path:
    folder = Path(folder)
    path = folder / f"{ROOT}_{when:%Y-%m-%d}.zip"
    if os.path.lexists(path):
        stem = f"{ROOT}_{when:%Y-%m-%d_%H%M%S}"
        path = folder / f"{stem}.zip"
        number = 2
        while os.path.lexists(path):
            path = folder / f"{stem} ({number}).zip"
            number += 1
    return path


def write_archive(vault: Vault, volume: Volume, settings: Path, password: str, when: datetime | None = None,
                  test: bool = True) -> tuple[Path, int]:
    """Пишет архив в папку PW_STORAGE_BACKUP доверенного носителя: сначала .part, проверка, затем переименование."""
    if volume.root.upper() in system_roots():
        raise ExportError("На системный диск выгрузка не пишется")
    if not is_trusted(settings, volume):
        raise ExportError("Носитель не отмечен как доверенный")
    when = when or datetime.now()
    data, count = build_archive(vault, password, when, test)
    folder = Path(volume.root) / FOLDER
    try:
        folder.mkdir(exist_ok=True)
    except PermissionError:
        raise ExportError(f"Windows не даёт создать папку {folder}: носитель защищён от записи "
                          "или нужны права администратора") from None
    except OSError as e:
        raise ExportError(f"Не удалось создать папку {folder}: носитель недоступен ({type(e).__name__})") from None
    part = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=folder, prefix=f"{ROOT}_", suffix=".part",
                                         delete=False) as stream:
            part = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        check_archive(part, password)
        while True:
            target = archive_name(folder, when)
            try:
                # В Windows rename не затирает цель, появившуюся после выбора имени.
                os.rename(part, target)
                break
            except FileExistsError:
                continue
    except PermissionError:
        raise ExportError(f"Windows не даёт записать файл в {folder}: нет прав на запись") from None
    except OSError as e:
        raise ExportError(f"Запись на носитель не удалась ({type(e).__name__}): возможно, он отключён или "
                          "на нём нет места") from None
    finally:
        if part is not None:
            part.unlink(missing_ok=True)
    return target, count
