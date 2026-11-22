"""Файл хранилища: KDBX 4 с Argon2id поверх pykeepass.

Запись — список проектов, пометка ALL, сервис, имя ключа или логин, значение, комментарий (Т26).
В KDBX: теги = проекты и ALL, название = сервис, пользователь = ключ, пароль = значение, заметки = комментарий.
Группа — только для порядка, доступ определяют теги: владелец правит их прямо в KeePassXC.
Значения из этого модуля не печатаются и не пишутся в журналы.

Только формат 4.0: файл 3.1 после сохранения через pykeepass перестаёт открываться в KeePassXC
(проверено 01.11.2026). Argon2id задаётся через внутренние структуры pykeepass, публичного способа нет,
поэтому версия библиотеки закреплена в requirements.txt.
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import io
import json
import os
import re
import secrets
import struct
import tempfile
import threading
from functools import wraps
from contextlib import contextmanager
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path

from pykeepass import PyKeePass, create_database
from pykeepass.exceptions import CredentialsError
from pykeepass.kdbx_parsing import kdf_uuids

from .config import ALL_SCOPE, SYSTEM_SCOPE

KDBX_SIGNATURE = bytes.fromhex("03d9a29a67fb4bb5")
SUPPORTED_VERSION = (4, 0)
SCOPE_NAME = re.compile(r"^[A-Za-z0-9_-]+$")
MB = 1024 * 1024
ROW_ID_CHARS = 8
TRASH_GROUP_PROPERTY = "PW_STORAGE_GROUP"  # из какой группы запись ушла в корзину


class VaultError(Exception):
    pass


class WrongPassword(VaultError):
    pass


class UnsupportedFormat(VaultError):
    pass


class VaultChanged(VaultError):
    """Файл изменён вне программы после открытия: запись затёрла бы эти изменения."""


class VaultCommitted(VaultError):
    def __init__(self, source_hash: str, reason: str):
        super().__init__(f"Изменения записаны; очистка операции не завершена ({reason}).")
        self.source_hash = source_hash


@dataclass(frozen=True)
class Kdf:
    memory_mb: int = 1024
    iterations: int = 4
    parallelism: int = 4


@dataclass(frozen=True)
class Row:
    uid: str  # непрозрачный номер: по нему сессия просит строку, сервиса и ключа он не раскрывает
    group: str
    service: str
    key: str
    comment: str
    projects: tuple[str, ...] = ()
    shared: bool = False  # ALL: другой проект может запросить запись
    digest: str = ""  # отпечаток значения, только в памяти: в перечень и ответы не попадает

    @property
    def stamp(self) -> tuple[str, str, str, str, str]:
        """Подтверждённое содержимое строки и вложений; список проектов не входит."""
        return self.uid, self.service, self.key, self.comment, self.digest

    def visible_to(self, project: str) -> bool:
        return bool(self.comment.strip()) and (project in self.projects or self.shared)


@dataclass(frozen=True)
class ExportEntry:
    uid: str
    group: str
    service: str
    key: str
    value: str
    comment: str
    projects: tuple[str, ...]
    shared: bool
    attachments: tuple[tuple[str, bytes], ...] = ()

    def __repr__(self) -> str:  # значение не попадает ни в отладочный вывод, ни в трассировку
        return f"ExportEntry({self.uid}, {self.group}/{self.service}/{self.key})"


def row_id(uuid) -> str:
    return hashlib.sha256(uuid.bytes).hexdigest()[:ROW_ID_CHARS]


def parse_tags(tags: list[str]) -> tuple[tuple[str, ...], bool]:
    """Проекты и пометка ALL. KeePassXC разделяет теги запятой или точкой с запятой, лишние пробелы убираем."""
    names = {tag.strip() for tag in tags}
    names = {name for name in names if name and SCOPE_NAME.match(name) and name != SYSTEM_SCOPE}
    return tuple(sorted(names - {ALL_SCOPE})), ALL_SCOPE in names


def file_hash(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _version(data: bytes) -> tuple[int, int]:
    if len(data) < 12 or data[:8] != KDBX_SIGNATURE:
        raise UnsupportedFormat("Это не файл KDBX")
    minor, major = struct.unpack("<HH", data[8:12])
    return major, minor


def file_version(path: Path) -> tuple[int, int]:
    with open(path, "rb") as stream:
        return _version(stream.read(12))


@contextmanager
def _writer(path: Path):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateMutexW.argtypes = (ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR)
    kernel.CreateMutexW.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.ReleaseMutex.argtypes = (wintypes.HANDLE,)
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    identity = hashlib.sha256(str(path.resolve()).casefold().encode("utf-8")).hexdigest()
    handle = kernel.CreateMutexW(None, False, "Global\\PW_STORAGE_WRITE_" + identity)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    acquired = False
    try:
        state = kernel.WaitForSingleObject(handle, 10000)
        if state not in (0, 0x80):
            raise VaultError("Хранилище занято другой операцией")
        acquired = True
        yield
    finally:
        if acquired:
            kernel.ReleaseMutex(handle)
        kernel.CloseHandle(handle)


def _atomic_bytes(path: Path, data: bytes) -> None:
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".pw_storage_", suffix=".part", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _hash_or_none(path: Path) -> str | None:
    try:
        return file_hash(path)
    except FileNotFoundError:
        return None


def _transaction_path(path: Path) -> Path:
    return path.with_name(path.name + ".transaction")


def _install_item(folder: Path, item: dict) -> None:
    target, stage, claim = (folder / item[name] for name in ("target", "stage", "claim"))
    if _hash_or_none(target) == item["after"]:
        return
    data = base64.b64decode(item["data"], validate=True)
    if hashlib.sha256(data).hexdigest() != item["after"]:
        raise VaultError("Повреждён зашифрованный снимок операции")
    if not stage.exists():
        _atomic_bytes(stage, data)
    elif file_hash(stage) != item["after"]:
        raise VaultError("Повреждён временный файл операции")
    if item["before"] is not None:
        if not claim.exists():
            try:
                os.rename(target, claim)
            except FileNotFoundError:
                raise VaultChanged("Рабочий файл удалён во время сохранения") from None
        if file_hash(claim) != item["before"]:
            try:
                os.rename(claim, target)
            except FileExistsError:
                pass
            raise VaultChanged("Файл изменился во время сохранения; внешняя версия сохранена")
    try:
        # Windows rename устанавливает новую версию только в свободное имя.
        os.rename(stage, target)
    except FileExistsError:
        raise VaultChanged("Во время сохранения появилась другая версия; файлы сохранены для разбора") from None


def _resume_transaction(path: Path) -> None:
    journal = _transaction_path(path)
    if not journal.exists():
        return
    try:
        operation = json.loads(journal.read_bytes())
        items = operation["items"]
        if (operation["format"] != "PWT1" or not isinstance(items, list) or len(items) not in (1, 2)
                or type(operation["backup"]) is not bool or not isinstance(operation["retire"], list)):
            raise ValueError
        token = re.fullmatch(r"\.pw_storage_([0-9a-f]{24})_0\.stage", items[0]["stage"])
        if token is None:
            raise ValueError
        for index, item in enumerate(items):
            if (item["target"] != (path.name if index == 0 else "recovery.json")
                    or item["stage"] != f".pw_storage_{token[1]}_{index}.stage"
                    or item["claim"] != f".pw_storage_{token[1]}_{index}.claim"
                    or (item["before"] is not None and not re.fullmatch(r"[0-9a-f]{64}", item["before"]))
                    or not re.fullmatch(r"[0-9a-f]{64}", item["after"])):
                raise ValueError
            raw = base64.b64decode(item["data"], validate=True)
            if hashlib.sha256(raw).hexdigest() != item["after"]:
                raise ValueError
        allowed_retire = {path.name + ".bak", "remote.bin"}
        if (any(name not in allowed_retire for name in operation["retire"])
                or len(set(operation["retire"])) != len(operation["retire"])):
            raise ValueError
        for item in items:
            _install_item(path.parent, item)
        for item in items:
            claim = path.parent / item["claim"]
            if (_hash_or_none(path.parent / item["target"]) != item["after"]
                    or (claim.exists() and file_hash(claim) != item["before"])):
                raise VaultChanged("Файлы операции изменены; версии сохранены для разбора")
        try:
            if operation["backup"] and items[0]["before"] is not None:
                claim = path.parent / items[0]["claim"]
                if claim.exists():
                    _atomic_bytes(path.with_name(path.name + ".bak"), claim.read_bytes())
            for name in operation["retire"]:
                (path.parent / name).unlink(missing_ok=True)
            for item in items:
                for field in ("stage", "claim"):
                    (path.parent / item[field]).unlink(missing_ok=True)
            journal.unlink()
        except OSError as error:
            raise VaultCommitted(items[0]["after"], type(error).__name__) from None
    except (KeyError, TypeError, ValueError):
        raise VaultError("Повреждён файл незавершённой операции хранилища") from None


def _commit(path: Path, data: bytes, expected: str | None, recovery_path: Path | None = None,
            recovery_blob: bytes | None = None, recovery_hash: str | None = None,
            retire: tuple[Path, ...] = (), backup: bool = True) -> None:
    with _writer(path):
        _resume_transaction(path)
        targets = [(path, data, expected)]
        if recovery_path is not None:
            if recovery_path != path.parent / "recovery.json" or recovery_blob is None:
                raise VaultError("Файл восстановления должен называться recovery.json и быть рядом с хранилищем")
            targets.append((recovery_path, recovery_blob, recovery_hash))
        if any(target not in (path.with_name(path.name + ".bak"), path.parent / "remote.bin") for target in retire):
            raise VaultError("Операция может убрать только старый снимок и файл дистанционного кода")
        for target, _, before in targets:
            if _hash_or_none(target) != before:
                raise VaultChanged("Файл изменён вне программы. Откройте хранилище заново.")
        token = secrets.token_hex(12)
        items = [{"target": target.name, "before": before,
                  "after": hashlib.sha256(raw).hexdigest(), "data": base64.b64encode(raw).decode("ascii"),
                  "stage": f".pw_storage_{token}_{index}.stage", "claim": f".pw_storage_{token}_{index}.claim"}
                 for index, (target, raw, before) in enumerate(targets)]
        operation = {"format": "PWT1", "items": items, "retire": [p.name for p in retire], "backup": backup}
        _atomic_bytes(_transaction_path(path), json.dumps(operation).encode("utf-8"))
        _resume_transaction(path)


def _apply_kdf(kp: PyKeePass, kdf: Kdf) -> None:
    params = kp.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
    params["$UUID"].value = kdf_uuids["argon2id"]
    params["M"].value = kdf.memory_mb * MB
    params["I"].value = kdf.iterations
    params["P"].value = kdf.parallelism


def _synchronized(method):
    @wraps(method)
    def locked(self, *args, **kwargs):
        with self._model_lock:
            return method(self, *args, **kwargs)
    return locked


class Vault:
    def __init__(self, path: Path, kp: PyKeePass, source_hash: str | None, *, read_only: bool = False):
        self.path = Path(path)
        self._kp = kp
        self._hash = source_hash
        self._read_only = read_only
        self._model_lock = threading.RLock()

    @property
    def source_hash(self) -> str | None:
        return self._hash

    @property
    def read_only(self) -> bool:
        return self._read_only

    @classmethod
    def new(cls, path: Path, password: str, kdf: Kdf = Kdf()) -> "Vault":
        kp = create_database(io.BytesIO(), password=password)
        _apply_kdf(kp, kdf)
        return cls(Path(path), kp, None)

    @classmethod
    def create(cls, path: Path, password: str, kdf: Kdf = Kdf()) -> "Vault":
        path = Path(path)
        if path.exists():
            raise VaultError(f"Файл уже существует, перезапись запрещена: {path.name}")
        vault = cls.new(path, password, kdf)
        vault.save()
        return vault

    @classmethod
    def resume(cls, path: Path) -> None:
        path = Path(path)
        with _writer(path):
            _resume_transaction(path)

    @classmethod
    def open(cls, path: Path, password: str) -> "Vault":
        path = Path(path)
        with _writer(path):
            _resume_transaction(path)
            data = path.read_bytes()
        version = _version(data)
        if version != SUPPORTED_VERSION:
            raise UnsupportedFormat(f"Поддерживается только KDBX 4.0, у файла {version[0]}.{version[1]}")
        try:
            return cls(path, PyKeePass(io.BytesIO(data), password=password), hashlib.sha256(data).hexdigest())
        except CredentialsError:
            raise WrongPassword("Неверный пароль") from None

    @classmethod
    def open_readonly(cls, path: Path, password: str) -> "Vault":
        path = Path(path)
        with _writer(path):
            try:
                _transaction_path(path).lstat()
            except FileNotFoundError:
                pass
            else:
                raise VaultError("Есть незавершённая операция хранилища; чтение без восстановления запрещено")
            data = path.read_bytes()
        version = _version(data)
        if version != SUPPORTED_VERSION:
            raise UnsupportedFormat(f"Поддерживается только KDBX 4.0, у файла {version[0]}.{version[1]}")
        try:
            return cls(path, PyKeePass(io.BytesIO(data), password=password), hashlib.sha256(data).hexdigest(),
                       read_only=True)
        except CredentialsError:
            raise WrongPassword("Неверный пароль") from None

    @_synchronized
    def clone(self) -> "Vault":
        buffer = io.BytesIO()
        transformed_key = self._kp.transformed_key
        self._kp.save(buffer, transformed_key=transformed_key)
        kp = PyKeePass(io.BytesIO(buffer.getvalue()), password=self._kp.password, transformed_key=transformed_key)
        return type(self)(self.path, kp, self._hash, read_only=self._read_only)

    @property
    def kdf_algorithm(self) -> str:
        return self._kp.kdf_algorithm

    def _scopes(self) -> list:
        """Все обычные группы, включая корень; служебные поддеревья целиком пропускаются."""
        recycle = self._trash_group()
        out = []
        pending = [self._kp.root_group]
        while pending:
            group = pending.pop()
            if group.name == SYSTEM_SCOPE or (recycle is not None and group.uuid == recycle.uuid):
                continue
            out.append(group)
            pending.extend(reversed(group.subgroups))
        return out

    def _group_path(self, group, root=None) -> str:
        """Путь без имени корня: плоские метки прежние, вложенные — через /; сам корень имеет метку."""
        root = self._kp.root_group if root is None else root
        names = []
        while group is not None and group.uuid != root.uuid:
            names.append(group.name or "_")
            group = group.parentgroup
        return "/".join(reversed(names)) or root.name or "(корень)"

    def _group(self, scope: str, create: bool = False):
        for group in self._kp.root_group.subgroups:
            if group.name == scope:
                return group
        return self._kp.add_group(self._kp.root_group, scope) if create else None

    def _entry(self, scope: str, service: str, key: str):
        group = self._group(scope)
        if group is None:
            return None
        for entry in group.entries:
            if (entry.title or "") == service and (entry.username or "") == key:
                return entry
        return None

    def _entries(self):
        for group in self._scopes():
            for entry in group.entries:
                yield group, entry

    def rows(self) -> list[Row]:
        """Все записи без значений и без служебных строк. Строки без комментария тоже здесь: их считает перечень."""
        out = []
        for group, entry in self._entries():
            projects, shared = parse_tags(entry.tags)
            value = entry.password or ""
            digest = hashlib.sha256(value.encode("utf-8")).hexdigest() if value else ""
            attachments = sorted((a.filename, hashlib.sha256(a.data).hexdigest()) for a in entry.attachments)
            if attachments:
                digest = hashlib.sha256(json.dumps((value, attachments), ensure_ascii=True).encode("ascii")).hexdigest()
            out.append(Row(row_id(entry.uuid), self._group_path(group), entry.title or "", entry.username or "", entry.notes or "",
                           projects, shared, digest))
        if len({row.uid for row in out}) != len(out):
            raise VaultError("Совпали номера строк: нужен более длинный номер")  # при 8 знаках почти невозможно
        return out

    def _entry_by_uid(self, uid: str):
        for _, entry in self._entries():
            if row_id(entry.uuid) == uid:
                return entry
        return None

    def value(self, uid: str) -> str | None:
        entry = self._entry_by_uid(uid)
        return None if entry is None else entry.password

    @_synchronized
    def put(self, group: str, service: str, key: str, value: str, comment: str,
            projects: tuple[str, ...] | None = None, shared: bool = False) -> None:
        """Добавляет или заменяет запись группы; без списка проектов запись доступна проекту-группе. На диск — после save()."""
        projects = (group,) if projects is None else tuple(projects)
        for name in (group, *projects):
            if not SCOPE_NAME.match(name) or name in (SYSTEM_SCOPE, ALL_SCOPE):
                raise VaultError(f"Недопустимое имя проекта: {name}")
        if not projects:
            raise VaultError("Нужен хотя бы один проект")
        if not service or not key:
            raise VaultError("Нужны сервис и имя ключа")
        if not comment or not comment.strip():
            raise VaultError("Комментарий обязателен")  # Т22
        if not value:
            raise VaultError("Пустое значение")
        entry = self._entry(group, service, key)
        if entry is None:
            # add_entry подставляет название и логин в XPath: кавычка в имени его ломает.
            # Дубликат уже проверен выше, поэтому создаём под случайным именем и задаём настоящее.
            entry = self._kp.add_entry(self._group(group, create=True), secrets.token_hex(8), "", value, notes=comment)
            entry.title = service
            entry.username = key
        else:
            entry.password = value
            entry.notes = comment
        entry.tags = sorted(set(projects)) + ([ALL_SCOPE] if shared else [])

    @_synchronized
    def rename_key(self, uid: str, key: str) -> None:
        """Новое имя ключа в существующей строке: номер строки и комментарий не меняются. На диск — после save()."""
        entry = self._entry_by_uid(uid)
        if entry is None:
            raise VaultError("Нет такой записи")
        if not key:
            raise VaultError("Нужно имя ключа")
        siblings = entry.group.entries if entry.group is not None else ()
        for other in siblings:
            if (other is not entry and (other.title or "") == (entry.title or "")
                    and (other.username or "") == key):
                raise VaultError("Такое имя уже есть у этого сервиса")
        entry.username = key

    @_synchronized
    def add_project(self, uid: str, project: str) -> bool:
        """Т26: одобренная строка из ALL получает проект в список. True — список изменился. На диск — после save()."""
        if not SCOPE_NAME.match(project) or project in (SYSTEM_SCOPE, ALL_SCOPE):
            raise VaultError(f"Недопустимое имя проекта: {project}")
        entry = self._entry_by_uid(uid)
        if entry is None:
            raise VaultError("Нет такой записи")
        projects, shared = parse_tags(entry.tags)
        if project in projects:
            return False
        entry.tags = sorted({*projects, project}) + ([ALL_SCOPE] if shared else [])
        return True

    def export_entries(self) -> list["ExportEntry"]:
        """Для выгрузки на флэшку (Т28): записи со значениями и вложениями, без служебных. Только в память."""
        out = []
        for group, entry in self._entries():
            projects, shared = parse_tags(entry.tags)
            out.append(ExportEntry(row_id(entry.uuid), self._group_path(group), entry.title or "", entry.username or "",
                                   entry.password or "", entry.notes or "", projects, shared,
                                   tuple((a.filename, a.data) for a in entry.attachments)))
        return out

    @_synchronized
    def update_entry(self, uid: str, comment: str | None = None, value: str | None = None) -> None:
        """Окно записи: новый комментарий и/или значение. Отпечаток строки меняется — выданный доступ к ней
        без нового подтверждения не действует (Т23). На диск — после save()."""
        entry = self._entry_by_uid(uid)
        if entry is None:
            raise VaultError("Нет такой записи")
        if comment is not None:
            if not comment.strip():
                raise VaultError("Комментарий обязателен")  # Т22
            entry.notes = comment.strip()
        if value is not None:
            if not value:
                raise VaultError("Пустое значение")
            entry.password = value

    @_synchronized
    def trash(self, uid: str) -> None:
        """В корзину файла: из перечня и выдачи пропадает, в выгрузку на флэшку ещё входит. На диск — после save()."""
        entry = self._entry_by_uid(uid)
        if entry is None:
            raise VaultError("Нет такой записи")
        group = self._group_path(entry.group) if entry.group is not None else ""
        entry.set_custom_property(TRASH_GROUP_PROPERTY, group)
        self._kp.trash_entry(entry)

    def _trash_group(self):
        try:
            return self._kp.recyclebin_group
        except (TypeError, ValueError, AttributeError):  # в новом файле корзины ещё нет
            return None

    def trashed(self) -> list["ExportEntry"]:
        recycle = self._trash_group()
        if recycle is None:
            return []
        out = []
        pending = [recycle]
        while pending:
            group = pending.pop()
            if group.name == SYSTEM_SCOPE:
                continue
            pending.extend(reversed(group.subgroups))
            for entry in group.entries:
                projects, shared = parse_tags(entry.tags)
                origin = entry.get_custom_property(TRASH_GROUP_PROPERTY) or (
                    self._group_path(group, recycle) if group.uuid != recycle.uuid else "?")
                if SYSTEM_SCOPE in origin.split("/"):
                    continue
                out.append(ExportEntry(row_id(entry.uuid), origin, entry.title or "", entry.username or "",
                                       entry.password or "", entry.notes or "", projects, shared,
                                       tuple((a.filename, a.data) for a in entry.attachments)))
        return out

    @_synchronized
    def empty_trash(self) -> int:
        """Окончательное удаление. Число стёртых записей. На диск — после save()."""
        group = self._trash_group()
        if group is None:
            return 0
        count = 0
        pending = [group]
        while pending:
            current = pending.pop()
            count += len(current.entries)
            pending.extend(current.subgroups)
        self._kp.empty_group(group)
        return count

    @_synchronized
    def set_tags(self, uid: str, projects, shared: bool) -> None:
        """Окно администрирования: новый список проектов и ALL. Пустой список допустим: запись только в выгрузке.
        Отпечаток строки (Т23) не меняется: список проектов в него не входит. На диск — после save()."""
        projects = tuple(sorted(set(projects)))
        for name in projects:
            if not SCOPE_NAME.match(name) or name in (SYSTEM_SCOPE, ALL_SCOPE):
                raise VaultError(f"Недопустимое имя проекта: {name}")
        entry = self._entry_by_uid(uid)
        if entry is None:
            raise VaultError("Нет такой записи")
        entry.tags = list(projects) + ([ALL_SCOPE] if shared else [])

    @_synchronized
    def attach(self, group: str, service: str, key: str, name: str, data: bytes) -> None:
        """Вложение к существующей записи (Т19, копии .jks); одноимённое заменяется. На диск — после save()."""
        entry = self._entry(group, service, key)
        if entry is None or group == SYSTEM_SCOPE:
            raise VaultError("Нет такой записи")
        for attachment in entry.attachments:
            if attachment.filename == name:
                entry.delete_attachment(attachment)
        entry.add_attachment(self._kp.add_binary(data), name)

    def attachment(self, group: str, service: str, key: str, name: str) -> bytes | None:
        entry = self._entry(group, service, key)
        if entry is None or group == SYSTEM_SCOPE:
            return None
        for attachment in entry.attachments:
            if attachment.filename == name:
                return attachment.data
        return None

    def attachment_by_uid(self, uid: str, name: str) -> bytes | None:
        entry = self._entry_by_uid(uid)
        if entry is None:
            return None
        found = [a for a in entry.attachments if a.filename == name]
        if len(found) > 1:
            raise VaultError("Несколько вложений с таким именем")
        return found[0].data if found else None

    def system_value(self, name: str) -> str | None:
        entry = self._entry(SYSTEM_SCOPE, name, "")
        return None if entry is None else entry.password

    @_synchronized
    def set_system_value(self, name: str, value: str) -> None:
        entry = self._entry(SYSTEM_SCOPE, name, "")
        if entry is None:
            group = self._group(SYSTEM_SCOPE, create=True)
            self._kp.add_entry(group, name, "", value, notes="Служебная запись PW_STORAGE")
        else:
            entry.password = value

    @_synchronized
    def change_password(self, new_password: str) -> None:
        """На диске новый пароль начнёт действовать после save(). Файл восстановления нужно выпустить заново."""
        if not new_password:
            raise VaultError("Пустой пароль")
        self._kp.password = new_password

    @_synchronized
    def save(self, *, recovery_path: Path | None = None, recovery_blob: bytes | None = None,
             recovery_hash: str | None = None, retire: tuple[Path, ...] = (), backup: bool = True) -> None:
        if self._read_only:
            raise VaultError("Хранилище открыто только для чтения; сохранение запрещено")
        expected = self._hash
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with _writer(self.path):
            _resume_transaction(self.path)
            if _hash_or_none(self.path) != expected:
                raise VaultChanged("Файл хранилища изменён вне программы. Откройте его заново.")
        buffer = io.BytesIO()
        self._kp.save(buffer)
        data = buffer.getvalue()
        check = PyKeePass(io.BytesIO(data), password=self._kp.password)
        if check.version != SUPPORTED_VERSION or check.kdf_algorithm != self._kp.kdf_algorithm:
            raise VaultError("Записанный файл не прошёл проверку формата")
        if len(check.entries) != len(self._kp.entries):
            raise VaultError("Записанный файл не прошёл проверку числа записей")
        digest = hashlib.sha256(data).hexdigest()
        try:
            _commit(self.path, data, expected, recovery_path, recovery_blob, recovery_hash, retire, backup)
        except VaultCommitted as error:
            if error.source_hash == digest:
                self._kp = check
                self._hash = digest
            raise
        self._kp = check
        self._hash = digest
