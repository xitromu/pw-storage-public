"""Сверка явно выбранных файлов KEY=VALUE; значения не выводятся, запись в хранилище не предусмотрена."""

from __future__ import annotations

import argparse
import csv
import ctypes
import getpass
import io
import msvcrt
import os
import re
import sys
import warnings
from ctypes import wintypes
from dataclasses import dataclass, field, replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pw_storage.config import ALL_SCOPE, PROFILES, SYSTEM_SCOPE
from pw_storage.vault import Vault, _transaction_path, _writer, file_hash

NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*\Z")
PROJECT = re.compile(r"[A-Za-z0-9_-]+\Z")
ROW_ID = re.compile(r"[0-9a-f]{8}\Z")
STATUSES = {
    "inventory": "Найдено в источнике",
    "same": "Совпадает",
    "different": "Различается — выбрать актуальное значение",
    "unmatched": "Нет сопоставления — требуется решение",
    "ambiguous": "Несколько подходящих строк — требуется решение",
    "empty": "Пустое значение источника — требуется решение",
    "source_conflict": "Источники расходятся — требуется решение",
}


class ReviewError(Exception):
    pass


@dataclass(frozen=True)
class Source:
    project: str
    path: Path


@dataclass(frozen=True)
class Snapshot:
    source: Source
    raw: bytes = field(repr=False)
    values: dict[str, str] = field(repr=False)


@dataclass(frozen=True)
class Finding:
    project: str
    source: str
    key: str
    status: str
    row_ids: tuple[str, ...] = ()


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(2, "Некорректные параметры. См. --help; значения и пароль в аргументах не передаются.\n")


def selected_sources(specs: list[str], root: Path) -> list[Source]:
    sources, seen = [], set()
    for spec in specs:
        project, separator, name = spec.partition("=")
        if not separator or not PROJECT.fullmatch(project) or project in (ALL_SCOPE, SYSTEM_SCOPE):
            raise ReviewError("Источник задаётся как ПРОЕКТ=абсолютный_путь.")
        path = Path(name)
        if not path.is_absolute():
            raise ReviewError("Путь источника должен быть абсолютным.")
        path = path.resolve()
        try:
            relative = path.relative_to(root.resolve())
        except ValueError:
            raise ReviewError("Источник находится вне указанного проекта.") from None
        if not relative.parts or relative.parts[0].casefold() != project.casefold():
            raise ReviewError("Источник находится вне указанного проекта.")
        if not path.is_file():
            raise ReviewError("Выбранный источник не является доступным файлом.")
        if path in seen:
            raise ReviewError("Один источник указан несколько раз.")
        seen.add(path)
        sources.append(Source(project, path))
    return sources


def selected_mappings(specs: list[str], sources: list[Source]) -> dict[tuple[str, str], str]:
    mappings = {}
    projects = {source.project for source in sources}
    for spec in specs:
        name, separator, uid = spec.partition("=")
        project, slash, key = name.partition("/")
        if (not separator or not slash or project not in projects or not NAME.fullmatch(key)
                or not ROW_ID.fullmatch(uid)):
            raise ReviewError("Сопоставление задаётся как ПРОЕКТ/ИМЯ=номер_строки.")
        if (project, key) in mappings:
            raise ReviewError("Для одного имени задано несколько сопоставлений.")
        mappings[project, key] = uid
    return mappings


def _opened_path(stream) -> Path:
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    final_path = kernel.GetFinalPathNameByHandleW
    final_path.argtypes = (wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD)
    final_path.restype = wintypes.DWORD
    buffer = ctypes.create_unicode_buffer(32768)
    size = final_path(msvcrt.get_osfhandle(stream.fileno()), buffer, len(buffer), 0)
    if not size or size >= len(buffer):
        raise ReviewError("Не удалось проверить путь открытого источника.")
    name = buffer.value
    if name.startswith("\\\\?\\UNC\\"):
        name = "\\\\" + name[8:]
    elif name.startswith("\\\\?\\"):
        name = name[4:]
    return Path(name)


def _read_selected(path: Path) -> bytes:
    with path.open("rb") as stream:
        if _opened_path(stream) != path:
            raise ReviewError("Путь источника изменился после выбора. Содержимое не прочитано.")
        return stream.read()


def read_source(source: Source) -> Snapshot:
    raw = _read_selected(source.path)
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeError:
        raise ReviewError("Источник должен быть в UTF-8; содержимое ошибки не выводится.") from None
    values = {}
    for number, line in enumerate(text.split("\n"), 1):
        line = line.removesuffix("\r")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        name, separator, value = line.partition("=")
        name = name.strip()
        if not separator or not NAME.fullmatch(name):
            raise ReviewError(f"Неподдерживаемая строка KEY=VALUE, номер {number}; содержимое не выводится.")
        if name in values:
            raise ReviewError(f"Повторное имя в источнике, строка {number}; содержимое не выводится.")
        values[name] = value
    return Snapshot(source, raw, values)


def ensure_sources_unchanged(snapshots: list[Snapshot]) -> None:
    if any(_read_selected(snapshot.source.path) != snapshot.raw for snapshot in snapshots):
        raise ReviewError("Источник изменился во время сверки. Повтори её на актуальных файлах.")


def compare(vault: Vault, snapshots: list[Snapshot], mappings: dict[tuple[str, str], str]) -> list[Finding]:
    rows = vault.rows()
    by_id = {row.uid: row for row in rows}
    present = {(snapshot.source.project, name) for snapshot in snapshots for name in snapshot.values}
    if mappings.keys() - present:
        raise ReviewError("Сопоставление ссылается на имя, которого нет в выбранных источниках.")
    findings, groups = [], {}
    for snapshot in snapshots:
        project = snapshot.source.project
        for name, value in sorted(snapshot.values.items()):
            explicit = mappings.get((project, name))
            if explicit is not None:
                row = by_id.get(explicit)
                if row is None or project not in row.projects:
                    raise ReviewError("Указанная строка не существует или не разрешена выбранному проекту.")
                candidates = [row]
            else:
                candidates = [row for row in rows if row.key == name and project in row.projects]
            ids = tuple(sorted(row.uid for row in candidates))
            if not candidates:
                status = "unmatched"
            elif len(candidates) > 1:
                status = "ambiguous"
            elif not value:
                status = "empty"
            else:
                status = "same" if vault.value(ids[0]) == value else "different"
            index = len(findings)
            findings.append(Finding(project, str(snapshot.source.path), name, status, ids))
            target = ("row", ids[0]) if len(ids) == 1 else ("source", project, name)
            groups.setdefault(target, []).append((index, value))
    for observations in groups.values():
        if any(value != observations[0][1] for _, value in observations[1:]):
            for index, _ in observations:
                findings[index] = replace(findings[index], status="source_conflict")
    with _writer(vault.path):
        ensure_sources_unchanged(snapshots)
        if os.path.lexists(_transaction_path(vault.path)) or file_hash(vault.path) != vault.source_hash:
            raise ReviewError("Хранилище изменилось или имеет незавершённую запись. Сверку нужно повторить.")
    return findings


def render(findings: list[Finding]) -> str:
    output = io.StringIO(newline="")
    writer = csv.writer(output, delimiter=";", lineterminator="\n")
    writer.writerow(("Проект", "Источник", "Имя", "Статус", "Строки хранилища"))
    for item in findings:
        cells = (item.project, item.source, item.key, STATUSES[item.status], ",".join(item.row_ids))
        writer.writerow("'" + value if value.startswith(("=", "+", "-", "@", "\t", "\r")) else value for value in cells)
    return output.getvalue()


def main(argv: list[str] | None = None) -> int:
    parser = Parser(description="Сверка без записи. Формат источников: KEY=VALUE, UTF-8; значение целиком после =, включая пробелы. Кавычки и ${...} не раскрываются.")
    parser.add_argument("mode", choices=("inventory", "compare"), help="inventory: только имена; compare: сравнение с хранилищем")
    parser.add_argument("--profile", choices=tuple(PROFILES), required=True)
    parser.add_argument("--source", action="append", required=True, metavar="ПРОЕКТ=АБСОЛЮТНЫЙ_ПУТЬ")
    parser.add_argument("--map", action="append", default=[], metavar="ПРОЕКТ/ИМЯ=НОМЕР_СТРОКИ")
    parser.add_argument("--report", type=Path, metavar="АБСОЛЮТНЫЙ_ПУТЬ.csv", help="новый CSV только с именами и статусами, без перезаписи")
    args = parser.parse_args(argv)
    try:
        if args.report is not None:
            if not args.report.is_absolute() or args.report.suffix.lower() != ".csv" or not args.report.parent.is_dir():
                raise ReviewError("Отчёт — абсолютный путь нового CSV в существующей папке.")
            if os.path.lexists(args.report):
                raise ReviewError("Файл отчёта уже существует; перезапись запрещена.")
        profile = PROFILES[args.profile]
        sources = selected_sources(args.source, profile.projects_root)
        mappings = selected_mappings(args.map, sources)
        if args.mode == "inventory" and mappings:
            raise ReviewError("Для перечня имён сопоставления не используются.")
        if args.mode == "compare":
            if not sys.stdin.isatty():
                raise ReviewError("Сравнение запускается в видимой консоли; пароль вводится локально и скрыто.")
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                password = getpass.getpass(f"Пароль хранилища {profile.name} (скрытый ввод): ")
            try:
                vault = Vault.open_readonly(profile.vault, password)
            finally:
                password = ""
        snapshots = [read_source(source) for source in sources]
        if args.mode == "inventory":
            findings = [Finding(snapshot.source.project, str(snapshot.source.path), key, "inventory")
                        for snapshot in snapshots for key in sorted(snapshot.values)]
            ensure_sources_unchanged(snapshots)
        else:
            findings = compare(vault, snapshots, mappings)
        report = render(findings)
        if args.report is None:
            print(report, end="")
        else:
            with args.report.open("x", encoding="utf-8-sig", newline="") as stream:
                stream.write(report)
            print(f"Отчёт: {args.report}; строк: {len(findings)}. Источники и хранилище не изменены.")
        return 0
    except ReviewError as error:
        print(f"Сверка остановлена: {error}", file=sys.stderr)
    except KeyboardInterrupt:
        print("Сверка отменена.", file=sys.stderr)
        return 130
    except Exception as error:
        print(f"Сверка не выполнена ({type(error).__name__}); содержимое источников не выводится.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
