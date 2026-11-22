"""Кто обратился к посреднику: определяем по процессу на другом конце канала, а не со слов скрипта.

Проект — первая папка под корнем проектов: сначала по пути запущенного скрипта, затем по рабочей папке.
Сессия — диагностический идентификатор ближайшего предка claude.exe из claude-code, иначе «manual».
Доступ общий для проекта; сессия и время жизни её процесса не определяют разрешения.
Это защита от ошибки, а не от намеренного обхода: процесс той же учётной записи может притвориться другим.
"""

from __future__ import annotations

import ctypes
from ctypes import POINTER, byref, wintypes
from dataclasses import dataclass
from pathlib import Path

from .config import TOOL_PATHS

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010

# Смещения в структурах 64-битного процесса.
PEB_PROCESS_PARAMETERS = 0x20
PARAMS_CURRENT_DIRECTORY = 0x38
PARAMS_COMMAND_LINE = 0x70

MANUAL_SESSION = "manual"
MAX_ANCESTORS = 64

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_ntdll = ctypes.WinDLL("ntdll")
_shell32 = ctypes.WinDLL("shell32", use_last_error=True)

_kernel32.OpenProcess.restype = wintypes.HANDLE
_kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
_kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
_kernel32.ReadProcessMemory.argtypes = (wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID, ctypes.c_size_t, POINTER(ctypes.c_size_t))
_kernel32.QueryFullProcessImageNameW.argtypes = (wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, POINTER(wintypes.DWORD))
_kernel32.GetProcessTimes.argtypes = (wintypes.HANDLE,) + (POINTER(wintypes.FILETIME),) * 4
_kernel32.GetNamedPipeClientProcessId.argtypes = (wintypes.HANDLE, POINTER(wintypes.ULONG))
_kernel32.LocalFree.argtypes = (wintypes.HLOCAL,)
_ntdll.NtQueryInformationProcess.restype = ctypes.c_long
_ntdll.NtQueryInformationProcess.argtypes = (wintypes.HANDLE, wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG, POINTER(wintypes.ULONG))
_shell32.CommandLineToArgvW.restype = POINTER(wintypes.LPWSTR)
_shell32.CommandLineToArgvW.argtypes = (wintypes.LPCWSTR, POINTER(ctypes.c_int))


class _BasicInfo(ctypes.Structure):
    _fields_ = [
        ("ExitStatus", ctypes.c_void_p),
        ("PebBaseAddress", ctypes.c_void_p),
        ("AffinityMask", ctypes.c_size_t),
        ("BasePriority", ctypes.c_void_p),
        ("UniqueProcessId", ctypes.c_size_t),
        ("InheritedFromUniqueProcessId", ctypes.c_size_t),
    ]


@dataclass(frozen=True)
class ClientInfo:
    pid: int
    cwd: Path | None
    script: Path | None


def pipe_client_pid(handle: int) -> int:
    pid = wintypes.ULONG()
    if not _kernel32.GetNamedPipeClientProcessId(handle, byref(pid)):
        raise ctypes.WinError(ctypes.get_last_error())
    return pid.value


def _open(pid: int, access: int) -> int:
    handle = _kernel32.OpenProcess(access, False, pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    return handle


def _basic(handle: int) -> _BasicInfo:
    info = _BasicInfo()
    status = _ntdll.NtQueryInformationProcess(handle, 0, byref(info), ctypes.sizeof(info), None)
    if status != 0:
        raise OSError(f"NtQueryInformationProcess: 0x{status & 0xFFFFFFFF:08X}")
    return info


def _read(handle: int, address: int, size: int) -> bytes:
    buffer = ctypes.create_string_buffer(size)
    done = ctypes.c_size_t()
    if not _kernel32.ReadProcessMemory(handle, address, buffer, size, byref(done)):
        raise ctypes.WinError(ctypes.get_last_error())
    return buffer.raw[:done.value]


def _read_pointer(handle: int, address: int) -> int:
    return int.from_bytes(_read(handle, address, 8), "little")


def _read_unicode_string(handle: int, address: int) -> str:
    raw = _read(handle, address, 16)
    length = int.from_bytes(raw[:2], "little")
    buffer = int.from_bytes(raw[8:16], "little")
    return _read(handle, buffer, length).decode("utf-16-le") if length else ""


def split_command_line(command_line: str) -> list[str]:
    count = ctypes.c_int()
    argv = _shell32.CommandLineToArgvW(command_line, byref(count))
    if not argv:
        return []
    try:
        return [argv[i] for i in range(count.value)]
    finally:
        _kernel32.LocalFree(argv)


def script_from_args(argv: list[str], cwd: Path | None) -> Path | None:
    """Путь скрипта из командной строки Python. Для -c и -m скрипта нет."""
    if not argv or "python" not in Path(argv[0]).name.lower():
        return None
    args = iter(argv[1:])
    for arg in args:
        if arg in ("-c", "-m"):
            return None
        if arg in ("-X", "-W"):
            next(args, None)
            continue
        if arg.startswith("-"):
            continue
        path = Path(arg)
        if not path.is_absolute() and cwd is not None:
            path = cwd / path
        return path
    return None


def inspect(pid: int) -> ClientInfo:
    handle = _open(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)
    try:
        params = _read_pointer(handle, _basic(handle).PebBaseAddress + PEB_PROCESS_PARAMETERS)
        cwd_text = _read_unicode_string(handle, params + PARAMS_CURRENT_DIRECTORY)
        command_line = _read_unicode_string(handle, params + PARAMS_COMMAND_LINE)
    finally:
        _kernel32.CloseHandle(handle)
    cwd = Path(cwd_text) if cwd_text else None
    return ClientInfo(pid, cwd, script_from_args(split_command_line(command_line), cwd))


def _is_under(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except (ValueError, OSError):
        return False


def _top_folder(path: Path, root: Path) -> str | None:
    try:
        parts = path.resolve().relative_to(root.resolve()).parts
    except (ValueError, OSError):
        return None
    return parts[0] if parts else None


def resolve_project(info: ClientInfo, root: Path, tool_paths=TOOL_PATHS) -> str | None:
    candidates = []
    # Скрипт самого инструмента (pw.py) не определяет проект: важна папка, откуда его вызвали.
    if info.script is not None and not any(_is_under(info.script, tool) for tool in tool_paths):
        candidates.append(info.script)
    if info.cwd is not None:
        candidates.append(info.cwd)
    for path in candidates:
        project = _top_folder(path, root)
        if project is not None:
            return project
    return None


def _process_facts(pid: int) -> tuple[Path, int, int] | None:
    """Образ, родитель, время создания; None, если процесса нет или он недоступен."""
    try:
        handle = _open(pid, PROCESS_QUERY_LIMITED_INFORMATION)
    except OSError:
        return None
    try:
        size = wintypes.DWORD(32768)
        image = ctypes.create_unicode_buffer(size.value)
        if not _kernel32.QueryFullProcessImageNameW(handle, 0, image, byref(size)):
            return None
        created, exited, kernel, user = (wintypes.FILETIME() for _ in range(4))
        if not _kernel32.GetProcessTimes(handle, byref(created), byref(exited), byref(kernel), byref(user)):
            return None
        parent = _basic(handle).InheritedFromUniqueProcessId
        return Path(image.value), parent, (created.dwHighDateTime << 32) | created.dwLowDateTime
    except OSError:
        return None
    finally:
        _kernel32.CloseHandle(handle)


def _is_session_process(image: Path) -> bool:
    return image.name.lower() == "claude.exe" and "claude-code" in str(image).lower()


def session_of(pid: int) -> str:
    """Опознаёт сессию Claude по цепочке родителей; идентификатор переживает повтор номера процесса."""
    current, younger_than = pid, None
    for _ in range(MAX_ANCESTORS):
        facts = _process_facts(current)
        if facts is None:
            return MANUAL_SESSION
        image, parent, created = facts
        if younger_than is not None and created > younger_than:
            return MANUAL_SESSION  # номер родителя занят более новым процессом: цепочка оборвалась
        if _is_session_process(image):
            return f"claude:{current}:{created}"
        if not parent:
            return MANUAL_SESSION
        current, younger_than = parent, created
    return MANUAL_SESSION
