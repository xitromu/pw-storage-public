"""Хост постоянных служб PW_STORAGE: SCM-слой и надзор за детским процессом.

Служба запускается от имени NT SERVICE\\<имя> — только она расшифровывает свой пакет
секретов (pw_storage.service_store). Здесь нет ни секретов, ни паролей: конфигурация службы
описывает только командами, что запускать, из какой папки и с каким профилем.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

from .config import PROFILES
from .service_store import NAME as SERVICE_NAME
from . import winsecurity

SC_MANAGER_CONNECT = 0x0001
SC_MANAGER_CREATE_SERVICE = 0x0002
SERVICE_QUERY_STATUS = 0x0004
SERVICE_START = 0x0010
SERVICE_STOP = 0x0020
SERVICE_QUERY_CONFIG = 0x0001
DELETE = 0x00100000
SERVICE_WIN32_OWN_PROCESS = 0x0010
SERVICE_AUTO_START = 2
SERVICE_DEMAND_START = 3
SERVICE_ERROR_NORMAL = 1
SERVICE_STOPPED = 1
SERVICE_START_PENDING = 2
SERVICE_STOP_PENDING = 3
SERVICE_RUNNING = 4
SERVICE_PAUSED = 5
SERVICE_PAUSE_CONTINUE = 0x0002
SERVICE_ACCEPT_STOP = 0x0001
SERVICE_ACCEPT_SHUTDOWN = 0x0004
SC_STATUS_PROCESS_INFO = 0
ERROR_SERVICE_DOES_NOT_EXIST = 1060
ERROR_SERVICE_EXISTS = 1073
ERROR_SERVICE_ALREADY_RUNNING = 1056
ERROR_SERVICE_NOT_ACTIVE = 1062
ERROR_SERVICE_DISABLED = 1058
ERROR_CALL_NOT_IMPLEMENTED = 120
ERROR_INVALID_HANDLE = 6
ERROR_INVALID_PARAMETER = 87
ERROR_TIMEOUT = 1460
ERROR_DEPENDENCY_EXISTS = 1077
ERROR_HINTS = {5: "недостаточно прав: запусти консоль от имени администратора",
               87: "проверь имя службы и абсолютный путь конфигурации",
               1056: "служба уже запущена", 1058: "служба отключена",
               1060: "службы с таким именем нет", 1062: "служба не запущена",
               1073: "служба с таким именем уже создана", 1460: "истекло ожидание ответа службы"}
STATE_NAMES = {SERVICE_STOPPED: "остановлена", SERVICE_START_PENDING: "запускается",
               SERVICE_STOP_PENDING: "останавливается", SERVICE_RUNNING: "работает",
               SERVICE_PAUSED: "на паузе"}
TIMEOUT = 30.0
POLL = 0.1
CHILD_POLL = 0.5
KILL_GRACE = 10.0
RESTART_DELAY = 5.0
RESTART_LIMIT = 8
FAST_EXIT = 10.0
MAX_CONFIG_BYTES = 65536
EXCEPTION_CODE = 900

DWORD = ctypes.c_uint32
BOOL = ctypes.c_int32
HANDLE = ctypes.c_void_p
LPWSTR = ctypes.c_wchar_p
LPDWORD = ctypes.POINTER(DWORD)
LPBYTE = ctypes.POINTER(ctypes.c_ubyte)


class HostError(RuntimeError):
    """Стадия и числовой код: текст системных ошибок в журнал службы не попадает."""

    def __init__(self, stage: str, code):
        self.stage = stage
        self.code = code
        super().__init__(f"{stage}: {code}")


class SERVICE_STATUS(ctypes.Structure):
    _fields_ = [("dwServiceType", DWORD), ("dwCurrentState", DWORD),
                ("dwControlsAccepted", DWORD), ("dwWin32ExitCode", DWORD),
                ("dwServiceSpecificExitCode", DWORD), ("dwCheckPoint", DWORD),
                ("dwWaitHint", DWORD)]


class SERVICE_STATUS_PROCESS(ctypes.Structure):
    _fields_ = SERVICE_STATUS._fields_ + [("dwProcessId", DWORD), ("dwServiceFlags", DWORD)]


SERVICE_MAIN = ctypes.WINFUNCTYPE(None, DWORD, ctypes.POINTER(LPWSTR))
HANDLER_EX = ctypes.WINFUNCTYPE(DWORD, DWORD, DWORD, ctypes.c_void_p, ctypes.c_void_p)


class SERVICE_TABLE_ENTRYW(ctypes.Structure):
    _fields_ = [("lpServiceName", LPWSTR), ("lpServiceProc", SERVICE_MAIN)]


def _last_error() -> int:
    return ctypes.get_last_error()


def load_api():
    if os.name != "nt":
        raise HostError("platform", ERROR_DEPENDENCY_EXISTS)
    try:
        api = ctypes.WinDLL("advapi32.dll", use_last_error=True)
    except OSError as error:
        raise HostError("load_api", getattr(error, "winerror", None) or 1) from None
    for name, (argtypes, restype) in {
        "OpenSCManagerW": ([LPWSTR, LPWSTR, DWORD], HANDLE),
        "OpenServiceW": ([HANDLE, LPWSTR, DWORD], HANDLE),
        "CreateServiceW": ([HANDLE, LPWSTR, LPWSTR, DWORD, DWORD, DWORD, DWORD, LPWSTR, LPWSTR,
                           LPDWORD, LPWSTR, LPWSTR, LPWSTR], HANDLE),
        "StartServiceW": ([HANDLE, DWORD, ctypes.POINTER(LPWSTR)], BOOL),
        "QueryServiceStatusEx": ([HANDLE, ctypes.c_int, LPBYTE, DWORD, LPDWORD], BOOL),
        "ControlService": ([HANDLE, DWORD, ctypes.POINTER(SERVICE_STATUS)], BOOL),
        "DeleteService": ([HANDLE], BOOL),
        "CloseServiceHandle": ([HANDLE], BOOL),
        "StartServiceCtrlDispatcherW": ([ctypes.POINTER(SERVICE_TABLE_ENTRYW)], BOOL),
        "RegisterServiceCtrlHandlerExW": ([LPWSTR, HANDLER_EX, ctypes.c_void_p], HANDLE),
        "SetServiceStatus": ([HANDLE, ctypes.POINTER(SERVICE_STATUS)], BOOL),
    }.items():
        function = getattr(api, name)
        function.argtypes = argtypes
        function.restype = restype
    return api


def service_account(name: str) -> str:
    return "NT SERVICE\\" + service_name(name)


def service_name(value: str) -> str:
    if not isinstance(value, str) or not _valid_name(value):
        raise HostError("name", ERROR_INVALID_PARAMETER)
    return value.upper()


def _valid_name(value) -> bool:
    return isinstance(value, str) and bool(SERVICE_NAME.fullmatch(value))


def _deadline(timeout: float, stage: str) -> float:
    if not isinstance(timeout, (int, float)) or timeout < 0:
        raise HostError(stage, ERROR_INVALID_PARAMETER)
    return time.monotonic() + timeout


def _wait(deadline: float, stage: str) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise HostError(stage, ERROR_TIMEOUT)
    time.sleep(min(POLL, remaining))


class Service:
    """Одна служба по имени; чужие службы только читаются, но не меняются."""

    def __init__(self, name: str, api=None, wants_create: bool = False):
        self.name = service_name(name)
        self.api = api or load_api()
        self.wants_create = wants_create
        self.manager = None
        self.handle = None

    def __enter__(self) -> "Service":
        # Право создания службы спрашиваем только при установке: обычному пользователю
        # SCM отказывает на открытии, и даже status выглядел бы как отказ.
        access = SC_MANAGER_CONNECT | (SC_MANAGER_CREATE_SERVICE if self.wants_create else 0)
        self.manager = self.api.OpenSCManagerW(None, None, access)
        if not self.manager:
            raise HostError("OpenSCManagerW", _last_error())
        return self

    def __exit__(self, *_exc) -> bool:
        for attribute in ("handle", "manager"):
            handle = getattr(self, attribute)
            if handle:
                self.api.CloseServiceHandle(handle)
                setattr(self, attribute, None)
        return False

    def _open(self, access: int) -> bool:
        self.handle = self.api.OpenServiceW(self.manager, self.name, access)
        if not self.handle:
            code = _last_error()
            if code == ERROR_SERVICE_DOES_NOT_EXIST:
                return False
            raise HostError("OpenServiceW", code)
        return True

    def exists(self) -> bool:
        if not self.manager:
            raise HostError("manager_handle", ERROR_INVALID_HANDLE)
        found = self._open(SERVICE_QUERY_STATUS)
        if self.handle:
            self.api.CloseServiceHandle(self.handle)
            self.handle = None
        return found

    def create(self, binary_path: str, autostart: bool = True) -> None:
        if not binary_path.strip() or "\0" in binary_path:
            raise HostError("CreateServiceW", ERROR_INVALID_PARAMETER)
        if self.exists():
            raise HostError("CreateServiceW", ERROR_SERVICE_EXISTS)
        self.handle = self.api.CreateServiceW(
            self.manager, self.name, self.name,
            SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP | DELETE | SERVICE_QUERY_CONFIG,
            SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START if autostart else SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL, binary_path, None, None, None, service_account(self.name), None)
        if not self.handle:
            raise HostError("CreateServiceW", _last_error())

    def start(self, args: list[str] | None = None) -> None:
        if not self._open(SERVICE_START):
            raise HostError("StartServiceW", ERROR_SERVICE_DOES_NOT_EXIST)
        argv = (LPWSTR * len(args))(*args) if args else None
        if not self.api.StartServiceW(self.handle, len(args or []), argv):
            code = _last_error()
            if code != ERROR_SERVICE_ALREADY_RUNNING:
                raise HostError("StartServiceW", code)

    def stop(self) -> None:
        if not self._open(SERVICE_STOP | SERVICE_QUERY_STATUS):
            raise HostError("ControlService", ERROR_SERVICE_DOES_NOT_EXIST)
        status = SERVICE_STATUS()
        if not self.api.ControlService(self.handle, 1, ctypes.byref(status)):
            code = _last_error()
            if code not in (ERROR_SERVICE_NOT_ACTIVE, 1061):
                raise HostError("ControlService", code)

    def status(self) -> dict:
        if not self._open(SERVICE_QUERY_STATUS):
            raise HostError("QueryServiceStatusEx", ERROR_SERVICE_DOES_NOT_EXIST)
        info = SERVICE_STATUS_PROCESS()
        needed = DWORD()
        if not self.api.QueryServiceStatusEx(
                self.handle, SC_STATUS_PROCESS_INFO,
                ctypes.cast(ctypes.byref(info), LPBYTE), ctypes.sizeof(info),
                ctypes.byref(needed)):
            raise HostError("QueryServiceStatusEx", _last_error())
        return {"state": info.dwCurrentState, "pid": info.dwProcessId,
                "win32_exit": info.dwWin32ExitCode, "service_exit": info.dwServiceSpecificExitCode}

    def wait(self, wanted: int, timeout: float = TIMEOUT) -> dict:
        deadline = _deadline(timeout, "wait")
        while True:
            current = self.status()
            if current["state"] == wanted:
                return current
            _wait(deadline, "wait")

    def remove(self) -> None:
        if not self._open(DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS):
            raise HostError("DeleteService", ERROR_SERVICE_DOES_NOT_EXIST)
        self.stop()
        self.wait(SERVICE_STOPPED)
        if not self.api.DeleteService(self.handle):
            raise HostError("DeleteService", _last_error())


def read_config(path: Path) -> dict:
    """Не секретная конфигурация: argv запускаемого процесса, рабочая папка и профиль."""
    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(MAX_CONFIG_BYTES + 1)
        if len(raw) > MAX_CONFIG_BYTES:
            raise HostError("config", ERROR_INVALID_PARAMETER)
        data = json.loads(raw)
    except (OSError, ValueError, RecursionError):
        raise HostError("config", 1) from None
    return validate_config(data)


def validate_config(data) -> dict:
    if (not isinstance(data, dict) or set(data) != {"name", "profile", "argv", "cwd", "log"}
            or not _valid_name(data.get("name"))
            or data.get("profile") not in PROFILES
            or not isinstance(data.get("argv"), list) or not 1 <= len(data["argv"]) <= 32
            or any(not isinstance(item, str) or not item or "\0" in item for item in data["argv"])
            or not isinstance(data.get("cwd"), str) or not os.path.isabs(data["cwd"])
            or not isinstance(data.get("log"), str) or not os.path.isabs(data["log"])):
        raise HostError("config", ERROR_INVALID_PARAMETER)
    return {"name": data["name"].upper(), "profile": data["profile"], "argv": list(data["argv"]),
            "cwd": data["cwd"], "log": data["log"]}


def log_line(path: str, text: str) -> None:
    try:
        with open(path, "a", encoding="utf-8") as stream:
            stream.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {text}\n")
    except OSError:
        pass


def supervise(stop: threading.Event, config: dict, popen=subprocess.Popen,
              poll: float = CHILD_POLL, delay: float = RESTART_DELAY,
              grace: float = KILL_GRACE, limit: int = RESTART_LIMIT) -> int:
    """Держит детский процесс живым; остановка службы завершает ребёнка, а не только цикл.

    Пауза между отказами растёт вдвое (до минуты): после перезагрузки сеть поднимается
    не сразу, и мост не должен сдаться раньше, чем появится интернет.
    """
    failures = 0
    while not stop.is_set():
        started = time.monotonic()
        log = None
        try:
            log = open(config["log"], "a", encoding="utf-8")
            child = popen(config["argv"], cwd=config["cwd"], stdout=log, stderr=subprocess.STDOUT,
                          stdin=subprocess.DEVNULL)
        except OSError:
            log_line(config["log"], "не удалось запустить процесс службы")
            child = None
        if child is not None:
            log_line(config["log"], f"процесс службы запущен, pid {child.pid}")
            while child.poll() is None:
                if stop.is_set():
                    break
                stop.wait(poll)
            code = child.poll()
            if stop.is_set() and code is None:
                child.terminate()
                deadline = time.monotonic() + grace
                while child.poll() is None and time.monotonic() < deadline:
                    stop.wait(POLL)
                if child.poll() is None:
                    child.kill()
                    log_line(config["log"], "процесс снят принудительно")
                code = child.poll()
        if log is not None:
            log.close()
        if stop.is_set():
            return 0
        finished = child.poll() if child is not None else None
        log_line(config["log"], f"процесс службы завершился, код {finished}")
        failures = failures + 1 if time.monotonic() - started < FAST_EXIT else 0
        if failures >= limit:
            log_line(config["log"], "слишком частые отказы: остановлено, служба не перезапускается")
            return 1
        stop.wait(min(delay * (2 ** failures), 60.0))
    return 0


def run_service(name: str, work) -> int:
    """Точка входа SCM: work(stop_event) возвращает код завершения службы."""
    api = load_api()
    stop = threading.Event()
    lock = threading.RLock()
    state = {"handle": None, "current": 0, "reported_stopped": False, "failed": False}

    def report(current: int, code: int = 0) -> None:
        if state["reported_stopped"]:
            return
        pending = current in (SERVICE_START_PENDING, SERVICE_STOP_PENDING)
        status = SERVICE_STATUS(
            SERVICE_WIN32_OWN_PROCESS, current,
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN if current == SERVICE_RUNNING else 0,
            1066 if code else 0, code, 1 if pending else 0, int(TIMEOUT * 1000) if pending else 0)
        if current == SERVICE_STOPPED:
            state["reported_stopped"] = True
        if not api.SetServiceStatus(state["handle"], ctypes.byref(status)):
            raise HostError("SetServiceStatus", _last_error())
        state["current"] = current

    @HANDLER_EX
    def handler(control, event_type, event_data, context):
        with lock:
            try:
                if control == 4:
                    return 0
                if control not in (1, 5):
                    return ERROR_CALL_NOT_IMPLEMENTED
                stop.set()
                if state["handle"] and state["current"] != SERVICE_STOP_PENDING:
                    report(SERVICE_STOP_PENDING)
                return 0
            except BaseException:
                state["failed"] = True
                stop.set()
                return EXCEPTION_CODE

    @SERVICE_MAIN
    def service_main(argc, argv):
        result = EXCEPTION_CODE
        try:
            state["handle"] = api.RegisterServiceCtrlHandlerExW(name, handler, None)
            if not state["handle"]:
                raise HostError("RegisterServiceCtrlHandlerExW", _last_error())
            with lock:
                report(SERVICE_START_PENDING)
                if not stop.is_set():
                    report(SERVICE_RUNNING)
            code = work(stop)
            result = code if type(code) is int and 0 <= code <= 0xFFFFFFFF else EXCEPTION_CODE
        except BaseException:
            result = EXCEPTION_CODE
        finally:
            with lock:
                if state["handle"]:
                    try:
                        report(SERVICE_STOPPED, EXCEPTION_CODE if state["failed"] else result)
                    except BaseException:
                        result = EXCEPTION_CODE

    table = (SERVICE_TABLE_ENTRYW * 2)()
    table[0].lpServiceName = name
    table[0].lpServiceProc = service_main
    if not api.StartServiceCtrlDispatcherW(table):
        raise HostError("StartServiceCtrlDispatcherW", _last_error())
    return result


def service_interpreter() -> Path:
    """SCM должен запускать именно тот процесс, который вызывает диспетчер служб.

    .venv\Scripts\python.exe — трамплин uv: он перезапускает базовый интерпретатор
    отдельным процессом, и SCM отвергает подключение (событие 7039, отказ 1063).
    """
    base = Path(sys.base_prefix) / "python.exe"
    return base if os.name == "nt" and base.is_file() else Path(sys.executable)


def command_line(python: Path, launcher: Path, config: Path) -> str:
    return f'"{python}" -X utf8 "{launcher}" "{config}"'


def service_log(name: str) -> Path:
    """Журнал службы живёт в ProgramData и доступен только этой службе."""
    return (winsecurity.common_app_data() / "PW_STORAGE_LOGS" / service_name(name)
            / "service.log")


def prepare_log_directory(name: str) -> Path:
    """Папка журнала службы: писать в неё может только эта служба (плюс система и админы)."""
    path = service_log(name)
    sid = winsecurity.service_sid(service_name(name))
    path.parent.mkdir(parents=True, exist_ok=True)
    winsecurity.create_service_directory(path.parent, sid, writable=True)
    return path


def run_from_config(path: Path) -> int:
    """Вызывается из pw_service.py: SCM запускает этот файл с путём конфигурации."""
    config = read_config(path)
    return run_service(config["name"], lambda stop: supervise(stop, config))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Службы PW_STORAGE: без --apply только план.")
    parser.add_argument("command", choices=("status", "install", "uninstall", "start", "stop"))
    parser.add_argument("--name", help="имя службы вида PW_...")
    parser.add_argument("--config", type=Path, help="JSON-описание запускаемого процесса")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    try:
        name = service_name(args.name or "")
        with Service(name, wants_create=args.command == "install") as service:
            if args.command == "status":
                if not service.exists():
                    print(f"{name}: службы нет")
                    return 0
                current = service.status()
                line = (f"{name}: {STATE_NAMES.get(current['state'], current['state'])}, "
                        f"pid {current['pid']}")
                if current["state"] == SERVICE_STOPPED and current["win32_exit"]:
                    line += (f"; код службы {current['service_exit']}, "
                             f"код Windows {current['win32_exit']}")
                print(line)
                return 0
            if args.command == "uninstall":
                print(f"Будет удалена служба {name}; её процесс будет остановлен.")
                if args.apply:
                    service.remove()
                    print("Служба удалена. Пакет секретов и ключ TPM отзывались отдельно "
                          "(service_store revoke).")
                return 0
            if args.command == "stop":
                print(f"Будет остановлена служба {name}; автозапуск сохранится.")
                if args.apply:
                    service.stop()
                    print(f"{name}: "
                          f"{STATE_NAMES.get(service.wait(SERVICE_STOPPED, 15)['state'])}")
                return 0
            if args.command == "install":
                config = validate_config(read_config(args.config)) if args.config else None
                if (config is None or config["name"] != name
                        or config["log"] != str(service_log(name))):
                    raise HostError("config", ERROR_INVALID_PARAMETER)
                binary = command_line(service_interpreter(),
                                      Path(__file__).resolve().parent.parent / "pw_service.py",
                                      args.config.resolve())
                print(f"Будет создана служба {name} от имени {service_account(name)}: {binary}")
                print(f"Запускается: {' '.join(config['argv'])}; папка {config['cwd']}; "
                      f"профиль {config['profile']}; журнал {config['log']}")
                if args.apply:
                    try:
                        service.create(binary)
                        created = f"Служба {name} создана с автозапуском."
                    except HostError as error:
                        if error.code != ERROR_SERVICE_EXISTS:
                            raise
                        created = f"Служба {name} уже существовала."
                    # Папку журнала можно открыть на службу только после её создания:
                    # виртуальная учётная запись появляется вместе со службой.
                    prepare_log_directory(name)
                    print(created + " Папка журнала доступна только этой службе; "
                                    "запуск — start после выдачи пакета.")
                return 0
            # Пуск и остановка спрашивают только имя: конфигурация уже зашита в службу.
            if args.config:
                config = validate_config(read_config(args.config))
                if config["name"] != name:
                    raise HostError("config", ERROR_INVALID_PARAMETER)
                print(f"Запуск {name}: {config['argv'][0]}")
            else:
                print(f"Запуск {name}")
            if args.apply:
                service.start()
                print(f"{name}: "
                      f"{STATE_NAMES.get(service.wait(SERVICE_RUNNING, 15)['state'])}")
            return 0
    except HostError as error:
        hint = ERROR_HINTS.get(error.code)
        print(f"Не выполнено: {error.stage} (код {error.code})"
              + (f" — {hint}" if hint else ""), file=sys.stderr)
        return 1
    except winsecurity.SecurityError as error:
        print(f"Не выполнено: {error}\nВиртуальная учётная запись службы существует только "
              "после install --apply — создай службу, потом выдавай пакет.", file=sys.stderr)
        return 1
    except (ValueError, TypeError, OSError):
        print("Не выполнено: проверка не пройдена; детали не выводятся.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
