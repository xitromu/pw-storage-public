"""SCM-хост единственной временной службы; при импорте системных вызовов нет."""

from __future__ import annotations

import ctypes
import math
import os
import threading
import time
from collections.abc import Callable

NAME = "PW_STORAGE_TEST_SERVICE"
SC_MANAGER_CONNECT = 0x0001
SC_MANAGER_CREATE_SERVICE = 0x0002
SERVICE_QUERY_STATUS = 0x0004
SERVICE_START = 0x0010
SERVICE_STOP = 0x0020
DELETE = 0x00010000
SERVICE_WIN32_OWN_PROCESS = 0x0010
SERVICE_DEMAND_START = 3
SERVICE_ERROR_NORMAL = 1
SERVICE_STOPPED = 1
SERVICE_START_PENDING = 2
SERVICE_STOP_PENDING = 3
SERVICE_RUNNING = 4
SERVICE_CONTROL_STOP = 1
SERVICE_CONTROL_INTERROGATE = 4
SERVICE_ACCEPT_STOP = 1
SC_STATUS_PROCESS_INFO = 0
ERROR_INVALID_HANDLE = 6
ERROR_NOT_SUPPORTED = 50
ERROR_INVALID_PARAMETER = 87
ERROR_CALL_NOT_IMPLEMENTED = 120
ERROR_SERVICE_DOES_NOT_EXIST = 1060
ERROR_SERVICE_NOT_ACTIVE = 1062
ERROR_SERVICE_SPECIFIC_ERROR = 1066
ERROR_SERVICE_MARKED_FOR_DELETE = 1072
ERROR_SERVICE_EXISTS = 1073
ERROR_TIMEOUT = 1460
WORK_EXCEPTION = 900
_TIMEOUT = 30.0
_POLL = 0.1

# Fixed-width Win32 integers and pointer-sized handles, including on 64-bit Python.
DWORD = ctypes.c_uint32
BOOL = ctypes.c_int32
HANDLE = ctypes.c_void_p
LPWSTR = ctypes.c_wchar_p
LPDWORD = ctypes.POINTER(DWORD)
LPBYTE = ctypes.POINTER(ctypes.c_ubyte)
_WINFUNCTYPE = ctypes.WINFUNCTYPE
SERVICE_MAIN = _WINFUNCTYPE(None, DWORD, ctypes.POINTER(LPWSTR))
HANDLER_EX = _WINFUNCTYPE(DWORD, DWORD, DWORD, ctypes.c_void_p, ctypes.c_void_p)


class SERVICE_STATUS(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", DWORD),
        ("dwCurrentState", DWORD),
        ("dwControlsAccepted", DWORD),
        ("dwWin32ExitCode", DWORD),
        ("dwServiceSpecificExitCode", DWORD),
        ("dwCheckPoint", DWORD),
        ("dwWaitHint", DWORD),
    ]


class SERVICE_STATUS_PROCESS(ctypes.Structure):
    _fields_ = SERVICE_STATUS._fields_ + [
        ("dwProcessId", DWORD),
        ("dwServiceFlags", DWORD),
    ]


class SERVICE_TABLE_ENTRYW(ctypes.Structure):
    _fields_ = [("lpServiceName", LPWSTR), ("lpServiceProc", SERVICE_MAIN)]


class ProbeError(RuntimeError):
    """Only a fixed operation name and numeric error; never API/user text."""

    def __init__(self, stage: str, code: int):
        self.stage = stage
        self.code = code
        super().__init__(f"{stage}: {code}")


def _last_error() -> int:
    return ctypes.get_last_error()


def _load_api():
    if os.name != "nt":
        raise ProbeError("platform", ERROR_NOT_SUPPORTED)
    try:
        api = ctypes.WinDLL("advapi32.dll", use_last_error=True)
    except OSError as error:
        raise ProbeError("load_api", getattr(error, "winerror", None) or ERROR_NOT_SUPPORTED) from None
    signatures = {
        "OpenSCManagerW": ([LPWSTR, LPWSTR, DWORD], HANDLE),
        "OpenServiceW": ([HANDLE, LPWSTR, DWORD], HANDLE),
        "CreateServiceW": (
            [HANDLE, LPWSTR, LPWSTR, DWORD, DWORD, DWORD, DWORD,
             LPWSTR, LPWSTR, LPDWORD, LPWSTR, LPWSTR, LPWSTR], HANDLE
        ),
        "StartServiceW": ([HANDLE, DWORD, ctypes.POINTER(LPWSTR)], BOOL),
        "QueryServiceStatusEx": (
            [HANDLE, ctypes.c_int, LPBYTE, DWORD, LPDWORD], BOOL
        ),
        "ControlService": ([HANDLE, DWORD, ctypes.POINTER(SERVICE_STATUS)], BOOL),
        "DeleteService": ([HANDLE], BOOL),
        "CloseServiceHandle": ([HANDLE], BOOL),
        "StartServiceCtrlDispatcherW": ([ctypes.POINTER(SERVICE_TABLE_ENTRYW)], BOOL),
        "RegisterServiceCtrlHandlerExW": ([LPWSTR, HANDLER_EX, ctypes.c_void_p], HANDLE),
        "SetServiceStatus": ([HANDLE, ctypes.POINTER(SERVICE_STATUS)], BOOL),
    }
    for name, (argtypes, restype) in signatures.items():
        function = getattr(api, name)
        function.argtypes = argtypes
        function.restype = restype
    return api


def _deadline(timeout: float, stage: str) -> float:
    try:
        valid = isinstance(timeout, (int, float)) and math.isfinite(timeout) and timeout >= 0
    except (OverflowError, ValueError):
        valid = False
    if not valid:
        raise ProbeError(stage, ERROR_INVALID_PARAMETER)
    return time.monotonic() + timeout


def _poll(deadline: float, stage: str) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ProbeError(stage, ERROR_TIMEOUT)
    time.sleep(min(_POLL, remaining))


class Scm:
    """Single controller context; never attach to an existing service to mutate it."""

    def __init__(self):
        self.created = False
        self._delete_pending = False
        self._manager = None
        self._service = None
        self._query = None
        self._api = None

    def __enter__(self) -> Scm:
        if self._manager or self._service or self._query or self.created:
            raise ProbeError("enter", ERROR_INVALID_PARAMETER)
        self._api = _load_api()
        self._manager = self._api.OpenSCManagerW(
            None, None, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE
        )
        if not self._manager:
            raise ProbeError("OpenSCManagerW", _last_error())
        return self

    def _close(self, attribute: str) -> None:
        handle = getattr(self, attribute)
        if handle:
            if not self._api.CloseServiceHandle(handle):
                raise ProbeError("CloseServiceHandle", _last_error())
            setattr(self, attribute, None)

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        error = None
        for attribute in ("_service", "_query", "_manager"):
            try:
                self._close(attribute)
            except ProbeError as close_error:
                if error is None:
                    error = close_error
        if error is not None:
            raise error from None
        return False

    def _require_manager(self) -> None:
        if not self._manager:
            raise ProbeError("manager_handle", ERROR_INVALID_HANDLE)

    def _require_service(self) -> None:
        if not self.created or not self._service or self._delete_pending:
            raise ProbeError("service_handle", ERROR_INVALID_HANDLE)

    def exists(self) -> bool:
        self._require_manager()
        self._close("_query")
        self._query = self._api.OpenServiceW(self._manager, NAME, SERVICE_QUERY_STATUS)
        if not self._query:
            code = _last_error()
            if code == ERROR_SERVICE_DOES_NOT_EXIST:
                return False
            raise ProbeError("OpenServiceW", code)
        # Retain a failed-to-close query handle so context exit can retry it.
        self._close("_query")
        return True

    def create(self, binary_path: str) -> None:
        self._require_manager()
        if self.created or self._service:
            raise ProbeError("CreateServiceW", ERROR_SERVICE_EXISTS)
        if not isinstance(binary_path, str) or not binary_path.strip() or "\0" in binary_path:
            raise ProbeError("CreateServiceW", ERROR_INVALID_PARAMETER)
        if self.exists():
            raise ProbeError("CreateServiceW", ERROR_SERVICE_EXISTS)
        self._service = self._api.CreateServiceW(
            self._manager, NAME, NAME,
            SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP | DELETE,
            SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
            binary_path, None, None, None, "NT SERVICE\\" + NAME, None,
        )
        if not self._service:
            raise ProbeError("CreateServiceW", _last_error())
        self.created = True

    def start(self, args: list[str]) -> None:
        """Pass only non-secret arguments (excluding the implicit service name)."""
        self._require_service()
        if not isinstance(args, list) or any(
            not isinstance(arg, str) or "\0" in arg for arg in args
        ):
            raise ProbeError("StartServiceW", ERROR_INVALID_PARAMETER)
        argv = (LPWSTR * len(args))(*args) if args else None
        if not self._api.StartServiceW(self._service, len(args), argv):
            raise ProbeError("StartServiceW", _last_error())

    def status(self) -> dict:
        """Return raw SCM fields; pid is not valid in STOPPED and pending states."""
        self._require_service()
        status = SERVICE_STATUS_PROCESS()
        needed = DWORD()
        if not self._api.QueryServiceStatusEx(
            self._service, SC_STATUS_PROCESS_INFO,
            ctypes.cast(ctypes.byref(status), LPBYTE), ctypes.sizeof(status),
            ctypes.byref(needed),
        ):
            raise ProbeError("QueryServiceStatusEx", _last_error())
        return {
            "state": status.dwCurrentState,
            "win32_exit": status.dwWin32ExitCode,
            "service_exit": status.dwServiceSpecificExitCode,
            "pid": status.dwProcessId,
        }

    def wait_stopped(self, timeout: float = 30) -> dict:
        deadline = _deadline(timeout, "wait_stopped")
        while True:
            status = self.status()
            if status["state"] == SERVICE_STOPPED:
                return status
            _poll(deadline, "wait_stopped")

    def remove(self) -> None:
        """Удаляет только созданную здесь службу; повторная проверка не трогает замену с тем же именем."""
        if not self.created:
            return
        self._require_manager()
        if not self._delete_pending:
            self._require_service()
            stop_deadline = _deadline(_TIMEOUT, "wait_stopped")
            while True:
                state = self.status()["state"]
                if state == SERVICE_STOPPED:
                    break
                if state == SERVICE_START_PENDING:
                    _poll(stop_deadline, "wait_stopped")
                    continue
                if state != SERVICE_STOP_PENDING:
                    status = SERVICE_STATUS()
                    if not self._api.ControlService(
                        self._service, SERVICE_CONTROL_STOP, ctypes.byref(status)
                    ):
                        code = _last_error()
                        if code == 1061:
                            _poll(stop_deadline, "wait_stopped")
                            continue
                        if code != ERROR_SERVICE_NOT_ACTIVE:
                            raise ProbeError("ControlService", code)
                self.wait_stopped(max(0, stop_deadline - time.monotonic()))
                break
            if not self._api.DeleteService(self._service):
                code = _last_error()
                if code != ERROR_SERVICE_MARKED_FOR_DELETE:
                    raise ProbeError("DeleteService", code)
            self._delete_pending = True
        self._close("_service")
        deadline = _deadline(_TIMEOUT, "wait_deleted")
        while True:
            try:
                present = self.exists()
            except ProbeError as error:
                if error.stage != "OpenServiceW" or error.code != ERROR_SERVICE_MARKED_FOR_DELETE:
                    raise
                present = True
            if not present:
                self.created = False
                self._delete_pending = False
                return
            _poll(deadline, "wait_deleted")


def run_service(work: Callable[[threading.Event, list[str]], int]) -> int:
    """Запускает work внутри SCM; обработчик обязан учитывать stop_event, ошибки дают код 900."""
    api = _load_api()
    stop_event = threading.Event()
    lock = threading.RLock()
    status_handle = None
    current_state = 0
    stopped_reported = False
    handler_failed = False
    result = WORK_EXCEPTION

    def report(state: int, code: int = 0) -> None:
        # All callers hold lock: STOP cannot race a final STOPPED report.
        nonlocal current_state, stopped_reported
        if stopped_reported:
            return
        pending = state in (SERVICE_START_PENDING, SERVICE_STOP_PENDING)
        status = SERVICE_STATUS(
            SERVICE_WIN32_OWN_PROCESS, state,
            SERVICE_ACCEPT_STOP if state == SERVICE_RUNNING else 0,
            ERROR_SERVICE_SPECIFIC_ERROR if code else 0, code,
            1 if pending else 0, int(_TIMEOUT * 1000) if pending else 0,
        )
        if state == SERVICE_STOPPED:
            # SetServiceStatus(STOPPED) closes the RPC context: never repeat it.
            stopped_reported = True
        if not api.SetServiceStatus(status_handle, ctypes.byref(status)):
            raise ProbeError("SetServiceStatus", _last_error())
        current_state = state

    @HANDLER_EX
    def handler(control, event_type, event_data, context):
        nonlocal handler_failed
        with lock:
            try:
                if control == SERVICE_CONTROL_INTERROGATE:
                    return 0
                if control != SERVICE_CONTROL_STOP:
                    return ERROR_CALL_NOT_IMPLEMENTED
                if not stopped_reported:
                    stop_event.set()
                    if status_handle and current_state != SERVICE_STOP_PENDING:
                        report(SERVICE_STOP_PENDING)
                return 0
            except BaseException:
                # Exceptions must never escape a ctypes callback (stderr may leak).
                handler_failed = True
                stop_event.set()
                return WORK_EXCEPTION

    @SERVICE_MAIN
    def service_main(argc, argv):
        nonlocal status_handle, result
        code = WORK_EXCEPTION
        try:
            status_handle = api.RegisterServiceCtrlHandlerExW(NAME, handler, None)
            if not status_handle:
                raise ProbeError("RegisterServiceCtrlHandlerExW", _last_error())
            with lock:
                report(SERVICE_START_PENDING)
            if argc and (not argv or argv[0] != NAME):
                raise ProbeError("service_args", ERROR_INVALID_PARAMETER)
            start_args = [argv[index] for index in range(1, argc)]
            with lock:
                if not stop_event.is_set():
                    report(SERVICE_RUNNING)
            code = work(stop_event, start_args)
            if type(code) is not int or not 0 <= code <= 0xFFFFFFFF:
                code = WORK_EXCEPTION
        except BaseException:
            code = WORK_EXCEPTION
        finally:
            with lock:
                result = WORK_EXCEPTION if handler_failed else code
                if status_handle:
                    try:
                        report(SERVICE_STOPPED, result)
                    except BaseException:
                        result = WORK_EXCEPTION

    # Both callbacks and the null-terminated table stay alive until dispatch ends.
    table = (SERVICE_TABLE_ENTRYW * 2)()
    table[0].lpServiceName = NAME
    table[0].lpServiceProc = service_main
    if not api.StartServiceCtrlDispatcherW(table):
        raise ProbeError("StartServiceCtrlDispatcherW", _last_error())
    return result
