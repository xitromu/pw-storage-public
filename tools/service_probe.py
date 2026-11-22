"""Аппаратная проба только PW_STORAGE_TEST_SERVICE, без боевого хранилища."""

from __future__ import annotations

import argparse
import base64
import ctypes
import io
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
from ctypes import POINTER, byref, wintypes
from multiprocessing.connection import Client, Listener
from dataclasses import replace
from pathlib import Path

NAME = "PW_STORAGE_TEST_SERVICE"
KEY_NAME = "PW_STORAGE_SERVICE_test_" + NAME
DIRECTORY_NAME = KEY_NAME
DUMMY_SID = "S-1-5-80-0-0-0-0-0"
RUN_ID = re.compile(r"[0-9a-f]{32}")
REPO = Path(__file__).resolve().parents[1]

_kernel = ctypes.WinDLL("kernel32", use_last_error=True)
_shell = ctypes.WinDLL("shell32", use_last_error=True)
_ole = ctypes.WinDLL("ole32")
for _name, _args, _result in (
    ("WaitForSingleObject", (wintypes.HANDLE, wintypes.DWORD), wintypes.DWORD),
    ("GetExitCodeProcess", (wintypes.HANDLE, POINTER(wintypes.DWORD)), wintypes.BOOL),
    ("OpenProcess", (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD), wintypes.HANDLE),
    ("CloseHandle", (wintypes.HANDLE,), wintypes.BOOL),
):
    _fn = getattr(_kernel, _name)
    _fn.argtypes, _fn.restype = _args, _result


class _ShellInfo(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("fMask", wintypes.ULONG), ("hwnd", wintypes.HWND),
                ("lpVerb", wintypes.LPCWSTR), ("lpFile", wintypes.LPCWSTR), ("lpParameters", wintypes.LPCWSTR),
                ("lpDirectory", wintypes.LPCWSTR), ("nShow", ctypes.c_int), ("hInstApp", wintypes.HINSTANCE),
                ("lpIDList", wintypes.LPVOID), ("lpClass", wintypes.LPCWSTR), ("hkeyClass", wintypes.HKEY),
                ("dwHotKey", wintypes.DWORD), ("hIcon", wintypes.HANDLE), ("hProcess", wintypes.HANDLE)]


_shell.ShellExecuteExW.argtypes = (POINTER(_ShellInfo),)
_shell.ShellExecuteExW.restype = wintypes.BOOL
_shell.IsUserAnAdmin.argtypes = ()
_shell.IsUserAnAdmin.restype = wintypes.BOOL
_ole.CoInitializeEx.argtypes = (wintypes.LPVOID, wintypes.DWORD)
_ole.CoInitializeEx.restype = ctypes.c_long
_ole.CoUninitialize.argtypes = ()
_ole.CoUninitialize.restype = None


class ProbeFailure(RuntimeError):
    def __init__(self, stage: str, code: int | None = None):
        self.stage = stage
        self.code = code
        super().__init__(stage)


def load_storage(service=False):
    root = Path(__file__).resolve().parent if service else REPO
    if service:
        sys.path.insert(0, str(root / "deps"))
    else:
        sys.path.insert(0, str(root / "tools"))
    sys.path.insert(0, str(root))
    from pw_storage import service_store, winsecurity
    return service_store, winsecurity


def error_record(error: BaseException) -> dict:
    found = re.search(r"0x[0-9a-fA-F]{8}|winerror [0-9]+", str(error))
    code = getattr(error, "winerror", None) or getattr(error, "code", None) or (found.group(0) if found else None)
    return {"kind": type(error).__name__, "code": code}


def pipe_name(run_id: str) -> str:
    if not RUN_ID.fullmatch(run_id):
        raise ProbeFailure("run id")
    return r"\\.\pipe\PW_STORAGE_TEST_" + run_id


def send_message(connection, kind: str, payload: dict) -> None:
    connection.send_bytes(json.dumps({"kind": kind, "payload": payload}, ensure_ascii=False).encode("utf-8"))


def receive_message(connection) -> tuple[str, dict]:
    data = json.loads(connection.recv_bytes(65536))
    if not isinstance(data, dict) or not isinstance(data.get("payload"), dict):
        raise ProbeFailure("coordination format")
    return data["kind"], data["payload"]


def wait(handle, milliseconds: int) -> None:
    if _kernel.WaitForSingleObject(handle, milliseconds) != 0:
        raise ProbeFailure("wait timeout or failure")


def elevate(run_id: str):
    info = _ShellInfo()
    info.cbSize, info.fMask = ctypes.sizeof(info), 0x140
    info.lpVerb, info.lpFile = "runas", sys.executable
    info.lpParameters = subprocess.list2cmdline(["-I", str(Path(__file__).resolve()), "--controller",
                                               "--run-id", run_id])
    info.lpDirectory, info.nShow = str(REPO), 1
    initialized = _ole.CoInitializeEx(None, 0x6) in (0, 1)
    try:
        if not _shell.ShellExecuteExW(byref(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not info.hProcess:
            raise ProbeFailure("elevated process handle missing")
        return info.hProcess
    finally:
        if initialized:
            _ole.CoUninitialize()


def existing(path: Path) -> bool:
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False


def create_root(root: Path, sid: str, ws) -> None:
    sddl = f"O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;{sid})"
    with ws.security_descriptor(sddl) as (descriptor, _):
        attributes = ws._SecurityAttributes(ctypes.sizeof(ws._SecurityAttributes), descriptor, False)
        if not ws._kernel32.CreateDirectoryW(str(root), byref(attributes)):
            raise ctypes.WinError(ctypes.get_last_error())


RUNTIME_FILES = ("python.exe", "python3.dll", "python311.dll", "vcruntime140.dll", "vcruntime140_1.dll")


def runtime_preflight() -> None:
    if (sys.version_info[:3] != (3, 11, 9) or ctypes.sizeof(ctypes.c_void_p) != 8
            or Path(sys.prefix).resolve() != (REPO / ".venv").resolve()):
        raise ProbeFailure("run with the pinned project Python 3.11.9 x64")
    base = Path(sys._base_executable).parent
    required = [base / name for name in RUNTIME_FILES]
    required += [base / "Lib" / "os.py", base / "Lib" / "encodings" / "__init__.py",
                 base / "DLLs" / "_ctypes.pyd",
                 REPO / ".venv" / "Lib" / "site-packages" / "pykeepass" / "__init__.py",
                 REPO / ".venv" / "Lib" / "site-packages" / "Cryptodome" / "Cipher" / "AES.py"]
    if not all(path.is_file() for path in required):
        raise ProbeFailure("required Python runtime files missing")


def stage_runtime(root: Path, ws) -> Path:
    runtime = root / "runtime"
    runtime.mkdir()
    base = Path(sys._base_executable).parent
    for name in RUNTIME_FILES:
        shutil.copy2(base / name, runtime / name)
    ignore = shutil.ignore_patterns("site-packages", "__pycache__", "test", "tests", "idlelib", "turtledemo")
    shutil.copytree(base / "Lib", runtime / "Lib", ignore=ignore)
    shutil.copytree(base / "DLLs", runtime / "DLLs", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(REPO / ".venv" / "Lib" / "site-packages", root / "deps",
                    ignore=shutil.ignore_patterns("__pycache__"))
    package = root / "pw_storage"
    package.mkdir()
    for name in ("__init__.py", "config.py", "tpm.py", "winsecurity.py", "vault.py", "service_store.py"):
        shutil.copy2(REPO / "pw_storage" / name, package / name)
    for name in ("service_probe.py", "service_probe_scm.py"):
        shutil.copy2(REPO / "tools" / name, root / name)
    with ws.security_descriptor("O:BA") as (descriptor, _):
        for path in (root, *root.rglob("*")):
            if not ws._advapi32.SetFileSecurityW(str(path), ws.OWNER_SECURITY_INFORMATION, descriptor):
                raise ctypes.WinError(ctypes.get_last_error())
    return runtime / "python.exe"


def worker(stop, args: list[str]) -> int:
    store, ws = load_storage(service=True)
    mode = args[0] if args else "first"
    sys.stderr = io.StringIO()
    if stop.is_set():
        return 101
    if ws.current_user_sid() != ws.service_sid(NAME):
        return 102
    client = store.ServiceClient(NAME, "test")
    try:
        value = client.get("PROBE_TOKEN")
    except store.ServiceError as error:
        return 0 if mode == "revoked" and str(error) == "Разрешение службы отозвано" else 103
    expected_prefix = {"first": "TEST1-", "updated": "TEST2-"}.get(mode)
    if expected_prefix is None or not value.startswith(expected_prefix) or len(value) != 70:
        return 104
    try:
        client.get("NOT_GRANTED")
    except store.ServiceError:
        pass
    else:
        return 105
    root = ws.common_app_data() / DIRECTORY_NAME
    for path in (root / "credentials.bin", root / "service_probe.py", root / "runtime" / "python.exe"):
        try:
            with path.open("r+b"):
                pass
        except PermissionError:
            continue
        return 106
    return 0


def service_round(scm, mode: str) -> dict:
    scm.start([mode])
    first = scm.status()
    pid = first.get("pid", 0) if first["state"] == 4 else 0
    process = _kernel.OpenProcess(0x100000, False, pid) if pid else None
    try:
        status = scm.wait_stopped(45)
        if process:
            wait(process, 30000)
        if status["win32_exit"] or status["service_exit"]:
            raise ProbeFailure("service exit", status["service_exit"] or status["win32_exit"])
        return {"passed": True, "mode": mode}
    finally:
        if process:
            _kernel.CloseHandle(process)


def negative_checks(challenge: dict) -> dict:
    store, ws = load_storage()
    if _shell.IsUserAnAdmin():
        raise ProbeFailure("negative check must not be elevated")
    if challenge.get("name") != NAME:
        raise ProbeFailure("wrong challenge")
    key = store._key(NAME, "test", ws.service_sid(NAME))
    root = ws.common_app_data() / DIRECTORY_NAME
    result = {}
    try:
        store.ServiceClient(NAME, "test").get("PROBE_TOKEN")
        result["client_refused"] = False
    except store.ServiceError as error:
        result["client_refused"] = str(error) == "Секреты доступны только отдельной учётной записи этой службы"
    try:
        (root / "credentials.bin").read_bytes()
        result["file_refused"] = False
    except PermissionError:
        result["file_refused"] = True
    blob = base64.b64decode(challenge["ciphertext"], validate=True)
    try:
        store.unseal(key, blob)
        result["tpm_refused"] = False
    except store.TpmError as error:
        code = error_record(error)["code"]
        result["tpm_code"] = code
        result["tpm_refused"] = code in ("0x80090010", "0x80070005", "0x80090016")
    return result


def controller(run_id: str, connection) -> int:
    store, ws = load_storage()
    from service_probe_scm import Scm
    from pw_storage.vault import Kdf, Vault
    ws.require_admin()
    runtime_preflight()
    if not RUN_ID.fullmatch(run_id):
        raise ProbeFailure("run id")
    root = ws.common_app_data() / DIRECTORY_NAME
    result = {"name": NAME, "run_id": run_id, "passed": False, "stage": "preflight", "checks": {}, "cleanup": {}}
    root_owned = False
    key_attempted = False
    key = store._key(NAME, "test", DUMMY_SID)
    with Scm() as scm:
        try:
            if scm.exists() or existing(root) or key.exists():
                raise ProbeFailure("preexisting test object; no changes")
            result["stage"] = "create_service"
            executable = root / "runtime" / "python.exe"
            command = subprocess.list2cmdline([str(executable), "-I", "-B", "-S", str(root / "service_probe.py"), "--service"])
            scm.create(command)
            sid = ws.service_sid(NAME)
            key = store._key(NAME, "test", sid)
            result["stage"] = "create_directory"
            create_root(root, sid, ws)
            root_owned = True
            (root / ".probe-owner").write_text(run_id, encoding="ascii")
            ws.protect_directory(root, sid)
            result["stage"] = "stage_runtime"
            stage_runtime(root, ws)
            result["stage"] = "create_synthetic_vault"
            source = root / "source"
            source.mkdir()
            store.PROFILES["test"] = replace(store.PROFILES["test"], data=source)
            value = "TEST1-" + secrets.token_hex(32)
            vault = Vault.create(source / "vault.kdbx", secrets.token_urlsafe(40), Kdf(16, 1, 1))
            vault.put("PROBE", "Synthetic", "token", value, "Только аппаратная проба")
            vault.save()
            row = vault.rows()[0]
            spec = store.ServiceSpec(NAME, "test", (store.Binding("PROBE", row.uid, "Synthetic", "token", "PROBE_TOKEN"),))
            result["stage"] = "provision"
            key_attempted = True
            store.provision(spec, vault)
            result["checks"]["admin_round_trip"] = True
            result["stage"] = "service_read"
            result["checks"]["service_read"] = service_round(scm, "first")
            result["stage"] = "ordinary_user_denial"
            send_message(connection, "challenge", {"run_id": run_id, "name": NAME,
                         "ciphertext": base64.b64encode(store.seal(key, value.encode())).decode("ascii")})
            if not connection.poll(90):
                raise ProbeFailure("ordinary account response timed out")
            kind, negative = receive_message(connection)
            if kind != "negative" or negative.get("run_id") != run_id:
                raise ProbeFailure("wrong negative result")
            checks = negative["checks"]
            result["checks"]["ordinary_user"] = checks
            if not all(checks.get(name) is True for name in ("client_refused", "file_refused", "tpm_refused")):
                raise ProbeFailure("ordinary account isolation failed")
            result["stage"] = "refresh"
            vault.put("PROBE", "Synthetic", "token", "TEST2-" + secrets.token_hex(32), "Только аппаратная проба")
            vault.save()
            store.provision(spec, vault)
            del vault, value
            shutil.rmtree(source)
            result["checks"]["source_removed"] = not source.exists()
            result["checks"]["service_restart"] = service_round(scm, "updated")
            result["stage"] = "revoke"
            store.revoke(NAME, "test")
            result["checks"]["revoked_service"] = service_round(scm, "revoked")
            result["passed"] = True
            result["stage"] = "complete"
        except BaseException as error:
            result["error"] = error_record(error)
        finally:
            if scm.created:
                try:
                    scm.remove()
                    result["cleanup"]["service_removed"] = not scm.exists()
                except BaseException as error:
                    result["cleanup"]["service_error"] = error_record(error)
            if key_attempted:
                try:
                    if key.exists():
                        key.delete()
                    result["cleanup"]["key_removed"] = not key.exists()
                except BaseException as error:
                    result["cleanup"]["key_error"] = error_record(error)
            if root_owned:
                try:
                    store._no_links(root)
                    if (root / ".probe-owner").read_text(encoding="ascii") != run_id:
                        raise ProbeFailure("directory ownership marker changed")
                    if result["cleanup"].get("service_removed") is not True:
                        raise ProbeFailure("service still registered; directory retained")
                    shutil.rmtree(root)
                    result["cleanup"]["directory_removed"] = not existing(root)
                except BaseException as error:
                    result["cleanup"]["directory_error"] = error_record(error)
            if result["passed"]:
                result["passed"] = all(result["cleanup"].get(name) is True for name in
                                       ("service_removed", "key_removed", "directory_removed"))
            send_message(connection, "result", result)
    return 0 if result["passed"] else 1


def run_probe() -> int:
    if _shell.IsUserAnAdmin():
        raise ProbeFailure("run from ordinary non-elevated terminal")
    runtime_preflight()
    run_id = secrets.token_hex(16)
    result = {}
    with Listener(pipe_name(run_id), family="AF_PIPE") as listener:
        def exchange():
            try:
                with listener.accept() as connection:
                    while True:
                        kind, message = receive_message(connection)
                        if message.get("run_id") != run_id:
                            raise ProbeFailure("wrong response run")
                        if kind == "result":
                            result.update(message)
                            return
                        if kind != "challenge":
                            raise ProbeFailure("unexpected response")
                        try:
                            checks = negative_checks(message)
                        except BaseException as error:
                            checks = {"failure": error_record(error)}
                        send_message(connection, "negative", {"run_id": run_id, "checks": checks})
            except BaseException as error:
                result.update({"passed": False, "stage": "exchange", "error": error_record(error)})
        print("Ожидается подтверждение UAC для временной аппаратной пробы.", flush=True)
        process = elevate(run_id)
        try:
            thread = threading.Thread(target=exchange, daemon=True)
            thread.start()
            wait(process, 300000)
            thread.join(timeout=10)
            exit_code = wintypes.DWORD()
            if not _kernel.GetExitCodeProcess(process, byref(exit_code)):
                raise ctypes.WinError(ctypes.get_last_error())
            if thread.is_alive() or not result:
                raise ProbeFailure("controller ended without report")
            if exit_code.value:
                result["passed"] = False
                result["controller_exit"] = exit_code.value
            print(json.dumps(result, ensure_ascii=False, indent=2), flush=True)
            return 0 if result.get("passed") else 1
        finally:
            _kernel.CloseHandle(process)


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="Временная проба службы и TPM; без --run системных изменений нет")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--controller", action="store_true")
    parser.add_argument("--service", action="store_true")
    parser.add_argument("--run-id", default="")
    args = parser.parse_args(argv)
    try:
        if args.service:
            sys.path.insert(0, str(Path(__file__).resolve().parent))
            from service_probe_scm import run_service
            return run_service(worker)
        if args.controller:
            with Client(pipe_name(args.run_id), family="AF_PIPE") as connection:
                try:
                    return controller(args.run_id, connection)
                except BaseException as error:
                    send_message(connection, "result", {"name": NAME, "run_id": args.run_id, "passed": False,
                                 "stage": "initialization", "error": error_record(error)})
                    return 1
        if args.run:
            return run_probe()
        print(f"Только тест: {NAME}; ключ {KEY_NAME}; main не используется; после пробы объекты удаляются.")
        return 0
    except BaseException as error:
        result = {"name": NAME, "passed": False, "stage": "initialization", "error": error_record(error)}
        print(json.dumps(result, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
