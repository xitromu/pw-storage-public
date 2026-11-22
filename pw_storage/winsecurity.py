"""Win32 SID, descriptor and dedicated-directory security helpers."""

from __future__ import annotations

import ctypes
import msvcrt
import os
import re
import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from ctypes import POINTER, byref, wintypes
from pathlib import Path

TOKEN_QUERY = 0x0008
TOKEN_USER = 1
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_INVALID_DATA = 13
CSIDL_COMMON_APPDATA = 0x23
OWNER_SECURITY_INFORMATION = 0x00000001
DACL_SECURITY_INFORMATION = 0x00000004
PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
FILE_ATTRIBUTE_DIRECTORY = 0x10
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF

_SERVICE_NAME = re.compile(r"PW_[A-Za-z0-9_]{1,60}")
_SERVICE_SID = re.compile(r"S-1-5-80(?:-(?:0|[1-9][0-9]{0,9})){5}")

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
_shell32 = ctypes.WinDLL("shell32", use_last_error=True)

_kernel32.GetCurrentProcess.argtypes = ()
_kernel32.GetCurrentProcess.restype = wintypes.HANDLE
_kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
_kernel32.CloseHandle.restype = wintypes.BOOL
_kernel32.LocalFree.argtypes = (wintypes.HLOCAL,)
_kernel32.LocalFree.restype = wintypes.HLOCAL
_kernel32.GetFileAttributesW.argtypes = (wintypes.LPCWSTR,)
_kernel32.GetFileAttributesW.restype = wintypes.DWORD
_kernel32.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                                wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
_kernel32.CreateFileW.restype = wintypes.HANDLE
_kernel32.CreateDirectoryW.argtypes = (wintypes.LPCWSTR, wintypes.LPVOID)
_kernel32.CreateDirectoryW.restype = wintypes.BOOL
_kernel32.GetFileInformationByHandleEx.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD)
_kernel32.GetFileInformationByHandleEx.restype = wintypes.BOOL
_kernel32.LockFileEx.argtypes = (wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
                               wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID)
_kernel32.LockFileEx.restype = wintypes.BOOL
_kernel32.UnlockFileEx.argtypes = (wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID)
_kernel32.UnlockFileEx.restype = wintypes.BOOL
_advapi32.LookupAccountNameW.argtypes = (
    wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPVOID, POINTER(wintypes.DWORD),
    wintypes.LPWSTR, POINTER(wintypes.DWORD), POINTER(ctypes.c_int),
)
_advapi32.LookupAccountNameW.restype = wintypes.BOOL
_advapi32.ConvertSidToStringSidW.argtypes = (wintypes.LPVOID, POINTER(wintypes.LPWSTR))
_advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
_advapi32.OpenProcessToken.argtypes = (wintypes.HANDLE, wintypes.DWORD, POINTER(wintypes.HANDLE))
_advapi32.OpenProcessToken.restype = wintypes.BOOL
_advapi32.GetTokenInformation.argtypes = (
    wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD, POINTER(wintypes.DWORD),
)
_advapi32.GetTokenInformation.restype = wintypes.BOOL
_advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = (
    wintypes.LPCWSTR, wintypes.DWORD, POINTER(wintypes.LPVOID), POINTER(wintypes.ULONG),
)
_advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
_advapi32.GetSecurityDescriptorLength.argtypes = (wintypes.LPVOID,)
_advapi32.GetSecurityDescriptorLength.restype = wintypes.DWORD
_advapi32.SetFileSecurityW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.LPVOID)
_advapi32.SetFileSecurityW.restype = wintypes.BOOL
_advapi32.GetSecurityInfo.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.DWORD,
                                    POINTER(wintypes.LPVOID), POINTER(wintypes.LPVOID),
                                    POINTER(wintypes.LPVOID), POINTER(wintypes.LPVOID), POINTER(wintypes.LPVOID))
_advapi32.GetSecurityInfo.restype = wintypes.DWORD
_shell32.IsUserAnAdmin.argtypes = ()
_shell32.IsUserAnAdmin.restype = wintypes.BOOL
_shell32.SHGetFolderPathW.argtypes = (
    wintypes.HWND, ctypes.c_int, wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
)
_shell32.SHGetFolderPathW.restype = ctypes.c_long


class SecurityError(RuntimeError):
    pass


class PublicationPending(SecurityError):
    pass


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [("length", wintypes.DWORD), ("descriptor", wintypes.LPVOID), ("inherit", wintypes.BOOL)]


class _AttributeTagInfo(ctypes.Structure):
    _fields_ = [("attributes", wintypes.DWORD), ("tag", wintypes.DWORD)]


class _SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


class _TOKEN_USER(ctypes.Structure):
    _fields_ = [("User", _SID_AND_ATTRIBUTES)]


def _error(operation: str, code: int | None = None) -> SecurityError:
    if code is None:
        code = ctypes.get_last_error()
    return SecurityError(f"{operation} failed (winerror {code}).")


def _validate_service_sid(sid: str) -> None:
    if (not isinstance(sid, str) or not _SERVICE_SID.fullmatch(sid)
            or any(int(part) > 0xFFFFFFFF for part in sid.split("-")[4:])):
        raise SecurityError("Invalid virtual service SID.")


def _sid_to_string(sid: ctypes.c_void_p) -> str:
    text = wintypes.LPWSTR()
    try:
        if not _advapi32.ConvertSidToStringSidW(sid, byref(text)):
            raise _error("SID conversion")
        if not text or not text.value:
            raise _error("SID conversion", ERROR_INVALID_DATA)
        return text.value
    finally:
        if text:
            _kernel32.LocalFree(ctypes.cast(text, ctypes.c_void_p))


def service_sid(name: str) -> str:
    if not isinstance(name, str) or not _SERVICE_NAME.fullmatch(name):
        raise SecurityError("Invalid service name.")
    account = "NT SERVICE\\" + name
    sid_size, domain_size = wintypes.DWORD(), wintypes.DWORD()
    sid_use = ctypes.c_int()
    if _advapi32.LookupAccountNameW(
        None, account, None, byref(sid_size), None, byref(domain_size), byref(sid_use),
    ):
        raise _error("Service SID sizing", ERROR_INVALID_DATA)
    code = ctypes.get_last_error()
    if code != ERROR_INSUFFICIENT_BUFFER:
        raise _error("Service SID lookup", code)
    if not sid_size.value:
        raise _error("Service SID sizing", ERROR_INVALID_DATA)
    sid = ctypes.create_string_buffer(sid_size.value)
    domain = ctypes.create_unicode_buffer(domain_size.value) if domain_size.value else None
    if not _advapi32.LookupAccountNameW(
        None, account, sid, byref(sid_size), domain, byref(domain_size), byref(sid_use),
    ):
        raise _error("Service SID lookup")
    result = _sid_to_string(ctypes.cast(sid, ctypes.c_void_p))
    _validate_service_sid(result)
    return result


def current_user_sid() -> str:
    token = wintypes.HANDLE()
    if not _advapi32.OpenProcessToken(_kernel32.GetCurrentProcess(), TOKEN_QUERY, byref(token)):
        raise _error("Process token open")
    try:
        size = wintypes.DWORD()
        if _advapi32.GetTokenInformation(token, TOKEN_USER, None, 0, byref(size)):
            raise _error("Token user sizing", ERROR_INVALID_DATA)
        code = ctypes.get_last_error()
        if code != ERROR_INSUFFICIENT_BUFFER:
            raise _error("Token user query", code)
        if size.value < ctypes.sizeof(_TOKEN_USER):
            raise _error("Token user sizing", ERROR_INVALID_DATA)
        buffer = ctypes.create_string_buffer(size.value)
        if not _advapi32.GetTokenInformation(token, TOKEN_USER, buffer, len(buffer), byref(size)):
            raise _error("Token user query")
        if not ctypes.sizeof(_TOKEN_USER) <= size.value <= len(buffer):
            raise _error("Token user query", ERROR_INVALID_DATA)
        user = ctypes.cast(buffer, POINTER(_TOKEN_USER)).contents
        if not user.User.Sid:
            raise _error("Token user SID", ERROR_INVALID_DATA)
        return _sid_to_string(ctypes.c_void_p(user.User.Sid))
    finally:
        _kernel32.CloseHandle(token)


def require_admin() -> None:
    if not _shell32.IsUserAnAdmin():
        raise SecurityError("Administrator privileges are required.")


@contextmanager
def security_descriptor(sddl: str) -> Iterator[tuple[ctypes.c_void_p, int]]:
    if not isinstance(sddl, str) or not sddl or "\x00" in sddl:
        raise SecurityError("Invalid security descriptor text.")
    descriptor = ctypes.c_void_p()
    size = wintypes.ULONG()
    try:
        if not _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, byref(descriptor), byref(size),
        ):
            raise _error("Security descriptor conversion")
        if not descriptor.value:
            raise _error("Security descriptor conversion", ERROR_INVALID_DATA)
        length = _advapi32.GetSecurityDescriptorLength(descriptor)
        if not length:
            raise _error("Security descriptor length", ERROR_INVALID_DATA)
        yield descriptor, int(length)
    finally:
        if descriptor.value:
            _kernel32.LocalFree(descriptor)


def common_app_data() -> Path:
    buffer = ctypes.create_unicode_buffer(260)
    result = _shell32.SHGetFolderPathW(None, CSIDL_COMMON_APPDATA, None, 0, buffer)
    if result != 0:
        hresult = result & 0xFFFFFFFF
        if hresult & 0xFFFF0000 == 0x80070000:
            raise _error("Common application data lookup", hresult & 0xFFFF)
        raise SecurityError(f"Common application data lookup failed (HRESULT {hresult}).")
    path = Path(buffer.value)
    if not buffer.value or not path.is_absolute():
        raise _error("Common application data path", ERROR_INVALID_DATA)
    return path


def service_sddl(sid: str, writable: bool = False) -> str:
    """Служба читает свой пакет; писать ей нечем, кроме папки журнала (writable=True)."""
    return (f"O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
            f"(A;OICI;{'GRGW' if writable else 'GRGX'};;;{sid})")


def create_service_directory(path: Path, sid: str, writable: bool = False) -> None:
    _validate_service_sid(sid)
    if not isinstance(path, Path) or not path.is_absolute() or "\x00" in str(path):
        raise SecurityError("Invalid directory path.")
    require_admin()
    sddl = service_sddl(sid, writable)
    with security_descriptor(sddl) as (descriptor, _):
        attributes = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, False)
        if not _kernel32.CreateDirectoryW(str(path), byref(attributes)):
            code = ctypes.get_last_error()
            if code != 183:
                raise _error("Service directory creation", code)
    protect_directory(path, sid, writable)


def protect_directory(path: Path, sid: str, writable: bool = False) -> None:
    _validate_service_sid(sid)
    if not isinstance(path, Path) or not path.is_absolute() or "\x00" in str(path):
        raise SecurityError("Invalid directory path.")
    require_admin()
    attributes = _kernel32.GetFileAttributesW(str(path))
    if attributes == INVALID_FILE_ATTRIBUTES:
        raise _error("Directory inspection")
    if not attributes & FILE_ATTRIBUTE_DIRECTORY or attributes & FILE_ATTRIBUTE_REPARSE_POINT:
        raise SecurityError("An existing non-reparse directory is required.")
    # Запрет совместного удаления удерживает имя каталога до смены владельца и DACL.
    handle = _kernel32.CreateFileW(str(path), 0x20081, 0x1, None, 3, 0x02200000, None)
    if handle == ctypes.c_void_p(-1).value or handle is None:
        raise _error("Directory lock")
    try:
        info = _AttributeTagInfo()
        if not _kernel32.GetFileInformationByHandleEx(handle, 9, byref(info), ctypes.sizeof(info)):
            raise _error("Directory handle inspection")
        if not info.attributes & FILE_ATTRIBUTE_DIRECTORY or info.attributes & FILE_ATTRIBUTE_REPARSE_POINT:
            raise SecurityError("An existing non-reparse directory is required.")
        owner, security = ctypes.c_void_p(), ctypes.c_void_p()
        try:
            result = _advapi32.GetSecurityInfo(handle, 1, OWNER_SECURITY_INFORMATION,
                                              byref(owner), None, None, None, byref(security))
            if result:
                raise _error("Directory owner inspection", result)
            if not owner.value or _sid_to_string(owner) != "S-1-5-32-544":
                raise SecurityError("Service directory must already belong to Administrators.")
        finally:
            if security.value:
                _kernel32.LocalFree(security)
        sddl = service_sddl(sid, writable)
        with security_descriptor(sddl) as (descriptor, _):
            information = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION
            if not _advapi32.SetFileSecurityW(str(path), information, descriptor):
                raise _error("Directory owner and DACL update")
    finally:
        _kernel32.CloseHandle(handle)


@contextmanager
def package_lock(path: Path):
    class Overlapped(ctypes.Structure):
        _fields_ = [("internal", ctypes.c_size_t), ("internal_high", ctypes.c_size_t),
                    ("offset", wintypes.DWORD), ("offset_high", wintypes.DWORD), ("event", wintypes.HANDLE)]
    handle = _kernel32.CreateFileW(str(path), 0x80000000, 0x3, None, 3, 0x00200000, None)
    if handle == ctypes.c_void_p(-1).value or handle is None:
        raise _error("Package lock open")
    acquired = False
    overlapped = Overlapped()
    try:
        info = _AttributeTagInfo()
        if not _kernel32.GetFileInformationByHandleEx(handle, 9, byref(info), ctypes.sizeof(info)):
            raise _error("Package lock inspection")
        if info.attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT):
            raise SecurityError("A regular lock file is required.")
        if not _kernel32.LockFileEx(handle, 2, 0, 1, 0, byref(overlapped)):
            raise _error("Package locking")
        acquired = True
        yield
    finally:
        try:
            if acquired and not _kernel32.UnlockFileEx(handle, 0, 1, 0, byref(overlapped)):
                raise _error("Package unlocking")
        finally:
            _kernel32.CloseHandle(handle)


def publish_file(path: Path, data: bytes, sid: str) -> None:
    _validate_service_sid(sid)
    require_admin()
    temporary = None
    try:
        name = path.with_name(".pw_service_" + secrets.token_hex(16) + ".part")
        with security_descriptor("O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)") as (descriptor, _):
            attributes = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, False)
            handle = _kernel32.CreateFileW(str(name), 0x40000000, 0, byref(attributes), 1, 0x00200000, None)
        if handle == ctypes.c_void_p(-1).value or handle is None:
            raise _error("Private package staging")
        temporary = name
        try:
            fd = msvcrt.open_osfhandle(handle, os.O_WRONLY | os.O_BINARY | os.O_NOINHERIT)
        except BaseException:
            _kernel32.CloseHandle(handle)
            raise
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
        # До этой точки даже зашифрованный staging недоступен службе с ключом расшифровки.
        try:
            sddl = f"O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;{sid})"
            with security_descriptor(sddl) as (descriptor, _):
                information = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION
                if not _advapi32.SetFileSecurityW(str(path), information, descriptor):
                    raise _error("Package publication")
        except (SecurityError, OSError):
            raise PublicationPending("Package replaced but service access is not published; retry provisioning.") from None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
