"""Ключи в TPM этого ПК через ncrypt.dll (Microsoft Platform Crypto Provider).

Закрытая часть ключа не извлекается: файл, зашифрованный здесь, на другом компьютере бесполезен.
Работаем только с ключами по их именам. В провайдере есть чужой ключ, его не трогаем и не перечисляем.
Ключи здесь без кода, поэтому ошибки не расходуют лимит подбора TPM.
"""

from __future__ import annotations

import ctypes
import os
import re
import struct
from contextlib import contextmanager
from ctypes import POINTER, byref, wintypes

from Cryptodome.Cipher import AES

PROVIDER = "Microsoft Platform Crypto Provider"
NCRYPT_SILENT_FLAG = 0x40
NCRYPT_PAD_OAEP_FLAG = 0x4
NCRYPT_ALLOW_DECRYPT_FLAG = 0x1
NCRYPT_MACHINE_KEY_FLAG = 0x20
NCRYPT_PERSIST_FLAG = 0x80000000
OWNER_SECURITY_INFORMATION = 0x1
DACL_SECURITY_INFORMATION = 0x4
NTE_BAD_KEYSET = 0x80090016
RSA_BITS = 2048
SEAL_MAGIC = b"PWT1"

_Handle = ctypes.c_size_t
_ncrypt = ctypes.WinDLL("ncrypt")
_Status = ctypes.c_long
for _name, _args in {
    "NCryptOpenStorageProvider": (POINTER(_Handle), wintypes.LPCWSTR, wintypes.DWORD),
    "NCryptOpenKey": (_Handle, POINTER(_Handle), wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD),
    "NCryptCreatePersistedKey": (_Handle, POINTER(_Handle), wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD),
    "NCryptSetProperty": (_Handle, wintypes.LPCWSTR, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD),
    "NCryptGetProperty": (_Handle, wintypes.LPCWSTR, ctypes.c_void_p, wintypes.DWORD, POINTER(wintypes.DWORD), wintypes.DWORD),
    "NCryptFinalizeKey": (_Handle, wintypes.DWORD),
    "NCryptEncrypt": (_Handle, ctypes.c_char_p, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, POINTER(wintypes.DWORD), wintypes.DWORD),
    "NCryptDecrypt": (_Handle, ctypes.c_char_p, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, POINTER(wintypes.DWORD), wintypes.DWORD),
    "NCryptDeleteKey": (_Handle, wintypes.DWORD),
    "NCryptFreeObject": (_Handle,),
}.items():
    _func = getattr(_ncrypt, _name)
    _func.argtypes = _args
    _func.restype = _Status


class TpmError(Exception):
    pass


class _OaepInfo(ctypes.Structure):
    _fields_ = [("pszAlgId", wintypes.LPCWSTR), ("pbLabel", ctypes.c_void_p), ("cbLabel", wintypes.ULONG)]


def _check(status: int, what: str) -> None:
    if status != 0:
        raise TpmError(f"{what}: 0x{status & 0xFFFFFFFF:08X}")


@contextmanager
def _provider():
    handle = _Handle()
    _check(_ncrypt.NCryptOpenStorageProvider(byref(handle), PROVIDER, 0), "открытие провайдера TPM")
    try:
        yield handle
    finally:
        _ncrypt.NCryptFreeObject(handle)


def _set_dword(handle: _Handle, prop: str, value: int) -> None:
    data = wintypes.DWORD(value)
    _check(_ncrypt.NCryptSetProperty(handle, prop, byref(data), ctypes.sizeof(data), 0), f"свойство {prop}")


def _set_pin(handle: _Handle, pin: str) -> None:
    data = ctypes.create_unicode_buffer(pin)
    _check(_ncrypt.NCryptSetProperty(handle, "SmartCardPin", data, ctypes.sizeof(data), 0), "свойство SmartCardPin")


class TpmKey:
    """Постоянный ключ RSA-2048 в TPM: только расшифровка, экспорт запрещён.

    С кодом каждая неверная попытка расходует лимит подбора TPM: число попыток ограничивает вызывающий.
    """

    def __init__(self, name: str, pin: str | None = None, *, machine: bool = False,
                 service_sid: str | None = None):
        if machine and (pin is not None or not isinstance(service_sid, str)
                        or not re.fullmatch(r"S-1-5-80(?:-[0-9]{1,10}){5}", service_sid)):
            raise ValueError("Машинный ключ требует SID отдельной службы и не использует PIN")
        if not machine and service_sid is not None:
            raise ValueError("SID службы допустим только для машинного ключа")
        self.name = name
        self.pin = pin
        self.service_sid = service_sid
        self.flags = NCRYPT_MACHINE_KEY_FLAG if machine else 0

    @contextmanager
    def _opened(self):
        with _provider() as provider:
            key = _Handle()
            _check(_ncrypt.NCryptOpenKey(provider, byref(key), self.name, 0, self.flags), f"открытие ключа {self.name}")
            try:
                if self.pin is not None:
                    _set_pin(key, self.pin)
                yield key
            finally:
                _ncrypt.NCryptFreeObject(key)

    def exists(self) -> bool:
        with _provider() as provider:
            key = _Handle()
            status = _ncrypt.NCryptOpenKey(provider, byref(key), self.name, 0, self.flags)
            if status == 0:
                _ncrypt.NCryptFreeObject(key)
                return True
            if status & 0xFFFFFFFF == NTE_BAD_KEYSET:
                return False
            _check(status, f"открытие ключа {self.name}")
            return False

    def create(self) -> None:
        """Создание занимает около 8 секунд."""
        with _provider() as provider:
            key = _Handle()
            _check(_ncrypt.NCryptCreatePersistedKey(provider, byref(key), "RSA", self.name, 0, self.flags), f"создание ключа {self.name}")
            try:
                _set_dword(key, "Length", RSA_BITS)
                _set_dword(key, "Key Usage", NCRYPT_ALLOW_DECRYPT_FLAG)
                _set_dword(key, "Export Policy", 0)
                if self.pin is not None:
                    _set_pin(key, self.pin)
                _check(_ncrypt.NCryptFinalizeKey(key, NCRYPT_SILENT_FLAG), f"завершение ключа {self.name}")
                if self.service_sid is not None:
                    self._restrict_service_access(key)
            except Exception:
                if self.service_sid is not None and _ncrypt.NCryptDeleteKey(key, 0) == 0:
                    key.value = 0
                raise
            finally:
                if key.value:
                    _ncrypt.NCryptFreeObject(key)

    def _restrict_service_access(self, key) -> None:
        from .winsecurity import security_descriptor
        policy, size = wintypes.DWORD(), wintypes.DWORD()
        _check(_ncrypt.NCryptGetProperty(key, "Export Policy", byref(policy), ctypes.sizeof(policy),
                                        byref(size), 0), "политика экспорта машинного ключа")
        if size.value != ctypes.sizeof(policy) or policy.value != 0:
            raise TpmError("Машинный ключ допускает экспорт; использование запрещено")
        sddl = f"O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;{self.service_sid})"
        with security_descriptor(sddl) as (descriptor, length):
            _check(_ncrypt.NCryptSetProperty(
                key, "Security Descr", descriptor, length,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | NCRYPT_PERSIST_FLAG | NCRYPT_SILENT_FLAG),
                "права машинного ключа")

    def restrict_service_access(self) -> None:
        if self.service_sid is None:
            raise TpmError("Это не служебный ключ")
        with self._opened() as key:
            self._restrict_service_access(key)

    def delete(self) -> None:
        with self._opened() as key:
            # С NCRYPT_SILENT_FLAG удаление возвращает 0x80090009; после успеха описатель освобождать нельзя.
            status = _ncrypt.NCryptDeleteKey(key, 0)
            _check(status, f"удаление ключа {self.name}")
            key.value = 0

    def _rsa(self, func, data: bytes, what: str) -> bytes:
        padding = _OaepInfo("SHA256", None, 0)
        out = ctypes.create_string_buffer(RSA_BITS // 8)
        size = wintypes.DWORD()
        with self._opened() as key:
            status = func(key, data, len(data), byref(padding), out, len(out), byref(size),
                          NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG)
        _check(status, what)
        return out.raw[:size.value]

    def encrypt(self, data: bytes) -> bytes:
        return self._rsa(_ncrypt.NCryptEncrypt, data, f"шифрование ключом {self.name}")

    def decrypt(self, data: bytes) -> bytes:
        return self._rsa(_ncrypt.NCryptDecrypt, data, f"расшифровка ключом {self.name}")


def seal(key, data: bytes) -> bytes:
    """Шифрует данные любой длины: AES-256-GCM, а его ключ закрыт ключом TPM."""
    session = os.urandom(32)
    cipher = AES.new(session, AES.MODE_GCM)
    body, tag = cipher.encrypt_and_digest(data)
    wrapped = key.encrypt(session)
    return b"".join((SEAL_MAGIC, struct.pack("<H", len(wrapped)), wrapped, cipher.nonce, tag, body))


def unseal(key, blob: bytes) -> bytes:
    if len(blob) < 6 or blob[:4] != SEAL_MAGIC:
        raise TpmError("Неизвестный формат файла")
    size = struct.unpack("<H", blob[4:6])[0]
    if not size or len(blob) < 6 + size + 32:
        raise TpmError("Файл повреждён")
    wrapped, rest = blob[6:6 + size], blob[6 + size:]
    session = key.decrypt(wrapped)
    if len(session) != 32:
        raise TpmError("Файл повреждён")
    cipher = AES.new(session, AES.MODE_GCM, nonce=rest[:16])
    try:
        return cipher.decrypt_and_verify(rest[32:], rest[16:32])
    except ValueError as e:
        raise TpmError("Файл повреждён") from e
