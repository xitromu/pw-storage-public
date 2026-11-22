"""Восстановление забытого пароля (Т11): файл восстановления, контрольный вопрос и часть ключа.

В файле лежит пароль, зашифрованный ключом из ответа и отдельной части (Argon2id, AES-256-GCM).
Часть на диске не остаётся: её владелец хранит в другом месте. Вопрос лежит открыто: окно должно
показать его до ввода ответа. Число попыток ограничить нельзя, файл можно перебирать вне программы:
защита держится на этой части и на длине ответа.
"""

from __future__ import annotations

import base64
import json
import secrets
import unicodedata
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw
from Cryptodome.Cipher import AES

FORMAT = "PWR1"
PART_BYTES = 20  # 160 бит: 32 знака Base32
MIN_ANSWER_CHARS = 20
KEY_BYTES = 32
SALT_BYTES = 16
ARGON2_VERSION = 19
MAX_KDF_MEMORY_MB = 1024
MAX_KDF_ITERATIONS = 10
MAX_KDF_PARALLELISM = 16


class RecoveryError(Exception):
    pass


class WrongRecovery(RecoveryError):
    """Ответ или часть из письма не подошли. Что именно, не сообщаем: это облегчило бы подбор."""


class WeakAnswer(RecoveryError):
    pass


@dataclass(frozen=True)
class RecoveryKdf:
    memory_mb: int = 1024
    iterations: int = 4
    parallelism: int = 4


def normalize_answer(answer: str) -> str:
    """Регистр, лишние пробелы и вид букв не должны мешать вспомнить ответ."""
    return " ".join(unicodedata.normalize("NFKC", answer).casefold().split())


def new_part() -> str:
    text = base64.b32encode(secrets.token_bytes(PART_BYTES)).decode("ascii")
    return " ".join(text[i:i + 4] for i in range(0, len(text), 4))


def _normalize_part(part: str) -> str:
    return "".join(part.split()).upper()


def _derive(answer: str, part: str, salt: bytes, kdf: RecoveryKdf) -> bytes:
    secret = (normalize_answer(answer) + "\n" + _normalize_part(part)).encode("utf-8")
    return hash_secret_raw(
        secret=secret, salt=salt, time_cost=kdf.iterations, memory_cost=kdf.memory_mb * 1024,
        parallelism=kdf.parallelism, hash_len=KEY_BYTES, type=Type.ID, version=ARGON2_VERSION,
    )


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def check_answer(question: str, answer: str) -> None:
    if not question.strip():
        raise WeakAnswer("Нужен контрольный вопрос")
    if len(normalize_answer(answer)) < MIN_ANSWER_CHARS:
        raise WeakAnswer(f"Ответ короче {MIN_ANSWER_CHARS} знаков: нужна длинная фраза, а не имя или дата")
    if normalize_answer(answer) in normalize_answer(question):
        raise WeakAnswer("Ответ не должен быть частью вопроса")


def issue(password: str, question: str, answer: str, kdf: RecoveryKdf = RecoveryKdf()) -> tuple[bytes, str]:
    """Новый файл восстановления и новая часть для письма. Часть вызывающий отправляет и нигде не сохраняет."""
    check_answer(question, answer)
    part = new_part()
    salt = secrets.token_bytes(SALT_BYTES)
    header = {"format": FORMAT, "question": question, "salt": _b64(salt), "memory_mb": kdf.memory_mb,
              "iterations": kdf.iterations, "parallelism": kdf.parallelism}
    cipher = AES.new(_derive(answer, part, salt, kdf), AES.MODE_GCM)
    cipher.update(json.dumps(header, sort_keys=True, ensure_ascii=False).encode("utf-8"))
    body, tag = cipher.encrypt_and_digest(password.encode("utf-8"))
    blob = {**header, "nonce": _b64(cipher.nonce), "tag": _b64(tag), "body": _b64(body)}
    return json.dumps(blob, ensure_ascii=False, indent=1).encode("utf-8"), part


def _load(blob: bytes) -> dict:
    try:
        data = json.loads(blob.decode("utf-8"))
    except ValueError:
        raise RecoveryError("Файл восстановления повреждён") from None
    if not isinstance(data, dict) or data.get("format") != FORMAT:
        raise RecoveryError("Неизвестный формат файла восстановления")
    try:
        if not isinstance(data["question"], str) or not data["question"].strip():
            raise ValueError
        for name, maximum in (("memory_mb", MAX_KDF_MEMORY_MB), ("iterations", MAX_KDF_ITERATIONS),
                              ("parallelism", MAX_KDF_PARALLELISM)):
            value = data[name]
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError
        if data["memory_mb"] * 1024 < 8 * data["parallelism"]:
            raise ValueError
        for name, size in (("salt", SALT_BYTES), ("nonce", 16), ("tag", 16), ("body", None)):
            value = data[name]
            if not isinstance(value, str):
                raise ValueError
            decoded = base64.b64decode(value, validate=True)
            if size is not None and len(decoded) != size:
                raise ValueError
    except (KeyError, ValueError, TypeError):
        raise RecoveryError("Файл восстановления повреждён или параметры шифрования не поддерживаются") from None
    return data


def question_of(blob: bytes) -> str:
    return _load(blob)["question"]


def recover(blob: bytes, answer: str, part: str) -> str:
    """Возвращает пароль хранилища."""
    data = _load(blob)
    try:
        header = {key: data[key] for key in ("format", "question", "salt", "memory_mb", "iterations", "parallelism")}
        kdf = RecoveryKdf(data["memory_mb"], data["iterations"], data["parallelism"])
        salt, nonce, tag, body = (base64.b64decode(data[key]) for key in ("salt", "nonce", "tag", "body"))
    except (KeyError, ValueError):
        raise RecoveryError("Файл восстановления повреждён") from None
    cipher = AES.new(_derive(answer, part, salt, kdf), AES.MODE_GCM, nonce=nonce)
    cipher.update(json.dumps(header, sort_keys=True, ensure_ascii=False).encode("utf-8"))
    try:
        return cipher.decrypt_and_verify(body, tag).decode("utf-8")
    except ValueError:
        raise WrongRecovery("Ответ или часть из письма не подошли") from None
