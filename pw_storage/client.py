"""Обращение к посреднику из скриптов проектов. Только стандартная библиотека: подходит любой Python 3.10+.

    from pw_storage.client import PwClient
    token = PwClient().get("Такси", "login")

Доступ к выбранным строкам общий для всех сессий проекта на срок: pw.py list, затем pw.py open --why "…" <номера>.
Значение получает только вызвавший скрипт. В stderr пишется имя взятого ключа (Т8), само значение — нигде.
Проект определяет посредник по запущенному процессу, а не по словам скрипта.
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
import time
from multiprocessing.connection import Client as _PipeClient

from .config import HOME, PROFILES, PYTHON

BROKER_START_SECONDS = 20
CREATE_NEW_CONSOLE = 0x00000010
CREATE_BREAKAWAY_FROM_JOB = 0x01000000


class PwError(Exception):
    pass


class NeedsAccess(PwError):
    """У проекта нет доступа: нужен запрос через `pw.py open`."""


class NotFound(PwError):
    pass


class BrokerUnavailable(PwError):
    pass


class ProjectUnknown(PwError):
    pass


class TokenConflict(PwError):
    pass


_ERRORS = {"needs_access": NeedsAccess, "not_approved": NeedsAccess, "not_found": NotFound,
           "unknown_rows": NotFound, "project_unknown": ProjectUnknown, "token_conflict": TokenConflict}


class PwClient:
    def __init__(self, profile: str = "main", pipe: str | None = None):
        self.profile = profile
        self.pipe = pipe or PROFILES[profile].pipe

    def _connect(self):
        return _PipeClient(self.pipe, family="AF_PIPE")

    def _call(self, op: str, **fields) -> dict:
        try:
            conn = self._connect()
        except (FileNotFoundError, ConnectionError, OSError) as e:
            raise BrokerUnavailable("Посредник не запущен. Запросите доступ: pw.py open") from e
        with conn:
            try:
                conn.send_bytes(json.dumps({"op": op, **fields}, ensure_ascii=False).encode("utf-8"))
                answer = json.loads(conn.recv_bytes().decode("utf-8"))
            except (EOFError, OSError) as e:
                raise BrokerUnavailable("Посредник не ответил") from e
        if not answer.get("ok"):
            error = answer.get("error", "")
            raise _ERRORS.get(error, PwError)(answer.get("message") or error)
        return answer

    def _start_broker(self) -> None:
        command = [str(PYTHON), "-m", "pw_storage.broker", "--profile", self.profile]
        # Отдельное окно: видно, что посредник работает; закрыл окно — доступы закрыты и файл ушёл из памяти.
        try:
            subprocess.Popen(command, cwd=str(HOME), close_fds=True,
                             creationflags=CREATE_NEW_CONSOLE | CREATE_BREAKAWAY_FROM_JOB)
        except OSError:
            subprocess.Popen(command, cwd=str(HOME), close_fds=True, creationflags=CREATE_NEW_CONSOLE)
        deadline = time.monotonic() + BROKER_START_SECONDS
        while time.monotonic() < deadline:
            try:
                self._connect().close()
                return
            except (FileNotFoundError, ConnectionError, OSError):
                time.sleep(0.2)
        raise BrokerUnavailable("Посредник не запустился")

    def _ensure_broker(self) -> None:
        try:
            self._connect().close()
        except (FileNotFoundError, ConnectionError, OSError):
            self._start_broker()

    def open(self, rows: list[str], why: str = "") -> dict:
        """Запрашивает строки по номерам: посредник показывает окно и ждёт решения владельца.

        Без номеров — только если перечня нет: владелец соберёт его паролем, доступ при этом не выдаётся.
        В ответе rows — номера одобренных строк: владелец мог снять часть отметок.
        """
        self._ensure_broker()
        return self._call("open", rows=list(rows), why=why)

    def preview(self) -> dict:
        """Номера и комментарии строк, которые может запросить проект. Имён ключей и значений здесь нет."""
        self._ensure_broker()
        return self._call("preview")

    def status(self) -> dict:
        return self._call("status")

    def rows(self) -> list[dict]:
        """Одобренные строки: номер, сервис, ключ, комментарий, all — пришла из ALL. Значений здесь нет."""
        return self._call("list")["rows"]

    def report(self) -> list[dict]:
        """Какие ключи сессии проекта уже взяли (Т8)."""
        return self._call("report")["issued"]

    def close(self) -> dict:
        return self._call("close")

    def get(self, service: str, key: str) -> str:
        answer = self._call("get", service=service, key=key)
        print(f"[PW_STORAGE] взят ключ: {service} / {key} (строка {answer['id']})", file=sys.stderr)
        return answer["value"]

    def get_attachment(self, service: str, key: str, name: str) -> bytes:
        """Возвращает вложение разрешённой строки в память, без записи на диск."""
        answer = self._call("get_attachment", service=service, key=key, name=name)
        data = base64.b64decode(answer["data"], validate=True)
        try:
            print(f"[PW_STORAGE] взято вложение: {service} / {key} / {name} (строка {answer['id']})", file=sys.stderr)
        except (OSError, ValueError):
            pass
        return data

    def save_token(self, service: str, key: str, value: str, *, expected: str) -> dict:
        """Заменяет разрешённое значение только при совпадении с expected; срок доступа не продлевается."""
        answer = self._call("save_token", service=service, key=key, value=value, expected=expected)
        try:
            print(f"[PW_STORAGE] сохранён токен: {service} / {key} (строка {answer['id']})", file=sys.stderr)
        except (OSError, ValueError):
            answer["warnings"].append("Токен записан; диагностический вывод клиента недоступен")
        return answer
