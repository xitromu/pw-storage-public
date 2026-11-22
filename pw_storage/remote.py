"""Доступ через бота, когда владелец не у ПК (Т14): отдельный код с приставкой pw вместо пароля хранилища.

Пароль хранилища зашифрован ключом TPM, защищённым этим кодом. Перехваченный код бесполезен без этого ПК,
а файл из Google он не открывает. Сообщение с кодом бот сразу удаляет. Код из цифр: так сообщение
безошибочно отличается от обычного текста.
"""

from __future__ import annotations

import json
import math
import os
import re
import secrets
import sys
import time
import tempfile
from contextlib import contextmanager
from pathlib import Path

from .second_factor import ChannelLifecycle, DENY, NoLink, POLL_TIMEOUT_SECONDS, TELEGRAM_TEXT_LIMIT, common_title, request_head
from .tpm import TpmError, seal, unseal

MIN_CODE_DIGITS = 8
CODE_MESSAGE = re.compile(r"^\s*pw\s*([0-9]{8,})\s*$", re.IGNORECASE | re.ASCII)
LOCK_SECONDS = 60
BUTTON_CHARS = 40
WAIT_TEXT = "Если вы за ПК, введите пароль в окне.\nЖду ответа, если не за ПК: pw и ваш код, одним сообщением."


class WrongCode(Exception):
    pass


def valid_code(code: str) -> bool:
    return code.isascii() and code.isdigit() and len(code) >= MIN_CODE_DIGITS


def enroll(key, path: Path, password: str) -> None:
    """Ключ с кодом создаётся заново: старый код перестаёт действовать. Около 8 секунд."""
    if key.exists():
        key.delete()
    key.create()
    path = Path(path)
    new = path.with_name(path.name + ".new")
    new.write_bytes(seal(key, password.encode("utf-8")))
    os.replace(new, path)


def forget(key, path: Path) -> None:
    Path(path).unlink(missing_ok=True)
    if key.exists():
        key.delete()


def read_password(key, path: Path) -> str:
    try:
        return unseal(key, Path(path).read_bytes()).decode("utf-8")
    except (TpmError, OSError, ValueError):
        raise WrongCode("Код не подошёл") from None


class QueueLock:
    """Пока ждём ответа, второй опросчик того же бота очередь не читает. После сбоя запрет истекает сам."""

    def __init__(self, path: Path, clock=time.time, seconds=LOCK_SECONDS):
        self.path = Path(path)
        self.clock = clock
        self.seconds = seconds
        self.token = secrets.token_hex(24)
        self._acquired = False

    @contextmanager
    def _guard(self):
        # Keep the guard inode stable so waiters lock the same file.
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.with_name(self.path.name + ".guard").open("a+b") as guard:
            guard.seek(0, os.SEEK_END)
            if guard.tell() == 0:
                guard.write(b"\0")
                guard.flush()
            guard.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(guard.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(guard.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                yield
            finally:
                guard.seek(0)
                if os.name == "nt":
                    msvcrt.locking(guard.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(guard.fileno(), fcntl.LOCK_UN)

    def _read(self):
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if (not isinstance(data, dict) or type(data.get("until")) not in (int, float)
                    or not math.isfinite(data["until"])):
                raise RuntimeError("invalid queue lease")
            return data
        except FileNotFoundError:
            return {}
        except (ValueError, TypeError):
            raise RuntimeError("invalid queue lease") from None

    def _owned(self, data):
        return data.get("token") == self.token and data.get("until", 0) > self.clock()

    def refresh(self, token: str | None = None) -> str:
        """Acquire/renew; retain the returned token for request-specific cleanup."""
        with self._guard():
            data = self._read()
            if token is not None and (token != self.token or not self._acquired):
                raise RuntimeError("queue lease lost")
            if self._acquired:
                if not self._owned(data):
                    raise RuntimeError("queue lease lost")
            elif data.get("until", 0) > self.clock():
                raise RuntimeError("queue lease busy")
            else:
                self.token = secrets.token_hex(24)  # a new acquisition is a new lease
            fd, name = tempfile.mkstemp(prefix=self.path.name + ".", suffix=".new", dir=self.path.parent)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as new:
                    json.dump({"until": self.clock() + self.seconds, "owner": "PW_STORAGE", "token": self.token}, new)
                os.replace(name, self.path)
                self._acquired = True
                return self.token
            finally:
                Path(name).unlink(missing_ok=True)

    def release(self, token: str | None = None, *, before_release=None) -> bool:
        with self._guard():
            if token is not None and token != self.token:
                return False
            if not self._acquired:
                return False
            if not self._owned(self._read()):
                self._acquired = False  # abandon only our local handle, never the successor's file
                return False
            if before_release is not None:
                before_release()
            self.path.unlink(missing_ok=True)
            self._acquired = False
            return True


class RemoteListener(ChannelLifecycle):
    """Сообщение со списком строк, отметки кнопками (вариант Б) и ожидание кода.

    Код подтверждает строки, отмеченные в сообщении на момент его прихода. Очередь только просматривается,
    чужое в ней остаётся; каждое нажатие учитывается один раз.
    """

    channel_name = "Telegram"

    def __init__(self, api, project: str, hours: int, own: list[tuple[str, str]], common: list[tuple[str, str]],
                 why: str = "", test: bool = False, clock=time.time):
        super().__init__()
        self._baseline: int | None = None
        self._boundary_date: int | None = None
        self._frozen: tuple[str, ...] | None = None
        self._deletions: dict[str, int] = {}
        self._failed_deletions: set[str] = set()
        self._acks: dict[str, int] = {}
        self.api = api
        self.project = project
        self.hours = hours
        self.why = why
        self.test = test
        self.clock = clock
        self.rows = [*own, *common]  # (номер строки, комментарий)
        self.own_count = len(own)
        self.marked = [True] * len(self.rows)
        self.nonce = secrets.token_urlsafe(12)
        self.message_id: int | str | None = None
        self.started: float | None = None
        self._seen: set[int] = set()
        self._seen_callbacks: set[str] = set()
        self._pending_events: list[dict] = []

    def chosen(self) -> list[str]:
        with self._operations:
            if self._frozen is not None:
                return list(self._frozen)
            return [uid for (uid, _), marked in zip(self.rows, self.marked) if marked]

    def _line(self, index: int) -> str:
        return f"{'✅' if self.marked[index] else '⬜'} {index + 1}. {self.rows[index][1]}"

    def _text(self, status: str) -> str:
        lines = request_head(self.project, self.hours, self.why, self.test)
        for title, indexes in ((f"Проект {self.project}", range(self.own_count)),
                               (common_title(self.project), range(self.own_count, len(self.rows)))):
            if indexes:
                lines += ["", title + ":"]
                lines += [self._line(i) for i in indexes]
        return "\n".join([*lines, "", "Кнопками снимите лишние строки: выдаются только отмеченные.", status])

    def _keyboard(self) -> str:
        buttons = []
        for i, (_, comment) in enumerate(self.rows):
            label = comment if len(comment) <= BUTTON_CHARS else comment[:BUTTON_CHARS - 1] + "…"
            prefix = "ALL: " if i >= self.own_count else ""
            buttons.append([{"text": f"{'✅' if self.marked[i] else '⬜'} {i + 1}. {prefix}{label}",
                             "callback_data": f"pw:{self.nonce}:t{i}"}])
        buttons.append([{"text": "Отказать", "callback_data": f"pw:{self.nonce}:{DENY}"}])
        return json.dumps({"inline_keyboard": buttons}, ensure_ascii=False)

    def fits(self) -> bool:
        return len(self._text("x" * 200)) <= TELEGRAM_TEXT_LIMIT

    def start(self) -> None:
        with self._operations:
            if self._cancelled.is_set() or self.message_id is not None:
                return
            if self.started is None:
                self.started = self.clock()  # stable, including retries of the baseline/send
            if self._baseline is None:
                updates = self.api.call("getUpdates", {"timeout": "0"}, POLL_TIMEOUT_SECONDS).get("result", [])
                self._baseline = max((u.get("update_id", -1) for u in updates
                                      if isinstance(u.get("update_id"), int)), default=-1)
            if self._cancelled.is_set():
                return
            answer = self.api.call("sendMessage", {"chat_id": self.api.chat, "text": self._text(WAIT_TEXT),
                                                   "reply_markup": self._keyboard()})
            self._set_prompt_boundary(answer["result"])

    def _set_prompt_boundary(self, result: dict) -> None:
        self.message_id = result["message_id"]
        self._boundary_date = result.get("date", int(self.started))

    def _owner(self, part: dict) -> bool:
        sender = part.get("from")
        return isinstance(sender, dict) and str(sender.get("id")) == str(self.api.chat)

    def _resolve_message(self, update: dict, accept: bool) -> dict | None:
        """Telegram already carries text; journal-backed channels resolve metadata in memory."""
        message = update.get("message")
        if not isinstance(message, dict) or not isinstance(message.get("text"), str):
            return None
        if not CODE_MESSAGE.match(message["text"]) or not self._owner(message):
            return None
        chat = message.get("chat")
        if not isinstance(chat, dict) or str(chat.get("id")) != str(self.api.chat):
            return None
        self._deletions.setdefault(str(message.get("message_id")), 0)
        return message

    def _fresh_message(self, update: dict, message: dict) -> bool:
        return (update["update_id"] > self._baseline
                and message.get("date", 0) > self._boundary_date
                and isinstance(message.get("message_id"), int)
                and message["message_id"] > self.message_id)

    def poll(self) -> str | None:
        with self._operations:
            if self._cancelled.is_set() or self.message_id is None:
                return None
            return self._poll()

    def _retry_pending(self, pending: dict, method: str, field: str, *, only: str | None = None) -> None:
        items = [(only, pending[only])] if only is not None else list(pending.items())
        for identifier, attempts in items:
            fields = {field: identifier}
            if method == "deleteMessage":
                fields["chat_id"] = self.api.chat
            try:
                self.api.call(method, fields)
            except NoLink:
                if attempts + 1 < 3:
                    pending[identifier] = attempts + 1
                    continue
                if method == "deleteMessage":
                    self._failed_deletions.add(identifier)
            except Exception:
                if method == "deleteMessage":
                    self._failed_deletions.add(identifier)
            pending.pop(identifier, None)

    def _retry_cosmetics(self) -> None:
        self._retry_pending(self._acks, "answerCallbackQuery", "callback_query_id")
        self._retry_pending(self._deletions, "deleteMessage", "message_id")

    def _poll(self) -> str | None:
        found = None
        denied = False
        toggled = False
        try:
            updates = self.api.call("getUpdates", {"timeout": "0"}, POLL_TIMEOUT_SECONDS).get("result", [])
        except NoLink:
            if not self._pending_events:
                raise
            updates = []  # consumed journal markers still have their own finite fetch budget
        if self._cancelled.is_set():
            return None
        queued = {u["update_id"] for u in self._pending_events}
        updates = [u for u in updates if isinstance(u, dict) and type(u.get("update_id")) is int]
        for update in sorted(updates, key=lambda u: u["update_id"]):
            uid = update["update_id"]
            if uid not in self._seen and uid not in queued:
                self._pending_events.append(update)
                queued.add(uid)
        events, self._pending_events = self._pending_events, []
        for index, update in enumerate(events):
            if self._cancelled.is_set():
                break
            uid = update["update_id"]
            if uid in self._seen:
                continue
            query = update.get("callback_query")
            if isinstance(query, dict):
                prefix = f"pw:{self.nonce}:"
                data = query.get("data")
                callback_id = query.get("id")
                self._seen.add(uid)
                if (not self._owner(query) or not isinstance(data, str) or not data.startswith(prefix)
                        or not isinstance(callback_id, str) or not callback_id
                        or callback_id in self._seen_callbacks):
                    continue
                self._seen_callbacks.add(callback_id)
                self._acks.setdefault(callback_id, 0)
                action = data[len(prefix):]
                if found is not None or denied or update.get("_ignore_code"):
                    continue
                if action == DENY:
                    denied = True
                elif (self._frozen is None and action[:1] == "t" and action[1:].isascii()
                      and action[1:].isdigit() and int(action[1:]) < len(self.rows)):
                    self.marked[int(action[1:])] = not self.marked[int(action[1:])]
                    toggled = True
                continue
            accept = found is None and not denied and not update.get("_ignore_code")
            try:
                message = self._resolve_message(update, accept=accept)
            except NoLink:
                # Keep event order and the marks preceding the failed fetch, without keeping code text.
                self._pending_events = events[index:]
                if found is not None or denied:
                    self._pending_events = [dict(event, _ignore_code=True) for event in self._pending_events]
                break
            self._seen.add(uid)
            if message is None:
                continue
            match = CODE_MESSAGE.match(message.get("text") or "")
            if accept and match and self._fresh_message(update, message):
                found = match.group(1)
                if self._frozen is None:
                    self._frozen = tuple(uid for (uid, _), marked in zip(self.rows, self.marked) if marked)
        self._retry_cosmetics()
        if self._cancelled.is_set():
            return None
        if found is not None:
            return found
        if denied:
            return DENY
        if toggled:
            try:
                self.say(WAIT_TEXT, keep_buttons=True)
            except Exception:
                pass  # an edit is cosmetic, never a decision retry
        return None

    def say(self, status: str, keep_buttons: bool = False) -> None:
        """Без keep_buttons кнопки убираются: запрос закрыт, нажатия больше ни на что не влияют."""
        with self._operations:
            if self.message_id is None or keep_buttons and self._cancelled.is_set():
                return
            if not keep_buttons:
                self.cancel()
            # Cleanup has its own finite budget, independent of decision delivery.
            for _ in range(3):
                if not self._deletions and not self._acks:
                    break
                self._retry_cosmetics()
            if self._failed_deletions:
                warning = "Удаление сообщения с кодом не подтверждено. Проверь переписку и удали его вручную."
                status = f"{status}\n\n{warning}"
                if not keep_buttons:
                    try:
                        print(f"[PW_STORAGE][{self.channel_name}] {warning}", file=sys.stderr)
                    except (OSError, ValueError):
                        pass
            fields = {"chat_id": self.api.chat, "message_id": str(self.message_id), "text": self._text(status)}
            if keep_buttons:
                fields["reply_markup"] = self._keyboard()
            self.api.call("editMessageText", fields)
