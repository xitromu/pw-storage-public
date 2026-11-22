"""Подтверждение с телефона (Т21): кнопка в своём Telegram-боте, при отсутствии связи — код из приложения.

getUpdates вызывается без offset: очередь только просматривается, прочитанное не исчезает.
Так каналу не мешает другой опросчик того же бота; если он есть, посредник бережёт очередь
файлом-запретом (telegram_queue_lock в settings.json).
"""

from __future__ import annotations

import http.client
import json
import secrets
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import pyotp


API_URL = "https://api.telegram.org/bot{token}/{method}"
API_FALLBACK_IP = "149.154.167.220"  # запасной адрес api.telegram.org: прокси и DNS иногда не отдают имя
API_TIMEOUT_SECONDS = 20
POLL_TIMEOUT_SECONDS = 8  # через VPN запрос иногда зависает: опрос не должен ждать его долго, следующий пройдёт
TELEGRAM_TEXT_LIMIT = 4096
ALLOW = "allow"
DENY = "deny"
TOTP_DIGITS = 6
TOTP_WINDOW = 1  # код соседнего интервала: часы телефона и ПК могут расходиться


def new_totp_secret() -> str:
    return pyotp.random_base32(length=32)


def totp_uri(secret: str, account: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=account, issuer_name="PW_STORAGE")


class Totp:
    """Проверка кода. Принятый код повторно не проходит."""

    def __init__(self, secret: str, clock=time.time):
        self._totp = pyotp.TOTP(secret)
        self._clock = clock
        self._last_used: int | None = None

    def verify(self, code: str) -> bool:
        code = "".join(code.split())
        if len(code) != TOTP_DIGITS or not code.isdigit():
            return False
        now = int(self._clock())
        step = self._totp.interval
        for offset in range(-TOTP_WINDOW, TOTP_WINDOW + 1):
            moment = now + offset * step
            counter = moment // step
            if self._last_used is not None and counter <= self._last_used:
                continue
            if secrets.compare_digest(self._totp.at(moment), code):
                self._last_used = counter
                return True
        return False


class NoLink(RuntimeError):
    """Запрос не дошёл до Telegram, в отличие от отказа самого Telegram."""


def _direct_opener():
    """Без прокси из окружения: посредник, запущенный из чужой консоли, наследует её HTTP(S)_PROXY,
    и Telegram через такой прокси не проходит (обрыв TLS). Ходим напрямую."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _pinned_opener(ip: str):
    """Соединение с запасным адресом, но имя и сертификат проверяются как для api.telegram.org."""
    class Connection(http.client.HTTPSConnection):
        def connect(self):
            self.sock = socket.create_connection((ip, self.port), self.timeout, self.source_address)
            self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)

    class Handler(urllib.request.HTTPSHandler):
        def https_open(self, req):
            return self.do_open(Connection, req, context=self._context, check_hostname=self._check_hostname)

    return urllib.request.build_opener(urllib.request.ProxyHandler({}), Handler())


class BotApi:
    """Вызовы бота прямо из этого процесса: токен не передаётся другим программам и никуда не выводится.

    HTTPS идёт через urllib, а не через curl: системный curl иногда не определяет имя api.telegram.org,
    хотя связь работает. Окно подтверждения от этого зависеть не должно.
    """

    def __init__(self, token: str, chat: str):
        self._token = token
        self.chat = chat
        self._opener = _direct_opener()
        self._pinned = _pinned_opener(API_FALLBACK_IP)

    def call(self, method: str, fields: dict[str, str], timeout: int = API_TIMEOUT_SECONDS) -> dict:
        url = API_URL.format(token=self._token, method=method)
        data = urllib.parse.urlencode(fields).encode("utf-8")
        # В адресе запроса ключ, поэтому исходные исключения не пробрасываем: только вид ошибки.
        try:
            answer = self._fetch(url, data, timeout)
        except urllib.error.HTTPError as e:
            kind = NoLink if e.code == 429 or e.code >= 500 else RuntimeError
            raise kind(f"Telegram: HTTP {e.code}") from None
        except (OSError, ValueError) as e:
            raise NoLink(f"нет связи с Telegram: {type(e).__name__}") from None
        if not answer.get("ok"):
            code = answer.get("error_code", 0)
            kind = NoLink if code == 429 or isinstance(code, int) and code >= 500 else RuntimeError
            raise kind(f"Telegram: {code}")
        return answer

    def _fetch(self, url: str, data: bytes, timeout: int) -> dict:
        try:
            with self._opener.open(url, data=data, timeout=timeout) as response:
                return json.load(response)
        except urllib.error.HTTPError:
            raise
        except urllib.error.URLError as e:
            if not isinstance(e.reason, socket.gaierror):
                raise
            # DNS не отдал имя api.telegram.org: пробуем запасной адрес с проверкой сертификата.
            with self._pinned.open(url, data=data, timeout=timeout) as response:
                return json.load(response)


def request_head(project: str, hours: int, why: str, test: bool) -> list[str]:
    mark = " (ТЕСТ)" if test else ""
    return [f"Проект: PW_STORAGE{mark}", f"Проект {project} просит на {hours} ч. доступ к этим секретам для всех своих сессий:",
            f"Зачем, со слов сессии (не проверено): {why or 'не указано'}"]


def common_title(project: str) -> str:
    return f"Из ALL (одобрение добавит {project} в список записи)"


class ChannelLifecycle:
    """Slow operations serialize on workers; cancellation never waits for that lock."""

    def __init__(self):
        self._operations = threading.RLock()
        self._cancelled = threading.Event()
        self._closed = False

    def cancel(self) -> None:
        self._cancelled.set()


class TelegramConfirm(ChannelLifecycle):
    """Кнопка подтверждения. В сообщении перечислены строки, отмеченные в окне: выдаются именно они (Т23)."""

    def __init__(self, api, project: str, hours: int, own: list[str], common: list[str], why: str = "",
                 test: bool = False):
        super().__init__()
        self._seen_callbacks: set[str] = set()
        self.api = api
        self.project = project
        self.hours = hours
        self.own = own
        self.common = common
        self.why = why
        self.test = test
        self.nonce = secrets.token_urlsafe(12)
        self.message_id: int | None = None

    def _text(self, status: str) -> str:
        lines = request_head(self.project, self.hours, self.why, self.test)
        for title, comments in ((f"Проект {self.project}", self.own), (common_title(self.project), self.common)):
            if comments:
                lines += ["", title + ":"]
                lines += [f"• {comment}" for comment in comments]
        if not self.own and not self.common:
            lines += ["", "Строк нет."]
        return "\n".join([*lines, "", "Только эти строки и будут выданы.", status])

    def fits(self) -> bool:
        """Список не обрезаем: иначе подтверждение покрывало бы то, чего владелец не видел."""
        return len(self._text("Жду ответа: разрешить или отказать кнопкой\nОтвет не нужен")) <= TELEGRAM_TEXT_LIMIT

    def start(self) -> None:
        with self._operations:
            if self._cancelled.is_set() or self.message_id is not None:
                return
            self._start()

    def _start(self) -> None:
        keyboard = {"inline_keyboard": [[
            {"text": "Разрешить", "callback_data": f"pw:{self.nonce}:{ALLOW}"},
            {"text": "Отказать", "callback_data": f"pw:{self.nonce}:{DENY}"},
        ]]}
        answer = self.api.call("sendMessage", {
            "chat_id": self.api.chat,
            "text": self._text("Жду ответа: разрешить или отказать кнопкой"),
            "reply_markup": json.dumps(keyboard, ensure_ascii=False),
        })
        self.message_id = answer["result"]["message_id"]

    def poll(self) -> str | None:
        """ALLOW, DENY or None; ACK failure cannot undo a verified decision."""
        with self._operations:
            if self._cancelled.is_set() or self.message_id is None:
                return None
            return self._poll()

    def _poll(self) -> str | None:
        updates = self.api.call("getUpdates", {"timeout": "0"}, POLL_TIMEOUT_SECONDS).get("result", [])
        if self._cancelled.is_set():
            return None
        for update in updates:
            query = update.get("callback_query")
            if not isinstance(query, dict):
                continue
            if str((query.get("from") or {}).get("id")) != str(self.api.chat):
                continue
            for result in (ALLOW, DENY):
                if query.get("data") == f"pw:{self.nonce}:{result}":
                    callback_id = query.get("id")
                    if not isinstance(callback_id, str) or callback_id in self._seen_callbacks:
                        continue
                    self._seen_callbacks.add(callback_id)
                    try:
                        self.api.call("answerCallbackQuery", {"callback_query_id": query["id"]})
                    except RuntimeError:
                        pass  # Подтверждение доставки кнопке не должно отменять уже проверенное решение.
                    return result
        return None

    def finish(self, status: str) -> None:
        self.cancel()
        with self._operations:
            if self._closed:
                return
            self._closed = True
            if self.message_id is None:
                return
            self.api.call("editMessageText", {
                "chat_id": self.api.chat,
                "message_id": str(self.message_id),
                "text": self._text(status + "\nОтвет не нужен"),
            })
