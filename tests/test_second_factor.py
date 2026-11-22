"""Код из приложения и кнопка Telegram. Telegram подменён: настоящих запросов здесь нет."""

import io
import json
import os
import socket
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from unittest import mock

import pyotp

from pw_storage.second_factor import (
    ALLOW,
    DENY,
    POLL_TIMEOUT_SECONDS,
    BotApi,
    NoLink,
    TelegramConfirm,
    Totp,
    new_totp_secret,
    totp_uri,
)


class TotpTest(unittest.TestCase):
    def setUp(self):
        self.secret = new_totp_secret()
        self.now = 1_800_000_000
        self.totp = Totp(self.secret, clock=lambda: self.now)
        self.code = pyotp.TOTP(self.secret).at(self.now)

    def test_secret_is_long_enough(self):
        self.assertEqual(len(self.secret), 32)

    def test_correct_code(self):
        self.assertTrue(self.totp.verify(self.code))

    def test_spaces_are_ignored(self):
        self.assertTrue(self.totp.verify(self.code[:3] + " " + self.code[3:]))

    def test_wrong_code(self):
        wrong = "000000" if self.code != "000000" else "111111"
        self.assertFalse(self.totp.verify(wrong))

    def test_malformed(self):
        for code in ("", "12345", "1234567", "abcdef"):
            self.assertFalse(self.totp.verify(code))

    def test_code_cannot_be_reused(self):
        self.assertTrue(self.totp.verify(self.code))
        self.assertFalse(self.totp.verify(self.code))

    def test_neighbour_interval_accepted(self):
        self.assertTrue(self.totp.verify(pyotp.TOTP(self.secret).at(self.now - 30)))

    def test_old_code_refused(self):
        self.assertFalse(self.totp.verify(pyotp.TOTP(self.secret).at(self.now - 300)))

    def test_uri_names_the_tool(self):
        self.assertIn("PW_STORAGE", totp_uri(self.secret, "test"))


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class BotApiTest(unittest.TestCase):
    TOKEN = "TEST-TOKEN-VALUE"

    def setUp(self):
        self.api = BotApi(self.TOKEN, "42")

    def _call_with(self, side_effect=None, body=None):
        answer = None if body is None else _Response(json.dumps(body).encode())
        with mock.patch.object(self.api._opener, "open", side_effect=side_effect, return_value=answer) as opened:
            return self.api.call("sendMessage", {"chat_id": "42", "text": "Привет & пока"}), opened

    def test_posts_form_to_method(self):
        result, opened = self._call_with(body={"ok": True, "result": 1})
        self.assertEqual(result["result"], 1)
        url = opened.call_args.args[0]
        self.assertTrue(url.startswith("https://api.telegram.org/bot"))
        self.assertTrue(url.endswith("/sendMessage"))
        form = urllib.parse.parse_qs(opened.call_args.kwargs["data"].decode())
        self.assertEqual(form["text"], ["Привет & пока"])

    def _assert_fails_without_token(self, kind, **call):
        with self.assertRaises(kind) as caught:
            self._call_with(**call)
        self.assertNotIn(self.TOKEN, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertTrue(caught.exception.__context__ is None or caught.exception.__suppress_context__)

    def test_no_connection(self):
        self._assert_fails_without_token(NoLink, side_effect=urllib.error.URLError("сбой"))

    def test_timeout(self):
        self._assert_fails_without_token(NoLink, side_effect=TimeoutError())

    def test_http_error_hides_address(self):
        url = f"https://api.telegram.org/bot{self.TOKEN}/sendMessage"
        error = urllib.error.HTTPError(url, 401, "Unauthorized", None, io.BytesIO(b"{}"))
        self._assert_fails_without_token(RuntimeError, side_effect=error)

    def test_refusal_from_telegram(self):
        self._assert_fails_without_token(RuntimeError, body={"ok": False, "error_code": 400})

    def test_transient_http_and_api_errors_are_nolink(self):
        for code in (429, 503):
            error = urllib.error.HTTPError("https://synthetic", code, "later", None, io.BytesIO(b"{}"))
            self._assert_fails_without_token(NoLink, side_effect=error)
            self._assert_fails_without_token(NoLink, body={"ok": False, "error_code": code})

    def test_garbage_answer(self):
        with mock.patch.object(self.api._opener, "open", return_value=_Response(b"<html>")):
            with self.assertRaises(NoLink):
                self.api.call("getUpdates", {})

    def test_env_proxies_are_not_used(self):
        """Посредник из чужой консоли наследует её прокси: Telegram через них не проходит."""
        with mock.patch.dict(os.environ, {"HTTP_PROXY": "http://127.0.0.1:1", "HTTPS_PROXY": "http://127.0.0.1:1"}):
            api = BotApi(self.TOKEN, "42")
        for opener in (api._opener, api._pinned):
            # Пустой ProxyHandler вытесняет читающий окружение и сам не регистрируется: прокси в opener нет.
            self.assertFalse(any(isinstance(h, urllib.request.ProxyHandler) for h in opener.handlers))

    def test_dns_failure_falls_back_to_pinned_address(self):
        body = _Response(json.dumps({"ok": True, "result": 7}).encode())
        dns_fail = urllib.error.URLError(socket.gaierror(11002, "getaddrinfo failed"))
        with mock.patch.object(self.api._opener, "open", side_effect=dns_fail), \
                mock.patch.object(self.api._pinned, "open", return_value=body) as pinned:
            result = self.api.call("sendMessage", {"chat_id": "42"})
        self.assertEqual(result["result"], 7)
        self.assertTrue(pinned.call_args.args[0].startswith("https://api.telegram.org/bot"))

    def test_other_link_errors_do_not_use_pinned_address(self):
        with mock.patch.object(self.api._opener, "open", side_effect=urllib.error.URLError("сбой")), \
                mock.patch.object(self.api._pinned, "open") as pinned:
            with self.assertRaises(NoLink):
                self.api.call("getUpdates", {})
        pinned.assert_not_called()


class FakeApi:
    chat = "42"

    def __init__(self):
        self.calls = []
        self.updates = []
        self.fail = None

    def call(self, method, fields, timeout=None):
        if self.fail:
            raise self.fail
        self.calls.append((method, fields))
        if method == "sendMessage":
            return {"result": {"message_id": 7}}
        if method == "getUpdates":
            return {"result": self.updates}
        return {"result": True}

    def methods(self):
        return [m for m, _ in self.calls]


class TelegramTest(unittest.TestCase):
    def setUp(self):
        self.api = FakeApi()
        self.confirm = TelegramConfirm(self.api, "DELTA", 12, ["Логин Такси", "Токен Pandora"], ["Ключ погоды"])
        self.confirm.start()

    def _press(self, data, user="42"):
        self.api.updates = [{"update_id": 1, "callback_query": {"id": "q1", "from": {"id": user}, "data": data}}]

    def test_message_follows_house_format(self):
        text = self.api.calls[0][1]["text"].split("\n")
        self.assertEqual(text[0], "Проект: PW_STORAGE")
        self.assertIn("DELTA", text[1])
        self.assertIn("для всех своих сессий", text[1])
        self.assertTrue(text[-1].startswith("Жду ответа"))

    def test_message_lists_exact_rows(self):
        text = self.api.calls[0][1]["text"]
        self.assertIn("Проект DELTA:\n• Логин Такси\n• Токен Pandora", text)
        self.assertIn("Из ALL (одобрение добавит DELTA в список записи):\n• Ключ погоды", text)
        self.assertIn("Зачем, со слов сессии (не проверено): не указано", text)
        self.assertIn("Только эти строки и будут выданы.", text)

    def test_edited_message_keeps_the_list(self):
        self.confirm.finish("Доступ разрешён")
        text = self.api.calls[-1][1]["text"]
        self.assertIn("• Логин Такси", text)
        self.assertIn("Доступ разрешён", text)

    def test_empty_group_is_omitted(self):
        confirm = TelegramConfirm(self.api, "DELTA", 12, ["Логин"], [])
        confirm.start()
        self.assertNotIn("Общие (ALL)", self.api.calls[-1][1]["text"])

    def test_no_rows_is_stated(self):
        confirm = TelegramConfirm(self.api, "DELTA", 12, [], [])
        confirm.start()
        self.assertIn("Строк нет.", self.api.calls[-1][1]["text"])

    def test_long_list_does_not_fit_and_is_not_cut(self):
        self.assertTrue(self.confirm.fits())
        long_list = [f"Комментарий номер {i}: достаточно длинный текст строки" for i in range(200)]
        self.assertFalse(TelegramConfirm(self.api, "DELTA", 12, long_list, []).fits())

    def test_poll_uses_short_timeout(self):
        calls = []
        self.api.call = lambda method, fields, timeout=None: calls.append(timeout) or {"result": []}
        self.confirm.poll()
        self.assertEqual(calls, [POLL_TIMEOUT_SECONDS])

    def test_buttons_carry_nonce(self):
        markup = json.loads(self.api.calls[0][1]["reply_markup"])["inline_keyboard"][0]
        self.assertEqual([b["text"] for b in markup], ["Разрешить", "Отказать"])
        self.assertIn(self.confirm.nonce, markup[0]["callback_data"])
        self.assertLessEqual(len(markup[0]["callback_data"].encode()), 64)

    def test_allow(self):
        self._press(f"pw:{self.confirm.nonce}:allow")
        self.assertEqual(self.confirm.poll(), ALLOW)
        self.assertIn("answerCallbackQuery", self.api.methods())

    def test_deny(self):
        self._press(f"pw:{self.confirm.nonce}:deny")
        self.assertEqual(self.confirm.poll(), DENY)

    def test_acknowledgement_failure_does_not_lose_decision(self):
        original = self.api.call

        def call(method, fields, timeout=None):
            if method == "answerCallbackQuery":
                raise NoLink("нет связи")
            return original(method, fields, timeout)

        self.api.call = call
        for decision in (ALLOW, DENY):
            with self.subTest(decision=decision):
                self._press(f"pw:{self.confirm.nonce}:{decision}")
                self.api.updates[0]["callback_query"]["id"] = decision
                self.assertEqual(self.confirm.poll(), decision)

    def test_poll_failure_still_requires_retry(self):
        self.api.fail = NoLink("нет связи")
        with self.assertRaises(NoLink):
            self.confirm.poll()

    def test_nothing_pressed(self):
        self.assertIsNone(self.confirm.poll())

    def test_other_user_is_ignored(self):
        self._press(f"pw:{self.confirm.nonce}:allow", user="99")
        self.assertIsNone(self.confirm.poll())

    def test_other_request_is_ignored(self):
        self._press("pw:another-request:allow")
        self.assertIsNone(self.confirm.poll())

    def test_ordinary_messages_are_skipped(self):
        self.api.updates = [{"update_id": 1, "message": {"text": "привет", "from": {"id": 42}, "chat": {"id": 42}}}]
        self.assertIsNone(self.confirm.poll())

    def test_queue_is_never_confirmed(self):
        # С offset Telegram удалил бы чужие сообщения из общей очереди бота.
        self.confirm.poll()
        for method, fields in self.api.calls:
            if method == "getUpdates":
                self.assertNotIn("offset", fields)
                self.assertNotIn("allowed_updates", fields)

    def test_finish_edits_message(self):
        self.confirm.finish("Разрешено")
        method, fields = self.api.calls[-1]
        self.assertEqual(method, "editMessageText")
        self.assertEqual(fields["message_id"], "7")
        self.assertEqual(fields["text"].split("\n")[-1], "Ответ не нужен")

    def test_test_profile_is_marked(self):
        confirm = TelegramConfirm(self.api, "DELTA", 12, [], [], test=True)
        confirm.start()
        self.assertIn("ТЕСТ", self.api.calls[-1][1]["text"].split("\n")[0])

    def test_duplicate_callback_is_not_accepted_again(self):
        self._press(f"pw:{self.confirm.nonce}:allow")
        self.assertEqual(self.confirm.poll(), ALLOW)
        self.assertIsNone(self.confirm.poll())
        self.assertEqual(self.api.methods().count("answerCallbackQuery"), 1)

    def test_cancel_and_finish_are_final_and_idempotent(self):
        self.confirm.finish("cancelled")
        count = len(self.api.calls)
        self.confirm.start()
        self._press(f"pw:{self.confirm.nonce}:allow")
        self.assertIsNone(self.confirm.poll())
        self.confirm.finish("again")
        self.assertEqual(len(self.api.calls), count)

    def test_cancel_blocked_start_serializes_cleanup_without_gui_wait(self):
        api = FakeApi()
        confirm = TelegramConfirm(api, "DEMO", 1, [], [])
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        calls = []
        def call(method, fields, timeout=None):
            calls.append(method)
            if method == "sendMessage":
                entered.set()
                if not release.wait(5):
                    raise AssertionError("barrier timeout")
                calls.append("send_return")
                return {"result": {"message_id": 7}}
            return {"result": []}
        api.call = call
        start = threading.Thread(target=confirm.start)
        start.start()
        self.assertTrue(entered.wait(5))
        confirm.cancel()
        def finish():
            confirm.finish("cancelled")
            finished.set()
        close = threading.Thread(target=finish)
        close.start()
        self.assertFalse(finished.is_set())
        release.set()
        start.join(5)
        close.join(5)
        self.assertTrue(finished.is_set())
        confirm.start()
        self.assertEqual(calls, ["sendMessage", "send_return", "editMessageText"])

    def test_cancel_blocked_poll_discards_approval(self):
        entered, release = threading.Event(), threading.Event()
        self._press(f"pw:{self.confirm.nonce}:allow")
        original = self.api.call
        def call(method, fields, timeout=None):
            if method == "getUpdates":
                entered.set()
                if not release.wait(5):
                    raise AssertionError("barrier timeout")
            return original(method, fields, timeout)
        self.api.call = call
        results = []
        worker = threading.Thread(target=lambda: results.append(self.confirm.poll()))
        worker.start()
        self.assertTrue(entered.wait(5))
        self.confirm.cancel()
        release.set()
        worker.join(5)
        self.assertEqual(results, [None])


if __name__ == "__main__":
    unittest.main()
