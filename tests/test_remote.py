"""Код pw через бота. Telegram и ключ TPM подменены: настоящий ключ с кодом проверяется только при PW_STORAGE_REAL_TPM=1."""

import contextlib
import io
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
import unittest
from unittest import mock
from pathlib import Path

from pw_storage import catalog, remote
from pw_storage.audit import Audit
from pw_storage.broker import Broker
from pw_storage.config import MAX_REMOTE_ATTEMPTS, Profile
from pw_storage.second_factor import DENY, NoLink
from pw_storage.remote import QueueLock, RemoteListener, WrongCode
from pw_storage.tpm import TpmError, TpmKey
from pw_storage.vault import Kdf, Vault
from pw_storage.window import AccessWindow, apply_style
from tests.test_broker import INFO
from tests.test_catalog import FakeTpm
from tests.test_second_factor import FakeApi
from tests.test_window import Request, unlocked

CODE = "12345678"


class PinTpm(FakeTpm):
    """Как ключ с кодом: расшифровка только с верным кодом, неверные попытки считаются."""

    attempts = []

    def __init__(self, pin, real="12345678"):
        super().__init__()
        self.pin = pin
        self.real = real
        self.created = True

    def decrypt(self, data):
        if self.pin != self.real:
            PinTpm.attempts.append(self.pin)
            raise TpmError("неверный код")
        return super().decrypt(data)


def code_update(update_id, text, date, user=42, message_id=None):
    return {"update_id": update_id, "message": {"message_id": message_id or update_id + 100, "date": date, "text": text,
                                                "from": {"id": user}, "chat": {"id": user}}}


class ValidCodeTest(unittest.TestCase):
    def test_rules(self):
        self.assertTrue(remote.valid_code("12345678"))
        for code in ("1234567", "abcdefgh", "1234 5678", "١٢٣٤٥٦٧٨", ""):
            self.assertFalse(remote.valid_code(code), code)


class QueueLockTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="pwtest"))
        self.addCleanup(shutil.rmtree, self.dir, True)

    def test_lock_lease_and_release(self):
        path = self.dir / "sub" / "lock.json"
        lock = QueueLock(path, clock=lambda: 1000.0)
        lock.refresh()
        self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["until"], 1060.0)
        lock.release()
        self.assertFalse(path.exists())
        lock.release()

    def test_competing_leases_and_stale_release(self):
        now = [1000.0]
        path = self.dir / "lock.json"
        first = QueueLock(path, clock=lambda: now[0])
        second = QueueLock(path, clock=lambda: now[0])
        first.refresh()
        original = path.read_bytes()
        with self.assertRaises(RuntimeError):
            second.refresh()
        self.assertEqual(path.read_bytes(), original)
        now[0] += 61
        second.refresh()
        successor = path.read_bytes()
        self.assertFalse(first.release())
        with self.assertRaises(RuntimeError):
            first.refresh()
        self.assertEqual(path.read_bytes(), successor)
        self.assertTrue(second.release())
        self.assertEqual(list(self.dir.glob("*.new")), [])

    def test_simultaneous_acquisition_has_exactly_one_owner(self):
        path = self.dir / "lock.json"
        locks = [QueueLock(path), QueueLock(path)]
        barrier = threading.Barrier(3)
        winners = []
        def acquire(lock):
            barrier.wait()
            try:
                lock.refresh()
                winners.append(lock)
            except (RuntimeError, OSError):
                pass
        threads = [threading.Thread(target=acquire, args=(lock,)) for lock in locks]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(5)
            self.assertFalse(thread.is_alive())
        self.assertEqual(len(winners), 1)
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(data["token"], winners[0].token)
        winners[0].release()

    def test_process_lease_ownership_guard_and_expiry(self):
        now = [1000.0]
        path = self.dir / "lock.json"
        first = QueueLock(path, clock=lambda: now[0])
        first.refresh()
        original = path.read_bytes()
        script = """
import sys
from pathlib import Path
from pw_storage.remote import QueueLock
lock = QueueLock(Path(sys.argv[1]), clock=lambda: float(sys.argv[2]))
try:
    lock.refresh()
except (RuntimeError, OSError):
    print('busy')
else:
    print('owned')
"""

        def probe(at):
            run = subprocess.run([sys.executable, "-c", script, str(path), str(at)],
                                 capture_output=True, text=True, encoding="utf-8", timeout=10,
                                 env={**os.environ, "PW_STORAGE_REAL_TPM": "0", "PYTHONUTF8": "1"})
            self.assertEqual(run.returncode, 0, run.stderr)
            return run.stdout.strip()

        with first._guard():
            self.assertEqual(probe(now[0]), "busy")
        self.assertEqual(probe(now[0]), "busy")
        self.assertEqual(path.read_bytes(), original)
        now[0] += 61
        self.assertEqual(probe(now[0]), "owned")
        successor = path.read_bytes()
        self.assertFalse(first.release())
        self.assertEqual(path.read_bytes(), successor)
        self.assertEqual(probe(now[0]), "busy")
        self.assertEqual(probe(now[0] + 61), "owned")

    def test_expired_handle_can_be_abandoned_then_reacquired_with_new_token(self):
        now = [1.0]
        lock = QueueLock(self.dir / "lock.json", clock=lambda: now[0])
        old = lock.refresh()
        now[0] += 61
        with self.assertRaises(RuntimeError):
            lock.refresh(old)
        self.assertFalse(lock.release(old))
        current = lock.refresh()
        self.assertNotEqual(old, current)
        self.assertFalse(lock.release(old))
        self.assertTrue(lock.release(current))

    def test_reused_lock_instance_rejects_previous_request_token(self):
        lock = QueueLock(self.dir / "lock.json")
        old = lock.refresh()
        self.assertTrue(lock.release(old))
        current = lock.refresh()
        self.assertNotEqual(old, current)
        self.assertFalse(lock.release(old))
        with self.assertRaises(RuntimeError):
            lock.refresh(old)
        self.assertEqual(lock.refresh(current), current)
        self.assertTrue(lock.release(current))

    def test_legacy_live_or_corrupt_lease_cannot_be_overwritten(self):
        path = self.dir / "lock.json"
        lock = QueueLock(path, clock=lambda: 1)
        for payload in ('{"until":60}', '{broken', '{"until":NaN}', '{"until":true}'):
            path.write_text(payload, encoding="utf-8")
            with self.assertRaises(RuntimeError):
                lock.refresh()
            self.assertEqual(path.read_text(encoding="utf-8"), payload)


class ListenerTest(unittest.TestCase):
    def setUp(self):
        self.api = FakeApi()
        self.now = 1_800_000_000.0
        self.listener = RemoteListener(self.api, "DELTA", 12, [("u1", "Логин Такси")], [("u2", "Ключ погоды")],
                                       why="проверить вход", clock=lambda: self.now)
        self.listener.start()

    def press(self, update_id, action, user=42, nonce=None):
        data = f"pw:{nonce or self.listener.nonce}:{action}"
        return {"update_id": update_id, "callback_query": {"id": f"q{update_id}", "from": {"id": user}, "data": data}}

    def last_edit(self):
        return [f for m, f in self.api.calls if m == "editMessageText"][-1]

    def deleted(self):
        return [f["message_id"] for m, f in self.api.calls if m == "deleteMessage"]

    def test_message_lists_rows_and_asks_for_code(self):
        fields = next(f for m, f in self.api.calls if m == "sendMessage")
        text = fields["text"]
        self.assertIn("Проект DELTA:\n✅ 1. Логин Такси", text)
        self.assertIn("Из ALL (одобрение добавит DELTA в список записи):\n✅ 2. Ключ погоды", text)
        self.assertIn("Зачем, со слов сессии (не проверено): проверить вход", text)
        self.assertIn("выдаются только отмеченные", text)
        self.assertIn("Жду ответа", text.split("\n")[-1])
        self.assertEqual(text.split("\n")[0], "Проект: PW_STORAGE")
        keyboard = json.loads(fields["reply_markup"])["inline_keyboard"]
        self.assertEqual([row[0]["text"] for row in keyboard], ["✅ 1. Логин Такси", "✅ 2. ALL: Ключ погоды", "Отказать"])

    def test_button_toggles_mark_once(self):
        self.api.updates = [self.press(1, "t1")]
        self.assertIsNone(self.listener.poll())
        self.assertEqual(self.listener.chosen(), ["u1"])
        self.assertIn("⬜ 2. Ключ погоды", self.last_edit()["text"])
        self.assertIn("reply_markup", self.last_edit())
        self.assertIn("answerCallbackQuery", self.api.methods())
        self.listener.poll()  # то же нажатие в очереди: повторно не учитывается
        self.assertEqual(self.listener.chosen(), ["u1"])
        self.api.updates.append(self.press(2, "t1"))
        self.listener.poll()
        self.assertEqual(self.listener.chosen(), ["u1", "u2"])

    def test_foreign_or_old_buttons_are_ignored(self):
        self.api.updates = [self.press(1, "t0", user=99), self.press(2, "t0", nonce="old"), self.press(3, "t9")]
        self.assertIsNone(self.listener.poll())
        self.assertEqual(self.listener.chosen(), ["u1", "u2"])

    def test_deny_button(self):
        self.api.updates = [self.press(1, DENY)]
        self.assertEqual(self.listener.poll(), DENY)

    def test_deny_after_wrong_code_keeps_selection_frozen(self):
        self.api.updates = [self.press(1, "t0"), code_update(2, f"pw {CODE}", int(self.now) + 1)]
        self.assertEqual(self.listener.poll(), CODE)
        self.assertEqual(self.listener.chosen(), ["u2"])
        self.listener.say("Код не подошёл", keep_buttons=True)
        self.api.updates.extend([self.press(3, "t1"), self.press(4, DENY, user=99)])
        self.assertIsNone(self.listener.poll())
        self.assertEqual(self.listener.chosen(), ["u2"])
        self.api.updates.append(self.press(5, DENY))
        self.assertEqual(self.listener.poll(), DENY)
        self.assertEqual(self.listener.chosen(), ["u2"])
        self.assertIsNone(self.listener.poll())

    def test_code_confirms_marks_made_before_it(self):
        self.api.updates = [self.press(1, "t0"), code_update(2, f"pw {CODE}", int(self.now) + 1), self.press(3, "t1")]
        self.assertEqual(self.listener.poll(), CODE)
        self.assertEqual(self.listener.chosen(), ["u2"])

    def test_final_status_removes_buttons(self):
        self.listener.say("Код не подошёл", keep_buttons=True)
        self.assertIn("reply_markup", self.last_edit())
        self.listener.say("Доступ разрешён по коду.")
        self.assertNotIn("reply_markup", self.last_edit())
        before = len(self.api.calls)
        self.listener.say("Код не подошёл", keep_buttons=True)
        self.assertEqual(len(self.api.calls), before)  # cannot reopen a closed prompt

    def test_code_is_returned_and_deleted(self):
        self.api.updates = [code_update(1, f"pw {CODE}", int(self.now) + 1)]
        self.assertEqual(self.listener.poll(), CODE)
        self.assertEqual(self.deleted(), ["101"])

    def test_same_message_is_not_used_twice(self):
        self.api.updates = [code_update(1, f"pw {CODE}", int(self.now) + 1)]
        self.listener.poll()
        self.assertIsNone(self.listener.poll())

    def test_old_code_is_deleted_but_not_used(self):
        self.api.updates = [code_update(1, f"pw {CODE}", int(self.now) - 3600)]
        self.assertIsNone(self.listener.poll())
        self.assertEqual(self.deleted(), ["101"])

    def test_foreign_user_is_ignored(self):
        self.api.updates = [code_update(1, f"pw {CODE}", int(self.now) + 1, user=99)]
        self.assertIsNone(self.listener.poll())
        self.assertEqual(self.deleted(), [])

    def test_ordinary_messages_stay(self):
        self.api.updates = [code_update(1, "привет", int(self.now) + 1), code_update(2, "pw storage", int(self.now) + 1)]
        self.assertIsNone(self.listener.poll())
        self.assertEqual(self.deleted(), [])

    def test_queue_is_not_confirmed(self):
        self.listener.poll()
        for method, fields in self.api.calls:
            if method == "getUpdates":
                self.assertNotIn("offset", fields)

    def test_code_never_in_status_text(self):
        self.api.updates = [code_update(1, f"pw {CODE}", int(self.now) + 1)]
        self.listener.poll()
        self.listener.say("Готово")
        for method, fields in self.api.calls:
            if method in ("sendMessage", "editMessageText"):
                self.assertNotIn(CODE, fields["text"])

    def test_long_list_does_not_fit(self):
        rows = [(f"r{i}", f"Комментарий номер {i}: достаточно длинный текст строки") for i in range(200)]
        self.assertFalse(RemoteListener(self.api, "DELTA", 12, rows, []).fits())

    def test_ack_and_delete_failure_do_not_lose_decision_or_selection(self):
        original = self.api.call
        counts = {"deleteMessage": 0, "answerCallbackQuery": 0}
        def call(method, fields, timeout=None):
            if method in counts:
                counts[method] += 1
                raise NoLink("cosmetic failure")
            return original(method, fields, timeout)
        self.api.call = call
        self.api.updates = [self.press(1, "t0"), code_update(2, f"pw {CODE}", int(self.now) + 1), self.press(3, "t1")]
        self.assertEqual(self.listener.poll(), CODE)
        self.assertEqual(self.listener.chosen(), ["u2"])
        self.listener.marked[:] = [True, True]
        self.assertEqual(self.listener.chosen(), ["u2"])
        for _ in range(5):
            self.assertIsNone(self.listener.poll())
        self.assertEqual(counts["deleteMessage"], 3)
        self.assertEqual(counts["answerCallbackQuery"], 6)  # two callbacks, three tries each

    def test_failed_code_deletion_warns_without_disclosing_code(self):
        original = self.api.call
        attempts = []

        def call(method, fields, timeout=None):
            if method == "deleteMessage":
                attempts.append(fields["message_id"])
                raise NoLink("synthetic deletion failure")
            return original(method, fields, timeout)

        self.api.call = call
        self.api.updates = [code_update(1, f"pw {CODE}", int(self.now) + 1)]
        self.assertEqual(self.listener.poll(), CODE)
        error_output = io.StringIO()
        with contextlib.redirect_stderr(error_output):
            self.listener.say("Доступ выдан")
        self.assertEqual(len(attempts), 3)
        self.assertEqual(self.listener._failed_deletions, {"101"})
        self.assertIn("Удаление сообщения с кодом не подтверждено", self.last_edit()["text"])
        self.assertIn("[Telegram]", error_output.getvalue())
        for text in (self.last_edit()["text"], error_output.getvalue()):
            self.assertNotIn(CODE, text)
            self.assertNotIn("synthetic deletion failure", text)

    def test_terminal_deletion_failure_warns_even_when_final_message_fails(self):
        original = self.api.call

        def call(method, fields, timeout=None):
            if method in ("deleteMessage", "editMessageText"):
                raise RuntimeError("synthetic channel failure")
            return original(method, fields, timeout)

        self.api.call = call
        self.api.updates = [code_update(1, f"pw {CODE}", int(self.now) + 1)]
        self.assertEqual(self.listener.poll(), CODE)
        error_output = io.StringIO()
        with contextlib.redirect_stderr(error_output), self.assertRaises(RuntimeError):
            self.listener.say("Доступ не выдан")
        self.assertIn("удали его вручную", error_output.getvalue())
        self.assertNotIn(CODE, error_output.getvalue())

    def test_retry_success_does_not_report_failed_deletion(self):
        original = self.api.call
        attempts = []

        def call(method, fields, timeout=None):
            if method == "deleteMessage":
                attempts.append(fields["message_id"])
                if len(attempts) == 1:
                    raise NoLink("synthetic transient failure")
            return original(method, fields, timeout)

        self.api.call = call
        self.api.updates = [code_update(1, f"pw {CODE}", int(self.now) + 1)]
        self.assertEqual(self.listener.poll(), CODE)
        error_output = io.StringIO()
        with contextlib.redirect_stderr(error_output):
            self.listener.say("Доступ выдан")
        self.assertEqual(len(attempts), 2)
        self.assertEqual(self.listener._failed_deletions, set())
        self.assertNotIn("не подтверждено", self.last_edit()["text"])
        self.assertEqual(error_output.getvalue(), "")

    def test_deny_is_verified_even_when_ack_fails(self):
        original = self.api.call
        def call(method, fields, timeout=None):
            if method == "answerCallbackQuery":
                raise RuntimeError("terminal cosmetic failure")
            return original(method, fields, timeout)
        self.api.call = call
        self.api.updates = [self.press(1, DENY)]
        self.assertEqual(self.listener.poll(), DENY)
        self.assertIsNone(self.listener.poll())

    def test_same_second_code_fails_closed_even_if_missing_from_baseline(self):
        self.now += 0.5
        self.api.updates = [code_update(1, f"pw {CODE}", int(self.now))]
        self.assertIsNone(self.listener.poll())
        self.assertEqual(self.deleted(), ["101"])

    def test_initial_baseline_and_send_boundary_are_stable_across_retries(self):
        api = FakeApi()
        api.updates = [code_update(10, f"pw {CODE}", int(self.now) + 5)]
        listener = RemoteListener(api, "DEMO", 1, [("u1", "synthetic")], [], clock=lambda: self.now)
        original = api.call
        sends = [0]
        def call(method, fields, timeout=None):
            if method == "sendMessage":
                sends[0] += 1
                if sends[0] == 1:
                    raise NoLink("transient send")
                return {"result": {"message_id": 500, "date": int(self.now)}}
            return original(method, fields, timeout)
        api.call = call
        with self.assertRaises(NoLink):
            listener.start()
        started = listener.started
        self.now += 10
        listener.start()
        self.assertEqual(listener.started, started)
        self.assertEqual(listener._baseline, 10)
        api.updates = [code_update(10, f"pw {CODE}", int(self.now) + 1, message_id=501),
                       code_update(11, f"pw {CODE}", int(self.now) - 1, message_id=499)]
        self.assertIsNone(listener.poll())
        api.updates.append(code_update(12, f"pw {CODE}", int(self.now) + 1, message_id=502))
        self.assertEqual(listener.poll(), CODE)
        self.assertEqual(api.methods().count("getUpdates"), 3)

    def test_cancel_during_baseline_prevents_subsequent_send(self):
        api = FakeApi()
        listener = RemoteListener(api, "DEMO", 1, [], [], clock=lambda: self.now)
        entered, release = threading.Event(), threading.Event()
        def call(method, fields, timeout=None):
            api.calls.append((method, fields))
            entered.set()
            if not release.wait(5):
                raise AssertionError("barrier timeout")
            return {"result": []}
        api.call = call
        worker = threading.Thread(target=listener.start)
        worker.start()
        self.assertTrue(entered.wait(5))
        listener.cancel()
        release.set()
        worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(api.methods(), ["getUpdates"])


class EnrollTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="pwtest"))
        self.addCleanup(shutil.rmtree, self.dir, True)

    def test_password_sealed_not_plain(self):
        key = FakeTpm()
        path = self.dir / "remote.bin"
        remote.enroll(key, path, "TEST-password-value")
        self.assertNotIn(b"TEST-password-value", path.read_bytes())
        self.assertEqual(remote.read_password(key, path), "TEST-password-value")

    def test_wrong_key_is_wrong_code(self):
        key = FakeTpm()
        path = self.dir / "remote.bin"
        remote.enroll(key, path, "TEST-password-value")
        with self.assertRaises(WrongCode):
            remote.read_password(FakeTpm(mark=0x33), path)

    def test_forget(self):
        key = FakeTpm()
        path = self.dir / "remote.bin"
        remote.enroll(key, path, "x")
        key.delete = lambda: setattr(key, "created", False)
        remote.forget(key, path)
        self.assertFalse(path.exists())
        self.assertFalse(key.exists())


class BrokerRemoteTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="pwtest"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.profile = Profile("unit", self.dir / "data", self.dir / "logs", self.dir / "projects", "unused", "UNUSED")
        self.password = secrets.token_urlsafe(24)
        vault = Vault.create(self.profile.vault, self.password, Kdf(16, 1, 1))
        vault.put("DEMO", "Камеры", "token", "TEST-value", "Камеры Neocam")
        vault.put("COMMON", "Погода", "key", "TEST-all", "Общий ключ погоды", ("COMMON",), shared=True)
        vault.save()
        self.ids = {row.service: row.uid for row in vault.rows()}
        self.pin_store = FakeTpm()
        remote.enroll(self.pin_store, self.profile.remote, self.password)
        self.catalog_key = FakeTpm()
        catalog.write(self.catalog_key, self.profile.catalog, vault.rows(), self.profile.vault,
                      source_hash=vault.source_hash)
        self.api = FakeApi()
        self.lock = QueueLock(self.dir / "lock.json")
        PinTpm.attempts = []

        def factory(code):
            key = PinTpm(code)
            key.mark = self.pin_store.mark
            return key

        self.ui = self
        self.asked = None
        self.broker = Broker(self.profile, self.catalog_key, self, bot_api=self.api, audit=Audit(self.profile.audit, echo=False),
                             remote_key_factory=factory, queue_lock=self.lock)

    def ask(self, request, unlock, done, remote=None, unlock_remote=None, request_deadline=None,
            on_channels_closed=None):
        def finished(*args, **kwargs):
            done(*args, **kwargs)
            if on_channels_closed is not None:
                on_channels_closed()
        self.asked = dict(request=request, unlock=unlock, done=finished, remote=remote, unlock_remote=unlock_remote,
                          request_deadline=request_deadline)

    def start_request(self, session="s1"):
        result = {}
        request = {"op": "open", "rows": [self.ids["Камеры"], self.ids["Погода"]], "why": "проба"}
        thread = threading.Thread(target=lambda: result.update(self.broker.dispatch(request, INFO, "DEMO", session)), daemon=True)
        thread.start()
        deadline = time.monotonic() + 5
        while self.broker._active is None:
            self.assertLess(time.monotonic(), deadline)
            self.broker.pump()
            time.sleep(0.005)
        return result, thread

    def test_listener_offered_with_fresh_list(self):
        self.start_request()
        listener = self.asked["remote"]["telegram"]
        self.assertIsNotNone(listener)
        self.assertEqual(listener.rows, [(self.ids["Камеры"], "Камеры Neocam"), (self.ids["Погода"], "Общий ключ погоды")])
        self.assertEqual((listener.own_count, listener.why), (1, "проба"))
        self.asked["done"](False, reason="конец")

    def test_no_listener_when_list_is_stale(self):
        outside = Vault.open(self.profile.vault, self.password)
        outside.put("DEMO", "Новый", "k", "TEST-n", "Новая строка")
        outside.save()
        self.start_request()
        self.assertEqual(self.asked["remote"], {})
        self.asked["done"](False, reason="конец")

    def test_no_listener_without_enrollment(self):
        self.profile.remote.unlink()
        self.start_request()
        self.assertEqual(self.asked["remote"], {})
        self.asked["done"](False, reason="конец")

    def test_lock_held_during_request_and_released(self):
        self.start_request()
        self.assertTrue(self.lock.path.exists())
        self.asked["done"](False, reason="конец")
        self.assertFalse(self.lock.path.exists())

    def test_correct_code_grants_exact_rows(self):
        result, thread = self.start_request()
        self.asked["remote"]["telegram"].marked[1] = False  # владелец снял строку из ALL кнопкой
        answer = self.asked["unlock_remote"](CODE, "telegram")
        self.assertEqual(answer, "granted")
        self.asked["done"](True, via="pw")
        thread.join(5)
        self.assertTrue(result["granted"])
        self.assertEqual(result["rows"], [self.ids["Камеры"]])
        get = lambda service, key: self.broker.dispatch({"op": "get", "service": service, "key": key}, INFO, "DEMO", "s1")
        self.assertEqual(get("Камеры", "token")["value"], "TEST-value")
        self.assertEqual(get("Погода", "key")["error"], "not_approved")
        events = [json.loads(line) for line in self.profile.audit.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(next(e for e in events if e["event"] == "access_granted")["via"], "pw")

    def test_wrong_codes_stop_before_tpm_lockout(self):
        self.start_request()
        self.asked["remote"]["telegram"].start()
        for i in range(MAX_REMOTE_ATTEMPTS - 1):
            self.assertIsNone(self.asked["unlock_remote"]("00000000", "telegram"))
        self.assertEqual(self.asked["unlock_remote"]("00000000", "telegram"), "refused")
        self.assertEqual(len(PinTpm.attempts), MAX_REMOTE_ATTEMPTS)
        self.asked["done"](False, reason="неверный код")
        self.start_request("s2")
        self.assertEqual(self.asked["remote"], {})
        self.asked["done"](False, reason="конец")

    def test_nothing_marked_is_refused_without_tpm(self):
        self.start_request()
        self.asked["remote"]["telegram"].start()
        self.asked["remote"]["telegram"].marked = [False, False]
        self.assertEqual(self.asked["unlock_remote"](CODE, "telegram"), "refused")
        self.assertEqual(PinTpm.attempts, [])
        self.asked["done"](False, reason="конец")

    def test_codes_not_in_audit(self):
        self.start_request()
        self.asked["remote"]["telegram"].start()
        self.asked["unlock_remote"]("00000000", "telegram")
        self.asked["unlock_remote"](CODE, "telegram")
        self.asked["done"](True, via="pw")
        text = self.profile.audit.read_text(encoding="utf-8")
        self.assertNotIn("00000000", text)
        self.assertNotIn(CODE, text)
        self.assertIn("code_failed", text)


    def test_wrong_code_budget_is_exhausted_for_the_request(self):
        self.start_request()
        for _ in range(MAX_REMOTE_ATTEMPTS - 1):
            self.assertIsNone(self.asked["unlock_remote"]("00000000", "telegram"))
        self.assertEqual(self.asked["unlock_remote"]("00000000", "telegram"), "refused")
        self.assertEqual(len(PinTpm.attempts), MAX_REMOTE_ATTEMPTS)
        self.asked["done"](False, reason="попытки исчерпаны")
        self.start_request("s2")
        self.assertEqual(self.asked["remote"], {})
        self.asked["done"](False, reason="конец")

    def test_failed_status_edit_does_not_reset_code_budget(self):
        self.start_request()
        listener = self.asked["remote"]["telegram"]
        listener.say = mock.Mock(side_effect=NoLink("synthetic failure"))
        self.assertIsNone(self.asked["unlock_remote"]("00000000", "telegram"))
        self.assertEqual(self.broker._remote_failures, 1)
        self.asked["done"](False, reason="конец")


    def test_confirmation_constructor_failure_leaves_no_pending_vault(self):
        self.start_request()
        pending = self.broker._active
        with mock.patch.object(self.broker, "_make_telegram", side_effect=RuntimeError("synthetic constructor")):
            with self.assertRaises(RuntimeError):
                self.asked["unlock"](self.password, [self.ids["Камеры"]], 1)
        self.assertIsNone(pending.vault)
        self.assertEqual(pending.chosen, [])
        self.asked["done"](True, via="pw")
        self.assertFalse(pending.result["ok"])
        self.assertEqual(self.broker.grants, {})

    def test_remote_rows_vanished_does_not_report_granted(self):
        self.start_request()
        vault = Vault.open(self.profile.vault, self.password)
        for uid in self.ids.values():
            vault.trash(uid)
        vault.save()
        self.assertEqual(self.asked["unlock_remote"](CODE, "telegram"), "refused")
        self.asked["done"](False, reason="строк нет")
        self.assertEqual(self.broker.grants, {})

    def test_audit_failure_denies_without_wedging_request(self):
        result, thread = self.start_request()
        pending = self.broker._active
        self.assertEqual(self.asked["unlock_remote"](CODE, "telegram"), "granted")
        with mock.patch.object(self.broker.audit, "write", side_effect=OSError("synthetic audit")):
            self.asked["done"](True, via="pw")
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(result["error"], "denied")
        self.assertIn("журнал", result["message"])
        self.assertEqual(self.broker.grants, {})
        self.assertIsNone(pending.vault)
        self.assertEqual(pending.chosen, [])
        self.assertIsNone(self.broker._active)
        self.assertIsNone(self.broker._queue_owner)
        self.assertTrue(pending.event.is_set())

    def test_deny_audit_failure_still_completes_and_releases_queue(self):
        result, thread = self.start_request()
        with mock.patch.object(self.broker.audit, "write", side_effect=OSError("synthetic audit")):
            self.asked["done"](False, reason="отказ")
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(result["error"], "denied")
        self.assertFalse(self.lock.path.exists())


class FakeRemote:
    def __init__(self, code=None):
        self.code = code
        self.started = False
        self.said = []

    def start(self):
        self.started = True

    def poll(self):
        code, self.code = self.code, None
        return code

    def chosen(self):
        return ["a0000001"]

    def say(self, status, keep_buttons=False):
        self.said.append(status)


class WindowRemoteTest(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        self.root.withdraw()
        apply_style(self.root)
        self.results = []

    def tearDown(self):
        self.window.finish(False, reason="конец теста")
        self.root.update()
        self.root.destroy()

    def make(self, listener, answer="granted", unlock=None):
        self.window = AccessWindow(self.root, Request(), unlock or (lambda p, c, h: unlocked()),
                                   lambda g, via="", reason="": self.results.append((g, via, reason)), take_focus=False,
                                   remote={"telegram": listener}, unlock_remote=lambda code, kind: answer)

    def pump(self, until):
        deadline = time.monotonic() + 5
        while not until():
            self.assertLess(time.monotonic(), deadline)
            self.root.update()
            time.sleep(0.005)

    def test_code_closes_window_with_grant(self):
        listener = FakeRemote(CODE)
        self.make(listener)
        self.pump(lambda: self.results)
        self.assertEqual(self.results, [(True, "pw", "")])
        self.assertTrue(listener.started)
        self.pump(lambda: listener.said)
        self.assertIn("разрешён", listener.said[0])

    def test_refused_code_closes_without_grant(self):
        self.make(FakeRemote(CODE), answer="refused")
        self.pump(lambda: self.results)
        self.assertFalse(self.results[0][0])

    def test_deny_from_phone(self):
        self.make(FakeRemote(DENY))
        self.pump(lambda: self.results)
        self.assertEqual(self.results, [(False, "", "отказ с телефона")])

    def test_password_at_pc_stops_waiting_for_code(self):
        listener = FakeRemote()
        self.make(listener)
        self.window.password_var.set("x")
        self.window.continue_button.invoke()
        self.pump(lambda: self.window.unlocked is not None and listener.said)
        self.assertIn("Пароль введён на ПК", listener.said[0])

    def test_local_claim_while_remote_poll_blocked_prevents_remote_unlock(self):
        entered, release, polled = threading.Event(), threading.Event(), threading.Event()
        listener = FakeRemote(CODE)
        def poll():
            entered.set()
            if not release.wait(5):
                raise AssertionError("barrier timeout")
            polled.set()
            return CODE
        listener.poll = poll
        calls = []
        with mock.patch("pw_storage.window.TELEGRAM_POLL_SECONDS", 0):
            self.window = AccessWindow(self.root, Request(), lambda *a: unlocked(),
                                       lambda *a: self.results.append(a), take_focus=False,
                                       remote={"telegram": listener}, unlock_remote=lambda code, kind: calls.append(code) or "granted")
            self.assertTrue(entered.wait(5))
            self.window.password_var.set("synthetic")
            self.window.submit_password()
            release.set()
            self.assertTrue(polled.wait(5))
            self.pump(lambda: self.window.unlocked is not None and listener.said)
        self.assertEqual(calls, [])
        self.assertEqual(self.results, [])

    def test_remote_claim_blocks_local_password_and_cancel_rejects_late_grant(self):
        entered, release, completed = threading.Event(), threading.Event(), threading.Event()
        local_calls = []
        def unlock_remote(code, kind):
            entered.set()
            if not release.wait(5):
                raise AssertionError("barrier timeout")
            completed.set()
            return "granted"
        with mock.patch("pw_storage.window.TELEGRAM_POLL_SECONDS", 0):
            self.window = AccessWindow(self.root, Request(), lambda *a: local_calls.append(a) or unlocked(),
                                       lambda *a: self.results.append(a), take_focus=False,
                                       remote={"telegram": FakeRemote(CODE)}, unlock_remote=unlock_remote)
            self.assertTrue(entered.wait(5))
            self.window.password_var.set("synthetic")
            self.window.submit_password()
            self.assertEqual(local_calls, [])
            self.window.cancel()
            release.set()
            self.assertTrue(completed.wait(5))
        self.root.update()
        self.assertEqual(len(self.results), 1)
        self.assertFalse(self.results[0][0])

    def test_late_remote_event_and_request_deadline_fail_closed(self):
        self.make(FakeRemote())
        token = self.window._state.claim("password", "remote")
        self.window._events.put((token, "remote", "granted"))
        self.window._state.deadline = self.window.clock()
        self.window._tick()
        self.assertFalse(self.results[0][0])


    def test_unavailable_telegram_reports_truthful_status(self):
        telegram = FakeRemote()
        telegram.start = mock.Mock(side_effect=RuntimeError("synthetic failure"))
        self.window = AccessWindow(self.root, Request(), lambda *a: unlocked(),
                                   lambda *a: self.results.append(a), take_focus=False,
                                   remote={"telegram": telegram},
                                   unlock_remote=lambda code, kind: "granted")
        self.pump(lambda: "Telegram: недоступен" in self.window.remote_label.cget("text"))
        self.assertEqual(self.results, [])
        self.window.cancel()
        self.pump(lambda: self.results)
        self.assertFalse(self.results[0][0])

    def test_confirmation_waits_for_remote_reader_cleanup(self):
        from tests.test_window import FakeConfirm
        entered, release = threading.Event(), threading.Event()
        listener, confirm = FakeRemote(), FakeConfirm()
        def cleanup(status):
            entered.set()
            if not release.wait(5):
                raise AssertionError("cleanup barrier timeout")
            listener.said.append(status)
        listener.say = cleanup
        self.window = AccessWindow(self.root, Request(), lambda *a: unlocked(telegram=confirm),
                                   lambda *a: self.results.append(a), take_focus=False,
                                   remote={"telegram": listener}, unlock_remote=lambda *a: None)
        try:
            self.window.password_var.set("synthetic")
            self.window.submit_password()
            self.pump(lambda: self.window.unlocked is not None and entered.is_set())
            self.assertFalse(confirm.started)
            release.set()
            self.pump(lambda: confirm.started)
            self.window.cancel()
            self.pump(lambda: self.window._state.channel_workers == 0)
        finally:
            release.set()


@unittest.skipUnless(os.environ.get("PW_STORAGE_REAL_TPM") == "1", "нужен PW_STORAGE_REAL_TPM=1")
class RealPinTest(unittest.TestCase):
    """Только верный код: неверные попытки на настоящем TPM намеренно не пробуем (лимит подбора)."""

    NAME = "PW_STORAGE_TEST_PIN_UNIT"

    def test_seal_and_open_with_pin(self):
        dir_ = Path(tempfile.mkdtemp(prefix="pwtest"))
        self.addCleanup(shutil.rmtree, dir_, True)
        code = "".join(secrets.choice("0123456789") for _ in range(10))
        key = TpmKey(self.NAME, pin=code)
        self.assertFalse(key.exists())
        self.addCleanup(lambda: TpmKey(self.NAME, pin=code).delete() if TpmKey(self.NAME).exists() else None)
        path = dir_ / "remote.bin"
        remote.enroll(key, path, "TEST-password-value")
        self.assertEqual(remote.read_password(TpmKey(self.NAME, pin=code), path), "TEST-password-value")
        self.assertNotIn(b"TEST-password-value", path.read_bytes())


if __name__ == "__main__":
    unittest.main()
