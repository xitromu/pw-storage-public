"""Посредник на случайных тестовых значениях: окно и TPM подменены, канал и клиенты настоящие."""

import base64
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
import unittest
from pathlib import Path
from unittest import mock

import pyotp

from pw_storage import catalog, vault as vault_module
from pw_storage.audit import Audit
from pw_storage.broker import Broker, _Pending
from pw_storage.config import DEFAULT_GRANT_HOURS, HOME, IDLE_EXIT_SECONDS, TOTP_ENTRY, Profile
from pw_storage.procinfo import ClientInfo
from pw_storage.vault import Kdf, Vault, VaultCommitted
from tests.test_catalog import FakeTpm
from tests.test_second_factor import FakeApi

FAST = Kdf(memory_mb=16, iterations=1, parallelism=1)
INFO = ClientInfo(1, None, None)
WHY = "проба посредника"

CHILD = """
import json, sys
from pw_storage.client import PwClient
pw = PwClient(pipe=sys.argv[1])
out = {}
def attempt(name, func):
    try:
        out[name] = {"ok": True, "result": func()}
    except Exception as e:
        out[name] = {"ok": False, "error": type(e).__name__}
attempt("status", lambda: pw.status()["granted"])
attempt("project", lambda: pw.status()["project"])
attempt("get_before", lambda: pw.get("Погода", "API_KEY"))
preview = pw.preview()
out["preview"] = {"ok": True, "result": preview["state"]}
wanted = [i["id"] for i in (*preview["own"], *preview["common"])]
attempt("unknown", lambda: pw.open(["00000000"], why="чужой номер"))
attempt("open", lambda: pw.open(wanted, why="проба клиента")["granted"])
attempt("status_after", lambda: pw.status()["granted"])
attempt("rows", pw.rows)
attempt("own", lambda: pw.get("Такси", "login"))
attempt("common", lambda: pw.get("Погода", "API_KEY"))
attempt("foreign", lambda: pw.get("Маркет", "password"))
attempt("report", pw.report)
attempt("close", lambda: pw.close()["closed"])
attempt("after_close", lambda: pw.get("Такси", "login"))
sys.stdout.reconfigure(encoding="utf-8")
print(json.dumps(out, ensure_ascii=False))
"""


class FakeUi:
    """Вместо окна: оставляет отметки (по умолчанию все), вводит пароль и принимает заданное решение."""

    def __init__(self, password, decision="code"):
        self.password = password
        self.decision = decision
        self.requests = []
        self.unlocked = None
        self.choose = None  # функция запроса → номера строк; None — все запрошенные
        self.hours = None
        self.before_done = None

    def ask(self, request, unlock, done, remote=None, unlock_remote=None, request_deadline=None,
            on_channels_closed=None):
        self.requests.append(request)

        def work():
            chosen = None if request.rebuild else (self.choose or (lambda r: [i.uid for i in r.rows]))(request)
            self.unlocked = unlock(self.password, chosen, self.hours or request.hours)
            if self.before_done:
                self.before_done()
            if self.unlocked is None:
                done(False, reason="неверный пароль")
            elif self.unlocked.rebuilt:
                done(False, reason="перечень собран заново")
            elif self.decision == "deny":
                done(False, reason="отказ владельца")
            elif self.decision == "code":
                self.code_ok = self.unlocked.verify_code(self.code) if hasattr(self, "code") else True
                done(self.code_ok, via="code", reason="" if self.code_ok else "неверный код")
            else:
                done(True, via=self.decision)
            if on_channels_closed is not None:
                on_channels_closed()

        threading.Thread(target=work, daemon=True).start()


class BrokerCase(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="pwtest"))
        self.profile = Profile(
            name="unit",
            data=self.dir / "data",
            logs=self.dir / "logs",
            projects_root=self.dir / "projects",
            pipe=rf"\\.\pipe\pw_storage_unit_{os.getpid()}_{secrets.token_hex(4)}",
            catalog_key="UNUSED",
        )
        self.password = secrets.token_urlsafe(24)
        self.values = {name: "TEST-" + secrets.token_urlsafe(24) for name in ("own", "common", "foreign", "totp")}
        self.totp_secret = pyotp.random_base32(32)
        self.now = time.time()
        vault = Vault.create(self.profile.vault, self.password, FAST)
        vault.put("COMMON", "Погода", "API_KEY", self.values["common"], "Общий ключ погоды", ("COMMON",), shared=True)
        vault.put("DEMO_A", "Такси", "login", self.values["own"], "Логин Такси")
        vault.put("DEMO_B", "Маркет", "password", self.values["foreign"], "Пароль Маркет")
        vault.set_system_value(TOTP_ENTRY, self.totp_secret)
        vault.save()
        self.ids = {row.service: row.uid for row in vault.rows()}
        self.ui = FakeUi(self.password, decision="telegram")
        self.key = FakeTpm()
        self._write_catalog()
        self.broker = Broker(self.profile, self.key, self.ui, clock=lambda: self.now,
                             audit=Audit(self.profile.audit, echo=False))
        self._stop_pump = threading.Event()
        self._pump = threading.Thread(target=self._pump_loop, daemon=True)
        self._pump.start()

    def _pump_loop(self):
        while not self._stop_pump.is_set():
            self.broker.pump()
            time.sleep(0.01)

    def tearDown(self):
        self._stop_pump.set()
        self._pump.join(2)
        self.broker.stop()
        shutil.rmtree(self.dir, ignore_errors=True)

    def call(self, op, project="DEMO_A", session="s1", **fields):
        return self.broker.dispatch({"op": op, **fields}, INFO, project, session)

    def open(self, *services, session="s1", project="DEMO_A", why=WHY):
        rows = [self.ids[s] for s in (services or ("Такси", "Погода"))]
        return self.call("open", project=project, session=session, rows=rows, why=why)

    def audit_events(self, event=None):
        if not self.profile.audit.exists():
            return []
        events = [json.loads(line) for line in self.profile.audit.read_text(encoding="utf-8").splitlines()]
        return [e for e in events if event is None or e["event"] == event]

    def _write_catalog(self):
        vault = Vault.open(self.profile.vault, self.password)
        catalog.write(self.key, self.profile.catalog, vault.rows(), self.profile.vault, source_hash=vault.source_hash)

    def _change_vault_outside(self, *args, edit=None, **kwargs):
        outside = Vault.open(self.profile.vault, self.password)
        if args or kwargs:
            outside.put(*args, **kwargs)
        if edit:
            edit(outside)
        outside.save()
        return outside

    def _row(self, service):
        return next(r for r in Vault.open(self.profile.vault, self.password).rows() if r.service == service)

    # До доступа

    def test_no_access_at_start(self):
        self.assertFalse(self.call("status")["granted"])
        self.assertEqual(self.call("get", service="Погода", key="API_KEY")["error"], "needs_access")
        self.assertEqual(self.call("list")["error"], "needs_access")

    def test_preview_shows_ids_and_comments_of_own_and_common_rows(self):
        answer = self.call("preview")
        self.assertEqual(answer["state"], catalog.FRESH)
        self.assertEqual(answer["own"], [{"id": self.ids["Такси"], "comment": "Логин Такси", "all": False}])
        self.assertEqual(answer["common"], [{"id": self.ids["Погода"], "comment": "Общий ключ погоды", "all": True}])
        self.assertEqual(answer["unnamed"], 0)
        text = json.dumps(answer, ensure_ascii=False)
        for hidden in ("Пароль Маркет", self.ids["Маркет"], "login", "API_KEY", "COMMON",
                       *self.values.values(), self.password, self.totp_secret):
            self.assertNotIn(hidden, text)

    def test_preview_gives_no_access_and_is_logged(self):
        self.call("preview")
        self.assertFalse(self.call("status")["granted"])
        self.assertEqual(self.ui.requests, [])
        viewed = self.audit_events("catalog_viewed")
        self.assertEqual([(e["project"], e["state"]) for e in viewed], [("DEMO_A", catalog.FRESH)])

    def test_preview_without_catalog_is_empty(self):
        self.profile.catalog.unlink()
        answer = self.call("preview")
        self.assertEqual(answer["state"], catalog.MISSING)
        self.assertEqual((answer["own"], answer["common"]), ([], []))

    def test_preview_marks_stale_catalog(self):
        self._change_vault_outside("DEMO_A", "Новый", "token", "TEST-new", "Новая строка")
        answer = self.call("preview")
        self.assertEqual(answer["state"], catalog.STALE)
        self.assertNotIn("Новая строка", [i["comment"] for i in answer["own"]])

    # Запрос строк (Т26)

    def test_open_needs_rows(self):
        answer = self.call("open", why=WHY)
        self.assertEqual(answer["error"], "no_rows")
        self.assertEqual(self.ui.requests, [])

    def test_foreign_and_unknown_rows_are_refused_before_window(self):
        for rows in ([self.ids["Маркет"]], ["00000000"], [self.ids["Такси"], "zzz"]):
            answer = self.call("open", rows=rows, why=WHY)
            self.assertEqual(answer["error"], "unknown_rows")
        self.assertIn(self.ids["Маркет"], self.call("open", rows=[self.ids["Маркет"]])["message"])
        self.assertEqual(self.ui.requests, [])

    def test_bad_rows_field(self):
        for rows in ("abc", None, {}, [1], [None], [{}], [True]):
            with self.subTest(rows=rows):
                self.assertEqual(self.call("open", rows=rows)["error"], "bad_request")

    def test_non_object_request_is_rejected(self):
        for request in (None, [], "open", 42):
            with self.subTest(request=request):
                answer = self.broker.dispatch(request, INFO, "DEMO_A", "s1")
                self.assertEqual(answer["error"], "bad_request")

    def test_reason_must_be_text(self):
        for why in ([], {}, 42, None):
            with self.subTest(why=why):
                self.assertEqual(self.call("open", rows=[self.ids["Такси"]], why=why)["error"], "bad_request")

    def test_window_gets_requested_rows_and_why(self):
        self.open(why="  проверить   вход  ")
        request = self.ui.requests[0]
        self.assertEqual(request.listing.state, catalog.FRESH)
        self.assertEqual([i.uid for i in request.own], [self.ids["Такси"]])
        self.assertEqual([i.uid for i in request.common], [self.ids["Погода"]])
        self.assertEqual(request.why, "проверить вход")
        self.assertEqual(request.hours, DEFAULT_GRANT_HOURS)
        self.assertFalse(request.rebuild)

    def test_own_rows_come_first_in_window(self):
        self.open("Погода", "Такси")
        self.assertEqual([i.uid for i in self.ui.requests[0].rows], [self.ids["Такси"], self.ids["Погода"]])

    def test_grant_gives_only_requested_rows(self):
        answer = self.open("Такси")
        self.assertEqual(answer["rows"], [self.ids["Такси"]])
        self.assertEqual(self.call("get", service="Такси", key="login")["value"], self.values["own"])
        self.assertEqual(self.call("get", service="Погода", key="API_KEY")["error"], "not_approved")
        self.assertEqual(self.call("get", service="Маркет", key="password")["error"], "not_found")
        self.assertEqual([r["id"] for r in self.call("list")["rows"]], [self.ids["Такси"]])

    def test_unchecked_row_is_not_issued(self):
        self.ui.choose = lambda request: [self.ids["Такси"]]
        answer = self.open("Такси", "Погода")
        self.assertEqual(answer["rows"], [self.ids["Такси"]])
        self.assertEqual(self.call("get", service="Погода", key="API_KEY")["error"], "not_approved")
        self.assertEqual(self._row("Погода").projects, ("COMMON",))

    def test_window_cannot_add_rows_beyond_visible(self):
        self.ui.choose = lambda request: [self.ids["Такси"], self.ids["Маркет"]]
        answer = self.open("Такси")
        self.assertEqual(answer["rows"], [self.ids["Такси"]])
        self.assertEqual(self.call("get", service="Маркет", key="password")["error"], "not_found")

    def test_approved_common_row_adds_project_to_list(self):
        self.assertTrue(self.open("Погода")["granted"])
        self.assertEqual(self.call("get", service="Погода", key="API_KEY")["value"], self.values["common"])
        row = self._row("Погода")
        self.assertEqual((row.projects, row.shared), (("COMMON", "DEMO_A"), True))
        extended = self.audit_events("list_extended")
        self.assertEqual(extended[0]["rows"], ["COMMON / Погода / API_KEY"])
        preview = self.call("preview")
        self.assertEqual(preview["state"], catalog.FRESH)
        self.assertEqual(sorted(i["id"] for i in preview["own"]), sorted([self.ids["Такси"], self.ids["Погода"]]))
        self.assertEqual(preview["common"], [])
        self.assertFalse([r for r in self.call("list")["rows"] if r["id"] == self.ids["Погода"]][0]["all"])

    def test_extension_failure_keeps_grant(self):
        self.ui.before_done = lambda: self._change_vault_outside("DEMO_A", "Внешний", "k", "TEST-o", "Внешняя правка")
        self.assertTrue(self.open("Погода")["granted"])
        self.assertEqual(self.audit_events("list_extend_failed")[0]["reason"], "VaultChanged")
        self.assertEqual(self.call("get", service="Погода", key="API_KEY")["value"], self.values["common"])
        self.assertEqual(self._row("Погода").projects, ("COMMON",))

    def test_row_without_comment_is_counted_not_offered(self):
        def strip_comment(vault):
            vault.put("DEMO_A", "Без", "comment", "TEST-nc", "временно")
            vault._entry("DEMO_A", "Без", "comment").notes = ""
        self._change_vault_outside(edit=strip_comment)
        self._write_catalog()
        hidden = self._row("Без").uid
        answer = self.call("preview")
        self.assertEqual(answer["unnamed"], 1)
        self.assertNotIn(hidden, json.dumps(answer))
        self.assertEqual(self.call("open", rows=[hidden], why=WHY)["error"], "unknown_rows")
        self.open("Такси")
        self.assertEqual(self.ui.requests[0].unnamed, 1)
        self.assertEqual(self.call("get", service="Без", key="comment")["error"], "not_found")

    def test_missing_catalog_is_rebuilt_without_grant(self):
        self.profile.catalog.unlink()
        self.assertEqual(self.call("open", rows=[self.ids["Такси"]], why=WHY)["error"], "no_catalog")
        answer = self.call("open", why=WHY)
        self.assertEqual(answer["error"], "denied")
        self.assertTrue(self.ui.requests[0].rebuild)
        self.assertFalse(self.call("status")["granted"])
        self.assertIsNone(self.broker.vault)
        self.assertEqual(catalog.read(self.key, self.profile.catalog, self.profile.vault).state, catalog.FRESH)
        self.assertEqual(len(self.audit_events("catalog_rebuilt")), 1)

    def test_rows_gone_before_unlock_give_no_grant(self):
        self.ui.before_done = None
        self.ui.choose = lambda request: []
        self.assertEqual(self.open("Такси")["error"], "denied")
        self.assertFalse(self.call("status")["granted"])

    def test_system_rows_are_not_reachable(self):
        self.open()
        self.assertEqual(self.call("get", service=TOTP_ENTRY, key="")["error"], "not_found")
        self.assertNotIn(TOTP_ENTRY, json.dumps(self.call("list"), ensure_ascii=False))

    def test_list_has_no_values(self):
        self.open()
        text = json.dumps(self.call("list"), ensure_ascii=False)
        for value in self.values.values():
            self.assertNotIn(value, text)

    def test_sessions_share_project_grant_without_renewal_or_second_window(self):
        self.assertTrue(self.open(session="s1")["granted"])
        grant = self.broker.grants["DEMO_A"]
        self.now += 3600
        for session in ("s2", "manual", "claude:123:456"):
            with self.subTest(session=session):
                status = self.call("status", session=session)
                self.assertTrue(status["granted"])
                self.assertEqual(status["session"], session)
                self.assertEqual(self.call("get", session=session, service="Погода", key="API_KEY")["value"],
                                 self.values["common"])
                self.assertEqual(len(self.call("list", session=session)["rows"]), 2)
                self.assertTrue(self.open(session=session)["granted"])
                self.assertEqual(self.broker.grants["DEMO_A"], grant)
        self.assertEqual(len(self.ui.requests), 1)
        self.assertEqual(self.call("report", session="s1"), self.call("report", session="s2"))
        self.assertEqual(len(self.call("report")["issued"]), 3)
        self.assertFalse(self.call("status", project="DEMO_B")["granted"])
        self.assertEqual(self.call("get", project="DEMO_B", service="Погода", key="API_KEY")["error"], "needs_access")
        self.assertEqual(self.call("report", project="DEMO_B")["issued"], [])
        self.assertEqual([event["session"] for event in self.audit_events("value_issued")],
                         ["s2", "manual", "claude:123:456"])

    def test_repeat_open_does_not_ask_again(self):
        self.open()
        self.assertTrue(self.open("Такси")["granted"])
        self.assertEqual(len(self.ui.requests), 1)

    def test_more_rows_ask_again_and_keep_earlier(self):
        self.open("Такси")
        self.now += 3600
        self.ui.hours = 2
        self.assertTrue(self.open("Погода", session="s2")["granted"])
        self.assertEqual(self.broker.grants["DEMO_A"].expires, self.now + 2 * 3600)
        self.assertEqual(len(self.ui.requests), 2)
        self.assertEqual(self.call("get", service="Такси", key="login")["value"], self.values["own"])
        self.assertEqual(self.call("get", service="Погода", key="API_KEY")["value"], self.values["common"])

    # Срок (Т27)

    def test_grant_lasts_default_hours(self):
        self.assertEqual(DEFAULT_GRANT_HOURS, 12)
        self.open()
        self.now += DEFAULT_GRANT_HOURS * 3600 - 60
        self.assertTrue(self.call("status")["granted"])
        self.now += 120
        self.assertFalse(self.call("status")["granted"])
        self.assertEqual(self.call("get", service="Погода", key="API_KEY")["error"], "needs_access")

    def test_hours_chosen_in_window(self):
        self.ui.hours = 2
        self.open()
        self.assertEqual(self.audit_events("access_granted")[0]["hours"], 2)
        self.now += 2 * 3600 - 60
        self.assertTrue(self.call("status")["granted"])
        self.now += 120
        self.assertFalse(self.call("status")["granted"])

    def test_default_hours_from_settings(self):
        self.profile.settings.write_text(json.dumps({"grant_hours": 3}), encoding="utf-8")
        self.open()
        self.assertEqual(self.ui.requests[0].hours, 3)
        for bad in (0, 8761, "много"):
            self.call("close")
            self.profile.settings.write_text(json.dumps({"grant_hours": bad}), encoding="utf-8")
            self.open(session=f"s-{bad}")
            self.assertEqual(self.ui.requests[-1].hours, DEFAULT_GRANT_HOURS)

    def test_sweep_expires_and_drops_vault(self):
        self.open()
        self.assertIsNotNone(self.broker.vault)
        self.now += DEFAULT_GRANT_HOURS * 3600 + 1
        self.broker.sweep()
        self.assertEqual(self.broker.grants, {})
        self.assertIsNone(self.broker.vault)
        self.assertTrue(self.audit_events("access_expired"))

    def test_expiry_clears_only_expired_project_grant_and_report(self):
        self.ui.hours = 1
        self.open("Погода")
        self.call("get", service="Погода", key="API_KEY")
        self.ui.hours = 2
        self.open("Погода", project="DEMO_B")
        self.call("get", project="DEMO_B", service="Погода", key="API_KEY")
        other_grant = self.broker.grants["DEMO_B"]
        other_report = self.call("report", project="DEMO_B")
        self.now += 3601
        self.broker.sweep()
        self.assertNotIn("DEMO_A", self.broker.grants)
        self.assertEqual(self.call("report", session="s2")["issued"], [])
        self.assertFalse(self.call("status", session="s2")["granted"])
        self.assertEqual(self.broker.grants["DEMO_B"], other_grant)
        self.assertEqual(self.call("report", project="DEMO_B"), other_report)
        self.assertIsNotNone(self.broker.vault)

    def test_dead_session_does_not_revoke_project(self):
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        session = f"claude:{child.pid}:1"
        try:
            self.assertTrue(self.open(session=session)["granted"])
        finally:
            child.kill()
            child.wait()
        grant = self.broker.grants["DEMO_A"]
        self.now += 60
        self.broker.sweep()
        self.assertEqual(self.broker.grants["DEMO_A"], grant)
        self.assertTrue(self.call("status", session=session)["granted"])
        self.assertEqual(self.call("get", session="s2", service="Погода", key="API_KEY")["value"],
                         self.values["common"])
        self.assertEqual(self.audit_events("access_expired"), [])
        self.assertIsNotNone(self.broker.vault)

    def test_close_drops_vault_when_last(self):
        self.open()
        self.assertTrue(self.call("close", session="s2")["closed"])
        self.assertIsNone(self.broker.vault)
        self.assertFalse(self.call("close")["closed"])

    # close: только синтетические запросы, pump и Tk-callback на основном потоке.

    def _manual_close_ui(self):
        self._stop_pump.set()
        self._pump.join(2)
        shown, cancelled = [], []

        def ask(request, unlock, done, **options):
            self.assertIs(threading.current_thread(), threading.main_thread())
            self.assertFalse(self.broker._lock._is_owned())
            shown.append(dict(request=request, unlock=unlock, done=done, **options))

            def cancel():
                self.assertIs(threading.current_thread(), threading.main_thread())
                self.assertFalse(self.broker._lock._is_owned())
                cancelled.append(request)
                done(False, reason="время запроса вышло")
                # Каналы закрываются отдельно: cancel не означает завершение cleanup.

            return cancel

        self.ui.ask = mock.Mock(side_effect=ask)
        return shown, cancelled

    def _queued_open(self, service="Такси", project="DEMO_A", session="s1"):
        queued = threading.Event()
        captured, answer = [], {}
        put = self.broker._pending.put

        def enqueue(pending):
            captured.append(pending)
            put(pending)
            queued.set()

        thread = threading.Thread(target=lambda: answer.update(self.open(service, project=project, session=session)),
                                  daemon=True)

        def cleanup():
            if thread.is_alive():
                self.call("close", project=project, session=session)
                thread.join(5)

        self.addCleanup(cleanup)
        with mock.patch.object(self.broker._pending, "put", side_effect=enqueue):
            thread.start()
            self.assertTrue(queued.wait(5), "open did not enqueue")
        return captured[0], thread, answer

    def _assert_closed_open(self, pending, thread, answer):
        thread.join(5)
        self.assertFalse(thread.is_alive(), "close must wake open without pump/channel cleanup")
        self.assertNotIn(id(pending), self.broker._waiting)
        self.assertTrue(pending.cancelled)
        self.assertTrue(pending.finished)
        self.assertTrue(pending.event.is_set())
        self.assertEqual(answer["error"], "denied")
        self.assertIn("close", answer["message"])
        self.assertNotIn("время", answer["message"])
        self.assertIsNone(pending.vault)
        self.assertEqual(pending.chosen, [])

    def _approve_close_window(self, window):
        request = window["request"]
        self.assertIsNotNone(window["unlock"](self.password, [row.uid for row in request.rows], request.hours))
        verdict = window["done"](True, via="telegram")
        self.assertEqual(verdict, (True, "telegram", ""))
        window["on_channels_closed"]()

    def test_queued_sessions_share_approval_without_second_window_or_renewal(self):
        shown, _ = self._manual_close_ui()
        first = self._queued_open(session="s1")
        second = self._queued_open(session="s2")
        self.broker.pump()
        self._approve_close_window(shown[0])
        first[1].join(5)
        self.assertFalse(first[1].is_alive())
        self.assertTrue(first[2]["granted"])
        grant = self.broker.grants["DEMO_A"]
        self.now += 60
        self.broker.pump()
        second[1].join(5)
        self.assertFalse(second[1].is_alive())
        self.assertTrue(second[2]["granted"])
        self.assertEqual(len(shown), 1)
        self.assertEqual(self.broker.grants["DEMO_A"], grant)

    def test_close_before_done_never_regrants(self):
        cleaned = threading.Event()
        channels_closed = self.broker._channels_closed

        def cleanup(pending):
            channels_closed(pending)
            cleaned.set()

        self.ui.before_done = lambda: self.call("close", session="s2")
        with mock.patch.object(self.broker, "_channels_closed", side_effect=cleanup):
            answer = self.open("Такси")
            self.assertTrue(cleaned.wait(5))
        self.assertEqual(answer["error"], "denied")
        self.assertIn("close", answer["message"])
        self.assertFalse(self.call("status")["granted"])
        self.assertEqual(self.audit_events("access_granted"), [])

    def test_close_wakes_active_and_all_queued_but_retains_lease_until_channels_closed(self):
        from pw_storage.remote import QueueLock
        shown, cancelled = self._manual_close_ui()
        self.broker.bot_api = FakeApi()
        self.broker.queue_lock = QueueLock(self.dir / "queue.json")
        active = self._queued_open()
        self.broker.pump()
        pending = active[0]
        self.assertIsNotNone(shown[0]["unlock"](self.password, list(pending.rows), 1))
        queued = [self._queued_open(session=session) for session in ("s1", "s2", "manual")]
        pending.deadline = self.now - 1  # даже здесь явная причина close важнее timeout
        result = {}
        closer = threading.Thread(target=lambda: result.update(self.call("close", session="s2")))
        closer.start()
        closer.join(5)
        self.assertFalse(closer.is_alive())
        self.assertTrue(result["closed"])
        for request in [active, *queued]:
            self._assert_closed_open(*request)
        self.assertFalse(self.call("close")["closed"])
        self.assertEqual(cancelled, [])  # worker close не вызывает Tk
        self.assertIs(self.broker._queue_owner, pending)
        self.assertTrue(pending.defer_release)
        self.assertTrue(self.broker.queue_lock.path.exists())
        self.assertEqual(shown[0]["done"](True, via="telegram"), (False, "", "доступ закрыт клиентом (close)"))
        self.now += 30
        self.broker.pump()
        self.assertEqual(len(cancelled), 1)
        self.assertTrue(self.broker.queue_lock.path.exists())
        self.assertIs(self.broker._queue_owner, pending)
        fresh = self._queued_open()
        self.broker.pump()
        self.assertEqual(len(shown), 1)
        shown[0]["on_channels_closed"]()
        self.assertFalse(self.broker.queue_lock.path.exists())
        for _ in range(4):
            self.broker.pump()
        self.assertEqual(len(shown), 2)  # отменённые queued не открывают окна
        new_token = fresh[0].queue_token
        shown[0]["on_channels_closed"]()  # старый cleanup не снимает новую аренду
        self.assertEqual(fresh[0].queue_token, new_token)
        self.assertIs(self.broker._queue_owner, fresh[0])
        self._approve_close_window(shown[1])
        fresh[1].join(5)
        self.assertTrue(fresh[2]["granted"])
        self.assertEqual(shown[0]["done"](True, via="telegram"), (False, "", "доступ закрыт клиентом (close)"))
        self.assertTrue(self.call("status")["granted"])
        self.assertEqual(len(cancelled), 1)

    def test_close_is_scoped_to_project_including_all_sessions(self):
        self.open("Такси", session="granted")
        self.open("Маркет", project="DEMO_B")
        self.call("get", session="granted", service="Такси", key="login")
        self.call("get", project="DEMO_B", service="Маркет", key="password")
        other_grant = self.broker.grants["DEMO_B"]
        other_report = self.call("report", project="DEMO_B")
        shown, _ = self._manual_close_ui()
        victims = [self._queued_open("Погода", session=session) for session in ("s1", "s2", "manual")]
        other = self._queued_open("Погода", project="DEMO_B", session="s2")
        self.assertTrue(self.call("close", session="s2")["closed"])
        for victim in victims:
            self._assert_closed_open(*victim)
        self.assertFalse(other[0].cancelled)
        self.assertFalse(self.call("status", session="granted")["granted"])
        self.assertEqual(self.call("get", session="granted", service="Такси", key="login")["error"],
                         "needs_access")
        self.assertTrue(self.call("status", project="DEMO_B")["granted"])
        self.assertEqual(self.broker.grants["DEMO_B"], other_grant)
        self.assertEqual(self.call("report", project="DEMO_B"), other_report)
        self.assertEqual(self.call("report", session="granted")["issued"], [])
        for _ in victims:
            self.broker.pump()  # отменённые запросы не открывают окна
        self.assertEqual(shown, [])
        self.broker.pump()
        self._approve_close_window(shown[0])
        other[1].join(5)
        self.assertFalse(other[1].is_alive())
        self.assertTrue(other[2]["granted"])

    def test_close_during_listing_before_enqueue_blocks_old_open_only(self):
        shown, _ = self._manual_close_ui()
        entered, release = threading.Event(), threading.Event()
        answer = {}
        listing = self.broker._current_listing

        def slow_listing():
            entered.set()
            if not release.wait(5):
                raise RuntimeError("synthetic listing barrier timeout")
            return listing()

        thread = threading.Thread(target=lambda: answer.update(self.open("Такси")), daemon=True)
        with mock.patch.object(self.broker, "_current_listing", side_effect=slow_listing):
            thread.start()
            try:
                self.assertTrue(entered.wait(5))
                self.assertTrue(self.call("close", session="s2")["closed"])
            finally:
                release.set()
                thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertIn("close", answer["message"])
        self.assertTrue(self.broker._pending.empty())
        self.assertEqual(self.broker._waiting, {})
        fresh = self._queued_open()
        self.broker.pump()
        self._approve_close_window(shown[0])
        fresh[1].join(5)
        self.assertTrue(fresh[2]["granted"])

    def test_close_during_vault_open_discards_late_decryption(self):
        shown, _ = self._manual_close_ui()
        request = self._queued_open()
        self.broker.pump()
        entered, release = threading.Event(), threading.Event()
        opened, results = Vault.open, []

        def slow_open(*args, **kwargs):
            vault = opened(*args, **kwargs)
            entered.set()
            if not release.wait(5):
                raise RuntimeError("synthetic decryption barrier timeout")
            return vault

        worker = threading.Thread(target=lambda: results.append(
            shown[0]["unlock"](self.password, list(request[0].rows), 1)), daemon=True)
        with mock.patch.object(Vault, "open", side_effect=slow_open):
            worker.start()
            try:
                self.assertTrue(entered.wait(5))
                self.assertTrue(self.call("close", session="s2")["closed"])
                self._assert_closed_open(*request)
            finally:
                release.set()
                worker.join(5)
        self.assertEqual(results, [None])
        self.assertEqual(shown[0]["done"](True, via="code"), (False, "", "доступ закрыт клиентом (close)"))
        self.assertIsNone(request[0].vault)
        self.assertFalse(self.call("status")["granted"])
        self.broker.pump()
        shown[0]["on_channels_closed"]()

    def test_close_during_remote_password_read_refuses_late_completion(self):
        shown, _ = self._manual_close_ui()
        request = self._queued_open()
        self.broker.pump()
        entered, release = threading.Event(), threading.Event()
        remote = mock.Mock()
        remote.chosen.return_value = list(request[0].rows)
        self.broker.remote_key_factory = mock.Mock(return_value=FakeTpm())
        results = []

        def password(*args):
            entered.set()
            if not release.wait(5):
                raise RuntimeError("synthetic remote barrier timeout")
            return self.password

        worker = threading.Thread(target=lambda: results.append(
            self.broker._unlock_by_code(request[0], remote, "synthetic", 1)), daemon=True)
        with mock.patch("pw_storage.broker.read_password", side_effect=password):
            worker.start()
            try:
                self.assertTrue(entered.wait(5))
                self.call("close", session="s2")
                self._assert_closed_open(*request)
            finally:
                release.set()
                worker.join(5)
        self.assertEqual(results, ["refused"])
        self.assertEqual(self.broker._remote_failures, 0)
        self.assertEqual(shown[0]["done"](True, via="telegram"), (False, "", "доступ закрыт клиентом (close)"))
        self.assertFalse(self.call("status")["granted"])
        self.broker.pump()
        shown[0]["on_channels_closed"]()

    def test_close_between_dequeue_and_ask_skips_window_and_releases_reservation(self):
        shown, cancelled = self._manual_close_ui()
        request = self._queued_open()
        listing = self.broker._current_listing

        def close_before_ask():
            closer = threading.Thread(target=lambda: self.call("close", session="s2"))
            closer.start()
            closer.join(5)
            self.assertFalse(closer.is_alive(), "pump must not hold lock while preparing UI")
            self.assertIs(self.broker._queue_owner, request[0])
            self.assertTrue(request[0].defer_release)
            return listing()

        with mock.patch.object(self.broker, "_current_listing", side_effect=close_before_ask):
            self.broker.pump()
        self._assert_closed_open(*request)
        self.assertEqual(shown, [])
        self.assertEqual(cancelled, [])
        self.assertIsNone(self.broker._queue_owner)
        self.assertIsNone(self.broker._active)

    def test_close_inside_ask_cancels_returned_callback_on_main_thread(self):
        shown, cancelled = self._manual_close_ui()
        request = self._queued_open()
        ask = self.ui.ask.side_effect

        def closing_ask(*args, **kwargs):
            cancel = ask(*args, **kwargs)
            closer = threading.Thread(target=lambda: self.call("close", session="s2"))
            closer.start()
            closer.join(5)
            self.assertFalse(closer.is_alive(), "ask must not hold broker lock")
            self.assertEqual(shown[0]["done"](True, via="telegram"), (False, "", "доступ закрыт клиентом (close)"))
            return cancel

        self.ui.ask.side_effect = closing_ask
        self.broker.pump()
        self._assert_closed_open(*request)
        self.assertEqual(len(cancelled), 1)
        self.assertIsNone(request[0].cancel_ui)
        self.assertIs(self.broker._queue_owner, request[0])
        self.broker.pump()
        self.assertEqual(len(cancelled), 1)
        shown[0]["on_channels_closed"]()
        self.assertIsNone(self.broker._queue_owner)

    # Пароль и второй фактор

    def test_wrong_password_is_denied_and_logged_without_value(self):
        self.ui.password = "wrong-" + secrets.token_urlsafe(16)
        self.assertEqual(self.open()["error"], "denied")
        self.assertFalse(self.call("status")["granted"])
        self.assertTrue(self.audit_events("password_failed"))
        self.assertNotIn(self.ui.password, self.profile.audit.read_text(encoding="utf-8"))

    def test_deny_by_owner(self):
        self.ui.decision = "deny"
        self.assertEqual(self.open()["error"], "denied")
        self.assertIsNone(self.broker.vault)
        self.assertEqual(self._row("Погода").projects, ("COMMON",))

    def test_totp_code_works_once_across_requests(self):
        self.ui.decision = "code"
        self.ui.code = pyotp.TOTP(self.totp_secret).at(self.now)
        self.assertTrue(self.open("Такси", session="s1")["granted"])
        self.assertEqual(self.open("Погода", session="s2")["error"], "denied")
        self.assertEqual(self.open("Маркет", project="DEMO_B")["error"], "denied")

    def test_no_vault(self):
        self.profile.vault.unlink()
        self.assertEqual(self.open()["error"], "no_vault")

    def test_catalog_is_rewritten_on_unlock(self):
        self._change_vault_outside("DEMO_A", "Новый", "token", "TEST-new", "Новая строка")
        self.assertEqual(catalog.read(self.key, self.profile.catalog, self.profile.vault).state, catalog.STALE)
        self.open("Такси")
        listing = catalog.read(self.key, self.profile.catalog, self.profile.vault)
        self.assertEqual(listing.state, catalog.FRESH)
        self.assertIn("Новая строка", [i.comment for i in listing.own("DEMO_A")])

    def test_project_unknown(self):
        answer = self.broker.dispatch({"op": "status"}, INFO, None, "s1")
        self.assertEqual(answer["error"], "project_unknown")

    # Журнал и отчёт (Т6, Т8)

    def test_audit_has_names_not_values(self):
        self.open(why="зачем-то")
        self.call("get", service="Такси", key="login")
        self.call("get", service="Маркет", key="password")
        text = self.profile.audit.read_text(encoding="utf-8")
        requested = self.audit_events("access_requested")[0]
        self.assertEqual((requested["rows"], requested["why"]), ([self.ids["Такси"], self.ids["Погода"]], "зачем-то"))
        issued = self.audit_events("value_issued")
        self.assertEqual((issued[0]["service"], issued[0]["key"], issued[0]["group"], issued[0]["row"]),
                         ("Такси", "login", "DEMO_A", self.ids["Такси"]))
        self.assertIn("value_refused", text)
        for value in [*self.values.values(), self.password, self.totp_secret]:
            self.assertNotIn(value, text)

    def test_report_lists_taken_keys(self):
        self.open()
        self.call("get", service="Такси", key="login")
        issued = self.call("report")["issued"]
        self.assertEqual([(i["id"], i["service"], i["key"]) for i in issued],
                         [(self.ids["Такси"], "Такси", "login")])
        self.assertNotIn(self.values["own"], json.dumps(issued))

    def test_audit_refuses_unknown_fields(self):
        with self.assertRaises(ValueError):
            Audit(self.profile.audit, echo=False).write("x", value="secret")

    def test_audit_records_approved_rows_by_name(self):
        self.open()
        granted = self.audit_events("access_granted")[0]
        self.assertEqual(granted["rows"], ["COMMON / Погода / API_KEY", "DEMO_A / Такси / login"])

    def test_idle_exit(self):
        self.assertFalse(self.broker.should_exit())
        self.now += IDLE_EXIT_SECONDS + 1
        self.assertTrue(self.broker.should_exit())

    def test_no_idle_exit_with_grant(self):
        self.open()
        self.now += IDLE_EXIT_SECONDS + 1
        self.assertFalse(self.broker.should_exit())

    def test_shutdown_only_in_test_profile(self):
        self.assertEqual(self.call("shutdown")["error"], "bad_request")
        self.assertFalse(self.broker.stop_requested)

    # Т23: выдаётся только то, что владелец видел

    def test_row_added_after_approval_is_not_issued(self):
        self.open(session="s1")
        self._change_vault_outside("DEMO_A", "Новый", "token", "TEST-new", "Новая строка")
        self.open("Маркет", project="DEMO_B")  # файл перечитан без одобрения новых строк DEMO_A
        answer = self.call("get", session="s1", service="Новый", key="token")
        self.assertEqual(answer["error"], "not_approved")
        self.assertNotIn("TEST-new", json.dumps(answer, ensure_ascii=False))
        self.assertNotIn("Новый", [row["service"] for row in self.call("list", session="s1")["rows"]])
        self.assertEqual(self.call("get", session="s1", service="Такси", key="login")["value"], self.values["own"])

    def test_row_with_changed_comment_is_not_issued(self):
        self.open(session="s1")
        self._change_vault_outside("DEMO_A", "Такси", "login", self.values["own"], "Другой смысл строки")
        self.open("Маркет", project="DEMO_B")
        self.assertEqual(self.call("get", session="s1", service="Такси", key="login")["error"], "not_approved")

    def test_row_with_changed_value_is_not_issued(self):
        self.open(session="s1")
        self._change_vault_outside("DEMO_A", "Такси", "login", "TEST-changed", "Логин Такси")
        self.open("Маркет", project="DEMO_B")
        self.assertEqual(self.call("get", session="s1", service="Такси", key="login")["error"], "not_approved")

    def test_changed_row_can_be_requested_again(self):
        self.open(session="s1")
        self._change_vault_outside("DEMO_A", "Такси", "login", "TEST-changed", "Логин Такси")
        self.open("Маркет", project="DEMO_B")
        self.assertTrue(self.open("Такси", session="s1")["granted"])
        self.assertEqual(self.call("get", session="s1", service="Такси", key="login")["value"], "TEST-changed")

    def test_removed_project_loses_row(self):
        self.open("Такси", session="s1")
        self._change_vault_outside("DEMO_A", "Такси", "login", self.values["own"], "Логин Такси", ("DEMO_B",))
        self.open("Погода", session="s2")
        self.assertEqual(self.call("get", session="s1", service="Такси", key="login")["error"], "not_found")

    def test_grant_holds_stamps_of_approved_rows(self):
        self.open()
        allowed = self.broker.grants["DEMO_A"].allowed
        self.assertEqual({(uid, service, key) for uid, service, key, _, _ in allowed},
                         {(self.ids["Такси"], "Такси", "login"), (self.ids["Погода"], "Погода", "API_KEY")})

    def test_grant_check_and_read_are_atomic_with_close(self):
        original = self.broker._has_grant
        for operation in ("get", "status"):
            with self.subTest(operation=operation):
                self.open("Такси")
                checking, release, closed = threading.Event(), threading.Event(), threading.Event()
                answer = {}

                def guarded(project):
                    granted = original(project)
                    checking.set()
                    release.wait(5)
                    return granted

                def close():
                    self.broker._close("DEMO_A", "s2")
                    closed.set()

                with mock.patch.object(self.broker, "_has_grant", side_effect=guarded):
                    reader = threading.Thread(target=lambda: answer.update(self.call(operation, service="Такси", key="login")))
                    closer = threading.Thread(target=close)
                    reader.start()
                    try:
                        self.assertTrue(checking.wait(5))
                        closer.start()
                        self.assertFalse(closed.wait(0.05))
                    finally:
                        release.set()
                        reader.join(5)
                        if closer.ident is not None:
                            closer.join(5)
                self.assertTrue(answer["ok"])
                self.assertTrue(closed.is_set())

    def test_queue_release_waits_for_channel_cleanup_and_is_request_owned(self):
        from pw_storage.remote import QueueLock
        self.broker.bot_api = FakeApi()
        self.broker.queue_lock = QueueLock(self.dir / "queue.json")
        first = _Pending("DEMO_A", "s1", defer_release=True)
        self.assertTrue(self.broker._hold_queue(first))
        self.broker._finish(first, False, reason="closed")
        self.assertTrue(self.broker.queue_lock.path.exists())
        self.assertIs(self.broker._queue_owner, first)
        self.broker._channels_closed(first)
        self.assertFalse(self.broker.queue_lock.path.exists())
        second = _Pending("DEMO_A", "s2")
        self.assertTrue(self.broker._hold_queue(second))
        token = second.queue_token
        self.broker._channels_closed(first)
        self.assertEqual(second.queue_token, token)
        self.assertTrue(self.broker.queue_lock.path.exists())
        self.broker._channels_closed(second)

    def test_synchronous_window_completion_does_not_retain_cancel_callback(self):
        self._stop_pump.set()
        self._pump.join(2)
        pending = _Pending("DEMO_A", "s1", (self.ids["Такси"],), deadline=self.now + 60)
        cancel = mock.Mock()

        def ask(request, unlock, done, **options):
            done(False, reason="closed during construction")
            options["on_channels_closed"]()
            return cancel

        with mock.patch.object(self.ui, "ask", side_effect=ask):
            self.broker._pending.put(pending)
            self.broker.pump()
        self.assertTrue(pending.finished)
        self.assertTrue(pending.event.is_set())
        self.assertIsNone(pending.cancel_ui)
        self.assertIsNone(self.broker._active)
        cancel.assert_not_called()

    def test_queue_busy_and_refresh_errors_fail_closed(self):
        from pw_storage.remote import QueueLock
        path = self.dir / "queue.json"
        other = QueueLock(path)
        other.refresh()
        original = path.read_bytes()
        self.broker.bot_api = FakeApi()
        self.broker.queue_lock = QueueLock(path)
        pending = _Pending("DEMO_A", "s1")
        self.assertFalse(self.broker._hold_queue(pending))
        self.assertIsNone(pending.queue_token)
        self.assertEqual(path.read_bytes(), original)
        other.release()
        with mock.patch.object(self.broker.queue_lock, "refresh", side_effect=OSError("synthetic guard failure")):
            self.assertFalse(self.broker._hold_queue(pending))
        self.assertIsNone(self.broker._queue_owner)

    def test_late_unlock_cannot_replace_newer_selection(self):
        self._stop_pump.set()
        self._pump.join(2)
        pending = _Pending("DEMO_A", "s1", deadline=self.now + 60)
        started = threading.Event()
        release = threading.Event()
        opened = Vault.open
        results = []
        worker_id = []

        def slow(*args, **kwargs):
            if threading.get_ident() == worker_id[0]:
                started.set()
                if not release.wait(5):
                    raise RuntimeError("synthetic barrier timeout")
            return opened(*args, **kwargs)

        def first():
            worker_id.append(threading.get_ident())
            results.append(self.broker._unlock(pending, self.password, [self.ids["Такси"]], 1))

        with mock.patch.object(Vault, "open", side_effect=slow):
            thread = threading.Thread(target=first)
            thread.start()
            try:
                self.assertTrue(started.wait(5))
                self.assertIsNotNone(self.broker._unlock(pending, self.password, [self.ids["Погода"]], 2))
            finally:
                release.set()
                thread.join(5)
        self.assertEqual(results, [None])
        self.assertEqual([row.uid for row in pending.chosen], [self.ids["Погода"]])
        self.assertEqual(pending.hours, 2)

    def test_expired_queued_request_never_opens_window(self):
        self._stop_pump.set()
        self._pump.join(2)
        pending = _Pending("DEMO_A", "s1", (self.ids["Такси"],), deadline=self.now - 1)
        self.broker._pending.put(pending)
        self.broker.pump()
        self.assertEqual(self.ui.requests, [])
        self.assertTrue(pending.event.is_set())
        self.assertEqual(pending.result["error"], "denied")
        self.assertFalse(self.call("status")["granted"])

    def test_expired_or_cancelled_request_cannot_grant(self):
        for cancelled in (False, True):
            with self.subTest(cancelled=cancelled):
                pending = _Pending("DEMO_A", "s1", deadline=self.now + 60 if cancelled else self.now - 1,
                                   cancelled=cancelled)
                pending.vault = Vault.open(self.profile.vault, self.password)
                pending.chosen = pending.vault.rows()
                self.broker._finish(pending, True, via="telegram")
                self.assertEqual(pending.result["error"], "denied")
                self.assertIsNone(pending.vault)
                self.assertEqual(pending.chosen, [])
                self.assertFalse(self.call("status")["granted"])
        self.assertEqual(self.audit_events("access_granted"), [])

    def test_timeout_cancels_pending_request(self):
        self._stop_pump.set()
        self._pump.join(2)
        with mock.patch.object(threading.Event, "wait", return_value=False):
            answer = self.open("Такси")
        pending = self.broker._pending.get_nowait()
        self.assertEqual(answer["error"], "timeout")
        self.assertTrue(pending.cancelled)
        with mock.patch.object(Vault, "open") as opener:
            self.assertIsNone(self.broker._unlock(pending, self.password, list(pending.rows), 12))
            opener.assert_not_called()
        self.broker._finish(pending, True, via="code")
        self.assertFalse(self.call("status")["granted"])

    def test_cancel_during_decryption_does_not_restore_pending_vault(self):
        pending = _Pending("DEMO_A", "s1", deadline=self.now + 60)
        vault = Vault.open(self.profile.vault, self.password)

        def cancel(*args):
            self.broker._finish(pending, False, reason="отменено")
            return vault

        with mock.patch.object(Vault, "open", side_effect=cancel):
            self.assertIsNone(self.broker._unlock(pending, self.password, [self.ids["Такси"]], 12))
        self.assertIsNone(pending.vault)
        self.assertEqual(pending.chosen, [])

    def test_finish_is_idempotent_and_does_not_close_next_request(self):
        pending = _Pending("DEMO_A", "s1")
        self.broker._finish(pending, False, reason="отказ")
        answer = dict(pending.result)
        next_request = _Pending("DEMO_A", "s2")
        self.broker._active = next_request
        self.assertEqual(self.broker._finish(pending, True, via="telegram"), (False, "", "отказ"))
        self.assertEqual(pending.result, answer)
        self.assertIs(self.broker._active, next_request)
        self.assertEqual(len(self.audit_events("access_denied")), 1)
        self.broker._active = None

    # Бот

    def test_bot_message_lists_what_will_be_issued(self):
        self.broker.bot_api = FakeApi()
        self.ui.choose = lambda request: [self.ids["Такси"]]
        self.open(why="проверить вход")
        confirm = self.ui.unlocked.telegram
        confirm.start()
        text = self.broker.bot_api.calls[-1][1]["text"]
        self.assertIn("Логин Такси", text)
        self.assertIn("проверить вход", text)
        self.assertNotIn("Общий ключ погоды", text)  # снят в окне
        self.assertNotIn("Пароль Маркет", text)
        for value in [*self.values.values(), self.password, self.totp_secret]:
            self.assertNotIn(value, text)

    def test_too_long_list_has_no_button(self):
        vault = Vault.open(self.profile.vault, self.password)
        for i in range(120):
            vault.put("DEMO_A", f"s{i}", "k", "TEST-x", f"Длинный комментарий номер {i} для проверки предела сообщения")
        vault.save()
        self._write_catalog()
        self.broker.bot_api = FakeApi()
        rows = [r.uid for r in Vault.open(self.profile.vault, self.password).rows() if r.service.startswith("s")]
        self.call("open", rows=rows, why=WHY)
        self.assertIsNone(self.ui.unlocked.telegram)

    # Telegram из хранилища: файла secrets.env у COMMON больше нет, токен берётся после ввода пароля

    def _telegram_settings(self):
        self.profile.settings.write_text(json.dumps({"telegram": True}), encoding="utf-8")

    def _telegram_rows(self, token="TEST-tg-token", chat="TEST-tg-chat", projects=("COMMON",), extra=False):
        vault = Vault.open(self.profile.vault, self.password)
        vault.put("COMMON", "Telegram", "TG_BOT_TOKEN", token, "Токен бота", projects)
        vault.put("COMMON", "Telegram", "TG_CHAT_ID", chat, "Chat id владельца", projects)
        if extra:
            vault.put("COMMON", "Telegram второй", "TG_BOT_TOKEN", token, "Дубль токена", projects)
        vault.save()

    def _unlock_one(self):
        return self.broker._unlock(_Pending("DEMO_A", "s1"), self.password, [self.ids["Такси"]], 1)

    def test_telegram_turns_on_after_first_unlock(self):
        self._telegram_settings()
        self._telegram_rows()
        self.assertIsNone(self.broker.bot_api, "на старте канала нет")
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            unlocked = self._unlock_one()
        self.assertIsNotNone(self.broker.bot_api)
        self.assertEqual(self.broker.bot_api.chat, "TEST-tg-chat")
        self.assertIsNotNone(unlocked.telegram, "подтверждение уходит в этот же запрос")
        self.assertIn("Telegram включён", out.getvalue())
        text = out.getvalue() + (self.profile.audit.read_text(encoding="utf-8") if self.profile.audit.exists() else "")
        for value in ("TEST-tg-token", "TEST-tg-chat", self.password):
            self.assertNotIn(value, text, "значения секретов в консоль и журнал не пишутся")

    def test_channel_enabled_only_once_keeps_the_first_api(self):
        self._telegram_settings()
        self._telegram_rows()
        with mock.patch("sys.stdout", new_callable=io.StringIO):
            self._unlock_one()
        api = self.broker.bot_api
        self._telegram_rows(token="TEST-tg-token-2", chat="TEST-tg-chat-2")
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            self._unlock_one()
        self.assertIs(self.broker.bot_api, api)
        self.assertNotIn("Telegram", out.getvalue(), "канал включают один раз: повторного решения нет")

    def test_telegram_stays_off_without_token_rows(self):
        self._telegram_settings()
        self._telegram_rows(projects=("DEMO_A",))  # строки есть, но проекту COMMON не разрешены
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            self.assertIsNone(self._unlock_one().telegram)
        self.assertIn("Telegram не включён", out.getvalue())
        self.assertNotIn("TEST-tg-token", out.getvalue())
        self.assertIsNone(self.broker.bot_api)
        self._telegram_rows(extra=True)  # и спорных строк тоже хватает
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            self.assertIsNone(self._unlock_one().telegram)
        self.assertIn("TG_BOT_TOKEN: строк 2", out.getvalue())
        self.assertIsNone(self.broker.bot_api)

    def test_telegram_stays_off_when_channel_disabled(self):
        self._telegram_rows()  # без settings.json канал выключен решением владельца
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            self._unlock_one()
        self.assertIsNone(self.broker.bot_api)
        self.assertNotIn("не включён", out.getvalue(), "выключенный канал — не поломка, сообщать не о чем")

    def test_empty_token_does_not_enable_channel(self):
        self._telegram_settings()
        self._telegram_rows()
        rows = Vault.open(self.profile.vault, self.password).rows()
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            self.broker._enable_telegram(rows, mock.Mock(value=lambda uid: ""))  # запись без пароля в KeePassXC
        self.assertIsNone(self.broker.bot_api)
        self.assertIn("пустое значение", out.getvalue())

    # Вложения и сохранение обновлённого токена: только синтетические данные.

    def _prepare_attachment_rows(self):
        self.attachment_data = b"TEST-JKS-" + secrets.token_bytes(512)
        self.values["nested"] = "TEST-" + secrets.token_urlsafe(24)

        def attach(vault):
            for group, service, key in (("DEMO_A", "Такси", "login"),
                                        ("COMMON", "Погода", "API_KEY"),
                                        ("DEMO_B", "Маркет", "password")):
                vault.attach(group, service, key, "release.jks", self.attachment_data)
            vault.attach("DEMO_A", "Такси", "login", "empty.jks", b"")
            nested = vault._kp.add_group(vault._group("DEMO_A"), "Nested")
            entry = vault._kp.add_entry(nested, "Вложенный", "token", self.values["nested"],
                                       notes="Synthetic nested token", tags=["DEMO_A"])
            entry.add_attachment(vault._kp.add_binary(self.attachment_data), "nested.jks")
            root = vault._kp.add_entry(vault._kp.root_group, "Корень", "token", self.values["nested"],
                                      notes="Synthetic root token", tags=["DEMO_A"])
            root.add_attachment(vault._kp.add_binary(b""), "empty.jks")
            system = vault._kp.add_entry(vault._group("_SYSTEM"), "Synthetic system", "token",
                                         self.values["foreign"], notes="Synthetic system entry", tags=["DEMO_A", "ALL"])
            system.add_attachment(vault._kp.add_binary(self.attachment_data), "release.jks")

        outside = self._change_vault_outside(edit=attach)
        self.ids.update({row.service: row.uid for row in outside.rows()})
        self._write_catalog()

    def _get_attachment(self, service="Такси", key="login", name="release.jks", **fields):
        return self.call("get_attachment", service=service, key=key, name=name, **fields)

    def _token_save(self, value, *, expected, service="Такси", key="login", **fields):
        return self.call("save_token", service=service, key=key, value=value, expected=expected, **fields)

    def _assert_token_reply(self, answer, uid, *, warning=False):
        self.assertEqual(set(answer), {"ok", "id", "warnings"})
        self.assertTrue(answer["ok"])
        self.assertEqual(answer["id"], uid)
        self.assertIsInstance(answer["warnings"], list)
        self.assertTrue(all(isinstance(item, str) for item in answer["warnings"]))
        self.assertEqual(bool(answer["warnings"]), warning)

    def _assert_live_unchanged(self, live, entries, grants, source_hash):
        self.assertIs(self.broker.vault, live)
        self.assertEqual(live.export_entries(), entries)
        self.assertEqual(live.source_hash, source_hash)
        self.assertEqual(self.broker.grants, grants)

    def test_attachment_round_trip_empty_root_nested_and_metadata_only(self):
        self._prepare_attachment_rows()
        self.assertTrue(self.open("Такси", "Вложенный", "Корень")["granted"])
        before = {path: path.read_bytes() for path in self.dir.rglob("*")
                  if path.is_file() and path != self.profile.audit}
        cases = (("Такси", "login", "release.jks", self.attachment_data),
                 ("Такси", "login", "empty.jks", b""),
                 ("Вложенный", "token", "nested.jks", self.attachment_data),
                 ("Корень", "token", "empty.jks", b""))
        for service, key, name, expected in cases:
            with self.subTest(service=service, name=name):
                answer = self._get_attachment(service, key, name)
                self.assertEqual(set(answer), {"ok", "id", "data"})
                self.assertTrue(answer["ok"])
                self.assertEqual(answer["id"], self.ids[service])
                self.assertIsInstance(answer["data"], str)
                answer["data"].encode("ascii")
                self.assertEqual(base64.b64decode(answer["data"], validate=True), expected)
        missing = self._get_attachment(name="missing.jks")
        self.assertEqual(missing["error"], "not_found")
        self.assertNotIn("data", missing)
        events = self.audit_events("attachment_issued")
        self.assertEqual(len(events), len(cases))
        for event, (service, key, name, _) in zip(events, cases):
            row = next(row for row in self.broker.vault.rows() if row.uid == self.ids[service])
            self.assertEqual((event["row"], event["group"], event["service"], event["key"],
                              event["pid"], event["script"], event["target"]),
                             (row.uid, row.group, service, key, INFO.pid, "", name))
        report = self.call("report")["issued"]
        self.assertEqual([(item["id"], item["service"], item["key"], item["attachment"]) for item in report],
                         [(self.ids[service], service, key, name) for service, key, name, _ in cases])
        metadata = json.dumps(report) + self.profile.audit.read_text(encoding="utf-8")
        for hidden in (*self.values.values(), self.password, self.totp_secret,
                       base64.b64encode(self.attachment_data).decode("ascii")):
            self.assertNotIn(hidden, metadata)
        for item in report:
            self.assertTrue({"value", "expected", "digest", "data"}.isdisjoint(item))
        self.assertEqual(before, {path: path.read_bytes() for path in self.dir.rglob("*")
                                  if path.is_file() and path != self.profile.audit})
        self._assert_no_plaintext_on_disk(self.attachment_data)

    def test_attachment_and_token_save_require_live_explicit_visible_grant(self):
        self._prepare_attachment_rows()
        new_value = "TEST-" + secrets.token_urlsafe(24)
        before = self.profile.vault.read_bytes()

        def refused(error, service="Такси", key="login", **fields):
            for answer in (self._get_attachment(service, key, **fields),
                           self._token_save(new_value, expected=self.values["own"],
                                            service=service, key=key, **fields)):
                self.assertFalse(answer["ok"])
                self.assertEqual(answer["error"], error)
                self.assertTrue({"value", "expected", "digest", "data"}.isdisjoint(answer))
                self.assertNotIn(new_value, json.dumps(answer))
                self.assertNotIn(self.values["own"], json.dumps(answer))

        refused("needs_access")
        self.open("Такси")
        refused("needs_access", project="DEMO_B")
        refused("not_approved", "Погода", "API_KEY")  # ALL is visibility, not approval.
        refused("not_approved", "Вложенный", "token")
        refused("not_found", "Маркет", "password")
        refused("not_found", "Synthetic system", "token")
        refused("not_found", "Nonexistent", "token")
        self.call("close")
        refused("needs_access")
        self.open("Такси")
        self.now += DEFAULT_GRANT_HOURS * 3600 + 1
        refused("needs_access")
        self.assertEqual(self.profile.vault.read_bytes(), before)
        self.assertEqual(self.audit_events("token_saved"), [])
        failures = self.audit_events("token_save_failed") + self.audit_events("token_save_refused")
        self.assertEqual(len(failures), 9)
        self._assert_no_plaintext_on_disk(self.attachment_data, new_value)

    def test_attachment_and_token_save_reject_malformed_fields_without_mutation(self):
        self._prepare_attachment_rows()
        self.open("Такси")
        live = self.broker.vault
        entries, grants, source_hash = live.export_entries(), dict(self.broker.grants), live.source_hash
        before = self.profile.vault.read_bytes()
        valid = {"get_attachment": {"service": "Такси", "key": "login", "name": "release.jks"},
                 "save_token": {"service": "Такси", "key": "login", "value": "TEST-new",
                                "expected": self.values["own"]}}
        for op, fields in valid.items():
            for field in fields:
                for bad in (None, True, 7, [], {}):
                    with self.subTest(op=op, field=field, kind=type(bad).__name__):
                        answer = self.call(op, **{**fields, field: bad})
                        self.assertEqual(answer["error"], "bad_request")
            required = ("name",) if op == "get_attachment" else ("value", "expected")
            for field in required:
                with self.subTest(op=op, missing=field):
                    answer = self.call(op, **{name: value for name, value in fields.items() if name != field})
                    self.assertEqual(answer["error"], "bad_request")
            nonempty = "name" if op == "get_attachment" else "value"
            self.assertEqual(self.call(op, **{**fields, nonempty: ""})["error"], "bad_request")
        self._assert_live_unchanged(live, entries, grants, source_hash)
        self.assertEqual(self.profile.vault.read_bytes(), before)
        self.assertEqual(self.audit_events("token_saved"), [])

    def test_attachment_change_invalidates_old_value_and_attachment_approval(self):
        self._prepare_attachment_rows()
        self.open("Такси", session="s1")
        old_stamp = self._row("Такси").stamp
        replacement = secrets.token_bytes(512)
        self._change_vault_outside(edit=lambda vault: vault.attach("DEMO_A", "Такси", "login",
                                                                  "release.jks", replacement))
        self.open("Вложенный", session="s2")  # Reload without approving the changed row.
        self.assertNotEqual(self._row("Такси").stamp, old_stamp)
        for answer in (self._get_attachment(), self.call("get", service="Такси", key="login"),
                       self._token_save("TEST-new", expected=self.values["own"])):
            self.assertEqual(answer["error"], "not_approved")
        self.assertTrue(self.open("Такси", session="s1")["granted"])
        self.assertEqual(base64.b64decode(self._get_attachment()["data"], validate=True), replacement)
        self._assert_no_plaintext_on_disk(self.attachment_data, replacement)

    def test_attachment_and_token_save_do_not_bypass_removed_visibility_or_comment(self):
        self._prepare_attachment_rows()
        self.open("Такси", "Вложенный", session="s1")

        def hide(vault):
            vault.set_tags(self.ids["Такси"], ("DEMO_B",), False)
            vault._entry_by_uid(self.ids["Вложенный"]).notes = ""

        self._change_vault_outside(edit=hide)
        self.open("Корень", session="s2")
        for service, key, name in (("Такси", "login", "release.jks"),
                                   ("Вложенный", "token", "nested.jks")):
            with self.subTest(service=service):
                self.assertEqual(self._get_attachment(service, key, name)["error"], "not_found")
                answer = self._token_save("TEST-new", expected=self.values["own"], service=service, key=key)
                self.assertEqual(answer["error"], "not_found")
        self.assertEqual(self.audit_events("token_saved"), [])

    def test_attachment_duplicate_filename_is_refused_as_ambiguous_attachment(self):
        self._prepare_attachment_rows()

        def duplicate(vault):
            entry = vault._entry("DEMO_A", "Такси", "login")
            entry.add_attachment(vault._kp.add_binary(b""), "release.jks")

        self._change_vault_outside(edit=duplicate)
        self._write_catalog()
        self.open("Такси")
        answer = self._get_attachment()
        self.assertEqual(answer["error"], "ambiguous_attachment")
        self.assertNotIn("data", answer)
        self.assertEqual(self.audit_events("attachment_issued"), [])

    def test_attachment_and_token_save_select_approved_duplicate_prefer_own_else_ambiguous(self):
        self._prepare_attachment_rows()
        other_value, third_value = "TEST-" + secrets.token_urlsafe(24), "TEST-" + secrets.token_urlsafe(24)
        other_data = secrets.token_bytes(128)

        def duplicate(vault):
            for group, value in (("OTHER", other_value), ("THIRD", third_value)):
                vault.put(group, "Такси", "login", value, "Synthetic duplicate", ("DEMO_A",))
                vault.attach(group, "Такси", "login", "release.jks", other_data)

        outside = self._change_vault_outside(edit=duplicate)
        ids = {row.group: row.uid for row in outside.rows() if row.service == "Такси"}
        self._write_catalog()
        self.assertTrue(self.call("open", rows=[ids["OTHER"]], why=WHY, session="only-other")["granted"])
        answer = self._get_attachment(session="only-other")
        self.assertEqual(answer["id"], ids["OTHER"])
        self.assertEqual(base64.b64decode(answer["data"], validate=True), other_data)
        updated_other = "TEST-" + secrets.token_urlsafe(24)
        self._assert_token_reply(self._token_save(updated_other, expected=other_value, session="only-other"), ids["OTHER"])
        self.assertTrue(self.call("open", rows=[ids["DEMO_A"], ids["OTHER"]], why=WHY, session="both")["granted"])
        answer = self._get_attachment(session="both")
        self.assertEqual(answer["id"], ids["DEMO_A"])
        self.assertEqual(base64.b64decode(answer["data"], validate=True), self.attachment_data)
        updated_own = "TEST-" + secrets.token_urlsafe(24)
        self._assert_token_reply(self._token_save(updated_own, expected=self.values["own"], session="both"), ids["DEMO_A"])
        self.call("close", session="both")  # новая выборка без ранее одобренной собственной строки
        self.assertTrue(self.call("open", rows=[ids["OTHER"], ids["THIRD"]], why=WHY, session="ambiguous")["granted"])
        before = self.profile.vault.read_bytes()
        self.assertEqual(self._get_attachment(session="ambiguous")["error"], "ambiguous")
        self.assertEqual(self._token_save("TEST-unused", expected=updated_other, session="ambiguous")["error"], "ambiguous")
        self.assertEqual(self.profile.vault.read_bytes(), before)
        reopened = Vault.open(self.profile.vault, self.password)
        self.assertEqual([reopened.value(ids[group]) for group in ("DEMO_A", "OTHER", "THIRD")],
                         [updated_own, updated_other, third_value])
        self._assert_no_plaintext_on_disk(self.attachment_data, other_data, other_value, third_value,
                                          updated_other, updated_own)

    def test_token_save_persists_value_only_replaces_uid_stamps_preserves_expiry(self):
        self._prepare_attachment_rows()
        self._change_vault_outside(edit=lambda vault: vault.set_tags(self.ids["Такси"],
                                                                    ("DEMO_A", "DEMO_B"), False))
        self._write_catalog()
        self.open("Такси", "Погода", "Вложенный", session="s1")
        self.open("Такси", "Погода", project="DEMO_B", session="s2")
        uid = self.ids["Такси"]
        grant = self.broker.grants["DEMO_A"]
        old_row = next(row for row in self.broker.vault.rows() if row.uid == uid)
        obsolete = (*old_row.stamp[:-1], "synthetic-obsolete-stamp")
        self.broker.grants["DEMO_A"] = type(grant)(grant.expires, grant.allowed | {obsolete})
        before = {entry.uid: entry for entry in self.broker.vault.export_entries()}
        other_grant = self.broker.grants["DEMO_B"]
        self.now += 3600
        new_value = "TEST-" + secrets.token_urlsafe(24)
        self._assert_token_reply(self._token_save(new_value, expected=self.values["own"]), uid)
        reopened = Vault.open(self.profile.vault, self.password)
        after = {entry.uid: entry for entry in reopened.export_entries()}
        self.assertEqual(set(after), set(before))
        for entry_uid, old in before.items():
            if entry_uid != uid:
                self.assertEqual(after[entry_uid], old)
            else:
                self.assertEqual(after[uid].value, new_value)
                for field in ("uid", "group", "service", "key", "comment", "projects", "shared", "attachments"):
                    self.assertEqual(getattr(after[uid], field), getattr(old, field))
        self.assertEqual(reopened.system_value(TOTP_ENTRY), self.totp_secret)
        current_row = next(row for row in self.broker.vault.rows() if row.uid == uid)
        current_grant = self.broker.grants["DEMO_A"]
        self.assertEqual(current_grant.expires, grant.expires)
        self.assertEqual({stamp for stamp in current_grant.allowed if stamp[0] == uid}, {current_row.stamp})
        self.assertEqual({stamp for stamp in current_grant.allowed if stamp[0] != uid},
                         {stamp for stamp in grant.allowed if stamp[0] != uid})
        self.assertEqual(self.broker.grants["DEMO_B"], other_grant)
        self.assertEqual(self.call("get", service="Такси", key="login")["value"], new_value)
        self.assertEqual(base64.b64decode(self._get_attachment()["data"], validate=True), self.attachment_data)
        self.assertEqual(self.call("get", service="Такси", key="login", session="s2")["value"], new_value)
        self.assertEqual(base64.b64decode(self._get_attachment(session="s2")["data"], validate=True), self.attachment_data)
        self.assertEqual(self.call("report", session="s1"), self.call("report", session="s2"))
        self.assertEqual(self.call("get", project="DEMO_B", service="Такси", key="login")["error"], "not_approved")
        self.assertEqual(self._get_attachment(project="DEMO_B")["error"], "not_approved")
        self.assertEqual(self._token_save("TEST-unused", expected=new_value, project="DEMO_B")["error"], "not_approved")
        self.assertEqual(self.call("get", project="DEMO_B", service="Погода", key="API_KEY")["value"], self.values["common"])
        listing = catalog.read(self.key, self.profile.catalog, self.profile.vault)
        self.assertEqual(listing.state, catalog.FRESH)
        self.assertEqual(self.broker.vault.source_hash, reopened.source_hash)
        saved = self.audit_events("token_saved")
        self.assertEqual(len(saved), 1)
        self.assertEqual((saved[0]["row"], saved[0]["group"], saved[0]["service"], saved[0]["key"]),
                         (uid, "DEMO_A", "Такси", "login"))
        metadata = self.profile.audit.read_text(encoding="utf-8") + json.dumps(self.call("report"))
        self.assertNotIn(new_value, metadata)
        self.assertNotIn(self.values["own"], metadata)
        self.assertNotIn(current_row.digest, metadata)
        self._assert_no_plaintext_on_disk(self.attachment_data, new_value)
        self.now = grant.expires + 1
        self.assertEqual(self.call("get", service="Такси", key="login")["error"], "needs_access")

    def test_token_compare_and_set_two_writers_only_one_wins(self):
        self.open("Такси")
        values = ["TEST-" + secrets.token_urlsafe(24) for _ in range(2)]
        gate = threading.Barrier(3)
        results, errors = {}, []

        def writer(index):
            try:
                gate.wait(5)
                results[index] = self._token_save(values[index], expected=self.values["own"], session=f"s{index + 1}")
            except Exception as error:
                errors.append(type(error).__name__)

        threads = [threading.Thread(target=writer, args=(index,)) for index in range(2)]
        for thread in threads:
            thread.start()
        try:
            gate.wait(5)
        finally:
            for thread in threads:
                thread.join(10)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 2)
        winners = [index for index, answer in results.items() if answer["ok"]]
        self.assertEqual(len(winners), 1)
        loser = results[1 - winners[0]]
        self.assertEqual(loser["error"], "token_conflict")
        self.assertNotIn("value", loser)
        self._assert_token_reply(results[winners[0]], self.ids["Такси"])
        self.assertEqual(Vault.open(self.profile.vault, self.password).value(self.ids["Такси"]), values[winners[0]])
        self.assertEqual(self.call("get", service="Такси", key="login")["value"], values[winners[0]])
        self.assertEqual(len(self.audit_events("token_saved")), 1)
        failures = self.audit_events("token_save_refused") + self.audit_events("token_save_failed")
        self.assertEqual(len(failures), 1)
        self._assert_no_plaintext_on_disk(*values)

    def test_token_save_empty_expected_is_valid_compare_and_set_not_bad_request(self):
        self.open("Такси")
        before = self.profile.vault.read_bytes()
        answer = self._token_save("TEST-new", expected="")
        self.assertEqual(answer["error"], "token_conflict")
        self.assertEqual(self.profile.vault.read_bytes(), before)
        self.assertEqual(self.call("get", service="Такси", key="login")["value"], self.values["own"])

    def test_token_save_external_file_change_preserves_live_model_and_grants(self):
        self.open("Такси")
        live = self.broker.vault
        entries, grants, source_hash = live.export_entries(), dict(self.broker.grants), live.source_hash
        outside = self._change_vault_outside("DEMO_A", "External", "token", "TEST-external", "External edit")
        before = self.profile.vault.read_bytes()
        answer = self._token_save("TEST-new", expected=self.values["own"])
        self.assertEqual(answer["error"], "vault_changed")
        self.assertEqual(self.profile.vault.read_bytes(), before)
        self._assert_live_unchanged(live, entries, grants, source_hash)
        self.assertEqual(Vault.open(self.profile.vault, self.password).export_entries(), outside.export_entries())
        self.assertEqual(self.audit_events("token_saved"), [])

    def test_token_save_concurrent_external_writer_is_not_overwritten(self):
        self.open("Такси")
        live = self.broker.vault
        entries, grants, source_hash = live.export_entries(), dict(self.broker.grants), live.source_hash
        save = Vault.save
        external_bytes = []
        outside_value = "TEST-" + secrets.token_urlsafe(24)
        attempted_value = "TEST-" + secrets.token_urlsafe(24)

        def race(working, *args, **kwargs):
            self.assertIsNot(working, live)
            outside = Vault.open(self.profile.vault, self.password)
            outside.update_entry(self.ids["Такси"], value=outside_value)
            save(outside)
            external_bytes.append(self.profile.vault.read_bytes())
            return save(working, *args, **kwargs)

        with mock.patch.object(Vault, "save", autospec=True, side_effect=race):
            answer = self._token_save(attempted_value, expected=self.values["own"])
        self.assertEqual(answer["error"], "vault_changed")
        self.assertEqual(len(external_bytes), 1)
        self.assertEqual(self.profile.vault.read_bytes(), external_bytes[0])
        self._assert_live_unchanged(live, entries, grants, source_hash)
        self.assertEqual(Vault.open(self.profile.vault, self.password).value(self.ids["Такси"]), outside_value)
        self._assert_no_plaintext_on_disk(outside_value, attempted_value)

    def test_token_save_precommit_failures_do_not_pollute_or_disclose(self):
        self._prepare_attachment_rows()
        self.open("Такси")
        live = self.broker.vault
        entries, grants, source_hash = live.export_entries(), dict(self.broker.grants), live.source_hash
        before_vault, before_catalog = self.profile.vault.read_bytes(), self.profile.catalog.read_bytes()
        new_value = "TEST-" + secrets.token_urlsafe(24)
        self.broker.audit.echo = True
        for method in ("clone", "update_entry", "save"):
            with self.subTest(method=method):
                def fail(working, *args, **kwargs):
                    if method == "save":
                        self.assertIsNot(working, live)
                        working.add_project(self.ids["Такси"], "UNSAVED")
                    raise OSError(new_value + " / " + self.values["own"])

                with mock.patch.object(Vault, method, autospec=True, side_effect=fail), \
                     mock.patch.object(sys, "stdout", new_callable=io.StringIO) as stdout, \
                     mock.patch.object(sys, "stderr", new_callable=io.StringIO) as stderr:
                    answer = self._token_save(new_value, expected=self.values["own"])
                self.assertEqual(answer["error"], "save_failed")
                self._assert_live_unchanged(live, entries, grants, source_hash)
                self.assertEqual(self.profile.vault.read_bytes(), before_vault)
                self.assertEqual(self.profile.catalog.read_bytes(), before_catalog)
                emitted = stdout.getvalue() + stderr.getvalue() + json.dumps(answer) + self.profile.audit.read_text(encoding="utf-8")
                for value in (new_value, *self.values.values(), self.password, self.totp_secret):
                    self.assertNotIn(value, emitted)
        self.broker.audit.echo = False
        failures = self.audit_events("token_save_failed")
        self.assertEqual(len(failures), 3)
        self.assertTrue(all(event["reason"] == "OSError" for event in failures))
        self.assertEqual(self.audit_events("token_saved"), [])
        self._assert_token_reply(self._token_save(new_value, expected=self.values["own"]), self.ids["Такси"])
        self.assertNotIn("UNSAVED", self._row("Такси").projects)
        self._assert_no_plaintext_on_disk(self.attachment_data, new_value)

    def test_token_save_refuses_during_pending_approval(self):
        self.open("Такси")
        self._stop_pump.set()
        self._pump.join(2)
        live = self.broker.vault
        entries, grants, source_hash = live.export_entries(), dict(self.broker.grants), live.source_hash
        before = self.profile.vault.read_bytes()
        pending = _Pending("DEMO_A", "s2", (self.ids["Такси"],), vault=live.clone(),
                           chosen=live.rows(), presented=True, deadline=self.now + 60)
        self.broker._active = pending
        try:
            with mock.patch.object(Vault, "save") as save:
                answer = self._token_save("TEST-new", expected=self.values["own"])
            self.assertEqual(answer["error"], "vault_busy")
            save.assert_not_called()
            self.assertIs(self.broker._active, pending)
            self.assertFalse(pending.finished)
            self._assert_live_unchanged(live, entries, grants, source_hash)
            self.assertEqual(self.profile.vault.read_bytes(), before)
        finally:
            self.broker._active = None

    def test_token_save_current_cleanup_failure_is_committed_with_warning_and_new_grant(self):
        self._prepare_attachment_rows()
        self._change_vault_outside(edit=lambda vault: vault.set_tags(self.ids["Такси"],
                                                                    ("DEMO_A", "DEMO_B"), False))
        self._write_catalog()
        self.open("Такси", session="s1")
        self.open("Такси", project="DEMO_B")
        other_grant = self.broker.grants["DEMO_B"]
        grant = self.broker.grants["DEMO_A"]
        before_hash = self.broker.vault.source_hash
        new_value = "TEST-" + secrets.token_urlsafe(24)
        atomic = vault_module._atomic_bytes

        def fail_backup(path, data):
            if Path(path) == self.profile.vault.with_name(self.profile.vault.name + ".bak"):
                raise OSError(new_value)
            return atomic(path, data)

        with mock.patch.object(vault_module, "_atomic_bytes", side_effect=fail_backup):
            answer = self._token_save(new_value, expected=self.values["own"])
            self._assert_token_reply(answer, self.ids["Такси"], warning=True)
            self.assertNotEqual(self.broker.vault.source_hash, before_hash)
            self.assertEqual(self.broker.vault.source_hash, vault_module.file_hash(self.profile.vault))
            self.assertEqual(self.call("get", service="Такси", key="login")["value"], new_value)
            self.assertEqual(self.call("get", service="Такси", key="login", session="s2")["value"], new_value)
            self.assertEqual(self.call("get", project="DEMO_B", service="Такси", key="login")["error"], "not_approved")
            self.assertEqual(self.broker.grants["DEMO_B"], other_grant)
        self.assertEqual(self.broker.grants["DEMO_A"].expires, grant.expires)
        self.assertEqual(Vault.open(self.profile.vault, self.password).value(self.ids["Такси"]), new_value)
        self.assertEqual(len(self.audit_events("token_saved")), 1)
        self.assertEqual(self.audit_events("token_save_failed"), [])
        self.assertNotIn(new_value, json.dumps(answer) + self.profile.audit.read_text(encoding="utf-8"))
        self._assert_no_plaintext_on_disk(self.attachment_data, new_value)

    def test_token_save_prior_cleanup_failure_is_not_current_commit(self):
        self.open("Такси")
        live = self.broker.vault
        entries, grants, source_hash = live.export_entries(), dict(self.broker.grants), live.source_hash
        prior = Vault.open(self.profile.vault, self.password)
        prior_value, attempted_value = "TEST-" + secrets.token_urlsafe(24), "TEST-" + secrets.token_urlsafe(24)
        prior.update_entry(self.ids["Такси"], value=prior_value)
        atomic = vault_module._atomic_bytes

        def fail_backup(path, data):
            if Path(path) == self.profile.vault.with_name(self.profile.vault.name + ".bak"):
                raise OSError(attempted_value)
            return atomic(path, data)

        with mock.patch.object(vault_module, "_atomic_bytes", side_effect=fail_backup):
            with self.assertRaises(VaultCommitted):
                prior.save()
            prior_bytes = self.profile.vault.read_bytes()
            answer = self._token_save(attempted_value, expected=self.values["own"])
        self.assertFalse(answer["ok"])
        self.assertEqual(answer["error"], "save_failed")
        self.assertEqual(self.profile.vault.read_bytes(), prior_bytes)
        self._assert_live_unchanged(live, entries, grants, source_hash)
        self.assertEqual(Vault.open(self.profile.vault, self.password).value(self.ids["Такси"]), prior_value)
        self.assertEqual(self.audit_events("token_saved"), [])
        self.assertEqual(len(self.audit_events("token_save_failed")), 1)
        emitted = json.dumps(answer) + self.profile.audit.read_text(encoding="utf-8")
        for value in (attempted_value, prior_value, self.values["own"]):
            self.assertNotIn(value, emitted)
        self._assert_no_plaintext_on_disk(prior_value, attempted_value)

    def test_token_save_catalog_and_tpm_failures_are_warnings_after_commit(self):
        from pw_storage.tpm import TpmError

        self.open("Такси")
        grant = self.broker.grants["DEMO_A"]
        expected = self.values["own"]
        for target, method, error_type in ((catalog, "write", OSError), (self.key, "encrypt", TpmError)):
            with self.subTest(method=method):
                new_value = "TEST-" + secrets.token_urlsafe(24)
                self.broker.audit.echo = True
                with mock.patch.object(target, method, side_effect=error_type(new_value + " / " + expected)), \
                     mock.patch.object(sys, "stdout", new_callable=io.StringIO) as stdout, \
                     mock.patch.object(sys, "stderr", new_callable=io.StringIO) as stderr:
                    answer = self._token_save(new_value, expected=expected)
                self.broker.audit.echo = False
                self._assert_token_reply(answer, self.ids["Такси"], warning=True)
                self.assertEqual(Vault.open(self.profile.vault, self.password).value(self.ids["Такси"]), new_value)
                self.assertEqual(self.call("get", service="Такси", key="login")["value"], new_value)
                current = next(row for row in self.broker.vault.rows() if row.uid == self.ids["Такси"])
                updated_grant = self.broker.grants["DEMO_A"]
                self.assertEqual(updated_grant.expires, grant.expires)
                self.assertIn(current.stamp, updated_grant.allowed)
                emitted = stdout.getvalue() + stderr.getvalue() + json.dumps(answer) + self.profile.audit.read_text(encoding="utf-8")
                self.assertNotIn(new_value, emitted)
                self.assertNotIn(expected, emitted)
                self.assertNotIn(current.digest, emitted)
                self._assert_no_plaintext_on_disk(new_value)
                expected = new_value
        self.assertEqual(len(self.audit_events("token_saved")), 2)
        self.assertEqual(self.audit_events("token_save_failed"), [])

    def test_token_commit_survives_unavailable_audit_echo(self):
        self.open("Такси")
        grant = self.broker.grants["DEMO_A"]
        expected = self.values["own"]
        for mode in ("ascii", "closed", "broken"):
            with self.subTest(mode=mode):
                new_value = "TEST-" + secrets.token_urlsafe(24)
                stream = io.TextIOWrapper(io.BytesIO(), encoding="ascii")
                if mode == "closed":
                    stream.close()
                write = mock.Mock(wraps=stream.write, side_effect=BrokenPipeError() if mode == "broken" else None)
                self.broker.audit.echo = True
                try:
                    with mock.patch.object(sys, "stdout", stream), mock.patch.object(stream, "write", write):
                        answer = self._token_save(new_value, expected=expected)
                finally:
                    self.broker.audit.echo = False
                    stream.close()
                self._assert_token_reply(answer, self.ids["Такси"], warning=True)
                self.assertEqual(Vault.open(self.profile.vault, self.password).value(self.ids["Такси"]), new_value)
                self.assertEqual(self.call("get", service="Такси", key="login")["value"], new_value)
                self.assertEqual(self.broker.vault.source_hash, vault_module.file_hash(self.profile.vault))
                current = next(row for row in self.broker.vault.rows() if row.uid == self.ids["Такси"])
                updated_grant = self.broker.grants["DEMO_A"]
                self.assertEqual(updated_grant.expires, grant.expires)
                self.assertIn(current.stamp, updated_grant.allowed)
                emitted = json.dumps(answer) + self.profile.audit.read_text(encoding="utf-8")
                self.assertTrue(write.called)
                emitted += "".join(call.args[0] for call in write.call_args_list)
                for hidden in (new_value, expected, current.digest, self.password, self.totp_secret):
                    self.assertNotIn(hidden, emitted)
                self._assert_no_plaintext_on_disk(new_value)
                expected = new_value
        self.assertEqual(len(self.audit_events("token_saved")), 3)
        self.assertEqual(self.audit_events("token_save_failed"), [])

    def test_committed_list_extension_cleanup_failure_keeps_next_token_save_working(self):
        before_hash = vault_module.file_hash(self.profile.vault)
        atomic = vault_module._atomic_bytes

        def fail_backup(path, data):
            if Path(path) == self.profile.vault.with_name(self.profile.vault.name + ".bak"):
                raise OSError("synthetic extension cleanup failure")
            return atomic(path, data)

        with mock.patch.object(vault_module, "_atomic_bytes", side_effect=fail_backup):
            self.assertTrue(self.open("Погода")["granted"])
            self.assertNotEqual(self.broker.vault.source_hash, before_hash)
            self.assertEqual(self.broker.vault.source_hash, vault_module.file_hash(self.profile.vault))
            row = next(row for row in self.broker.vault.rows() if row.uid == self.ids["Погода"])
            self.assertEqual(row.projects, ("COMMON", "DEMO_A"))
            self.assertIn(row.stamp, self.broker.grants["DEMO_A"].allowed)
        self.assertEqual(self._row("Погода").projects, ("COMMON", "DEMO_A"))
        events = self.audit_events("list_extended")
        self.assertEqual(len(events), 1)
        self.assertIn("очистка", events[0]["reason"])
        self.assertEqual(self.audit_events("list_extend_failed"), [])
        grant = self.broker.grants["DEMO_A"]
        new_value = "TEST-" + secrets.token_urlsafe(24)
        answer = self._token_save(new_value, expected=self.values["common"], service="Погода", key="API_KEY")
        self._assert_token_reply(answer, self.ids["Погода"])
        self.assertEqual(self._row("Погода").projects, ("COMMON", "DEMO_A"))
        self.assertEqual(Vault.open(self.profile.vault, self.password).value(self.ids["Погода"]), new_value)
        self.assertEqual(self.call("get", service="Погода", key="API_KEY")["value"], new_value)
        self.assertEqual(self.broker.grants["DEMO_A"].expires, grant.expires)
        self.assertEqual(catalog.read(self.key, self.profile.catalog, self.profile.vault).state, catalog.FRESH)
        self.assertEqual(len(self.audit_events("token_saved")), 1)
        self.assertNotIn(new_value, json.dumps(answer) + self.profile.audit.read_text(encoding="utf-8"))
        self._assert_no_plaintext_on_disk(new_value)

    def test_failed_list_extension_does_not_pollute_live_tags(self):
        before = self.profile.vault.read_bytes()
        with mock.patch.object(Vault, "save", side_effect=OSError("synthetic extension failure")):
            self.assertTrue(self.open("Погода")["granted"])
        row = next(row for row in self.broker.vault.rows() if row.uid == self.ids["Погода"])
        self.assertEqual(row.projects, ("COMMON",))
        self.assertTrue(row.shared)
        self.assertEqual(self._row("Погода").projects, ("COMMON",))
        self.assertEqual(self.profile.vault.read_bytes(), before)
        self.assertEqual(self.call("get", service="Погода", key="API_KEY")["value"], self.values["common"])
        self.assertEqual(self.call("preview")["common"], [{"id": row.uid, "comment": row.comment, "all": True}])
        self.assertEqual(len(self.audit_events("list_extend_failed")), 1)
        self.call("close", session="s2")  # повтор уже разрешённой строки не является новым одобрением
        self.assertTrue(self.open("Погода", session="s2")["granted"])
        self.assertEqual(self._row("Погода").projects, ("COMMON", "DEMO_A"))

    # Настоящий канал

    def test_real_client_over_real_pipe(self):
        self.broker.start()
        folder = self.profile.projects_root / "DEMO_A" / "tools"
        folder.mkdir(parents=True)
        script = folder / "run.py"
        script.write_text(CHILD, encoding="utf-8")
        env = {**os.environ, "PYTHONPATH": str(HOME), "PYTHONUTF8": "1"}
        run = subprocess.run([sys.executable, str(script), self.profile.pipe], capture_output=True, text=True,
                             encoding="utf-8", env=env, cwd=self.dir, timeout=60)
        self.assertEqual(run.returncode, 0, run.stderr)
        out = json.loads(run.stdout)
        self.assertEqual(out["project"]["result"], "DEMO_A")
        self.assertFalse(out["status"]["result"])
        self.assertEqual(out["get_before"]["error"], "NeedsAccess")
        self.assertEqual(out["preview"]["result"], catalog.FRESH)
        self.assertEqual(out["unknown"]["error"], "NotFound")
        self.assertTrue(out["open"]["result"])
        self.assertTrue(out["status_after"]["result"])
        self.assertEqual({r["id"] for r in out["rows"]["result"]}, {self.ids["Такси"], self.ids["Погода"]})
        self.assertEqual(out["own"]["result"], self.values["own"])
        self.assertEqual(out["common"]["result"], self.values["common"])
        self.assertEqual(out["foreign"]["error"], "NotFound")
        self.assertEqual([(i["service"], i["key"]) for i in out["report"]["result"]],
                         [("Такси", "login"), ("Погода", "API_KEY")])
        self.assertTrue(out["close"]["result"])
        self.assertEqual(out["after_close"]["error"], "NeedsAccess")
        # Т8: в stderr имена взятых ключей, значений нет.
        self.assertIn(f"взят ключ: Такси / login (строка {self.ids['Такси']})", run.stderr)
        for value in self.values.values():
            self.assertNotIn(value, run.stderr)
        self._assert_no_plaintext_on_disk()

    def test_real_client_attachment_and_token_methods_over_pipe_without_plaintext_output(self):
        self._prepare_attachment_rows()
        self.broker.start()
        folder = self.profile.projects_root / "DEMO_A" / "attachment-tools"
        folder.mkdir(parents=True)
        script = folder / "run.py"
        script.write_text("""
import base64, json, sys
from pw_storage.client import PwClient, NeedsAccess, NotFound, PwError
pw = PwClient(pipe=sys.argv[1])
data = json.loads(sys.stdin.read())
attachment = base64.b64decode(data['attachment'])
out = {'completed': False}
def check(name, action):
    try:
        out[name] = bool(action())
    except Exception:
        out[name] = False
def refuses(action, error):
    try:
        action()
    except error as exc:
        return all(value not in str(exc) for value in (data['old'], data['new'], data['attachment']))
    except Exception:
        return False
    return False
def attachment_matches(service, key, name, expected):
    actual = pw.get_attachment(service, key, name)
    return type(actual) is bytes and actual == expected
try:
    check('attachment_before', lambda: refuses(lambda: pw.get_attachment('Такси', 'login', 'release.jks'), NeedsAccess))
    check('save_before', lambda: refuses(lambda: pw.save_token('Такси', 'login', data['new'], expected=data['old']), NeedsAccess))
    preview = pw.preview()
    check('opened', lambda: pw.open([row['id'] for row in (*preview['own'], *preview['common'])], why='synthetic client regression')['granted'])
    check('bytes', lambda: attachment_matches('Такси', 'login', 'release.jks', attachment))
    check('empty', lambda: attachment_matches('Такси', 'login', 'empty.jks', b''))
    check('nested', lambda: attachment_matches('Вложенный', 'token', 'nested.jks', attachment))
    check('root', lambda: attachment_matches('Корень', 'token', 'empty.jks', b''))
    check('missing', lambda: refuses(lambda: pw.get_attachment('Такси', 'login', 'missing.jks'), NotFound))
    check('expected_required', lambda: refuses(lambda: pw.save_token('Такси', 'login', data['new']), TypeError))
    check('expected_keyword_only', lambda: refuses(lambda: pw.save_token('Такси', 'login', data['new'], data['old']), TypeError))
    answer = pw.save_token('Такси', 'login', data['new'], expected=data['old'])
    out['save_reply'] = set(answer) == {'ok', 'id', 'warnings'} and answer['ok'] is True and isinstance(answer['warnings'], list)
    out['warning_count'] = len(answer['warnings'])
    check('persisted', lambda: pw.get('Такси', 'login') == data['new'])
    check('conflict', lambda: refuses(lambda: pw.save_token('Такси', 'login', data['old'], expected=data['old']), PwError))
    report = pw.report()
    out['report_count'] = len(report)
    out['report_metadata_only'] = all({'value', 'expected', 'digest', 'data'}.isdisjoint(row) for row in report)
    check('closed', lambda: pw.close()['closed'])
    check('attachment_after', lambda: refuses(lambda: pw.get_attachment('Такси', 'login', 'release.jks'), NeedsAccess))
    check('save_after', lambda: refuses(lambda: pw.save_token('Такси', 'login', data['old'], expected=data['new']), NeedsAccess))
    out['completed'] = True
except Exception:
    out['completed'] = False
sys.stdout.reconfigure(encoding='utf-8')
print(json.dumps(out))
""", encoding="utf-8")
        new_value = "TEST-" + secrets.token_urlsafe(24)
        payload = {"old": self.values["own"], "new": new_value,
                   "attachment": base64.b64encode(self.attachment_data).decode("ascii")}
        env = {**os.environ, "PYTHONPATH": str(HOME), "PYTHONUTF8": "1", "PYTHONDONTWRITEBYTECODE": "1"}
        run = subprocess.run([sys.executable, str(script), self.profile.pipe], input=json.dumps(payload),
                             capture_output=True, text=True, encoding="utf-8", env=env, cwd=self.dir, timeout=60)
        self.assertEqual(run.returncode, 0, run.stderr)
        out = json.loads(run.stdout)
        self.assertEqual(out.get("warning_count"), 0)
        self.assertEqual(out.get("report_count"), 5)
        checks = ("completed", "attachment_before", "save_before", "opened", "bytes", "empty", "nested", "root",
                  "missing", "expected_required", "expected_keyword_only", "save_reply", "persisted", "conflict",
                  "report_metadata_only", "closed", "attachment_after", "save_after")
        for name in checks:
            with self.subTest(check=name):
                self.assertIs(out.get(name), True)
        self.assertTrue(all(type(value) in (bool, int) for value in out.values()))
        for value in (*self.values.values(), self.password, self.totp_secret, new_value, payload["attachment"]):
            self.assertNotIn(value, run.stdout + run.stderr)
        reopened = Vault.open(self.profile.vault, self.password)
        self.assertEqual(reopened.value(self.ids["Такси"]), new_value)
        self.assertEqual(reopened.attachment_by_uid(self.ids["Такси"], "release.jks"), self.attachment_data)
        self.assertEqual(len(self.audit_events("attachment_issued")), 4)
        self.assertEqual(len(self.audit_events("token_saved")), 1)
        self._assert_no_plaintext_on_disk(self.attachment_data, new_value, payload["attachment"])

    def test_script_outside_projects_gets_nothing(self):
        self.broker.start()
        folder = self.dir / "elsewhere"
        folder.mkdir()
        script = folder / "run.py"
        script.write_text(CHILD, encoding="utf-8")
        env = {**os.environ, "PYTHONPATH": str(HOME), "PYTHONUTF8": "1"}
        run = subprocess.run([sys.executable, str(script), self.profile.pipe], capture_output=True, text=True,
                             encoding="utf-8", env=env, cwd=folder, timeout=60)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("ProjectUnknown", run.stderr)
        self.assertEqual(self.ui.requests, [])

    def _assert_no_plaintext_on_disk(self, *extra):
        secrets_list = [*self.values.values(), self.password, self.totp_secret, *extra]
        for path in self.dir.rglob("*"):
            if path.is_file():
                data = path.read_bytes()
                for value in secrets_list:
                    raw = value if isinstance(value, bytes) else value.encode()
                    if raw:
                        self.assertNotIn(raw, data, f"значение в открытом виде: {path.name}")


class BrokerLifecycleTest(unittest.TestCase):
    def test_main_releases_tk_references_on_exit_and_mainloop_error(self):
        from pw_storage.broker import main
        from types import SimpleNamespace

        for error in (None, RuntimeError("synthetic mainloop failure")):
            with self.subTest(error=type(error).__name__):
                root = mock.Mock()
                root.mainloop.side_effect = error
                ui = SimpleNamespace(window=object())
                broker = mock.Mock(ui=ui)
                order = []
                broker.stop.side_effect = lambda: order.append("stop")
                root.destroy.side_effect = lambda: order.append("destroy")

                def collect():
                    self.assertIsNone(ui.window)
                    order.append("collect")

                with mock.patch.object(sys, "argv", ["broker", "--profile", "main"]), \
                     mock.patch("pw_storage.window.make_root", return_value=root), \
                     mock.patch("pw_storage.window.TkUi", return_value=ui), \
                     mock.patch("pw_storage.broker.Broker", return_value=broker), \
                     mock.patch("pw_storage.broker.TpmKey"), \
                     mock.patch("pw_storage.broker.telegram_enabled", return_value=False), \
                     mock.patch("pw_storage.broker.gc.collect", side_effect=collect), \
                     mock.patch("builtins.print"):
                    if error is None:
                        self.assertEqual(main(), 0)
                    else:
                        with self.assertRaisesRegex(RuntimeError, "synthetic mainloop failure"):
                            main()
                self.assertEqual(order, ["stop", "destroy", "collect"])
                broker.stop.assert_called_once_with()
                root.destroy.assert_called_once_with()

    def test_existing_broker_destroys_unused_root(self):
        from pw_storage.broker import main
        root, broker = mock.Mock(), mock.Mock()
        broker.start.side_effect = OSError("synthetic pipe already owned")
        with mock.patch.object(sys, "argv", ["broker", "--profile", "main"]), \
             mock.patch("pw_storage.window.make_root", return_value=root), \
             mock.patch("pw_storage.broker.Broker", return_value=broker), \
             mock.patch("pw_storage.broker.TpmKey"), \
             mock.patch("pw_storage.broker.telegram_enabled", return_value=False), \
             mock.patch("builtins.print"):
            self.assertEqual(main(), 0)
        root.destroy.assert_called_once_with()
        root.mainloop.assert_not_called()
        broker.stop.assert_not_called()


if __name__ == "__main__":
    unittest.main()
