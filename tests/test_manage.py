"""Окно администрирования: данные без Tk и настоящее окно с программными щелчками, на быстром тестовом файле."""

import gc
import json
import shutil
import tempfile
import threading
import time
import tkinter as tk
import unittest
from dataclasses import replace
from datetime import date
from itertools import product
from pathlib import Path
from unittest.mock import Mock, patch

from pw_storage import manage
from pw_storage.manage import ManageWindow, Model, Usage, load_view, read_usage, save_view
from pw_storage.projects import BEGIN, END
from pw_storage.vault import Kdf, Row, Vault, VaultChanged
from pw_storage.window import apply_style

FAST = Kdf(memory_mb=16, iterations=1, parallelism=1)
TODAY = date(2026, 11, 4)
PASSWORD = "тестовый-пароль-123"


def row(uid, group, comment, projects, shared=False, service="S", key="K"):
    return Row(uid, group, service, key, comment, tuple(projects), shared, "d")


ROWS = [
    row("a1", "DELTA", "Логин Такси", ["DELTA"]),
    row("a2", "DELTA", "Пароль Такси", ["DELTA"]),
    row("a3", "DELTA", "", ["DELTA"]),
    row("c1", "COMMON", "Номер чата", ["COMMON", "DELTA"], True),
    row("c2", "COMMON", "Коды GitHub", []),
    row("m1", "POST", "Пароль почты", ["POST", "DELTA"]),
]
USAGE = {"a1": Usage(14, date(2026, 11, 3)), "a2": Usage(2, date(2026, 9, 1)), "c1": Usage(120, TODAY),
         "m1": Usage(3, date(2026, 10, 20))}


class UsageTest(unittest.TestCase):
    def test_counts_issued_rows_only(self):
        path = Path(tempfile.mkdtemp(prefix="pwtest")) / "access.log"
        lines = [
            {"time": "2026-11-01T10:00:00", "event": "value_issued", "row": "a1"},
            {"time": "2026-11-03T09:00:00", "event": "value_issued", "row": "a1"},
            {"time": "2026-11-02T09:00:00", "event": "value_issued", "row": "a1"},
            {"time": "2026-11-03T09:00:00", "event": "value_issued", "service": "старый вид, без номера"},
            {"time": "2026-11-03T09:00:00", "event": "access_granted", "rows": ["a2"]},
        ]
        path.write_text("\n".join(json.dumps(x) for x in lines) + "\nбитая строка\n", encoding="utf-8")
        usage = read_usage(path)
        self.assertEqual(usage, {"a1": Usage(3, date(2026, 11, 3))})
        shutil.rmtree(path.parent)

    def test_missing_log_is_empty(self):
        self.assertEqual(read_usage(Path(tempfile.gettempdir()) / "нет-такого-журнала.log"), {})

    def test_attachment_and_token_activity_prevent_unused_classification(self):
        with tempfile.TemporaryDirectory(prefix="pwtest") as folder:
            path = Path(folder) / "access.log"
            records = [dict(time="2026-11-04T09:00:00", event=event, row="a1", project="DELTA",
                            script="C:/projects/DELTA/tools/sign.py")
                       for event in ("attachment_issued", "token_saved", "token_save_failed", "attachment_refused")]
            path.write_text("\n".join(json.dumps(record) for record in records), encoding="utf-8")
            journal = manage.read_journal(path)
        self.assertEqual(journal.by_row, {"a1": Usage(2, TODAY)})
        self.assertEqual(journal.by_pair, {("a1", "DELTA"): Usage(2, TODAY)})
        self.assertEqual(journal.scripts, {("a1", "DELTA"): {"sign.py"}})


class ModelTest(unittest.TestCase):
    def setUp(self):
        self.model = Model(ROWS, USAGE, TODAY, stale_days=45)

    def test_columns_by_record_count_all_last(self):
        self.assertEqual(self.model.columns, ["DELTA", "COMMON", "POST", "ALL"])

    def test_project_without_records_gets_column_and_can_be_granted(self):
        model = Model(ROWS, USAGE, TODAY, stale_days=45, extra_projects=("ALPHA",))
        self.assertEqual(model.columns, ["DELTA", "COMMON", "POST", "ALPHA", "ALL"])
        model.toggle("a1", "ALPHA")
        self.assertEqual(model.changed_uids(), ["a1"])
        self.assertEqual(model.describe("a1"), "добавлен ALPHA")
        model.reload(ROWS)
        self.assertEqual(model.columns, ["DELTA", "COMMON", "POST", "ALPHA", "ALL"])
        self.assertEqual(model.changed_uids(), ["a1"], "перечитывание не снимает колонку и отметку")

    def test_states(self):
        states = {r.uid: self.model.state(r) for r in ROWS}
        self.assertEqual(states["a3"], manage.NO_COMMENT)
        self.assertEqual(states["c2"], manage.NO_PROJECTS)
        self.assertEqual(states["a2"], manage.STALE)  # 64 дня
        self.assertEqual(states["m1"], manage.ACTIVE)  # 15 дней

    def test_group_marks_and_toggle(self):
        delta = ["a1", "a2", "a3"]
        common = ["c1", "c2"]
        self.assertEqual(self.model.group_mark(delta, "DELTA"), "on")
        self.assertEqual(self.model.group_mark(common, "DELTA"), "part")
        self.assertEqual(self.model.group_mark(delta, "POST"), "off")
        self.model.toggle_group(common, "DELTA")  # частично → всем
        self.assertEqual(self.model.group_mark(common, "DELTA"), "on")
        self.model.toggle_group(common, "DELTA")  # у всех → снять у всех
        self.assertEqual(self.model.group_mark(common, "DELTA"), "off")
        self.assertEqual(self.model.describe("c1"), "снят DELTA")

    def test_changes_and_revert(self):
        self.model.toggle("m1", "COMMON")
        self.model.toggle("m1", "ALL")
        self.model.toggle("a1", "POST")
        self.model.toggle("a1", "POST")  # вернули как было
        self.assertEqual(self.model.changed_uids(), ["m1"])
        self.assertEqual(self.model.describe("m1"), "добавлен COMMON, ALL включён")
        self.model.revert()
        self.assertEqual(self.model.changed_uids(), [])

    def test_order(self):
        self.assertEqual(self.model.ordered("count", -1)[:2], ["c1", "a1"])
        self.assertEqual(self.model.ordered("last", -1)[0], "c1")
        by_comment = self.model.ordered("comment", 1)
        self.assertEqual(by_comment[-1], "a3", "строка без комментария в конце")
        self.assertEqual(set(self.model.ordered("POST", -1)[:1]), {"m1"})

    def test_groups(self):
        groups = self.model.groups(self.model.ordered("comment", 1), "project")
        self.assertEqual([key for key, _, _ in groups], ["COMMON", "DELTA", "POST"])
        self.assertEqual(groups[0][1], "Проект COMMON")
        states = self.model.groups(self.model.ordered("comment", 1), "state")
        self.assertEqual([title for _, title, _ in states][0], manage.STATE_TITLES[manage.NO_COMMENT])

    def test_search(self):
        found = [uid for uid in self.model.ordered("comment", 1) if self.model.matches(self.model.by_uid[uid], "такси")]
        self.assertEqual(sorted(found), ["a1", "a2"])

    def test_reload_keeps_pending_marks(self):
        self.model.toggle("m1", "COMMON")
        rows = [r for r in ROWS if r.uid != "a1"]
        self.model.reload(rows)
        self.assertEqual(self.model.changed_uids(), ["m1"])
        self.assertNotIn("a1", self.model.by_uid)

    def test_reload_merges_each_boolean_cell_against_original(self):
        for original, local, external in product((False, True), repeat=3):
            with self.subTest(original=original, local=local, external=external):
                model = Model([row("x", "BASE", "Synthetic", ["TAG"] if original else [], original)], {}, TODAY)
                model.set("x", "TAG", local)
                model.set("x", "ALL", local)
                projects = ["EXTERNAL", *(["TAG"] if external else [])]
                model.reload([row("x", "BASE", "Synthetic", projects, external)])
                expected = local if local != original else external
                self.assertEqual(model.has("x", "TAG"), expected)
                self.assertEqual(model.has("x", "ALL"), expected)
                self.assertTrue(model.has("x", "EXTERNAL"))
                self.assertEqual(model.orig["x"], (frozenset(projects), external))
                self.assertEqual(model.changed_uids(), ["x"] if expected != external else [])
                model.revert()
                self.assertEqual(model.cur["x"], [set(projects), external])

    def test_reload_preserves_unrelated_external_removal_and_addition(self):
        self.model.toggle("m1", "COMMON")
        rows = [replace(r, projects=("POST", "EXTERNAL"), shared=True) if r.uid == "m1" else r for r in ROWS]
        self.model.reload(rows)
        self.assertEqual(self.model.cur["m1"], [{"POST", "EXTERNAL", "COMMON"}, True])
        self.assertEqual(self.model.describe("m1"), "добавлен COMMON")
        self.assertEqual(self.model.changed_uids(), ["m1"])

    def test_reload_preserves_local_removal_and_external_all_change(self):
        self.model.toggle("m1", "DELTA")
        rows = [replace(r, projects=("POST", "DELTA", "EXTERNAL"), shared=True) if r.uid == "m1" else r for r in ROWS]
        self.model.reload(rows)
        self.assertEqual(self.model.cur["m1"], [{"POST", "EXTERNAL"}, True])
        self.assertEqual(self.model.describe("m1"), "снят DELTA")

    def test_reload_drops_deleted_changed_row_and_accepts_unchanged_row(self):
        self.model.toggle("a1", "POST")
        self.model.toggle("m1", "COMMON")
        rows = [replace(r, projects=(), shared=True) if r.uid == "a2" else r for r in ROWS if r.uid != "a1"]
        self.model.reload(rows)
        self.assertNotIn("a1", self.model.by_uid)
        self.assertNotIn("a1", self.model.orig)
        self.assertNotIn("a1", self.model.cur)
        self.assertEqual(self.model.cur["a2"], [set(), True])
        self.assertFalse(self.model.changed("a2"))
        self.assertEqual(self.model.changed_uids(), ["m1"])

    def test_reload_rebases_pending_cells_each_time(self):
        self.model.toggle("m1", "COMMON")
        for projects in (("POST",), ("EXTERNAL",)):
            rows = [replace(r, projects=projects) if r.uid == "m1" else r for r in ROWS]
            self.model.reload(rows)
            self.assertEqual(self.model.cur["m1"][0], {*projects, "COMMON"})
        self.model.revert()
        self.assertEqual(self.model.cur["m1"], [{"EXTERNAL"}, False])

    def test_reload_absorbs_local_edit_already_present_externally(self):
        self.model.toggle("m1", "COMMON")
        self.model.toggle("m1", "ALL")
        rows = [replace(r, projects=("POST", "COMMON"), shared=True) if r.uid == "m1" else r for r in ROWS]
        self.model.reload(rows)
        self.assertEqual(self.model.changed_uids(), [])
        rows = [replace(r, projects=(), shared=False) if r.uid == "m1" else r for r in rows]
        self.model.reload(rows)
        self.assertEqual(self.model.cur["m1"], [set(), False])
        self.assertEqual(self.model.changed_uids(), [])


class ViewSettingsTest(unittest.TestCase):
    def test_keeps_other_settings(self):
        path = Path(tempfile.mkdtemp(prefix="pwtest")) / "settings.json"
        path.write_text(json.dumps({"telegram": True, "grant_hours": 5}), encoding="utf-8")
        self.assertEqual(load_view(path)["group"], "project", "по умолчанию — по проекту")
        save_view(path, {"group": "state", "sort": "count", "dir": -1, "collapsed": ["project:DELTA"]})
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertTrue(data["telegram"])
        self.assertEqual(data["grant_hours"], 5)
        self.assertEqual(load_view(path), {"group": "state", "sort": "count", "dir": -1, "collapsed": ["project:DELTA"]})
        path.write_text(json.dumps({"admin_view": {"group": "чужое", "dir": 7}}), encoding="utf-8")
        self.assertEqual(load_view(path)["group"], "project")
        self.assertEqual(load_view(path)["dir"], 1)
        shutil.rmtree(path.parent)


class VaultTagsTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="pwtest"))
        self.path = self.dir / "vault.kdbx"
        vault = Vault.create(self.path, PASSWORD, FAST)
        vault.put("DELTA", "Такси", "login", "TEST-1", "Логин", ("DELTA",))
        vault.put("COMMON", "Погода", "API_KEY", "TEST-2", "Погода", ("COMMON",), True)
        vault.save()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_set_tags_keeps_stamp_and_allows_empty(self):
        vault = Vault.open(self.path, PASSWORD)
        before = {r.uid: r for r in vault.rows()}
        login = next(r for r in before.values() if r.key == "login")
        weather = next(r for r in before.values() if r.key == "API_KEY")
        vault.set_tags(login.uid, ("POST", "DELTA"), True)
        vault.set_tags(weather.uid, (), False)
        vault.save()
        after = {r.uid: r for r in Vault.open(self.path, PASSWORD).rows()}
        self.assertEqual(after[login.uid].projects, ("DELTA", "POST"))
        self.assertTrue(after[login.uid].shared)
        self.assertEqual(after[weather.uid].projects, ())
        self.assertFalse(after[weather.uid].shared)
        self.assertEqual(after[login.uid].stamp, login.stamp, "Т23: отметки не меняют отпечаток строки")


class FakeAudit:
    def __init__(self):
        self.events = []

    def write(self, event, **fields):
        self.events.append((event, fields))


class WindowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tk.Tk()
        cls.root.withdraw()
        apply_style(cls.root)

    @classmethod
    def tearDownClass(cls):
        cls.root.destroy()

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="pwtest"))
        self.path = self.dir / "vault.kdbx"
        vault = Vault.create(self.path, PASSWORD, FAST)
        vault.put("DELTA", "Такси", "login", "TEST-1", "Логин Такси", ("DELTA",))
        vault.put("DELTA", "Такси", "password", "TEST-2", "Пароль Такси", ("DELTA",))
        vault.put("COMMON", "Погода", "API_KEY", "TEST-3", "Ключ погоды", ("COMMON", "DELTA"), True)
        vault.save()
        self.log = self.dir / "access.log"
        self.log.write_text("", encoding="utf-8")
        self.settings = self.dir / "settings.json"
        self.audit = FakeAudit()
        self.after_save_calls = 0
        self.closed = []

    def tearDown(self):
        if self.window._busy:
            self.wait(lambda: not self.window._busy)
        if self.window.win.winfo_exists():
            self.window.close(force=True)
        self.window = None
        gc.collect()
        shutil.rmtree(self.dir, ignore_errors=True)

    def after_save(self, vault):
        self.after_save_calls += 1

    def make(self, projects_root=None):
        self.window = ManageWindow(self.root, lambda p: Vault.open(self.path, p), self.after_save, self.audit, self.log,
                                   self.settings, today=TODAY, take_focus=False, on_close=self.closed.append,
                                   projects_root=projects_root)
        return self.window

    def test_documentation_screenshot(self):
        """Снимок матрицы «записи × проекты» для документации."""
        from tests.shot import snapshot

        window = self.unlock()
        window.win.update()
        snapshot(window.win, "admin-matrix.png")

    def wait(self, condition, seconds=15):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            self.root.update()
            if condition():
                return
            time.sleep(0.02)
        self.fail("не дождались")

    def unlock(self, password=PASSWORD, projects_root=None):
        window = self.make(projects_root)
        window.password_var.set(password)
        window.submit_password()
        self.wait(lambda: not window._busy and (window.model is not None or window.message.cget("text").startswith("Неверный")))
        return window

    def uid(self, key):
        return next(r.uid for r in self.window.model.rows if r.key == key)

    def test_wrong_password(self):
        window = self.unlock("не тот пароль")
        self.assertIsNone(window.model)
        self.assertIn(("admin_password_failed", {}), self.audit.events)
        self.assertEqual(window.password_var.get(), "", "пароль не остаётся в поле")

    def test_default_view_and_groups(self):
        window = self.unlock()
        self.assertEqual(window.view["group"], "project")
        self.assertEqual(window.model.columns, ["DELTA", "COMMON", "ALL"])
        kinds = [kind for _, _, kind, _ in window.hits]
        self.assertEqual(kinds, ["group", "row", "group", "row", "row"])  # COMMON, затем DELTA
        window.toggle_collapse("project:DELTA")
        self.assertEqual([kind for _, _, kind, _ in window.hits], ["group", "row", "group"])
        window.set_mode("none")
        self.assertEqual([kind for _, _, kind, _ in window.hits], ["row", "row", "row"])

    def test_connected_project_without_records_is_a_column(self):
        projects_root = self.dir / "projects"
        (projects_root / "ALPHA").mkdir(parents=True)
        (projects_root / "ALPHA" / "AGENTS.md").write_text(f"{BEGIN}\n{END}\n", encoding="utf-8")
        (projects_root / "STUDIO").mkdir()
        window = self.unlock(projects_root=projects_root)
        self.assertEqual(window.model.columns, ["DELTA", "COMMON", "ALPHA", "ALL"],
                         "подключённая папка без записей — колонка, неподключённая — нет")
        login = self.uid("login")
        window.toggle(login, "ALPHA")
        window.save()
        self.wait(lambda: not window._busy)
        persisted = {r.uid: r for r in Vault.open(self.path, PASSWORD).rows()}
        self.assertIn("ALPHA", persisted[login].projects)
        self.assertEqual(window.model.columns, ["DELTA", "ALPHA", "COMMON", "ALL"],
                         "после сохранения колонка на месте, порядок — по числу отмеченных записей")

    def test_close_waits_for_active_save(self):
        window = self.unlock()
        started = threading.Event()
        release = threading.Event()
        workers = []
        work = window._save_work

        def blocked():
            workers.append(threading.current_thread())
            started.set()
            if not release.wait(5):
                raise RuntimeError("synthetic barrier timeout")
            return work()

        window._save_work = blocked
        window.toggle(self.uid("login"), "COMMON")
        window.save()
        try:
            self.assertTrue(started.wait(5))
            self.assertFalse(workers[0].daemon)
            window.close(force=True)
            self.assertEqual(self.closed, [])
            self.assertTrue(window.win.winfo_exists())
            self.assertIn("Дождитесь", window.note.cget("text"))
        finally:
            release.set()
            workers[0].join(5)
        self.wait(lambda: not window._busy)
        window.close(force=True)
        self.assertEqual(self.closed, [True])

    def test_toggle_and_save(self):
        window = self.unlock()
        login = self.uid("login")
        window.toggle(login, "COMMON")
        self.assertIn("добавлен COMMON", window.note.cget("text"))
        self.assertEqual(str(window.save_button.cget("state")), "normal")
        window.save()
        self.wait(lambda: not window._busy)
        self.assertEqual(self.after_save_calls, 1)
        self.assertEqual(window.model.changed_uids(), [])
        event, fields = self.audit.events[-1]
        self.assertEqual(event, "tags_changed")
        self.assertIn("добавлен COMMON", fields["rows"][0])
        self.assertNotIn("TEST-", json.dumps(self.audit.events, ensure_ascii=False))
        rows = {r.uid: r for r in Vault.open(self.path, PASSWORD).rows()}
        self.assertEqual(rows[login].projects, ("COMMON", "DELTA"))
        window.close()
        self.assertEqual(self.closed, [True])
        self.assertEqual(json.loads(self.settings.read_text(encoding="utf-8"))["admin_view"]["group"], "project")

    def test_after_save_error_is_committed_success(self):
        window = self.unlock()
        login = self.uid("login")
        original = window.vault
        original_rows = original.rows()
        original_hash = original.source_hash
        ui_thread = threading.get_ident()
        callbacks = []

        def after_save(working):
            callbacks.append((working, window.vault, threading.get_ident()))
            raise RuntimeError("synthetic callback detail must not be displayed")

        window.after_save = after_save
        window.toggle(login, "COMMON")
        window.save()
        self.wait(lambda: not window._busy)
        self.assertEqual(len(callbacks), 1)
        working, published_in_worker, worker_thread = callbacks[0]
        self.assertIs(published_in_worker, original, "worker must not swap the UI vault")
        self.assertNotEqual(worker_thread, ui_thread)
        self.assertIs(window.vault, working, "UI publishes the committed clone despite callback failure")
        self.assertIsNot(window.vault, original)
        self.assertEqual(original.rows(), original_rows)
        self.assertEqual(original.source_hash, original_hash)
        self.assertEqual(window.model.changed_uids(), [])
        self.assertEqual(window.saved, 1)
        self.assertIn("Записано изменений: 1", window.note.cget("text"))
        self.assertIn("RuntimeError", window.note.cget("text"))
        self.assertNotIn("synthetic callback detail", window.note.cget("text"))
        self.assertEqual([event for event, _ in self.audit.events], ["admin_opened", "tags_changed", "catalog_failed"])
        self.assertEqual(self.audit.events[-1][1], {"reason": "RuntimeError"})
        persisted = {r.uid: r for r in Vault.open(self.path, PASSWORD).rows()}
        self.assertIn("COMMON", persisted[login].projects)
        self.assertEqual(window.vault.rows(), list(persisted.values()))
        window.revert()
        self.assertTrue(window.model.has(login, "COMMON"), "cancel cannot undo already committed tags")
        window.close()
        self.assertEqual(self.closed, [True])

    def failed_save_and_cancel(self):
        window = self.unlock()
        login = self.uid("login")
        original = window.vault
        before = {r.uid: r for r in original.rows()}
        original_hash = original.source_hash
        disk_before = self.path.read_bytes()
        attempts = []

        def fail_save(working):
            attempts.append(working)
            raise OSError("synthetic save failure")

        window.toggle(login, "COMMON")
        window.toggle(login, "ALL")
        with patch.object(Vault, "save", autospec=True, side_effect=fail_save):
            window.save()
            self.wait(lambda: not window._busy)
        self.assertEqual(len(attempts), 1)
        self.assertIsNot(attempts[0], original)
        attempted = {r.uid: r for r in attempts[0].rows()}[login]
        self.assertIn("COMMON", attempted.projects, "failure is injected after applying the edits")
        self.assertTrue(attempted.shared)
        self.assertIs(window.vault, original)
        self.assertEqual({r.uid: r for r in original.rows()}, before)
        self.assertEqual(original.source_hash, original_hash)
        self.assertEqual(self.path.read_bytes(), disk_before)
        self.assertEqual(window.model.changed_uids(), [login])
        self.assertEqual(window.saved, 0)
        self.assertEqual(self.after_save_calls, 0)
        self.assertEqual([event for event, _ in self.audit.events], ["admin_opened"])
        self.assertIn("OSError", window.note.cget("text"))
        window.revert()
        self.assertEqual(window.model.changed_uids(), [])
        self.assertFalse(window.model.has(login, "COMMON"))
        self.assertFalse(window.model.has(login, "ALL"))
        return window, login, before

    def test_failed_save_cancel_then_unrelated_tag_save(self):
        window, login, before = self.failed_save_and_cancel()
        password = self.uid("password")
        window.toggle(password, "ALL")
        window.save()
        self.wait(lambda: not window._busy)
        persisted = {r.uid: r for r in Vault.open(self.path, PASSWORD).rows()}
        self.assertEqual(persisted[login], before[login], "reverted permissions must not leak into another save")
        self.assertTrue(persisted[password].shared)
        self.assertEqual(window.model.changed_uids(), [])
        self.assertEqual(self.after_save_calls, 1)
        self.assertEqual(window.saved, 1)
        self.assertEqual(len(self.audit.events[-1][1]["rows"]), 1)
        self.assertTrue(self.audit.events[-1][1]["rows"][0].startswith(password + " "))

    def test_failed_save_cancel_then_unrelated_record_save(self):
        window, login, before = self.failed_save_and_cancel()
        password = self.uid("password")
        self.assertFalse(window._pending_block())
        # Операция окна записи использует общее хранилище, а не модель отметок.
        window.vault.update_entry(password, comment="Synthetic updated comment")
        window.vault.save()
        window._child_done(True)
        persisted = {r.uid: r for r in Vault.open(self.path, PASSWORD).rows()}
        self.assertEqual(persisted[login], before[login], "shared-vault operations must not persist cancelled tags")
        self.assertEqual(persisted[password].comment, "Synthetic updated comment")
        self.assertEqual(window.model.changed_uids(), [])
        self.assertEqual(window.saved, 1)

    def test_group_toggle(self):
        window = self.unlock()
        delta = [self.uid("login"), self.uid("password")]
        window.toggle_group(delta, "ALL")
        self.assertEqual(window.model.group_mark(delta, "ALL"), "on")
        self.assertEqual(len(window.model.changed_uids()), 2)
        window.revert()
        self.assertEqual(window.model.changed_uids(), [])

    def test_changed_outside_then_reload(self):
        window = self.unlock()
        login = self.uid("login")
        window.toggle(login, "COMMON")
        other = Vault.open(self.path, PASSWORD)  # как KeePassXC или посредник
        other.set_tags(self.uid("password"), ("DELTA", "COMMON"), False)
        other.save()
        window.save()
        self.wait(lambda: not window._busy)
        self.assertIn("изменён вне окна", window.note.cget("text"))
        self.assertTrue(window.reload_button.winfo_ismapped())
        window.reload()
        self.wait(lambda: not window._busy)
        self.assertEqual(window.model.changed_uids(), [login], "отметка владельца пережила перечитывание")
        self.assertTrue(window.model.has(self.uid("password"), "COMMON"), "чужая правка видна")
        window.save()
        self.wait(lambda: not window._busy)
        rows = {r.uid: r for r in Vault.open(self.path, PASSWORD).rows()}
        self.assertIn("COMMON", rows[login].projects)
        self.assertIn("COMMON", rows[self.uid("password")].projects)

    def test_reload_preserves_same_row_external_permission_revocation(self):
        window = self.unlock()
        weather = self.uid("API_KEY")
        password = self.uid("password")
        original = window.vault
        before = {r.uid: r for r in original.rows()}
        window.toggle(weather, "COMMON")  # локально снимаем одну клетку
        other = Vault.open(self.path, PASSWORD)
        other.set_tags(weather, ("COMMON", "EXTERNAL"), False)  # снаружи сняты DELTA и ALL, добавлен EXTERNAL
        other.set_tags(password, ("COMMON", "DELTA"), False)  # строку в окне не меняли
        other.save()
        window.save()
        self.wait(lambda: not window._busy)
        self.assertIn("изменён вне окна", window.note.cget("text"))
        self.assertIs(window.vault, original)
        self.assertEqual({r.uid: r for r in original.rows()}, before)
        window.reload()
        self.wait(lambda: not window._busy)
        self.assertEqual(window.model.cur[weather], [{"EXTERNAL"}, False])
        self.assertEqual(window.model.describe(weather), "снят COMMON")
        self.assertEqual(window.model.cur[password], [{"COMMON", "DELTA"}, False])
        self.assertEqual(window.model.changed_uids(), [weather])
        window.save()
        self.wait(lambda: not window._busy)
        persisted = {r.uid: r for r in Vault.open(self.path, PASSWORD).rows()}
        self.assertEqual(persisted[weather].projects, ("EXTERNAL",))
        self.assertFalse(persisted[weather].shared)
        self.assertEqual(persisted[password].projects, ("COMMON", "DELTA"))
        self.assertEqual(window.model.changed_uids(), [])
        self.assertEqual(self.after_save_calls, 1)
        self.assertEqual(window.saved, 1)

    def test_sort_by_header(self):
        window = self.unlock()
        window.set_mode("none")
        window.set_sort("comment")  # уже по строке: второй щелчок — обратный порядок
        self.assertEqual(window.view["dir"], -1)
        window.set_sort("COMMON")
        self.assertEqual(window.order[0], self.uid("API_KEY"))

    def test_blocks_other_windows_with_pending_changes(self):
        opened = []
        window = self.unlock()
        window.add_secret = lambda root, on_close: opened.append(on_close)
        window.toggle(self.uid("login"), "COMMON")
        window.new_secret()
        self.assertEqual(opened, [])
        self.assertIn("Сначала сохраните", window.note.cget("text"))
        window.revert()
        window.new_secret()
        self.assertEqual(len(opened), 1)


class CallbackCleanupTest(unittest.TestCase):
    """Only synthetic rows and pending Tk callbacks; no vault writes or background work."""

    def setUp(self):
        gc.collect()
        self.root = tk.Tk()
        self.root.withdraw()
        apply_style(self.root)
        self.dir = Path(tempfile.mkdtemp(prefix="pwtest"))
        self.window = None
        self.closed = Mock()
        self.after_before = set(self.root.tk.call("after", "info"))

    def tearDown(self):
        if self.root is not None:
            if self.window is not None and self.window.win.winfo_exists():
                self.window.win.destroy()
            self.root.destroy()
        self.window = None
        self.root = None
        gc.collect()
        shutil.rmtree(self.dir, ignore_errors=True)

    def make(self, matrix=False):
        w = self.window = ManageWindow(self.root, Mock(), Mock(), Mock(), self.dir / "access.log",
                                       self.dir / "settings.json", today=TODAY, take_focus=False,
                                       on_close=self.closed)
        if matrix:
            w.vault = Mock()
            w.model = Model(ROWS, USAGE, TODAY)
            w._matrix_screen()
        return w

    def check_cleanup(self, matrix=False, destroy=False):
        w = self.make(matrix)
        pending = w._poll_id
        script, kind = self.root.tk.call("after", "info", pending)
        self.assertEqual(kind, "timer")
        self.assertEqual(set(self.root.tk.call("after", "info")) - self.after_before, {pending})
        child = tk.Frame(w.win)
        child.destroy()
        self.assertEqual(w._poll_id, pending)
        with patch.object(manage, "save_view"):
            (w.win.destroy if destroy else w.close)()
        self.assertIsNone(w._poll_id)
        self.assertEqual(set(self.root.tk.call("after", "info")), self.after_before)
        self.assertFalse(self.root.tk.call("info", "commands", script))
        self.root.update()
        if destroy:
            self.closed.assert_not_called()
        else:
            self.closed.assert_called_once_with(False)

    def test_password_close_cancels_pending_poll(self):
        self.check_cleanup()

    def test_password_manual_destroy_cancels_pending_poll(self):
        self.check_cleanup(destroy=True)

    def test_matrix_close_has_no_orphan_title_or_poll_timer(self):
        self.check_cleanup(matrix=True)

    def test_matrix_manual_destroy_has_no_orphan_title_or_poll_timer(self):
        self.check_cleanup(matrix=True, destroy=True)

    def test_root_teardown_cancels_pending_poll(self):
        w = self.make()
        self.assertIsNotNone(w._poll_id)
        interpreter = self.root.tk
        self.root.destroy()
        self.root = None
        self.assertIsNone(w._poll_id)
        self.assertEqual(set(interpreter.call("after", "info")), self.after_before)

    def test_poll_clears_id_before_finishing_and_tracks_replacement(self):
        w = self.make()
        first = w._poll_id
        w._result = ("synthetic", None, None)
        with patch.object(w, "_finish", side_effect=lambda *args: self.assertIsNone(w._poll_id)) as finish:
            end = time.monotonic() + 3
            while w._poll_id == first and time.monotonic() < end:
                self.root.update()
                time.sleep(0.01)
            finish.assert_called_once_with("synthetic", None, None)
        self.assertIsNotNone(w._poll_id)
        self.assertNotEqual(w._poll_id, first)
        self.assertNotIn(first, self.root.tk.call("after", "info"))

    def test_dark_title_map_ignores_child_widgets(self):
        w = self.make()
        self.root.update()
        with patch.object(manage, "dark_title_bar") as dark:
            w.body.event_generate("<Map>")
            dark.assert_not_called()
            w.win.event_generate("<Map>")
            dark.assert_called_once_with(w.win)


if __name__ == "__main__":
    unittest.main()
