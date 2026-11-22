"""Чистки (Т31): журнал по проектам, предложения, применение, корзина, окна записи и чистки."""

import gc
import json
import shutil
import tempfile
import threading
import time
import tkinter as tk
import unittest
from datetime import date, datetime
from pathlib import Path
from unittest import mock

from pw_storage import cleanup, export
from pw_storage.cleanup import JKS, OPEN_FILE, PROJECT, TRASH, UNLINK, CleanupWindow, RecordWindow, Scan
from pw_storage.manage import Journal, Usage, read_journal
from pw_storage.vault import Kdf, Row, Vault, VaultError
from pw_storage.window import apply_style

FAST = Kdf(memory_mb=16, iterations=1, parallelism=1)
PASSWORD = "тестовый-пароль-123"
TODAY = date(2026, 11, 4)
OLD = date(2026, 8, 1)  # журнал ведётся дольше порога


def row(uid, group, comment, projects, shared=False, key="K"):
    return Row(uid, group, "S", key, comment, tuple(projects), shared, "d")


def journal(pairs, since=OLD):
    by_row, by_pair = {}, {}
    for (uid, project), use in pairs.items():
        by_pair[(uid, project)] = use
        old = by_row.get(uid, Usage())
        by_row[uid] = Usage(old.count + use.count, max(filter(None, (old.last, use.last)), default=None))
    return Journal(by_row, by_pair, {}, since)


class JournalTest(unittest.TestCase):
    def test_pairs_scripts_since(self):
        path = Path(tempfile.mkdtemp(prefix="pwtest")) / "access.log"
        lines = [
            {"time": "2026-10-01T09:00:00", "event": "catalog_viewed", "project": "DELTA"},
            {"time": "2026-11-01T10:00:00", "event": "value_issued", "row": "a1", "project": "DELTA",
             "script": "C:\\projects\\DELTA\\tools\\probe.py"},
            {"time": "2026-11-03T10:00:00", "event": "value_issued", "row": "a1", "project": "COMMON"},
        ]
        path.write_text("\n".join(json.dumps(x) for x in lines), encoding="utf-8")
        j = read_journal(path)
        self.assertEqual(j.since, date(2026, 10, 1))
        self.assertEqual(j.by_row["a1"], Usage(2, date(2026, 11, 3)))
        self.assertEqual(j.by_pair[("a1", "DELTA")], Usage(1, date(2026, 11, 1)))
        self.assertEqual(j.scripts[("a1", "DELTA")], {"probe.py"})
        shutil.rmtree(path.parent)


class SuggestionsTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="pwtest"))
        for name in ("DELTA", "COMMON", "POST"):
            (self.root / name).mkdir()
        self.rows = [
            row("w1", "COMMON", "Погода", ["COMMON", "DELTA", "POST"], True),
            row("g1", "COMMON", "Коды GitHub", []),
            row("n1", "DELTA", "", ["DELTA"]),
            row("o1", "DELTA", "Старый ключ", ["DELTA"]),
            row("t1", "TV", "Кино", ["TV"]),
            row("f1", "DELTA", "Свежий ключ", ["DELTA"]),
        ]
        self.j = journal({("w1", "COMMON"): Usage(5, date(2026, 11, 1)), ("w1", "DELTA"): Usage(2, date(2026, 9, 4)),
                          ("o1", "DELTA"): Usage(1, date(2026, 6, 1)), ("f1", "DELTA"): Usage(3, date(2026, 11, 3)),
                          ("t1", "TV"): Usage(1, date(2026, 11, 2))})

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def kinds(self, found):
        return {(s.kind, s.uid, s.project) for s in found}

    def test_rules(self):
        found = cleanup.suggestions(self.rows, self.j, TODAY, self.root, set())
        kinds = self.kinds(found)
        self.assertIn((UNLINK, "w1", "DELTA"), kinds)  # 61 день
        self.assertIn((UNLINK, "w1", "POST"), kinds)  # ни разу
        self.assertNotIn((UNLINK, "w1", "COMMON"), kinds, "домашний проект не снимаем")
        self.assertIn((TRASH, "n1", None), kinds, "без комментария")
        self.assertIn((TRASH, "o1", None), kinds, "давно не брали")
        self.assertNotIn((TRASH, "g1", None), kinds, "запись только для выгрузки не трогаем")
        self.assertNotIn((TRASH, "f1", None), kinds)
        self.assertIn((PROJECT, None, "TV"), kinds, "папки нет")
        defaults = {(s.kind, s.uid, s.project): s.default for s in found}
        self.assertTrue(defaults[(UNLINK, "w1", "DELTA")])
        self.assertFalse(defaults[(TRASH, "o1", None)], "удаления — только вручную")
        self.assertFalse(defaults[(PROJECT, None, "TV")])

    def test_young_journal_does_not_call_never(self):
        young = journal({("w1", "COMMON"): Usage(5, date(2026, 11, 1))}, since=date(2026, 11, 1))
        kinds = self.kinds(cleanup.suggestions(self.rows, young, TODAY, self.root, set()))
        self.assertNotIn((UNLINK, "w1", "POST"), kinds, "журнал моложе порога: «ни разу» ещё ничего не значит")

    def test_scan(self):
        (self.root / "DELTA" / "android").mkdir()
        (self.root / "DELTA" / "android" / "delta-release.jks").write_bytes(b"x")
        (self.root / "POST" / "app.jks").write_bytes(b"x")
        (self.root / "POST" / "secrets.env").write_text("X=1", encoding="utf-8")
        (self.root / "POST" / "node_modules").mkdir()
        (self.root / "POST" / "node_modules" / "skip.jks").write_bytes(b"x")
        scan = cleanup.scan_projects(self.root)
        self.assertEqual(sorted(p.name for p in scan.jks), ["app.jks", "delta-release.jks"])
        found = cleanup.suggestions(self.rows, self.j, TODAY, self.root, {"delta-release.jks"}, scan)
        self.assertEqual([s.title for s in found if s.kind == JKS], ["Копия " + str(Path("POST") / "app.jks")])
        self.assertEqual(len([s for s in found if s.kind == OPEN_FILE]), 1)
        self.assertFalse(any(s.actionable for s in found if s.kind in (JKS, OPEN_FILE)))


class VaultCase(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="pwtest"))
        self.path = self.dir / "vault.kdbx"
        v = Vault.create(self.path, PASSWORD, FAST)
        v.put("COMMON", "Погода", "API_KEY", "TEST-1", "Погода", ("COMMON", "DELTA"), True)
        v.put("DELTA", "Такси", "login", "TEST-2", "Логин", ("DELTA",))
        v.put("TV", "Кино", "token", "TEST-3", "Кино", ("TV",))
        v.put("COMMON", "Почта", "pass", "TEST-4", "Почта для TV", ("COMMON", "TV"))
        v.save()
        self.vault = Vault.open(self.path, PASSWORD)
        self.uid = {r.key: r.uid for r in self.vault.rows()}

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def reopen(self):
        return Vault.open(self.path, PASSWORD)


class ApplyAndTrashTest(VaultCase):
    def test_apply_unlink_project_trash(self):
        rows = self.vault.rows()
        chosen = [cleanup.Suggestion(UNLINK, "", "", uid=self.uid["API_KEY"], project="DELTA"),
                  cleanup.Suggestion(PROJECT, "", "", project="TV")]
        lines = cleanup.apply(self.vault, rows, chosen)
        self.vault.save()
        after = {r.key: r for r in self.reopen().rows()}
        self.assertEqual(after["API_KEY"].projects, ("COMMON",))
        self.assertNotIn("token", after, "запись только проекта TV — в корзину")
        self.assertEqual(after["pass"].projects, ("COMMON",), "TV снят, запись COMMON осталась")
        self.assertEqual([e.key for e in self.reopen().trashed()], ["token"])
        self.assertTrue(any("проект TV" in line for line in lines))
        self.assertNotIn("TEST-", "".join(lines))

    def test_update_entry_changes_stamp_and_requires_comment(self):
        before = {r.key: r for r in self.vault.rows()}["login"]
        self.vault.update_entry(before.uid, value="TEST-new")
        self.vault.save()
        after = {r.key: r for r in self.reopen().rows()}["login"]
        self.assertNotEqual(after.stamp, before.stamp, "Т23: новое значение — новый отпечаток")
        with self.assertRaises(VaultError):
            self.vault.update_entry(before.uid, comment="  ")

    def test_trash_in_export_until_emptied(self):
        self.vault.trash(self.uid["token"])
        self.vault.save()
        v = self.reopen()
        self.assertNotIn("token", {r.key for r in v.rows()})
        text = export.catalog_text(v.export_entries(), None, datetime(2026, 11, 4), True, v.trashed())
        self.assertIn("КОРЗИНА", text)
        self.assertIn("TEST-3", text)
        self.assertIn("Был в проекте: TV", text)
        self.assertEqual(v.empty_trash(), 1)
        v.save()
        self.assertEqual(self.reopen().trashed(), [])


class WindowsTest(VaultCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tk.Tk()
        cls.root.withdraw()
        apply_style(cls.root)

    @classmethod
    def tearDownClass(cls):
        cls.root.destroy()
        gc.collect()

    def setUp(self):
        gc.collect()
        super().setUp()
        self.window = None
        self.audit = mock.Mock()
        self.done = []
        self.catalogs = 0

    def tearDown(self):
        try:
            if self.window is not None and self.window.win.winfo_exists():
                if self.window._busy:
                    self.wait(lambda: not self.window._busy)
                self.window.close()
        finally:
            self.window = None
            gc.collect()
            super().tearDown()

    def after_save(self, vault):
        self.catalogs += 1

    def test_documentation_screenshots(self):
        """Снимки для документации: окно записи и окно чистки."""
        from tests.shot import snapshot

        row = {r.key: r for r in self.vault.rows()}["API_KEY"]
        record = self.window = RecordWindow(self.root, self.vault, row, journal({}), TODAY, self.after_save,
                                            self.audit, self.done.append, take_focus=False)
        self.wait(lambda: record.win.winfo_exists())
        record.win.update()
        snapshot(record.win, "record.png")
        record.close()
        self.window = None

        projects = self.dir / "projects"
        for name in ("COMMON", "DELTA"):
            (projects / name).mkdir(parents=True)
        window = self.window = CleanupWindow(self.root, self.vault, journal({}), TODAY, projects, self.after_save,
                                             self.audit, self.done.append, take_focus=False,
                                             scanner=lambda root: Scan())
        self.wait(lambda: window.items)
        window.win.update()
        snapshot(window.win, "cleanup.png")

    def wait(self, condition, seconds=20):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            self.root.update()
            if condition():
                return
            time.sleep(0.02)
        self.fail("не дождались")

    def test_record_window_saves_comment_value_unlink(self):
        row = {r.key: r for r in self.vault.rows()}["API_KEY"]
        j = journal({(row.uid, "DELTA"): Usage(2, date(2026, 9, 4))})
        w = self.window = RecordWindow(self.root, self.vault, row, j, TODAY, self.after_save, self.audit, self.done.append,
                         take_focus=False)
        self.assertIn("DELTA", w.unlink_buttons)
        self.assertNotIn("COMMON", w.unlink_buttons, "домашний проект кнопкой не снимается")
        w.comment.set("Ключ погоды")
        w.value.set("TEST-new-value")
        w.toggle_unlink("DELTA")
        w.save()
        self.wait(lambda: self.done)
        self.assertEqual(self.done, [True])
        after = {r.key: r for r in self.reopen().rows()}["API_KEY"]
        self.assertEqual(after.comment, "Ключ погоды")
        self.assertEqual(after.projects, ("COMMON",))
        self.assertEqual(self.reopen().value(after.uid), "TEST-new-value")
        self.assertEqual(self.catalogs, 1)
        self.assertNotIn("TEST-", repr(self.audit.write.call_args_list))

    def test_record_window_trash(self):
        row = {r.key: r for r in self.vault.rows()}["login"]
        w = self.window = RecordWindow(self.root, self.vault, row, journal({}), TODAY, self.after_save, self.audit,
                         self.done.append, take_focus=False)
        with mock.patch.object(cleanup.messagebox, "askyesno", return_value=True):
            w.trash()
        self.wait(lambda: self.done)
        self.assertNotIn("login", {r.key for r in self.reopen().rows()})
        self.assertEqual(self.audit.write.call_args.args[0], "record_trashed")

    def test_cleanup_window_defaults_and_empty_trash(self):
        projects = self.dir / "projects"
        for name in ("COMMON", "DELTA"):
            (projects / name).mkdir(parents=True)
        w = self.window = CleanupWindow(self.root, self.vault, journal({}), TODAY, projects, self.after_save, self.audit,
                          self.done.append, take_focus=False, scanner=lambda root: Scan())
        self.wait(lambda: w.items)
        kinds = {(s.kind, s.project) for s, _ in w.items}
        self.assertIn((UNLINK, "DELTA"), kinds)
        self.assertIn((PROJECT, "TV"), kinds)
        self.assertEqual({s.kind for s in w.chosen()}, {UNLINK}, "отмечены заранее только снятия проектов")
        for s, var in w.items:
            if s.kind == PROJECT:
                var.set(True)
        with mock.patch.object(cleanup.messagebox, "askyesno", return_value=True):
            w.apply()
            self.wait(lambda: not w._busy and "Применено" in w.message.cget("text"))
            self.assertEqual(len(self.reopen().trashed()), 1)
            w.empty_trash()
            self.wait(lambda: not w._busy and "Стёрто" in w.message.cget("text"))
        self.assertEqual(self.reopen().trashed(), [])
        events = [c.args[0] for c in self.audit.write.call_args_list]
        self.assertEqual(events, ["cleanup_applied", "trash_emptied"])
        w.close()
        self.assertEqual(self.done, [True])


class CallbackCleanupTest(unittest.TestCase):
    """Synthetic vault/scanner only; workers are released and joined before main-thread Tk cleanup."""

    def setUp(self):
        gc.collect()
        self.root = tk.Tk()
        self.root.withdraw()
        apply_style(self.root)
        self.dir = Path(tempfile.mkdtemp(prefix="pwtest"))
        self.window = None
        self.vault = mock.Mock()
        self.row = row("synthetic", "DELTA", "Synthetic record", ["DELTA"])
        self.vault.rows.return_value = [self.row]
        self.vault.trashed.return_value = []
        self.vault.export_entries.return_value = []
        self.done = mock.Mock()
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

    def make_record(self):
        self.window = RecordWindow(self.root, self.vault, self.row, journal({}), TODAY, mock.Mock(), mock.Mock(),
                                   self.done, take_focus=False)
        return self.window

    def check_record_cleanup(self, destroy=False):
        w = self.make_record()
        pending = w._poll_id
        script, kind = self.root.tk.call("after", "info", pending)
        self.assertEqual(kind, "timer")
        self.assertEqual(set(self.root.tk.call("after", "info")) - self.after_before, {pending})
        child = tk.Frame(w.win)
        child.destroy()
        self.assertEqual(w._poll_id, pending)
        (w.win.destroy if destroy else w.close)()
        self.assertIsNone(w._poll_id)
        self.assertEqual(set(self.root.tk.call("after", "info")), self.after_before)
        self.assertFalse(self.root.tk.call("info", "commands", script))
        self.root.update()
        if destroy:
            self.done.assert_not_called()
        else:
            self.done.assert_called_once_with(False)
        self.vault.save.assert_not_called()

    def test_record_close_cancels_pending_poll(self):
        self.check_record_cleanup()

    def test_record_manual_destroy_cancels_pending_poll(self):
        self.check_record_cleanup(destroy=True)

    def check_blocked_scan_cleanup(self, destroy=False, teardown=False, finish_scan=False):
        started, release = threading.Event(), threading.Event()
        workers = []
        thread_class = threading.Thread

        def thread(*args, **kwargs):
            worker = thread_class(*args, **kwargs)
            workers.append(worker)
            return worker

        def scanner(folder):
            started.set()
            release.wait()
            return Scan()

        try:
            with mock.patch.object(cleanup.threading, "Thread", side_effect=thread):
                w = self.window = CleanupWindow(self.root, self.vault, journal({}), TODAY, self.dir, mock.Mock(),
                                                mock.Mock(), self.done, take_focus=False, scanner=scanner)
            self.assertTrue(started.wait(5))
            poll, scan = w._poll_id, w._scan_id
            self.assertIsNotNone(poll)
            self.assertIsNotNone(scan)
            self.assertNotEqual(poll, scan)
            interpreter = self.root.tk
            scripts = [interpreter.call("after", "info", pending)[0] for pending in (poll, scan)]
            self.assertEqual(set(interpreter.call("after", "info")) - self.after_before, {poll, scan})
            child = tk.Frame(w.win)
            child.destroy()
            self.assertEqual((w._poll_id, w._scan_id), (poll, scan))
            if finish_scan:
                release.set()
                workers[0].join(5)
                self.assertFalse(workers[0].is_alive())
                with mock.patch.object(w, "refresh", side_effect=lambda: self.assertIsNone(w._scan_id)) as refresh:
                    end = time.monotonic() + 3
                    while w._scan_id is not None and time.monotonic() < end:
                        self.root.update()
                        time.sleep(0.01)
                    refresh.assert_called_once_with()
                self.assertIsNone(w._scan_id)
                self.assertNotIn(scan, interpreter.call("after", "info"))
            if teardown:
                self.root.destroy()
                self.root = None
            else:
                (w.win.destroy if destroy else w.close)()
            self.assertIsNone(w._poll_id)
            self.assertIsNone(w._scan_id)
            self.assertEqual(set(interpreter.call("after", "info")), self.after_before)
            for script in scripts:
                self.assertFalse(interpreter.call("info", "commands", script))
            if self.root is not None:
                self.root.update()
            if destroy or teardown:
                self.done.assert_not_called()
            else:
                self.done.assert_called_once_with(False)
            self.vault.save.assert_not_called()
        finally:
            release.set()
            for worker in workers:
                worker.join(5)
            for worker in workers:
                self.assertFalse(worker.is_alive(), "synthetic scanner must not outlive the test")

    def test_cleanup_close_cancels_poll_and_blocked_scan(self):
        self.check_blocked_scan_cleanup()

    def test_cleanup_manual_destroy_cancels_poll_and_blocked_scan(self):
        self.check_blocked_scan_cleanup(destroy=True)

    def test_cleanup_root_teardown_cancels_poll_and_blocked_scan(self):
        self.check_blocked_scan_cleanup(teardown=True)

    def test_scan_clears_id_before_refresh(self):
        self.check_blocked_scan_cleanup(finish_scan=True)

    def test_poll_clears_id_before_done_and_tracks_replacement(self):
        w = self.make_record()
        first = w._poll_id
        w._result = (None, "synthetic")
        w._done = mock.Mock(side_effect=lambda *args: self.assertIsNone(w._poll_id))
        end = time.monotonic() + 3
        while w._poll_id == first and time.monotonic() < end:
            self.root.update()
            time.sleep(0.01)
        w._done.assert_called_once_with(None, "synthetic")
        self.assertIsNotNone(w._poll_id)
        self.assertNotEqual(w._poll_id, first)
        self.assertNotIn(first, self.root.tk.call("after", "info"))

    def test_dark_title_map_ignores_child_widgets(self):
        w = self.make_record()
        self.root.update()
        with mock.patch.object(cleanup, "dark_title_bar") as dark:
            w.body.event_generate("<Map>")
            dark.assert_not_called()
            w.win.event_generate("<Map>")
            dark.assert_called_once_with(w.win)


if __name__ == "__main__":
    unittest.main()
