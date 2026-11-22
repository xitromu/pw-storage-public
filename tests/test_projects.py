"""Подключение проекта (Т30): инструкция в CLAUDE.md, состояние папок, окно «Проекты». Только временные папки."""

import gc
import shutil
import time
import tempfile
import tkinter as tk
import unittest
from pathlib import Path
from unittest import mock

from pw_storage import projects
from pw_storage.cleanup import Scan
from pw_storage.projects import BEGIN, END, ProjectsWindow, collect, has_instruction, write_instruction
from pw_storage.vault import Row
from pw_storage.window import apply_style


def row(uid, group, comment, projects_=()):
    return Row(uid, group, "S", "K", comment, tuple(projects_), False, "d")


class InstructionTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="pwtest"))

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_creates_file(self):
        path = write_instruction(self.dir)
        text = path.read_text(encoding="utf-8")
        self.assertTrue(text.startswith(BEGIN))
        self.assertIn("pw.py list", text)
        self.assertTrue(has_instruction(self.dir))

    def test_appends_keeps_text_bom_and_crlf(self):
        path = self.dir / "CLAUDE.md"
        path.write_bytes(b"\xef\xbb\xbf# \xd0\x9f\xd1\x80\xd0\xbe\xd0\xb5\xd0\xba\xd1\x82\r\n\r\n\xd0\xa2\xd0\xb5\xd0\xba\xd1\x81\xd1\x82\r\n")
        write_instruction(self.dir)
        raw = path.read_bytes()
        self.assertTrue(raw.startswith(b"\xef\xbb\xbf"), "BOM сохранён")
        text = raw.decode("utf-8-sig")
        self.assertTrue(text.startswith("# Проект\r\n\r\nТекст\r\n\r\n" + BEGIN))
        self.assertNotIn("\n", text.replace("\r\n", ""), "переводы строк остались CRLF")

    def test_replaces_block_only(self):
        path = self.dir / "CLAUDE.md"
        path.write_text(f"до\n\n{BEGIN}\nстарый текст\n{END}\n\nпосле\n", encoding="utf-8")
        write_instruction(self.dir)
        text = path.read_text(encoding="utf-8")
        self.assertNotIn("старый текст", text)
        self.assertTrue(text.startswith("до\n\n" + BEGIN))
        self.assertTrue(text.endswith(END + "\n\nпосле\n"))
        self.assertEqual(text.count(BEGIN), 1)


class CollectTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="pwtest"))
        for name in ("DELTA", "CLUB", "POST", ".git"):
            (self.root / name).mkdir()
        write_instruction(self.root / "DELTA")
        (self.root / "CLUB" / "secrets.env").write_text("X=1", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_states(self):
        rows = [row("a", "DELTA", "Логин", ["DELTA"]), row("b", "POST", "Почта", ["POST", "DELTA"]),
                row("c", "TV", "Кино", ["TV"])]
        infos = {i.name: i for i in collect(self.root, rows)}
        self.assertNotIn(".git", infos)
        self.assertEqual(infos["DELTA"].state[0], "✓")
        self.assertEqual(len(infos["DELTA"].records), 2, "своя запись и отмеченная у DELTA")
        self.assertEqual(infos["POST"].state[0], "нет инструкции")
        self.assertEqual(infos["CLUB"].state[0], "не подключён · файлов: 1")
        self.assertEqual(infos["CLUB"].open_files, ["secrets.env"])
        self.assertFalse(infos["TV"].exists)
        self.assertEqual(infos["TV"].state[0], "папки нет")

    def test_project_folders_only_connected(self):
        (self.root / "ALL").mkdir()
        (self.root / "_SYSTEM").mkdir()
        self.assertEqual(projects.project_folders(self.root), ["DELTA"])
        self.assertEqual(projects.project_folders(self.root / "нет-папки"), [])


class WindowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tk = tk.Tk()
        cls.tk.withdraw()
        apply_style(cls.tk)

    @classmethod
    def tearDownClass(cls):
        cls.tk.destroy()
        gc.collect()

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="pwtest"))
        for name in ("DELTA", "CLUB"):
            (self.root / name).mkdir()
        self.rows = [row("a", "DELTA", "Логин", ["DELTA"])]
        self.added = []
        self.closed = []
        self.audit = mock.Mock()
        self.after_before = set(self.tk.tk.call("after", "info"))
        self.window = ProjectsWindow(self.tk, self.root, lambda: self.rows, lambda p, done: self.added.append((p, done)),
                                     self.audit, lambda: self.closed.append(True), take_focus=False,
                                     scanner=lambda folder: Scan())

    def tearDown(self):
        if self.window.win.winfo_exists():
            self.window.close()
        self.window = None
        gc.collect()
        shutil.rmtree(self.root, ignore_errors=True)

    def test_documentation_screenshot(self):
        """Снимок окна «Проекты» для документации: путь без временной папки этой машины."""
        import os
        from tests.shot import snapshot

        if os.environ.get("PW_STORAGE_SHOTS"):
            demo = Path(__file__).resolve().parent / "_demo_projects"
            shutil.rmtree(demo, ignore_errors=True)
            for name in ("DELTA", "CLUB"):
                (demo / name).mkdir(parents=True)
            self.addCleanup(shutil.rmtree, demo, True)
            self.window.projects_root = demo
            self.window.refresh()
        self.window.win.update()
        snapshot(self.window.win, "projects.png")

    def test_connect_flow(self):
        w = self.window
        self.assertEqual(w.selected, "CLUB", "сначала выбран неподключённый проект")
        self.assertFalse((self.root / "CLUB" / "CLAUDE.md").exists(), "без «Записать» ничего не пишется")
        w.show_instruction("CLUB")
        self.assertTrue(w.preview.winfo_exists())
        self.assertFalse((self.root / "CLUB" / "CLAUDE.md").exists())
        w.write("CLUB")
        self.assertTrue(has_instruction(self.root / "CLUB"))
        self.assertEqual(self.audit.write.call_args.args[0], "project_connected")
        self.assertTrue(w.info("CLUB").connected)
        self.assertIn("подключено: 1", w.summary.cget("text"))

    def test_new_record_passes_project(self):
        self.window.new_record("CLUB")
        self.assertEqual(self.added[0][0], "CLUB")

    def test_close(self):
        self.window.close()
        self.window.close()
        self.assertEqual(self.closed, [True])

    def check_pending_refresh_cleanup(self, destroy=False):
        w = self.window
        w.new_record("CLUB")
        done = self.added[-1][1]
        with mock.patch.object(w.win, "after", wraps=w.win.after) as after:
            done(True)
            self.assertEqual(after.call_args.args[0], 1500)
        pending = w._refresh_after
        script, kind = self.tk.tk.call("after", "info", pending)
        self.assertEqual(kind, "timer")
        self.assertEqual(set(self.tk.tk.call("after", "info")) - self.after_before, {pending})
        child = tk.Frame(w.win)
        child.destroy()
        self.assertEqual(w._refresh_after, pending, "child destruction must not cancel the window timer")
        (w.win.destroy if destroy else w.close)()
        self.assertIsNone(w._refresh_after)
        self.assertEqual(set(self.tk.tk.call("after", "info")), self.after_before)
        self.assertFalse(self.tk.tk.call("info", "commands", script))
        done(True)  # A synthetic new-record window can finish after its parent closes.
        self.assertIsNone(w._refresh_after)
        self.tk.update()
        self.assertEqual(self.closed, [] if destroy else [True])

    def test_close_cancels_new_record_refresh(self):
        self.check_pending_refresh_cleanup()

    def test_manual_destroy_cancels_new_record_refresh(self):
        self.check_pending_refresh_cleanup(destroy=True)

    def test_new_record_refresh_replaces_timer_and_clears_on_entry(self):
        w = self.window
        w.new_record("CLUB")
        done = self.added[-1][1]
        with mock.patch.object(w, "refresh", side_effect=lambda: self.assertIsNone(w._refresh_after)) as refresh:
            done(True)
            first = w._refresh_after
            with mock.patch.object(w.win, "after_cancel", wraps=w.win.after_cancel) as cancel:
                done(True)
                cancel.assert_called_once_with(first)
            pending = w._refresh_after
            self.assertNotEqual(first, pending)
            self.assertNotIn(first, self.tk.tk.call("after", "info"))
            self.assertEqual(set(self.tk.tk.call("after", "info")) - self.after_before, {pending})
            refresh.assert_not_called()
            start = time.monotonic()
            end = start + 3
            while w._refresh_after is not None and time.monotonic() < end:
                self.tk.update()
                time.sleep(0.01)
            self.assertIsNone(w._refresh_after)
            self.assertGreaterEqual(time.monotonic() - start, 1.4)
            refresh.assert_called_once_with()
            self.assertNotIn(pending, self.tk.tk.call("after", "info"))

    def test_dark_title_map_ignores_child_widgets(self):
        self.tk.update()
        with mock.patch.object(projects, "dark_title_bar") as dark:
            self.window.body.event_generate("<Map>")
            dark.assert_not_called()
            self.window.win.event_generate("<Map>")
            dark.assert_called_once_with(self.window.win)


if __name__ == "__main__":
    unittest.main()
