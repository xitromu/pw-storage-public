"""Опознание клиента: проект и сессия по процессу."""

import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from pw_storage import procinfo
from pw_storage.config import HOME
from pw_storage.procinfo import ClientInfo, resolve_project, script_from_args, split_command_line


class ArgsTest(unittest.TestCase):
    def test_script_absolute(self):
        self.assertEqual(script_from_args(["python.exe", r"C:\p\x.py", "--flag"], None), Path(r"C:\p\x.py"))

    def test_script_relative_to_cwd(self):
        self.assertEqual(script_from_args(["python", "x.py"], Path(r"C:\p")), Path(r"C:\p\x.py"))

    def test_options_before_script(self):
        self.assertEqual(script_from_args(["python", "-I", "-X", "utf8", "x.py"], Path(r"C:\p")), Path(r"C:\p\x.py"))

    def test_no_script_for_c_and_m(self):
        self.assertIsNone(script_from_args(["python", "-c", "print(1)"], None))
        self.assertIsNone(script_from_args(["python", "-m", "unittest"], None))

    def test_not_python(self):
        self.assertIsNone(script_from_args(["gradlew.bat", "assemble"], None))

    def test_split_handles_spaces_and_cyrillic(self):
        self.assertEqual(split_command_line(r'"C:\Program Files\python.exe" "C:\Папка с пробелом\x.py" a'),
                         [r"C:\Program Files\python.exe", r"C:\Папка с пробелом\x.py", "a"])


class ProjectTest(unittest.TestCase):
    root = Path(r"C:\projects")

    def test_script_wins_over_cwd(self):
        info = ClientInfo(1, Path(r"C:\projects\DELTA"), Path(r"C:\projects\COMMON\tools\mail.py"))
        self.assertEqual(resolve_project(info, self.root), "COMMON")

    def test_cwd_when_no_script(self):
        self.assertEqual(resolve_project(ClientInfo(1, Path(r"C:\projects\DELTA\src"), None), self.root), "DELTA")

    def test_tool_script_uses_cwd(self):
        info = ClientInfo(1, Path(r"C:\projects\DELTA"), HOME / "pw.py")
        self.assertEqual(resolve_project(info, self.root), "DELTA")

    def test_outside_root_is_unknown(self):
        self.assertIsNone(resolve_project(ClientInfo(1, Path(r"C:\Windows"), Path(r"C:\tmp\x.py")), self.root))

    def test_root_itself_is_unknown(self):
        self.assertIsNone(resolve_project(ClientInfo(1, self.root, None), self.root))

    def test_case_insensitive(self):
        self.assertEqual(resolve_project(ClientInfo(1, Path(r"c:\PROJECTS\DELTA"), None), self.root), "DELTA")

    def test_prefix_is_not_a_match(self):
        self.assertIsNone(resolve_project(ClientInfo(1, Path(r"C:\projects2\DELTA"), None), self.root))


class LiveProcessTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="pwtest"))

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_inspect_reads_cwd_and_script(self):
        script = self.dir / "sleeper.py"
        script.write_text("import time; time.sleep(30)", encoding="ascii")
        child = subprocess.Popen([sys.executable, "sleeper.py"], cwd=self.dir)
        try:
            # Сразу после запуска данные процесса ещё не заполнены; настоящий клиент обращается уже работая.
            deadline = time.monotonic() + 5
            while True:
                info = procinfo.inspect(child.pid)
                ready = info.script is not None and info.script.is_absolute() and info.cwd.resolve() == self.dir.resolve()
                if ready or time.monotonic() > deadline:
                    break
                time.sleep(0.05)
        finally:
            child.kill()
            child.wait()
        self.assertEqual(info.cwd.resolve(), self.dir.resolve())
        self.assertEqual(info.script.resolve(), script.resolve())

    def test_inspect_self(self):
        info = procinfo.inspect(os.getpid())
        self.assertEqual(info.cwd.resolve(), Path.cwd().resolve())

    def test_session_identity_is_stable(self):
        first = procinfo.session_of(os.getpid())
        self.assertEqual(first, procinfo.session_of(os.getpid()))


if __name__ == "__main__":
    unittest.main()
