"""Хост служб: имена, конфигурация, SCM-слой и надзор за детским процессом."""

import ctypes
import io
import json
import subprocess
import threading
import time
import unittest
from pathlib import Path
from tempfile import mkdtemp
from unittest import mock

from pw_storage import service_host as host


def config(**changes) -> dict:
    base = {"name": "PW_PROXY_BOT", "profile": "main",
            "argv": [r"C:\py\python.exe", r"C:\projects\COMMON\tools\proxy_gateway.py"],
            "cwd": r"C:\projects\COMMON", "log": r"C:\projects\COMMON\data\gateway.log"}
    return {**base, **changes}


class FakeApi:
    """Достаточно для проверок аргументов и порядка вызовов advapi32."""

    def __init__(self, states=None, open_code=0):
        self.calls = []
        self.states = list(states or [host.SERVICE_STOPPED])
        self.open_code = open_code
        self.counter = 100

    def _handle(self, name):
        self.counter += 1
        return self.counter

    def OpenSCManagerW(self, machine, database, access):
        self.calls.append(("OpenSCManagerW", machine, database, access))
        return self._handle("manager")

    def OpenServiceW(self, manager, name, access):
        self.calls.append(("OpenServiceW", name, access))
        if self.open_code:
            ctypes.set_last_error(self.open_code)
            return None
        return self._handle("service")

    def CreateServiceW(self, manager, name, display, access, kind, start, errors, binary,
                       group, tag, deps, account, password):
        self.calls.append(("CreateServiceW", name, kind, start, account, binary))
        return self._handle("service")

    def StartServiceW(self, service, count, argv):
        self.calls.append(("StartServiceW", count))
        return 1

    def ControlService(self, service, control, status):
        self.calls.append(("ControlService", control))
        return 1

    def QueryServiceStatusEx(self, service, level, buffer, size, needed):  # needed не читаем
        info = ctypes.cast(buffer, ctypes.POINTER(host.SERVICE_STATUS_PROCESS)).contents
        info.dwCurrentState = self.states.pop(0) if len(self.states) > 1 else self.states[0]
        info.dwProcessId = 4321
        return 1

    def DeleteService(self, service):
        self.calls.append(("DeleteService",))
        return 1

    def CloseServiceHandle(self, handle):
        self.calls.append(("CloseServiceHandle", handle))
        return 1


class FakeChild:
    def __init__(self, exits_after=None, never_exits=False):
        self.pid = 777
        self.started = time.monotonic()
        self.exits_after = exits_after
        self.never_exits = never_exits
        self.terminated = False
        self.killed = False

    def poll(self):
        if self.terminated or self.killed:
            return 0
        if self.never_exits:
            return None
        if self.exits_after is not None and time.monotonic() - self.started > self.exits_after:
            return 1
        return None

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True


class NameTest(unittest.TestCase):
    def test_only_service_names(self):
        self.assertEqual(host.service_name("PW_TGBRIDGE"), "PW_TGBRIDGE")
        for bad in ("pw_bridge", "", "BRIDGE", "PW_" + "X" * 70, None):
            with self.subTest(name=bad), self.assertRaises(host.HostError):
                host.service_name(bad)

    def test_account_matches_service_store(self):
        self.assertEqual(host.service_account("PW_PROXY_BOT"), "NT SERVICE\\PW_PROXY_BOT")

    def test_command_line_quotes_paths(self):
        line = host.command_line(Path(r"C:\Program Files\py.exe"), Path(r"C:\r\pw_service.py"),
                                 Path(r"C:\ProgramData\cfg.json"))
        self.assertEqual(line.count('"'), 6)
        self.assertIn("-X utf8", line)


class ConfigTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(mkdtemp(prefix="pwhost_"))

    def test_valid_config(self):
        self.assertEqual(host.validate_config(config())["profile"], "main")

    def test_rejects_shape_and_paths(self):
        for bad in (config(argv=[]), config(argv=["ok", 5]), config(cwd="relative"),
                    config(log="data.log"), config(profile="боевой"), config(name="GIGA"),
                    config(extra=1), "не dict"):
            with self.subTest(config=str(bad)[:40]), self.assertRaises(host.HostError):
                host.validate_config(bad)

    def test_reads_only_own_file(self):
        path = self.dir / "pw_proxy_bot.launch.json"
        path.write_text(json.dumps(config()), encoding="utf-8")
        self.assertEqual(host.read_config(path)["name"], "PW_PROXY_BOT")
        for broken in ("не json", json.dumps([1, 2]), ""):
            path.write_text(broken, encoding="utf-8")
            with self.subTest(body=broken), self.assertRaises(host.HostError):
                host.read_config(path)

    def test_oversize_config_is_refused(self):
        path = self.dir / "big.json"
        path.write_bytes(b'{"name": "PW_X", "pad": "' + b"x" * host.MAX_CONFIG_BYTES + b'"}')
        with self.assertRaises(host.HostError):
            host.read_config(path)


class ScmLayerTest(unittest.TestCase):
    def service(self, api) -> host.Service:
        return host.Service("PW_PROXY_BOT", api=api)

    def test_open_and_close(self):
        api = FakeApi()
        with self.service(api) as service:
            self.assertTrue(service.exists())
        self.assertIn(("OpenServiceW", "PW_PROXY_BOT", host.SERVICE_QUERY_STATUS), api.calls)
        self.assertEqual(len([c for c in api.calls if c[0] == "CloseServiceHandle"]), 2)

    def test_missing_service(self):
        api = FakeApi(open_code=host.ERROR_SERVICE_DOES_NOT_EXIST)
        with self.service(api) as service:
            self.assertFalse(service.exists())

    def test_create_uses_service_account_and_autostart(self):
        api = FakeApi(open_code=host.ERROR_SERVICE_DOES_NOT_EXIST)
        with self.service(api) as service:
            service.create(r'"C:\py\python.exe" "C:\r\pw_service.py" "C:\r\cfg.json"')
        created = [call for call in api.calls if call[0] == "CreateServiceW"][0]
        self.assertEqual(created[1], "PW_PROXY_BOT")
        self.assertEqual(created[3], host.SERVICE_AUTO_START)
        self.assertEqual(created[4], "NT SERVICE\\PW_PROXY_BOT")

    def test_create_refuses_existing(self):
        api = FakeApi()
        with self.service(api) as service:
            with self.assertRaises(host.HostError) as caught:
                service.create("cmd")
        self.assertEqual(caught.exception.code, host.ERROR_SERVICE_EXISTS)

    def test_stop_tolerates_inactive(self):
        api = FakeApi()
        api.ControlService = lambda service, control, status: (
            ctypes.set_last_error(host.ERROR_SERVICE_NOT_ACTIVE), 0)[1]
        with self.service(api) as service:
            service.stop()

    def test_remove_stops_then_deletes(self):
        api = FakeApi(states=[host.SERVICE_RUNNING, host.SERVICE_STOPPED])
        with self.service(api) as service:
            service.remove()
        kinds = [call[0] for call in api.calls]
        self.assertLess(kinds.index("ControlService"), kinds.index("DeleteService"))

    def test_stopped_service_shows_exit_codes(self):
        out = io.StringIO()
        api = FakeApi(states=[host.SERVICE_STOPPED])
        api.QueryServiceStatusEx = self.dead
        with mock.patch.object(host, "load_api", return_value=api),                 mock.patch("sys.stdout", out):
            host.main(["status", "--name", "PW_PROXY_BOT"])
        self.assertIn("код службы 1", out.getvalue())

    def dead(self, service, level, buffer, size, needed):
        info = ctypes.cast(buffer, ctypes.POINTER(host.SERVICE_STATUS_PROCESS)).contents
        info.dwCurrentState = host.SERVICE_STOPPED
        info.dwWin32ExitCode = 1066
        info.dwServiceSpecificExitCode = 1
        return 1

    def test_wait_times_out(self):
        api = FakeApi(states=[host.SERVICE_START_PENDING])
        with self.service(api) as service:
            with mock.patch.object(host.time, "sleep"):
                with self.assertRaises(host.HostError) as caught:
                    service.wait(host.SERVICE_STOPPED, 0.01)
        self.assertEqual(caught.exception.code, host.ERROR_TIMEOUT)


class SuperviseTest(unittest.TestCase):
    def setUp(self):
        self.cfg = config(log=str(Path(mkdtemp(prefix="pwsup_")) / "service.log"))

    def start_supervise(self, popen, stop_after=0.05, timeout=5.0, limit=3):
        stop = threading.Event()

        def later():
            stop.wait(stop_after)
            stop.set()

        thread = threading.Thread(target=later)
        thread.start()
        started = time.monotonic()
        code = host.supervise(stop, self.cfg, popen=popen, poll=0.01, delay=0.01,
                             grace=0.05, limit=limit)
        thread.join()
        self.assertLess(time.monotonic() - started, timeout)
        return code

    def test_child_is_restarted(self):
        children = []

        def popen(argv, **kwargs):
            child = FakeChild(exits_after=0.01)
            children.append(child)
            return child

        self.start_supervise(popen, stop_after=0.2)
        self.assertGreater(len(children), 1)
        self.assertIn("завершился", Path(self.cfg["log"]).read_text(encoding="utf-8"))

    def test_stop_terminates_running_child(self):
        made = []

        def popen(argv, **kwargs):
            child = FakeChild(never_exits=True)
            made.append(child)
            return child

        code = self.start_supervise(popen)
        self.assertEqual(code, 0)
        self.assertTrue(made[0].terminated)
        self.assertFalse(made[0].killed)

    def test_hard_stop_uses_kill(self):
        made = []

        def popen(argv, **kwargs):
            child = FakeChild(never_exits=True)
            child.terminate = lambda: None
            made.append(child)
            return child

        code = self.start_supervise(popen, stop_after=0.05, timeout=host.KILL_GRACE + 5)
        self.assertEqual(code, 0)
        self.assertTrue(made[0].killed)

    def test_launch_failure_gives_up_after_limit(self):
        def popen(argv, **kwargs):
            raise OSError("нет файла")

        self.assertEqual(self.start_supervise(popen, stop_after=0.5), 1)
        self.assertIn("слишком частые отказы", Path(self.cfg["log"]).read_text(encoding="utf-8"))

    def test_restart_pause_grows_and_is_capped(self):
        waits = []

        class Stop:
            def is_set(self):
                return len(waits) >= 8

            def set(self):
                pass

            def wait(self, seconds):
                waits.append(seconds)
                return False

        def popen(argv, **kwargs):
            raise OSError("нет файла")

        code = host.supervise(Stop(), self.cfg, popen=popen, poll=0.01, delay=5.0, limit=99)
        self.assertEqual(code, 0)
        self.assertEqual(waits[:4], [10.0, 20.0, 40.0, 60.0])
        self.assertEqual(waits[-1], 60.0)

    def test_child_stdout_goes_to_the_log_file(self):
        opened = {}

        def popen(argv, **kwargs):
            opened.update(kwargs)
            return FakeChild(never_exits=True)

        self.start_supervise(popen)
        self.assertEqual(opened["cwd"], self.cfg["cwd"])
        self.assertIs(opened["stderr"], subprocess.STDOUT)
        self.assertEqual(opened["stdout"].name, self.cfg["log"])
        self.assertEqual(opened["stdin"], subprocess.DEVNULL)


class InstallOrderTest(unittest.TestCase):
    """Сначала регистрация службы, потом папка журнала: SID службы появляется с ней."""

    def setUp(self):
        self.dir = Path(mkdtemp(prefix="pworder_"))
        self.path = self.dir / "pw_proxy_bot.launch.json"
        self.path.write_text(json.dumps(config(log=str(self.dir / "s.log"))), encoding="utf-8")
        self.order = []

    def run_install(self, api):
        def prepare(name):
            api.calls.append(("prepare_log_directory",))
            return self.dir / "s.log"

        with mock.patch.object(host, "load_api", return_value=api), \
                mock.patch.object(host, "service_log", return_value=self.dir / "s.log"), \
                mock.patch.object(host, "prepare_log_directory", prepare), \
                mock.patch("sys.stdout", new_callable=io.StringIO):
            return host.main(["install", "--name", "PW_PROXY_BOT", "--config", str(self.path),
                              "--apply"])

    def test_create_precedes_log_directory(self):
        api = FakeApi(open_code=host.ERROR_SERVICE_DOES_NOT_EXIST)
        self.assertEqual(self.run_install(api), 0)
        self.assertEqual(self.sequence(api), ["CreateServiceW", "prepare_log_directory"])

    def test_existing_service_still_gets_log_directory(self):
        api = FakeApi()  # OpenServiceW успешен: служба уже зарегистрирована
        self.assertEqual(self.run_install(api), 0)
        self.assertEqual(self.sequence(api), ["prepare_log_directory"])

    @staticmethod
    def sequence(api):
        return [call[0] for call in api.calls if call[0] in ("CreateServiceW",
                                                             "prepare_log_directory")]

    def test_log_folder_is_writable_for_the_service(self):
        with mock.patch.object(host.winsecurity, "service_sid",
                               return_value="S-1-5-80-1-2-3-4-5"),                 mock.patch.object(host.winsecurity, "create_service_directory") as created:
            path = host.prepare_log_directory("PW_PROXY_BOT")
        self.assertEqual(path.name, "service.log")
        self.assertEqual(created.call_args.args[1], "S-1-5-80-1-2-3-4-5")
        self.assertTrue(created.call_args.kwargs["writable"])

    def test_missing_service_account_is_explained(self):
        api = FakeApi(open_code=host.ERROR_SERVICE_DOES_NOT_EXIST)
        err = io.StringIO()

        def prepare(name):
            raise host.winsecurity.SecurityError("Service SID lookup failed (winerror 1332).")

        with mock.patch.object(host, "load_api", return_value=api), \
                mock.patch.object(host, "service_log", return_value=self.dir / "s.log"), \
                mock.patch.object(host, "prepare_log_directory", prepare), \
                mock.patch("sys.stdout", new_callable=io.StringIO), \
                mock.patch("sys.stderr", err):
            code = host.main(["install", "--name", "PW_PROXY_BOT", "--config", str(self.path),
                              "--apply"])
        self.assertEqual(code, 1)
        self.assertIn("1332", err.getvalue())
        self.assertIn("install --apply", err.getvalue())


class CliTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(mkdtemp(prefix="pwsvc_"))
        self.path = self.dir / "pw_proxy_bot.launch.json"
        self.path.write_text(json.dumps(config()), encoding="utf-8")

    def run_cli(self, argv, api):
        out, err = io.StringIO(), io.StringIO()
        log = self.dir / "PW_PROXY_BOT" / "service.log"
        with mock.patch.object(host, "load_api", return_value=api),                 mock.patch.object(host, "service_log", return_value=log),                 mock.patch.object(host, "prepare_log_directory", return_value=log),                 mock.patch("sys.stdout", out), mock.patch("sys.stderr", err):
            code = host.main(argv)
        return code, out.getvalue()

    def good(self):
        path = self.dir / "PW_PROXY_BOT" / "service.log"
        data = config(log=str(path))
        self.path.write_text(json.dumps(data), encoding="utf-8")

    def test_install_refuses_foreign_log(self):
        self.good()
        api = FakeApi()
        foreign = self.dir.parent / "чужой.log"
        self.path.write_text(json.dumps(config(log=str(foreign))), encoding="utf-8")
        code, _ = self.run_cli(["install", "--name", "PW_PROXY_BOT", "--config", str(self.path),
                                "--apply"], api)
        self.assertEqual(code, 1)
        self.assertFalse(any(call[0] == "CreateServiceW" for call in api.calls))

    def test_install_without_apply_only_prints(self):
        self.good()
        api = FakeApi(open_code=host.ERROR_SERVICE_DOES_NOT_EXIST)
        code, text = self.run_cli(["install", "--name", "PW_PROXY_BOT", "--config", str(self.path)],
                                  api)
        self.assertEqual(code, 0)
        self.assertIn("NT SERVICE\\PW_PROXY_BOT", text)
        self.assertIn("proxy_gateway.py", text)
        self.assertNotIn("ключ", text)
        self.assertFalse(any(call[0] == "CreateServiceW" for call in api.calls))

    def test_install_apply_creates_once(self):
        self.good()
        api = FakeApi(open_code=host.ERROR_SERVICE_DOES_NOT_EXIST)
        code, _ = self.run_cli(["install", "--name", "PW_PROXY_BOT", "--config", str(self.path),
                                "--apply"], api)
        self.assertEqual(code, 0)
        self.assertEqual([call[0] for call in api.calls].count("CreateServiceW"), 1)

    def test_name_must_match_config(self):
        self.good()
        api = FakeApi()
        code, text = self.run_cli(["install", "--name", "PW_TGBRIDGE",
                                   "--config", str(self.path), "--apply"], api)
        self.assertEqual(code, 1)
        self.assertEqual(text, "")
        self.assertFalse(any(call[0] == "CreateServiceW" for call in api.calls))
        self.assertFalse(any(call[0] == "CreateServiceW" for call in api.calls))

    def test_start_needs_only_the_name(self):
        api = FakeApi(states=[host.SERVICE_RUNNING])
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(host, "load_api", return_value=api), \
                mock.patch("sys.stdout", out), mock.patch("sys.stderr", err):
            code = host.main(["start", "--name", "PW_PROXY_BOT", "--apply"])
        self.assertEqual(code, 0, err.getvalue())
        self.assertIn("StartServiceW", [call[0] for call in api.calls])
        self.assertIn("работает", out.getvalue())

    def test_start_rejects_foreign_config(self):
        api = FakeApi(states=[host.SERVICE_RUNNING])
        with mock.patch.object(host, "load_api", return_value=api), \
                mock.patch("sys.stderr", new_callable=io.StringIO):
            code = host.main(["start", "--name", "PW_TGBRIDGE", "--config", str(self.path),
                              "--apply"])
        self.assertEqual(code, 1)
        self.assertNotIn("StartServiceW", [call[0] for call in api.calls])

    def test_status_of_absent_service(self):
        api = FakeApi(open_code=host.ERROR_SERVICE_DOES_NOT_EXIST)
        code, text = self.run_cli(["status", "--name", "PW_PROXY_BOT"], api)
        self.assertEqual(code, 0)
        self.assertIn("службы нет", text)

    def test_uninstall_plan_does_not_delete(self):
        api = FakeApi(states=[host.SERVICE_STOPPED])
        code, text = self.run_cli(["uninstall", "--name", "PW_PROXY_BOT"], api)
        self.assertEqual(code, 0)
        self.assertIn("Будет удалена", text)
        self.assertFalse(any(call[0] == "DeleteService" for call in api.calls))


if __name__ == "__main__":
    unittest.main()
