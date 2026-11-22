"""Mock-only tests: no native SCM library may be loaded by this suite."""

import contextlib
import ctypes
import gc
import io
import threading
import unittest
from unittest import mock

with mock.patch.object(
    ctypes, "WinDLL", side_effect=AssertionError("native API forbidden"), create=True
):
    from tools import service_probe_scm as scm_module

_REAL_LOAD_API = scm_module._load_api
_API_NAMES = (
    "OpenSCManagerW OpenServiceW CreateServiceW StartServiceW QueryServiceStatusEx "
    "ControlService DeleteService CloseServiceHandle StartServiceCtrlDispatcherW "
    "RegisterServiceCtrlHandlerExW SetServiceStatus"
).split()
MANAGER = 0x100000001
SERVICE = 0x200000002
QUERY = 0x300000003
STATUS_HANDLE = 0x400000004
COMMAND = '"C:\\Probe Files\\python.exe" "C:\\Probe Files\\probe.py" --service'


class MockApiTest(unittest.TestCase):
    def setUp(self):
        self.api = mock.Mock(spec_set=_API_NAMES)
        for name in _API_NAMES:
            getattr(self.api, name).return_value = 1
        self.api.OpenSCManagerW.return_value = MANAGER
        self.api.CreateServiceW.return_value = SERVICE
        self.api.OpenServiceW.return_value = None
        self.api.RegisterServiceCtrlHandlerExW.return_value = STATUS_HANDLE
        self.native = self.enterContext(mock.patch.object(
            ctypes, "WinDLL", side_effect=AssertionError("native API forbidden"), create=True
        ))
        self.loader = self.enterContext(mock.patch.object(
            scm_module, "_load_api", return_value=self.api
        ))
        self.last_error = self.enterContext(mock.patch.object(
            scm_module, "_last_error", return_value=scm_module.ERROR_SERVICE_DOES_NOT_EXIST
        ))

    def tearDown(self):
        self.native.assert_not_called()

    def assert_error(self, stage, code):
        return self.assertRaisesRegex(scm_module.ProbeError, rf"^{stage}: {code}$")


class BindingTests(MockApiTest):
    def test_all_native_signatures_and_pointer_widths(self):
        with mock.patch.object(scm_module.os, "name", "nt"), mock.patch.object(
            ctypes, "WinDLL", return_value=self.api, create=True
        ) as loader:
            self.assertIs(_REAL_LOAD_API(), self.api)
        loader.assert_called_once_with("advapi32.dll", use_last_error=True)
        m = scm_module
        expected = {
            "OpenSCManagerW": ([m.LPWSTR, m.LPWSTR, m.DWORD], m.HANDLE),
            "OpenServiceW": ([m.HANDLE, m.LPWSTR, m.DWORD], m.HANDLE),
            "CreateServiceW": (
                [m.HANDLE, m.LPWSTR, m.LPWSTR, m.DWORD, m.DWORD, m.DWORD, m.DWORD,
                 m.LPWSTR, m.LPWSTR, m.LPDWORD, m.LPWSTR, m.LPWSTR, m.LPWSTR], m.HANDLE
            ),
            "StartServiceW": ([m.HANDLE, m.DWORD, ctypes.POINTER(m.LPWSTR)], m.BOOL),
            "QueryServiceStatusEx": (
                [m.HANDLE, ctypes.c_int, m.LPBYTE, m.DWORD, m.LPDWORD], m.BOOL
            ),
            "ControlService": ([m.HANDLE, m.DWORD, ctypes.POINTER(m.SERVICE_STATUS)], m.BOOL),
            "DeleteService": ([m.HANDLE], m.BOOL),
            "CloseServiceHandle": ([m.HANDLE], m.BOOL),
            "StartServiceCtrlDispatcherW": ([ctypes.POINTER(m.SERVICE_TABLE_ENTRYW)], m.BOOL),
            "RegisterServiceCtrlHandlerExW": ([m.LPWSTR, m.HANDLER_EX, ctypes.c_void_p], m.HANDLE),
            "SetServiceStatus": ([m.HANDLE, ctypes.POINTER(m.SERVICE_STATUS)], m.BOOL),
        }
        for name, (argtypes, restype) in expected.items():
            with self.subTest(name=name):
                self.assertEqual(getattr(self.api, name).argtypes, argtypes)
                self.assertIs(getattr(self.api, name).restype, restype)
        self.assertEqual(ctypes.sizeof(m.HANDLE), ctypes.sizeof(ctypes.c_void_p))
        self.assertEqual(ctypes.sizeof(m.DWORD), 4)
        self.assertEqual(ctypes.sizeof(m.BOOL), 4)
        self.assertEqual(ctypes.sizeof(m.SERVICE_STATUS), 28)
        self.assertEqual(ctypes.sizeof(m.SERVICE_STATUS_PROCESS), 36)
        self.assertEqual(ctypes.sizeof(m.SERVICE_TABLE_ENTRYW), 2 * ctypes.sizeof(m.HANDLE))
        self.assertEqual(m.SERVICE_MAIN._argtypes_, (m.DWORD, ctypes.POINTER(m.LPWSTR)))
        self.assertIsNone(m.SERVICE_MAIN._restype_)
        self.assertEqual(
            m.HANDLER_EX._argtypes_, (m.DWORD, m.DWORD, ctypes.c_void_p, ctypes.c_void_p)
        )
        self.assertIs(m.HANDLER_EX._restype_, m.DWORD)
        if hasattr(ctypes, "WINFUNCTYPE"):
            self.assertFalse(m.SERVICE_MAIN._flags_ & ctypes._FUNCFLAG_CDECL)
            self.assertFalse(m.HANDLER_EX._flags_ & ctypes._FUNCFLAG_CDECL)

    def test_non_windows_refuses_before_loading(self):
        with mock.patch.object(scm_module.os, "name", "posix"):
            with self.assert_error("platform", 50):
                _REAL_LOAD_API()

    def test_library_loading_error_does_not_expose_os_message(self):
        with mock.patch.object(scm_module.os, "name", "nt"), mock.patch.object(
            ctypes, "WinDLL", side_effect=OSError("secret path"), create=True
        ):
            with self.assert_error("load_api", 50):
                _REAL_LOAD_API()

    def test_error_has_only_stage_and_numeric_code(self):
        error = scm_module.ProbeError("OpenServiceW", 5)
        self.assertEqual(str(error), "OpenServiceW: 5")
        self.assertEqual((error.stage, error.code), ("OpenServiceW", 5))


class ScmTests(MockApiTest):
    def setUp(self):
        super().setUp()
        self.now = 0.0
        self.enterContext(mock.patch.object(scm_module.time, "monotonic", side_effect=lambda: self.now))
        self.sleep = self.enterContext(mock.patch.object(scm_module.time, "sleep", side_effect=self.advance))
        self.query_states = [scm_module.SERVICE_STOPPED]
        self.api.QueryServiceStatusEx.side_effect = self.query

    def advance(self, seconds):
        self.assertGreater(seconds, 0)
        self.assertLessEqual(seconds, 0.1)
        self.now += seconds

    def query(self, handle, level, buffer, size, needed):
        self.assertEqual(handle, SERVICE)
        self.assertEqual(level, scm_module.SC_STATUS_PROCESS_INFO)
        self.assertEqual(size, 36)
        status = ctypes.cast(buffer, ctypes.POINTER(scm_module.SERVICE_STATUS_PROCESS)).contents
        status.dwCurrentState = self.query_states[0]
        if len(self.query_states) > 1:
            self.query_states.pop(0)
        status.dwWin32ExitCode = 1066
        status.dwServiceSpecificExitCode = 71
        status.dwProcessId = 12345
        return 1

    def test_enter_and_exit_only_open_and_close_manager(self):
        controller = scm_module.Scm()
        self.loader.assert_not_called()
        with controller as entered:
            self.assertIs(controller, entered)
            self.api.OpenSCManagerW.assert_called_once_with(None, None, 3)
            self.assertFalse(controller.created)
        self.api.CloseServiceHandle.assert_called_once_with(MANAGER)
        self.api.CreateServiceW.assert_not_called()
        self.api.DeleteService.assert_not_called()

    def test_manager_open_error_is_not_hidden(self):
        self.api.OpenSCManagerW.return_value = None
        self.last_error.return_value = 5
        with self.assert_error("OpenSCManagerW", 5):
            with scm_module.Scm():
                self.fail("must not enter")
        self.api.CloseServiceHandle.assert_not_called()

    def test_create_uses_fixed_name_minimal_rights_and_virtual_account(self):
        with scm_module.Scm() as controller:
            controller.create(COMMAND)
            self.assertTrue(controller.created)
            self.api.OpenServiceW.assert_called_once_with(MANAGER, scm_module.NAME, 4)
            self.api.CreateServiceW.assert_called_once_with(
                MANAGER, "PW_STORAGE_TEST_SERVICE", "PW_STORAGE_TEST_SERVICE",
                0x10034, 0x10, 3, 1, COMMAND, None, None, None,
                "NT SERVICE\\PW_STORAGE_TEST_SERVICE", None,
            )
        self.assertTrue(controller.created)  # Closing handles is NOT deletion.
        self.assertIsNone(controller._service)
        self.api.CloseServiceHandle.assert_has_calls([mock.call(SERVICE), mock.call(MANAGER)])
        self.api.DeleteService.assert_not_called()
        self.api.ControlService.assert_not_called()

    def test_existing_service_is_refused_and_query_handle_closed(self):
        self.api.OpenServiceW.return_value = QUERY
        with scm_module.Scm() as controller:
            with self.assert_error("CreateServiceW", 1073):
                controller.create(COMMAND)
            self.assertFalse(controller.created)
            controller.remove()
        self.api.CloseServiceHandle.assert_has_calls([mock.call(QUERY), mock.call(MANAGER)])
        self.api.CreateServiceW.assert_not_called()
        self.api.DeleteService.assert_not_called()
        self.api.ControlService.assert_not_called()

    def test_query_close_failure_is_retained_for_context_cleanup(self):
        self.api.OpenServiceW.return_value = QUERY
        self.api.CloseServiceHandle.side_effect = [0, 1, 1]
        self.last_error.return_value = 5
        with scm_module.Scm() as controller:
            with self.assert_error("CloseServiceHandle", 5):
                controller.create(COMMAND)
            self.assertEqual(controller._query, QUERY)
            self.assertFalse(controller.created)
        self.assertIsNone(controller._query)
        self.api.CloseServiceHandle.assert_has_calls([
            mock.call(QUERY), mock.call(QUERY), mock.call(MANAGER),
        ])
        self.api.CreateServiceW.assert_not_called()
        self.api.DeleteService.assert_not_called()

    def test_exists_false_only_for_service_does_not_exist(self):
        with scm_module.Scm() as controller:
            self.assertFalse(controller.exists())
            for code in (5, 6, 1072):
                with self.subTest(code=code):
                    self.last_error.return_value = code
                    with self.assert_error("OpenServiceW", code):
                        controller.exists()
                    with self.assert_error("OpenServiceW", code):
                        controller.create(COMMAND)
        self.api.CreateServiceW.assert_not_called()

    def test_create_race_does_not_acquire_ownership(self):
        self.api.CreateServiceW.return_value = None
        self.last_error.side_effect = [1060, 1073]
        with scm_module.Scm() as controller:
            with self.assert_error("CreateServiceW", 1073):
                controller.create(COMMAND)
            self.assertFalse(controller.created)
            controller.remove()
        self.api.DeleteService.assert_not_called()
        self.api.ControlService.assert_not_called()

    def test_repeated_create_cannot_replace_owned_handle(self):
        with scm_module.Scm() as controller:
            controller.create(COMMAND)
            with self.assert_error("CreateServiceW", 1073):
                controller.create(COMMAND)
            with self.assert_error("enter", 87):
                controller.__enter__()
        self.assertEqual(self.api.CreateServiceW.call_count, 1)

    def test_invalid_binary_commands_rejected_without_api_mutation(self):
        with scm_module.Scm() as controller:
            for command in (None, "", "  ", "secret\0suffix"):
                with self.subTest(command_type=type(command).__name__):
                    with self.assert_error("CreateServiceW", 87):
                        controller.create(command)
        self.api.CreateServiceW.assert_not_called()
        self.api.OpenServiceW.assert_not_called()

    def test_start_passes_non_secret_unicode_args_and_null_for_empty(self):
        with scm_module.Scm() as controller:
            controller.create(COMMAND)
            controller.start(["--probe", "тест"])
            handle, count, args = self.api.StartServiceW.call_args.args
            self.assertEqual((handle, count, list(args)), (SERVICE, 2, ["--probe", "тест"]))
            controller.start([])
            self.api.StartServiceW.assert_called_with(SERVICE, 0, None)
            for args in ("not-a-list", [None], ["secret\0suffix"]):
                with self.assert_error("StartServiceW", 87):
                    controller.start(args)
        self.assertEqual(self.api.StartServiceW.call_count, 2)

    def test_start_failure_still_allows_finally_cleanup(self):
        self.api.StartServiceW.return_value = 0
        with scm_module.Scm() as controller:
            controller.create(COMMAND)
            try:
                self.last_error.return_value = 5
                with self.assert_error("StartServiceW", 5):
                    controller.start([])
                self.assertTrue(controller.created)
            finally:
                self.last_error.return_value = 1060
                controller.remove()
            self.assertFalse(controller.created)
        self.api.DeleteService.assert_called_once_with(SERVICE)

    def test_status_and_wait_return_raw_fields(self):
        with scm_module.Scm() as controller:
            controller.create(COMMAND)
            expected = {"state": 1, "win32_exit": 1066, "service_exit": 71, "pid": 12345}
            self.assertEqual(controller.status(), expected)
            self.assertEqual(controller.wait_stopped(0), expected)
            self.query_states = [4, 3, 1]
            self.assertEqual(controller.wait_stopped(1), expected)
        self.assertEqual(self.sleep.call_count, 2)

    def test_unowned_start_and_status_are_refused(self):
        with scm_module.Scm() as controller:
            for action in (lambda: controller.start([]), controller.status):
                with self.assert_error("service_handle", 6):
                    action()
        self.api.StartServiceW.assert_not_called()
        self.api.QueryServiceStatusEx.assert_not_called()

    def test_status_failure_is_numeric(self):
        with scm_module.Scm() as controller:
            controller.create(COMMAND)
            self.api.QueryServiceStatusEx.side_effect = None
            self.api.QueryServiceStatusEx.return_value = 0
            self.last_error.return_value = 5
            with self.assert_error("QueryServiceStatusEx", 5):
                controller.status()

    def test_wait_timeout_and_invalid_bounds(self):
        self.query_states = [4]
        with scm_module.Scm() as controller:
            controller.create(COMMAND)
            with self.assert_error("wait_stopped", 1460):
                controller.wait_stopped(0.25)
            self.assertAlmostEqual(self.now, 0.25)
            for timeout in (-1, float("nan"), float("inf"), "secret", 10 ** 1000):
                with self.assert_error("wait_stopped", 87):
                    controller.wait_stopped(timeout)

    def test_remove_without_ownership_is_noop(self):
        scm_module.Scm().remove()
        self.loader.assert_not_called()
        self.assertEqual(self.api.mock_calls, [])

    def test_remove_stops_waits_deletes_closes_then_verifies(self):
        self.query_states = [4, 3, 1]
        with scm_module.Scm() as controller:
            controller.create(COMMAND)
            self.api.reset_mock()
            controller.remove()
            self.assertFalse(controller.created)
            self.assertFalse(controller._delete_pending)
            self.assertIsNone(controller._service)
            self.api.ControlService.assert_called_once()
            self.assertEqual(self.api.ControlService.call_args.args[:2], (SERVICE, 1))
            self.api.DeleteService.assert_called_once_with(SERVICE)
            names = [call[0] for call in self.api.mock_calls]
            self.assertEqual(names, [
                "QueryServiceStatusEx", "ControlService", "QueryServiceStatusEx",
                "QueryServiceStatusEx", "DeleteService", "CloseServiceHandle", "OpenServiceW",
            ])
            controller.remove()  # Idempotent, without another lookup/mutation.
            self.assertEqual(self.api.DeleteService.call_count, 1)

    def test_remove_waits_for_already_stop_pending_without_duplicate_stop(self):
        self.query_states = [3, 3, 1]
        with scm_module.Scm() as controller:
            controller.create(COMMAND)
            controller.remove()
        self.api.ControlService.assert_not_called()
        self.api.DeleteService.assert_called_once_with(SERVICE)

    def test_stop_race_with_already_inactive_service_is_verified(self):
        self.query_states = [4, 1]
        with scm_module.Scm() as controller:
            controller.create(COMMAND)
            self.api.ControlService.return_value = 0
            self.last_error.side_effect = [1062, 1060]
            controller.remove()
            self.assertFalse(controller.created)

    def test_remove_waits_until_start_pending_accepts_stop(self):
        self.query_states = [2, 2, 4, 1]
        with scm_module.Scm() as controller:
            controller.create(COMMAND)
            controller.remove()
            self.assertFalse(controller.created)
        self.api.ControlService.assert_called_once()
        self.api.DeleteService.assert_called_once()

    def test_stop_not_yet_accepted_is_retried_within_deadline(self):
        self.query_states = [4, 4, 1]
        with scm_module.Scm() as controller:
            controller.create(COMMAND)
            self.api.ControlService.side_effect = [0, 1]
            self.last_error.side_effect = [1061, 1060]
            controller.remove()
            self.assertFalse(controller.created)
        self.assertEqual(self.api.ControlService.call_count, 2)
        self.api.DeleteService.assert_called_once()

    def test_stop_failure_preserves_ownership_and_does_not_delete(self):
        self.query_states = [4]
        with scm_module.Scm() as controller:
            controller.create(COMMAND)
            self.api.ControlService.return_value = 0
            self.last_error.return_value = 5
            with self.assert_error("ControlService", 5):
                controller.remove()
            self.assertTrue(controller.created)
            self.assertFalse(controller._delete_pending)
            self.assertEqual(controller._service, SERVICE)
        self.api.DeleteService.assert_not_called()

    def test_stop_timeout_preserves_ownership_and_never_kills_process(self):
        self.query_states = [4, 3]
        with scm_module.Scm() as controller, mock.patch.object(scm_module, "_TIMEOUT", 0.2):
            controller.create(COMMAND)
            with self.assert_error("wait_stopped", 1460):
                controller.remove()
            self.assertTrue(controller.created)
            self.assertFalse(controller._delete_pending)
        self.api.DeleteService.assert_not_called()

    def test_delete_failure_preserves_handle_for_retry(self):
        with scm_module.Scm() as controller:
            controller.create(COMMAND)
            self.api.DeleteService.return_value = 0
            self.last_error.return_value = 5
            with self.assert_error("DeleteService", 5):
                controller.remove()
            self.assertTrue(controller.created)
            self.assertFalse(controller._delete_pending)
            self.assertEqual(controller._service, SERVICE)
            self.api.CloseServiceHandle.assert_not_called()
            self.api.DeleteService.return_value = 1
            self.last_error.return_value = 1060
            controller.remove()
            self.assertFalse(controller.created)

    def test_already_marked_delete_is_verified_not_treated_as_absence(self):
        with scm_module.Scm() as controller:
            controller.create(COMMAND)
            self.api.DeleteService.return_value = 0
            self.last_error.side_effect = [1072, 1072, 1060]
            controller.remove()
            self.assertFalse(controller.created)
            self.assertEqual(self.sleep.call_count, 1)

    def test_close_after_delete_failure_is_retriable_without_second_delete(self):
        with scm_module.Scm() as controller:
            controller.create(COMMAND)
            self.api.CloseServiceHandle.side_effect = [0, 1, 1]
            self.last_error.return_value = 5
            with self.assert_error("CloseServiceHandle", 5):
                controller.remove()
            self.assertTrue(controller.created)
            self.assertTrue(controller._delete_pending)
            self.assertEqual(controller._service, SERVICE)
            self.last_error.return_value = 1060
            controller.remove()
            self.assertFalse(controller.created)
        self.api.DeleteService.assert_called_once_with(SERVICE)

    def test_deletion_timeout_retains_flags_and_retry_never_deletes_replacement(self):
        with scm_module.Scm() as controller, mock.patch.object(scm_module, "_TIMEOUT", 0.2):
            controller.create(COMMAND)
            self.api.OpenServiceW.return_value = QUERY
            with self.assert_error("wait_deleted", 1460):
                controller.remove()
            self.assertTrue(controller.created)
            self.assertTrue(controller._delete_pending)
            self.assertIsNone(controller._service)
            with self.assert_error("wait_deleted", 1460):
                controller.remove()
            self.api.DeleteService.assert_called_once_with(SERVICE)
            self.api.ControlService.assert_not_called()
            self.api.OpenServiceW.return_value = None
            controller.remove()
            self.assertFalse(controller.created)
        self.api.DeleteService.assert_called_once_with(SERVICE)

    def test_deletion_verification_denial_is_not_success(self):
        with scm_module.Scm() as controller:
            controller.create(COMMAND)
            self.last_error.return_value = 5
            with self.assert_error("OpenServiceW", 5):
                controller.remove()
            self.assertTrue(controller.created)
            self.assertTrue(controller._delete_pending)
            self.assertIsNone(controller._service)

    def test_exit_attempts_both_closes_and_preserves_failed_handle(self):
        controller = scm_module.Scm()
        with self.assert_error("CloseServiceHandle", 5):
            with controller:
                controller.create(COMMAND)
                self.api.CloseServiceHandle.side_effect = [0, 1]
                self.last_error.return_value = 5
        self.assertTrue(controller.created)
        self.assertEqual(controller._service, SERVICE)
        self.assertIsNone(controller._manager)
        self.api.CloseServiceHandle.assert_has_calls([mock.call(SERVICE), mock.call(MANAGER)])
        self.api.DeleteService.assert_not_called()

    def test_exit_does_not_suppress_body_failure_or_delete(self):
        with self.assertRaisesRegex(ValueError, "body failure"):
            with scm_module.Scm() as controller:
                controller.create(COMMAND)
                raise ValueError("body failure")
        self.api.DeleteService.assert_not_called()
        self.assertTrue(controller.created)


class ServiceRuntimeTests(MockApiTest):
    def setUp(self):
        super().setUp()
        self.reports = []
        self.handler = None
        self.args = [scm_module.NAME, "--probe", "тест"]
        self.main_thread = None
        self.api.RegisterServiceCtrlHandlerExW.side_effect = self.register
        self.api.SetServiceStatus.side_effect = self.report
        self.api.StartServiceCtrlDispatcherW.side_effect = self.dispatch

    def tearDown(self):
        for name in ("OpenSCManagerW", "OpenServiceW", "CreateServiceW", "StartServiceW",
                     "QueryServiceStatusEx", "ControlService", "DeleteService", "CloseServiceHandle"):
            getattr(self.api, name).assert_not_called()
        super().tearDown()

    def register(self, name, handler, context):
        self.assertEqual(name, "PW_STORAGE_TEST_SERVICE")
        self.assertIsNone(context)
        self.assertIsInstance(handler, scm_module.HANDLER_EX)
        self.handler = handler
        return STATUS_HANDLE

    def report(self, handle, pointer):
        self.assertEqual(handle, STATUS_HANDLE)
        value = ctypes.cast(pointer, ctypes.POINTER(scm_module.SERVICE_STATUS)).contents
        self.reports.append({name: getattr(value, name) for name, _ in value._fields_})
        return 1

    def dispatch(self, table):
        self.assertEqual(table[0].lpServiceName, "PW_STORAGE_TEST_SERVICE")
        self.assertIsNone(table[1].lpServiceName)
        self.assertFalse(table[1].lpServiceProc)
        gc.collect()  # Callback references must survive until dispatcher returns.
        argv = (scm_module.LPWSTR * len(self.args))(*self.args) if self.args else None
        self.main_thread = threading.get_ident()
        table[0].lpServiceProc(len(self.args), argv)
        return 1

    def states(self):
        return [status["dwCurrentState"] for status in self.reports]

    def test_work_runs_on_service_main_thread_after_registration_and_running(self):
        def work(stop_event, args):
            self.assertEqual(threading.get_ident(), self.main_thread)
            self.assertIsInstance(stop_event, threading.Event)
            self.assertFalse(stop_event.is_set())
            self.assertEqual(args, ["--probe", "тест"])
            self.assertEqual(self.states(), [2, 4])
            return 0

        self.assertEqual(scm_module.run_service(work), 0)
        self.assertEqual(self.states(), [2, 4, 1])
        self.assertEqual([r["dwControlsAccepted"] for r in self.reports], [0, 1, 0])
        self.assertEqual([r["dwCheckPoint"] for r in self.reports], [1, 0, 0])
        self.assertEqual([r["dwWaitHint"] for r in self.reports], [30000, 0, 0])
        for report in self.reports:
            self.assertEqual(report["dwServiceType"], 0x10)
            self.assertEqual(report["dwWin32ExitCode"], 0)
            self.assertEqual(report["dwServiceSpecificExitCode"], 0)

    def test_stop_signals_event_and_pending_interrogate_is_noop(self):
        def work(stop_event, args):
            self.assertEqual(self.handler(4, 0, None, None), 0)
            self.assertEqual(self.handler(999, 0, None, None), 120)
            self.assertFalse(stop_event.is_set())
            self.assertEqual(self.states(), [2, 4])
            self.assertEqual(self.handler(1, 0, None, None), 0)
            self.assertTrue(stop_event.is_set())
            self.assertEqual(self.states(), [2, 4, 3])
            self.assertEqual(self.reports[-1]["dwControlsAccepted"], 0)
            self.assertEqual(self.reports[-1]["dwCheckPoint"], 1)
            self.assertEqual(self.reports[-1]["dwWaitHint"], 30000)
            self.assertEqual(self.handler(1, 0, None, None), 0)
            self.assertEqual(self.states(), [2, 4, 3])
            return 0

        self.assertEqual(scm_module.run_service(work), 0)
        self.assertEqual(self.states(), [2, 4, 3, 1])
        self.assertEqual(self.handler(1, 0, None, None), 0)
        self.assertEqual(self.handler(4, 0, None, None), 0)
        self.assertEqual(self.states(), [2, 4, 3, 1])

    def test_work_exit_codes_are_reported_without_truncation(self):
        for code in (71, 0xFFFFFFFF):
            with self.subTest(code=code):
                self.reports.clear()
                self.assertEqual(scm_module.run_service(lambda event, args: code), code)
                self.assertEqual(self.reports[-1]["dwWin32ExitCode"], 1066)
                self.assertEqual(self.reports[-1]["dwServiceSpecificExitCode"], code)

    def test_work_exceptions_do_not_leak_to_ctypes_stderr(self):
        for exception in (RuntimeError("secret details"), SystemExit("secret details")):
            with self.subTest(exception_type=type(exception).__name__):
                self.reports.clear()
                work = mock.Mock(side_effect=exception)
                output = io.StringIO()
                with contextlib.redirect_stderr(output), contextlib.redirect_stdout(output):
                    self.assertEqual(scm_module.run_service(work), 900)
                self.assertEqual(output.getvalue(), "")
                self.assertEqual(self.states(), [2, 4, 1])
                self.assertEqual(self.reports[-1]["dwWin32ExitCode"], 1066)
                self.assertEqual(self.reports[-1]["dwServiceSpecificExitCode"], 900)

    def test_invalid_work_exit_code_is_fixed_failure(self):
        for code in (None, True, -1, 0x100000000, "secret details"):
            with self.subTest(code_type=type(code).__name__):
                self.reports.clear()
                self.assertEqual(scm_module.run_service(lambda event, args: code), 900)
                self.assertEqual(self.reports[-1]["dwServiceSpecificExitCode"], 900)

    def test_registration_failure_does_not_run_work_or_report_invalid_handle(self):
        self.api.RegisterServiceCtrlHandlerExW.side_effect = None
        self.api.RegisterServiceCtrlHandlerExW.return_value = None
        self.last_error.return_value = 5
        work = mock.Mock()
        self.assertEqual(scm_module.run_service(work), 900)
        work.assert_not_called()
        self.assertEqual(self.reports, [])

    def test_pending_or_running_report_failure_stops_with_fixed_code(self):
        for failed_state in (2, 4):
            with self.subTest(state=failed_state):
                self.reports.clear()

                def report(handle, pointer):
                    self.report(handle, pointer)
                    return int(self.reports[-1]["dwCurrentState"] != failed_state)

                self.api.SetServiceStatus.side_effect = report
                work = mock.Mock()
                self.assertEqual(scm_module.run_service(work), 900)
                work.assert_not_called()
                self.assertEqual(self.reports[-1]["dwCurrentState"], 1)
                self.assertEqual(self.reports[-1]["dwServiceSpecificExitCode"], 900)

    def test_handler_failure_is_contained_and_changes_final_exit_code(self):
        def report(handle, pointer):
            self.report(handle, pointer)
            if self.reports[-1]["dwCurrentState"] == 3:
                raise RuntimeError("secret handler details")
            return 1

        self.api.SetServiceStatus.side_effect = report

        def work(stop_event, args):
            self.assertEqual(self.handler(1, 0, None, None), 900)
            self.assertTrue(stop_event.is_set())
            return 0

        output = io.StringIO()
        with contextlib.redirect_stderr(output), contextlib.redirect_stdout(output):
            self.assertEqual(scm_module.run_service(work), 900)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(self.reports[-1]["dwServiceSpecificExitCode"], 900)

    def test_stopped_report_is_never_retried_after_failure(self):
        def report(handle, pointer):
            self.report(handle, pointer)
            return int(self.reports[-1]["dwCurrentState"] != 1)

        self.api.SetServiceStatus.side_effect = report
        self.assertEqual(scm_module.run_service(lambda event, args: 0), 900)
        self.assertEqual(self.states(), [2, 4, 1])
        self.handler(1, 0, None, None)
        self.assertEqual(self.states(), [2, 4, 1])

    def test_dispatcher_failure_has_no_console_fallback(self):
        self.api.StartServiceCtrlDispatcherW.side_effect = None
        self.api.StartServiceCtrlDispatcherW.return_value = 0
        self.last_error.return_value = 1063
        work = mock.Mock()
        with self.assert_error("StartServiceCtrlDispatcherW", 1063):
            scm_module.run_service(work)
        work.assert_not_called()
        self.api.RegisterServiceCtrlHandlerExW.assert_not_called()

    def test_null_argv_passes_empty_list(self):
        self.args = []
        work = mock.Mock(return_value=0)
        self.assertEqual(scm_module.run_service(work), 0)
        self.assertEqual(work.call_args.args[1], [])

    def test_other_service_name_never_runs_work(self):
        self.args = ["OTHER_SERVICE", "--probe"]
        work = mock.Mock()
        self.assertEqual(scm_module.run_service(work), 900)
        work.assert_not_called()
        self.assertEqual(self.states(), [2, 1])
        self.assertEqual(self.reports[-1]["dwServiceSpecificExitCode"], 900)


if __name__ == "__main__":
    unittest.main()
