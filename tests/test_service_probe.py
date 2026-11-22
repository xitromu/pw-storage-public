import io
import json
import tempfile
import threading
import unittest
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from unittest import mock

from tools import service_probe as probe
from tests.test_service_store import MemoryKey, SID
from pw_storage import service_store as store, winsecurity as ws
from pw_storage.vault import _atomic_bytes

RUN = "a" * 32


class ProbeTest(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.parent = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix="pw_probe_unit_")))
        self.root = self.parent / probe.DIRECTORY_NAME
        self.stack.enter_context(mock.patch.object(probe, "load_storage", return_value=(store, ws)))
        self.stack.enter_context(mock.patch.object(probe, "runtime_preflight"))
        self.stack.enter_context(mock.patch.object(ws, "require_admin"))
        self.stack.enter_context(mock.patch.object(ws, "common_app_data", return_value=self.parent))
        self.stack.enter_context(mock.patch.object(ws, "service_sid", return_value=SID))
        self.stack.enter_context(mock.patch.object(ws, "current_user_sid", return_value=SID))
        self.stack.enter_context(mock.patch.object(ws, "protect_directory"))
        self.stack.enter_context(mock.patch.object(ws, "create_service_directory"))
        self.stack.enter_context(mock.patch.object(ws, "publish_file", side_effect=lambda p, b, sid: _atomic_bytes(p, b)))
        self.stack.enter_context(mock.patch.dict(store.PROFILES, dict(store.PROFILES)))
        self.key = MemoryKey()
        self.key.delete = lambda: setattr(self.key, "created", False)
        self.stack.enter_context(mock.patch.object(store, "_key", return_value=self.key))
        self.create = self.stack.enter_context(mock.patch.object(probe, "create_root", side_effect=lambda p, sid, w: p.mkdir()))
        self.stage = self.stack.enter_context(mock.patch.object(probe, "stage_runtime"))
        self.scm = mock.Mock()
        self.scm.created = False
        self.scm.exists.return_value = False
        self.scm.create.side_effect = lambda command: setattr(self.scm, "created", True)
        self.scm.remove.side_effect = lambda: setattr(self.scm, "created", False)
        self.scm.__enter__ = mock.Mock(return_value=self.scm)
        self.scm.__exit__ = mock.Mock(return_value=False)
        probe.sys.path.insert(0, str(probe.REPO / "tools"))
        self.stack.enter_context(mock.patch("service_probe_scm.Scm", return_value=self.scm))
        self.connection = mock.Mock()
        self.connection.poll.return_value = True
        self.connection.recv_bytes.return_value = json.dumps({"kind": "negative", "payload": {
            "run_id": RUN, "checks": {"client_refused": True, "file_refused": True, "tpm_refused": True}}}).encode()
        self.output = self.stack.enter_context(mock.patch.object(probe.sys, "stderr", io.StringIO()))

    def result(self):
        frames = [json.loads(call.args[0]) for call in self.connection.send_bytes.call_args_list]
        return next(frame["payload"] for frame in frames if frame["kind"] == "result")

    def test_existing_service_is_not_modified(self):
        self.scm.exists.return_value = True
        self.assertEqual(probe.controller(RUN, self.connection), 1)
        self.scm.create.assert_not_called()
        self.scm.remove.assert_not_called()
        self.create.assert_not_called()
        self.assertEqual(self.result()["cleanup"], {})

    def test_existing_folder_is_not_deleted(self):
        self.root.mkdir()
        marker = self.root / "unrelated.txt"
        marker.write_text("keep")
        self.assertEqual(probe.controller(RUN, self.connection), 1)
        self.assertTrue(marker.exists())
        self.scm.create.assert_not_called()
        self.scm.remove.assert_not_called()

    def test_existing_key_is_not_reused_or_deleted(self):
        self.key.created = True
        self.assertEqual(probe.controller(RUN, self.connection), 1)
        self.assertTrue(self.key.created)
        self.scm.create.assert_not_called()

    def test_staging_failure_removes_only_owned_service_and_directory(self):
        self.stage.side_effect = RuntimeError("synthetic")
        self.assertEqual(probe.controller(RUN, self.connection), 1)
        self.scm.remove.assert_called_once()
        self.assertFalse(self.root.exists())
        result = self.result()
        self.assertEqual(result["stage"], "stage_runtime")
        self.assertTrue(result["cleanup"]["service_removed"])
        self.assertTrue(result["cleanup"]["directory_removed"])

    def test_cleanup_failure_keeps_directory_for_still_registered_service(self):
        self.stage.side_effect = RuntimeError("synthetic")
        self.scm.remove.side_effect = RuntimeError("synthetic stop failure")
        self.assertEqual(probe.controller(RUN, self.connection), 1)
        self.assertTrue(self.root.exists())
        self.assertIn("service_error", self.result()["cleanup"])
        self.assertIn("directory_error", self.result()["cleanup"])

    def test_full_controller_path_uses_only_synthetic_vault_and_cleans_up(self):
        def round_trip(scm, mode):
            client = store.ServiceClient(probe.NAME, "test")
            if mode == "revoked":
                with self.assertRaisesRegex(store.ServiceError, "отозвано"):
                    client.get("PROBE_TOKEN")
            else:
                prefix = "TEST1-" if mode == "first" else "TEST2-"
                self.assertTrue(client.get("PROBE_TOKEN").startswith(prefix))
                if mode == "updated":
                    self.assertFalse((self.root / "source").exists())
            return {"passed": True, "mode": mode}
        with mock.patch.object(probe, "service_round", side_effect=round_trip):
            self.assertEqual(probe.controller(RUN, self.connection), 0)
        self.assertFalse(self.key.created)
        self.assertFalse(self.root.exists())
        self.assertTrue(self.result()["passed"])
        self.assertTrue(all(self.result()["cleanup"].values()))
        command = self.scm.create.call_args.args[0]
        self.assertIn("-I -B -S", command)
        self.assertNotIn("secrets.env", command)
        self.assertNotIn("TEST1-", json.dumps(self.result()))

    def test_wrong_negative_response_still_cleans_resources(self):
        self.connection.recv_bytes.return_value = json.dumps({"kind": "negative", "payload": {"run_id": "wrong"}}).encode()
        with mock.patch.object(probe, "service_round", return_value={"passed": True}):
            self.assertEqual(probe.controller(RUN, self.connection), 1)
        self.assertFalse(self.key.created)
        self.assertFalse(self.root.exists())

    def test_ipc_timeout_still_cleans_resources(self):
        self.connection.poll.return_value = False
        with mock.patch.object(probe, "service_round", return_value={"passed": True}):
            self.assertEqual(probe.controller(RUN, self.connection), 1)
        self.assertFalse(self.root.exists())
        self.assertFalse(self.key.created)

    def test_worker_requires_correct_version_and_read_only_paths(self):
        client = mock.Mock()
        client.get.side_effect = ["TEST1-" + "a" * 64, store.ServiceError("not granted")]
        with mock.patch.object(store, "ServiceClient", return_value=client), \
                mock.patch.object(Path, "open", side_effect=PermissionError) as opened:
            self.assertEqual(probe.worker(threading.Event(), ["first"]), 0)
        self.assertEqual(opened.call_count, 3)
        client.get.side_effect = ["TEST1-" + "a" * 64]
        with mock.patch.object(store, "ServiceClient", return_value=client):
            self.assertEqual(probe.worker(threading.Event(), ["updated"]), 104)

    def test_worker_does_not_treat_any_error_as_successful_revocation(self):
        client = mock.Mock()
        with mock.patch.object(store, "ServiceClient", return_value=client):
            client.get.side_effect = store.ServiceError("missing key")
            self.assertEqual(probe.worker(threading.Event(), ["revoked"]), 103)
            client.get.side_effect = store.ServiceError("Разрешение службы отозвано")
            self.assertEqual(probe.worker(threading.Event(), ["revoked"]), 0)


class PreflightTest(unittest.TestCase):
    def test_default_command_has_no_side_effects(self):
        with mock.patch.object(probe, "run_probe") as run, mock.patch.object(probe, "elevate") as elevate, \
                redirect_stdout(io.StringIO()):
            self.assertEqual(probe.main([]), 0)
        run.assert_not_called()
        elevate.assert_not_called()

    def test_wrong_runtime_refused_before_elevation(self):
        with mock.patch.object(probe.sys, "version_info", (3, 12, 0)), self.assertRaises(probe.ProbeFailure):
            probe.runtime_preflight()
        with mock.patch.object(Path, "is_file", return_value=False), self.assertRaises(probe.ProbeFailure):
            probe.runtime_preflight()

    def test_pipe_name_is_local_and_run_id_is_strict(self):
        self.assertEqual(probe.pipe_name(RUN), r"\\.\pipe\PW_STORAGE_TEST_" + RUN)
        for run in ("", "../main", "a" * 31, "a" * 33):
            with self.assertRaises(probe.ProbeFailure):
                probe.pipe_name(run)

    def test_errors_do_not_echo_values(self):
        result = probe.error_record(RuntimeError("secret synthetic marker 0x80090010"))
        self.assertEqual(result, {"kind": "RuntimeError", "code": "0x80090010"})


if __name__ == "__main__":
    unittest.main()
