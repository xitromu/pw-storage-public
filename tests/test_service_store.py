import io
import json
import os
import secrets
import tempfile
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from dataclasses import replace
from pathlib import Path
from unittest import mock

from Cryptodome.Cipher import AES

from pw_storage import service_store as store
from pw_storage.tpm import TpmError, seal, unseal
from pw_storage.vault import Kdf, Vault, _atomic_bytes

SID = "S-1-5-80-101-202-303-404-505"
OTHER_SID = "S-1-5-80-111-222-333-444-555"


class MemoryKey:
    def __init__(self):
        self.secret = secrets.token_bytes(32)
        self.created = False
        self.restricted = 0

    def exists(self):
        return self.created

    def create(self):
        self.created = True
        self.restricted += 1

    def restrict_service_access(self):
        self.restricted += 1

    def encrypt(self, data):
        cipher = AES.new(self.secret, AES.MODE_GCM)
        body, tag = cipher.encrypt_and_digest(data)
        return cipher.nonce + tag + body

    def decrypt(self, data):
        if not self.created:
            raise TpmError("Нет ключа")
        try:
            return AES.new(self.secret, AES.MODE_GCM, nonce=data[:16]).decrypt_and_verify(data[32:], data[16:32])
        except ValueError:
            raise TpmError("Чужой ключ") from None


class ServiceStoreTest(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix="pwservice_test_")))
        self.password = secrets.token_urlsafe(30)
        self.value = secrets.token_urlsafe(40)
        self.other_value = secrets.token_urlsafe(40)
        self.vault = Vault.create(self.root / "vault.kdbx", self.password, Kdf(8, 1, 1))
        self.vault.put("COMMON", "Прокси", "AUTH_TOKEN", self.value, "Прокси")
        self.vault.put("BETA", "Telegram", "TELEGRAM_BOT_TOKEN", self.other_value, "Бот")
        self.vault.save()
        rows = self.vault.rows()
        self.row = next(r for r in rows if r.group == "COMMON")
        self.other_row = next(r for r in rows if r.group == "BETA")
        self.binding = store.Binding("COMMON", self.row.uid, self.row.service, self.row.key, "PROXY_CREDENTIALS")
        self.spec = store.ServiceSpec("PW_PROXY_BOT", "test", (self.binding,))
        self.directory = self.root / "package"
        self.path = self.directory / "credentials.bin"
        self.key = MemoryKey()
        self.stack.enter_context(mock.patch.dict(store.PROFILES, {"test": replace(store.PROFILES["test"], data=self.root)}))
        self.admin = self.stack.enter_context(mock.patch.object(store.winsecurity, "require_admin"))
        self.identity = self.stack.enter_context(mock.patch.object(store.winsecurity, "current_user_sid", return_value=SID))
        self.sid = self.stack.enter_context(mock.patch.object(store.winsecurity, "service_sid", return_value=SID))
        self.protect = self.stack.enter_context(mock.patch.object(
            store.winsecurity, "create_service_directory", side_effect=lambda path, sid: path.mkdir(exist_ok=True)))
        self.stack.enter_context(mock.patch.object(store.winsecurity, "protect_directory"))
        self.stack.enter_context(mock.patch.object(store.winsecurity, "publish_file",
                                                  side_effect=lambda path, data, sid: _atomic_bytes(path, data)))
        self.stack.enter_context(mock.patch.object(store, "_location", return_value=self.directory))
        self.keys = self.stack.enter_context(mock.patch.object(store, "_key", return_value=self.key))

    def client(self, name="PW_PROXY_BOT", profile="test"):
        return store.ServiceClient(name, profile)

    def payload(self):
        return json.loads(unseal(self.key, self.path.read_bytes()))

    def put_payload(self, payload):
        self.path.write_bytes(seal(self.key, json.dumps(payload).encode()))

    def test_round_trip_only_selected_rows_and_ciphertext_on_disk(self):
        store.provision(self.spec, self.vault)
        self.assertTrue(self.client().get("PROXY_CREDENTIALS") == self.value)
        data = self.payload()
        self.assertEqual(set(data["values"]), {"PROXY_CREDENTIALS"})
        raw = self.path.read_bytes()
        self.assertNotIn(self.value.encode(), raw)
        self.assertNotIn(self.other_value.encode(), raw)
        self.assertNotIn(self.password.encode(), raw)
        self.assertNotIn(self.other_value, json.dumps(data))
        self.assertNotIn(self.password, json.dumps(data))
        self.protect.assert_called_once_with(self.directory, SID)
        self.keys.assert_called_with(self.spec.name, self.spec.profile, SID)

    def test_reopen_without_vault_or_broker(self):
        store.provision(self.spec, self.vault)
        with mock.patch.object(Vault, "open", side_effect=AssertionError("vault opened")), \
                mock.patch.object(Vault, "open_readonly", side_effect=AssertionError("vault opened")):
            first = self.client()
            self.assertTrue(first.get("PROXY_CREDENTIALS") == self.value)
            del first
            self.assertTrue(self.client().get("PROXY_CREDENTIALS") == self.value)

    def test_other_identity_refused_before_read_or_tpm(self):
        self.identity.return_value = OTHER_SID
        with mock.patch.object(store, "_read_payload") as read:
            with self.assertRaises(store.ServiceError):
                self.client().get("PROXY_CREDENTIALS")
        read.assert_not_called()
        self.keys.assert_not_called()

    def test_success_reports_only_key_metadata(self):
        store.provision(self.spec, self.vault)
        with redirect_stderr(io.StringIO()) as report:
            self.client().get("PROXY_CREDENTIALS")
        self.assertIn(self.spec.name, report.getvalue())
        self.assertIn(self.row.uid, report.getvalue())
        self.assertIn(self.row.key, report.getvalue())
        self.assertNotIn(self.value, report.getvalue())
        self.assertNotIn(self.password, report.getvalue())

    def test_unknown_alias_is_refused(self):
        store.provision(self.spec, self.vault)
        with self.assertRaises(store.ServiceError):
            self.client().get("TELEGRAM_BOT_TOKEN")

    def test_no_key_or_package_never_creates_key(self):
        with self.assertRaises(store.ServiceError):
            self.client().get("PROXY_CREDENTIALS")
        self.assertFalse(self.key.created)
        self.admin.assert_not_called()
        self.protect.assert_not_called()

    def test_missing_or_wrong_service_identity_is_sanitized(self):
        self.sid.side_effect = store.winsecurity.SecurityError(self.value)
        with self.assertRaises(store.ServiceError) as error:
            self.client().get("PROXY_CREDENTIALS")
        self.assertNotIn(self.value, str(error.exception))
        self.assertTrue(error.exception.__suppress_context__)

    def test_copied_bundle_wrong_name_or_profile_is_refused(self):
        store.provision(self.spec, self.vault)
        for name, profile in (("PW_TELEGRAM", "test"), ("PW_PROXY_BOT", "main")):
            with self.subTest(name=name, profile=profile), self.assertRaises(store.ServiceError):
                self.client(name, profile).get("PROXY_CREDENTIALS")

    def test_ciphertext_tampering_and_truncation_fail_closed(self):
        store.provision(self.spec, self.vault)
        original = self.path.read_bytes()
        corrupt = bytearray(original)
        corrupt[-1] ^= 1
        for raw in (b"", b"PWT1", original[:6], original[:-1], bytes(corrupt)):
            with self.subTest(length=len(raw)):
                self.path.write_bytes(raw)
                with self.assertRaises(store.ServiceError):
                    self.client().get("PROXY_CREDENTIALS")

    def test_other_machine_key_refused(self):
        store.provision(self.spec, self.vault)
        other = MemoryKey()
        other.create()
        self.keys.return_value = other
        with self.assertRaises(store.ServiceError):
            self.client().get("PROXY_CREDENTIALS")

    def test_payload_metadata_tampering_rejected_even_with_test_key(self):
        store.provision(self.spec, self.vault)
        original = self.payload()
        for field, value in (("sid", OTHER_SID), ("format", True), ("enabled", 1),
                             ("values", {"OTHER": "synthetic"}), ("bindings", [])):
            with self.subTest(field=field):
                self.put_payload({**original, field: value})
                with self.assertRaises(store.ServiceError):
                    self.client().get("PROXY_CREDENTIALS")

    def test_explicit_project_membership_required_even_for_shared_row(self):
        self.vault.set_tags(self.row.uid, ("BETA",), True)
        with mock.patch.object(self.vault, "value") as value:
            with self.assertRaises(store.ServiceError):
                store.provision(self.spec, self.vault)
        value.assert_not_called()
        self.keys.assert_not_called()
        self.assertFalse(self.directory.exists())

    def test_wrong_row_metadata_refused_before_any_values_are_read(self):
        wrong = store.Binding("BETA", self.other_row.uid, "Wrong", self.other_row.key, "BOT_TOKEN")
        spec = replace(self.spec, bindings=(self.binding, wrong))
        with mock.patch.object(self.vault, "value") as value:
            with self.assertRaises(store.ServiceError):
                store.provision(spec, self.vault)
        value.assert_not_called()
        self.assertFalse(self.directory.exists())

    def test_wrong_vault_profile_refused(self):
        spec = replace(self.spec, profile="main")
        with mock.patch.object(self.vault, "value") as value:
            with self.assertRaises(store.ServiceError):
                store.provision(spec, self.vault)
        value.assert_not_called()

    def test_no_admin_no_secret_read_or_persistent_change(self):
        self.admin.side_effect = store.winsecurity.SecurityError("Требуется администратор")
        with mock.patch.object(self.vault, "value") as value:
            with self.assertRaises(store.winsecurity.SecurityError):
                store.provision(self.spec, self.vault)
        value.assert_not_called()
        self.assertFalse(self.directory.exists())
        self.assertFalse(self.key.created)

    def test_failed_permissions_never_creates_key_or_package(self):
        self.protect.side_effect = store.winsecurity.SecurityError("Права")
        with self.assertRaises(store.winsecurity.SecurityError):
            store.provision(self.spec, self.vault)
        self.keys.assert_not_called()
        self.assertFalse(self.path.exists())

    def test_atomic_update_and_live_client_refresh(self):
        store.provision(self.spec, self.vault)
        client = self.client()
        self.assertTrue(client.get("PROXY_CREDENTIALS") == self.value)
        updated = secrets.token_urlsafe(40)
        self.vault.put("COMMON", "Прокси", "AUTH_TOKEN", updated, "Прокси")
        self.vault.save()
        store.provision(self.spec, self.vault)
        self.assertTrue(client.get("PROXY_CREDENTIALS") == updated)
        self.assertEqual(self.key.restricted, 2)
        self.assertEqual(sorted(p.name for p in self.directory.iterdir()), ["access.lock", "credentials.bin"])

    def test_failed_replace_preserves_previous_package(self):
        store.provision(self.spec, self.vault)
        before = self.path.read_bytes()
        with mock.patch("pw_storage.vault.os.replace", side_effect=OSError("synthetic")):
            with self.assertRaises(OSError):
                store.provision(self.spec, self.vault)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(sorted(p.name for p in self.directory.iterdir()), ["access.lock", "credentials.bin"])

    def test_stale_vault_preserves_previous_package(self):
        store.provision(self.spec, self.vault)
        before = self.path.read_bytes()
        with mock.patch.object(store, "_hash_or_none", return_value="changed"):
            with self.assertRaises(store.ServiceError):
                store.provision(self.spec, self.vault)
        self.assertEqual(self.path.read_bytes(), before)

    def test_revoke_does_not_need_main_vault_and_stops_new_reads(self):
        store.provision(self.spec, self.vault)
        client = self.client()
        old_value = client.get("PROXY_CREDENTIALS")
        with mock.patch.object(Vault, "open_readonly", side_effect=AssertionError("vault opened")):
            store.revoke(self.spec.name, self.spec.profile)
        with self.assertRaises(store.ServiceError):
            client.get("PROXY_CREDENTIALS")
        self.assertTrue(old_value == self.value)
        self.assertEqual(self.payload()["values"], {})
        self.assertFalse(self.payload()["enabled"])

    def test_removed_binding_is_not_retained(self):
        other = store.Binding("BETA", self.other_row.uid, self.other_row.service, self.other_row.key, "BOT_TOKEN")
        store.provision(replace(self.spec, bindings=(self.binding, other)), self.vault)
        self.assertTrue(self.client().get("BOT_TOKEN") == self.other_value)
        store.provision(self.spec, self.vault)
        with self.assertRaises(store.ServiceError):
            self.client().get("BOT_TOKEN")

    def test_cli_plan_never_reads_vault_or_creates_keys(self):
        manifest = self.root / "service.json"
        manifest.write_text(json.dumps({"name": self.spec.name, "profile": "test", "bindings": [
            {"project": "COMMON", "row": self.row.uid, "service": "Прокси", "key": "AUTH_TOKEN",
             "alias": "PROXY_CREDENTIALS"}]}))
        with mock.patch.object(Vault, "open_readonly") as opened, redirect_stdout(io.StringIO()) as output:
            self.assertEqual(store.main(["provision", str(manifest)]), 0)
            self.assertEqual(store.main(["revoke", "PW_PROXY_BOT", "--profile", "test"]), 0)
        opened.assert_not_called()
        self.admin.assert_not_called()
        self.sid.assert_not_called()
        self.keys.assert_not_called()
        self.assertNotIn(self.value, output.getvalue())

    def test_cli_apply_refuses_noninteractive_password_input(self):
        manifest = self.root / "service.json"
        manifest.write_text(json.dumps({"name": self.spec.name, "profile": "test", "bindings": [
            {"project": "COMMON", "row": self.row.uid, "service": "Прокси", "key": "AUTH_TOKEN",
             "alias": "PROXY_CREDENTIALS"}]}))
        with mock.patch.object(store.sys.stdin, "isatty", return_value=False), \
                mock.patch.object(Vault, "open_readonly") as opened, \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(store.main(["provision", str(manifest), "--apply"]), 1)
        opened.assert_not_called()
        self.keys.assert_not_called()

    def test_cli_corrupt_vault_error_is_sanitized(self):
        from pykeepass.exceptions import HeaderChecksumError
        with mock.patch.object(store.ServiceSpec, "read", return_value=self.spec), \
                mock.patch.object(store.sys.stdin, "isatty", return_value=True), \
                mock.patch("builtins.input", return_value=self.spec.name), \
                mock.patch.object(store.getpass, "getpass", return_value=self.password), \
                mock.patch.object(Vault, "open_readonly", side_effect=HeaderChecksumError(self.value)), \
                redirect_stdout(io.StringIO()) as output, redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(store.main(["provision", "unused.json", "--apply"]), 1)
        self.assertNotIn(self.value, output.getvalue() + errors.getvalue())
        self.assertNotIn("Traceback", errors.getvalue())
        self.keys.assert_not_called()

    def test_cli_reports_incomplete_publication_distinctly(self):
        with mock.patch.object(store, "revoke", side_effect=store.winsecurity.PublicationPending("synthetic")), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(store.main(["revoke", "PW_PROXY_BOT", "--profile", "test", "--apply"]), 1)
        self.assertIn("Пакет заменён", errors.getvalue())

    def test_objects_do_not_cache_secret_values(self):
        store.provision(self.spec, self.vault)
        client = self.client()
        client.get("PROXY_CREDENTIALS")
        for item in (client, vars(client), self.spec):
            self.assertNotIn(self.value, repr(item))


class ValidationTest(unittest.TestCase):
    def test_invalid_bindings(self):
        binding = store.Binding("COMMON", "a0000001", "Прокси", "key", "ALIAS")
        for field, value in (("project", "ALL"), ("project", "_SYSTEM"), ("row", "*"),
                             ("alias", "../key"), ("key", "\nvalue"), ("service", "")):
            with self.subTest(field=field, value=value), self.assertRaises(store.ServiceError):
                replace(binding, **{field: value})
        for name in ("", "..", "PW_../x", "Spooler", "PW_x\0suffix"):
            with self.subTest(name=name), self.assertRaises(store.ServiceError):
                store.ServiceClient(name)
        with self.assertRaises(store.ServiceError):
            store.ServiceSpec("PW_TEST", "test", (binding, binding))
        with self.assertRaises(store.ServiceError):
            store.ServiceSpec("PW_TEST", "test", ())

    def test_manifest_does_not_accept_values_or_credential_fields(self):
        with tempfile.TemporaryDirectory(prefix="pwservice_manifest_") as tmp:
            path = Path(tmp) / "manifest.json"
            for content in ({"name": "PW_TEST", "profile": "test", "bindings": [], "password": "synthetic"},
                            [], {"name": "PW_TEST", "profile": "test", "bindings": None}):
                path.write_text(json.dumps(content))
                with self.assertRaises(store.ServiceError):
                    store.ServiceSpec.read(path)

    def test_deep_manifest_returns_controlled_failure(self):
        with tempfile.TemporaryDirectory(prefix="pwservice_manifest_") as tmp:
            path = Path(tmp) / "manifest.json"
            path.write_text("[" * 2000 + "0" + "]" * 2000)
            with self.assertRaises(store.ServiceError):
                store.ServiceSpec.read(path)
            with redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(store.main(["provision", str(path)]), 1)
            self.assertNotIn("Traceback", errors.getvalue())

    def test_no_links_detects_parent_reparse_point(self):
        with mock.patch.object(Path, "lstat") as lstat:
            lstat.return_value.st_file_attributes = 0x400
            with self.assertRaises(store.ServiceError):
                store._no_links(Path("C:/ProgramData/PW_STORAGE_SERVICE_test_PW_TEST"))


if __name__ == "__main__":
    unittest.main()
