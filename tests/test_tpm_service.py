import ctypes
import unittest
from contextlib import ExitStack, nullcontext
from unittest import mock

from pw_storage import tpm
from pw_storage.tpm import TpmError, TpmKey, seal, unseal
from tests.test_service_store import MemoryKey, SID


class ServiceTpmTest(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.api = mock.Mock()
        self.api.NCryptOpenKey.side_effect = self.open_key
        self.api.NCryptCreatePersistedKey.side_effect = self.create_key
        self.api.NCryptSetProperty.return_value = 0
        self.api.NCryptGetProperty.side_effect = self.get_property
        self.api.NCryptFinalizeKey.return_value = 0
        self.api.NCryptDeleteKey.return_value = 0
        self.stack.enter_context(mock.patch.object(tpm, "_ncrypt", self.api))
        self.stack.enter_context(mock.patch.object(tpm, "_provider", side_effect=lambda: nullcontext(99)))
        self.descriptors = self.stack.enter_context(mock.patch(
            "pw_storage.winsecurity.security_descriptor", side_effect=lambda value: nullcontext((ctypes.c_void_p(77), 64))))
        self.key = TpmKey("PW_STORAGE_SERVICE_test_PW_TEST", machine=True, service_sid=SID)

    @staticmethod
    def open_key(provider, handle, name, spec, flags):
        handle._obj.value = 123
        return 0

    @staticmethod
    def create_key(provider, handle, algorithm, name, spec, flags):
        handle._obj.value = 123
        return 0

    @staticmethod
    def get_property(key, name, data, length, result, flags):
        data._obj.value = 0
        result._obj.value = ctypes.sizeof(data._obj)
        return 0

    def test_machine_scope_used_for_create_and_open_without_overwrite(self):
        self.key.create()
        self.assertEqual(self.api.NCryptCreatePersistedKey.call_args.args[-1], tpm.NCRYPT_MACHINE_KEY_FLAG)
        self.assertTrue(self.key.exists())
        self.assertEqual(self.api.NCryptOpenKey.call_args.args[-1], tpm.NCRYPT_MACHINE_KEY_FLAG)
        with self.key._opened():
            self.assertEqual(self.api.NCryptOpenKey.call_args.args[-1], tpm.NCRYPT_MACHINE_KEY_FLAG)

    def test_existing_user_key_behavior_unchanged(self):
        key = TpmKey("PW_STORAGE_TEST_OLD")
        key.create()
        self.assertEqual(self.api.NCryptCreatePersistedKey.call_args.args[-1], 0)
        self.assertTrue(key.exists())
        self.assertEqual(self.api.NCryptOpenKey.call_args.args[-1], 0)
        self.descriptors.assert_not_called()

    def test_acl_only_service_read_admin_system_full_and_admin_owner(self):
        self.key.create()
        sddl = self.descriptors.call_args.args[0]
        self.assertEqual(sddl, f"O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;{SID})")
        security_call = next(call for call in self.api.NCryptSetProperty.call_args_list
                             if call.args[1] == "Security Descr")
        self.assertTrue(security_call.args[-1] & tpm.DACL_SECURITY_INFORMATION)
        self.assertTrue(security_call.args[-1] & tpm.NCRYPT_PERSIST_FLAG)
        self.assertTrue(security_call.args[-1] & 0x1)
        self.api.NCryptDeleteKey.assert_not_called()

    def test_acl_failure_destroys_only_newly_created_key(self):
        self.api.NCryptSetProperty.side_effect = lambda handle, name, *args: 0x80090029 if name == "Security Descr" else 0
        with self.assertRaises(TpmError):
            self.key.create()
        self.api.NCryptDeleteKey.assert_called_once()
        self.api.NCryptFreeObject.assert_not_called()

    def test_existing_key_not_deleted_when_acl_update_fails(self):
        self.api.NCryptSetProperty.return_value = 0x80090029
        with self.assertRaises(TpmError):
            self.key.restrict_service_access()
        self.api.NCryptDeleteKey.assert_not_called()
        self.api.NCryptFreeObject.assert_called_once()

    def test_duplicate_key_not_deleted_or_overwritten(self):
        self.api.NCryptCreatePersistedKey.side_effect = None
        self.api.NCryptCreatePersistedKey.return_value = 0x8009000F
        with self.assertRaises(TpmError):
            self.key.create()
        self.api.NCryptDeleteKey.assert_not_called()
        self.api.NCryptSetProperty.assert_not_called()

    def test_exportable_existing_key_is_refused(self):
        def exportable(key, name, data, length, result, flags):
            data._obj.value = 1
            result._obj.value = ctypes.sizeof(data._obj)
            return 0
        self.api.NCryptGetProperty.side_effect = exportable
        with self.assertRaises(TpmError):
            self.key.restrict_service_access()
        self.descriptors.assert_not_called()
        self.api.NCryptDeleteKey.assert_not_called()

    def test_machine_key_cannot_be_created_without_virtual_service_sid(self):
        for sid in (None, "S-1-5-80-0", "S-1-5-18", "S-1-5-21-1-2-3-1001", SID + ";;;WD"):
            with self.subTest(sid=sid), self.assertRaises(ValueError):
                TpmKey("PW_TEST", machine=True, service_sid=sid)
        with self.assertRaises(ValueError):
            TpmKey("PW_TEST", pin="test", machine=True, service_sid=SID)
        with self.assertRaises(ValueError):
            TpmKey("PW_TEST", service_sid=SID)
        with self.assertRaises(TpmError):
            TpmKey("PW_TEST").restrict_service_access()


class EnvelopeTest(unittest.TestCase):
    def test_malformed_envelopes_fail_with_tpm_error(self):
        key = MemoryKey()
        key.create()
        for blob in (b"", b"PWT1", b"PWT1\0\0" + b"x" * 32, b"PWT1\xff\xffshort"):
            with self.subTest(size=len(blob)), self.assertRaises(TpmError):
                unseal(key, blob)
        blob = seal(key, b"synthetic value")
        with mock.patch.object(key, "decrypt", return_value=b"short"), self.assertRaises(TpmError):
            unseal(key, blob)


if __name__ == "__main__":
    unittest.main()
