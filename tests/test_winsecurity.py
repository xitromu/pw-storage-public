"""Win32 boundaries are mocked; no live ACL, service or TPM changes."""

import ctypes
import os
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from ctypes import POINTER, wintypes
from pathlib import Path
from unittest.mock import Mock, patch

from pw_storage import winsecurity as ws


SERVICE_SID = "S-1-5-80-1-2-3-4-4294967295"
USER_SID = "S-1-5-21-1-2-3-1001"
TEST_DIRECTORY = Path(r"C:\unit-test-only\private-directory")
POINTER_VALUE = 0x123456789ABC if ctypes.sizeof(ctypes.c_void_p) == 8 else 0x12345678


def put(output, value_type, value):
    ctypes.cast(output, POINTER(value_type))[0] = value


class WinApiTest(unittest.TestCase):
    def setUp(self):
        self.kernel = Mock(spec_set=[
            "GetCurrentProcess", "CloseHandle", "LocalFree", "GetFileAttributesW",
            "CreateDirectoryW", "CreateFileW", "GetFileInformationByHandleEx",
        ])
        self.advapi = Mock(spec_set=[
            "LookupAccountNameW", "ConvertSidToStringSidW", "OpenProcessToken",
            "GetTokenInformation", "ConvertStringSecurityDescriptorToSecurityDescriptorW",
            "GetSecurityDescriptorLength", "SetFileSecurityW", "GetSecurityInfo",
        ])
        self.shell = Mock(spec_set=["IsUserAnAdmin", "SHGetFolderPathW"])
        for name, library in (("_kernel32", self.kernel), ("_advapi32", self.advapi), ("_shell32", self.shell)):
            patcher = patch.object(ws, name, library)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.object(ws.ctypes, "get_last_error", return_value=5)
        self.last_error = patcher.start()
        self.addCleanup(patcher.stop)
        self.kernel.LocalFree.return_value = None
        self.kernel.CloseHandle.return_value = 1
        self.buffers = []

    def assert_no_api_calls(self):
        self.assertEqual(self.kernel.mock_calls, [])
        self.assertEqual(self.advapi.mock_calls, [])
        self.assertEqual(self.shell.mock_calls, [])

    def converted_sid(self, value=SERVICE_SID):
        text = ctypes.create_unicode_buffer(value)
        self.buffers.append(text)

        def convert(sid, output):
            self.assertIsInstance(sid, ctypes.c_void_p)
            self.assertTrue(sid.value)
            put(output, wintypes.LPWSTR, ctypes.cast(text, wintypes.LPWSTR))
            return 1

        self.advapi.ConvertSidToStringSidW.side_effect = convert
        return ctypes.addressof(text)

    def lookup(self, domain_size=11):
        def lookup(system, account, sid, sid_size, domain, domain_length, use):
            self.assertIsNone(system)
            self.assertTrue(account.startswith("NT SERVICE\\PW_"))
            if sid is None:
                self.assertEqual(ctypes.cast(sid_size, POINTER(wintypes.DWORD))[0], 0)
                self.assertIsNone(domain)
                self.assertEqual(ctypes.cast(domain_length, POINTER(wintypes.DWORD))[0], 0)
                put(sid_size, wintypes.DWORD, 32)
                put(domain_length, wintypes.DWORD, domain_size)
                self.last_error.return_value = 122
                return 0
            self.assertEqual(ctypes.sizeof(sid), 32)
            if domain_size:
                self.assertEqual(len(domain), domain_size)
                domain.value = "NT SERVICE"
            else:
                self.assertIsNone(domain)
            put(use, ctypes.c_int, 5)
            self.lookup_sid_address = ctypes.addressof(sid)
            return 1

        self.advapi.LookupAccountNameW.side_effect = lookup

    def token(self):
        self.kernel.GetCurrentProcess.return_value = ctypes.c_void_p(-1).value

        def open_token(process, access, output):
            self.assertEqual(process, ctypes.c_void_p(-1).value)
            self.assertEqual(access, 0x0008)
            put(output, wintypes.HANDLE, POINTER_VALUE)
            return 1

        def information(handle, info_class, buffer, size, required):
            self.assertEqual(handle.value, POINTER_VALUE)
            self.assertEqual(info_class, 1)
            if buffer is None:
                self.assertEqual(size, 0)
                put(required, wintypes.DWORD, ctypes.sizeof(ws._TOKEN_USER) + 32)
                self.last_error.return_value = 122
                return 0
            self.assertEqual(size, ctypes.sizeof(buffer))
            self.token_sid_address = ctypes.addressof(buffer) + ctypes.sizeof(ws._TOKEN_USER)
            user = ctypes.cast(buffer, POINTER(ws._TOKEN_USER)).contents
            user.User.Sid = self.token_sid_address
            user.User.Attributes = 0
            return 1

        self.advapi.OpenProcessToken.side_effect = open_token
        self.advapi.GetTokenInformation.side_effect = information

    def descriptor(self):
        def convert(sddl, revision, output, size):
            self.assertEqual(revision, 1)
            put(output, ctypes.c_void_p, POINTER_VALUE)
            put(size, wintypes.ULONG, 100)
            return 1

        self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.side_effect = convert
        self.advapi.GetSecurityDescriptorLength.return_value = 96

    def directory(self):
        self.shell.IsUserAnAdmin.return_value = 1
        self.kernel.GetFileAttributesW.return_value = 0x10
        self.advapi.SetFileSecurityW.return_value = 1
        self.kernel.CreateFileW.return_value = POINTER_VALUE
        self.kernel.CreateDirectoryW.return_value = 1

        def information(handle, info_class, buffer, size):
            self.assertEqual(info_class, 9)
            buffer._obj.attributes = 0x10
            return 1

        def security(handle, object_type, info, owner, group, dacl, sacl, descriptor):
            put(owner, ctypes.c_void_p, POINTER_VALUE + 100)
            put(descriptor, ctypes.c_void_p, POINTER_VALUE + 200)
            return 0

        self.kernel.GetFileInformationByHandleEx.side_effect = information
        self.advapi.GetSecurityInfo.side_effect = security
        self.converted_sid("S-1-5-32-544")
        self.descriptor()


class ServiceSidTest(WinApiTest):
    def test_invalid_name_before_any_api(self):
        for name in (None, 3, b"PW_test", "", "PW_", "pw_test", "PW_" + "a" * 61,
                     "PW_тест", "PW_a-b", "PW_a\\b", "PW_a/b", "PW_a\n", "PW_a\x00suffix",
                     "PW_a ", "NT SERVICE\\PW_test", "Administrator"):
            with self.subTest(name=name), self.assertRaises(ws.SecurityError) as caught:
                ws.service_sid(name)
            self.assertEqual(str(caught.exception), "Invalid service name.")
            self.assert_no_api_calls()

    def test_two_pass_lookup_and_local_free(self):
        self.lookup()
        allocated = self.converted_sid()
        self.assertEqual(ws.service_sid("PW_Pilot_01"), SERVICE_SID)
        self.assertEqual(self.advapi.LookupAccountNameW.call_count, 2)
        for call in self.advapi.LookupAccountNameW.call_args_list:
            self.assertEqual(call.args[:2], (None, "NT SERVICE\\PW_Pilot_01"))
        self.assertEqual(self.advapi.ConvertSidToStringSidW.call_args.args[0].value, self.lookup_sid_address)
        self.kernel.LocalFree.assert_called_once()
        self.assertEqual(self.kernel.LocalFree.call_args.args[0].value, allocated)
        self.advapi.OpenProcessToken.assert_not_called()

    def test_name_length_boundaries(self):
        self.lookup()
        self.converted_sid()
        for suffix in ("a", "_", "A0_" * 20):
            with self.subTest(length=len(suffix)):
                self.assertEqual(ws.service_sid("PW_" + suffix), SERVICE_SID)

    def test_empty_domain_buffer_is_supported(self):
        self.lookup(domain_size=0)
        self.converted_sid()
        self.assertEqual(ws.service_sid("PW_test"), SERVICE_SID)

    def test_lookup_failure_has_no_fallback_or_input_echo(self):
        self.advapi.LookupAccountNameW.return_value = 0
        self.last_error.return_value = 1332
        with self.assertRaisesRegex(ws.SecurityError, r"winerror 1332") as caught:
            ws.service_sid("PW_private_marker")
        self.assertNotIn("private_marker", str(caught.exception))
        self.advapi.LookupAccountNameW.assert_called_once()
        self.advapi.ConvertSidToStringSidW.assert_not_called()
        self.kernel.LocalFree.assert_not_called()

    def test_unexpected_sizing_success_is_rejected(self):
        self.advapi.LookupAccountNameW.return_value = 1
        with self.assertRaisesRegex(ws.SecurityError, r"winerror 13"):
            ws.service_sid("PW_test")
        self.advapi.LookupAccountNameW.assert_called_once()

    def test_zero_sid_size_is_rejected(self):
        self.advapi.LookupAccountNameW.return_value = 0
        self.last_error.return_value = 122
        with self.assertRaisesRegex(ws.SecurityError, r"winerror 13"):
            ws.service_sid("PW_test")
        self.advapi.LookupAccountNameW.assert_called_once()

    def test_second_lookup_failure_does_not_retry(self):
        self.lookup()
        lookup = self.advapi.LookupAccountNameW.side_effect

        def fail_second(*args):
            if args[2] is None:
                return lookup(*args)
            self.last_error.return_value = 122
            return 0

        self.advapi.LookupAccountNameW.side_effect = fail_second
        with self.assertRaisesRegex(ws.SecurityError, r"winerror 122"):
            ws.service_sid("PW_test")
        self.assertEqual(self.advapi.LookupAccountNameW.call_count, 2)
        self.advapi.ConvertSidToStringSidW.assert_not_called()

    def test_non_service_and_malformed_sids_are_rejected_and_freed(self):
        self.lookup()
        for sid in (USER_SID, "S-1-5-18", "S-1-5-80-0", "S-1-5-80-1-2-3-4",
                    "S-1-5-80-1-2-3-4-5-6", "S-1-5-80-1-2-3-4-4294967296",
                    "S-1-5-80-1-2-3-4-５", "S-1-5-80-1-2-3-4-5\n"):
            self.kernel.LocalFree.reset_mock()
            self.converted_sid(sid)
            with self.subTest(sid=sid), self.assertRaises(ws.SecurityError) as caught:
                ws.service_sid("PW_test")
            self.assertNotIn(sid, str(caught.exception))
            self.kernel.LocalFree.assert_called_once()

    def test_conversion_failure_is_safe(self):
        self.lookup()
        self.advapi.ConvertSidToStringSidW.return_value = 0

        def fail(*args):
            self.last_error.return_value = 1337
            return 0

        self.advapi.ConvertSidToStringSidW.side_effect = fail
        with self.assertRaisesRegex(ws.SecurityError, r"winerror 1337"):
            ws.service_sid("PW_private_marker")
        self.kernel.LocalFree.assert_not_called()

    def test_conversion_success_with_null_string_is_rejected(self):
        self.lookup()
        self.advapi.ConvertSidToStringSidW.return_value = 1
        with self.assertRaisesRegex(ws.SecurityError, r"winerror 13"):
            ws.service_sid("PW_test")
        self.kernel.LocalFree.assert_not_called()


class CurrentUserSidTest(WinApiTest):
    def assert_token_closed(self):
        self.kernel.CloseHandle.assert_called_once()
        self.assertEqual(self.kernel.CloseHandle.call_args.args[0].value, POINTER_VALUE)

    def test_queries_token_user_sid_pointer_and_closes_handle(self):
        self.token()
        allocated = self.converted_sid(USER_SID)
        self.assertEqual(ws.current_user_sid(), USER_SID)
        self.kernel.GetCurrentProcess.assert_called_once_with()
        self.advapi.OpenProcessToken.assert_called_once()
        self.assertEqual(self.advapi.GetTokenInformation.call_count, 2)
        self.assertEqual(self.advapi.ConvertSidToStringSidW.call_args.args[0].value, self.token_sid_address)
        self.assertEqual(self.kernel.LocalFree.call_args.args[0].value, allocated)
        self.assert_token_closed()
        self.advapi.LookupAccountNameW.assert_not_called()

    def test_open_failure_does_not_close_unowned_handle(self):
        self.kernel.GetCurrentProcess.return_value = ctypes.c_void_p(-1).value
        self.advapi.OpenProcessToken.return_value = 0
        with self.assertRaisesRegex(ws.SecurityError, r"winerror 5"):
            ws.current_user_sid()
        self.kernel.CloseHandle.assert_not_called()
        self.advapi.GetTokenInformation.assert_not_called()

    def test_probe_failure_closes_handle(self):
        self.token()
        self.advapi.GetTokenInformation.side_effect = None
        self.advapi.GetTokenInformation.return_value = 0
        with self.assertRaisesRegex(ws.SecurityError, r"winerror 5"):
            ws.current_user_sid()
        self.assert_token_closed()

    def test_unexpected_probe_success_closes_handle(self):
        self.token()
        self.advapi.GetTokenInformation.side_effect = None
        self.advapi.GetTokenInformation.return_value = 1
        with self.assertRaisesRegex(ws.SecurityError, r"winerror 13"):
            ws.current_user_sid()
        self.assert_token_closed()

    def test_short_probe_buffer_is_rejected(self):
        self.token()

        def short_buffer(handle, info_class, buffer, size, required):
            put(required, wintypes.DWORD, ctypes.sizeof(ws._TOKEN_USER) - 1)
            self.last_error.return_value = 122
            return 0

        self.advapi.GetTokenInformation.side_effect = short_buffer
        with self.assertRaisesRegex(ws.SecurityError, r"winerror 13"):
            ws.current_user_sid()
        self.assert_token_closed()
        self.advapi.GetTokenInformation.assert_called_once()

    def test_second_query_failure_closes_handle(self):
        self.token()
        query = self.advapi.GetTokenInformation.side_effect

        def fail_second(*args):
            if args[2] is None:
                return query(*args)
            self.last_error.return_value = 87
            return 0

        self.advapi.GetTokenInformation.side_effect = fail_second
        with self.assertRaisesRegex(ws.SecurityError, r"winerror 87"):
            ws.current_user_sid()
        self.assert_token_closed()
        self.advapi.ConvertSidToStringSidW.assert_not_called()

    def test_invalid_returned_sizes_close_handle(self):
        for returned in (0, ctypes.sizeof(ws._TOKEN_USER) - 1, 9999):
            self.token()
            self.kernel.CloseHandle.reset_mock()
            query = self.advapi.GetTokenInformation.side_effect

            def bad_size(*args):
                result = query(*args)
                if args[2] is not None:
                    put(args[4], wintypes.DWORD, returned)
                return result

            self.advapi.GetTokenInformation.side_effect = bad_size
            with self.subTest(size=returned), self.assertRaisesRegex(ws.SecurityError, r"winerror 13"):
                ws.current_user_sid()
            self.assert_token_closed()
        self.advapi.ConvertSidToStringSidW.assert_not_called()

    def test_null_sid_closes_handle(self):
        self.token()
        query = self.advapi.GetTokenInformation.side_effect

        def null_sid(*args):
            result = query(*args)
            if args[2] is not None:
                ctypes.cast(args[2], POINTER(ws._TOKEN_USER)).contents.User.Sid = None
            return result

        self.advapi.GetTokenInformation.side_effect = null_sid
        with self.assertRaisesRegex(ws.SecurityError, r"winerror 13"):
            ws.current_user_sid()
        self.assert_token_closed()
        self.advapi.ConvertSidToStringSidW.assert_not_called()

    def test_sid_conversion_failure_closes_handle(self):
        self.token()

        def fail(*args):
            self.last_error.return_value = 1337
            return 0

        self.advapi.ConvertSidToStringSidW.side_effect = fail
        with self.assertRaisesRegex(ws.SecurityError, r"winerror 1337"):
            ws.current_user_sid()
        self.assert_token_closed()
        self.kernel.LocalFree.assert_not_called()


class AdminTest(WinApiTest):
    def test_admin_returns_none(self):
        self.shell.IsUserAnAdmin.return_value = 1
        self.assertIsNone(ws.require_admin())
        self.shell.IsUserAnAdmin.assert_called_once_with()

    def test_non_admin_raises_without_elevation(self):
        self.shell.IsUserAnAdmin.return_value = 0
        with self.assertRaisesRegex(ws.SecurityError, "Administrator privileges"):
            ws.require_admin()
        self.assertEqual(len(self.shell.mock_calls), 1)
        self.assertEqual(self.kernel.mock_calls, [])
        self.assertEqual(self.advapi.mock_calls, [])


class DescriptorTest(WinApiTest):
    def test_yields_pointer_and_measured_size_then_frees(self):
        self.descriptor()
        with ws.security_descriptor("D:P(A;;FA;;;SY)") as (descriptor, size):
            self.assertIsInstance(descriptor, ctypes.c_void_p)
            self.assertEqual(descriptor.value, POINTER_VALUE)
            self.assertIs(type(size), int)
            self.assertEqual(size, 96)
            self.advapi.GetSecurityDescriptorLength.assert_called_once_with(descriptor)
            self.kernel.LocalFree.assert_not_called()
        self.kernel.LocalFree.assert_called_once_with(descriptor)

    def test_frees_when_body_raises(self):
        self.descriptor()
        with self.assertRaisesRegex(ValueError, "caller failure"):
            with ws.security_descriptor("D:P"):
                raise ValueError("caller failure")
        self.kernel.LocalFree.assert_called_once()

    def test_bad_sddl_rejected_before_api(self):
        for sddl in (None, 3, b"D:P", "", "D:P\x00private_marker"):
            with self.subTest(sddl=sddl), self.assertRaises(ws.SecurityError) as caught:
                with ws.security_descriptor(sddl):
                    self.fail("Invalid SDDL reached body")
            self.assertNotIn("private_marker", str(caught.exception))
            self.assert_no_api_calls()

    def test_failed_conversion_has_safe_numeric_error(self):
        self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.return_value = 0
        self.last_error.return_value = 1336
        with self.assertRaisesRegex(ws.SecurityError, r"winerror 1336") as caught:
            with ws.security_descriptor("private_sddl_marker"):
                self.fail("Failed conversion reached body")
        self.assertNotIn("private_sddl_marker", str(caught.exception))
        self.advapi.GetSecurityDescriptorLength.assert_not_called()
        self.kernel.LocalFree.assert_not_called()

    def test_null_success_is_rejected(self):
        self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.return_value = 1
        with self.assertRaisesRegex(ws.SecurityError, r"winerror 13"):
            with ws.security_descriptor("D:P"):
                self.fail("Null descriptor reached body")
        self.kernel.LocalFree.assert_not_called()

    def test_zero_length_frees_descriptor(self):
        self.descriptor()
        self.advapi.GetSecurityDescriptorLength.return_value = 0
        with self.assertRaisesRegex(ws.SecurityError, r"winerror 13"):
            with ws.security_descriptor("D:P"):
                self.fail("Zero length descriptor reached body")
        self.kernel.LocalFree.assert_called_once()

    def test_partial_allocation_is_freed_on_conversion_failure(self):
        self.descriptor()
        convert = self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.side_effect

        def fail(*args):
            convert(*args)
            return 0

        self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.side_effect = fail
        with self.assertRaisesRegex(ws.SecurityError, r"winerror 5"):
            with ws.security_descriptor("D:P"):
                self.fail("Failed conversion reached body")
        self.kernel.LocalFree.assert_called_once()


class CommonAppDataTest(WinApiTest):
    def test_shell_path_without_create_flag_or_filesystem_calls(self):
        def folder(window, folder_id, token, flags, buffer):
            self.assertIsNone(window)
            self.assertEqual(folder_id, 0x23)
            self.assertIsNone(token)
            self.assertEqual(flags, 0)
            self.assertEqual(len(buffer), 260)
            buffer.value = r"D:\Common Data\Общее"
            return 0

        self.shell.SHGetFolderPathW.side_effect = folder
        self.assertEqual(ws.common_app_data(), Path(r"D:\Common Data\Общее"))
        self.shell.SHGetFolderPathW.assert_called_once()
        self.assertEqual(self.kernel.mock_calls, [])
        self.assertEqual(self.advapi.mock_calls, [])

    def test_hresult_failure_is_numeric_and_not_stale_last_error(self):
        self.shell.SHGetFolderPathW.return_value = -2147024891
        self.last_error.return_value = 87
        with self.assertRaisesRegex(ws.SecurityError, r"winerror 5"):
            ws.common_app_data()
        self.last_error.assert_not_called()

    def test_non_win32_hresult_keeps_its_numeric_status(self):
        self.shell.SHGetFolderPathW.return_value = -2147467259
        with self.assertRaisesRegex(ws.SecurityError, r"HRESULT 2147500037"):
            ws.common_app_data()
        self.last_error.assert_not_called()

    def test_false_success_and_invalid_paths_are_rejected(self):
        for result, path in ((1, ""), (0, ""), (0, "relative"), (0, r"C:relative")):
            def folder(window, folder_id, token, flags, buffer):
                buffer.value = path
                return result

            self.shell.SHGetFolderPathW.side_effect = folder
            with self.subTest(result=result, path=path), self.assertRaises(ws.SecurityError):
                ws.common_app_data()


class ServiceSddlTest(unittest.TestCase):
    def test_package_folder_stays_read_only_for_the_service(self):
        self.assertIn("GRGX;;;S-1-5-80-1-2-3-4-5", ws.service_sddl("S-1-5-80-1-2-3-4-5"))

    def test_log_folder_grants_write_only_to_the_service(self):
        sddl = ws.service_sddl("S-1-5-80-1-2-3-4-5", writable=True)
        self.assertIn("GRGW;;;S-1-5-80-1-2-3-4-5", sddl)
        self.assertNotIn("GRGX", sddl)
        self.assertIn("(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", sddl)


class ProtectDirectoryTest(WinApiTest):
    def test_sets_only_exact_protected_dacl_once(self):
        self.directory()
        self.assertIsNone(ws.protect_directory(TEST_DIRECTORY, SERVICE_SID))
        self.shell.IsUserAnAdmin.assert_called_once_with()
        self.kernel.GetFileAttributesW.assert_called_once_with(str(TEST_DIRECTORY))
        conversion = self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.call_args
        self.assertEqual(conversion.args[0],
                         f"O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;{SERVICE_SID})")
        self.advapi.SetFileSecurityW.assert_called_once()
        path, flags, descriptor = self.advapi.SetFileSecurityW.call_args.args
        self.assertEqual(path, str(TEST_DIRECTORY))
        self.assertEqual(flags, 0x80000005)
        self.assertIsInstance(descriptor, ctypes.c_void_p)
        self.assertEqual(descriptor.value, POINTER_VALUE)
        self.assertEqual(self.kernel.LocalFree.call_count, 3)
        self.assertEqual(self.kernel.LocalFree.call_args.args[0].value, descriptor.value)
        self.kernel.CloseHandle.assert_called_once_with(POINTER_VALUE)
        self.assertEqual(self.kernel.CreateFileW.call_args.args[1], 0x20081)
        self.assertEqual(self.kernel.CreateFileW.call_args.args[2], 1)

    def test_invalid_sid_never_reaches_api(self):
        for sid in (None, b"S-1-5-80-1-2-3-4-5", USER_SID, "S-1-5-80-0",
                    "S-1-5-80-1-2-3-4-5)(A;;FA;;;WD)", "S-1-5-80-1-2-3-4-5\x00",
                    "S-1-5-80-1-2-3-4-5\n", "S-1-5-80-1-2-3-4-4294967296"):
            with self.subTest(sid=sid), self.assertRaises(ws.SecurityError):
                ws.protect_directory(TEST_DIRECTORY, sid)
            self.assert_no_api_calls()

    def test_invalid_path_never_reaches_api(self):
        for path in (None, str(TEST_DIRECTORY), Path("relative"), Path("C:relative"),
                     Path("C:/private\x00marker")):
            with self.subTest(path=path), self.assertRaises(ws.SecurityError) as caught:
                ws.protect_directory(path, SERVICE_SID)
            self.assertNotIn("marker", str(caught.exception))
            self.assert_no_api_calls()

    def test_non_admin_never_reaches_filesystem_or_conversion(self):
        self.shell.IsUserAnAdmin.return_value = 0
        with self.assertRaises(ws.SecurityError):
            ws.protect_directory(TEST_DIRECTORY, SERVICE_SID)
        self.assertEqual(self.kernel.mock_calls, [])
        self.assertEqual(self.advapi.mock_calls, [])

    def test_missing_directory_has_safe_numeric_error(self):
        self.directory()
        self.kernel.GetFileAttributesW.return_value = 0xFFFFFFFF
        self.last_error.return_value = 3
        with self.assertRaisesRegex(ws.SecurityError, r"winerror 3") as caught:
            ws.protect_directory(TEST_DIRECTORY, SERVICE_SID)
        self.assertNotIn(str(TEST_DIRECTORY), str(caught.exception))
        self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.assert_not_called()
        self.advapi.SetFileSecurityW.assert_not_called()

    def test_file_and_all_reparse_directories_are_rejected(self):
        self.directory()
        for attributes in (0, 0x20, 0x400, 0x410, 0x430):
            self.kernel.GetFileAttributesW.return_value = attributes
            with self.subTest(attributes=attributes), self.assertRaises(ws.SecurityError):
                ws.protect_directory(TEST_DIRECTORY, SERVICE_SID)
        self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.assert_not_called()
        self.advapi.SetFileSecurityW.assert_not_called()

    def test_descriptor_failure_never_sets_acl(self):
        self.directory()
        self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.side_effect = None
        self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.return_value = 0
        with self.assertRaisesRegex(ws.SecurityError, r"winerror 5"):
            ws.protect_directory(TEST_DIRECTORY, SERVICE_SID)
        self.advapi.SetFileSecurityW.assert_not_called()

    def test_set_failure_frees_descriptor_and_does_not_echo_inputs(self):
        self.directory()
        self.advapi.SetFileSecurityW.return_value = 0
        with self.assertRaisesRegex(ws.SecurityError, r"winerror 5") as caught:
            ws.protect_directory(TEST_DIRECTORY, SERVICE_SID)
        self.assertNotIn(str(TEST_DIRECTORY), str(caught.exception))
        self.assertNotIn(SERVICE_SID, str(caught.exception))
        self.advapi.SetFileSecurityW.assert_called_once()
        self.assertEqual(self.kernel.LocalFree.call_count, 3)
        self.kernel.CloseHandle.assert_called_once_with(POINTER_VALUE)

    def test_existing_user_owned_directory_is_not_adopted(self):
        self.directory()
        self.converted_sid(USER_SID)
        with self.assertRaises(ws.SecurityError):
            ws.protect_directory(TEST_DIRECTORY, SERVICE_SID)
        self.advapi.SetFileSecurityW.assert_not_called()
        self.kernel.CloseHandle.assert_called_once_with(POINTER_VALUE)

    def test_reparse_swap_between_path_check_and_open_is_refused(self):
        self.directory()
        def changed(handle, kind, buffer, size):
            buffer._obj.attributes = 0x410
            return 1
        self.kernel.GetFileInformationByHandleEx.side_effect = changed
        with self.assertRaises(ws.SecurityError):
            ws.protect_directory(TEST_DIRECTORY, SERVICE_SID)
        self.advapi.SetFileSecurityW.assert_not_called()
        self.kernel.CloseHandle.assert_called_once_with(POINTER_VALUE)

    def test_open_failure_does_not_close_invalid_handle(self):
        self.directory()
        self.kernel.CreateFileW.return_value = ctypes.c_void_p(-1).value
        with self.assertRaises(ws.SecurityError):
            ws.protect_directory(TEST_DIRECTORY, SERVICE_SID)
        self.kernel.CloseHandle.assert_not_called()
        self.advapi.SetFileSecurityW.assert_not_called()

    def test_create_directory_has_protected_acl_from_first_instant(self):
        self.directory()
        self.assertIsNone(ws.create_service_directory(TEST_DIRECTORY, SERVICE_SID))
        path, attributes = self.kernel.CreateDirectoryW.call_args.args
        self.assertEqual(path, str(TEST_DIRECTORY))
        self.assertFalse(attributes._obj.inherit)
        self.assertTrue(attributes._obj.descriptor)
        self.assertEqual(self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.call_count, 2)
        for call in self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.call_args_list:
            self.assertTrue(call.args[0].startswith("O:BAD:P"))
        self.advapi.SetFileSecurityW.assert_called_once()

    def test_creation_error_does_not_proceed_but_existing_directory_is_checked(self):
        self.directory()
        self.kernel.CreateDirectoryW.return_value = 0
        self.last_error.return_value = 5
        with self.assertRaises(ws.SecurityError):
            ws.create_service_directory(TEST_DIRECTORY, SERVICE_SID)
        self.kernel.CreateFileW.assert_not_called()
        self.last_error.return_value = 183
        ws.create_service_directory(TEST_DIRECTORY, SERVICE_SID)
        self.kernel.CreateFileW.assert_called_once()
        self.advapi.GetSecurityInfo.assert_called_once()


class PublishFileTest(WinApiTest):
    def setUp(self):
        super().setUp()
        self.directory()
        self.stream = Mock()
        self.stream.fileno.return_value = 17
        self.events = []
        self.stream.write.side_effect = lambda data: self.events.append("write")
        self.patchers = [
            patch.object(ws.msvcrt, "open_osfhandle", return_value=17),
            patch.object(ws.os, "fdopen"),
            patch.object(ws.os, "fsync"),
            patch.object(ws.os, "replace", side_effect=lambda *args: self.events.append("replace")),
            patch.object(Path, "unlink"),
        ]
        self.adopt, self.fdopen, self.fsync, self.replace, self.unlink = [p.start() for p in self.patchers]
        for p in self.patchers:
            self.addCleanup(p.stop)
        self.fdopen.return_value.__enter__.return_value = self.stream
        self.advapi.SetFileSecurityW.side_effect = lambda *args: self.events.append("publish") or 1
        self.path = TEST_DIRECTORY / "credentials.bin"

    def test_staging_is_admin_only_and_service_read_is_granted_after_replace(self):
        ws.publish_file(self.path, b"synthetic ciphertext", SERVICE_SID)
        descriptions = [c.args[0] for c in self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.call_args_list]
        self.assertEqual(descriptions[0], "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)")
        self.assertNotIn(SERVICE_SID, descriptions[0])
        self.assertIn(f"(A;;GR;;;{SERVICE_SID})", descriptions[1])
        self.assertEqual(self.events, ["write", "replace", "publish"])
        self.assertEqual(self.kernel.CreateFileW.call_args.args[4], 1)
        self.assertEqual(self.kernel.CreateFileW.call_args.args[2], 0)
        self.unlink.assert_not_called()
        self.fsync.assert_called_once_with(17)

    def test_replace_failure_never_grants_service_read(self):
        self.replace.side_effect = OSError("synthetic")
        with self.assertRaises(OSError):
            ws.publish_file(self.path, b"synthetic ciphertext", SERVICE_SID)
        self.advapi.SetFileSecurityW.assert_not_called()
        self.assertEqual(self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.call_count, 1)
        self.unlink.assert_called_once_with(missing_ok=True)

    def test_acl_failure_after_replace_reports_partial_commit_without_rollback(self):
        self.advapi.SetFileSecurityW.side_effect = None
        self.advapi.SetFileSecurityW.return_value = 0
        with self.assertRaises(ws.PublicationPending):
            ws.publish_file(self.path, b"synthetic ciphertext", SERVICE_SID)
        self.replace.assert_called_once()
        self.unlink.assert_not_called()

    def test_create_collision_does_not_remove_someone_elses_file(self):
        self.kernel.CreateFileW.return_value = ctypes.c_void_p(-1).value
        with self.assertRaises(ws.SecurityError):
            ws.publish_file(self.path, b"synthetic ciphertext", SERVICE_SID)
        self.unlink.assert_not_called()
        self.adopt.assert_not_called()
        self.replace.assert_not_called()

    def test_handle_adoption_failure_closes_handle_and_removes_own_staging(self):
        self.adopt.side_effect = OSError("synthetic")
        with self.assertRaises(OSError):
            ws.publish_file(self.path, b"synthetic ciphertext", SERVICE_SID)
        self.kernel.CloseHandle.assert_called_once_with(POINTER_VALUE)
        self.unlink.assert_called_once_with(missing_ok=True)
        self.replace.assert_not_called()


class NativePackageLockTest(unittest.TestCase):
    def test_directory_name_cannot_change_during_protection(self):
        with tempfile.TemporaryDirectory(prefix="pwservice_directory_") as tmp:
            directory = Path(tmp) / "package"
            moved = Path(tmp) / "moved"
            directory.mkdir()
            def attempted_replacement(path, flags, descriptor):
                with self.assertRaises(PermissionError):
                    os.rename(directory, moved)
                return 1
            with patch.object(ws, "require_admin"), \
                    patch.object(ws, "_sid_to_string", return_value="S-1-5-32-544"), \
                    patch.object(ws._advapi32, "SetFileSecurityW", side_effect=attempted_replacement) as update:
                ws.protect_directory(directory, SERVICE_SID)
            update.assert_called_once()
            os.rename(directory, moved)
            self.assertTrue(moved.is_dir())

    def test_real_windows_lock_serializes_reader_and_replacement(self):
        with tempfile.TemporaryDirectory(prefix="pwservice_read_") as tmp:
            path = Path(tmp) / "credentials.bin"
            replacement = Path(tmp) / "next.bin"
            lock = Path(tmp) / "access.lock"
            lock.touch()
            path.write_bytes(b"old synthetic ciphertext")
            replacement.write_bytes(b"new synthetic ciphertext")
            started = threading.Event()
            def swap():
                started.set()
                with ws.package_lock(lock):
                    os.replace(replacement, path)
            with ThreadPoolExecutor(max_workers=1) as pool:
                with ws.package_lock(lock):
                    with path.open("rb") as stream:
                        future = pool.submit(swap)
                        self.assertTrue(started.wait(5))
                        self.assertFalse(future.done())
                        self.assertEqual(stream.read(), b"old synthetic ciphertext")
                future.result(timeout=5)
            self.assertEqual(path.read_bytes(), b"new synthetic ciphertext")

    def test_lock_is_released_on_exception_and_missing_lock_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="pwservice_read_") as tmp:
            lock = Path(tmp) / "access.lock"
            with self.assertRaises(ws.SecurityError):
                with ws.package_lock(lock):
                    self.fail("Missing lock was accepted")
            lock.touch()
            with self.assertRaises(RuntimeError):
                with ws.package_lock(lock):
                    raise RuntimeError("synthetic")
            with ws.package_lock(lock):
                pass


class BindingTest(unittest.TestCase):
    def test_explicit_signatures(self):
        signatures = (
            (ws._kernel32.GetCurrentProcess, (), wintypes.HANDLE),
            (ws._kernel32.CloseHandle, (wintypes.HANDLE,), wintypes.BOOL),
            (ws._kernel32.LocalFree, (wintypes.HLOCAL,), wintypes.HLOCAL),
            (ws._kernel32.GetFileAttributesW, (wintypes.LPCWSTR,), wintypes.DWORD),
            (ws._advapi32.LookupAccountNameW,
             (wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPVOID, POINTER(wintypes.DWORD),
              wintypes.LPWSTR, POINTER(wintypes.DWORD), POINTER(ctypes.c_int)), wintypes.BOOL),
            (ws._advapi32.ConvertSidToStringSidW,
             (wintypes.LPVOID, POINTER(wintypes.LPWSTR)), wintypes.BOOL),
            (ws._advapi32.OpenProcessToken,
             (wintypes.HANDLE, wintypes.DWORD, POINTER(wintypes.HANDLE)), wintypes.BOOL),
            (ws._advapi32.GetTokenInformation,
             (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD, POINTER(wintypes.DWORD)),
             wintypes.BOOL),
            (ws._advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW,
             (wintypes.LPCWSTR, wintypes.DWORD, POINTER(wintypes.LPVOID), POINTER(wintypes.ULONG)),
             wintypes.BOOL),
            (ws._advapi32.GetSecurityDescriptorLength, (wintypes.LPVOID,), wintypes.DWORD),
            (ws._advapi32.SetFileSecurityW,
             (wintypes.LPCWSTR, wintypes.DWORD, wintypes.LPVOID), wintypes.BOOL),
            (ws._shell32.IsUserAnAdmin, (), wintypes.BOOL),
            (ws._shell32.SHGetFolderPathW,
             (wintypes.HWND, ctypes.c_int, wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR),
             ctypes.c_long),
        )
        for function, arguments, result in signatures:
            with self.subTest(function=function.__name__):
                self.assertEqual(function.argtypes, arguments)
                self.assertIs(function.restype, result)

    def test_token_user_uses_native_pointer_alignment(self):
        pointer_size = ctypes.sizeof(ctypes.c_void_p)
        self.assertEqual(ws._SID_AND_ATTRIBUTES.Sid.offset, 0)
        self.assertEqual(ws._SID_AND_ATTRIBUTES.Attributes.offset, pointer_size)
        self.assertEqual(ctypes.sizeof(ws._TOKEN_USER), 16 if pointer_size == 8 else 8)
        self.assertTrue(issubclass(ws.SecurityError, RuntimeError))


if __name__ == "__main__":
    unittest.main()
