"""Файл хранилища на случайных тестовых значениях; совместимость проверяется настоящим KeePassXC."""

import errno
import io
import json
import os
import secrets
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest import mock

from pw_storage import vault as vault_module

from pw_storage.vault import (Kdf, UnsupportedFormat, Vault, VaultChanged, VaultCommitted, VaultError, WrongPassword,
                              file_version, parse_tags)

CLI = r"C:\Program Files\KeePassXC\keepassxc-cli.exe"
FAST = Kdf(memory_mb=16, iterations=1, parallelism=1)


def cli(*args, stdin=""):
    return subprocess.run([CLI, *args], input=stdin, capture_output=True, text=True, timeout=120)


def uid_of(vault, service, key):
    return next(r.uid for r in vault.rows() if r.service == service and r.key == key)


def header_seeds(path):
    data = Path(path).read_bytes()
    pos, fields = 12, {}
    while True:
        fid = data[pos]
        size = struct.unpack("<I", data[pos + 1:pos + 5])[0]
        fields[fid] = data[pos + 5:pos + 5 + size]
        pos += 5 + size
        if fid == 0:
            return fields[4], fields[7]


class VaultTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="pwtest"))
        self.path = self.dir / "vault.kdbx"
        self.password = secrets.token_urlsafe(24)
        self.value = secrets.token_urlsafe(24)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _vault(self):
        vault = Vault.create(self.path, self.password, FAST)
        vault.put("COMMON", "Погода", "API_KEY", secrets.token_urlsafe(8), "Общий ключ", ("COMMON",), shared=True)
        vault.put("DELTA", "Такси", "login", self.value, "Логин к кабинету Такси")
        vault.save()
        return vault

    def _directory_snapshot(self):
        return {path.name: ("link", os.readlink(path)) if path.is_symlink() else ("file", path.read_bytes())
                for path in self.dir.iterdir()}

    def test_readonly_open_leaves_directory_unchanged(self):
        original = self._vault()
        before = self._directory_snapshot()
        with mock.patch.object(vault_module, "_resume_transaction", side_effect=AssertionError("Unexpected recovery")) as resume:
            opened = Vault.open_readonly(self.path, self.password)
        resume.assert_not_called()
        self.assertTrue(opened.read_only)
        self.assertFalse(original.read_only)
        self.assertFalse(original.clone().read_only)
        self.assertTrue(opened.export_entries() == original.export_entries())
        self.assertTrue(opened.source_hash == original.source_hash)
        self.assertTrue(before == self._directory_snapshot(), "Directory changed during readonly open")

    def test_readonly_reads_encrypted_snapshot_under_writer(self):
        self._vault()
        before = self._directory_snapshot()
        writer, read, parse = vault_module._writer, Path.read_bytes, vault_module.PyKeePass
        locked = False

        @contextmanager
        def tracked_writer(path):
            nonlocal locked
            with writer(path):
                locked = True
                try:
                    yield
                finally:
                    locked = False

        def tracked_read(path):
            self.assertTrue(locked)
            return read(path)

        def tracked_parse(stream, **kwargs):
            self.assertIsInstance(stream, io.BytesIO)
            self.assertTrue(stream.getvalue() == before[self.path.name][1])
            return parse(stream, **kwargs)

        with mock.patch.object(vault_module, "_writer", side_effect=tracked_writer) as lock, \
                mock.patch.object(Path, "read_bytes", autospec=True, side_effect=tracked_read) as read_bytes, \
                mock.patch.object(vault_module, "PyKeePass", side_effect=tracked_parse) as parser:
            Vault.open_readonly(self.path, self.password)
        lock.assert_called_once_with(self.path)
        read_bytes.assert_called_once_with(self.path)
        parser.assert_called_once()
        self.assertTrue(before == self._directory_snapshot(), "Directory changed during snapshot read")

    def test_readonly_save_and_clone_save_refuse_before_io(self):
        self._vault()
        before = self._directory_snapshot()
        opened = Vault.open_readonly(self.path, self.password)
        for cloned, working in ((False, opened), (True, opened.clone())):
            with self.subTest(cloned=cloned):
                self.assertTrue(working.read_only)
                working.update_entry(uid_of(working, "Такси", "login"), value="TEST-memory-only")
                working.change_password("TEST-memory-only-password")
                if cloned:
                    working.path = self.dir / "missing" / "vault.kdbx"
                with ExitStack() as stack:
                    guards = [stack.enter_context(mock.patch.object(owner, name,
                              side_effect=AssertionError("Unexpected save IO"))) for owner, name in (
                                  (Path, "mkdir"), (Path, "open"), (Path, "read_bytes"), (Path, "write_bytes"),
                                  (vault_module, "_writer"), (vault_module, "_resume_transaction"),
                                  (vault_module, "_commit"), (vault_module, "_atomic_bytes"), (working._kp, "save"))]
                    with self.assertRaisesRegex(VaultError, "только для чтения"):
                        working.save(recovery_path=self.dir / "recovery.json", recovery_blob=b"TEST-recovery",
                                     retire=(self.dir / "remote.bin",), backup=False)
                    for guard in guards:
                        guard.assert_not_called()
        self.assertFalse((self.dir / "missing").exists())
        self.assertTrue(before == self._directory_snapshot(), "Readonly save changed directory")

    def test_readonly_refuses_active_transaction_without_recovery(self):
        vault = self._vault()
        rename = vault_module.os.rename

        def interrupted(source, target):
            rename(source, target)
            if Path(source) == self.path:
                raise OSError("synthetic interruption")

        with mock.patch.object(vault_module.os, "rename", side_effect=interrupted):
            with self.assertRaises(OSError):
                vault.save()
        self.assertFalse(self.path.exists())
        self.assertTrue(vault_module._transaction_path(self.path).exists())
        self.assertTrue(any(self.dir.glob("*.stage")))
        self.assertTrue(any(self.dir.glob("*.claim")))
        before = self._directory_snapshot()
        with mock.patch.object(vault_module, "_resume_transaction", side_effect=AssertionError("Unexpected recovery")) as resume, \
                mock.patch.object(Path, "read_bytes", side_effect=AssertionError("Unexpected read")) as read:
            with self.assertRaisesRegex(VaultError, "незавершённая"):
                Vault.open_readonly(self.path, self.password)
        resume.assert_not_called()
        read.assert_not_called()
        self.assertTrue(before == self._directory_snapshot(), "Active transaction changed")

    def test_readonly_refuses_dangling_transaction_untouched(self):
        self._vault()
        journal = vault_module._transaction_path(self.path)
        before = self._directory_snapshot()
        real_stat = Path.stat
        link_stat = os.stat_result((stat.S_IFLNK | 0o777, 0, 0, 1, 0, 0, 0, 0, 0, 0))

        # Моделируем dangling symlink без привилегии Windows на создание ссылок.
        def dangling_stat(path, *, follow_symlinks=True):
            if path == journal:
                if follow_symlinks:
                    raise FileNotFoundError(errno.ENOENT, "Synthetic dangling symlink")
                return link_stat
            return real_stat(path, follow_symlinks=follow_symlinks)

        with mock.patch.object(Path, "stat", autospec=True, side_effect=dangling_stat), \
                mock.patch.object(vault_module, "_resume_transaction", side_effect=AssertionError("Unexpected recovery")) as resume, \
                mock.patch.object(Path, "read_bytes", side_effect=AssertionError("Unexpected read")) as read, \
                mock.patch.object(Path, "unlink", side_effect=AssertionError("Unexpected unlink")) as unlink:
            self.assertTrue(journal.is_symlink())
            self.assertFalse(journal.exists())
            with self.assertRaisesRegex(VaultError, "незавершённая"):
                Vault.open_readonly(self.path, self.password)
            self.assertTrue(journal.is_symlink())
            self.assertFalse(journal.exists())
        resume.assert_not_called()
        read.assert_not_called()
        unlink.assert_not_called()
        self.assertTrue(before == self._directory_snapshot(), "Dangling transaction changed")

    def test_readonly_wrong_password_does_not_write(self):
        self._vault()
        before = self._directory_snapshot()
        with mock.patch.object(vault_module, "_resume_transaction", side_effect=AssertionError("Unexpected recovery")) as resume:
            with self.assertRaises(WrongPassword):
                Vault.open_readonly(self.path, "TEST-wrong-password")
        resume.assert_not_called()
        self.assertTrue(before == self._directory_snapshot(), "Wrong password changed directory")

    def test_readonly_bad_format_does_not_write(self):
        for data in (b"", b"not a database", vault_module.KDBX_SIGNATURE + struct.pack("<HH", 1, 3),
                     vault_module.KDBX_SIGNATURE + struct.pack("<HH", 1, 4)):
            with self.subTest(size=len(data)):
                self.path.write_bytes(data)
                before = self._directory_snapshot()
                with mock.patch.object(vault_module, "_resume_transaction", side_effect=AssertionError("Unexpected recovery")) as resume, \
                        mock.patch.object(vault_module, "PyKeePass", side_effect=AssertionError("Unexpected parse")) as parse:
                    with self.assertRaises(UnsupportedFormat):
                        Vault.open_readonly(self.path, self.password)
                resume.assert_not_called()
                parse.assert_not_called()
                self.assertTrue(before == self._directory_snapshot(), "Bad format changed directory")

    def test_create_uses_format4_argon2id(self):
        vault = self._vault()
        self.assertEqual(file_version(self.path), (4, 0))
        self.assertEqual(vault.kdf_algorithm, "argon2id")

    def test_default_kdf_is_the_agreed_one(self):
        self.assertEqual(Kdf(), Kdf(memory_mb=1024, iterations=4, parallelism=4))

    def test_create_refuses_to_overwrite(self):
        self._vault()
        before = self.path.read_bytes()
        with self.assertRaises(VaultError):
            Vault.create(self.path, "other-password", FAST)
        self.assertEqual(self.path.read_bytes(), before)

    def test_rows_have_no_values_and_no_system(self):
        vault = self._vault()
        vault.set_system_value("totp", "SECRET-TEST")
        vault.save()
        rows = Vault.open(self.path, self.password).rows()
        self.assertEqual(sorted(r.group for r in rows), ["COMMON", "DELTA"])
        self.assertNotIn(self.value, repr(rows))
        self.assertNotIn("SECRET-TEST", repr(rows))

    def test_value_and_system_value(self):
        vault = self._vault()
        vault.set_system_value("totp", "SECRET-TEST")
        vault.save()
        reopened = Vault.open(self.path, self.password)
        self.assertEqual(reopened.value(uid_of(reopened, "Такси", "login")), self.value)
        self.assertIsNone(reopened.value("00000000"))
        self.assertNotIn("totp", [r.service for r in reopened.rows()])
        self.assertEqual(reopened.system_value("totp"), "SECRET-TEST")

    def test_put_updates_existing(self):
        vault = self._vault()
        vault.put("DELTA", "Такси", "login", "new-value-test", "Новый комментарий")
        vault.save()
        reopened = Vault.open(self.path, self.password)
        self.assertEqual(reopened.value(uid_of(reopened, "Такси", "login")), "new-value-test")
        self.assertEqual(len(reopened.rows()), 2)

    def test_quotes_in_names_are_safe(self):
        vault = self._vault()
        vault.put("DELTA", 'Сервис "кавычки"', "ключ'1", "test-value-q", "Комментарий")
        vault.save()
        reopened = Vault.open(self.path, self.password)
        self.assertEqual(reopened.value(uid_of(reopened, 'Сервис "кавычки"', "ключ'1")), "test-value-q")

    def test_comment_is_required(self):
        vault = self._vault()
        for comment in ("", "   "):
            with self.assertRaises(VaultError):
                vault.put("DELTA", "X", "y", "z", comment)

    def test_system_and_all_are_not_projects(self):
        vault = self._vault()
        for group, projects in (("_SYSTEM", None), ("ALL", None), ("DELTA", ("ALL",)), ("DELTA", ())):
            with self.assertRaises(VaultError):
                vault.put(group, "X", "y", "z", "c", projects)

    def test_wrong_password(self):
        self._vault()
        with self.assertRaises(WrongPassword):
            Vault.open(self.path, "wrong-password")

    def test_refuses_format_31(self):
        old = self.dir / "old.kdbx"
        created = cli("db-create", "-p", str(old), stdin=self.password + "\n" + self.password + "\n")
        self.assertEqual(created.returncode, 0)
        self.assertEqual(file_version(old), (3, 1))
        with self.assertRaises(UnsupportedFormat):
            Vault.open(old, self.password)

    def test_refuses_not_kdbx(self):
        other = self.dir / "other.kdbx"
        other.write_bytes(b"not a database at all")
        with self.assertRaises(UnsupportedFormat):
            Vault.open(other, self.password)

    def test_seeds_change_on_save(self):
        vault = self._vault()
        before = header_seeds(self.path)
        vault.save()
        after = header_seeds(self.path)
        self.assertNotEqual(before[0], after[0])
        self.assertNotEqual(before[1], after[1])

    def test_outside_change_is_not_overwritten(self):
        vault = self._vault()
        outside = cli("add", "-u", "user", "-p", str(self.path), "outside",
                      stdin=self.password + "\n" + self.value + "\n")
        self.assertEqual(outside.returncode, 0)
        changed = self.path.read_bytes()
        vault.put("DELTA", "X", "y", "z", "c")
        with self.assertRaises(VaultChanged):
            vault.save()
        self.assertEqual(self.path.read_bytes(), changed)

    def test_save_keeps_backup_and_leaves_no_temp(self):
        vault = self._vault()
        vault.save()
        names = sorted(p.name for p in self.dir.iterdir())
        self.assertEqual(names, ["vault.kdbx", "vault.kdbx.bak"])

    def test_open_hashes_the_exact_parsed_snapshot(self):
        vault = self._vault()
        original = self.path.read_bytes()
        outside = vault.clone()
        outside.put("DELTA", "outside", "k", "TEST-outside", "External record")
        buffer = io.BytesIO()
        outside._kp.save(buffer)
        replacement = buffer.getvalue()
        parse = vault_module.PyKeePass

        def replaced(stream, **kwargs):
            self.path.write_bytes(replacement)
            return parse(stream, **kwargs)

        with mock.patch.object(vault_module, "PyKeePass", side_effect=replaced):
            opened = Vault.open(self.path, self.password)
        self.assertEqual(opened.source_hash, vault_module.hashlib.sha256(original).hexdigest())
        self.assertEqual(len(opened.rows()), 2)
        with self.assertRaises(VaultChanged):
            opened.save()
        self.assertEqual(self.path.read_bytes(), replacement)

    def test_external_save_during_serialization_is_not_overwritten(self):
        vault = self._vault()
        other = Vault.open(self.path, self.password)
        other.put("DELTA", "outside", "k", "TEST-outside", "External record")
        serialize = vault._kp.save
        saved = []

        def changed(*args, **kwargs):
            serialize(*args, **kwargs)
            other.save()
            saved.append(self.path.read_bytes())

        vault.put("DELTA", "local", "k", "TEST-local", "Local record")
        with mock.patch.object(vault._kp, "save", side_effect=changed):
            with self.assertRaises(VaultChanged):
                vault.save()
        self.assertEqual(self.path.read_bytes(), saved[0])
        self.assertFalse(vault_module._transaction_path(self.path).exists())

    def test_external_rename_race_preserves_external_bytes(self):
        vault = self._vault()
        external = vault.clone()
        external.put("DELTA", "outside", "k", "TEST-outside", "External record")
        buffer = io.BytesIO()
        external._kp.save(buffer)
        replacement = buffer.getvalue()
        rename = vault_module.os.rename
        raced = False

        def race(source, target):
            nonlocal raced
            if Path(source) == self.path and not raced:
                raced = True
                self.path.write_bytes(replacement)
            return rename(source, target)

        with mock.patch.object(vault_module.os, "rename", side_effect=race):
            with self.assertRaises(VaultChanged):
                vault.save()
        self.assertTrue(raced)
        self.assertEqual(self.path.read_bytes(), replacement)

    def test_new_target_race_does_not_overwrite_either_version(self):
        vault = self._vault()
        original = self.path.read_bytes()
        foreign = b"TEST-external-created-target"
        rename = vault_module.os.rename
        raced = False

        def race(source, target):
            nonlocal raced
            if Path(source).suffix == ".stage" and Path(target) == self.path and not raced:
                raced = True
                with self.path.open("xb") as stream:
                    stream.write(foreign)
            return rename(source, target)

        with mock.patch.object(vault_module.os, "rename", side_effect=race):
            with self.assertRaises(VaultChanged):
                vault.save()
        self.assertEqual(self.path.read_bytes(), foreign)
        self.assertTrue(any(p.read_bytes() == original for p in self.dir.glob("*.claim")))

    def test_two_writers_cannot_commit_stale_snapshot(self):
        first = self._vault()
        second = Vault.open(self.path, self.password)
        serialized = threading.Event()
        release = threading.Event()
        errors = []
        save = first._kp.save

        def blocked(*args, **kwargs):
            save(*args, **kwargs)
            serialized.set()
            if not release.wait(5):
                raise RuntimeError("test barrier timeout")

        def writer():
            try:
                first.save()
            except Exception as error:
                errors.append(type(error))

        with mock.patch.object(first._kp, "save", side_effect=blocked):
            thread = threading.Thread(target=writer)
            thread.start()
            try:
                self.assertTrue(serialized.wait(5))
                second.put("DELTA", "second", "k", "TEST-second", "Second writer")
                second.save()
                expected = self.path.read_bytes()
            finally:
                release.set()
                thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [VaultChanged])
        self.assertEqual(self.path.read_bytes(), expected)

    def test_reentrant_save_cannot_rebind_older_serialized_bytes(self):
        vault = self._vault()
        uid = uid_of(vault, "Такси", "login")
        save = vault._kp.save
        nested = False
        committed = []

        def raced(*args, **kwargs):
            nonlocal nested
            save(*args, **kwargs)
            if not nested:
                nested = True
                vault.update_entry(uid, value="TEST-newer-same-object")
                vault.save()
                committed.append(self.path.read_bytes())

        with mock.patch.object(vault._kp, "save", side_effect=raced):
            with self.assertRaises(VaultChanged):
                vault.save()
        self.assertEqual(self.path.read_bytes(), committed[0])
        self.assertEqual(Vault.open(self.path, self.password).value(uid), "TEST-newer-same-object")

    def test_exclusive_create_preserves_target_appearing_during_build(self):
        vault = Vault.new(self.path, self.password, FAST)
        save = vault._kp.save
        foreign = b"TEST-a-file-created-by-another-writer"

        def raced(*args, **kwargs):
            save(*args, **kwargs)
            self.path.write_bytes(foreign)

        with mock.patch.object(vault._kp, "save", side_effect=raced):
            with self.assertRaises(VaultChanged):
                vault.save()
        self.assertEqual(self.path.read_bytes(), foreign)

    def test_process_exit_resumes_password_pair_at_each_rename(self):
        script = """
import os
from pathlib import Path
from pw_storage import recovery, vault as module
from pw_storage.vault import Kdf, Vault, file_hash
path = Path(os.environ['PW_TEST_PATH'])
recovery_path = path.parent / 'recovery.json'
vault = Vault.new(path, 'TEST-initial-password', Kdf(16, 1, 1))
blob, part = recovery.issue('TEST-initial-password', 'Test question', 'TEST-answer-with-enough-characters', recovery.RecoveryKdf(16, 1, 1))
vault.set_system_value('recovery_part', part)
vault.save(recovery_path=recovery_path, recovery_blob=blob)
blob, part = recovery.issue('TEST-final-password', 'Test question', 'TEST-answer-with-enough-characters', recovery.RecoveryKdf(16, 1, 1))
vault.change_password('TEST-final-password')
vault.set_system_value('recovery_part', part)
rename = module.os.rename
count = 0
def exit_at_boundary(source, target):
    global count
    rename(source, target)
    count += 1
    if count == int(os.environ['PW_TEST_BOUNDARY']):
        os._exit(17)
module.os.rename = exit_at_boundary
vault.save(recovery_path=recovery_path, recovery_blob=blob, recovery_hash=file_hash(recovery_path), backup=False,
           retire=(path.with_name(path.name + '.bak'),))
"""
        from pw_storage import recovery

        for boundary in range(1, 5):
            with self.subTest(boundary=boundary):
                path = self.dir / str(boundary) / "vault.kdbx"
                result = subprocess.run([sys.executable, "-c", script], capture_output=True, timeout=30,
                                        env={**os.environ, "PW_TEST_PATH": str(path), "PW_TEST_BOUNDARY": str(boundary)})
                self.assertEqual(result.returncode, 17)
                vault = Vault.open(path, "TEST-final-password")
                blob = (path.parent / "recovery.json").read_bytes()
                self.assertEqual(recovery.recover(blob, "TEST-answer-with-enough-characters",
                                                  vault.system_value("recovery_part")), "TEST-final-password")
                self.assertEqual(sorted(p.name for p in path.parent.iterdir()), ["recovery.json", "vault.kdbx"])

    def test_damaged_transaction_cannot_delete_unrelated_file(self):
        vault = self._vault()
        install = vault_module._install_item
        count = 0

        def interrupted(folder, item):
            nonlocal count
            install(folder, item)
            count += 1
            if count == 1:
                raise OSError("synthetic interruption")

        with mock.patch.object(vault_module, "_install_item", side_effect=interrupted):
            with self.assertRaises(OSError):
                vault.save()
        journal = vault_module._transaction_path(self.path)
        operation = json.loads(journal.read_bytes())
        unrelated = self.dir / "unrelated.txt"
        unrelated.write_bytes(b"TEST-unrelated-content")
        operation["retire"] = [unrelated.name]
        journal.write_text(json.dumps(operation), encoding="utf-8")
        with self.assertRaises(VaultError):
            Vault.resume(self.path)
        self.assertEqual(unrelated.read_bytes(), b"TEST-unrelated-content")
        self.assertTrue(journal.exists())

    def test_clone_does_not_share_mutable_records(self):
        vault = self._vault()
        original_hash = vault.source_hash
        working = vault.clone()
        uid = uid_of(working, "Такси", "login")
        working.set_tags(uid, ("OTHER",), True)
        working.update_entry(uid, value="TEST-cloned-value")
        self.assertEqual(vault.source_hash, original_hash)
        self.assertEqual(next(r.projects for r in vault.rows() if r.uid == uid), ("DELTA",))
        self.assertEqual(vault.value(uid), self.value)
        self.assertNotEqual(working.value(uid), vault.value(uid))

    def test_attachment_by_uid_round_trips_root_nested_and_empty_bytes(self):
        vault = self._vault()
        data = b"TEST-JKS-" + secrets.token_bytes(512)
        vault.attach("DELTA", "Такси", "login", "release.jks", data)
        nested = vault._kp.add_group(vault._group("DELTA"), "Nested")
        nested_entry = vault._kp.add_entry(nested, "Nested token", "token", self.value,
                                          notes="Synthetic nested entry", tags=["DELTA"])
        nested_entry.add_attachment(vault._kp.add_binary(data), "nested.jks")
        root_entry = vault._kp.add_entry(vault._kp.root_group, "Root token", "token", self.value,
                                        notes="Synthetic root entry", tags=["DELTA"])
        root_entry.add_attachment(vault._kp.add_binary(b""), "empty.jks")
        ids = [vault_module.row_id(entry.uuid) for entry in
               (vault._entry("DELTA", "Такси", "login"), nested_entry, root_entry)]
        vault.save()
        reopened = Vault.open(self.path, self.password)
        before = {path.name: path.read_bytes() for path in self.dir.iterdir() if path.is_file()}
        for uid, name, expected in zip(ids, ("release.jks", "nested.jks", "empty.jks"), (data, data, b"")):
            with self.subTest(name=name):
                actual = reopened.attachment_by_uid(uid, name)
                self.assertIsInstance(actual, bytes)
                self.assertEqual(actual, expected)
                self.assertIsNone(reopened.attachment_by_uid(uid, "missing.jks"))
        self.assertIsNone(reopened.attachment_by_uid("00000000", "release.jks"))
        self.assertEqual(before, {path.name: path.read_bytes() for path in self.dir.iterdir() if path.is_file()})
        for raw in before.values():
            self.assertNotIn(data, raw)
            self.assertNotIn(self.value.encode(), raw)

    def test_attachment_by_uid_excludes_system_and_trash_subtrees(self):
        vault = self._vault()
        data = secrets.token_bytes(128)
        vault.set_system_value("synthetic", self.value)
        system = vault._entry("_SYSTEM", "synthetic", "")
        nested_system = vault._kp.add_group(system.group, "Nested")
        hidden = vault._kp.add_entry(nested_system, "Hidden", "token", self.value,
                                    notes="Synthetic hidden entry", tags=["DELTA", "ALL"])
        ordinary = vault._entry("DELTA", "Такси", "login")
        for entry in (system, hidden, ordinary):
            entry.add_attachment(vault._kp.add_binary(data), "release.jks")
        trashed_uid = vault_module.row_id(ordinary.uuid)
        vault.trash(trashed_uid)
        nested_trash = vault._kp.add_group(vault._trash_group(), "Nested")
        trash_child = vault._kp.add_entry(nested_trash, "Trash child", "token", self.value,
                                         notes="Synthetic trash entry", tags=["DELTA", "ALL"])
        trash_child.add_attachment(vault._kp.add_binary(data), "release.jks")
        hidden_ids = [vault_module.row_id(entry.uuid) for entry in (system, hidden, ordinary, trash_child)]
        vault.save()
        reopened = Vault.open(self.path, self.password)
        for uid in hidden_ids:
            with self.subTest(uid=uid):
                self.assertIsNone(reopened.attachment_by_uid(uid, "release.jks"))
                self.assertIsNone(reopened.value(uid))
        self.assertTrue(set(hidden_ids).isdisjoint(row.uid for row in reopened.rows()))

    def test_attachment_by_uid_refuses_duplicate_filename(self):
        vault = self._vault()
        entry = vault._entry("DELTA", "Такси", "login")
        uid = vault_module.row_id(entry.uuid)
        for data in (b"", secrets.token_bytes(128)):
            entry.add_attachment(vault._kp.add_binary(data), "duplicate.jks")
        vault.save()
        reopened = Vault.open(self.path, self.password)
        with self.assertRaises(VaultError):
            reopened.attachment_by_uid(uid, "duplicate.jks")
        self.assertIsNone(reopened.attachment_by_uid(uid, "missing.jks"))

    def test_attachment_stamp_covers_names_contents_and_not_order_or_binary_ids(self):
        vault = self._vault()
        uid = uid_of(vault, "Такси", "login")

        def stamp():
            return next(row.stamp for row in vault.rows() if row.uid == uid)

        bare = stamp()
        first, second = secrets.token_bytes(128), secrets.token_bytes(128)
        vault.attach("DELTA", "Такси", "login", "first.jks", first)
        one = stamp()
        self.assertNotEqual(one, bare)
        vault.attach("DELTA", "Такси", "login", "empty.jks", b"")
        original = stamp()
        self.assertNotEqual(original, one)
        entry = vault._entry_by_uid(uid)
        attachments = [(attachment.filename, attachment.data) for attachment in entry.attachments]
        for attachment in list(entry.attachments):
            entry.delete_attachment(attachment)
        for name, data in reversed(attachments):
            entry.add_attachment(vault._kp.add_binary(data), name)
        self.assertEqual(stamp(), original)
        vault.save()
        reopened = Vault.open(self.path, self.password)
        self.assertEqual(next(row.stamp for row in reopened.rows() if row.uid == uid), original)
        vault.attach("DELTA", "Такси", "login", "first.jks", second)
        changed_content = stamp()
        self.assertNotEqual(changed_content, original)
        entry = vault._entry_by_uid(uid)
        attachment = next(a for a in entry.attachments if a.filename == "first.jks")
        entry.delete_attachment(attachment)
        entry.add_attachment(vault._kp.add_binary(second), "renamed.jks")
        self.assertNotEqual(stamp(), changed_content)
        for attachment in list(entry.attachments):
            entry.delete_attachment(attachment)
        self.assertEqual(stamp(), bare)
        self.assertEqual(vault.value(uid), self.value)

    def test_attachment_free_digest_keeps_existing_value_hash(self):
        vault = self._vault()
        uid = uid_of(vault, "Такси", "login")
        for value in (self.value, ""):
            with self.subTest(empty=not value):
                vault._entry_by_uid(uid).password = value
                row = next(row for row in vault.rows() if row.uid == uid)
                expected = vault_module.hashlib.sha256(value.encode("utf-8")).hexdigest() if value else ""
                self.assertEqual(row.digest, expected)

    def test_value_update_clone_preserves_attachments_and_original_model(self):
        vault = self._vault()
        uid = uid_of(vault, "Такси", "login")
        data = secrets.token_bytes(128)
        vault.attach("DELTA", "Такси", "login", "release.jks", data)
        vault.attach("DELTA", "Такси", "login", "empty.jks", b"")
        vault.save()
        before = {entry.uid: entry for entry in vault.export_entries()}
        working = vault.clone()
        new_value = secrets.token_urlsafe(24)
        working.update_entry(uid, value=new_value)
        working.save()
        self.assertEqual({entry.uid: entry for entry in vault.export_entries()}, before)
        after = {entry.uid: entry for entry in Vault.open(self.path, self.password).export_entries()}
        self.assertEqual(set(after), set(before))
        for entry_uid, old in before.items():
            if entry_uid != uid:
                self.assertEqual(after[entry_uid], old)
            else:
                self.assertEqual(after[uid].value, new_value)
                for field in ("uid", "group", "service", "key", "comment", "projects", "shared", "attachments"):
                    self.assertEqual(getattr(after[uid], field), getattr(old, field))

    def test_current_cleanup_failure_advances_source_hash_only_after_commit(self):
        vault = self._vault()
        uid = uid_of(vault, "Такси", "login")
        before_hash = vault.source_hash
        new_value = secrets.token_urlsafe(24)
        vault.update_entry(uid, value=new_value)
        atomic = vault_module._atomic_bytes

        def fail_backup(path, data):
            if Path(path) == self.path.with_name(self.path.name + ".bak"):
                raise OSError("synthetic cleanup failure")
            return atomic(path, data)

        with mock.patch.object(vault_module, "_atomic_bytes", side_effect=fail_backup):
            with self.assertRaises(VaultCommitted) as raised:
                vault.save()
        self.assertNotEqual(vault.source_hash, before_hash)
        self.assertEqual(vault.source_hash, vault_module.file_hash(self.path))
        self.assertEqual(raised.exception.source_hash, vault.source_hash)
        self.assertTrue(vault_module._transaction_path(self.path).exists())
        self.assertEqual(Vault.open(self.path, self.password).value(uid), new_value)
        self.assertFalse(vault_module._transaction_path(self.path).exists())

    def test_prior_cleanup_failure_does_not_advance_current_source_hash(self):
        vault = self._vault()
        uid = uid_of(vault, "Такси", "login")
        working = vault.clone()
        prior = vault.clone()
        before_hash = working.source_hash
        prior_value, attempted_value = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        prior.update_entry(uid, value=prior_value)
        working.update_entry(uid, value=attempted_value)
        atomic = vault_module._atomic_bytes

        def fail_backup(path, data):
            if Path(path) == self.path.with_name(self.path.name + ".bak"):
                raise OSError("synthetic prior cleanup failure")
            return atomic(path, data)

        with mock.patch.object(vault_module, "_atomic_bytes", side_effect=fail_backup):
            with self.assertRaises(VaultCommitted):
                prior.save()
            committed_bytes = self.path.read_bytes()
            with self.assertRaises(VaultCommitted) as raised:
                working.save()
        self.assertEqual(working.source_hash, before_hash)
        self.assertNotEqual(raised.exception.source_hash, working.source_hash)
        self.assertEqual(self.path.read_bytes(), committed_bytes)
        self.assertEqual(vault.value(uid), self.value)
        self.assertEqual(Vault.open(self.path, self.password).value(uid), prior_value)

    def test_attachment_round_trip_and_keepassxc(self):
        vault = self._vault()
        data = secrets.token_bytes(5000)
        vault.attach("DELTA", "Такси", "login", "release.jks", data)
        vault.save()
        reopened = Vault.open(self.path, self.password)
        self.assertEqual(reopened.attachment("DELTA", "Такси", "login", "release.jks"), data)
        self.assertIsNone(reopened.attachment("DELTA", "Такси", "login", "нет.jks"))
        self.assertNotIn(data[:64], self.path.read_bytes())
        out = self.dir / "out.jks"
        exported = cli("attachment-export", str(self.path), "DELTA/Такси", "release.jks", str(out), stdin=self.password + "\n")
        self.assertEqual(exported.returncode, 0)
        self.assertEqual(out.read_bytes(), data)

    def test_attachment_is_replaced_by_name(self):
        vault = self._vault()
        vault.attach("DELTA", "Такси", "login", "release.jks", b"first")
        vault.attach("DELTA", "Такси", "login", "release.jks", b"second")
        vault.save()
        self.assertEqual(Vault.open(self.path, self.password).attachment("DELTA", "Такси", "login", "release.jks"), b"second")

    def test_attachment_needs_existing_row(self):
        vault = self._vault()
        with self.assertRaises(VaultError):
            vault.attach("DELTA", "Нет", "login", "x.jks", b"x")

    def test_keepassxc_reads_what_we_wrote(self):
        self._vault()
        shown = cli("show", "-s", "-a", "Password", str(self.path), "DELTA/Такси", stdin=self.password + "\n")
        self.assertEqual(shown.returncode, 0)
        self.assertEqual(shown.stdout.strip(), self.value)

    def test_we_read_what_keepassxc_wrote(self):
        self._vault()
        added = cli("add", "-u", "user", "-p", str(self.path), "DELTA/from-xc",
                    stdin=self.password + "\n" + self.value + "\n")
        self.assertEqual(added.returncode, 0)
        reopened = Vault.open(self.path, self.password)
        self.assertEqual(reopened.value(uid_of(reopened, "from-xc", "user")), self.value)
        self.assertEqual(file_version(self.path), (4, 0))
        self.assertEqual(reopened.kdf_algorithm, "argon2id")
        reopened.put("DELTA", "after-xc", "user", "test-value-x", "Комментарий")
        reopened.save()
        shown = cli("show", "-s", "-a", "Password", str(self.path), "DELTA/after-xc", stdin=self.password + "\n")
        self.assertEqual(shown.stdout.strip(), "test-value-x")

    # Т26: проекты и ALL — теги записи, владелец правит их в KeePassXC

    def test_rows_carry_projects_and_all(self):
        vault = self._vault()
        rows = {r.service: r for r in Vault.open(self.path, self.password).rows()}
        self.assertEqual((rows["Погода"].projects, rows["Погода"].shared), (("COMMON",), True))
        self.assertEqual((rows["Такси"].projects, rows["Такси"].shared), (("DELTA",), False))
        self.assertEqual(len(rows["Такси"].uid), 8)
        self.assertNotEqual(rows["Погода"].uid, rows["Такси"].uid)

    def test_uid_is_stable_and_opaque(self):
        vault = self._vault()
        before = uid_of(vault, "Такси", "login")
        vault.put("DELTA", "Такси", "login", "other-test-value", "Новый комментарий")
        vault.save()
        reopened = Vault.open(self.path, self.password)
        self.assertEqual(uid_of(reopened, "Такси", "login"), before)
        self.assertNotIn(before, "Такси login DELTA")

    def test_visibility(self):
        rows = {r.service: r for r in self._vault().rows()}
        self.assertTrue(rows["Такси"].visible_to("DELTA"))
        self.assertFalse(rows["Такси"].visible_to("FLEET"))
        self.assertTrue(rows["Погода"].visible_to("FLEET"))

    def test_stamp_follows_value_but_not_projects(self):
        vault = self._vault()
        row = next(r for r in vault.rows() if r.service == "Погода")
        self.assertTrue(vault.add_project(row.uid, "DELTA"))
        self.assertFalse(vault.add_project(row.uid, "DELTA"))
        after = next(r for r in vault.rows() if r.service == "Погода")
        self.assertEqual(after.projects, ("COMMON", "DELTA"))
        self.assertTrue(after.shared)
        self.assertEqual(after.stamp, row.stamp)
        vault.put("COMMON", "Погода", "API_KEY", "changed-test-value", "Общий ключ", ("COMMON", "DELTA"), shared=True)
        self.assertNotEqual(next(r for r in vault.rows() if r.service == "Погода").stamp, row.stamp)
        self.assertNotIn("changed-test-value", repr(vault.rows()))

    def test_add_project_refuses_bad_names(self):
        vault = self._vault()
        uid = uid_of(vault, "Погода", "API_KEY")
        for name in ("ALL", "_SYSTEM", "две части"):
            with self.assertRaises(VaultError):
                vault.add_project(uid, name)
        with self.assertRaises(VaultError):
            vault.add_project("00000000", "DELTA")

    def test_rename_key_keeps_row_and_value(self):
        vault = self._vault()
        before = next(r for r in vault.rows() if r.service == "Погода")
        value = vault.value(before.uid)
        vault.rename_key(before.uid, "API_TOKEN")
        vault.save()
        reopened = Vault.open(self.path, self.password)
        after = next(r for r in reopened.rows() if r.service == "Погода")
        self.assertEqual(after.uid, before.uid)
        self.assertEqual(after.key, "API_TOKEN")
        self.assertEqual(after.projects, before.projects)
        self.assertEqual(after.stamp, (before.uid, "Погода", "API_TOKEN", before.comment, before.digest))
        self.assertEqual(reopened.value(before.uid), value)

    def test_rename_key_refuses_duplicates_and_empty(self):
        vault = self._vault()
        uid = uid_of(vault, "Такси", "login")
        vault.put("DELTA", "Такси", "login2", "test-value-second", "Второй ключ")
        with self.assertRaises(VaultError):
            vault.rename_key(uid, "login2")
        with self.assertRaises(VaultError):
            vault.rename_key(uid, "")
        with self.assertRaises(VaultError):
            vault.rename_key("00000000", "login3")
        self.assertEqual(sorted(r.key for r in vault.rows() if r.service == "Такси"), ["login", "login2"])

    def test_parse_tags(self):
        self.assertEqual(parse_tags([" DELTA", "ALL", "", "COMMON ", "_SYSTEM", "плохое имя"]), (("COMMON", "DELTA"), True))
        self.assertEqual(parse_tags([]), ((), False))

    def test_keepassxc_reads_tags_we_wrote(self):
        self._vault()
        exported = cli("export", "-q", "--format", "xml", str(self.path), stdin=self.password + "\n")
        self.assertEqual(exported.returncode, 0)
        self.assertIn("<Tags>ALL,COMMON</Tags>", exported.stdout)
        self.assertIn("<Tags>DELTA</Tags>", exported.stdout)

    def test_entry_without_comment_from_keepassxc(self):
        self._vault()
        added = cli("add", "-u", "user", "-p", str(self.path), "DELTA/no-notes",
                    stdin=self.password + "\n" + self.value + "\n")
        self.assertEqual(added.returncode, 0)
        row = next(r for r in Vault.open(self.path, self.password).rows() if r.service == "no-notes")
        self.assertEqual((row.comment, row.projects), ("", ()))
        self.assertFalse(row.visible_to("DELTA"))


if __name__ == "__main__":
    unittest.main()
