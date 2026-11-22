"""Выгрузка на флэшку: каталог, архив, доверенные носители, часть ключа в хранилище. Носитель — временная папка."""

import io
import json
import shutil
import tempfile
import time
import tkinter as tk
import unittest
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from unittest import mock

import pyzipper

from pw_storage import admin, export
from pw_storage.config import RECOVERY_ENTRY, SYSTEM_SCOPE, Profile
from pw_storage.export import ExportError, Volume
from pw_storage.recovery import RecoveryKdf
from pw_storage.second_factor import new_totp_secret
from pw_storage.vault import Kdf, TRASH_GROUP_PROPERTY, Vault, row_id
from pw_storage.window import apply_style
from tests.test_catalog import FakeTpm

FAST = Kdf(memory_mb=16, iterations=1, parallelism=1)
PASSWORD = "тестовый-пароль-123"
ARCHIVE = "длинная тестовая фраза архива"
WHEN = datetime(2026, 11, 4, 18, 30)


class ExportCase(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="pwtest"))
        self.drive = self.dir / "flash"
        self.drive.mkdir()
        self.volume = Volume(str(self.drive) + "\\", "1A2B3C4D", "КОПИИ", "съёмный")
        self.settings = self.dir / "settings.json"
        self.settings.write_text(json.dumps({"telegram": True}), encoding="utf-8")
        vault = Vault.create(self.dir / "vault.kdbx", PASSWORD, FAST)
        vault.put("DELTA", "Такси", "login", "TEST-login-1", "Логин Такси", ("DELTA",))
        vault.put("DELTA", "Android", "keystore", "TEST-store\nвторая строка", "Подпись DELTA", ("DELTA",))
        vault.attach("DELTA", "Android", "keystore", "delta-release.jks", b"\x00TESTJKS")
        vault.put("COMMON", "GitHub", "codes", "TEST-code-1\nTEST-code-2", "Коды GitHub", ("COMMON",))
        vault.set_tags(next(r.uid for r in vault.rows() if r.key == "codes"), (), False)
        vault.set_system_value("totp", "TESTTOTPSECRET")
        vault.set_system_value(RECOVERY_ENTRY, "TEST-PART-1234")
        vault.save()
        self.vault = Vault.open(self.dir / "vault.kdbx", PASSWORD)
        patch = mock.patch.object(export, "system_roots", lambda: {"C:\\"} - {self.volume.root.upper()})
        patch.start()
        self.addCleanup(patch.stop)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def read(self, path, password=ARCHIVE):
        with pyzipper.AESZipFile(path) as z:
            z.setpassword(password.encode("utf-8"))
            return {name: z.read(name) for name in z.namelist()}

    def assert_json_values(self, data, entries):
        text = self.read(io.BytesIO(data))["PW_STORAGE/catalog.txt"].decode("utf-8")
        values = {}
        uid = None
        for line in text.split("\n"):
            if line.startswith("["):
                uid = line.split("]", 1)[0][1:]
            if line.startswith("  Значение (JSON): "):
                self.assertNotIn(uid, values, "ровно одно точное значение на запись")
                values[uid] = json.loads(line.removeprefix("  Значение (JSON): "))
        self.assertEqual(values, {e.uid: e.value for e in entries})


class CatalogTest(ExportCase):
    def test_catalog_has_everything_but_system_secrets(self):
        text = export.catalog_text(self.vault.export_entries(), self.vault.system_value(RECOVERY_ENTRY), WHEN, True)
        self.assertIn("TEST-PART-1234", text)
        self.assertIn("TEST-login-1", text)
        self.assertIn("TEST-code-2", text, "многострочное значение целиком")
        self.assertIn("Проекты: нет; ALL: нет", text)
        self.assertIn("Вложение: PW_STORAGE/DELTA/delta-release.jks", text)
        self.assertNotIn("TESTTOTPSECRET", text, "ключ аутентификатора не выгружается")
        self.assertIn("(ТЕСТ)", text)

    def test_missing_part_is_explained(self):
        text = export.catalog_text([], None, WHEN, False)
        self.assertIn("admin reissue", text)

    def test_entry_repr_hides_value(self):
        entry = self.vault.export_entries()[0]
        self.assertNotIn("TEST-", repr(entry))

    def test_catalog_trash_paths_without_mapping(self):
        entry = next(e for e in self.vault.export_entries() if e.attachments)
        text = export.catalog_text([], None, WHEN, False, [entry])
        self.assertIn("=== КОРЗИНА:", text)
        self.assertIn("Вложение: PW_STORAGE/_КОРЗИНА/DELTA/delta-release.jks", text)
        self.assertNotIn("(ТЕСТ)", text)


class ArchiveTest(ExportCase):
    def assert_attachment_catalog(self, entries, trashed, expected):
        with mock.patch.object(self.vault, "export_entries", return_value=entries), \
                mock.patch.object(self.vault, "trashed", return_value=trashed):
            data, count = export.build_archive(self.vault, ARCHIVE, WHEN, True)
        self.assertEqual(count, len(entries))
        with pyzipper.AESZipFile(io.BytesIO(data)) as z:
            names = z.namelist()
            self.assertEqual(len(names), len({name.casefold() for name in names}))
            self.assertTrue(all(info.flag_bits & 0x1 for info in z.infolist()))
        files = self.read(io.BytesIO(data))
        text = files.pop("PW_STORAGE/catalog.txt").decode("utf-8")
        expected_files = {}
        for entry, paths in expected:
            block = text.split(f"[{entry.uid}]", 1)[1].split("\n[", 1)[0]
            references = [line.removeprefix("  Вложение: ") for line in block.splitlines()
                          if line.startswith("  Вложение: ")]
            self.assertEqual(references, paths)
            self.assertEqual(len(paths), len(entry.attachments))
            expected_files.update((path, attachment[1]) for path, attachment in zip(paths, entry.attachments))
        self.assertEqual(files, expected_files)

    def test_refuses_untrusted_and_system(self):
        with self.assertRaises(ExportError):
            export.write_archive(self.vault, self.volume, self.settings, ARCHIVE, WHEN)
        system = Volume("C:\\", "00000001", "", "диск")
        with self.assertRaises(ExportError):
            export.trust(self.settings, system)
        self.assertEqual(list(self.drive.iterdir()), [])

    def test_short_password(self):
        export.trust(self.settings, self.volume)
        with self.assertRaises(ExportError):
            export.write_archive(self.vault, self.volume, self.settings, "короткий", WHEN)
        self.assertEqual(list(self.drive.iterdir()), [])

    def test_writes_encrypted_archive(self):
        export.trust(self.settings, self.volume)
        self.assertTrue(json.loads(self.settings.read_text(encoding="utf-8"))["telegram"], "прочие настройки целы")
        path, count = export.write_archive(self.vault, self.volume, self.settings, ARCHIVE, WHEN)
        self.assertEqual(path.name, "PW_STORAGE_2026-11-04.zip")
        self.assertEqual(count, 3)
        self.assertEqual(path.parent, self.drive / "PW_STORAGE_BACKUP")
        self.assertEqual([p.name for p in path.parent.iterdir()], [path.name], "временного .part не осталось")
        raw = path.read_bytes()
        self.assertNotIn(b"TEST-", raw, "открытого текста в архиве нет")
        files = self.read(path)
        self.assertEqual(sorted(files), ["PW_STORAGE/DELTA/delta-release.jks", "PW_STORAGE/catalog.txt"])
        self.assertEqual(files["PW_STORAGE/DELTA/delta-release.jks"], b"\x00TESTJKS")
        self.assertIn("TEST-PART-1234", files["PW_STORAGE/catalog.txt"].decode("utf-8"))
        with self.assertRaises(RuntimeError):
            self.read(path, "неверный пароль архива 12345")
        second, _ = export.write_archive(self.vault, self.volume, self.settings, ARCHIVE, WHEN)
        self.assertNotEqual(second, path, "старый архив не затирается")
        self.assertTrue(path.exists())

    def test_duplicate_attachment_catalog_paths(self):
        base = self.vault.export_entries()[0]
        entry = replace(base, group="Project.v1", attachments=[
            ("key.jks", b"TEST-key-1"), ("key.jks", b"TEST-key-2"),
            ("key.jks", b"TEST-key-3"), ("README", b"TEST-readme-1"),
            ("README", b"TEST-readme-2"), ("README", b"TEST-readme-3"),
            ("README (2)", b"TEST-readme-suffix"),
        ])
        paths = [f"PW_STORAGE/Project.v1/{name}" for name in (
            "key.jks", "key (2).jks", "key (3).jks", "README", "README (2)",
            "README (3)", "README (2) (2)",
        )]
        self.assert_attachment_catalog([entry], [], [(entry, paths)])

    def test_sanitized_case_insensitive_and_trash_catalog_paths(self):
        bases = self.vault.export_entries()
        first = replace(bases[0], group="PROJ:ECT", attachments=[("release?.JKS", b"TEST-first")])
        second = replace(bases[1], group="proj?ect. ", attachments=[
            ("release*.jks", b"TEST-second"), ("RELEASE_.JKS ", b"TEST-third"),
        ])
        trash = replace(bases[2], group="proj?ect", attachments=[
            ("key?.jks", b"TEST-trash-1"), ("key*.JKS", b"TEST-trash-2"),
            ("README", b"TEST-trash-3"), ("readme", b"TEST-trash-4"),
            ("README ", b"TEST-trash-5"),
        ])
        self.assert_attachment_catalog([first, second], [trash], [
            (first, ["PW_STORAGE/PROJ_ECT/release_.JKS"]),
            (second, ["PW_STORAGE/proj_ect/release_ (2).jks", "PW_STORAGE/proj_ect/RELEASE_ (3).JKS"]),
            (trash, [f"PW_STORAGE/_КОРЗИНА/proj_ect/{name}" for name in (
                "key_.jks", "key_ (2).JKS", "README", "readme (2)", "README (3)",
            )]),
        ])

    def test_exact_values_round_trip_inside_encrypted_catalog(self):
        # NUL cannot be set through PyKeePass's XML API; exercise it as an in-memory export record.
        values = ("", "\n", "\r\n", "TEST-LF\nlast\n", "TEST-CRLF\r\nlast\r\n",
                  "TEST-mixed\r\nLF\nCR\r\n\n", "TEST-\x00nul\x00", "TEST-\\path\\n\\r\\",
                  'TEST-"quoted"\t Юникод 雪 \U0001d11e \u2028\u2029', "TEST-spaces  \n\n")
        base = self.vault.export_entries()[0]
        entries = [replace(base, uid=f"{index:08x}", value=value, attachments=())
                   for index, value in enumerate(values)]
        active, deleted = entries[:5], entries[5:]
        before = set(self.dir.rglob("*"))
        with mock.patch.object(self.vault, "export_entries", return_value=active), \
                mock.patch.object(self.vault, "trashed", return_value=deleted):
            data, count = export.build_archive(self.vault, ARCHIVE, WHEN, False)
        self.assertEqual(count, len(active))
        self.assert_json_values(data, entries)
        text = self.read(io.BytesIO(data))["PW_STORAGE/catalog.txt"].decode("utf-8")
        self.assertIn("  Значение: TEST-LF", text, "читаемое представление сохранено")
        self.assertEqual(text, export.catalog_text(active, "TEST-PART-1234", WHEN, False, deleted))
        self.assertNotIn(b"TEST-", data)
        self.assertEqual(set(self.dir.rglob("*")), before, "архив собирается только в памяти")
        with pyzipper.AESZipFile(io.BytesIO(data)) as z:
            self.assertTrue(all(info.flag_bits & 0x1 and info.wz_aes_strength == 3 for info in z.infolist()))
            with self.assertRaises(RuntimeError):
                z.read("PW_STORAGE/catalog.txt")

    def test_each_hierarchy_segment_is_safe_and_collisions_match_catalog(self):
        bases = self.vault.export_entries()
        first = replace(bases[0], group="../PROJ:ECT/.. /nested\\bad./NUL",
                        attachments=[("../release?.JKS", b"TEST-first")])
        second = replace(bases[1], group=". /proj?ect/./nested?bad /nul", attachments=[
            ("..\\RELEASE*.jks ", b"TEST-second"), ("C:\\absolute?.jks", b"TEST-third"),
        ])
        trash = replace(bases[2], group=first.group, attachments=[("../../key.jks", b"TEST-trash")])
        self.assert_attachment_catalog([first, second], [trash], [
            (first, ["PW_STORAGE/_/PROJ_ECT/_/nested_bad/_NUL/_release_.JKS"]),
            (second, ["PW_STORAGE/_/proj_ect/_/nested_bad/_nul/_RELEASE_ (2).jks",
                      "PW_STORAGE/_/proj_ect/_/nested_bad/_nul/C__absolute_.jks"]),
            (trash, ["PW_STORAGE/_КОРЗИНА/_/PROJ_ECT/_/nested_bad/_NUL/_.._key.jks"]),
        ])
        for entry in (first, second, trash):
            for name, _ in entry.attachments:
                for path_for in (export.attachment_path, export.trash_attachment_path):
                    path = path_for(entry, name)
                    self.assertTrue(path.startswith("PW_STORAGE/"))
                    self.assertNotIn("\\", path)
                    self.assertNotIn(":", path)
                    self.assertTrue(all(segment and segment not in (".", "..")
                                        and segment == segment.strip(" .") for segment in path.split("/")))

    def test_attachment_file_directory_and_catalog_prefix_collisions(self):
        bases = self.vault.export_entries()
        first = replace(bases[0], group="A", attachments=[("B", b"TEST-file")])
        nested = replace(bases[1], group="A/B", attachments=[("key.jks", b"TEST-nested")])
        catalog = replace(bases[2], group="catalog.txt/Child", attachments=[("key.jks", b"TEST-catalog")])
        self.assert_attachment_catalog([first, nested, catalog], [], [
            (first, ["PW_STORAGE/A/B (2)"]),
            (nested, ["PW_STORAGE/A/B/key.jks"]),
            (catalog, ["PW_STORAGE/catalog.txt (2)/Child/key.jks"]),
        ])

    def test_four_exports_same_timestamp_preserve_bytes_and_foreign_part(self):
        export.trust(self.settings, self.volume)
        folder = self.drive / export.FOLDER
        folder.mkdir()
        foreign = folder / "PW_STORAGE_2026-11-04.zip.part"
        foreign.write_bytes(b"foreign unfinished export")
        saved = {}
        for _ in range(4):
            path, count = export.write_archive(self.vault, self.volume, self.settings, ARCHIVE, WHEN)
            self.assertEqual(count, 3)
            self.assertNotIn(path, saved)
            saved[path] = path.read_bytes()
            for previous, raw in saved.items():
                self.assertEqual(previous.read_bytes(), raw)
        self.assertEqual([path.name for path in saved], [
            "PW_STORAGE_2026-11-04.zip", "PW_STORAGE_2026-11-04_183000.zip",
            "PW_STORAGE_2026-11-04_183000 (2).zip", "PW_STORAGE_2026-11-04_183000 (3).zip",
        ])
        self.assertEqual(foreign.read_bytes(), b"foreign unfinished export")
        self.assertEqual(set(folder.iterdir()), set(saved) | {foreign})

    def test_final_rename_races_preserve_existing_targets(self):
        export.trust(self.settings, self.volume)
        existing, _ = export.build_archive(self.vault, ARCHIVE, WHEN, True)
        rename = export.os.rename
        raced = {}
        sources = []

        def race(source, target):
            sources.append(Path(source))
            if len(raced) < 2:
                with Path(target).open("xb") as stream:
                    stream.write(existing)
                raced[Path(target)] = existing
            return rename(source, target)

        with mock.patch.object(export.os, "rename", side_effect=race) as mocked:
            path, count = export.write_archive(self.vault, self.volume, self.settings, ARCHIVE, WHEN)
        self.assertEqual(mocked.call_count, 3)
        self.assertEqual(len(set(sources)), 1)
        self.assertEqual(sources[0].suffix, ".part")
        self.assertFalse(sources[0].exists())
        self.assertEqual(count, 3)
        self.assertEqual(path.name, "PW_STORAGE_2026-11-04_183000 (2).zip")
        for previous, raw in raced.items():
            self.assertEqual(previous.read_bytes(), raw)
        self.assertIn("PW_STORAGE/catalog.txt", self.read(path))
        self.assertEqual(set(path.parent.iterdir()), set(raced) | {path})

    def test_check_archive_failure_cleans_only_owned_encrypted_part(self):
        export.trust(self.settings, self.volume)
        folder = self.drive / export.FOLDER
        folder.mkdir()
        foreign = folder / "PW_STORAGE_2026-11-04.zip.part"
        foreign.write_bytes(b"foreign unfinished export")
        existing = folder / "PW_STORAGE_2026-11-04.zip"
        existing.write_bytes(export.build_archive(self.vault, ARCHIVE, WHEN, True)[0])
        saved = {path: path.read_bytes() for path in folder.iterdir()}
        parts = []

        def fail_check(path, password):
            parts.append(path)
            self.assertNotEqual(path, foreign)
            self.assertEqual(path.suffix, ".part")
            self.assertEqual(password, ARCHIVE)
            self.assertNotIn(b"TEST-", path.read_bytes())
            self.assertIn("PW_STORAGE/catalog.txt", self.read(path))
            raise ExportError("test verification failure")

        with mock.patch.object(export, "check_archive", side_effect=fail_check):
            with self.assertRaisesRegex(ExportError, "test verification failure"):
                export.write_archive(self.vault, self.volume, self.settings, ARCHIVE, WHEN)
        self.assertEqual(len(parts), 1)
        self.assertFalse(parts[0].exists())
        self.assertEqual({path: path.read_bytes() for path in folder.iterdir()}, saved)

    def test_archive_is_flushed_before_verification(self):
        export.trust(self.settings, self.volume)
        fsync = export.os.fsync
        check = export.check_archive
        synced = []

        def sync(fd):
            fsync(fd)
            synced.append(fd)

        def verify(path, password):
            self.assertEqual(len(synced), 1)
            return check(path, password)

        with mock.patch.object(export.os, "fsync", side_effect=sync), \
             mock.patch.object(export, "check_archive", side_effect=verify):
            path, count = export.write_archive(self.vault, self.volume, self.settings, ARCHIVE, WHEN)
        self.assertEqual(count, 3)
        self.assertIn("PW_STORAGE/catalog.txt", self.read(path))

    def test_fsync_failure_preserves_existing_archive_and_cleans_owned_part(self):
        export.trust(self.settings, self.volume)
        existing, _ = export.write_archive(self.vault, self.volume, self.settings, ARCHIVE, WHEN)
        saved = existing.read_bytes()
        with mock.patch.object(export.os, "fsync", side_effect=OSError("synthetic flush failure")), \
             mock.patch.object(export, "check_archive") as check, \
             mock.patch.object(export.os, "rename") as rename:
            with self.assertRaises(ExportError):
                export.write_archive(self.vault, self.volume, self.settings, ARCHIVE, WHEN)
        check.assert_not_called()
        rename.assert_not_called()
        self.assertEqual(existing.read_bytes(), saved)
        self.assertEqual(list(existing.parent.iterdir()), [existing])

    def test_rename_failure_cleans_owned_part(self):
        export.trust(self.settings, self.volume)
        for error in (PermissionError("denied"), OSError("disconnected")):
            with self.subTest(error=type(error).__name__):
                with mock.patch.object(export.os, "rename", side_effect=error):
                    with self.assertRaises(ExportError):
                        export.write_archive(self.vault, self.volume, self.settings, ARCHIVE, WHEN)
                self.assertEqual(list((self.drive / export.FOLDER).iterdir()), [])


class RecursiveExportTest(ExportCase):
    def api_entry(self, group, key, value="TEST-synthetic", tags=(), attachments=()):
        kp = self.vault._kp
        entry = kp.add_entry(group, "Synthetic " + key, key, value,
                             notes="Synthetic comment", tags=list(tags))
        for name, data in attachments:
            entry.add_attachment(kp.add_binary(data), name)
        return entry

    def reopen(self):
        self.vault.save()
        self.vault = Vault.open(self.dir / "vault.kdbx", PASSWORD)

    def test_root_nested_uid_tags_and_entire_system_recycle_subtrees(self):
        kp = self.vault._kp
        root = kp.root_group
        root.name = "Synthetic root"
        parent = kp.add_group(root, "PARENT")
        child = kp.add_group(parent, "CHILD")
        deep = kp.add_group(child, "Deep group")
        ordinary = [
            self.api_entry(root, "root", "TEST-root\r\nlast\r\n", ("ROOT_ALLOWED",),
                           [("root.txt", b"TEST-root-attachment")]),
            self.api_entry(parent, "flat", "TEST-flat\n", ("OTHER",)),
            self.api_entry(child, "untagged", "TEST-untagged\n\n"),
            self.api_entry(deep, "deep", "TEST-deep\r\nLF\nCR\r", ("ALLOWED", "ALL"),
                           [("deep.jks", b"TEST-deep-attachment")]),
        ]
        system = kp.find_groups(name=SYSTEM_SCOPE, first=True)
        hidden = [self.api_entry(kp.add_group(system, "Hidden child"), "hidden-top", attachments=[
            ("hidden.jks", b"TEST-system-only"),
        ])]
        nested_system = kp.add_group(parent, SYSTEM_SCOPE)
        hidden += [self.api_entry(nested_system, "hidden-nested"),
                   self.api_entry(kp.add_group(nested_system, "Hidden grandchild"), "hidden-deep")]
        retired = kp.add_group(root, "RETIRED")
        retired_child = kp.add_group(retired, "Nested")
        deleted = self.api_entry(retired_child, "retired", "TEST-retired\r\n", (),
                                 [("retired.jks", b"TEST-retired-attachment")])
        kp.trash_group(retired)
        # RecycleBinUUID, not a name or root-only position, defines the excluded subtree.
        kp.move_group(kp.recyclebin_group, parent)
        self.reopen()
        rows = {r.key: r for r in self.vault.rows()}
        self.assertEqual(set(rows), {"login", "keystore", "codes", "root", "flat", "untagged", "deep"})
        self.assertEqual([rows[e.username].group for e in ordinary],
                         ["Synthetic root", "PARENT", "PARENT/CHILD", "PARENT/CHILD/Deep group"])
        for entry in ordinary:
            self.assertEqual(rows[entry.username].uid, row_id(entry.uuid))
            self.assertEqual(self.vault.value(row_id(entry.uuid)), entry.password)
        self.assertEqual(rows["root"].projects, ("ROOT_ALLOWED",))
        self.assertFalse(rows["root"].visible_to("Synthetic root"))
        self.assertEqual(rows["untagged"].projects, ())
        self.assertFalse(rows["untagged"].visible_to("PARENT"))
        self.assertFalse(rows["untagged"].visible_to("CHILD"))
        self.assertEqual(rows["deep"].projects, ("ALLOWED",))
        self.assertTrue(rows["deep"].shared)
        for entry in hidden + [deleted]:
            self.assertIsNone(self.vault.value(row_id(entry.uuid)))
        trashed = self.vault.trashed()
        self.assertEqual([(e.key, e.group) for e in trashed], [("retired", "RETIRED/Nested")])
        active = self.vault.export_entries()
        self.assertEqual({e.uid for e in active}, {r.uid for r in rows.values()})
        data, count = export.build_archive(self.vault, ARCHIVE, WHEN, False)
        self.assertEqual(count, 7)
        self.assert_json_values(data, active + trashed)
        files = self.read(io.BytesIO(data))
        files.pop("PW_STORAGE/catalog.txt")
        self.assertEqual(files, {
            "PW_STORAGE/DELTA/delta-release.jks": b"\x00TESTJKS",
            "PW_STORAGE/Synthetic root/root.txt": b"TEST-root-attachment",
            "PW_STORAGE/PARENT/CHILD/Deep group/deep.jks": b"TEST-deep-attachment",
            "PW_STORAGE/_КОРЗИНА/RETIRED/Nested/retired.jks": b"TEST-retired-attachment",
        })

    def test_actual_nested_sanitized_attachment_collisions_and_references(self):
        kp = self.vault._kp
        entries = []
        for index, (parent_name, child_name, filename) in enumerate((
                ("PROJ:ECT", "Sub:Group", "key?.JKS"), ("proj?ect", "sub?group", "key*.jks"))):
            group = kp.add_group(kp.add_group(kp.root_group, parent_name), child_name)
            entries.append(self.api_entry(group, f"collision-{index}", tags=("ALLOWED",),
                                          attachments=[(filename, f"TEST-{index}".encode("ascii"))]))
        self.reopen()
        data, _ = export.build_archive(self.vault, ARCHIVE, WHEN, False)
        files = self.read(io.BytesIO(data))
        text = files["PW_STORAGE/catalog.txt"].decode("utf-8")
        for entry, path in zip(entries, ("PW_STORAGE/PROJ_ECT/Sub_Group/key_.JKS",
                                         "PW_STORAGE/proj_ect/sub_group/key_ (2).jks")):
            block = text.split(f"[{row_id(entry.uuid)}]", 1)[1].split("\n[", 1)[0]
            self.assertIn(f"  Вложение: {path}\n", block)
            self.assertEqual(files[path], entry.attachments[0].data)
        self.assertEqual(len(files), len({path.casefold() for path in files}))
        self.assert_json_values(data, self.vault.export_entries())

    def test_nested_trash_origin_system_exclusion_and_recursive_erased_count(self):
        self.assertEqual(self.vault.empty_trash(), 0)
        kp = self.vault._kp
        root = kp.root_group
        root.name = "Synthetic root"
        parent = kp.add_group(root, "PARENT")
        nested = kp.add_group(kp.add_group(parent, "CHILD"), "DEEP")
        ordinary = [self.api_entry(root, "root-deleted"),
                    self.api_entry(nested, "deep-deleted", "TEST-deleted\r\n\n", (),
                                   [("key.jks", b"TEST-key")])]
        for entry in ordinary:
            self.vault.trash(row_id(entry.uuid))
        self.assertEqual([entry.get_custom_property(TRASH_GROUP_PROPERTY) for entry in ordinary],
                         ["Synthetic root", "PARENT/CHILD/DEEP"])
        recycle = kp.recyclebin_group
        native = kp.add_group(root, "NATIVE")
        native_child = kp.add_group(native, "Nested")
        native_entries = [self.api_entry(native, "native-flat"),
                          self.api_entry(native_child, "native-deep", "TEST-native\n", (),
                                         [("native.jks", b"TEST-native-attachment")])]
        kp.trash_group(native)
        system = kp.add_group(recycle, SYSTEM_SCOPE)
        excluded = [self.api_entry(system, "system-trash"),
                    self.api_entry(kp.add_group(system, "Hidden"), "system-trash-deep")]
        nested_system = kp.add_group(native_child, SYSTEM_SCOPE)
        excluded.append(self.api_entry(kp.add_group(nested_system, "Hidden"), "system-native-deep"))
        known_system = self.api_entry(recycle, "system-origin")
        known_system.set_custom_property(TRASH_GROUP_PROPERTY, SYSTEM_SCOPE + "/Hidden")
        excluded.append(known_system)
        self.reopen()
        trash = {e.key: e for e in self.vault.trashed()}
        self.assertEqual({key: e.group for key, e in trash.items()}, {
            "root-deleted": "Synthetic root", "deep-deleted": "PARENT/CHILD/DEEP",
            "native-flat": "NATIVE", "native-deep": "NATIVE/Nested",
        })
        for entry in ordinary + native_entries + excluded:
            self.assertIsNone(self.vault.value(row_id(entry.uuid)))
        data, _ = export.build_archive(self.vault, ARCHIVE, WHEN, False)
        active = self.vault.export_entries()
        self.assert_json_values(data, active + list(trash.values()))
        files = self.read(io.BytesIO(data))
        self.assertEqual(files["PW_STORAGE/_КОРЗИНА/PARENT/CHILD/DEEP/key.jks"], b"TEST-key")
        self.assertEqual(files["PW_STORAGE/_КОРЗИНА/NATIVE/Nested/native.jks"], b"TEST-native-attachment")
        text = files["PW_STORAGE/catalog.txt"].decode("utf-8")
        for entry in excluded:
            self.assertNotIn(f"[{row_id(entry.uuid)}]", text)
        count_before = len(self.vault._kp.entries)
        self.assertEqual(self.vault.empty_trash(), len(ordinary + native_entries + excluded),
                         "считаются все реально стёртые записи, даже исключённые из экспорта")
        self.assertEqual(len(self.vault._kp.entries), count_before - 8)
        self.assertEqual(self.vault._kp.recyclebin_group.subgroups, [])
        self.reopen()
        self.assertEqual(self.vault.trashed(), [])
        self.assertEqual(self.vault.empty_trash(), 0)
        self.assertEqual({e.uid for e in self.vault.export_entries()}, {e.uid for e in active})


class RecoveryPartTest(unittest.TestCase):
    """Часть ключа попадает в хранилище при создании и при каждом перевыпуске."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="pwtest"))
        self.profile = Profile(name="test", data=self.dir / "data", logs=self.dir / "logs",
                               projects_root=self.dir / "projects", pipe="unused", catalog_key="UNUSED")
        for patch in (mock.patch.object(admin, "PROFILE", self.profile), mock.patch.object(admin, "TpmKey", lambda *a, **k: FakeTpm())):
            patch.start()
            self.addCleanup(patch.stop)
        self.fast = RecoveryKdf(16, 1, 1)
        self.answer = "Зелёная лодка уплыла за старую мельницу"

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def stored(self, password):
        return Vault.open(self.profile.vault, password).system_value(RECOVERY_ENTRY)

    def test_part_follows_every_issue(self):
        part = admin.create_test_vault(PASSWORD, new_totp_secret(), "Вопрос?", self.answer, FAST, self.fast)
        self.assertEqual(self.stored(PASSWORD), part)
        part = admin.reissue_test_part(PASSWORD, self.answer, self.fast)
        self.assertEqual(self.stored(PASSWORD), part)
        new = "новый-тестовый-пароль-456"
        part = admin.change_test_password(PASSWORD, new, self.answer, self.fast)
        self.assertEqual(self.stored(new), part)
        newest = "ещё-один-тестовый-пароль-789"
        part = admin.recover_test_vault(self.answer, part, newest, self.fast)
        self.assertEqual(self.stored(newest), part)


class ExportWindowTest(ExportCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tk.Tk()
        cls.root.withdraw()
        apply_style(cls.root)

    @classmethod
    def tearDownClass(cls):
        cls.root.destroy()

    def make(self):
        self.audit = mock.Mock()
        self.closed = []
        self.window = admin.ExportWindow(self.root, vault=self.vault, take_focus=False, on_close=self.closed.append,
                                         volumes=lambda: [self.volume], settings=self.settings, audit=self.audit)
        self.addCleanup(lambda: self.window.win.winfo_exists() and self.window.win.destroy())
        return self.window

    def test_documentation_screenshot(self):
        """Снимок окна выгрузки для документации: носитель показан нейтральной буквой."""
        from tests.shot import snapshot

        window = self.make()
        window.volumes_source = lambda: [Volume("E:\\", "1A2B3C4D", "КОПИИ", "съёмный")]
        window.refresh()
        window.win.update()
        snapshot(window.win, "export.png")

    def test_trust_then_export(self):
        window = self.make()
        self.assertTrue(window.trust_button.winfo_manager(), "носитель не доверенный: кнопка видна")
        window.archive.set(ARCHIVE)
        window.repeat.set(ARCHIVE)
        window.submit()
        self.assertIn("доверенный", window.message.cget("text"))
        with mock.patch.object(admin.messagebox, "askyesno", return_value=True):
            window.trust_selected()
        self.assertTrue(export.is_trusted(self.settings, self.volume))
        window.archive.set(ARCHIVE)
        window.repeat.set(ARCHIVE + "x")
        window.submit()
        self.assertIn("не совпадают", window.message.cget("text"))
        window.repeat.set(ARCHIVE)
        window.submit()
        end = time.monotonic() + 20
        while "Архив записан" not in window.message.cget("text") and time.monotonic() < end:
            self.root.update()
            time.sleep(0.02)
        self.root.update()
        self.assertTrue(window.ok, window.message.cget("text"))
        self.assertIn("Архив записан", window.message.cget("text"))
        self.assertEqual(window.archive.get(), "", "пароль архива не остаётся в поле")
        events = [c.args[0] for c in self.audit.write.call_args_list]
        self.assertEqual(events, ["media_trusted", "export_written"])
        self.assertNotIn(ARCHIVE, repr(self.audit.write.call_args_list))
        self.assertEqual(len(list((self.drive / "PW_STORAGE_BACKUP").glob("*.zip"))), 1)


if __name__ == "__main__":
    unittest.main()
