"""Перечень для окна доступа. Ключ TPM здесь подменён: настоящий проверяется в test_tpm_real.py."""

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pw_storage import catalog
from pw_storage.vault import Row, VaultChanged, file_hash


class FakeTpm:
    """Поведение как у TpmKey: создаётся один раз, шифрует обратимо, на другом «компьютере» не расшифрует."""

    def __init__(self, mark=0x5A):
        self.mark = mark
        self.created = False

    def exists(self):
        return self.created

    def create(self):
        self.created = True

    def encrypt(self, data):
        return bytes(b ^ self.mark for b in data) + bytes([self.mark])

    def decrypt(self, data):
        from pw_storage.tpm import TpmError

        if data[-1] != self.mark:
            raise TpmError("чужой ключ")
        return bytes(b ^ self.mark for b in data[:-1])


ROWS = [
    Row("a0000001", "COMMON", "Погода", "API_KEY", "Общий ключ погоды", ("COMMON",), True),
    Row("a0000002", "DELTA", "Такси", "login", "Логин Такси", ("DELTA",), False),
    Row("a0000003", "DELTA", "Такси", "password", "", ("DELTA",), False),  # без комментария
    Row("a0000004", "FLEET", "Свет", "token", "Токен сервиса", ("FLEET",), False),
]


class CatalogTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="pwtest"))
        self.vault = self.dir / "vault.kdbx"
        self.vault.write_bytes(b"first version")
        self.path = self.dir / "catalog.bin"
        self.key = FakeTpm()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_round_trip_is_fresh(self):
        catalog.write(self.key, self.path, ROWS, self.vault, source_hash=file_hash(self.vault))
        listing = catalog.read(self.key, self.path, self.vault)
        self.assertEqual(listing.state, catalog.FRESH)
        self.assertEqual([i.uid for i in listing.own("DELTA")], ["a0000002"])
        self.assertEqual([i.uid for i in listing.common("DELTA")], ["a0000001"])
        self.assertEqual(sorted(listing.visible("DELTA")), ["a0000001", "a0000002"])
        self.assertEqual([i.uid for i in listing.own("COMMON")], ["a0000001"])
        self.assertEqual(listing.common("COMMON"), [])

    def test_creates_key_once(self):
        self.assertFalse(self.key.exists())
        catalog.write(self.key, self.path, ROWS, self.vault, source_hash=file_hash(self.vault))
        self.assertTrue(self.key.exists())

    def test_contains_no_service_or_key(self):
        catalog.write(self.key, self.path, ROWS, self.vault, source_hash=file_hash(self.vault))
        listing = catalog.read(self.key, self.path, self.vault)
        self.assertNotIn("'login'", repr(listing))
        self.assertNotIn("API_KEY", repr(listing))
        self.assertEqual(listing.items[0].to_dict(), {"id": "a0000001", "comment": "Общий ключ погоды", "all": True})

    def test_rows_without_comment_are_only_counted(self):
        catalog.write(self.key, self.path, ROWS, self.vault, source_hash=file_hash(self.vault))
        listing = catalog.read(self.key, self.path, self.vault)
        self.assertNotIn("a0000003", [i.uid for i in listing.items])
        self.assertEqual(listing.unnamed_count("DELTA"), 1)
        self.assertEqual(listing.unnamed_count("FLEET"), 0)

    def test_old_format_counts_as_missing(self):
        import json
        from pw_storage.tpm import seal
        self.key.create()
        self.path.write_bytes(seal(self.key, json.dumps({"vault_sha256": "x", "rows": [["ALL", "c"]]}).encode()))
        self.assertEqual(catalog.read(self.key, self.path, self.vault).state, catalog.MISSING)

    def test_file_is_not_plain_text(self):
        catalog.write(self.key, self.path, ROWS, self.vault, source_hash=file_hash(self.vault))
        self.assertNotIn("Логин".encode("utf-8"), self.path.read_bytes())

    def test_stale_when_vault_changed(self):
        catalog.write(self.key, self.path, ROWS, self.vault, source_hash=file_hash(self.vault))
        self.vault.write_bytes(b"changed outside")
        listing = catalog.read(self.key, self.path, self.vault)
        self.assertEqual(listing.state, catalog.STALE)
        self.assertEqual([i.comment for i in listing.common("DELTA")], ["Общий ключ погоды"])

    def test_vault_disappearing_during_freshness_check_is_stale(self):
        catalog.write(self.key, self.path, ROWS, self.vault, source_hash=file_hash(self.vault))
        with mock.patch.object(catalog, "_hash_or_none", return_value=None):
            self.assertEqual(catalog.read(self.key, self.path, self.vault).state, catalog.STALE)

    def test_snapshot_hash_cannot_be_rebound_to_changed_disk(self):
        original_hash = file_hash(self.vault)
        self.vault.write_bytes(b"a later external version")
        with self.assertRaises(VaultChanged):
            catalog.write(self.key, self.path, ROWS, self.vault, source_hash=original_hash)
        self.assertFalse(self.path.exists())

    def test_change_during_encryption_marks_catalog_stale(self):
        original_hash = file_hash(self.vault)
        seal = catalog.seal

        def changed(key, data):
            self.vault.write_bytes(b"changed while catalog encrypted")
            return seal(key, data)

        with mock.patch.object(catalog, "seal", side_effect=changed):
            catalog.write(self.key, self.path, ROWS, self.vault, source_hash=original_hash)
        self.assertEqual(catalog.read(self.key, self.path, self.vault).state, catalog.STALE)

    def test_missing_file(self):
        self.assertEqual(catalog.read(self.key, self.path, self.vault).state, catalog.MISSING)

    def test_other_computer_cannot_read(self):
        catalog.write(self.key, self.path, ROWS, self.vault, source_hash=file_hash(self.vault))
        listing = catalog.read(FakeTpm(mark=0x33), self.path, self.vault)
        self.assertEqual(listing, catalog.Listing(catalog.MISSING))

    def test_corrupted_file(self):
        catalog.write(self.key, self.path, ROWS, self.vault, source_hash=file_hash(self.vault))
        blob = bytearray(self.path.read_bytes())
        blob[-1] ^= 0xFF
        self.path.write_bytes(bytes(blob))
        self.assertEqual(catalog.read(self.key, self.path, self.vault).state, catalog.MISSING)


if __name__ == "__main__":
    unittest.main()
