"""Настоящий TPM: запускается только явно, PW_STORAGE_REAL_TPM=1.

Ключ без кода, поэтому неверных попыток нет и лимит подбора TPM не расходуется.
Работает только с ключом PW_STORAGE_TEST_UNIT и удаляет его в конце.
"""

import os
import secrets
import shutil
import tempfile
import unittest
from pathlib import Path

from pw_storage import catalog
from pw_storage.tpm import TpmError, TpmKey, seal, unseal
from pw_storage.vault import Row, file_hash

NAME = "PW_STORAGE_TEST_UNIT"


@unittest.skipUnless(os.environ.get("PW_STORAGE_REAL_TPM") == "1", "нужен PW_STORAGE_REAL_TPM=1")
class RealTpmTest(unittest.TestCase):
    def setUp(self):
        self.key = TpmKey(NAME)
        self.assertFalse(self.key.exists(), "тестовый ключ остался от прошлого прогона")
        self.key.create()
        self.dir = Path(tempfile.mkdtemp(prefix="pwtest"))

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)
        if self.key.exists():
            self.key.delete()
        self.assertFalse(self.key.exists())

    def test_everything_on_one_key(self):
        # Создание ключа занимает секунды, поэтому один ключ на всю проверку.
        short = secrets.token_bytes(32)
        wrapped = self.key.encrypt(short)
        self.assertEqual(len(wrapped), 256)
        self.assertNotEqual(wrapped, short)
        self.assertEqual(self.key.decrypt(wrapped), short)

        long_data = secrets.token_bytes(100_000)
        self.assertEqual(unseal(self.key, seal(self.key, long_data)), long_data)

        blob = bytearray(seal(self.key, b"test data"))
        blob[-1] ^= 0xFF
        with self.assertRaises(TpmError):
            unseal(self.key, bytes(blob))

        vault = self.dir / "vault.kdbx"
        vault.write_bytes(b"test")
        path = self.dir / "catalog.bin"
        catalog.write(self.key, path, [Row("a0000001", "COMMON", "s", "k", "Комментарий", ("COMMON",), True)],
                      vault, source_hash=file_hash(vault))
        listing = catalog.read(self.key, path, vault)
        self.assertEqual(listing.state, catalog.FRESH)
        self.assertEqual([item.comment for item in listing.common("DELTA")], ["Комментарий"])


class MissingKeyTest(unittest.TestCase):
    def test_absent_key_is_reported_not_created(self):
        key = TpmKey("PW_STORAGE_TEST_ABSENT")
        self.assertFalse(key.exists())
        with self.assertRaises(TpmError):
            key.decrypt(b"x" * 256)
        self.assertFalse(key.exists())


if __name__ == "__main__":
    unittest.main()
