"""Восстановление пароля на случайных тестовых значениях, письма здесь не отправляются."""

import base64
import json
import secrets
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pw_storage import recovery
from pw_storage.recovery import RecoveryError, RecoveryKdf, WeakAnswer, WrongRecovery
from pw_storage.vault import Kdf, Vault, WrongPassword

FAST = RecoveryKdf(memory_mb=16, iterations=1, parallelism=1)
QUESTION = "Какая фраза была на первой странице тетради?"
ANSWER = "Зелёная лодка уплыла за старую мельницу"
CLI = r"C:\Program Files\KeePassXC\keepassxc-cli.exe"


class RecoveryTest(unittest.TestCase):
    def setUp(self):
        self.password = secrets.token_urlsafe(24)
        self.blob, self.part = recovery.issue(self.password, QUESTION, ANSWER, FAST)

    def test_round_trip(self):
        self.assertEqual(recovery.recover(self.blob, ANSWER, self.part), self.password)

    def test_default_kdf_is_strong(self):
        self.assertEqual(RecoveryKdf(), RecoveryKdf(1024, 4, 4))

    def test_answer_tolerates_case_and_spaces(self):
        self.assertEqual(recovery.recover(self.blob, "  зелёная ЛОДКА  уплыла за старую   мельницу ", self.part), self.password)

    def test_part_tolerates_spaces_and_case(self):
        self.assertEqual(recovery.recover(self.blob, ANSWER, self.part.replace(" ", "").lower()), self.password)

    def test_wrong_answer(self):
        with self.assertRaises(WrongRecovery):
            recovery.recover(self.blob, "Совсем другая длинная фраза для проверки", self.part)

    def test_wrong_part(self):
        with self.assertRaises(WrongRecovery):
            recovery.recover(self.blob, ANSWER, recovery.new_part())

    def test_answer_alone_or_part_alone_is_not_enough(self):
        for answer, part in ((ANSWER, ""), ("", self.part)):
            with self.assertRaises(WrongRecovery):
                recovery.recover(self.blob, answer, part)

    def test_error_does_not_say_which_half_failed(self):
        messages = set()
        for answer, part in (("Другая длинная фраза для проверки ошибки", self.part), (ANSWER, recovery.new_part())):
            with self.assertRaises(WrongRecovery) as caught:
                recovery.recover(self.blob, answer, part)
            messages.add(str(caught.exception))
        self.assertEqual(len(messages), 1)

    def test_file_holds_no_secret_in_the_open(self):
        text = self.blob.decode("utf-8")
        for value in (self.password, ANSWER, self.part, self.part.replace(" ", "")):
            self.assertNotIn(value, text)

    def test_question_is_readable_without_answer(self):
        self.assertEqual(recovery.question_of(self.blob), QUESTION)

    def test_changed_question_breaks_the_file(self):
        data = json.loads(self.blob.decode("utf-8"))
        data["question"] = "Подменённый вопрос"
        with self.assertRaises(WrongRecovery):
            recovery.recover(json.dumps(data).encode("utf-8"), ANSWER, self.part)

    def test_each_issue_has_new_part_and_salt(self):
        blob, part = recovery.issue(self.password, QUESTION, ANSWER, FAST)
        self.assertNotEqual(part, self.part)
        self.assertNotEqual(json.loads(blob)["salt"], json.loads(self.blob)["salt"])

    def test_old_part_does_not_open_new_file(self):
        blob, _ = recovery.issue(self.password, QUESTION, ANSWER, FAST)
        with self.assertRaises(WrongRecovery):
            recovery.recover(blob, ANSWER, self.part)

    def test_short_answer_refused(self):
        for answer in ("Москва", "01.01.1980", "   коротко   "):
            with self.assertRaises(WeakAnswer):
                recovery.issue(self.password, QUESTION, answer, FAST)

    def test_question_required(self):
        with self.assertRaises(WeakAnswer):
            recovery.issue(self.password, "  ", ANSWER, FAST)

    def test_answer_inside_question_refused(self):
        with self.assertRaises(WeakAnswer):
            recovery.issue(self.password, f"Подсказка: {ANSWER}?", ANSWER, FAST)

    def test_missing_fields_are_rejected_before_derivation(self):
        for field in ("question", "salt", "nonce", "tag", "body", "memory_mb", "iterations", "parallelism"):
            data = json.loads(self.blob)
            del data[field]
            with self.subTest(field=field), mock.patch.object(recovery, "_derive") as derive:
                blob = json.dumps(data).encode()
                for operation in (lambda: recovery.question_of(blob), lambda: recovery.recover(blob, ANSWER, self.part)):
                    with self.assertRaises(RecoveryError):
                        operation()
                derive.assert_not_called()

    def test_invalid_kdf_is_rejected_before_derivation(self):
        changes = [("memory_mb", 0), ("memory_mb", 1025), ("memory_mb", 1_000_000),
                   ("iterations", 0), ("iterations", 11), ("iterations", "4"),
                   ("parallelism", 0), ("parallelism", 17), ("parallelism", True),
                   ("memory_mb", []), ("iterations", 1.5)]
        for field, value in changes:
            data = json.loads(self.blob)
            data[field] = value
            with self.subTest(field=field, value=value), mock.patch.object(recovery, "_derive") as derive:
                with self.assertRaises(RecoveryError):
                    recovery.recover(json.dumps(data).encode(), ANSWER, self.part)
                derive.assert_not_called()

    def test_invalid_binary_fields_are_rejected_before_derivation(self):
        for field in ("salt", "nonce", "tag", "body"):
            values = [None, [], "!invalid base64!"]
            if field != "body":
                values += ["", base64.b64encode(b"short").decode()]
            for value in values:
                data = json.loads(self.blob)
                data[field] = value
                with self.subTest(field=field, value=value), mock.patch.object(recovery, "_derive") as derive:
                    with self.assertRaises(RecoveryError):
                        recovery.recover(json.dumps(data).encode(), ANSWER, self.part)
                    derive.assert_not_called()

    def test_invalid_question_type_is_rejected(self):
        for value in (None, [], 42, " "):
            data = json.loads(self.blob)
            data["question"] = value
            with self.subTest(value=value), self.assertRaises(RecoveryError):
                recovery.question_of(json.dumps(data).encode())

    def test_invalid_utf8_is_reported_as_recovery_error(self):
        with self.assertRaises(RecoveryError):
            recovery.question_of(b"\xff")

    def test_garbage_file(self):
        for blob in (b"not json", b"[]", b'{"format": "OTHER"}'):
            with self.assertRaises(RecoveryError):
                recovery.question_of(blob)
        with self.assertRaises(RecoveryError):
            recovery.recover(b'{"format": "PWR1", "question": "q"}', ANSWER, self.part)


class VaultRecoveryFlowTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="pwtest"))
        self.path = self.dir / "vault.kdbx"
        self.old = secrets.token_urlsafe(24)
        self.new = secrets.token_urlsafe(24)
        self.value = "TEST-" + secrets.token_urlsafe(16)
        vault = Vault.create(self.path, self.old, Kdf(16, 1, 1))
        vault.put("DELTA", "Такси", "login", self.value, "Логин")
        vault.save()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_full_recovery_changes_password(self):
        blob, part = recovery.issue(self.old, QUESTION, ANSWER, FAST)
        forgotten = recovery.recover(blob, ANSWER, part)
        vault = Vault.open(self.path, forgotten)
        vault.change_password(self.new)
        vault.save()
        with self.assertRaises(WrongPassword):
            Vault.open(self.path, self.old)
        reopened = Vault.open(self.path, self.new)
        self.assertEqual(reopened.value(next(r.uid for r in reopened.rows() if r.service == "Такси")), self.value)
        self.assertEqual(reopened.kdf_algorithm, "argon2id")
        shown = subprocess.run([CLI, "show", "-s", "-a", "Password", str(self.path), "DELTA/Такси"],
                               input=self.new + "\n", capture_output=True, text=True, timeout=60)
        self.assertEqual(shown.stdout.strip(), self.value)

    def test_backup_keeps_old_password(self):
        # Копия .bak открывается старым паролем: после смены пароля из-за утечки её нужно удалить.
        vault = Vault.open(self.path, self.old)
        vault.change_password(self.new)
        vault.save()
        Vault.open(self.path.with_name("vault.kdbx.bak"), self.old)


if __name__ == "__main__":
    unittest.main()
