"""Обслуживание: заготовка тестового хранилища и защита от случайного создания настоящего."""

import contextlib
import gc
import io
import os
import shutil
import tempfile
import threading
import time
import tkinter as tk
import unittest
from pathlib import Path
from unittest import mock

import pyotp

from pw_storage import admin, recovery, vault as vault_module
from pw_storage.broker import telegram_enabled
from pw_storage.config import HOME, PROFILES, Profile
from pw_storage.recovery import RecoveryKdf, WrongRecovery
from pw_storage.second_factor import new_totp_secret
from pw_storage.vault import Kdf, Vault, VaultError, WrongPassword
from pw_storage.window import SecretEntry, apply_style
from tests.test_catalog import FakeTpm


def masks(window):
    """Маска каждого поля ввода сверху вниз, включая поля с глазком."""
    out = []
    for widget in window.body.winfo_children():
        entry = widget.entry if isinstance(widget, SecretEntry) else widget
        if entry.winfo_class() == "TEntry":
            out.append(entry.cget("show"))
    return out


ANSWER = "Зелёная лодка уплыла за старую мельницу"
FAST_RECOVERY = RecoveryKdf(16, 1, 1)


class AdminTest(unittest.TestCase):
    def test_tools_are_bound_to_test_profile(self):
        self.assertEqual(admin.PROFILE.name, "test")
        self.assertEqual(admin.PROFILE.data, HOME / "test_data")
        self.assertNotEqual(admin.PROFILE.vault, PROFILES["main"].vault)
        self.assertTrue(admin.PROFILE.catalog_key.startswith("PW_STORAGE_TEST_"))

    def test_seed_has_comments_and_no_values(self):
        for group, service, key, comment, projects, shared in admin.SEED:
            self.assertTrue(comment.startswith("Тест:"), comment)
            self.assertIn(group, projects)
        self.assertEqual(len(admin.SEED[0]), 6)
        self.assertTrue(any(shared for *_, shared in admin.SEED), "нужна строка с ALL для пробы")

    def test_parse_projects(self):
        self.assertEqual(admin.parse_projects("DELTA, COMMON all"), (("DELTA", "COMMON"), True))
        self.assertEqual(admin.parse_projects("DELTA"), (("DELTA",), False))
        with self.assertRaises(VaultError):
            admin.parse_projects("ALL")

    def test_demo_script_prints_no_values(self):
        text = admin.DEMO.format(home=str(HOME), foreign=("Маркет", "password"))
        compile(text, "demo.py", "exec")
        self.assertNotIn("print(value", text)
        self.assertIn("len(value)", text)

    def test_main_paths_are_separate(self):
        main, test = PROFILES["main"], PROFILES["test"]
        self.assertNotEqual(main.pipe, test.pipe)
        self.assertNotEqual(main.catalog_key, test.catalog_key)
        self.assertNotEqual(Path(main.audit), Path(test.audit))


class MainProfileTest(unittest.TestCase):
    """Боевой профиль только на временных путях с подменным TPM; настоящие данные не затрагиваются."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="pwtest"))
        self.profile = Profile(name="main", data=self.dir / "data", logs=self.dir / "logs",
                               projects_root=self.dir / "projects", pipe="unused", catalog_key="UNUSED")
        patches = (mock.patch.object(admin, "PROFILE", self.profile), mock.patch.object(admin, "TpmKey", lambda _: FakeTpm()))
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.addCleanup(shutil.rmtree, self.dir, True)

    def create(self, password="test-password-long"):
        return admin.create_main_vault(password, new_totp_secret(), "Какой вопрос?", ANSWER, Kdf(16, 1, 1),
                                       FAST_RECOVERY)

    def test_main_vault_has_no_seed_or_demo_projects(self):
        self.profile.projects_root.mkdir(parents=True)
        part = self.create()
        vault = Vault.open(self.profile.vault, "test-password-long")
        self.assertEqual(vault.rows(), [], "боевое хранилище создаётся пустым")
        self.assertEqual(recovery.recover(admin._read_recovery(), ANSWER, part), "test-password-long")
        self.assertEqual(sorted(p.name for p in self.profile.projects_root.iterdir()), [], "демо-проекты не пишутся")

    def test_window_titles_hide_test_mark_for_main(self):
        self.root = tk.Tk()
        self.root.withdraw()
        apply_style(self.root)
        self.addCleanup(self.root.destroy)
        window = admin.SetupWindow(self.root, create=admin.create_main_vault, take_focus=False)
        self.addCleanup(lambda: (window.close(), gc.collect()))
        self.assertNotIn("ТЕСТ", window.win.title())
        self.assertEqual(admin._mark(), "")

    def test_window_titles_keep_test_mark_for_test(self):
        self.root = tk.Tk()
        self.root.withdraw()
        apply_style(self.root)
        self.addCleanup(self.root.destroy)
        test_profile = Profile(name="test", data=self.profile.data, logs=self.profile.logs,
                               projects_root=self.profile.projects_root, pipe="unused", catalog_key="UNUSED")
        with mock.patch.object(admin, "PROFILE", test_profile):
            window = admin.SetupWindow(self.root, create=admin.create_test_vault, take_focus=False)
            self.addCleanup(lambda: (window.close(), gc.collect()))
            self.assertIn("(ТЕСТ)", window.win.title())
            self.assertEqual(admin._mark(), " (ТЕСТ)")

    def test_reset_refuses_non_test_profile(self):
        self.profile.data.mkdir(parents=True)
        sentinel = self.profile.data / "sentinel.txt"
        sentinel.write_text("keep", encoding="utf-8")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(admin.reset(), 1)
        self.assertIn("не удаляются", out.getvalue())
        self.assertTrue(sentinel.exists(), "данные боевого профиля не удаляются")


class TelegramSettingTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="pwtest"))
        self.profile = Profile(name="test", data=self.dir / "data", logs=self.dir / "logs",
                               projects_root=self.dir / "projects", pipe="unused", catalog_key="UNUSED")
        patches = (mock.patch.object(admin, "PROFILE", self.profile), mock.patch.object(admin, "TpmKey", lambda _: FakeTpm()))
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.addCleanup(shutil.rmtree, self.dir, True)

    def create(self, password="test-password-long"):
        return admin.create_test_vault(password, new_totp_secret(), "Какой вопрос?", ANSWER, Kdf(16, 1, 1), FAST_RECOVERY)

    def test_recovery_file_written_and_part_not_on_disk(self):
        part = self.create()
        self.assertTrue(self.profile.recovery.exists())
        for path in self.dir.rglob("*"):
            if path.is_file():
                self.assertNotIn(part.encode(), path.read_bytes())

    def test_recover_changes_password_and_reissues(self):
        part = self.create()
        new_part = admin.recover_test_vault(ANSWER, part, "new-test-password", FAST_RECOVERY)
        self.assertNotEqual(new_part, part)
        self.assertEqual(len(Vault.open(self.profile.vault, "new-test-password").rows()), len(admin.SEED))
        with self.assertRaises(WrongPassword):
            Vault.open(self.profile.vault, "test-password-long")
        self.assertFalse(self.profile.vault.with_name("vault.kdbx.bak").exists())
        with self.assertRaises(WrongRecovery):
            admin.recover_test_vault(ANSWER, part, "another-password", FAST_RECOVERY)
        admin.recover_test_vault(ANSWER, new_part, "another-password", FAST_RECOVERY)
        Vault.open(self.profile.vault, "another-password")

    def test_passwd_changes_password_and_reissues(self):
        part = self.create()
        remote_file = self.profile.remote
        remote_file.write_bytes(b"old code file")
        new_part = admin.change_test_password("test-password-long", "new-test-password", ANSWER, FAST_RECOVERY)
        self.assertNotEqual(new_part, part)
        Vault.open(self.profile.vault, "new-test-password")
        with self.assertRaises(WrongPassword):
            Vault.open(self.profile.vault, "test-password-long")
        self.assertFalse(self.profile.vault.with_name("vault.kdbx.bak").exists())
        self.assertFalse(remote_file.exists())
        with self.assertRaises(WrongRecovery):
            admin.recover_test_vault(ANSWER, part, "x-test-password", FAST_RECOVERY)
        admin.recover_test_vault(ANSWER, new_part, "another-password", FAST_RECOVERY)

    def test_passwd_needs_current_password(self):
        self.create()
        before = self.profile.recovery.read_bytes()
        with self.assertRaises(WrongPassword):
            admin.change_test_password("wrong-password", "new-test-password", ANSWER, FAST_RECOVERY)
        self.assertEqual(self.profile.recovery.read_bytes(), before)
        Vault.open(self.profile.vault, "test-password-long")

    def test_reissue_with_password_replaces_part(self):
        old = self.create()
        new = admin.reissue_test_part("test-password-long", ANSWER, FAST_RECOVERY)
        with self.assertRaises(WrongRecovery):
            admin.recover_test_vault(ANSWER, old, "new-test-password", FAST_RECOVERY)
        admin.recover_test_vault(ANSWER, new, "new-test-password", FAST_RECOVERY)
        Vault.open(self.profile.vault, "new-test-password")

    def test_reissue_needs_correct_password(self):
        old = self.create()
        before = self.profile.recovery.read_bytes()
        with self.assertRaises(WrongPassword):
            admin.reissue_test_part("wrong-password", ANSWER, FAST_RECOVERY)
        self.assertEqual(self.profile.recovery.read_bytes(), before)
        self.assertTrue(old)

    def test_add_secret_reaches_vault_and_catalog_without_plain_value(self):
        self.create()
        admin.add_test_secret("test-password-long", "DEMO_A ALL", "Камеры", "token", "TEST-new-value", "Камеры Neocam")
        vault = Vault.open(self.profile.vault, "test-password-long")
        row = next(r for r in vault.rows() if r.service == "Камеры")
        self.assertEqual((row.group, row.projects, row.shared), ("DEMO_A", ("DEMO_A",), True))
        self.assertEqual(vault.value(row.uid), "TEST-new-value")
        for path in self.dir.rglob("*"):
            if path.is_file():
                self.assertNotIn(b"TEST-new-value", path.read_bytes())

    def test_add_secret_requires_password(self):
        self.create()
        with self.assertRaises(WrongPassword):
            admin.add_test_secret("wrong-password", "DEMO_A", "Камеры", "token", "TEST-x", "Камеры")

    def test_wrong_answer_changes_nothing(self):
        part = self.create()
        before = self.profile.vault.read_bytes()
        with self.assertRaises(WrongRecovery):
            admin.recover_test_vault("Совсем другая длинная фраза для проверки", part, "new-test-password", FAST_RECOVERY)
        self.assertEqual(self.profile.vault.read_bytes(), before)

    def test_password_transaction_resumes_after_each_rename_boundary(self):
        for boundary in range(1, 5):
            with self.subTest(boundary=boundary):
                shutil.rmtree(self.profile.data, ignore_errors=True)
                self.create()
                rename = vault_module.os.rename
                count = 0

                def interrupted(source, target):
                    nonlocal count
                    result = rename(source, target)
                    count += 1
                    if count == boundary:
                        raise OSError("synthetic interruption")
                    return result

                with mock.patch.object(vault_module.os, "rename", side_effect=interrupted):
                    with self.assertRaises(OSError):
                        admin.change_test_password("test-password-long", "new-test-password", ANSWER, FAST_RECOVERY)
                reopened = Vault.open(self.profile.vault, "new-test-password")
                part = reopened.system_value("recovery_part")
                self.assertEqual(recovery.recover(admin._read_recovery(), ANSWER, part), "new-test-password")
                self.assertFalse(self.profile.vault.with_name("vault.kdbx.bak").exists())
                self.assertFalse(vault_module._transaction_path(self.profile.vault).exists())
                self.assertFalse(list(self.profile.data.glob("*.claim")))
                self.assertFalse(list(self.profile.data.glob("*.stage")))

    def test_setup_resumes_without_partial_seed_or_system_records(self):
        install = vault_module._install_item
        count = 0

        def interrupted(folder, item):
            nonlocal count
            install(folder, item)
            count += 1
            if count == 1:
                raise OSError("synthetic setup interruption")

        with mock.patch.object(vault_module, "_install_item", side_effect=interrupted):
            with self.assertRaises(OSError):
                self.create()
        Vault.resume(self.profile.vault)
        vault = Vault.open(self.profile.vault, "test-password-long")
        self.assertEqual(len(vault.rows()), len(admin.SEED))
        self.assertTrue(vault.system_value("totp"))
        part = vault.system_value("recovery_part")
        self.assertEqual(recovery.recover(admin._read_recovery(), ANSWER, part), "test-password-long")

    def test_reissue_resumes_to_matching_stored_part(self):
        self.create()
        install = vault_module._install_item
        count = 0

        def interrupted(folder, item):
            nonlocal count
            count += 1
            if count == 2:
                raise OSError("synthetic reissue interruption")
            install(folder, item)

        with mock.patch.object(vault_module, "_install_item", side_effect=interrupted):
            with self.assertRaises(OSError):
                admin.reissue_test_part("test-password-long", ANSWER, FAST_RECOVERY)
        blob = admin._read_recovery()
        vault = Vault.open(self.profile.vault, "test-password-long")
        self.assertEqual(recovery.recover(blob, ANSWER, vault.system_value("recovery_part")), "test-password-long")

    def test_tpm_cleanup_failure_does_not_break_recovery_pair(self):
        self.create()
        with mock.patch.object(admin.remote, "forget", side_effect=RuntimeError("synthetic TPM failure")):
            with self.assertRaises(admin.RecoveryCommitted):
                admin.change_test_password("test-password-long", "new-test-password", ANSWER, FAST_RECOVERY)
        vault = Vault.open(self.profile.vault, "new-test-password")
        self.assertEqual(recovery.recover(admin._read_recovery(), ANSWER, vault.system_value("recovery_part")),
                         "new-test-password")
        self.assertFalse(self.profile.remote.exists())

    def test_cleanup_failure_reports_committed_part_then_resumes(self):
        self.create()
        unlink = Path.unlink
        journal = vault_module._transaction_path(self.profile.vault)

        def failed(path, *args, **kwargs):
            if path == journal:
                raise OSError("synthetic cleanup failure")
            return unlink(path, *args, **kwargs)

        with mock.patch.object(Path, "unlink", autospec=True, side_effect=failed):
            with self.assertRaises(admin.RecoveryCommitted) as outcome:
                admin.change_test_password("test-password-long", "new-test-password", ANSWER, FAST_RECOVERY)
        vault = Vault.open(self.profile.vault, "new-test-password")
        self.assertEqual(vault.system_value("recovery_part"), outcome.exception.part)
        self.assertEqual(recovery.recover(admin._read_recovery(), ANSWER, outcome.exception.part), "new-test-password")
        self.assertFalse(journal.exists())

    def test_changed_recovery_is_not_replaced_by_stale_generation(self):
        self.create()
        vault = Vault.open(self.profile.vault, "test-password-long")
        _, previous = admin._recovery_snapshot()
        new_blob, new_part = recovery.issue("test-password-long", "Какой вопрос?", ANSWER, FAST_RECOVERY)
        other_blob, _ = recovery.issue("test-password-long", "Другой вопрос?", ANSWER, FAST_RECOVERY)
        self.profile.recovery.write_bytes(other_blob)
        original = self.profile.vault.read_bytes()
        vault.set_system_value("recovery_part", new_part)
        with self.assertRaises(vault_module.VaultChanged):
            admin._save_recovery(vault, new_blob, previous)
        self.assertEqual(self.profile.vault.read_bytes(), original)
        self.assertEqual(self.profile.recovery.read_bytes(), other_blob)

    def test_off_by_default(self):
        self.create()
        self.assertFalse(telegram_enabled(self.profile))

    def test_on_before_setup_survives_creation(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(admin.telegram("on"), 0)
        self.assertTrue(telegram_enabled(self.profile))
        self.create()
        self.assertTrue(telegram_enabled(self.profile))

    def test_off_after_on(self):
        with contextlib.redirect_stdout(io.StringIO()):
            admin.telegram("on")
            admin.telegram("off")
        self.assertFalse(telegram_enabled(self.profile))


class SetupWindowTest(unittest.TestCase):
    PASSWORD = "test-password-long"

    def setUp(self):
        self.root = tk.Tk()
        self.root.withdraw()
        apply_style(self.root)
        self.created = []
        self.fail = None
        self.window = admin.SetupWindow(self.root, create=self._create, take_focus=False)

    def tearDown(self):
        self.root.after_cancel(self.window.poll_id)
        self.root.update()
        self.root.destroy()
        self.window = None
        gc.collect()

    def _create(self, password, secret, question, answer):
        if self.fail:
            raise self.fail
        self.created.append((password, secret, question, answer))
        return "PART TEST"

    def _fill(self, password=PASSWORD, repeat=PASSWORD, code=None, answer=ANSWER):
        self.window.password.set(password)
        self.window.repeat.set(repeat)
        self.window.question.set("Какой вопрос?")
        self.window.answer.set(answer)
        self.window.code.set(pyotp.TOTP(self.window.secret).now() if code is None else code)
        self.window.action_button.invoke()

    def test_short_answer(self):
        self._fill(answer="Москва")
        self.assertIn("короче", self.window.message.cget("text"))
        self.assertEqual(self.created, [])

    def test_part_shown_after_creation_and_button_closes(self):
        self._fill()
        self._pump(lambda: hasattr(self.window, "part_var"))
        self.assertEqual(self.window.part_var.get(), "PART TEST")
        self.assertEqual(self.window.action_button.cget("text"), "Закрыть")

    def _pump(self, until):
        deadline = time.monotonic() + 5
        while not until():
            self.assertLess(time.monotonic(), deadline)
            self.root.update()
            time.sleep(0.005)

    def test_close_waits_for_active_write_and_worker_is_non_daemon(self):
        started = threading.Event()
        release = threading.Event()
        workers = []

        def work(*args):
            workers.append(threading.current_thread())
            started.set()
            if not release.wait(5):
                raise RuntimeError("synthetic barrier timeout")
            return "PART TEST"

        self.window.create = work
        self._fill()
        try:
            self.assertTrue(started.wait(5))
            self.assertFalse(workers[0].daemon)
            with mock.patch.object(self.root, "quit") as quit_root:
                self.window.close()
                quit_root.assert_not_called()
            self.assertTrue(self.window.win.winfo_exists())
            self.assertIn("Дождитесь", self.window.message.cget("text"))
        finally:
            release.set()
            workers[0].join(5)
        self._pump(lambda: hasattr(self.window, "part_var"))
        with mock.patch.object(self.root, "quit") as quit_root:
            self.window.close()
            quit_root.assert_called_once()
        self.assertNotIn(self.window.poll_id, self.root.tk.call("after", "info"))

    def test_short_password(self):
        self._fill(password="short", repeat="short")
        self.assertIn("короче", self.window.message.cget("text"))
        self.assertEqual(self.created, [])

    def test_passwords_must_match(self):
        self._fill(repeat="another-password-long")
        self.assertIn("не совпадают", self.window.message.cget("text"))
        self.assertEqual(self.created, [])

    def test_wrong_code(self):
        self._fill(code="000000" if pyotp.TOTP(self.window.secret).now() != "000000" else "111111")
        self.assertIn("Код не подошёл", self.window.message.cget("text"))
        self.assertEqual(self.created, [])
        self.assertEqual(self.window.password.get(), self.PASSWORD)

    def test_creates_and_clears_fields(self):
        self._fill()
        self._pump(lambda: self.window.ok)
        self.assertEqual(self.created, [(self.PASSWORD, self.window.secret, "Какой вопрос?", ANSWER)])
        self.assertEqual((self.window.password.get(), self.window.repeat.get(), self.window.answer.get(), self.window.code.get()),
                         ("", "", "", ""))

    def test_failure_shows_only_kind_and_allows_retry(self):
        self.fail = RuntimeError("подробности с содержимым")
        self._fill()
        self._pump(lambda: "RuntimeError" in self.window.message.cget("text"))
        self.assertNotIn("подробности", self.window.message.cget("text"))
        self.assertFalse(self.window.ok)
        self.assertEqual(str(self.window.action_button["state"]), "normal")

    def test_committed_warning_shows_new_part_without_retrying_write(self):
        self.fail = admin.RecoveryCommitted("PART TEST", "synthetic cleanup")
        self._fill()
        self._pump(lambda: hasattr(self.window, "part_var"))
        self.assertTrue(self.window.ok)
        self.assertEqual(self.window.part_var.get(), "PART TEST")
        self.assertIn("Изменения записаны", self.window.message.cget("text"))
        self.assertEqual(self.window.action_button.cget("text"), "Закрыть")

    def test_secret_is_shown_for_the_authenticator(self):
        self.assertEqual(self.window.secret_var.get().replace(" ", ""), self.window.secret)

    def test_snapshot(self):
        from tests.shot import snapshot

        self.window.win.update()
        snapshot(self.window.win, "new-vault.png")


class SmallWindowsTest(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        self.root.withdraw()
        apply_style(self.root)
        self.calls = []
        self.fail = None

    def tearDown(self):
        self.root.after_cancel(self.window.poll_id)
        self.root.update()
        self.root.destroy()
        self.window = None
        gc.collect()

    def _work(self, *args):
        if self.fail:
            raise self.fail
        self.calls.append(args)
        return "NEW PART"

    def _pump(self, until):
        deadline = time.monotonic() + 5
        while not until():
            self.assertLess(time.monotonic(), deadline)
            self.root.update()
            time.sleep(0.005)

    def _fill_add(self, comment="Камеры Neocam"):
        for var, text in ((self.window.password, "test-pw"), (self.window.scope, "DEMO_A"), (self.window.service, "Камеры"),
                          (self.window.key, "token"), (self.window.value, " значение с пробелом "), (self.window.comment, comment)):
            var.set(text)
        self.window.action_button.invoke()

    def test_add_passes_fields_and_clears_secrets(self):
        self.window = admin.AddSecretWindow(self.root, work=self._work, take_focus=False)
        self._fill_add()
        self.assertEqual((self.window.password.get(), self.window.value.get()), ("", ""))
        self._pump(lambda: self.calls and self.window.ok)
        self.root.update()
        self.root.after(150, self.root.quit)
        self.root.mainloop()
        self.assertEqual(self.calls, [("test-pw", "DEMO_A", "Камеры", "token", " значение с пробелом ", "Камеры Neocam")])
        self.assertEqual(self.window.action_button.cget("text"), "Закрыть")

    def test_add_requires_all_fields(self):
        self.window = admin.AddSecretWindow(self.root, work=self._work, take_focus=False)
        self._fill_add(comment="   ")
        self.assertIn("все поля", self.window.message.cget("text"))
        self.assertEqual(self.calls, [])

    def test_add_value_is_masked(self):
        self.window = admin.AddSecretWindow(self.root, work=self._work, take_focus=False)
        self.assertEqual(masks(self.window), ["•", "", "", "", "•", ""])
        from tests.shot import snapshot

        self.window.win.update()
        snapshot(self.window.win, "add-secret.png")

    def test_reissue_shows_new_part(self):
        self.window = admin.ReissueWindow(self.root, "Какой вопрос?", work=self._work, take_focus=False)
        self.window.password.set("test-pw")
        self.window.answer.set(ANSWER)
        self.window.action_button.invoke()
        self._pump(lambda: hasattr(self.window, "part_var"))
        self.assertEqual(self.calls, [("test-pw", ANSWER)])
        self.assertEqual(self.window.part_var.get(), "NEW PART")

    def test_wrong_password_message_allows_retry(self):
        self.fail = WrongPassword("Неверный пароль")
        self.window = admin.ReissueWindow(self.root, "Какой вопрос?", work=self._work, take_focus=False)
        self.window.password.set("x")
        self.window.answer.set(ANSWER)
        self.window.action_button.invoke()
        self._pump(lambda: "Неверный пароль" in self.window.message.cget("text"))
        self.assertEqual(str(self.window.action_button["state"]), "normal")


class PasswdWindowTest(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        self.root.withdraw()
        self.calls = []
        self.closed = []
        self.window = admin.PasswdWindow(self.root, "Какой вопрос?", work=self._work, take_focus=False,
                                         on_close=self.closed.append)

    def tearDown(self):
        if self.window.win.winfo_exists():
            self.root.after_cancel(self.window.poll_id)
        self.root.update()
        self.root.destroy()
        self.window = None
        gc.collect()

    def _work(self, old, new, answer):
        self.calls.append((old, new, answer))
        return "NEW PART"

    def _fill(self, old="old-test-password", new="new-test-password", repeat="new-test-password"):
        self.window.old.set(old)
        self.window.password.set(new)
        self.window.repeat.set(repeat)
        self.window.answer.set(ANSWER)
        self.window.action_button.invoke()

    def test_changes_and_clears_fields(self):
        self._fill()
        deadline = time.monotonic() + 5
        while not hasattr(self.window, "part_var"):
            self.assertLess(time.monotonic(), deadline)
            self.root.update()
            time.sleep(0.005)
        self.assertEqual(self.calls, [("old-test-password", "new-test-password", ANSWER)])
        self.assertEqual((self.window.old.get(), self.window.password.get()), ("", ""))

    def test_same_password_is_refused(self):
        self._fill(old="same-test-password", new="same-test-password", repeat="same-test-password")
        self.assertIn("совпадает", self.window.message.cget("text"))
        self.assertEqual(self.calls, [])

    def test_close_calls_back_instead_of_quitting(self):
        self.window.close()
        self.assertEqual(self.closed, [False])
        self.assertFalse(self.window.win.winfo_exists())


class RecoveryWindowTest(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        self.root.withdraw()
        apply_style(self.root)
        self.calls = []
        self.fail = None
        keeper = "keeper@example.test"  # адрес берётся из settings.json, в тестах — подставной
        with mock.patch.object(admin, "recovery_mail", return_value=keeper):
            self.window = admin.RecoveryWindow(self.root, "Какой вопрос?", work=self._work, take_focus=False)

    def tearDown(self):
        self.root.after_cancel(self.window.poll_id)
        self.root.update()
        self.root.destroy()
        self.window = None
        gc.collect()

    def _work(self, answer, part, password):
        if self.fail:
            raise self.fail
        self.calls.append((answer, part, password))
        return "NEW PART"

    def _fill(self, password="new-test-password", repeat="new-test-password"):
        self.window.answer.set(ANSWER)
        self.window.key_part.set("AAAA BBBB")
        self.window.password.set(password)
        self.window.repeat.set(repeat)
        self.window.action_button.invoke()

    def _pump(self, until):
        deadline = time.monotonic() + 5
        while not until():
            self.assertLess(time.monotonic(), deadline)
            self.root.update()
            time.sleep(0.005)

    def test_question_is_shown(self):
        texts = [w.cget("text") for w in self.window.body.winfo_children() if w.winfo_class() in ("TLabel", "Label")]
        self.assertIn("Вопрос: Какой вопрос?", texts)
        self.assertTrue(any("keeper@example.test" in t for t in texts))

    def test_answer_and_password_are_masked(self):
        self.assertEqual(masks(self.window), ["•", "", "•", "•"])

    def test_eye_shows_and_hides_each_secret_field(self):
        fields = [w for w in self.window.body.winfo_children() if isinstance(w, SecretEntry)]
        self.assertEqual(len(fields), 3)
        self.window.win.update()
        for field in fields:
            field.eye.event_generate("<Button-1>")
            self.root.update()
            self.assertEqual(field.entry.cget("show"), "")
            field.eye.event_generate("<Button-1>")
            self.root.update()
            self.assertEqual(field.entry.cget("show"), "•")

    def test_passwords_must_match(self):
        self._fill(repeat="another-password")
        self.assertIn("не совпадают", self.window.message.cget("text"))
        self.assertEqual(self.calls, [])

    def test_success_shows_new_part_and_clears_fields(self):
        self._fill()
        self._pump(lambda: hasattr(self.window, "part_var"))
        self.assertEqual(self.calls, [(ANSWER, "AAAA BBBB", "new-test-password")])
        self.assertEqual(self.window.part_var.get(), "NEW PART")
        self.assertEqual(self.window.answer.get(), "")

    def test_wrong_recovery_message_allows_retry(self):
        self.fail = WrongRecovery("Ответ или часть из письма не подошли")
        self._fill()
        self._pump(lambda: "не подошли" in self.window.message.cget("text"))
        self.assertEqual(str(self.window.action_button["state"]), "normal")

    def test_snapshot(self):
        from tests.shot import snapshot

        self.window.win.update()
        snapshot(self.window.win, "recover.png")


if __name__ == "__main__":
    unittest.main()
