"""Меню владельца: печать по-русски и запуск только известных команд обслуживания."""

import io
import unittest
from unittest import mock

from tools import owner_menu as menu


class RenderTest(unittest.TestCase):
    def test_menu_lists_every_mode_in_russian(self):
        text = menu.render("main")
        self.assertIn("режимы владельца (профиль main)", text)
        for key, title, _, _ in menu.ITEMS:
            self.assertIn(f"{key}  {title}", text)
        self.assertIn("0  Выход", text)

    def test_menu_names_the_profile(self):
        self.assertIn("профиль test", menu.render("test"))

    def test_no_secrets_in_render(self):
        text = menu.render("main")
        for forbidden in ("token", "пароль хранилища", "secrets.env"):
            self.assertNotIn(forbidden, text.lower())


class CommandTest(unittest.TestCase):
    def test_admin_modes_run_admin_module(self):
        plan = menu.command("1", "main")
        self.assertEqual(plan[-4:], ["pw_storage.admin", "--profile", "main", "manage"])
        self.assertEqual(plan[1:3], ["-X", "utf8"])

    def test_broker_mode_runs_broker(self):
        plan = menu.command("9", "test")
        self.assertIn("pw_storage.broker", plan)
        self.assertEqual(plan[-2:], ["--profile", "test"])

    def test_packages_mode_raises_uac_for_the_installer(self):
        plan = menu.command("8", "main")
        self.assertEqual(plan[0], "powershell")
        self.assertIn("-Verb RunAs", " ".join(plan))
        self.assertIn("provision_services.bat", " ".join(plan))

    def test_menu_accepts_lowercase_letters(self):
        self.assertEqual(menu.command("h", "main")[-1], "--help")

    def test_help_mode(self):
        self.assertEqual(menu.command("H", "main")[-1], "--help")

    def test_unknown_choice_has_no_plan(self):
        for choice in ("", "x", "11", "0", "01"):
            with self.subTest(choice=choice):
                self.assertIsNone(menu.command(choice, "main"))


class LoopTest(unittest.TestCase):
    def run_menu(self, answers, returncode=0):
        answers = list(answers)
        out = io.StringIO()
        with mock.patch.object(menu, "ask", side_effect=lambda: answers.pop(0)), \
                mock.patch.object(menu, "wait"), \
                mock.patch.object(menu.subprocess, "run",
                                  return_value=mock.Mock(returncode=returncode)), \
                mock.patch("sys.stdout", out):
            code = menu.main([])
        return code, out.getvalue()

    def test_exit_stops_immediately(self):
        code, text = self.run_menu(["0"])
        self.assertEqual(code, 0)
        self.assertEqual(text.count("режимы владельца"), 1)

    def test_bad_choice_reprints_menu(self):
        code, text = self.run_menu(["42", "0"])
        self.assertEqual(code, 0)
        self.assertIn("Нет такой команды", text)
        self.assertEqual(text.count("режимы владельца"), 2)

    def test_chosen_mode_is_started_once(self):
        code, text = self.run_menu(["3", "0"])
        self.assertEqual(code, 0)
        self.assertNotIn("кодом", text)

    def test_failing_mode_reports_code(self):
        code, text = self.run_menu(["4", "0"], returncode=2)
        self.assertEqual(code, 0)
        self.assertIn("завершилась кодом 2", text)

    def test_missing_python_stops_menu(self):
        answers = ["1"]
        out = io.StringIO()
        with mock.patch.object(menu, "ask", side_effect=lambda: answers.pop(0)), \
                mock.patch.object(menu.subprocess, "run", side_effect=OSError), \
                mock.patch("sys.stdout", out):
            code = menu.main([])
        self.assertEqual(code, 1)
        self.assertIn("Не удалось запустить окно", out.getvalue())


if __name__ == "__main__":
    unittest.main()
