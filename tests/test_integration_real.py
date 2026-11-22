"""Сквозная проверка на настоящем: TPM, Argon2id 1 ГиБ, канал, клиент в отдельном процессе, настоящее окно.

Запускается только явно: PW_STORAGE_REAL_TPM=1. Значения случайные, нажатия в окне программные.
Работает только с ключом PW_STORAGE_TEST_INTEGRATION и удаляет его. Снимки экранов: PW_STORAGE_SHOTS=<папка>.
"""

import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

import pyotp

from pw_storage import catalog
from pw_storage.audit import Audit
from pw_storage.broker import Broker
from pw_storage.config import HOME, TOTP_ENTRY, Profile
from pw_storage.tpm import TpmKey
from pw_storage.vault import Vault, file_version
from pw_storage.window import TkUi, make_root
from tests.test_broker import CHILD

KEY_NAME = "PW_STORAGE_TEST_INTEGRATION"
FLOW_SECONDS = 90


@unittest.skipUnless(os.environ.get("PW_STORAGE_REAL_TPM") == "1", "нужен PW_STORAGE_REAL_TPM=1")
class RealFlowTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="pwtest"))
        self.key = TpmKey(KEY_NAME)
        self.assertFalse(self.key.exists(), "тестовый ключ остался от прошлого прогона")
        self.shots = os.environ.get("PW_STORAGE_SHOTS")

    def tearDown(self):
        if self.key.exists():
            self.key.delete()
        self.assertFalse(self.key.exists())
        shutil.rmtree(self.dir, ignore_errors=True)

    def shot(self, window, name):
        if self.shots:
            from tests.shot import capture

            capture(window, str(Path(self.shots) / name))

    def test_full_flow(self):
        profile = Profile(
            name="test",
            data=self.dir / "data",
            logs=self.dir / "logs",
            projects_root=self.dir / "projects",
            pipe=rf"\\.\pipe\pw_storage_integration_{os.getpid()}",
            catalog_key=KEY_NAME,
        )
        password = secrets.token_urlsafe(24)
        totp_secret = pyotp.random_base32(32)
        values = {name: "TEST-" + secrets.token_urlsafe(24) for name in ("own", "common", "foreign")}
        vault = Vault.create(profile.vault, password)  # настоящие параметры Argon2id
        vault.put("COMMON", "Погода", "API_KEY", values["common"], "Общий ключ к сервису погоды", ("COMMON",), shared=True)
        vault.put("DEMO_A", "Такси", "login", values["own"], "Логин к личному кабинету Такси")
        vault.put("DEMO_A", "Камеры", "token", "TEST-" + secrets.token_urlsafe(8), "Камеры Neocam")
        vault.put("DEMO_B", "Маркет", "password", values["foreign"], "Пароль к личному кабинету магазина Маркет")
        vault.set_system_value(TOTP_ENTRY, totp_secret)
        vault.save()
        self.assertEqual(file_version(profile.vault), (4, 0))
        self.assertEqual(vault.kdf_algorithm, "argon2id")
        catalog.write(self.key, profile.catalog, vault.rows(), profile.vault, source_hash=vault.source_hash)
        del vault

        script = profile.projects_root / "DEMO_A" / "run.py"
        script.parent.mkdir(parents=True)
        script.write_text(CHILD, encoding="utf-8")

        root = make_root()
        ui = TkUi(root, take_focus=False)
        broker = Broker(profile, self.key, ui, audit=Audit(profile.audit, echo=False))
        broker.start()
        env = {**os.environ, "PYTHONPATH": str(HOME), "PYTHONUTF8": "1"}
        client = subprocess.Popen([sys.executable, str(script), profile.pipe], stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True, encoding="utf-8", env=env, cwd=self.dir)
        listed = typed = coded = False
        comments_before_password = ""
        deadline = time.monotonic() + FLOW_SECONDS
        try:
            while client.poll() is None:
                self.assertLess(time.monotonic(), deadline, "сквозной прогон завис")
                broker.pump()
                root.update()
                window = ui.window
                if window is None or window.finished:
                    time.sleep(0.01)
                    continue
                if not typed:
                    comments_before_password = "\n".join(text.cget("text") for _, _, _, text, _ in window.choices)
                    self.shot(window.win, "screen1.png")
                    window.password_var.set(password)
                    self.shot(window.win, "screen1_typed.png")
                    window.continue_button.invoke()
                    typed = True
                elif window.unlocked is not None and not coded:
                    root.update()
                    time.sleep(0.3)
                    root.update()
                    self.shot(window.win, "screen2.png")
                    window.code_var.set(pyotp.TOTP(totp_secret).now())
                    window.code_button.invoke()
                    coded = True
                time.sleep(0.01)
            stdout, stderr = client.communicate(timeout=10)
        finally:
            if client.poll() is None:
                client.kill()
            broker.stop()
            root.destroy()

        self.assertEqual(client.returncode, 0, stderr)
        out = json.loads(stdout)
        self.assertTrue(typed and coded)
        # Окно показало комментарии до ввода пароля: перечень расшифрован настоящим TPM.
        self.assertIn("Камеры Neocam", comments_before_password)
        self.assertIn("Общий ключ к сервису погоды", comments_before_password)
        self.assertNotIn("Маркет", comments_before_password)
        self.assertEqual(out["project"]["result"], "DEMO_A")
        self.assertTrue(out["open"]["result"], out["open"])
        self.assertEqual(out["own"]["result"], values["own"])
        self.assertEqual(out["common"]["result"], values["common"])
        self.assertEqual(out["foreign"]["error"], "NotFound")
        self.assertEqual(out["after_close"]["error"], "NeedsAccess")
        self.assertIn("взят ключ: Такси / login", stderr)

        events = [json.loads(line) for line in profile.audit.read_text(encoding="utf-8").splitlines()]
        kinds = [e["event"] for e in events]
        for expected in ("access_requested", "access_granted", "list_extended", "value_issued", "value_refused", "access_closed"):
            self.assertIn(expected, kinds)
        granted = next(e for e in events if e["event"] == "access_granted")
        self.assertEqual(granted["via"], "code")

        forbidden = [*values.values(), password, totp_secret]
        for text in (stderr,):
            for value in forbidden:
                self.assertNotIn(value, text)
        for path in self.dir.rglob("*"):
            if path.is_file():
                data = path.read_bytes()
                for value in forbidden:
                    self.assertNotIn(value.encode(), data, f"значение в открытом виде: {path.name}")


if __name__ == "__main__":
    unittest.main()
