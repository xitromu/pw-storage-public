"""Снимки окон для документации: docs/screenshots/*.png.

  .venv\\Scripts\\python.exe tools\\make_screenshots.py

Как это работает: окно нельзя снять «снаружи», поэтому съемку делают сами тесты — они ловят
переменную окружения PW_STORAGE_SHOTS (см. tests/shot.py). Без неё тесты ничего не пишут, так что
обычный прогон тестов от этого инструмента не зависит.

Данных настоящих здесь нет: все окна строятся на фикстурах из tests (Такси, Маркет, Погода, значения с
префиксом TEST-). Файлы, которые уже есть, перезаписываются.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "docs" / "screenshots"
SHOTS = ("new-vault.png", "add-secret.png", "recover.png", "export.png", "access-request.png",
         "access-confirm.png", "admin-matrix.png", "record.png", "cleanup.png", "projects.png")
TESTS = (
    "tests.test_admin.SetupWindowTest.test_snapshot",
    "tests.test_admin.SmallWindowsTest.test_add_value_is_masked",
    "tests.test_admin.RecoveryWindowTest.test_snapshot",
    "tests.test_export.ExportWindowTest.test_documentation_screenshot",
    "tests.test_window.WindowCase.test_documentation_screenshots",
    "tests.test_manage.WindowTest.test_documentation_screenshot",
    "tests.test_cleanup.WindowsTest.test_documentation_screenshots",
    "tests.test_projects.WindowTest.test_documentation_screenshot",
)


def main() -> int:
    if not OUT.is_dir():
        OUT.mkdir(parents=True)
    env = {**os.environ, "PW_STORAGE_SHOTS": str(OUT), "PW_STORAGE_REAL_TPM": "0",
           "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}
    done = subprocess.run([sys.executable, "-X", "utf8", "-m", "unittest", *TESTS],
                          cwd=str(REPO), env=env)
    missing = [name for name in SHOTS if not (OUT / name).exists()]
    for name in SHOTS:
        path = OUT / name
        print(f"{name:22} {'нет' if not path.exists() else f'{path.stat().st_size // 1024} КиБ'}")
    if done.returncode or missing:
        print(f"Не хватает: {', '.join(missing)}" if missing else "Тесты снимок прошли с ошибкой.")
        return 1
    print(f"\nГотово: {len(SHOTS)} файлов в {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
