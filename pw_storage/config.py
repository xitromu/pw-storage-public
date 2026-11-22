"""Пути и постоянные. Профиль main — настоящее хранилище, test — опыты на тестовых значениях."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

HOME = Path(__file__).resolve().parent.parent
PYTHON = HOME / ".venv" / "Scripts" / "python.exe"
TOOL_PATHS = (HOME / "pw.py", HOME / "pw_storage")
MAX_REMOTE_ATTEMPTS = 3  # TPM считает неверные коды и может заблокироваться: подбор отсекаем раньше него

ALL_SCOPE = "ALL"  # метка записи: другой проект может её запросить (Т26)
SYSTEM_SCOPE = "_SYSTEM"  # служебные записи: в перечень и проектам не попадают
TOTP_ENTRY = "totp"
RECOVERY_ENTRY = "recovery_part"  # часть ключа восстановления: только для выгрузки на флэшку (Т11, Т28)
MIN_ARCHIVE_PASSWORD = 20  # zip AES слабо защищён от подбора: пароль архива — длинная фраза

DEFAULT_GRANT_HOURS = 12  # Т27: значение по умолчанию, в settings.json — grant_hours
MAX_GRANT_HOURS = 8760
MAX_WHY_CHARS = 300
STALE_DAYS = 45  # окно администрирования: «давно не брали» (решение владельца 04.11.2026)
CONFIRM_SECONDS = 180  # сколько ждём подтверждения с телефона
IDLE_EXIT_SECONDS = 600  # посредник без доступов завершается и не держит файл в памяти
MAX_PASSWORD_ATTEMPTS = 5
MAX_CODE_ATTEMPTS = 5


def valid_hours(value) -> int | None:
    """Срок доступа в часах: целое от 1 до MAX_GRANT_HOURS, иначе None."""
    try:
        hours = int(str(value).strip())
    except ValueError:
        return None
    return hours if 1 <= hours <= MAX_GRANT_HOURS else None


@dataclass(frozen=True)
class Profile:
    name: str
    data: Path
    logs: Path
    projects_root: Path
    pipe: str
    catalog_key: str
    remote_key: str = "PW_STORAGE_TEST_REMOTE_UNUSED"

    @property
    def remote(self) -> Path:
        return self.data / "remote.bin"

    @property
    def vault(self) -> Path:
        return self.data / "vault.kdbx"

    @property
    def recovery(self) -> Path:
        return self.data / "recovery.json"

    @property
    def catalog(self) -> Path:
        return self.data / "catalog.bin"

    @property
    def audit(self) -> Path:
        return self.logs / "access.log"

    @property
    def settings(self) -> Path:
        return self.data / "settings.json"


def read_settings(profile: Profile) -> dict:
    """Настройки профиля из data/settings.json; нет файла или битый JSON — значения по умолчанию."""
    try:
        return json.loads(profile.settings.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


_TEST_DATA = HOME / "test_data"


def _projects_root(settings_path: Path, fallback: Path) -> Path:
    """projects_root из settings.json — тем, у кого папки проектов не на C:\\projects."""
    try:
        value = json.loads(settings_path.read_text(encoding="utf-8")).get("projects_root")
    except (OSError, ValueError):
        return fallback
    return Path(value) if value else fallback


PROFILES = {
    "main": Profile(
        name="main",
        data=HOME / "data",
        logs=HOME / "logs",
        projects_root=_projects_root(HOME / "data" / "settings.json", Path(r"C:\projects")),
        pipe=r"\\.\pipe\pw_storage",
        catalog_key="PW_STORAGE_CATALOG",
        remote_key="PW_STORAGE_REMOTE",
    ),
    "test": Profile(
        name="test",
        data=_TEST_DATA,
        logs=_TEST_DATA / "logs",
        projects_root=_TEST_DATA / "projects",
        pipe=r"\\.\pipe\pw_storage_test",
        catalog_key="PW_STORAGE_TEST_CATALOG",
        remote_key="PW_STORAGE_TEST_REMOTE",
    ),
}
