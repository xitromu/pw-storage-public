"""Точка входа службы Windows: SCM запускает этот файл с путём конфигурации.

Значений секретов здесь нет: ребёнок получает их только через pw_storage.service_store.
"""

import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parent
SITE = REPO / ".venv" / "Lib" / "site-packages"

if SITE.is_dir():
    sys.path.insert(0, str(SITE))
sys.path.insert(0, str(REPO))

from pw_storage.service_host import run_from_config  # noqa: E402

if len(sys.argv) != 2:
    raise SystemExit("Использование: pw_service.py <путь конфигурации службы>")
raise SystemExit(run_from_config(pathlib.Path(sys.argv[1])))
