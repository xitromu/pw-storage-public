"""Перевыпуск пакетов секретов служб: манифест → пакет → перезапуск службы.

  python tools/provision_services.py [deploy\\services\\my_service.json ...]

Без аргументов — все манифесты из deploy\\services\\: файлы `*.json`, кроме `*.launch.json`
(это описание процесса) и `*.example.json` (образцы с заглушками).

Требуются права администратора: пакеты лежат в ProgramData, а управлением службами занимается SCM.
Значений секретов скрипт не печатает — он только передаёт файлы конфигураций модулям pw_storage.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PYTHON = REPO / ".venv" / "Scripts" / "python.exe"
SERVICES = REPO / "deploy" / "services"


class ProvisionError(Exception):
    pass


def manifests(paths: list[Path]) -> list[Path]:
    if paths:
        return [Path(p) for p in paths]
    if not SERVICES.is_dir():
        return []
    return sorted(p for p in SERVICES.glob("*.json")
                  if not p.name.endswith((".launch.json", ".example.json")))


def service_name(path: Path) -> str:
    try:
        name = json.loads(path.read_text(encoding="utf-8"))["name"]
    except (OSError, ValueError, KeyError) as error:
        raise ProvisionError(f"Не удалось прочитать имя службы из {path.name}") from error
    if not isinstance(name, str) or not name.strip():
        raise ProvisionError(f"В {path.name} нет непустого поля name")
    return name.strip().upper()


def run(module_args: list[str]) -> None:
    done = subprocess.run([str(PYTHON), "-X", "utf8", "-m", *module_args], cwd=str(REPO))
    if done.returncode:
        raise ProvisionError(f"Не вышло: {' '.join(module_args[:2])} (код {done.returncode})")


def reissue(manifest: Path) -> None:
    name = service_name(manifest)
    print(f"\n--- {name}: пакет по {manifest} ---")
    run(["pw_storage.service_store", "provision", str(manifest), "--apply"])
    print(f"--- {name}: перезапуск ---")
    run(["pw_storage.service_host", "stop", "--name", name, "--apply"])
    time.sleep(2)  # SCM снимает процесс не мгновенно: старт сразу за стопом иногда отвергается
    run(["pw_storage.service_host", "start", "--name", name, "--apply"])
    run(["pw_storage.service_host", "status", "--name", name])


def main(argv=None) -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="Перевыпуск пакетов секретов служб.")
    parser.add_argument("manifests", nargs="*", type=Path, help="JSON-манифесты; без них — все из deploy\\services")
    args = parser.parse_args(argv)
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("Нужны права администратора: пакеты служб в ProgramData, службы ведёт SCM.\n"
              "Запусти это окно от имени администратора (из меню владельца пункт 8 поднимает UAC сам).")
        return 1
    found = manifests(args.manifests)
    if not found:
        print(f"В {SERVICES} нет манифестов. Скопируй demo_bot.example.json в my_service.json, "
              "впиши номера строк и запусти снова.")
        return 1
    failed = []
    for manifest in found:
        try:
            reissue(manifest)
        except ProvisionError as error:
            print(str(error), file=sys.stderr)
            failed.append(manifest.name)
    if failed:
        print(f"\nНе перевыпущено: {', '.join(failed)}. "
              "Эти службы продолжают работать со старым пакетом секретов.")
        return 1
    print("\nВсе перечисленные службы перевыпущены и перезапущены.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
