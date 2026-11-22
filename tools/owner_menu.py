"""Меню режимов владельца PW_STORAGE: печать и запуск команд обслуживания.

Сам файл .bat остаётся ASCII — русский текст печатает этот модуль, а консоль заранее
переведена в UTF-8. Значений секретов здесь нет: всё вводится в окнах pw_storage.admin.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ADMIN = "pw_storage.admin"
BROKER = "pw_storage.broker"
BAT = "!bat"
REPO = Path(__file__).resolve().parent.parent
ITEMS = (
    ("N", "Создать хранилище", (ADMIN, ("setup",)), "первый запуск: пароль, контрольный вопрос, код TOTP"),
    ("1", "Окно управления", (ADMIN, ("manage",)), "перечень строк и кто какой проект видит"),
    ("2", "Добавить секрет", (ADMIN, ("add",)), "значение вводится в окне, не в файле"),
    ("3", "Выгрузка", (ADMIN, ("export",)), "зашифрованный архив на доверенный носитель"),
    ("4", "Сменить пароль", (ADMIN, ("passwd",)), "старый пароль и новый"),
    ("5", "Новая часть ключа", (ADMIN, ("reissue",)), "пароль и ответ на вопрос"),
    ("6", "Забыл пароль", (ADMIN, ("recover",)), "понадобится ответ и часть ключа из надёжного места"),
    ("7", "Код доступа", (ADMIN, ("remote-code",)), "код для доступа через бота, когда вы не у ПК"),
    ("8", "Пакеты службам", (BAT, ("provision_services.bat",)),
     "выдать заново секреты службам из их конфигураций, затем перезапустить их"),
    ("9", "Посредник", (BROKER, ()), "запуск доступа проектам, Ctrl-C останавливает"),
    ("H", "Справка", (ADMIN, ("--help",)), "полный список команд обслуживания"),
)


def render(profile: str) -> str:
    lines = ["", f"PW_STORAGE — режимы владельца (профиль {profile})", ""]
    width = max(len(title) for _, title, _, _ in ITEMS)
    for key, title, _, note in ITEMS:
        lines.append(f"  {key}  {title:<{width}}  — {note}")
    lines.append("  0  Выход")
    lines.append("")
    return "\n".join(lines)


def elevated(script: str) -> list[str]:
    """Запуск bat с повышением прав: provision и перезапуск служб требуют администратора."""
    target = REPO / script
    command_line = (f"Start-Process -FilePath '{target}' -Verb RunAs "
                    f"-WorkingDirectory '{REPO}'")
    return ["powershell", "-NoProfile", "-Command", command_line]


def command(choice: str, profile: str) -> list[str] | None:
    for key, _, (module, args), _note in ITEMS:
        if key.upper() == choice.upper():
            if module == BAT:
                return elevated(args[0])
            base = [sys.executable, "-X", "utf8", "-m", module, "--profile", profile]
            return base if module == BROKER else base + list(args)
    return None


def ask(reader=input) -> str:
    try:
        return str(reader("Выбор: ")).strip()
    except EOFError:
        return "0"


def wait(reader=input) -> None:
    try:
        reader("Готово — нажми Enter для возврата в меню. ")
    except EOFError:
        pass


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Меню режимов владельца.")
    parser.add_argument("--profile", default="main", choices=("main", "test"))
    args = parser.parse_args(argv)
    while True:
        print(render(args.profile))
        choice = ask()
        if choice == "0":
            return 0
        plan = command(choice, args.profile)
        if plan is None:
            print("Нет такой команды. Выбери число из списка.")
            continue
        try:
            done = subprocess.run(plan)
        except OSError:
            print("Не удалось запустить окно. Проверь, что рядом папка PW_STORAGE.")
            return 1
        if done.returncode:
            print(f"Команда завершилась кодом {done.returncode}.")
        wait()


if __name__ == "__main__":
    raise SystemExit(main())
