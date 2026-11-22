"""Команды для сессий проектов. Запускать из папки проекта: проект определяет посредник.

  python pw.py list                     строки, которые можно запросить: номер и комментарий;
                                        с доступом — ещё сервис и ключ одобренных строк
  python pw.py open --why "зачем" N1 N2  запросить строки: откроется окно, решает владелец
  python pw.py status                   есть ли доступ и до какого времени
  python pw.py report                   какие ключи проект уже взял
  python pw.py close                    закрыть доступ всему проекту

Клиент идёт к посреднику этого ПК, так что запускать можно из любой папки — важна папка проекта.
Просить только то, что действительно нужно сейчас (Т26). «Зачем» видит владелец в окне и в боте.
Необязательно: --profile test (тестовое хранилище). Команды, выводящей значения, нет и не будет:
значение получает только скрипт, которому оно нужно, через pw_storage.client.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from pw_storage.client import BrokerUnavailable, NeedsAccess, PwClient, PwError  # noqa: E402


def print_preview(answer: dict, granted: set[str] = frozenset()) -> None:
    project = answer["project"]
    if answer["state"] == "missing":
        print("Перечня строк нет на этом ПК. Запросите pw.py open --why \"зачем\" без номеров: "
              "владелец соберёт перечень паролем, затем запросите строки снова.")
        return
    if answer["state"] == "stale":
        print("Перечень устарел: хранилище менялось после его сборки, список может быть неточным.")
    groups = ((f"Проект {project}", answer["own"]),
              (f"Из ALL (одобрение добавит {project} в список записи)", answer["common"]))
    for title, items in groups:
        items = [item for item in items if item["id"] not in granted]
        print(f"{title}:")
        for item in items or [{"id": "", "comment": "нет строк"}]:
            print(f"  {item['id']:8}  {item['comment']}")
    if answer.get("unnamed"):
        print(f"Строк без комментария: {answer['unnamed']}. Они не выдаются, пока владелец не добавит комментарий.")
    print('Запрос: pw.py open --why "зачем" <номера через пробел>')


def print_list(client: PwClient) -> None:
    try:
        rows = client.rows()
    except (NeedsAccess, BrokerUnavailable):
        rows = []
    if rows:
        print("Одобрено всем сессиям проекта:")
        for row in rows:
            source = "ALL, " if row["all"] else ""
            print(f"  {row['id']:8}  {row['service']} / {row['key']} — {row['comment']} ({source}есть доступ)")
        print("Можно запросить ещё:")
    else:
        print("Доступа нет. Строки, которые может запросить проект (имена ключей видны после доступа):")
    print_preview(client.preview(), {row["id"] for row in rows})


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="Доступ к хранилищу PW_STORAGE")
    parser.add_argument("command", choices=("open", "status", "list", "report", "close"))
    parser.add_argument("rows", nargs="*", help="номера строк из pw.py list (для open)")
    parser.add_argument("--why", default="", help="зачем нужны строки: видит владелец (для open)")
    parser.add_argument("--profile", choices=("main", "test"), default="main")
    args = parser.parse_intermixed_args()  # номера строк принимаются и до, и после --why
    if args.command != "open" and args.rows:
        parser.error("номера строк нужны только для open")
    if args.command == "open" and not args.why.strip():
        parser.error('для open нужно --why "зачем": владелец видит это в окне')
    client = PwClient(profile=args.profile)
    try:
        if args.command == "open":
            answer = client.open(args.rows, args.why)
            print(f"Доступ выдан: {answer.get('project')} до {answer.get('expires')}")
            if answer.get("rows") is not None:
                print("Одобрены строки:", " ".join(answer["rows"]))
                refused = [uid for uid in args.rows if uid.lower() not in answer["rows"]]
                if refused:
                    print("Владелец не одобрил:", " ".join(refused))
        elif args.command == "status":
            answer = client.status()
            if answer["granted"]:
                print(f"Доступ есть: {answer['project']} до {answer['expires']}")
            else:
                print(f"Доступа нет: {answer['project']}")
        elif args.command == "list":
            print_list(client)
        elif args.command == "report":
            issued = client.report()
            if not issued:
                print("Проект ещё не брал ключей.")
            for item in issued:
                print(f"{item['time']} {item['id']} {item['service']} / {item['key']}")
        elif args.command == "close":
            print("Доступ закрыт." if client.close()["closed"] else "Доступа не было.")
    except PwError as e:
        print(f"Не вышло: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
