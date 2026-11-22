"""Обслуживание хранилища: тестовый профиль по умолчанию, боевой — с --profile main.

  python -m pw_storage.admin setup          создать тестовое хранилище: пароль и код вводятся в окне
  python -m pw_storage.admin --profile main setup    создать боевое хранилище (без тестовых записей)
  python -m pw_storage.admin recover        забыт пароль: ответ, часть ключа из надёжного места, новый пароль
  python -m pw_storage.admin passwd         сменить пароль: старый пароль, новый и ответ на вопрос
  python -m pw_storage.admin reissue        часть ключа утеряна: пароль и ответ дают новую
  python -m pw_storage.admin add            новый секрет: значение вводится в окне
  python -m pw_storage.admin manage         окно администрирования: какие проекты видят какие записи
  python -m pw_storage.admin export         выгрузка на доверенную флэшку: зашифрованный архив zip
  python -m pw_storage.admin remote-code    задать код для доступа через бота, когда вы не у ПК
  python -m pw_storage.admin telegram on  включить кнопку в боте для теста (off — выключить)
  python -m pw_storage.admin reset          удалить тестовые данные и тестовый ключ TPM

--profile main допустим во всех командах. В боевом профиле reset отказывает, окна работают
без пометки «ТЕСТ»; настоящие значения записываются только через окна, в чат и журналы не попадают.
В тестовом профиле значения записей — случайные строки с приставкой TEST-.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk

from tkinter import messagebox

from . import catalog, export, recovery, remote
from .audit import Audit
from .client import BrokerUnavailable, PwClient
from .config import (ALL_SCOPE, HOME, MIN_ARCHIVE_PASSWORD, PROFILES, RECOVERY_ENTRY, TOTP_ENTRY,
                      Profile, read_settings)
from .recovery import RecoveryKdf
from .second_factor import Totp, new_totp_secret
from .tpm import TpmKey
from .vault import Vault, VaultCommitted, VaultError, _writer
from .window import UI_FONT, Dark, SecretEntry, dark_title_bar, make_root, use_dark_theme

PROFILE = PROFILES["test"]
MIN_PASSWORD = 12


def recovery_mail(profile: Profile | None = None) -> str:
    """Т11: адрес, где владелец спрятал часть ключа (settings.json, recovery_mail)."""
    return str(read_settings(profile or PROFILE).get("recovery_mail") or "").strip()


def _mark() -> str:
    """Пометка профиля в заголовках окон: тестовая видна всегда, боевая — без пометки."""
    return " (ТЕСТ)" if PROFILE.name == "test" else ""

SEED = (
    # группа, сервис, ключ, комментарий, проекты, ALL
    ("COMMON", "Погода", "API_KEY", "Тест: общий ключ к сервису погоды", ("COMMON",), True),
    ("DEMO_A", "Такси", "login", "Тест: логин к личному кабинету Такси", ("DEMO_A",), False),
    ("DEMO_A", "Такси", "password", "Тест: пароль к личному кабинету Такси", ("DEMO_A",), False),
    ("DEMO_B", "Маркет", "password", "Тест: пароль к личному кабинету магазина Маркет", ("DEMO_B",), False),
)

DEMO = '''"""Проба Т26: скрипт проекта просит свои строки и общую из ALL, берёт одобренные, пробует чужие.

Значения не печатает. Повторный запуск после одобрения общей строки покажет её среди своих строк проекта.
"""
import sys

sys.path.insert(0, {home!r})
from pw_storage.client import NotFound, PwClient, PwError

FOREIGN = {foreign!r}

sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")
pw = PwClient(profile="test")
preview = pw.preview()
if preview["state"] == "missing":
    print("Перечня нет: прошу владельца собрать его паролем, доступ при этом не выдаётся.")
    try:
        pw.open([], why="собрать перечень для пробы")
    except PwError as e:
        print("Ответ:", e)
    raise SystemExit(0)
print("Строки проекта:", [(i["id"], i["comment"]) for i in preview["own"]])
print("Строки из ALL:", [(i["id"], i["comment"]) for i in preview["common"]])
wanted = [i["id"] for i in (*preview["own"], *preview["common"])]
try:
    pw.open(["00000000"], why="проба: чужой или несуществующий номер")
    print("ОШИБКА: принят несуществующий номер")
except NotFound as e:
    print("Несуществующий номер не принят:", e)
try:
    answer = pw.open(wanted, why="проба Т26: свои строки и общая из ALL")
except PwError as e:
    print("Доступ не выдан:", e)
    raise SystemExit(1)
print("Доступ выдан:", answer["project"], "до", answer.get("expires"), "| одобрены:", answer["rows"])
print("Одобренные строки (значений здесь нет):")
for row in pw.rows():
    print(" ", row["id"], row["service"], "/", row["key"], "—", row["comment"], "(из ALL)" if row["all"] else "")
    value = pw.get(row["service"], row["key"])
    print("    получено символов:", len(value))
try:
    pw.get(*FOREIGN)
    print("ОШИБКА: выдан чужой ключ")
except NotFound as e:
    print("Чужой ключ не выдан:", e)
print("Отчёт сессии:", [(i["id"], i["service"], i["key"]) for i in pw.report()])
'''


def write_demo_projects() -> None:
    foreign = {"DEMO_A": ("Маркет", "password"), "DEMO_B": ("Такси", "login")}
    for project, other in foreign.items():
        folder = PROFILE.projects_root / project
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "demo.py").write_text(DEMO.format(home=str(HOME), foreign=other), encoding="utf-8")


def _recovery_snapshot() -> tuple[bytes, str]:
    with _writer(PROFILE.vault):
        Vault.resume(PROFILE.vault)
        blob = PROFILE.recovery.read_bytes()
        return blob, hashlib.sha256(blob).hexdigest()


def _read_recovery() -> bytes:
    return _recovery_snapshot()[0]


class RecoveryCommitted(VaultError):
    def __init__(self, part: str, reason: str):
        super().__init__(f"Изменения записаны; дополнительная очистка или перечень не завершены ({reason}).")
        self.part = part


def _save_recovery(vault: Vault, blob: bytes, previous_hash: str | None, rotate: bool = False) -> None:
    retire = (PROFILE.vault.with_name(PROFILE.vault.name + ".bak"), PROFILE.remote) if rotate else ()
    with vault._model_lock, _writer(PROFILE.vault):
        try:
            vault.save(recovery_path=PROFILE.recovery, recovery_blob=blob, recovery_hash=previous_hash,
                       retire=retire, backup=not rotate)
        except VaultCommitted as error:
            if error.source_hash == vault.source_hash:
                raise RecoveryCommitted(vault.system_value(RECOVERY_ENTRY), type(error).__name__) from None
            raise
        try:
            if rotate:
                remote.forget(TpmKey(PROFILE.remote_key), PROFILE.remote)
            catalog.write(TpmKey(PROFILE.catalog_key), PROFILE.catalog, vault.rows(), PROFILE.vault,
                          source_hash=vault.source_hash)
        except Exception as error:
            raise RecoveryCommitted(vault.system_value(RECOVERY_ENTRY), type(error).__name__) from None


def _create_vault(password: str, totp_secret: str, question: str, answer: str, kdf=None,
                  recovery_kdf: RecoveryKdf = RecoveryKdf(), seed: bool = True) -> str:
    blob, part = recovery.issue(password, question, answer, recovery_kdf)
    vault = Vault.new(PROFILE.vault, password) if kdf is None else Vault.new(PROFILE.vault, password, kdf)
    if seed:
        for group, service, key, comment, projects, shared in SEED:
            vault.put(group, service, key, "TEST-" + secrets.token_urlsafe(24), comment, projects, shared)
    vault.set_system_value(TOTP_ENTRY, totp_secret)
    vault.set_system_value(RECOVERY_ENTRY, part)
    _save_recovery(vault, blob, None)
    if seed:
        write_demo_projects()
    return part


def create_test_vault(password: str, totp_secret: str, question: str, answer: str, kdf=None,
                      recovery_kdf: RecoveryKdf = RecoveryKdf()) -> str:
    return _create_vault(password, totp_secret, question, answer, kdf, recovery_kdf, seed=True)


def create_main_vault(password: str, totp_secret: str, question: str, answer: str, kdf=None,
                      recovery_kdf: RecoveryKdf = RecoveryKdf()) -> str:
    """Боевое хранилище: без тестовых записей и демо-скриптов."""
    return _create_vault(password, totp_secret, question, answer, kdf, recovery_kdf, seed=False)


def recover_test_vault(answer: str, part: str, new_password: str, recovery_kdf: RecoveryKdf = RecoveryKdf()) -> str:
    blob, before = _recovery_snapshot()
    old_password = recovery.recover(blob, answer, part)
    new_blob, new_part = recovery.issue(new_password, recovery.question_of(blob), answer, recovery_kdf)
    vault = Vault.open(PROFILE.vault, old_password)
    vault.change_password(new_password)
    vault.set_system_value(RECOVERY_ENTRY, new_part)
    _save_recovery(vault, new_blob, before, rotate=True)
    return new_part


def change_test_password(old_password: str, new_password: str, answer: str,
                         recovery_kdf: RecoveryKdf = RecoveryKdf()) -> str:
    vault = Vault.open(PROFILE.vault, old_password)
    old_blob, before = _recovery_snapshot()
    blob, part = recovery.issue(new_password, recovery.question_of(old_blob), answer, recovery_kdf)
    vault.change_password(new_password)
    vault.set_system_value(RECOVERY_ENTRY, part)
    _save_recovery(vault, blob, before, rotate=True)
    return part


def reissue_test_part(password: str, answer: str, recovery_kdf: RecoveryKdf = RecoveryKdf()) -> str:
    vault = Vault.open(PROFILE.vault, password)
    old_blob, before = _recovery_snapshot()
    blob, part = recovery.issue(password, recovery.question_of(old_blob), answer, recovery_kdf)
    vault.set_system_value(RECOVERY_ENTRY, part)
    _save_recovery(vault, blob, before)
    return part


def enroll_test_code(password: str, code: str) -> None:
    with _writer(PROFILE.vault):
        Vault.open(PROFILE.vault, password)
        remote.enroll(TpmKey(PROFILE.remote_key, pin=code), PROFILE.remote, password)


def parse_projects(text: str) -> tuple[tuple[str, ...], bool]:
    """«DELTA COMMON ALL» → проекты и пометка ALL. Группа записи — первый проект."""
    names = text.replace(",", " ").replace(";", " ").split()
    projects = tuple(dict.fromkeys(name for name in names if name.upper() != ALL_SCOPE))
    if not projects:
        raise VaultError("Нужен хотя бы один проект")
    return projects, any(name.upper() == ALL_SCOPE for name in names)


def add_test_secret(password: str, projects_text: str, service: str, key: str, value: str, comment: str) -> None:
    projects, shared = parse_projects(projects_text)
    vault = Vault.open(PROFILE.vault, password)
    vault.put(projects[0], service, key, value, comment, projects, shared)
    vault.save()
    try:
        catalog.write(TpmKey(PROFILE.catalog_key), PROFILE.catalog, vault.rows(), PROFILE.vault,
                      source_hash=vault.source_hash)
    except Exception as error:
        raise VaultCommitted(vault.source_hash, type(error).__name__) from None


class _FormWindow:
    """Общее для окон с полями: работа в фоновом потоке, показ новой части ключа в конце."""

    done_text = ""

    def __init__(self, root, title: str, take_focus: bool, on_close=None):
        self.root = root
        self.ok = False
        self.part = None
        self.take_focus = take_focus
        self.on_close = on_close  # None — отдельная команда admin: закрытие окна завершает её
        self._failure = None
        self._warning = ""
        self._working = False
        use_dark_theme(root)
        win = self.win = tk.Toplevel(root)
        win.title(title)
        win.configure(bg=Dark.BG)
        win.resizable(False, False)
        win.protocol("WM_DELETE_WINDOW", self.close)
        self.body = tk.Frame(win, bg=Dark.BG, padx=22, pady=16)
        self.body.pack()
        dark_title_bar(win)

    def close(self) -> None:
        if self._working and not self.ok:
            self.message.configure(text="Запись ещё выполняется. Дождитесь её завершения.", fg=Dark.WARN)
            return
        if getattr(self, "poll_id", None):
            self.root.after_cancel(self.poll_id)
        if self.on_close is None:
            self.root.quit()
            return
        if self.win.winfo_exists():
            self.win.destroy()
        self.on_close(self.ok)

    def _text(self, text: str, fg=Dark.TEXT, size=10, font=None, pady=(0, 0), wrap=440) -> tk.Label:
        label = tk.Label(self.body, text=text, fg=fg, bg=Dark.BG, font=font or (UI_FONT, size), wraplength=wrap,
                         justify="left", anchor="w")
        label.pack(anchor="w", pady=pady)
        return label

    def _title(self, text: str) -> None:
        self._text(text, font=(UI_FONT, 14, "bold"))

    def _muted(self, text: str, pady=(2, 12)) -> None:
        self._text(text, fg=Dark.MUTED, size=9, pady=pady)

    def _warn(self, text: str, pady=(2, 12)) -> None:
        self._text(text, fg=Dark.WARN, size=9, pady=pady)

    def _label(self, text: str, pady=(0, 0)) -> None:
        self._text(text, fg=Dark.MUTED, size=9, pady=pady)

    def _entry(self, secret: bool = False, gap: int = 8) -> tk.StringVar:
        var = tk.StringVar()
        if secret:
            SecretEntry(self.body, var, bg=Dark.BG, color=Dark.MUTED, font=(UI_FONT, 11),
                        width=44).pack(fill="x", pady=(2, gap))
        else:
            ttk.Entry(self.body, textvariable=var, font=(UI_FONT, 11), width=44).pack(fill="x", pady=(2, gap))
        return var

    def _finish_form(self, action_text: str) -> None:
        self.message = tk.Label(self.body, text="", bg=Dark.BG, fg=Dark.ERROR, font=(UI_FONT, 9), wraplength=440,
                                justify="left")
        self.message.pack(anchor="w", pady=(8, 0))
        self.buttons = tk.Frame(self.body, bg=Dark.BG)
        self.buttons.pack(fill="x", pady=(8, 0))
        self.action_button = ttk.Button(self.buttons, text=action_text, style="Accent.TButton", command=self.submit)
        self.action_button.pack(side="right")
        ttk.Button(self.buttons, text="Отмена", command=self.close).pack(side="right", padx=(0, 8))
        self.win.bind("<Return>", lambda _: self.submit())
        if self.take_focus:
            self.win.attributes("-topmost", True)
            self.win.focus_force()
        self._poll()

    def _poll(self) -> None:
        # Рабочий поток только ставит отметки: виджеты трогаем из основного потока.
        if self.ok:
            self._show_part()
            return
        if self._failure is not None:
            self.message.configure(text=self._failure, fg=Dark.ERROR)
            self.action_button.configure(state="normal")
            self._failure = None
            self._working = False
        self.poll_id = self.root.after(100, self._poll)

    def _show_part(self) -> None:
        self.message.configure(text=f"{self.done_text}\n{self._warning}" + "В настоящем хранилище эту часть ключа "
                                    "хранят отдельно от компьютера. Здесь она показана один раз, для пробы: ",
                               fg=Dark.MUTED)
        self.part_var = tk.StringVar(value=self.part)
        ttk.Entry(self.body, textvariable=self.part_var, state="readonly", font=("Consolas", 11)).pack(
            fill="x", pady=(4, 0), before=self.buttons)
        self.action_button.configure(text="Закрыть", state="normal", command=self.close)
        self.win.bind("<Return>", lambda _: self.close())

    def _start(self, work, *args) -> None:
        self._working = True
        self.action_button.configure(state="disabled")
        self.message.configure(text="Работаю, до 15 секунд…", fg=Dark.MUTED)
        threading.Thread(target=self._run, args=(work, *args), daemon=False).start()

    def _run(self, work, *args) -> None:
        try:
            self.part = work(*args)
            self.ok = True
        except RecoveryCommitted as error:
            self.part = error.part
            self._warning = str(error) + "\n"
            self.ok = True
        except VaultCommitted as error:
            self._warning = str(error)
            self.ok = True
        except (recovery.WrongRecovery, recovery.WeakAnswer, VaultError) as e:
            self._failure = str(e)
        except Exception as e:  # текст чужого исключения не показываем: только его вид
            self._failure = f"Не вышло: {type(e).__name__}"

    def _password_ok(self, password: str) -> bool:
        if len(password) < MIN_PASSWORD:
            self.message.configure(text=f"Пароль короче {MIN_PASSWORD} знаков", fg=Dark.ERROR)
            return False
        if password != self.repeat.get():
            self.message.configure(text="Пароли не совпадают", fg=Dark.ERROR)
            return False
        return True


class RecoveryWindow(_FormWindow):
    done_text = "Новый пароль задан, старая часть ключа больше не действует."

    def __init__(self, root, question: str, work=None, take_focus=True, on_close=None):
        super().__init__(root, f"PW_STORAGE{_mark()}: восстановление пароля", take_focus, on_close)
        self.work = work or recover_test_vault
        self._title("Восстановление пароля")
        mail = recovery_mail()
        self._muted("Нужны ответ на вопрос и часть ключа "
                    + (f"из письма на {mail}." if mail else "из того места, где её спрятал владелец."))
        self._label(f"Вопрос: {question}")
        self._label("Ответ", (6, 0))
        self.answer = self._entry(secret=True)
        self._label("Часть ключа из надёжного места")
        self.key_part = self._entry()
        self._label(f"Новый пароль, не короче {MIN_PASSWORD} знаков")
        self.password = self._entry(secret=True)
        self._label("Повторите пароль")
        self.repeat = self._entry(secret=True, gap=0)
        self._finish_form("Восстановить")

    def submit(self) -> None:
        if self._working or self.ok:
            return
        password = self.password.get()
        if not self._password_ok(password):
            return
        answer, part = self.answer.get(), self.key_part.get()
        for var in (self.password, self.repeat, self.answer, self.key_part):
            var.set("")
        self._start(self.work, answer, part, password)


class ReissueWindow(_FormWindow):
    done_text = "Выпущена новая часть ключа, старая больше не действует."

    def __init__(self, root, question: str, work=None, take_focus=True):
        super().__init__(root, f"PW_STORAGE{_mark()}: новая часть ключа", take_focus)
        self.work = work or reissue_test_part
        self._title("Новая часть ключа")
        self._muted("Если часть ключа утеряна или сменилось место, где она лежит. Нужен пароль хранилища.")
        self._label("Пароль хранилища")
        self.password = self._entry(secret=True)
        self._label(f"Вопрос: {question}")
        self._label(f"Ответ: прежний или новый, не короче {recovery.MIN_ANSWER_CHARS} знаков", (6, 0))
        self.answer = self._entry(secret=True, gap=0)
        self._finish_form("Выпустить")

    def submit(self) -> None:
        if self._working or self.ok:
            return
        password, answer = self.password.get(), self.answer.get()
        if not password:
            self.message.configure(text="Введите пароль", fg=Dark.ERROR)
            return
        self.password.set("")
        self.answer.set("")
        self._start(self.work, password, answer)


class PasswdWindow(_FormWindow):
    done_text = "Пароль сменён. Старая часть ключа и копия .bak больше не действуют, код pw нужно задать заново."

    def __init__(self, root, question: str, work=None, take_focus=True, on_close=None):
        super().__init__(root, f"PW_STORAGE{_mark()}: смена пароля", take_focus, on_close)
        self.work = work or change_test_password
        self._title("Смена пароля")
        self._muted("Архивы на флэшке и в Google открываются старым паролем: после смены выгрузите заново.")
        self._label("Текущий пароль")
        self.old = self._entry(secret=True)
        self._label(f"Новый пароль, не короче {MIN_PASSWORD} знаков")
        self.password = self._entry(secret=True)
        self._label("Повторите новый пароль")
        self.repeat = self._entry(secret=True)
        self._label(f"Вопрос: {question}")
        self._label(f"Ответ: прежний или новый, не короче {recovery.MIN_ANSWER_CHARS} знаков", (6, 0))
        self.answer = self._entry(secret=True, gap=0)
        self._finish_form("Сменить")

    def submit(self) -> None:
        if self._working or self.ok:
            return
        old, password, answer = self.old.get(), self.password.get(), self.answer.get()
        if not old:
            self.message.configure(text="Введите текущий пароль", fg=Dark.ERROR)
            return
        if not self._password_ok(password):
            return
        if password == old:
            self.message.configure(text="Новый пароль совпадает с текущим", fg=Dark.ERROR)
            return
        for var in (self.old, self.password, self.repeat, self.answer):
            var.set("")
        self._start(self.work, old, password, answer)


class RemoteCodeWindow(_FormWindow):
    done_text = "Код задан. Теперь доступ можно открыть из бота, сообщением pw и код."

    def __init__(self, root, work=None, take_focus=True):
        super().__init__(root, f"PW_STORAGE{_mark()}: код для бота", take_focus)
        self.work = work or enroll_test_code
        self._title("Код для доступа через бота")
        self._muted("Нужен, когда вы не у ПК: это не пароль хранилища. Работает только на этом ПК. "
                    "В боте он пишется с приставкой, например pw 12345678.")
        self._label("Пароль хранилища")
        self.password = self._entry(secret=True)
        self._label(f"Код: только цифры, не короче {remote.MIN_CODE_DIGITS}")
        self.code = self._entry(secret=True)
        self._label("Повторите код")
        self.repeat_code = self._entry(secret=True, gap=0)
        self._finish_form("Задать")

    def submit(self) -> None:
        if self._working or self.ok:
            return
        password, code = self.password.get(), self.code.get()
        if not password:
            self.message.configure(text="Введите пароль", fg=Dark.ERROR)
            return
        if not remote.valid_code(code):
            self.message.configure(text=f"Код: только цифры, не короче {remote.MIN_CODE_DIGITS}", fg=Dark.ERROR)
            return
        if code != self.repeat_code.get():
            self.message.configure(text="Коды не совпадают", fg=Dark.ERROR)
            return
        for var in (self.password, self.code, self.repeat_code):
            var.set("")
        self._start(self.work, password, code)

    def _show_part(self) -> None:
        self.message.configure(text=self.done_text + ("\n" + self._warning if self._warning else ""), fg=Dark.MUTED)
        self.action_button.configure(text="Закрыть", state="normal", command=self.close)
        self.win.bind("<Return>", lambda _: self.close())


class AddSecretWindow(_FormWindow):
    """Новый секрет сразу в хранилище (путь 9): значение вводит владелец, в чат и журналы оно не попадает."""

    done_text = "Записано."

    def __init__(self, root, work=None, take_focus=True, on_close=None, projects: str = ""):
        super().__init__(root, f"PW_STORAGE{_mark()}: новый секрет", take_focus, on_close)
        self.preset = projects  # из окна «Проекты»: проект уже подставлен
        self.work = work or add_test_secret
        self._title("Новый секрет")
        self._muted("Значение вводится только здесь: в чат и журналы оно не попадает.")
        self._label("Пароль хранилища")
        self.password = self._entry(secret=True)
        self._label(f"Проекты через пробел (папки в {PROFILE.projects_root}); "
                    "ALL — другие проекты смогут запросить")
        self.scope = self._entry()
        self.scope.set(self.preset)
        self._label("Сервис")
        self.service = self._entry()
        self._label("Логин или имя ключа")
        self.key = self._entry()
        self._label("Значение")
        self.value = self._entry(secret=True)
        self._label("Комментарий человеческим языком, без секретов: его видно в запросах доступа")
        self.comment = self._entry(gap=0)
        self._finish_form("Записать")

    def submit(self) -> None:
        if self._working or self.ok:
            return
        fields = (self.password, self.scope, self.service, self.key, self.value, self.comment)
        values = [var.get().strip() if var not in (self.password, self.value) else var.get() for var in fields]
        if not all(values):
            self.message.configure(text="Заполните все поля", fg=Dark.ERROR)
            return
        self.password.set("")
        self.value.set("")
        self._start(self.work, *values)

    def _show_part(self) -> None:
        self.message.configure(text=self.done_text + ("\n" + self._warning if self._warning else ""), fg=Dark.MUTED)
        self.action_button.configure(text="Закрыть", state="normal", command=self.close)
        self.win.bind("<Return>", lambda _: self.close())


class ExportWindow(_FormWindow):
    """Выгрузка на доверенную флэшку (Т28, Т29): носитель, пароль архива дважды. Архив собирается в памяти."""

    def __init__(self, root, vault=None, take_focus=True, on_close=None, volumes=None, settings=None, audit=None):
        super().__init__(root, f"PW_STORAGE{_mark()}: выгрузка на флэшку", take_focus, on_close)
        self.vault = vault  # из окна администрирования хранилище уже открыто
        self.volumes_source = volumes or export.list_volumes
        self.settings = settings or PROFILE.settings
        self.audit = audit or Audit(PROFILE.audit, echo=False)
        self.found: list = []
        self._title("Выгрузка на флэшку")
        self._muted("Зашифрованный архив zip (AES-256) пишется сразу на носитель: открытых файлов нет ни на ПК, "
                    "ни на флэшке. Внутри — каталог всех записей с частью ключа восстановления и кодами GitHub, "
                    "папки проектов с файлами .jks. Имена файлов в архиве видны без пароля.")
        if vault is None:
            self._label("Пароль хранилища")
            self.password = self._entry(secret=True)
        self._label("Носитель: только отмеченные как доверенные; диск с Windows не годится")
        self.volume_var = tk.StringVar()
        row = tk.Frame(self.body, bg=Dark.BG)
        row.pack(fill="x", pady=(2, 4))
        self.volume_box = ttk.Combobox(row, textvariable=self.volume_var, state="readonly", font=(UI_FONT, 10), width=44)
        self.volume_box.pack(side="left", fill="x", expand=True)
        self.volume_box.bind("<<ComboboxSelected>>", lambda _: self._volume_changed())
        ttk.Button(row, text="Обновить", command=self.refresh).pack(side="left", padx=(6, 0))
        self.trust_row = tk.Frame(self.body, bg=Dark.BG)
        self.trust_row.pack(fill="x", pady=(0, 8))
        self.trust_text = tk.Label(self.trust_row, text="", fg=Dark.MUTED, bg=Dark.BG, font=(UI_FONT, 9), justify="left",
                                   anchor="w", wraplength=330)
        self.trust_text.pack(side="left", fill="x", expand=True)
        self.trust_button = ttk.Button(self.trust_row, text="Доверить носитель", command=self.trust_selected)
        self._label(f"Пароль архива: длинная фраза, не короче {MIN_ARCHIVE_PASSWORD} знаков. Программа его не хранит")
        self.archive = self._entry(secret=True)
        self._label("Повторите пароль архива")
        self.repeat = self._entry(secret=True, gap=0)
        self._finish_form("Выгрузить")
        self.refresh()

    def selected(self):
        index = self.volume_box.current()
        return self.found[index] if 0 <= index < len(self.found) else None

    def refresh(self) -> None:
        try:
            self.found = list(self.volumes_source())
        except OSError:
            self.found = []
        titles = [v.title + (" — доверенный" if export.is_trusted(self.settings, v) else "") for v in self.found]
        self.volume_box.configure(values=titles)
        trusted_index = next((i for i, v in enumerate(self.found) if export.is_trusted(self.settings, v)), 0)
        if self.found:
            self.volume_box.current(trusted_index)
        else:
            self.volume_var.set("")
        self._volume_changed()

    def _volume_changed(self) -> None:
        volume = self.selected()
        self.trust_button.pack_forget()
        if volume is None:
            self.trust_text.configure(text="Флэшка не найдена: вставьте её и нажмите «Обновить».", fg=Dark.WARN)
        elif export.is_trusted(self.settings, volume):
            self.trust_text.configure(text="Доверенный носитель.", fg=Dark.OK)
        else:
            self.trust_text.configure(text="Носитель ещё не доверенный: отметьте его, если это ваша флэшка для копий.",
                                      fg=Dark.WARN)
            self.trust_button.pack(side="right")

    def trust_selected(self) -> None:
        volume = self.selected()
        if volume is None:
            return
        if not messagebox.askyesno("PW_STORAGE", f"Доверить носитель {volume.title}?\nНа него можно будет "
                                   "выгружать все секреты (в зашифрованном архиве).", parent=self.win):
            return
        try:
            export.trust(self.settings, volume)
        except (export.ExportError, OSError) as e:
            self.message.configure(text=str(e), fg=Dark.ERROR)
            return
        self.audit.write("media_trusted", target=f"том {volume.serial} {volume.label}")
        self.refresh()

    def submit(self) -> None:
        if self._working or self.ok:
            return
        volume = self.selected()
        if volume is None or not export.is_trusted(self.settings, volume):
            self.message.configure(text="Выберите доверенный носитель", fg=Dark.ERROR)
            return
        archive = self.archive.get()
        if len(archive) < MIN_ARCHIVE_PASSWORD:
            self.message.configure(text=f"Пароль архива короче {MIN_ARCHIVE_PASSWORD} знаков", fg=Dark.ERROR)
            return
        if archive != self.repeat.get():
            self.message.configure(text="Пароли архива не совпадают", fg=Dark.ERROR)
            return
        password = None
        if self.vault is None:
            password = self.password.get()
            if not password:
                self.message.configure(text="Введите пароль хранилища", fg=Dark.ERROR)
                return
            self.password.set("")
        self.archive.set("")
        self.repeat.set("")
        self._start(self._work, volume, archive, password)

    def _work(self, volume, archive: str, password: str | None) -> str:
        vault = self.vault or Vault.open(PROFILE.vault, password)
        path, count = export.write_archive(vault, volume, self.settings, archive, test=PROFILE.name == "test")
        self.audit.write("export_written", target=f"{path.name} на томе {volume.serial} {volume.label}", count=count)
        return f"Архив записан: {path}. Записей: {count}."

    def _show_part(self) -> None:
        self.message.configure(text=self.part + " Проверен: открывается этим паролем.", fg=Dark.OK)
        self.action_button.configure(text="Закрыть", state="normal", command=self.close)
        self.win.bind("<Return>", lambda _: self.close())


class SetupWindow(_FormWindow):
    done_text = "Хранилище создано."

    def __init__(self, root, create=None, take_focus=True):
        super().__init__(root, f"PW_STORAGE{_mark()}: новое хранилище", take_focus)
        self.secret = new_totp_secret()
        self.create = create or create_test_vault
        self._title("Новое тестовое хранилище" if PROFILE.name == "test" else "Новое боевое хранилище")
        if PROFILE.name == "test":
            self._warn("Настоящий пароль сюда не вводите: файл только для пробы.")
        else:
            mail = recovery_mail()
            self._muted("Боевой профиль: пароль и ответ настоящие. Часть ключа восстановления сохраните "
                        + (f"в письме на {mail}" if mail else "вне этого компьютера")
                        + " — сама программа письма не отправляет.")
        self._label(f"Пароль, не короче {MIN_PASSWORD} знаков")
        self.password = self._entry(secret=True)
        self._label("Повторите пароль")
        self.repeat = self._entry(secret=True)
        self._label("Контрольный вопрос (для восстановления пароля)")
        self.question = self._entry()
        self._label(f"Ответ: длинная фраза, не короче {recovery.MIN_ANSWER_CHARS} знаков, не имя и не дата")
        self.answer = self._entry(secret=True)
        self._label("Приложение на телефоне (например, Google Authenticator): нажмите «+», «Ввести ключ настройки», "
                    "введите этот ключ. Оно будет показывать коды из 6 цифр.")
        self.secret_var = tk.StringVar(value=" ".join(self.secret[i:i + 4] for i in range(0, len(self.secret), 4)))
        ttk.Entry(self.body, textvariable=self.secret_var, state="readonly", font=("Consolas", 11)).pack(fill="x", pady=(2, 8))
        self._label("Код из приложения")
        self.code = self._entry(gap=0)
        self._finish_form("Создать")

    def submit(self) -> None:
        if self._working or self.ok:
            return
        password = self.password.get()
        if not self._password_ok(password):
            return
        question, answer = self.question.get(), self.answer.get()
        try:
            recovery.check_answer(question, answer)
        except recovery.WeakAnswer as e:
            self.message.configure(text=str(e), fg=Dark.ERROR)
            return
        if not Totp(self.secret).verify(self.code.get()):
            self.message.configure(text="Код не подошёл: проверьте ключ в приложении и часы телефона", fg=Dark.ERROR)
            return
        for var in (self.password, self.repeat, self.answer, self.code):
            var.set("")
        self._start(self.create, password, self.secret, question, answer)


def setup() -> int:
    Vault.resume(PROFILE.vault)
    if PROFILE.vault.exists():
        print(f"Хранилище профиля {PROFILE.name} уже есть: {PROFILE.vault}."
              + (" Удалить: python -m pw_storage.admin reset" if PROFILE.name == "test" else ""))
        return 1
    root = make_root()
    window = SetupWindow(root, create=create_main_vault if PROFILE.name == "main" else create_test_vault)
    root.mainloop()
    root.destroy()
    if window.ok:
        print("Готово.")
        if PROFILE.name == "test":
            print("Проба:")
            print(f"  python {PROFILE.projects_root / 'DEMO_A' / 'demo.py'}")
    else:
        print("Хранилище не создано.")
    return 0 if window.ok else 1


def recover() -> int:
    Vault.resume(PROFILE.vault)
    if not PROFILE.recovery.exists():
        print(f"Файла восстановления нет: сначала создайте хранилище профиля {PROFILE.name}.")
        return 1
    root = make_root()
    window = RecoveryWindow(root, recovery.question_of(_read_recovery()))
    root.mainloop()
    root.destroy()
    print("Пароль изменён." if window.ok else "Пароль не менялся.")
    return 0 if window.ok else 1


def _run_window(make) -> int:
    root = make_root()
    window = make(root)
    root.mainloop()
    root.destroy()
    print("Готово." if window.ok else "Ничего не изменено.")
    return 0 if window.ok else 1


def passwd() -> int:
    Vault.resume(PROFILE.vault)
    if not PROFILE.recovery.exists():
        print(f"Файла восстановления нет: сначала создайте хранилище профиля {PROFILE.name}.")
        return 1
    question = recovery.question_of(_read_recovery())
    return _run_window(lambda root: PasswdWindow(root, question))


def recovery_window(root, on_close):
    """Для окна запроса (кнопка «Забыли пароль?»): то же восстановление, но без остановки посредника."""
    Vault.resume(PROFILE.vault)
    if not PROFILE.recovery.exists():
        return None
    return RecoveryWindow(root, recovery.question_of(_read_recovery()), on_close=on_close)


def reissue() -> int:
    Vault.resume(PROFILE.vault)
    if not PROFILE.recovery.exists():
        print(f"Файла восстановления нет: сначала создайте хранилище профиля {PROFILE.name}.")
        return 1
    question = recovery.question_of(_read_recovery())
    return _run_window(lambda root: ReissueWindow(root, question))


def add() -> int:
    Vault.resume(PROFILE.vault)
    if not PROFILE.vault.exists():
        print(f"Сначала создайте хранилище профиля {PROFILE.name}.")
        return 1
    return _run_window(AddSecretWindow)


def manage() -> int:
    """Окно администрирования: матрица «записи × проекты» (вариант В макета)."""
    Vault.resume(PROFILE.vault)
    if not PROFILE.vault.exists():
        print(f"Сначала создайте хранилище профиля {PROFILE.name}.")
        return 1
    from .audit import Audit
    from .manage import ManageWindow

    def after_save(vault: Vault) -> None:
        catalog.write(TpmKey(PROFILE.catalog_key), PROFILE.catalog, vault.rows(), PROFILE.vault,
                      source_hash=vault.source_hash)

    def change_password(root, on_close):
        Vault.resume(PROFILE.vault)
        if not PROFILE.recovery.exists():
            return None
        return PasswdWindow(root, recovery.question_of(_read_recovery()), on_close=on_close)

    root = make_root()
    window = ManageWindow(root, lambda password: Vault.open(PROFILE.vault, password), after_save,
                          Audit(PROFILE.audit, echo=False), PROFILE.audit, PROFILE.settings,
                          test=PROFILE.name == "test",
                          add_secret=lambda r, on_close, project="": AddSecretWindow(r, on_close=on_close,
                                                                                     projects=project),
                          change_password=change_password,
                          export=lambda r, vault, on_close: ExportWindow(r, vault=vault, on_close=on_close),
                          projects_root=PROFILE.projects_root)
    root.mainloop()
    root.destroy()
    print(f"Записано изменений: {window.saved}." if window.saved else "Отметки не менялись.")
    return 0


def reset() -> int:
    if PROFILE.name != "test":
        print("reset работает только в тестовом профиле: боевые данные не удаляются.")
        return 1
    try:
        PwClient("test")._call("shutdown")
        time.sleep(1)
    except BrokerUnavailable:
        pass
    if PROFILE.data != HOME / "test_data":
        raise SystemExit("Папка тестовых данных неожиданная, ничего не удаляю")
    shutil.rmtree(PROFILE.data, ignore_errors=True)
    for name in (PROFILE.catalog_key, PROFILE.remote_key):
        key = TpmKey(name)
        if key.exists():
            key.delete()
    print("Тестовые данные и тестовый ключ TPM удалены.")
    return 0


def telegram(state: str) -> int:
    # Можно до создания хранилища. Без этой настройки в тестовом профиле бот выключен; reset её удаляет.
    PROFILE.data.mkdir(parents=True, exist_ok=True)
    try:
        settings = json.loads(PROFILE.settings.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        settings = {}
    settings["telegram"] = state == "on"  # остальные настройки, например grant_hours, сохраняются
    PROFILE.settings.write_text(json.dumps(settings), encoding="utf-8")
    print(f"Подтверждения в Telegram: {'включены' if state == 'on' else 'выключены'}."
          " Подействуют при следующем запуске посредника.")
    return 0



def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    args = sys.argv[1:]
    global PROFILE
    if len(args) >= 2 and args[0] == "--profile" and args[1] in PROFILES:
        PROFILE = PROFILES[args[1]]
        args = args[2:]
    if args == ["setup"]:
        return setup()
    if args == ["recover"]:
        return recover()
    if args == ["passwd"]:
        return passwd()
    if args == ["reissue"]:
        return reissue()
    if args == ["add"]:
        return add()
    if args == ["remote-code"]:
        Vault.resume(PROFILE.vault)
        if not PROFILE.vault.exists():
            print(f"Сначала создайте хранилище профиля {PROFILE.name}.")
            return 1
        return _run_window(RemoteCodeWindow)
    if args == ["manage"]:
        return manage()
    if args == ["export"]:
        Vault.resume(PROFILE.vault)
        if not PROFILE.vault.exists():
            print(f"Сначала создайте хранилище профиля {PROFILE.name}.")
            return 1
        return _run_window(ExportWindow)
    if args == ["reset"]:
        return reset()
    if len(args) == 2 and args[0] == "telegram" and args[1] in ("on", "off"):
        return telegram(args[1])
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
