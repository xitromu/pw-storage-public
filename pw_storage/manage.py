"""Окно администрирования: матрица «записи × проекты», вариант В макета (04.11.2026).

Строки — записи, колонки — проекты по числу записей и ALL последней, клетка — отметка. Подключённая папка
проекта без записей — тоже колонка: так проекту можно выдать доступ. Группировка «нет»,
«по проекту» (по умолчанию: группа записи в файле) и «по состоянию»; сортировка щелчком по заголовку; группы
сворачиваются; в строке группы ✓ — проект отмечен у всех записей группы, закрашенный квадрат — у части, щелчок
ставит отметку всем или снимает у всех. Статистика «сколько раз и когда брали» — из журнала выдачи (Т31).

Значений здесь нет: окно читает только проекты, сервис, ключ и комментарий. Пароль хранилища живёт в окне,
пока оно открыто, — он нужен, чтобы перечитать файл, если его изменили в KeePassXC или посредник.
"""

from __future__ import annotations

import json
import threading
import tkinter as tk
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from tkinter import font as tkfont
from tkinter import messagebox, ttk

from .config import MAX_PASSWORD_ATTEMPTS, STALE_DAYS
from .vault import Row, Vault, VaultChanged, VaultCommitted, VaultError, WrongPassword
from .window import UI_FONT, Dark, SecretEntry, dark_title_bar, use_dark_theme

ALL = "ALL"
NO_COMMENT, STALE, NO_PROJECTS, ACTIVE = range(4)
STATE_TITLES = ("Без комментария — не выдаётся", f"Не брали {STALE_DAYS} дней и больше",
                "Ни одного проекта — только в выгрузке", "Используются")
MODES = (("none", "Нет"), ("project", "По проекту"), ("state", "По состоянию"))
DEFAULT_DIR = {"comment": 1, "count": -1, "last": -1}  # остальное — колонки проектов: отмеченные сверху


def plural(n: int, one: str, few: str, many: str) -> str:
    if n % 10 == 1 and n % 100 != 11:
        return one
    if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14:
        return few
    return many


# Данные

@dataclass(frozen=True)
class Usage:
    count: int = 0
    last: date | None = None


@dataclass
class Journal:
    """Выдачи из журнала: по строке, по паре «строка — проект», скрипты пары и дата начала журнала."""
    by_row: dict
    by_pair: dict
    scripts: dict
    since: date | None


def _add(table: dict, key, day: date) -> None:
    old = table.get(key, Usage())
    table[key] = Usage(old.count + 1, max(day, old.last) if old.last else day)


def read_journal(path: Path) -> Journal:
    """Выдача значений/вложений и сохранение токенов с номером строки; битые строки пропускаются."""
    journal = Journal({}, {}, {}, None)
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return journal
    for line in lines:
        try:
            record = json.loads(line)
            day = datetime.fromisoformat(record["time"]).date()
        except (ValueError, KeyError, TypeError):
            continue
        if journal.since is None or day < journal.since:
            journal.since = day
        if record.get("event") not in ("value_issued", "attachment_issued", "token_saved") or not record.get("row"):
            continue
        uid, project = record["row"], record.get("project") or "?"
        _add(journal.by_row, uid, day)
        _add(journal.by_pair, (uid, project), day)
        if record.get("script"):
            journal.scripts.setdefault((uid, project), set()).add(Path(str(record["script"])).name)
    return journal


def read_usage(path: Path) -> dict[str, Usage]:
    """Сколько раз и когда выдавалась строка."""
    return read_journal(path).by_row


class Model:
    """Отметки записей: исходные из файла и текущие в окне. Без Tk, чтобы проверять тестами."""

    def __init__(self, rows: list[Row], usage: dict[str, Usage], today: date, stale_days: int = STALE_DAYS,
                 extra_projects=()):
        """extra_projects — подключённые папки без записей: колонка нужна, чтобы проект можно выдать."""
        self.today = today
        self.stale_days = stale_days
        self.usage = usage
        self.extra_projects = set(extra_projects)
        self._load(rows)

    def _load(self, rows: list[Row]) -> None:
        self.rows = list(rows)
        self.by_uid = {row.uid: row for row in self.rows}
        self.orig = {row.uid: (frozenset(row.projects), row.shared) for row in self.rows}
        self.cur = {uid: [set(projects), shared] for uid, (projects, shared) in self.orig.items()}
        count: dict[str, int] = {}
        for row in self.rows:
            for name in row.projects:
                count[name] = count.get(name, 0) + 1
            count.setdefault(row.group, 0)
        for name in self.extra_projects:
            count.setdefault(name, 0)
        self.projects = sorted(count, key=lambda name: (-count[name], name))
        self.columns = [*self.projects, ALL]

    def reload(self, rows: list[Row]) -> None:
        """Трёхстороннее слияние: переносим только клетки, изменённые относительно исходных отметок."""
        wanted = {
            uid: (p - self.orig[uid][0], self.orig[uid][0] - p,
                  s if s != self.orig[uid][1] else None)
            for uid, (p, s) in self.cur.items() if self.changed(uid)
        }
        self._load(rows)
        for uid, (added, removed, shared) in wanted.items():
            if uid in self.cur:
                self.cur[uid][0].update(added)
                self.cur[uid][0].difference_update(removed)
                if shared is not None:
                    self.cur[uid][1] = shared

    # Отметки

    def has(self, uid: str, column: str) -> bool:
        projects, shared = self.cur[uid]
        return shared if column == ALL else column in projects

    def set(self, uid: str, column: str, on: bool) -> None:
        if column == ALL:
            self.cur[uid][1] = on
        elif on:
            self.cur[uid][0].add(column)
        else:
            self.cur[uid][0].discard(column)

    def toggle(self, uid: str, column: str) -> None:
        self.set(uid, column, not self.has(uid, column))

    def group_mark(self, uids: list[str], column: str) -> str:
        marked = sum(self.has(uid, column) for uid in uids)
        return "off" if marked == 0 else "on" if marked == len(uids) else "part"

    def toggle_group(self, uids: list[str], column: str) -> None:
        """✓ у всех — снять у всех, иначе поставить всем."""
        on = self.group_mark(uids, column) != "on"
        for uid in uids:
            self.set(uid, column, on)

    def changed(self, uid: str) -> bool:
        projects, shared = self.cur[uid]
        return (frozenset(projects), shared) != self.orig[uid]

    def changed_uids(self) -> list[str]:
        return [row.uid for row in self.rows if self.changed(row.uid)]

    def describe(self, uid: str) -> str:
        (old, old_shared), (new, new_shared) = self.orig[uid], self.cur[uid]
        parts = [f"добавлен {name}" for name in sorted(new - old)] + [f"снят {name}" for name in sorted(old - new)]
        if new_shared != old_shared:
            parts.append("ALL включён" if new_shared else "ALL снят")
        return ", ".join(parts)

    def revert(self) -> None:
        self.cur = {uid: [set(projects), shared] for uid, (projects, shared) in self.orig.items()}

    def apply(self, vault: Vault) -> list[str]:
        """Применяет отметки в памяти vault (save — отдельно). Возвращает строки для журнала, без значений."""
        lines = []
        for uid in self.changed_uids():
            projects, shared = self.cur[uid]
            vault.set_tags(uid, projects, shared)
            row = self.by_uid[uid]
            lines.append(f"{uid} {row.group}/{row.service}/{row.key}: {self.describe(uid)}")
        return lines

    # Состояние, порядок, группы

    def use(self, uid: str) -> Usage:
        return self.usage.get(uid, Usage())

    def state(self, row: Row) -> int:
        if not row.comment.strip():
            return NO_COMMENT
        projects, shared = self.cur[row.uid]
        if not projects and not shared:
            return NO_PROJECTS
        last = self.use(row.uid).last
        if last is None or (self.today - last).days >= self.stale_days:
            return STALE
        return ACTIVE

    def ordered(self, key: str, direction: int) -> list[str]:
        def comment(row: Row) -> str:
            return row.comment.strip().lower() or "￿"

        def value(row: Row):
            if key == "comment":
                return comment(row)
            if key == "count":
                return self.use(row.uid).count
            if key == "last":
                last = self.use(row.uid).last
                return last.toordinal() if last else 0
            return int(self.has(row.uid, key))

        if key == "comment":
            rows = sorted(self.rows, key=comment, reverse=direction < 0)
        else:  # равные — по комментарию по алфавиту при любом направлении
            rows = sorted(self.rows, key=comment)
            rows = sorted(rows, key=value, reverse=direction < 0)
        return [row.uid for row in rows]

    def matches(self, row: Row, query: str) -> bool:
        query = query.strip().lower()
        return not query or query in f"{row.comment} {row.service} {row.key} {row.group}".lower()

    def groups(self, uids: list[str], mode: str) -> list[tuple[str, str, list[str]]]:
        """(ключ группы, заголовок, номера строк в заданном порядке)."""
        found: dict = {}
        for uid in uids:
            row = self.by_uid[uid]
            key = row.group if mode == "project" else self.state(row)
            found.setdefault(key, []).append(uid)
        if mode == "state":
            return [(str(key), STATE_TITLES[key], found[key]) for key in sorted(found)]
        return [(key, f"Проект {key}", found[key]) for key in sorted(found, key=str.lower)]


# Настройки вида

def load_view(settings: Path) -> dict:
    try:
        view = json.loads(Path(settings).read_text(encoding="utf-8")).get("admin_view", {})
    except (OSError, ValueError, AttributeError):
        view = {}
    mode = view.get("group") if view.get("group") in dict(MODES) else "project"
    direction = view.get("dir") if view.get("dir") in (1, -1) else 1
    key = view.get("sort") if isinstance(view.get("sort"), str) else "comment"
    collapsed = [name for name in view.get("collapsed", []) if isinstance(name, str)]
    return {"group": mode, "sort": key, "dir": direction, "collapsed": collapsed}


def save_view(settings: Path, view: dict) -> None:
    """Остальные настройки (grant_hours, telegram) сохраняются."""
    try:
        data = json.loads(Path(settings).read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            data = {}
    except (OSError, ValueError):
        data = {}
    data["admin_view"] = view
    Path(settings).parent.mkdir(parents=True, exist_ok=True)
    Path(settings).write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")


# Окно

class Size:
    """Размеры при масштабе 100 %; умножаются на масштаб экрана."""
    COMMENT = 380
    PROJECT = 76
    COUNT = 56
    LAST = 100
    HEAD = 28
    ROW = 42
    GROUP = 30
    BOX = 15
    LIST_HEIGHT = 460
    MAX_WIDTH = 1180


GROUP_BG = "#222222"
CHANGED_BG = "#1f3a4d"
WARN_BG = "#3a3000"
BOX_OFF = "#6a6a6a"
INK = "#002033"
ALL_INK = "#1e1033"


class ManageWindow:
    def __init__(self, root, open_vault, after_save, audit, usage_path: Path, settings_path: Path, test: bool = True,
                 add_secret=None, change_password=None, today: date | None = None, take_focus: bool = True,
                 on_close=None, export=None, projects_root: Path | None = None):
        """open_vault(пароль) → Vault; after_save(vault) пересобирает перечень; add_secret/change_password(root,
        on_close) открывают готовые окна admin. on_close=None — отдельная команда: закрытие завершает её."""
        self.root = root
        self.open_vault = open_vault
        self.after_save = after_save
        self.audit = audit
        self.usage_path = Path(usage_path)
        self.settings_path = Path(settings_path)
        self.test = test
        self.add_secret = add_secret
        self.change_password = change_password
        self.export = export  # export(root, vault, on_close) — окно выгрузки на флэшку с уже открытым хранилищем
        self.projects_root = projects_root  # для чистки: какие папки проектов есть; None — кнопки «Чистка» нет
        self.journal = None
        self.today = today or date.today()
        self.on_close = on_close
        self.take_focus = take_focus
        self.vault = None
        self.model = None
        self._password = None
        self._attempts = 0
        self._busy = False
        self._result = None  # итог фоновой работы: ("open"|"save"|"reload", исключение или None, данные)
        self._poll_id = None
        self._child = None
        self.view = load_view(self.settings_path)
        self.collapsed = set(self.view["collapsed"])
        self.order: list[str] = []
        self.hits: list[tuple[int, int, str, object]] = []
        self.saved = 0

        use_dark_theme(root)
        self.scale = root.winfo_fpixels("1i") / 96
        self.win = tk.Toplevel(root)
        self.win.title("PW_STORAGE" + (" (ТЕСТ)" if test else "") + ": администрирование")
        self.win.configure(bg=Dark.BG)
        self.win.protocol("WM_DELETE_WINDOW", self.close)
        self.win.bind("<Destroy>", self._destroyed)
        self.win.bind("<Map>", lambda event: dark_title_bar(self.win) if event.widget is self.win else None)
        self.body = tk.Frame(self.win, bg=Dark.BG, padx=self.px(18), pady=self.px(12))
        self.body.pack(fill="both", expand=True)
        dark_title_bar(self.win)
        self.f_text = tkfont.Font(root=root, family=UI_FONT, size=10)
        self.f_sub = tkfont.Font(root=root, family="Consolas", size=8)
        self.f_head = tkfont.Font(root=root, family=UI_FONT, size=8, weight="bold")
        self.f_group = tkfont.Font(root=root, family=UI_FONT, size=10, weight="bold")
        self.f_box = tkfont.Font(root=root, family=UI_FONT, size=8, weight="bold")
        self._password_screen()
        self._poll()

    def px(self, value: float) -> int:
        return int(round(value * self.scale))

    def _label(self, parent, text, fg=Dark.TEXT, size=10, bold=False, **options) -> tk.Label:
        return tk.Label(parent, text=text, fg=fg, bg=options.pop("bg", Dark.BG),
                        font=(UI_FONT, size, "bold") if bold else (UI_FONT, size), justify="left", anchor="w", **options)

    def _pill(self, parent, text, fg=Dark.MUTED, bg=Dark.PILL, line=Dark.PILL_LINE) -> tk.Label:
        pill = tk.Label(parent, text=text, fg=fg, bg=bg, font=(UI_FONT, 9), padx=self.px(7),
                        highlightthickness=1, highlightbackground=line, highlightcolor=line)
        pill.pack(side="left", padx=(self.px(6), 0))
        return pill

    def _clear(self) -> None:
        for widget in self.body.winfo_children():
            widget.destroy()

    def _top(self) -> tk.Frame:
        top = tk.Frame(self.body, bg=Dark.BG)
        top.pack(fill="x")
        self._label(top, "Хранилище", size=15, bold=True).pack(side="left")
        if self.test:
            self._pill(top, "ТЕСТ", fg=Dark.TEST_FG, bg=Dark.TEST_BG, line="#7a6100")
        return top

    # Пароль

    def _password_screen(self) -> None:
        self._clear()
        self._top()
        if self.test:
            self._label(self.body, "Тестовое хранилище: настоящий пароль сюда не вводите.", fg=Dark.WARN,
                        size=9).pack(anchor="w", pady=(self.px(6), 0))
        self._label(self.body, "Пароль хранилища", fg=Dark.MUTED, size=9).pack(anchor="w", pady=(self.px(10), 0))
        self.password_var = tk.StringVar()
        entry = SecretEntry(self.body, self.password_var, bg=Dark.BG, color=Dark.MUTED, font=(UI_FONT, 11), width=40)
        entry.pack(fill="x", pady=(self.px(2), 0))
        self.password_entry = entry.entry
        self.message = self._label(self.body, "", fg=Dark.ERROR, size=9, wraplength=self.px(420))
        self.message.pack(anchor="w", pady=(self.px(8), 0))
        buttons = tk.Frame(self.body, bg=Dark.BG)
        buttons.pack(fill="x", pady=(self.px(8), 0))
        self.open_button = ttk.Button(buttons, text="Открыть", style="Accent.TButton", command=self.submit_password)
        self.open_button.pack(side="right")
        ttk.Button(buttons, text="Отмена", command=self.close).pack(side="right", padx=(0, self.px(8)))
        self.win.bind("<Return>", lambda _: self.submit_password())
        self.win.resizable(False, False)
        if self.take_focus:
            self.win.attributes("-topmost", True)
            self.win.focus_force()
            self.password_entry.focus_set()

    def submit_password(self) -> None:
        if self._busy or self.model is not None:
            return
        password = self.password_var.get()
        if not password:
            self.message.configure(text="Введите пароль", fg=Dark.ERROR)
            return
        self.password_var.set("")
        self.open_button.configure(state="disabled")
        self.message.configure(text="Открываю хранилище, до 5 секунд…", fg=Dark.MUTED)
        self._background("open", self._open_work, password)

    def _open_work(self, password: str):
        vault = self.open_vault(password)
        return vault, password, read_journal(self.usage_path), self._project_folders()

    def _project_folders(self) -> list[str]:
        """Имена подключённых папок проектов; читаются вне основного потока."""
        if self.projects_root is None:
            return []
        from .projects import project_folders  # импорт внутри: projects → cleanup → manage
        return project_folders(self.projects_root)

    # Фоновая работа: поток только кладёт итог, виджеты трогаем из основного потока

    def _background(self, kind: str, work, *args) -> None:
        self._busy = True

        def run():
            try:
                self._result = (kind, None, work(*args))
            except Exception as e:  # noqa: BLE001 — разбирается в _finish
                self._result = (kind, e, None)

        threading.Thread(target=run, daemon=False).start()

    def _destroyed(self, event) -> None:
        if event.widget is self.win and self._poll_id is not None:
            self.root.after_cancel(self._poll_id)
            self._poll_id = None

    def _poll(self) -> None:
        self._poll_id = None
        if self._result is not None:
            kind, error, data = self._result
            self._result = None
            self._busy = False
            self._finish(kind, error, data)
        if self.win.winfo_exists():
            self._poll_id = self.root.after(100, self._poll)

    def _finish(self, kind: str, error, data) -> None:
        if kind == "open":
            if isinstance(error, WrongPassword):
                self._attempts += 1
                self.audit.write("admin_password_failed")
                if self._attempts >= MAX_PASSWORD_ATTEMPTS:
                    self.close(force=True)
                    return
                left = MAX_PASSWORD_ATTEMPTS - self._attempts
                self.message.configure(text=f"Неверный пароль. Осталось попыток: {left}", fg=Dark.ERROR)
                self.open_button.configure(state="normal")
                return
            if error is not None:
                self.message.configure(text=self._error_text(error), fg=Dark.ERROR)
                self.open_button.configure(state="normal")
                return
            self.vault, self._password, self.journal, folders = data
            self.model = Model(self.vault.rows(), self.journal.by_row, self.today, extra_projects=folders)
            self.audit.write("admin_opened")
            self._matrix_screen()
            return
        if kind == "save":
            if isinstance(error, VaultChanged):
                self._note("Файл хранилища изменён вне окна — в KeePassXC или посредником. Ничего не записано. "
                           "Нажмите «Перечитать»: ваши отметки сохранятся, затем снова «Сохранить».", Dark.WARN)
                self.reload_button.pack(side="right", padx=(0, self.px(8)), before=self.cancel_button)
                self._buttons_state()
                return
            if error is not None:
                self._note(self._error_text(error), Dark.ERROR)
                self._buttons_state()
                return
            self.vault, lines, catalog_error = data
            self.saved += len(lines)
            self.audit.write("tags_changed", rows=lines)
            self.model.reload(self.vault.rows())
            self._resort()
            self._draw()
            if catalog_error:
                self.audit.write("catalog_failed", reason=catalog_error)
                self._note(f"Записано изменений: {len(lines)}. Перечень не собран ({catalog_error}): окно запроса "
                           "соберёт его по паролю.", Dark.WARN)
            else:
                self._note(f"Записано изменений: {len(lines)}. Перечень для окна запроса собран заново.", Dark.OK)
            return
        if kind == "reload":
            if error is not None:
                self._note(self._error_text(error), Dark.ERROR)
                self._buttons_state()
                return
            self.vault, self.journal, folders = data
            self.model.usage = self.journal.by_row
            self.model.extra_projects = set(folders)
            self.model.reload(self.vault.rows())
            self.reload_button.pack_forget()
            self._resort()
            self._draw()
            self._note("Файл перечитан." + (" Несохранённые отметки на месте." if self.model.changed_uids() else ""),
                       Dark.MUTED)

    @staticmethod
    def _error_text(error) -> str:
        if isinstance(error, VaultError):
            return str(error)
        return f"Не вышло: {type(error).__name__}"  # текст чужого исключения не показываем

    # Матрица

    def _matrix_screen(self) -> None:
        self._clear()
        self.win.unbind("<Return>")
        self.win.attributes("-topmost", False)
        self.win.resizable(True, True)
        top = self._top()
        self.pill_rows = self._pill(top, "")
        self.pill_projects = self._pill(top, "")
        self.pill_nocomment = self._pill(top, "", fg=Dark.WARN, line="#7a6100")
        self.pill_stale = self._pill(top, "", fg=Dark.WARN, line="#7a6100")
        for pill in (self.pill_nocomment, self.pill_stale):
            pill.configure(cursor="hand2")
            pill.bind("<Button-1>", lambda _: self.set_mode("state"))
        self.query = tk.StringVar()
        search = ttk.Entry(top, textvariable=self.query, font=(UI_FONT, 10), width=30)
        search.pack(side="right", padx=(self.px(12), 0))
        self._label(top, "Поиск", fg=Dark.MUTED, size=9).pack(side="right")
        self.query.trace_add("write", lambda *_: self._draw())

        bar = tk.Frame(self.body, bg=Dark.BG)
        bar.pack(fill="x", pady=(self.px(10), self.px(8)))
        self._label(bar, "Группировать:", fg=Dark.MUTED, size=9).pack(side="left", padx=(0, self.px(8)))
        self.mode_buttons = {}
        for mode, text in MODES:
            button = ttk.Button(bar, text=text, command=lambda m=mode: self.set_mode(m))
            button.pack(side="left", padx=(0, self.px(4)))
            self.mode_buttons[mode] = button
        self.fold = tk.Frame(bar, bg=Dark.BG)
        self.fold.pack(side="right")
        for text, collapse in (("Свернуть все", True), ("Развернуть все", False)):
            link = self._label(self.fold, text, fg=Dark.ACCENT, size=9, cursor="hand2")
            link.pack(side="left", padx=(self.px(10), 0))
            link.bind("<Button-1>", lambda _, c=collapse: self.fold_all(c))

        width = self.px(Size.COMMENT + Size.PROJECT * len(self.model.columns) + Size.COUNT + Size.LAST)
        self.table_width = width
        shown = min(width, self.px(Size.MAX_WIDTH))
        table = tk.Frame(self.body, bg=Dark.SURFACE)
        table.pack(fill="both", expand=True)
        self.head = tk.Canvas(table, bg=Dark.HEADER, highlightthickness=0, bd=0, width=shown, height=self.px(Size.HEAD),
                              xscrollincrement=self.px(20))
        self.canvas = tk.Canvas(table, bg=Dark.SURFACE, highlightthickness=0, bd=0, width=shown,
                                height=self.px(Size.LIST_HEIGHT), yscrollincrement=self.px(Size.ROW // 2),
                                xscrollincrement=self.px(20))
        ybar = ttk.Scrollbar(table, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=ybar.set)
        self.head.grid(row=0, column=0, sticky="ew")
        self.canvas.grid(row=1, column=0, sticky="nsew")
        ybar.grid(row=1, column=1, sticky="ns")
        if width > shown:
            xbar = ttk.Scrollbar(table, orient="horizontal", command=self._xview)
            self.canvas.configure(xscrollcommand=xbar.set)
            xbar.grid(row=2, column=0, sticky="ew")
        table.columnconfigure(0, weight=1)
        table.rowconfigure(1, weight=1)
        self.head.bind("<Button-1>", self._head_click)
        self.canvas.bind("<Button-1>", self._click)
        self.canvas.bind("<Double-Button-1>", self._double_click)
        self.win.bind("<MouseWheel>", self._wheel)

        self.note = self._label(self.body, "", fg=Dark.MUTED, size=9, wraplength=self.px(min(Size.MAX_WIDTH, 900)))
        self.note.pack(fill="x", pady=(self.px(8), 0))
        buttons = tk.Frame(self.body, bg=Dark.BG)
        buttons.pack(fill="x", pady=(self.px(10), 0))
        self.add_button = ttk.Button(buttons, text="Новая запись", command=self.new_secret)
        self.add_button.pack(side="left")
        ttk.Button(buttons, text="Подключить проект", command=self.projects_window,
                   state="normal" if self.projects_root is not None else "disabled").pack(side="left", padx=(self.px(8), 0))
        ttk.Button(buttons, text="Выгрузить на флэшку", command=self.export_archive,
                   state="normal" if self.export else "disabled").pack(side="left", padx=(self.px(8), 0))
        self.passwd_button = ttk.Button(buttons, text="Сменить пароль", command=self.new_password)
        self.passwd_button.pack(side="left", padx=(self.px(8), 0))
        if self.projects_root is not None:
            ttk.Button(buttons, text="Чистка", command=self.cleanup).pack(side="left", padx=(self.px(8), 0))
        self.save_button = ttk.Button(buttons, text="Сохранить изменения", style="Accent.TButton", command=self.save)
        self.save_button.pack(side="right")
        self.cancel_button = ttk.Button(buttons, text="Отменить", command=self.revert)
        self.cancel_button.pack(side="right", padx=(0, self.px(8)))
        self.reload_button = ttk.Button(buttons, text="Перечитать", command=self.reload)
        self._resort()
        self._draw()
        self._note("")
        dark_title_bar(self.win)

    def _xview(self, *args) -> None:
        self.canvas.xview(*args)
        self.head.xview(*args)

    def _wheel(self, event) -> None:
        if self.model is not None and self.canvas.winfo_exists():
            self.canvas.yview_scroll(-1 if event.delta > 0 else 1, "units")

    # Действия

    def set_mode(self, mode: str) -> None:
        self.view["group"] = mode
        self._draw()

    def set_sort(self, key: str) -> None:
        if self.view["sort"] == key:
            self.view["dir"] = -self.view["dir"]
        else:
            self.view["sort"], self.view["dir"] = key, DEFAULT_DIR.get(key, -1)
        self._resort()
        self._draw()

    def _resort(self) -> None:
        key = self.view["sort"]
        if key not in DEFAULT_DIR and key not in self.model.columns:
            key = self.view["sort"] = "comment"
        self.order = self.model.ordered(key, self.view["dir"])

    def fold_all(self, collapse: bool) -> None:
        for gid in self._group_ids():
            (self.collapsed.add if collapse else self.collapsed.discard)(gid)
        self._draw()

    def _group_ids(self) -> list[str]:
        mode = self.view["group"]
        if mode == "none":
            return []
        return [f"{mode}:{key}" for key, _, _ in self.model.groups(self._visible(), mode)]

    def _visible(self) -> list[str]:
        query = self.query.get()
        return [uid for uid in self.order if self.model.matches(self.model.by_uid[uid], query)]

    def toggle(self, uid: str, column: str) -> None:
        self.model.toggle(uid, column)
        self._draw()
        self._note("")

    def toggle_group(self, uids: list[str], column: str) -> None:
        self.model.toggle_group(uids, column)
        self._draw()
        self._note("")

    def toggle_collapse(self, gid: str) -> None:
        (self.collapsed.discard if gid in self.collapsed else self.collapsed.add)(gid)
        self._draw()

    def revert(self) -> None:
        if self._busy:
            return
        self.model.revert()
        self._draw()
        self._note("")

    def save(self) -> None:
        if self._busy or not self.model.changed_uids():
            return
        self._note("Записываю файл с проверкой, до 10 секунд…", Dark.MUTED)
        self._background("save", self._save_work)
        self._buttons_state()

    def _save_work(self) -> tuple[Vault, list[str], str | None]:
        working = self.vault.clone()
        lines = self.model.apply(working)
        try:
            working.save()
        except VaultCommitted:
            return working, lines, "очистка записи ожидает перезапуска"
        try:  # файл уже записан: сбой перечня не должен выглядеть как несохранённые изменения
            self.after_save(working)
        except Exception as e:  # noqa: BLE001
            return working, lines, type(e).__name__
        return working, lines, None

    def reload(self) -> None:
        if self._busy:
            return
        self._note("Перечитываю файл…", Dark.MUTED)
        self._background("reload", lambda: (self.open_vault(self._password), read_journal(self.usage_path),
                                            self._project_folders()))
        self._buttons_state()

    def _pending_block(self) -> bool:
        if self._busy or self._child is not None:
            return True
        if self.model.changed_uids():
            self._note("Сначала сохраните или отмените изменения.", Dark.WARN)
            return True
        return False

    def new_secret(self) -> None:
        if self.add_secret is None or self._pending_block():
            return

        def closed(ok: bool) -> None:
            self._child = None
            if ok:
                self.reload()

        self._child = self.add_secret(self.root, closed)

    def _child_done(self, changed: bool) -> None:
        """Окно записи или чистки закрыто: хранилище общее и уже записано — перечитываем строки и журнал."""
        self._child = None
        if not changed or not self.win.winfo_exists():
            return
        self.saved += 1
        self.journal = read_journal(self.usage_path)
        self.model.usage = self.journal.by_row
        self.model.reload(self.vault.rows())
        self._resort()
        self._draw()
        self._note("Изменения записаны, перечень для окна запроса собран заново.", Dark.OK)

    def open_record(self, uid: str) -> None:
        if self._pending_block():
            return
        from .cleanup import RecordWindow  # cleanup импортирует этот модуль
        self._child = RecordWindow(self.root, self.vault, self.model.by_uid[uid], self.journal, self.today,
                                   self.after_save, self.audit, self._child_done, test=self.test,
                                   take_focus=self.take_focus)

    def cleanup(self) -> None:
        if self.projects_root is None or self._pending_block():
            return
        from .cleanup import CleanupWindow
        self._child = CleanupWindow(self.root, self.vault, self.journal, self.today, self.projects_root,
                                    self.after_save, self.audit, self._child_done, test=self.test,
                                    take_focus=self.take_focus)

    def projects_window(self) -> None:
        """Окно «Проекты» (Т30). Новая запись из него — готовое окно admin с подставленным проектом."""
        if self.projects_root is None or self._pending_block():
            return
        from .projects import ProjectsWindow

        def add(project: str, done) -> None:
            if self.add_secret is None:
                return

            def closed(ok: bool) -> None:
                if ok:
                    self.reload()
                done(ok)

            self.add_secret(self.root, closed, project)

        def closed_window() -> None:
            """Проект могли подключить, пока окно открыто: его колонка появляется без перечитывания хранилища."""
            self._child = None
            if not self.win.winfo_exists():
                return
            self.model.extra_projects = set(self._project_folders())
            self._draw()

        self._child = ProjectsWindow(self.root, self.projects_root, lambda: self.vault.rows(), add, self.audit,
                                     closed_window, test=self.test, take_focus=self.take_focus)

    def export_archive(self) -> None:
        if self.export is None or self._pending_block():
            return

        def closed(ok: bool) -> None:
            self._child = None

        self._child = self.export(self.root, self.vault, closed)

    def new_password(self) -> None:
        if self.change_password is None or self._pending_block():
            return

        def closed(ok: bool) -> None:
            self._child = None
            if ok:  # пароль в окне устарел: перечитать файл уже нельзя
                self.close(force=True)

        self._child = self.change_password(self.root, closed)

    def close(self, force: bool = False) -> None:
        if self._busy:
            label = self.message if self.model is None else self.note
            label.configure(text="Операция ещё выполняется. Дождитесь её завершения.", fg=Dark.WARN)
            return
        if not force and self.model is not None and self.model.changed_uids():
            if not messagebox.askyesno("PW_STORAGE", "Есть несохранённые изменения. Закрыть без сохранения?",
                                       parent=self.win):
                return
        if self.model is not None:
            try:
                save_view(self.settings_path, {**self.view, "collapsed": sorted(self.collapsed)})
            except OSError:
                pass
        self._password = None
        self.vault = None
        if self._poll_id is not None:
            self.root.after_cancel(self._poll_id)
            self._poll_id = None
        if self.win.winfo_exists():
            self.win.destroy()
        if self.on_close is None:
            self.root.quit()
        else:
            self.on_close(self.saved > 0)

    # Вид

    def _note(self, text: str, color=Dark.MUTED) -> None:
        if not text:
            changed = self.model.changed_uids()
            if changed:
                parts = [f"«{self.model.by_uid[uid].comment or self.model.by_uid[uid].key}» — {self.model.describe(uid)}"
                         for uid in changed]
                text = f"Изменено {len(changed)}: " + "; ".join(parts)
                color = Dark.TEXT
            else:
                text = ("Изменений нет. Отметка ставится и снимается щелчком по клетке; "
                        "галочка в строке группы — у всех записей группы.")
        self.note.configure(text=text, fg=color)
        self._buttons_state()

    def _buttons_state(self) -> None:
        changed = len(self.model.changed_uids())
        self.save_button.configure(text=f"Сохранить изменения ({changed})" if changed else "Сохранить изменения",
                                   state="normal" if changed and not self._busy else "disabled")
        self.cancel_button.configure(state="normal" if changed and not self._busy else "disabled")

    def _columns_x(self) -> list[tuple[str, int, int]]:
        """(колонка, левый край, ширина): comment, проекты, ALL, count, last."""
        out, x = [("comment", 0, self.px(Size.COMMENT))], self.px(Size.COMMENT)
        for name in self.model.columns:
            out.append((name, x, self.px(Size.PROJECT)))
            x += self.px(Size.PROJECT)
        out.append(("count", x, self.px(Size.COUNT)))
        out.append(("last", x + self.px(Size.COUNT), self.px(Size.LAST)))
        return out

    def _column_at(self, x: int) -> str | None:
        for name, left, width in self._columns_x():
            if left <= x < left + width:
                return name
        return None

    def _fit(self, font, text: str, width: int) -> str:
        if font.measure(text) <= width:
            return text
        while text and font.measure(text + "…") > width:
            text = text[:-1]
        return text + "…"

    def _date(self, day: date | None) -> str:
        if day is None:
            return "никогда"
        days = (self.today - day).days
        if days == 0:
            return "сегодня"
        if days == 1:
            return "вчера"
        return day.strftime("%d.%m") if day.year == self.today.year else day.strftime("%d.%m.%y")

    def _box(self, cx: int, cy: int, mark: str, column: str) -> None:
        size = self.px(Size.BOX)
        x0, y0 = cx - size // 2, cy - size // 2
        color = Dark.SOURCE if column == ALL else Dark.ACCENT
        if mark == "on":
            self.canvas.create_rectangle(x0, y0, x0 + size, y0 + size, fill=color, outline=color)
            self.canvas.create_text(cx, cy, text="✓", fill=ALL_INK if column == ALL else INK, font=self.f_box)
        elif mark == "part":
            self.canvas.create_rectangle(x0, y0, x0 + size, y0 + size, outline=color)
            inset = self.px(4)
            self.canvas.create_rectangle(x0 + inset, y0 + inset, x0 + size - inset, y0 + size - inset, fill=color,
                                         outline=color)
        else:
            self.canvas.create_rectangle(x0, y0, x0 + size, y0 + size, outline=BOX_OFF)

    def _draw(self) -> None:
        if self.model is None:
            return
        model, mode = self.model, self.view["group"]
        for name, button in self.mode_buttons.items():
            button.configure(style="Accent.TButton" if name == mode else "TButton")
        if mode == "none":
            self.fold.pack_forget()
        elif not self.fold.winfo_ismapped():
            self.fold.pack(side="right")
        self._draw_head()
        self._draw_pills()

        canvas, cols = self.canvas, self._columns_x()
        canvas.delete("all")
        self.hits = []
        visible = self._visible()
        y = 0
        if not visible:
            canvas.create_text(self.table_width // 2, self.px(30), text="Ничего не найдено", fill=Dark.MUTED,
                               font=self.f_text)
            y = self.px(60)
        elif mode == "none":
            for uid in visible:
                y = self._draw_row(uid, y, cols, mode)
        else:
            for key, title, uids in model.groups(visible, mode):
                gid = f"{mode}:{key}"
                y = self._draw_group(gid, title, uids, y, cols, mode)
                if gid not in self.collapsed:
                    for uid in uids:
                        y = self._draw_row(uid, y, cols, mode)
        canvas.configure(scrollregion=(0, 0, self.table_width, max(y, 1)))
        self.head.configure(scrollregion=(0, 0, self.table_width, self.px(Size.HEAD)))

    def _draw_head(self) -> None:
        head = self.head
        head.delete("all")
        mid = self.px(Size.HEAD) // 2
        titles = {"comment": "СТРОКА", "count": "РАЗ", "last": "ПОСЛЕДНИЙ"}
        for name, left, width in self._columns_x():
            active = self.view["sort"] == name
            text = titles.get(name, name) + ((" ▲" if self.view["dir"] > 0 else " ▼") if active else "")
            color = Dark.TEXT if active else Dark.SOURCE if name == ALL else Dark.MUTED
            if name in ("comment", "last"):
                head.create_text(left + self.px(10), mid, text=text, anchor="w", fill=color, font=self.f_head)
            elif name == "count":
                head.create_text(left + width - self.px(10), mid, text=text, anchor="e", fill=color, font=self.f_head)
            else:
                head.create_text(left + width // 2, mid, text=self._fit(self.f_head, text, width - self.px(4)),
                                 fill=color, font=self.f_head)

    def _draw_pills(self) -> None:
        model = self.model
        states = [model.state(row) for row in model.rows]
        count = len(model.rows)
        self.pill_rows.configure(text=f"{count} {plural(count, 'запись', 'записи', 'записей')}")
        projects = len(model.projects)
        self.pill_projects.configure(text=f"{projects} {plural(projects, 'проект', 'проекта', 'проектов')}")
        for pill, value, text in ((self.pill_nocomment, states.count(NO_COMMENT), "▲ без комментария"),
                                  (self.pill_stale, states.count(STALE), "давно не брали")):
            pill.configure(text=f"{text} · {value}")
            if value and not pill.winfo_ismapped():
                pill.pack(side="left", padx=(self.px(6), 0))
            elif not value:
                pill.pack_forget()

    def _draw_group(self, gid: str, title: str, uids: list[str], y: int, cols, mode: str) -> int:
        canvas, height = self.canvas, self.px(Size.GROUP)
        mid = y + height // 2
        canvas.create_rectangle(0, y, self.table_width, y + height, fill=GROUP_BG, outline="")
        canvas.create_line(0, y, self.table_width, y, fill="#4a4a4a")
        arrow = "▸" if gid in self.collapsed else "▾"
        color = Dark.WARN if mode == "state" and title == STATE_TITLES[NO_COMMENT] else Dark.TEXT
        name, left, width = cols[0]
        count = f"{len(uids)} {plural(len(uids), 'запись', 'записи', 'записей')}"
        room = width - self.px(28) - self.f_text.measure(count)  # заголовок не заходит на колонки проектов
        label = canvas.create_text(left + self.px(10), mid, text=self._fit(self.f_group, f"{arrow}  {title}", room),
                                   anchor="w", fill=color, font=self.f_group)
        right = canvas.bbox(label)[2]
        canvas.create_text(right + self.px(8), mid, text=count, anchor="w", fill=Dark.ID, font=self.f_text)
        for name, left, width in cols[1:-2]:
            self._box(left + width // 2, mid, self.model.group_mark(uids, name), name)
        total = sum(self.model.use(uid).count for uid in uids)
        lasts = [self.model.use(uid).last for uid in uids if self.model.use(uid).last]
        name, left, width = cols[-2]
        canvas.create_text(left + width - self.px(10), mid, text=str(total), anchor="e", fill=Dark.ID, font=self.f_text)
        name, left, width = cols[-1]
        canvas.create_text(left + self.px(10), mid, text=self._date(max(lasts) if lasts else None), anchor="w",
                           fill=Dark.ID, font=self.f_text)
        self.hits.append((y, y + height, "group", (gid, uids)))
        return y + height

    def _draw_row(self, uid: str, y: int, cols, mode: str) -> int:
        canvas, model, height = self.canvas, self.model, self.px(Size.ROW)
        row, use = model.by_uid[uid], model.use(uid)
        changed = model.changed(uid)
        bg = WARN_BG if not row.comment.strip() else CHANGED_BG if changed else Dark.SURFACE
        canvas.create_rectangle(0, y, self.table_width, y + height, fill=bg, outline="")
        canvas.create_line(0, y, self.table_width, y, fill=Dark.LINE)
        name, left, width = cols[0]
        text_w = width - self.px(20)
        suffix = "  · изменено" if changed else ""
        main_w = text_w - (self.f_text.measure(suffix) if suffix else 0)
        if row.comment.strip():
            main = canvas.create_text(left + self.px(10), y + self.px(14), text=self._fit(self.f_text, row.comment, main_w),
                                      anchor="w", fill=Dark.TEXT, font=self.f_text)
        else:
            main = canvas.create_text(left + self.px(10), y + self.px(14), text="▲ без комментария", anchor="w",
                                      fill=Dark.WARN, font=self.f_text)
        if suffix:
            canvas.create_text(canvas.bbox(main)[2], y + self.px(14), text=suffix, anchor="w", fill=Dark.WARN,
                               font=self.f_text)
        where = f"{row.service} · {row.key}" if mode == "project" else f"{row.group} › {row.service} · {row.key}"
        canvas.create_text(left + self.px(10), y + self.px(30), text=self._fit(self.f_sub, f"{where} · {uid}", text_w),
                           anchor="w", fill="#7f7f7f", font=self.f_sub)
        mid = y + height // 2
        for name, left, width in cols[1:-2]:
            self._box(left + width // 2, mid, "on" if model.has(uid, name) else "off", name)
        state = model.state(row)
        name, left, width = cols[-2]
        canvas.create_text(left + width - self.px(10), mid, text=str(use.count), anchor="e",
                           fill=Dark.TEXT if use.count else Dark.DIM, font=self.f_text)
        name, left, width = cols[-1]
        canvas.create_text(left + self.px(10), mid, text=self._date(use.last), anchor="w",
                           fill=Dark.DIM if state == STALE or use.last is None else Dark.MUTED, font=self.f_text)
        self.hits.append((y, y + height, "row", uid))
        return y + height

    # Щелчки

    def _hit(self, event):
        x, y = int(self.canvas.canvasx(event.x)), int(self.canvas.canvasy(event.y))
        for top, bottom, kind, payload in self.hits:
            if top <= y < bottom:
                return kind, payload, self._column_at(x)
        return None, None, None

    def _click(self, event) -> None:
        if self._busy:
            return
        kind, payload, column = self._hit(event)
        projects = column is not None and column in self.model.columns
        if kind == "row" and projects:
            self.toggle(payload, column)
        elif kind == "group" and projects:
            self.toggle_group(payload[1], column)
        elif kind == "group":
            self.toggle_collapse(payload[0])

    def _double_click(self, event) -> None:
        kind, payload, column = self._hit(event)
        if kind == "row" and column not in self.model.columns:
            self.open_record(payload)

    def _head_click(self, event) -> None:
        column = self._column_at(int(self.head.canvasx(event.x)))
        if column is not None:
            self.set_sort(column)
