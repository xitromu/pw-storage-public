"""Чистки (Т31), варианты А и Б по макету (выбор владельца 04.11.2026).

А — окно записи по двойному щелчку в матрице: комментарий, замена значения, кто брал по проектам, «снять проект»,
удаление в корзину. Б — окно «Чистка»: список предложений с отметками, применяются только отмеченные.

Удалённое уходит в корзину файла хранилища: в перечень и выдачу не попадает, в выгрузку на флэшку входит.
Окончательно — «Очистить корзину». Всё пишется в журнал без значений.
"""

from __future__ import annotations

import os
import threading
import tkinter as tk
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from tkinter import messagebox, ttk

from .config import STALE_DAYS
from .manage import Journal, Usage
from .vault import Row, Vault, VaultError
from .window import UI_FONT, Dark, SecretEntry, dark_title_bar, use_dark_theme

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "build", ".gradle", ".idea", "dist", ".cxx",
             "uv-cache"}
OPEN_SECRET_FILES = {"secrets.env", ".env", "keystore.properties"}
UNLINK, TRASH, PROJECT, JKS, OPEN_FILE = "unlink", "trash", "project", "jks", "open_file"
SECTIONS = ((UNLINK, "Проекты в списках записей"), (TRASH, "Записи"), (PROJECT, "Проекты"),
            (JKS, "Новое на диске"), (OPEN_FILE, "Новое на диске"))
KIND_TEXT = {UNLINK: ("снять проект", Dark.ACCENT), TRASH: ("в корзину", Dark.ERROR), PROJECT: ("удалить проект", Dark.WARN),
             JKS: ("добавить вручную", Dark.OK), OPEN_FILE: ("перенести", Dark.OK)}


def days_text(n: int) -> str:
    if n % 10 == 1 and n % 100 != 11:
        return f"{n} день"
    if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14:
        return f"{n} дня"
    return f"{n} дней"


def times_text(n: int) -> str:
    return f"{n} раз" if not (2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14) else f"{n} раза"


@dataclass
class Suggestion:
    kind: str
    title: str
    reason: str
    default: bool = False
    uid: str | None = None
    project: str | None = None

    @property
    def actionable(self) -> bool:
        return self.kind in (UNLINK, TRASH, PROJECT)


@dataclass
class Scan:
    jks: list = field(default_factory=list)
    open_files: list = field(default_factory=list)


def scan_projects(root: Path, limit: int = 20000) -> Scan:
    """Файлы .jks и открытые файлы секретов в папках проектов. Служебные папки пропускаются."""
    scan, seen = Scan(), 0
    root = Path(root)
    if not root.is_dir():
        return scan
    for folder, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for name in files:
            seen += 1
            if name.lower().endswith(".jks"):
                scan.jks.append(Path(folder) / name)
            elif name.lower() in OPEN_SECRET_FILES:
                scan.open_files.append(Path(folder) / name)
        if seen > limit:
            break
    return scan


def _stale(usage: Usage, journal: Journal, today: date, stale_days: int) -> bool:
    """Давно не брали: последний раз не позже порога, или ни разу — если журнал ведётся дольше порога."""
    if usage.last is not None:
        return (today - usage.last).days >= stale_days
    return journal.since is not None and (today - journal.since).days >= stale_days


def suggestions(rows: list[Row], journal: Journal, today: date, projects_root: Path, attachment_names: set[str],
                scan: Scan | None = None, stale_days: int = STALE_DAYS) -> list[Suggestion]:
    out: list[Suggestion] = []
    for row in rows:
        if not row.comment.strip():
            continue
        for project in row.projects:
            if project == row.group:  # домашний проект не снимаем: запись осиротела бы — для неё есть «в корзину»
                continue
            use = journal.by_pair.get((row.uid, project), Usage())
            if _stale(use, journal, today, stale_days):
                reason = (f"{project} брал {days_text((today - use.last).days)} назад, {times_text(use.count)}"
                          if use.last else f"{project} не брал ни разу с начала журнала")
                out.append(Suggestion(UNLINK, f"Снять {project} с «{row.comment}»", reason, True, row.uid, project))
    for row in rows:
        if not row.comment.strip():
            out.append(Suggestion(TRASH, f"Удалить «без комментария» ({row.group} › {row.service} · {row.key})",
                                  "не выдаётся: нет комментария", False, row.uid))
            continue
        if not row.projects and not row.shared:
            continue  # только для выгрузки, например коды GitHub: не предлагаем
        use = journal.by_row.get(row.uid, Usage())
        if _stale(use, journal, today, stale_days):
            reason = (f"никто не брал {days_text((today - use.last).days)}" if use.last
                      else "никто не брал с начала журнала")
            out.append(Suggestion(TRASH, f"Удалить «{row.comment}»", reason, False, row.uid))
    names = sorted({p for row in rows for p in row.projects} | {row.group for row in rows}, key=str.lower)
    for name in names:
        if not (Path(projects_root) / name).is_dir():
            only = sum(1 for row in rows if set(row.projects) <= {name} and row.group == name)
            out.append(Suggestion(PROJECT, f"Удалить проект {name}: снять со всех записей, его записей в корзину: {only}",
                                  "папки проекта нет", False, project=name))
    if scan is not None:
        for path in scan.jks:
            if path.name not in attachment_names:
                out.append(Suggestion(JKS, f"Копия {_short(path, projects_root)}", "файла подписи нет в хранилище"))
        for path in scan.open_files:
            out.append(Suggestion(OPEN_FILE, f"Проверить {_short(path, projects_root)}", "открытый файл с секретами (Т9)"))
    return out


def _short(path: Path, root: Path) -> str:
    """Путь от папки проектов: DELTA\\android\\release.jks."""
    try:
        return str(Path(path).relative_to(root))
    except ValueError:
        return str(path)


def apply(vault: Vault, rows: list[Row], chosen: list[Suggestion]) -> list[str]:
    """Отмеченные предложения → изменения в хранилище (save — отдельно). Строки для журнала, без значений."""
    by_uid = {row.uid: row for row in rows}
    projects = {row.uid: set(row.projects) for row in rows}
    trashed: set[str] = set()
    lines: list[str] = []

    def name(uid: str) -> str:
        row = by_uid[uid]
        return f"{uid} {row.group}/{row.service}/{row.key}"

    for s in (s for s in chosen if s.kind == UNLINK):
        projects[s.uid].discard(s.project)
    for s in (s for s in chosen if s.kind == PROJECT):
        for row in rows:
            if row.group == s.project and projects[row.uid] <= {s.project}:
                trashed.add(row.uid)
            projects[row.uid].discard(s.project)
        lines.append(f"проект {s.project}: удалён")
    trashed |= {s.uid for s in chosen if s.kind == TRASH}
    for uid, now in projects.items():
        if uid in trashed or now == set(by_uid[uid].projects):
            continue
        vault.set_tags(uid, now, by_uid[uid].shared)
        removed = sorted(set(by_uid[uid].projects) - now)
        lines.append(f"{name(uid)}: снят {', '.join(removed)}")
    for uid in sorted(trashed):
        vault.trash(uid)
        lines.append(f"{name(uid)}: в корзину")
    return lines


# Окна

class _Child:
    """Общее для окон над открытым хранилищем: фоновая запись и её итог в основном потоке."""

    def __init__(self, root, title: str, vault: Vault, after_save, audit, on_done, take_focus: bool = True):
        self.root = root
        self.vault = vault
        self.after_save = after_save
        self.audit = audit
        self.on_done = on_done  # on_done(изменилось ли хранилище)
        self.changed = False
        self._busy = False
        self._result = None
        self._poll_id = None
        use_dark_theme(root)
        self.scale = root.winfo_fpixels("1i") / 96
        self.win = tk.Toplevel(root)
        self.win.title(title)
        self.win.configure(bg=Dark.BG)
        self.win.protocol("WM_DELETE_WINDOW", self.close)
        self.win.bind("<Destroy>", self._destroyed)
        self.body = tk.Frame(self.win, bg=Dark.BG, padx=self.px(18), pady=self.px(12))
        self.body.pack(fill="both", expand=True)
        dark_title_bar(self.win)
        self.win.bind("<Map>", lambda event: dark_title_bar(self.win) if event.widget is self.win else None)
        if take_focus:
            self.win.focus_force()
        self._poll()

    def px(self, value: float) -> int:
        return int(round(value * self.scale))

    def label(self, parent, text, fg=Dark.TEXT, size=10, bold=False, **options) -> tk.Label:
        return tk.Label(parent, text=text, fg=fg, bg=options.pop("bg", Dark.BG),
                        font=(UI_FONT, size, "bold") if bold else (UI_FONT, size), justify="left", anchor="w", **options)

    def run(self, work, done) -> None:
        """work() в потоке: меняет хранилище и пишет файл; done(ошибка, итог) — в основном потоке."""
        self._busy = True

        def body():
            try:
                result = work()
                self.vault.save()
                try:
                    self.after_save(self.vault)
                except Exception as e:  # noqa: BLE001 — файл уже записан, перечень соберёт окно запроса
                    self.audit.write("catalog_failed", reason=type(e).__name__)
                self._result = (None, result)
            except Exception as e:  # noqa: BLE001
                self._result = (e, None)

        self._done = done
        threading.Thread(target=body, daemon=True).start()

    def _destroyed(self, event) -> None:
        if event.widget is self.win and self._poll_id is not None:
            self.root.after_cancel(self._poll_id)
            self._poll_id = None

    def _poll(self) -> None:
        self._poll_id = None
        if self._result is not None:
            error, result = self._result
            self._result = None
            self._busy = False
            if error is None:
                self.changed = True
            self._done(error, result)
        if self.win.winfo_exists():
            self._poll_id = self.root.after(100, self._poll)

    @staticmethod
    def error_text(error) -> str:
        return str(error) if isinstance(error, VaultError) else f"Не вышло: {type(error).__name__}"

    def close(self) -> None:
        if self._busy:
            return
        if self.win.winfo_exists():
            self.win.destroy()
        self.on_done(self.changed)


class RecordWindow(_Child):
    """Вариант А: одна запись."""

    def __init__(self, root, vault: Vault, row: Row, journal: Journal, today: date, after_save, audit, on_done,
                 test: bool = True, take_focus: bool = True):
        super().__init__(root, "PW_STORAGE" + (" (ТЕСТ)" if test else "") + ": запись", vault, after_save, audit,
                         on_done, take_focus)
        self.row = row
        self.today = today
        self.unlink: set[str] = set()
        width = self.px(520)
        self.win.resizable(False, False)
        top = tk.Frame(self.body, bg=Dark.BG)
        top.pack(fill="x")
        self.label(top, row.comment or "▲ без комментария", size=14, bold=True, wraplength=width,
                   fg=Dark.TEXT if row.comment else Dark.WARN).pack(side="left")
        tk.Label(self.body, text=f"номер {row.uid} · проект {row.group} · сервис {row.service} · ключ {row.key}",
                 fg=Dark.ID, bg=Dark.BG, font=("Consolas", 9), anchor="w").pack(fill="x", pady=(self.px(2), 0))
        self.label(self.body, "Комментарий — его видят сессии и бот; без логинов, телефонов и адресов", fg=Dark.MUTED,
                   size=9).pack(fill="x", pady=(self.px(10), 0))
        self.comment = tk.StringVar(value=row.comment)
        ttk.Entry(self.body, textvariable=self.comment, font=(UI_FONT, 10)).pack(fill="x", pady=(self.px(2), 0))
        self.label(self.body, "Новое значение — оставьте пустым, если не меняете", fg=Dark.MUTED, size=9).pack(
            fill="x", pady=(self.px(10), 0))
        self.value = tk.StringVar()
        SecretEntry(self.body, self.value, bg=Dark.BG, color=Dark.MUTED, font=(UI_FONT, 10)).pack(fill="x",
                                                                                               pady=(self.px(2), 0))
        self.label(self.body, "Кто брал — из журнала" + (f" (ведётся с {journal.since:%d.%m.%Y})" if journal.since else ""),
                   fg=Dark.MUTED, size=9).pack(fill="x", pady=(self.px(12), self.px(4)))
        table = tk.Frame(self.body, bg=Dark.SURFACE)
        table.pack(fill="x")
        for column, text in enumerate(("ПРОЕКТ", "РАЗ", "ПОСЛЕДНИЙ", "СКРИПТЫ", "")):
            tk.Label(table, text=text, fg=Dark.MUTED, bg=Dark.HEADER, font=(UI_FONT, 8, "bold"), anchor="w",
                     padx=self.px(8), pady=self.px(4)).grid(row=0, column=column, sticky="ew")
        self.unlink_buttons = {}
        projects = list(row.projects) + [p for (uid, p) in journal.by_pair if uid == row.uid and p not in row.projects]
        for index, project in enumerate(projects, start=1):
            use = journal.by_pair.get((row.uid, project), Usage())
            listed = project in row.projects
            last = "никогда" if use.last is None else f"{use.last:%d.%m} · {days_text((today - use.last).days)}"
            stale = use.last is None or (today - use.last).days >= STALE_DAYS
            cells = (project + ("" if listed else " (не в списке)"), str(use.count), last,
                     ", ".join(sorted(journal.scripts.get((row.uid, project), ()))) or "—")
            for column, text in enumerate(cells):
                color = Dark.WARN if column == 2 and stale and use.last else Dark.DIM if use.count == 0 else Dark.TEXT
                tk.Label(table, text=text, fg=color, bg=Dark.SURFACE, font=(UI_FONT, 10), anchor="w", padx=self.px(8),
                         pady=self.px(3)).grid(row=index, column=column, sticky="ew")
            if listed and project != row.group:
                button = ttk.Button(table, text=f"Снять {project}", command=lambda p=project: self.toggle_unlink(p))
                button.grid(row=index, column=4, sticky="e", padx=self.px(6), pady=self.px(2))
                self.unlink_buttons[project] = button
        if not projects:
            tk.Label(table, text="Проектов нет: запись только для выгрузки", fg=Dark.DIM, bg=Dark.SURFACE,
                     font=(UI_FONT, 10), anchor="w", padx=self.px(8)).grid(row=1, column=0, columnspan=5, sticky="ew")
        table.columnconfigure(3, weight=1)
        self.label(self.body, f"Домашний проект {row.group} снимается только удалением записи.", fg=Dark.DIM,
                   size=9).pack(fill="x", pady=(self.px(4), 0))
        self.message = self.label(self.body, "", fg=Dark.MUTED, size=9, wraplength=width)
        self.message.pack(fill="x", pady=(self.px(8), 0))
        buttons = tk.Frame(self.body, bg=Dark.BG)
        buttons.pack(fill="x", pady=(self.px(10), 0))
        ttk.Button(buttons, text="Удалить запись в корзину", command=self.trash).pack(side="left")
        self.save_button = ttk.Button(buttons, text="Сохранить", style="Accent.TButton", command=self.save)
        self.save_button.pack(side="right")
        ttk.Button(buttons, text="Закрыть", command=self.close).pack(side="right", padx=(0, self.px(8)))

    def toggle_unlink(self, project: str) -> None:
        if project in self.unlink:
            self.unlink.discard(project)
            self.unlink_buttons[project].configure(text=f"Снять {project}")
        else:
            self.unlink.add(project)
            self.unlink_buttons[project].configure(text=f"Вернуть {project}")
        self.message.configure(text=("Будет снято: " + ", ".join(sorted(self.unlink))) if self.unlink else "",
                               fg=Dark.WARN)

    def save(self) -> None:
        if self._busy:
            return
        comment = self.comment.get().strip()
        value = self.value.get()
        if not comment:
            self.message.configure(text="Комментарий обязателен", fg=Dark.ERROR)
            return
        new_comment = comment if comment != self.row.comment else None
        if new_comment is None and not value and not self.unlink:
            self.message.configure(text="Изменений нет", fg=Dark.MUTED)
            return
        self.value.set("")
        row, unlink = self.row, set(self.unlink)

        def work():
            parts = []
            if new_comment is not None or value:
                self.vault.update_entry(row.uid, comment=new_comment, value=value or None)
                parts += (["комментарий"] if new_comment is not None else []) + (["значение заменено"] if value else [])
            if unlink:
                self.vault.set_tags(row.uid, set(row.projects) - unlink, row.shared)
                parts.append("снят " + ", ".join(sorted(unlink)))
            return f"{row.uid} {row.group}/{row.service}/{row.key}: " + "; ".join(parts)

        def done(error, line):
            if error is not None:
                self.message.configure(text=self.error_text(error), fg=Dark.ERROR)
                return
            self.audit.write("record_changed", rows=[line])
            self.close()

        self.message.configure(text="Записываю файл с проверкой…", fg=Dark.MUTED)
        self.run(work, done)

    def trash(self) -> None:
        if self._busy:
            return
        if not messagebox.askyesno("PW_STORAGE", f"Удалить «{self.row.comment or self.row.key}» в корзину?\n"
                                   "Из выдачи пропадёт сразу; окончательно — «Очистить корзину» в окне чистки.",
                                   parent=self.win):
            return
        row = self.row

        def done(error, _):
            if error is not None:
                self.message.configure(text=self.error_text(error), fg=Dark.ERROR)
                return
            self.audit.write("record_trashed", rows=[f"{row.uid} {row.group}/{row.service}/{row.key}"])
            self.close()

        self.message.configure(text="Записываю файл с проверкой…", fg=Dark.MUTED)
        self.run(lambda: self.vault.trash(row.uid), done)


class CleanupWindow(_Child):
    """Вариант Б: предложения с отметками; применяются только отмеченные."""

    def __init__(self, root, vault: Vault, journal: Journal, today: date, projects_root: Path, after_save, audit,
                 on_done, test: bool = True, take_focus: bool = True, scanner=scan_projects):
        self._scan_id = None
        super().__init__(root, "PW_STORAGE" + (" (ТЕСТ)" if test else "") + ": чистка", vault, after_save, audit,
                         on_done, take_focus)
        self.journal = journal
        self.today = today
        self.projects_root = Path(projects_root)
        self.scanner = scanner
        self.items: list[tuple[Suggestion, tk.BooleanVar | None]] = []
        self.width = self.px(760)
        top = tk.Frame(self.body, bg=Dark.BG)
        top.pack(fill="x")
        self.label(top, "Чистка", size=15, bold=True).pack(side="left")
        since = f"журнал с {journal.since:%d.%m.%Y}" if journal.since else "журнал пуст"
        self.label(top, f"   порог {STALE_DAYS} дней · {since}", fg=Dark.MUTED, size=9).pack(side="left")
        self.list_frame = tk.Frame(self.body, bg=Dark.SURFACE)
        self.list_frame.pack(fill="both", expand=True, pady=(self.px(10), 0))
        self.canvas = tk.Canvas(self.list_frame, bg=Dark.SURFACE, highlightthickness=0, width=self.width,
                                height=self.px(380), yscrollincrement=self.px(16))
        bar = ttk.Scrollbar(self.list_frame, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=bar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        bar.pack(side="right", fill="y")
        self.inner = tk.Frame(self.canvas, bg=Dark.SURFACE)
        item = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfigure(item, width=e.width))
        self.inner.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.win.bind("<MouseWheel>", lambda e: self.canvas.yview_scroll(-1 if e.delta > 0 else 1, "units"))
        self.label(self.body, "Отмечены заранее только безопасные: снятый проект можно вернуть отметкой в матрице. "
                   "Удаления — только вручную. «Добавить вручную» и «перенести» — подсказки, без кнопки.",
                   fg=Dark.MUTED, size=9, wraplength=self.width).pack(fill="x", pady=(self.px(8), 0))
        self.message = self.label(self.body, "Ищу, что можно почистить…", fg=Dark.MUTED, size=9, wraplength=self.width)
        self.message.pack(fill="x", pady=(self.px(6), 0))
        buttons = tk.Frame(self.body, bg=Dark.BG)
        buttons.pack(fill="x", pady=(self.px(10), 0))
        self.trash_label = self.label(buttons, "", fg=Dark.MUTED, size=9)
        self.trash_label.pack(side="left")
        self.empty_button = ttk.Button(buttons, text="Очистить корзину", command=self.empty_trash)
        self.empty_button.pack(side="left", padx=(self.px(8), 0))
        self.apply_button = ttk.Button(buttons, text="Применить", style="Accent.TButton", command=self.apply)
        self.apply_button.pack(side="right")
        ttk.Button(buttons, text="Закрыть", command=self.close).pack(side="right", padx=(0, self.px(8)))
        self._trash_state()
        self._scan_result = None
        threading.Thread(target=self._scan, daemon=True).start()
        self._wait_scan()

    def _scan(self) -> None:
        try:
            self._scan_result = self.scanner(self.projects_root)
        except OSError:
            self._scan_result = Scan()

    def _destroyed(self, event) -> None:
        super()._destroyed(event)
        if event.widget is self.win and self._scan_id is not None:
            self.root.after_cancel(self._scan_id)
            self._scan_id = None

    def _wait_scan(self) -> None:
        self._scan_id = None
        if not self.win.winfo_exists():
            return
        if self._scan_result is None:
            self._scan_id = self.root.after(100, self._wait_scan)
            return
        self.scan = self._scan_result
        self.refresh()

    def refresh(self) -> None:
        self.rows = self.vault.rows()
        names = {name for e in self.vault.export_entries() for name, _ in e.attachments}
        found = suggestions(self.rows, self.journal, self.today, self.projects_root, names, self.scan)
        for widget in self.inner.winfo_children():
            widget.destroy()
        self.items = []
        row_index, last_section = 0, None
        for kind, title in SECTIONS:
            group = [s for s in found if s.kind == kind]
            if not group:
                continue
            if title != last_section:
                tk.Label(self.inner, text=title, fg=Dark.TEXT, bg="#222222", font=(UI_FONT, 10, "bold"), anchor="w",
                         padx=self.px(10), pady=self.px(4)).grid(row=row_index, column=0, columnspan=4, sticky="ew")
                row_index += 1
                last_section = title
            for s in group:
                var = None
                if s.actionable:
                    var = tk.BooleanVar(value=s.default)
                    ttk.Checkbutton(self.inner, variable=var, command=self._count, style="Row.TCheckbutton").grid(
                        row=row_index, column=0, sticky="w", padx=(self.px(8), 0))
                tk.Label(self.inner, text=s.title, fg=Dark.TEXT, bg=Dark.SURFACE, font=(UI_FONT, 10), anchor="w",
                         justify="left", wraplength=self.px(400)).grid(row=row_index, column=1, sticky="ew",
                                                                       pady=self.px(3))
                tk.Label(self.inner, text=s.reason, fg=Dark.MUTED, bg=Dark.SURFACE, font=(UI_FONT, 9), anchor="w",
                         justify="left", wraplength=self.px(200)).grid(row=row_index, column=2, sticky="ew",
                                                                       padx=self.px(8))
                text, color = KIND_TEXT[s.kind]
                tk.Label(self.inner, text=text, fg=color, bg=Dark.SURFACE, font=(UI_FONT, 8), padx=self.px(5),
                         highlightthickness=1, highlightbackground=Dark.PILL_LINE).grid(row=row_index, column=3,
                                                                                         sticky="e", padx=self.px(8))
                self.items.append((s, var))
                row_index += 1
        self.inner.columnconfigure(1, weight=1)
        if not found:
            tk.Label(self.inner, text="Чистить нечего.", fg=Dark.MUTED, bg=Dark.SURFACE, font=(UI_FONT, 10),
                     padx=self.px(10), pady=self.px(12)).grid(row=0, column=0, sticky="w")
        self._count()
        self._trash_state()

    def chosen(self) -> list[Suggestion]:
        return [s for s, var in self.items if var is not None and var.get()]

    def _count(self) -> None:
        n = len(self.chosen())
        self.apply_button.configure(text=f"Применить ({n})" if n else "Применить",
                                    state="normal" if n and not self._busy else "disabled")
        self.message.configure(text=f"Отмечено: {n}." if self.items else "", fg=Dark.MUTED)

    def _trash_state(self) -> None:
        count = len(self.vault.trashed())
        self.trash_label.configure(text=f"В корзине: {count}")
        self.empty_button.configure(state="normal" if count and not self._busy else "disabled")

    def apply(self) -> None:
        chosen = self.chosen()
        if self._busy or not chosen:
            return
        if any(s.kind != UNLINK for s in chosen) and not messagebox.askyesno(
                "PW_STORAGE", "Среди отмеченного есть удаления в корзину. Применить?", parent=self.win):
            return
        rows = self.rows

        def done(error, lines):
            if error is not None:
                self.message.configure(text=self.error_text(error), fg=Dark.ERROR)
                self._count()
                return
            self.audit.write("cleanup_applied", rows=lines)
            self.refresh()
            self.message.configure(text=f"Применено: {len(lines)}.", fg=Dark.OK)

        self.message.configure(text="Записываю файл с проверкой…", fg=Dark.MUTED)
        self.apply_button.configure(state="disabled")
        self.run(lambda: apply(self.vault, rows, chosen), done)

    def empty_trash(self) -> None:
        if self._busy:
            return
        count = len(self.vault.trashed())
        if not count or not messagebox.askyesno(
                "PW_STORAGE", f"Стереть {count} записей из корзины навсегда?\nСначала сделайте выгрузку на флэшку: "
                "в ней корзина ещё есть, после очистки записи останутся только там.", parent=self.win):
            return

        def done(error, erased):
            if error is not None:
                self.message.configure(text=self.error_text(error), fg=Dark.ERROR)
                return
            self.audit.write("trash_emptied", count=erased)
            self._trash_state()
            self.message.configure(text=f"Стёрто записей: {erased}.", fg=Dark.OK)

        self.empty_button.configure(state="disabled")
        self.run(self.vault.empty_trash, done)
