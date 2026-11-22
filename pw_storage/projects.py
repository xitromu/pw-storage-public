"""Подключение проекта (Т30).

Окно «Проекты»: слева все папки проектов с состоянием, справа выбранный проект — инструкция в AGENTS.md,
открытые файлы секретов, записи проекта, «Новая запись для проекта», «Подключить».

Подключён — в AGENTS.md проекта есть блок между метками PW_STORAGE. Блок пишется только после показа текста
и «Записать»; повторная запись заменяет блок, остальной файл не трогается. Открытые файлы секретов программа
только показывает: не читает и не удаляет.
"""

from __future__ import annotations

import os
import tkinter as tk
from dataclasses import dataclass, field
from pathlib import Path
from tkinter import ttk

from .cleanup import scan_projects
from .config import ALL_SCOPE, HOME, PYTHON, SYSTEM_SCOPE
from .vault import SCOPE_NAME, Row
from .window import UI_FONT, Dark, dark_title_bar, use_dark_theme

BEGIN = "<!-- PW_STORAGE: начало -->"
END = "<!-- PW_STORAGE: конец -->"
INSTRUCTION = f"""## Секреты
- Секреты проекта — только в хранилище PW_STORAGE. Не заводить secrets.env, .env, пароли в коде и в git.
- Что есть: "{PYTHON}" "{HOME / "pw.py"}" list — номера строк и комментарии, без значений.
- Доступ для всего проекта на срок: "{PYTHON}" "{HOME / "pw.py"}" open --why "зачем" НОМЕР_СТРОКИ — подставить нужные номера из list; владелец подтверждает выбранные строки в окне.
- "{PYTHON}" "{HOME / "pw.py"}" close закрывает доступ всему проекту и отменяет его ожидающие запросы.
- В скриптах: PwClient().get("сервис", "ключ"). Значения не печатать и не писать в файлы, журналы, чат.
- Нужен новый секрет — попросить владельца завести его в окне «Новая запись»."""


def block() -> str:
    return f"{BEGIN}\n{INSTRUCTION}\n{END}"


def has_instruction(folder: Path) -> bool:
    try:
        return BEGIN in (Path(folder) / "AGENTS.md").read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError):
        return False


def write_instruction(folder: Path) -> Path:
    """Дописывает или заменяет блок между метками. Кодировка (с BOM или без) и переводы строк файла сохраняются."""
    path = Path(folder) / "AGENTS.md"
    raw = path.read_bytes() if path.exists() else b""
    bom = raw.startswith(b"\xef\xbb\xbf")
    text = raw.decode("utf-8-sig") if raw else ""
    newline = "\r\n" if "\r\n" in text else "\n"
    text = text.replace("\r\n", "\n")
    start, end = text.find(BEGIN), text.find(END)
    if start != -1 and end > start:
        text = text[:start] + block() + text[end + len(END):]
    else:
        text = (text.rstrip("\n") + "\n\n" if text.strip() else "") + block() + "\n"
    data = text.replace("\n", newline).encode("utf-8")
    new = path.with_name(path.name + ".new")
    new.write_bytes((b"\xef\xbb\xbf" if bom else b"") + data)
    os.replace(new, path)
    return path


@dataclass
class ProjectInfo:
    name: str
    folder: Path
    exists: bool
    records: list[Row] = field(default_factory=list)
    instruction: bool = False
    open_files: list[str] = field(default_factory=list)  # пути от папки проекта

    @property
    def connected(self) -> bool:
        return self.instruction

    @property
    def state(self) -> tuple[str, str]:
        """(текст, цвет) для таблицы."""
        if not self.exists:
            return "папки нет", Dark.WARN
        files = f" · файлов: {len(self.open_files)}" if self.open_files else ""
        if self.connected:
            return ("✓" if self.records else "✓ записей нет") + files, Dark.OK if not files else Dark.WARN
        if self.records:
            return "нет инструкции" + files, Dark.WARN
        return "не подключён" + files, Dark.WARN if files else Dark.DIM


def project_folders(root: Path) -> list[str]:
    """Имена папок проектов, подключённых к хранилищу (блок инструкции в AGENTS.md)."""
    root = Path(root)
    if not root.is_dir():
        return []
    names = {p.name for p in root.iterdir() if p.is_dir() and SCOPE_NAME.match(p.name)}
    names -= {ALL_SCOPE, SYSTEM_SCOPE}
    return sorted((name for name in names if has_instruction(root / name)), key=str.lower)


def collect(root: Path, rows: list[Row], scanner=scan_projects) -> list[ProjectInfo]:
    """Все папки проектов и проекты из хранилища без папки."""
    root = Path(root)
    names = set()
    if root.is_dir():
        names = {p.name for p in root.iterdir() if p.is_dir() and SCOPE_NAME.match(p.name) and not p.name.startswith(".")}
    names |= {p for row in rows for p in row.projects} | {row.group for row in rows}
    out = []
    for name in sorted(names, key=str.lower):
        folder = root / name
        exists = folder.is_dir()
        records = [row for row in rows if name in row.projects or row.group == name]
        info = ProjectInfo(name, folder, exists, records, exists and has_instruction(folder))
        if exists:
            scan = scanner(folder)
            info.open_files = sorted(str(p.relative_to(folder)) for p in (*scan.open_files, *scan.jks))
        out.append(info)
    return out


class ProjectsWindow:
    def __init__(self, root, projects_root: Path, rows_source, add_secret, audit, on_close, test: bool = True,
                 take_focus: bool = True, scanner=scan_projects):
        """rows_source() → строки хранилища; add_secret(project, done) открывает окно новой записи и по закрытии
        вызывает done(ok) — окно администрирования перечитывает файл; on_close() — окно закрыто."""
        self.root = root
        self.projects_root = Path(projects_root)
        self.rows_source = rows_source
        self.add_secret = add_secret
        self.audit = audit
        self.on_close = on_close
        self.test = test
        self.scanner = scanner
        self.infos: list[ProjectInfo] = []
        self.selected: str | None = None
        self.preview = None
        self._refresh_after = None
        self._closed = False
        use_dark_theme(root)
        self.scale = root.winfo_fpixels("1i") / 96
        self.win = tk.Toplevel(root)
        self.win.title("PW_STORAGE" + (" (ТЕСТ)" if test else "") + ": проекты")
        self.win.configure(bg=Dark.BG)
        self.win.protocol("WM_DELETE_WINDOW", self.close)
        self.win.bind("<Destroy>", self._destroyed)
        body = self.body = tk.Frame(self.win, bg=Dark.BG, padx=self.px(18), pady=self.px(12))
        body.pack(fill="both", expand=True)
        dark_title_bar(self.win)
        self.win.bind("<Map>", lambda event: dark_title_bar(self.win) if event.widget is self.win else None)
        top = tk.Frame(body, bg=Dark.BG)
        top.pack(fill="x")
        self._label(top, "Проекты", size=15, bold=True).pack(side="left")
        self.summary = self._label(top, "", fg=Dark.MUTED, size=9)
        self.summary.pack(side="left", padx=(self.px(12), 0))
        split = tk.Frame(body, bg=Dark.BG)
        split.pack(fill="both", expand=True, pady=(self.px(10), 0))
        left = tk.Frame(split, bg=Dark.BG)
        left.pack(side="left", fill="y")
        self.tree = ttk.Treeview(left, columns=("name", "records", "state"), show="headings", height=14,
                                 selectmode="browse")
        for column, text, width, anchor in (("name", "Папка", 150, "w"), ("records", "Записей", 70, "e"),
                                            ("state", "Состояние", 190, "w")):
            self.tree.heading(column, text=text, anchor=anchor)
            self.tree.column(column, width=self.px(width), anchor=anchor, stretch=False)
        for tag, color in (("ok", Dark.OK), ("warn", Dark.WARN), ("dim", Dark.DIM)):
            self.tree.tag_configure(tag, foreground=color)
        self.tree.pack(side="left", fill="y")
        bar = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=bar.set)
        bar.pack(side="left", fill="y")
        self.tree.bind("<<TreeviewSelect>>", lambda _: self._selected())
        self.panel = tk.Frame(split, bg=Dark.SURFACE, padx=self.px(14), pady=self.px(12), width=self.px(420))
        self.panel.pack(side="left", fill="both", expand=True, padx=(self.px(14), 0))
        self.message = self._label(body, "", fg=Dark.MUTED, size=9, wraplength=self.px(820))
        self.message.pack(fill="x", pady=(self.px(8), 0))
        buttons = tk.Frame(body, bg=Dark.BG)
        buttons.pack(fill="x", pady=(self.px(8), 0))
        ttk.Button(buttons, text="Обновить", command=self.refresh).pack(side="left")
        ttk.Button(buttons, text="Закрыть", command=self.close).pack(side="right")
        if take_focus:
            self.win.focus_force()
        self.refresh()

    def px(self, value: float) -> int:
        return int(round(value * self.scale))

    def _label(self, parent, text, fg=Dark.TEXT, size=10, bold=False, bg=Dark.BG, **options) -> tk.Label:
        return tk.Label(parent, text=text, fg=fg, bg=bg, font=(UI_FONT, size, "bold") if bold else (UI_FONT, size),
                        justify="left", anchor="w", **options)

    def info(self, name: str | None) -> ProjectInfo | None:
        return next((i for i in self.infos if i.name == name), None)

    def refresh(self) -> None:
        self.infos = collect(self.projects_root, self.rows_source(), self.scanner)
        self.tree.delete(*self.tree.get_children())
        for info in self.infos:
            text, color = info.state
            tag = "ok" if color == Dark.OK else "warn" if color == Dark.WARN else "dim"
            self.tree.insert("", "end", iid=info.name, values=(info.name, len(info.records), text), tags=(tag,))
        folders = [i for i in self.infos if i.exists]
        connected = sum(1 for i in folders if i.connected)
        self.summary.configure(text=f"папок: {len(folders)} · подключено: {connected} · {self.projects_root}")
        keep = self.selected if self.info(self.selected) else (self._first_unconnected() or
                                                                (self.infos[0].name if self.infos else None))
        if keep:
            self.tree.selection_set(keep)
            self.tree.see(keep)
        self.selected = keep
        self._panel()

    def _first_unconnected(self) -> str | None:
        return next((i.name for i in self.infos if i.exists and not i.connected), None)

    def _selected(self) -> None:
        chosen = self.tree.selection()
        self.selected = chosen[0] if chosen else None
        self._panel()

    def _section(self, text: str) -> None:
        self._label(self.panel, text, fg=Dark.MUTED, size=9, bg=Dark.SURFACE).pack(fill="x", pady=(self.px(10), self.px(2)))

    def _panel(self) -> None:
        for widget in self.panel.winfo_children():
            widget.destroy()
        info = self.info(self.selected)
        if info is None:
            self._label(self.panel, "Папок проектов нет.", fg=Dark.MUTED, bg=Dark.SURFACE).pack(fill="x")
            return
        wrap = self.px(400)
        self._label(self.panel, info.name, size=14, bold=True, bg=Dark.SURFACE).pack(fill="x")
        where = str(info.folder) if info.exists else f"{info.folder} — папки нет"
        self._label(self.panel, f"{where} · записей в хранилище: {len(info.records)}", fg=Dark.MUTED, size=9,
                    bg=Dark.SURFACE, wraplength=wrap).pack(fill="x")
        if not info.exists:
            self._section("Проект есть в хранилище, а папки нет. Удалить его можно в окне «Чистка».")
            return
        self._section("Инструкция в AGENTS.md")
        row = tk.Frame(self.panel, bg=Dark.SURFACE)
        row.pack(fill="x")
        self._label(row, "есть" if info.instruction else "нет", fg=Dark.OK if info.instruction else Dark.WARN,
                    bg=Dark.SURFACE).pack(side="left")
        ttk.Button(row, text="Показать и записать…" if not info.instruction else "Показать и обновить…",
                   command=lambda: self.show_instruction(info.name)).pack(side="left", padx=(self.px(10), 0))
        self._section("Открытые файлы секретов и подписи — программа их не читает")
        self._label(self.panel, "\n".join(info.open_files) or "нет", fg=Dark.WARN if info.open_files else Dark.DIM,
                    bg=Dark.SURFACE, wraplength=wrap).pack(fill="x")
        if info.open_files:
            self._label(self.panel, "Значения перенесите в «Новая запись», файл удалите сами после проверки.",
                        fg=Dark.MUTED, size=9, bg=Dark.SURFACE, wraplength=wrap).pack(fill="x", pady=(self.px(2), 0))
        self._section("Записи проекта")
        lines = [f"{r.comment or '▲ без комментария'}" + ("" if info.name in r.projects else " (не в списке)")
                 for r in info.records[:12]]
        if len(info.records) > 12:
            lines.append(f"… и ещё {len(info.records) - 12}")
        self._label(self.panel, "\n".join(lines) or "пока нет", fg=Dark.TEXT if lines else Dark.DIM, bg=Dark.SURFACE,
                    wraplength=wrap).pack(fill="x")
        buttons = tk.Frame(self.panel, bg=Dark.SURFACE)
        buttons.pack(fill="x", pady=(self.px(14), 0))
        ttk.Button(buttons, text=f"Новая запись для {info.name}", command=lambda: self.new_record(info.name)).pack(side="left")
        connect = ttk.Button(buttons, text="Подключён" if info.connected else "Подключить", style="Accent.TButton",
                             command=lambda: self.show_instruction(info.name))
        connect.pack(side="right")
        if info.connected:
            connect.configure(state="disabled")

    def show_instruction(self, name: str) -> None:
        """Показ блока и «Записать»: без этого в AGENTS.md ничего не пишется."""
        info = self.info(name)
        if info is None or not info.exists:
            return
        if self.preview is not None and self.preview.winfo_exists():
            self.preview.destroy()
        win = self.preview = tk.Toplevel(self.win)
        win.title("PW_STORAGE: инструкция для " + name)
        win.configure(bg=Dark.BG)
        win.transient(self.win)
        body = tk.Frame(win, bg=Dark.BG, padx=self.px(16), pady=self.px(12))
        body.pack(fill="both", expand=True)
        dark_title_bar(win)
        path = info.folder / "AGENTS.md"
        action = ("заменён" if info.instruction else "дописан в конец") if path.exists() else "записан в новый файл"
        self._label(body, f"В {path} будет {action} этот блок; остальной текст файла не меняется:", fg=Dark.MUTED,
                    size=9, wraplength=self.px(620)).pack(fill="x")
        text = tk.Text(body, height=10, width=90, bg="#141414", fg=Dark.OK, insertbackground=Dark.TEXT, relief="flat",
                       font=("Consolas", 9), wrap="word", padx=self.px(8), pady=self.px(6))
        text.insert("1.0", block())
        text.configure(state="disabled")
        text.pack(fill="both", expand=True, pady=(self.px(6), 0))
        buttons = tk.Frame(body, bg=Dark.BG)
        buttons.pack(fill="x", pady=(self.px(10), 0))
        ttk.Button(buttons, text="Записать", style="Accent.TButton", command=lambda: self.write(name)).pack(side="right")
        ttk.Button(buttons, text="Отмена", command=win.destroy).pack(side="right", padx=(0, self.px(8)))

    def write(self, name: str) -> None:
        info = self.info(name)
        if self.preview is not None and self.preview.winfo_exists():
            self.preview.destroy()
        try:
            path = write_instruction(info.folder)
        except OSError as e:
            self.message.configure(text=f"Не удалось записать AGENTS.md: {type(e).__name__}", fg=Dark.ERROR)
            return
        self.audit.write("project_connected", project=name, target=str(path))
        self.message.configure(text=f"Инструкция записана: {path}.", fg=Dark.OK)
        self.refresh()

    def new_record(self, name: str) -> None:
        def done(ok: bool) -> None:
            if ok and not self._closed and self.win.winfo_exists():
                self.message.configure(text="Запись добавлена; список обновится, когда окно администрирования "
                                            "перечитает файл.", fg=Dark.OK)
                if self._refresh_after is not None:
                    self.win.after_cancel(self._refresh_after)
                self._refresh_after = self.win.after(1500, self._refresh_records)

        self.add_secret(name, done)

    def _refresh_records(self) -> None:
        self._refresh_after = None
        if not self._closed and self.win.winfo_exists():
            self.refresh()

    def _destroyed(self, event) -> None:
        if event.widget is self.win:
            self._closed = True
            if self._refresh_after is not None:
                self.win.after_cancel(self._refresh_after)
                self._refresh_after = None

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self.win.winfo_exists():
            self.win.destroy()
        self.on_close()
