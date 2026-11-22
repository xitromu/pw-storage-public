"""Окно доступа. Содержание — вариант Б макета (03.11.2026),
вид — вариант В «Тёмная компактная» (04.11.2026), тема sv-ttk.

Экран 1: кто просит, срок (можно изменить), запрос проекта, запрошенные строки с отметками и номерами,
предупреждение о строках без комментария, скрытый ввод пароля. Снятая отметка — строка этой сессии не выдаётся.
Экран 2: «Пароль принят», «Подтвердите на телефоне», оставшееся время, код из приложения на случай без связи.
Если перечня нет, экран 1 только собирает его заново по паролю: доступ при этом не выдаётся.

Пароль живёт только здесь и в посреднике этого же процесса: в журнал, на диск и в канал он не попадает.
Окна admin пока в прежнем светлом виде: для них остаются make_root, apply_style и светлые цвета ниже.
"""

from __future__ import annotations

import ctypes
import queue
import threading
import time
import tkinter as tk
from tkinter import font as tkfont
from tkinter import ttk

import sv_ttk

from . import catalog
from .config import CONFIRM_SECONDS, MAX_CODE_ATTEMPTS, MAX_GRANT_HOURS, MAX_PASSWORD_ATTEMPTS, valid_hours
from .second_factor import ALLOW, DENY, NoLink
from .vault import VaultError

# Светлый вид: окна admin
FONT = "Segoe UI"
BG = "#ffffff"
LIST_BG = "#f4f5f7"
MUTED = "#5f6672"
ERROR = "#b3261e"
OK = "#1b7f3b"
WARN = "#8a5a00"
PASSWORD_MASK = "•"
TELEGRAM_POLL_SECONDS = 2
CHANNEL_RETRY_MAX_SECONDS = 30  # дальше этого паузу между попытками канала не растим
TICK_MS = 100


def channel_retry_pause(failures: int) -> float:
    """Пауза после сбоя канала связи: растёт, но канал держим до конца времени подтверждения."""
    return min(CHANNEL_RETRY_MAX_SECONDS, TELEGRAM_POLL_SECONDS * (2 ** min(failures - 1, 4)))


CHANNEL_LABELS = {"telegram": "Telegram"}
CHANNEL_EVENTS = {"sent": "отправлено", "no_link": "нет связи", "retrying": "не отправлено",
                  "unavailable": "недоступен", ALLOW: "нажато «Разрешить»", DENY: "нажато «Отказать»"}


class Dark:
    """Цвета варианта В. Фон совпадает с фоном темы sv-ttk: у её виджетов нет рамки другого цвета."""
    BG = "#1c1c1c"
    SURFACE = "#2b2b2b"
    HEADER = "#262626"
    LINE = "#353535"
    TEXT = "#fafafa"
    MUTED = "#a7a7a7"
    DIM = "#7a7a7a"
    ID = "#8f8f8f"
    ACCENT = "#57c8ff"
    SOURCE = "#c6a6ff"
    WARN = "#ffd75e"
    ERROR = "#ff99a4"
    OK = "#6ccb5f"
    PILL = "#2d2d2d"
    PILL_LINE = "#3d3d3d"
    TEST_BG = "#4a3a00"
    TEST_FG = "#ffd75e"


UI_FONT = "Segoe UI Variable Text"
UI_FONT_STRONG = "Segoe UI Variable Text Semibold"
MONO_FONT = "Cascadia Mono"
LIST_MAX_PX = 260  # выше — прокрутка
CONTENT_PX = 500
CODE_DIGITS = 6
SV_FONTS_PT = {"SunValleyCaptionFont": 9, "SunValleyBodyFont": 10, "SunValleyBodyStrongFont": 10,
               "SunValleyBodyLargeFont": 13, "SunValleySubtitleFont": 15, "SunValleyTitleFont": 21,
               "SunValleyTitleLargeFont": 30, "SunValleyDisplayFont": 51}


def make_root() -> tk.Tk:
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except (AttributeError, OSError):
        pass
    root = tk.Tk()
    root.withdraw()
    apply_style(root)
    return root


def apply_style(root: tk.Misc) -> None:
    style = ttk.Style(root)
    if "vista" in style.theme_names():
        style.theme_use("vista")
    style.configure("Card.TFrame", background=BG)
    style.configure("Card.TLabel", background=BG, font=(FONT, 10))
    style.configure("Title.TLabel", background=BG, font=(FONT, 14, "bold"))
    style.configure("Muted.TLabel", background=BG, foreground=MUTED, font=(FONT, 10))
    style.configure("Error.TLabel", background=BG, foreground=ERROR, font=(FONT, 10))
    style.configure("Warn.TLabel", background=BG, foreground=WARN, font=(FONT, 10))
    style.configure("Ok.TLabel", background=BG, foreground=OK, font=(FONT, 11, "bold"))
    style.configure("Timer.TLabel", background=BG, foreground=MUTED, font=(FONT, 12))
    style.configure("TButton", font=(FONT, 10), padding=(10, 4))
    style.configure("Accent.TButton", font=(FONT, 10, "bold"), padding=(10, 4))


def use_dark_theme(root: tk.Tk) -> None:
    """Тёмная тема sv-ttk. Её шрифты заданы в пикселях и не растут с масштабом экрана: переводим в пункты."""
    if getattr(root, "_pw_dark", False):
        return
    sv_ttk.set_theme("dark", root)
    for name, points in SV_FONTS_PT.items():
        try:
            tkfont.nametofont(name, root=root).configure(size=points)
        except tk.TclError:
            pass
    families = set(tkfont.families(root))
    global UI_FONT, UI_FONT_STRONG, MONO_FONT
    if UI_FONT not in families:
        UI_FONT = UI_FONT_STRONG = "Segoe UI"
    if MONO_FONT not in families:
        MONO_FONT = "Consolas"
    style = ttk.Style(root)
    style.configure("Row.TCheckbutton", background=Dark.SURFACE)
    root._pw_dark = True


def dark_title_bar(win: tk.Misc) -> None:
    """Тёмная строка заголовка Windows 11, как в макете. На других версиях молча остаётся светлой."""
    try:
        win.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(win.winfo_id())
        value = ctypes.c_int(1)
        ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(value), ctypes.sizeof(value))
    except (AttributeError, OSError):
        pass


def rows_word(count: int) -> str:
    if count % 10 == 1 and count % 100 != 11:
        return f"{count} строка"
    if 2 <= count % 10 <= 4 and not 12 <= count % 100 <= 14:
        return f"{count} строки"
    return f"{count} строк"


class SecretEntry(tk.Frame):
    """Скрытое поле с глазком: показать написанное и скрыть снова. Значок нарисован, чтобы не зависеть от шрифта.

    Обёртка — tk.Frame с явным фоном: ttk.Frame под темой sv-ttk рисовал вокруг глазка светлый прямоугольник.
    """

    def __init__(self, parent, textvariable, bg=BG, color=MUTED, **entry_options):
        super().__init__(parent, bg=bg)
        self.entry = ttk.Entry(self, textvariable=textvariable, show=PASSWORD_MASK, **entry_options)
        self.entry.pack(side="left", fill="x", expand=True)
        self.eye = tk.Canvas(self, width=30, height=24, bg=bg, highlightthickness=0, cursor="hand2", takefocus=0)
        self.eye.pack(side="left", padx=(6, 0))
        self.eye.create_polygon(3, 12, 10, 5, 20, 5, 27, 12, 20, 19, 10, 19, smooth=True, fill="", outline=color, width=1.5)
        self.eye.create_oval(11, 8, 19, 16, fill=color, outline="")
        self._slash = self.eye.create_line(5, 21, 25, 3, fill=color, width=2)
        self.eye.bind("<Button-1>", lambda _: self.toggle())
        self.shown = False

    def toggle(self) -> None:
        self.shown = not self.shown
        self.entry.configure(show="" if self.shown else PASSWORD_MASK)
        # Зачёркнутый глаз: текст скрыт.
        self.eye.itemconfigure(self._slash, state="hidden" if self.shown else "normal")


class CodeCells(tk.Frame):
    """Шесть клеток для кода из приложения. Цифра переводит в следующую клетку, вставка раскладывается по клеткам."""

    def __init__(self, parent, on_enter):
        super().__init__(parent, bg=Dark.BG)
        self.vars = [tk.StringVar() for _ in range(CODE_DIGITS)]
        self.cells = []
        self._busy = False
        for i, var in enumerate(self.vars):
            cell = ttk.Entry(self, textvariable=var, width=2, justify="center", font=(MONO_FONT, 14))
            cell.pack(side="left", padx=(0, 6))
            cell.bind("<BackSpace>", lambda e, i=i: self._back(i))
            cell.bind("<Return>", lambda e: on_enter())
            var.trace_add("write", lambda *_, i=i: self._changed(i))
            self.cells.append(cell)

    def _changed(self, index: int) -> None:
        if self._busy:
            return
        digits = "".join(ch for ch in self.vars[index].get() if ch.isdigit())
        self._busy = True
        try:
            self.vars[index].set(digits[:1])
            for offset, ch in enumerate(digits[1:], start=1):  # вставка нескольких цифр
                if index + offset < CODE_DIGITS:
                    self.vars[index + offset].set(ch)
        finally:
            self._busy = False
        if digits:
            self.cells[min(index + len(digits), CODE_DIGITS - 1)].focus_set()

    def _back(self, index: int) -> None:
        if not self.vars[index].get() and index > 0:
            self.vars[index - 1].set("")
            self.cells[index - 1].focus_set()

    def get(self) -> str:
        return "".join(var.get() for var in self.vars)

    def set(self, value: str) -> None:
        self._busy = True
        try:
            for i, var in enumerate(self.vars):
                var.set(value[i] if i < len(value) else "")
        finally:
            self._busy = False

    def focus_set(self) -> None:
        self.cells[0].focus_set()

    def configure_state(self, state: str) -> None:
        for cell in self.cells:
            cell.configure(state=state)


class _RequestState:
    """Worker-visible state contains no Tk objects. Phase claims are atomic."""

    def __init__(self, clock, deadline, on_channels_closed=None):
        self.lock = threading.RLock()
        self.clock = clock
        self.deadline = deadline
        self.confirm_deadline = None
        self.phase = "password"
        self.generation = 0
        self.finished = False
        self.events = queue.Queue()
        self.on_channels_closed = on_channels_closed
        self.channel_workers = 0
        self.done_completed = False
        self._channels_closed_notified = False

    def add_channel_worker(self):
        with self.lock:
            if self.finished:
                return False
            self.channel_workers += 1
            return True

    def channel_worker_closed(self):
        with self.lock:
            self.channel_workers -= 1
        self.notify_channels_closed()

    def notify_channels_closed(self):
        with self.lock:
            # The broker must see UI completion before it can release the drained lease.
            if not self.finished or not self.done_completed or self.channel_workers or self._channels_closed_notified:
                return
            self._channels_closed_notified = True
            callback, self.on_channels_closed = self.on_channels_closed, None
        if callback is not None:
            callback()

    def expired(self):
        return (self.clock() >= self.deadline or
                self.confirm_deadline is not None and self.clock() >= self.confirm_deadline)

    def active(self, token):
        with self.lock:
            return not self.finished and not self.expired() and token == self.generation

    def claim(self, expected, phase):
        with self.lock:
            if self.finished or self.expired() or self.phase != expected:
                return None
            self.phase = phase
            self.generation += 1
            return self.generation

    def emit(self, token, kind, value):
        with self.lock:
            if self.active(token):
                self.events.put((token, kind, value))


class _Channel:
    """Only a worker performs slow operations and cleanup; GUI just signals."""

    def __init__(self, confirm, remote=False, kind="", previous=None):
        self.confirm = confirm
        self.remote = remote
        self.kind = kind
        self.previous = previous
        self.closed = threading.Event()
        self.stop = threading.Event()
        self.status = "Доступ не выдан: запрос закрыт.\nОтвет не нужен"

    def cancel(self, status):
        self.status = status
        self.stop.set()
        cancel = getattr(self.confirm, "cancel", None)
        if cancel is not None:
            cancel()  # nonblocking signal, not finish's slow operation lock

    def close(self):
        try:
            if self.remote:
                self.confirm.say(self.status)
            else:
                self.confirm.finish(self.status)
        except Exception:
            pass
        finally:
            self.closed.set()


class AccessWindow:
    def __init__(self, root, request, unlock, done, clock=time.monotonic, take_focus=True, remote=None, unlock_remote=None,
                 on_forgot=None, request_deadline=None, on_channels_closed=None):
        self.root = root
        self.on_forgot = on_forgot  # (root, on_close) → окно восстановления или None; None — кнопки нет
        self._recovery = None
        self.request = request
        self.unlock = unlock
        self.done = done
        self.remote = remote or {}
        self.remote_status = {kind: "sending" for kind in self.remote}
        self.unlock_remote = unlock_remote
        self._stop_remote = threading.Event()
        self.clock = clock
        self.finished = False
        self.unlocked = None
        self.password_attempts = 0
        self.code_attempts = 0
        self.deadline = None
        self.telegram_sent = False
        self.channel_status: dict[str, str] = {}  # чем закончилась каждая попытка канала: попадает в журнал
        self._tick_id = None
        self._state = _RequestState(clock, clock() + 1080 if request_deadline is None else request_deadline,
                                    on_channels_closed)
        self._events = self._state.events
        self._channels: dict[str, _Channel] = {}
        self._stop_telegram = threading.Event()
        self.choices: list[tuple[str, tk.BooleanVar, ttk.Checkbutton, tk.Label, tk.Label | None]] = []
        self.hours_box = None
        self.list_canvas = None

        use_dark_theme(root)
        self.scale = root.winfo_fpixels("1i") / 96
        self.win = tk.Toplevel(root)
        mark = " (ТЕСТ)" if request.test else ""
        self.win.title(f"PW_STORAGE{mark}: доступ к секретам")
        self.win.configure(bg=Dark.BG)
        self.win.resizable(False, False)
        self.win.protocol("WM_DELETE_WINDOW", self.deny)
        self.win.bind("<MouseWheel>", self._wheel)
        self.win.bind("<Destroy>", self._destroyed, add="+")
        self.body = tk.Frame(self.win, bg=Dark.BG, padx=self.px(18), pady=self.px(12))
        self.body.pack(fill="both", expand=True)
        dark_title_bar(self.win)
        self._show_password_screen()
        self._center()
        if take_focus:
            self.win.attributes("-topmost", True)
            self.win.lift()
            self.win.focus_force()
            self.password_entry.focus_set()
        for kind, listener in self.remote.items():
            if self._state.add_channel_worker():
                channel = self._channels["remote_" + kind] = _Channel(listener, remote=True, kind=kind)
                threading.Thread(target=AccessWindow._remote_worker,
                                 args=(self._state, channel,
                                       lambda code, k=kind: self.unlock_remote(code, k)), daemon=False).start()
        self._tick()

    def px(self, value: float) -> int:
        return int(round(value * self.scale))

    # Мелкие части вида

    def _label(self, parent, text, fg=Dark.TEXT, bg=Dark.BG, size=10, font=None, **options) -> tk.Label:
        return tk.Label(parent, text=text, fg=fg, bg=bg, font=font or (UI_FONT, size), justify="left", anchor="w",
                        **options)

    def _pill(self, parent, text, fg=Dark.MUTED, bg=Dark.PILL, line=Dark.PILL_LINE) -> tk.Label:
        pill = tk.Label(parent, text=text, fg=fg, bg=bg, font=(UI_FONT, 9), padx=self.px(7), pady=0,
                        highlightthickness=1, highlightbackground=line, highlightcolor=line)
        pill.pack(side="left", padx=(self.px(6), 0))
        return pill

    def _test_pill(self, parent) -> None:
        if self.request.test:
            self._pill(parent, "ТЕСТ", fg=Dark.TEST_FG, bg=Dark.TEST_BG, line="#7a6100")

    def _test_notice(self) -> None:
        if self.request.test:
            self._label(self.body, "Тестовое хранилище: настоящий пароль сюда не вводите.", fg=Dark.WARN,
                        size=9).pack(anchor="w", pady=(self.px(4), 0))

    def _warn(self, text: str) -> tk.Label:
        label = self._label(self.body, text, fg=Dark.WARN, size=9, wraplength=self.px(CONTENT_PX))
        label.pack(anchor="w", pady=(self.px(8), 0))
        return label

    def _wheel(self, event) -> None:
        if self.list_canvas is not None and self.list_canvas.winfo_exists() and self._scrolls:
            self.list_canvas.yview_scroll(-1 if event.delta > 0 else 1, "units")

    def _list_area(self) -> tk.Frame:
        """Таблица строк: прокручивается, если не помещается."""
        outer = tk.Frame(self.body, bg=Dark.SURFACE)
        outer.pack(fill="x", pady=(self.px(10), 0))
        self.list_canvas = tk.Canvas(outer, bg=Dark.SURFACE, highlightthickness=0, bd=0, width=self.px(CONTENT_PX),
                                     yscrollincrement=self.px(16))
        inner = tk.Frame(self.list_canvas, bg=Dark.SURFACE)
        item = self.list_canvas.create_window((0, 0), window=inner, anchor="nw")
        self.list_canvas.bind("<Configure>", lambda e: self.list_canvas.itemconfigure(item, width=e.width))
        self._list_outer, self._list_inner = outer, inner
        self._scrolls = False
        self.list_canvas.pack(side="left", fill="both", expand=True)
        return inner

    def _fit_list(self) -> None:
        self._list_inner.update_idletasks()
        height = self._list_inner.winfo_reqheight()
        limit = self.px(LIST_MAX_PX)
        self.list_canvas.configure(height=min(height, limit), scrollregion=(0, 0, 0, height))
        self._scrolls = height > limit
        if self._scrolls:
            bar = ttk.Scrollbar(self._list_outer, orient="vertical", command=self.list_canvas.yview)
            self.list_canvas.configure(yscrollcommand=bar.set)
            bar.pack(side="right", fill="y")

    def _table_head(self, inner, columns) -> None:
        """Шапка таблицы: (колонка, текст). Строк-разделов с именем проекта нет: проект крупно в заголовке окна."""
        for column, text in columns:
            cell = self._label(inner, text, fg=Dark.MUTED, bg=Dark.HEADER, size=8, padx=self.px(10), pady=self.px(5))
            cell.grid(row=0, column=column, sticky="ew")

    def _whose(self, item_projects) -> tuple[str, str]:
        """Третья колонка: строка этого проекта или из ALL."""
        if self.request.project in item_projects:
            return self.request.project, Dark.MUTED
        return "ALL", Dark.SOURCE

    COMMON_HINT = "Строки ALL с отметкой после одобрения закрепятся за проектом."

    # Экран 1

    def _show_password_screen(self) -> None:
        self._clear()
        self.hours_var = tk.StringVar(value=str(self.request.hours))
        if self.request.rebuild:
            top = tk.Frame(self.body, bg=Dark.BG)
            top.pack(anchor="w")
            self._label(top, "Перечень строк недоступен", font=(UI_FONT_STRONG, 14)).pack(side="left")
            self._test_pill(top)
            self._test_notice()
            self._label(self.body, f"Сессия {self.request.project} просит доступ, но перечня строк на этом ПК нет "
                                   "(новый ПК или перечень прежнего вида). Введите пароль: соберу перечень заново. "
                                   "Доступ при этом не выдаётся, сессия запросит строки снова.",
                        fg=Dark.MUTED, wraplength=self.px(CONTENT_PX)).pack(anchor="w", pady=(self.px(8), 0))
        else:
            self._request_head()
        self._label(self.body, "Пароль хранилища", fg=Dark.MUTED, size=9).pack(anchor="w", pady=(self.px(14), self.px(4)))
        self.password_var = tk.StringVar()
        self.password_field = SecretEntry(self.body, self.password_var, bg=Dark.BG, color=Dark.MUTED,
                                          font=(UI_FONT, 11))
        self.password_field.pack(fill="x")
        self.password_entry = self.password_field.entry
        self.message_label = self._label(self.body, "", fg=Dark.ERROR, size=9)
        self.message_label.pack(anchor="w", pady=(self.px(4), 0))
        self.remote_label = None
        if self.remote:
            self.remote_label = self._label(self.body, "", fg=Dark.MUTED, size=9,
                                            wraplength=self.px(CONTENT_PX))
            self.remote_label.pack(anchor="w", pady=(self.px(4), 0))
            self._show_remote_status()

        buttons = tk.Frame(self.body, bg=Dark.BG)
        buttons.pack(fill="x", pady=(self.px(8), 0))
        self.forgot_link = None
        if self.on_forgot is not None:
            self.forgot_link = self._label(buttons, "Забыли пароль?", fg=Dark.ACCENT, size=9, cursor="hand2")
            self.forgot_link.pack(side="left")
            self.forgot_link.bind("<Button-1>", lambda _: self.forgot())
        action = "Собрать перечень" if self.request.rebuild else "Продолжить"
        self.continue_button = ttk.Button(buttons, text=action, style="Accent.TButton", command=self.submit_password)
        self.continue_button.pack(side="right")
        self.deny_button = ttk.Button(buttons, text="Отказать", command=self.deny)
        self.deny_button.pack(side="right", padx=(0, self.px(8)))
        if self.choices:
            self._on_choice()
        self.win.bind("<Return>", lambda _: self.submit_password())
        self.win.bind("<Escape>", lambda _: self.deny())

    def _request_head(self) -> None:
        top = tk.Frame(self.body, bg=Dark.BG)
        top.pack(anchor="w", fill="x")
        self._label(top, f"{self.request.project} просит секреты", font=(UI_FONT_STRONG, 14)).pack(side="left")
        self._test_pill(top)
        self._pill(top, rows_word(len(self.request.rows)))
        hours = tk.Frame(top, bg=Dark.BG)
        hours.pack(side="left", padx=(self.px(8), 0))
        self._label(hours, "на", fg=Dark.ACCENT, size=9).pack(side="left")
        self.hours_box = ttk.Spinbox(hours, from_=1, to=MAX_GRANT_HOURS, textvariable=self.hours_var, width=5,
                                     font=(UI_FONT, 9))
        self.hours_box.pack(side="left", padx=self.px(4))
        self._label(hours, f"ч (1–{MAX_GRANT_HOURS})", fg=Dark.ACCENT, size=9).pack(side="left")
        self._test_notice()
        self._label(self.body, "Выбранные строки будут доступны всем сессиям проекта на указанный срок.",
                    fg=Dark.MUTED, size=9, wraplength=self.px(CONTENT_PX)).pack(anchor="w", pady=(self.px(8), 0))
        self._label(self.body, "Запрос проекта:", fg=Dark.MUTED, size=9).pack(anchor="w", pady=(self.px(10), 0))
        self.why_label = self._label(self.body, self.request.why or "не указан", wraplength=self.px(CONTENT_PX))
        self.why_label.pack(anchor="w")
        if self.request.listing.state == catalog.STALE:
            self._warn("▲ Файл хранилища менялся вне программы, перечень может быть неточным. "
                       "Точный список — после ввода пароля.")
        self._choices()
        if self.request.unnamed:
            self._warn(f"▲ Строки без комментария не показаны и не выдаются: {self.request.unnamed} у "
                       f"{self.request.project}. Комментарий — в KeePassXC.")

    def _choices(self) -> None:
        """Запрошенные строки с отметками и номерами (вариант В). Щелчок по тексту тоже меняет отметку."""
        inner = self._list_area()
        inner.columnconfigure(1, weight=1)
        self._table_head(inner, ((0, ""), (1, "СТРОКА"), (2, "ЧЬЯ"), (3, "НОМЕР")))
        row = 1
        wrap = self.px(CONTENT_PX - 200)
        for item in (*self.request.own, *self.request.common):
            var = tk.BooleanVar(value=True)
            box = ttk.Checkbutton(inner, variable=var, command=self._on_choice, style="Row.TCheckbutton")
            box.grid(row=row, column=0, sticky="nw", padx=(self.px(8), 0), pady=(self.px(3), 0))
            text = self._label(inner, item.comment, bg=Dark.SURFACE, wraplength=wrap, padx=self.px(10))
            text.grid(row=row, column=1, sticky="ew", pady=self.px(6))
            whose, color = self._whose(item.projects)
            source = self._label(inner, whose, fg=color, bg=Dark.SURFACE, size=9, padx=self.px(10))
            source.grid(row=row, column=2, sticky="nw", pady=self.px(7))
            uid = self._label(inner, item.uid, fg=Dark.ID, bg=Dark.SURFACE, font=(MONO_FONT, 9), padx=self.px(10))
            uid.grid(row=row, column=3, sticky="ne", pady=self.px(7))
            for widget in (text, source, uid):
                widget.bind("<Button-1>", lambda e, b=box: self._toggle(b))
            self.choices.append((item.uid, var, box, text, source))
            row += 1
            tk.Frame(inner, bg=Dark.LINE, height=1).grid(row=row, column=0, columnspan=4, sticky="ew")
            row += 1
        self._fit_list()
        if self.request.common:
            self._label(self.body, self.COMMON_HINT, fg=Dark.MUTED, size=9).pack(anchor="w", pady=(self.px(4), 0))

    def _toggle(self, box: ttk.Checkbutton) -> None:
        if "disabled" not in box.state():
            box.invoke()

    def chosen(self) -> list[str]:
        return [uid for uid, var, *_ in self.choices if var.get()]

    def _on_choice(self) -> None:
        for _, var, _, text, source in self.choices:
            on = var.get()
            text.configure(fg=Dark.TEXT if on else Dark.DIM, font=(UI_FONT, 10) if on else (UI_FONT, 10, "overstrike"))
            if source is not None:
                base = Dark.SOURCE if source.cget("text") == "ALL" else Dark.MUTED
                source.configure(fg=base if on else Dark.DIM)
        count = len(self.chosen())
        self.continue_button.configure(text=f"Одобрить {count} из {len(self.choices)}",
                                       state="normal" if count else "disabled")

    def _set_inputs(self, state: str) -> None:
        for _, _, box, *_ in self.choices:
            box.configure(state=state)
        if self.hours_box is not None:
            self.hours_box.configure(state=state)

    def forgot(self) -> None:
        """Восстановление поверх запроса: запрос ждёт, после нового пароля его вводят здесь же."""
        if self._recovery is not None or self.unlocked is not None or self.finished:
            return
        self._recovery = self.on_forgot(self.root, self._recovered)
        if self._recovery is None:
            self.message_label.configure(text="Восстановление недоступно: нет файла восстановления", fg=Dark.ERROR)

    def _recovered(self, ok: bool) -> None:
        self._recovery = None
        if self.finished:
            return
        if ok:
            self.message_label.configure(text="Пароль изменён: введите новый пароль", fg=Dark.OK)
        self.win.lift()
        self.password_entry.focus_set()

    def submit_password(self) -> None:
        if self.finished or self._expire() or self.unlocked is not None or str(self.continue_button["state"]) == "disabled":
            return
        hours = valid_hours(self.hours_var.get())
        if hours is None:
            self.message_label.configure(text=f"Срок — целое число часов от 1 до {MAX_GRANT_HOURS}", fg=Dark.ERROR)
            return
        chosen = None if self.request.rebuild else self.chosen()
        if chosen is not None and not chosen:
            self.message_label.configure(text="Отметьте хотя бы одну строку или откажите", fg=Dark.ERROR)
            return
        password = self.password_var.get()
        if not password:
            self.message_label.configure(text="Введите пароль", fg=Dark.ERROR)
            return
        token = self._state.claim("password", "local")
        if token is None:
            return  # a remote code already owns this unlock phase
        self._submitted_hours = hours
        self._close_remote("Пароль введён на ПК, код больше не нужен.\nОтвет не нужен")
        self.password_var.set("")
        self.continue_button.configure(state="disabled")
        self._set_inputs("disabled")
        self.message_label.configure(text="Проверяю пароль…", fg=Dark.MUTED)
        threading.Thread(target=AccessWindow._unlock_worker,
                         args=(self._state, token, self.unlock, password, chosen, hours), daemon=True).start()

    @staticmethod
    def _unlock_worker(state, token, unlock, password, chosen, hours) -> None:
        try:
            if not state.active(token):
                return
            result = unlock(password, chosen, hours)
            state.emit(token, "unlocked", result)
            if result is not None and not state.active(token):
                for confirm in (result.telegram,):
                    if confirm is not None:
                        _Channel(confirm).close()
        except VaultError as e:
            state.emit(token, "unlock_error", str(e))
        except Exception as e:
            state.emit(token, "unlock_error", f"Ошибка открытия файла: {type(e).__name__}")
        finally:
            password = None

    def _on_unlocked(self, result) -> None:
        if self.finished or self._expire():
            return
        if result is None:
            self._state.claim("local", "password")
            self.password_attempts += 1
            left = MAX_PASSWORD_ATTEMPTS - self.password_attempts
            if left <= 0:
                self.finish(False, reason=f"неверный пароль {MAX_PASSWORD_ATTEMPTS} раз")
                return
            self.message_label.configure(text=f"Неверный пароль. Осталось попыток: {left}", fg=Dark.ERROR)
            self._enable_inputs()
            self.password_entry.focus_set()
            return
        if result.rebuilt:
            self.finish(False, reason="перечень собран заново: запросите строки снова (pw.py list)")
            return
        if not result.own and not result.common:
            self.finish(False, reason="запрошенных строк нет в хранилище")
            return
        if result.verify_code is None and result.telegram is None:
            self.finish(False, reason="нет способа подтверждения: ни кнопки, ни кода")
            return
        self.unlocked = result
        self.granted_hours = self._submitted_hours
        self._close_remote("Пароль введён на ПК, код больше не нужен.\nОтвет не нужен")
        self._show_confirm_screen()

    def _enable_inputs(self) -> None:
        self._set_inputs("normal")
        self.continue_button.configure(state="normal")
        if self.choices:
            self._on_choice()

    # Экран 2

    def _comments(self, own: list[str], common: list[str]) -> tk.Frame:
        """Что будет выдано, по файлу хранилища: показывается после пароля, если перечень был неточным."""
        inner = self._list_area()
        inner.columnconfigure(0, weight=1)
        self._table_head(inner, ((0, "СТРОКА"), (1, "ЧЬЯ")))
        row = 1
        rows = [(comment, self.request.project, Dark.MUTED) for comment in own]
        rows += [(comment, "ALL", Dark.SOURCE) for comment in common]
        for comment, whose, color in rows:
            self._label(inner, f"•  {comment}", bg=Dark.SURFACE, padx=self.px(10), pady=self.px(4),
                        wraplength=self.px(CONTENT_PX - 100)).grid(row=row, column=0, sticky="ew")
            self._label(inner, whose, fg=color, bg=Dark.SURFACE, size=9, padx=self.px(10)).grid(row=row, column=1,
                                                                                               sticky="nw")
            row += 1
        self._fit_list()
        return inner

    def _show_confirm_screen(self) -> None:
        self._clear()
        self.choices = []
        self.hours_box = None
        top = tk.Frame(self.body, bg=Dark.BG)
        top.pack(anchor="w", fill="x")
        self._label(top, "✓ Пароль принят", fg=Dark.OK, font=(UI_FONT_STRONG, 14)).pack(side="left")
        self._test_pill(top)
        self._pill(top, rows_word(len(self.unlocked.own) + len(self.unlocked.common)))
        self._pill(top, f"на {self.granted_hours} ч")
        self._test_notice()
        self._label(self.body, "Подтвердите на телефоне", size=12).pack(anchor="w", pady=(self.px(10), 0))
        self.timer_label = self._label(self.body, "", font=(MONO_FONT, 30))
        self.timer_label.pack(anchor="w")
        status = tk.Frame(self.body, bg=Dark.BG)
        status.pack(anchor="w", fill="x")
        self.phone_dot = self._label(status, "●", fg=Dark.DIM, size=9)
        self.phone_dot.pack(side="left", anchor="n")
        self.phone_label = self._label(status, "", fg=Dark.TEXT, size=9, wraplength=self.px(CONTENT_PX - 20))
        self.phone_label.pack(side="left", padx=(self.px(4), 0))

        if self.request.listing.state != catalog.FRESH:
            self._comments(self.unlocked.own, self.unlocked.common)

        tk.Frame(self.body, bg=Dark.LINE, height=1).pack(fill="x", pady=(self.px(14), self.px(10)))
        self.code_var = None
        self.code_entry = None
        if self.unlocked.verify_code is not None:
            self._label(self.body, "Нет связи? Код из приложения-аутентификатора", fg=Dark.MUTED,
                        size=9).pack(anchor="w", pady=(0, self.px(6)))
            self.code_var = self.code_entry = CodeCells(self.body, self.submit_code)
            self.code_entry.pack(anchor="w")
        self.message_label = self._label(self.body, "", fg=Dark.ERROR, size=9)
        self.message_label.pack(anchor="w", pady=(self.px(4), 0))

        buttons = tk.Frame(self.body, bg=Dark.BG)
        buttons.pack(fill="x", pady=(self.px(8), 0))
        self.code_button = None
        if self.unlocked.verify_code is not None:
            self.code_button = ttk.Button(buttons, text="Подтвердить кодом", style="Accent.TButton", command=self.submit_code)
            self.code_button.pack(side="right")
        self.cancel_button = ttk.Button(buttons, text="Отменить", command=self.cancel)
        self.cancel_button.pack(side="right", padx=(0, self.px(8)))
        self.win.bind("<Return>", lambda _: self.submit_code())
        self.win.bind("<Escape>", lambda _: self.cancel())
        self.win.protocol("WM_DELETE_WINDOW", self.cancel)

        token = self._state.claim("local", "confirm")
        self.deadline = min(self.clock() + CONFIRM_SECONDS, self._state.deadline)
        self._state.confirm_deadline = self.deadline
        if token is not None:
            for kind, confirm in (("telegram", self.unlocked.telegram),):
                if confirm is not None and self._state.add_channel_worker():
                    channel = self._channels[kind] = _Channel(confirm,
                                                               previous=self._channels.get("remote_" + kind))
                    setattr(self, "_stop_" + kind, channel.stop)
                    threading.Thread(target=AccessWindow._confirm_worker,
                                     args=(self._state, token, kind, channel), daemon=False).start()
        channels = self._channels_text()
        if channels:
            self._phone(f"Отправляю запрос в {channels}…", Dark.DIM)
        else:
            self._phone("Кнопки выключены: подтвердите кодом из приложения.", Dark.DIM)
        if self.code_entry is not None:
            self.code_entry.focus_set()
        self._center()

    def _channels_text(self, *, sent_only=False) -> str:
        if self.unlocked is None or self.unlocked.telegram is None:
            return ""
        return "" if sent_only and not self.telegram_sent else "Telegram"

    def _phone(self, text: str, color: str) -> None:
        self.phone_label.configure(text=text)
        self.phone_dot.configure(fg=color)

    def submit_code(self) -> None:
        if self.finished or self._expire() or self.unlocked is None or self.unlocked.verify_code is None:
            return
        code = self.code_var.get()
        self.code_var.set("")
        if self.unlocked.verify_code(code):
            self.finish(True, via="code")
            return
        self.code_attempts += 1
        left = MAX_CODE_ATTEMPTS - self.code_attempts
        if left <= 0:
            self.finish(False, reason=f"неверный код {MAX_CODE_ATTEMPTS} раз")
            return
        self.message_label.configure(text=f"Код не подошёл. Осталось попыток: {left}")
        self.code_entry.focus_set()

    @staticmethod
    def _confirm_worker(state, token, kind, channel) -> None:
        sent = False
        failures = 0
        try:
            while not channel.stop.is_set() and state.active(token):
                if channel.previous is not None and not channel.previous.closed.is_set():
                    channel.stop.wait(0.05)
                    continue
                pause = TELEGRAM_POLL_SECONDS
                try:
                    if not sent:
                        channel.confirm.start()
                        if channel.stop.is_set() or not state.active(token):
                            break
                        sent = True
                        state.emit(token, kind, "sent")
                    else:
                        result = channel.confirm.poll()
                        if result is not None:
                            state.emit(token, kind, result)
                            # Stay alive until GUI chooses the final cleanup status.
                            channel.stop.wait(max(0, min(state.deadline, state.confirm_deadline) - state.clock()))
                            break
                    failures = 0
                except NoLink:
                    # Решение владельца должно дойти хоть откуда-то: сеть может пропасть на несколько секунд,
                    # канал не закрываем, а повторяем с нарастающей паузой до конца времени подтверждения.
                    failures += 1
                    pause = channel_retry_pause(failures)
                    state.emit(token, kind, "no_link" if sent else "retrying")
                except Exception:
                    state.emit(token, kind, "unavailable")
                    break  # terminal errors are not retried
                if channel.stop.wait(pause):
                    break
        finally:
            channel.close()
            state.channel_worker_closed()

    def _note_channel(self, kind: str, event: str) -> None:
        self.channel_status[kind] = CHANNEL_EVENTS.get(event, event)

    def _on_telegram(self, event: str) -> None:
        if self.finished or self._expire():
            return
        self._note_channel("telegram", event)
        if event == ALLOW:
            self.finish(True, via="telegram")
        elif event == DENY:
            self.finish(False, reason="отказ с телефона")
        elif event == "sent":
            self.telegram_sent = True
            self._phone(f"Запрос отправлен в {self._channels_text(sent_only=True)} — нажмите «Разрешить»", Dark.OK)
        elif event == "no_link":
            self._phone("Нет связи с Telegram, повторяю. Можно подтвердить кодом из приложения.", Dark.WARN)
        elif event == "retrying":
            self._phone("Нет связи с Telegram, повторяю отправку. Можно подтвердить кодом из приложения.", Dark.WARN)
        elif event == "unavailable":
            self._phone("Telegram недоступен — подтвердите кодом из приложения.", Dark.WARN)

    # Общее

    @staticmethod
    def _remote_worker(state, channel, unlock_remote) -> None:
        sent = False
        failures = 0
        owned = None
        try:
            while not channel.stop.is_set():
                with state.lock:
                    if state.finished or state.expired() or state.phase not in ("password", "remote"):
                        break
                    token, phase = state.generation, state.phase
                if phase == "remote":
                    channel.stop.wait(0.05)
                    continue
                pause = TELEGRAM_POLL_SECONDS
                try:
                    if not sent:
                        channel.confirm.start()
                        if channel.stop.is_set() or not state.active(token):
                            continue
                        sent = True
                        state.emit(token, "remote_status", (channel.kind, "sent"))
                    else:
                        code = channel.confirm.poll()
                        while code is not None:
                            with state.lock:
                                if (channel.stop.is_set() or state.finished or state.expired()
                                        or state.phase not in ("password", "remote")):
                                    code = None
                                    break
                                owned = state.claim("password", "remote")
                            if owned is not None:
                                break
                            channel.stop.wait(0.05)
                        if owned is not None:
                            try:
                                result = "denied" if code == DENY else unlock_remote(code)
                            finally:
                                code = None
                            if result is not None:
                                state.emit(owned, "remote", result)
                                channel.stop.wait(max(0, state.deadline - state.clock()))
                                break
                            token = state.claim("remote", "password")
                            owned = None
                            if token is None:
                                break
                    failures = 0
                except Exception as error:
                    if owned is not None:
                        with state.lock:
                            if state.active(owned):
                                state.claim("remote", "password")
                        owned = None
                        token = state.generation
                    failures += 1
                    retry = isinstance(error, NoLink)
                    if retry:
                        pause = channel_retry_pause(failures)
                    state.emit(token, "remote_status", (channel.kind, "retrying" if retry else "unavailable"))
                    if not retry:
                        break
                if channel.stop.wait(pause):
                    break
        finally:
            channel.close()
            state.channel_worker_closed()

    def _show_remote_status(self) -> None:
        names = CHANNEL_LABELS
        statuses = {"sending": "отправляю запрос", "sent": "жду код pw …",
                    "retrying": "нет связи, повторяю", "unavailable": "недоступен"}
        text = "\n".join(f"{names[kind]}: {statuses[status]}" for kind, status in self.remote_status.items())
        self.remote_label.configure(text=text)

    def _close_remote(self, status: str) -> None:
        for channel in self._channels.values():
            if channel.remote:
                channel.cancel(status)
        self._stop_remote.set()

    def _center(self) -> None:
        self.win.update_idletasks()
        x = (self.win.winfo_screenwidth() - self.win.winfo_reqwidth()) // 2
        y = (self.win.winfo_screenheight() - self.win.winfo_reqheight()) // 3
        self.win.geometry(f"+{max(x, 0)}+{max(y, 0)}")

    def _clear(self) -> None:
        for child in self.body.winfo_children():
            child.destroy()
        self.list_canvas = None

    def deny(self) -> None:
        self.finish(False, reason="отказ владельца")

    def cancel(self) -> None:
        self.finish(False, reason="отменено в окне")

    def _timeout_reason(self) -> str:
        base = "время подтверждения вышло" if self.deadline is not None else "время запроса вышло"
        notes = ", ".join(f"{CHANNEL_LABELS.get(kind, kind)}: {state}" for kind, state in self.channel_status.items())
        return f"{base} (каналы: {notes})" if notes else base

    def _expire(self) -> bool:
        with self._state.lock:
            expired = self._state.expired() or self.deadline is not None and self.clock() >= self.deadline
        if expired and not self.finished:
            self.finish(False, reason=self._timeout_reason())
        return expired

    def _destroyed(self, event) -> None:
        if event.widget is self.win and not self.finished:
            self.finish(False, reason="окно закрыто", destroy=False)

    def _tick(self) -> None:
        if self._tick_id is not None:
            try:
                self.root.after_cancel(self._tick_id)
            except tk.TclError:
                pass
            self._tick_id = None
        if self.finished or self._expire():
            return
        while True:
            try:
                token, kind, value = self._events.get_nowait()
            except queue.Empty:
                break
            if not self._state.active(token) or self._expire():
                continue
            phase = self._state.phase
            if kind == "unlocked" and phase == "local":
                self._on_unlocked(value)
            elif kind == "unlock_error" and phase == "local":
                self._state.claim("local", "password")
                self.message_label.configure(text=value, fg=Dark.ERROR)
                self._enable_inputs()
            elif kind == "telegram" and phase == "confirm":
                self._on_telegram(value)
            elif kind == "remote_status" and phase == "password":
                channel_kind, status = value
                self.remote_status[channel_kind] = status
                if self.remote_label is not None:
                    self._show_remote_status()
            elif kind == "remote" and phase == "remote":
                reasons = {"denied": "отказ с телефона", "refused": "код из бота не принят"}
                self.finish(value == "granted", via="pw" if value == "granted" else "", reason=reasons.get(value, ""))
            if self.finished:
                return
        if self.deadline is not None:
            if self._expire():
                return
            left = self.deadline - self.clock()
            self.timer_label.configure(text=f"{int(left) // 60}:{int(left) % 60:02d}")
        self._tick_id = self.root.after(TICK_MS, self._tick)

    def finish(self, granted: bool, via: str = "", reason: str = "", *, destroy=True) -> None:
        with self._state.lock:
            if self.finished:
                return
            if granted and (self._state.expired() or self.deadline is not None and self.clock() >= self.deadline):
                granted, via = False, ""
                reason = self._timeout_reason()
            self.finished = self._state.finished = True
            self._state.phase = "finished"
            self._state.generation += 1
        if self._tick_id is not None:
            try:
                self.root.after_cancel(self._tick_id)
            except tk.TclError:
                pass
            self._tick_id = None
        error = None
        try:
            # Текст каналов отправляется после вердикта посредника: он может отказать уже после окна.
            final = self.done(granted, via, reason)
            if final is not None:
                granted, via, reason = final
        except Exception as e:
            error = e
            granted, via, reason = False, "", "посредник не завершил запрос"
        finally:
            with self._state.lock:
                self._state.done_completed = True
        status = "Доступ разрешён по коду." if granted and via == "pw" else f"Доступ не выдан: {reason}."
        self._close_remote(status + "\nОтвет не нужен")
        if granted:
            status = {"telegram": "Доступ разрешён", "code": "Подтверждено кодом"}.get(via, "Доступ разрешён")
        else:
            status = f"Доступ не выдан: {reason}"
        for kind in CHANNEL_LABELS:
            channel = self._channels.get(kind)
            if channel is not None:
                channel.cancel(status)
        # Discard unstarted confirms so queued vault/verifier references do not outlive cancellation.
        while True:
            try:
                self._events.get_nowait()
            except queue.Empty:
                break
        if destroy:
            self.win.destroy()
        self._state.notify_channels_closed()
        if error is not None:
            raise error

class TkUi:
    def __init__(self, root, take_focus: bool = True, on_forgot=None):
        self.root = root
        self.take_focus = take_focus
        self.on_forgot = on_forgot
        self.window: AccessWindow | None = None

    def ask(self, request, unlock, done, remote=None, unlock_remote=None, request_deadline=None,
            on_channels_closed=None):
        self.window = AccessWindow(self.root, request, unlock, done, take_focus=self.take_focus,
                                   remote=remote, unlock_remote=unlock_remote, on_forgot=self.on_forgot,
                                   request_deadline=request_deadline, on_channels_closed=on_channels_closed)
        return self.window.cancel
