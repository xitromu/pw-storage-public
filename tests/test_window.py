"""Окно доступа: настоящие виджеты Tk, нажатия выполняются программно, фокус не перехватывается."""

import gc
import json
import tempfile
import time
import threading
from pathlib import Path
from unittest import mock
import tkinter as tk
from tkinter import ttk
import unittest
from types import SimpleNamespace

from pw_storage import catalog
from pw_storage.broker import AccessRequest
from pw_storage.config import CONFIRM_SECONDS, MAX_CODE_ATTEMPTS, MAX_PASSWORD_ATTEMPTS
from pw_storage.second_factor import ALLOW, DENY, NoLink
from pw_storage.vault import VaultError
from pw_storage.window import AccessWindow, apply_style

ITEMS = (
    catalog.Item("a0000001", "DEMO", ("DEMO",), False, "Камеры Neocam"),
    catalog.Item("a0000002", "DEMO", ("DEMO",), False, "Токен к почте"),
    catalog.Item("a0000003", "COMMON", ("COMMON",), True, "Общий ключ погоды"),
)
FRESH = catalog.Listing(catalog.FRESH, ITEMS)


def Request(rows=ITEMS, listing=FRESH, why="проверить камеры", test=False, hours=12):
    return AccessRequest("DEMO", "s1", hours, listing, tuple(rows), why, test=test)


def item(i, comment, shared=False):
    return catalog.Item(f"b{i:07d}", "COMMON" if shared else "DEMO", ("COMMON",) if shared else ("DEMO",), shared, comment)


class FakeConfirm:
    def __init__(self, result=None, fail_start=False):
        self.result = result
        self.fail_start = fail_start
        self.started = False
        self.finished = None

    def start(self):
        if self.fail_start:
            raise NoLink("нет связи")
        self.started = True

    def poll(self):
        return self.result

    def finish(self, status):
        self.finished = status


def unlocked(code_ok=True, telegram=None, with_code=True, own=("Камеры Neocam", "Токен к почте"),
             common=("Общий ключ погоды",), rebuilt=False):
    verify = (lambda code: code == "123456" and code_ok) if with_code else None
    return SimpleNamespace(own=list(own), common=list(common), verify_code=verify, telegram=telegram,
                           rebuilt=rebuilt)


class WindowCase(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        self.root.withdraw()
        apply_style(self.root)
        self.now = 1000.0
        self.results = []
        self.calls = []
        self.windows = []

    def tearDown(self):
        for window in self.windows:
            window.finish(False, reason="конец теста")
        self.root.destroy()

    @property
    def passwords(self):
        return [password for password, _, _ in self.calls]

    def make(self, answer, request=None, **options):
        def unlock(password, chosen, hours):
            self.calls.append((password, chosen, hours))
            if isinstance(answer, Exception):
                raise answer
            return answer

        def done(granted, via="", reason=""):
            self.results.append((granted, via, reason))

        window = AccessWindow(self.root, request or Request(), unlock, done, clock=lambda: self.now, take_focus=False,
                              **options)
        self.windows.append(window)
        return window

    def pump(self, until, seconds=5.0):
        deadline = time.monotonic() + seconds
        while not until():
            self.assertLess(time.monotonic(), deadline, "окно не дошло до ожидаемого состояния")
            self.root.update()
            time.sleep(0.005)

    def submit(self, window, password="test-password"):
        window.password_var.set(password)
        window.continue_button.invoke()

    def to_confirm(self, window):
        self.submit(window)
        self.pump(lambda: window.unlocked is not None)

    def test_documentation_screenshots(self):
        """Снимки для документации: запрос доступа и подтверждение выбранных строк."""
        from tests.shot import snapshot

        window = self.make(unlocked())
        window.win.update()
        snapshot(window.win, "access-request.png")
        self.to_confirm(window)
        window.win.update()
        snapshot(window.win, "access-confirm.png")

    def labels(self, window):
        return [w.cget("text") for w in window.body.winfo_children() if w.winfo_class() in ("TLabel", "Label")]

    def texts(self, window):
        """Все надписи экрана, включая вложенные рамки."""
        out, stack = [], [window.body]
        while stack:
            widget = stack.pop()
            if widget.winfo_class() in ("TLabel", "Label"):
                out.append(widget.cget("text"))
            stack.extend(widget.winfo_children())
        return out

    def boxes(self, window):
        return [text.cget("text") + (f"  · {source.cget('text')}" if source else "")
                for _, _, _, text, source in window.choices]

    # Экран 1: вариант Б

    def test_screen1_says_who_how_many_and_for_how_long(self):
        window = self.make(unlocked())
        texts = self.texts(window)
        self.assertIn("DEMO просит секреты", texts)
        self.assertIn("3 строки", texts)
        self.assertIn("Пароль хранилища", texts)
        self.assertEqual(window.hours_var.get(), "12")

    def test_why_is_shown_as_words_of_session(self):
        texts = self.texts(self.make(unlocked()))
        self.assertIn("Запрос проекта:", texts)
        self.assertIn("проверить камеры", texts)
        texts = self.texts(self.make(unlocked(), Request(why="")))
        self.assertIn("не указан", texts)

    def test_rows_are_listed_in_two_groups_with_marks(self):
        window = self.make(unlocked())
        self.assertEqual(self.boxes(window), ["Камеры Neocam  · DEMO", "Токен к почте  · DEMO", "Общий ключ погоды  · ALL"])
        texts = self.texts(window)
        self.assertFalse(any("Проект DEMO" in t for t in texts))  # проект только в заголовке окна
        self.assertIn("ЧЬЯ", texts)
        self.assertIn(AccessWindow.COMMON_HINT, texts)
        self.assertIn("a0000003", texts)
        self.assertTrue(all(var.get() for _, var, *_ in window.choices))
        self.assertEqual(window.continue_button.cget("text"), "Одобрить 3 из 3")

    def test_group_without_rows_is_not_shown(self):
        window = self.make(unlocked(), Request(rows=ITEMS[:2]))
        self.assertNotIn(AccessWindow.COMMON_HINT, self.texts(window))
        self.assertNotIn("ALL", self.texts(window))

    def test_unchecked_row_is_not_requested(self):
        window = self.make(unlocked())
        window.choices[2][2].invoke()
        self.assertEqual(window.continue_button.cget("text"), "Одобрить 2 из 3")
        self.assertIn("overstrike", str(window.choices[2][3].cget("font")))
        self.submit(window)
        self.pump(lambda: self.calls)
        self.assertEqual(self.calls[0][1:], (["a0000001", "a0000002"], 12))

    def test_nothing_checked_cannot_be_approved(self):
        window = self.make(unlocked())
        for _, _, box, *_ in window.choices:
            box.invoke()
        self.assertEqual(str(window.continue_button["state"]), "disabled")
        self.submit(window)
        self.root.update()
        self.assertEqual(self.calls, [])

    def test_hours_can_be_changed_for_this_request(self):
        window = self.make(unlocked())
        window.hours_var.set("2")
        self.submit(window)
        self.pump(lambda: self.calls)
        self.assertEqual(self.calls[0][2], 2)

    def test_wrong_hours_are_refused(self):
        window = self.make(unlocked())
        for bad in ("0", "8761", "много", ""):
            window.hours_var.set(bad)
            self.submit(window)
            self.root.update()
            self.assertIn("от 1 до 8760", window.message_label.cget("text"))
        self.assertEqual(self.calls, [])

    def test_unnamed_rows_are_warned_about(self):
        listing = catalog.Listing(catalog.FRESH, ITEMS, ((("DEMO",), False), (("OTHER",), True), (("OTHER",), False)))
        window = self.make(unlocked(), Request(listing=listing))
        self.assertTrue(any("без комментария" in t and "2 у DEMO" in t for t in self.texts(window)))
        window = self.make(unlocked())
        self.assertFalse(any("без комментария" in t for t in self.texts(window)))

    def test_click_on_text_toggles_mark(self):
        window = self.make(unlocked())
        window._toggle(window.choices[0][2])
        self.assertFalse(window.choices[0][1].get())

    def test_rows_word(self):
        from pw_storage.window import rows_word
        self.assertEqual([rows_word(n) for n in (1, 2, 5, 11, 21, 22)],
                         ["1 строка", "2 строки", "5 строк", "11 строк", "21 строка", "22 строки"])

    def test_password_is_masked(self):
        self.assertEqual(self.make(unlocked()).password_entry.cget("show"), "•")

    def test_eye_shows_password_and_hides_again(self):
        window = self.make(unlocked())
        window.password_field.toggle()
        self.assertEqual(window.password_entry.cget("show"), "")
        window.password_field.toggle()
        self.assertEqual(window.password_entry.cget("show"), "•")

    def test_buttons_of_screen1(self):
        window = self.make(unlocked())
        self.assertEqual(window.deny_button.cget("text"), "Отказать")

    def test_deny_button(self):
        self.make(unlocked()).deny_button.invoke()
        self.assertEqual(self.results, [(False, "", "отказ владельца")])

    def test_closing_window_is_a_deny(self):
        self.make(unlocked()).deny()
        self.assertFalse(self.results[0][0])

    def test_empty_password_not_submitted(self):
        window = self.make(unlocked())
        window.continue_button.invoke()
        self.root.update()
        self.assertEqual(self.calls, [])
        self.assertEqual(window.message_label.cget("text"), "Введите пароль")

    def test_entry_is_cleared_after_submit(self):
        window = self.make(None)
        self.submit(window)
        self.assertEqual(window.password_var.get(), "")

    def test_inputs_are_locked_while_checking(self):
        window = self.make(None)
        self.submit(window)
        self.assertEqual(str(window.choices[0][2].cget("state")), "disabled")
        self.pump(lambda: "Неверный" in window.message_label.cget("text"))
        self.assertEqual(str(window.choices[0][2].cget("state")), "normal")

    def test_wrong_password_keeps_window_and_counts(self):
        window = self.make(None)
        self.submit(window)
        self.pump(lambda: "Неверный" in window.message_label.cget("text"))
        self.assertEqual(str(window.continue_button["state"]), "normal")
        self.assertEqual(window.continue_button.cget("text"), "Одобрить 3 из 3")
        self.assertEqual(self.results, [])

    def test_too_many_wrong_passwords(self):
        window = self.make(None)
        for attempt in range(MAX_PASSWORD_ATTEMPTS):
            self.submit(window)
            self.pump(lambda n=attempt + 1: len(self.results) > 0 or window.password_attempts == n)
        self.assertEqual(len(self.results), 1)
        self.assertFalse(self.results[0][0])

    def test_vault_error_is_shown(self):
        window = self.make(VaultError("Поддерживается только KDBX 4.0"))
        self.submit(window)
        self.pump(lambda: "KDBX" in window.message_label.cget("text"))
        self.assertEqual(self.results, [])

    def test_unexpected_error_shows_only_its_kind(self):
        window = self.make(RuntimeError("текст с подробностями"))
        self.submit(window)
        self.pump(lambda: "RuntimeError" in window.message_label.cget("text"))
        self.assertNotIn("подробностями", window.message_label.cget("text"))

    def test_rows_gone_from_vault_are_denied(self):
        window = self.make(unlocked(own=(), common=()))
        self.submit(window)
        self.pump(lambda: self.results)
        self.assertEqual(self.results, [(False, "", "запрошенных строк нет в хранилище")])

    # Перечня нет: только сборка заново

    def test_missing_catalog_screen_rebuilds_without_grant(self):
        window = self.make(unlocked(rebuilt=True), Request(rows=(), listing=catalog.Listing(catalog.MISSING)))
        self.assertIn("Перечень строк недоступен", self.texts(window))
        self.assertEqual(window.continue_button.cget("text"), "Собрать перечень")
        self.assertIsNone(window.list_canvas)
        self.submit(window)
        self.pump(lambda: self.results)
        self.assertEqual(self.calls[0][1], None)
        self.assertFalse(self.results[0][0])
        self.assertIn("перечень собран заново", self.results[0][2])

    def test_stale_listing_notice_and_list_after_password(self):
        stale = catalog.Listing(catalog.STALE, (catalog.Item("a0000001", "DEMO", ("DEMO",), False, "Старый комментарий"),))
        window = self.make(unlocked(own=("Новый комментарий",), common=()), Request(rows=stale.items, listing=stale))
        self.assertEqual(self.boxes(window), ["Старый комментарий  · DEMO"])
        self.assertTrue(any("менялся вне программы" in t for t in self.texts(window)))
        self.to_confirm(window)
        self.root.update()
        self.assertIn("•  Новый комментарий", self.texts(window))

    def assert_last_line_fully_visible(self, window):
        window.win.update()
        last = window.choices[-1][3]
        bottom = last.winfo_rooty() + last.winfo_height()
        canvas = window.list_canvas
        self.assertLessEqual(bottom, canvas.winfo_rooty() + canvas.winfo_height(), "последняя строка перечня обрезана")

    def test_short_list_is_not_clipped(self):
        self.assert_last_line_fully_visible(self.make(unlocked()))

    def test_one_row_in_each_group_is_not_clipped(self):
        self.assert_last_line_fully_visible(self.make(unlocked(), Request(rows=(item(1, "Один"), item(2, "Другой", True)))))

    def test_one_row_is_not_clipped(self):
        self.assert_last_line_fully_visible(self.make(unlocked(), Request(rows=(item(1, "Один"),))))

    def test_long_comments_are_not_clipped(self):
        long_comment = "Очень длинный комментарий, который не помещается в одну строку перечня и переносится на следующую"
        rows = (item(1, long_comment), item(2, long_comment), item(3, long_comment, True))
        self.assert_last_line_fully_visible(self.make(unlocked(), Request(rows=rows)))

    def test_long_list_scrolls(self):
        rows = tuple(item(i, f"Комментарий {i}") for i in range(40))
        window = self.make(unlocked(), Request(rows=rows))
        self.assertLessEqual(int(window.list_canvas.cget("height")), window.px(260))
        self.assertEqual(len(window.choices), 40)
        bars = [w for w in window.list_canvas.master.winfo_children() if w.winfo_class() == "TScrollbar"]
        self.assertEqual(len(bars), 1)

    def test_test_mode_warns_about_real_password(self):
        window = self.make(unlocked(), Request(test=True))
        self.assertTrue(any("настоящий пароль" in t for t in self.texts(window)))
        self.assertIn("ТЕСТ", window.win.title())

    # Экран 2

    def test_screen2_content(self):
        window = self.make(unlocked())
        self.to_confirm(window)
        labels = self.texts(window)
        self.assertIn("✓ Пароль принят", labels)
        self.assertIn("3 строки", labels)
        self.assertIn("на 12 ч", labels)
        self.assertIn("Подтвердите на телефоне", labels)
        self.assertEqual(window.code_button.cget("text"), "Подтвердить кодом")
        self.assertEqual(window.cancel_button.cget("text"), "Отменить")

    def test_screen2_shows_time_left(self):
        window = self.make(unlocked())
        self.to_confirm(window)
        self.pump(lambda: window.timer_label.cget("text") != "")
        self.assertEqual(window.timer_label.cget("text"), f"{CONFIRM_SECONDS // 60}:00")

    def test_correct_code_grants(self):
        window = self.make(unlocked())
        self.to_confirm(window)
        window.code_var.set("123456")
        window.code_button.invoke()
        self.assertEqual(self.results, [(True, "code", "")])

    def test_code_cells_spread_paste_and_clear(self):
        window = self.make(unlocked())
        self.to_confirm(window)
        cells = window.code_entry
        cells.vars[0].set("12 34 56")
        self.assertEqual(cells.get(), "123456")
        cells.set("")
        self.assertEqual(cells.get(), "")
        cells.vars[0].set("x")
        self.assertEqual(cells.get(), "")

    def test_wrong_code_then_limit(self):
        window = self.make(unlocked())
        self.to_confirm(window)
        for _ in range(MAX_CODE_ATTEMPTS - 1):
            window.code_var.set("000000")
            window.code_button.invoke()
            self.assertEqual(window.code_var.get(), "")
        self.assertEqual(self.results, [])
        window.code_var.set("000000")
        window.code_button.invoke()
        self.assertFalse(self.results[0][0])

    def test_cancel_on_screen2(self):
        window = self.make(unlocked())
        self.to_confirm(window)
        window.cancel_button.invoke()
        self.assertEqual(self.results, [(False, "", "отменено в окне")])

    def test_timeout_denies(self):
        window = self.make(unlocked())
        self.to_confirm(window)
        self.now += CONFIRM_SECONDS + 1
        self.pump(lambda: self.results)
        self.assertEqual(self.results, [(False, "", "время подтверждения вышло")])

    def test_no_second_factor_is_refused(self):
        window = self.make(unlocked(with_code=False))
        self.submit(window)
        self.pump(lambda: self.results)
        self.assertFalse(self.results[0][0])
        self.assertIn("нет способа подтверждения", self.results[0][2])

    def test_telegram_allow(self):
        confirm = FakeConfirm(ALLOW)
        self.to_confirm(self.make(unlocked(telegram=confirm)))
        self.pump(lambda: self.results)
        self.assertEqual(self.results, [(True, "telegram", "")])
        self.assertTrue(confirm.started)
        self.pump(lambda: confirm.finished is not None)
        self.assertEqual(confirm.finished, "Доступ разрешён")

    def test_telegram_deny(self):
        confirm = FakeConfirm(DENY)
        self.to_confirm(self.make(unlocked(telegram=confirm)))
        self.pump(lambda: self.results)
        self.assertEqual(self.results, [(False, "", "отказ с телефона")])

    def test_telegram_sent_status(self):
        window = self.make(unlocked(telegram=FakeConfirm()))
        self.to_confirm(window)
        self.pump(lambda: window.telegram_sent)
        self.assertIn("Telegram", window.phone_label.cget("text"))
        window.cancel_button.invoke()

    def test_telegram_no_link_leaves_code_path(self):
        window = self.make(unlocked(telegram=FakeConfirm(fail_start=True)))
        self.to_confirm(window)
        self.pump(lambda: "Нет связи" in window.phone_label.cget("text"))
        window.code_var.set("123456")
        window.code_button.invoke()
        self.assertEqual(self.results, [(True, "code", "")])

    def test_timeout_reason_tells_what_happened_on_the_channel(self):
        """Журнал должен отвечать на «почему не пришло»: отправлено или канал не дозвонился."""
        for confirm, note in ((FakeConfirm(fail_start=True), "не отправлено"), (FakeConfirm(), "отправлено")):
            self.results.clear()
            window = self.make(unlocked(telegram=confirm))
            self.to_confirm(window)
            self.pump(lambda: window.telegram_sent or "Нет связи" in window.phone_label.cget("text"))
            self.now = window.deadline + 1
            window._expire()
            self.assertEqual(self.results,
                             [(False, "", f"время подтверждения вышло (каналы: Telegram: {note})")])

    def test_code_marks_telegram_message(self):
        confirm = FakeConfirm()
        window = self.make(unlocked(telegram=confirm))
        self.to_confirm(window)
        self.pump(lambda: window.telegram_sent)
        window.code_var.set("123456")
        window.code_button.invoke()
        self.pump(lambda: confirm.finished is not None)
        self.assertEqual(confirm.finished, "Подтверждено кодом")

    def test_broker_denial_after_approval_replaces_final_channel_text(self):
        confirm = FakeConfirm()
        window = self.make(unlocked(telegram=confirm))
        self.to_confirm(window)
        self.pump(lambda: window.telegram_sent)
        window.done = lambda granted, via="", reason="": (False, "", "журнал доступа недоступен")
        window.finish(True, via="telegram")
        self.pump(lambda: confirm.finished is not None)
        self.assertEqual(confirm.finished, "Доступ не выдан: журнал доступа недоступен")

    def test_telegram_only_without_code(self):
        window = self.make(unlocked(telegram=FakeConfirm(), with_code=False))
        self.to_confirm(window)
        self.assertIsNone(window.code_button)
        window.cancel_button.invoke()

    def test_forgot_link_only_when_recovery_is_available(self):
        self.assertIsNone(self.make(unlocked()).forgot_link)
        opened = []

        def on_forgot(root, on_close):
            opened.append(on_close)
            return object()

        window = AccessWindow(self.root, Request(), lambda *a: None, lambda *a, **k: self.results.append(a),
                              clock=lambda: self.now, take_focus=False, on_forgot=on_forgot)
        self.windows.append(window)
        self.assertEqual(window.forgot_link.cget("text"), "Забыли пароль?")
        window.forgot()
        window.forgot()  # второе окно восстановления не открывается
        self.assertEqual(len(opened), 1)
        opened[0](True)
        self.assertIn("введите новый пароль", window.message_label.cget("text"))
        self.assertEqual(self.results, [])

    def test_finish_is_final(self):
        window = self.make(unlocked())
        window.deny()
        window.finish(True, via="code")
        self.assertEqual(len(self.results), 1)

    def test_code_at_deadline_and_slow_verifier_are_denied(self):
        for slow in (False, True):
            answer = unlocked()
            window = self.make(answer)
            self.to_confirm(window)
            if slow:
                def verify(code):
                    self.now = window.deadline
                    return True
                answer.verify_code = verify
            else:
                self.now = window.deadline
            window.code_var.set("123456")
            window.submit_code()
            self.assertFalse(self.results[-1][0])

    def test_queued_phone_approval_expires_before_dispatch(self):
        window = self.make(unlocked())
        self.to_confirm(window)
        window._events.put((window._state.generation, "telegram", ALLOW))
        self.now = window.deadline
        window._tick()
        self.assertFalse(self.results[-1][0])
        self.assertIsNone(window._tick_id)

    def test_stale_phase_events_cannot_grant_or_replace_local_unlock(self):
        window = self.make(unlocked())
        old = window._state.generation
        self.to_confirm(window)
        for kind, value in (("remote", "granted"), ("unlocked", unlocked()), ("telegram", ALLOW)):
            window._events.put((old, kind, value))
        window._tick()
        self.assertEqual(self.results, [])
        self.assertEqual(window._state.phase, "confirm")

    def test_password_phase_has_finite_request_deadline(self):
        window = self.make(unlocked())
        self.now = window._state.deadline
        self.submit(window)
        self.assertEqual(self.calls, [])
        self.assertFalse(self.results[-1][0])

    def test_external_destroy_cleans_after_callbacks(self):
        window = self.make(unlocked())
        timer = window._tick_id
        window.win.destroy()
        self.assertTrue(window.finished)
        self.assertIsNone(window._tick_id)
        self.assertNotIn(timer, self.root.tk.call("after", "info"))
        self.root.update()
        self.assertEqual(len(self.results), 1)

    def test_cancel_while_local_unlock_blocked_discards_late_result(self):
        entered, release, completed = threading.Event(), threading.Event(), threading.Event()
        window = self.make(unlocked())
        def unlock(password, chosen, hours):
            entered.set()
            self.assertTrue(release.wait(5))
            completed.set()
            return unlocked()
        window.unlock = unlock
        self.submit(window)
        self.assertTrue(entered.wait(5))
        window.cancel()
        release.set()
        self.assertTrue(completed.wait(5))
        window._tick()
        self.assertEqual(len(self.results), 1)
        self.assertFalse(self.results[0][0])

    def test_inputs_are_snapshotted_on_gui_thread(self):
        window = self.make(unlocked())
        window.hours_var.set("2")
        self.submit(window)
        window.hours_var.set("3")
        self.pump(lambda: window.unlocked is not None)
        self.assertEqual(window.granted_hours, 2)
        self.assertEqual(self.calls[0][2], 2)

    def test_delayed_remote_launch_is_counted_before_cancel(self):
        closed, pending = mock.Mock(), []
        listener, unlock_remote = mock.Mock(), mock.Mock()
        with mock.patch("pw_storage.window.threading.Thread") as thread:
            thread.side_effect = lambda **kwargs: pending.append(kwargs) or mock.Mock()
            window = self.make(unlocked(), remote={"telegram": listener}, unlock_remote=unlock_remote,
                               on_channels_closed=closed)
        self.assertEqual(window._state.channel_workers, 1)
        self.assertFalse(pending[0]["daemon"])
        self.assertIs(pending[0]["target"], AccessWindow._remote_worker)
        self.assertEqual(pending[0]["args"][:2], (window._state, window._channels["remote_telegram"]))
        window.cancel()
        self.assertEqual(len(self.results), 1)
        closed.assert_not_called()
        pending[0]["target"](*pending[0]["args"])
        listener.start.assert_not_called()
        listener.poll.assert_not_called()
        unlock_remote.assert_not_called()
        listener.say.assert_called_once()
        closed.assert_called_once_with()
        self.assertEqual(window._state.channel_workers, 0)

    def test_delayed_confirm_launch_waits_for_the_cleanup(self):
        telegram, closed = mock.Mock(), mock.Mock()
        window = self.make(unlocked(telegram=telegram), on_channels_closed=closed)
        window._submitted_hours = 12
        self.assertIsNotNone(window._state.claim("password", "local"))
        pending = []
        with mock.patch("pw_storage.window.threading.Thread") as thread:
            thread.side_effect = lambda **kwargs: pending.append(kwargs) or mock.Mock()
            window._on_unlocked(unlocked(telegram=telegram))
        self.assertEqual(window._state.channel_workers, 1)
        window.cancel()
        closed.assert_not_called()
        self.assertEqual(len(pending), 1)
        for launch in pending:
            self.assertFalse(launch["daemon"])
            self.assertIs(launch["target"], AccessWindow._confirm_worker)
            self.assertEqual(launch["args"], (window._state, window._state.generation - 1,
                                            "telegram", window._channels["telegram"]))
            launch["target"](*launch["args"])
        telegram.start.assert_not_called()
        telegram.poll.assert_not_called()
        telegram.finish.assert_called_once()
        closed.assert_called_once_with()
        self.assertEqual(window._state.channel_workers, 0)

    def test_constructor_destroy_before_remote_launch_never_starts_worker(self):
        listener, closed = mock.Mock(), mock.Mock()
        with mock.patch.object(AccessWindow, "_center", lambda window: window.win.destroy()):
            window = self.make(unlocked(), remote={"telegram": listener}, on_channels_closed=closed)
        self.assertTrue(window.finished)
        self.assertEqual(window._state.channel_workers, 0)
        listener.start.assert_not_called()
        closed.assert_called_once_with()
        self.assertEqual(len(self.results), 1)


class ChannelDrainTest(unittest.TestCase):
    def window(self):
        from pw_storage.window import _RequestState
        order = []
        state = _RequestState(lambda: 0, 30, lambda: order.append("closed"))
        window = object.__new__(AccessWindow)
        window._state, window._events = state, state.events
        window.clock, window.deadline = state.clock, None
        window.root, window.win = mock.Mock(), mock.Mock()
        window._tick_id, window.finished = None, False
        window._channels, window._stop_remote = {}, threading.Event()
        window.channel_status = {}
        window.done = lambda *args: order.append("done")
        return window, order

    def test_close_waits_for_blocked_poll_and_cleanup_without_delaying_done(self):
        from pw_storage.window import _Channel
        for kind in ("remote", "telegram"):
            with self.subTest(kind=kind):
                window, order = self.window()
                state = window._state
                if kind != "remote":
                    state.claim("password", "local")
                    token = state.claim("local", "confirm")
                    state.confirm_deadline = 20
                poll_entered, poll_release = threading.Event(), threading.Event()
                cleanup_entered, cleanup_release = threading.Event(), threading.Event()
                calls = []
                def poll():
                    poll_entered.set()
                    if not poll_release.wait(5):
                        raise AssertionError("poll barrier timeout")
                    calls.append("poll returned")
                    return ALLOW
                def cleanup(status):
                    cleanup_entered.set()
                    if not cleanup_release.wait(5):
                        raise AssertionError("cleanup barrier timeout")
                    calls.append("cleanup completed")
                confirm, unlock_remote = mock.Mock(), mock.Mock()
                confirm.poll.side_effect = poll
                getattr(confirm, "say" if kind == "remote" else "finish").side_effect = cleanup
                channel = window._channels[kind] = _Channel(confirm, remote=kind == "remote")
                self.assertTrue(state.add_channel_worker())
                target = AccessWindow._remote_worker if kind == "remote" else AccessWindow._confirm_worker
                args = (state, channel, unlock_remote) if kind == "remote" else (state, token, kind, channel)
                worker = threading.Thread(target=target, args=args, daemon=True)
                with mock.patch("pw_storage.window.TELEGRAM_POLL_SECONDS", 0):
                    worker.start()
                    try:
                        self.assertTrue(poll_entered.wait(5))
                        window.cancel()
                        self.assertEqual(order, ["done"])
                        self.assertFalse(cleanup_entered.is_set())
                        self.assertEqual(state.channel_workers, 1)
                        poll_release.set()
                        self.assertTrue(cleanup_entered.wait(5))
                        self.assertEqual(order, ["done"])
                        self.assertEqual(state.channel_workers, 1)
                        cleanup_release.set()
                        worker.join(5)
                        self.assertFalse(worker.is_alive())
                        self.assertEqual(calls, ["poll returned", "cleanup completed"])
                        self.assertEqual(order, ["done", "closed"])
                        self.assertEqual(state.channel_workers, 0)
                        unlock_remote.assert_not_called()
                        window.finish(True, via="telegram")
                        state.notify_channels_closed()
                        self.assertEqual(order, ["done", "closed"])
                    finally:
                        poll_release.set()
                        cleanup_release.set()
                        worker.join(5)

    def test_no_channels_notifies_once_after_done_for_cancel_destroy_and_expiry(self):
        for close in ("cancel", "destroy", "expiry"):
            with self.subTest(close=close):
                window, order = self.window()
                if close == "cancel":
                    window.cancel()
                elif close == "destroy":
                    window._destroyed(SimpleNamespace(widget=window.win))
                    window.win.destroy.assert_not_called()
                else:
                    window._state.clock = window.clock = lambda: 30
                    self.assertTrue(window._expire())
                self.assertEqual(order, ["done", "closed"])
                self.assertFalse(window._state.add_channel_worker())
                window.cancel()
                window._state.notify_channels_closed()
                self.assertEqual(order, ["done", "closed"])

    def test_worker_drained_before_finish_notifies_only_after_done_outside_lock(self):
        from pw_storage.window import _Channel
        window, order = self.window()
        state = window._state
        self.assertTrue(state.add_channel_worker())
        channel = _Channel(mock.Mock(), remote=True)
        channel.cancel("cancelled")
        AccessWindow._remote_worker(state, channel, mock.Mock())
        self.assertEqual(state.channel_workers, 0)
        self.assertEqual(order, [])
        acquired = []
        def callback():
            def probe():
                locked = state.lock.acquire(blocking=False)
                acquired.append(locked)
                if locked:
                    state.lock.release()
            probe_thread = threading.Thread(target=probe)
            probe_thread.start()
            probe_thread.join(5)
            order.append("closed")
        state.on_channels_closed = callback
        window.cancel()
        self.assertEqual(order, ["done", "closed"])
        self.assertEqual(acquired, [True])
        self.assertIsNone(state.on_channels_closed)

    def test_last_worker_closing_during_done_cannot_notify_early(self):
        from pw_storage.window import _Channel
        window, order = self.window()
        state = window._state
        self.assertTrue(state.add_channel_worker())
        channel = window._channels["remote"] = _Channel(mock.Mock(), remote=True)
        def done(*args):
            worker = threading.Thread(target=AccessWindow._remote_worker, args=(state, channel, mock.Mock()))
            worker.start()
            worker.join(5)
            self.assertFalse(worker.is_alive())
            self.assertEqual(state.channel_workers, 0)
            self.assertEqual(order, [])
            order.append("done")
        window.done = done
        window.cancel()
        self.assertEqual(order, ["done", "closed"])

    def test_done_exception_still_notifies_once(self):
        window, order = self.window()
        window.done = mock.Mock(side_effect=RuntimeError("done failed"))
        with self.assertRaisesRegex(RuntimeError, "done failed"):
            window.cancel()
        self.assertEqual(order, ["closed"])
        window.cancel()
        window.done.assert_called_once()
        self.assertEqual(order, ["closed"])

    def test_tkui_passes_optional_callback_and_keeps_old_call_valid(self):
        from pw_storage.window import TkUi
        ui = TkUi(mock.Mock(), take_focus=False)
        request, unlock, done, closed = object(), mock.Mock(), mock.Mock(), mock.Mock()
        with mock.patch("pw_storage.window.AccessWindow") as window_class:
            cancel = ui.ask(request, unlock, done)
            self.assertIs(cancel, ui.window.cancel)
            self.assertIsNone(window_class.call_args.kwargs["on_channels_closed"])
            cancel = ui.ask(request, unlock, done, on_channels_closed=closed)
            self.assertIs(cancel, ui.window.cancel)
            self.assertIs(window_class.call_args.kwargs["on_channels_closed"], closed)
            self.assertIs(ui.window, window_class.return_value)


class BrokerTkUiIntegrationTest(unittest.TestCase):
    def setUp(self):
        from pw_storage.broker import Broker
        from pw_storage.config import Profile
        from pw_storage.remote import QueueLock
        from pw_storage.window import TkUi

        self.root = self.ui = self.window = self.broker = self.temp = None
        self.threads, self.barriers, self.worker_errors = [], [], []
        self.addCleanup(self._cleanup)
        self.now = 1000.0
        self.temp = tempfile.TemporaryDirectory(prefix="pw-window-broker-")
        base = Path(self.temp.name)
        profile = Profile("test", base, base, base, "unused", "unused")
        profile.settings.write_text(json.dumps({"grant_hours": 12, "telegram": False}), encoding="utf-8")
        self.root = tk.Tk()
        self.root.withdraw()
        apply_style(self.root)
        self.ui = TkUi(self.root, take_focus=False)
        self.queue = QueueLock(base / "queue.json", clock=lambda: self.now)
        self.broker = Broker(profile, object(), self.ui, bot_api=object(), clock=lambda: self.now,
                             queue_lock=self.queue,
                             remote_key_factory=mock.Mock(side_effect=AssertionError("TPM must not be used")))
        self._thread_class = threading.Thread
        self.listing = self._patch(self.broker, "_current_listing", return_value=FRESH)
        self.make_remote = self._patch(self.broker, "_make_remote", return_value=None)
        self.unlock = self._patch(self.broker, "_unlock", side_effect=AssertionError("Vault must not be opened"))
        self.unlock_remote = self._patch(self.broker, "_unlock_by_code",
                                         side_effect=AssertionError("late remote code must be ignored"))
        self.release_queue = self._patch(self.queue, "release", wraps=self.queue.release)

    def _patch(self, obj, name, **kwargs):
        patcher = mock.patch.object(obj, name, **kwargs)
        patched = patcher.start()
        self.addCleanup(patcher.stop)
        return patched

    def _cleanup(self):
        try:
            try:
                if self.broker is not None:
                    self.broker.stop()
            finally:
                for barrier in self.barriers:
                    barrier.set()
                for thread in self.threads:
                    if thread.ident is not None:
                        thread.join(5)
                self.assertFalse(any(thread.is_alive() for thread in self.threads), "channel worker leaked")
        finally:
            try:
                if self.root is not None:
                    self.root.destroy()
            finally:
                if self.ui is not None:
                    self.ui.window = self.ui.root = None
                if hasattr(self, "pending"):
                    self.pending.cancel_ui = None
                self.window = self.ui = self.broker = self.root = None
                self.threads.clear()
                try:
                    if self.temp is not None:
                        self.temp.cleanup()
                finally:
                    self.temp = None
                    gc.collect()  # Tk variables and widget cycles must die on the main thread.

    def _capture_thread(self, **kwargs):
        thread = self._thread_class(**kwargs)
        self.threads.append(thread)
        return thread

    def _present(self):
        from pw_storage.broker import _Pending
        request = Request(test=True)
        self.pending = _Pending(request.project, request.session, tuple(row.uid for row in request.rows),
                                request.why, deadline=self.now + 1080)
        self.broker._pending.put(self.pending)
        with mock.patch("pw_storage.window.threading.Thread", side_effect=self._capture_thread):
            self.broker.pump()
        self.window = self.ui.window
        self.assertIsInstance(self.window, AccessWindow)
        self.assertIsInstance(self.window.password_entry, ttk.Entry)
        self.assertEqual(self.window.request.rows, ITEMS)
        self.assertIs(self.window.request.listing, FRESH)

    def _start_blocked_remote(self):
        self.poll_entered, self.poll_release = threading.Event(), threading.Event()
        self.cleanup_entered, self.cleanup_release = threading.Event(), threading.Event()
        self.barriers.extend((self.poll_release, self.cleanup_release))
        self.remote = FakeConfirm(result="12345678")

        def poll():
            self.poll_entered.set()
            if not self.poll_release.wait(10):
                self.worker_errors.append("poll barrier timeout")
            return self.remote.result

        def cleanup(status):
            self.cleanup_entered.set()
            if not self.cleanup_release.wait(10):
                self.worker_errors.append("cleanup barrier timeout")
            self.remote.finish(status)

        self.remote.poll = mock.Mock(side_effect=poll)
        self.remote.say = mock.Mock(side_effect=cleanup)
        self.make_remote.return_value = {"telegram": self.remote}
        with mock.patch("pw_storage.window.TELEGRAM_POLL_SECONDS", 0):
            self._present()
            self.assertTrue(self.poll_entered.wait(5), "remote worker did not reach poll")
        self.assertTrue(self.remote.started)
        self.assertEqual(len(self.threads), 1)
        self.assertFalse(self.threads[0].daemon)
        self.assertIs(self.broker._active, self.pending)
        self.assertIs(self.pending.cancel_ui.__self__, self.window)
        self.token = self.pending.queue_token
        self.lease = json.loads(self.queue.path.read_text(encoding="utf-8"))
        self.timer = self.window._tick_id
        self._assert_lease_retained()

    def _assert_denied(self):
        self.assertTrue(self.window.finished)
        self.assertFalse(self.window.win.winfo_exists())
        self.assertIsNone(self.window._tick_id)
        self.assertTrue(self.pending.finished)
        self.assertTrue(self.pending.event.is_set())
        self.assertEqual(self.pending.result["error"], "denied")
        self.assertFalse(self.pending.result["ok"])
        self.assertEqual(self.broker.grants, {})
        self.assertIsNone(self.broker._active)
        self.assertIsNone(self.pending.cancel_ui)
        self.unlock.assert_not_called()
        self.unlock_remote.assert_not_called()

    def _assert_lease_retained(self):
        self.assertIs(self.broker._queue_owner, self.pending)
        self.assertEqual(self.pending.queue_token, self.token)
        self.assertTrue(self.pending.defer_release)
        self.assertEqual(json.loads(self.queue.path.read_text(encoding="utf-8")), self.lease)
        self.release_queue.assert_not_called()
        self.assertEqual(self.window._state.channel_workers, 1)
        self.assertTrue(self.threads[0].is_alive())

    def _drain_remote(self):
        self._assert_denied()
        self.assertNotIn(self.timer, self.root.tk.call("after", "info"))
        self.assertFalse(self.cleanup_entered.is_set())
        self._assert_lease_retained()
        self.poll_release.set()
        self.assertTrue(self.cleanup_entered.wait(5), "remote worker did not reach cleanup")
        self._assert_lease_retained()
        self.unlock_remote.assert_not_called()
        self.cleanup_release.set()
        for thread in self.threads:
            thread.join(5)
            self.assertFalse(thread.is_alive())
        self.assertEqual(self.worker_errors, [])
        self.remote.poll.assert_called_once_with()
        self.remote.say.assert_called_once()
        self.assertIn("Доступ не выдан", self.remote.finished)
        self.release_queue.assert_called_once_with(self.token)
        self.assertFalse(self.queue.path.exists())
        self.assertIsNone(self.pending.queue_token)
        self.assertIsNone(self.broker._queue_owner)
        self.assertFalse(self.pending.defer_release)
        self.assertEqual(self.window._state.channel_workers, 0)
        self.root.update()
        self._assert_denied()

    def test_renewal_failure_cancels_ui_but_retains_lease_until_remote_cleanup(self):
        self._start_blocked_remote()
        self.now += 21
        with mock.patch.object(self.queue, "refresh", side_effect=RuntimeError("renewal failed")) as refresh:
            started = time.monotonic()
            self.broker.pump()
            self.assertLess(time.monotonic() - started, 2, "GUI cancellation waited for remote I/O")
            refresh.assert_called_once_with(self.token)
        self._drain_remote()

    def test_stop_cancels_ui_but_retains_lease_until_remote_cleanup(self):
        self._start_blocked_remote()
        started = time.monotonic()
        self.broker.stop()
        self.assertLess(time.monotonic() - started, 2, "shutdown waited for remote I/O")
        self.assertTrue(self.broker.stop_requested)
        self.assertTrue(self.pending.cancelled)
        self._drain_remote()

    def test_stop_without_channels_cancels_and_releases_immediately(self):
        self._present()
        token = self.pending.queue_token
        self.assertIs(self.broker._queue_owner, self.pending)
        self.assertTrue(self.queue.path.exists())
        self.assertIsNotNone(self.pending.cancel_ui)
        self.broker.stop()
        self._assert_denied()
        self.release_queue.assert_called_once_with(token)
        self.assertFalse(self.queue.path.exists())
        self.assertIsNone(self.broker._queue_owner)
        self.assertIsNone(self.pending.queue_token)
        self.assertFalse(self.pending.defer_release)
        self.assertEqual(self.window._state.channel_workers, 0)
        self.assertEqual(self.threads, [])

    def test_constructor_finished_request_does_not_retain_cancel_handle(self):
        with mock.patch.object(AccessWindow, "_center", lambda window: window.win.destroy()):
            self._present()
        self._assert_denied()
        self.release_queue.assert_called_once()
        self.assertFalse(self.queue.path.exists())
        self.assertIsNone(self.broker._queue_owner)
        self.assertIsNone(self.pending.queue_token)
        self.assertFalse(self.pending.defer_release)
        self.assertEqual(self.threads, [])

    def test_close_keeps_denial_when_late_window_result_claims_success(self):
        self._start_blocked_remote()
        self.broker._waiting[id(self.pending)] = self.pending
        self.assertTrue(self.broker._close(self.pending.project, "another-session")["closed"])
        self.window.finish(True, via="pw")
        self.poll_release.set()
        self.assertTrue(self.cleanup_entered.wait(5))
        self.cleanup_release.set()
        for thread in self.threads:
            thread.join(5)
            self.assertFalse(thread.is_alive())
        self.assertEqual(self.worker_errors, [])
        self.assertIn("Доступ не выдан: доступ закрыт клиентом (close)", self.remote.finished)
        self.assertNotIn("Доступ разрешён", self.remote.finished)
        self.assertEqual(self.pending.verdict, (False, "", "доступ закрыт клиентом (close)"))
        self.assertEqual(self.broker.grants, {})
        self.release_queue.assert_called_once_with(self.token)

    def test_audit_failure_sends_denial_as_final_remote_text(self):
        self._start_blocked_remote()
        self.unlock_remote.side_effect = None
        self.unlock_remote.return_value = "granted"
        self.pending.vault = object()
        self.pending.chosen = [SimpleNamespace(group="DEMO", service="s", key="k")]
        real_write = self.broker.audit.write

        def write(event, **kwargs):
            if event == "access_granted":
                raise OSError("synthetic audit")
            return real_write(event, **kwargs)

        self.poll_release.set()
        with mock.patch.object(self.broker.audit, "write", side_effect=write):
            deadline = time.monotonic() + 5
            while not self.window.finished:
                self.assertLess(time.monotonic(), deadline, "окно не завершило запрос")
                self.root.update()
                time.sleep(0.005)
        self.assertTrue(self.cleanup_entered.wait(5), "remote worker did not reach cleanup")
        self.cleanup_release.set()
        for thread in self.threads:
            thread.join(5)
            self.assertFalse(thread.is_alive())
        self.assertEqual(self.worker_errors, [])
        self.assertIn("Доступ не выдан: журнал доступа недоступен", self.remote.finished)
        self.assertEqual(self.pending.result["error"], "denied")
        self.assertEqual(self.broker.grants, {})
        self.release_queue.assert_called_once_with(self.token)
        self.assertFalse(self.queue.path.exists())


class WorkerRaceTest(unittest.TestCase):
    def state(self):
        from pw_storage.window import _RequestState
        state = _RequestState(lambda: 0, 30)
        token = state.claim("password", "local")
        token = state.claim("local", "confirm")
        state.confirm_deadline = 20
        self.assertTrue(state.add_channel_worker())
        return state, token

    def test_cancel_blocked_max_start_never_retries_and_finishes_after_start(self):
        from pw_storage.window import _Channel
        state, token = self.state()
        entered, release, closed = threading.Event(), threading.Event(), threading.Event()
        calls = []
        class Confirm:
            def start(self):
                calls.append("start")
                entered.set()
                if not release.wait(5):
                    raise AssertionError("barrier timeout")
                calls.append("start_return")
                raise NoLink("transient")
            def finish(self, status):
                calls.append("finish")
                closed.set()
        channel = _Channel(Confirm())
        worker = threading.Thread(target=AccessWindow._confirm_worker, args=(state, token, "telegram", channel))
        worker.start()
        self.assertTrue(entered.wait(5))
        channel.cancel("cancelled")
        self.assertFalse(closed.is_set())
        release.set()
        worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(calls, ["start", "start_return", "finish"])

    def test_terminal_error_is_not_retried_but_nolink_retries_until_expiry(self):
        from pw_storage.window import _Channel, _RequestState
        for error, check in ((RuntimeError("terminal"), lambda n: self.assertEqual(n, 1)),
                             (NoLink("transient"), lambda n: self.assertGreaterEqual(n, 4))):
            now = [0]

            def clock():  # время идёт с каждым взглядом на него: поток конечен даже без пауз
                now[0] += 1
                return now[0]

            state = _RequestState(clock, 20)
            state.claim("password", "local")
            token = state.claim("local", "confirm")
            state.confirm_deadline = 18
            self.assertTrue(state.add_channel_worker())
            confirm = mock.Mock()
            confirm.start.side_effect = error
            channel = _Channel(confirm)
            with mock.patch("pw_storage.window.TELEGRAM_POLL_SECONDS", 0), \
                    mock.patch("pw_storage.window.channel_retry_pause", lambda failures: 0):
                AccessWindow._confirm_worker(state, token, "telegram", channel)
            check(confirm.start.call_count)
            confirm.finish.assert_called_once()

    def test_channel_retry_pause_grows_and_caps(self):
        from pw_storage.window import channel_retry_pause
        self.assertEqual([channel_retry_pause(failures) for failures in (1, 2, 3, 5, 20)], [2, 4, 8, 30, 30])

    def test_cancelled_worker_never_starts(self):
        from pw_storage.window import _Channel
        state, token = self.state()
        confirm = mock.Mock()
        channel = _Channel(confirm)
        channel.cancel("cancelled")
        AccessWindow._confirm_worker(state, token, "telegram", channel)
        confirm.start.assert_not_called()
        confirm.poll.assert_not_called()

    def test_expired_worker_never_starts(self):
        from pw_storage.window import _Channel
        state, token = self.state()
        state.clock = lambda: 20
        confirm = mock.Mock()
        AccessWindow._confirm_worker(state, token, "telegram", _Channel(confirm))
        confirm.start.assert_not_called()

    def test_remote_terminal_error_stops_but_no_link_retries_until_expiry(self):
        from pw_storage.window import _Channel, _RequestState
        for error, check in ((RuntimeError("terminal"), lambda n: self.assertEqual(n, 1)),
                             (NoLink("transient"), lambda n: self.assertGreaterEqual(n, 4))):
            now = [0]

            def clock():
                now[0] += 1
                return now[0]

            state = _RequestState(clock, 20)
            self.assertTrue(state.add_channel_worker())
            listener = mock.Mock()
            listener.start.side_effect = error
            channel = _Channel(listener, remote=True)
            with mock.patch("pw_storage.window.TELEGRAM_POLL_SECONDS", 0), \
                    mock.patch("pw_storage.window.channel_retry_pause", lambda failures: 0):
                AccessWindow._remote_worker(state, channel, mock.Mock())
            check(listener.start.call_count)
            listener.say.assert_called_once()

    def test_remote_cancel_blocked_start_never_polls_or_unlocks(self):
        from pw_storage.window import _Channel, _RequestState
        state = _RequestState(lambda: 0, 20)
        self.assertTrue(state.add_channel_worker())
        entered, release = threading.Event(), threading.Event()
        listener, unlock = mock.Mock(), mock.Mock()
        def start():
            entered.set()
            if not release.wait(5):
                raise AssertionError("barrier timeout")
        listener.start.side_effect = start
        channel = _Channel(listener, remote=True)
        worker = threading.Thread(target=AccessWindow._remote_worker, args=(state, channel, unlock))
        worker.start()
        self.assertTrue(entered.wait(5))
        channel.cancel("cancelled")
        release.set()
        worker.join(5)
        self.assertFalse(worker.is_alive())
        listener.poll.assert_not_called()
        unlock.assert_not_called()
        listener.say.assert_called_once_with("cancelled")


if __name__ == "__main__":
    unittest.main()
