"""Тесты PW_STORAGE.

Окна Tk в тестах уводятся за экран: виджеты остаются mapped (проверки видимости работают),
но на рабочем столе ничего не мелькает. Production-код не меняется.
"""

import tkinter

_OriginalToplevel = tkinter.Toplevel


class _HeadlessToplevel(_OriginalToplevel):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # До первой отрисовки уводим окно за пределы экрана: mapped, но не видно.
        self.geometry("+-32000+-32000")


tkinter.Toplevel = _HeadlessToplevel