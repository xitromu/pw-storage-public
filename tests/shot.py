"""Снимок окна Tk в PNG для проверки вида и для снимков окон в документации."""

import ctypes
import os
import struct
import time
import zlib
from ctypes import wintypes
from pathlib import Path

PW_RENDERFULLCONTENT = 2
GA_ROOT = 2

_user32 = ctypes.WinDLL("user32")
_gdi32 = ctypes.WinDLL("gdi32")
_user32.GetAncestor.restype = wintypes.HWND
_user32.GetAncestor.argtypes = (wintypes.HWND, wintypes.UINT)
_user32.GetWindowRect.argtypes = (wintypes.HWND, ctypes.POINTER(wintypes.RECT))
_user32.GetDC.restype = wintypes.HDC
_user32.GetDC.argtypes = (wintypes.HWND,)
_user32.ReleaseDC.argtypes = (wintypes.HWND, wintypes.HDC)
_user32.PrintWindow.argtypes = (wintypes.HWND, wintypes.HDC, wintypes.UINT)
_gdi32.CreateCompatibleDC.restype = wintypes.HDC
_gdi32.CreateCompatibleDC.argtypes = (wintypes.HDC,)
_gdi32.CreateCompatibleBitmap.restype = wintypes.HBITMAP
_gdi32.CreateCompatibleBitmap.argtypes = (wintypes.HDC, ctypes.c_int, ctypes.c_int)
_gdi32.SelectObject.restype = wintypes.HGDIOBJ
_gdi32.SelectObject.argtypes = (wintypes.HDC, wintypes.HGDIOBJ)
_gdi32.DeleteObject.argtypes = (wintypes.HGDIOBJ,)
_gdi32.DeleteDC.argtypes = (wintypes.HDC,)
_gdi32.GetDIBits.argtypes = (wintypes.HDC, wintypes.HBITMAP, wintypes.UINT, wintypes.UINT, ctypes.c_void_p, ctypes.c_void_p, wintypes.UINT)


class _BitmapInfo(ctypes.Structure):
    _fields_ = [("biSize", wintypes.DWORD), ("biWidth", wintypes.LONG), ("biHeight", wintypes.LONG),
                ("biPlanes", wintypes.WORD), ("biBitCount", wintypes.WORD), ("biCompression", wintypes.DWORD),
                ("biSizeImage", wintypes.DWORD), ("biXPelsPerMeter", wintypes.LONG), ("biYPelsPerMeter", wintypes.LONG),
                ("biClrUsed", wintypes.DWORD), ("biClrImportant", wintypes.DWORD), ("bmiColors", wintypes.DWORD * 3)]


def _png(path, width, height, rows):
    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data))

    raw = b"".join(b"\x00" + row for row in rows)
    with open(path, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n")
        f.write(chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)))
        f.write(chunk(b"IDAT", zlib.compress(raw, 6)))
        f.write(chunk(b"IEND", b""))


def snapshot(widget, name: str, cycles: int = 25, pause: float = 0.04) -> None:
    """Снимок окна для docs/screenshots: пишется, только задана переменная окружения PW_STORAGE_SHOTS.

    Tk рисует таблицы и канвы лишь реально показанному окну, поэтому окно выводится на экран и
    несколько раз прогоняется цикл событий. Инструмент tools/make_screenshots.py из-за этого мелькает
    окнами — он ручной; обычный прогон тестов переменную не задаёт и окон не показывает.
    """
    folder = os.environ.get("PW_STORAGE_SHOTS")
    if not folder:
        return
    shown = bool(widget.winfo_ismapped())
    widget.deiconify()
    widget.state("normal")
    if widget.winfo_x() < 0 or widget.winfo_y() < 0:
        widget.geometry("+80+80")
    widget.update_idletasks()
    for _ in range(cycles):
        widget.update()
        widget.update_idletasks()
        time.sleep(pause)
        if widget.winfo_viewable() and widget.winfo_width() > 1 and widget.winfo_height() > 1:
            break
    capture(widget, str(Path(folder) / name))
    if not shown:
        widget.withdraw()


def capture(window, path):
    window.update()
    hwnd = _user32.GetAncestor(window.winfo_id(), GA_ROOT)
    rect = wintypes.RECT()
    _user32.GetWindowRect(hwnd, ctypes.byref(rect))
    width, height = rect.right - rect.left, rect.bottom - rect.top
    screen = _user32.GetDC(None)
    memory = _gdi32.CreateCompatibleDC(screen)
    bitmap = _gdi32.CreateCompatibleBitmap(screen, width, height)
    previous = _gdi32.SelectObject(memory, bitmap)
    try:
        _user32.PrintWindow(hwnd, memory, PW_RENDERFULLCONTENT)
        info = _BitmapInfo(biSize=40, biWidth=width, biHeight=-height, biPlanes=1, biBitCount=24, biCompression=0)
        stride = ((width * 3 + 3) // 4) * 4
        buffer = ctypes.create_string_buffer(stride * height)
        _gdi32.GetDIBits(memory, bitmap, 0, height, buffer, ctypes.byref(info), 0)
    finally:
        _gdi32.SelectObject(memory, previous)
        _gdi32.DeleteObject(bitmap)
        _gdi32.DeleteDC(memory)
        _user32.ReleaseDC(None, screen)
    rows = []
    for y in range(height):
        row = bytearray(buffer.raw[y * stride:y * stride + width * 3])
        row[0::3], row[2::3] = row[2::3], row[0::3]  # BGR в RGB
        rows.append(bytes(row))
    _png(path, width, height, rows)
