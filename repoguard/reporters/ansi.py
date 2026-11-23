"""Minimal ANSI colour support (respects NO_COLOR / FORCE_COLOR, enables VT mode on Windows)."""

from __future__ import annotations

import os
import sys
from typing import TextIO

CODES = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m", "red": "\033[31m", "green": "\033[32m",
    "yellow": "\033[33m", "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m", "white": "\033[37m",
    "bg_red": "\033[41;97m", "bg_yellow": "\033[43;30m", "bg_green": "\033[42;30m", "bg_magenta": "\033[45;97m",
}


def _enable_windows_vt() -> bool:
    if os.name != "nt":
        return True
    try:
        import ctypes

        k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        h = k32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not k32.GetConsoleMode(h, ctypes.byref(mode)):
            return False
        return bool(k32.SetConsoleMode(h, mode.value | 0x0004))
    except Exception:  # noqa: BLE001
        return False


def supports_color(stream: TextIO = sys.stdout) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if not hasattr(stream, "isatty") or not stream.isatty():
        return False
    return _enable_windows_vt()


class Painter:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, *styles: str) -> str:
        if not self.enabled or not styles:
            return text
        return "".join(CODES[s] for s in styles) + text + CODES["reset"]
