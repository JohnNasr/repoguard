"""Text helpers: entropy, invisible characters, snippet sanitizing, secret masking."""

from __future__ import annotations

import base64
import binascii
import math
import re
import unicodedata
from collections import Counter

# Characters that render as nothing (or reorder text) and are used to hide content.
_INVISIBLE_RANGES: tuple[tuple[int, int], ...] = (
    (0x00AD, 0x00AD),  # soft hyphen
    (0x034F, 0x034F),  # combining grapheme joiner
    (0x115F, 0x1160),  # hangul fillers
    (0x17B4, 0x17B5),
    (0x180E, 0x180E),  # mongolian vowel separator
    (0x200B, 0x200F),  # zero-width space/joiners, LRM/RLM
    (0x202A, 0x202E),  # bidi embeddings/overrides (Trojan Source)
    (0x2060, 0x2064),  # word joiner, invisible operators
    (0x2066, 0x2069),  # bidi isolates (Trojan Source)
    (0x3164, 0x3164),  # hangul filler
    (0xFEFF, 0xFEFF),  # BOM / ZWNBSP (allowed only at offset 0)
    (0xFFA0, 0xFFA0),
    (0xE0000, 0xE007F),  # Unicode tag characters (ASCII smuggling)
)
BIDI_CODEPOINTS = frozenset(range(0x202A, 0x202F)) | frozenset(range(0x2066, 0x206A))
TAG_RANGE = range(0xE0000, 0xE0080)

_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?|\x1b[@-Z\\-_]")


def _is_invisible(cp: int) -> bool:
    for lo, hi in _INVISIBLE_RANGES:
        if lo <= cp <= hi:
            return True
    return False


def find_invisible(s: str) -> list[tuple[int, str]]:
    """Return (offset, 'U+XXXX NAME') for each hidden/bidi character. A BOM at offset 0 is ignored."""
    out: list[tuple[int, str]] = []
    for i, ch in enumerate(s):
        cp = ord(ch)
        if cp < 0xAD:
            continue
        if _is_invisible(cp) and not (cp == 0xFEFF and i == 0):
            out.append((i, f"U+{cp:04X} {unicodedata.name(ch, 'UNNAMED')}"))
    return out


def decode_tag_chars(s: str) -> str:
    """Reveal ASCII smuggled via Unicode tag characters (U+E0020..U+E007E)."""
    return "".join(chr(ord(c) - 0xE0000) for c in s if 0xE0020 <= ord(c) <= 0xE007E)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def sanitize_snippet(s: str, max_len: int = 200) -> str:
    """Make untrusted text safe to print in a terminal / Markdown / JSON consumer."""
    s = mask_secrets_in(_ANSI_RE.sub("", s))
    out: list[str] = []
    for ch in s:
        cp = ord(ch)
        if ch == "\t":
            out.append(" ")
        elif cp < 0x20 or cp == 0x7F or 0x80 <= cp < 0xA0:
            out.append(f"\\x{cp:02x}")
        elif _is_invisible(cp):
            out.append(f"<U+{cp:04X}>")
        else:
            out.append(ch)
    text = " ".join("".join(out).split())
    if len(text) > max_len:
        text = text[: max_len - 1] + "…"
    return text


_SECRET_SHAPES = re.compile(
    r"(?<![A-Za-z0-9_-])(?P<a>gh[pousr]_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{40,255}|sk-ant-[A-Za-z0-9_-]{20,255}"
    r"|sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,255}|(?:AKIA|ASIA)[0-9A-Z]{16}|xox[abprse]-[A-Za-z0-9-]{10,255}"
    r"|AIza[0-9A-Za-z_-]{35}|glpat-[A-Za-z0-9_-]{20,255}|npm_[A-Za-z0-9]{36}|hf_[A-Za-z0-9]{30,255}"
    r"|eyJ[A-Za-z0-9_-]{10,4096}\.eyJ[A-Za-z0-9_-]{10,4096}\.[A-Za-z0-9_-]{10,4096})"
    r"|\b(?i:bearer|token)\s+(?P<b>[A-Za-z0-9._~+/=-]{20,512})"
    r"|/api/webhooks/\d{5,25}/(?P<c>[A-Za-z0-9_-]{30,128})"
)


def mask_secrets_in(s: str) -> str:
    """Mask anything secret-shaped so no snippet prints a live credential."""

    def _m(m: re.Match[str]) -> str:
        g = next(k for k in ("a", "b", "c") if m.group(k))
        rel = m.start(g) - m.start()
        return m.group(0)[:rel] + mask_secret(m.group(g)) + m.group(0)[rel + len(m.group(g)):]

    return _SECRET_SHAPES.sub(_m, s)


def mask_secret(value: str) -> str:
    if len(value) <= 6:
        return "*" * len(value)
    return value[:4] + "*" * min(len(value) - 4, 16)


_PLACEHOLDER_RE = re.compile(
    r"(?i)x{4,}|\*{3,}|\.{3}|<[^>]*>|\$\{|\{\{|%\(|example|sample|dummy|fake|placeholder|"
    r"your[_-]|changeme|redacted|insert|replace|test[_-]?key|0{8,}|1234567|abcdef12|"
    r"process\.env|os\.environ|getenv"
)


def is_placeholder(value: str) -> bool:
    """True for obvious placeholder secrets like sk-xxxx, <YOUR_KEY>, ${TOKEN}, EXAMPLE."""
    if _PLACEHOLDER_RE.search(value):
        return True
    return len(set(value)) <= 3  # aaaaaaaa, 00000000


_B64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}|[A-Za-z0-9_-]{40,}={0,2}")


def decode_base64_candidates(s: str, min_len: int = 40, limit: int = 20) -> list[bytes]:
    """Decode base64-looking runs in s. Returns decoded payloads (best-effort, capped)."""
    out: list[bytes] = []
    for m in _B64_RE.finditer(s):
        token = m.group(0)
        if len(token) < min_len:
            continue
        pad = "=" * (-len(token) % 4)
        try:
            if "-" in token or "_" in token:
                data = base64.urlsafe_b64decode(token + pad)
            else:
                data = base64.b64decode(token + pad, validate=True)
        except (binascii.Error, ValueError):
            continue
        out.append(data)
        if len(out) >= limit:
            break
    return out


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    ok = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return ok / len(data)
