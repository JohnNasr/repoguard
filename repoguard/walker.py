"""Walk a directory tree without following links and without executing anything."""

from __future__ import annotations

import os
import re
import stat
import unicodedata
from dataclasses import dataclass, field, replace
from pathlib import Path

from .context import FileContext, SpecialEntry
from .models import ScanOptions, ScanStats

_RESERVED = re.compile(r"^(con|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³])(\..*)?$", re.I)
_BINARY_MAGIC = (
    b"MZ", b"\x7fELF", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe", b"PK\x03\x04", b"\x1f\x8b", b"7z\xbc\xaf", b"Rar!", b"\x89PNG", b"\xff\xd8\xff",
    b"GIF8", b"%PDF", b"\xd0\xcf\x11\xe0", b"BZh", b"\xfd7zXZ", b"\x00asm", b"OggS", b"RIFF", b"ID3",
)
_SNIFF = 8192
_LONG_PATH = 240


@dataclass
class WalkResult:
    files: list[FileContext] = field(default_factory=list)
    special: list[SpecialEntry] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)
    limits_hit: list[str] = field(default_factory=list)


def _is_binary(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            head = fh.read(_SNIFF)
    except OSError:
        return False
    if b"\x00" in head:
        # UTF-16 text has NULs too; treat a BOM-prefixed file as text
        return not head.startswith((b"\xff\xfe", b"\xfe\xff"))
    return head.startswith(_BINARY_MAGIC)


def _readlink(path: str) -> str:
    try:
        return os.readlink(path)
    except OSError:
        return ""


def walk(root: Path, options: ScanOptions) -> WalkResult:
    """Iterative scandir walk. Never follows symlinks/junctions; skips only the top-level .git."""
    res = WalkResult()
    root_s = str(root)
    seen_fold: dict[str, str] = {}
    total = seen = oversize = binaries = 0
    stack: list[tuple[str, str, int]] = [(root_s, "", 0)]
    stop = False

    while stack and not stop:
        abs_dir, rel_dir, depth = stack.pop()
        try:
            with os.scandir(abs_dir) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError as exc:
            res.special.append(SpecialEntry(rel_dir or ".", "unreadable", str(exc)[:200]))
            continue
        for e in entries:
            rel = f"{rel_dir}/{e.name}" if rel_dir else e.name
            fold = unicodedata.normalize("NFC", rel).casefold()
            if fold in seen_fold and seen_fold[fold] != rel:
                res.special.append(SpecialEntry(rel, "case_collision", seen_fold[fold]))
            seen_fold.setdefault(fold, rel)
            if len(rel) > _LONG_PATH:
                res.special.append(SpecialEntry(rel, "long_path", str(len(rel))))
            if _RESERVED.match(e.name) or e.name.endswith((".", " ")):
                res.special.append(SpecialEntry(rel, "reserved_name"))
                continue
            try:
                if e.is_symlink():
                    res.special.append(SpecialEntry(rel, "symlink", _readlink(e.path)))
                    continue
                if hasattr(e, "is_junction") and e.is_junction():
                    res.special.append(SpecialEntry(rel, "junction", _readlink(e.path)))
                    continue
                st = e.stat(follow_symlinks=False)
            except OSError as exc:
                res.special.append(SpecialEntry(rel, "unreadable", str(exc)[:200]))
                continue
            # Directory reparse points that are neither symlink nor junction (mount points etc.)
            if stat.S_ISDIR(st.st_mode) and getattr(st, "st_file_attributes", 0) & getattr(
                stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
            ):
                res.special.append(SpecialEntry(rel, "junction", "reparse point"))
                continue

            if stat.S_ISDIR(st.st_mode):
                if e.name == ".git":
                    if rel_dir:  # nested repo / fake submodule
                        res.special.append(SpecialEntry(rel, "nested_git"))
                    continue
                if depth + 1 > options.max_depth:
                    res.special.append(SpecialEntry(rel, "depth", str(depth + 1)))
                    if "max_depth" not in res.limits_hit:
                        res.limits_hit.append("max_depth")
                    continue
                stack.append((e.path, rel, depth + 1))
                continue
            if not stat.S_ISREG(st.st_mode):
                res.special.append(SpecialEntry(rel, "device"))
                continue
            if e.name == ".git" and rel_dir:  # gitdir file of a nested worktree/submodule
                res.special.append(SpecialEntry(rel, "nested_git", "gitfile"))

            seen += 1
            if len(res.files) >= options.max_files:
                res.limits_hit.append("max_files")
                stop = True
                break
            size = st.st_size
            truncated = size > options.max_file_size
            read_bytes = min(size, 65536 if truncated else size)
            if total + read_bytes > options.max_total_bytes:
                res.limits_hit.append("max_total_bytes")
                stop = True
                break
            total += read_bytes
            if truncated:
                oversize += 1
                res.special.append(SpecialEntry(rel, "oversize", str(size)))
            binary = _is_binary(e.path)
            if binary:
                binaries += 1
            res.files.append(FileContext(Path(e.path), rel, size, binary, truncated=truncated,
                                         max_bytes=options.max_file_size))
    res.stats = replace(res.stats, files_seen=seen, skipped_oversize=oversize, skipped_binary=binaries,
                        bytes_scanned=total)
    res.files.sort(key=lambda f: f.rel_path)
    return res
