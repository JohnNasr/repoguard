"""BIN - committed binaries and artifacts. Uses magic bytes from ctx.head; archives are LISTED with
zipfile/tarfile (central directory / headers only) and never extracted."""

from __future__ import annotations

import io
import posixpath
import re
import tarfile
import zipfile
import zlib
from collections.abc import Iterable, Iterator

from .. import tags as T
from ..context import FileContext, RepoContext
from ..detector import Detector, RuleInfo
from ..models import Category, Confidence, Finding, Severity

_C = Category.BINARY
_BX = frozenset({T.BINARY_EXEC})

BIN001 = RuleInfo(
    "BIN001", "Committed executable", Severity.MEDIUM, Confidence.HIGH, _C,
    "A compiled program (Windows PE, ELF or Mach-O) is committed. Its behaviour cannot be reviewed from source.",
    "Do not run it. Prefer building from source; check the file hash on VirusTotal if you must use it.", _BX,
)
BIN002 = RuleInfo(
    "BIN002", "Prebuilt native module", Severity.MEDIUM, Confidence.HIGH, _C,
    "A native library (.node/.so/.dylib/.dll/.pyd) is loaded into the process with full privileges when the package is imported.",
    "Rebuild native modules from source, or verify they match an official release.", _BX,
)
BIN003 = RuleInfo(
    "BIN003", "Orphan Python bytecode", Severity.HIGH, Confidence.HIGH, _C,
    "A .pyc file has no matching .py source. Python can import it directly, so it can hide code from reviewers.",
    "Delete the .pyc files and ask for the source.", _BX,
)
BIN004 = RuleInfo(
    "BIN004", "Java archive / class file", Severity.MEDIUM, Confidence.MEDIUM, _C,
    "Compiled Java code is committed; build tools may put it on the classpath and run it.",
    "Prefer artifacts fetched from a trusted repository with checksums; review why it is committed.",
)
BIN005 = RuleInfo(
    "BIN005", "Committed archive", Severity.MEDIUM, Confidence.HIGH, _C,
    "An archive is committed. Its contents were listed but not extracted or scanned.",
    "Do not extract it blindly; scan its contents separately.",
)
BIN006 = RuleInfo(
    "BIN006", "File content does not match its extension", Severity.HIGH, Confidence.HIGH, _C,
    "A file named like an image/font/text/data file is really an executable, archive or script - a common way to smuggle payloads.",
    "Treat the file as hostile; find out what loads it.", _BX,
)
BIN007 = RuleInfo(
    "BIN007", "Deceptive file name", Severity.HIGH, Confidence.HIGH, _C,
    "The file name hides its real type (double extension, right-to-left override, trailing dot/space).",
    "Do not open it; rename it to see its real extension.",
)
BIN008 = RuleInfo(
    "BIN008", "Windows launcher / macro document", Severity.HIGH, Confidence.HIGH, _C,
    "Shortcut, script, installer or macro-enabled Office files run code when double-clicked or opened.",
    "Do not double-click it; open it in a text/hex viewer to see what it runs.", _BX,
)
BIN009 = RuleInfo(
    "BIN009", "Data appended after image end", Severity.MEDIUM, Confidence.MEDIUM, _C,
    "Bytes after the PNG IEND / JPEG end-of-image marker are ignored by viewers and can carry a hidden payload (polyglot file).",
    "Check what reads this image; strip the trailing data.",
)

_NATIVE_EXT = frozenset({".node", ".so", ".dylib", ".dll", ".pyd"})
_SO_VERSIONED_RE = re.compile(r"(?i)\.so(?:\.\d+)+$")
_JAVA_EXT = frozenset({".jar", ".war", ".ear", ".class", ".aar"})
_JAVA_WRAPPERS = frozenset({"gradle-wrapper.jar", "maven-wrapper.jar"})
_OFFICE_ZIP_EXT = frozenset({".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".epub", ".docm", ".xlsm", ".pptm",
                             ".dotm", ".xltm", ".xlam", ".ppam", ".potm", ".sldm", ".dotx", ".xltx", ".potx", ".vsdx"})
_MACRO_EXT = frozenset({".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".ppam", ".potm", ".sldm"})
_LAUNCH_HIGH = frozenset({".lnk", ".scr", ".hta", ".cpl", ".reg", ".xll", ".sct", ".library-ms", ".search-ms", ".url",
                          ".application", ".pif", ".msc", ".jse", ".appref-ms", ".settingcontent-ms", ".iqy"})
_DOC_CONTAINERS = frozenset({".sketch", ".fig", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".epub",
                             ".xd", ".key", ".pages", ".numbers", ".kra", ".ora", ".3mf", ".vsdx"})
_LAUNCH_MED = frozenset({".bat", ".cmd", ".vbs", ".vbe", ".wsf", ".ps1", ".msi", ".msix", ".chm"})
_MISMATCH_EXT = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".tif", ".tiff", ".psd", ".woff", ".woff2", ".ttf",
    ".otf", ".eot", ".mp3", ".mp4", ".wav", ".avi", ".mov", ".ogg", ".flac", ".pdf", ".txt", ".csv", ".tsv", ".dat",
    ".log", ".json", ".xml", ".yml", ".yaml", ".md",
})
_SHEBANG_SUSPECT_EXT = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".woff", ".woff2", ".ttf", ".otf", ".mp3", ".mp4",
    ".wav", ".pdf", ".txt", ".csv", ".dat", ".log",
})
_EXEC_NAME_RE = re.compile(
    r"(?i)\.(?:exe|dll|scr|sys|com|pif|bat|cmd|ps1|vbs|vbe|jse|wsf|hta|lnk|msi|cpl|jar|elf|so|dylib|node|pyd|"
    r"app/contents/macos/[^/]{1,100})$"
)
_ARCHIVE_NAME_RE = re.compile(r"(?i)\.(?:zip|tar|tgz|gz|bz2|xz|7z|rar|cab|iso|jar|whl|apk|zst)$")
_DOUBLE_EXT_RE = re.compile(
    r"(?i)\.(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|mp4|mp3|zip|rar)\s{0,40}\."
    r"(?:exe|scr|bat|cmd|com|pif|vbs|vbe|jse?|wsf|hta|lnk|ps1|msi|cpl|jar)$"
)
_PAD_EXT_RE = re.compile(r"\s{5,}\.[A-Za-z0-9]{2,4}$")
_NAME_TRICK_RE = re.compile("[‪-‮⁦-⁩​-‏⁠﻿]")
_BUILD_SOURCE_NAMES = frozenset({"binding.gyp", "cargo.toml", "cmakelists.txt", "meson.build", "build.rs", "configure.ac"})
_BUILD_SOURCE_EXT = frozenset({".c", ".cc", ".cpp", ".cxx", ".rs", ".zig", ".m", ".mm", ".go"})
_MAX_ENTRIES = 10_000
_MAX_TAR_MEMBERS = 2_000
_READ_CAP = 30 * 1024 * 1024
_MACHO = (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")


def _conf(base: Confidence, ctx: FileContext | None) -> Confidence:
    if ctx is not None and ctx.context_kind is not None and base > Confidence.LOW:
        return Confidence(base - 1)
    return base


def exec_kind(head: bytes, ext: str = "") -> str | None:
    """Name of the executable format identified by magic bytes, or None."""
    if head[:2] == b"MZ" and len(head) >= 0x40:
        off = int.from_bytes(head[0x3C:0x40], "little")
        if off + 4 <= len(head) and head[off : off + 4] == b"PE\x00\x00":
            return "Windows PE"
        return None
    if head[:4] == b"\x7fELF":
        return "ELF"
    if head[:4] in _MACHO:
        return "Mach-O"
    if head[:4] == b"\xca\xfe\xba\xbe" and ext != ".class" and len(head) >= 8 and 0 < int.from_bytes(head[4:8], "big") < 20:
        return "Mach-O universal"
    return None


def _archive_kind(head: bytes, ext: str) -> str | None:
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "zip"
    if head[257:262] == b"ustar":
        return "tar"
    if head[:2] == b"\x1f\x8b":
        return "gzip"
    if head[:3] == b"BZh":
        return "bzip2"
    if head[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if head[:4] == b"\x28\xb5\x2f\xfd":
        return "zstd"
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if head[:6] == b"Rar!\x1a\x07":
        return "rar"
    if head[:4] == b"MSCF":
        return "cab"
    if head[0x8001:0x8006] == b"CD001":
        return "iso"
    if head[:8] == b"vhdxfile":
        return "vhdx"
    by_ext = {
        ".zip": "zip", ".tar": "tar", ".gz": "gzip", ".tgz": "gzip", ".bz2": "bzip2", ".xz": "xz", ".7z": "7z",
        ".rar": "rar", ".cab": "cab", ".iso": "iso", ".img": "disk image", ".vhd": "vhd", ".vhdx": "vhdx",
        ".dmg": "disk image", ".zst": "zstd",
    }
    return by_ext.get(ext)


def _bad_member_name(name: str) -> bool:
    n = name.replace("\\", "/")
    return n.startswith("/") or bool(re.match(r"[A-Za-z]:", n)) or ".." in n.split("/")


def _jpeg_eoi(data: bytes) -> int | None:
    """Offset of the main image's EOI marker, walking segments so embedded thumbnails are skipped."""
    i, n = 2, len(data)
    while i + 4 <= n:
        if data[i] != 0xFF:
            return None
        marker = data[i + 1]
        if marker == 0xFF:
            i += 1
            continue
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        if marker == 0xD9:
            return i
        seglen = int.from_bytes(data[i + 2 : i + 4], "big")
        if marker == 0xDA:
            j = data.find(b"\xff\xd9", i + 2 + seglen)
            return j if j >= 0 else None
        i += 2 + seglen
    return None


class BinariesDetector(Detector):
    id = "binaries"
    name = "Binaries and artifacts"
    category = _C
    checks = (BIN001, BIN002, BIN003, BIN004, BIN005, BIN006, BIN007, BIN008, BIN009)

    def applies_to(self, ctx: FileContext) -> bool:
        return True  # name checks are cheap; magic checks are gated inside scan_file

    def scan_file(self, ctx: FileContext) -> Iterable[Finding]:
        out: list[Finding] = []
        ext = ctx.ext
        out.extend(self._names(ctx))
        if ext in _LAUNCH_HIGH or ext in _LAUNCH_MED or ext in _MACRO_EXT:
            out.extend(self._launcher(ctx))
        if ext in _JAVA_EXT:
            low = ctx.basename.lower()
            out.append(Finding.from_rule(
                BIN004, ctx, None, ctx.rel_path,
                severity=Severity.INFO if low in _JAVA_WRAPPERS else Severity.MEDIUM,
                confidence=_conf(Confidence.MEDIUM, ctx),
            ))
        if not ctx.is_binary:
            if ext in _SHEBANG_SUSPECT_EXT and ctx.text.startswith("#!"):
                out.append(Finding.from_rule(
                    BIN006, ctx, 1, ctx.line_text(1),
                    description=f"'{ctx.basename}' is named like a {ext} file but is a script (starts with #!).",
                ))
            return out
        head = ctx.head
        kind = exec_kind(head, ext)
        arch = _archive_kind(head, ext)
        native = ext in _NATIVE_EXT or bool(_SO_VERSIONED_RE.search(ctx.rel_lower))
        mismatch = None
        if ext in _MISMATCH_EXT:
            if kind:
                mismatch = kind
            elif head[:4] == b"PK\x03\x04":
                mismatch = "zip archive"
            elif head[:2] == b"#!":
                mismatch = "script"
        if mismatch:
            out.append(Finding.from_rule(
                BIN006, ctx, None, ctx.rel_path,
                description=f"'{ctx.basename}' is named like a {ext} file but its content is a {mismatch}.",
            ))
        elif kind and not native:
            out.append(Finding.from_rule(
                BIN001, ctx, None, ctx.rel_path,
                severity=Severity.LOW if ctx.is_test else Severity.MEDIUM,
                confidence=Confidence.HIGH if ctx.is_test else _conf(Confidence.HIGH, ctx),
                description=f"{BIN001.description} Format: {kind}.",
            ))
        if arch and ext not in _OFFICE_ZIP_EXT and ext not in _JAVA_EXT and not mismatch:
            out.extend(self._archive(ctx, arch))
        if ext in (".png", ".jpg", ".jpeg") and not mismatch:
            out.extend(self._appended(ctx, head))
        if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" and ext not in _MACRO_EXT:
            out.extend(self._ole_macro(ctx))
        return out

    # ---- BIN007 ----------------------------------------------------------------------------------------
    def _names(self, ctx: FileContext) -> Iterator[Finding]:
        name = ctx.basename
        if _NAME_TRICK_RE.search(name):
            yield Finding.from_rule(
                BIN007, ctx, None, name, severity=Severity.CRITICAL,
                description="File name contains a right-to-left override or invisible character that disguises its extension.",
            )
        elif _DOUBLE_EXT_RE.search(name) or _PAD_EXT_RE.search(name):
            yield Finding.from_rule(
                BIN007, ctx, None, name, description="Double extension: the file looks like a document but is executable.",
            )
        elif name.endswith((".", " ")):
            yield Finding.from_rule(
                BIN007, ctx, None, name, description="File name ends with a dot/space, which Windows silently strips.",
            )

    # ---- BIN008 ----------------------------------------------------------------------------------------
    def _launcher(self, ctx: FileContext) -> Iterator[Finding]:
        ext = ctx.ext
        if ext in _MACRO_EXT:
            yield Finding.from_rule(
                BIN008, ctx, None, ctx.rel_path, confidence=_conf(Confidence.HIGH, ctx),
                description=f"Macro-enabled Office document ({ext}) can run VBA when opened.",
            )
        elif ext in _LAUNCH_HIGH:
            yield Finding.from_rule(
                BIN008, ctx, None, ctx.rel_path, confidence=_conf(Confidence.HIGH, ctx),
                description=f"{ext} files launch programs or change system settings when opened.",
            )
        else:
            yield Finding.from_rule(
                BIN008, ctx, None, ctx.rel_path,
                severity=Severity.LOW if (ext in (".bat", ".cmd", ".ps1") and not ctx.is_binary) else Severity.MEDIUM,
                confidence=_conf(Confidence.MEDIUM, ctx),
                description=f"{ext} script/installer runs when double-clicked on Windows.",
            )

    def _ole_macro(self, ctx: FileContext) -> Iterator[Finding]:
        data = ctx.raw if ctx.size <= _READ_CAP else ctx.head
        if b"_\x00V\x00B\x00A\x00_\x00P\x00R\x00O\x00J\x00E\x00C\x00T" in data or b"V\x00B\x00A\x00\x00\x00" in data:
            yield Finding.from_rule(
                BIN008, ctx, None, ctx.rel_path, confidence=_conf(Confidence.HIGH, ctx),
                description="Legacy Office (OLE) document contains a VBA macro project.",
            )

    # ---- BIN005 ----------------------------------------------------------------------------------------
    def _archive(self, ctx: FileContext, kind: str) -> Iterator[Finding]:
        names: list[str] = []
        issues: list[str] = []
        sev = Severity.MEDIUM
        extra: list[str] = []
        listed = False
        if kind == "zip":
            try:
                src = ctx.path if ctx.path is not None and ctx.path.exists() else io.BytesIO(ctx.raw)
                with zipfile.ZipFile(src) as zf:
                    infos = zf.infolist()[:_MAX_ENTRIES]
                listed = True
                names = [i.filename for i in infos]
                if any(i.flag_bits & 0x1 for i in infos):
                    issues.append("password-protected entries (hides content from scanners)")
                    sev = Severity.HIGH
                if any(i.filename.lower().endswith("vbaproject.bin") for i in infos):
                    issues.append("contains a VBA macro project")
                    sev = Severity.HIGH
            except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, ValueError, EOFError, NotImplementedError):
                issues.append("could not be listed (corrupt or truncated)")
        elif kind in ("tar", "gzip") and ctx.path is not None:
            names, problem, links = self._list_tar(ctx, kind)
            listed = problem is None
            if problem:
                issues.append(problem)
            if links:
                issues.append(f"links pointing outside the archive ({', '.join(links[:3])})")
                sev = Severity.HIGH
        else:
            issues.append("contents not inspected (no safe stdlib reader)")
        if names:
            execs = [n for n in names if _EXEC_NAME_RE.search(n)]
            nested = [n for n in names if _ARCHIVE_NAME_RE.search(n)]
            slip = [n for n in names if _bad_member_name(n)]
            if execs:
                issues.append(f"executables inside ({', '.join(execs[:3])})")
                extra.append(T.BINARY_EXEC)
                sev = Severity.HIGH
            if slip:
                issues.append(f"path-traversal entry names ({', '.join(slip[:3])})")
                sev = Severity.HIGH
            if nested:
                issues.append(f"nested archives ({', '.join(nested[:3])})")
        if sev == Severity.MEDIUM and ctx.ext in _DOC_CONTAINERS and listed and not extra:
            sev = Severity.LOW
        count = f"{len(names)} entries" if listed else kind
        yield Finding.from_rule(
            BIN005, ctx, None, ", ".join(names[:5]) or ctx.rel_path, severity=sev,
            confidence=_conf(Confidence.HIGH, ctx), extra_tags=tuple(extra),
            description=f"{kind} archive ({count})" + (": " + "; ".join(issues) if issues else "") + ".",
        )

    @staticmethod
    def _list_tar(ctx: FileContext, kind: str) -> tuple[list[str], str | None, list[str]]:
        assert ctx.path is not None
        mode = "r:"
        if kind == "gzip":
            try:
                with open(ctx.path, "rb") as fh:
                    fh.seek(-4, 2)
                    isize = int.from_bytes(fh.read(4), "little")
            except OSError:
                return [], "could not be read", []
            if isize > 200 * 1024 * 1024 or isize / max(ctx.size, 1) > 100:
                return [], "not listed (decompressed size too large)", []
            mode = "r:gz"
        names: list[str] = []
        links: list[str] = []
        try:
            with tarfile.open(name=str(ctx.path), mode=mode) as tf:
                for n, member in enumerate(tf):
                    if n >= _MAX_TAR_MEMBERS or ctx.deadline_exceeded():
                        break
                    names.append(member.name)
                    if member.issym() or member.islnk():
                        target = member.linkname.replace("\\", "/")
                        joined = posixpath.normpath(posixpath.join(posixpath.dirname(member.name), target))
                        if target.startswith("/") or joined == ".." or joined.startswith("../"):
                            links.append(f"{member.name} -> {target}")
        except (tarfile.TarError, OSError, EOFError, zlib.error, ValueError):
            if kind == "gzip":
                return [], None if names else "single gzip-compressed file (not a tar)", links
            return names, "could not be fully listed", links
        return names, None, links

    # ---- BIN009 ----------------------------------------------------------------------------------------
    def _appended(self, ctx: FileContext, head: bytes) -> Iterator[Finding]:
        is_png = head[:8] == b"\x89PNG\r\n\x1a\n"
        is_jpg = head[:3] == b"\xff\xd8\xff"
        if not (is_png or is_jpg) or ctx.size > _READ_CAP:
            return
        try:
            data = ctx.path.read_bytes() if ctx.path is not None else ctx.raw
        except OSError:
            return
        if is_png:
            idx = data.rfind(b"IEND")
            end = idx + 8 if idx >= 0 else None
        else:
            eoi = _jpeg_eoi(data)
            end = eoi + 2 if eoi is not None else None
        if end is None or len(data) - end <= 1024:
            return
        tail = data[end:]
        if not tail.strip(b"\x00"):
            return  # zero padding
        if is_jpg and (tail[:2] == b"\xff\xd8" or tail[4:8] == b"ftyp"):
            return  # multi-picture (MPF) JPEG or Motion Photo video
        sev = Severity.MEDIUM
        extra: tuple[str, ...] = ()
        what = "unknown data"
        probe = tail[:65536]
        if exec_kind(tail[:4096]) or b"PE\x00\x00" in probe[:1024] and probe[:2] == b"MZ":
            what, sev, extra = "an executable", Severity.HIGH, (T.BINARY_EXEC,)
        elif b"PK\x03\x04" in probe or b"PK\x05\x06" in tail[-65536:]:
            what, sev = "a zip archive (polyglot)", Severity.HIGH
        elif tail[:2] == b"#!" or re.search(rb"(?i)<script|eval\(|powershell|/bin/sh", probe[:4096]):
            what, sev = "script text", Severity.HIGH
        yield Finding.from_rule(
            BIN009, ctx, None, ctx.rel_path, severity=sev, confidence=_conf(Confidence.MEDIUM, ctx), extra_tags=extra,
            description=f"{len(tail)} bytes after the end of the {'PNG' if is_png else 'JPEG'} image; looks like {what}.",
        )

    # ---- repo-level: BIN002, BIN003 ------------------------------------------------------------------
    def scan_repo(self, repo: RepoContext) -> Iterable[Finding]:
        out: list[Finding] = []
        paths = {f.rel_lower for f in repo.files}
        has_build = any(
            f.basename.lower() in _BUILD_SOURCE_NAMES or f.ext in _BUILD_SOURCE_EXT for f in repo.files
        ) or any(
            "ext_modules" in f.text or "Extension(" in f.text for f in repo.by_basename("setup.py")
        )
        natives = 0
        orphans = 0
        for f in repo.files:
            rl = f.rel_lower
            if natives < 50 and (f.ext in _NATIVE_EXT or _SO_VERSIONED_RE.search(rl)):
                natives += 1
                out.append(Finding.from_rule(
                    BIN002, f, None, f.rel_path,
                    severity=Severity.LOW if has_build else Severity.MEDIUM,
                    confidence=_conf(Confidence.MEDIUM if has_build else Confidence.HIGH, f),
                    description=BIN002.description + (
                        " The repo also contains native build sources." if has_build
                        else " The repo has no native build sources (no binding.gyp, Cargo.toml, C/C++/Rust files)."
                    ),
                ))
            elif orphans < 50 and f.ext in (".pyc", ".pyo"):
                if self._source_for(rl) not in paths:
                    orphans += 1
                    out.append(Finding.from_rule(
                        BIN003, f, None, f.rel_path, confidence=_conf(Confidence.HIGH, f),
                    ))
        return out

    @staticmethod
    def _source_for(rel_lower: str) -> str:
        directory, _, name = rel_lower.rpartition("/")
        stem = name.rsplit(".", 1)[0]
        if directory.endswith("__pycache__"):
            directory = directory[: -len("__pycache__")].rstrip("/")
            stem = stem.split(".", 1)[0]  # mod.cpython-313 -> mod
        return f"{directory}/{stem}.py" if directory else f"{stem}.py"


DETECTORS = (BinariesDetector,)
