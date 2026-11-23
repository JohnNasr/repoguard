"""FSX - filesystem tricks: symlinks, traversal names, reserved names, collisions, bombs, submodules,
.gitattributes drivers and a hostile local .git directory. Never runs git: .git/config is read as text."""

from __future__ import annotations

import io
import posixpath
import re
import stat
import unicodedata
import zipfile
from collections import defaultdict
from collections.abc import Iterable, Iterator
from pathlib import Path

from .. import tags as T
from ..context import FileContext, RepoContext, SpecialEntry
from ..detector import Detector, RuleInfo
from ..models import Category, Confidence, Finding, Severity

_C = Category.FILESYSTEM
_FS = frozenset({T.FS_TRICK})

FSX001 = RuleInfo(
    "FSX001", "Symbolic link / junction", Severity.HIGH, Confidence.HIGH, _C,
    "Symlinks can make tools read or overwrite files outside the repository (SSH keys, system files) when it is built or extracted.",
    "Check where each link points; delete links that leave the repository.", _FS,
)
FSX002 = RuleInfo(
    "FSX002", "Path traversal / absolute path name", Severity.HIGH, Confidence.HIGH, _C,
    "A path contains '..', an absolute path, a drive letter or ':' (NTFS alternate data stream). Extracting or copying it can write outside the folder.",
    "Do not extract or build this repo with tools that trust paths; rename or remove the entry.", _FS,
)
FSX003 = RuleInfo(
    "FSX003", "Reserved device name or .git look-alike", Severity.HIGH, Confidence.HIGH, _C,
    "Windows device names (CON, NUL, AUX...), trailing dots/spaces and .git look-alikes break checkouts or overwrite git internals (CVE-2019-1353 family).",
    "Avoid checking this repo out on Windows/macOS until the names are removed.", _FS,
)
FSX004 = RuleInfo(
    "FSX004", "Case / Unicode normalization collision", Severity.MEDIUM, Confidence.HIGH, _C,
    "Two paths differ only by case or Unicode normalization. On Windows/macOS one silently replaces the other (used in CVE-2021-21300 style attacks).",
    "Inspect both files; the one you see after checkout may not be the one reviewers saw.", _FS,
)
FSX005 = RuleInfo(
    "FSX005", "Huge file or decompression bomb", Severity.MEDIUM, Confidence.HIGH, _C,
    "A very large file or an archive with an extreme compression ratio can exhaust disk/memory or hide content from scanners.",
    "Do not extract the archive; ask why it is committed.", _FS,
)
FSX006 = RuleInfo(
    "FSX006", "Git submodule", Severity.HIGH, Confidence.HIGH, _C,
    "Submodules pull extra code from other locations. Option-like URLs, ext:: / file:// transports or '..' paths are known clone-time exploits.",
    "Do not clone with --recursive; review each submodule URL and scan it separately.", _FS,
)
FSX007 = RuleInfo(
    "FSX007", ".gitattributes drivers / review evasion", Severity.MEDIUM, Confidence.MEDIUM, _C,
    ".gitattributes can attach filter/diff/merge drivers to files, keep content in LFS (not scanned) or hide first-party code from diffs and release archives.",
    "Check that any driver it names is not defined in your git config; review files hidden from diffs manually.", _FS,
)
FSX008 = RuleInfo(
    "FSX008", "Hostile local .git directory", Severity.CRITICAL, Confidence.HIGH, _C,
    "The folder's own .git/config or .git/hooks run commands as soon as you run ordinary git commands inside it (git status, git diff, your IDE).",
    "Do not run git in this folder. Delete the .git directory or re-clone from the original source.", _FS,
)
FSX009 = RuleInfo(
    "FSX009", "File missing after checkout", Severity.HIGH, Confidence.MEDIUM, _C,
    "A file is in the git tree but not on disk: antivirus quarantine or a name the OS refused. Either way it was not scanned.",
    "Check your antivirus log; inspect the blob with `git show` in a disposable environment.", _FS,
)
FSX010 = RuleInfo(
    "FSX010", "Nested .git directory", Severity.MEDIUM, Confidence.MEDIUM, _C,
    "A .git directory inside the tree is a hidden repository or a fake submodule, which can carry its own hostile config.",
    "Inspect the nested .git/config and hooks; delete the nested repository if it is not needed.", _FS,
)

_BIG = 50 * 1024 * 1024
_GIG = 1024 * 1024 * 1024
_MAX = 20
_RESERVED_RE = re.compile(r"(?i)^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$")
_GIT_SPOOF_RE = re.compile(r"(?i)^\.git[\. ]+$|^git~\d+$")
_IGNORABLE_RE = re.compile("[­͏​-‏‪-‮⁠-⁤⁦-⁩﻿]")
_SENSITIVE_RE = re.compile(
    r"(?i)(?:^|[\\/])\.(?:ssh|aws|gnupg|kube|azure|docker|config/gcloud)(?:[\\/]|$)|^/etc(?:/|$)|^[a-z]:[\\/]users|"
    r"%appdata%|%userprofile%|%localappdata%|^~|/root(?:/|$)|^/home/|^/users/|[\\/]appdata[\\/]|^/proc/|^/dev/|"
    r"docker\.sock|id_rsa|id_ed25519|\.netrc|\.npmrc|\.pypirc|\.git-credentials|keychain|login data|cookies|"
    r"\.bash_history|\.zsh_history|\.bashrc|\.zshrc|\.profile"
)
_ZIP_EXT = frozenset({".zip", ".jar", ".war", ".ear", ".apk", ".whl", ".nupkg", ".xpi", ".vsix", ".crx", ".egg", ".aar"})
_ARCHIVE_EXT = frozenset({".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".whl", ".cab", ".iso", ".zst"})
_BUILTIN_DIFF = frozenset(
    {"ada", "bash", "bibtex", "cpp", "csharp", "css", "dts", "elixir", "fortran", "fountain", "golang", "html", "java",
     "kotlin", "markdown", "matlab", "objc", "pascal", "perl", "php", "python", "ruby", "rust", "scheme", "tex",
     "astextplain", "default"}
)
_BUILTIN_MERGE = frozenset({"text", "binary", "union"})
_CODE_PATTERN_RE = re.compile(
    r"(?i)\.(?:py|js|mjs|cjs|jsx|ts|tsx|sh|bash|ps1|psm1|bat|cmd|rb|go|rs|java|kt|php|c|cc|cpp|h|cs|lua|pl|swift)\b"
    r"|(?:^|/)(?:src|lib|app|bin|scripts|cmd|pkg)(?:/|$)|^\*$|^/?\*\*?$"
)
_NOT_FIRST_PARTY_RE = re.compile(
    r"(?i)vendor|third[_-]?party|node_modules|dist/|build/|generated|\.min\.|tests?/|fixtures?|docs?/|examples?/|"
    r"\.github|lock|_pb2|\.pb\.|snapshots?|testdata|__snapshots__|bundle|external|deps/"
)
_HIDE_ATTRS = frozenset({"export-ignore", "linguist-generated", "linguist-generated=true", "linguist-vendored",
                         "linguist-vendored=true", "linguist-documentation", "-diff", "binary"})
_BAD_SUB_URL_RE = re.compile(r"(?i)^\s*(?:-|ext::|file://|http://)")


def _conf(base: Confidence, ctx: FileContext | None) -> Confidence:
    if ctx is not None and ctx.context_kind is not None and base > Confidence.LOW:
        return Confidence(base - 1)
    return base


def _norm(p: str) -> str:
    return p.replace("\\", "/")


def _is_zip(ctx: FileContext) -> bool:
    if ctx.ext in _ZIP_EXT:
        return True
    return ctx.is_binary and ctx.head[:4] in (b"PK\x03\x04", b"PK\x05\x06")



_REPARSE = 0x400


def _lkind(p: Path) -> str | None:
    """'dir' / 'file' / 'link' (symlink, junction or other reparse point) / 'other', without following links."""
    try:
        st = p.lstat()
    except OSError:
        return None
    if stat.S_ISLNK(st.st_mode) or getattr(st, "st_file_attributes", 0) & _REPARSE:
        return "link"
    if stat.S_ISDIR(st.st_mode):
        return "dir"
    if stat.S_ISREG(st.st_mode):
        return "file"
    return "other"


def _read_head(p: Path, n: int) -> bytes:
    try:
        with open(p, "rb") as fh:
            return fh.read(n)
    except OSError:
        return b""

class FsTricksDetector(Detector):
    id = "fs_tricks"
    name = "Filesystem tricks"
    category = _C
    checks = (FSX001, FSX002, FSX003, FSX004, FSX005, FSX006, FSX007, FSX008, FSX009, FSX010)

    def applies_to(self, ctx: FileContext) -> bool:
        name = ctx.basename.lower()
        if name in (".gitmodules", ".gitattributes"):
            return not ctx.is_binary
        return ctx.ext in (".gz", ".tgz") or _is_zip(ctx)

    def scan_file(self, ctx: FileContext) -> Iterable[Finding]:
        name = ctx.basename.lower()
        if name == ".gitmodules":
            return list(self._gitmodules(ctx))
        if name == ".gitattributes":
            return list(self._gitattributes(ctx))
        if ctx.ext in (".gz", ".tgz"):
            return list(self._gzip_bomb(ctx))
        return list(self._zip_bomb(ctx))

    # ---- FSX005 (per file) -----------------------------------------------------------------------------
    def _zip_bomb(self, ctx: FileContext) -> Iterator[Finding]:
        try:
            src = ctx.path if ctx.path is not None and ctx.path.exists() else io.BytesIO(ctx.raw)
            zf = zipfile.ZipFile(src)  # reads the central directory only; nothing is extracted
        except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, ValueError, EOFError, NotImplementedError):
            return
        with zf:
            infos = zf.infolist()
        reasons: list[str] = []
        total_u = sum(i.file_size for i in infos)
        total_c = sum(i.compress_size for i in infos)
        if total_u > _GIG:
            reasons.append(f"declares {total_u / _GIG:.1f} GB uncompressed")
        if total_u > 10 * 1024 * 1024 and total_u / max(total_c, 1) > 100:
            reasons.append(f"overall compression ratio {total_u // max(total_c, 1)}:1")
        else:
            worst = max(
                (i for i in infos if i.file_size > 10 * 1024 * 1024), key=lambda i: i.file_size / max(i.compress_size, 1),
                default=None,
            )
            if worst is not None and worst.file_size / max(worst.compress_size, 1) > 100:
                reasons.append(f"entry '{worst.filename[:80]}' ratio {worst.file_size // max(worst.compress_size, 1)}:1")
        if len(infos) > 1 and len({i.header_offset for i in infos}) < len(infos):
            reasons.append("entries overlap (non-recursive zip bomb layout)")
        if len(infos) > 100_000:
            reasons.append(f"{len(infos)} entries")
        if reasons:
            yield Finding.from_rule(
                FSX005, ctx, None, ctx.rel_path, confidence=_conf(Confidence.HIGH, ctx),
                description=f"Archive looks like a decompression bomb: {'; '.join(reasons)}.",
            )

    def _gzip_bomb(self, ctx: FileContext) -> Iterator[Finding]:
        if ctx.path is None or ctx.size < 18 or not ctx.head.startswith(b"\x1f\x8b"):
            return
        try:
            with open(ctx.path, "rb") as fh:
                fh.seek(-4, 2)
                isize = int.from_bytes(fh.read(4), "little")
        except OSError:
            return
        if isize > 10 * 1024 * 1024 and isize / ctx.size > 100:
            yield Finding.from_rule(
                FSX005, ctx, None, ctx.rel_path, confidence=_conf(Confidence.HIGH, ctx),
                description=f"gzip stream expands {isize // ctx.size}:1 (to {isize // (1024 * 1024)} MB or more).",
            )

    # ---- FSX006 ----------------------------------------------------------------------------------------
    def _gitmodules(self, ctx: FileContext) -> Iterator[Finding]:
        subs: list[dict[str, tuple[int, str]]] = []
        for ln, raw in enumerate(ctx.lines, 1):
            line = raw.strip()
            if not line or line[0] in "#;":
                continue
            m = re.match(r'^\[\s*submodule\s+"([^"]*)"\s*\]', line, re.I)
            if m:
                subs.append({"name": (ln, m.group(1))})
                continue
            if not subs or "=" not in line:
                continue
            key, _, val = line.partition("=")
            subs[-1][key.strip().lower()] = (ln, val.strip().strip('"'))
        for n, sub in enumerate(subs):
            if n >= 50:
                break
            name_ln, name = sub["name"]
            url_ln, url = sub.get("url", (name_ln, ""))
            path_ln, path = sub.get("path", (name_ln, ""))
            issues: list[tuple[int, str]] = []
            if url and _BAD_SUB_URL_RE.match(url):
                issues.append((url_ln, f"dangerous URL '{url[:100]}'"))
            if "--upload-pack" in url or "-u " in url:
                issues.append((url_ln, "URL injects git options"))
            for label, val, vln in (("path", path, path_ln), ("name", name, name_ln)):
                parts = _norm(val).split("/")
                if ".." in parts or val.startswith(("-", "/")) or re.match(r"[A-Za-z]:", val):
                    issues.append((vln, f"{label} '{val[:100]}' escapes the repo or looks like an option"))
                elif any(p.lower() == ".git" for p in parts):
                    issues.append((vln, f"{label} '{val[:100]}' writes into .git"))
            upd_ln, upd = sub.get("update", (0, ""))
            if upd.startswith("!"):
                issues.append((upd_ln, f"update runs a shell command '{upd[:100]}'"))
            if issues:
                yield Finding.from_rule(
                    FSX006, ctx, issues[0][0], ctx.line_text(issues[0][0]),
                    description=f"Submodule '{name[:80]}': " + "; ".join(i[1] for i in issues) + ".",
                )
            else:
                yield Finding.from_rule(
                    FSX006, ctx, url_ln, ctx.line_text(url_ln), severity=Severity.INFO,
                    description=f"Submodule '{name[:80]}' -> {url[:120] or '(no url)'} is not part of this scan.",
                )

    # ---- FSX007 ----------------------------------------------------------------------------------------
    def _gitattributes(self, ctx: FileContext) -> Iterator[Finding]:
        emitted = 0
        lfs_lines: list[int] = []
        for ln, raw in enumerate(ctx.lines, 1):
            if emitted >= _MAX:
                break
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            tokens = line.split()
            pattern, attrs = tokens[0], tokens[1:]
            issues: list[str] = []
            for a in attrs:
                key, _, val = a.partition("=")
                if key == "filter" and val:
                    if val == "lfs":
                        lfs_lines.append(ln)
                    else:
                        issues.append(f"custom filter driver '{val}'")
                elif key == "diff" and val and val not in _BUILTIN_DIFF and val != "lfs":
                    issues.append(f"custom diff driver '{val}'")
                elif key == "merge" and val and val not in _BUILTIN_MERGE and val != "lfs":
                    issues.append(f"custom merge driver '{val}'")
            hide = sorted({a for a in attrs if a in _HIDE_ATTRS})
            if hide and _CODE_PATTERN_RE.search(pattern) and not _NOT_FIRST_PARTY_RE.search(pattern):
                issues.append(f"{', '.join(hide)} on first-party code '{pattern}' hides it from review/diffs/archives")
            if issues:
                emitted += 1
                extra = (T.EVASION,) if hide else ()
                yield Finding.from_rule(
                    FSX007, ctx, ln, raw, confidence=_conf(Confidence.MEDIUM, ctx), extra_tags=extra,
                    description="; ".join(issues) + ".",
                )
        if lfs_lines:
            yield Finding.from_rule(
                FSX007, ctx, lfs_lines[0], ctx.line_text(lfs_lines[0]), severity=Severity.INFO,
                description=f"{len(lfs_lines)} pattern(s) stored in Git LFS: their real content is not in the tree and was not scanned.",
            )

    # ---- repo-level ------------------------------------------------------------------------------------
    def scan_repo(self, repo: RepoContext) -> Iterable[Finding]:
        out: list[Finding] = []
        specials = [SpecialEntry(_norm(s.rel_path), s.kind, s.detail) for s in repo.special]
        paths = [f.rel_path for f in repo.files] + [s.rel_path for s in specials]
        out.extend(self._specials(repo, specials))
        out.extend(self._names(repo, paths, specials))
        out.extend(self._collisions(repo, paths, specials))
        out.extend(self._big_files(repo, specials))
        if not repo.is_remote:
            out.extend(self._local_git(repo.root))
        return out

    def _specials(self, repo: RepoContext, specials: list[SpecialEntry]) -> Iterator[Finding]:
        has_gitmodules = repo.get(".gitmodules") is not None
        counts: dict[str, int] = defaultdict(int)
        for sp in specials:
            counts[sp.kind] += 1
            if counts[sp.kind] > 100:
                continue
            ctx = repo.get(sp.rel_path)
            if sp.kind in ("symlink", "junction"):
                yield self._symlink(sp, ctx)
            elif sp.kind == "missing_checkout":
                yield Finding.from_rule(FSX009, ctx, None, sp.detail or sp.rel_path, path=sp.rel_path)
            elif sp.kind == "nested_git":
                yield Finding.from_rule(FSX010, ctx, None, sp.detail or sp.rel_path, path=sp.rel_path)
            elif sp.kind == "submodule" and not has_gitmodules:
                yield Finding.from_rule(
                    FSX006, ctx, None, sp.detail or sp.rel_path, path=sp.rel_path, severity=Severity.INFO,
                    description="Submodule (gitlink) without a .gitmodules entry; it was not scanned.",
                )

    @staticmethod
    def _symlink(sp: SpecialEntry, ctx: FileContext | None) -> Finding:
        target = sp.detail.strip()
        kind = "Junction" if sp.kind == "junction" else "Symlink"
        if not target:
            return Finding.from_rule(
                FSX001, ctx, None, sp.rel_path, path=sp.rel_path, severity=Severity.INFO,
                description=f"{kind} (target unknown).",
            )
        t = _norm(target)
        if t.startswith("/") or re.match(r"[A-Za-z]:", t) or t.startswith("//"):
            escapes = True
        else:
            joined = posixpath.normpath(posixpath.join(posixpath.dirname(sp.rel_path), t))
            escapes = joined == ".." or joined.startswith("../")
        if _SENSITIVE_RE.search(target):
            sev, why = Severity.CRITICAL, "points at a sensitive location"
        elif escapes:
            sev, why = Severity.HIGH, "points outside the repository"
        else:
            sev, why = Severity.INFO, "stays inside the repository"
        return Finding.from_rule(
            FSX001, ctx, None, f"{sp.rel_path} -> {target}", path=sp.rel_path, severity=sev,
            description=f"{kind} {why}: '{target[:150]}'.",
        )

    def _names(self, repo: RepoContext, paths: list[str], specials: list[SpecialEntry]) -> Iterator[Finding]:
        n2 = n3 = 0
        for sp in specials:
            if sp.kind == "reserved_name" and n3 < _MAX:
                n3 += 1
                yield Finding.from_rule(
                    FSX003, repo.get(sp.rel_path), None, sp.rel_path, path=sp.rel_path,
                    description=f"Walker flagged a reserved/invalid name{': ' + sp.detail if sp.detail else ''}.",
                )
        for p in paths:
            if n2 >= _MAX and n3 >= _MAX:
                break
            parts = p.split("/")
            if n2 < _MAX:
                why = ""
                if ".." in parts:
                    why = "'..' component"
                elif p.startswith("/") or re.match(r"[A-Za-z]:", p):
                    why = "absolute path / drive letter"
                elif ":" in p:
                    why = "':' in name (NTFS alternate data stream)"
                if why:
                    n2 += 1
                    yield Finding.from_rule(FSX002, repo.get(p), None, p, path=p, description=f"{FSX002.title}: {why}.")
            if n3 < _MAX:
                why, sev = self._reserved(parts)
                if why:
                    n3 += 1
                    ctx = repo.get(p)
                    yield Finding.from_rule(
                        FSX003, ctx, None, p, path=p, severity=sev, confidence=_conf(Confidence.HIGH, ctx),
                        description=f"{why}.",
                    )

    @staticmethod
    def _reserved(parts: list[str]) -> tuple[str, Severity]:
        for comp in parts:
            if comp in ("", ".", ".."):
                continue
            low = comp.lower()
            if _GIT_SPOOF_RE.match(comp) or (low == ".git" and comp != ".git"):
                return f"'{comp}' is treated as .git on Windows/macOS", Severity.HIGH
            stripped = _IGNORABLE_RE.sub("", unicodedata.normalize("NFC", comp)).casefold()
            if stripped == ".git" and low != ".git":
                return f"'{comp}' hides invisible characters and is treated as .git on macOS (HFS+)", Severity.HIGH
            if comp.endswith((".", " ")):
                return f"'{comp}' has a trailing dot/space (silently renamed on Windows)", Severity.HIGH
            m = _RESERVED_RE.match(comp)
            if m:
                exact = m.group(2) is None
                return (
                    f"'{comp}' is a Windows reserved device name",
                    Severity.HIGH if exact else Severity.MEDIUM,
                )
        return "", Severity.INFO

    def _collisions(self, repo: RepoContext, paths: list[str], specials: list[SpecialEntry]) -> Iterator[Finding]:
        groups: dict[str, set[str]] = defaultdict(set)
        for p in paths:
            parts = p.split("/")
            for i in range(1, len(parts) + 1):
                prefix = "/".join(parts[:i])
                groups[unicodedata.normalize("NFC", prefix).casefold()].add(prefix)
        reported: set[str] = set()
        emitted = 0
        for key in sorted(groups, key=lambda k: (k.count("/"), k)):
            originals = groups[key]
            if len(originals) < 2:
                continue
            parent = key.rsplit("/", 1)[0] if "/" in key else ""
            if parent and parent in reported:
                reported.add(key)  # already covered by the colliding parent directory
                continue
            reported.add(key)
            emitted += 1
            if emitted > _MAX:
                break
            ordered = sorted(originals)
            yield Finding.from_rule(
                FSX004, repo.get(ordered[0]), None, " <-> ".join(ordered[:4]), path=ordered[0],
                description=f"{len(ordered)} paths collide on case-insensitive / normalizing filesystems: {', '.join(ordered[:4])}.",
            )
        for sp in specials:
            if sp.kind == "case_collision" and unicodedata.normalize("NFC", sp.rel_path).casefold() not in reported:
                yield Finding.from_rule(
                    FSX004, repo.get(sp.rel_path), None, sp.detail or sp.rel_path, path=sp.rel_path,
                    description=f"Walker saw a case/normalization collision{': ' + sp.detail if sp.detail else ''}.",
                )

    def _big_files(self, repo: RepoContext, specials: list[SpecialEntry]) -> Iterator[Finding]:
        seen: set[str] = set()
        for f in repo.files:
            if f.size > _BIG and len(seen) < _MAX:
                seen.add(f.rel_path)
                yield Finding.from_rule(
                    FSX005, f, None, f.rel_path, confidence=_conf(Confidence.HIGH, f),
                    description=f"File is {f.size // (1024 * 1024)} MB (over 50 MB).",
                )
        for sp in specials:
            if sp.kind != "oversize" or sp.rel_path in seen or len(seen) >= _MAX:
                continue
            sizes = [int(x) for x in re.findall(r"\d{6,}", sp.detail)]
            if sizes and max(sizes) > _BIG:
                seen.add(sp.rel_path)
                yield Finding.from_rule(
                    FSX005, repo.get(sp.rel_path), None, sp.rel_path, path=sp.rel_path,
                    description=f"File is {max(sizes) // (1024 * 1024)} MB (over 50 MB).",
                )

    # ---- FSX008 ----------------------------------------------------------------------------------------
    def _local_git(self, root: Path) -> Iterator[Finding]:
        dotgit = root / ".git"
        kind = _lkind(dotgit)
        if kind is None:
            return
        if kind == "link":
            yield Finding.from_rule(
                FSX008, None, None, ".git", path=".git", severity=Severity.HIGH,
                description="The .git entry is a symlink/junction to another folder; git would use that folder's "
                            "config and hooks.",
            )
            return
        if kind == "file":
            head = _read_head(dotgit, 4096).decode("utf-8", "replace")
            m = re.match(r"\s*gitdir:[ \t]*([^\r\n]+)", head)
            if not m:
                return
            try:
                root_r = root.resolve()
                gitdir = (root / m.group(1).strip()).resolve()
                inside = gitdir.is_relative_to(root_r)
            except (OSError, ValueError):
                return
            if not inside:
                yield Finding.from_rule(
                    FSX008, None, None, head.strip()[:200], path=".git", severity=Severity.HIGH,
                    description="The .git file redirects git to a folder outside this project; git would run with "
                                "that folder's config and hooks.",
                )
                return
            if _lkind(gitdir) != "dir":
                return
            rel_git = gitdir.relative_to(root_r).as_posix()
        elif kind == "dir":
            gitdir, rel_git = dotgit, ".git"
        else:
            return
        cfg = gitdir / "config"
        text = _read_head(cfg, 1_000_000).decode("utf-8", "replace") if _lkind(cfg) == "file" else ""
        if text:
            for f in self._git_config(text):
                yield f if rel_git == ".git" else f.replace(path=f"{rel_git}/config")
        hooks = gitdir / "hooks"
        try:
            entries = sorted(hooks.iterdir())[:200] if _lkind(hooks) == "dir" else []
        except OSError:
            entries = []
        n = 0
        for h in entries:
            if n >= _MAX or h.name.endswith(".sample") or _lkind(h) != "file":
                continue
            n += 1
            head = _read_head(h, 4096).decode("utf-8", "replace")
            known = re.search(r"(?i)generated by pre-commit|husky|lefthook|git-lfs", head)
            first = next((ln for ln in head.splitlines() if ln.strip() and not ln.startswith("#!")), "")
            yield Finding.from_rule(
                FSX008, None, None, first or h.name, path=f"{rel_git}/hooks/{h.name}",
                severity=Severity.MEDIUM if known else Severity.CRITICAL,
                extra_tags=(T.EXEC_DYNAMIC,),
                description=f"Active git hook '{h.name}' runs on ordinary git commands"
                f"{' (looks like a standard hook manager)' if known else ''}.",
            )

    @staticmethod
    def _git_config(text: str) -> Iterator[Finding]:
        section = ""
        emitted = 0
        for ln, raw in enumerate(text.splitlines(), 1):
            if emitted >= _MAX:
                break
            line = raw.strip()
            if not line or line[0] in "#;":
                continue
            m = re.match(r'^\[\s*([A-Za-z0-9.-]+)(?:\s+"[^"]*")?\s*\]', line)
            if m:
                section = m.group(1).lower()
                if section in ("include", "includeif"):
                    emitted += 1
                    yield Finding.from_rule(
                        FSX008, None, ln, raw, path=".git/config",
                        description="[include]/[includeIf] pulls in another config file that can define commands.",
                    )
                continue
            key, _, val = line.partition("=")
            key, val = key.strip().lower(), val.strip()
            sub = section.split(".", 1)[0]
            why = ""
            sev = Severity.CRITICAL
            if sub == "core" and key in ("fsmonitor", "sshcommand", "pager", "editor", "hookspath", "askpass", "gitproxy"):
                if key == "fsmonitor" and val.lower() in ("true", "false", "0", "1", "yes", "no", "on", "off", ""):
                    continue
                why = f"core.{key} runs a program"
                if key == "hookspath" and re.match(r"^(?:\./)?\.husky\b", val):
                    sev = Severity.MEDIUM
            elif sub == "filter" and key in ("clean", "smudge", "process"):
                why = f"filter {key} command runs on checkout/add"
            elif sub == "diff" and key in ("textconv", "command"):
                why = f"diff {key} command runs on git diff/log"
            elif sub == "merge" and key == "driver":
                why = "merge driver command"
            elif sub == "credential" and key == "helper":
                why = "credential.helper runs a program that receives your git credentials"
            elif (sub == "gpg" and key == "program") or (sub == "sequence" and key == "editor") or (
                sub in ("difftool", "mergetool") and key == "cmd"
            ):
                why = f"{sub}.{key} runs a program"
            elif sub == "alias" and val.startswith("!"):
                why, sev = f"alias '{key}' runs a shell command", Severity.HIGH
            if why:
                emitted += 1
                yield Finding.from_rule(
                    FSX008, None, ln, raw, path=".git/config", severity=sev, extra_tags=(T.EXEC_DYNAMIC,),
                    description=f"Local .git/config: {why}.",
                )


DETECTORS = (FsTricksDetector,)
