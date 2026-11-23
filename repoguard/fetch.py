"""Safe acquisition of a remote repository: hardened shallow clone, no hooks, no LFS, no submodules."""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from . import procutil
from .context import SpecialEntry

PREFIX = "repoguard-"
MIN_GIT = (2, 45, 1)
_SHORTHAND = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$")
_REF_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,200}$")


class FetchError(RuntimeError):
    pass


def validate_url(target: str) -> str:
    """Return a normalized https clone URL or raise FetchError. Accepts `owner/repo` shorthand."""
    t = target.strip()
    if not t or any(ord(c) < 0x21 or ord(c) == 0x7F for c in t):
        raise FetchError("URL contains spaces or control characters")
    if t.startswith("-"):
        raise FetchError("URL may not start with '-'")
    if _SHORTHAND.match(t) and "://" not in t:
        return f"https://github.com/{t.removesuffix('.git')}.git"
    low = t.lower()
    if low.startswith(("ext::", "fd::", "file:", "ssh:", "git:", "git@", "http:")) or "::" in low.split("/")[0]:
        raise FetchError("only https:// URLs (or owner/repo for GitHub) are allowed")
    if not low.startswith("https://"):
        raise FetchError("only https:// URLs (or owner/repo for GitHub) are allowed")
    parts = urlsplit(t)
    if parts.username or parts.password or "@" in parts.netloc:
        raise FetchError("URLs with embedded credentials are refused")
    if not parts.hostname or parts.query or parts.fragment:
        raise FetchError("malformed URL")
    path = parts.path.rstrip("/")
    if parts.hostname.lower() in {"github.com", "www.github.com"}:
        segs = [s for s in path.split("/") if s]
        if len(segs) < 2:
            raise FetchError("GitHub URL must look like https://github.com/owner/repo")
        owner, repo = segs[0], segs[1].removesuffix(".git")
        return f"https://github.com/{owner}/{repo}.git"
    return f"https://{parts.netloc}{path}"


def github_slug(url: str) -> tuple[str, str] | None:
    m = re.match(r"^https://github\.com/([^/]+)/([^/]+?)(?:\.git)?$", url)
    return (m.group(1), m.group(2)) if m else None


def _git_env(empty_cfg: str) -> dict[str, str]:
    return {
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": empty_cfg,
        "GIT_ASKPASS": "",
        "SSH_ASKPASS": "",
        "GCM_INTERACTIVE": "never",
        "GIT_PROTOCOL_FROM_USER": "0",
        "NoDefaultCurrentDirectoryInExePath": "1",
    }


def _hardening(hooks_dir: str) -> list[str]:
    flags = {
        "core.hooksPath": hooks_dir,
        "core.symlinks": "false",
        "core.fsmonitor": "false",
        "core.protectNTFS": "true",
        "core.protectHFS": "true",
        "core.longpaths": "true",
        "protocol.allow": "never",
        "protocol.https.allow": "always",
        "submodule.recurse": "false",
        "filter.lfs.smudge": "",
        "filter.lfs.process": "",
        "filter.lfs.required": "false",
        "credential.helper": "",
        "http.followRedirects": "initial",
        "http.lowSpeedLimit": "1000",
        "http.lowSpeedTime": "30",
        "init.templateDir": "",
        "safe.directory": "*",
    }
    out: list[str] = []
    for k, v in flags.items():
        out += ["-c", f"{k}={v}"]
    return out


class _Sandbox:
    """Empty hooks dir + empty global config file, created per clone and removed afterwards."""

    def __init__(self) -> None:
        self.dir = tempfile.mkdtemp(prefix=PREFIX + "cfg-")
        self.hooks = os.path.join(self.dir, "hooks")
        os.mkdir(self.hooks)
        self.cfg = os.path.join(self.dir, "gitconfig")
        Path(self.cfg).write_bytes(b"")

    def git(self, args: list[str], timeout: float = 120,
            max_stdout: int | None = None) -> subprocess.CompletedProcess[bytes]:
        return procutil.run(["git", *_hardening(self.hooks), *args], env=_git_env(self.cfg), timeout=timeout,
                            max_stdout=max_stdout)

    def close(self) -> None:
        cleanup(self.dir)


def git_version() -> tuple[int, ...] | None:
    try:
        proc = procutil.run(["git", "--version"], timeout=20)
    except (procutil.ToolMissing, OSError, subprocess.TimeoutExpired):
        return None
    m = re.search(rb"(\d+)\.(\d+)\.(\d+)", proc.stdout)
    return tuple(int(x) for x in m.groups()) if m else None


def git_version_ok() -> bool:
    v = git_version()
    return v is not None and v >= MIN_GIT


def safe_clone(url: str, ref: str | None = None, depth: int = 1, timeout: float = 300) -> Path:
    """Shallow, hardened clone into a fresh temp dir. Returns the checkout path."""
    if ref is not None and not _REF_OK.match(ref):
        raise FetchError("invalid --ref")
    try:
        procutil.resolve("git")
    except procutil.ToolMissing as exc:
        raise FetchError("git is not installed or not on PATH") from exc
    dest = tempfile.mkdtemp(prefix=PREFIX)
    sb = _Sandbox()
    try:
        args = ["clone", "--depth", str(max(1, depth)), "--single-branch", "--no-recurse-submodules", "--no-tags"]
        if ref:
            args += ["--branch", ref]
        args += ["--", url, dest]
        try:
            proc = sb.git(args, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise FetchError(f"git clone timed out after {timeout:.0f}s") from exc
        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", "replace").strip().splitlines()
            raise FetchError("git clone failed: " + (err[-1] if err else f"exit {proc.returncode}"))
        return Path(dest)
    except BaseException:
        cleanup(dest)
        raise
    finally:
        sb.close()


def _git_in(dest: Path, args: list[str], timeout: float = 120,
            max_stdout: int | None = None) -> subprocess.CompletedProcess[bytes]:
    sb = _Sandbox()
    try:
        return sb.git(["-C", str(dest), *args], timeout=timeout, max_stdout=max_stdout)
    finally:
        sb.close()


def head_commit(dest: Path) -> str | None:
    try:
        proc = _git_in(dest, ["rev-parse", "HEAD"], timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    out = proc.stdout.decode("ascii", "replace").strip()
    return out if re.fullmatch(r"[0-9a-f]{40,64}", out) else None


def tree_specials(dest: Path) -> list[SpecialEntry]:
    """Use the git tree (not the checkout) to find symlinks, submodules and files missing on disk."""
    try:
        proc = _git_in(dest, ["ls-tree", "-r", "-z", "--full-tree", "HEAD"], timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        return []
    out: list[SpecialEntry] = []
    for rec in proc.stdout.split(b"\x00"):
        if not rec or b"\t" not in rec:
            continue
        meta, _, raw_path = rec.partition(b"\t")
        mode = meta.split(b" ", 1)[0]
        path = raw_path.decode("utf-8", "replace")
        disk = dest / path
        if mode == b"120000":
            target = ""
            try:
                target = disk.read_bytes()[:500].decode("utf-8", "replace")  # core.symlinks=false -> text file
            except OSError:
                pass
            out.append(SpecialEntry(path, "symlink", target))
        elif mode == b"160000":
            out.append(SpecialEntry(path, "submodule"))
        elif not os.path.lexists(disk):
            out.append(SpecialEntry(path, "missing_checkout", "in git tree but not on disk"))
    return out


def git_log_patch(dest: Path, max_commits: int, max_bytes: int = 50_000_000) -> bytes:
    """Patch text of recent history (no external diff, no textconv). Only for repos we cloned."""
    try:
        proc = _git_in(
            dest,
            ["log", "-p", "--no-ext-diff", "--no-textconv", "--no-color", "--no-renames", "--format=commit %H",
             f"-n{max(1, max_commits)}"],
            timeout=300,
            max_stdout=max_bytes,
        )
    except (OSError, subprocess.TimeoutExpired):
        return b""
    return proc.stdout[:max_bytes]


def _on_rm_error(func, path, _exc) -> None:  # type: ignore[no-untyped-def]
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except OSError:
        pass


def cleanup(path: str | Path) -> bool:
    """Delete a repoguard temp dir. Refuses anything that isn't a `repoguard-*` dir under the temp root."""
    p = Path(path).resolve()
    tmp = Path(tempfile.gettempdir()).resolve()
    if not p.name.startswith(PREFIX) or p.parent != tmp or not p.is_dir() or p.is_symlink():
        return False
    shutil.rmtree(p, onexc=_on_rm_error)
    return not p.exists()


def clean_all() -> int:
    n = 0
    tmp = Path(tempfile.gettempdir())
    for d in tmp.glob(PREFIX + "*"):
        if cleanup(d):
            n += 1
    return n
