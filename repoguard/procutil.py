"""Safe subprocess wrapper: absolute exe path, explicit cwd outside the target, timeout, no shell."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path

if sys.platform == "win32":
    # Stop Windows from resolving executables in the current directory (a planted git.exe).
    os.environ["NoDefaultCurrentDirectoryInExePath"] = "1"


class ToolMissing(RuntimeError):
    pass


def resolve(exe: str) -> str:
    found = shutil.which(exe, path=os.environ.get("PATH", os.defpath))
    if not found:
        raise ToolMissing(f"'{exe}' not found on PATH")
    path = Path(found).resolve()
    if not path.is_absolute():
        raise ToolMissing(f"refusing relative executable path for {exe}")
    return str(path)


def safe_cwd() -> str:
    return str(Path.home())


def _kill_tree(proc: subprocess.Popen[bytes]) -> None:
    """Kill the process and its children (git spawns git-remote-https, which keeps the pipes open)."""
    if sys.platform == "win32":
        try:
            subprocess.run(  # noqa: S603
                [resolve("taskkill"), "/T", "/F", "/PID", str(proc.pid)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15, check=False,
            )
        except (ToolMissing, OSError, subprocess.TimeoutExpired):
            pass
    try:
        proc.kill()
    except OSError:
        pass


def _drain(proc: subprocess.Popen[bytes]) -> None:
    """Close pipes after a kill without waiting forever on grandchildren that still hold them."""
    for pipe in (proc.stdin, proc.stdout, proc.stderr):
        try:
            if pipe:
                pipe.close()
        except OSError:
            pass
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        pass


def run(
    argv: list[str],
    *,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    timeout: float = 120,
    input_bytes: bytes | None = None,
    max_stdout: int | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Run without a shell. On timeout the whole process tree is killed and TimeoutExpired is raised.
    Stdout is read in chunks; with max_stdout the process is killed once that many bytes have arrived."""
    exe = resolve(argv[0])
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    proc = subprocess.Popen(  # noqa: S603 - argv list, no shell
        [exe, *argv[1:]],
        cwd=cwd or safe_cwd(),
        env=full_env,
        stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    cap = max_stdout if max_stdout is not None else 1 << 62
    chunks: list[bytes] = []
    errbuf: list[bytes] = []
    got = [0]

    def _read_out() -> None:
        assert proc.stdout is not None
        try:
            while True:
                block = proc.stdout.read1(65536) if hasattr(proc.stdout, "read1") else proc.stdout.read(65536)
                if not block:
                    return
                room = cap - got[0]
                chunks.append(block[:room])
                got[0] += min(len(block), room)
                if got[0] >= cap:
                    _kill_tree(proc)
                    return
        except (OSError, ValueError):
            return

    def _read_err() -> None:
        assert proc.stderr is not None
        try:
            while True:
                block = proc.stderr.read(65536)
                if not block:
                    return
                if sum(map(len, errbuf)) < 1_000_000:
                    errbuf.append(block)
        except (OSError, ValueError):
            return

    t_out = threading.Thread(target=_read_out, daemon=True)
    t_err = threading.Thread(target=_read_err, daemon=True)
    t_out.start()
    t_err.start()
    if input_bytes is not None and proc.stdin is not None:
        try:
            proc.stdin.write(input_bytes)
            proc.stdin.close()
        except OSError:
            pass
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        if got[0] < cap:
            _kill_tree(proc)
            _drain(proc)
            raise
    t_out.join(10)
    t_err.join(2)
    rc = proc.returncode if proc.returncode is not None else -9
    return subprocess.CompletedProcess(proc.args, rc, b"".join(chunks), b"".join(errbuf))
