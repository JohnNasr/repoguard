"""Git history checks (opt-in with --history; remote clones only, so git never reads a hostile local config)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from . import fetch
from . import tags as T
from .context import FileContext
from .detector import Detector, RuleInfo
from .models import Category, Confidence, Finding, Severity

HIS001 = RuleInfo(
    "HIS001", "Secret in git history", Severity.MEDIUM, Confidence.MEDIUM, Category.SECRETS,
    "A credential was committed in an earlier revision. Removing it later does not help: anyone can read history.",
    "If this is your repo, revoke/rotate the key now; then purge history (git filter-repo) if needed.",
    frozenset({T.SECRET, T.HYGIENE}),
)
HIS002 = RuleInfo(
    "HIS002", "Suspicious code in history that is gone at HEAD", Severity.MEDIUM, Confidence.LOW, Category.MALWARE,
    "Malware-like code (exfiltration, obfuscation, malware behaviour) existed in recent commits but is no longer in "
    "the current files. This can be a cleaned-up incident, or a payload that is re-added in releases/tags.",
    "Check whether published packages/releases were built from the affected commits.",
    frozenset({T.EVASION}),
)
ALL = (HIS001, HIS002)
_THREAT = {Category.MALWARE, Category.EXFILTRATION, Category.OBFUSCATION}
_MAX_UNIT = 1_000_000
_MAX_UNITS = 5000


def _units(patch: bytes) -> Iterator[tuple[str, str, str]]:
    """Yield (sha, path, added_text) per file per commit."""
    sha = path = ""
    buf: list[str] = []
    size = 0

    def flush() -> tuple[str, str, str] | None:
        return (sha, path, "\n".join(buf)) if sha and path and buf else None

    for raw in patch.decode("utf-8", "replace").splitlines():
        if raw.startswith("commit ") or raw.startswith("diff --git "):
            u = flush()
            if u:
                yield u
            buf, size = [], 0
            if raw.startswith("commit "):
                sha, path = raw[7:].strip(), ""
            else:
                path = ""
            continue
        if raw.startswith("+++ "):
            p = raw[4:].strip()
            path = p[2:] if p.startswith("b/") else ("" if p == "/dev/null" else p)
            continue
        if raw.startswith("+") and size < _MAX_UNIT:
            buf.append(raw[1:])
            size += len(raw)
    u = flush()
    if u:
        yield u


def scan_history(dest: Path, max_commits: int, detectors: tuple[Detector, ...], head: list[Finding]) -> list[Finding]:
    patch = fetch.git_log_patch(dest, max_commits)
    if not patch:
        return []
    dets = [d for d in detectors if d.category == Category.SECRETS or d.category in _THREAT]
    head_keys = {(f.rule_id, f.snippet) for f in head}
    head_secrets = {f.snippet for f in head if f.category == Category.SECRETS}
    out: dict[tuple[str, str], Finding] = {}
    for n, (sha, path, text) in enumerate(_units(patch)):
        if n >= _MAX_UNITS:
            break
        ctx = FileContext.from_text(path, text)
        for det in dets:
            try:
                if not det.applies_to(ctx):
                    continue
                ctx.start_deadline(2.0)
                found = list(det.scan_file(ctx))
            except Exception:  # noqa: BLE001 - history is best effort
                continue
            for f in found:
                if f.severity <= Severity.INFO:
                    continue
                hpath = f"history:{sha[:12]}:{path}"
                if det.category == Category.SECRETS:
                    if f.snippet in head_secrets:
                        continue
                    key = ("HIS001", f.snippet)
                    if key not in out:
                        out[key] = Finding.from_rule(
                            HIS001, None, f.line, f.snippet, path=hpath, title=f"Secret in git history: {f.title}",
                            description=f"{HIS001.description} Original rule: {f.rule_id}.",
                        ).replace(snippet=f.snippet)
                elif (f.rule_id, f.snippet) not in head_keys and f.severity >= Severity.HIGH:
                    key = ("HIS002", f.rule_id + f.snippet)
                    if key not in out:
                        out[key] = Finding.from_rule(
                            HIS002, None, f.line, f.snippet, path=hpath, title=f"Removed from HEAD: {f.title}",
                            description=f"{HIS002.description} Original rule: {f.rule_id}.",
                        ).replace(snippet=f.snippet)
    return list(out.values())
