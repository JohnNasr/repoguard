"""User-controlled suppressions and baselines.

A scanned repository can NEVER silence the scanner: in-repo ignore files and inline markers are reported
(META010) and ignored. Suppressions come only from files outside the target (--ignore-file, the user config
file) or, for your own projects, the repo's file with --trust-repo-ignore. CRITICAL findings and hard-block
findings are never suppressed.

Ignore file format (one per line, `#` comments):
    SEC016                      rule everywhere
    SEC016 tests/**             rule in matching paths (fnmatch, case-insensitive)
    * docs/**                   every rule in matching paths
    fp:<sha256 fingerprint>     one exact finding
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

from . import tags as T
from .models import Finding, Severity

REPO_IGNORE_NAMES = (".repoguardignore", ".repoguard.toml", ".repoguard.yml", ".repoguard.yaml", ".repoguard.json")
INLINE_RE = re.compile(r"repoguard\s*:\s*(?:ignore|disable|skip|safe)", re.I)


def user_ignore_path() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "repoguard" / "ignore"


@dataclass(frozen=True)
class IgnoreEntry:
    rule: str  # rule id or "*"
    glob: str | None = None
    fingerprint: str | None = None

    def matches(self, f: Finding) -> bool:
        if self.fingerprint:
            return f.fingerprint == self.fingerprint
        if self.rule != "*" and self.rule != f.rule_id:
            return False
        return self.glob is None or fnmatch.fnmatchcase(f.path.lower(), self.glob.lower())


def parse_ignore(text: str) -> list[IgnoreEntry]:
    out: list[IgnoreEntry] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.lower().startswith("fp:"):
            out.append(IgnoreEntry("*", fingerprint=line[3:].strip().lower()))
            continue
        parts = line.split(None, 1)
        out.append(IgnoreEntry(parts[0].upper() if parts[0] != "*" else "*", parts[1].strip() if len(parts) > 1 else None))
    return out


def load_entries(paths: list[Path]) -> list[IgnoreEntry]:
    entries: list[IgnoreEntry] = []
    for p in paths:
        try:
            entries += parse_ignore(p.read_text(encoding="utf-8", errors="replace")[:1_000_000])
        except OSError:
            continue
    return entries


def suppressible(f: Finding) -> bool:
    return f.severity < Severity.CRITICAL and T.BLOCK_TRIGGER not in f.tags


def apply(findings: list[Finding], entries: list[IgnoreEntry], baseline: set[str]) -> tuple[list[Finding], list[Finding]]:
    kept: list[Finding] = []
    dropped: list[Finding] = []
    for f in findings:
        if suppressible(f) and (f.fingerprint in baseline or any(e.matches(f) for e in entries)):
            dropped.append(f)
        else:
            kept.append(f)
    return kept, dropped


def load_baseline(path: str | None) -> set[str]:
    """A baseline is a previous `--format json` report or a plain list of fingerprints."""
    if not path:
        return set()
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    if isinstance(data, dict):
        data = data.get("findings", [])
    fps: set[str] = set()
    for item in data if isinstance(data, list) else []:
        if isinstance(item, str):
            fps.add(item)
        elif isinstance(item, dict) and isinstance(item.get("fingerprint"), str):
            fps.add(item["fingerprint"])
    return fps


def write_baseline(path: str, findings: list[Finding]) -> None:
    Path(path).write_text(json.dumps(sorted({f.fingerprint for f in findings}), indent=2), encoding="utf-8")
