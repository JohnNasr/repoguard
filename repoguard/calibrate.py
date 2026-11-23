"""Location-aware calibration applied to every finding before correlation and scoring.

Detectors judge one pattern at a time; this module applies the shared rules about *where* a pattern is:
- Prose files (.md/.rst/.txt...) do not execute. Text that merely describes an attack (changelogs, security docs,
  AGENTS.md) is capped at LOW/LOW. Exceptions: AI-instruction rules (AIX*, prose is exactly their attack surface),
  README pipe-to-shell (INS013), live exfil endpoints (EXF001-004) and leaked secrets (SEC*).
- Test files that exercise Unicode-trick handling contain bidi/invisible characters on purpose.
- Low-confidence-ish malware patterns in tests are usually test strings.
"""

from __future__ import annotations

import re

from . import tags as T
from .models import Confidence, Finding, Severity

PROSE_EXT = (".md", ".markdown", ".rst", ".txt", ".adoc", ".org")
_PROSE_DEMOTE = ("MAL", "OBF", "CRD", "CIX", "INS", "EXF", "PHI", "COR")
_PROSE_KEEP = frozenset({"INS013", "EXF001", "EXF002", "EXF003", "EXF004"})
_TEST_UNICODE = frozenset({"AIX006", "AIX007", "AIX008"})
_CHANGELOG_RE = re.compile(r"(?i)(?:^|/)(?:changelog|changes|history|news|release[-_ ]?notes)[^/]*$")


def is_prose(path: str) -> bool:
    return path.lower().endswith(PROSE_EXT)


def _cap(f: Finding, sev: Severity, conf: Confidence, note: str) -> Finding:
    new_sev = min(f.severity, sev)
    new_conf = min(f.confidence, conf)
    tags = tuple(t for t in f.tags if t not in (T.BLOCK_TRIGGER, T.NO_DAMPEN))
    if new_sev == f.severity and new_conf == f.confidence and tags == f.tags:
        return f
    return f.replace(severity=new_sev, confidence=new_conf, tags=tags, description=f"{f.description} {note}")


def calibrate(f: Finding) -> Finding:
    if not f.path or f.path.startswith("history:"):
        return f
    rid = f.rule_id
    if is_prose(f.path) and rid.startswith(_PROSE_DEMOTE) and (rid not in _PROSE_KEEP or _CHANGELOG_RE.search(f.path)):
        return _cap(f, Severity.LOW, Confidence.LOW, "(Found in documentation text, which does not execute.)")
    if f.context_kind == "test":
        if rid in _TEST_UNICODE:
            f = _cap(f, Severity.MEDIUM, Confidence.LOW,
                     "(In a test file: likely a test of Unicode handling - check it is inside a string literal.)")
        elif rid.startswith("MAL") and f.confidence <= Confidence.MEDIUM:
            f = _cap(f, Severity.MEDIUM, Confidence.LOW, "(In a test file: probably a test string.)")
        if f.confidence == Confidence.LOW and not rid.startswith(("SEC", "COR")):
            f = _cap(f, Severity.LOW, Confidence.LOW, "(Low-confidence match inside a test file.)")
    return f


def calibrate_all(findings: list[Finding]) -> list[Finding]:
    return [calibrate(f) for f in findings]
