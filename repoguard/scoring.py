"""Risk score (0-100) and verdict.

points(finding) = S[severity] * C[confidence] * L[location]
per rule        = max + 0.25 * sum(others), capped at 1.5 * max
per category    = noisy-OR of rule scores, capped at 35 unless the category has a HIGH+/high-confidence
                  finding or is a correlation
hygiene         = findings tagged HYGIENE (leaked keys, CVEs, CI misconfig) add at most 10 points
low signal      = LOW-severity findings outside correlations add at most 10 points together, so a pile of
                  'worth knowing' notes cannot by itself make a repo DANGEROUS
total           = noisy-OR across categories
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from . import tags as T
from .models import Category, Confidence, Finding, Severity, Verdict

S = {Severity.CRITICAL: 40.0, Severity.HIGH: 20.0, Severity.MEDIUM: 8.0, Severity.LOW: 2.0, Severity.INFO: 0.0}
C = {Confidence.HIGH: 1.0, Confidence.MEDIUM: 0.7, Confidence.LOW: 0.4}
L_EXEC, L_NORMAL, L_VENDORED, L_TESTDOC = 1.5, 1.0, 0.8, 0.5
CATEGORY_CAP = 35.0
HYGIENE_CAP = 10.0
LOW_SIGNAL_CAP = 10.0
THRESHOLDS = ((70, Verdict.BLOCK), (40, Verdict.DANGEROUS), (15, Verdict.CAUTION), (0, Verdict.SAFE))
_HIGH_SIGNAL_RULES = {"OBF001", "OBF002", "OBF003", "OBF004", "AIX006", "AIX008"}
_HIGH_SIGNAL_CATS = {Category.EXFILTRATION, Category.MALWARE, Category.CORRELATION}


def _loc(f: Finding, exec_paths: frozenset[str]) -> float:
    if f.path in exec_paths:
        return L_EXEC
    if f.context_kind in ("test", "doc"):
        mult = L_TESTDOC
    elif f.context_kind == "vendored":
        mult = L_VENDORED
    else:
        mult = L_NORMAL
    if mult < 1.0 and (T.NO_DAMPEN in f.tags or f.rule_id in _HIGH_SIGNAL_RULES or f.category in _HIGH_SIGNAL_CATS):
        mult = 1.0
    return mult


def points(f: Finding, exec_paths: frozenset[str] = frozenset()) -> float:
    return S[f.severity] * C[f.confidence] * _loc(f, exec_paths)


def _noisy_or(values: Iterable[float]) -> float:
    keep = 1.0
    for v in values:
        keep *= 1.0 - min(max(v, 0.0), 100.0) / 100.0
    return 100.0 * (1.0 - keep)


def _group_score(findings: list[Finding], exec_paths: frozenset[str]) -> float:
    per_rule: dict[str, list[float]] = defaultdict(list)
    for f in findings:
        per_rule[f.rule_id].append(points(f, exec_paths))
    rule_scores = []
    for pts in per_rule.values():
        pts.sort(reverse=True)
        top = pts[0]
        rule_scores.append(min(top + 0.25 * sum(pts[1:]), 1.5 * top))
    return _noisy_or(rule_scores)


def category_scores(findings: Iterable[Finding], exec_paths: frozenset[str] = frozenset()) -> dict[str, float]:
    threat: dict[Category, list[Finding]] = defaultdict(list)
    hygiene: list[Finding] = []
    low: list[Finding] = []
    for f in findings:
        if f.category == Category.META and f.severity <= Severity.LOW:
            continue
        if T.HYGIENE in f.tags:
            hygiene.append(f)
        elif f.severity <= Severity.LOW and f.category != Category.CORRELATION:
            low.append(f)
        else:
            threat[f.category].append(f)
    out: dict[str, float] = {}
    for cat, fs in threat.items():
        score = _group_score(fs, exec_paths)
        strong = cat == Category.CORRELATION or any(
            f.severity >= Severity.HIGH and f.confidence == Confidence.HIGH for f in fs
        )
        out[str(cat)] = score if strong else min(score, CATEGORY_CAP)
    if hygiene:
        out["hygiene"] = min(_group_score(hygiene, exec_paths), HYGIENE_CAP)
    if low:
        out["low_signal"] = min(_group_score(low, exec_paths), LOW_SIGNAL_CAP)
    return out


def score(findings: Iterable[Finding], exec_paths: frozenset[str] = frozenset()) -> int:
    return int(round(_noisy_or(category_scores(findings, exec_paths).values())))


def verdict_for(total: int) -> Verdict:
    for th, v in THRESHOLDS:
        if total >= th:
            return v
    return Verdict.SAFE


def decide(
    findings: list[Finding],
    exec_paths: frozenset[str] = frozenset(),
    *,
    incomplete: bool = False,
    offline: bool = False,
    network_skipped: bool = False,
) -> tuple[int, Verdict, list[str]]:
    total = score(findings, exec_paths)
    verdict = verdict_for(total)
    reasons = [f"risk score {total}/100 -> {verdict}"]

    def floor(v: Verdict, why: str) -> None:
        nonlocal verdict
        if v.rank > verdict.rank:
            verdict = v
            reasons.append(why)

    triggers = [f for f in findings if T.BLOCK_TRIGGER in f.tags and f.confidence >= Confidence.MEDIUM]
    hard = [f for f in triggers if f.context_kind not in ("test", "doc")]
    if hard:
        floor(Verdict.BLOCK, f"hard block: {hard[0].rule_id} {hard[0].title} ({hard[0].location})")
    elif triggers:
        floor(Verdict.DANGEROUS, f"block-level pattern in test/doc file: {triggers[0].rule_id} ({triggers[0].location})")
    crit = [f for f in findings if f.severity == Severity.CRITICAL and f.confidence == Confidence.HIGH
            and f.context_kind not in ("test", "doc") and T.HYGIENE not in f.tags]
    if crit:
        floor(Verdict.DANGEROUS, f"high-confidence critical finding: {crit[0].rule_id} ({crit[0].location})")
    if incomplete:
        floor(Verdict.CAUTION, "scan incomplete (limits, timeouts or crashes) - cannot vouch for unscanned parts")
    if offline or network_skipped:
        reasons.append("reputation and OSV (known-malicious/vulnerable package) checks were not run")
    return total, verdict, reasons
