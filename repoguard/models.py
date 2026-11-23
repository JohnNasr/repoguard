"""Core data model shared by every repoguard module."""

from __future__ import annotations

import dataclasses
import hashlib
from dataclasses import dataclass
from enum import IntEnum, StrEnum
from typing import Any, Protocol


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        return cls[value.strip().upper()]

    @property
    def label(self) -> str:
        return self.name.lower()


class Confidence(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @property
    def label(self) -> str:
        return self.name.lower()


class Category(StrEnum):
    SECRETS = "secrets"
    EXFILTRATION = "exfiltration"
    EXEC_HOOK = "exec_hook"
    AI_SURFACE = "ai_surface"
    OBFUSCATION = "obfuscation"
    MALWARE = "malware"
    BINARY = "binary"
    DEPENDENCY = "dependency"
    CICD = "cicd"
    REPUTATION = "reputation"
    FILESYSTEM = "filesystem"
    CORRELATION = "correlation"
    META = "meta"


class Verdict(StrEnum):
    SAFE = "SAFE"
    CAUTION = "CAUTION"
    DANGEROUS = "DANGEROUS"
    BLOCK = "BLOCK"

    @property
    def rank(self) -> int:
        return _VERDICT_RANK[self]


_VERDICT_RANK = {Verdict.SAFE: 0, Verdict.CAUTION: 1, Verdict.DANGEROUS: 2, Verdict.BLOCK: 3}


class RuleLike(Protocol):
    """Anything with rule metadata: rules.Rule, detector.RuleInfo, correlate.CorrelationRule."""

    id: str
    title: str
    severity: Severity
    confidence: Confidence
    category: Category
    description: str
    recommendation: str
    tags: frozenset[str]


class ContextLike(Protocol):
    rel_path: str

    @property
    def context_kind(self) -> str | None: ...


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    category: Category
    path: str  # repo-relative POSIX path; "" = repo level; "history:<sha>:<path>" for history
    line: int | None
    snippet: str  # sanitized, truncated, secrets masked
    description: str
    recommendation: str
    tags: tuple[str, ...] = ()
    related: tuple[str, ...] = ()  # fingerprints of findings this one was built from
    context_kind: str | None = None  # "test" | "doc" | "vendored" | None -> score dampening

    @property
    def fingerprint(self) -> str:
        """Line-independent id so baselines survive unrelated edits."""
        raw = f"{self.rule_id}\0{self.path}\0{' '.join(self.snippet.split())}"
        return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]

    @property
    def location(self) -> str:
        if not self.path:
            return "(repository)"
        return f"{self.path}:{self.line}" if self.line else self.path

    def replace(self, **changes: Any) -> "Finding":
        return dataclasses.replace(self, **changes)

    @classmethod
    def from_rule(
        cls,
        rule: RuleLike,
        ctx: ContextLike | None,
        line: int | None,
        raw_snippet: str,
        *,
        extra_tags: tuple[str, ...] = (),
        description: str | None = None,
        severity: Severity | None = None,
        confidence: Confidence | None = None,
        secret: str | None = None,
        path: str | None = None,
        title: str | None = None,
    ) -> "Finding":
        """Build a finding from rule metadata. `secret` is masked inside the snippet."""
        from .textutil import mask_secret, sanitize_snippet

        snippet = raw_snippet or ""
        if secret:
            snippet = snippet.replace(secret, mask_secret(secret))
        return cls(
            rule_id=rule.id,
            title=title or rule.title,
            severity=severity if severity is not None else rule.severity,
            confidence=confidence if confidence is not None else rule.confidence,
            category=rule.category,
            path=path if path is not None else (ctx.rel_path if ctx else ""),
            line=line,
            snippet=sanitize_snippet(snippet),
            description=description or rule.description,
            recommendation=rule.recommendation,
            tags=tuple(sorted(set(rule.tags) | set(extra_tags))),
            context_kind=ctx.context_kind if ctx else None,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.label,
            "confidence": self.confidence.label,
            "category": str(self.category),
            "path": self.path,
            "line": self.line,
            "snippet": self.snippet,
            "description": self.description,
            "recommendation": self.recommendation,
            "tags": list(self.tags),
            "related": list(self.related),
            "context_kind": self.context_kind,
            "fingerprint": self.fingerprint,
        }


@dataclass(frozen=True, slots=True)
class ScanOptions:
    max_file_size: int = 2_000_000
    max_total_bytes: int = 500_000_000
    max_files: int = 50_000
    max_depth: int = 64
    per_file_timeout: float = 2.0
    offline: bool = False
    history: bool = False
    history_depth: int = 300
    keep: bool = False
    ref: str | None = None
    min_severity: Severity = Severity.LOW
    ignore_files: tuple[str, ...] = ()
    trust_repo_ignore: bool = False
    baseline: str | None = None


@dataclass(frozen=True, slots=True)
class ScanStats:
    files_seen: int = 0
    files_scanned: int = 0
    bytes_scanned: int = 0
    skipped_oversize: int = 0
    skipped_binary: int = 0
    timeouts: int = 0
    duration_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass(frozen=True, slots=True)
class ScanResult:
    target: str
    root: str
    kept_path: str | None
    commit: str | None
    findings: tuple[Finding, ...]
    suppressed: tuple[Finding, ...]
    hidden_below_min_severity: int
    stats: ScanStats
    errors: tuple[str, ...]
    incomplete: bool
    network_used: bool


@dataclass(frozen=True, slots=True)
class Report:
    schema: str
    tool_version: str
    generated_at: str
    result: ScanResult
    score: int
    verdict: Verdict
    verdict_reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        r = self.result
        return {
            "schema": self.schema,
            "tool_version": self.tool_version,
            "generated_at": self.generated_at,
            "verdict": str(self.verdict),
            "score": self.score,
            "verdict_reasons": list(self.verdict_reasons),
            "target": r.target,
            "root": r.root,
            "kept_path": r.kept_path,
            "commit": r.commit,
            "incomplete": r.incomplete,
            "network_used": r.network_used,
            "stats": r.stats.to_dict(),
            "counts": severity_counts(r.findings),
            "findings": [f.to_dict() for f in r.findings],
            "suppressed": [f.to_dict() for f in r.suppressed],
            "hidden_below_min_severity": r.hidden_below_min_severity,
            "errors": list(r.errors),
        }


def severity_counts(findings: tuple[Finding, ...] | list[Finding]) -> dict[str, int]:
    counts = {s.label: 0 for s in sorted(Severity, reverse=True)}
    for f in findings:
        counts[f.severity.label] += 1
    return counts
