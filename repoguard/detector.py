"""Detector base class. A detector = declarative Rules + optional code checks."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import ClassVar

from .context import FileContext, RepoContext
from .models import Category, Confidence, Finding, Severity
from .rules import Rule, run_rules


@dataclass(frozen=True, slots=True)
class RuleInfo:
    """Metadata for a code-based (non-regex) check, so `repoguard rules` can list it."""

    id: str
    title: str
    severity: Severity
    confidence: Confidence
    category: Category
    description: str
    recommendation: str
    tags: frozenset[str] = frozenset()


class Detector:
    id: ClassVar[str] = ""
    name: ClassVar[str] = ""
    category: ClassVar[Category] = Category.META
    rules: ClassVar[tuple[Rule, ...]] = ()
    checks: ClassVar[tuple[RuleInfo, ...]] = ()
    needs_network: ClassVar[bool] = False  # scan_repo skipped with --offline

    def applies_to(self, ctx: FileContext) -> bool:
        return not ctx.is_binary

    def scan_file(self, ctx: FileContext) -> Iterable[Finding]:
        return run_rules(self.rules, ctx)

    def scan_repo(self, repo: RepoContext) -> Iterable[Finding]:
        return ()

    # helper for code-based checks
    @staticmethod
    def finding(
        info: RuleInfo | Rule,
        ctx: FileContext | None,
        line: int | None,
        snippet: str,
        **kw: object,
    ) -> Finding:
        return Finding.from_rule(info, ctx, line, snippet, **kw)  # type: ignore[arg-type]
