"""Declarative regex rules and the runner that applies them safely to a file."""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from functools import lru_cache

from .context import FileContext
from .models import Category, Confidence, Finding, Severity
from .textutil import is_placeholder, shannon_entropy

MAX_UNIT = 4096  # longest line chunk a regex ever sees
UNIT_OVERLAP = 256
MULTILINE_CAP = 1_000_000
SNIPPET_PAD = 80


@dataclass(frozen=True, slots=True)
class Rule:
    """One regex-based detection. Detector modules are mostly lists of these."""

    id: str
    title: str
    pattern: str
    severity: Severity
    confidence: Confidence
    category: Category
    description: str
    recommendation: str
    tags: frozenset[str] = frozenset()
    keywords: tuple[str, ...] = ()  # lowercase literals; rule skipped unless one occurs in the file
    flags: int = 0
    file_globs: tuple[str, ...] = ()  # case-insensitive fnmatch on rel path OR basename; empty = all
    languages: frozenset[str] = frozenset()  # empty = all
    exclude_line: tuple[str, ...] = ()  # regexes on the whole line -> drop match
    exclude_match: tuple[str, ...] = ()  # regexes on the matched text -> drop match
    require_in_file: tuple[str, ...] = ()  # all must also match somewhere in the file
    secret_group: str | None = None  # named group: placeholder-checked, entropy-checked, masked
    min_entropy: float | None = None
    skip_tests: bool = False
    skip_docs: bool = False
    skip_vendored: bool = False
    multiline: bool = False  # run on whole text (capped) instead of per line
    validator: Callable[[re.Match[str], FileContext], bool] | None = None
    max_per_file: int = 5


@lru_cache(maxsize=8192)
def _compile(pattern: str, flags: int) -> re.Pattern[str]:
    return re.compile(pattern, flags)


def compiled(rule: Rule) -> re.Pattern[str]:
    return _compile(rule.pattern, rule.flags)


def _glob_ok(rule: Rule, ctx: FileContext) -> bool:
    if not rule.file_globs:
        return True
    base = ctx.basename.lower()
    for g in rule.file_globs:
        gl = g.lower()
        if fnmatch.fnmatchcase(ctx.rel_lower, gl) or fnmatch.fnmatchcase(base, gl):
            return True
    return False


def rule_applies(rule: Rule, ctx: FileContext) -> bool:
    if ctx.is_binary:
        return False
    if rule.skip_tests and ctx.is_test:
        return False
    if rule.skip_docs and ctx.is_doc:
        return False
    if rule.skip_vendored and ctx.is_vendored:
        return False
    if rule.languages and ctx.language not in rule.languages:
        return False
    if not _glob_ok(rule, ctx):
        return False
    if rule.keywords and not any(k in ctx.lower for k in rule.keywords):
        return False
    return True


def iter_scan_units(ctx: FileContext) -> Iterator[tuple[int, str]]:
    """(line_no, text). Long lines are chunked so no regex sees more than MAX_UNIT chars."""
    for i, line in enumerate(ctx.lines, 1):
        if len(line) <= MAX_UNIT:
            yield i, line
            continue
        step = MAX_UNIT - UNIT_OVERLAP
        for start in range(0, len(line), step):
            yield i, line[start : start + MAX_UNIT]


def _window(text: str, start: int, end: int) -> str:
    return text[max(0, start - SNIPPET_PAD) : end + SNIPPET_PAD]


def _accept(rule: Rule, m: re.Match[str], ctx: FileContext, line_text: str) -> tuple[bool, str | None]:
    matched = m.group(0)
    for pat in rule.exclude_match:
        if _compile(pat, re.I).search(matched):
            return False, None
    for pat in rule.exclude_line:
        if _compile(pat, re.I).search(line_text):
            return False, None
    secret: str | None = None
    if rule.secret_group:
        secret = m.group(rule.secret_group)
        if not secret or is_placeholder(secret):
            return False, None
        if rule.min_entropy is not None and shannon_entropy(secret) < rule.min_entropy:
            return False, None
    if rule.validator is not None and not rule.validator(m, ctx):
        return False, None
    return True, secret


def run_rules(rules: Iterable[Rule], ctx: FileContext) -> Iterator[Finding]:
    """Apply rules to one file. Cooperative deadline: stops early when ctx's budget is spent."""
    for rule in rules:
        if ctx.deadline_exceeded():
            return
        if not rule_applies(rule, ctx):
            continue
        if rule.require_in_file and not all(
            _compile(p, re.I | re.M).search(ctx.text[:MULTILINE_CAP]) for p in rule.require_in_file
        ):
            continue
        pat = compiled(rule)
        count = 0
        seen_lines: set[int] = set()
        if rule.multiline:
            text = ctx.text[:MULTILINE_CAP]
            for m in pat.finditer(text):
                line = ctx.line_of(m.start())
                if line in seen_lines:
                    continue
                ok, secret = _accept(rule, m, ctx, ctx.line_text(line))
                if not ok:
                    continue
                seen_lines.add(line)
                yield Finding.from_rule(rule, ctx, line, _window(text, m.start(), m.end()), secret=secret)
                count += 1
                if count >= rule.max_per_file:
                    break
            continue
        for n, (line_no, unit) in enumerate(iter_scan_units(ctx)):
            if n % 500 == 499 and ctx.deadline_exceeded():
                return
            if line_no in seen_lines:
                continue
            for m in pat.finditer(unit):
                ok, secret = _accept(rule, m, ctx, unit)
                if not ok:
                    continue
                seen_lines.add(line_no)
                yield Finding.from_rule(rule, ctx, line_no, _window(unit, m.start(), m.end()), secret=secret)
                count += 1
                break
            if count >= rule.max_per_file:
                break


# ---- static ReDoS lint --------------------------------------------------------------
_ADJ_UNBOUNDED = re.compile(r"(?:\.\*|\.\+)\??(?:\.\*|\.\+)")


def lint_pattern(pattern: str) -> list[str]:
    """Cheap static check for catastrophic-backtracking shapes such as (a+)+ and .*.*"""
    issues: list[str] = []
    if re.search(r"\((?:\?:)?[^()]*[+*]\)[+*]", pattern):
        issues.append("nested quantifier like (x+)+")
    if _ADJ_UNBOUNDED.search(pattern):
        issues.append("adjacent unbounded wildcards like .*.*")
    return issues
