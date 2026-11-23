"""Auto-discovers detector modules and validates every rule they declare."""

from __future__ import annotations

import importlib
import pkgutil
import re
from functools import lru_cache

from . import meta, tags
from .detector import Detector, RuleInfo
from .rules import Rule, compiled, lint_pattern

RULE_ID_RE = re.compile(r"^[A-Z]{2,4}\d{3}$")


class RegistryError(RuntimeError):
    pass


@lru_cache(maxsize=4)
def discover(package: str = "repoguard.detectors") -> tuple[Detector, ...]:
    """Import every non-underscore module in the package; each exports DETECTORS = (cls, ...)."""
    pkg = importlib.import_module(package)
    found: list[Detector] = []
    for mod_info in sorted(pkgutil.iter_modules(pkg.__path__), key=lambda m: m.name):
        if mod_info.name.startswith("_"):
            continue
        module = importlib.import_module(f"{package}.{mod_info.name}")
        for cls in getattr(module, "DETECTORS", ()):
            found.append(cls())
    validate(found)
    return tuple(found)


def validate(detectors: list[Detector]) -> None:
    det_ids: set[str] = set()
    rule_ids: set[str] = {m.id for m in meta.ALL}
    errors: list[str] = []
    for det in detectors:
        if not det.id or det.id in det_ids:
            errors.append(f"detector id missing or duplicated: {det.id!r} ({type(det).__name__})")
        det_ids.add(det.id)
        items: list[Rule | RuleInfo] = [*det.rules, *det.checks]
        for r in items:
            if not RULE_ID_RE.match(r.id):
                errors.append(f"bad rule id format: {r.id}")
            if r.id in rule_ids:
                errors.append(f"duplicate rule id: {r.id}")
            rule_ids.add(r.id)
            unknown = set(r.tags) - tags.ALL
            if unknown:
                errors.append(f"{r.id}: unknown tags {sorted(unknown)}")
            if isinstance(r, Rule):
                try:
                    compiled(r)
                except re.error as exc:
                    errors.append(f"{r.id}: regex does not compile: {exc}")
                for issue in lint_pattern(r.pattern):
                    errors.append(f"{r.id}: ReDoS risk: {issue}")
                if any(k != k.lower() for k in r.keywords):
                    errors.append(f"{r.id}: keywords must be lowercase")
    if errors:
        raise RegistryError("Invalid detector rules:\n  " + "\n  ".join(errors))


def all_rules() -> dict[str, Rule | RuleInfo]:
    from .correlate import CORRELATIONS

    out: dict[str, Rule | RuleInfo] = {}
    for det in discover():
        for r in (*det.rules, *det.checks):
            out[r.id] = r
    for c in CORRELATIONS:
        out[c.id] = c  # type: ignore[assignment]
    for m in meta.ALL:
        out[m.id] = m
    from . import history

    for h in history.ALL:
        out[h.id] = h
    return dict(sorted(out.items()))


def get_rule(rule_id: str) -> Rule | RuleInfo | None:
    return all_rules().get(rule_id.upper())
