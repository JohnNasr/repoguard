"""SARIF 2.1.0 output (GitHub code scanning, VS Code SARIF viewer)."""

from __future__ import annotations

import json

from ..models import Report, Severity

_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note",
          Severity.INFO: "note"}
_SEC = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5", Severity.LOW: "3.0", Severity.INFO: "0.0"}


def render(report: Report) -> str:
    r = report.result
    rules: dict[str, dict] = {}
    results = []
    for f in r.findings:
        rules.setdefault(f.rule_id, {
            "id": f.rule_id,
            "name": f.rule_id,
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.description[:1000]},
            "help": {"text": f.recommendation or f.description[:500]},
            "properties": {"tags": ["security", str(f.category), *f.tags], "security-severity": _SEC[f.severity]},
        })
        res: dict = {
            "ruleId": f.rule_id,
            "level": _LEVEL[f.severity],
            "message": {"text": f"{f.title}: {f.snippet}"[:1000]},
            "partialFingerprints": {"repoguard/v1": f.fingerprint},
            "properties": {"severity": f.severity.label, "confidence": f.confidence.label},
        }
        if f.path and not f.path.startswith("history:"):
            loc: dict = {"artifactLocation": {"uri": f.path}}
            if f.line:
                loc["region"] = {"startLine": f.line}
            res["locations"] = [{"physicalLocation": loc}]
        results.append(res)
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "repoguard", "version": report.tool_version,
                                "informationUri": "https://example.invalid/repoguard", "rules": list(rules.values())}},
            "results": results,
            "properties": {"verdict": str(report.verdict), "score": report.score, "target": r.target},
        }],
    }
    return json.dumps(doc, indent=2) + "\n"
