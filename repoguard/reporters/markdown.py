"""Markdown report (for issues, PR comments, notes)."""

from __future__ import annotations

from ..models import Report, severity_counts


def _cell(s: str) -> str:
    return s.replace("|", "\\|").replace("`", "'").replace("\n", " ")


def render(report: Report) -> str:
    r = report.result
    lines = [
        f"# repoguard report: {report.verdict} ({report.score}/100)",
        "",
        f"- Target: `{_cell(r.target)}`" + (f" @ `{r.commit[:12]}`" if r.commit else ""),
        f"- Files scanned: {r.stats.files_scanned}; generated {report.generated_at}; repoguard {report.tool_version}",
        "",
        "## Why",
        *[f"- {_cell(x)}" for x in report.verdict_reasons],
        "",
        "## Counts",
        " | ".join(f"{k}: {v}" for k, v in severity_counts(r.findings).items()),
        "",
        "## Findings",
        "",
        "| Severity | Conf | Rule | Title | Location | Snippet |",
        "|---|---|---|---|---|---|",
    ]
    for f in r.findings:
        lines.append(f"| {f.severity.label} | {f.confidence.label} | {f.rule_id} | {_cell(f.title)} | "
                     f"`{_cell(f.location)}` | `{_cell(f.snippet[:120])}` |")
    if r.errors:
        lines += ["", "## Scan errors", *[f"- {_cell(e)}" for e in r.errors]]
    return "\n".join(lines) + "\n"
