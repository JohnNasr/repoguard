"""Human-readable terminal report."""

from __future__ import annotations

import textwrap

from ..models import Report, Severity, Verdict, severity_counts
from .ansi import Painter

_SEV_STYLE = {
    Severity.CRITICAL: ("bold", "magenta"), Severity.HIGH: ("bold", "red"), Severity.MEDIUM: ("yellow",),
    Severity.LOW: ("cyan",), Severity.INFO: ("dim",),
}
_VERDICT_STYLE = {
    Verdict.SAFE: ("bg_green",), Verdict.CAUTION: ("bg_yellow",), Verdict.DANGEROUS: ("bg_red",),
    Verdict.BLOCK: ("bg_magenta", "bold"),
}
_ADVICE = {
    Verdict.SAFE: "No significant risks found by static analysis. Still review install scripts before running them.",
    Verdict.CAUTION: "Some risky patterns. Read the findings below before installing; prefer a VM/container.",
    Verdict.DANGEROUS: "Serious risks. Do not install or run unless you have verified every HIGH/CRITICAL finding.",
    Verdict.BLOCK: "Malicious patterns detected. Do NOT install, build, run or open this repo in an AI agent/IDE.",
}


def render(report: Report, *, color: bool = False, verbose: bool = False) -> str:
    p = Painter(color)
    r = report.result
    out: list[str] = []
    w = 78
    out.append(p("repoguard", "bold") + f" {report.tool_version}  " + p(r.target, "bold"))
    if r.commit:
        out.append(p(f"commit {r.commit[:12]}", "dim"))
    st = r.stats
    out.append(p(f"{st.files_scanned} files, {st.bytes_scanned / 1_000_000:.1f} MB, {st.duration_s:.1f}s"
                 + (" (network used)" if r.network_used else ""), "dim"))
    out.append("")

    counts = severity_counts(r.findings)
    if not r.findings:
        out.append(p("No findings at or above the selected severity.", "green"))
    current: Severity | None = None
    for f in r.findings:
        if f.severity != current:
            current = f.severity
            out.append("")
            out.append(p(f"== {current.label} ({counts[current.label]}) ", *_SEV_STYLE[current]) + p("=" * 40, "dim"))
        head = f"[{f.rule_id}] {f.title}"
        conf = p(f"conf:{f.confidence.label.lower()}", "dim")
        ctxk = p(f" ({f.context_kind})", "dim") if f.context_kind else ""
        out.append(f"  {p(head, *_SEV_STYLE[f.severity])}  {conf}{ctxk}")
        out.append(f"    {p(f.location, 'blue')}")
        if f.snippet:
            out.append(p("    > " + f.snippet, "dim"))
        if verbose or f.severity >= Severity.HIGH:
            for line in textwrap.wrap(f.description, w - 6):
                out.append("      " + line)
            if f.recommendation:
                out.append(p("      fix: ", "green") + f.recommendation)
    out.append("")
    if r.hidden_below_min_severity:
        out.append(p(f"{r.hidden_below_min_severity} lower-severity finding(s) hidden (use --min-severity info).", "dim"))
    if r.suppressed:
        out.append(p(f"{len(r.suppressed)} finding(s) suppressed by your ignore file/baseline.", "dim"))
    if r.errors:
        out.append(p(f"{len(r.errors)} scan error(s):", "yellow"))
        for e in r.errors[:5]:
            out.append(p("  - " + e, "yellow"))
    if r.kept_path:
        out.append(f"Clone kept at: {r.kept_path}  (delete with: repoguard clean \"{r.kept_path}\")")
    out.append("")
    summary = "  ".join(f"{k}:{v}" for k, v in counts.items() if v)
    out.append(p(f" VERDICT: {report.verdict} ", *_VERDICT_STYLE[report.verdict]) + f"  score {report.score}/100"
               + (f"   {summary}" if summary else ""))
    for reason in report.verdict_reasons:
        out.append(p("  - " + reason, "dim"))
    out.append(_ADVICE[report.verdict])
    if r.incomplete:
        out.append(p("Scan incomplete: some content was not checked.", "yellow"))
    return "\n".join(out) + "\n"
