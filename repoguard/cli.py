"""Command line interface.

Exit codes: 0 verdict below --fail-on | 1 CAUTION | 2 DANGEROUS | 3 BLOCK (when at/above --fail-on)
            4 bad input / clone failed | 5 internal error
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from pathlib import Path

from . import __version__, fetch
from .models import Category, ScanOptions, Severity, Verdict

EXIT_USAGE, EXIT_INTERNAL = 4, 5
_FAIL_ON = {"never": 99, "caution": 1, "dangerous": 2, "block": 3}


def _size(text: str) -> int:
    t = text.strip().lower()
    mult = 1
    for suffix, m in (("kb", 1_000), ("mb", 1_000_000), ("gb", 1_000_000_000), ("k", 1_000), ("m", 1_000_000), ("g", 1_000_000_000)):
        if t.endswith(suffix):
            t, mult = t[: -len(suffix)], m
            break
    return int(float(t) * mult)


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="repoguard", description="Check a repository for malware, credential theft, "
                                 "API-key phishing, secrets and risky install hooks BEFORE you install it. "
                                 "Static only: nothing from the repo is ever executed.")
    ap.add_argument("--version", action="version", version=f"repoguard {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan a GitHub URL, owner/repo, https git URL or local folder")
    s.add_argument("target")
    s.add_argument("-f", "--format", choices=("terminal", "json", "sarif", "markdown"), default="terminal")
    s.add_argument("-o", "--output", help="write the report to this file instead of stdout")
    s.add_argument("--offline", action="store_true", help="no network lookups (OSV, GitHub reputation)")
    s.add_argument("--history", action="store_true", help="also scan recent git history (remote URLs only)")
    s.add_argument("--history-depth", type=int, default=300, metavar="N")
    s.add_argument("--ref", help="branch or tag to clone")
    s.add_argument("--keep", action="store_true", help="keep the temporary clone for manual review")
    s.add_argument("--min-severity", default="low", choices=[x.label.lower() for x in Severity])
    s.add_argument("--fail-on", default="dangerous", choices=list(_FAIL_ON))
    s.add_argument("--ignore-file", action="append", default=[], metavar="PATH",
                   help="your own suppression file (files inside the scanned repo are refused)")
    s.add_argument("--trust-repo-ignore", action="store_true", help="honour the repo's .repoguardignore (own projects only)")
    s.add_argument("--baseline", metavar="JSON", help="hide findings present in this earlier JSON report")
    s.add_argument("--write-baseline", metavar="JSON", help="write current finding fingerprints to this file")
    s.add_argument("--max-file-size", type=_size, default=2_000_000)
    s.add_argument("--max-total-bytes", type=_size, default=500_000_000)
    s.add_argument("--max-files", type=int, default=50_000)
    s.add_argument("--timeout-per-file", type=float, default=2.0)
    s.add_argument("--no-color", action="store_true")
    s.add_argument("-v", "--verbose", action="store_true", help="show descriptions and fixes for every finding")
    s.add_argument("-q", "--quiet", action="store_true", help="no progress messages")

    r = sub.add_parser("rules", help="list all detection rules")
    r.add_argument("--category", choices=[str(c) for c in Category])
    r.add_argument("--json", action="store_true")

    e = sub.add_parser("explain", help="explain one rule id, e.g. COR001")
    e.add_argument("rule_id")

    c = sub.add_parser("clean", help="delete repoguard temp clones (all, or one path printed by --keep)")
    c.add_argument("path", nargs="?")

    i = sub.add_parser("install-agent", help="install the Claude Code subagent into ~/.claude/agents")
    i.add_argument("--dest", default=str(Path.home() / ".claude" / "agents"))
    i.add_argument("--force", action="store_true", help="overwrite without keeping a .bak copy")

    sub.add_parser("version", help="print version and environment checks")
    return ap


def _progress(quiet: bool):  # type: ignore[no-untyped-def]
    if quiet:
        return None
    t0 = time.monotonic()
    return lambda msg: print(f"[{time.monotonic() - t0:5.1f}s] {msg}", file=sys.stderr, flush=True)


def cmd_scan(a: argparse.Namespace) -> int:
    from .engine import ScanError, scan
    from .reporters import render
    from .reporters.ansi import supports_color

    opts = ScanOptions(
        max_file_size=a.max_file_size, max_total_bytes=a.max_total_bytes, max_files=a.max_files,
        per_file_timeout=a.timeout_per_file, offline=a.offline, history=a.history, history_depth=a.history_depth,
        keep=a.keep, ref=a.ref, min_severity=Severity.parse(a.min_severity), ignore_files=tuple(a.ignore_file),
        trust_repo_ignore=a.trust_repo_ignore, baseline=a.baseline,
    )
    try:
        report = scan(a.target, opts, progress=_progress(a.quiet or a.format != "terminal" and not a.output))
    except ScanError as exc:
        print(f"repoguard: {exc}", file=sys.stderr)
        return EXIT_USAGE
    color = a.format == "terminal" and not a.output and not a.no_color and supports_color(sys.stdout)
    text = render(report, a.format, color=color, verbose=a.verbose)
    if a.output:
        Path(a.output).write_text(text, encoding="utf-8")
        print(f"report written to {a.output}  (verdict {report.verdict}, score {report.score})", file=sys.stderr)
    else:
        sys.stdout.write(text)
    if a.write_baseline:
        from .suppress import write_baseline

        write_baseline(a.write_baseline, list(report.result.findings))
    rank = report.verdict.rank
    return rank if rank >= _FAIL_ON[a.fail_on] else 0


def cmd_rules(a: argparse.Namespace) -> int:
    from .registry import all_rules

    rows = [r for r in all_rules().values() if not a.category or str(r.category) == a.category]
    if a.json:
        print(json.dumps([{"id": r.id, "title": r.title, "severity": r.severity.label, "confidence": r.confidence.label,
                           "category": str(r.category), "tags": sorted(r.tags)} for r in rows], indent=2))
        return 0
    for r in rows:
        print(f"{r.id:<8} {r.severity.label:<8} {str(r.category):<12} {r.title}")
    print(f"\n{len(rows)} rules")
    return 0


def cmd_explain(a: argparse.Namespace) -> int:
    from .registry import get_rule

    r = get_rule(a.rule_id)
    if r is None:
        print(f"unknown rule id: {a.rule_id}", file=sys.stderr)
        return EXIT_USAGE
    print(f"{r.id}  {r.title}\nseverity {r.severity.label}, confidence {r.confidence.label}, category {r.category}")
    if r.tags:
        print("tags: " + ", ".join(sorted(r.tags)))
    print(f"\n{r.description}\n\nWhat to do: {r.recommendation}")
    pattern = getattr(r, "pattern", None)
    if pattern:
        print(f"\nPattern: {pattern}")
    return 0


def cmd_clean(a: argparse.Namespace) -> int:
    if a.path:
        ok = fetch.cleanup(a.path)
        print("deleted" if ok else "refused: not a repoguard temp folder (or already gone)")
        return 0 if ok else EXIT_USAGE
    print(f"deleted {fetch.clean_all()} repoguard temp folder(s)")
    return 0


def cmd_install_agent(a: argparse.Namespace) -> int:
    src = Path(__file__).resolve().parent.parent / "agent" / "repoguard.md"
    if not src.is_file():
        print(f"agent file not found: {src}", file=sys.stderr)
        return EXIT_USAGE
    project = str(src.parent.parent)
    text = src.read_text(encoding="utf-8").replace("{{REPOGUARD_HOME}}", project.replace("\\", "/"))
    dest_dir = Path(a.dest).expanduser()
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / "repoguard.md"
    if dest.exists() and not a.force:
        if dest.read_text(encoding="utf-8", errors="replace") == text:
            print(f"already up to date: {dest}")
            return 0
        bak = dest.with_suffix(".md.bak")
        shutil.copy2(dest, bak)
        print(f"backed up existing agent to {bak}")
    dest.write_text(text, encoding="utf-8")
    print(f"installed Claude Code agent: {dest}\nUse it in Claude Code: \"use the repoguard agent to check <repo url>\"")
    return 0


def cmd_version(_: argparse.Namespace) -> int:
    v = fetch.git_version()
    print(f"repoguard {__version__}  python {sys.version.split()[0]}")
    if v is None:
        print("git: NOT FOUND (needed for remote URLs; local folders still work)")
    else:
        ok = v >= fetch.MIN_GIT
        print(f"git: {'.'.join(map(str, v))}" + ("" if ok else "  (older than 2.45.1 - please update before cloning untrusted repos)"))
    print("gh: " + ("found" if shutil.which("gh") else "not found (GitHub reputation checks need `gh auth login`)"))
    return 0


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass
    a = _parser().parse_args(argv)
    handlers = {"scan": cmd_scan, "rules": cmd_rules, "explain": cmd_explain, "clean": cmd_clean,
                "install-agent": cmd_install_agent, "version": cmd_version}
    try:
        return handlers[a.cmd](a)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001
        print(f"repoguard internal error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_INTERNAL


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["main", "Verdict"]
