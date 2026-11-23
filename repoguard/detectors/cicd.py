"""CIX001-CIX007: CI/CD workflow risks. YAML is read with line/regex logic only (no PyYAML)."""

from __future__ import annotations

import re
from collections.abc import Iterable

from .. import tags as T
from ..context import FileContext
from ..detector import Detector, RuleInfo
from ..models import Category, Confidence, Finding, Severity
from .exec_hooks import URL_HOST, Pat, lower_conf, pipe_shell_pats, scan_pats

S = Severity
C = Confidence
_CAT = Category.CICD
_H = frozenset({T.CI_RISK, T.HYGIENE})


def _ri(rid: str, title: str, sev: Severity, conf: Confidence, desc: str, rec: str, tags: frozenset[str]) -> RuleInfo:
    return RuleInfo(rid, title, sev, conf, _CAT, desc, rec, tags)


CIX001 = _ri("CIX001", "Pwn request: privileged trigger checks out PR code", S.MEDIUM, C.HIGH,
             "A pull_request_target/workflow_run workflow checks out the untrusted pull-request head. PR code then runs with repository secrets and a write token.",
             "Do not check out PR head code in privileged workflows, or split into an unprivileged pull_request job.", _H)
CIX002 = _ri("CIX002", "Script injection from untrusted GitHub context", S.MEDIUM, C.HIGH,
             "A run/script step interpolates attacker-controlled github.event fields (title, body, branch name...) directly into shell code.",
             "Pass the value through an env: variable and quote it in the script.", _H)
CIX003 = _ri("CIX003", "Workflow exfiltrates secrets", S.HIGH, C.HIGH,
             "A CI step serialises, encodes or sends repository secrets to an external host, or reads runner process memory.",
             "Treat as malicious: remove the step and rotate every secret the workflow can reach.",
             frozenset({T.CI_RISK}))
CIX004 = _ri("CIX004", "Third-party action not pinned to a commit SHA", S.LOW, C.HIGH,
             "A third-party action is referenced by a mutable tag/branch; the owner (or an attacker who compromises them) can change the code that runs with your secrets.",
             "Pin third-party actions to a full 40-character commit SHA.", _H)
CIX005 = _ri("CIX005", "Self-hosted runner", S.LOW, C.MEDIUM,
             "The workflow runs on a self-hosted runner; untrusted jobs can persist on that machine.",
             "Use ephemeral runners and never run fork PRs on self-hosted runners.", _H)
CIX006 = _ri("CIX006", "Broad workflow permissions", S.LOW, C.MEDIUM,
             "The workflow grants write-all or contents: write (on PR triggers), widening the blast radius of any compromise.",
             "Grant the minimum permissions per job.", _H)
CIX007 = _ri("CIX007", "CI pipes a remote script to a shell", S.MEDIUM, C.MEDIUM,
             "A CI job downloads a script and runs it immediately; whoever controls that URL controls your pipeline and secrets.",
             "Download, verify a checksum/signature, then run.", _H)

_COMPROMISED = frozenset({
    "tj-actions/changed-files", "tj-actions/verify-changed-files", "tj-actions/eslint-changed-files",
    "reviewdog/action-setup", "reviewdog/action-shellcheck", "reviewdog/action-composite-template",
    "reviewdog/action-staticcheck", "reviewdog/action-ast-grep", "reviewdog/action-typos",
})
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_USES_RE = re.compile(r"^\s*(?:-\s+)?uses:\s*[\"']?([^\s\"'#@]+)(?:@([^\s\"'#]+))?")
_RUN_KEY = re.compile(r"^(\s*)(?:-\s+)?(run|script|before_script|after_script|inline_script|command)\s*:\s*(.*)$")
_LIST_ITEM = re.compile(r"^(\s*)-\s")
_TRIGGER_RE = re.compile(r"\b(pull_request_target|workflow_run)\b")
_PR_TRIGGER_RE = re.compile(r"^\s*(?:on:\s*)?[\[\-]?[^#\n]{0,80}\bpull_request(?:_target)?\b")
_NET_CMD = re.compile(r"\b(?:curl|wget|nc|ncat|netcat|invoke-webrequest|invoke-restmethod|iwr|irm)\b", re.I)
_GH_HOSTS = ("github.com", "githubusercontent.com", "ghcr.io", "localhost", "127.0.0.1", "0.0.0.0", "github.io")


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _not_comment(_n: int, unit: str) -> bool:
    return not unit.lstrip().startswith("#")


def _run_lines(lines: tuple[str, ...]) -> set[int]:
    """1-based line numbers that belong to run:/script: bodies."""
    out: set[int] = set()
    i, n = 0, len(lines)
    while i < n:
        m = _RUN_KEY.match(lines[i])
        if not m:
            i += 1
            continue
        col = m.start(2)
        rest = m.group(3).strip()
        out.add(i + 1)
        i += 1
        if rest and not rest.startswith(("|", ">")):
            continue
        while i < n:
            ln = lines[i]
            if ln.strip() and _indent(ln) <= col:
                break
            out.add(i + 1)
            i += 1
    return out


def _step_range(lines: tuple[str, ...], idx: int) -> tuple[int, int]:
    """0-based [start, end) of the YAML list item (step) containing line idx."""
    ind = _indent(lines[idx])
    start, dash = idx, -1
    for j in range(idx, -1, -1):
        m = _LIST_ITEM.match(lines[j])
        if m and (len(m.group(1)) < ind or j == idx):
            start, dash = j, len(m.group(1))
            break
    if dash < 0:
        return idx, idx + 1
    end = start + 1
    while end < len(lines):
        ln = lines[end]
        if ln.strip() and not ln.lstrip().startswith("#") and _indent(ln) <= dash:
            break
        end += 1
    return start, end


def _external(hosts: Iterable[str]) -> list[str]:
    out = []
    for h in hosts:
        hl = h.lower()
        if "${{" in hl or "$" in hl:
            continue
        if not any(hl == g or hl.endswith("." + g) for g in _GH_HOSTS):
            out.append(hl)
    return out


def _vendor_match(step: str, hosts: list[str]) -> bool:
    """True when every secret used in the step is named after the vendor it is sent to
    (e.g. STATSIG_API_KEY -> api.statsig.com): that is the secret's intended use."""
    names = re.findall(r"secrets\.([A-Za-z0-9_]+)", step)
    if not names or not hosts:
        return False
    labels = {lab for h in hosts for lab in re.split(r"[.-]", h.lower()) if len(lab) >= 4}
    labels |= {lab[: -3] for lab in labels if lab.endswith("api") and len(lab) > 6}
    def ok(name: str) -> bool:
        toks = [t for t in name.lower().split("_") if len(t) >= 4]
        return any(t in labels or any(lab.startswith(t) for lab in labels) for t in toks)
    return all(ok(n) for n in names)


class CicdDetector(Detector):
    id = "cicd"
    name = "CI/CD workflow risks"
    category = _CAT
    checks = (CIX001, CIX002, CIX003, CIX004, CIX005, CIX006, CIX007)

    def applies_to(self, ctx: FileContext) -> bool:
        return ctx.is_ci and not ctx.is_binary

    def scan_file(self, ctx: FileContext) -> Iterable[Finding]:
        rl = ctx.rel_lower
        gha = rl.startswith(".github/") or ctx.basename.lower() in {"action.yml", "action.yaml"}
        out: list[Finding] = []
        if gha:
            out += self._cix001(ctx)
            out += self._cix002(ctx)
            out += self._cix004(ctx)
            out += scan_pats(CIX005, ctx, (
                Pat(r"^\s*(?:runs-on:[^\n]{0,40}|-\s*)\bself-hosted\b", ("self-hosted",)),
            ), max_findings=3, line_filter=_not_comment)
            out += self._cix006(ctx)
        out += self._cix003(ctx)
        out += scan_pats(CIX007, ctx, pipe_shell_pats(), line_filter=_not_comment)
        return out

    # ---- CIX001 ----------------------------------------------------------------------
    def _cix001(self, ctx: FileContext) -> list[Finding]:
        low = ctx.lower
        if "pull_request_target" not in low and "workflow_run" not in low:
            return []
        triggered = any(
            _TRIGGER_RE.search(ln) and "github.event" not in ln and "${{" not in ln and not ln.lstrip().startswith("#")
            for ln in ctx.lines
        )
        if not triggered:
            return []
        return scan_pats(CIX001, ctx, (
            Pat(r"\bref:\s*[^\n]{0,80}github\.event\.(?:pull_request\.head\.(?:sha|ref)|workflow_run\.head)", ("ref:",)),
            Pat(r"\bref:\s*[^\n]{0,80}(?:refs/pull/|github\.head_ref)", ("ref:",)),
            Pat(r"\bgit\s+(?:checkout|fetch|switch)\b[^\n]{0,120}(?:github\.event\.pull_request\.head|github\.event\.workflow_run\.head|refs/pull/|github\.head_ref)",
                ("git",)),
        ), max_findings=3, line_filter=_not_comment)

    # ---- CIX002 ----------------------------------------------------------------------
    def _cix002(self, ctx: FileContext) -> list[Finding]:
        if "${{" not in ctx.text or "github." not in ctx.lower:
            return []
        run = _run_lines(ctx.lines)
        if not run:
            return []
        return scan_pats(CIX002, ctx, (
            Pat(r"\$\{\{\s*github\.(?:event\.(?:issue|pull_request|comment|review|review_comment|head_commit|commits|discussion|pages)[^}]{0,80}(?:title|body|message|name|label|ref)|head_ref)\b",
                ("github.",)),
        ), line_filter=lambda n, u: n in run and not u.lstrip().startswith("#"))

    # ---- CIX003 ----------------------------------------------------------------------
    def _cix003(self, ctx: FileContext) -> list[Finding]:  # noqa: C901
        out = scan_pats(CIX003, ctx, (
            Pat(r"/proc/[^/\s]{0,12}/mem\b|Runner\.Worker", ("/proc/", "runner.worker"), S.CRITICAL, C.HIGH,
                (T.READS_CREDENTIALS,), "reads runner process memory to dump masked secrets"),
            Pat(r"toJSON\(\s*secrets\s*\)", ("tojson",), S.HIGH, C.HIGH, (T.READS_CREDENTIALS,),
                "serialises the whole secrets context"),
            Pat(r"secrets\.\w+[^\n]{0,40}base64|base64[^\n]{0,40}secrets\.\w+", ("base64",), S.HIGH, C.HIGH,
                (T.READS_CREDENTIALS,), "base64-encodes a secret (evades log masking)"),
        ), dampen=False, line_filter=_not_comment)
        if "secrets." not in ctx.lower:
            return out
        lines = ctx.lines
        done_steps: set[int] = set()
        taken = {f.line for f in out}
        for idx, ln in enumerate(lines):
            if ln.lstrip().startswith("#") or not _NET_CMD.search(ln):
                continue
            start, end = _step_range(lines, idx)
            if start in done_steps:
                continue
            step = "\n".join(lines[start:end])
            if "secrets." not in step:
                continue
            ext = _external(URL_HOST.findall(step))
            if not ext and not re.search(r"\b(?:nc|ncat|netcat)\s+(?:-\w+\s+){0,3}[\w.-]+\.[a-z]{2,}", ln, re.I):
                continue
            done_steps.add(start)
            if idx + 1 in taken:
                continue
            host = ext[0] if ext else "a netcat target"
            vendor = _vendor_match(step, ext)
            out.append(self.finding(CIX003, ctx, idx + 1, ln, severity=S.LOW if vendor else S.HIGH,
                                    confidence=C.LOW if vendor else C.MEDIUM,
                                    extra_tags=(T.NETWORK_SEND,),
                                    description=f"{CIX003.description} A step that uses secrets.* also sends data to {host}."))
            if len(out) >= 5:
                break
        return out

    # ---- CIX004 ----------------------------------------------------------------------
    def _cix004(self, ctx: FileContext) -> list[Finding]:
        if "uses:" not in ctx.lower:
            return []
        out: list[Finding] = []
        seen: set[str] = set()
        for i, ln in enumerate(ctx.lines, 1):
            m = _USES_RE.match(ln)
            if not m:
                continue
            action, ref = m.group(1), m.group(2) or ""
            if action.startswith(("./", "../", "docker://")) or "/" not in action:
                continue
            owner = action.split("/", 1)[0].lower()
            name = "/".join(action.lower().split("/")[:2])
            key = f"{name}@{ref}"
            if key in seen:
                continue
            seen.add(key)
            pinned = bool(_SHA_RE.match(ref.lower()))
            if name in _COMPROMISED and not pinned:
                out.append(self.finding(CIX004, ctx, i, ln, severity=S.MEDIUM, confidence=lower_conf(C.HIGH, ctx),
                                        description=f"{CIX004.description} {name} was compromised in a real supply-chain attack; a tag reference may resolve to malicious code."))
                continue
            if owner in {"actions", "github"} or pinned:
                continue
            out.append(self.finding(CIX004, ctx, i, ln, confidence=lower_conf(C.HIGH, ctx),
                                    description=f"{CIX004.description} {action}@{ref or '(no ref)'}"))
            if len(out) >= 20:
                break
        return out

    # ---- CIX006 ----------------------------------------------------------------------
    def _cix006(self, ctx: FileContext) -> list[Finding]:
        pats = [Pat(r"^\s*permissions:\s*[\"']?write-all\b", ("write-all",))]
        if any(_PR_TRIGGER_RE.search(ln) for ln in ctx.lines if "${{" not in ln):
            pats.append(Pat(r"^\s*contents:\s*[\"']?write\b", ("contents",), note="contents: write on a pull-request trigger"))
        return scan_pats(CIX006, ctx, pats, max_findings=3, line_filter=_not_comment)


DETECTORS = (CicdDetector,)
