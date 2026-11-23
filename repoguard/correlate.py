"""Correlation engine: combines individual findings into higher-confidence attack patterns.

A single `requests.post` or a single read of `~/.aws/credentials` is normal; both in one file is a stealer.
Correlations are driven by finding *tags* (see tags.py), so detectors stay independent.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from . import tags as T
from .calibrate import is_prose
from .models import Category, Confidence, Finding, Severity

Matcher = Callable[[Finding], bool]


def any_tag(*tags: str) -> Matcher:
    ts = frozenset(tags)
    return lambda f: not ts.isdisjoint(f.tags)


def all_tags(*tags: str) -> Matcher:
    ts = frozenset(tags)
    return lambda f: ts <= set(f.tags)


def rule_in(*ids: str) -> Matcher:
    s = frozenset(ids)
    return lambda f: f.rule_id in s


def prefix(*pfx: str) -> Matcher:
    return lambda f: f.rule_id.startswith(pfx)


def either(*ms: Matcher) -> Matcher:
    return lambda f: any(m(f) for m in ms)


def both(*ms: Matcher) -> Matcher:
    return lambda f: all(m(f) for m in ms)


def min_conf(c: Confidence) -> Matcher:
    return lambda f: f.confidence >= c


def min_sev(s: Severity) -> Matcher:
    return lambda f: f.severity >= s


@dataclass(frozen=True)
class CorrelationRule:
    id: str
    title: str
    severity: Severity
    confidence: Confidence
    description: str
    recommendation: str
    groups: tuple[Matcher, ...]
    scope: str = "file"  # "file" | "repo"
    block: bool = False
    block_when: Matcher | None = None  # BLOCK only if at least one participant matches this
    relate: Callable[[Finding, Finding], bool] | None = None  # pairwise link between group 0 and group 1 hits
    require: Matcher | None = None  # at least one chosen participant must match, or the rule does not fire
    prose_ok: bool = False  # also correlate inside prose files (.md/.rst/.txt); only AI-instruction rules need it
    superseded_by: str | None = None  # skip when that (stronger) rule already fired on the same file
    tags: frozenset[str] = field(default_factory=frozenset)
    category: Category = Category.CORRELATION


_STRONG_CRED = either(
    rule_in("CRD003", "CRD004", "CRD005", "CRD009", "CRD010"),
    both(rule_in("CRD001"), lambda f: "id_" in f.snippet.lower()),  # private SSH key, not ~/.ssh/config
)
_HOOK = both(any_tag(T.INSTALL_HOOK, T.OPEN_HOOK), lambda f: f.rule_id != "INS013", min_sev(Severity.MEDIUM))
_NET = any_tag(T.NETWORK_SEND, T.EXFIL_CHANNEL)
_IS_PROSE = lambda f: is_prose(f.path)  # noqa: E731
_NOT_DOC = lambda f: f.context_kind not in ("test", "doc")  # noqa: E731
_SOLID = both(min_conf(Confidence.MEDIUM), _NOT_DOC)
_R = "Treat the repository as malicious. Do not install or run it; report it to the hosting platform."

CORRELATIONS: tuple[CorrelationRule, ...] = (
    CorrelationRule(
        "COR001", "Credential theft with network exfiltration", Severity.CRITICAL, Confidence.HIGH,
        "The same file reads credential stores (SSH keys, cloud/AI CLI tokens, browser data, wallets) and sends data "
        "over the network. This is the core pattern of an info-stealer.", _R,
        (any_tag(T.READS_CREDENTIALS), _NET), block=True,
        require=either(_STRONG_CRED, any_tag(T.EXFIL_CHANNEL)),
    ),
    CorrelationRule(
        "COR018", "Reads a credential file and uses the network", Severity.MEDIUM, Confidence.LOW,
        "The same file reads a credential/config file (e.g. ~/.netrc, ~/.npmrc) and makes network requests. HTTP "
        "clients and CLIs do this legitimately (to authenticate); a stealer does it to exfiltrate.",
        "Check where the credential value goes: to the service it belongs to (normal) or to a third party.",
        (any_tag(T.READS_CREDENTIALS), _NET), superseded_by="COR001",
    ),
    CorrelationRule(
        "COR002", "Decode-and-execute dropper with network access", Severity.CRITICAL, Confidence.HIGH,
        "Encoded content is decoded and executed in a file that also talks to the network: a typical dropper/loader.",
        _R, (either(all_tags(T.DECODE, T.EXEC_DYNAMIC), rule_in("OBF001", "OBF002", "OBF004")),
             any_tag(T.NETWORK_SEND, T.DOWNLOAD)),
    ),
    CorrelationRule(
        "COR003", "Install/open hook that downloads, executes or hides code", Severity.CRITICAL, Confidence.HIGH,
        "Code that runs automatically when you install the package or open the folder also fetches, executes or "
        "obfuscates code. Installing or opening the repo would run it with your permissions.",
        "Do not install or open this repo in an editor that runs tasks; read the hook manually first.",
        (_HOOK, any_tag(T.NETWORK_SEND, T.DOWNLOAD, T.EXEC_DYNAMIC, T.OBFUSCATED)),
    ),
    CorrelationRule(
        "COR004", "Environment variable dump sent over the network", Severity.CRITICAL, Confidence.HIGH,
        "The whole environment (which normally holds API keys and tokens) is collected and a network send exists "
        "in the same file.", _R, (any_tag(T.ENV_HARVEST), _NET),
    ),
    CorrelationRule(
        "COR005", "Surveillance with exfiltration (spyware)", Severity.CRITICAL, Confidence.HIGH,
        "Keylogging, screen/camera/clipboard capture combined with a network send in the same file.", _R,
        (any_tag(T.SURVEILLANCE), _NET),
    ),
    CorrelationRule(
        "COR006", "Anti-analysis combined with malicious behaviour", Severity.CRITICAL, Confidence.HIGH,
        "The code checks for sandboxes/debuggers/CI and also contains malware behaviour. Legitimate software rarely "
        "hides from analysts.", _R,
        (both(any_tag(T.ANTI_ANALYSIS), min_conf(Confidence.MEDIUM)),
         both(any_tag(T.REVERSE_SHELL, T.MINER, T.PROCESS_INJECTION, T.PERSISTENCE, T.AV_TAMPER, T.EXFIL_CHANNEL,
                      T.OBFUSCATED, T.READS_CREDENTIALS), min_conf(Confidence.MEDIUM))),
        block=True,
    ),
    CorrelationRule(
        "COR007", "Persistence with download or obfuscation", Severity.CRITICAL, Confidence.HIGH,
        "The code installs itself to run at startup and also downloads, decodes or executes payloads.", _R,
        (any_tag(T.PERSISTENCE), any_tag(T.DOWNLOAD, T.OBFUSCATED, T.EXEC_DYNAMIC)),
    ),
    CorrelationRule(
        "COR008", "AI agent hijack: instructions plus command/secret/network access", Severity.CRITICAL,
        Confidence.MEDIUM,
        "An AI-assistant instruction file contains injection-style instructions and also tells the agent to run "
        "commands, touch secrets or contact URLs. Opening this repo with an AI coding agent could make it act "
        "against you.",
        "Do not open this repo with an AI coding agent (Claude Code, Cursor, Copilot...) until the file is reviewed.",
        (both(any_tag(T.AI_INSTRUCTION), min_sev(Severity.HIGH)),
         any_tag(T.EXEC_DYNAMIC, T.SECRET, T.NETWORK_SEND, T.READS_CREDENTIALS)),
        prose_ok=True,
    ),
    CorrelationRule(
        "COR009", "Committed binary referenced from an install/open hook", Severity.HIGH, Confidence.MEDIUM,
        "A prebuilt executable is committed and a hook/README step references it, so it would run on install.",
        "Never run committed binaries from untrusted repos; build from source or verify signatures.",
        (any_tag(T.BINARY_EXEC), _HOOK), scope="repo", relate=lambda b, h: _refers(h, b),
    ),
    CorrelationRule(
        "COR010", "Download lure from a low-reputation repository", Severity.CRITICAL, Confidence.HIGH,
        "The README pushes downloads (cracks, password-protected archives, AV exclusions, file hosts) and the "
        "repository shows fake-popularity or throwaway-account signals. This matches GitHub malware-lure campaigns.",
        _R, (rule_in("REP003", "REP005", "REP007"), rule_in("REP001", "REP004", "REP006")), scope="repo", block=True,
        block_when=min_conf(Confidence.MEDIUM),
    ),
    CorrelationRule(
        "COR011", "Fork that adds hooks, binaries or AI config", Severity.CRITICAL, Confidence.MEDIUM,
        "This fork changes install hooks, binaries or AI instruction files compared to its parent: a common way "
        "to trojanize a popular project.", _R,
        (rule_in("REP002"), both(prefix("INS", "AIX", "BIN"), min_sev(Severity.HIGH))), scope="repo",
    ),
    CorrelationRule(
        "COR012", "API-key phishing with network send", Severity.CRITICAL, Confidence.HIGH,
        "The code asks for API keys/passwords/seed phrases and sends data over the network.",
        "Never type keys into this tool; revoke any key you already entered.", (any_tag(T.PHISHING), _NET),
    ),
    CorrelationRule(
        "COR013", "Hidden/invisible content in a file that executes code", Severity.HIGH, Confidence.MEDIUM,
        "Invisible Unicode or hidden text appears in a file that also executes commands or code; reviewers would "
        "not see what actually runs.", "Inspect the file with a hex viewer or `repoguard explain` before use.",
        (any_tag(T.INVISIBLE_UNICODE), any_tag(T.EXEC_DYNAMIC)),
        prose_ok=True,
    ),
    CorrelationRule(
        "COR014", "Text tries to talk the scanner/AI reviewer out of findings", Severity.CRITICAL, Confidence.MEDIUM,
        "The repo contains text addressed to AI reviewers or security scanners (\"this is safe\", \"ignore\", "
        "\"false positive\") AND other high-severity findings. Benign projects do not need to persuade scanners.",
        _R, (both(prefix("AIX"), any_tag(T.EVASION), min_conf(Confidence.MEDIUM)),
            both(min_sev(Severity.HIGH), min_conf(Confidence.MEDIUM), lambda f: not f.rule_id.startswith(("AIX", "META", "COR")))),
        scope="repo",
    ),
    CorrelationRule(
        "COR015", "Payload gated on CI/locale/sandbox checks", Severity.HIGH, Confidence.MEDIUM,
        "Code changes behaviour depending on CI, locale or sandbox detection and also downloads/executes/sends data.",
        "Review the gated branch manually; it may only trigger on real user machines.",
        (any_tag(T.ANTI_ANALYSIS), any_tag(T.DOWNLOAD, T.EXEC_DYNAMIC, T.NETWORK_SEND)),
    ),
    CorrelationRule(
        "COR016", "Publish token theft (worm pattern)", Severity.CRITICAL, Confidence.HIGH,
        "Package-registry or CI tokens are read and code publishes packages / exfiltrates CI secrets.", _R,
        (any_tag(T.READS_CREDENTIALS, T.SECRET), rule_in("MAL013", "CIX003")), block=True,
        block_when=min_conf(Confidence.MEDIUM),
    ),
    CorrelationRule(
        "COR017", "Typosquatted dependency next to an install/open hook", Severity.CRITICAL, Confidence.MEDIUM,
        "A dependency name imitates a popular package and the same manifest runs install-time code.", _R,
        (any_tag(T.TYPOSQUAT), _HOOK),
    ),
)


def _inputs(findings: Iterable[Finding]) -> list[Finding]:
    return [f for f in findings if f.category not in (Category.META, Category.CORRELATION)
            and not f.path.startswith("history:")]


def _build(rule: CorrelationRule, parts: list[Finding], path: str) -> Finding:
    parts = sorted(parts, key=lambda f: (-f.severity, f.path, f.line or 0))
    block = rule.block and all(_SOLID(p) for p in parts) and (
        rule.block_when is None or any(rule.block_when(p) for p in parts)
    )
    tags = set(rule.tags) | {T.NO_DAMPEN}
    for p in parts:
        tags |= set(p.tags)
    tags -= {T.HYGIENE, T.BLOCK_TRIGGER}
    if block:
        tags.add(T.BLOCK_TRIGGER)
    evidence = "; ".join(f"{p.rule_id} {p.title} @ {p.location}" for p in parts[:8])
    first = next((p for p in parts if p.path == path), parts[0])
    return Finding(
        rule_id=rule.id, title=rule.title, severity=rule.severity, confidence=rule.confidence,
        category=Category.CORRELATION, path=path, line=first.line if path else None,
        snippet=" + ".join(dict.fromkeys(p.rule_id for p in parts)),
        description=f"{rule.description} Evidence: {evidence}", recommendation=rule.recommendation,
        tags=tuple(sorted(tags)), related=tuple(p.fingerprint for p in parts),
        context_kind=None if any(p.context_kind is None for p in parts) else parts[0].context_kind,
    )


def _refers(hook: Finding, binary: Finding) -> bool:
    name = binary.path.rsplit("/", 1)[-1].lower()
    return len(name) >= 3 and (name in hook.snippet.lower() or name in hook.description.lower())


def _match(rule: CorrelationRule, pool: list[Finding]) -> list[Finding] | None:
    parts = _match_groups(rule, pool)
    if parts and rule.require is not None and not any(rule.require(p) for p in parts):
        return None
    return parts


def _match_groups(rule: CorrelationRule, pool: list[Finding]) -> list[Finding] | None:
    if rule.relate is not None:
        g0 = [f for f in pool if rule.groups[0](f)]
        g1 = [f for f in pool if rule.groups[1](f)]
        pairs = [(a, b) for a in g0 for b in g1 if a is not b and rule.relate(a, b)]
        return list(dict.fromkeys(x for pr in pairs[:3] for x in pr)) or None
    chosen: list[Finding] = []
    per_group: list[list[Finding]] = []
    for g in rule.groups:
        hits = [f for f in pool if g(f)]
        if not hits:
            return None
        per_group.append(hits)
        chosen.extend(sorted(hits, key=lambda f: (-f.severity, -f.confidence))[:3])
    # a correlation needs separate pieces of evidence: one finding carrying both tags is not a chain
    distinct = list(dict.fromkeys(f for hits in per_group for f in hits))
    if len(distinct) < len(rule.groups):
        return None
    if len(per_group) == 2 and not any(a is not b for a in per_group[0] for b in per_group[1]):
        return None
    return list(dict.fromkeys(chosen))


def correlate(findings: Iterable[Finding]) -> list[Finding]:
    pool = _inputs(findings)
    by_file: dict[str, list[Finding]] = defaultdict(list)
    for f in pool:
        if f.path:
            by_file[f.path].append(f)
    out: list[Finding] = []
    fired: set[tuple[str, str]] = set()
    for rule in CORRELATIONS:
        if rule.scope == "file":
            for path, fs in sorted(by_file.items()):
                if rule.superseded_by and (rule.superseded_by, path) in fired:
                    continue
                if not rule.prose_ok:
                    fs = [f for f in fs if not _IS_PROSE(f)]
                parts = _match(rule, fs)
                if parts:
                    fired.add((rule.id, path))
                    out.append(_build(rule, parts, path))
        else:
            parts = _match(rule, pool)
            if parts:
                out.append(_build(rule, parts, ""))
    return out
