"""SEC001-SEC016: committed secrets (hygiene: they hurt the repo owner, not the installer).

Also hosts two small helpers reused by exfil.py and obfuscation.py:
- `PatternSpec` / `scan_specs`: code-based regex checks that need several patterns, per-match
  severity/confidence overrides or value dedupe (things a single declarative `Rule` cannot express).
- `adjust_for_location`: the std-FP confidence lowering for test/doc/vendored and rule-list files.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from typing import Any

from .. import tags as T
from ..context import FileContext
from ..detector import Detector, RuleInfo
from ..models import Category, Confidence, Finding, Severity
from ..rules import MULTILINE_CAP
from ..textutil import is_placeholder, shannon_entropy

# ---------------------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------------------


def lower_confidence(conf: Confidence, steps: int = 1) -> Confidence:
    return Confidence(max(int(Confidence.LOW), int(conf) - steps))


def drop_severity(sev: Severity, steps: int = 1) -> Severity:
    return Severity(max(int(Severity.INFO), int(sev) - steps))


_RULE_LIST_LINE = re.compile(
    r"""['"][^'"\n]{0,200}?(?:\\[.dswbSW(\[/]|\(\?[:<!=iP]|\[[A-Za-z0-9]-[A-Za-z0-9])"""
)


def is_rule_list_file(ctx: FileContext) -> bool:
    """Detection-rule-list files (>40% of non-empty lines are regex/IOC literals). Cached on ctx."""
    cache = ctx.__dict__
    if "_rg_rule_list" in cache:
        return bool(cache["_rg_rule_list"])
    lines = [ln for ln in ctx.lines[:5000] if ln.strip()]
    result = False
    if len(lines) >= 5:
        hits = sum(1 for ln in lines if _RULE_LIST_LINE.search(ln[:2000]))
        result = hits / len(lines) > 0.4
    cache["_rg_rule_list"] = result
    return result


def adjust_for_location(f: Finding, ctx: FileContext) -> Finding:
    """std-FP: test/doc/vendored lowers confidence one level unless the rule is NO_DAMPEN;
    detection-rule-list files lower it one more level for every rule."""
    conf = f.confidence
    if T.NO_DAMPEN not in f.tags and ctx.context_kind is not None:
        conf = lower_confidence(conf)
    if is_rule_list_file(ctx):
        conf = lower_confidence(conf)
    return f if conf == f.confidence else f.replace(confidence=conf)


def line_snippet(text: str, start: int, end: int, pad: int = 80) -> str:
    ls = text.rfind("\n", 0, start) + 1
    le = text.find("\n", end)
    le = len(text) if le == -1 else le
    return text[max(ls, start - pad) : min(le, end + pad)].replace("\n", " ")


Check = Callable[[re.Match[str], FileContext], "dict[str, Any] | None"]


@dataclass(frozen=True, slots=True)
class PatternSpec:
    """One regex used by a code-based rule. Several specs may share one RuleInfo."""

    info: RuleInfo
    regex: re.Pattern[str]
    keywords: tuple[str, ...] = ()  # lowercase; any must occur in ctx.lower
    require: tuple[str, ...] = ()  # lowercase; all must occur in ctx.lower
    languages: frozenset[str] = frozenset()
    group: int | str = 0  # value group (masked + deduped when is_secret)
    is_secret: bool = False
    min_entropy: float | None = None
    check: Check | None = None  # returns None to drop, or overrides {severity, confidence, tags, description}
    severity: Severity | None = None
    confidence: Confidence | None = None
    extra_tags: tuple[str, ...] = ()
    max_per_file: int = 5


def scan_specs(specs: Iterable[PatternSpec], ctx: FileContext) -> Iterator[Finding]:
    """Run specs over the whole (capped) text. Overlapping matches and repeated secret values are
    reported once; earlier specs win, so list specific patterns before generic ones."""
    text = ctx.text[:MULTILINE_CAP]
    if not text:
        return
    low = ctx.lower
    taken: list[tuple[int, int]] = []
    seen: set[str] = set()
    for spec in specs:
        if ctx.deadline_exceeded():
            return
        if spec.languages and ctx.language not in spec.languages:
            continue
        if spec.keywords and not any(k in low for k in spec.keywords):
            continue
        if spec.require and not all(r in low for r in spec.require):
            continue
        count = 0
        for m in spec.regex.finditer(text):
            value = m.group(spec.group) or ""
            s, e = m.span(spec.group)
            if spec.is_secret:
                if not value or value in seen or is_placeholder(value):
                    continue
                if spec.min_entropy is not None and shannon_entropy(value) < spec.min_entropy:
                    continue
            if any(s < te and ts < e for ts, te in taken):
                continue
            over = spec.check(m, ctx) if spec.check else {}
            if over is None:
                continue
            taken.append((s, e))
            if spec.is_secret:
                seen.add(value)
            yield Finding.from_rule(
                spec.info,
                ctx,
                ctx.line_of(m.start()),
                line_snippet(text, m.start(), m.end()),
                extra_tags=spec.extra_tags + tuple(over.get("tags", ())),
                severity=over.get("severity", spec.severity),
                confidence=over.get("confidence", spec.confidence),
                secret=value if spec.is_secret else None,
                description=over.get("description"),
            )
            count += 1
            if count >= spec.max_per_file:
                break


# ---------------------------------------------------------------------------------------
# SEC rules
# ---------------------------------------------------------------------------------------

H, M, L = Severity.HIGH, Severity.MEDIUM, Severity.LOW
CH, CM, CL = Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW
_TAGS = frozenset({T.SECRET, T.HYGIENE})
_REC = (
    "Revoke/rotate the credential at the provider now, remove it from the code and the git history "
    "(git filter-repo / BFG), and load it from an environment variable or a secret manager."
)


def _sec(rid: str, title: str, sev: Severity, conf: Confidence, desc: str) -> RuleInfo:
    return RuleInfo(rid, title, sev, conf, Category.SECRETS, desc, _REC, _TAGS)


SEC001 = _sec("SEC001", "Anthropic API key", H, CH, "An Anthropic API/admin key is committed in the repository.")
SEC002 = _sec("SEC002", "OpenAI API key", H, CH, "An OpenAI API key is committed in the repository.")
SEC003 = _sec("SEC003", "Google API key or service-account key", H, CH,
              "A Google API key, OAuth client secret or service-account private key is committed.")
SEC004 = _sec("SEC004", "AWS access key", H, CH, "An AWS access key id or secret access key is committed.")
SEC005 = _sec("SEC005", "Azure credential", H, CM,
              "An Azure storage account key, client secret or SAS signature is committed.")
SEC006 = _sec("SEC006", "GitHub token", H, CH, "A GitHub personal access / OAuth / app token is committed.")
SEC007 = _sec("SEC007", "Slack token or webhook", H, CH, "A Slack API token or incoming-webhook URL is committed.")
SEC008 = _sec("SEC008", "Stripe secret key", H, CH, "A Stripe secret/restricted key or webhook signing secret is committed.")
SEC009 = _sec("SEC009", "Discord bot token", H, CM, "A Discord bot token is committed.")
SEC010 = _sec("SEC010", "Telegram bot token", H, CH, "A Telegram bot token is committed.")
SEC011 = _sec("SEC011", "Private key", H, CH, "A PEM/OpenSSH/PGP private key block is committed.")
SEC012 = _sec("SEC012", "JSON Web Token", M, CM, "A JWT (bearer token) is committed; it may still grant access.")
SEC013 = _sec("SEC013", "Database URL with password", M, CM, "A database/broker connection URL embeds a password.")
SEC014 = _sec("SEC014", "Committed .env file", M, CH, "A .env file with high-entropy values is committed.")
SEC015 = _sec("SEC015", "Provider API token", H, CM,
              "An API token for a known provider (Hugging Face, npm, PyPI, GitLab, SendGrid, Groq, xAI, "
              "Twilio, Mailgun) is committed.")
SEC016 = _sec("SEC016", "High-entropy secret assignment", M, CL,
              "A variable named like a key/secret/token/password is assigned a high-entropy literal.")

CHECKS = (SEC001, SEC002, SEC003, SEC004, SEC005, SEC006, SEC007, SEC008, SEC009, SEC010, SEC011, SEC012,
          SEC013, SEC014, SEC015, SEC016)


def _b64url(seg: str) -> bytes | None:
    try:
        return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))
    except (binascii.Error, ValueError):
        return None


def _discord_check(m: re.Match[str], ctx: FileContext) -> dict[str, Any] | None:
    raw = _b64url(m.group(0).split(".", 1)[0])  # first part = base64(user id)
    return {} if raw and raw.isdigit() and len(raw) >= 15 else None


_PK_BODY = re.compile(r"[A-Za-z0-9+/]{40,}")


def _pk_check(m: re.Match[str], ctx: FileContext) -> dict[str, Any] | None:
    # a header alone (parsers, docs, detection code) is not a key: require a base64 body after it
    return {} if _PK_BODY.search(m.string, m.end(), m.end() + 400) else None


def _jwt_check(m: re.Match[str], ctx: FileContext) -> dict[str, Any] | None:
    raw = _b64url(m.group(0).split(".")[1])
    if raw is None:
        return None
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    flat = json.dumps(payload)
    if "1234567890" in flat or "John Doe" in flat:  # jwt.io sample token
        return None
    exp = payload.get("exp")
    if isinstance(exp, (int, float)) and exp < time.time():
        return {"confidence": CL, "description": "A committed JWT (already expired)."}
    return {}


_TRIVIAL_PW = frozenset({
    "password", "passwd", "pass", "secret", "postgres", "root", "admin", "test", "mysql", "guest", "changeme",
    "user", "username", "pwd", "redis", "mongo", "rabbitmq", "default", "1234", "12345", "123456", "qwerty",
})
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "0.0.0.0", "::1", "db", "database", "postgres", "mysql",
                          "redis", "mongo", "mongodb", "rabbitmq", "mariadb", "host.docker.internal"})
_HOST_RE = re.compile(r"[\w.-]+")


def _db_check(m: re.Match[str], ctx: FileContext) -> dict[str, Any] | None:
    pw = m.group("pw")
    hm = _HOST_RE.match(m.group("host"))
    host = hm.group(0).lower() if hm else ""
    if pw.startswith(("$", "%")) or "{" in pw or pw.lower() in _TRIVIAL_PW:
        return None
    if host in _LOCAL_HOSTS and shannon_entropy(pw) < 3.0:
        return None
    return {}


_PATHISH = re.compile(r"^(?:/|\./|\.\./|~/|[A-Za-z]:[\\/])|\\|\.(?:py|js|ts|json|txt|pem|key|crt|ya?ml|toml|cfg|ini|html?|png)$")
_IDENTISH = re.compile(r"^[A-Za-z_.-]+$|^[a-z]+(?:[_.-][a-z0-9]+)+$")
_HEX = re.compile(r"^[0-9a-fA-F]+$")


def _generic_check(m: re.Match[str], ctx: FileContext) -> dict[str, Any] | None:
    v = m.group("val")
    if "://" in v or _PATHISH.search(v) or _IDENTISH.match(v):
        return None
    floor = 3.0 if _HEX.match(v) else 4.0
    return {} if shannon_entropy(v) >= floor else None


def _p(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


SPECS: tuple[PatternSpec, ...] = (
    PatternSpec(SEC001, _p(r"sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}"), ("sk-ant-",), is_secret=True),
    PatternSpec(SEC002, _p(r"sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}"),
                ("t3blbkfj",), is_secret=True),
    PatternSpec(SEC002, _p(r"sk-proj-[A-Za-z0-9_-]{80,}"), ("sk-proj-",), is_secret=True),
    PatternSpec(SEC003, _p(r'"private_key"[ \t]*:[ \t]*"(?P<v>-----BEGIN[^"\n]{40,})"'),
                ('"private_key"', "service_account"), require=("service_account",), group="v", is_secret=True),
    PatternSpec(SEC003, _p(r"AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])"), ("aiza",), is_secret=True),
    PatternSpec(SEC003, _p(r"GOCSPX-[A-Za-z0-9_-]{28}"), ("gocspx-",), is_secret=True),
    PatternSpec(SEC004, _p(r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b"), ("akia", "asia", "abia", "acca"),
                is_secret=True),
    PatternSpec(SEC004, _p(r"aws.{0,25}(?:secret|sk).{0,25}['\"](?P<v>[A-Za-z0-9/+=]{40})['\"]", re.I), ("aws",),
                group="v", is_secret=True, min_entropy=3.5),
    PatternSpec(SEC005, _p(r"AccountKey=(?P<v>[A-Za-z0-9+/=]{86,88})"), ("accountkey=",), group="v",
                is_secret=True),
    PatternSpec(SEC005, _p(r"(?<![A-Za-z0-9_~.-])[A-Za-z0-9_~.-]{3}\dQ~[A-Za-z0-9_~.-]{31,34}(?![A-Za-z0-9_~.-])"),
                ("q~",), is_secret=True, min_entropy=3.5),
    PatternSpec(SEC005, _p(r"[?&]sig=(?P<v>[A-Za-z0-9%]{40,})"), ("sig=",), group="v", is_secret=True),
    PatternSpec(SEC006, _p(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"), ("ghp_", "gho_", "ghu_", "ghs_", "ghr_"),
                is_secret=True),
    PatternSpec(SEC006, _p(r"github_pat_[A-Za-z0-9_]{82}"), ("github_pat_",), is_secret=True),
    PatternSpec(SEC007, _p(r"xox[abprs]-[A-Za-z0-9-]{10,}"), ("xox",), is_secret=True),
    PatternSpec(SEC007, _p(r"hooks\.slack\.com/services/T\w+/B\w+/(?P<v>\w{24})"), ("hooks.slack.com",),
                group="v", is_secret=True),
    PatternSpec(SEC008, _p(r"\b(?:sk|rk)_live_[A-Za-z0-9]{24,}"), ("_live_",), is_secret=True),
    PatternSpec(SEC008, _p(r"\b(?:sk|rk)_test_[A-Za-z0-9]{24,}"), ("_test_",), is_secret=True, severity=L,
                check=lambda m, c: {"description": "A Stripe TEST-mode secret key is committed (low impact)."}),
    PatternSpec(SEC008, _p(r"whsec_[A-Za-z0-9]{32,}"), ("whsec_",), is_secret=True),
    PatternSpec(SEC009, _p(r"(?<![A-Za-z\d_-])[MNO][A-Za-z\d_-]{23,25}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,38}"
                           r"(?![A-Za-z\d_-])"), is_secret=True, check=_discord_check),
    PatternSpec(SEC010, _p(r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b"), (":aa",), is_secret=True),
    PatternSpec(SEC011, _p(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
                ("private key",), check=_pk_check),
    PatternSpec(SEC012, _p(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,4096}\.eyJ[A-Za-z0-9_-]{10,4096}\.[A-Za-z0-9_-]{10,4096}"), ("eyj",),
                is_secret=True, check=_jwt_check),
    PatternSpec(SEC013, _p(r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql)://"
                           r"[^:\s/@'\"]+:(?P<pw>[^@\s/'\"]{3,})@(?P<host>[^\s/'\"]+)", re.I),
                ("postgres", "mysql", "mariadb", "mongodb", "redis", "amqp", "mssql"), group="pw", is_secret=True,
                check=_db_check),
    PatternSpec(SEC015, _p(r"\bhf_[A-Za-z]{34}\b"), ("hf_",), is_secret=True),
    PatternSpec(SEC015, _p(r"\bnpm_[A-Za-z0-9]{36}\b"), ("npm_",), is_secret=True),
    PatternSpec(SEC015, _p(r"pypi-AgEIcHlwaS5vcmc[\w-]{50,}"), ("pypi-ageichlwas5vcmc",), is_secret=True),
    PatternSpec(SEC015, _p(r"\bglpat-[\w-]{20,}"), ("glpat-",), is_secret=True),
    PatternSpec(SEC015, _p(r"\bSG\.[\w-]{22}\.[\w-]{43}\b"), ("sg.",), is_secret=True),
    PatternSpec(SEC015, _p(r"\bgsk_[A-Za-z0-9]{52}\b"), ("gsk_",), is_secret=True),
    PatternSpec(SEC015, _p(r"\bxai-[A-Za-z0-9]{80}\b"), ("xai-",), is_secret=True),
    PatternSpec(SEC015, _p(r"\b(?:AC|SK)[0-9a-f]{32}\b"), ("twilio",), is_secret=True),
    PatternSpec(SEC015, _p(r"\bkey-[0-9a-f]{32}\b"), ("mailgun",), is_secret=True),
    PatternSpec(SEC016, _p(r"(?:api[_-]?key|secret|token|passw(?:or)?d|auth|credential|private[_-]?key)['\"]?"
                           r"[ \t]*[:=]{1,2}[ \t]*['\"](?P<val>[^'\"\s]{16,})['\"]", re.I),
                ("key", "secret", "token", "passw", "auth", "credential"), group="val", is_secret=True,
                check=_generic_check),
)

_ENV_NAME = re.compile(r"^\.env(?:\.[\w.-]+)?$", re.I)
_ENV_SAFE_SUFFIX = (".example", ".sample", ".template", ".dist", ".tmpl", ".tpl", ".defaults")
_ENV_LINE = re.compile(r"^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*(?P<v>.*?)\s*$")


def _dotenv_finding(ctx: FileContext) -> Finding | None:
    for i, line in enumerate(ctx.lines[:5000], 1):
        m = _ENV_LINE.match(line)
        if not m:
            continue
        v = m.group("v")
        if v[:1] in ("'", '"') and v[-1:] == v[:1] and len(v) >= 2:
            v = v[1:-1]
        else:
            v = v.split(" #", 1)[0].strip()
        if len(v) >= 8 and not is_placeholder(v) and "${" not in v and shannon_entropy(v) >= 3.5:
            return Finding.from_rule(SEC014, ctx, i, line, secret=v)
    return None


class SecretsDetector(Detector):
    id = "secrets"
    name = "Committed secrets"
    category = Category.SECRETS
    checks = CHECKS

    def scan_file(self, ctx: FileContext) -> Iterable[Finding]:
        out = list(scan_specs(SPECS, ctx))
        name = ctx.basename
        if _ENV_NAME.match(name) and not name.lower().endswith(_ENV_SAFE_SUFFIX):
            f = _dotenv_finding(ctx)
            if f:
                out.append(f)
        return [self._locate(f, ctx) for f in out]

    @staticmethod
    def _locate(f: Finding, ctx: FileContext) -> Finding:
        if ctx.is_doc:  # catalog: keys in docs are still reported, confidence L
            f = f.replace(confidence=CL)
        return adjust_for_location(f, ctx)


DETECTORS = (SecretsDetector,)
