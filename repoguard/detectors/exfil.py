"""CRD001-CRD010 (credential theft sources), EXF001-EXF010 (exfiltration channels / network sinks)
and PHI001-PHI005 (API-key phishing). Static only: regexes plus `ast` parsing, nothing is executed."""

from __future__ import annotations

import ast
import ipaddress
import re
from collections.abc import Iterable, Iterator
from typing import Any
from urllib.parse import urlsplit

from .. import tags as T
from ..context import FileContext
from ..detector import Detector, RuleInfo
from ..models import Category, Confidence, Finding, Severity
from ..pyast import (call_name, calls_in_scope, const_str, dotted_name, enclosing_functions, import_aliases,
                     iter_calls, parse, segment)
from ..rules import Rule
from ..textutil import is_placeholder
from .secrets import PatternSpec, adjust_for_location, is_rule_list_file, lower_confidence, scan_specs

C, H, M, L, I = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO
CH, CM, CL = Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW
_CAT = Category.EXFILTRATION

CODE_LANGS = frozenset({
    "python", "javascript", "typescript", "shell", "powershell", "batch", "vbscript", "ruby", "go", "rust", "java",
    "kotlin", "csharp", "c", "cpp", "php", "perl", "lua", "swift", "scala", "groovy", "r", "dart", "elixir", "nim",
    "zig", "make", "dockerfile", "yaml",
})
HTMLISH_EXT = frozenset({".html", ".htm", ".php", ".vue", ".svelte", ".jsx", ".tsx", ".hta", ".ejs", ".hbs"})


def _info(rid: str, title: str, sev: Severity, conf: Confidence, tags: Iterable[str], desc: str, rec: str) -> RuleInfo:
    return RuleInfo(rid, title, sev, conf, _CAT, desc, rec, frozenset(tags))


def _rule(rid: str, title: str, pattern: str, sev: Severity, conf: Confidence, tags: Iterable[str],
          keywords: tuple[str, ...], desc: str, rec: str, **kw: Any) -> Rule:
    return Rule(rid, title, pattern, sev, conf, _CAT, desc, rec, frozenset(tags), keywords, **kw)


_BARE_PATH = re.compile(r"^[\s!/*\w.~\\-]*$")


def _not_bare_path(m: re.Match[str], ctx: FileContext) -> bool:
    """Ignore-file style lines (`.npmrc`, `**/.aws/credentials`) list paths, they do not read them."""
    return not _BARE_PATH.match(m.string)


# =======================================================================================
# CRD - credential theft sources
# =======================================================================================
_CRD = frozenset({T.READS_CREDENTIALS})
_CRD_REC = ("Find out why this code touches credential stores. Unless it is a tool you trust for exactly this "
            "purpose, do not install or run it.")

CRD001 = _rule("CRD001", "Reads SSH keys/config",
               r"\.ssh[/\\]+(?:id_\w+|authorized_keys|config\b|known_hosts)"
               r"|(?:home|expanduser|homedir|userprofile)[^\n]{0,80}['\"]~?[/\\]{0,2}\.ssh\b",
               M, CM, _CRD, (".ssh",), "Code references private SSH keys or the ~/.ssh directory.", _CRD_REC,
               flags=re.I, validator=_not_bare_path)
CRD002 = _rule("CRD002", "Reads CLI / cloud / AI-tool credentials",
               r"\.aws[/\\]+credentials|\.azure[/\\]|application_default_credentials\.json|\bgh[/\\]+hosts\.ya?ml"
               r"|\.docker[/\\]+config\.json|\.kube[/\\]+config|\.npmrc\b|\.pypirc\b|\.git-credentials|\.netrc\b"
               r"|\.claude[/\\]+\.credentials\.json|\.codex[/\\]+auth\.json|\.config[/\\]+(?:openai|anthropic|gcloud)\b",
               L, CM, _CRD, (".aws", ".azure", "application_default_credentials", "hosts.y", ".docker", ".kube",
                            ".npmrc", ".pypirc", ".git-credentials", ".netrc", ".credentials.json", "auth.json",
                            ".config"),
               "Code references credential files of cloud CLIs, package managers or AI tools.", _CRD_REC,
               flags=re.I, validator=_not_bare_path)
CRD003 = _rule("CRD003", "Reads browser password/cookie stores",
               r"['\"/\\](?:Login Data|Web Data|Local State)['\"]|key4\.db|logins\.json|cookies\.sqlite"
               r"|(?:Google[/\\]+Chrome|google-chrome|BraveSoftware[/\\]+Brave-Browser|Microsoft[/\\]+Edge)[/\\]+"
               r"(?:User Data|Default|Profile)|Opera Software[/\\]+Opera|Firefox[/\\]+Profiles|CryptUnprotectData"
               r"|\bos_crypt\b|\[['\"]encrypted_key['\"]\]",
               H, CH, _CRD, ("login data", "web data", "local state", "key4.db", "logins.json", "cookies.sqlite",
                            "chrome", "brave", "edge", "opera software", "firefox", "cryptunprotectdata", "os_crypt",
                            "encrypted_key"),
               "Code references browser credential/cookie databases or their decryption keys (infostealer behaviour).",
               _CRD_REC, validator=_not_bare_path)
CRD004 = _rule("CRD004", "Reads cryptocurrency wallets",
               r"wallet\.dat|(?:Exodus|Electrum|Atomic)[/\\]+(?:exodus\.wallet|wallets|Local Storage)|\bAtomic Wallet\b"
               r"|nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa",
               H, CM, _CRD, ("wallet", "exodus", "electrum", "atomic", "nkbihfbeogaeaoehlefnkodbefgpgknn",
                            "bfnaelmomeimhlpmgjnjophhpkkoljpa"),
               "Code references wallet files or MetaMask/Phantom extension storage.", _CRD_REC,
               validator=_not_bare_path)
CRD005 = _rule("CRD005", "Reads Discord/Telegram/Steam sessions",
               r"discord(?:canary|ptb)?[/\\]+Local Storage[/\\]+leveldb|dQw4w9WgXcQ:|Telegram Desktop[/\\]+tdata"
               r"|\btdata[/\\]+(?:key_data|D877F783D5D3EF8C)|['\"/\\]ssfn",
               H, CH, _CRD, ("local storage", "dqw4w9wgxcq:", "tdata", "ssfn"),
               "Code references Discord token storage, Telegram tdata or Steam ssfn session files.", _CRD_REC,
               flags=re.I, validator=_not_bare_path)
CRD010 = _rule("CRD010", "OS credential dump",
               r"/etc/shadow\b|\breg(?:\.exe)?[ \t]+save[ \t]+HKLM\\{1,2}(?:SAM|SYSTEM|SECURITY)\b"
               r"|comsvcs(?:\.dll)?.{0,40}MiniDump|procdump.{0,20}lsass|\bsekurlsa\b",
               C, CH, {T.READS_CREDENTIALS, T.BLOCK_TRIGGER}, ("/etc/shadow", "reg", "comsvcs", "procdump", "sekurlsa"),
               "Reads /etc/shadow, dumps the SAM/SYSTEM hives or LSASS memory (credential dumping).",
               "Do not run this. Credential dumping has no place in a normal project.", flags=re.I)

CRD006 = _info("CRD006", "Reads OS keychain / credential vault", M, CM, _CRD,
               "Code queries the macOS keychain, Windows Credential Manager or the Secret Service.", _CRD_REC)
CRD007 = _info("CRD007", "Dumps the whole environment", M, CM, {T.READS_CREDENTIALS, T.ENV_HARVEST},
               "Code copies or serialises every environment variable (tokens and keys live there).", _CRD_REC)
CRD008 = _info("CRD008", "Reads the clipboard", M, CM, {T.READS_CREDENTIALS, T.SURVEILLANCE},
               "Code reads clipboard contents (passwords, seed phrases, addresses are often copied).", _CRD_REC)
CRD009 = _info("CRD009", "Sweeps the home directory for secrets", H, CM, _CRD,
               "Code walks the home directory looking for several kinds of secret files.", _CRD_REC)

_CRYPTO_ADDR = re.compile(r"\b(?:bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40}|T[1-9A-HJ-NP-Za-km-z]{33})\b")
_CRYPTO_HINT = re.compile(r"bc1|\[13\]|0x\[|bitcoin|ethereum|monero|\bbtc\b|\beth\b|\bxmr\b|\busdt\b")
_CLIP_WRITE = re.compile(r"pyperclip\.copy|setclipboarddata|set-clipboard|clipboard\.writetext|clipboard\.settext|\bpbcopy\b|\bclip\.exe\b|xclip[^\n]{0,30}-selection")


def _clipper_check(m: re.Match[str], ctx: FileContext) -> dict[str, Any] | None:
    low = ctx.lower
    if _CLIP_WRITE.search(low) and (_CRYPTO_HINT.search(low) or _CRYPTO_ADDR.search(ctx.text)):
        return {"severity": H, "description": "Clipboard is read and rewritten next to crypto-address logic "
                                              "(clipboard hijacker / 'clipper')."}
    return {}


def _p(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


CRD_SPECS = (
    PatternSpec(CRD006, _p(r"\bsecurity[ \t]+(?:find-generic-password|find-internet-password|dump-keychain)"
                           r"|\bCredEnumerate\w*|\bcmdkey(?:\.exe)?[ \t]+/list|\bvaultcmd\b|\bsecret-tool[ \t]+lookup",
                           re.I), ("security", "credenumerate", "cmdkey", "vaultcmd", "secret-tool")),
    PatternSpec(CRD006, _p(r"\bkeyring\.get_password\("), ("keyring",), confidence=CL),
    PatternSpec(CRD007, _p(r"JSON\.stringify\(\s*process\.env\s*[,)]|Object\.(?:entries|keys|values)\(\s*process\.env\s*\)"),
                ("process.env",), languages=frozenset({"javascript", "typescript", "html"})),
    PatternSpec(CRD007, _p(r"\b(?:env|printenv)\b[ \t]*\||\b(?:Get-ChildItem|gci|dir|ls)[ \t]+env:", re.I),
                ("env",), languages=frozenset({"shell", "dockerfile", "make", "yaml", "powershell", "batch"})),
    PatternSpec(CRD008, _p(r"\bpyperclip\.paste\(|\bGetClipboardData\b|\bGet-Clipboard\b|navigator\.clipboard\.readText"
                           r"|\bclipboard\.readText\(|\bClipboard\.GetText\(|\bpbpaste\b|\bxclip\b[^\n]{0,30}[ \t]-o\b"),
                ("pyperclip", "getclipboarddata", "get-clipboard", "readtext", "gettext", "pbpaste", "xclip"),
                check=_clipper_check),
)

_ENV_ITER = frozenset({"os.environ.items", "os.environ.keys", "os.environ.values"})


def _crd007_python(ctx: FileContext, tree: ast.Module) -> Iterator[Finding]:
    aliases = import_aliases(tree)

    def is_environ(n: ast.AST) -> bool:
        return dotted_name(n, aliases) == "os.environ"

    seen: set[int] = set()
    for node in ast.walk(tree):
        line: int | None = None
        conf = CM
        if isinstance(node, ast.Call):
            name = call_name(node, aliases)
            if name == "os.environ.copy":
                line = node.lineno
            elif name in ("dict", "json.dumps", "str", "repr") and node.args and is_environ(node.args[0]):
                line = node.lineno
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            it = node.iter
            if is_environ(it) or (isinstance(it, ast.Call) and call_name(it, aliases) in _ENV_ITER):
                line = it.lineno
                if isinstance(node, ast.comprehension) and node.ifs:
                    conf = CL  # filtered (e.g. prefix-selected) env vars
        if line is None or line in seen:
            continue
        seen.add(line)
        text = ctx.line_text(line)
        compact = text.replace(" ", "").lower()
        if "env=" in compact or "env" in compact.split("=", 1)[0]:
            conf = CL  # building a child-process environment (env=..., full_env = dict(os.environ))
        yield Finding.from_rule(CRD007, ctx, line, text, confidence=conf)
        if len(seen) >= 3:
            return


_SWEEP_TARGETS = (".env", "id_rsa", ".pem", "wallet", "credentials", ".kdbx", "token")
_SWEEP_WALK = re.compile(r"os\.walk|\.rglob\(|glob\.glob|\bglob\(|\biglob|scandir|listdir|readdirsync|readdir\("
                         r"|walkdir|get-childitem|\bfind[ \t]+[~$/\"]|fast-glob|globby|\bwalk\(")
_SWEEP_HOME = re.compile(r"expanduser|path\.home|homedir|userprofile|\$home|env:home|['\"]~|getenv\(['\"]home"
                         r"|environ\[['\"]home|appdata")
_QUOTED = re.compile(r"['\"]([^'\"\n]{1,60})['\"]")


def _crd009(ctx: FileContext) -> Iterator[Finding]:
    low = ctx.lower
    if sum(1 for t in _SWEEP_TARGETS if t in low) < 3 or not _SWEEP_WALK.search(low) or not _SWEEP_HOME.search(low):
        return
    per_line: list[set[str]] = []
    for line in ctx.lines[:20000]:
        found: set[str] = set()
        if "'" in line or '"' in line:
            for q in _QUOTED.findall(line.lower()):
                found.update(t for t in _SWEEP_TARGETS if t in q)
        per_line.append(found)
    for i in range(len(per_line)):
        if not per_line[i]:
            continue
        union: set[str] = set()
        for s in per_line[i : i + 6]:
            union |= s
        if len(union) >= 3:
            yield Finding.from_rule(CRD009, ctx, i + 1, ctx.line_text(i + 1),
                                    description=f"Home-directory walk looking for: {', '.join(sorted(union))}.")
            return


class CredentialTheftDetector(Detector):
    id = "cred_theft"
    name = "Credential theft sources"
    category = _CAT
    rules = (CRD001, CRD002, CRD003, CRD004, CRD005, CRD010)
    checks = (CRD006, CRD007, CRD008, CRD009)

    def scan_file(self, ctx: FileContext) -> Iterable[Finding]:
        out = list(super().scan_file(ctx))
        out.extend(scan_specs(CRD_SPECS, ctx))
        if ctx.language == "python" and "environ" in ctx.lower:
            tree = parse(ctx)
            if tree is not None:
                out.extend(_crd007_python(ctx, tree))
        out.extend(_crd009(ctx))
        return [self._post(f, ctx) for f in out]

    @staticmethod
    def _post(f: Finding, ctx: FileContext) -> Finding:
        if f.rule_id == "CRD010" and (ctx.context_kind is not None or ctx.is_doc or is_rule_list_file(ctx)):
            # a mention in docs/tests/rule lists must not force BLOCK on its own
            f = f.replace(tags=tuple(t for t in f.tags if t != T.BLOCK_TRIGGER), confidence=lower_confidence(f.confidence))
        return adjust_for_location(f, ctx)


# =======================================================================================
# EXF - exfiltration channels
# =======================================================================================
_EXF = frozenset({T.EXFIL_CHANNEL, T.NETWORK_SEND, T.NO_DAMPEN})
_EXF_REC = ("Find out what data is sent to this endpoint and why. Hard-coded drop points are a hallmark of "
            "stealers: do not install unless you can explain it.")


def _not_placeholder(m: re.Match[str], ctx: FileContext) -> bool:
    return not is_placeholder(m.group(0))


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(ip.is_global) and not ip.is_multicast


def _public_ip(m: re.Match[str], ctx: FileContext) -> bool:
    return is_public_ip(m.group("ip"))  # looked up at call time (tests patch it to stay on 203.0.113.x)


EXF001 = _rule("EXF001", "Discord webhook", r"discord(?:app)?\.com/api/webhooks/\d{17,20}/(?P<tok>[\w-]{60,})",
               H, CH, _EXF, ("discord",), "A Discord webhook URL: a classic stealer drop point.", _EXF_REC,
               secret_group="tok")
EXF002 = _rule("EXF002", "Telegram bot API", r"api\.telegram\.org/bot", H, CH, _EXF, ("api.telegram.org",),
               "Telegram Bot API used to send messages/files: a common exfiltration channel.", _EXF_REC,
               require_in_file=(r"send(?:Message|Document|Photo|Video|Audio)|getUpdates",))
EXF003 = _rule("EXF003", "Slack/Teams webhook",
               r"hooks\.slack\.com/(?:services|workflows|triggers)/[\w/-]{20,}|\.webhook\.office\.com\b",
               M, CM, _EXF, ("hooks.slack.com", "webhook.office.com"),
               "A Slack or Microsoft Teams incoming webhook URL.", _EXF_REC, validator=_not_placeholder)
EXF004 = _rule("EXF004", "Paste site / anonymous file drop",
               r"\bpastebin\.com/(?:api|raw)\b|\bpaste\.ee\b|\bhastebin\b|\btransfer\.sh\b|\bfile\.io\b|\b0x0\.st\b"
               r"|\bgofile\.io\b|\bcatbox\.moe\b|\btemp\.sh\b|\bbashupload\b|\banonfiles\b|\bufile\.io\b",
               H, CM, _EXF, ("pastebin", "paste.ee", "hastebin", "transfer.sh", "file.io", "0x0.st", "gofile",
                            "catbox", "temp.sh", "bashupload", "anonfiles", "ufile.io"),
               "A paste site or anonymous file-drop service (used to stage payloads or dump stolen data).",
               _EXF_REC, flags=re.I)
EXF005 = _rule("EXF005", "Tunnel / request catcher / OAST endpoint",
               r"\bngrok(?:-free)?\.(?:io|app|dev)\b|\btrycloudflare\.com\b|\bserveo\.net\b|\blocalhost\.run\b"
               r"|\bloca\.lt\b|\bwebhook\.site\b|\brequestbin\b|\bpipedream\.net\b|\binteract\.sh\b"
               r"|\boast\.(?:fun|me|pro|live|site|online)\b|\bburpcollaborator\b|\bbeeceptor\b",
               H, CM, _EXF, ("ngrok", "trycloudflare", "serveo", "localhost.run", "loca.lt", "webhook.site",
                            "requestbin", "pipedream", "interact.sh", "oast.", "burpcollaborator", "beeceptor"),
               "A tunnel, request-catcher or out-of-band (OAST) endpoint.", _EXF_REC, flags=re.I)
EXF006 = _rule("EXF006", "URL with a raw public IP",
               r"\b(?:https?|wss?|tcp|ftp)://(?P<ip>(?:\d{1,3}\.){3}\d{1,3})(?![\d.])",
               M, CM, _EXF, ("://",), "A URL pointing at a hard-coded public IP address instead of a domain.",
               _EXF_REC, flags=re.I, validator=_public_ip)
EXF008 = _rule("EXF008", "Dynamic DNS host",
               r"\b(?:duckdns\.org|no-ip\.(?:com|org|biz|info)|noip\.com|ddns\.net|hopto\.org|zapto\.org|portmap\.io)\b",
               M, CM, _EXF, ("duckdns", "no-ip", "noip", "ddns.net", "hopto", "zapto", "portmap"),
               "A dynamic-DNS hostname (cheap, disposable C2/exfil infrastructure).", _EXF_REC, flags=re.I)

EXF007 = _info("EXF007", "DNS exfiltration", H, CM, _EXF,
               "A DNS lookup of a hostname built at runtime from (encoded) data: data smuggled out via DNS.", _EXF_REC)
EXF009 = _info("EXF009", "SMTP with hard-coded credentials", M, CM, _EXF,
               "Mail is sent with credentials hard-coded in the source (stealers mail loot to themselves).", _EXF_REC)
EXF010 = _info("EXF010", "Network sink", I, CH, {T.NETWORK_SEND},
               "Code that sends/fetches data over the network (informational, used for correlation).",
               "No action needed on its own; it matters when combined with credential reads or decoding.")

_SHELLISH = frozenset({"shell", "powershell", "batch", "dockerfile", "make", "yaml"})
EXF_SPECS = (
    PatternSpec(EXF007, _p(r"\bdns\.(?:resolve\w*|lookup)\(\s*(?:`[^`\n]{0,120}\$\{|[\w.$]+\s*\+|['\"][^'\"\n]{0,80}['\"]\s*\+)"),
                ("dns.",), languages=frozenset({"javascript", "typescript"}), max_per_file=2,
                check=lambda m, c: {} if re.search(r"base64|hex|btoa", c.lower) else None),
    PatternSpec(EXF007, _p(r"\b(?:nslookup|dig|host|Resolve-DnsName)[ \t]+[^\n|;]{0,60}\$(?:\(|\{|[A-Za-z_])[^\n|;]{0,60}\.[A-Za-z]"),
                ("nslookup", "dig", "host", "resolve-dnsname"), languages=_SHELLISH, max_per_file=2,
                check=lambda m, c: {} if re.search(r"base64|xxd|\bod |hexdump|tobase64string", c.lower) else None),
    PatternSpec(EXF009, _p(r"\bauth\s{0,20}:\s{0,20}\{\s{0,20}user\s{0,20}:\s{0,20}['\"][^'\"\n]{1,100}['\"]\s{0,20},"
                           r"\s{0,20}pass\s{0,20}:\s{0,20}['\"](?P<pw>[^'\"\n]{4,100})['\"]"),
                ("nodemailer",), require=("nodemailer",), group="pw", is_secret=True, max_per_file=2),
    PatternSpec(EXF010, _p(r"\brequests\.(?:post|put|patch)\(|\bhttpx\.(?:post|put|patch)\(|\bhttp\.client\b|\.connect\(\("
                           r"|\bsocket\.create_connection\(|\bXMLHttpRequest\b|\bhttps?\.request\(|\bnavigator\.sendBeacon\("
                           r"|\bcurl\b[^\n]{0,80}(?:[ \t]-d\b|[ \t]-F\b|--data|[ \t]-T\b)|\bwget\b[^\n]{0,40}--post"),
                ("requests.", "httpx.", "http.client", ".connect((", "create_connection", "xmlhttprequest",
                 "request(", "sendbeacon", "curl", "wget"), max_per_file=3),
    PatternSpec(EXF010, _p(r"\brequests\.get\(|\burlopen\(|\burllib\.request\b|(?<![.\w])fetch\(|\b(?:window|globalThis)\.fetch\("
                           r"|\baxios\b|\bInvoke-(?:WebRequest|RestMethod)\b|\b(?:iwr|irm)\b|Net\.WebClient|\bhttpx\.get\("
                           r"|\baiohttp\b|\bWebClient\(\)\.Download"),
                ("requests.get", "urlopen", "urllib.request", "fetch(", "axios", "invoke-webrequest", "invoke-restmethod",
                 "iwr", "irm", "webclient", "httpx.get", "aiohttp"), extra_tags=(T.DOWNLOAD,), max_per_file=3),
)

_DNS_LAST = frozenset({"gethostbyname", "gethostbyname_ex", "getaddrinfo", "resolve", "query", "nslookup"})
_ENC_HINT = re.compile(r"b64encode|b32encode|hexlify|\.hex\(\)|base64|binascii|encode\(\s*['\"]hex")


def _const_parts(node: ast.AST) -> list[str]:
    return [n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)]


def _dynamic_host(arg: ast.AST) -> bool:
    if isinstance(arg, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in arg.values) and "." in "".join(_const_parts(arg))
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, (ast.Add, ast.Mod)) and const_str(arg) is None:
        return "." in "".join(_const_parts(arg))
    if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute) and arg.func.attr == "format":
        base = const_str(arg.func.value)
        return base is not None and "." in base
    return False


def _exf_python(ctx: FileContext, tree: ast.Module) -> Iterator[Finding]:
    aliases = import_aliases(tree)
    low = ctx.lower
    calls = list(iter_calls(tree))
    if _ENC_HINT.search(low):
        for call in calls:
            name = call_name(call, aliases) or ""
            last = name.rsplit(".", 1)[-1]
            if last not in _DNS_LAST or not call.args:
                continue
            if last in ("resolve", "query") and not (name.startswith("dns.") or "resolver" in name):
                continue
            if _dynamic_host(call.args[0]):
                yield Finding.from_rule(EXF007, ctx, call.lineno, segment(ctx, call))
                break
    if "smtp" in low:
        has_smtp = any(call_name(c, aliases) in ("smtplib.SMTP", "smtplib.SMTP_SSL") for c in calls)
        if has_smtp:
            for c in calls:
                if isinstance(c.func, ast.Attribute) and c.func.attr == "login" and len(c.args) >= 2:
                    user, pw = const_str(c.args[0]), const_str(c.args[1])
                    if user and pw and len(pw) >= 4 and not is_placeholder(pw):
                        yield Finding.from_rule(EXF009, ctx, c.lineno, segment(ctx, c), secret=pw)
                        break


class ExfilDetector(Detector):
    id = "exfil"
    name = "Exfiltration channels"
    category = _CAT
    rules = (EXF001, EXF002, EXF003, EXF004, EXF005, EXF006, EXF008)
    checks = (EXF007, EXF009, EXF010)

    def scan_file(self, ctx: FileContext) -> Iterable[Finding]:
        out = list(super().scan_file(ctx))
        out.extend(scan_specs(EXF_SPECS, ctx))
        if ctx.language == "python" and ("smtp" in ctx.lower or _ENC_HINT.search(ctx.lower)):
            tree = parse(ctx)
            if tree is not None:
                out.extend(_exf_python(ctx, tree))
        return [self._post(f, ctx) for f in out]

    @staticmethod
    def _post(f: Finding, ctx: FileContext) -> Finding:
        if f.rule_id in ("EXF001", "EXF003") and (ctx.is_doc or ctx.is_test) and f.severity > M:
            f = f.replace(severity=M)  # catalog: webhooks in docs/tests still reported at M (they are live)
        return adjust_for_location(f, ctx)


# =======================================================================================
# PHI - API-key phishing
# =======================================================================================
_PHI = frozenset({T.PHISHING})
_PHI_REC = "Never paste API keys, tokens or seed phrases into this tool; it sends them to a third party."

_GOOGLE = ("googleapis.com", "google.com", "gstatic.com", "googleusercontent.com", "google-analytics.com",
           "firebaseio.com", "cloudfunctions.net", "run.app", "appspot.com")
PROVIDER_DOMAINS: dict[str, tuple[str, ...]] = {
    "ANTHROPIC": ("anthropic.com", "claude.ai"), "CLAUDE": ("anthropic.com", "claude.ai"),
    "OPENAI": ("openai.com",), "GEMINI": _GOOGLE, "GOOGLE": _GOOGLE, "GROQ": ("groq.com",),
    "MISTRAL": ("mistral.ai",), "COHERE": ("cohere.ai", "cohere.com"),
    "HF": ("huggingface.co", "hf.co"), "HUGGINGFACE": ("huggingface.co", "hf.co"),
    "GITHUB": ("github.com", "githubusercontent.com", "ghcr.io", "codecov.io", "coveralls.io"),
    "GH": ("github.com", "githubusercontent.com", "ghcr.io"),
    "XAI": ("x.ai",), "DEEPSEEK": ("deepseek.com",), "OPENROUTER": ("openrouter.ai",),
    "TOGETHER": ("together.xyz", "together.ai"), "PERPLEXITY": ("perplexity.ai",), "REPLICATE": ("replicate.com",),
}
AI_OFFICIAL = ("anthropic.com", "openai.com", "googleapis.com", "x.ai", "deepseek.com", "mistral.ai", "cohere.ai",
               "cohere.com", "perplexity.ai", "replicate.com", "huggingface.co")
GATEWAYS = ("openrouter.ai", "openai.azure.com", "azure.com", "together.xyz", "together.ai", "groq.com", "localhost",
            "127.0.0.1", "0.0.0.0", "ollama", "litellm", "cloudflare.com", "portkey.ai", "helicone.ai",
            "amazonaws.com", "deepinfra.com", "fireworks.ai", "anyscale.com")
ALLOW_HOSTS = tuple(sorted({d for v in PROVIDER_DOMAINS.values() for d in v} | set(AI_OFFICIAL) | set(GATEWAYS) | {
    "gitlab.com", "bitbucket.org", "pypi.org", "npmjs.com", "npmjs.org", "readthedocs.io", "readthedocs.org",
    "shields.io", "python.org", "microsoft.com", "apple.com", "stripe.com"}))


def host_in(host: str | None, domains: Iterable[str]) -> bool:
    if not host:
        return False
    host = host.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in domains)


def _host(url: str | None) -> str | None:
    if not url or not url.lower().startswith(("http://", "https://")):
        return None
    try:
        return urlsplit(url).hostname or None
    except ValueError:
        return None


PHI001 = _info("PHI001", "Prompts for a secret, then sends it to a third party", H, CM, _PHI,
               "The program asks the user for an API key/token/password/seed and sends data to a host that is not "
               "the matching provider.", _PHI_REC)
PHI002 = _info("PHI002", "HTML form collects API keys for an external host", H, CM, _PHI,
               "A web form asks for API keys/seed phrases and submits them to an external host.", _PHI_REC)
PHI003 = _info("PHI003", "API key sent to the wrong host", H, CM, _PHI,
               "A provider API key/token is used in a request to a host that does not belong to that provider.",
               _PHI_REC)
PHI004 = _info("PHI004", "Brand login page clone", H, CM, _PHI,
               "An HTML page imitates a well-known login page and posts the password somewhere else.", _PHI_REC)
PHI005 = _info("PHI005", "Docs ask you to submit secrets to a website", M, CL, _PHI,
               "Documentation asks readers to paste/enter API keys, tokens or seed phrases on a third-party site.",
               _PHI_REC)

_SECRET_PROMPT = re.compile(r"(?i)api[ _-]?key|token|secret|password|seed|mnemonic|private key")
_INPUT_FUNCS = frozenset({"input", "raw_input", "getpass", "getpass.getpass", "click.prompt", "typer.prompt",
                          "rich.prompt.Prompt.ask", "Prompt.ask"})
_PY_SINK_LAST = frozenset({"post", "put", "patch", "get", "request", "urlopen", "Request", "fetch"})


def _url_prefix(node: ast.AST | None, consts: dict[str, str]) -> str | None:
    if node is None:
        return None
    s = const_str(node)
    if s is not None:
        return s
    if isinstance(node, ast.Name):
        return consts.get(node.id)
    if isinstance(node, ast.JoinedStr):
        out = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                out.append(v.value)
            else:
                break
        return "".join(out) or None
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return _url_prefix(node.left, consts)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return const_str(node.func.value)
    return None


def _phi001(ctx: FileContext, tree: ast.Module) -> Iterator[Finding]:
    aliases = import_aliases(tree)
    consts: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            v = const_str(node.value)
            if v is not None:
                consts[node.targets[0].id] = v
    for scope in enclosing_functions(tree):
        calls = calls_in_scope(scope, aliases)
        prompt_call = None
        for name, c in calls:
            if name in _INPUT_FUNCS:
                arg = c.args[0] if c.args else next((k.value for k in c.keywords if k.arg in ("prompt", "text")), None)
                text = const_str(arg) if arg is not None else None
                if text and _SECRET_PROMPT.search(text):
                    prompt_call = c
                    break
        if prompt_call is None:
            continue
        for name, c in calls:
            if name.rsplit(".", 1)[-1] not in _PY_SINK_LAST:
                continue
            url_node = c.args[0] if c.args else next((k.value for k in c.keywords if k.arg == "url"), None)
            host = _host(_url_prefix(url_node, consts))
            if host and not host_in(host, ALLOW_HOSTS):
                yield Finding.from_rule(PHI001, ctx, prompt_call.lineno, segment(ctx, prompt_call),
                                        description=f"Asks for a secret, then sends data to {host}.")
                return


_INPUT_TAG = re.compile(r"<input\b[^>]{0,500}>", re.I)
_KEY_ATTR = re.compile(r"(?:name|id|placeholder|aria-label)\s*=\s*['\"]?[^'\">]{0,80}?(?:api[ _-]?key|apikey|secret|"
                       r"seed[ _-]?phrase|mnemonic|private[ _-]?key|recovery[ _-]?phrase|\bsk-)", re.I)
_FORM_TARGET = re.compile(r"action\s*=\s*['\"]?(?P<a>https?://[^'\"\s>]+)"
                          r"|(?:fetch|post|ajax|open|sendBeacon)\([^)\n]{0,60}?[`'\"](?P<b>https?://[^`'\"\s)]+)", re.I)


def _external_targets(ctx: FileContext, allowed: Iterable[str]) -> list[str]:
    hosts = []
    for m in _FORM_TARGET.finditer(ctx.text[:1_000_000]):
        h = _host(m.group("a") or m.group("b"))
        if h and not host_in(h, allowed):
            hosts.append(h)
    return hosts


def _phi002(ctx: FileContext) -> Iterator[Finding]:
    if "<input" not in ctx.lower:
        return
    text = ctx.text[:1_000_000]
    for m in _INPUT_TAG.finditer(text):
        if _KEY_ATTR.search(m.group(0)):
            hosts = _external_targets(ctx, ALLOW_HOSTS)
            if hosts:
                yield Finding.from_rule(PHI002, ctx, ctx.line_of(m.start()), m.group(0),
                                        description=f"A form asks for API keys/seed phrases and submits to {hosts[0]}.")
            return


_KEYVAR = re.compile(r"\b(?P<prov>ANTHROPIC|CLAUDE|OPENAI|GEMINI|GOOGLE|GROQ|MISTRAL|COHERE|HF|HUGGINGFACE|GITHUB|GH|"
                     r"XAI|DEEPSEEK|OPENROUTER|TOGETHER|PERPLEXITY|REPLICATE)_(?:API_KEY|API_TOKEN|ACCESS_TOKEN|"
                     r"AUTH_TOKEN|TOKEN|KEY|PAT)\b")
_SINK_HINT = re.compile(r"(?i)\b(?:post|put|patch|get|fetch|request|urlopen|sendbeacon)\s*\(|\bcurl\b|\bwget\b"
                        r"|\binvoke-(?:restmethod|webrequest)\b|\baxios\b|\bhttpx\b|\brequests\b")
_URL_HOST = re.compile(r"https?://(?P<host>[A-Za-z0-9.-]+)")
_BASE_URL = re.compile(r"(?i)\b(?:base_url|baseurl|api_base|api_base_url|openai_base_url|openai_api_base|"
                       r"anthropic_base_url|anthropic_api_url)\b['\"]?[ \t]*[:=][ \t]*['\"](?P<url>https?://[^'\"\s]+)")
_AI_HINT = re.compile(r"openai|anthropic|claude|gemini|chat\.completions|messages\.create|\bllm\b")


def _phi003(ctx: FileContext) -> Iterator[Finding]:
    low = ctx.lower
    lines = ctx.lines
    flagged: set[int] = set()
    if ("_key" in low or "_token" in low or "_pat" in low) and "http" in low:
        hits = 0
        for i, line in enumerate(lines[:50000]):
            km = _KEYVAR.search(line)
            if not km:
                continue
            hits += 1
            if hits > 30:
                break
            lo, hi = max(0, i - 4), min(len(lines), i + 5)
            window = lines[lo:hi]
            if not any(_SINK_HINT.search(w) for w in window):
                continue
            hosts = [(lo + k, hm.group("host")) for k, w in enumerate(window) for hm in _URL_HOST.finditer(w)]
            if not hosts:
                continue
            ok = PROVIDER_DOMAINS[km.group("prov")] + GATEWAYS
            if any(host_in(h, ok) for _, h in hosts):
                continue
            ln, host = hosts[0]
            if ln in flagged:
                continue
            flagged.add(ln)
            yield Finding.from_rule(PHI003, ctx, ln + 1, lines[ln],
                                    description=f"{km.group(0)} is used in a request to {host}, which is not a "
                                                f"{km.group('prov').title()} host.")
    if "http" in low and _AI_HINT.search(low):
        for m in _BASE_URL.finditer(ctx.text[:1_000_000]):
            host = _host(m.group("url"))
            if not host or host_in(host, AI_OFFICIAL):
                continue
            line = ctx.line_of(m.start())
            if line in flagged:
                continue
            gw = host_in(host, GATEWAYS)
            yield Finding.from_rule(
                PHI003, ctx, line, ctx.line_text(line), severity=I if gw else M,
                description=(f"API base URL points at the known gateway {host}." if gw else
                             f"API base URL is overridden to {host}; your provider key would be sent there."))


_BRANDS: dict[str, tuple[str, ...]] = {
    "github": ("github.com",), "google": ("google.com",), "gmail": ("google.com",),
    "microsoft": ("microsoft.com", "microsoftonline.com", "live.com", "office.com"),
    "outlook": ("microsoft.com", "microsoftonline.com", "live.com", "office.com"),
    "office 365": ("microsoft.com", "microsoftonline.com", "office.com"),
    "apple": ("apple.com", "icloud.com"), "icloud": ("apple.com", "icloud.com"),
    "binance": ("binance.com",), "metamask": ("metamask.io",), "coinbase": ("coinbase.com",),
    "paypal": ("paypal.com",),
}
_BRAND_RE = re.compile(r"\b(" + "|".join(re.escape(b) for b in _BRANDS) + r")\b", re.I)
_TITLE = re.compile(r"<title[^>]{0,100}>([^<]{0,300})</title>", re.I)
_PASSWORD_FIELD = re.compile(r"<input\b[^>]{0,300}type\s*=\s*['\"]?password", re.I)
_REL_PHP_ACTION = re.compile(r"action\s*=\s*['\"]?[\w./-]{0,80}\.php", re.I)


def _phi004(ctx: FileContext) -> Iterator[Finding]:
    low = ctx.lower
    if "password" not in low or "<title" not in low:
        return
    tm = _TITLE.search(ctx.text[:200_000])
    bm = _BRAND_RE.search(tm.group(1)) if tm else None
    pm = _PASSWORD_FIELD.search(ctx.text[:1_000_000])
    if not bm or not pm:
        return
    brand = bm.group(1).lower()
    hosts = _external_targets(ctx, _BRANDS[brand])
    line = ctx.line_of(pm.start())
    if hosts:
        yield Finding.from_rule(PHI004, ctx, line, pm.group(0),
                                description=f"Page titled like {bm.group(1)} posts the password to {hosts[0]}.")
    elif _REL_PHP_ACTION.search(ctx.text[:1_000_000]):
        yield Finding.from_rule(PHI004, ctx, line, pm.group(0), confidence=CL,
                                description=f"Page titled like {bm.group(1)} posts the password to a bundled PHP script.")


_SOCIAL = re.compile(r"(?i)\b(?:paste|enter|send|submit)\b[^\n]{0,40}?\b(?:api[ _-]?key|token|seed phrase|private key)")


def _phi005(ctx: FileContext) -> Iterator[Finding]:
    if not (ctx.is_doc or ctx.is_readme) or "http" not in ctx.lower:
        return
    lines = ctx.lines
    for i, line in enumerate(lines[:20000]):
        if not _SOCIAL.search(line):
            continue
        for w in lines[max(0, i - 2) : i + 3]:
            for hm in _URL_HOST.finditer(w):
                host = hm.group("host")
                if not host_in(host, ALLOW_HOSTS):
                    yield Finding.from_rule(PHI005, ctx, i + 1, line,
                                            description=f"Docs ask readers to submit secrets near a link to {host}.")
                    return


class PhishingDetector(Detector):
    id = "phishing"
    name = "API-key phishing"
    category = _CAT
    checks = (PHI001, PHI002, PHI003, PHI004, PHI005)

    def scan_file(self, ctx: FileContext) -> Iterable[Finding]:
        out: list[Finding] = []
        low = ctx.lower
        if ctx.language == "python" and "http" in low and ("input(" in low or "getpass" in low or "prompt" in low):
            tree = parse(ctx)
            if tree is not None:
                out.extend(_phi001(ctx, tree))
        htmlish = ctx.ext in HTMLISH_EXT or ctx.language == "html"
        if htmlish:
            out.extend(_phi002(ctx))
            out.extend(_phi004(ctx))
        if ctx.language in CODE_LANGS:
            out.extend(_phi003(ctx))
        out.extend(_phi005(ctx))
        return [adjust_for_location(f, ctx) for f in out]


DETECTORS = (CredentialTheftDetector, ExfilDetector, PhishingDetector)
