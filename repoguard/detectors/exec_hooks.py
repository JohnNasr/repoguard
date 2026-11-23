"""INS001-INS016: code that runs at install time (npm scripts, setup.py, build files...) or when a
folder is opened (VS Code tasks, devcontainers, JetBrains). Static only: nothing is executed.

The small pattern engine (`Pat`, `scan_pats`), `body_tags`, `parse_jsonc` and the pipe-to-shell
patterns are also used by cicd.py and malware.py."""

from __future__ import annotations

import ast
import json
import re
import tomllib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from .. import pyast
from .. import tags as T
from ..context import FileContext
from ..detector import Detector, RuleInfo
from ..models import Category, Confidence, Finding, Severity
from ..rules import iter_scan_units

S = Severity
C = Confidence
_CAT = Category.EXEC_HOOK


# ======================================================================================
# shared helpers
# ======================================================================================
def lower_conf(conf: Confidence, ctx: FileContext) -> Confidence:
    """std-FP: test/doc/vendored locations lower confidence one level (non-high-signal rules)."""
    if ctx.is_test or ctx.is_doc or ctx.is_vendored:
        return Confidence(max(int(Confidence.LOW), int(conf) - 1))
    return conf


@lru_cache(maxsize=1024)
def rx(pattern: str, flags: int = re.I) -> re.Pattern[str]:
    return re.compile(pattern, flags)


@dataclass(frozen=True, slots=True)
class Pat:
    """One alternative of a code-based rule: its own severity/confidence/tags."""

    pattern: str
    keywords: tuple[str, ...] = ()  # lowercase; the pattern is skipped unless one occurs in the file
    severity: Severity | None = None
    confidence: Confidence | None = None
    tags: tuple[str, ...] = ()
    note: str = ""
    exclude: str | None = None  # regex on the line: drop the match
    skip: bool = False  # a match consumes the line without producing a finding (allowlist)
    flags: int = re.I

    @property
    def regex(self) -> re.Pattern[str]:
        return rx(self.pattern, self.flags)


def _window(text: str, m: re.Match[str], pad: int = 80) -> str:
    return text[max(0, m.start() - pad) : m.end() + pad]


def find_line(ctx: FileContext, needle: str, start: int = 1, ci: bool = False) -> int:
    """First 1-based line number >= start containing needle (1 if absent)."""
    n = needle.lower() if ci else needle
    for i in range(max(1, start), len(ctx.lines) + 1):
        line = ctx.lines[i - 1]
        if n in (line.lower() if ci else line):
            return i
    return 1 if start <= 1 else start


def has_keyword(ctx: FileContext, kw: str) -> bool:
    """Substring test on ctx.lower, memoised per file (many rules share keywords)."""
    cache: dict[str, bool] = ctx.__dict__.setdefault("_rg_kwcache", {})
    hit = cache.get(kw)
    if hit is None:
        hit = cache[kw] = kw in ctx.lower
    return hit


def any_keyword(ctx: FileContext, kws: Iterable[str]) -> bool:
    return any(has_keyword(ctx, k) for k in kws)


def scan_pats(
    info: RuleInfo,
    ctx: FileContext,
    pats: Sequence[Pat],
    *,
    dampen: bool = True,
    max_findings: int = 5,
    extra_tags: tuple[str, ...] = (),
    line_filter: Any = None,
) -> list[Finding]:
    """Run pattern alternatives line by line; at most one finding per line (first matching Pat wins)."""
    live = [p for p in pats if not p.keywords or any_keyword(ctx, p.keywords)]
    if not live or not any(not p.skip for p in live):
        return []
    out: list[Finding] = []
    for n, (line_no, unit) in enumerate(iter_scan_units(ctx)):
        if n % 500 == 499 and ctx.deadline_exceeded():
            break
        if out and out[-1].line == line_no:
            continue
        if line_filter is not None and not line_filter(line_no, unit):
            continue
        for p in live:
            m = p.regex.search(unit)
            if not m:
                continue
            if p.exclude and rx(p.exclude).search(unit):
                continue
            if p.skip:
                break
            conf = p.confidence or info.confidence
            if dampen:
                conf = lower_conf(conf, ctx)
            desc = f"{info.description} ({p.note})" if p.note else info.description
            out.append(
                Finding.from_rule(
                    info, ctx, line_no, _window(unit, m),
                    severity=p.severity if p.severity is not None else info.severity,
                    confidence=conf, extra_tags=(*p.tags, *extra_tags), description=desc,
                )
            )
            break
        if len(out) >= max_findings:
            break
    return out


_TAG_DOWNLOAD = re.compile(
    r"\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|urlopen|urlretrieve|downloadfile|downloadstring|"
    r"axios|reqwest|ureq)\b|https?://|\brequests\.(?:get|post)|\bfetch\(|\bhttps?\.(?:get|request)\(",
)
_TAG_SEND = re.compile(
    r"\bcurl\b[^\n]{0,200}(?:\s-d\b|--data|\s-f\s|\s-t\s|--upload|-x\s*post)|requests\.(?:post|put)|"
    r"method\s*[:=]\s*[\"']post|\bnc\s+-?\w|uploadstring|uploadfile",
)
_TAG_EXEC = re.compile(
    r"\beval\b|\bexec\b|\bnode\s+-e\b|\bpython[0-9.]*\s+-c\b|\b(?:ba|z|da)?sh\s+-c\b|\|\s*(?:sudo\s+)?\w{0,8}sh\b|"
    r"\biex\b|invoke-expression|powershell[^\n]{0,40}\s-(?:e|enc|encodedcommand|c|command)\b|child_process|"
    r"subprocess|os\.system|start-process",
)
_TAG_DECODE = re.compile(r"base64|\batob\(|b64decode|frombase64string|xxd\s+-r|certutil[^\n]{0,20}-decode")


def body_tags(text: str) -> tuple[str, ...]:
    """Behaviour tags for a hook body (what the hook actually does)."""
    low = text.lower()
    out: list[str] = []
    if _TAG_DOWNLOAD.search(low):
        out.append(T.DOWNLOAD)
    if _TAG_SEND.search(low):
        out.append(T.NETWORK_SEND)
    if _TAG_EXEC.search(low):
        out.append(T.EXEC_DYNAMIC)
    if _TAG_DECODE.search(low):
        out.append(T.DECODE)
    return tuple(out)


def parse_jsonc(text: str) -> Any:
    """json.loads after stripping // and /* */ comments and trailing commas (string-aware)."""
    out: list[str] = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            out.append(" ")
            continue
        out.append(ch)
        i += 1
    stripped = "".join(out)
    # second pass: drop trailing commas outside strings
    res: list[str] = []
    in_str = False
    i, n = 0, len(stripped)
    while i < n:
        ch = stripped[i]
        if in_str:
            res.append(ch)
            if ch == "\\" and i + 1 < n:
                res.append(stripped[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
        elif ch == ",":
            j = i + 1
            while j < n and stripped[j] in " \t\r\n":
                j += 1
            if j < n and stripped[j] in "}]":
                i += 1
                continue
        res.append(ch)
        i += 1
    return json.loads("".join(res))


def cmd_text(value: Any) -> str:
    """Flatten a command that may be a string, list, or {name: str|list} dict."""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return " ".join(cmd_text(v) for v in value)
    if isinstance(value, dict):
        return " ; ".join(cmd_text(v) for v in value.values())
    return ""


# ---- pipe-to-shell (INS004 / INS012 / INS013 / INS016 / CIX007) ------------------------
PIPE_SHELL_KEYWORDS = ("curl", "wget", "iwr", "irm", "invoke-", "mshta", "certutil", "iex")
PIPE_SHELL_PATTERNS: tuple[str, ...] = (
    r"\b(?:curl|wget)\b[^\n]{0,200}\|\s*(?:sudo\s+(?:-\S+\s+){0,3})?(?:/usr/bin/env\s+|/usr/bin/|/bin/)?\w{0,8}sh\b",
    r"\b(?:ba|z|k)?sh\s+(?:-s\s+)?<\(\s*(?:curl|wget)\b",
    r"\b(?:ba|z)?sh\s+-c\s+[\"']?\$\(\s*(?:curl|wget)\b",
    r"\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n]{0,200}\|\s*(?:iex|invoke-expression)\b",
    r"\b(?:iex|invoke-expression)\s*\(?\s*\(?\s*(?:new-object\s+(?:system\.)?net\.webclient|iwr|irm|invoke-webrequest|invoke-restmethod)\b",
    r"\bmshta(?:\.exe)?\s+[\"']?https?:",
    r"\bcertutil(?:\.exe)?\b[^\n]{0,20}-urlcache",
)


def pipe_shell_pats(
    severity: Severity | None = None, confidence: Confidence | None = None, note: str = "remote script piped to a shell"
) -> tuple[Pat, ...]:
    return tuple(
        Pat(p, PIPE_SHELL_KEYWORDS, severity, confidence, (T.DOWNLOAD, T.EXEC_DYNAMIC), note) for p in PIPE_SHELL_PATTERNS
    )


URL_HOST = re.compile(r"https?://(?:[^/\s\"'@|)<>`]{1,100}@)?([^/\s\"'|)<>`:?#]{1,200})", re.I)
_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$|^\[")
_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "goo.gl", "rb.gy", "cutt.ly", "shorturl.at", "ow.ly", "buff.ly",
    "tiny.cc", "v.gd", "rebrand.ly", "s.id", "t.ly", "bit.do", "shorturl.asia", "clck.ru",
})
_RISKY_HOST_SUFFIXES = (
    "pastebin.com", "paste.ee", "hastebin.com", "ghostbin.com", "rentry.co", "rentry.org", "transfer.sh",
    "termbin.com", "0x0.st", "ix.io", "sprunge.us", "dpaste.org", "ngrok.io", "ngrok-free.app", "ngrok.app",
    "trycloudflare.com", "duckdns.org", "no-ip.org", "ddns.net", "serveo.net", "loca.lt", "pipedream.net",
    "webhook.site", "requestbin.net", "glitch.me", "replit.dev", "temp.sh", "file.io", "anonfiles.com",
)
_FIRST_PARTY_SUFFIXES = (
    "github.com", "githubusercontent.com", "github.io", "gitlab.com", "gitlab.io", "bitbucket.org",
    # well-known vendor installers (reputable, widely documented)
    "sh.rustup.rs", "rustup.rs", "get.docker.com", "docker.com", "deno.land", "deno.com", "bun.sh", "astral.sh",
    "get.pnpm.io", "python-poetry.org", "brew.sh", "nixos.org", "sdkman.io", "cloud.google.com", "ollama.com",
    "pyenv.run", "volta.sh", "starship.rs", "vercel.app", "helm.sh", "determinate.systems", "tailscale.com",
    "nodejs.org", "nvm.sh", "fly.io", "railway.app", "supabase.com", "k3s.io", "get.k3s.io", "dot.net",
    "microsoft.com", "chocolatey.org", "scoop.sh", "rye-up.com", "pixi.sh", "prefix.dev", "golang.org", "go.dev",
)


def classify_host(host: str, ctx: FileContext) -> tuple[Severity, str]:
    """M for first-party / reputable installer hosts, H for IP, shortener, paste, tunnel or unknown third party."""
    h = host.lower().rstrip(".")
    if _IP_RE.match(h):
        return S.HIGH, f"raw IP host {h}"
    if h in _SHORTENERS:
        return S.HIGH, f"URL shortener {h}"
    if any(h == s or h.endswith("." + s) for s in _RISKY_HOST_SUFFIXES):
        return S.HIGH, f"paste/tunnel host {h}"
    if any(h == s or h.endswith("." + s) for s in _FIRST_PARTY_SUFFIXES):
        return S.MEDIUM, f"first-party/reputable host {h}"
    parts = h.split(".")
    label = parts[-2] if len(parts) >= 2 else h
    if len(label) >= 4 and ctx.lower.count(label) >= 3:  # project's own domain, mentioned throughout
        return S.MEDIUM, f"project domain {h}"
    return S.HIGH, f"third-party host {h}"


def _rel_depth(ctx: FileContext) -> int:
    return ctx.rel_lower.count("/")


# ======================================================================================
# rule metadata
# ======================================================================================
def _ri(rid: str, title: str, sev: Severity, conf: Confidence, desc: str, rec: str, tags: Iterable[str]) -> RuleInfo:
    return RuleInfo(rid, title, sev, conf, _CAT, desc, rec, frozenset(tags))


_IH = T.INSTALL_HOOK
_OH = T.OPEN_HOOK
INS001 = _ri("INS001", "npm lifecycle script runs on install", S.MEDIUM, C.HIGH,
             "package.json defines a lifecycle script that npm/yarn/pnpm run automatically during install.",
             "Read the script before installing; install with --ignore-scripts if unsure.", {_IH})
INS002 = _ri("INS002", "setup.py runs risky code at install time", S.HIGH, C.HIGH,
             "setup.py executes network, process, eval/exec, decoding or out-of-tree file writes at module level or in a cmdclass hook. This runs on pip install.",
             "Inspect setup.py; install from a wheel or in a disposable VM/container.", {_IH})
INS003 = _ri("INS003", "Unusual Python build backend", S.MEDIUM, C.HIGH,
             "pyproject.toml uses a non-standard or in-tree build backend, or pulls build requirements from URLs/git. That code runs on pip install.",
             "Check the backend code and the build requirement sources before installing.", {_IH})
INS004 = _ri("INS004", "Build file downloads or executes code", S.MEDIUM, C.MEDIUM,
             "A Makefile/CMake/justfile/Taskfile contains network or dynamic-execution commands.",
             "Read the targets you are about to run; avoid running them as root.", {_IH})
INS005 = _ri("INS005", "Cargo build script / proc-macro with network or process access", S.HIGH, C.MEDIUM,
             "build.rs or a proc-macro crate runs at compile time (also triggered by IDE rust-analyzer) and uses network, processes, out-of-tree writes or embedded binaries.",
             "Review build.rs/proc-macro code before building or opening the project in an IDE.", {_IH})
INS006 = _ri("INS006", "binding.gyp command expansion", S.MEDIUM, C.MEDIUM,
             "binding.gyp runs shell commands via <!( ) expansion or actions during node-gyp rebuild (npm install).",
             "Inspect the expanded commands; install with --ignore-scripts if unsure.", {_IH})
INS007 = _ri("INS007", "Install/build hook in another ecosystem", S.MEDIUM, C.MEDIUM,
             "composer scripts, gem extensions, MSBuild <Exec>, NuGet init.ps1, Gradle exec/URL, Maven exec plugins or go:generate run commands during install/build.",
             "Review the hook commands before installing or building.", {_IH})
INS008 = _ri("INS008", "VS Code workspace runs code on open", S.HIGH, C.HIGH,
             "The .vscode configuration runs tasks on folder open or changes terminal/interpreter/trust settings so repo code runs when you open the folder.",
             "Open the folder in Restricted Mode (untrusted workspace) and review .vscode/ first.", {_OH})
INS009 = _ri("INS009", "Devcontainer lifecycle command", S.HIGH, C.HIGH,
             "devcontainer.json runs commands when the container is built/opened; initializeCommand runs on the HOST machine.",
             "Review devcontainer.json commands and features before reopening in a container.", {_OH})
INS010 = _ri("INS010", "JetBrains project runs scripts", S.MEDIUM, C.MEDIUM,
             "The committed .idea/ config defines startup tasks, external tools or script run configurations.",
             "Review .idea/ before trusting the project in the IDE.", {_OH})
INS011 = _ri("INS011", "Committed git hooks", S.MEDIUM, C.MEDIUM,
             "The repo ships git hooks (or sets core.hooksPath) that run automatically on commit/checkout once enabled.",
             "Read the hook scripts before enabling them (husky install / pre-commit install / core.hooksPath).", {_IH})
INS012 = _ri("INS012", "Risky Docker build or compose setting", S.MEDIUM, C.MEDIUM,
             "Dockerfile/compose pipes remote scripts to a shell, ADDs remote URLs, runs privileged, uses the host network or mounts host-sensitive paths.",
             "Review before building/running; never mount docker.sock, / or ~/.ssh from untrusted projects.", {_IH})
INS013 = _ri("INS013", "Install instructions pipe a remote script to a shell", S.MEDIUM, C.MEDIUM,
             "The README/docs tell you to pipe a downloaded script straight into a shell (or paste a command into the Run dialog), which runs unreviewed code.",
             "Download the script, read it, then run it; verify the host is the project's own.",
             {_IH, T.NO_DAMPEN, T.DOWNLOAD, T.EXEC_DYNAMIC})
INS014 = _ri("INS014", "Setup script modifies your shell or privileges", S.MEDIUM, C.MEDIUM,
             "An install/setup/bootstrap script writes to shell startup files or $PROFILE, prepends to PATH, or sets setuid bits.",
             "Read the script and run it without sudo; check what it adds to your shell startup files.", {_IH})
INS015 = _ri("INS015", "Import-time auto-execution hook", S.HIGH, C.HIGH,
             "A file Python/Node/direnv loads automatically (.pth, sitecustomize, conftest/__init__ with network/exec, yarnPath, .npmrc, .envrc) runs code without being called.",
             "Inspect the file; do not run pytest/import/yarn in this repo until reviewed.", {_IH, T.NO_DAMPEN})
INS016 = _ri("INS016", "Notebook cell installs or runs remote code", S.MEDIUM, C.MEDIUM,
             "A Jupyter notebook cell pipes a remote script to a shell, %runs a remote file, or pip-installs from a URL/custom index.",
             "Read notebook cells before 'Run All'.", {_IH})


# ======================================================================================
# INS001 npm lifecycle scripts
# ======================================================================================
_LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "preuninstall", "prepack")
_NPM_BUILD = re.compile(r"^(?:npm\s+run|yarn(?:\s+run)?|pnpm(?:\s+run)?|bun\s+run)\s+[\w:.-]{1,40}$|"
                        r"^(?:npx\s+)?(?:tsc|tsup|rollup|vite\s+build|esbuild|babel|webpack|node-gyp\s+rebuild)(?:\s+[\w ./=:@-]{0,100})?$", re.I)
_NPM_ALLOW = re.compile(
    r"^(?:npx\s+)?(?:husky(?:\s+install)?(?:\s+[\w./-]{1,100})?|node-gyp\s+rebuild|prebuild-install(?:\s+[\w ./=:@-]{0,100})?|"
    r"patch-package|tsc(?:\s+[\w ./=:@-]{0,100})?|ngcc(?:\s+[\w ./=:@-]{0,100})?|is-ci|true|exit\s+0)$",
    re.I,
)
_NPM_HIGH = re.compile(r"node\s+-e|curl|wget|powershell|bash\s+-c|https?:|base64|eval", re.I)
_NPM_SCRIPT_FILE = re.compile(
    r"(?:node|sh|bash|python3?|pwsh|powershell(?:\.exe)?(?:\s+-file)?|tsx|ts-node|bun|deno\s+run)\s+((?:\./)?[\w@./-]{1,200}\.(?:js|cjs|mjs|ts|sh|py|ps1))",
    re.I,
)


class NpmLifecycleDetector(Detector):
    id = "exec_hooks.npm"
    name = "npm lifecycle scripts"
    category = _CAT
    checks = (INS001,)

    def applies_to(self, ctx: FileContext) -> bool:
        return not ctx.is_binary and ctx.basename.lower() == "package.json" and '"scripts"' in ctx.lower

    def scan_file(self, ctx: FileContext) -> Iterable[Finding]:
        try:
            data = json.loads(ctx.text)
        except (ValueError, RecursionError):
            return []
        scripts = data.get("scripts") if isinstance(data, dict) else None
        if not isinstance(scripts, dict):
            return []
        out: list[Finding] = []
        base = find_line(ctx, '"scripts"')
        for key in _LIFECYCLE:
            body = scripts.get(key)
            if not isinstance(body, str) or not body.strip():
                continue
            line = find_line(ctx, f'"{key}"', base)
            parts = [p.strip() for p in re.split(r"&&|\|\||;", body) if p.strip()]
            if parts and key in ("prepare", "prepack") and all(_NPM_BUILD.match(p) or _NPM_ALLOW.match(p) for p in parts):
                out.append(self.finding(INS001, ctx, line, f'"{key}": "{body}"', severity=S.LOW,
                                        confidence=lower_conf(C.HIGH, ctx),
                                        description=f"{INS001.description} '{key}' runs a project build step ({body.strip()[:60]}); "
                                                    "check what that script does."))
                continue
            if parts and all(_NPM_ALLOW.match(p) for p in parts):
                out.append(self.finding(INS001, ctx, line, f'"{key}": "{body}"', severity=S.INFO,
                                        confidence=lower_conf(C.HIGH, ctx),
                                        description=f"{INS001.description} '{key}' runs a well-known build tool ({body.strip()[:60]})."))
                continue
            sev = S.HIGH if _NPM_HIGH.search(body) else S.MEDIUM
            desc = f"{INS001.description} '{key}' runs: {body.strip()[:120]}"
            m = _NPM_SCRIPT_FILE.search(body)
            if m:
                desc += f" (references script file {m.group(1)}; review that file too)"
            out.append(self.finding(INS001, ctx, line, f'"{key}": "{body}"', severity=sev,
                                    confidence=lower_conf(C.HIGH, ctx), extra_tags=body_tags(body), description=desc))
        return out


# ======================================================================================
# Python: INS002 setup.py, INS003 pyproject, INS015 import-time hooks
# ======================================================================================
_NET_EXACT = frozenset({
    "urllib.request.urlopen", "urllib.request.urlretrieve", "urllib.urlopen", "urllib.urlretrieve", "urllib2.urlopen",
    "socket.socket", "socket.create_connection", "http.client.HTTPConnection", "http.client.HTTPSConnection",
    "httplib.HTTPConnection", "httplib.HTTPSConnection", "ftplib.FTP", "smtplib.SMTP", "smtplib.SMTP_SSL",
    "urllib.request.Request", "urllib.request.build_opener", "wget.download",
})
_NET_PREFIX = ("requests.", "httpx.", "aiohttp.", "urllib3.", "pycurl.")
# only these attribute names under _NET_PREFIX modules actually talk to the network
# (e.g. urllib3.contrib.pyopenssl.inject_into_urllib3() or requests.utils.quote() do not)
_NET_VERBS = frozenset({
    "get", "post", "put", "patch", "delete", "head", "options", "request", "urlopen", "stream", "send", "sendall",
    "connect", "create_connection", "socket", "perform", "fetch", "request_encode_url", "request_encode_body",
    "urlretrieve", "ClientSession", "Client", "AsyncClient", "Session", "PoolManager", "Curl",
})
_EXEC_EXACT = frozenset({"os.system", "os.popen", "exec", "eval", "commands.getoutput", "pty.spawn", "os.startfile"})
_EXEC_PREFIX = ("subprocess.", "os.exec", "os.spawn", "os.posix_spawn")
_DECODE_EXACT = frozenset({
    "base64.b64decode", "base64.b32decode", "base64.b16decode", "base64.a85decode", "base64.b85decode",
    "base64.decodebytes", "base64.urlsafe_b64decode", "codecs.decode", "zlib.decompress", "marshal.loads",
    "binascii.unhexlify", "binascii.a2b_base64", "bytes.fromhex", "lzma.decompress", "bz2.decompress",
    "gzip.decompress",
})
_BENIGN_CMDS = frozenset({
    "git", "pkg-config", "cmake", "make", "ninja", "nvcc", "gcc", "g++", "cc", "c++", "clang", "clang++", "cl",
    "xcrun", "uname", "sw_vers", "rustc", "cargo", "swig", "cython", "hg", "svn", "nproc", "sysctl", "llvm-config",
    "python-config", "icu-config", "lsb_release", "ldconfig", "which", "where",
})
_SETUP_HOOK_BASES = frozenset({"install", "develop", "egg_info", "build_py"})


@dataclass(frozen=True, slots=True)
class _Hit:
    node: ast.Call
    kind: str  # network | exec | decode | write
    tags: tuple[str, ...]
    benign: bool = False


def _first_cmd(call: ast.Call) -> tuple[str | None, bool]:
    """(program basename, has_url_arg) for subprocess-like calls with constant args."""
    if not call.args:
        return None, False
    a = call.args[0]
    words: list[str] = []
    if isinstance(a, (ast.List, ast.Tuple)):
        for e in a.elts:
            s = pyast.const_str(e)
            if s is not None:
                words.append(s)
            elif not words:
                return None, False
    else:
        s = pyast.const_str(a)
        if s is None:
            return None, False
        words = s.split()
    if not words:
        return None, False
    prog = words[0].replace("\\", "/").rsplit("/", 1)[-1].lower().removesuffix(".exe")
    return prog, any("://" in w or w.startswith("git@") for w in words)


def _is_open_read_local(node: ast.AST) -> bool:
    """exec(open('pkg/version.py').read()) style - common, local, benign."""
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "read"):
        return False
    inner = node.func.value
    if isinstance(inner, ast.Call) and pyast.dotted_name(inner.func) in {"open", "io.open", "codecs.open"} and inner.args:
        p = pyast.const_str(inner.args[0])
        if p is None:
            return isinstance(inner.args[0], (ast.Name, ast.Call, ast.BinOp))  # path built locally
        return "://" not in p and not p.startswith(("/", "~"))
    return False


_HOME_CALLS = frozenset({"os.path.expanduser", "expanduser", "pathlib.Path.home", "Path.home", "os.getenv",
                         "os.environ.get", "getenv"})


def _outside_path(node: ast.AST, aliases: dict[str, str]) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            n = pyast.call_name(sub, aliases) or ""
            if n in _HOME_CALLS or n.endswith((".expanduser", ".home")):
                return True
        elif isinstance(sub, ast.Subscript) and (pyast.dotted_name(sub.value, aliases) or "") == "os.environ":
            return True
    s = pyast.const_str(node)
    if s and (s.startswith(("/", "~")) or re.match(r"^[A-Za-z]:[\\/]", s)):
        return True
    return False


def classify_call(name: str, call: ast.Call, aliases: dict[str, str]) -> _Hit | None:
    short = name.rsplit(".", 1)[-1]
    if name in _NET_EXACT or (name.startswith(_NET_PREFIX) and short in _NET_VERBS):
        tags: tuple[str, ...] = (T.DOWNLOAD,)
        if short in {"post", "put", "patch", "send", "sendall", "connect", "create_connection", "socket"}:
            tags = (T.DOWNLOAD, T.NETWORK_SEND)
        return _Hit(call, "network", tags)
    if name in _EXEC_EXACT or name.startswith(_EXEC_PREFIX):
        if short.endswith(("Error", "Exception")) or short in {"list2cmdline", "PIPE", "DEVNULL", "STDOUT"}:
            return None
        if name in {"exec", "eval"}:
            arg = call.args[0] if call.args else None
            return _Hit(call, "exec", (T.EXEC_DYNAMIC,), benign=arg is not None and _is_open_read_local(arg))
        prog, has_url = _first_cmd(call)
        benign = prog in _BENIGN_CMDS and not has_url
        return _Hit(call, "exec", (T.EXEC_DYNAMIC,), benign=benign)
    if name in _DECODE_EXACT:
        return _Hit(call, "decode", (T.DECODE,))
    if name in {"open", "io.open", "codecs.open"} and call.args:
        mode = None
        if len(call.args) > 1:
            mode = pyast.const_str(call.args[1])
        for kw in call.keywords:
            if kw.arg == "mode":
                mode = pyast.const_str(kw.value)
        if mode and any(c in mode for c in "wax") and _outside_path(call.args[0], aliases):
            return _Hit(call, "write", ())
    if name in {"shutil.copy", "shutil.copyfile", "shutil.copy2", "shutil.move", "shutil.copytree"} and len(call.args) > 1:
        if _outside_path(call.args[1], aliases):
            return _Hit(call, "write", ())
    return None


def _module_level_calls(tree: ast.Module, aliases: dict[str, str]) -> list[tuple[str, ast.Call, str]]:
    """Calls executed on import: module scope + top-level functions called from it (2 hops)."""
    funcs = {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    out: list[tuple[str, ast.Call, str]] = []
    seen_funcs: set[str] = set()
    frontier: list[tuple[ast.AST, str]] = [(tree, "module level")]
    for _hop in range(3):
        nxt: list[tuple[ast.AST, str]] = []
        for scope, where in frontier:
            for name, call in pyast.calls_in_scope(scope, aliases):
                out.append((name, call, where))
                if name in funcs and name not in seen_funcs:
                    seen_funcs.add(name)
                    nxt.append((funcs[name], f"function {name}() called at import"))
        frontier = nxt
    return out


def _hook_class_calls(tree: ast.Module, aliases: dict[str, str]) -> list[tuple[str, ast.Call, str]]:
    funcs = {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    out: list[tuple[str, ast.Call, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        bases = [(pyast.dotted_name(b, aliases) or "").rsplit(".", 1)[-1].lstrip("_").lower() for b in node.bases]
        if not any(b in _SETUP_HOOK_BASES for b in bases):
            continue
        helper_names: set[str] = set()
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                name = pyast.call_name(sub, aliases)
                if name:
                    out.append((name, sub, f"cmdclass {node.name}"))
                    if name in funcs:
                        helper_names.add(name)
        for h in helper_names:
            for sub in ast.walk(funcs[h]):
                if isinstance(sub, ast.Call):
                    name = pyast.call_name(sub, aliases)
                    if name:
                        out.append((name, sub, f"{h}() called from cmdclass {node.name}"))
    return out


_KIND_TEXT = {"network": "network access", "exec": "process/dynamic execution", "decode": "payload decoding",
              "write": "file write outside the build directory"}

_STD_BACKENDS = frozenset({
    "setuptools.build_meta", "hatchling.build", "flit_core.buildapi", "poetry.core.masonry.api", "pdm.backend",
    "maturin", "scikit_build_core.build", "mesonpy", "setuptools.build_meta:__legacy__", "poetry.masonry.api",
    "pdm.pep517.api", "flit.buildapi", "whey", "sipbuild.api", "enscons.api", "uv_build", "hatchling.ouroboros",
})
_IMPORT_TIME_PREFILTER = ("subprocess", "os.system", "urlopen", "requests", "socket", "exec(", "eval(", "popen",
                          "urllib", "http", "pty", "spawn", "startfile", "httpx")


class PythonHookDetector(Detector):
    id = "exec_hooks.python"
    name = "Python install/import-time hooks"
    category = _CAT
    checks = (INS002, INS003, INS015)

    def applies_to(self, ctx: FileContext) -> bool:
        if ctx.is_binary:
            return False
        b = ctx.basename.lower()
        return (
            b in {"setup.py", "pyproject.toml", "sitecustomize.py", "usercustomize.py", "conftest.py", "__init__.py",
                  ".yarnrc.yml", ".npmrc", ".envrc"}
            or ctx.ext == ".pth"
        )

    def scan_file(self, ctx: FileContext) -> Iterable[Finding]:
        b = ctx.basename.lower()
        if b == "setup.py":
            return self._setup_py(ctx)
        if b == "pyproject.toml":
            return self._pyproject(ctx)
        return self._import_time(ctx, b)

    # ---- INS002 ----------------------------------------------------------------------
    def _setup_py(self, ctx: FileContext) -> list[Finding]:
        tree = pyast.parse(ctx)
        if tree is None:
            return []
        aliases = pyast.import_aliases(tree)
        out: list[Finding] = []
        seen: set[int] = set()
        for name, call, where in [*_module_level_calls(tree, aliases), *_hook_class_calls(tree, aliases)]:
            hit = classify_call(name, call, aliases)
            if hit is None or call.lineno in seen:
                continue
            seen.add(call.lineno)
            sev = S.INFO if hit.benign else INS002.severity
            desc = f"{INS002.description} Found {_KIND_TEXT[hit.kind]} ({name}) in {where}."
            if hit.benign:
                desc += " The command looks like a routine build/version step."
            out.append(self.finding(INS002, ctx, call.lineno, pyast.segment(ctx, call), severity=sev,
                                    confidence=lower_conf(C.HIGH, ctx), extra_tags=hit.tags, description=desc))
            if len(out) >= 10:
                break
        return out

    # ---- INS003 ----------------------------------------------------------------------
    def _pyproject(self, ctx: FileContext) -> list[Finding]:
        if "build-system" not in ctx.lower:
            return []
        try:
            data = tomllib.loads(ctx.text)
        except (tomllib.TOMLDecodeError, ValueError, RecursionError):
            return []
        bs = data.get("build-system")
        if not isinstance(bs, dict):
            return []
        out: list[Finding] = []
        conf = lower_conf(C.HIGH, ctx)
        backend = bs.get("build-backend")
        if isinstance(backend, str) and backend.strip() and backend.strip() not in _STD_BACKENDS:
            line = find_line(ctx, "build-backend")
            out.append(self.finding(INS003, ctx, line, ctx.line_text(line), confidence=conf,
                                    description=f"{INS003.description} Backend '{backend.strip()}' is not a standard one."))
        bpath = bs.get("backend-path")
        if bpath:
            line = find_line(ctx, "backend-path")
            out.append(self.finding(INS003, ctx, line, ctx.line_text(line), confidence=conf,
                                    description=f"{INS003.description} backend-path {bpath!r} loads the build backend from code inside this repo."))
        reqs = bs.get("requires")
        if isinstance(reqs, list):
            for r in reqs:
                if isinstance(r, str) and ("://" in r or r.strip().lower().startswith("git+") or " @ " in r):
                    line = find_line(ctx, r[:40]) if r[:40] else 1
                    out.append(self.finding(INS003, ctx, line, ctx.line_text(line) or r, confidence=conf,
                                            extra_tags=(T.DOWNLOAD,),
                                            description=f"{INS003.description} Build requirement '{r[:100]}' comes from a URL/VCS."))
        return out

    # ---- INS015 ----------------------------------------------------------------------
    def _import_time(self, ctx: FileContext, b: str) -> list[Finding]:
        out: list[Finding] = []
        if ctx.ext == ".pth":
            for i, line in enumerate(ctx.lines, 1):
                s = line.lstrip()
                if s.startswith(("import ", "import\t")):
                    out.append(self.finding(INS015, ctx, i, line, extra_tags=(T.EXEC_DYNAMIC, *body_tags(line)),
                                            description=f"{INS015.description} A .pth line starting with 'import' runs on every Python start-up."))
                    if len(out) >= 3:
                        break
            return out
        if b in {"sitecustomize.py", "usercustomize.py"}:
            if not ctx.text.strip():
                return []
            line = next((i for i, ln in enumerate(ctx.lines, 1) if ln.strip() and not ln.lstrip().startswith("#")), 1)
            return [self.finding(INS015, ctx, line, ctx.line_text(line), extra_tags=body_tags(ctx.text),
                                 description=f"{INS015.description} {ctx.basename} is imported automatically by every Python interpreter on the path.")]
        if b in {"conftest.py", "__init__.py"}:
            low = ctx.lower
            if not any(k in low for k in _IMPORT_TIME_PREFILTER):
                return []
            tree = pyast.parse(ctx)
            if tree is None:
                return []
            aliases = pyast.import_aliases(tree)
            hits = [(classify_call(n, c, aliases), where) for n, c, where in _module_level_calls(tree, aliases)]
            decode = any(h is not None and h.kind == "decode" for h, _ in hits)
            for hit, where in hits:
                if hit is None or hit.benign or hit.kind not in {"network", "exec"}:
                    continue
                tags = (*hit.tags, T.DECODE) if decode else hit.tags
                out.append(self.finding(INS015, ctx, hit.node.lineno, pyast.segment(ctx, hit.node), extra_tags=tags,
                                        description=f"{INS015.description} {ctx.basename} performs {_KIND_TEXT[hit.kind]} at {where}; it runs on import / when pytest starts."))
                if len(out) >= 5:
                    break
            return out
        if b == ".yarnrc.yml":
            m_line = next((i for i, ln in enumerate(ctx.lines, 1) if re.match(r"\s*yarnPath\s*:", ln)), None)
            if m_line is None:
                return []
            val = ctx.line_text(m_line).split(":", 1)[1].strip().strip("\"'")
            standard = bool(re.match(r"^\.yarn/releases/yarn-[\w.-]{1,40}\.c?js$", val))
            return [self.finding(INS015, ctx, m_line, ctx.line_text(m_line),
                                 severity=S.LOW if standard else S.MEDIUM, confidence=C.MEDIUM, extra_tags=(T.EXEC_DYNAMIC,),
                                 description=f"{INS015.description} yarnPath makes every yarn command execute the committed file {val}.")]
        if b == ".npmrc":
            return scan_pats(INS015, ctx, (
                Pat(r"^\s*(?:script-shell|node-options)\s*=", ("script-shell", "node-options"), S.MEDIUM, C.MEDIUM,
                    (T.EXEC_DYNAMIC,), "npmrc changes the shell/Node options used for every npm script"),
            ), dampen=False)
        if b == ".envrc":
            if not ctx.text.strip():
                return []
            line = next((i for i, ln in enumerate(ctx.lines, 1) if ln.strip() and not ln.lstrip().startswith("#")), 1)
            return [self.finding(INS015, ctx, line, ctx.line_text(line), severity=S.MEDIUM, confidence=C.MEDIUM,
                                 extra_tags=body_tags(ctx.text),
                                 description=f"{INS015.description} direnv runs .envrc whenever you cd into the folder (after 'direnv allow').")]
        return out


# ======================================================================================
# INS004-INS007 build tools of other ecosystems
# ======================================================================================
_INS004_PATS = (
    *pipe_shell_pats(S.MEDIUM, C.MEDIUM),
    Pat(r"\bfile\s*\(\s*DOWNLOAD\b", ("download",), S.MEDIUM, C.MEDIUM, (T.DOWNLOAD,), "CMake file(DOWNLOAD)"),
    Pat(r"\bbase64\s+(?:-d|--decode|-D)\b", ("base64",), S.MEDIUM, C.MEDIUM, (T.DECODE,), "decodes a base64 payload"),
    Pat(r"(?<![(\w$])eval\s+[\"'$`]", ("eval",), S.MEDIUM, C.MEDIUM, (T.EXEC_DYNAMIC,), "shell eval"),
    Pat(r"\bexecute_process\s*\([^\n]{0,200}\b(?:curl|wget|sh\s+-c|bash\s+-c|powershell)\b", ("execute_process",),
        S.MEDIUM, C.MEDIUM, (T.EXEC_DYNAMIC, T.DOWNLOAD), "CMake execute_process with network/shell"),
    Pat(r"\bexecute_process\s*\(", ("execute_process",), S.LOW, C.MEDIUM, (T.EXEC_DYNAMIC,),
        "CMake execute_process runs at configure time", exclude=r"\bgit\b|GIT_EXECUTABLE"),
    Pat(r"\b(?:curl|wget|invoke-webrequest|iwr)\b[^\n]{0,200}https?://", ("curl", "wget", "invoke-webrequest", "iwr"),
        S.LOW, C.MEDIUM, (T.DOWNLOAD,), "downloads a remote file"),
)
_INS005_NET = (
    Pat(r"\b(?:reqwest|ureq|attohttpc|isahc|curl::easy)\b|TcpStream::connect|UdpSocket::bind|hyper::Client",
        ("reqwest", "ureq", "attohttpc", "isahc", "curl::", "tcpstream", "udpsocket", "hyper::"), S.HIGH, C.MEDIUM,
        (T.DOWNLOAD, T.NETWORK_SEND), "network access at compile time"),
    Pat(r"(?:fs::write|File::create|OpenOptions::new\(\))[^\n]{0,160}(?:home_dir|\"/etc/|\"/usr/|\"~|APPDATA|USERPROFILE|\"HOME\")",
        ("fs::write", "file::create", "openoptions"), S.HIGH, C.MEDIUM, (), "writes outside OUT_DIR"),
    Pat(r"Command::new\(\s*\"(?:git|rustc|cc|c\+\+|gcc|clang|pkg-config|cmake|make|xcrun|nasm|ar|protoc|llvm-config)\"",
        ("command::new",), skip=True),
    Pat(r"Command::new\(\s*(?:env!\(\s*\"RUSTC\"|&?rustc\b|&?cc\b)", ("command::new",), skip=True),
    Pat(r"Command::new\(", ("command::new",), S.MEDIUM, C.MEDIUM, (T.EXEC_DYNAMIC,), "spawns a process at compile time"),
)
_INS005_BIN = Pat(r"include_bytes!\(\s*\"[^\"]{0,200}\.(?:exe|dll|so|dylib|bin|elf)\"", ("include_bytes!",), S.MEDIUM,
                  C.MEDIUM, (T.BINARY_EXEC,), "embeds a binary")
_INS006_PATS = (
    Pat(r"<!@?\(\s*node\s+-[pe]\s+\\?[\"']\s*require\(\s*\\?[\"'][\w@./-]{1,80}\\?[\"']\s*\)[\w.]{0,40}\\?[\"']\s*\)",
        ("<!",), skip=True),
    Pat(r"<!@?\([^\n]{0,200}(?:curl|wget|https?:|powershell|base64|\|\s*\w{0,8}sh\b)", ("<!",), S.HIGH, C.MEDIUM,
        (T.EXEC_DYNAMIC, T.DOWNLOAD), "command expansion fetches or decodes remote content"),
    Pat(r"<!@?\(", ("<!",), S.MEDIUM, C.MEDIUM, (T.EXEC_DYNAMIC,), "command expansion runs a shell command"),
    Pat(r"[\"']action[\"']\s*:\s*\[", ("action",), S.MEDIUM, C.LOW, (T.EXEC_DYNAMIC,), "gyp action runs a script"),
)
_GEMSPEC_PATS = (Pat(r"\.extensions\s*(?:=|<<|\+=)", ("extensions",), S.MEDIUM, C.MEDIUM, (T.EXEC_DYNAMIC,),
                     "gem extension runs extconf.rb at install"),)
_EXTCONF_PATS = (
    Pat(r"\b(?:system|exec|spawn)\s*\(|`[^`\n]{1,200}`|%x[({\[]|Net::HTTP|open-uri|URI\.open|Kernel\.open\(\s*[\"']\|",
        ("system", "exec", "spawn", "`", "%x", "net::http", "open-uri", "uri.open", "kernel.open"), S.MEDIUM, C.MEDIUM,
        (T.EXEC_DYNAMIC,), "extconf.rb runs commands or network calls at gem install"),
)
_MSBUILD_PATS = (Pat(r"<Exec\b[^>]{0,300}\bCommand\s*=", ("<exec",), S.MEDIUM, C.MEDIUM, (T.EXEC_DYNAMIC,),
                     "MSBuild <Exec> runs a command at build/restore"),)
_GRADLE_PATS = (
    Pat(r"\bexec\s*\{|\.execute\(\s*\)|\bcommandLine\b|Runtime\.getRuntime\(\)\.exec|ProcessBuilder\s*\(",
        ("exec", "execute(", "commandline", "processbuilder"), S.MEDIUM, C.MEDIUM, (T.EXEC_DYNAMIC,),
        "Gradle runs a process during build/sync"),
    Pat(r"\b(?:new\s+)?URL\s*\(\s*[\"']https?:|\.toURL\(\)", ("url(", "tourl"), S.MEDIUM, C.MEDIUM, (T.DOWNLOAD,),
        "Gradle fetches a URL during build/sync"),
)
_POM_PATS = (Pat(r"\b(?:exec-maven-plugin|maven-antrun-plugin|groovy-maven-plugin|gmavenplus-plugin)\b",
                 ("exec-maven-plugin", "maven-antrun-plugin", "groovy-maven-plugin", "gmavenplus-plugin"), S.MEDIUM,
                 C.MEDIUM, (T.EXEC_DYNAMIC,), "Maven plugin runs commands/scripts during the build"),)
_GOGEN_PATS = (
    Pat(r"^\s*//go:generate\s[^\n]{0,300}(?:curl|wget|https?://|\bsh\s+-c|\bbash\s+-c|powershell)", ("go:generate",),
        S.MEDIUM, C.MEDIUM, (T.EXEC_DYNAMIC, T.DOWNLOAD), "go:generate fetches remote content"),
    Pat(r"^\s*//go:generate\s", ("go:generate",), S.LOW, C.MEDIUM, (T.EXEC_DYNAMIC,), "go:generate command"),
)
_COMPOSER_EVENTS = ("pre-install-cmd", "post-install-cmd", "pre-update-cmd", "post-update-cmd", "post-autoload-dump",
                    "pre-autoload-dump", "post-root-package-install", "post-create-project-cmd")


def _is_buildfile(b: str, ext: str) -> bool:
    return b in {"makefile", "gnumakefile", "justfile", "cmakelists.txt", "taskfile.yml", "taskfile.yaml"} or ext in {
        ".mk", ".cmake"}


class BuildToolDetector(Detector):
    id = "exec_hooks.build"
    name = "Build-tool install hooks"
    category = _CAT
    checks = (INS004, INS005, INS006, INS007)

    def applies_to(self, ctx: FileContext) -> bool:
        if ctx.is_binary:
            return False
        b, ext, rl = ctx.basename.lower(), ctx.ext, ctx.rel_lower
        return (
            _is_buildfile(b, ext)
            or b in {"build.rs", "binding.gyp", "composer.json", "extconf.rb", "pom.xml"}
            or ext in {".gemspec", ".csproj", ".vbproj", ".fsproj", ".props", ".targets", ".gradle", ".kts", ".go"}
            or (ext == ".rs" and "proc_macro" in ctx.lower)
            or rl.endswith(("tools/init.ps1", "tools/install.ps1"))
        )

    def scan_file(self, ctx: FileContext) -> Iterable[Finding]:
        b, ext, rl = ctx.basename.lower(), ctx.ext, ctx.rel_lower
        if _is_buildfile(b, ext):
            return scan_pats(INS004, ctx, _INS004_PATS)
        if b == "build.rs":
            return scan_pats(INS005, ctx, (*_INS005_NET, _INS005_BIN))
        if ext == ".rs":
            if "#[proc_macro" not in ctx.text:
                return []
            return scan_pats(INS005, ctx, _INS005_NET, extra_tags=())
        if b == "binding.gyp":
            return scan_pats(INS006, ctx, _INS006_PATS)
        if b == "composer.json":
            return self._composer(ctx)
        if ext == ".gemspec":
            return scan_pats(INS007, ctx, _GEMSPEC_PATS)
        if b == "extconf.rb":
            return scan_pats(INS007, ctx, _EXTCONF_PATS)
        if ext in {".csproj", ".vbproj", ".fsproj", ".props", ".targets"}:
            found = scan_pats(INS007, ctx, _MSBUILD_PATS)
            if b.startswith("directory.build."):
                found = [f.replace(description=f.description + " Directory.Build.* files are auto-imported by every project below them.")
                         for f in found]
            return [f.replace(tags=tuple(sorted(set(f.tags) | set(body_tags(ctx.line_text(f.line or 1)))))) for f in found]
        if rl.endswith(("tools/init.ps1", "tools/install.ps1")):
            if not ctx.text.strip():
                return []
            return [self.finding(INS007, ctx, 1, ctx.line_text(1), confidence=lower_conf(C.MEDIUM, ctx),
                                 extra_tags=(T.EXEC_DYNAMIC, *body_tags(ctx.text)),
                                 description=f"{INS007.description} NuGet runs {ctx.basename} when the package is installed/opened in Visual Studio.")]
        if ext in {".gradle", ".kts"}:
            if ext == ".kts" and not b.endswith(".gradle.kts"):
                return []
            return scan_pats(INS007, ctx, _GRADLE_PATS)
        if b == "pom.xml":
            return scan_pats(INS007, ctx, _POM_PATS)
        if ext == ".go":
            return scan_pats(INS007, ctx, _GOGEN_PATS, max_findings=3)
        return []

    def _composer(self, ctx: FileContext) -> list[Finding]:
        try:
            data = json.loads(ctx.text)
        except (ValueError, RecursionError):
            return []
        scripts = data.get("scripts") if isinstance(data, dict) else None
        if not isinstance(scripts, dict):
            return []
        out: list[Finding] = []
        for ev in _COMPOSER_EVENTS:
            body = cmd_text(scripts.get(ev))
            if not body.strip():
                continue
            risky = bool(_NPM_HIGH.search(body)) or bool(set(body_tags(body)) & {T.DOWNLOAD, T.DECODE})
            line = find_line(ctx, f'"{ev}"')
            out.append(self.finding(INS007, ctx, line, ctx.line_text(line), severity=S.MEDIUM if risky else S.LOW,
                                    confidence=lower_conf(C.MEDIUM, ctx), extra_tags=body_tags(body),
                                    description=f"{INS007.description} composer '{ev}' runs: {body[:120]}"))
        return out


# ======================================================================================
# INS008-INS010 editor / devcontainer open hooks
# ======================================================================================
_TERM_KEY = re.compile(r"^terminal\.integrated\.(?:env|shell(?!Integration)|profiles|automationProfile)", re.I)
_PATH_KEY_SUFFIX = frozenset({"path", "executablepath", "serverpath", "runtime", "pythonpath", "defaultinterpreterpath",
                              "nodepath", "runtimeexecutable"})
_VENV_HINT = re.compile(r"(?:^|[/\\])(?:\.?venv|env|\.tox|node_modules|\.nox|\.pixi|\.conda)(?:[/\\]|$)", re.I)


def _in_repo_path(v: str) -> bool:
    v = v.strip()
    if not v or v.startswith(("/", "~", "$env", "%")) or re.match(r"^[A-Za-z]:[\\/]", v):
        return False
    if v.startswith(("${workspaceFolder", "${workspaceRoot", "./", ".\\")):
        return True
    return ("/" in v or "\\" in v) and not v.startswith("$")


def _flatten_settings(data: dict[str, Any]) -> Iterable[tuple[str, Any]]:
    for k, v in data.items():
        if isinstance(k, str) and k.startswith("[") and isinstance(v, dict):
            yield from ((kk, vv) for kk, vv in v.items() if isinstance(kk, str))
        elif isinstance(k, str):
            yield k, v


class EditorHookDetector(Detector):
    id = "exec_hooks.editor"
    name = "Editor and devcontainer open hooks"
    category = _CAT
    checks = (INS008, INS009, INS010)

    def applies_to(self, ctx: FileContext) -> bool:
        if ctx.is_binary:
            return False
        rl = ctx.rel_lower
        return (
            rl.endswith((".vscode/tasks.json", ".vscode/settings.json", ".vscode/launch.json", ".code-workspace",
                         "devcontainer.json"))
            or ((rl.startswith(".idea/") or "/.idea/" in rl) and ctx.ext == ".xml")
        )

    def scan_file(self, ctx: FileContext) -> Iterable[Finding]:
        rl = ctx.rel_lower
        if rl.endswith("devcontainer.json"):
            return self._devcontainer(ctx)
        if ctx.ext == ".xml":
            return self._jetbrains(ctx)
        return self._vscode(ctx)

    # ---- INS008 ----------------------------------------------------------------------
    def _vscode(self, ctx: FileContext) -> list[Finding]:
        try:
            data = parse_jsonc(ctx.text)
        except (ValueError, RecursionError):
            return scan_pats(INS008, ctx, (
                Pat(r"\"runOn\"\s*:\s*\"folderOpen\"", ("folderopen",), S.HIGH, C.MEDIUM, (T.EXEC_DYNAMIC,),
                    "task runs automatically on folder open (file did not parse)"),
            ))
        if not isinstance(data, dict):
            return []
        rl = ctx.rel_lower
        out: list[Finding] = []
        if rl.endswith("tasks.json"):
            out += self._tasks(ctx, data)
        elif rl.endswith("settings.json"):
            out += self._settings(ctx, data)
        elif rl.endswith("launch.json"):
            out += self._launch(ctx, data)
        else:  # .code-workspace bundles all three
            if isinstance(data.get("tasks"), dict):
                out += self._tasks(ctx, data["tasks"])
            if isinstance(data.get("settings"), dict):
                out += self._settings(ctx, data["settings"])
            if isinstance(data.get("launch"), dict):
                out += self._launch(ctx, data["launch"])
        return out

    def _tasks(self, ctx: FileContext, data: dict[str, Any]) -> list[Finding]:
        tasks = data.get("tasks")
        if not isinstance(tasks, list):
            return []
        out: list[Finding] = []
        line = 0
        for t in tasks:
            if not isinstance(t, dict):
                continue
            ro = t.get("runOptions")
            if not (isinstance(ro, dict) and ro.get("runOn") == "folderOpen"):
                continue
            parts = [cmd_text(t.get("command")), cmd_text(t.get("args"))]
            for osk in ("windows", "linux", "osx"):
                sub = t.get(osk)
                if isinstance(sub, dict):
                    parts += [cmd_text(sub.get("command")), cmd_text(sub.get("args"))]
            cmd = " ".join(p for p in parts if p)
            line = find_line(ctx, "folderopen", line + 1, ci=True)
            out.append(self.finding(INS008, ctx, line, ctx.line_text(line), severity=S.HIGH,
                                    confidence=lower_conf(C.HIGH, ctx), extra_tags=(T.EXEC_DYNAMIC, *body_tags(cmd)),
                                    description=f"{INS008.description} Task '{t.get('label', '?')}' runs on folder open: {cmd[:150]}"))
        return out

    def _settings(self, ctx: FileContext, data: dict[str, Any]) -> list[Finding]:
        out: list[Finding] = []
        conf_h = lower_conf(C.HIGH, ctx)
        for k, v in _flatten_settings(data):
            sev: Severity | None = None
            conf = conf_h
            note = ""
            last = k.rsplit(".", 1)[-1].lower()
            if _TERM_KEY.match(k):
                sev, note = S.MEDIUM, f"'{k}' changes the integrated terminal's shell/environment"
            elif (last in _PATH_KEY_SUFFIX or k == "python.defaultInterpreterPath") and isinstance(v, str) and _in_repo_path(v):
                if _VENV_HINT.search(v):
                    sev, conf, note = S.LOW, C.LOW, f"'{k}' points to a local environment ({v})"
                else:
                    sev, conf, note = S.MEDIUM, lower_conf(C.MEDIUM, ctx), f"'{k}' points to an executable inside the repo ({v})"
            elif k == "task.allowAutomaticTasks" and v in ("on", True):
                sev, note = S.MEDIUM, "'task.allowAutomaticTasks' lets folder-open tasks run without asking"
            elif k.startswith("security.workspace.trust"):
                sev, note = S.MEDIUM, f"'{k}' weakens Workspace Trust"
            if sev is None:
                continue
            line = find_line(ctx, f'"{k}"')
            out.append(self.finding(INS008, ctx, line, ctx.line_text(line), severity=sev, confidence=conf,
                                    extra_tags=(T.EXEC_DYNAMIC,) if sev >= S.MEDIUM else (),
                                    description=f"{INS008.description} {note}."))
            if len(out) >= 10:
                break
        return out

    def _launch(self, ctx: FileContext, data: dict[str, Any]) -> list[Finding]:
        cfgs = data.get("configurations")
        if not isinstance(cfgs, list):
            return []
        out: list[Finding] = []
        line = 0
        for c in cfgs:
            if isinstance(c, dict) and isinstance(c.get("preLaunchTask"), str):
                line = find_line(ctx, '"preLaunchTask"', line + 1)
                out.append(self.finding(INS008, ctx, line, ctx.line_text(line), severity=S.LOW,
                                        confidence=lower_conf(C.MEDIUM, ctx),
                                        description=f"{INS008.description} Debug configuration runs task '{c['preLaunchTask']}' before launching."))
        return out[:5]

    # ---- INS009 ----------------------------------------------------------------------
    def _devcontainer(self, ctx: FileContext) -> list[Finding]:
        try:
            data = parse_jsonc(ctx.text)
        except (ValueError, RecursionError):
            return scan_pats(INS009, ctx, (
                Pat(r"\"initializeCommand\"\s*:", ("initializecommand",), S.HIGH, C.MEDIUM, (T.EXEC_DYNAMIC,),
                    "initializeCommand runs on the host (file did not parse)"),
            ))
        if not isinstance(data, dict):
            return []
        out: list[Finding] = []
        keys = (("initializeCommand", S.HIGH, C.HIGH, "runs on the HOST before the container exists"),
                ("onCreateCommand", S.MEDIUM, C.HIGH, "runs when the container is created"),
                ("updateContentCommand", S.MEDIUM, C.HIGH, "runs when the container is created/updated"),
                ("postCreateCommand", S.MEDIUM, C.HIGH, "runs after the container is created"),
                ("postStartCommand", S.MEDIUM, C.HIGH, "runs every time the container starts"),
                ("postAttachCommand", S.MEDIUM, C.HIGH, "runs every time the editor attaches"))
        for key, sev, conf, note in keys:
            cmd = cmd_text(data.get(key))
            if not cmd.strip():
                continue
            if sev == S.MEDIUM and not _NPM_HIGH.search(cmd):
                sev = S.LOW  # runs inside the container, and only if you open it as a devcontainer
            line = find_line(ctx, f'"{key}"')
            out.append(self.finding(INS009, ctx, line, ctx.line_text(line), severity=sev,
                                    confidence=lower_conf(conf, ctx), extra_tags=(T.EXEC_DYNAMIC, *body_tags(cmd)),
                                    description=f"{INS009.description} {key} {note}: {cmd[:150]}"))
        feats = data.get("features")
        if isinstance(feats, dict):
            for fk in feats:
                if isinstance(fk, str) and not fk.startswith("ghcr.io/devcontainers/"):
                    line = find_line(ctx, f'"{fk}"')
                    out.append(self.finding(INS009, ctx, line, ctx.line_text(line), severity=S.MEDIUM,
                                            confidence=lower_conf(C.MEDIUM, ctx),
                                            description=f"{INS009.description} Feature '{fk}' comes from outside ghcr.io/devcontainers; its install script runs as root in the container."))
        run_args = cmd_text(data.get("runArgs"))
        if re.search(r"--privileged|docker\.sock|--network[= ]host|--pid[= ]host", run_args):
            line = find_line(ctx, '"runArgs"')
            out.append(self.finding(INS009, ctx, line, ctx.line_text(line), severity=S.MEDIUM,
                                    confidence=lower_conf(C.MEDIUM, ctx),
                                    description=f"{INS009.description} runArgs give the container host-level access: {run_args[:120]}"))
        return out

    # ---- INS010 ----------------------------------------------------------------------
    def _jetbrains(self, ctx: FileContext) -> list[Finding]:
        pats = [
            Pat(r"ProjectStartup\w{0,40}(?:Configuration|TaskManager)", ("projectstartup",), S.MEDIUM, C.MEDIUM,
                (T.EXEC_DYNAMIC,), "startup task runs a configuration when the project opens"),
            Pat(r"type=\"(?:ShConfigurationType|BatchConfigurationType|PowerShellRunType|ShellScript)\"|name=\"SCRIPT_TEXT\"|name=\"SCRIPT_PATH\"",
                ("shconfigurationtype", "batchconfigurationtype", "powershellruntype", "shellscript", "script_text",
                 "script_path"), S.LOW, C.MEDIUM, (T.EXEC_DYNAMIC,), "run configuration executes a script"),
        ]
        if "/tools/" in ctx.rel_lower or ctx.rel_lower.startswith(".idea/tools/"):
            pats.append(Pat(r"<tool\b", ("<tool",), S.LOW, C.MEDIUM, (T.EXEC_DYNAMIC,), "external tool definition"))
        return scan_pats(INS010, ctx, pats, max_findings=3)


# ======================================================================================
# INS011 git hooks
# ======================================================================================
_GIT_HOOK_NAMES = frozenset({
    "applypatch-msg", "pre-applypatch", "post-applypatch", "pre-commit", "pre-merge-commit", "prepare-commit-msg",
    "commit-msg", "post-commit", "pre-rebase", "post-checkout", "post-merge", "pre-push", "pre-receive", "update",
    "post-receive", "post-update", "push-to-checkout", "pre-auto-gc", "post-rewrite", "reference-transaction",
    "fsmonitor-watchman", "post-index-change",
})


def _is_hook_file(ctx: FileContext) -> bool:
    rl = ctx.rel_lower
    if ctx.is_doc:
        return False
    if rl.startswith((".githooks/", ".git-hooks/")):
        return True
    if rl.startswith(".husky/"):
        return not rl.startswith(".husky/_/")
    return rl.startswith("hooks/") and ctx.basename.lower() in _GIT_HOOK_NAMES


class GitHookDetector(Detector):
    id = "exec_hooks.githooks"
    name = "Committed git hooks"
    category = _CAT
    checks = (INS011,)

    def applies_to(self, ctx: FileContext) -> bool:
        if ctx.is_binary:
            return False
        return (_is_hook_file(ctx) or ctx.basename.lower() in {".pre-commit-config.yaml", ".pre-commit-config.yml"}
                or "core.hookspath" in ctx.lower)

    def scan_file(self, ctx: FileContext) -> Iterable[Finding]:
        out: list[Finding] = []
        b = ctx.basename.lower()
        if _is_hook_file(ctx):
            if ctx.text.strip():
                tags = body_tags(ctx.text)
                risky = bool(set(tags) & {T.DOWNLOAD, T.DECODE, T.NETWORK_SEND}) or T.EXEC_DYNAMIC in tags
                out.append(self.finding(INS011, ctx, 1, ctx.line_text(1) or ctx.basename,
                                        severity=S.MEDIUM if risky else S.LOW, confidence=lower_conf(C.MEDIUM, ctx),
                                        extra_tags=tags,
                                        description=f"{INS011.description} Hook '{ctx.rel_path}'"
                                                    + (" downloads/executes dynamic code." if risky else " runs local commands.")))
            return out
        if b in {".pre-commit-config.yaml", ".pre-commit-config.yml"}:
            return scan_pats(INS011, ctx, (
                Pat(r"^\s*(?:-\s+)?entry:\s[^\n]{0,200}(?:curl|wget|https?://|base64)", ("entry:",), S.MEDIUM, C.MEDIUM,
                    (T.DOWNLOAD, T.EXEC_DYNAMIC), "local pre-commit hook fetches remote content"),
                Pat(r"^\s*-?\s*repo:\s*local\b", ("local",), S.LOW, C.MEDIUM, (), "repo: local hook runs repo scripts"),
                Pat(r"^\s*-?\s*repo:\s*[\"']?(?:https?://|git@)(?!(?:www\.)?(?:github\.com|gitlab\.com|bitbucket\.org)[/:])",
                    ("repo:",), S.LOW, C.MEDIUM, (T.DOWNLOAD,), "hook repo on an unusual host"),
            ), max_findings=5)
        if ctx.is_ci:
            return []
        return scan_pats(INS011, ctx, (
            Pat(r"\bcore\.hooksPath\b", ("core.hookspath",), S.LOW, C.MEDIUM, (),
                "sets core.hooksPath so committed hooks activate automatically"),
        ), max_findings=2)


# ======================================================================================
# INS012 Docker
# ======================================================================================
def _is_dockerfile(b: str) -> bool:
    return b in {"dockerfile", "containerfile"} or b.startswith(("dockerfile.", "containerfile.")) or b.endswith(".dockerfile")


def _is_compose(b: str) -> bool:
    return bool(re.match(r"^(?:docker-)?compose(?:[.-][\w.-]{0,40})?\.ya?ml$", b))


_DOCKERFILE_PATS = (
    *pipe_shell_pats(S.MEDIUM, C.MEDIUM),
    Pat(r"^\s*ADD\s+(?:--\S+\s+){0,3}[\"']?https?://", ("add",), S.MEDIUM, C.MEDIUM, (T.DOWNLOAD,),
        "ADD downloads a remote file into the image"),
)
_COMPOSE_PATS = (
    Pat(r"^\s*privileged:\s*[\"']?true\b", ("privileged",), S.MEDIUM, C.MEDIUM, (), "container runs privileged"),
    Pat(r"^\s*network_mode:\s*[\"']?host\b", ("network_mode",), S.MEDIUM, C.MEDIUM, (), "container uses the host network"),
    Pat(r"^\s*pid:\s*[\"']?host\b", ("pid",), S.MEDIUM, C.MEDIUM, (), "container shares the host PID namespace"),
    Pat(r"docker\.sock\b", ("docker.sock",), S.MEDIUM, C.MEDIUM, (), "mounts the Docker socket (host root access)"),
    Pat(r"(?:~|\$\{?HOME\}?|/root|/home/[\w.-]{1,40})/\.(?:ssh|aws|gnupg|kube)\b", ("ssh", "aws", "gnupg", "kube"),
        S.MEDIUM, C.MEDIUM, (T.READS_CREDENTIALS,), "mounts host credential directory"),
    Pat(r"(?:^|[\s\"'-])/:/", ("/:/",), S.MEDIUM, C.MEDIUM, (), "mounts the host root filesystem"),
)


class DockerDetector(Detector):
    id = "exec_hooks.docker"
    name = "Docker build/compose risks"
    category = _CAT
    checks = (INS012,)

    def applies_to(self, ctx: FileContext) -> bool:
        b = ctx.basename.lower()
        return not ctx.is_binary and (_is_dockerfile(b) or _is_compose(b))

    def scan_file(self, ctx: FileContext) -> Iterable[Finding]:
        if _is_dockerfile(ctx.basename.lower()):
            return scan_pats(INS012, ctx, _DOCKERFILE_PATS)
        return scan_pats(INS012, ctx, _COMPOSE_PATS)


# ======================================================================================
# INS013 README pipe-to-shell / ClickFix
# ======================================================================================
_CLICKFIX = Pat(r"(?:win(?:dows)?\s*(?:key\s*)?\+\s*r\b|run dialog)[^\n]{0,80}(?:paste|ctrl\s*\+\s*v)",
                ("+ r", "+r", "run dialog"), S.HIGH, C.MEDIUM, (), "ClickFix: asks you to paste a command into the Run dialog")


_PROSE_EXT = frozenset({".md", ".markdown", ".rst", ".txt", ".adoc", ".org", ".textile"})


def _is_prose(ctx: FileContext) -> bool:
    """README/docs text (is_readme alone also matches install.sh / setup.py, which are code)."""
    return ctx.ext in _PROSE_EXT or (ctx.is_readme and ctx.ext == "" and ctx.language == "unknown")


class ReadmeDetector(Detector):
    id = "exec_hooks.readme"
    name = "Install instructions that pipe to a shell"
    category = _CAT
    checks = (INS013,)

    def applies_to(self, ctx: FileContext) -> bool:
        return not ctx.is_binary and not ctx.is_ci and (_is_prose(ctx) or ctx.language == "html")

    def scan_file(self, ctx: FileContext) -> Iterable[Finding]:
        out = scan_pats(INS013, ctx, (_CLICKFIX,), dampen=False, max_findings=3)
        if not _is_prose(ctx):
            return out
        for f in scan_pats(INS013, ctx, pipe_shell_pats(), dampen=False, max_findings=8):
            line = ctx.line_text(f.line or 1)
            m = URL_HOST.search(line)
            if m:
                sev, why = classify_host(m.group(1), ctx)
            else:
                sev, why = S.MEDIUM, "URL not shown on the line"
            out.append(f.replace(severity=sev, description=f"{INS013.description} ({why})"))
        return out


# ======================================================================================
# INS014 setup scripts
# ======================================================================================
_SETUP_SCRIPT_RX = re.compile(r"^(?:install[\w.-]{0,40}\.(?:sh|bash|ps1)|setup[\w.-]{0,40}\.(?:ps1|sh|bash)|bootstrap[\w.-]{0,40})$", re.I)
_INS014_PATS = (
    Pat(r"(?:>>?|\btee\s+-a)\s*[\"']?(?:~|\$HOME|\$\{HOME\})/\.(?:bashrc|zshrc|bash_profile|profile|zprofile|zshenv|config/fish/config\.fish)\b",
        ("bashrc", "zshrc", "profile", "zshenv", "config.fish"), S.MEDIUM, C.MEDIUM, (), "writes to a shell start-up file"),
    Pat(r"(?:Add-Content|Set-Content|Out-File|>>?)[^\n]{0,80}\$PROFILE\b", ("$profile",), S.MEDIUM, C.MEDIUM, (),
        "writes to the PowerShell $PROFILE"),
    Pat(r"\bPATH\s*=\s*[\"']?[^\s\"';]{1,200}:\s*\$\{?PATH\b", ("path",), S.MEDIUM, C.MEDIUM, (),
        "prepends a directory to PATH", flags=0),
    Pat(r"\bsetx\s+(?:/m\s+)?PATH\b|SetEnvironmentVariable\(\s*[\"']Path[\"']", ("setx", "setenvironmentvariable"),
        S.MEDIUM, C.MEDIUM, (), "permanently changes PATH"),
    Pat(r"\bchmod\s+(?:-\w+\s+){0,2}(?:[ugoa]{0,3}\+s|[2467][0-7]{3})\b", ("chmod",), S.MEDIUM, C.MEDIUM, (),
        "sets a setuid/setgid bit"),
)


class SetupScriptDetector(Detector):
    id = "exec_hooks.setup_scripts"
    name = "Setup scripts that modify the system"
    category = _CAT
    checks = (INS014,)

    def applies_to(self, ctx: FileContext) -> bool:
        if ctx.is_binary:
            return False
        b = ctx.basename
        if _SETUP_SCRIPT_RX.match(b):
            return True
        return "/" not in ctx.rel_path and ctx.ext in {".bat", ".cmd"}

    def scan_file(self, ctx: FileContext) -> Iterable[Finding]:
        return scan_pats(INS014, ctx, _INS014_PATS)


# ======================================================================================
# INS016 notebooks
# ======================================================================================
_NB_PATS = (
    Pat(r"^\s*%run\s+[\"']?https?://", ("%run",), S.MEDIUM, C.MEDIUM, (T.DOWNLOAD, T.EXEC_DYNAMIC), "%run of a remote file"),
    Pat(r"^\s*[!%]\s*(?:python3?\s+-m\s+)?pip3?\s+install\b[^\n]{0,300}(?:https?://|git\+|--index-url|--extra-index-url|\s-i\s|--find-links|\s-f\s)",
        ("pip",), S.MEDIUM, C.MEDIUM, (T.DOWNLOAD,), "pip install from a URL or custom index"),
)


class NotebookDetector(Detector):
    id = "exec_hooks.notebooks"
    name = "Notebook cells running remote code"
    category = _CAT
    checks = (INS016,)

    def applies_to(self, ctx: FileContext) -> bool:
        return not ctx.is_binary and ctx.ext == ".ipynb"

    def scan_file(self, ctx: FileContext) -> Iterable[Finding]:
        low = ctx.lower
        if not any(k in low for k in ("curl", "wget", "%run", "pip", "iwr", "irm")):
            return []
        try:
            nb = json.loads(ctx.text)
        except (ValueError, RecursionError):
            nb = None
        cells = nb.get("cells") if isinstance(nb, dict) else None
        if not isinstance(cells, list):
            return scan_pats(INS016, ctx, (*_NB_PATS, *pipe_shell_pats(S.MEDIUM, C.MEDIUM)))
        shell_pats = pipe_shell_pats(S.MEDIUM, C.MEDIUM)
        out: list[Finding] = []
        cursor = 1
        for cell in cells:
            if not isinstance(cell, dict) or cell.get("cell_type") != "code":
                continue
            src = cell.get("source")
            lines = src if isinstance(src, list) else str(src or "").splitlines(True)
            lines = [ln for ln in lines if isinstance(ln, str)]
            shell_cell = bool(lines) and lines[0].lstrip().startswith(("%%bash", "%%sh", "%%script", "%%cmd", "%%powershell"))
            for raw in lines:
                code = raw.rstrip("\n")
                hit: tuple[Pat, re.Match[str]] | None = None
                for p in _NB_PATS:
                    m = p.regex.search(code)
                    if m:
                        hit = (p, m)
                        break
                if hit is None and (shell_cell or code.lstrip().startswith("!")):
                    for p in shell_pats:
                        m = p.regex.search(code)
                        if m:
                            hit = (p, m)
                            break
                if hit is None:
                    continue
                p, m = hit
                needle = json.dumps(code.strip())[1:-1][:40]
                line = find_line(ctx, needle, cursor) if needle else cursor
                cursor = line
                out.append(Finding.from_rule(INS016, ctx, line, code, severity=p.severity, confidence=lower_conf(C.MEDIUM, ctx),
                                             extra_tags=p.tags, description=f"{INS016.description} ({p.note})"))
                if len(out) >= 5:
                    return out
        return out


DETECTORS = (
    NpmLifecycleDetector,
    PythonHookDetector,
    BuildToolDetector,
    EditorHookDetector,
    GitHookDetector,
    DockerDetector,
    ReadmeDetector,
    SetupScriptDetector,
    NotebookDetector,
)
