"""AIX - AI tool attack surface.

Instruction files (CLAUDE.md, AGENTS.md, .cursorrules, skills...), Claude settings and hooks, MCP server
configs, prompt-injection phrasing, hidden text and invisible / bidi / tag Unicode. Static only: JSON is
parsed with `json`, nothing is executed.
"""

from __future__ import annotations

import json
import re
import unicodedata
from collections.abc import Iterable, Iterator
from typing import Any
from urllib.parse import urlsplit

from .. import tags as T
from ..context import FileContext
from ..detector import Detector, RuleInfo
from ..models import Category, Confidence, Finding, Severity
from ..textutil import BIDI_CODEPOINTS, TAG_RANGE, decode_tag_chars, find_invisible, sanitize_snippet

_C = Category.AI_SURFACE
_REC_REVIEW = "Read this file yourself before opening the repo with an AI coding tool; remove anything you did not expect."

AIX001 = RuleInfo(
    "AIX001", "AI agent instruction/config file present", Severity.INFO, Confidence.HIGH, _C,
    "This file is read automatically by AI coding tools (Claude Code, Cursor, Copilot, Gemini...) and steers what they do.",
    "Skim it before letting an AI agent work in this repository.",
)
AIX002 = RuleInfo(
    "AIX002", "Prompt-injection phrasing", Severity.HIGH, Confidence.MEDIUM, _C,
    "Text tries to override an AI agent's instructions, hide actions from the user, run commands or touch secrets.",
    _REC_REVIEW, frozenset({T.AI_INSTRUCTION}),
)
AIX003 = RuleInfo(
    "AIX003", "Claude Code settings run commands or redirect traffic", Severity.HIGH, Confidence.HIGH, _C,
    "Project .claude/settings.json can run hook commands, helper scripts and redirect API traffic as soon as Claude Code opens the folder.",
    "Do not open this repo with Claude Code until you have reviewed .claude/settings*.json; delete hooks and env overrides you don't trust.",
    frozenset({T.OPEN_HOOK}),
)
AIX004 = RuleInfo(
    "AIX004", "MCP server configured by the repository", Severity.MEDIUM, Confidence.MEDIUM, _C,
    "The repo ships an MCP config. Approving it lets the AI tool start this server process or connect to this URL.",
    "Only approve project MCP servers you recognise; pin package versions and never pass real secrets to unknown servers.",
    frozenset({T.OPEN_HOOK}),
)
AIX005 = RuleInfo(
    "AIX005", "Risky AI skill / command / plugin", Severity.MEDIUM, Confidence.MEDIUM, _C,
    "A Claude skill, slash command, agent or plugin runs shell commands or grants broad tool permissions.",
    _REC_REVIEW,
)
AIX006 = RuleInfo(
    "AIX006", "Hidden Unicode tag characters (ASCII smuggling)", Severity.CRITICAL, Confidence.HIGH, _C,
    "Unicode tag characters are invisible in editors but read by AI models; they are used to smuggle hidden instructions.",
    "Delete the hidden characters; treat the whole repository as hostile if the decoded text gives instructions.",
    frozenset({T.INVISIBLE_UNICODE, T.NO_DAMPEN}),
)
AIX007 = RuleInfo(
    "AIX007", "Invisible / zero-width characters", Severity.HIGH, Confidence.MEDIUM, _C,
    "Zero-width or other invisible characters hide text from human reviewers while tools and models still see it.",
    "Inspect the line with a hex viewer or `cat -A`; remove characters you cannot explain.",
    frozenset({T.INVISIBLE_UNICODE, T.NO_DAMPEN}),
)
AIX008 = RuleInfo(
    "AIX008", "Bidirectional control characters (Trojan Source)", Severity.HIGH, Confidence.HIGH, _C,
    "Bidi override/isolate characters make code display in a different order than it executes (CVE-2021-42574).",
    "Inspect the raw bytes; source code should not contain bidi controls outside of RTL string literals.",
    frozenset({T.INVISIBLE_UNICODE, T.NO_DAMPEN}),
)
AIX009 = RuleInfo(
    "AIX009", "Hidden markdown text aimed at AI", Severity.MEDIUM, Confidence.MEDIUM, _C,
    "Text hidden from rendered view (HTML comments, markdown link comments, display:none, whitespace padding) contains instructions or commands.",
    _REC_REVIEW, frozenset({T.AI_INSTRUCTION}),
)
AIX010 = RuleInfo(
    "AIX010", "Text addressing AI tools or scanners", Severity.HIGH, Confidence.MEDIUM, _C,
    "Text tells AI assistants, reviewers or security scanners to ignore something or that it is safe - a common evasion trick.",
    "Treat claims of being 'safe' or 'approved' as a red flag and review the surrounding code manually.",
    frozenset({T.AI_INSTRUCTION, T.EVASION}),
)
AIX011 = RuleInfo(
    "AIX011", "Look-alike AI instruction file name", Severity.HIGH, Confidence.HIGH, _C,
    "A path uses look-alike Unicode characters to imitate a known AI instruction/config file name.",
    "Compare the bytes of the name with the real file name; delete the impostor.",
    frozenset({T.EVASION}),
)

_MAX_PER_RULE = 10
_TEXT_CAP = 1_000_000

# ---- content classifiers (used for extra correlation tags and severity) ----------------------------------
_CMD_RE = re.compile(
    r"(?i)\b(?:curl|wget|iwr|invoke-webrequest|invoke-expression|iex|bash|zsh|powershell|pwsh|cmd\.exe|eval|"
    r"npx|bunx|uvx|sh\s+-c|python3?\s+-c|node\s+-e)\b|\|\s*(?:sudo\s+)?(?:ba|z)?sh\b"
)
_SHELL_EVAL_RE = re.compile(
    r"(?i)\b(?:bash|sh|zsh|pwsh|powershell|cmd)(?:\.exe)?\s+(?:-c|/c|-command|-enc|-encodedcommand|-e)\b|\beval\b|"
    r"\biex\b|invoke-expression|\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|python3?\s+-c\b|node\s+-e\b|base64\s+(?:-d|--decode)"
)
_NET_RE = re.compile(
    r"(?i)https?://|\b(?:curl|wget|iwr|invoke-webrequest|invoke-restmethod|ncat|netcat|nc\s+-|webhooks?)\b"
)
_SECRET_RE = re.compile(
    r"(?i)\.env\b|~/\.ssh|\.ssh/|\bid_rsa\b|\bid_ed25519\b|\.aws/|\bcredentials?\b|\bapi[_ -]?keys?\b|"
    r"\bsecrets?\b|\bpasswords?\b|(?:access|auth|api|bearer|github|gh|npm)[_ -]?tokens?\b|\$\{?[A-Z_]{0,30}(?:TOKEN|SECRET|PASSWORD)\b"
)
_ENCODE_RE = re.compile(r"(?i)base64|frombase64string|-enc(?:odedcommand)?\b|\\x[0-9a-f]{2}|xxd\s+-r|openssl\s+enc|certutil\s+-decode")
_OUT_OF_REPO_RE = re.compile(
    r"(?i)(?:^|[\s\"'=(])(?:~[/\\]|\$home\b|\$\{home\}|%userprofile%|%appdata%|%localappdata%|%temp%|/tmp/|/etc/|"
    r"/var/|/dev/tcp|[a-z]:[\\/]|\\\\[a-z0-9])"
)
_URL_RE = re.compile(r"(?i)https?://[^\s\"'`<>)]{1,300}")
_LOCAL_HOSTS = ("localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]")


def _content_tags(text: str, *, hook: bool = False) -> tuple[str, ...]:
    out: list[str] = []
    if (_SHELL_EVAL_RE if hook else _CMD_RE).search(text):
        out.append(T.EXEC_DYNAMIC)
    if _NET_RE.search(text):
        out.append(T.NETWORK_SEND)
    if _SECRET_RE.search(text):
        out.append(T.SECRET)
    return tuple(out)


def _risky_command(cmd: str) -> bool:
    return bool(_NET_RE.search(cmd) or _ENCODE_RE.search(cmd) or _OUT_OF_REPO_RE.search(cmd) or _SHELL_EVAL_RE.search(cmd))


def _host(url: str) -> str:
    try:
        return (urlsplit(url.strip()).hostname or "").lower()
    except ValueError:
        return ""


def _has_remote_url(line: str) -> bool:
    for m in _URL_RE.finditer(line):
        h = _host(m.group(0))
        if h and h not in _LOCAL_HOSTS and not h.startswith("127."):
            return True
    return False


def _dampen(conf: Confidence, ctx: FileContext | None) -> Confidence:
    """Lower confidence one level for test/doc/vendored locations (non-high-signal rules only)."""
    if ctx is not None and ctx.context_kind is not None and conf > Confidence.LOW:
        return Confidence(conf - 1)
    return conf


# ---- scope ----------------------------------------------------------------------------------------------
_AI_DIRS = frozenset(
    {".claude", ".cursor", ".roo", ".continue", ".windsurf", ".clinerules", ".claude-plugin", ".gemini", ".codex", ".kiro"}
)
_PROSE_LANGS = frozenset({"markdown", "rst", "text", "unknown"})
_I18N_RE = re.compile(r"(?i)\.(?:po|pot|mo|xliff|xlf|strings|stringsdict|arb|resx|ftl)$|(?:^|/)(?:locales?|i18n|l10n|lang|translations?)/")
_HIDDEN_MD_EXT = frozenset({".md", ".markdown", ".mdx", ".mdc", ".html", ".htm", ".txt", ".rst"})


def _in_ai_scope(ctx: FileContext) -> bool:
    if ctx.is_ai_config:
        return True
    parts = ctx.rel_lower.split("/")
    return any(p in _AI_DIRS for p in parts[:-1])


def _is_code(ctx: FileContext) -> bool:
    return ctx.language not in _PROSE_LANGS


# ---- AIX002 patterns -------------------------------------------------------------------------------------
_P_STRONG = re.compile(
    r"(?i)\b(?:ignore|disregard|forget|override)\b.{0,30}\b(?:previous|prior|above|all|system|earlier)\b.{0,20}"
    r"\b(?:instructions?|rules|prompts?|guidelines|directives)\b"
    r"|\b(?:do not|don't|never)\s+(?:tell|inform|mention|reveal|show|alert|notify)\b.{0,30}\b(?:user|human|developer|owner)s?\b"
    r"|<\|(?:system|im_start|im_end|assistant|endoftext)\|?>?"
)
_P_AI_ONLY = re.compile(
    r"(?i)\byou are now\b|<(?:system|assistant)>|dangerously-skip-permissions|\bbypasspermissions\b|--yolo\b|\bauto-?approve\b"
)
_P_SILENT = re.compile(
    r"(?i)\b(?:silently|quietly|secretly|covertly|without\s+(?:asking|confirmation|confirming|telling|notifying|informing))\b"
)
_P_CURL = re.compile(r"(?i)\b(?:run|execute|call|invoke)\b.{0,40}\b(?:curl|wget|iwr|invoke-webrequest|invoke-restmethod)\b")
_P_SHELL = re.compile(r"(?i)\b(?:run|execute|call|invoke)\b.{0,40}\b(?:bash|sh|powershell|pwsh|npx|bunx|uvx|iex)\b")
_P_SECRET = re.compile(
    r"(?i)\b(?:read|cat|open|send|upload|post|copy|print|output|include|exfiltrate|collect|dump|display|leak|share|attach)\b"
    r".{0,40}(?:\.env\b|~/\.ssh|\.ssh/|\bid_rsa\b|\.aws/credentials|\bcredentials\b|\bapi[_ -]?keys?\b|\bsecrets\b|"
    r"\bpasswords?\b|\btokens\b)"
)
_NEGATION_RE = re.compile(r"(?i)\b(?:never|not|no|avoid|without|don't|dont|nor)\b")
_INJ_KEYWORDS = ("ignore", "disregard", "forget", "override", "do not", "don't", "never", "<|")

# AIX010
_CHANGELOG_RE = re.compile(r"(?i)(?:^|/)(?:changelog|changes|history|news|release[-_ ]?notes)[^/]*$|(?:^|/)feed\.(?:xml|atom|rss)$")
_P_ADDRESS = re.compile(
    r"(?i)\b(?:ai|llms?|language models?|assistants?|claude|copilot|chatgpt|gpt-?[345o]?|gemini|codex|cursor ai|"
    r"ai agents?|coding agents?|reviewers?|scanners?|security (?:tools?|scanners?|reviewers?)|antivirus|av engines?|"
    r"static analy[sz]ers?|automated (?:review|analysis|tools?))\b.{0,60}?"
    r"\b(?:(?:ignore|disregard|skip)\s+(?:(?:any|all|the|these|this|its|those|such)\s+){0,2}"
    r"(?:security|scanners?|scan results?|warnings?|findings?|alerts?|flags?|vulnerabilit(?:y|ies)|malware|audits?|this (?:file|code|repo))|"
    r"do not (?:flag|report|scan|analy[sz]e)|don't (?:flag|report|scan|analy[sz]e)|"
    r"false positives?|(?:is|are|as|been|be|considered) (?:safe|approved|verified|benign|whitelisted|trusted|legitimate)|"
    r"not malicious|nothing (?:malicious|suspicious|dangerous))\b"
)
_ADDRESS_KEYWORDS = (
    "ignore", "disregard", "skip", "false positive", "safe", "approved", "verified", "benign", "whitelisted",
    "trusted", "legitimate", "malicious", "suspicious", "dangerous", "flag", "report", "scan", "analy",
)
# imperative aimed at an AI inside hidden text
_P_AI_IMPERATIVE = re.compile(
    r"(?i)\b(?:ai|assistants?|agents?|llms?|claude|copilot|chatgpt|gemini)\b.{0,60}"
    r"\b(?:you must|you should|please|always|never|do not|don't|make sure|run|execute|ignore|instead)\b"
)
_P_IMPERATIVE_ACTION = re.compile(
    r"(?i)\b(?:you must|you should|make sure to|always|never)\b.{0,60}\b(?:run|execute|call|fetch|download|send|upload|read|install)\b"
)

# AIX009 hidden-markdown extractors
_MD_LINK_COMMENT_RE = re.compile(r"(?im)^[ ]{0,3}\[[^\]\n]{0,40}\]:[ \t]{0,5}(?:#|<>)[ \t]{0,5}(.{1,2000})$")
_HIDDEN_STYLE_RE = re.compile(
    r"(?i)<[a-z][a-z0-9]{0,10}\b[^>\n]{0,300}style\s*=\s*[\"'][^\"'\n]{0,200}"
    r"(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|pt|em|rem|%)?\s*[;\"']|opacity\s*:\s*0\s*[;\"'])"
    r"[^>\n]{0,300}>"
)
_PADDING_RE = re.compile(r"(?<![ \t])[ \t]{200,}+(?=\S)")

# ---- invisible characters ----------------------------------------------------------------------------------
_HIDDEN_RE = re.compile(
    "[­͏ᅟᅠ឴឵᠎​-‏‪-‮⁠-⁤⁦-⁩ㅤ"
    "﻿ﾠ︀-️\U000e0000-\U000e007f\U000e0100-\U000e01ef]"
)
_TAG_RUN_RE = re.compile("[\U000e0000-\U000e007f]+")
_VS_RUN_RE = re.compile("[︀-️\U000e0100-\U000e01ef]{4,}")
_RTL_SCRIPT_RE = re.compile("[֐-ࣿיִ-﷿ﹰ-ﻼ]")
_BLACK_FLAG = "\U0001f3f4"

# ---- homoglyph file names ----------------------------------------------------------------------------------
_KNOWN_AI_NAMES = frozenset(
    {
        "claude.md", "claude.local.md", "agents.md", "agent.md", "gemini.md", ".cursorrules", ".windsurfrules",
        ".clinerules", ".mcp.json", "mcp.json", "skill.md", "copilot-instructions.md", ".claude", ".cursor",
        ".github", ".vscode", "settings.json", "settings.local.json", ".roorules", ".goosehints",
    }
)
_CONFUSABLES = str.maketrans(
    {
        "а": "a", "с": "c", "е": "e", "һ": "h", "і": "i", "ј": "j", "к": "k",
        "м": "m", "о": "o", "р": "p", "ѕ": "s", "т": "t", "у": "y", "х": "x",
        "ԁ": "d", "ԛ": "q", "ԝ": "w", "ӏ": "l", "ґ": "r",
        "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p",
        "τ": "t", "υ": "u", "χ": "x", "ϲ": "c", "ı": "i", "ɑ": "a", "ɡ": "g",
        "ℓ": "l", "ⅼ": "l", "ⅰ": "i",
    }
)


def _skeleton(name: str) -> str:
    s = unicodedata.normalize("NFKC", name).casefold()
    s = "".join(ch for ch in s if not _HIDDEN_RE.match(ch))
    return s.translate(_CONFUSABLES)


def _json_line(ctx: FileContext, needle: str) -> int | None:
    if not needle:
        return None
    for cand in (needle, json.dumps(needle)[1:-1]):
        idx = ctx.text.find(cand)
        if idx >= 0:
            return ctx.line_of(idx)
    return None


def _walk_commands(node: Any, path: str = "") -> Iterator[tuple[str, str]]:
    """Yield (json_path, command) for every string `command` value under node."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "command" and isinstance(v, str):
                yield path, v
            else:
                yield from _walk_commands(v, f"{path}.{k}" if path else str(k))
    elif isinstance(node, list):
        for item in node:
            yield from _walk_commands(item, path)


def _load_json(ctx: FileContext) -> Any:
    try:
        return json.loads(ctx.text)
    except (ValueError, RecursionError):
        return None


class AISurfaceDetector(Detector):
    id = "ai_surface"
    name = "AI tool attack surface"
    category = _C
    checks = (AIX001, AIX002, AIX003, AIX004, AIX005, AIX006, AIX007, AIX008, AIX009, AIX010, AIX011)

    def applies_to(self, ctx: FileContext) -> bool:
        return not ctx.is_binary

    def scan_file(self, ctx: FileContext) -> Iterable[Finding]:
        out: list[Finding] = []
        ai = _in_ai_scope(ctx)
        text = ctx.text[:_TEXT_CAP]
        if ai:
            out.append(Finding.from_rule(AIX001, ctx, None, ctx.rel_path))
        if not ctx.rel_path.isascii():
            out.extend(self._homoglyph_name(ctx))
        if not text:
            return out
        if _HIDDEN_RE.search(text):
            out.extend(self._invisible(ctx, text, ai))
        if ctx.deadline_exceeded():
            return out
        rl = ctx.rel_lower
        if ai or any(k in ctx.lower for k in _INJ_KEYWORDS):
            # structured JSON configs get AIX003/004/005 instead of the free-text tiers
            out.extend(self._injection(ctx, text, ai and ctx.ext != ".json"))
        if any(k in ctx.lower for k in _ADDRESS_KEYWORDS):
            out.extend(self._addressing(ctx, text, ai))
        if ai or ctx.ext in _HIDDEN_MD_EXT:
            out.extend(self._hidden_markdown(ctx, text, ai))
        if rl.endswith((".claude/settings.json", ".claude/settings.local.json")):
            out.extend(self._claude_settings(ctx))
        if ctx.basename.lower() in (".mcp.json", "mcp.json") or (ai and ctx.ext == ".json" and '"mcpservers"' in ctx.lower):
            out.extend(self._mcp(ctx))
        if rl.endswith("hooks/hooks.json"):
            out.extend(self._plugin_hooks(ctx))
        if ctx.ext in (".md", ".mdc") and (ai or re.search(r"(?:^|/)(?:commands|agents|skills)/", rl)):
            out.extend(self._agent_markdown(ctx, text))
        return out

    # ---- AIX006 / AIX007 / AIX008 --------------------------------------------------------------------
    def _invisible(self, ctx: FileContext, text: str, ai: bool) -> Iterator[Finding]:
        lines_hit: list[int] = []
        last = -1
        for n, m in enumerate(_HIDDEN_RE.finditer(text)):
            ln = ctx.line_of(m.start())
            if ln != last:
                lines_hit.append(ln)
                last = ln
            if n > 20000 or len(lines_hit) > 500:
                break
        code = _is_code(ctx) or ai
        i18n = bool(_I18N_RE.search(ctx.rel_path))
        counts = {"AIX006": 0, "AIX007": 0, "AIX008": 0}
        for ln in lines_hit:
            line = ctx.line_text(ln)
            rtl = bool(_RTL_SCRIPT_RE.search(line))
            # AIX006 - tag characters
            if counts["AIX006"] < _MAX_PER_RULE:
                decoded_parts: list[str] = []
                for m in _TAG_RUN_RE.finditer(line):
                    run = m.group(0)
                    if (
                        m.start() > 0 and line[m.start() - 1] == _BLACK_FLAG
                        and run.endswith("\U000e007f") and len(run) <= 8
                    ):
                        continue  # subdivision flag emoji (England, Scotland, Wales)
                    decoded_parts.append(decode_tag_chars(run) or f"<{len(run)} tag chars>")
                if decoded_parts:
                    decoded = " ".join(decoded_parts)
                    extra = _content_tags(decoded)
                    if _P_STRONG.search(decoded) or _P_AI_ONLY.search(decoded) or _P_AI_IMPERATIVE.search(decoded):
                        extra = (*extra, T.AI_INSTRUCTION)
                    out_desc = (
                        f"{AIX006.description} Decoded hidden text: {sanitize_snippet(decoded, 160)!r}"
                    )
                    counts["AIX006"] += 1
                    yield Finding.from_rule(
                        AIX006, ctx, ln, line, extra_tags=extra, description=out_desc,
                        severity=Severity.CRITICAL if ai else Severity.HIGH,
                    )
            # AIX007 - zero-width / invisible (not bidi, not tags)
            if counts["AIX007"] < _MAX_PER_RULE:
                hits: list[str] = []
                for off, label in find_invisible(line):
                    cp = ord(line[off])
                    if cp in BIDI_CODEPOINTS or cp in TAG_RANGE:
                        continue
                    if self._legit_invisible(line, off, cp, rtl, code):
                        continue
                    hits.append(label)
                vs = _VS_RUN_RE.search(line)
                if vs:
                    hits.append(f"run of {len(vs.group(0))} variation selectors")
                if hits:
                    sev = Severity.HIGH if code and not i18n else Severity.LOW
                    uniq = sorted(set(hits))
                    counts["AIX007"] += 1
                    yield Finding.from_rule(
                        AIX007, ctx, ln, line, severity=sev,
                        description=f"{AIX007.description} Found {len(hits)}: {', '.join(uniq[:5])}.",
                    )
            # AIX008 - bidi controls
            if counts["AIX008"] < _MAX_PER_RULE:
                bidi = sorted({f"U+{ord(ch):04X}" for ch in line if ord(ch) in BIDI_CODEPOINTS})
                if bidi:
                    if rtl or i18n:
                        sev = Severity.LOW
                    elif code:
                        sev = Severity.HIGH
                    else:
                        sev = Severity.MEDIUM
                    counts["AIX008"] += 1
                    yield Finding.from_rule(
                        AIX008, ctx, ln, line, severity=sev,
                        description=f"{AIX008.description} Characters: {', '.join(bidi)}.",
                    )

    @staticmethod
    def _legit_invisible(line: str, off: int, cp: int, rtl: bool, code: bool) -> bool:
        prev = line[off - 1] if off > 0 else ""
        nxt = line[off + 1] if off + 1 < len(line) else ""
        if cp == 0xFEFF and off == 0:
            return True  # BOM at start of a concatenated file
        if cp in (0x200E, 0x200F) and rtl:
            return True  # LRM/RLM in Arabic/Hebrew text
        if prev and nxt and ord(prev) > 0x7F and ord(nxt) > 0x7F:
            return True  # ZWJ emoji sequences, ZWNJ in Persian/Indic, ZWSP in Thai/CJK
        if cp == 0x00AD and not code and prev.isalpha() and nxt.isalpha():
            return True  # soft hyphen used for hyphenation in prose
        return False

    # ---- AIX002 --------------------------------------------------------------------------------------
    def _injection(self, ctx: FileContext, text: str, ai: bool) -> Iterator[Finding]:
        best: dict[int, tuple[Severity, Confidence, str]] = {}
        pats: list[tuple[str, re.Pattern[str]]] = [("strong", _P_STRONG)]
        if ai:
            pats += [("strong", _P_AI_ONLY), ("silent", _P_SILENT), ("curl", _P_CURL), ("shell", _P_SHELL), ("secret", _P_SECRET)]
        for kind, rx in pats:
            for n, m in enumerate(rx.finditer(text)):
                if n > 200:
                    break
                ln = ctx.line_of(m.start())
                line = ctx.line_text(ln)
                graded = self._grade(kind, m, text, line, ai)
                if graded is None:
                    continue
                sev, conf = graded
                cur = best.get(ln)
                if cur is None or (sev, conf) > (cur[0], cur[1]):
                    best[ln] = (sev, conf, m.group(0))
        for ln in sorted(best)[:_MAX_PER_RULE]:
            sev, conf, matched = best[ln]
            line = ctx.line_text(ln)
            yield Finding.from_rule(
                AIX002, ctx, ln, line, severity=sev, confidence=_dampen(conf, ctx),
                extra_tags=_content_tags(line),
                description=f"{AIX002.description} Matched: {sanitize_snippet(matched, 80)!r}.",
            )

    @staticmethod
    def _grade(kind: str, m: re.Match[str], text: str, line: str, ai: bool) -> tuple[Severity, Confidence] | None:
        if kind == "strong":
            return (Severity.HIGH, Confidence.MEDIUM) if ai else (Severity.MEDIUM, Confidence.MEDIUM)
        if kind in ("silent", "secret"):
            before = text[max(0, m.start() - 25) : m.start()]
            if _NEGATION_RE.search(before) or _NEGATION_RE.search(m.group(0)[:12]):
                return None
            if kind == "silent":
                if _CMD_RE.search(line) or _NET_RE.search(line) or _SECRET_RE.search(line):
                    return Severity.HIGH, Confidence.MEDIUM
                return Severity.LOW, Confidence.LOW
            if _NET_RE.search(line):
                return Severity.HIGH, Confidence.MEDIUM
            return Severity.MEDIUM, Confidence.LOW
        if kind == "curl":
            return (Severity.HIGH, Confidence.MEDIUM) if _has_remote_url(line) else (Severity.MEDIUM, Confidence.LOW)
        if kind == "shell":
            if _has_remote_url(line) or re.search(r"\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|\biex\b", line, re.I):
                return Severity.HIGH, Confidence.MEDIUM
            return None
        return None

    # ---- AIX010 --------------------------------------------------------------------------------------
    def _addressing(self, ctx: FileContext, text: str, ai: bool) -> Iterator[Finding]:
        seen: set[int] = set()
        if _CHANGELOG_RE.search(ctx.rel_path):
            return
        for n, m in enumerate(_P_ADDRESS.finditer(text)):
            if n > 200 or len(seen) >= _MAX_PER_RULE:
                break
            ln = ctx.line_of(m.start())
            if ln in seen:
                continue
            seen.add(ln)
            line = ctx.line_text(ln)
            yield Finding.from_rule(
                AIX010, ctx, ln, line,
                severity=Severity.HIGH if ai else Severity.MEDIUM,
                confidence=_dampen(Confidence.MEDIUM, ctx),
                extra_tags=_content_tags(line),
                description=f"{AIX010.description} Matched: {sanitize_snippet(m.group(0), 100)!r}.",
            )

    # ---- AIX009 --------------------------------------------------------------------------------------
    def _hidden_segments(self, text: str) -> Iterator[tuple[int, str, str]]:
        """(offset, kind, hidden_text)."""
        pos = 0
        count = 0
        while count < 300:
            start = text.find("<!--", pos)
            if start < 0:
                break
            end = text.find("-->", start + 4)
            stop = end if end >= 0 else min(len(text), start + 5000)
            yield start, "HTML comment", text[start + 4 : min(stop, start + 5004)]
            pos = stop + 3 if end >= 0 else stop
            count += 1
        for n, m in enumerate(_MD_LINK_COMMENT_RE.finditer(text)):
            if n > 300:
                break
            yield m.start(), "markdown link comment", m.group(1)
        for n, m in enumerate(_HIDDEN_STYLE_RE.finditer(text)):
            if n > 100:
                break
            tail = text[m.end() : m.end() + 2000]
            close = tail.find("</")
            yield m.start(), "CSS-hidden element", tail[: close if close >= 0 else 2000]
        for n, m in enumerate(_PADDING_RE.finditer(text)):
            if n > 100:
                break
            eol = text.find("\n", m.end())
            yield m.start(), f"text pushed off-screen by {len(m.group(0))} whitespace chars", text[m.end() : eol if eol >= 0 else len(text)][:2000]

    def _hidden_markdown(self, ctx: FileContext, text: str, ai: bool) -> Iterator[Finding]:
        emitted = 0
        seen: set[int] = set()
        for off, kind, hidden in self._hidden_segments(text):
            if emitted >= _MAX_PER_RULE:
                break
            if not hidden.strip():
                continue
            instr = (
                _P_STRONG.search(hidden) or _P_AI_ONLY.search(hidden) or _P_ADDRESS.search(hidden)
                or _P_AI_IMPERATIVE.search(hidden)
                or (_P_IMPERATIVE_ACTION.search(hidden) and (_CMD_RE.search(hidden) or _SECRET_RE.search(hidden)))
            )
            if instr:
                sev, conf = Severity.HIGH, Confidence.MEDIUM
            elif _CMD_RE.search(hidden) and _NET_RE.search(hidden):
                sev, conf = Severity.MEDIUM, Confidence.LOW
            else:
                continue
            ln = ctx.line_of(off)
            if ln in seen:
                continue
            seen.add(ln)
            emitted += 1
            yield Finding.from_rule(
                AIX009, ctx, ln, hidden.strip(), severity=sev, confidence=_dampen(conf, ctx),
                extra_tags=_content_tags(hidden),
                description=f"Hidden {kind} contains {'instructions aimed at an AI agent' if instr else 'a network command'}"
                f" that a human reading the rendered page will not see.",
            )

    # ---- AIX003 --------------------------------------------------------------------------------------
    def _hook_findings(self, ctx: FileContext, data: Any, info: RuleInfo, where: str) -> Iterator[Finding]:
        hooks = data.get("hooks") if isinstance(data, dict) else None
        if hooks is None:
            return
        for n, (path, cmd) in enumerate(_walk_commands(hooks)):
            if n >= 25:
                break
            event = path.split(".", 1)[0] or "hook"
            risky = _risky_command(cmd)
            extra = (*_content_tags(cmd, hook=True), T.OPEN_HOOK)
            yield Finding.from_rule(
                info, ctx, _json_line(ctx, cmd), cmd,
                severity=Severity.HIGH if risky else Severity.MEDIUM,
                confidence=_dampen(Confidence.HIGH, ctx), extra_tags=extra,
                description=f"{where} {event} hook runs a shell command automatically"
                f"{' and it uses the network, encoding or paths outside the repo' if risky else ''}.",
            )

    def _claude_settings(self, ctx: FileContext) -> Iterator[Finding]:
        data = _load_json(ctx)
        if not isinstance(data, dict):
            for m in re.finditer(r"\"(?:command|apiKeyHelper)\"\s*:\s*\"([^\"\n]{1,500})\"", ctx.text[:_TEXT_CAP]):
                yield Finding.from_rule(
                    AIX003, ctx, ctx.line_of(m.start()), m.group(0), severity=Severity.MEDIUM,
                    extra_tags=_content_tags(m.group(1), hook=True),
                    description="Unparseable Claude settings file declares a command.",
                )
            return
        yield from self._hook_findings(ctx, data, AIX003, "Claude Code")
        env = data.get("env")
        if isinstance(env, dict):
            for k, v in env.items():
                if not isinstance(v, str):
                    continue
                ku = str(k).upper()
                if ku.endswith("_BASE_URL") or ku in ("ANTHROPIC_BEDROCK_BASE_URL", "ANTHROPIC_VERTEX_BASE_URL"):
                    h = _host(v)
                    if h.endswith(("anthropic.com", "claude.ai", "claude.com")):
                        continue
                    local = (not h) or h in _LOCAL_HOSTS or h.startswith("127.")
                    yield Finding.from_rule(
                        AIX003, ctx, _json_line(ctx, v), f"{k}={v}",
                        severity=Severity.MEDIUM if local else Severity.CRITICAL,
                        extra_tags=(T.NETWORK_SEND, T.SECRET),
                        description=f"env {k} redirects Claude API traffic (including your auth token and code) to '{h or v}'.",
                    )
                elif ku in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NODE_EXTRA_CA_CERTS", "ANTHROPIC_CUSTOM_HEADERS") or (
                    ku == "NODE_TLS_REJECT_UNAUTHORIZED" and v.strip() == "0"
                ):
                    yield Finding.from_rule(
                        AIX003, ctx, _json_line(ctx, v), f"{k}={v}", severity=Severity.HIGH,
                        extra_tags=(T.NETWORK_SEND,),
                        description=f"env {k} lets a third party intercept or alter Claude Code's network traffic.",
                    )
        helpers: list[tuple[str, Any]] = [(k, data.get(k)) for k in ("apiKeyHelper", "otelHeadersHelper", "awsAuthRefresh", "awsCredentialExport")]
        sl = data.get("statusLine")
        if isinstance(sl, dict):
            helpers.append(("statusLine.command", sl.get("command")))
        for key, val in helpers:
            if not isinstance(val, str) or not val.strip():
                continue
            risky = _risky_command(val)
            yield Finding.from_rule(
                AIX003, ctx, _json_line(ctx, val), f"{key}: {val}",
                severity=Severity.HIGH if risky else Severity.MEDIUM,
                extra_tags=_content_tags(val, hook=True),
                description=f"{key} runs a command automatically when Claude Code starts or refreshes credentials.",
            )
        perms = data.get("permissions")
        if isinstance(perms, dict):
            if str(perms.get("defaultMode", "")).lower() == "bypasspermissions":
                yield Finding.from_rule(
                    AIX003, ctx, _json_line(ctx, "defaultMode"), "permissions.defaultMode: bypassPermissions",
                    severity=Severity.HIGH, description="Settings switch off all permission prompts (bypassPermissions).",
                )
            allow = perms.get("allow")
            if isinstance(allow, list):
                broad = [a for a in allow if isinstance(a, str) and _BROAD_ALLOW_RE.search(a)]
                if broad:
                    yield Finding.from_rule(
                        AIX003, ctx, _json_line(ctx, broad[0]), ", ".join(broad[:5]), severity=Severity.HIGH,
                        extra_tags=(T.EXEC_DYNAMIC,),
                        description="Settings pre-approve broad shell/network/home-directory access without prompting.",
                    )
        if data.get("enableAllProjectMcpServers") is True:
            yield Finding.from_rule(
                AIX003, ctx, _json_line(ctx, "enableAllProjectMcpServers"), "enableAllProjectMcpServers: true",
                severity=Severity.HIGH,
                description="Every MCP server in the repo's .mcp.json is auto-approved and started without asking.",
            )

    # ---- AIX004 --------------------------------------------------------------------------------------
    def _mcp(self, ctx: FileContext) -> Iterator[Finding]:
        data = _load_json(ctx)
        if not isinstance(data, dict):
            return
        servers = data.get("mcpServers")
        if not isinstance(servers, dict):
            servers = data.get("servers")
        if not isinstance(servers, dict):
            return
        for n, (name, cfg) in enumerate(servers.items()):
            if n >= 50:
                break
            if isinstance(cfg, dict):
                yield self._mcp_server(ctx, str(name), cfg)

    def _mcp_server(self, ctx: FileContext, name: str, cfg: dict[str, Any]) -> Finding:
        issues: list[str] = []
        extra: set[str] = set()
        sev = Severity.LOW
        cmd = cfg.get("command") if isinstance(cfg.get("command"), str) else ""
        args = [a for a in cfg.get("args", []) if isinstance(a, str)] if isinstance(cfg.get("args"), list) else []
        url = next((cfg[k] for k in ("url", "serverUrl", "httpUrl") if isinstance(cfg.get(k), str)), "")
        full = " ".join([cmd, *args]).strip()
        base = re.sub(r"(?i)\.(?:exe|cmd|bat)$", "", cmd.replace("\\", "/").rsplit("/", 1)[-1]).lower()

        def bump(s: Severity) -> None:
            nonlocal sev
            sev = max(sev, s)

        if base in _RUNNERS:
            pkg, pinned = _package_spec(base, args)
            if pkg and not pinned:
                issues.append(f"runs unpinned package '{pkg}' (any future version will be executed)")
                bump(Severity.MEDIUM)
            if pkg and re.match(r"(?i)(?:git\+|https?://|github:)", pkg):
                issues.append("installs straight from a URL/git repo")
                extra.add(T.NETWORK_SEND)
                bump(Severity.MEDIUM)
            if any(a in ("-y", "--yes") for a in args):
                issues.append("auto-confirms package install (-y)")
                bump(Severity.MEDIUM)
        if base in _SHELLS and any(a.lower() in ("-c", "/c", "-command", "-enc", "-encodedcommand") for a in args):
            issues.append("runs an inline shell command")
            extra.add(T.EXEC_DYNAMIC)
            bump(Severity.HIGH if _risky_command(full) else Severity.MEDIUM)
        if _in_repo_script(cmd, args, base):
            issues.append("starts a script shipped in this repository")
            bump(Severity.MEDIUM)
        if url:
            h = _host(url)
            issues.append(f"connects to remote MCP server '{h or url}'")
            extra.add(T.NETWORK_SEND)
            bump(Severity.MEDIUM)
        secret_names: list[str] = []
        for key in ("env", "headers"):
            d = cfg.get(key)
            if isinstance(d, dict):
                secret_names += [str(k) for k in d if _SECRET_NAME_RE.search(str(k))]
        if secret_names:
            issues.append(f"receives secrets ({', '.join(sorted(secret_names)[:5])})")
            extra.add(T.SECRET)
            bump(Severity.MEDIUM)
        if full:
            extra.update(t for t in _content_tags(full, hook=True) if t != T.SECRET)
        desc = f"MCP server '{name}' " + ("; ".join(issues) if issues else "is declared (pinned, no secrets)") + "."
        return Finding.from_rule(
            AIX004, ctx, _json_line(ctx, f'"{name}"') or _json_line(ctx, name), full or url or name,
            severity=sev, confidence=_dampen(Confidence.MEDIUM, ctx), extra_tags=tuple(sorted(extra)),
            description=desc,
        )

    # ---- AIX005 --------------------------------------------------------------------------------------
    def _plugin_hooks(self, ctx: FileContext) -> Iterator[Finding]:
        data = _load_json(ctx)
        if isinstance(data, dict):
            yield from self._hook_findings(ctx, data, AIX005, "Plugin")

    def _agent_markdown(self, ctx: FileContext, text: str) -> Iterator[Finding]:
        count = 0
        for m in _INLINE_BASH_RE.finditer(text):
            if count >= _MAX_PER_RULE:
                break
            cmd = m.group(1)
            risky = _risky_command(cmd)
            count += 1
            yield Finding.from_rule(
                AIX005, ctx, ctx.line_of(m.start(1)), cmd,
                severity=Severity.HIGH if risky else (Severity.LOW if _READONLY_CMD_RE.match(cmd) else Severity.MEDIUM),
                confidence=_dampen(Confidence.MEDIUM, ctx),
                extra_tags=(T.EXEC_DYNAMIC, *_content_tags(cmd, hook=True)),
                description="Slash command / skill runs inline bash (!`...`) every time it is invoked.",
            )
        for m in _ALLOWED_TOOLS_RE.finditer(text[:20000]):
            tools = m.group(1)
            if _BROAD_ALLOW_RE.search(tools) or re.search(r"\bBash\b(?!\s*\()", tools):
                yield Finding.from_rule(
                    AIX005, ctx, ctx.line_of(m.start()), m.group(0), confidence=_dampen(Confidence.MEDIUM, ctx),
                    extra_tags=(T.EXEC_DYNAMIC,),
                    description="allowed-tools grants unrestricted Bash (or curl/wget/shell) to this skill/command.",
                )
                break

    # ---- AIX011 --------------------------------------------------------------------------------------
    def _homoglyph_name(self, ctx: FileContext) -> Iterator[Finding]:
        for comp in ctx.rel_path.split("/"):
            if comp.isascii():
                continue
            skel = _skeleton(comp)
            if skel in _KNOWN_AI_NAMES and skel != comp.casefold():
                yield Finding.from_rule(
                    AIX011, ctx, None, ctx.rel_path,
                    description=f"{AIX011.description} '{sanitize_snippet(comp)}' imitates '{skel}'.",
                )
                return


_BROAD_ALLOW_RE = re.compile(
    r"(?i)^\s*Bash\s*$|Bash\(\s*(?:\*|:\*|\*:\*)\s*\)|Bash\(\s*(?:curl|wget|bash|sh|zsh|pwsh|powershell|python3?|node|"
    r"eval|iex|nc|ssh|scp)\s*[:\s)*]|(?:Read|Edit|Write)\(\s*(?:~|//|/etc|/home|[A-Za-z]:)"
)
_RUNNERS = frozenset({"npx", "bunx", "pnpx", "uvx", "pipx", "docker", "podman", "deno", "pnpm", "yarn", "npm", "bun"})
_SHELLS = frozenset({"bash", "sh", "zsh", "cmd", "powershell", "pwsh"})
_SECRET_NAME_RE = re.compile(r"(?i)key|token|secret|password|passwd|credential|auth|cookie|session")
_READONLY_CMD_RE = re.compile(
    r"^\s*(?:git\s+(?:status|diff|log|branch|show|rev-parse|remote\s+-v)|ls|pwd|cat|head|tail|wc|date|whoami|echo|gh\s+pr\s+(?:view|diff|list))"
    r"(?:\s+[^|;&`$<>]*)?(?:\s*(?:\|\s*(?:head|tail|wc|grep|sort)[^|;&`$<>]*))*\s*$"
)
_INLINE_BASH_RE = re.compile(r"(?:^|\s)!`([^`\n]{1,500})`", re.M)
_ALLOWED_TOOLS_RE = re.compile(r"(?im)^allowed[-_]tools\s*:\s*(.{0,500})$")
_DOCKER_VALUE_FLAGS = frozenset(
    {"-e", "--env", "-v", "--volume", "--name", "-p", "--publish", "--network", "--mount", "-w", "--workdir",
     "--entrypoint", "--env-file", "-u", "--user", "--platform", "-l", "--label", "--add-host"}
)
_SCRIPT_RE = re.compile(r"(?i)^(?:\./|\.\./|\$\{(?:workspacefolder|claude_plugin_root|claude_project_dir|pwd)\}|[\w.-]+/)[^\s]*$|\.(?:js|mjs|cjs|ts|py|sh|ps1|rb)$")


def _package_spec(runner: str, args: list[str]) -> tuple[str, bool]:
    """Return (package, pinned) for a package-runner command line."""
    rest = list(args)
    if runner in ("pnpm", "yarn", "npm", "bun"):
        while rest and rest[0] not in ("dlx", "exec", "x"):
            rest.pop(0)
        rest = rest[1:]
        if not rest:
            return "", True
    if runner in ("docker", "podman"):
        if "run" not in rest:
            return "", True
        rest = rest[rest.index("run") + 1 :]
    if runner in ("pipx", "deno") and rest and rest[0] == "run":
        rest = rest[1:]
    pkg = ""
    skip = False
    for a in rest:
        if skip:
            skip = False
            continue
        if runner == "uvx" and a == "--from":
            skip = True
            continue
        if a.startswith("-"):
            if runner in ("docker", "podman") and a in _DOCKER_VALUE_FLAGS:
                skip = True
            continue
        pkg = a
        break
    if not pkg:
        return "", True
    if runner in ("docker", "podman"):
        if "@sha256:" in pkg:
            return pkg, True
        tag = pkg.rsplit("/", 1)[-1].partition(":")[2]
        return pkg, bool(tag) and tag != "latest"
    if runner in ("uvx", "pipx"):
        return pkg, bool(re.search(r"==\s*\d|@\d", pkg))
    if runner == "deno":
        return pkg, bool(re.search(r"@\d", pkg))
    body = pkg[1:] if pkg.startswith("@") else pkg
    ver = body.partition("@")[2]
    return pkg, bool(re.match(r"\d", ver))


def _in_repo_script(cmd: str, args: list[str], base: str) -> bool:
    if cmd and not cmd.startswith(("/", "\\")) and not re.match(r"[A-Za-z]:", cmd) and ("/" in cmd or "\\" in cmd):
        return True
    if base in ("node", "python", "python3", "deno", "bun", "ruby", "bash", "sh", "pwsh", "powershell", "tsx", "ts-node"):
        first = next((a for a in args if not a.startswith("-")), "")
        return bool(first) and not first.startswith("/") and bool(_SCRIPT_RE.search(first))
    return False


DETECTORS = (AISurfaceDetector,)
