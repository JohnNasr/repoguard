"""OBF001-OBF011: obfuscation (decode->exec, packers, encoded PowerShell, encoded blobs, hidden code, entropy,
homoglyphs, dynamic resolution, commercial packers, odd source encodings). Static only: nothing is executed;
encoded blobs are decoded in memory (size-capped) and the decoded text is rescanned with regex rules."""

from __future__ import annotations

import ast
import base64
import binascii
import bz2
import codecs
import lzma
import re
import unicodedata
import zlib
from collections.abc import Iterable, Iterator

from .. import tags as T
from ..context import FileContext
from ..detector import Detector, RuleInfo
from ..models import Category, Confidence, Finding, Severity
from ..pyast import call_name, const_str, dotted_name, import_aliases, iter_calls, parse, segment
from ..rules import MULTILINE_CAP, Rule, run_rules
from ..textutil import printable_ratio, sanitize_snippet, shannon_entropy
from .secrets import adjust_for_location, drop_severity, line_snippet

C, H, M, L, I = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO
CH, CM, CL = Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW
_CAT = Category.OBFUSCATION
_REC = ("Decode the hidden part (without running it) and read it before installing. Legitimate projects rarely "
        "need to hide what their code does.")


def _info(rid: str, title: str, sev: Severity, conf: Confidence, tags: Iterable[str], desc: str) -> RuleInfo:
    return RuleInfo(rid, title, sev, conf, _CAT, desc, _REC, frozenset(tags))


_DX = {T.OBFUSCATED, T.DECODE, T.EXEC_DYNAMIC, T.NO_DAMPEN}
OBF001 = _info("OBF001", "Python decode -> exec", C, CH, _DX,
               "Python code decodes data (base64/hex/zlib/marshal/chr-join...) and executes the result.")
OBF002 = _info("OBF002", "JavaScript decode -> exec", C, CH, _DX,
               "JavaScript passes decoded data (atob/Buffer.from/fromCharCode/\\x escapes) to eval/Function/exec.")
OBF003 = _info("OBF003", "JavaScript packer / obfuscator output", H, CH, {T.OBFUSCATED, T.NO_DAMPEN},
               "Output of a JS packer or obfuscator (p,a,c,k,e,d, _0x names, JSFuck, aaencode/jjencode).")
OBF004 = _info("OBF004", "Obfuscated PowerShell", H, CH, _DX,
               "PowerShell run with an encoded command, decode+Invoke-Expression, or a hidden bypass launcher.")
OBF005 = _info("OBF005", "Large encoded blob", M, CM, {T.OBFUSCATED, T.DECODE},
               "A large base64/hex blob in source code. It was decoded (not run) and inspected.")
OBF006 = _info("OBF006", "Code hidden by whitespace or very long lines", H, CH, {T.OBFUSCATED},
               "Code pushed off-screen by a long run of spaces, or a suspiciously long line in a script.")
OBF007 = _info("OBF007", "High-entropy source", M, CL, {T.OBFUSCATED},
               "The file or a long string literal has random-looking (encrypted/compressed) content.")
OBF008 = _info("OBF008", "Homoglyph identifiers", H, CM, {T.OBFUSCATED},
               "Identifiers mix Latin with look-alike Cyrillic/Greek letters (or imports use non-ASCII names).")
OBF009 = _info("OBF009", "Dynamic name resolution", M, CM, {T.OBFUSCATED, T.EXEC_DYNAMIC},
               "Functions or modules are looked up by computed names, hiding what is actually called.")
OBF010 = _info("OBF010", "Commercially packed Python", H, CM, {T.OBFUSCATED, T.EXEC_DYNAMIC},
               "Python protected by PyArmor/PyObfuscator/Hyperion or lambda-chain packing.")
OBF011 = _info("OBF011", "Unusual source encoding", M, CH, {T.OBFUSCATED},
               "Source declares an unusual encoding (PEP 263) or is stored as UTF-16, which hides content from "
               "reviewers and tools.")
CHECKS = (OBF001, OBF002, OBF003, OBF004, OBF005, OBF006, OBF007, OBF008, OBF009, OBF010, OBF011)

CODE_LANGS = frozenset({
    "python", "javascript", "typescript", "shell", "powershell", "batch", "vbscript", "ruby", "go", "rust", "java",
    "kotlin", "csharp", "c", "cpp", "php", "perl", "lua", "swift", "scala", "groovy", "r", "dart", "elixir", "nim",
    "zig", "html",
})
JS_LANGS = frozenset({"javascript", "typescript", "html"})

# =====================================================================================
# OBF001 - Python decode -> exec
# =====================================================================================
_DECODE_FULL = frozenset({
    "base64.b64decode", "base64.b32decode", "base64.b85decode", "base64.a85decode", "base64.urlsafe_b64decode",
    "base64.standard_b64decode", "base64.decodebytes", "base64.b16decode", "binascii.unhexlify",
    "binascii.a2b_base64", "binascii.a2b_hex", "bytes.fromhex", "bytearray.fromhex", "codecs.decode",
    "zlib.decompress", "lzma.decompress", "bz2.decompress", "gzip.decompress", "pickle.loads", "marshal.loads",
})
_DECODE_LAST = frozenset({"b64decode", "b32decode", "b85decode", "a85decode", "urlsafe_b64decode", "unhexlify",
                          "fromhex", "decompress", "a2b_base64"})
_SINKS = frozenset({"exec", "eval", "compile", "__import__", "builtins.exec", "builtins.eval", "builtins.compile",
                    "builtins.__import__", "types.FunctionType", "marshal.loads"})


def _is_decode_call(node: ast.Call, aliases: dict[str, str]) -> bool:
    name = call_name(node, aliases) or ""
    if name in _DECODE_FULL or name.rsplit(".", 1)[-1] in _DECODE_LAST:
        return True
    f = node.func
    if isinstance(f, ast.Attribute) and f.attr == "join" and node.args:
        return any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "chr"
                   for n in ast.walk(node.args[0]))
    return False


def _is_reverse(node: ast.AST) -> bool:
    if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice):
        st = node.slice.step
        return isinstance(st, ast.UnaryOp) and isinstance(st.op, ast.USub) and isinstance(st.operand, ast.Constant) \
            and st.operand.value == 1
    return False


def _ops(node: ast.AST, aliases: dict[str, str], var_ops: dict[str, int]) -> int:
    n = 0
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call) and _is_decode_call(sub, aliases):
            n += 1
        elif _is_reverse(sub):
            n += 1
        elif isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load):
            n += var_ops.get(sub.id, 0)
    return n


def _is_builtins(node: ast.AST, aliases: dict[str, str]) -> bool:
    return isinstance(node, ast.Name) and node.id == "__builtins__" or dotted_name(node, aliases) == "builtins"


def _sink_name(call: ast.Call, aliases: dict[str, str]) -> str | None:
    name = call_name(call, aliases)
    if name in _SINKS:
        return name
    f = call.func
    if isinstance(f, ast.Call) and call_name(f, aliases) == "getattr" and f.args and _is_builtins(f.args[0], aliases):
        return "getattr(builtins, ...)"
    return None


def _obf001(ctx: FileContext, tree: ast.Module, aliases: dict[str, str]) -> Iterator[Finding]:
    assigns = [(t.id, node.value) for node in ast.walk(tree) if isinstance(node, (ast.Assign, ast.AnnAssign))
               and node.value is not None
               for t in (node.targets if isinstance(node, ast.Assign) else [node.target]) if isinstance(t, ast.Name)]
    var_ops: dict[str, int] = {}
    for _ in range(2):  # two passes propagate through one level of intermediate variables
        nxt: dict[str, int] = {}
        for name, value in assigns:
            k = min(_ops(value, aliases, var_ops), 4)
            if k:
                nxt[name] = max(nxt.get(name, 0), k)
        var_ops = nxt
    seen: set[int] = set()
    for call in iter_calls(tree):
        sink = _sink_name(call, aliases)
        if sink is None or not call.args or call.lineno in seen:
            continue
        k = sum(_ops(a, aliases, var_ops) for a in call.args)
        if sink == "marshal.loads":
            k += 1
        if k == 0 or (sink == "marshal.loads" and k < 2):
            continue
        seen.add(call.lineno)
        yield Finding.from_rule(OBF001, ctx, call.lineno, segment(ctx, call), severity=C if k >= 2 else H,
                                description=f"{sink}() runs data produced by {k} decoding step(s).")
        if len(seen) >= 3:
            return


# =====================================================================================
# OBF009 - dynamic resolution (Python part) / OBF008 homoglyphs (Python part)
# =====================================================================================
def _obf009_py(ctx: FileContext, tree: ast.Module, aliases: dict[str, str]) -> Iterator[Finding]:
    n = 0
    for call in iter_calls(tree):
        name = call_name(call, aliases)
        if not call.args:
            continue
        a0 = call.args[0]
        conf: Confidence | None = None
        what = ""
        if name == "getattr" and len(call.args) >= 2 and _is_builtins(a0, aliases) \
                and not isinstance(call.args[1], ast.Constant):
            conf, what = CM, "getattr(builtins, <computed>)"
        elif name in ("__import__", "builtins.__import__") and not isinstance(a0, ast.Constant):
            folded = const_str(a0) is not None or _ops(a0, aliases, {}) > 0
            conf, what = (CM if folded else CL), "__import__(<computed>)"
        elif name == "importlib.import_module" and not isinstance(a0, ast.Constant) and \
                (const_str(a0) is not None or _ops(a0, aliases, {}) > 0):
            conf, what = CM, "importlib.import_module(<decoded>)"
        if conf is None:
            continue
        yield Finding.from_rule(OBF009, ctx, call.lineno, segment(ctx, call), confidence=conf,
                                description=f"{what}: the real target is hidden until run time.")
        n += 1
        if n >= 3:
            return


_CONFUSABLE_GREEK = frozenset("ΑΒΕΖΗΙΚΜΝΟΡΤΥΧοιρνυκα")


def _mixed_script(name: str) -> bool:
    if name.isascii():
        return False
    latin = other = False
    for ch in name:
        if not ch.isalpha():
            continue
        if ch.isascii():
            latin = True
            continue
        try:
            script = unicodedata.name(ch).split(" ", 1)[0]
        except ValueError:
            continue
        if script == "LATIN":
            latin = True
        elif script == "CYRILLIC" or (script == "GREEK" and ch in _CONFUSABLE_GREEK):
            other = True
    return latin and other


def _obf008_py(ctx: FileContext, tree: ast.Module) -> Iterator[Finding]:
    for node in ast.walk(tree):
        names: list[str] = []
        imports = False
        if isinstance(node, ast.Name):
            names = [node.id]
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names = [node.name]
        elif isinstance(node, ast.arg):
            names = [node.arg]
        elif isinstance(node, ast.Attribute):
            names = [node.attr]
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            imports = True
            names = [a.name for a in node.names] + ([node.module] if isinstance(node, ast.ImportFrom) and
                                                     node.module else [])
        for nm in names:
            if (imports and not nm.isascii()) or _mixed_script(nm):
                line = getattr(node, "lineno", 1)
                yield Finding.from_rule(OBF008, ctx, line, ctx.line_text(line),
                                        description=f"Identifier {nm!r} uses look-alike non-Latin letters"
                                                    + (" in an import." if imports else "."))
                return


_JS_STRIP = re.compile(r"'[^'\n]*'|\"[^\"\n]*\"|`[^`\n]*`|//[^\n]*")
_WORD = re.compile(r"[^\W\d]\w*")


def _obf008_js(ctx: FileContext) -> Iterator[Finding]:
    for i, line in enumerate(ctx.lines[:50000], 1):
        if line.isascii():
            continue
        for w in _WORD.findall(_JS_STRIP.sub(" ", line)):
            if _mixed_script(w):
                yield Finding.from_rule(OBF008, ctx, i, line,
                                        description=f"Identifier {w!r} uses look-alike non-Latin letters.")
                return


# =====================================================================================
# OBF002 / OBF003 / OBF009 (JS)
# =====================================================================================
_JS_SINK = re.compile(r"(?<![\w$.])(?:eval|Function|setTimeout|setInterval)\s*\(|(?<![\w$])execSync\s*\("
                      r"|\bvm\.run\w*\s*\(")
_JS_DECODE = re.compile(r"\batob\s*\(|Buffer\.from\([^)]{0,200}?,\s*['\"](?:base64|hex)['\"]|String\.fromCharCode"
                        r"|\bunescape\s*\(|(?:\\x[0-9a-fA-F]{2}){4,}")


def _obf002(ctx: FileContext) -> Iterator[Finding]:
    low = ctx.lower
    if not any(k in low for k in ("atob", "buffer.from", "fromcharcode", "unescape", "\\x")):
        return
    text = ctx.text[:MULTILINE_CAP]
    n = 0
    for m in _JS_SINK.finditer(text):
        window = text[m.end(): m.end() + 400].split(";", 1)[0]
        d = _JS_DECODE.search(window)
        if not d:
            continue
        yield Finding.from_rule(OBF002, ctx, ctx.line_of(m.start()), line_snippet(text, m.start(), m.end() + d.end()),
                                description=f"{m.group(0).rstrip('( ')}() runs decoded data ({d.group(0)[:20]}...).")
        n += 1
        if n >= 3:
            return


_PACKER = re.compile(r"eval\(function\(p,a,c,k,e,[dr]\)")
_HEXNAME = re.compile(r"\b_0x[a-f0-9]{4,6}\b", re.I)
_JSFUCK = re.compile(r"[\[\]()!+]{200,}")


def _obf003(ctx: FileContext) -> Iterator[Finding]:
    low = ctx.lower
    text = ctx.text[:MULTILINE_CAP]
    if "p,a,c,k,e," in low:
        m = _PACKER.search(text)
        if m:
            yield Finding.from_rule(OBF003, ctx, ctx.line_of(m.start()), line_snippet(text, m.start(), m.end()),
                                    extra_tags=(T.EXEC_DYNAMIC,), description="Dean Edwards p,a,c,k,e,d packer.")
            return
    if low.count("_0x") >= 20:
        hits = _HEXNAME.findall(text)
        if len(hits) >= 20:
            first = _HEXNAME.search(text)
            assert first is not None
            yield Finding.from_rule(OBF003, ctx, ctx.line_of(first.start()),
                                    line_snippet(text, first.start(), first.end()),
                                    description=f"obfuscator.io style _0x names ({len(hits)} occurrences).")
            return
    if "[][" in text or "![]" in text:
        m = _JSFUCK.search(text)
        if m:
            yield Finding.from_rule(OBF003, ctx, ctx.line_of(m.start()), text[m.start(): m.start() + 80],
                                    description="JSFuck-encoded JavaScript.")
            return
    for marker, label in (("ﾟωﾟﾉ", "aaencode"), ("ﾟдﾟ", "aaencode"), ("$=~[];", "jjencode"), ("$={___:++$", "jjencode")):
        pos = low.find(marker.lower())
        if pos >= 0:
            yield Finding.from_rule(OBF003, ctx, ctx.line_of(pos), text[pos: pos + 80],
                                    description=f"{label}-encoded JavaScript.")
            return


_JS_DYN = re.compile(r"\brequire\(\s*(?:['\"][^'\"\n]*['\"]\s*\+|[\w$]+\s*\[|atob\(|Buffer\.from\(|String\.fromCharCode)"
                     r"|\b(?:global|globalThis)\[[^\]\n]{1,80}\]\s*\(")


def _obf009_js(ctx: FileContext) -> Iterator[Finding]:
    low = ctx.lower
    if "require(" not in low and "global" not in low:
        return
    text = ctx.text[:MULTILINE_CAP]
    for m in _JS_DYN.finditer(text):
        yield Finding.from_rule(OBF009, ctx, ctx.line_of(m.start()), line_snippet(text, m.start(), m.end()),
                                description="Module/function looked up by a computed name.")
        return


# =====================================================================================
# OBF004 - PowerShell
# =====================================================================================
_PS_ENC = re.compile(r"(?i)(?<![\w-])-e(?:c|n[a-z]{0,12})?[ \t]+[\"']?(?P<b64>[A-Za-z0-9+/]{20,}={0,2})")
_PS_FROMB64 = re.compile(r"(?i)frombase64string")
_PS_IEX = re.compile(r"(?i)\biex\b|invoke-expression")
_PS_CHARJOIN = re.compile(r"(?i)\[char\[\]\][^\n]{0,200}-join")
_PS_HIDDEN = re.compile(r"(?i)(?<![\w-])-w(?:indowstyle)?[ \t]+h(?:idden)?\b")
_PS_BYPASS = re.compile(r"(?i)(?<![\w-])-(?:ep|exec|executionpolicy)[ \t]+bypass\b|(?<![\w-])-nop(?:rofile)?\b")


def _decode_ps(b64: str) -> str | None:
    try:
        raw = base64.b64decode(b64 + "=" * (-len(b64) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) < 4 or len(raw) % 2:
        return None
    try:
        s = raw.decode("utf-16-le")
    except UnicodeDecodeError:
        return None
    return s if s.isprintable() or printable_ratio(s.encode("utf-8", "replace")) > 0.9 else None


def _obf004(ctx: FileContext) -> Iterator[Finding]:
    low = ctx.lower
    ps_file = ctx.language in ("powershell", "batch")
    if not (ps_file or "powershell" in low or "pwsh" in low):
        return
    lines = ctx.lines[:50000]
    clean = [ln.replace("`", "").replace("^", "") for ln in lines]
    done: set[str] = set()
    for i, ln in enumerate(clean):
        lo = ln.lower()
        if "enc" not in done and "-e" in lo and (ps_file or "powershell" in lo or "pwsh" in lo):
            m = _PS_ENC.search(ln)
            if m:
                done.add("enc")
                decoded = _decode_ps(m.group("b64"))
                desc = "PowerShell runs a base64 -EncodedCommand"
                desc += f" that decodes to: {sanitize_snippet(decoded, 100)}" if decoded else "."
                yield Finding.from_rule(OBF004, ctx, i + 1, lines[i], confidence=CH if decoded else CM,
                                        description=desc)
        if "combo" not in done and (_PS_FROMB64.search(ln) or _PS_CHARJOIN.search(ln)):
            window = clean[max(0, i - 3): i + 4]
            if any(_PS_IEX.search(w) for w in window):
                done.add("combo")
                b64 = bool(_PS_FROMB64.search(ln))
                yield Finding.from_rule(OBF004, ctx, i + 1, lines[i], confidence=CH if b64 else CM,
                                        description="Decoded string is passed to Invoke-Expression.")
        if "launch" not in done and _PS_HIDDEN.search(ln) and _PS_BYPASS.search(ln):
            done.add("launch")
            yield Finding.from_rule(OBF004, ctx, i + 1, lines[i], confidence=CM,
                                    description="Hidden-window PowerShell launched with execution-policy bypass.")
        if len(done) == 3:
            return


# =====================================================================================
# OBF005 - large encoded blob (decoded in memory and rescanned)
# =====================================================================================
_B64_BLOB = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{200,}={0,2}")
_XESC_BLOB = re.compile(r"(?:\\x[0-9a-fA-F]{2}){100,}")
_HEXONLY = re.compile(r"^[0-9a-fA-F]+$")
_DECOMP_CAP = 5 * 1024 * 1024
_SCRIPT_HINT = re.compile(r"\bimport\b|\bexec\(|\beval\(|\bfunction\b|\brequire\(|powershell|<\?php|\bsubprocess\b"
                          r"|\bos\.system\b|\bcurl\b|\bwget\b|invoke-|\bchild_process\b")
_MEDIA_MAGIC = (b"\x89PNG", b"GIF8", b"\xff\xd8\xff", b"RIFF", b"wOFF", b"wOF2", b"OTTO", b"\x00\x01\x00\x00",
                b"%PDF", b"\x00\x00\x01\x00", b"ID3", b"OggS", b"fLaC", b"<svg", b"BM")
_rescan_rules: tuple[Rule, ...] | None = None


def _get_rescan_rules() -> tuple[Rule, ...]:
    global _rescan_rules
    if _rescan_rules is None:
        from . import exfil
        rules: list[Rule] = list(exfil.CredentialTheftDetector.rules) + list(exfil.ExfilDetector.rules)
        try:  # another coder's module; optional
            from . import malware  # type: ignore[attr-defined]
            for det in getattr(malware, "DETECTORS", ()):
                rules.extend(getattr(det, "rules", ()))
        except Exception:  # noqa: BLE001 - a broken sibling module must not break this detector
            pass
        _rescan_rules = tuple(rules)
    return _rescan_rules


def _decompress(data: bytes) -> bytes | None:
    try:
        if data[:2] == b"\x1f\x8b":
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        elif data[:1] == b"\x78" and data[1:2] in (b"\x01", b"\x5e", b"\x9c", b"\xda"):
            d = zlib.decompressobj()
        elif data[:3] == b"BZh":
            return bz2.BZ2Decompressor().decompress(data, max_length=_DECOMP_CAP)
        elif data[:6] == b"\xfd7zXZ\x00":
            return lzma.LZMADecompressor().decompress(data, max_length=_DECOMP_CAP)
        else:
            return None
        return d.decompress(data, _DECOMP_CAP)
    except (zlib.error, OSError, EOFError, lzma.LZMAError, ValueError):
        return None


def _classify(data: bytes, ctx: FileContext, depth: int = 0) -> tuple[str, set[str], bool]:
    """-> (kind, nested tags, dangerous). kind is a short human label."""
    if depth > 3 or not data:
        return "data", set(), False
    if data[:2] == b"MZ":
        return "Windows executable", {T.BINARY_EXEC}, True
    if data[:4] == b"\x7fELF":
        return "ELF executable", {T.BINARY_EXEC}, True
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "Mach-O executable", {T.BINARY_EXEC}, True
    if data[:4] == b"PK\x03\x04":
        return "zip archive", set(), True
    if len(data) >= 16 and data[2:4] == b"\r\n" and data[:2] != b"\r\n":
        return "compiled Python (.pyc)", {T.EXEC_DYNAMIC}, True
    if data.startswith(_MEDIA_MAGIC):
        return "media", set(), False
    inner = _decompress(data)
    if inner is not None:
        kind, tags, bad = _classify(inner, ctx, depth + 1)
        return f"compressed {kind}", tags, bad
    if printable_ratio(data[:4096]) < 0.85:
        return "binary data", set(), False
    text = data[:_DECOMP_CAP].decode("utf-8", "replace")
    nested: set[str] = set()
    sub = FileContext.from_text(ctx.rel_path, text)
    for f in run_rules(_get_rescan_rules(), sub):
        nested.update(t for t in f.tags if t not in (T.NO_DAMPEN, T.BLOCK_TRIGGER))
    for m in list(_B64_BLOB.finditer(text))[:3]:
        try:
            raw = base64.b64decode(m.group(0) + "=" * (-len(m.group(0)) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        k, t, bad = _classify(raw, ctx, depth + 1)
        nested |= t
        if bad:
            nested.add(T.OBFUSCATED)
    script = text.startswith("#!") or bool(_SCRIPT_HINT.search(text[:20000].lower()))
    if nested:
        return "text with threat indicators", nested, True
    return ("script" if script else "text"), set(), script


def _blob_bytes(token: str, kind: str) -> bytes | None:
    try:
        if kind == "hex":
            return binascii.unhexlify(token[: len(token) // 2 * 2])
        if kind == "xesc":
            return bytes(int(token[i + 2: i + 4], 16) for i in range(0, len(token), 4))
        return base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None


def _obf005(ctx: FileContext) -> Iterator[Finding]:
    if ctx.language not in CODE_LANGS or not any(len(ln) >= 200 for ln in ctx.lines[:50000]):
        return
    text = ctx.text[:MULTILINE_CAP]
    cands: list[tuple[int, str, str]] = []
    for m in _B64_BLOB.finditer(text):
        tok = m.group(0)
        pre = text[max(0, m.start() - 60): m.start()].lower()
        if "data:" in pre and "base64," in pre:
            continue  # inline media data: URI
        if _HEXONLY.match(tok):
            if len(tok) >= 400:
                cands.append((m.start(), tok, "hex"))
        elif shannon_entropy(tok[:4096]) >= 4.2:
            cands.append((m.start(), tok, "b64"))
    if "\\x" in text:
        cands.extend((m.start(), m.group(0), "xesc") for m in _XESC_BLOB.finditer(text))
    n = 0
    for start, tok, kind in sorted(cands)[:10]:
        data = _blob_bytes(tok, kind)
        if not data:
            continue
        label, nested, bad = _classify(data, ctx)
        sev, conf = (H, CH if nested else CM) if bad else ((L, CM) if label == "media" else (M, CM))
        yield Finding.from_rule(OBF005, ctx, ctx.line_of(start), tok[:60] + "...", severity=sev, confidence=conf,
                                extra_tags=tuple(sorted(nested)),
                                description=f"{len(tok)}-char {kind} blob decodes to {label}.")
        n += 1
        if n >= 3:
            return


# =====================================================================================
# OBF006 / OBF007 / OBF010 / OBF011
# =====================================================================================
_WS_RUN = re.compile(r"(?<![ \t])[ \t]{150,}(?=\S)")
_STRONG_CODE = re.compile(r"(?:import|from|exec|eval|__import__|require|subprocess|os\.system|powershell|curl|wget|"
                          r"iex|invoke-expression|child_process|system)\b", re.I)
_WEAK_CODE = re.compile(r"[;:]\s*\S")
_LONGLINE_EXT = frozenset({".py", ".pyw", ".sh", ".bash", ".ps1", ".psm1", ".bat", ".cmd"})
_JS_EXT = frozenset({".js", ".mjs", ".cjs"})
_WS_LANGS = CODE_LANGS - {"html"}


def _obf006(ctx: FileContext) -> Iterator[Finding]:
    if ctx.language not in _WS_LANGS:
        return
    lines = ctx.lines[:50000]
    if "               " in ctx.text[:MULTILINE_CAP]:
        for i, ln in enumerate(lines):
            if len(ln) < 150:
                continue
            for m in _WS_RUN.finditer(ln):
                rest = ln[m.end():]
                if _STRONG_CODE.match(rest) or (m.start() > 0 and _WEAK_CODE.match(rest)):
                    yield Finding.from_rule(OBF006, ctx, i + 1, ln.strip(),
                                            description=f"{m.end() - m.start()} spaces push code off-screen.")
                    return
    long_ok = ctx.ext in _LONGLINE_EXT
    if ctx.ext in _JS_EXT and not ctx.is_vendored and ".min." not in ctx.basename and len(lines) >= 5:
        lens = sorted(len(x) for x in lines)
        long_ok = lens[len(lens) // 2] < 120  # mostly normal lines: a single huge line stands out
    if not long_ok:
        return
    for i, ln in enumerate(lines):
        if len(ln) > 1000:
            data_only = ln.count("(") + ln.count(";") < 3
            yield Finding.from_rule(OBF006, ctx, i + 1, ln[:120], severity=M if data_only else H,
                                    confidence=CL if data_only else CH,
                                    description=f"{len(ln)}-character line in a script"
                                                + (" (looks like data)." if data_only else "."))
            return


_LONG_LIT = re.compile(r"['\"]([^'\"\s]{100,})['\"]")
_ENT_LANGS = CODE_LANGS - {"html"}
_REGEXISH = re.compile(r"[\\[\](){}|?*^$]")


def _obf007(ctx: FileContext, skip_lines: set[int]) -> Iterator[Finding]:
    if ctx.language not in _ENT_LANGS:
        return
    head = ctx.text[:65536]
    if len(ctx.text) >= 1024 and shannon_entropy(head) > 5.5:
        yield Finding.from_rule(OBF007, ctx, 1, ctx.line_text(1)[:120],
                                description=f"File entropy {shannon_entropy(head):.2f} bits/char (normal code < 5.2).")
        return
    for m in _LONG_LIT.finditer(ctx.text[:MULTILINE_CAP]):
        s = m.group(1)
        if s.lower().startswith(("http", "data:", "file:")) or _REGEXISH.search(s):
            continue  # URLs and regex sources are not encoded payloads
        line = ctx.line_of(m.start())
        if line in skip_lines:
            continue
        e = shannon_entropy(s[:4096])
        if e > 4.5:
            yield Finding.from_rule(OBF007, ctx, line, s[:60] + "...",
                                    description=f"{len(s)}-char string literal with entropy {e:.2f}.")
            return


OBF010_PAT = re.compile(r"__pyarmor__|pyarmor_runtime|\bPyObfuscator\b|\bHyperion\b|exec\(\s*\(\s*lambda"
                        r"|lambda[^:\n]{0,30}:\s*\(?\s*lambda[^:\n]{0,30}:\s*\(?\s*lambda")


def _obf010(ctx: FileContext) -> Iterator[Finding]:
    low = ctx.lower
    if not any(k in low for k in ("pyarmor", "pyobfuscator", "hyperion", "lambda")):
        return
    m = OBF010_PAT.search(ctx.text[:MULTILINE_CAP])
    if m:
        yield Finding.from_rule(OBF010, ctx, ctx.line_of(m.start()), line_snippet(ctx.text, m.start(), m.end()),
                                description=f"Packed/protected Python ({m.group(0)[:30]}).")


_CODING = re.compile(r"^[ \t\f]*#.*?coding[:=][ \t]*([-\w.]+)")
_OK_CODECS = frozenset({"utf-8", "utf-8-sig", "ascii", "latin-1", "iso8859-1"})


def _obf011(ctx: FileContext) -> Iterator[Finding]:
    if ctx.encoding == "utf-16" and ctx.language in CODE_LANGS:
        yield Finding.from_rule(OBF011, ctx, 1, ctx.line_text(1)[:120],
                                description="Source file is stored as UTF-16, which many tools and diffs skip.")
        return
    if ctx.language != "python":
        return
    for i, ln in enumerate(ctx.lines[:2], 1):
        m = _CODING.match(ln)
        if not m:
            continue
        try:
            name = codecs.lookup(m.group(1)).name
        except LookupError:
            name = None
        if name not in _OK_CODECS:
            yield Finding.from_rule(OBF011, ctx, i, ln,
                                    description=f"PEP 263 declares source encoding {m.group(1)!r}.")
        return


# =====================================================================================
class ObfuscationDetector(Detector):
    id = "obfuscation"
    name = "Obfuscation"
    category = _CAT
    checks = CHECKS

    def scan_file(self, ctx: FileContext) -> Iterable[Finding]:
        out: list[Finding] = []
        lang = ctx.language
        if lang == "python":
            low = ctx.lower
            need_ast = (any(k in low for k in ("exec", "eval", "compile", "__import__", "functiontype", "marshal",
                                               "getattr", "import_module"))
                        or not ctx.text.isascii())
            tree = parse(ctx) if need_ast else None
            if tree is not None:
                aliases = import_aliases(tree)
                out.extend(_obf001(ctx, tree, aliases))
                out.extend(_obf009_py(ctx, tree, aliases))
                if not ctx.text.isascii():
                    out.extend(_obf008_py(ctx, tree))
            out.extend(_obf010(ctx))
        elif lang in JS_LANGS:
            out.extend(_obf002(ctx))
            out.extend(_obf003(ctx))
            out.extend(_obf009_js(ctx))
            if not ctx.text.isascii():
                out.extend(_obf008_js(ctx))
        out.extend(_obf004(ctx))
        blobs = list(_obf005(ctx))
        out.extend(blobs)
        out.extend(_obf006(ctx))
        out.extend(_obf007(ctx, {f.line for f in blobs if f.line}))
        out.extend(_obf011(ctx))
        return [self._post(f, ctx) for f in out]

    @staticmethod
    def _post(f: Finding, ctx: FileContext) -> Finding:
        rl = ctx.rel_lower
        packed = ctx.is_vendored or ".min." in ctx.basename.lower() or rl.startswith("dist/") or "/dist/" in rl
        if packed and f.rule_id not in ("OBF001", "OBF002", "OBF004"):
            f = f.replace(severity=drop_severity(f.severity))
        return adjust_for_location(f, ctx)


DETECTORS = (ObfuscationDetector,)
