"""OBF tests. Payloads are inert: encoded blobs decode to harmless print/echo statements or random bytes,
and are produced at runtime (base64/utf-16 encoding in the test), never stored as opaque literals."""

from __future__ import annotations

import base64
import random
import string

import pytest

from repoguard import registry
from repoguard import tags as T
from repoguard.detectors import obfuscation as O
from repoguard.models import Confidence, Severity
from repoguard.rules import lint_pattern
from tests.conftest import rule_ids, run_detector

D = O.ObfuscationDetector
ALNUM = string.ascii_letters + string.digits
_rng = random.Random(777)
INERT_B64 = base64.b64encode(b"print('inert')").decode()


def rnd(n: int, alphabet: str = ALNUM) -> str:
    return "".join(_rng.choice(alphabet) for _ in range(n))


def _by(findings, rid):
    return [f for f in findings if f.rule_id == rid]


def _run(make_ctx, text, path="x.py"):
    return run_detector(D, make_ctx(text, path))


def test_module_validates_and_tags():
    registry.validate([cls() for cls in O.DETECTORS])
    for pat in (O._JS_SINK, O._JS_DECODE, O._PS_ENC, O._B64_BLOB, O._XESC_BLOB, O._WS_RUN, O.OBF010_PAT,
                O._JS_DYN, O._LONG_LIT, O._PACKER, O._JSFUCK):
        assert lint_pattern(pat.pattern) == [], pat.pattern
    for info in O.CHECKS:
        assert T.OBFUSCATED in info.tags
        assert (T.NO_DAMPEN in info.tags) == (info.id in ("OBF001", "OBF002", "OBF003", "OBF004"))


# ---- OBF001 -----------------------------------------------------------------------------------------
def test_obf001_single_and_chained(make_ctx):
    f = _by(_run(make_ctx, f'import base64\nexec(base64.b64decode("{INERT_B64}"))\n'), "OBF001")
    assert f and f[0].severity == Severity.HIGH and {T.DECODE, T.EXEC_DYNAMIC, T.NO_DAMPEN} <= set(f[0].tags)
    f = _by(_run(make_ctx, "import base64, zlib\nexec(zlib.decompress(base64.b64decode(P)))\n"), "OBF001")
    assert f and f[0].severity == Severity.CRITICAL


def test_obf001_through_variable_and_reverse(make_ctx):
    text = f'import base64 as b\ncode = b.b64decode("{INERT_B64}"[::-1])\nexec(code)\n'
    f = _by(_run(make_ctx, text), "OBF001")
    assert f and f[0].severity == Severity.CRITICAL


def test_obf001_not_dampened_in_tests(make_ctx):
    f = _by(_run(make_ctx, "import base64\nexec(base64.b64decode(P))\n", "tests/test_x.py"), "OBF001")
    assert f and f[0].confidence == Confidence.HIGH


@pytest.mark.parametrize("text", [
    'exec(open("helpers.py").read())\n',
    "import base64\ndata = base64.b64decode(blob)\nsave(data)\n",
    "model.eval()\nresult = compile_assets(x)\n",
])
def test_obf001_false_positives(make_ctx, text):
    assert "OBF001" not in rule_ids(_run(make_ctx, text))


# ---- OBF002 / OBF003 / OBF009 (JS) -----------------------------------------------------------------
def test_obf002_js_decode_exec(make_ctx):
    f = _by(_run(make_ctx, f'eval(atob("{INERT_B64}"));\n', "x.js"), "OBF002")
    assert f and f[0].severity == Severity.CRITICAL
    f = _by(_run(make_ctx, 'new Function(Buffer.from(p, "base64").toString())();\n', "x.js"), "OBF002")
    assert f


def test_obf002_false_positive(make_ctx):
    text = "setTimeout(() => render(), 100);\nconst s = atob(x);\nshow(s);\n"
    assert "OBF002" not in rule_ids(_run(make_ctx, text, "x.js"))


def test_obf003_packers(make_ctx):
    packed = "eval(function(p,a,c,k,e,d){e=function(c){return c};return p}('0 1',2,2,'a|b'.split('|'),0,{}))\n"
    f = _by(_run(make_ctx, packed, "x.js"), "OBF003")
    assert f and f[0].severity == Severity.HIGH and T.EXEC_DYNAMIC in f[0].tags
    hexnames = "".join(f"var _0x{_rng.randrange(0x1000, 0xffff):04x}=_0x1a2b[{i}];\n" for i in range(25))
    assert "OBF003" in rule_ids(_run(make_ctx, hexnames, "x.js"))
    jsfuck = "".join(_rng.choice("[]()!+") for _ in range(260))
    assert "OBF003" in rule_ids(_run(make_ctx, "x = " + jsfuck + ";\n", "x.js"))


def test_obf003_vendored_min_drops_severity(make_ctx):
    packed = "eval(function(p,a,c,k,e,d){return p}('',0,0,[],0,{}))\n"
    f = _by(_run(make_ctx, packed, "vendor/lib.min.js"), "OBF003")
    assert f and f[0].severity == Severity.MEDIUM
    f = _by(_run(make_ctx, f'eval(atob("{INERT_B64}"));\n', "vendor/lib.min.js"), "OBF002")
    assert f and f[0].severity == Severity.CRITICAL  # OBF001/002/004 are never dropped


def test_obf003_false_positive(make_ctx):
    assert "OBF003" not in rule_ids(_run(make_ctx, "const _0xff = 1;\nconst a = [1, 2];\n", "x.js"))


def test_obf009_dynamic_resolution(make_ctx):
    f = _by(_run(make_ctx, 'fn = getattr(__builtins__, "ex" + "ec")\n'), "OBF009")
    assert f and f[0].confidence == Confidence.MEDIUM
    f = _by(_run(make_ctx, "mod = __import__(name)\n"), "OBF009")
    assert f and f[0].confidence == Confidence.LOW
    assert "OBF009" in rule_ids(_run(make_ctx, 'const cp = require("child_" + "process");\n', "x.js"))


@pytest.mark.parametrize("text,path", [
    ("v = getattr(obj, name)\nm = importlib.import_module(f'plugins.{name}')\n", "x.py"),
    ('const fs = require("fs");\n', "x.js"),
])
def test_obf009_false_positives(make_ctx, text, path):
    assert "OBF009" not in rule_ids(_run(make_ctx, text, path))


# ---- OBF004 -----------------------------------------------------------------------------------------
def test_obf004_encoded_command(make_ctx):
    enc = base64.b64encode("Write-Output 'inert'".encode("utf-16-le")).decode()
    text = f"powershell -NoP -W Hidden -ExecutionPolicy Bypass -enc {enc}\n"
    f = _by(_run(make_ctx, text, "run.bat"), "OBF004")
    assert f and f[0].confidence == Confidence.HIGH and "inert" in f[0].description
    assert len(f) == 2  # encoded command + hidden bypass launcher


def test_obf004_decode_iex_combo(make_ctx):
    text = "$s = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p))\nIEX $s\n"
    assert "OBF004" in rule_ids(_run(make_ctx, text, "x.ps1"))


@pytest.mark.parametrize("text,path", [
    ("grep -e pattern file.txt\npython -m pip install -e .\n", "x.sh"),
    ("Write-Host 'hello'\nGet-ChildItem -Recurse\n", "x.ps1"),
])
def test_obf004_false_positives(make_ctx, text, path):
    assert "OBF004" not in rule_ids(_run(make_ctx, text, path))


# ---- OBF005 -----------------------------------------------------------------------------------------
def test_obf005_blob_decoding_to_script(make_ctx):
    script = "import os\n" + "".join(f"v_{rnd(6)} = '{rnd(12)}'\n" for _ in range(20)) + "print('inert')\n"
    blob = base64.b64encode(script.encode()).decode()
    f = _by(_run(make_ctx, f'PAYLOAD = "{blob}"\n'), "OBF005")
    assert f and f[0].severity == Severity.HIGH and "script" in f[0].description


def test_obf005_media_blob_is_low(make_ctx):
    png = b"\x89PNG\r\n\x1a\n" + bytes(_rng.randrange(256) for _ in range(300))
    f = _by(_run(make_ctx, f'ICON = "{base64.b64encode(png).decode()}"\n'), "OBF005")
    assert f and f[0].severity == Severity.LOW


def test_obf005_false_positives(make_ctx):
    png = b"\x89PNG\r\n\x1a\n" + bytes(_rng.randrange(256) for _ in range(300))
    uri = "data:image/png;base64," + base64.b64encode(png).decode()
    assert "OBF005" not in rule_ids(_run(make_ctx, f'ICON = "{uri}"\n'))
    assert "OBF005" not in rule_ids(_run(make_ctx, f'H = "{rnd(300, "0123456789abcdef")}"\n'))


# ---- OBF006 / OBF007 --------------------------------------------------------------------------------
def test_obf006_whitespace_hidden_code(make_ctx):
    text = 'print("hi")' + " " * 200 + ';import os;os.system("echo inert")\n'
    f = _by(_run(make_ctx, text), "OBF006")
    assert f and f[0].severity == Severity.HIGH


def test_obf006_long_script_line(make_ctx):
    assert "OBF006" in rule_ids(_run(make_ctx, "echo start; " * 120 + "\n", "x.sh"))


def test_obf006_false_positives(make_ctx):
    text = "x = 1" + " " * 200 + "# aligned comment\n"
    assert "OBF006" not in rule_ids(_run(make_ctx, text))
    minified = "!function(){" + "a();" * 400 + "}();\n"
    assert "OBF006" not in rule_ids(_run(make_ctx, minified, "dist/app.min.js"))


def test_obf007_high_entropy_literal(make_ctx):
    f = _by(_run(make_ctx, f'K = "{rnd(150, ALNUM + "+/")}"\n'), "OBF007")
    assert f and f[0].confidence == Confidence.LOW


def test_obf007_false_positives(make_ctx):
    text = f'H = "{rnd(128, "0123456789abcdef")}"\nU = "https://example.invalid/{rnd(120)}"\n'
    assert "OBF007" not in rule_ids(_run(make_ctx, text))


# ---- OBF008 -----------------------------------------------------------------------------------------
def test_obf008_homoglyph_identifier(make_ctx):
    text = "def pаy(amount):\n    return amount\n"  # Cyrillic a inside a Latin name
    assert "OBF008" in rule_ids(_run(make_ctx, text))
    js = "function sеnd(x) { return x; }\n"  # Cyrillic e
    assert "OBF008" in rule_ids(_run(make_ctx, js, "x.js"))


def test_obf008_false_positives(make_ctx):
    text = 'msg = "Привет world"\nпривет = 1\n'
    assert "OBF008" not in rule_ids(_run(make_ctx, text))


# ---- OBF010 / OBF011 --------------------------------------------------------------------------------
def test_obf010_pyarmor(make_ctx):
    assert "OBF010" in rule_ids(_run(make_ctx, "from pytransform import pyarmor_runtime\npyarmor_runtime()\n"))
    assert "OBF010" not in rule_ids(_run(make_ctx, "rows = sorted(rows, key=lambda r: r[0])\n"))


def test_obf011_unusual_encoding(make_ctx):
    assert "OBF011" in rule_ids(_run(make_ctx, "# -*- coding: rot13 -*-\nprint('inert')\n"))
    assert "OBF011" not in rule_ids(_run(make_ctx, "# -*- coding: utf-8 -*-\nprint('ok')\n"))


def test_obf011_utf16_source(make_ctx):
    from repoguard.context import FileContext
    raw = make_ctx("print('inert')\n".encode("utf-16"), "x.py")
    # conftest's NUL sniff marks UTF-16 as binary; the real walker treats a BOM-prefixed file as text
    ctx = FileContext(raw.path, raw.rel_path, raw.size, False)
    assert ctx.encoding == "utf-16"
    assert "OBF011" in rule_ids(run_detector(D, ctx))
