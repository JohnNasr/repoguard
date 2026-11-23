"""BIN tests. All binary fixtures are built in memory: headers only, no runnable code."""

from __future__ import annotations

import io
import struct
import zipfile
import zlib

from repoguard import tags as T
from repoguard.detectors.binaries import BinariesDetector, exec_kind
from repoguard.models import Severity
from tests.conftest import rule_ids, run_detector, run_repo_detector

D = BinariesDetector


def _by(findings, rid):
    return [f for f in findings if f.rule_id == rid]


def _pe() -> bytes:
    hdr = bytearray(512)
    hdr[0:2] = b"MZ"
    hdr[0x3C:0x40] = struct.pack("<I", 0x80)
    hdr[0x80:0x84] = b"PE\0\0"
    return bytes(hdr)


def _elf() -> bytes:
    return b"\x7fELF\x02\x01\x01" + b"\0" * 249


def _chunk(kind: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)


def _png() -> bytes:
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", zlib.compress(b"\0\0")) + _chunk(b"IEND", b"")


def _zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for n, data in entries.items():
            z.writestr(n, data)
    return buf.getvalue()


def test_exec_kind_magic():
    assert exec_kind(_pe()) and exec_kind(_elf())
    assert exec_kind(b"\xca\xfe\xba\xbe\0\0\0\x37", ".class") is None
    assert exec_kind(_png()) is None


# ---- BIN001 -------------------------------------------------------------------------------------------
def test_committed_executable(make_ctx):
    f = _by(run_detector(D, make_ctx(_pe(), "tools/helper.bin")), "BIN001")
    assert f and f[0].severity >= Severity.MEDIUM and T.BINARY_EXEC in f[0].tags


def test_executable_in_test_fixture_is_low(make_ctx):
    f = _by(run_detector(D, make_ctx(_elf(), "tests/fixtures/sample")), "BIN001")
    assert f and f[0].severity == Severity.LOW


# ---- BIN002 / BIN003 ----------------------------------------------------------------------------------
def test_native_module_without_sources(make_repo):
    f = _by(run_repo_detector(D, make_repo({"lib/addon.so": _elf(), "index.js": "module.exports = 1\n"})), "BIN002")
    assert len(f) == 1 and f[0].severity == Severity.MEDIUM and T.BINARY_EXEC in f[0].tags


def test_native_module_with_build_sources_is_low(make_repo):
    repo = make_repo({"build/addon.node": _elf(), "binding.gyp": "{}\n", "src/addon.cc": "int x;\n"})
    f = _by(run_repo_detector(D, repo), "BIN002")
    assert len(f) == 1 and f[0].severity == Severity.LOW


def test_orphan_pyc(make_repo):
    pyc = b"\xf3\r\r\n" + b"\0" * 60
    f = run_repo_detector(D, make_repo({"pkg/__pycache__/core.cpython-313.pyc": pyc, "pkg/__init__.py": ""}))
    assert "BIN003" in rule_ids(f)
    g = run_repo_detector(D, make_repo({"pkg/__pycache__/core.cpython-313.pyc": pyc, "pkg/core.py": "x = 1\n"}))
    assert "BIN003" not in rule_ids(g)


# ---- BIN004 -------------------------------------------------------------------------------------------
def test_jar_and_gradle_wrapper(make_ctx):
    jar = _zip({"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n", "a/B.class": b"\xca\xfe\xba\xbe\0\0"})
    f = _by(run_detector(D, make_ctx(jar, "libs/tool.jar")), "BIN004")
    assert f and f[0].severity > Severity.INFO
    g = _by(run_detector(D, make_ctx(jar, "gradle/wrapper/gradle-wrapper.jar")), "BIN004")
    assert g and g[0].severity == Severity.INFO


# ---- BIN005 -------------------------------------------------------------------------------------------
def test_archive_with_executable_and_traversal(make_ctx):
    data = _zip({"setup/a.exe": _pe(), "../../evil.txt": b"x", "readme.txt": b"hi"})
    f = _by(run_detector(D, make_ctx(data, "dist/bundle.zip")), "BIN005")
    assert any(x.severity >= Severity.HIGH and T.BINARY_EXEC in x.tags for x in f)
    assert any("evil" in x.description or "travers" in x.description.lower() for x in f)


def test_plain_archive_not_escalated(make_ctx):
    # Catalog: any committed archive is inventoried at MEDIUM; benign contents must not raise it.
    data = _zip({"docs/a.txt": b"hello\0", "docs/b.md": b"# b\n"})
    f = run_detector(D, make_ctx(data, "dist/docs.zip"))
    assert rule_ids(f) == {"BIN005"}
    assert f[0].severity == Severity.MEDIUM and T.BINARY_EXEC not in f[0].tags


# ---- BIN006 -------------------------------------------------------------------------------------------
def test_extension_mismatch(make_ctx):
    f = _by(run_detector(D, make_ctx(_elf(), "assets/logo.png")), "BIN006")
    assert f and T.BINARY_EXEC in f[0].tags


def test_png_with_correct_magic_clean(make_ctx):
    assert not run_detector(D, make_ctx(_png(), "assets/logo.png"))


# ---- BIN007 -------------------------------------------------------------------------------------------
def test_double_extension_and_rtlo(make_ctx):
    f = _by(run_detector(D, make_ctx(_pe(), "invoice.pdf.exe")), "BIN007")
    assert f and f[0].severity >= Severity.HIGH
    g = _by(run_detector(D, make_ctx("x\n", "report‮txt.js")), "BIN007")
    assert g and g[0].severity == Severity.CRITICAL


def test_normal_dotted_names_clean(make_ctx):
    for name in ("jquery.min.js", "app.config.json", "archive.tar.gz", "v1.2.3.txt"):
        assert "BIN007" not in rule_ids(run_detector(D, make_ctx("x\n", name)))


# ---- BIN008 -------------------------------------------------------------------------------------------
def test_shortcut_launcher(make_ctx):
    lnk = b"L\0\0\0\x01\x14\x02\0" + b"\0" * 68
    f = _by(run_detector(D, make_ctx(lnk, "docs/Setup.lnk")), "BIN008")
    assert f and f[0].severity == Severity.HIGH and T.BINARY_EXEC in f[0].tags


def test_batch_script_is_low(make_ctx):
    f = _by(run_detector(D, make_ctx("@echo off\necho build\n", "scripts/build.bat")), "BIN008")
    assert f and f[0].severity == Severity.LOW


# ---- BIN009 -------------------------------------------------------------------------------------------
def test_appended_data_after_png(make_ctx):
    tail = bytes((i * 37 + 11) % 251 + 1 for i in range(2048))
    f = _by(run_detector(D, make_ctx(_png() + tail, "img/photo.png")), "BIN009")
    assert f
    g = _by(run_detector(D, make_ctx(_png() + _elf() + tail, "img/photo2.png")), "BIN009")
    assert g and g[0].severity == Severity.HIGH


def test_png_zero_padding_clean(make_ctx):
    assert not run_detector(D, make_ctx(_png() + b"\0" * 4096, "img/padded.png"))
