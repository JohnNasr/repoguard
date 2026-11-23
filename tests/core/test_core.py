"""Core engine tests: URL validation, walker, correlation, scoring, suppression, engine, CLI."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from repoguard import engine, fetch, registry, scoring, suppress
from repoguard import tags as T
from repoguard.correlate import correlate
from repoguard.detector import Detector, RuleInfo
from repoguard.models import Category, Confidence, Finding, ScanOptions, Severity, Verdict
from repoguard.walker import walk


def F(rule: str, sev: Severity, conf: Confidence = Confidence.HIGH, cat: Category = Category.MALWARE,
      path: str = "a.py", tags: tuple[str, ...] = (), ctx: str | None = None, line: int = 1) -> Finding:
    return Finding(rule, rule, sev, conf, cat, path, line, f"snip {rule} {path}", "d", "r", tuple(sorted(tags)),
                   (), ctx)


# ---------------------------------------------------------------- fetch
@pytest.mark.parametrize("good,expected", [
    ("octo/hello", "https://github.com/octo/hello.git"),
    ("https://github.com/octo/hello", "https://github.com/octo/hello.git"),
    ("https://github.com/octo/hello/tree/main/src", "https://github.com/octo/hello.git"),
    ("https://gitlab.example.invalid/a/b.git", "https://gitlab.example.invalid/a/b.git"),
])
def test_validate_url_accepts(good: str, expected: str) -> None:
    assert fetch.validate_url(good) == expected


@pytest.mark.parametrize("bad", [
    "-uhelp", "ext::sh -c touch% /tmp/x", "file:///etc", "ssh://git@github.com/a/b", "git@github.com:a/b.git",
    "http://github.com/a/b", "https://user:pw@github.com/a/b", "https://tok@github.com/a/b", "https://github.com/a",
    "https://github.com/a/b c", "fd::17", "https://github.com/a/b?x=1",
])
def test_validate_url_rejects(bad: str) -> None:
    with pytest.raises(fetch.FetchError):
        fetch.validate_url(bad)


def test_cleanup_refuses_non_repoguard_dirs(tmp_path: Path) -> None:
    victim = tmp_path / "important"
    victim.mkdir()
    assert fetch.cleanup(victim) is False and victim.exists()
    d = tempfile.mkdtemp(prefix="repoguard-")
    Path(d, "f.txt").write_text("x")
    os.chmod(Path(d, "f.txt"), 0o444)
    assert fetch.cleanup(d) is True and not Path(d).exists()


# ---------------------------------------------------------------- walker
def test_walker_skips_top_git_flags_nested_git_and_limits(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("[core]\n")
    (tmp_path / "sub" / ".git").mkdir(parents=True)
    (tmp_path / "a.py").write_text("print(1)\n")
    (tmp_path / "big.txt").write_bytes(b"x" * 5000)
    (tmp_path / "bin.dat").write_bytes(b"MZ\x90\x00" + b"\x00" * 100)
    res = walk(tmp_path, ScanOptions(max_file_size=1000))
    rels = {f.rel_path for f in res.files}
    assert ".git/config" not in rels and "a.py" in rels
    kinds = {(s.rel_path, s.kind) for s in res.special}
    assert ("sub/.git", "nested_git") in kinds and ("big.txt", "oversize") in kinds
    assert next(f for f in res.files if f.rel_path == "bin.dat").is_binary
    big = next(f for f in res.files if f.rel_path == "big.txt")
    assert big.truncated and len(big.raw) <= 65536


def test_walker_max_files(tmp_path: Path) -> None:
    for i in range(5):
        (tmp_path / f"f{i}.txt").write_text("x")
    res = walk(tmp_path, ScanOptions(max_files=3))
    assert len(res.files) == 3 and "max_files" in res.limits_hit


def test_walker_does_not_follow_symlinks(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("s")
    repo = tmp_path / "repo"
    repo.mkdir()
    try:
        os.symlink(outside, repo / "link", target_is_directory=True)
    except OSError:
        pytest.skip("symlinks not permitted on this machine")
    res = walk(repo, ScanOptions())
    assert not any("secret.txt" in f.rel_path for f in res.files)
    assert any(s.kind in ("symlink", "junction") for s in res.special)


# ---------------------------------------------------------------- correlation
def test_cor001_credential_plus_exfil_blocks() -> None:
    fs = [F("CRD003", Severity.HIGH, cat=Category.SECRETS, tags=(T.READS_CREDENTIALS,)),
          F("EXF001", Severity.HIGH, cat=Category.EXFILTRATION, tags=(T.EXFIL_CHANNEL, T.NETWORK_SEND))]
    cor = correlate(fs)
    c1 = [c for c in cor if c.rule_id == "COR001"]
    assert c1 and T.BLOCK_TRIGGER in c1[0].tags and c1[0].path == "a.py"
    assert set(c1[0].related) == {f.fingerprint for f in fs}


def test_weak_credential_plus_plain_http_is_only_cor018() -> None:
    fs = [F("CRD002", Severity.MEDIUM, Confidence.MEDIUM, Category.SECRETS, tags=(T.READS_CREDENTIALS,)),
          F("EXF010", Severity.INFO, cat=Category.EXFILTRATION, tags=(T.NETWORK_SEND,))]
    ids = {c.rule_id: c for c in correlate(fs)}
    assert "COR001" not in ids and ids["COR018"].severity == Severity.MEDIUM
    assert T.BLOCK_TRIGGER not in ids["COR018"].tags


def test_correlations_ignore_prose_files() -> None:
    fs = [F("CRD003", Severity.HIGH, cat=Category.SECRETS, path="README.md", tags=(T.READS_CREDENTIALS,)),
          F("EXF001", Severity.HIGH, cat=Category.EXFILTRATION, path="README.md", tags=(T.EXFIL_CHANNEL,))]
    assert not correlate(fs)


def test_correlation_requires_same_file() -> None:
    fs = [F("CRD003", Severity.HIGH, path="a.py", tags=(T.READS_CREDENTIALS,)),
          F("EXF001", Severity.HIGH, path="b.py", tags=(T.EXFIL_CHANNEL, T.NETWORK_SEND))]
    assert not [c for c in correlate(fs) if c.rule_id == "COR001"]


def test_cor009_needs_reference() -> None:
    binf = F("BIN001", Severity.MEDIUM, cat=Category.BINARY, path="tools/payload.exe", tags=(T.BINARY_EXEC,))
    hook = F("INS001", Severity.HIGH, cat=Category.EXEC_HOOK, path="package.json", tags=(T.INSTALL_HOOK,))
    assert not [c for c in correlate([binf, hook]) if c.rule_id == "COR009"]
    hook2 = hook.replace(snippet='"postinstall": "tools/payload.exe"')
    assert [c for c in correlate([binf, hook2]) if c.rule_id == "COR009"]


# ---------------------------------------------------------------- scoring
def test_scoring_bands() -> None:
    assert scoring.decide([])[1] == Verdict.SAFE
    one_high = [F("MAL003", Severity.HIGH)]
    s, v, _ = scoring.decide(one_high)
    assert s == 20 and v == Verdict.CAUTION
    s, v, _ = scoring.decide([F("MAL010", Severity.CRITICAL)])
    assert v == Verdict.DANGEROUS


def test_hygiene_is_capped() -> None:
    leaks = [F(f"SEC00{i}", Severity.HIGH, cat=Category.SECRETS, tags=(T.SECRET, T.HYGIENE)) for i in range(1, 9)]
    s, v, _ = scoring.decide(leaks)
    assert s <= 10 and v == Verdict.SAFE


def test_test_files_are_dampened_but_not_high_signal() -> None:
    low = scoring.points(F("SEC016", Severity.MEDIUM, cat=Category.SECRETS, ctx="test"))
    full = scoring.points(F("SEC016", Severity.MEDIUM, cat=Category.SECRETS))
    assert low < full
    assert scoring.points(F("MAL001", Severity.CRITICAL, ctx="test")) == scoring.points(F("MAL001", Severity.CRITICAL))


def test_block_trigger_overrides_and_test_context_only_dangerous() -> None:
    f = F("MAL005", Severity.LOW, tags=(T.BLOCK_TRIGGER,))
    assert scoring.decide([f])[1] == Verdict.BLOCK
    assert scoring.decide([f.replace(context_kind="test")])[1] == Verdict.DANGEROUS


def test_incomplete_floor() -> None:
    assert scoring.decide([], incomplete=True)[1] == Verdict.CAUTION


def test_category_cap_without_strong_finding() -> None:
    fs = [F(f"OBF00{i}", Severity.MEDIUM, Confidence.MEDIUM, Category.OBFUSCATION, path=f"{i}.py") for i in range(5, 10)]
    assert scoring.category_scores(fs)["obfuscation"] <= scoring.CATEGORY_CAP


# ---------------------------------------------------------------- suppression
def test_suppress_rules_globs_and_never_critical() -> None:
    entries = suppress.parse_ignore("SEC016 tests/*\n* docs/*\n# c\nMAL001\n")
    a = F("SEC016", Severity.MEDIUM, path="tests/x.py")
    b = F("SEC016", Severity.MEDIUM, path="src/x.py")
    c = F("OBF007", Severity.LOW, path="docs/y.md")
    d = F("MAL001", Severity.CRITICAL)
    kept, dropped = suppress.apply([a, b, c, d], entries, set())
    assert dropped == [a, c] and d in kept


def test_baseline_roundtrip(tmp_path: Path) -> None:
    f = F("SEC016", Severity.MEDIUM)
    p = tmp_path / "b.json"
    suppress.write_baseline(str(p), [f])
    assert suppress.load_baseline(str(p)) == {f.fingerprint}


# ---------------------------------------------------------------- engine with a fake detector
_FAKE = RuleInfo("ZZZ001", "fake hit", Severity.HIGH, Confidence.HIGH, Category.MALWARE, "d", "r",
                 frozenset({T.REVERSE_SHELL}))


class _FakeDet(Detector):
    id = "fake"
    name = "fake"
    category = Category.MALWARE
    checks = (_FAKE,)

    def scan_file(self, ctx):  # type: ignore[no-untyped-def]
        if "evil" in ctx.text:
            yield self.finding(_FAKE, ctx, 1, ctx.line_text(1))


class _CrashDet(Detector):
    id = "crash"
    name = "crash"
    category = Category.MALWARE

    def scan_file(self, ctx):  # type: ignore[no-untyped-def]
        raise ValueError("boom")


def test_engine_end_to_end(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(registry, "discover", lambda: (_FakeDet(), _CrashDet()))
    (tmp_path / "x.py").write_text("evil()\n")
    (tmp_path / ".repoguardignore").write_text("ZZZ001\n")
    (tmp_path / "y.py").write_text("# repoguard: ignore\n")
    rep = engine.scan(str(tmp_path), ScanOptions(offline=True))
    ids = [f.rule_id for f in rep.result.findings]
    assert "ZZZ001" in ids  # in-repo ignore file NOT honoured
    assert ids.count("META010") == 2
    assert "META002" in ids and rep.result.incomplete
    assert rep.verdict.rank >= Verdict.CAUTION.rank
    d = rep.to_dict()
    assert d["schema"] == "repoguard/1" and json.dumps(d)


def test_engine_user_ignore_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(registry, "discover", lambda: (_FakeDet(),))
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "x.py").write_text("evil()\n")
    ign = tmp_path / "my.ignore"
    ign.write_text("ZZZ001\n")
    rep = engine.scan(str(repo), ScanOptions(offline=True, ignore_files=(str(ign),)))
    assert not [f for f in rep.result.findings if f.rule_id == "ZZZ001"]
    assert [f for f in rep.result.suppressed if f.rule_id == "ZZZ001"]
    inside = repo / "inside.ignore"
    inside.write_text("ZZZ001\n")
    rep2 = engine.scan(str(repo), ScanOptions(offline=True, ignore_files=(str(inside),)))
    assert [f for f in rep2.result.findings if f.rule_id == "ZZZ001"]


def test_engine_bad_target() -> None:
    with pytest.raises(engine.ScanError):
        engine.scan("ext::sh -c id", ScanOptions(offline=True))


def test_cli_exit_codes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    from repoguard.cli import main

    monkeypatch.setattr(registry, "discover", lambda: (_FakeDet(),))
    (tmp_path / "x.py").write_text("ok\n")
    assert main(["scan", str(tmp_path), "--offline", "-q", "--format", "json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["verdict"] == "SAFE"
    assert main(["scan", "file:///etc", "-q"]) == 4
    assert main(["explain", "COR001"]) == 0
