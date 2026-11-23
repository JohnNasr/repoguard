"""REP tests with canned `gh api` responses (FakeNet). Inert data: example.invalid hosts only."""

from __future__ import annotations

import dataclasses
from datetime import datetime, timedelta, timezone

from repoguard import registry
from repoguard import tags as T
from repoguard.detectors.reputation import ReadmeLureDetector, ReputationDetector, github_slug
from repoguard.models import ScanOptions, Severity
from tests.conftest import rule_ids, run_detector, run_repo_detector


def _by(findings, rid):
    return [f for f in findings if f.rule_id == rid]


def _ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _repo_json(owner="someone", name="tool", **kw):
    base = {"full_name": f"{owner}/{name}", "owner": {"login": owner, "type": "User"}, "fork": False,
            "created_at": _ago(1000), "stargazers_count": 10, "forks_count": 3, "open_issues_count": 1,
            "default_branch": "main", "description": "a tool"}
    base.update(kw)
    return base


def _old_user(login="someone"):
    return {"login": login, "created_at": _ago(3000), "followers": 50}


def _commit(sha, days):
    return {"sha": sha, "commit": {"committer": {"date": _ago(days)}, "author": {"date": _ago(days)}}}


def _remote(make_repo, net, files=None, target="https://github.com/someone/tool"):
    return make_repo(files or {"README.md": "# tool\n"}, net=net, target=target, is_remote=True)


# ---- registration / plumbing ----------------------------------------------------------------------
def test_detectors_validate():
    registry.validate([ReputationDetector, ReadmeLureDetector])
    assert ReadmeLureDetector.needs_network is False and ReputationDetector.needs_network is True


def test_github_slug():
    assert github_slug("https://github.com/Owner/repo.git") == ("Owner", "repo")
    assert github_slug("git@github.com:o/r") == ("o", "r")
    assert github_slug("https://gitlab.example.invalid/o/r") is None
    assert github_slug("https://github.com/o/r;rm -rf") is None


def test_not_remote_or_offline_makes_no_calls(make_repo, fake_net):
    net = fake_net({"repos/*": _repo_json()})
    local = make_repo({"README.md": "x"}, net=net, target="https://github.com/someone/tool", is_remote=False)
    assert run_repo_detector(ReputationDetector, local) == []
    off = dataclasses.replace(_remote(make_repo, net), options=ScanOptions(offline=True))
    assert run_repo_detector(ReputationDetector, off) == []
    non_gh = make_repo({"README.md": "x"}, net=net, target="https://example.invalid/a/b", is_remote=True)
    assert run_repo_detector(ReputationDetector, non_gh) == []
    assert net.calls == []


def test_net_disabled_is_silent(make_repo, fake_net):
    assert run_repo_detector(ReputationDetector, _remote(make_repo, fake_net(offline=True))) == []


def test_clean_repo_no_findings(make_repo, fake_net):
    net = fake_net({"repos/someone/tool": _repo_json(), "users/someone": _old_user(),
                    "repos/someone/tool/commits?per_page=30": [_commit("a" * 40, 2), _commit("b" * 40, 10)]})
    assert run_repo_detector(ReputationDetector, _remote(make_repo, net)) == []


# ---- REP001 ---------------------------------------------------------------------------------------
def test_rep001_star_inflation(make_repo, fake_net):
    net = fake_net({"repos/someone/tool": _repo_json(created_at=_ago(10), stargazers_count=3000, forks_count=5,
                                                     open_issues_count=0),
                    "users/someone": _old_user()})
    f = run_repo_detector(ReputationDetector, _remote(make_repo, net))
    assert rule_ids(f) == {"REP001"}


# ---- REP002 ---------------------------------------------------------------------------------------
def test_rep002_fork_touches_hooks(make_repo, fake_net):
    data = _repo_json(fork=True, parent={"full_name": "upstream/tool", "default_branch": "main"})
    net = fake_net({"repos/someone/tool": data, "users/someone": _old_user(),
                    "repos/upstream/tool/compare/main...someone:main": {"files": [
                        {"filename": "package.json", "status": "modified"},
                        {"filename": "src/util.js", "status": "modified"},
                        {"filename": "bin/helper.exe", "status": "added"},
                        {"filename": ".github/workflows/ci.yml", "status": "modified"}]}})
    f = _by(run_repo_detector(ReputationDetector, _remote(make_repo, net)), "REP002")
    by_snip = {x.snippet: x.severity for x in f}
    assert by_snip == {"package.json": Severity.HIGH, "bin/helper.exe": Severity.HIGH,
                       ".github/workflows/ci.yml": Severity.MEDIUM}


# ---- REP003 ---------------------------------------------------------------------------------------
def test_rep003_impersonation_with_exe_release(make_repo, fake_net):
    net = fake_net({"repos/fakeacct/vscode": _repo_json("fakeacct", "vscode", description="Official VS Code build"),
                    "users/fakeacct": {"created_at": _ago(20), "followers": 0},
                    "repos/fakeacct/vscode/releases?per_page=20": [{"assets": [{"name": "VSCodeSetup.exe"}]}]})
    repo = _remote(make_repo, net, target="https://github.com/fakeacct/vscode")
    f = run_repo_detector(ReputationDetector, repo)
    imp = _by(f, "REP003")
    assert len(imp) == 1 and T.PHISHING in imp[0].tags
    assert {"REP003", "REP004", "REP005"} <= rule_ids(f)
    assert _by(f, "REP004")[0].severity is Severity.MEDIUM  # raised because of executable releases


def test_rep003_same_name_without_signals_is_quiet(make_repo, fake_net):
    net = fake_net({"repos/someone/react": _repo_json("someone", "react"), "users/someone": _old_user()})
    f = run_repo_detector(ReputationDetector, _remote(make_repo, net, target="https://github.com/someone/react"))
    assert not _by(f, "REP003")


def test_release_built_by_ci_not_flagged(make_repo, fake_net):
    net = fake_net({"repos/someone/tool": _repo_json(), "users/someone": _old_user(),
                    "repos/someone/tool/releases?per_page=20": [{"assets": [{"name": "tool.exe"}]}]})
    files = {"README.md": "# tool\n", ".github/workflows/release.yml": "on: push\njobs:\n  release:\n    steps:\n"
                                                                       "      - uses: softprops/action-gh-release@v2\n"}
    assert not _by(run_repo_detector(ReputationDetector, _remote(make_repo, net, files)), "REP005")


# ---- REP004 ---------------------------------------------------------------------------------------
def test_rep004_new_account(make_repo, fake_net):
    net = fake_net({"repos/someone/tool": _repo_json(),
                    "users/someone": {"created_at": _ago(5), "followers": 0}})
    f = run_repo_detector(ReputationDetector, _remote(make_repo, net))
    assert rule_ids(f) == {"REP004"} and f[0].severity is Severity.LOW


def test_rep004_skipped_for_orgs(make_repo, fake_net):
    org = {**_repo_json(), "owner": {"login": "someone", "type": "Organization"}}
    net = fake_net({"repos/someone/tool": org,
                    "users/someone": {"created_at": _ago(5), "followers": 0}})
    assert not _by(run_repo_detector(ReputationDetector, _remote(make_repo, net)), "REP004")
    assert all(c[0] != "users/someone" for c in net.calls)


# ---- REP006 ---------------------------------------------------------------------------------------
def test_rep006_dormant_repo_hook_commit(make_repo, fake_net):
    net = fake_net({"repos/someone/tool": _repo_json(), "users/someone": _old_user(),
                    "repos/someone/tool/commits?per_page=30": [_commit("c" * 40, 1), _commit("d" * 40, 800)],
                    "repos/someone/tool/commits/" + "c" * 40: {"files": [{"filename": "setup.py"}]}})
    f = _by(run_repo_detector(ReputationDetector, _remote(make_repo, net)), "REP006")
    assert len(f) == 1 and f[0].severity is Severity.HIGH


def test_rep006_bulk_upload_by_new_account(make_repo, fake_net):
    net = fake_net({"repos/someone/tool": _repo_json(), "users/someone": {"created_at": _ago(3), "followers": 4},
                    "repos/someone/tool/commits?per_page=30": [_commit("e" * 40, 1)],
                    "repos/someone/tool/commits/" + "e" * 40: {"files": [{"filename": f"f{i}.py"} for i in range(80)],
                                                              "stats": {"additions": 9000}}})
    f = _by(run_repo_detector(ReputationDetector, _remote(make_repo, net)), "REP006")
    assert len(f) == 1 and f[0].severity is Severity.LOW


# ---- REP005 / REP007 offline (README) -------------------------------------------------------------
LURE_README = """# Super Tool Pro (cracked)

## Download
Get the latest build here: https://www.mediafire.com/file/abc123/SuperTool.zip
Archive password: st2025

Windows Defender may flag it. This is a false positive, please disable Windows Defender before running.
"""


def test_rep007_and_rep005_offline_readme(make_repo):
    repo = make_repo({"README.md": LURE_README})  # net=None -> offline
    f = run_repo_detector(ReadmeLureDetector, repo)
    lure = _by(f, "REP007")
    assert any(x.severity is Severity.HIGH and T.PHISHING in x.tags for x in lure)
    assert any("antivirus" in x.title.lower() for x in lure)
    pw = _by(f, "REP005")
    assert len(pw) == 1 and pw[0].line == 5


def test_shortener_needs_download_context(make_ctx):
    quiet = run_detector(ReadmeLureDetector, make_ctx("See the talk slides: https://bit.ly/abc123\n", "README.md"))
    assert quiet == []
    loud = run_detector(ReadmeLureDetector, make_ctx("Download the installer: https://bit.ly/abc123\n", "README.md"))
    assert rule_ids(loud) == {"REP007"} and T.PHISHING in loud[0].tags


def test_normal_readme_is_clean(make_ctx):
    text = ("# mylib\n\n## Install\n\n```\npip install mylib\n```\n\nConfigure the database:\n\n```yaml\n"
            "user: app\npassword: hunter22\n```\n\nDownload releases from https://github.com/o/r/releases\n"
            "Antivirus tools are not needed to use this library.\n")
    assert run_detector(ReadmeLureDetector, make_ctx(text, "README.md")) == []


def test_readme_detector_ignores_other_files(make_ctx):
    assert run_detector(ReadmeLureDetector, make_ctx(LURE_README, "src/notes.md")) == []
    assert run_detector(ReadmeLureDetector, make_ctx(LURE_README, "setup.py")) == []
