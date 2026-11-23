"""DEP tests. No real network: FakeNet only. Inert data: example.invalid hosts, 203.0.113.x IPs."""

from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timedelta, timezone

from repoguard import registry
from repoguard import tags as T
from repoguard.detectors import dependencies as depmod
from repoguard.detectors.dependencies import (
    OSV_URL,
    DependencyDetector,
    DependencyOnlineDetector,
    typosquat_target,
)
from repoguard.models import ScanOptions, Severity
from tests.conftest import rule_ids, run_repo_detector


def _by(findings, rid):
    return [f for f in findings if f.rule_id == rid]


def _scan(repo):
    return run_repo_detector(DependencyDetector, repo) + run_repo_detector(DependencyOnlineDetector, repo)


def _pkg(deps, name="my-app", **extra):
    return json.dumps({"name": name, "dependencies": deps, **extra}, indent=2)


LOCK = json.dumps({"lockfileVersion": 3, "packages": {"": {}}})


# ---- registration --------------------------------------------------------------------------------
def test_detectors_validate():
    registry.validate([DependencyDetector, DependencyOnlineDetector])
    ids = {r.id for d in (DependencyDetector, DependencyOnlineDetector) for r in d.checks}
    assert ids == {f"DEP00{i}" for i in range(1, 10)}


# ---- DEP001 typosquats ---------------------------------------------------------------------------
def test_typosquat_true_positives():
    assert typosquat_target("pypi", "reqeusts")[0] == "requests"
    assert typosquat_target("npm", "lodahs")[0] == "lodash"
    assert typosquat_target("pypi", "python-requests")[0] == "requests"
    assert typosquat_target("npm", "crossenv")[0] == "cross-env"


def test_typosquat_false_positive_guards():
    assert typosquat_target("pypi", "requests") is None
    assert typosquat_target("npm", "react-dom") is None
    assert typosquat_target("npm", "@babel/somethingnew") is None  # same scope as popular packages
    assert typosquat_target("npm", "reac") is None  # too short
    assert typosquat_target("pypi", "boto4") is None  # differs only by trailing digit


def test_typosquat_in_manifests(make_repo):
    repo = make_repo({"requirements.txt": "reqeusts==2.0.0\nrequests==2.31.0\n",
                      "package.json": _pkg({"lodahs": "^4.0.0", "react-dom": "^18.2.0"}),
                      "package-lock.json": LOCK})
    f = _by(run_repo_detector(DependencyDetector, repo), "DEP001")
    assert {x.description.split("'")[1] for x in f} == {"reqeusts", "lodahs"}
    assert all(T.TYPOSQUAT in x.tags and T.DEPENDENCY_RISK in x.tags for x in f)
    assert len(f) == 2


def test_own_package_name_not_flagged(make_repo):
    repo = make_repo({"package.json": _pkg({"react": "^18.2.0"}, name="lodahs"), "package-lock.json": LOCK})
    assert not _by(run_repo_detector(DependencyDetector, repo), "DEP001")


# ---- DEP002 ---------------------------------------------------------------------------------------
def test_offline_malicious_list(make_repo):
    repo = make_repo({"package.json": _pkg({"flatmap-stream": "0.1.1"}), "package-lock.json": LOCK})
    f = _by(run_repo_detector(DependencyDetector, repo), "DEP002")
    assert len(f) == 1
    assert f[0].severity is Severity.CRITICAL and T.BLOCK_TRIGGER in f[0].tags


def test_osv_mal_gives_critical(make_repo, fake_net):
    net = fake_net({OSV_URL: {"results": [{"vulns": [{"id": "MAL-2025-0001"}]}]}})
    repo = make_repo({"requirements.txt": "somepkgxyz==1.0.0\n"}, net=net, target="https://github.com/a/b",
                     is_remote=True)
    f = _scan(repo)
    mal = _by(f, "DEP002")
    assert len(mal) == 1 and mal[0].severity is Severity.CRITICAL and T.BLOCK_TRIGGER in mal[0].tags
    osv_calls = [c for c in net.calls if c[0] == OSV_URL]
    assert len(osv_calls) == 1
    q = osv_calls[0][1]["queries"][0]
    assert q == {"package": {"name": "somepkgxyz", "ecosystem": "PyPI"}, "version": "1.0.0"}


def test_osv_vuln_gives_dep003_hygiene(make_repo, fake_net):
    net = fake_net({OSV_URL: {"results": [{"vulns": [{"id": "GHSA-aaaa-bbbb-cccc"}, {"id": "CVE-2020-0001"}]}]}})
    repo = make_repo({"requirements.txt": "somepkgxyz==1.0.0\n"}, net=net)
    f = _by(_scan(repo), "DEP003")
    assert len(f) == 1 and f[0].severity is Severity.LOW and T.HYGIENE in f[0].tags
    assert "BLOCK" not in " ".join(f[0].tags).upper()


def test_offline_mode_makes_no_network_calls(make_repo, fake_net):
    net = fake_net({OSV_URL: {"results": [{"vulns": [{"id": "MAL-1"}]}]}})
    repo = make_repo({"requirements.txt": "somepkgxyz==1.0.0\n", "package.json": _pkg({"leftish": "1.0.0"})},
                     net=net)
    repo = dataclasses.replace(repo, options=ScanOptions(offline=True))
    _scan(repo)
    assert net.calls == []


def test_net_disabled_is_silent(make_repo, fake_net):
    net = fake_net(offline=True)
    repo = make_repo({"requirements.txt": "somepkgxyz==1.0.0\n"}, net=net)
    assert _by(_scan(repo), "DEP002") == []


# ---- DEP004 / DEP005 ------------------------------------------------------------------------------
def test_non_registry_index_url(make_repo):
    repo = make_repo({"requirements.txt": "--index-url http://203.0.113.7/simple\nsix==1.16.0\n"})
    f = _by(run_repo_detector(DependencyDetector, repo), "DEP004")
    assert len(f) == 1 and f[0].severity is Severity.HIGH


def test_git_dependency_and_npmrc(make_repo):
    repo = make_repo({"package.json": _pkg({"thing": "git+https://example.invalid/thing.git"}),
                      "package-lock.json": LOCK, ".npmrc": "registry=https://npm.example.invalid/\n"})
    f = _by(run_repo_detector(DependencyDetector, repo), "DEP004")
    assert len(f) == 2
    assert all(x.severity is Severity.MEDIUM for x in f)


def test_default_registry_not_flagged(make_repo):
    repo = make_repo({"requirements.txt": "--index-url https://pypi.org/simple\nsix==1.16.0\n"})
    assert not _by(run_repo_detector(DependencyDetector, repo), "DEP004")


def test_extra_index_dependency_confusion(make_repo):
    repo = make_repo({"requirements.txt": "--extra-index-url https://pypi.example.invalid/simple\ncorp-lib==1.0\n"})
    f = run_repo_detector(DependencyDetector, repo)
    assert len(_by(f, "DEP005")) == 1 and len(_by(f, "DEP004")) == 1


def test_confusion_online_missing_on_pypi(make_repo, fake_net):
    net = fake_net({OSV_URL: {"results": [{}]}})  # pypi JSON lookups -> None (404)
    repo = make_repo({"requirements.txt": "--extra-index-url https://pypi.example.invalid/simple\ncorp-lib==1.0\n"},
                     net=net)
    f = _by(run_repo_detector(DependencyOnlineDetector, repo), "DEP005")
    assert len(f) == 1 and f[0].severity is Severity.HIGH
    assert any(c[0] == "https://pypi.org/pypi/corp-lib/json" for c in net.calls)


def test_goproxy_env(make_repo):
    repo = make_repo({"go.mod": "module example.invalid/m\n", "Makefile": "export GOSUMDB=off\nbuild:\n\tgo build\n"})
    assert _by(run_repo_detector(DependencyDetector, repo), "DEP004")


# ---- DEP006 ---------------------------------------------------------------------------------------
def test_lockfile_resolved_to_example_invalid(make_repo):
    lock = json.dumps({"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"left-pad": "^1.3.0"}},
        "node_modules/left-pad": {"version": "1.3.0", "resolved": "https://example.invalid/left-pad-1.3.0.tgz",
                                  "integrity": "sha512-AAAA"},
        "node_modules/ok": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/ok/-/ok-1.0.0.tgz",
                            "integrity": "sha512-BBBB"},
    }}, indent=2)
    repo = make_repo({"package.json": _pkg({"left-pad": "^1.3.0", "ok": "^1.0.0"}), "package-lock.json": lock})
    f = _by(run_repo_detector(DependencyDetector, repo), "DEP006")
    assert len(f) == 1 and f[0].severity is Severity.HIGH and "example.invalid" in f[0].description
    assert f[0].path == "package-lock.json" and f[0].line


def test_lockfile_missing_integrity(make_repo):
    lock = json.dumps({"lockfileVersion": 3, "packages": {
        "node_modules/ok": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/ok/-/ok-1.0.0.tgz"}}})
    repo = make_repo({"package.json": _pkg({"ok": "1.0.0"}), "package-lock.json": lock})
    f = _by(run_repo_detector(DependencyDetector, repo), "DEP006")
    assert len(f) == 1 and f[0].severity is Severity.MEDIUM


# ---- DEP007 / DEP008 ------------------------------------------------------------------------------
def test_loose_pins_and_missing_lockfile(make_repo):
    repo = make_repo({"package.json": _pkg({"express": "*", "react": "^18.2.0"})})
    f = _by(run_repo_detector(DependencyDetector, repo), "DEP007")
    assert len(f) == 2
    assert all(T.HYGIENE in x.tags and x.severity is Severity.LOW for x in f)


def test_pinned_with_lock_is_clean(make_repo):
    repo = make_repo({"package.json": _pkg({"express": "4.18.2"}), "package-lock.json": LOCK,
                      "requirements.txt": "six==1.16.0\n"})
    assert rule_ids(run_repo_detector(DependencyDetector, repo)) == set()


def test_committed_node_modules_with_install_script(make_repo):
    hook = json.dumps({"name": "evilpkg", "version": "1.0.0", "scripts": {"postinstall": "node setup.js"}}, indent=2)
    repo = make_repo({"package.json": _pkg({"express": "4.18.2"}), "package-lock.json": LOCK,
                      "node_modules/evilpkg/package.json": hook, "node_modules/evilpkg/setup.js": "// inert\n",
                      "node_modules/plain/package.json": '{"name": "plain"}'})
    f = _by(run_repo_detector(DependencyDetector, repo), "DEP008")
    sev = sorted(x.severity for x in f)
    assert sev == [Severity.MEDIUM, Severity.HIGH]
    tree = next(x for x in f if x.severity is Severity.MEDIUM)
    assert tree.path == "node_modules" and "2 package" in tree.description
    # packages inside node_modules are not treated as project manifests
    assert not _by(run_repo_detector(DependencyDetector, repo), "DEP007")


# ---- DEP009 ---------------------------------------------------------------------------------------
def test_new_package_on_registry(make_repo, fake_net):
    recent = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
    old = (datetime.now(timezone.utc) - timedelta(days=900)).isoformat()
    net = fake_net({
        OSV_URL: {"results": [{}, {}]},
        "https://registry.npmjs.org/brandnewthing": {"time": {"created": recent}},
        "https://registry.npmjs.org/oldthingzz": {"time": {"created": old}},
    })
    repo = make_repo({"package.json": _pkg({"brandnewthing": "1.0.0", "oldthingzz": "2.0.0", "react": "18.2.0"}),
                      "package-lock.json": LOCK}, net=net)
    f = _by(run_repo_detector(DependencyOnlineDetector, repo), "DEP009")
    assert len(f) == 1 and "brandnewthing" in f[0].description
    looked_up = [c[0] for c in net.calls if c[0].startswith("https://registry.npmjs.org/")]
    assert "https://registry.npmjs.org/react" not in looked_up  # popular packages are skipped


def test_registry_lookup_budget(make_repo, fake_net):
    deps = {f"zzpkg{i:03d}": "1.0.0" for i in range(60)}
    net = fake_net({OSV_URL: {"results": []}})
    repo = make_repo({"package.json": _pkg(deps), "package-lock.json": LOCK}, net=net)
    run_repo_detector(DependencyOnlineDetector, repo)
    regs = [c for c in net.calls if c[0].startswith("https://registry.npmjs.org/")]
    assert len(regs) == depmod.MAX_REGISTRY_LOOKUPS
    assert len([c for c in net.calls if c[0] == OSV_URL]) == 1
