"""Parser tests for _depparse. Inert data: example.invalid hosts and 203.0.113.x IPs only."""

from __future__ import annotations

import json

from repoguard.context import FileContext
from repoguard.detectors import _depparse as dp


def _deps(parsed, eco=None):
    return {d.name: d for d in parsed.deps if eco is None or d.ecosystem == eco}


def _kinds(parsed):
    return {(s.kind, s.url) for s in parsed.sources}


def test_normalize():
    assert dp.normalize("pypi", "Foo_Bar.baz") == "foo-bar-baz"
    assert dp.normalize("npm", "@Scope/Pkg") == "@scope/pkg"


def test_package_json_sections_and_specs():
    text = json.dumps({
        "name": "my-app",
        "dependencies": {"react": "^18.2.0", "evil": "git+https://example.invalid/evil.git",
                         "tar": "https://203.0.113.5/pkg.tgz", "local": "file:../../outside",
                         "alias": "npm:lodash@^4"},
        "devDependencies": {"jest": "*", "gh": "someuser/somerepo"},
        "workspaces": ["packages/*"],
    }, indent=2)
    p = dp.parse_package_json("package.json", text)
    deps = _deps(p)
    assert ("npm", "my-app") in p.own_names
    assert deps["react"].kind == "registry" and deps["react"].version_spec == "^18.2.0"
    assert deps["evil"].kind == "git"
    assert deps["tar"].kind == "url" and "203.0.113.5" in deps["tar"].source_url
    assert deps["local"].kind == "path"
    assert deps["gh"].kind == "git"
    assert deps["jest"].section == "devDependencies"
    assert deps["react"].line == 4


def test_package_lock_v3_and_v1():
    v3 = json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "x"},
        "node_modules/left-pad": {"version": "1.3.0", "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                                  "integrity": "sha512-AAAA"},
        "node_modules/@s/p": {"version": "2.0.0", "resolved": "https://example.invalid/p.tgz"},
    }}, indent=2)
    locks = {e.name: e for e in dp.parse_package_lock("package-lock.json", v3).locks}
    assert locks["left-pad"].version == "1.3.0" and locks["left-pad"].integrity
    assert locks["@s/p"].resolved == "https://example.invalid/p.tgz"
    v1 = json.dumps({"lockfileVersion": 1, "dependencies": {"a": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
                                                                  "dependencies": {"b": {"version": "2.0.0"}}}}})
    names = {e.name for e in dp.parse_package_lock("package-lock.json", v1).locks}
    assert {"a", "b"} <= names


def test_yarn_lock_classic_and_berry():
    classic = ('# yarn lockfile v1\n\n"left-pad@^1.3.0":\n  version "1.3.0"\n'
               '  resolved "https://example.invalid/left-pad-1.3.0.tgz#abc"\n  integrity sha512-AAAA\n')
    e = dp.parse_yarn_lock("yarn.lock", classic).locks[0]
    assert (e.name, e.version) == ("left-pad", "1.3.0") and "example.invalid" in e.resolved
    berry = ('__metadata:\n  version: 6\n\n"@s/p@npm:^1.0.0":\n  version: 1.0.1\n  resolution: "@s/p@npm:1.0.1"\n'
             '  checksum: abc\n')
    e2 = dp.parse_yarn_lock("yarn.lock", berry).locks[0]
    assert (e2.name, e2.version) == ("@s/p", "1.0.1")


def test_pnpm_lock():
    text = ("lockfileVersion: '6.0'\n\npackages:\n\n  /left-pad@1.3.0:\n    resolution: {integrity: sha512-AAAA}\n"
            "    dev: false\n\n  /@s/p@2.0.0(react@18.2.0):\n    resolution: {tarball: https://example.invalid/p.tgz}\n")
    locks = {e.name: e for e in dp.parse_pnpm_lock("pnpm-lock.yaml", text).locks}
    assert locks["left-pad"].version == "1.3.0" and locks["left-pad"].integrity
    assert locks["@s/p"].resolved == "https://example.invalid/p.tgz"


def test_pep508():
    assert dp.parse_pep508("requests[socks]>=2.0; python_version>'3'")[:2] == ("requests", ">=2.0")
    name, _spec, kind, url = dp.parse_pep508("pkg @ git+https://example.invalid/pkg.git")
    assert (name, kind) == ("pkg", "git") and "example.invalid" in url
    assert dp.parse_pep508("https://example.invalid/x-1.0-py3-none-any.whl")[2] == "url"


def test_requirements_options_and_includes():
    text = ("--index-url https://example.invalid/simple\n--extra-index-url https://pypi.example.invalid/simple\n"
            "--trusted-host example.invalid\n-r other.txt\nrequests==2.31.0 \\\n    --hash=sha256:abc\n"
            "-e git+https://example.invalid/x.git#egg=xpkg\nflask\n")
    p = dp.parse_requirements("requirements.txt", text)
    deps = _deps(p)
    assert deps["requests"].version_spec == "==2.31.0"
    assert deps["xpkg"].kind == "git"
    assert deps["flask"].version_spec == ""
    kinds = {k for k, _u in _kinds(p)}
    assert {"index-url", "extra-index-url", "trusted-host"} <= kinds
    assert "other.txt" in p.includes


def test_pyproject_pep621_poetry_uv():
    text = """
[project]
name = "mine"
dependencies = ["httpx>=0.27", "attrs==23.1.0"]
[project.optional-dependencies]
dev = ["pytest"]
[build-system]
requires = ["setuptools>=61"]
[tool.poetry.dependencies]
python = "^3.11"
rich = "*"
[[tool.poetry.source]]
name = "corp"
url = "https://pypi.example.invalid/simple"
[tool.uv]
extra-index-url = ["https://uv.example.invalid/simple"]
"""
    p = dp.parse_pyproject("pyproject.toml", text)
    deps = _deps(p)
    assert {"httpx", "attrs", "pytest", "setuptools", "rich"} <= set(deps)
    assert "python" not in deps
    assert ("pypi", "mine") in p.own_names
    kinds = {k for k, _u in _kinds(p)}
    assert "poetry-source" in kinds and "extra-index-url" in kinds


def test_pipfile_and_setup_py():
    pip = ('[[source]]\nurl = "https://pypi.org/simple"\nname = "pypi"\n[[source]]\n'
           'url = "https://example.invalid/simple"\nname = "corp"\n[packages]\nrequests = "*"\n')
    p = dp.parse_pipfile("Pipfile", pip)
    assert "requests" in _deps(p)
    assert sum(1 for s in p.sources if s.kind == "pipfile-source") == 2
    setup = ("from setuptools import setup\nREQS = ['click>=8', 'pyyaml']\n"
             "setup(name='mypkg', install_requires=REQS, dependency_links=['https://example.invalid/dl'])\n")
    s = dp.parse_setup_py("setup.py", setup)
    assert {"click", "pyyaml"} <= set(_deps(s))
    assert ("pypi", "mypkg") in s.own_names
    assert any(x.kind == "dependency-link" for x in s.sources)


def test_pip_conf_npmrc_yarnrc():
    pc = dp.parse_pip_conf("pip.conf", "[global]\nextra-index-url = https://example.invalid/simple\n")
    assert ("extra-index-url", "https://example.invalid/simple") in _kinds(pc)
    rc = dp.parse_npmrc(".npmrc", "registry=http://203.0.113.9/\n@corp:registry=https://npm.example.invalid/\n"
                                  "strict-ssl=false\n")
    kinds = {k for k, _u in _kinds(rc)}
    assert {"registry", "scoped-registry", "strict-ssl-off"} <= kinds
    yrc = dp.parse_yarnrc(".yarnrc.yml", 'npmRegistryServer: "https://example.invalid"\n')
    assert any("example.invalid" in s.url for s in yrc.sources)


def test_cargo_go_gem_composer_nuget():
    cargo = dp.parse_cargo_toml("Cargo.toml", '[package]\nname = "me"\n[dependencies]\nserde = "1"\n'
                                              'x = { git = "https://example.invalid/x" }\n')
    assert _deps(cargo)["x"].kind == "git" and ("cargo", "me") in cargo.own_names
    clock = dp.parse_file("Cargo.lock", '[[package]]\nname = "serde"\nversion = "1.0.0"\n'
                                        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                                        'checksum = "abc"\n')
    assert clock.locks[0].name == "serde"
    gomod = dp.parse_go_mod("go.mod", "module example.invalid/me\n\nrequire (\n\tgithub.com/a/b v1.2.3\n)\n"
                                      "replace github.com/a/b => github.com/evil/b v1.2.4\n")
    gd = [d for d in gomod.deps if d.name == "github.com/a/b"]
    assert any(d.kind == "registry" for d in gd) and any(d.kind == "replace" for d in gd)
    gem = dp.parse_gemfile("Gemfile", "source 'https://example.invalid'\ngem 'rails', '7.0.0'\n"
                                      "gem 'x', git: 'https://example.invalid/x.git'\n")
    assert _deps(gem)["x"].kind == "git" and any(s.kind == "gem-source" for s in gem.sources)
    comp = dp.parse_composer_json("composer.json", json.dumps(
        {"require": {"monolog/monolog": "^3"}, "repositories": [{"type": "vcs", "url": "https://example.invalid/r"}]}))
    assert "monolog/monolog" in _deps(comp) and any(s.kind == "composer-repo" for s in comp.sources)
    nuget = dp.parse_nuget_config("nuget.config", '<configuration><packageSources>'
                                                  '<add key="corp" value="https://example.invalid/v3/index.json" />'
                                                  '</packageSources></configuration>')
    assert any("example.invalid" in s.url for s in nuget.sources)


def test_parser_for_and_garbage():
    assert dp.parser_for("requirements-dev.txt") is dp.parse_requirements
    assert dp.parser_for("src/main.py") is None
    ctx = FileContext.from_text("node_modules/x/package.json", '{"dependencies": {"reqeusts": "1"}}')
    assert dp.parse_repo((ctx,)).parsed.deps == ()  # committed trees are not parsed as manifests
    assert dp.parse_file("package.json", "{not json").deps == ()


def test_parse_repo_follows_includes_and_lockdirs():
    files = {"requirements.txt": "-r reqs/base.txt\n", "reqs/base.txt": "six==1.16.0\n",
             "web/package.json": '{"dependencies": {"react": "^18"}}', "web/package-lock.json": "{}"}
    ctxs = tuple(FileContext.from_text(k, v) for k, v in files.items())
    by = {c.rel_path: c for c in ctxs}
    rd = dp.parse_repo(ctxs, by.get)
    assert "six" in {d.name for d in rd.parsed.deps}
    assert "web" in rd.lockfile_dirs
