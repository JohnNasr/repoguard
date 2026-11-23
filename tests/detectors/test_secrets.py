"""SEC tests. Payloads are inert: every secret-shaped token is assembled at runtime from a prefix plus
seeded pseudo-random characters, so this file contains no real-looking secrets."""

from __future__ import annotations

import base64
import json
import random
import string
import time

import pytest

from repoguard import registry
from repoguard import tags as T
from repoguard.detectors import secrets as S
from repoguard.models import Confidence, Severity
from repoguard.rules import lint_pattern
from tests.conftest import rule_ids, run_detector

D = S.SecretsDetector
ALNUM = string.ascii_letters + string.digits
_rng = random.Random(1337)


def rnd(n: int, alphabet: str = ALNUM) -> str:
    return "".join(_rng.choice(alphabet) for _ in range(n))


def _by(findings, rid):
    return [f for f in findings if f.rule_id == rid]


def _b64u(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def test_module_validates_and_patterns_lint():
    registry.validate([cls() for cls in S.DETECTORS])
    for spec in S.SPECS:
        assert lint_pattern(spec.regex.pattern) == [], spec.info.id
    for info in S.CHECKS:
        assert {T.SECRET, T.HYGIENE} <= set(info.tags)


# ---- true positives, one per rule ------------------------------------------------------------------
def _tp_cases():
    return [
        ("SEC001", f'KEY = "{"sk-ant-" + "api03-" + rnd(93, ALNUM + "-_")}"\n', "x.py"),
        ("SEC002", f'key = "{"sk-proj-" + rnd(20) + "T3Blbk" + "FJ" + rnd(20)}"\n', "x.py"),
        ("SEC003", f'g = "{"AI" + "za" + rnd(35)}"\n', "x.py"),
        ("SEC004", f'id = "{"AK" + "IA" + rnd(16, string.ascii_uppercase + "234567")}"\n', "x.py"),
        ("SEC005", f'conn = "DefaultEndpointsProtocol=https;AccountKey={rnd(86, ALNUM + "+/")}=="\n', "x.py"),
        ("SEC006", f'tok = "{"gh" + "p_" + rnd(36)}"\n', "x.py"),
        ("SEC007", f'slack = "{"xo" + "xb-" + rnd(12, string.digits) + "-" + rnd(24)}"\n', "x.py"),
        ("SEC008", f'stripe = "{"sk" + "_live_" + rnd(30)}"\n', "x.py"),
        ("SEC010", f'bot = "{rnd(9, string.digits)}:{"A" + "A" + rnd(33, ALNUM + "_-")}"\n', "x.py"),
        ("SEC013", f'DB = "postgres://app:{rnd(18)}@db1.example.invalid:5432/prod"\n', "x.py"),
        ("SEC015", f'HF = "{"h" + "f_" + rnd(34, string.ascii_letters)}"\n', "x.py"),
        ("SEC016", f'api_key = "{rnd(32)}"\n', "x.py"),
    ]


TP_CASES = _tp_cases()


@pytest.mark.parametrize("rid,text,path", TP_CASES, ids=[c[0] for c in TP_CASES])
def test_true_positives(make_ctx, rid, text, path):
    f = run_detector(D, make_ctx(text, path))
    assert rid in rule_ids(f), (rid, [x.rule_id for x in f])
    hit = _by(f, rid)[0]
    assert {T.SECRET, T.HYGIENE} <= set(hit.tags)


def test_secret_is_masked_in_snippet(make_ctx):
    tok = "gh" + "p_" + rnd(36)
    f = _by(run_detector(D, make_ctx(f'tok = "{tok}"\n')), "SEC006")
    assert f and tok not in f[0].snippet


def test_discord_token(make_ctx):
    # the first segment is base64 of a numeric user id ("1..." encodes to a leading M)
    uid = base64.urlsafe_b64encode(("1" + rnd(17, string.digits)).encode()).decode().rstrip("=")
    tok = uid + "." + rnd(6, ALNUM + "_-") + "." + rnd(30, ALNUM + "_-")
    f = run_detector(D, make_ctx(f'TOKEN = "{tok}"\n'))
    assert "SEC009" in rule_ids(f)


def test_private_key_needs_body(make_ctx):
    header = "-----BEGIN " + "RSA PRIVATE KEY" + "-----"
    body = "\n".join(rnd(64, ALNUM + "+/") for _ in range(4))
    assert "SEC011" in rule_ids(run_detector(D, make_ctx(header + "\n" + body + "\n", "key.txt")))
    # parser/detection code that only mentions the header is not a key
    code = f'if line.startswith("{header}"):\n    kind = "rsa"\n'
    assert "SEC011" not in rule_ids(run_detector(D, make_ctx(code)))


def test_jwt_live_and_sample(make_ctx):
    hdr = _b64u({"alg": "HS256", "typ": "JWT"})
    live = hdr + "." + _b64u({"sub": rnd(10), "exp": int(time.time()) + 86400}) + "." + rnd(43, ALNUM + "_-")
    f = _by(run_detector(D, make_ctx(f'T = "{live}"\n')), "SEC012")
    assert f and f[0].confidence == Confidence.MEDIUM
    sample = hdr + "." + _b64u({"sub": "1234567890", "name": "John Doe"}) + "." + rnd(43, ALNUM + "_-")
    assert "SEC012" not in rule_ids(run_detector(D, make_ctx(f'T = "{sample}"\n')))


def test_dotenv_committed(make_ctx):
    text = "DEBUG=true\nSERVICE_TOKEN=" + rnd(32) + "\n"
    assert "SEC014" in rule_ids(run_detector(D, make_ctx(text, ".env")))
    assert "SEC014" not in rule_ids(run_detector(D, make_ctx(text, ".env.example")))


def test_stripe_test_key_is_low(make_ctx):
    f = _by(run_detector(D, make_ctx(f'k = "{"sk" + "_test_" + rnd(30)}"\n')), "SEC008")
    assert f and f[0].severity == Severity.LOW


# ---- false-positive guards --------------------------------------------------------------------------
@pytest.mark.parametrize("text", [
    'api_key = os.environ["OPENAI_API_KEY"]\n',
    'api_key = "your-api-key-here-xxxxxxxx"\n',
    'password = "${DB_PASSWORD}"\n',
    'token_url = "https://auth.example.invalid/oauth/token"\n',
    'secret_path = "/etc/app/config/secret.yaml"\n',
    'auth_header_name = "X-Authorization-Header"\n',
    'DB = "postgres://postgres:postgres@localhost:5432/dev"\n',
    'KEY = "sk-ant-api03-' + "x" * 90 + '"\n',
])
def test_placeholders_and_benign_values(make_ctx, text):
    assert not run_detector(D, make_ctx(text))


def test_test_location_lowers_confidence(make_ctx):
    tok = "gh" + "p_" + rnd(36)
    f = _by(run_detector(D, make_ctx(f'tok = "{tok}"\n', "tests/test_x.py")), "SEC006")
    assert f and f[0].confidence == Confidence.MEDIUM


def test_doc_location_is_low_confidence(make_ctx):
    tok = "gh" + "p_" + rnd(36)
    f = _by(run_detector(D, make_ctx(f"Use `{tok}`\n", "docs/setup.md")), "SEC006")
    assert f and f[0].confidence == Confidence.LOW
