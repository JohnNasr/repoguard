"""Regressions for issues found in the security review."""

from __future__ import annotations

import sys
import time
from pathlib import Path

from repoguard import engine, procutil
from repoguard.models import ScanOptions, Verdict
from repoguard.textutil import sanitize_snippet

_CFG = '[core]\n\tfsmonitor = "calc.exe"\n'


def _scan(root: Path):  # type: ignore[no-untyped-def]
    return engine.scan(str(root), ScanOptions(offline=True))


def test_gitfile_redirect_to_hostile_config_is_flagged(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    (root / ".cache").mkdir(parents=True)
    (root / ".git").write_text("gitdir: .cache\n")
    (root / ".cache" / "config").write_text(_CFG)
    (root / "main.py").write_text("print(1)\n")
    rep = _scan(root)
    assert "FSX008" in {f.rule_id for f in rep.result.findings}
    assert rep.verdict.rank >= Verdict.DANGEROUS.rank


def test_gitfile_pointing_outside_project_is_flagged(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    root.mkdir()
    (tmp_path / "elsewhere").mkdir()
    (root / ".git").write_text(f"gitdir: {tmp_path / 'elsewhere'}\n")
    (root / "main.py").write_text("print(1)\n")
    rep = _scan(root)
    assert any(f.rule_id == "FSX008" and f.path == ".git" for f in rep.result.findings)


def test_jwt_pattern_is_linear_on_adversarial_input(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    root.mkdir()
    (root / "blob.txt").write_text("eyJ" * 300_000)  # ~900 KB; took minutes with the old pattern
    start = time.monotonic()
    _scan(root)
    assert time.monotonic() - start < 20


def test_snippets_never_print_live_tokens() -> None:
    gh = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    out = sanitize_snippet(f'curl -H "Authorization: Bearer {gh}" https://api.example.invalid')
    assert gh not in out and "ghp_" in out
    hook = "https://discord" + ".com/api/web" + "hooks/123456789012345678/" + "Zq9" * 20
    assert "Zq9" * 20 not in sanitize_snippet(hook)


def test_run_caps_stdout_and_kills_process() -> None:
    code = "import sys\nwhile True: sys.stdout.write('x' * 65536)"
    start = time.monotonic()
    proc = procutil.run([sys.executable, "-c", code], timeout=30, max_stdout=1_000_000)
    assert len(proc.stdout) == 1_000_000
    assert time.monotonic() - start < 25


def test_run_timeout_kills_hanging_process() -> None:
    import subprocess

    import pytest

    start = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        procutil.run([sys.executable, "-c", "import time; time.sleep(60)"], timeout=2)
    assert time.monotonic() - start < 20


def test_agent_prompt_single_quotes_and_validates_target() -> None:
    text = (Path(__file__).resolve().parents[2] / "agent" / "repoguard.md").read_text(encoding="utf-8")
    assert "scan '<target>'" in text and 'scan "<target>"' not in text
    assert "Validate the target first" in text
