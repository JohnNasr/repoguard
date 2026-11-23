"""Shared test helpers. Payload strings in tests must be INERT: use example.invalid domains,
203.0.113.x IPs, and build secret-shaped tokens by string concatenation so the test files
themselves don't trip GitHub push protection or antivirus."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

import pytest

from repoguard.context import FileContext, RepoContext, SpecialEntry
from repoguard.detector import Detector
from repoguard.models import Finding, ScanOptions
from repoguard.net import NetClient, NetDisabled


def _ctx_for(path: Path, rel: str) -> FileContext:
    data = path.read_bytes()
    head = data[:65536]
    is_bin = b"\x00" in head[:8192] and not head.startswith((b"\xff\xfe", b"\xfe\xff"))
    return FileContext(path, rel, len(data), is_bin)


@pytest.fixture
def make_ctx(tmp_path: Path) -> Callable[..., FileContext]:
    """make_ctx(text_or_bytes, rel_path='x.py') -> FileContext backed by a real file."""

    def _make(content: str | bytes, rel_path: str = "x.py") -> FileContext:
        p = tmp_path / rel_path
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, str):
            p.write_bytes(content.encode("utf-8"))
        else:
            p.write_bytes(content)
        return _ctx_for(p, rel_path)

    return _make


class FakeNet(NetClient):
    """Returns canned responses keyed by URL / gh path; records calls."""

    def __init__(self, responses: dict[str, Any] | None = None, offline: bool = False) -> None:
        super().__init__(offline=offline)
        self.responses = responses or {}
        self.calls: list[tuple[str, Any]] = []

    def _lookup(self, key: str) -> Any:
        if self.offline:
            raise NetDisabled("offline")
        self.used = True
        for k, v in self.responses.items():
            if k == key or (k.endswith("*") and key.startswith(k[:-1])):
                return v(key) if callable(v) else v
        return None

    def post_json(self, url: str, payload: dict[str, Any], timeout: float | None = None) -> Any:
        self.calls.append((url, payload))
        return self._lookup(url)

    def get_json(self, url: str, timeout: float | None = None) -> Any:
        self.calls.append((url, None))
        return self._lookup(url)

    def gh_api(self, path: str, accept: str | None = None) -> Any:
        self.calls.append((path, accept))
        return self._lookup(path)


@pytest.fixture
def fake_net() -> Callable[..., FakeNet]:
    return lambda responses=None, offline=False: FakeNet(responses, offline)


@pytest.fixture
def make_repo(tmp_path: Path) -> Callable[..., RepoContext]:
    """make_repo({'rel/path': 'text' or b'bytes'}, special=[SpecialEntry...], net=None, target=...)"""

    def _make(
        files: dict[str, str | bytes],
        special: Iterable[SpecialEntry] = (),
        net: NetClient | None = None,
        target: str = "local",
        is_remote: bool = False,
    ) -> RepoContext:
        root = tmp_path / "repo"
        root.mkdir(exist_ok=True)
        ctxs = []
        for rel, content in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(content.encode("utf-8") if isinstance(content, str) else content)
            ctxs.append(_ctx_for(p, rel))
        return RepoContext(
            root=root,
            target=target,
            is_remote=is_remote,
            commit=None,
            files=tuple(ctxs),
            special=tuple(special),
            options=ScanOptions(offline=net is None),
            net=net or NetClient(offline=True),
        )

    return _make


def run_detector(det_cls: type[Detector], ctx: FileContext) -> list[Finding]:
    det = det_cls()
    if not det.applies_to(ctx):
        return []
    return list(det.scan_file(ctx))


def run_repo_detector(det_cls: type[Detector], repo: RepoContext) -> list[Finding]:
    """Runs scan_file over every file plus scan_repo, like the engine does."""
    det = det_cls()
    out: list[Finding] = []
    for ctx in repo.files:
        if det.applies_to(ctx):
            out.extend(det.scan_file(ctx))
    out.extend(det.scan_repo(repo))
    return out


def rule_ids(findings: Iterable[Finding]) -> set[str]:
    return {f.rule_id for f in findings}
