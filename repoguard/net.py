"""Network access for optional online checks (OSV.dev, GitHub via `gh`). Offline-aware."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from . import __version__, procutil


class NetDisabled(RuntimeError):
    """Raised when a network call is attempted in --offline mode."""


class NetError(RuntimeError):
    pass


class NetClient:
    def __init__(self, offline: bool = False, timeout: float = 15.0) -> None:
        self.offline = offline
        self.timeout = timeout
        self.used = False

    def _guard(self) -> None:
        if self.offline:
            raise NetDisabled("network disabled (--offline)")
        self.used = True

    def post_json(self, url: str, payload: dict[str, Any], timeout: float | None = None) -> Any:
        self._guard()
        if not url.startswith("https://"):
            raise NetError("only https URLs are allowed")
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json", "User-Agent": f"repoguard/{__version__}"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as resp:  # noqa: S310
                return json.loads(resp.read(20_000_000).decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            raise NetError(f"POST {url} failed: {exc}") from exc

    def get_json(self, url: str, timeout: float | None = None) -> Any:
        self._guard()
        if not url.startswith("https://"):
            raise NetError("only https URLs are allowed")
        req = urllib.request.Request(url, headers={"User-Agent": f"repoguard/{__version__}"})
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as resp:  # noqa: S310
                return json.loads(resp.read(20_000_000).decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise NetError(f"GET {url} failed: {exc}") from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            raise NetError(f"GET {url} failed: {exc}") from exc

    def gh_api(self, path: str, accept: str | None = None) -> Any:
        """Call `gh api <path>` (uses the user's gh login if present). Returns parsed JSON or None on 404."""
        self._guard()
        argv = ["gh", "api", path]
        if accept:
            argv += ["-H", f"Accept: {accept}"]
        try:
            proc = procutil.run(argv, timeout=self.timeout + 15, env={"GH_PROMPT_DISABLED": "1", "NO_COLOR": "1"})
        except (procutil.ToolMissing, OSError) as exc:
            raise NetError(str(exc)) from exc
        except Exception as exc:  # TimeoutExpired
            raise NetError(f"gh api timed out: {exc}") from exc
        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", "replace")
            if "404" in err or "Not Found" in err:
                return None
            raise NetError(f"gh api {path} failed: {err.strip()[:200]}")
        try:
            return json.loads(proc.stdout.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise NetError(f"gh api {path}: bad JSON") from exc
