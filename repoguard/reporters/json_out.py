"""Machine-readable JSON (schema repoguard/1). This is what the Claude Code agent consumes."""

from __future__ import annotations

import json

from ..models import Report


def render(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=True) + "\n"
