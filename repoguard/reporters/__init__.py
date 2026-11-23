"""Output formats: terminal, json, sarif, markdown."""

from __future__ import annotations

from ..models import Report

FORMATS = ("terminal", "json", "sarif", "markdown")


def render(report: Report, fmt: str = "terminal", *, color: bool = False, verbose: bool = False) -> str:
    if fmt == "json":
        from .json_out import render as r

        return r(report)
    if fmt == "sarif":
        from .sarif import render as r

        return r(report)
    if fmt == "markdown":
        from .markdown import render as r

        return r(report)
    from .terminal import render as r

    return r(report, color=color, verbose=verbose)
