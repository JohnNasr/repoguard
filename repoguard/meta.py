"""Engine-level findings about the scan itself."""

from __future__ import annotations

from . import tags as T
from .detector import RuleInfo
from .models import Category, Confidence, Severity

_C = Category.META

META001 = RuleInfo("META001", "File scan timed out", Severity.MEDIUM, Confidence.LOW, _C,
                   "The per-file time budget ran out before every rule finished. Content in this file was not fully checked.",
                   "Review this file manually or re-run with --timeout-per-file set higher.", frozenset({T.EVASION}))
META002 = RuleInfo("META002", "Detector crashed", Severity.LOW, Confidence.LOW, _C,
                   "A detector raised an error on this input, so the scan is incomplete.",
                   "Report the error; review the file manually.")
META003 = RuleInfo("META003", "Network check skipped", Severity.INFO, Confidence.HIGH, _C,
                   "A check that needs the network was skipped (--offline or network failure).",
                   "Re-run without --offline for dependency vulnerability and reputation lookups.")
META004 = RuleInfo("META004", "Scan limits reached", Severity.MEDIUM, Confidence.MEDIUM, _C,
                   "The repository exceeded a size/file/depth limit, so part of it was not scanned. Attackers sometimes pad repos to exhaust scanners.",
                   "Re-run with higher limits (--max-total-bytes, --max-file-size) or review manually.", frozenset({T.EVASION}))
META005 = RuleInfo("META005", "Oversized file only partially scanned", Severity.LOW, Confidence.LOW, _C,
                   "Only the first 64 KiB of this file were inspected because it exceeds --max-file-size.",
                   "Check why such a large file is committed; review it if it is code.")
META010 = RuleInfo("META010", "Repository ships scanner suppression files", Severity.MEDIUM, Confidence.MEDIUM, _C,
                   "The repo contains its own repoguard ignore/suppression config. It was NOT honoured: a repo must not be able to silence the scanner.",
                   "Ignore it unless this is your own project (then use --trust-repo-ignore).", frozenset({T.EVASION}))
META011 = RuleInfo("META011", "Old git version", Severity.LOW, Confidence.HIGH, _C,
                   "Your git is older than 2.45.1, which had clone-time code execution bugs (CVE-2024-32002 family).",
                   "Update git before cloning untrusted repositories.")

ALL = (META001, META002, META003, META004, META005, META010, META011)
