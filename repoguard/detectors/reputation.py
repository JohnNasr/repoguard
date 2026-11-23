"""REP001-REP007: repository reputation signals (fake stars, malicious forks, impersonation, throwaway
accounts, password-protected downloads, odd commit history, README download lures).

ReputationDetector uses the GitHub API (`gh api`) and only runs for remote github.com targets.
ReadmeLureDetector is offline and reads README / install docs.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from importlib import resources
from typing import Any

from .. import tags as T
from ..context import FileContext, RepoContext
from ..detector import Detector, RuleInfo
from ..models import Category, Confidence, Finding, Severity
from ..net import NetDisabled, NetError

_C = Category.REPUTATION

REP001 = RuleInfo("REP001", "Suspicious star growth", Severity.MEDIUM, Confidence.MEDIUM, _C,
                  "The repository is very young but has gained stars far faster than forks or issues. Bought or "
                  "bot stars are used to make malware repos look trustworthy.",
                  "Do not trust the star count. Check who starred it, the author's history and the code itself.")
REP002 = RuleInfo("REP002", "Fork changes sensitive files", Severity.HIGH, Confidence.MEDIUM, _C,
                  "This is a fork whose differences from the original touch install hooks, CI, AI-agent config or "
                  "add binaries. Malicious forks copy a popular project and add a payload there.",
                  "Prefer the original repository, or review exactly what the fork changed.")
REP003 = RuleInfo("REP003", "Possible impersonation of a popular project", Severity.HIGH, Confidence.MEDIUM, _C,
                  "The repository has the same name as a well-known project but a different owner, and shows "
                  "signs of a lure (new account, executable releases, crack/cheat wording or claims to be official).",
                  "Get the project from its official owner/website instead.")
REP004 = RuleInfo("REP004", "New account with no followers", Severity.LOW, Confidence.MEDIUM, _C,
                  "The owner account was created recently and has no followers. Malware campaigns use throwaway "
                  "accounts.", "Treat the code with extra suspicion and review it before running anything.")
REP005 = RuleInfo("REP005", "Password-protected or unverifiable download", Severity.MEDIUM, Confidence.MEDIUM, _C,
                  "The project distributes an archive with a password, or ships executable release assets that are "
                  "not built by any CI workflow. Passwords stop antivirus from scanning the archive; hand-uploaded "
                  "binaries cannot be tied to the source.",
                  "Do not run the download. Build from source or use a trusted distribution channel.")
REP006 = RuleInfo("REP006", "Suspicious commit history", Severity.LOW, Confidence.MEDIUM, _C,
                  "The history is a single bulk upload by a new account, or a long-dormant repository whose latest "
                  "commit only touches install hooks, CI or binaries (a hijacked-account pattern).",
                  "Review the most recent commit in full before using the project.")
REP007 = RuleInfo("REP007", "Download lure in README", Severity.HIGH, Confidence.MEDIUM, _C,
                  "The README points users to file-hosting or link-shortener downloads, or tells them to disable or "
                  "whitelist their antivirus. This is how fake 'tool' repos deliver stealers.",
                  "Do not download or run the file; never disable antivirus for a download.")

# ---------------------------------------------------------------------------- helpers

_GH_RE = re.compile(
    r"^(?:(?:https?|ssh|git)://(?:git@)?(?:www\.)?github\.com/|git@github\.com:|github\.com/)"
    r"([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/([A-Za-z0-9._-]{1,100}?)(?:\.git)?/?(?:[#?].*)?$",
    re.I,
)
EXEC_EXTS = (".exe", ".msi", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".dmg", ".pkg", ".apk", ".appimage",
             ".deb", ".rpm", ".jar", ".com", ".lnk", ".hta")
ARCHIVE_EXTS = (".rar", ".7z")
BINARY_EXTS = EXEC_EXTS + (".dll", ".so", ".dylib", ".bin", ".node", ".pyd", ".sys", ".elf", ".o", ".a")
LURE_WORDS = re.compile(r"(?i)\b(crack(?:ed)?|keygen|cheats?|aimbot|wallhack|spoofer|unlocked|bypass|activator|"
                        r"hwid|injector|free\s+v-?bucks|license\s+key\s+generator)\b")
RECENT_REPO_DAYS = 60
NEW_ACCOUNT_DAYS = 90


def github_slug(target: str) -> tuple[str, str] | None:
    m = _GH_RE.match((target or "").strip())
    if not m:
        return None
    owner, repo = m.group(1), m.group(2)
    if repo in (".", "..") or repo.startswith("."):
        return None
    return owner, repo


@lru_cache(maxsize=1)
def top_repos() -> dict[str, str]:
    try:
        text = (resources.files("repoguard") / "data" / "top_repos.txt").read_text(encoding="utf-8")
    except (FileNotFoundError, OSError, ModuleNotFoundError):
        return {}
    out: dict[str, str] = {}
    for ln in text.splitlines():
        parts = ln.split()
        if len(parts) == 2 and not ln.lstrip().startswith("#"):
            out.setdefault(parts[0].lower(), parts[1].lower())
    return out


def _parse_dt(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _d(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _l(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _sensitive_kind(path: str) -> str | None:
    if not isinstance(path, str) or not path:
        return None
    ctx = FileContext.from_text(path, "")
    if ctx.is_install_hook:
        return "install hook"
    if ctx.is_ai_config:
        return "AI-agent config"
    if ctx.is_ci:
        return "CI workflow"
    if path.lower().endswith(BINARY_EXTS):
        return "binary"
    return None


def _readme_text(repo: RepoContext) -> str:
    for ctx in repo.files:
        if "/" not in ctx.rel_path and ctx.basename.lower().startswith("readme") and not ctx.is_binary:
            return ctx.text or ""
    return ""


def _release_workflow(repo: RepoContext) -> bool:
    for ctx in repo.files:
        if ctx.is_ci and not ctx.is_binary:
            low = ctx.lower or ""
            if any(k in low for k in ("release", "upload-artifact", "goreleaser", "electron-builder", "pyinstaller",
                                      "cargo-dist", "softprops/action-gh-release", "gh release")):
                return True
    return False


class _Ctx:
    """Per-scan state: repo, accumulated findings, fetched API objects."""

    def __init__(self, repo: RepoContext, owner: str, name: str) -> None:
        self.repo, self.owner, self.name = repo, owner, name
        self.now = datetime.now(timezone.utc)
        self.out: list[Finding] = []

    def api(self, path: str) -> Any:
        try:
            return self.repo.net.gh_api(path)
        except NetError:
            return None

    def add(self, info: RuleInfo, snippet: str, description: str, **kw: Any) -> None:
        self.out.append(Finding.from_rule(info, None, None, snippet, path=kw.pop("path", ""),
                                          description=description, **kw))


# ---------------------------------------------------------------------------- online detector


class ReputationDetector(Detector):
    id = "reputation"
    name = "Repository reputation (GitHub)"
    category = _C
    checks = (REP001, REP002, REP003, REP004, REP006)
    needs_network = True

    def scan_file(self, ctx: FileContext) -> Iterable[Finding]:
        return ()

    def scan_repo(self, repo: RepoContext) -> Iterable[Finding]:
        if not repo.is_remote or repo.options.offline:
            return []
        slug = github_slug(repo.target)
        if slug is None:
            return []
        st = _Ctx(repo, *slug)
        try:
            self._scan(st)
        except NetDisabled:
            pass
        return st.out

    def _scan(self, st: _Ctx) -> None:
        data = _d(st.api(f"repos/{st.owner}/{st.name}"))
        if not data:
            return
        owner = _d(data.get("owner"))
        login = owner.get("login") if isinstance(owner.get("login"), str) else st.owner
        user = _d(st.api(f"users/{login}")) if owner.get("type", "User") == "User" else {}
        account_age = None
        created = _parse_dt(user.get("created_at"))
        if created is not None:
            account_age = (st.now - created).days
        new_account = account_age is not None and account_age < NEW_ACCOUNT_DAYS
        releases = [r for r in _l(st.api(f"repos/{st.owner}/{st.name}/releases?per_page=20")) if isinstance(r, dict)]
        assets = [a.get("name", "") for r in releases for a in _l(r.get("assets"))
                  if isinstance(a, dict) and isinstance(a.get("name"), str)]
        exec_assets = [a for a in assets if a.lower().endswith(EXEC_EXTS + ARCHIVE_EXTS)]
        zip_assets = [a for a in assets if a.lower().endswith(".zip")]

        self._stars(st, data)
        self._fork(st, data)
        self._impersonation(st, data, account_age, exec_assets)
        if user and new_account and _int(user.get("followers")) == 0:
            sev = Severity.MEDIUM if exec_assets else Severity.LOW
            st.add(REP004, f"{login} created {created.date().isoformat() if created else '?'}",
                   f"Owner '{login}' was created {account_age} day(s) ago and has 0 followers. {REP004.description}",
                   severity=sev)
        risky_assets = exec_assets or (zip_assets if new_account else [])
        if risky_assets and not _release_workflow(st.repo):
            st.add(REP005, ", ".join(risky_assets[:5]),
                   f"Release assets {', '.join(risky_assets[:5])} are uploaded by hand: no CI workflow in the repo "
                   "builds or publishes releases. You cannot verify they match the source.")
        self._history(st, data, new_account)

    # REP001
    def _stars(self, st: _Ctx, data: dict[str, Any]) -> None:
        created = _parse_dt(data.get("created_at"))
        if created is None:
            return
        age = max(1, (st.now - created).days)
        stars = _int(data.get("stargazers_count"))
        engagement = _int(data.get("forks_count")) + _int(data.get("open_issues_count"))
        if age < RECENT_REPO_DAYS and stars >= 200 and stars / age > 50 and engagement < stars * 0.02:
            st.add(REP001, f"{stars} stars in {age} days, {engagement} forks+issues",
                   f"{stars} stars in {age} day(s) ({stars // age}/day) but only {engagement} forks and open "
                   f"issues combined. {REP001.description}")

    # REP002
    def _fork(self, st: _Ctx, data: dict[str, Any]) -> None:
        if not data.get("fork"):
            return
        parent = _d(data.get("parent")) or _d(data.get("source"))
        p_full = parent.get("full_name")
        p_branch = parent.get("default_branch") or "HEAD"
        branch = data.get("default_branch") or "HEAD"
        if not isinstance(p_full, str) or "/" not in p_full:
            return
        cmp = _d(st.api(f"repos/{p_full}/compare/{p_branch}...{st.owner}:{branch}"))
        hits: list[tuple[str, str]] = []
        for f in _l(cmp.get("files")):
            name = _d(f).get("filename")
            if _d(f).get("status") == "removed":
                continue
            kind = _sensitive_kind(name)
            if kind:
                hits.append((name, kind))
        for name, kind in hits[:10]:
            sev = Severity.MEDIUM if kind == "CI workflow" else Severity.HIGH
            st.add(REP002, name, f"Fork of {p_full} changes {kind} '{name}'. {REP002.description}",
                   severity=sev, path=name if st.repo.get(name) else "")

    # REP003
    def _impersonation(self, st: _Ctx, data: dict[str, Any], account_age: int | None,
                       exec_assets: list[str]) -> None:
        canonical = top_repos().get(st.name.lower())
        if not canonical or canonical == st.owner.lower() or data.get("fork"):
            return
        desc = data.get("description") if isinstance(data.get("description"), str) else ""
        text = desc + "\n" + _readme_text(st.repo)
        signals: list[str] = []
        if account_age is not None and account_age < 180:
            signals.append(f"owner account is {account_age} day(s) old")
        if exec_assets:
            signals.append(f"executable release assets ({', '.join(exec_assets[:3])})")
        lure = LURE_WORDS.search(text)
        if lure:
            signals.append(f"lure wording '{lure.group(0)}'")
        if re.search(r"(?i)\bofficial\b", desc):
            signals.append("description claims to be official")
        if not signals:
            return
        extra = (T.PHISHING,) if exec_assets else ()
        st.add(REP003, f"{st.owner}/{st.name} (official: {canonical}/{st.name})",
               f"'{st.owner}/{st.name}' shares its name with the popular '{canonical}/{st.name}'; "
               f"{'; '.join(signals)}. {REP003.description}", extra_tags=extra)

    # REP006
    def _history(self, st: _Ctx, data: dict[str, Any], new_account: bool) -> None:
        commits = [c for c in _l(st.api(f"repos/{st.owner}/{st.name}/commits?per_page=30")) if isinstance(c, dict)]
        if not commits:
            return

        def when(c: dict[str, Any]) -> datetime | None:
            meta = _d(c.get("commit"))
            return _parse_dt(_d(meta.get("committer")).get("date")) or _parse_dt(_d(meta.get("author")).get("date"))

        sha = commits[0].get("sha")
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-fA-F]{7,64}", sha):
            return
        if len(commits) <= 2 and new_account:
            detail = _d(st.api(f"repos/{st.owner}/{st.name}/commits/{sha}"))
            nfiles = len(_l(detail.get("files")))
            adds = _int(_d(detail.get("stats")).get("additions"))
            if nfiles >= 50 or adds >= 5000:
                st.add(REP006, f"{sha[:10]}: {nfiles} files, +{adds}",
                       f"The whole repository arrived in {len(commits)} commit(s) ({nfiles} files, {adds} added "
                       f"lines) from a new account. {REP006.description}")
            return
        if len(commits) >= 2:
            latest, prev = when(commits[0]), when(commits[1])
            if latest and prev and latest - prev > timedelta(days=365):
                detail = _d(st.api(f"repos/{st.owner}/{st.name}/commits/{sha}"))
                files = [_d(f).get("filename") for f in _l(detail.get("files"))]
                kinds = [(f, _sensitive_kind(f)) for f in files if isinstance(f, str)]
                if kinds and all(k for _f, k in kinds):
                    st.add(REP006, f"{sha[:10]}: " + ", ".join(f for f, _k in kinds[:5]),
                           f"After {(latest - prev).days} days without commits, the latest commit only changes "
                           f"{', '.join(sorted({k for _f, k in kinds if k}))} files. {REP006.description}",
                           severity=Severity.HIGH)


# ---------------------------------------------------------------------------- offline README detector

_README_PREFIXES = ("readme", "install", "getting-started", "getting_started", "quickstart", "download", "usage")
_README_EXTS = {".md", ".markdown", ".rst", ".txt", ".html", ".htm", ".adoc", ""}

_FILE_HOST = re.compile(
    r"(?i)\b(?:mediafire\.com/(?:file|download|folder)|mega\.nz/(?:file|folder|#)|mega\.co\.nz/|gofile\.io/d/|"
    r"pixeldrain\.com/u/|anonfiles\.com/|transfer\.sh/|files\.catbox\.moe/|cdn\.discordapp\.com/attachments/|"
    r"media\.discordapp\.net/attachments/|dropbox\.com/s/|sendspace\.com/file|uploadhaven\.com/|krakenfiles\.com/|"
    r"workupload\.com/)"
)
_SHORTENER = re.compile(r"(?i)\b(?:bit\.ly|tinyurl\.com|cutt\.ly|t\.ly|is\.gd|rb\.gy|shorturl\.at|rebrand\.ly|"
                        r"tiny\.cc|goo\.su|clck\.ru)/[\w-]+")
_DOWNLOAD_CTX = re.compile(r"(?i)\b(?:download|setup|installer|launcher|release|get it|\.exe|\.zip|\.rar|\.7z|"
                           r"\.msi|crack|keygen|cheat|loader)\b|\.(?:exe|zip|rar|7z|msi)\b")
_ARCHIVE_CTX = re.compile(r"(?i)(?:\.(?:zip|rar|7z|exe|msi)\b|/releases\b|\barchive\b|\bextract\b|\bunzip\b|"
                          r"\bunrar\b)")
_AV_DISABLE = re.compile(
    r"(?i)\b(?:disable|turn\s+off|deactivate|pause|close|exit)\s+(?:your\s+|the\s+|windows\s+|all\s+)*"
    r"(?:defender|anti-?virus|av\b|antimalware|real-?time\s+protection|smartscreen|virus\s+protection)"
    r"|\b(?:add|whitelist|exclude)\b.{0,40}\b(?:exclusion|exception|whitelist)\b.{0,40}\b(?:defender|anti-?virus)"
    r"|\b(?:defender|anti-?virus)\b.{0,40}\b(?:exclusion|whitelist)\b"
)
_FALSE_POSITIVE = re.compile(r"(?i)\bfalse[\s-]+positive")
_AV_WORDS = re.compile(r"(?i)\b(?:anti-?virus|defender|virustotal|av\s+detect|windows\s+security|detected\s+as)")
_PASSWORD = re.compile(r"(?i)\b(?:archive\s+|zip\s+|rar\s+)?(?:password|passwd|pwd|pass)\b\s*(?:is\s*)?[:=\-]\s*"
                       r"[`'\"*]{0,3}([^\s`'\"*]{2,40})")
_PLACEHOLDER_PW = {"your_password", "yourpassword", "<password>", "password", "xxx", "xxxx", "****", "changeme",
                   "secret", "postgres", "root", "admin", "example", "${password}", "<your-password>"}


def _lower_conf(conf: Confidence, ctx: FileContext) -> Confidence:
    if (ctx.is_test or ctx.is_vendored) and conf > Confidence.LOW:
        return Confidence(conf - 1)
    return conf


class ReadmeLureDetector(Detector):
    id = "readme_lure"
    name = "README download lures"
    category = _C
    checks = (REP005, REP007)
    needs_network = False

    def applies_to(self, ctx: FileContext) -> bool:
        if ctx.is_binary or ctx.is_vendored:
            return False
        base = ctx.basename.lower()
        return base.startswith(_README_PREFIXES) and ctx.ext.lower() in _README_EXTS

    def scan_file(self, ctx: FileContext) -> Iterable[Finding]:
        lines = ctx.lines
        out: list[Finding] = []
        counts = {"host": 0, "short": 0, "av": 0, "pw": 0}
        in_fence = False
        fences: list[bool] = []
        for raw in lines:
            if raw.lstrip().startswith(("```", "~~~")):
                in_fence = not in_fence
                fences.append(True)
            else:
                fences.append(in_fence)

        def window(i: int) -> str:
            return "\n".join(lines[max(0, i - 3): i + 4])

        for i, line in enumerate(lines):
            n = i + 1
            if counts["host"] < 5 and (m := _FILE_HOST.search(line)):
                ctx_hit = bool(_DOWNLOAD_CTX.search(window(i)))
                sev = Severity.HIGH if ctx_hit else Severity.MEDIUM
                out.append(Finding.from_rule(REP007, ctx, n, line, severity=sev, extra_tags=(T.PHISHING,),
                                             confidence=_lower_conf(REP007.confidence, ctx),
                                             description=f"Download hosted on a file-sharing service "
                                                         f"({m.group(0)}) instead of GitHub releases or a package "
                                                         f"registry. {REP007.description}"))
                counts["host"] += 1
            elif counts["short"] < 5 and (m := _SHORTENER.search(line)) and _DOWNLOAD_CTX.search(window(i)):
                out.append(Finding.from_rule(REP007, ctx, n, line, severity=Severity.MEDIUM, extra_tags=(T.PHISHING,),
                                             confidence=_lower_conf(REP007.confidence, ctx),
                                             description=f"Download link hidden behind a URL shortener "
                                                         f"({m.group(0)}), so the real destination is not visible. "
                                                         f"{REP007.description}"))
                counts["short"] += 1
            if counts["av"] < 5 and (_AV_DISABLE.search(line) or
                                     (_FALSE_POSITIVE.search(line) and _AV_WORDS.search(window(i)))):
                out.append(Finding.from_rule(REP007, ctx, n, line, confidence=_lower_conf(REP007.confidence, ctx),
                                             title="README tells users to disable or ignore antivirus",
                                             description="The instructions ask users to disable antivirus, add an "
                                                         "exclusion, or dismiss detections as false positives. "
                                                         f"{REP007.description}"))
                counts["av"] += 1
            if counts["pw"] < 3 and not fences[i] and (pm := _PASSWORD.search(line)):
                value = pm.group(1).strip().lower().rstrip(".,;)")
                if value in _PLACEHOLDER_PW or value.startswith(("<", "${", "{{")):
                    continue
                win = window(i)
                if _ARCHIVE_CTX.search(win) or _FILE_HOST.search(win):
                    out.append(Finding.from_rule(REP005, ctx, n, line,
                                                 confidence=_lower_conf(REP005.confidence, ctx),
                                                 description="A password is given next to a download/archive link. "
                                                             "Password-protected archives hide their contents from "
                                                             f"antivirus and upload scanners. {REP005.description}"))
                    counts["pw"] += 1
        return out


DETECTORS = (ReputationDetector, ReadmeLureDetector)
