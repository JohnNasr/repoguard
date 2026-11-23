"""DEP001-DEP009: dependency and supply-chain risks (typosquats, malicious/vulnerable packages,
non-registry sources, dependency confusion, lockfile tampering, loose pins, committed trees).

Offline checks live in DependencyDetector. Online checks (OSV.dev, npm registry, PyPI JSON) live in
DependencyOnlineDetector (needs_network=True). Only package names and versions are ever sent.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Iterable, Iterator
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from importlib import resources
from typing import Any
from urllib.parse import quote, urlsplit

from .. import tags as T
from ..context import FileContext, RepoContext
from ..detector import Detector, RuleInfo
from ..models import Category, Confidence, Finding, Severity
from ..net import NetDisabled, NetError
from . import _depparse as dp

_C = Category.DEPENDENCY
_DR = frozenset({T.DEPENDENCY_RISK})

DEP001 = RuleInfo("DEP001", "Possible typosquatted dependency", Severity.MEDIUM, Confidence.MEDIUM, _C,
                  "A dependency name is one typo, separator, affix or look-alike character away from a very popular "
                  "package. Typosquats steal credentials or run code at install time.",
                  "Check the exact package name on the registry; replace it with the intended popular package.",
                  frozenset({T.DEPENDENCY_RISK, T.TYPOSQUAT}))
DEP002 = RuleInfo("DEP002", "Known malicious package", Severity.CRITICAL, Confidence.HIGH, _C,
                  "This dependency is a known malicious package (OSV MAL- advisory or bundled list of historical "
                  "malware packages). Installing it runs attacker code.",
                  "Do not install. Remove the dependency and treat any machine that installed it as compromised.",
                  frozenset({T.DEPENDENCY_RISK, T.BLOCK_TRIGGER}))
DEP003 = RuleInfo("DEP003", "Dependency version with known vulnerabilities", Severity.LOW, Confidence.HIGH, _C,
                  "A pinned/locked dependency version has published CVE/GHSA advisories (OSV.dev).",
                  "Upgrade to a fixed version.", frozenset({T.DEPENDENCY_RISK, T.HYGIENE}))
DEP004 = RuleInfo("DEP004", "Dependency from a non-registry source", Severity.MEDIUM, Confidence.HIGH, _C,
                  "A dependency or package-index setting pulls code from a git URL, tarball, raw IP, plain-http host, "
                  "path outside the repo or an alternative registry. These bypass the default registry's malware "
                  "takedowns and integrity guarantees.",
                  "Verify the source is trusted and pinned to an immutable commit or hash; prefer the default registry.",
                  _DR)
DEP005 = RuleInfo("DEP005", "Dependency confusion risk", Severity.MEDIUM, Confidence.MEDIUM, _C,
                  "An extra package index is merged with the public one. Anyone can publish a higher-versioned "
                  "package with an internal name on the public index and it may be installed instead.",
                  "Use a single index (--index-url) or pin each private package to its index; reserve internal names publicly.",
                  _DR)
DEP006 = RuleInfo("DEP006", "Lockfile integrity problem", Severity.HIGH, Confidence.HIGH, _C,
                  "A lockfile resolves packages from a host other than the official/declared registry, to a different "
                  "kind of source than the manifest asks for, or without an integrity hash. Lockfile tampering is a "
                  "known way to slip malicious tarballs past review.",
                  "Regenerate the lockfile from the official registry and review the diff.", _DR)
DEP007 = RuleInfo("DEP007", "Loosely pinned dependencies", Severity.LOW, Confidence.HIGH, _C,
                  "Dependencies use `*`, `latest`, open-ended ranges, or the project has no lockfile, so a future "
                  "malicious release would be installed automatically.",
                  "Pin versions and commit a lockfile.", frozenset({T.DEPENDENCY_RISK, T.HYGIENE}))
DEP008 = RuleInfo("DEP008", "Committed dependency tree", Severity.MEDIUM, Confidence.MEDIUM, _C,
                  "Third-party packages (node_modules, site-packages, vendor) are committed. Their contents are not "
                  "what the registry serves and are rarely reviewed, a good hiding place for modified code.",
                  "Delete the committed tree and install from the registry with a lockfile.", _DR)
DEP009 = RuleInfo("DEP009", "Very new dependency", Severity.LOW, Confidence.MEDIUM, _C,
                  "A dependency was first published less than 30 days ago. Most malicious packages are removed within "
                  "days, so brand-new packages carry more risk.",
                  "Check the package's author, repository and code before installing.", _DR)

# ---------------------------------------------------------------------------- data

NPM_HOSTS = frozenset({"registry.npmjs.org", "registry.yarnpkg.com", "registry.npmjs.com"})
PYPI_HOSTS = frozenset({"pypi.org", "pypi.python.org", "files.pythonhosted.org", "test.pypi.org"})
CARGO_DEFAULT = ("registry+https://github.com/rust-lang/crates.io-index", "sparse+https://index.crates.io/")
OTHER_HOSTS = {
    "rubygems": frozenset({"rubygems.org", "www.rubygems.org"}),
    "packagist": frozenset({"packagist.org", "repo.packagist.org"}),
    "nuget": frozenset({"api.nuget.org", "www.nuget.org", "nuget.org"}),
}
OSV_ECOSYSTEM = {"npm": "npm", "pypi": "PyPI", "cargo": "crates.io", "go": "Go", "rubygems": "RubyGems",
                 "packagist": "Packagist"}
OSV_URL = "https://api.osv.dev/v1/querybatch"
OSV_BATCH = 1000
MAX_OSV_BATCHES = 5
MAX_REGISTRY_LOOKUPS = 30
RECENT_DAYS = 30
MAX_PER_FILE = 20


@lru_cache(maxsize=8)
def _data_lines(name: str) -> tuple[str, ...]:
    try:
        text = (resources.files("repoguard") / "data" / name).read_text(encoding="utf-8")
    except (FileNotFoundError, OSError, ModuleNotFoundError):
        return ()
    return tuple(ln.strip() for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#"))


@lru_cache(maxsize=4)
def top_names(ecosystem: str) -> frozenset[str]:
    fname = {"npm": "top_npm.txt", "pypi": "top_pypi.txt"}.get(ecosystem)
    return frozenset(dp.normalize(ecosystem, n) for n in _data_lines(fname)) if fname else frozenset()


@lru_cache(maxsize=1)
def malicious_names() -> frozenset[tuple[str, str]]:
    out: set[tuple[str, str]] = set()
    for ln in _data_lines("malicious_packages.txt"):
        eco, sep, name = ln.partition(":")
        if sep and name:
            out.add((eco.strip().lower(), dp.normalize(eco.strip().lower(), name)))
    return frozenset(out)


# ---------------------------------------------------------------------------- typosquat


def dl_distance(a: str, b: str, max_d: int) -> int:
    """Optimal-string-alignment Damerau-Levenshtein distance, exiting early above max_d."""
    if abs(len(a) - len(b)) > max_d:
        return max_d + 1
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            v = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                v = min(v, prev2[j - 2] + 1)
            cur[j] = v
        if min(cur) > max_d:
            return max_d + 1
        prev2, prev = prev, cur
    return prev[-1]


_SEP_RE = re.compile(r"[-_.]")
_HOMOGLYPHS = (("rn", "m"), ("vv", "w"), ("1", "l"), ("0", "o"), ("5", "s"))
_PREFIXES = ("python-", "python", "py-", "py", "node-", "node")
_SUFFIXES = ("-js", ".js", "js", "-py", "-python", "-node")


def _canon(s: str) -> str:
    for a, b in _HOMOGLYPHS:
        s = s.replace(a, b)
    return s


@lru_cache(maxsize=4)
def _index(ecosystem: str) -> tuple[dict[str, str], dict[str, str], frozenset[str]]:
    top = top_names(ecosystem)
    nosep: dict[str, str] = {}
    canon: dict[str, str] = {}
    scopes = frozenset(t.split("/", 1)[0] for t in top if t.startswith("@"))
    for t in sorted(top):
        nosep.setdefault(_SEP_RE.sub("", t), t)
        canon.setdefault(_canon(t), t)
    return nosep, canon, scopes


def _same_modulo_digits(a: str, b: str) -> bool:
    return re.sub(r"\d+$", "", a) == re.sub(r"\d+$", "", b)


def typosquat_target(ecosystem: str, name: str) -> tuple[str, str] | None:
    """(popular package, reason) when `name` looks like a typosquat of a popular package."""
    top = top_names(ecosystem)
    if not top or not name:
        return None
    n = dp.normalize(ecosystem, name)
    if n in top:
        return None
    nosep, canon, scopes = _index(ecosystem)
    if n.startswith("@") and "/" in n:
        scope, base = n.split("/", 1)
        if scope in scopes:
            return None  # same scope as a popular package: the scope owner published it
        for ts in sorted(scopes):
            if len(ts) >= 5 and (dl_distance(scope, ts, 1) == 1 or _SEP_RE.sub("", scope) == _SEP_RE.sub("", ts)):
                cand = f"{ts}/{base}"
                return (cand if cand in top else ts), "scope look-alike"
        return None
    if len(n) < 5:
        return None
    hit = nosep.get(_SEP_RE.sub("", n))
    if hit and hit != n:
        return hit, "separator swap"
    hit = canon.get(_canon(n))
    if hit and hit != n:
        return hit, "look-alike characters"
    for p in _PREFIXES:
        if n.startswith(p) and n[len(p):] in top and len(n) - len(p) >= 4:
            return n[len(p):], f"added prefix '{p}'"
    for s in _SUFFIXES:
        if n.endswith(s) and n[: -len(s)] in top and len(n) - len(s) >= 4:
            return n[: -len(s)], f"added suffix '{s}'"
    max_d = 2 if len(n) >= 10 else 1
    best: tuple[int, str] | None = None
    for t in top:
        if t.startswith("@") or len(t) < 4 or abs(len(t) - len(n)) > max_d or _same_modulo_digits(n, t):
            continue
        d = dl_distance(n, t, max_d)
        if 0 < d <= max_d and (best is None or (d, t) < best):
            best = (d, t)
    if best:
        return best[1], f"edit distance {best[0]}"
    return None


# ---------------------------------------------------------------------------- helpers

_PARSE_CACHE: list[tuple[RepoContext, dp.RepoDeps]] = []


def parsed_repo(repo: RepoContext) -> dp.RepoDeps:
    for cached_repo, deps in _PARSE_CACHE:
        if cached_repo is repo:
            return deps
    deps = dp.parse_repo(repo.files, repo.get)
    _PARSE_CACHE.insert(0, (repo, deps))
    del _PARSE_CACHE[2:]
    return deps


def _lower(conf: Confidence, ctx: FileContext | None) -> Confidence:
    if ctx is not None and (ctx.is_test or ctx.is_doc or ctx.is_vendored) and conf > Confidence.LOW:
        return Confidence(conf - 1)
    return conf


def _emit(repo: RepoContext, info: RuleInfo, path: str, line: int | None, fallback: str, *,
          lower: bool = True, **kw: Any) -> Finding:
    ctx = repo.get(path)
    snippet = (ctx.line_text(line) if (ctx is not None and line) else "") or fallback
    if lower and "confidence" not in kw:
        kw["confidence"] = _lower(info.confidence, ctx)
    return Finding.from_rule(info, ctx, line, snippet, path=path, **kw)


def _host(url: str) -> str:
    u = url.strip().strip("'\"")
    for prefix in ("git+", "registry+", "sparse+"):
        if u.startswith(prefix):
            u = u[len(prefix):]
    if u.startswith("git@"):
        return u[4:].split(":", 1)[0].lower()
    if "://" not in u:
        if re.match(r"^[\w.-]+\.[a-z]{2,}(?::\d+)?(?:/|$)", u, re.I):  # bare host (trusted-host)
            return u.split("/", 1)[0].split(":", 1)[0].lower()
        return ""
    try:
        return (urlsplit(u).hostname or "").lower()
    except ValueError:
        return ""


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _url_severity(url: str) -> Severity:
    host = _host(url)
    if url.strip().lower().startswith(("http://", "git://", "git+http://", "ftp://")) or (host and _is_ip(host)):
        return Severity.HIGH
    return Severity.MEDIUM


def _escapes_repo(source_file: str, path: str) -> bool:
    p = path.strip()
    for prefix in ("file:", "link:", "portal:"):
        if p.startswith(prefix):
            p = p[len(prefix):]
    if p.startswith(("/", "~")) or re.match(r"^[A-Za-z]:[\\/]", p) or p.startswith("\\\\"):
        return True
    base = source_file.rpartition("/")[0]
    depth = len([x for x in base.split("/") if x])
    for part in p.replace("\\", "/").split("/"):
        if part == "..":
            depth -= 1
            if depth < 0:
                return True
        elif part not in ("", "."):
            depth += 1
    return False


def _exact_version(eco: str, spec: str) -> str | None:
    s = spec.strip()
    pats = {
        "npm": r"^=?v?(\d+\.\d+\.\d+[\w.+-]*)$",
        "pypi": r"^===?\s*([\w.+!-]+)$",
        "cargo": r"^=\s*(\d+\.\d+\.\d+[\w.+-]*)$",
        "go": r"^v?(\d+\.\d+\.\d+[\w.+-]*)$",
        "rubygems": r"^=?\s*(\d+(?:\.\d+)+[\w.-]*)$",
        "packagist": r"^v?(\d+\.\d+\.\d+[\w.-]*)$",
    }
    pat = pats.get(eco)
    m = re.match(pat, s) if pat else None
    return m.group(1) if m else None


# ---------------------------------------------------------------------------- offline detector


class DependencyDetector(Detector):
    id = "dependencies"
    name = "Dependencies & supply chain"
    category = _C
    checks = (DEP001, DEP002, DEP004, DEP005, DEP006, DEP007, DEP008)
    needs_network = False

    def scan_file(self, ctx: FileContext) -> Iterable[Finding]:
        return ()

    def scan_repo(self, repo: RepoContext) -> Iterable[Finding]:
        deps = parsed_repo(repo)
        out: list[Finding] = []
        out += self._typosquats(repo, deps)
        out += self._known_malicious(repo, deps)
        out += self._sources(repo, deps)
        out += self._go_env(repo, deps)
        out += self._confusion(repo, deps)
        out += self._lockfiles(repo, deps)
        out += self._loose(repo, deps)
        out += self._committed_trees(repo)
        return out

    # DEP001
    def _typosquats(self, repo: RepoContext, rd: dp.RepoDeps) -> Iterator[Finding]:
        own = {n for _e, n in rd.parsed.own_names}
        own_scopes = {n.split("/", 1)[0] for n in own if n.startswith("@")}
        seen: set[tuple[str, str, str]] = set()
        for dep in rd.parsed.deps:
            if dep.kind not in ("registry", "alt-registry") or not dep.name or dep.name in own:
                continue
            if dep.name.startswith("@") and dep.name.split("/", 1)[0] in own_scopes:
                continue
            key = (dep.ecosystem, dep.name, dep.source_file)
            if key in seen:
                continue
            seen.add(key)
            hit = typosquat_target(dep.ecosystem, dep.name)
            if hit:
                target, reason = hit
                yield _emit(repo, DEP001, dep.source_file, dep.line, f"{dep.name} {dep.version_spec}",
                            description=f"'{dep.name}' resembles the popular {dep.ecosystem} package '{target}' "
                                        f"({reason}). {DEP001.description}")

    # DEP002 (offline list)
    def _known_malicious(self, repo: RepoContext, rd: dp.RepoDeps) -> Iterator[Finding]:
        bad = malicious_names()
        seen: set[tuple[str, str]] = set()
        records = [(d.ecosystem, d.name, d.source_file, d.line) for d in rd.parsed.deps]
        records += [(e.ecosystem, e.name, e.source_file, e.line) for e in rd.parsed.locks]
        for eco, name, path, line in records:
            key = (eco, dp.normalize(eco, name))
            if key in bad and key not in seen:
                seen.add(key)
                yield _emit(repo, DEP002, path, line, name, lower=False,
                            description=f"'{name}' ({eco}) is on the bundled list of known malicious packages. "
                                        f"{DEP002.description}")

    # DEP004
    def _sources(self, repo: RepoContext, rd: dp.RepoDeps) -> Iterator[Finding]:
        for dep in rd.parsed.deps:
            url = dep.source_url
            if dep.kind in ("git", "url"):
                msg = f"'{dep.name or url}' is installed from {dep.kind} source {url!r} instead of the registry."
                yield _emit(repo, DEP004, dep.source_file, dep.line, url, severity=_url_severity(url), description=msg)
            elif dep.kind == "alt-registry":
                msg = f"'{dep.name}' is pinned to alternative registry/index {url!r}."
                yield _emit(repo, DEP004, dep.source_file, dep.line, url, description=msg)
            elif dep.kind == "replace" and dep.ecosystem == "go":
                msg = f"go.mod replaces '{dep.name}' with a different module: {url!r}."
                yield _emit(repo, DEP004, dep.source_file, dep.line, url, description=msg)
            elif dep.kind == "path" and url and _escapes_repo(dep.source_file, url):
                msg = f"'{dep.name or url}' is installed from a path outside the repository: {url!r}."
                yield _emit(repo, DEP004, dep.source_file, dep.line, url, description=msg)
        for src in rd.parsed.sources:
            f = self._source_finding(repo, src, rd)
            if f is not None:
                yield f

    def _source_finding(self, repo: RepoContext, src: dp.SourceConfig, rd: dp.RepoDeps) -> Finding | None:
        url, host = src.url, _host(src.url)
        if src.kind == "strict-ssl-off":
            return _emit(repo, DEP004, src.source_file, src.line, src.raw, severity=Severity.HIGH,
                         description="TLS certificate verification for the package registry is disabled, so "
                                     "packages can be swapped in transit.")
        if src.kind == "trusted-host":
            return _emit(repo, DEP004, src.source_file, src.line, src.raw or url,
                         description=f"pip --trusted-host {url!r} disables TLS verification for that index.")
        if src.kind in ("replace-with", "cargo-registry"):
            return _emit(repo, DEP004, src.source_file, src.line, src.raw or url,
                         description=f"Cargo source replacement/alternate registry: {src.raw or url!r}.")
        default = {"npm": NPM_HOSTS, "pypi": PYPI_HOSTS}.get(src.ecosystem) or OTHER_HOSTS.get(src.ecosystem, frozenset())
        if src.kind == "find-links" and not host:
            return None  # local wheel directory
        if src.kind in ("nuget-source", "composer-repo") and not host:
            if src.kind == "composer-repo" or not _escapes_repo(src.source_file, url):
                return None
        if host and host in default and not url.lower().startswith("http://"):
            return None
        where = f" ({src.scope})" if src.scope else ""
        return _emit(repo, DEP004, src.source_file, src.line, src.raw or url, severity=_url_severity(url),
                     description=f"{src.ecosystem} package source{where} points to {url!r} ({src.kind}) instead of "
                                 f"the default registry. {DEP004.description}")

    # DEP004 GOPROXY & co
    _GOENV_RE = re.compile(r"(?i)\b(GOPROXY|GONOSUMDB|GONOSUMCHECK|GOINSECURE|GOSUMDB|GOFLAGS)\b[\"']?\s{0,3}[=:]\s{0,3}[\"']?([^\s\"';]{1,300})")

    def _go_env(self, repo: RepoContext, rd: dp.RepoDeps) -> Iterator[Finding]:
        if not repo.by_basename("go.mod"):
            return
        names = {"makefile", "dockerfile", "go.env", ".envrc", ".env", "justfile", "gnumakefile"}
        exts = {".sh", ".bash", ".ps1", ".yml", ".yaml", ".env", ".mk", ".bat", ".cmd", ".toml"}
        count = 0
        for ctx in repo.files:
            if ctx.is_binary or not (ctx.basename.lower() in names or ctx.ext in exts or ctx.is_ci):
                continue
            if not any(k in ctx.lower for k in ("goproxy", "gonosum", "goinsecure", "gosumdb", "goflags")):
                continue
            for i, line in enumerate(ctx.lines, 1):
                for m in self._GOENV_RE.finditer(line):
                    var, val = m.group(1).upper(), m.group(2)
                    bad = (
                        (var == "GOPROXY" and any(_host(v) and _host(v) != "proxy.golang.org"
                                                  for v in re.split(r"[,|]", val)))
                        or (var == "GOSUMDB" and val.lower() == "off")
                        or var in ("GONOSUMDB", "GONOSUMCHECK", "GOINSECURE")
                        or (var == "GOFLAGS" and "-insecure" in val)
                    )
                    if bad:
                        yield Finding.from_rule(DEP004, ctx, i, line, confidence=_lower(DEP004.confidence, ctx),
                                                description=f"Go module download/verification changed: {var}={val}. "
                                                            "Checksum database or default proxy bypassed.")
                        count += 1
                        break
                if count >= MAX_PER_FILE:
                    return

    # DEP005 (offline part)
    def _confusion(self, repo: RepoContext, rd: dp.RepoDeps) -> Iterator[Finding]:
        pipfile_sources: dict[str, list[dp.SourceConfig]] = {}
        for src in rd.parsed.sources:
            if src.kind == "extra-index-url":
                yield _emit(repo, DEP005, src.source_file, src.line, src.raw or src.url,
                            description=f"Extra index {src.url!r} is merged with the default index. {DEP005.description}")
            elif src.kind == "pipfile-source":
                pipfile_sources.setdefault(src.source_file, []).append(src)
        for srcs in pipfile_sources.values():
            if len(srcs) > 1:
                s = srcs[1]
                yield _emit(repo, DEP005, s.source_file, s.line, s.raw or s.url,
                            description="Pipfile declares several package sources; pipenv may resolve unpinned "
                                        f"packages from any of them. {DEP005.description}")

    # DEP006
    def _lockfiles(self, repo: RepoContext, rd: dp.RepoDeps) -> Iterator[Finding]:
        p = rd.parsed
        allowed = {
            "npm": set(NPM_HOSTS) | {_host(s.url) for s in p.sources if s.ecosystem == "npm" and s.url},
            "pypi": set(PYPI_HOSTS) | {_host(s.url) for s in p.sources if s.ecosystem == "pypi" and s.url},
            "cargo": {_host(s.url) for s in p.sources if s.ecosystem == "cargo" and s.url},
        }
        manifest_kinds: dict[tuple[str, str], set[str]] = {}
        for d in p.deps:
            manifest_kinds.setdefault((d.ecosystem, d.name), set()).add(d.kind)
        per_file: dict[str, int] = {}
        for e in p.locks:
            problem = self._lock_problem(e, allowed, manifest_kinds)
            if not problem:
                continue
            per_file[e.source_file] = per_file.get(e.source_file, 0) + 1
            if per_file[e.source_file] > MAX_PER_FILE:
                continue
            msg, sev = problem
            yield _emit(repo, DEP006, e.source_file, e.line, f"{e.name} {e.resolved}", severity=sev,
                        description=f"{e.name}@{e.version}: {msg}")

    @staticmethod
    def _lock_problem(e: dp.LockEntry, allowed: dict[str, set[str]],
                      manifest_kinds: dict[tuple[str, str], set[str]]) -> tuple[str, Severity] | None:
        declared = manifest_kinds.get((e.ecosystem, e.name), set())
        if e.kind == "git" and declared and not (declared & {"git", "url"}):
            return f"manifest asks for a registry version but the lockfile resolves to git source {e.resolved!r}", Severity.HIGH
        if e.ecosystem == "cargo":
            if e.kind == "registry" and e.resolved and not e.resolved.startswith(CARGO_DEFAULT):
                if _host(e.resolved) not in allowed["cargo"]:
                    return f"resolved from undeclared registry {e.resolved!r}", Severity.HIGH
            if e.kind == "registry" and e.resolved and not e.integrity:
                return "registry package without checksum", Severity.MEDIUM
            return None
        if e.kind not in ("registry", "url") or not e.resolved:
            if e.ecosystem == "npm" and e.kind == "registry" and not e.integrity and e.source_file.endswith("pnpm-lock.yaml"):
                return "no integrity hash recorded", Severity.MEDIUM
            return None
        url = e.resolved
        host = _host(url)
        if url.lower().startswith("http://"):
            return f"downloaded over plain http: {url!r}", Severity.HIGH
        if host and host not in allowed.get(e.ecosystem, set()):
            return f"resolved from unexpected host {host!r} ({url!r})", Severity.HIGH
        if e.ecosystem == "npm" and not e.integrity and url.lower().startswith("https://"):
            return "no integrity hash recorded for a registry tarball", Severity.MEDIUM
        return None

    # DEP007
    _OPEN_RANGE = re.compile(r"^\s*>=?\s*[\w.*-]+\s*$")

    def _loose(self, repo: RepoContext, rd: dp.RepoDeps) -> Iterator[Finding]:
        loose: dict[str, list[dp.Dep]] = {}
        for d in rd.parsed.deps:
            if d.kind != "registry" or not d.name:
                continue
            spec = d.version_spec.strip().lower()
            base = d.source_file.rsplit("/", 1)[-1].lower()
            is_loose = False
            if d.ecosystem == "npm" and d.section not in ("peerDependencies", "overrides", "resolutions"):
                is_loose = spec in ("*", "", "latest", "x", "next") or bool(self._OPEN_RANGE.match(spec))
            elif d.ecosystem == "pypi" and dp.parser_for(d.source_file) is dp.parse_requirements:
                is_loose = spec == "" or bool(self._OPEN_RANGE.match(spec))
            elif d.ecosystem in ("pypi", "cargo") and base in ("pipfile", "cargo.toml", "pyproject.toml"):
                is_loose = spec == "*"
            if is_loose:
                loose.setdefault(d.source_file, []).append(d)
        for path, items in loose.items():
            names = ", ".join(f"{d.name}{(' ' + d.version_spec) if d.version_spec else ''}" for d in items[:10])
            more = f" (+{len(items) - 10} more)" if len(items) > 10 else ""
            yield _emit(repo, DEP007, path, items[0].line, names,
                        description=f"Unpinned / open-ended dependencies: {names}{more}.")
        for path in rd.manifests:
            if not path.lower().endswith("package.json") or path.rsplit("/", 1)[-1].lower() != "package.json":
                continue
            ctx = repo.get(path)
            if ctx is None or ctx.is_test or ctx.is_vendored:
                continue
            has_reg = any(d.source_file == path and d.kind == "registry" and d.section in ("dependencies", "devDependencies")
                          for d in rd.parsed.deps)
            d = path.rpartition("/")[0]
            if has_reg and d not in rd.lockfile_dirs and "" not in rd.lockfile_dirs:
                yield _emit(repo, DEP007, path, None, "package.json without lockfile",
                            description="package.json has dependencies but no package-lock.json / yarn.lock / "
                                        "pnpm-lock.yaml, so every install resolves the newest matching versions.")

    # DEP008
    def _committed_trees(self, repo: RepoContext) -> Iterator[Finding]:
        roots: dict[str, set[str]] = {}
        hooks: list[tuple[FileContext, int, str]] = []
        vendor_markers: dict[str, str] = {}
        for ctx in repo.files:
            rl = ctx.rel_lower
            m = re.search(r"(^|/)(node_modules|site-packages)/", rl)
            if m:
                root = ctx.rel_path[: m.end() - 1]
                rest = ctx.rel_path[m.end():]
                parts = rest.split("/")
                if m.group(2) == "node_modules":
                    pkg = "/".join(parts[:2]) if parts[0].startswith("@") else parts[0]
                    if ctx.basename == "package.json" and rest.count("/") == pkg.count("/") + 1 - (0 if "/" in pkg else 0) and rest == f"{pkg}/package.json":
                        roots.setdefault(root, set()).add(pkg)
                        hook = self._install_hook(ctx)
                        if hook:
                            hooks.append((ctx, *hook))
                    else:
                        roots.setdefault(root, set())
                else:
                    pkg = parts[0]
                    if pkg.endswith((".dist-info", ".egg-info")) or len(parts) > 1:
                        roots.setdefault(root, set()).add(pkg.split("-")[0] if pkg.endswith("-info") else pkg)
                continue
            vm = re.search(r"(^|/)vendor/(modules\.txt|autoload\.php|composer/|bundle/)", rl)
            if vm:
                vendor_markers.setdefault(ctx.rel_path[: vm.start(2) - 1], vm.group(2).rstrip("/"))
        for root, pkgs in sorted(roots.items())[:10]:
            if "/node_modules" in root and any(root.startswith(r + "/") for r in roots if r != root):
                continue  # nested node_modules inside an already-reported tree
            yield Finding.from_rule(DEP008, None, None, root + "/", path=root,
                                    description=f"Committed dependency tree '{root}/' with {len(pkgs)} package(s). "
                                                f"{DEP008.description}")
        for ctx, line, script in hooks[:10]:
            yield Finding.from_rule(DEP008, ctx, line, script, severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                                    title="Install script inside committed node_modules",
                                    description="A package inside the committed node_modules declares an install-time "
                                                "script; it would run on `npm rebuild`/install and is not the "
                                                "registry's copy.")
        for root, marker in sorted(vendor_markers.items())[:5]:
            yield Finding.from_rule(DEP008, None, None, f"{root}/{marker}", path=root, severity=Severity.LOW,
                                    description=f"Vendored dependencies committed under '{root}/' ({marker}). "
                                                "Review that they match upstream releases.")

    @staticmethod
    def _install_hook(ctx: FileContext) -> tuple[int, str] | None:
        try:
            data = json.loads(ctx.text)
        except (json.JSONDecodeError, ValueError, RecursionError):
            return None
        scripts = data.get("scripts") if isinstance(data, dict) else None
        if not isinstance(scripts, dict):
            return None
        for key in ("preinstall", "install", "postinstall"):
            if isinstance(scripts.get(key), str) and scripts[key].strip():
                needle = f'"{key}"'
                line = next((i for i, ln in enumerate(ctx.lines, 1) if needle in ln), None)
                return line or 1, f'"{key}": {scripts[key]}'
        return None


# ---------------------------------------------------------------------------- online detector


class DependencyOnlineDetector(Detector):
    id = "dependencies_online"
    name = "Dependencies (online: OSV, registries)"
    category = _C
    checks = (DEP003, DEP009)
    needs_network = True

    def scan_file(self, ctx: FileContext) -> Iterable[Finding]:
        return ()

    def scan_repo(self, repo: RepoContext) -> Iterable[Finding]:
        if repo.options.offline:
            return []
        rd = parsed_repo(repo)
        out: list[Finding] = []
        try:
            out += self._osv(repo, rd)
            out += self._registry_checks(repo, rd)
        except NetDisabled:
            pass
        return out

    # DEP002 (OSV MAL-) + DEP003
    def _osv(self, repo: RepoContext, rd: dp.RepoDeps) -> list[Finding]:
        queries: dict[tuple[str, str, str], tuple[str, int | None]] = {}
        offline_bad = malicious_names()
        for e in rd.parsed.locks:
            if e.ecosystem in OSV_ECOSYSTEM and e.kind == "registry" and e.name and e.version:
                queries.setdefault((e.ecosystem, e.name, e.version), (e.source_file, e.line))
        for d in rd.parsed.deps:
            if d.ecosystem in OSV_ECOSYSTEM and d.kind in ("registry", "alt-registry") and d.name:
                version = _exact_version(d.ecosystem, d.version_spec) or ""
                queries.setdefault((d.ecosystem, d.name, version), (d.source_file, d.line))
        keys = [k for k in queries if (k[0], dp.normalize(k[0], k[1])) not in offline_bad]
        keys = keys[: OSV_BATCH * MAX_OSV_BATCHES]
        out: list[Finding] = []
        reported_mal: set[tuple[str, str]] = set()
        reported_vuln: set[tuple[str, str, str]] = set()
        for start in range(0, len(keys), OSV_BATCH):
            chunk = keys[start: start + OSV_BATCH]
            payload = {"queries": [self._osv_query(eco, name, ver) for eco, name, ver in chunk]}
            try:
                resp = repo.net.post_json(OSV_URL, payload)
            except NetError:
                break
            results = resp.get("results") if isinstance(resp, dict) else None
            if not isinstance(results, list):
                continue
            for (eco, name, ver), res in zip(chunk, results):
                vulns = res.get("vulns") if isinstance(res, dict) else None
                ids = [v.get("id", "") for v in (vulns or []) if isinstance(v, dict) and isinstance(v.get("id"), str)]
                if not ids:
                    continue
                path, line = queries[(eco, name, ver)]
                mal = [i for i in ids if i.startswith("MAL-")]
                if mal and ver and (eco, name) not in reported_mal:
                    reported_mal.add((eco, name))
                    out.append(_emit(repo, DEP002, path, line, f"{name} {ver}".strip(), lower=False,
                                     description=f"OSV reports '{name}@{ver}' ({eco}) as malicious: "
                                                 f"{', '.join(mal[:5])}. {DEP002.description}"))
                elif mal and (eco, name) not in reported_mal:
                    # Version range only: OSV lists advisories for ANY version (e.g. a few hijacked releases of a
                    # popular package). Without an exact version we cannot say the repo uses a bad one.
                    reported_mal.add((eco, name))
                    out.append(_emit(repo, DEP002, path, line, name, lower=False, severity=Severity.LOW,
                                     confidence=Confidence.LOW, title="Some versions of this package were malicious",
                                     description=f"OSV lists malware advisories for some versions of '{name}' ({eco}): "
                                                 f"{', '.join(mal[:5])}. The manifest only gives a version range, so "
                                                 "check the lockfile / installed version is not one of them."))
                vuln = [i for i in ids if not i.startswith("MAL-")]
                if vuln and ver and (eco, name, ver) not in reported_vuln:
                    reported_vuln.add((eco, name, ver))
                    more = f" (+{len(vuln) - 5} more)" if len(vuln) > 5 else ""
                    out.append(_emit(repo, DEP003, path, line, f"{name} {ver}",
                                     description=f"{name}@{ver} ({eco}) has known advisories: "
                                                 f"{', '.join(vuln[:5])}{more}."))
        return out

    @staticmethod
    def _osv_query(eco: str, name: str, version: str) -> dict[str, Any]:
        q: dict[str, Any] = {"package": {"name": name, "ecosystem": OSV_ECOSYSTEM[eco]}}
        if version:
            q["version"] = version.removeprefix("v") if eco == "go" else version
        return q

    # DEP005 (online) + DEP009
    def _registry_checks(self, repo: RepoContext, rd: dp.RepoDeps) -> list[Finding]:
        p = rd.parsed
        own = {n for _e, n in p.own_names}
        extra_index = any(s.kind in ("extra-index-url",) or (s.kind == "pipfile-source" and _host(s.url) not in PYPI_HOSTS)
                          for s in p.sources if s.ecosystem == "pypi")
        custom_npm = any(s.kind == "registry" and _host(s.url) not in NPM_HOSTS for s in p.sources if s.ecosystem == "npm")
        out: list[Finding] = []
        budget = MAX_REGISTRY_LOOKUPS
        seen: set[tuple[str, str]] = set()
        now = datetime.now(timezone.utc)
        for d in p.deps:
            if budget <= 0:
                break
            if d.ecosystem not in ("npm", "pypi") or d.kind != "registry" or not d.name or d.name in own:
                continue
            if d.name in top_names(d.ecosystem) or (d.ecosystem, d.name) in seen:
                continue
            if d.ecosystem == "npm" and custom_npm:
                continue  # resolved from a private registry; the public one says nothing useful
            seen.add((d.ecosystem, d.name))
            budget -= 1
            try:
                data = repo.net.get_json(self._registry_url(d.ecosystem, d.name))
            except NetError:
                continue
            if data is None:
                if d.ecosystem == "pypi" and extra_index:
                    out.append(_emit(repo, DEP005, d.source_file, d.line, d.name, severity=Severity.HIGH,
                                     confidence=Confidence.HIGH,
                                     description=f"'{d.name}' does not exist on public PyPI while an extra index is "
                                                 "configured: anyone can register it there and pip may prefer it."))
                continue
            created = self._created(d.ecosystem, data)
            if created is not None and now - created < timedelta(days=RECENT_DAYS):
                age = max(0, (now - created).days)
                out.append(_emit(repo, DEP009, d.source_file, d.line, f"{d.name} {d.version_spec}",
                                 description=f"'{d.name}' ({d.ecosystem}) was first published {age} day(s) ago "
                                             f"({created.date().isoformat()}). {DEP009.description}"))
        return out

    @staticmethod
    def _registry_url(eco: str, name: str) -> str:
        if eco == "npm":
            return "https://registry.npmjs.org/" + quote(name, safe="@")
        return f"https://pypi.org/pypi/{quote(name, safe='')}/json"

    @staticmethod
    def _created(eco: str, data: Any) -> datetime | None:
        stamps: list[str] = []
        if not isinstance(data, dict):
            return None
        if eco == "npm":
            t = data.get("time")
            if isinstance(t, dict) and isinstance(t.get("created"), str):
                stamps.append(t["created"])
        else:
            for files in (data.get("releases") or {}).values() if isinstance(data.get("releases"), dict) else ():
                for f in files if isinstance(files, list) else ():
                    if isinstance(f, dict):
                        s = f.get("upload_time_iso_8601") or f.get("upload_time")
                        if isinstance(s, str):
                            stamps.append(s)
        parsed: list[datetime] = []
        for s in stamps:
            try:
                dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            except ValueError:
                continue
            parsed.append(dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc))
        return min(parsed) if parsed else None


DETECTORS = (DependencyDetector, DependencyOnlineDetector)
