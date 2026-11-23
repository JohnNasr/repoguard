"""Pure dependency-manifest parsers. Text in, records out: nothing is executed, imported or fetched.

Every parser takes ``(rel_path, text)`` and returns a ``Parsed`` bundle of dependency records, lockfile
entries, package-source configuration and the project's own package names. Parsers never raise on
malformed input; they return whatever they could read.
"""

from __future__ import annotations

import ast
import json
import re
import tomllib
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from .. import pyast
from ..context import FileContext

# ---------------------------------------------------------------------------- records


@dataclass(frozen=True, slots=True)
class Dep:
    """One declared dependency."""

    ecosystem: str  # npm | pypi | cargo | go | rubygems | packagist
    name: str
    version_spec: str
    source_file: str
    line: int | None
    source_url: str = ""  # git/url/path/alt-registry location when not the default registry
    kind: str = "registry"  # registry | git | url | path | workspace | alt-registry | replace
    section: str = ""


@dataclass(frozen=True, slots=True)
class LockEntry:
    """One resolved package in a lockfile."""

    ecosystem: str
    name: str
    version: str
    resolved: str  # download URL / source string ("" when the lockfile does not record one)
    integrity: str  # integrity hash / checksum ("" when missing)
    source_file: str
    line: int | None
    kind: str = "registry"  # registry | git | url | path | workspace


@dataclass(frozen=True, slots=True)
class SourceConfig:
    """A package index / registry / TLS setting that changes where packages come from."""

    ecosystem: str
    kind: str  # index-url | extra-index-url | trusted-host | find-links | registry | scoped-registry |
    #            strict-ssl-off | poetry-source | uv-index | pipfile-source | dependency-link |
    #            replace-with | cargo-registry | nuget-source | gem-source | composer-repo | pdm-source
    url: str
    source_file: str
    line: int | None
    raw: str = ""
    scope: str = ""


@dataclass(frozen=True, slots=True)
class Parsed:
    deps: tuple[Dep, ...] = ()
    locks: tuple[LockEntry, ...] = ()
    sources: tuple[SourceConfig, ...] = ()
    own_names: tuple[tuple[str, str], ...] = ()  # (ecosystem, name) of the project itself
    includes: tuple[str, ...] = ()  # requirement files referenced with -r / -c (relative to the file)

    def merge(self, other: "Parsed") -> "Parsed":
        return Parsed(
            self.deps + other.deps,
            self.locks + other.locks,
            self.sources + other.sources,
            self.own_names + other.own_names,
            self.includes + other.includes,
        )


EMPTY = Parsed()

# ---------------------------------------------------------------------------- helpers

_PEP503_RE = re.compile(r"[-_.]+")


def normalize(ecosystem: str, name: str) -> str:
    name = name.strip()
    if ecosystem == "pypi":
        return _PEP503_RE.sub("-", name).lower()
    return name.lower()


def _load_toml(text: str) -> dict[str, Any]:
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError, RecursionError, TypeError):
        return {}
    return data if isinstance(data, dict) else {}


def _load_json(text: str) -> Any:
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError, RecursionError):
        return None


def _d(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _l(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _s(value: Any) -> str:
    return value if isinstance(value, str) else ""


class _Lines:
    """Offset -> line lookups for one text, plus approximate 'where is this name' searches."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.starts = [0] + [m.end() for m in re.finditer("\n", text)]

    def line_of(self, offset: int) -> int:
        lo, hi = 0, len(self.starts)
        while lo < hi:
            mid = (lo + hi) // 2
            if self.starts[mid] <= offset:
                lo = mid + 1
            else:
                hi = mid
        return lo

    def find(self, needle: str, start: int = 0) -> tuple[int | None, int]:
        pos = self.text.find(needle, start)
        if pos < 0:
            return None, start
        return self.line_of(pos), pos

    def name_line(self, name: str) -> int | None:
        """Line where a dependency name is declared (TOML key, quoted string, or bare word)."""
        esc = re.escape(name)
        for pat in (rf"(?mi)^[ \t]*[\"']?{esc}[\"']?[ \t]*=", rf"(?i)[\"']{esc}(?![\w-])", rf"(?i)(?<![\w-]){esc}(?![\w-])"):
            m = re.search(pat, self.text)
            if m:
                return self.line_of(m.start())
        return None


def classify_location(spec: str) -> str:
    """git | url | path | '' for a version-spec-or-location string."""
    s = spec.strip().lower()
    if s.startswith(("git+", "git://", "git@", "github:", "gitlab:", "bitbucket:", "gist:", "hg+", "svn+", "bzr+")):
        return "git"
    if s.startswith(("http://", "https://", "ftp://")):
        return "git" if s.split("#", 1)[0].endswith(".git") else "url"
    if s.startswith(("file:", "link:", "portal:", "./", "../", "/", "~/", ".\\", "..\\")) or re.match(r"^[a-z]:[\\/]", s):
        return "path"
    return ""


# ---------------------------------------------------------------------------- npm


NPM_DEP_SECTIONS = (
    "dependencies", "devDependencies", "peerDependencies", "optionalDependencies", "overrides", "resolutions",
)
_GH_SHORTHAND_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:#\S*)?$")


def classify_npm_spec(spec: str) -> tuple[str, str, str | None]:
    """(kind, source_url, alias_target) for an npm version spec."""
    s = spec.strip()
    if s.startswith("npm:"):
        rest = s[4:]
        if rest.startswith("@"):
            head, sep, _ver = rest[1:].partition("@")
            target = "@" + head
        else:
            target, sep, _ver = rest.partition("@")
        return "registry", "", target or None
    if s.startswith("workspace:"):
        return "workspace", s, None
    loc = classify_location(s)
    if loc:
        return loc, s, None
    if _GH_SHORTHAND_RE.match(s) and not s.startswith("@"):
        return "git", s, None
    return "registry", "", None


def parse_package_json(rel: str, text: str) -> Parsed:
    data = _load_json(text)
    if not isinstance(data, dict):
        return EMPTY
    lines = _Lines(text)
    deps: list[Dep] = []
    own: list[tuple[str, str]] = []
    if isinstance(data.get("name"), str) and data["name"]:
        own.append(("npm", data["name"].lower()))
    for section in NPM_DEP_SECTIONS:
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        _ln, sec_pos = lines.find(f'"{section}"')
        for name, spec in block.items():
            if not isinstance(name, str):
                continue
            if isinstance(spec, dict):  # nested overrides
                spec = _s(spec.get("."))
            spec = _s(spec)
            line, _ = lines.find(f'"{name}"', sec_pos)
            kind, url, alias = classify_npm_spec(spec)
            real = alias or name.split("/node_modules/")[-1]
            if section == "resolutions":  # yarn resolution keys can be paths like "a/**/b"
                real = real.rsplit("**/", 1)[-1]
                if real.count("/") > (1 if real.startswith("@") else 0):
                    continue
            deps.append(Dep("npm", real.lower(), spec, rel, line, url, kind, section))
    for section in ("bundledDependencies", "bundleDependencies"):
        for name in _l(data.get(section)):
            if isinstance(name, str):
                deps.append(Dep("npm", name.lower(), "", rel, lines.find(f'"{name}"')[0], "", "registry", section))
    return Parsed(deps=tuple(deps), own_names=tuple(own))


def _npm_lock_kind(resolved: str) -> str:
    if not resolved:
        return "registry"
    return classify_location(resolved) or "registry"


def parse_package_lock(rel: str, text: str) -> Parsed:
    data = _load_json(text)
    if not isinstance(data, dict):
        return EMPTY
    lines = _Lines(text)
    out: list[LockEntry] = []
    packages = data.get("packages")
    pos = 0
    if isinstance(packages, dict):
        for key, entry in packages.items():
            if not key or not isinstance(entry, dict) or entry.get("link") or "node_modules/" not in key:
                continue
            name = _s(entry.get("name")) or key.rsplit("node_modules/", 1)[-1]
            line, pos = lines.find(f'"{key}"', pos)
            resolved = _s(entry.get("resolved"))
            out.append(LockEntry("npm", name.lower(), _s(entry.get("version")), resolved,
                                 _s(entry.get("integrity")), rel, line, _npm_lock_kind(resolved)))
        return Parsed(locks=tuple(out))

    def walk(deps: Any, depth: int) -> None:
        nonlocal pos
        if not isinstance(deps, dict) or depth > 40:
            return
        for name, entry in deps.items():
            if not isinstance(entry, dict):
                continue
            line, pos = lines.find(f'"{name}"', pos)
            resolved = _s(entry.get("resolved"))
            version = _s(entry.get("version"))
            kind = _npm_lock_kind(resolved) if resolved else (classify_location(version) or "registry")
            out.append(LockEntry("npm", str(name).lower(), version, resolved, _s(entry.get("integrity")),
                                 rel, line, kind))
            walk(entry.get("dependencies"), depth + 1)

    walk(data.get("dependencies"), 0)
    return Parsed(locks=tuple(out))


def _yarn_name(spec: str) -> str:
    spec = spec.strip().strip('"').strip("'")
    if spec.startswith("@"):
        head, _sep, _rest = spec[1:].partition("@")
        return "@" + head
    return spec.partition("@")[0]


def _berry_resolution(resolution: str) -> tuple[str, str]:
    """(kind, resolved-url) for a yarn berry `resolution:` value like `x@npm:1.0.0`."""
    res = resolution.strip().strip('"')
    body = res[1:].partition("@")[2] if res.startswith("@") else res.partition("@")[2]
    if body.startswith(("npm:", "patch:")):
        return "registry", ""
    if body.startswith("workspace:"):
        return "workspace", ""
    loc = classify_location(body)
    return (loc or "registry"), (body if loc else "")


def parse_yarn_lock(rel: str, text: str) -> Parsed:
    out: list[LockEntry] = []
    cur: dict[str, Any] | None = None

    def flush() -> None:
        if cur is None or cur["name"] in ("__metadata", ""):
            return
        resolved, kind = cur.get("resolved", ""), "registry"
        if resolved:
            kind = classify_location(resolved) or "registry"
        elif cur.get("resolution"):
            kind, resolved = _berry_resolution(cur["resolution"])
        out.append(LockEntry("npm", cur["name"].lower(), cur.get("version", ""), resolved,
                             cur.get("integrity", "") or cur.get("checksum", ""), rel, cur["line"], kind))

    for i, raw in enumerate(text.split("\n"), 1):
        line = raw.rstrip("\r")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace() and line.rstrip().endswith(":"):
            flush()
            first = line.rstrip()[:-1].split(",")[0]
            cur = {"name": _yarn_name(first), "line": i}
            continue
        if cur is None:
            continue
        m = re.match(r"^\s{2,4}(version|resolved|integrity|resolution|checksum|linkType):?\s+\"?([^\"]*)\"?\s*$", line)
        if m:
            cur.setdefault(m.group(1), m.group(2).strip())
    flush()
    return Parsed(locks=tuple(out))


_PNPM_FIELD_RE = {k: re.compile(rf"\b{k}:\s*['\"]?([^,'\"}}\s]+)") for k in ("integrity", "tarball", "repo", "commit")}


_PNPM_V5_KEY = re.compile(r"^((?:@[^/@]+/)?[^/@]+)/(\d[^_/(]*)")  # /name/1.0.0_peer
_PNPM_V6_KEY = re.compile(r"^((?:@[^/@]+/)?[^/@]+)@([^(]*)")  # /name@1.0.0(peer) or name@1.0.0


def _pnpm_key(key: str) -> tuple[str, str]:
    k = key.strip().rstrip(":").strip().strip("'\"").lstrip("/")
    m = _PNPM_V5_KEY.match(k) or _PNPM_V6_KEY.match(k)
    return (m.group(1), m.group(2)) if m else (k, "")


def parse_pnpm_lock(rel: str, text: str) -> Parsed:
    out: list[LockEntry] = []
    raw_lines = [ln.rstrip("\r") for ln in text.split("\n")]
    in_packages = False
    entry: dict[str, Any] | None = None

    def flush() -> None:
        if entry is None:
            return
        body = entry["body"]
        vals = {k: (r.search(body).group(1) if r.search(body) else "") for k, r in _PNPM_FIELD_RE.items()}
        resolved, kind = vals["tarball"], "registry"
        if resolved:
            kind = classify_location(resolved) or "url"
        if vals["repo"] or re.search(r"\btype:\s*git\b", body):
            resolved, kind = vals["repo"] or resolved, "git"
        if re.search(r"\bdirectory:", body):
            kind = "path"
        out.append(LockEntry("npm", entry["name"].lower(), entry["version"], resolved, vals["integrity"],
                             rel, entry["line"], kind))

    for i, line in enumerate(raw_lines, 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0:
            flush()
            entry = None
            in_packages = line.startswith("packages:")
            continue
        if not in_packages:
            continue
        if indent == 2 and line.rstrip().endswith(":"):
            flush()
            name, ver = _pnpm_key(line)
            entry = {"name": name, "version": ver, "line": i, "body": ""}
        elif entry is not None:
            entry["body"] += line.strip() + "\n"
    flush()
    return Parsed(locks=tuple(out))


# ---------------------------------------------------------------------------- python

_REQ_RE = re.compile(r"^\s*([A-Za-z0-9](?:[A-Za-z0-9._-]{0,200}[A-Za-z0-9])?)\s*(\[[^\]]{0,200}\])?\s*(.*)$")
_EGG_RE = re.compile(r"[#&]egg=([A-Za-z0-9][A-Za-z0-9._-]*)")
_WHEEL_RE = re.compile(r"/([A-Za-z0-9][A-Za-z0-9._]*?)-\d[^/]*\.(?:whl|tar\.gz|zip|tgz)(?:[#?].*)?$", re.I)


def parse_pep508(req: str) -> tuple[str, str, str, str] | None:
    """(name, version_spec, kind, url) for a PEP 508 string, or None if unparseable."""
    req = req.strip()
    if not req:
        return None
    loc = classify_location(req)
    if loc:
        m = _EGG_RE.search(req) or _WHEEL_RE.search(req)
        name = m.group(1) if m else ""
        return name, "", loc, req
    m = _REQ_RE.match(req)
    if not m:
        return None
    name, rest = m.group(1), m.group(3).strip()
    if rest.startswith("@"):
        url = rest[1:].split(";", 1)[0].strip()
        return name, "", classify_location(url) or "url", url
    spec = rest.split(";", 1)[0].strip().strip("()").strip()
    return name, spec, "registry", ""


def _logical_lines(text: str) -> Iterable[tuple[int, str]]:
    buf, start = "", 0
    for i, raw in enumerate(text.split("\n"), 1):
        line = raw.rstrip("\r")
        if not buf:
            start = i
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        yield start, buf + line
        buf = ""
    if buf:
        yield start, buf


_OPT_SOURCE = {
    "-i": "index-url", "--index-url": "index-url", "--extra-index-url": "extra-index-url",
    "--trusted-host": "trusted-host", "-f": "find-links", "--find-links": "find-links",
}
_OPT_INCLUDE = ("-r", "--requirement", "-c", "--constraint")


def parse_requirements(rel: str, text: str) -> Parsed:
    deps: list[Dep] = []
    sources: list[SourceConfig] = []
    includes: list[str] = []
    for n, line in _logical_lines(text):
        stripped = re.sub(r"(^|\s)#.*$", "", line).strip()
        if not stripped:
            continue
        m = re.match(r"^(--?[A-Za-z-]+)(?:\s*=\s*|\s+|(?<=^-[irfce])(?=\S))(\S+)", stripped)
        if m and m.group(1) in _OPT_SOURCE:
            sources.append(SourceConfig("pypi", _OPT_SOURCE[m.group(1)], m.group(2), rel, n, stripped))
            continue
        if m and m.group(1) in _OPT_INCLUDE:
            includes.append(m.group(2))
            continue
        if m and m.group(1) in ("-e", "--editable"):
            target = m.group(2)
            parsed = parse_pep508(target)
            if parsed:
                name, _spec, kind, url = parsed
                deps.append(Dep("pypi", normalize("pypi", name) if name else "", "", rel, n,
                                url or target, kind if kind != "registry" else "path", "editable"))
            continue
        if stripped.startswith("-"):
            continue  # --hash, --pre, --no-binary ...
        req = re.split(r"\s+--?[a-z]", stripped, maxsplit=1)[0]
        parsed = parse_pep508(req)
        if not parsed:
            continue
        name, spec, kind, url = parsed
        deps.append(Dep("pypi", normalize("pypi", name) if name else "", spec, rel, n, url, kind))
    return Parsed(deps=tuple(deps), sources=tuple(sources), includes=tuple(includes))


def _pep508_deps(items: Iterable[Any], rel: str, lines: _Lines, section: str) -> list[Dep]:
    out: list[Dep] = []
    for item in items:
        if not isinstance(item, str):
            continue
        parsed = parse_pep508(item)
        if not parsed or not parsed[0]:
            continue
        name, spec, kind, url = parsed
        out.append(Dep("pypi", normalize("pypi", name), spec, rel, lines.name_line(name), url, kind, section))
    return out


def _poetry_dep(name: str, value: Any, rel: str, lines: _Lines, section: str) -> Dep | None:
    if name.lower() == "python":
        return None
    if isinstance(value, list):
        value = value[0] if value else ""
    spec, kind, url = "", "registry", ""
    if isinstance(value, str):
        spec = value
    elif isinstance(value, dict):
        spec = _s(value.get("version"))
        for key in ("git", "url", "path"):
            if isinstance(value.get(key), str):
                kind, url = ("path" if key == "path" else classify_location(value[key]) or key), value[key]
                break
        else:
            if isinstance(value.get("source"), str):
                kind, url = "alt-registry", value["source"]
    return Dep("pypi", normalize("pypi", name), spec, rel, lines.name_line(name), url, kind, section)


def parse_pyproject(rel: str, text: str) -> Parsed:
    data = _load_toml(text)
    if not data:
        return EMPTY
    lines = _Lines(text)
    deps: list[Dep] = []
    sources: list[SourceConfig] = []
    own: list[tuple[str, str]] = []
    project = _d(data.get("project"))
    if _s(project.get("name")):
        own.append(("pypi", normalize("pypi", project["name"])))
    deps += _pep508_deps(_l(project.get("dependencies")), rel, lines, "project.dependencies")
    for grp, items in _d(project.get("optional-dependencies")).items():
        deps += _pep508_deps(_l(items), rel, lines, f"project.optional-dependencies.{grp}")
    for grp, items in _d(data.get("dependency-groups")).items():
        deps += _pep508_deps(_l(items), rel, lines, f"dependency-groups.{grp}")
    deps += _pep508_deps(_l(_d(data.get("build-system")).get("requires")), rel, lines, "build-system.requires")

    tool = _d(data.get("tool"))
    poetry = _d(tool.get("poetry"))
    if _s(poetry.get("name")):
        own.append(("pypi", normalize("pypi", poetry["name"])))
    groups: list[tuple[str, dict[str, Any]]] = [
        ("tool.poetry.dependencies", _d(poetry.get("dependencies"))),
        ("tool.poetry.dev-dependencies", _d(poetry.get("dev-dependencies"))),
    ]
    groups += [(f"tool.poetry.group.{g}", _d(_d(v).get("dependencies"))) for g, v in _d(poetry.get("group")).items()]
    for section, block in groups:
        for name, value in block.items():
            dep = _poetry_dep(str(name), value, rel, lines, section)
            if dep:
                deps.append(dep)
    for src in _l(poetry.get("source")):
        src = _d(src)
        if _s(src.get("url")):
            sources.append(SourceConfig("pypi", "poetry-source", src["url"], rel, lines.find(src["url"])[0],
                                        f"{_s(src.get('name'))} priority={_s(src.get('priority')) or 'primary'}"))

    uv = _d(tool.get("uv"))
    sources += _uv_sources(uv, rel, lines)
    deps += _pep508_deps(_l(uv.get("dev-dependencies")), rel, lines, "tool.uv.dev-dependencies")
    for name, value in _d(uv.get("sources")).items():
        value = _d(value)
        for key in ("git", "url", "path"):
            if _s(value.get(key)):
                kind = "path" if key == "path" else (classify_location(value[key]) or key)
                deps.append(Dep("pypi", normalize("pypi", str(name)), "", rel, lines.name_line(str(name)),
                                value[key], kind, "tool.uv.sources"))
                break
    for src in _l(_d(tool.get("pdm")).get("source")):
        src = _d(src)
        if _s(src.get("url")):
            sources.append(SourceConfig("pypi", "pdm-source", src["url"], rel, lines.find(src["url"])[0],
                                        _s(src.get("name"))))
    return Parsed(deps=tuple(deps), sources=tuple(sources), own_names=tuple(own))


def _uv_sources(uv: dict[str, Any], rel: str, lines: _Lines) -> list[SourceConfig]:
    out: list[SourceConfig] = []
    for cfg in (uv, _d(uv.get("pip"))):
        if _s(cfg.get("index-url")):
            out.append(SourceConfig("pypi", "index-url", cfg["index-url"], rel, lines.find(cfg["index-url"])[0]))
        extra = cfg.get("extra-index-url")
        for url in ([extra] if isinstance(extra, str) else _l(extra)):
            if isinstance(url, str):
                out.append(SourceConfig("pypi", "extra-index-url", url, rel, lines.find(url)[0]))
        links = cfg.get("find-links")
        for url in ([links] if isinstance(links, str) else _l(links)):
            if isinstance(url, str):
                out.append(SourceConfig("pypi", "find-links", url, rel, lines.find(url)[0]))
    for idx in _l(uv.get("index")):
        idx = _d(idx)
        if _s(idx.get("url")):
            flags = " ".join(k for k in ("default", "explicit") if idx.get(k) is True)
            out.append(SourceConfig("pypi", "uv-index", idx["url"], rel, lines.find(idx["url"])[0],
                                    f"{_s(idx.get('name'))} {flags}".strip()))
    return out


def parse_uv_toml(rel: str, text: str) -> Parsed:
    data = _load_toml(text)
    return Parsed(sources=tuple(_uv_sources(data, rel, _Lines(text)))) if data else EMPTY


def parse_pipfile(rel: str, text: str) -> Parsed:
    data = _load_toml(text)
    if not data:
        return EMPTY
    lines = _Lines(text)
    sources = [
        SourceConfig("pypi", "pipfile-source", s["url"], rel, lines.find(s["url"])[0],
                     f"{_s(s.get('name'))} verify_ssl={s.get('verify_ssl', True)}")
        for s in map(_d, _l(data.get("source"))) if _s(s.get("url"))
    ]
    deps: list[Dep] = []
    for section in ("packages", "dev-packages"):
        for name, value in _d(data.get(section)).items():
            spec, kind, url = "", "registry", ""
            if isinstance(value, str):
                spec = value
            elif isinstance(value, dict):
                spec = _s(value.get("version"))
                for key in ("git", "file", "path"):
                    if _s(value.get(key)):
                        kind, url = ("path" if key == "path" else classify_location(value[key]) or "url"), value[key]
                        break
                else:
                    if _s(value.get("index")):
                        kind, url = "alt-registry", value["index"]
            deps.append(Dep("pypi", normalize("pypi", str(name)), spec, rel, lines.name_line(str(name)), url, kind, section))
    return Parsed(deps=tuple(deps), sources=tuple(sources))


def _ast_str_list(node: ast.AST | None, names: dict[str, ast.AST]) -> list[tuple[str, int]]:
    if isinstance(node, ast.Name) and node.id in names:
        node = names[node.id]
    out: list[tuple[str, int]] = []
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        for elt in node.elts:
            val = pyast.const_str(elt)
            if val is not None:
                out.append((val, getattr(elt, "lineno", 0)))
    elif node is not None:
        val = pyast.const_str(node)
        if val is not None:
            out += [(ln.strip(), getattr(node, "lineno", 0)) for ln in val.splitlines() if ln.strip()]
    return out


def parse_setup_py(rel: str, text: str) -> Parsed:
    """install_requires & co. from setup.py via static AST (literal values only; never executed)."""
    tree = pyast.parse(FileContext.from_text(rel, text))
    if tree is None:
        return EMPTY
    names: dict[str, ast.AST] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            names[node.targets[0].id] = node.value
    deps: list[Dep] = []
    sources: list[SourceConfig] = []
    own: list[tuple[str, str]] = []
    for call in pyast.iter_calls(tree):
        cname = pyast.call_name(call) or ""
        if cname.rsplit(".", 1)[-1] != "setup":
            continue
        for kw in call.keywords:
            if kw.arg == "name":
                val = pyast.const_str(kw.value)
                if val:
                    own.append(("pypi", normalize("pypi", val)))
            elif kw.arg in ("install_requires", "setup_requires", "tests_require"):
                items = _ast_str_list(kw.value, names)
                deps += _setup_deps(items, rel, kw.arg)
            elif kw.arg == "extras_require":
                value = names.get(kw.value.id, kw.value) if isinstance(kw.value, ast.Name) else kw.value
                if isinstance(value, ast.Dict):
                    for key, val in zip(value.keys, value.values):
                        deps += _setup_deps(_ast_str_list(val, names), rel, f"extras_require.{pyast.const_str(key) if key else ''}")
            elif kw.arg == "dependency_links":
                for url, ln in _ast_str_list(kw.value, names):
                    sources.append(SourceConfig("pypi", "dependency-link", url, rel, ln or None, url))
    return Parsed(deps=tuple(deps), sources=tuple(sources), own_names=tuple(own))


def _setup_deps(items: list[tuple[str, int]], rel: str, section: str) -> list[Dep]:
    out: list[Dep] = []
    for req, ln in items:
        parsed = parse_pep508(req)
        if parsed and parsed[0]:
            name, spec, kind, url = parsed
            out.append(Dep("pypi", normalize("pypi", name), spec, rel, ln or None, url, kind, section))
    return out


def parse_pip_conf(rel: str, text: str) -> Parsed:
    out: list[SourceConfig] = []
    current: str | None = None
    for i, raw in enumerate(text.split("\n"), 1):
        line = raw.rstrip("\r")
        if not line.strip() or line.lstrip().startswith(("#", ";")):
            continue
        m = re.match(r"^(index-url|extra-index-url|trusted-host|find-links)\s*[=:]\s*(.*)$", line.strip(), re.I)
        if m and not line[0].isspace():
            current = m.group(1).lower()
            for val in m.group(2).split():
                out.append(SourceConfig("pypi", current, val, rel, i, line.strip()))
            continue
        if line[0].isspace() and current:
            for val in line.split():
                out.append(SourceConfig("pypi", current, val, rel, i, line.strip()))
            continue
        current = None
    return Parsed(sources=tuple(out))


def _toml_lock(rel: str, text: str, ecosystem: str) -> Parsed:
    """poetry.lock / uv.lock / Cargo.lock [[package]] tables."""
    data = _load_toml(text)
    lines = _Lines(text)
    out: list[LockEntry] = []
    pos = 0
    for pkg in map(_d, _l(data.get("package"))):
        name = _s(pkg.get("name"))
        if not name:
            continue
        line, pos = lines.find(f'name = "{name}"', pos)
        version = _s(pkg.get("version"))
        resolved, integrity, kind = "", "", "registry"
        src = pkg.get("source")
        if ecosystem == "cargo":
            resolved, integrity = _s(src), _s(pkg.get("checksum"))
            if resolved.startswith("git+"):
                kind = "git"
            elif not resolved:
                kind = "path"
        elif isinstance(src, dict):  # poetry: {type, url, reference}; uv: {registry|git|url|path|editable|...}
            if "type" in src:
                stype = _s(src.get("type"))
                resolved = _s(src.get("url"))
                kind = {"git": "git", "url": "url", "file": "path", "directory": "path", "legacy": "registry"}.get(stype, "registry")
            else:
                for key in ("registry", "git", "url", "path", "editable", "directory", "virtual"):
                    if _s(src.get(key)):
                        resolved = src[key]
                        kind = {"registry": "registry", "git": "git", "url": "url"}.get(key, "path")
                        break
            integrity = "files" if pkg.get("files") or pkg.get("wheels") or pkg.get("sdist") else ""
        out.append(LockEntry(ecosystem, normalize(ecosystem, name), version, resolved, integrity, rel, line, kind))
    return Parsed(locks=tuple(out))


# ---------------------------------------------------------------------------- other ecosystems


def parse_cargo_toml(rel: str, text: str) -> Parsed:
    data = _load_toml(text)
    if not data:
        return EMPTY
    lines = _Lines(text)
    own = [("cargo", _s(_d(data.get("package")).get("name")).lower())] if _s(_d(data.get("package")).get("name")) else []
    blocks: list[tuple[str, dict[str, Any]]] = []
    for sec in ("dependencies", "dev-dependencies", "build-dependencies"):
        blocks.append((sec, _d(data.get(sec))))
        for target, tdata in _d(data.get("target")).items():
            blocks.append((f"target.{target}.{sec}", _d(_d(tdata).get(sec))))
    blocks.append(("workspace.dependencies", _d(_d(data.get("workspace")).get("dependencies"))))
    deps: list[Dep] = []
    for section, block in blocks:
        for key, value in block.items():
            name, spec, kind, url = str(key), "", "registry", ""
            if isinstance(value, str):
                spec = value
            elif isinstance(value, dict):
                spec = _s(value.get("version"))
                name = _s(value.get("package")) or name
                if _s(value.get("git")):
                    kind, url = "git", value["git"]
                elif _s(value.get("path")):
                    kind, url = "path", value["path"]
                elif _s(value.get("registry")) or _s(value.get("registry-index")):
                    kind, url = "alt-registry", _s(value.get("registry")) or _s(value.get("registry-index"))
                elif value.get("workspace") is True:
                    kind = "workspace"
            deps.append(Dep("cargo", name.lower(), spec, rel, lines.name_line(str(key)), url, kind, section))
    return Parsed(deps=tuple(deps), own_names=tuple(own))


def parse_cargo_config(rel: str, text: str) -> Parsed:
    data = _load_toml(text)
    if not data:
        return EMPTY
    lines = _Lines(text)
    out: list[SourceConfig] = []
    srcs = _d(data.get("source"))
    for name, cfg in srcs.items():
        cfg = _d(cfg)
        target = _s(cfg.get("replace-with"))
        if target:
            tcfg = _d(srcs.get(target))
            loc = _s(tcfg.get("registry")) or _s(tcfg.get("local-registry")) or _s(tcfg.get("directory")) or target
            out.append(SourceConfig("cargo", "replace-with", loc, rel, lines.find("replace-with")[0],
                                    f"source.{name}.replace-with = {target}"))
    for name, cfg in _d(data.get("registries")).items():
        idx = _s(_d(cfg).get("index"))
        if idx:
            out.append(SourceConfig("cargo", "cargo-registry", idx, rel, lines.find(idx)[0], f"registries.{name}"))
    return Parsed(sources=tuple(out))


def parse_go_mod(rel: str, text: str) -> Parsed:
    deps: list[Dep] = []
    own: list[tuple[str, str]] = []
    block: str | None = None
    for i, raw in enumerate(text.split("\n"), 1):
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if line == ")":
            block = None
            continue
        m = re.match(r"^(module|require|replace)\s*\(\s*$", line)
        if m:
            block = m.group(1)
            continue
        m = re.match(r"^(module|require|replace)\s+(.+)$", line)
        verb, body = (m.group(1), m.group(2)) if m else (block, line)
        if verb == "module":
            own.append(("go", body.strip().strip('"').lower()))
        elif verb == "require":
            parts = body.split()
            if parts:
                deps.append(Dep("go", parts[0].lower(), parts[1] if len(parts) > 1 else "", rel, i))
        elif verb == "replace" and "=>" in body:
            left, right = (s.split() for s in body.split("=>", 1))
            if left and right:
                target = right[0]
                kind = "path" if classify_location(target) == "path" or target.startswith(".") else "replace"
                deps.append(Dep("go", left[0].lower(), right[1] if len(right) > 1 else "", rel, i,
                                " ".join(right), kind, "replace"))
    return Parsed(deps=tuple(deps), own_names=tuple(own))


def parse_gemfile(rel: str, text: str) -> Parsed:
    deps: list[Dep] = []
    sources: list[SourceConfig] = []
    for i, raw in enumerate(text.split("\n"), 1):
        line = raw.split("#", 1)[0].rstrip() if not re.search(r"['\"][^'\"]*#", raw) else raw.rstrip()
        m = re.match(r"^\s*source\s+['\"]([^'\"]+)['\"]", line)
        if m:
            sources.append(SourceConfig("rubygems", "gem-source", m.group(1), rel, i, line.strip()))
            continue
        m = re.match(r"^\s*gem\s+['\"]([A-Za-z0-9_.-]+)['\"](.*)$", line)
        if not m:
            continue
        name, rest = m.group(1), m.group(2)
        specs = re.findall(r",\s*['\"]([^'\"]*)['\"]", rest.split(":", 1)[0] if re.search(r"\w+:", rest) else rest)
        kind, url = "registry", ""
        km = re.search(r"(?::?(git|github|path|source)\s*(?::|=>)\s*)['\"]([^'\"]+)['\"]", rest)
        if km:
            key = km.group(1)
            kind = {"git": "git", "github": "git", "path": "path", "source": "alt-registry"}[key]
            url = km.group(2)
        deps.append(Dep("rubygems", name.lower(), ", ".join(specs), rel, i, url, kind))
    return Parsed(deps=tuple(deps), sources=tuple(sources))


def parse_composer_json(rel: str, text: str) -> Parsed:
    data = _load_json(text)
    if not isinstance(data, dict):
        return EMPTY
    lines = _Lines(text)
    own = [("packagist", data["name"].lower())] if _s(data.get("name")) else []
    deps: list[Dep] = []
    for section in ("require", "require-dev"):
        _ln, sec_pos = lines.find(f'"{section}"')
        for name, spec in _d(data.get(section)).items():
            n = str(name).lower()
            if n in ("php", "composer-plugin-api", "composer-runtime-api", "hhvm") or n.startswith(("ext-", "lib-")):
                continue
            deps.append(Dep("packagist", n, _s(spec), rel, lines.find(f'"{name}"', sec_pos)[0], "", "registry", section))
    sources: list[SourceConfig] = []
    repos = data.get("repositories")
    for repo in (repos.values() if isinstance(repos, dict) else _l(repos)):
        repo = _d(repo)
        if _s(repo.get("url")):
            sources.append(SourceConfig("packagist", "composer-repo", repo["url"], rel, lines.find(repo["url"])[0],
                                        _s(repo.get("type"))))
    return Parsed(deps=tuple(deps), sources=tuple(sources), own_names=tuple(own))


def parse_npmrc(rel: str, text: str) -> Parsed:
    out: list[SourceConfig] = []
    for i, raw in enumerate(text.split("\n"), 1):
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        m = re.match(r"^(@[\w.~-]+):registry\s*=\s*[\"']?([^\"'\s]+)", line, re.I)
        if m:
            out.append(SourceConfig("npm", "scoped-registry", m.group(2), rel, i, line, m.group(1).lower()))
            continue
        m = re.match(r"^registry\s*=\s*[\"']?([^\"'\s]+)", line, re.I)
        if m:
            out.append(SourceConfig("npm", "registry", m.group(1), rel, i, line))
            continue
        if re.match(r"^strict-ssl\s*=\s*false\b", line, re.I):
            out.append(SourceConfig("npm", "strict-ssl-off", "", rel, i, line))
    return Parsed(sources=tuple(out))


def parse_yarnrc(rel: str, text: str) -> Parsed:
    """Both classic .yarnrc (`registry "url"`) and berry .yarnrc.yml (`npmRegistryServer: url`)."""
    out: list[SourceConfig] = []
    scope = ""
    for i, raw in enumerate(text.split("\n"), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^[\"']?(@?[\w.~-]+)[\"']?:\s*$", line)
        if m and raw.startswith("  "):
            scope = "@" + m.group(1).lstrip("@")
            continue
        m = re.match(r"^npmRegistryServer:\s*[\"']?([^\"'\s]+)", line)
        if m:
            indented = raw[:1].isspace()
            out.append(SourceConfig("npm", "scoped-registry" if indented and scope else "registry", m.group(1),
                                    rel, i, line, scope if indented else ""))
            continue
        m = re.match(r"^[\"']?(@[\w.~-]+):registry[\"']?\s+[\"']?([^\"'\s]+)", line)
        if m:
            out.append(SourceConfig("npm", "scoped-registry", m.group(2), rel, i, line, m.group(1).lower()))
            continue
        m = re.match(r"^registry\s+[\"']?([^\"'\s]+)", line)
        if m:
            out.append(SourceConfig("npm", "registry", m.group(1), rel, i, line))
            continue
        if re.match(r"^(strict-ssl\s+false|enableStrictSsl:\s*false)\b", line):
            out.append(SourceConfig("npm", "strict-ssl-off", "", rel, i, line))
        if not raw[:1].isspace():
            scope = ""
    return Parsed(sources=tuple(out))


def parse_nuget_config(rel: str, text: str) -> Parsed:
    out: list[SourceConfig] = []
    lines = _Lines(text)
    for sec in re.finditer(r"(?is)<packageSources>(.{0,200000}?)</packageSources>", text):
        for tag in re.finditer(r"(?is)<add\b[^>]{0,1000}>", sec.group(1)):
            vm = re.search(r"(?i)\bvalue\s*=\s*[\"']([^\"']+)[\"']", tag.group(0))
            km = re.search(r"(?i)\bkey\s*=\s*[\"']([^\"']*)[\"']", tag.group(0))
            if vm:
                out.append(SourceConfig("nuget", "nuget-source", vm.group(1), rel,
                                        lines.line_of(sec.start(1) + tag.start()), km.group(1) if km else ""))
    return Parsed(sources=tuple(out))


# ---------------------------------------------------------------------------- dispatch

_BY_NAME: dict[str, Callable[[str, str], Parsed]] = {
    "package.json": parse_package_json,
    "package-lock.json": parse_package_lock,
    "npm-shrinkwrap.json": parse_package_lock,
    "yarn.lock": parse_yarn_lock,
    "pnpm-lock.yaml": parse_pnpm_lock,
    "pyproject.toml": parse_pyproject,
    "pipfile": parse_pipfile,
    "setup.py": parse_setup_py,
    "poetry.lock": lambda r, t: _toml_lock(r, t, "pypi"),
    "uv.lock": lambda r, t: _toml_lock(r, t, "pypi"),
    "cargo.toml": parse_cargo_toml,
    "cargo.lock": lambda r, t: _toml_lock(r, t, "cargo"),
    "go.mod": parse_go_mod,
    "gemfile": parse_gemfile,
    "composer.json": parse_composer_json,
    ".npmrc": parse_npmrc,
    ".yarnrc": parse_yarnrc,
    ".yarnrc.yml": parse_yarnrc,
    "pip.conf": parse_pip_conf,
    "pip.ini": parse_pip_conf,
    "uv.toml": parse_uv_toml,
    "nuget.config": parse_nuget_config,
}
_REQ_FILE_RE = re.compile(r"(^|/)(?:[^/]*requirements[^/]*\.(?:txt|in)|constraints[^/]*\.txt|requirements/[^/]+\.(?:txt|in))$")
_SKIP_TREE_RE = re.compile(r"(^|/)(node_modules|site-packages)/")
LOCKFILE_NAMES = frozenset({"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
                            "bun.lockb", "bun.lock"})


def parser_for(rel_path: str) -> Callable[[str, str], Parsed] | None:
    rl = rel_path.replace("\\", "/").lower()
    base = rl.rsplit("/", 1)[-1]
    if base in _BY_NAME:
        return _BY_NAME[base]
    if rl.endswith((".cargo/config.toml", ".cargo/config")) or rl in ("cargo/config.toml",):
        return parse_cargo_config
    if _REQ_FILE_RE.search(rl):
        return parse_requirements
    return None


def parse_file(rel_path: str, text: str) -> Parsed:
    parser = parser_for(rel_path)
    if parser is None:
        return EMPTY
    try:
        return parser(rel_path, text)
    except (ValueError, TypeError, KeyError, AttributeError, IndexError, RecursionError):
        return EMPTY


@dataclass(frozen=True)
class RepoDeps:
    parsed: Parsed
    manifests: tuple[str, ...]
    lockfile_dirs: frozenset[str] = field(default_factory=frozenset)


def parse_repo(files: Iterable[FileContext], get: Callable[[str], FileContext | None] | None = None) -> RepoDeps:
    """Parse every manifest/lockfile/config in the repo (skipping committed node_modules/site-packages)."""
    total = EMPTY
    seen: set[str] = set()
    manifests: list[str] = []
    lock_dirs: set[str] = set()
    pending: list[FileContext] = []
    for ctx in files:
        if ctx.is_binary or _SKIP_TREE_RE.search(ctx.rel_lower):
            continue
        if ctx.basename.lower() in LOCKFILE_NAMES:
            lock_dirs.add(ctx.rel_path.rpartition("/")[0])
        if parser_for(ctx.rel_path):
            pending.append(ctx)
    depth = 0
    while pending and depth < 6:
        nxt: list[FileContext] = []
        for ctx in pending:
            if ctx.rel_path in seen:
                continue
            seen.add(ctx.rel_path)
            parser = parser_for(ctx.rel_path) or parse_requirements
            try:
                parsed = parser(ctx.rel_path, ctx.text)
            except (ValueError, TypeError, KeyError, AttributeError, IndexError, RecursionError):
                parsed = EMPTY
            manifests.append(ctx.rel_path)
            total = total.merge(Parsed(parsed.deps, parsed.locks, parsed.sources, parsed.own_names))
            if get is not None:
                base_dir = ctx.rel_path.rpartition("/")[0]
                for inc in parsed.includes:
                    target = _join(base_dir, inc)
                    inc_ctx = get(target) if target else None
                    if inc_ctx is not None and inc_ctx.rel_path not in seen and not inc_ctx.is_binary:
                        nxt.append(inc_ctx)
        pending = nxt
        depth += 1
    return RepoDeps(total, tuple(manifests), frozenset(lock_dirs))


def _join(base_dir: str, rel: str) -> str | None:
    parts = [p for p in base_dir.split("/") if p] + [p for p in rel.replace("\\", "/").split("/") if p]
    out: list[str] = []
    for p in parts:
        if p == ".":
            continue
        if p == "..":
            if not out:
                return None
            out.pop()
        else:
            out.append(p)
    return "/".join(out) or None
