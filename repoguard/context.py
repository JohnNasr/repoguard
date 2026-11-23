"""Per-file and per-repo context objects handed to detectors."""

from __future__ import annotations

import bisect
import fnmatch
import math
import re
import time
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from .models import ScanOptions

if TYPE_CHECKING:
    from .net import NetClient

HEAD_BYTES = 64 * 1024

_TEST_DIR_RE = re.compile(
    r"(^|/)(tests?|__tests__|__mocks__|spec|specs|testdata|test_data|testing|fixtures?|examples?|samples?)(/|$)",
    re.I,
)
_TEST_FILE_RE = re.compile(
    r"(^|/)(test_[^/]*\.py|[^/]*_test\.(py|go|rs)|[^/]*\.(test|spec)\.[cm]?[jt]sx?|[^/]*Test\.java|conftest\.py)$"
)
_VENDOR_RE = re.compile(
    r"(^|/)(node_modules|vendor|vendors|third_party|thirdparty|bower_components|site-packages|external|deps)(/|$)"
    r"|\.min\.(js|css|mjs)$|\.bundle\.js$|-bundle\.js$",
    re.I,
)
_DOC_EXT = frozenset({".md", ".markdown", ".rst", ".txt", ".adoc", ".textile", ".org"})
_DOC_DIR_RE = re.compile(r"(^|/)(docs?|documentation|man)(/|$)", re.I)

_INSTALL_HOOK_NAMES = frozenset(
    {
        "package.json", "setup.py", "setup.cfg", "pyproject.toml", "build.rs", "makefile", "gnumakefile",
        "binding.gyp", "composer.json", "gemfile", "rakefile", "cmakelists.txt", "install.sh", "setup.sh",
        "install.ps1", "setup.ps1", "install.bat", "setup.bat", "install.cmd", "bootstrap.sh", "configure",
        "dockerfile", "docker-compose.yml", "docker-compose.yaml", "justfile", "taskfile.yml", "build.gradle",
        "build.gradle.kts", "pom.xml", "meson.build", ".npmrc", ".yarnrc", ".yarnrc.yml", "pip.conf",
        "requirements.txt", "conftest.py", "noxfile.py", "tox.ini", "hatch_build.py", "build.py",
        "deno.json", "bunfig.toml", ".pnpmfile.cjs", "pnpm-workspace.yaml", "cargo.toml",
    }
)
_INSTALL_HOOK_GLOBS = (
    ".vscode/*", ".devcontainer/*", ".devcontainer/**/*", ".idea/runConfigurations/*", ".idea/workspace.xml",
    "*.gemspec", "*.csproj", "*.vcxproj", "*.sln", "directory.build.props", "directory.build.targets",
    ".husky/*", ".githooks/*", ".git-hooks/*", "hooks/*", "*.nuspec", "tools/install.ps1", "tools/init.ps1",
    ".envrc", ".tool-versions", "mise.toml", ".mise.toml",
)
_AI_CONFIG_NAMES = frozenset(
    {
        "claude.md", "claude.local.md", "agents.md", "agent.md", "gemini.md", ".cursorrules", ".windsurfrules",
        ".clinerules", ".mcp.json", "mcp.json", ".roorules", ".goosehints", "copilot-instructions.md",
        "conventions.md", ".aider.conf.yml", "skill.md",
    }
)
_AI_CONFIG_GLOBS = (
    ".claude/*", ".claude/**/*", ".cursor/*", ".cursor/**/*", ".github/copilot-instructions.md",
    ".github/instructions/*", ".github/prompts/*", ".clinerules/*", ".windsurf/*", ".roo/*", ".kiro/*",
    ".continue/*", ".gemini/*", ".codex/*", ".vscode/mcp.json", "*.prompt.md", "*.instructions.md",
    "skills/*/skill.md", ".claude-plugin/*",
    # the same tool folders nested deeper (monorepos, plugin bundles)
    "*/.claude/*", "*/.cursor/*", "*/.claude-plugin/*", "*/.windsurf/*", "*/.roo/*", "*/.kiro/*",
    "*/.gemini/*", "*/.codex/*", "*/.continue/*", "*/.clinerules/*", "*/skills/*/skill.md",
)
_README_EXT = frozenset({"", ".md", ".markdown", ".rst", ".txt", ".adoc", ".org"})
_CI_GLOBS = (
    ".github/workflows/*.yml", ".github/workflows/*.yaml", ".github/actions/*/action.yml",
    ".github/actions/*/action.yaml", "action.yml", "action.yaml", ".gitlab-ci.yml", ".circleci/*",
    "azure-pipelines.yml", "jenkinsfile", ".travis.yml", "bitbucket-pipelines.yml", ".drone.yml",
    "appveyor.yml", ".buildkite/*", "cloudbuild.yaml", "cloudbuild.yml",
)

_LANG_BY_EXT = {
    ".py": "python", ".pyw": "python", ".pyi": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell", ".ksh": "shell", ".fish": "shell",
    ".ps1": "powershell", ".psm1": "powershell", ".psd1": "powershell",
    ".bat": "batch", ".cmd": "batch",
    ".vbs": "vbscript", ".vbe": "vbscript", ".wsf": "vbscript", ".hta": "html",
    ".rb": "ruby", ".go": "go", ".rs": "rust", ".java": "java", ".kt": "kotlin", ".kts": "kotlin",
    ".cs": "csharp", ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".hpp": "cpp", ".cxx": "cpp",
    ".php": "php", ".pl": "perl", ".pm": "perl", ".lua": "lua", ".swift": "swift", ".scala": "scala",
    ".json": "json", ".jsonc": "json", ".yml": "yaml", ".yaml": "yaml", ".toml": "toml",
    ".xml": "xml", ".html": "html", ".htm": "html", ".svg": "xml", ".md": "markdown",
    ".markdown": "markdown", ".rst": "rst", ".txt": "text", ".ini": "ini", ".cfg": "ini",
    ".gradle": "groovy", ".groovy": "groovy", ".dockerfile": "dockerfile", ".ipynb": "json",
    ".r": "r", ".dart": "dart", ".ex": "elixir", ".exs": "elixir", ".nim": "nim", ".zig": "zig",
}
_LANG_BY_NAME = {
    "makefile": "make", "gnumakefile": "make", "dockerfile": "dockerfile", "rakefile": "ruby",
    "gemfile": "ruby", "jenkinsfile": "groovy", "justfile": "make", "configure": "shell", ".envrc": "shell",
}
_SHEBANG_LANG = (
    ("python", "python"), ("node", "javascript"), ("deno", "typescript"), ("bun", "javascript"),
    ("bash", "shell"), ("/sh", "shell"), ("zsh", "shell"), ("pwsh", "powershell"), ("perl", "perl"),
    ("ruby", "ruby"), ("php", "php"),
)


def _match_any(rel_lower: str, globs: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatchcase(rel_lower, g) for g in globs)


def decode_bytes(data: bytes) -> tuple[str, str]:
    """Decode with BOM sniffing, then strict UTF-8, then latin-1 (never raises)."""
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", "replace"), "utf-8-sig"
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", "replace"), "utf-16"
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return data.decode("latin-1"), "latin-1"


class FileContext:
    """Lazily loaded view of one file. Never executes anything."""

    def __init__(
        self,
        path: Path | None,
        rel_path: str,
        size: int,
        is_binary: bool,
        *,
        truncated: bool = False,
        max_bytes: int = 2_000_000,
        text: str | None = None,
        head: bytes | None = None,
    ) -> None:
        self.path = path
        self.rel_path = rel_path.replace("\\", "/")
        self.size = size
        self.is_binary = is_binary
        self.truncated = truncated
        self.max_bytes = max_bytes
        self._preset_text = text
        self._preset_head = head
        self._deadline = math.inf

        rl = self.rel_path.lower()
        self.rel_lower = rl
        name = rl.rsplit("/", 1)[-1]
        self.basename = self.rel_path.rsplit("/", 1)[-1]
        ext = ("." + name.rsplit(".", 1)[-1]) if "." in name else ""
        self.ext = ext
        self.is_test = bool(_TEST_DIR_RE.search(rl) or _TEST_FILE_RE.search(self.rel_path))
        self.is_vendored = bool(_VENDOR_RE.search(rl))
        self.is_doc = ext in _DOC_EXT or (bool(_DOC_DIR_RE.search(rl)) and ext in {".html", ".htm", ""})
        self.is_install_hook = name in _INSTALL_HOOK_NAMES or _match_any(rl, _INSTALL_HOOK_GLOBS)
        self.is_ai_config = name in _AI_CONFIG_NAMES or _match_any(rl, _AI_CONFIG_GLOBS)
        self.is_ci = _match_any(rl, _CI_GLOBS)
        self.is_readme = ext in _README_EXT and name.startswith(
            ("readme", "install", "setup", "getting-started", "quickstart"))

    # ----- construction helpers -------------------------------------------------
    @classmethod
    def from_text(cls, rel_path: str, text: str) -> "FileContext":
        """In-memory context (used for git history and tests)."""
        data = text.encode("utf-8", "replace")
        return cls(None, rel_path, len(data), False, text=text, head=data[:HEAD_BYTES])

    # ----- lazy content ----------------------------------------------------------
    @cached_property
    def head(self) -> bytes:
        if self._preset_head is not None:
            return self._preset_head
        if self.path is None:
            return b""
        try:
            with open(self.path, "rb") as fh:
                return fh.read(HEAD_BYTES)
        except OSError:
            return b""

    @cached_property
    def raw(self) -> bytes:
        if self._preset_text is not None:
            return self._preset_text.encode("utf-8", "replace")
        if self.path is None:
            return b""
        if self.truncated:
            return self.head
        try:
            with open(self.path, "rb") as fh:
                return fh.read(self.max_bytes)
        except OSError:
            return b""

    @cached_property
    def _decoded(self) -> tuple[str, str]:
        if self._preset_text is not None:
            return self._preset_text, "utf-8"
        if self.is_binary:
            return "", "binary"
        return decode_bytes(self.raw)

    @property
    def text(self) -> str:
        return self._decoded[0]

    @property
    def encoding(self) -> str:
        return self._decoded[1]

    @cached_property
    def lines(self) -> tuple[str, ...]:
        return tuple(ln.rstrip("\r") for ln in self.text.split("\n"))

    @cached_property
    def lower(self) -> str:
        return self.text.lower()

    @cached_property
    def _line_starts(self) -> list[int]:
        starts = [0]
        starts.extend(m.end() for m in re.finditer("\n", self.text))
        return starts

    def line_of(self, offset: int) -> int:
        """1-based line number for a character offset in self.text."""
        return bisect.bisect_right(self._line_starts, offset)

    def line_text(self, line: int) -> str:
        if 1 <= line <= len(self.lines):
            return self.lines[line - 1]
        return ""

    @cached_property
    def language(self) -> str:
        name = self.basename.lower()
        if name in _LANG_BY_NAME:
            return _LANG_BY_NAME[name]
        if self.ext in _LANG_BY_EXT:
            return _LANG_BY_EXT[self.ext]
        if not self.is_binary and self.head.startswith(b"#!"):
            first = self.head.split(b"\n", 1)[0].decode("latin-1").lower()
            for needle, lang in _SHEBANG_LANG:
                if needle in first:
                    return lang
        return "unknown"

    @property
    def context_kind(self) -> str | None:
        """Location class used for score dampening. Hook/AI/CI files are never dampened."""
        if self.is_install_hook or self.is_ai_config or self.is_ci:
            return None
        if self.is_test:
            return "test"
        if self.is_vendored:
            return "vendored"
        if self.is_doc and not self.is_readme:
            return "doc"
        return None

    # ----- time budget -----------------------------------------------------------
    def start_deadline(self, seconds: float) -> None:
        self._deadline = time.monotonic() + seconds

    def deadline_exceeded(self) -> bool:
        return time.monotonic() > self._deadline

    def release(self) -> None:
        """Drop cached content to keep memory flat on big repos (re-read on demand)."""
        for attr in ("raw", "_decoded", "lines", "lower", "_line_starts"):
            self.__dict__.pop(attr, None)

    def __repr__(self) -> str:
        return f"FileContext({self.rel_path!r}, size={self.size}, binary={self.is_binary})"


SpecialKind = Literal[
    "symlink", "junction", "oversize", "unreadable", "reserved_name", "depth", "device", "nested_git",
    "submodule", "missing_checkout", "case_collision", "long_path",
]


@dataclass(frozen=True, slots=True)
class SpecialEntry:
    """Something the walker saw but did not (fully) read."""

    rel_path: str
    kind: SpecialKind
    detail: str = ""


@dataclass(frozen=True)
class RepoContext:
    root: Path
    target: str
    is_remote: bool
    commit: str | None
    files: tuple[FileContext, ...]
    special: tuple[SpecialEntry, ...]
    options: ScanOptions
    net: "NetClient"
    _index: dict[str, FileContext] = field(default_factory=dict, repr=False, compare=False)

    def __post_init__(self) -> None:
        self._index.update({f.rel_path: f for f in self.files})

    def get(self, rel_path: str) -> FileContext | None:
        return self._index.get(rel_path.replace("\\", "/"))

    def glob(self, pattern: str) -> tuple[FileContext, ...]:
        """Case-insensitive fnmatch over repo-relative paths (`*` crosses directories)."""
        p = pattern.lower()
        return tuple(f for f in self.files if fnmatch.fnmatchcase(f.rel_lower, p))

    def by_basename(self, *names: str) -> tuple[FileContext, ...]:
        wanted = {n.lower() for n in names}
        return tuple(f for f in self.files if f.basename.lower() in wanted)
