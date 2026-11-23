"""Scan orchestration: acquire -> walk -> detectors -> correlate -> suppress -> score."""

from __future__ import annotations

import time
from dataclasses import replace
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from . import SCHEMA, __version__, fetch, history, meta, registry, scoring, suppress
from . import tags as T
from .context import FileContext, RepoContext
from .calibrate import calibrate_all
from .correlate import correlate
from .models import Finding, Report, ScanOptions, ScanResult, Severity
from .net import NetClient
from .walker import walk

Progress = Callable[[str], None]
_MAX_META_PER_KIND = 20


class ScanError(RuntimeError):
    """Bad input or acquisition failure (exit code 4)."""


def _sort_key(f: Finding) -> tuple:
    return (-f.severity, -f.confidence, f.path, f.line or 0, f.rule_id)


def _meta(info, path: str, snippet: str = "", description: str | None = None) -> Finding:  # type: ignore[no-untyped-def]
    return Finding.from_rule(info, None, None, snippet, path=path, description=description)


def _scan_files(repo: RepoContext, detectors, opts: ScanOptions, findings: list[Finding],  # type: ignore[no-untyped-def]
                errors: list[str], progress: Progress | None) -> tuple[int, int]:
    timeouts = crashes = 0
    file_dets = [d for d in detectors if not (d.needs_network and opts.offline)]
    n_files = len(repo.files)
    for i, ctx in enumerate(repo.files):
        if progress and i % 250 == 0:
            progress(f"scanning files {i}/{n_files}")
        timed_out = False
        for det in file_dets:
            try:
                if not det.applies_to(ctx):
                    continue
                ctx.start_deadline(opts.per_file_timeout)
                findings.extend(det.scan_file(ctx))
                if ctx.deadline_exceeded():
                    timed_out = True
            except Exception as exc:  # noqa: BLE001 - one bad detector must not kill the scan
                crashes += 1
                errors.append(f"{det.id} on {ctx.rel_path}: {type(exc).__name__}: {exc}"[:300])
                if crashes <= _MAX_META_PER_KIND:
                    findings.append(_meta(meta.META002, ctx.rel_path, f"{det.id}: {type(exc).__name__}"))
        if timed_out:
            timeouts += 1
            if timeouts <= _MAX_META_PER_KIND:
                findings.append(_meta(meta.META001, ctx.rel_path))
        ctx.release()
    return timeouts, crashes


def _scan_repo_level(repo: RepoContext, detectors, opts: ScanOptions, findings: list[Finding],  # type: ignore[no-untyped-def]
                     errors: list[str]) -> tuple[int, bool]:
    crashes = 0
    net_skipped = False
    for det in detectors:
        if det.needs_network and (opts.offline or not repo.is_remote):
            if opts.offline and repo.is_remote:
                net_skipped = True
                findings.append(_meta(meta.META003, "", det.id, f"{det.name}: skipped because --offline was used."))
            continue
        try:
            findings.extend(det.scan_repo(repo))
        except Exception as exc:  # noqa: BLE001
            crashes += 1
            errors.append(f"{det.id} (repo): {type(exc).__name__}: {exc}"[:300])
            findings.append(_meta(meta.META002, "", f"{det.id}: {type(exc).__name__}"))
    return crashes, net_skipped


def _repo_suppression_files(repo: RepoContext) -> list[FileContext]:
    names = {n.lower() for n in suppress.REPO_IGNORE_NAMES}
    return [f for f in repo.files if f.basename.lower() in names]


def _inline_suppressions(repo: RepoContext) -> list[Finding]:
    out: list[Finding] = []
    for ctx in repo.files:
        if ctx.is_binary or ctx.size > 2_000_000:
            continue
        try:
            low = ctx.lower
        except Exception:  # noqa: BLE001
            continue
        if "repoguard" in low:
            m = suppress.INLINE_RE.search(ctx.text)
            if m:
                out.append(Finding.from_rule(meta.META010, ctx, ctx.line_of(m.start()), ctx.line_text(ctx.line_of(m.start()))))
                if len(out) >= _MAX_META_PER_KIND:
                    break
        ctx.release()
    return out


def scan(target: str, opts: ScanOptions | None = None, progress: Progress | None = None) -> Report:
    opts = opts or ScanOptions()
    t0 = time.monotonic()
    findings: list[Finding] = []
    errors: list[str] = []
    local = Path(target).expanduser()
    is_remote = not local.exists()
    dest: Path | None = None
    commit: str | None = None
    tree_special = []

    if is_remote:
        try:
            url = fetch.validate_url(target)
        except fetch.FetchError as exc:
            raise ScanError(f"{exc}. (Not an existing local folder either: {target})") from exc
        if not fetch.git_version_ok():
            findings.append(_meta(meta.META011, "", ".".join(map(str, fetch.git_version() or ()))))
        if progress:
            progress(f"cloning {url} (hardened, shallow, no hooks/LFS/submodules)")
        try:
            dest = fetch.safe_clone(url, opts.ref, depth=opts.history_depth if opts.history else 1)
        except fetch.FetchError as exc:
            raise ScanError(str(exc)) from exc
        root = dest
        target_label = url
        commit = fetch.head_commit(dest)
        tree_special = fetch.tree_specials(dest)
    else:
        if not local.is_dir():
            raise ScanError(f"not a directory: {local}")
        root = local.resolve()
        target_label = str(root)

    try:
        if progress:
            progress("listing files")
        walked = walk(root, opts)
        special = list(walked.special)
        seen_special = {(s.rel_path, s.kind) for s in special}
        special += [s for s in tree_special if (s.rel_path, s.kind) not in seen_special]
        # files that git says are symlinks are checked out as tiny text files; keep them out of normal scanning
        link_paths = {s.rel_path for s in special if s.kind == "symlink"}
        files = tuple(f for f in walked.files if f.rel_path not in link_paths)
        net = NetClient(offline=opts.offline)
        repo = RepoContext(root=root, target=target_label, is_remote=is_remote, commit=commit, files=files,
                           special=tuple(special), options=opts, net=net)

        detectors = registry.discover()
        timeouts, crashes = _scan_files(repo, detectors, opts, findings, errors, progress)
        if progress:
            progress("running repository-level checks")
        repo_crashes, net_skipped = _scan_repo_level(repo, detectors, opts, findings, errors)
        crashes += repo_crashes

        if walked.limits_hit:
            findings.append(_meta(meta.META004, "", ", ".join(dict.fromkeys(walked.limits_hit))))
        for s in [s for s in special if s.kind == "oversize"][:_MAX_META_PER_KIND]:
            findings.append(_meta(meta.META005, s.rel_path, f"{s.detail} bytes"))

        suppression_files = _repo_suppression_files(repo)
        for f in suppression_files:
            findings.append(Finding.from_rule(meta.META010, f, None, f.basename))
        findings.extend(_inline_suppressions(repo))

        if opts.history:
            if is_remote and dest is not None:
                if progress:
                    progress(f"scanning last {opts.history_depth} commits")
                findings.extend(history.scan_history(dest, opts.history_depth, detectors, findings))
            else:
                errors.append("--history is only supported for remote URLs (local .git config is untrusted)")

        # dedupe
        uniq: dict[str, Finding] = {}
        for f in findings:
            uniq.setdefault(f.fingerprint, f)
        findings = calibrate_all(list(uniq.values()))
        findings.extend(correlate(findings))

        # suppressions (never from the scanned repo unless explicitly trusted)
        ignore_paths = [Path(p) for p in opts.ignore_files]
        up = suppress.user_ignore_path()
        if up.is_file():
            ignore_paths.append(up)
        if opts.trust_repo_ignore:
            ignore_paths += [f.path for f in suppression_files if f.path is not None]
        root_r = root.resolve()
        safe_paths = [p for p in ignore_paths if opts.trust_repo_ignore or not _inside(p, root_r)]
        for p in ignore_paths:
            if p not in safe_paths:
                errors.append(f"ignored --ignore-file inside the scanned repo: {p}")
        kept, dropped = suppress.apply(findings, suppress.load_entries(safe_paths), suppress.load_baseline(opts.baseline))

        incomplete = bool(walked.limits_hit or timeouts or crashes)
        exec_paths = frozenset(f.rel_path for f in files if f.is_install_hook or f.is_ai_config or f.is_ci)
        total, verdict, reasons = scoring.decide(
            kept, exec_paths, incomplete=incomplete, offline=opts.offline and is_remote, network_skipped=net_skipped
        )
        if not is_remote:
            reasons.append("local folder: GitHub reputation checks do not apply")

        kept.sort(key=_sort_key)
        shown = [f for f in kept if f.severity >= opts.min_severity or T.BLOCK_TRIGGER in f.tags]
        stats = replace(walked.stats, files_scanned=len(files), timeouts=timeouts,
                        duration_s=round(time.monotonic() - t0, 2))
        kept_path = str(dest) if (dest is not None and opts.keep) else None
        result = ScanResult(
            target=target_label, root=str(root), kept_path=kept_path, commit=commit, findings=tuple(shown),
            suppressed=tuple(sorted(dropped, key=_sort_key)), hidden_below_min_severity=len(kept) - len(shown),
            stats=stats, errors=tuple(errors), incomplete=incomplete, network_used=net.used,
        )
        return Report(SCHEMA, __version__, datetime.now(UTC).isoformat(timespec="seconds"), result, total, verdict,
                      tuple(reasons))
    finally:
        if dest is not None and not opts.keep:
            fetch.cleanup(dest)


def _inside(p: Path, root: Path) -> bool:
    try:
        p.resolve().relative_to(root)
        return True
    except (ValueError, OSError):
        return False


__all__ = ["scan", "ScanError", "Severity"]
