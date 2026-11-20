from __future__ import annotations

import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from server.sli.storage.storage_policy_format import _iso, _now_utc, fmt_bytes

ACTIVE_LOG_NAMES = {"adlog-monitor.log", "internal-errors.log", "performance-events.log", "self-test.log", "release-check.log", "audit-actions.log"}


PROTECTED_RAW_HINTS = {"failed", "partial", "error", "retry", "evidence", "finding", "findings", "investigation", "keep"}


PYTEST_RUN_NAME_RE = re.compile(
    r"^[\w-]+-\d{8}-\d{6}-\d+-[0-9a-f]{8}$",
    re.IGNORECASE,
)


def _safe_stat(path: Path):
    try:
        return path.stat()
    except OSError:
        return None


def _bounded_dir_size(path: Path, *, max_entries: int = 5000, max_seconds: float = 2.0, skip_dir_names: set[str] | None = None) -> dict[str, Any]:
    started = time.monotonic()
    skip_dir_names = skip_dir_names or set()
    result: dict[str, Any] = {"path": str(path), "bytes": 0, "files_seen": 0, "dirs_seen": 0, "truncated": False, "reason": None, "exists": path.exists()}
    if not path.exists():
        result["human"] = fmt_bytes(0)
        result["duration_ms"] = int((time.monotonic() - started) * 1000)
        return result
    if path.is_file():
        st = _safe_stat(path)
        result["bytes"] = st.st_size if st else 0
        result["files_seen"] = 1 if st else 0
        result["human"] = fmt_bytes(result["bytes"])
        result["duration_ms"] = int((time.monotonic() - started) * 1000)
        return result
    stack = [path]
    while stack:
        if time.monotonic() - started > max_seconds:
            result["truncated"] = True
            result["reason"] = "max_seconds"
            break
        current = stack.pop()
        try:
            with os.scandir(current) as iterator:
                for entry in iterator:
                    if int(result["files_seen"]) + int(result["dirs_seen"]) >= max_entries:
                        result["truncated"] = True
                        result["reason"] = "max_entries"
                        stack.clear()
                        break
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            if entry.name in skip_dir_names:
                                continue
                            result["dirs_seen"] += 1
                            stack.append(Path(entry.path))
                        elif entry.is_file(follow_symlinks=False):
                            result["files_seen"] += 1
                            result["bytes"] += entry.stat(follow_symlinks=False).st_size
                    except OSError:
                        continue
        except OSError:
            continue
    result["human"] = fmt_bytes(int(result["bytes"]))
    result["duration_ms"] = int((time.monotonic() - started) * 1000)
    return result


def _raw_path_variants(path: Path) -> set[str]:
    variants = {str(path)}
    try:
        variants.add(str(path.resolve()))
    except OSError:
        pass
    if os.name == "nt":
        variants.update(item.lower() for item in list(variants))
    return variants


def _file_age_days(path: Path) -> float | None:
    st = _safe_stat(path)
    if not st:
        return None
    return max(0.0, (_now_utc() - datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)).total_seconds() / 86400)


def _iter_files(root: Path, *, max_entries: int, max_seconds: float) -> tuple[list[Path], dict[str, Any]]:
    started = time.monotonic()
    files: list[Path] = []
    meta = {"truncated": False, "reason": None, "files_seen": 0, "dirs_seen": 0}
    if not root.exists():
        return files, meta
    stack = [root]
    while stack:
        if time.monotonic() - started > max_seconds:
            meta["truncated"] = True
            meta["reason"] = "max_seconds"
            break
        current = stack.pop()
        try:
            with os.scandir(current) as iterator:
                for entry in iterator:
                    if int(meta["files_seen"]) + int(meta["dirs_seen"]) >= max_entries:
                        meta["truncated"] = True
                        meta["reason"] = "max_entries"
                        stack.clear()
                        break
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            meta["dirs_seen"] += 1
                            stack.append(Path(entry.path))
                        elif entry.is_file(follow_symlinks=False):
                            meta["files_seen"] += 1
                            files.append(Path(entry.path))
                    except OSError:
                        continue
        except OSError:
            continue
    meta["duration_ms"] = int((time.monotonic() - started) * 1000)
    return files, meta


def _action(path: Path, action: str, reason: str, category: str, target: Path | None = None) -> dict[str, Any]:
    st = _safe_stat(path)
    return {
        "category": category,
        "action": action,
        "path": str(path),
        "target": str(target) if target else None,
        "reason": reason,
        "size_bytes": st.st_size if st else 0,
        "size_human": fmt_bytes(st.st_size if st else 0),
        "modified_utc": _iso(datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)) if st else None,
        "age_days": round(_file_age_days(path) or 0, 2),
    }


def _pytest_active_marker(root: Path, run_name: str) -> Path:
    return root / f".active-{run_name}.json"


def _path_is_link_like(path: Path) -> bool:
    """Reject symlinks and Windows junctions without following either."""
    is_junction = getattr(path, "is_junction", None)
    return path.is_symlink() or bool(is_junction and is_junction())


def _scan_pytest_run_tree(path: Path) -> dict[str, Any]:
    """Measure one generated pytest run without following links."""
    result: dict[str, Any] = {
        "bytes": 0,
        "files": 0,
        "directories": 0,
        "newest_mtime": 0.0,
        "links_not_followed": 0,
        "errors": [],
    }
    stack = [path]
    while stack:
        current = stack.pop()
        try:
            stat = current.stat()
            result["newest_mtime"] = max(float(result["newest_mtime"]), stat.st_mtime)
            with os.scandir(current) as iterator:
                for entry in iterator:
                    try:
                        entry_path = Path(entry.path)
                        if _path_is_link_like(entry_path):
                            result["links_not_followed"] += 1
                            continue
                        stat = entry.stat(follow_symlinks=False)
                        result["newest_mtime"] = max(
                            float(result["newest_mtime"]), stat.st_mtime
                        )
                        if entry.is_dir(follow_symlinks=False):
                            result["directories"] += 1
                            stack.append(Path(entry.path))
                        elif entry.is_file(follow_symlinks=False):
                            result["files"] += 1
                            result["bytes"] += stat.st_size
                    except OSError as exc:
                        result["errors"].append({
                            "path": entry.path,
                            "error_type": type(exc).__name__,
                            "error": str(exc),
                        })
        except OSError as exc:
            result["errors"].append({
                "path": str(current),
                "error_type": type(exc).__name__,
                "error": str(exc),
            })
    return result


def _build_age_delete_actions(root: Path, *, days: int, category: str, limit: int, deep: bool, include_active_logs: bool = False) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    files, scan = _iter_files(root, max_entries=(10000 if deep else 3000), max_seconds=(5.0 if deep else 1.5))
    actions: list[dict[str, Any]] = []
    excluded = {"recent": 0, "active_log": 0, "over_limit": 0, "stat_error": 0}
    for path in sorted(files):
        if category == "logs" and not include_active_logs and path.name in ACTIVE_LOG_NAMES:
            excluded["active_log"] += 1
            continue
        st = _safe_stat(path)
        if not st:
            excluded["stat_error"] += 1
            continue
        age = _file_age_days(path)
        if age is None or age < days:
            excluded["recent"] += 1
            continue
        if len(actions) >= limit:
            excluded["over_limit"] += 1
            continue
        actions.append(_action(path, "delete_file", f"{category} older than {days} days", category))
    scan["excluded"] = {k: v for k, v in excluded.items() if v}
    return actions, scan


def _unique(path: Path) -> Path:
    if not path.exists():
        return path
    for i in range(1, 10000):
        candidate = path.with_name(f"{path.stem}.{i}{path.suffix}")
        if not candidate.exists():
            return candidate
    raise OSError(f"cannot allocate unique path for {path}")
