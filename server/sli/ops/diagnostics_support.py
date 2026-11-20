"""Общие помощники диагностики для runtime (без зависимости от scripts.maintenance).

Перенесено из scripts/maintenance/bundle_common.py; bundle_common реэкспортирует
эти имена, чтобы CLI и тесты в scripts/maintenance работали без изменений.
"""

from __future__ import annotations

import json
import os
import time
from collections import deque
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = PROJECT_ROOT / "data"
LOG_DIR = DATA_DIR / "logs"

INTERNAL_ERROR_FRESHNESS_MINUTES = 30


def _jsonl_timestamp(payload: Mapping[str, Any]) -> datetime | None:
    raw = str(payload.get("ts") or "").strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def assess_recent_internal_errors(
    error_text: str,
    *,
    activity_text: str = "",
    now: datetime | None = None,
    freshness_minutes: int = INTERNAL_ERROR_FRESHNESS_MINUTES,
) -> dict[str, Any]:
    """Return active recent internal errors from JSONL log tails.

    Old entries do not keep diagnostics yellow forever. A fresh collection
    failure is also considered recovered when a later successful collection
    stage exists for the same server (and channel, when both records have one).
    Malformed non-empty lines remain active: diagnostics must fail closed when
    it cannot prove that an error is old or recovered.
    """
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    cutoff = current - timedelta(minutes=max(1, freshness_minutes))
    recoveries: list[tuple[datetime, str, str]] = []
    for line in activity_text.splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(payload, dict):
            continue
        ts = _jsonl_timestamp(payload)
        status = str(payload.get("status") or "").lower()
        event = str(payload.get("event") or "")
        stage = str(payload.get("stage") or "")
        successful_collection = (
            status in {"ok", "completed", "success", "succeeded"}
            and (event in {"import_completed", "server_collection_completed", "collection_completed"}
                 or (event == "stage_completed" and stage in {"collection_backend_command", "evt_next_read", "render_parse_write_jsonl"}))
        )
        if ts is not None and successful_collection:
            recoveries.append((ts, str(payload.get("server") or ""), str(payload.get("channel") or "")))

    active_lines: list[str] = []
    parsed_count = 0
    malformed_count = 0
    recovered_count = 0
    ignored_non_error_count = 0
    for line in error_text.splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            malformed_count += 1
            active_lines.append(line)
            continue
        if not isinstance(payload, dict):
            malformed_count += 1
            active_lines.append(line)
            continue
        ts = _jsonl_timestamp(payload)
        if ts is None:
            malformed_count += 1
            active_lines.append(line)
            continue
        parsed_count += 1
        if ts < cutoff:
            continue
        level = str(payload.get("level") or "").upper()
        if level and level not in {"ERROR", "CRITICAL"}:
            ignored_non_error_count += 1
            continue
        server = str(payload.get("server") or "")
        channel = str(payload.get("channel") or "")
        recovered = bool(server) and any(
            success_ts > ts
            and success_server == server
            and (not channel or not success_channel or success_channel == channel)
            for success_ts, success_server, success_channel in recoveries
        )
        if recovered:
            recovered_count += 1
            continue
        active_lines.append(line)
    return {
        "active": bool(active_lines),
        "active_count": len(active_lines),
        "active_text": "\n".join(active_lines),
        "parsed_count": parsed_count,
        "malformed_count": malformed_count,
        "recovered_count": recovered_count,
        "ignored_non_error_count": ignored_non_error_count,
        "freshness_minutes": freshness_minutes,
    }


def tail_lines(path: Path, limit: int = 3000) -> str:
    """Return the last *limit* text lines without reading huge logs fully."""
    if not path.exists() or not path.is_file():
        return ""
    limit = max(1, int(limit))
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            return "".join(deque(f, maxlen=limit))
    except OSError:
        return ""


def dir_size_report(
    path: Path,
    *,
    max_entries: int | None = None,
    max_seconds: float | None = None,
    skip_dir_names: set[str] | None = None,
) -> dict[str, Any]:
    """Fast, bounded directory size estimate.

    Diagnostics and release checks must never hang on very large runtime trees.
    This helper returns a partial size if max_entries/max_seconds is reached and
    marks the result as truncated. It is conservative enough for warnings and
    operational triage, while deep storage accounting remains a separate task.
    """
    started = time.monotonic()
    skip_dir_names = skip_dir_names or set()
    result: dict[str, Any] = {
        "path": str(path),
        "bytes": 0,
        "files_seen": 0,
        "dirs_seen": 0,
        "truncated": False,
        "reason": None,
    }
    if not path.exists():
        result["human"] = fmt_bytes(0)
        result["exists"] = False
        result["duration_ms"] = int((time.monotonic() - started) * 1000)
        return result
    result["exists"] = True
    if path.is_file():
        try:
            result["bytes"] = path.stat().st_size
            result["files_seen"] = 1
        except OSError as exc:
            result["error"] = str(exc)
        result["human"] = fmt_bytes(int(result["bytes"]))
        result["duration_ms"] = int((time.monotonic() - started) * 1000)
        return result
    stack = [path]
    while stack:
        if max_seconds is not None and (time.monotonic() - started) > max_seconds:
            result["truncated"] = True
            result["reason"] = "max_seconds"
            break
        current = stack.pop()
        try:
            with os.scandir(current) as iterator:
                for entry in iterator:
                    if max_entries is not None and int(result["files_seen"]) + int(result["dirs_seen"]) >= max_entries:
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


def fmt_bytes(value: int) -> str:
    size = float(value or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{value} B"
