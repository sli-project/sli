"""Read-only снимок состояния runtime (in-process, без scripts.maintenance).

Не останавливает/запускает службы и не чистит файлы. Используется
diagnostics_report и CLI scripts/maintenance/runtime_watchdog.py.
"""

from __future__ import annotations

import time
from typing import Any

from server.sli.ops.diagnostics_support import (
    DATA_DIR,
    LOG_DIR,
    PROJECT_ROOT,
    assess_recent_internal_errors,
    dir_size_report,
    tail_lines,
)
from server.sli.ops.version import get_release_metadata


def _parse_recent_internal_errors(limit: int = 50) -> dict[str, Any]:
    return assess_recent_internal_errors(
        tail_lines(LOG_DIR / "internal-errors.log", limit),
        activity_text=tail_lines(LOG_DIR / "adlog-monitor.log", 1000),
    )


def _recent_performance_present() -> bool:
    text = tail_lines(LOG_DIR / "performance-events.log", 5)
    return bool(text.strip())


def run_watchdog() -> dict[str, Any]:
    started = time.monotonic()
    warnings: list[str] = []
    items: dict[str, Any] = {}
    try:
        from server.sli.sources.collector_health import get_collector_health

        collector = get_collector_health()
        items["collector_health"] = collector
        summary = collector.get("summary") or {}
        if int(summary.get("high") or 0) or int(summary.get("security_high") or 0):
            warnings.append("collector health has high-risk channels")
        if int(summary.get("warn") or 0) or int(summary.get("security_warn") or 0):
            warnings.append("collector health has warning channels")
    except Exception as exc:
        items["collector_health"] = {"status": "failed", "error_type": type(exc).__name__, "error": str(exc)}
        warnings.append("collector health snapshot failed")

    raw = dir_size_report(DATA_DIR / "raw", max_entries=3000, max_seconds=2.0)
    processed = dir_size_report(DATA_DIR / "processed", max_entries=1000, max_seconds=1.0)
    items["storage"] = {"raw": raw, "processed": processed}
    if int(raw.get("bytes") or 0) > 1024**3:
        warnings.append(f"data/raw is larger than 1 GB: {raw.get('human')}")
    if int(processed.get("bytes") or 0) > 5 * 1024**3:
        warnings.append(f"processed/SQLite is larger than 5 GB: {processed.get('human')}")

    internal_errors = _parse_recent_internal_errors()
    performance_present = _recent_performance_present()
    items["logs"] = {"recent_internal_error_lines": internal_errors["active_count"], "internal_errors": internal_errors, "performance_events_present": performance_present}
    if internal_errors["active"]:
        warnings.append(f"internal-errors.log has {internal_errors['active_count']} active errors in the last 30 minutes")

    return {
        "package_type": "RUNTIME_WATCHDOG_SNAPSHOT",
        "status": "warn" if warnings else "ok",
        "duration_ms": int((time.monotonic() - started) * 1000),
        "release_metadata": get_release_metadata(PROJECT_ROOT),
        "warnings": list(dict.fromkeys(warnings)),
        "items": items,
    }
