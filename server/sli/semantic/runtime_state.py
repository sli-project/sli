"""Shared, value-free runtime quality decisions for reports and producer."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any

FACTS_MODE = "facts-v1"
INVESTIGATION_MODE = "investigation-v1"
FINDINGS_MODE = "findings-v1"

def semantic_runtime_projection(
    heartbeat: dict[str, Any],
    *,
    generated: datetime,
) -> dict[str, Any]:

    details = heartbeat.get("details_json") or {}
    stamp = heartbeat.get("heartbeat_at")
    if isinstance(stamp, str):
        try:
            stamp = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        except ValueError:
            stamp = None
    if isinstance(stamp, datetime) and stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    age_seconds = (
        max(0, int((generated - stamp.astimezone(timezone.utc)).total_seconds()))
        if isinstance(stamp, datetime)
        else None
    )
    try:
        expected = max(1, int(heartbeat.get("expected_interval_seconds") or 30))
    except (TypeError, ValueError):
        expected = 30
    fresh = age_seconds is not None and age_seconds <= max(60, expected * 2 + 30)
    runtime_mode = details.get("runtime_mode")
    runtime_mode = str(runtime_mode).strip() if runtime_mode is not None else None
    if not runtime_mode:
        runtime_mode = None
    capabilities = {
        FACTS_MODE: (True, False, False),
        INVESTIGATION_MODE: (True, True, False),
        FINDINGS_MODE: (True, True, True),
    }.get(runtime_mode)
    worker_active = (
        heartbeat.get("status") in {"running", "idle"}
        and details.get("manual_runtime") is False
    )
    if capabilities is None:
        facts_state = relations_state = findings_state = "unknown"
    elif not fresh:
        facts_state = "stale"
        relations_state = "stale" if capabilities[1] else "inactive"
        findings_state = "stale" if capabilities[2] else "inactive"
    elif worker_active:
        facts_state = "active"
        relations_state = "active" if capabilities[1] else "inactive"
        findings_state = "active" if capabilities[2] else "inactive"
    else:
        facts_state = relations_state = findings_state = "inactive"
    return {
        # Compatibility: this has always meant the findings publisher state.
        "state": findings_state,
        "runtime_mode": runtime_mode,
        "facts_state": facts_state,
        "relations_state": relations_state,
        "findings_state": findings_state,
        "fresh": fresh,
        "age_seconds": age_seconds,
        "status": heartbeat.get("status"),
        "phase": heartbeat.get("phase"),
        "heartbeat_at": heartbeat.get("heartbeat_at"),
        "enabled_policy": details.get("enabled_policy"),
        "enabled_policies": details.get("enabled_policies"),
    }


def scheduled_quality(heartbeat, *, generated, total, refresh_limited=False,
                      coverage_incomplete=False, has_more=False):
    """Mirror the existing report adapter plus snapshot limitation handling."""
    runtime = semantic_runtime_projection(heartbeat, generated=generated)
    mode = runtime["findings_state"]
    quality = "stale" if mode == "stale" else "partial" if mode in {"inactive", "unknown"} else "ok" if total else "empty"
    if quality in {"ok", "empty"} and (refresh_limited or coverage_incomplete or has_more):
        quality = "partial"
    return quality
