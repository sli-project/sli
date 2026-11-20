"""Pure limits and DTO shaping helpers split out of ``ui_workspace``.

Nothing here touches storage, so no test patches these names on
``ui_workspace``; they are re-exported there unchanged.
"""
from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from server.sli.core.time_format import parse_event_time

OVERVIEW_ALERT_LIMIT = 12
INVESTIGATION_FINDING_LIMIT = 20
ENTITY_LIST_LIMIT = 50
ENTITY_LIST_MAX = 100
ENTITY_DETAIL_EVENT_LIMIT = 50
ENTITY_DETAIL_EVENT_MAX = 100
EVENT_ENTITY_LIMIT = 30
_EVENT_EVIDENCE_FIELD_PROJECTIONS = frozenset({
    "full", "technical", "security_metadata", "metadata",
})


def _parse_investigation_exact_id(value: str | int | None, error_code: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(error_code)
    text = str(value).strip()
    if not text or not text.isascii() or not text.isdecimal():
        raise ValueError(error_code)
    identity = int(text)
    if not 0 < identity <= 9_007_199_254_740_991:
        raise ValueError(error_code)
    return identity


def _entity_candidate_sort_key(item: Mapping[str, Any]) -> tuple[datetime, int]:
    observed_at = parse_event_time(item.get("time_created_utc"))
    if observed_at is None:
        observed_at = datetime.min.replace(tzinfo=timezone.utc)
    elif observed_at.tzinfo is None:
        observed_at = observed_at.replace(tzinfo=timezone.utc)
    else:
        observed_at = observed_at.astimezone(timezone.utc)
    return observed_at, int(item.get("event_db_id") or 0)


def _exact_event_db_id(item: dict[str, Any]) -> int | None:
    """Return a valid persisted event ID, never a placeholder for the UI."""
    raw = item.get("event_db_id") if item.get("event_db_id") is not None else item.get("id")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def _investigation_finding(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": int(item.get("id") or 0), "title": str(item.get("title") or ""),
        "severity": str(item.get("severity") or "unknown"), "status": str(item.get("status") or "unknown"),
        "target": item.get("target"), "last_seen_utc": item.get("last_seen_utc"),
        "recommended_action": item.get("recommended_action"),
        "assigned_to": item.get("assigned_to"), "status_reason": item.get("status_reason"),
        "updated_at": item.get("updated_at"),
        "status_history": [
            {
                "id": int(history.get("id") or 0),
                "old_status": history.get("old_status"),
                "new_status": str(history.get("new_status") or ""),
                "changed_at": history.get("changed_at"),
                "changed_by": str(history.get("changed_by") or "system"),
                "note": history.get("note"),
            }
            for history in (item.get("status_history") or [])[:20]
        ],
    }


def _entity_item(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": int(item.get("id") or 0), "type": str(item.get("entity_type") or "unknown"),
        "natural_key": str(item.get("natural_key") or ""), "display_name": item.get("display_name"),
        "first_seen_utc": item.get("first_seen_utc"), "last_seen_utc": item.get("last_seen_utc"),
        "latest_state": (
            {
                "status": str(item.get("latest_state_status")),
                "summary": item.get("latest_state_summary"),
                "observed_at_utc": item.get("latest_state_observed_at_utc"),
                "evidence_event_db_id": int(item["latest_state_event_db_id"]),
            }
            if item.get("latest_state_status") and item.get("latest_state_event_db_id") is not None
            else None
        ),
    }
