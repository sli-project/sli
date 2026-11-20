from __future__ import annotations

import json
from typing import Any

from server.sli.events.event_details import make_event_detail_url
from server.sli.events.event_search_sql import (
    _SECURITY_SOURCE_NORMALIZER,
    ACCOUNT_MANAGEMENT_EVENT_IDS,
    AUTHENTICATION_EVENT_IDS,
    POLICY_CHANGE_EVENT_IDS,
    PRIVILEGE_MANAGEMENT_EVENT_IDS,
    SERVICE_TASK_EVENT_IDS,
)
from server.sli.reporting.ui_labels import event_id_label

IMPORTANT_ACCOUNT_EVENT_IDS = list(
    _SECURITY_SOURCE_NORMALIZER.important_account_event_ids()
)


ACCOUNT_EVENT_LABELS = {
    event_id: (
        semantics.label,
        semantics.timeline_category,
        semantics.severity,
    )
    for event_id in IMPORTANT_ACCOUNT_EVENT_IDS
    if (semantics := _SECURITY_SOURCE_NORMALIZER.account_event(event_id)) is not None
}


def _fallback_event_category(row: dict[str, Any]) -> str:
    """Classify catalogue rows whose older declaration omitted category.

    The catalogue already identifies the exact Provider/Channel/Event ID.  A
    missing category must not collapse every such known event into ``other``;
    that was why only the one explicitly tagged authentication entry appeared
    in category views.
    """
    event_id = int(row.get("event_id") or 0)
    channel = str(row.get("channel") or "").lower()
    provider = str(row.get("provider_name") or "").lower()
    if event_id in AUTHENTICATION_EVENT_IDS:
        return "authentication"
    if event_id in ACCOUNT_MANAGEMENT_EVENT_IDS:
        return "account_management"
    if event_id in PRIVILEGE_MANAGEMENT_EVENT_IDS:
        return "privilege_management"
    if event_id in POLICY_CHANGE_EVENT_IDS:
        return "policy_change"
    if "taskscheduler" in channel or "task scheduler" in provider:
        return "service_task"
    if event_id in SERVICE_TASK_EVENT_IDS and (
        channel == "system" or "service control manager" in provider
    ):
        return "service_task"
    return "operations"


def _semantic_filter_matches(item: dict[str, Any], filters: dict[str, Any]) -> bool:
    risks = {value.strip().lower() for value in str(filters.get("risk") or "").split(",") if value.strip()}
    tier = str(filters.get("tier") or "")
    category = str(filters.get("category") or "")
    return (
        (not risks or str(
            item.get("final_security_severity")
            if item.get("final_security_severity") is not None
            else item.get("final_risk")
            if item.get("final_risk") is not None
            else item.get("severity") or ""
        ).lower() in risks)
        and (not tier or str(
            item.get("purpose_tier")
            if item.get("purpose_tier") is not None
            else item.get("tier") or ""
        ).lower() == tier)
        and (not category or str(item.get("category") or "").lower() == category)
    )


def _empty_search_result(filters: dict[str, Any], *, mode: str, warning: str | None = None) -> dict[str, Any]:
    return {
        "filters": filters,
        "mode": mode,
        "query_status": "empty",
        "warning": warning,
        "total": None,
        "total_is_exact": False,
        "returned_count": 0,
        "has_more": False,
        "truncated": False,
        "next_cursor": None,
        "items": [],
        "facets": {},
        "facets_computed": False,
        "performance": {
            "bounded": True,
            "limit_plus_one": True,
            "pagination": "keyset",
            "automatic_exact_count": False,
            "automatic_facets": False,
            "payload_scan": mode == "deep",
        },
    }


_EVENT_SUMMARY_KEYS = (
    "event_db_id", "event_id", "event_record_id", "time_created_utc",
    "time_created_utc_display", "time_created_local_display", "server", "channel",
    "provider_name", "label", "category", "severity", "tier", "purpose_tier",
    "base_risk", "final_risk", "final_security_severity", "confidence", "noise_class",
    "source_payload_state",
    "assessment_confidence", "catalog_match", "reasons", "evidence_fields",
    "display_labels", "summary",
    "relation_count", "relation_count_status",
)


def event_summary_projection(item: dict[str, Any]) -> dict[str, Any]:
    """Project an event onto the summary-only API contract."""
    source = dict(item)
    event_db_id = source.get("event_db_id", source.get("id"))
    event_id = int(source.get("event_id") or 0)
    defaults = {
        "event_db_id": int(event_db_id or 0),
        "event_id": event_id,
        "label": str(source.get("label") or event_id_label(
            event_id, prefix=False, channel=str(source.get("channel") or ""),
            provider_name=source.get("provider_name"),
        ) or "Событие журнала"),
        "summary": str(source.get("summary") or "Сводка события; точные данные доступны в карточке доказательства."),
    }
    return {
        key: (defaults[key] if key in defaults else source.get(key))
        for key in _EVENT_SUMMARY_KEYS
        if key in source or key in defaults
    }


def _timeline_item(row: dict[str, Any]) -> dict[str, Any]:
    timeline_label = (ACCOUNT_EVENT_LABELS.get(int(row.get("event_id") or 0)) or (row.get("label"), None, None))[0]
    return {
        "time": row.get("time_created_utc"),
        "time_display": row.get("time_created_utc_display"),
        "local_time": row.get("time_created_local"),
        "local_time_display": row.get("time_created_local_display"),
        "server": row.get("server"),
        "channel": row.get("channel"),
        "event_id": row.get("event_id"),
        "label": timeline_label,
        "category": row.get("category"),
        "severity": row.get("severity"),
        "summary": row.get("summary"),
        "detail_url": make_event_detail_url(event_db_id=row.get("event_db_id"), event_id=row.get("event_id"), channel=row.get("channel"), servers=[row.get("server")] if row.get("server") else [], time_from=row.get("time_created_utc"), time_to=row.get("time_created_utc"), limit=50),
    }


def _timeline_summary(items: list[dict[str, Any]]) -> dict[str, int]:
    # Timeline counters are behavioural buckets, not the canonical UI category.
    # Preserve their finer-grained meaning by deriving them from Event ID while
    # the public ``category`` field remains aligned with the semantic contract.
    categories = [
        str((ACCOUNT_EVENT_LABELS.get(int(item.get("event_id") or 0)) or (None, item.get("category"), None))[1] or "")
        for item in items
    ]
    return {
        "total": len(items),
        "logons": sum(1 for value in categories if value in {"logon", "logon_failed", "explicit_credentials", "kerberos", "kerberos_failed", "credential_validation"}),
        "password_or_lockout": sum(1 for value in categories if value in {"password", "lockout"}),
        "privileged_or_group": sum(1 for value in categories if value in {"privileged_logon", "group_change"}),
    }


def _parse_json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not value:
        return {}
    try:
        parsed = json.loads(str(value))
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}
