# ruff: noqa: F401 -- re-export hub (plan 7.2b): split-out modules read these
# names through ``ui_workspace`` at call time, and callers import them from here.
"""Read-only, bounded DTO sources for the React workspace.

This module intentionally adapts existing operational data instead of letting a
browser infer state from legacy HTML.  It must remain safe to call from a page
refresh: no jobs, finding refreshes, collection actions, migrations, or
full-history counts live here.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
from typing import Any

from server.sli.core.database import (
    QueryTimeoutError,
    get_sources,
    is_postgres_runtime_db,
    query_rows,
    query_rows_bounded,
)
from server.sli.core.time_contract import normalize_utc_range
from server.sli.core.time_format import parse_event_time
from server.sli.events.event_catalog import lookup_event_catalog
from server.sli.events.event_details import (
    get_event_detail_report_data,
    get_event_details_by_ids,
)
from server.sli.events.event_relations import get_event_relations
from server.sli.ops.runtime_workers import get_runtime_workers_overview
from server.sli.reporting.dashboard_fast import get_overview_activity
from server.sli.reporting.dashboard_snapshot import build_dashboard_snapshot
from server.sli.reporting.ui_operations import _collection_execution_view, collection_progress_view, get_collection_runtime_status
from server.sli.reporting.ui_workspace_overview import (
    _merge_registered_source_inventory,
    _overview_alert,
    _overview_collection_freshness,
    _overview_source,
    _overview_sources,
    _overview_time,
)
from server.sli.reporting.ui_workspace_shaping import (
    _EVENT_EVIDENCE_FIELD_PROJECTIONS,
    ENTITY_DETAIL_EVENT_LIMIT,
    ENTITY_DETAIL_EVENT_MAX,
    ENTITY_LIST_LIMIT,
    ENTITY_LIST_MAX,
    EVENT_ENTITY_LIMIT,
    INVESTIGATION_FINDING_LIMIT,
    OVERVIEW_ALERT_LIMIT,
    _entity_candidate_sort_key,
    _entity_item,
    _exact_event_db_id,
    _investigation_finding,
    _parse_investigation_exact_id,
)
from server.sli.semantic.event_card_semantics import build_event_card
from server.sli.semantic.event_semantic_contract import (
    normalize_category,
    normalize_risk,
)
from server.sli.semantic.investigation import get_investigation_workspace_data
from server.sli.sources.collector_health import (
    get_collector_health,
)
from server.sli.storage.permanent_fact_history import (
    configured_read_port,
    primary_read_enabled,
    read_published_event,
    read_published_links,
)
from server.sli.storage.runtime_storage import (
    StorageRouteAuthorizationError,
    StorageRouteConsumer,
    resolve_storage_route,
)
from server.sli.storage.storage_policy import load_storage_policy
from server.sli.storage.storage_v2_transition_controller import (
    CutoverAuthorization,
)
from server.source_packs.windows_ad_dc import event_label as windows_event_label

INVESTIGATION_TIMELINE_LIMIT = 100
ENTITY_CURRENT_STATE_LIMIT = 64

def get_overview_workspace_data(
    *, time_from: str | None = None, time_to: str | None = None,
    server: str | None = None,
    authorization: CutoverAuthorization | None = None,
) -> dict[str, Any]:
    """Adapt the cached bounded dashboard snapshot to a small UI contract."""
    snapshot = (
        build_dashboard_snapshot()
        if authorization is None
        else build_dashboard_snapshot(authorization=authorization)
    )
    event_summary = snapshot.get("events_summary") or {}
    entity_summary = snapshot.get("entity_summary") or {}
    findings = (snapshot.get("role_views") or {}).get("findings") or (snapshot.get("findings") or {})
    finding_items = list(findings.get("items") or [])[:OVERVIEW_ALERT_LIMIT]
    registered_sources = list((snapshot.get("sources") or {}).get("items") or [])
    source_inventory_is_incomplete = any(
        not all(field in item for field in ("fqdn", "os_name", "os_version", "ip_addresses"))
        for item in registered_sources
    )
    if (
        (not registered_sources and (snapshot.get("diagnostics") or {}).get("request_model") == "startup_warming_response")
        or source_inventory_is_incomplete
    ):
        # Source inventory is a small bounded PostgreSQL read.  Do not leave a
        # newly restarted UI empty merely because the heavier dashboard
        # snapshot is still warming.  Also enrich snapshots produced by an
        # older contract instead of hiding configured source attributes until
        # the dashboard cache expires.
        try:
            registered_sources = _merge_registered_source_inventory(
                registered_sources,
                list(get_sources()),
            )
        except Exception:
            # The cached inventory remains an honest partial state when the
            # bounded live read is temporarily unavailable.
            pass
    collector_health = snapshot.get("collector_health") or {}
    health_items = list(collector_health.get("items") or [])
    if (
        not health_items
        and (snapshot.get("diagnostics") or {}).get("request_model") == "startup_warming_response"
    ):
        # A cold dashboard cache must not turn a healthy or partially healthy
        # collector into a red failure indicator for the whole browser
        # session.  Collector health is a bounded read and is safe to use as
        # the same startup fallback already used for source inventory.
        try:
            collector_health = get_collector_health()
            health_items = list(collector_health.get("items") or [])
        except Exception:
            # The response remains an honest unavailable state; no synthetic
            # channels or success status are introduced.
            pass
    sources = _overview_sources(registered_sources, health_items)[:50]
    try:
        progress_collector_health = get_collector_health()
        progress_workers = get_runtime_workers_overview()
        try:
            collection = _collection_execution_view(get_collection_runtime_status(), progress_workers)
        except Exception:
            collection = {}
        collection_progress = collection_progress_view(
            progress_collector_health, progress_workers, collection
        )
    except Exception:
        collection_progress = collection_progress_view(collector_health, {"items": []})
    end = _overview_time(time_to) or datetime.now(timezone.utc)
    start = _overview_time(time_from) or (end - timedelta(hours=24))
    if end <= start or end - start > timedelta(days=8):
        start = end - timedelta(hours=24)
    selected_source = str(server or "").strip() or None
    finding_items = [
        item for item in finding_items
        if (not selected_source or selected_source.lower() in str(item.get("source") or "").lower())
        and (_overview_time(item.get("last_seen_utc")) is None or start <= _overview_time(item.get("last_seen_utc")) < end)
    ][:OVERVIEW_ALERT_LIMIT]
    filtered_sources = [item for item in sources if not selected_source or str(item.get("hostname") or "").lower() == selected_source.lower()]
    period_label = "7 дней" if end - start > timedelta(days=2) else "24 часа"
    # The chart contract is deliberately human-sized: one bar group per hour
    # for the 24-hour view and one group per day for the seven-day view.
    bucket_count = 7 if period_label == "7 дней" else 24
    try:
        activity_kwargs: dict[str, Any] = {
            "time_from": start.isoformat().replace("+00:00", "Z"),
            "time_to": end.isoformat().replace("+00:00", "Z"),
            "server": selected_source,
            "bucket_count": bucket_count,
        }
        if authorization is not None:
            activity_kwargs["authorization"] = authorization
        activity = get_overview_activity(**activity_kwargs)
    except Exception as exc:
        activity = {"items": [], "available": False, "exact": False, "reason": type(exc).__name__}
    return {
        "generated_at_utc": snapshot.get("generated_at_utc"),
        "status": str(snapshot.get("status") or "warming"),
        "data_state": {
            "cache": (snapshot.get("diagnostics") or {}).get("response_model") or "warming",
            "stale": bool((snapshot.get("diagnostics") or {}).get("stale")),
            "failures": list((snapshot.get("diagnostics") or {}).get("failures") or []),
        },
        "metrics": {
            "events_total": int(event_summary.get("total_events") or 0),
            "events_estimated": bool(event_summary.get("estimated")),
            "entities_total": int(entity_summary.get("total_entities") or 0),
            "entities_estimated": bool(entity_summary.get("estimated")),
            "important_recent": int((event_summary.get("security_24h_summary") or {}).get("important_total") or 0),
            "sources_total": len(sources),
        },
        "alerts": [_overview_alert(item) for item in finding_items],
        "sources": filtered_sources,
        "collection_freshness": _overview_collection_freshness(collector_health, selected_source),
        "collection_progress": collection_progress,
        "activity": {
            "period_label": period_label,
            "time_from_utc": start.isoformat().replace("+00:00", "Z"),
            "time_to_utc": end.isoformat().replace("+00:00", "Z"),
            "selected_source": selected_source,
            **activity,
        },
        "limits": {"alerts": OVERVIEW_ALERT_LIMIT, "sources": 50, "full_history": False},
    }


def parse_investigation_event_id(value: str | int | None) -> int | None:
    """An explicit malformed anchor must never become an unanchored query."""
    return _parse_investigation_exact_id(value, "invalid_event_db_id")


def parse_investigation_entity_id(value: str | int | None) -> int | None:
    """An explicit malformed entity must never become a name-led search."""
    return _parse_investigation_exact_id(value, "invalid_entity_id")




class EntityEvidenceLookupError(LookupError):
    """The entity has no response-safe exact evidence history."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)












class EntityTypeFilterError(ValueError):
    def __init__(self, unknown_types: list[str]) -> None:
        self.unknown_types = sorted(set(unknown_types))
        super().__init__(f"unknown entity types: {', '.join(self.unknown_types)}")










































from server.sli.reporting.ui_workspace_entity import (
    _detail_timeline_source,
    _entity_detail_event_item,
    _exact_event_catalog_descriptor,
    _get_current_entity_states,
    _get_entity_evidence_event_rows,
    _metadata_timeline_source,
    get_entity_workspace_detail_data,
    get_entity_workspace_resource_preflight,
)
from server.sli.reporting.ui_workspace_events import (
    _history_event_entities_data,
    _timeline_item,
    get_entities_workspace_data,
    get_event_entities_data,
)
from server.sli.reporting.ui_workspace_investigations import (
    _anchored_investigation_workspace_data,
    _entity_investigation_workspace_data,
    get_investigations_workspace_data,
)
