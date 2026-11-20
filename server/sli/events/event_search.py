# ruff: noqa: F401 -- re-export hub (plan 7.2b): split-out modules read these
# names through ``event_search`` at call time, and callers import them from here.
from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from server.sli.core import database as _database
from server.sli.core.database import (
    QueryTimeoutError,
    is_postgres_runtime_db,
    query_rows_bounded,
)
from server.sli.core.time_format import format_event_time
from server.sli.events.event_catalog import all_event_catalog_entries
from server.sli.events.event_search_filters import (
    DEFAULT_DEEP_WINDOW_HOURS,
    DEFAULT_SEARCH_LIMIT,
    DEFAULT_SEARCH_WINDOW_HOURS,
    MAX_SEARCH_LIMIT,
    VALID_SORT_ORDERS,
    _clean_int_list,
    _cursor_scalar,
    _datetime_local_input_value,
    _default_time_from,
    _unique_ints,
    decode_search_cursor,
    encode_search_cursor,
    make_account_timeline_url,
    make_deep_search_url,
    make_search_url,
    normalize_search_filters,
)
from server.sli.events.event_search_projection import (
    _EVENT_SUMMARY_KEYS,
    ACCOUNT_EVENT_LABELS,
    IMPORTANT_ACCOUNT_EVENT_IDS,
    _empty_search_result,
    _fallback_event_category,
    _parse_json_object,
    _semantic_filter_matches,
    _timeline_item,
    _timeline_summary,
    event_summary_projection,
)
from server.sli.events.event_search_render import (
    _best_account,
    _e,
    _facets_html,
    _metric,
    _next_page_url,
    _pill,
    _search_form,
    _search_rows,
    _shorten,
    _style,
    _timeline_html,
    render_account_timeline_report,
    render_event_search_report,
)
from server.sli.events.event_search_sql import (
    _SECURITY_SOURCE_NORMALIZER,
    ACCOUNT_MANAGEMENT_EVENT_IDS,
    AUTHENTICATION_EVENT_IDS,
    POLICY_CHANGE_EVENT_IDS,
    PRIVILEGE_MANAGEMENT_EVENT_IDS,
    SERVICE_TASK_EVENT_IDS,
    _account_exact_values,
    _account_lookup_predicate,
    _account_prefix_values,
    _account_timeline_where_clause,
    _append_where,
    _category_prefilter,
    _common_filter_parts,
    _cursor_where_clause,
    _deep_q_predicate,
    _fast_q_predicate,
    _join_where,
    _v2_handler_where_clause,
    _where_clause,
)
from server.sli.ops import logging_config as _logging
from server.sli.ops.logging_config import log_event
from server.sli.reporting.ui_labels import event_id_label
from server.sli.semantic.event_card_semantics import build_event_card
from server.sli.storage import permanent_fact_history as _fact_history
from server.sli.storage.permanent_fact_history import (
    _json_ch_time,
    _payload_sha,
    configured_read_port,
    primary_read_enabled,
)
from server.sli.storage.permanent_fact_history import (
    _rows as _history_rows,
)
from server.sli.storage.runtime_storage import (
    StorageRouteConsumer,
    resolve_storage_route,
)
from server.sli.storage.storage_policy import load_storage_policy
from server.sli.storage.storage_v2_archive import (
    ArchiveIntegrityError,
    ArchiveReader,
)
from server.sli.storage.storage_v2_repository import (
    PostgresArchiveManifestStore,
    PostgresStorageV2Repository,
)
from server.sli.storage.storage_v2_runtime import (
    PostgresStorageV2ReadStore,
    StorageV2RuntimeReader,
)
from server.sli.storage.storage_v2_transition_controller import (
    CutoverAuthorization,
)

FAST_SEARCH_TIMEOUT_MS = 8000
DEEP_SEARCH_TIMEOUT_MS = 12000
ACCOUNT_TIMELINE_TIMEOUT_MS = 8000
SEMANTIC_FILTER_SCAN_LIMIT = 5000
SEMANTIC_FILTER_BATCH_MIN = 200
SEMANTIC_FILTER_QUERY_BUDGET = 8


def get_event_search_data(
    *,
    authorization: CutoverAuthorization | None = None,
    **raw_filters: Any,
) -> dict[str, Any]:
    return _get_event_slice(
        deep=False, raw_filters=raw_filters, authorization=authorization
    )


def get_event_deep_search_data(
    *,
    authorization: CutoverAuthorization | None = None,
    **raw_filters: Any,
) -> dict[str, Any]:
    """Explicit bounded substring search over Message/EventData payloads."""
    return _get_event_slice(
        deep=True, raw_filters=raw_filters, authorization=authorization
    )


def _query_event_rows_batch(
    *,
    deep: bool,
    filters: dict[str, Any],
    fetch_limit: int,
    timeout_ms: int,
    authorization: CutoverAuthorization | None,
) -> list[dict[str, Any]]:
    """Read one keyset page without semantic post-processing (Storage V2, plan 6.5)."""
    _v2_primary_read_enabled_for_request(authorization)
    rows = (
        _query_v2_deep_archive_rows(filters, fetch_limit, timeout_ms)
        if deep
        else _query_v2_event_rows(filters, fetch_limit, timeout_ms, account_timeline=False)
    )
    from server.sli.semantic.account_watch_projection import attach_event_priorities

    return attach_event_priorities(rows)


def _attach_relation_counts(
    items: list[dict[str, Any]], *, timeout_ms: int,
    authorization: CutoverAuthorization | None = None,
) -> list[dict[str, Any]]:
    """Attach exact stored-link counts with one bounded page-level aggregate."""
    def exact_id(item: dict[str, Any]) -> int:
        return int(item.get("event_db_id") or item.get("id") or 0)

    event_ids = list(dict.fromkeys(exact_id(item) for item in items if exact_id(item) > 0))
    if not event_ids:
        return items
    _v2_primary_read_enabled_for_request(authorization)
    cold_ids = [
        event_id for item in items
        if (event_id := exact_id(item)) > 0
        and item.get("source_payload_state") == "expired"
    ]
    history_counts: dict[int, int] = {}
    if cold_ids and _fact_history.primary_read_enabled():
        port = configured_read_port()
        if port is None:
            raise RuntimeError("history ClickHouse port missing")
        rows = _history_rows(
            port,
            "SELECT event_db_id,count() AS relation_count FROM sli_history.links "
            f"WHERE event_db_id IN ({','.join(str(value) for value in cold_ids)}) "
            "AND batch_sha256 IN (SELECT batch_sha256 FROM sli_history.published_batches) "
            "GROUP BY event_db_id",
        )
        history_counts = {
            int(row["event_db_id"]): int(row["relation_count"]) for row in rows
        }
    hot_ids = [event_id for event_id in event_ids if event_id not in cold_ids]
    if not hot_ids:
        for item in items:
            item["relation_count"] = history_counts.get(exact_id(item), 0)
            item["relation_count_status"] = "exact"
        return items
    placeholders = ",".join("?" for _ in hot_ids)
    # Read the link blocks directly: the event_entity_links_v2 view unnests
    # every block, so a lookup by event_id scans the whole table. Blocks keep
    # event_ids sorted (validate_link_blocks), so first/last_event_id bound
    # each block and the BRIN index on that range prunes the scan.
    try:
        rows = _database.query_rows_bounded(
            f"""
            select expanded.event_id as event_db_id, count(*) as relation_count
            from event_entity_link_blocks_v2 block
            cross join lateral unnest(block.event_ids) as expanded(event_id)
            where block.first_event_id <= ? and block.last_event_id >= ?
              and expanded.event_id in ({placeholders})
            group by expanded.event_id
            """,
            (max(hot_ids), min(hot_ids), *hot_ids),
            statement_timeout_ms=min(timeout_ms, 2000),
            wall_timeout_ms=min(timeout_ms, 2000) + 500,
        )
    except QueryTimeoutError:
        # Relation counts are a secondary projection: a slow link index must
        # not erase an otherwise valid event page or its exact evidence IDs.
        for item in items:
            item["relation_count"] = None
            item["relation_count_status"] = "unavailable"
        return items
    counts = {int(row["event_db_id"]): int(row.get("relation_count") or 0) for row in rows}
    counts.update(history_counts)
    for item in items:
        item["relation_count"] = counts.get(exact_id(item), 0)
        item["relation_count_status"] = "exact"
    return items

def get_event_category_counts(
    *,
    authorization: CutoverAuthorization | None = None,
    **raw_filters: Any,
) -> dict[str, int] | None:
    """Return exact tab counts independently from the bounded event page."""
    filters = normalize_search_filters(**raw_filters)
    return _event_category_counts(
        filters,
        timeout_ms=FAST_SEARCH_TIMEOUT_MS,
        authorization=authorization,
    )


def _v2_primary_read_enabled(
    authorization: CutoverAuthorization | None = None,
) -> bool:
    resolve_storage_route(authorization=authorization, consumer=StorageRouteConsumer.EVENT_SEARCH)
    if not _database.is_postgres_runtime_db():
        raise ValueError("storage_v2_route_requires_postgres")
    return True


def _v2_primary_read_enabled_for_request(
    authorization: CutoverAuthorization | None,
) -> bool:
    """Validate the Storage V2 route (the only one, plan 6.5) for this request."""
    if authorization is None:
        return _v2_primary_read_enabled()
    return _v2_primary_read_enabled(authorization)


def _query_v2_event_rows(filters: dict[str, Any], fetch_limit: int, timeout_ms: int, *, account_timeline: bool) -> list[dict[str, Any]]:
    if not _fact_history.primary_read_enabled():
        return _query_v2_postgres_event_rows(
            filters, fetch_limit, timeout_ms,
            account_timeline=account_timeline,
        )
    cutoff = datetime.now(timezone.utc) - timedelta(days=load_storage_policy().db_retention_days)
    lower = filters.get("time_from")
    upper = filters.get("time_to")
    cold: list[dict[str, Any]] = []
    hot: list[dict[str, Any]] = []
    if lower is None or datetime.fromisoformat(str(lower).replace("Z", "+00:00")) < cutoff:
        cold_filters = dict(filters)
        cold_filters["time_to"] = min(
            datetime.fromisoformat(str(upper).replace("Z", "+00:00")) if upper else cutoff,
            cutoff,
        ).isoformat()
        cold = _query_clickhouse_history_rows(
            cold_filters, fetch_limit, account_timeline=account_timeline,
        )
    if upper is None or datetime.fromisoformat(str(upper).replace("Z", "+00:00")) > cutoff:
        hot_filters = dict(filters)
        hot_filters["time_from"] = max(
            datetime.fromisoformat(str(lower).replace("Z", "+00:00")) if lower else cutoff,
            cutoff,
        ).isoformat()
        hot = _query_v2_postgres_event_rows(
            hot_filters, fetch_limit, timeout_ms,
            account_timeline=account_timeline,
        )
    order_reverse = filters["order"] != "asc"
    merged = sorted(
        [*cold, *hot],
        key=lambda row: (
            datetime.fromisoformat(str(row["time_created_utc"]).replace("Z", "+00:00")),
            int(row.get("event_record_id") or -1), int(row["id"]),
        ),
        reverse=order_reverse,
    )
    ids = [int(row["id"]) for row in merged]
    if len(ids) != len(set(ids)):
        raise ArchiveIntegrityError("historical search returned duplicate event IDs")
    return merged[:fetch_limit]








def _normalize_search_row(
    row: dict[str, Any],
    *,
    include_internal_evidence: bool = False,
) -> dict[str, Any]:
    event_id = int(row.get("event_id") or 0)
    label, category, severity = ACCOUNT_EVENT_LABELS.get(event_id, ("Событие журнала", "event", "info"))
    event_data = _parse_json_object(row.get("event_data_json"))
    semantic = build_event_card({**row, "event_data": event_data})
    catalogued = bool(semantic.get("known"))
    if catalogued:
        label = str(semantic.get("title") or label)
        category = str(semantic.get("category") or category)
        if category in {"other", "unknown"}:
            category = _fallback_event_category(row)
        severity = str(semantic.get("final_risk") or severity)
        summary = str(semantic.get("summary") or "")
    else:
        summary = "Каталог не содержит проверенной интерпретации этого события."
    projected = event_summary_projection({
        "event_db_id": row.get("id") or row.get("event_db_id"),
        "event_id": event_id,
        "event_record_id": row.get("event_record_id"),
        "time_created_utc": row.get("time_created_utc"),
        "server": row.get("server"),
        "channel": row.get("channel"),
        "provider_name": row.get("provider_name"),
        # A catalogued source-pack event already has a precise analyst-facing
        # action name.  Keeping only its numeric Event ID here made the fast
        # search regress to a technical label and hid the value of the
        # semantic catalogue from the unified UI.
        "label": label if catalogued or not event_id else None,
        "category": category,
        "severity": severity,
        "tier": semantic.get("purpose_tier") if catalogued else None,
        "purpose_tier": semantic.get("purpose_tier"),
        "base_risk": semantic.get("base_risk"),
        "final_risk": semantic.get("final_risk"),
        "final_security_severity": semantic.get("final_security_severity"),
        "confidence": semantic.get("confidence"),
        "noise_class": semantic.get("noise_class"),
        "source_payload_state": row.get("source_payload_state"),
        "assessment_confidence": semantic.get("assessment_confidence"),
        "catalog_match": bool(semantic.get("catalog_match")),
        "reasons": list(semantic.get("reasons") or []),
        "evidence_fields": list(semantic.get("evidence_fields") or []),
        "display_labels": dict(semantic.get("display_labels") or {}),
        "time_created_utc_display": format_event_time(row.get("time_created_utc")),
        "time_created_local_display": format_event_time(row.get("time_created_local"), suffix="") if row.get("time_created_local") else "—",
        "summary": summary,
    })
    if include_internal_evidence:
        projected.update({
            key: row.get(key)
            for key in (
                "subject_user_name", "subject_domain_name",
                "target_user_name", "target_domain_name",
                "ip_address", "workstation_name", "logon_id",
                "message_text", "event_data_json",
            )
        })
    return projected


# Split-out parts (plan 7.2b). They read this module's names through ``_src`` at
# call time, so imports above that look unused here are used there, and tests
# that patch ``event_search.<name>`` still reach the moved code.
from server.sli.events.event_search_readers import (
    _query_clickhouse_history_rows,
    _query_v2_deep_archive_rows,
    _query_v2_postgres_event_rows,
)
from server.sli.events.event_search_slices import (
    _event_category_counts,
    _get_event_slice,
    _semantic_filtered_slice,
)
from server.sli.events.event_search_timeline import (
    get_account_timeline_data,
)
