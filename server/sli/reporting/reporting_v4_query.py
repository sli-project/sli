"""Interactive query compilation, cursors, sort and grant-branch helpers for reporting_v4."""
from __future__ import annotations

import base64
import json
from datetime import datetime
from hashlib import sha256
from typing import Any, Mapping, Sequence

from server.sli.reporting.reporting_v4_catalog import (
    BOOLEAN_FILTER_FIELDS,
    DEFAULT_ORDERS,
    EVENT_VIEW_EVENT_IDS,
    GPO_EXECUTABLE_COUNT_SQL,
    INTEGER_FILTER_FIELDS,
    RUNTIME_FILTER_FIELDS,
    RUNTIME_SORT_FIELDS,
    runtime_filter_expression,
)

VPN_ACCOUNT_CURSOR_ORDER = "source_entity.id asc"


def _vpn_account_cursor(row: Mapping[str, Any]) -> str:
    raw = json.dumps({"object_id": str(row["object_id"])}, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_vpn_account_cursor(value: Any) -> int:
    clean = str(value or "").strip()
    if not clean or len(clean) > 512:
        raise ValueError("invalid_report_cursor")
    try:
        payload = json.loads(base64.urlsafe_b64decode(clean + "=" * (-len(clean) % 4)))
        row_id = payload["object_id"]
        if not isinstance(row_id, str) or not row_id.isascii() or not row_id.isdecimal():
            raise ValueError("invalid_report_cursor")
        row_id = int(row_id)
    except (ValueError, TypeError, KeyError, UnicodeError) as exc:
        raise ValueError("invalid_report_cursor") from exc
    if not 0 < row_id < 2**63:
        raise ValueError("invalid_report_cursor")
    return row_id


def _bounded_filter_value(value: Any, *, many: bool) -> Any:
    if many:
        raw_items = value if isinstance(value, (list, tuple)) else str(value).split(",")
        items = [str(item).strip() for item in raw_items if str(item).strip()]
        if not items or len(items) > 100 or any(len(item) > 512 for item in items):
            raise ValueError("invalid_filter_value")
        return items
    if isinstance(value, (Mapping, list, tuple)) or value is None:
        raise ValueError("invalid_filter_value")
    clean = str(value).strip()
    if not clean or len(clean) > 512:
        raise ValueError("invalid_filter_value")
    return clean


def _typed_filter_value(dataset_key: str, field: str, value: Any, *, many: bool) -> Any:
    bounded = _bounded_filter_value(value, many=many)
    values = bounded if many else [bounded]
    if (dataset_key, field) in INTEGER_FILTER_FIELDS:
        try:
            typed = [int(item) for item in values]
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid_filter_value") from exc
        if any(item < -(2**63) or item > 2**63 - 1 for item in typed):
            raise ValueError("invalid_filter_value")
    elif (dataset_key, field) in BOOLEAN_FILTER_FIELDS:
        typed = []
        for item in values:
            normalized = str(item).strip().lower()
            if normalized in {"1", "true", "yes", "on"}:
                typed.append(True)
            elif normalized in {"0", "false", "no", "off"}:
                typed.append(False)
            else:
                raise ValueError("invalid_filter_value")
    else:
        typed = list(values)
    return typed if many else typed[0]


def _compile_definition_query(dataset_key: str, definition: Mapping[str, Any]) -> tuple[list[str], list[Any], str]:
    """Compile stored builder predicates and sort using server-owned fragments."""
    predicates: list[str] = []
    params: list[Any] = []
    raw_filters = definition.get("filters") or []
    if not isinstance(raw_filters, list):
        raise ValueError("invalid_report_definition_filters")
    for item in raw_filters:
        if not isinstance(item, Mapping):
            raise ValueError("invalid_report_definition_filters")
        # Seeded reports store the dataset filter schema ({key, ops}) here.
        # Only builder predicates have {field, op, value} and are executable.
        if "field" not in item and "value" not in item:
            continue
        field = str(item.get("field") or "")
        op = str(item.get("op") or "").lower()
        expression = runtime_filter_expression(dataset_key, field)
        if expression is None or op not in {"eq", "in", "contains", "gte", "lte"}:
            raise ValueError("report_filter_not_executable")
        value = _typed_filter_value(dataset_key, field, item.get("value"), many=op == "in")
        if op == "eq":
            predicates.append(f"{expression}=?")
            params.append(value)
        elif op == "in":
            predicates.append(f"{expression}=any(?)")
            params.append(value)
        elif op == "contains":
            predicates.append(f"{expression} ilike ?")
            params.append(f"%{value}%")
        elif op == "gte":
            predicates.append(f"{expression}>=?")
            params.append(value)
        else:
            predicates.append(f"{expression}<=?")
            params.append(value)

    raw_sort = definition.get("sort")
    if raw_sort is None:
        raw_sort = definition.get("default_sort") or []
    if not isinstance(raw_sort, list) or len(raw_sort) > 5:
        raise ValueError("invalid_report_definition_sort")
    sort_parts: list[str] = []
    for item in raw_sort:
        if not isinstance(item, Mapping):
            raise ValueError("invalid_report_definition_sort")
        field = str(item.get("field") or "")
        direction = str(item.get("direction") or "").lower()
        expression = RUNTIME_SORT_FIELDS.get(dataset_key, {}).get(field)
        if expression is None or direction not in {"asc", "desc"}:
            raise ValueError("report_sort_not_executable")
        sort_parts.append(f"{expression} {direction}")
    return predicates, params, ",".join(sort_parts) or DEFAULT_ORDERS[dataset_key]


def _append_predicates(where_sql: str, predicates: Sequence[str]) -> str:
    if not predicates:
        return where_sql
    connector = " and " if where_sql else " where "
    return where_sql + connector + " and ".join(f"({item})" for item in predicates)


def _report_cursor(row: Mapping[str, Any]) -> str | None:
    time_value = str(row.get("time_created_utc") or "").strip()
    row_id = int(row.get("id") or 0)
    if not time_value or row_id <= 0:
        return None
    raw = json.dumps({"time": time_value, "id": row_id}, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_report_cursor(value: Any) -> tuple[str, int]:
    clean = str(value or "").strip()
    if not clean or len(clean) > 512:
        raise ValueError("invalid_report_cursor")
    try:
        decoded = base64.urlsafe_b64decode((clean + "=" * (-len(clean) % 4)).encode("ascii"))
        payload = json.loads(decoded.decode("utf-8"))
        time_value = str(payload.get("time") or "").strip()
        row_id = int(payload.get("id") or 0)
    except (ValueError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid_report_cursor") from exc
    if not time_value or len(time_value) > 64 or row_id <= 0:
        raise ValueError("invalid_report_cursor")
    return time_value, row_id


def _utc_filter_value(value: Any) -> str:
    clean = str(value or "").strip()
    if not clean or len(clean) > 64:
        raise ValueError("invalid_report_time_filter")
    try:
        parsed = datetime.fromisoformat(clean.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid_report_time_filter") from exc
    if parsed.tzinfo is None:
        raise ValueError("invalid_report_time_filter")
    return clean


def _compile_interactive_event_query(
    query: Mapping[str, Any] | None, *, order_sql: str,
) -> tuple[list[str], list[Any]]:
    if not query:
        return [], []
    allowed = {"q", "server", "time_from", "time_to", "cursor", "view"}
    if any(str(key) not in allowed for key in query):
        raise ValueError("unknown_report_query_filter")
    clauses: list[str] = []
    params: list[Any] = []
    view = str(query.get("view") or "").strip().lower()
    if view:
        if view not in {*EVENT_VIEW_EVENT_IDS, "all"}:
            raise ValueError("invalid_report_query_filter")
        if view == "tasks":
            clauses.append(
                "(lower(coalesce(channel.value,'')) like ? or event.event_id=any(?))"
            )
            params.extend(["%taskscheduler%", EVENT_VIEW_EVENT_IDS[view]])
        elif view != "all":
            clauses.append("event.event_id=any(?)")
            params.append(EVENT_VIEW_EVENT_IDS[view])
    q = str(query.get("q") or "").strip()
    if q:
        if len(q) > 256:
            raise ValueError("invalid_report_query_filter")
        account_values = [q]
        for separator in ("\\", "@"):
            if separator in q:
                candidate = q.rsplit(separator, 1)[-1] if separator == "\\" else q.split(separator, 1)[0]
                if candidate and candidate not in account_values:
                    account_values.append(candidate)
        predicates: list[str] = []
        for column in ("event.subject_user_name", "event.target_user_name"):
            for value in account_values:
                predicates.append(f"lower(coalesce({column},''))=lower(?)")
                params.append(value)
        for column in ("event.ip_address", "event.workstation_name", "event.logon_id"):
            predicates.append(f"lower(coalesce({column},''))=lower(?)")
            params.append(q)
        try:
            event_id = int(q)
        except ValueError:
            event_id = None
        if event_id is not None:
            predicates.append("event.event_id=?")
            params.append(event_id)
        clauses.append("(" + " or ".join(predicates) + ")")
    server = str(query.get("server") or "").strip()
    if server:
        if len(server) > 256:
            raise ValueError("invalid_report_query_filter")
        clauses.append("lower(server.hostname)=lower(?)")
        params.append(server)
    if query.get("time_from") not in (None, ""):
        clauses.append("event.time_created_utc>=?")
        params.append(_utc_filter_value(query["time_from"]))
    if query.get("time_to") not in (None, ""):
        clauses.append("event.time_created_utc<?")
        params.append(_utc_filter_value(query["time_to"]))
    if query.get("cursor") not in (None, ""):
        if order_sql != DEFAULT_ORDERS["events.v2"]:
            raise ValueError("report_cursor_requires_default_sort")
        time_value, row_id = _decode_report_cursor(query["cursor"])
        clauses.append("(event.time_created_utc<? or (event.time_created_utc=? and event.id<?))")
        params.extend([time_value, time_value, row_id])
    return clauses, params


def _compile_interactive_report_query(
    dataset_key: str,
    query: Mapping[str, Any] | None,
) -> tuple[list[str], list[Any]]:
    """Compile the small, dataset-specific set of interactive report filters.

    These are deliberately not a generic client-provided filtering language.
    Every SQL expression is owned by the server and every value is bounded.
    """
    if not query:
        return [], []
    allowed_by_dataset = {
        "ad.audit.snapshot": {"entity_type"},
        "ad.accounts.vpn": {"q", "activity_state", "privileged_overlap"},
        "ad.gpo.governance": {
            "q", "application_state", "link_count", "has_executable_components",
        },
    }
    allowed = allowed_by_dataset.get(dataset_key, set())
    if any(str(key) not in allowed for key in query):
        raise ValueError("unknown_report_query_filter")
    clauses: list[str] = []
    params: list[Any] = []
    if dataset_key == "ad.audit.snapshot":
        entity_type = str(query.get("entity_type") or "").strip().lower()
        if entity_type:
            if entity_type not in {"ad_user", "ad_computer"}:
                raise ValueError("invalid_report_query_filter")
            clauses.append(f"{RUNTIME_FILTER_FIELDS[dataset_key]['entity_type']}=?")
            params.append(entity_type)
    elif dataset_key == "ad.accounts.vpn":
        q = str(query.get("q") or "").strip()
        if q:
            if len(q) > 256:
                raise ValueError("invalid_report_query_filter")
            clauses.append("strpos(lower(concat_ws(' ',source_entity.display_name,source_entity.natural_key)),lower(?))>0")
            params.append(q)
        activity_state = str(query.get("activity_state") or "").strip().lower()
        if activity_state:
            if activity_state not in {"active", "disabled", "inactive", "unknown"}:
                raise ValueError("invalid_report_query_filter")
            clauses.append(f"{runtime_filter_expression(dataset_key, 'activity_state')}=?")
            params.append(activity_state)
        if query.get("privileged_overlap") not in (None, ""):
            value = _typed_filter_value(
                dataset_key, "privileged_overlap",
                query["privileged_overlap"], many=False,
            )
            clauses.append(f"{RUNTIME_FILTER_FIELDS[dataset_key]['privileged_overlap']}=?")
            params.append(value)
    elif dataset_key == "ad.gpo.governance":
        application_state = str(
            query.get("application_state") or ""
        ).strip().lower()
        if application_state:
            if application_state not in {
                "both_enabled", "computer_only", "user_only", "disabled", "partial",
            }:
                raise ValueError("invalid_report_query_filter")
            if application_state == "partial":
                clauses.append(
                    f"{RUNTIME_FILTER_FIELDS[dataset_key]['application_state']} in (?,?)"
                )
                params.extend(["computer_only", "user_only"])
            else:
                clauses.append(
                    f"{RUNTIME_FILTER_FIELDS[dataset_key]['application_state']}=?"
                )
                params.append(application_state)
        if query.get("link_count") not in (None, ""):
            try:
                link_count = int(str(query["link_count"]).strip())
            except (TypeError, ValueError) as exc:
                raise ValueError("invalid_report_query_filter") from exc
            if not 0 <= link_count <= 1_000_000:
                raise ValueError("invalid_report_query_filter")
            clauses.append(
                f"{RUNTIME_FILTER_FIELDS[dataset_key]['link_count']}=?"
            )
            params.append(link_count)
        executable = str(query.get("has_executable_components") or "").strip().lower()
        if executable:
            if executable not in {"true", "false"}:
                raise ValueError("invalid_report_query_filter")
            clauses.append(
                f"({GPO_EXECUTABLE_COUNT_SQL})>0"
                if executable == "true"
                else f"({GPO_EXECUTABLE_COUNT_SQL})=0"
            )
        q = str(query.get("q") or "").strip()
        if q:
            if len(q) > 256:
                raise ValueError("invalid_report_query_filter")
            value = f"%{q}%"
            expressions = (
                "entity.display_name", "entity.natural_key",
                "version.attributes_json->'attributes'->>'gpo_wmi_filter_id'",
                "version.attributes_json->'attributes'->'links'::text",
                "version.attributes_json->'attributes'->'gpo_security_filtering_sids'::text",
                "version.attributes_json->'attributes'->'gpo_settings'::text",
            )
            clauses.append(
                "(" + " or ".join(f"coalesce({expression},'') ilike ?" for expression in expressions) + ")"
            )
            params.extend([value] * len(expressions))
    return clauses, params


def _compile_interactive_sort(
    dataset_key: str,
    query: Mapping[str, Any] | None,
    *,
    default_order_sql: str,
) -> str:
    """Compile a user-selected sort through the server-owned field allowlist."""
    if not query:
        return default_order_sql
    raw_field = query.get("sort")
    raw_direction = query.get("direction")
    if raw_field in (None, "") and raw_direction in (None, ""):
        return default_order_sql
    if raw_field in (None, "") or raw_direction in (None, ""):
        raise ValueError("incomplete_report_sort")
    field = str(raw_field).strip()
    direction = str(raw_direction).strip().lower()
    expression = RUNTIME_SORT_FIELDS.get(dataset_key, {}).get(field)
    if expression is None or direction not in {"asc", "desc"}:
        raise ValueError("report_sort_not_executable")
    if dataset_key == "ad.accounts.vpn" and field == "object_id" and direction == "asc":
        return VPN_ACCOUNT_CURSOR_ORDER
    # The canonical order is retained as a deterministic tie-breaker. This is
    # especially important before LIMIT and when multiple rows share a label.
    return f"{expression} {direction} nulls last,{default_order_sql}"


def _sort_combined_report_items(
    items: Sequence[Mapping[str, Any]],
    query: Mapping[str, Any] | None,
) -> list[dict[str, Any]]:
    """Order rows from independent grant branches without JSON-key sorting."""
    rows = [dict(item) for item in items]
    field = str((query or {}).get("sort") or "").strip()
    direction = str((query or {}).get("direction") or "").strip().lower()
    if not field:
        return sorted(
            rows,
            key=lambda item: json.dumps(
                item, ensure_ascii=True, sort_keys=True,
                separators=(",", ":"), default=str,
            ),
        )
    present = [item for item in rows if item.get(field) is not None]
    missing = [item for item in rows if item.get(field) is None]

    def key(item: Mapping[str, Any]) -> tuple[str, str]:
        value = item.get(field)
        if isinstance(value, bool):
            normalized = "1" if value else "0"
        elif isinstance(value, (int, float)):
            normalized = f"{value:030.10f}"
        else:
            normalized = str(value).casefold()
        tie = json.dumps(
            item, ensure_ascii=True, sort_keys=True,
            separators=(",", ":"), default=str,
        )
        return normalized, tie

    present.sort(key=key, reverse=direction == "desc")
    missing.sort(
        key=lambda item: json.dumps(
            item, ensure_ascii=True, sort_keys=True,
            separators=(",", ":"), default=str,
        ),
    )
    return present + missing


def _grant_scope_covers(broader: Mapping[str, Any], narrower: Mapping[str, Any]) -> bool:
    broader_kind = str(broader.get("kind") or "")
    narrower_kind = str(narrower.get("kind") or "")
    if broader_kind == "all":
        return True
    if broader_kind != narrower_kind or broader_kind not in {"server", "domain", "channel"}:
        return False
    key = "values" if broader_kind == "channel" else "ids"
    return set(broader.get(key) or []) >= set(narrower.get(key) or [])


def _grant_subsumes(broader: Mapping[str, Any], narrower: Mapping[str, Any]) -> bool:
    """Return whether one active grant already covers another grant's projection."""
    return (
        set(str(item) for item in broader.get("field_categories") or [])
        >= set(str(item) for item in narrower.get("field_categories") or [])
        and set(str(item) for item in broader.get("allowed_actions") or [])
        >= set(str(item) for item in narrower.get("allowed_actions") or [])
        and _grant_scope_covers(
            dict(broader.get("scope") or {}),
            dict(narrower.get("scope") or {}),
        )
    )


def _prune_subsumed_grants(grants: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Remove redundant branches without combining unrelated scope/field tuples."""
    result: list[dict[str, Any]] = []
    for index, candidate in enumerate(grants):
        if any(
            other_index != index
            and _grant_subsumes(other, candidate)
            and (
                not _grant_subsumes(candidate, other)
                or other_index < index
            )
            for other_index, other in enumerate(grants)
        ):
            continue
        result.append(dict(candidate))
    return result


def _grant_branch_key(grant: Mapping[str, Any]) -> str:
    identity = json.dumps(
        {
            "scope": grant.get("scope") or {},
            "field_categories": sorted(
                str(item) for item in grant.get("field_categories") or []
            ),
            "allowed_actions": sorted(
                str(item) for item in grant.get("allowed_actions") or []
            ),
            "source_type": grant.get("source_type"),
            "source": grant.get("source"),
            "valid_from": grant.get("valid_from"),
            "valid_until": grant.get("valid_until"),
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return sha256(identity.encode("utf-8")).hexdigest()
