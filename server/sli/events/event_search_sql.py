from __future__ import annotations

from typing import Any

from server.source_packs.registry import resolve_source_normalizer

_SECURITY_SOURCE_NORMALIZER = resolve_source_normalizer("Security")


if _SECURITY_SOURCE_NORMALIZER is None:
    raise RuntimeError("Security source pack normalizer is required")


AUTHENTICATION_EVENT_IDS = frozenset(
    _SECURITY_SOURCE_NORMALIZER.event_ids_for_search_family("authentication")
)


ACCOUNT_MANAGEMENT_EVENT_IDS = frozenset(
    _SECURITY_SOURCE_NORMALIZER.event_ids_for_search_family("account_management")
)


PRIVILEGE_MANAGEMENT_EVENT_IDS = frozenset(
    _SECURITY_SOURCE_NORMALIZER.event_ids_for_search_family("privilege_management")
)


POLICY_CHANGE_EVENT_IDS = frozenset(
    _SECURITY_SOURCE_NORMALIZER.event_ids_for_search_family("policy_change")
)


SERVICE_TASK_EVENT_IDS = frozenset(
    _SECURITY_SOURCE_NORMALIZER.event_ids_for_search_family("service_task")
)


def _account_timeline_where_clause(filters: dict[str, Any]) -> tuple[str, list[Any]]:
    """Build one bounded, index-friendly account timeline predicate."""
    parts, params = _common_filter_parts(filters)
    event_ids = filters.get("event_ids") or []
    if event_ids:
        parts.append(f"e.event_id in ({','.join(['?'] * len(event_ids))})")
        params.extend(event_ids)
    account_sql, account_params = _account_lookup_predicate(filters.get("account"), columns=("e.subject_user_name", "e.target_user_name"))
    if not account_sql:
        parts.append("1 = 0")
    else:
        parts.append(account_sql)
        params.extend(account_params)
    return _join_where(parts), params


def _account_exact_values(value: Any) -> list[str]:
    raw = str(value or "").strip()
    if not raw:
        return []
    base_values = [raw]
    if "\\" in raw:
        base_values.append(raw.rsplit("\\", 1)[1])
    if "@" in raw:
        base_values.append(raw.split("@", 1)[0])
    output: list[str] = []
    for item in base_values:
        candidate = item.casefold()
        if candidate and candidate not in output:
            output.append(candidate)
    return output


def _account_prefix_values(value: Any) -> list[str]:
    raw = str(value or "").strip()
    # A numeric, IP or LogonId input must remain exact. A human login prefix is
    # useful in the operator UI and is limited to normalized account fields.
    if len(raw) < 3 or raw.isdigit() or raw.lower().startswith("0x") or raw.replace(".", "").isdigit():
        return []
    return [f"{item}%" for item in _account_exact_values(raw)]


def _account_lookup_predicate(value: Any, *, columns: tuple[str, ...]) -> tuple[str, list[Any]]:
    exact_values = _account_exact_values(value)
    if not exact_values:
        return "", []
    prefix_values = _account_prefix_values(value)
    predicates: list[str] = []
    params: list[Any] = []
    for column in columns:
        exact_placeholders = ",".join(["?"] * len(exact_values))
        normalized_column = f"lower(coalesce({column}, ''))"
        predicate = f"{normalized_column} in ({exact_placeholders})"
        params.extend(exact_values)
        if prefix_values:
            prefix_sql = " or ".join(f"{normalized_column} like ?" for _ in prefix_values)
            predicate = f"({predicate} or ({prefix_sql}))"
            params.extend(prefix_values)
        predicates.append(predicate)
    return "(" + " or ".join(predicates) + ")", params


def _where_clause(filters: dict[str, Any], *, include_payload: bool = False) -> tuple[str, list[Any]]:
    parts, params = _common_filter_parts(filters)
    category_sql, category_params = _category_prefilter(filters.get("category"), channel_column="e.channel")
    if category_sql:
        parts.append(category_sql)
        params.extend(category_params)
    event_ids = filters.get("event_ids") or []
    if event_ids:
        parts.append(f"e.event_id in ({','.join(['?'] * len(event_ids))})")
        params.extend(event_ids)
    if filters.get("account"):
        account_sql, account_params = _account_lookup_predicate(filters["account"], columns=("e.subject_user_name", "e.target_user_name"))
        parts.append(account_sql or "1 = 0")
        params.extend(account_params)
    if filters.get("q"):
        q_sql, q_params = _deep_q_predicate(filters["q"]) if include_payload else _fast_q_predicate(filters["q"])
        parts.append(q_sql)
        params.extend(q_params)
    return _join_where(parts), params


def _common_filter_parts(filters: dict[str, Any]) -> tuple[list[str], list[Any]]:
    parts: list[str] = []
    params: list[Any] = []
    if filters.get("channel"):
        parts.append("e.channel = ?")
        params.append(filters["channel"])
    if filters.get("provider"):
        parts.append("lower(coalesce(e.provider_name, '')) = lower(?)")
        params.append(filters["provider"])
    for filter_name, column in (("subject", "e.subject_user_name"), ("target", "e.target_user_name")):
        if filters.get(filter_name):
            predicate, predicate_params = _account_lookup_predicate(filters[filter_name], columns=(column,))
            parts.append(predicate or "1 = 0")
            params.extend(predicate_params)
    servers = filters.get("servers") or []
    if servers:
        parts.append(f"s.hostname in ({','.join(['?'] * len(servers))})")
        params.extend(servers)
    if filters.get("time_from"):
        parts.append("e.time_created_utc >= ?")
        params.append(filters["time_from"])
    if filters.get("time_to"):
        parts.append("e.time_created_utc < ?")
        params.append(filters["time_to"])
    return parts, params


def _category_prefilter(category: Any, *, channel_column: str) -> tuple[str, list[Any]]:
    """Return a conservative indexed prefilter for a canonical UI category.

    Semantic normalization still verifies every returned row.  This predicate
    only prevents a category request from scanning thousands of newer events
    from another family (typically a burst of authentication rows).
    """
    key = str(category or "").strip().lower()
    families = {
        "authentication": AUTHENTICATION_EVENT_IDS,
        "account_management": ACCOUNT_MANAGEMENT_EVENT_IDS,
        "privilege_management": PRIVILEGE_MANAGEMENT_EVENT_IDS,
        "policy_change": POLICY_CHANGE_EVENT_IDS,
    }
    if key in families:
        values = sorted(families[key])
        return f"e.event_id in ({','.join(['?'] * len(values))})", list(values)
    if key == "service_task":
        service_ids = sorted(SERVICE_TASK_EVENT_IDS)
        return (
            f"(lower(coalesce({channel_column}, '')) like ? or e.event_id in ({','.join(['?'] * len(service_ids))}))",
            ["%taskscheduler%", *service_ids],
        )
    return "", []


def _fast_q_predicate(value: Any) -> tuple[str, list[Any]]:
    """Match indexed fields; login names may be supplied as a useful prefix."""
    raw = str(value or "").strip()
    if not raw:
        return "1 = 1", []
    values = _account_exact_values(raw)
    account_sql, account_params = _account_lookup_predicate(raw, columns=("e.subject_user_name", "e.target_user_name"))
    predicates: list[str] = [account_sql] if account_sql else []
    params: list[Any] = list(account_params)
    # Keep the generic fast path on fields backed by PostgreSQL indexes. Host,
    # provider and payload searches remain available through explicit filters or
    # the bounded deep-search route instead of forcing a million-row filter scan.
    for column in ("e.ip_address", "e.logon_id"):
        placeholders = ",".join(["?"] * len(values))
        predicates.append(f"{column} in ({placeholders})")
        params.extend(values)
    try:
        event_id = int(raw)
    except ValueError:
        event_id = None
    if event_id is not None:
        predicates.append("e.event_id = ?")
        params.append(event_id)
    return "(" + " or ".join(predicates) + ")", params


def _deep_q_predicate(value: Any) -> tuple[str, list[Any]]:
    raw = str(value or "").strip()
    if not raw:
        return "1 = 1", []
    like = f"%{raw}%"
    predicates = [
        "lower(coalesce(e.subject_user_name, '')) like lower(?)",
        "lower(coalesce(e.subject_domain_name, '')) like lower(?)",
        "lower(coalesce(e.target_user_name, '')) like lower(?)",
        "lower(coalesce(e.target_domain_name, '')) like lower(?)",
        "lower(coalesce(e.ip_address, '')) like lower(?)",
        "lower(coalesce(e.workstation_name, '')) like lower(?)",
        "lower(coalesce(e.computer, '')) like lower(?)",
        "lower(coalesce(e.logon_id, '')) like lower(?)",
        "lower(coalesce(e.channel, '')) like lower(?)",
        "lower(coalesce(e.provider_name, '')) like lower(?)",
        "lower(coalesce(e.message_text, '')) like lower(?)",
        "lower(coalesce(e.event_data_json, '')) like lower(?)",
        "lower(cast(e.event_id as text)) like lower(?)",
    ]
    return "(" + " or ".join(predicates) + ")", [like] * len(predicates)


def _cursor_where_clause(filters: dict[str, Any]) -> tuple[str, list[Any]]:
    cursor = filters.get("cursor_values") or {}
    if not cursor:
        return "", []
    op = ">" if filters.get("order") == "asc" else "<"
    time_value = cursor["time"]
    record = int(cursor["record"])
    row_id = int(cursor["id"])
    sql = (
        f"(e.time_created_utc {op} ? or "
        f"(e.time_created_utc = ? and coalesce(e.event_record_id, -1) {op} ?) or "
        f"(e.time_created_utc = ? and coalesce(e.event_record_id, -1) = ? and e.id {op} ?))"
    )
    return sql, [time_value, time_value, record, time_value, record, row_id]


def _append_where(where_sql: str, extra_sql: str) -> str:
    if not extra_sql:
        return where_sql
    if where_sql:
        return where_sql + " and " + extra_sql
    return "where " + extra_sql


def _join_where(parts: list[str]) -> str:
    return "where " + " and ".join(parts) if parts else ""


def _v2_handler_where_clause(filters: dict[str, Any], *, account_timeline: bool) -> tuple[str, list[Any]]:
    parts: list[str] = []
    params: list[Any] = []
    if filters.get("channel"):
        parts.append("channel.value = ?")
        params.append(filters["channel"])
    if filters.get("provider"):
        parts.append("lower(coalesce(provider.value, '')) = lower(?)")
        params.append(filters["provider"])
    for filter_name, column in (("subject", "e.subject_user_name"), ("target", "e.target_user_name")):
        if filters.get(filter_name):
            predicate, predicate_params = _account_lookup_predicate(filters[filter_name], columns=(column,))
            parts.append(predicate or "1 = 0")
            params.extend(predicate_params)
    servers = filters.get("servers") or []
    if servers:
        parts.append(f"s.hostname in ({','.join(['?'] * len(servers))})")
        params.extend(servers)
    if filters.get("time_from"):
        parts.append("e.time_created_utc >= ?")
        params.append(filters["time_from"])
    if filters.get("time_to"):
        parts.append("e.time_created_utc < ?")
        params.append(filters["time_to"])
    category_sql, category_params = _category_prefilter(filters.get("category"), channel_column="channel.value")
    if category_sql:
        parts.append(category_sql)
        params.extend(category_params)
    event_ids = filters.get("event_ids") or []
    if event_ids:
        parts.append(f"e.event_id in ({','.join(['?'] * len(event_ids))})")
        params.extend(event_ids)
    if account_timeline or filters.get("account"):
        account_sql, account_params = _account_lookup_predicate(filters.get("account"), columns=("e.subject_user_name", "e.target_user_name"))
        if not account_sql:
            parts.append("1 = 0")
        else:
            parts.append(account_sql)
            params.extend(account_params)
    elif filters.get("q"):
        values = _account_exact_values(filters["q"])
        account_sql, account_params = _account_lookup_predicate(filters["q"], columns=("e.subject_user_name", "e.target_user_name"))
        predicates: list[str] = [account_sql] if account_sql else []
        params.extend(account_params)
        for column in ("e.ip_address", "e.logon_id"):
            placeholders = ",".join(["?"] * len(values))
            predicates.append(f"{column} in ({placeholders})")
            params.extend(values)
        try:
            event_id = int(filters["q"])
        except ValueError:
            event_id = None
        if event_id is not None:
            predicates.append("e.event_id = ?")
            params.append(event_id)
        parts.append("(" + " or ".join(predicates) + ")")
    return _join_where(parts), params
