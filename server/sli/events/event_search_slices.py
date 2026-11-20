"""Split out of ``server.sli.events.event_search`` (plan 7.2b).

Module-level names of ``event_search`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.events.event_search as _src


def _get_event_slice(
    *,
    deep: bool,
    raw_filters: dict[str, _src.Any],
    authorization: _src.CutoverAuthorization | None,
) -> dict[str, _src.Any]:
    window = _src.DEFAULT_DEEP_WINDOW_HOURS if deep else _src.DEFAULT_SEARCH_WINDOW_HOURS
    include_internal_evidence = bool(raw_filters.pop("include_internal_evidence", False))
    filters = _src.normalize_search_filters(default_window_hours=window, **raw_filters)
    # This flag is never accepted from an HTTP query. It is set only by
    # server-side investigation/redaction consumers that need bounded raw
    # identifiers to build pivots or immediately redact them.
    filters["include_internal_evidence"] = include_internal_evidence
    if deep and _src._fact_history.primary_read_enabled():
        cutoff = _src.datetime.now(_src.timezone.utc) - _src.timedelta(days=_src.load_storage_policy().db_retention_days)
        lower = filters.get("time_from")
        if lower is None or _src.datetime.fromisoformat(str(lower).replace("Z", "+00:00")) < cutoff:
            result = _src._empty_search_result(
                filters, mode="deep",
                warning="Исходный текст старше 7 суток удалён; ищите по сохранённым фактам и связям.",
            )
            result["query_status"] = "unavailable"
            return result
    if deep:
        filters["limit"] = min(filters["limit"], 200)
    if deep and not (filters.get("q") or filters.get("account")):
        return _src._empty_search_result(filters, mode="deep", warning="Для глубокого поиска нужен текст запроса.")
    timeout_ms = _src.DEEP_SEARCH_TIMEOUT_MS if deep else _src.FAST_SEARCH_TIMEOUT_MS
    semantic_scan_truncated = False
    semantic_budget_exhausted = False
    semantic_query_count = 0
    try:
        if filters.get("risk") or filters.get("tier") or filters.get("category"):
            items, has_more, next_cursor, semantic_scan_truncated, semantic_budget_exhausted, semantic_query_count = _src._semantic_filtered_slice(
                deep=deep,
                filters=filters,
                timeout_ms=timeout_ms,
                authorization=authorization,
            )
        else:
            fetch_limit = filters["limit"] + 1
            rows = _src._query_event_rows_batch(
                deep=deep,
                filters=filters,
                fetch_limit=fetch_limit,
                timeout_ms=timeout_ms,
                authorization=authorization,
            )
            has_more = len(rows) > filters["limit"]
            visible_rows = rows[: filters["limit"]]
            items = [
                (
                    _src._normalize_search_row(row, include_internal_evidence=True)
                    if include_internal_evidence
                    else _src._normalize_search_row(row)
                )
                for row in visible_rows
            ]
            next_cursor = _src.encode_search_cursor(visible_rows[-1]) if has_more and visible_rows else None
        items = _src._attach_relation_counts(
            items,
            timeout_ms=timeout_ms,
            authorization=authorization,
        )
        status = "ok"
        warning = (
            "Семантический фильтр достиг лимита запросов или времени; продолжите со следующей страницы."
            if semantic_budget_exhausted
            else "Семантический фильтр достиг лимита сканирования; продолжите со следующей страницы."
            if semantic_scan_truncated
            else None
        )
    except (_src.QueryTimeoutError, _src.ArchiveIntegrityError, KeyError, ValueError) as exc:
        items = []
        has_more = False
        next_cursor = None
        status = "timeout"
        warning = str(exc)
    mode = "deep" if deep else "fast"
    _src._logging.log_event(
        "reports",
        "event_search_requested",
        "Bounded event search requested.",
        mode=mode,
        q=filters.get("q"),
        account=filters.get("account"),
        returned=len(items),
        has_more=has_more,
        query_status=status,
    )
    return {
        "filters": filters,
        "mode": mode,
        "query_status": status,
        "warning": warning,
        "total": None,
        "total_is_exact": False,
        "returned_count": len(items),
        "has_more": has_more,
        "truncated": has_more,
        "next_cursor": next_cursor,
        "items": items,
        "facets": {},
        "facets_computed": False,
        "performance": {
            "bounded": True,
            "statement_timeout_ms": timeout_ms,
            "limit_plus_one": True,
            "pagination": "keyset",
            "automatic_exact_count": False,
            "automatic_facets": False,
            "payload_scan": deep,
            "semantic_filter_before_page": bool(filters.get("risk") or filters.get("tier") or filters.get("category")),
            "semantic_scan_limit": _src.SEMANTIC_FILTER_SCAN_LIMIT,
            "semantic_scan_truncated": semantic_scan_truncated,
            "semantic_query_budget": _src.SEMANTIC_FILTER_QUERY_BUDGET,
            "semantic_query_count": semantic_query_count,
            "semantic_budget_exhausted": semantic_budget_exhausted,
            "semantic_source": "v1_payload" if filters.get("risk") or filters.get("tier") or filters.get("category") else "primary",
        },
    }


def _semantic_filtered_slice(
    *,
    deep: bool,
    filters: dict[str, _src.Any],
    timeout_ms: int,
    authorization: _src.CutoverAuthorization | None,
) -> tuple[list[dict[str, _src.Any]], bool, str | None, bool, bool, int]:
    """Apply semantic filters before the public page boundary.

    Semantics depend on normalized event fields and cannot be expressed as a
    second, divergent SQL heuristic.  Bounded keyset scanning therefore keeps
    reading physical pages until it has ``limit + 1`` matching events or hits
    the explicit scan cap.  The continuation cursor always advances past the
    rows already examined, so matches are never silently discarded.
    """
    public_limit = int(filters["limit"])
    batch_size = min(_src.MAX_SEARCH_LIMIT, max(_src.SEMANTIC_FILTER_BATCH_MIN, public_limit * 4))
    working = dict(filters)
    matches: list[tuple[dict[str, _src.Any], dict[str, _src.Any]]] = []
    scanned = 0
    last_scanned: dict[str, _src.Any] | None = None
    source_exhausted = False
    budget_exhausted = False
    query_count = 0
    deadline = _src.time.monotonic() + ((timeout_ms + 1000) / 1000)

    while scanned < _src.SEMANTIC_FILTER_SCAN_LIMIT and len(matches) <= public_limit:
        if query_count >= _src.SEMANTIC_FILTER_QUERY_BUDGET or _src.time.monotonic() >= deadline:
            budget_exhausted = True
            break
        remaining = _src.SEMANTIC_FILTER_SCAN_LIMIT - scanned
        current_batch = min(batch_size, remaining)
        remaining_ms = max(100, int((deadline - _src.time.monotonic()) * 1000))
        rows = _src._query_event_rows_batch(
            deep=deep,
            filters=working,
            fetch_limit=current_batch,
            timeout_ms=min(timeout_ms, remaining_ms),
            authorization=authorization,
        )
        query_count += 1
        if not rows:
            source_exhausted = True
            break
        for row in rows:
            if filters.get("include_internal_evidence"):
                item = _src._normalize_search_row(row, include_internal_evidence=True)
            else:
                item = _src._normalize_search_row(row)
            scanned += 1
            last_scanned = row
            if _src._semantic_filter_matches(item, filters):
                matches.append((row, item))
                if len(matches) > public_limit:
                    break
        if len(matches) > public_limit:
            break
        if len(rows) < current_batch:
            source_exhausted = True
            break
        cursor = _src.encode_search_cursor(rows[-1])
        if not cursor:
            source_exhausted = True
            break
        working["cursor"] = cursor
        working["cursor_values"] = _src.decode_search_cursor(cursor)

    scan_truncated = not source_exhausted and scanned >= _src.SEMANTIC_FILTER_SCAN_LIMIT
    has_more = len(matches) > public_limit or scan_truncated or budget_exhausted
    visible = matches[:public_limit]
    items = [item for _, item in visible]
    if not has_more:
        next_cursor = None
    elif len(matches) > public_limit and visible:
        next_cursor = _src.encode_search_cursor(visible[-1][0])
    else:
        next_cursor = _src.encode_search_cursor(last_scanned or {})
    return items, has_more, next_cursor, scan_truncated, budget_exhausted, query_count


def _event_category_counts(
    filters: dict[str, _src.Any],
    *,
    timeout_ms: int,
    authorization: _src.CutoverAuthorization | None = None,
) -> dict[str, int] | None:
    """Count the five UI tabs over the same physical filter window.

    Category predicates are the same conservative Event ID/channel families
    used before pagination.  The attention set is compiled from the canonical
    catalogue entries whose purpose tier is critical or whose base severity
    normalizes to critical/high.
    """
    base_filters = {**filters, "category": None, "tier": None, "risk": None, "cursor": None, "cursor_values": None}
    _src._v2_primary_read_enabled_for_request(authorization)
    if _src._fact_history.primary_read_enabled():
        # The PostgreSQL count excludes events removed after permanent publication.
        # Hide the aggregate until a matching ClickHouse aggregate is available.
        return None
    where_sql, where_params = _src._v2_handler_where_clause(base_filters, account_timeline=False)
    source_sql = """events_v2_core e
        join servers s on s.id=e.server_id
        join storage_v2_channel channel on channel.id=e.channel_id
        left join storage_v2_provider provider on provider.id=e.provider_id"""
    channel_sql = "channel.value"
    attention_ids = sorted({
        int(entry.get("event_id") or 0)
        for entry in _src.all_event_catalog_entries()
        if int(entry.get("event_id") or 0) > 0 and (
            str(entry.get("purpose_tier") or "").lower() == "critical"
            or str(entry.get("base_risk") or entry.get("severity") or "").lower() in {"critical", "high"}
        )
    })
    auth_ids = sorted(_src.AUTHENTICATION_EVENT_IDS)
    account_ids = sorted(_src.ACCOUNT_MANAGEMENT_EVENT_IDS)
    service_ids = sorted(_src.SERVICE_TASK_EVENT_IDS)
    placeholders = lambda values: ",".join("?" for _ in values) or "null"
    try:
        rows = _src._database.query_rows_bounded(
            f"""
            select
              count(*) as all_count,
              sum(case when e.event_id in ({placeholders(attention_ids)}) then 1 else 0 end) as attention_count,
              sum(case when e.event_id in ({placeholders(auth_ids)}) then 1 else 0 end) as authentication_count,
              sum(case when e.event_id in ({placeholders(account_ids)}) then 1 else 0 end) as accounts_count,
              sum(case when lower(coalesce({channel_sql}, '')) like ? or e.event_id in ({placeholders(service_ids)}) then 1 else 0 end) as tasks_count
            from {source_sql}
            {where_sql}
            """,
            tuple([*attention_ids, *auth_ids, *account_ids, "%taskscheduler%", *service_ids, *where_params]),
            statement_timeout_ms=min(timeout_ms, 5000),
            wall_timeout_ms=min(timeout_ms, 5000) + 1000,
        )
    except _src.QueryTimeoutError:
        return None
    row = rows[0] if rows else {}
    return {
        "attention": int(row.get("attention_count") or 0),
        "authentication": int(row.get("authentication_count") or 0),
        "accounts": int(row.get("accounts_count") or 0),
        "tasks": int(row.get("tasks_count") or 0),
        "all": int(row.get("all_count") or 0),
    }
