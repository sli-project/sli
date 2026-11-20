"""Split out of ``server.sli.events.event_search`` (plan 7.2b).

Module-level names of ``event_search`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.events.event_search as _src


def get_account_timeline_data(
    *,
    authorization: _src.CutoverAuthorization | None = None,
    **raw_filters: _src.Any,
) -> dict[str, _src.Any]:
    if "db_path" in raw_filters:
        raise TypeError("get_account_timeline_data() got an unexpected keyword argument 'db_path'")
    raw_q = raw_filters.get("q") or raw_filters.get("account")
    account = str(raw_q or "").strip()
    filters = _src.normalize_search_filters(
        q=None,
        account=account,
        event_ids=raw_filters.get("event_ids") or _src.IMPORTANT_ACCOUNT_EVENT_IDS,
        channel=raw_filters.get("channel"),
        servers=raw_filters.get("servers"),
        limit=raw_filters.get("limit") or 500,
        offset=raw_filters.get("offset") or 0,
        cursor=raw_filters.get("cursor"),
        time_from=raw_filters.get("time_from"),
        time_to=raw_filters.get("time_to"),
        timezone_name=raw_filters.get("timezone_name") or "UTC",
        order=raw_filters.get("order") or "desc",
    )
    if not account:
        empty = _src._empty_search_result(filters, mode="account_timeline")
        return {
            **empty,
            "account": "",
            "summary": _src._timeline_summary([]),
            "chain": [],
        }

    fetch_limit = filters["limit"] + 1
    try:
        _src._v2_primary_read_enabled_for_request(authorization)
        rows = _src._query_v2_event_rows(
            filters,
            fetch_limit,
            _src.ACCOUNT_TIMELINE_TIMEOUT_MS,
            account_timeline=True,
        )
        from server.sli.semantic.account_watch_projection import attach_event_priorities

        rows = attach_event_priorities(rows)
        has_more = len(rows) > filters["limit"]
        visible_rows = rows[: filters["limit"]]
        items = [_src._normalize_search_row(row) for row in visible_rows]
        next_cursor = _src.encode_search_cursor(visible_rows[-1]) if has_more and visible_rows else None
        status = "ok"
        warning = None
    except _src.QueryTimeoutError as exc:
        items = []
        has_more = False
        next_cursor = None
        status = "timeout"
        warning = str(exc)
    _src._logging.log_event(
        "reports",
        "account_timeline_requested",
        "Account timeline requested through one bounded normalized query.",
        account=account,
        returned=len(items),
        has_more=has_more,
        query_status=status,
    )
    return {
        "filters": filters,
        "mode": "account_timeline",
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
        "account": account,
        "summary": _src._timeline_summary(items),
        "chain": [_src._timeline_item(row) for row in items],
        "performance": {
            "bounded": True,
            "statement_timeout_ms": _src.ACCOUNT_TIMELINE_TIMEOUT_MS,
            "limit_plus_one": True,
            "pagination": "keyset",
            "automatic_exact_count": False,
            "automatic_facets": False,
            "payload_scan": False,
        },
    }
