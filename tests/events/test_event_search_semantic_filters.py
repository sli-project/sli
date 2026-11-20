from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _skip_relation_projection(monkeypatch):
    from server.sli.events import event_search

    monkeypatch.setattr(event_search, "_attach_relation_counts", lambda items, **_kwargs: items)


def _row(row_id: int) -> dict:
    return {
        "id": row_id,
        "event_id": 4624,
        "event_record_id": row_id,
        "time_created_utc": f"2026-07-17T00:{row_id // 60:02d}:{row_id % 60:02d}Z",
    }


def test_risk_filter_uses_decorated_semantic_rows(monkeypatch) -> None:
    from server.sli.events import event_search

    monkeypatch.setattr("server.sli.core.database.query_rows_bounded", lambda *args, **kwargs: [{"id": 1}, {"id": 2}])
    monkeypatch.setattr(
        event_search,
        "_normalize_search_row",
        lambda row: {"event_db_id": row["id"], "severity": "high" if row["id"] == 1 else "low", "tier": "security"},
    )

    result = event_search.get_event_search_data(limit=10, risk="high")

    assert [item["event_db_id"] for item in result["items"]] == [1]
    assert result["filters"]["risk"] == "high"


def test_tier_filter_uses_decorated_semantic_rows(monkeypatch) -> None:
    from server.sli.events import event_search

    monkeypatch.setattr("server.sli.core.database.query_rows_bounded", lambda *args, **kwargs: [{"id": 1}, {"id": 2}])
    monkeypatch.setattr(
        event_search,
        "_normalize_search_row",
        lambda row: {"event_db_id": row["id"], "severity": "low", "tier": "security" if row["id"] == 1 else "operations"},
    )

    result = event_search.get_event_search_data(limit=10, tier="operations")

    assert [item["event_db_id"] for item in result["items"]] == [2]


def test_category_filter_uses_canonical_semantics_before_page_boundary(monkeypatch) -> None:
    from server.sli.events import event_search

    monkeypatch.setattr("server.sli.core.database.query_rows_bounded", lambda *args, **kwargs: [{"id": 1}, {"id": 2}])
    monkeypatch.setattr(
        event_search,
        "_normalize_search_row",
        lambda row: {
            "event_db_id": row["id"],
            "severity": "info",
            "tier": "technical",
            "category": "authentication" if row["id"] == 1 else "account_management",
        },
    )

    result = event_search.get_event_search_data(limit=10, category="accounts")

    assert [item["event_db_id"] for item in result["items"]] == [2]
    assert result["filters"]["category"] == "account_management"
    assert result["performance"]["semantic_filter_before_page"] is True


def test_known_catalog_rows_without_category_use_backend_event_family() -> None:
    from server.sli.events import event_search

    assert event_search._fallback_event_category({"event_id": 4625, "channel": "Security"}) == "authentication"
    assert event_search._fallback_event_category({"event_id": 4722, "channel": "Security"}) == "account_management"
    assert event_search._fallback_event_category({"event_id": 140, "channel": "Microsoft-Windows-TaskScheduler/Operational"}) == "service_task"


def test_multiple_risk_filter_is_an_or_selection() -> None:
    from server.sli.events import event_search

    filters = {"risk": "critical,high", "tier": "", "category": ""}

    assert event_search._semantic_filter_matches({"severity": "critical"}, filters)
    assert event_search._semantic_filter_matches({"severity": "high"}, filters)
    assert not event_search._semantic_filter_matches({"severity": "medium"}, filters)


def test_semantic_filter_scans_past_first_physical_page(monkeypatch) -> None:
    from server.sli.events import event_search

    calls = 0

    def fake_query(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return [_row(row_id) for row_id in range(400, 200, -1)]
        return [_row(200)]

    monkeypatch.setattr("server.sli.core.database.query_rows_bounded", fake_query)
    monkeypatch.setattr(event_search, "_v2_primary_read_enabled", lambda: False)
    monkeypatch.setattr(
        event_search,
        "_normalize_search_row",
        lambda row: {
            "event_db_id": row["id"],
            "severity": "high" if row["id"] == 200 else "low",
            "tier": "security",
        },
    )

    result = event_search.get_event_search_data(limit=1, risk="high")

    assert calls == 2
    assert [item["event_db_id"] for item in result["items"]] == [200]
    assert result["has_more"] is False
    assert result["next_cursor"] is None
    assert result["performance"]["semantic_filter_before_page"] is True


def test_semantic_cursor_pages_do_not_duplicate_or_skip_matches(monkeypatch) -> None:
    from server.sli.events import event_search

    rows = [_row(row_id) for row_id in (5, 4, 3, 2, 1)]

    def batch(*, filters, **_kwargs):
        cursor = (filters.get("cursor_values") or {}).get("id")
        return [row for row in rows if cursor is None or row["id"] < cursor]

    monkeypatch.setattr(event_search, "_query_event_rows_batch", batch)
    monkeypatch.setattr(
        event_search,
        "_normalize_search_row",
        lambda row: {"event_db_id": row["id"], "severity": "high" if row["id"] in {5, 3, 2} else "low", "tier": "important"},
    )

    first = event_search.get_event_search_data(limit=2, risk="high")
    second = event_search.get_event_search_data(limit=2, risk="high", cursor=first["next_cursor"])

    assert [item["event_db_id"] for item in first["items"]] == [5, 3]
    assert [item["event_db_id"] for item in second["items"]] == [2]
    assert first["has_more"] is True
    assert second["has_more"] is False


def test_semantic_scan_cap_returns_advancing_cursor_and_preserves_filters(monkeypatch) -> None:
    from server.sli.events import event_search

    monkeypatch.setattr(event_search, "SEMANTIC_FILTER_SCAN_LIMIT", 4)
    monkeypatch.setattr(event_search, "_query_event_rows_batch", lambda **_kwargs: [_row(value) for value in (8, 7, 6, 5)])
    monkeypatch.setattr(event_search, "_normalize_search_row", lambda row: {"event_db_id": row["id"], "severity": "low", "tier": "technical"})

    result = event_search.get_event_search_data(limit=1, risk="high", tier="important")
    url = event_search._next_page_url(result, route="search")

    assert result["items"] == []
    assert result["has_more"] is True
    assert result["next_cursor"]
    assert result["performance"]["semantic_scan_truncated"] is True
    assert "risk=high" in url
    assert "tier=important" in url


def test_semantic_scan_stops_at_fixed_query_budget(monkeypatch) -> None:
    from server.sli.events import event_search

    calls = 0

    def batch(**_kwargs):
        nonlocal calls
        calls += 1
        return [_row(calls * 1000 - offset) for offset in range(200)]

    monkeypatch.setattr(event_search, "_query_event_rows_batch", batch)
    monkeypatch.setattr(event_search, "_normalize_search_row", lambda row: {"event_db_id": row["id"], "severity": "low", "tier": "technical"})

    result = event_search.get_event_search_data(limit=1, risk="high")

    assert calls == event_search.SEMANTIC_FILTER_QUERY_BUDGET
    assert result["has_more"] is True
    assert result["performance"]["semantic_budget_exhausted"] is True
    assert result["performance"]["semantic_query_count"] == calls


def test_v2_primary_does_not_read_v1_and_semantic_filters_use_v2_facts(monkeypatch) -> None:
    from server.sli.events import event_search

    v1_calls = 0
    v2_calls = 0

    def v1(*_args, **_kwargs):
        nonlocal v1_calls
        v1_calls += 1
        return []

    def v2(*_args, **_kwargs):
        nonlocal v2_calls
        v2_calls += 1
        return []

    monkeypatch.setattr("server.sli.core.database.query_rows_bounded", v1)
    monkeypatch.setattr(event_search, "_query_v2_event_rows", v2)
    monkeypatch.setattr(event_search, "_v2_primary_read_enabled", lambda: True)

    event_search.get_event_search_data(limit=10)
    assert (v1_calls, v2_calls) == (0, 1)

    event_search.get_event_search_data(limit=10, risk="high")
    assert (v1_calls, v2_calls) == (0, 2)


def test_unknown_canonical_risk_cannot_match_legacy_high() -> None:
    from server.sli.events import event_search

    filters = {"risk": "high", "tier": "", "category": ""}
    assert not event_search._semantic_filter_matches(
        {"severity": "high", "final_security_severity": "unknown"}, filters
    )


def test_category_counts_use_same_v2_store_as_event_page(monkeypatch) -> None:
    from server.sli.events import event_search

    captured: list[str] = []

    def fake_query(sql, *_args, **_kwargs):
        captured.append(sql)
        return [{"all_count": 80, "attention_count": 2, "authentication_count": 50, "accounts_count": 3, "tasks_count": 25}]

    monkeypatch.setattr(event_search, "_v2_primary_read_enabled", lambda: True)
    monkeypatch.setattr("server.sli.core.database.query_rows_bounded", fake_query)

    counts = event_search.get_event_category_counts(limit=50)

    assert counts == {"attention": 2, "authentication": 50, "accounts": 3, "tasks": 25, "all": 80}
    assert "from events_v2_core e" in captured[0]
    assert "storage_v2_channel channel" in captured[0]
    assert "channel.value" in captured[0]
