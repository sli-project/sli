from __future__ import annotations

from server.sli.events import event_search


def test_account_timeline_uses_one_bounded_index_friendly_query(monkeypatch) -> None:
    calls: list[tuple[str, tuple]] = []

    def fake_query_rows(sql: str, params: tuple = (), **kwargs):
        calls.append((sql, params))
        return []

    monkeypatch.setattr("server.sli.core.database.query_rows_bounded", fake_query_rows)
    monkeypatch.setattr("server.sli.ops.logging_config.log_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(event_search, "_v2_primary_read_enabled", lambda: False)

    data = event_search.get_account_timeline_data(
        q="__html_audit_no_match__",
        limit=20,
        order="asc",
    )

    assert data["total"] is None
    assert data["total_is_exact"] is False
    assert data["returned_count"] == 0
    assert data["truncated"] is False
    assert data["facets"] == {}
    assert len(calls) == 1

    sql, params = calls[0]
    normalized_sql = " ".join(sql.lower().split())
    assert "count(*)" not in normalized_sql
    assert "group by" not in normalized_sql
    assert "event_data_json like" not in normalized_sql
    assert "message_text like" not in normalized_sql
    assert "lower(coalesce(e.subject_user_name, '')) in" in normalized_sql
    assert "lower(coalesce(e.target_user_name, '')) in" in normalized_sql
    assert "limit ?" in normalized_sql
    assert "offset" not in normalized_sql
    assert params[-1:] == (21,)


def test_account_timeline_normalizes_domain_and_upn_without_wildcards() -> None:
    assert event_search._account_exact_values("EXAMPLE\\alice") == [
        "example\\alice",
        "alice",
    ]
    assert event_search._account_exact_values("alice@host13.example.invalid") == [
        "alice@host13.example.invalid",
        "alice",
    ]


def test_empty_account_timeline_does_not_query_database(monkeypatch) -> None:
    monkeypatch.setattr("server.sli.core.database.query_rows_bounded",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("query must not run")),
    )
    data = event_search.get_account_timeline_data(q="")
    assert data["account"] == ""
    assert data["chain"] == []
    assert data["summary"]["total"] == 0
