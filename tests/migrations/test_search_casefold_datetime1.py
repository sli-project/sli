from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest


def test_local_calendar_day_is_end_exclusive_and_dst_aware() -> None:
    from server.sli.core.time_contract import normalize_utc_range

    spring_start, spring_end = normalize_utc_range(
        "2026-03-29", "2026-03-29", timezone_name="Europe/Helsinki"
    )
    assert spring_start == "2026-03-28T22:00:00Z"
    assert spring_end == "2026-03-29T21:00:00Z"
    assert (
        datetime.fromisoformat(spring_end.replace("Z", "+00:00"))
        - datetime.fromisoformat(spring_start.replace("Z", "+00:00"))
    ).total_seconds() == 23 * 3600

    fall_start, fall_end = normalize_utc_range(
        "2026-10-25", "2026-10-25", timezone_name="Europe/Helsinki"
    )
    assert (
        datetime.fromisoformat(fall_end.replace("Z", "+00:00"))
        - datetime.fromisoformat(fall_start.replace("Z", "+00:00"))
    ).total_seconds() == 25 * 3600


def test_offset_is_converted_once_and_invalid_ranges_fail_closed() -> None:
    from server.sli.core.time_contract import TimeRangeError, normalize_utc_range

    start, end = normalize_utc_range(
        "2026-07-18T10:15:00+03:00", "2026-07-18T10:16:00+03:00"
    )
    assert start == "2026-07-18T07:15:00Z"
    assert end == "2026-07-18T07:16:00Z"
    with pytest.raises(TimeRangeError, match="empty_or_reversed"):
        normalize_utc_range("2026-07-19", "2026-07-18")
    with pytest.raises(TimeRangeError, match="invalid_timezone"):
        normalize_utc_range("2026-07-18", None, timezone_name="Fixture/Nowhere")


def test_windows_target_zones_have_expected_calendar_boundaries() -> None:
    from server.sli.core.time_contract import normalize_utc_range

    novosibirsk = normalize_utc_range("2026-07-18", "2026-07-18", timezone_name="Asia/Novosibirsk")
    moscow = normalize_utc_range("2026-07-18", "2026-07-18", timezone_name="Europe/Moscow")
    assert novosibirsk == ("2026-07-17T17:00:00Z", "2026-07-18T17:00:00Z")
    assert moscow == ("2026-07-17T21:00:00Z", "2026-07-18T21:00:00Z")


def test_ambiguous_or_nonexistent_dst_wall_time_requires_an_explicit_offset() -> None:
    from server.sli.core.time_contract import TimeRangeError, normalize_utc_range

    with pytest.raises(TimeRangeError, match="nonexistent_local_datetime"):
        normalize_utc_range("2026-03-29T03:30:00", None, timezone_name="Europe/Helsinki")
    with pytest.raises(TimeRangeError, match="ambiguous_local_datetime_requires_offset"):
        normalize_utc_range("2026-10-25T03:30:00", None, timezone_name="Europe/Helsinki")
    explicit, _ = normalize_utc_range(
        "2026-10-25T03:30:00+03:00", None, timezone_name="Europe/Helsinki"
    )
    assert explicit == "2026-10-25T00:30:00Z"


def test_search_uses_exclusive_upper_bound_without_casting_time_column() -> None:
    from server.sli.events.event_search import _common_filter_parts, normalize_search_filters

    filters = normalize_search_filters(
        time_from="2026-07-18", time_to="2026-07-18", timezone_name="UTC"
    )
    parts, params = _common_filter_parts(filters)
    sql = " ".join(parts).lower()
    assert "e.time_created_utc < ?" in sql
    assert "cast(e.time_created_utc" not in sql and "date(e.time_created_utc" not in sql
    assert params[-1] == "2026-07-19T00:00:00Z"


def test_entity_lookup_is_case_insensitive_exact_or_prefix_only(monkeypatch) -> None:
    """Contract test: the lookup asks PostgreSQL for a case-insensitive exact-or-prefix match.

    The former SQLite version executed the SQL; that comparison semantics (lower() on
    both sides) is a database behaviour and belongs to a postgres_integration test.
    Here we pin what the code sends: lower() comparisons, no substring LIKE, and a
    casefolded prefix parameter.
    """
    from server.sli.entities import entity_details
    from server.sli.entities.entity_details import _resolve_entity, normalize_entity_filters

    stored = {"id": 1, "display_name": r"EXAMPLE\Dc-Fixture"}
    calls: list[tuple[str, tuple]] = []

    def fake_query_rows(sql, params=()):
        calls.append((" ".join(sql.split()).lower(), tuple(params)))
        return [stored]

    monkeypatch.setattr(entity_details, "query_rows", fake_query_rows)
    exact = _resolve_entity(normalize_entity_filters(q="example\\DC-FIXTURE"))
    prefix = _resolve_entity(normalize_entity_filters(q="example\\dc-fix"))

    assert exact == stored and prefix == stored
    sql, params = calls[0]
    assert "lower(entity.natural_key) = lower(?)" in sql
    assert "lower(coalesce(entity.display_name,'')) = lower(?)" in sql
    assert "like ?" in sql and "'%" not in sql
    assert params[:2] == ("example\\DC-FIXTURE", "example\\DC-FIXTURE")
    assert params[2:4] == ("example\\dc-fixture%", "example\\dc-fixture%")
    assert calls[1][1][2] == "example\\dc-fix%"


def test_casefold_migration_covers_v1_v2_events_and_entities() -> None:
    sql = Path("config/postgres_migrations/020_casefold_search_indexes.sql").read_text(encoding="utf-8").lower()
    rollback = Path("config/postgres_migrations/020_casefold_search_indexes.rollback.sql").read_text(encoding="utf-8").lower()
    for token in ("events_subject_casefold", "events_target_casefold", "entities_natural_casefold", "events_v2_subject_casefold", "entities_v2_natural_casefold", "text_pattern_ops"):
        assert token in sql
    assert "drop index" in rollback
    entity_source = Path("server/sli/entities/entity_details.py").read_text(encoding="utf-8")
    assert 'f"%{q}%"' not in entity_source


def test_account_timeline_and_investigation_forward_timezone_to_one_boundary(monkeypatch) -> None:
    from server.sli.events import event_search
    from server.sli.semantic import investigation

    timeline_filters = []
    monkeypatch.setattr("server.sli.core.database.query_rows_bounded", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(event_search, "_v2_primary_read_enabled", lambda: False)
    data = event_search.get_account_timeline_data(
        q="fixture", time_from="2026-03-29", time_to="2026-03-29",
        timezone_name="Europe/Helsinki",
    )
    assert data["filters"]["time_from"] == "2026-03-28T22:00:00Z"
    assert data["filters"]["time_to"] == "2026-03-29T21:00:00Z"

    def fake_search(**kwargs):
        timeline_filters.append(kwargs)
        return {"items": [], "returned_count": 0, "total": None, "total_is_exact": False, "has_more": False}

    monkeypatch.setattr(investigation, "get_event_search_data", fake_search)
    monkeypatch.setattr(investigation, "get_findings_data", lambda **_kwargs: {"items": [], "summary": []})
    investigation.get_investigation_workspace_data(
        q="fixture", time_from="2026-03-29", time_to="2026-03-29",
        timezone_name="Europe/Helsinki",
    )
    assert timeline_filters[0]["timezone_name"] == "Europe/Helsinki"
