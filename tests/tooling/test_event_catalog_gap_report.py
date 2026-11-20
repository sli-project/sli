from __future__ import annotations

from datetime import datetime, timezone


def test_catalog_gap_query_is_postgres_v2_bounded_and_payload_free(monkeypatch) -> None:
    from scripts.maintenance import find_event_catalog_gaps as report

    calls: list[tuple[str, tuple, dict]] = []

    def rows(sql, params=(), **kwargs):
        calls.append((sql, tuple(params), kwargs))
        return [{
            "channel": "Security", "event_id": 9999, "provider_name": "Provider",
            "count": 12,
            "first_seen": datetime(2026, 7, 16, tzinfo=timezone.utc),
            "last_seen": datetime(2026, 7, 17, tzinfo=timezone.utc),
        }]

    monkeypatch.setattr(report, "query_rows_bounded", rows)
    monkeypatch.setattr(report, "is_postgres_runtime_db", lambda: True)
    result = report._load_event_groups(min_count=2, limit=9000)

    assert result[0]["event_id"] == 9999
    assert result[0]["first_seen"] == "2026-07-16T00:00:00+00:00"
    assert len(calls) == 1
    sql = " ".join(calls[0][0].lower().split())
    assert "from events_v2_core e" in sql
    assert "join storage_v2_channel channel" in sql
    assert "left join storage_v2_provider provider" in sql
    assert "group by channel.value, e.event_id, provider.value" in sql
    assert "from events e" not in sql
    assert "message_text" not in sql
    assert "event_data_json" not in sql
    assert "record_xml" not in sql
    # One extra aggregate identity is read only to prove whether the bounded
    # result is complete or truncated; no payload is selected.
    assert calls[0][1] == (2, 2001)
    assert calls[0][2]["statement_timeout_ms"] == 8000


def test_catalog_gap_query_rejects_non_postgres_runtime(monkeypatch) -> None:
    import pytest

    from scripts.maintenance import find_event_catalog_gaps as report

    monkeypatch.setattr(report, "is_postgres_runtime_db", lambda: False)
    monkeypatch.setattr(
        report,
        "query_rows_bounded",
        lambda *_args, **_kwargs: pytest.fail("query must not run outside PostgreSQL"),
    )

    with pytest.raises(RuntimeError, match="requires the configured PostgreSQL runtime"):
        report._load_event_groups(min_count=1)


def test_catalog_gap_json_contract_declares_no_payload(monkeypatch, capsys) -> None:
    from scripts.maintenance import find_event_catalog_gaps as report

    monkeypatch.setattr(report, "_load_event_groups", lambda *_args: [])
    monkeypatch.setattr("sys.argv", ["find_event_catalog_gaps.py", "--format", "json"])

    assert report.main() == 0
    output = capsys.readouterr().out
    assert '"contains_event_payload": false' in output
    assert '"source": "postgres_storage_v2"' in output
