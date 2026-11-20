"""History readers must work with only published facts, links and PG identities."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from server.sli.events import event_details, event_search
from server.sli.semantic import account_watch_projection
from server.sli.storage import permanent_fact_history as history


@pytest.fixture
def retained(monkeypatch, tmp_path):
    core = {
        "id": 41, "event_id": 4624, "server_id": 3,
        "time_created_utc": "2020-01-01T00:00:00+00:00",
        "normalized_hash": "61" * 32, "noise_class": "",
        "subject_user_name": "fixture-subject", "target_user_name": "fixture-target",
        "channel": "Security", "provider_name": "Microsoft-Windows-Security-Auditing",
    }
    facts = {"logon_type": 3}
    event = {
        "event_db_id": 41, "event_key": 4624, "server_id": 3, "noise_class": "",
        "time_created_utc": "2020-01-01 00:00:00.000000",
        "core_json": json.dumps(core), "facts_json": json.dumps(facts),
        "row_sha256": history._payload_sha({"core": core, "facts": facts}),
        "batch_sha256": "a" * 64,
    }
    detail = {"event_id": 41, "entity_id": 5, "link_role": "subject", "role_id": 2}
    link = {
        "event_db_id": 41, "entity_id": 5, "link_role": "subject",
        "time_created_utc": event["time_created_utc"], "details_json": json.dumps(detail),
        "row_sha256": history._payload_sha(detail), "batch_sha256": "a" * 64,
    }

    def rows(port, sql, **kw):
        if "FROM sli_history.published_batches" in sql and "FROM sli_history.events" not in sql:
            return [{"batch_sha256": "a" * 64, "first_event_db_id": 41, "last_event_db_id": 41}]
        if "FROM sli_history.links" in sql:
            return [link]
        assert "FROM sli_history.events" in sql
        return [event]

    monkeypatch.setattr(history, "_rows", rows)
    monkeypatch.setattr(history, "primary_read_enabled", lambda: True)
    monkeypatch.setattr(event_details, "primary_read_enabled", lambda: True)
    monkeypatch.setattr(event_details, "configured_read_port", lambda: 8123)
    monkeypatch.setattr(event_details, "_v2_detail_route_selected", lambda *a, **kw: True)
    monkeypatch.setattr(event_details, "load_storage_policy", lambda: SimpleNamespace(db_retention_days=7))
    monkeypatch.setattr(event_details, "PostgresStorageV2ReadStore",
                        lambda *a: SimpleNamespace(get_event_summary=lambda event_id: None))
    monkeypatch.setattr(event_details, "query_rows", lambda *a, **kw: [{"server": "fixture-source"}])
    def priorities(sql, params, **kw):
        assert "public.account_watch_event_priority" in sql
        assert params == (41, "61" * 32)
        return [{"id": 41, "watch_priority": None}]

    monkeypatch.setattr(account_watch_projection, "query_rows_bounded", priorities)
    monkeypatch.setattr(event_details, "log_event", lambda *a, **kw: None)
    monkeypatch.setattr(event_details, "ArchiveReader", lambda *a, **kw: pytest.fail("raw archive read"))
    monkeypatch.setattr(event_search, "ArchiveReader", lambda *a, **kw: pytest.fail("raw search"))
    return event, rows, detail


def test_card_and_report_keep_facts_and_links_without_raw_or_hot_event(retained):
    event, _, detail = retained
    data = event_details.get_event_detail_report_data(event_db_id=41)
    item = data["items"][0]
    assert data["total"] == 1
    assert item["source_payload_state"] == "expired"
    assert item["retained_facts"] == {"logon_type": 3}
    assert item["record_xml"] is None and not item["message_text"] and not item["event_data"]
    assert history.read_published_links(8123, 41) == [detail]
    html = event_details.render_event_detail_report(data)
    assert "Исходный текст удалён по сроку хранения" in html
    assert "Сохранённые факты" in html
    assert "fixture-target" in html and "logon_type" in html
    assert event["facts_json"] == json.dumps({"logon_type": 3})


def test_historical_search_uses_facts_without_hot_rows_or_archive(retained, monkeypatch):
    _, rows, _ = retained
    queries = []

    def search_rows(port, sql, **kw):
        queries.append(sql)
        return rows(port, sql, **kw)

    monkeypatch.setattr(event_search, "_history_rows", search_rows)
    monkeypatch.setattr(event_search, "configured_read_port", lambda: 8123)
    monkeypatch.setattr(event_search, "load_storage_policy", lambda: SimpleNamespace(db_retention_days=7))
    monkeypatch.setattr(event_search, "_query_v2_postgres_event_rows", lambda *a, **kw: pytest.fail("hot events read"))
    monkeypatch.setattr(event_search._database, "query_rows_bounded",
                        lambda *a, **kw: [{"id": 3, "hostname": "fixture-source"}])
    filters = event_search.normalize_search_filters(
        q="fixture-subject", time_from="2020-01-01T00:00:00Z", time_to="2020-01-02T00:00:00Z",
    )
    found = event_search._query_v2_event_rows(filters, 10, 1000, account_timeline=False)
    assert found[0]["source_payload_state"] == "expired"
    assert found[0]["logon_type"] == 3 and found[0]["id"] == 41
    assert found[0]["server"] == "fixture-source"
    assert "sli_history.published_batches" in queries[0]
    assert "record_xml" not in queries[0]


@pytest.mark.parametrize("failure", ["hash", "count", "readback"])
def test_preservation_guard_rejects_mismatched_hash_count_or_readback(monkeypatch, failure):
    events = [{"event_db_id": 41, "core_json": json.dumps({
        "normalized_hash": "62" * 32 if failure == "hash" else "61" * 32,
    })}]
    monkeypatch.setattr(history, "_source_batch", lambda *a, **kw: ([] if failure == "count" else events, []))
    monkeypatch.setattr(history, "_readback", lambda *a, **kw: (set(), set(), {}))
    reason = {"hash": "source_hash_changed", "count": "source_count_mismatch", "readback": "history_incomplete"}[failure]
    with pytest.raises(RuntimeError, match=reason):
        history.verify_preserved_candidates(8123, [{"id": 41, "normalized_hash": b"a" * 32}])
