from __future__ import annotations

from http import HTTPStatus
from types import SimpleNamespace

import pytest

from server.api.routes import events
from server.sli.core.database import QueryTimeoutError
from server.sli.reporting import ui_workspace


@pytest.mark.parametrize("timeout_query", [1, 2])
def test_entities_timeout_is_unavailable_and_can_recover(monkeypatch, timeout_query):
    monkeypatch.setattr(ui_workspace, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(ui_workspace, "primary_read_enabled", lambda: False)
    calls = []
    timed_out = False

    def query(sql, params, **kwargs):
        nonlocal timed_out
        calls.append((sql, params, kwargs))
        assert kwargs["statement_timeout_ms"] == 3000
        if len(calls) == timeout_query:
            timed_out = True
            raise QueryTimeoutError("synthetic-query-detail", timeout_ms=3000)
        if "select 1 as present" in sql:
            return [{"present": 1, "time_created_utc": "2026-10-04T00:00:00Z"}]
        return [{"id": 7, "type": "ad_user", "natural_key": "fixture-entity", "link_role": "target", "confidence": 1.0}]

    monkeypatch.setattr(ui_workspace, "query_rows_bounded", query)
    sent = []
    handler = SimpleNamespace(_send_json=lambda payload, status=HTTPStatus.OK: sent.append((payload, status)))

    assert events.try_handle_get(handler, "/api/v1/events/42/entities", {})
    payload, status = sent[-1]
    assert timed_out
    assert status == HTTPStatus.OK
    assert payload["api_version"] == "v1"
    assert payload["event_db_id"] == 42
    assert payload["event_found"] is None
    assert payload["evidence_status"] == "timeout"
    assert payload["items"] == []
    assert payload["limit"] == ui_workspace.EVENT_ENTITY_LIMIT
    assert "временно недоступны" in payload["warning"]
    assert "synthetic-query-detail" not in str(payload)

    assert events.try_handle_get(handler, "/api/v1/events/42/entities", {})
    recovered, status = sent[-1]
    assert status == HTTPStatus.OK
    assert recovered["event_found"] is True
    assert recovered["evidence_status"] == "present"
    assert recovered["items"][0]["id"] == 7


@pytest.mark.parametrize("event_found", [True, False])
def test_entities_empty_and_missing_event_keep_distinct_states(monkeypatch, event_found):
    monkeypatch.setattr(ui_workspace, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(ui_workspace, "primary_read_enabled", lambda: False)
    monkeypatch.setattr(ui_workspace, "query_rows_bounded", lambda sql, *_args, **_kwargs: (
        [{"present": 1}] if event_found and "select 1 as present" in sql else []
    ))
    sent = []
    handler = SimpleNamespace(_send_json=lambda payload, status=HTTPStatus.OK: sent.append((payload, status)))

    events.try_handle_get(handler, "/api/v1/events/42/entities", {})
    payload, status = sent[-1]
    assert status == HTTPStatus.OK
    assert payload["event_found"] is event_found
    assert payload["evidence_status"] == ("zero_extracted" if event_found else "event_not_found")


def test_entities_does_not_hide_unexpected_failures(monkeypatch):
    def fail(**_kwargs):
        raise RuntimeError("synthetic-unexpected-failure")

    monkeypatch.setattr(events, "get_event_entities_data", fail)
    with pytest.raises(RuntimeError, match="synthetic-unexpected-failure"):
        events.try_handle_get(SimpleNamespace(), "/api/v1/events/42/entities", {})
