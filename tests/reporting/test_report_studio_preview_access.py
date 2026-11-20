"""Студия отчётов, backend 2: предпросмотр с реальными строками и сводка доступа (fake-БД)."""
from __future__ import annotations

from http import HTTPStatus

import pytest

from server.api import http_server
from server.api.routes import reports as routes_reports
from server.sli.access.access_control_v4 import route_capability
from server.sli.reporting import reporting_v4
from tests.reporting.test_report_studio_lifecycle import FakeDb

DATASET = {
    "dataset_key": "entities.v2", "version": 1, "name": "Объекты", "object_type": "entity",
    "fields_json": [
        {"key": "display_name", "category": "identity_basic"},
        {"key": "natural_key", "category": "technical"},
    ],
    "filters_json": [], "actions_json": ["export"], "status": "published",
}
GRANT = {
    "source_type": "direct", "source": "user:7", "scope": {"kind": "all"},
    "field_categories": ["identity_basic"], "allowed_actions": ["view"],
}
CAPS = ["reports.design", "field.identity_basic", "field.technical"]


def _access(caps=None, grants=None, owner=False):
    grants = [GRANT] if grants is None else grants
    return {
        "capabilities": list(CAPS if caps is None else caps), "platform_owner": owner,
        "reports": [{
            "report_key": "any.report", "allowed": bool(grants), "dataset_key": "entities.v2",
            "grants": grants,
        }] if grants else [],
    }


def _setup(monkeypatch, row_count=30):
    db = FakeDb(lambda sql, _p: [dict(DATASET)] if "from report_datasets_v4" in sql else [])
    monkeypatch.setattr(reporting_v4, "_connect", lambda: db)
    calls = []

    def fake_rows(sql, params, **_kw):
        calls.append((sql, params))
        return [{"display_name": f"n{i}", "natural_key": f"k{i}"} for i in range(row_count)]

    monkeypatch.setattr(reporting_v4, "query_rows_bounded", fake_rows)
    return calls


PAYLOAD = {"dataset_key": "entities.v2", "fields": ["display_name", "natural_key"]}


def test_without_with_rows_contract_is_unchanged(monkeypatch):
    calls = _setup(monkeypatch)
    result = reporting_v4.builder_preview(PAYLOAD, None, access=_access())
    assert result["sample_rows"] == [] and result["sample_state"] == "not_requested_no_data_disclosure"
    assert "sample_columns" not in result and "sample_limit" not in result
    assert not calls
    result = reporting_v4.builder_preview({**PAYLOAD, "with_rows": False}, None, access=_access())
    assert result["sample_state"] == "not_requested_no_data_disclosure" and not calls


def test_with_rows_returns_at_most_20_projected_by_grant(monkeypatch):
    calls = _setup(monkeypatch)
    result = reporting_v4.builder_preview({**PAYLOAD, "with_rows": True}, None, access=_access())
    assert result["status"] == "accepted" and result["sample_state"] == "rows"
    assert result["sample_limit"] == 20 and len(result["sample_rows"]) == 20
    # technical not covered by the caller's grant: projected out
    assert result["sample_rows"][0] == {"display_name": "n0"}
    assert [c["key"] for c in result["sample_columns"]] == ["display_name"]
    assert calls[0][1][-1] == 21  # limit + 1 probe, never more


def test_with_rows_owner_sees_all_categories(monkeypatch):
    _setup(monkeypatch, row_count=2)
    result = reporting_v4.builder_preview(
        {**PAYLOAD, "with_rows": True}, None, access=_access(owner=True, grants=[]),
    )
    assert result["sample_state"] == "rows"
    assert set(result["sample_rows"][0]) == {"display_name", "natural_key"}


def test_with_rows_empty(monkeypatch):
    _setup(monkeypatch, row_count=0)
    result = reporting_v4.builder_preview({**PAYLOAD, "with_rows": True}, None, access=_access())
    assert result["sample_state"] == "empty" and result["sample_rows"] == []


def test_with_rows_gated_when_capability_missing(monkeypatch):
    calls = _setup(monkeypatch)
    result = reporting_v4.builder_preview(
        {**PAYLOAD, "with_rows": True}, None, access=_access(caps=["reports.design", "field.identity_basic"]),
    )
    assert result["status"] == "gated" and result["sample_state"] == "gated"
    assert result["sample_missing_capabilities"] == ["field.technical"]
    assert result["sample_rows"] == [] and not calls


def test_with_rows_gated_without_dataset_access(monkeypatch):
    calls = _setup(monkeypatch)
    result = reporting_v4.builder_preview({**PAYLOAD, "with_rows": True}, None, access=_access(grants=[]))
    assert result["sample_state"] == "gated" and result["sample_rows"] == [] and not calls


# --- access summary ---------------------------------------------------------------

def _summary_handler(published=True):
    def handler(sql, _p):
        if "select version,discoverable,requestable" in sql:
            return [{"version": 3, "discoverable": True, "requestable": False}] if published else []
        if "select 1 as n from report_registry_v4" in sql:
            return []
        if "from access_report_assignments a" in sql:
            return [{"subject_type": "user", "subject_id": 7, "effect": "allow", "source_type": "direct",
                     "valid_until": None, "allowed_actions": ["view"],
                     "field_categories": ["identity_basic"], "subject_name": "alice"}]
        if "from access_package_reports pr" in sql:
            return [{"package_key": "pkg", "name": "Пакет"}]
        if "count(*)" in sql:
            return [{"n": 2}]
        return []
    return handler


def _summary_db(monkeypatch, **kw):
    db = FakeDb(_summary_handler(**kw))
    monkeypatch.setattr(reporting_v4, "_connect", lambda: db)
    monkeypatch.setattr(reporting_v4, "ensure_access_schema", lambda: None)
    return db


@pytest.mark.parametrize("cap", ["reports.assign", "access.manage"])
def test_access_summary_shape(monkeypatch, cap):
    _summary_db(monkeypatch)
    result = reporting_v4.report_access_summary("my.report", None, access={"capabilities": [cap]})
    assert result["report_key"] == "my.report" and result["published_version"] == 3
    assert result["discoverable"] is True and result["requestable"] is False
    assert result["assignments"] == [{
        "subject_type": "user", "subject_id": 7, "subject_name": "alice", "effect": "allow",
        "source_type": "direct", "valid_until": None, "actions": ["view"],
        "field_categories": ["identity_basic"],
    }]
    assert result["packages"] == [{"package_key": "pkg", "name": "Пакет"}]
    assert result["pending_requests"] == 2


def test_access_summary_requires_capability_and_known_report(monkeypatch):
    _summary_db(monkeypatch)
    with pytest.raises(PermissionError):
        reporting_v4.report_access_summary("my.report", None, access={"capabilities": ["reports.design"]})
    _summary_db(monkeypatch, published=False)
    with pytest.raises(LookupError, match="report_not_found"):
        reporting_v4.report_access_summary("my.report", None, access={"capabilities": ["reports.assign"]})


def test_access_summary_route_mapping():
    path = "/api/v1/reports/my.report/access-summary"
    assert route_capability(path) == "reports.assign"
    assert route_capability("/api/v1/reports/my.report/data") == "reports.catalog"
    assert ("GET", "/api/v1/reports/{}/access-summary") in routes_reports.ROUTES
    assert routes_reports.is_resource_aware(path) is True


def _http(path, caps):
    handler = object.__new__(http_server.RequestHandler)
    handler.path = path
    sent = []
    handler._send_json = lambda payload, status=HTTPStatus.OK: sent.append((payload, status))
    handler._access_decision = lambda: {"capabilities": caps}
    return handler, sent


def test_http_access_summary_enforces_capability(monkeypatch):
    _summary_db(monkeypatch)
    path = "/api/v1/reports/my.report/access-summary"
    handler, sent = _http(path, ["reports.catalog"])
    assert routes_reports.try_handle_get(handler, path, {}) is True
    assert sent[0][1] == HTTPStatus.FORBIDDEN
    handler, sent = _http(path, ["access.manage"])
    assert routes_reports.try_handle_get(handler, path, {}) is True
    assert sent[0][1] == HTTPStatus.OK and sent[0][0]["pending_requests"] == 2


# --- «Назначить мне» ----------------------------------------------------------------

def test_assignment_for_publisher_allows_report_data(monkeypatch):
    definition = {
        "definition_json": {"columns": ["display_name"], "actions": ["view"],
                            "field_categories": ["identity_basic"]},
        "dataset_key": "entities.v2", "fields_json": DATASET["fields_json"],
    }
    db = FakeDb(lambda sql, _p: [definition] if "from report_registry_v4 r" in sql else [])
    monkeypatch.setattr(reporting_v4, "_connect", lambda: db)
    monkeypatch.setattr(reporting_v4, "query_rows_bounded", lambda *a, **k: [{"display_name": "x"}])

    def access(allowed):
        return {"capabilities": ["field.identity_basic"], "reports": [{
            "report_key": "my.report", "version": 1, "allowed": allowed,
            "grants": [GRANT] if allowed else [],
        }]}

    with pytest.raises(PermissionError, match="report_access_denied"):
        reporting_v4.execute_report("my.report", None, access=access(False))
    result = reporting_v4.execute_report("my.report", None, access=access(True))
    assert result["items"] == [{"display_name": "x"}]
