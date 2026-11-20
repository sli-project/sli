"""Without a report domain every caller degrades to an honest state instead of a 500 (owner decision 2026-10-02)."""

from __future__ import annotations

from http import HTTPStatus
from types import SimpleNamespace

import pytest

from server.api import http_server
from server.sli.core import platform_settings
from server.sli.core.report_domain import ReportDomainNotConfiguredError
from server.sli.entities import what_where_when_projection
from server.sli.reporting.v2.reports import computer_logons
from server.sli.reports import users_reporting


@pytest.fixture(autouse=True)
def _domain_not_configured(monkeypatch: pytest.MonkeyPatch):
    platform_settings.clear_cache()
    monkeypatch.setattr(platform_settings.database, "query_rows", lambda *_a, **_k: [])
    # Neither legacy runtime environment nor the install-time seed is authority.
    monkeypatch.setenv("ADLOG_REPORT_DOMAIN_FQDN", "env.example.invalid")
    monkeypatch.setenv("SLI_INSTALL_DOMAIN", "install.example.invalid")
    yield
    platform_settings.clear_cache()


def _handler(method: str) -> tuple[object, list]:
    handler = object.__new__(http_server.RequestHandler)
    handler.path = "/api/v1/reports/ad.users.v2/data?q=secret"
    handler._admit_request = lambda: True
    setattr(handler, f"_do_{method}", lambda: (_ for _ in ()).throw(ReportDomainNotConfiguredError()))
    sent: list = []
    handler._send_json = lambda payload, status=HTTPStatus.OK: sent.append((payload, status))
    handler.server = SimpleNamespace(request_slots=SimpleNamespace(release=lambda: None))
    return handler, sent


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_http_report_endpoint_returns_structured_503_not_a_traceback(
    monkeypatch: pytest.MonkeyPatch, method: str,
) -> None:
    monkeypatch.setattr(http_server, "log_internal_error", lambda *_a, **_k: pytest.fail("not an internal error"))
    handler, sent = _handler(method)
    getattr(handler, f"do_{method}")()
    assert len(sent) == 1
    payload, status = sent[0]
    assert status == HTTPStatus.SERVICE_UNAVAILABLE
    assert payload["error"] == "report_domain_not_configured"
    assert "Настройки платформы" in payload["message"]


def test_users_report_without_stored_domain_returns_not_configured_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        users_reporting, "query_rows_bounded",
        lambda *_a, **_k: pytest.fail("an unset report domain must not query report data"),
    )
    handler, sent = _handler("GET")
    handler._do_GET = lambda: users_reporting.get_users_report(domain_ids=[7])

    handler.do_GET()

    assert len(sent) == 1
    payload, status = sent[0]
    assert status == HTTPStatus.SERVICE_UNAVAILABLE
    assert payload["error"] == "report_domain_not_configured"
    assert "Домен отчётов не задан" in payload["message"]
    assert "Настройки платформы" in payload["message"]


def test_computer_logons_report_is_unavailable_with_a_specific_limitation() -> None:
    access = {"reports": [{
        "report_key": "ad.computer-logons", "allowed": True, "allowed_actions": ["view"],
        "grants": [{"allowed_actions": ["view"], "field_categories": ["computer_logon_observation"], "scope": {"kind": "all"}}],
    }]}
    context = SimpleNamespace(
        access=access, limit=50, cursor=None,
        params={"period": {"from_utc": "2026-08-01T00:00:00Z", "to_utc": "2026-09-01T00:00:00Z"}},
    )
    payload = computer_logons._query(context)
    assert payload["state"] == "error"
    assert payload["items"] == []
    assert [item["code"] for item in payload["limitations"]] == ["report_domain_not_configured"]
    assert "Настройки платформы" in payload["limitations"][0]["text"]


def test_report_domain_id_lookup_uses_only_the_stored_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    from server.sli.reports import what_where_when_reporting

    monkeypatch.setattr(platform_settings.database, "query_rows", lambda *_a, **_k: [{"value": " DB.Example.Invalid "}])
    calls = []

    def query(sql, params, **_kwargs):
        calls.append((sql, params))
        return [{"id": 42}]

    monkeypatch.setattr(what_where_when_reporting, "query_rows_bounded", query)
    assert what_where_when_reporting.resolve_report_domain_id() == 42
    assert len(calls) == 1
    assert calls[0][1] == ("db.example.invalid",)


def test_projection_cycle_skips_without_touching_the_database() -> None:
    def no_connection():
        raise AssertionError("must not connect")

    result = what_where_when_projection.run_projection_cycle(
        batch_limit=10, retention_limit=10, connection_factory=no_connection,
    )
    assert result["status"] == "skipped"
    assert result["reason"] == "report_domain_not_configured"


def test_snapshot_workers_skip_the_cycle() -> None:
    from scripts.runtime import (
        computers_report_v5_snapshot_worker, computers_report_v6_snapshot_worker, users_report_v2_snapshot_worker,
    )

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def cursor(self):
            return self

        def execute(self, *_args):
            raise AssertionError("the report domain is resolved before any query")

    for worker in (users_report_v2_snapshot_worker, computers_report_v5_snapshot_worker, computers_report_v6_snapshot_worker):
        result = worker.run_once(connection_factory=Connection)
        assert result == {"status": "skipped", "reason": "report_domain_not_configured"}
