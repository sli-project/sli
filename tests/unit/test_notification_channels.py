"""N01 contracts with fake PostgreSQL and handlers; no network or real DB."""

from dataclasses import replace
from http import HTTPStatus

import pytest

from server.api.routes import notification_channels as routes, reports_v2
from server.sli.access.access_control_v4 import _bounded_report_grant, route_capability
from server.sli.core import notification_channels as channels
from server.sli.reporting.v2.access import ReportAccess
from server.sli.reporting.v2.definition import QueryContext
from server.sli.reporting.v2.reports.notification_channels import REPORT


def access(*, role="admin", scope=None, actions=("view", "configure_channel"), fields=("technical",)):
    return {"subject": {"coarse_role": role}, "capabilities": ["access.manage", "field.technical"],
            "reports": [{"report_key": REPORT.key, "allowed": True, "allowed_actions": list(actions),
                         "grants": [{"allowed_actions": list(actions), "field_categories": list(fields),
                                     "scope": scope or {"kind": "all"}}]}]}


def row(kind="smtp", **overrides):
    return {"kind": kind, "enabled": False, "tls_mode": "starttls" if kind == "smtp" else "tls",
            "secret_ref": channels.SECRET_REFS[kind], "state": "not_configured", "revision": 1,
            "updated_at": "2026-10-17T00:00:00Z", **overrides}


def body(**overrides):
    return {"enabled": True, "tls_mode": "tls", "secret_ref": channels.SECRET_REFS["smtp"],
            "revision": 1, **overrides}


@pytest.fixture(autouse=True)
def no_database(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("unexpected database access")
    monkeypatch.setattr(channels.database, "query_rows", forbidden)
    monkeypatch.setattr("server.sli.core.postgres_runtime_pipeline.connect", forbidden)


@pytest.fixture
def stored(monkeypatch):
    calls = []
    def query(sql, params=()):
        calls.append((sql, params))
        return [row(), row("telegram")]
    monkeypatch.setattr(channels.database, "query_rows", query)
    return calls


class Handler:
    def __init__(self, decision=None, payload=None, mutation=True):
        self.decision = decision if decision is not None else access()
        self.payload = payload if payload is not None else body()
        self.mutation = mutation
        self.reads = 0
        self._principal = {"type": "session", "id": 1, "role": "admin"}

    def _access_decision(self):
        return self.decision

    def _authorize_mutation(self, *, required_role):
        assert required_role == "admin"
        return self.mutation

    def _read_json_body(self):
        self.reads += 1
        return self.payload

    def _send_json(self, payload, status=HTTPStatus.OK):
        self.response, self.status = payload, status


def test_rows_are_metadata_only_and_both_not_configured(stored, monkeypatch):
    monkeypatch.setattr(channels.database, "query_rows", lambda *a: [row(password="synthetic-value"), row("telegram", token="synthetic-value")])
    items = channels.list_channels(access())
    assert [item["kind"] for item in items] == ["smtp", "telegram"]
    assert all(item["state"] == "not_configured" and not item["enabled"] for item in items)
    assert all(set(item) == set(channels.FIELDS) for item in items)
    assert "synthetic-value" not in str(items)


@pytest.mark.parametrize("decision", [
    access(role="viewer"), access(role="operator"), access(role=""), {},
    {**access(), "capabilities": []},
    {**access(), "reports": []},
    access(scope={"kind": "domain", "ids": [1]}),
    access(scope={"kind": "domain", "ids": [2]}),
    access(scope={"mode": "restricted", "clauses": [{"source_instance_ids": ["synthetic-source"]}]}),
    access(fields=()),
    {**access(), "capability_policies": [{"capability_key": "access.manage", "effect": "deny", "valid": True,
                                        "scope": {"kind": "domain", "ids": [1]}}]},
    {**access(), "capability_policies": [{"capability_key": "access.manage", "effect": "deny", "valid": True,
                                        "scope": {"kind": "all"}}]},
])
def test_wrong_role_scope_or_permission_denied_before_read_or_write(decision):
    with pytest.raises(PermissionError):
        channels.list_channels(decision)
    with pytest.raises(PermissionError):
        channels.update_channel(decision, "smtp", body(), audit=lambda *a: pytest.fail("unexpected audit"))
    with pytest.raises(PermissionError):
        ReportAccess(REPORT, decision).declaration()
    with pytest.raises(PermissionError):
        REPORT.query(QueryContext(access=decision, params={}))
    handler = Handler(decision)
    assert routes.try_handle_get(handler, routes.PREFIX, {})
    assert handler.status == HTTPStatus.FORBIDDEN
    assert routes.try_handle_post(handler, routes.PREFIX + "/smtp")
    assert handler.status == HTTPStatus.FORBIDDEN and handler.reads == 0


def test_view_grant_does_not_allow_update(stored):
    decision = access(actions=("view",))
    assert len(channels.list_channels(decision)) == 2
    with pytest.raises(PermissionError):
        channels.update_channel(decision, "smtp", body(), audit=lambda *a: None)


@pytest.mark.parametrize("payload", [
    {}, None, [], "synthetic-value", body(password="synthetic-value"), body(token="synthetic-value"),
    body(url="https://example.invalid"), body(recipients=["synthetic-recipient"]),
    body(secret_ref="/arbitrary/path"), body(secret_ref=channels.SECRET_REFS["telegram"]),
    body(tls_mode="plain"), body(tls_mode=[]), body(enabled="true"),
    body(revision=True), body(revision=0), body(revision=2**63),
])
def test_invalid_metadata_never_reaches_database_or_echoes_input(payload):
    with pytest.raises(ValueError, match="^invalid_notification_channel_metadata$"):
        channels.update_channel(access(), "smtp", payload, audit=lambda *a: pytest.fail("unexpected audit"))


def test_telegram_requires_tls_and_its_fixed_secret_ref():
    value = body(secret_ref=channels.SECRET_REFS["telegram"])
    assert channels.validate_update("telegram", value) == value
    with pytest.raises(ValueError):
        channels.validate_update("telegram", {**value, "tls_mode": "starttls"})
    with pytest.raises(LookupError, match="notification_channel_not_found"):
        channels.validate_update("unknown", value)


class Connection:
    def __init__(self, *, conflict=False):
        self.events = []
        self.conflict = conflict

    def __enter__(self):
        return self

    def __exit__(self, exc_type, *_):
        self.events.append("rollback" if exc_type else "exit")

    def cursor(self):
        return self

    def execute(self, sql, params=()):
        self.events.append((sql, params))

    def fetchone(self):
        return None if self.conflict else row(enabled=True, tls_mode="tls", revision=2)

    def commit(self):
        self.events.append("commit")


def test_metadata_and_safe_audit_commit_together(monkeypatch):
    conn = Connection()
    monkeypatch.setattr("server.sli.core.postgres_runtime_pipeline.connect", lambda: conn)
    changes = []
    def audit(cur, details):
        assert cur is conn
        changes.append(details)
        conn.events.append("audit")
    item = channels.update_channel(access(), "smtp", body(), audit=audit)
    assert item == row(enabled=True, tls_mode="tls", revision=2)
    assert item["state"] == "not_configured"
    assert conn.events[0][1] == (True, "tls", channels.SECRET_REFS["smtp"], "smtp", 1)
    assert changes == [{"kind": "smtp", "revision": 2, "changed_fields": ["enabled", "tls_mode", "secret_ref"]}]
    assert conn.events[1:3] == ["audit", "commit"]


@pytest.mark.parametrize("conflict", [False, True])
def test_audit_failure_or_stale_revision_never_commits(monkeypatch, conflict):
    conn = Connection(conflict=conflict)
    monkeypatch.setattr("server.sli.core.postgres_runtime_pipeline.connect", lambda: conn)
    def fail_audit(*args):
        raise RuntimeError("synthetic audit failure")
    with pytest.raises(LookupError if conflict else RuntimeError):
        channels.update_channel(access(), "smtp", body(), audit=fail_audit)
    assert "commit" not in conn.events and conn.events[-1] == "rollback"


def test_api_csrf_error_redaction_and_conflict(monkeypatch):
    handler = Handler(mutation=False)
    assert routes.try_handle_post(handler, routes.PREFIX + "/smtp") and handler.reads == 0
    handler = Handler(payload=body(token="synthetic-secret-value"))
    routes.try_handle_post(handler, routes.PREFIX + "/smtp")
    assert handler.status == HTTPStatus.BAD_REQUEST
    assert handler.response == {"error": "invalid_notification_channel_metadata"}
    conn = Connection(conflict=True)
    monkeypatch.setattr("server.sli.core.postgres_runtime_pipeline.connect", lambda: conn)
    handler = Handler()
    routes.try_handle_post(handler, routes.PREFIX + "/smtp")
    assert handler.status == HTTPStatus.CONFLICT
    assert routes.try_handle_post(handler, routes.PREFIX + "/missing")
    assert handler.status == HTTPStatus.NOT_FOUND


def test_api_read_write_and_safe_audit(monkeypatch, stored):
    handler = Handler()
    assert routes.try_handle_get(handler, routes.PREFIX, {})
    assert handler.status == HTTPStatus.OK and len(handler.response["items"]) == 2
    conn = Connection()
    monkeypatch.setattr("server.sli.core.postgres_runtime_pipeline.connect", lambda: conn)
    audits = []
    monkeypatch.setattr(routes, "record_access_audit_with_cursor", lambda **kwargs: audits.append(kwargs))
    routes.try_handle_post(handler, routes.PREFIX + "/smtp")
    assert handler.status == HTTPStatus.OK and handler.response["item"]["revision"] == 2
    assert audits[0]["target_key"] == "smtp" and audits[0]["cursor"] is conn
    assert set(audits[0]["details"]) == {"kind", "revision", "changed_fields"}
    assert not routes.try_handle_get(handler, "/unrelated", {})
    assert not routes.try_handle_post(handler, "/unrelated")


def test_api_storage_and_audit_failures_are_fixed_codes_without_values(monkeypatch, caplog):
    def broken(*args, **kwargs):
        raise RuntimeError("synthetic-secret-value")
    monkeypatch.setattr(channels.database, "query_rows", broken)
    handler = Handler()
    routes.try_handle_get(handler, routes.PREFIX, {})
    assert handler.status == HTTPStatus.SERVICE_UNAVAILABLE
    assert handler.response == {"error": "notification_channels_unavailable"}
    conn = Connection()
    monkeypatch.setattr("server.sli.core.postgres_runtime_pipeline.connect", lambda: conn)
    monkeypatch.setattr(routes, "record_access_audit_with_cursor", broken)
    routes.try_handle_post(handler, routes.PREFIX + "/smtp")
    assert handler.status == HTTPStatus.SERVICE_UNAVAILABLE
    assert handler.response == {"error": "notification_channels_unavailable"}
    assert "commit" not in conn.events and conn.events[-1] == "rollback"
    assert "synthetic-secret-value" not in caplog.text


def test_v2_journal_paginates_and_reports_read_failure(stored, monkeypatch):
    context = QueryContext(access=access(), params={}, limit=1)
    first = REPORT.query(context)
    assert first["contract_id"] == "sli.report-result.v2" and first["state"] == "ok"
    assert first["items"] == [row()] and first["next_cursor"] == "smtp" and first["has_more"]
    second = REPORT.query(replace(context, cursor=first["next_cursor"]))
    assert second["items"] == [row("telegram")] and not second["has_more"]
    with pytest.raises(ValueError, match="^invalid_cursor$"):
        REPORT.query(replace(context, cursor="synthetic-invalid"))
    def broken(*args):
        raise RuntimeError("synthetic-secret-value")
    monkeypatch.setattr(channels.database, "query_rows", broken)
    failed = REPORT.query(context)
    assert failed["state"] == "error" and failed["items"] == []
    assert "synthetic-secret-value" not in str(failed)


@pytest.mark.parametrize("decision,status", [(access(), HTTPStatus.OK), (access(role="viewer"), HTTPStatus.FORBIDDEN),
    (access(scope={"kind": "domain", "ids": [2]}), HTTPStatus.FORBIDDEN)])
def test_v2_api_declaration_and_data_enforce_same_access(monkeypatch, stored, decision, status):
    monkeypatch.setattr(reports_v2, "get_report", lambda key: REPORT)
    monkeypatch.setattr(reports_v2, "report_plugin_state", lambda key: None)
    monkeypatch.setattr(reports_v2, "annotate_plugin_report", lambda *a: None)
    monkeypatch.setattr(reports_v2, "validate_storage_route_authorization", lambda *a: None)
    handler = Handler(decision)
    for suffix in ("", "/data"):
        assert reports_v2.try_handle_get(handler, "/api/v2/reports/notifications.channels" + suffix, {})
        assert handler.status == status
        if suffix and status == HTTPStatus.OK:
            assert [item["state"] for item in handler.response["items"]] == ["not_configured"] * 2


def test_channel_action_survives_capability_bounding_and_route_is_registered():
    grant = access()["reports"][0]["grants"][0]
    assert "configure_channel" in _bounded_report_grant(grant, {"access.manage", "field.technical"})["allowed_actions"]
    assert "configure_channel" not in _bounded_report_grant(grant, {"field.technical"})["allowed_actions"]
    assert route_capability(routes.PREFIX + "/smtp") == "access.manage"
    from server.api.http_server import create_app
    registry = create_app()
    assert routes in registry.candidates("GET", routes.PREFIX)
    assert routes in registry.candidates("POST", routes.PREFIX + "/smtp")


def test_registry_passport_and_navigation_are_registered():
    from server.sli.reporting.v2.registry import get_report
    from server.sli.reporting.navigation_registry import load_registry
    from server.sli.reporting.report_intent_contract import validate_report_intent
    assert get_report(REPORT.key) is REPORT
    assert load_registry()[1][REPORT.key]["section_id"] == "admin"
    assert validate_report_intent(REPORT.intent_contract()) == REPORT.key
