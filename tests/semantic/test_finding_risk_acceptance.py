"""Risk acceptance contracts with fake PostgreSQL cursors; no runtime DB."""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import pytest

from server.api.routes import findings as routes
from server.sli.semantic import finding_risk_acceptance as risk

NOW = datetime(2026, 10, 7, tzinfo=timezone.utc)


def body(**updates):
    return {"action": "create", "reason": "Fixture decision", "responsible_user_id": 12,
            "expires_at": (NOW + timedelta(days=1)).isoformat(), **updates}


class Cursor:
    def __init__(self, rows=()):
        self.rows = iter(rows)
        self.calls = []

    def execute(self, sql, params=()):
        self.calls.append((sql, params))

    def fetchone(self):
        return next(self.rows, None)

    def fetchall(self):
        return []


@pytest.mark.parametrize("updates,code", [
    ({"reason": " "}, "reason_required"),
    ({"reason": "x" * 2001}, "reason_required"),
    ({"expires_at": NOW.isoformat()}, "invalid_expiry"),
    ({"expires_at": (NOW - timedelta(days=1)).isoformat()}, "invalid_expiry"),
    ({"expires_at": (NOW + timedelta(days=91)).isoformat()}, "invalid_expiry"),
    ({"expires_at": "2026-10-08"}, "invalid_expiry"),
    ({"responsible_user_id": True}, "invalid_responsible"),
    ({"responsible_user_id": 1.5}, "invalid_responsible"),
    ({"responsible_user_id": 0}, "invalid_responsible"),
])
def test_create_rejects_invalid_input_before_writing(updates, code):
    cur = Cursor()
    with pytest.raises(risk.RiskAcceptanceError) as exc:
        risk.create_acceptance(cur, 7, body(**updates), actor="fixture-analyst", now=NOW)
    assert exc.value.code == code
    assert not cur.calls


def test_responsible_must_be_an_active_platform_user():
    cur = Cursor([{"id": 7, "rule_code": "semantic.fixture"}, None])
    with pytest.raises(risk.RiskAcceptanceError, match="responsible_not_found"):
        risk.create_acceptance(cur, 7, body(), actor="fixture-analyst", now=NOW)
    assert not any("insert into" in sql for sql, _ in cur.calls)


def test_create_reuses_suppression_and_records_authenticated_author():
    cur = Cursor([{"id": 7, "rule_code": "semantic.fixture"}, {"id": 12}, None, {"id": 31}])
    assert risk.create_acceptance(cur, 7, body(created_by="forged"), actor="fixture-analyst", now=NOW) == {"id": 31}
    sql, params = cur.calls[-1]
    assert "insert into semantic_suppressions" in sql
    assert "risk_acceptance" in sql and "responsible_user_id" in sql
    assert params == (NOW + timedelta(days=1), "semantic.fixture", "7", 7, 12, "Fixture decision", "fixture-analyst")
    assert "expiry > at" in sql
    assert "interval '2160 hours'" in sql


def test_create_rejects_expiry_that_passes_during_the_request():
    cur = Cursor([{"id": 7, "rule_code": "semantic.fixture"}, {"id": 12}, None, None])
    with pytest.raises(risk.RiskAcceptanceError, match="invalid_expiry"):
        risk.create_acceptance(cur, 7, body(), actor="fixture-analyst", now=NOW)


def test_duplicate_acceptance_is_a_conflict():
    cur = Cursor([{"id": 7, "rule_code": "semantic.fixture"}, {"id": 12}, {"id": 31}])
    with pytest.raises(risk.RiskAcceptanceError, match="risk_already_accepted"):
        risk.create_acceptance(cur, 7, body(), actor="fixture-analyst", now=NOW)


def test_missing_finding_is_rejected():
    with pytest.raises(risk.RiskAcceptanceError, match="not_found"):
        risk.create_acceptance(Cursor(), 7, body(), actor="fixture-analyst", now=NOW)


@pytest.mark.parametrize("action", [None, [], {}, "unknown"])
def test_action_must_be_an_explicit_create_or_revoke(action):
    with pytest.raises(risk.RiskAcceptanceError, match="invalid_action"):
        risk.change_risk_acceptance(7, body(action=action), actor="fixture-analyst")


def test_revoke_targets_exact_finding_and_active_acceptance():
    cur = Cursor([{"id": 31}])
    assert risk.revoke_acceptance(cur, 7, 31, actor="fixture-analyst") == {"id": 31}
    sql, params = cur.calls[-1]
    assert "kind='risk_acceptance'" in sql and "finding_id=%s" in sql
    assert "expires_at > clock_timestamp()" in sql
    assert params == ("fixture-analyst", 7, 31)
    with pytest.raises(risk.RiskAcceptanceError, match="risk_not_active"):
        risk.revoke_acceptance(Cursor(), 7, 31, actor="fixture-analyst")


class Handler:
    _principal = {"username": "fixture-analyst"}

    def __init__(self, payload=None, *, allowed=True, authorized=True):
        self.payload = payload or body()
        self.allowed = allowed
        self.authorized = authorized
        self.response = None
        self.capabilities = []

    def _authorize_mutation(self):
        return self.authorized

    def _require_capability(self, capability):
        assert capability in {"investigations.manage", "investigations.view"}
        self.capabilities.append(capability)
        return self.allowed

    def _read_json_body(self):
        return self.payload

    def _send_json(self, value, status=200):
        self.response = (value, status)


@pytest.mark.parametrize("allowed,authorized", [(False, True), (True, False)])
def test_access_uses_the_same_gate_as_finding_lifecycle(monkeypatch, allowed, authorized):
    monkeypatch.setattr(routes, "change_risk_acceptance", lambda *a, **k: pytest.fail("denied write"))
    handler = Handler(allowed=allowed, authorized=authorized)
    assert routes.try_handle_post(handler, "/api/findings/7/risk-acceptance")
    assert handler.response is None
    assert handler.capabilities == (["investigations.manage"] if authorized else [])


@pytest.mark.parametrize("action", ["create", "revoke"])
def test_api_records_author_from_principal(monkeypatch, action):
    captured = {}
    monkeypatch.setattr(routes, "change_risk_acceptance", lambda *a, **k: captured.update(k) or {"status": "ok"})
    handler = Handler(body(action=action, id=31, changed_by="forged"))
    assert routes.try_handle_post(handler, "/api/findings/7/risk-acceptance")
    assert captured["actor"] == "fixture-analyst"
    assert handler.response == ({"status": "ok"}, 200)


@pytest.mark.parametrize("code,status", [("reason_required", 400), ("responsible_not_found", 400),
                                         ("invalid_expiry", 400), ("not_found", 404), ("risk_not_active", 409)])
def test_api_validation_errors(monkeypatch, code, status):
    def fail(*args, **kwargs):
        raise risk.RiskAcceptanceError(code)
    monkeypatch.setattr(routes, "change_risk_acceptance", fail)
    handler = Handler()
    routes.try_handle_post(handler, "/api/findings/7/risk-acceptance")
    assert handler.response[1] == status
    assert handler.response[0]["error"] == code


@pytest.mark.parametrize("path", ["/api/findings/not-an-id/risk-acceptance", "/api/findings/7/extra/risk-acceptance"])
def test_api_requires_one_exact_numeric_finding_id(monkeypatch, path):
    monkeypatch.setattr(routes, "change_risk_acceptance", lambda *a, **k: pytest.fail("invalid route write"))
    handler = Handler()
    assert routes.try_handle_post(handler, path)
    assert handler.response == ({"error": "invalid_finding_id"}, 400)


def test_change_write_and_audit_read_share_the_transaction(monkeypatch):
    from server.sli.core import postgres_runtime_pipeline as pg
    events = []
    cur = Cursor([{"id": 31, "expires_at": NOW}])

    class Connection:
        @contextmanager
        def cursor(self):
            yield cur

    @contextmanager
    def connect():
        events.append("begin")
        try:
            yield Connection()
        except Exception:
            events.append("rollback")
            raise
        else:
            events.append("commit")

    monkeypatch.setattr(pg, "connect", connect)
    result = risk.change_risk_acceptance(7, body(action="revoke", id=31), actor="fixture-analyst")
    assert result["acceptance"]["expires_at"] == NOW.isoformat()
    assert result["risk_audit"] == []
    assert "semantic_control_audit" in cur.calls[-1][0]
    assert events == ["begin", "commit"]
    events.clear()
    with pytest.raises(risk.RiskAcceptanceError):
        risk.change_risk_acceptance(7, body(action="revoke", id=31), actor="fixture-analyst")
    assert events == ["begin", "rollback"]


@pytest.mark.parametrize("risk_filter,expected", [(None, "not coalesce"), ("accepted", "and coalesce"), ("all", None)])
def test_risk_filter_and_expired_attention_apply_to_list_and_summary(monkeypatch, risk_filter, expected):
    from server.sli.semantic import findings
    monkeypatch.setattr(findings, "is_postgres_runtime_db", lambda *a, **k: True)
    monkeypatch.setattr(findings, "resolve_storage_route", lambda **kwargs: {"route": "v2"})
    monkeypatch.setattr(findings, "_attach_postgres_finding_details", lambda *a, **k: None)
    monkeypatch.setattr(findings, "get_findings_refresh_status", lambda **kwargs: {})
    calls = []
    monkeypatch.setattr(findings, "query_rows", lambda sql, *a, **k: calls.append(sql) or [])
    findings.get_security_problems_data(risk=risk_filter, status="new")
    queries = [sql for sql in calls if "from findings_active" in sql]
    assert len(queries) == 2
    for sql in queries:
        assert "risk.expires_at <= statement_timestamp()" in sql
        assert "coalesce(findings.repeat_count,0)>0 then 'repeated' else 'new'" in sql
        assert "kind='risk_acceptance'" in sql
        if expected:
            assert expected in sql
    assert "semantic_control_audit" in queries[0]


def test_responsible_picker_is_not_an_admin_user_listing(monkeypatch):
    monkeypatch.setattr(routes, "risk_responsibles", lambda: {"items": [{"id": 12, "username": "fixture-owner"}]})
    denied = Handler(allowed=False)
    assert routes.try_handle_get(denied, "/api/findings/risk-responsibles", {})
    assert denied.response is None
    allowed = Handler()
    assert routes.try_handle_get(allowed, "/api/findings/risk-responsibles", {})
    assert allowed.response[0] == {"items": [{"id": 12, "username": "fixture-owner"}]}


def test_audit_pagination_is_finding_scoped_and_read_protected(monkeypatch):
    calls = []
    monkeypatch.setattr(routes, "get_risk_audit", lambda *args, **kwargs: calls.append((args, kwargs)) or {"items": [], "has_more": False})
    denied = Handler(allowed=False)
    assert routes.try_handle_get(denied, "/api/findings/7/risk-audit", {"before": ["31"]})
    assert calls == []
    allowed = Handler()
    assert routes.try_handle_get(allowed, "/api/findings/7/risk-audit", {"before": ["31"]})
    assert calls == [((7,), {"before": 31})]
    assert allowed.response[0] == {"items": [], "has_more": False}
    assert allowed.capabilities == ["investigations.view"]


def test_audit_reader_bounds_and_serializes_each_page(monkeypatch):
    from server.sli.core import postgres_runtime_pipeline as pg
    class AuditCursor(Cursor):
        def fetchall(self):
            return [{"id": 100 - index, "occurred_at": NOW} for index in range(51)]
    cur = AuditCursor()
    class Connection:
        @contextmanager
        def cursor(self):
            yield cur
    @contextmanager
    def connect():
        yield Connection()
    monkeypatch.setattr(pg, "connect", connect)
    result = risk.get_risk_audit(7, before=101)
    assert result["has_more"] is True
    assert len(result["items"]) == 50
    assert result["items"][0] == {"id": 100, "occurred_at": NOW.isoformat()}
    assert cur.calls[0][1] == ("7", 101, 101)
    assert "limit 51" in cur.calls[0][0]


def test_risk_filter_is_forwarded_by_the_findings_api(monkeypatch):
    monkeypatch.setattr(routes, "_with_storage_route_authorization", lambda handler, values: {**values, "authorization": None})
    calls = []
    monkeypatch.setattr(routes, "get_security_problems_data", lambda **kwargs: calls.append(kwargs) or {"items": []})
    handler = Handler()
    handler._access_decision = lambda: {"reports": [{
        "report_key": "security.queue", "allowed": True, "allowed_actions": ["view"],
        "grants": [{"scope": {"kind": "all"}, "allowed_actions": ["view"], "field_categories": ["security"]}],
    }]}
    assert routes.try_handle_get(handler, "/api/findings", {"source": ["semantic-production"], "risk": ["accepted"]})
    assert calls[0]["risk"] == "accepted"
