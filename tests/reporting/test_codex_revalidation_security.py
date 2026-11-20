from __future__ import annotations

import ast
from http import HTTPStatus
from pathlib import Path

import pytest

from server.sli.reporting import reporting_v4
from server.sli.access import object_facade_v4
from server.sli.reporting.ui_api_models import V4AccessResponse, V4ObjectDetailResponse
from server.sli.access.access_control_v4 import (
    _bounded_report_grant,
    _capability_scope_is_global,
    _validate_scope_targets,
    route_capability,
)
from server.api import http_server
from server.api.http_server import RequestHandler, _safe_request_path


def test_report_grant_tuple_does_not_cross_product_scope_and_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    access = {
        "reports": [{
            "report_key": "tuple.test", "version": 1, "allowed": True,
            "field_categories": ["identity_basic", "technical"],
            "allowed_actions": ["view", "export"],
            "scopes": [{"kind": "server", "ids": [1]}, {"kind": "server", "ids": [2]}],
            "grants": [
                {"source": "A", "scope": {"kind": "server", "ids": [1]}, "field_categories": ["identity_basic"], "allowed_actions": ["view"]},
                {"source": "B", "scope": {"kind": "server", "ids": [2]}, "field_categories": ["technical"], "allowed_actions": ["view", "export"]},
            ],
        }],
    }

    class Cursor:
        def execute(self, _query: str, _params: tuple[object, ...]) -> None:
            return None

        def fetchone(self) -> dict[str, object]:
            return {
                "dataset_key": "entities.v2",
                "definition_json": {"columns": ["name", "natural_key"]},
                "fields_json": [
                    {"key": "name", "label": "Name", "category": "identity_basic"},
                    {"key": "natural_key", "label": "Key", "category": "technical"},
                ],
            }

        def __enter__(self) -> "Cursor":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    class Connection:
        def cursor(self) -> Cursor:
            return Cursor()

        def __enter__(self) -> "Connection":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    calls: list[tuple[str, tuple[object, ...]]] = []
    monkeypatch.setattr(reporting_v4, "_connect", lambda: Connection())
    monkeypatch.setattr(
        reporting_v4,
        "query_rows_bounded",
        lambda sql, params=(), **_kwargs: calls.append((sql, params)) or [{"name": "alice", "natural_key": "secret"}],
    )

    basic = reporting_v4.execute_report("tuple.test", None, fields=["name"], access=access)
    assert basic["items"] == [{"name": "alice"}]
    assert calls[-1][1][0] == [1]

    technical = reporting_v4.execute_report("tuple.test", None, fields=["natural_key"], access=access)
    assert technical["items"] == [{"natural_key": "secret"}]
    assert calls[-1][1][0] == [2]

    with pytest.raises(PermissionError, match="report_field_access_denied"):
        reporting_v4.execute_report("tuple.test", None, fields=["name", "natural_key"], access=access)


def test_report_definition_normalizes_legacy_columns_and_detects_security_expansion() -> None:
    fields = {
        "name": {"key": "name", "category": "identity_basic"},
        "sid": {"key": "sid", "category": "technical"},
    }
    assert reporting_v4._definition_columns({"columns": ["name", {"key": "sid"}]}, fields) == ["name", "sid"]
    with pytest.raises(ValueError, match="invalid_report_definition_columns"):
        reporting_v4._definition_columns({"columns": ["name", "unknown"]}, fields)
    previous = {"columns": ["name"], "actions": ["view"], "field_categories": ["identity_basic"]}
    assert reporting_v4._security_expands(previous, {**previous, "columns": ["name", "sid"]}) is True
    assert reporting_v4._security_expands(previous, {**previous, "columns": ["name"]}) is False
    metric = {
        "key": "objects.total", "kind": "required",
        "value_path": "summary.total", "target_path": "/reports/objects",
        "filters": {},
    }
    metric_previous = {**previous, "dashboard_metrics": [metric]}
    assert reporting_v4._security_expands(metric_previous, {
        **metric_previous,
        "dashboard_metrics": [{**metric, "value_path": "summary.enabled"}],
    }) is True


def test_report_definition_rejects_structural_sql_but_not_ordinary_text() -> None:
    assert reporting_v4._definition_has_unsafe_text({"filters": [{"value": "SQL Server select account"}]}) is False
    assert reporting_v4._definition_has_unsafe_text({"filters": [{"raw_sql": "select * from events"}]}) is True


def test_scoped_capability_is_not_global_and_sensitive_grant_parts_require_capabilities() -> None:
    assert _capability_scope_is_global({"kind": "all"})
    assert not _capability_scope_is_global({"kind": "server", "ids": [7]})
    bounded = _bounded_report_grant(
        {"field_categories": ["identity_basic", "raw_evidence"], "allowed_actions": ["view", "export"]},
        {"field.identity_basic"},
    )
    assert bounded["field_categories"] == ["identity_basic"]
    assert bounded["allowed_actions"] == ["view"]


def test_policy_diagnostics_and_forbidden_object_state_survive_response_validation() -> None:
    access_payload = {
        "api_version": "v4", "evaluated_at_utc": "2026-07-22T00:00:00Z", "preview": False,
        "subject": {}, "groups": [], "packages": [], "package_explain": [], "capabilities": [],
        "capability_explain": {}, "quarantined_capability_assignments": [{"reason": "resource_context_required"}],
        "reports": [], "allowed_report_count": 0, "navigation": [],
        "explicit_denies": {"packages": [], "capabilities": [], "reports": []},
    }
    assert V4AccessResponse(**access_payload).quarantined_capability_assignments
    detail_payload = {
        "api_version": "v4", "state": "available", "object": {}, "identity_links": [],
        "identity_contract": "test", "tabs": [], "current_states": [], "directory_context": {},
        "findings": [], "events": [], "events_state": "forbidden", "has_more_events": False,
        "actions": [], "provenance": [], "limitations": [],
    }
    assert V4ObjectDetailResponse(**detail_payload).events_state == "forbidden"


def test_report_scope_targets_are_resolved_server_side() -> None:
    class Cursor:
        rows: list[dict[str, object]] = []

        def execute(self, _sql: str, _params: tuple[object, ...]) -> None:
            return None

        def fetchall(self) -> list[dict[str, object]]:
            return self.rows

    cursor = Cursor()
    cursor.rows = [{"id": 7}]
    _validate_scope_targets(cursor, "server", {"ids": [7]})
    with pytest.raises(ValueError, match="report_scope_target_not_found"):
        _validate_scope_targets(cursor, "server", {"ids": [7, 8]})
    cursor.rows = [{"value": "Security"}]
    _validate_scope_targets(cursor, "channel", {"values": ["Security"]})


@pytest.mark.parametrize(
    ("path", "capability"),
    [
        ("/api/v1/events/42", "evidence.exact"),
        ("/api/health/details", "operations.view"),
        ("/api/v1/events/batch", "evidence.exact"),
        ("/api/security/events-monitor", "events.view"),
        ("/api/dashboard/snapshot", "workspace.view"),
        ("/api/logs/tail", "operations.view"),
        ("/api/findings", "investigations.view"),
        ("/api/v1/objects", "objects.view"),
        ("/api/v1/admin/agent-packages", "access.manage"),
        ("/api/v1/admin/agents/update-policy", "access.manage"),
        ("/reports/security-events-monitor.csv", "events.view"),
        ("/reports/search.html", "events.view"),
        ("/reports/entity-details.html", "objects.view"),
    ],
)
def test_sensitive_routes_have_explicit_capability(path: str, capability: str) -> None:
    assert route_capability(path) == capability


def test_literal_data_api_routes_are_classified_or_explicit_auth_bootstrap() -> None:
    # Domain route modules under server/api/routes/ carry their own literal
    # path checks now that http_server.py dispatches to them instead of
    # matching paths itself -- scan both so a route moving out of
    # http_server.py does not silently drop out of this check.
    sources = [Path("server/api/http_server.py"), *sorted(Path("server/api/routes").glob("*.py"))]
    api_paths: set[str] = set()
    for source in sources:
        tree = ast.parse(source.read_text(encoding="utf-8"))
        api_paths |= {
            node.value for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
            and node.value.startswith("/api/") and node.value != "/api/"
        }
    auth_bootstrap = {
        "/api/auth/bootstrap",  # Initial owner activation; guarded by the owner setup flow.
        "/api/auth/me", "/api/auth/users", "/api/auth/api-keys",
        "/api/auth/login", "/api/auth/logout", "/api/test/sli-v4/session",
        "/api/health", "/api/health/live", "/api/health/ready",
        # Agent transport: authenticated by an enrollment token or the agent's mTLS
        # client certificate (server/sli/agents/transport.py), never by a user session.
        "/api/v1/agent/enroll", "/api/v1/agent/identity", "/api/v1/agent/renew", "/api/v1/agent/revocations",
        "/api/v1/agent/group-enroll",  # TLS + scoped group token (agents/group_enrollment.py); creates only a pending request.
        "/api/v1/agent/packets",  # mTLS client certificate + packet signature (routes/agent_packets.py)
        "/api/v1/agent/policy-report",  # mTLS client certificate + registry.authenticate (routes/agents.py)
        "/api/v1/agent/package",  # mTLS client certificate + registry.authenticate (routes/agents.py)
        "/api/v1/agent/update-result",  # mTLS client certificate + registry.authenticate (routes/agents.py)
        "/api/v1/agent/uninstall",  # mTLS client certificate + registry.authenticate (routes/agents.py)
        "/api/v1/agent/removal-result",  # mTLS client certificate + registry.authenticate(removal_only=True)
        "/api/v1/agent/windows-audit-report",  # mTLS client certificate + registry.authenticate (routes/agents.py)
        "/api/v1/agent/file-audit-report",  # mTLS client certificate + registry.authenticate before the plugin hook (routes/agents.py)
    }
    # GPO plans use session + Origin checks and explicit actor/domain/OU/action
    # grants (gpo_plans._scope), not a global capability or an owner bypass.
    # test_gpo_routes_enforce_session_origin_and_scoped_grants exercises the
    # real HTTP handler and service for every exact route below.
    scoped_gpo_routes = {
        "/api/v1/agent-deployment/gpo/credentials",
        "/api/v1/agent-deployment/gpo/preview",
        "/api/v1/agent-deployment/gpo/confirm",
        "/api/v1/agent-deployment/gpo/cancel",
    }
    # AD credentials require a session, Origin checks on mutations and explicit
    # domain/OU grants (ad_credentials._scopes), with no owner bypass. The real
    # handler/service boundary for every route is covered by
    # test_ad_credential_routes_enforce_session_origin_and_scoped_grants.
    scoped_ad_credential_routes = {
        "/api/v1/ad-operation-credentials",
        "/api/v1/ad-operation-credentials/replace-password",
        "/api/v1/ad-operation-credentials/delete",
        "/api/v1/ad-operation-credentials/check",
    }
    # Workstation metadata requires authentication and atomic report grants,
    # with scoped read capabilities for the new workspace. The real dispatcher
    # and plugin authorization are covered by
    # test_workstation_agent_http_route_enforces_scoped_grants.
    scoped_workstation_routes = {"/api/v1/workstations/agents"}
    scoped_routes = scoped_gpo_routes | scoped_ad_credential_routes | scoped_workstation_routes
    assert sorted(path for path in api_paths - auth_bootstrap - scoped_routes if route_capability(path) is None) == []


def test_exact_event_handler_fails_before_data_read_when_capability_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    from server.api.routes import events as routes_events

    handler = object.__new__(RequestHandler)
    sent: list[tuple[dict[str, object], HTTPStatus]] = []
    handler._require_capability = lambda capability: capability != "evidence.exact"
    handler._send_json = lambda payload, status=HTTPStatus.OK: sent.append((payload, status))
    monkeypatch.setattr(
        "server.api.routes.events.get_event_detail_report_data",
        lambda **_kwargs: pytest.fail("exact data must not be read"),
    )

    routes_events._handle_event_by_id_api(handler, "/api/v1/events/42")
    assert sent == []


def test_error_log_path_strips_query_values() -> None:
    assert _safe_request_path("/api/v1/events?q=do-not-log&sid=S-1-5-21") == "/api/v1/events"
    source = Path("server/api/http_server.py").read_text(encoding="utf-8")
    assert '"request_failed", "GET request failed.", error=str(exc)' not in source
    assert '"request_failed", "POST request failed.", error=str(exc)' not in source


@pytest.mark.parametrize("headers", [None, {}, {"Cookie": ""}], ids=["missing-headers", "empty-headers", "empty-cookie"])
def test_effective_access_snapshot_is_request_scoped(monkeypatch: pytest.MonkeyPatch, headers) -> None:
    calls: list[object] = []
    monkeypatch.setattr(http_server, "effective_access", lambda principal: calls.append(principal) or {"capabilities": ["workspace.view"]})
    first = object.__new__(RequestHandler)
    first._principal = {"id": 1, "type": "session"}
    if headers is not None:
        first.headers = headers
    assert first._access_decision() is first._access_decision()
    second = object.__new__(RequestHandler)
    second._principal = {"id": 2, "type": "session"}
    if headers is not None:
        second.headers = headers
    second._access_decision()
    assert [item["id"] for item in calls] == [1, 2]


def test_rule_based_recommendation_report_is_not_labelled_as_ai() -> None:
    source = Path("server/sli/reports/analysis.py").read_text(encoding="utf-8")
    assert "AI Security Report:" not in source
    assert '"analysis_mode": "local_rules"' in source


def test_object_attribute_projection_is_category_based_and_unknown_is_denied() -> None:
    attributes = {
        "object_sid": "S-1-5-21", "department": "Finance",
        "email": "alice@example.invalid", "unknown_secret": "hidden",
    }
    assert object_facade_v4._project_attributes(attributes, {"field.technical"}) == {
        "object_sid": "S-1-5-21",
    }
    assert object_facade_v4._project_attributes(attributes, {"field.hr", "field.contact"}) == {
        "department": "Finance", "email": "alice@example.invalid",
    }


def test_object_detail_reports_forbidden_evidence_and_hides_identity_links(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(object_facade_v4, "ensure_access_schema", lambda: None)
    monkeypatch.setattr(
        object_facade_v4,
        "get_entity_workspace_resource_preflight",
        lambda **_kwargs: {"id": 7, "entity_type": "ad_user", "domain_id": None, "server_id": None},
    )
    monkeypatch.setattr(
        object_facade_v4, "get_entity_workspace_detail_data",
        lambda **_kwargs: {
            "entity": {"id": 7, "type": "ad_user", "display_name": "Alice", "latest_state": {"status": "active"}},
            "ad_context": {"resolution": "resolved", "items": [{"context_kind": "entity", "attributes": {"department": "Finance", "object_sid": "S-1"}}]},
            "events": [{"event_db_id": 99, "message_text": "secret"}], "events_state": "available", "has_more": True,
            "current_states": [{"state": "active"}],
        },
    )
    calls = 0

    def rows(sql: str, *_args, **_kwargs):
        nonlocal calls
        calls += 1
        if "object_identity_links" in sql:
            return [{"source_object_id": "7", "confidence": 1.0}]
        return []

    monkeypatch.setattr(object_facade_v4, "query_rows_bounded", rows)
    access = {"capabilities": ["objects.view", "field.identity_basic", "field.security"]}
    result = object_facade_v4.object_detail(None, object_type="user", object_id="7", access=access)
    assert result["identity_links"] == []
    assert result["events"] == []
    assert result["events_state"] == "forbidden"
    assert result["has_more_events"] is False
    assert result["directory_context"]["items"][0]["attributes"] == {}
    assert "evidence.exact" in " ".join(result["limitations"])
    assert calls >= 1
