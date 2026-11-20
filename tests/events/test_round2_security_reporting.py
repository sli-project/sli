from __future__ import annotations

import json
from http import HTTPStatus

import pytest

pytestmark = pytest.mark.core

from server.api import http_server
from server.api.http_server import RequestHandler
from server.api.routes import health as routes_health
from server.sli.events import event_search
from server.sli.reporting import reporting_v4
from server.sli.events import security_events_monitor
from server.sli.access.access_control_v4 import (
    _version_bound_report_grant,
    capability_decision,
    capability_decision_for_resource_groups,
    normalize_capability_scope,
    report_action_decision,
    restrict_viewer_starter_sources,
    route_capability,
)
from server.sli.reporting.ui_api_models import EventListResponse


SENSITIVE_EVENT_KEYS = {
    "message_text", "event_data_json", "event_data", "raw_xml", "xml",
    "rendered_description", "properties", "subject_sid", "target_sid",
    "subject_name", "target_name", "subject_user_name", "target_user_name",
    "ip_address", "workstation", "workstation_name", "logon_id", "correlation_id",
}


def _assert_summary_only(value: object) -> None:
    if isinstance(value, dict):
        assert not (set(value) & SENSITIVE_EVENT_KEYS)
        for item in value.values():
            _assert_summary_only(item)
    elif isinstance(value, list):
        for item in value:
            _assert_summary_only(item)


def _raw_event_row() -> dict[str, object]:
    return {
        "id": 17,
        "event_db_id": 17,
        "event_id": 4624,
        "event_record_id": 99,
        "time_created_utc": "2026-07-22T00:00:00Z",
        "server": "REAL-DC",
        "channel": "Security",
        "provider_name": "Microsoft-Windows-Security-Auditing",
        "message_text": "ROUND2-RAW-MARKER",
        "event_data_json": json.dumps({"SubjectUserName": "ROUND2-IDENTITY-MARKER"}),
        "event_data": {"SubjectUserName": "ROUND2-IDENTITY-MARKER"},
        "subject_user_name": "ROUND2-IDENTITY-MARKER",
        "target_user_name": "ROUND2-TARGET-MARKER",
        "ip_address": "192.0.2.55",
        "workstation_name": "ROUND2-WORKSTATION-MARKER",
        "logon_id": "0xdeadbeef",
        "correlation_id": "ROUND2-CORRELATION-MARKER",
        "raw_xml": "<ROUND2-RAW-XML />",
    }


def test_event_summary_projection_recursively_removes_exact_evidence() -> None:
    projected = event_search.event_summary_projection(_raw_event_row())
    _assert_summary_only(projected)
    serialized = json.dumps(projected, ensure_ascii=False)
    assert "ROUND2-RAW-MARKER" not in serialized
    assert "ROUND2-IDENTITY-MARKER" not in serialized


@pytest.mark.parametrize("with_exact", [False, True])
def test_v1_event_list_remains_summary_only_even_with_exact_capability(
    monkeypatch: pytest.MonkeyPatch, with_exact: bool,
) -> None:
    from server.api.routes import events as routes_events

    handler = object.__new__(RequestHandler)
    captured: list[dict[str, object]] = []
    access = {"capabilities": ["events.view", *(["evidence.exact"] if with_exact else [])]}
    handler._effective_access_cache = access
    handler._send_json = lambda payload, status=HTTPStatus.OK: captured.append(payload)
    monkeypatch.setattr(routes_events, "get_event_search_data", lambda **_kwargs: {"items": [_raw_event_row()]})
    monkeypatch.setattr(routes_events, "get_event_category_counts", lambda **_kwargs: {})

    routes_events._handle_v1_events_api(handler, {})

    _assert_summary_only(captured[0])
    assert "ROUND2-RAW-MARKER" not in json.dumps(captured[0], ensure_ascii=False)
    EventListResponse(**captured[0])


def test_exact_detail_denies_before_read_and_allows_after_capability(monkeypatch: pytest.MonkeyPatch) -> None:
    from server.api.routes import events as routes_events

    denied = object.__new__(RequestHandler)
    denied._require_capability = lambda _capability: False
    monkeypatch.setattr(
        routes_events, "get_event_detail_report_data",
        lambda **_kwargs: pytest.fail("exact data read before authorization"),
    )
    routes_events._handle_event_by_id_api(denied, "/api/v1/events/17")

    allowed = object.__new__(RequestHandler)
    sent: list[dict[str, object]] = []
    allowed._require_capability = lambda capability: capability == "evidence.exact"
    allowed._send_json = lambda payload, status=HTTPStatus.OK: sent.append(payload)
    monkeypatch.setattr(routes_events, "get_event_detail_report_data", lambda **_kwargs: {
        "items": [{"id": 17, "event_id": 4624, "channel": "Security", "message_text": "exact"}],
    })
    routes_events._handle_event_by_id_api(allowed, "/api/v1/events/17")
    assert sent[0]["item"]["message_text"] == "exact"


def test_legacy_search_and_monitor_rendering_do_not_contain_raw_marker() -> None:
    item = event_search.event_summary_projection(_raw_event_row())
    search_html = event_search.render_event_search_report({"items": [item], "filters": {}, "performance": {}})
    monitor_item = security_events_monitor._decorate(_raw_event_row())
    monitor_html = security_events_monitor.render_security_events_monitor_report({
        "items": [monitor_item], "filters": {}, "summary": [], "category_counts": {},
        "matched_total": 1, "generated_at_utc": "2026-07-22T00:00:00Z",
    })
    assert "ROUND2-RAW-MARKER" not in search_html + monitor_html
    assert "ROUND2-IDENTITY-MARKER" not in search_html + monitor_html
    _assert_summary_only(monitor_item)


def test_arbitrary_report_artifact_fails_closed_before_file_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    from server.api.routes import legacy_reports as routes_legacy_reports

    handler = object.__new__(RequestHandler)
    sent: list[tuple[dict[str, object], HTTPStatus]] = []
    handler._send_json = lambda payload, status=HTTPStatus.OK: sent.append((payload, status))
    monkeypatch.setattr(routes_legacy_reports, "resolve_report", lambda _name: pytest.fail("unclassified artifact read"))

    routes_legacy_reports._handle_report(handler, "/reports/REAL-DC-security-profile.html")

    assert sent == [({"error": "report_artifact_unclassified"}, HTTPStatus.FORBIDDEN)]
    assert route_capability("/api/v1/reports/catalog") == "reports.catalog"
    assert route_capability("/reports/REAL-DC-security-profile.html") is None
    assert route_capability("/reports/event-details.html") == "evidence.exact"
    assert route_capability("/app/assets/main.js") is None
    assert route_capability("/login") is None


def test_capability_scope_parser_and_deny_decision_are_fail_closed() -> None:
    assert normalize_capability_scope(None) == ({"kind": "all"}, None)
    assert normalize_capability_scope({}) == ({"kind": "all"}, None)
    assert normalize_capability_scope({"kind": "all"}) == ({"kind": "all"}, None)
    for invalid in (
        {"ids": [7]}, {"kind": ""}, {"kind": "server", "ids": []},
        {"kind": "all", "ids": [7]}, {"kind": "unknown"}, "{broken-json",
    ):
        assert normalize_capability_scope(invalid)[1] == "invalid_scope"

    access = {
        "capabilities": ["events.view"],
        "capability_policies": [{
            "capability_key": "events.view", "effect": "deny",
            "scope": {"kind": "server", "ids": [7]}, "valid": True,
        }],
    }
    assert capability_decision(access, "events.view", resource={"kind": "server", "id": 7})["reason"] == "explicit_deny"
    assert capability_decision(access, "events.view", resource={"kind": "server", "id": 8})["allowed"] is True
    assert capability_decision(access, "events.view")["reason"] == "resource_context_required"

    invalid_deny = {**access, "capability_policies": [{
        "capability_key": "events.view", "effect": "deny", "valid": False,
        "diagnostic": "invalid_scope",
    }]}
    assert capability_decision(invalid_deny, "events.view")["reason"] == "invalid_scope_policy"
    global_deny = {**access, "capability_policies": [{
        "capability_key": "events.view", "effect": "deny",
        "scope": {"kind": "all"}, "valid": True,
    }]}
    assert capability_decision(global_deny, "events.view")["reason"] == "explicit_deny"


def test_resource_group_capability_requires_every_event_and_deny_wins() -> None:
    access = {
        "capabilities": [],
        "capability_policies": [
            {"capability_key": "investigations.view", "effect": "allow", "scope": {"kind": "server", "ids": [7, 8]}, "valid": True},
            {"capability_key": "investigations.view", "effect": "deny", "scope": {"kind": "channel", "values": ["System"]}, "valid": True},
        ],
    }
    covered = [
        [{"kind": "server", "id": 7}, {"kind": "channel", "value": "Security"}],
        [{"kind": "server", "id": 8}, {"kind": "channel", "value": "Directory Service"}],
    ]
    assert capability_decision_for_resource_groups(
        access, "investigations.view", resource_groups=covered,
    )["reason"] == "scoped_allow"
    denied = covered + [[{"kind": "server", "id": 8}, {"kind": "channel", "value": "System"}]]
    assert capability_decision_for_resource_groups(
        access, "investigations.view", resource_groups=denied,
    )["reason"] == "explicit_deny"
    uncovered = covered + [[{"kind": "server", "id": 9}]]
    assert capability_decision_for_resource_groups(
        access, "investigations.view", resource_groups=uncovered,
    )["reason"] == "insufficient_capability"
    assert capability_decision_for_resource_groups(
        access, "investigations.view", resource_groups=[],
    )["reason"] == "resource_context_required"


def test_platform_owner_has_full_capability_despite_recorded_denies() -> None:
    access = {
        "platform_owner": True,
        "capabilities": [],
        "capability_policies": [{
            "capability_key": "events.view",
            "effect": "deny",
            "scope": None,
            "valid": False,
        }],
    }
    assert capability_decision(access, "events.view")["reason"] == "platform_owner"
    assert capability_decision_for_resource_groups(
        access,
        "events.view",
        resource_groups=[[{"kind": "server", "id": 7}]],
    )["reason"] == "platform_owner"


def test_report_action_scope_keeps_grants_atomic_for_every_event() -> None:
    access = {
        "reports": [{
            "report_key": "investigations.workspace",
            "allowed": True,
            "grants": [
                {"scope": {"kind": "server", "ids": [7]}, "allowed_actions": ["view", "start_case"]},
                {"scope": {"kind": "channel", "values": ["Security"]}, "allowed_actions": ["view"]},
            ],
        }],
    }
    resources = [
        [{"kind": "server", "id": 7}, {"kind": "channel", "value": "System"}],
        [{"kind": "server", "id": 9}, {"kind": "channel", "value": "Security"}],
    ]
    assert report_action_decision(
        access, "investigations.workspace", "view", resource_groups=resources,
    )["reason"] == "report_scope_match"
    assert report_action_decision(
        access, "investigations.workspace", "start_case", resource_groups=resources,
    )["reason"] == "report_scope_denied"
    assert report_action_decision(
        access, "investigations.workspace", "view", resource_groups=[],
    )["reason"] == "resource_context_required"


def test_report_assignment_is_revalidated_without_widening_on_new_version() -> None:
    grant = {
        "scope": {"kind": "server", "ids": [7]},
        "field_categories": ["identity_basic", "technical"],
        "allowed_actions": ["view", "export"],
    }
    compatible = _version_bound_report_grant(
        grant, categories={"identity_basic", "security"}, actions={"view", "create_task"},
        report_version=3, dataset_version=2,
    )
    assert compatible is not None
    assert compatible["field_categories"] == ["identity_basic"]
    assert compatible["allowed_actions"] == ["view"]
    assert compatible["validated_report_version"] == 3
    assert compatible["validated_dataset_version"] == 2
    assert _version_bound_report_grant(
        grant, categories={"identity_basic"}, actions={"create_task"},
        report_version=4, dataset_version=2,
    ) is None


def test_viewer_restriction_applies_only_to_role_starter_source() -> None:
    sources = {
        "workspace.view": [{"source_type": "package", "source_origin": "role", "source": "viewer"}],
        "evidence.exact": [
            {"source_type": "package", "source_origin": "role", "source": "viewer"},
            {"source_type": "direct", "source_origin": "direct", "source": "user:7"},
        ],
        "reports.export": [{"source_type": "group", "source_origin": "group", "source": "group:3"}],
        "field.technical": [{"source_type": "package", "source_origin": "role", "source": "viewer"}],
    }
    bounded = restrict_viewer_starter_sources("viewer", sources)
    assert "workspace.view" in bounded
    assert bounded["evidence.exact"] == [sources["evidence.exact"][1]]
    assert bounded["reports.export"] == sources["reports.export"]
    assert "field.technical" not in bounded


@pytest.mark.parametrize("auth_enabled", [False, True])
def test_public_liveness_is_db_and_access_independent(
    monkeypatch: pytest.MonkeyPatch, auth_enabled: bool,
) -> None:
    monkeypatch.setattr(http_server, "effective_access", lambda *_args, **_kwargs: pytest.fail("access read"))
    monkeypatch.setattr(http_server, "auth_required", lambda: auth_enabled)
    monkeypatch.setattr(routes_health, "get_runtime_identity", lambda: {"runtime_instance_id": "safe"})
    monkeypatch.setattr(
        "server.sli.core.postgres_runtime_pipeline.connect",
        lambda: pytest.fail("database read"),
    )
    for path in ("/api/health", "/api/health/live"):
        handler = object.__new__(RequestHandler)
        handler.path = path
        sent: list[tuple[dict[str, object], HTTPStatus]] = []
        handler._send_json = lambda payload, status=HTTPStatus.OK: sent.append((payload, status))
        handler._do_GET()
        assert sent[0][1] == HTTPStatus.OK
        assert sent[0][0]["status"] == "ok"


def test_public_readiness_sanitizes_database_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "server.sli.core.postgres_runtime_pipeline.connect",
        lambda: (_ for _ in ()).throw(RuntimeError("sensitive database failure detail")),
    )
    handler = object.__new__(RequestHandler)
    handler.path = "/api/health/ready"
    sent: list[tuple[dict[str, object], HTTPStatus]] = []
    handler._send_json = lambda payload, status=HTTPStatus.OK: sent.append((payload, status))
    handler._do_GET()
    payload, status = sent[0]
    assert status == HTTPStatus.SERVICE_UNAVAILABLE
    assert payload == {"ready": False, "code": "postgres_unavailable"}
    assert "dsn" not in json.dumps(payload).lower()


def test_detailed_health_requires_operations_capability(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(http_server, "auth_required", lambda: False)
    handler = object.__new__(RequestHandler)
    handler.path = "/api/health/details"
    required: list[str] = []
    handler._require_capability = lambda capability: required.append(capability) or False
    handler._handle_health = lambda _query: pytest.fail("detailed diagnostics served without capability")
    handler._do_GET()
    assert required == ["operations.view"]


def _report_access() -> dict[str, object]:
    return {
        "capabilities": ["reports.catalog", "field.identity_basic", "field.technical", "reports.export"],
        "reports": [{
            "report_key": "tuple.test", "version": 1, "allowed": True,
            "field_categories": ["identity_basic", "technical"],
            "allowed_actions": ["view", "export"],
            "grants": [
                {"source": "A", "scope": {"kind": "server", "ids": [1]}, "field_categories": ["identity_basic"], "allowed_actions": ["view"]},
                {"source": "B", "scope": {"kind": "server", "ids": [2]}, "field_categories": ["technical"], "allowed_actions": ["view", "export"]},
            ],
        }],
    }


def test_disjoint_report_grants_default_to_separate_safe_projections(monkeypatch: pytest.MonkeyPatch) -> None:
    class Cursor:
        def execute(self, _query: str, _params: tuple[object, ...]) -> None: pass
        def fetchone(self) -> dict[str, object]:
            return {
                "dataset_key": "entities.v2",
                "definition_json": {"columns": ["name", "natural_key"], "actions": ["view", "export"], "export_policy": "controlled"},
                "fields_json": [
                    {"key": "name", "label": "Name", "category": "identity_basic"},
                    {"key": "natural_key", "label": "Key", "category": "technical"},
                ],
            }
        def __enter__(self): return self
        def __exit__(self, *_args): return None
    class Connection:
        def cursor(self): return Cursor()
        def __enter__(self): return self
        def __exit__(self, *_args): return None

    monkeypatch.setattr(reporting_v4, "_connect", lambda: Connection())
    monkeypatch.setattr(
        reporting_v4, "query_rows_bounded",
        lambda _sql, params=(), **_kwargs: [{"id": 77, "name": "basic-row", "natural_key": "technical-row"}],
    )

    result = reporting_v4.execute_report("tuple.test", None, access=_report_access())
    assert {tuple(sorted(row)) for row in result["items"]} == {("name",), ("natural_key",)}
    assert not any(set(row) == {"name", "natural_key"} for row in result["items"])
    assert result["field_visibility"] == "per_grant"
    assert len(result["branch_continuations"]) == 2
    assert all(
        len(item["grant_branch"]) == 64
        for item in result["branch_continuations"]
    )

    identity_branch = next(
        item
        for item in result["branch_continuations"]
        if item["fields"] == ["name"]
    )
    identity_page = reporting_v4.execute_report(
        "tuple.test",
        None,
        query_filters={"grant_branch": identity_branch["grant_branch"]},
        access=_report_access(),
    )
    assert identity_page["items"] == [{"name": "basic-row"}]
    assert identity_page["grant_branch"] == identity_branch["grant_branch"]

    with pytest.raises(PermissionError, match="report_field_access_denied"):
        reporting_v4.execute_report("tuple.test", None, fields=["name", "natural_key"], access=_report_access())
    with pytest.raises(PermissionError, match="report_field_access_denied"):
        reporting_v4.execute_report("tuple.test", None, fields=["name"], action="export", access=_report_access())
    exported = reporting_v4.execute_report("tuple.test", None, fields=["natural_key"], action="export", access=_report_access())
    assert exported["items"] == [{"natural_key": "technical-row"}]
