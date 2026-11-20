from __future__ import annotations

import io
import json
from dataclasses import replace

import pytest
from psycopg import OperationalError

from server.api.routes import reports_v2 as routes
from server.sli.access import domain_scope
from server.sli.reporting.v2 import registry
from server.sli.reporting.v2.access import ReportAccess
from server.sli.reporting.v2.definition import (
    AccessRule,
    Column,
    Detail,
    Param,
    ReportDefinition,
    View,
    csv_from_columns,
    result,
)
from server.sli.reporting.v2.reports import users
from server.sli.sources import plugin_state


def grant(fields, ids=(1,), actions=("view", "export")):
    return {"field_categories": list(fields), "scope": {"kind": "domain", "ids": list(ids)}, "allowed_actions": list(actions)}


def access(*grants, key="fixture.report"):
    return {"reports": [{"report_key": key, "allowed": True, "allowed_actions": ["view", "export"], "grants": list(grants)}]}


class Handler:
    def __init__(self, decision):
        self.decision = decision
        self.sent = []
        self.wfile = io.BytesIO()
        self.headers = {}

    def _access_decision(self):
        return self.decision

    def _send_json(self, payload, status=200):
        self.sent.append((payload, int(status)))

    def send_response(self, status):
        self.status = status

    def send_header(self, key, value):
        self.headers[key] = value

    def end_headers(self):
        pass


def call(monkeypatch, definition, decision, suffix="", query=None):
    monkeypatch.setattr(routes, "get_report", lambda _key: definition)
    monkeypatch.setattr(domain_scope, "_domain_rows", lambda ids: [
        {"id": key, "display_name": f"domain-{key}.example.test"} for key in (ids or [])
    ])
    handler = Handler(decision)
    assert routes.try_handle_get(handler, f"/api/v2/reports/{definition.key}{suffix}", query or {})
    return handler


def definition(**overrides):
    columns = (Column("name", "Name"), Column("department", "Department", sortable=True, field_categories=frozenset({"hr"})))
    values = {
        "key": "fixture.report", "section": "reports/identity", "title": "Fixture", "description": "", "archetype": "inventory-status",
        "access": AccessRule("fixture.report", frozenset({"identity_basic"})),
        "columns": columns, "params": (replace(Param.text("department", "Department"), field_categories=frozenset({"hr"})),), "row_key": "id",
        "metric_categories": {"hr_count": frozenset({"hr"})},
    }
    values.update(overrides)
    report = ReportDefinition(query=lambda ctx: {}, **values)
    return replace(report, query=lambda ctx: result(report, state="ok", items=[{"id": 1, "name": "Synthetic account", "department": "hidden-marker"}],
                   metrics=[{"key": "hr_count", "value": 1}], filter_options={"department": [{"value": "hidden-marker"}]}),
                   export_csv=lambda ctx: (csv_from_columns(columns, [{"name": "Synthetic account", "department": "hidden-marker"}]), {"rows": 1}))


def test_metadata_data_metrics_filters_and_csv_hide_unavailable_category(monkeypatch):
    report = definition()
    decision = access(grant({"identity_basic"}))
    metadata, status = call(monkeypatch, report, decision).sent[-1]
    assert status == 200
    assert [col["key"] for col in metadata["columns"]] == ["name"]
    assert metadata["params"] == []
    assert metadata["access"]["hidden_categories"] == ["hr"]
    payload, status = call(monkeypatch, report, decision, "/data").sent[-1]
    assert status == 200
    assert payload["items"] == [{"id": 1, "name": "Synthetic account"}]
    assert payload["metrics"] == [] and payload["filter_options"] == {}
    assert "hidden-marker" not in json.dumps(payload)
    exported = call(monkeypatch, report, decision, "/export.csv")
    assert exported.status == 200
    assert exported.wfile.getvalue().decode("utf-8-sig").splitlines() == ["Name", "Synthetic account"]


@pytest.mark.parametrize("suffix", ["", "/data"])
@pytest.mark.parametrize("state", ["enabled", "disabled", "unknown"])
def test_plugin_metadata_preserves_field_access_projection(monkeypatch, suffix, state):
    plugin = {"plugin_id": "sli.remote-access", "state": state, "read_only": state != "enabled"}
    report = definition(key="vpn.connections", options=lambda _access: {"department": [{"value": "hidden-marker"}]})
    # Both declaration and data annotation must use the same fake state source.
    monkeypatch.setattr(plugin_state, "list_plugin_states", lambda: [] if state == "unknown" else [
        {"plugin_id": plugin["plugin_id"], "enabled": state == "enabled"},
    ])

    payload, status = call(monkeypatch, report, access(grant({"identity_basic"})), suffix).sent[-1]

    assert status == 200
    assert payload["plugin"] == plugin
    assert payload["access"]["allowed"] is True
    assert payload["access"]["hidden_categories"] == ["hr"]
    assert payload["filter_options"] == {}
    assert "hidden-marker" not in json.dumps(payload)
    if suffix:
        assert payload["items"] == [{"id": 1, "name": "Synthetic account"}]
        assert payload["metrics"] == []
    else:
        assert [col["key"] for col in payload["columns"]] == ["name"]
        assert payload["params"] == []


@pytest.mark.parametrize("suffix", ["", "/data"])
@pytest.mark.parametrize("error_type", [OperationalError, RuntimeError])
def test_plugin_state_lookup_failure_retains_field_access_projection(monkeypatch, suffix, error_type):
    def unavailable():
        raise error_type("lookup-failure-marker")

    monkeypatch.setattr(plugin_state, "list_plugin_states", unavailable)
    report = definition(key="vpn.connections")

    payload, status = call(monkeypatch, report, access(grant({"identity_basic"})), suffix).sent[-1]

    assert status == 200
    assert payload["plugin"] == {"plugin_id": "sli.remote-access", "state": "unknown", "read_only": True}
    assert payload["access"]["allowed"] is True
    assert payload["access"]["hidden_categories"] == ["hr"]
    assert "lookup-failure-marker" not in json.dumps(payload)
    assert "hidden-marker" not in json.dumps(payload)
    if suffix:
        assert payload["items"] == [{"id": 1, "name": "Synthetic account"}]
        assert payload["metrics"] == []


@pytest.mark.parametrize("query", [{"department": ["hidden-marker"]}, {"sort": ["department"]}])
def test_hidden_filters_and_sort_cannot_be_used_as_an_oracle(monkeypatch, query):
    payload, status = call(monkeypatch, definition(), access(grant({"identity_basic"})), "/data", query).sent[-1]
    assert status == 403 and payload["reason"] == "report_field_categories_not_allowed"
    assert payload["access"]["hidden_categories"] == ["hr"]


@pytest.mark.parametrize("grants", [
    (grant({"identity_basic"}, (1, 2)), grant({"identity_basic", "hr"}, (1,))),
    (grant({"identity_basic"}, (1,)), grant({"hr"}, (1,))),
    (grant({"identity_basic"}, (1,)), grant({"identity_basic", "hr"}, (2,), ("export",))),
])
def test_categories_never_borrow_another_grants_scope_or_action(monkeypatch, grants):
    payload, status = call(monkeypatch, definition(), access(*grants), "/data").sent[-1]
    assert status == 200 and "department" not in payload["items"][0]


def test_view_and_detail_denial_is_local_and_queries_do_not_run(monkeypatch):
    rule = AccessRule("fixture.report", frozenset({"hr"}))
    report = definition(views=(View("table"), View("table", "restricted", source="restricted", access=rule)),
                        detail=Detail("Restricted detail", "id", (), query=lambda *_: pytest.fail("denied detail executed"), access=rule))
    report = replace(report, query=lambda ctx: result(report, state="ok", items=[{"id": 1, "name": "Synthetic account", "reasons": [{"value": "hidden-marker"}]}],
                                                      collections={"restricted": [{"value": "hidden-marker"}]}))
    decision = access(grant({"identity_basic"}))
    metadata = call(monkeypatch, report, decision).sent[-1][0]
    assert metadata["views"][1]["access"]["allowed"] is False
    assert metadata["detail"]["access"]["allowed"] is False
    payload, status = call(monkeypatch, report, decision, "/data").sent[-1]
    assert status == 200 and payload["collections"] == {}
    for suffix, query in [("/data", {"tab": ["restricted"]}), ("/rows/1/detail", {})]:
        payload, status = call(monkeypatch, report, decision, suffix, query).sent[-1]
        assert status == 403
        assert payload["state"] == "denied"
        assert payload["reason"] == "report_field_categories_not_allowed"
    assert call(monkeypatch, report, decision, "/data").sent[-1][1] == 200


def test_users_without_hr_open_and_do_not_search_or_export_hr(monkeypatch):
    current = {"metadata": {"observed_at": "2026-10-05T00:00:00Z", "collection_status": "completed"},
               "users": [{"id": "fixture-user", "entityId": 1, "displayName": "Synthetic account", "samAccountName": "fixture",
                          "department": "hidden-marker", "title": "hidden-marker", "employeeID": "hidden-marker", "enabled": True}], "groups": []}
    previous = {**current, "users": [{**current["users"][0], "department": "old-hidden-marker"}]}
    monkeypatch.setattr(users, "_snapshots", lambda *_args, **_kwargs: {"state": "ok", "current": current, "previous": previous})
    decision = access(grant({"identity_basic", "technical", "security", "privilege", "contact"}), key=users.REPORT_KEY)
    monkeypatch.setattr(registry, "registered_reports", lambda: (users.REPORT,))
    assert registry.catalog(decision)["items"][0]["executable"] is True
    metadata, status = call(monkeypatch, users.REPORT, decision).sent[-1]
    assert status == 200
    assert {c["key"] for c in metadata["columns"]}.isdisjoint({"department", "title", "company", "manager", "employee_id"})
    payload, status = call(monkeypatch, users.REPORT, decision, "/data", {"tab": ["all"]}).sent[-1]
    assert status == 200 and len(payload["items"]) == 1
    assert "hidden-marker" not in json.dumps(payload)
    assert payload["collections"] == {}
    searched, _ = call(monkeypatch, users.REPORT, decision, "/data", {"tab": ["all"], "q": ["hidden-marker"]}).sent[-1]
    assert searched["items"] == []
    exported = call(monkeypatch, users.REPORT, decision, "/export.csv", {"tab": ["all"]})
    assert "hidden-marker" not in exported.wfile.getvalue().decode("utf-8-sig")
    assert current["users"][0]["department"] == "hidden-marker"  # Shared snapshot remains untouched.


@pytest.mark.parametrize("tab,required", [("all", {"security"}), ("checks", {"security", "technical", "privilege"}),
                                         ("privileged", {"security", "privilege"})])
def test_users_tabs_require_atomic_categories_before_any_source_read(monkeypatch, tab, required):
    monkeypatch.setattr(users, "_snapshots", lambda *_args, **_kwargs: pytest.fail("denied tab read snapshot"))
    for missing in required:
        fields = {"identity_basic", *required} - {missing}
        decision = access(grant(fields), key=users.REPORT_KEY)
        metadata, status = call(monkeypatch, users.REPORT, decision).sent[-1]
        assert status == 200
        view = next(view for view in metadata["views"] if view["key"] == tab)
        assert not view["access"]["allowed"]
        data, status = call(monkeypatch, users.REPORT, decision, "/data", {"tab": [tab]}).sent[-1]
        assert status == 403 and data["state"] == "denied"


def test_denied_default_view_does_not_execute(monkeypatch):
    report = definition(views=(View("table", access=AccessRule("fixture.report", frozenset({"hr"}))),))
    report = replace(report, query=lambda _: pytest.fail("denied default view executed"))
    payload, status = call(monkeypatch, report, access(grant({"identity_basic"})), "/data").sent[-1]
    assert status == 403 and payload["reason"] == "report_field_categories_not_allowed"


def test_inline_nested_detail_denial_and_non_column_paths_are_projected(monkeypatch):
    report = definition(detail=Detail("Restricted", "id", (), inline="nested.reasons", access=AccessRule("fixture.report", frozenset({"hr"}))),
                        row_categories={"nested.secret": frozenset({"hr"})}, series_categories={"hr_total": frozenset({"hr"})})
    report = replace(report, query=lambda _: result(report, state="ok", items=[{"id": 1, "nested": {"reasons": [{"value": "hidden-marker"}], "secret": "hidden-marker"}}], series={"hr_total": 1}))
    payload, status = call(monkeypatch, report, access(grant({"identity_basic"})), "/data").sent[-1]
    assert status == 200 and payload["items"] == [{"id": 1, "nested": {}}]
    assert payload["series"] == {}


def test_hidden_required_param_does_not_close_the_report(monkeypatch):
    report = definition(params=(Param("department", "Department", "text", required=True, field_categories=frozenset({"hr"})),))
    assert call(monkeypatch, report, access(grant({"identity_basic"})), "/data").sent[-1][1] == 200


def test_csv_projection_does_not_match_duplicate_labels():
    report = definition(columns=(Column("name", "Value"), Column("department", "Value", field_categories=frozenset({"hr"}))))
    projection = ReportAccess(report, access(grant({"identity_basic"})))
    body = csv_from_columns(report.columns, [{"name": "Synthetic account", "department": "hidden-marker"}])
    assert "hidden-marker" not in projection.csv(body)


def test_filter_options_use_the_declared_source_key(monkeypatch):
    report = definition(params=(Param.choice("department", "Department", options_from="departments"),))
    report = replace(report, options=lambda _: {"departments": [{"value": "Synthetic department"}]},
                     query=lambda _: result(report, state="ok", filter_options={"departments": [{"value": "Synthetic department"}]}))
    decision = access(grant({"identity_basic"}))
    assert "departments" in call(monkeypatch, report, decision).sent[-1][0]["filter_options"]
    assert "departments" in call(monkeypatch, report, decision, "/data").sent[-1][0]["filter_options"]


def test_items_view_columns_are_removed_from_data(monkeypatch):
    report = definition(columns=(Column("name", "Name"),), views=(View("table", columns=(Column("department", "Department", field_categories=frozenset({"hr"})),)),))
    payload, status = call(monkeypatch, report, access(grant({"identity_basic"})), "/data").sent[-1]
    assert status == 200 and "department" not in payload["items"][0]


def test_separate_report_rule_denies_only_its_view(monkeypatch):
    report = definition(views=(View("table"), View("table", "restricted", access=AccessRule("fixture.detail", frozenset({"hr"}))),))
    decision = access(grant({"identity_basic", "hr"}))
    assert call(monkeypatch, report, decision, "/data").sent[-1][1] == 200
    payload, status = call(monkeypatch, report, decision, "/data", {"tab": ["restricted"]}).sent[-1]
    assert status == 403 and payload["reason"] == "report_access_denied"


@pytest.mark.parametrize("category, attribute", [("hr", "department"), ("hr", "employeeID"), ("contact", "mail"), ("contact", "telephoneNumber"), ("technical", "sid")])
def test_users_search_does_not_match_an_isolated_hidden_attribute(monkeypatch, category, attribute):
    current = {"metadata": {"observed_at": "2026-10-05T00:00:00Z"}, "users": [{"id": "fixture-user", "entityId": 1, "displayName": "Synthetic account", "samAccountName": "fixture", "enabled": True, attribute: "hidden-marker"}]}
    monkeypatch.setattr(users, "_snapshots", lambda *_args, **_kwargs: {"state": "ok", "current": current})
    decision = access(grant({"identity_basic", "technical", "security", "privilege", "hr", "contact"} - {category}), key=users.REPORT_KEY)
    payload, status = call(monkeypatch, users.REPORT, decision, "/data", {"tab": ["all"], "q": ["hidden-marker"]}).sent[-1]
    assert status == 200 and payload["items"] == [] and payload["filtered_count"] == 0


def test_category_visibility_requires_full_scope_including_all_scope():
    report = definition()
    all_scope = {**grant({"identity_basic"}), "scope": {"kind": "all"}}
    projection = ReportAccess(report, access(all_scope, grant({"identity_basic", "hr"})))
    assert projection.domain_ids is None
    assert not projection.fields_allowed(frozenset({"hr"}))


def test_same_report_tab_cannot_borrow_core_from_another_grant():
    projection = ReportAccess(definition(), access(grant({"identity_basic"}), grant({"hr"})))
    assert not projection.rule_decision(AccessRule("fixture.report", frozenset({"hr"})))["allowed"]


def test_core_denial_has_safe_reason_and_does_not_execute(monkeypatch):
    report = replace(definition(), query=lambda _: pytest.fail("denied core executed"))
    for suffix in ("", "/data", "/export.csv"):
        payload, status = call(monkeypatch, report, access(grant({"hr"})), suffix).sent[-1]
        assert status == 403 and payload["reason"] == "report_field_categories_not_allowed"


def test_engine_denial_has_explicit_reason_and_no_data(monkeypatch):
    report = definition()
    report = replace(report, query=lambda _: result(report, state="denied", items=[{"name": "hidden-marker"}], metrics=[{"key": "count", "value": 1}]))
    payload, status = call(monkeypatch, report, access(grant({"identity_basic"})), "/data").sent[-1]
    assert status == 200 and payload["state"] == "denied"
    assert payload["reason"] == "report_access_denied"
    assert payload["access"]["allowed"] is False
    assert payload["items"] == [] and payload["metrics"] == []


@pytest.mark.parametrize("category", ["hr", "contact", "security", "privilege", "technical"])
def test_users_hidden_categories_do_not_affect_search_details_or_metrics(monkeypatch, category):
    user = {"id": "fixture-user", "entityId": 1, "samAccountName": "fixture", "displayName": "Synthetic account", "enabled": True,
            "department": "hidden-marker", "mail": "hidden-marker", "description": "hidden-marker", "lockedOut": True,
            "memberships": {"status": "partial", "unresolved": ["hidden-marker"], "effective": [{"id": "group", "name": "hidden-marker", "watchGroup": True}]}}
    current = {"metadata": {"observed_at": "2026-10-05T00:00:00Z"}, "users": [user], "groups": [{"id": "group", "name": "hidden-marker"}]}
    previous = {**current, "users": [{**user, "department": "old", "mail": "old", "description": "old", "lockedOut": False, "memberships": {}}]}
    monkeypatch.setattr(users, "_snapshots", lambda *_args, **_kwargs: {"state": "ok", "current": current, "previous": previous})
    fields = {"identity_basic", "technical", "security", "privilege", "hr", "contact"} - {category}
    decision = access(grant(fields), key=users.REPORT_KEY)
    payload, status = call(monkeypatch, users.REPORT, decision, "/data", {"tab": ["all"]}).sent[-1]
    if category == "security":
        assert status == 403 and payload["state"] == "denied"
        return
    assert status == 200
    row = payload["items"][0]
    hidden_paths = {"hr": {"department", "company", "title", "manager", "employee_id"}, "contact": {"mail", "phones"},
                    "technical": {"description", "sid", "guid", "dn", "ou", "created", "changed", "spn"},
                    "security": {"enabled", "locked", "account_expired", "activity_at", "activity_source", "password_last_set", "password_never_expires", "flags"},
                    "privilege": {"direct_groups", "effective_count", "watch_groups"}}[category]
    assert hidden_paths.isdisjoint(row)
    if category in {"security", "privilege", "technical"}:
        assert not any(key in row for key in ("reasons", "reason_keys", "reason_text", "information_limitations", "information_keys", "information_text", "review_details"))
        assert {metric["key"] for metric in payload["metrics"]} <= {"all"}
