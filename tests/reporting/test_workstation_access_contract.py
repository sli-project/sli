"""Owner access -> declaration -> data -> navigation, with no PostgreSQL calls."""

from contextlib import nullcontext
from dataclasses import replace
from http import HTTPStatus
from types import SimpleNamespace

import pytest

from server.api.routes import reports_v2
from server.sli.access import access_control_v4
from server.sli.plugins.workstations import reports
from server.sli.plugins.workstations import scope as workstation_scope
from server.sli.reporting.v2 import registry


@pytest.fixture(autouse=True)
def no_external_history(monkeypatch):
    monkeypatch.setattr(reports.history, "configured_history", lambda: None)


class AccessCursor:
    def __init__(self, owner):
        self.owner = owner
        self.sql = ""

    def execute(self, sql, params=()):
        self.sql = " ".join(sql.split())

    def fetchone(self):
        assert "access_platform_owners" in self.sql
        return {"is_owner": self.owner}

    def fetchall(self):
        if "from access_capabilities order by" in self.sql:
            return [{"capability_key": key} for key in ("reports.catalog", *(f"field.{field}" for field in reports.FIELDS))]
        if "from report_registry_v4 r join report_datasets_v4" in self.sql:
            return [{
                "report_key": key, "version": 1, "name": title, "owner_name": "fixture",
                "purpose": "fixture purpose", "sensitivity": "restricted", "status": "published",
                "dataset_key": "workstations.security", "dataset_version": 1,
                "definition_json": {"field_categories": sorted(reports.FIELDS), "actions": ["view"]},
                "fields_json": [{"category": field} for field in reports.FIELDS], "actions_json": ["view"],
                "discoverable": True, "requestable": False,
            } for key, title in reports.REPORTS.values()]
        return []


def effective(monkeypatch, *, owner):
    cursor = AccessCursor(owner)
    monkeypatch.setattr(access_control_v4, "ensure_access_schema", lambda: None)
    monkeypatch.setattr(access_control_v4, "_connect", lambda: nullcontext(SimpleNamespace(cursor=lambda: nullcontext(cursor))))
    return access_control_v4.effective_access({"type": "session", "id": 7, "role": "viewer", "username": "fixture-user"})


class Handler:
    def __init__(self, access):
        self.access = access
        self.payload = None
        self.status = None

    def _access_decision(self):
        return self.access

    def _send_json(self, payload, status=HTTPStatus.OK):
        self.payload, self.status = payload, status


@pytest.mark.parametrize("enabled", [True, False])
def test_owner_full_grant_opens_all_four_reports_and_enablement_controls_menu(monkeypatch, enabled):
    access = effective(monkeypatch, owner=True)
    monkeypatch.setattr(reports_v2, "report_plugin_state", lambda key: None)
    cursor = DataCursor()
    monkeypatch.setattr(workstation_scope, "connect", lambda: nullcontext(SimpleNamespace(cursor=lambda: nullcontext(cursor))))
    monkeypatch.setattr(reports, "connect", lambda: nullcontext(SimpleNamespace(cursor=lambda: nullcontext(cursor))))
    assert access["platform_owner"]
    for key, title in reports.REPORTS.values():
        grant = next(item for item in access["reports"] if item["report_key"] == key)
        assert grant["allowed"] and grant["explanation_code"] == "platform_owner"
        assert set(grant["grants"][0]["field_categories"]) == reports.FIELDS
        assert grant["grants"][0]["scope"] == {"kind": "all"}
        handler = Handler(access)
        reports_v2.try_handle_get(handler, f"/api/v2/reports/{key}", {})
        assert handler.status == HTTPStatus.OK and handler.payload["title"] == title
        reports_v2.try_handle_get(handler, f"/api/v2/reports/{key}/data", {})
        assert handler.status == HTTPStatus.OK
        assert handler.payload["state"] == "partial"
        snapshots = [row for row in handler.payload["items"] if row["quality"].get("snapshot")]
        events = [row for row in handler.payload["items"] if not row["quality"].get("snapshot")]
        assert [row["agent_key"] for row in events] == ["fixture-pilot", "fixture-other"]
        assert [row["agent_key"] for row in snapshots] == (
            ["fixture-pilot", "fixture-other"] if key == "workstations.protection" else [])

    catalog = registry.catalog(access, plugin_states=[{"plugin_id": "sli.workstations", "enabled": enabled}])
    keys = {key for key, _ in reports.REPORTS.values()}
    assert keys <= {item["key"] for item in catalog["items"] if item["executable"]}
    paths = {entry["path"] for section in catalog["navigation"]["sections"]
             for group in section["groups"] for entry in group["entries"]}
    workstation_paths = {f"/report/{key}" for key in keys}
    assert workstation_paths <= paths if enabled else not workstation_paths & paths


class DataCursor:
    def __init__(self):
        self.sql = ""
        self.params = ()

    def execute(self, sql, params=()):
        self.sql, self.params = " ".join(sql.split()), params

    def fetchall(self):
        if "enrolled.host_name as enrolled_name" in self.sql:
            return []
        if self.sql.startswith("select wanted.agent_key, recent.source_xml"):
            assert "from unnest(%s::text[]) wanted(agent_key)" in self.sql
            assert self.params[0] and set(self.params[0]) <= {"fixture-pilot", "fixture-other"}
            return []
        if "from sli_agents a" in self.sql:
            assert "m->>'module_id'='sli.workstations'" in self.sql
            assert self.params[-1] == reports.MAX_STATIONS + 1
            if "core_entity_scope_resources" in self.sql:
                assert "r.collection_scope_id = ANY(%s)" in self.sql
                assert self.params == (["ad-domain:11"], reports.MAX_STATIONS + 1)
                return [{"agent_key": "fixture-pilot"}]
            return [{"agent_key": key} for key in ("fixture-pilot", "fixture-other")]
        if "from sli_plugin_workstations.protection_state" in self.sql:
            assert "agent_key=any(%s)" in self.sql
            assert self.params[-1] == reports.MAX_STATIONS
            return [{"id": "c" + str(index) * 63, "agent_key": key,
                     "semantic_type": "security.protection.state",
                     "facts": {"real_time_protection_enabled": False},
                     "quality": {"snapshot": True, "state": "available"}}
                    for index, key in enumerate(self.params[0], 1)]
        assert "from sli_plugin_workstations.observations" in self.sql
        assert "agent_key=any(%s)" in self.sql
        return [{"id": str(index) * 64, "agent_key": key, "facts": {}, "quality": {}}
                for index, key in enumerate(self.params[0], 1)]


@pytest.mark.parametrize("family", list(reports.REPORTS))
@pytest.mark.parametrize("scope,expected", [
    ({"kind": "domain", "ids": [11]}, ["fixture-pilot"]),
    ({"mode": "restricted", "clauses": [{"collection_scope_ids": ["ad-domain:11"]}]}, ["fixture-pilot"]),
    ({"kind": "unknown"}, []),
])
def test_four_data_endpoints_enforce_scopes_with_production_adapter(monkeypatch, family, scope, expected):
    access = effective(monkeypatch, owner=True)
    access["platform_owner"] = False
    for report in access["reports"]:
        report["grants"][0]["scope"] = scope
    monkeypatch.setattr(reports_v2, "report_plugin_state", lambda key: None)
    cursor = DataCursor()
    connection = lambda: nullcontext(SimpleNamespace(cursor=lambda: nullcontext(cursor)))
    monkeypatch.setattr(workstation_scope, "connect", connection)
    monkeypatch.setattr(reports, "connect", connection if expected else lambda: pytest.fail("unresolved scope queried observations"))
    key = reports.REPORTS[family][0]
    definition = reports.make_report(family)
    original_query = definition.query

    def query(context):
        assert isinstance(context.runtime["workstation_scope_adapter"], workstation_scope.WorkstationScopeAdapter)
        return original_query(context)

    monkeypatch.setattr(reports_v2, "get_report", lambda report_key: replace(definition, query=query))
    handler = Handler(access)
    assert reports_v2.try_handle_get(handler, f"/api/v2/reports/{key}/data", {})
    assert handler.status == HTTPStatus.OK
    assert handler.payload["state"] == "partial"
    snapshots = [row for row in handler.payload["items"] if row["quality"].get("snapshot")]
    events = [row for row in handler.payload["items"] if not row["quality"].get("snapshot")]
    assert [row["agent_key"] for row in events] == expected
    assert [row["agent_key"] for row in snapshots] == (expected if family == "protection" else [])
    assert all(row["facts"]["real_time_protection_enabled"] is False for row in snapshots)
    if not expected:
        assert handler.payload["limitations"][0]["code"] == "workstation_scope_unresolved"


def test_enablement_does_not_grant_unassigned_reports_or_disclose_declarations(monkeypatch):
    access = effective(monkeypatch, owner=False)
    monkeypatch.setattr(reports, "connect", lambda: pytest.fail("denied report must not query data"))
    catalog = registry.catalog(access, plugin_states=[{"plugin_id": "sli.workstations", "enabled": True}])
    assert not any(item["key"].startswith("workstations.") for item in catalog["items"])
    assert not any(section["id"] == "workstations" for section in catalog["navigation"]["sections"])
    for key, _ in reports.REPORTS.values():
        for suffix in ("", "/data"):
            handler = Handler(access)
            reports_v2.try_handle_get(handler, f"/api/v2/reports/{key}{suffix}", {})
            assert handler.status == HTTPStatus.FORBIDDEN
            assert handler.payload == {"error": "report_access_denied"}
