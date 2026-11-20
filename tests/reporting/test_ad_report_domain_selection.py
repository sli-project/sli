"""Shared domain selection must narrow each AD report before any data read."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from io import BytesIO

import pytest

from server.api.routes import reports_v2 as routes
from server.sli.access import domain_scope
from server.sli.plugins.ad.reports import computers_v6_reporting as computers
from server.sli.plugins.ad import directory_projection
from server.sli.plugins.ad.reports import users_v2_reporting
from server.sli.plugins.ad.reports.definitions import ad_state, computers as computer_report, users
from server.sli.reporting.v2.definition import csv_from_columns, result
from server.sli.reporting.v2.definition import QueryContext
from server.sli.core import platform_settings


DOMAINS = {11: "alpha.example.test", 22: "beta.example.test"}
NOW = datetime.now(timezone.utc)


class Handler:
    def __init__(self, definition, *, ids=(11, 22), export_ids=None):
        def grant(action, domains):
            return {"allowed_actions": [action], "field_categories": [
                "identity_basic", "technical", "security", "privilege", "identity_extended", "contacts",
            ], "scope": {"kind": "domain", "ids": list(domains)}}

        self.access = {"reports": [{
            "report_key": definition.access.report_key, "allowed": True, "allowed_actions": ["view", "export"],
            "grants": [grant("view", ids), grant("export", export_ids if export_ids is not None else ids)],
        }]}
        self.status = None
        self.payload = None
        self.headers = {}
        self.wfile = BytesIO()

    def _access_decision(self):
        return self.access

    def _send_json(self, payload, status=200):
        self.payload, self.status = payload, status

    def send_response(self, status):
        self.status = status

    def send_header(self, key, value):
        self.headers[key] = value

    def end_headers(self):
        pass


@pytest.fixture
def domain_rows(monkeypatch):
    calls = []

    def read(ids):
        calls.append(ids)
        return [{"id": key, "display_name": value,
                 "observed_at_utc": NOW - timedelta(days=key == 22),
                 "snapshot_state": "complete"} for key, value in DOMAINS.items() if ids is None or key in ids]

    monkeypatch.setattr(domain_scope, "_domain_rows", read)
    monkeypatch.setattr(routes, "annotate_plugin_report", lambda *_: None)
    return calls


@pytest.mark.parametrize("definition", [users.REPORT, computer_report.REPORT, ad_state.REPORT])
@pytest.mark.parametrize("selected,expected", [(None, [11, 22]), ("22", [22])])
@pytest.mark.parametrize("action", ["data", "export.csv"])
def test_route_scopes_rows_counts_and_csv(monkeypatch, domain_rows, definition, selected, expected, action):
    reads = []

    def query(context):
        reads.append(context.domain_ids)
        rows = [{"id": key, "display_name": DOMAINS[key], "entity_name": DOMAINS[key]} for key in context.domain_ids]
        return result(definition, state="ok", items=rows, filtered_count=len(rows),
                      metrics=[{"key": "all", "label": "All", "value": len(rows)}])

    def export(context):
        data = query(context)
        return csv_from_columns(definition.columns, data["items"]), {"rows": len(data["items"])}

    monkeypatch.setattr(routes, "get_report", lambda _: replace(definition, query=query, export_csv=export))
    handler = Handler(definition)
    params = {} if selected is None else {"domain_id": [selected]}
    routes.try_handle_get(handler, f"/api/v2/reports/{definition.key}/{action}", params)
    assert handler.status == 200, handler.payload
    assert reads == [expected]
    if action == "data":
        assert handler.payload["filtered_count"] == len(expected)
        assert handler.payload["metrics"][0]["value"] == len(expected)
        assert handler.payload["domain_scope"]["domain_ids"] == expected
        assert [domain["id"] for domain in handler.payload["domains"]] == expected
        if selected is None:
            assert len({domain["freshness"]["observed_at_utc"] for domain in handler.payload["domains"]}) == 2
    else:
        assert handler.headers["X-Sli-Export-Rows"] == str(len(expected))
        text = handler.wfile.getvalue().decode("utf-8-sig")
        for key, name in DOMAINS.items():
            assert (name in text) == (key in expected)


@pytest.mark.parametrize("definition", [users.REPORT, computer_report.REPORT, ad_state.REPORT])
@pytest.mark.parametrize("action", ["data", "export.csv"])
def test_foreign_domain_denied_before_metadata_or_report_read(monkeypatch, domain_rows, definition, action):
    monkeypatch.setattr(routes, "get_report", lambda _: definition)
    handler = Handler(definition, ids=(11,), export_ids=(11,))
    routes.try_handle_get(handler, f"/api/v2/reports/{definition.key}/{action}", {"domain_id": ["22"]})
    assert handler.status == 403
    assert domain_rows == []


@pytest.mark.parametrize("value", [[], [""], ["0"], ["-1"], ["all"], ["11", "22"], [str(2**63)]])
def test_invalid_selection_is_400(monkeypatch, domain_rows, value):
    monkeypatch.setattr(routes, "get_report", lambda _: computer_report.REPORT)
    handler = Handler(computer_report.REPORT)
    routes.try_handle_get(handler, "/api/v2/reports/ad.computers.v6/data", {"domain_id": value})
    assert handler.status == 400
    assert domain_rows == []


def test_export_selection_uses_export_grants(monkeypatch, domain_rows):
    monkeypatch.setattr(routes, "get_report", lambda _: computer_report.REPORT)
    handler = Handler(computer_report.REPORT, export_ids=(11,))
    routes.try_handle_get(handler, "/api/v2/reports/ad.computers.v6/export.csv", {"domain_id": ["22"]})
    assert handler.status == 403
    assert domain_rows == []


@pytest.mark.parametrize("selected,expected", [(None, [11, 22]), ("22", [22])])
def test_all_grant_is_materialized_as_registered_domains(monkeypatch, domain_rows, selected, expected):
    reads = []
    definition = replace(ad_state.REPORT, query=lambda ctx: reads.append(ctx.domain_ids) or result(ad_state.REPORT, state="empty"))
    monkeypatch.setattr(routes, "get_report", lambda _: definition)
    handler = Handler(definition)
    for grant in handler.access["reports"][0]["grants"]:
        grant["scope"] = {"kind": "all"}
    routes.try_handle_get(handler, "/api/v2/reports/ad.infrastructure/data", {} if selected is None else {"domain_id": [selected]})
    assert handler.status == 200
    assert reads == [expected]


def test_other_report_grant_cannot_authorize_selection(monkeypatch, domain_rows):
    monkeypatch.setattr(routes, "get_report", lambda _: users.REPORT)
    handler = Handler(users.REPORT, ids=(11,))
    other = Handler(computer_report.REPORT, ids=(22,))
    handler.access["reports"].extend(other.access["reports"])
    routes.try_handle_get(handler, "/api/v2/reports/ad.users.v2/data", {"domain_id": ["22"]})
    assert handler.status == 403
    assert domain_rows == []


@pytest.mark.parametrize("selected", [{"domain": ["22"]}, {"domain": ["22"], "domain_id": ["22"]}])
def test_legacy_domain_alias_keeps_selection(monkeypatch, domain_rows, selected):
    seen = []
    definition = replace(users.REPORT, query=lambda ctx: seen.append(ctx.domain_ids) or result(users.REPORT, state="empty"))
    monkeypatch.setattr(routes, "get_report", lambda _: definition)
    handler = Handler(definition)
    routes.try_handle_get(handler, "/api/v2/reports/ad.users.v2/data", selected)
    assert handler.status == 200, handler.payload
    assert seen == [[22]]


def test_conflicting_aliases_are_rejected(monkeypatch, domain_rows):
    monkeypatch.setattr(routes, "get_report", lambda _: computer_report.REPORT)
    handler = Handler(computer_report.REPORT)
    routes.try_handle_get(handler, "/api/v2/reports/ad.computers.v6/data", {"domain_id": ["11"], "domain": ["22"]})
    assert handler.status == 400
    assert domain_rows == []


@pytest.fixture
def computer_store(monkeypatch):
    calls = []

    def query(sql, params=(), **_):
        calls.append((sql, params))
        assert "lower(report_domain.fqdn)=" not in sql
        assert "lower(domain.fqdn)=" not in sql
        ids = params[0]
        if "computers_v6_coverage" in sql:
            return [{"domain_id": key, "domain_name": DOMAINS[key], "run_status": "completed",
                     "section_status": "complete", "record_count": 1,
                     "observed_at_utc": NOW - timedelta(days=2 if key == 22 else 0)} for key in ids]
        if "computers_v6_accounts" in sql:
            return [{"entity_id": key, "domain_id": key, "domain_name": DOMAINS[key],
                     "display_name": "shared", "natural_key": "shared", "observed_at_utc": NOW,
                     "attributes": {"attributes": {"object_class": "computer", "enabled": True}}} for key in ids]
        if "computers_v6_snapshots" in sql:
            return []
        pytest.fail("unexpected reader")

    monkeypatch.setattr(computers, "query_rows_bounded", query)
    monkeypatch.setattr(computers, "_semantic_rows", lambda _: [])
    monkeypatch.setattr(computers, "_load_computers_v6_source_overlay", lambda _: {})
    return calls


@pytest.mark.parametrize("scope", [[11, 22], [22]])
def test_computers_scope_identity_freshness_counts_and_csv(computer_store, scope):
    payload = computers.get_computers_v6_report(domain_ids=scope, view="all")
    assert {item["domain_id"] for item in payload["items"]} == set(scope)
    assert payload["summary"]["total_computers"] == len(scope)
    assert payload["filtered_count"] == len(scope)
    assert {item["domain_id"] for item in payload["coverage"]["domains"]} == set(scope)
    assert payload["coverage"]["stale_domain_count"] == 1
    if len(scope) == 2:
        assert {item["display_name"] for item in payload["items"]} == {f"{name}\\shared" for name in DOMAINS.values()}
    text = computers.render_computers_v6_csv(payload).decode("utf-8-sig")
    assert len(text.splitlines()) == len(scope) + 1


def test_empty_computer_scope_never_reads(monkeypatch):
    monkeypatch.setattr(computers, "query_rows_bounded", lambda *a, **k: pytest.fail("empty scope read"))
    monkeypatch.setattr(computers, "connect", lambda: pytest.fail("empty scope connected"))
    payload = computers.get_computers_v6_report(domain_ids=[], view="all")
    assert payload["items"] == []
    assert payload["coverage"]["domains"] == []


@pytest.mark.parametrize("scope", [[11, 22], [22]])
def test_users_keep_same_login_in_each_domain_and_scope_csv(monkeypatch, scope):
    monkeypatch.setattr(platform_settings, "_stored_row", lambda _: None)

    def snapshots(domain_ids, **_):
        assert domain_ids == scope
        return {"current": {"metadata": {"collection_status": "complete", "observed_at": NOW.isoformat(),
                                          "coverage": {"state": "complete", "domains": [
                                              {"domain_id": key, "domain_name": DOMAINS[key],
                                               "observed_at_utc": (NOW - timedelta(days=key == 22)).isoformat()} for key in scope]}},
                            "users": [{"id": f"user:{key}", "entityId": key, "domainId": key,
                                       "domainName": DOMAINS[key], "objectGuid": str(key),
                                       "displayName": "shared", "samAccountName": "shared", "enabled": True,
                                       "memberships": {"direct": [], "effective": []}} for key in scope]}}

    monkeypatch.setattr(users, "_snapshots", snapshots)
    context = QueryContext(access={}, params={}, domain_ids=scope, tab="active")
    payload = users._query(context)
    assert {row["entity_id"] for row in payload["items"]} == set(scope)
    expected = {f"{DOMAINS[key]}\\shared" for key in scope} if len(scope) > 1 else {"shared"}
    assert {row["display_name"] for row in payload["items"]} == expected
    assert {row["sam"] for row in payload["items"]} == expected
    assert payload["filtered_count"] == len(scope)
    text, meta = users._export(context)
    assert meta["rows"] == len(scope)
    for name in expected:
        assert name in text
    assert {row["domain_id"] for row in payload["coverage"]["domains"]} == set(scope)


def test_computer_overlay_is_domain_local_even_for_same_guid(monkeypatch):
    from types import SimpleNamespace

    monkeypatch.setattr(computers, "query_rows_bounded", lambda *a, **k: [{"id": key, "fqdn": name} for key, name in DOMAINS.items()])
    monkeypatch.setattr(computers, "connect", lambda: SimpleNamespace(close=lambda: None))
    called = []

    def load(connection, *, domain_fqdn):
        called.append(domain_fqdn)
        return {"base_inventory_status": "observed", "collection_status": "complete",
                "snapshot": {"metadata": {"completed_at": domain_fqdn},
                             "objects": [{"objectGuid": "same-guid", "name": domain_fqdn}]}}

    monkeypatch.setattr(computers, "load_latest_computers_v6_source_snapshot", load)
    overlay = computers._load_computers_v6_source_overlay([11, 22])
    assert called == list(DOMAINS.values())
    for key, name in DOMAINS.items():
        item = {"domain_id": key, "object_guid": "same-guid", "evidence": {}, "activity": {}}
        computers._apply_computers_v6_source_overlay(item, overlay)
        assert item["display_name"] == name
        assert item["source_snapshot"]["completed_at_utc"] == name


def test_computer_comparison_never_pairs_snapshots_across_domains(monkeypatch):
    calls = []

    def query(sql, params, **_):
        assert "lower(domain.fqdn)=" not in sql
        assert params == ([11, 22],)
        calls.append(tuple(params[0]))
        # Interleave domains so globally taking the first two rows would pair
        # different domains. Preserve each domain's own newest/previous order.
        return [{"snapshot_id": key * 10 + index, "domain_id": key,
                 "payload_json": {"contract_id": computers.CONTRACT_ID, "state": "available", "items": []}}
                for index in (2, 1) for key in params[0]]

    monkeypatch.setattr(computers, "query_rows_bounded", query)
    payload = computers._load_snapshot_comparison([11, 22])
    assert calls == [(11, 22)]
    assert {domain["domain_id"] for domain in payload["domains"]} == {11, 22}
    for domain in payload["domains"]:
        key = domain["domain_id"]
        assert domain["current"]["snapshot_id"] == key * 10 + 2
        assert domain["previous"]["snapshot_id"] == key * 10 + 1
    assert payload["state"] == "available"


@pytest.mark.parametrize("selected,expected", [(None, "beta.example.test\\shared"), ("22", "shared")])
def test_all_mode_qualifies_even_one_accessible_domain(monkeypatch, domain_rows, computer_store, selected, expected):
    monkeypatch.setattr(routes, "get_report", lambda _: computer_report.REPORT)
    handler = Handler(computer_report.REPORT, ids=(22,))
    query = {"view": ["all"], **({"domain_id": [selected]} if selected else {})}
    routes.try_handle_get(handler, "/api/v2/reports/ad.computers.v6/data", query)
    assert handler.status == 200
    assert handler.payload["items"][0]["display_name"] == expected


def test_empty_users_scope_never_reads_projection_or_saved_snapshots(monkeypatch):
    monkeypatch.setattr(directory_projection, "query_rows_bounded", lambda *a, **k: pytest.fail("empty scope read"))
    projection = directory_projection.build_directory_projection(items=[], coverage={}, requested_domain_ids=[])
    assert projection["users"] == []
    assert projection["domain_ids"] == []


def test_user_projection_preserves_domain_identity_and_source_times():
    items = [{"entity_id": key, "domain_id": key, "display_name": "shared", "natural_key": "shared"} for key in DOMAINS]
    observed = {key: NOW - timedelta(days=key == 22) for key in DOMAINS}
    inputs = {"domains": {key: key for key in DOMAINS}, "aliases": {},
              "sections": {(key, "directory_accounts"): {"status": "observed", "observed_at": observed[key]} for key in DOMAINS},
              "versions": {key: {"directory_accounts": {"observed_at": observed[key], "attributes": {"sam_account_name": "shared"}}} for key in DOMAINS},
              "graph": {"groups": [], "references": {}, "user_edges": {}, "parent_edges": {}}}
    projection = directory_projection.build_directory_projection(
        items=items, coverage={}, requested_domain_ids=[11, 22], exact_inputs=inputs,
    )
    snapshot = users_v2_reporting.snapshot_from_directory_projection(
        projection, coverage={"domains": [{"domain_id": key, "domain_name": name} for key, name in DOMAINS.items()]},
        active={"state": "available"},
    )
    assert {user["domainId"] for user in snapshot["users"]} == {11, 22}
    assert {user["domainName"] for user in snapshot["users"]} == set(DOMAINS.values())
    assert len({user["sourceStates"]["directory"]["observed_at"] for user in snapshot["users"]}) == 2


def test_one_failed_overlay_does_not_erase_another_domain(monkeypatch):
    from types import SimpleNamespace

    rollbacks = []
    monkeypatch.setattr(computers, "query_rows_bounded", lambda *a, **k: [{"id": key, "fqdn": name} for key, name in DOMAINS.items()])
    monkeypatch.setattr(computers, "connect", lambda: SimpleNamespace(close=lambda: None, rollback=lambda: rollbacks.append(True)))

    def load(connection, *, domain_fqdn):
        if domain_fqdn == DOMAINS[22]:
            raise ValueError("invalid_snapshot")
        return {"base_inventory_status": "observed", "collection_status": "complete",
                "snapshot": {"metadata": {"completed_at": NOW.isoformat()}, "objects": []}}

    monkeypatch.setattr(computers, "load_latest_computers_v6_source_snapshot", load)
    overlay = computers._load_computers_v6_source_overlay([11, 22])
    assert overlay["by_domain"][11]["source_snapshot"]["state"] == "complete"
    assert overlay["by_domain"][22]["source_snapshot"]["state"] == "unavailable"
    assert overlay["source_snapshot"]["state"] == "partial"
    assert rollbacks == [True]


def test_stale_users_grant_cannot_disclose_foreign_saved_changes(monkeypatch, domain_rows):
    """Exercise domain resolver -> real snapshot reader -> definition -> API."""
    from copy import deepcopy
    import json

    from server.sli.plugins.ad.reports import users_reporting

    foreign = {
        "metadata": {"observed_at": "2026-10-20T12:00:00Z"}, "groups": [], "users": [
            {"id": "user:22001", "entityId": 22001, "domainId": 22,
             "displayName": "Foreign account", "samAccountName": "foreign-login"},
        ],
    }

    saved_reads = []

    def saved(sql, params, **kwargs):
        saved_reads.append((sql, params))
        assert "users_v2_saved_snapshots" in sql
        return [{"snapshot_id": 7, "captured_at_utc": "2026-10-20T12:00:00Z",
                 "payload_json": deepcopy(foreign)}]

    monkeypatch.setattr(routes, "get_report", lambda _: users.REPORT)
    monkeypatch.setattr(users, "_cache", {})
    monkeypatch.setattr(platform_settings, "_stored_row", lambda _: None)
    monkeypatch.setattr(users_v2_reporting, "query_rows_bounded", saved)
    monkeypatch.setattr(users_reporting, "query_rows_bounded", lambda *a, **k: pytest.fail("empty scope inventory read"))
    monkeypatch.setattr(directory_projection, "query_rows_bounded", lambda *a, **k: pytest.fail("empty scope projection read"))
    handler = Handler(users.REPORT, ids=(99,))  # Authorized but no longer registered.
    routes.try_handle_get(handler, "/api/v2/reports/ad.users.v2/data", {"tab": ["changes"]})

    assert handler.status == 200, handler.payload
    assert domain_rows == [[99]]
    assert handler.payload["domain_scope"]["domain_ids"] == []
    assert handler.payload["items"] == []
    assert handler.payload["collections"]["changes"] == []
    assert saved_reads == []
    serialized = json.dumps(handler.payload)
    for value in ("Foreign account", "foreign-login", "22001"):
        assert value not in serialized


def test_declaration_recommends_only_authorized_nonarchive_domain(monkeypatch, domain_rows):
    monkeypatch.setattr(routes, "get_report", lambda _: computer_report.REPORT)
    monkeypatch.setattr(routes, "report_plugin_state", lambda _: None)
    monkeypatch.setattr(platform_settings, "get_setting", lambda _: "beta.example.test")
    handler = Handler(computer_report.REPORT, ids=(11,))
    routes.try_handle_get(handler, "/api/v2/reports/ad.computers.v6", {})
    assert handler.status == 200
    assert handler.payload["default_domain_id"] == 11
    assert handler.payload["default_domain_state"] == "available"
