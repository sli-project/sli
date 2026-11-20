"""Read boundary, capability denies, cursors and honest unavailable states."""
import json
from contextlib import contextmanager
from dataclasses import replace

import pytest
from psycopg import errors

from server.sli.access.scope import AccessScope, ScopeClause
from server.sli.plugins.file_audit import reports
from server.sli.reporting.v2.access import ReportAccess
from server.sli.reporting.v2.definition import QueryContext, parse_params

AGENT = "00000000-0000-4000-8000-000000000001"
ROOT = {"agent_id": AGENT, "source_instance_id": "synthetic-source", "collection_scope_id": "scope:one",
        "source_name": "Synthetic server", "share_name": "Synthetic share", "path": "C:\\Synthetic", "important": True}
SCOPE = AccessScope("restricted", (ScopeClause(plugin_ids=("sli.file-audit",), device_ids=(AGENT,),
    source_instance_ids=(ROOT["source_instance_id"],), collection_scope_ids=(ROOT["collection_scope_id"],)),))


def context(tab="actions", action="view", **kwargs):
    access = {"capabilities": ["file-audit.view", "file-audit.export"], "reports": [{
        "report_key": f"file-audit.{tab}", "allowed": True, "allowed_actions": ["view", "export"],
        "grants": [{"allowed_actions": ["view", "export"], "field_categories": sorted(reports.FIELDS), "scope": SCOPE.to_dict()}],
    }]}
    return QueryContext(access=access, action=action, scope=SCOPE, params={"period": {
        "from_utc": "2026-10-09T12:00:00Z", "to_utc": "2026-10-10T12:00:00Z"}}, **kwargs)


class Cursor:
    def __init__(self, roots=None, data=None):
        self.roots = roots if roots is not None else [ROOT]
        self.data = data or {"items": [{"id": "synthetic", **ROOT, "path": "=Synthetic"}],
            "filtered_count": 1, "has_more": False, "after": None}
        self.calls = []

    def execute(self, sql, args=None):
        self.calls.append((sql, args))

    def fetchone(self):
        if "read_file_ransom_details" in self.calls[-1][0]:
            return {"decisions": getattr(self, "decisions", {})}
        if "report_roots" in self.calls[-1][0]:
            return {"roots": self.roots}
        return {"data": {**self.data, **({} if getattr(self, "old_function", False) else {"service_filter_version": 1})}}


def install(monkeypatch, cur):
    @contextmanager
    def connect():
        class Connection:
            @contextmanager
            def cursor(self):
                yield cur
        yield Connection()
    monkeypatch.setattr(reports, "connect", connect)


def test_scope_and_capability_are_applied_before_counts_options_and_rows(monkeypatch):
    forbidden = {**ROOT, "collection_scope_id": "scope:two", "share_name": "Must stay hidden"}
    cur = Cursor(roots=[ROOT, forbidden])
    install(monkeypatch, cur)
    data = reports.query("actions", context())
    assert data["state"] == "partial" and data["filtered_count"] == 1
    assert data["filter_options"]["share"] == reports.share_options([ROOT])
    args = cur.calls[-1][1]
    assert json.loads(args[0]) == [ROOT]
    assert "repeatable read, read only" in cur.calls[0][0]

    denied = context()
    denied.access["capability_policies"] = [{"capability_key": "file-audit.view", "effect": "deny", "valid": True, "scope": SCOPE.to_dict()}]
    cur.calls.clear()
    data = reports.query("actions", denied)
    assert data["state"] == "not_collected" and data["filtered_count"] is None
    assert data["filter_options"]["share"] == []
    assert not any("report_rows" in sql for sql, _ in cur.calls)


def test_ransom_details_are_read_only_for_the_authorized_page_and_keep_file_evidence(monkeypatch):
    forbidden = {**ROOT, "collection_scope_id": "scope:other"}
    witness = {"path": "C:\\synthetic\\file.txt", "operation": "write"}
    cur = Cursor(roots=[ROOT, forbidden], data={"items": [{"id": "synthetic", **ROOT,
        "rule_code": "file-audit.mass-write", "details": {"distinct_files": 110, "window_seconds": 300},
        "evidence": [witness]}], "filtered_count": 1, "has_more": False, "after": None})
    cur.decisions = {"synthetic": {"state": "excluded", "exclusion": {"reason": "Synthetic backup"}}}
    install(monkeypatch, cur)
    ctx = context("mass-operations")
    ctx.access["reports"].append({"report_key": "security.queue", "allowed": True, "allowed_actions": ["view"], "grants": [
        {"allowed_actions": ["view"], "field_categories": ["security"], "scope": SCOPE.to_dict()}]})
    data = reports.query("mass-operations", ctx)
    assert data["items"][0]["ransom"] == cur.decisions["synthetic"]
    assert data["items"][0]["evidence"] == [witness]
    assert json.loads(cur.calls[-1][1][0]) == [ROOT]
    assert json.loads(cur.calls[-1][1][1]) == ["synthetic"]
    cur.data["items"][0]["rule_code"] = "file-audit.mass-read"
    assert reports.query("mass-operations", ctx)["items"][0]["ransom"] == {"state": "not_applicable"}
    cur.data["items"][0]["rule_code"] = "file-audit.mass-delete"
    cur.decisions = {}
    assert reports.query("mass-operations", ctx)["items"][0]["ransom"] == {"state": "not_evaluated"}


@pytest.mark.parametrize("grant", [None, {"mode": "all", "field_categories": []},
    {"mode": "restricted", "clauses": [{"collection_scope_ids": ["scope:other"]}]}])
def test_ransom_metadata_requires_queue_security_permission_in_the_same_scope(monkeypatch, grant):
    cur = Cursor(data={"items": [{"id": "synthetic", **ROOT, "rule_code": "file-audit.mass-write",
        "details": {"distinct_files": 110, "window_seconds": 300}, "evidence": [{"path": "C:\\synthetic"}]}],
        "filtered_count": 1, "has_more": False, "after": None})
    cur.decisions = {"synthetic": {"state": "excluded", "exclusion": {"reason": "Must stay hidden"}}}
    install(monkeypatch, cur)
    ctx = context("mass-operations")
    if grant is not None:
        ctx.access["reports"].append({"report_key": "security.queue", "allowed": True, "allowed_actions": ["view"], "grants": [
            {"allowed_actions": ["view"], "field_categories": grant.get("field_categories", ["security"]),
             "scope": {key: value for key, value in grant.items() if key != "field_categories"}}]})
    data = reports.query("mass-operations", ctx)
    assert data["items"][0]["ransom"] == {"state": "denied"}
    assert data["items"][0]["evidence"] == [{"path": "C:\\synthetic"}]
    assert "Must stay hidden" not in json.dumps(data)
    assert not any("read_file_ransom_details" in sql for sql, _ in cur.calls)


def test_selected_share_cannot_widen_scope_and_cursor_is_validated(monkeypatch):
    cur = Cursor()
    install(monkeypatch, cur)
    selected = replace(context(), params={**context().params, "share": [reports.share_key({**ROOT, "source_instance_id": "other"})]})
    assert reports.query("actions", selected)["items"] == []
    assert not any("report_rows" in sql for sql, _ in cur.calls)
    for value in ("not-json", "{}", '{"at":"not-time","id":"one"}'):
        with pytest.raises(ValueError, match="report_cursor_invalid"):
            reports.query("actions", replace(context(), cursor=value))


def test_unreadable_source_has_no_zero_total(monkeypatch):
    def unavailable():
        raise errors.UndefinedFunction()
    monkeypatch.setattr(reports, "connect", unavailable)
    data = reports.query("overview", context("overview"))
    assert data["state"] == "error" and data["filtered_count"] is None and not data["items"]


def test_old_report_function_is_unavailable_not_a_false_empty_page(monkeypatch):
    cur = Cursor()
    cur.old_function = True
    install(monkeypatch, cur)
    data = reports.query("actions", context())
    assert data["state"] == "error" and data["filtered_count"] is None and not data["items"]


def test_timeout_is_distinct_from_unreadable_and_does_not_become_an_empty_result(monkeypatch):
    def unavailable():
        raise errors.QueryCanceled("synthetic-private-diagnostic")
    monkeypatch.setattr(reports, "connect", unavailable)
    data = reports.query("actions", context())
    assert data["state"] == "error" and data["filtered_count"] is None
    assert data["coverage"]["reason"] == "source_timeout" and not data["items"]
    assert data["limitations"][0]["code"] == "source_timeout"
    assert "synthetic-private" not in json.dumps(data)


def test_rename_filter_and_delivery_columns_are_declared():
    for definition in reports.REPORTS:
        assert parse_params(definition, {"operation": ["rename"]})[0]["operation"] == "rename"
    audit = reports.REPORTS[reports.REPORT_KEYS.index("audit-state")]
    keys = {column.key for column in audit.columns}
    assert {"delivery_received_at", "delivery_imported_at", "delivery_record_id"} <= keys


@pytest.mark.parametrize("delivery,expected", [({}, "unknown"),
    ({"delivery_received_at": None, "delivery_imported_at": None}, "not_received"),
    ({"delivery_received_at": "2026-01-01T00:00:00Z", "delivery_imported_at": None}, "pending_import"),
    ({"delivery_received_at": "2026-01-01T00:00:00Z", "delivery_imported_at": "2026-01-01T00:00:10Z"}, "imported"),
])
def test_delivery_status_keeps_received_and_imported_separate(monkeypatch, delivery, expected):
    cur = Cursor(data={"items": [{"id": "synthetic", **ROOT, **delivery}],
                       "filtered_count": 1, "has_more": False, "after": None})
    install(monkeypatch, cur)
    data = reports.query("audit-state", context("audit-state"))
    assert data["items"][0]["delivery_state"] == expected
    assert data["state"] == "partial"


@pytest.mark.parametrize("kind", ["server", "workstation"])
def test_source_filter_applies_before_rows_counts_options_and_export(monkeypatch, kind):
    station = {**ROOT, "source_kind": "workstation", "collection_scope_id": "scope:station", "share_name": ""}
    ctx = context()
    # Admit both synthetic roots, then narrow by source independently of grants.
    ctx = replace(ctx, scope=AccessScope("all"), params={**ctx.params, "source_kind": kind})
    ctx.access["reports"][0]["grants"][0]["scope"] = AccessScope("all").to_dict()
    cur = Cursor(roots=[ROOT, station])
    install(monkeypatch, cur)
    data = reports.query("actions", ctx)
    selected = [station] if kind == "workstation" else [ROOT]
    assert json.loads(cur.calls[-1][1][0]) == selected
    assert data["filter_options"]["share"] == reports.share_options(selected)
    reports.export("actions", replace(ctx, action="export"))
    assert json.loads(cur.calls[-1][1][0]) == selected


@pytest.mark.parametrize("show", ["false", "true"])
def test_service_filter_reaches_each_page_and_export(monkeypatch, show):
    cur = Cursor()
    install(monkeypatch, cur)
    ctx = replace(context(), params={**context().params, "show_service": show})
    reports.query("actions", ctx)
    assert json.loads(cur.calls[-1][1][8]) == {"show_service": show == "true"}
    cursor = json.dumps({"at": "2026-10-10T09:00:00+00:00", "id": "synthetic"})
    reports.query("actions", replace(ctx, cursor=cursor))
    assert json.loads(cur.calls[-1][1][8]) == {"at": "2026-10-10T09:00:00+00:00", "id": "synthetic", "show_service": show == "true"}
    reports.export("actions", replace(ctx, action="export"))
    assert json.loads(cur.calls[-1][1][8]) == {"show_service": show == "true"}


def test_service_filter_defaults_to_hidden_and_rejects_unknown_values():
    for definition in reports.REPORTS:
        assert parse_params(definition, {})[0]["show_service"] == "false"
        with pytest.raises(ValueError, match="report_parameter_invalid:show_service"):
            parse_params(definition, {"show_service": ["unknown"]})


@pytest.mark.parametrize("show", ["false", "true"])
def test_service_filter_is_retained_across_csv_pages(monkeypatch, show):
    class Pages(Cursor):
        def fetchone(self):
            if "report_roots" in self.calls[-1][0]:
                return {"roots": self.roots}
            options = json.loads(self.calls[-1][1][8])
            second = "at" in options
            return {"data": {"service_filter_version": 1, "items": [{"id": "second" if second else "first",
                **ROOT, "path": "second-file" if second else "first-file"}], "filtered_count": 2,
                "has_more": not second, "after": None if second else {"at": "2026-10-10T09:00:00+00:00", "id": "first"}}}

    cur = Pages()
    install(monkeypatch, cur)
    ctx = replace(context(), params={**context().params, "show_service": show}, action="export")
    body, meta = reports.export("actions", ctx)
    assert "first-file" in body and "second-file" in body
    assert meta == {"rows": 2, "truncated": False}
    calls = [json.loads(args[8]) for sql, args in cur.calls if "report_rows" in sql]
    assert [call["show_service"] for call in calls] == [show == "true", show == "true"]
    assert calls[1]["id"] == "first"


def test_unknown_source_kind_is_rejected_by_every_report_contract():
    for definition in reports.REPORTS:
        with pytest.raises(ValueError, match="report_parameter_invalid:source_kind"):
            parse_params(definition, {"source_kind": ["unknown"]})


def test_export_requires_its_own_capability_and_protects_native_values(monkeypatch):
    cur = Cursor()
    install(monkeypatch, cur)
    ctx = context(action="export")
    body, meta = reports.export("actions", ctx)
    assert "'=Synthetic" in body and meta == {"rows": 1, "truncated": False}
    ctx.access["capabilities"] = ["file-audit.view"]
    with pytest.raises(PermissionError, match="report_access_denied"):
        reports.export("actions", ctx)


def test_eight_definitions_parse_shared_filters_and_require_atomic_categories():
    for definition in reports.REPORTS:
        params, paging = parse_params(definition, {"path": ["C:\\Synthetic"], "include_nested": ["false"],
            "employee": ["S-1-1-0"], "share": [reports.share_key(ROOT)], "operation": ["delete"]})
        assert params["include_nested"] == "false" and params["share"] == [reports.share_key(ROOT)]
        assert paging["limit"] == 50
        long_path = "C:\\" + "folder\\" * 50
        assert parse_params(definition, {"path": [long_path]})[0]["path"] == long_path
        with pytest.raises(ValueError, match="report_parameter_invalid:path"):
            parse_params(definition, {"path": ["x" * 4097]})
        ctx = context(definition.key.removeprefix("file-audit."))
        assert ReportAccess(definition, ctx.access).scope.allows(plugin_id="sli.file-audit", device_id=AGENT,
            source_instance_id=ROOT["source_instance_id"], collection_scope_id=ROOT["collection_scope_id"])
        ctx.access["reports"][0]["grants"][0]["field_categories"].remove("privilege")
        with pytest.raises(PermissionError, match="report_field_categories_not_allowed"):
            ReportAccess(definition, ctx.access)


def test_api_definitions_data_and_cursor_binding_recheck_the_report_grant(monkeypatch):
    from server.api.routes import reports_v2
    from tests.reporting.test_reporting_v2 import FakeHandler

    cur = Cursor(data={"items": [{"id": "synthetic", **ROOT}], "filtered_count": 2,
        "has_more": True, "after": {"at": "2026-10-10T09:00:00+00:00", "id": "synthetic"}})
    install(monkeypatch, cur)
    monkeypatch.setattr(reports_v2, "report_plugin_state", lambda _key: None)
    monkeypatch.setattr(reports_v2, "annotate_plugin_report", lambda *_args: None)
    monkeypatch.setattr(reports_v2, "validate_storage_route_authorization", lambda _value: None)
    for tab in reports.REPORT_KEYS:
        cur.data["items"][0].update(rule_code="file-audit.mass-read", details={
            "distinct_files": 1, "window_seconds": 60, "operation": "read"})
        handler = FakeHandler(context(tab).access)
        path = f"/api/v2/reports/file-audit.{tab}"
        assert reports_v2.try_handle_get(handler, path, {})
        assert handler.sent[-1][1] == 200
        params = {"period": ["custom"], "from": ["2026-10-09T12:00:00Z"], "to": ["2026-10-10T12:00:00Z"]}
        assert reports_v2.try_handle_get(handler, path + "/data", params)
        data, status = handler.sent[-1]
        assert status == 200 and data["items"] and data["next_cursor"], data
        cursor = data["next_cursor"]
        assert reports_v2.try_handle_get(handler, path + "/data", {**params, "cursor": [cursor]})
        assert handler.sent[-1][1] == 200
        assert reports_v2.try_handle_get(handler, path + "/data", {**params, "employee": ["other"], "cursor": [cursor]})
        assert handler.sent[-1][1] == 400
        handler.access["reports"][0]["allowed"] = False
        assert reports_v2.try_handle_get(handler, path + "/data", params)
        assert handler.sent[-1][1] == 403
