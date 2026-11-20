"""Access adapter checks with fake PostgreSQL cursors; no database is used."""

from contextlib import nullcontext
from dataclasses import replace
from types import SimpleNamespace

import pytest

from server.sli.plugins.workstations import reports, scope
from server.sli.reporting.v2.access import ReportAccess
from tests.unit.test_workstations_plugin import context


def access(*scopes, fields=reports.FIELDS, action="view"):
    return {"reports": [{"report_key": "workstations.logons", "allowed": True, "allowed_actions": ["view"],
                         "grants": [{"scope": item, "field_categories": list(fields), "allowed_actions": [action]}
                                    for item in scopes]}]}


def adapter_query(monkeypatch, issued, rows):
    calls = []
    cursor = SimpleNamespace(execute=lambda sql, params=(): calls.append((" ".join(sql.split()), params)),
                             fetchall=lambda: [{"agent_key": row} for row in rows])
    monkeypatch.setattr(scope, "connect", lambda: nullcontext(SimpleNamespace(cursor=lambda: nullcontext(cursor))))
    adapter = scope.WorkstationScopeAdapter()
    keys = adapter.agent_keys(issued, "workstations.logons", "view", reports.FIELDS)
    return adapter, keys, calls


@pytest.mark.parametrize("full_scope", [{"kind": "all"}, {"mode": "all", "clauses": []}])
def test_full_grant_includes_registered_pilot_without_directory_identity(monkeypatch, full_scope):
    adapter, keys, calls = adapter_query(monkeypatch, access(full_scope), ["fixture-pilot"])
    sql, params = calls[-1]
    assert keys == ("fixture-pilot",) and not adapter.limitations
    assert "from sli_agents a" in sql and "m->>'module_id'='sli.workstations'" in sql
    assert "core_entity" not in sql
    assert params == (reports.MAX_STATIONS + 1,)


@pytest.mark.parametrize("issued,predicate,values", [
    ({"kind": "domain", "ids": [11]}, "r.collection_scope_id = ANY(%s)", [["ad-domain:11"]]),
    ({"kind": "agent", "ids": ["fixture-pilot"]}, "r.agent_key = ANY(%s)", [["fixture-pilot"]]),
    ({"kind": "ou", "domain_id": 11, "values": ["fixture-ou"]},
     "r.collection_scope_id = %s AND r.ou_path = ANY(%s)", ["ad-domain:11", ["fixture-ou"]]),
    ({"mode": "restricted", "clauses": [{"plugin_ids": ["sli.workstations"], "source_instance_ids": ["fixture-host"]}]},
     "r.plugin_id = ANY(%s) AND r.source_instance_id = ANY(%s)", [["sli.workstations"], ["fixture-host"]]),
    ({"mode": "restricted", "clauses": [{"entity_ids": [29]}]}, "r.entity_id = ANY(%s)", [[29]]),
    ({"mode": "restricted", "clauses": [{"source_instance_ids": ["fixture-host"], "collection_scope_ids": ["ad-domain:11"]}]},
     "r.source_instance_id = ANY(%s) AND r.collection_scope_id = ANY(%s)", [["fixture-host"], ["ad-domain:11"]]),
])
def test_scoped_queries_bind_all_dimensions_before_bounded_key_selection(monkeypatch, issued, predicate, values):
    adapter, keys, calls = adapter_query(monkeypatch, access(issued), ["fixture-pilot"])
    sql, params = calls[-1]
    assert keys == ("fixture-pilot",) and not adapter.limitations
    assert predicate in sql and params == (*values, reports.MAX_STATIONS + 1)
    assert "select distinct r.agent_key from resources r where" in sql
    assert "r.natural_key=a.identity_key" in sql and "r.source_instance_id=a.source_instance_id" in sql
    assert "having count(distinct target_entity_id)=1" in sql
    assert "t.value='ad_computer'" in sql
    assert "v.source_section='directory_accounts' and v.valid_to_utc is null" in sql
    assert "v.attributes_json->'attributes'->>'organizational_unit'" in sql


@pytest.mark.parametrize("issued", [
    {"kind": "unknown"}, {"kind": "all", "ids": [11]},
    {}, None, [["kind", "all"]], {"mode": "none", "clauses": []},
    {"mode": "restricted", "clauses": [{}]},
    {"kind": "ou", "values": ["fixture-ou"]}, {"kind": "agent", "ids": []},
])
def test_unknown_or_invalid_grant_never_reads_registered_agents(monkeypatch, issued):
    monkeypatch.setattr(scope, "connect", lambda: pytest.fail("unresolved grant must not query agents"))
    adapter = scope.WorkstationScopeAdapter()
    assert adapter.agent_keys(access(issued), "workstations.logons", "view", reports.FIELDS) == ()
    assert adapter.limitations[0]["code"] == "workstation_scope_unresolved"


def test_unresolved_grant_cannot_widen_valid_scoped_grant(monkeypatch):
    adapter, keys, calls = adapter_query(monkeypatch, access({"kind": "unknown"}, {"kind": "domain", "ids": [11]}), ["fixture-pilot"])
    assert keys == ("fixture-pilot",) and adapter.limitations
    assert calls[-1][1] == (["ad-domain:11"], reports.MAX_STATIONS + 1)


def test_station_bound_rejects_adapter_overflow_without_reading_observations(monkeypatch):
    adapter, keys, calls = adapter_query(monkeypatch, access({"kind": "all"}),
                                       [f"fixture-{index}" for index in range(reports.MAX_STATIONS + 1)])
    assert len(keys) == reports.MAX_STATIONS + 1 and calls[-1][1][-1] == len(keys)
    monkeypatch.setattr(reports, "connect", lambda: pytest.fail("overflow queried observations"))
    ctx = replace(context("logons"), runtime={"workstation_scope_adapter": adapter})
    with pytest.raises(ValueError, match="scope_invalid"):
        reports.make_report("logons").query(ctx)


def test_scope_database_failure_returns_safe_source_error(monkeypatch):
    from psycopg.errors import InsufficientPrivilege

    def unavailable(*args):
        raise InsufficientPrivilege("fixture failure")

    ctx = replace(context("logons"), runtime={"workstation_scope_adapter": SimpleNamespace(agent_keys=unavailable)})
    monkeypatch.setattr(reports, "connect", lambda: pytest.fail("unavailable scope queried observations"))
    outcome = reports.make_report("logons").query(ctx)
    assert outcome["state"] == "error" and outcome["items"] == []
    assert outcome["coverage"]["reason"] == outcome["state_details"]["reason"] == "source_access_denied"
    assert outcome["limitations"] == [{
        "code": "source_access_denied", "text": reports.message("reports.workstations.source_access_denied")["text"],
    }]
    assert "fixture failure" not in str(outcome)


def test_partial_category_or_wrong_action_grants_cannot_confer_full_scope(monkeypatch):
    issued = access({"kind": "domain", "ids": [11]})
    issued["reports"][0]["grants"] += access({"kind": "all"}, fields={"technical"})["reports"][0]["grants"]
    issued["reports"][0]["grants"] += access({"kind": "all"}, action="export")["reports"][0]["grants"]
    _, keys, calls = adapter_query(monkeypatch, issued, ["fixture-pilot"])
    assert keys == ("fixture-pilot",)
    assert calls[-1][1] == (["ad-domain:11"], reports.MAX_STATIONS + 1)


def test_no_eligible_atomic_grant_denies_before_database(monkeypatch):
    monkeypatch.setattr(scope, "connect", lambda: pytest.fail("denied grant queried agents"))
    with pytest.raises(PermissionError, match="field_categories_not_allowed"):
        scope.WorkstationScopeAdapter().agent_keys(access({"kind": "all"}, fields={"technical"}),
                                                   "workstations.logons", "view", reports.FIELDS)


def test_delegated_generic_scope_opt_in_does_not_relax_other_readers():
    issued = access({"mode": "restricted", "clauses": [{"source_instance_ids": ["fixture-host"]}]})
    definition = reports.make_report("logons")
    ReportAccess(definition, issued)
    with pytest.raises(PermissionError, match="scope_not_executable"):
        ReportAccess(replace(definition, access=replace(definition.access, accepts_generic_scope=False)), issued)


def test_empty_scope_has_limitation_and_selected_foreign_agent_is_denied(monkeypatch):
    monkeypatch.setattr(reports, "connect", lambda: pytest.fail("empty scope queried observations"))
    ctx = context("logons", keys=())
    payload = reports.make_report("logons").query(ctx)
    assert payload["state"] == "partial" and payload["items"] == []
    assert payload["limitations"][0]["code"] == "workstation_scope_empty"
    with pytest.raises(PermissionError, match="scope_denied"):
        reports.make_report("logons").query(replace(ctx, params={**ctx.params, "agent_key": "fixture-other"}))


@pytest.mark.parametrize("keys", [("",), (" fixture-agent",), ("fixture-agent", "fixture-agent"), ("x" * 257,), (None,)])
def test_invalid_adapter_keys_never_query_observations(monkeypatch, keys):
    monkeypatch.setattr(reports, "connect", lambda: pytest.fail("invalid keys queried observations"))
    with pytest.raises(ValueError, match="scope_invalid"):
        reports.make_report("logons").query(context("logons", keys=keys))
