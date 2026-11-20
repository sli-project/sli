"""WR03 authorization contracts with synthetic grants and fake cursors only."""

from copy import deepcopy
from types import SimpleNamespace
from contextlib import nullcontext
from http import HTTPStatus

import pytest

from server.api import http_server
from server.api.routes import agents
from server.sli.agents.ca import AgentError
from server.sli.plugins.workstations import access as ws, agent_read
from server.sli.plugins.workstations.reports import FIELDS, REPORTS
from tests.unit.test_agent_api import Handler

AGENT = "00000000-0000-4000-8000-000000000001"
OTHER = "00000000-0000-4000-8000-000000000002"


def grant(scope, *, fields=FIELDS, actions=("view",)):
    return {"scope": scope, "field_categories": sorted(fields), "allowed_actions": list(actions)}


def issued(*grants, key="workstations.logons", caps=(), policies=()):
    return {"capabilities": list(caps), "capability_policies": list(policies), "reports": [
        {"report_key": key, "allowed": True, "allowed_actions": ["view"], "grants": list(grants)},
    ]}


def policy(action, scope, *, effect="allow", valid=True):
    return {"capability_key": ws.CAPABILITIES[action], "effect": effect, "valid": valid, "scope": scope}


@pytest.mark.parametrize("family", REPORTS)
def test_each_legacy_grant_is_read_only_and_keeps_its_family(family):
    snapshot = issued(grant({"kind": "domain", "ids": [11]}), key=REPORTS[family][0])
    sql, params = ws.station_predicate(snapshot, family=family)
    assert "r.collection_scope_id = ANY(%s)" in sql
    assert params == [["ad-domain:11"]]
    mutation, _ = ws.station_predicate(snapshot, family=family, action="review")
    assert mutation.endswith("AND (FALSE AND NOT FALSE))")
    other_family = next(item for item in REPORTS if item != family)
    with pytest.raises(PermissionError, match="workstation_access_denied"):
        ws.station_predicate(snapshot, family=other_family)


def test_missing_fields_cannot_be_combined_with_another_grant_or_report():
    snapshot = issued(grant({"kind": "all"}, fields={"identity_basic", "technical"}),
                      grant({"kind": "all"}, fields={"security", "privilege"}))
    with pytest.raises(PermissionError):
        ws.station_predicate(snapshot)
    snapshot["reports"].append(issued(grant({"kind": "all"}, fields={"security", "privilege"}),
                                      key="workstations.protection")["reports"][0])
    with pytest.raises(PermissionError):
        ws.station_predicate(snapshot)


def test_partial_and_wrong_action_grants_never_expand_scoped_rows():
    snapshot = issued(grant({"kind": "domain", "ids": [11]}),
                      grant({"kind": "all"}, fields={"technical"}),
                      grant({"kind": "all"}, actions=("export",)), grant({"kind": "unknown"}))
    sql, params = ws.station_predicate(snapshot)
    assert params == [["ad-domain:11"]]
    assert "and (TRUE)" not in sql


def test_new_workspace_requires_explicit_read_capability_and_atomic_report_grant():
    snapshot = issued(grant({"kind": "all"}), key=ws.REPORT_KEY)
    sql, _ = ws.station_predicate(snapshot)
    assert "AND (FALSE AND NOT FALSE)" in sql
    snapshot["capabilities"] = [ws.CAPABILITIES["read"]]
    sql, _ = ws.station_predicate(snapshot)
    assert "AND (TRUE AND NOT FALSE)" in sql
    snapshot["reports"] = []
    with pytest.raises(PermissionError):
        ws.station_predicate(snapshot)


def test_scoped_read_allow_and_deny_are_independent_of_grant_resource_rows():
    snapshot = issued(grant({"kind": "all"}), key=ws.REPORT_KEY, policies=[
        policy("read", {"kind": "domain", "ids": [11]}),
        policy("read", {"kind": "domain", "ids": [22]}, effect="deny"),
    ])
    sql, params = ws.station_predicate(snapshot)
    assert params == [["ad-domain:22"], ["ad-domain:11"], ["ad-domain:22"]]
    assert "AND NOT (exists(select 1 from resources r where r.agent_key=a.agent_key" in sql
    # All resource alternatives are checked by an independent NOT EXISTS;
    # the agent-only row cannot bypass a denied directory-domain resource.
    assert "r.collection_scope_id = ANY(%s)" in sql


@pytest.mark.parametrize("raw,valid", [(None, False), ({"kind": "all", "extra": True}, True), ({}, True)])
def test_invalid_read_deny_cannot_be_bypassed_by_legacy_view(raw, valid):
    snapshot = issued(grant({"kind": "all"}), policies=[policy("read", raw, effect="deny", valid=valid)])
    sql, params = ws.station_predicate(snapshot)
    assert "AND FALSE" in sql and params == []


@pytest.mark.parametrize("action", ["review", "exception.station", "decision.manage"])
def test_concrete_decision_requires_every_selected_station_in_read_and_action_scope(action):
    snapshot = issued(grant({"kind": "agent", "ids": [AGENT]}),
                      policies=[policy(action, {"kind": "domain", "ids": [11]})])
    calls = []
    cur = SimpleNamespace(execute=lambda sql, params=(): calls.append((sql, params)),
                          fetchall=lambda: [{"agent_key": AGENT}])
    ws.require_stations(cur, snapshot, [AGENT], family="logons", action=action)
    assert calls[-1][1] == ([AGENT], ["ad-domain:11"], [AGENT])
    assert "having count(distinct target_entity_id)=1" in calls[-1][0]
    with pytest.raises(PermissionError, match="workstation_access_denied"):
        ws.require_stations(cur, snapshot, [AGENT, OTHER], family="logons", action=action)


@pytest.mark.parametrize("action", ["exception.account", "exception.ou", "decision.manage"])
def test_dynamic_decision_scope_cannot_expand_view_authority(action):
    target = {"kind": "ou", "domain_id": 11, "values": ["fixture-ou"]}
    snapshot = issued(grant({"kind": "domain", "ids": [11]}), caps=[ws.CAPABILITIES[action]])
    ws.require_decision_scope(snapshot, target, family="logons", action=action)
    for foreign in ({**target, "domain_id": 22}, {"kind": "all"}):
        with pytest.raises(PermissionError):
            ws.require_decision_scope(snapshot, foreign, family="logons", action=action)
    # Having authority over today's one agent cannot authorize future OU members.
    snapshot["reports"][0]["grants"] = [grant({"kind": "agent", "ids": [AGENT]})]
    with pytest.raises(PermissionError):
        ws.require_decision_scope(snapshot, target, family="logons", action=action)


def test_dynamic_scope_rechecks_action_rights_and_denies_without_returning_counts():
    target = {"kind": "ou", "domain_id": 11, "values": ["fixture-ou"]}
    snapshot = issued(grant({"kind": "domain", "ids": [11]}), policies=[
        policy("exception.ou", {"kind": "domain", "ids": [11]}),
    ])
    ws.require_decision_scope(snapshot, target, family="logons", action="exception.ou")
    for revoked in ([], [policy("exception.ou", {"kind": "domain", "ids": [11]}, effect="deny")],
                    [policy("read", {"kind": "domain", "ids": [11]}, effect="deny")]):
        changed = deepcopy(snapshot)
        changed["capability_policies"] = revoked
        with pytest.raises(PermissionError, match="^workstation_access_denied$"):
            ws.require_decision_scope(changed, target, family="logons", action="exception.ou")


def test_foreign_domain_deny_does_not_remove_authority_in_the_permitted_domain():
    target = {"kind": "ou", "domain_id": 11, "values": ["fixture-ou"]}
    snapshot = issued(grant({"kind": "domain", "ids": [11]}), policies=[
        policy("exception.ou", {"kind": "domain", "ids": [11]}),
        policy("exception.ou", {"kind": "domain", "ids": [22]}, effect="deny"),
        policy("read", {"kind": "domain", "ids": [22]}, effect="deny"),
    ])
    ws.require_decision_scope(snapshot, target, family="logons", action="exception.ou")
    with pytest.raises(PermissionError):
        ws.require_decision_scope(snapshot, {**target, "domain_id": 22}, family="logons", action="exception.ou")


def row(agent_key=AGENT):
    return {"agent_key": agent_key, "status": "active", "last_seen": None,
            "policy_revision": 2, "applied_policy_revision": 1,
            "certificates": ["fixture-secret"], "rights_probe": {"fixture": "private"},
            "collection_policy": {"fixture": "private"}, "policy_audit": ["private"]}


@pytest.mark.parametrize("domain,key", [(11, AGENT), (22, OTHER)])
def test_two_users_read_only_their_agent_rows_and_no_global_counts(domain, key):
    snapshot = issued(grant({"kind": "domain", "ids": [domain]}))
    calls = []

    def execute(sql, params=()):
        calls.append((sql, params))
        if "from registered a join sli_agents" in sql:
            assert params == ([f"ad-domain:{domain}"], agent_read.PAGE_SIZE + 1)
            assert sql.index("r.collection_scope_id = ANY(%s)") < sql.index("order by a.agent_key limit")
            assert "count(" not in sql.split(" select a.agent_key,s.status", 1)[1]

    cur = SimpleNamespace(execute=execute, fetchall=lambda: [row(key)])
    result = agent_read.read_agents(cur, snapshot, {})
    assert result == {"items": [{field: row(key)[field] for field in agent_read.FIELDS}],
                      "has_more": False, "next_cursor": None}
    assert "certificates" not in calls[-1][0] and "policy_audit" not in calls[-1][0]


@pytest.mark.parametrize("selected", [AGENT, OTHER])
def test_absent_and_foreign_agent_return_same_denial(selected):
    cur = SimpleNamespace(execute=lambda *args: None, fetchall=lambda: [])
    with pytest.raises(PermissionError, match="^workstation_access_denied$"):
        agent_read.read_agents(cur, issued(grant({"kind": "domain", "ids": [11]})), {"agent_key": [selected]})


def test_page_boundary_100_101_and_cursor_remain_scoped():
    rows = [row(f"00000000-0000-4000-8000-{index:012d}") for index in range(1, 102)]
    calls = []
    cur = SimpleNamespace(execute=lambda sql, params=(): calls.append((sql, params)), fetchall=lambda: rows)
    snapshot = issued(grant({"kind": "domain", "ids": [11]}))
    result = agent_read.read_agents(cur, snapshot, {})
    assert len(result["items"]) == 100 and result["has_more"]
    assert result["next_cursor"] == rows[99]["agent_key"]
    assert calls[-1][1][-1] == 101
    rows[:] = rows[100:]
    result = agent_read.read_agents(cur, snapshot, {"cursor": [result["next_cursor"]]})
    assert [item["agent_key"] for item in result["items"]] == [rows[0]["agent_key"]]
    assert not result["has_more"] and result["next_cursor"] is None
    assert calls[-1][1] == (["ad-domain:11"], "00000000-0000-4000-8000-000000000100", 101)


@pytest.mark.parametrize("query", [{"domain": ["22"]}, {"agent_key": []}, {"cursor": [AGENT, OTHER]}, {"cursor": "invalid"}])
def test_unknown_or_malformed_parameters_never_query(query):
    cur = SimpleNamespace(execute=lambda *args: pytest.fail("invalid request queried data"))
    with pytest.raises(ValueError, match="workstation_request_invalid"):
        agent_read.read_agents(cur, {}, query)


def test_no_grant_or_missing_fields_never_queries_metadata():
    cur = SimpleNamespace(execute=lambda *args: pytest.fail("denied request queried data"))
    for snapshot in ({}, issued(grant({"kind": "all"}, fields={"technical"}))):
        with pytest.raises(PermissionError):
            agent_read.read_agents(cur, snapshot, {})


def test_agent_endpoint_requires_authentication_but_not_owner(monkeypatch):
    monkeypatch.setattr(agents, "plugin_hook", lambda *args: agent_read.read_agents)
    monkeypatch.setattr(agents, "connect", lambda: pytest.fail("unauthenticated request queried data"))
    handler = Handler(authenticated=False, owner=False)
    assert agents.try_handle_get(handler, "/api/v1/workstations/agents", {})
    assert handler.responses[-1][1] == HTTPStatus.UNAUTHORIZED
    handler = Handler(owner=False)
    handler._access_decision = lambda: issued(grant({"kind": "agent", "ids": [AGENT]}))
    cur = SimpleNamespace(execute=lambda *args: None, fetchall=lambda: [row()])
    monkeypatch.setattr(agents, "connect", lambda: nullcontext(SimpleNamespace(cursor=lambda: nullcontext(cur))))
    assert agents.try_handle_get(handler, "/api/v1/workstations/agents", {})
    payload, status, headers = handler.responses[-1]
    assert status == HTTPStatus.OK and payload["items"][0]["agent_key"] == AGENT
    assert headers == {"Cache-Control": "no-store"}


@pytest.mark.parametrize("case,status", [
    ("anonymous", HTTPStatus.UNAUTHORIZED),
    ("no_grant", HTTPStatus.FORBIDDEN),
    ("owner_without_grant", HTTPStatus.FORBIDDEN),
    ("missing_fields", HTTPStatus.FORBIDDEN),
    ("wrong_action", HTTPStatus.FORBIDDEN),
    ("legacy_scope", HTTPStatus.OK),
    ("workspace_scope", HTTPStatus.OK),
])
def test_workstation_agent_http_route_enforces_scoped_grants(monkeypatch, case, status):
    domain = {"kind": "domain", "ids": [11]}
    snapshot = issued(grant(domain))
    if case in {"no_grant", "owner_without_grant"}:
        snapshot["reports"] = []
        snapshot["platform_owner"] = case == "owner_without_grant"
    elif case == "missing_fields":
        snapshot["reports"][0]["grants"] = [grant(domain, fields={"technical"})]
    elif case == "wrong_action":
        snapshot["reports"][0]["grants"] = [grant(domain, actions=("export",))]
    elif case == "workspace_scope":
        snapshot = issued(grant(domain), key=ws.REPORT_KEY, policies=[policy("read", domain)])

    calls, connections, responses = [], [], []
    cur = SimpleNamespace(execute=lambda sql, params=(): calls.append((sql, params)), fetchall=lambda: [row()])

    def connect():
        connections.append(True)
        return nullcontext(SimpleNamespace(cursor=lambda: nullcontext(cur)))

    # Keep HTTP dispatch, authentication, access snapshot loading, plugin
    # registration and scoped authorization real; replace only their DB inputs.
    monkeypatch.setattr(agents, "connect", connect)
    principal = {"type": "session", "id": 1, "role": "viewer"}
    monkeypatch.setattr(http_server, "principal_from_headers", lambda headers: None if case == "anonymous" else principal)
    monkeypatch.setattr(http_server, "auth_required", lambda: True)
    monkeypatch.setattr(http_server, "effective_access", lambda actor: snapshot)
    handler = object.__new__(http_server.RequestHandler)
    handler.server = SimpleNamespace()
    handler.path = "/api/v1/workstations/agents"
    handler.command = "GET"
    handler.headers = {"Host": "localhost"}
    handler._send_json = lambda payload, status=HTTPStatus.OK, **kwargs: responses.append((payload, status, kwargs))

    handler._do_GET()

    assert len(responses) == 1
    payload, actual_status, options = responses[0]
    assert actual_status == status
    if case == "anonymous":
        assert not connections and not calls
        assert payload == {"error": "authentication_required"}
    elif status == HTTPStatus.FORBIDDEN:
        assert not calls
        assert payload == {"error": "workstation_access_denied"}
    else:
        sql, params = calls[-1]
        assert "r.collection_scope_id = ANY(%s)" in sql
        assert params == (*([["ad-domain:11"]] * (2 if case == "workspace_scope" else 1)), agent_read.PAGE_SIZE + 1)
        assert payload == {"items": [{field: row()[field] for field in agent_read.FIELDS}],
                           "has_more": False, "next_cursor": None}
    if case != "anonymous":
        assert options == {"headers": {"Cache-Control": "no-store"}}


@pytest.mark.parametrize("error,status,code", [
    (PermissionError("private fixture"), HTTPStatus.FORBIDDEN, "workstation_access_denied"),
    (ValueError("private fixture"), HTTPStatus.BAD_REQUEST, "workstation_request_invalid"),
    (RuntimeError("private fixture"), HTTPStatus.SERVICE_UNAVAILABLE, "workstation_source_unavailable"),
    (AgentError("invalid_agent_id"), HTTPStatus.BAD_REQUEST, "workstation_request_invalid"),
])
def test_endpoint_denials_and_failures_contain_no_rows_counts_or_diagnostics(monkeypatch, error, status, code):
    def reader(*args):
        raise error

    monkeypatch.setattr(agents, "plugin_hook", lambda *args: reader)
    monkeypatch.setattr(agents, "connect", lambda: nullcontext(SimpleNamespace(cursor=lambda: nullcontext(object()))))
    handler = Handler(owner=False)
    agents.try_handle_get(handler, "/api/v1/workstations/agents", {})
    assert handler.responses[-1] == ({"error": code}, status, {"Cache-Control": "no-store"})


def test_missing_plugin_fails_before_data_read(monkeypatch):
    monkeypatch.setattr(agents, "plugin_hook", lambda *args: None)
    monkeypatch.setattr(agents, "connect", lambda: pytest.fail("missing plugin queried data"))
    handler = Handler(owner=False)
    agents.try_handle_get(handler, "/api/v1/workstations/agents", {})
    assert handler.responses[-1][1] == HTTPStatus.CONFLICT
