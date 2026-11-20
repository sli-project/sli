"""Bounded projection: exact revision/policy pins, no inferred admission."""
from copy import deepcopy
from dataclasses import asdict
from urllib.parse import urlencode

import pytest

from server.api.errors import RequestInputError
from server.api.routes import semantic as routes
from server.sli.sigma import rule_list
from tests.unit.test_sigma_attack_coverage import Connection, Cursor, END, Handler, SCOPE, START, observation


def policy(**changes):
    pin = {"version": "sli.sigma.execution.v1", "rule_id": "00000000-0000-0000-0000-000000000001",
           "rule_sha256": "a" * 64, "manifest_sha256": "c" * 64, "compiler_version": "compiler-v1",
           "mapping_version": "mapping-v1", "overlay_sha256": "d" * 64, "scope": asdict(SCOPE)}
    return {"policy_id": "fixture-policy", "policy_version": 2, "policy_title": "Synthetic policy title",
            "lifecycle_status": "shadow", "admitted": False, "effective_mode": "shadow",
            "selector": {"rule_id": pin["rule_id"], "execution": pin}, **changes}


class ListCursor(Cursor):
    def __init__(self):
        super().__init__()
        self.policies = [policy()]
        self.observations = [observation(counts={"scanned": 10, "evaluable": 10, "matched": 3})]

    def execute(self, sql, params=()):
        normalized = " ".join(sql.split()).lower()
        if "from semantic_risk_policies" in normalized:
            self.calls.append((normalized, params))
            self.result = deepcopy(self.policies)
        elif "from sli_sigma.attack_source_scopes" in normalized and not params:
            self.calls.append((normalized, params))
            self.result = [{**dict(zip(asdict(SCOPE), key)), **value} for key, value in self.sources.items()]
        elif "from sli_sigma.attack_history_coverage" in normalized:
            self.calls.append((normalized, params))
            self.result = [row for row in self.observations if tuple(row[key] for key in asdict(SCOPE)) == params[:5]]
        else:
            super().execute(sql, params)


@pytest.fixture
def cur(monkeypatch):
    value = ListCursor()
    monkeypatch.setattr(rule_list, "get_runtime_connection", lambda: Connection(value))
    return value


def read(access=None):
    return rule_list.get_sigma_rules({"platform_owner": True} if access is None else access, scope=SCOPE)


def test_test_matches_never_become_admission_or_live_matches(cur):
    data = read()
    row = data["rules"][0]
    assert data["read_only"] is True and data["since"] == START.isoformat() and data["until"] == END.isoformat()
    assert row["executions"][0]["mode"] == "test" and row["executions"][0]["counts"]["matched"] == 3
    assert row["admission"]["policies"][0]["admitted"] is False
    assert row["runtime"]["enabled"] == 0 and row["runtime"]["state"] == "measured"
    assert row["title"] is None and row["description"] is None and row["metadata_state"] == "unavailable"
    assert row["admission"]["policies"][0]["policy_title"] == "Synthetic policy title"
    assert all(sql.startswith(("select", "set transaction")) for sql, _ in cur.calls)
    assert all("canonical_rule" not in sql and "raw_yaml" not in sql for sql, _ in cur.calls)


def test_exact_retained_labels_are_not_replaced_with_policy_metadata(cur):
    cur.revisions[0].update(title="Retained Sigma title", description="Retained purpose", labels_available=True)
    row = read()["rules"][0]
    assert row["title"] == "Retained Sigma title" and row["description"] == "Retained purpose"
    assert row["metadata_state"] == "available"
    assert row["admission"]["policies"][0]["policy_title"] == "Synthetic policy title"


@pytest.mark.parametrize("change", ["sha", "generation", "source", "rule", "missing_pin"])
def test_unbound_or_malformed_pins_are_never_manageable(cur, change):
    selector = cur.policies[0]["selector"]
    if change == "sha":
        selector["execution"]["rule_sha256"] = "b" * 64
    elif change == "generation":
        selector["execution"]["scope"]["source_generation"] = "other-generation"
    elif change == "source":
        selector["execution"]["scope"]["source_instance_id"] = "other-source"
    elif change == "rule":
        selector["rule_id"] = "00000000-0000-0000-0000-000000000099"
    else:
        del selector["execution"]["overlay_sha256"]
    assert read()["rules"][0]["admission"]["policies"] == []


def test_multiple_exact_policy_versions_and_lifecycle_remain_distinct(cur):
    cur.policies += [policy(policy_version=3, admitted=True, lifecycle_status="retired", effective_mode=None)]
    policies = read()["rules"][0]["admission"]["policies"]
    assert [(p["policy_version"], p["admitted"], p["lifecycle_status"]) for p in policies] == [
        (2, False, "shadow"), (3, True, "retired")]


def test_runtime_modes_are_separate_from_test_execution_counters(cur):
    rev = cur.revisions[0]
    cur.matches = [{"rule_id": str(rev["rule_id"]), "rule_sha256": rev["raw_sha256"],
                    "evaluation_mode": mode, "matches": count} for mode, count in [("test", 12), ("shadow", 7), ("enabled", 2)]]
    runtime = read()["rules"][0]["runtime"]
    assert (runtime["enabled"], runtime["shadow"], runtime["test"]) == (2, 7, 12)


def test_missing_history_is_unknown_and_does_not_invent_a_current_window(cur):
    cur.observations = []
    data = read()
    assert data["since"] is None and data["until"] is None
    row = data["rules"][0]
    assert row["executions"] == [] and row["runtime"]["enabled"] is None
    assert not any("read_attack_live_matches" in sql for sql, _ in cur.calls)


def test_source_access_is_checked_before_revision_and_policy_reads(cur):
    cur.sources[tuple(asdict(SCOPE).values())] = {"resources": []}
    data = read()
    assert data["state"] == "unavailable" and data["rules"] == []
    assert len(cur.calls) == 2


def test_discovery_needs_no_manual_sha_and_filters_unproven_sources(cur):
    cur.sources[tuple(asdict(SCOPE).values())[:-2] + ("other-generation", "")] = {"resources": []}
    data = rule_list.get_sigma_rules({"platform_owner": True})
    assert data["sources"] == [asdict(SCOPE)]
    assert data["rules"] == []


def test_capability_preflight_reads_nothing(cur):
    assert read({})["state"] == "unavailable"
    assert cur.calls == []


def test_nonowner_never_receives_owner_policy_metadata(cur, monkeypatch):
    monkeypatch.setattr(rule_list, "_authorized", lambda access, resources: bool(resources))
    data = read({"capabilities": list(rule_list.CAPABILITIES)})
    assert data["rules"][0]["admission"] == {"state": "unavailable", "reason": "owner_required", "policies": []}
    assert not any("semantic_risk_policies" in sql for sql, _ in cur.calls)


def test_storage_failure_has_fixed_diagnostic_and_no_rows(cur):
    def fail(*_args):
        raise RuntimeError("fixture private SQL detail")
    cur.execute = fail
    data = read()
    assert data["state"] == "unavailable" and data["reason"] == "projection_unavailable"
    assert "private" not in repr(data) and data["rules"] == []


def test_http_discovery_and_exact_scope_use_existing_resource_aware_route(cur):
    path = "/api/v1/semantic/sigma-rules"
    assert ("GET", path) in routes.ROUTES and routes.is_resource_aware(path)
    handler = Handler()
    assert routes.try_handle_get(handler, path, {})
    assert handler.payload["sources"] == [asdict(SCOPE)]
    assert routes.try_handle_get(handler, path, {key: [value] for key, value in asdict(SCOPE).items()})
    assert handler.payload["rules"][0]["raw_sha256"] == "a" * 64


@pytest.mark.parametrize("query", [{"raw_sql": ["x"]}, {"plugin_id": [SCOPE.plugin_id]},
                                   {**{key: [value] for key, value in asdict(SCOPE).items()}, "source_generation": ["a", "b"]}])
def test_http_rejects_partial_unknown_and_duplicate_scope_filters(cur, query):
    with pytest.raises(RequestInputError, match="sigma_rule_filter_invalid"):
        routes.try_handle_get(Handler(), "/api/v1/semantic/sigma-rules", query)
    assert not cur.calls


def test_serialized_http_get_preserves_empty_collection_scope(cur, monkeypatch):
    from server.api import http_server
    handler = Handler()
    handler.path = "/api/v1/semantic/sigma-rules?" + urlencode(asdict(SCOPE))
    handler._require_secure_api_transport = lambda _path: True
    monkeypatch.setattr(http_server, "auth_required", lambda: False)
    http_server.RequestHandler._do_GET(handler)
    assert handler.payload["scope"] == asdict(SCOPE)
    assert handler.payload["state"] == "available"


def test_serialized_http_get_rejects_duplicate_blank_collection_scope(cur, monkeypatch):
    from server.api import http_server
    handler = Handler()
    handler.path = "/api/v1/semantic/sigma-rules?" + urlencode(asdict(SCOPE)) + "&collection_scope_id="
    handler._require_secure_api_transport = lambda _path: True
    monkeypatch.setattr(http_server, "auth_required", lambda: False)
    with pytest.raises(RequestInputError, match="sigma_rule_filter_invalid"):
        http_server.RequestHandler._do_GET(handler)
    assert not cur.calls
