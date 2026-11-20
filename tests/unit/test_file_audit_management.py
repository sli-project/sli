"""Scoped administrator / mTLS contracts using agent and cursor fakes."""
import json
from copy import deepcopy
from unittest.mock import Mock, patch

import pytest

from server.sli.access.scope import AccessScope, ScopeClause
from server.sli.agents.ca import AgentError
from server.sli.plugins.file_audit import management
from sli_agent.file_audit import digest, request
from sli_agent.control import collection_policy
from test_sli_agent_file_audit import NOW, command, execute, paged_check, settings, setup

AGENT = "00000000-0000-4000-8000-000000000001"
HOST = "00000000-0000-4000-8000-000000000002"
PRINCIPAL = {"type": "session", "id": 1, "role": "admin"}


def access(capability="file-audit.audit.manage", scope="scope:one"):
    allowed = AccessScope("restricted", (ScopeClause(plugin_ids=("sli.file-audit",), device_ids=(AGENT,),
        source_instance_ids=(HOST,), collection_scope_ids=(scope,)),))
    return {"capability_policies": [{"capability_key": capability, "effect": "allow", "valid": True, "scope": allowed.to_dict()}]}


class Cursor:
    def __init__(self):
        self.agent = {"id": AGENT, "host_id": HOST, "status": "active", "policy_revision": 1,
                      "assigned_modules": [], "collection_policy": {"manage_windows_audit": True}, "rights_probe": {},
                      "file_audit": {}}
        self.calls = []

    def execute(self, sql, params=()):
        self.calls.append((sql, params))
        if sql.startswith("update sli_agents set file_audit"):
            self.agent["file_audit"] = json.loads(params[0])
            if "policy_revision=%s" in sql:
                self.agent["policy_revision"] = params[1]
            if "assigned_modules=%s" in sql:
                self.agent["assigned_modules"] = json.loads(params[2])

    def fetchone(self):
        return deepcopy(self.agent)

    def fetchall(self):
        return []


def body(action="check"):
    value = command(action)
    value["command"]["policy_revision"] = "2"
    return {"agent_id": AGENT, "expected_revision": 1, **value}


def observed(tmp_path, action="apply"):
    manager, api, audit = setup(tmp_path)
    _, result = execute(manager, command(action))
    return result, {"request": request(command(action)), "state": "pending", "scopes": {}, "may_own_audit": action == "apply"}


def test_command_is_revisioned_authored_and_offline_pending():
    cur = Cursor()
    result = management.enqueue(cur, body("apply"), principal=PRINCIPAL, access=access())
    assert result == {"policy_revision": 2, "command_id": "synthetic-apply", "state": "pending"}
    assert cur.agent["file_audit"]["may_own_audit"] is True
    assert cur.agent["file_audit"]["request"]["config"]["policy_revision"] == "2"
    assert cur.agent["assigned_modules"] == []
    call = next(params for sql, params in cur.calls if "enqueue_audit" in sql)
    assert call[0:2] == (AGENT, HOST) and call[-2:] == ("session", 1)
    details = json.loads(next(params[3] for sql, params in cur.calls if sql.startswith("insert into sli_agent_audit")))
    assert details["command_action"] == "apply"
    assert "path" not in json.dumps(details) and details["policy_sha256"]
    from server.sli.agents.policies import check_in
    assert check_in(cur.agent)["file_audit"] == cur.agent["file_audit"]["request"]


def test_retained_command_is_not_dispatched_without_installed_package(monkeypatch):
    from server.sli.agents import policies
    cur = Cursor()
    cur.agent["file_audit"] = {"request": request(command())}
    monkeypatch.setattr(policies, "plugin_hook", lambda *args: None)
    assert "file_audit" not in policies.check_in(cur.agent)


def test_workstation_command_and_collection_assignment_share_one_revision():
    from tests.unit.test_workstation_file_audit import workstation_policy
    cur = Cursor()
    cur.agent["assigned_modules"] = [{"module_id": "sli.workstations", "enabled": True, "config": {}}]
    value = {**body("apply"), "config": workstation_policy(), "enabled": True}
    management.enqueue(cur, value, principal=PRINCIPAL, access=access())
    assignment = next(item for item in cur.agent["assigned_modules"] if item["module_id"] == "sli.file-audit")
    assert assignment["enabled"] is True and assignment["config"]["source_kind"] == "workstation"
    assert assignment["config"]["policy_revision"] == "2"
    assert cur.agent["file_audit"]["request"]["config"] == assignment["config"]


def test_batch_validates_all_revisions_before_enqueuing_any_command():
    from tests.unit.test_workstation_file_audit import workstation_policy
    cur = Cursor()
    value = {"agents": [{"agent_id": AGENT, "expected_revision": 0}], "config": workstation_policy(),
             "action": "check", "enabled": True}
    with pytest.raises(AgentError, match="revision_conflict"):
        management.enqueue_batch(cur, value, principal=PRINCIPAL, access=access())
    assert not any("enqueue_audit" in sql for sql, _ in cur.calls)


def test_server_request_cannot_set_workstation_collection_toggle():
    cur = Cursor()
    with pytest.raises(AgentError, match="request_invalid"):
        management.enqueue(cur, {**body(), "enabled": True}, principal=PRINCIPAL, access=access())


@pytest.mark.parametrize("source_kind", ["server", "workstation"])
def test_explicit_activation_publishes_one_collector_request_and_snapshot(source_kind):
    cur = Cursor()
    config = body("apply")["config"]
    if source_kind == "workstation":
        from tests.unit.test_workstation_file_audit import workstation_policy
        config = workstation_policy()
        cur.agent["assigned_modules"] = [{"module_id": "sli.workstations", "enabled": True, "config": {}}]
    original = deepcopy(cur.agent["assigned_modules"])
    management.enqueue(cur, {**body("apply"), "config": config, "enabled": True,
                            "activate_collection": True}, principal=PRINCIPAL, access=access())
    assignment = cur.agent["assigned_modules"][-1]
    assert cur.agent["assigned_modules"][:-1] == original
    assert assignment["enabled"] is True and assignment["config"]["policy_revision"] == "2"
    assert assignment["config"] == cur.agent["file_audit"]["request"]["config"]
    history = [params for sql, params in cur.calls if sql.startswith("insert into sli_agent_policy_history")]
    assert history[0][1] == 1 and json.loads(history[0][2]) == original
    assert history[1][1] == 2 and json.loads(history[1][2]) == cur.agent["assigned_modules"]


@pytest.mark.parametrize("changes", [
    {"activate_collection": "true", "enabled": True},
    {"activate_collection": True}, {"activate_collection": True, "enabled": False},
    {"activate_collection": True, "enabled": True, "command_action": "check"},
    {"activate_collection": True, "enabled": True, "command_action": "restore"},
])
def test_activation_rejects_implicit_or_contradictory_intent(changes):
    cur = Cursor()
    value = body(changes.get("command_action", "apply"))
    value.update({key: val for key, val in changes.items() if key != "command_action"})
    with pytest.raises(AgentError, match="request_invalid"):
        management.enqueue(cur, value, principal=PRINCIPAL, access=access())
    assert not cur.calls


def test_false_activation_preserves_server_request_only_semantics():
    cur = Cursor()
    management.enqueue(cur, {**body("apply"), "activate_collection": False}, principal=PRINCIPAL, access=access())
    assert cur.agent["assigned_modules"] == []


def test_workstation_batch_forwards_explicit_activation():
    from tests.unit.test_workstation_file_audit import workstation_policy
    cur = Cursor()
    cur.agent["assigned_modules"] = [{"module_id": "sli.workstations", "enabled": True, "config": {}}]
    result = management.enqueue_batch(cur, {"agents": [{"agent_id": AGENT, "expected_revision": 1}],
        "config": workstation_policy(), "action": "apply", "enabled": True, "activate_collection": True},
        principal=PRINCIPAL, access=access())
    assert result["items"][0]["policy_revision"] == 2
    assert cur.agent["assigned_modules"][-1]["config"] == cur.agent["file_audit"]["request"]["config"]


def test_activation_checkin_constructs_collector_at_registered_revision_without_native_calls():
    from types import SimpleNamespace
    from server.sli.agents.policies import check_in
    from sli_agent.policies import apply_policy

    cur = Cursor()
    management.enqueue(cur, {**body("apply"), "enabled": True, "activate_collection": True},
                       principal=PRINCIPAL, access=access())
    cur.agent["policy_revision"] = 3  # A later unrelated control revision.
    request = cur.agent["file_audit"]["request"]

    class Manager:
        def reconcile(self, assignments, control, revision, value):
            assert assignments[-1]["config"] == value["config"] == request["config"]
            assert revision == 3 and value["command"]["policy_revision"] == "2"
            return None, None

    applied = apply_policy(SimpleNamespace(collection_enabled=False), HOST, check_in(cur.agent),
                           None, SimpleNamespace(agent_id=AGENT), defer_ack=True, file_audit_manager=Manager())
    collector = next(module for module in applied if module.module_id == "sli.file-audit")
    assert collector.policy["policy_revision"] == "2"
    assert applied.report == {"applied_policy_revision": 3}


@pytest.mark.parametrize("source_kind", ["server", "workstation"])
def test_activation_cannot_bypass_all_collector_root_authorization(source_kind):
    cur = Cursor()
    value = {**body("apply"), "enabled": True, "activate_collection": True}
    if source_kind == "workstation":
        from tests.unit.test_workstation_file_audit import workstation_policy
        value["config"] = workstation_policy()
        cur.agent["assigned_modules"] = [{"module_id": "sli.workstations", "enabled": True, "config": {}}]
    extra = deepcopy(value["config"]["roots"][0])
    extra.update(collection_scope_id="scope:other", path=r"C:\synthetic-other")
    value["config"]["roots"].append(extra)
    with pytest.raises(AgentError, match="file_audit_request_denied"):
        management.enqueue(cur, value, principal=PRINCIPAL, access=access())
    assert not any("enqueue_audit" in sql or sql.startswith("update") for sql, _ in cur.calls)


@pytest.mark.parametrize("oversized", ["modules", "checkin", "request"])
def test_activation_preserves_module_and_wire_size_limits(oversized):
    cur = Cursor()
    value = {**body("apply"), "enabled": True, "activate_collection": True}
    if oversized == "modules":
        cur.agent["assigned_modules"] = ["synthetic"] * 64
    elif oversized == "checkin":
        cur.agent["assigned_modules"] = [{"module_id": "synthetic", "config": {"text": "x" * 60000}}]
    else:
        root = value["config"]["roots"][0]
        value["config"]["roots"] = [{**deepcopy(root), "collection_scope_id": f"scope:{i}",
            "path": "C:\\" + "x" * 4000} for i in range(20)]
    with pytest.raises(AgentError, match="file_audit_request_denied"):
        management.enqueue(cur, value, principal=PRINCIPAL, access=access())
    assert not any("enqueue_audit" in sql or sql.startswith("update") for sql, _ in cur.calls)


def test_workstation_batch_restore_uses_retained_scope_and_disables_collection():
    from tests.unit.test_workstation_file_audit import workstation_policy
    cur = Cursor()
    retained = workstation_policy()
    cur.agent["file_audit"] = {"request": request(command("apply", config=retained)), "may_own_audit": True}
    changed = workstation_policy()
    changed["roots"][0]["path"] = r"C:\synthetic-other"
    management.enqueue_batch(cur, {"agents": [{"agent_id": AGENT, "expected_revision": 1}],
        "config": changed, "action": "restore", "enabled": True}, principal=PRINCIPAL, access=access())
    assignment = cur.agent["assigned_modules"][0]
    assert assignment["enabled"] is False
    assert assignment["config"]["roots"] == retained["roots"]
    assert cur.agent["file_audit"]["request"]["command"]["action"] == "restore"


def test_batch_rejects_malformed_roots_without_writes():
    cur = Cursor()
    with pytest.raises(AgentError, match="request_invalid"):
        management.enqueue_batch(cur, {"agents": [{"agent_id": AGENT, "expected_revision": 1}],
            "config": {"source_kind": "workstation", "roots": [{}]}, "action": "check", "enabled": True},
            principal=PRINCIPAL, access=access())
    assert not cur.calls


@pytest.mark.parametrize("principal,decision", [
    ({"type": "session", "id": 1, "role": "viewer"}, access()),
    (PRINCIPAL, access("file-audit.view")),
    (PRINCIPAL, access(scope="scope:other")),
])
def test_admin_and_own_scope_are_required_before_enqueue(principal, decision):
    cur = Cursor()
    with pytest.raises(AgentError, match="file_audit_request_denied"):
        management.enqueue(cur, body(), principal=principal, access=decision)
    assert not any("enqueue_audit" in sql or sql.startswith("update") for sql, _ in cur.calls)


def test_missing_consent_stale_revision_and_command_revision_drift_fail_closed():
    cur = Cursor()
    cur.agent["collection_policy"] = {}
    with pytest.raises(AgentError, match="file_audit_management_disabled"):
        management.enqueue(cur, body("apply"), principal=PRINCIPAL, access=access())
    with pytest.raises(AgentError, match="agent_policy_revision_conflict"):
        management.enqueue(cur, {**body(), "expected_revision": 0}, principal=PRINCIPAL, access=access())
    value = body()
    value["command"]["policy_revision"] = "1"
    with pytest.raises(AgentError, match="file_audit_request_denied"):
        management.enqueue(cur, value, principal=PRINCIPAL, access=access())
    assert not any("enqueue_audit" in sql for sql, _ in cur.calls)


def test_command_cannot_overflow_checkin_with_other_assignments():
    cur = Cursor()
    cur.agent["assigned_modules"] = [{"module_id": "synthetic", "config": {"synthetic": "x" * 60000}}]
    with pytest.raises(AgentError, match="file_audit_request_denied"):
        management.enqueue(cur, body(), principal=PRINCIPAL, access=access())
    assert not any("enqueue_audit" in sql for sql, _ in cur.calls)


def test_audit_status_is_scoped_and_excludes_inventory_and_private_paths(monkeypatch):
    cur = Cursor()
    monkeypatch.setattr(management.registry, "audit", Mock())
    management.enqueue(cur, body("apply"), principal=PRINCIPAL, access=access())
    result = management.status(cur, AGENT, principal=PRINCIPAL, access=access())
    assert result["state"] == "pending" and "C:" not in json.dumps(result)
    with pytest.raises(AgentError, match="file_audit_request_denied"):
        management.status(cur, AGENT, principal=PRINCIPAL, access=access(scope="scope:other"))


def test_scope_cannot_be_changed_before_restore(monkeypatch):
    cur = Cursor()
    monkeypatch.setattr(management.registry, "audit", Mock())
    management.enqueue(cur, body("apply"), principal=PRINCIPAL, access=access())
    value = body("apply")
    value["expected_revision"] = 2
    value["command"]["policy_revision"] = "3"
    value["config"]["roots"][0]["important"] = True
    with pytest.raises(AgentError, match="file_audit_restore_required"):
        management.enqueue(cur, value, principal=PRINCIPAL, access=access())


def test_agent_result_stores_immutable_snapshots_and_safe_status_with_mtls_identity(tmp_path):
    value, state = observed(tmp_path)
    cur = Cursor()
    cur.agent["file_audit"] = state
    result = management.ingest(cur, cur.agent, value)
    assert result == {"command_id": "synthetic-apply", "state": "verified"}
    assert cur.agent["file_audit"]["may_own_audit"] is True
    assert "snapshots" not in cur.agent["file_audit"]
    assert "C:" not in json.dumps(cur.agent["file_audit"]["scopes"])
    params = next(params for sql, params in cur.calls if "store_audit_result" in sql)
    assert params[0] == AGENT
    payload = json.loads(params[1])
    assert payload["scopes"][0]["result_sha256"] == digest(value)
    # Duplicate delivery keeps exactly the same immutable snapshot and receipt IDs.
    management.ingest(cur, cur.agent, value)
    repeated = [params for sql, params in cur.calls if "store_audit_result" in sql]
    assert repeated[0] == repeated[1]


def test_admitted_inventory_publishes_scope_bound_permission_rule(tmp_path):
    from uuid import NAMESPACE_URL, uuid5
    value, state = observed(tmp_path)
    inventory = value["snapshots"][0]
    inventory["share"]["dacl"] = "D:(A;;FR;;;WD)"
    inventory["objects"][0]["dacl"] = "D:(A;;FW;;;WD)"
    contents = {key: row for key, row in inventory.items() if key not in ("snapshot_id", "snapshot_sha256")}
    inventory["snapshot_sha256"] = digest(contents)
    inventory["snapshot_id"] = str(uuid5(NAMESPACE_URL, value["command_id"] + digest(contents)))
    cur = Cursor()
    cur.agent["file_audit"] = state
    management.ingest(cur, cur.agent, value)
    payload = json.loads(next(args[-1] for sql, args in cur.calls if "publish_rules" in sql))
    assert len(payload) == 1
    assert payload[0]["rule_code"] == "file-audit.broad-write"
    assert payload[0]["snapshot_ids"] == [inventory["snapshot_id"]]
    assert payload[0]["source_instance_id"] == HOST


@pytest.mark.parametrize("mutation", [
    lambda result: result.update(agent_id=HOST),
    lambda result: result.update(policy_revision="2"),
    lambda result: result.update(command_id="synthetic-stale"),
    lambda result: result.update(ownership_remaining=1),
    lambda result: result["scopes"][0].update(collection_scope_id="scope:other"),
    lambda result: result["scopes"][0].update(reason_code="synthetic-private-diagnostic"),
    lambda result: result["scopes"][0]["actual_masks"].update({"0cce921d-69ae-11d9-bed3-505054503030": 0}),
    lambda result: result["snapshots"][0].update(snapshot_sha256="a" * 64),
    lambda result: result["snapshots"][0]["objects"][0].update(path=r"C:\outside"),
    lambda result: result["snapshots"][0].update(completeness="complete", unread_objects=1),
    lambda result: result["snapshots"][0].update(extra="synthetic"),
])
def test_untrusted_or_stale_result_is_rejected_before_sql(tmp_path, mutation):
    value, state = observed(tmp_path)
    mutation(value)
    cur = Cursor()
    cur.agent["file_audit"] = state
    with pytest.raises(AgentError, match="file_audit_result_invalid"):
        management.ingest(cur, cur.agent, value)
    assert not any("store_audit_result" in sql or sql.startswith("update") for sql, _ in cur.calls)


def test_historical_lost_receipt_is_admitted_without_replacing_new_command(tmp_path):
    value, original = observed(tmp_path)
    cur = Cursor()
    cur.agent["file_audit"] = {"request": request(command("check")), "state": "pending"}
    before = deepcopy(cur.agent["file_audit"])
    cur.fetchone = lambda: {"request": original["request"]}
    assert management.ingest(cur, cur.agent, value)["state"] == "superseded"
    assert cur.agent["file_audit"] == before
    assert any("store_audit_result" in sql for sql, _ in cur.calls)
    assert not any(sql.startswith("update") for sql, _ in cur.calls)


def test_partial_snapshot_is_retained_without_claiming_full_coverage(tmp_path):
    manager, api, audit = setup(tmp_path)
    api.objects[r"C:\synthetic\item"].row["sacl_protected"] = True
    _, value = execute(manager, command("apply"))
    cur = Cursor()
    cur.agent["file_audit"] = {"request": request(command("apply")), "state": "pending", "scopes": {}, "may_own_audit": True}
    assert management.ingest(cur, cur.agent, value)["state"] == "partial"
    assert value["snapshots"][0]["completeness"] == "partial"


def test_verified_restore_clears_removal_guard_only_after_readback(tmp_path):
    manager, api, audit = setup(tmp_path)
    _, applied = execute(manager, command("apply"))
    manager.acknowledge(applied)
    _, value = execute(manager, command("restore"))
    cur = Cursor()
    cur.agent["file_audit"] = {"request": request(command("restore")), "state": "pending", "scopes": {}, "may_own_audit": True}
    assert management.ingest(cur, cur.agent, value)["state"] == "verified"
    assert cur.agent["file_audit"]["may_own_audit"] is False


@pytest.mark.parametrize("action,reason", [("check", "managed_by_gpo"), ("restore", "restore_conflict")])
def test_management_blockers_are_admitted_without_releasing_rollback_guard(tmp_path, action, reason):
    manager, api, audit = setup(tmp_path)
    if action == "restore":
        _, applied = execute(manager, command("apply"))
        manager.acknowledge(applied)
        api.objects[r"C:\synthetic\item"].row["sacl"] = "synthetic-foreign-change"
    else:
        api.owner = reason
    _, value = execute(manager, command(action))
    cur = Cursor()
    cur.agent["file_audit"] = {"request": request(command(action)), "state": "pending", "scopes": {}, "may_own_audit": True}
    assert management.ingest(cur, cur.agent, value)["state"] == "partial"
    assert cur.agent["file_audit"]["scopes"]["scope:one"]["reason_code"] == reason
    assert cur.agent["file_audit"]["may_own_audit"] is True


def test_api_routes_keep_independent_owner_and_mtls_admission(monkeypatch):
    from server.api.routes import agents
    calls = []
    hooks = {"enqueue_audit": Mock(return_value={"state": "pending"}), "ingest_audit": Mock(return_value={"state": "partial"})}
    monkeypatch.setattr(agents, "plugin_hook", lambda plugin, name: hooks[name])
    monkeypatch.setattr(agents, "_owner", lambda handler, **kw: calls.append("owner") or True)
    monkeypatch.setattr(agents, "_execute", lambda handler, operation, **kw: calls.append(kw.get("transport")))
    handler = SimpleHandler()
    assert agents.try_handle_post(handler, "/api/v1/admin/agents/file-audit")
    assert calls == ["owner", None]
    calls.clear()
    assert agents.try_handle_post(handler, "/api/v1/agent/file-audit-report")
    assert calls == [agents.peer_certificate]
    assert ("POST", "/api/v1/admin/agents/file-audit") in agents.ROUTES


def test_api_batch_uses_owner_route_and_scoped_plugin_hook(monkeypatch):
    from server.api.routes import agents
    hook = Mock(return_value={"items": []})
    selected = {"agents": [{"agent_id": AGENT, "expected_revision": 1}]}
    requested = []
    monkeypatch.setattr(agents, "plugin_hook", lambda plugin, name: requested.append((plugin, name)) or hook)
    owner = Mock(return_value=True)
    monkeypatch.setattr(agents, "_owner", owner)
    monkeypatch.setattr(agents, "_execute", lambda handler, operation: operation("synthetic-cursor"))
    handler = SimpleHandler()
    handler._read_json_body = lambda: selected
    handler._access_decision = lambda: access()
    assert agents.try_handle_post(handler, "/api/v1/admin/agents/file-audit")
    assert requested == [("sli.file-audit", "enqueue_audit_batch")]
    owner.assert_called_once_with(handler, mutation=True)
    hook.assert_called_once_with("synthetic-cursor", selected, principal=PRINCIPAL, access=access())


class SimpleHandler:
    _principal = PRINCIPAL

    def _read_json_body(self):
        return body()


def test_clean_final_page_preserves_scan_wide_partial_readiness(tmp_path):
    # Isolate rule publishing; exercise real validation and readiness persistence.
    with patch.object(management, "evaluate_snapshots"):
        manager, api, audit, value = paged_check(tmp_path)
        cur = Cursor()
        cur.agent["file_audit"] = {"request": request(value), "state": "pending", "scopes": {}}
        _, first = execute(manager, value)
        assert management.ingest(cur, cur.agent, first)["state"] == "partial"
        manager.acknowledge(first)
        _, final = execute(manager, value)
        assert not final["snapshots"][0]["has_more"]
        assert not any(row["sacl_missing"] for row in final["snapshots"][0]["objects"])
        assert management.validate_result(final, cur.agent["file_audit"]) == final
        assert management.ingest(cur, cur.agent, final)["state"] == "partial"
        assert cur.agent["file_audit"]["scopes"]["scope:one"]["reason_code"] == "sacl_missing"
        assert not api.writes and not audit.writes
