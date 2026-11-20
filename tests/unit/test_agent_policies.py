"""Policy contracts using locked-row cursor fakes, never a real database."""
import json
from copy import deepcopy

import pytest

from server.sli.agents import policies, registry, windows_audit
from server.sli.agents.ca import AgentError
from sli_agent.windows_audit import family_report, required_families

AGENT = "00000000-0000-4000-8000-000000000001"
HOST = "00000000-0000-4000-8000-000000000002"


class Cursor:
    def __init__(self):
        self.agent = dict(id=AGENT, host_id=HOST, status="active", assigned_modules=[],
                          policy_revision=1, applied_policy_revision=0, rights_probe={})
        self.calls = []
        self.audits = []
        self.history = {}
        self.retained_policies = []

    def execute(self, sql, params=()):
        self.calls.append((sql, params))
        if sql.startswith("insert into sli_agent_audit"):
            self.audits.append((params[0], json.loads(params[3])))
        elif sql.startswith("insert into sli_agent_policy_history"):
            self.history.setdefault((params[0], params[1]), json.loads(params[2]))
        elif sql.startswith("update sli_agents set assigned_modules"):
            self.agent.update(assigned_modules=json.loads(params[0]), policy_revision=params[1])
        elif sql == "select sli_plugin_file_audit.retain_assignment_policy(%s,%s,%s)":
            agent_id, actor_kind, actor_id = params
            assert agent_id == str(self.agent["id"])
            assert actor_kind in {"session", "api_key"} and type(actor_id) is int and actor_id > 0
            self.retained_policies.append({"params": params, "call_index": len(self.calls) - 1,
                "policy_revision": self.agent["policy_revision"],
                "assigned_modules": deepcopy(self.agent["assigned_modules"]), "audit_count": len(self.audits)})
        elif sql.startswith("update sli_agents set applied_policy_revision"):
            self.agent.update(applied_policy_revision=params[0], rights_probe=json.loads(params[1]))
        elif sql.startswith("update sli_agents set applied_collection_state"):
            self.agent["applied_collection_state"] = params[0]
        elif sql.startswith("update sli_agents set rights_probe"):
            self.agent["rights_probe"] = json.loads(params[0])
        elif sql.startswith("update sli_agents set windows_audit"):
            self.agent["windows_audit"] = json.loads(params[0])
        elif sql.startswith("update sli_agents set collection_policy"):
            self.agent.update(collection_policy=json.loads(params[0]), policy_revision=params[1])
        else:
            assert sql.endswith("for update")

    def fetchone(self):
        return deepcopy(self.agent)


def assignment(enabled=True, **extra):
    return dict(agent_id=AGENT, module_id="sli.workstations", enabled=enabled, config={}, **extra)


def audit_report(cur, *, revision=None, management="disabled", ownership="ok", complete=False):
    requirements = required_families(cur.agent["assigned_modules"])
    actual = {spec["guid"]: 3 if complete else 0 for specs in requirements.values() for spec in specs}
    return {"policy_revision": cur.agent["policy_revision"] if revision is None else revision,
            "management_state": management, "command_line_enabled": None,
            "families": family_report(requirements, actual, ownership)}


def test_audit_management_is_off_by_default_revisioned_isolated_and_audited():
    cur, other = Cursor(), Cursor()
    assert policies.check_in(cur.agent)["collection_policy"].get("manage_windows_audit", False) is False
    result = policies.update_control(cur, {"agent_id": AGENT, "expected_revision": 1,
        "collection_policy": {"manage_windows_audit": True}}, actor="session:1")
    assert result["policy_revision"] == 2 and result["collection_policy"]["manage_windows_audit"] is True
    assert policies.check_in(other.agent)["collection_policy"].get("manage_windows_audit", False) is False
    assert cur.audits[-1][0] == "policy_update"
    assert cur.audits[-1][1]["changed_fields"] == ["manage_windows_audit"]
    assert cur.history[(AGENT, 1)] == []
    assert cur.history[(AGENT, 2)] == []


def test_server_ingests_safe_per_family_audit_observations_for_authenticated_agent():
    cur = Cursor()
    cur.agent["assigned_modules"] = [{"module_id": "sli.workstations", "enabled": True, "config": {}}]
    observation = audit_report(cur)
    result = windows_audit.report(cur, deepcopy(cur.agent), {"windows_audit": observation})
    stored = cur.agent["windows_audit"]
    assert stored["families"]["logons"]["state"] == "missing"
    assert stored["reported_at"] and result["windows_audit"] == stored
    assert stored["policy_revision"] == 1 and stored["management_state"] == "disabled"
    assert next(params[1] for sql, params in cur.calls if sql.startswith("update sli_agents set windows_audit")) == AGENT
    assert cur.agent["applied_policy_revision"] == 0 and cur.agent["rights_probe"] == {}
    assert not cur.audits


@pytest.mark.parametrize("value", [False, True, None])
def test_powershell_audit_report_is_optional_and_strict(value):
    cur = Cursor()
    cur.agent["assigned_modules"] = [{"module_id": "sli.workstations", "enabled": True, "config": {}}]
    observation = audit_report(cur)
    observation["powershell_logging"] = {"channel_enabled": value, "script_block_logging_enabled": value}
    result = windows_audit.report(cur, cur.agent, {"windows_audit": observation})
    assert result["windows_audit"]["powershell_logging"] == observation["powershell_logging"]
    observation["powershell_logging"]["channel_enabled"] = "false"
    with pytest.raises(AgentError, match="invalid_agent_windows_audit_report"):
        windows_audit.report(cur, cur.agent, {"windows_audit": observation})


def test_current_audit_revision_ack_and_stale_observation_do_not_replace_newer_state():
    cur = Cursor()
    cur.agent.update(policy_revision=3, assigned_modules=[{"module_id": "sli.workstations", "enabled": True, "config": {}}],
                     collection_policy={"manage_windows_audit": True})
    observation = audit_report(cur, management="applied", complete=True)
    result = policies.report(cur, deepcopy(cur.agent), {"applied_policy_revision": 3, "collection_state": "active"})
    assert result["applied_policy_revision"] == 3 and "windows_audit" not in result
    result = windows_audit.report(cur, deepcopy(cur.agent), {"windows_audit": observation})
    assert result["windows_audit"]["management_state"] == "applied"
    saved = deepcopy(cur.agent["windows_audit"])
    windows_audit.report(cur, deepcopy(cur.agent), {
        "windows_audit": audit_report(cur, revision=2, ownership="managed_by_gpo", management="blocked")})
    assert cur.agent["windows_audit"] == saved


@pytest.mark.parametrize("change", [
    {"policy_revision": True}, {"policy_revision": 2}, {"host": "private-fixture"},
    {"management_state": "arbitrary"}, {"command_line_enabled": 1}, {"families": {"arbitrary": {}}},
    {"families": {}}, {"management_state": "applied"},
])
def test_invalid_audit_report_does_not_store_untrusted_fields_or_ack(change):
    cur = Cursor()
    cur.agent["assigned_modules"] = [{"module_id": "sli.workstations", "enabled": True, "config": {}}]
    with pytest.raises(AgentError, match="invalid_agent_windows_audit_report"):
        windows_audit.report(cur, cur.agent, {"windows_audit": {**audit_report(cur), **change}})
    assert not any(sql.startswith("update") for sql, _ in cur.calls)


@pytest.mark.parametrize("field,value", [("guid", "invalid"), ("actual_success", "true"),
                                       ("failure", 1), ("diagnostic", "private-fixture")])
def test_untrusted_audit_subcategories_and_diagnostics_are_rejected(field, value):
    cur = Cursor()
    cur.agent["assigned_modules"] = [{"module_id": "sli.workstations", "enabled": True, "config": {}}]
    observation = audit_report(cur)
    observation["families"]["logons"]["required"][0][field] = value
    with pytest.raises(AgentError, match="invalid_agent_windows_audit_report"):
        windows_audit.report(cur, cur.agent, {"windows_audit": observation})
    assert not any(sql.startswith("update") for sql, _ in cur.calls)


def test_command_line_consent_requires_explicit_actual_confirmation():
    cur = Cursor()
    cur.agent.update(collection_policy={"manage_windows_audit": True, "audit_process_command_line": True},
        assigned_modules=[{"module_id": "sli.workstations", "enabled": True, "config": {}}])
    observation = audit_report(cur, management="applied", complete=True)
    with pytest.raises(AgentError, match="invalid_agent_windows_audit_report"):
        windows_audit.report(cur, cur.agent, {"windows_audit": observation})
    observation["command_line_enabled"] = True
    result = windows_audit.report(cur, cur.agent, {"windows_audit": observation})
    assert result["windows_audit"]["command_line_enabled"] is True


def test_opt_out_keeps_old_agents_wire_compatible_and_ack_does_not_confirm_audit_management():
    cur = Cursor()
    cur.agent["collection_policy"] = {"manage_windows_audit": False, "audit_process_command_line": True}
    control = policies.check_in(cur.agent)["collection_policy"]
    assert "manage_windows_audit" not in control and "audit_process_command_line" not in control
    cur.agent["collection_policy"]["manage_windows_audit"] = True
    assert policies.check_in(cur.agent)["collection_policy"]["manage_windows_audit"] is True
    result = policies.report(cur, cur.agent, {"applied_policy_revision": 1, "collection_state": "active"})
    assert result["applied_policy_revision"] == 1 and "windows_audit" not in result
    assert "windows_audit" not in cur.agent


@pytest.mark.parametrize("body", [None, {}, {"windows_audit": None},
    {"windows_audit": {}, "agent_id": HOST}, {"windows_audit": {}, "applied_policy_revision": 1}])
def test_audit_report_rejects_invalid_body_without_writes(body):
    cur = Cursor()
    with pytest.raises(AgentError, match="invalid_agent_windows_audit_report"):
        windows_audit.report(cur, cur.agent, body)
    assert not cur.calls


@pytest.mark.parametrize("revision", [0, -1, True, 2, "1"])
def test_audit_report_rejects_invalid_revision_without_writes(revision):
    cur = Cursor()
    with pytest.raises(AgentError, match="invalid_agent_windows_audit_report"):
        windows_audit.report(cur, cur.agent, {"windows_audit": audit_report(cur, revision=revision)})
    assert not cur.calls


def test_policy_ack_rejects_audit_report_fields():
    cur = Cursor()
    with pytest.raises(AgentError, match="invalid_agent_policy_report"):
        policies.report(cur, cur.agent, {"applied_policy_revision": 1, "windows_audit": audit_report(cur)})
    assert not cur.calls


def test_each_change_creates_a_revision_retains_other_modules_and_audits():
    cur = Cursor()
    cur.agent["assigned_modules"] = ["sli.heartbeat"]
    first = registry.assign_module(cur, assignment(expected_revision=1), actor="session:1")
    assert first["policy_revision"] == 2
    assert first["assigned_modules"][0] == "sli.heartbeat"
    assert first["assigned_modules"][1]["config"]["policy_revision"] == "2"
    second = registry.assign_module(cur, assignment(False, expected_revision=2), actor="session:1")
    assert second["policy_revision"] == 3
    assert second["assigned_modules"][1]["enabled"] is False
    assert cur.agent["applied_policy_revision"] == 0
    assert [details["revision"] for action, details in cur.audits] == [2, 3]
    assert all("config" not in details and len(details["policy_sha256"]) == 64 for action, details in cur.audits)
    assert cur.history[(AGENT, 2)][1]["enabled"] is True
    assert cur.history[(AGENT, 3)][1]["enabled"] is False


@pytest.mark.parametrize("module", ["sli.vpn-nps", "sli.radius-accounting"])
def test_nps_assignments_share_revision_history_control_and_safe_audit(tmp_path, module):
    from tests.unit.test_sli_agent_nps import CONFIG, accounting_config

    cur = Cursor()
    existing = {"module_id": "sli.workstations", "enabled": True, "config": {}}
    cur.agent["assigned_modules"] = [existing]
    cur.agent["collection_policy"] = {"state": "paused"}
    config = CONFIG if module == "sli.vpn-nps" else accounting_config(tmp_path)
    body = {"agent_id": AGENT, "module_id": module, "enabled": True,
            "config": config, "expected_revision": 1}
    result = registry.assign_module(cur, body, actor="session:1")
    issued = result["assigned_modules"][1]
    assert result["assigned_modules"][0] == existing
    assert result["policy_revision"] == 2 and issued["config"]["policy_revision"] == "2"
    assert cur.history[(AGENT, 1)] == [existing]
    assert cur.history[(AGENT, 2)] == [existing, issued]
    checkin = policies.check_in(cur.agent)
    assert checkin["policy_revision"] == 2 and checkin["collection_policy"]["state"] == "paused"
    details = cur.audits[-1][1]
    assert details["families"] == issued["config"]["families"]
    assert details["revision"] == 2 and len(details["policy_sha256"]) == 64
    assert "fixture-endpoint" not in repr(cur.audits)
    assert str(tmp_path) not in repr(cur.audits)
    with pytest.raises(AgentError, match="agent_policy_revision_conflict"):
        registry.assign_module(cur, body, actor="session:1")
    assert cur.agent["policy_revision"] == 2 and len(cur.audits) == 1


def test_assignment_conflict_and_disabled_agent_do_not_write():
    cur = Cursor()
    with pytest.raises(AgentError, match="agent_policy_revision_conflict"):
        policies.assign_module(cur, assignment(expected_revision=0), actor="session:1")
    cur.agent["status"] = "disabled"
    with pytest.raises(AgentError, match="agent_disabled"):
        policies.assign_module(cur, assignment(), actor="session:1")
    assert all(not sql.startswith("update") for sql, _ in cur.calls)


@pytest.mark.parametrize("body", [assignment(enabled=1), assignment(module="arbitrary"),
    {**assignment(), "config": {"unknown": True}}, {**assignment(), "module_id": "arbitrary"}])
def test_invalid_assignments_do_not_mutate(body):
    cur = Cursor()
    with pytest.raises(AgentError):
        policies.assign_module(cur, body, actor="session:1")
    assert cur.agent["policy_revision"] == 1 and not cur.audits


def test_probe_pending_survives_checkin_and_is_idempotent_until_reported():
    cur = Cursor()
    first = policies.request_probe(cur, {"agent_id": AGENT}, actor="session:1")
    again = policies.request_probe(cur, {"agent_id": AGENT}, actor="session:1")
    assert first == again and len(cur.audits) == 1
    checkin = policies.check_in(cur.agent)
    assert checkin["rights_probe_request"] == first["rights_probe"]["pending"]
    assert "pending" in cur.agent["rights_probe"]
    report = {"applied_policy_revision": 1, "rights_probe": {
        "request_id": checkin["rights_probe_request"]["request_id"], "status": "denied"}}
    result = policies.report(cur, deepcopy(cur.agent), report)
    assert "pending" not in result["rights_probe"]
    assert result["rights_probe"]["last_result"]["status"] == "denied"
    assert result["rights_probe"]["last_result"]["policy_revision"] == 1
    assert result["rights_probe"]["last_result"]["reported_at"]
    policies.request_probe(cur, {"agent_id": AGENT}, actor="session:1")
    assert cur.agent["rights_probe"]["last_result"]["status"] == "denied"
    assert cur.agent["rights_probe"]["pending"] != first["rights_probe"]["pending"]


@pytest.mark.parametrize("revision", [True, -1, 2, "1"])
def test_invalid_ack_is_rejected(revision):
    cur = Cursor()
    with pytest.raises(AgentError, match="invalid_agent_policy_revision"):
        policies.report(cur, cur.agent, {"applied_policy_revision": revision})
    assert not cur.audits


def test_stale_ack_never_marks_current_revision_applied_or_regresses_ack():
    cur = Cursor()
    cur.agent.update(policy_revision=4, applied_policy_revision=2)
    assert policies.report(cur, deepcopy(cur.agent), {"applied_policy_revision": 1})["applied_policy_revision"] == 2
    assert cur.agent["policy_revision"] == 4
    assert not cur.audits


@pytest.mark.parametrize("result", [None, {"request_id": "old", "status": "allowed"},
    {"request_id": "request", "status": "arbitrary"},
    {"request_id": "request", "status": "allowed", "diagnostics": "private-fixture"}])
def test_probe_mismatch_and_untrusted_diagnostics_are_rejected(result):
    cur = Cursor()
    cur.agent["rights_probe"] = {"pending": {"request_id": "request"}}
    if result is None:
        cur.agent["rights_probe"] = {}
        result = {"request_id": "request", "status": "allowed"}
    with pytest.raises(AgentError, match="invalid_agent_probe_report"):
        policies.report(cur, cur.agent, {"applied_policy_revision": 1, "rights_probe": result})
    assert not cur.audits


def test_two_agents_have_independent_settings_and_revision_acknowledgements():
    first, second = Cursor(), Cursor()
    second.agent.update(id=HOST, host_id=AGENT)
    policies.assign_module(first, {**assignment(), "config": {"families": {"usb": False}}}, actor="session:1")
    policies.assign_module(second, {**assignment(), "agent_id": HOST,
                                   "config": {"families": {"processes": False}}}, actor="session:1")
    policies.update_control(first, {"agent_id": AGENT, "expected_revision": 2,
                                   "collection_policy": {"state": "paused", "interval_seconds": 120}}, actor="session:1")
    left, right = policies.check_in(first.agent), policies.check_in(second.agent)
    assert left["collection_policy"]["state"] == "paused"
    assert right["collection_policy"]["state"] == "active"
    assert left["assigned_modules"][0]["config"]["families"]["usb"] is False
    assert right["assigned_modules"][0]["config"]["families"]["usb"] is True
    assert right["assigned_modules"][0]["config"]["families"]["processes"] is False
    policies.report(first, deepcopy(first.agent), {"applied_policy_revision": 3, "collection_state": "paused"})
    assert first.agent["applied_policy_revision"] == 3
    assert second.agent["applied_policy_revision"] == 0 and second.agent["policy_revision"] == 2
    assert first.audits[-2][0] == "policy_update"
    assert first.audits[-2][1]["state"] == "paused"


@pytest.mark.parametrize("control", [{"state": "disabled"}, {"interval_seconds": True},
    {"batch_size": 129}, {"rate_limit_per_minute": 0}, {"spool_max_bytes": -1}, {"unknown": 1}])
def test_invalid_common_policy_does_not_write(control):
    cur = Cursor()
    with pytest.raises(AgentError, match="invalid_agent_collection_policy"):
        policies.update_control(cur, {"agent_id": AGENT, "expected_revision": 1,
                                     "collection_policy": control}, actor="session:1")
    assert not cur.audits and cur.agent["policy_revision"] == 1


def test_control_conflict_and_pause_resume_are_revisioned():
    cur = Cursor()
    body = {"agent_id": AGENT, "expected_revision": 1, "collection_policy": {"state": "paused"}}
    assert policies.update_control(cur, body, actor="session:1")["policy_revision"] == 2
    with pytest.raises(AgentError, match="agent_policy_revision_conflict"):
        policies.update_control(cur, body, actor="session:1")
    result = policies.update_control(cur, {**body, "expected_revision": 2,
                                          "collection_policy": {"state": "active"}}, actor="session:1")
    assert result["policy_revision"] == 3 and result["collection_policy"]["state"] == "active"


def test_dc_assignment_validates_pack_allowlist_and_reader_conflicts():
    cur = Cursor()
    body = {**assignment(), "module_id": "sli.windows.ad-dc", "config": {
        "source_name": "fixture-source", "connect_address": "fixture-endpoint",
        "channels": {"System": False}, "allow_event_ids": [4624]}}
    result = policies.assign_module(cur, body, actor="session:1")
    assert result["assigned_modules"][0]["config"]["channels"]["System"] is False
    assert result["assigned_modules"][0]["config"]["initial_read_hours"] == 24
    with pytest.raises(AgentError, match="invalid_agent_module_config"):
        policies.assign_module(cur, {**body, "config": {**body["config"], "allow_event_ids": [65535]}}, actor="session:1")
    with pytest.raises(AgentError, match="agent_channel_owner_conflict"):
        policies.assign_module(cur, assignment(), actor="session:1")


def test_dc_history_assignment_is_explicit_bound_and_audited():
    cur = Cursor()
    config = {"source_name": "fixture-source", "connect_address": "fixture-endpoint"}
    policies.assign_module(cur, {**assignment(), "module_id": "sli.windows.ad-dc", "config": config}, actor="session:1")
    body = {**assignment(), "module_id": "sli.windows.ad-dc-history", "config": {
        **config, "history_before_utc": "2026-10-10T00:00:00Z", "channels": {"System": False}}}
    result = policies.assign_module(cur, body, actor="session:1")
    issued = result["assigned_modules"][1]
    assert issued["config"]["initial_read_hours"] == "all" and issued["config"]["batch_size"] == 4
    assert cur.audits[-1][1]["module_id"] == "sli.windows.ad-dc-history"
    with pytest.raises(AgentError, match="invalid_agent_module_config"):
        policies.assign_module(cur, {**body, "config": config}, actor="session:1")


def test_stale_state_report_does_not_overwrite_current_state():
    cur = Cursor()
    cur.agent.update(policy_revision=4, applied_policy_revision=3, applied_collection_state="paused")
    policies.report(cur, deepcopy(cur.agent), {"applied_policy_revision": 2, "collection_state": "active"})
    assert cur.agent["applied_collection_state"] == "paused"


def test_legacy_agent_cannot_acknowledge_collection_control_it_did_not_apply():
    cur = Cursor()
    cur.agent["collection_policy"] = {"state": "paused"}
    with pytest.raises(AgentError, match="invalid_agent_collection_state"):
        policies.report(cur, cur.agent, {"applied_policy_revision": 1})
    assert not cur.audits


def test_shared_store_routes_changes_and_checkins_to_only_the_target_agent():
    class SharedCursor(Cursor):
        def __init__(self):
            super().__init__()
            self.rows = {AGENT: self.agent, HOST: {**deepcopy(self.agent), "id": HOST, "host_id": AGENT}}

        def execute(self, sql, params=()):
            if sql.startswith("select * from sli_agents") or sql.startswith("update sli_agents"):
                assert "where id=%s" in sql
                self.agent = self.rows[params[-1]]
            super().execute(sql, params)

    cur = SharedCursor()
    policies.assign_module(cur, {**assignment(), "config": {"families": {"usb": False}}}, actor="session:1")
    policies.assign_module(cur, {**assignment(), "agent_id": HOST, "config": {"families": {"logons": False}}}, actor="session:1")
    other_before = deepcopy(cur.rows[HOST])
    policies.update_control(cur, {"agent_id": AGENT, "expected_revision": 2,
                                 "collection_policy": {"state": "paused", "interval_seconds": 120}}, actor="session:1")
    first = policies.check_in(cur.rows[AGENT])
    second = policies.check_in(cur.rows[HOST])
    assert first["collection_policy"]["interval_seconds"] == 120
    assert second["collection_policy"]["interval_seconds"] == 60
    assert first["assigned_modules"] != second["assigned_modules"]
    assert cur.rows[HOST] == other_before
    assert (AGENT, 3) in cur.history and (HOST, 3) not in cur.history


@pytest.mark.parametrize("state", ["active", "unknown", None, True])
def test_pause_ack_requires_applied_paused_state(state):
    cur = Cursor()
    cur.agent["collection_policy"] = {"state": "paused"}
    with pytest.raises(AgentError, match="invalid_agent_collection_state"):
        policies.report(cur, cur.agent, {"applied_policy_revision": 1, "collection_state": state})
    assert not cur.audits


def test_policy_must_fit_the_agents_bounded_checkin_response():
    cur = Cursor()
    paths = ["*/" + "x" * 500 for _ in range(64)]
    with pytest.raises(AgentError, match="agent_policy_size_limit"):
        policies.assign_module(cur, {**assignment(), "config": {
            "allow_process_paths": paths, "deny_process_paths": paths}}, actor="session:1")
    assert cur.agent["policy_revision"] == 1 and not cur.audits and not cur.history


def test_missing_ad_policy_hook_rejects_assignment_without_writes(monkeypatch):
    cur = Cursor()
    real_hook = policies.plugin_hook
    monkeypatch.setattr(policies, "plugin_hook", lambda owner, name: None if owner == "sli.ad" else real_hook(owner, name))
    with pytest.raises(AgentError, match="invalid_agent_module_assignment"):
        policies.assign_module(cur, {**assignment(), "module_id": "sli.windows.ad-dc", "config": {
            "source_name": "fixture-dc", "connect_address": "fixture-endpoint"}}, actor="session:1")
    assert not cur.calls and not cur.history and not cur.audits
    assert cur.agent["policy_revision"] == 1


def test_password_domain_metadata_uses_separate_sql_wire_and_authenticated_actor():
    class MetadataCursor:
        def __init__(self):
            self.calls = []

        def execute(self, sql, params):
            self.calls.append((sql, params))

        def fetchone(self):
            return {"metadata": {"status": "configured", "domain_id": 7, "domain_fqdn": "fixture.invalid"}}

    cur = MetadataCursor()
    body = {"agent_id": AGENT, "module_id": "sli.windows.ad-dc", "expected_revision": 9,
            "password_detection_domain": {"fqdn": "Fixture.Invalid", "expected_domain_id": None}}
    before = deepcopy(body)
    result = policies.assign_module(cur, body, actor="session:42")
    assert result == {"agent_id": AGENT, "policy_revision": 9,
                      "password_detection_domain": {"status": "configured", "domain_id": 7, "domain_fqdn": "fixture.invalid"}}
    assert body == before
    assert len(cur.calls) == 1
    assert cur.calls[0][0].startswith("select public.provision_password_detection_domain_v2(")
    assert cur.calls[0][1] == (AGENT, 9, None, "fixture.invalid", "session:42")


@pytest.mark.parametrize("mutation", ["config", "enabled", "actor", "revision_bool", "missing_cas", "domain_bool", "extra_metadata"])
def test_password_domain_metadata_strict_shape_rejects_before_sql(mutation):
    body = {"agent_id": AGENT, "module_id": "sli.windows.ad-dc", "expected_revision": 9,
            "password_detection_domain": {"fqdn": "fixture.invalid", "expected_domain_id": None}}
    if mutation in {"config", "enabled", "actor"}:
        body[mutation] = {} if mutation == "config" else True
    elif mutation == "revision_bool":
        body["expected_revision"] = True
    elif mutation == "missing_cas":
        del body["password_detection_domain"]["expected_domain_id"]
    elif mutation == "domain_bool":
        body["password_detection_domain"]["expected_domain_id"] = True
    else:
        body["password_detection_domain"]["source_name"] = "forged"
    cur = Cursor()
    with pytest.raises(AgentError, match="invalid_password_domain_metadata"):
        policies.assign_module(cur, body, actor="session:42")
    assert cur.calls == [] and cur.audits == [] and cur.history == {}
