"""Local policy application and access checks with transport/native fakes."""
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from sli_agent.policies import apply_policy, probe_access

AGENT = "00000000-0000-4000-8000-000000000001"
HOST = "00000000-0000-4000-8000-000000000002"


@pytest.mark.parametrize("enabled", [True, False])
def test_apply_reports_revision_after_configuration_and_fresh_probe(enabled):
    transport = Mock()
    identity = SimpleNamespace(agent_id=AGENT)
    assignment = {"agent_id": AGENT, "policy_revision": 3, "assigned_modules": [
        {"module_id": "sli.workstations", "enabled": enabled, "config": {"policy_revision": "3"}}],
        "rights_probe_request": {"request_id": "synthetic-request"}}
    probe = Mock(return_value="denied")
    config = SimpleNamespace(collection_enabled=False)
    modules = apply_policy(config, HOST, assignment, transport, identity, probe=probe)
    assert [module.module_id for module in modules] == ["sli.heartbeat"] + (["sli.workstations"] if enabled else [])
    probe.assert_called_once_with(config, assignment["assigned_modules"])
    transport.post.assert_called_once_with("/api/v1/agent/policy-report", {
        "applied_policy_revision": 3, "rights_probe": {"request_id": "synthetic-request", "status": "denied"}}, identity=identity)


@pytest.mark.parametrize("change", [{"agent_id": HOST}, {"policy_revision": True},
    {"policy_revision": 0}, {"assigned_modules": [{"module_id": "sli.workstations", "enabled": True, "config": {"unknown": 1}}]}])
def test_configuration_failure_never_acknowledges(change):
    transport = Mock()
    assignment = {"agent_id": AGENT, "policy_revision": 1, "assigned_modules": [], **change}
    with pytest.raises(ValueError):
        apply_policy(SimpleNamespace(collection_enabled=False), HOST, assignment, transport, SimpleNamespace(agent_id=AGENT))
    transport.post.assert_not_called()


def test_no_pending_probe_does_not_perform_a_probe():
    transport, probe = Mock(), Mock()
    apply_policy(SimpleNamespace(collection_enabled=False), HOST,
                 {"agent_id": AGENT, "policy_revision": 1, "assigned_modules": []},
                 transport, SimpleNamespace(agent_id=AGENT), probe=probe)
    probe.assert_not_called()
    assert transport.post.call_args.args[1] == {"applied_policy_revision": 1}


@pytest.mark.parametrize("verified,ready,checks,status", [
    (True, True, [], "allowed"), (False, True, [], "unavailable"),
    (True, False, [{"required": True, "status": "denied"}], "denied"),
    (True, False, [{"required": True, "status": "not_present"}], "unavailable"),
    (True, False, [{"required": False, "status": "denied"}], "unavailable"),
])
def test_l03_probe_uses_live_assignments_and_service_identity(verified, ready, checks, status):
    config, assignments = object(), [{"module_id": "sli.workstations", "enabled": True}]
    runner = Mock(return_value={"contract": "sli.agent-rights-probe.v1", "identity_verified": verified,
                                "ready": ready, "checks": checks, "private": "private-fixture-diagnostic"})
    assert probe_access(config, assignments, runner=runner) == status
    runner.assert_called_once_with(config, assigned_modules=assignments, planned=False)


@pytest.mark.parametrize("error", [ModuleNotFoundError("sli_agent.probe"), RuntimeError("private-fixture-diagnostic")])
def test_missing_dependency_and_probe_errors_are_unavailable(error):
    assert probe_access(object(), [], runner=Mock(side_effect=error)) == "unavailable"


def test_pause_returns_no_source_readers_and_reports_applied_state():
    transport = Mock()
    config = SimpleNamespace(collection_enabled=False)
    assignment = {"agent_id": AGENT, "policy_revision": 2, "assigned_modules": [
        {"module_id": "sli.workstations", "enabled": True, "config": {}}],
        "collection_policy": {"state": "paused"}}
    modules = apply_policy(config, HOST, assignment, transport, SimpleNamespace(agent_id=AGENT))
    assert [module.module_id for module in modules] == ["sli.heartbeat"]
    assert transport.post.call_args.args[1] == {"applied_policy_revision": 2, "collection_state": "paused"}


def test_common_batch_limit_is_applied_before_acknowledgement():
    transport = Mock()
    assignment = {"agent_id": AGENT, "policy_revision": 2, "assigned_modules": [
        {"module_id": "sli.workstations", "enabled": True, "config": {"batch_size": 64}}],
        "collection_policy": {"batch_size": 8}}
    modules = apply_policy(SimpleNamespace(collection_enabled=False), HOST, assignment, transport, SimpleNamespace(agent_id=AGENT))
    assert modules[1].policy["batch_size"] == 8
    assert transport.post.call_args.args[1] == {"applied_policy_revision": 2, "collection_state": "active"}


@pytest.mark.parametrize("control", [{"state": "unknown"}, {"interval_seconds": False}, {"batch_size": 129},
                                    {"spool_max_bytes": 0}, {"rate_limit_per_minute": 0}])
def test_invalid_common_policy_is_never_acknowledged(control):
    transport = Mock()
    assignment = {"agent_id": AGENT, "policy_revision": 2, "assigned_modules": [], "collection_policy": control}
    with pytest.raises(ValueError, match="agent_collection_policy_invalid"):
        apply_policy(SimpleNamespace(collection_enabled=False), HOST, assignment, transport, SimpleNamespace(agent_id=AGENT))
    transport.post.assert_not_called()
