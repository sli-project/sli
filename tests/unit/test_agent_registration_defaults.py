"""Fresh agents receive a runnable policy without an administrator assignment."""
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from server.sli.agents import policies, registry
from server.sli.agents.ca import AgentError
from sli_agent.modules import configured_modules
from tests.unit.test_agent_registry import lifecycle as lifecycle  # noqa: PLC0414
from tests.unit.test_agent_registry import request


@pytest.mark.parametrize("role,module", [
    (None, "sli.workstations"),
    ("workstation", "sli.workstations"),
    ("domain_controller", "sli.windows.ad-dc"),
])
def test_registration_assigns_role_policy_returned_by_next_check_in(lifecycle, role, module):
    cur, authority, key, token = lifecycle
    body = {"token": token["token"], "csr_pem": request(key), "reported_hostname": "pc.example.invalid"}
    if role is not None:
        body["machine_role"] = role
    result = registry.enroll(cur, authority, body)
    der = x509.load_pem_x509_certificate(result["certificate_pem"].encode()).public_bytes(serialization.Encoding.DER)
    agent = registry.authenticate(cur, authority, der)
    wire = policies.check_in(agent)
    assert len(wire["assigned_modules"]) == 1
    assignment = wire["assigned_modules"][0]
    assert assignment["module_id"] == module and assignment["enabled"] is True
    assert wire["collection_policy"]["state"] == "active"
    assert wire["collection_policy"]["manage_windows_audit"] is True
    assert wire["collection_policy"]["audit_process_command_line"] is False
    assert str(wire["policy_revision"]) == assignment["config"]["policy_revision"]
    modules = configured_modules(SimpleNamespace(collection_enabled=False), str(agent["host_id"]), wire["assigned_modules"])
    assert module in [item.module_id for item in modules]
    if role == "domain_controller":
        assert assignment["config"]["channels"] == {"Security": True, "System": True, "Directory Service": True}
    else:
        assert assignment["config"]["families"]["processes"] is True
        assert assignment["config"]["families"]["logons"] is True
        workstation = next(item for item in modules if item.module_id == "sli.workstations")
        assert {"Security", "System"}.issubset(workstation.enabled_channels())


@pytest.mark.parametrize("role", [None, True, [], "unknown"])
def test_invalid_explicit_role_does_not_consume_token(lifecycle, role):
    cur, authority, key, token = lifecycle
    with pytest.raises(AgentError, match="invalid_agent_module_config"):
        registry.enroll(cur, authority, {"token": token["token"], "csr_pem": request(key), "machine_role": role})
    assert not cur.agents and not cur.certificates
    assert cur.tokens[token["id"]]["used_at"] is None


def test_explicit_paused_empty_template_is_not_replaced_by_role_defaults(lifecycle):
    cur, authority, key, token = lifecycle
    cur.policy_templates[token["id"]] = {
        "id": "00000000-0000-4000-8000-000000000002", "version": 1, "policy_sha256": "a" * 64,
        "assigned_modules": [], "collection_policy": {"state": "paused", "manage_windows_audit": False},
    }
    result = registry.enroll(cur, authority, {"token": token["token"], "csr_pem": request(key),
                                           "machine_role": "domain_controller"})
    wire = policies.check_in(cur.agents[result["agent_id"]])
    assert wire["assigned_modules"] == []
    assert wire["collection_policy"]["state"] == "paused"
    assert not wire["collection_policy"].get("manage_windows_audit", False)
    assert wire["policy_revision"] == 1
