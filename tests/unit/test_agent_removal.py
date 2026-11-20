"""Removal lifecycle with real certificates and in-memory transaction fakes."""
from copy import deepcopy
from datetime import timedelta
from uuid import uuid4

import pytest

from server.sli.agents import registry, removal
from server.sli.agents.ca import AgentError, utcnow
from tests.unit.test_agent_registry import Cursor as RegistryCursor  # noqa: F401
from tests.unit.test_agent_registry import enroll, lifecycle

OPERATION = "00000000-0000-4000-8000-000000000099"


class Cursor(RegistryCursor):
    def __init__(self):
        super().__init__()
        self.removals = {}

    def execute(self, sql, params=()):
        if sql.startswith("select id,host_id,key_fingerprint,status") or ("sli_agent_removals" not in sql and not sql.startswith("select id from sli_agents where id=any")):
            return super().execute(sql, params)
        self.calls.append((sql, params))
        self.rows = []
        if sql.startswith("select id from sli_agents where id=any"):
            self.rows = [dict(id=agent_id) for agent_id in params[0] if agent_id in self.agents]
        elif sql.startswith("select agent_id"):
            self.rows = [row for row in self.removals.values() if
                         (row["agent_id"] in params[0] if "any(" in sql else row["operation_id"] == params[0])]
        elif sql.startswith("insert into sli_agent_removals"):
            agent, operation, command = params
            self.removals[agent] = dict(agent_id=agent, operation_id=operation, command_id=command,
                                       state="pending", reason=None, requested_at=utcnow(), reported_at=None)
        elif sql.startswith("select command_id") or sql.startswith("select operation_id"):
            self.rows = [self.removals[params[0]]] if params[0] in self.removals else []
        elif sql.startswith("update sli_agent_removals"):
            state, reason, agent = params
            self.removals[agent].update(state=state, reason=reason, reported_at=utcnow())
        else:
            raise AssertionError(sql)


def removal_lifecycle(lifecycle):
    old, ca, key, token = lifecycle
    cur = Cursor()
    cur.tokens = deepcopy(old.tokens)
    result, der = enroll((cur, ca, key, token))
    return cur, ca, result, der


def test_100_agents_one_operation_revokes_all_and_retains_history():
    cur = Cursor()
    ids = [str(uuid4()) for _ in range(100)]
    for i, agent in enumerate(ids):
        cur.agents[agent] = dict(id=agent, status="active", assigned_modules=["fixture-module"])
        cur.certificates[str(i)] = dict(agent_id=agent, serial=str(i), revoked_at=None)
    result = removal.request(cur, {"operation_id": OPERATION, "agent_ids": ids}, actor="session:1")
    assert len(result["items"]) == len(cur.removals) == 100
    assert all(a["status"] == "disabled" for a in cur.agents.values())
    assert all(c["revoked_at"] for c in cur.certificates.values())
    assert len(cur.agents) == 100
    assert all(a["assigned_modules"] == ["fixture-module"] for a in cur.agents.values())
    assert len([a for a in cur.audits if a["action"] == "removal_request"]) == 100
    assert not any("delete " in sql.lower() for sql, _ in cur.calls)
    with pytest.raises(AgentError, match="agent_removal_replay"):
        removal.request(cur, {"operation_id": OPERATION, "agent_ids": ids}, actor="session:1")
    with pytest.raises(AgentError, match="agent_removal_replay"):
        removal.request(cur, {"operation_id": str(uuid4()), "agent_ids": ids}, actor="session:1")


def test_revoked_certificate_can_only_receive_own_pending_removal(lifecycle):
    cur, ca, initial, der = removal_lifecycle(lifecycle)
    agent_id = initial["agent_id"]
    removal.request(cur, {"operation_id": OPERATION, "agent_ids": [agent_id]}, actor="session:1")
    assert registry.list_agents(cur, actor="session:1")["items"] == []
    assert registry.list_agents(cur, actor="session:1", agent_id=agent_id)["items"][0]["inventory_hidden_reason"] == "administrator_removed"
    with pytest.raises(AgentError, match="agent_certificate_rejected"):
        registry.authenticate(cur, ca, der)
    with pytest.raises(AgentError, match="agent_certificate_rejected"):
        registry.renew(cur, ca, der, {})
    agent = registry.authenticate(cur, ca, der, removal_only=True)
    offered = removal.command(cur, agent)
    assert set(offered) == {"agent_id", "agent_removal"}
    command = offered["agent_removal"]["command_id"]
    with pytest.raises(AgentError, match="agent_removal_replay"):
        removal.report(cur, agent, {"command_id": str(uuid4()), "state": "state_cleaned", "reason": None})
    removal.report(cur, agent, {"command_id": command, "state": "cleanup_failed", "reason": "agent_removal_requires_admin"})
    assert removal.command(cur, agent) == offered
    removal.report(cur, agent, {"command_id": command, "state": "state_cleaned", "reason": None})
    with pytest.raises(AgentError, match="agent_removal_replay"):
        removal.report(cur, agent, {"command_id": command, "state": "state_cleaned", "reason": None})
    with pytest.raises(AgentError, match="agent_certificate_rejected"):
        registry.authenticate(cur, ca, der, removal_only=True)
    assert cur.agents[agent_id]["status"] == "disabled"
    assert initial["serial"] in cur.certificates


def test_plain_disabled_and_unregistered_certificates_get_no_removal_channel(lifecycle):
    cur, ca, initial, der = removal_lifecycle(lifecycle)
    registry.revoke(cur, {"agent_id": initial["agent_id"]}, actor="session:1", disable=True)
    with pytest.raises(AgentError, match="agent_certificate_rejected"):
        registry.authenticate(cur, ca, der, removal_only=True)
    removal.request(cur, {"operation_id": OPERATION, "agent_ids": [initial["agent_id"]]}, actor="session:1")
    with pytest.raises(AgentError, match="agent_certificate_rejected"):
        registry.authenticate(cur, ca, der, removal_only=True)
    cur.certificates.clear()
    with pytest.raises(AgentError, match="agent_certificate_rejected"):
        registry.authenticate(cur, ca, der, removal_only=True)


@pytest.mark.parametrize("alter", ["expired", "fingerprint"])
def test_removal_channel_keeps_certificate_validity_and_exact_fingerprint(lifecycle, alter):
    cur, ca, initial, der = removal_lifecycle(lifecycle)
    removal.request(cur, {"operation_id": OPERATION, "agent_ids": [initial["agent_id"]]}, actor="session:1")
    cert = cur.certificates[initial["serial"]]
    if alter == "expired":
        cert["not_after"] = utcnow() - timedelta(seconds=1)
    else:
        cert["fingerprint"] = "0" * 64
    with pytest.raises(AgentError, match="agent_certificate_rejected"):
        registry.authenticate(cur, ca, der, removal_only=True)


def test_local_uninstall_uses_same_command_and_offline_remainder_is_visible(lifecycle):
    cur, ca, initial, der = removal_lifecycle(lifecycle)
    agent = registry.authenticate(cur, ca, der)
    offered = removal.local_uninstall(cur, agent)
    assert removal.local_uninstall(cur, agent) == offered
    row = cur.agents[initial["agent_id"]]
    for seen, expected in ((None, "never_seen"), (utcnow() - timedelta(days=2), "offline"), (utcnow(), "online")):
        row["last_seen"] = seen
        visible = removal.visibility(cur, row)
        assert visible["connection"] == expected and visible["state"] == "pending"


@pytest.mark.parametrize("ids", [[], [str(uuid4())] * 2, [str(uuid4()) for _ in range(101)], "all", ["invalid"]])
def test_invalid_selection_has_no_effect(ids):
    cur = Cursor()
    with pytest.raises(AgentError):
        removal.request(cur, {"operation_id": OPERATION, "agent_ids": ids}, actor="session:1")
    assert not cur.removals and not cur.calls


def test_unknown_selection_is_rejected_before_any_revocation():
    cur = Cursor()
    known, unknown = str(uuid4()), str(uuid4())
    cur.agents[known] = dict(id=known, status="active")
    with pytest.raises(AgentError, match="agent_not_found"):
        removal.request(cur, {"operation_id": OPERATION, "agent_ids": [known, unknown]}, actor="session:1")
    assert not cur.removals and cur.agents[known]["status"] == "active"
