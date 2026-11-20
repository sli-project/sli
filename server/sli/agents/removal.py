"""Explicit bounded removal; registry, policy and collected history are retained."""
from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

from server.sli.agents import registry
from server.sli.agents.ca import AgentError, utcnow, uuid_text

REASONS = {"agent_removal_requires_admin", "agent_removal_unmanaged", "agent_removal_cleanup_failed"}


def request(cur, body, *, actor):
    if not isinstance(body, dict) or set(body) != {"operation_id", "agent_ids"}:
        raise AgentError("agent_removal_invalid")
    operation = uuid_text(body["operation_id"])
    values = body["agent_ids"]
    if not isinstance(values, list) or not 1 <= len(values) <= 100:
        raise AgentError("agent_removal_invalid")
    ids = sorted(uuid_text(value) for value in values)
    if len(set(ids)) != len(ids):
        raise AgentError("agent_removal_invalid")
    # Serialize operation IDs even when two requests target disjoint agents.
    cur.execute("select pg_advisory_xact_lock(hashtext(%s))", ("agent-removal:" + operation,))
    cur.execute("select agent_id from sli_agent_removals where operation_id=%s", (operation,))
    if cur.fetchone():
        raise AgentError("agent_removal_replay", 409)
    # Lock the whole selection before any mutation; the caller rolls back on error.
    cur.execute("select id from sli_agents where id=any(%s::uuid[]) order by id for update", (ids,))
    if {str(row["id"]) for row in cur.fetchall()} != set(ids):
        raise AgentError("agent_not_found", 404)
    cur.execute("select agent_id from sli_agent_removals where agent_id=any(%s::uuid[])", (ids,))
    if cur.fetchone():
        raise AgentError("agent_removal_replay", 409)
    items = []
    for agent_id in ids:
        command_id = str(uuid4())
        cur.execute("insert into sli_agent_removals(agent_id,operation_id,command_id) values(%s,%s,%s)",
                    (agent_id, operation, command_id))
        registry.revoke(cur, {"agent_id": agent_id}, actor=actor, disable=True)
        registry.audit(cur, "removal_request", actor, agent_id, operation_id=operation, command_id=command_id)
        items.append({"agent_id": agent_id, "command_id": command_id, "state": "pending"})
    return {"operation_id": operation, "items": items}


def pending(cur, agent_id):
    cur.execute("select command_id,state,requested_at from sli_agent_removals where agent_id=%s for update", (str(agent_id),))
    row = cur.fetchone()
    return row if row and row["state"] != "state_cleaned" else None


def command(cur, agent):
    row = pending(cur, agent["id"])
    if not row:
        raise AgentError("agent_certificate_rejected", 401)
    return {"agent_id": str(agent["id"]), "agent_removal": {"command_id": str(row["command_id"]), "action": "uninstall"}}


def local_uninstall(cur, agent):
    if not pending(cur, agent["id"]):
        request(cur, {"operation_id": str(uuid4()), "agent_ids": [str(agent["id"])]},
                actor="agent:" + str(agent["id"]))
    return command(cur, agent)


def report(cur, agent, body):
    if not isinstance(body, dict) or set(body) != {"command_id", "state", "reason"}:
        raise AgentError("agent_removal_result_invalid")
    command_id = uuid_text(body["command_id"])
    state, reason = body["state"], body["reason"]
    if (state not in ("state_cleaned", "cleanup_failed") or
            (state == "state_cleaned" and reason is not None) or
            (state == "cleanup_failed" and (not isinstance(reason, str) or reason not in REASONS))):
        raise AgentError("agent_removal_result_invalid")
    row = pending(cur, agent["id"])
    if not row or str(row["command_id"]) != command_id:
        raise AgentError("agent_removal_replay", 409)
    cur.execute("update sli_agent_removals set state=%s,reason=%s,reported_at=clock_timestamp() where agent_id=%s",
                (state, reason, str(agent["id"])))
    registry.audit(cur, "removal_result", "agent:" + str(agent["id"]), str(agent["id"]),
                   command_id=command_id, state=state, reason=reason)
    return {"state": state}


def visibility(cur, agent):
    cur.execute("select operation_id,command_id,state,reason,requested_at,reported_at from sli_agent_removals where agent_id=%s",
                (str(agent["id"]),))
    row = cur.fetchone()
    if not row:
        return None
    seen = agent["last_seen"]
    return {**dict(row), "connection": "never_seen" if seen is None else
            "offline" if seen < utcnow() - timedelta(minutes=5) else "online"}
