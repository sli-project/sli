"""Explicit, audited same-machine replacement; the database owns the atomic fence."""
from server.sli.agents.ca import AgentError, uuid_text


def source_host(agent):
    host = agent.get("source_host_id") or agent.get("host_id")
    if not host:
        raise AgentError("agent_identity_unavailable", 409)
    return str(host)


def source_agent(agent):
    return str(agent.get("source_agent_id") or agent["id"])


def replace(cur, body, *, actor, access):
    if access.get("platform_owner") is not True and "access.manage" not in access.get("capabilities", []):
        raise AgentError("agent_replacement_denied", 403)
    if (not isinstance(body, dict) or set(body) != {"old_agent_id", "new_agent_id", "phase", "confirm"}
            or body["confirm"] is not True or body["phase"] not in ("prepare", "complete")):
        raise AgentError("agent_replacement_invalid")
    old, new = uuid_text(body["old_agent_id"]), uuid_text(body["new_agent_id"])
    if old == new:
        raise AgentError("agent_replacement_invalid")
    try:
        cur.execute("select public.replace_agent_runtime_v296(%s,%s,%s,%s) as result",
                    (old, new, body["phase"], actor))
        return cur.fetchone()["result"]
    except Exception as exc:
        # Never surface SQL values, source names, paths or server diagnostics.
        if getattr(exc, "sqlstate", None) == "55000":
            code = getattr(getattr(exc, "diag", None), "message_primary", "")
            if code in {"agent_replacement_not_ready", "agent_replacement_hostname_mismatch",
                        "agent_replacement_token_mismatch",
                        "agent_replacement_target_used", "agent_replacement_conflict",
                        "agent_replacement_pending_import", "agent_replacement_policy_changed",
                        "agent_replacement_module_unsupported", "agent_replacement_policy_size",
                        "agent_replacement_client_unsupported"}:
                raise AgentError(code, 409) from None
        raise
