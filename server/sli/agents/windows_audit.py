"""Bounded, privacy-preserving audit heartbeat contract, shared GUID catalog."""
import json

from server.sli.agents.ca import AgentError, utcnow
from sli_agent.windows_audit import FAMILY_SUBCATEGORIES, family_report, required_families


def report(cur, agent, body):
    # The route supplies the locked, authenticated mTLS agent row.
    if not isinstance(body, dict) or set(body) != {"windows_audit"} or not isinstance(body["windows_audit"], dict):
        raise AgentError("invalid_agent_windows_audit_report")
    revision = body["windows_audit"].get("policy_revision")
    if type(revision) is not int or not 1 <= revision <= agent["policy_revision"]:
        raise AgentError("invalid_agent_windows_audit_report")
    observation = validate_report(body["windows_audit"], agent, revision)
    state = agent.get("windows_audit", {})
    if revision >= state.get("policy_revision", 0):
        state = observation
        cur.execute("update sli_agents set windows_audit=%s::jsonb where id=%s",
                    (json.dumps(state), str(agent["id"])))
    return {"windows_audit": state}


def validate_report(value, agent, revision):
    def invalid():
        raise AgentError("invalid_agent_windows_audit_report")

    if (not isinstance(value, dict) or set(value) - {"powershell_logging"} != {
            "policy_revision", "management_state", "command_line_enabled", "families"}
            or type(value["policy_revision"]) is not int or value["policy_revision"] != revision
            or not isinstance(value["management_state"], str)
            or value["management_state"] not in ("disabled", "applied", "restored", "blocked", "unknown")
            or value["command_line_enabled"] is not None and type(value["command_line_enabled"]) is not bool
            or not isinstance(value["families"], dict) or set(value["families"]) - set(FAMILY_SUBCATEGORIES)):
        invalid()
    if "powershell_logging" in value:
        ps = value["powershell_logging"]
        if (not isinstance(ps, dict) or set(ps) != {"channel_enabled", "script_block_logging_enabled"}
                or any(v is not None and type(v) is not bool for v in ps.values())
                or "protection" not in value["families"]):
            invalid()
    expected = required_families([{"module_id": "sli.workstations", "enabled": True, "config": {}}])
    current = required_families(agent["assigned_modules"])
    if revision == agent["policy_revision"] and set(current) != set(value["families"]):
        invalid()
    families = {}
    for family, result in value["families"].items():
        if (not isinstance(result, dict) or set(result) != {"state", "required", "non_security_channels"}
                or not isinstance(result["state"], str) or result["state"] not in ("ok", "missing", "managed_by_gpo", "unknown")
                or not isinstance(result["required"], list) or len(result["required"]) != len(expected[family])):
            invalid()
        actual = {}
        for spec, row in zip(expected[family], result["required"], strict=True):
            if (not isinstance(row, dict) or set(row) != set(spec) | {"actual_success", "actual_failure"}
                    or any(row[key] != spec[key] or type(row[key]) is not type(spec[key]) for key in spec)
                    or any(row[key] is not None and type(row[key]) is not bool for key in ("actual_success", "actual_failure"))
                    or (row["actual_success"] is None) != (row["actual_failure"] is None)):
                invalid()
            if row["actual_success"] is not None:
                actual[spec["guid"]] = int(row["actual_success"]) | (int(row["actual_failure"]) << 1)
        normalized = family_report({family: expected[family]}, actual,
            result["state"] if result["state"] in ("unknown", "managed_by_gpo") else "ok")[family]
        if result != normalized:
            invalid()
        families[family] = normalized
    if value["management_state"] == "applied" and (
            any(result["state"] != "ok" for result in families.values())
            or revision == agent["policy_revision"] and (
                not agent.get("collection_policy", {}).get("manage_windows_audit", False)
                or agent.get("collection_policy", {}).get("audit_process_command_line", False)
                and "processes" in families and value["command_line_enabled"] is not True)):
        invalid()
    return {**value, "families": families, "reported_at": utcnow().isoformat()}
