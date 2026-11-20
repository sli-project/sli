"""The owner-issued workstation opt-in; payload names never assign authority."""
from copy import deepcopy

from server.sli.agents.ca import AgentError
from server.sli.plugins.registry import plugin_hook
from sli_agent.workstations import WorkstationsModule

MODULE = "sli.workstations"
NPS_MODULES = ("sli.vpn-nps", "sli.radius-accounting")


def workstation_assignment(assignments):
    if not isinstance(assignments, list):
        return None
    matches = [item for item in assignments if isinstance(item, dict) and item.get("module_id") == MODULE]
    if len(matches) != 1 or matches[0].get("enabled") is not True:
        return None
    return deepcopy(matches[0])


def validate_assignment(body, host_id):
    nps_policy = plugin_hook("sli.remote-access", "nps_agent_policy") if (
        isinstance(body, dict) and body.get("module_id") in NPS_MODULES) else None
    if (not isinstance(body, dict) or set(body) - {"agent_id", "module_id", "enabled", "config"}
            or body.get("module_id") not in (MODULE, *NPS_MODULES) or type(body.get("enabled")) is not bool
            or body.get("module_id") in NPS_MODULES and nps_policy is None
            or not isinstance(body.get("config", {}), dict)):
        raise AgentError("invalid_agent_module_assignment")
    try:
        policy = (WorkstationsModule(host_id, body.get("config", {})).policy if body["module_id"] == MODULE
                  else nps_policy(body["module_id"], body.get("config", {})))
    except ValueError:
        raise AgentError("invalid_agent_module_config") from None
    return {"module_id": body["module_id"], "enabled": body["enabled"], "config": policy}
