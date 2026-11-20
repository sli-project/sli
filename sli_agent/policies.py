# SPDX-License-Identifier: Apache-2.0
"""Apply server assignments and report safe, bounded local access probes."""
from sli_agent.control import collection_policy
from sli_agent.modules import configured_modules


def spool_limit(config, modules, control):
    """The shared spool pauses at the strictest active source budget."""
    maximum = control["spool_max_bytes"] if control is not None else config.spool_max_bytes
    return min([maximum, *(module.policy["spool_bytes"] for module in modules
                           if module.module_id == "sli.file-audit")])


class AppliedPolicy(list):
    """Configured collectors and the acknowledgement for this exact revision."""

    def __init__(self, modules, control, report, windows_audit=None, file_audit=None):
        super().__init__(modules)
        self.control = control
        self.report = report
        self.windows_audit = windows_audit
        self.file_audit = file_audit


def acknowledge_policy(modules, transport, identity, *, state="active", diagnostics=None):
    if modules.report is not None:
        body = dict(modules.report)
        if modules.control is not None:
            body["collection_state"] = state
        if getattr(modules, "diagnostics_supported", False) and diagnostics is not None:
            from sli_collect.eventlog_diagnostics import validate_observations
            body["eventlog_diagnostics"] = validate_observations(diagnostics)
        transport.post("/api/v1/agent/policy-report", body, identity=identity)


def probe_access(config, assignments, *, runner=None):
    try:
        if runner is None:
            # L03 owns native reads and service-identity verification. An agent
            # without that dependency must never claim that access is proven.
            from sli_agent.probe import probe as runner
        result = runner(config, assigned_modules=assignments, planned=False)
        if result.get("contract") != "sli.agent-rights-probe.v1" or result.get("identity_verified") is not True:
            return "unavailable"
        if result.get("ready") is True:
            return "allowed"
        if any(check.get("required") is True and check.get("status") == "denied" for check in result["checks"]):
            return "denied"
    except Exception:
        # Return enums only; diagnostics and report labels stay on the agent.
        pass
    return "unavailable"


def apply_policy(config, host_id, assignment, transport, identity, *, probe=probe_access, defer_ack=False,
                 audit_manager=None, file_audit_manager=None):
    if assignment.get("agent_id") != identity.agent_id:
        raise ValueError("agent_module_identity_mismatch")
    modules = configured_modules(config, host_id, assignment["assigned_modules"])
    control = collection_policy(assignment["collection_policy"]) if "collection_policy" in assignment else None
    if control is not None:
        for module in modules:
            settings = getattr(module, "policy", getattr(module, "config", None))
            if isinstance(settings, dict) and "batch_size" in settings:
                settings["batch_size"] = min(settings["batch_size"], control["batch_size"])
        if control["state"] != "active":
            modules = [module for module in modules if module.module_id == "sli.heartbeat"]
    revision = assignment.get("policy_revision")
    if revision is None:
        # Compatible with pre-revision servers during the dependency rollout.
        if control is not None:
            raise ValueError("agent_policy_revision_invalid")
        return AppliedPolicy(modules, None, None)
    if type(revision) is not int or not 1 <= revision <= 9007199254740991:
        raise ValueError("agent_policy_revision_invalid")
    body = {"applied_policy_revision": revision}
    windows_audit = None
    file_audit = None
    if file_audit_manager is not None:
        windows_audit, file_audit = file_audit_manager.reconcile(assignment["assigned_modules"],
            control or collection_policy({}), revision, assignment.get("file_audit"))
    elif assignment.get("file_audit") is not None:
        raise ValueError("agent_file_audit_executor_unavailable")
    elif audit_manager is not None:
        windows_audit = audit_manager.reconcile(assignment["assigned_modules"],
            control or collection_policy({}), revision)
    request = assignment.get("rights_probe_request")
    if request:
        body["rights_probe"] = {"request_id": request["request_id"], "status": probe(config, assignment["assigned_modules"])}
    applied = AppliedPolicy(modules, control, body, windows_audit, file_audit)
    applied.diagnostics_supported = assignment.get("eventlog_diagnostics_supported") is True
    if not defer_ack:
        if control is not None and control["state"] == "drain":
            raise ValueError("agent_policy_drain_requires_runtime")
        acknowledge_policy(applied, transport, identity, state=control["state"] if control else "active")
    return applied
