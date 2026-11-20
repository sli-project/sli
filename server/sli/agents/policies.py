"""Serialized policy revisions and agent-reported acknowledgement/probe state."""
import hashlib
import json
from types import SimpleNamespace
from uuid import uuid4

from server.sli.agents import registry
from server.sli.agents.runtime_switch import source_host
from server.sli.agents.assignments import NPS_MODULES
from server.sli.agents.ca import AgentError, utcnow, uuid_text
from server.sli.plugins.registry import plugin_hook
from sli_agent.control import collection_policy
from sli_agent.envelope import MAX_PACKET_BYTES, canonical
from sli_agent.modules import configured_modules
from sli_agent.snapshot_stream import MODULE_FAMILIES
from sli_agent.snapshot_stream import policy as snapshot_policy
from sli_agent.workstations import WorkstationsModule


def _agent(cur, agent_id):
    cur.execute("select * from sli_agents where id=%s for update", (agent_id,))
    row = cur.fetchone()
    if not row:
        raise AgentError("agent_not_found", 404)
    if row["status"] != "active":
        raise AgentError("agent_disabled", 409)
    return {**row, "host_id": source_host(row)}


def _next_revision(agent, expected):
    revision = agent["policy_revision"]
    if type(expected) is not int or expected != revision:
        raise AgentError("agent_policy_revision_conflict", 409)
    if revision >= 9007199254740991:
        raise AgentError("agent_policy_revision_exhausted", 409)
    return revision + 1


def _snapshot(cur, agent_id, revision, modules, control):
    cur.execute("insert into sli_agent_policy_history(agent_id,revision,assigned_modules,collection_policy) "
                "values(%s,%s,%s::jsonb,%s::jsonb) on conflict(agent_id,revision) do nothing",
                (agent_id, revision, json.dumps(modules), json.dumps(collection_policy(control))))


def assign_module(cur, body, *, actor):
    if isinstance(body, dict) and "password_detection_domain" in body:
        return _assign_password_domain(cur, body, actor=actor)
    if isinstance(body, dict) and isinstance(body.get("module_id"), str) and body["module_id"] in MODULE_FAMILIES:
        return _assign_snapshot(cur, body, actor=actor)
    nps_policy = plugin_hook("sli.remote-access", "nps_agent_policy") if (
        isinstance(body, dict) and body.get("module_id") in NPS_MODULES) else None
    ad_policy = plugin_hook("sli.ad", "ad_agent_policy") if (
        isinstance(body, dict) and body.get("module_id") in ("sli.windows.ad-dc", "sli.windows.ad-dc-history")) else None
    file_policy = plugin_hook("sli.file-audit", "file_audit_agent_policy") if (
        isinstance(body, dict) and body.get("module_id") == "sli.file-audit") else None
    if (not isinstance(body, dict) or set(body) - {"agent_id", "module_id", "enabled", "config", "expected_revision"}
            or body.get("module_id") not in ("sli.workstations", "sli.windows.ad-dc", "sli.windows.ad-dc-history", "sli.file-audit", *NPS_MODULES) or type(body.get("enabled")) is not bool
            or body.get("module_id") in NPS_MODULES and nps_policy is None
            or body.get("module_id") in ("sli.windows.ad-dc", "sli.windows.ad-dc-history") and ad_policy is None
            or body.get("module_id") == "sli.file-audit" and file_policy is None
            or not isinstance(body.get("config", {}), dict)):
        raise AgentError("invalid_agent_module_assignment")
    agent_id = uuid_text(body.get("agent_id"))
    agent = _agent(cur, agent_id)
    revision = _next_revision(agent, body.get("expected_revision", agent["policy_revision"]))
    module_id = body["module_id"]
    try:
        settings = {**body.get("config", {}), "policy_revision": str(revision)}
        if module_id == "sli.workstations":
            config = WorkstationsModule(str(agent["host_id"]), settings).policy
        elif module_id in NPS_MODULES:
            config = nps_policy(module_id, settings)
        elif module_id == "sli.file-audit":
            config = file_policy(settings)
        else:
            if (module_id == "sli.windows.ad-dc-history") != ("history_before_utc" in settings):
                raise ValueError()
            config = ad_policy(str(agent["host_id"]), settings)
    except ValueError:
        raise AgentError("invalid_agent_module_config") from None
    assignment = {"module_id": module_id, "enabled": body["enabled"], "config": config}
    modules = [item for item in agent["assigned_modules"] if item != module_id
               and not (isinstance(item, dict) and item.get("module_id") == module_id)]
    modules.append(assignment)
    if len(modules) > 64:
        raise AgentError("agent_module_limit")
    if len(canonical(check_in({**agent, "assigned_modules": modules, "policy_revision": revision}))) > MAX_PACKET_BYTES - 1024:
        raise AgentError("agent_policy_size_limit")
    try:
        configured_modules(SimpleNamespace(collection_enabled=False), str(agent["host_id"]), modules)
    except ValueError:
        raise AgentError("agent_channel_owner_conflict", 409) from None
    _snapshot(cur, agent_id, agent["policy_revision"], agent["assigned_modules"], agent.get("collection_policy", {}))
    _snapshot(cur, agent_id, revision, modules, agent.get("collection_policy", {}))
    cur.execute("update sli_agents set assigned_modules=%s::jsonb,policy_revision=%s where id=%s",
                (json.dumps(modules), revision, agent_id))
    if module_id == "sli.file-audit":
        retain = plugin_hook("sli.file-audit", "retain_assignment_policy")
        if retain is None:
            raise AgentError("file_audit_plugin_unavailable", 409)
        retain(cur, agent_id, actor=actor)
    # Keep private path filters out of audit diagnostics; the hash identifies
    # the exact policy applied at this monotonically increasing revision.
    digest = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
    registry.audit(cur, "module_assign", actor, agent_id, module_id=module_id,
                   enabled=body["enabled"], policy_sha256=digest, revision=revision,
                   **({"families": config["families"]} if module_id in ("sli.workstations", *NPS_MODULES)
                      else {"channels": ["Security"]} if module_id == "sli.file-audit" else {"channels": config["channels"]}),
                   changed_fields=sorted(body.get("config", {})))
    return {"agent_id": agent_id, "assigned_modules": modules, "policy_revision": revision}


def _assign_snapshot(cur, body, *, actor):
    if (set(body) - {"agent_id", "module_id", "enabled", "config", "expected_revision"}
            or type(body.get("enabled")) is not bool or not isinstance(body.get("config"), dict)):
        raise AgentError("invalid_agent_module_assignment")
    agent_id = uuid_text(body.get("agent_id"))
    agent = _agent(cur, agent_id)
    revision = _next_revision(agent, body.get("expected_revision", agent["policy_revision"]))
    module = body["module_id"]
    try:
        config = snapshot_policy(module, {**body["config"], "policy_revision": str(revision)})
    except ValueError:
        raise AgentError("invalid_agent_module_config") from None
    cur.execute("select pg_advisory_xact_lock(170,1)")
    cur.execute("select config from sli_agent_snapshot_bindings where agent_id=%s and module_id=%s", (agent_id, module))
    old = cur.fetchone()
    if old and any(old["config"][name] != config[name] for name in
                   ("source_instance_id", "domain_sid", "domain_dns", "scope")):
        raise AgentError("agent_snapshot_binding_immutable", 409)
    if body["enabled"]:
        cur.execute("""select agent_id from sli_agent_snapshot_bindings
            where module_id=%s and domain_sid=%s and enabled and agent_id<>%s""", (module, config["domain_sid"], agent_id))
        if cur.fetchone():
            raise AgentError("agent_snapshot_collector_conflict", 409)
    assignment = {"module_id": module, "enabled": body["enabled"], "config": config}
    modules = [item for item in agent["assigned_modules"] if item != module
               and not (isinstance(item, dict) and item.get("module_id") == module)] + [assignment]
    if len(modules) > 64:
        raise AgentError("agent_module_limit")
    if len(canonical(check_in({**agent, "assigned_modules": modules, "policy_revision": revision}))) > MAX_PACKET_BYTES - 1024:
        raise AgentError("agent_policy_size_limit")
    _snapshot(cur, agent_id, agent["policy_revision"], agent["assigned_modules"], agent.get("collection_policy", {}))
    _snapshot(cur, agent_id, revision, modules, agent.get("collection_policy", {}))
    cur.execute("""insert into sli_agent_snapshot_bindings(agent_id,module_id,config,enabled)
        values(%s,%s,%s::jsonb,%s) on conflict(agent_id,module_id)
        do update set config=excluded.config,enabled=excluded.enabled""", (agent_id, module, json.dumps(config), body["enabled"]))
    cur.execute("""update sli_agent_snapshot_policies set superseded_at=clock_timestamp()
        where agent_id=%s and module_id=%s and superseded_at is null""", (agent_id, module))
    cur.execute("""insert into sli_agent_snapshot_policies(agent_id,module_id,config,enabled)
        values(%s,%s,%s::jsonb,%s)""", (agent_id, module, json.dumps(config), body["enabled"]))
    cur.execute("update sli_agents set assigned_modules=%s::jsonb,policy_revision=%s where id=%s",
                (json.dumps(modules), revision, agent_id))
    registry.audit(cur, "module_assign", actor, agent_id, module_id=module, enabled=body["enabled"],
                   policy_sha256=hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest(), revision=revision)
    return {"agent_id": agent_id, "assigned_modules": modules, "policy_revision": revision}


def update_control(cur, body, *, actor):
    if (not isinstance(body, dict) or set(body) != {"agent_id", "expected_revision", "collection_policy"}
            or not isinstance(body["collection_policy"], dict)):
        raise AgentError("invalid_agent_collection_policy")
    agent_id = uuid_text(body["agent_id"])
    agent = _agent(cur, agent_id)
    revision = _next_revision(agent, body["expected_revision"])
    try:
        control = collection_policy({**agent.get("collection_policy", {}), **body["collection_policy"]})
    except ValueError:
        raise AgentError("invalid_agent_collection_policy") from None
    _snapshot(cur, agent_id, agent["policy_revision"], agent["assigned_modules"], agent.get("collection_policy", {}))
    _snapshot(cur, agent_id, revision, agent["assigned_modules"], control)
    cur.execute("update sli_agents set collection_policy=%s::jsonb,policy_revision=%s where id=%s",
                (json.dumps(control), revision, agent_id))
    registry.audit(cur, "policy_update", actor, agent_id, revision=revision,
                   changed_fields=sorted(body["collection_policy"]), **control)
    return {"agent_id": agent_id, "policy_revision": revision, "collection_policy": control}


def request_probe(cur, body, *, actor):
    if not isinstance(body, dict) or set(body) != {"agent_id"}:
        raise AgentError("invalid_agent_probe_request")
    agent_id = uuid_text(body["agent_id"])
    agent = _agent(cur, agent_id)
    probe = dict(agent["rights_probe"])
    if not probe.get("pending"):
        probe["pending"] = {"request_id": str(uuid4()), "requested_at": utcnow().isoformat()}
        cur.execute("update sli_agents set rights_probe=%s::jsonb where id=%s", (json.dumps(probe), agent_id))
        registry.audit(cur, "probe_request", actor, agent_id, request_id=probe["pending"]["request_id"])
    return {"rights_probe": probe}


def check_in(agent):
    control = collection_policy(agent.get("collection_policy", {}))
    if not control["manage_windows_audit"]:
        # Older agents validate collection keys strictly. An opt-out remains
        # wire-compatible; upgraded agents default to observe/restore locally.
        control.pop("manage_windows_audit")
        control.pop("audit_process_command_line")
    return {"agent_id": str(agent["id"]), "assigned_modules": agent["assigned_modules"],
            **({"runtime_handoff": {"source_host_id": source_host(agent),
                                   "cursors": agent.get("runtime_resume", {})}}
               if agent.get("source_host_id") else {}),
            "policy_revision": agent["policy_revision"], "rights_probe_request": agent["rights_probe"].get("pending"),
            "collection_policy": control, "eventlog_diagnostics_supported": True, "delivery_diagnostics_supported": True,
            **({"file_audit": agent["file_audit"]["request"]} if agent.get("file_audit", {}).get("request")
               and plugin_hook("sli.file-audit", "audit_command") is not None else {})}


def report(cur, agent, body):
    agent = dict(agent)
    # Agent identity comes exclusively from mTLS, never a caller-supplied ID.
    if isinstance(body, dict) and set(body) == {"delivery_diagnostics"}:
        from sli_agent.delivery_diagnostics import validate_observations
        try:
            items = validate_observations(body["delivery_diagnostics"])
        except ValueError:
            raise AgentError("invalid_agent_delivery_diagnostics") from None
        probe = dict(agent["rights_probe"])
        probe["delivery_diagnostics"] = {"reported_at": utcnow().isoformat(), "items": items}
        cur.execute("update sli_agents set rights_probe=%s::jsonb where id=%s",
                    (json.dumps(probe), str(agent["id"])))
        # An independent report is not a policy acknowledgement, including drain.
        return {"delivery_diagnostics": probe["delivery_diagnostics"]}
    if not isinstance(body, dict) or set(body) - {"applied_policy_revision", "rights_probe", "collection_state", "eventlog_diagnostics", "runtime_handoff_supported"}:
        raise AgentError("invalid_agent_policy_report")
    if "runtime_handoff_supported" in body and body["runtime_handoff_supported"] is not True:
        raise AgentError("invalid_agent_policy_report")
    revision = body.get("applied_policy_revision")
    if type(revision) is not int or not 0 <= revision <= agent["policy_revision"]:
        raise AgentError("invalid_agent_policy_revision")
    state = body.get("collection_state")
    desired = agent.get("collection_policy", {}).get("state", "active")
    if ("collection_policy" in agent and state is None or state is not None and (
            state not in ("active", "paused") or revision == agent["policy_revision"]
            and state != ("active" if desired == "active" else "paused"))):
        raise AgentError("invalid_agent_collection_state")
    probe = dict(agent["rights_probe"])
    if body.get("runtime_handoff_supported") is True:
        # Agent-reported compatibility only; replacement authority is enforced
        # separately by the server's key-bound replacement token and DB linkage.
        probe["runtime_handoff_supported"] = True
    if "eventlog_diagnostics" in body:
        from sli_collect.eventlog_diagnostics import validate_observations
        try:
            observations = validate_observations(body["eventlog_diagnostics"])
            if any(item["policy_revision"] > revision for item in observations):
                raise ValueError()
        except ValueError:
            raise AgentError("invalid_agent_eventlog_diagnostics") from None
        probe["eventlog_diagnostics"] = {"reported_at": utcnow().isoformat(), "items": observations}
    result = body.get("rights_probe")
    if result is not None:
        pending = probe.get("pending")
        if (not isinstance(result, dict) or set(result) != {"request_id", "status"}
                or result["status"] not in ("allowed", "denied", "unavailable")
                or not pending or result["request_id"] != pending["request_id"]):
            raise AgentError("invalid_agent_probe_report")
        probe.pop("pending")
        probe["last_result"] = {**result, "policy_revision": revision, "reported_at": utcnow().isoformat()}
    applied = max(revision, agent["applied_policy_revision"])
    cur.execute("update sli_agents set applied_policy_revision=%s,rights_probe=%s::jsonb where id=%s",
                (applied, json.dumps(probe), str(agent["id"])))
    applied_state = agent.get("applied_collection_state", "unknown")
    if revision >= agent["applied_policy_revision"] and (state is not None or revision > agent["applied_policy_revision"]):
        applied_state = state or "unknown"
        cur.execute("update sli_agents set applied_collection_state=%s where id=%s", (applied_state, str(agent["id"])))
    if applied != agent["applied_policy_revision"]:
        registry.audit(cur, "policy_ack", "agent:" + str(agent["id"]), str(agent["id"]), revision=applied)
    if result is not None:
        registry.audit(cur, "probe_report", "agent:" + str(agent["id"]), str(agent["id"]), revision=revision, **result)
    return {"applied_policy_revision": applied, "rights_probe": probe, "applied_collection_state": applied_state}


def _assign_password_domain(cur, body, *, actor):
    from server.sli.core.platform_settings import _dns_name

    metadata = body.get("password_detection_domain")
    if (set(body) != {"agent_id", "module_id", "expected_revision", "password_detection_domain"}
            or body.get("module_id") != "sli.windows.ad-dc"
            or type(body.get("expected_revision")) is not int
            or not 1 <= body["expected_revision"] <= 9007199254740991
            or not isinstance(metadata, dict) or set(metadata) != {"fqdn", "expected_domain_id"}
            or not isinstance(metadata.get("fqdn"), str)
            or metadata.get("expected_domain_id") is not None and (
                type(metadata["expected_domain_id"]) is not int or not 1 <= metadata["expected_domain_id"] < 2**63)):
        raise AgentError("invalid_password_domain_metadata")
    agent_id = uuid_text(body["agent_id"])
    try:
        fqdn = _dns_name(metadata["fqdn"])
    except ValueError:
        raise AgentError("invalid_password_domain_metadata") from None
    try:
        cur.execute("select public.provision_password_detection_domain_v2(%s::uuid,%s::bigint,%s::bigint,%s,%s) as metadata",
                    (agent_id, body["expected_revision"], metadata["expected_domain_id"], fqdn, actor))
        result = cur.fetchone()["metadata"]
    except Exception as exc:
        code = getattr(exc, "sqlstate", None)
        if code == "40001":
            raise AgentError("password_domain_conflict", 409) from None
        if code == "55000":
            raise AgentError("password_domain_immutable", 409) from None
        if code == "22023":
            raise AgentError("invalid_password_domain_metadata") from None
        raise
    return {"agent_id": agent_id, "policy_revision": body["expected_revision"], "password_detection_domain": result}
