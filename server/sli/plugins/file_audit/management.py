"""Administrator commands and authenticated local inventory; no server collector."""
from __future__ import annotations

import json
import re
from types import SimpleNamespace
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from server.sli.agents import policies, registry
from server.sli.agents.ca import AgentError, utcnow, uuid_text
from server.sli.plugins.file_audit.access import require_access
from server.sli.plugins.file_audit.rule_runtime import evaluate_snapshots
from sli_agent.envelope import MAX_PACKET_BYTES, canonical
from sli_agent.file_audit import CONTRACT, PAGE_BYTES, digest, request
from sli_agent.file_audit_policy import SID, audit_requirements, path_in_root, policy
from sli_agent.modules import configured_modules

REASONS = {"ok", "coverage_incomplete", "sacl_missing", "policy_missing", "restore_incomplete",
           "native_unavailable", "policy_blocked", "management_disabled", "restore_required",
           "restore_scope_mismatch", "system_required", "managed_by_gpo", "unknown",
           "global_sacl_unknown", "global_sacl_present", "restore_scan_incomplete", "inheritance_untracked",
           "restore_conflict"}


def retain_assignment_policy(cur, agent_id, *, actor):
    """Retain the just-issued locked assignment; no AG-AUDIT command or commit."""
    matched = re.fullmatch(r"(session|api_key):([1-9][0-9]{0,18})", actor) if isinstance(actor, str) else None
    if matched is None or int(matched[2]) > 2**63 - 1:
        raise AgentError("file_audit_request_denied", 403)
    cur.execute("select sli_plugin_file_audit.retain_assignment_policy(%s,%s,%s)",
                (agent_id, matched[1], int(matched[2])))


def status(cur, agent_id, *, principal, access):
    agent_id = uuid_text(agent_id)
    agent = policies._agent(cur, agent_id)
    state = agent.get("file_audit", {})
    if not state:
        # Even an empty state must not become an unscoped discovery endpoint.
        raise AgentError("file_audit_not_configured", 404)
    command = state["request"]["command"]
    try:
        for scope in command["collection_scope_ids"]:
            require_access(access, action="manage_audit", agent_id=agent_id,
                           source_instance_id=str(agent["host_id"]), collection_scope_id=scope, principal=principal)
    except PermissionError:
        raise AgentError("file_audit_request_denied", 403) from None
    return {"command": command, "state": state["state"], "scopes": state.get("scopes", {}),
            "reported_at": state.get("reported_at"), "may_own_audit": state["may_own_audit"]}


def enqueue(cur, body, *, principal, access):
    required = {"agent_id", "expected_revision", "config", "command"}
    if (not isinstance(body, dict) or not required <= set(body) or set(body) - required - {"enabled", "activate_collection"}
            or "activate_collection" in body and type(body["activate_collection"]) is not bool
            or body.get("activate_collection") is True and (body.get("enabled") is not True
                or not isinstance(body["command"], dict) or body["command"].get("action") != "apply")
            or "enabled" in body and (type(body["enabled"]) is not bool
                or not isinstance(body["config"], dict)
                or not body.get("activate_collection") and body["config"].get("source_kind") != "workstation")):
        raise AgentError("file_audit_request_invalid")
    activate = body.get("activate_collection", False)
    agent_id = uuid_text(body["agent_id"])
    agent = policies._agent(cur, agent_id)
    revision = policies._next_revision(agent, body["expected_revision"])
    try:
        parsed = request({"config": {**body["config"], "policy_revision": str(revision)}, "command": body["command"]})
        modules = agent["assigned_modules"]
        if parsed["config"].get("source_kind") == "workstation":
            if parsed["command"]["action"] != "restore" and not any(
                    isinstance(item, dict) and item.get("module_id") == "sli.workstations"
                    and item.get("enabled") is True for item in modules):
                raise ValueError("file_audit_workstation_required")
        if activate or parsed["config"].get("source_kind") == "workstation" and "enabled" in body:
            modules = [item for item in modules if item != "sli.file-audit"
                       and not (isinstance(item, dict) and item.get("module_id") == "sli.file-audit")]
            modules = [*modules, {"module_id": "sli.file-audit", "enabled": body["enabled"], "config": parsed["config"]}]
            configured_modules(SimpleNamespace(collection_enabled=False), str(agent["host_id"]), modules)
        if len(canonical(parsed)) > 48 * 1024:
            raise ValueError("file_audit_request_invalid")
        candidate = {**agent, "assigned_modules": modules, "policy_revision": revision, "file_audit": {"request": parsed}}
        if len(canonical(policies.check_in(candidate))) > MAX_PACKET_BYTES - 1024:
            raise ValueError("file_audit_request_invalid")
        scopes = ([root["collection_scope_id"] for root in parsed["config"]["roots"]] if activate
                  else parsed["command"]["collection_scope_ids"])
        for scope in scopes:
            require_access(access, action="manage_audit", agent_id=agent_id,
                           source_instance_id=str(agent["host_id"]), collection_scope_id=scope, principal=principal)
    except (ValueError, TypeError, PermissionError):
        raise AgentError("file_audit_request_denied", 403) from None
    if parsed["command"]["action"] != "check" and not agent.get("collection_policy", {}).get("manage_windows_audit", False):
        raise AgentError("file_audit_management_disabled", 409)
    prior = agent.get("file_audit", {})
    # A superseding command must never lose the rollback scope of an apply.
    if prior.get("may_own_audit") and (parsed["config"]["roots"] != prior["request"]["config"]["roots"]):
        raise AgentError("file_audit_restore_required", 409)
    cur.execute("select sli_plugin_file_audit.enqueue_audit(%s,%s,%s::jsonb,%s::jsonb,%s,%s)",
                (agent_id, str(agent["host_id"]), json.dumps(parsed["config"]), json.dumps(parsed["command"]),
                 principal["type"], principal["id"]))
    state = {"request": parsed, "state": "pending", "scopes": {},
             "may_own_audit": prior.get("may_own_audit", False) or parsed["command"]["action"] == "apply"}
    policies._snapshot(cur, agent_id, agent["policy_revision"], agent["assigned_modules"], agent.get("collection_policy", {}))
    policies._snapshot(cur, agent_id, revision, modules, agent.get("collection_policy", {}))
    cur.execute("update sli_agents set file_audit=%s::jsonb,policy_revision=%s,assigned_modules=%s::jsonb where id=%s",
                (json.dumps(state), revision, json.dumps(modules), agent_id))
    registry.audit(cur, "file_audit_command", f"{principal['type']}:{principal['id']}", agent_id,
                   command_id=parsed["command"]["command_id"], command_action=parsed["command"]["action"],
                   policy_sha256=digest(parsed["config"]), revision=revision,
                   **({"activate_collection": True} if activate else {}))
    return {"policy_revision": revision, "command_id": parsed["command"]["command_id"], "state": "pending"}


def enqueue_batch(cur, body, *, principal, access):
    """Explicit selection of workstation agents; caller commits the whole batch."""
    required = {"agents", "config", "action", "enabled"}
    if (not isinstance(body, dict) or not required <= set(body) or set(body) - required - {"activate_collection"}
            or "activate_collection" in body and type(body["activate_collection"]) is not bool
            or body.get("activate_collection") is True and (body.get("enabled") is not True or body.get("action") != "apply")
            or not isinstance(body["agents"], list) or not 1 <= len(body["agents"]) <= 64
            or not isinstance(body["config"], dict) or body["config"].get("source_kind") != "workstation"
            or type(body["enabled"]) is not bool or body["action"] not in ("check", "apply", "restore")):
        raise AgentError("file_audit_request_invalid")
    selected = {}
    try:
        config = policy(body["config"])
    except ValueError:
        raise AgentError("file_audit_request_invalid") from None
    for item in body["agents"]:
        if not isinstance(item, dict) or set(item) != {"agent_id", "expected_revision"}:
            raise AgentError("file_audit_request_invalid")
        agent_id = uuid_text(item["agent_id"])
        if agent_id in selected:
            raise AgentError("file_audit_request_invalid")
        selected[agent_id] = item["expected_revision"]
    # Lock in a stable order and reject stale selections before any writes.
    configurations = {}
    for agent_id, expected in sorted(selected.items()):
        agent = policies._agent(cur, agent_id)
        policies._next_revision(agent, expected)
        retained = agent.get("file_audit", {}).get("request", {}).get("config", {})
        if body["action"] == "restore":
            if retained.get("source_kind") != "workstation":
                raise AgentError("file_audit_restore_required", 409)
            configurations[agent_id] = retained
        else:
            configurations[agent_id] = config
    results = []
    for agent_id, expected in sorted(selected.items()):
        config = configurations[agent_id]
        results.append({"agent_id": agent_id, **enqueue(cur, {
            "agent_id": agent_id, "expected_revision": expected, "config": config,
            "enabled": False if body["action"] == "restore" else body["enabled"],
            **({"activate_collection": body["activate_collection"]} if "activate_collection" in body else {}),
            "command": {"contract_id": "sli.file-audit.audit-command.v1", "command_id": str(uuid4()),
                "action": body["action"], "policy_revision": str(expected + 1),
                "collection_scope_ids": [root["collection_scope_id"] for root in config["roots"]]},
        }, principal=principal, access=access)})
    return {"items": results}


def _utc(value):
    from datetime import datetime
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("file_audit_result_invalid")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise ValueError("file_audit_result_invalid")


def _text(value, limit=65536):
    return isinstance(value, str) and len(value) <= limit and not any(ord(char) < 32 for char in value)


def _snapshot(snapshot, config, command):
    if (not isinstance(snapshot, dict) or set(snapshot) != {"contract_id", "collection_scope_id", "policy_revision",
            "observed_at_utc", "scan_id", "page_number", "has_more", "completeness", "unread_objects", "share",
            "local_groups", "objects", "snapshot_sha256", "snapshot_id"}
            or snapshot["contract_id"] != "sli.file-audit.inventory.v1"
            or snapshot["policy_revision"] != command["policy_revision"]
            or snapshot["collection_scope_id"] not in command["collection_scope_ids"]
            or type(snapshot["page_number"]) is not int or not 0 <= snapshot["page_number"] <= 100000
            or type(snapshot["has_more"]) is not bool
            or snapshot["completeness"] not in ("complete", "partial", "failed")
            or type(snapshot["unread_objects"]) is not int or not 0 <= snapshot["unread_objects"] <= 100000
            or snapshot["completeness"] == "complete" and (snapshot["unread_objects"] or snapshot["has_more"] or snapshot["page_number"])
            or not isinstance(snapshot["objects"], list) or len(snapshot["objects"]) > config["inventory_objects"]
            or len(canonical(snapshot)) > PAGE_BYTES):
        raise ValueError("file_audit_result_invalid")
    _utc(snapshot["observed_at_utc"])
    UUID(snapshot["scan_id"])
    UUID(snapshot["snapshot_id"])
    contents = {key: value for key, value in snapshot.items() if key not in ("snapshot_sha256", "snapshot_id")}
    if snapshot["snapshot_sha256"] != digest(contents):
        raise ValueError("file_audit_result_invalid")
    if snapshot["snapshot_id"] != str(uuid5(NAMESPACE_URL, command["command_id"] + digest(contents))):
        raise ValueError("file_audit_result_invalid")
    root = next(root for root in config["roots"] if root["collection_scope_id"] == snapshot["collection_scope_id"])
    share = snapshot["share"]
    if (not isinstance(share, dict) or set(share) != {"name", "path", "dacl", "complete"}
            or share["name"] != root["share_name"] or share["path"] != root["path"]
            or not _text(share["dacl"]) or type(share["complete"]) is not bool):
        raise ValueError("file_audit_result_invalid")
    groups = snapshot["local_groups"]
    if (not isinstance(groups, dict) or set(groups) != {"complete", "groups"}
            or type(groups["complete"]) is not bool or not isinstance(groups["groups"], list) or len(groups["groups"]) > 100):
        raise ValueError("file_audit_result_invalid")
    for group in groups["groups"]:
        if (not isinstance(group, dict) or set(group) != {"group_sid", "member_sids"}
                or not isinstance(group["group_sid"], str) or not SID.fullmatch(group["group_sid"])
                or not isinstance(group["member_sids"], list) or len(group["member_sids"]) > 100
                or any(not isinstance(sid, str) or len(sid) > 184 or not SID.fullmatch(sid) for sid in group["member_sids"])):
            raise ValueError("file_audit_result_invalid")
    seen = set()
    for row in snapshot["objects"]:
        if (not isinstance(row, dict) or set(row) != {"path", "object_id", "object_type", "owner_sid", "dacl", "sacl", "sacl_protected", "sacl_missing"}
                or not path_in_root(row["path"], root["path"]) or row["path"].lower() in seen
                or row["object_type"] not in ("file", "directory") or not _text(row["object_id"], 256)
                or not isinstance(row["owner_sid"], str) or len(row["owner_sid"]) > 184 or not SID.fullmatch(row["owner_sid"])
                or not _text(row["dacl"]) or not _text(row["sacl"])
                or type(row["sacl_protected"]) is not bool or type(row["sacl_missing"]) is not bool):
            raise ValueError("file_audit_result_invalid")
        seen.add(row["path"].lower())
    return snapshot


def validate_result(body, state):
    parsed = request(state["request"])
    config, command = parsed["config"], parsed["command"]
    if (not isinstance(body, dict) or set(body) != {"contract_id", "command_id", "policy_revision", "action", "observed_at_utc", "scopes", "snapshots", "ownership_remaining"}
            or body["contract_id"] != CONTRACT or any(body[key] != command[key] for key in ("command_id", "policy_revision", "action"))
            or type(body["ownership_remaining"]) is not bool
            or not isinstance(body["scopes"], list) or not 1 <= len(body["scopes"]) <= 100
            or not isinstance(body["snapshots"], list) or len(body["snapshots"]) > 1
            or len(canonical(body)) > 128 * 1024):
        raise ValueError("file_audit_result_invalid")
    _utc(body["observed_at_utc"])
    scopes = set()
    for scope in body["scopes"]:
        if (not isinstance(scope, dict) or set(scope) != {"collection_scope_id", "state", "reason_code", "required_masks", "actual_masks"}
                or not isinstance(scope["collection_scope_id"], str) or scope["collection_scope_id"] in scopes
                or scope["collection_scope_id"] not in command["collection_scope_ids"]
                or scope["state"] not in ("verified", "partial", "blocked", "failed")
                or scope["reason_code"] not in REASONS):
            raise ValueError("file_audit_result_invalid")
        scopes.add(scope["collection_scope_id"])
        root = next(root for root in config["roots"] if root["collection_scope_id"] == scope["collection_scope_id"])
        required = audit_requirements({**config, "roots": [root]})
        if scope["state"] != "failed":
            if (not isinstance(scope["required_masks"], dict) or scope["required_masks"] != required
                    or any(type(mask) is not int for mask in scope["required_masks"].values())
                    or not isinstance(scope["actual_masks"], dict) or set(scope["actual_masks"]) != set(required)):
                raise ValueError("file_audit_result_invalid")
            if any(mask is not None and (type(mask) is not int or not 0 <= mask <= 3) for mask in scope["actual_masks"].values()):
                raise ValueError("file_audit_result_invalid")
            if scope["state"] == "verified" and command["action"] != "restore" and any(
                    scope["actual_masks"][guid] is None or scope["actual_masks"][guid] & mask != mask for guid, mask in required.items()):
                raise ValueError("file_audit_result_invalid")
        elif scope["required_masks"] != {} or scope["actual_masks"] != {}:
            raise ValueError("file_audit_result_invalid")
    for snapshot in body["snapshots"]:
        _snapshot(snapshot, config, command)
        if snapshot["collection_scope_id"] not in scopes:
            raise ValueError("file_audit_result_invalid")
    for scope in body["scopes"]:
        if scope["state"] == "verified":
            snapshot = next((row for row in body["snapshots"] if row["collection_scope_id"] == scope["collection_scope_id"]), None)
            if snapshot is None or snapshot["has_more"] or snapshot["unread_objects"]:
                raise ValueError("file_audit_result_invalid")
            if snapshot["share"]["complete"] is not True or snapshot["local_groups"]["complete"] is not True:
                raise ValueError("file_audit_result_invalid")
            if command["action"] != "restore" and any(row["sacl_missing"] for row in snapshot["objects"]):
                raise ValueError("file_audit_result_invalid")
            if command["action"] == "restore" and body["ownership_remaining"]:
                raise ValueError("file_audit_result_invalid")
    return body


def ingest(cur, agent, body):
    state = agent.get("file_audit", {})
    current = state.get("request", {}).get("command", {}).get("command_id")
    historical = isinstance(body, dict) and isinstance(body.get("command_id"), str) and body["command_id"] != current
    if historical:
        # A lost receipt must not wedge the agent after a new admin command.
        # Admit only an immutable command authored for this mTLS identity.
        cur.execute("select sli_plugin_file_audit.audit_request(%s,%s) as request", (str(agent["id"]), body["command_id"]))
        row = cur.fetchone()
        if not row or not row.get("request"):
            raise AgentError("file_audit_result_invalid")
        state = {"request": row["request"]}
    try:
        value = validate_result(body, state)
    except (ValueError, TypeError, KeyError, StopIteration, AttributeError):
        raise AgentError("file_audit_result_invalid") from None
    records = {**value, "scopes": [{**scope, "receipt_id": str(uuid5(NAMESPACE_URL, str(agent["id"]) + digest(value) + scope["collection_scope_id"])),
                "result_sha256": digest(value)} for scope in value["scopes"]]}
    cur.execute("select sli_plugin_file_audit.store_audit_result(%s,%s::jsonb)", (str(agent["id"]), json.dumps(records)))
    cur.execute("select domain_id from servers where hostname=%s and is_active",
                (state["request"]["config"].get("source_name", str(agent["host_id"])),))
    sources = cur.fetchall()
    source = sources[0] if len(sources) == 1 else {}
    evaluate_snapshots(cur, agent_id=str(agent["id"]), source_instance_id=str(agent["host_id"]),
        command_id=value["command_id"], config=state["request"]["config"], snapshots=value["snapshots"],
        domain_id=source.get("domain_id"))
    if historical:
        return {"command_id": value["command_id"], "state": "superseded"}
    states = {**state.get("scopes", {}), **{scope["collection_scope_id"]: scope for scope in value["scopes"]}}
    complete = set(states) == set(state["request"]["command"]["collection_scope_ids"]) and all(row["state"] == "verified" for row in states.values())
    state = {**state, "scopes": states, "state": "verified" if complete else "partial",
             "reported_at": utcnow().isoformat()}
    if complete and value["action"] == "restore" and not value["ownership_remaining"]:
        state["may_own_audit"] = False
    cur.execute("update sli_agents set file_audit=%s::jsonb where id=%s", (json.dumps(state), str(agent["id"])))
    return {"command_id": value["command_id"], "state": state["state"]}
