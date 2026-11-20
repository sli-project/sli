"""Deterministic, bounded file actions with explicit evidence provenance."""
from datetime import timedelta
from hashlib import sha256
import ipaddress
import json

from server.sli.plugins.file_audit.contracts import EvidenceIdentity
from server.sli.plugins.file_audit.normalizers import native_facts
from sli_agent.envelope import digest, timestamp
from sli_agent.file_audit_events import admitted_event, masked_event, native_event, number, outcome
from sli_agent.file_audit_policy import CONTEXT_EVENT_IDS

WINDOW_SECONDS = 300


def observation_from_xml(raw, *, agent_id, source_instance_id, generation, policy_revision, core_evidence_ref, config):
    row, data = native_event(raw, source_instance_id)
    admitted, scopes, path = admitted_event(row, data, config)
    if not admitted:
        raise ValueError("file_audit_scope_invalid")
    observed = timestamp(row["time_created"]).isoformat()
    event = row["event_id"]
    if not scopes:
        _, data = native_event(masked_event(raw, config), source_instance_id)
    if event in CONTEXT_EVENT_IDS:
        # Shared evidence keeps its existing AD normalizer owner. This narrow
        # context contains only correlation fields, not another AD projection.
        key = sha256(json.dumps([agent_id, source_instance_id, "Security", generation, row["record_id"]],
                                separators=(",", ":")).encode()).hexdigest()
        facts = {"subject_user_sid": data.get("TargetUserSid") or data.get("SubjectUserSid"),
                 "logon_id_numeric": number(data.get("TargetLogonId") or data.get("SubjectLogonId")),
                 "ip_address": data.get("IpAddress"), "outcome": outcome(row)}
    else:
        identity = EvidenceIdentity(agent_id, source_instance_id, generation, row["record_id"], event, row["version"] or 0)
        key, facts = identity.key, native_facts(row=row, event_data=data)
    return {"evidence_key": key, "agent_id": agent_id, "source_instance_id": source_instance_id,
            "generation": generation, "record_id": row["record_id"], "event_id": event,
            "event_version": row["version"] or 0, "provider": row["provider_name"], "channel": "Security",
            "observed_at": observed, "policy_revision": policy_revision, "core_evidence_ref": core_evidence_ref,
            "payload_sha256": sha256(raw.encode()).hexdigest(), "facts": facts, "path": path,
            "scopes": [{"collection_scope_id": r["collection_scope_id"], "share_name": r["share_name"],
                        "important": r["important"]} for r in scopes],
            "correlation_state": "not_attempted",
            "excluded": data.get("SubjectUserSid") in config["service_account_exclusions"]}


def _contexts(item, contexts):
    now = timestamp(item["observed_at"])
    available = [other for other in contexts if all(other[k] == item[k] for k in
            ("agent_id", "source_instance_id", "generation", "policy_revision"))
            and other["record_id"] < item["record_id"]
            and now - timedelta(seconds=WINDOW_SECONDS) <= timestamp(other["observed_at"]) <= now]
    boot = max((r["record_id"] for r in available if r["event_id"] in (4608, 1102)), default=0)
    return [r for r in available if r["record_id"] > boot]


def _reference(item, role):
    return {"evidence_key": item["evidence_key"], "core_evidence_ref": item["core_evidence_ref"], "role": role}


def delete_context(item, contexts):
    facts = item["facts"]
    if facts["outcome"] != "success":
        return "partial", None
    fields = ("subject_user_sid", "logon_id_numeric", "server_process_id", "handle_id")
    if not facts.get("handle_id") or any(facts.get(k) is None for k in fields):
        return "ambiguous", None
    related = [other for other in _contexts(item, contexts) if other["event_id"] in (4656, 4659, 4663, 4658, 4660)
               and all(other["facts"].get(k) == facts[k] for k in fields)]
    boundary = max((r["record_id"] for r in related if r["event_id"] in (4658, 4660)), default=0)
    if any(r["record_id"] > boundary and r["event_id"] != 4660 and not r["path"] for r in related):
        return "ambiguous", None
    candidates = [r for r in related if r["record_id"] > boundary and r["path"]
                  and r["facts"].get("outcome") == "success"]
    paths = {r["path"].casefold() for r in candidates}
    if len(paths) != 1:
        return "ambiguous" if paths or boundary else "partial", None
    return "complete", max(candidates, key=lambda r: r["record_id"])


def rename_context(item, contexts):
    """Two names on one live handle; a delete right alone proves no rename."""
    facts = item["facts"]
    fields = ("subject_user_sid", "logon_id_numeric", "server_process_id", "handle_id")
    if (item["event_id"] != 4663 or facts.get("outcome") != "success" or not item["path"]
            or not facts.get("handle_id") or any(facts.get(key) is None for key in fields)
            or not (facts.get("access_mask", 0) & (0x10000 | 6))):
        return None
    related = [r for r in _contexts(item, contexts) if r["event_id"] in (4656, 4659, 4663, 4658, 4660)
               and all(r["facts"].get(key) == facts[key] for key in fields)]
    # A new open, close or confirmed deletion ends the previous handle's life.
    boundary = max((r["record_id"] for r in related if r["event_id"] in (4656, 4658, 4660)), default=0)
    opened = next((r for r in related if r["record_id"] == boundary and r["event_id"] == 4656
                   and r["facts"].get("outcome") == "success" and r["path"]), None)
    if opened is None or not (opened["facts"].get("access_mask", 0) & 0x10000):
        return None
    previous = [r for r in related if r["record_id"] > boundary and r["event_id"] == 4663]
    if (not previous or any(not r["path"] or r["path"].casefold() != opened["path"].casefold()
                            or r["facts"].get("outcome") != "success" for r in previous)
            or opened["path"].casefold() == item["path"].casefold()):
        return None
    deleted = [r for r in previous if r["facts"].get("access_mask", 0) & 0x10000]
    return (opened, max(deleted, key=lambda r: r["record_id"])) if deleted else None


def project_actions(item, contexts=(), *, object_type="unknown"):
    facts, event = item["facts"], item["event_id"]
    scopes, path, state = item["scopes"], item["path"], "complete"
    evidence = [_reference(item, "primary")]
    available = _contexts(item, contexts)
    if event in CONTEXT_EVENT_IDS or event == 4658:
        return []
    if event == 4660:
        state, chosen = delete_context(item, contexts)
        if chosen is None:
            return []
        # All scope decisions come from server revalidation of native evidence.
        scopes, path = chosen["scopes"], chosen["path"]
        evidence.append(_reference(chosen, "handle_context"))
        operations = ["delete"]
    elif event == 4663:
        if facts["outcome"] != "success":
            return []  # 4663 has no Failure form
        mask = facts.get("access_mask") or 0
        operations = (["read"] if mask & 1 and object_type != "directory" else [])
        if mask & 6:
            operations.append("write")
        if mask & 0x10000:
            operations.append("delete_right")
        renamed = rename_context(item, contexts)
        if renamed is not None:
            opened, previous = renamed
            admitted = ({r["collection_scope_id"] for r in previous["scopes"]}
                        & {r["collection_scope_id"] for r in opened["scopes"]})
            scopes = [scope for scope in scopes if scope["collection_scope_id"] in admitted]
            operations = ["rename"]
            evidence.extend(_reference(witness, "handle_context") for witness in (opened, previous))
    elif event in (4656, 5140, 5145, 5168):
        operations = ["access_check"]
    elif event == 4659:
        operations = ["delete_right"]
    elif event == 4670:
        operations = ["permissions"]
    elif event in (5142, 5143, 5144):
        operations = ["share_change"]
    elif event == 4907:
        operations = ["audit_change"]
    else:
        operations = ["unknown"]
    ip, ip_source = None, None
    if event in (5140, 5145, 5168):
        try:
            ip = str(ipaddress.ip_address(facts.get("ip_address")))
            ip_source = f"event:{event}"
        except ValueError:
            pass
    if ip is None and facts.get("subject_user_sid") and facts.get("logon_id_numeric"):
        logons = [r for r in available if r["event_id"] == 4624
                  and r["facts"].get("outcome") == "success"
                  and r["facts"].get("subject_user_sid") == facts["subject_user_sid"]
                  and r["facts"].get("logon_id_numeric") == facts["logon_id_numeric"]]
        addresses = {r["facts"].get("ip_address") for r in logons}
        if len(addresses) == 1 and not any(r["event_id"] == 4634 and
                r["facts"].get("logon_id_numeric") == facts["logon_id_numeric"] for r in available):
            try:
                ip = str(ipaddress.ip_address(next(iter(addresses))))
                ip_source = "event:4624"
                evidence.append(_reference(logons[-1], "logon_context"))
            except ValueError:
                pass
    result = []
    for scope in scopes:
        for operation in operations:
            if operation == "read" and (not scope["important"] or item["excluded"]):
                continue
            if item["excluded"] and operation in ("write", "delete_right", "delete", "rename") and facts["outcome"] != "failure":
                continue
            quality = "partial" if operation == "delete_right" or operation == "read" and object_type == "unknown" else state
            result.append({"action_id": digest([item["evidence_key"], scope["collection_scope_id"], operation, 1]),
                "agent_id": item["agent_id"], "source_instance_id": item["source_instance_id"],
                "collection_scope_id": scope["collection_scope_id"], "observed_at": item["observed_at"],
                "subject_sid": facts.get("subject_user_sid"), "logon_id": facts.get("logon_id"),
                "path": path, "share_name": scope["share_name"], "object_type": object_type,
                "access_mask": facts.get("access_mask"), "operation": operation, "outcome": facts["outcome"],
                "denial_layer": ("ntfs" if event == 4656 else "smb" if event in (5145, 5168) else None)
                    if facts["outcome"] == "failure" else None,
                "client_ip": ip, "client_ip_source": ip_source, "server_process_id": facts.get("server_process_id"),
                "handle_id": str(facts["handle_id"]) if facts.get("handle_id") is not None else None,
                "correlation_state": quality, "projection_version": 1, "contract_version": 1, "evidence": evidence})
    return result
