"""Owner-attested batch approval and immutable, portable policy templates.

Approval prepares key-bound single-use tokens for the existing CSR enrollment
path. It does not install agents or issue certificates. AD eligibility alone
never authenticates a key; evidence must come from the administrator's trusted
deployment report, never from an agent submission. Requires AG-DEP-1 tables.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

from server.sli.agents.ca import AgentError, utcnow, uuid_text
from server.sli.agents.registry import audit, instance_name, token_hash
from sli_agent.control import collection_policy
from sli_agent.envelope import MAX_PACKET_BYTES, canonical
from sli_agent.modules import configured_modules
from sli_agent.workstations import WorkstationsModule

MAX_BATCH = 1000
PORTABLE_MODULES = {"sli.workstations"}


def _directory_entity(cur, entity_id, domain_id, *, ou=False):
    # The AG-DEP-1 implementation is the authority for accepted AD versions,
    # complete sections, freshness, enabled computers and DN boundaries.
    from server.sli.agents.group_enrollment import _directory_entity as resolve
    return resolve(cur, entity_id, domain_id, ou=ou)


def _version(value):
    if type(value) is not int or not 1 <= value <= 9007199254740991:
        raise AgentError("invalid_agent_template")
    return value


def _template_policy(modules, control):
    try:
        control = collection_policy(control)
        if not isinstance(modules, list) or len(modules) > len(PORTABLE_MODULES):
            raise ValueError()
        normalized, seen = [], set()
        # Templates deliberately exclude source/instance-bound snapshot and
        # plugin policies. Those require their existing assignment validators.
        host = "00000000-0000-4000-8000-000000000001"
        for item in modules:
            if (not isinstance(item, dict) or set(item) != {"module_id", "enabled", "config"}
                    or not isinstance(item["module_id"], str) or item["module_id"] not in PORTABLE_MODULES
                    or item["module_id"] in seen or type(item["enabled"]) is not bool
                    or not isinstance(item["config"], dict)):
                raise ValueError()
            module = item["module_id"]
            seen.add(module)
            settings = {**item["config"], "policy_revision": "1"}
            config = WorkstationsModule(host, settings).policy
            normalized.append({"module_id": module, "enabled": item["enabled"], "config": config})
        configured_modules(SimpleNamespace(collection_enabled=False), host, normalized)
        policy = {"assigned_modules": normalized, "collection_policy": control}
        if len(canonical(policy)) > MAX_PACKET_BYTES - 2048:
            raise ValueError()
        return policy
    except (ValueError, TypeError):
        raise AgentError("invalid_agent_template") from None


def save_template(cur, body, *, actor):
    if (not isinstance(body, dict) or set(body) - {"template_id", "expected_version", "assigned_modules", "collection_policy"}
            or type(body.get("expected_version")) is not int or not 0 <= body["expected_version"] < 9007199254740991):
        raise AgentError("invalid_agent_template")
    template_id = uuid_text(body["template_id"]) if "template_id" in body else str(uuid4())
    policy = _template_policy(body.get("assigned_modules"), body.get("collection_policy"))
    digest = hashlib.sha256(canonical(policy)).hexdigest()
    cur.execute("select pg_advisory_xact_lock(hashtext(%s))", ("sli-agent-template:" + template_id,))
    cur.execute("select coalesce(max(version),0) as version from sli_agent_policy_templates where id=%s", (template_id,))
    current = cur.fetchone()["version"]
    if current != body["expected_version"]:
        raise AgentError("agent_template_version_conflict", 409)
    version = current + 1
    cur.execute("insert into sli_agent_policy_templates(id,version,assigned_modules,collection_policy,policy_sha256) "
                "values(%s,%s,%s::jsonb,%s::jsonb,%s)",
                (template_id, version, json.dumps(policy["assigned_modules"]), json.dumps(policy["collection_policy"]), digest))
    audit(cur, "template_save", actor, template_id, result="saved", version=version, policy_sha256=digest)
    return {"id": template_id, "version": version, "policy_sha256": digest}


def list_templates(cur, *, actor):
    cur.execute("select distinct on(id) id,version,assigned_modules,collection_policy,policy_sha256,created_at "
                "from sli_agent_policy_templates order by id,version desc limit 100")
    items = [dict(row) for row in cur.fetchall()]
    audit(cur, "template_list", actor, "templates", result="listed")
    return {"items": items}


def list_requests(cur, token_id, *, actor):
    token_id = uuid_text(token_id)
    cur.execute("""select r.id,r.host_id,r.instance_name,r.key_fingerprint,r.computer_entity_id,r.computer_version_id,r.status,
        a.id as agent_id,a.last_seen,c.template_id,c.template_version,a.applied_policy_revision
        from sli_agent_group_requests r
        left join sli_agent_group_approval_links link on link.request_id=r.id
        left join sli_agent_onboarding_copies c on c.enrollment_token_id=link.enrollment_token_id
        left join sli_agent_audit issued on issued.actor='enrollment:' || link.enrollment_token_id::text
          and issued.action='issue'
        left join sli_agents a on a.id=issued.target::uuid
        where r.token_id=%s order by r.created_at,r.id limit 1000""", (token_id,))
    items = []
    for row in cur.fetchall():
        item = dict(row)
        # Certificate issue is registration; only an authenticated request
        # updates last_seen. Neither fact claims MSI/gpresult acceptance.
        stage = item["status"]
        if item.get("agent_id"):
            stage = "signaled" if item.get("last_seen") is not None else "registered"
        item["deployment_status"] = stage
        items.append(item)
    audit(cur, "onboarding_list", actor, token_id, result="listed", count=len(items))
    return {"items": items}


def _approval_body(body):
    allowed = {"token_id", "template_id", "template_version", "mode", "request_ids", "evidence"}
    if not isinstance(body, dict) or set(body) - allowed or body.get("mode") not in ("selected", "rule"):
        raise AgentError("invalid_agent_batch_approval")
    token_id, template_id = uuid_text(body.get("token_id")), uuid_text(body.get("template_id"))
    version = _version(body.get("template_version"))
    ids = body.get("request_ids")
    if body["mode"] == "selected":
        if not isinstance(ids, list) or not 1 <= len(ids) <= MAX_BATCH:
            raise AgentError("invalid_agent_batch_approval")
        ids = sorted(uuid_text(value) for value in ids)
        if len(set(ids)) != len(ids):
            raise AgentError("invalid_agent_batch_approval")
    elif ids is not None:
        raise AgentError("invalid_agent_batch_approval")
    evidence = body.get("evidence")
    if not isinstance(evidence, list) or len(evidence) > MAX_BATCH:
        raise AgentError("invalid_agent_batch_approval")
    bindings = {}
    for item in evidence:
        if (not isinstance(item, dict) or set(item) != {"request_id", "host_id", "instance_name", "key_fingerprint", "computer_entity_id"}
                or type(item["computer_entity_id"]) is not int or not 1 <= item["computer_entity_id"] <= 2**63 - 1
                or not isinstance(item["key_fingerprint"], str) or not re.fullmatch(r"[0-9a-f]{64}", item["key_fingerprint"])):
            raise AgentError("invalid_agent_batch_approval")
        request_id = uuid_text(item["request_id"])
        if request_id in bindings:
            raise AgentError("invalid_agent_batch_approval")
        bindings[request_id] = {**item, "host_id": uuid_text(item["host_id"]), "instance_name": instance_name(item["instance_name"])}
    return token_id, template_id, version, ids, bindings


def approve(cur, body, *, actor):
    token_id, template_id, version, ids, bindings = _approval_body(body)
    # Follow AG-DEP-1's token -> request -> host lock order, including revoke.
    cur.execute("select * from sli_agent_group_tokens where id=%s for update", (token_id,))
    group = cur.fetchone()
    if not group:
        raise AgentError("enrollment_token_not_found", 404)
    cur.execute("select * from sli_agent_policy_templates where id=%s and version=%s", (template_id, version))
    template = cur.fetchone()
    if not template:
        raise AgentError("agent_template_not_found", 404)
    if ids is None:
        cur.execute("select * from sli_agent_group_requests where token_id=%s and status='pending' order by id limit 1001 for update", (token_id,))
    else:
        cur.execute("select * from sli_agent_group_requests where token_id=%s and id=any(%s::uuid[]) order by id for update", (token_id, ids))
    requests = cur.fetchall()
    if len(requests) > MAX_BATCH:
        raise AgentError("agent_batch_size_limit")
    by_id = {str(row["id"]): row for row in requests}
    candidates = sorted(by_id) if ids is None else ids
    # Different batches can contain the same hosts. Acquire every host lock in
    # one order, so a large batch cannot deadlock another approval operation.
    for host in sorted({str(row["host_id"]) for row in requests if row["status"] == "pending"}):
        cur.execute("select pg_advisory_xact_lock(hashtext(%s))", ("sli-agent-host:" + host,))
    items = []
    for request_id in candidates:
        row = by_id.get(request_id)
        status = "rejected"
        reason = "request_not_pending"
        if row and row["status"] == "approved":
            status, reason = "already_approved", "already_approved"
        elif row and row["status"] == "pending":
            binding = bindings.get(request_id)
            if group["revoked_at"] or group["expires_at"] <= utcnow() + timedelta(seconds=60):
                reason = "batch_unavailable"
            elif not binding or any(binding[key] != (str(row[key]) if key == "host_id" else row[key])
                    for key in ("host_id", "instance_name", "key_fingerprint", "computer_entity_id")):
                reason = "key_identity_unverified"
            else:
                try:
                    from server.sli.agents.group_enrollment import check_scope
                    check_scope(cur, group, row["computer_entity_id"], resolve=_directory_entity)
                except AgentError:
                    reason = "directory_scope_rejected"
                else:
                    result = _prepare(cur, row, group, template, actor)
                    if result is not None:
                        items.append(result)
                        continue
                    reason = "host_conflict_or_expired"
        audit(cur, "onboarding_decision", actor, request_id, result=status, reason=reason, token_id=token_id,
              domain_id=group["domain_id"], ou_entity_ids=group["ou_entity_ids"])
        items.append({"request_id": request_id, "status": status, "reason": reason})
    audit(cur, "onboarding_batch", actor, token_id, result="processed", mode=body["mode"],
          domain_id=group["domain_id"], ou_entity_ids=group["ou_entity_ids"],
          approved=sum(item["status"] == "approved" for item in items),
          rejected=sum(item["status"] == "rejected" for item in items))
    return {"items": items}


def _prepare(cur, row, group, template, actor):
    host, request_id = str(row["host_id"]), str(row["id"])
    if row["instance_name"] is None:
        cur.execute("select id from sli_agents where host_id=%s", (host,))
    else:
        cur.execute("select id from sli_agents where host_id=%s and (instance_name=%s or key_fingerprint=%s)",
                    (host, row["instance_name"], row["key_fingerprint"]))
    if cur.fetchone() or group["expires_at"] <= utcnow() + timedelta(seconds=60):
        return None
    now = utcnow()
    expires = min(group["expires_at"], now + timedelta(seconds=900))
    raw, enrollment_id = secrets.token_urlsafe(32), str(uuid4())
    cur.execute("insert into sli_agent_enrollment_tokens(id,token_hash,host_id,key_fingerprint,created_at,expires_at,instance_name) "
                "values(%s,%s,%s,%s,%s,%s,%s)",
                (enrollment_id, token_hash(raw), host, row["key_fingerprint"], now, expires, row["instance_name"]))
    cur.execute("insert into sli_agent_onboarding_copies(enrollment_token_id,request_id,template_id,template_version) values(%s,%s,%s,%s)",
                (enrollment_id, request_id, str(template["id"]), template["version"]))
    cur.execute("update sli_agent_group_requests set status=%s where id=%s", ("approved", request_id))
    audit(cur, "onboarding_decision", actor, request_id, result="approved", token_id=str(group["id"]),
          domain_id=group["domain_id"], ou_entity_ids=group["ou_entity_ids"], template_id=str(template["id"]),
          template_version=template["version"], policy_sha256=template["policy_sha256"])
    # This secret is returned once, after commit, only to the authenticated
    # administrator for delivery through the trusted deployment channel.
    return {"request_id": request_id, "status": "approved", "token": raw, "expires_at": expires.isoformat()}


def copy_policy(cur, enrollment_token_id, agent_id):
    cur.execute("select t.* from sli_agent_onboarding_copies c join sli_agent_policy_templates t "
                "on t.id=c.template_id and t.version=c.template_version where c.enrollment_token_id=%s", (enrollment_token_id,))
    template = cur.fetchone()
    if not template:
        return False
    # JSON serialization produces a personal copy; later template versions and
    # other agents cannot modify this agent's desired or applied revision.
    cur.execute("update sli_agents set assigned_modules=%s::jsonb,collection_policy=%s::jsonb,"
                "template_id=%s,template_version=%s,template_sha256=%s where id=%s",
                (json.dumps(template["assigned_modules"]), json.dumps(template["collection_policy"]),
                 str(template["id"]), template["version"], template["policy_sha256"], agent_id))
    cur.execute("insert into sli_agent_policy_history(agent_id,revision,assigned_modules,collection_policy) values(%s,1,%s::jsonb,%s::jsonb)",
                (agent_id, json.dumps(template["assigned_modules"]), json.dumps(template["collection_policy"])))
    audit(cur, "template_copy", "enrollment:" + str(enrollment_token_id), agent_id, result="copied", revision=1,
          template_id=str(template["id"]), template_version=template["version"], policy_sha256=template["policy_sha256"])
    return True
