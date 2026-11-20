"""Filtered, administrator-attested approval; never trust agent AD claims alone."""
from __future__ import annotations

import re
import secrets
from datetime import timedelta
from uuid import uuid4

from server.sli.agents import group_enrollment, registry
from server.sli.agents.ca import AgentError, utcnow, uuid_text

MAX_BATCH = 1000


def resolve_group(cur, body):
    if "group_id" in body:
        if "domain_id" in body or "ou_entity_ids" in body:
            raise AgentError("invalid_group_enrollment_scope")
        group_id = uuid_text(body["group_id"])
        cur.execute("select * from sli_agent_enrollment_groups where id=%s", (group_id,))
        row = cur.fetchone()
        if not row:
            raise AgentError("agent_group_not_found", 404)
        return group_id, row["domain_id"], row["ou_entity_ids"]
    domain = group_enrollment._positive_id(body.get("domain_id"))
    ous = body.get("ou_entity_ids", [])
    if not isinstance(ous, list) or len(ous) > 128:
        raise AgentError("invalid_group_enrollment_scope")
    ous = sorted({group_enrollment._positive_id(value) for value in ous})
    for ou in ous:
        group_enrollment._directory_entity(cur, ou, domain, ou=True)
    group_id = str(uuid4())
    cur.execute("insert into sli_agent_enrollment_groups(id,domain_id,ou_entity_ids) values(%s,%s,%s)",
                (group_id, domain, ous))
    return group_id, domain, ous


def _filter(body):
    if not isinstance(body, dict) or set(body) != {"group_id", "token_id"}:
        raise AgentError("invalid_agent_batch_filter")
    return uuid_text(body["group_id"]), uuid_text(body["token_id"])


def list_pending(cur, body, *, actor):
    group_id, token_id = _filter(body)
    cur.execute("""select r.id,r.host_id,r.instance_name,r.key_fingerprint,r.computer_entity_id,r.computer_version_id
        from sli_agent_group_requests r join sli_agent_group_tokens t on t.id=r.token_id
        where t.group_id=%s and t.id=%s and r.status='pending' order by r.id limit 1001""", (group_id, token_id))
    rows = [dict(row) for row in cur.fetchall()]
    registry.audit(cur, "group_pending_list", actor, group_id, token_id=token_id, result="listed")
    return {"items": rows[:MAX_BATCH], "has_more": len(rows) > MAX_BATCH}


def _bindings(evidence):
    if not isinstance(evidence, list) or not 1 <= len(evidence) <= MAX_BATCH:
        raise AgentError("invalid_agent_batch_evidence")
    bindings = {}
    for item in evidence:
        if (not isinstance(item, dict) or set(item) != {"request_id", "host_id", "instance_name", "key_fingerprint", "computer_entity_id"}
                or not isinstance(item["key_fingerprint"], str) or not re.fullmatch(r"[0-9a-f]{64}", item["key_fingerprint"])):
            raise AgentError("invalid_agent_batch_evidence")
        request_id = uuid_text(item["request_id"])
        if request_id in bindings:
            raise AgentError("invalid_agent_batch_evidence")
        bindings[request_id] = {**item, "host_id": uuid_text(item["host_id"]),
            "instance_name": registry.instance_name(item["instance_name"]),
            "computer_entity_id": group_enrollment._positive_id(item["computer_entity_id"])}
    return bindings


def approve(cur, body, *, actor):
    if not isinstance(body, dict) or set(body) != {"filter", "evidence"}:
        raise AgentError("invalid_agent_batch_filter")
    group_id, token_id = _filter(body["filter"])
    bindings = _bindings(body["evidence"])
    # The group-token lock serializes admission, approval, withdrawal and issue.
    cur.execute("select * from sli_agent_group_tokens where id=%s and group_id=%s for update", (token_id, group_id))
    group = cur.fetchone()
    if not group:
        raise AgentError("enrollment_token_not_found", 404)
    cur.execute("""select * from sli_agent_group_requests
        where token_id=%s and id=any(%s::uuid[]) order by id for update""", (token_id, sorted(bindings)))
    rows = {str(row["id"]): row for row in cur.fetchall()}
    # One order for overlapping hosts in independent batches avoids deadlocks.
    for host in sorted({str(row["host_id"]) for row in rows.values() if row["status"] == "pending"}):
        cur.execute("select pg_advisory_xact_lock(hashtext(%s))", ("sli-agent-host:" + host,))
    results = []
    for request_id, binding in sorted(bindings.items()):
        row = rows.get(request_id)
        reason, status = "request_not_pending", "rejected"
        if row and row["status"] == "approved":
            status, reason = "already_approved", "already_approved"
        elif row and row["status"] == "pending":
            if group["revoked_at"] or group["expires_at"] <= utcnow() + timedelta(seconds=60):
                reason = "batch_unavailable"
            elif any(binding[key] != (str(row[key]) if key == "host_id" else row[key])
                     for key in ("host_id", "instance_name", "key_fingerprint", "computer_entity_id")):
                reason = "key_identity_unverified"
            else:
                try:
                    group_enrollment.check_scope(cur, group, row["computer_entity_id"])
                except AgentError:
                    reason = "directory_scope_rejected"
                else:
                    from server.sli.agents.deployment_scope import template_for
                    template = template_for(cur, group)
                    if template:
                        from server.sli.agents.onboarding import _prepare
                        prepared = _prepare(cur, row, group, template, actor)
                        if prepared:
                            results.append(prepared)
                            continue
                        registry.audit(cur, "group_approval", actor, request_id, result="rejected",
                                       reason="host_conflict_or_expired", group_id=group_id, token_id=token_id)
                        results.append({"request_id": request_id, "status": "rejected", "reason": "host_conflict_or_expired"})
                        continue
                    host = str(row["host_id"])
                    if row["instance_name"] is None:
                        cur.execute("select id from sli_agents where host_id=%s", (host,))
                    else:
                        cur.execute("select id from sli_agents where host_id=%s and (instance_name=%s or key_fingerprint=%s)",
                                    (host, row["instance_name"], row["key_fingerprint"]))
                    # Recheck expiry after host and directory lock waits.
                    if cur.fetchone() or group["expires_at"] <= utcnow() + timedelta(seconds=60):
                        reason = "host_conflict_or_expired"
                    else:
                        now = utcnow()
                        expires = min(group["expires_at"], now + timedelta(seconds=900))
                        if expires >= now + timedelta(seconds=60):
                            raw, enrollment_id = secrets.token_urlsafe(32), str(uuid4())
                            cur.execute("""insert into sli_agent_enrollment_tokens
                                (id,token_hash,host_id,key_fingerprint,created_at,expires_at,instance_name)
                                values(%s,%s,%s,%s,%s,%s,%s)""",
                                (enrollment_id, registry.token_hash(raw), host, row["key_fingerprint"], now, expires, row["instance_name"]))
                            registry.audit(cur, "token_create", actor, enrollment_id, group_id=group_id,
                                           ttl_seconds=int((expires - now).total_seconds()))
                            cur.execute("insert into sli_agent_group_approvals(request_id,enrollment_token_id) values(%s,%s)",
                                        (request_id, enrollment_id))
                            cur.execute("update sli_agent_group_requests set status='approved' where id=%s", (request_id,))
                            registry.audit(cur, "group_approval", actor, request_id, result="approved", group_id=group_id, token_id=token_id)
                            results.append({"request_id": request_id, "status": "approved", "token": raw,
                                            "expires_at": expires.isoformat()})
                            continue
                        reason = "batch_unavailable"
        registry.audit(cur, "group_approval", actor, request_id, result=status, reason=reason, group_id=group_id, token_id=token_id)
        results.append({"request_id": request_id, "status": status, "reason": reason})
    registry.audit(cur, "group_approval_batch", actor, group_id, token_id=token_id, result="processed",
                   approved=sum(item["status"] == "approved" for item in results),
                   rejected=sum(item["status"] == "rejected" for item in results))
    # Key-bound tokens are returned once to the administrator, only after commit.
    return {"items": results}


def lock_approval(cur, digest):
    cur.execute("""select r.token_id,r.computer_entity_id,r.instance_name from sli_agent_group_approval_links a
        join sli_agent_group_requests r on r.id=a.request_id
        join sli_agent_enrollment_tokens e on e.id=a.enrollment_token_id where e.token_hash=%s""", (digest,))
    row = cur.fetchone()
    if row:
        cur.execute("select * from sli_agent_group_tokens where id=%s for update", (row["token_id"],))
        group = cur.fetchone()
        if not group or group["revoked_at"] or group["expires_at"] <= utcnow():
            raise AgentError("enrollment_token_rejected", 401)
        group_enrollment.check_scope(cur, group, row["computer_entity_id"])
        # A second host/key claiming the same directory computer must not get
        # another certificate, including through a different deployment batch.
        cur.execute("select pg_advisory_xact_lock(hashtext(%s))",
            (f"sli-agent-computer:{row['computer_entity_id']}:{row['instance_name'] or ''}",))
        cur.execute("""select issued.target from sli_agent_audit issued
            join sli_agent_group_approval_links a on issued.actor='enrollment:' || a.enrollment_token_id::text
            join sli_agent_group_requests r on r.id=a.request_id
            where issued.action='issue' and r.computer_entity_id=%s
              and r.instance_name is not distinct from %s limit 1""",
            (row["computer_entity_id"], row["instance_name"]))
        if cur.fetchone():
            raise AgentError("enrollment_token_rejected", 401)


def release_approval(cur, group, row, *, actor):
    """Deliver only an existing administrator-attested approval to its CSR key.

    A retry rotates the unused token, retaining its profile copy and membership.
    No pending request, claimed name or directory match can create an approval.
    """
    group_enrollment.check_scope(cur, group, row["computer_entity_id"])
    cur.execute("select pg_advisory_xact_lock(hashtext(%s))", ("sli-agent-host:" + str(row["host_id"]),))
    now = utcnow()
    if group["revoked_at"] or group["expires_at"] <= now + timedelta(seconds=60):
        raise AgentError("group_enrollment_rejected", 401)
    raw = secrets.token_urlsafe(32)
    expires = min(group["expires_at"], now + timedelta(seconds=900))
    cur.execute("""update sli_agent_enrollment_tokens e set token_hash=%s,created_at=%s,expires_at=%s
        from sli_agent_group_approval_links a where a.enrollment_token_id=e.id and a.request_id=%s
          and e.host_id=%s and e.key_fingerprint=%s and e.instance_name is not distinct from %s
          and e.used_at is null and e.revoked_at is null
          and %s>clock_timestamp()+interval '60 seconds' returning e.id""",
        (registry.token_hash(raw), now, expires, str(row["id"]), str(row["host_id"]),
         row["key_fingerprint"], row["instance_name"], group["expires_at"]))
    if not cur.fetchone():
        raise AgentError("group_enrollment_rejected", 401)
    registry.audit(cur, "group_approval_delivery", actor, str(row["id"]), result="approved", token_id=str(group["id"]))
    return {"request_id": str(row["id"]), "status": "approved", "token": raw, "expires_at": expires.isoformat()}


def record_membership(cur, enrollment_token_id, agent_id):
    cur.execute("""insert into sli_agent_group_members(agent_id,group_id)
        select %s,t.group_id from sli_agent_group_approval_links a
        join sli_agent_group_requests r on r.id=a.request_id
        join sli_agent_group_tokens t on t.id=r.token_id where a.enrollment_token_id=%s""", (agent_id, enrollment_token_id))
