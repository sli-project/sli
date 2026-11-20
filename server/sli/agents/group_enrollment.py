"""Group admission; an explicit key-attested rule can prepare approval tokens.

An AD match establishes eligibility only. Key-to-machine verification and
approval require an authenticated administrative operation or its trusted rule.
max_uses bounds distinct submissions; replay consumes no extra slot.
Callers commit before returning tokens or request IDs, including denied audits.
"""
from __future__ import annotations

import secrets
from datetime import timedelta
from uuid import uuid4

from server.sli.agents.ca import AgentError, fingerprint, parse_csr, utcnow, uuid_text
from server.sli.agents.registry import audit, instance_name, token_hash


class AuditedRejection(AgentError):
    """Validation failed without writes other than a denial audit."""


def _positive_id(value):
    if type(value) is not int or not 1 <= value <= 2**63 - 1:
        raise AgentError("invalid_group_enrollment_scope")
    return value


def _dn_parts(value):
    # Split only unescaped RDN boundaries. Ambiguous/malformed DNs fail closed;
    # equivalent spellings may require a fresh canonical snapshot.
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        raise AgentError("invalid_group_enrollment_scope")
    parts, current, escaped = [], [], False
    for char in value:
        if char == "," and not escaped:
            parts.append("".join(current).strip().casefold())
            current = []
            continue
        current.append(char)
        escaped = char == "\\" and not escaped
    if escaped:
        raise AgentError("invalid_group_enrollment_scope")
    parts.append("".join(current).strip().casefold())
    if any("=" not in part or not part.split("=", 1)[1] for part in parts):
        raise AgentError("invalid_group_enrollment_scope")
    return parts


def _directory_entity(cur, entity_id, domain_id, *, ou=False):
    section = "domain_posture" if ou else "directory_accounts"
    cur.execute("""select v.id as version_id,v.attributes_json as record
        from ad_context_entity_versions v
        join entities_v2 e on e.id=v.entity_id
        join ad_context_runs r on r.run_id=v.source_run_id and r.domain_id=e.domain_id
        join ad_context_sections s on s.run_id=r.run_id and s.section_name=v.source_section
        where e.id=%s and e.domain_id=%s and v.source_section=%s
          and v.valid_to_utc is null and r.status='completed' and s.status='complete'
          and v.last_observed_at_utc between clock_timestamp()-interval '24 hours' and clock_timestamp()""",
        (entity_id, domain_id, section))
    row = cur.fetchone()
    if not row:
        raise AgentError("invalid_group_enrollment_scope")
    return _directory_record(row, ou=ou)


def _directory_record(row, *, ou=False):
    record = row["record"]
    attrs = record.get("attributes", {})
    kind = record.get("identity", {}).get("kind")
    if (ou and (kind != "security_principal" or attrs.get("infrastructure_role") != "organizational_unit")) or (
        not ou and (kind != "ad_computer" or attrs.get("enabled") is not True)
    ):
        raise AgentError("invalid_group_enrollment_scope")
    dn = _dn_parts(attrs.get("distinguished_name"))
    if ou and not dn[0].startswith("ou="):
        raise AgentError("invalid_group_enrollment_scope")
    return row["version_id"], dn


def check_scope(cur, token, computer_id, *, resolve=None):
    resolve = resolve or _directory_entity
    version, dn = resolve(cur, computer_id, token["domain_id"])
    selected = token.get("computer_entity_ids", [])
    if selected and computer_id not in selected:
        raise AgentError("invalid_group_enrollment_scope")
    ous = token["ou_entity_ids"]
    if ous and not any(len(dn) > len(ou_dn) and dn[-len(ou_dn):] == ou_dn
                       for ou_dn in (resolve(cur, ou, token["domain_id"], ou=True)[1] for ou in ous)):
        raise AgentError("invalid_group_enrollment_scope")
    return version


def create_token(cur, body: dict, *, actor: str):
    from server.sli.agents.group_deployment import resolve_group
    if not isinstance(body, dict) or set(body) - {"ttl_seconds", "max_uses", "group_id", "domain_id", "ou_entity_ids",
                                                "computer_entity_ids", "template_id", "template_version", "auto_approve", "trusted_bindings"}:
        raise AgentError("invalid_group_enrollment_scope")
    ttl = body.get("ttl_seconds", 3600)
    maximum = body.get("max_uses")
    if type(ttl) is not int or not 60 <= ttl <= 604800:
        raise AgentError("invalid_enrollment_ttl")
    if type(maximum) is not int or not 1 <= maximum <= 10000:
        raise AgentError("invalid_group_enrollment_limit")
    group_id, domain_id, ous = resolve_group(cur, body)
    for entity_id in ous:
        _directory_entity(cur, entity_id, domain_id, ou=True)
    from server.sli.agents import deployment_scope
    selected, policy = deployment_scope.enrollment_policy(cur, body, domain_id, ous)
    raw, token_id, now = secrets.token_urlsafe(32), str(uuid4()), utcnow()
    expires = now + timedelta(seconds=ttl)
    cur.execute("""insert into sli_agent_group_tokens
        (id,token_hash,created_at,expires_at,max_uses,domain_id,ou_entity_ids,group_id,computer_entity_ids,enrollment_policy)
        values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)""",
        (token_id, token_hash(raw), now, expires, maximum, domain_id, ous, group_id, selected, deployment_scope.encode(policy)))
    audit(cur, "group_token_create", actor, token_id, result="created", group_id=group_id, ttl_seconds=ttl, max_uses=maximum)
    return {"id": token_id, "group_id": group_id, "token": raw, "expires_at": expires.isoformat(), "max_uses": maximum}


def list_tokens(cur, *, actor: str):
    cur.execute("""select id,created_at,expires_at,max_uses,uses_count,domain_id,ou_entity_ids,revoked_at,group_id,computer_entity_ids,
        coalesce((enrollment_policy->>'auto_approve')::boolean,false) as auto_approve
        from sli_agent_group_tokens order by created_at desc,id limit 100""")
    items = [dict(row) for row in cur.fetchall()]
    audit(cur, "group_token_list", actor, "group_tokens", result="listed")
    return {"items": items}


def revoke_token(cur, value, *, actor: str):
    token_id = uuid_text(value)
    cur.execute("""update sli_agent_group_tokens set revoked_at=coalesce(revoked_at,clock_timestamp())
        where id=%s returning id""", (token_id,))
    if not cur.fetchone():
        raise AgentError("enrollment_token_not_found", 404)
    cur.execute("""update sli_agent_enrollment_tokens e set revoked_at=coalesce(e.revoked_at,clock_timestamp())
        from sli_agent_group_approval_links a join sli_agent_group_requests r on r.id=a.request_id
        where e.id=a.enrollment_token_id and r.token_id=%s and e.used_at is null""", (token_id,))
    cur.execute("""update sli_agent_group_requests r set status='cancelled'
        from sli_agent_group_approval_links a join sli_agent_enrollment_tokens e on e.id=a.enrollment_token_id
        where r.id=a.request_id and r.token_id=%s and r.status='approved' and e.used_at is null""", (token_id,))
    cur.execute("update sli_agent_group_requests set status='cancelled' where token_id=%s and status='pending'", (token_id,))
    audit(cur, "group_token_revoke", actor, token_id, result="revoked")
    return {"status": "revoked"}


def submit(cur, body: dict):
    target, actor = "group_tokens", "enrollment:group"
    try:
        digest = token_hash(body.get("token"))
        # The token row serializes both deduplication and capacity through commit.
        cur.execute("select * from sli_agent_group_tokens where token_hash=%s for update", (digest,))
        token = cur.fetchone()
        if not token:
            raise AgentError("group_enrollment_rejected", 401)
        target = str(token["id"])
        actor = "enrollment:" + target
        if token["revoked_at"] or token["expires_at"] <= utcnow():
            raise AgentError("group_enrollment_rejected", 401)
        if set(body) - {"token", "host_id", "instance_name", "csr_pem", "computer_entity_id"}:
            raise AgentError("group_enrollment_rejected", 401)
        host_id = uuid_text(body.get("host_id"))
        instance = instance_name(body.get("instance_name"))
        computer_id = _positive_id(body.get("computer_entity_id"))
        csr = parse_csr(body.get("csr_pem"), host_id)
        key_fp = fingerprint(csr.public_key())
        cur.execute("""select id,host_id,computer_entity_id,status from sli_agent_group_requests
            where token_id=%s and key_fingerprint=%s and instance_name is not distinct from %s""",
            (target, key_fp, instance))
        previous = cur.fetchone()
        if previous:
            if str(previous["host_id"]) != host_id or previous["computer_entity_id"] != computer_id or previous["status"] == "cancelled":
                raise AgentError("group_enrollment_rejected", 401)
            if previous["status"] == "approved" and not token.get("enrollment_policy", {}).get("auto_approve"):
                from server.sli.agents.group_deployment import release_approval
                return release_approval(cur, token, {**previous, "key_fingerprint": key_fp,
                    "instance_name": instance}, actor=actor)
            from server.sli.agents.deployment_scope import auto_approve
            approved = auto_approve(cur, token, {**previous, "key_fingerprint": key_fp, "instance_name": instance}, actor=actor)
            if approved:
                return approved
            if previous["status"] != "pending":
                raise AgentError("group_enrollment_rejected", 401)
            audit(cur, "group_request", actor, target, result="replayed", request_id=str(previous["id"]))
            return {"request_id": str(previous["id"]), "status": "pending"}
        version_id = check_scope(cur, token, computer_id)
        cur.execute("select pg_advisory_xact_lock(hashtext(%s))", ("sli-agent-host:" + host_id,))
        if instance is None:
            cur.execute("select id from sli_agents where host_id=%s", (host_id,))
        else:
            cur.execute("select id from sli_agents where host_id=%s and (instance_name=%s or key_fingerprint=%s)",
                        (host_id, instance, key_fp))
        if cur.fetchone():
            raise AgentError("group_enrollment_rejected", 401)
        # Recheck expiry in PostgreSQL after every possible lock wait.
        cur.execute("""update sli_agent_group_tokens set uses_count=uses_count+1
            where id=%s and revoked_at is null and expires_at>clock_timestamp() and uses_count<max_uses
            returning id""", (target,))
        if not cur.fetchone():
            raise AgentError("group_enrollment_rejected", 401)
    except AgentError:
        # No denial includes claimed names, AD contents, CSR, token or its hash.
        audit(cur, "group_request", actor, target, result="rejected")
        raise AuditedRejection("group_enrollment_rejected", 401) from None
    request_id = str(uuid4())
    cur.execute("""insert into sli_agent_group_requests
        (id,token_id,host_id,instance_name,key_fingerprint,computer_entity_id,computer_version_id)
        values(%s,%s,%s,%s,%s,%s,%s)""", (request_id, target, host_id, instance, key_fp, computer_id, version_id))
    audit(cur, "group_request", actor, target, result="pending", request_id=request_id)
    from server.sli.agents.deployment_scope import auto_approve
    approved = auto_approve(cur, token, {"id": request_id, "host_id": host_id, "instance_name": instance,
        "key_fingerprint": key_fp, "computer_entity_id": computer_id, "status": "pending"}, actor=actor)
    if approved:
        return approved
    return {"request_id": request_id, "status": "pending"}
