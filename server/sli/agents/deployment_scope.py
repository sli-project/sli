"""Accepted AD selection and opt-in, independently key-attested onboarding."""
from __future__ import annotations

import json
import re
import secrets
from datetime import timedelta

from server.sli.agents import group_enrollment as groups, onboarding, registry
from server.sli.agents.ca import AgentError, utcnow, uuid_text


def encode(value):
    return json.dumps(value)


def directory(cur, body):
    if not isinstance(body, dict) or set(body) - {"domain_id", "ou_entity_ids"}:
        raise AgentError("invalid_group_enrollment_scope")
    if "domain_id" not in body:
        cur.execute("""select distinct d.id,d.fqdn as name from domains d
            join ad_context_runs r on r.domain_id=d.id
            join ad_context_sections s on s.run_id=r.run_id
            where r.status='completed' and s.section_name='directory_accounts' and s.status='complete'
            order by d.id limit 1000""")
        return {"domains": [dict(row) for row in cur.fetchall()]}
    domain = groups._positive_id(body["domain_id"])
    ous = body.get("ou_entity_ids", [])
    if not isinstance(ous, list) or len(ous) > 128:
        raise AgentError("invalid_group_enrollment_scope")
    ou_dns = [groups._directory_entity(cur, groups._positive_id(ou), domain, ou=True)[1] for ou in ous]
    cur.execute("""select e.id as entity_id,v.id as version_id,v.attributes_json as record,v.source_section
        from ad_context_entity_versions v join entities_v2 e on e.id=v.entity_id
        join ad_context_runs r on r.run_id=v.source_run_id and r.domain_id=e.domain_id
        join ad_context_sections s on s.run_id=r.run_id and s.section_name=v.source_section
        where e.domain_id=%s and v.valid_to_utc is null and r.status='completed' and s.status='complete'
          and v.source_section in ('directory_accounts','domain_posture')
          and v.last_observed_at_utc between clock_timestamp()-interval '24 hours' and clock_timestamp()
        order by e.id limit 10001""", (domain,))
    rows = cur.fetchall()
    items, units = [], []
    for row in rows[:10000]:
        ou = row["source_section"] == "domain_posture"
        try:
            _, dn = groups._directory_record(row, ou=ou)
        except AgentError:
            continue
        item = {"id": row["entity_id"], "version_id": row["version_id"],
                "name": row["record"]["attributes"]["distinguished_name"]}
        if ou:
            units.append(item)
        elif not ou_dns or any(len(dn) > len(unit) and dn[-len(unit):] == unit for unit in ou_dns):
            items.append(item)
    return {"computers": items, "ous": units, "has_more": len(rows) > 10000}


def enrollment_policy(cur, body, domain, ous):
    selected = body.get("computer_entity_ids", [])
    if not isinstance(selected, list) or len(selected) > 1000:
        raise AgentError("invalid_group_enrollment_scope")
    selected = sorted({groups._positive_id(value) for value in selected})
    scope = {"domain_id": domain, "ou_entity_ids": ous, "computer_entity_ids": selected}
    for computer in selected:
        groups.check_scope(cur, scope, computer)
    policy = {}
    if "template_id" in body or "template_version" in body:
        policy = {"template_id": uuid_text(body.get("template_id")),
                  "template_version": onboarding._version(body.get("template_version"))}
        template_for(cur, {"enrollment_policy": policy})
    enabled = body.get("auto_approve", False)
    if type(enabled) is not bool:
        raise AgentError("invalid_agent_auto_approval")
    bindings = body.get("trusted_bindings", [])
    if not isinstance(bindings, list) or len(bindings) > 1000 or not enabled and bindings:
        raise AgentError("invalid_agent_auto_approval")
    if enabled:
        if not policy or not bindings:
            raise AgentError("invalid_agent_auto_approval")
        normalized, seen = [], set()
        for item in bindings:
            if (not isinstance(item, dict) or set(item) != {"host_id", "instance_name", "key_fingerprint", "computer_entity_id"}
                    or not isinstance(item["key_fingerprint"], str) or not re.fullmatch(r"[0-9a-f]{64}", item["key_fingerprint"])):
                raise AgentError("invalid_agent_auto_approval")
            binding = {**item, "host_id": uuid_text(item["host_id"]),
                       "instance_name": registry.instance_name(item["instance_name"]),
                       "computer_entity_id": groups._positive_id(item["computer_entity_id"])}
            identity = (binding["host_id"], binding["instance_name"])
            if identity in seen:
                raise AgentError("invalid_agent_auto_approval")
            seen.add(identity)
            groups.check_scope(cur, scope, binding["computer_entity_id"])
            normalized.append(binding)
        policy.update(auto_approve=True, trusted_bindings=normalized)
    return selected, policy


def template_for(cur, token):
    policy = token.get("enrollment_policy", {})
    if "template_id" not in policy:
        return None
    cur.execute("select * from sli_agent_policy_templates where id=%s and version=%s",
                (policy["template_id"], policy["template_version"]))
    template = cur.fetchone()
    if not template:
        raise AgentError("agent_template_not_found", 404)
    return template


def auto_approve(cur, token, row, *, actor):
    policy = token.get("enrollment_policy", {})
    if not policy.get("auto_approve"):
        return None
    if not any(all(binding[key] == (str(row[key]) if key == "host_id" else row[key]) for key in binding)
               for binding in policy["trusted_bindings"]):
        return None
    # Never use the agent's directory claim as proof of key ownership.
    groups.check_scope(cur, token, row["computer_entity_id"])
    if token["revoked_at"] or token["expires_at"] <= utcnow() + timedelta(seconds=60):
        raise AgentError("group_enrollment_rejected", 401)
    cur.execute("select pg_advisory_xact_lock(hashtext(%s))", ("sli-agent-host:" + str(row["host_id"]),))
    if token["expires_at"] <= utcnow() + timedelta(seconds=60):
        raise AgentError("group_enrollment_rejected", 401)
    if row["status"] == "approved":
        # A lost response can be retried with the same signed CSR. Rotate only
        # the unused credential, keeping its immutable template and membership.
        raw, now = secrets.token_urlsafe(32), utcnow()
        expires = min(token["expires_at"], now + timedelta(seconds=900))
        cur.execute("""update sli_agent_enrollment_tokens e set token_hash=%s,created_at=%s,expires_at=%s
            from sli_agent_onboarding_copies c where c.enrollment_token_id=e.id and c.request_id=%s
              and e.used_at is null and e.revoked_at is null returning e.id""",
            (registry.token_hash(raw), now, expires, str(row["id"])))
        if not cur.fetchone():
            raise AgentError("group_enrollment_rejected", 401)
        result = {"request_id": str(row["id"]), "status": "approved", "token": raw, "expires_at": expires.isoformat()}
    else:
        result = onboarding._prepare(cur, row, token, template_for(cur, token), actor)
        if result is None:
            raise AgentError("group_enrollment_rejected", 401)
    registry.audit(cur, "group_auto_approval", actor, str(row["id"]), result="approved", token_id=str(token["id"]))
    return result
