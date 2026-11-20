"""Credential-bound, durable GPO intentions. AD writes remain disabled."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import timedelta
from uuid import uuid4

from server.sli.agents import group_enrollment as groups
from server.sli.agents import gpo_plan_credentials as credentials
from server.sli.agents.ca import AgentError, utcnow, uuid_text


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _audit(cur, actor, domain, action, *, plan_id=None, result="ok", binding=None, expires=None):
    # No names, DNs, SIDs, package paths or enrollment credentials in audit.
    binding = binding or {}
    recipient = binding.get("recipient", {})
    cur.execute("""insert into sli_agent_gpo_plan_audit(actor,domain_id,action,plan_id,result,
        credential_id,credential_revision,recipient_agent_id,recipient_certificate_sha256,expires_at)
        values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""", (actor, domain, action, plan_id, result,
        binding.get("credential_id"), binding.get("credential_revision"), recipient.get("agent_id"),
        recipient.get("certificate_sha256"), expires))


def _reject(cur, actor, domain, reason, *, plan_id=None, status=403):
    _audit(cur, actor, domain, "denied", plan_id=plan_id, result=reason)
    raise groups.AuditedRejection(reason, status)


def _scope(cur, actor, domain, action):
    # A platform owner has no implicit deployment assignment. No AD grants here.
    cur.execute("select public.sli_agent_gpo_plan_scope(%s,%s,%s) as scope", (actor, domain, action))
    scope = cur.fetchone()["scope"]
    if not scope:
        _reject(cur, actor, domain, "gpo_deployment_denied")
    if not scope.get("revision"):
        _reject(cur, actor, domain, "gpo_scope_unavailable", status=409)
    try:
        ad_ous = credentials.scope(cur, actor, domain)
    except groups.AuditedRejection:
        raise
    except AgentError as exc:
        _reject(cur, actor, domain, str(exc), status=exc.status)
    allowed = sorted(set(scope["grant_ou_entity_ids"]) & set(scope["ou_entity_ids"]) & set(ad_ous))
    if not allowed:
        _reject(cur, actor, domain, "gpo_deployment_denied")
    return scope, allowed


def _ids(value, maximum):
    if not isinstance(value, list) or not 1 <= len(value) <= maximum:
        raise AgentError("gpo_selection_invalid")
    return sorted({groups._positive_id(item) for item in value})


def _within(dn, unit):
    return len(dn) > len(unit) and dn[-len(unit):] == unit


def _package(value):
    if value == {}:
        return {}
    keys = {"version", "sha256", "size_bytes", "signature"}
    if (not isinstance(value, dict) or not keys <= set(value) or set(value) - keys - {"signer_sha256"}
            or not isinstance(value["version"], str) or not re.fullmatch(r"[A-Za-z0-9_.+-]{1,64}", value["version"])
            or not isinstance(value["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["sha256"])
            or type(value["size_bytes"]) is not int or value["size_bytes"] <= 0
            or value["signature"] not in ("valid", "invalid", "unavailable")
            or "signer_sha256" in value and (not isinstance(value["signer_sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", value["signer_sha256"]))):
        raise AgentError("gpo_package_unavailable", 409)
    return value


def _snapshot(cur, actor, domain, selection, action):
    scope, allowed = _scope(cur, actor, domain, action)
    ous = selection["ou_entity_ids"] or allowed
    if not set(ous) <= set(allowed):
        _reject(cur, actor, domain, "gpo_deployment_denied")
    units = {ou: groups._directory_entity(cur, ou, domain, ou=True) for ou in ous}
    if any(any(part == "ou=domain controllers" for part in dn) for _, dn in units.values()):
        _reject(cur, actor, domain, "gpo_target_excluded", status=409)
    # OU selection is expanded once into a finite list. Never silently truncate.
    if selection["computer_entity_ids"]:
        ids = selection["computer_entity_ids"]
    else:
        cur.execute("""select e.id as entity_id,v.id as version_id,v.attributes_json as record
            from ad_context_entity_versions v join entities_v2 e on e.id=v.entity_id
            join ad_context_runs r on r.run_id=v.source_run_id and r.domain_id=e.domain_id
            join ad_context_sections s on s.run_id=r.run_id and s.section_name=v.source_section
            where e.domain_id=%s and v.valid_to_utc is null and r.status='completed'
              and s.status='complete' and v.source_section='directory_accounts'
              and v.last_observed_at_utc between clock_timestamp()-interval '24 hours' and clock_timestamp()
            order by e.id""", (domain,))
        ids = []
        for row in cur.fetchall():
            record = row["record"]
            if record.get("identity", {}).get("kind") != "ad_computer" or record.get("attributes", {}).get("enabled") is not True:
                continue
            _, dn = groups._directory_record(row)
            if any(_within(dn, unit) for _, unit in units.values()):
                ids.append(row["entity_id"])
                if len(ids) > 1000:
                    raise AgentError("gpo_target_limit", 409)
    if not ids:
        raise AgentError("gpo_selection_empty", 409)
    targets, names, used_ous, seen = [], [], set(), set()
    for entity in ids:
        version, dn = groups._directory_entity(cur, entity, domain)
        if not any(_within(dn, unit) for _, unit in units.values()):
            _reject(cur, actor, domain, "gpo_deployment_denied")
        used_ous.update(ou for ou, (_, unit) in units.items() if _within(dn, unit))
        cur.execute("select attributes_json from ad_context_entity_versions where id=%s", (version,))
        record = cur.fetchone()["attributes_json"]
        attrs, identity = record["attributes"], record["identity"]
        uac = attrs.get("user_account_control")
        if type(uac) is not int or uac & 8192 or any(part == "ou=domain controllers" for part in dn):
            _reject(cur, actor, domain, "gpo_target_excluded", status=409)
        guid, sid = uuid_text(identity.get("object_guid")), identity.get("object_sid")
        if (not isinstance(sid, str) or not re.fullmatch(r"S-1-5-21-\d+-\d+-\d+-\d+", sid)
                or guid == "00000000-0000-0000-0000-000000000000" or guid in seen or sid in seen):
            raise AgentError("gpo_identity_unavailable", 409)
        seen.update((guid, sid))
        targets.append({"entity_id": entity, "version_id": version, "identity_sha256": _hash([guid, sid, dn])})
        names.append({"entity_id": entity, "name": attrs.get("display_name") or attrs["distinguished_name"]})
    # Scope revision and evidence hash bind the package/preflight/GPO readback.
    selection["ou_entity_ids"] = sorted(used_ous)
    snapshot = {"domain_id": domain, "ou_versions": [[ou, units[ou][0]] for ou in sorted(used_ous)],
        "targets": targets, "scope_revision": scope["revision"],
        "grant_ou_entity_ids": sorted(scope["grant_ou_entity_ids"]),
        "grant_permissions": sorted(scope["grant_permissions"]),
        "evidence_sha256": scope["evidence_sha256"], "package": _package(scope["package"])}
    return snapshot, names


def _checked_snapshot(cur, actor, domain, selection, action, *, plan_id=None):
    try:
        snapshot, names = _snapshot(cur, actor, domain, selection, action)
        snapshot["credential_binding"] = credentials.bind(cur, actor, domain,
            selection.get("credential_id"), selection.get("credential_revision"), selection["ou_entity_ids"])
        return snapshot, names
    except groups.AuditedRejection:
        raise
    except AgentError as exc:
        _reject(cur, actor, domain, str(exc), plan_id=plan_id, status=exc.status)


def _selection(body, *, with_credential=True):
    if (not isinstance(body, dict) or set(body) - {"domain_id", "ou_entity_ids", "computer_entity_ids",
            "credential_id", "credential_revision"}
            or with_credential and not {"credential_id", "credential_revision"} <= set(body)
            or not with_credential and set(body) & {"credential_id", "credential_revision"}):
        raise AgentError("gpo_selection_invalid")
    domain = groups._positive_id(body.get("domain_id"))
    ous, computers = body.get("ou_entity_ids", []), body.get("computer_entity_ids", [])
    if not isinstance(ous, list) or not isinstance(computers, list) or not ous and not computers:
        raise AgentError("gpo_selection_invalid")
    selection = {"ou_entity_ids": _ids(ous, 128) if ous else [],
        "computer_entity_ids": _ids(computers, 1000) if computers else []}
    if with_credential:
        selection.update(credential_id=uuid_text(body["credential_id"]), credential_revision=body["credential_revision"])
    return domain, selection


def preview(cur, body, *, actor):
    domain, selection = _selection(body)
    snapshot, names = _checked_snapshot(cur, actor, domain, selection, "preview")
    # Persist the expansion, so later OU membership never expands this plan.
    selection["computer_entity_ids"] = [row["entity_id"] for row in snapshot["targets"]]
    plan, expires = str(uuid4()), utcnow() + timedelta(minutes=10)
    digest = _hash(snapshot)
    cur.execute("""insert into sli_agent_gpo_plans(id,actor,domain_id,selection,snapshot,plan_sha256,expires_at)
        values(%s,%s,%s,%s::jsonb,%s::jsonb,%s,%s)""",
        (plan, actor, domain, json.dumps(selection), json.dumps(snapshot), digest, expires))
    _audit(cur, actor, domain, "preview", plan_id=plan, binding=snapshot["credential_binding"], expires=expires)
    cur.execute("select fqdn from domains where id=%s", (domain,))
    name = cur.fetchone()["fqdn"]
    cur.execute("""select e.id as entity_id,v.attributes_json as record from ad_context_entity_versions v
        join entities_v2 e on e.id=v.entity_id where e.id=any(%s) and e.domain_id=%s
        and v.valid_to_utc is null and v.source_section='domain_posture' order by e.id""",
        (selection["ou_entity_ids"], domain))
    units = [{"entity_id": row["entity_id"], "name": row["record"]["attributes"]["distinguished_name"]} for row in cur.fetchall()]
    return {"plan_id": plan, "plan_sha256": digest, "domain_id": domain, "domain_name": name,
        "expires_at": expires.isoformat(), "targets": names, "ou_entity_ids": selection["ou_entity_ids"],
        "ous": units, "package": snapshot["package"], "credential_binding": snapshot["credential_binding"],
        "write_enabled": False, "token_ttl_seconds": 604800}


def finish(cur, body, *, actor, cancel=False):
    required = {"plan_id", "plan_sha256"} if cancel else {
        "plan_id", "plan_sha256", "acknowledged", "credential_id", "credential_revision"}
    if not isinstance(body, dict) or set(body) != required or not cancel and body.get("acknowledged") is not True:
        raise AgentError("gpo_confirmation_invalid")
    plan = uuid_text(body.get("plan_id"))
    cur.execute("select * from sli_agent_gpo_plans where id=%s for update", (plan,))
    row = cur.fetchone()
    if not row or row["actor"] != actor:
        _reject(cur, actor, None, "gpo_plan_unavailable", status=404)
    domain = row["domain_id"]
    _scope(cur, actor, domain, "preview" if cancel else "apply")
    if body["plan_sha256"] != row["plan_sha256"]:
        _reject(cur, actor, domain, "gpo_plan_mismatch", plan_id=plan, status=409)
    binding = row["snapshot"].get("credential_binding")
    if not cancel and (not binding or body["credential_id"] != binding["credential_id"]
            or type(body["credential_revision"]) is not int
            or body["credential_revision"] != binding["credential_revision"]):
        _reject(cur, actor, domain, "gpo_credential_changed", plan_id=plan, status=409)
    desired = "cancelled" if cancel else "confirmed"
    if cancel and row["status"] == desired:
        return {"plan_id": plan, "status": desired, "write_enabled": False}
    # Confirmation is one-shot, including after a server restart. It is not a
    # renewable authorization; retries need a fresh preview, never a new secret.
    if row["status"] != "preview" or row["expires_at"] <= utcnow():
        _reject(cur, actor, domain, "gpo_plan_unavailable", plan_id=plan, status=409)
    if not cancel:
        snapshot, _ = _checked_snapshot(cur, actor, domain, row["selection"], "apply", plan_id=plan)
        if _hash(snapshot) != row["plan_sha256"]:
            _reject(cur, actor, domain, "gpo_plan_drift", plan_id=plan, status=409)
    # Recheck the deadline after waiting for locks and directory reads.
    cur.execute("""update sli_agent_gpo_plans set status=%s,finished_at=clock_timestamp()
        where id=%s and status='preview' and expires_at>clock_timestamp() returning id""", (desired, plan))
    if not cur.fetchone():
        _reject(cur, actor, domain, "gpo_plan_unavailable", plan_id=plan, status=409)
    if not cancel:
        credentials.remember(cur, actor, domain, binding)
    _audit(cur, actor, domain, desired, plan_id=plan, binding=binding, expires=row["expires_at"])
    return {"plan_id": plan, "status": desired, "write_enabled": False}
