"""Credential/recipient binding for intentions; never decrypt or dispatch secrets.

The stage 3 registry is an optional deployment dependency. Its absence blocks
planning, rather than falling back to the agent's service identity.
"""
from __future__ import annotations

from importlib import import_module
import hashlib
import json

from server.sli.agents.ca import AgentError, uuid_text
from server.sli.agents.group_enrollment import AuditedRejection


def _registry():
    try:
        return import_module("server.sli.agents.ad_credentials")
    except ModuleNotFoundError as exc:
        if exc.name != "server.sli.agents.ad_credentials":
            raise
        raise AgentError("gpo_credentials_unavailable", 409) from None


def scope(cur, actor, domain):
    allowed = _registry()._scopes(cur, actor).get(domain)
    if not allowed:
        raise AgentError("ad_operations_denied", 403)
    return allowed


def bind(cur, actor, domain, credential, revision, ous):
    registry = _registry()
    # The registry reauthorizes Operations in AD and locks the saved revision.
    row = registry._record(cur, uuid_text(credential), actor=actor)
    if (row["domain_id"] != domain or type(revision) is not int or revision <= 0
            or row["credential_revision"] != revision
            or not set(ous) <= set(row["ou_entity_ids"])):
        raise AgentError("gpo_credential_changed", 409)
    # The currently available registry has no authenticated check transport.
    # An unchecked account may be attached to a non-executable intention only.
    # Unknown/future statuses must not silently authorize a different contract.
    if row["check_status"] != "not_checked":
        raise AgentError("gpo_credential_unavailable", 409)
    registry._key()
    # The configured recipient is explicitly assigned by an administrator.
    # Runtime cannot select another agent, certificate or service identity.
    cur.execute("select public.sli_gpo_plan_recipient(%s) as recipient", (domain,))
    recipient = cur.fetchone()["recipient"]
    if not recipient:
        raise AgentError("gpo_recipient_unavailable", 409)
    authorization = {"operator_ous": sorted(scope(cur, actor, domain)),
        "credential_ous": sorted(row["ou_entity_ids"]), "check_status": row["check_status"],
        "checked_at": str(row.get("checked_at"))}
    authorization_sha256 = hashlib.sha256(json.dumps(authorization, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"credential_id": str(row["credential_id"]), "credential_revision": revision,
        "authorization_sha256": authorization_sha256,
        "recipient": recipient}


def options(cur, body, *, actor):
    from server.sli.agents import gpo_plans

    domain, selection = gpo_plans._selection(body, with_credential=False)
    try:
        gpo_plans._snapshot(cur, actor, domain, selection, "preview")
    except AuditedRejection:
        raise
    except AgentError as exc:
        gpo_plans._reject(cur, actor, domain, str(exc), status=exc.status)
    # Metadata only; the registry also enforces the independent AD assignment.
    records = _registry().list_credentials(cur, actor=actor)["items"]
    items = [{key: row[key] for key in ("credential_id", "credential_revision", "label", "username", "check_status")}
             for row in records if row["domain_id"] == domain]
    # This endpoint never locks credential rows or reads envelopes. Locking
    # several accounts around a recipient lock would invert confirm's order.
    cur.execute("""select credential_id,credential_revision,ou_entity_ids from sli_ad_operation_credentials
        where domain_id=%s""", (domain,))
    scopes = {str(row["credential_id"]): row for row in cur.fetchall()}
    cur.execute("select public.sli_gpo_plan_recipient(%s) as recipient", (domain,))
    recipient = cur.fetchone()["recipient"]
    try:
        _registry()._key()
        key_ready = True
    except AgentError:
        key_ready = False
    cur.execute("""select credential_id,credential_revision from sli_gpo_plan_last_credentials
        where actor=%s and domain_id=%s""", (actor, domain))
    last = cur.fetchone()
    # Do not silently choose a different account if the last one is unusable.
    selected = None
    for item in items:
        record = scopes.get(item["credential_id"])
        item["eligible"] = bool(key_ready and recipient and record
            and record["credential_revision"] == item["credential_revision"]
            and set(selection["ou_entity_ids"]) <= set(record["ou_entity_ids"])
            and item["check_status"] == "not_checked")
        if (last and item["eligible"] and str(last["credential_id"]) == item["credential_id"]
                and last["credential_revision"] == item["credential_revision"]):
            selected = item["credential_id"]
    return {"items": items, "selected_credential_id": selected, "write_enabled": False}


def remember(cur, actor, domain, binding):
    cur.execute("""insert into sli_gpo_plan_last_credentials(actor,domain_id,credential_id,credential_revision)
        values(%s,%s,%s,%s) on conflict(actor,domain_id) do update
        set credential_id=excluded.credential_id,credential_revision=excluded.credential_revision""",
        (actor, domain, binding["credential_id"], binding["credential_revision"]))
