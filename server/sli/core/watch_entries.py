"""W01: scoped account watch registry with immutable revisions."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from uuid import UUID, uuid4

from server.sli.access.access_control_v4 import capability_decision
from server.sli.core.decoys import _text
from server.sli.reporting.v2.access import resolve_access_scope
from server.sli.reporting.v2.definition import AccessRequirement
from sli_agent.file_audit_policy import SID

ACCESS = AccessRequirement("watch.registry", required_fields=frozenset({"identity_basic", "security"}))
COLUMNS = {"plugin_ids": "plugin_id", "entity_ids": "entity_id", "collection_scope_ids": "collection_scope_id"}


def require_access(access, identity=None, *, manage=False, principal=None):
    scope = resolve_access_scope(access, ACCESS, "manage_watch" if manage else "view")
    target = None
    if identity:
        target = {"kind": "domain", "id": identity["domain_id"], "domain_id": identity["domain_id"],
                  "plugin_id": "sli.ad", "entity_id": identity["entity_id"],
                  "collection_scope_id": f"ad-domain:{identity['domain_id']}"}
        if (not scope.allows(plugin_id="sli.ad", entity_id=identity["entity_id"],
                             collection_scope_id=target["collection_scope_id"])
                or not capability_decision(access, "objects.view", resource=target)["allowed"]):
            raise PermissionError("watch_access_denied")
    if manage and (not principal or principal.get("role") not in ("admin", "operator")
                   or principal.get("type") not in ("session", "api_key")
                   or type(principal.get("id")) is not int or principal["id"] <= 0
                   or not capability_decision(access, "watch.manage", resource=target)["allowed"]):
        raise PermissionError("watch_access_denied")
    return scope


def _id(value):
    if type(value) is not int or not 0 < value < 2**53:
        raise ValueError("watch_invalid")
    return value


def validate(body, *, now):
    if (not isinstance(body, dict) or set(body) != {"entity_id", "owner", "reason", "expires_at", "active", "revision"}
            or type(body["active"]) is not bool or type(body["revision"]) is not int
            or not 0 <= body["revision"] < 2**53 - 1):
        raise ValueError("watch_invalid")
    value = {**body, "entity_id": _id(body["entity_id"]), "owner": _text(body["owner"], 128),
             "reason": _text(body["reason"], 500)}
    value["expires_at"] = datetime.fromisoformat(_text(body["expires_at"], 40).replace("Z", "+00:00"))
    if value["expires_at"].utcoffset() is None or (value["active"] and value["expires_at"] <= now):
        raise ValueError("watch_invalid")
    return value


def account_identity(cur, access, entity_id):
    """Resolve an existing exact account, never a caller-supplied name/SID."""
    require_access(access)
    cur.execute("""select e.id as entity_id,e.domain_id from entities_v2_active e
        join storage_v2_entity_type t on t.id=e.entity_type_id
        where e.id=%s and t.value='ad_user' and e.domain_id is not null""", (_id(entity_id),))
    row = cur.fetchone()
    if not row:
        raise ValueError("watch_identity_unverified")
    require_access(access, row)
    cur.execute("""select v.attributes_json from ad_context_entity_versions v
        join ad_context_runs r on r.run_id=v.source_run_id
        where v.entity_id=%s and r.domain_id=%s and r.status='completed'
          and v.source_section='directory_accounts' and v.valid_to_utc is null limit 2""",
                (entity_id, row["domain_id"]))
    rows = cur.fetchall()
    exact = rows[0].get("attributes_json", {}).get("identity", {}) if len(rows) == 1 else {}
    if exact.get("kind") != "ad_user" or not SID.fullmatch(str(exact.get("object_sid", ""))):
        raise ValueError("watch_identity_unverified")
    return {**row, "sid": exact["object_sid"], "guid": str(UUID(exact.get("object_guid", "")))}


def can_manage(access, identity, principal):
    try:
        require_access(access, identity, manage=True, principal=principal)
    except PermissionError:
        return False
    return True


def list_entries(cur, access, *, principal=None, entity_id=None, entry_id=None, after=None, now=None):
    scope = require_access(access)
    now = now or datetime.now(timezone.utc)
    identity = account_identity(cur, access, entity_id) if entity_id is not None else None
    predicate, params = scope.sql_predicate(COLUMNS)
    condition = "valid_to is null"
    if entry_id is not None:
        condition = "id=%s"
        params.append(str(UUID(entry_id)))
        if after is not None and (not after.isdigit() or not 0 < int(after) < 2**53):
            raise ValueError("watch_invalid")
        condition += " and (%s::bigint is null or revision<%s::bigint)"
        params.extend((after, after))
    else:
        after = str(UUID(after)) if after else None
        condition += " and (%s::uuid is null or id>%s::uuid)"
        params.extend((after, after))
    if identity:
        condition += " and identity=%s::jsonb"
        params.append(json.dumps(identity))
    cur.execute(f"""select * from watch_entry_versions where {predicate} and {condition}
        order by id,revision desc limit 101""", params)
    rows, items = cur.fetchall(), []
    for row in rows[:100]:
        try:
            require_access(access, row["identity"])
        except PermissionError:
            continue
        item = {key: row[key] for key in ("id", "revision", "identity", "owner", "reason", "active",
                                        "active_from", "expires_at", "valid_from", "valid_to", "actor_type", "actor_id")}
        item["status"] = "disabled" if not row["active"] else "expired" if row["expires_at"] <= now else "active"
        item["can_manage"] = can_manage(access, row["identity"], principal)
        items.append(item)
    return {"items": items, "has_more": len(rows) > 100,
            "next_cursor": str(rows[99]["revision"] if entry_id else rows[99]["id"]) if len(rows) > 100 else None,
            "can_manage": can_manage(access, identity, principal) if identity else False}


def save_entry(cur, access, body, *, principal, audit, entry_id=None, now=None):
    require_access(access)
    now = now or datetime.now(timezone.utc)
    value = validate(body, now=now)
    # Coarse denial before source reads; scoped decisions are checked below.
    if not principal or principal.get("role") not in ("admin", "operator"):
        raise PermissionError("watch_access_denied")
    identity = account_identity(cur, access, value["entity_id"])
    require_access(access, identity, manage=True, principal=principal)
    cur.execute("select pg_advisory_xact_lock(hashtext(%s))", (f"watch:{value['entity_id']}",))
    cur.execute("select * from watch_entry_versions where entity_id=%s and valid_to is null for update",
                (value["entity_id"],))
    previous = cur.fetchone()
    if previous:
        require_access(access, previous["identity"], manage=True, principal=principal)
    if (previous is None and (entry_id is not None or value["revision"] != 0 or not value["active"])) or (
            previous and (entry_id is None or str(previous["id"]) != str(UUID(entry_id))
                          or previous["revision"] != value["revision"] or previous["identity"] != identity)):
        raise LookupError("watch_revision_conflict")
    entry_id = str(UUID(entry_id)) if entry_id else str(uuid4())
    active_from = (previous["active_from"] if previous and previous["active"]
                   and previous["expires_at"] > now and value["active"] else now)
    if previous:
        cur.execute("update watch_entry_versions set valid_to=%s where id=%s and revision=%s and valid_to is null",
                    (now, entry_id, previous["revision"]))
    cur.execute("""insert into watch_entry_versions(id,revision,identity,entity_id,collection_scope_id,
        owner,reason,active,active_from,expires_at,valid_from,actor_type,actor_id)
        values(%s,%s,%s::jsonb,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (entry_id, value["revision"] + 1, json.dumps(identity), value["entity_id"],
                 f"ad-domain:{identity['domain_id']}", value["owner"], value["reason"], value["active"],
                 active_from, value["expires_at"], now, principal["type"], principal["id"]))
    audit(cur, {"id": entry_id, "revision": value["revision"] + 1, "active": value["active"]})
    return {"id": entry_id, "revision": value["revision"] + 1}
