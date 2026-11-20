"""D01: scoped, revisioned labels over existing objects; no source mutations."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import ntpath
from uuid import UUID, uuid4

from server.sli.access.access_control_v4 import capability_decision
from server.sli.reporting.v2.access import resolve_access_scope
from server.sli.reporting.v2.definition import AccessRequirement
from sli_agent.file_audit_policy import SID, local_path, path_in_root

ACCESS = AccessRequirement("decoys.registry", required_fields=frozenset({"identity_basic", "security", "technical"}))
COLUMNS = {"plugin_ids": "plugin_id", "source_instance_ids": "source_instance_id", "device_ids": "device_id",
           "entity_ids": "entity_id", "collection_scope_ids": "collection_scope_id"}
FIELDS = {"kind", "identity", "owner", "reason", "active"}


def _text(value, limit):
    if (not isinstance(value, str) or not 1 <= len(value) <= limit or value.strip() != value
            or any(ord(char) < 32 for char in value)):
        raise ValueError("decoy_invalid")
    return value


def validate(body):
    if (not isinstance(body, dict) or set(body) != FIELDS | {"revision"}
            or not isinstance(body["kind"], str) or body["kind"] not in ("account", "file") or type(body["active"]) is not bool
            or type(body["revision"]) is not int or not 0 <= body["revision"] < 2**53 - 1
            or not isinstance(body["identity"], dict)):
        raise ValueError("decoy_invalid")
    value = {**body, "identity": dict(body["identity"]), "owner": _text(body["owner"], 128),
             "reason": _text(body["reason"], 500)}
    identity = value["identity"]
    if body["kind"] == "account":
        if (set(identity) != {"domain_id", "entity_id", "sid", "guid"}
                or any(type(identity[key]) is not int or not 0 < identity[key] < 2**53 for key in ("domain_id", "entity_id"))
                or not SID.fullmatch(_text(identity["sid"], 184))):
            raise ValueError("decoy_invalid")
        identity["guid"] = str(UUID(_text(identity["guid"], 36)))
    else:
        if set(identity) != {"agent_id", "source_instance_id", "collection_scope_id", "path"}:
            raise ValueError("decoy_invalid")
        identity["agent_id"] = str(UUID(_text(identity["agent_id"], 36)))
        for key in ("source_instance_id", "collection_scope_id"):
            _text(identity[key], 256)
        identity["path"] = ntpath.normcase(local_path(identity["path"]))
    return value


def resource(value):
    identity = value["identity"]
    if value["kind"] == "account":
        return {"plugin_id": "sli.ad", "entity_id": identity["entity_id"], "kind": "domain",
                "id": identity["domain_id"], "domain_id": identity["domain_id"],
                "collection_scope_id": f"ad-domain:{identity['domain_id']}"}
    return {"plugin_id": "sli.file-audit", "device_id": identity["agent_id"],
            "source_instance_id": identity["source_instance_id"], "collection_scope_id": identity["collection_scope_id"]}


def require_access(access, value=None, *, manage=False, principal=None):
    scope = resolve_access_scope(access, ACCESS, "manage_decoy" if manage else "view")
    target = resource(value) if value else None
    if target and not scope.allows(**{key: target[key] for key in (
            "plugin_id", "source_instance_id", "device_id", "entity_id", "collection_scope_id") if key in target}):
        raise PermissionError("decoy_access_denied")
    if manage and (not principal or principal.get("role") != "admin"
                   or principal.get("type") not in ("session", "api_key")
                   or type(principal.get("id")) is not int or principal["id"] <= 0
                   or not capability_decision(access, "decoys.manage", resource=target)["allowed"]):
        raise PermissionError("decoy_access_denied")
    return scope


def _fresh(value, now):
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return False
    return isinstance(value, datetime) and value.utcoffset() is not None and timedelta(0) <= now - value <= timedelta(days=1)


def readiness(cur, value, *, now):
    """Read retained identity/audit receipts. Never equate a label with protection."""
    identity, reasons, observed = value["identity"], [], None
    if value["kind"] == "account":
        cur.execute("""select v.attributes_json,v.last_observed_at_utc
            from ad_context_entity_versions v join ad_context_runs r on r.run_id=v.source_run_id
            where v.entity_id=%s and r.domain_id=%s and r.status='completed'
              and v.source_section='directory_accounts' and v.valid_to_utc is null limit 2""",
                    (identity["entity_id"], identity["domain_id"]))
        rows = cur.fetchall()
        record = rows[0] if len(rows) == 1 else {}
        exact = record.get("attributes_json", {}).get("identity", {})
        observed = record.get("last_observed_at_utc")
        if (exact.get("kind") != "ad_user" or exact.get("object_sid") != identity["sid"]
                or str(exact.get("object_guid", "")).lower() != identity["guid"]):
            reasons.append("identity_unverified")
        if not _fresh(observed, now):
            reasons.append("identity_stale")
        # Directory inventory proves identity, never authentication audit coverage.
        reasons.append("authentication_audit_unverified")
    else:
        cur.execute("""select host_id,status,assigned_modules,file_audit,collection_policy,
            policy_revision,applied_policy_revision,last_seen from sli_agents where id=%s""", (identity["agent_id"],))
        agent = cur.fetchone() or {}
        audit = agent.get("file_audit") or {}
        config = audit.get("request", {}).get("config", {})
        observed = audit.get("reported_at")
        roots = [root for root in config.get("roots", []) if root.get("collection_scope_id") == identity["collection_scope_id"]]
        root = roots[0] if len(roots) == 1 else {}
        modules = [item for item in agent.get("assigned_modules", []) if isinstance(item, dict)
                   and item.get("module_id") == "sli.file-audit" and item.get("enabled") is True]
        if (str(agent.get("host_id")) != identity["source_instance_id"] or agent.get("status") != "active"
                or not modules or {k: v for k, v in modules[0].get("config", {}).items() if k != "policy_revision"}
                    != {k: v for k, v in config.items() if k != "policy_revision"}
                or agent.get("collection_policy", {}).get("state", "active") != "active"
                or agent.get("applied_policy_revision") != agent.get("policy_revision")):
            reasons.append("source_not_ready")
        if not _fresh(agent.get("last_seen"), now) or not _fresh(observed, now):
            reasons.append("audit_stale")
        if config.get("source_kind", "server") != "server":
            reasons.append("server_profile_required")
        if not root or not path_in_root(identity["path"], root["path"]):
            reasons.append("root_not_covered")
        sacl = root.get("sacl", {})
        if (not root.get("important") or not sacl.get("inherit_files")
                or "S-1-1-0" not in sacl.get("trustee_sids", [])):
            reasons.append("read_audit_missing")
        if config.get("service_account_exclusions"):
            reasons.append("exclusions_conflict")
        receipt = audit.get("scopes", {}).get(identity["collection_scope_id"], {})
        command = audit.get("request", {}).get("command", {})
        if (receipt.get("state") != "verified" or receipt.get("reason_code") != "ok"
                or command.get("action") not in ("check", "apply")
                or command.get("policy_revision") != config.get("policy_revision")):
            reasons.append("audit_missing")
        cur.execute("select sli_plugin_file_audit.decoy_file_present(%s,%s,%s,%s,%s) as present",
                    (identity["agent_id"], identity["source_instance_id"], identity["collection_scope_id"],
                     identity["path"], config.get("policy_revision", "")))
        if (cur.fetchone() or {}).get("present") is not True:
            reasons.append("file_unverified")
        cur.execute("select * from public.file_decoy_coverage(%s,%s,%s,%s)", (
            identity["agent_id"], identity["source_instance_id"], identity["collection_scope_id"],
            config.get("policy_revision", "")))
        coverage = cur.fetchone() or {}
        if (coverage.get("state") != "complete" or coverage.get("read_audit_enabled") is not True
                or coverage.get("lost_count") != 0 or not _fresh(coverage.get("window_end"), now)):
            reasons.append("collection_gap")
    if not value["active"]:
        reasons.append("label_disabled")
    return {"state": "not_ready" if reasons else "ready", "reasons": reasons,
            "checked_at": now.isoformat(), "last_observation_at": observed}


def list_labels(cur, access, *, principal=None, after=None, label_id=None, revision=None):
    scope = require_access(access)
    predicate, params = scope.sql_predicate(COLUMNS)
    condition = "active_to is null"
    if label_id:
        condition = "id=%s"
        params.append(str(UUID(label_id)))
    if revision is not None:
        if (not label_id or not isinstance(revision, str) or not revision.isdigit()
                or not 0 < int(revision) < 2**53 or after is not None):
            raise ValueError("decoy_invalid")
        condition += " and revision=%s"
        params.append(int(revision))
    if after and not label_id:
        after = str(UUID(after))
    if label_id:
        if after is not None and (not after.isdigit() or not 0 < int(after) < 2**53):
            raise ValueError("decoy_invalid")
        condition += " and (%s::bigint is null or revision<%s::bigint)"
        params.extend((after, after))
        after = None
    cur.execute(f"""select * from decoy_label_versions where {predicate} and {condition}
        and (%s::uuid is null or id>%s::uuid) order by id,revision desc limit 101""", (*params, after, after))
    rows = cur.fetchall()
    items = []
    for row in rows[:100]:
        item = {key: row[key] for key in ("id", "revision", "kind", "identity", "owner", "reason", "active",
                                        "active_from", "active_to", "actor_type", "actor_id")}
        item["readiness"] = readiness(cur, item, now=datetime.now(timezone.utc)) if row["active_to"] is None else row["readiness"]
        try:
            require_access(access, item, manage=True, principal=principal)
            item["can_manage"] = True
        except PermissionError:
            item["can_manage"] = False
        items.append(item)
    return {"items": items, "has_more": len(rows) > 100,
            "next_cursor": str(items[-1]["revision"] if label_id else items[-1]["id"]) if len(rows) > 100 else None}


def list_touches(cur, access, *, label_id, revision, after=None):
    """Authorize the exact historical version before reading any native detail."""
    from server.sli.semantic.qw_input import _hash

    scope = require_access(access)
    label_id = str(UUID(label_id))
    if (not isinstance(revision, str) or not revision.isascii() or not revision.isdigit()
            or not 0 < int(revision) < 2**53 or after is not None and not _hash(after)):
        raise ValueError("decoy_invalid")
    predicate, params = scope.sql_predicate(COLUMNS)
    cur.execute(f"select * from decoy_label_versions where {predicate} and id=%s and revision=%s and kind='file'",
                (*params, label_id, int(revision)))
    label = cur.fetchone()
    if not label:
        raise PermissionError("decoy_access_denied")
    require_access(access, label)
    cur.execute("select * from public.read_file_decoy_touches(%s,%s,%s)", (label_id, int(revision), after))
    rows = list(cur.fetchall() or [])
    items = []
    for row in rows[:100]:
        obs, context = row["observation"], row["context"]
        items.append({"id": row["signal_id"], "mode": row["evaluation_mode"], "revision": context["label_revision"],
            "path": label["identity"]["path"], "observed_at": obs["observed_at"], "event_id": obs["event_id"],
            "meaning": context["meaning"], "outcome": context["outcome"],
            "denial_layer": ("smb" if obs["event_id"] == 5145 else "ntfs") if context["outcome"] == "failure" else None,
            "subject_sid": obs["facts"].get("subject_user_sid"), "access_mask": obs["facts"].get("access_mask"),
            "evidence_key": obs["evidence_key"], "sha256": obs["payload_sha256"]})
    return {"items": items, "has_more": len(rows) > 100,
            "next_cursor": rows[99]["signal_id"] if len(rows) > 100 else None}


def save_label(cur, access, body, *, principal, audit, label_id=None, now=None):
    # Check coarse grants before parsing user input or reading any source.
    require_access(access)
    value = validate(body)
    require_access(access, value, manage=True, principal=principal)
    updating = label_id is not None
    label_id = str(UUID(label_id)) if updating else str(uuid4())
    cur.execute("select pg_advisory_xact_lock(hashtext(%s))", ("decoy:" + label_id,))
    cur.execute("select * from decoy_label_versions where id=%s and active_to is null for update", (label_id,))
    previous = cur.fetchone()
    if previous:
        require_access(access, previous, manage=True, principal=principal)
    if (previous is None and (updating or value["revision"] != 0)) or (previous and previous["revision"] != value["revision"]):
        raise LookupError("decoy_revision_conflict")
    now = now or datetime.now(timezone.utc)
    checked = readiness(cur, value, now=now)
    if previous:
        cur.execute("update decoy_label_versions set active_to=%s where id=%s and revision=%s and active_to is null",
                    (now, label_id, previous["revision"]))
    target = resource(value)
    cur.execute("""insert into decoy_label_versions(id,revision,kind,identity,owner,reason,active,
        active_from,actor_type,actor_id,readiness,plugin_id,source_instance_id,device_id,entity_id,collection_scope_id)
        values(%s,%s,%s,%s::jsonb,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s,%s,%s)""",
                (label_id, value["revision"] + 1, value["kind"], json.dumps(value["identity"]), value["owner"],
                 value["reason"], value["active"], now, principal["type"], principal["id"], json.dumps(checked, default=str),
                 target["plugin_id"], target.get("source_instance_id"), target.get("device_id"),
                 target.get("entity_id"), target["collection_scope_id"]))
    audit(cur, {"id": label_id, "revision": value["revision"] + 1, "active": value["active"],
                "readiness": checked["state"]})
    return {"id": label_id, "revision": value["revision"] + 1, "readiness": checked}
