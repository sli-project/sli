"""Bounded review hints and explicit controls over published semantic findings."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

from server.sli.semantic.password_policy_lock import lock_policy_row

BUCKETS = frozenset({"machine_account", "system_account", "known_gpo_refresh", "interactive_admin", "unknown"})
_TYPE = re.compile(r"[a-z][a-z0-9_.-]{1,159}\Z")
_SID = re.compile(r"S-1-(?:[0-9]+-)+[0-9]+\Z")


def classify_audit_change(facts: dict[str, Any]) -> dict[str, Any]:
    """Conservative hint; process names and interactive logons alone prove nothing."""
    bucket = "unknown"
    if facts.get("mixed") is True or facts.get("has_audit_change") is False:
        return {"bucket": bucket, "kind": "hint", "verdict": False}
    process = str(facts.get("process_name") or "").replace("\\", "/").rsplit("/", 1)[-1].casefold()
    if facts.get("gpo_correlated") is True and process in {"", "gpupdate.exe", "svchost.exe", "gpscript.exe"}:
        bucket = "known_gpo_refresh"
    elif facts.get("subject_sid") in {"S-1-5-18", "S-1-5-19", "S-1-5-20"}:
        bucket = "system_account"
    elif facts.get("machine_account") is True:
        bucket = "machine_account"
    elif (str(facts.get("logon_type")) in {"2", "10"} or facts.get("interactive_session") is True) and facts.get("privileged_session") is True:
        bucket = "interactive_admin"
    return {"bucket": bucket, "kind": "hint", "verdict": False}


def validate_suppression(body: dict, *, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    try:
        expires = datetime.fromisoformat(str(body.get("expires_at") or "").replace("Z", "+00:00"))
        domain = int(body.get("domain_id"))
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid_suppression") from exc
    reason = str(body.get("reason") or "").strip()
    semantic_type = str(body.get("semantic_type") or "").strip()
    scope = str(body.get("scope_value") or "").strip()
    kind = body.get("scope_kind")
    if (not 0 < domain <= 9223372036854775807 or isinstance(body.get("domain_id"), (bool, float))
        or not _TYPE.fullmatch(semantic_type) or not 1 <= len(reason) <= 2000
        or expires.tzinfo is None or not now < expires <= now + timedelta(days=90)
        or not ((kind == "subject_sid" and len(scope) <= 184 and _SID.fullmatch(scope))
                or (kind == "bucket" and scope in BUCKETS))):
        raise ValueError("invalid_suppression")
    return {"semantic_type": semantic_type, "domain_id": domain, "scope_kind": kind,
            "scope_value": scope, "reason": reason, "expires_at": expires}


def _actor(actor: str) -> str:
    value = str(actor or "").strip()
    if not 1 <= len(value) <= 256:
        raise ValueError("actor_required")
    return value


def create_suppression(cur, body: dict, *, actor: str, audit, now=None) -> dict:
    rule = validate_suppression(body, now=now)
    actor = _actor(actor)
    cur.execute("""
        insert into semantic_suppressions
          (semantic_type,domain_id,scope_kind,scope_value,reason,expires_at,created_by)
        values (%s,%s,%s,%s,%s,%s,%s) returning id
    """, (rule["semantic_type"], rule["domain_id"], rule["scope_kind"], rule["scope_value"],
           rule["reason"], rule["expires_at"], actor))
    result = dict(cur.fetchone())
    audit(cur, "semantic_suppression_create", str(result["id"]), {"reason": rule["reason"]})
    return result


def _reason(reason: str) -> str:
    value = str(reason or "").strip()
    if not 1 <= len(value) <= 2000:
        raise ValueError("reason_required")
    return value


def revoke_suppression(cur, rule_id: int, *, actor: str, audit, reason: str = "") -> None:
    actor, reason = _actor(actor), _reason(reason)
    cur.execute("""update semantic_suppressions set state='revoked',changed_by=%s
        where id=%s and kind='suppression' and state='active' and expires_at > clock_timestamp() returning id""", (actor, rule_id))
    if not cur.fetchone():
        raise LookupError("suppression_not_active")
    audit(cur, "semantic_suppression_revoke", str(rule_id), {"actor": actor, "reason": reason})


def set_policy_admission(cur, policy_id: str, version: int, enabled: bool, *, actor: str, audit, reason: str = "") -> None:
    if type(enabled) is not bool or type(version) is not int or version < 1:
        raise ValueError("invalid_policy_admission")
    actor = _actor(actor)
    reason = _reason(reason)
    # Family precedes policy rows; changed identity requires whole-writer retry.
    policy = lock_policy_row(cur, policy_id, version)
    if not policy:
        raise LookupError("policy_not_found")
    if enabled and policy["lifecycle_status"] not in {"shadow", "enabled"}:
        raise ValueError("policy_not_ready")
    cur.execute("""insert into semantic_policy_admission(policy_id,policy_version,enabled,updated_by)
        values (%s,%s,%s,%s) on conflict(policy_id,policy_version) do update
        set enabled=excluded.enabled,updated_by=excluded.updated_by,updated_at=now()""",
        (policy_id, version, enabled, actor))
    audit(cur, "semantic_policy_admission", f"{policy_id}:{version}", {"enabled": enabled, "actor": actor, "reason": reason})


def list_controls(cur) -> dict:
    cur.execute("""select policy_id,policy_version,lifecycle_status,
        definition_json->>'title' as title,created_at::text as version_created_at,
        semantic_policy_mode_v160(policy_id,policy_version,lifecycle_status)='enabled' as enabled,
        exists(select 1 from semantic_policy_admission a where a.policy_id=p.policy_id
            and a.policy_version=p.policy_version) as managed
        from semantic_risk_policies p order by policy_id,policy_version limit 200""")
    policies = [dict(row) for row in cur.fetchall()]
    cur.execute("""select id,semantic_type,domain_id,scope_kind,scope_value,reason,
        expires_at::text,created_by,case when state='active' and expires_at <= clock_timestamp()
        then 'expired' else state end as state
        from semantic_suppressions where kind='suppression' order by id desc limit 200""")
    suppressions = [dict(row) for row in cur.fetchall()]
    cur.execute("""select action,target,actor,occurred_at::text from semantic_control_audit
        order by id desc limit 100""")
    return {"policies": policies, "suppressions": suppressions,
            "audit": [dict(row) for row in cur.fetchall()], "limit": 200}
