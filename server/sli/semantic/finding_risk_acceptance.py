"""Finding-specific decisions on top of audited semantic suppressions (U01)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone


class RiskAcceptanceError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _id(value, code: str) -> int:
    if type(value) is not int or not 0 < value <= 9223372036854775807:
        raise RiskAcceptanceError(code)
    return value


def _actor(actor: str) -> str:
    if not isinstance(actor, str) or not 1 <= len(actor.strip()) <= 256:
        raise RiskAcceptanceError("actor_required")
    return actor.strip()


def create_acceptance(cur, finding_id: int, body: dict, *, actor: str, now=None) -> dict:
    now = now or datetime.now(timezone.utc)
    actor = _actor(actor)
    reason = body.get("reason")
    if not isinstance(reason, str) or not 1 <= len(reason.strip()) <= 2000:
        raise RiskAcceptanceError("reason_required")
    responsible = _id(body.get("responsible_user_id"), "invalid_responsible")
    try:
        expires = datetime.fromisoformat(str(body.get("expires_at") or "").replace("Z", "+00:00"))
    except ValueError as exc:
        raise RiskAcceptanceError("invalid_expiry") from exc
    if expires.tzinfo is None or not now < expires <= now + timedelta(days=90):
        raise RiskAcceptanceError("invalid_expiry")
    # Suppression before finding is also the expiry trigger's lock order.
    cur.execute("""update semantic_suppressions set state='expired',changed_by='system:expiry'
        where finding_id=%s and kind='risk_acceptance' and state='active'
          and expires_at <= clock_timestamp()""", (finding_id,))
    cur.execute("""select id,rule_code from findings
        where id=%s and is_semantic_finding_published_v1(id) for update""", (finding_id,))
    finding = cur.fetchone()
    if not finding:
        raise RiskAcceptanceError("not_found")
    cur.execute("select id from auth_users where id=%s and is_active=true for share", (responsible,))
    if not cur.fetchone():
        raise RiskAcceptanceError("responsible_not_found")
    cur.execute("""select id from semantic_suppressions
        where finding_id=%s and kind='risk_acceptance' and state='active'""", (finding_id,))
    if cur.fetchone():
        raise RiskAcceptanceError("risk_already_accepted")
    # Use one database timestamp for both validation and the immutable creation time.
    cur.execute("""with decision as materialized (select %s::timestamptz as expiry,clock_timestamp() as at)
        insert into semantic_suppressions
        (semantic_type,scope_kind,scope_value,kind,finding_id,responsible_user_id,reason,expires_at,created_at,created_by)
        select %s,'finding',%s,'risk_acceptance',%s,%s,%s,expiry,at,%s from decision
        where expiry > at and expiry <= at + interval '2160 hours' returning *""",
        (expires, finding["rule_code"], str(finding_id), finding_id, responsible, reason.strip(), actor))
    # semantic_suppressions_audit snapshots the complete decision in this transaction.
    result = cur.fetchone()
    if not result:
        raise RiskAcceptanceError("invalid_expiry")
    return dict(result)


def revoke_acceptance(cur, finding_id: int, acceptance_id: int, *, actor: str) -> dict:
    cur.execute("""update semantic_suppressions set state='revoked',changed_by=%s
        where finding_id=%s and id=%s and kind='risk_acceptance' and state='active'
          and expires_at > clock_timestamp() returning *""", (_actor(actor), finding_id, acceptance_id))
    row = cur.fetchone()
    if not row:
        raise RiskAcceptanceError("risk_not_active")
    return dict(row)


def change_risk_acceptance(finding_id: int, body: dict, *, actor: str) -> dict:
    from server.sli.core.postgres_runtime_pipeline import connect
    finding_id = _id(finding_id, "invalid_finding_id")
    if not isinstance(body, dict):
        raise RiskAcceptanceError("invalid_request")
    action = body.get("action")
    if action not in ("create", "revoke"):
        raise RiskAcceptanceError("invalid_action")
    acceptance_id = _id(body.get("id"), "invalid_acceptance_id") if action == "revoke" else None
    with connect() as conn, conn.cursor() as cur:
        row = (create_acceptance(cur, finding_id, body, actor=actor) if action == "create"
               else revoke_acceptance(cur, finding_id, acceptance_id, actor=actor))
        cur.execute("""select id,action,actor,occurred_at,details from semantic_control_audit
            where details->'rule'->>'kind'='risk_acceptance' and details->'rule'->>'finding_id'=%s
            order by id desc limit 50""", (str(finding_id),))
        audit = [dict(item) for item in cur.fetchall()]
    return {"status": "ok", "acceptance": {
        key: value.isoformat() if isinstance(value, datetime) else value for key, value in row.items()
    }, "risk_audit": [{key: value.isoformat() if isinstance(value, datetime) else value
                        for key, value in item.items()} for item in audit]}


def risk_responsibles() -> dict:
    from server.sli.core.postgres_runtime_pipeline import connect
    with connect() as conn, conn.cursor() as cur:
        cur.execute("select id,username from auth_users where is_active=true order by lower(username),id limit 500")
        return {"items": [dict(row) for row in cur.fetchall()]}


def get_risk_audit(finding_id: int, *, before: int | None = None) -> dict:
    from server.sli.core.postgres_runtime_pipeline import connect
    finding_id = _id(finding_id, "invalid_finding_id")
    if before is not None:
        before = _id(before, "invalid_cursor")
    with connect() as conn, conn.cursor() as cur:
        cur.execute("""select id,action,actor,occurred_at,details from semantic_control_audit
            where details->'rule'->>'kind'='risk_acceptance' and details->'rule'->>'finding_id'=%s
              and (%s::bigint is null or id < %s)
            order by id desc limit 51""", (str(finding_id), before, before))
        rows = [dict(row) for row in cur.fetchall()]
    return {"items": [{key: value.isoformat() if isinstance(value, datetime) else value
                       for key, value in row.items()} for row in rows[:50]], "has_more": len(rows) > 50}
