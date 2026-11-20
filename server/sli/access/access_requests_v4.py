"""Server-authoritative report access requests for SLI v4."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from server.sli.access.access_control_v4 import (
    _optional_utc,
    create_report_assignment,
    effective_access,
    ensure_access_schema,
    record_access_audit_with_cursor,
)


ACTIVE_REQUEST_STATES = frozenset({"submitted", "reviewing"})


def _connect():
    from server.sli.core.postgres_runtime_pipeline import connect
    return connect()


def _session_user_id(actor: Mapping[str, Any] | None) -> int:
    principal = dict(actor or {})
    if principal.get("type") != "session" or principal.get("id") is None:
        raise PermissionError("authenticated_user_required")
    return int(principal["id"])


def _normalize_scope(value: Any, allowed_kinds: set[str]) -> dict[str, Any]:
    scope = dict(value or {"kind": "all"}) if isinstance(value, Mapping) else {}
    kind = str(scope.get("kind") or "").strip().lower()
    if kind not in allowed_kinds:
        raise ValueError("request_scope_not_supported")
    if kind == "all":
        return {"kind": "all"}
    key = "values" if kind == "channel" else "ids"
    values = scope.get(key)
    if (
        not isinstance(values, list) or not values or len(values) > 100
        or any(not isinstance(item, str) or not item.strip() or len(item) > 255 for item in values)
    ):
        raise ValueError("invalid_request_scope")
    return {"kind": kind, key: sorted({item.strip() for item in values})}


def _scope_is_subset(granted: Mapping[str, Any], requested: Mapping[str, Any]) -> bool:
    requested_kind = str(requested.get("kind") or "")
    granted_kind = str(granted.get("kind") or "")
    if requested_kind == "all":
        return granted_kind in {"all", "server", "domain", "channel"}
    if granted_kind != requested_kind:
        return False
    key = "values" if requested_kind == "channel" else "ids"
    return set(granted.get(key) or []) <= set(requested.get(key) or [])


def create_report_access_request(
    payload: Mapping[str, Any], *, actor: Mapping[str, Any] | None,
    remote_address: str | None = None,
) -> dict[str, Any]:
    """Create one bounded request; fields and actions come from the publisher profile."""
    ensure_access_schema()
    user_id = _session_user_id(actor)
    report_key = str(payload.get("report_key") or "").strip()
    reason = str(payload.get("business_reason") or "").strip()
    if not report_key or not 10 <= len(reason) <= 2000:
        raise ValueError("invalid_access_request")
    access = effective_access(actor)
    report = next(
        (item for item in access["reports"] if item["report_key"] == report_key),
        None,
    )
    if not report or not report.get("discoverable"):
        raise ValueError("report_not_found")
    if report.get("allowed"):
        raise ValueError("report_already_accessible")
    if not report.get("requestable") or report.get("access_state") == "request_unavailable":
        raise PermissionError("report_request_unavailable")
    profile = dict(report.get("request_profile") or {})
    allowed_scope_kinds = {
        str(item) for item in profile.get("scope_kinds", ["all"]) if str(item)
    }
    scope = _normalize_scope(payload.get("scope"), allowed_scope_kinds)
    now = datetime.now(timezone.utc)
    valid_until = _optional_utc(
        payload.get("valid_until"), "invalid_request_valid_until",
    )
    max_days = max(1, min(int(profile.get("max_duration_days") or 90), 365))
    if valid_until is None or valid_until <= now or valid_until > now + timedelta(days=max_days):
        raise ValueError("invalid_request_valid_until")
    fields = sorted({
        str(item) for item in profile.get("field_categories", [])
        if str(item)
    })
    actions = sorted({
        str(item) for item in profile.get("allowed_actions", ["view"])
        if str(item)
    })
    if "view" not in actions:
        actions.append("view")
        actions.sort()
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into report_access_requests_v4(
                requester_user_id,report_key,report_version,dataset_version,
                requested_scope_json,requested_valid_until,business_reason,
                requested_field_categories,requested_actions,status
            )
            values(%s,%s,%s,%s,%s::jsonb,%s,%s,%s,%s,'submitted')
            on conflict(requester_user_id,report_key,requested_scope_json)
                where status in ('submitted','reviewing')
            do nothing
            returning *
            """,
            (
                user_id, report_key, int(report["version"]),
                int(report["dataset_version"]),
                json.dumps(scope, ensure_ascii=False), valid_until, reason,
                fields, actions,
            ),
        )
        result = cur.fetchone()
        if result is None:
            raise ValueError("active_request_already_exists")
        item = dict(result)
        record_access_audit_with_cursor(
            cursor=cur, actor=actor, action="report_access_requested",
            subject_type="user", subject_id=user_id, target_type="report",
            target_key=report_key, reason=reason,
            details={
                "request_id": item["id"], "report_version": report["version"],
                "dataset_version": report["dataset_version"], "scope": scope,
                "valid_until": valid_until.isoformat(), "field_categories": fields,
                "allowed_actions": actions,
            },
            remote_address=remote_address,
        )
    return item


def list_report_access_requests(
    *, actor: Mapping[str, Any] | None, include_all: bool = False,
    limit: int = 100,
) -> dict[str, Any]:
    ensure_access_schema()
    user_id = _session_user_id(actor)
    access = effective_access(actor)
    can_review = "access.manage" in access["capabilities"]
    if include_all and not can_review:
        raise PermissionError("access_manage_required")
    clean_limit = max(1, min(int(limit), 250))
    where = "" if include_all else "where request.requester_user_id=%s"
    params: tuple[Any, ...] = (clean_limit,) if include_all else (user_id, clean_limit)
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(
            f"""
            select request.*,users.username,
                   coalesce(report.name,request.report_key) as report_name
            from report_access_requests_v4 request
            join auth_users users on users.id=request.requester_user_id
            left join lateral (
                select name from report_registry_v4
                where report_key=request.report_key and version=request.report_version
            ) report on true
            {where}
            order by
                case request.status when 'submitted' then 0 when 'reviewing' then 1 else 2 end,
                request.created_at desc,request.id desc
            limit %s
            """,
            params,
        )
        items = [dict(row) for row in cur.fetchall()]
    return {
        "api_version": "v4", "items": items, "limit": clean_limit,
        "review_allowed": can_review,
    }


def decide_report_access_request(
    request_id: int, payload: Mapping[str, Any], *,
    actor: Mapping[str, Any] | None, remote_address: str | None = None,
) -> dict[str, Any]:
    """Resolve a submitted request without allowing the reviewer to widen it."""
    ensure_access_schema()
    actor_id = _session_user_id(actor)
    actor_access = effective_access(actor)
    if not {"access.manage", "reports.assign"} <= set(actor_access["capabilities"]):
        raise PermissionError("access_request_review_required")
    decision = str(payload.get("decision") or "").strip().lower()
    decision_reason = str(payload.get("decision_reason") or "").strip()
    if decision not in {"approve", "reject"} or len(decision_reason) < 5:
        raise ValueError("invalid_access_request_decision")
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(
            """
            update report_access_requests_v4
            set status='reviewing',decided_by=%s,updated_at=now()
            where id=%s and status='submitted'
            returning *
            """,
            (actor_id, int(request_id)),
        )
        row = cur.fetchone()
        if row is None:
            raise ValueError("access_request_not_pending")
        request = dict(row)
        if decision == "approve":
            # Validate before committing the claim so malformed or widened grants
            # roll back to submitted without a separate recovery transaction.
            requested_scope = dict(request["requested_scope_json"])
            granted_scope = _normalize_scope(
                payload.get("scope", requested_scope),
                {"all", "server", "domain", "channel"},
            )
            requested_fields = set(request["requested_field_categories"] or [])
            granted_fields = sorted({
                str(item) for item in payload.get("field_categories", requested_fields)
                if str(item)
            })
            requested_actions = set(request["requested_actions"] or [])
            granted_actions = sorted({
                str(item) for item in payload.get("allowed_actions", requested_actions)
                if str(item)
            })
            requested_until = request["requested_valid_until"]
            granted_until = _optional_utc(
                payload.get("valid_until", requested_until), "invalid_request_valid_until",
            )
            if (
                not _scope_is_subset(granted_scope, requested_scope)
                or not set(granted_fields) <= requested_fields
                or not set(granted_actions) <= requested_actions
                or "view" not in granted_actions
                or granted_until is None or granted_until > requested_until
            ):
                raise ValueError("decision_may_not_expand_request")
            limited = (
                granted_scope != requested_scope
                or set(granted_fields) != requested_fields
                or set(granted_actions) != requested_actions
                or granted_until != requested_until
            )
    if decision == "reject":
        with _connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                update report_access_requests_v4
                set status='rejected',decision_reason=%s,decided_at=now(),updated_at=now()
                where id=%s and status='reviewing'
                returning *
                """,
                (decision_reason, int(request_id)),
            )
            result = dict(cur.fetchone() or {})
            record_access_audit_with_cursor(
                cursor=cur, actor=actor,
                action="report_access_request_rejected",
                subject_type="user",
                subject_id=int(request["requester_user_id"]),
                target_type="report", target_key=str(request["report_key"]),
                reason=decision_reason,
                details={"request_id": int(request_id)},
                remote_address=remote_address,
            )
        return result

    try:
        assignment = create_report_assignment(
            {
                "subject_type": "user",
                "subject_id": int(request["requester_user_id"]),
                "report_key": str(request["report_key"]),
                "effect": "allow",
                "scope": granted_scope,
                "field_categories": granted_fields,
                "allowed_actions": granted_actions,
                "valid_until": granted_until.isoformat(),
                "source_type": "temporary",
                "business_reason": (
                    f"Заявка #{request_id}: {request['business_reason']}"
                ),
                "approved_by": str((actor or {}).get("username") or actor_id),
            },
            actor=actor, remote_address=remote_address,
        )
    except Exception:
        with _connect() as conn, conn.cursor() as cur:
            cur.execute(
                "update report_access_requests_v4 set status='submitted',decided_by=null,updated_at=now() where id=%s and status='reviewing'",
                (int(request_id),),
            )
        raise
    requester_access = effective_access(actor, preview_user_id=int(request["requester_user_id"]))
    actual = next(
        (
            item for item in requester_access["reports"]
            if item["report_key"] == request["report_key"]
        ),
        {},
    )
    final_status = "approved_limited" if limited else "approved"
    if not actual.get("allowed"):
        final_status = "approved_limited"
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(
            """
            update report_access_requests_v4
            set status=%s,decision_reason=%s,assignment_id=%s,
                granted_scope_json=%s::jsonb,granted_valid_until=%s,
                granted_field_categories=%s,granted_actions=%s,
                decided_at=now(),updated_at=now()
            where id=%s and status='reviewing'
            returning *
            """,
            (
                final_status, decision_reason, assignment.get("id"),
                json.dumps(granted_scope, ensure_ascii=False), granted_until,
                granted_fields, granted_actions, int(request_id),
            ),
        )
        result = dict(cur.fetchone() or {})
        record_access_audit_with_cursor(
            cursor=cur, actor=actor,
            action="report_access_request_approved",
            subject_type="user", subject_id=int(request["requester_user_id"]),
            target_type="report", target_key=str(request["report_key"]),
            reason=decision_reason,
            details={
                "request_id": int(request_id),
                "assignment_id": assignment.get("id"),
                "requested": {
                    "scope": requested_scope,
                    "valid_until": requested_until.isoformat(),
                    "field_categories": sorted(requested_fields),
                    "allowed_actions": sorted(requested_actions),
                },
                "granted": {
                    "scope": granted_scope,
                    "valid_until": granted_until.isoformat(),
                    "field_categories": granted_fields,
                    "allowed_actions": granted_actions,
                },
                "effective_allowed": bool(actual.get("allowed")),
            },
            remote_address=remote_address,
        )
    result["effective_report"] = actual
    return result
