"""Split out of ``server.sli.access.access_control_v4`` (plan 7.2b).

Module-level names of ``access_control_v4`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.access.access_control_v4 as _src


def create_package_assignment(payload: _src.Mapping[str, _src.Any], *, actor: _src.Mapping[str, _src.Any] | None, remote_address: str | None = None) -> dict[str, _src.Any]:
    """Assign or deny one existing capability package and record the decision."""
    _src.ensure_access_schema()
    subject_type = str(payload.get("subject_type") or "").strip().lower()
    if subject_type not in {"user", "group"}:
        raise ValueError("invalid_subject_type")
    subject_id = int(payload.get("subject_id") or 0)
    package_key = str(payload.get("package_key") or "").strip()
    effect = str(payload.get("effect") or "allow").strip().lower()
    source_type = str(payload.get("source_type") or "direct").strip().lower()
    reason = str(payload.get("business_reason") or "").strip()
    if subject_id <= 0 or not package_key or effect not in {"allow", "deny"} or source_type not in {"group", "direct", "temporary", "system"} or not reason:
        raise ValueError("invalid_package_assignment")
    valid_from = _src._optional_utc(payload.get("valid_from"), "invalid_valid_from")
    valid_until = _src._optional_utc(payload.get("valid_until"), "invalid_valid_until")
    if valid_from and valid_until and valid_until <= valid_from:
        raise ValueError("invalid_assignment_window")
    if source_type == "temporary" and valid_until is None:
        raise ValueError("temporary_assignment_requires_expiry")
    approved_by = str(payload.get("approved_by") or "").strip() or None
    actor_id = int(actor["id"]) if actor and actor.get("id") is not None else None
    with _src._connect() as conn, conn.cursor() as cur:
        cur.execute("select id,name from access_packages where package_key=%s", (package_key,))
        package = dict(cur.fetchone() or {})
        if not package:
            raise ValueError("access_package_not_found")
        if subject_type == "user":
            cur.execute("select 1 from auth_users where id=%s and is_active=true", (subject_id,))
        else:
            cur.execute("select 1 from access_groups where id=%s and is_active=true", (subject_id,))
        if not cur.fetchone():
            raise ValueError("access_subject_not_found")
        cur.execute(
            """
            insert into access_subject_packages(subject_type,subject_id,package_id,effect,valid_from,valid_until,business_reason,approved_by,source_type,created_by)
            values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            on conflict(subject_type,subject_id,package_id,effect,source_type) do update set
                valid_from=excluded.valid_from,valid_until=excluded.valid_until,
                business_reason=excluded.business_reason,approved_by=excluded.approved_by,
                created_by=excluded.created_by,created_at=now()
            returning id,subject_type,subject_id,package_id,effect,valid_from,valid_until,
                      business_reason,approved_by,source_type,created_at
            """,
            (subject_type, subject_id, int(package["id"]), effect, valid_from, valid_until,
             reason, approved_by, source_type, actor_id),
        )
        result = dict(cur.fetchone() or {})
        result["package_key"] = package_key
        result["package_name"] = str(package["name"])
        _src.record_access_audit_with_cursor(
            cursor=cur, actor=actor, action="package_assignment_created",
            subject_type=subject_type, subject_id=subject_id,
            target_type="package", target_key=package_key, reason=reason,
            details={
                "assignment_id": result.get("id"), "effect": effect,
                "valid_until": str(valid_until) if valid_until else None,
            },
            remote_address=remote_address,
        )
    return result


def list_access_subjects(*, account_type: str = "all") -> dict[str, _src.Any]:
    if account_type not in ("all", "people", "service"):
        raise ValueError("invalid_account_type")
    service_filter = None if account_type == "all" else account_type == "service"
    _src.ensure_access_schema()
    _src.require_table_columns("auth_users", ("is_service",), minimum_schema_version=280)
    with _src._connect() as conn, conn.cursor() as cur:
        # Persisted origin survives key deletion; retain legacy key associations.
        # Names and login status are not account-type evidence.
        cur.execute("""
            select u.id,u.username,u.role,u.is_active,u.last_login_at,
                   (u.is_service or exists (select 1 from auth_api_keys k where k.report_subject_id = u.id)) as is_service
            from auth_users u
            where (%s::boolean is null or (u.is_service or exists (select 1 from auth_api_keys k where k.report_subject_id = u.id)) = %s)
            order by lower(u.username),u.id limit 500
        """, (service_filter, service_filter))
        users = [dict(row) for row in cur.fetchall()]
        cur.execute("select id,group_key,name,description,is_active from access_groups order by name,id limit 500")
        groups = [dict(row) for row in cur.fetchall()]
        cur.execute(
            """
            select p.package_key,p.name,p.description,
                   coalesce(array_agg(distinct c.capability_key) filter (where c.capability_key is not null),'{}') as capabilities,
                   coalesce(array_agg(distinct pr.report_key) filter (where pr.report_key is not null),'{}') as reports
            from access_packages p
            left join access_package_capabilities pc on pc.package_id=p.id
            left join access_capabilities c on c.id=pc.capability_id
            left join access_package_reports pr on pr.package_id=p.id
            group by p.id,p.package_key,p.name,p.description
            order by p.name
            """
        )
        packages = [dict(row) for row in cur.fetchall()]
        cur.execute(
            """select id,subject_type,subject_id,report_key,effect,scope_json,field_categories,
                      allowed_actions,valid_from,valid_until,source_type,business_reason,approved_by,created_at
               from access_report_assignments order by created_at desc,id desc limit 200"""
        )
        assignments = [dict(row) for row in cur.fetchall()]
        cur.execute(
            """
            select sp.id,sp.subject_type,sp.subject_id,p.package_key,p.name as package_name,
                   sp.effect,sp.valid_from,sp.valid_until,sp.business_reason,sp.approved_by,
                   sp.source_type,sp.created_at
            from access_subject_packages sp join access_packages p on p.id=sp.package_id
            order by sp.created_at desc,sp.id desc limit 200
            """
        )
        package_assignments = [dict(row) for row in cur.fetchall()]
    return {"users": users, "groups": groups, "packages": packages, "assignments": assignments,
            "package_assignments": package_assignments, "limits": {"subjects": 500, "assignments": 200}}


def update_user_report_preference(
    report_key: str, payload: _src.Mapping[str, _src.Any], *,
    actor: _src.Mapping[str, _src.Any] | None, remote_address: str | None = None,
) -> dict[str, _src.Any]:
    """Persist one user's report pin after a fresh server-side access check."""
    _src.ensure_access_schema()
    principal = dict(actor or {})
    if principal.get("type") != "session" or principal.get("id") is None:
        raise PermissionError("authenticated_user_required")
    key = str(report_key or "").strip()
    has_pinned = "pinned" in payload
    has_focus = "focus_metric_keys" in payload
    if not key or not (has_pinned or has_focus):
        raise ValueError("invalid_report_preference")
    if has_pinned and not isinstance(payload.get("pinned"), bool):
        raise ValueError("invalid_report_preference")
    raw_focus_keys = payload.get("focus_metric_keys")
    if has_focus and (
        not isinstance(raw_focus_keys, list)
        or len(raw_focus_keys) > 24
        or any(not isinstance(item, str) or not _src.re.fullmatch(r"[a-z0-9][a-z0-9_.-]{1,79}", item) for item in raw_focus_keys)
        or len(set(raw_focus_keys)) != len(raw_focus_keys)
    ):
        raise ValueError("invalid_report_preference")
    access = _src.effective_access(principal)
    report = next((item for item in access["reports"] if item["report_key"] == key), None)
    if not report or not report.get("allowed"):
        raise PermissionError("report_access_denied")
    user_id = int(principal["id"])
    optional_metric_keys = {
        str(item.get("key"))
        for item in report.get("dashboard_metrics", [])
        if str(item.get("kind") or "") == "optional" and item.get("key")
    }
    if has_focus and not set(raw_focus_keys or []) <= optional_metric_keys:
        raise ValueError("invalid_report_preference")
    with _src._connect() as conn, conn.cursor() as cur:
        cur.execute(
            "select pinned,view_json from user_report_preferences where user_id=%s and report_key=%s",
            (user_id, key),
        )
        current = dict(cur.fetchone() or {})
        pinned = bool(payload["pinned"]) if has_pinned else bool(current.get("pinned"))
        view = _src._json_object(current.get("view_json"))
        if has_focus:
            view["focus_metric_keys"] = list(raw_focus_keys or [])
        cur.execute(
            """
            insert into user_report_preferences(user_id,report_key,pinned,view_json,updated_at)
            values(%s,%s,%s,%s::jsonb,now())
            on conflict(user_id,report_key) do update
            set pinned=excluded.pinned,view_json=excluded.view_json,updated_at=now()
            returning user_id,report_key,pinned,view_json,updated_at
            """,
            (user_id, key, pinned, _src.json.dumps(view, ensure_ascii=False)),
        )
        result = dict(cur.fetchone() or {})
        cur.execute(
            """
            insert into access_audit_v4(actor_type,actor_id,action,subject_type,subject_id,target_type,target_key,reason,outcome,details_json,remote_address)
            values(%s,%s,'report_preference_updated','user',%s,'report',%s,null,'ok',%s::jsonb,%s)
            """,
            (
                str(principal.get("type") or "session"), user_id, user_id, key,
                _src.json.dumps({
                    "pinned": pinned,
                    **({"focus_metric_keys": list(raw_focus_keys or [])} if has_focus else {}),
                }, ensure_ascii=False),
                remote_address,
            ),
        )
    return result


def grant_vpn_session_evidence_allow_with_cursor(
    *,
    cursor: _src.Any,
    subject: _src.Mapping[str, _src.Any],
    scope: _src.Mapping[str, _src.Any],
    actor: _src.Mapping[str, _src.Any],
    reason: str,
    approved_by: str,
    plan_digest: str,
    now: _src.datetime | None = None,
) -> dict[str, _src.Any]:
    """Create an audited, domain-scoped VPN-evidence assignment.

    The caller is responsible for obtaining and rechecking the target's
    authorised report/session preconditions. Existing assignments remain
    ordinary access policies; no login name confers or restricts this right.
    """
    target_id = int(subject.get("id") or 0)
    username = str(subject.get("username") or "")
    role = str(subject.get("role") or "")
    if target_id <= 0 or not username or not role or subject.get("is_active") is not True:
        raise ValueError("vpn_evidence_target_invalid")
    actor_type = str(actor.get("type") or "")
    if actor_type not in {"system", "local"} or actor.get("id") is not None:
        raise ValueError("vpn_evidence_audit_actor_invalid")
    clean_reason = str(reason or "").strip()
    clean_approved_by = str(approved_by or "").strip()
    if not clean_reason or not clean_approved_by or _src.re.fullmatch(r"[0-9a-f]{64}", str(plan_digest or "")) is None:
        raise ValueError("vpn_evidence_grant_metadata_invalid")
    scope, scope_error = _src.normalize_capability_scope(scope)
    if scope_error is not None or scope is None or scope.get("kind") != "domain":
        raise ValueError("vpn_evidence_scope_invalid")
    effective_now = (now or _src.datetime.now(_src.timezone.utc)).astimezone(_src.timezone.utc)

    # This row lock serializes every compliant invocation, including the
    # no-assignment case where ``FOR UPDATE`` on assignment rows locks nothing.
    cursor.execute(
        "select id,username,role,is_active from auth_users where id=%s for update",
        (target_id,),
    )
    locked_subject = dict(cursor.fetchone() or {})
    if (
        int(locked_subject.get("id") or 0) != target_id
        or locked_subject.get("username") != username
        or locked_subject.get("role") != role
        or locked_subject.get("is_active") is not True
    ):
        raise ValueError("vpn_evidence_target_changed")
    cursor.execute(
        "select id from access_capabilities where capability_key=%s for key share",
        (_src.VPN_SESSION_EVIDENCE_CAPABILITY,),
    )
    capability = dict(cursor.fetchone() or {})
    capability_id = int(capability.get("id") or 0)
    if capability_id <= 0:
        raise ValueError("vpn_evidence_capability_not_registered")
    cursor.execute(
        """
        select id,effect,scope_json
        from access_capability_assignments
        where subject_type='user' and subject_id=%s and capability_id=%s
          and (valid_from is null or valid_from<=%s)
          and (valid_until is null or valid_until>%s)
        order by id
        for update
        """,
        (target_id, capability_id, effective_now, effective_now),
    )
    matching_allow_id: int | None = None
    for existing in cursor.fetchall():
        item = dict(existing)
        existing_scope, scope_error = _src.normalize_capability_scope(item.get("scope_json"))
        if str(item.get("effect") or "") == "deny" and (
            scope_error is not None
            or existing_scope == {"kind": "all"}
            or any(
                _src._scope_matches_resource(existing_scope or {}, {"kind": "domain", "id": domain_id})
                for domain_id in scope["ids"]
            )
        ):
            raise ValueError("vpn_evidence_matching_deny")
        if str(item.get("effect") or "") == "allow" and scope_error is None and existing_scope == scope:
            matching_allow_id = int(item["id"])
    if matching_allow_id is not None:
        return {
            "status": "already_granted",
            "assignment_id": matching_allow_id,
            "scope": scope,
        }

    cursor.execute(
        """
        insert into access_capability_assignments(
            subject_type,subject_id,capability_id,effect,scope_json,
            business_reason,approved_by,source_type,created_by
        ) values('user',%s,%s,'allow',%s::jsonb,%s,%s,'direct',null)
        returning id,subject_id,scope_json
        """,
        (
            target_id, capability_id, _src.json.dumps(scope, ensure_ascii=False),
            clean_reason, clean_approved_by,
        ),
    )
    created = dict(cursor.fetchone() or {})
    assignment_id = int(created.get("id") or 0)
    if assignment_id <= 0:
        raise RuntimeError("vpn_evidence_assignment_write_failed")
    _src.record_access_audit_with_cursor(
        cursor=cursor,
        actor=actor,
        action="vpn_session_evidence_grant_created",
        subject_type="user",
        subject_id=target_id,
        target_type="capability",
        target_key=_src.VPN_SESSION_EVIDENCE_CAPABILITY,
        reason=clean_reason,
        outcome="ok",
        details={
            "scope": scope,
            "approved_by": clean_approved_by,
            "plan_digest": str(plan_digest),
            "source_type": "direct",
        },
        remote_address=None,
    )
    return {"status": "created", "assignment_id": assignment_id, "scope": scope}

