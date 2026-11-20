"""Lifecycle of builder reports in ``report_registry_v4`` (Студия отчётов).

Module-level names of ``reporting_v4`` are looked up through ``_src`` at call
time, so tests that patch them there keep working.  Reports defined in code
(``server.sli.reporting.v2.registry``) are never changed here.
"""

from __future__ import annotations

import server.sli.reporting.reporting_v4 as _src

from .reporting_v4_security import _security_predecessor


def code_defined_report_keys() -> frozenset[str]:
    """Keys of reports registered in code; builder lifecycle must not touch them."""
    from server.sli.reporting.v2.registry import registered_reports

    return frozenset(str(item.key) for item in registered_reports())


def _require_publisher(access: _src.Mapping[str, _src.Any]) -> None:
    capabilities = set(access["capabilities"])
    if "reports.publish" not in capabilities:
        raise PermissionError("reports_publish_required")
    if "reports.design" not in capabilities:
        raise PermissionError("report_design_capability_required")


def _clean_key(report_key: str) -> str:
    key = str(report_key or "").strip()
    if not _src.re.fullmatch(r"[a-z0-9][a-z0-9_.-]{2,79}", key):
        raise ValueError("invalid_report_key")
    if key in _src.code_defined_report_keys():
        raise ValueError("report_is_code_defined")
    return key


def _lock(cur, report_key: str) -> None:
    cur.execute("select pg_advisory_xact_lock(hashtext(%s))", (report_key,))


def _has_grants(cur, report_key: str) -> bool:
    cur.execute(
        """select exists(
               select 1 from access_report_assignments where report_key=%s
               union all
               select 1 from access_package_reports where report_key=%s
           ) as has_grants""",
        (report_key, report_key),
    )
    return bool((cur.fetchone() or {}).get("has_grants"))


def report_definition_detail(
    report_key: str, principal: _src.Mapping[str, _src.Any] | None, *,
    access: _src.Mapping[str, _src.Any] | None = None,
) -> dict[str, _src.Any]:
    access = dict(access or _src.effective_access(principal))
    if not ({"reports.design", "reports.publish"} & set(access["capabilities"])):
        raise PermissionError("reports_design_required")
    key = str(report_key or "").strip()
    _src.ensure_access_schema()
    with _src._connect() as conn, conn.cursor() as cur:
        cur.execute(
            """select r.report_key,r.version,r.name,r.owner_name,r.purpose,r.sensitivity,
                      r.status,r.definition_json,r.discoverable,r.requestable,
                      r.published_at,r.created_by,d.dataset_key
               from report_registry_v4 r join report_datasets_v4 d on d.id=r.dataset_id
               where r.report_key=%s order by r.version desc""",
            (key,),
        )
        versions = [dict(row) for row in cur.fetchall()]
        if not versions:
            raise LookupError("report_not_found")
        cur.execute(
            "select count(*) as n from access_report_assignments where report_key=%s", (key,),
        )
        assignment_count = int((cur.fetchone() or {}).get("n") or 0)
        cur.execute(
            "select count(*) as n from access_package_reports where report_key=%s", (key,),
        )
        package_count = int((cur.fetchone() or {}).get("n") or 0)
    return {
        "api_version": "v4",
        "report_key": key,
        "code_defined": key in _src.code_defined_report_keys(),
        "versions": versions,
        "assignment_count": assignment_count,
        "package_count": package_count,
    }


def _audit(cur, principal, action, key, details, remote_address) -> None:
    _src.record_access_audit_with_cursor(
        cursor=cur, actor=principal, action=action, target_type="report",
        target_key=key, reason=None, details=details, remote_address=remote_address,
    )


def promote_report_version(
    report_key: str, version: int, principal: _src.Mapping[str, _src.Any] | None, *,
    remote_address: str | None = None, access: _src.Mapping[str, _src.Any] | None = None,
) -> dict[str, _src.Any]:
    access = dict(access or _src.effective_access(principal))
    _require_publisher(access)
    key = _clean_key(report_key)
    try:
        version = int(version)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid_report_version") from exc
    with _src._connect() as conn, conn.cursor() as cur:
        _lock(cur, key)
        cur.execute(
            """select r.id,r.status,r.definition_json,d.dataset_key,d.version as dataset_version
               from report_registry_v4 r join report_datasets_v4 d on d.id=r.dataset_id
               where r.report_key=%s and r.version=%s for update of r""",
            (key, version),
        )
        draft = dict(cur.fetchone() or {})
        if not draft:
            raise LookupError("report_version_not_found")
        if draft["status"] != "draft":
            raise ValueError("report_version_not_draft")
        definition = _src._json_mapping(draft.get("definition_json"))
        _src.builder_preview({
            "dataset_key": draft["dataset_key"],
            "dataset_version": draft["dataset_version"],
            "fields": definition.get("columns") or [],
            "filters": definition.get("filters") or [],
            "sort": definition.get("sort") or [],
            "actions": definition.get("actions") or [],
            "dashboard_metrics": definition.get("dashboard_metrics") or [],
        }, principal, access=access)
        cur.execute(
            """select r.version,r.definition_json,d.dataset_key
               from report_registry_v4 r join report_datasets_v4 d on d.id=r.dataset_id
               where r.report_key=%s and r.status='published' for update of r""",
            (key,),
        )
        previous = dict(cur.fetchone() or {})
        if _has_grants(cur, key):
            predecessor = _security_predecessor(cur, key, previous)
            dataset_changed = str(predecessor.get("dataset_key") or "") != str(draft["dataset_key"])
            if not predecessor or dataset_changed or _src._security_expands(
                _src._json_mapping(predecessor.get("definition_json")), definition,
            ):
                raise ValueError("report_security_reapproval_required")
        cur.execute(
            "update report_registry_v4 set status='retired' where report_key=%s and status='published'",
            (key,),
        )
        cur.execute(
            """update report_registry_v4 set status='published',published_at=now()
               where report_key=%s and version=%s
               returning report_key,version,name,status,published_at,discoverable,requestable""",
            (key, version),
        )
        result = dict(cur.fetchone() or {})
        _audit(cur, principal, "report_version_promoted", key, {
            "version": version, "retired_version": previous.get("version"),
        }, remote_address)
    return result


def retire_report(
    report_key: str, principal: _src.Mapping[str, _src.Any] | None, *,
    remote_address: str | None = None, access: _src.Mapping[str, _src.Any] | None = None,
) -> dict[str, _src.Any]:
    access = dict(access or _src.effective_access(principal))
    _require_publisher(access)
    key = _clean_key(report_key)
    with _src._connect() as conn, conn.cursor() as cur:
        _lock(cur, key)
        cur.execute(
            """update report_registry_v4 set status='retired'
               where report_key=%s and status='published'
               returning report_key,version,name,status""",
            (key,),
        )
        result = dict(cur.fetchone() or {})
        if not result:
            raise LookupError("report_not_published")
        _audit(cur, principal, "report_retired", key, {"version": result["version"]}, remote_address)
    return result


def set_report_visibility(
    report_key: str, payload: _src.Mapping[str, _src.Any],
    principal: _src.Mapping[str, _src.Any] | None, *,
    remote_address: str | None = None, access: _src.Mapping[str, _src.Any] | None = None,
) -> dict[str, _src.Any]:
    access = dict(access or _src.effective_access(principal))
    _require_publisher(access)
    key = _clean_key(report_key)
    discoverable = payload.get("discoverable")
    requestable = payload.get("requestable")
    if not isinstance(discoverable, bool) or not isinstance(requestable, bool):
        raise ValueError("invalid_report_discovery_policy")
    if requestable and not discoverable:
        raise ValueError("requestable_report_must_be_discoverable")
    with _src._connect() as conn, conn.cursor() as cur:
        _lock(cur, key)
        cur.execute(
            """update report_registry_v4 set discoverable=%s,requestable=%s
               where report_key=%s and status='published'
               returning report_key,version,status,discoverable,requestable""",
            (discoverable, requestable, key),
        )
        result = dict(cur.fetchone() or {})
        if not result:
            raise LookupError("report_not_published")
        _audit(cur, principal, "report_visibility_changed", key, {
            "version": result["version"], "discoverable": discoverable,
            "requestable": requestable,
        }, remote_address)
    return result


def report_access_summary(
    report_key: str, principal: _src.Mapping[str, _src.Any] | None, *,
    access: _src.Mapping[str, _src.Any] | None = None,
) -> dict[str, _src.Any]:
    """Who can see the report: assignments, packages, pending requests (no secrets)."""
    access = dict(access or _src.effective_access(principal))
    if not ({"reports.assign", "access.manage"} & set(access["capabilities"])):
        raise PermissionError("reports_assign_required")
    key = str(report_key or "").strip()
    if not _src.re.fullmatch(r"[a-z0-9][a-z0-9_.-]{2,79}", key):
        raise ValueError("invalid_report_key")
    _src.ensure_access_schema()
    with _src._connect() as conn, conn.cursor() as cur:
        cur.execute(
            """select version,discoverable,requestable from report_registry_v4
               where report_key=%s and status='published' order by version desc limit 1""",
            (key,),
        )
        published = cur.fetchone()
        if not published:
            cur.execute("select 1 as n from report_registry_v4 where report_key=%s limit 1", (key,))
            if not cur.fetchone():
                raise LookupError("report_not_found")
        cur.execute(
            """select a.subject_type,a.subject_id,a.effect,a.source_type,a.valid_until,
                      a.allowed_actions,a.field_categories,
                      case when a.subject_type='user' then u.username else g.name end as subject_name
               from access_report_assignments a
               left join auth_users u on a.subject_type='user' and u.id=a.subject_id
               left join access_groups g on a.subject_type='group' and g.id=a.subject_id
               where a.report_key=%s order by a.created_at desc,a.id desc limit 200""",
            (key,),
        )
        assignments = [{
            "subject_type": str(row["subject_type"]), "subject_id": int(row["subject_id"]),
            "subject_name": str(row.get("subject_name") or ""),
            "effect": str(row["effect"]), "source_type": str(row["source_type"]),
            "valid_until": row.get("valid_until"),
            "actions": [str(item) for item in (row.get("allowed_actions") or [])],
            "field_categories": [str(item) for item in (row.get("field_categories") or [])],
        } for row in cur.fetchall()]
        cur.execute(
            """select p.package_key,p.name from access_package_reports pr
               join access_packages p on p.id=pr.package_id
               where pr.report_key=%s order by p.name,p.package_key""",
            (key,),
        )
        packages = [
            {"package_key": str(row["package_key"]), "name": str(row["name"])}
            for row in cur.fetchall()
        ]
        cur.execute(
            """select count(*) as n from report_access_requests_v4
               where report_key=%s and status in ('submitted','reviewing')""",
            (key,),
        )
        pending = int((cur.fetchone() or {}).get("n") or 0)
    return {
        "api_version": "v4", "report_key": key,
        "published_version": int(published["version"]) if published else None,
        "discoverable": bool(published["discoverable"]) if published else False,
        "requestable": bool(published["requestable"]) if published else False,
        "assignments": assignments, "packages": packages, "pending_requests": pending,
    }
