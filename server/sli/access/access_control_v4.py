# ruff: noqa: F401 -- re-export hub (plan 7.2b): split-out modules read these
# names through ``access_control_v4`` at call time, and callers import them from here.
"""Composite, server-authoritative SLI v4 access decisions.

Coarse viewer/operator/admin roles remain compatibility inputs. They expand to
starter packages, then user/group/direct/temporary grants are composed and
explicit denies win. This module returns decisions only; UI visibility is never
treated as authorization.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from server.sli.ops.postgres_schema_guard import require_table_columns
from server.sli.access.scope import AccessScope
from server.sli.access.access_composition import (
    VIEWER_SAFE_CAPABILITIES,
    FIELD_CATEGORY_CAPABILITIES,
    ACTION_CAPABILITIES,
    _active,
    _json_object,
    _json_list,
    normalize_capability_scope,
    _capability_scope_is_global,
    restrict_viewer_starter_sources,
    _scope_matches_resource,
    capability_decision,
    capability_decision_for_resource_groups,
    _report_scope_is_global,
    report_action_decision,
    _bounded_report_grant,
    _version_bound_report_grant,
    _access_explanation_code,
    _access_subject,
    compose_access_facts,
)

SCHEMA_VERSION = 40

ROUTE_CAPABILITIES: tuple[tuple[str, str], ...] = (
    ("/api/v1/event-search/query", "events.view"),
    ("/api/v1/event-search/page", "events.view"),
    ("/api/v1/event-search/members", "events.view"),
    ("/api/v1/events/batch", "evidence.exact"),
    ("/api/health/details", "operations.view"),
    ("/api/v1/events/", "evidence.exact"),
    ("/api/events/details", "evidence.exact"),
    ("/reports/event-details.html", "evidence.exact"),
    ("/reports/security-events-monitor", "events.view"),
    ("/api/security/events-monitor", "events.view"),
    ("/api/v1/reports/datasets", "reports.design"),
    ("/api/v1/reports/definitions", "reports.design"),
    ("/api/v1/reports/builder/", "reports.design"),
    ("/api/v1/reports/", "reports.catalog"),
    ("/api/v2/reports", "reports.catalog"),
    ("/api/v1/workspace", "workspace.view"),
    ("/api/v1/overview", "workspace.view"),
    ("/api/v1/home/summary", "workspace.view"),
    ("/api/v1/domains", "workspace.view"),
    ("/api/v1/ui/", "workspace.view"),
    ("/api/v1/objects", "objects.view"),
    ("/api/dashboard/", "workspace.view"),
    ("/api/v1/access/subjects", "access.manage"),
    ("/api/v1/access/report-requests", "reports.catalog"),
    ("/api/v1/access/grant-options", "reports.assign"),
    ("/api/v1/access/audit", "access.manage"),
    ("/api/v1/access/package-assignments", "access.manage"),
    ("/api/v1/access/assignments", "reports.assign"),
    ("/api/v1/access/effective", "workspace.view"),
    ("/api/v1/platform-settings", "access.manage"),
    ("/api/v1/notification-channels", "access.manage"),
    ("/api/v1/notification-subscriptions", "access.manage"),
    ("/api/v1/decoys", "reports.catalog"),
    ("/api/v1/watch", "reports.catalog"),
    # Agent registry administration; handlers require owner or access.manage.
    ("/api/v1/admin/agent", "access.manage"),
    ("/api/v1/setup", "access.manage"),
    ("/api/v1/plugins", "operations.view"),
    ("/api/v1/operations/administrative-activity", "administrative.activity.view"),
    ("/api/v1/operations", "operations.view"),
    ("/api/v1/source-", "operations.view"),
    ("/api/runtime/", "operations.view"),
    ("/api/collector/", "operations.view"),
    ("/api/system/", "operations.view"),
    ("/api/storage/", "operations.view"),
    ("/api/db/", "operations.view"),
    ("/api/diagnostics/", "operations.view"),
    ("/api/jobs", "operations.view"),
    ("/api/autocollection/", "operations.view"),
    ("/api/sources", "operations.view"),
    ("/api/domain-controllers", "operations.view"),
    ("/api/logs/", "operations.view"),
    ("/reports/collector-", "operations.view"),
    ("/reports/autocollection", "operations.view"),
    ("/reports/storage-", "operations.view"),
    ("/reports/system-", "operations.view"),
    ("/reports/db-", "operations.view"),
    ("/reports/diagnostics", "operations.view"),
    ("/api/v1/semantic/", "semantic.review"),
    ("/api/ai/", "semantic.review"),
    ("/api/v1/events", "events.view"),
    ("/api/events/", "events.view"),
    ("/api/v1/entities", "objects.view"),
    ("/api/entities/", "objects.view"),
    ("/api/v1/investigation", "investigations.view"),
    ("/api/investigation/", "investigations.view"),
    ("/api/findings", "investigations.view"),
    ("/reports/investigation", "investigations.view"),
    ("/reports/findings", "investigations.view"),
    ("/reports/search", "events.view"),
    ("/reports/account-timeline", "events.view"),
    ("/reports/entity-details", "objects.view"),
    ("/reports/ai-", "semantic.review"),
    ("/reports/role-overview", "workspace.view"),
    ("/reports/ui-navigation", "workspace.view"),
    ("/api/role-views", "workspace.view"),
    ("/api/ui/navigation", "workspace.view"),
    ("/api/reports", "reports.catalog"),
    ("/api/auth/users", "access.manage"),
    ("/api/auth/api-keys", "access.manage"),
)


VPN_SESSION_EVIDENCE_CAPABILITY = "vpn.session.evidence.read"


def _connect():
    from server.sli.core.postgres_runtime_pipeline import connect
    return connect()


def ensure_access_schema() -> None:
    contracts = {
        "access_capabilities": ("id", "capability_key", "label"),
        "access_packages": ("id", "package_key", "name"),
        "access_role_packages": ("coarse_role", "package_id"),
        "access_subject_packages": (
            "id", "subject_type", "subject_id", "package_id", "effect",
            "valid_from", "valid_until", "business_reason", "source_type",
        ),
        "access_platform_owners": ("user_id", "owner_key", "business_reason", "created_at"),
        "access_report_assignments": (
            "id", "subject_type", "subject_id", "report_key", "effect",
            "scope_json", "field_categories", "allowed_actions", "valid_from", "valid_until",
        ),
        "report_registry_v4": (
            "report_key", "version", "definition_json", "status",
            "discoverable", "requestable", "request_profile_json",
        ),
        "report_access_requests_v4": (
            "id", "requester_user_id", "report_key", "report_version",
            "dataset_version", "requested_scope_json", "status", "created_at",
        ),
        "user_report_preferences": ("user_id", "report_key", "pinned", "view_json", "updated_at"),
        "access_audit_v4": ("id", "actor_type", "actor_id", "action", "outcome", "details_json"),
    }
    for table, columns in contracts.items():
        require_table_columns(table, columns, minimum_schema_version=SCHEMA_VERSION)


def _optional_utc(value: Any, error_code: str) -> datetime | None:
    if value in (None, ""):
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(error_code) from exc
    if parsed.tzinfo is None:
        raise ValueError(error_code)
    return parsed.astimezone(timezone.utc)


def _principal_for_user(user_id: int) -> dict[str, Any]:
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("select id,username,role,is_active from auth_users where id=%s", (int(user_id),))
        row = dict(cur.fetchone() or {})
    if not row or not row.get("is_active"):
        raise ValueError("access_subject_not_found")
    return {"type": "session", "id": int(row["id"]), "username": str(row["username"]), "role": str(row["role"])}


def _validate_scope_targets(cur: Any, scope_kind: str, scope: Mapping[str, Any]) -> None:
    """Reject syntactically valid scopes that cannot resolve server-side."""
    if scope_kind == "all":
        return
    if scope_kind == "scope":
        generic = AccessScope.from_dict(scope)
        for clause in generic.clauses:
            if len(clause.plugin_ids) == 1:
                from server.sli.plugins.registry import plugin_hook
                validator = plugin_hook(clause.plugin_ids[0], 'validate_scope_targets')
                if validator is not None and validator(cur, clause) is True:
                    continue
            for dimension, values in (("plugin_id", clause.plugin_ids), ("source_instance_id", clause.source_instance_ids)):
                if values:
                    cur.execute(f"select distinct {dimension} as value from core_entity_scope_resources where {dimension}=any(%s)", (list(values),))
                    if {row["value"] for row in cur.fetchall()} != set(values):
                        raise ValueError("report_scope_target_not_found")
            if clause.entity_ids:
                cur.execute("select id from entities_v2 where id=any(%s)", (list(clause.entity_ids),))
                if {row["id"] for row in cur.fetchall()} != set(clause.entity_ids):
                    raise ValueError("report_scope_target_not_found")
            if clause.device_ids:
                cur.execute("""select e.natural_key from entities_v2 e join storage_v2_entity_type t on t.id=e.entity_type_id
                    where e.natural_key=any(%s) and t.value in ('device','ad_computer','asset','workstation')""", (list(clause.device_ids),))
                if {row["natural_key"] for row in cur.fetchall()} != set(clause.device_ids):
                    raise ValueError("report_scope_target_not_found")
            for collection in clause.collection_scope_ids:
                if not re.fullmatch(r"ad-domain:[1-9][0-9]*", collection):
                    raise ValueError("report_scope_target_not_found")
                cur.execute("select id from domains where id=%s", (int(collection.split(":", 1)[1]),))
                if not cur.fetchone():
                    raise ValueError("report_scope_target_not_found")
        return
    if scope_kind in {"server", "domain"}:
        requested = {int(item) for item in (scope.get("ids") or [])}
        table = "servers" if scope_kind == "server" else "domains"
        cur.execute(f"select id from {table} where id=any(%s)", (sorted(requested),))
        resolved = {int(row["id"]) for row in cur.fetchall()}
    else:
        requested = {str(item) for item in (scope.get("values") or []) if str(item)}
        cur.execute("select value from storage_v2_channel where value=any(%s)", (sorted(requested),))
        resolved = {str(row["value"]) for row in cur.fetchall()}
    if not requested or resolved != requested:
        raise ValueError("report_scope_target_not_found")


def _load_access_facts(cur, subject, now):
    """Existing DB/UI loader; schedule workers never use this table-reading path."""
    role, user_id, restricted_key = _access_subject(subject)
    def read(sql, params=()):
        cur.execute(sql, params)
        return [dict(row) for row in cur.fetchall()]
    facts = {}
    facts['is_owner'] = []
    if user_id is not None and not restricted_key:
        cur.execute(
            "select exists(select 1 from access_platform_owners where user_id=%s) as is_owner",
            (user_id,),
        )
        owner = cur.fetchone()
        if owner:
            facts['is_owner'] = [dict(owner)]
    is_owner = bool(facts['is_owner'] and facts['is_owner'][0]['is_owner'])
    facts['groups'] = (
        read(
            """
            select g.id,g.group_key,g.name,m.valid_from,m.valid_until,m.source
            from access_group_members m join access_groups g on g.id=m.group_id
            where m.user_id=%s and g.is_active=true
              and (m.valid_from is null or m.valid_from<=%s)
              and (m.valid_until is null or m.valid_until>%s)
            order by g.group_key
            """,
            (user_id, now, now),
        )
        if user_id is not None and not restricted_key else []
    )
    group_ids = [int(row['id']) for row in facts['groups']]
    facts['role_packages'] = (
        read(
            """
            select p.id,p.package_key,p.name,'role'::text as source_kind,%s::text as source_key,
                   'allow'::text as effect,null::timestamptz as valid_from,null::timestamptz as valid_until
            from access_role_packages rp join access_packages p on p.id=rp.package_id
            where rp.coarse_role=%s
            order by p.package_key
            """,
            (role, role),
        )
    )
    facts['subject_packages'] = (
        read(
            """
            select p.id,p.package_key,p.name,sp.source_type as source_kind,
                   (sp.subject_type||':'||sp.subject_id::text) as source_key,
                   sp.effect,sp.valid_from,sp.valid_until
            from access_subject_packages sp join access_packages p on p.id=sp.package_id
            where ((sp.subject_type='user' and sp.subject_id=%s)
                or (sp.subject_type='group' and sp.subject_id=any(%s)))
              and (sp.valid_from is null or sp.valid_from<=%s)
              and (sp.valid_until is null or sp.valid_until>%s)
            order by p.package_key,sp.effect desc
            """,
            (user_id, group_ids or [-1], now, now),
        )
        if user_id is not None and not restricted_key else []
    )
    facts['owner_packages'] = (
        read(
            """
            select id,package_key,name,'platform_owner'::text as source_kind,
                                      'owner:primary'::text as source_key,'allow'::text as effect,
                                      null::timestamptz as valid_from,null::timestamptz as valid_until
                               from access_packages order by package_key
            """,
            (),
        )
        if is_owner else []
    )
    package_ids = sorted({int(row['id']) for key in ('role_packages','subject_packages','owner_packages') for row in facts[key]})
    facts['package_capabilities'] = (
        read(
            """
            select c.capability_key,c.label,p.package_key
            from access_package_capabilities pc
            join access_capabilities c on c.id=pc.capability_id
            join access_packages p on p.id=pc.package_id
            where pc.package_id=any(%s)
            order by c.capability_key,p.package_key
            """,
            (package_ids,),
        )
        if bool(package_ids) else []
    )
    facts['direct_capabilities'] = (
        read(
            """
            select c.capability_key,c.label,a.effect,a.subject_type,a.subject_id,a.source_type,
                   a.valid_from,a.valid_until,a.scope_json
            from access_capability_assignments a join access_capabilities c on c.id=a.capability_id
            where ((a.subject_type='user' and a.subject_id=%s)
                or (a.subject_type='group' and a.subject_id=any(%s)))
              and (a.valid_from is null or a.valid_from<=%s)
              and (a.valid_until is null or a.valid_until>%s)
            order by c.capability_key,a.effect desc
            """,
            (user_id, group_ids or [-1], now, now),
        )
        if user_id is not None else []
    )
    facts['all_capabilities'] = (
        read(
            """
            select capability_key from access_capabilities order by capability_key
            """,
            (),
        )
        if is_owner else []
    )
    facts['package_reports'] = (
        read(
            """
            select pr.report_key,pr.field_categories,pr.allowed_actions,pr.scope_json,p.package_key
            from access_package_reports pr join access_packages p on p.id=pr.package_id
            where pr.package_id=any(%s)
            """,
            (package_ids,),
        )
        if bool(package_ids) else []
    )
    facts['report_assignments'] = (
        read(
            """
            select * from access_report_assignments
            where ((subject_type='user' and subject_id=%s)
                or (subject_type='group' and subject_id=any(%s)))
              and (valid_from is null or valid_from<=%s)
              and (valid_until is null or valid_until>%s)
            order by report_key,effect desc,id
            """,
            (user_id, group_ids or [-1], now, now),
        )
        if user_id is not None else []
    )
    facts['definitions'] = (
        read(
            """
            select distinct on (r.report_key)
                   r.report_key,r.version,r.name,r.owner_name,r.purpose,r.sensitivity,r.status,
                   r.definition_json,r.discoverable,r.requestable,r.request_profile_json,
                   d.dataset_key,d.version as dataset_version,d.fields_json,d.actions_json
            from report_registry_v4 r join report_datasets_v4 d on d.id=r.dataset_id
            where r.status='published'
            order by r.report_key,r.version desc
            """,
            (),
        )
    )
    facts['requests'] = (
        read(
            """
            select distinct on (report_key)
                   id,report_key,status,created_at,updated_at,decision_reason
            from report_access_requests_v4
            where requester_user_id=%s
            order by report_key,created_at desc,id desc
            """,
            (user_id,),
        )
        if user_id is not None else []
    )
    facts['preferences'] = (
        read(
            """
            select report_key,pinned,view_json,updated_at from user_report_preferences where user_id=%s
            """,
            (user_id,),
        )
        if user_id is not None else []
    )
    return facts


def effective_access(
    principal: Mapping[str, Any] | None,
    *,
    preview_user_id: int | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Return a bounded explainable access composition for one principal."""
    ensure_access_schema()
    if preview_user_id is not None:
        subject = _principal_for_user(int(preview_user_id))
        preview = True
    else:
        subject = dict(principal or {"type": "local", "id": None, "username": "local-operator", "role": "operator"})
        preview = False
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    role, user_id, restricted_key = _access_subject(subject)

    with _connect() as conn, conn.cursor() as cur:
        facts = _load_access_facts(cur, subject, now)
    return compose_access_facts(subject, facts, now=now, preview=preview)


_REPORT_KEY_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")


def has_capability(principal: Mapping[str, Any] | None, capability: str) -> bool:
    return bool(capability_decision(effective_access(principal), str(capability))["allowed"])


_REPORT_ACCESS_SUMMARY = re.compile(r"/api/v1/reports/[^/]+/access-summary")


def route_capability(path: str) -> str | None:
    clean = str(path or "")
    # Classify the whole administrative namespace, including route-table
    # templates. This requires an existing capability; it grants no access.
    # The settings handler still validates the exact path and plugin owner.
    if clean.startswith("/api/plugins/"):
        return "access.manage"
    if _REPORT_ACCESS_SUMMARY.fullmatch(clean):
        return "reports.assign"
    for prefix, capability in ROUTE_CAPABILITIES:
        if clean.startswith(prefix):
            return capability
    return None


def record_access_audit(
    *, actor: Mapping[str, Any] | None, action: str, subject_type: str | None = None,
    subject_id: int | None = None, target_type: str | None = None, target_key: str | None = None,
    reason: str | None = None, outcome: str = "ok", details: Mapping[str, Any] | None = None,
    remote_address: str | None = None,
) -> None:
    ensure_access_schema()
    with _connect() as conn, conn.cursor() as cur:
        record_access_audit_with_cursor(
            cursor=cur, actor=actor, action=action,
            subject_type=subject_type, subject_id=subject_id,
            target_type=target_type, target_key=target_key,
            reason=reason, outcome=outcome, details=details,
            remote_address=remote_address,
        )


def record_access_audit_with_cursor(
    *, cursor: Any, actor: Mapping[str, Any] | None, action: str,
    subject_type: str | None = None, subject_id: int | None = None,
    target_type: str | None = None, target_key: str | None = None,
    reason: str | None = None, outcome: str = "ok",
    details: Mapping[str, Any] | None = None,
    remote_address: str | None = None,
) -> dict[str, Any]:
    """Write legacy access audit and its disabled-by-default journal bridge atomically."""
    principal = dict(actor or {})
    clean_action = str(action)[:120]
    clean_outcome = str(outcome)[:40]
    cursor.execute(
        """
        insert into access_audit_v4(actor_type,actor_id,action,subject_type,subject_id,target_type,target_key,reason,outcome,details_json,remote_address)
        values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s)
        returning id,created_at
        """,
        (
            str(principal.get("type") or "local"), principal.get("id"),
            clean_action, subject_type, subject_id, target_type, target_key,
            reason, clean_outcome,
            json.dumps(dict(details or {}), ensure_ascii=False), remote_address,
        ),
    )
    audit_row = dict(cursor.fetchone() or {})
    from server.sli.sources.administrative_activity_producer import (
        ACCESS_ACTIONS, mirror_access_audit_if_enabled,
    )

    if clean_action.strip() in ACCESS_ACTIONS:
        mirror_access_audit_if_enabled(
            cursor=cursor,
            audit_id=int(audit_row.get("id") or 0),
            created_at=audit_row.get("created_at"),
            actor_type=str(principal.get("type") or "local"),
            actor_id=principal.get("id"),
            action=clean_action,
            subject_type=subject_type,
            subject_id=subject_id,
            target_type=target_type,
            target_key=target_key,
            outcome=clean_outcome,
            remote_address=remote_address,
        )
    return audit_row


def create_report_assignment(payload: Mapping[str, Any], *, actor: Mapping[str, Any] | None, remote_address: str | None = None) -> dict[str, Any]:
    """Create one bounded user/group allow or deny assignment and audit it."""
    ensure_access_schema()
    subject_type = str(payload.get("subject_type") or "").strip().lower()
    if subject_type not in {"user", "group"}:
        raise ValueError("invalid_subject_type")
    subject_id = int(payload.get("subject_id") or 0)
    report_key = str(payload.get("report_key") or "").strip()
    effect = str(payload.get("effect") or "allow").strip().lower()
    source_type = str(payload.get("source_type") or "direct").strip().lower()
    reason = str(payload.get("business_reason") or "").strip()
    if subject_id <= 0 or not report_key or effect not in {"allow", "deny"} or source_type not in {"group", "direct", "temporary", "system"} or not reason:
        raise ValueError("invalid_report_assignment")
    fields = sorted({str(item) for item in (payload.get("field_categories") or []) if str(item)})[:32]
    actions = sorted({str(item) for item in (payload.get("allowed_actions") or ["view"]) if str(item)})[:32]
    scope = dict(payload.get("scope") or {"kind": "all"})
    scope_kind = "scope" if "mode" in scope else str(scope.get("kind") or "").strip().lower()
    if scope_kind == "scope":
        if set(scope) != {"mode", "clauses"}:
            raise ValueError("invalid_report_scope_values")
        generic_scope = AccessScope.from_dict(scope)
        if generic_scope.mode == "none":
            raise ValueError("invalid_report_scope_values")
    if scope_kind not in {"all", "server", "domain", "channel", "scope"}:
        raise ValueError("unsupported_report_scope")
    if scope_kind not in {"all", "scope"}:
        values = scope.get("ids") if scope_kind in {"server", "domain"} else scope.get("values")
        if not isinstance(values, list) or not values or len(values) > 100:
            raise ValueError("invalid_report_scope_values")
    valid_from = _optional_utc(payload.get("valid_from"), "invalid_valid_from")
    valid_until = _optional_utc(payload.get("valid_until"), "invalid_valid_until")
    if valid_from and valid_until and valid_until <= valid_from:
        raise ValueError("invalid_assignment_window")
    if source_type == "temporary" and valid_until is None:
        raise ValueError("temporary_assignment_requires_expiry")
    approved_by = str(payload.get("approved_by") or "").strip() or None
    actor_id = int(actor["id"]) if actor and actor.get("id") is not None else None
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(
            """select r.definition_json,d.dataset_key,d.fields_json,d.actions_json
               from report_registry_v4 r join report_datasets_v4 d on d.id=r.dataset_id
               where r.report_key=%s and r.status='published' order by r.version desc limit 1""",
            (report_key,),
        )
        registered = dict(cur.fetchone() or {})
        if not registered:
            raise ValueError("report_not_found")
        if subject_type == "user":
            cur.execute("select 1 from auth_users where id=%s and is_active=true", (subject_id,))
        else:
            cur.execute("select 1 from access_groups where id=%s and is_active=true", (subject_id,))
        if not cur.fetchone():
            raise ValueError("access_subject_not_found")
        dataset_key = str(registered.get("dataset_key") or "")
        supported_scopes = {"all"}
        if dataset_key in {"entities.v2", "ad.audit.snapshot", "ad.accounts.privileged", "ad.accounts.vpn", "ad.gpo.governance"}:
            supported_scopes.update({"server", "domain"})
        if dataset_key == "events.v2":
            supported_scopes.update({"server", "domain", "channel"})
        if dataset_key in {"ad.gpo.reference.v2", "security.problems", "security.events.atomic", "ad.accounts.users.reference.v2", "ad.assets.computers.v6"}:
            supported_scopes.add("domain")
        if scope_kind == "scope":
            from server.sli.reporting.v2.definition import AccessRequirement, AccessRule
            from server.sli.reporting.v2.registry import registered_reports

            if any(
                isinstance(item.access, AccessRequirement) and item.access.access_key == report_key
                or isinstance(item.access, AccessRule) and item.access.report_key == report_key
                and item.access.scope == "delegated" and item.access.accepts_generic_scope is True
                for item in registered_reports()
            ):
                supported_scopes.add("scope")
        if scope_kind not in supported_scopes:
            raise ValueError("scope_not_supported_by_dataset")
        _validate_scope_targets(cur, scope_kind, scope)
        definition = _json_object(registered.get("definition_json"))
        dataset_categories = {
            str(item.get("category")) for item in (registered.get("fields_json") or [])
            if isinstance(item, Mapping) and item.get("category")
        }
        defined_categories = {str(item) for item in definition.get("field_categories", []) if str(item)}
        allowed_categories = dataset_categories & defined_categories
        dataset_actions = {str(item) for item in (registered.get("actions_json") or [])}
        defined_actions = {str(item) for item in definition.get("actions", []) if str(item)}
        report_actions = dataset_actions & defined_actions
        if effect == "allow":
            if not fields:
                fields = sorted(allowed_categories)
            if any(item not in allowed_categories for item in fields):
                raise ValueError("unknown_report_field_category")
            if any(item not in report_actions for item in actions):
                raise ValueError("unknown_report_action")
            if "view" not in actions:
                raise ValueError("report_view_action_required")
        else:
            fields = []
            actions = []
        cur.execute(
            """
            insert into access_report_assignments(subject_type,subject_id,report_key,effect,scope_json,field_categories,allowed_actions,valid_from,valid_until,source_type,business_reason,approved_by,created_by)
            values(%s,%s,%s,%s,%s::jsonb,%s,%s,%s,%s,%s,%s,%s,%s)
            returning id,subject_type,subject_id,report_key,effect,scope_json,field_categories,allowed_actions,valid_from,valid_until,source_type,business_reason,approved_by,created_at
            """,
            (subject_type,subject_id,report_key,effect,json.dumps(scope,ensure_ascii=False),fields,actions,valid_from,valid_until,source_type,reason,approved_by,actor_id),
        )
        result = dict(cur.fetchone() or {})
        record_access_audit_with_cursor(
            cursor=cur, actor=actor, action="report_assignment_created",
            subject_type=subject_type, subject_id=subject_id,
            target_type="report", target_key=report_key, reason=reason,
            details={
                "assignment_id": result.get("id"), "effect": effect,
                "valid_until": str(valid_until) if valid_until else None,
            },
            remote_address=remote_address,
        )
    return result


def list_report_grant_options() -> dict[str, Any]:
    """Return bounded server-authoritative choices for report assignments."""
    ensure_access_schema()
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select distinct on (r.report_key)
                   r.report_key,r.version,r.name,r.purpose,r.sensitivity,r.definition_json,
                   d.dataset_key,d.fields_json,d.actions_json
            from report_registry_v4 r join report_datasets_v4 d on d.id=r.dataset_id
            where r.status='published'
            order by r.report_key,r.version desc
            """
        )
        rows = [dict(row) for row in cur.fetchall()]
    items: list[dict[str, Any]] = []
    for row in rows:
        definition = _json_object(row.get("definition_json"))
        dataset_fields = _json_list(row.get("fields_json"))
        dataset_actions = {str(item) for item in _json_list(row.get("actions_json")) if str(item)}
        defined_categories = {str(item) for item in definition.get("field_categories", []) if str(item)}
        category_labels: dict[str, str] = {}
        for field in dataset_fields:
            if not isinstance(field, Mapping):
                continue
            category = str(field.get("category") or "")
            if category in defined_categories and category not in category_labels:
                category_labels[category] = str(field.get("category_label") or category)
        defined_actions = {str(item) for item in definition.get("actions", []) if str(item)}
        dataset_key = str(row.get("dataset_key") or "")
        scope_kinds = ["all"]
        if dataset_key in {"entities.v2", "ad.audit.snapshot", "ad.accounts.privileged", "ad.accounts.vpn", "ad.gpo.governance"}:
            scope_kinds.extend(["server", "domain"])
        if dataset_key == "events.v2":
            scope_kinds.extend(["server", "domain", "channel"])
        if dataset_key in {"ad.gpo.reference.v2", "security.problems", "security.events.atomic", "ad.accounts.users.reference.v2", "ad.assets.computers.v6"}:
            scope_kinds.append("domain")
        items.append({
            "report_key": str(row["report_key"]), "version": int(row["version"]),
            "name": str(row["name"]), "purpose": str(row["purpose"]),
            "sensitivity": str(row["sensitivity"]), "dataset_key": dataset_key,
            "field_categories": [{"key": key, "label": category_labels.get(key, key)} for key in sorted(category_labels)],
            "allowed_actions": sorted(dataset_actions & defined_actions),
            "required_capabilities": sorted({str(item) for item in definition.get("required_capabilities", []) if str(item)}),
            "scope_kinds": scope_kinds,
        })
    return {"api_version": "v4", "items": items, "limits": {"reports": len(items)}}


def list_access_audit(*, limit: int = 100) -> dict[str, Any]:
    ensure_access_schema()
    clean_limit = max(1, min(int(limit), 500))
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(
            """select id,actor_type,actor_id,action,subject_type,subject_id,target_type,target_key,
                      reason,outcome,details_json,remote_address,created_at
               from access_audit_v4 order by created_at desc,id desc limit %s""",
            (clean_limit,),
        )
        items = [dict(row) for row in cur.fetchall()]
    return {"items": items, "limit": clean_limit, "total_count": "not_calculated"}


from server.sli.access.access_control_v4_admin import (
    create_package_assignment,
    grant_vpn_session_evidence_allow_with_cursor,
    list_access_subjects,
    update_user_report_preference,
)
from server.sli.access.access_control_v4_trace import (
    _trace_source_reference,
    report_access_trace,
)

