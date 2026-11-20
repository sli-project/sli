# ruff: noqa: F401 -- re-export hub (plan 7.2b): split-out modules read these
# names through ``reporting_v4`` at call time, and callers import them from here.
"""Registered SLI v4 reports and safe dataset builder contracts."""

from __future__ import annotations

import csv
import io
import json
import re
from typing import Any, Mapping, Sequence

from server.sli.access.access_control_v4 import (
    capability_decision_for_resource_groups,
    effective_access,
    ensure_access_schema,
    record_access_audit_with_cursor,
)
from server.sli.core.database import QueryTimeoutError, query_rows_bounded
from server.sli.plugins.registry import plugin_installed, require_plugin
from server.sli.reporting.reporting_common import (
    format_csv_cell,
    get_runtime_connection,
)
from server.sli.reports.ad_hygiene_policy import inactivity_sql
from server.sli.reporting.reporting_v4_catalog import (
    BOOLEAN_FILTER_FIELDS,
    DATASET_FIELDS,
    DEFAULT_ORDERS,
    EVENT_VIEW_EVENT_IDS,
    EXECUTABLE_DATASETS,
    FOCUS_METRIC_MAX,
    FOCUS_REQUIRED_METRIC_MAX,
    GPO_APPLICATION_STATE_SQL,
    GPO_EXECUTABLE_COUNT_SQL,
    GPO_GOVERNANCE_FIELDS,
    GPO_GOVERNANCE_SELECT_SQL,
    GPO_LINK_COUNT_SQL,
    GPO_SETTINGS_SQL,
    INTEGER_FILTER_FIELDS,
    REPORT_DATA_TIMEOUT_MS,
    REPORT_GRANT_BRANCH_MAX,
    REPORT_LIMIT_MAX,
    RUNTIME_FILTER_FIELDS,
    runtime_filter_expression,
    RUNTIME_SORT_FIELDS,
    UNSAFE_DEFINITION_KEYS,
    VPN_ACCOUNT_ATTRIBUTES_LATERAL,
    _active_entity_predicate,
)
from server.sli.reporting.reporting_v4_definitions import (
    _dashboard_metric_definitions,
    _definition_columns,
    _definition_has_unsafe_text,
    _json_mapping,
    _metric_state,
    _metric_value,
    _security_expands,
    _vpn_connections_catalog_item,
)
from server.sli.reporting.reporting_v4_query import (
    VPN_ACCOUNT_CURSOR_ORDER,
    _append_predicates,
    _bounded_filter_value,
    _compile_definition_query,
    _compile_interactive_event_query,
    _compile_interactive_report_query,
    _compile_interactive_sort,
    _decode_report_cursor,
    _decode_vpn_account_cursor,
    _grant_branch_key,
    _grant_scope_covers,
    _grant_subsumes,
    _prune_subsumed_grants,
    _report_cursor,
    _sort_combined_report_items,
    _typed_filter_value,
    _utc_filter_value,
    _vpn_account_cursor,
)

_connect = get_runtime_connection


def report_catalog(principal: Mapping[str, Any] | None, *, access: Mapping[str, Any] | None = None) -> dict[str, Any]:
    access = dict(access or effective_access(principal))
    if "reports.catalog" not in access["capabilities"]:
        raise PermissionError("reports_catalog_required")
    # Working tools and administrative screens may still use a registered
    # report/dataset for access checks, but they are not analytical cards in
    # the user catalog.
    non_catalog_targets = {
        "/events", "/investigations", "/cases", "/access", "/access-center",
        "/operations", "/project-readiness", "/report-management", "/report-editor",
    }
    catalog_items = [
        report for report in access["reports"]
        if str(report.get("target_path") or "").removeprefix("/app") not in non_catalog_targets
    ]
    report_keys = {str(report.get("report_key") or "") for report in catalog_items}
    vpn_audit = next(
        (report for report in catalog_items if report.get("report_key") == "vpn.audit"),
        None,
    )
    if vpn_audit is not None and "vpn.connections" not in report_keys and plugin_installed("sli.remote-access"):
        catalog_items.append(_vpn_connections_catalog_item(
            vpn_audit,
            capabilities={str(item) for item in access["capabilities"]},
        ))
    catalog_items = [
        report for report in catalog_items
        if str(report.get("report_key") or "") != "vpn.audit"
    ]
    return {
        "api_version": "v4",
        "state": "available" if catalog_items else "empty",
        "items": catalog_items,
        "allowed_count": sum(1 for report in catalog_items if report.get("allowed")),
        "total_count": len(catalog_items),
        "explain_contract": "assignment + required capabilities - explicit deny",
    }


def report_definitions(
    principal: Mapping[str, Any] | None, *, limit: int = 200,
    access: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a bounded administrative registry for mutation verification."""
    access = dict(access or effective_access(principal))
    capabilities = set(access["capabilities"])
    if not ({"reports.design", "reports.publish"} & capabilities):
        raise PermissionError("reports_design_required")
    ensure_access_schema()
    clean_limit = max(1, min(int(limit), 500))
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select r.report_key,r.version,r.name,r.owner_name,r.purpose,r.sensitivity,r.status,
                   r.published_at,r.created_at,d.dataset_key,d.version as dataset_version,
                   r.discoverable,r.requestable,
                   (select count(*) from access_report_assignments a
                     where a.report_key=r.report_key) as assignment_count,
                   (select count(*) from access_package_reports pr
                     where pr.report_key=r.report_key) as package_count
            from report_registry_v4 r join report_datasets_v4 d on d.id=r.dataset_id
            order by r.created_at desc,r.id desc limit %s
            """,
            (clean_limit,),
        )
        rows = [dict(row) for row in cur.fetchall()]
    code_defined = code_defined_report_keys()
    items = [
        {**row, "code_defined": str(row.get("report_key")) in code_defined}
        for row in rows
    ]
    return {"api_version": "v4", "items": items, "limit": clean_limit, "total_count": "not_calculated"}


def workspace(principal: Mapping[str, Any] | None, *, access: Mapping[str, Any] | None = None) -> dict[str, Any]:
    access = dict(access or effective_access(principal))
    if "workspace.view" not in access["capabilities"]:
        raise PermissionError("workspace_view_required")
    reports = [item for item in access["reports"] if item["allowed"]]
    pinned = sorted(reports, key=lambda item: (not item["pinned"], item["name"]))
    recent_objects: list[dict[str, Any]] = []
    recent_objects_state = "available"
    if (
        access.get("platform_owner")
        or "objects.view" in access["capabilities"]
        or "objects.view" in (access.get("resource_bound_capabilities") or [])
    ):
        # Import at call time: the facade also depends on reporting modules.
        from server.sli.access.object_facade_v4 import _object_resource_group

        try:
            rows = query_rows_bounded(
                """
                select entity.id,entity_type.value as object_type,entity.display_name,
                       entity.natural_key,entity.last_seen_utc,entity.domain_id,entity.server_id
                from entities_v2_active entity join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id
                order by entity.last_seen_utc desc nulls last,entity.id desc limit ?
                """,
                (8,), statement_timeout_ms=3000,
            )
        except QueryTimeoutError:
            # `recent_objects` is a convenience block, not the workspace contract.
            # This ORDER BY has no matching composite index on `entities_v2`
            # (`last_seen_utc desc nulls last, id desc`), so on a large table it
            # exceeds the 3000 ms budget and previously turned the whole
            # /api/v1/workspace response into HTTP 500 — the main screen died
            # because of an auxiliary list.  Degrade honestly instead, matching
            # the precedent in `ui_workspace._entity_workspace_detail`.
            rows = []
            recent_objects_state = "temporarily_unavailable"
        for row in rows:
            # Explicit NULL is valid for a partial context (e.g. domain-only
            # directory entities). Missing columns, malformed IDs, and fully
            # unknown context must never reach the mapper's global fallback.
            if any(key not in row for key in ("domain_id", "server_id")):
                continue
            resource_ids = [row[key] for key in ("domain_id", "server_id") if row[key] is not None]
            if not resource_ids or any(
                isinstance(value, bool) or not isinstance(value, int) or value <= 0
                for value in resource_ids
            ):
                continue
            resources = [_object_resource_group(row)]
            if not capability_decision_for_resource_groups(
                access, "objects.view", resource_groups=resources,
            )["allowed"]:
                continue
            technical_allowed = capability_decision_for_resource_groups(
                access, "field.technical", resource_groups=resources,
            )["allowed"]
            natural_key = str(row.get("natural_key") or "") if technical_allowed else None
            recent_objects.append({
                "object_type": str(row["object_type"]), "object_id": str(row["id"]),
                "display_name": str(row.get("display_name") or natural_key or row["id"]),
                "natural_key": natural_key,
                "observed_at_utc": row.get("last_seen_utc"), "source": "Storage V2",
            })
    return {
        "api_version": "v4", "state": "available" if reports else "empty",
        "subject": access["subject"], "packages": access["packages"], "groups": access["groups"],
        "capabilities": access["capabilities"], "reports": pinned,
        "focus_metrics": _workspace_focus_metrics(principal, access, reports),
        "recent_objects": recent_objects,
        "recent_objects_state": recent_objects_state,
        "composition": {
            "package_count": len(access["packages"]), "group_count": len(access["groups"]),
            "direct_report_count": sum(1 for report in reports for source in report["sources"] if source["source_type"] in {"direct", "temporary"}),
            "allowed_report_count": len(reports), "explicit_deny_count": sum(len(items) for items in access["explicit_denies"].values()),
        },
        "limits": {"recent_objects": 8, "reports": len(reports)},
    }


def dataset_registry(principal: Mapping[str, Any] | None, *, access: Mapping[str, Any] | None = None) -> dict[str, Any]:
    access = dict(access or effective_access(principal))
    if "reports.design" not in access["capabilities"]:
        raise PermissionError("reports_design_required")
    ensure_access_schema()
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select dataset_key,version,name,object_type,fields_json,filters_json,actions_json,status
            from report_datasets_v4 where status='published' order by name,dataset_key
            """
        )
        items = [dict(row) for row in cur.fetchall()]
    for item in items:
        key = str(item.get("dataset_key") or "")
        item["executable"] = key in EXECUTABLE_DATASETS
        item["executable_filter_keys"] = sorted(RUNTIME_FILTER_FIELDS.get(key, {}))
        item["executable_sort_keys"] = sorted(RUNTIME_SORT_FIELDS.get(key, {}))
    return {"api_version": "v4", "items": items, "arbitrary_sql_allowed": False}


















def execute_report(
    report_key: str, principal: Mapping[str, Any] | None, *, limit: int = 50,
    fields: Sequence[str] | None = None, action: str = "view",
    query_filters: Mapping[str, Any] | None = None,
    access: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Execute one allowlisted dataset with field policy and hard bounds."""
    access = dict(access or effective_access(principal))
    report = next((item for item in access["reports"] if item["report_key"] == report_key), None)
    if report is None:
        raise ValueError("report_not_found")
    if not report["allowed"]:
        raise PermissionError("report_access_denied")
    clean_limit = max(1, min(int(limit), REPORT_LIMIT_MAX))
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select r.definition_json,d.dataset_key,d.fields_json
            from report_registry_v4 r join report_datasets_v4 d on d.id=r.dataset_id
            where r.report_key=%s and r.version=%s
            """, (report_key, report["version"]),
        )
        definition = dict(cur.fetchone() or {})
    if not definition:
        raise ValueError("report_definition_not_found")
    return _execute_definition(
        report_key, report, definition, principal, limit=clean_limit, fields=fields,
        action=action, query_filters=query_filters, access=access,
    )


def _execute_definition(
    report_key: str, report: Mapping[str, Any], definition: Mapping[str, Any],
    principal: Mapping[str, Any] | None, *, limit: int, fields: Sequence[str] | None,
    action: str, query_filters: Mapping[str, Any] | None, access: Mapping[str, Any],
) -> dict[str, Any]:
    """Shared runner: ``report`` carries the effective grants, ``definition`` is the
    (published or unsaved) definition row: dataset_key, fields_json, definition_json."""
    clean_limit = max(1, min(int(limit), REPORT_LIMIT_MAX))
    dataset_key = str(definition["dataset_key"])
    if dataset_key not in EXECUTABLE_DATASETS:
        raise ValueError("report_dataset_not_executable")
    field_defs = {str(item["key"]): dict(item) for item in (definition.get("fields_json") or [])}
    runtime_definition = _json_mapping(definition.get("definition_json"))
    published_columns = _definition_columns(runtime_definition, field_defs)
    clean_action = str(action or "").lower()
    if clean_action not in {"view", "export"}:
        raise ValueError("report_action_not_executable")
    definition_actions = {str(item) for item in (runtime_definition.get("actions") or ["view"])}
    if clean_action not in definition_actions:
        raise PermissionError("report_action_denied")
    if clean_action == "export" and (
        "reports.export" not in set(access.get("capabilities") or [])
        or str(runtime_definition.get("export_policy") or "disabled") != "controlled"
    ):
        raise PermissionError("report_export_denied")
    all_grants = [dict(item) for item in (report.get("grants") or [])]
    grants = [item for item in all_grants if clean_action in item.get("allowed_actions", [])]
    if not grants:
        raise PermissionError("report_access_denied")
    requested = [str(item) for item in fields] if fields is not None else None
    if requested is None:
        branch_filters = dict(query_filters or {})
        requested_branch = str(
            branch_filters.pop("grant_branch", "") or ""
        ).strip().lower()
        if requested_branch and not re.fullmatch(r"[0-9a-f]{64}", requested_branch):
            raise ValueError("invalid_report_grant_branch")
        unique_grants: list[dict[str, Any]] = []
        seen_grants: set[str] = set()
        for grant in grants:
            identity = _grant_branch_key(grant)
            if identity not in seen_grants:
                seen_grants.add(identity)
                unique_grants.append(grant)
        unique_grants = _prune_subsumed_grants(unique_grants)
        if requested_branch:
            unique_grants = [
                grant
                for grant in unique_grants
                if _grant_branch_key(grant) == requested_branch
            ]
            if not unique_grants:
                raise PermissionError("report_grant_branch_access_denied")
        if len(unique_grants) > REPORT_GRANT_BRANCH_MAX:
            raise PermissionError("report_grant_branch_limit_exceeded")
        branches: list[dict[str, Any]] = []
        for grant in unique_grants:
            categories = set(str(item) for item in grant.get("field_categories") or [])
            projection = [
                key for key in published_columns
                if str(field_defs[key].get("category") or "") in categories
            ]
            if not projection:
                continue
            branch_report = {
                **report,
                "grants": [grant],
                "field_categories": sorted(categories),
                "allowed_actions": sorted(str(item) for item in grant.get("allowed_actions") or []),
                "scopes": [dict(grant.get("scope") or {})],
            }
            branch_access = {
                **access,
                "reports": [branch_report if item.get("report_key") == report_key else item for item in access["reports"]],
            }
            branch = _execute_definition(
                report_key, branch_report, definition, principal, limit=clean_limit,
                fields=projection, action=clean_action, query_filters=branch_filters,
                access=branch_access,
            )
            branch["_grant_branch"] = _grant_branch_key(grant)
            branch["_grant_fields"] = projection
            branches.append(branch)
        if not branches:
            raise PermissionError("report_field_access_denied")
        if len(branches) == 1:
            single = dict(branches[0])
            single["grant_branch"] = single.pop("_grant_branch")
            single["grant_branch_fields"] = single.pop("_grant_fields")
            single["field_visibility"] = "per_grant"
            single["limitations"] = list(dict.fromkeys([
                *(str(item) for item in single.get("limitations") or []),
                "Каждая строка содержит только проекцию одного неделимого назначения доступа.",
            ]))
            single["limits"] = {
                **dict(single.get("limits") or {}),
                "grant_branches": 1,
                "grant_branch_max": REPORT_GRANT_BRANCH_MAX,
            }
            return single
        combined = _sort_combined_report_items(
            [dict(item) for branch in branches for item in branch.get("items") or []],
            query_filters,
        )
        visible_keys = {
            str(field.get("key")) for branch in branches for field in branch.get("fields") or []
        }
        union_fields = [field_defs[key] for key in published_columns if key in visible_keys]
        public_report = {key: value for key, value in report.items() if key != "grants"}
        public_report["allowed_actions"] = sorted({
            str(item) for grant in unique_grants for item in grant.get("allowed_actions") or []
            if str(item) in definition_actions
        })
        if (
            "reports.export" not in set(access.get("capabilities") or [])
            or str(runtime_definition.get("export_policy") or "disabled") != "controlled"
        ):
            public_report["allowed_actions"] = [
                item for item in public_report["allowed_actions"] if item != "export"
            ]
        has_more = len(combined) > clean_limit or any(bool(branch.get("has_more")) for branch in branches)
        branch_states = [{
            "grant_branch": str(branch.get("_grant_branch") or ""),
            "state": str(branch.get("state") or "unknown"),
            "has_more": bool(branch.get("has_more")),
            "next_cursor": branch.get("next_cursor"),
            "fields": list(branch.get("_grant_fields") or []),
            "field_count": len(branch.get("fields") or []),
            "summary_available": isinstance(branch.get("summary"), Mapping),
        } for branch in branches]
        branch_summaries = [branch.get("summary") for branch in branches]
        common_summary = None
        if branch_summaries and all(isinstance(item, Mapping) for item in branch_summaries):
            canonical = [
                json.dumps(item, ensure_ascii=True, sort_keys=True, separators=(",", ":"), default=str)
                for item in branch_summaries
            ]
            if len(set(canonical)) == 1:
                common_summary = dict(branch_summaries[0])
        limitations = [
            "Каждая строка содержит только проекцию одного неделимого назначения доступа.",
            "При нескольких независимых назначениях каждая ветвь читается отдельно по grant_branch и имеет собственный cursor.",
        ]
        if common_summary is None:
            limitations.append(
                "Сводка веток не объединяется арифметически: области назначений могут пересекаться."
            )
        result = {
            "api_version": "v4", "report": public_report, "dataset_key": dataset_key,
            "state": "available" if combined else "empty", "items": combined[:clean_limit],
            "fields": union_fields, "field_visibility": "per_grant",
            "limitations": limitations, "branch_states": branch_states,
            "branch_continuations": branch_states,
            "has_more": has_more, "next_cursor": None,
            "limits": {"rows": clean_limit, "grant_branches": len(branches), "grant_branch_max": REPORT_GRANT_BRANCH_MAX, "total_count": "not_calculated"},
        }
        if common_summary is not None:
            result["summary"] = common_summary
        return result
    if requested is not None:
        if not requested or any(item not in published_columns for item in requested):
            raise PermissionError("report_field_access_denied")
        requested_categories = {str(field_defs[item].get("category") or "") for item in requested}
        eligible_grants = [grant for grant in grants if requested_categories <= set(grant.get("field_categories") or [])]
        selected = requested
    else:
        common_categories = set(grants[0].get("field_categories") or [])
        for grant in grants[1:]:
            common_categories &= set(grant.get("field_categories") or [])
        selected = [key for key in published_columns if str(field_defs[key].get("category") or "") in common_categories]
        eligible_grants = grants
    if not selected or not eligible_grants:
        raise PermissionError("report_field_access_denied")
    category_caps = {str(field_defs[key].get("category") or "") for key in selected}
    scopes = [dict(grant.get("scope") or {}) for grant in eligible_grants]
    unrestricted = any(str(scope.get("kind") or "") == "all" for scope in scopes)
    scope_clauses: list[str] = []
    scope_params: list[Any] = []
    if not unrestricted:
        for scope in scopes:
            kind = str(scope.get("kind") or "")
            if kind in {"server", "domain"}:
                raw_ids = scope.get("ids") or []
                try:
                    ids = [int(item) for item in raw_ids][:100]
                except (TypeError, ValueError) as exc:
                    raise PermissionError("invalid_report_scope") from exc
                if ids:
                    column = "server_id" if kind == "server" else "domain_id"
                    scope_clauses.append(f"{{alias}}.{column}=any(?)")
                    scope_params.append(ids)
            elif kind == "channel" and dataset_key == "events.v2":
                values = [str(item) for item in (scope.get("values") or [])][:100]
                if values:
                    scope_clauses.append("channel.value=any(?)")
                    scope_params.append(values)
        if not scope_clauses:
            raise PermissionError("report_scope_not_executable")
    where_sql = "" if unrestricted else " where (" + " or ".join(scope_clauses) + ")"
    filter_clauses, filter_params, order_sql = _compile_definition_query(dataset_key, runtime_definition)
    order_sql = _compile_interactive_sort(
        dataset_key,
        query_filters,
        default_order_sql=order_sql,
    )
    interactive_clauses: list[str] = []
    interactive_params: list[Any] = []
    vpn_cursor_id = None
    if query_filters:
        interactive_query = {
            str(key): value
            for key, value in query_filters.items()
            if str(key) not in {"sort", "direction"}
        }
        if dataset_key == "ad.accounts.vpn":
            vpn_cursor = interactive_query.pop("cursor", None)
            if vpn_cursor not in (None, ""):
                if order_sql != VPN_ACCOUNT_CURSOR_ORDER:
                    raise ValueError("report_cursor_requires_default_sort")
                vpn_cursor_id = _decode_vpn_account_cursor(vpn_cursor)
        if interactive_query:
            if dataset_key == "events.v2":
                interactive_clauses, interactive_params = _compile_interactive_event_query(
                    interactive_query, order_sql=order_sql,
                )
            else:
                interactive_clauses, interactive_params = _compile_interactive_report_query(
                    dataset_key, interactive_query,
                )
    effective_filter_clauses = filter_clauses + interactive_clauses
    effective_filter_params = filter_params + interactive_params
    state = "available"
    summary: dict[str, Any] | None = None
    filtered_count = None
    if dataset_key == "entities.v2":
        scoped_where = _append_predicates(where_sql.replace("{alias}", "entity"), effective_filter_clauses)
        rows = query_rows_bounded(
            f"""select entity.id,entity_type.value as entity_type,entity.display_name,entity.natural_key,entity.last_seen_utc,
                      case when exists(select 1 from ad_context_entity_versions v where v.entity_id=entity.id) then 'AD Context' else 'Storage V2' end as context_source
               from entities_v2_active entity join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id
               {scoped_where} order by {order_sql} limit ?""",
            tuple(scope_params + effective_filter_params + [clean_limit + 1]), statement_timeout_ms=5000,
        )
    elif dataset_key == "ad.audit.snapshot":
        summary_where = where_sql.replace("{alias}", "entity")
        scoped_where = _append_predicates(summary_where, effective_filter_clauses)
        connector = " and " if scoped_where else " where "
        summary = _ad_snapshot_summary(summary_where, scope_params, category_caps)
        rows = query_rows_bounded(
            f"""select entity.id::text as object_id,entity.display_name,entity_type.value as entity_type,entity.last_seen_utc,
                       'AD Context' as context_source,
                       (version.attributes_json->'attributes'->>'enabled')::boolean as enabled,
                       case when entity_type.value='ad_user' then {inactivity_sql("version.attributes_json->'attributes'", 'version.last_observed_at_utc')} else (version.attributes_json->'attributes'->>'is_inactive')::boolean end as is_inactive,
                       (version.attributes_json->'attributes'->>'password_never_expires')::boolean as password_never_expires,
                       (version.attributes_json->'attributes'->>'locked_out')::boolean as locked_out
                from entities_v2_active entity
                join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id
                join ad_context_entity_versions version
                  on version.entity_id=entity.id
                 and version.valid_to_utc is null
                 and version.source_section='directory_accounts'
                {scoped_where}
                order by {order_sql} limit ?""",
            tuple(scope_params + effective_filter_params + [clean_limit + 1]), statement_timeout_ms=REPORT_DATA_TIMEOUT_MS,
        )
    elif dataset_key == "events.v2":
        scoped_where = _append_predicates(where_sql.replace("{alias}", "event"), effective_filter_clauses)
        rows = query_rows_bounded(
            f"""select event.id,event.time_created_utc,event.event_id,channel.value as channel,event.subject_user_name,event.target_user_name
               from events_v2_core event join servers server on server.id=event.server_id
               join storage_v2_channel channel on channel.id=event.channel_id
               {scoped_where} order by {order_sql} limit ?""",
            tuple(scope_params + effective_filter_params + [clean_limit + 1]), statement_timeout_ms=5000,
        )
    elif dataset_key == "security.problems":
        if not unrestricted:
            raise PermissionError("report_scope_not_executable")
        filtered_where = _append_predicates("", effective_filter_clauses)
        rows = query_rows_bounded(
            f"""select title,severity,status,last_evidence_event_id as evidence_event_id
               from findings_active findings {filtered_where} order by {order_sql} limit ?""",
            tuple(effective_filter_params + [clean_limit + 1]), statement_timeout_ms=5000,
        )
        totals = query_rows_bounded(
            f"""select count(*) as total_items,max(updated_at) as latest_observed_at_utc
                from findings_active findings {filtered_where}""",
            tuple(effective_filter_params), statement_timeout_ms=5000,
        )
        aggregate = totals[0] if totals else {}
        summary = {
            "kind": "security_problems",
            "aggregate_scope": "effective_report_scope",
            "total_items": int(aggregate.get("total_items") or 0),
            "latest_observed_at_utc": aggregate.get("latest_observed_at_utc"),
        }
    elif dataset_key == "ad.accounts.privileged":
        summary_where = where_sql.replace("{alias}", "source_entity")
        scoped_where = _append_predicates(summary_where, effective_filter_clauses)
        connector = " and " if scoped_where else " where "
        summary = _privileged_account_summary(summary_where, scope_params, category_caps)
        rows = query_rows_bounded(
            f"""select source_entity.id::text as object_id,source_entity.display_name,source_entity.natural_key,
                       concat('member_of → ',target_entity.display_name) as privilege_path,
                       greatest(relation.last_observed_at_utc,source_entity.last_seen_utc) as last_seen_utc,
                       (account.attributes_json->'attributes'->>'enabled')::boolean as enabled,
                       {inactivity_sql("account.attributes_json->'attributes'", 'account.last_observed_at_utc')} as is_inactive,
                       (account.attributes_json->'attributes'->>'password_never_expires')::boolean as password_never_expires,
                       (account.attributes_json->'attributes'->>'locked_out')::boolean as locked_out,
                       account.attributes_json->'attributes'->>'last_logon_utc' as last_logon_utc
                from ad_context_relation_versions relation
                join entities_v2 source_entity on source_entity.id=relation.source_entity_id
                join entities_v2 target_entity on target_entity.id=relation.target_entity_id
                {VPN_ACCOUNT_ATTRIBUTES_LATERAL}
                {scoped_where}{connector}relation.valid_to_utc is null
                  and relation.relation_kind='member_of'
                  and relation.source_section='privileged_membership'
                  and {_active_entity_predicate('source_entity', 'target_entity')}
                order by {order_sql} limit ?""",
            tuple(scope_params + effective_filter_params + [clean_limit + 1]), statement_timeout_ms=5000,
        )
    elif dataset_key == "ad.accounts.vpn":
        summary, rows, filtered_count = require_plugin(
            "sli.remote-access", "accounts_dataset",
            where_sql=where_sql, scope_params=scope_params,
            effective_filter_clauses=effective_filter_clauses,
            effective_filter_params=effective_filter_params, category_caps=category_caps,
            vpn_cursor_id=vpn_cursor_id, order_sql=order_sql, clean_limit=clean_limit,
        )
    elif dataset_key == "ad.gpo.governance":
        summary_where = where_sql.replace("{alias}", "entity")
        scoped_where = _append_predicates(summary_where, effective_filter_clauses)
        connector = " and " if scoped_where else " where "
        summary = _gpo_governance_summary(summary_where, scope_params, category_caps)
        rows = query_rows_bounded(
            f"""select {GPO_GOVERNANCE_SELECT_SQL}
                 from ad_context_entity_versions version
                 join entities_v2 entity on entity.id=version.entity_id
                 join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id
                 {scoped_where}{connector}version.valid_to_utc is null
                   and version.source_section='gpo_governance'
                   and (entity_type.value='gpo' or lower(entity_type.value) like '%gpo%')
                   and {_active_entity_predicate('entity')}
                 order by {order_sql} limit ?""",
            tuple(scope_params + effective_filter_params + [clean_limit + 1]), statement_timeout_ms=5000,
        )
    else:
        raise ValueError("report_dataset_not_executable")
    has_more = len(rows) > clean_limit
    safe_rows = [{key: row.get(key) for key in selected} for row in rows[:clean_limit]]
    next_cursor = (
        _report_cursor(rows[clean_limit - 1])
        if dataset_key == "events.v2" and has_more and order_sql == DEFAULT_ORDERS["events.v2"]
        else None
    )
    if dataset_key == "ad.accounts.vpn" and has_more and order_sql == VPN_ACCOUNT_CURSOR_ORDER:
        next_cursor = _vpn_account_cursor(rows[clean_limit - 1])
    selected_categories = {str(field_defs[key].get("category") or "") for key in selected}
    effective_actions = sorted({
        str(action_name)
        for grant in all_grants
        if selected_categories <= set(grant.get("field_categories") or [])
        for action_name in (grant.get("allowed_actions") or [])
        if str(action_name) in definition_actions
    })
    if (
        "reports.export" not in set(access.get("capabilities") or [])
        or str(runtime_definition.get("export_policy") or "disabled") != "controlled"
    ):
        effective_actions = [item for item in effective_actions if item != "export"]
    public_report = {key: value for key, value in report.items() if key != "grants"}
    public_report["allowed_actions"] = effective_actions
    return {
        "api_version": "v4", "report": public_report, "dataset_key": dataset_key,
        "state": state if safe_rows or state != "available" else "empty", "items": safe_rows,
        "fields": [field_defs[key] for key in selected], "has_more": has_more,
        "next_cursor": next_cursor,
        "limits": {"rows": clean_limit, "total_count": filtered_count if filtered_count is not None else "not_calculated"},
        **({"filtered_count": filtered_count} if filtered_count is not None else {}),
        **({"summary": summary} if summary is not None else {}),
    }




_csv_cell = format_csv_cell






from server.sli.reporting.reporting_v4_export import (
    _workspace_focus_metrics,
    export_report_csv,
    export_report_csv_document,
)
from server.sli.reporting.reporting_v4_lifecycle import (
    code_defined_report_keys,
    promote_report_version,
    report_access_summary,
    report_definition_detail,
    retire_report,
    set_report_visibility,
)
from server.sli.reporting.reporting_v4_publish import (
    builder_preview,
    publish_report,
)
from server.sli.reporting.reporting_v4_summaries import (
    _ad_snapshot_summary,
    _context_section_coverage,
    _coverage_scope,
    _gpo_governance_summary,
    _privileged_account_summary,
    _vpn_account_summary,
)
