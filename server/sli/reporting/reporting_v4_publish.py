"""Split out of ``server.sli.reporting.reporting_v4`` (plan 7.2b).

Module-level names of ``reporting_v4`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.reporting.reporting_v4 as _src

from .reporting_v4_security import _security_predecessor


def publish_report(
    payload: _src.Mapping[str, _src.Any], principal: _src.Mapping[str, _src.Any] | None, *,
    remote_address: str | None = None, access: _src.Mapping[str, _src.Any] | None = None,
) -> dict[str, _src.Any]:
    access = dict(access or _src.effective_access(principal))
    if "reports.publish" not in access["capabilities"]:
        raise PermissionError("reports_publish_required")
    if "reports.design" not in access["capabilities"]:
        raise PermissionError("report_design_capability_required")
    preview = _src.builder_preview(payload, principal, access=access)
    report_key = str(payload.get("report_key") or "").strip()
    name = str(payload.get("name") or "").strip()
    purpose = str(payload.get("purpose") or "").strip()
    owner = str(payload.get("owner") or "").strip()
    status = str(payload.get("status") or "draft").strip().lower()
    sensitivity = str(payload.get("sensitivity") or "restricted").strip().lower()
    if not _src.re.fullmatch(r"[a-z0-9][a-z0-9_.-]{2,79}", report_key) or not name or not purpose or not owner or status not in {"draft", "published"} or sensitivity not in {"internal", "restricted", "confidential"}:
        raise ValueError("invalid_report_definition")
    actor_id = int(principal["id"]) if principal and principal.get("id") is not None else None
    with _src._connect() as conn, conn.cursor() as cur:
        cur.execute("select pg_advisory_xact_lock(hashtext(%s))", (report_key,))
        cur.execute(
            """select r.definition_json,r.discoverable,r.requestable,r.request_profile_json,d.dataset_key
               from report_registry_v4 r join report_datasets_v4 d on d.id=r.dataset_id
               where r.report_key=%s and r.status='published'
               order by r.version desc limit 1 for update""",
            (report_key,),
        )
        previous = dict(cur.fetchone() or {})
        cur.execute("select id from report_datasets_v4 where dataset_key=%s and version=%s", (preview["dataset"]["key"], preview["dataset"]["version"]))
        dataset_id = int(cur.fetchone()["id"])
        cur.execute("select coalesce(max(version),0)+1 as version from report_registry_v4 where report_key=%s", (report_key,))
        version = int(cur.fetchone()["version"])
        definition = {
            "columns": [item["key"] for item in preview["fields"]], "filters": preview["filters"],
            "sort": preview["sort"],
            "actions": preview["actions"], "required_capabilities": preview["required_capabilities"],
            "field_categories": preview["required_field_categories"], "target_path": f"/reports/{report_key}",
            "export_policy": "controlled" if "export" in preview["actions"] else "disabled",
            "dashboard_metrics": preview["dashboard_metrics"],
        }
        discoverable = payload.get(
            "discoverable",
            previous.get("discoverable", False) if previous else False,
        )
        requestable = payload.get(
            "requestable",
            previous.get("requestable", False) if previous else False,
        )
        if not isinstance(discoverable, bool) or not isinstance(requestable, bool):
            raise ValueError("invalid_report_discovery_policy")
        raw_profile = payload.get(
            "request_profile",
            _src._json_mapping(previous.get("request_profile_json")) if previous else {},
        )
        if not isinstance(raw_profile, _src.Mapping):
            raise ValueError("invalid_report_request_profile")
        supported_scope_kinds = {"all"}
        if preview["dataset"]["key"] in {
            "entities.v2", "ad.audit.snapshot", "ad.accounts.privileged",
            "ad.accounts.vpn", "ad.gpo.governance",
        }:
            supported_scope_kinds.update({"server", "domain"})
        if preview["dataset"]["key"] == "events.v2":
            supported_scope_kinds.update({"server", "domain", "channel"})
        scope_kinds = sorted({
            str(item) for item in raw_profile.get("scope_kinds", ["all"])
            if str(item)
        })
        profile_fields = sorted({
            str(item) for item in raw_profile.get(
                "field_categories", preview["required_field_categories"],
            ) if str(item)
        })
        profile_actions = sorted({
            str(item) for item in raw_profile.get("allowed_actions", ["view"])
            if str(item)
        })
        max_duration_days = int(raw_profile.get("max_duration_days") or 90)
        if (
            not scope_kinds or not set(scope_kinds) <= supported_scope_kinds
            or not set(profile_fields) <= set(preview["required_field_categories"])
            or not set(profile_actions) <= set(preview["actions"])
            or "view" not in profile_actions
            or not 1 <= max_duration_days <= 365
        ):
            raise ValueError("invalid_report_request_profile")
        request_profile = {
            "scope_kinds": scope_kinds,
            "field_categories": profile_fields,
            "allowed_actions": profile_actions,
            "max_duration_days": max_duration_days,
        }
        if requestable and not discoverable:
            raise ValueError("requestable_report_must_be_discoverable")
        if status == "published":
            cur.execute(
                """select exists(
                       select 1 from access_report_assignments where report_key=%s
                       union all
                       select 1 from access_package_reports where report_key=%s
                   ) as has_grants""",
                (report_key, report_key),
            )
            has_grants = bool((cur.fetchone() or {}).get("has_grants"))
            if has_grants:
                predecessor = _security_predecessor(cur, report_key, previous)
                dataset_changed = str(predecessor.get("dataset_key") or "") != str(preview["dataset"]["key"])
                if not predecessor or dataset_changed or _src._security_expands(
                    _src._json_mapping(predecessor.get("definition_json")), definition,
                ):
                    raise ValueError("report_security_reapproval_required")
        if status == "published" and previous:
            cur.execute(
                "update report_registry_v4 set status='retired' where report_key=%s and status='published'",
                (report_key,),
            )
        cur.execute(
            """
            insert into report_registry_v4(
                report_key,version,name,owner_name,purpose,dataset_id,definition_json,
                sensitivity,status,published_at,created_by,
                discoverable,requestable,request_profile_json
            )
            values(
                %s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s,
                case when %s='published' then now() else null end,%s,
                %s,%s,%s::jsonb
            )
            returning report_key,version,name,owner_name,purpose,sensitivity,status,
                      published_at,created_at,discoverable,requestable,request_profile_json
            """,
            (
                report_key,version,name,owner,purpose,dataset_id,
                _src.json.dumps(definition,ensure_ascii=False),sensitivity,status,status,
                actor_id,discoverable,requestable,
                _src.json.dumps(request_profile,ensure_ascii=False),
            ),
        )
        result = dict(cur.fetchone() or {})
        _src.record_access_audit_with_cursor(
            cursor=cur,
            actor=principal,
            action=(
                "report_published" if status == "published"
                else "report_draft_created"
            ),
            target_type="report",
            target_key=report_key,
            reason=purpose,
            details={"version": version, "dataset": preview["dataset"]},
            remote_address=remote_address,
        )
    return result


def builder_preview(
    payload: _src.Mapping[str, _src.Any], principal: _src.Mapping[str, _src.Any] | None, *,
    access: _src.Mapping[str, _src.Any] | None = None,
) -> dict[str, _src.Any]:
    access = dict(access or _src.effective_access(principal))
    if "reports.design" not in access["capabilities"]:
        raise PermissionError("reports_design_required")
    if _src._definition_has_unsafe_text(payload):
        raise ValueError("arbitrary_sql_or_unsafe_definition_rejected")
    dataset_key = str(payload.get("dataset_key") or "").strip()
    dataset_version = int(payload.get("dataset_version") or 1)
    requested_fields = [str(item) for item in (payload.get("fields") or [])]
    requested_filters = list(payload.get("filters") or [])
    requested_sort = list(payload.get("sort") or [])
    requested_actions = [str(item) for item in (payload.get("actions") or [])]
    dashboard_metrics = _src._dashboard_metric_definitions(payload.get("dashboard_metrics"))
    with _src._connect() as conn, conn.cursor() as cur:
        cur.execute(
            """select dataset_key,version,name,object_type,fields_json,filters_json,actions_json
               from report_datasets_v4 where dataset_key=%s and version=%s and status='published'""",
            (dataset_key, dataset_version),
        )
        dataset = dict(cur.fetchone() or {})
    if not dataset:
        raise ValueError("unknown_dataset")
    if dataset_key not in _src.EXECUTABLE_DATASETS:
        raise ValueError("report_dataset_not_executable")
    known_fields = {str(item["key"]): dict(item) for item in (dataset.get("fields_json") or []) if isinstance(item, _src.Mapping) and item.get("key")}
    known_filters = {str(item["key"]): set(str(op) for op in (item.get("ops") or [])) for item in (dataset.get("filters_json") or []) if isinstance(item, _src.Mapping) and item.get("key")}
    known_actions = {str(item) for item in (dataset.get("actions_json") or [])}
    if not requested_fields or any(field not in known_fields for field in requested_fields):
        raise ValueError("unknown_or_empty_field_selection")
    for item in requested_filters:
        if not isinstance(item, _src.Mapping):
            raise ValueError("invalid_filter")
        key = str(item.get("field") or "")
        op = str(item.get("op") or "")
        if key not in known_filters or op not in known_filters[key]:
            raise ValueError("unknown_filter_or_operator")
        if key not in _src.RUNTIME_FILTER_FIELDS.get(dataset_key, {}):
            raise ValueError("report_filter_not_executable")
        _src._typed_filter_value(dataset_key, key, item.get("value"), many=op == "in")
    for item in requested_sort:
        if not isinstance(item, _src.Mapping):
            raise ValueError("invalid_sort")
        key = str(item.get("field") or "")
        direction = str(item.get("direction") or "").lower()
        if key not in known_fields or direction not in {"asc", "desc"}:
            raise ValueError("unknown_sort_field_or_direction")
        if key not in _src.RUNTIME_SORT_FIELDS.get(dataset_key, {}):
            raise ValueError("report_sort_not_executable")
    if any(action not in known_actions for action in requested_actions):
        raise ValueError("unknown_action")
    categories = sorted({str(known_fields[field].get("category") or "identity_basic") for field in requested_fields})
    capability_map = {
        "raw_evidence": "evidence.exact", "technical": "field.technical", "privilege": "field.privilege",
        "security": "field.security", "hr": "field.hr", "contact": "field.contact",
        "identity_basic": "field.identity_basic", "sensitive": "field.sensitive",
    }
    action_caps = {"export": "reports.export", "start_case": "investigations.manage", "create_task": "tasks.create", "grant_access": "access.manage"}
    required = sorted({capability_map.get(category, f"field.{category}") for category in categories} | {action_caps[action] for action in requested_actions if action in action_caps})
    missing = sorted(set(required) - set(access["capabilities"]))
    result = {
        "api_version": "v4", "status": "accepted" if not missing else "gated",
        "dataset": {"key": dataset_key, "version": dataset_version, "name": dataset["name"]},
        "fields": [known_fields[field] for field in requested_fields], "filters": requested_filters,
        "sort": requested_sort,
        "actions": requested_actions, "required_capabilities": required, "missing_capabilities": missing,
        "required_field_categories": categories, "arbitrary_sql_allowed": False,
        "dashboard_metrics": dashboard_metrics,
        "sample_rows": [], "sample_state": "not_requested_no_data_disclosure",
    }
    if payload.get("with_rows") is True:
        result.update(_preview_sample(
            result, list(known_fields.values()), principal, access, missing,
        ))
    return result


PREVIEW_SAMPLE_LIMIT = 20


def _preview_grants(
    access: _src.Mapping[str, _src.Any], dataset_key: str,
    all_categories: set[str],
) -> list[dict[str, _src.Any]]:
    """The caller's own grants for the dataset (owner: unrestricted)."""
    if access.get("platform_owner"):
        return [{
            "source_type": "platform_owner", "source": "owner:primary",
            "scope": {"kind": "all"}, "field_categories": sorted(all_categories),
            "allowed_actions": ["view"],
        }]
    grants: list[dict[str, _src.Any]] = []
    for item in access.get("reports") or []:
        if item.get("allowed") and str(item.get("dataset_key")) == dataset_key:
            grants.extend(
                dict(grant) for grant in item.get("grants") or []
                if "view" in (grant.get("allowed_actions") or [])
            )
    return grants


def _preview_sample(
    preview: _src.Mapping[str, _src.Any], dataset_fields: list[dict[str, _src.Any]],
    principal: _src.Mapping[str, _src.Any] | None, access: _src.Mapping[str, _src.Any],
    missing: list[str],
) -> dict[str, _src.Any]:
    base: dict[str, _src.Any] = {
        "sample_rows": [], "sample_columns": [], "sample_limit": PREVIEW_SAMPLE_LIMIT,
    }
    if preview["status"] != "accepted" or missing:
        return {**base, "sample_state": "gated", "sample_missing_capabilities": list(missing)}
    dataset_key = str(preview["dataset"]["key"])
    categories = {str(item.get("category") or "identity_basic") for item in dataset_fields}
    grants = _preview_grants(access, dataset_key, categories)
    if not grants:
        return {**base, "sample_state": "gated", "sample_missing_capabilities": [],
                "sample_gate_reason": "no_dataset_access"}
    definition_json = {
        "columns": [item["key"] for item in preview["fields"]],
        "filters": preview["filters"], "sort": preview["sort"], "actions": ["view"],
        "export_policy": "disabled",
        "required_capabilities": preview["required_capabilities"],
        "field_categories": preview["required_field_categories"],
    }
    report = {"report_key": "builder.preview", "version": 0, "allowed": True, "grants": grants}
    definition = {
        "dataset_key": dataset_key, "fields_json": dataset_fields,
        "definition_json": definition_json,
    }
    try:
        result = _src._execute_definition(
            "builder.preview", report, definition, principal, limit=PREVIEW_SAMPLE_LIMIT,
            fields=None, action="view", query_filters=None, access=access,
        )
    except PermissionError:
        return {**base, "sample_state": "gated", "sample_missing_capabilities": [],
                "sample_gate_reason": "no_dataset_access"}
    rows = [dict(item) for item in (result.get("items") or [])][:PREVIEW_SAMPLE_LIMIT]
    return {
        "sample_rows": rows,
        "sample_columns": [dict(item) for item in result.get("fields") or []],
        "sample_state": "rows" if rows else "empty",
        "sample_limit": PREVIEW_SAMPLE_LIMIT,
    }
