"""Shared policy evaluator for trusted, time-filtered facts.

No DB/schema/credential/UI loaders. Facts are authority inputs; a schedule
worker must load them only from the fixed lease-bound database accessor.
"""
from __future__ import annotations
import json
from copy import deepcopy
from datetime import datetime
from typing import Any, Mapping, Sequence
from server.sli.access.scope import AccessScope


def compose_schedule_access(subject, facts, *, report_key, now):
    """Apply the shared evaluator to fixed-accessor facts, with no DB/UI path.

    This is trusted-process code, not an RPC accepting client authority. The
    lease-bound accessor must derive actors/report and time-filter facts in one
    database snapshot. Expiry is checked again at the supplied DB evaluation
    time. Callers must reload facts at publication/dispatch, not cache decisions.
    """
    keys = {"security.problems": "security.queue", "file-audit.mass-operations": "file-audit.mass-operations"}
    expected = {"is_owner", "groups", "role_packages", "subject_packages", "owner_packages",
                "package_capabilities", "direct_capabilities", "all_capabilities", "package_reports",
                "report_assignments", "definitions"}
    try:
        if (report_key not in keys or not isinstance(subject, Mapping)
                or set(subject) != {"type", "id", "role", "is_active"}
                or subject["type"] != "session" or subject["is_active"] is not True
                or type(subject["id"]) is not int or subject["id"] <= 0
                or not isinstance(subject["role"], str) or now.tzinfo is None
                or not isinstance(facts, Mapping) or set(facts) != expected):
            raise ValueError
        data = deepcopy(dict(facts))
        if any(not isinstance(rows, list) or len(rows) > 2048 for rows in data.values()):
            raise ValueError
        # These fields have no role in worker policy composition.
        forbidden = {"username", "name", "group_key", "label", "business_reason", "request_states",
                     "preferences", "navigation", "owner_name", "purpose", "password_hash", "is_service"}
        def check(value):
            if isinstance(value, dict):
                if set(value) & forbidden:
                    raise ValueError
                for key, child in value.items():
                    # Scope syntax (including malformed denies) is policy data
                    # for the existing fail-closed normalizer, not a UI record.
                    if key != "scope_json":
                        check(child)
            elif isinstance(value, list):
                for child in value:
                    check(child)
        check(data)
        for rows in data.values():
            for row in rows:
                if not isinstance(row, dict):
                    raise ValueError
                for field in ("valid_from", "valid_until"):
                    value = row.get(field)
                    if isinstance(value, str):
                        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
                        row[field] = value
                    if value is not None and (not isinstance(value, datetime) or value.tzinfo is None):
                        raise ValueError
        for key in ("groups", "role_packages", "subject_packages", "owner_packages",
                    "direct_capabilities", "report_assignments"):
            data[key] = [row for row in data[key] if _active(row.get("valid_from"), row.get("valid_until"), now)]
        group_ids = {row["id"] for row in data["groups"]}
        for key in ("direct_capabilities", "report_assignments"):
            data[key] = [row for row in data[key] if row.get("subject_type") == "user"
                         and row.get("subject_id") == subject["id"] or row.get("subject_type") == "group"
                         and row.get("subject_id") in group_ids]
        data["subject_packages"] = [row for row in data["subject_packages"]
            if row.get("source_key") == f"user:{subject['id']}"
            or row.get("source_key") in {f"group:{identifier}" for identifier in group_ids}]
        access_key = keys[report_key]
        if len(data["definitions"]) != 1 or any(row.get("report_key") != access_key
                for key in ("definitions", "package_reports", "report_assignments") for row in data[key]):
            raise ValueError
        data.update(requests=[], preferences=[])
        result = compose_access_facts(subject, data, now=now)
    except (KeyError, TypeError, ValueError, AttributeError, RecursionError):
        raise ValueError("invalid_schedule_access_facts") from None
    report_fields = {"report_key", "version", "dataset_version", "dataset_key", "allowed",
                     "allowed_actions", "field_categories", "grants"}
    return {
        "subject": {key: result["subject"][key] for key in ("type", "id", "coarse_role")},
        "platform_owner": result["platform_owner"], "capabilities": result["capabilities"],
        "capability_policies": result["capability_policies"],
        "reports": [{key: value for key, value in report.items() if key in report_fields}
                    for report in result["reports"]],
    }

VIEWER_SAFE_CAPABILITIES = frozenset({
    "workspace.view", "reports.catalog", "objects.view", "objects.groups",
    "events.view", "investigations.view", "field.identity_basic", "field.security",
    "field.computer_logon_observation",
})


FIELD_CATEGORY_CAPABILITIES: dict[str, frozenset[str]] = {
    "identity_basic": frozenset({"field.identity_basic"}),
    "security": frozenset({"field.security"}),
    "technical": frozenset({"field.technical"}),
    "privilege": frozenset({"field.privilege"}),
    "contact": frozenset({"field.contact"}),
    "hr": frozenset({"field.hr"}),
    "sensitive": frozenset({"field.sensitive"}),
    "raw_evidence": frozenset({"field.raw_evidence", "evidence.exact"}),
    "computer_logon_observation": frozenset({"field.computer_logon_observation"}),
}


ACTION_CAPABILITIES = {
    "export": "reports.export", "create_task": "tasks.create",
    "start_case": "investigations.manage", "grant_access": "access.manage",
    "configure_channel": "access.manage",
    "manage_decoy": "decoys.manage",
    "manage_watch": "watch.manage",
}


def _active(valid_from: Any, valid_until: Any, now: datetime) -> bool:
    if valid_from is not None and valid_from > now:
        return False
    return valid_until is None or valid_until > now


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if value in (None, ""):
        return {}
    parsed = json.loads(str(value))
    return dict(parsed) if isinstance(parsed, Mapping) else {}


def _json_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value in (None, ""):
        return []
    parsed = json.loads(str(value))
    return list(parsed) if isinstance(parsed, list) else []


def normalize_capability_scope(value: Any) -> tuple[dict[str, Any] | None, str | None]:
    """Parse the strict capability-scope contract without widening malformed rows."""
    if value in (None, ""):
        return {"kind": "all"}, None
    if isinstance(value, Mapping):
        scope = dict(value)
    else:
        try:
            parsed = json.loads(str(value))
        except (TypeError, ValueError, json.JSONDecodeError):
            return None, "invalid_scope"
        if not isinstance(parsed, Mapping):
            return None, "invalid_scope"
        scope = dict(parsed)
    if not scope:
        return {"kind": "all"}, None
    kind = scope.get("kind")
    if kind == "all" and set(scope) == {"kind"}:
        return {"kind": "all"}, None
    if kind in {"server", "domain"} and set(scope) == {"kind", "ids"}:
        raw_ids = scope.get("ids")
        if not isinstance(raw_ids, list) or not raw_ids:
            return None, "invalid_scope"
        if any(isinstance(item, bool) or not isinstance(item, int) or item <= 0 for item in raw_ids):
            return None, "invalid_scope"
        if len(set(raw_ids)) != len(raw_ids):
            return None, "invalid_scope"
        return {"kind": kind, "ids": list(raw_ids)}, None
    if kind == "channel" and set(scope) == {"kind", "values"}:
        raw_values = scope.get("values")
        if not isinstance(raw_values, list) or not raw_values:
            return None, "invalid_scope"
        values = [str(item).strip() for item in raw_values if isinstance(item, str)]
        if len(values) != len(raw_values) or any(not item for item in values) or len(set(values)) != len(values):
            return None, "invalid_scope"
        return {"kind": "channel", "values": values}, None
    return None, "invalid_scope"


def _capability_scope_is_global(value: Any) -> bool:
    scope, error = normalize_capability_scope(value)
    return error is None and scope == {"kind": "all"}


def restrict_viewer_starter_sources(
    role: str, capability_sources: Mapping[str, list[dict[str, Any]]],
) -> dict[str, list[dict[str, Any]]]:
    """Limit only the coarse-role starter source; preserve approved direct/group grants."""
    if role != "viewer":
        return {str(key): list(value) for key, value in capability_sources.items()}
    bounded: dict[str, list[dict[str, Any]]] = {}
    for key, sources in capability_sources.items():
        kept = [
            dict(source) for source in sources
            if key in VIEWER_SAFE_CAPABILITIES or str(source.get("source_origin") or "") != "role"
        ]
        if kept:
            bounded[str(key)] = kept
    return bounded


def _scope_matches_resource(scope: Mapping[str, Any], resource: Mapping[str, Any]) -> bool:
    if "mode" in scope:
        try:
            generic = AccessScope.from_dict(scope)
        except ValueError:
            return False
        return generic.allows(
            plugin_id=resource.get("plugin_id"), source_instance_id=resource.get("source_instance_id"),
            device_id=resource.get("device_id"), entity_id=resource.get("entity_id"),
            collection_scope_id=resource.get("collection_scope_id"),
            domain_id=resource.get("domain_id") or (resource.get("id") if resource.get("kind") == "domain" else None),
        )
    kind = str(scope.get("kind") or "")
    if kind == "all":
        return True
    if str(resource.get("kind") or "") != kind:
        return False
    if kind in {"server", "domain"}:
        try:
            return int(resource.get("id")) in set(int(item) for item in scope.get("ids") or [])
        except (TypeError, ValueError):
            return False
    if kind == "channel":
        return str(resource.get("value") or "") in set(str(item) for item in scope.get("values") or [])
    return False


def capability_decision(
    access: Mapping[str, Any], capability: str, *, resource: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Evaluate one capability including scoped/invalid deny rows."""
    key = str(capability)
    if access.get("platform_owner"):
        return {"allowed": True, "reason": "platform_owner", "capability": key, "diagnostics": []}
    policies = [
        dict(item) for item in access.get("capability_policies", [])
        if str(item.get("capability_key") or "") == key
    ]
    invalid_denies = [item for item in policies if item.get("effect") == "deny" and not item.get("valid")]
    if invalid_denies:
        return {"allowed": False, "reason": "invalid_scope_policy", "capability": key, "diagnostics": ["invalid_scope"]}
    valid = [item for item in policies if item.get("valid")]
    global_denies = [item for item in valid if item.get("effect") == "deny" and item.get("scope") == {"kind": "all"}]
    if global_denies:
        return {"allowed": False, "reason": "explicit_deny", "capability": key, "diagnostics": []}
    scoped_denies = [
        item for item in valid
        if item.get("effect") == "deny" and item.get("scope") != {"kind": "all"}
    ]
    if scoped_denies and resource is None:
        return {"allowed": False, "reason": "resource_context_required", "capability": key, "diagnostics": []}
    if resource is not None and any(_scope_matches_resource(item.get("scope") or {}, resource) for item in scoped_denies):
        return {"allowed": False, "reason": "explicit_deny", "capability": key, "diagnostics": []}
    if key in set(access.get("capabilities") or []):
        return {"allowed": True, "reason": "global_allow", "capability": key, "diagnostics": []}
    scoped_allows = [
        item for item in valid
        if item.get("effect") == "allow" and item.get("scope") != {"kind": "all"}
    ]
    if scoped_allows and resource is None:
        return {"allowed": False, "reason": "resource_context_required", "capability": key, "diagnostics": []}
    if resource is not None and any(_scope_matches_resource(item.get("scope") or {}, resource) for item in scoped_allows):
        return {"allowed": True, "reason": "scoped_allow", "capability": key, "diagnostics": []}
    return {"allowed": False, "reason": "insufficient_capability", "capability": key, "diagnostics": []}


def capability_decision_for_resource_groups(
    access: Mapping[str, Any],
    capability: str,
    *,
    resource_groups: Sequence[Sequence[Mapping[str, Any]]] | None,
) -> dict[str, Any]:
    """Evaluate one capability for one or more evidence-resource alternatives.

    Each inner group represents the equivalent dimensions of one protected
    object (for example server/domain/channel for one event).  Every group must
    be covered by an allow, while any matching deny rejects the whole action.
    """
    key = str(capability)
    if access.get("platform_owner"):
        return {"allowed": True, "reason": "platform_owner", "capability": key, "diagnostics": []}
    policies = [
        dict(item) for item in access.get("capability_policies", [])
        if str(item.get("capability_key") or "") == key
    ]
    if any(item.get("effect") == "deny" and not item.get("valid") for item in policies):
        return {"allowed": False, "reason": "invalid_scope_policy", "capability": key, "diagnostics": ["invalid_scope"]}
    valid = [item for item in policies if item.get("valid")]
    denies = [item for item in valid if item.get("effect") == "deny"]
    if any(item.get("scope") == {"kind": "all"} for item in denies):
        return {"allowed": False, "reason": "explicit_deny", "capability": key, "diagnostics": []}
    groups = [[dict(resource) for resource in group] for group in (resource_groups or [])]
    if any(not group for group in groups):
        return {"allowed": False, "reason": "resource_context_required", "capability": key, "diagnostics": []}
    if any(
        _scope_matches_resource(item.get("scope") or {}, resource)
        for item in denies
        for group in groups
        for resource in group
    ):
        return {"allowed": False, "reason": "explicit_deny", "capability": key, "diagnostics": []}
    if key in set(access.get("capabilities") or []):
        return {"allowed": True, "reason": "global_allow", "capability": key, "diagnostics": []}
    allows = [item for item in valid if item.get("effect") == "allow"]
    if not groups:
        return {"allowed": False, "reason": "resource_context_required", "capability": key, "diagnostics": []}
    if all(
        any(
            item.get("scope") == {"kind": "all"}
            or _scope_matches_resource(item.get("scope") or {}, resource)
            for item in allows
            for resource in group
        )
        for group in groups
    ):
        return {"allowed": True, "reason": "scoped_allow", "capability": key, "diagnostics": []}
    return {"allowed": False, "reason": "insufficient_capability", "capability": key, "diagnostics": []}


def _report_scope_is_global(scope: Mapping[str, Any]) -> bool:
    if scope == {"kind": "all"}:
        return True
    if "mode" not in scope:
        return False
    try:
        return AccessScope.from_dict(scope).mode == "all"
    except (TypeError, ValueError):
        return False


def report_action_decision(
    access: Mapping[str, Any],
    report_key: str,
    action: str,
    *,
    resource_groups: Sequence[Sequence[Mapping[str, Any]]] | None,
    required_field_categories: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Authorize one report action and optional fields without trusting client scope.

    A grant remains atomic: when fields are required, the same grant must
    contain the action, every field category, and a matching scope.
    """
    key = str(report_key)
    clean_action = str(action)
    required_fields = {str(item) for item in (required_field_categories or []) if str(item)}
    report = next((dict(item) for item in access.get("reports", []) if str(item.get("report_key") or "") == key), None)
    if report is None or not report.get("allowed"):
        return {"allowed": False, "reason": "report_not_assigned", "report_key": key, "action": clean_action}
    grants = [
        dict(grant) for grant in report.get("grants", [])
        if clean_action in set(str(item) for item in grant.get("allowed_actions", []))
        and required_fields <= {str(item) for item in grant.get("field_categories", [])}
    ]
    if not grants:
        return {
            "allowed": False,
            "reason": "report_field_categories_not_allowed" if required_fields else "report_action_not_allowed",
            "report_key": key,
            "action": clean_action,
        }
    groups = [[dict(resource) for resource in group] for group in (resource_groups or [])]
    if not groups:
        if any(_report_scope_is_global(grant.get("scope") or {}) for grant in grants):
            return {"allowed": True, "reason": "global_report_scope", "report_key": key, "action": clean_action}
        return {"allowed": False, "reason": "resource_context_required", "report_key": key, "action": clean_action}
    if any(not group for group in groups):
        return {"allowed": False, "reason": "resource_context_required", "report_key": key, "action": clean_action}
    if all(
        any(
            _report_scope_is_global(grant.get("scope") or {})
            or _scope_matches_resource(grant.get("scope") or {}, resource)
            for grant in grants
            for resource in group
        )
        for group in groups
    ):
        return {"allowed": True, "reason": "report_scope_match", "report_key": key, "action": clean_action}
    return {"allowed": False, "reason": "report_scope_denied", "report_key": key, "action": clean_action}


def _bounded_report_grant(grant: Mapping[str, Any], capabilities: set[str]) -> dict[str, Any]:
    """Keep one grant atomic while removing fields/actions its principal cannot use."""
    fields = [
        str(item) for item in grant.get("field_categories", [])
        if FIELD_CATEGORY_CAPABILITIES.get(str(item), frozenset({f"field.{item}"})) <= capabilities
    ]
    actions = [
        str(item) for item in grant.get("allowed_actions", [])
        if item == "view" or ACTION_CAPABILITIES.get(str(item)) in capabilities
    ]
    return {**dict(grant), "field_categories": sorted(set(fields)), "allowed_actions": sorted(set(actions))}


def _version_bound_report_grant(
    grant: Mapping[str, Any], *, categories: set[str], actions: set[str],
    report_version: int, dataset_version: int,
) -> dict[str, Any] | None:
    """Revalidate a floating assignment without widening it on publication."""
    compatible = {
        **dict(grant),
        "field_categories": sorted(set(grant.get("field_categories") or []) & categories),
        "allowed_actions": sorted(set(grant.get("allowed_actions") or []) & actions),
        "validated_report_version": int(report_version),
        "validated_dataset_version": int(dataset_version),
    }
    return compatible if "view" in compatible["allowed_actions"] else None


def _access_explanation_code(
    *, allowed: bool, is_platform_owner: bool, resource_context_required: bool,
    explicit_deny: bool, missing: bool, has_assignment_source: bool, assigned: bool,
) -> str:
    """Presentation code for an already evaluated decision; does not authorize access."""
    return (
        "platform_owner" if allowed and is_platform_owner else
        "resource_context" if allowed and resource_context_required else
        "assignment_policy" if allowed else
        "explicit_deny" if explicit_deny else
        "missing_capabilities" if missing else
        "version_review" if has_assignment_source and not assigned else
        "not_assigned"
    )


def _access_subject(subject):
    restricted = subject.get('type') == 'api_key' and subject.get('report_subject_id') is not None
    if restricted:
        return 'report_reader', int(subject['report_subject_id']), True
    user_id = int(subject['id']) if subject.get('type') == 'session' and subject.get('id') is not None else None
    return str(subject.get('role') or 'viewer'), user_id, False


def compose_access_facts(subject, facts, *, now, preview=False):
    """Compose trusted, time-filtered policy facts without database reads."""
    role, user_id, restricted_key = _access_subject(subject)
    is_platform_owner = False
    if user_id is not None and not restricted_key:
        is_platform_owner = bool((next(iter(facts.get('is_owner', [])), {}) or {}).get("is_owner"))
    group_ids: list[int] = []
    groups: list[dict[str, Any]] = []
    if user_id is not None and not restricted_key:
        groups = [dict(row) for row in facts.get('groups', [])]
        group_ids = [int(row["id"]) for row in groups]

    package_rows = [dict(row) for row in facts.get('role_packages', [])]
    if user_id is not None and not restricted_key:
        package_rows.extend(dict(row) for row in facts.get('subject_packages', []))
    if is_platform_owner:
        package_rows.extend(dict(row) for row in facts.get('owner_packages', []))

    denied_packages = {str(row["package_key"]) for row in package_rows if row.get("effect") == "deny"}
    allowed_packages: dict[str, dict[str, Any]] = {}
    package_explain: list[dict[str, Any]] = []
    for row in package_rows:
        key = str(row["package_key"])
        package_explain.append({
            "package_key": key, "name": str(row.get('name', '')), "effect": str(row["effect"]),
            "source_type": str(row["source_kind"]), "source": str(row["source_key"]),
            "valid_from": row.get("valid_from"), "valid_until": row.get("valid_until"),
        })
        if row.get("effect") == "allow" and (is_platform_owner or key not in denied_packages):
            allowed_packages[key] = row

    package_ids = [int(row["id"]) for row in allowed_packages.values()]
    capability_sources: dict[str, list[dict[str, Any]]] = {}
    if package_ids:
        for row in [r for r in facts.get('package_capabilities', []) if str(r['package_key']) in allowed_packages]:
            package = allowed_packages.get(str(row["package_key"])) or {}
            capability_sources.setdefault(str(row["capability_key"]), []).append({
                "source_type": "package", "source": str(row["package_key"]),
                "source_origin": str(package.get("source_kind") or "role"),
            })

    direct_cap_rows: list[dict[str, Any]] = []
    if user_id is not None:
        direct_cap_rows = [dict(row) for row in facts.get('direct_capabilities', [])]
    global_cap_rows: list[dict[str, Any]] = []
    capability_policies: list[dict[str, Any]] = []
    quarantined_capabilities: list[dict[str, Any]] = []
    resource_bound_capabilities: list[dict[str, Any]] = []
    for row in direct_cap_rows:
        scope, scope_error = normalize_capability_scope(row.get("scope_json"))
        policy = {
            "capability_key": str(row["capability_key"]),
            "effect": str(row["effect"]),
            "scope": scope,
            "valid": scope_error is None,
            "diagnostic": scope_error,
            "source_type": str(row.get("source_type") or row.get("subject_type") or "assignment"),
            "source": f"{row['subject_type']}:{row['subject_id']}",
        }
        capability_policies.append(policy)
        if scope_error is not None:
            quarantined_capabilities.append({
                "capability_key": str(row["capability_key"]), "effect": str(row["effect"]),
                "reason": "invalid_scope",
            })
        elif scope == {"kind": "all"}:
            global_cap_rows.append(row)
        else:
            resource_bound_capabilities.append({
                "capability_key": str(row["capability_key"]), "effect": str(row["effect"]),
                "scope": scope, "reason": "resource_context_required",
            })
    denied_caps = {str(row["capability_key"]) for row in global_cap_rows if row.get("effect") == "deny"}
    invalid_deny_caps = {
        str(item["capability_key"]) for item in capability_policies
        if item.get("effect") == "deny" and not item.get("valid")
    }
    for row in global_cap_rows:
        key = str(row["capability_key"])
        if row.get("effect") == "allow" and key not in denied_caps:
            capability_sources.setdefault(key, []).append({
                "source_type": str(row["source_type"]),
                "source": f"{row['subject_type']}:{row['subject_id']}",
                "source_origin": str(row.get("subject_type") or row.get("source_type") or "direct"),
                "scope": {"kind": "all"},
                "valid_until": row.get("valid_until"),
            })
    for key in denied_caps | invalid_deny_caps:
        capability_sources.pop(key, None)
    capability_sources = restrict_viewer_starter_sources(role, capability_sources)
    if is_platform_owner:
        capability_sources = {
            str(row["capability_key"]): [{
                "source_type": "platform_owner", "source": "owner:primary",
                "source_origin": "platform_owner", "scope": {"kind": "all"},
            }]
            for row in facts.get('all_capabilities', [])
        }
    capabilities = sorted(capability_sources)
    resource_capability_keys = {
        str(item["capability_key"]) for item in resource_bound_capabilities
        if item.get("effect") == "allow"
        and str(item["capability_key"]) not in (invalid_deny_caps | denied_caps)
    }

    report_sources: dict[str, list[dict[str, Any]]] = {}
    report_fields: dict[str, set[str]] = {}
    report_actions: dict[str, set[str]] = {}
    report_scopes: dict[str, list[dict[str, Any]]] = {}
    report_grants: dict[str, list[dict[str, Any]]] = {}
    if package_ids:
        for row in [r for r in facts.get('package_reports', []) if str(r['package_key']) in allowed_packages]:
            key = str(row["report_key"])
            report_sources.setdefault(key, []).append({"source_type": "package", "source": str(row["package_key"])})
            report_grants.setdefault(key, []).append({
                "source_type": "package", "source": str(row["package_key"]),
                "scope": _json_object(row.get("scope_json")),
                "field_categories": [str(item) for item in (row.get("field_categories") or [])],
                "allowed_actions": [str(item) for item in (row.get("allowed_actions") or [])],
            })

    assignment_rows: list[dict[str, Any]] = []
    if user_id is not None:
        assignment_rows = [dict(row) for row in facts.get('report_assignments', [])]
    denied_reports = {str(row["report_key"]) for row in assignment_rows if row.get("effect") == "deny"}
    for row in assignment_rows:
        key = str(row["report_key"])
        if row.get("effect") != "allow" or key in denied_reports:
            continue
        report_sources.setdefault(key, []).append({
            "source_type": str(row["source_type"]), "source": f"{row['subject_type']}:{row['subject_id']}",
            "valid_from": row.get("valid_from"), "valid_until": row.get("valid_until"),
            "business_reason": str(row.get("business_reason") or ""),
        })
        report_grants.setdefault(key, []).append({
            "source_type": str(row["source_type"]), "source": f"{row['subject_type']}:{row['subject_id']}",
            "scope": _json_object(row.get("scope_json")),
            "field_categories": [str(item) for item in (row.get("field_categories") or [])],
            "allowed_actions": [str(item) for item in (row.get("allowed_actions") or [])],
            "valid_from": row.get("valid_from"), "valid_until": row.get("valid_until"),
        })
    for key in denied_reports:
        report_sources.pop(key, None)
        report_fields.pop(key, None)
        report_actions.pop(key, None)
        report_scopes.pop(key, None)
        report_grants.pop(key, None)

    capability_set = set(capabilities) | resource_capability_keys
    for key, grants in list(report_grants.items()):
        bounded = [_bounded_report_grant(grant, capability_set) for grant in grants]
        bounded = [grant for grant in bounded if "view" in grant["allowed_actions"]]
        report_grants[key] = bounded
        report_fields[key] = {field for grant in bounded for field in grant["field_categories"]}
        report_actions[key] = {action for grant in bounded for action in grant["allowed_actions"]}
        report_scopes[key] = [dict(grant["scope"]) for grant in bounded]

    definitions = [dict(row) for row in facts.get('definitions', [])]
    request_states: dict[str, dict[str, Any]] = {}
    if user_id is not None:
        request_states = {
            str(row["report_key"]): dict(row) for row in facts.get('requests', [])
        }
    preferences: dict[str, dict[str, Any]] = {}
    if user_id is not None:
        preferences = {str(row["report_key"]): dict(row) for row in facts.get('preferences', [])}

    reports: list[dict[str, Any]] = []
    for row in definitions:
        key = str(row["report_key"])
        definition = _json_object(row.get("definition_json"))
        dataset_categories = {
            str(item.get("category")) for item in _json_list(row.get("fields_json"))
            if isinstance(item, Mapping) and item.get("category")
        }
        defined_categories = {str(item) for item in definition.get("field_categories", []) if str(item)}
        current_categories = dataset_categories & defined_categories if defined_categories else dataset_categories
        dataset_actions = {str(item) for item in _json_list(row.get("actions_json")) if str(item)}
        defined_actions = {str(item) for item in definition.get("actions", []) if str(item)}
        current_actions = dataset_actions & defined_actions
        if is_platform_owner:
            report_sources[key] = [{"source_type": "platform_owner", "source": "owner:primary"}]
            report_grants[key] = [{
                "source_type": "platform_owner", "source": "owner:primary",
                "scope": {"kind": "all"},
                "field_categories": sorted(current_categories),
                "allowed_actions": sorted(current_actions),
            }]
        version_grants = []
        for grant in report_grants.get(key, []):
            compatible = _version_bound_report_grant(
                grant, categories=current_categories, actions=current_actions,
                report_version=int(row["version"]), dataset_version=int(row["dataset_version"]),
            )
            if compatible is not None:
                version_grants.append(compatible)
        report_grants[key] = version_grants
        report_fields[key] = {field for grant in version_grants for field in grant["field_categories"]}
        report_actions[key] = {action for grant in version_grants for action in grant["allowed_actions"]}
        report_scopes[key] = [dict(grant["scope"]) for grant in version_grants]
        required = {str(item) for item in definition.get("required_capabilities", [])}
        missing = sorted(required - capability_set)
        resource_context_required = bool(required - set(capabilities)) and not missing
        explicit_deny = key in denied_reports and not is_platform_owner
        has_assignment_source = bool(report_sources.get(key))
        assigned = bool(version_grants)
        allowed = assigned and not missing and not explicit_deny
        discoverable = bool(row.get("discoverable")) or allowed or is_platform_owner
        if not discoverable:
            continue
        requestable = bool(row.get("requestable")) and not missing and not explicit_deny
        request_state = request_states.get(key)
        active_valid_until = sorted(
            (
                source.get("valid_until") for source in report_sources.get(key, [])
                if source.get("valid_until") is not None
            )
        )
        if allowed:
            access_state = "available_until" if active_valid_until else "available"
        elif request_state and request_state.get("status") in {"submitted", "reviewing"}:
            access_state = "request_pending"
        elif request_state and request_state.get("status") == "rejected":
            access_state = "request_rejected"
        elif requestable:
            access_state = "requestable"
        else:
            access_state = "request_unavailable"
        explanation = (
            "Полный доступ владельца платформы"
            if allowed and is_platform_owner else
            "Доступ назначен; строки проверяются по области ресурса"
            if allowed and resource_context_required else
            "Доступ разрешён назначением и политикой возможностей"
            if allowed else
            "Явный запрет имеет приоритет"
            if explicit_deny else
            f"Не хватает возможностей: {', '.join(missing)}"
            if missing else
            "Назначение требует пересмотра для текущей версии отчёта"
            if has_assignment_source and not assigned else
            "Отчёт не назначен пользователю или его группам"
        )
        explanation_code = _access_explanation_code(
            allowed=allowed, is_platform_owner=is_platform_owner,
            resource_context_required=resource_context_required, explicit_deny=explicit_deny,
            missing=bool(missing), has_assignment_source=has_assignment_source, assigned=assigned,
        )
        preference_view = _json_object(preferences.get(key, {}).get("view_json"))
        reports.append({
            "report_key": key, "version": int(row["version"]), "name": str(row.get('name', '')),
            "owner": str(row.get('owner_name', '')), "purpose": str(row.get('purpose', '')),
            "dataset_key": str(row.get('dataset_key', '')), "dataset_version": int(row["dataset_version"]),
            "sensitivity": str(row.get('sensitivity', '')), "status": str(row.get('status', '')),
            "target_path": str(definition.get("target_path") or "/reports"),
            "allowed": allowed, "explanation": explanation, "explanation_code": explanation_code, "missing_capabilities": missing,
            "resource_context_required": resource_context_required,
            "discoverable": discoverable,
            "requestable": requestable,
            "access_state": access_state,
            "access_valid_until": active_valid_until[0] if active_valid_until else None,
            "request": request_state,
            "request_profile": (
                _json_object(row.get("request_profile_json"))
                if requestable else {}
            ),
            "assignment_version_state": "owner" if is_platform_owner else "compatible" if assigned else "requires_review" if has_assignment_source else "not_assigned",
            "field_categories": sorted(report_fields.get(key, set())) if allowed else [],
            "allowed_actions": sorted(report_actions.get(key, set())) if allowed else [],
            "scopes": report_scopes.get(key, []) if allowed else [],
            "sources": report_sources.get(key, []) if allowed else [],
            "grants": report_grants.get(key, []) if allowed else [],
            "pinned": bool(preferences.get(key, {}).get("pinned")),
            "preference_updated_at": preferences.get(key, {}).get("updated_at"),
            "dashboard_metrics": [
                dict(item) for item in _json_list(definition.get("dashboard_metrics"))
                if allowed and isinstance(item, Mapping)
            ],
            "selected_optional_metric_keys": [
                str(item) for item in _json_list(preference_view.get("focus_metric_keys"))
                if str(item)
            ],
            "focus_preference_configured": "focus_metric_keys" in preference_view,
        })

    navigation_candidates = [
        ("workspace", "Моё рабочее пространство", "/", "workspace.view"),
        ("reports", "Каталог отчётов", "/reports", "reports.catalog"),
        ("objects", "Объекты и сущности", "/objects", "objects.view"),
        ("events", "События", "/events", "events.view"),
        ("investigations", "Расследования", "/investigations", "investigations.view"),
        ("scenarios", "Сценарии · SHADOW", "/scenarios", "semantic.review"),
        ("operations", "Эксплуатация", "/operations", "operations.view"),
        ("access", "Доступы пользователей", "/access", "access.manage"),
        ("report-builder", "Конструктор отчёта", "/report-builder", "reports.design"),
    ]
    navigation = [
        {"id": item_id, "label": label, "path": path}
        for item_id, label, path, capability in navigation_candidates if capability in capabilities
        or (
            item_id == "investigations"
            and any(
                item["allowed"] and item["report_key"] in {"investigations.workspace", "cases.workspace"}
                for item in reports
            )
        )
    ]
    allowed_reports = [item for item in reports if item["allowed"]]
    return {
        "api_version": "v4",
        "evaluated_at_utc": now,
        "preview": preview,
        "platform_owner": is_platform_owner,
        "owner_policy": {
            "key": "primary", "full_product_access": is_platform_owner,
            "surveyed_system_write_access": False,
        },
        "subject": {"type": str(subject.get("type") or "local"), "id": subject.get("id"), "username": subject.get("username") or subject.get("label") or "local-operator", "coarse_role": role},
        "groups": [{"id": int(item["id"]), "key": str(item.get('group_key', '')), "name": str(item.get('name', '')), "source": str(item.get('source', '')), "valid_until": item.get("valid_until")} for item in groups],
        "packages": [{"key": key, "name": str(row.get('name', ''))} for key, row in sorted(allowed_packages.items())],
        "package_explain": package_explain,
        "capabilities": capabilities,
        "resource_bound_capabilities": sorted(resource_capability_keys),
        "capability_explain": capability_sources,
        "capability_policies": capability_policies,
        "quarantined_capability_assignments": quarantined_capabilities,
        "resource_bound_capability_assignments": resource_bound_capabilities,
        "reports": reports,
        "allowed_report_count": len(allowed_reports),
        "navigation": navigation,
        "explicit_denies": {
            "packages": [] if is_platform_owner else sorted(denied_packages),
            "capabilities": [] if is_platform_owner else sorted(denied_caps),
            "reports": [] if is_platform_owner else sorted(denied_reports),
        },
        "ignored_denies": {
            "packages": sorted(denied_packages) if is_platform_owner else [],
            "capabilities": sorted(denied_caps | invalid_deny_caps) if is_platform_owner else [],
            "reports": sorted(denied_reports) if is_platform_owner else [],
        },
    }

