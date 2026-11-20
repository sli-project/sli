"""Split out of ``server.sli.access.access_control_v4`` (plan 7.2b).

Module-level names of ``access_control_v4`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.access.access_control_v4 as _src


def report_access_trace(access: _src.Mapping[str, _src.Any], report_key: str) -> dict[str, _src.Any]:
    """Project one fresh access decision into a bounded, report-only explanation."""
    key = str(report_key or "").strip()
    if not _src._REPORT_KEY_PATTERN.fullmatch(key):
        raise ValueError("invalid_report_key")
    report = next(
        (item for item in access.get("reports", []) if str(item.get("report_key")) == key),
        None,
    )
    if report is None:
        raise LookupError("report_not_found")

    allowed = bool(report.get("allowed"))
    trace_incomplete = False
    groups = [item for item in access.get("groups", []) if isinstance(item, _src.Mapping)]
    grants: list[dict[str, _src.Any]] = []
    if allowed:
        for raw_grant in report.get("grants", []):
            if not isinstance(raw_grant, _src.Mapping):
                continue
            source_type = str(raw_grant.get("source_type") or "assignment")
            grants.append({
                "source_type": source_type,
                "source": _src._trace_source_reference(source_type, str(raw_grant.get("source") or ""), groups),
                "scope": dict(raw_grant.get("scope") or {"kind": "all"}),
                "field_categories": sorted({str(item) for item in raw_grant.get("field_categories", [])}),
                "allowed_actions": sorted({str(item) for item in raw_grant.get("allowed_actions", [])}),
                "valid_from": raw_grant.get("valid_from"),
                "valid_until": raw_grant.get("valid_until"),
                "validated_report_version": raw_grant.get("validated_report_version"),
                "validated_dataset_version": raw_grant.get("validated_dataset_version"),
            })
        if not grants:
            allowed = False
            trace_incomplete = True

    explicit_denies = access.get("explicit_denies") or {}
    ignored_denies = access.get("ignored_denies") or {}
    subject = access.get("subject") or {}
    platform_owner = bool(access.get("platform_owner"))
    return {
        "api_version": "v4",
        "evaluated_at_utc": access.get("evaluated_at_utc"),
        "subject": {
            "username": str(subject.get("username") or "current_subject"),
            "coarse_role": str(subject.get("coarse_role") or "viewer"),
        },
        "report": {
            "report_key": key,
            "name": str(report.get("name") or key),
            "version": int(report.get("version") or 0),
        },
        "decision": "allowed" if allowed else "denied",
        "explanation": (
            "Сервер не вернул атомарную разрешающую ветвь; доступ этим ответом не подтверждён"
            if trace_incomplete else
            str(report.get("explanation") or "Решение сервера не содержит пояснения")
        ),
        "platform_owner": platform_owner,
        "owner_policy": {
            "full_product_access": platform_owner,
            "surveyed_system_write_access": False,
        },
        "exact_deny": key in set(explicit_denies.get("reports") or []),
        "ignored_deny": key in set(ignored_denies.get("reports") or []),
        "missing_capabilities": [str(item) for item in report.get("missing_capabilities", [])],
        "assignment_version_state": str(report.get("assignment_version_state") or "not_assigned"),
        "grants": grants if allowed else [],
    }


def _trace_source_reference(
    source_type: str,
    source: str,
    groups: _src.Sequence[_src.Mapping[str, _src.Any]],
) -> str:
    """Return a useful source label without exposing internal subject identifiers."""
    if source_type == "platform_owner":
        return "owner:primary"
    if source_type == "package":
        return source
    if source.startswith("user:"):
        return "current_subject"
    if source.startswith("group:"):
        group_id = source.partition(":")[2]
        for group in groups:
            if str(group.get("id")) == group_id:
                return f"group:{group.get('key') or 'assigned'}"
        return "group:assigned"
    return source_type or "assignment"
