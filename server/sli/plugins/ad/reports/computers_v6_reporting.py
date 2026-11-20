# ruff: noqa: F401 -- re-export hub (plan 7.2b): split-out modules read these
# names through ``computers_v6_reporting`` at call time.
from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from server.sli.core.database import query_rows_bounded
from server.sli.core.postgres_runtime_pipeline import connect
from server.sli.reporting.reporting_common import format_spreadsheet_cell
from server.sli.plugins.ad.reports.computers_reporting import (
    COMPUTERS_INPUT_LIMIT,
    COMPUTERS_PAGE_LIMIT_MAX,
    COMPUTERS_SORT_FIELDS,
    _attributes,
    _iso,
    _utc,
    classify_computer_type,
    evaluate_computer_activity,
)
from server.sli.plugins.ad.reports.users_reporting import normalize_ou_path
from server.sli.sources.computers_v6_source import (
    load_latest_computers_v6_source_snapshot,
    missing_required_object_fields,
    quality_category_for_source_state,
)

CONTRACT_ID = "sli.computers-report.v6"
REPORT_KEY = "ad.computers.v6"
SEMANTIC_LINK_CONTRACT = "exact_finding_entity_id_to_ad_computer"
VIEWS = frozenset({
    "attention", "changes", "data_quality", "semantic",
    "workstation_enabled", "workstation_disabled", "server_enabled",
    "server_disabled", "unknown_type", "all",
})
ENABLED_FILTERS = frozenset({"enabled", "disabled", "unknown"})
ACTIVITY_FILTERS = frozenset({
    "within_threshold", "over_threshold", "missing",
    "within_30_days", "days_31_to_90", "over_60_days",
})
SORT_FIELDS = frozenset({
    *COMPUTERS_SORT_FIELDS,
    "ip_addresses",
    "ad_site",
    "reason",
    "quality",
})
FAILURE_STATES = frozenset({"failed", "access_denied", "parse_error"})
MISSING_STATES = frozenset({"absent_in_source", "missing_in_source", "no_record"})
THRESHOLD_DAYS = (30, 60, 90, 180)
DEFAULT_THRESHOLD_DAYS = 90
REASON_CATALOG = (
    "source_error",
    "unknown_type",
    "stale_activity",
    "unavailable_activity",
    "unknown_os",
    "unsupported_os", "unconstrained_delegation", "laps_expired",
)
COMPUTERS_V6_EXPORT_COLUMNS = (
    "display_name",
    "dns_host_name",
    "account_state",
    "computer_type",
    "operating_system",
    "operating_system_version",
    "ou_path",
    "canonical_name",
    "ip_addresses",
    "ad_site",
    "location",
    "managed_by",
    "last_logon_utc",
    "reasons",
    "quality_issues",
    "observed_at_utc",
)
COMPUTERS_V6_EXPORT_LABELS = {
    "display_name": "Компьютер",
    "dns_host_name": "DNS-имя",
    "account_state": "Состояние AD",
    "computer_type": "Тип",
    "operating_system": "ОС",
    "operating_system_version": "Версия ОС",
    "ou_path": "OU",
    "canonical_name": "CanonicalName",
    "ip_addresses": "IP-адреса",
    "ad_site": "AD Site",
    "location": "Location",
    "managed_by": "ManagedBy",
    "last_logon_utc": "Последняя активность UTC",
    "reasons": "Причины внимания",
    "quality_issues": "Качество данных",
    "observed_at_utc": "Наблюдалось UTC",
}


def project_computers_v6_exact(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Pure shadow projector for one exact immutable Computers V6 payload."""
    return deepcopy(dict(snapshot))












def _field_states(attrs: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    raw = attrs.get("computer_reference_attribute_states")
    if not isinstance(raw, Mapping):
        raw = attrs.get("attribute_states")
    if not isinstance(raw, Mapping):
        return {}
    return {str(key): dict(value) for key, value in raw.items() if isinstance(value, Mapping)}


def _state_name(value: Mapping[str, Any] | None) -> str:
    return str((value or {}).get("state") or "unknown").strip().lower()


def _matches_dynamic_filter(value: Any, selected: str) -> bool:
    normalized = str(value or "").strip().casefold()
    clean_selected = str(selected or "").strip().casefold()
    return not normalized if clean_selected == "__missing__" else normalized == clean_selected


def _operating_system_family(value: Any) -> str | None:
    normalized = str(value or "").strip()
    if not normalized:
        return None
    if "server" in normalized.casefold():
        return "Windows Server"
    if "windows" in normalized.casefold():
        return "Windows client"
    return "Другое"
















def _quality_codes(item: Mapping[str, Any]) -> str:
    values = sorted(str(issue.get("code") or "") for issue in item.get("quality_issues") or [] if issue.get("code"))
    return ", ".join(values) if values else "без отмеченных пробелов"


def _semantic_count(item: Mapping[str, Any]) -> str:
    count = len(item.get("semantic_findings") or [])
    return f"{count} точных опубликованных связей" if count else "нет точных опубликованных связей"










def _sort_value(item: Mapping[str, Any], field: str) -> Any:
    if field == "enabled":
        value = item.get("enabled")
        return 0 if value is True else 1 if value is False else None
    if field == "operating_system":
        value = str(item.get("operating_system") or "").casefold()
        return value or None
    if field == "ip_addresses":
        value = ", ".join(str(address) for address in item.get("ip_addresses") or [])
        return value.casefold() or None
    if field == "ad_site":
        value = ((item.get("network") or {}).get("ad_site") or {}).get("value")
        return str(value).casefold() if value not in (None, "") else None
    if field == "reason":
        value = ", ".join(str(reason.get("label") or reason.get("code") or "") for reason in item.get("reasons") or [])
        return value.casefold() or None
    if field == "quality":
        value = ", ".join(str(issue.get("label") or issue.get("code") or "") for issue in item.get("quality_issues") or [])
        return value.casefold() or None
    value = item.get(field)
    return str(value).casefold() if value not in (None, "") else None


def _sort(items: list[dict[str, Any]], field: str, direction: str) -> list[dict[str, Any]]:
    present = [item for item in items if _sort_value(item, field) is not None]
    missing = [item for item in items if _sort_value(item, field) is None]
    present.sort(key=lambda item: (_sort_value(item, field), str(item["display_name"]).casefold(), item["entity_id"]), reverse=direction == "desc")
    missing.sort(key=lambda item: (str(item["display_name"]).casefold(), item["entity_id"]))
    return [*present, *missing]


def _encode_cursor(field: str, direction: str, entity_id: int) -> str:
    payload = json.dumps(["v1", field, direction, int(entity_id)], separators=(",", ":")).encode("utf-8")
    signature = hashlib.sha256(b"sli.computers-report.v6\0" + payload).digest()[:12]
    return base64.urlsafe_b64encode(signature + payload).decode("ascii").rstrip("=")


def _decode_cursor(value: str, field: str, direction: str) -> int:
    try:
        raw = base64.urlsafe_b64decode(str(value) + "=" * (-len(str(value)) % 4))
        signature, payload = raw[:12], raw[12:]
        if signature != hashlib.sha256(b"sli.computers-report.v6\0" + payload).digest()[:12]:
            raise ValueError
        decoded = json.loads(payload.decode("utf-8"))
        if decoded[:3] != ["v1", field, direction]:
            raise ValueError
        return int(decoded[3])
    except (TypeError, ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("invalid_computers_v6_cursor") from exc


def _view_matches(item: Mapping[str, Any], view: str) -> bool:
    if view == "attention":
        return bool(item.get("reasons"))
    if view == "data_quality":
        return bool(item.get("quality_issues"))
    if view == "semantic":
        return bool(item.get("semantic_findings"))
    if view == "workstation_enabled":
        return item.get("enabled") is True and item.get("computer_type") == "workstation"
    if view == "workstation_disabled":
        return item.get("enabled") is False and item.get("computer_type") == "workstation"
    if view == "server_enabled":
        return item.get("enabled") is True and item.get("computer_type") in {"server", "domain_controller"}
    if view == "server_disabled":
        return item.get("enabled") is False and item.get("computer_type") in {"server", "domain_controller"}
    if view == "unknown_type":
        return item.get("computer_type") == "unknown"
    if view == "changes":
        return False
    return True


def _item_search_text(item: Mapping[str, Any]) -> str:
    values: list[Any] = [
        item.get("display_name"), item.get("natural_key"), item.get("dns_host_name"),
        item.get("distinguished_name"), item.get("ou_path"), item.get("operating_system"),
        item.get("operating_system_version"), item.get("operating_system_build"),
        item.get("object_guid"), item.get("object_sid"), item.get("canonical_name"),
        item.get("location"), item.get("managed_by"), item.get("description"),
        ((item.get("network") or {}).get("ad_site") or {}).get("value"),
        *(item.get("ip_addresses") or []),
        *(item.get("service_principal_names") or []),
    ]
    for reason in item.get("reasons") or []:
        values.extend(reason.get(key) for key in (
            "code", "label", "observed", "condition", "qualification", "limitation", "next_action",
        ))
    for issue in item.get("quality_issues") or []:
        values.extend((issue.get("code"), issue.get("label")))
    return " ".join(str(value or "") for value in values).casefold()


def _change_search_text(change: Mapping[str, Any]) -> str:
    values = [
        change.get("display_name"), change.get("change_type"), change.get("before"),
        change.get("after"), change.get("qualification"), change.get("limitation"),
        change.get("next_action"), _item_search_text(change.get("object") or {}),
    ]
    return " ".join(str(value or "") for value in values).casefold()


def _view_metrics(
    items: list[dict[str, Any]],
    *,
    snapshot_changes: list[dict[str, Any]],
) -> dict[str, Any]:
    metric_counts: dict[str, int] = {"all": len(snapshot_changes) if snapshot_changes else len(items)}
    for item in items:
        for reason in item.get("reasons") or []:
            code = str(reason.get("code") or "")
            if code:
                metric_counts[code] = metric_counts.get(code, 0) + 1
        for issue in item.get("quality_issues") or []:
            code = str(issue.get("code") or "")
            if code:
                metric_counts[code] = metric_counts.get(code, 0) + 1
        dns_state = str((((item.get("evidence") or {}).get("source_states") or {}).get("dns") or {}).get("status") or "")
        if not item.get("ip_addresses") or (dns_state and dns_state != "observed"):
            metric_counts["ip_gap"] = metric_counts.get("ip_gap", 0) + 1
        if not item.get("operating_system"):
            metric_counts["os_gap"] = metric_counts.get("os_gap", 0) + 1
        if (item.get("activity") or {}).get("age_days") is None:
            metric_counts["activity_gap"] = metric_counts.get("activity_gap", 0) + 1
        if any(reason.get("code") == "source_error" for reason in item.get("reasons") or []):
            metric_counts["source_failed"] = metric_counts.get("source_failed", 0) + 1
    for change in snapshot_changes:
        code = str(change.get("change_type") or "")
        if code:
            metric_counts[code] = metric_counts.get(code, 0) + 1
    return {
        "slice_count": len(items),
        "attention": sum(bool(item.get("reasons")) for item in items),
        "changes": len(snapshot_changes),
        "data_quality": sum(bool(item.get("quality_issues")) for item in items),
        "semantic_links": sum(bool(item.get("semantic_findings")) for item in items),
        "semantic_findings": sum(len(item.get("semantic_findings") or []) for item in items),
        "metric_counts": metric_counts,
    }


def get_computers_v6_report(
    *,
    domain_ids: list[int] | None,
    view: str = "attention",
    reason_code: str | None = None,
    quality_code: str | None = None,
    enabled: str | None = None,
    computer_type: str | None = None,
    operating_system: str | None = None,
    operating_system_version: str | None = None,
    operating_system_family: str | None = None,
    ou: str | None = None,
    ad_site: str | None = None,
    activity: str | None = None,
    q: str | None = None,
    sort_by: str = "display_name",
    sort_direction: str = "asc",
    limit: int = 50,
    cursor: str | None = None,
    max_page_limit: int = COMPUTERS_PAGE_LIMIT_MAX,
    threshold_days: int = DEFAULT_THRESHOLD_DAYS,
    qualify_names: bool | None = None,
) -> dict[str, Any]:
    clean_view = str(view or "attention").strip().lower()
    clean_reason = str(reason_code or "").strip()
    clean_quality = str(quality_code or "").strip()
    clean_enabled = str(enabled or "").strip().lower()
    clean_type = str(computer_type or "").strip().lower()
    clean_activity = str(activity or "").strip().lower()
    clean_sort = str(sort_by or "display_name").strip().lower()
    clean_direction = str(sort_direction or "asc").strip().lower()
    clean_threshold = int(threshold_days)
    if clean_view not in VIEWS:
        raise ValueError("invalid_computers_v6_view")
    if clean_enabled and clean_enabled not in ENABLED_FILTERS:
        raise ValueError("invalid_computers_v6_enabled_filter")
    if clean_type and clean_type not in {"workstation", "server", "domain_controller", "unknown"}:
        raise ValueError("invalid_computers_v6_type_filter")
    if clean_activity and clean_activity not in ACTIVITY_FILTERS:
        raise ValueError("invalid_computers_v6_activity_filter")
    if clean_sort not in SORT_FIELDS or clean_direction not in {"asc", "desc"}:
        raise ValueError("invalid_computers_v6_sort")
    if clean_threshold not in THRESHOLD_DAYS:
        raise ValueError("invalid_computers_v6_threshold")
    clean_limit = max(1, min(int(limit), int(max_page_limit)))
    clean_domains = None if domain_ids is None else sorted({int(value) for value in domain_ids if int(value) > 0})
    coverage = _coverage(clean_domains)
    scope_sql = " and entity.domain_id=any(?)" if clean_domains else ""
    rows = [] if clean_domains == [] else query_rows_bounded(
        f"""/* computers_v6_accounts */
            select entity.id as entity_id,entity.domain_id,report_domain.fqdn as domain_name,entity.display_name,entity.natural_key,
                   version.last_observed_at_utc as observed_at_utc,
                   version.attributes_json->'identity' as identity,
                   version.attributes_json as attributes
            from entities_v2_active entity
            join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id
            join domains report_domain on report_domain.id=entity.domain_id
            join ad_context_entity_versions version on version.entity_id=entity.id
             and version.valid_to_utc is null and version.source_section='directory_accounts'
            where entity_type.value='ad_computer'
              {scope_sql}
            order by entity.domain_id,entity.id limit ?""",
        tuple([*([clean_domains] if clean_domains else []), COMPUTERS_INPUT_LIMIT + 1]),
        statement_timeout_ms=20_000,
    )
    truncated = len(rows) > COMPUTERS_INPUT_LIMIT
    items = [_item(row, clean_threshold) for row in rows[:COMPUTERS_INPUT_LIMIT]]
    source_overlay = _load_computers_v6_source_overlay(clean_domains)
    snapshot_state = dict(source_overlay.get("source_snapshot") or {})
    if snapshot_state.get("state") == "stale":
        coverage = {**coverage, "state": "stale", "computer_snapshot_observed_at_utc": snapshot_state.get("completed_at_utc")}
    qualified = qualify_names if qualify_names is not None else clean_domains is None or len(clean_domains) > 1
    for item in items:
        _apply_computers_v6_source_overlay(item, source_overlay)
        _requalify_computers_v6_item(item, clean_threshold)
        if qualified:
            domain_name = item.get("domain_name") or str(item["domain_id"])
            item["display_name"] = f"{domain_name}\\{item['display_name']}"
    semantic_rows = _semantic_rows(items)
    by_entity: dict[int, list[dict[str, Any]]] = {}
    for row in semantic_rows[:200]:
        serialized = {key: _iso(value) for key, value in dict(row).items()}
        by_entity.setdefault(int(row["entity_id"]), []).append(serialized)
    for item in items:
        item["semantic_findings"] = by_entity.get(item["entity_id"], [])
    snapshot_comparison = _load_snapshot_comparison(clean_domains)
    if qualified:
        names = {row["domain_id"]: row.get("domain_name") for row in coverage.get("domains") or []}
        for change in snapshot_comparison.get("items") or []:
            domain_id = change.get("domain_id") or (change.get("object") or {}).get("domain_id")
            if domain_id is not None:
                change["display_name"] = f"{names.get(domain_id) or domain_id}\\{change['display_name']}"

    enabled_items = [item for item in items if item["enabled"] is True]
    disabled_items = [item for item in items if item["enabled"] is False]
    unknown_items = [item for item in items if item["enabled"] is None]
    attention_items = [item for item in items if item["reasons"]]
    quality_items = [item for item in items if item["quality_issues"]]
    linked_items = [item for item in items if item["semantic_findings"]]
    reason_counts: dict[str, int] = {}
    quality_counts: dict[str, int] = {}
    for item in attention_items:
        for reason in item["reasons"]:
            code = str(reason["code"])
            reason_counts[code] = reason_counts.get(code, 0) + 1
    for item in quality_items:
        for issue in item["quality_issues"]:
            code = str(issue["code"])
            quality_counts[code] = quality_counts.get(code, 0) + 1
    change_counts: dict[str, int] = {}
    for change in snapshot_comparison.get("items") or []:
        code = str(change["change_type"])
        change_counts[code] = change_counts.get(code, 0) + 1
    summary = {
        "total_computers": len(items),
        "enabled": len(enabled_items),
        "disabled": len(disabled_items),
        "unknown_enabled": len(unknown_items),
        "workstation_enabled": sum(item["computer_type"] == "workstation" for item in enabled_items),
        "workstation_disabled": sum(item["computer_type"] == "workstation" for item in disabled_items),
        "server_enabled": sum(item["computer_type"] in {"server", "domain_controller"} for item in enabled_items),
        "server_disabled": sum(item["computer_type"] in {"server", "domain_controller"} for item in disabled_items),
        "unknown_type": sum(item["computer_type"] == "unknown" for item in items),
        # Непересекающееся разбиение для метрик: включённые (ПК + серверы + тип не определён),
        # отключённые и «состояние не определено» в сумме дают total_computers.
        "unknown_type_enabled": sum(item["computer_type"] == "unknown" for item in enabled_items),
        "attention": len(attention_items),
        "attention_population": "all_ad_records",
        "reason_counts": reason_counts,
        "data_quality": len(quality_items),
        "quality_population": "all_ad_records",
        "quality_counts": quality_counts,
        "change_counts": change_counts,
        "semantic_linked_computers": len(linked_items),
        "semantic_findings": sum(len(item["semantic_findings"]) for item in linked_items),
    }

    clean_os = str(operating_system or "").strip().casefold()
    clean_version = str(operating_system_version or "").strip().casefold()
    clean_family = str(operating_system_family or "").strip().casefold()
    clean_ou = str(ou or "").strip().casefold()
    clean_site = str(ad_site or "").strip().casefold()
    clean_q = str(q or "").strip().casefold()
    filter_options = {
        "operating_systems": sorted({str(item["operating_system"]) for item in items if item.get("operating_system")}, key=str.casefold),
        "operating_system_families": sorted({str(item["operating_system_family"]) for item in items if item.get("operating_system_family")}, key=str.casefold) + (["__missing__"] if any(not item.get("operating_system_family") for item in items) else []),
        "operating_system_versions": sorted({str(item["operating_system_version"]) for item in items if item.get("operating_system_version")}, key=str.casefold),
        "ous": sorted({str(item["ou_path"]) for item in items if item.get("ou_path")}, key=str.casefold) + (["__missing__"] if any(not item.get("ou_path") for item in items) else []),
        "ad_site": {
            "state": "observed" if any((item.get("network") or {}).get("ad_site", {}).get("value") for item in items) else "not_collected",
            "values": sorted({str((item.get("network") or {}).get("ad_site", {}).get("value")) for item in items if (item.get("network") or {}).get("ad_site", {}).get("value")}, key=str.casefold) + (["__missing__"] if any(not (item.get("network") or {}).get("ad_site", {}).get("value") for item in items) else []),
        },
    }
    filtered: list[dict[str, Any]] = []
    if clean_view == "changes":
        change_rows = list(snapshot_comparison.get("items") or [])
        if clean_reason:
            change_rows = [item for item in change_rows if item.get("change_type") == clean_reason]
        if clean_q:
            change_rows = [item for item in change_rows if clean_q in _change_search_text(item)]
        change_rows.sort(key=lambda item: (str(item.get("change_type") or ""), str(item.get("display_name") or "").casefold(), int(item.get("entity_id") or 0)))
        filtered_count = len(change_rows)
        if cursor:
            raise ValueError("changes_view_does_not_accept_cursor")
        page = change_rows[:clean_limit]
        has_more = len(change_rows) > clean_limit
        next_cursor = None
    else:
        page = []
        has_more = False
        next_cursor = None
    for item in items:
        if clean_view == "changes":
            break
        if not _view_matches(item, clean_view):
            continue
        if clean_reason and clean_reason not in {reason["code"] for reason in item["reasons"]}:
            continue
        if clean_quality and clean_quality not in {issue["code"] for issue in item["quality_issues"]}:
            continue
        if clean_enabled and not (
            item["enabled"] is True if clean_enabled == "enabled"
            else item["enabled"] is False if clean_enabled == "disabled"
            else item["enabled"] is None
        ):
            continue
        if clean_type and item["computer_type"] != clean_type:
            continue
        if clean_os and str(item.get("operating_system") or "").casefold() != clean_os:
            continue
        if clean_version and str(item.get("operating_system_version") or "").casefold() != clean_version:
            continue
        if clean_family and not _matches_dynamic_filter(item.get("operating_system_family"), clean_family):
            continue
        if clean_ou and not _matches_dynamic_filter(item.get("ou_path"), clean_ou):
            continue
        item_site = str(((item.get("network") or {}).get("ad_site") or {}).get("value") or "").casefold()
        if clean_site and not _matches_dynamic_filter(item_site, clean_site):
            continue
        age_days = (item.get("activity") or {}).get("age_days")
        if clean_activity == "missing" and age_days is not None:
            continue
        if clean_activity == "within_30_days" and not (age_days is not None and int(age_days) <= 30):
            continue
        if clean_activity == "days_31_to_90" and not (age_days is not None and 31 <= int(age_days) <= 90):
            continue
        if clean_activity == "over_60_days" and not (age_days is not None and int(age_days) > 60):
            continue
        if clean_activity == "within_threshold" and not (age_days is not None and int(age_days) <= clean_threshold):
            continue
        if clean_activity == "over_threshold" and not (age_days is not None and int(age_days) > clean_threshold):
            continue
        search_text = _item_search_text(item)
        if clean_q and clean_q not in search_text:
            continue
        filtered.append(item)
    if clean_view != "changes":
        filtered = _sort(filtered, clean_sort, clean_direction)
        filtered_count = len(filtered)
        if cursor:
            after_id = _decode_cursor(cursor, clean_sort, clean_direction)
            try:
                position = next(index for index, item in enumerate(filtered) if item["entity_id"] == after_id)
            except StopIteration as exc:
                raise ValueError("invalid_computers_v6_cursor") from exc
            filtered = filtered[position + 1:]
        page = filtered[:clean_limit]
        has_more = len(filtered) > clean_limit
        next_cursor = _encode_cursor(clean_sort, clean_direction, page[-1]["entity_id"]) if page and has_more else None
    coverage_state = str(coverage["state"])
    state = (
        "unavailable" if coverage_state == "failed"
        else "not_collected" if coverage_state == "not_collected" and not items
        else "partial" if truncated or coverage_state == "partial"
        else "stale" if coverage_state == "stale"
        else "available" if items
        else "empty"
    )
    semantic = {
        "state": "available" if semantic_rows else "empty",
        "items": [{key: _iso(value) for key, value in dict(row).items()} for row in semantic_rows[:200]],
        "linked_computer_count": len(linked_items),
        "finding_count": sum(len(item["semantic_findings"]) for item in linked_items),
        "has_more": len(semantic_rows) > 200,
        "excludes_unlinked_findings": True,
        "link_contract": SEMANTIC_LINK_CONTRACT,
    }
    view_metrics = (
        _view_metrics(
            [dict(change.get("object") or {}) for change in change_rows],
            snapshot_changes=change_rows,
        )
        if clean_view == "changes"
        else _view_metrics(filtered, snapshot_changes=[])
    )
    return {
        "contract_id": CONTRACT_ID,
        "report_key": REPORT_KEY,
        "state": state,
        "view": clean_view,
        "items": page,
        "filtered_count": filtered_count,
        "has_more": has_more,
        "next_cursor": next_cursor,
        "coverage": coverage,
        "source_snapshot": dict(source_overlay.get("source_snapshot") or {}),
        "summary": summary,
        "view_metrics": view_metrics,
        "threshold": {
            "selected_days": clean_threshold,
            "allowed_days": list(THRESHOLD_DAYS),
            "default_days": DEFAULT_THRESHOLD_DAYS,
            "is_policy": False,
            "is_severity": False,
        },
        "reason_catalog": list(REASON_CATALOG),
        "semantic": semantic,
        "snapshot_comparison": snapshot_comparison,
        "filter_options": filter_options,
        "filters": {
            "reason_code": clean_reason or None,
            "quality_code": clean_quality or None,
            "enabled": clean_enabled or None,
            "type": clean_type or None,
            "os": str(operating_system or "").strip() or None,
            "os_version": str(operating_system_version or "").strip() or None,
            "os_family": str(operating_system_family or "").strip() or None,
            "ou": str(ou or "").strip() or None,
            "activity": clean_activity or None,
            "q": str(q or "").strip() or None,
        },
        "sort": {"field": clean_sort, "direction": clean_direction},
        "limits": {"page": clean_limit, "input": COMPUTERS_INPUT_LIMIT, "input_truncated": truncated},
        "limitations": [
            "Признак «Включена в AD» показывает состояние учётной записи, а не питание или доступность устройства.",
            "Последняя активность основана на приблизительном реплицируемом lastLogonTimestamp.",
            "Причины источника, типа и ОС оцениваются для всех записей AD; давность активности — только для включённых учётных записей.",
            "Семантические выводы показываются только по точным опубликованным связям объектов и не изменяют квалификацию AD.",
        ],
    }


_spreadsheet_cell = format_spreadsheet_cell


def _csv_item_value(item: Mapping[str, Any], column: str) -> Any:
    if column == "ip_addresses":
        return " | ".join(str(value) for value in item.get("ip_addresses") or [])
    if column == "ad_site":
        return ((item.get("network") or {}).get("ad_site") or {}).get("value")
    if column == "reasons":
        return " | ".join(str(value.get("code") or "") for value in item.get("reasons") or [])
    if column == "quality_issues":
        return " | ".join(str(value.get("code") or "") for value in item.get("quality_issues") or [])
    return item.get(column)


def render_computers_v6_csv(
    payload: Mapping[str, Any],
    *,
    columns: list[str] | tuple[str, ...] | None = None,
) -> bytes:
    selected = list(columns or COMPUTERS_V6_EXPORT_COLUMNS)
    if not selected or len(selected) != len(set(selected)):
        raise ValueError("invalid_computers_v6_export_column")
    if any(column not in COMPUTERS_V6_EXPORT_COLUMNS for column in selected):
        raise ValueError("invalid_computers_v6_export_column")
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, delimiter=";", lineterminator="\r\n")
    write = lambda values: writer.writerow([_spreadsheet_cell(value) for value in values])
    write([COMPUTERS_V6_EXPORT_LABELS[column] for column in selected])
    for item in payload.get("items") or []:
        write([_csv_item_value(item, column) for column in selected])
    return stream.getvalue().encode("utf-8-sig")


from server.sli.plugins.ad.reports.computers_v6_reporting_comparison import (
    _change_row,
    _load_snapshot_comparison,
    _semantic_rows,
    _snapshot_context,
    _snapshot_index,
    compare_computers_v6_snapshots,
)
from server.sli.plugins.ad.reports.computers_v6_reporting_items import (
    _attention_reasons,
    _coverage,
    _item,
    _quality_issues,
    _reason,
    _requalify_computers_v6_item,
)
from server.sli.plugins.ad.reports.computers_v6_reporting_overlay import (
    _apply_computers_v6_source_overlay,
    _load_computers_v6_source_overlay,
    _source_quality_issues,
    _source_snapshot_public_state,
)
