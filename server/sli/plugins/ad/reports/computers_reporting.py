"""Evidence-bound read model helpers for the additional Computers report."""
from __future__ import annotations

import base64
import csv
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import re
from typing import Any, Mapping

from server.sli.core.database import query_rows_bounded
from server.sli.reporting.reporting_common import format_spreadsheet_cell, parse_utc
from server.sli.plugins.ad.reports.users_reporting import normalize_ou_path
from server.sli.core.report_domain import report_domain_fqdn


COMPUTERS_REPORT_CONTRACT_ID = "sli.computers-report.v1"
RISK_RULE_VERSION = 1
RISK_LABELS = {
    "enabled_inactive_over_60_days": "Включён, но неактивен более 60 дней",
    "enabled_without_last_logon_data": "Включён без данных о последнем входе",
    "enabled_without_operating_system": "Включён без определённой ОС",
    "legacy_operating_system_family": "Базовый срок поддержки Microsoft завершён",
    "technical_inventory_unavailable": "Техническая инвентаризация недоступна",
    "low_fixed_disk_free_space": "Мало свободного места на фиксированном диске",
}
RISK_EXPECTED_CONDITIONS = {
    "enabled_inactive_over_60_days": "Последняя активность не старше 60 дней",
    "enabled_without_last_logon_data": "Для включённого компьютера наблюдается последний вход",
    "enabled_without_operating_system": "Для включённого компьютера наблюдается операционная система",
    "legacy_operating_system_family": "Базовый срок поддержки Microsoft ещё не завершён",
    "technical_inventory_unavailable": "Запрошенная техническая инвентаризация завершена",
    "low_fixed_disk_free_space": "На фиксированном диске свободно не менее 10%",
}
RISK_SOURCE_SECTIONS = {
    "legacy_operating_system_family": ["directory_accounts", "microsoft_lifecycle_catalog"],
}
RISK_RULE_VERSIONS = {"legacy_operating_system_family": 2}
OS_SUPPORT_CATALOG_VERSION = "microsoft-lifecycle-2026-10-16"
OS_SUPPORT_CATALOG_CHECKED_AT_UTC = "2026-10-15T23:22:15Z"
COMPUTERS_INPUT_LIMIT = 10_000
COMPUTERS_PAGE_LIMIT_MAX = 200
COMPUTERS_SORT_FIELDS = {
    "display_name", "computer_type", "enabled", "activity_state",
    "operating_system", "ou_path", "last_logon_utc", "risk_count",
}


def classify_computer_type(operating_system: Any) -> str:
    """Classify only from the observed OS label; never infer business role."""
    value = str(operating_system or "").strip().casefold()
    if not value or value in {"unknown", "неизвестно"}:
        return "unknown"
    return "server" if "server" in value else "workstation"


def _catalog_result(
    *,
    operating_system: str,
    operating_system_version: str,
    state: str,
    support_end_date: str | None,
    source_url: str | None,
    applicability_note: str,
) -> dict[str, Any]:
    return {
        "state": state,
        "operating_system": operating_system or None,
        "operating_system_version": operating_system_version or None,
        "support_end_date": support_end_date,
        "publisher": "Microsoft",
        "source_url": source_url,
        "catalog_version": OS_SUPPORT_CATALOG_VERSION,
        "catalog_checked_at_utc": OS_SUPPORT_CATALOG_CHECKED_AT_UTC,
        "applicability_note": applicability_note,
    }


def evaluate_operating_system_support(operating_system: Any, operating_system_version: Any) -> dict[str, Any]:
    """Evaluate observed Windows product/version against a curated Microsoft lifecycle snapshot."""
    name = str(operating_system or "").strip()
    version = str(operating_system_version or "").strip()
    normalized = name.casefold()
    build_match = re.search(r"\((\d{4,5})\)", version)
    build = int(build_match.group(1)) if build_match else None
    unknown = lambda note: _catalog_result(
        operating_system=name,
        operating_system_version=version,
        state="not_evaluated",
        support_end_date=None,
        source_url=None,
        applicability_note=note,
    )
    if not name or normalized in {"unknown", "неизвестно"}:
        return unknown("Операционная система не наблюдалась.")
    for marker, end_date, product in (
        (r"windows\s+8\.1(?:\s|$)", "2023-01-10", "windows-81"),
        (r"windows\s+8(?:\s|$)", "2016-01-12", "windows-8"),
        (r"windows\s+vista(?:\s|$)", "2017-04-11", "windows-vista"),
    ):
        if re.search(marker, normalized):
            return _catalog_result(
                operating_system=name, operating_system_version=version, state="ended",
                support_end_date=end_date,
                source_url=f"https://learn.microsoft.com/en-us/lifecycle/products/{product}",
                applicability_note="Расширенная поддержка завершена.",
            )
    if "windows 10" in normalized:
        if "ltsc" in normalized and build == 17763:
            return _catalog_result(
                operating_system=name, operating_system_version=version, state="supported",
                support_end_date="2029-01-09",
                source_url="https://learn.microsoft.com/en-us/lifecycle/products/windows-10-enterprise-ltsc-2019",
                applicability_note="Применимо к Windows 10 Enterprise LTSC 2019 build 17763.",
            )
        if "ltsc" in normalized:
            return unknown("Для LTSC требуется точное сопоставление редакции и build с отдельным жизненным циклом.")
        return _catalog_result(
            operating_system=name, operating_system_version=version, state="ended",
            support_end_date="2025-10-14",
            source_url="https://learn.microsoft.com/en-us/lifecycle/announcements/windows-10-end-of-support",
            applicability_note="Базовая поддержка завершена; наличие и срок программы ESU в текущем evidence не наблюдаются.",
        )
    if "windows 11" in normalized:
        if "ltsc" in normalized and build == 26100:
            return _catalog_result(
                operating_system=name, operating_system_version=version, state="supported",
                support_end_date="2029-10-09",
                source_url="https://learn.microsoft.com/en-us/lifecycle/products/windows-11-enterprise-ltsc-2024",
                applicability_note="Применимо к Windows 11 Enterprise LTSC 2024 build 26100.",
            )
        pro_builds = {
            22000: ("ended", "2023-10-10"),
            22621: ("ended", "2024-10-08"),
            22631: ("ended", "2025-11-11"),
            26100: ("supported", "2026-10-13"),
            26200: ("supported", "2027-10-13"),
        }
        if "pro" in normalized and build in pro_builds:
            state, end_date = pro_builds[build]
            return _catalog_result(
                operating_system=name, operating_system_version=version, state=state,
                support_end_date=end_date,
                source_url="https://learn.microsoft.com/en-us/lifecycle/products/windows-11-home-and-pro",
                applicability_note=f"Сопоставлено с Windows 11 Home/Pro build {build}.",
            )
        return unknown("Для Windows 11 требуется точное сопоставление редакции и build.")
    server_catalog = [
        ("windows server 2022", "supported", "2031-10-14", "https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2022", "Применимо к редакциям Windows Server 2022 LTSC."),
        ("windows server 2019", "supported", "2029-01-09", "https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2019", "Применимо к редакциям Windows Server 2019 LTSC."),
        ("windows server 2016", "supported", "2027-01-12", "https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2016", "Применимо к редакциям Windows Server 2016 LTSC."),
        ("windows server 2012", "ended", "2023-10-10", "https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2012-r2", "Базовый срок завершён; наличие платных или Azure ESU до октября 2026 в текущем evidence не наблюдается."),
        ("windows server 2008", "ended", "2020-01-14", "https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2008-r2", "Расширенная поддержка завершена."),
        ("windows server 2003", "ended", "2015-07-14", "https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2003-r2", "Расширенная поддержка завершена."),
    ]
    for marker, state, end_date, source_url, note in server_catalog:
        if marker in normalized:
            return _catalog_result(
                operating_system=name, operating_system_version=version, state=state,
                support_end_date=end_date, source_url=source_url, applicability_note=note,
            )
    if re.search(r"windows\s+7(?:\s|$)", normalized):
        return _catalog_result(
            operating_system=name, operating_system_version=version, state="ended",
            support_end_date="2020-01-14",
            source_url="https://learn.microsoft.com/en-us/lifecycle/products/windows-7",
            applicability_note="Расширенная поддержка завершена.",
        )
    if re.search(r"windows\s+xp(?:\s|$)", normalized):
        return _catalog_result(
            operating_system=name, operating_system_version=version, state="ended",
            support_end_date="2014-04-08",
            source_url="https://learn.microsoft.com/en-us/lifecycle/products/windows-xp",
            applicability_note="Расширенная поддержка завершена.",
        )
    return unknown("ОС не входит в текущий Microsoft Lifecycle catalog отчёта.")


_utc = parse_utc


def evaluate_computer_activity(attributes: Mapping[str, Any], observed_at_utc: Any) -> dict[str, Any]:
    enabled = attributes.get("enabled")
    if enabled is not True:
        return {"state": "not_applicable" if enabled is False else "not_evaluated", "reason": "computer_not_enabled" if enabled is False else "enabled_state_not_observed", "evidence": {"enabled": enabled}}
    observed = _utc(observed_at_utc)
    last_logon = _utc(attributes.get("last_logon_utc"))
    evidence = {
        "threshold_days": 60,
        "time_semantics": "replicated_lastLogonTimestamp_approximation",
        "observed_at_utc": observed.isoformat() if observed else None,
        "last_logon_utc": last_logon.isoformat() if last_logon else None,
    }
    if observed is None:
        return {"state": "not_evaluated", "reason": "observation_time_not_observed", "evidence": evidence}
    if last_logon is None:
        return {"state": "not_evaluated", "reason": "last_logon_not_observed", "evidence": evidence}
    inactive = last_logon < observed - timedelta(days=60)
    return {"state": "inactive" if inactive else "recent", "reason": "last_logon_over_60_days" if inactive else "last_logon_within_60_days", "evidence": evidence}


def _risk(key: str, qualification: str, reason: str, evidence: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "risk_key": key,
        "rule_version": RISK_RULE_VERSIONS.get(key, RISK_RULE_VERSION),
        "label": RISK_LABELS[key],
        "qualification": qualification,
        "reason": reason,
        "evidence": dict(evidence),
        "expected_condition": RISK_EXPECTED_CONDITIONS[key],
        "source_sections": list(RISK_SOURCE_SECTIONS.get(key, ["directory_accounts"])),
    }


def _disk_free_percentages(value: Any) -> list[dict[str, Any]] | None:
    if not isinstance(value, list) or not value:
        return None
    parsed: list[dict[str, Any]] = []
    try:
        for item in value:
            name, size_text, free_text = str(item).split("|", 2)
            size, free = int(size_text), int(free_text)
            if not name or size <= 0 or free < 0:
                return None
            parsed.append({"drive": name, "size_bytes": size, "free_bytes": free, "free_percent": free * 100 / size})
    except (TypeError, ValueError):
        return None
    return parsed


def evaluate_computer_risks(attributes: Mapping[str, Any], observed_at_utc: Any) -> list[dict[str, Any]]:
    enabled = attributes.get("enabled")
    activity = evaluate_computer_activity(attributes, observed_at_utc)
    operating_system = str(attributes.get("operating_system") or "").strip()
    computer_type = classify_computer_type(operating_system)
    result: list[dict[str, Any]] = []

    if enabled is None:
        result.append(_risk("enabled_inactive_over_60_days", "not_evaluated", "enabled_state_not_observed", {}))
        result.append(_risk("enabled_without_last_logon_data", "not_evaluated", "enabled_state_not_observed", {}))
        result.append(_risk("enabled_without_operating_system", "not_evaluated", "enabled_state_not_observed", {}))
    else:
        inactive = enabled is True and activity["state"] == "inactive"
        result.append(_risk("enabled_inactive_over_60_days", "matched" if inactive else "not_evaluated" if enabled is True and activity["state"] == "not_evaluated" else "not_matched", activity["reason"] if enabled is True else "computer_not_enabled", activity["evidence"]))
        missing_logon = enabled is True and _utc(attributes.get("last_logon_utc")) is None
        result.append(_risk("enabled_without_last_logon_data", "matched" if missing_logon else "not_matched", "enabled_without_last_logon_data" if missing_logon else "compound_condition_not_met", {"enabled": enabled, "last_logon_observed": _utc(attributes.get("last_logon_utc")) is not None}))
        missing_os = enabled is True and computer_type == "unknown"
        result.append(_risk("enabled_without_operating_system", "matched" if missing_os else "not_matched", "enabled_without_operating_system" if missing_os else "compound_condition_not_met", {"enabled": enabled, "operating_system": operating_system or None}))

    support = evaluate_operating_system_support(operating_system, attributes.get("operating_system_version"))
    support_qualification = "matched" if support["state"] == "ended" else "not_matched" if support["state"] == "supported" else "not_evaluated"
    support_reason = "base_support_ended" if support["state"] == "ended" else "operating_system_supported" if support["state"] == "supported" else "operating_system_support_not_evaluated"
    result.append(_risk("legacy_operating_system_family", support_qualification, support_reason, support))

    technical_status = str(attributes.get("technical_inventory_status") or "").strip().lower()
    if not technical_status:
        result.append(_risk("technical_inventory_unavailable", "not_evaluated", "technical_inventory_not_requested", {}))
    else:
        unavailable = technical_status != "complete"
        result.append(_risk("technical_inventory_unavailable", "matched" if unavailable else "not_matched", "technical_inventory_not_complete" if unavailable else "technical_inventory_complete", {"technical_inventory_status": technical_status}))

    disks = _disk_free_percentages(attributes.get("logical_disks")) if technical_status == "complete" else None
    if disks is None:
        result.append(_risk("low_fixed_disk_free_space", "not_evaluated", "fixed_disk_inventory_not_observed", {"technical_inventory_status": technical_status or None}))
    else:
        low = [disk for disk in disks if disk["free_percent"] < 10]
        result.append(_risk("low_fixed_disk_free_space", "matched" if low else "not_matched", "fixed_disk_free_space_below_10_percent" if low else "fixed_disk_free_space_at_least_10_percent", {"disks": disks, "threshold_percent": 10}))
    return result


def _attributes(row: Mapping[str, Any]) -> dict[str, Any]:
    value = row.get("attributes") or {}
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return {}
    if not isinstance(value, Mapping):
        return {}
    nested = value.get("attributes")
    return dict(nested) if isinstance(nested, Mapping) else dict(value)


def _cursor_value(item: Mapping[str, Any]) -> tuple[str, int]:
    return (str(item["display_name"]).casefold(), int(item["entity_id"]))


def _encode_cursor(field: str, direction: str, entity_id: int) -> str:
    payload = json.dumps(["v2", field, direction, int(entity_id)], ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    signature = hashlib.sha256(b"sli.computers-report.v1\0" + payload).digest()[:12]
    return base64.urlsafe_b64encode(signature + payload).decode("ascii").rstrip("=")


def _decode_cursor(value: str, field: str, direction: str) -> int:
    try:
        raw = base64.urlsafe_b64decode(str(value) + "=" * (-len(str(value)) % 4))
        signature, payload = raw[:12], raw[12:]
        if signature != hashlib.sha256(b"sli.computers-report.v1\0" + payload).digest()[:12]:
            raise ValueError
        decoded = json.loads(payload.decode("utf-8"))
        if not isinstance(decoded, list) or len(decoded) != 4 or decoded[:3] != ["v2", field, direction]:
            raise ValueError
        return int(decoded[3])
    except (TypeError, ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("invalid_computers_cursor") from exc


def _computer_sort_value(item: Mapping[str, Any], field: str) -> Any:
    if field == "risk_count":
        return len(item.get("matched_risk_keys") or [])
    value = item.get(field)
    if field == "enabled":
        return 0 if value is True else 1 if value is False else None
    if field == "operating_system":
        name = str(item.get("operating_system") or "").casefold()
        version = str(item.get("operating_system_version") or "").casefold()
        return (name, version) if name else None
    return str(value).casefold() if value not in (None, "") else None


def _sort_computers(items: list[dict[str, Any]], field: str, direction: str) -> list[dict[str, Any]]:
    present = [item for item in items if _computer_sort_value(item, field) is not None]
    missing = [item for item in items if _computer_sort_value(item, field) is None]
    present.sort(key=lambda item: (_computer_sort_value(item, field), str(item["display_name"]).casefold(), int(item["entity_id"])), reverse=direction == "desc")
    missing.sort(key=_cursor_value)
    return [*present, *missing]


def _iso(value: Any) -> Any:
    return value.isoformat() if isinstance(value, datetime) else value


def get_computers_report(
    *,
    domain_ids: list[int] | None,
    view: str = "workstations",
    risk_key: str | None = None,
    operating_system: str | None = None,
    operating_system_version: str | None = None,
    ou: str | None = None,
    q: str | None = None,
    sort_by: str = "display_name",
    sort_direction: str = "asc",
    limit: int = 50,
    cursor: str | None = None,
    max_page_limit: int = COMPUTERS_PAGE_LIMIT_MAX,
) -> dict[str, Any]:
    clean_view = str(view or "workstations").strip().lower()
    if clean_view not in {"workstations", "servers", "inactive", "disabled", "risk", "operating_systems", "semantic"}:
        raise ValueError("invalid_computers_view")
    clean_risk = str(risk_key or "").strip()
    if clean_view == "risk" and clean_risk not in RISK_LABELS:
        raise ValueError("invalid_computers_risk_key")
    clean_sort = str(sort_by or "display_name").strip().lower()
    clean_direction = str(sort_direction or "asc").strip().lower()
    if clean_sort not in COMPUTERS_SORT_FIELDS or clean_direction not in {"asc", "desc"}:
        raise ValueError("invalid_computers_sort")
    clean_limit = max(1, min(int(limit), int(max_page_limit)))
    clean_domains = sorted({int(item) for item in (domain_ids or []) if int(item) > 0})
    domain_scope_sql = " and domain.id=any(?)" if clean_domains else ""
    coverage_rows = query_rows_bounded(
        f"""/* computers_report_coverage */
            with expected_domains as (
                select domain.id as domain_id,domain.fqdn as domain_name
                from domains domain
                where lower(domain.fqdn)='{report_domain_fqdn()}'{domain_scope_sql}
            ), latest_section as (
                select distinct on (run.domain_id) run.domain_id,run.status as run_status,
                       section.status as section_status,section.record_count,run.observed_at_utc
                from ad_context_runs run
                join expected_domains expected on expected.domain_id=run.domain_id
                join ad_context_sections section on section.run_id=run.run_id
                where section.section_name='directory_accounts'
                order by run.domain_id,run.observed_at_utc desc,run.created_at desc,run.run_id desc
            )
            select expected.domain_id,expected.domain_name,latest.run_status,latest.section_status,
                   latest.record_count,latest.observed_at_utc
            from expected_domains expected
            left join latest_section latest on latest.domain_id=expected.domain_id
            order by expected.domain_id""",
        tuple([clean_domains] if clean_domains else []),
        statement_timeout_ms=3000,
    )
    coverage_domains = len(coverage_rows)
    complete_domains = sum(1 for row in coverage_rows if row.get("run_status") == "completed" and row.get("section_status") == "complete")
    failed_domains = sum(1 for row in coverage_rows if row.get("run_status") in {"failed", "cancelled"} or row.get("section_status") == "failed")
    partial_domains = sum(1 for row in coverage_rows if row.get("run_status") == "partial" or row.get("section_status") == "partial")
    skipped_domains = coverage_domains - complete_domains - failed_domains - partial_domains
    observed_values = [_utc(row.get("observed_at_utc")) for row in coverage_rows]
    observed_values = [item for item in observed_values if item is not None]
    stale_domains = sum(1 for row in coverage_rows if _utc(row.get("observed_at_utc")) is None or _utc(row.get("observed_at_utc")) < datetime.now(timezone.utc) - timedelta(hours=24))
    if not coverage_domains or skipped_domains == coverage_domains:
        coverage_state = "not_collected"
    elif failed_domains == coverage_domains:
        coverage_state = "failed"
    elif complete_domains == coverage_domains:
        coverage_state = "stale" if stale_domains else "complete"
    else:
        coverage_state = "partial"
    coverage = {
        "state": coverage_state,
        "domain_count": coverage_domains,
        "complete_domain_count": complete_domains,
        "partial_domain_count": partial_domains,
        "failed_domain_count": failed_domains,
        "skipped_domain_count": skipped_domains,
        "stale_domain_count": stale_domains,
        "directory_record_count": sum(int(row.get("record_count") or 0) for row in coverage_rows),
        "latest_observed_at_utc": max(observed_values).isoformat() if observed_values else None,
        "domains": [{**{key: _iso(value) for key, value in dict(row).items()}, "directory_state": "stale" if _utc(row.get("observed_at_utc")) is None or _utc(row.get("observed_at_utc")) < datetime.now(timezone.utc) - timedelta(hours=24) else "complete" if row.get("run_status") == "completed" and row.get("section_status") == "complete" else "failed" if row.get("run_status") in {"failed", "cancelled"} or row.get("section_status") == "failed" else "partial" if row.get("run_status") == "partial" or row.get("section_status") == "partial" else "not_collected"} for row in coverage_rows],
    }

    account_scope_sql = " and entity.domain_id=any(?)" if clean_domains else ""
    rows = query_rows_bounded(
        f"""/* computers_report_accounts */
            select entity.id as entity_id,entity.domain_id,entity.display_name,entity.natural_key,
                   version.last_observed_at_utc as observed_at_utc,version.attributes_json as attributes
            from entities_v2_active entity
            join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id
            join domains report_domain on report_domain.id=entity.domain_id
            join ad_context_entity_versions version on version.entity_id=entity.id
             and version.valid_to_utc is null and version.source_section='directory_accounts'
            where entity_type.value='ad_computer'
              and lower(report_domain.fqdn)='{report_domain_fqdn()}'{account_scope_sql}
              and lower(coalesce(version.attributes_json->'attributes'->>'object_class',''))='computer'
            order by entity.domain_id,entity.id limit ?""",
        tuple([*([clean_domains] if clean_domains else []), COMPUTERS_INPUT_LIMIT + 1]),
        statement_timeout_ms=20_000,
    )
    truncated = len(rows) > COMPUTERS_INPUT_LIMIT
    source_rows = rows[:COMPUTERS_INPUT_LIMIT]
    items: list[dict[str, Any]] = []
    risk_counts = {key: 0 for key in RISK_LABELS}
    type_counts = {"workstation": 0, "server": 0, "unknown": 0}
    enabled_count = disabled_count = unknown_enabled_count = recent_count = inactive_count = activity_unknown_count = 0
    os_counts: dict[tuple[str, str], int] = {}
    ou_counts: dict[str, int] = {}
    for source in source_rows:
        attrs = _attributes(source)
        observed = source.get("observed_at_utc")
        computer_type = classify_computer_type(attrs.get("operating_system"))
        activity = evaluate_computer_activity(attrs, observed)
        risks = evaluate_computer_risks(attrs, observed)
        observed_text = _utc(observed).isoformat() if _utc(observed) else None
        for risk in risks:
            risk["observed_at_utc"] = observed_text
        matched = [risk for risk in risks if risk["qualification"] == "matched"]
        for risk in matched:
            risk_counts[str(risk["risk_key"])] += 1
        type_counts[computer_type] += 1
        enabled = attrs.get("enabled")
        if enabled is True:
            enabled_count += 1
            if activity["state"] == "recent":
                recent_count += 1
            elif activity["state"] == "inactive":
                inactive_count += 1
            else:
                activity_unknown_count += 1
        elif enabled is False:
            disabled_count += 1
        else:
            unknown_enabled_count += 1
        os_name = str(attrs.get("operating_system") or "").strip()
        os_version = str(attrs.get("operating_system_version") or "").strip()
        if os_name:
            os_counts[(os_name, os_version)] = os_counts.get((os_name, os_version), 0) + 1
        ou_path = normalize_ou_path(attrs.get("distinguished_name"))
        ou_counts[ou_path] = ou_counts.get(ou_path, 0) + 1
        items.append({
            "entity_id": int(source["entity_id"]),
            "domain_id": int(source["domain_id"]),
            "display_name": str(source.get("display_name") or source.get("natural_key") or source["entity_id"]),
            "natural_key": str(source.get("natural_key") or ""),
            "dns_host_name": attrs.get("dns_host_name"),
            "computer_type": computer_type,
            "enabled": enabled,
            "activity_state": activity["state"],
            "activity": activity,
            "ou_path": ou_path,
            "created_utc": attrs.get("created_utc"),
            "last_logon_utc": attrs.get("last_logon_utc"),
            "operating_system": attrs.get("operating_system"),
            "operating_system_version": attrs.get("operating_system_version"),
            "technical_inventory_status": attrs.get("technical_inventory_status"),
            "technical_inventory_observed_at_utc": attrs.get("technical_inventory_observed_at_utc"),
            "ip_addresses": attrs.get("ip_addresses") if isinstance(attrs.get("ip_addresses"), list) else [],
            "logical_disks": _disk_free_percentages(attrs.get("logical_disks")),
            "observed_at_utc": _iso(observed),
            "risks": risks,
            "matched_risk_keys": [str(risk["risk_key"]) for risk in matched],
        })

    filtered: list[dict[str, Any]] = []
    clean_os = str(operating_system or "").strip().casefold()
    clean_os_version = str(operating_system_version or "").strip().casefold()
    clean_ou = str(ou or "").strip().casefold()
    clean_q = str(q or "").strip().casefold()
    for item in items:
        if clean_view in {"operating_systems", "semantic"}:
            continue
        if clean_view == "workstations" and item["computer_type"] != "workstation":
            continue
        if clean_view == "servers" and item["computer_type"] != "server":
            continue
        if clean_view == "inactive" and not (item["enabled"] is True and item["activity_state"] in {"inactive", "not_evaluated"}):
            continue
        if clean_view == "disabled" and item["enabled"] is not False:
            continue
        if clean_view == "risk" and clean_risk not in item["matched_risk_keys"]:
            continue
        if clean_os and str(item.get("operating_system") or "").casefold() != clean_os:
            continue
        if clean_os_version and str(item.get("operating_system_version") or "").casefold() != clean_os_version:
            continue
        if clean_ou and str(item["ou_path"]).casefold() != clean_ou:
            continue
        if clean_q and clean_q not in f"{item['display_name']} {item['natural_key']} {item.get('dns_host_name') or ''}".casefold():
            continue
        filtered.append(item)
    filtered = _sort_computers(filtered, clean_sort, clean_direction)
    if cursor:
        after_entity_id = _decode_cursor(cursor, clean_sort, clean_direction)
        try:
            position = next(index for index, item in enumerate(filtered) if int(item["entity_id"]) == after_entity_id)
        except StopIteration as exc:
            raise ValueError("invalid_computers_cursor") from exc
        filtered = filtered[position + 1:]
    page = filtered[:clean_limit]
    has_more = len(filtered) > clean_limit
    next_cursor = _encode_cursor(clean_sort, clean_direction, int(page[-1]["entity_id"])) if page and has_more else None

    semantic_items: list[dict[str, Any]] = []
    semantic_has_more = False
    if clean_view == "semantic" and items:
        semantic_rows = query_rows_bounded(
            """/* computers_report_semantic */
               select distinct finding.id as finding_id,linked.entity_id,computer.display_name,
                      finding.title,finding.severity,finding.status,finding.summary,
                      finding.why_it_matters,finding.recommended_action,finding.last_seen_utc
               from findings finding
               join finding_entities linked on linked.finding_id=finding.id
               join entities_v2_active computer on computer.id=linked.entity_id
               join storage_v2_entity_type entity_type on entity_type.id=computer.entity_type_id
               where linked.entity_id=any(?) and entity_type.value='ad_computer'
                 and is_semantic_finding_published_v1(finding.id)
               order by finding.last_seen_utc desc,finding.id desc limit 201""",
            ([int(item["entity_id"]) for item in items],),
            statement_timeout_ms=5000,
        )
        semantic_has_more = len(semantic_rows) > 200
        semantic_items = [{key: _iso(value) for key, value in dict(row).items()} for row in semantic_rows[:200]]

    if coverage_state == "failed":
        state = "unavailable"
    elif coverage_state == "not_collected" and not source_rows:
        state = "not_collected"
    elif truncated or coverage_state == "partial":
        state = "partial"
    elif coverage_state == "stale":
        state = "stale"
    elif source_rows:
        state = "available"
    else:
        state = "empty"
    limitations = [
        "Последний вход основан на реплицируемом lastLogonTimestamp и является приближённым.",
        "Тип компьютера определяется только по наблюдаемому названию операционной системы.",
        "Категории рисков пересекаются; их количества нельзя складывать как число уникальных компьютеров.",
        "Техническая инвентаризация доступна только для явно настроенного ограниченного списка серверов.",
    ]
    if coverage_state == "partial":
        limitations.append("Последний снимок directory_accounts неполон.")
    if coverage_state == "stale":
        limitations.append("Последнее наблюдение directory_accounts старше 24 часов.")
    return {
        "contract_id": COMPUTERS_REPORT_CONTRACT_ID,
        "report_key": "ad.computers",
        "state": state,
        "view": clean_view,
        "items": page,
        "has_more": has_more,
        "next_cursor": next_cursor,
        "coverage": coverage,
        "summary": {
            "total_computers": len(items),
            "workstations": type_counts["workstation"],
            "servers": type_counts["server"],
            "unknown_type": type_counts["unknown"],
            "enabled": enabled_count,
            "disabled": disabled_count,
            "unknown_enabled": unknown_enabled_count,
            "enabled_recent": recent_count,
            "enabled_inactive": inactive_count,
            "enabled_activity_unknown": activity_unknown_count,
            "unique_computers_with_risks": sum(1 for item in items if item["matched_risk_keys"]),
            "risk_counts": risk_counts,
            "operating_system_distribution": [
                {"operating_system": key[0], "operating_system_version": key[1] or None, "count": count}
                for key, count in sorted(os_counts.items(), key=lambda pair: (-pair[1], pair[0][0].casefold(), pair[0][1].casefold()))
            ],
            "ou_counts": ou_counts,
            "semantic_findings": len(semantic_items),
        },
        "filters": {"risk_key": clean_risk or None, "os": str(operating_system or "").strip() or None, "os_version": str(operating_system_version or "").strip() or None, "ou": str(ou or "").strip() or None, "q": str(q or "").strip() or None},
        "sort": {"field": clean_sort, "direction": clean_direction},
        "limits": {"page": clean_limit, "input": COMPUTERS_INPUT_LIMIT, "input_truncated": truncated},
        "semantic": {
            "state": "available" if semantic_items else "empty",
            "items": semantic_items,
            "linked_count": len(semantic_items),
            "has_more": semantic_has_more,
            "excludes_unlinked_findings": True,
            "link_contract": "exact_finding_entity_id_to_ad_computer",
        },
        "limitations": limitations,
    }


_spreadsheet_cell = format_spreadsheet_cell


def render_computers_report_csv(payload: Mapping[str, Any]) -> bytes:
    """Render one already-authorized Computers report slice for Russian Excel."""
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, delimiter=";", lineterminator="\r\n")
    write_row = lambda values: writer.writerow([_spreadsheet_cell(value) for value in values])
    write_row([
        "Тип строки", "Контракт", "Состояние отчёта", "Состояние покрытия", "Выбранный риск", "Ограничения",
        "Компьютер", "Учётная запись", "DNS-имя", "Тип", "Состояние AD", "Активность",
        "Расположение", "Операционная система", "Версия ОС", "Последний вход UTC",
        "Техническая инвентаризация", "Квалифицированные риски", "Фактическое основание рисков",
        "Условия проверок", "Версии правил", "Источники проверок", "Ссылки источников", "Наблюдалось UTC",
    ])
    selected_risk = str((payload.get("filters") or {}).get("risk_key") or "") if payload.get("view") == "risk" else ""
    coverage = dict(payload.get("coverage") or {})
    metadata = [
        "data", payload.get("contract_id") or COMPUTERS_REPORT_CONTRACT_ID, payload.get("state") or "",
        coverage.get("state") or "", selected_risk, " | ".join(str(item) for item in (payload.get("limitations") or [])),
    ]
    if not (payload.get("items") or []):
        write_row(["metadata", *metadata[1:], "", "", "", "", "", "", "", "", "", "", "", ""])
    for item in payload.get("items") or []:
        enabled = item.get("enabled")
        ad_state = "Включён" if enabled is True else "Отключён" if enabled is False else "Не определено"
        qualified_risks = [
            value for value in (item.get("risks") or [])
            if value.get("qualification") == "matched" and (not selected_risk or value.get("risk_key") == selected_risk)
        ]
        risks = ", ".join(str(value.get("label") or value.get("risk_key") or "") for value in qualified_risks)
        facts = " | ".join(json.dumps(value.get("evidence") or {}, ensure_ascii=False, sort_keys=True) for value in qualified_risks)
        conditions = " | ".join(str(value.get("expected_condition") or "") for value in qualified_risks)
        rule_versions = ", ".join(f"v{int(value.get('rule_version') or 0)}" for value in qualified_risks)
        risk_sources = " | ".join(" + ".join(str(source) for source in (value.get("source_sections") or [])) for value in qualified_risks)
        source_urls = " | ".join(str((value.get("evidence") or {}).get("source_url") or "") for value in qualified_risks)
        write_row([
            *metadata,
            item.get("display_name"), item.get("natural_key"), item.get("dns_host_name"), item.get("computer_type"),
            ad_state, item.get("activity_state"), item.get("ou_path"), item.get("operating_system"),
            item.get("operating_system_version"), item.get("last_logon_utc"), item.get("technical_inventory_status"),
            risks, facts, conditions, rule_versions, risk_sources, source_urls, item.get("observed_at_utc"),
        ])
    return stream.getvalue().encode("utf-8-sig")
