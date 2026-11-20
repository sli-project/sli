from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

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
from server.sli.core.database import query_rows_bounded
from server.sli.reporting.reporting_common import format_spreadsheet_cell
from server.sli.plugins.ad.reports.users_reporting import normalize_ou_path
from server.sli.core.report_domain import report_domain_fqdn


CONTRACT_ID = "sli.computers-report.v5"
REPORT_KEY = "ad.computers.v5"
SEMANTIC_LINK_CONTRACT = "exact_finding_entity_id_to_ad_computer"
VIEWS = frozenset({
    "attention", "changes", "data_quality", "semantic",
    "workstation_enabled", "workstation_disabled", "server_enabled",
    "server_disabled", "unknown_type", "all",
})
ENABLED_FILTERS = frozenset({"enabled", "disabled", "unknown"})
ACTIVITY_FILTERS = frozenset({"within_30_days", "days_31_to_90", "over_60_days", "missing"})
SORT_FIELDS = frozenset(COMPUTERS_SORT_FIELDS)
FAILURE_STATES = frozenset({"failed", "access_denied", "parse_error"})
MISSING_STATES = frozenset({"absent_in_source", "missing_in_source", "no_record"})


def _coverage(domain_ids: list[int]) -> dict[str, Any]:
    scope_sql = " and domain.id=any(?)" if domain_ids else ""
    rows = query_rows_bounded(
        f"""/* computers_v5_coverage */
            with expected_domains as (
                select domain.id as domain_id,domain.fqdn as domain_name
                from domains domain
                where lower(domain.fqdn)='{report_domain_fqdn()}'{scope_sql}
            ), latest_section as (
                select distinct on (run.domain_id) run.domain_id,run.run_id,
                       run.status as run_status,section.status as section_status,
                       section.record_count,run.observed_at_utc
                from ad_context_runs run
                join expected_domains expected on expected.domain_id=run.domain_id
                join ad_context_sections section on section.run_id=run.run_id
                where section.section_name='directory_accounts'
                order by run.domain_id,run.observed_at_utc desc,run.created_at desc,run.run_id desc
            )
            select expected.domain_id,expected.domain_name,latest.run_id,latest.run_status,
                   latest.section_status,latest.record_count,latest.observed_at_utc
            from expected_domains expected
            left join latest_section latest on latest.domain_id=expected.domain_id
            order by expected.domain_id""",
        tuple([domain_ids] if domain_ids else []),
        statement_timeout_ms=3000,
    )
    count = len(rows)
    complete = sum(row.get("run_status") == "completed" and row.get("section_status") == "complete" for row in rows)
    failed = sum(row.get("run_status") in {"failed", "cancelled"} or row.get("section_status") == "failed" for row in rows)
    partial = sum(row.get("run_status") == "partial" or row.get("section_status") == "partial" for row in rows)
    skipped = count - complete - failed - partial
    observed = [_utc(row.get("observed_at_utc")) for row in rows]
    observed = [value for value in observed if value is not None]
    stale = sum(
        _utc(row.get("observed_at_utc")) is None
        or _utc(row.get("observed_at_utc")) < datetime.now(timezone.utc) - timedelta(hours=24)
        for row in rows
    )
    if not count or skipped == count:
        state = "not_collected"
    elif failed == count:
        state = "failed"
    elif complete == count:
        state = "stale" if stale else "complete"
    else:
        state = "partial"
    return {
        "state": state,
        "domain_count": count,
        "complete_domain_count": complete,
        "partial_domain_count": partial,
        "failed_domain_count": failed,
        "skipped_domain_count": skipped,
        "stale_domain_count": stale,
        "directory_record_count": sum(int(row.get("record_count") or 0) for row in rows),
        "latest_observed_at_utc": max(observed).isoformat() if observed else None,
        "domains": [{key: _iso(value) for key, value in dict(row).items()} for row in rows],
    }


def _field_states(attrs: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    raw = attrs.get("attribute_states")
    if not isinstance(raw, Mapping):
        return {}
    return {str(key): dict(value) for key, value in raw.items() if isinstance(value, Mapping)}


def _state_name(value: Mapping[str, Any] | None) -> str:
    return str((value or {}).get("state") or "unknown").strip().lower()


def _quality_issues(attrs: Mapping[str, Any], field_states: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    states = {_state_name(value) for value in field_states.values()}
    if states.intersection(FAILURE_STATES):
        issues.append({"code": "source_failed", "label": "Ошибка источника"})
    if "not_collected" in states:
        issues.append({"code": "not_collected", "label": "Не собиралось"})
    if "not_evaluated" in states:
        issues.append({"code": "not_evaluated", "label": "Не оценивалось"})
    if states.intersection(MISSING_STATES):
        issues.append({"code": "no_record", "label": "Запись или значение не найдено"})
    if "partial" in states:
        issues.append({"code": "partial", "label": "Частичный результат"})
    required = ("enabled", "operating_system", "last_logon_utc")
    missing = [name for name in required if attrs.get(name) in (None, "")]
    if missing:
        issues.append({"code": "missing_field", "label": "Поле отсутствует", "fields": missing})
    return issues


def _reason(
    code: str,
    label: str,
    observed: str,
    condition: str,
    qualification: str,
    limitation: str,
    next_action: str,
    *,
    source_sections: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "code": code,
        "label": label,
        "rule_version": 1,
        "observed": observed,
        "condition": condition,
        "qualification": qualification,
        "limitation": limitation,
        "next_action": next_action,
        "source_sections": source_sections or ["directory_accounts"],
    }


def _attention_reasons(item: Mapping[str, Any]) -> list[dict[str, Any]]:
    if item.get("enabled") is not True:
        return []
    reasons: list[dict[str, Any]] = []
    quality_codes = {issue["code"] for issue in item.get("quality_issues") or []}
    if "source_failed" in quality_codes:
        reasons.append(_reason(
            "source_failed", "Ошибка источника", "Один или несколько обязательных атрибутов имеют состояние ошибки.",
            "Хотя бы один фактически запрошенный источник имеет состояние failed, access_denied или parse_error.",
            "Данные объекта получены с явной ошибкой источника.",
            "Ошибка источника не доказывает неисправность или небезопасность устройства.",
            "Проверить указанный источник и повторить соответствующий этап сбора.",
        ))
    if item.get("computer_type") == "unknown":
        reasons.append(_reason(
            "classification_unknown", "Тип объекта не определён", "Наблюдаемая ОС не позволяет определить тип.",
            "Ни одно заданное правило не позволило однозначно отнести объект к ПК или серверу.",
            "Тип объекта определить нельзя.",
            "Это не означает, что объект не является реальным компьютером или сервером.",
            "Проверить ОС и классификационные evidence.",
        ))
    activity = dict(item.get("activity") or {})
    if activity.get("state") == "inactive":
        age = activity.get("age_days")
        reasons.append(_reason(
            "activity_over_60_days", "Активность старше 60 дней",
            f"Последнее приблизительное AD-наблюдение: {item.get('last_logon_utc') or 'нет'}; возраст: {age if age is not None else '?'} дней.",
            "Разница больше фиксированного порога 60 дней и Enabled = true.",
            "Последнее доступное AD-наблюдение старше 60 дней.",
            "lastLogonTimestamp является приблизительным реплицируемым атрибутом и не подтверждает физическое состояние устройства.",
            "Сопоставить с назначением объекта; решение об отключении или удалении принимает человек.",
        ))
    elif activity.get("state") == "not_evaluated":
        reasons.append(_reason(
            "activity_unavailable", "Нет доступной даты активности", "Доступная дата AD-наблюдения отсутствует.",
            "Источник не дал дату наблюдения при Enabled = true.", "Дату последней активности определить нельзя.",
            "Отсутствие даты не доказывает отсутствие активности устройства.",
            "Проверить полноту directory_accounts и источник LastLogonDate.",
        ))
    if not item.get("operating_system"):
        reasons.append(_reason(
            "os_unavailable", "Операционная система не определена", "OperatingSystem отсутствует в текущем evidence.",
            "Название ОС отсутствует либо источник поля не имеет наблюдаемого значения.",
            "Операционную систему по текущему снимку определить нельзя.",
            "Это не доказывает отсутствие ОС на устройстве.",
            "Проверить атрибут OperatingSystem и полноту directory_accounts.",
        ))
    return reasons


def _item(source: Mapping[str, Any]) -> dict[str, Any]:
    attrs = _attributes(source)
    observed = source.get("observed_at_utc")
    activity = evaluate_computer_activity(attrs, observed)
    observed_value = _utc(observed)
    last_logon_value = _utc(attrs.get("last_logon_utc"))
    age_days = max(0, (observed_value - last_logon_value).days) if observed_value and last_logon_value else None
    activity = {
        **activity,
        "age_days": age_days,
        "time_semantics": "replicated_lastLogonTimestamp_approximation",
        "source_attribute": "LastLogonDate",
    }
    field_states = _field_states(attrs)
    enabled = attrs.get("enabled") if isinstance(attrs.get("enabled"), bool) else None
    result = {
        "entity_id": int(source["entity_id"]),
        "domain_id": int(source["domain_id"]),
        "display_name": str(source.get("display_name") or source.get("natural_key") or source["entity_id"]),
        "natural_key": str(source.get("natural_key") or ""),
        "dns_host_name": attrs.get("dns_host_name"),
        "distinguished_name": attrs.get("distinguished_name"),
        "enabled": enabled,
        "account_state": "enabled" if enabled is True else "disabled" if enabled is False else "unknown",
        "computer_type": classify_computer_type(attrs.get("operating_system")),
        "activity_state": activity["state"],
        "activity": activity,
        "last_logon_utc": attrs.get("last_logon_utc"),
        "operating_system": attrs.get("operating_system"),
        "operating_system_version": attrs.get("operating_system_version"),
        "ou_path": normalize_ou_path(attrs.get("distinguished_name")),
        "ip_addresses": attrs.get("ip_addresses") if isinstance(attrs.get("ip_addresses"), list) else [],
        "observed_at_utc": _iso(observed),
        "evidence": {"attribute_states": field_states},
        "quality_issues": _quality_issues(attrs, field_states),
        "semantic_findings": [],
    }
    result["reasons"] = _attention_reasons(result)
    return result


def _semantic_rows(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not items:
        return []
    return query_rows_bounded(
        """/* computers_v5_semantic */
           select distinct finding.id as finding_id,linked.entity_id,computer.display_name,
                  finding.title,finding.status,finding.summary,finding.why_it_matters,
                  finding.recommended_action,finding.last_seen_utc
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


def _snapshot_index(snapshot: Mapping[str, Any]) -> dict[int, dict[str, Any]]:
    indexed: dict[int, dict[str, Any]] = {}
    for raw in snapshot.get("items") or []:
        item = dict(raw)
        entity_id = int(item["entity_id"])
        if entity_id in indexed:
            raise ValueError("snapshot_duplicate_entity_id")
        indexed[entity_id] = item
    return indexed


def _quality_codes(item: Mapping[str, Any]) -> str:
    values = sorted(str(issue.get("code") or "") for issue in item.get("quality_issues") or [] if issue.get("code"))
    return ", ".join(values) if values else "без отмеченных пробелов"


def _semantic_count(item: Mapping[str, Any]) -> str:
    count = len(item.get("semantic_findings") or [])
    return f"{count} точных опубликованных связей" if count else "нет точных опубликованных связей"


def _change_row(
    *,
    change_type: str,
    item: Mapping[str, Any],
    before: str,
    after: str,
    current_partial: bool,
) -> dict[str, Any]:
    missing = change_type == "missing_current"
    qualification = (
        "Объект отсутствует в текущем неполном снимке; причина не установлена."
        if missing and current_partial
        else "Объект отсутствует в текущем снимке; причина не установлена."
        if missing
        else "Зафиксировано различие двух совместимых снимков; причина изменения не устанавливается автоматически."
    )
    limitation = (
        "Отсутствие в текущем снимке не доказывает удаление: объект мог выпасть из scope или неполного сбора."
        if missing
        else "Снимки показывают два наблюдаемых состояния и не доказывают, кто, почему или вследствие чего внёс изменение."
    )
    return {
        "row_id": f"{change_type}:{int(item['entity_id'])}",
        "entity_id": int(item["entity_id"]),
        "display_name": str(item.get("display_name") or item["entity_id"]),
        "change_type": change_type,
        "before": before,
        "after": after,
        "object": dict(item),
        "qualification": qualification,
        "limitation": limitation,
        "next_action": "Проверить объект и связанные evidence; решение принимает человек.",
    }


def compare_computers_v5_snapshots(
    *, current: Mapping[str, Any], previous: Mapping[str, Any],
) -> dict[str, Any]:
    if current.get("contract_id") != CONTRACT_ID or previous.get("contract_id") != CONTRACT_ID:
        raise ValueError("incompatible_computers_v5_snapshots")
    current_index = _snapshot_index(current)
    previous_index = _snapshot_index(previous)
    current_partial = (
        str(current.get("state") or "") == "partial"
        or str((current.get("coverage") or {}).get("state") or "") == "partial"
    )
    previous_partial = (
        str(previous.get("state") or "") == "partial"
        or str((previous.get("coverage") or {}).get("state") or "") == "partial"
    )
    rows: list[dict[str, Any]] = []
    for entity_id in sorted(set(current_index) | set(previous_index)):
        current_item = current_index.get(entity_id)
        previous_item = previous_index.get(entity_id)
        if current_item is None:
            rows.append(_change_row(
                change_type="missing_current", item=previous_item or {"entity_id": entity_id},
                before="Присутствовал в предыдущем снимке", after="Отсутствует в текущем снимке",
                current_partial=current_partial,
            ))
            continue
        if previous_item is None:
            rows.append(_change_row(
                change_type="new_object", item=current_item, before="Отсутствовал",
                after="Присутствует в текущем снимке", current_partial=current_partial,
            ))
            continue
        comparisons = (
            ("enabled_changed", str(previous_item.get("enabled")), str(current_item.get("enabled"))),
            ("ou_changed", str(previous_item.get("ou_path") or "нет данных"), str(current_item.get("ou_path") or "нет данных")),
            (
                "os_changed",
                " · ".join(str(value) for value in (previous_item.get("operating_system"), previous_item.get("operating_system_version")) if value) or "нет данных",
                " · ".join(str(value) for value in (current_item.get("operating_system"), current_item.get("operating_system_version")) if value) or "нет данных",
            ),
            ("ip_changed", ", ".join(sorted(previous_item.get("ip_addresses") or [])) or "нет данных", ", ".join(sorted(current_item.get("ip_addresses") or [])) or "нет данных"),
            ("classification_changed", str(previous_item.get("computer_type") or "unknown"), str(current_item.get("computer_type") or "unknown")),
            ("quality_changed", _quality_codes(previous_item), _quality_codes(current_item)),
            ("semantic_changed", _semantic_count(previous_item), _semantic_count(current_item)),
        )
        for change_type, before, after in comparisons:
            if before == after:
                continue
            rows.append(_change_row(
                change_type=change_type, item=current_item, before=before, after=after,
                current_partial=current_partial,
            ))
    state = "partial" if current_partial or previous_partial else "available"
    return {
        "state": state,
        "current": {"captured_at_utc": current.get("captured_at_utc"), "state": current.get("state")},
        "previous": {"captured_at_utc": previous.get("captured_at_utc"), "state": previous.get("state")},
        "items": rows,
        "change_count": len(rows),
        "deletion_claim_allowed": False,
    }


def _load_snapshot_comparison(domain_ids: list[int]) -> dict[str, Any]:
    scope_sql = " and snapshot.domain_id=any(?)" if domain_ids else ""
    rows = query_rows_bounded(
        f"""/* computers_v5_snapshots */
            with latest as (
                select snapshot.domain_id,snapshot.scope_sha256,snapshot.contract_id,snapshot.schema_version
                from computers_report_v5_snapshots snapshot
                join domains domain on domain.id=snapshot.domain_id
                where lower(domain.fqdn)='{report_domain_fqdn()}'{scope_sql}
                order by snapshot.captured_at_utc desc,snapshot.snapshot_id desc limit 1
            )
            select snapshot.snapshot_id,snapshot.domain_id,snapshot.bucket_start_utc,
                   snapshot.captured_at_utc,snapshot.source_observed_at_utc,
                   snapshot.source_state,snapshot.object_count,snapshot.payload_json
            from computers_report_v5_snapshots snapshot
            join latest on latest.domain_id=snapshot.domain_id
             and latest.scope_sha256=snapshot.scope_sha256
             and latest.contract_id=snapshot.contract_id
             and latest.schema_version=snapshot.schema_version
            order by snapshot.captured_at_utc desc,snapshot.snapshot_id desc limit 2""",
        tuple([domain_ids] if domain_ids else []),
        statement_timeout_ms=5000,
    )
    if len(rows) < 2:
        return {
            "state": "not_collected",
            "reason": "insufficient_compatible_snapshot_history",
            "current": ({key: _iso(value) for key, value in dict(rows[0]).items() if key != "payload_json"} if rows else None),
            "previous": None,
            "items": [],
            "change_count": 0,
            "deletion_claim_allowed": False,
        }
    payloads: list[dict[str, Any]] = []
    for row in rows[:2]:
        raw = row.get("payload_json")
        payload = dict(raw) if isinstance(raw, Mapping) else json.loads(str(raw))
        payloads.append(payload)
    result = compare_computers_v5_snapshots(current=payloads[0], previous=payloads[1])
    result["current"] = {
        **dict(result.get("current") or {}),
        "snapshot_id": int(rows[0]["snapshot_id"]),
        "captured_at_utc": _iso(rows[0]["captured_at_utc"]),
        "source_state": str(rows[0]["source_state"]),
        "object_count": int(rows[0]["object_count"]),
    }
    result["previous"] = {
        **dict(result.get("previous") or {}),
        "snapshot_id": int(rows[1]["snapshot_id"]),
        "captured_at_utc": _iso(rows[1]["captured_at_utc"]),
        "source_state": str(rows[1]["source_state"]),
        "object_count": int(rows[1]["object_count"]),
    }
    return result


def _sort_value(item: Mapping[str, Any], field: str) -> Any:
    if field == "enabled":
        value = item.get("enabled")
        return 0 if value is True else 1 if value is False else None
    if field == "operating_system":
        value = str(item.get("operating_system") or "").casefold()
        return value or None
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
    signature = hashlib.sha256(b"sli.computers-report.v5\0" + payload).digest()[:12]
    return base64.urlsafe_b64encode(signature + payload).decode("ascii").rstrip("=")


def _decode_cursor(value: str, field: str, direction: str) -> int:
    try:
        raw = base64.urlsafe_b64decode(str(value) + "=" * (-len(str(value)) % 4))
        signature, payload = raw[:12], raw[12:]
        if signature != hashlib.sha256(b"sli.computers-report.v5\0" + payload).digest()[:12]:
            raise ValueError
        decoded = json.loads(payload.decode("utf-8"))
        if decoded[:3] != ["v1", field, direction]:
            raise ValueError
        return int(decoded[3])
    except (TypeError, ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("invalid_computers_v5_cursor") from exc


def _view_matches(item: Mapping[str, Any], view: str) -> bool:
    if view == "attention":
        return item.get("enabled") is True and bool(item.get("reasons"))
    if view == "data_quality":
        return bool(item.get("quality_issues"))
    if view == "semantic":
        return bool(item.get("semantic_findings"))
    if view == "workstation_enabled":
        return item.get("enabled") is True and item.get("computer_type") == "workstation"
    if view == "workstation_disabled":
        return item.get("enabled") is False and item.get("computer_type") == "workstation"
    if view == "server_enabled":
        return item.get("enabled") is True and item.get("computer_type") == "server"
    if view == "server_disabled":
        return item.get("enabled") is False and item.get("computer_type") == "server"
    if view == "unknown_type":
        return item.get("computer_type") == "unknown"
    if view == "changes":
        return False
    return True


def get_computers_v5_report(
    *,
    domain_ids: list[int] | None,
    view: str = "attention",
    reason_code: str | None = None,
    quality_code: str | None = None,
    enabled: str | None = None,
    computer_type: str | None = None,
    operating_system: str | None = None,
    operating_system_version: str | None = None,
    ou: str | None = None,
    activity: str | None = None,
    q: str | None = None,
    sort_by: str = "display_name",
    sort_direction: str = "asc",
    limit: int = 50,
    cursor: str | None = None,
    max_page_limit: int = COMPUTERS_PAGE_LIMIT_MAX,
) -> dict[str, Any]:
    clean_view = str(view or "attention").strip().lower()
    clean_reason = str(reason_code or "").strip()
    clean_quality = str(quality_code or "").strip()
    clean_enabled = str(enabled or "").strip().lower()
    clean_type = str(computer_type or "").strip().lower()
    clean_activity = str(activity or "").strip().lower()
    clean_sort = str(sort_by or "display_name").strip().lower()
    clean_direction = str(sort_direction or "asc").strip().lower()
    if clean_view not in VIEWS:
        raise ValueError("invalid_computers_v5_view")
    if clean_enabled and clean_enabled not in ENABLED_FILTERS:
        raise ValueError("invalid_computers_v5_enabled_filter")
    if clean_type and clean_type not in {"workstation", "server", "unknown"}:
        raise ValueError("invalid_computers_v5_type_filter")
    if clean_activity and clean_activity not in ACTIVITY_FILTERS:
        raise ValueError("invalid_computers_v5_activity_filter")
    if clean_sort not in SORT_FIELDS or clean_direction not in {"asc", "desc"}:
        raise ValueError("invalid_computers_v5_sort")
    clean_limit = max(1, min(int(limit), int(max_page_limit)))
    clean_domains = sorted({int(value) for value in (domain_ids or []) if int(value) > 0})
    coverage = _coverage(clean_domains)
    scope_sql = " and entity.domain_id=any(?)" if clean_domains else ""
    rows = query_rows_bounded(
        f"""/* computers_v5_accounts */
            select entity.id as entity_id,entity.domain_id,entity.display_name,entity.natural_key,
                   version.last_observed_at_utc as observed_at_utc,version.attributes_json as attributes
            from entities_v2_active entity
            join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id
            join domains report_domain on report_domain.id=entity.domain_id
            join ad_context_entity_versions version on version.entity_id=entity.id
             and version.valid_to_utc is null and version.source_section='directory_accounts'
            where entity_type.value='ad_computer'
              and lower(report_domain.fqdn)='{report_domain_fqdn()}'{scope_sql}
              and lower(coalesce(version.attributes_json->'attributes'->>'object_class',''))='computer'
            order by entity.domain_id,entity.id limit ?""",
        tuple([*([clean_domains] if clean_domains else []), COMPUTERS_INPUT_LIMIT + 1]),
        statement_timeout_ms=20_000,
    )
    truncated = len(rows) > COMPUTERS_INPUT_LIMIT
    items = [_item(row) for row in rows[:COMPUTERS_INPUT_LIMIT]]
    semantic_rows = _semantic_rows(items)
    by_entity: dict[int, list[dict[str, Any]]] = {}
    for row in semantic_rows[:200]:
        serialized = {key: _iso(value) for key, value in dict(row).items()}
        by_entity.setdefault(int(row["entity_id"]), []).append(serialized)
    for item in items:
        item["semantic_findings"] = by_entity.get(item["entity_id"], [])
    snapshot_comparison = _load_snapshot_comparison(clean_domains)

    enabled_items = [item for item in items if item["enabled"] is True]
    disabled_items = [item for item in items if item["enabled"] is False]
    unknown_items = [item for item in items if item["enabled"] is None]
    attention_items = [item for item in enabled_items if item["reasons"]]
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
        "server_enabled": sum(item["computer_type"] == "server" for item in enabled_items),
        "server_disabled": sum(item["computer_type"] == "server" for item in disabled_items),
        "unknown_type": sum(item["computer_type"] == "unknown" for item in items),
        "attention": len(attention_items),
        "attention_population": "enabled_ad_records",
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
    clean_ou = str(ou or "").strip().casefold()
    clean_q = str(q or "").strip().casefold()
    filter_options = {
        "operating_systems": sorted({str(item["operating_system"]) for item in items if item.get("operating_system")}, key=str.casefold),
        "operating_system_versions": sorted({str(item["operating_system_version"]) for item in items if item.get("operating_system_version")}, key=str.casefold),
        "ous": sorted({str(item["ou_path"]) for item in items if item.get("ou_path")}, key=str.casefold),
        "ad_site": {"state": "not_collected", "values": []},
    }
    filtered: list[dict[str, Any]] = []
    if clean_view == "changes":
        change_rows = list(snapshot_comparison.get("items") or [])
        if clean_reason:
            change_rows = [item for item in change_rows if item.get("change_type") == clean_reason]
        if clean_q:
            change_rows = [item for item in change_rows if clean_q in f"{item.get('display_name') or ''} {item.get('before') or ''} {item.get('after') or ''}".casefold()]
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
        if clean_ou and clean_ou not in str(item.get("ou_path") or "").casefold():
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
        search_text = " ".join(str(value or "") for value in (
            item["display_name"], item["natural_key"], item.get("dns_host_name"),
            item.get("distinguished_name"), item.get("ou_path"), item.get("operating_system"),
            item.get("operating_system_version"), " ".join(item.get("ip_addresses") or []),
        )).casefold()
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
                raise ValueError("invalid_computers_v5_cursor") from exc
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
        "summary": summary,
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
            "ou": str(ou or "").strip() or None,
            "activity": clean_activity or None,
            "q": str(q or "").strip() or None,
        },
        "sort": {"field": clean_sort, "direction": clean_direction},
        "limits": {"page": clean_limit, "input": COMPUTERS_INPUT_LIMIT, "input_truncated": truncated},
        "limitations": [
            "Enabled показывает состояние записи Active Directory, а не питание или доступность устройства.",
            "Последняя активность основана на приблизительном реплицируемом lastLogonTimestamp.",
            "Ежедневная очередь включает только enabled=true; отключённые записи остаются в качестве данных и инвентаре.",
            "Semantic findings показываются только по точным опубликованным entity-связям и не изменяют AD-квалификацию.",
        ],
    }


_spreadsheet_cell = format_spreadsheet_cell


def render_computers_v5_csv(payload: Mapping[str, Any]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, delimiter=";", lineterminator="\r\n")
    write = lambda values: writer.writerow([_spreadsheet_cell(value) for value in values])
    filters = dict(payload.get("filters") or {})
    filter_text = " | ".join(f"{key}={value}" for key, value in filters.items() if value not in (None, ""))
    write([
        "Контракт", "Состояние", "Представление", "Фильтры", "Компьютер", "Учётная запись",
        "Состояние AD", "Тип", "ОС", "Версия ОС", "OU", "Последняя активность UTC",
        "Семантика времени", "Причины внимания", "Качество данных", "Состояния полей",
        "Semantic link contract", "Semantic findings", "Наблюдалось UTC",
    ])
    for item in payload.get("items") or []:
        write([
            payload.get("contract_id"), payload.get("state"), payload.get("view"), filter_text,
            item.get("display_name"), item.get("natural_key"), item.get("account_state"),
            item.get("computer_type"), item.get("operating_system"), item.get("operating_system_version"),
            item.get("ou_path"), item.get("last_logon_utc"), (item.get("activity") or {}).get("time_semantics"),
            " | ".join(reason.get("code", "") for reason in item.get("reasons") or []),
            " | ".join(issue.get("code", "") for issue in item.get("quality_issues") or []),
            json.dumps((item.get("evidence") or {}).get("attribute_states") or {}, ensure_ascii=False, sort_keys=True),
            SEMANTIC_LINK_CONTRACT,
            " | ".join(str(finding.get("finding_id") or "") for finding in item.get("semantic_findings") or []),
            item.get("observed_at_utc"),
        ])
    return stream.getvalue().encode("utf-8-sig")
