from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from typing import Any

from server.sli.core.database import query_rows_bounded
from server.sli.core.report_domain import report_domain_fqdn
from server.sli.reporting.reporting_common import format_csv_cell, parse_utc

CONTRACT_ID = "sli.active-directory-report.v1"
RISK_RULE_VERSION = 1
INPUT_LIMIT = 5_000
ALLOWED_ENTITY_TYPES = frozenset({"domain", "ad_computer", "replication_link", "password_policy", "domain_trust"})
ALLOWED_SECTIONS = ("domain_posture", "domain_health")
ALLOWED_VIEWS = frozenset({"overview", "domain_controllers", "replication", "dns", "policies", "trusts", "risks", "semantic"})

ACTIVE_DIRECTORY_RISK_LABELS = {
    "dc_advertising_failed": "Контроллер домена не проходит Advertising",
    "dc_connectivity_failed": "Нарушена связность контроллера домена",
    "dc_services_failed": "Не работают обязательные службы контроллера домена",
    "dc_sysvol_failed": "SYSVOL контроллера домена неисправен",
    "dc_netlogon_failed": "NETLOGON контроллера домена недоступен",
    "dns_health_failed": "DNS-проверка контроллера домена не пройдена",
    "replication_failed": "Репликация завершилась ошибкой",
    "replication_stale_over_24h": "Успешной репликации не было более 24 часов",
    "ldap_signing_not_required": "LDAP signing не является обязательным",
    "ldap_channel_binding_never": "LDAP channel binding отключён",
}


_csv_cell = format_csv_cell


def render_active_directory_report_csv(payload: Mapping[str, Any]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, delimiter=";", lineterminator="\r\n")
    controls = payload.get("controls") or []
    if "controls" in payload:
        writer.writerow(("Параметр", "Объект", "Тип объекта", "Контекст", "Фактическое значение", "Ожидаемое условие", "Результат", "Основание", "Источник правила", "Секция", "Наблюдалось"))
        for control in controls:
            actual = control.get("actual_value")
            if isinstance(actual, (dict, list)):
                actual = json.dumps(actual, ensure_ascii=False, sort_keys=True)
            context = json.dumps(control.get("object_context") or {}, ensure_ascii=False, sort_keys=True)
            writer.writerow(tuple(_csv_cell(value) for value in (
                control.get("label"), control.get("entity_name"), control.get("entity_type"), context, actual,
                control.get("expected_condition"), control.get("qualification"), control.get("basis"),
                control.get("authority"), control.get("source_section"), control.get("observed_at_utc"),
            )))
        return ("\ufeff" + output.getvalue()).encode("utf-8")
    writer.writerow(("Тип", "Объект", "Наблюдался", "DNS-имя", "Состояние DNS", "Подтверждённые риски", "Не оценено"))
    for item in payload.get("items") or []:
        attrs = dict(item.get("attributes") or {})
        matched = ", ".join(ACTIVE_DIRECTORY_RISK_LABELS.get(key, key) for key in item.get("matched_risk_keys") or [])
        not_evaluated = ", ".join(ACTIVE_DIRECTORY_RISK_LABELS.get(key, key) for key in item.get("not_evaluated_risk_keys") or [])
        writer.writerow(tuple(_csv_cell(value) for value in (
            item.get("entity_type"), item.get("display_name"), item.get("observed_at_utc"),
            attrs.get("dns_host_name"), attrs.get("dns_state"), matched, not_evaluated,
        )))
    return ("\ufeff" + output.getvalue()).encode("utf-8")


_STATE_RISKS = {
    "advertising_state": "dc_advertising_failed",
    "connectivity_state": "dc_connectivity_failed",
    "services_state": "dc_services_failed",
    "sysvol_state": "dc_sysvol_failed",
    "netlogon_state": "dc_netlogon_failed",
    "dns_state": "dns_health_failed",
}
_UNKNOWN_STATES = {"", "unknown", "unavailable", "timeout", "not_collected", "not_evaluated", "partial"}


_utc = parse_utc


def _iso(value: Any) -> Any:
    parsed = _utc(value)
    return parsed.isoformat() if parsed is not None else value


def _attributes(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return {}
    if not isinstance(value, Mapping):
        return {}
    nested = value.get("attributes")
    return dict(nested) if isinstance(nested, Mapping) else dict(value)


def _qualification_for_state(value: Any) -> str:
    state = str(value or "").strip().casefold()
    if state in _UNKNOWN_STATES:
        return "not_evaluated"
    return "matched" if state == "failed" else "not_matched"


def _risk(risk_key: str, qualification: str, evidence: Any = None) -> dict[str, Any]:
    return {
        "risk_key": risk_key,
        "label": ACTIVE_DIRECTORY_RISK_LABELS[risk_key],
        "qualification": qualification,
        "rule_version": RISK_RULE_VERSION,
        "evidence": evidence,
    }


_LDAP_QUALIFICATIONS = {
    "ldap_signing_requirement": {"require_signing": "passed", "not_required": "failed"},
    "ldap_channel_binding_requirement": {"always": "passed", "when_supported": "passed", "never": "failed"},
}


def _ldap_qualification(field: str, value: Any) -> str:
    # Only producer-defined observed enums can satisfy the existing report rule.
    # Unknown or malformed evidence is not a safe fallback.
    if not isinstance(value, str):
        return "not_evaluated"
    return _LDAP_QUALIFICATIONS[field].get(value.strip().casefold(), "not_evaluated")


def evaluate_active_directory_risks(entity_type: str, attributes: Mapping[str, Any], snapshot_utc: datetime) -> list[dict[str, Any]]:
    results = {key: _risk(key, "not_applicable") for key in ACTIVE_DIRECTORY_RISK_LABELS}
    if entity_type == "domain_controller":
        for field, key in _STATE_RISKS.items():
            results[key] = _risk(key, _qualification_for_state(attributes.get(field)), attributes.get(field))
    elif entity_type == "replication_link":
        state = str(attributes.get("replication_state") or "").strip().casefold()
        if state in _UNKNOWN_STATES:
            qualification = "not_evaluated"
        else:
            qualification = "matched" if state == "failed" or int(attributes.get("consecutive_failure_count") or 0) > 0 or int(attributes.get("last_replication_result") or 0) != 0 else "not_matched"
        results["replication_failed"] = _risk("replication_failed", qualification, attributes.get("last_replication_result"))
        last_success = _utc(attributes.get("last_replication_success_utc"))
        stale = "not_evaluated" if last_success is None else "matched" if snapshot_utc - last_success > timedelta(hours=24) else "not_matched"
        results["replication_stale_over_24h"] = _risk("replication_stale_over_24h", stale, _iso(last_success))
    elif entity_type == "domain":
        for field, risk_key in (
            ("ldap_signing_requirement", "ldap_signing_not_required"),
            ("ldap_channel_binding_requirement", "ldap_channel_binding_never"),
        ):
            actual = attributes.get(field)
            qualification = _ldap_qualification(field, actual)
            risk_qualification = {"passed": "not_matched", "failed": "matched"}.get(qualification, "not_evaluated")
            results[risk_key] = _risk(risk_key, risk_qualification, actual)
    return list(results.values())


_CONTROL_CONTEXT_FIELDS = {
    "domain_controller": ("dns_host_name", "site_name", "is_global_catalog", "is_read_only", "operation_master_roles", "distinguished_name"),
    "domain": ("forest_name", "netbios_name", "distinguished_name", "pdc_emulator", "rid_master", "infrastructure_master", "schema_master", "domain_naming_master"),
    "replication_link": ("source_dc", "destination_dc", "naming_context", "last_replication_attempt_utc"),
    "domain_trust": ("trust_partner", "trust_flat_name", "distinguished_name"),
}


def _object_context(item: Mapping[str, Any]) -> dict[str, Any]:
    attributes = dict(item.get("attributes") or {})
    return {
        field: attributes[field]
        for field in _CONTROL_CONTEXT_FIELDS.get(str(item["entity_type"]), ())
        if field in attributes and attributes[field] is not None
    }


def _control(
    item: Mapping[str, Any],
    *,
    control_id: str,
    category: str,
    label: str,
    actual_value: Any,
    expected_condition: str,
    qualification: str,
    authority: str,
    basis: str,
) -> dict[str, Any]:
    return {
        "control_id": control_id,
        "category": category,
        "label": label,
        "entity_id": int(item["entity_id"]),
        "domain_id": item.get("domain_id"),
        "domain_name": item.get("domain_name"),
        "entity_type": str(item["entity_type"]),
        "entity_name": str(item["display_name"]),
        "object_context": _object_context(item),
        "actual_value": actual_value,
        "expected_condition": expected_condition,
        "qualification": qualification,
        "authority": authority,
        "basis": basis,
        "source_section": str(item["source_section"]),
        "observed_at_utc": item.get("observed_at_utc"),
    }


def _diagnostic_qualification(value: Any) -> str:
    state = str(value or "").strip().casefold()
    if state in _UNKNOWN_STATES:
        return "not_evaluated"
    return "passed" if state == "passed" else "failed"


def build_active_directory_controls(items: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    controls: list[dict[str, Any]] = []

    def add_policy_unset(item: Mapping[str, Any], control_id: str, category: str, label: str, value: Any) -> None:
        if value is None:
            return
        controls.append(_control(
            item,
            control_id=control_id,
            category=category,
            label=label,
            actual_value=value,
            expected_condition="Требование организации не задано",
            qualification="policy_not_defined",
            authority="not_defined",
            basis="Фактическое значение показано без квалификации; условие должен определить владелец политики.",
        ))

    def add_diagnostic(item: Mapping[str, Any], field: str, control_id: str, label: str, test_name: str) -> None:
        attributes = dict(item.get("attributes") or {})
        if field not in attributes:
            return
        actual = attributes.get(field)
        controls.append(_control(
            item,
            control_id=control_id,
            category="domain_controllers" if control_id != "dc.dns" else "dns",
            label=label,
            actual_value=actual,
            expected_condition=f"DCDiag {test_name} должен завершиться успешно",
            qualification=_diagnostic_qualification(actual),
            authority="collector_diagnostic",
            basis=f"Результат read-only DCDiag {test_name} для конкретного контроллера домена.",
        ))

    for item in items:
        attributes = dict(item.get("attributes") or {})
        entity_type = str(item["entity_type"])
        if entity_type == "domain_controller":
            for field, control_id, label, test_name in (
                ("advertising_state", "dc.advertising", "Advertising контроллера домена", "Advertising"),
                ("connectivity_state", "dc.connectivity", "Связность контроллера домена", "Connectivity"),
                ("services_state", "dc.services", "Обязательные службы контроллера домена", "Services"),
                ("sysvol_state", "dc.sysvol", "Доступность SYSVOL", "SysVolCheck"),
                ("netlogon_state", "dc.netlogon", "Доступность NETLOGON", "NetLogons"),
                ("dns_state", "dc.dns", "DNS контроллера домена", "DNS"),
            ):
                add_diagnostic(item, field, control_id, label, test_name)
            for field, control_id, label in (
                ("operating_system", "dc.operating_system", "Операционная система контроллера"),
                ("operating_system_version", "dc.operating_system_version", "Версия операционной системы"),
            ):
                add_policy_unset(item, control_id, "domain_controllers", label, attributes.get(field))
        elif entity_type == "domain":
            for field, control_id, label in (
                ("domain_mode", "domain.functional_level", "Функциональный уровень домена"),
                ("forest_mode", "forest.functional_level", "Функциональный уровень леса"),
                ("recycle_bin_enabled", "domain.recycle_bin", "Active Directory Recycle Bin"),
                ("machine_account_quota", "domain.machine_account_quota", "MachineAccountQuota"),
            ):
                add_policy_unset(item, control_id, "policies", label, attributes.get(field))
            if "ldap_signing_requirement" in attributes:
                actual = attributes.get("ldap_signing_requirement")
                qualification = _ldap_qualification("ldap_signing_requirement", actual)
                controls.append(_control(
                    item,
                    control_id="domain.ldap_signing",
                    category="policies",
                    label="Требование подписывания LDAP",
                    actual_value=actual,
                    expected_condition="Правило отчёта v1: подписывание LDAP должно быть обязательным",
                    qualification=qualification,
                    authority="report_rule_v1",
                    basis="Неизвестное значение не является доказательством безопасной настройки; правило применяется только к наблюдаемому параметру.",
                ))
            if "ldap_channel_binding_requirement" in attributes:
                actual = attributes.get("ldap_channel_binding_requirement")
                qualification = _ldap_qualification("ldap_channel_binding_requirement", actual)
                controls.append(_control(
                    item,
                    control_id="domain.ldap_channel_binding",
                    category="policies",
                    label="Требование LDAP channel binding",
                    actual_value=actual,
                    expected_condition="Правило отчёта v1: значение не должно быть Never",
                    qualification=qualification,
                    authority="report_rule_v1",
                    basis="Неизвестное значение не является доказательством безопасной настройки; правило применяется только к наблюдаемому параметру.",
                ))
        elif entity_type == "replication_link":
            if "replication_state" in attributes:
                actual = attributes.get("replication_state")
                controls.append(_control(
                    item,
                    control_id="replication.state",
                    category="replication",
                    label="Состояние репликации",
                    actual_value=actual,
                    expected_condition="Сборщик должен вернуть passed",
                    qualification=_diagnostic_qualification(actual),
                    authority="collector_diagnostic",
                    basis="Результат read-only Get-ADReplicationPartnerMetadata.",
                ))
            for field, control_id, label in (
                ("last_replication_result", "replication.result_code", "Код последней репликации"),
                ("consecutive_failure_count", "replication.consecutive_failures", "Последовательные ошибки репликации"),
            ):
                if field not in attributes:
                    continue
                actual = attributes.get(field)
                passed = int(actual or 0) == 0
                controls.append(_control(
                    item,
                    control_id=control_id,
                    category="replication",
                    label=label,
                    actual_value=actual,
                    expected_condition="Значение должно быть равно 0",
                    qualification="passed" if passed else "failed",
                    authority="collector_diagnostic",
                    basis="Фактический счётчик последнего read-only снимка метаданных репликации.",
                ))
            if "last_replication_success_utc" in attributes:
                actual = attributes.get("last_replication_success_utc")
                success = _utc(actual)
                observed = _utc(item.get("observed_at_utc"))
                qualification = "not_evaluated" if success is None or observed is None else "failed" if observed - success > timedelta(hours=24) else "passed"
                controls.append(_control(
                    item,
                    control_id="replication.last_success_freshness",
                    category="replication",
                    label="Свежесть успешной репликации",
                    actual_value=actual,
                    expected_condition="Правило отчёта v1: успешная репликация не старше 24 часов",
                    qualification=qualification,
                    authority="report_rule_v1",
                    basis="Сравниваются время снимка и наблюдаемое время последней успешной репликации.",
                ))
        elif entity_type == "password_policy":
            for field, control_id, label in (
                ("password_min_length", "password.minimum_length", "Минимальная длина пароля"),
                ("password_history_length", "password.history_length", "История паролей"),
                ("password_min_age", "password.minimum_age", "Минимальный возраст пароля"),
                ("password_max_age", "password.maximum_age", "Максимальный возраст пароля"),
                ("password_properties", "password.properties", "Свойства парольной политики"),
                ("lockout_threshold", "password.lockout_threshold", "Порог блокировки"),
                ("lockout_duration", "password.lockout_duration", "Длительность блокировки"),
                ("lockout_observation_window", "password.lockout_observation_window", "Окно наблюдения блокировки"),
            ):
                add_policy_unset(item, control_id, "policies", label, attributes.get(field))
        elif entity_type == "domain_trust":
            for field, control_id, label in (
                ("trust_direction", "trust.direction", "Направление доверия"),
                ("trust_type", "trust.type", "Тип доверия"),
                ("trust_attributes", "trust.attributes", "Атрибуты доверия"),
            ):
                add_policy_unset(item, control_id, "trusts", label, attributes.get(field))
    return controls


def _cursor_value(item: Mapping[str, Any]) -> tuple[str, int]:
    return str(item.get("display_name") or "").casefold(), int(item["entity_id"])


def _encode_cursor(value: tuple[str, int]) -> str:
    payload = json.dumps(list(value), ensure_ascii=False, separators=(",", ":")).encode()
    signature = hashlib.sha256(b"sli.active-directory-report.v1\0" + payload).digest()[:12]
    return base64.urlsafe_b64encode(signature + payload).decode().rstrip("=")


def _decode_cursor(value: str) -> tuple[str, int]:
    try:
        raw = base64.urlsafe_b64decode(str(value) + "=" * (-len(str(value)) % 4))
        signature, payload = raw[:12], raw[12:]
        if signature != hashlib.sha256(b"sli.active-directory-report.v1\0" + payload).digest()[:12]:
            raise ValueError
        decoded = json.loads(payload.decode())
        if not isinstance(decoded, list) or len(decoded) != 2:
            raise ValueError
        return str(decoded[0]), int(decoded[1])
    except (TypeError, ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("invalid_active_directory_cursor") from exc


def _coverage_state(rows: Sequence[Mapping[str, Any]], domain_ids: Sequence[int]) -> tuple[str, dict[str, Any]]:
    now = datetime.now(timezone.utc)
    expected = {(int(domain), section) for domain in domain_ids for section in ALLOWED_SECTIONS} if domain_ids else set()
    present = {
        (int(row["domain_id"]), str(row["section_name"]))
        for row in rows
        if row.get("observed_at_utc") is not None
    }
    missing = sorted({f"{domain}:{section}" for domain, section in expected - present})
    stale = sorted(
        f"{int(row['domain_id'])}:{row['section_name']}"
        for row in rows
        if _utc(row.get("observed_at_utc")) is None or _utc(row.get("observed_at_utc")) < now - timedelta(hours=24)
    )
    failed = sorted(
        f"{int(row['domain_id'])}:{row['section_name']}"
        for row in rows
        if row.get("run_status") in {"failed", "cancelled"} or row.get("section_status") == "failed"
    )
    partial = sorted(
        f"{int(row['domain_id'])}:{row['section_name']}"
        for row in rows
        if row.get("run_status") == "partial" or row.get("section_status") == "partial"
    )
    if not rows:
        state = "not_collected"
    elif failed or partial or missing:
        state = "partial"
    elif stale:
        state = "stale"
    else:
        state = "available"
    return state, {
        "expected_sections": list(ALLOWED_SECTIONS),
        "missing": missing,
        "stale": stale,
        "failed": failed,
        "partial": partial,
        "domains": [{key: _iso(value) for key, value in dict(row).items()} for row in rows],
    }


def get_active_directory_report(
    *,
    domain_ids: Sequence[int] | None,
    view: str = "overview",
    risk_key: str | None = None,
    q: str | None = None,
    limit: int = 50,
    cursor: str | None = None,
    max_page_limit: int = 200,
    qualify_names: bool | None = None,
) -> dict[str, Any]:
    clean_view = str(view or "overview").strip().casefold()
    if clean_view not in ALLOWED_VIEWS:
        raise ValueError("unknown_active_directory_view")
    clean_risk = str(risk_key or "").strip() or None
    if clean_risk is not None and clean_risk not in ACTIVE_DIRECTORY_RISK_LABELS:
        raise ValueError("unknown_active_directory_risk")
    clean_q = str(q or "").strip().casefold()
    clean_limit = int(limit)
    if clean_limit < 1 or clean_limit > max_page_limit:
        raise ValueError("invalid_active_directory_limit")
    clean_domains = sorted({int(item) for item in domain_ids or [] if int(item) > 0})

    # Explicit domain IDs are server-authorized; only legacy callers use the installation domain.
    domain_sql = "report_domain.id=any(?)" if domain_ids is not None else f"lower(report_domain.fqdn)='{report_domain_fqdn()}'"
    coverage_rows = [] if domain_ids is not None and not clean_domains else query_rows_bounded(
        f"""/* active_directory_report_coverage */
        with expected_domains as (
          select report_domain.id as domain_id,report_domain.fqdn as domain_name
          from domains report_domain
          where {domain_sql}
        ), required_sections(section_name) as (
          values ('domain_posture'),('domain_health')
        ), latest_section as (
          select distinct on (run.domain_id,section.section_name)
                 run.domain_id,section.section_name,run.status as run_status,
                 section.status as section_status,section.record_count,run.observed_at_utc
          from ad_context_runs run
          join expected_domains expected on expected.domain_id=run.domain_id
          join ad_context_sections section on section.run_id=run.run_id
          where section.section_name=any(?)
          order by run.domain_id,section.section_name,run.observed_at_utc desc,run.created_at desc,run.run_id desc
        )
        select expected.domain_id,expected.domain_name,required.section_name,
               latest.run_status,latest.section_status,latest.record_count,latest.observed_at_utc
        from expected_domains expected cross join required_sections required
        left join latest_section latest on latest.domain_id=expected.domain_id and latest.section_name=required.section_name
        order by expected.domain_id,required.section_name""",
        (*([clean_domains] if clean_domains else []), list(ALLOWED_SECTIONS)),
        statement_timeout_ms=5_000,
    )
    state, coverage = _coverage_state(coverage_rows, clean_domains)

    entity_domain_sql = "entity.domain_id=any(?)" if domain_ids is not None else f"lower(report_domain.fqdn)='{report_domain_fqdn()}'"
    rows = [] if domain_ids is not None and not clean_domains else query_rows_bounded(
        f"""/* active_directory_report_entities */
        select entity.id as entity_id,entity.domain_id,report_domain.fqdn as domain_name,entity_type.value as entity_type,
               entity.display_name,entity.natural_key,version.source_section,
               version.last_observed_at_utc as observed_at_utc,version.attributes_json as attributes
        from entities_v2_active entity
        join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id
        join domains report_domain on report_domain.id=entity.domain_id
        join ad_context_entity_versions version on version.entity_id=entity.id and version.valid_to_utc is null
        where version.source_section=any(?) and entity_type.value=any(?)
          and {entity_domain_sql}
        order by entity.domain_id,entity.id limit ?""",
        (list(ALLOWED_SECTIONS), sorted(ALLOWED_ENTITY_TYPES), *([clean_domains] if clean_domains else []), INPUT_LIMIT + 1),
        statement_timeout_ms=20_000,
    )
    input_truncated = len(rows) > INPUT_LIMIT
    rows = rows[:INPUT_LIMIT]
    allowed_rows = []
    for row in rows:
        if row.get("entity_type") not in ALLOWED_ENTITY_TYPES or row.get("source_section") not in ALLOWED_SECTIONS:
            continue
        attrs = _attributes(row.get("attributes"))
        if row.get("entity_type") == "ad_computer" and (
            row.get("source_section") != "domain_health"
            or attrs.get("infrastructure_role") != "domain_controller"
        ):
            continue
        allowed_rows.append(row)
    observed = [_utc(row.get("observed_at_utc")) for row in allowed_rows]
    snapshot_utc = max((value for value in observed if value is not None), default=datetime.now(timezone.utc))
    all_items: list[dict[str, Any]] = []
    qualified = qualify_names if qualify_names is not None else domain_ids is None or len(clean_domains) > 1
    for raw in allowed_rows:
        attrs = _attributes(raw.get("attributes"))
        report_entity_type = "domain_controller" if raw["entity_type"] == "ad_computer" else str(raw["entity_type"])
        risks = evaluate_active_directory_risks(report_entity_type, attrs, snapshot_utc)
        domain_name = raw.get("domain_name")
        display_name = str(raw.get("display_name") or raw.get("natural_key") or "—")
        if qualified:
            display_name = f"{domain_name or raw['domain_id']}\\{display_name}"
        all_items.append({
            "entity_id": int(raw["entity_id"]),
            "domain_id": int(raw["domain_id"]),
            "domain_name": domain_name,
            "entity_type": report_entity_type,
            "display_name": display_name,
            "source_section": str(raw["source_section"]),
            "observed_at_utc": _iso(raw.get("observed_at_utc")),
            "attributes": attrs,
            "risks": risks,
            "matched_risk_keys": [item["risk_key"] for item in risks if item["qualification"] == "matched"],
            "not_evaluated_risk_keys": [item["risk_key"] for item in risks if item["qualification"] == "not_evaluated"],
        })

    controllers = [item for item in all_items if item["entity_type"] == "domain_controller"]
    replications = [item for item in all_items if item["entity_type"] == "replication_link"]
    summary = {
        "domain_count": sum(item["entity_type"] == "domain" for item in all_items),
        "domain_controller_count": len(controllers),
        "domain_controllers_with_failures": sum(bool(item["matched_risk_keys"]) for item in controllers),
        "replication_link_count": len(replications),
        "replication_failure_count": sum("replication_failed" in item["matched_risk_keys"] for item in replications),
        "dns_failure_count": sum("dns_health_failed" in item["matched_risk_keys"] for item in controllers),
        "policy_count": sum(item["entity_type"] == "password_policy" for item in all_items),
        "trust_count": sum(item["entity_type"] == "domain_trust" for item in all_items),
        "unique_infrastructure_entities_with_risks": sum(bool(item["matched_risk_keys"]) for item in all_items),
        "risk_counts": {key: sum(key in item["matched_risk_keys"] for item in all_items) for key in ACTIVE_DIRECTORY_RISK_LABELS},
        "not_evaluated_counts": {key: sum(key in item["not_evaluated_risk_keys"] for item in all_items) for key in ACTIVE_DIRECTORY_RISK_LABELS},
    }
    all_controls = build_active_directory_controls(all_items)
    summary["control_counts"] = {
        qualification: sum(control["qualification"] == qualification for control in all_controls)
        for qualification in ("passed", "failed", "not_evaluated", "policy_not_defined")
    }
    control_category = {
        "domain_controllers": "domain_controllers",
        "replication": "replication",
        "dns": "dns",
        "policies": "policies",
        "trusts": "trusts",
    }
    if clean_view == "overview":
        controls = all_controls
    elif clean_view == "risks":
        controls = [control for control in all_controls if control["qualification"] == "failed"]
    elif clean_view == "semantic":
        controls = []
    else:
        controls = [control for control in all_controls if control["category"] == control_category[clean_view]]

    view_types = {
        "overview": {"domain"},
        "domain_controllers": {"domain_controller"},
        "replication": {"replication_link"},
        "dns": {"domain_controller"},
        "policies": {"password_policy", "domain"},
        "trusts": {"domain_trust"},
        "risks": ALLOWED_ENTITY_TYPES,
        "semantic": {item["entity_type"] for item in all_items},
    }
    items = [item for item in all_items if item["entity_type"] in view_types[clean_view]]
    if clean_view == "dns":
        items = [{**item, "matched_risk_keys": [key for key in item["matched_risk_keys"] if key == "dns_health_failed"]} for item in items]
    if clean_view == "risks":
        items = [item for item in items if item["matched_risk_keys"]]
    if clean_view == "semantic" and items:
        semantic_rows = query_rows_bounded(
            """/* active_directory_report_semantic */
            select distinct finding.id as finding_id,linked.entity_id,finding.title,finding.severity,
                   finding.status,finding.summary,finding.why_it_matters,finding.recommended_action,finding.last_seen_utc
            from findings finding join finding_entities linked on linked.finding_id=finding.id
            where linked.entity_id=any(?) and is_semantic_finding_published_v1(finding.id)
            order by finding.last_seen_utc desc,finding.id desc limit 201""",
            ([item["entity_id"] for item in items],), statement_timeout_ms=5_000,
        )
        by_entity: dict[int, list[dict[str, Any]]] = {}
        for semantic in semantic_rows:
            by_entity.setdefault(int(semantic["entity_id"]), []).append({key: _iso(value) for key, value in dict(semantic).items()})
        items = [
            {**item, "semantic_findings": by_entity[item["entity_id"]]}
            for item in items
            if item["entity_id"] in by_entity
        ]
    if clean_risk:
        items = [item for item in items if clean_risk in item["matched_risk_keys"]]
    if clean_q:
        items = [item for item in items if clean_q in (item["display_name"] + " " + json.dumps(item["attributes"], ensure_ascii=False, default=str)).casefold()]
    items.sort(key=_cursor_value)
    if cursor:
        after = _decode_cursor(cursor)
        items = [item for item in items if _cursor_value(item) > after]
    has_more = len(items) > clean_limit
    page = items[:clean_limit]

    return {
        "contract_id": CONTRACT_ID,
        "rule_version": RISK_RULE_VERSION,
        "state": state if all_items else "empty" if state == "available" else state,
        "view": clean_view,
        "evaluation_snapshot_utc": snapshot_utc.isoformat(),
        "coverage": coverage,
        "summary": summary,
        "controls": controls,
        "filters": {"risk_key": clean_risk, "q": clean_q or None},
        "items": page,
        "has_more": has_more,
        "next_cursor": _encode_cursor(_cursor_value(page[-1])) if has_more and page else None,
        "limits": {"input_limit": INPUT_LIMIT, "input_truncated": input_truncated, "page_limit": clean_limit},
    }
