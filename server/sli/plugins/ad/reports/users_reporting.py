"""Evidence-bound read model helpers for the additional Users report."""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from server.sli.core.database import query_rows_bounded
from server.sli.reporting.reporting_common import format_spreadsheet_cell, parse_utc
from server.sli.core.report_domain import report_domain_fqdn
from server.sli.plugins.ad.reports import ad_hygiene_policy


USERS_REPORT_CONTRACT_ID = "sli.users-report.v1"
RISK_RULE_VERSION = 1

RISK_LABELS = {
    "password_never_expires": "Пароль не истекает",
    "password_older_than_90_days": "Возраст пароля превышает политику",
    "inactive_over_60_days": "Неактивность превышает политику",
    "account_locked": "Учётная запись заблокирована",
    "enabled_account_expired": "Включённая запись с истёкшим сроком действия",
    "disabled_with_direct_privilege": "Отключённая запись с сохранённой привилегией",
    "multiple_direct_privileged_roles": "Несколько прямых привилегированных ролей",
    "enabled_without_last_logon_data": "Нет данных о последнем входе",
}

RISK_EXPECTED_CONDITIONS = {
    "password_never_expires": "Пароль имеет ограниченный срок действия",
    "password_older_than_90_days": "Возраст пароля в пределах принятой политики",
    "inactive_over_60_days": "Последняя активность в пределах принятой политики",
    "account_locked": "Учётная запись не заблокирована",
    "enabled_account_expired": "У включённой записи не истёк срок действия",
    "disabled_with_direct_privilege": "У отключённой записи нет прямых привилегий",
    "multiple_direct_privileged_roles": "У записи не более одной прямой привилегированной роли",
    "enabled_without_last_logon_data": "Для включённой записи наблюдается последний вход",
}
RISK_SOURCE_SECTIONS = {
    "disabled_with_direct_privilege": ["directory_accounts", "privileged_membership"],
    "multiple_direct_privileged_roles": ["privileged_membership"],
}
_SERVICE_OU_PATTERN = re.compile(r"(?:^|,)OU=ServiceAcc(?:,|$)", re.IGNORECASE)
_SERVICE_SVC_PATTERN = re.compile(r"(?:^|[._-])svc(?:[._-]|$)", re.IGNORECASE)


_utc = parse_utc


def _risk(key: str, qualification: str, reason: str, evidence: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "risk_key": key,
        "rule_version": RISK_RULE_VERSION,
        "label": RISK_LABELS[key],
        "qualification": qualification,
        "reason": reason,
        "evidence": dict(evidence),
        "expected_condition": RISK_EXPECTED_CONDITIONS[key],
        "source_sections": list(RISK_SOURCE_SECTIONS.get(key, ["directory_accounts"])),
    }


def classify_service_account(
    attributes: Mapping[str, Any],
    *,
    natural_key: str,
) -> tuple[bool, list[str]]:
    """Classify only from the explicit historical OU/name heuristic."""
    basis: list[str] = []
    distinguished_name = str(attributes.get("distinguished_name") or "").strip()
    if _SERVICE_OU_PATTERN.search(distinguished_name):
        basis.append("ou:ServiceAcc")
    names = {
        str(attributes.get("sam_account_name") or "").strip(),
        str(attributes.get("user_principal_name") or "").split("@", 1)[0].strip(),
        str(attributes.get("display_name") or "").strip(),
        str(natural_key or "").rsplit("\\", 1)[-1].strip(),
    }
    normalized_names = {value.casefold() for value in names if value}
    if any(_SERVICE_SVC_PATTERN.search(value) for value in normalized_names):
        basis.append("name:svc")
    if any("service" in value for value in normalized_names):
        basis.append("name:service")
    return bool(basis), basis


def evaluate_account_risks(
    attributes: Mapping[str, Any],
    *,
    observed_at_utc: datetime | str | None,
    direct_privilege_count: int,
    privilege_evidence_complete: bool = True,
    policy: Mapping[str, int] | None = None,
) -> list[dict[str, Any]]:
    """Evaluate the eight owner-approved v1 account risk rules.

    Missing evidence yields ``not_evaluated`` instead of false. Time rules are
    evaluated against the timestamp of the directory observation, never the
    browser clock.
    """
    observed = _utc(observed_at_utc)

    enabled = attributes.get("enabled")
    password_never_expires = attributes.get("password_never_expires")
    last_logon = _utc(attributes.get("last_logon_utc"))
    expiration = _utc(attributes.get("account_expiration_utc"))
    locked = attributes.get("locked_out")
    roles = max(0, int(direct_privilege_count or 0))

    result: list[dict[str, Any]] = []
    if password_never_expires is None:
        result.append(_risk("password_never_expires", "not_evaluated", "password_expiration_policy_not_observed", {}))
    else:
        result.append(_risk("password_never_expires", "matched" if password_never_expires is True else "not_matched", "password_never_expires" if password_never_expires is True else "password_expiration_enabled", {"password_never_expires": password_never_expires}))

    policy = ad_hygiene_policy.thresholds() if policy is None else policy
    for key, value, policy_key, field in (
        ("password_older_than_90_days", attributes.get("password_last_set_utc"), "password_age", "password_last_set_utc"),
        ("inactive_over_60_days", attributes.get("last_logon_utc"), "inactivity", "last_logon_utc"),
    ):
        evaluation = ad_hygiene_policy.evaluate(value, observed_at_utc, policy[policy_key])
        qualification = {"unknown": "not_evaluated", "exceeded": "matched", "within_policy": "not_matched"}[evaluation["status"]]
        evidence = {field: evaluation["value"], "observed_at_utc": evaluation["observed_at"], "threshold_days": policy[policy_key]}
        if policy_key == "inactivity":
            evidence["time_semantics"] = "replicated_lastLogonTimestamp_approximation"
            evidence["limitation"] = ad_hygiene_policy.REPLICATION_CAVEAT
        reason = evaluation["reason"] or f"{policy_key}_{evaluation['status']}"
        if evaluation["reason"] == "fact_missing_or_invalid" and not value:
            reason = "password_last_set_not_observed" if policy_key == "password_age" else "last_logon_not_observed"
        risk = _risk(key, qualification, reason, evidence)
        days = policy[policy_key]
        risk["label"] = f"Пароль не менялся более {days} дней" if policy_key == "password_age" else f"Нет активности более {days} дней"
        risk["expected_condition"] = f"Пароль установлен не более {days} дней назад" if policy_key == "password_age" else f"Последняя активность не старше {days} дней"
        result.append(risk)

    if locked is None:
        result.append(_risk("account_locked", "not_evaluated", "lock_state_not_observed", {}))
    else:
        result.append(_risk("account_locked", "matched" if locked is True else "not_matched", "locked_out" if locked is True else "not_locked", {"locked_out": locked}))

    if enabled is None:
        result.append(_risk("enabled_account_expired", "not_evaluated", "enabled_state_not_observed", {}))
    elif enabled is not True:
        result.append(_risk("enabled_account_expired", "not_matched", "account_not_enabled", {"enabled": enabled}))
    elif expiration is None:
        result.append(_risk("enabled_account_expired", "not_evaluated", "account_expiration_not_observed", {"enabled": True}))
    elif observed is None:
        result.append(_risk("enabled_account_expired", "not_evaluated", "observation_time_not_observed", {"enabled": True, "account_expiration_utc": expiration.isoformat()}))
    else:
        matched = expiration < observed
        result.append(_risk("enabled_account_expired", "matched" if matched else "not_matched", "enabled_account_expired" if matched else "account_not_expired", {"enabled": True, "account_expiration_utc": expiration.isoformat(), "observed_at_utc": observed.isoformat()}))

    if not privilege_evidence_complete:
        result.append(_risk("disabled_with_direct_privilege", "not_evaluated", "privileged_membership_incomplete", {"enabled": enabled}))
        result.append(_risk("multiple_direct_privileged_roles", "not_evaluated", "privileged_membership_incomplete", {}))
    else:
        disabled_privileged = enabled is False and roles > 0
        result.append(_risk("disabled_with_direct_privilege", "matched" if disabled_privileged else "not_matched", "disabled_with_direct_privilege" if disabled_privileged else "compound_condition_not_met", {"enabled": enabled, "direct_privilege_count": roles}))
        multiple_roles = roles > 1
        result.append(_risk("multiple_direct_privileged_roles", "matched" if multiple_roles else "not_matched", "multiple_direct_privileged_roles" if multiple_roles else "fewer_than_two_direct_privileged_roles", {"direct_privilege_count": roles}))

    if enabled is None:
        result.append(_risk("enabled_without_last_logon_data", "not_evaluated", "enabled_state_not_observed", {}))
    else:
        missing = enabled is True and last_logon is None
        result.append(_risk("enabled_without_last_logon_data", "matched" if missing else "not_matched", "enabled_without_last_logon_data" if missing else "compound_condition_not_met", {"enabled": enabled, "last_logon_observed": last_logon is not None}))
    return result


def _split_dn(value: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for char in value:
        if char == "," and not escaped:
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(char)
        if char == "\\" and not escaped:
            escaped = True
        else:
            escaped = False
    if current:
        parts.append("".join(current).strip())
    return parts


def normalize_ou_path(distinguished_name: str | None) -> str:
    if distinguished_name is None or not str(distinguished_name).strip():
        return "Расположение не получено"
    # The first RDN identifies the account itself.  All following OU/CN RDNs
    # identify its actual directory location, including standard CN=Users.
    parent_parts = _split_dn(str(distinguished_name))[1:]
    values = [
        part.split("=", 1)[1].replace(r"\,", ",").strip()
        for part in parent_parts
        if "=" in part and part.split("=", 1)[0].upper() in {"OU", "CN"}
    ]
    return " / ".join(reversed(values)) if values else "Корень домена"


def encode_users_cursor(value: tuple[int, str, str, int]) -> str:
    payload = json.dumps(list(value), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    signature = hashlib.sha256(b"sli.users-report.v1\0" + payload).digest()[:12]
    return base64.urlsafe_b64encode(signature + payload).decode("ascii").rstrip("=")


def decode_users_cursor(value: str) -> tuple[int, str, str, int]:
    try:
        raw = base64.urlsafe_b64decode(str(value) + "=" * (-len(str(value)) % 4))
        signature, payload = raw[:12], raw[12:]
        expected = hashlib.sha256(b"sli.users-report.v1\0" + payload).digest()[:12]
        if signature != expected:
            raise ValueError
        decoded = json.loads(payload.decode("utf-8"))
        if not isinstance(decoded, list) or len(decoded) != 4:
            raise ValueError
        return int(decoded[0]), str(decoded[1]), str(decoded[2]), int(decoded[3])
    except (TypeError, ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("invalid_users_cursor") from exc


USERS_INPUT_LIMIT = 10_000
USERS_PAGE_LIMIT_MAX = 200
USERS_SORT_FIELDS = {
    "display_name", "department", "ou_path", "enabled", "last_logon_utc",
    "direct_privilege_count", "risk_count",
}


def _encode_users_sort_cursor(field: str, direction: str, entity_id: int) -> str:
    payload = json.dumps(["v2", field, direction, int(entity_id)], ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    signature = hashlib.sha256(b"sli.users-report.v1\0" + payload).digest()[:12]
    return base64.urlsafe_b64encode(signature + payload).decode("ascii").rstrip("=")


def _decode_users_sort_cursor(value: str, field: str, direction: str) -> int:
    try:
        raw = base64.urlsafe_b64decode(str(value) + "=" * (-len(str(value)) % 4))
        signature, payload = raw[:12], raw[12:]
        if signature != hashlib.sha256(b"sli.users-report.v1\0" + payload).digest()[:12]:
            raise ValueError
        decoded = json.loads(payload.decode("utf-8"))
        if not isinstance(decoded, list) or len(decoded) != 4 or decoded[:3] != ["v2", field, direction]:
            raise ValueError
        return int(decoded[3])
    except (TypeError, ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("invalid_users_cursor") from exc


def _users_sort_value(item: Mapping[str, Any], field: str) -> Any:
    if field == "risk_count":
        return len(item.get("matched_risk_keys") or [])
    value = item.get(field)
    if field == "enabled":
        return 0 if value is True else 1 if value is False else None
    if field == "direct_privilege_count":
        return int(value or 0)
    return str(value).casefold() if value not in (None, "") else None


def _sort_users(items: list[dict[str, Any]], field: str, direction: str) -> list[dict[str, Any]]:
    present = [item for item in items if _users_sort_value(item, field) is not None]
    missing = [item for item in items if _users_sort_value(item, field) is None]
    present.sort(key=lambda item: (_users_sort_value(item, field), str(item["display_name"]).casefold(), int(item["entity_id"])), reverse=direction == "desc")
    missing.sort(key=_account_cursor)
    return [*present, *missing]


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


def _relation_membership_type(row: Mapping[str, Any]) -> str:
    direct = str(row.get("membership_type") or "").strip().lower()
    if direct:
        return direct
    value = row.get("relation_attributes") or {}
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return ""
    if isinstance(value, Mapping):
        nested = value.get("attributes")
        source = nested if isinstance(nested, Mapping) else value
        return str(source.get("membership_type") or "").strip().lower()
    return ""


def _account_cursor(item: Mapping[str, Any]) -> tuple[int, str, str, int]:
    return (
        int(item["domain_id"]),
        str(item["display_name"]).casefold(),
        str(item["natural_key"]).casefold(),
        int(item["entity_id"]),
    )


def get_users_report(
    *,
    domain_ids: list[int] | None,
    view: str = "active",
    department: str | None = None,
    ou: str | None = None,
    risk_key: str | None = None,
    account_type: str | None = None,
    q: str | None = None,
    sort_by: str = "display_name",
    sort_direction: str = "asc",
    limit: int = 50,
    cursor: str | None = None,
    max_page_limit: int = USERS_PAGE_LIMIT_MAX,
    _directory_only: bool = False,
    _directory_rows: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Return one bounded, scope-filtered Users report page and full summary.

    The V2 adapter uses ``_directory_only`` to read active and disabled inputs
    together, without V1 risks/acceptances that are not part of its projection.
    Its optional raw rows come only from V2's complete scoped population.
    Neither internal argument is exposed by the report API.
    """
    clean_view = str(view or "active").strip().lower()
    if clean_view not in {"active", "disabled", "privileged", "risk", "semantic"}:
        raise ValueError("invalid_users_view")
    clean_risk = str(risk_key or "").strip()
    if clean_view == "risk" and clean_risk not in RISK_LABELS:
        raise ValueError("invalid_users_risk_key")
    clean_account_type = str(account_type or "").strip().lower()
    if clean_account_type not in {"", "service", "regular"}:
        raise ValueError("invalid_users_account_type")
    clean_sort = str(sort_by or "display_name").strip().lower()
    clean_direction = str(sort_direction or "asc").strip().lower()
    if clean_sort not in USERS_SORT_FIELDS or clean_direction not in {"asc", "desc"}:
        raise ValueError("invalid_users_sort")
    clean_limit = max(1, min(int(limit), int(max_page_limit)))
    clean_domains = sorted({int(item) for item in (domain_ids or []) if int(item) > 0})
    if _directory_only and domain_ids is not None and not clean_domains:
        return {"state": "not_collected", "items": [], "coverage": {"state": "not_collected", "domains": []},
                "limitations": [], "has_more": False}
    scope_sql = " and entity.domain_id=any(?)" if clean_domains else ""
    scope_params: list[Any] = [clean_domains] if clean_domains else []
    if _directory_only:
        # The sibling V2 reader and its source coverage share the authorized
        # domain set. Legacy ad.users retains its configured-domain contract.
        expected_domains_sql = "select id as domain_id from domains"
        if clean_domains:
            expected_domains_sql += " where id=any(?)"
    else:
        expected_domains_sql = "select id as domain_id from domains where lower(fqdn)='" + report_domain_fqdn() + "'"
        if clean_domains:
            expected_domains_sql += " and id=any(?)"
    coverage_rows = query_rows_bounded(
        f"""/* users_report_coverage */
            with expected_domains as ({expected_domains_sql}),
            expected_sections(section_name) as (
                values ('directory_accounts'),('privileged_membership')
            ),
            latest_section as (
                select distinct on (run.domain_id,section.section_name)
                       run.domain_id,section.section_name,run.status as run_status,
                       section.status as section_status,section.record_count,
                       run.observed_at_utc
                from ad_context_runs run
                join expected_domains expected on expected.domain_id=run.domain_id
                join ad_context_sections section on section.run_id=run.run_id
                where section.section_name in ('directory_accounts','privileged_membership')
                order by run.domain_id,section.section_name,run.observed_at_utc desc,
                         run.created_at desc,run.run_id desc
            )
            select expected.domain_id,domain.fqdn as domain_name,required.section_name,latest.run_status,
                   latest.section_status,latest.record_count,latest.observed_at_utc
            from expected_domains expected
            left join domains domain on domain.id=expected.domain_id
            cross join expected_sections required
            left join latest_section latest
              on latest.domain_id=expected.domain_id
             and latest.section_name=required.section_name
            order by expected.domain_id,required.section_name""",
        tuple([clean_domains] if clean_domains else []),
        statement_timeout_ms=3000,
    )
    section_rows: dict[tuple[int, str], Mapping[str, Any]] = {}
    for row in coverage_rows:
        domain_id = int(row["domain_id"])
        if row.get("section_name"):
            section_rows[(domain_id, str(row["section_name"]))] = row
        else:  # Compatibility for callers/tests using the former aggregate shape.
            for section_name, status_field in (("directory_accounts", "directory_status"), ("privileged_membership", "privilege_status")):
                section_rows[(domain_id, section_name)] = {
                    **row, "section_name": section_name, "section_status": row.get(status_field),
                }
    coverage_domain_ids = sorted({int(row["domain_id"]) for row in coverage_rows})
    directory_rows = [section_rows.get((domain_id, "directory_accounts"), {}) for domain_id in coverage_domain_ids]
    privilege_rows_coverage = [section_rows.get((domain_id, "privileged_membership"), {}) for domain_id in coverage_domain_ids]
    coverage_domains = len(coverage_domain_ids)
    coverage_complete = sum(1 for row in directory_rows if row.get("run_status") == "completed" and row.get("section_status") == "complete")
    coverage_failed = sum(1 for row in directory_rows if row.get("run_status") in {"failed", "cancelled"} or row.get("section_status") == "failed")
    coverage_partial = sum(1 for row in directory_rows if row.get("run_status") == "partial" or row.get("section_status") == "partial")
    coverage_skipped = coverage_domains - coverage_complete - coverage_failed - coverage_partial
    if coverage_domains == 0:
        coverage_state = "not_collected"
    elif coverage_failed == coverage_domains:
        coverage_state = "failed"
    elif coverage_skipped == coverage_domains:
        coverage_state = "not_collected"
    elif coverage_complete == coverage_domains:
        coverage_state = "complete"
    else:
        coverage_state = "partial"
    observed_values = [_utc(row.get("observed_at_utc")) for row in directory_rows]
    observed_values = [item for item in observed_values if item is not None]
    latest_coverage = max(observed_values) if observed_values else None
    stale_domains = sum(
        1 for row in directory_rows
        if ("domain_name" not in row or bool(row.get("domain_name")))
        and (_utc(row.get("observed_at_utc")) is None or _utc(row.get("observed_at_utc")) < datetime.now(timezone.utc) - timedelta(hours=24))
    )
    privilege_complete = bool(coverage_domains) and all(row.get("run_status") == "completed" and row.get("section_status") == "complete" for row in privilege_rows_coverage)
    privilege_state = "complete" if privilege_complete else "not_collected" if all(row.get("section_status") in {None, "skipped"} for row in privilege_rows_coverage) else "partial"
    if coverage_state == "complete" and stale_domains:
        coverage_state = "stale"
    domain_coverage: list[dict[str, Any]] = []
    for domain_id, directory_row, privilege_row in zip(coverage_domain_ids, directory_rows, privilege_rows_coverage, strict=True):
        domain_name = directory_row.get("domain_name") or privilege_row.get("domain_name")
        has_registration_field = "domain_name" in directory_row or "domain_name" in privilege_row
        registered = bool(domain_name) if has_registration_field else True

        def section_state(row: Mapping[str, Any]) -> str:
            if not registered:
                return "not_registered"
            if row.get("run_status") in {"failed", "cancelled"} or row.get("section_status") == "failed":
                return "failed"
            if row.get("run_status") == "completed" and row.get("section_status") == "complete":
                observed = _utc(row.get("observed_at_utc"))
                return "stale" if observed is None or observed < datetime.now(timezone.utc) - timedelta(hours=24) else "complete"
            if row.get("run_status") == "partial" or row.get("section_status") == "partial":
                return "partial"
            return "not_collected"

        directory_observed = _utc(directory_row.get("observed_at_utc"))
        observed_candidates = [directory_observed, _utc(privilege_row.get("observed_at_utc"))]
        observed_candidates = [item for item in observed_candidates if item is not None]
        domain_coverage.append({
            "domain_id": domain_id,
            "domain_name": str(domain_name) if domain_name else None,
            "registered": registered,
            "directory_state": section_state(directory_row),
            "privilege_state": section_state(privilege_row),
            "directory_record_count": int(directory_row.get("record_count") or 0),
            "privilege_record_count": int(privilege_row.get("record_count") or 0),
            "observed_at_utc": directory_observed.isoformat() if directory_observed else None,
            "latest_observed_at_utc": max(observed_candidates).isoformat() if observed_candidates else None,
        })
    coverage = {
        "state": coverage_state,
        "domain_count": coverage_domains,
        "complete_domain_count": coverage_complete,
        "partial_domain_count": coverage_partial,
        "failed_domain_count": coverage_failed,
        "skipped_domain_count": coverage_skipped,
        "stale_domain_count": stale_domains,
        "privilege_state": privilege_state,
        "directory_record_count": sum(int(row.get("record_count") or 0) for row in directory_rows),
        "privilege_record_count": sum(int(row.get("record_count") or 0) for row in privilege_rows_coverage),
        "latest_observed_at_utc": latest_coverage.isoformat() if latest_coverage else None,
        "domains": domain_coverage,
    }
    if _directory_only:
        from .users_v2_reporting import _directory_user_rows

    # Reuse the V1 item assembly for OU and privilege evidence, with the scoped
    # canonical population for V2 instead of the legacy deployment FQDN filter.
    rows = (_directory_rows if _directory_rows is not None else _directory_user_rows(domain_ids=domain_ids, legacy_assembly=True)) if _directory_only else query_rows_bounded(
        f"""select entity.id as entity_id,entity.domain_id,entity.display_name,
                   entity.natural_key,version.last_observed_at_utc as observed_at_utc,
                   version.attributes_json as attributes
            from entities_v2_active entity
            join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id
            join domains report_domain on report_domain.id=entity.domain_id
            join ad_context_entity_versions version
              on version.entity_id=entity.id and version.valid_to_utc is null
             and version.source_section='directory_accounts'
            where entity_type.value='ad_user'
              and lower(report_domain.fqdn)='{report_domain_fqdn()}'{scope_sql}
              and lower(coalesce(version.attributes_json->'attributes'->>'object_class',''))='user'
              and coalesce(version.attributes_json->'attributes'->>'sam_account_name','') not like '%$'
            order by entity.domain_id,entity.id limit ?""",
        tuple([*scope_params, USERS_INPUT_LIMIT + 1]),
        statement_timeout_ms=20_000,
    )
    if _directory_only and _directory_rows is not None:
        # The internal V2 caller reuses only an uncapped authorized population.
        # Match the SQL filter on the nested attribute, not the flat fallback.
        def legacy_account(row):
            raw = row.get("attributes") or {}
            if isinstance(raw, str):
                raw = json.loads(raw)
            attrs = raw.get("attributes") if isinstance(raw, Mapping) else None
            sam = attrs.get("sam_account_name") if isinstance(attrs, Mapping) else None
            return not str(sam or "").endswith("$")

        rows = [row for row in rows if legacy_account(row)
                and (domain_ids is None or int(row["domain_id"]) in clean_domains)]
    truncated = len(rows) > USERS_INPUT_LIMIT
    account_rows = [dict(item) for item in rows[:USERS_INPUT_LIMIT]]
    entity_ids = [int(item["entity_id"]) for item in account_rows]
    privilege_rows: list[dict[str, Any]] = []
    if entity_ids:
        privilege_rows = [dict(item) for item in query_rows_bounded(
            """select relation.source_entity_id,relation.target_entity_id,
                      target_entity.display_name as target_name,
                      relation.attributes_json as relation_attributes
               from ad_context_relation_versions relation
               join entities_v2 target_entity on target_entity.id=relation.target_entity_id
               where relation.valid_to_utc is null
                 and relation.relation_kind='member_of'
                 and relation.source_section='privileged_membership'
                 and relation.source_entity_id=any(?)
                 /* users_report_privileges */
               order by relation.source_entity_id,target_entity.display_name,relation.id""",
            (entity_ids,), statement_timeout_ms=10_000,
        )]
    by_account: dict[int, list[dict[str, Any]]] = {}
    for relation in privilege_rows:
        if _relation_membership_type(relation) != "direct":
            continue
        by_account.setdefault(int(relation["source_entity_id"]), []).append({
            "group_entity_id": int(relation["target_entity_id"]),
            "group_name": str(relation.get("target_name") or relation["target_entity_id"]),
            "membership_type": "direct",
        })

    acceptance_by_risk: dict[tuple[int, str], dict[str, Any]] = {}
    if entity_ids and not _directory_only:
        acceptance_rows = query_rows_bounded(
            """select entity_id,risk_key,public_id,reason,responsible,valid_until,created_by,created_at
               from account_risk_acceptances
               where entity_id=any(?) and status='active' and valid_until>now()
               /* users_report_acceptances */
               order by entity_id,risk_key,created_at desc""",
            (entity_ids,), statement_timeout_ms=3000,
        )
        for raw in acceptance_rows:
            value = dict(raw)
            key = (int(value["entity_id"]), str(value["risk_key"]))
            if key in acceptance_by_risk:
                continue
            acceptance_by_risk[key] = {
                field: item.isoformat() if isinstance(item, datetime) else str(item) if isinstance(item, uuid.UUID) else item
                for field, item in value.items()
                if field != "entity_id"
            }

    items: list[dict[str, Any]] = []
    risk_counts = {key: 0 for key in RISK_LABELS}
    active_count = disabled_count = unknown_count = 0
    ou_counts: dict[str, int] = {}
    department_counts: dict[str, int] = {}
    policy = ad_hygiene_policy.thresholds() if account_rows and not _directory_only else None
    for source in account_rows:
        attrs = _attributes(source)
        entity_id = int(source["entity_id"])
        privileges = by_account.get(entity_id, [])
        observed = source.get("observed_at_utc")
        risks = evaluate_account_risks(
            attrs,
            observed_at_utc=observed,
            direct_privilege_count=len(privileges),
            privilege_evidence_complete=privilege_complete,
            policy=policy,
        ) if not _directory_only else []
        observed_text = _utc(observed).isoformat() if _utc(observed) else None
        for risk in risks:
            risk["observed_at_utc"] = observed_text
        for risk in risks:
            acceptance = acceptance_by_risk.get((entity_id, str(risk["risk_key"])))
            if acceptance is not None:
                risk["acceptance"] = acceptance
        matched = [item for item in risks if item["qualification"] == "matched"]
        for risk in matched:
            risk_counts[str(risk["risk_key"])] += 1
        enabled = attrs.get("enabled")
        if enabled is True:
            active_count += 1
        elif enabled is False:
            disabled_count += 1
        else:
            unknown_count += 1
        ou_path = normalize_ou_path(attrs.get("distinguished_name"))
        department_value = str(attrs.get("department") or "").strip() or None
        natural_key = str(source.get("natural_key") or "")
        service_account, service_account_basis = classify_service_account(attrs, natural_key=natural_key)
        ou_counts[ou_path] = ou_counts.get(ou_path, 0) + 1
        if department_value:
            department_counts[department_value] = department_counts.get(department_value, 0) + 1
        items.append({
            "entity_id": entity_id,
            "domain_id": int(source["domain_id"]),
            "display_name": str(source.get("display_name") or source.get("natural_key") or entity_id),
            "natural_key": natural_key,
            "enabled": enabled,
            "ou_path": ou_path,
            "department": department_value,
            "title": attrs.get("title"),
            "email": attrs.get("email"),
            "created_utc": attrs.get("created_utc"),
            "last_logon_utc": attrs.get("last_logon_utc"),
            "password_last_set_utc": attrs.get("password_last_set_utc"),
            "password_never_expires": attrs.get("password_never_expires"),
            "account_expiration_utc": attrs.get("account_expiration_utc"),
            "locked_out": attrs.get("locked_out"),
            "service_account": service_account,
            "service_account_basis": service_account_basis,
            "observed_at_utc": observed,
            "direct_privileges": privileges,
            "direct_privilege_count": len(privileges),
            "risks": risks,
            "matched_risk_keys": [str(item["risk_key"]) for item in matched],
        })
    semantic_items: list[dict[str, Any]] = []
    semantic_has_more = False
    if clean_view == "semantic" and entity_ids:
        semantic_rows = query_rows_bounded(
            """select distinct finding.id as finding_id,linked.entity_id,
                      account.display_name,finding.title,finding.severity,finding.status,
                      finding.summary,finding.why_it_matters,finding.recommended_action,
                      finding.last_seen_utc
               from findings finding
               join finding_entities linked on linked.finding_id=finding.id
               join entities_v2_active account on account.id=linked.entity_id
               join storage_v2_entity_type entity_type on entity_type.id=account.entity_type_id
               where linked.entity_id=any(?)
                 and entity_type.value='ad_user'
                 and is_semantic_finding_published_v1(finding.id)
                 /* users_report_semantic_linked */
               order by finding.last_seen_utc desc,finding.id desc
               limit 201""",
            (entity_ids,), statement_timeout_ms=5000,
        )
        semantic_has_more = len(semantic_rows) > 200
        for raw in semantic_rows[:200]:
            semantic_items.append({
                key: item.isoformat() if isinstance(item, datetime) else item
                for key, item in dict(raw).items()
            })
    clean_department = str(department or "").strip().casefold()
    clean_ou = str(ou or "").strip().casefold()
    clean_q = str(q or "").strip().casefold()
    filtered = []
    for item in items:
        if clean_view == "semantic":
            continue
        if _directory_only and item["enabled"] is not True and item["enabled"] is not False:
            continue
        if clean_view == "active" and not _directory_only and item["enabled"] is not True:
            continue
        if clean_view == "disabled" and item["enabled"] is not False:
            continue
        if clean_view == "privileged" and int(item["direct_privilege_count"]) == 0:
            continue
        if clean_view == "risk" and clean_risk not in item["matched_risk_keys"]:
            continue
        if clean_account_type == "service" and item["service_account"] is not True:
            continue
        if clean_account_type == "regular" and item["service_account"] is True:
            continue
        if clean_department and str(item["department"] or "").casefold() != clean_department:
            continue
        if clean_ou and str(item["ou_path"]).casefold() != clean_ou:
            continue
        if clean_q and clean_q not in f"{item['display_name']} {item['natural_key']}".casefold():
            continue
        filtered.append(item)
    filtered = _sort_users(filtered, clean_sort, clean_direction)
    if cursor:
        after_entity_id = _decode_users_sort_cursor(cursor, clean_sort, clean_direction)
        try:
            position = next(index for index, item in enumerate(filtered) if int(item["entity_id"]) == after_entity_id)
        except StopIteration as exc:
            raise ValueError("invalid_users_cursor") from exc
        filtered = filtered[position + 1:]
    page = filtered[:clean_limit]
    has_more = len(filtered) > clean_limit
    next_cursor = _encode_users_sort_cursor(clean_sort, clean_direction, int(page[-1]["entity_id"])) if page and has_more else None
    state = (
        "unavailable" if coverage_state == "failed"
        else "not_collected" if coverage_state == "not_collected" and not account_rows
        else "partial" if truncated or coverage_state == "partial" or privilege_state != "complete"
        else "stale" if coverage_state == "stale"
        else "available" if account_rows
        else "empty"
    )
    limitations = [
        "Последний вход основан на реплицируемом lastLogonTimestamp и не является точным временем входа.",
        "Категории рисков пересекаются; их количества нельзя складывать как число уникальных записей.",
    ]
    if coverage_state == "partial":
        limitations.append("Последний directory_accounts snapshot неполон хотя бы для одного разрешённого домена.")
    if privilege_state != "complete":
        limitations.append("Срез privileged_membership неполон; зависящие от него риски не оценены.")
    if coverage_state == "stale":
        limitations.append("Последнее наблюдение directory_accounts старше 24 часов хотя бы для одного разрешённого домена.")
    return {
        "contract_id": USERS_REPORT_CONTRACT_ID,
        "report_key": "ad.users",
        "state": state,
        "view": clean_view,
        "items": page,
        "has_more": has_more,
        "next_cursor": next_cursor,
        "coverage": coverage,
        "summary": {
            "total_users": len(account_rows),
            "active_users": active_count,
            "disabled_users": disabled_count,
            "unknown_enabled_users": unknown_count,
            "privileged_users": sum(1 for item in items if item["direct_privilege_count"]),
            "unique_users_with_risks": sum(1 for item in items if item["matched_risk_keys"]),
            "service_accounts": sum(1 for item in items if item["service_account"]),
            "risk_counts": risk_counts,
            "ou_counts": ou_counts,
            "department_counts": department_counts,
        },
        "filters": {"department": department, "ou": ou, "risk_key": risk_key, "account_type": clean_account_type or None, "q": q},
        "sort": {"field": clean_sort, "direction": clean_direction},
        "limits": {"page": clean_limit, "input": USERS_INPUT_LIMIT, "input_truncated": truncated},
        "semantic": {
            "state": "available" if semantic_items else "empty",
            "items": semantic_items,
            "linked_count": len(semantic_items),
            "has_more": semantic_has_more,
            "excludes_unlinked_findings": True,
            "link_contract": "exact_finding_entity_id_to_ad_user",
        },
        "limitations": limitations,
    }


_spreadsheet_cell = format_spreadsheet_cell


def render_users_report_csv(payload: Mapping[str, Any]) -> bytes:
    """Render the already-authorized Users report slice for Russian Excel."""
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, delimiter=";", lineterminator="\r\n")
    write_row = lambda values: writer.writerow([_spreadsheet_cell(value) for value in values])
    write_row([
        "Тип строки", "Контракт", "Состояние отчёта", "Состояние покрытия", "Выбранный риск", "Ограничения", "Наблюдалось UTC",
        "Учётная запись", "Логин", "Состояние", "OU", "Подразделение",
        "Последний вход UTC", "Пароль установлен UTC", "Прямые привилегии",
        "Квалифицированные риски", "Наблюдалось UTC строки",
        "Сервисная запись", "Основание классификации",
    ])
    selected_risk = str((payload.get("filters") or {}).get("risk_key") or "") if payload.get("view") == "risk" else ""
    coverage = dict(payload.get("coverage") or {})
    metadata = [
        "data", payload.get("contract_id") or USERS_REPORT_CONTRACT_ID, payload.get("state") or "",
        coverage.get("state") or "", selected_risk, " | ".join(str(item) for item in (payload.get("limitations") or [])),
        coverage.get("latest_observed_at_utc") or "",
    ]
    if not (payload.get("items") or []):
        write_row(["metadata", *metadata[1:], "", "", "", "", "", "", "", "", "", "", "", ""])
    for item in payload.get("items") or []:
        enabled = item.get("enabled")
        state = "Включена" if enabled is True else "Отключена" if enabled is False else "Не определено"
        privileges = ", ".join(
            str(value.get("group_name") or "")
            for value in (item.get("direct_privileges") or [])
            if value.get("membership_type") == "direct"
        )
        risks = ", ".join(
            str(value.get("label") or value.get("risk_key") or "")
            for value in (item.get("risks") or [])
            if value.get("qualification") == "matched" and (not selected_risk or value.get("risk_key") == selected_risk)
        )
        write_row([
            *metadata,
            _spreadsheet_cell(item.get("display_name")), _spreadsheet_cell(item.get("natural_key")), state,
            _spreadsheet_cell(item.get("ou_path")), _spreadsheet_cell(item.get("department")),
            item.get("last_logon_utc") or "", item.get("password_last_set_utc") or "",
            privileges, risks, item.get("observed_at_utc") or "",
            "Да" if item.get("service_account") is True else "Нет",
            ", ".join(str(value) for value in (item.get("service_account_basis") or [])),
        ])
    return stream.getvalue().encode("utf-8-sig")


def validate_risk_acceptance_input(
    *,
    risk_key: str,
    reason: str,
    responsible: str,
    valid_until_utc: str,
    now_utc: datetime | None = None,
) -> dict[str, Any]:
    now = _utc(now_utc or datetime.now(timezone.utc)) or datetime.now(timezone.utc)
    clean_risk = str(risk_key or "").strip()
    clean_reason = str(reason or "").strip()
    clean_responsible = str(responsible or "").strip()
    valid_until = _utc(valid_until_utc)
    if clean_risk not in RISK_LABELS:
        raise ValueError("invalid_risk_key")
    if len(clean_reason) < 10 or len(clean_reason) > 2000:
        raise ValueError("invalid_acceptance_reason")
    if not clean_responsible or len(clean_responsible) > 256:
        raise ValueError("invalid_acceptance_responsible")
    if valid_until is None or valid_until <= now or valid_until > now + timedelta(days=365):
        raise ValueError("invalid_acceptance_expiry")
    return {
        "risk_key": clean_risk,
        "reason": clean_reason,
        "responsible": clean_responsible,
        "valid_until_utc": valid_until,
    }


def create_risk_acceptance(
    *,
    entity_id: int,
    domain_ids: list[int] | None,
    risk_key: str,
    reason: str,
    responsible: str,
    valid_until_utc: str,
    actor: str,
) -> dict[str, Any]:
    actor = _decision_actor(actor)
    values = validate_risk_acceptance_input(
        risk_key=risk_key,
        reason=reason,
        responsible=responsible,
        valid_until_utc=valid_until_utc,
    )
    current = get_users_report(
        domain_ids=domain_ids,
        view="risk",
        risk_key=values["risk_key"],
        limit=USERS_INPUT_LIMIT,
        max_page_limit=USERS_INPUT_LIMIT,
    )
    if current.get("state") != "available":
        raise PermissionError("risk_evidence_not_actionable")
    account = next((item for item in current["items"] if int(item["entity_id"]) == int(entity_id)), None)
    if account is None:
        raise PermissionError("risk_subject_not_visible_or_not_qualified")
    from server.sli.core.postgres_runtime_pipeline import connect

    try:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """update account_risk_acceptances
                       set status=case when valid_until<=now() then 'expired' else 'superseded' end,
                           revoked_by=%s,revoke_reason=%s
                       where entity_id=%s and risk_key=%s and rule_version=%s and status='active'""",
                    (actor, values["reason"], int(entity_id), values["risk_key"], RISK_RULE_VERSION),
                )
                cur.execute(
                    """insert into account_risk_acceptances(
                           public_id,entity_id,domain_id,risk_key,rule_version,reason,
                           responsible,valid_until,created_by
                       ) values(%s,%s,%s,%s,%s,%s,%s,%s,%s)
                       returning public_id,entity_id,domain_id,risk_key,rule_version,
                                 reason,responsible,status,valid_from,valid_until,created_by,created_at""",
                    (
                        uuid.uuid4(), int(entity_id), int(account["domain_id"]), values["risk_key"],
                        RISK_RULE_VERSION, values["reason"], values["responsible"],
                        values["valid_until_utc"], actor,
                    ),
                )
                row = dict(cur.fetchone())
            conn.commit()
    except Exception as exc:
        if getattr(exc, "sqlstate", None) == "23505":
            raise ValueError("active_risk_acceptance_exists") from exc
        raise
    return {key: value.isoformat() if isinstance(value, datetime) else str(value) if isinstance(value, uuid.UUID) else value for key, value in row.items()}


def create_risk_investigation(
    *,
    entity_id: int,
    domain_ids: list[int] | None,
    risk_key: str,
    actor: str,
) -> dict[str, Any]:
    clean_risk = str(risk_key or "").strip()
    if clean_risk not in RISK_LABELS:
        raise ValueError("invalid_risk_key")
    current = get_users_report(
        domain_ids=domain_ids,
        view="risk",
        risk_key=clean_risk,
        limit=USERS_INPUT_LIMIT,
        max_page_limit=USERS_INPUT_LIMIT,
    )
    if current.get("state") != "available":
        raise PermissionError("risk_evidence_not_actionable")
    account = next((item for item in current["items"] if int(item["entity_id"]) == int(entity_id)), None)
    if account is None:
        raise PermissionError("risk_subject_not_visible_or_not_qualified")
    qualification = next(item for item in account["risks"] if item["risk_key"] == clean_risk and item["qualification"] == "matched")
    case_id = uuid.uuid4()
    clean_actor = str(actor or "unknown")
    title = f"Пользователь: {account['display_name']} — {RISK_LABELS[clean_risk]}"[:300]
    description = f"Передано из отчёта «Пользователи». Учётная запись: {account['natural_key']}. Правило: {clean_risk}, версия {RISK_RULE_VERSION}."
    from server.sli.core.postgres_runtime_pipeline import connect

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """insert into investigations(
                       public_id,title,owner,created_by
                   ) values(%s,%s,%s,%s)
                   returning id,public_id,created_at""",
                (case_id, title, clean_actor, clean_actor),
            )
            case_row = dict(cur.fetchone())
            cur.execute(
                """insert into account_risk_investigation_links(
                       investigation_id,entity_id,domain_id,risk_key,rule_version,
                       qualification_snapshot,created_by
                   ) values(%s,%s,%s,%s,%s,%s::jsonb,%s)""",
                (
                    int(case_row["id"]), int(entity_id), int(account["domain_id"]), clean_risk,
                    RISK_RULE_VERSION, json.dumps(qualification, ensure_ascii=False, default=str), clean_actor,
                ),
            )
            cur.execute(
                """insert into investigation_audit(investigation_id,action,actor,payload)
                   values(%s,'created',%s,%s::jsonb)""",
                (int(case_row["id"]), clean_actor, json.dumps({"subject": "ad_user_risk", "entity_id": int(entity_id), "risk_key": clean_risk, "description": description}, ensure_ascii=False)),
            )
        conn.commit()
    return {
        "case_id": str(case_row["public_id"]),
        "entity_id": int(entity_id),
        "risk_key": clean_risk,
        "created_at": case_row["created_at"].isoformat() if isinstance(case_row.get("created_at"), datetime) else case_row.get("created_at"),
    }


def _decision_actor(actor: str) -> str:
    value = str(actor or "").strip()
    if not value or len(value) > 256:
        raise ValueError("actor_required")
    return value


def revoke_risk_acceptance(*, public_id: str, domain_ids: list[int] | None, actor: str, reason: str = "") -> dict[str, Any]:
    actor = _decision_actor(actor)
    reason = str(reason or "").strip()
    if not 3 <= len(reason) <= 2000:
        raise ValueError("invalid_revocation_reason")
    try:
        acceptance_id = uuid.UUID(str(public_id))
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid_acceptance_id") from exc
    clean_domains = sorted({int(value) for value in (domain_ids or []) if int(value) > 0})
    params: list[Any] = [actor, reason, acceptance_id]
    if domain_ids is not None:
        if not clean_domains:
            raise PermissionError("users_report_field_category_scope_denied")
        params.append(clean_domains)
    from server.sli.core.postgres_runtime_pipeline import connect

    with connect() as conn:
        with conn.cursor() as cur:
            query = """update account_risk_acceptances as acceptance
                       set status='revoked',revoked_at=now(),revoked_by=%s,revoke_reason=%s
                       from entities_v2 as entity
                       where acceptance.entity_id=entity.id and acceptance.public_id=%s
                         and acceptance.status='active' and acceptance.valid_until>now()
                       returning acceptance.public_id,acceptance.status,acceptance.revoked_at,acceptance.revoked_by,acceptance.revoke_reason"""
            if domain_ids is not None:
                query = """update account_risk_acceptances as acceptance
                           set status='revoked',revoked_at=now(),revoked_by=%s,revoke_reason=%s
                           from entities_v2 as entity
                           where acceptance.entity_id=entity.id and acceptance.public_id=%s
                             and acceptance.status='active' and acceptance.valid_until>now()
                             and entity.domain_id=any(%s)
                           returning acceptance.public_id,acceptance.status,acceptance.revoked_at,acceptance.revoked_by,acceptance.revoke_reason"""
            cur.execute(
                query,
                tuple(params),
            )
            row = cur.fetchone()
            if not row:
                raise PermissionError("risk_acceptance_not_visible_or_not_active")
            item = dict(row)
        conn.commit()
    return {key: value.isoformat() if isinstance(value, datetime) else str(value) if isinstance(value, uuid.UUID) else value for key, value in item.items()}
