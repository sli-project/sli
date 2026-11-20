from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from server.sli.core import platform_settings
from server.sli.reports import users_reporting
from server.sli.reports.users_reporting import (
    create_risk_acceptance,
    create_risk_investigation,
    decode_users_cursor,
    encode_users_cursor,
    evaluate_account_risks,
    get_users_report,
    normalize_ou_path,
    render_users_report_csv,
    validate_risk_acceptance_input,
)


@pytest.fixture(autouse=True)
def _installation_report_domain(
    installation_report_domain: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Keep unrelated settings unset while explicitly configuring the report domain.
    monkeypatch.setattr(
        platform_settings, "_stored_row",
        lambda key: {"value": installation_report_domain} if key == "reports.domain_fqdn" else None,
    )
    return None

OBSERVED = datetime(2026, 8, 27, 0, 0, tzinfo=timezone.utc)


def risk_keys(attributes: dict[str, object], *, roles: int = 0) -> set[str]:
    return {
        item["risk_key"]
        for item in evaluate_account_risks(
            attributes,
            observed_at_utc=OBSERVED,
            direct_privilege_count=roles,
        )
        if item["qualification"] == "matched"
    }


def test_eight_users_report_risks_are_qualified_without_treating_disabled_as_risk() -> None:
    attributes = {
        "enabled": True,
        "password_never_expires": True,
        "password_last_set_utc": (OBSERVED - timedelta(days=366)).isoformat(),
        "last_logon_utc": (OBSERVED - timedelta(days=91)).isoformat(),
        "locked_out": True,
        "account_expiration_utc": "2026-08-01T00:00:00Z",
    }
    assert risk_keys(attributes, roles=2) == {
        "password_never_expires",
        "password_older_than_90_days",
        "inactive_over_60_days",
        "account_locked",
        "enabled_account_expired",
        "multiple_direct_privileged_roles",
    }
    assert risk_keys({"enabled": False}) == set()
    assert risk_keys({"enabled": False}, roles=1) == {"disabled_with_direct_privilege"}
    assert risk_keys({"enabled": True, "last_logon_utc": None}) == {
        "enabled_without_last_logon_data"
    }


@pytest.mark.parametrize("field,key,days", [
    ("password_last_set_utc", "password_older_than_90_days", 365),
    ("last_logon_utc", "inactive_over_60_days", 90),
])
def test_time_thresholds_are_strict_and_missing_password_date_is_not_safe(field, key, days) -> None:
    # Rule IDs stay compatible; the owner-approved default policy is 365/90.
    boundary = OBSERVED - timedelta(days=days)
    assert key not in risk_keys({"enabled": True, field: boundary.isoformat()})
    assert key in risk_keys({"enabled": True, field: (boundary - timedelta(seconds=1)).isoformat()})

    result = evaluate_account_risks(
        {"enabled": True, "password_last_set_utc": None, "last_logon_utc": "2026-08-01T00:00:00Z"},
        observed_at_utc=OBSERVED,
        direct_privilege_count=0,
    )
    password_age = next(item for item in result if item["risk_key"] == "password_older_than_90_days")
    assert password_age["qualification"] == "not_evaluated"
    assert password_age["reason"] == "password_last_set_not_observed"


def test_users_risks_publish_the_fact_condition_source_and_rule_version() -> None:
    result = evaluate_account_risks(
        {
            "enabled": True,
            "last_logon_utc": "2026-05-01T00:00:00Z",
            "password_last_set_utc": "2026-01-01T00:00:00Z",
            "password_never_expires": True,
        },
        observed_at_utc=OBSERVED,
        direct_privilege_count=0,
    )
    by_key = {item["risk_key"]: item for item in result}

    assert by_key["inactive_over_60_days"]["expected_condition"] == "Последняя активность не старше 90 дней"
    assert by_key["inactive_over_60_days"]["evidence"]["threshold_days"] == 90
    assert by_key["password_older_than_90_days"]["evidence"]["threshold_days"] == 365
    assert by_key["inactive_over_60_days"]["source_sections"] == ["directory_accounts"]
    assert by_key["inactive_over_60_days"]["evidence"]["last_logon_utc"] == "2026-05-01T00:00:00+00:00"
    assert by_key["inactive_over_60_days"]["rule_version"] == 1
    assert by_key["multiple_direct_privileged_roles"]["source_sections"] == ["privileged_membership"]


def test_service_account_classification_uses_only_explicit_ou_and_name_patterns() -> None:
    assert users_reporting.classify_service_account(
        {"distinguished_name": "CN=backup,OU=ServiceAcc,OU=Users,DC=example,DC=test"},
        natural_key="EXAMPLE\\backup",
    ) == (True, ["ou:ServiceAcc"])
    assert users_reporting.classify_service_account(
        {"sam_account_name": "svc_backup"},
        natural_key="EXAMPLE\\svc_backup",
    ) == (True, ["name:svc"])
    assert users_reporting.classify_service_account(
        {"display_name": "ProxyService", "sam_account_name": "ProxyService"},
        natural_key="EXAMPLE\\ProxyService",
    ) == (True, ["name:service"])
    assert users_reporting.classify_service_account(
        {"display_name": "Иван Иванов", "sam_account_name": "ivanov"},
        natural_key="EXAMPLE\\ivanov",
    ) == (False, [])


def test_directory_path_parser_preserves_escaped_commas_and_standard_containers() -> None:
    assert normalize_ou_path(r"CN=Иванов\, Иван,OU=Сотрудники,OU=Москва,DC=example,DC=local") == "Москва / Сотрудники"
    assert normalize_ou_path("CN=Administrator,CN=Users,DC=example,DC=local") == "Users"
    assert normalize_ou_path("CN=Account,CN=Nested,CN=Users,DC=example,DC=local") == "Users / Nested"
    assert normalize_ou_path(None) == "Расположение не получено"


def test_users_cursor_is_opaque_stable_and_rejects_tampering() -> None:
    value = (7, "Москва / Сотрудники", "иванов", 42)
    cursor = encode_users_cursor(value)
    assert cursor != repr(value)
    assert decode_users_cursor(cursor) == value
    with pytest.raises(ValueError, match="invalid_users_cursor"):
        decode_users_cursor(cursor + "broken")


def test_users_read_model_groups_filters_counts_and_paginates_full_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    accounts = [
        {
            "entity_id": 10,
            "domain_id": 7,
            "display_name": "Анна",
            "natural_key": "EXAMPLE\\anna",
            "observed_at_utc": "2026-08-27T00:00:00Z",
            "attributes": {
                "enabled": True,
                "distinguished_name": "CN=Анна,OU=ServiceAcc,OU=Москва,DC=example,DC=local",
                "department": "ИБ",
                "last_logon_utc": "2026-08-20T00:00:00Z",
                "password_last_set_utc": "2026-08-01T00:00:00Z",
                "password_never_expires": False,
                "locked_out": False,
            },
        },
        {
            "entity_id": 11,
            "domain_id": 7,
            "display_name": "Борис",
            "natural_key": "EXAMPLE\\boris",
            "observed_at_utc": "2026-08-27T00:00:00Z",
            "attributes": {
                "enabled": True,
                "distinguished_name": "CN=Борис,OU=ИТ,OU=Москва,DC=example,DC=local",
                "department": "ИТ",
                "last_logon_utc": None,
                "password_last_set_utc": "2026-01-01T00:00:00Z",
                "password_never_expires": True,
                "locked_out": True,
            },
        },
        {
            "entity_id": 12,
            "domain_id": 7,
            "display_name": "Вера",
            "natural_key": "EXAMPLE\\vera",
            "observed_at_utc": "2026-08-27T00:00:00Z",
            "attributes": {
                "enabled": False,
                "distinguished_name": "CN=Вера,OU=ИБ,OU=Москва,DC=example,DC=local",
                "department": "ИБ",
                "last_logon_utc": "2026-01-01T00:00:00Z",
                "password_last_set_utc": "2026-01-01T00:00:00Z",
                "password_never_expires": False,
                "locked_out": False,
            },
        },
    ]
    privileges = [
        {"source_entity_id": 11, "target_entity_id": 90, "target_name": "Domain Admins", "membership_type": "direct"},
        {"source_entity_id": 11, "target_entity_id": 91, "target_name": "Administrators", "membership_type": "direct"},
        {"source_entity_id": 12, "target_entity_id": 90, "target_name": "Domain Admins", "membership_type": "direct"},
        {"source_entity_id": 10, "target_entity_id": 92, "target_name": "Nested ignored", "membership_type": "nested"},
    ]

    def rows(sql: str, *_args, **_kwargs):
        if "users_report_coverage" in sql:
            return [{"domain_id": 1, "run_status": "completed", "directory_status": "complete", "privilege_status": "complete", "observed_at_utc": OBSERVED}]
        if "users_report_acceptances" in sql:
            return [{"entity_id": 11, "risk_key": "multiple_direct_privileged_roles", "public_id": "accepted-1", "reason": "Проверено владельцем", "responsible": "ivanov", "valid_until": datetime(2026, 9, 1, tzinfo=timezone.utc), "created_by": "auditor", "created_at": OBSERVED}]
        return privileges if "users_report_privileges" in sql else accounts

    monkeypatch.setattr("server.sli.reports.users_reporting.query_rows_bounded", rows)

    first = get_users_report(domain_ids=[7], view="active", limit=1)
    assert first["state"] in {"available", "stale"}
    assert [item["display_name"] for item in first["items"]] == ["Анна"]
    assert first["has_more"] is True
    second = get_users_report(domain_ids=[7], view="active", limit=5, cursor=first["next_cursor"])
    assert [item["display_name"] for item in second["items"]] == ["Борис"]
    assert second["items"][0]["direct_privilege_count"] == 2
    accepted = next(item for item in second["items"][0]["risks"] if item["risk_key"] == "multiple_direct_privileged_roles")
    assert accepted["acceptance"]["public_id"] == "accepted-1"
    assert second["items"][0]["ou_path"] == "Москва / ИТ"
    assert first["summary"]["total_users"] == 3
    assert first["summary"]["active_users"] == 2
    assert first["summary"]["disabled_users"] == 1
    assert first["summary"]["risk_counts"]["enabled_without_last_logon_data"] == 1
    assert first["summary"]["risk_counts"]["disabled_with_direct_privilege"] == 1

    disabled = get_users_report(domain_ids=[7], view="disabled", department="ИБ", limit=5)
    assert [item["entity_id"] for item in disabled["items"]] == [12]
    risk = get_users_report(domain_ids=[7], view="risk", risk_key="account_locked", limit=5)
    assert [item["entity_id"] for item in risk["items"]] == [11]
    privileged = get_users_report(domain_ids=[7], view="privileged", limit=5)
    assert [item["entity_id"] for item in privileged["items"]] == [11, 12]
    service = get_users_report(domain_ids=[7], view="active", account_type="service", limit=5)
    assert [item["entity_id"] for item in service["items"]] == [10]
    assert service["items"][0]["service_account_basis"] == ["ou:ServiceAcc"]


def test_users_read_model_defensively_excludes_non_user_directory_objects(monkeypatch: pytest.MonkeyPatch) -> None:
    observed_sql: list[str] = []

    def rows(sql: str, *_args, **_kwargs):
        observed_sql.append(sql)
        if "users_report_coverage" in sql:
            return [
                {"domain_id": 1, "section_name": "directory_accounts", "run_status": "completed", "section_status": "complete", "record_count": 2, "observed_at_utc": OBSERVED},
                {"domain_id": 1, "section_name": "privileged_membership", "run_status": "completed", "section_status": "complete", "record_count": 0, "observed_at_utc": OBSERVED},
            ]
        if "users_report_privileges" in sql or "users_report_acceptances" in sql:
            return []
        return []

    monkeypatch.setattr("server.sli.reports.users_reporting.query_rows_bounded", rows)
    get_users_report(domain_ids=[1], view="active")

    account_query = next(sql for sql in observed_sql if "entities_v2_active" in sql and "directory_accounts" in sql)
    assert "object_class" in account_query
    assert "='user'" in account_query.replace(" ", "")
    assert "example.test" in account_query
    coverage_query = next(sql for sql in observed_sql if "users_report_coverage" in sql)
    assert "example.test" in coverage_query


def test_users_are_sorted_by_display_name_not_directory_path(monkeypatch: pytest.MonkeyPatch) -> None:
    accounts = [
        {"entity_id": 2, "domain_id": 1, "display_name": "Анна", "natural_key": "EXAMPLE\\anna", "observed_at_utc": OBSERVED, "attributes": {"enabled": True, "object_class": "user", "distinguished_name": "CN=Анна,OU=Я,DC=example,DC=test"}},
        {"entity_id": 1, "domain_id": 1, "display_name": "Борис", "natural_key": "EXAMPLE\\boris", "observed_at_utc": OBSERVED, "attributes": {"enabled": True, "object_class": "user", "distinguished_name": "CN=Борис,OU=А,DC=example,DC=test"}},
    ]

    def rows(sql: str, *_args, **_kwargs):
        if "users_report_coverage" in sql:
            return [
                {"domain_id": 1, "section_name": "directory_accounts", "run_status": "completed", "section_status": "complete", "record_count": 2, "observed_at_utc": OBSERVED},
                {"domain_id": 1, "section_name": "privileged_membership", "run_status": "completed", "section_status": "complete", "record_count": 0, "observed_at_utc": OBSERVED},
            ]
        if "users_report_privileges" in sql or "users_report_acceptances" in sql:
            return []
        return accounts

    monkeypatch.setattr("server.sli.reports.users_reporting.query_rows_bounded", rows)
    result = get_users_report(domain_ids=[1], view="active")

    assert [item["display_name"] for item in result["items"]] == ["Анна", "Борис"]


def test_users_support_allowlisted_sort_with_cursor(monkeypatch: pytest.MonkeyPatch) -> None:
    accounts = [
        {"entity_id": 1, "domain_id": 1, "display_name": "Анна", "natural_key": "anna", "observed_at_utc": OBSERVED, "attributes": {"enabled": True, "object_class": "user", "department": "А", "last_logon_utc": "2026-08-01T00:00:00Z"}},
        {"entity_id": 2, "domain_id": 1, "display_name": "Борис", "natural_key": "boris", "observed_at_utc": OBSERVED, "attributes": {"enabled": True, "object_class": "user", "department": "Б", "last_logon_utc": "2026-08-02T00:00:00Z"}},
    ]

    def rows(sql: str, *_args, **_kwargs):
        if "users_report_coverage" in sql:
            return [
                {"domain_id": 1, "section_name": "directory_accounts", "run_status": "completed", "section_status": "complete", "record_count": 2, "observed_at_utc": OBSERVED},
                {"domain_id": 1, "section_name": "privileged_membership", "run_status": "completed", "section_status": "complete", "record_count": 0, "observed_at_utc": OBSERVED},
            ]
        if "users_report_privileges" in sql or "users_report_acceptances" in sql:
            return []
        return accounts

    monkeypatch.setattr("server.sli.reports.users_reporting.query_rows_bounded", rows)
    first = get_users_report(domain_ids=[1], view="active", sort_by="department", sort_direction="desc", limit=1)
    assert [item["display_name"] for item in first["items"]] == ["Борис"]
    assert first["sort"] == {"field": "department", "direction": "desc"}
    second = get_users_report(domain_ids=[1], view="active", sort_by="department", sort_direction="desc", limit=1, cursor=first["next_cursor"])
    assert [item["display_name"] for item in second["items"]] == ["Анна"]
    with pytest.raises(ValueError, match="invalid_users_sort"):
        get_users_report(domain_ids=[1], sort_by="sql")
    with pytest.raises(ValueError, match="invalid_users_cursor"):
        get_users_report(domain_ids=[1], sort_by="display_name", cursor=first["next_cursor"])


def test_users_report_exposes_partial_directory_collection(monkeypatch: pytest.MonkeyPatch) -> None:
    def rows(sql: str, *_args, **_kwargs):
        if "users_report_coverage" in sql:
            return [
                {"domain_id": 1, "run_status": "completed", "directory_status": "complete", "privilege_status": "complete", "observed_at_utc": OBSERVED},
                {"domain_id": 2, "run_status": "completed", "directory_status": "partial", "privilege_status": "complete", "observed_at_utc": OBSERVED},
            ]
        if "users_report_privileges" in sql:
            return []
        if "users_report_acceptances" in sql:
            return []
        return [{
            "entity_id": 10, "domain_id": 7, "display_name": "Анна", "natural_key": "EXAMPLE\\anna",
            "observed_at_utc": OBSERVED, "attributes": {"enabled": True, "distinguished_name": "CN=Анна,OU=ИБ,DC=example"},
        }]
    monkeypatch.setattr("server.sli.reports.users_reporting.query_rows_bounded", rows)
    result = get_users_report(domain_ids=[7, 8], view="active")
    assert result["state"] == "partial"
    assert result["coverage"]["state"] == "partial"
    assert result["coverage"]["partial_domain_count"] == 1


def test_users_report_combines_latest_runs_per_section(monkeypatch: pytest.MonkeyPatch) -> None:
    def rows(sql: str, *_args, **_kwargs):
        if "users_report_coverage" in sql:
            return [
                {"domain_id": 1, "domain_name": "example.test", "section_name": "directory_accounts", "run_status": "completed", "section_status": "complete", "record_count": 4553, "observed_at_utc": OBSERVED},
                {"domain_id": 1, "domain_name": "example.test", "section_name": "privileged_membership", "run_status": "completed", "section_status": "complete", "record_count": 69, "observed_at_utc": OBSERVED},
            ]
        if "users_report_privileges" in sql or "users_report_acceptances" in sql:
            return []
        return [{
            "entity_id": 10, "domain_id": 1, "display_name": "Анна", "natural_key": "EXAMPLE\\anna",
            "observed_at_utc": OBSERVED, "attributes": {"enabled": True, "distinguished_name": "CN=Анна,OU=ИБ,DC=example"},
        }]

    monkeypatch.setattr("server.sli.reports.users_reporting.query_rows_bounded", rows)

    result = get_users_report(domain_ids=[1], view="active")

    assert result["state"] in {"available", "stale"}
    assert result["coverage"]["state"] in {"complete", "stale"}
    assert result["coverage"]["privilege_state"] == "complete"
    assert result["coverage"]["directory_record_count"] == 4553
    assert result["coverage"]["privilege_record_count"] == 69
    assert len(result["coverage"]["domains"]) == 1
    domain = result["coverage"]["domains"][0]
    assert domain["domain_id"] == 1
    assert domain["domain_name"] == "example.test"
    assert domain["registered"] is True
    assert domain["directory_state"] in {"complete", "stale"}
    assert domain["privilege_state"] in {"complete", "stale"}
    assert domain["directory_record_count"] == 4553
    assert domain["privilege_record_count"] == 69
    assert domain["latest_observed_at_utc"] == OBSERVED.isoformat()
    assert not any("privileged_membership" in item for item in result["limitations"])


def test_users_report_names_unregistered_domains_in_coverage(monkeypatch: pytest.MonkeyPatch) -> None:
    def rows(sql: str, *_args, **_kwargs):
        if "users_report_coverage" in sql:
            return [
                {"domain_id": 2, "domain_name": None, "section_name": "directory_accounts", "run_status": None, "section_status": None, "record_count": None, "observed_at_utc": None},
                {"domain_id": 2, "domain_name": None, "section_name": "privileged_membership", "run_status": None, "section_status": None, "record_count": None, "observed_at_utc": None},
            ]
        if "users_report_privileges" in sql or "users_report_acceptances" in sql:
            return []
        return []

    monkeypatch.setattr("server.sli.reports.users_reporting.query_rows_bounded", rows)

    result = get_users_report(domain_ids=[2], view="active")

    assert result["coverage"]["domains"][0]["registered"] is False
    assert result["coverage"]["domains"][0]["directory_state"] == "not_registered"
    assert result["coverage"]["domains"][0]["privilege_state"] == "not_registered"
    assert result["coverage"]["stale_domain_count"] == 0


def test_users_report_semantic_view_requires_exact_ad_user_link(monkeypatch: pytest.MonkeyPatch) -> None:
    def rows(sql: str, *_args, **_kwargs):
        if "users_report_coverage" in sql:
            return [
                {"domain_id": 1, "section_name": "directory_accounts", "run_status": "completed", "section_status": "complete", "record_count": 2, "observed_at_utc": OBSERVED},
                {"domain_id": 1, "section_name": "privileged_membership", "run_status": "completed", "section_status": "complete", "record_count": 1, "observed_at_utc": OBSERVED},
            ]
        if "users_report_semantic_linked" in sql:
            return [{"finding_id": 88, "entity_id": 10, "display_name": "Анна", "title": "User added to privileged group", "severity": "high", "status": "new", "summary": "Observed exact membership change", "why_it_matters": "Privilege changed", "recommended_action": "Review change", "last_seen_utc": OBSERVED}]

        if "users_report_privileges" in sql or "users_report_acceptances" in sql:
            return []
        return [{"entity_id": 10, "domain_id": 1, "display_name": "Анна", "natural_key": "EXAMPLE\\anna", "observed_at_utc": OBSERVED, "attributes": {"enabled": True}}]

    monkeypatch.setattr("server.sli.reports.users_reporting.query_rows_bounded", rows)

    result = get_users_report(domain_ids=[1], view="semantic")

    assert result["semantic"]["state"] == "available"
    assert result["semantic"]["linked_count"] == 1
    assert result["semantic"]["excludes_unlinked_findings"] is True
    assert result["semantic"]["items"][0]["entity_id"] == 10
    assert result["semantic"]["items"][0]["finding_id"] == 88


def test_users_report_latest_failed_run_is_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    def rows(sql: str, *_args, **_kwargs):
        if "users_report_coverage" in sql:
            return [{"domain_id": 1, "run_status": "failed", "directory_status": None, "privilege_status": None, "observed_at_utc": OBSERVED}]
        return []

    monkeypatch.setattr("server.sli.reports.users_reporting.query_rows_bounded", rows)
    result = get_users_report(domain_ids=[1], view="active")
    assert result["state"] == "unavailable"
    assert result["coverage"]["failed_domain_count"] == 1


def test_users_report_migration_is_additive_registered_and_auditable() -> None:
    migration = Path("config/postgres_migrations/099_users_report_v1.sql").read_text(encoding="utf-8")
    rollback = Path("config/postgres_migrations/099_users_report_v1.rollback.sql").read_text(encoding="utf-8")
    assert "'ad.accounts.users'" in migration
    assert "'ad.users'" in migration
    assert "'/users-report'" in migration
    assert "account_risk_acceptances" in migration
    assert "account_risk_acceptance_audit" in migration
    assert "account_risk_investigation_links" in migration
    assert "account_risks.accept" in migration
    assert "valid_until > valid_from" in migration
    assert "drop table if exists account_risk_acceptance_audit" not in rollback
    assert "drop table if exists account_risk_acceptances" not in rollback
    assert "drop table if exists account_risk_investigation_links" not in rollback
    assert "delete from report_registry_v4 where report_key='ad.users'" in rollback


def test_legacy_users_report_scope_guard_and_update_use_the_same_domain() -> None:
    migration = Path("config/postgres_migrations/100_users_report_domain_scope.sql").read_text(encoding="utf-8")
    compact = "".join(migration.split())
    # Applied SQL stays immutable; the clean-install baseline substitutes its domain.
    domain_filters = compact.split("lower(domain.fqdn)='")[1:]
    assert len(domain_filters) == 2
    assert domain_filters[0].split("'", 1)[0] == domain_filters[1].split("'", 1)[0]
    assert "jsonb_build_object('kind','domain','ids'" in compact
    assert "netbios" not in migration.casefold()


def test_users_report_csv_preserves_evidence_and_direct_privilege_basis() -> None:
    payload = {
        "contract_id": "sli.users-report.v1", "state": "partial", "view": "risk", "filters": {"risk_key": "account_locked"},
        "coverage": {"state": "partial", "latest_observed_at_utc": "2026-08-27T00:00:00Z"},
        "limitations": ["Неполный privilege snapshot"],
        "items": [{
            "display_name": "Иван Иванов",
            "natural_key": r"EXAMPLE\ivanov",
            "enabled": True,
            "service_account": True,
            "service_account_basis": ["ou:ServiceAcc"],
            "ou_path": "Москва / Сотрудники",
            "department": "ИТ",
            "last_logon_utc": None,
            "password_last_set_utc": "2026-01-01T00:00:00Z",
            "direct_privileges": [{"group_name": "Domain Admins", "membership_type": "direct"}],
            "risks": [
                {"risk_key": "account_locked", "label": "Учётная запись заблокирована", "qualification": "matched"},
                {"risk_key": "password_never_expires", "label": "Пароль не истекает", "qualification": "matched"},
            ],
            "observed_at_utc": "2026-08-27T00:00:00Z",
        }],
    }
    text = render_users_report_csv(payload).decode("utf-8-sig")
    assert "Тип строки;Контракт;Состояние отчёта;Состояние покрытия;Выбранный риск;Ограничения;Наблюдалось UTC;Учётная запись" in text
    assert "Сервисная запись;Основание классификации" in text
    assert "data;sli.users-report.v1;partial;partial;account_locked" in text
    assert "Иван Иванов;EXAMPLE\\ivanov;Включена;Москва / Сотрудники;ИТ" in text
    assert "Да;ou:ServiceAcc" in text
    assert "Domain Admins" in text
    assert "Учётная запись заблокирована" in text
    assert "Пароль не истекает" not in text
    empty_text = render_users_report_csv({**payload, "items": []}).decode("utf-8-sig")
    assert "metadata;sli.users-report.v1;partial;partial;account_locked" in empty_text


def test_risk_acceptance_requires_known_rule_reason_owner_and_bounded_expiry() -> None:
    validated = validate_risk_acceptance_input(
        risk_key="account_locked",
        reason="Известная блокировка на время расследования",
        responsible="ivanov",
        valid_until_utc="2026-09-01T00:00:00Z",
        now_utc=OBSERVED,
    )
    assert validated["risk_key"] == "account_locked"
    assert validated["valid_until_utc"].isoformat() == "2026-09-01T00:00:00+00:00"
    for bad in [
        {"risk_key": "unknown", "reason": "достаточная причина", "responsible": "ivanov", "valid_until_utc": "2026-09-01T00:00:00Z"},
        {"risk_key": "account_locked", "reason": "коротко", "responsible": "ivanov", "valid_until_utc": "2026-09-01T00:00:00Z"},
        {"risk_key": "account_locked", "reason": "достаточная причина", "responsible": "", "valid_until_utc": "2026-09-01T00:00:00Z"},
        {"risk_key": "account_locked", "reason": "достаточная причина", "responsible": "ivanov", "valid_until_utc": "2026-08-01T00:00:00Z"},
    ]:
        with pytest.raises(ValueError):
            validate_risk_acceptance_input(**bad, now_utc=OBSERVED)


def test_users_report_csv_neutralizes_spreadsheet_formulas() -> None:
    payload = {
        "contract_id": "sli.users-report.v1", "state": "available", "view": "active", "risk_key": None,
        "coverage": {"state": "complete"}, "limitations": [],
        "items": [{
            "entity_id": 1, "display_name": "\t=WEBSERVICE(\"https://invalid\")", "natural_key": "+cmd",
            "ou_path": "@OU", "department": "-1+1", "title": "", "enabled": True,
            "last_logon_utc": "+cmd", "password_last_set_utc": "@SUM(1)",
            "direct_privileges": [{"group_name": "=1+1", "membership_type": "direct"}],
            "risks": [{"risk_key": "account_locked", "label": "-1+1", "qualification": "matched"}],
        }],
    }
    text = render_users_report_csv(payload).decode("utf-8-sig")
    assert "'\t=WEBSERVICE" in text
    assert ";'+cmd;" in text
    assert ";'@OU;" in text
    assert ";'-1+1;" in text
    assert "'=1+1" in text
    assert "'@SUM(1)" in text


def test_users_report_mutations_reject_unavailable_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("server.sli.reports.users_reporting.get_users_report", lambda **_kwargs: {"state": "unavailable", "items": [{"entity_id": 42}]})
    with pytest.raises(PermissionError, match="risk_evidence_not_actionable"):
        create_risk_acceptance(entity_id=42, domain_ids=[7], risk_key="account_locked", reason="Достаточная причина блокировки", responsible="ivanov", valid_until_utc=(datetime.now(timezone.utc) + timedelta(days=30)).isoformat(), actor="auditor")
    with pytest.raises(PermissionError, match="risk_evidence_not_actionable"):
        create_risk_investigation(entity_id=42, domain_ids=[7], risk_key="account_locked", actor="auditor")


def test_age_risks_require_observation_time_and_privilege_coverage() -> None:
    risks = evaluate_account_risks(
        {"enabled": False, "last_logon_utc": "2026-01-01T00:00:00Z", "password_last_set_utc": "2026-01-01T00:00:00Z"},
        observed_at_utc=None,
        direct_privilege_count=2,
        privilege_evidence_complete=False,
    )
    by_key = {item["risk_key"]: item for item in risks}
    assert by_key["password_older_than_90_days"]["qualification"] == "not_evaluated"
    assert by_key["disabled_with_direct_privilege"]["qualification"] == "not_evaluated"
    assert by_key["multiple_direct_privileged_roles"]["qualification"] == "not_evaluated"


def test_users_v2_exact_projector_hash_matches_active_output_fixture() -> None:
    from server.sli.reports.users_v2_reporting import project_users_v2_exact
    from server.sli.sources.ad_snapshot_projection import canonical_output_sha256

    active_output = {
        "metadata": {"contract_id": "sli.users-report.v2", "saved_snapshot_id": 42},
        "users": [{"id": "user:1", "displayName": "Иван"}],
        "groups": [],
        "collectionErrors": [],
    }
    shadow = project_users_v2_exact(active_output)
    assert shadow is not active_output
    assert canonical_output_sha256(shadow) == canonical_output_sha256(active_output)


def test_users_v2_snapshot_does_not_invent_observation_time(monkeypatch: pytest.MonkeyPatch) -> None:
    from server.sli.reports import users_v2_reporting

    monkeypatch.setattr(users_v2_reporting, "get_users_report", lambda **_kwargs: {
        "state": "empty", "items": [], "coverage": {"latest_observed_at_utc": None}, "limitations": [],
    })
    def forbidden(*_args, **_kwargs):
        pytest.fail("observation-time test must never access a database")

    monkeypatch.setattr("server.sli.core.postgres_runtime_pipeline.connect", forbidden)
    monkeypatch.setattr(users_v2_reporting, "query_rows_bounded", forbidden)
    monkeypatch.setattr(users_v2_reporting, "_directory_user_rows", lambda **_kwargs: [])
    monkeypatch.setattr(users_v2_reporting, "build_directory_projection", lambda **_kwargs: {
        "users": [], "groups": [], "observed_at": None, "collection_status": "not_collected", "sources": [],
    })

    snapshot = users_v2_reporting.build_users_v2_snapshot(domain_ids=[1])

    assert snapshot["metadata"]["observed_at"] is None
    assert snapshot["metadata"]["snapshot_id"] == "live:not-collected"


def test_users_v2_snapshot_pair_marks_current_and_previous_roles(monkeypatch: pytest.MonkeyPatch) -> None:
    from server.sli.reports import users_v2_reporting

    current = {"metadata": {"observed_at": "2026-09-11T10:00:00Z", "label": "Текущий серверный снимок SLI"}, "users": [{}]}
    previous_payload = {"metadata": {"observed_at": "2026-09-10T10:00:00Z", "label": "Текущий серверный снимок SLI"}, "users": [{}]}
    monkeypatch.setattr(users_v2_reporting, "build_users_v2_snapshot", lambda **_kwargs: current)
    monkeypatch.setattr(users_v2_reporting, "query_rows_bounded", lambda *_args, **_kwargs: [{
        "snapshot_id": 7,
        "captured_at_utc": "2026-09-10T10:05:00Z",
        "payload_json": previous_payload,
    }])

    pair = users_v2_reporting.load_users_v2_snapshots(domain_ids=[1])

    assert pair["current"]["metadata"]["comparison_role"] == "current_context"
    assert pair["previous"]["metadata"]["comparison_role"] == "previous_saved_snapshot"
    assert pair["previous"]["metadata"]["captured_at"] == "2026-09-10T10:05:00Z"
