from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from server.sli.reporting.v2.access import resolve_domain_scope
from server.sli.reporting.v2.definition import QueryContext
from server.sli.reporting.v2.reports import ad_state
from server.sli.reports.active_directory_reporting import (
    ACTIVE_DIRECTORY_RISK_LABELS,
    build_active_directory_controls,
    evaluate_active_directory_risks,
    get_active_directory_report,
    render_active_directory_report_csv,
)

OBSERVED = datetime.now(timezone.utc).replace(microsecond=0)
ROOT = Path(__file__).resolve().parents[2]


def test_active_directory_risks_are_versioned_and_unknown_is_not_safe():
    failed = {item["risk_key"]: item for item in evaluate_active_directory_risks(
        "domain_controller",
        {"advertising_state": "failed", "connectivity_state": "timeout", "services_state": "passed", "sysvol_state": "unavailable", "netlogon_state": "passed", "dns_state": "failed"},
        OBSERVED,
    )}
    assert set(failed) == set(ACTIVE_DIRECTORY_RISK_LABELS)
    assert failed["dc_advertising_failed"]["qualification"] == "matched"
    assert failed["dc_connectivity_failed"]["qualification"] == "not_evaluated"
    assert failed["dc_services_failed"]["qualification"] == "not_matched"
    assert failed["dc_sysvol_failed"]["qualification"] == "not_evaluated"
    assert failed["dns_health_failed"]["qualification"] == "matched"
    assert all(item["rule_version"] == 1 for item in failed.values())

    replication = {item["risk_key"]: item for item in evaluate_active_directory_risks(
        "replication_link",
        {"replication_state": "failed", "consecutive_failure_count": 3, "last_replication_success_utc": "2026-08-27T00:00:00Z"},
        OBSERVED,
    )}
    assert replication["replication_failed"]["qualification"] == "matched"
    assert replication["replication_stale_over_24h"]["qualification"] == "matched"

    domain = {item["risk_key"]: item for item in evaluate_active_directory_risks(
        "domain",
        {"ldap_signing_requirement": "not_required", "ldap_channel_binding_requirement": "unknown"},
        OBSERVED,
    )}
    assert domain["ldap_signing_not_required"]["qualification"] == "matched"
    assert domain["ldap_channel_binding_never"]["qualification"] == "not_evaluated"


def test_active_directory_read_model_counts_full_scope_and_excludes_account_computer_gpo(monkeypatch: pytest.MonkeyPatch):
    observed_sql: list[str] = []
    entities = [
        {"entity_id": 1, "domain_id": 1, "entity_type": "domain", "display_name": "example.test", "natural_key": "domain:example.test", "source_section": "domain_posture", "observed_at_utc": OBSERVED, "attributes": {"forest_name": "example.test", "domain_mode": "Windows2016Domain", "forest_mode": "Windows2016Forest", "ldap_signing_requirement": "not_required", "ldap_channel_binding_requirement": "when_supported"}},
        {"entity_id": 2, "domain_id": 1, "entity_type": "ad_computer", "display_name": "DC1", "natural_key": "dc1", "source_section": "domain_health", "observed_at_utc": OBSERVED, "attributes": {"infrastructure_role": "domain_controller", "dns_host_name": "dc1.example.test", "advertising_state": "passed", "connectivity_state": "passed", "services_state": "passed", "sysvol_state": "passed", "netlogon_state": "passed", "dns_state": "passed"}},
        {"entity_id": 3, "domain_id": 1, "entity_type": "ad_computer", "display_name": "DC2", "natural_key": "dc2", "source_section": "domain_health", "observed_at_utc": OBSERVED, "attributes": {"infrastructure_role": "domain_controller", "dns_host_name": "dc2.example.test", "advertising_state": "failed", "connectivity_state": "passed", "services_state": "passed", "sysvol_state": "passed", "netlogon_state": "passed", "dns_state": "failed"}},
        {"entity_id": 4, "domain_id": 1, "entity_type": "replication_link", "display_name": "DC2 → DC1", "natural_key": "repl1", "source_section": "domain_health", "observed_at_utc": OBSERVED, "attributes": {"source_dc": "DC2", "destination_dc": "DC1", "replication_state": "failed", "consecutive_failure_count": 2, "last_replication_success_utc": "2026-08-27T00:00:00Z"}},
        {"entity_id": 5, "domain_id": 1, "entity_type": "password_policy", "display_name": "Default domain policy", "natural_key": "policy1", "source_section": "domain_posture", "observed_at_utc": OBSERVED, "attributes": {"password_min_length": 14}},
        {"entity_id": 6, "domain_id": 1, "entity_type": "domain_trust", "display_name": "trusted.example.test", "natural_key": "trust1", "source_section": "domain_posture", "observed_at_utc": OBSERVED, "attributes": {"trust_partner": "trusted.example.test", "trust_direction": "BiDirectional"}},
        {"entity_id": 90, "domain_id": 1, "entity_type": "ad_user", "display_name": "must-not-leak", "natural_key": "user", "source_section": "domain_posture", "observed_at_utc": OBSERVED, "attributes": {}},
        {"entity_id": 91, "domain_id": 1, "entity_type": "ad_computer", "display_name": "must-not-leak-pc", "natural_key": "pc", "source_section": "domain_health", "observed_at_utc": OBSERVED, "attributes": {}},
        {"entity_id": 92, "domain_id": 1, "entity_type": "gpo", "display_name": "must-not-leak-gpo", "natural_key": "gpo", "source_section": "domain_posture", "observed_at_utc": OBSERVED, "attributes": {}},
    ]

    def rows(sql: str, *_args, **_kwargs):
        observed_sql.append(sql)
        if "active_directory_report_coverage" in sql:
            return [
                {"domain_id": 1, "domain_name": "example.test", "section_name": "domain_posture", "run_status": "completed", "section_status": "complete", "record_count": 3, "observed_at_utc": OBSERVED},
                {"domain_id": 1, "domain_name": "example.test", "section_name": "domain_health", "run_status": "completed", "section_status": "complete", "record_count": 3, "observed_at_utc": OBSERVED},
            ]
        if "active_directory_report_semantic" in sql:
            return []
        return entities

    monkeypatch.setattr("server.sli.reports.active_directory_reporting.query_rows_bounded", rows)

    result = get_active_directory_report(domain_ids=[1], view="domain_controllers", limit=1)
    assert result["state"] == "available"
    assert [item["display_name"] for item in result["items"]] == ["DC1"]
    assert result["has_more"] is True
    assert result["summary"]["domain_controller_count"] == 2
    assert result["summary"]["domain_controllers_with_failures"] == 1
    assert result["summary"]["replication_link_count"] == 1
    assert result["summary"]["replication_failure_count"] == 1
    assert result["summary"]["dns_failure_count"] == 1
    assert result["summary"]["trust_count"] == 1
    assert result["summary"]["policy_count"] == 1
    assert result["summary"]["unique_infrastructure_entities_with_risks"] == 3
    assert "must-not-leak" not in repr(result)
    assert result["controls"]
    assert {row["category"] for row in result["controls"]} == {"domain_controllers"}
    assert result["summary"]["control_counts"]["failed"] >= 1
    assert result["summary"]["control_counts"]["passed"] >= 1
    assert result["summary"]["control_counts"]["policy_not_defined"] >= 1

    dns = get_active_directory_report(domain_ids=[1], view="dns", limit=50)
    assert {row["control_id"] for row in dns["controls"]} == {"dc.dns"}

    failed_controls = get_active_directory_report(domain_ids=[1], view="risks", limit=50)
    assert failed_controls["controls"]
    assert {row["qualification"] for row in failed_controls["controls"]} == {"failed"}

    semantic = get_active_directory_report(domain_ids=[1], view="semantic", limit=50)
    assert semantic["items"] == []
    assert semantic["controls"] == []
    assert "must-not-leak-pc" not in repr(result)
    assert "must-not-leak-gpo" not in repr(result)

    risk = get_active_directory_report(domain_ids=[1], view="risks", risk_key="replication_failed")
    assert [item["entity_type"] for item in risk["items"]] == ["replication_link"]
    entity_sql = next(sql for sql in observed_sql if "active_directory_report_entities" in sql)
    normalized_sql = "".join(entity_sql.split())
    assert "version.source_section=any(?)" in normalized_sql
    assert "entity_type.value=any(?)" in normalized_sql
    assert "directory_accounts" not in entity_sql
    assert "gpo_governance" not in entity_sql


def test_active_directory_report_exposes_each_checked_parameter_without_false_green(monkeypatch):
    entities = [
        {"entity_id": 1, "domain_id": 1, "entity_type": "domain", "display_name": "example.test", "natural_key": "domain:example.test", "source_section": "domain_posture", "observed_at_utc": OBSERVED, "attributes": {"ldap_signing_requirement": "unknown", "ldap_channel_binding_requirement": "unknown"}},
        {"entity_id": 2, "domain_id": 1, "entity_type": "ad_computer", "display_name": "DC1", "natural_key": "dc1", "source_section": "domain_health", "observed_at_utc": OBSERVED, "attributes": {"infrastructure_role": "domain_controller", "advertising_state": "passed", "dns_state": "passed"}},
        {"entity_id": 4, "domain_id": 1, "entity_type": "password_policy", "display_name": "Default domain policy", "natural_key": "policy1", "source_section": "domain_posture", "observed_at_utc": OBSERVED, "attributes": {"password_min_length": 8}},
        {"entity_id": 90, "domain_id": 1, "entity_type": "ad_user", "display_name": "must-not-leak", "natural_key": "user", "source_section": "domain_posture", "observed_at_utc": OBSERVED, "attributes": {}},
        {"entity_id": 91, "domain_id": 1, "entity_type": "gpo", "display_name": "must-not-leak-gpo", "natural_key": "gpo", "source_section": "domain_posture", "observed_at_utc": OBSERVED, "attributes": {}},
    ]

    def rows(sql, *_args, **_kwargs):
        if "active_directory_report_coverage" in sql:
            return [
                {"domain_id": 1, "domain_name": "example.test", "section_name": "domain_posture", "run_status": "partial", "section_status": "partial", "record_count": 2, "observed_at_utc": OBSERVED},
                {"domain_id": 1, "domain_name": "example.test", "section_name": "domain_health", "run_status": "completed", "section_status": "complete", "record_count": 1, "observed_at_utc": OBSERVED},
            ]
        if "active_directory_report_semantic" in sql:
            return []
        return entities

    monkeypatch.setattr("server.sli.reports.active_directory_reporting.query_rows_bounded", rows)

    result = get_active_directory_report(domain_ids=[1], view="overview", limit=200)
    controls = {(row["control_id"], row["entity_id"]): row for row in result["controls"]}

    advertising = controls[("dc.advertising", 2)]
    assert advertising["label"] == "Advertising контроллера домена"
    assert advertising["actual_value"] == "passed"
    assert advertising["qualification"] == "passed"
    assert advertising["expected_condition"] == "DCDiag Advertising должен завершиться успешно"
    assert advertising["authority"] == "collector_diagnostic"
    assert advertising["source_section"] == "domain_health"

    ldap_signing = controls[("domain.ldap_signing", 1)]
    assert ldap_signing["actual_value"] == "unknown"
    assert ldap_signing["qualification"] == "not_evaluated"
    assert ldap_signing["authority"] == "report_rule_v1"
    assert "не является доказательством" in ldap_signing["basis"]

    password_length = controls[("password.minimum_length", 4)]
    assert password_length["actual_value"] == 8
    assert password_length["qualification"] == "policy_not_defined"
    assert password_length["expected_condition"] == "Требование организации не задано"
    assert password_length["authority"] == "not_defined"
    assert "нормой" not in password_length["basis"].casefold()

    serialized = json.dumps(result["controls"], ensure_ascii=False).casefold()
    assert "gpo" not in serialized
    assert "ad_user" not in serialized
    assert "обычный компьютер" not in serialized


def test_active_directory_control_ledger_covers_all_collected_infrastructure_parameters():
    items = [
        {"entity_id": 1, "entity_type": "domain", "display_name": "example.test", "source_section": "domain_posture", "observed_at_utc": OBSERVED.isoformat(), "attributes": {
            "domain_mode": "Windows2008Domain", "forest_mode": "Windows2008Forest", "forest_name": "example.test", "netbios_name": "EXAMPLE", "distinguished_name": "DC=example,DC=test",
            "pdc_emulator": "dc1", "rid_master": "dc1", "infrastructure_master": "dc1", "schema_master": "dc1", "domain_naming_master": "dc1",
            "recycle_bin_enabled": False, "machine_account_quota": 10, "ldap_signing_requirement": "unknown", "ldap_channel_binding_requirement": "unknown",
        }},
        {"entity_id": 2, "entity_type": "domain_controller", "display_name": "DC1", "source_section": "domain_health", "observed_at_utc": OBSERVED.isoformat(), "attributes": {
            "advertising_state": "passed", "connectivity_state": "passed", "services_state": "passed", "sysvol_state": "passed", "netlogon_state": "passed", "dns_state": "passed",
            "site_name": "Default-First-Site-Name", "dns_host_name": "dc1.example.test", "operating_system": "Windows Server 2012 R2 Standard", "operating_system_version": "6.3 (9600)",
            "is_global_catalog": True, "is_read_only": False, "operation_master_roles": ["PDCEmulator"], "distinguished_name": "CN=DC1,OU=Domain Controllers,DC=example,DC=test",
        }},
        {"entity_id": 3, "entity_type": "replication_link", "display_name": "DC1 -> DC2", "source_section": "domain_health", "observed_at_utc": OBSERVED.isoformat(), "attributes": {
            "source_dc": "DC1", "destination_dc": "DC2", "naming_context": "DC=example,DC=test", "replication_state": "passed", "last_replication_result": 0,
            "consecutive_failure_count": 0, "last_replication_attempt_utc": OBSERVED.isoformat(), "last_replication_success_utc": OBSERVED.isoformat(),
        }},
        {"entity_id": 4, "entity_type": "password_policy", "display_name": "Default domain policy", "source_section": "domain_posture", "observed_at_utc": OBSERVED.isoformat(), "attributes": {
            "password_min_length": 8, "password_history_length": 5, "password_min_age": "1.00:00:00", "password_max_age": "90.00:00:00", "password_properties": [],
            "lockout_threshold": 10, "lockout_duration": "00:30:00", "lockout_observation_window": "00:30:00",
        }},
        {"entity_id": 5, "entity_type": "domain_trust", "display_name": "partner.test", "source_section": "domain_posture", "observed_at_utc": OBSERVED.isoformat(), "attributes": {
            "trust_partner": "partner.test", "trust_flat_name": "PARTNER", "trust_direction": "BiDirectional", "trust_type": "Uplevel", "trust_attributes": 8,
            "distinguished_name": "CN=partner.test,CN=System,DC=example,DC=test",
        }},
    ]

    controls = build_active_directory_controls(items)
    ids = {row["control_id"] for row in controls}

    assert {
        "domain.functional_level", "forest.functional_level",
        "domain.recycle_bin", "domain.machine_account_quota", "domain.ldap_signing", "domain.ldap_channel_binding",
        "dc.advertising", "dc.connectivity", "dc.services", "dc.sysvol", "dc.netlogon", "dc.dns",
        "dc.operating_system", "dc.operating_system_version",
        "replication.state", "replication.result_code", "replication.consecutive_failures", "replication.last_success_freshness",
        "password.minimum_length", "password.history_length", "password.minimum_age", "password.maximum_age", "password.properties",
        "password.lockout_threshold", "password.lockout_duration", "password.lockout_observation_window",
        "trust.direction", "trust.type", "trust.attributes",
    } <= ids
    assert all(row["actual_value"] is not None for row in controls)
    assert {row["qualification"] for row in controls} >= {"passed", "not_evaluated", "policy_not_defined"}
    by_id = {row["control_id"]: row for row in controls}
    assert {
        "dc.dns_host_name", "dc.site", "dc.distinguished_name", "dc.global_catalog", "dc.read_only", "dc.operation_master_roles",
        "replication.endpoints", "replication.naming_context", "replication.last_attempt",
        "domain.forest_name", "domain.netbios_name", "domain.distinguished_name", "domain.pdc_emulator",
        "domain.rid_master", "domain.infrastructure_master", "forest.schema_master", "forest.domain_naming_master",
        "trust.partner", "trust.flat_name", "trust.distinguished_name",
    }.isdisjoint(ids)
    assert by_id["dc.advertising"]["object_context"]["dns_host_name"] == "dc1.example.test"
    assert by_id["dc.advertising"]["object_context"]["site_name"] == "Default-First-Site-Name"
    assert by_id["replication.state"]["object_context"] == {
        "source_dc": "DC1",
        "destination_dc": "DC2",
        "naming_context": "DC=example,DC=test",
        "last_replication_attempt_utc": OBSERVED.isoformat(),
    }
    assert by_id["trust.direction"]["object_context"]["trust_partner"] == "partner.test"
    assert by_id["password.minimum_length"]["qualification"] == "policy_not_defined"


def _context(params: dict[str, str], *, tab: str | None = None, action: str = "view") -> QueryContext:
    return QueryContext(access={}, params=params, domain_ids=[1], action=action, cursor=None, limit=200, timezone="UTC", tab=tab, sort=None, direction="asc")


def test_active_directory_v2_scope_uses_ad_state_grants_and_denies_without_them():
    access = {"reports": [{
        "report_key": "ad.state", "allowed": True, "allowed_actions": ["view"],
        "grants": [{"scope": {"kind": "domain", "ids": [1]}, "field_categories": ["identity_basic", "technical", "security"], "allowed_actions": ["view"]}],
    }]}
    assert resolve_domain_scope(access, ad_state.REPORT.access) == [1]
    access["reports"][0]["allowed"] = False
    with pytest.raises(PermissionError):
        resolve_domain_scope(access, ad_state.REPORT.access)


@pytest.mark.parametrize(
    ("domain_fields", "expected_domain_id", "expected_domain_name"),
    [
        ({}, None, None),
        ({"domain_id": 1, "domain_name": "example.test"}, 1, "example.test"),
    ],
    ids=["missing-domain", "known-domain"],
)
def test_active_directory_v2_rows_are_the_control_ledger_filtered_by_result(
    monkeypatch: pytest.MonkeyPatch,
    domain_fields: dict[str, object],
    expected_domain_id: int | None,
    expected_domain_name: str | None,
):
    calls: list[dict[str, object]] = []
    controls = [
        {"control_id": "a", "entity_id": 7, "entity_name": "DC1", "entity_type": "domain_controller", "label": "DNS", "qualification": "failed", "actual_value": {"source": "DC1", "destination": "DC2"}, "object_context": {"site_name": "HQ"}, "authority": "collector_diagnostic"},
        {"control_id": "b", "entity_id": 7, "entity_name": "DC1", "entity_type": "domain_controller", "label": "GC", "qualification": "passed", "actual_value": True, "object_context": {}, "authority": "report_rule_v1"},
    ]
    payload = {"state": "available", "controls": controls, "summary": {"control_counts": {"failed": 1, "passed": 1}}, "coverage": {}, "items": [{**domain_fields, "entity_id": 7, "display_name": "DC1", "semantic_findings": [{"finding_id": 3, "title": "F"}]}]}
    monkeypatch.setattr(ad_state, "get_active_directory_report", lambda **kwargs: calls.append(kwargs) or payload)

    body = ad_state._query(_context({"view": "replication", "qualification": "failed"}))
    assert calls[0]["domain_ids"] == [1] and calls[0]["view"] == "replication"
    assert [row["row_id"] for row in body["items"]] == ["7:a"]
    assert body["items"][0]["actual_text"] == "DC1 → DC2"
    assert body["items"][0]["context"] == [{
        "code": "site_name", "label": "Сайт", "value": "HQ",
        "presentation_messages": {"label": {
            "code": "reports.v2.ad.infrastructure.context_labels.site_name", "params": {}, "text": "Сайт",
        }},
    }]
    assert body["items"][0]["object_context"] == controls[0]["object_context"]
    assert body["collections"] == {}

    semantic = ad_state._query(_context({}, tab="semantic"))
    assert calls[-1]["view"] == "semantic"
    assert semantic["collections"]["semantic"] == [{
        "finding_id": 3,
        "title": "F",
        "entity_name": "DC1",
        "entity_id": 7,
        "domain_id": expected_domain_id,
        "domain_name": expected_domain_name,
    }]


def test_active_directory_csv_neutralizes_formulas_and_keeps_visible_risk_context():
    body = render_active_directory_report_csv({
        "view": "risks",
        "items": [{
            "entity_type": "domain_controller", "display_name": "=cmd|' /C calc'!A0",
            "observed_at_utc": "2026-08-28T06:00:00+00:00",
            "attributes": {"dns_host_name": "dc1.example.test", "dns_state": "failed"},
            "matched_risk_keys": ["dns_health_failed"],
            "not_evaluated_risk_keys": [],
        }],
    }).decode("utf-8-sig")

    assert "Тип;Объект;Наблюдался;DNS-имя;Состояние DNS;Подтверждённые риски;Не оценено" in body
    assert "'=cmd|' /C calc'!A0" in body
    assert ACTIVE_DIRECTORY_RISK_LABELS["dns_health_failed"] in body


def test_active_directory_csv_exports_the_visible_control_ledger():
    body = render_active_directory_report_csv({
        "view": "policies",
        "controls": [{
            "control_id": "password.minimum_length",
            "label": "=Минимальная длина пароля",
            "entity_id": 4,
            "entity_type": "password_policy",
            "entity_name": "Default domain policy",
            "object_context": {"domain": "example.test"},
            "actual_value": "+8",
            "expected_condition": "Требование организации не задано",
            "qualification": "policy_not_defined",
            "authority": "not_defined",
            "basis": "Фактическое значение без квалификации.",
            "source_section": "domain_posture",
            "observed_at_utc": "2026-08-28T06:00:00+00:00",
        }],
        "items": [],
    }).decode("utf-8-sig")

    assert "Параметр;Объект;Тип объекта;Контекст;Фактическое значение;Ожидаемое условие;Результат;Основание;Источник правила;Секция;Наблюдалось" in body
    assert "'=Минимальная длина пароля" in body
    assert "'+8" in body
    assert "policy_not_defined" in body
    assert "Требование организации не задано" in body
    assert '""domain"": ""example.test""' in body


def test_active_directory_v2_export_uses_the_custom_csv(monkeypatch: pytest.MonkeyPatch):
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(ad_state, "get_active_directory_report", lambda **kwargs: calls.append(kwargs) or {"state": "available", "controls": [{"control_id": "x"}], "has_more": False})
    monkeypatch.setattr(ad_state, "render_active_directory_report_csv", lambda _payload: "csv".encode("utf-8-sig"))

    text, meta = ad_state._export(_context({"view": "trusts"}, action="export"))
    assert calls[0]["max_page_limit"] == 10_000 and calls[0]["view"] == "trusts"
    assert text == "csv" and meta == {"rows": 1, "truncated": False}


def test_active_directory_migration_republishes_existing_report_without_account_or_computer_fields():
    migration = (ROOT / "config/postgres_migrations/102_active_directory_report_v1.sql").read_text(encoding="utf-8")
    rollback = (ROOT / "config/postgres_migrations/102_active_directory_report_v1_rollback.sql").read_text(encoding="utf-8")
    folded = migration.casefold()

    assert "'ad.state'" in migration
    assert "'Active Directory'" in migration
    assert "'/ad-report'" in migration
    assert "'view','export'" in migration.replace(" ", "")
    assert "domain_controller" in migration
    assert "replication_link" in migration
    assert "domain_trust" in migration
    assert "ad_user" not in folded
    assert "ad_computer" not in folded
    assert "gpo" not in folded
    assert "insert into schema_migrations(version,name) values(102" in folded
    assert "Состояние и риски Active Directory" in rollback
