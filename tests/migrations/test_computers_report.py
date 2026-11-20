from datetime import datetime, timezone
from pathlib import Path

import pytest

from server.sli.reports import computers_reporting
from server.sli.reports.computers_reporting import (
    classify_computer_type,
    evaluate_computer_activity,
    evaluate_computer_risks,
    get_computers_report,
    render_computers_report_csv,
)


@pytest.fixture(autouse=True)
def _installation_report_domain(installation_report_domain: str) -> None:
    # These checks read applied migrations written for the installation domain (plan 9.1).
    return None

ROOT = Path(__file__).resolve().parents[2]
OBSERVED = datetime(2026, 8, 28, 0, 0, tzinfo=timezone.utc)


def test_computer_type_comes_only_from_observed_operating_system() -> None:
    assert classify_computer_type("Windows Server 2022 Datacenter") == "server"
    assert classify_computer_type("Windows 11 Pro") == "workstation"
    assert classify_computer_type("macOS") == "workstation"
    assert classify_computer_type("pc-linux-gnu") == "workstation"
    assert classify_computer_type(None) == "unknown"
    assert classify_computer_type("unknown") == "unknown"


def test_computer_activity_uses_snapshot_time_and_keeps_unknown_separate() -> None:
    observed = "2026-08-28T00:00:00Z"

    assert evaluate_computer_activity({"enabled": True, "last_logon_utc": "2026-08-01T00:00:00Z"}, observed)["state"] == "recent"
    inactive = evaluate_computer_activity({"enabled": True, "last_logon_utc": "2026-05-01T00:00:00Z"}, observed)
    assert inactive["state"] == "inactive"
    assert inactive["evidence"]["threshold_days"] == 60
    assert inactive["evidence"]["time_semantics"] == "replicated_lastLogonTimestamp_approximation"
    assert evaluate_computer_activity({"enabled": True}, observed)["state"] == "not_evaluated"
    assert evaluate_computer_activity({"enabled": False, "last_logon_utc": "2026-05-01T00:00:00Z"}, observed)["state"] == "not_applicable"


def test_operating_system_support_uses_versioned_official_catalog() -> None:
    evaluate_operating_system_support = computers_reporting.evaluate_operating_system_support
    windows_10 = evaluate_operating_system_support("Windows 10 Pro", "10.0 (19045)")
    assert windows_10["state"] == "ended"
    assert windows_10["support_end_date"] == "2025-10-14"
    assert windows_10["source_url"] == "https://learn.microsoft.com/en-us/lifecycle/announcements/windows-10-end-of-support"
    assert "ESU" in windows_10["applicability_note"]

    ltsc = evaluate_operating_system_support("Windows 10 Корпоративная LTSC", "10.0 (17763)")
    assert ltsc["state"] == "supported"
    assert ltsc["support_end_date"] == "2029-01-09"

    assert evaluate_operating_system_support("Windows 11 Pro", "10.0 (22631)")["state"] == "ended"
    assert evaluate_operating_system_support("Windows 11 Pro", "10.0 (26200)")["state"] == "supported"
    server_2012 = evaluate_operating_system_support("Windows Server 2012 R2 Standard", "6.3 (9600)")
    assert server_2012["state"] == "ended"
    assert "ESU" in server_2012["applicability_note"]
    assert evaluate_operating_system_support("Windows Server 2022 Datacenter", "10.0 (20348)")["state"] == "supported"
    assert evaluate_operating_system_support("macOS", "13.6")["state"] == "not_evaluated"


def test_computer_risks_are_versioned_and_missing_evidence_is_not_safe() -> None:
    risks = evaluate_computer_risks({
        "enabled": True,
        "last_logon_utc": "2026-05-01T00:00:00Z",
        "operating_system": "Windows Server 2008 R2 Standard",
        "technical_inventory_status": "complete",
        "logical_disks": ["C:|1000|50", "D:|2000|1000"],
    }, "2026-08-28T00:00:00Z")
    by_key = {risk["risk_key"]: risk for risk in risks}

    assert set(by_key) == {
        "enabled_inactive_over_60_days",
        "enabled_without_last_logon_data",
        "enabled_without_operating_system",
        "legacy_operating_system_family",
        "technical_inventory_unavailable",
        "low_fixed_disk_free_space",
    }
    assert by_key["legacy_operating_system_family"]["rule_version"] == 2
    assert all(risk["rule_version"] == 1 for key, risk in by_key.items() if key != "legacy_operating_system_family")
    assert by_key["enabled_inactive_over_60_days"]["qualification"] == "matched"
    assert by_key["legacy_operating_system_family"]["qualification"] == "matched"
    assert by_key["legacy_operating_system_family"]["expected_condition"] == "Базовый срок поддержки Microsoft ещё не завершён"
    assert by_key["legacy_operating_system_family"]["source_sections"] == ["directory_accounts", "microsoft_lifecycle_catalog"]
    assert by_key["legacy_operating_system_family"]["evidence"]["source_url"].startswith("https://learn.microsoft.com/")
    assert by_key["low_fixed_disk_free_space"]["qualification"] == "matched"
    assert by_key["enabled_without_last_logon_data"]["qualification"] == "not_matched"

    unknown = {risk["risk_key"]: risk for risk in evaluate_computer_risks({"enabled": True}, None)}
    assert unknown["enabled_inactive_over_60_days"]["qualification"] == "not_evaluated"
    assert unknown["enabled_without_last_logon_data"]["qualification"] == "matched"
    assert unknown["enabled_without_operating_system"]["qualification"] == "matched"
    assert unknown["technical_inventory_unavailable"]["qualification"] == "not_evaluated"
    assert unknown["low_fixed_disk_free_space"]["qualification"] == "not_evaluated"


def test_computers_read_model_counts_full_scope_before_view_and_pagination(monkeypatch: pytest.MonkeyPatch) -> None:
    observed_sql: list[str] = []
    computers = [
        {"entity_id": 10, "domain_id": 1, "display_name": "WS-01", "natural_key": "EXAMPLE\\WS-01$", "observed_at_utc": OBSERVED, "attributes": {"object_class": "computer", "enabled": True, "dns_host_name": "ws-01.example.test", "distinguished_name": "CN=WS-01,OU=Workstations,DC=example,DC=test", "last_logon_utc": "2026-08-20T00:00:00Z", "operating_system": "Windows 11 Pro", "operating_system_version": "10.0"}},
        {"entity_id": 11, "domain_id": 1, "display_name": "SRV-01", "natural_key": "EXAMPLE\\SRV-01$", "observed_at_utc": OBSERVED, "attributes": {"object_class": "computer", "enabled": True, "dns_host_name": "srv-01.example.test", "distinguished_name": "CN=SRV-01,OU=Servers,DC=example,DC=test", "last_logon_utc": "2026-05-01T00:00:00Z", "operating_system": "Windows Server 2008 R2 Standard", "operating_system_version": "6.1", "technical_inventory_status": "complete", "logical_disks": ["C:|1000|50"]}},
        {"entity_id": 12, "domain_id": 1, "display_name": "OLD-01", "natural_key": "EXAMPLE\\OLD-01$", "observed_at_utc": OBSERVED, "attributes": {"object_class": "computer", "enabled": False, "distinguished_name": "CN=OLD-01,CN=Computers,DC=example,DC=test"}},
    ]

    def rows(sql: str, *_args, **_kwargs):
        observed_sql.append(sql)
        if "computers_report_coverage" in sql:
            return [{"domain_id": 1, "domain_name": "example.test", "run_status": "completed", "section_status": "complete", "record_count": 3, "observed_at_utc": OBSERVED}]
        if "computers_report_semantic" in sql:
            return []
        return computers

    monkeypatch.setattr("server.sli.reports.computers_reporting.query_rows_bounded", rows)

    first = get_computers_report(domain_ids=[1], view="workstations", limit=1)
    assert [item["display_name"] for item in first["items"]] == ["WS-01"]
    assert first["summary"]["total_computers"] == 3
    assert first["summary"]["workstations"] == 1
    assert first["summary"]["servers"] == 1
    assert first["summary"]["unknown_type"] == 1
    assert first["summary"]["enabled_recent"] == 1
    assert first["summary"]["enabled_inactive"] == 1
    assert first["summary"]["disabled"] == 1
    assert first["summary"]["unique_computers_with_risks"] == 1
    assert first["summary"]["operating_system_distribution"][0]["operating_system"] == "Windows 11 Pro"

    assert [item["entity_id"] for item in get_computers_report(domain_ids=[1], view="servers")["items"]] == [11]
    assert [item["entity_id"] for item in get_computers_report(domain_ids=[1], view="inactive")["items"]] == [11]
    assert [item["entity_id"] for item in get_computers_report(domain_ids=[1], view="disabled")["items"]] == [12]
    assert [item["entity_id"] for item in get_computers_report(domain_ids=[1], view="risk", risk_key="low_fixed_disk_free_space")["items"]] == [11]

    account_sql = next(sql for sql in observed_sql if "computers_report_accounts" in sql)
    assert "entity_type.value='ad_computer'" in account_sql.replace(" ", "")
    assert "object_class" in account_sql and "='computer'" in account_sql.replace(" ", "")
    assert "example.test" in account_sql


def test_computers_support_allowlisted_sort_with_cursor_and_exact_os_slice(monkeypatch: pytest.MonkeyPatch) -> None:
    computers = [
        {"entity_id": 10, "domain_id": 1, "display_name": "WS-10", "natural_key": "WS-10$", "observed_at_utc": OBSERVED, "attributes": {"object_class": "computer", "enabled": True, "operating_system": "Windows 10 Pro", "operating_system_version": "10.0 (19045)", "distinguished_name": "CN=WS-10,OU=Workstations,DC=example,DC=test"}},
        {"entity_id": 11, "domain_id": 1, "display_name": "WS-11", "natural_key": "WS-11$", "observed_at_utc": OBSERVED, "attributes": {"object_class": "computer", "enabled": True, "operating_system": "Windows 11 Pro", "operating_system_version": "10.0 (26100)", "distinguished_name": "CN=WS-11,OU=Workstations,DC=example,DC=test"}},
        {"entity_id": 12, "domain_id": 1, "display_name": "WS-10-B", "natural_key": "WS-10-B$", "observed_at_utc": OBSERVED, "attributes": {"object_class": "computer", "enabled": False, "operating_system": "Windows 10 Pro", "operating_system_version": "10.0 (19045)", "distinguished_name": "CN=WS-10-B,OU=Workstations,DC=example,DC=test"}},
        {"entity_id": 13, "domain_id": 1, "display_name": "WS-10-OLD", "natural_key": "WS-10-OLD$", "observed_at_utc": OBSERVED, "attributes": {"object_class": "computer", "enabled": True, "operating_system": "Windows 10 Pro", "operating_system_version": "10.0 (19044)", "distinguished_name": "CN=WS-10-OLD,OU=Workstations,DC=example,DC=test"}},
    ]

    def rows(sql: str, *_args, **_kwargs):
        if "computers_report_coverage" in sql:
            return [{"domain_id": 1, "domain_name": "example.test", "run_status": "completed", "section_status": "complete", "record_count": 3, "observed_at_utc": OBSERVED}]
        if "computers_report_semantic" in sql:
            return []
        return computers

    monkeypatch.setattr("server.sli.reports.computers_reporting.query_rows_bounded", rows)
    first = get_computers_report(domain_ids=[1], view="workstations", operating_system="Windows 10 Pro", operating_system_version="10.0 (19045)", sort_by="display_name", sort_direction="desc", limit=1)
    assert [item["display_name"] for item in first["items"]] == ["WS-10-B"]
    assert first["filters"]["os"] == "Windows 10 Pro"
    assert first["filters"]["os_version"] == "10.0 (19045)"
    assert first["sort"] == {"field": "display_name", "direction": "desc"}
    second = get_computers_report(domain_ids=[1], view="workstations", operating_system="Windows 10 Pro", operating_system_version="10.0 (19045)", sort_by="display_name", sort_direction="desc", limit=1, cursor=first["next_cursor"])
    assert [item["display_name"] for item in second["items"]] == ["WS-10"]
    assert second["has_more"] is False
    with pytest.raises(ValueError, match="invalid_computers_sort"):
        get_computers_report(domain_ids=[1], sort_by="raw_sql")
    with pytest.raises(ValueError, match="invalid_computers_cursor"):
        get_computers_report(domain_ids=[1], sort_by="operating_system", cursor=first["next_cursor"])


def test_computers_semantic_view_requires_exact_published_computer_link(monkeypatch: pytest.MonkeyPatch) -> None:
    observed_sql: list[str] = []

    def rows(sql: str, *_args, **_kwargs):
        observed_sql.append(sql)
        if "computers_report_coverage" in sql:
            return [{"domain_id": 1, "domain_name": "example.test", "run_status": "completed", "section_status": "complete", "record_count": 1, "observed_at_utc": OBSERVED}]
        if "computers_report_semantic" in sql:
            return [{"finding_id": 77, "entity_id": 10, "display_name": "WS-01", "title": "Подозрительная цепочка", "severity": "high", "status": "new", "last_seen_utc": OBSERVED}]
        return [{"entity_id": 10, "domain_id": 1, "display_name": "WS-01", "natural_key": "EXAMPLE\\WS-01$", "observed_at_utc": OBSERVED, "attributes": {"object_class": "computer", "enabled": True, "operating_system": "Windows 11 Pro"}}]

    monkeypatch.setattr("server.sli.reports.computers_reporting.query_rows_bounded", rows)
    result = get_computers_report(domain_ids=[1], view="semantic")

    assert result["items"] == []
    assert result["semantic"]["linked_count"] == 1
    assert result["semantic"]["link_contract"] == "exact_finding_entity_id_to_ad_computer"
    semantic_sql = next(sql for sql in observed_sql if "computers_report_semantic" in sql)
    assert "entity_type.value='ad_computer'" in semantic_sql.replace(" ", "")
    assert "is_semantic_finding_published_v1(finding.id)" in semantic_sql
    assert "join finding_entities" in semantic_sql


def test_computers_csv_preserves_qualified_risk_and_neutralizes_formulas() -> None:
    payload = {
        "contract_id": "sli.computers-report.v1", "state": "partial", "view": "risk",
        "filters": {"risk_key": "legacy_operating_system_family"}, "coverage": {"state": "partial"},
        "limitations": ["Неполный снимок"],
        "items": [{"display_name": "=WEBSERVICE(\"https://invalid\")", "natural_key": "+cmd", "dns_host_name": "srv-01.example.test", "computer_type": "server", "enabled": True, "activity_state": "inactive", "ou_path": "Servers", "operating_system": "Windows Server 2008 R2", "operating_system_version": "6.1", "last_logon_utc": "2026-05-01T00:00:00Z", "technical_inventory_status": "complete", "risks": [{"risk_key": "legacy_operating_system_family", "rule_version": 2, "label": "Базовый срок поддержки Microsoft завершён", "qualification": "matched", "expected_condition": "Базовый срок поддержки Microsoft ещё не завершён", "source_sections": ["directory_accounts", "microsoft_lifecycle_catalog"], "evidence": {"support_end_date": "2020-01-14", "source_url": "https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2008-r2"}}], "observed_at_utc": "2026-08-28T00:00:00Z"}],
    }
    text = render_computers_report_csv(payload).decode("utf-8-sig")
    assert "sli.computers-report.v1;partial;partial;legacy_operating_system_family" in text
    assert "'=WEBSERVICE" in text
    assert "'+cmd" in text
    assert "Базовый срок поддержки Microsoft завершён" in text
    assert "Фактическое основание рисков;Условия проверок;Версии правил;Источники проверок;Ссылки источников" in text
    assert "2020-01-14" in text
    assert "Базовый срок поддержки Microsoft ещё не завершён" in text
    assert "v2" in text
    assert "directory_accounts + microsoft_lifecycle_catalog" in text
    assert "https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2008-r2" in text


def test_computers_report_migration_registers_separate_scoped_report() -> None:
    migration = (ROOT / "config/postgres_migrations/101_computers_report_v1.sql").read_text(encoding="utf-8")
    normalized = "".join(migration.split()).casefold()

    assert "'ad.assets.computers',1,'компьютерыactivedirectory','ad_computer'" in normalized
    assert "'ad.computers',1,'компьютеры'" in normalized
    assert "'target_path','/computers-report'" in normalized
    assert "array['identity_basic','technical','security']" in normalized
    assert "array['view','export']" in normalized
    # Historical migration bytes are pinned by the V6 predecessor contract.
    # Its registration guard and package grant must select the same domain;
    # clean installs use the configured domain in the PostgreSQL baseline.
    domain_filters = normalized.split("lower(domain.fqdn)='")[1:]
    assert len(domain_filters) == 2
    assert domain_filters[0].split("'", 1)[0] == domain_filters[1].split("'", 1)[0]
    assert "jsonb_build_object('kind','domain','ids',jsonb_build_array(domain.id))" in normalized
    assert "insertintoschema_migrations(version,name)values(101,'computers_report_v1')" in normalized

    rollback = (ROOT / "config/postgres_migrations/101_computers_report_v1.rollback.sql").read_text(encoding="utf-8").casefold()
    assert "report_key='ad.computers'" in rollback
    assert "dataset_key='ad.assets.computers'" in rollback
    assert "version=101" in rollback
