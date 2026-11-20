from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from server.api.routes import reports as routes_reports
from server.sli.reports.computers_v5_reporting import (
    get_computers_v5_report,
    render_computers_v5_csv,
)

ROOT = Path(__file__).resolve().parents[2]
OBSERVED = datetime(2026, 8, 29, 0, 0, tzinfo=timezone.utc)


def _rows(sql: str, *_args, **_kwargs):
    if "computers_v5_coverage" in sql:
        return [{
            "domain_id": 1,
            "domain_name": "example.test",
            "run_status": "completed",
            "section_status": "complete",
            "record_count": 3,
            "observed_at_utc": OBSERVED,
            "run_id": "00000000-0000-0000-0000-000000000029",
        }]
    if "computers_v5_semantic" in sql:
        return [{
            "finding_id": 77,
            "entity_id": 10,
            "display_name": "WS-INACTIVE",
            "title": "Подозрительная последовательность входов",
            "status": "open",
            "summary": "Наблюдалась опубликованная цепочка событий.",
            "why_it_matters": "Требует проверки контекста администратором.",
            "recommended_action": "Открыть доказательства и проверить события.",
            "last_seen_utc": OBSERVED,
        }]
    if "computers_v5_snapshot" in sql:
        return []
    return [
        {
            "entity_id": 10,
            "domain_id": 1,
            "display_name": "WS-INACTIVE",
            "natural_key": "WS-INACTIVE$",
            "observed_at_utc": OBSERVED,
            "attributes": {
                "object_class": "computer",
                "enabled": True,
                "last_logon_utc": "2026-05-01T00:00:00Z",
                "operating_system": "Windows 11 Pro",
                "operating_system_version": "10.0 (26100)",
                "ip_addresses": ["10.42.8.15"],
                "distinguished_name": "CN=WS-INACTIVE,OU=Workstations,DC=example,DC=test",
                "attribute_states": {
                    "enabled": {"state": "present", "source_attribute": "Enabled"},
                    "last_logon_utc": {"state": "present", "source_attribute": "LastLogonDate"},
                    "operating_system": {"state": "present", "source_attribute": "OperatingSystem"},
                },
            },
        },
        {
            "entity_id": 11,
            "domain_id": 1,
            "display_name": "WS-DISABLED-NO-ACTIVITY",
            "natural_key": "WS-DISABLED-NO-ACTIVITY$",
            "observed_at_utc": OBSERVED,
            "attributes": {
                "object_class": "computer",
                "enabled": False,
                "operating_system": "Windows 10 Pro",
                "operating_system_version": "10.0 (19045)",
                "distinguished_name": "CN=WS-DISABLED-NO-ACTIVITY,OU=Disabled,DC=example,DC=test",
                "attribute_states": {
                    "enabled": {"state": "present", "source_attribute": "Enabled"},
                    "last_logon_utc": {"state": "absent_in_source", "source_attribute": "LastLogonDate"},
                    "operating_system": {"state": "present", "source_attribute": "OperatingSystem"},
                },
            },
        },
        {
            "entity_id": 12,
            "domain_id": 1,
            "display_name": "UNKNOWN-AD-STATE",
            "natural_key": "UNKNOWN-AD-STATE$",
            "observed_at_utc": OBSERVED,
            "attributes": {
                "object_class": "computer",
                "distinguished_name": "CN=UNKNOWN-AD-STATE,CN=Computers,DC=example,DC=test",
                "attribute_states": {
                    "enabled": {"state": "absent_in_source", "source_attribute": "Enabled"},
                    "operating_system": {"state": "absent_in_source", "source_attribute": "OperatingSystem"},
                },
            },
        },
    ]


def test_v5_attention_is_enabled_only_but_quality_keeps_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("server.sli.reports.computers_v5_reporting.query_rows_bounded", _rows)

    attention = get_computers_v5_report(domain_ids=[1], view="attention")
    quality = get_computers_v5_report(domain_ids=[1], view="data_quality")
    disabled = get_computers_v5_report(domain_ids=[1], view="workstation_disabled")

    assert attention["contract_id"] == "sli.computers-report.v5"
    assert attention["report_key"] == "ad.computers.v5"
    assert attention["summary"]["attention_population"] == "enabled_ad_records"
    assert [item["display_name"] for item in attention["items"]] == ["WS-INACTIVE"]
    assert attention["items"][0]["reasons"][0]["code"] == "activity_over_60_days"
    assert attention["items"][0]["reasons"][0]["condition"].endswith("60 дней и Enabled = true.")

    assert "WS-DISABLED-NO-ACTIVITY" in {item["display_name"] for item in quality["items"]}
    assert [item["display_name"] for item in disabled["items"]] == ["WS-DISABLED-NO-ACTIVITY"]
    assert quality["summary"]["quality_population"] == "all_ad_records"


def test_v5_does_not_default_missing_enabled_to_true(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("server.sli.reports.computers_v5_reporting.query_rows_bounded", _rows)

    report = get_computers_v5_report(domain_ids=[1], view="all")
    unknown = next(item for item in report["items"] if item["display_name"] == "UNKNOWN-AD-STATE")

    assert unknown["enabled"] is None
    assert unknown["account_state"] == "unknown"
    assert "UNKNOWN-AD-STATE" not in {
        item["display_name"] for item in get_computers_v5_report(domain_ids=[1], view="attention")["items"]
    }


def test_v5_exposes_complete_filter_options_and_server_side_activity_filter(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("server.sli.reports.computers_v5_reporting.query_rows_bounded", _rows)

    report = get_computers_v5_report(domain_ids=[1], view="all", activity="over_60_days")

    assert [item["display_name"] for item in report["items"]] == ["WS-INACTIVE"]
    assert report["filters"]["activity"] == "over_60_days"
    assert report["filter_options"]["operating_systems"] == ["Windows 10 Pro", "Windows 11 Pro"]
    assert "Workstations" in report["filter_options"]["ous"]
    assert report["filter_options"]["ad_site"] == {"state": "not_collected", "values": []}


def test_v5_global_search_includes_observed_ip_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("server.sli.reports.computers_v5_reporting.query_rows_bounded", _rows)

    report = get_computers_v5_report(domain_ids=[1], view="all", q="10.42.8")

    assert [item["display_name"] for item in report["items"]] == ["WS-INACTIVE"]


def test_v5_semantic_is_exact_published_evidence_and_reaches_object(monkeypatch: pytest.MonkeyPatch) -> None:
    observed_sql: list[str] = []

    def rows(sql: str, *args, **kwargs):
        observed_sql.append(sql)
        return _rows(sql, *args, **kwargs)

    monkeypatch.setattr("server.sli.reports.computers_v5_reporting.query_rows_bounded", rows)
    result = get_computers_v5_report(domain_ids=[1], view="semantic")

    assert result["semantic"]["state"] == "available"
    assert result["semantic"]["linked_computer_count"] == 1
    assert result["semantic"]["finding_count"] == 1
    assert result["semantic"]["link_contract"] == "exact_finding_entity_id_to_ad_computer"
    assert result["items"][0]["semantic_findings"][0]["finding_id"] == 77
    assert result["items"][0]["semantic_findings"][0]["why_it_matters"]

    semantic_sql = next(sql for sql in observed_sql if "computers_v5_semantic" in sql)
    normalized = "".join(semantic_sql.split())
    assert "entity_type.value='ad_computer'" in normalized
    assert "is_semantic_finding_published_v1(finding.id)" in semantic_sql
    assert "join finding_entities" in semantic_sql


def test_v5_csv_preserves_evidence_and_neutralizes_formulas(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("server.sli.reports.computers_v5_reporting.query_rows_bounded", _rows)
    report = get_computers_v5_report(domain_ids=[1], view="attention")
    report["items"][0]["display_name"] = "=WEBSERVICE(\"https://invalid\")"

    text = render_computers_v5_csv(report).decode("utf-8-sig")

    assert "sli.computers-report.v5" in text
    assert "'=WEBSERVICE" in text
    assert "activity_over_60_days" in text
    assert "replicated_lastLogonTimestamp_approximation" in text
    assert "exact_finding_entity_id_to_ad_computer" in text


def test_retired_v2_v4_specialized_api_paths_are_removed() -> None:
    handler = SimpleNamespace()

    assert routes_reports.try_handle_get(handler, "/api/v1/reports/ad.computers.v2/computers", {}) is False
    assert routes_reports.try_handle_get(handler, "/api/v1/reports/ad.computers.v4/computers", {}) is False


def test_retired_users_v1_computers_v1_v5_api_paths_are_removed() -> None:
    handler = SimpleNamespace()

    for path in (
        "/api/v1/reports/ad.users/accounts",
        "/api/v1/reports/ad.computers/computers",
        "/api/v1/reports/ad.computers.v5/computers",
    ):
        assert routes_reports.try_handle_get(handler, path, {}) is False
    for path in (
        "/api/v1/reports/ad.users/risk-acceptances",
        "/api/v1/reports/ad.users/investigations",
        "/api/v1/reports/ad.users/risk-acceptances/00000000-0000-0000-0000-000000000000/revoke",
    ):
        assert routes_reports.try_handle_post(handler, path) is False


def test_migration_108_registers_v5_and_retires_v2_v4_without_touching_v1() -> None:
    migration = (ROOT / "config/postgres_migrations/108_computers_report_v5.sql").read_text(encoding="utf-8")
    normalized = "".join(migration.split()).casefold()

    assert "'ad.assets.computers.v5',1" in normalized
    assert "'ad.computers.v5',1,'компьютерыv5'" in normalized
    assert "'target_path','/computers-v5-report'" in normalized
    assert "report_keyin('ad.computers.v2','ad.computers.v4')" in normalized
    assert "status='retired'" in normalized
    assert "deletefromaccess_package_reportswherereport_keyin('ad.computers.v2','ad.computers.v4')" in normalized
    assert "report_key='ad.computers'" not in normalized
    assert "version=106" not in normalized and "version=107" not in normalized
    assert "insertintoschema_migrations(version,name)values(108,'computers_report_v5')" in normalized

    rollback = (ROOT / "config/postgres_migrations/108_computers_report_v5.rollback.sql").read_text(encoding="utf-8").casefold()
    assert "report_key='ad.computers.v5'" in rollback
    assert "version=108" in rollback
