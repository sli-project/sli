from __future__ import annotations

import csv
import importlib
import json
from datetime import datetime, timezone
from io import BytesIO, StringIO
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
OBSERVED = datetime(2026, 8, 29, 0, 0, tzinfo=timezone.utc)


def _rows(sql: str, *_args, **_kwargs):
    if "computers_v6_coverage" in sql:
        return [
            {
                "domain_id": 1,
                "domain_name": "example.test",
                "run_status": "completed",
                "section_status": "complete",
                "record_count": 1,
                "observed_at_utc": OBSERVED,
                "run_id": "00000000-0000-0000-0000-000000000030",
                "source_pack_version": "0.8.0",
            }
        ]
    if "computers_v6_semantic" in sql or "computers_v6_snapshot" in sql:
        return []
    return [
        {
            "entity_id": 10,
            "domain_id": 1,
            "display_name": "WS-REFERENCE",
            "natural_key": "WS-REFERENCE$",
            "observed_at_utc": OBSERVED,
            "identity": {
                "object_guid": "11111111-2222-3333-4444-555555555555",
                "object_sid": "S-1-5-21-1000-1000-1000-1100",
            },
            "attributes": {
                "object_class": "computer",
                "dns_host_name": "ws-reference.example.test",
                "enabled": True,
                "last_logon_utc": "2026-05-01T00:00:00Z",
                "operating_system": "Windows 11 Pro",
                "operating_system_version": "10.0 (26100)",
                "operating_system_service_pack": "",
                "canonical_name": "example.test/Workstations/WS-REFERENCE",
                "distinguished_name": "CN=WS-REFERENCE,OU=Workstations,DC=example,DC=test",
                "location": "Новосибирск",
                "managed_by": "CN=Helpdesk,OU=Groups,DC=example,DC=test",
                "description": "Рабочая станция с очень длинным описанием",
                "password_last_set_utc": "2026-04-01T00:00:00Z",
                "created_utc": "2025-01-01T00:00:00Z",
                "when_changed_utc": "2026-08-28T00:00:00Z",
                "service_principal_names": ["HOST/ws-reference"],
                "trusted_for_delegation": False,
                "trusted_to_auth_for_delegation": False,
                "user_account_control": 4096,
                "ip_addresses": ["10.42.8.15", "2001:db8::15"],
                "attribute_states": {
                    "enabled": {"state": "present", "source_attribute": "Enabled"},
                    "last_logon_utc": {"state": "present", "source_attribute": "LastLogonDate"},
                    "operating_system": {"state": "present", "source_attribute": "OperatingSystem"},
                    "operating_system_version": {"state": "present", "source_attribute": "OperatingSystemVersion"},
                    "operating_system_service_pack": {"state": "absent_in_source", "source_attribute": "OperatingSystemServicePack"},
                    "canonical_name": {"state": "present", "source_attribute": "CanonicalName"},
                    "location": {"state": "present", "source_attribute": "Location"},
                    "managed_by": {"state": "present", "source_attribute": "ManagedBy"},
                    "description": {"state": "present", "source_attribute": "Description"},
                    "password_last_set_utc": {"state": "present", "source_attribute": "PasswordLastSet"},
                    "created_utc": {"state": "present", "source_attribute": "whenCreated"},
                    "when_changed_utc": {"state": "present", "source_attribute": "whenChanged"},
                    "service_principal_names": {"state": "present", "source_attribute": "servicePrincipalName"},
                    "trusted_for_delegation": {"state": "present", "source_attribute": "TrustedForDelegation"},
                    "trusted_to_auth_for_delegation": {"state": "present", "source_attribute": "TrustedToAuthForDelegation"},
                    "user_account_control": {"state": "present", "source_attribute": "userAccountControl"},
                },
            },
        }
    ]


def test_v6_backend_exposes_reference_contract_and_enriched_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_path = ROOT / "server/sli/reports/computers_v6_reporting.py"
    assert module_path.is_file(), "Computers V6 backend module is not implemented"
    module = importlib.import_module("server.sli.reports.computers_v6_reporting")
    monkeypatch.setattr(module, "query_rows_bounded", _rows)

    report = module.get_computers_v6_report(
        domain_ids=[1],
        view="attention",
        threshold_days=30,
    )

    assert report["contract_id"] == "sli.computers-report.v6"
    assert report["report_key"] == "ad.computers.v6"
    assert report["view"] == "attention"
    assert report["threshold"] == {
        "selected_days": 30,
        "allowed_days": [30, 60, 90, 180],
        # PR658 changes the default; an explicit 30-day request still wins.
        "default_days": 90,
        "is_policy": False,
        "is_severity": False,
    }
    assert report["reason_catalog"] == [
        "source_error",
        "unknown_type",
        "stale_activity",
        "unavailable_activity",
        "unknown_os",
        "unsupported_os",
        "unconstrained_delegation",
        "laps_expired",
    ]
    assert report["summary"]["attention_population"] == "all_ad_records"
    assert (
        "Причины источника, типа и ОС оцениваются для всех записей AD; "
        "давность активности — только для включённых учётных записей."
        in report["limitations"]
    )
    assert (
        "Семантические выводы показываются только по точным опубликованным связям объектов "
        "и не изменяют квалификацию AD."
        in report["limitations"]
    )
    assert all("очередь включает только enabled=true" not in item.casefold() for item in report["limitations"])
    item = report["items"][0]
    assert item["display_name"] == "WS-REFERENCE"
    assert item["identity"]["object_guid"] == "11111111-2222-3333-4444-555555555555"
    assert item["identity"]["object_sid"].endswith("-1100")
    assert item["canonical_name"] == "example.test/Workstations/WS-REFERENCE"
    assert item["location"] == "Новосибирск"
    assert item["managed_by"].startswith("CN=Helpdesk")
    assert item["service_principal_names"] == ["HOST/ws-reference"]
    assert item["network"]["addresses"] == ["10.42.8.15", "2001:db8::15"]
    assert item["network"]["ad_site"]["state"] == "not_collected"
    assert item["activity"]["last_logon_timestamp"]["semantics"] == (
        "replicated_lastLogonTimestamp_approximation"
    )
    assert item["activity"]["exact_last_logon"]["state"] == "not_collected"
    assert item["activity"]["dc_event"]["state"] == "not_collected"
    assert [reason["family"] for reason in item["reasons"]] == ["stale_activity"]
    assert item["reasons"][0]["threshold_days"] == 30
    assert item["reasons"][0]["requires_human_review"] is True


def test_v6_object_projection_exposes_typed_source_states_to_frontend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = importlib.import_module("server.sli.reports.computers_v6_reporting")
    monkeypatch.setattr(module, "query_rows_bounded", _rows)

    item = module.get_computers_v6_report(
        domain_ids=[1], view="all", threshold_days=60
    )["items"][0]

    assert item["object_guid"] == item["identity"]["object_guid"]
    assert item["object_sid"] == item["identity"]["object_sid"]
    assert item["ad_site"] == {"state": "not_collected", "value": None}
    assert item["evidence"]["activity_sources"] == {
        "replicated_last_logon": item["activity"]["last_logon_timestamp"],
        "exact_last_logon": item["activity"]["exact_last_logon"],
        "dc_logon_events": item["activity"]["dc_event"],
    }
    assert item["evidence"]["network_sources"] == {
        "dns_addresses": {"state": "observed", "values": item["ip_addresses"]},
        "ad_site": item["ad_site"],
    }


@pytest.mark.parametrize("state", ["failed", "access_denied", "parse_error"])
def test_v6_attention_reasons_use_only_authorized_source_error_states(state: str) -> None:
    module = importlib.import_module("server.sli.reports.computers_v6_reporting")
    field_states = {
        "operating_system": {
            "state": state,
            "source_attribute": "OperatingSystem",
        }
    }
    item = {
        "enabled": True,
        "computer_type": "unknown",
        "operating_system": None,
        "activity": {"age_days": 120},
        "evidence": {"attribute_states": field_states},
        "quality_issues": module._quality_issues(
            {"enabled": True, "last_logon_utc": "2026-05-01T00:00:00Z"},
            field_states,
        ),
    }

    reasons = module._attention_reasons(item, 60)

    assert [reason["family"] for reason in reasons] == [
        "source_error",
        "unknown_type",
        "stale_activity",
        "unknown_os",
    ]


def test_v6_read_error_does_not_invent_reference_source_error_reason() -> None:
    module = importlib.import_module("server.sli.reports.computers_v6_reporting")
    field_states = {"operating_system": {"state": "read_error"}}
    item = {
        "enabled": True,
        "computer_type": "unknown",
        "operating_system": None,
        "activity": {"age_days": 120},
        "evidence": {"attribute_states": field_states},
        "quality_issues": module._quality_issues({}, field_states),
    }

    assert "source_error" not in {
        reason["family"] for reason in module._attention_reasons(item, 60)
    }


def test_v6_optional_absence_does_not_make_every_object_a_quality_issue() -> None:
    module = importlib.import_module("server.sli.reports.computers_v6_reporting")
    attrs = {
        "enabled": True,
        "operating_system": "Windows 11 Pro",
        "last_logon_utc": "2026-08-01T00:00:00Z",
        "location": None,
    }
    states = {
        "enabled": {"state": "present"},
        "operating_system": {"state": "present"},
        "last_logon_utc": {"state": "present"},
        "location": {"state": "absent_in_source"},
    }

    assert module._quality_issues(attrs, states) == []
    states["operating_system"] = {"state": "absent_in_source"}
    assert {issue["code"] for issue in module._quality_issues(attrs, states)} == {
        "no_record"
    }


def test_v6_comparison_detects_reference_fields_and_preserves_uncertainty() -> None:
    module_path = ROOT / "server/sli/reports/computers_v6_reporting.py"
    assert module_path.is_file(), "Computers V6 backend module is not implemented"
    module = importlib.import_module("server.sli.reports.computers_v6_reporting")

    base = {
        "entity_id": 10,
        "object_guid": "11111111-1111-4111-8111-111111111110",
        "display_name": "WS-REFERENCE",
        "enabled": True,
        "ou_path": "Workstations",
        "operating_system": "Windows 11 Pro",
        "operating_system_version": "10.0 (26100)",
        "ip_addresses": ["10.42.8.15", "2001:db8::15"],
        "computer_type": "workstation",
        "managed_by": "CN=Old,OU=Groups,DC=example,DC=test",
        "network": {"ad_site": {"state": "observed", "value": "SITE-A"}},
        "quality_issues": [],
        "semantic_findings": [],
    }
    previous = {
        "contract_id": "sli.computers-report.v6",
        "state": "available",
        "captured_at_utc": "2026-08-29T00:00:00Z",
        "items": [
            base,
            {
                **base,
                "entity_id": 11,
                "object_guid": "11111111-1111-4111-8111-111111111111",
                "display_name": "MISSING",
            },
        ],
    }
    current = {
        "contract_id": "sli.computers-report.v6",
        "state": "partial",
        "captured_at_utc": "2026-08-30T00:00:00Z",
        "items": [
            {
                **base,
                "managed_by": "CN=New,OU=Groups,DC=example,DC=test",
                "network": {
                    "ad_site": {"state": "observed", "value": "SITE-B"}
                },
                "ip_addresses": ["2001:db8::15", "10.42.8.15"],
            },
            {
                **base,
                "entity_id": 12,
                "object_guid": "11111111-1111-4111-8111-111111111112",
                "display_name": "NEW",
            },
        ],
    }

    result = module.compare_computers_v6_snapshots(
        current=current,
        previous=previous,
    )

    types = [row["change_type"] for row in result["items"]]
    assert types == [
        "site_changed",
        "managed_by_changed",
        "missing_current",
        "new_object",
    ]
    assert "ip_changed" not in types
    missing = next(row for row in result["items"] if row["change_type"] == "missing_current")
    assert "причина не установлена" in missing["qualification"]
    assert "не доказывает удаление" in missing["limitation"]
    assert result["deletion_claim_allowed"] is False


def test_v6_snapshot_history_reads_only_v6_storage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = importlib.import_module("server.sli.reports.computers_v6_reporting")
    statements: list[str] = []
    monkeypatch.setattr(
        module,
        "query_rows_bounded",
        lambda sql, *_args, **_kwargs: statements.append(sql) or [],
    )

    result = module._load_snapshot_comparison([1])

    assert result["state"] == "not_collected"
    sql = "\n".join(statements).casefold()
    assert "from computers_report_v6_snapshots" in sql
    assert "computers_report_v5_snapshots" not in sql


def test_v6_comparison_emits_one_quality_row_per_field_difference() -> None:
    module = importlib.import_module("server.sli.reports.computers_v6_reporting")
    base = {
        "entity_id": 10,
        "object_guid": "22222222-2222-4222-8222-222222222222",
        "display_name": "WS-QUALITY",
        "enabled": True,
        "ou_path": "Workstations",
        "operating_system": "Windows 11 Pro",
        "operating_system_version": "10.0",
        "ip_addresses": [],
        "network": {"ad_site": {"state": "not_collected", "value": None}},
        "computer_type": "workstation",
        "managed_by": None,
        "quality_issues": [],
        "semantic_findings": [],
    }
    previous_item = {
        **base,
        "evidence": {"attribute_states": {
            "operating_system": {"state": "present", "source_attribute": "OperatingSystem"},
            "location": {"state": "absent_in_source", "source_attribute": "Location"},
        }},
    }
    current_item = {
        **base,
        "evidence": {"attribute_states": {
            "operating_system": {"state": "read_error", "source_attribute": "OperatingSystem"},
            "location": {"state": "present", "source_attribute": "Location"},
        }},
    }

    result = module.compare_computers_v6_snapshots(
        current={"contract_id": "sli.computers-report.v6", "state": "available", "items": [current_item]},
        previous={"contract_id": "sli.computers-report.v6", "state": "available", "items": [previous_item]},
    )
    quality = [row for row in result["items"] if row["change_type"] == "quality_changed"]

    assert [row["field"] for row in quality] == ["location", "operating_system"]
    assert quality[0]["before"] == "absent_in_source"
    assert quality[0]["after"] == "present"
    assert quality[1]["before"] == "present"
    assert quality[1]["after"] == "read_error"


def test_v6_read_model_filters_ad_site_and_activity_against_selected_threshold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = importlib.import_module("server.sli.reports.computers_v6_reporting")
    def rows_with_site(sql: str, *args, **kwargs):
        rows = _rows(sql, *args, **kwargs)
        if "computers_v6_accounts" not in sql:
            return rows
        return [
            {**row, "attributes": {**row["attributes"], "ad_site": "SITE-A"}}
            for row in rows
        ]

    monkeypatch.setattr(module, "query_rows_bounded", rows_with_site)

    over = module.get_computers_v6_report(
        domain_ids=[1],
        view="all",
        ad_site="SITE-A",
        activity="over_threshold",
        threshold_days=90,
    )
    within = module.get_computers_v6_report(
        domain_ids=[1],
        view="all",
        ad_site="SITE-A",
        activity="within_threshold",
        threshold_days=180,
    )
    wrong_site = module.get_computers_v6_report(
        domain_ids=[1],
        view="all",
        ad_site="SITE-B",
        threshold_days=90,
    )

    assert over["filtered_count"] == 1
    assert within["filtered_count"] == 1
    assert wrong_site["filtered_count"] == 0


@pytest.mark.parametrize(
    "query",
    ["helpdesk", "11111111-2222", "host/ws-reference", "новосибирск"],
)
def test_v6_search_includes_reference_identity_and_context_fields(
    monkeypatch: pytest.MonkeyPatch,
    query: str,
) -> None:
    module = importlib.import_module("server.sli.reports.computers_v6_reporting")
    monkeypatch.setattr(module, "query_rows_bounded", _rows)

    report = module.get_computers_v6_report(
        domain_ids=[1], view="all", q=query, threshold_days=60
    )

    assert report["filtered_count"] == 1


def test_v6_csv_exports_only_selected_allowlisted_columns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = importlib.import_module("server.sli.reports.computers_v6_reporting")
    monkeypatch.setattr(module, "query_rows_bounded", _rows)
    report = module.get_computers_v6_report(
        domain_ids=[1],
        view="all",
        threshold_days=60,
        limit=10_000,
        max_page_limit=10_000,
    )
    report["items"][0]["display_name"] = "=WEBSERVICE(\"https://invalid\")"
    report["items"][0]["network"]["ad_site"] = {
        "state": "observed",
        "value": "SITE-A",
    }

    text = module.render_computers_v6_csv(
        report,
        columns=["display_name", "ad_site", "managed_by"],
    ).decode("utf-8-sig")
    rows = list(csv.reader(StringIO(text), delimiter=";"))

    assert rows[0] == ["Компьютер", "AD Site", "ManagedBy"]
    assert rows[1][0].startswith("'=WEBSERVICE")
    assert rows[1][1] == "SITE-A"
    assert rows[1][2].startswith("CN=Helpdesk")
    assert "Состояние AD" not in text
    with pytest.raises(ValueError, match="invalid_computers_v6_export_column"):
        module.render_computers_v6_csv(report, columns=["raw_secret"])


def test_v6_storage_registration_and_worker_are_strictly_additive() -> None:
    migration_path = (
        ROOT / "config/postgres_migrations/113_computers_report_v6.sql"
    )
    rollback_path = (
        ROOT / "config/postgres_migrations/113_computers_report_v6.rollback.sql"
    )
    worker_path = ROOT / "scripts/runtime/computers_report_v6_snapshot_worker.py"
    assert migration_path.is_file(), "Computers V6 migration is not implemented"
    assert rollback_path.is_file(), "Computers V6 rollback is not implemented"
    assert worker_path.is_file(), "Computers V6 snapshot worker is not implemented"

    migration = "".join(migration_path.read_text(encoding="utf-8").split()).casefold()
    rollback = "".join(rollback_path.read_text(encoding="utf-8").split()).casefold()
    worker = worker_path.read_text(encoding="utf-8")
    registry = (ROOT / "server/sli/ops/runtime_component_registry.py").read_text(
        encoding="utf-8"
    )

    assert "createtableifnotexistscomputers_report_v6_snapshots" in migration
    assert "check(contract_id='sli.computers-report.v6')" in migration
    assert "'ad.assets.computers.v6',1,'компьютерыactivedirectoryv6'" in migration
    assert "'ad.computers.v6',1,'компьютеры—пореференсу'" in migration
    assert "'target_path','/computers-v6-report'" in migration
    assert "package.package_key='ad_auditor'" in migration
    assert "'computers_v6_snapshot'" in migration
    assert "insertintoschema_migrations(version,name)values(113,'computers_report_v6')" in migration
    for protected in (
        "ad.computers'",
        "ad.computers.v2",
        "ad.computers.v4",
        "ad.computers.v5",
        "ad.assets.computers.v2",
        "ad.assets.computers.v4",
        "ad.assets.computers.v5",
    ):
        assert protected not in migration

    assert "droptableifexistscomputers_report_v6_snapshots" in rollback
    assert "report_key='ad.computers.v6'" in rollback
    assert "dataset_key='ad.assets.computers.v6'" in rollback
    assert "version=113" in rollback
    assert "status='published'" not in rollback

    assert "from server.sli.reports.computers_v6_reporting import get_computers_v6_report" in worker
    assert 'WORKER_NAME = "computers_v6_snapshot"' in worker
    assert "SNAPSHOT_INTERVAL_SECONDS = 12 * 60 * 60" in worker
    assert "RETENTION_DAYS = 365" in worker
    assert "computers_report_v6_snapshots" in worker
    assert 'name="computers_v6_snapshot"' in registry
    assert 'script="computers_report_v6_snapshot_worker.py"' in registry


def _v6_access(allowed: bool = True) -> dict:
    return {"reports": [{
        "report_key": "ad.computers.v6", "allowed": allowed, "allowed_actions": ["view", "export"],
        "grants": [{"scope": {"kind": "domain", "ids": [1]}, "field_categories": ["identity_basic", "technical", "security"], "allowed_actions": ["view", "export"]}],
    }]}


def _v6_handler(access: dict, responses: list):
    return SimpleNamespace(
        _access_decision=lambda: access,
        _send_json=lambda payload, status=200: responses.append((payload, int(status))),
        send_response=lambda *_args: responses.append(("status", _args)),
        send_header=lambda *args: responses.append(("header", args)),
        end_headers=lambda: None,
        wfile=BytesIO(),
    )


@pytest.fixture
def _v6_domain_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    from server.sli.access import domain_scope

    def read_domains(_sql, params):
        assert params == ([1], [1])
        return [{"id": 1, "display_name": "example.test"}]

    monkeypatch.setattr(domain_scope, "query_rows_bounded", read_domains)


def test_v6_on_v2_uses_its_own_scope_threshold_site_and_activity(monkeypatch: pytest.MonkeyPatch, _v6_domain_rows) -> None:
    from server.api.routes import reports_v2
    from server.sli.reporting.v2.reports import computers

    calls: list[dict] = []
    monkeypatch.setattr(computers, "get_computers_v6_report", lambda **kwargs: calls.append(kwargs) or {"state": "available", "items": [], "summary": {}})
    responses: list = []
    access = _v6_access()
    handler = _v6_handler(access, responses)
    assert reports_v2.try_handle_get(handler, "/api/v2/reports/ad.computers.v6/data", {
        "view": ["attention"], "threshold_days": ["90"], "limit": ["25"], "ad_site": ["SITE-A"], "activity": ["over_threshold"],
    }) is True
    assert calls[0]["domain_ids"] == [1] and calls[0]["threshold_days"] == 90 and calls[0]["limit"] == 25
    assert calls[0]["ad_site"] == "SITE-A" and calls[0]["activity"] == "over_threshold"
    calls.clear()
    reports_v2.try_handle_get(handler, "/api/v2/reports/ad.computers.v6/data", {"unknown": ["1"]})
    assert calls == [] and responses[-1] == ({"error": "report_parameter_unknown:unknown"}, 400)
    access["reports"][0]["allowed"] = False
    reports_v2.try_handle_get(handler, "/api/v2/reports/ad.computers.v6/data", {})
    assert calls == [] and responses[-1] == ({"error": "report_access_denied"}, 403)


def test_v6_on_v2_export_is_scoped_and_complete(monkeypatch: pytest.MonkeyPatch, _v6_domain_rows) -> None:
    from server.api.routes import reports_v2
    from server.sli.reporting.v2.reports import computers

    calls: list[dict] = []
    monkeypatch.setattr(computers, "get_computers_v6_report", lambda **kwargs: calls.append(kwargs) or {"state": "available", "items": [{"entity_id": 1}], "has_more": False})
    monkeypatch.setattr(computers, "render_computers_v6_csv", lambda payload: "csv".encode("utf-8-sig"))
    responses: list = []
    handler = _v6_handler(_v6_access(), responses)
    assert reports_v2.try_handle_get(handler, "/api/v2/reports/ad.computers.v6/export.csv", {"threshold_days": ["90"]}) is True
    assert calls[0]["domain_ids"] == [1] and calls[0]["limit"] == 10_000 and calls[0]["threshold_days"] == 90
    headers = {args[0]: args[1] for kind, args in responses if kind == "header"}
    assert "sli-ad.computers.v6-complete-1-rows.csv" in headers["Content-Disposition"]
    assert handler.wfile.getvalue() == "csv".encode("utf-8-sig")
