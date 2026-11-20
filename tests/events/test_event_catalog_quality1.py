from __future__ import annotations

import json
from pathlib import Path

import pytest


def _catalog() -> dict:
    return json.loads(Path("config/event_catalog.json").read_text(encoding="utf-8"))


def test_shipped_catalog_passes_schema_event_4016_is_known_and_203_remains_unknown() -> None:
    from server.sli.events.event_catalog import lookup_event_catalog
    from server.sli.events.event_catalog_quality import validate_catalog_data

    result = validate_catalog_data(_catalog())
    assert result == {"valid": True, "entry_count": 105, "errors": []}
    dns_timeout = lookup_event_catalog(
        4016, "DNS Server", "Microsoft-Windows-DNS-Server-Service"
    )
    assert dns_timeout is not None
    assert dns_timeout["severity"] == "medium"
    assert dns_timeout["purpose_tier"] == "important"
    assert lookup_event_catalog(
        203, "Microsoft-Windows-TaskScheduler/Operational", "Microsoft-Windows-TaskScheduler"
    ) is None


def test_service_install_7045_descriptor_is_exact_and_non_causal() -> None:
    catalog = _catalog()
    descriptor = next(
        entry for entry in catalog["entries"]
        if entry.get("channel") == "System" and entry.get("event_id") == 7045
    )

    assert descriptor["provider_name"] == "Service Control Manager"
    assert descriptor["severity"] == "info"
    assert descriptor["purpose_tier"] == "important"
    assert descriptor["noise_class"] == "signal"
    assert descriptor["category"] == "operations"
    assert {
        "event_id", "time_created_utc", "server_id", "event_record_id",
        "source_core_sha256", "source_facts_sha256", "service_name",
        "service_file", "service_account", "service_start_type",
    } <= set(descriptor["required_fields"])
    assert not {"process_user_sid", "process_user_name", "process_user_domain", "process_logon_id"} & set(descriptor["required_fields"])
    assert "time" in descriptor["correlation_absent_reason"]
    assert "name" in descriptor["correlation_absent_reason"]


def test_validator_rejects_duplicate_identity_invalid_enum_and_pivot() -> None:
    from server.sli.events.event_catalog_quality import validate_catalog_data

    entry = {
        "channel": "Fixture", "event_id": 1, "provider_name": "Provider",
        "severity": "medium", "card": {"field_roles": {"object": ["ObjectName"]}},
    }
    result = validate_catalog_data({"entries": [entry, {**entry, "severity": "extreme", "card": {"field_roles": {"magic": ["bad field"]}}}]})
    codes = {item["code"] for item in result["errors"]}
    assert {"duplicate_identity", "invalid_severity", "invalid_field_role", "invalid_field_pivot"} <= codes


def test_infrastructure_category_is_canonical_and_unknown_categories_are_rejected() -> None:
    from server.sli.events.event_catalog_quality import validate_catalog_data
    from server.sli.semantic.event_semantic_contract import normalize_category

    assert normalize_category("infrastructure") == "infrastructure"
    assert normalize_category("infra") == "infrastructure"
    valid = {
        "channel": "Fixture", "event_id": 2, "provider_name": "Provider",
        "severity": "info", "category": "infrastructure", "card": {},
    }
    assert validate_catalog_data({"entries": [valid]})["valid"] is True
    result = validate_catalog_data({"entries": [{**valid, "category": "invented"}]})
    assert "invalid_category" in {item["code"] for item in result["errors"]}


def test_coverage_is_weighted_payload_free_and_unknowns_do_not_block() -> None:
    from server.sli.events.event_catalog_quality import coverage_summary

    rows = [
        {"channel": "Security", "event_id": 4720, "provider_name": "Microsoft-Windows-Security-Auditing", "count": 9},
        {"channel": "Fixture", "event_id": 999999, "provider_name": "Unknown", "count": 1, "message_text": "must-not-leak"},
    ]
    result = coverage_summary(rows, catalog_entries=_catalog()["entries"])
    assert result["groups_covered"] == 1
    assert result["event_coverage_ratio"] == 0.9
    assert result["gap_count"] == 1
    assert "message_text" not in json.dumps(result)


def test_fixture_promotion_requires_field_evidence_and_never_writes() -> None:
    from server.sli.events.event_catalog_quality import propose_catalog_promotion

    fixture = {
        "channel": "Fixture", "event_id": 9001, "provider_name": "Fixture-Provider",
        "verified_semantics": {"severity": "low", "title": "Fixture action", "why": "Verified", "fix": "Inspect", "missing": "Field"},
    }
    with pytest.raises(ValueError, match="field_level_evidence_required"):
        propose_catalog_promotion(_catalog(), fixture)
    proposal = propose_catalog_promotion(_catalog(), {**fixture, "evidence_fields": ["ObjectName"]})
    assert proposal["status"] == "proposed"
    assert proposal["writes_performed"] is False


def test_report_dto_and_search_row_share_exact_machine_semantics() -> None:
    from server.sli.events.event_catalog_quality import build_report_event_dto
    from server.sli.events.event_search import _normalize_search_row

    row = {
        "id": 77, "event_id": 140, "provider_name": "Microsoft-Windows-TaskScheduler",
        "channel": "Microsoft-Windows-TaskScheduler/Operational", "server": "DC1",
        "time_created_utc": "2026-07-18T10:00:00Z",
        "event_data_json": json.dumps({"TaskName": "\\Fixture", "Action": "cmd.exe /c whoami"}),
    }
    search = _normalize_search_row(row)
    report = build_report_event_dto({**row, "event_db_id": 77, "event_data": json.loads(row["event_data_json"])})
    for key in ("final_security_severity", "purpose_tier", "assessment_confidence", "noise_class", "catalog_match", "reasons", "evidence_fields"):
        assert report[key] == search[key]


def test_compiled_catalog_sql_binds_all_catalog_values_and_like_patterns() -> None:
    from server.sli.semantic.event_card_semantics import compile_catalog_risk_sql

    compiled = compile_catalog_risk_sql([140])
    sql = (compiled.case_sql + compiled.matched_sql).lower()
    assert "microsoft-windows" not in sql
    assert "powershell" not in sql
    assert "like ?" in sql
    params = [str(value).lower() for value in (*compiled.case_params, *compiled.matched_params)]
    assert any("microsoft-windows-taskscheduler" in value for value in params)
    assert any("powershell" in value for value in params)
