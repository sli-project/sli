from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
CURRENT = json.loads((ROOT / "tests/fixtures/gpo_v2_reference_current.json").read_text(encoding="utf-8"))
PREVIOUS = json.loads((ROOT / "tests/fixtures/gpo_v2_reference_previous.json").read_text(encoding="utf-8"))
MATRIX = json.loads((ROOT / "tests/fixtures/gpo_v2_reference_contract.json").read_text(encoding="utf-8"))


def production_snapshot(source: dict = CURRENT) -> dict:
    result = deepcopy(source)
    result["demo"] = False
    result["demo_notice"] = None
    result["domain"]["dns_name"] = "example.test"
    result["domain"]["dns_root"] = "example.test"
    return result


def test_gpo_v2_contract_matrix_has_stable_denominator_and_non_waivable_gates() -> None:
    clauses = MATRIX["clauses"]
    assert MATRIX["threshold_percent"] == 95
    assert len(clauses) == 88
    assert len({item["id"] for item in clauses}) == len(clauses)
    assert all(item["selectors"] for item in clauses)
    assert sum(bool(item["non_waivable"]) for item in clauses) == 62


def test_gpo_v2_collector_is_read_only() -> None:
    collector = (ROOT / "scripts/ad_context/Export-AdGpoV2Snapshot.ps1").read_text(encoding="utf-8")
    assert "#requires -Version 5.1" in collector
    for forbidden in (
        "New-GPO", "Set-GPO", "Remove-GPO", "New-GPLink", "Set-GPLink",
        "Remove-GPLink", "Set-ADObject", "Remove-ADObject", "Restore-GPO", "Import-GPO",
    ):
        assert forbidden not in collector
    for required in ("Get-GPO -All", "Get-GPOReport", "Get-GPPermission", "Get-ADObject", "Get-ADOrganizationalUnit"):
        assert required in collector


def test_gpo_v2_collector_deduplicates_identical_normalized_setting_leaves() -> None:
    source = (ROOT / "scripts/ad_context/Export-AdGpoV2Snapshot.ps1").read_text(encoding="utf-8-sig")
    assert "$seenSettingFingerprints" in source
    assert "$seenSettingFingerprints.Add($fingerprint)" in source


def test_gpo_v2_collector_preserves_legacy_projection() -> None:
    source = (ROOT / "scripts/ad_context/Export-AdAuditContextBundle.ps1").read_text(encoding="utf-8")
    assert "Merge-SLIGpoGovernanceAttributes" in source
    assert 'section = "gpo_governance"' in source
    assert "gpo_v2_snapshot" in source
    assert "gpo_governance_v3" in source


def test_gpo_v2_collector_writes_bounded_compatibility_sidecar_from_same_reads() -> None:
    source = (ROOT / "scripts/ad_context/Export-AdGpoV2Snapshot.ps1").read_text(encoding="utf-8-sig")
    assert "CompatibilityProjectionPath" in source
    assert 'sli.ad-gpo.compatibility-projection/1.0' in source
    assert "records_sha256" in source
    assert "record_count" in source
    assert "domain_sid" in source
    assert "observed_at_utc" in source
    assert "ConvertFrom-SLIGpoReportXml -XmlText $xmlText" in source
    assert "ConvertFrom-SLIGpoPermissionObjects -PermissionObjects $permissionRows" in source


def test_gpo_v2_migration_registers_sibling_report() -> None:
    migration = (ROOT / "config/postgres_migrations/116_gpo_report_v2_reference.sql").read_text(encoding="utf-8")
    assert "'ad.gpo.v2'" in migration
    # The applied migration is immutable; baseline domain substitution is tested separately.
    assert "'Групповые политики — " in migration
    assert "'/gpo-v2-report'" in migration
    assert "gpo_report_v2_source_snapshots" in migration


def test_gpo_v2_preserves_predecessor_registration() -> None:
    migration = (ROOT / "config/postgres_migrations/116_gpo_report_v2_reference.sql").read_text(encoding="utf-8")
    assert "update report_registry_v4" not in migration.casefold()
    assert "delete from report_registry_v4" not in migration.casefold()
    assert "'ad.gpo.review'" in migration  # source grant only


def test_gpo_v2_snapshot_ingest_role_has_additive_write_grant() -> None:
    migration = (ROOT / "config/postgres_migrations/117_gpo_v2_snapshot_ingest_grant.sql").read_text(encoding="utf-8").casefold()
    assert "grant insert on gpo_report_v2_source_snapshots to adlog_context_worker" in migration
    assert "grant usage, select on sequence gpo_report_v2_source_snapshots_snapshot_id_seq to adlog_context_worker" in migration


def test_gpo_v2_snapshot_ingest_role_can_resolve_idempotent_conflicts() -> None:
    migration = (ROOT / "config/postgres_migrations/118_gpo_v2_snapshot_ingest_select_grant.sql").read_text(encoding="utf-8").casefold()
    assert "grant select on gpo_report_v2_source_snapshots to adlog_context_worker" in migration
