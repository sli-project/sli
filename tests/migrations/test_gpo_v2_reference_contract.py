from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from server.ad_context.contracts import AdContextContractError, validate_bundle
from server.ad_context.repository import _store_gpo_v2_snapshot
from server.sli.reports.gpo_v2_reporting import (
    attention_reasons,
    build_gpo_v2_payload,
    compare_snapshots,
    filter_snapshot_view,
    load_authorized_snapshot_pair,
)
from server.sli.sources.gpo_v2_source import (
    GpoV2SourceContractError,
    canonical_snapshot,
    validate_snapshot,
)

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


@pytest.mark.parametrize(
    "field",
    [
        "schema_version", "collector_version", "demo", "started_at", "completed_at",
        "observed_at", "collection_status", "domain", "scope", "source_states",
        "gpos", "scopes", "links", "settings", "permissions", "wmi_filters",
        "unresolved_links", "collection_errors",
    ],
)
def test_gpo_v2_snapshot_root_contract(field: str) -> None:
    candidate = production_snapshot()
    assert field in validate_snapshot(candidate)
    candidate.pop(field)
    with pytest.raises(GpoV2SourceContractError, match="root_fields_missing"):
        validate_snapshot(candidate)


def test_gpo_v2_source_rejects_demo_snapshot() -> None:
    with pytest.raises(GpoV2SourceContractError, match="demo_source_snapshot_forbidden"):
        validate_snapshot(CURRENT)


@pytest.mark.parametrize("field", ["started_at", "completed_at", "observed_at"])
@pytest.mark.parametrize("value, code", [
    ("invalid-date", "timestamp_invalid"),
    ("2026-02-30T00:00:00Z", "timestamp_invalid"),
    ("2026-10-04T00:00:00", "timestamp_timezone_required"),
])
def test_gpo_v2_source_strictly_rejects_invalid_snapshot_dates(field, value, code):
    snapshot = production_snapshot()
    snapshot[field] = value
    with pytest.raises(GpoV2SourceContractError, match=f"{code}:{field}"):
        validate_snapshot(snapshot)


def test_gpo_v2_source_coverage_keeps_non_numeric_provenance() -> None:
    snapshot = production_snapshot()
    snapshot["source_states"]["sysvol_gpt"]["coverage"]["query_server"] = "DC2"
    validated = validate_snapshot(snapshot)
    assert validated["source_states"]["sysvol_gpt"]["coverage"]["query_server"] == "DC2"


@pytest.mark.parametrize(
    "case",
    ["closed_vocabulary", "partial", "not_collected", "errors", "unlinked_gate"],
)
def test_gpo_v2_source_semantics(case: str) -> None:
    snapshot = production_snapshot()
    if case == "closed_vocabulary":
        snapshot["source_states"]["links"]["status"] = "safe"
        with pytest.raises(GpoV2SourceContractError, match="source_state_status_invalid"):
            validate_snapshot(snapshot)
        return
    validated = validate_snapshot(snapshot)
    if case == "partial":
        assert filter_snapshot_view(validated, "unlinked")["state"] == "available"
        validated["source_states"]["links"]["status"] = "partial"
        result = filter_snapshot_view(validated, "unlinked")
        assert result["state"] == "not_evaluated"
        assert result["items"] == []
    elif case == "not_collected":
        validated["source_states"]["links"]["status"] = "not_collected"
        assert filter_snapshot_view(validated, "unlinked")["state"] == "not_evaluated"
    elif case == "errors":
        state = validated["source_states"]["gpo_reports"]
        assert {"status", "source", "detail", "error", "coverage"} <= set(state)
    else:
        assert len(filter_snapshot_view(validated, "unlinked")["items"]) == 6


@pytest.mark.parametrize(
    "case",
    [
        "gpo_identity", "gpo_context", "gpo_sides", "gpc", "gpt", "references",
        "per_gpo_states", "unresolved_refs", "scope_entity", "scope_block",
        "link_flags", "link_order", "setting_leaf", "setting_limit", "permission",
        "wmi", "wmi_no_exec",
    ],
)
def test_gpo_v2_entity_contract(case: str) -> None:
    snapshot = validate_snapshot(production_snapshot())
    gpo = snapshot["gpos"][0]
    scope = snapshot["scopes"][0]
    link = snapshot["links"][0]
    setting = snapshot["settings"][0]
    permission = snapshot["permissions"][0]
    wmi = snapshot["wmi_filters"][0]
    checks = {
        "gpo_identity": {"id", "guid", "display_name"} <= set(gpo),
        "gpo_context": {"domain_name", "owner", "description", "creation_time", "modification_time"} <= set(gpo),
        "gpo_sides": {"enabled", "directory_version", "sysvol_version", "settings_count", "source_state"} <= set(gpo["computer"]) and "user" in gpo,
        "gpc": {"distinguished_name", "gpc_file_sys_path", "flags", "version_number"} <= set(gpo["gpc"]),
        "gpt": {"path", "status", "ini_version", "detail"} <= set(gpo["gpt"]),
        "references": {"link_ids", "setting_ids", "permission_ids"} <= set(gpo),
        "per_gpo_states": {"source_states", "collection_errors"} <= set(gpo),
        "unresolved_refs": "unresolved_link_references" in gpo and "unresolved_links" in snapshot,
        "scope_entity": {"id", "scope_type", "distinguished_name", "canonical_path"} <= set(scope),
        "scope_block": "gpo_inheritance_blocked" in scope,
        "link_flags": {"enabled", "enforced", "order", "raw_options"} <= set(link),
        "link_order": link["order_source"] in {"gPLink sequence", "Get-GPInheritance.Order"},
        "setting_leaf": {"side", "extension", "path", "setting_name", "value_display", "source_xml_path", "fingerprint"} <= set(setting),
        "setting_limit": snapshot["source_states"]["gpo_reports"]["status"] in {"observed", "partial"},
        "permission": {"gpo_id", "trustee_name", "trustee_sid", "trustee_type", "permission", "inherited"} <= set(permission),
        "wmi": {"id", "guid", "name", "queries", "used_by_gpo_ids", "source_state"} <= set(wmi),
        "wmi_no_exec": all("result" not in query and "matched" not in query for query in wmi["queries"]),
    }
    assert checks[case]


@pytest.mark.parametrize(
    "reason",
    [
        "source_failed", "version_mismatch", "gpt_unavailable", "unresolved_link",
        "unresolved_wmi", "all_settings_disabled", "unlinked", "empty_enabled_side",
        "stale_modified",
    ],
)
def test_gpo_v2_attention_reason(reason: str) -> None:
    snapshot = validate_snapshot(production_snapshot())
    found = {
        item["code"]
        for gpo in snapshot["gpos"]
        for item in attention_reasons(gpo, snapshot=snapshot, stale_days=30)
    }
    assert reason in found


def test_gpo_v2_attention_explanation_chain() -> None:
    snapshot = validate_snapshot(production_snapshot())
    rows = [reason for gpo in snapshot["gpos"] for reason in attention_reasons(gpo, snapshot=snapshot, stale_days=30)]
    assert rows
    assert all({"code", "rank", "title", "fact", "condition", "qualification", "limitation", "next_action"} <= set(row) for row in rows)


def test_gpo_v2_stale_reason_requires_user_threshold() -> None:
    snapshot = validate_snapshot(production_snapshot())
    assert all(reason["code"] != "stale_modified" for gpo in snapshot["gpos"] for reason in attention_reasons(gpo, snapshot=snapshot, stale_days=0))
    assert any(reason["code"] == "stale_modified" for gpo in snapshot["gpos"] for reason in attention_reasons(gpo, snapshot=snapshot, stale_days=30))


def test_gpo_v2_previous_contract() -> None:
    current = production_snapshot(CURRENT)
    previous = production_snapshot(PREVIOUS)
    result = compare_snapshots(current=current, previous=previous)
    assert result["state"] == "partial"
    assert len(result["items"]) == 11
    assert result["deletion_claim_allowed"] is False


def test_gpo_v2_comparison_does_not_claim_deletion() -> None:
    result = compare_snapshots(current=production_snapshot(CURRENT), previous=production_snapshot(PREVIOUS))
    absent = [item for item in result["items"] if "absent_current" in item["change_kinds"]]
    assert absent
    assert all("удален" not in json.dumps(item, ensure_ascii=False).casefold() for item in absent)


def test_gpo_v2_no_pagination_contract() -> None:
    result = filter_snapshot_view(validate_snapshot(production_snapshot()), "all", limit=1000)
    assert len(result["items"]) == 68
    assert result["has_more"] is False
    limited = filter_snapshot_view(validate_snapshot(production_snapshot()), "all", limit=10)
    assert len(limited["items"]) == 10
    assert limited["state"] == "partial"
    assert limited["has_more"] is True


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


def test_gpo_v2_prohibited_claims() -> None:
    source = (ROOT / "server/sli/plugins/gpo/reports/gpo_v2_reporting.py").read_text(encoding="utf-8")
    assert "not_rsop" in source
    assert "deletion_claim_allowed" in source


def test_gpo_v2_report_is_domain_scoped_on_the_v2_framework() -> None:
    from server.api.routes import reports as routes_reports
    from server.sli.reporting.v2.reports import gpo

    assert gpo.REPORT.access.scope == "domain"
    assert {"identity_basic", "technical", "security", "privilege"} <= gpo.REPORT.access.required_fields
    assert routes_reports.try_handle_get(object(), "/api/v1/reports/ad.gpo.v2/snapshots", {}) is False


def test_gpo_v2_source_snapshot_hash_is_stable() -> None:
    first_text, first_hash = canonical_snapshot(production_snapshot())
    second_text, second_hash = canonical_snapshot(json.loads(first_text))
    assert first_text == second_text
    assert first_hash == second_hash
    assert len(first_hash) == 64


def test_gpo_v2_loads_two_latest_compatible_completed_snapshots() -> None:
    class Cursor:
        def execute(self, sql: str, params: tuple) -> None:
            assert "order by source_completed_at_utc desc" in sql.casefold()
            assert "limit 2" in sql.casefold()
            assert params == ([7],)

        def fetchall(self):
            return []

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    class Connection:
        def cursor(self):
            return Cursor()

    result = load_authorized_snapshot_pair(Connection(), domain_ids=[7])
    assert result["state"] == "not_collected"
    assert result["current"] is None
    assert result["previous"] is None


def test_gpo_v2_api_read_model_materializes_deterministic_attention_reasons() -> None:
    current_snapshot = production_snapshot()
    previous_snapshot = production_snapshot(PREVIOUS)
    payload = build_gpo_v2_payload({"state": "available", "current": current_snapshot, "previous": previous_snapshot})
    assert payload["current"] is not current_snapshot
    by_id = {row["id"]: row for row in payload["current"]["gpos"]}
    for gpo in current_snapshot["gpos"]:
        assert by_id[gpo["id"]]["reasons"] == attention_reasons(gpo, snapshot=current_snapshot)
    assert payload["comparison"]["change_count"] == 11
    assert payload["boundaries"]["not_rsop"] is True


def test_gpo_v2_snapshot_is_versioned_addition_to_shared_collector_bundle() -> None:
    bundle = {
        "schema_version": "ad-context-bundle/v1",
        "source_pack_id": "sli.windows.ad-context",
        "source_pack_version": "0.9.0",
        "run_id": "8a8b93f8-1eaa-40ef-a9e5-5a17f55d7567",
        "mode": "full",
        "domain": {"sid": "S-1-5-21-100-200-300", "dns_name": "example.test"},
        "scope": {
            "search_base": "DC=example,DC=test",
            "privileged_group_sids": [],
            "vpn_group_sids": [],
            "collection_profile": "gpo_governance_v3",
        },
        "observed_at_utc": "2026-08-29T10:30:00Z",
        "sections": [{"name": "gpo_governance", "status": "complete", "record_count": 0, "duration_ms": 1, "error_code": None}],
        "records": [],
        "gpo_v2_snapshot": production_snapshot(),
    }
    normalized = validate_bundle(bundle)
    assert normalized["scope"]["collection_profile"] == "gpo_governance_v3"
    assert normalized["gpo_v2_snapshot"]["schema_version"] == "sli.ad-gpo.snapshot/1.0"

    bundle["scope"]["collection_profile"] = "gpo_governance_v4"
    assert validate_bundle(bundle)["scope"]["collection_profile"] == "gpo_governance_v4"
    missing_v4_snapshot = deepcopy(bundle)
    missing_v4_snapshot.pop("gpo_v2_snapshot")
    with pytest.raises(AdContextContractError, match="gpo_governance_v4 requires"):
        validate_bundle(missing_v4_snapshot)

    bundle["scope"]["collection_profile"] = "gpo_governance_v2"
    with pytest.raises(AdContextContractError, match="requires gpo_governance_v3 or gpo_governance_v4"):
        validate_bundle(bundle)


def test_gpo_v2_snapshot_is_persisted_in_the_same_import_transaction() -> None:
    class Cursor:
        statement = ""
        params = ()

        def execute(self, statement: str, params: tuple) -> None:
            self.statement = statement
            self.params = params

    cursor = Cursor()
    snapshot = production_snapshot()
    _store_gpo_v2_snapshot(
        cursor,
        domain_id=7,
        run_id="8a8b93f8-1eaa-40ef-a9e5-5a17f55d7567",
        snapshot=snapshot,
    )
    assert "insert into gpo_report_v2_source_snapshots" in cursor.statement.casefold()
    assert "on conflict(domain_id,source_run_id) do nothing" in cursor.statement.casefold()
    assert cursor.params[0] == 7
    assert cursor.params[1] == "8a8b93f8-1eaa-40ef-a9e5-5a17f55d7567"
    assert cursor.params[3] == snapshot["collector_version"]
    assert cursor.params[9] == len(snapshot["gpos"])


def test_gpo_v2_search_contract() -> None:
    snapshot = validate_snapshot(production_snapshot())
    selected = snapshot["gpos"][0]
    result = filter_snapshot_view(snapshot, "all", query=selected["guid"])
    assert result["total"] == 1
    assert result["items"][0]["id"] == selected["id"]


def test_gpo_v2_exact_projector_hash_matches_active_current_fixture() -> None:
    from server.sli.reports.gpo_v2_reporting import project_gpo_v2_exact
    from server.sli.sources.ad_snapshot_projection import canonical_output_sha256

    active_output = production_snapshot()
    shadow = project_gpo_v2_exact(active_output)
    assert shadow is not active_output
    assert canonical_output_sha256(shadow) == canonical_output_sha256(active_output)


def test_gpo_v2_report_declaration_keeps_the_reference_capabilities() -> None:
    from server.sli.reporting.v2.reports import gpo

    payload = gpo.REPORT.to_json()
    sortable = {column["key"] for column in payload["columns"] if column.get("sortable")}
    assert {"name", "links", "settings", "modified"} <= sortable
    assert payload["export"] is True
    assert any(column.get("hidden_by_default") for column in payload["columns"])
    assert [column["label"] for column in payload["detail"]["columns"]] == [
        "Основание", "Приоритет проверки", "Причина", "Наблюдалось", "Условие", "Квалификация", "Ограничение", "Безопасный следующий шаг",
    ]
    # Effective access and link inheritance are additive views of ad.gpo.v2;
    # keep every reference view alongside the extensions in GPO_REPORT_PASSPORT.
    assert {view["key"] for view in payload["views"]} == {
        "gpos", "changes", "scopes", "settings", "permissions", "wmi", "quality",
        "filtering", "delegation", "linked_scopes",
    }
    assert {metric_key for metric_key, _ in gpo.GPO_VIEWS} == {"attention", "unverified", "assignment", "all", "linked", "unlinked"}

