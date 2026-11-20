from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]
BASELINE_PATH = ROOT / "tests/fixtures/ad_collection_unification_baseline.json"


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def _load_baseline() -> dict[str, object]:
    if not BASELINE_PATH.is_file():
        raise FileNotFoundError(f"baseline fixture missing: {BASELINE_PATH}")
    return json.loads(BASELINE_PATH.read_text(encoding="utf-8"))


def _component_facts() -> dict[str, dict[str, object]]:
    tree = ast.parse(_read("server/sli/ops/runtime_component_registry.py"))
    facts: dict[str, dict[str, object]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        if node.func.id != "Component":
            continue
        values = {keyword.arg: ast.literal_eval(keyword.value) for keyword in node.keywords}
        facts[str(values["name"])] = values
    return facts


def _snapshot_config_defaults() -> dict[str, object]:
    wanted = {
        "interval_seconds",
        "deep_interval_seconds",
        "exact_logon_interval_seconds",
    }
    tree = ast.parse(_read("scripts/runtime/ad_context_snapshot_worker.py"))
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "SnapshotConfig":
            return {
                child.target.id: ast.literal_eval(child.value)
                for child in node.body
                if isinstance(child, ast.AnnAssign)
                and isinstance(child.target, ast.Name)
                and child.target.id in wanted
                and child.value is not None
            }
    raise AssertionError("SnapshotConfig source anchor missing")


def _normalized_checksum(payload: dict[str, object]) -> str:
    normalized = dict(payload)
    normalized.pop("normalized_content_sha256", None)
    content = json.dumps(
        normalized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(content).hexdigest()


def test_ad_collection_unification_baseline_contract() -> None:
    baseline = _load_baseline()

    assert set(baseline) == {
        "schema_version",
        "current_facts",
        "target_decisions",
        "normalized_content_sha256",
    }
    assert baseline["normalized_content_sha256"] == _normalized_checksum(baseline)

    current = baseline["current_facts"]
    target = baseline["target_decisions"]
    assert isinstance(current, dict)
    assert isinstance(target, dict)

    anchors = current["active_product_anchors"]
    assert anchors == [
        "ad.state",
        "ad.users.v2",
        "ad.computers.v6",
        "ad.gpo.v2",
        "vpn.audit",
    ]
    migration_anchors = {
        "ad.state": "config/postgres_migrations/102_active_directory_report_v1.sql",
        "ad.users.v2": "config/postgres_migrations/110_users_report_v2_reference.sql",
        "ad.computers.v6": "config/postgres_migrations/115_computers_v6_replaces_v1_v5.sql",
        "ad.gpo.v2": "config/postgres_migrations/116_gpo_report_v2_reference.sql",
        "vpn.audit": "config/postgres_migrations/119_retire_vpn_and_privileged_reports.sql",
    }
    for report_key, path in migration_anchors.items():
        source = _read(path)
        assert f"'{report_key}'" in source
        assert "published" in source

    components = _component_facts()
    workers = current["worker_cadences_seconds"]
    assert isinstance(workers, dict)
    assert workers == {"ad_snapshot_manifest_coordinator": 43200}
    for worker_name, cadence in workers.items():
        assert components[worker_name]["expected_interval_seconds"] == cadence
        assert components[worker_name]["feature_enabled"] is True
        assert components[worker_name]["supervised"] is True

    retained_rollback_entrypoints = current["retained_rollback_entrypoints"]
    assert retained_rollback_entrypoints == {
        "ad_context_snapshot": "ad_context_snapshot_worker.py",
        "ad_snapshot_projection": "ad_snapshot_projection_worker.py",
        "computers_v5_snapshot": "computers_report_v5_snapshot_worker.py",
        "computers_v6_source": "computers_v6_source_worker.py",
        "computers_v6_snapshot": "computers_report_v6_snapshot_worker.py",
        "users_v2_snapshot": "users_report_v2_snapshot_worker.py",
    }
    for worker_name, entrypoint in retained_rollback_entrypoints.items():
        assert components[worker_name]["script"] == entrypoint
        assert components[worker_name]["feature_enabled"] is False
        assert components[worker_name]["supervised"] is False
        assert (ROOT / "scripts/runtime" / entrypoint).is_file()

    from scripts.maintenance import worker_supervisor

    ad_runtime_roots = set(retained_rollback_entrypoints) | set(workers)
    assert {name for name in worker_supervisor.MANAGED if name in ad_runtime_roots} == {
        "ad_snapshot_manifest_coordinator"
    }
    assert {name for name in worker_supervisor.START_ORDER if name in ad_runtime_roots} == {
        "ad_snapshot_manifest_coordinator"
    }

    snapshot_defaults = _snapshot_config_defaults()
    assert current["ad_context_section_cadences_seconds"] == {
        "light": snapshot_defaults["interval_seconds"],
        "deep": snapshot_defaults["deep_interval_seconds"],
        "exact_logon": snapshot_defaults["exact_logon_interval_seconds"],
    } == {"light": 1800, "deep": 21600, "exact_logon": 86400}

    assert current["v5_runtime"] == {
        "feature_enabled": components["computers_v5_snapshot"]["feature_enabled"],
        "supervised": components["computers_v5_snapshot"]["supervised"],
        "entrypoint": components["computers_v5_snapshot"]["script"],
    }
    assert current["v5_runtime"] == {
        "feature_enabled": False,
        "supervised": False,
        "entrypoint": "computers_report_v5_snapshot_worker.py",
    }
    assert (ROOT / "scripts/runtime/computers_report_v5_snapshot_worker.py").is_file()
    assert (ROOT / "server/sli/reports/computers_v5_reporting.py").is_file()
    assert (ROOT / "config/postgres_migrations/108_computers_report_v5.sql").is_file()
    assert (ROOT / "config/postgres_migrations/109_computers_v5_snapshot_heartbeat.sql").is_file()
    assert (ROOT / "config/postgres_migrations/115_computers_v6_replaces_v1_v5.rollback.sql").is_file()

    exporter = _read("scripts/ad_context/Export-AdAuditContextBundle.ps1")
    legacy_anchor = 'if ($requestedSections -contains "gpo_governance")'
    v2_anchor = 'if ($CollectionProfile -eq "gpo_governance_v3")'
    assert legacy_anchor in exporter
    assert v2_anchor in exporter
    assert exporter.index(legacy_anchor) < exporter.index(v2_anchor)
    assert '"Export-AdGpoV2Snapshot.ps1"' in exporter
    assert '"gpo_v2_snapshot"' in exporter

    adapters = _read("server/source_packs/adapters.py")
    source_pack = json.loads(_read("config/source_packs/ad_context.json"))
    assert '"gpo_governance": "gpo_governance_v4"' in adapters
    assert "gpo_governance" in source_pack["sections"]

    legacy_projection = current["legacy_gpo_governance_projection"]
    assert legacy_projection == {
        "source_section": "gpo_governance",
        "dataset_key": "ad.gpo.governance",
        "report_key": "ad.gpo.review",
        "internal_consumers": [
            "server/sli/sources/plugin_compatibility_registration.py",
            "server/sli/reporting/reporting_v4.py",
        ],
    }
    compatibility_registration = _read("server/sli/sources/plugin_compatibility_registration.py")
    assert '"primary_source_sections": ("gpo_governance",)' in compatibility_registration
    assert '"dataset_key": "ad.gpo.governance"' in compatibility_registration
    assert '"report_key": "ad.gpo.review"' in compatibility_registration
    reporting = _read("server/sli/reporting/reporting_v4.py")
    assert 'elif dataset_key == "ad.gpo.governance":' in reporting
    assert "version.source_section='gpo_governance'" in reporting

    migration_115 = _read("config/postgres_migrations/115_computers_v6_replaces_v1_v5.sql")
    assert "where report_key in ('ad.computers','ad.computers.v5')" in migration_115
    assert "set status='retired'" in migration_115
    migration_120 = _read("config/postgres_migrations/120_gpo_v2_replaces_legacy_catalog.sql")
    assert "where report_key='ad.gpo.review'" in migration_120
    assert "set status='retired'" in migration_120

    assert target["v5"] == {
        "known": True,
        "feature_enabled_target": False,
        "supervised_target": False,
        "entrypoint_retained": True,
    }
    assert target["gpo"] == {
        "legacy_projection_retained": True,
        "single_v2_acquisition_target": True,
    }
    assert target["scope_guard"] == {
        "radius_untouched": True,
        "semantic_untouched": True,
        "product_untouched": True,
        "ui_untouched": True,
    }
    assert target["active_snapshot_storage"] == {
        "contracts": ["ad.users.v2", "ad.computers.v6", "ad.gpo.v2"],
        "cutover_before_s10": False,
    }
    assert target["manifest_foundation"] == {
        "contract_version": "sli.ad-snapshot-manifest/1.0",
        "migration_name": "121_ad_snapshot_manifest_foundation",
        "cadence_seconds": 43200,
        "source_only": True,
        "report_cutover": False,
        "production_apply": False,
    }
    assert sorted(path.name for path in (ROOT / "config/postgres_migrations").glob("121*")) == [
        "121_ad_snapshot_manifest_foundation.rollback.sql",
        "121_ad_snapshot_manifest_foundation.sql",
    ]
    manifest_component = components["ad_snapshot_manifest_coordinator"]
    assert manifest_component["expected_interval_seconds"] == 43200
    assert manifest_component["feature_enabled"] is True
    assert manifest_component["supervised"] is True
    assert manifest_component["script"] == "ad_snapshot_manifest_coordinator_worker.py"
    for legacy_source in ("ad_context_snapshot", "computers_v6_source"):
        assert components[legacy_source]["feature_enabled"] is False
        assert components[legacy_source]["supervised"] is False

    v5_decision = json.dumps(target["v5"], sort_keys=True).casefold()
    gpo_decision = json.dumps(target["gpo"], sort_keys=True).casefold()
    storage_decision = json.dumps(target["active_snapshot_storage"], sort_keys=True).casefold()
    for contradiction in ("retire", "delete", "remove"):
        assert contradiction not in v5_decision
        assert contradiction not in gpo_decision
    for contradiction in ("cutover_before_s10\": true", "switch", "replace"):
        assert contradiction not in storage_decision


def test_p2_gpo_v4_uses_one_v2_acquisition_and_keeps_v3_rollback() -> None:
    exporter = _read("scripts/ad_context/Export-AdAuditContextBundle.ps1")
    collector = _read("scripts/ad_context/Export-AdGpoV2Snapshot.ps1")
    adapters = _read("server/source_packs/adapters.py")
    source_pack = json.loads(_read("config/source_packs/ad_context.json"))

    assert '"gpo_governance_v4"' in exporter
    v4 = exporter.split('if ($CollectionProfile -eq "gpo_governance_v4")', 1)[1]
    v4 = v4.split('if ($requestedSections -contains "gpo_governance")', 1)[0]
    assert v4.count("Export-AdGpoV2Snapshot.ps1") == 1
    assert "Invoke-SLIBoundedGpoReportRead" not in v4
    assert "Invoke-SLIBoundedGpoPermissionRead" not in v4
    assert 'sli.ad-gpo.compatibility-projection/1.0' in collector
    assert "ConvertFrom-SLIGpoReportXml -XmlText $xmlText" in collector
    assert "ConvertFrom-SLIGpoPermissionObjects -PermissionObjects $permissionRows" in collector
    assert "ObjectGUID" in collector
    assert 'if ($CollectionProfile -eq "gpo_governance_v3")' in exporter
    assert '"gpo_governance": "gpo_governance_v4"' in adapters
    assert source_pack["version"] == "0.10.0"
    for fail_closed_anchor in (
        "did not produce both required projections",
        "compatibility projection domain SID mismatch",
        "compatibility projection count is invalid or unbounded",
        "compatibility projection hash mismatch",
        "compatibility projection record boundary mismatch",
    ):
        assert fail_closed_anchor.casefold() in v4.casefold()


def test_p4_profile_has_one_bounded_base_query_per_type_and_reuses_rows() -> None:
    exporter = _read("scripts/ad_context/Export-AdAuditContextBundle.ps1")
    assert '"ad_snapshot_base_v1"' in exporter
    profile = exporter.split('if ($CollectionProfile -eq "ad_snapshot_base_v1")', 1)[1]
    profile = profile.split("# P4-END-AD-SNAPSHOT-BASE-V1", 1)[0]

    assert profile.count("Get-ADUser @baseUserQuery") == 1
    assert profile.count("Get-ADComputer @baseComputerQuery") == 1
    assert "$graphUsers = $baseUsers" in exporter
    assert "$baseUsersForExactLogon = $baseUsers" in exporter
    assert "$baseUserGuidAllowlist.Contains($guidKey)" in exporter
    assert "$baseComputerGuidAllowlist" in exporter
    assert "ResultSetSize = ($userLimit + 1)" in profile
    assert "ResultSetSize = ($computerLimit + 1)" in profile


def test_p4_base_profile_exact_section_comparison_is_strict_mode_safe() -> None:
    exporter = _read("scripts/ad_context/Export-AdAuditContextBundle.ps1")

    assert "@(Compare-Object $requestedSections $baseProfileSections).Count -ne 0" in exporter


def test_p4_exact_logon_preserves_empty_failed_dc_coverage() -> None:
    exporter = _read("scripts/ad_context/Export-AdAuditContextBundle.ps1")

    assert '$record.attributes["exact_last_logon_failed_dcs"] = @($failedDcs)' in exporter


def test_p4_duplicate_entity_merges_only_missing_attributes_and_provenance() -> None:
    powershell = shutil.which("powershell.exe") or shutil.which("pwsh")
    if powershell is None:
        pytest.skip("PowerShell is required for the collector behavior contract")
    exporter = ROOT / "scripts/ad_context/Export-AdAuditContextBundle.ps1"
    command = rf"""
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    '{exporter.as_posix()}', [ref]$tokens, [ref]$parseErrors
)
if ($parseErrors.Count -ne 0) {{ throw ($parseErrors | Out-String) }}
$functionAst = $ast.Find({{
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Write-EntityRecord'
}}, $true)
Invoke-Expression $functionAst.Extent.Text

$records = [System.Collections.Generic.List[object]]::new()
$entities = @{{}}
$first = [ordered]@{{
    record_type = 'entity'
    record_key = 'ad:s-1-5-21-1:00000000-0000-4000-8000-000000000001'
    section = 'directory_accounts'
    observed_at_utc = '2026-08-31T01:00:00.000Z'
    identity = [ordered]@{{ display_name = 'first identity' }}
    attributes = [ordered]@{{ display_name = 'first value'; existing_null = $null }}
    provenance = [ordered]@{{ query_server = 'dc-first.example.test' }}
}}
$duplicate = [ordered]@{{
    record_type = 'entity'
    record_key = $first.record_key
    section = 'directory_exact_logon'
    observed_at_utc = '2026-08-31T02:00:00.000Z'
    identity = [ordered]@{{ display_name = 'duplicate identity' }}
    attributes = [ordered]@{{
        display_name = 'duplicate value'
        existing_null = 'must not overwrite'
        exact_last_logon_status = 'no_record'
        exact_last_logon_discovered_dc_count = 2
        exact_last_logon_successful_dc_count = 2
        exact_last_logon_failed_dcs = @()
    }}
    provenance = [ordered]@{{
        query_server = 'dc-duplicate.example.test'
        exact_logon_source = 'bounded_per_dc_guid_lookup'
    }}
}}
[void](Write-EntityRecord -Record $first -Records $records -EntityRecords $entities -RecordLimit 10)
[void](Write-EntityRecord -Record $duplicate -Records $records -EntityRecords $entities -RecordLimit 10)
[ordered]@{{
    record_count = $records.Count
    entity_count = $entities.Count
    retained = $records[0]
}} | ConvertTo-Json -Depth 10 -Compress
"""
    completed = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    result = json.loads(completed.stdout)
    retained = result["retained"]

    assert result["record_count"] == result["entity_count"] == 1
    assert retained["record_key"] == (
        "ad:s-1-5-21-1:00000000-0000-4000-8000-000000000001"
    )
    assert retained["section"] == "directory_accounts"
    assert retained["observed_at_utc"] == "2026-08-31T01:00:00.000Z"
    assert retained["identity"] == {"display_name": "first identity"}
    assert retained["attributes"] == {
        "display_name": "first value",
        "existing_null": None,
        "exact_last_logon_status": "no_record",
        "exact_last_logon_discovered_dc_count": 2,
        "exact_last_logon_successful_dc_count": 2,
        "exact_last_logon_failed_dcs": [],
    }
    assert retained["provenance"] == {
        "query_server": "dc-first.example.test",
        "exact_logon_source": "bounded_per_dc_guid_lookup",
    }


def test_p4_fixture_cycle_calls_each_base_enumerator_once_and_freezes_allowlists() -> None:
    from scripts.runtime import ad_context_snapshot_worker as worker

    calls: list[str] = []
    seen: dict[str, object] = {}
    users = [
        {
            "object_guid": "00000000-0000-4000-8000-000000000001",
            "object_sid": "S-1-5-21-1-2-3-1001",
            "dns_name": None,
            "member_of": ["CN=Users,DC=example,DC=test"],
            "primary_group_id": 513,
        }
    ]
    computers = [
        {
            "object_guid": "00000000-0000-4000-8000-000000000002",
            "object_sid": "S-1-5-21-1-2-3-2001",
            "dns_name": "app-01.example.test",
        }
    ]

    def enumerate_users():
        calls.append("Get-ADUser(full)")
        return users

    def enumerate_computers():
        calls.append("Get-ADComputer(full)")
        return computers

    result = worker.coordinate_ad_snapshot_base_v1(
        enumerate_users=enumerate_users,
        enumerate_computers=enumerate_computers,
        consume_group_graph=lambda rows, allowlist: seen.update(
            graph_rows=rows, graph_allowlist=allowlist
        ),
        consume_exact_user_logon=lambda allowlist: seen.update(user_allowlist=allowlist),
        consume_computer_enrichment=lambda identities: seen.update(
            computer_allowlist=identities
        ),
        max_user_records=2,
        max_computer_records=2,
        max_base_bytes=4096,
        max_elapsed_seconds=5,
    )

    assert calls == ["Get-ADUser(full)", "Get-ADComputer(full)"]
    assert result["profile"] == "ad_snapshot_base_v1"
    assert result["users"]["count"] == 1
    assert result["computers"]["count"] == 1
    assert len(result["users"]["sha256"]) == 64
    assert seen["user_allowlist"] == frozenset(
        {"00000000-0000-4000-8000-000000000001"}
    )
    assert seen["computer_allowlist"] == (
        (
            "00000000-0000-4000-8000-000000000002",
            "app-01.example.test",
        ),
    )
    with pytest.raises(TypeError):
        seen["graph_rows"][0]["object_guid"] = "changed"


def test_p4_base_overflow_fails_before_any_downstream_or_retry() -> None:
    from scripts.runtime import ad_context_snapshot_worker as worker

    calls: list[str] = []
    downstream: list[str] = []

    with pytest.raises(ValueError, match="user_record_bound"):
        worker.coordinate_ad_snapshot_base_v1(
            enumerate_users=lambda: calls.append("users") or [
                {"object_guid": "00000000-0000-4000-8000-000000000001"},
                {"object_guid": "00000000-0000-4000-8000-000000000002"},
            ],
            enumerate_computers=lambda: calls.append("computers") or [],
            consume_group_graph=lambda *_args: downstream.append("graph"),
            consume_exact_user_logon=lambda *_args: downstream.append("user_logon"),
            consume_computer_enrichment=lambda *_args: downstream.append("computer"),
            max_user_records=1,
            max_computer_records=1,
            max_base_bytes=4096,
            max_elapsed_seconds=5,
        )

    assert calls == ["users"]
    assert downstream == []


@pytest.mark.windows_only  # Validates an absolute Windows PowerShell executable path.
def test_p4_adapter_builds_one_versioned_multi_section_invocation(tmp_path: Path) -> None:
    from server.source_packs.adapters import AdContextRequest, build_ad_context_command

    command = build_ad_context_command(
        AdContextRequest(
            powershell_executable="C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
            output_path=tmp_path / "base.json",
            run_id="00000000-0000-4000-8000-000000000004",
            directory_server="dc01.example.test",
            search_base="DC=example,DC=test",
            domain="example.test",
            sections=(
                "directory_accounts",
                "directory_group_graph",
                "directory_exact_logon",
            ),
            collection_profile="ad_snapshot_base_v1",
            max_records=50_000,
            max_bundle_bytes=25 * 1024 * 1024,
            max_directory_accounts=30_000,
            max_directory_users=20_000,
            max_directory_computers=10_000,
        )
    )

    assert command.count("-File") == 1
    assert command[command.index("-CollectionProfile") + 1] == "ad_snapshot_base_v1"
    assert command[command.index("-Sections") + 1] == (
        "directory_accounts,directory_group_graph,directory_exact_logon"
    )


def test_p5_shadow_projection_scope_is_static_dormant_and_non_generic() -> None:
    from server.sli.sources.ad_snapshot_projection import PROJECTION_ALLOWLIST
    from server.sli.ops.runtime_component_registry import get

    assert PROJECTION_ALLOWLIST == {
        "ad.users.v2": 1,
        "ad.computers.v6": 1,
        "ad.gpo.v2": 1,
        "ad.state": 1,
    }
    retired = {
        "ad_context_snapshot",
        "ad_snapshot_projection",
        "computers_v5_snapshot",
        "computers_v6_source",
        "computers_v6_snapshot",
        "users_v2_snapshot",
    }
    assert all(not get(name).feature_enabled and not get(name).supervised for name in retired)
    assert get("ad_snapshot_manifest_coordinator").feature_enabled is True
    assert get("ad_snapshot_manifest_coordinator").supervised is True
    source = _read("server/sli/sources/ad_snapshot_projection.py").casefold()
    assert "vpn.audit" not in source
    assert "radius" not in source
    assert "semantic" not in source
