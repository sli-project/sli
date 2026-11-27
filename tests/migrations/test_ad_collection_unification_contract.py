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
