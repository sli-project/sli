from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from scripts.maintenance.github_sanitary_check import scan
from server.ad_context.contracts import AdContextContractError, _gpo_settings
from server.ad_context.repository import _store_gpo_v2_snapshot

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "scripts/ad_context/GpoReportContract.psm1"
EXPORTER = ROOT / "scripts/ad_context/Export-AdGpoV2Snapshot.ps1"
SENSITIVE_NAMES = (
    "cpassword", "Password", "passwd", "pwd", "client_secret", "private_key",
    "apiKey", "access-key", "shared_key", "preSharedKey", "PSK",
    "encryptionKey", "decryption_key", "symmetricKey", "signing_key", "keyMaterial", "passphrase",
    "refreshToken", "credential", "connectionString",
)


def test_redaction_test_source_passes_sanitary_check(tmp_path):
    source = Path(__file__)
    (tmp_path / source.name).write_bytes(source.read_bytes())

    assert scan(tmp_path)["findings"] == []


def snapshot_with_setting(setting: dict) -> dict:
    return {
        "schema_version": "sli.ad-gpo.snapshot/1.0", "collector_version": "test",
        "demo": False, "collection_status": "complete",
        **dict.fromkeys(("started_at", "completed_at", "observed_at"), "2026-10-05T00:00:00Z"),
        "domain": {}, "scope": {},
        "source_states": {name: {"status": "observed"} for name in (
            "gpo_list", "gpo_reports", "gpc_directory", "sysvol_gpt",
            "links", "permissions", "wmi_filters",
        )},
        "gpos": [{"id": "gpo-test", "guid": "00000000-0000-4000-8000-000000000001",
                  "display_name": "Synthetic policy", "source_states": {},
                  "setting_ids": ["setting-test"]}],
        "settings": [{"id": "setting-test", "gpo_id": "gpo-test", **setting}],
        **{name: [] for name in (
            "scopes", "links", "permissions", "wmi_filters", "unresolved_links", "collection_errors",
        )},
    }


def stored_snapshot(snapshot: dict) -> tuple[dict, str]:
    class Cursor:
        def execute(self, sql, params):
            assert "insert into gpo_report_v2_source_snapshots" in sql
            self.params = params

    cursor = Cursor()
    _store_gpo_v2_snapshot(cursor, domain_id=1, run_id="00000000-0000-4000-8000-000000000002", snapshot=snapshot)
    text, digest = cursor.params[-2:]
    assert hashlib.sha256(text.encode("utf-8")).hexdigest() == digest
    return json.loads(text), text


@pytest.mark.parametrize("name", SENSITIVE_NAMES)
@pytest.mark.parametrize("representation", ["leaf", "path", "properties", "named", "inline", "inline_named"])
def test_import_masks_sensitive_gpo_values(name, representation):
    marker = "synthetic-redaction-marker"
    setting = {"setting_name": "Properties", "path": "Preferences/Properties", "value_display": "enabled"}
    if representation == "leaf":
        setting.update(setting_name=name, value_display=marker, source_state={"status": "observed", "value": marker})
    elif representation == "path":
        setting.update(path=f"Preferences/{name}/Data", value_display=marker)
    elif representation == "properties":
        setting["properties"] = {name: {"Data": marker}, "action": "U"}
    elif representation == "named":
        setting["properties"] = {"Name": name, "Value": marker, "action": "U"}
    elif representation == "inline":
        setting["value_display"] = f"action=U; {name}={marker}"
    else:
        setting["value_display"] = f"name={name}; value={marker}"
    snapshot = snapshot_with_setting(setting)
    original = deepcopy(snapshot)
    stored, text = stored_snapshot(snapshot)
    assert marker not in text
    assert "значение скрыто" in text
    assert snapshot == original
    assert stored["settings"][0]["id"] == "setting-test"
    assert stored["gpos"][0]["setting_ids"] == ["setting-test"]
    if representation == "leaf":
        assert stored["settings"][0]["source_state"]["status"] == "observed"
    assert stored_snapshot(stored)[0] == stored


def test_import_preserves_ordinary_registry_values():
    snapshot = snapshot_with_setting({
        "setting_name": "Registry", "path": "Registry/Properties",
        "value_display": "action=U; key=Software\\Synthetic; value=1",
        "properties": {"key": "Software\\Synthetic", "value": "1"},
    })
    assert stored_snapshot(snapshot)[0] == snapshot


@pytest.mark.parametrize("key_type", ["", "RSA ", "EC ", "OPENSSH "])
def test_import_masks_embedded_private_key_blocks(key_type):
    # Assemble a synthetic PEM envelope without a secret signature in source.
    label = f"{key_type}PRIVATE KEY"
    pem = "\n".join((
        "-----" + f"BEGIN {label}" + "-----",
        "synthetic-redaction-marker",
        "-----" + f"END {label}" + "-----",
    ))
    snapshot = snapshot_with_setting({
        "setting_name": "Data", "path": "Preferences/Data",
        "value_display": pem,
    })
    stored, text = stored_snapshot(snapshot)
    assert "synthetic-redaction-marker" not in text
    assert stored["settings"][0]["value_display"] == "значение скрыто"


@pytest.mark.parametrize("field", ["Value", "Values", "Data", "Text", "ValueData", "DefaultValue"])
def test_import_masks_nested_named_value_containers(field):
    snapshot = snapshot_with_setting({
        "properties": [{"ValueName": "private_key", field: ["synthetic-redaction-marker"]}],
    })
    _, text = stored_snapshot(snapshot)
    assert "synthetic-redaction-marker" not in text


def test_import_masks_other_snapshot_sections_and_preserves_source_status():
    snapshot = snapshot_with_setting({"value_display": "enabled"})
    snapshot["gpos"][0]["source_states"] = {
        "report": {"status": "observed", "value": {"client_secret": "synthetic-redaction-marker"}},
    }
    snapshot["collection_errors"] = [{
        "id": "error-test", "message": "client_secret=synthetic-redaction-marker",
    }]
    stored, text = stored_snapshot(snapshot)
    assert "synthetic-redaction-marker" not in text
    assert stored["gpos"][0]["source_states"]["report"]["status"] == "observed"


@pytest.mark.parametrize("name", SENSITIVE_NAMES)
def test_compatibility_contract_accepts_redacted_names_and_rejects_sensitive_properties(name):
    setting = {
        "scope": "computer", "kind": "Task", "path": "Tasks/Task", "properties": {},
        "redacted_fields": [name], "truncated_fields": [], "sensitive_value_present": True,
        "sha256": "0" * 64,
    }
    assert _gpo_settings([setting])[0]["redacted_fields"] == [name.lower()]
    setting.update(properties={name: "synthetic-redaction-marker"}, redacted_fields=[], sensitive_value_present=False)
    with pytest.raises(AdContextContractError, match="contains a sensitive field"):
        _gpo_settings([setting])


def test_both_powershell_paths_filter_before_normalizing():
    module = MODULE.read_text(encoding="utf-8-sig")
    exporter = EXPORTER.read_text(encoding="utf-8-sig")
    fact = module.split("function ConvertTo-SLIGpoSettingFact", 1)[1].split("function Get-SLIGpoSettingFacts", 1)[0]
    rows = exporter.split("function Convert-GpoReportSettings", 1)[1].split("function Get-ProbeGptPath", 1)[0]
    assert fact.index("Protect-SLIGpoXmlValues") < fact.index("$propertyNodes =")
    assert fact.index("Protect-SLIGpoXmlValues") < fact.index("$serialized =")
    assert rows.index("Protect-SLIGpoXmlValues") < rows.index("$leafNodes =")
    assert rows.index("Protect-SLIGpoXmlValues") < rows.index("$seed =")
    import_line = 'Import-Module (Join-Path $PSScriptRoot "GpoReportContract.psm1")'
    prefix = exporter.split(import_line, 1)[0]
    assert "if (-not [string]::IsNullOrWhiteSpace($CompatibilityProjectionPath))" not in prefix
    assert "Protect-SLIGpoXmlValues" in module.split("Export-ModuleMember", 1)[1]


def test_powershell_filters_xml_attributes_leaves_and_named_values(tmp_path):
    powershell = shutil.which("powershell") or shutil.which("pwsh")
    if powershell is None:
        pytest.skip("PowerShell is unavailable; both paths are also checked statically")
    # Extract only the pure normalizer, so AD/GroupPolicy modules are never loaded.
    runner = tmp_path / "redaction.ps1"
    runner.write_text(r'''
param($ModulePath, $ExporterPath)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
Import-Module $ModulePath -Force -ErrorAction Stop
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($ExporterPath, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'exporter_parse_failed' }
foreach ($name in @('Convert-GpoReportSettings', 'Get-XmlNodePath', 'Get-Sha256Hex', 'New-StableId', 'New-SourceState')) {
    $definition = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    . ([scriptblock]::Create($definition.Extent.Text))
}
[xml]$xml = '<GPO><Computer><ExtensionData><Extension><Name>Preferences</Name><Task><Properties action="U" cpassword="synthetic-redaction-marker" private_key="synthetic-redaction-marker"/><Secret><Data>synthetic-redaction-marker</Data></Secret><Registry name="apiKey" value="synthetic-redaction-marker"/><Policy><Name>shared_key</Name><Value>synthetic-redaction-marker</Value></Policy><Registry key="Software\Synthetic" value="1"/></Task></Extension></ExtensionData></Computer></GPO>'
$inline = $xml.CreateElement('Registry')
$inline.SetAttribute('data', 'password=synthetic-redaction-marker')
$null = $xml.SelectSingleNode('//Task').AppendChild($inline)
$named = $xml.CreateElement('Registry')
$named.SetAttribute('data', 'name=apiKey; value=synthetic-redaction-marker')
$null = $xml.SelectSingleNode('//Task').AppendChild($named)
$secretContainer = $xml.CreateElement('private_key')
$secretContainer.InnerXml = '<Registry><Value>synthetic-redaction-marker</Value></Registry>'
$null = $xml.SelectSingleNode('//Extension').AppendChild($secretContainer)
$facts = ConvertFrom-SLIGpoReportXml -XmlText $xml.OuterXml
$rows = Convert-GpoReportSettings -Xml $xml -GpoId 'gpo-test' -GpoName 'Synthetic policy' -Side computer -Maximum 100
[xml]$changedXml = $xml.OuterXml.Replace('synthetic-redaction-marker', 'another-synthetic-marker')
$changedFacts = ConvertFrom-SLIGpoReportXml -XmlText $changedXml.OuterXml
$changedRows = Convert-GpoReportSettings -Xml $changedXml -GpoId 'gpo-test' -GpoName 'Synthetic policy' -Side computer -Maximum 100
@{ facts=$facts; rows=$rows; changedFacts=$changedFacts; changedRows=$changedRows; originalPreserved=$xml.OuterXml.Contains('synthetic-redaction-marker') } | ConvertTo-Json -Depth 15 -Compress
''', encoding="utf-8-sig")
    completed = subprocess.run(
        [str(powershell), "-NoProfile", "-NonInteractive", "-File", str(runner), str(MODULE), str(EXPORTER)],
        capture_output=True, timeout=30, check=True,
    )
    result = json.loads(completed.stdout.decode("utf-8-sig"))
    serialized = json.dumps(result, ensure_ascii=False)
    assert "synthetic-redaction-marker" not in serialized
    assert "another-synthetic-marker" not in serialized
    assert "значение скрыто" in serialized
    assert result["originalPreserved"] is True
    assert result["facts"]["attributes"] == result["changedFacts"]["attributes"]
    assert result["rows"] == result["changedRows"]
    assert any(row["value_display"] == "key=Software\\Synthetic; value=1" for row in result["rows"]["rows"])
    task = next(item for item in result["facts"]["attributes"]["gpo_settings"] if item["kind"] == "Task")
    assert task["sensitive_value_present"] is True
    assert {"cpassword", "private_key", "secret", "apikey", "shared_key"} <= set(task["redacted_fields"])


@pytest.mark.parametrize("name", SENSITIVE_NAMES)
def test_powershell_sensitive_name_rule_covers_server_cases(name):
    # Keep the cross-language rule aligned without requiring AD access.
    source = MODULE.read_text(encoding="utf-8-sig")
    function = source.split("function Test-SLIGpoSensitiveFieldName", 1)[1].split("function ", 1)[0]
    pattern = re.search(r"-match '([^']+)'", function).group(1)
    assert re.search(pattern, re.sub("[^a-z0-9]", "", name.lower()))
