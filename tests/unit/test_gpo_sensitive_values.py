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
    module = tmp_path / MODULE.name
    module.write_text(MODULE.read_text(encoding="utf-8-sig"), encoding="utf-8-sig")
    # Extract only the pure normalizer, so AD/GroupPolicy modules are never loaded.
    runner = tmp_path / "redaction.ps1"
    runner.write_text(r'''
param($ModulePath, $ExporterPath)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
Import-Module $ModulePath -Force -ErrorAction Stop
$tokens = $null; $errors = $null
$scriptText = Get-Content -LiteralPath $ExporterPath -Raw -Encoding UTF8
$ast = [Management.Automation.Language.Parser]::ParseInput($scriptText, [ref]$tokens, [ref]$errors)
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
        [str(powershell), "-NoProfile", "-NonInteractive", "-File", str(runner), str(module), str(EXPORTER)],
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
