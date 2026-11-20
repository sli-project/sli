from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from server.ad_context.contracts import validate_bundle


ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "scripts/ad_context/ActiveDirectoryContext.psm1"
EXPORTER = ROOT / "scripts/ad_context/Export-AdAuditContextBundle.ps1"
POWERSHELL = Path(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")


def test_active_directory_collector_is_bounded_read_only_and_covers_approved_sources():
    source = MODULE.read_text(encoding="utf-8")
    folded = source.casefold()

    for required in (
        "get-addomain", "get-adforest", "objectclass=trusteddomain", "resultsetsize", "get-addefaultdomainpasswordpolicy",
        "get-addomaincontroller", "get-adreplicationpartnermetadata", "dcdiag.exe",
        "advertising", "connectivity", "services", "sysvolcheck", "dns",
    ):
        assert required in folded

    assert "get-adtrust" not in folded
    for forbidden in (
        "set-ad", "new-ad", "remove-ad", "disable-ad", "enable-ad", "move-ad", "rename-ad",
        "repadmin /sync", "repadmin /replicate", "/fix", "set-acl", "invoke-command",
    ):
        assert forbidden not in folded
    assert "WaitForExit" in source
    assert "MaxDomainControllers" in source
    assert "CommandTimeoutSeconds" in source
    assert "MaxDiagnosticBytes" in source


@pytest.mark.windows_only
def test_replication_fixture_becomes_a_contract_valid_stable_record():
    command = f"""
$OutputEncoding = [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
Import-Module '{MODULE}' -Force
$row = [pscustomobject]@{{
  Server='dc1.example.test'; Partner='CN=NTDS Settings,CN=DC2,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=example,DC=test';
  Partition='DC=example,DC=test'; LastReplicationAttempt=[datetime]'2026-08-28T06:00:00Z';
  LastReplicationSuccess=[datetime]'2026-08-28T06:00:00Z'; ConsecutiveReplicationFailures=0; LastReplicationResult=0
}}
ConvertTo-SLIReplicationRecord -Metadata $row -DomainSid 'S-1-5-21-111-222-333' -ObservedAtUtc '2026-08-28T06:00:00.000Z' | ConvertTo-Json -Depth 8 -Compress
"""
    completed = subprocess.run(
        [str(POWERSHELL), "-NoProfile", "-NonInteractive", "-Command", command],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    record = json.loads(completed.stdout.strip())
    bundle = {
        "schema_version": "ad-context-bundle/v1", "source_pack_id": "sli.windows.ad-context",
        "source_pack_version": "0.5.0", "run_id": "00000000-0000-4000-8000-000000000104",
        "mode": "targeted", "domain": {"sid": "S-1-5-21-111-222-333", "dns_name": "example.test"},
        "scope": {"search_base": "DC=example,DC=test", "privileged_group_sids": [], "vpn_group_sids": [], "collection_profile": "domain_health_v1"},
        "observed_at_utc": "2026-08-28T06:00:00+00:00",
        "sections": [{"name": "domain_health", "status": "complete", "record_count": 1, "duration_ms": 1, "error_code": None}],
        "records": [record],
    }
    normalized = validate_bundle(bundle)
    item = normalized["records"][0]
    assert item["identity"]["kind"] == "replication_link"
    assert item["attributes"]["display_name"] == "DC2 -> dc1.example.test"
    assert item["attributes"]["source_dc"] == "DC2"
    assert item["attributes"]["destination_dc"] == "dc1.example.test"
    assert item["attributes"]["replication_state"] == "passed"


@pytest.mark.windows_only  # Executes the collector module with Windows PowerShell.
def test_domain_controller_reuses_the_existing_computer_identity_and_marks_its_infrastructure_role():
    command = f"""
$OutputEncoding = [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
Import-Module '{MODULE}' -Force
$dc = [pscustomobject]@{{ HostName='dc1.example.test'; Name='DC1'; Site='Default-First-Site-Name'; IsGlobalCatalog=$true; IsReadOnly=$false; OperationMasterRoles=@('PDCEmulator'); OperatingSystem='Windows Server'; OperatingSystemVersion='10.0' }}
$computer = [pscustomobject]@{{ ObjectGuid=[guid]'82da89e4-72d2-4c7c-9f70-3366106173ae'; SID='S-1-5-21-111-222-333-1001'; DistinguishedName='CN=DC1,OU=Domain Controllers,DC=example,DC=test' }}
$checks = @{{ advertising='passed'; connectivity='passed'; services='passed'; sysvol='passed'; netlogon='passed'; dns='passed'; errors=@() }}
ConvertTo-SLIDomainControllerRecord -DomainController $dc -ComputerObject $computer -Checks $checks -DomainSid 'S-1-5-21-111-222-333' -ObservedAtUtc '2026-08-28T06:00:00.000Z' | ConvertTo-Json -Depth 8 -Compress
"""
    completed = subprocess.run(
        [str(POWERSHELL), "-NoProfile", "-NonInteractive", "-Command", command],
        check=True, capture_output=True, text=True, timeout=30,
    )
    record = json.loads(completed.stdout.strip())
    bundle = {
        "schema_version": "ad-context-bundle/v1", "source_pack_id": "sli.windows.ad-context",
        "source_pack_version": "0.7.0", "run_id": "00000000-0000-4000-8000-000000000105",
        "mode": "targeted", "domain": {"sid": "S-1-5-21-111-222-333", "dns_name": "example.test"},
        "scope": {"search_base": "DC=example,DC=test", "privileged_group_sids": [], "vpn_group_sids": [], "collection_profile": "domain_health_v1"},
        "observed_at_utc": "2026-08-28T06:00:00+00:00",
        "sections": [{"name": "domain_health", "status": "complete", "record_count": 1, "duration_ms": 1, "error_code": None}],
        "records": [record],
    }
    item = validate_bundle(bundle)["records"][0]
    assert item["identity"]["kind"] == "ad_computer"
    assert item["attributes"]["infrastructure_role"] == "domain_controller"


def test_exporter_wires_each_active_directory_section_to_its_collector():
    source = EXPORTER.read_text(encoding="utf-8")
    assert 'Import-Module (Join-Path $PSScriptRoot "ActiveDirectoryContext.psm1")' in source
    assert 'Get-SLIDomainPostureRecords' in source
    assert 'Get-SLIDomainHealthRecords' in source
    assert '$sectionStatus["domain_posture"]' in source
    assert '$sectionStatus["domain_health"]' in source


@pytest.mark.windows_only
def test_domain_posture_keeps_password_policy_and_trust_facts_when_ad_returns_collection_properties():
    command = f"""
$OutputEncoding = [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
Import-Module '{MODULE}' -Force
$module = Get-Module ActiveDirectoryContext
& $module {{
  function script:Get-SLILdapPolicy {{ [ordered]@{{ signing='require_signing'; channel_binding='always'; error=$null }} }}
  function script:Get-ADDomain {{ [pscustomobject]@{{ DNSRoot='example.test'; Forest='example.test'; NetBIOSName='EXAMPLE'; DistinguishedName='DC=example,DC=test'; DomainMode='Windows2008Domain'; PDCEmulator='dc1.example.test'; RIDMaster='dc1.example.test'; InfrastructureMaster='dc1.example.test' }} }}
  function script:Get-ADForest {{ [pscustomobject]@{{ ForestMode='Windows2008Forest'; SchemaMaster='dc1.example.test'; DomainNamingMaster='dc1.example.test' }} }}
  function script:Get-ADObject {{
    param($Server,$Identity,$LDAPFilter,$SearchBase,$SearchScope,$ResultSetSize,$Properties,$ErrorAction)
    if ($LDAPFilter -eq '(objectClass=trustedDomain)') {{
      return [pscustomobject]@{{ ObjectGUID=[guid]'2c0cde70-f823-4201-bd1e-05dd82fe743a'; Name='trusted.example.test'; trustPartner='trusted.example.test'; flatName='TRUSTED'; trustDirection=3; trustType=2; trustAttributes=8; DistinguishedName='CN=trusted.example.test,CN=System,DC=example,DC=test' }}
    }}
    [pscustomobject]@{{ ObjectGUID=[guid]'2270b949-f853-4926-8410-4e1b6f61065e'; 'ms-DS-MachineAccountQuota'=10 }}
  }}
  function script:Get-ADOptionalFeature {{ [pscustomobject]@{{ EnabledScopes=@('CN=Partitions,CN=Configuration,DC=example,DC=test') }} }}
  function script:Get-ADDefaultDomainPasswordPolicy {{ [pscustomobject]@{{ MinPasswordLength=12; MaxPasswordAge='42.00:00:00'; MinPasswordAge='1.00:00:00'; PasswordHistoryCount=24; PasswordProperties=@('ComplexityEnabled','ReversibleEncryptionEnabled'); LockoutThreshold=5; LockoutDuration='00:30:00'; LockoutObservationWindow='00:30:00' }} }}
  function script:Get-ADTrust {{ throw 'Get-ADTrust_must_not_be_used' }}
}}
$result = Get-SLIDomainPostureRecords -DirectoryServer 'DC2' -Domain 'example.test' -DomainSid 'S-1-5-21-111-222-333' -ObservedAtUtc '2026-08-28T06:00:00.000Z'
$result | ConvertTo-Json -Depth 10 -Compress
"""
    completed = subprocess.run(
        [str(POWERSHELL), "-NoProfile", "-NonInteractive", "-Command", command],
        check=True, capture_output=True, text=True, timeout=30,
    )
    result = json.loads(completed.stdout.lstrip("\ufeff"))
    assert result["errors"] == []
    records = {record["identity"]["kind"]: record for record in result["records"]}
    assert set(records) == {"domain", "password_policy", "domain_trust"}
    assert records["password_policy"]["attributes"]["password_properties"] == [
        "ComplexityEnabled", "ReversibleEncryptionEnabled",
    ]


def test_exporter_does_not_overwrite_powershells_automatic_error_variable():
    source = EXPORTER.read_text(encoding="utf-8")
    assert "foreach ($error in @($posture.errors))" not in source
    assert "foreach ($error in @($health.errors))" not in source
