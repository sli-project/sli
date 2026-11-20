from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess

import pytest

from server.ad_context.contracts import (
    COMPUTER_ATTRIBUTE_SOURCES,
    AdContextContractError,
    load_bundle,
    validate_bundle,
)
from server.ad_context.enrichment import explain_privileged_membership_event
from server.ad_context.projection import ContextProjection


FIXTURE = Path("tests/fixtures/ad_context_privileged_membership.json")


def _bundle() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _supplemental_bundle() -> dict:
    observed = "2026-07-20T12:00:00Z"
    domain_sid = "S-1-5-21-100000003-200000003-300000003"
    user_key = f"ad:{domain_sid.lower()}:00000000-0000-4000-8000-000000000065"
    vpn_key = f"ad:{domain_sid.lower()}:00000000-0000-4000-8000-000000000067"
    gpo_key = f"ad:{domain_sid.lower()}:00000000-0000-4000-8000-000000000070"
    return {
        "schema_version": "ad-context-bundle/v1",
        "source_pack_id": "sli.windows.ad-context",
        "source_pack_version": "0.3.0",
        "run_id": "00000000-0000-4000-8000-000000000053",
        "mode": "full",
        "domain": {"sid": domain_sid, "dns_name": "host13.example.invalid"},
        "scope": {
            "search_base": "DC=example,DC=local",
            "privileged_group_sids": [],
            "vpn_group_sids": [f"{domain_sid}-1701"],
        },
        "observed_at_utc": observed,
        "sections": [
            {"name": "directory_accounts", "status": "complete", "record_count": 1, "duration_ms": 10, "error_code": None},
            {"name": "vpn_membership", "status": "complete", "record_count": 2, "duration_ms": 20, "error_code": None},
            {"name": "gpo_governance", "status": "complete", "record_count": 1, "duration_ms": 30, "error_code": None},
        ],
        "records": [
            {
                "record_type": "entity", "record_key": user_key, "section": "directory_accounts", "observed_at_utc": observed,
                "identity": {"kind": "ad_user", "domain_sid": domain_sid, "object_guid": "00000000-0000-4000-8000-000000000065", "object_sid": f"{domain_sid}-1101"},
                "attributes": {"display_name": "VPN User", "sam_account_name": "vpn.user", "distinguished_name": "CN=VPN User,DC=example,DC=local", "enabled": True, "object_class": "user", "last_logon_utc": observed, "password_never_expires": False, "admin_count": 0},
            },
            {
                "record_type": "entity", "record_key": vpn_key, "section": "vpn_membership", "observed_at_utc": observed,
                "identity": {"kind": "ad_group", "domain_sid": domain_sid, "object_guid": "00000000-0000-4000-8000-000000000067", "object_sid": f"{domain_sid}-1701"},
                "attributes": {"display_name": "VPNl2tp", "sam_account_name": "VPNl2tp", "distinguished_name": "CN=VPNl2tp,DC=example,DC=local", "enabled": None, "object_class": "group"},
            },
            {
                "record_type": "relation", "record_key": "member-of:vpn:user:vpn", "section": "vpn_membership", "observed_at_utc": observed,
                "relation_kind": "member_of", "source_record_key": user_key, "target_record_key": vpn_key,
                "attributes": {"membership_type": "direct", "source_section": "vpn_membership"},
            },
            {
                "record_type": "entity", "record_key": gpo_key, "section": "gpo_governance", "observed_at_utc": observed,
                "identity": {"kind": "gpo", "domain_sid": domain_sid, "object_guid": "00000000-0000-4000-8000-000000000070", "object_sid": None},
                "attributes": {"display_name": "Security Baseline", "object_class": "gpo", "owner": "EXAMPLE\\Domain Admins", "description": "Baseline", "link_count": 1, "links": ["OU=Servers,DC=example,DC=local"], "modified_utc": observed},
            },
        ],
    }


def test_contract_accepts_bounded_structured_bundle():
    normalized = load_bundle(FIXTURE)
    assert normalized["domain"]["dns_name"] == "host13.example.invalid"
    assert len(normalized["bundle_sha256"]) == 64
    assert validate_bundle(normalized) == normalized


def test_contract_accepts_matching_collection_profile_and_rejects_mismatch():
    bundle = _bundle()
    bundle.pop("bundle_sha256", None)
    bundle["scope"]["collection_profile"] = "privileged_membership_v1"
    assert validate_bundle(bundle)["scope"]["collection_profile"] == "privileged_membership_v1"
    bundle["scope"]["collection_profile"] = "vpn_security_v1"
    with pytest.raises(AdContextContractError, match="collection_profile"):
        validate_bundle(bundle)


def test_contract_accepts_only_exact_snapshot_base_profile_sections():
    bundle = _supplemental_bundle()
    bundle["source_pack_version"] = "0.10.0"
    bundle["scope"]["collection_profile"] = "ad_snapshot_base_v1"
    bundle["scope"]["vpn_group_sids"] = []
    bundle["sections"] = [
        {"name": "directory_accounts", "status": "complete", "record_count": 1, "duration_ms": 10, "error_code": None},
        {"name": "directory_group_graph", "status": "complete", "record_count": 0, "duration_ms": 20, "error_code": None},
        {"name": "directory_exact_logon", "status": "complete", "record_count": 0, "duration_ms": 30, "error_code": None},
    ]
    bundle["records"] = [bundle["records"][0]]
    bundle["records"][0]["attributes"].update(
        {
            "exact_last_logon_status": "no_record",
            "exact_last_logon_discovered_dc_count": 2,
            "exact_last_logon_successful_dc_count": 2,
            "exact_last_logon_failed_dcs": [],
        }
    )

    normalized = validate_bundle(bundle)

    assert normalized["scope"]["collection_profile"] == "ad_snapshot_base_v1"
    assert "exact_last_logon_utc" not in normalized["records"][0]["attributes"]
    bundle["sections"].pop()
    with pytest.raises(AdContextContractError, match="collection_profile"):
        validate_bundle(bundle)


def test_complete_snapshot_base_exact_logon_requires_coverage_on_every_account_user():
    bundle = _supplemental_bundle()
    bundle["source_pack_version"] = "0.10.0"
    bundle["scope"]["collection_profile"] = "ad_snapshot_base_v1"
    bundle["scope"]["vpn_group_sids"] = []
    bundle["sections"] = [
        {"name": "directory_accounts", "status": "complete", "record_count": 1, "duration_ms": 10, "error_code": None},
        {"name": "directory_group_graph", "status": "complete", "record_count": 0, "duration_ms": 20, "error_code": None},
        {"name": "directory_exact_logon", "status": "complete", "record_count": 0, "duration_ms": 30, "error_code": None},
    ]
    bundle["records"] = [bundle["records"][0]]

    with pytest.raises(AdContextContractError, match="exact lastLogon coverage"):
        validate_bundle(bundle)

    bundle["sections"][2]["status"] = "partial"
    assert validate_bundle(bundle)["sections"][2]["status"] == "partial"


def test_contract_accepts_account_vpn_and_gpo_sections_without_privileged_scope():
    normalized = validate_bundle(_supplemental_bundle())
    assert normalized["scope"]["privileged_group_sids"] == []
    assert normalized["scope"]["vpn_group_sids"] == ["S-1-5-21-100000003-200000003-300000003-1701"]
    assert {item["name"] for item in normalized["sections"]} == {"directory_accounts", "vpn_membership", "gpo_governance"}
    assert ContextProjection().apply(normalized)["relations_changed"] == 1


def test_contract_accepts_bounded_computer_inventory_attributes():
    bundle = _supplemental_bundle()
    bundle["records"].append({
        "record_type": "entity",
        "record_key": "ad:s-1-5-21-111-222-333:00000000-0000-4000-8000-000000000042",
        "section": "directory_accounts",
        "observed_at_utc": bundle["observed_at_utc"],
        "identity": {
            "kind": "ad_computer",
            "domain_sid": bundle["domain"]["sid"],
            "object_guid": "00000000-0000-4000-8000-000000000042",
            "object_sid": "S-1-5-21-100000003-200000003-300000003-2101",
        },
        "attributes": {
            "display_name": "APP-SRV-01",
            "sam_account_name": "APP-SRV-01$",
            "distinguished_name": "CN=APP-SRV-01,DC=example,DC=local",
            "enabled": True,
            "object_class": "computer",
            "last_logon_utc": bundle["observed_at_utc"],
            "is_inactive": False,
            "inactivity_basis": "last_logon",
            "inactive_threshold_days": 180,
            "dns_host_name": "host3.example.invalid",
            "operating_system": "Windows Server",
            "operating_system_version": "10.0",
            "attribute_states": {
                key: {
                    "state": "present" if key in {
                        "enabled", "last_logon_utc", "dns_host_name",
                        "operating_system", "operating_system_version",
                    } else "absent_in_source",
                    "source_attribute": source,
                }
                for key, source in COMPUTER_ATTRIBUTE_SOURCES.items()
            },
        },
    })
    directory = next(
        section for section in bundle["sections"]
        if section["name"] == "directory_accounts"
    )
    directory["record_count"] += 1

    normalized = validate_bundle(bundle)

    computer = next(
        record for record in normalized["records"]
        if record["identity"]["kind"] == "ad_computer"
    )
    assert computer["attributes"]["dns_host_name"] == "host3.example.invalid"
    assert computer["attributes"]["operating_system"] == "Windows Server"
    assert computer["attributes"]["inactivity_basis"] == "last_logon"
    assert computer["attributes"]["attribute_states"]["operating_system"] == {
        "state": "present",
        "source_attribute": "OperatingSystem",
    }


def test_contract_rejects_unknown_computer_attribute_state():
    bundle = _supplemental_bundle()
    bundle["records"][0]["identity"]["kind"] = "ad_computer"
    bundle["records"][0]["attributes"]["object_class"] = "computer"
    bundle["records"][0]["attributes"]["attribute_states"] = {
        key: {
            "state": "read_error" if key == "operating_system" else "present",
            "source_attribute": source,
        }
        for key, source in COMPUTER_ATTRIBUTE_SOURCES.items()
    }

    with pytest.raises(AdContextContractError, match="attribute state"):
        validate_bundle(bundle)


def test_contract_rejects_unknown_inactivity_basis():
    bundle = _supplemental_bundle()
    bundle["records"][0]["attributes"]["inactivity_basis"] = "guessed"

    with pytest.raises(AdContextContractError, match="inactivity_basis"):
        validate_bundle(bundle)


def test_domain_posture_contract_accepts_new_entity_kinds_and_rejects_unknown_attributes():
    observed = "2026-07-30T05:00:00Z"
    domain_sid = "S-1-5-21-111-222-333"
    kinds = ("domain", "domain_trust", "domain_controller", "password_policy")
    bundle = {
        "schema_version": "ad-context-bundle/v1",
        "source_pack_id": "sli.windows.ad-context",
        "source_pack_version": "0.4.0",
        "run_id": "00000000-0000-4000-8000-000000000059",
        "mode": "targeted",
        "domain": {"sid": domain_sid, "dns_name": "host13.example.invalid"},
        "scope": {
            "search_base": "DC=example,DC=local",
            "privileged_group_sids": [],
            "vpn_group_sids": [],
            "collection_profile": "domain_posture_v1",
        },
        "observed_at_utc": observed,
        "sections": [{
            "name": "domain_posture",
            "status": "complete",
            "record_count": len(kinds),
            "duration_ms": 20,
            "error_code": None,
        }],
        "records": [{
            "record_type": "entity",
            "record_key": f"ad:{domain_sid.lower()}:{index:08d}-0000-4000-8000-000000000000",
            "section": "domain_posture",
            "observed_at_utc": observed,
            "identity": {
                "kind": kind,
                "domain_sid": domain_sid,
                "object_guid": f"{index:08d}-0000-4000-8000-000000000000",
                "object_sid": domain_sid if kind == "domain" else None,
            },
            "attributes": {
                "display_name": kind,
                **({"password_min_length": 14} if kind == "password_policy" else {}),
                **({"trust_partner": "trusted.example"} if kind == "domain_trust" else {}),
            },
        } for index, kind in enumerate(kinds, 1)],
    }

    normalized = validate_bundle(bundle)
    assert {row["identity"]["kind"] for row in normalized["records"]} == set(kinds)

    bundle["records"][0]["attributes"]["unbounded_future_attribute"] = "rejected"
    with pytest.raises(AdContextContractError, match="unsupported fields"):
        validate_bundle(bundle)


@pytest.mark.windows_only
def test_gpo_report_contract_parses_fixture_facts_under_declared_ceilings(
    tmp_path: Path,
):
    xml_path = tmp_path / "gpo.xml"
    xml_path.write_text("""<?xml version="1.0" encoding="utf-8"?>
<GPO xmlns="http://www.microsoft.com/GroupPolicy/Settings">
  <ModifiedTime>2026-07-30T08:00:00Z</ModifiedTime>
  <SecurityDescriptor><Permissions><TrusteePermissions>
    <Trustee><SID>S-1-5-11</SID></Trustee><PermissionType>GpoApply</PermissionType>
  </TrusteePermissions></Permissions></SecurityDescriptor>
  <FilterData><ID>{00000000-0000-4000-8000-000000000042}</ID></FilterData>
  <Computer><Enabled>true</Enabled><ExtensionData><Extension>
    <Scripts><Script><Type>Startup</Type><Command>startup.ps1</Command><Parameters>-Mode Safe</Parameters></Script></Scripts>
    <ScheduledTasks><Task name="Inventory"><Properties action="U" appName="powershell.exe" args="-File inventory.ps1" runAs="EXAMPLE\\svc-gpo" cpassword="must-not-leave-parser" /><Data>__LONG_VALUE__</Data></Task></ScheduledTasks>
    <Services><Service name="Spooler"><Properties action="U" serviceName="Spooler" startup="DISABLED" /></Service></Services>
    <Groups><Group name="Administrators"><Properties action="U" groupName="Administrators" /></Group></Groups>
  </Extension></ExtensionData></Computer>
  <User><Enabled>false</Enabled><ExtensionData><Extension>
    <Scripts><Script><Type>Logon</Type></Script></Scripts>
  </Extension></ExtensionData></User>
  <LinksTo><SOMPath>OU=Servers,DC=example,DC=local</SOMPath>
    <Enabled>true</Enabled><NoOverride>true</NoOverride></LinksTo>
</GPO>""".replace("__LONG_VALUE__", "x" * 5000), encoding="utf-8")
    powershell = (
        Path(os.environ.get("WINDIR") or r"C:\Windows")
        / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    )
    module = Path("scripts/ad_context/GpoReportContract.psm1").resolve()
    command = (
        f"Import-Module '{module}' -Force -ErrorAction Stop; "
        f"$facts=ConvertFrom-SLIGpoReportXml (Get-Content -LiteralPath '{xml_path}' -Raw); "
        "$contract=Get-SLIGpoReportContract; "
        "$permissions=[pscustomobject]@{gpo_apply_allow_sids=@();gpo_apply_deny_sids=@();permission_count=0;permissions=@();effective_access_evaluated=$false}; "
        "$merged=Merge-SLIGpoGovernanceAttributes -BaseAttributes @{} -ReportFacts $facts -PermissionFacts $permissions; "
        "[pscustomobject]@{facts=$facts;contract=$contract;merged=$merged}|ConvertTo-Json -Depth 8 -Compress"
    )
    completed = subprocess.run(
        [str(powershell), "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True, text=True, timeout=60, check=True,
    )
    result = json.loads(completed.stdout)
    facts, contract = result["facts"]["attributes"], result["contract"]
    assert (
        facts["link_count"], facts["gpo_link_enabled_count"],
        facts["gpo_link_enforced_count"],
    ) == (1, 1, 1)
    assert facts["gpo_security_filtering_collected"] is False
    assert facts["gpo_computer_enabled"] is True and facts["gpo_user_enabled"] is False
    assert facts["gpo_wmi_filter_present"] is True
    assert [facts[key] for key in (
        "gpo_startup_script_count", "gpo_logon_script_count",
        "gpo_scheduled_task_count", "gpo_service_count", "gpo_local_group_count",
    )] == [1, 1, 1, 1, 1]
    settings = facts["gpo_settings"]
    assert len(settings) == 5
    startup = next(row for row in settings if row["scope"] == "computer" and row["kind"] == "Script")
    assert startup["properties"] == {
        "command": "startup.ps1", "parameters": "-Mode Safe", "type": "Startup",
    }
    task = next(row for row in settings if row["kind"] == "Task")
    assert task["properties"]["appname"] == "powershell.exe"
    assert task["properties"]["args"] == "-File inventory.ps1"
    assert task["properties"]["runas"] == r"EXAMPLE\svc-gpo"
    assert task["sensitive_value_present"] is True
    assert task["redacted_fields"] == ["cpassword"]
    assert task["truncated_fields"] == ["data"]
    assert len(task["properties"]["data"]) == 4096
    assert len(result["merged"]["gpo_settings"]) == 5
    assert result["merged"]["gpo_settings"][1]["truncated_fields"] == ["data"]
    assert "must-not-leave-parser" not in json.dumps(settings)
    assert all(len(row["sha256"]) == 64 for row in settings)
    assert contract == {
        "policy_limit": 72, "report_type": "Xml",
        "per_policy_time_limit_seconds": 30, "total_time_limit_seconds": 900,
        "single_response_bytes_limit": 33554432,
        "total_response_bytes_limit": 268435456,
        "per_policy_setting_limit": 2048,
        "per_setting_property_limit": 64,
        "setting_property_value_length_limit": 4096,
        "file_poll_interval_ms": 50,
        "processing_order": "one_policy_at_a_time_stop_on_first_breach",
    }


@pytest.mark.host_dependent  # needs the RSAT GroupPolicy/ActiveDirectory modules
@pytest.mark.windows_only
def test_gpo_permission_contract_matches_cmdlet_shape_and_preserves_acl_semantics():
    powershell = (
        Path(os.environ.get("WINDIR") or r"C:\Windows")
        / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    )
    module = Path("scripts/ad_context/GpoReportContract.psm1").resolve()
    command = f"""
Import-Module GroupPolicy -ErrorAction Stop
Import-Module '{module}' -Force -ErrorAction Stop
$rows = @(
  [pscustomobject]@{{
    Trustee=[pscustomobject]@{{Sid='S-1-5-11';SidType='WellKnownGroup';Name='not persisted'}}
    Permission='GpoApply';Denied=$false;Inherited=$false
  }},
  [pscustomobject]@{{
    Trustee=[pscustomobject]@{{Sid='S-1-5-18';SidType='WellKnownGroup';Name='not persisted'}}
    Permission='GpoApply';Denied=$true;Inherited=$true
  }},
  [pscustomobject]@{{
    Trustee=[pscustomobject]@{{Sid='S-1-5-32-544';SidType='Alias';Name='not persisted'}}
    Permission='GpoEditDeleteModifySecurity';Denied=$false;Inherited=$false
  }}
)
[pscustomobject]@{{
  command_parameters=@((Get-Command Get-GPPermission).Parameters.Keys)
  permission_properties=@([Microsoft.GroupPolicy.GPPermission].GetProperties().Name)
  trustee_properties=@([Microsoft.GroupPolicy.GPTrustee].GetProperties().Name)
  permission_types=@([Enum]::GetNames([Microsoft.GroupPolicy.GPPermissionType]))
  converted=ConvertFrom-SLIGpoPermissionObjects $rows
  contract=Get-SLIGpoPermissionContract
}} | ConvertTo-Json -Depth 8 -Compress
"""
    completed = subprocess.run(
        [str(powershell), "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True, text=True, timeout=60, check=True,
    )
    result = json.loads(completed.stdout)

    assert {"Guid", "DomainName", "Server", "All"} <= set(
        result["command_parameters"]
    )
    assert {"Trustee", "Permission", "Denied", "Inherited"} <= set(
        result["permission_properties"]
    )
    assert {"Sid", "SidType"} <= set(result["trustee_properties"])
    assert {
        "GpoApply", "GpoRead", "GpoEdit", "GpoEditDeleteModifySecurity",
        "GpoCustom",
    } <= set(result["permission_types"])
    converted = result["converted"]
    assert converted["permission_count"] == 3
    assert converted["gpo_apply_allow_sids"] == ["S-1-5-11"]
    assert converted["gpo_apply_deny_sids"] == ["S-1-5-18"]
    assert converted["effective_access_evaluated"] is False
    assert all("Name" not in row for row in converted["permissions"])
    assert result["contract"] == {
        "policy_limit": 72,
        "per_policy_permission_limit": 4096,
        "total_permission_limit": 65536,
        "per_policy_time_limit_seconds": 30,
        "total_time_limit_seconds": 900,
        "single_response_bytes_limit": 2097152,
        "total_response_bytes_limit": 67108864,
        "processing_order": "one_policy_at_a_time_stop_on_first_breach",
    }


@pytest.mark.windows_only
def test_gpo_permission_contract_fails_closed_on_invalid_sid_and_permission():
    powershell = (
        Path(os.environ.get("WINDIR") or r"C:\Windows")
        / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    )
    module = Path("scripts/ad_context/GpoReportContract.psm1").resolve()
    command = f"""
Import-Module '{module}' -Force -ErrorAction Stop
$errors = @()
foreach ($row in @(
  [pscustomobject]@{{
    Trustee=[pscustomobject]@{{Sid='not-a-sid';SidType='Group'}}
    Permission='GpoApply';Denied=$false;Inherited=$false
  }},
  [pscustomobject]@{{
    Trustee=[pscustomobject]@{{Sid='S-1-5-11';SidType='WellKnownGroup'}}
    Permission='SomLink';Denied=$false;Inherited=$false
  }}
)) {{
  try {{ ConvertFrom-SLIGpoPermissionObjects @($row) | Out-Null }}
  catch {{ $errors += $_.Exception.Message }}
}}
$errors | ConvertTo-Json -Compress
"""
    completed = subprocess.run(
        [str(powershell), "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True, text=True, timeout=60, check=True,
    )
    assert json.loads(completed.stdout) == [
        "invalid_gpo_permission_sid",
        "unsupported_gpo_permission_type",
    ]


@pytest.mark.windows_only
def test_gpo_permission_job_boundary_preserves_normalized_sid_text():
    powershell = (
        Path(os.environ.get("WINDIR") or r"C:\Windows")
        / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    )
    module = Path("scripts/ad_context/GpoReportContract.psm1").resolve()
    command = f"""
Import-Module '{module}' -Force -ErrorAction Stop
$job=Start-Job -ScriptBlock {{
  $sid=[Security.Principal.SecurityIdentifier]'S-1-5-11'
  [pscustomobject]@{{
    Trustee=[pscustomobject]@{{
      Sid=[string]$sid.Value
      SidType='WellKnownGroup'
    }}
    Permission='GpoApply'
    Denied=$false
    Inherited=$false
  }}
}}
try {{
  $null=Wait-Job $job -Timeout 10
  $converted=ConvertFrom-SLIGpoPermissionObjects @(
    Receive-Job $job -ErrorAction Stop
  )
  $converted | ConvertTo-Json -Depth 8 -Compress
}} finally {{ Remove-Job $job -Force -ErrorAction SilentlyContinue }}
"""
    completed = subprocess.run(
        [str(powershell), "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True, text=True, timeout=60, check=True,
    )
    converted = json.loads(completed.stdout)

    assert converted["gpo_apply_allow_sids"] == ["S-1-5-11"]
    assert converted["permission_count"] == 1


@pytest.mark.windows_only
def test_gpo_governance_merge_preserves_observation_and_acl_boundaries():
    powershell = (
        Path(os.environ.get("WINDIR") or r"C:\Windows")
        / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    )
    module = Path("scripts/ad_context/GpoReportContract.psm1").resolve()
    command = f"""
Import-Module '{module}' -Force -ErrorAction Stop
$base=[ordered]@{{
  display_name='Policy A'
  description='Observed through LDAP'
  modified_utc='2026-07-29T00:00:00Z'
}}
$report=[pscustomobject]@{{attributes=[pscustomobject][ordered]@{{
  modified_utc='2026-07-30T08:00:00Z'
  gpo_computer_enabled=$true
  gpo_user_enabled=$false
  link_count=2
  gpo_link_enabled_count=1
  gpo_link_enforced_count=1
  links=@('OU=A,DC=example,DC=local','OU=B,DC=example,DC=local')
  gpo_wmi_filter_present=$false
  gpo_wmi_filter_id=$null
  gpo_startup_script_count=1
  gpo_logon_script_count=0
  gpo_scheduled_task_count=2
  gpo_service_count=0
  gpo_local_group_count=1
  gpo_settings=@()
}}}}
$permission=[pscustomobject]@{{
  permission_count=3
  permissions=@(
    [pscustomobject]@{{permission='GpoApply'}},
    [pscustomobject]@{{permission='GpoCustom'}},
    [pscustomobject]@{{permission='GpoCustom'}}
  )
  gpo_apply_allow_sids=@('S-1-5-11')
  gpo_apply_deny_sids=@('S-1-5-18')
  effective_access_evaluated=$false
}}
Merge-SLIGpoGovernanceAttributes -BaseAttributes $base `
  -ReportFacts $report -PermissionFacts $permission |
  ConvertTo-Json -Depth 8 -Compress
"""
    completed = subprocess.run(
        [str(powershell), "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True, text=True, timeout=60, check=True,
    )
    attributes = json.loads(completed.stdout)

    assert attributes["display_name"] == "Policy A"
    assert attributes["description"] == "Observed through LDAP"
    assert attributes["modified_utc"] == "2026-07-30T08:00:00Z"
    assert attributes["application_state"] == "computer_only"
    assert attributes["gpo_security_filtering_sids"] == ["S-1-5-11"]
    assert attributes["gpo_security_filtering_deny_sids"] == ["S-1-5-18"]
    assert attributes["gpo_security_filtering_collected"] is True
    assert attributes["gpo_security_filtering_effective_evaluated"] is False
    assert attributes["gpo_permission_count"] == 3
    assert attributes["gpo_permission_custom_count"] == 2


def test_gpo_report_attributes_are_allowlisted_without_priority_formula():
    bundle = _supplemental_bundle()
    gpo = next(row for row in bundle["records"] if row["section"] == "gpo_governance")
    gpo["attributes"].update({
        "application_state": "computer_only",
        "gpo_computer_enabled": True, "gpo_user_enabled": False,
        "gpo_link_enabled_count": 1, "gpo_link_enforced_count": 1,
        "gpo_security_filtering_sids": ["S-1-5-11"],
        "gpo_security_filtering_deny_sids": ["S-1-5-18"],
        "gpo_security_filtering_collected": True,
        "gpo_security_filtering_effective_evaluated": False,
        "gpo_permission_count": 3,
        "gpo_permission_custom_count": 1,
        "gpo_wmi_filter_present": True,
        "gpo_wmi_filter_id": "{00000000-0000-4000-8000-000000000042}",
        "gpo_startup_script_count": 1, "gpo_logon_script_count": 1,
        "gpo_scheduled_task_count": 1, "gpo_service_count": 1,
        "gpo_local_group_count": 1,
        "gpo_settings": [{
            "scope": "computer", "kind": "Task", "path": "ScheduledTasks/Task",
            "properties": {"action": "U", "appname": "powershell.exe"},
            "redacted_fields": ["cpassword"], "truncated_fields": [],
            "sensitive_value_present": True,
            "sha256": "a" * 64,
        }],
    })
    normalized = validate_bundle(bundle)
    attributes = next(
        row["attributes"] for row in normalized["records"]
        if row["section"] == "gpo_governance"
    )
    assert attributes["gpo_security_filtering_sids"] == ["S-1-5-11"]
    assert attributes["gpo_security_filtering_deny_sids"] == ["S-1-5-18"]
    assert attributes["gpo_security_filtering_effective_evaluated"] is False
    assert attributes["application_state"] == "computer_only"
    assert attributes["gpo_settings"][0]["properties"]["appname"] == "powershell.exe"
    assert attributes["gpo_settings"][0]["truncated_fields"] == []
    assert "priority" not in attributes


def test_gpo_settings_contract_rejects_raw_sensitive_values():
    bundle = _supplemental_bundle()
    gpo = next(row for row in bundle["records"] if row["section"] == "gpo_governance")
    gpo["attributes"]["gpo_settings"] = [{
        "scope": "computer", "kind": "Task", "path": "ScheduledTasks/Task",
        "properties": {"cpassword": "must-not-enter-bundle"},
        "redacted_fields": [], "sensitive_value_present": False,
        "sha256": "b" * 64,
    }]
    with pytest.raises(AdContextContractError, match="sensitive"):
        validate_bundle(bundle)


def test_file_contract_requires_matching_sha256_sidecar(tmp_path: Path):
    target = tmp_path / "bundle.json"
    target.write_bytes(FIXTURE.read_bytes())
    with pytest.raises(AdContextContractError, match="sidecar is required"):
        load_bundle(target)
    target.with_name("bundle.json.sha256").write_text("0" * 64, encoding="ascii")
    with pytest.raises(AdContextContractError, match="SHA-256 mismatch"):
        load_bundle(target)


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (lambda value: value.update({"password": "secret"}), "unsupported fields"),
        (lambda value: value["records"][0]["identity"].update({"token": "secret"}), "unsupported fields"),
        (lambda value: value["records"][0]["identity"].update({"object_guid": ""}), "object_guid"),
        (lambda value: value.pop("scope"), "scope"),
    ],
)
def test_contract_fails_closed_for_unknown_or_unstable_identity(mutate, expected):
    bundle = _bundle()
    mutate(bundle)
    with pytest.raises(AdContextContractError, match=expected):
        validate_bundle(bundle)


def test_projection_is_idempotent_and_observation_time_does_not_create_versions():
    projection = ContextProjection()
    first = _bundle()
    assert projection.apply(first)["relations_changed"] == 1
    second = copy.deepcopy(first)
    second["run_id"] = "00000000-0000-4000-8000-000000000047"
    second["observed_at_utc"] = "2026-07-18T06:00:00Z"
    for record in second["records"]:
        record["observed_at_utc"] = second["observed_at_utc"]
    result = projection.apply(second)
    assert result["entities_changed"] == 0
    assert result["relations_changed"] == 0
    assert len(next(iter(projection.entity_versions.values()))) == 1
    assert projection.apply(second)["replayed"] == 1


def test_projection_rejects_out_of_order_observation():
    projection = ContextProjection()
    first = _bundle()
    projection.apply(first)
    older = copy.deepcopy(first)
    older["run_id"] = "00000000-0000-4000-8000-000000000052"
    older["observed_at_utc"] = "2026-07-18T04:59:59Z"
    for record in older["records"]:
        record["observed_at_utc"] = older["observed_at_utc"]
    with pytest.raises(ValueError, match="out-of-order"):
        projection.apply(older)


def test_partial_bundle_never_closes_missing_membership_but_complete_full_does():
    projection = ContextProjection()
    projection.apply(_bundle())
    partial = _bundle()
    partial["run_id"] = "00000000-0000-4000-8000-000000000048"
    partial["mode"] = "targeted"
    partial["sections"][0].update(status="partial", record_count=2)
    partial["records"] = partial["records"][:2]
    assert projection.apply(partial)["relations_closed"] == 0
    complete = copy.deepcopy(partial)
    complete["run_id"] = "00000000-0000-4000-8000-000000000049"
    complete["mode"] = "full"
    complete["sections"][0]["status"] = "complete"
    assert projection.apply(complete)["relations_closed"] == 1


def test_complete_reconcile_is_bounded_to_declared_group_scope():
    projection = ContextProjection()
    first = _bundle()
    projection.apply(first)

    second = copy.deepcopy(first)
    second["run_id"] = "00000000-0000-4000-8000-000000000050"
    second["observed_at_utc"] = "2026-07-18T06:00:00Z"
    group = second["records"][0]
    old_group_key = group["record_key"]
    group["record_key"] = "ad:s-1-5-21-111-222-333:00000000-0000-4000-8000-000000000062"
    group["identity"]["object_guid"] = "00000000-0000-4000-8000-000000000062"
    group["identity"]["object_sid"] = "S-1-5-21-100000003-200000003-300000003-519"
    group["attributes"]["display_name"] = "Enterprise Admins"
    relation = second["records"][2]
    relation["record_key"] = "member-of:alice:enterprise-admins"
    relation["target_record_key"] = group["record_key"]
    second["scope"]["privileged_group_sids"] = [group["identity"]["object_sid"]]
    for record in second["records"]:
        record["observed_at_utc"] = second["observed_at_utc"]
    assert old_group_key != group["record_key"]
    projection.apply(second)

    empty_first_scope = copy.deepcopy(first)
    empty_first_scope["run_id"] = "00000000-0000-4000-8000-000000000051"
    empty_first_scope["observed_at_utc"] = "2026-07-18T07:00:00Z"
    empty_first_scope["records"] = empty_first_scope["records"][:2]
    empty_first_scope["sections"][0]["record_count"] = 2
    for record in empty_first_scope["records"]:
        record["observed_at_utc"] = empty_first_scope["observed_at_utc"]
    result = projection.apply(empty_first_scope)
    assert result["relations_closed"] == 1
    assert projection.relation_versions["member-of:alice:enterprise-admins"][-1].valid_to_utc is None


def test_enrichment_requires_exact_sid_pivots_and_marks_current_only_limit():
    event = {"event_id": 4728, "event_data": {"MemberSid": "S-1-U", "TargetSid": "S-1-G"}}
    relation = {"member_sid": "S-1-U", "group_sid": "S-1-G", "current_active": True, "evidence_id": 7}
    result = explain_privileged_membership_event(event, relation=relation, historical_context_available=False)
    assert result["matched"] is True
    assert result["confidence_kind"] == "incomplete_context"
    assert result["limitation"]
    display_only = {"event_id": 4728, "event_data": {"MemberName": "Alice", "TargetUserName": "Admins"}}
    assert explain_privileged_membership_event(display_only, relation=relation, historical_context_available=True)["matched"] is False


def test_collector_is_read_only_structured_and_has_no_html_or_laps_collection():
    source = Path("scripts/ad_context/Export-AdContextBundle.ps1").read_text(encoding="utf-8").casefold()
    for forbidden in ("set-ad", "new-ad", "remove-ad", "add-ad", "html", "ms-mcs-admpwd", "mslaps-password"):
        assert forbidden not in source
    assert "get-adobject" in source
    assert "-resultsetsize $querylimit" in source
    assert "writealltext" in source
    assert "privileged_group_sids" in source
    assert "system.security.cryptography.sha256" in source
    assert "get-filehash" not in source
    assert 'outputpath + ".sha256"' in source


def test_ad_audit_collector_is_read_only_bounded_and_does_not_parse_existing_reports():
    source = Path("scripts/ad_context/Export-AdAuditContextBundle.ps1").read_text(encoding="utf-8").casefold()
    for forbidden in (
        "set-ad", "new-ad", "remove-ad", "disable-ad", "enable-ad", "move-ad", "rename-ad",
        "set-gp", "new-gp", "remove-gp", "set-acl", "get-adgroupmember", "convertto-html",
        "ms-mcs-admpwd", "mslaps-password",
    ):
        assert forbidden not in source
    assert "get-aduser" in source and "-resultsetsize $querylimit" in source
    assert "get-gpo -all" not in source
    assert 'ldapfilter "(objectclass=grouppolicycontainer)"' in source
    assert "-resultsetsize $gpoquerylimit" in source
    assert "$rawxml = get-gporeport" not in source
    assert "$maxgpos" in source
    assert "vpn_group_sids" in source
    assert "system.security.cryptography.sha256" in source




def test_domain_health_contract_accepts_its_exact_collection_profile():
    observed = "2026-08-28T06:00:00Z"
    domain_sid = "S-1-5-21-111-222-333"
    bundle = {
        "schema_version": "ad-context-bundle/v1",
        "source_pack_id": "sli.windows.ad-context",
        "source_pack_version": "0.5.0",
        "run_id": "00000000-0000-4000-8000-000000000102",
        "mode": "targeted",
        "domain": {"sid": domain_sid, "dns_name": "example.test"},
        "scope": {
            "search_base": "DC=example,DC=test",
            "privileged_group_sids": [],
            "vpn_group_sids": [],
            "collection_profile": "domain_health_v1",
        },
        "observed_at_utc": observed,
        "sections": [{
            "name": "domain_health",
            "status": "complete",
            "record_count": 0,
            "duration_ms": 25,
            "error_code": None,
        }],
        "records": [],
    }

    normalized = validate_bundle(bundle)
    assert normalized["scope"]["collection_profile"] == "domain_health_v1"
    assert normalized["sections"][0]["name"] == "domain_health"

    bundle["scope"]["collection_profile"] = "domain_posture_v1"
    with pytest.raises(AdContextContractError, match="collection_profile"):
        validate_bundle(bundle)


def test_active_directory_contract_accepts_only_bounded_infrastructure_facts():
    observed = "2026-08-28T06:00:00Z"
    domain_sid = "S-1-5-21-111-222-333"
    records = [
        {
            "record_type": "entity",
            "record_key": "ad-domain:example.test",
            "section": "domain_posture",
            "observed_at_utc": observed,
            "identity": {"kind": "domain", "domain_sid": domain_sid, "object_guid": "00000000-0000-4000-8000-000000000201", "object_sid": domain_sid},
            "attributes": {
                "display_name": "example.test", "forest_name": "example.test", "netbios_name": "EXAMPLE",
                "domain_mode": "Windows2016Domain", "forest_mode": "Windows2016Forest",
                "pdc_emulator": "dc1.example.test", "rid_master": "dc1.example.test",
                "infrastructure_master": "dc1.example.test", "schema_master": "dc1.example.test",
                "domain_naming_master": "dc1.example.test", "recycle_bin_enabled": True,
                "machine_account_quota": 10, "ldap_signing_requirement": "require_signing",
                "ldap_channel_binding_requirement": "when_supported",
            },
        },
        {
            "record_type": "entity",
            "record_key": "ad-dc:dc1.example.test",
            "section": "domain_health",
            "observed_at_utc": observed,
            "identity": {"kind": "domain_controller", "domain_sid": domain_sid, "object_guid": "00000000-0000-4000-8000-000000000202", "object_sid": f"{domain_sid}-1001"},
            "attributes": {
                "display_name": "DC1", "dns_host_name": "dc1.example.test", "site_name": "Default-First-Site-Name",
                "is_global_catalog": True, "is_read_only": False, "operation_master_roles": ["PDCEmulator", "RIDMaster"],
                "advertising_state": "passed", "connectivity_state": "passed", "services_state": "passed",
                "sysvol_state": "passed", "netlogon_state": "passed", "dns_state": "passed", "health_error_codes": [],
            },
        },
        {
            "record_type": "entity",
            "record_key": "ad-repl:dc1:dc2:domain",
            "section": "domain_health",
            "observed_at_utc": observed,
            "identity": {"kind": "replication_link", "domain_sid": domain_sid, "object_guid": "00000000-0000-4000-8000-000000000203", "object_sid": None},
            "attributes": {
                "display_name": "DC2 → DC1", "source_dc": "dc2.example.test", "destination_dc": "dc1.example.test",
                "naming_context": "DC=example,DC=test", "last_replication_attempt_utc": observed,
                "last_replication_success_utc": observed, "consecutive_failure_count": 0,
                "last_replication_result": 0, "replication_state": "passed",
            },
        },
    ]
    bundle = {
        "schema_version": "ad-context-bundle/v1", "source_pack_id": "sli.windows.ad-context",
        "source_pack_version": "0.5.0", "run_id": "00000000-0000-4000-8000-000000000103",
        "mode": "full", "domain": {"sid": domain_sid, "dns_name": "example.test"},
        "scope": {"search_base": "DC=example,DC=test", "privileged_group_sids": [], "vpn_group_sids": []},
        "observed_at_utc": observed,
        "sections": [
            {"name": "domain_posture", "status": "complete", "record_count": 1, "duration_ms": 20, "error_code": None},
            {"name": "domain_health", "status": "complete", "record_count": 2, "duration_ms": 30, "error_code": None},
        ],
        "records": records,
    }

    normalized = validate_bundle(bundle)
    assert {record["identity"]["kind"] for record in normalized["records"]} == {"domain", "domain_controller", "replication_link"}

    bundle["records"][0]["attributes"]["unbounded_vendor_score"] = 100
    with pytest.raises(AdContextContractError, match="unsupported fields"):
        validate_bundle(bundle)
