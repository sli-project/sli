from __future__ import annotations

import argparse
import hashlib
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.maintenance import ad_context_live_canary as canary
from server.source_packs.adapters import AdContextRequest, build_ad_context_command


def _args(**overrides) -> argparse.Namespace:
    now = datetime.now(timezone.utc)
    values = {
        "directory_server": "dc1.host13.example.invalid",
        "domain": "host13.example.invalid",
        "search_base": "DC=example,DC=local",
        "section": [],
        "group_sid": ["S-1-5-21-100000003-200000003-300000003-512"],
        "vpn_group_sid": [],
        "expected_account": "EXAMPLE\\svc_sli_read",
        "timeout_seconds": 120,
        "max_records": 2000,
        "max_bundle_bytes": 2 * 1024 * 1024,
        "max_directory_accounts": 2000,
        "max_directory_users": 1000,
        "max_directory_computers": 1000,
        "max_vpn_members": 500,
        "max_gpos": 500,
        "output_root": canary.DEFAULT_OUTPUT_ROOT,
        "not_before_utc": (now - timedelta(minutes=5)).isoformat(),
        "not_after_utc": (now + timedelta(minutes=30)).isoformat(),
        "execute": False,
        "validate_only": True,
        "confirmation": "",
        "approved_request_sha256": "",
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def _approve(args: argparse.Namespace) -> argparse.Namespace:
    args.approved_request_sha256 = canary.approval_request_sha256(canary.validate_request(args))
    return args


def _absolute_powershell() -> str:
    if os.name == "nt":
        return str(Path(os.environ.get("WINDIR") or r"C:\Windows") / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe")
    return "/usr/bin/pwsh"


def test_validate_only_has_no_external_or_storage_side_effects():
    result = canary.run(_args())
    assert result["status"] == "validated_only"
    assert result["live_ad_contacted"] is False
    assert result["database_imported"] is False
    assert result["scheduler_changed"] is False
    assert result["runtime_restarted"] is False
    assert result["html_generated"] is False
    assert result["approval_hash_verified"] is False
    assert len(result["approval_request_sha256"]) == 64


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("group_sid", ["Domain Admins"], "exact privileged group SIDs"),
        ("timeout_seconds", 301, "timeout_seconds"),
        ("max_records", 5001, "max_records"),
        ("directory_server", "dc1; whoami", "directory_server"),
        ("not_after_utc", (datetime.now(timezone.utc) + timedelta(hours=3)).isoformat(), "two hours"),
    ],
)
def test_canary_parameters_fail_closed(field, value, message):
    with pytest.raises(ValueError, match=message):
        canary.validate_request(_args(**{field: value}))


@pytest.mark.parametrize(
    ("section", "field", "message"),
    [
        ("privileged_membership", "group_sid", "privileged group"),
        ("vpn_membership", "vpn_group_sid", "VPN group"),
    ],
)
def test_canary_group_reference_limit_is_fifty(section, field, message):
    values = [f"S-1-5-21-111-222-333-{1000 + index}" for index in range(50)]
    overrides = {"section": [section], "group_sid": [], "vpn_group_sid": [], field: values}
    request = canary.validate_request(_args(**overrides))
    assert len(request["group_sids" if field == "group_sid" else "vpn_group_sids"]) == 50

    with pytest.raises(ValueError, match=message):
        canary.validate_request(_args(**{**overrides, field: [*values, "S-1-5-21-100000003-200000003-300000003-2000"]}))


def test_full_directory_bundle_budget_matches_exporter_ceiling():
    request = canary.validate_request(
        _args(
            section=["directory_accounts"],
            group_sid=[],
            max_records=5000,
            max_directory_accounts=5000,
            max_directory_users=3600,
            max_directory_computers=1400,
            max_bundle_bytes=25 * 1024 * 1024,
        )
    )

    assert request["max_bundle_bytes"] == 25 * 1024 * 1024
    assert request["max_directory_users"] == 3600
    assert request["max_directory_computers"] == 1400
    with pytest.raises(ValueError, match="max_bundle_bytes"):
        canary.validate_request(
            _args(max_bundle_bytes=25 * 1024 * 1024 + 1)
        )


def test_execute_requires_confirmation_before_windows_or_ad_checks():
    with pytest.raises(ValueError, match=canary.CONFIRMATION):
        canary.run(_args(execute=True, validate_only=False))


def test_supplemental_validate_only_requires_exact_vpn_sid_and_hashes_all_limits():
    args = _args(
        section=["vpn_membership"],
        group_sid=[],
        vpn_group_sid=["S-1-5-21-100000003-200000003-300000003-1601"],
        max_records=1000,
        max_directory_accounts=400,
        max_vpn_members=200,
        max_gpos=100,
    )
    result = canary.run(args)
    assert result["status"] == "validated_only"
    assert result["live_ad_contacted"] is False
    assert result["approved_scope"]["sections"] == ("vpn_membership",)
    assert result["approved_scope"]["vpn_group_sids"] == ("S-1-5-21-100000003-200000003-300000003-1601",)
    assert result["approved_scope"]["collection_mode"] == "targeted"
    assert result["approved_scope"]["collection_profile"] == "vpn_security_v1"
    assert result["approved_scope"]["source_pack_version"] == "0.10.0"
    changed = _args(**{**vars(args), "max_gpos": 99})
    assert canary.approval_request_sha256(canary.validate_request(changed)) != result["approval_request_sha256"]


def test_supplemental_validate_only_rejects_named_vpn_group_and_oversized_section():
    with pytest.raises(ValueError, match="exact VPN group SIDs"):
        canary.validate_request(_args(section=["vpn_membership"], group_sid=[], vpn_group_sid=["VPNl2tp"]))
    with pytest.raises(ValueError, match="section limits"):
        canary.validate_request(_args(section=["gpo_governance"], group_sid=[], max_records=100, max_gpos=101))
    with pytest.raises(ValueError, match="exactly one section"):
        canary.validate_request(_args(section=["directory_accounts", "gpo_governance"], group_sid=[]))


def test_gpo_validate_only_uses_governance_profile_and_current_pack_version():
    result = canary.run(
        _args(
            section=["gpo_governance"],
            group_sid=[],
            max_records=100,
            max_gpos=72,
            timeout_seconds=300,
        )
    )

    assert result["status"] == "validated_only"
    assert result["live_ad_contacted"] is False
    assert result["approved_scope"]["collection_profile"] == "gpo_governance_v4"
    assert result["approved_scope"]["source_pack_version"] == "0.10.0"


@pytest.mark.parametrize(
    ("section", "profile"),
    [("domain_posture", "domain_posture_v1"), ("domain_health", "domain_health_v1")],
)
def test_active_directory_validate_only_uses_exact_infrastructure_profile(section, profile):
    result = canary.run(_args(section=[section], group_sid=[], timeout_seconds=300))

    assert result["status"] == "validated_only"
    assert result["approved_scope"]["sections"] == (section,)
    assert result["approved_scope"]["collection_mode"] == "full"
    assert result["approved_scope"]["collection_profile"] == profile
    assert result["approved_scope"]["source_pack_version"] == "0.10.0"


def test_execute_requires_owner_hash_of_exact_request_before_os_or_ad_checks():
    args = _args(execute=True, validate_only=False, confirmation=canary.CONFIRMATION)
    with pytest.raises(PermissionError, match="owner-approved SHA-256"):
        canary.run(args)


def test_execute_rejects_approved_request_outside_its_window():
    now = datetime.now(timezone.utc)
    args = _approve(
        _args(
            execute=True,
            validate_only=False,
            confirmation=canary.CONFIRMATION,
            not_before_utc=(now - timedelta(hours=2)).isoformat(),
            not_after_utc=(now - timedelta(hours=1)).isoformat(),
        )
    )
    with pytest.raises(PermissionError, match="window is not active"):
        canary.run(args)


def test_adapter_command_pins_server_scope_and_budgets():
    command = build_ad_context_command(
        AdContextRequest(
            powershell_executable=_absolute_powershell(),
            output_path=Path("bundle.json"),
            run_id="00000000-0000-4000-8000-000000000046",
            directory_server="dc1.host13.example.invalid",
            search_base="DC=example,DC=local",
            domain="host13.example.invalid",
            sections=("privileged_membership",),
            privileged_groups=("S-1-5-21-100000003-200000003-300000003-512",),
            mode="targeted",
            max_records=101,
            max_bundle_bytes=65536,
        )
    )
    assert command[command.index("-DirectoryServer") + 1] == "dc1.host13.example.invalid"
    assert command[command.index("-MaxRecords") + 1] == "101"
    assert command[command.index("-MaxBundleBytes") + 1] == "65536"
    assert command[command.index("-CollectionProfile") + 1] == "privileged_membership_v1"
    assert Path(command[0]).is_absolute()
    with pytest.raises(ValueError, match="absolute allowlisted"):
        build_ad_context_command(
            AdContextRequest(
                powershell_executable="powershell.exe",
                output_path=Path("bundle.json"),
                run_id="00000000-0000-4000-8000-000000000046",
                directory_server="dc1.host13.example.invalid",
                search_base="DC=example,DC=local",
                domain="host13.example.invalid",
                sections=("privileged_membership",),
                privileged_groups=("S-1-5-21-100000003-200000003-300000003-512",),
            )
        )


def test_supplemental_adapter_pins_vpn_group_threshold_and_repository_script():
    command = build_ad_context_command(
        AdContextRequest(
            powershell_executable=_absolute_powershell(),
            output_path=Path("audit-bundle.json"),
            run_id="00000000-0000-4000-8000-000000000054",
            directory_server="dc1.host13.example.invalid",
            search_base="DC=example,DC=local",
            domain="host13.example.invalid",
            sections=("vpn_membership",),
            vpn_groups=("VPNl2tp",),
            inactive_days=180,
            mode="full",
            max_records=5000,
            max_bundle_bytes=4 * 1024 * 1024,
        )
    )
    assert Path(command[command.index("-File") + 1]).name == "Export-AdAuditContextBundle.ps1"
    assert command[command.index("-VpnGroups") + 1] == "VPNl2tp"
    assert command[command.index("-InactiveDays") + 1] == "180"
    assert command[command.index("-CollectionProfile") + 1] == "vpn_security_v1"
    assert command[command.index("-MaxDirectoryAccounts") + 1] == "2000"
    assert command[command.index("-MaxVpnMembers") + 1] == "500"
    assert command[command.index("-MaxGpos") + 1] == "72"
    with pytest.raises(ValueError, match="exactly one bounded section"):
        build_ad_context_command(
            AdContextRequest(
                powershell_executable=_absolute_powershell(), output_path=Path("audit-bundle.json"),
                run_id="00000000-0000-4000-8000-000000000057", directory_server="dc1.host13.example.invalid",
                search_base="DC=example,DC=local", domain="host13.example.invalid",
                sections=("directory_accounts", "gpo_governance"), max_records=5000,
            )
        )
    with pytest.raises(ValueError, match="exact bounded VPN group"):
        build_ad_context_command(
            AdContextRequest(
                powershell_executable=_absolute_powershell(), output_path=Path("audit-bundle.json"),
                run_id="00000000-0000-4000-8000-000000000055", directory_server="dc1.host13.example.invalid",
                search_base="DC=example,DC=local", domain="host13.example.invalid",
                sections=("vpn_membership",), vpn_groups=("VPN,Other",),
            )
        )
    with pytest.raises(ValueError, match="section limit"):
        build_ad_context_command(
            AdContextRequest(
                powershell_executable=_absolute_powershell(), output_path=Path("audit-bundle.json"),
                run_id="00000000-0000-4000-8000-000000000056", directory_server="dc1.host13.example.invalid",
                search_base="DC=example,DC=local", domain="host13.example.invalid",
                sections=("gpo_governance",), max_records=100, max_gpos=101,
            )
        )
    with pytest.raises(ValueError, match="72-policy"):
        build_ad_context_command(
            AdContextRequest(
                powershell_executable=_absolute_powershell(), output_path=Path("audit-bundle.json"),
                run_id="00000000-0000-4000-8000-000000000058", directory_server="dc1.host13.example.invalid",
                search_base="DC=example,DC=local", domain="host13.example.invalid",
                sections=("gpo_governance",), max_records=200, max_gpos=73,
            )
        )


def test_directory_accounts_adapter_uses_independent_user_and_computer_ceilings():
    command = build_ad_context_command(
        AdContextRequest(
            powershell_executable=_absolute_powershell(),
            output_path=Path("directory-bundle.json"),
            run_id="00000000-0000-4000-8000-000000000106",
            directory_server="dc2.example.test",
            search_base="DC=example,DC=test",
            domain="example.test",
            sections=("directory_accounts",),
            max_records=5000,
            max_directory_users=3600,
            max_directory_computers=1400,
        )
    )

    assert command[command.index("-MaxDirectoryUsers") + 1] == "3600"
    assert command[command.index("-MaxDirectoryComputers") + 1] == "1400"


def test_bundle_summary_distinguishes_transport_and_normalized_hashes():
    path = Path("tests/fixtures/ad_context_privileged_membership.json")
    result = canary.summarize_bundle(
        path,
        {
            "domain": "host13.example.invalid",
            "search_base": "DC=example,DC=local",
            "sections": ("privileged_membership",),
            "collection_mode": "full",
            "collection_profile": None,
            "source_pack_version": "0.1.0",
            "group_sids": ("S-1-5-21-100000003-200000003-300000003-512",),
            "vpn_group_sids": (),
            "max_records": 100,
            "max_bundle_bytes": 65536,
        },
        "00000000-0000-4000-8000-000000000046",
    )
    assert result["transport_file_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert len(result["normalized_content_sha256"]) == 64
    assert "bundle_sha256" not in result


@pytest.mark.parametrize("status", ["partial", "failed"])
def test_live_canary_rejects_incomplete_approved_section(status):
    measurements = {
        "section_statuses": {"gpo_governance": status},
    }
    with pytest.raises(RuntimeError, match=f"gpo_governance={status}"):
        canary.require_complete_sections(
            measurements,
            {"sections": ("gpo_governance",)},
        )


def test_live_canary_accepts_only_complete_approved_section():
    canary.require_complete_sections(
        {"section_statuses": {"gpo_governance": "complete"}},
        {"sections": ("gpo_governance",)},
    )


def test_timeout_termination_uses_windows_process_tree_kill(monkeypatch: pytest.MonkeyPatch):
    calls: list[list[str]] = []

    class Process:
        pid = 1234

        @staticmethod
        def poll():
            return None

        @staticmethod
        def wait(timeout):
            return 0

        @staticmethod
        def kill():
            raise AssertionError("taskkill should terminate the tree")

    monkeypatch.setattr(canary, "os", SimpleNamespace(**{**vars(canary.os), "name": "nt"}))
    monkeypatch.setattr(
        canary.subprocess,
        "run",
        lambda command, **kwargs: calls.append(command) or SimpleNamespace(returncode=0),
    )
    canary.terminate_process_tree(Process())
    assert calls == [["taskkill", "/PID", "1234", "/T", "/F"]]


def test_existing_lock_blocks_execution_before_collector(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setattr(canary, "DEFAULT_OUTPUT_ROOT", tmp_path)
    monkeypatch.setattr(canary, "os", SimpleNamespace(**{**vars(canary.os), "name": "nt"}))
    monkeypatch.setattr(canary, "current_windows_account", lambda: "EXAMPLE\\svc_sli_read")
    monkeypatch.setattr(canary, "trusted_windows_powershell", lambda: tmp_path / "powershell.exe")
    monkeypatch.setattr(canary, "powershell_version", lambda executable: "5.1.0")
    (tmp_path / "ADCTX-LIVE-CANARY-1.lock").write_text("busy", encoding="utf-8")
    args = _approve(
        _args(
            output_root=tmp_path,
            execute=True,
            validate_only=False,
            confirmation=canary.CONFIRMATION,
        )
    )
    with pytest.raises(RuntimeError, match="lock already exists"):
        canary.run(args)




def test_powershell_wrapper_has_validate_only_and_absolute_root_before_location():
    source = Path("scripts/maintenance/Run-SLI-AdContext-LiveCanary-v1.ps1").read_text(encoding="utf-8-sig")
    assert "[switch]$ValidateOnly" in source
    assert "[switch]$Execute" in source
    assert source.index("GetFullPath($ProjectRoot)") < source.index("Set-Location -LiteralPath $ProjectRoot")
    assert "ADCTX-LIVE-CANARY-READ-ONLY" not in source  # confirmation is passed explicitly by the operator.
    assert "$ApprovedRequestSha256" in source
    assert "$NotBeforeUtc" in source
    assert "$NotAfterUtc" in source
    assert "[ValidateRange(1, 72)][int]$MaxGpos = 72" in source


@pytest.mark.parametrize(
    ("section", "profile"),
    (("domain_posture", "domain_posture_v1"), ("domain_health", "domain_health_v1")),
)
def test_active_directory_sections_use_exact_repository_profiles(section: str, profile: str):
    command = build_ad_context_command(
        AdContextRequest(
            powershell_executable=_absolute_powershell(),
            output_path=Path("active-directory-bundle.json"),
            run_id="00000000-0000-4000-8000-000000000102",
            directory_server="dc1.example.test",
            search_base="DC=example,DC=test",
            domain="example.test",
            sections=(section,),
            mode="targeted",
            max_records=5000,
        )
    )

    assert Path(command[command.index("-File") + 1]).name == "Export-AdAuditContextBundle.ps1"
    assert command[command.index("-CollectionProfile") + 1] == profile
    assert command[command.index("-Sections") + 1] == section


def test_collector_uses_server_bounded_member_query_not_unbounded_group_member_cmdlet():
    source = Path("scripts/ad_context/Export-AdContextBundle.ps1").read_text(encoding="utf-8")
    assert "Get-ADGroupMember -Server" not in source
    assert "-ResultSetSize $queryLimit" in source
    assert "member query exceeded the approved record budget" in source


def test_supplemental_collector_has_independent_section_budgets_and_server_bounded_gpo_inventory():
    source = Path("scripts/ad_context/Export-AdAuditContextBundle.ps1").read_text(encoding="utf-8")
    for parameter in ("$MaxDirectoryAccounts", "$MaxVpnMembers", "$MaxGpos"):
        assert parameter in source
    assert "$rawXml = Get-GPOReport" not in source
    assert "Get-GPO -All" not in source
    assert 'LDAPFilter "(objectClass=groupPolicyContainer)"' in source
    assert "-Properties Name, ObjectGUID" in source
    assert "-ResultSetSize $gpoQueryLimit" in source
    assert "link_count = 0" not in source and "links = @()" not in source
    assert "GPO inventory exceeded the approved section budget" in source
    assert "Invoke-SLIBoundedGpoReportRead" in source
    assert "Invoke-SLIBoundedGpoPermissionRead" in source
    assert "$gpoDirectoryObjectGuid = [guid]$gpo.ObjectGUID" in source
    assert "$gpoPolicyGuid = [guid]([string]$gpo.Name)" in source
    assert "Invoke-SLIBoundedGpoReportRead -Guid $gpoPolicyGuid" in source
    assert "Invoke-SLIBoundedGpoPermissionRead -Guid $gpoPolicyGuid" in source
    assert "Get-StableRecordKey -DomainSid $domainSid -ObjectGuid $gpoDirectoryObjectGuid" in source
    assert "gpo_governance_total_time_ceiling_exceeded" in source
    assert "Get-ADComputer -Server $DirectoryServer" in source
    assert "-ResultSetSize ($computerLimit + 1)" in source
    assert "$computersTruncated = (-not $isBaseProfile) -and $computers.Count -gt $computerLimit" in source
    assert "if (-not $isBaseProfile) { $computers = @($computers | Select-Object -First $computerLimit) }" in source
    assert 'if ($baseComputers.Count -gt $computerLimit) { throw "ad_snapshot_base_v1_computer_record_bound_exceeded" }' in source
    assert 'if ($baseUsers.Count -gt $userLimit) { throw "ad_snapshot_base_v1_user_record_bound_exceeded" }' in source
    assert '-Code "directory_accounts_truncated"' in source
    for attribute in ("dns_host_name", "operating_system", "operating_system_version"):
        assert attribute in source
