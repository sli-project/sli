from inspect import getsource
from pathlib import Path


COLLECTOR = Path("scripts/ad_context/Export-AdAuditContextBundle.ps1")


def test_directory_snapshot_reserves_independent_user_and_computer_limits() -> None:
    source = COLLECTOR.read_text(encoding="utf-8")

    assert "$userLimit = if ($MaxDirectoryUsers -gt 0)" in source
    assert "$computerLimit = if ($MaxDirectoryComputers -gt 0)" in source
    assert "Select-Object -First $userLimit" in source
    assert "Select-Object -First $computerLimit" in source
    assert "directory_accounts_truncated" in source


def test_directory_user_query_excludes_computer_subclass() -> None:
    source = COLLECTOR.read_text(encoding="utf-8")

    assert 'Get-ADUser -Server $DirectoryServer -LDAPFilter "(&(objectCategory=person)(objectClass=user))"' in source


def test_inactivity_uses_creation_time_when_no_logon_exists() -> None:
    source = COLLECTOR.read_text(encoding="utf-8")

    assert '$createdAt = Get-OptionalProperty -Object $Object -Name "whenCreated"' in source
    assert '$inactivityBasis = "creation_time_without_logon"' in source
    assert '$inactivityBasis = "insufficient_time_evidence"' in source
    assert "inactivity_basis = $inactivityBasis" in source
    assert "created_utc = ConvertTo-OptionalUtcText $createdAt" in source
    assert '"whenCreated", "LastLogonDate"' in source


def test_current_entity_details_replace_the_previous_snapshot() -> None:
    from server.ad_context.repository import persist_entity_identity

    source = getsource(persist_entity_identity)

    assert "attributes_json=excluded.attributes_json" in source
    assert (
        "attributes_json=entity_details_v2.attributes_json || "
        "excluded.attributes_json"
    ) not in source


def test_supplemental_entity_details_preserve_directory_attributes() -> None:
    from server.ad_context.repository import materialize_entity_attributes

    existing = {
        "display_name": "Old name",
        "exact_last_logon_status": "observed",
        "exact_last_logon_utc": "2026-08-31T08:00:00Z",
    }
    incoming = {"display_name": "Current name", "sam_account_name": "user1"}

    for section in (
        "directory_group_graph",
        "directory_exact_logon",
        "privileged_membership",
        "vpn_membership",
    ):
        assert materialize_entity_attributes(existing, incoming, section=section) == {
            "display_name": "Current name",
            "sam_account_name": "user1",
            "exact_last_logon_status": "observed",
            "exact_last_logon_utc": "2026-08-31T08:00:00Z",
        }

    assert materialize_entity_attributes(
        existing, incoming, section="directory_accounts"
    ) == incoming


def test_running_exporter_uses_only_bounded_read_only_gpo_contract() -> None:
    exporter = COLLECTOR.read_text(encoding="utf-8")
    module = Path(
        "scripts/ad_context/GpoReportContract.psm1"
    ).read_text(encoding="utf-8")

    assert "GpoReportContract.psm1" in exporter
    assert "Invoke-SLIBoundedGpoReportRead" in exporter
    assert "Invoke-SLIBoundedGpoPermissionRead" in exporter
    assert "Merge-SLIGpoGovernanceAttributes" in exporter
    assert "$combinedTimeLimitSeconds = 240" in exporter
    assert "gpo_governance_total_time_ceiling_exceeded" in exporter
    for prohibited in (
        "Set-GPO", "New-GPO", "Remove-GPO", "Set-GPLink", "New-GPLink",
        "Remove-GPLink", "Set-GPRegistryValue", "Set-GPPermission",
    ):
        assert prohibited not in module
    assert "Get-GPOReport" in module
    assert "ConvertFrom-SLIGpoPermissionObjects" in module
    assert "Sid = [string]$_.Trustee.Sid.Value" in module
    assert "Permission = [string]$_.Permission" in module
    assert "Stop-Job" in module
    assert "single_response_bytes_limit" in module


def test_vpn_membership_keeps_exact_ad_contacts_without_data_quality_downgrade() -> None:
    source = COLLECTOR.read_text(encoding="utf-8")

    assert '"contact" {' in source
    contact_case = source.split('"contact" {', 1)[1].split("default {", 1)[0]
    assert "Get-ADObject" in contact_case
    assert "$unsupportedPrincipalCount += 1" not in contact_case
