from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "maintenance" / "New-SLI-RadiusAccountingReadOnlyShare.ps1"
SOURCE = SCRIPT.read_text(encoding="utf-8")


def test_share_script_is_exact_plan_first_and_radius_scoped() -> None:
    assert SOURCE.startswith("#requires -Version 5.0\n")
    assert "[ValidateSet('Plan', 'Apply')]" in SOURCE
    assert "[string]$Action = 'Plan'" in SOURCE
    assert "$ExpectedComputerName = 'radius01'" in SOURCE
    assert "'EXAMPLE\\example-admin'" in SOURCE
    assert "'EXAMPLE\\operator'" in SOURCE
    assert "$ReadAccount = 'EXAMPLE\\operator'" in SOURCE
    assert "$ShareName = 'SLI-RadiusAccounting$'" in SOURCE
    assert "CREATE-SLI-RADIUS-ACCOUNTING-READONLY-SHARE" in SOURCE
    assert "-Filter 'IN*.log'" in SOURCE
    assert "$ExpectedTimeZoneId = 'N. Central Asia Standard Time'" in SOURCE
    assert "$ExpectedUtcOffsetMinutes = 420" in SOURCE
    assert "[System.TimeZoneInfo]::Local" in SOURCE
    assert "timezone_id_mismatch" in SOURCE
    assert "timezone_offset_mismatch" in SOURCE
    assert "timezone_drift_check_accepted = $true" in SOURCE


def test_share_script_never_changes_ntfs_or_nps_service() -> None:
    lowered = SOURCE.casefold()
    for forbidden in (
        "set-acl",
        "icacls",
        "start-service",
        "stop-service",
        "restart-service",
        "set-service",
        "grant-smbshareaccess",
    ):
        assert forbidden not in lowered
    assert "ntfs_acl_changed_unexpectedly" in SOURCE
    assert "ias_service_status_changed_unexpectedly" in SOURCE


def test_share_script_creates_only_exact_read_share_and_rolls_back_bad_share() -> None:
    assert "New-SmbShare" in SOURCE
    assert "-ReadAccess $ReadAccount" in SOURCE
    assert "-FolderEnumerationMode AccessBased" in SOURCE
    assert "-CachingMode None" in SOURCE
    assert "-EncryptData $true" in SOURCE
    assert "Test-ExactShareAccess" in SOURCE
    assert "Remove-SmbShare -Name $ShareName" in SOURCE
    assert "-FullAccess" not in SOURCE
    assert "-ChangeAccess" not in SOURCE
