"""Static Windows installer boundaries; no service installation in tests."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "tools/install-sli-agent.ps1").read_text(encoding="utf-8-sig")


def test_installation_registers_stopped_service_then_displays_rights():
    assert "--startup manual install" in SOURCE
    assert SOURCE.index("--startup manual install") < SOURCE.index("$probeJson =")
    assert "-m sli_agent probe --config $ConfigPath --json" in SOURCE
    assert "Format-Table -Wrap -AutoSize" in SOURCE
    assert "$probeExit -notin @(0, 2)" in SOURCE
    assert "service_identity_sid" in SOURCE and "allow_missing_rights" in SOURCE
    assert "[Text.UTF8Encoding]::new($false)" in SOURCE


def test_missing_rights_blocks_start_except_explicit_override():
    guard = SOURCE.index("if (-not $probe.ready -and -not $AllowMissingRights)")
    start = SOURCE.index('Write-Output "sc.exe start $serviceName"')
    assert guard < start
    assert "return" in SOURCE[guard:SOURCE.index("if (-not $probe.ready) {", guard)]
    assert "[switch]$AllowMissingRights" in SOURCE
    # The installer only prints the start command; the operator starts the service.
    assert "Start-Service" not in SOURCE


def test_default_dry_run_and_whatif_do_not_persist_override():
    dry_run = SOURCE[SOURCE.index("if (-not $Install)"):SOURCE.index("if (Get-Service -Name $serviceName")]
    assert "--service-identity-sid $accountSid.Value" in dry_run
    assert "return" in dry_run and "WriteAllText" not in dry_run
    assert SOURCE.index("ShouldProcess($serviceName, 'Register stopped Windows service')") < SOURCE.index("WriteAllText")


def test_installer_never_changes_audit_policy_membership_or_passes_passwords():
    lowered = SOURCE.casefold()
    for forbidden in ("auditpol", "add-localgroupmember", "add-adgroupmember", "net localgroup",
                      "get-credential", "--password", "convertfrom-securestring"):
        assert forbidden not in lowered
    assert "collection_enabled -ne $false" in SOURCE
    assert "agent_service_already_registered" in SOURCE


def test_update_initialization_and_restart_grant_use_instance_paths():
    assert "$releaseRoot = Join-Path (Join-Path $config.update_root 'instances') $serviceName" in SOURCE
    assert "$initialRoot = Join-Path (Join-Path $releaseRoot 'versions') $initialDirectory" in SOURCE
    assert "Get-Acl -LiteralPath $releaseRoot" in SOURCE
    assert "grant_restart_access(sys.argv[1], (sys.argv[2] or None) if len(sys.argv) > 2 else None)" in SOURCE
    assert '$accountSid.Value "$Instance"' in SOURCE
    assert SOURCE.index("service_identity_sid -NotePropertyValue") < SOURCE.index("-I -m sli_agent.updates")
