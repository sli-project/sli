"""Local pilot installer boundaries; no MSI, service or Docker mutations."""
import json
import os
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools/install-sli-agent-local.ps1"
SOURCE = SCRIPT.read_text(encoding="utf-8-sig")


def test_windows_powershell_51_encoding_and_elevation():
    assert SCRIPT.read_bytes().startswith(b"\xef\xbb\xbf")
    assert "#Requires -Version 5.1" in SOURCE
    launch = next(line for line in SOURCE.splitlines() if "$child = Start-Process" in line)
    assert "-Verb RunAs" in launch and "-PassThru" in launch
    assert "-Wait" not in launch
    assert "Sysnative\\WindowsPowerShell" in SOURCE
    assert "-EncodedCommand" in SOURCE
    assert "-WindowStyle Hidden" in SOURCE
    assert "'-NonInteractive', '-WindowStyle', 'Hidden'" in launch
    assert SOURCE.index("$null = $child.Handle") < SOURCE.index("$child.WaitForExit()")
    assert SOURCE.index("$child.WaitForExit()") < SOURCE.index("return $child.ExitCode")
    assert "finally { $child.Dispose() }" in SOURCE


def test_output_capture_and_service_transitions_have_bounded_waits():
    assert "WaitForExit($TimeoutSeconds * 1000)" in SOURCE
    assert "Task]::WaitAll([Threading.Tasks.Task[]]@($stdout, $stderr), 5000)" in SOURCE
    assert SOURCE.index("Task]::WaitAll") < SOURCE.index("$stderr.GetAwaiter().GetResult()")
    assert "ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(180)" in SOURCE
    assert "ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30)" in SOURCE
    assert "Stop-Service -Name" not in SOURCE and "Restart-Service -Name" not in SOURCE


def test_local_install_harness_requires_exact_transition_timeouts():
    # Source-only: never launch the elevated Windows/ACL installer harness here.
    harness = (ROOT / "tests/tooling/sli_agent_local_install_harness.ps1").read_text(
        encoding="utf-8-sig",
    )
    wait = harness.split("Add-Member ScriptMethod WaitForStatus {", 1)[1].split(
        "$script:serviceCalls.Add", 1,
    )[0]
    for status, seconds in (("Stopped", 180), ("Running", 30)):
        assert re.search(
            rf"\$Status -eq \[ServiceProcess.ServiceControllerStatus\]::{status}"
            rf"\) \{{\s*if \(\$Timeout.TotalSeconds -ne {seconds}\)",
            wait,
        )
    assert "else { throw 'unexpected_service_wait_status' }" in wait
    assert wait.count("throw 'service_wait_not_bounded'") == 2


def test_pinned_msi_and_public_ca_before_installation():
    assert "afc08f33a706103be5280dc3daa04b4e3f2c841abc9910bba1a7ea62f5591dd1" in SOURCE
    main = SOURCE[SOURCE.index("function Install-SliAgentLocal {"):]
    assert main.index("Get-FileHash") < main.index("Get-InstalledAgentMsi") < main.index("Disable-ScheduledTask") < main.index("Invoke-AgentMsiInstall")
    assert "SLI_TLS_CA_FILE" in SOURCE and "SLI_HEALTH_URL" in SOURCE
    assert "ISSUER_KEY" not in SOURCE
    assert '"SERVER_URL=$Url", "CA_FILE=$CaPath"' in SOURCE
    assert "TOKEN_FILE=" not in SOURCE


def _assert_no_secret_in_process_arguments_or_logs(source):
    # Inspect command arguments, excluding the variable receiving captured stdout.
    # Parenthesized arrays/expressions and backtick continuations may span lines.
    secret = re.compile(r"\$(?:rawToken|issued|Token)\b|\$\{(?:rawToken|issued|Token)\}", re.IGNORECASE)
    sinks = (
        r"Invoke-LocalProcess|Start-Process|"
        r"Write-(?:Host|Output|Verbose|Debug|Information|Error|Warning)|"
        r"Out-File|Add-Content|Set-Content|Tee-Object"
    )
    arguments = r"(?:`\r?\n|[^()\r\n;]|\((?:[^()]|\([^()]*\))*\))*"
    for command in re.finditer(rf"\b(?:{sinks})\b(?P<arguments>{arguments})", source, re.IGNORECASE):
        assert not secret.search(command["arguments"]), "secret_in_process_or_log_arguments"
    # A pipeline supplies input before the command name; process APIs also accept
    # a command line through a property instead of a PowerShell command argument.
    for usage in re.finditer(
        rf"(?P<input>[^\r\n;]+)\|\s*(?:{sinks})\b|"
        rf"\.(?:Arguments|ArgumentList)\s*(?:\+?=|\.Add\()(?P<value>{arguments})",
        source, re.IGNORECASE,
    ):
        assert not secret.search(usage["input"] or usage["value"]), "secret_in_process_or_log_arguments"
    assert not re.search(r"\bStart-Transcript\b", source, re.IGNORECASE)


@pytest.mark.parametrize("source", [
    "$issued = Invoke-LocalProcess $docker @('exec', $Container, 'issue_token') 30",
    "$rawToken = $issued.Stdout.Trim()\nWrite-EnrollmentToken $tokenPath $rawToken",
    "$issued = $null\nWrite-Host 'safe status'",
])
def test_secret_check_allows_capture_and_protected_token_write(source):
    _assert_no_secret_in_process_arguments_or_logs(source)


@pytest.mark.parametrize("source", [
    "Invoke-LocalProcess $docker @('exec', $Container, $rawToken) 30",
    "$issued = Invoke-LocalProcess $docker @(\n'exec', $Container, $issued.Stdout\n) 30",
    "Start-Process $docker -ArgumentList @('exec', $Token)",
    "Start-Process $docker -ArgumentList $rawToken",
    'Write-Host "token: $rawToken"',
    "Write-Output `\n $issued.Stdout",
    "Write-Warning $Token",
    'Write-Information "${rawToken}"',
    "Add-Content -Path 'test.log' -Value $rawToken",
    "$issued.Stdout | Out-File 'test.log'",
    "$Token | Tee-Object 'test.log'",
    '$info.Arguments = "exec $rawToken"',
    "$info.ArgumentList.Add($Token)",
    "Start-Transcript -Path 'test.log'",
])
def test_secret_check_rejects_process_argument_and_log_leaks(source):
    with pytest.raises(AssertionError):
        _assert_no_secret_in_process_arguments_or_logs(source)


def test_secret_never_in_process_arguments_or_logs():
    _assert_no_secret_in_process_arguments_or_logs(SOURCE)
    assert "$info.RedirectStandardOutput = $true" in SOURCE
    assert "$info.RedirectStandardError = $true" in SOURCE
    assert "ReadToEndAsync" in SOURCE
    assert "Write-EnrollmentToken $tokenPath $rawToken" in SOURCE
    assert "Start-Transcript" not in SOURCE
    assert "$_.Exception.Message]" in SOURCE  # Only a lookup of predefined safe messages.
    assert '--ttl\', \'900\'' in SOURCE


def test_token_acl_exists_before_bytes_and_no_existing_file_overwrite():
    assert "$acl.SetAccessRuleProtection($true, $false)" in SOURCE
    assert "@('S-1-5-18', 'S-1-5-32-544')" in SOURCE
    assert "$acl.SetOwner($admins)" in SOURCE
    assert "[IO.FileMode]::CreateNew" in SOURCE
    assert "4096, [IO.FileOptions]::WriteThrough, $acl" in SOURCE
    assert SOURCE.index("$stream = New-Object System.IO.FileStream") < SOURCE.index("$stream.Write")
    assert "ReparsePoint" in SOURCE
    assert "$tokenWritten -and" in SOURCE and "$caWritten -and" in SOURCE


def test_prepare_and_server_readback_are_required_for_success():
    install = SOURCE[SOURCE.index("function Install-SliAgentLocal"):]
    assert install.index("Stop-LocalAgentService") < install.index("'prepare'") < install.index("'server.sli.agents.issue_token'")
    assert "--host-id', $hostId, '--key-fingerprint', $keyFingerprint" in SOURCE
    assert "$watch.Elapsed.TotalSeconds -lt 120" in SOURCE
    assert "a.host_id=%s and a.key_fingerprint=%s and a.status='active'" in SOURCE
    assert "c.revoked_at is null" in SOURCE
    assert SOURCE.index("$check.Stdout.Trim() -ceq 'registered'") < SOURCE.index('Write-Host "Агент зарегистрирован:')


def test_pilot_state_is_archived_and_revocation_follows_replacement_registration():
    install = SOURCE[SOURCE.index("function Install-SliAgentLocal"):]
    assert install.index("Disable-ScheduledTask") < install.index("Stop-ScheduledTask")
    assert install.index("pilot_task_stop_timeout") < install.index("$pilotId = Move-PilotAgentState")
    assert "[IO.Directory]::Move($root, $archive)" in SOURCE
    assert "[IO.File]::ReadAllText($marker) -cne 'sli-agent-msi-v1'" in SOURCE
    assert install.index("$check.Stdout.Trim() -ceq 'registered'") < install.index("'server.sli.agents.revoke_agent'")
    assert install.index("$revoked.Stdout.Trim() -cne 'revoked'") < install.index('Write-Host "Агент зарегистрирован:')


def test_msi_replacement_uses_inventory_and_preserves_enrollment():
    assert "Win32_Product" not in re.sub(r"#[^\n]*", "", SOURCE)
    assert "RelatedProducts('{D6836D37-49FA-4AB6-BDFD-10B07ED51973}')" in SOURCE
    assert "HKLM:\\SOFTWARE\\SLI\\Agent" in SOURCE
    workflow = SOURCE[SOURCE.index("function Invoke-AgentMsiInstall"):SOURCE.index("function Assert-NoReparseTree")]
    stop = workflow.index("Stop-LocalAgentService")
    recheck = workflow.index("$enrolled = Test-AgentEnrollmentState", stop)
    assert stop < recheck < workflow.index("'/x'") < workflow.index("'/i'")
    assert "Start-LocalAgentService" in workflow[:workflow.index("'/x'")]
    assert "@('/x', $InstalledProduct, '/qn', '/norestart', '/L*v', $log)" in workflow
    assert "@('/fomus', $InstalledProduct, '/qn', '/norestart', '/L*v', $log)" in workflow
    assert "Invoke-RegisteredAgentUpgrade $Msi $InstalledProduct" in workflow[:workflow.index("'/x'")]
    assert workflow.index("msi_remove_failed") < workflow.index("'/i'")
    assert workflow.index("msi_remove_incomplete") < workflow.index("'/i'")
    assert "agent-remove.log" in workflow and "agent-repair.log" in workflow
    assert "CreateNoWindow = $true" in SOURCE
    assert "identity.json" in SOURCE and "certificate.pem" in SOURCE


def test_registered_upgrade_preflight_state_preservation_and_rollback_contract():
    upgrade = SOURCE[SOURCE.index("function Invoke-RegisteredAgentUpgrade"):SOURCE.index("function Test-AgentEnrollmentState")]
    stop = upgrade.index("Stop-LocalAgentService")
    assert upgrade.index("agent_upgrade_previous_msi_required") < stop
    assert upgrade.index("msi_hash_mismatch") < upgrade.index("Get-AgentMsiMetadata") < stop
    assert upgrade.index("agent_upgrade_version_invalid") < stop
    assert upgrade.index("[IO.Directory]::Move($root, $snapshot)") < upgrade.index("'/i', $targetPath")
    assert '"RESTORE_STATE=$snapshot"' in upgrade
    assert "'PRESERVE_STATE=1'" in upgrade
    assert "'/i', $previousPath" in upgrade and "'/fomus', $InstalledProduct" in upgrade
    assert upgrade.index("Assert-AgentRegistrationHashes $root $hashes") < upgrade.index("Assert-AgentServiceHealthy")
    assert "agent_upgrade_rolled_back" in upgrade and "agent_upgrade_rollback_failed" in upgrade
    assert "Invoke-RegisteredAgentUpgrade $msi $installedProduct" in SOURCE
    assert SOURCE.index("if ($Upgrade)", SOURCE.index("function Install-SliAgentLocal")) < SOURCE.index("$docker = (Get-Command docker.exe")
    assert "Threading.Mutex" in upgrade and "$mutex.ReleaseMutex()" in upgrade
    assert "issue_token" not in upgrade and "revoke_agent" not in upgrade


@pytest.mark.windows_only
def test_native_powershell_51_waits_for_slow_or_pending_stop_without_double_stop():
    executable = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    result = subprocess.run([
        str(executable), "-NoProfile", "-NonInteractive", "-File",
        str(ROOT / "tests/tooling/sli_agent_stop_harness.ps1"), str(SCRIPT),
    ], capture_output=True, text=True, timeout=15, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PowerShell 5.1 stop checks passed" in result.stdout


@pytest.mark.windows_only
def test_native_powershell_51_registered_upgrade_contract(tmp_path):
    executable = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    result = subprocess.run([
        str(executable), "-NoProfile", "-NonInteractive", "-File",
        str(ROOT / "tests/tooling/sli_agent_upgrade_harness.ps1"), str(SCRIPT), str(tmp_path),
    ], capture_output=True, text=True, timeout=60, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PowerShell 5.1 upgrade checks passed" in result.stdout


@pytest.mark.windows_only
def test_native_powershell_51_msi_retry_contract(tmp_path):
    executable = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    result = subprocess.run([
        str(executable), "-NoProfile", "-NonInteractive", "-File",
        str(ROOT / "tests/tooling/sli_agent_msi_retry_harness.ps1"), str(SCRIPT), str(tmp_path),
    ], capture_output=True, text=True, timeout=60, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PowerShell 5.1 MSI retry checks passed" in result.stdout


@pytest.mark.windows_only
def test_native_powershell_51_parse_and_fake_installation(tmp_path):
    import ctypes

    if not ctypes.windll.shell32.IsUserAnAdmin():
        pytest.skip("Legacy token/parent ACL harness requires an elevated Windows token")
    executable = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    result = subprocess.run([
        str(executable), "-NoProfile", "-NonInteractive", "-File",
        str(ROOT / "tests/tooling/sli_agent_local_install_harness.ps1"), str(SCRIPT), str(tmp_path),
    ], capture_output=True, text=True, timeout=60, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "checks passed" in result.stdout
    arguments_line = next(line for line in result.stdout.splitlines() if line.startswith("MSI_ARGUMENTS="))
    assert json.loads(arguments_line.removeprefix("MSI_ARGUMENTS=")) == [
        (r'/i "C:\SLI-Build\artifacts\SLI-Agent-1.0.0-x64.msi" /qn /norestart '
        r'SERVER_URL="https://localhost:8443" CA_FILE="C:\CA files\server-ca.pem" '
        r'/L*v "C:\SLI-Build\artifacts\agent-install.log"'),
        (r'/i "D:\MSI files\agent.msi" /qn /norestart '
        r'SERVER_URL="https://localhost:8443" CA_FILE="C:\CA files\" '
        r'/L*v "D:\MSI files\agent-install.log"'),
    ]
