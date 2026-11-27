#Requires -Version 5.1
param([string]$SourcePath, [string]$TestRoot)
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) { throw 'requires_powershell_51' }
$tokens = $null
$errors = $null
$installerAst = [Management.Automation.Language.Parser]::ParseFile($SourcePath, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'installer_parse_failed' }
. $SourcePath
$realHealth = ${function:Assert-AgentServiceHealthy}

# Every service, COM inventory and process operation is a fake. Filesystem
# operations stay in the caller-owned test directory; no elevation is needed.
$env:ProgramData = Join-Path $TestRoot 'data'
$env:ProgramFiles = Join-Path $TestRoot 'programs'
$root = Join-Path $env:ProgramData 'SLI\Agent'
$state = Join-Path $root 'state'
$old = '{00000000-0000-4000-8000-000000000010}'
$new = '{00000000-0000-4000-8000-000000000011}'
$url = 'https://core.invalid'
$script:MsiPath = Join-Path $TestRoot 'target.msi'
$script:PreviousMsiPath = Join-Path $TestRoot 'previous.msi'
[IO.File]::WriteAllText($MsiPath, 'synthetic-new-full-msi')
[IO.File]::WriteAllText($PreviousMsiPath, 'synthetic-old-full-msi')
$script:MsiSha256 = (Get-FileHash -LiteralPath $MsiPath).Hash
$script:PreviousMsiSha256 = (Get-FileHash -LiteralPath $PreviousMsiPath).Hash
$script:events = New-Object 'System.Collections.Generic.List[string]'
$script:scenario = ''
$script:installed = $old
$script:healthCalls = 0
$script:version = '1.1.0'
$script:upgradeCode = '{D6836D37-49FA-4AB6-BDFD-10B07ED51973}'

# Invoke-Command -FilePath forwards these positional arguments on PSRemoting.
# Parse just the param block, never run the actual installer on the endpoint.
$bindingBlock = [scriptblock]::Create($installerAst.ParamBlock.Extent.Text + @'

if (-not $Upgrade -or -not $MsiSha256 -or -not $PreviousMsiPath -or -not $PreviousMsiSha256) { throw 'remote_parameter_binding_failed' }
'@)
Invoke-Command -ScriptBlock $bindingBlock -ArgumentList @($MsiPath, '', 'sli-api-1', $true, $MsiSha256, $PreviousMsiPath, $PreviousMsiSha256)

function New-RestrictedSecurity([bool]$Directory) {
    $type = if ($Directory) { 'System.Security.AccessControl.DirectorySecurity' } else { 'System.Security.AccessControl.FileSecurity' }
    $acl = New-Object $type
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $flags = if ($Directory) { [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit' } else { [Security.AccessControl.InheritanceFlags]::None }
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', $flags, 'None', 'Allow')))
    return $acl
}
function Get-InstalledAgentMsi { return $script:installed }
function Get-InstalledAgentMsiVersion { return '1.0.0' }
function Get-AgentMsiMetadata([string]$Msi) {
    $target = [IO.Path]::GetFileName($Msi) -eq 'target.msi'
    return @{ ProductCode = $(if ($target) { $new } else { $old }); UpgradeCode = $script:upgradeCode;
        ProductVersion = $(if ($target) { $script:version } else { '1.0.0' }); ProductName = 'SLI Agent' }
}
function Stop-LocalAgentService { $script:events.Add('stop') }
function Start-LocalAgentService { $script:events.Add('start') }
function Get-Service { return [pscustomobject]@{ Dispose = $null } | Add-Member ScriptMethod Dispose {} -PassThru -Force }
function Assert-AgentServiceHealthy {
    $script:events.Add('health')
    $script:healthCalls++
    if ($script:healthCalls -eq 1 -and $script:scenario -in @('service', 'rollback')) {
        # Preserve a packet/cursor created by the new service before its crash.
        [IO.File]::WriteAllText((Join-Path $state 'spool\live.json'), 'synthetic-new-buffer')
        [IO.File]::WriteAllText((Join-Path $state 'cursors.json'), 'synthetic-advanced-cursor')
        throw 'agent_upgrade_service_failed'
    }
}
function Invoke-LocalProcess([string]$FilePath, [string[]]$Arguments, [int]$TimeoutSeconds) {
    if ($Arguments -contains 'remove') {
        if (Test-AgentEnrollmentState $root $url) { throw 'cleanup_registered_state' }
        $fixture = [IO.Path]::GetFullPath($root)
        if (-not $fixture.StartsWith([IO.Path]::GetFullPath($TestRoot) + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'fixture_outside_test_root' }
        Remove-Item -LiteralPath $fixture -Recurse -Force
        $script:events.Add('cleanup-temporary')
        return @{ ExitCode = 0 }
    }
    if ([IO.Path]::GetFileName($FilePath) -ne 'msiexec.exe' -or $TimeoutSeconds -ne 600 -or
        $Arguments -notcontains '/qn' -or $Arguments -notcontains '/norestart' -or $Arguments -notcontains '/L*v') { throw 'unexpected_process' }
    if ($Arguments[0] -eq '/i' -and [IO.Path]::GetFileName($Arguments[1]) -eq 'target.msi') {
        if (Test-Path -LiteralPath $root) { throw 'legacy_cleanup_can_erase_identity' }
        $restore = @($Arguments | Where-Object { $_ -like 'RESTORE_STATE=*' })
        if ($restore.Count -ne 1 -or $Arguments -notcontains 'MSIRESTARTMANAGERCONTROL=Disable') { throw 'restore_property_missing' }
        $snapshot = $restore[0].Substring('RESTORE_STATE='.Length)
        if ([IO.File]::ReadAllText((Join-Path $snapshot 'state\identity.json')) -ne 'synthetic-identity') { throw 'identity_not_saved' }
        $script:events.Add('upgrade')
        if ($script:scenario -eq 'timeout') { throw 'process_timeout' }
        if ($script:scenario -eq 'install-before') { return @{ ExitCode = 1603 } }
        [IO.Directory]::Move($snapshot, $root)
        if ($script:scenario -eq 'install-after') { return @{ ExitCode = 1603 } }
        $script:installed = $new
        return @{ ExitCode = $(if ($script:scenario -eq 'reboot') { 3010 } else { 0 }) }
    }
    if ($Arguments[0] -eq '/x') {
        if ($Arguments[1] -ne $new -or $Arguments -notcontains 'PRESERVE_STATE=1' -or (Test-Path -LiteralPath $root)) { throw 'unsafe_rollback_remove' }
        $script:events.Add('rollback-remove')
        if ($script:scenario -eq 'rollback') { return @{ ExitCode = 1603 } }
        $script:installed = $null
        return @{ ExitCode = 0 }
    }
    if ($Arguments[0] -eq '/i' -and [IO.Path]::GetFileName($Arguments[1]) -eq 'previous.msi') {
        if ($script:installed -or (Test-Path -LiteralPath $root) -or $Arguments -notcontains "SERVER_URL=$url" -or
            @($Arguments | Where-Object { $_ -like 'TOKEN_FILE=*' }).Count) { throw 'unsafe_previous_install' }
        $script:events.Add('rollback-install')
        $null = [IO.Directory]::CreateDirectory($state)
        [IO.File]::WriteAllText((Join-Path $root '.msi-owned'), 'sli-agent-msi-v1')
        [IO.File]::WriteAllText((Join-Path $root 'agent.json'), (@{ state_dir = $state; server_url = $url;
            service_identity_sid = 'S-1-5-18' } | ConvertTo-Json))
        $script:installed = $old
        return @{ ExitCode = 0 }
    }
    if ($Arguments[0] -eq '/fomus' -and $Arguments[1] -eq $old) {
        $script:events.Add('rollback-repair')
        return @{ ExitCode = 0 }
    }
    throw 'unexpected_process'
}
function Reset-Fixture {
    $fixture = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'SLI'))
    if (-not $fixture.StartsWith([IO.Path]::GetFullPath($TestRoot) + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'fixture_outside_test_root' }
    if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force }
    $null = [IO.Directory]::CreateDirectory((Join-Path $state 'spool'))
    [IO.File]::WriteAllText((Join-Path $root '.msi-owned'), 'sli-agent-msi-v1')
    [IO.File]::WriteAllText((Join-Path $root 'server-ca.pem'), 'synthetic-ca')
    [IO.File]::WriteAllText((Join-Path $root 'agent.json'), (@{ state_dir = $state; server_url = $url;
        service_identity_sid = 'S-1-5-18' } | ConvertTo-Json))
    foreach ($name in @('identity.json', 'identity-key.json', 'host.json', 'cursors.json', 'spool\original.json')) {
        [IO.File]::WriteAllText((Join-Path $state $name), 'synthetic-' + $(if ($name -eq 'identity.json') { 'identity' } else { $name }))
    }
    $script:events.Clear()
    $script:installed = $old
    $script:healthCalls = 0
    $script:version = '1.1.0'
}
function Assert-Failure([string]$Reason) {
    try { Invoke-RegisteredAgentUpgrade $MsiPath $old; throw 'expected_failure' }
    catch { if ($_.Exception.Message -ne $Reason) { throw } }
}

foreach ($case in @('', 'reboot', 'install-before', 'install-after', 'service', 'rollback', 'timeout')) {
    Reset-Fixture
    $script:scenario = $case
    $identityBefore = [IO.File]::ReadAllText((Join-Path $state 'identity.json'))
    if ($case -eq 'timeout') {
        Assert-Failure 'agent_upgrade_transaction_pending'
        $snapshot = Get-ChildItem -LiteralPath (Split-Path -Parent $root) -Directory -Filter 'Agent.upgrade-*' | Select-Object -First 1
        if (($script:events -join ',') -ne 'stop,upgrade' -or -not $snapshot -or
            [IO.File]::ReadAllText((Join-Path $snapshot.FullName 'state\identity.json')) -ne $identityBefore) { throw 'timeout_raced_msi_transaction' }
        continue
    }
    if ($case -eq 'rollback') {
        Assert-Failure 'agent_upgrade_rollback_failed'
        $snapshot = Get-ChildItem -LiteralPath (Split-Path -Parent $root) -Directory -Filter 'Agent.upgrade-*' | Select-Object -First 1
        if (-not $snapshot -or [IO.File]::ReadAllText((Join-Path $snapshot.FullName 'state\identity.json')) -ne $identityBefore -or
            -not (Test-Path -LiteralPath (Join-Path $snapshot.FullName 'state\spool\live.json'))) { throw 'failed_rollback_lost_state' }
        continue
    }
    if ($case) {
        if ($case -eq 'reboot') { Invoke-RegisteredAgentUpgrade $MsiPath $old }
        else { Assert-Failure 'agent_upgrade_rolled_back' }
    } else { Invoke-RegisteredAgentUpgrade $MsiPath $old }
    if ([IO.File]::ReadAllText((Join-Path $state 'identity.json')) -ne $identityBefore -or
        -not (Test-Path -LiteralPath (Join-Path $state 'spool\original.json'))) { throw 'state_not_preserved' }
    if ($case -eq 'service' -and ([IO.File]::ReadAllText((Join-Path $state 'cursors.json')) -ne 'synthetic-advanced-cursor' -or
        -not $script:events.Contains('rollback-install') -or -not $script:events.Contains('cleanup-temporary'))) { throw 'rollback_discarded_live_state' }
    if ($case -in @('install-before', 'install-after', 'service') -and $script:installed -ne $old) { throw 'previous_product_not_restored' }
}
Reset-Fixture
$script:version = '1.0.0'
Assert-Failure 'agent_upgrade_version_invalid'
if ($script:events.Count) { throw 'version_preflight_stopped_service' }
Reset-Fixture
$script:PreviousMsiSha256 = '0' * 64
Assert-Failure 'msi_hash_mismatch'
if ($script:events.Count) { throw 'hash_preflight_stopped_service' }
$script:PreviousMsiSha256 = (Get-FileHash -LiteralPath $PreviousMsiPath).Hash
Reset-Fixture
$script:PreviousMsiPath = ''
Assert-Failure 'agent_upgrade_previous_msi_required'
if ($script:events.Count) { throw 'previous_preflight_stopped_service' }

# Exercise the actual bounded observation function with a fake SCM controller.
Add-Type -AssemblyName System.ServiceProcess
$script:refreshCount = 0
$script:healthFail = $false
$script:disposed = $false
function Start-Sleep {}
function Get-Service {
    $fake = [pscustomobject]@{ Status = [ServiceProcess.ServiceControllerStatus]::Running }
    $fake | Add-Member ScriptMethod Refresh {
        $script:refreshCount++
        if ($script:healthFail -and $script:refreshCount -eq 2) { $this.Status = [ServiceProcess.ServiceControllerStatus]::Stopped }
    }
    $fake | Add-Member ScriptMethod Dispose { $script:disposed = $true }
    return $fake
}
& $realHealth
if ($script:refreshCount -ne 15 -or -not $script:disposed) { throw 'health_observation_incomplete' }
$script:refreshCount = 0
$script:healthFail = $true
$script:disposed = $false
try { & $realHealth; throw 'service_failure_ignored' }
catch { if ($_.Exception.Message -ne 'agent_upgrade_service_failed') { throw } }
if ($script:refreshCount -ne 2 -or -not $script:disposed) { throw 'health_failure_not_bounded' }

Write-Output 'PowerShell 5.1 upgrade checks passed'
