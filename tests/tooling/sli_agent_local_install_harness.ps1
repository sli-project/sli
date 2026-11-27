#Requires -Version 5.1
param([string]$SourcePath, [string]$TestRoot)
$ErrorActionPreference = 'Stop'
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($SourcePath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw 'installer_parse_failed' }
if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) { throw 'requires_windows_powershell_51' }
. $SourcePath

# Bound SCM transitions without touching any real service.
Add-Type -AssemblyName System.ServiceProcess
$script:serviceCalls = New-Object 'System.Collections.Generic.List[string]'
$script:serviceTimeout = $false
$script:serviceDisposed = $false
$script:serviceStatus = [ServiceProcess.ServiceControllerStatus]::Running
function Get-Service {
    $fake = [pscustomobject]@{}
    $fake | Add-Member ScriptProperty Status { return $script:serviceStatus }
    $fake | Add-Member ScriptMethod Stop { $script:serviceCalls.Add('stop'); $script:serviceStatus = [ServiceProcess.ServiceControllerStatus]::Stopped }
    $fake | Add-Member ScriptMethod Start { $script:serviceCalls.Add('start'); $script:serviceStatus = [ServiceProcess.ServiceControllerStatus]::Running }
    $fake | Add-Member ScriptMethod WaitForStatus {
        param($Status, $Timeout)
        if ($Status -eq [ServiceProcess.ServiceControllerStatus]::Stopped) {
            if ($Timeout.TotalSeconds -ne 180) { throw 'service_wait_not_bounded' }
        } elseif ($Status -eq [ServiceProcess.ServiceControllerStatus]::Running) {
            if ($Timeout.TotalSeconds -ne 30) { throw 'service_wait_not_bounded' }
        } else { throw 'unexpected_service_wait_status' }
        $script:serviceCalls.Add([string]$Status)
        if ($script:serviceTimeout) { throw 'synthetic_service_timeout' }
    }
    $fake | Add-Member ScriptMethod Dispose { $script:serviceDisposed = $true }
    return $fake
}
Stop-LocalAgentService
Start-LocalAgentService
if (($script:serviceCalls -join ',') -cne 'stop,Stopped,start,Running' -or -not $script:serviceDisposed) { throw 'service_transition_failed' }
$script:serviceCalls.Clear()
Start-LocalAgentService
$script:serviceStatus = [ServiceProcess.ServiceControllerStatus]::Stopped
Stop-LocalAgentService
if (($script:serviceCalls -join ',') -cne 'Running,Stopped') { throw 'service_transition_not_idempotent' }
$script:serviceStatus = [ServiceProcess.ServiceControllerStatus]::Running
$script:serviceTimeout = $true
foreach ($operation in @('Stop-LocalAgentService', 'Start-LocalAgentService')) {
    $script:serviceDisposed = $false
    try { & $operation; throw 'service_timeout_ignored' } catch {
        if ($_.Exception.Message -notlike '*synthetic_service_timeout*') { throw }
    }
    if (-not $script:serviceDisposed) { throw 'service_controller_not_disposed' }
}
Remove-Item Function:\Get-Service

# Inspect process/log arguments as syntax, without executing an installation.
$commands = $ast.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] }, $true)
foreach ($command in $commands) {
    if ($command.GetCommandName() -in @('Invoke-LocalProcess', 'Start-Process', 'Write-Host', 'Write-Output', 'Write-Verbose', 'Write-Debug', 'Write-Information', 'Write-Error')) {
        if ($command.Extent.Text -match '\$(rawToken|issued|Token)\b') { throw 'secret_in_process_or_log_arguments' }
    }
}

# Exercise real stdout/stderr capture and Windows argument quoting. Only public
# test data reaches the child command line; a synthetic token is returned stdout.
$ps = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$publicProbe = Join-Path $TestRoot 'public-probe.ps1'
[IO.Directory]::CreateDirectory($TestRoot) | Out-Null
[IO.File]::WriteAllText($publicProbe, 'param([string]$Value) if ($Value -ne ''space "quote" trailing\'') { exit 3 }; [Console]::Out.Write((''t'' * 43)); [Console]::Error.Write(''safe-error'')')
$captured = Invoke-LocalProcess $ps @('-NoProfile', '-NonInteractive', '-File', $publicProbe, 'space "quote" trailing\') 30
if ($captured.ExitCode -ne 0 -or $captured.Stdout -cne ('t' * 43)) { throw 'process_capture_or_quoting_failed' }

# Capture the real ProcessStartInfo.Arguments without starting Windows Installer.
$script:realInvokeLocalProcess = ${function:Invoke-LocalProcess}
$script:msiCommandLines = New-Object 'System.Collections.Generic.List[string]'
function New-Object([string]$TypeName) {
    if ($TypeName -ne 'System.Diagnostics.Process') {
        return Microsoft.PowerShell.Utility\New-Object $TypeName @args
    }
    $fake = [pscustomobject]@{
        StartInfo = $null; ExitCode = 0
        StandardOutput = New-Object System.IO.StringReader ''
        StandardError = New-Object System.IO.StringReader ''
    }
    $fake | Add-Member ScriptMethod Start {
        $script:processArguments = $this.StartInfo.Arguments
        return $true
    }
    $fake | Add-Member ScriptMethod WaitForExit { param($Milliseconds) return $true }
    $fake | Add-Member ScriptMethod Dispose { }
    return $fake
}
$msiCases = @(
    @{ Arguments = @('/i', 'C:\SLI-Build\artifacts\SLI-Agent-1.0.0-x64.msi', '/qn', '/norestart', 'SERVER_URL=https://localhost:8443', 'CA_FILE=C:\CA files\server-ca.pem', '/L*v', 'C:\SLI-Build\artifacts\agent-install.log') }
    @{ Arguments = @('/i', 'D:\MSI files\agent.msi', '/qn', '/norestart', 'SERVER_URL=https://localhost:8443', 'CA_FILE=C:\CA files\', '/L*v', 'D:\MSI files\agent-install.log') }
)
foreach ($case in $msiCases) {
    $null = Invoke-LocalProcess (Join-Path $env:WINDIR 'System32\msiexec.exe') $case.Arguments 600
    $script:msiCommandLines.Add($script:processArguments)
}
if ($script:msiCommandLines[0] -cne '/i "C:\SLI-Build\artifacts\SLI-Agent-1.0.0-x64.msi" /qn /norestart SERVER_URL="https://localhost:8443" CA_FILE="C:\CA files\server-ca.pem" /L*v "C:\SLI-Build\artifacts\agent-install.log"') { throw 'msiexec_argument_quoting_failed' }
if ($script:msiCommandLines[1] -cne '/i "D:\MSI files\agent.msi" /qn /norestart SERVER_URL="https://localhost:8443" CA_FILE="C:\CA files\" /L*v "D:\MSI files\agent-install.log"') { throw 'msiexec_trailing_backslash_failed' }

$acl = New-RestrictedSecurity $false
$constructors = @([IO.FileStream].GetConstructors() | Where-Object { $_.ToString() -match 'FileSystemRights.*FileSecurity' })
if (-not $constructors.Count) { throw 'atomic_acl_constructor_missing' }
$rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
if (-not $acl.AreAccessRulesProtected -or $rules.Count -ne 2) { throw 'token_acl_not_protected' }
if (($rules.IdentityReference.Value | Sort-Object) -join ',' -ne 'S-1-5-18,S-1-5-32-544') { throw 'unexpected_token_principal' }
if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-32-544') { throw 'unexpected_token_owner' }
# Check the created file, not just the descriptor passed to FileStream.
$written = Join-Path $TestRoot 'written.token'
try {
    Write-EnrollmentToken $written ('t' * 43)
    $diskAcl = Get-Acl -LiteralPath $written
    $diskRules = @($diskAcl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if (-not $diskAcl.AreAccessRulesProtected -or $diskRules.Count -ne 2) { throw 'written_token_acl_not_protected' }
    if ($diskAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-32-544') { throw 'written_token_owner_untrusted' }
    if (($diskRules.IdentityReference.Value | Sort-Object) -join ',' -ne 'S-1-5-18,S-1-5-32-544') { throw 'written_token_principal_untrusted' }
    foreach ($rule in $diskRules) {
        if ($rule.IsInherited -or $rule.AccessControlType -ne 'Allow' -or $rule.FileSystemRights -ne 'FullControl') { throw 'written_token_rule_invalid' }
    }
    if ([IO.File]::ReadAllText($written) -cne ('t' * 43)) { throw 'written_token_content_invalid' }
} finally {
    if (Test-Path -LiteralPath $written) { Remove-Item -LiteralPath $written -Force }
}
$existing = Join-Path $TestRoot 'existing.token'
[IO.File]::WriteAllText($existing, 'preserved-test-content')
try { Write-EnrollmentToken $existing ('t' * 43); throw 'existing_token_overwritten' } catch {
    if ($_.Exception.Message -eq 'existing_token_overwritten') { throw }
}
if ([IO.File]::ReadAllText($existing) -ne 'preserved-test-content') { throw 'existing_token_changed' }

$env:ProgramData = Join-Path $TestRoot 'data'
$env:ProgramFiles = Join-Path $TestRoot 'programs'
$script:MsiPath = Join-Path $TestRoot 'agent.msi'
$script:ServerUrl = ''
$script:Container = 'test-api'
$root = Join-Path $env:ProgramData 'SLI\Agent'
$state = Join-Path $root 'state'
$bootstrap = Join-Path $env:ProgramData 'SLI\LocalBootstrap'
[IO.Directory]::CreateDirectory($state) | Out-Null
[IO.Directory]::CreateDirectory($bootstrap) | Out-Null
# Reproduce the owner-created parent left after the pilot was archived.
$parent = Split-Path $root
$parentAcl = New-RestrictedSecurity $true
$callerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$parentAcl.SetOwner($callerSid)
$parentAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($callerSid, 'FullControl', 'Allow')))
Microsoft.PowerShell.Security\Set-Acl -LiteralPath $parent -AclObject $parentAcl
[IO.File]::WriteAllText((Join-Path $root 'agent.json'), (@{
    server_url = 'https://example.invalid:8443'; state_dir = $state; service_identity_sid = 'S-1-5-18'
} | ConvertTo-Json))
[IO.File]::WriteAllText((Join-Path $state 'identity.json'), '{"agent_id":"00000000-0000-4000-8000-000000000002"}')
$pilotDacl = (Get-Acl -LiteralPath $root).Sddl
$stateDacl = (Get-Acl -LiteralPath $state).Sddl
$bootstrapDacl = (Get-Acl -LiteralPath $bootstrap).Sddl
$null = Move-PilotAgentState
if (Test-Path -LiteralPath $root) { throw 'pilot_fixture_not_archived' }
if (-not (Test-Path -LiteralPath $bootstrap)) { throw 'bootstrap_fixture_missing' }
$script:seenArguments = New-Object 'System.Collections.Generic.List[string]'
$script:events = New-Object 'System.Collections.Generic.List[string]'
$script:testToken = 't' * 43
$script:failIssue = $false
$script:failMsi = $false
$script:noTask = $false
$script:issuedCount = 0
$script:hashValid = $true
$script:failRevoke = $false
$script:registrationFailed = $false
$script:taskRunningChecks = 0
$script:checkArchivedAcl = $true

# MSI inventory and maintenance must refer only to this temporary fixture.
function Get-InstalledAgentMsi {
    if (Test-Path -LiteralPath (Join-Path $root '.msi-owned')) { return '{00000000-0000-4000-8000-000000000010}' }
    return $null
}
function Get-AgentMsiProductCode { return '{00000000-0000-4000-8000-000000000010}' }

function Test-LocalAdministrator { return $true }
function Get-FileHash { return @{ Hash = $(if ($script:hashValid) { 'afc08f33a706103be5280dc3daa04b4e3f2c841abc9910bba1a7ea62f5591dd1' } else { '0' * 64 }) } }
function Get-Command { return @{ Source = 'fake-docker.exe' } }
function Get-ScheduledTask {
    if (-not $script:noTask) {
        $taskState = 'Disabled'
        if ($script:taskRunningChecks -gt 0) { $script:taskRunningChecks--; $taskState = 'Running' }
        return @{ TaskName = 'SLI Agent'; State = $taskState }
    }
}
function Disable-ScheduledTask { param([Parameter(ValueFromPipeline)]$Task) process { $script:events.Add('disable-task') } }
function Stop-ScheduledTask { param([Parameter(ValueFromPipeline)]$Task) process { $script:events.Add('stop-task'); $script:taskRunningChecks = 2 } }
function Set-Acl { }
function Stop-LocalAgentService { $script:events.Add('stop-service') }
function Start-LocalAgentService {
    $script:events.Add('restart-service')
    [IO.File]::WriteAllText((Join-Path $state 'identity.json'), '{}')
}
function Get-Service {
    $fake = [pscustomobject]@{ Status = $(if ($script:registrationFailed) { 'Stopped' } else { 'Running' }) }
    $fake | Add-Member ScriptMethod WaitForStatus { param($Status, $Timeout) }
    return $fake
}
function Write-EnrollmentToken([string]$Path, [string]$Token) {
    if ($Token -cne $script:testToken -or $Path -ne (Join-Path $root 'enrollment.token')) { throw 'wrong_token_file' }
    $script:events.Add('write-token')
}
function Invoke-LocalProcess([string]$FilePath, [string[]]$Arguments, [int]$TimeoutSeconds) {
    $script:seenArguments.Add($FilePath + ' ' + ($Arguments -join ' '))
    if ($Arguments -contains '/fomus') { return @{ ExitCode = 0; Stdout = '' } }
    if ($Arguments -contains '/x') {
        $fixture = [IO.Path]::GetFullPath($root)
        if (-not $fixture.StartsWith([IO.Path]::GetFullPath($TestRoot) + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'fixture_outside_test_root' }
        Remove-Item -LiteralPath $fixture -Recurse -Force
        return @{ ExitCode = 0; Stdout = '' }
    }
    if ($Arguments -contains 'server.sli.agents.issue_token') {
        $script:issuedCount++
        $script:events.Add('issue-token')
        if ($script:failIssue) { return @{ ExitCode = 1; Stdout = '' } }
        return @{ ExitCode = 0; Stdout = $script:testToken + "`n" }
    }
    if ($Arguments -contains '/i') {
        if ($script:taskRunningChecks -gt 0) { throw 'msi_started_before_pilot_stopped' }
        $acl = Get-Acl -LiteralPath $parent
        if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-32-544' -or -not $acl.AreAccessRulesProtected) { throw 'msi_parent_still_unsafe' }
        $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
        if ($rules.Count -ne 2 -or ($rules.IdentityReference.Value | Sort-Object) -join ',' -ne 'S-1-5-18,S-1-5-32-544') { throw 'msi_parent_public_access' }
        if ($script:checkArchivedAcl) {
            $archive = Get-ChildItem -LiteralPath $parent -Filter 'Agent.pilot-*' -Directory | Select-Object -First 1
            if ((Get-Acl -LiteralPath $archive.FullName).Sddl -ne $pilotDacl -or (Get-Acl -LiteralPath (Join-Path $archive.FullName 'state')).Sddl -ne $stateDacl) { throw 'pilot_acl_changed_before_msi' }
            if ((Get-Acl -LiteralPath $bootstrap).Sddl -ne $bootstrapDacl) { throw 'parent_acl_propagated_to_bootstrap' }
        }
        $null = & $script:realInvokeLocalProcess $FilePath $Arguments $TimeoutSeconds
        $expected = '/i "' + $script:MsiPath + '" /qn /norestart SERVER_URL="https://example.invalid:8443" CA_FILE="' + (Join-Path $bootstrap 'server-ca.pem') + '" /L*v "' + (Join-Path $TestRoot 'agent-install.log') + '"'
        if ($script:processArguments -cne $expected) { throw 'installer_msiexec_command_line_failed' }
        $script:events.Add('install-msi')
        [IO.Directory]::CreateDirectory($state) | Out-Null
        [IO.File]::WriteAllText((Join-Path $root '.msi-owned'), 'sli-agent-msi-v1')
        [IO.File]::WriteAllText((Join-Path $root 'agent.json'), (@{
            server_url = 'https://example.invalid:8443'; state_dir = $state; service_identity_sid = 'S-1-5-18'
        } | ConvertTo-Json))
        return @{ ExitCode = $(if ($script:failMsi) { 1603 } else { 0 }); Stdout = '' }
    }
    if ($Arguments -contains 'server.sli.agents.revoke_agent') {
        $script:events.Add('revoke-pilot')
        if ($Arguments[$Arguments.IndexOf('--agent-id') + 1] -ne '00000000-0000-4000-8000-000000000002') { throw 'wrong_pilot_id' }
        if ($script:failRevoke) { return @{ ExitCode = 1; Stdout = '' } }
        return @{ ExitCode = 0; Stdout = 'revoked' }
    }
    if ($Arguments -contains 'prepare') {
        $script:events.Add('prepare')
        return @{ ExitCode = 0; Stdout = '{"host_id":"00000000-0000-4000-8000-000000000001","key_fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}' }
    }
    if (($Arguments -join ' ') -match 'SLI_TLS_CA_FILE') {
        return @{ ExitCode = 0; Stdout = '{"server_url":"https://example.invalid:8443","ca":"-----BEGIN CERTIFICATE-----\npublic-test-ca\n-----END CERTIFICATE-----"}' }
    }
    $script:events.Add('registered')
    return @{ ExitCode = 0; Stdout = 'registered' }
}

function Assert-NoSecret($Output) {
    if (($script:seenArguments -join "`n").Contains($script:testToken)) { throw 'token_in_arguments' }
    if (($Output | Out-String).Contains($script:testToken)) { throw 'token_in_output' }
}

$output = @(Install-SliAgentLocal *>&1)
Assert-NoSecret $output
if ($output[-1] -ne 0) { throw 'installer_success_failed' }
$script:checkArchivedAcl = $false
if (($script:events -join ',') -ne 'disable-task,stop-task,install-msi,stop-service,prepare,issue-token,write-token,restart-service,registered,revoke-pilot') { throw 'wrong_install_order' }
$archives = @(Get-ChildItem -LiteralPath (Split-Path $root) -Filter 'Agent.pilot-*' -Directory)
if ($archives.Count -ne 1) { throw 'pilot_not_archived' }
if ((Get-Acl -LiteralPath $archives[0].FullName).Sddl -ne $pilotDacl) { throw 'pilot_dacl_changed' }
if ([IO.File]::ReadAllText((Join-Path $archives[0].FullName 'state\identity.json')) -notmatch '00000000-0000-4000-8000-000000000002') { throw 'pilot_identity_lost' }
if (-not (($output | Out-String).Contains('00000000-0000-4000-8000-000000000001'))) { throw 'missing_registration_result' }

# Re-running an enrolled default instance verifies registration without issuance.
$before = $script:issuedCount
$script:noTask = $true
$output = @(Install-SliAgentLocal *>&1)
Assert-NoSecret $output
if ($output[-1] -ne 0 -or $script:issuedCount -ne $before) { throw 'rerun_issued_token' }
if (@(Get-ChildItem -LiteralPath (Split-Path $root) -Filter 'Agent.pilot-*' -Directory).Count -ne 1) { throw 'managed_state_moved' }

$script:registrationFailed = $true
$script:events.Clear()
$output = @(Install-SliAgentLocal *>&1)
if ($output[-1] -ne 1 -or $script:events.Contains('revoke-pilot')) { throw 'unregistered_replacement_revoked_pilot' }
$script:registrationFailed = $false
$script:failRevoke = $true
$script:events.Clear()
$output = @(Install-SliAgentLocal *>&1)
if ($output[-1] -ne 1 -or ($output | Out-String).Contains('старый пилот отозван')) { throw 'revocation_failure_reported_success' }
$script:failRevoke = $false

Remove-Item -LiteralPath (Join-Path $state 'identity.json')
$script:failIssue = $true
$script:events.Clear()
$output = @(Install-SliAgentLocal *>&1)
Assert-NoSecret $output
if ($output[-1] -ne 1 -or $script:events.Contains('write-token') -or $script:events.Contains('restart-service')) { throw 'issuance_failure_not_blocked' }

$script:failMsi = $true
$script:events.Clear()
$output = @(Install-SliAgentLocal *>&1)
Assert-NoSecret $output
if ($output[-1] -ne 1 -or $script:events.Contains('prepare')) { throw 'msi_failure_not_blocked' }
$script:hashValid = $false
$script:events.Clear()
$output = @(Install-SliAgentLocal *>&1)
Assert-NoSecret $output
if ($output[-1] -ne 1 -or $script:events.Count -ne 0) { throw 'hash_failure_not_blocked' }

$script:hashValid = $true
$existingCa = Join-Path $bootstrap 'server-ca.pem'
[IO.File]::WriteAllText($existingCa, 'preserved-public-ca')
$output = @(Install-SliAgentLocal *>&1)
Assert-NoSecret $output
if ($output[-1] -ne 1 -or [IO.File]::ReadAllText($existingCa) -ne 'preserved-public-ca') { throw 'existing_ca_removed' }
Remove-Item -LiteralPath $existingCa
$script:failMsi = $false
$script:failIssue = $false

# A descendant junction must block the archive and MSI without following it.
Remove-Item -LiteralPath (Join-Path $root '.msi-owned')
$junction = Join-Path $root 'unsafe-junction'
New-Item -ItemType Junction -Path $junction -Target $bootstrap | Out-Null
$script:events.Clear()
$output = @(Install-SliAgentLocal *>&1)
Assert-NoSecret $output
if ($output[-1] -ne 1 -or $script:events.Contains('install-msi') -or -not (Test-Path -LiteralPath $root)) { throw 'reparse_tree_not_blocked' }
Remove-Item -LiteralPath $junction -Force

# Empty-machine installation proceeds directly to MSI without revoking a pilot.
[IO.Directory]::Move($root, ($root + '.test-managed'))
[IO.Directory]::Move($archives[0].FullName, ($archives[0].FullName.Replace('Agent.pilot-', 'Agent.test-')))
$script:events.Clear()
$output = @(Install-SliAgentLocal *>&1)
Assert-NoSecret $output
if ($output[-1] -ne 0 -or ($script:events -join ',') -ne 'install-msi,stop-service,prepare,issue-token,write-token,restart-service,registered') { throw 'fresh_install_failed' }

# Pilot identity can live outside ProgramData; it remains intact after migration.
[IO.Directory]::Move($root, ($root + '.test-fresh'))
$externalState = Join-Path $TestRoot 'external-state'
[IO.Directory]::CreateDirectory($externalState) | Out-Null
[IO.Directory]::CreateDirectory($root) | Out-Null
[IO.File]::WriteAllText((Join-Path $root 'agent.json'), (@{ state_dir = $externalState } | ConvertTo-Json))
$externalIdentity = Join-Path $externalState 'identity.json'
$oldIdentity = '{"agent_id":"00000000-0000-4000-8000-000000000002"}'
[IO.File]::WriteAllText($externalIdentity, $oldIdentity)
$script:noTask = $false
$script:events.Clear()
$output = @(Install-SliAgentLocal *>&1)
Assert-NoSecret $output
if ($output[-1] -ne 0 -or -not $script:events.Contains('revoke-pilot')) { throw 'external_pilot_identity_not_used' }
if ([IO.File]::ReadAllText($externalIdentity) -cne $oldIdentity) { throw 'external_pilot_identity_changed' }

# The elevated child is hidden; only safe status messages return to this console.
# Run the encoded wrapper with a harmless installer fixture, without elevation.
Remove-Item Function:\New-Object
$elevationFixture = Join-Path $TestRoot "elevated fixture's script.ps1"
[IO.File]::WriteAllText($elevationFixture, @'
param($MsiPath, $ServerUrl, $Container)
function Assert-LocalPath($Path) { return $Path }
function Install-SliAgentLocal {
    Write-Error ('t' * 43) -ErrorAction Continue
    Write-Host 'safe elevated result'
    return 0
}
'@, [Text.Encoding]::UTF8)
function Start-Process {
    param($FilePath, $Verb, $WindowStyle, $ArgumentList, [switch]$Wait, [switch]$PassThru)
    if ($Verb -ne 'RunAs' -or $WindowStyle -ne 'Hidden' -or $Wait -or -not $PassThru) { throw 'elevation_window_or_tree_wait_invalid' }
    if ($ArgumentList -notcontains '-NonInteractive' -or $ArgumentList[$ArgumentList.IndexOf('-WindowStyle') + 1] -cne 'Hidden') { throw 'powershell_host_not_hidden' }
    $command = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($ArgumentList[-1]))
    $errors = $null
    $tokens = $null
    $null = [Management.Automation.Language.Parser]::ParseInput($command, [ref]$tokens, [ref]$errors)
    if ($errors.Count -or $command.Contains($script:testToken)) { throw 'unsafe_elevated_command' }
    if ($command -notmatch "Assert-LocalPath '([^']+)'") { throw 'elevation_result_missing' }
    $script:elevationResultPath = $Matches[1]
    $acl = Get-Acl -LiteralPath $script:elevationResultPath
    if (-not $acl.AreAccessRulesProtected) { throw 'elevation_result_not_protected' }
    $caller = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $allowed = @('S-1-5-18', 'S-1-5-32-544', $caller)
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.IdentityReference.Value -notin $allowed) { throw 'elevation_result_unexpected_principal' }
    }
    $child = & $script:realInvokeLocalProcess $FilePath $ArgumentList 30
    if ($child.Stdout.Contains($script:testToken)) { throw 'elevation_stdout_leaked_secret' }
    $script:elevationHandleCached = $false
    $script:elevationWaited = $false
    $script:elevationDisposed = $false
    $fake = [pscustomobject]@{ ExitCode = $child.ExitCode }
    $fake | Add-Member ScriptProperty Handle { $script:elevationHandleCached = $true; return [IntPtr]::Zero }
    $fake | Add-Member ScriptMethod WaitForExit {
        if (-not $script:elevationHandleCached) { throw 'elevation_handle_not_cached' }
        $script:elevationWaited = $true
    }
    $fake | Add-Member ScriptMethod Dispose { $script:elevationDisposed = $true }
    return $fake
}
$output = @(Invoke-ElevatedInstall $ps $elevationFixture $script:MsiPath *>&1)
Assert-NoSecret $output
if ($output[-1] -ne 0 -or -not ($output | Out-String).Contains('safe elevated result')) { throw 'elevation_result_not_relayed' }
if (Test-Path -LiteralPath $script:elevationResultPath) { throw 'elevation_result_not_cleaned' }
if (-not $script:elevationWaited -or -not $script:elevationDisposed) { throw 'elevation_wait_or_dispose_missing' }
[IO.File]::WriteAllText($elevationFixture, ([IO.File]::ReadAllText($elevationFixture).Replace('return 0', 'return 1')), [Text.Encoding]::UTF8)
$output = @(Invoke-ElevatedInstall $ps $elevationFixture $script:MsiPath *>&1)
Assert-NoSecret $output
if ($output[-1] -ne 1 -or -not $script:elevationWaited -or -not $script:elevationDisposed) { throw 'elevation_exit_code_not_preserved' }
if (Test-Path -LiteralPath $script:elevationResultPath) { throw 'failed_elevation_result_not_cleaned' }
Write-Output ('MSI_ARGUMENTS=' + (ConvertTo-Json -InputObject @($script:msiCommandLines) -Compress))
Write-Output 'PowerShell 5.1 parse, capture, quoting and fake installation checks passed'
