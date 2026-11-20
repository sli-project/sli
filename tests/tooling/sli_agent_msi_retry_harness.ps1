#Requires -Version 5.1
param([string]$SourcePath, [string]$TestRoot)
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$null = [Management.Automation.Language.Parser]::ParseFile($SourcePath, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'installer_parse_failed' }
if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) { throw 'requires_powershell_51' }
. $SourcePath

# Inventory tests mock both providers; never enumerate or repair the host MSI.
$realInventory = ${function:Get-InstalledAgentMsi}
$script:product = '{00000000-0000-4000-8000-000000000010}'
$script:related = @()
$script:registry = $null
function Get-SliRelatedMsiProducts { return $script:related }
function Get-ItemProperty { return $script:registry }
function Test-Path {
    param([string]$LiteralPath, [string]$PathType)
    if ($LiteralPath -eq 'HKLM:\SOFTWARE\SLI\Agent') { return $null -ne $script:registry }
    return Microsoft.PowerShell.Management\Test-Path @PSBoundParameters
}
if (& $realInventory) { throw 'empty_inventory_failed' }
$script:related = @($script:product)
$script:registry = @{ ProductCode = $script:product }
if ((& $realInventory) -cne $script:product) { throw 'matching_inventory_failed' }
$script:registry = @{ ServiceAccount = 'LocalSystem' }
if ((& $realInventory) -cne $script:product) { throw 'legacy_inventory_failed' }
$script:registry = $null
if ((& $realInventory) -cne $script:product) { throw 'related_product_inventory_failed' }
foreach ($case in @(
    @{ Related = @(); Registry = @{ ProductCode = $script:product } }
    @{ Related = @($script:product, $script:product); Registry = @{ ProductCode = $script:product } }
    @{ Related = @($script:product); Registry = @{ ProductCode = 'bad-code' } }
    @{ Related = @($script:product); Registry = @{ ProductCode = '{00000000-0000-4000-8000-000000000011}' } }
)) {
    $script:related = $case.Related
    $script:registry = $case.Registry
    try { $null = & $realInventory; throw 'ambiguous_inventory_accepted' }
    catch { if ($_.Exception.Message -ne 'agent_msi_inventory_mismatch') { throw } }
}
Remove-Item Function:\Test-Path
Remove-Item Function:\Get-ItemProperty

$env:ProgramData = Join-Path $TestRoot 'data'
$root = Join-Path $env:ProgramData 'SLI\Agent'
$state = Join-Path $root 'state'
$url = 'https://example.invalid:8443'
$msi = Join-Path $TestRoot 'agent.msi'
$ca = Join-Path $TestRoot 'public-ca.pem'
$script:installed = $null
$script:target = $script:product
$script:removeExit = 0
$script:repairExit = 0
$script:installExit = 0
$script:incomplete = $false
$script:race = $false
$script:events = New-Object 'System.Collections.Generic.List[string]'
function New-Fixture {
    $script:installed = $script:product
    $null = [IO.Directory]::CreateDirectory($state)
    [IO.File]::WriteAllText((Join-Path $root '.msi-owned'), 'sli-agent-msi-v1')
    [IO.File]::WriteAllText((Join-Path $root 'agent.json'), (@{
        state_dir = $state; server_url = $url; service_identity_sid = 'S-1-5-18'
    } | ConvertTo-Json))
    # Prepare artifacts alone do not prove registration.
    [IO.File]::WriteAllText((Join-Path $state 'identity-key.json'), 'fixture-key')
    [IO.File]::WriteAllText((Join-Path $state 'host.json'), 'fixture-host')
}
function Get-InstalledAgentMsi { return $script:installed }
function Get-AgentMsiProductCode { return $script:target }
function Stop-LocalAgentService {
    $script:events.Add('stop')
    $script:events.Add('wait')
    if ($script:race) { [IO.File]::WriteAllText((Join-Path $state 'identity.json'), 'identity-preserved') }
}
function Start-LocalAgentService { $script:events.Add('start'); $script:events.Add('wait') }
function Get-Service {
    $fake = [pscustomobject]@{ Status = 'Running' }
    $fake | Add-Member ScriptMethod WaitForStatus { param($Status, $Timeout) $script:events.Add('wait') }
    return $fake
}
function Invoke-LocalProcess([string]$FilePath, [string[]]$Arguments, [int]$TimeoutSeconds) {
    if ($FilePath -eq 'fixture-docker.exe') {
        if ($Arguments -contains 'server.sli.agents.issue_token') {
            $script:events.Add('issue-token')
            return @{ ExitCode = 0; Stdout = ('t' * 43) }
        }
        if ($Arguments -contains '-c' -and $Arguments[-1] -match 'SLI_TLS_CA_FILE') {
            return @{ ExitCode = 0; Stdout = (@{ server_url = $url; ca = '-----BEGIN CERTIFICATE-----public-fixture' } | ConvertTo-Json) }
        }
        $script:events.Add('registered')
        return @{ ExitCode = 0; Stdout = 'registered' }
    }
    if ($Arguments -contains 'prepare') {
        $script:events.Add('prepare')
        return @{ ExitCode = 0; Stdout = (@{ host_id = '00000000-0000-4000-8000-000000000001'; key_fingerprint = ('a' * 64) } | ConvertTo-Json) }
    }
    if ([IO.Path]::GetFileName($FilePath) -ne 'msiexec.exe' -or $TimeoutSeconds -ne 600 -or
        $Arguments -notcontains '/qn' -or $Arguments -notcontains '/norestart' -or $Arguments -notcontains '/L*v') { throw 'unsafe_msi_invocation' }
    $action = $Arguments[0]
    $script:events.Add($action)
    if ($action -in @('/x', '/fomus') -and $Arguments[1] -cne $script:product) { throw 'wrong_product_code' }
    switch ($action) {
        '/x' {
            if ([IO.Path]::GetFileName($Arguments[-1]) -ne 'agent-remove.log') { throw 'remove_log_missing' }
            if ($script:removeExit -eq 0) {
                $script:installed = $null
                if (-not $script:incomplete) {
                    $fixture = [IO.Path]::GetFullPath($root)
                    if (-not $fixture.StartsWith([IO.Path]::GetFullPath($TestRoot) + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'fixture_outside_test_root' }
                    Remove-Item -LiteralPath $fixture -Recurse -Force
                }
            }
            return @{ ExitCode = $script:removeExit; Stdout = '' }
        }
        '/fomus' {
            if ([IO.Path]::GetFileName($Arguments[-1]) -ne 'agent-repair.log') { throw 'repair_log_missing' }
            return @{ ExitCode = $script:repairExit; Stdout = '' }
        }
        '/i' {
            if ($script:installed -or (Test-Path -LiteralPath $root)) { throw 'install_before_clean_removal' }
            if ($Arguments -notcontains "SERVER_URL=$url" -or -not ($Arguments | Where-Object { $_ -like 'CA_FILE=*' })) { throw 'install_public_properties_missing' }
            New-Fixture
            return @{ ExitCode = $script:installExit; Stdout = '' }
        }
        default { throw 'unexpected_msi_action' }
    }
}
function Invoke-Fixture { Invoke-AgentMsiInstall $msi $url $ca $script:installed }
function Assert-Failure([string]$Reason) {
    try { Invoke-Fixture; throw 'failure_not_reported' }
    catch { if ($_.Exception.Message -ne $Reason) { throw } }
    if ($script:events.Contains('/i') -or $script:events.Contains('/fomus')) { throw 'failure_started_install_or_repair' }
}

Invoke-Fixture
if (($script:events -join ',') -ne '/i') { throw 'fresh_install_failed' }
$script:events.Clear()
$script:target = '{00000000-0000-4000-8000-000000000011}'
Invoke-Fixture
if (($script:events -join ',') -ne 'stop,wait,/x,/i') { throw 'unregistered_retry_failed' }

$identity = Join-Path $state 'identity.json'
[IO.File]::WriteAllText($identity, 'malformed-but-preserved')
$config = [IO.File]::ReadAllText((Join-Path $root 'agent.json'))
$script:events.Clear()
Assert-Failure 'agent_upgrade_previous_msi_required'
if ($script:events.Count -or [IO.File]::ReadAllText($identity) -cne 'malformed-but-preserved') { throw 'registered_agent_changed' }
$script:target = $script:product
Invoke-Fixture
if (($script:events -join ',') -ne 'stop,wait,/fomus' -or [IO.File]::ReadAllText($identity) -cne 'malformed-but-preserved' -or
    [IO.File]::ReadAllText((Join-Path $root 'agent.json')) -cne $config) { throw 'repair_did_not_preserve_state' }
Remove-Item -LiteralPath $identity

foreach ($case in @(@{ Exit = 1603; Reason = 'msi_remove_failed' }, @{ Exit = 3010; Reason = 'msi_remove_reboot_required' })) {
    $script:removeExit = $case.Exit
    $script:events.Clear()
    Assert-Failure $case.Reason
    if (($script:events -join ',') -ne 'stop,wait,/x') { throw 'remove_failure_order_failed' }
}
$script:removeExit = 0
$script:incomplete = $true
$script:events.Clear()
Assert-Failure 'msi_remove_incomplete'
$script:incomplete = $false
New-Fixture

$script:target = '{00000000-0000-4000-8000-000000000011}'
$script:race = $true
$script:events.Clear()
Assert-Failure 'agent_upgrade_previous_msi_required'
if (($script:events -join ',') -ne 'stop,wait,start,wait' -or -not (Test-Path -LiteralPath $identity)) { throw 'enrollment_race_not_protected' }
$script:race = $false
Remove-Item -LiteralPath $identity
$tls = Join-Path $state 'tls-fixture'
$null = [IO.Directory]::CreateDirectory($tls)
[IO.File]::WriteAllText((Join-Path $tls 'certificate.pem'), 'orphan-certificate')
$script:events.Clear()
Assert-Failure 'agent_upgrade_previous_msi_required'
if ($script:events.Count) { throw 'orphan_certificate_not_protected' }
Remove-Item -LiteralPath (Join-Path $tls 'certificate.pem')
# Reparse descendants are rejected before service or MSI mutation.
$junction = Join-Path $state 'unsafe-junction'
$null = New-Item -ItemType Junction -Path $junction -Target $TestRoot
$script:events.Clear()
Assert-Failure 'reparse_path_rejected'
if ($script:events.Count) { throw 'reparse_state_modified' }
[IO.Directory]::Delete($junction)
[IO.File]::WriteAllText((Join-Path $root 'agent.json'), (@{ state_dir = $TestRoot } | ConvertTo-Json))
Assert-Failure 'installed_config_mismatch'

# Exercise the complete owner command with every privileged/external action
# mocked. Only fixture directories are created; Docker/DB/services/MSI stay idle.
New-Fixture
$env:ProgramFiles = Join-Path $TestRoot 'programs'
$script:MsiPath = $msi
$script:ServerUrl = $url
$script:Container = 'fixture-api'
function Test-LocalAdministrator { return $true }
function Get-FileHash { return @{ Hash = 'afc08f33a706103be5280dc3daa04b4e3f2c841abc9910bba1a7ea62f5591dd1' } }
function Get-Command { return @{ Source = 'fixture-docker.exe' } }
function Get-ScheduledTask { return $null }
function Move-PilotAgentState { return $null }
function Initialize-LocalAgentParent { }
function Set-Acl { }
function New-RestrictedSecurity {
    # The production descriptor is covered by the separate ACL harness. This
    # descriptor permits the unelevated test caller to create its fixture folder.
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $caller = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($caller, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')))
    return $acl
}
function Write-EnrollmentToken {
    param($Path, $Token)
    if ($Token -cne ('t' * 43)) { throw 'unexpected_fixture_token' }
    $script:events.Add('write-token')
    [IO.File]::WriteAllText($Path, 'fixture-placeholder')
}
function Start-LocalAgentService {
    $script:events.Add('start')
    $script:events.Add('wait')
    [IO.File]::WriteAllText((Join-Path $state 'identity.json'), 'registered-fixture')
}
$script:events.Clear()
$output = @(Install-SliAgentLocal *>&1)
if (($output | Out-String).Contains(('t' * 43))) { throw 'token_leaked' }
if ($output[-1] -ne 0 -or ($script:events -join ',') -ne 'stop,wait,/x,/i,stop,wait,prepare,issue-token,write-token,start,wait,registered') {
    throw ('complete_retry_did_not_register: ' + ($output | Out-String) + '; events=' + ($script:events -join ','))
}
if (Test-Path -LiteralPath (Join-Path $root 'enrollment.token')) { throw 'fixture_token_not_cleaned' }
if (Test-Path -LiteralPath (Join-Path $env:ProgramData 'SLI\LocalBootstrap\server-ca.pem')) { throw 'bootstrap_ca_not_cleaned' }
$script:target = $script:product
$script:events.Clear()
$output = @(Install-SliAgentLocal *>&1)
if ($output[-1] -ne 0 -or $script:events.Contains('issue-token') -or $script:events.Contains('/x') -or
    ($script:events -join ',') -ne 'stop,wait,/fomus,stop,wait,prepare,start,wait,registered') { throw 'complete_repair_changed_registration' }
Write-Output 'PowerShell 5.1 MSI retry checks passed'
