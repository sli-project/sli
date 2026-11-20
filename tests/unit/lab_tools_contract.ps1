#Requires -Version 5.1
# Native parser + hermetic reruns. No AD, service, network, Docker or secret file access.
[CmdletBinding()]
param([switch]$EmitExpected)
$ErrorActionPreference = 'Stop'
$lab = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\tools\lab'))
function Assert-Test([bool]$Condition, [string]$Code) { if (-not $Condition) { throw ('lab_test_' + $Code) } }
Assert-Test ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -eq 1) 'native_ps51'
foreach ($file in @(Get-ChildItem -LiteralPath $lab -Filter '*.ps1') + @(Get-Item -LiteralPath $PSCommandPath)) {
    $tokens = $null; $errors = $null
    $null = [Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    Assert-Test ($errors.Count -eq 0) ('parse_' + $file.Name)
}
. "$lab\lab-common.ps1"
$row = New-LabExpected 'password_spray' 'lab.u001' ([datetime]::UtcNow.AddSeconds(-1)) @(4625) $true '' '127.0.0.1'
if ($EmitExpected) { $row | ConvertTo-Json -Compress; exit 0 }

# MSI has its own command-line grammar: switches are bare, property values quoted.
$msiArguments = @('/i', 'C:\Lab Files\agent.msi', '/qn', '/norestart',
    'SERVER_URL=https://localhost:8443', 'CA_FILE=C:\Lab Files\server-ca.pem')
$msiCommand = '/i "C:\Lab Files\agent.msi" /qn /norestart SERVER_URL="https://localhost:8443" CA_FILE="C:\Lab Files\server-ca.pem"'
$converter = 'ConvertTo-LabMsiArgument'
Assert-Test ((($msiArguments | ForEach-Object { & $converter $_ }) -join ' ') -ceq $msiCommand) 'msi_commandline'
Assert-Test ((& $converter 'LABEL=a"b') -ceq 'LABEL="a""b"') 'msi_embedded_quote'
Assert-Test ((& $converter 'EMPTY=') -ceq 'EMPTY=""') 'msi_empty_property'
Assert-Test ((& $converter 'C:\Lab Files\') -ceq '"C:\Lab Files\"') 'msi_trailing_backslash'
$rejected = $false
try { $null = & $converter ("invalid" + [char]0) } catch { $rejected = $_.Exception.Message -eq 'lab_invalid_argument' }
Assert-Test $rejected 'msi_nul_rejected'

# Capture the actual ProcessStartInfo without launching an installer or any process.
function New-Object {
    param([string]$TypeName, [object[]]$ArgumentList)
    if ($TypeName -ne 'Diagnostics.Process') { return (Microsoft.PowerShell.Utility\New-Object @PSBoundParameters) }
    $stream = [pscustomobject]@{}
    $stream | Add-Member ScriptMethod ReadToEndAsync {
        $task = [pscustomobject]@{}
        $task | Add-Member ScriptMethod GetAwaiter { return $this }
        $task | Add-Member ScriptMethod GetResult { return '' }
        return $task
    }
    $process = [pscustomobject]@{ StartInfo = $null; StandardOutput = $stream; StandardError = $stream; ExitCode = 0; HasExited = $true }
    $process | Add-Member ScriptMethod Start { $script:processInfo = $this.StartInfo; return $true }
    $process | Add-Member ScriptMethod WaitForExit { param($Timeout); return $true }
    $process | Add-Member ScriptMethod Kill { throw 'unexpected_process_kill' }
    $process | Add-Member ScriptMethod Dispose { }
    return $process
}
try {
    foreach ($file in @('msiexec.exe', 'C:\Windows\System32\MSIEXEC.EXE')) {
        $result = Invoke-LabProcess $file $msiArguments
        Assert-Test ($result.ExitCode -eq 0 -and $script:processInfo.Arguments -ceq $msiCommand) 'msi_process_dispatch'
    }
    $null = Invoke-LabProcess 'python.exe' @('-I', 'C:\Lab Files\')
    Assert-Test ($script:processInfo.Arguments -ceq '"-I" "C:\Lab Files\\"') 'generic_process_quoting_preserved'
} finally { Remove-Item function:New-Object }
Write-Output 'lab_msi_contracts_passed'

$script:created = 0
$null = Ensure-LabObject { [pscustomobject]@{ Description = 'SLI-LAB-SYNTHETIC' } } { $script:created++; throw 'unexpected_create' }
Assert-Test ($script:created -eq 0) 'existing_no_create'
$null = Ensure-LabObject { $null } { $script:created++; [pscustomobject]@{ Description = 'SLI-LAB-SYNTHETIC' } }
Assert-Test ($script:created -eq 1) 'missing_create_once'
$rejected = $false
try { $null = Ensure-LabObject { [pscustomobject]@{ Description = 'unowned' } } { throw 'unexpected_create' } }
catch { $rejected = $_.Exception.Message -eq 'lab_existing_object_not_owned' }
Assert-Test $rejected 'unowned_collision'
Assert-LabSshTarget 'labadmin@lab.invalid'
$rejected = $false
try { Assert-LabSshTarget '-F@lab.invalid' } catch { $rejected = $_.Exception.Message -eq 'lab_ssh_target_invalid' }
Assert-Test $rejected 'ssh_option_rejected'
$acl = New-LabAcl $false
Assert-Test $acl.AreAccessRulesProtected 'secret_acl_protected'
Assert-Test ($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]).Count -eq 2) 'secret_acl_two_principals'
$passwords = @(1..10 | ForEach-Object { New-LabPassword })
Assert-Test (@($passwords | Sort-Object -Unique).Count -eq 10) 'password_random'
Assert-Test (@($passwords | Where-Object { $_.Length -lt 40 }).Count -eq 0) 'password_length'
$passwords = $null

# Domain already exists: refuse any feature install, promotion or reboot.
. "$lab\lab-01-domain.ps1"
function Assert-LabAdministrator { }
function Initialize-LabDirectory { param($Path) }
function Import-Module { param($Name) }
function Test-Path { param($LiteralPath, $Path, $PathType) return $true }
function Get-CimInstance { param($ClassName) return [pscustomobject]@{ PartOfDomain = $true; DomainRole = 5; Name = 'LAB-DC01' } }
$script:domainName = 'demo.example'
function Get-ADDomain { return [pscustomobject]@{ DNSRoot = $script:domainName; NetBIOSName = 'DEMO'; DistinguishedName = 'DC=demo,DC=example'; DomainSID = @{ Value = 'S-1-5-21-1-2-3' } } }
function Install-WindowsFeature { throw 'unexpected_feature_install' }
function Install-ADDSForest { throw 'unexpected_promotion' }
function Restart-Computer { throw 'unexpected_reboot' }
$Continue = $false
$null = Invoke-LabDomain
$script:domainName = 'other.invalid'
$rejected = $false
try { $null = Invoke-LabDomain } catch { $rejected = $_.Exception.Message -eq 'lab_foreign_domain_rejected' }
Assert-Test $rejected 'foreign_domain'
$script:domainName = 'demo.example'

# Entire population rerun with existing objects, members, settings and links.
. "$lab\lab-02-populate.ps1"
function Assert-LabAdministrator { }
function Initialize-LabDirectory { param($Path) }
function New-ADUser { throw 'unexpected_user_create' }
function New-ADComputer { throw 'unexpected_computer_create' }
function New-ADGroup { throw 'unexpected_group_create' }
function New-ADOrganizationalUnit { throw 'unexpected_ou_create' }
function Get-ADOrganizationalUnit { param($Filter, $Properties) return [pscustomobject]@{ Description = 'SLI-LAB-SYNTHETIC' } }
function Get-ADComputer { param($Filter, $Properties) return [pscustomobject]@{ Description = 'SLI-LAB-SYNTHETIC' } }
function Get-ADUser {
    param($Identity, $Filter, $Properties)
    return [pscustomobject]@{ Description = 'SLI-LAB-SYNTHETIC'; DistinguishedName = "CN=$Identity,DC=demo,DC=example" }
}
$data = Get-Content -LiteralPath "$lab\lab-data.json" -Raw -Encoding UTF8 | ConvertFrom-Json
$script:allMembers = @($data.users | ForEach-Object { 'CN=' + $_.sam + ',DC=demo,DC=example' }) +
    @($data.groups | ForEach-Object { 'CN=' + $_ + ',DC=demo,DC=example' })
function Get-ADGroup { param($Identity, $Filter, $Properties)
    if ($Identity -and $Identity.EndsWith('-551')) { Assert-Test ($Identity -eq 'S-1-5-32-551') 'builtin_group_sid' }
    return [pscustomobject]@{
    Description = 'SLI-LAB-SYNTHETIC'; DistinguishedName = "CN=$Identity,DC=demo,DC=example"; Member = $script:allMembers
} }
function Add-ADGroupMember { throw 'unexpected_membership_add' }
function Set-ADDefaultDomainPasswordPolicy { }
function Get-GPO { param($Name); return [pscustomobject]@{ Id = [guid]'00000000-0000-4000-8000-000000000010'; Description = 'SLI-LAB-SYNTHETIC' } }
function New-GPO { throw 'unexpected_gpo_create' }
function Get-GPRegistryValue {
    param($Guid, $Key, $ValueName)
    $values = @{ NoLMHash = 1; SCENoApplyLegacyAuditPolicy = 1; InactivityTimeoutSecs = 900; EnableFirewall = 1;
        fDenyTSConnections = 1; NoLockScreenCamera = 1; NC_ShowSharedAccessUI = 0; NoAutoRebootWithLoggedOnUsers = 1 }
    return [pscustomobject]@{ Value = $values[$ValueName]; Type = 'DWord' }
}
function Set-GPRegistryValue { throw 'unexpected_gpo_update' }
function Get-GPInheritance { param($Target); return [pscustomobject]@{ GpoLinks = @([pscustomobject]@{ GpoId = [guid]'00000000-0000-4000-8000-000000000010' }) } }
function New-GPLink { throw 'unexpected_gpo_link' }
function Get-Acl {
    param($Path, [switch]$Audit)
    $security = New-Object DirectoryServices.ActiveDirectorySecurity
    $sid = New-Object Security.Principal.SecurityIdentifier('S-1-1-0')
    $security.AddAuditRule((New-Object DirectoryServices.ActiveDirectoryAuditRule($sid, [DirectoryServices.ActiveDirectoryRights]::WriteProperty, [Security.AccessControl.AuditFlags]::Success)))
    return $security
}
function Set-Acl { throw 'unexpected_gpo_sacl_update' }
$fileFunction = (Get-Item function:Set-LabGpoFile).ScriptBlock
function Set-LabGpoFile { param($Gpo, $RelativePath, $Content, $Extension, $Encoding) }
function Invoke-LabAudit { param($Guid, $Success, $Failure) }
function Invoke-LabProcess { param($File, $Arguments, $TimeoutSeconds); return [pscustomobject]@{ ExitCode = 0; Stdout = '' } }
$null = Invoke-LabPopulate
$null = Invoke-LabPopulate

# Public GPO file updates preserve user version and do nothing on identical content.
Remove-Item function:Test-Path
$taskTemp = Join-Path $PSScriptRoot ('lab-contract-' + [guid]::NewGuid().ToString())
$script:gpoObject = [pscustomobject]@{ gPCFileSysPath = $taskTemp; gPCMachineExtensionNames = '[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]'; versionNumber = 65538 }
$script:fileWrites = 0
function Get-ADObject { param($Identity, $Properties); return $script:gpoObject }
function Set-ADObject { param($Identity, $Replace); $script:fileWrites++; $script:gpoObject.versionNumber = $Replace.versionNumber; $script:gpoObject.gPCMachineExtensionNames = $Replace.gPCMachineExtensionNames }
try {
    $gpo = Get-GPO 'LAB-Password'
    $extension = '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'
    & $fileFunction $gpo 'Machine\lab.inf' "[System Access]`r`nMinimumPasswordLength = 14`r`n" $extension ([Text.Encoding]::Unicode)
    & $fileFunction $gpo 'Machine\lab.inf' "[System Access]`r`nMinimumPasswordLength = 14`r`n" $extension ([Text.Encoding]::Unicode)
    Assert-Test ($script:fileWrites -eq 1 -and $script:gpoObject.versionNumber -eq 65539) 'gpo_file_idempotent'
    Assert-Test $script:gpoObject.gPCMachineExtensionNames.Contains('35378EAC') 'gpo_registry_extension_preserved'
} finally {
    foreach ($name in @('Machine\lab.inf', 'GPT.INI')) { $file = Join-Path $taskTemp $name; if ([IO.File]::Exists($file)) { [IO.File]::Delete($file) } }
    if ([IO.Directory]::Exists("$taskTemp\Machine")) { [IO.Directory]::Delete("$taskTemp\Machine") }
    if ([IO.Directory]::Exists($taskTemp)) { [IO.Directory]::Delete($taskTemp) }
}

# Simulation writes failed execution explicitly and skips completed daily scenarios.
. "$lab\lab-03-simulate.ps1"
$script:captured = @()
function Write-LabExpected { param($Row); $script:captured += $Row }
function Invoke-LabBind { param($Account, $Password, $SuccessExpected); return $false }
$result = Invoke-LabLogon 'wrong_password' 'lab.u001' $false 'synthetic-unused-password'
Assert-Test (-not $result -and $script:captured.Count -eq 1 -and -not $script:captured[0].executed) 'failed_attempt_recorded'
function Test-Path { param($LiteralPath, $Path, $PathType); return $true }
Invoke-LabDaily 'password_spray' { throw 'unexpected_daily_replay' }

# Verifier: exact identity/source/time, no event reuse, incomplete is unavailable.
. "$lab\lab-verify.ps1" -DomainId 1 -ApiKeyFile 'synthetic-unused'
$script:LabHeaders = @{}
$script:LabExactCache = @{}
$script:LabEvidenceUnavailable = $false
$expected = (New-LabExpected 'password_spray' 'lab.u001' ([datetime]'2026-10-09T10:00:00Z') @(4625) $true '' '127.0.0.1') | ConvertTo-Json | ConvertFrom-Json
$expected.ended_at_utc = '2026-10-09T10:00:02Z'
Assert-LabExpected $expected
$event = [pscustomobject]@{ event_db_id = 1; event_id = 4625; time_created_utc = '2026-10-09T10:00:01Z';
    source_host = @{ hostname = 'LAB-DC01.demo.example' }; affected_account = @{ name = 'DEMO\lab.u001' }; source_address = '127.0.0.1' }
$used = @{}
Assert-Test ($null -ne (Find-LabEvent $expected @($event) $used)) 'event_match'
Assert-Test ($null -eq (Find-LabEvent $expected @($event) $used)) 'event_no_reuse'
$event.source_address = '192.0.2.1'
Assert-Test ($null -eq (Find-LabEvent $expected @($event) @{})) 'event_source_mismatch'
$event.source_address = '127.0.0.1'
$script:LabEvidenceUnavailable = $false
$event.affected_account.name = $null
Assert-Test ($null -eq (Find-LabEvent $expected @($event) @{}) -and $script:LabEvidenceUnavailable) 'missing_identity_unavailable'
$event.affected_account.name = 'lab.u002'
Assert-Test ($null -eq (Find-LabEvent $expected @($event) @{})) 'event_identity_mismatch'
$event.affected_account.name = 'lab.u001'
$event.time_created_utc = '2026-10-08T10:00:01Z'
Assert-Test ($null -eq (Find-LabEvent $expected @($event) @{})) 'event_time_mismatch'
Assert-Test ((Get-LabMatchState $null $false) -eq 'UNAVAILABLE') 'partial_not_missing'
Assert-Test ((Get-LabMatchState $null $true) -eq 'MISSING') 'complete_missing'
$expected.scenario = 'gpo_change'; $expected.target = 'LAB-Lock'; $expected.source_address = $null
$expected.object_id = '00000000-0000-4000-8000-000000000010'; $expected.event_ids = @(5136)
$expected.event_object_id = '00000000-0000-4000-8000-000000000012'
$gpoEvent = [pscustomobject]@{ event_db_id = 2; event_id = 5136; time_created_utc = '2026-10-09T10:00:01Z';
    source_host = @{ hostname = 'LAB-DC01.demo.example' }; object_id = $expected.object_id }
Assert-Test ($null -eq (Find-LabEvent $expected @($gpoEvent) @{})) 'gpo_cn_not_event_object_guid'
$gpoEvent.object_id = $expected.event_object_id
Assert-Test ($null -ne (Find-LabEvent $expected @($gpoEvent) @{})) 'gpo_event_object_guid'
$change = [pscustomobject]@{ object_id = $expected.object_id; kind = 'attribute_changed'; observed_at = '2026-10-09T10:10:00Z' }
Assert-Test ($null -ne (Find-LabChange $expected @($change))) 'snapshot_exact_guid'
$change.object_id = '00000000-0000-4000-8000-000000000011'
Assert-Test ($null -eq (Find-LabChange $expected @($change))) 'snapshot_foreign_guid'
$script:pageNumber = 0
function Invoke-RestMethod {
    param($Method, $Uri, $Headers, $TimeoutSec)
    $script:pageNumber++
    if ($script:pageNumber -eq 1) { return [pscustomobject]@{ state = 'ok'; items = @(1); has_more = $true; next_cursor = 'next' } }
    Assert-Test ($Uri.Contains('cursor=next')) 'paging_cursor'
    return [pscustomobject]@{ state = 'partial'; items = @(2); has_more = $false }
}
$page = Read-LabReport 'events.journal/data' @{}
Assert-Test ($page.Items.Count -eq 2 -and -not $page.Complete) 'pagination_partial'
function Invoke-RestMethod { throw 'synthetic_unavailable' }
$page = Read-LabReport 'events.journal/data' @{}
Assert-Test ($page.Items.Count -eq 0 -and -not $page.Complete) 'api_error_unavailable'

# Enrolled MSI rerun starts the service without reading/writing a new token.
. "$lab\lab-04-agent.ps1" -Phase Enroll
function Assert-LabAdministrator { }
function Initialize-LabDirectory { param($Path) }
function Assert-LabPath { param($Path); return $Path }
function Get-Content {
    param($LiteralPath, [switch]$Raw)
    if ($LiteralPath.EndsWith('agent.json')) { return '{"server_url":"https://localhost:8443","service_identity_sid":"S-1-5-18","state_dir":"C:\\SLI-Lab\\synthetic-state"}' }
    return (@{ error_code = $null; observed_at_utc = [datetime]::UtcNow.ToString('o'); collection_enabled = $false } | ConvertTo-Json)
}
function Get-Service { param($Name); return [pscustomobject]@{ Status = 'Running' } }
$script:started = 0; $script:removed = 0
function Stop-Service { param($Name) }
function Start-Service { param($Name); $script:started++ }
function Remove-Item { param($LiteralPath, [switch]$Force); $script:removed++ }
function Write-LabSecret { throw 'unexpected_enrollment_token_write' }
$state = Invoke-LabAgent
Assert-Test ($state -eq 'lab_agent_registered_waiting_for_server_policy') 'enrollment_not_collection'
Assert-Test ($script:started -eq 1 -and $script:removed -eq 1) 'enrolled_rerun_cleanup'
Write-Output 'lab_ps51_contracts_passed'
