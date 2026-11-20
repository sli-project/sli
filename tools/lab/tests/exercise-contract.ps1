$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\lab-common.ps1"
. "$PSScriptRoot\..\lab-exercise-attack.ps1"
function Assert-Test($Condition, [string]$Name) { if (-not $Condition) { throw $Name } }
function Assert-LabAdministrator {}
function Assert-LabDomain {
    return @{ DNSRoot = 'example.test'; NetBIOSName = 'LAB'; DomainMode = 'test';
        DomainSID = @{ Value = 'S-1-5-21-100000001-200000002-300000003' };
        UsersContainer = 'CN=Users,DC=example,DC=test'; PDCEmulator = 'LAB-DC01.example.test' }
}
$env:COMPUTERNAME = 'LAB-DC01'
$inventory = @{ domain = 'example.test'; netbios = 'LAB'; marker = 'SLI-LAB-SYNTHETIC'; users = @() }
for ($i = 1; $i -le 15; $i++) {
    $inventory.users += @{ sam = ('lab.u{0:000}' -f $i); enabled = $true; service = $false;
        marker = 'SLI-LAB-SYNTHETIC'; display_name = 'Synthetic lab user' }
}
$script:Created = 0
$script:Removed = 0
$script:FailGroup = $false
$script:FailCleanup = $false
$script:GroupRemoved = $false
function New-ADUser {
    param($Name, $SamAccountName, $DisplayName, $Path, $Description, $Enabled, $AccountPassword, [switch]$PassThru)
    $script:Created++
    return @{ SamAccountName = $SamAccountName; ObjectGUID = [guid]::NewGuid();
        DistinguishedName = "CN=$Name,CN=Users,DC=example,DC=test";
        SID = @{ Value = 'S-1-5-21-100000001-200000002-300000003-1100' } }
}
function Set-ADAccountControl { param($Identity, $DoesNotRequirePreAuth) }
function Get-ADUser { param($Identity, $Properties); return @{ Description = 'SLI-LAB-SYNTHETIC' } }
function Remove-ADUser {
    param($Identity, $Confirm)
    if ($script:FailCleanup) { throw 'private-error-must-not-escape' }
    $script:Removed++
}
function Get-ADGroup { param($Identity); return 'synthetic-group' }
function Add-ADGroupMember { param($Identity, $Members); if ($script:FailGroup) { throw 'private-error-must-not-escape' } }
function Remove-ADGroupMember { param($Identity, $Members, $Confirm); $script:GroupRemoved = $true }

$result = Invoke-LabExerciseAttack 6 $inventory
Assert-Test ($result.executed -and $result.restored -and $script:GroupRemoved -and $script:Created -eq $script:Removed) 'group_state_restored'
Assert-Test ($result.match_values -notcontains 'LAB-DC01') 'account_correlation_required'
$script:FailGroup = $true
$script:GroupRemoved = $false
$result = Invoke-LabExerciseAttack 6 $inventory
Assert-Test (-not $result.executed -and $result.restored -and $script:GroupRemoved -and $script:Created -eq $script:Removed) 'failed_group_state_restored'
$script:FailCleanup = $true
$result = Invoke-LabExerciseAttack 6 $inventory
Assert-Test (-not $result.restored -and $result.reason -eq 'cleanup_failed') 'cleanup_failure_visible'
$script:FailCleanup = $false

$script:AgentStarted = $false
function Get-Service { param($Name); return @{ Status = 'Running' } }
function Stop-Service { param($Name); throw 'private-error-must-not-escape' }
function Start-Service { param($Name); $script:AgentStarted = $true }
$result = Invoke-LabExerciseAttack 9 $inventory
Assert-Test (-not $result.executed -and $result.restored -and $script:AgentStarted) 'failed_stop_restores_agent'

function New-ScheduledTaskAction { param($Execute, $Argument); return 'harmless-action' }
function New-ScheduledTaskTrigger { param([switch]$Once, $At); return 'future-trigger' }
function Register-ScheduledTask { param($TaskName, $Action, $Trigger, $User); return $null }
$script:RemovedTask = ''
function Unregister-ScheduledTask { param($TaskName, $Confirm); $script:RemovedTask = $TaskName }
$result = Invoke-LabExerciseAttack 10 $inventory
Assert-Test ($result.executed -and $result.restored -and $script:RemovedTask -match '^SLI-Lab-Exercise-') 'temporary_task_removed'

$script:AuditCalls = @()
function Invoke-LabProcess {
    param($File, $Arguments)
    return @{ ExitCode = 0; Stdout = "Machine,Target,Subcategory,Guid,Inclusion,Exclusion,Value`nLAB-DC01,System,Logon,guid,Success,None,1" }
}
function Invoke-LabAudit {
    param($Guid, $Success, $Failure)
    $script:AuditCalls += "$Success/$Failure"
    if ($Success -eq 'disable') { throw 'private-error-must-not-escape' }
}
$result = Invoke-LabExerciseAttack 8 $inventory
Assert-Test (-not $result.executed -and $result.restored -and $script:AuditCalls[-1] -eq 'enable/disable') 'exact_audit_setting_restored'

function Clear-EventLog { throw 'must_never_clear_a_log' }
function Get-WinEvent { param($ListLog, $ErrorAction); return $null }
function New-EventLog { param($LogName, $Source) }
function Write-EventLog { param($LogName, $Source, $EventId, $EntryType, $Message) }
$script:RemovedLog = ''
function Remove-EventLog { param($LogName); $script:RemovedLog = $LogName }
function Invoke-LabProcess {
    param($File, $Arguments)
    Assert-Test ($Arguments[0] -ceq 'cl' -and $Arguments[1] -cmatch '^LX[0-9a-f]{20}$') 'only_temporary_log_cleared'
    return @{ ExitCode = 0 }
}
$result = Invoke-LabExerciseAttack 7 $inventory
Assert-Test ($result.executed -and $result.restored -and $script:RemovedLog -cmatch '^LX[0-9a-f]{20}$') 'temporary_log_removed_security_preserved'
$inventory.domain = 'other.example.test'
$before = $script:Created
$rejected = $false
try { $null = Invoke-LabExerciseAttack 6 $inventory } catch { $rejected = $true }
Assert-Test ($rejected -and $script:Created -eq $before) 'foreign_domain_rejected_before_mutation'
Write-Output 'exercise_contracts_passed'
