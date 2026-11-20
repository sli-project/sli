<#
VDS: powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\SLI-Lab\lab-03-simulate.ps1 -InstallTask
SYSTEM task runs every 5 minutes (including after reboot), weekdays 09:00-18:00
in the VDS timezone; rare night logons. -RunDaily runs today's missing scenarios now.
Day/scenario markers prevent replay after successful completion; a mutex prevents overlap.
LDAP Negotiate binds use 127.0.0.1:389, never an external target. Passwords stay on VDS.
Expected JSONL records describe attempts, not proof that Windows/SLI emitted an event.
Stop/remove with Disable-ScheduledTask/Unregister-ScheduledTask -TaskName 'SLI Lab Day'.
#>
#Requires -Version 5.1
[CmdletBinding()]
param([switch]$InstallTask, [switch]$RunDaily)
. "$PSScriptRoot\lab-common.ps1"

function Invoke-LabBind([string]$Account, [string]$Password, [bool]$SuccessExpected) {
    Add-Type -AssemblyName System.DirectoryServices.Protocols
    $identifier = New-Object DirectoryServices.Protocols.LdapDirectoryIdentifier('127.0.0.1', 389)
    $credential = New-Object Net.NetworkCredential($Account, $Password, 'DEMO')
    $connection = New-Object DirectoryServices.Protocols.LdapConnection($identifier, $credential,
        [DirectoryServices.Protocols.AuthType]::Negotiate)
    try {
        $connection.Timeout = New-TimeSpan -Seconds 10
        $connection.SessionOptions.Signing = $true
        $connection.SessionOptions.Sealing = $true
        $connection.Bind()
        return $SuccessExpected
    } catch [DirectoryServices.Protocols.LdapException] {
        # Invalid credentials proves that an authentication attempt reached AD.
        # Connection/referral/policy errors are failed scenarios, never expected successes.
        return (-not $SuccessExpected -and $_.Exception.ErrorCode -eq 49)
    } finally { $connection.Dispose(); $Password = $null }
}

function Invoke-LabLogon([string]$Scenario, [string]$Account, [bool]$Success, [string]$WrongPassword = '') {
    $start = [datetime]::UtcNow
    $password = $WrongPassword
    if ($Success -or $Scenario -eq 'disabled_logon') {
        $password = [IO.File]::ReadAllText((Assert-LabPath "$script:LabRoot\credentials\$Account.secret"))
    }
    if (-not $password) { $password = New-LabPassword }
    $executed = $false
    try { $executed = Invoke-LabBind $Account $password $Success }
    finally {
        $password = $null
        # A failed NTLM bind can emit only 4776 on the DC after account lockout.
        $ids = if ($Success) { @(4624) } else { @(4625, 4776) }
        Write-LabExpected (New-LabExpected $Scenario $Account $start $ids $executed '' '127.0.0.1')
    }
    return $executed
}

function Invoke-LabDaily([string]$Scenario, [scriptblock]$Operation) {
    $marker = "$script:LabRoot\daily\$([datetime]::Now.ToString('yyyy-MM-dd'))-$Scenario.done"
    if (Test-Path -LiteralPath $marker) { return }
    if (& $Operation) { 'done' | Set-Content -LiteralPath $marker -Encoding UTF8 }
}

function Invoke-LabSimulation {
    Assert-LabAdministrator
    $domain = Assert-LabDomain
    if ($InstallTask) {
        $action = New-ScheduledTaskAction -Execute "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" `
            -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '"')
        $trigger = New-ScheduledTaskTrigger -Once -At ([datetime]::Now.AddMinutes(1)) -RepetitionInterval (New-TimeSpan -Minutes 5)
        $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 4)
        Register-ScheduledTask -TaskName 'SLI Lab Day' -Action $action -Trigger $trigger -Settings $settings -User SYSTEM -RunLevel Highest -Force | Out-Null
        Write-Output 'lab_simulation_task_ready'
        return
    }
    $mutex = New-Object Threading.Mutex($false, 'Global\SLI-Lab-Day')
    $locked = $false
    try {
        try { $locked = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $locked = $true }
        if (-not $locked) { return }
        Initialize-LabDirectory "$script:LabRoot\daily"
        $now = [datetime]::Now
        $workday = $now.DayOfWeek -notin @([DayOfWeek]::Saturday, [DayOfWeek]::Sunday) -and $now.Hour -ge 9 -and $now.Hour -lt 18
        if ($workday) {
            for ($i = 0; $i -lt (Get-Random -Minimum 2 -Maximum 8); $i++) {
                $sam = 'lab.u{0:000}' -f (Get-Random -Minimum 1 -Maximum 120)
                $null = Invoke-LabLogon 'workday_logon' $sam $true
            }
            if ((Get-Random -Minimum 0 -Maximum 10) -eq 0) { $null = Invoke-LabLogon 'wrong_password' 'lab.u050' $false }
        } elseif ($now.Hour -lt 6 -and (Get-Random -Minimum 0 -Maximum 100) -eq 0) {
            $null = Invoke-LabLogon 'night_logon' 'lab.u051' $true
        }
        if (-not $RunDaily -and (-not $workday -or $now.Hour -lt 10)) { return }
        Invoke-LabDaily 'password_spray' {
            $ok = $true
            $wrong = New-LabPassword
            for ($i = 60; $i -lt 90; $i++) {
                $sam = 'lab.u{0:000}' -f $i
                for ($j = 0; $j -lt 2; $j++) {
                    if (-not (Invoke-LabLogon 'password_spray' $sam $false $wrong)) { $ok = $false }
                }
            }
            $wrong = $null
            return $ok
        }
        Invoke-LabDaily 'single_account_brute' {
            $ok = $true
            Unlock-ADAccount 'lab.u130'
            try {
                for ($i = 0; $i -lt 25; $i++) {
                    if (-not (Invoke-LabLogon 'single_account_brute' 'lab.u130' $false)) { $ok = $false }
                }
            } finally { Unlock-ADAccount 'lab.u130' }
            return $ok
        }
        Invoke-LabDaily 'disabled_logon' { return (Invoke-LabLogon 'disabled_logon' 'lab.u148' $false) }
        Invoke-LabDaily 'privileged_add' {
            $start = [datetime]::UtcNow
            $sam = 'lab.u{0:000}' -f (131 + ($now.DayOfYear % 16))
            $user = Get-ADUser $sam -Properties Description
            Assert-LabOwned $user
            $group = Get-ADGroup ($domain.DomainSID.Value + '-512') -Properties Member
            $ok = $false
            try {
                # Retain the change for the next snapshot; never remove it immediately.
                if ($group.Member -contains $user.DistinguishedName) { Remove-ADGroupMember $group $user -Confirm:$false }
                Add-ADGroupMember $group $user
                $ok = $true
            } finally { Write-LabExpected (New-LabExpected 'privileged_add' $sam $start @(4728) $ok $user.ObjectGUID.ToString() '' $user.SID.Value $group.ObjectGUID.ToString()) }
            return $ok
        }
        Invoke-LabDaily 'gpo_change' {
            Import-Module GroupPolicy
            $gpo = Get-GPO -Name 'LAB-Lock'
            Assert-LabOwned $gpo
            # The GPO CN GUID used by snapshots differs from the AD object's objectGUID in 5136.
            $gpc = Get-ADObject -Identity ('CN={' + $gpo.Id.ToString() + '},CN=Policies,CN=System,' + $domain.DistinguishedName) -Properties objectGUID
            $start = [datetime]::UtcNow
            $ok = $false
            try {
                Set-GPRegistryValue -Guid $gpo.Id -Key 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
                    -ValueName InactivityTimeoutSecs -Type DWord -Value (600 + $now.DayOfYear) | Out-Null
                $ok = $true
            } finally { Write-LabExpected (New-LabExpected 'gpo_change' 'LAB-Lock' $start @(5136) $ok $gpo.Id.ToString() '' '' '' $gpc.ObjectGUID.ToString()) }
            return $ok
        }
        Invoke-LabDaily 'audit_change' {
            $start = [datetime]::UtcNow
            $ok = $false
            try { Invoke-LabAudit '{0cce9215-69ae-11d9-bed3-505054503030}' 'enable' 'disable'; $ok = $true }
            finally {
                Invoke-LabAudit '{0cce9215-69ae-11d9-bed3-505054503030}'
                Write-LabExpected (New-LabExpected 'audit_change' 'LAB-Audit' $start @(4719) $ok)
            }
            return $ok
        }
        Write-Output 'lab_simulation_completed'
    } finally { if ($locked) { $mutex.ReleaseMutex() }; $mutex.Dispose() }
}

if ($MyInvocation.InvocationName -ne '.') {
    try { Invoke-LabSimulation } catch { Write-Output 'lab_simulation_failed'; exit 1 }
}
