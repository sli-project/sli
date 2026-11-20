<# Dot-source only. Invoked by lab-exercise.py locally on LAB-DC01 or over SSH.
   No credentials are accepted, read from disk, or written to the result. #>
#Requires -Version 5.1

function Invoke-LabExerciseAttack([int]$Number, $Inventory) {
    Assert-LabAdministrator
    $domain = Assert-LabDomain
    if ($env:COMPUTERNAME -cne 'LAB-DC01' -or $domain.DomainMode -eq $null -or
        $Inventory.domain -cne $domain.DNSRoot -or $Inventory.netbios -cne $domain.NetBIOSName -or
        $Inventory.marker -cne $script:LabMarker) { throw 'exercise_lab_required' }
    $mutex = New-Object Threading.Mutex($false, 'Global\SLI-Lab-Day')
    $locked = $false
    $created = New-Object Collections.ArrayList
    $result = @{ executed = $false; restored = $true; reason = 'attack_failed'; match_values = @() }
    try {
        try { $locked = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $locked = $true }
        if (-not $locked) { $result.reason = 'lab_simulation_busy'; return $result }
        $result.started_at_utc = [datetime]::UtcNow.ToString('o')
        $result.match_values = @($env:COMPUTERNAME, $domain.PDCEmulator)
        $templates = @($Inventory.users | Where-Object { $_.enabled -and -not $_.service })
        if ($templates.Count -lt 15 -or @($templates | Where-Object {
            $_.marker -cne $script:LabMarker -or $_.sam -cnotmatch '^lab\.u[0-9]{3}$'
        }).Count -gt 0) { throw 'exercise_inventory_invalid' }

        function New-ExerciseUser([int]$Index, [switch]$NoPreauth, [string[]]$Spns = @()) {
            # Clone only a synthetic manifest template; fresh passwords stay in memory.
            $template = $templates[$Index]
            $sam = 'lab.x' + [guid]::NewGuid().ToString('N').Substring(0, 14)
            $password = New-LabPassword
            $user = New-ADUser -Name $sam -SamAccountName $sam -DisplayName $template.display_name `
                -Path $domain.UsersContainer -Description $script:LabMarker -Enabled $true `
                -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru
            $null = $created.Add($user)
            Set-ADAccountControl -Identity $user -DoesNotRequirePreAuth ([bool]$NoPreauth)
            if ($Spns.Count -gt 0) {
                Set-ADUser -Identity $user -ServicePrincipalNames @{ Add = $Spns } -KerberosEncryptionType RC4
            }
            return @{ User = $user; Password = $password; Sam = $sam }
        }
        function Invoke-ExerciseBind($Account, [bool]$Success) {
            Add-Type -AssemblyName System.DirectoryServices.Protocols
            $identifier = New-Object DirectoryServices.Protocols.LdapDirectoryIdentifier($domain.PDCEmulator, 389)
            $password = if ($Success) { $Account.Password } else { New-LabPassword }
            $credential = New-Object Net.NetworkCredential($Account.Sam, $password, $domain.NetBIOSName)
            $connection = New-Object DirectoryServices.Protocols.LdapConnection($identifier, $credential,
                [DirectoryServices.Protocols.AuthType]::Negotiate)
            try {
                $connection.SessionOptions.Signing = $true
                $connection.SessionOptions.Sealing = $true
                $connection.Bind()
                if (-not $Success) { throw 'exercise_failed_logon_succeeded' }
            } catch [DirectoryServices.Protocols.LdapException] {
                if ($Success -or $_.Exception.ErrorCode -ne 49) { throw 'exercise_bind_failed' }
            } finally { $connection.Dispose(); $password = $null }
        }
        function Request-ExerciseTickets($Account, [string[]]$Spns) {
            Add-Type -AssemblyName System.IdentityModel
            if (-not ('SliLabExerciseLogon' -as [type])) {
                Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class SliLabExerciseLogon {
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool LogonUser(string user, string domain, string password,
        int logonType, int provider, out IntPtr token);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr token);
}
'@
            }
            $token = [IntPtr]::Zero
            $identity = $null
            $impersonation = $null
            try {
                if (-not [SliLabExerciseLogon]::LogonUser($Account.Sam, $domain.NetBIOSName,
                    $Account.Password, 9, 3, [ref]$token)) { throw 'exercise_logon_failed' }
                $identity = New-Object Security.Principal.WindowsIdentity($token)
                $impersonation = $identity.Impersonate()
                foreach ($spn in $Spns) {
                    $ticket = New-Object IdentityModel.Tokens.KerberosRequestorSecurityToken($spn)
                    $null = $ticket.GetRequest()
                }
            } finally {
                if ($impersonation) { $impersonation.Undo(); $impersonation.Dispose() }
                if ($identity) { $identity.Dispose() }
                if ($token -ne [IntPtr]::Zero) { $null = [SliLabExerciseLogon]::CloseHandle($token) }
            }
        }
        switch ($Number) {
            { $_ -in 1, 2, 3 } {
                $count = if ($Number -in 2, 3) { 15 } else { 1 }
                $attempts = if ($Number -in 2, 3) { 1 } else { 12 }
                for ($i = 0; $i -lt $count; $i++) {
                    $account = New-ExerciseUser $i
                    for ($j = 0; $j -lt $attempts; $j++) { Invoke-ExerciseBind $account $false }
                    if ($Number -eq 3 -and $i -eq ($count - 1)) {
                        Unlock-ADAccount -Identity $account.User
                        Invoke-ExerciseBind $account $true
                    }
                }
            }
            4 {
                $requester = New-ExerciseUser 0
                $spns = @()
                for ($i = 1; $i -le 10; $i++) {
                    $spn = 'HTTP/lab-exercise-' + [guid]::NewGuid().ToString('N') + '.' + $domain.DNSRoot
                    $null = New-ExerciseUser $i -Spns @($spn)
                    $spns += $spn
                }
                Request-ExerciseTickets $requester $spns
            }
            5 {
                $account = New-ExerciseUser 0 -NoPreauth
                Request-ExerciseTickets $account @('ldap/' + $domain.PDCEmulator)
            }
            6 {
                $account = New-ExerciseUser 0
                $group = Get-ADGroup ($domain.DomainSID.Value + '-512')
                try { Add-ADGroupMember $group $account.User }
                finally {
                    try { Remove-ADGroupMember $group $account.User -Confirm:$false }
                    catch { $result.restored = $false; throw 'exercise_group_restore_failed' }
                }
            }
            7 {
                # Exercise the detector's System/104 branch. Never clear Security:
                # exported events cannot be restored to the active Security log.
                $log = 'LX' + [guid]::NewGuid().ToString('N').Substring(0, 20)
                if (Get-WinEvent -ListLog $log -ErrorAction SilentlyContinue) {
                    throw 'exercise_log_collision'
                }
                $registered = $false
                try {
                    New-EventLog -LogName $log -Source $log
                    $registered = $true
                    Write-EventLog -LogName $log -Source $log -EventId 1 -EntryType Information -Message 'SLI LAB exercise'
                    $clear = Invoke-LabProcess (Join-Path $env:WINDIR 'System32\wevtutil.exe') @('cl', $log)
                    if ($clear.ExitCode -ne 0) { throw 'exercise_log_clear_failed' }
                } finally {
                    if ($registered -or (Get-WinEvent -ListLog $log -ErrorAction SilentlyContinue)) {
                        try { Remove-EventLog -LogName $log }
                        catch { $result.restored = $false; throw 'exercise_log_restore_failed' }
                    }
                }
            }
            8 {
                $guid = '{0cce9215-69ae-11d9-bed3-505054503030}'
                $get = Invoke-LabProcess (Join-Path $env:WINDIR 'System32\auditpol.exe') @('/get', "/subcategory:$guid", '/r')
                if ($get.ExitCode -ne 0) { throw 'exercise_audit_read_failed' }
                $rows = @($get.Stdout | ConvertFrom-Csv)
                if ($rows.Count -ne 1) { throw 'exercise_audit_read_failed' }
                $setting = [int](@($rows[0].PSObject.Properties)[-1].Value)
                if ($setting -lt 1 -or $setting -gt 3) { throw 'exercise_audit_already_disabled' }
                try { Invoke-LabAudit $guid 'disable' 'disable' }
                finally {
                    try {
                        $success = if ($setting -band 1) { 'enable' } else { 'disable' }
                        $failure = if ($setting -band 2) { 'enable' } else { 'disable' }
                        Invoke-LabAudit $guid $success $failure
                    } catch { $result.restored = $false; throw 'exercise_audit_restore_failed' }
                }
            }
            9 {
                $service = Get-Service -Name SLIAgentNet
                if ($service.Status -ne 'Running') { throw 'exercise_agent_not_running' }
                try { Stop-Service -Name SLIAgentNet }
                finally {
                    try { Start-Service -Name SLIAgentNet }
                    catch { $result.restored = $false; throw 'exercise_agent_restore_failed' }
                }
            }
            10 {
                $task = 'SLI-Lab-Exercise-' + [guid]::NewGuid().ToString('N')
                $registered = $false
                try {
                    $action = New-ScheduledTaskAction -Execute "$env:WINDIR\System32\cmd.exe" -Argument '/c exit 0'
                    $trigger = New-ScheduledTaskTrigger -Once -At ([datetime]::Now.AddDays(1))
                    Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger -User SYSTEM | Out-Null
                    $registered = $true
                } finally {
                    if ($registered) {
                        try { Unregister-ScheduledTask -TaskName $task -Confirm:$false }
                        catch { $result.restored = $false; throw 'exercise_task_restore_failed' }
                    }
                }
                $result.match_values += $task
            }
            default { throw 'exercise_attack_invalid' }
        }
        $result.executed = $true
        $result.reason = ''
    } catch {
        # Do not include exception messages: directory/LDAP errors can contain private data.
        $result.reason = 'attack_failed'
    } finally {
        if ($created.Count -gt 0) { $result.match_values = @() }
        foreach ($user in $created) {
            $result.match_values += @($user.SamAccountName, $user.SID.Value, $user.DistinguishedName)
            try {
                $owned = Get-ADUser -Identity $user.ObjectGUID -Properties Description
                Assert-LabOwned $owned
                Remove-ADUser -Identity $owned -Confirm:$false
            } catch { $result.restored = $false; $result.reason = 'cleanup_failed' }
        }
        if ($locked) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
    return $result
}
