<#
Real SMB operations using owned demo users' existing protected credentials.
Expected rows describe attempts; event IDs are conditional on administrator-enabled audit.
Daily markers + mutex bound replay; no auditpol writes, SACL writes or clock changes.
Task: SLI Lab Files, every five minutes; daily workday suite and a real 00:00-06:00 read.
#>
#Requires -Version 5.1
[CmdletBinding()]
param([switch]$InstallTask, [switch]$RunDaily, [switch]$RunNight)
. "$PSScriptRoot\lab-05-file-server.ps1"
$script:LabFileSimulationPath = $PSCommandPath

function Initialize-LabFileClient {
    if ('SliLabFileClient' -as [type]) { return }
    Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Security.AccessControl;
public static class SliLabFileClient {
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern bool LogonUser(string user, string domain, string password, int type, int provider, out IntPtr token);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    public static string Run(string user, string password, string path, string operation, string other, string sid) {
        IntPtr token;
        // NEW_CREDENTIALS creates a separate outbound SMB logon session per action.
        if (!LogonUser(user, "DEMO", password, 9, 3, out token)) return "logon_error";
        try {
            using (WindowsIdentity identity = new WindowsIdentity(token))
            using (WindowsImpersonationContext context = identity.Impersonate()) {
                try {
                    switch(operation) {
                        case "read": if (File.ReadAllText(path).Length == 0) return "empty_file"; break;
                        case "create": using (var s = new FileStream(path, FileMode.CreateNew, FileAccess.Write))
                            using (var w = new StreamWriter(s)) { w.WriteLine("SLI-LAB-SYNTHETIC: fictional request 42; draft"); } break;
                        case "modify": File.AppendAllText(path, "SLI-LAB-SYNTHETIC: approved training revision\r\n"); break;
                        case "delete": if (!File.Exists(path)) return "missing_file"; File.Delete(path); break;
                        case "rename": File.Move(path, other); break;
                        case "permissions": var acl = File.GetAccessControl(path, AccessControlSections.Access);
                            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid), FileSystemRights.Read, AccessControlType.Allow));
                            File.SetAccessControl(path, acl); break;
                        default: return "unknown_operation";
                    }
                    return "success";
                } catch (Exception e) {
                    int code = Marshal.GetHRForException(e) & 65535;
                    return code == 5 ? "access_denied" : "io_error_" + code.ToString();
                }
            }
        } finally { CloseHandle(token); }
    }
}
"@
}

function Invoke-LabFileAction([string]$Scenario, [string]$Sam, [string]$Share,
    [string]$Relative, [string]$Operation, [string]$Other = '', [bool]$DenyExpected = $false) {
    if ($Sam -cnotmatch '^lab\.u[0-9]{3}$' -or $Share -notin @((Get-LabFileShares).Name) -or
        $Relative -cnotmatch '^[A-Za-z0-9_-]+\.(txt|csv)$' -and $Relative -cne 'Сводка-01.csv' -or
        ($Other -and $Other -cnotmatch '^[A-Za-z0-9_-]+\.(txt|csv)$')) { throw 'lab_file_action_invalid' }
    $user = Get-ADUser $Sam -Properties Description
    Assert-LabOwned $user
    $path = '\\LAB-DC01.demo.example\' + $Share + '\' + $Relative
    $otherPath = if ($Other) { '\\LAB-DC01.demo.example\' + $Share + '\' + $Other } else { '' }
    $start = [datetime]::UtcNow
    $ok = $false; $result = 'not_attempted'; $password = $null
    try {
        $password = [IO.File]::ReadAllText((Assert-LabPath "$script:LabRoot\credentials\$Sam.secret"))
        $result = [SliLabFileClient]::Run($Sam, $password, $path, $Operation, $otherPath, (Get-ADUser 'lab.u009').SID.Value)
        $ok = if ($DenyExpected) { $result -ceq 'access_denied' } else { $result -ceq 'success' }
    } finally {
        $password = $null
        $ids = if ($DenyExpected) { @(4656,5145) } elseif ($Operation -eq 'permissions') { @(4670,5145) }
            elseif ($Operation -eq 'delete') { @(4663,4660,5145) } else { @(4663,5145) }
        $row = New-LabExpected $Scenario $Sam $start $ids $ok '' '' $user.SID.Value
        $row.actor = 'DEMO\' + $Sam
        $row['file_path'] = $path; $row['share'] = $Share; $row['operation'] = $Operation
        $row['destination_path'] = $(if ($Other) { $otherPath } else { $null })
        $row['outcome'] = $result; $row['audit_required'] = $true
        $row['local_time'] = [datetime]::Now.ToString('o')
        Write-LabExpected $row
    }
    return $ok
}

function Invoke-LabFileDaily([string]$Scenario, [scriptblock]$Operation) {
    $marker = Assert-LabPath "$script:LabRoot\file-daily\$([datetime]::Now.ToString('yyyy-MM-dd'))-$Scenario.done"
    if (Test-Path -LiteralPath $marker) { return $true }
    $ok = & $Operation
    if ($ok) { 'done' | Set-Content -LiteralPath $marker -Encoding UTF8 }
    return [bool]$ok
}

function Invoke-LabFileSimulation {
    Assert-LabAdministrator
    $null = Assert-LabDomain
    if ($env:COMPUTERNAME -cne 'LAB-DC01') { throw 'lab_file_host_rejected' }
    Assert-LabFileRoot
    if (-not (Test-Path -LiteralPath "$script:FsRoot\.sli-lab-owned")) { throw 'lab_file_fixture_missing' }
    if ($InstallTask) {
        $existing = Get-ScheduledTask -TaskName 'SLI Lab Files' -ErrorAction SilentlyContinue
        if ($existing -and $existing.Description -cne $script:LabMarker) { throw 'lab_file_task_collision' }
        $action = New-ScheduledTaskAction -Execute "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" `
            -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $script:LabFileSimulationPath + '"')
        $trigger = New-ScheduledTaskTrigger -Once -At ([datetime]::Now.AddMinutes(1)) -RepetitionInterval (New-TimeSpan -Minutes 5)
        $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 4)
        Register-ScheduledTask -TaskName 'SLI Lab Files' -Description $script:LabMarker -Action $action -Trigger $trigger `
            -Settings $settings -User SYSTEM -RunLevel Highest -Force | Out-Null
        Write-Output 'lab_file_task_ready'; return
    }
    $mutex = New-Object Threading.Mutex($false, 'Global\SLI-Lab-Files')
    $locked = $false
    try {
        try { $locked = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $locked = $true }
        if (-not $locked) { return }
        Initialize-LabDirectory "$script:LabRoot\file-daily"
        Initialize-LabFileClient
        $now = [datetime]::Now
        $workday = $now.DayOfWeek -notin @([DayOfWeek]::Saturday,[DayOfWeek]::Sunday) -and $now.Hour -ge 9 -and $now.Hour -lt 18
        $night = $now.Hour -lt 6
        if ($RunNight -and $workday) { throw 'lab_file_night_requires_actual_off_hours' }
        $ok = $true
        if ($night -or ($RunNight -and -not $workday)) {
            if (-not (Invoke-LabFileDaily 'file_off_hours' { Invoke-LabFileAction 'file_off_hours' 'lab.u003' 'LAB-Finance' 'Сводка-01.csv' 'read' })) { $ok = $false }
        }
        if ($RunDaily -or $workday) {
            foreach ($scenario in @('file_read','file_modify','file_delete','file_rename','file_permissions','file_mass_read','file_mass_delete','file_denied')) {
                $operation = {
                    $id = [guid]::NewGuid().ToString('N')
                    $file = 'sim-' + $id + '.txt'
                    switch ($scenario) {
                        'file_read' { return (Invoke-LabFileAction $scenario 'lab.u003' 'LAB-Finance' 'Сводка-01.csv' 'read') }
                        'file_denied' { return (Invoke-LabFileAction $scenario 'lab.u006' 'LAB-HR' 'Сводка-01.csv' 'read' '' $true) }
                        'file_mass_read' {
                            $passed = $true
                            for ($i=1; $i -le 20; $i++) {
                                # Twenty distinct seed files; each actual read gets its own expected row.
                                if (-not (Invoke-LabFileAction $scenario 'lab.u011' 'LAB-Exchange' ('batch-{0:00}.txt' -f $i) 'read')) { $passed = $false }
                            }
                            return $passed
                        }
                        'file_mass_delete' {
                            $passed = $true
                            for ($i=1; $i -le 20; $i++) {
                                $entry = 'sim-' + $id + '-{0:00}.txt' -f $i
                                if (-not (Invoke-LabFileAction 'file_fixture_create' 'lab.u011' 'LAB-Exchange' $entry 'create')) { $passed = $false; continue }
                                if (-not (Invoke-LabFileAction $scenario 'lab.u011' 'LAB-Exchange' $entry 'delete')) { $passed = $false }
                            }
                            return $passed
                        }
                        default {
                            $share = if ($scenario -eq 'file_permissions') { 'LAB-Finance' } else { 'LAB-Exchange' }
                            if (-not (Invoke-LabFileAction 'file_fixture_create' 'lab.u003' $share $file 'create')) { return $false }
                            $verb = $scenario.Substring(5)
                            $destination = if ($verb -eq 'rename') { 'sim-' + $id + '-renamed.txt' } else { '' }
                            return (Invoke-LabFileAction $scenario 'lab.u003' $share $file $verb $destination)
                        }
                    }
                }
                if (-not (Invoke-LabFileDaily $scenario $operation)) { $ok = $false }
            }
        }
        if (-not $ok) { throw 'lab_file_actions_failed' }
        Write-Output 'lab_file_simulation_completed'
    } finally { if ($locked) { $mutex.ReleaseMutex() }; $mutex.Dispose() }
}

if ($MyInvocation.InvocationName -ne '.') {
    try { Invoke-LabFileSimulation } catch { Write-Output 'lab_file_simulation_failed'; exit 1 }
}
