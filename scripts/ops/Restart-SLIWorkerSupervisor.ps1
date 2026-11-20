[CmdletBinding()]
param(
    [ValidateSet("Plan", "RepairLeastPrivilege", "Restart")]
    [string]$Action = "Plan",
    [string]$Confirmation = ""
)

$ErrorActionPreference = "Stop"
$TaskName = "SLI Worker Supervisor"
$ExpectedPrincipal = (& whoami).Trim()
$RequiredConfirmation = "RESTART-SLI-WORKER-SUPERVISOR-FOR-PLUGIN-AUTOSTART"
$RepairConfirmation = "REPAIR-SLI-WORKER-SUPERVISOR-LEAST-PRIVILEGE"
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$ExpectedPython = (Resolve-Path (Join-Path $ProjectRoot ".venv\Scripts\python.exe")).Path
$ExpectedSupervisor = (Resolve-Path (Join-Path $ProjectRoot "scripts\maintenance\worker_supervisor.py")).Path
$ExpectedBootstrap = (Resolve-Path (Join-Path $ProjectRoot "scripts\ops\Start-SLIWorkerSupervisor.ps1")).Path
$ExpectedPowerShell = (Get-Command powershell.exe -ErrorAction Stop).Source
$EvidenceStamp = [DateTimeOffset]::UtcNow.ToString("yyyyMMddTHHmmssfffZ")
$EvidencePath = Join-Path $ProjectRoot "data\maintenance\worker-supervisor-plugin-reload-$EvidenceStamp.json"
$RepairEvidencePath = Join-Path $ProjectRoot "data\maintenance\worker-supervisor-task-least-privilege-$EvidenceStamp.json"

function Get-ExactSupervisorProcesses {
    $escaped = [Regex]::Escape($ExpectedSupervisor)
    @(Get-CimInstance Win32_Process -Filter "Name LIKE 'python%.exe'" | Where-Object {
        $_.CommandLine -and $_.CommandLine -match $escaped
    } | Select-Object ProcessId, ParentProcessId, Name, CommandLine)
}

function Get-TaskSnapshot {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
    $info = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction Stop
    $taskAction = $task.Actions[0]
    [ordered]@{
        task_state = [string]$task.State
        task_enabled = ([string]$task.State -ne "Disabled")
        principal = [string]$task.Principal.UserId
        logon_type = [string]$task.Principal.LogonType
        run_level = [string]$task.Principal.RunLevel
        execute = [string]$taskAction.Execute
        arguments = [string]$taskAction.Arguments
        working_directory = [string]$taskAction.WorkingDirectory
        last_task_result = [uint32]([int64]$info.LastTaskResult -band [int64][uint32]::MaxValue)
    }
}

function Test-ExactTask([System.Collections.IDictionary]$Snapshot) {
    $expectedShort = ($ExpectedPrincipal -split '\\')[-1]
    $principalOk = $Snapshot.principal.Equals(
        $ExpectedPrincipal, [System.StringComparison]::OrdinalIgnoreCase
    ) -or $Snapshot.principal.Equals(
        $expectedShort, [System.StringComparison]::OrdinalIgnoreCase
    )
    $executeOk = $Snapshot.execute.Equals(
        $ExpectedPowerShell, [System.StringComparison]::OrdinalIgnoreCase
    )
    $workingOk = $Snapshot.working_directory.Equals(
        $ProjectRoot, [System.StringComparison]::OrdinalIgnoreCase
    )
    $argumentOk = $Snapshot.arguments -like "*$ExpectedBootstrap*" -and
        $Snapshot.arguments -like "*-IntervalSeconds 120*"
    return $Snapshot.task_enabled -and $principalOk -and $executeOk -and
        $workingOk -and $argumentOk -and $Snapshot.logon_type -eq "Interactive"
}

function Test-OneSupervisorTree([array]$Processes) {
    if ($Processes.Count -lt 1 -or $Processes.Count -gt 2) { return $false }
    $ids = @($Processes | ForEach-Object { [int]$_.ProcessId })
    $roots = @($Processes | Where-Object { $ids -notcontains [int]$_.ParentProcessId })
    if ($roots.Count -ne 1) { return $false }
    foreach ($process in $Processes) {
        if ([int]$process.ProcessId -eq [int]$roots[0].ProcessId) { continue }
        if ($ids -notcontains [int]$process.ParentProcessId) { return $false }
    }
    return $true
}

$CurrentPrincipal = $ExpectedPrincipal
$Before = Get-TaskSnapshot
$BeforeProcesses = @(Get-ExactSupervisorProcesses)
$Result = [ordered]@{
    status = "ready"
    action = $Action.ToLowerInvariant()
    current_principal = $CurrentPrincipal
    required_principal = $ExpectedPrincipal
    task_name = $TaskName
    exact_task = [bool](Test-ExactTask $Before)
    least_privilege = ($Before.run_level -eq "Limited")
    one_supervisor_tree = [bool](Test-OneSupervisorTree $BeforeProcesses)
    before = $Before
    before_supervisor_pids = @($BeforeProcesses | ForEach-Object { [int]$_.ProcessId })
    required_confirmation = $RequiredConfirmation
    repair_confirmation = $RepairConfirmation
    surveyed_source_contacted = $false
    # No child inventory is measured by this script. A normal bootstrap owns
    # a kill-on-close Job Object: stopping its task can terminate the workers.
    worker_children_stopped = $null
    worker_children_observation = "not_measured"
    worker_children_restart_expectation = "bootstrap_job_kill_on_close"
    worker_children_preservation_guaranteed = $false
    plugin_state_changed = $false
}

if ($Action -eq "Plan") {
    $Result | ConvertTo-Json -Depth 7
    exit 0
}
if (-not $CurrentPrincipal.Equals(
    $ExpectedPrincipal, [System.StringComparison]::OrdinalIgnoreCase
)) {
    throw "wrong_windows_account"
}
if (-not $Result.exact_task) {
    throw "scheduled_task_identity_or_action_mismatch"
}
if ($Action -eq "RepairLeastPrivilege") {
    if ($Confirmation -ne $RepairConfirmation) {
        throw "exact_least_privilege_repair_confirmation_required"
    }
    $principal = New-ScheduledTaskPrincipal `
        -UserId $ExpectedPrincipal `
        -LogonType Interactive `
        -RunLevel Limited
    Set-ScheduledTask -TaskName $TaskName -Principal $principal | Out-Null
    $AfterRepair = Get-TaskSnapshot
    if (-not (Test-ExactTask $AfterRepair) -or $AfterRepair.run_level -ne "Limited") {
        throw "least_privilege_repair_postcondition_failed"
    }
    $Result.status = "accepted"
    $Result.after = $AfterRepair
    $Result.repaired_at_utc = [DateTimeOffset]::UtcNow.ToString("o")
    $directory = Split-Path -Parent $RepairEvidencePath
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
    $temporary = "$RepairEvidencePath.tmp"
    $Result | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $RepairEvidencePath
    $Result | ConvertTo-Json -Depth 7
    exit 0
}
if (-not $Result.least_privilege) {
    throw "scheduled_task_must_be_limited_before_restart"
}
if (-not $Result.one_supervisor_tree) {
    throw "supervisor_process_inventory_is_not_one_tree"
}
if ($Confirmation -ne $RequiredConfirmation) {
    throw "exact_restart_confirmation_required"
}
if ($Before.task_state -eq "Running") {
    Stop-ScheduledTask -TaskName $TaskName
}
$BeforeProcesses | Sort-Object ProcessId -Descending | ForEach-Object {
    Stop-Process -Id ([int]$_.ProcessId) -Force -ErrorAction SilentlyContinue
}
$deadline = [DateTimeOffset]::UtcNow.AddSeconds(30)
do {
    Start-Sleep -Milliseconds 500
    $remaining = @(Get-ExactSupervisorProcesses)
} while ($remaining.Count -gt 0 -and [DateTimeOffset]::UtcNow -lt $deadline)
if ($remaining.Count -gt 0) {
    throw "exact_supervisor_did_not_stop"
}

Start-ScheduledTask -TaskName $TaskName
$deadline = [DateTimeOffset]::UtcNow.AddSeconds(45)
do {
    Start-Sleep -Seconds 1
    $afterProcesses = @(Get-ExactSupervisorProcesses)
    $After = Get-TaskSnapshot
} while ((-not (Test-OneSupervisorTree $afterProcesses) -or $After.task_state -ne "Running") -and
    [DateTimeOffset]::UtcNow -lt $deadline)
if (-not (Test-OneSupervisorTree $afterProcesses) -or $After.task_state -ne "Running") {
    throw "exact_supervisor_restart_postcondition_failed"
}

$Result.status = "accepted"
$Result.after = $After
$Result.after_supervisor_pids = @($afterProcesses | ForEach-Object { [int]$_.ProcessId })
$Result.restarted_at_utc = [DateTimeOffset]::UtcNow.ToString("o")
$directory = Split-Path -Parent $EvidencePath
New-Item -ItemType Directory -Force -Path $directory | Out-Null
$temporary = "$EvidencePath.tmp"
$Result | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $temporary -Encoding UTF8
Move-Item -LiteralPath $temporary -Destination $EvidencePath
$Result | ConvertTo-Json -Depth 7
