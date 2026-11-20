#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Apply,
    [switch]$Start,
    [switch]$ValidateOnly,
    [string]$ProjectRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$TaskName = 'SLI Web Server'

function Resolve-SLIProjectRoot {
    param([string]$RequestedRoot)

    $candidate = if ([string]::IsNullOrWhiteSpace($RequestedRoot)) {
        Join-Path -Path $PSScriptRoot -ChildPath '..\..'
    } else {
        $RequestedRoot
    }
    return [System.IO.Path]::GetFullPath($candidate)
}

function Write-SLIAtomicJson {
    param(
        [Parameter(Mandatory = $true)] [object]$Value,
        [Parameter(Mandatory = $true)] [string]$Path
    )

    $directory = Split-Path -Parent $Path
    [System.IO.Directory]::CreateDirectory($directory) | Out-Null
    $temporaryPath = Join-Path -Path $directory -ChildPath ('.{0}.{1}.tmp' -f (Split-Path -Leaf $Path), [Guid]::NewGuid().ToString('N'))
    try {
        [System.IO.File]::WriteAllText(
            $temporaryPath,
            ($Value | ConvertTo-Json -Depth 8),
            (New-Object System.Text.UTF8Encoding($false))
        )
        Move-Item -LiteralPath $temporaryPath -Destination $Path -Force
    } finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        }
    }
}

$ResolvedProjectRoot = Resolve-SLIProjectRoot -RequestedRoot $ProjectRoot
if (-not [System.IO.Path]::IsPathRooted($ResolvedProjectRoot)) {
    throw 'Project root must be absolute.'
}
$BootstrapPath = [System.IO.Path]::GetFullPath((Join-Path -Path $ResolvedProjectRoot -ChildPath 'scripts\ops\Start-SLIWebServer-v1.ps1'))
$EvidencePath = [System.IO.Path]::GetFullPath((Join-Path -Path $ResolvedProjectRoot -ChildPath 'data\maintenance\web-server-autostart.json'))
$PowerShellPath = [System.IO.Path]::GetFullPath((Join-Path -Path $env:SystemRoot -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe'))
if (-not (Test-Path -LiteralPath $BootstrapPath -PathType Leaf)) {
    throw "Web-server bootstrap was not found: $BootstrapPath"
}
if (-not (Test-Path -LiteralPath $PowerShellPath -PathType Leaf)) {
    throw "Windows PowerShell was not found: $PowerShellPath"
}
if ($Start -and -not $Apply) {
    throw '-Start requires -Apply.'
}

# This is a real PowerShell 5.1 and DPAPI preflight.  It performs no web start.
& $PowerShellPath -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $BootstrapPath -ValidateOnly -ProjectRoot $ResolvedProjectRoot
if ($LASTEXITCODE -ne 0) {
    throw "Web-server bootstrap validation failed with exit code $LASTEXITCODE."
}

$ConfiguredPrincipal = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$validation = [ordered]@{
    status = 'validated'
    script_version = 'v1'
    task_name = $TaskName
    task_principal = $ConfiguredPrincipal
    bootstrap_path = $BootstrapPath
    run_only_when_user_logged_on = $true
    protected_environment = 'current-user-dpapi'
    credential_values_exposed = $false
    apply_required = $true
}

if ($ValidateOnly) {
    $validation | ConvertTo-Json -Depth 4 -Compress
    exit 0
}
if (-not $Apply) {
    $validation.status = 'planned'
    $validation | ConvertTo-Json -Depth 4 -Compress
    exit 0
}

$TaskAction = New-ScheduledTaskAction -Execute $PowerShellPath -Argument (
    '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}"' -f $BootstrapPath
) -WorkingDirectory $ResolvedProjectRoot
$LogonTrigger = New-ScheduledTaskTrigger -AtLogOn -User $ConfiguredPrincipal
$RepetitionInterval = New-TimeSpan -Minutes 5
$RepetitionTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval $RepetitionInterval -RepetitionDuration (New-TimeSpan -Days 3650)
$TaskSettings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Minutes 4) -StartWhenAvailable
$TaskPrincipal = New-ScheduledTaskPrincipal -UserId $ConfiguredPrincipal -LogonType Interactive -RunLevel Limited

if (-not $PSCmdlet.ShouldProcess($TaskName, 'Register the per-user SLI web-server task')) {
    $validation.status = 'what_if'
    $validation | ConvertTo-Json -Depth 4 -Compress
    exit 0
}

Register-ScheduledTask -TaskName $TaskName -Action $TaskAction -Trigger @($LogonTrigger, $RepetitionTrigger) -Settings $TaskSettings -Principal $TaskPrincipal -Force | Out-Null
$registeredTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
$taskInfo = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction Stop
$registeredAction = @($registeredTask.Actions)[0]
$triggerKinds = @($registeredTask.Triggers | ForEach-Object { $_.CimClass.CimClassName })
$configurationVerified = (
    $registeredAction.WorkingDirectory -eq $ResolvedProjectRoot -and
    $registeredAction.Arguments.Contains($BootstrapPath) -and
    [string]$registeredTask.Principal.RunLevel -eq 'Limited' -and
    [string]$registeredTask.Settings.MultipleInstances -eq 'IgnoreNew' -and
    $triggerKinds -contains 'MSFT_TaskLogonTrigger' -and
    $triggerKinds -contains 'MSFT_TaskTimeTrigger'
)
if (-not $configurationVerified) {
    throw 'Scheduled task readback did not match the requested web-server contract.'
}

if ($Start) {
    Start-ScheduledTask -TaskName $TaskName
}

$result = [ordered]@{
    status = if ($Start) { 'start_requested' } else { 'registered' }
    script_version = 'v1'
    task_name = $registeredTask.TaskName
    task_state = [string]$registeredTask.State
    last_task_result = $taskInfo.LastTaskResult
    next_run_time = $taskInfo.NextRunTime
    task_principal = $ConfiguredPrincipal
    trigger_kinds = $triggerKinds
    working_directory_verified = $true
    action_contains_credentials = $false
    multiple_instances = [string]$registeredTask.Settings.MultipleInstances
    restart_count = $registeredTask.Settings.RestartCount
    start_requested = [bool]$Start
    credential_values_exposed = $false
}
Write-SLIAtomicJson -Value $result -Path $EvidencePath
$result | ConvertTo-Json -Depth 4 -Compress
