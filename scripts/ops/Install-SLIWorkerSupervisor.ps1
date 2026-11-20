[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$Start,
    [switch]$RepairTaskOnly
)

$ErrorActionPreference = "Stop"
$TaskName = "SLI Worker Supervisor"
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$Supervisor = Join-Path $ProjectRoot "scripts\maintenance\worker_supervisor.py"
$Bootstrap = Join-Path $ProjectRoot "scripts\ops\Start-SLIWorkerSupervisor.ps1"
$PowerShell = (Get-Command powershell.exe -ErrorAction Stop).Source
$Evidence = Join-Path $ProjectRoot "data\maintenance\worker-supervisor-install.json"

function Write-Evidence {
    param([hashtable]$Payload)
    $Payload.generated_at = [DateTimeOffset]::UtcNow.ToString("o")
    $Payload.task_name = $TaskName
    $Payload.principal = $ConfiguredPrincipal
    $Payload.project_root = $ProjectRoot
    $directory = Split-Path -Parent $Evidence
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
    $temporary = "$Evidence.tmp"
    $Payload | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $Evidence -Force
}

$CurrentPrincipal = (& whoami).Trim()
$Identity = ((& whoami /user /fo csv /nh) | ConvertFrom-Csv -Header Principal, Sid)
$ConfiguredPrincipal = [string]$Identity.Principal
$ConfiguredSid = [string]$Identity.Sid
$ConfiguredShortPrincipal = ($ConfiguredPrincipal -split '\\')[-1]
$WindowsPrincipal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
$Elevated = $WindowsPrincipal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

$Preflight = @{
    status = "planned"
    apply_requested = [bool]$Apply
    start_requested = [bool]$Start
    repair_task_only = [bool]$RepairTaskOnly
    current_principal = $CurrentPrincipal
    configured_principal = $ConfiguredPrincipal
    configured_sid = $ConfiguredSid
    elevated = $Elevated
    python_exists = Test-Path -LiteralPath $Python
    supervisor_exists = Test-Path -LiteralPath $Supervisor
    bootstrap_exists = Test-Path -LiteralPath $Bootstrap
    credential_values_exposed = $false
}

if (-not $Apply) {
    Write-Evidence $Preflight
    $Preflight | ConvertTo-Json -Depth 5
    exit 0
}
if ([string]::IsNullOrWhiteSpace($ConfiguredPrincipal) -or [string]::IsNullOrWhiteSpace($ConfiguredSid)) {
    throw "Current Windows principal and SID are required for supervisor installation."
}
if (-not $Elevated) {
    throw "Supervisor installation requires an elevated PowerShell token."
}
if (-not (Test-Path -LiteralPath $Supervisor) -or
    -not (Test-Path -LiteralPath $Bootstrap)) {
    throw "Supervisor or bootstrap script is missing."
}
if (-not $RepairTaskOnly) {
    if (-not (Test-Path -LiteralPath $Python)) {
        throw "Project Python is missing."
    }
    if ([string]::IsNullOrWhiteSpace($env:ADLOG_PG_DSN)) {
        throw "ADLOG_PG_DSN is not present in the current process environment."
    }
    $env:ADLOG_COLLECTION_PRINCIPAL = $ConfiguredPrincipal
    $env:ADLOG_COLLECTION_PRINCIPAL_SID = $ConfiguredSid
    & $Python $Supervisor --provision-environment
    if ($LASTEXITCODE -ne 0) {
        throw "DPAPI environment provisioning failed with exit code $LASTEXITCODE"
    }
}

$Action = New-ScheduledTaskAction `
    -Execute $PowerShell `
    -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$Bootstrap`" -IntervalSeconds 120" `
    -WorkingDirectory $ProjectRoot
$LogonTrigger = New-ScheduledTaskTrigger -AtLogOn -User $ConfiguredPrincipal
$PeriodicTrigger = New-ScheduledTaskTrigger `
    -Once `
    -At ((Get-Date).AddMinutes(1)) `
    -RepetitionInterval (New-TimeSpan -Minutes 5) `
    -RepetitionDuration (New-TimeSpan -Days 3650)
$Triggers = @($LogonTrigger, $PeriodicTrigger)
$Principal = New-ScheduledTaskPrincipal `
    -UserId $ConfiguredPrincipal `
    -LogonType Interactive `
    -RunLevel Limited
$Settings = New-ScheduledTaskSettingsSet `
    -MultipleInstances IgnoreNew `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -StartWhenAvailable

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $Action `
    -Trigger $Triggers `
    -Principal $Principal `
    -Settings $Settings `
    -Description "SLI: one least-privilege interactive supervisor for external runtime workers." `
    -Force | Out-Null

if ($Start) {
    Start-ScheduledTask -TaskName $TaskName
}

$Readback = Get-ScheduledTask -TaskName $TaskName
$Result = @{
    status = "ok"
    apply_requested = $true
    start_requested = [bool]$Start
    repair_task_only = [bool]$RepairTaskOnly
    environment_provisioned = (-not [bool]$RepairTaskOnly)
    current_principal = $CurrentPrincipal
    configured_principal = $ConfiguredPrincipal
    configured_sid = $ConfiguredSid
    principal_matches = (
        $Readback.Principal.UserId.Equals(
            $ConfiguredPrincipal,
            [System.StringComparison]::OrdinalIgnoreCase
        ) -or $Readback.Principal.UserId.Equals(
            $ConfiguredShortPrincipal,
            [System.StringComparison]::OrdinalIgnoreCase
        )
    )
    elevated = $Elevated
    task_state = [string]$Readback.State
    run_level = [string]$Readback.Principal.RunLevel
    logon_type = [string]$Readback.Principal.LogonType
    action_execute = [string]$Readback.Actions[0].Execute
    action_arguments = [string]$Readback.Actions[0].Arguments
    credential_values_exposed = $false
}
Write-Evidence $Result
$Result | ConvertTo-Json -Depth 5
