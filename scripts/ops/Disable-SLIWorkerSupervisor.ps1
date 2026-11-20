param(
    [string]$TaskName = "SLI Worker Supervisor"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$EvidencePath = Join-Path $ProjectRoot "artifacts\worker_supervisor_disabled.json"

$Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
if ($Task.State -eq "Running") {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction Stop
}
Disable-ScheduledTask -TaskName $TaskName -ErrorAction Stop | Out-Null

$Readback = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
$Result = [ordered]@{
    status = if (-not [bool]$Readback.Settings.Enabled -and $Readback.State -ne "Running") {
        "ok"
    } else {
        "failed"
    }
    task_name = $TaskName
    enabled = [bool]$Readback.Settings.Enabled
    state = [string]$Readback.State
    generated_at = (Get-Date).ToString("o")
    collection_started = $false
}

$Result | ConvertTo-Json -Depth 4 |
    Set-Content -LiteralPath $EvidencePath -Encoding UTF8

if ($Result.status -ne "ok") {
    throw "Supervisor task was not confirmed disabled and stopped."
}

Write-Host "SLI Worker Supervisor отключён. Сбор не запущен." -ForegroundColor Green
Write-Host "Evidence: $EvidencePath"
