#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location -LiteralPath $ProjectRoot

# Elevation check
$WindowsPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $WindowsPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Запрос прав администратора для удаления службы Windows..." -ForegroundColor Yellow
    $argumentList = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    $elevatedProcess = Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argumentList -Wait -PassThru
    exit $elevatedProcess.ExitCode
}

$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$ServiceScript = Join-Path $ProjectRoot "server\service\sli_web_service.py"

$service = Get-Service -Name "SLIWebServer" -ErrorAction SilentlyContinue
if (-not $service) {
    Write-Host "Служба 'SLIWebServer' не зарегистрирована в системе." -ForegroundColor Yellow
    exit 0
}

if ($service.Status -eq 'Running') {
    Write-Host "Остановка службы 'SLIWebServer'..." -ForegroundColor Cyan
    Stop-Service -Name "SLIWebServer" -Force
    Start-Sleep -Seconds 2
}

Write-Host "Удаление службы 'SLIWebServer'..." -ForegroundColor Cyan
& $Python $ServiceScript remove
if ($LASTEXITCODE -eq 0) {
    Write-Host "Служба 'SLIWebServer' успешно удалена из системы." -ForegroundColor Green
} else {
    Write-Warning "Удаление через python script вернуло код $LASTEXITCODE, попытка через sc.exe delete..."
    sc.exe delete SLIWebServer
}
