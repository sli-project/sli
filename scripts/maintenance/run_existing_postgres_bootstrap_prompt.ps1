[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$DataDir,
    [string]$BinDir = 'C:\Program Files\PostgreSQL\18\bin',
    [string]$Database = 'sli_local',
    [int]$Port = 55433
)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$python = Join-Path $projectRoot '.venv\Scripts\python.exe'
$bootstrap = Join-Path $projectRoot 'scripts\maintenance\existing_postgres_bootstrap.py'
$statusFile = Join-Path $projectRoot 'artifacts\operations\existing-postgres-bootstrap-status.json'
$utf8 = New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding = $utf8
$OutputEncoding = $utf8
$Host.UI.RawUI.WindowTitle = 'SLI - PostgreSQL and platform-owner'

function Convert-SecureStringToPlainText {
    param([Parameter(Mandatory = $true)][Security.SecureString]$Value)
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

Write-Host 'Enter the local PostgreSQL administrator password once.'
$adminSecure = Read-Host 'PostgreSQL postgres' -AsSecureString

do {
    $ownerSecure = Read-Host 'New platform-owner password (at least 12 characters)' -AsSecureString
    $ownerConfirmSecure = Read-Host 'Repeat the new platform-owner password' -AsSecureString
    $ownerCheck = Convert-SecureStringToPlainText $ownerSecure
    $ownerConfirmCheck = Convert-SecureStringToPlainText $ownerConfirmSecure
    $ownerMatches = [string]::Equals($ownerCheck, $ownerConfirmCheck, [StringComparison]::Ordinal)
    $ownerCheck = $null
    $ownerConfirmCheck = $null
    if (-not $ownerMatches) {
        Write-Host 'The platform-owner passwords did not match. Repeat only the new password.' -ForegroundColor Yellow
    }
} while (-not $ownerMatches)

$adminPlain = Convert-SecureStringToPlainText $adminSecure
$ownerPlain = Convert-SecureStringToPlainText $ownerSecure
try {
    $arguments = @(
        $bootstrap,
        '--app-root', $projectRoot,
        '--bin-dir', $BinDir,
        '--data-dir', $DataDir,
        '--database', $Database,
        '--host', '127.0.0.1',
        '--port', [string]$Port,
        '--admin-password-stdin',
        '--save-admin-password',
        '--platform-owner-password-stdin',
        '--save-platform-owner-password',
        '--apply-after-plan',
        '--status-file', $statusFile
    )
    $env:PYTHONUTF8 = '1'
    $adminPlain, $ownerPlain | & $python @arguments
    $bootstrapExitCode = $LASTEXITCODE
}
finally {
    $adminPlain = $null
    $ownerPlain = $null
    Remove-Item Env:PYTHONUTF8 -ErrorAction SilentlyContinue
}

if ($bootstrapExitCode -eq 0) {
    Write-Host 'The SLI database was created and verified. You can close this window.' -ForegroundColor Green
}
else {
    $adminStore = Join-Path $projectRoot 'data\runtime\local-postgres-admin\postgres-admin.dpapi.json'
    $ownerStore = Join-Path $projectRoot 'data\runtime\local-postgres-admin\platform-owner.dpapi.json'
    if ((Test-Path -LiteralPath $adminStore) -and (Test-Path -LiteralPath $ownerStore)) {
        Write-Host 'Bootstrap stopped safely. No password re-entry is needed; continuation uses DPAPI.' -ForegroundColor Yellow
    }
    else {
        Write-Host 'Bootstrap stopped before DPAPI persistence. The corrected launcher will request one retry.' -ForegroundColor Yellow
    }
}
Read-Host 'Press Enter to close this window'
exit $bootstrapExitCode
