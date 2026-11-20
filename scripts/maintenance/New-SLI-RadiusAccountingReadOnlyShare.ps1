#requires -Version 5.0
#requires -RunAsAdministrator

[CmdletBinding()]
param(
    [ValidateSet('Plan', 'Apply')]
    [string]$Action = 'Plan',

    [string]$Confirmation = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ExpectedComputerName = 'radius01'
$AllowedOperatorAccounts = @(
    'EXAMPLE\example-admin',
    'EXAMPLE\operator'
)
$ReadAccount = 'EXAMPLE\operator'
$ExpectedPath = [System.IO.Path]::GetFullPath(
    (Join-Path $env:SystemRoot 'System32\LogFiles')
)
$ShareName = 'SLI-RadiusAccounting$'
$ApplyConfirmation = 'CREATE-SLI-RADIUS-ACCOUNTING-READONLY-SHARE'
$ExpectedTimeZoneId = 'N. Central Asia Standard Time'
$ExpectedUtcOffsetMinutes = 420

function Get-TextSha256 {
    param([Parameter(Mandatory = $true)][string]$Text)

    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        return ([System.BitConverter]::ToString(
            $algorithm.ComputeHash($bytes)
        )).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $algorithm.Dispose()
    }
}

function Get-NtfsSnapshot {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    $acl = Get-Acl -LiteralPath $LiteralPath
    $sddl = $acl.GetSecurityDescriptorSddlForm(
        [System.Security.AccessControl.AccessControlSections]::All
    )
    return [ordered]@{
        owner = [string]$acl.Owner
        access_rules_protected = [bool]$acl.AreAccessRulesProtected
        sddl = $sddl
        sddl_sha256 = Get-TextSha256 -Text $sddl
    }
}

function Test-ExactShareAccess {
    param([Parameter(Mandatory = $true)][string]$Name)

    $entries = @(Get-SmbShareAccess -Name $Name)
    if ($entries.Count -ne 1) {
        return $false
    }
    $entry = $entries[0]
    return (
        ([string]$entry.AccountName -ieq $ReadAccount) -and
        ([string]$entry.AccessControlType -ieq 'Allow') -and
        ([string]$entry.AccessRight -ieq 'Read')
    )
}

function Assert-LocalReadWorks {
    param([Parameter(Mandatory = $true)][System.IO.FileInfo]$File)

    $shareMode = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
    $stream = [System.IO.File]::Open(
        $File.FullName,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        $shareMode
    )
    try {
        $buffer = New-Object byte[] 1
        [void]$stream.Read($buffer, 0, 1)
    }
    finally {
        $stream.Dispose()
    }
}

if ($env:COMPUTERNAME -ine $ExpectedComputerName) {
    throw "wrong_server: expected $ExpectedComputerName, got $env:COMPUTERNAME"
}

$currentAccount = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
if (-not ($AllowedOperatorAccounts -icontains $currentAccount)) {
    throw (
        "wrong_windows_account: allowed operators " +
        ($AllowedOperatorAccounts -join ', ') + ", got $currentAccount"
    )
}

foreach ($commandName in @('Get-SmbShare', 'Get-SmbShareAccess', 'New-SmbShare')) {
    if (-not (Get-Command $commandName -ErrorAction SilentlyContinue)) {
        throw "required_command_missing:$commandName"
    }
}

if (-not (Test-Path -LiteralPath $ExpectedPath -PathType Container)) {
    throw "accounting_directory_not_found:$ExpectedPath"
}
$resolvedPath = [System.IO.Path]::GetFullPath(
    (Resolve-Path -LiteralPath $ExpectedPath).Path
)
if ($resolvedPath -ine $ExpectedPath) {
    throw "accounting_directory_identity_mismatch:$resolvedPath"
}
$directory = Get-Item -LiteralPath $resolvedPath -Force
if (($directory.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'accounting_directory_reparse_point_forbidden'
}

$accountingFiles = @(
    Get-ChildItem -LiteralPath $resolvedPath -Filter 'IN*.log' -File -Force |
        Sort-Object LastWriteTimeUtc -Descending
)
if ($accountingFiles.Count -lt 1) {
    throw 'accounting_files_not_found'
}
Assert-LocalReadWorks -File $accountingFiles[0]

$localTimeZone = [System.TimeZoneInfo]::Local
$currentUtcOffsetMinutes = [int][System.Math]::Round(
    $localTimeZone.GetUtcOffset([System.DateTime]::UtcNow).TotalMinutes
)
if ([string]$localTimeZone.Id -cne $ExpectedTimeZoneId) {
    throw (
        "timezone_id_mismatch: expected $ExpectedTimeZoneId, got " +
        [string]$localTimeZone.Id
    )
}
if ($currentUtcOffsetMinutes -ne $ExpectedUtcOffsetMinutes) {
    throw (
        "timezone_offset_mismatch: expected $ExpectedUtcOffsetMinutes, got " +
        [string]$currentUtcOffsetMinutes
    )
}

$serviceBefore = Get-Service -Name 'IAS'
$ntfsBefore = Get-NtfsSnapshot -LiteralPath $resolvedPath
$existingShare = Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue
$shareAlreadyExact = $false
if ($null -ne $existingShare) {
    $existingPath = [System.IO.Path]::GetFullPath([string]$existingShare.Path)
    if ($existingPath -ine $resolvedPath) {
        throw "share_name_conflict:${ShareName}:$existingPath"
    }
    $shareAlreadyExact = Test-ExactShareAccess -Name $ShareName
    if (-not $shareAlreadyExact) {
        throw "existing_share_acl_not_exact:$ShareName"
    }
}

$result = [ordered]@{
    status = if ($shareAlreadyExact) { 'already_configured' } else { 'ready' }
    action = $Action.ToLowerInvariant()
    computer_name = $env:COMPUTERNAME
    windows_account = $currentAccount
    accounting_path = $resolvedPath
    accounting_file_count = $accountingFiles.Count
    timezone_id = [string]$localTimeZone.Id
    utc_offset_minutes = $currentUtcOffsetMinutes
    timezone_drift_check_accepted = $true
    share_name = $ShareName
    share_unc = "\\$env:COMPUTERNAME\$ShareName"
    read_account = $ReadAccount
    service_name = 'IAS'
    service_status_before = [string]$serviceBefore.Status
    service_status_after = [string]$serviceBefore.Status
    ntfs_owner = $ntfsBefore.owner
    ntfs_access_rules_protected = $ntfsBefore.access_rules_protected
    ntfs_sddl_sha256_before = $ntfsBefore.sddl_sha256
    ntfs_sddl_sha256_after = $ntfsBefore.sddl_sha256
    ntfs_acl_changed = $false
    share_created = $false
    existing_share_changed = $false
    nps_service_changed = $false
    files_changed = $false
    administrative_share_used = $false
    exact_share_read_acl = $shareAlreadyExact
    required_confirmation = $ApplyConfirmation
}

if ($Action -eq 'Plan') {
    $result | ConvertTo-Json -Depth 6
    exit 0
}

if ($Confirmation -cne $ApplyConfirmation) {
    throw "apply_requires_exact_confirmation:$ApplyConfirmation"
}
if ($shareAlreadyExact) {
    $result.action = 'apply'
    $result | ConvertTo-Json -Depth 6
    exit 0
}

$created = $false
try {
    New-SmbShare `
        -Name $ShareName `
        -Path $resolvedPath `
        -Description 'SLI read-only RADIUS Accounting source' `
        -ReadAccess $ReadAccount `
        -FolderEnumerationMode AccessBased `
        -CachingMode None `
        -EncryptData $true | Out-Null
    $created = $true

    if (-not (Test-ExactShareAccess -Name $ShareName)) {
        throw 'created_share_acl_not_exact'
    }

    $ntfsAfter = Get-NtfsSnapshot -LiteralPath $resolvedPath
    if ($ntfsAfter.sddl -cne $ntfsBefore.sddl) {
        throw 'ntfs_acl_changed_unexpectedly'
    }
    $serviceAfter = Get-Service -Name 'IAS'
    if ([string]$serviceAfter.Status -cne [string]$serviceBefore.Status) {
        throw 'ias_service_status_changed_unexpectedly'
    }

    $result.status = 'applied'
    $result.share_created = $true
    $result.exact_share_read_acl = $true
    $result.ntfs_sddl_sha256_after = $ntfsAfter.sddl_sha256
    $result.service_status_after = [string]$serviceAfter.Status
}
catch {
    if ($created) {
        Remove-SmbShare -Name $ShareName -Force -Confirm:$false -ErrorAction SilentlyContinue
    }
    throw
}

$result | ConvertTo-Json -Depth 6
