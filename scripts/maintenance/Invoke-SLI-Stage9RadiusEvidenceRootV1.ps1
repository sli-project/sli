#requires -version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$RootPath,

    [switch]$ValidateOnly,

    [string]$ResultPath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ProjectRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot "..\..")
)
$PythonExe = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$Validator = Join-Path $ProjectRoot "server\sli\storage\acquisition_evidence_root.py"
$CanonicalRoot = [System.IO.Path]::GetFullPath($RootPath)

if (-not [System.IO.Path]::IsPathRooted($RootPath)) {
    throw "RootPath must be absolute."
}
if ($CanonicalRoot.TrimEnd("\") -eq $ProjectRoot.TrimEnd("\")) {
    throw "Evidence root must be outside the project root."
}
$ProjectPrefix = $ProjectRoot.TrimEnd("\") + "\"
if ($CanonicalRoot.StartsWith(
        $ProjectPrefix,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
    throw "Evidence root must be outside the project root."
}
if (-not (Test-Path -LiteralPath $PythonExe -PathType Leaf)) {
    throw "Project Python runtime is missing."
}
if (-not (Test-Path -LiteralPath $Validator -PathType Leaf)) {
    throw "Evidence-root validator is missing."
}

function Get-Sha256Text {
    param([Parameter(Mandatory = $true)][string]$Value)
    $Sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $Bytes = [System.Text.Encoding]::UTF8.GetBytes(
            $Value.ToLowerInvariant()
        )
        return (
            [System.BitConverter]::ToString($Sha.ComputeHash($Bytes))
        ).Replace("-", "").ToLowerInvariant()
    }
    finally {
        $Sha.Dispose()
    }
}

function Get-SidValue {
    param([Parameter(Mandatory = $true)]$IdentityReference)
    return $IdentityReference.Translate(
        [System.Security.Principal.SecurityIdentifier]
    ).Value
}

function Get-AclNode {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$RelativePath
    )
    $Item = Get-Item -LiteralPath $Path -Force
    $Acl = Get-Acl -LiteralPath $Path
    $Entries = @(
        $Acl.Access | ForEach-Object {
            [ordered]@{
                sid = Get-SidValue -IdentityReference $_.IdentityReference
                access_type = $_.AccessControlType.ToString().ToLowerInvariant()
                rights = [int]$_.FileSystemRights
                inheritance_flags = [int]$_.InheritanceFlags
                propagation_flags = [int]$_.PropagationFlags
                is_inherited = [bool]$_.IsInherited
            }
        }
    )
    return [ordered]@{
        relative_path = $RelativePath
        exists = $true
        is_directory = [bool]$Item.PSIsContainer
        is_reparse_point = [bool](
            $Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint
        )
        owner_sid = Get-SidValue -IdentityReference (
            New-Object System.Security.Principal.NTAccount($Acl.Owner)
        )
        inheritance_protected = [bool]$Acl.AreAccessRulesProtected
        entries = $Entries
    }
}

if ($ValidateOnly) {
    $OutputLines = @(
        & $PythonExe $Validator --validate-contract 2>&1
    )
    $ExitCode = $LASTEXITCODE
}
else {
    if (-not (Test-Path -LiteralPath $CanonicalRoot -PathType Container)) {
        throw "Evidence root does not exist."
    }
    $RelativeNames = @(".", "staging", "published", "quarantine")
    $Nodes = @()
    $Roots = @()
    foreach ($RelativeName in $RelativeNames) {
        $NodePath = if ($RelativeName -eq ".") {
            $CanonicalRoot
        }
        else {
            Join-Path $CanonicalRoot $RelativeName
        }
        if (-not (Test-Path -LiteralPath $NodePath -PathType Container)) {
            throw "Required evidence-root directory is missing."
        }
        $FullNodePath = [System.IO.Path]::GetFullPath($NodePath)
        $Roots += [System.IO.Path]::GetPathRoot($FullNodePath)
        $Nodes += Get-AclNode -Path $FullNodePath -RelativePath $RelativeName
    }
    $SameVolume = @($Roots | Select-Object -Unique).Count -eq 1
    $RootItem = Get-Item -LiteralPath $CanonicalRoot -Force
    $Snapshot = [ordered]@{
        schema_version = 1
        platform = "windows"
        target = [ordered]@{
            root_fingerprint_sha256 = Get-Sha256Text -Value $CanonicalRoot
            is_absolute = $true
            outside_project_root = $true
            exists = $true
            is_directory = [bool]$RootItem.PSIsContainer
            is_reparse_point = [bool](
                $RootItem.Attributes -band (
                    [System.IO.FileAttributes]::ReparsePoint
                )
            )
            same_volume = $SameVolume
        }
        nodes = $Nodes
    }
    $SnapshotJson = $Snapshot | ConvertTo-Json -Depth 8 -Compress
    $OutputLines = @(
        $SnapshotJson | & $PythonExe $Validator --snapshot - 2>&1
    )
    $ExitCode = $LASTEXITCODE
}

$OutputText = ($OutputLines -join [Environment]::NewLine).Trim()
if ($ResultPath) {
    $CanonicalResult = [System.IO.Path]::GetFullPath($ResultPath)
    $ResultParent = Split-Path -Parent $CanonicalResult
    if (-not (Test-Path -LiteralPath $ResultParent -PathType Container)) {
        throw "ResultPath parent directory does not exist."
    }
    [System.IO.File]::WriteAllText(
        $CanonicalResult,
        $OutputText + [Environment]::NewLine,
        (New-Object System.Text.UTF8Encoding($false))
    )
}
Write-Output $OutputText
exit $ExitCode
