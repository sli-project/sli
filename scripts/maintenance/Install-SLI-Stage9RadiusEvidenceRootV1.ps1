#requires -version 5.1
[CmdletBinding()]
param(
    [switch]$ValidateOnly,

    [string]$Confirmation,

    [string]$ResultPath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ProjectRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot "..\..")
)
$EvidenceRoot = "C:\SLI"
$RequiredDirectories = @("staging", "published", "quarantine")
$ExpectedPrincipal = "EXAMPLE\operator"
$ExpectedSid = "S-1-5-21-100000004-200000004-300000004-6995"
$ApplyConfirmation = "CREATE-STAGE9-RADIUS-EVIDENCE-ROOT-C-SLI"
$ReadbackScript = Join-Path $PSScriptRoot (
    "Invoke-SLI-Stage9RadiusEvidenceRootV1.ps1"
)
$DefaultResult = Join-Path $ProjectRoot (
    "artifacts\stage9\evidence\radius-evidence-root-acl-readback.json"
)

if (-not $ResultPath) {
    $ResultPath = $DefaultResult
}
$CanonicalResult = [System.IO.Path]::GetFullPath($ResultPath)
if ((Join-Path $ProjectRoot "artifacts").ToLowerInvariant() -ne (
    $CanonicalResult.Substring(
        0,
        [Math]::Min(
            (Join-Path $ProjectRoot "artifacts").Length,
            $CanonicalResult.Length
        )
    ).ToLowerInvariant()
)) {
    throw "ResultPath must stay under project artifacts."
}
if (-not (Test-Path -LiteralPath $ReadbackScript -PathType Leaf)) {
    throw "Evidence-root readback gate is missing."
}

$CurrentPrincipal = (
    & whoami.exe 2>$null
).Trim()
if ($CurrentPrincipal.ToLowerInvariant() -ne (
    $ExpectedPrincipal.ToLowerInvariant()
)) {
    throw "Current Windows account is not the approved owner."
}
$TranslatedSid = (
    New-Object System.Security.Principal.NTAccount($ExpectedPrincipal)
).Translate(
    [System.Security.Principal.SecurityIdentifier]
).Value
if ($TranslatedSid -ne $ExpectedSid) {
    throw "Approved Windows identity SID changed."
}

if ($ValidateOnly) {
    & $ReadbackScript -RootPath $EvidenceRoot -ValidateOnly
    exit $LASTEXITCODE
}
if ($Confirmation -ne $ApplyConfirmation) {
    throw "Apply requires -Confirmation $ApplyConfirmation"
}
if (Test-Path -LiteralPath $CanonicalResult) {
    throw "Accepted ACL readback evidence already exists."
}
if (Test-Path -LiteralPath $EvidenceRoot) {
    throw "C:\SLI already exists; refusing to replace or repair it."
}

$CreatedRoot = $false
try {
    $null = New-Item -ItemType Directory -Path $EvidenceRoot
    $CreatedRoot = $true

    $Security = New-Object System.Security.AccessControl.DirectorySecurity
    $Security.SetAccessRuleProtection($true, $false)
    $AdminSid = New-Object System.Security.Principal.SecurityIdentifier(
        "S-1-5-32-544"
    )
    $SystemSid = New-Object System.Security.Principal.SecurityIdentifier(
        "S-1-5-18"
    )
    $WorkerSid = New-Object System.Security.Principal.SecurityIdentifier(
        $ExpectedSid
    )
    $Security.SetOwner($AdminSid)
    $Inheritance = (
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit `
        -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    )
    $Propagation = [System.Security.AccessControl.PropagationFlags]::None
    $Allow = [System.Security.AccessControl.AccessControlType]::Allow
    foreach ($Sid in @($SystemSid, $AdminSid, $WorkerSid)) {
        $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $Sid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            $Inheritance,
            $Propagation,
            $Allow
        )
        $Security.AddAccessRule($Rule)
    }
    Set-Acl -LiteralPath $EvidenceRoot -AclObject $Security

    foreach ($Name in $RequiredDirectories) {
        $null = New-Item -ItemType Directory -Path (
            Join-Path $EvidenceRoot $Name
        )
    }
}
catch {
    if ($CreatedRoot -and (Test-Path -LiteralPath $EvidenceRoot)) {
        $Children = @(Get-ChildItem -LiteralPath $EvidenceRoot -Force)
        if ($Children.Count -eq 0) {
            Remove-Item -LiteralPath $EvidenceRoot -Force
        }
    }
    throw
}

& $ReadbackScript `
    -RootPath $EvidenceRoot `
    -ResultPath $CanonicalResult
exit $LASTEXITCODE
