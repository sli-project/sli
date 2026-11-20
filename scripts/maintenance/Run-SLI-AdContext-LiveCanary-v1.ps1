[CmdletBinding()]
param(
    [string]$ProjectRoot = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),
    [Parameter(Mandatory = $true)][string]$DirectoryServer,
    [Parameter(Mandatory = $true)][string]$Domain,
    [Parameter(Mandatory = $true)][string]$SearchBase,
    [string]$Sections = "privileged_membership",
    [string]$GroupSids = "",
    [string]$VpnGroupSids = "",
    [Parameter(Mandatory = $true)][string]$ExpectedAccount,
    [ValidateRange(5, 300)][int]$TimeoutSeconds = 120,
    [ValidateRange(1, 5000)][int]$MaxRecords = 2000,
    [ValidateRange(1024, 26214400)][int]$MaxBundleBytes = 2097152,
    [ValidateRange(1, 5000)][int]$MaxDirectoryAccounts = 2000,
    [ValidateRange(1, 5000)][int]$MaxVpnMembers = 500,
    [ValidateRange(1, 72)][int]$MaxGpos = 72,
    [Parameter(Mandatory = $true)][string]$NotBeforeUtc,
    [Parameter(Mandatory = $true)][string]$NotAfterUtc,
    [switch]$Execute,
    [switch]$ValidateOnly,
    [string]$Confirmation = "",
    [string]$ApprovedRequestSha256 = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0
$ProjectRoot = [System.IO.Path]::GetFullPath($ProjectRoot)
if (-not (Test-Path -LiteralPath (Join-Path $ProjectRoot "PROJECT_RULES.md"))) { throw "Invalid ProjectRoot" }
if ($Execute -and $ValidateOnly) { throw "Choose either -Execute or -ValidateOnly" }
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $Python)) { throw "Project Python not found: $Python" }
$Runner = Join-Path $ProjectRoot "scripts\maintenance\ad_context_live_canary.py"
if (-not (Test-Path -LiteralPath $Runner)) { throw "Canary runner not found: $Runner" }
$SectionList = @($Sections.Split(",", [System.StringSplitOptions]::RemoveEmptyEntries) | ForEach-Object { $_.Trim() })
if ($SectionList.Count -eq 0) { throw "At least one section is required" }
$Groups = @($GroupSids.Split(",", [System.StringSplitOptions]::RemoveEmptyEntries) | ForEach-Object { $_.Trim() })
$VpnGroups = @($VpnGroupSids.Split(",", [System.StringSplitOptions]::RemoveEmptyEntries) | ForEach-Object { $_.Trim() })

$Arguments = @(
    $Runner,
    "--directory-server", $DirectoryServer,
    "--domain", $Domain,
    "--search-base", $SearchBase,
    "--expected-account", $ExpectedAccount,
    "--timeout-seconds", [string]$TimeoutSeconds,
    "--max-records", [string]$MaxRecords,
    "--max-bundle-bytes", [string]$MaxBundleBytes,
    "--max-directory-accounts", [string]$MaxDirectoryAccounts,
    "--max-vpn-members", [string]$MaxVpnMembers,
    "--max-gpos", [string]$MaxGpos,
    "--not-before-utc", $NotBeforeUtc,
    "--not-after-utc", $NotAfterUtc
)
foreach ($Section in $SectionList) { $Arguments += @("--section", $Section) }
foreach ($Group in $Groups) { $Arguments += @("--group-sid", $Group) }
foreach ($Group in $VpnGroups) { $Arguments += @("--vpn-group-sid", $Group) }
if ($Execute) {
    $Arguments += @("--execute", "--confirmation", $Confirmation, "--approved-request-sha256", $ApprovedRequestSha256)
}
else {
    $Arguments += "--validate-only"
}

Set-Location -LiteralPath $ProjectRoot
& $Python @Arguments
if ($LASTEXITCODE -ne 0) { throw "AD Context live canary failed with exit code $LASTEXITCODE" }
