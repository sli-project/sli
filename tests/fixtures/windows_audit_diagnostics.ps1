# Extract declarations only. Never import or dot-source either operational file.
param([string]$RepositoryRoot, [string]$FixtureRoot, [string]$HelperPath, [int]$ExpectedMajor)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
if ($PSVersionTable.PSVersion.Major -ne $ExpectedMajor) { throw "Unexpected PowerShell version" }
if ($ExpectedMajor -eq 5 -and $PSVersionTable.PSVersion.Minor -lt 1) { throw "PowerShell 5.1 required" }
$helper = [IO.Path]::GetFullPath($HelperPath)
$root = [IO.Path]::GetFullPath($FixtureRoot).TrimEnd('\') + '\'
if (-not $helper.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { throw "Helper must be fixture-owned" }
if (-not (Test-Path -LiteralPath $helper -PathType Leaf)) { throw "Fixture helper missing" }
$quotedHelper = "'" + $helper.Replace("'", "''") + "'"
function Import-OnlyDeclarations([string]$RelativePath, [string[]]$Names) {
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $RepositoryRoot $RelativePath), [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw "Source parse failed" }
    foreach ($name in $Names) {
        $matches = @($ast.EndBlock.Statements | Where-Object {
            $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -eq $name
        })
        if ($matches.Count -ne 1) { throw "Expected one top-level declaration: $name" }
        $text = $matches[0].Extent.Text.Replace('"dcdiag.exe"', $quotedHelper).Replace('"taskkill.exe"', $quotedHelper).Replace('"auditpol.exe"', $quotedHelper)
        # Output only declaration strings, never source-file top-level statements.
        $text
    }
}
$declarations = @(Import-OnlyDeclarations "scripts/ad_context/ActiveDirectoryContext.psm1" @("Invoke-SLIBoundedDcdiag"))
$declarations += @(Import-OnlyDeclarations "scripts/manual_dc_audit/Invoke-DcAuditLoggingSetup.ps1" @(
    "Invoke-CommandLine", "Set-AuditPolicyItem", "Export-DcAuditState", "Install-MinimumAuditPolicy"
))
if (($declarations -join "`n") -match '"(dcdiag|taskkill|auditpol)\.exe"') { throw "Unreplaced operational boundary" }
. ([scriptblock]::Create(($declarations -join "`n")))

# Replace every remaining operational/export/UI boundary before invoking anything.
$script:messages = [Collections.Generic.List[string]]::new()
function Write-Host { param([string]$Object) $script:messages.Add($Object) }
function Write-Section { param([string]$Title) }
function Read-YesNo { return $true }
function New-StateDirectory { return $FixtureRoot }
function wevtutil { throw "Unexpected event-channel boundary" }
function Get-ComputerInfo { throw "Unexpected computer-information boundary" }
function Get-CimInstance { throw "Unexpected CIM boundary" }
function Assert-Equal($Actual, $Expected) { if ($Actual -ne $Expected) { throw "Expected '$Expected', got '$Actual'" } }

# The helper starts no descendants and self-terminates after eight seconds.
foreach ($case in @(
    @{ Mode = "flood"; Limit = 262144; State = "passed"; Code = $null },
    @{ Mode = "nonzero"; Limit = 1024; State = "failed"; Code = "dcdiag_services_failed" },
    @{ Mode = "timeout"; Limit = 1024; State = "timeout"; Code = "dcdiag_timeout" },
    @{ Mode = "boundary"; Limit = 1024; State = "passed"; Code = $null },
    @{ Mode = "overflow"; Limit = 1024; State = "unavailable"; Code = "dcdiag_output_limit_exceeded" }
)) {
    $env:SLI_FIXTURE_MODE = $case.Mode
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $result = Invoke-SLIBoundedDcdiag -Server fixture.invalid -TestName Services -CommandTimeoutSeconds 5 -MaxDiagnosticBytes $case.Limit
    Assert-Equal $result.state $case.State
    Assert-Equal $result.error_code $case.Code
    if ($clock.Elapsed.TotalSeconds -gt 9) { throw "Deadline plus cleanup exceeded bound" }
}

$env:SLI_FIXTURE_MODE = "audit"
$env:SLI_FIXTURE_LOG = Join-Path $FixtureRoot "audit-actions.txt"
$env:SLI_FIXTURE_NTH = "1"
$setting = @{ Name = "Fixture"; Guid = "{0cce923f-69ae-11d9-bed3-505054503030}"; Success = $true; Failure = $true; Ru = "fixture"; En = "fixture" }
foreach ($action in @("/get", "/set", "/backup", "/list")) {
    [IO.File]::WriteAllText($env:SLI_FIXTURE_LOG, "")
    $script:messages.Clear()
    $env:SLI_FIXTURE_FAIL = $action
    $failureMessage = $null
    try {
        if ($action -in @("/get", "/set")) { Set-AuditPolicyItem $setting }
        else { Export-DcAuditState | Out-Null }
    } catch { $failureMessage = $_.Exception.Message }
    $expected = switch ($action) {
        "/get" { @{ Message = "Validate Fixture failed with exit code 5"; Calls = "/get" } }
        "/set" { @{ Message = "Fixture failed with exit code 5"; Calls = "/get,/set" } }
        "/backup" { @{ Message = "auditpol backup failed with exit code 5"; Calls = "/backup" } }
        "/list" { @{ Message = "auditpol subcategory inventory failed with exit code 5"; Calls = "/backup,/get,/list" } }
    }
    Assert-Equal $failureMessage $expected.Message
    if ($script:messages.Contains("Export completed.")) { throw "Export failure reached success" }
    $calls = [IO.File]::ReadAllLines($env:SLI_FIXTURE_LOG)
    Assert-Equal ($calls -join ",") $expected.Calls
    if ($action -eq "/get" -and $calls -contains "/set") { throw "Validation failure reached mutation" }
}
# Exercise current-policy export failure too, independently from Set's /get.
$env:SLI_FIXTURE_FAIL = "/get"
[IO.File]::WriteAllText($env:SLI_FIXTURE_LOG, "")
$failureMessage = $null
try { Export-DcAuditState | Out-Null } catch { $failureMessage = $_.Exception.Message }
Assert-Equal $failureMessage "auditpol current policy failed with exit code 5"
Assert-Equal ([IO.File]::ReadAllLines($env:SLI_FIXTURE_LOG) -join ",") "/backup,/get"

# Partial installation: first set succeeds, second set fails; final success/export is unreachable.
function Export-DcAuditState { return $FixtureRoot }
function Get-MinimumAuditPolicySettings { return @($setting, $setting) }
$script:messages.Clear()
[IO.File]::WriteAllText($env:SLI_FIXTURE_LOG, "")
$env:SLI_FIXTURE_FAIL = "/set"
$env:SLI_FIXTURE_NTH = "2"
$failureMessage = $null
try { Install-MinimumAuditPolicy } catch { $failureMessage = $_.Exception.Message }
Assert-Equal $failureMessage "Fixture failed with exit code 5"
if ($script:messages -match "Installation menu completed") { throw "Partial application reached success" }
Assert-Equal (@([IO.File]::ReadAllLines($env:SLI_FIXTURE_LOG) | Where-Object { $_ -eq "/set" }).Count) 2
[Console]::WriteLine("HERMETIC_WINDOWS_AUDIT_OK")
