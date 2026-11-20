#requires -version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RootPath,
    [switch]$ValidateOnly,
    [string]$ResultPath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
$PythonExe = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$Validator = Join-Path $ProjectRoot "server\sli\storage\acquisition_evidence_root.py"
$DefaultResult = Join-Path $ProjectRoot "artifacts\stage9\evidence\radius-evidence-root-acl-readback.json"
$CanonicalRoot = [System.IO.Path]::GetFullPath($RootPath)

if (-not [System.IO.Path]::IsPathRooted($RootPath)) { throw "Evidence root must be absolute." }
if ($CanonicalRoot.TrimEnd("\") -eq $ProjectRoot.TrimEnd("\") -or $CanonicalRoot.StartsWith($ProjectRoot.TrimEnd("\") + "\", [System.StringComparison]::OrdinalIgnoreCase)) { throw "Evidence root must be outside the project root." }
if (-not (Test-Path -LiteralPath $PythonExe -PathType Leaf)) { throw "Project Python runtime is missing." }
if (-not (Test-Path -LiteralPath $Validator -PathType Leaf)) { throw "Evidence-root validator is missing." }
if (-not $ResultPath) { $ResultPath = $DefaultResult }

function Get-Sha256Text([string]$Value) {
    $Sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($Sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value.ToLowerInvariant())))).Replace("-", "").ToLowerInvariant() }
    finally { $Sha.Dispose() }
}
function Get-SidValue($IdentityReference) {
    return $IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
}
function Get-AclNode([string]$Path, [string]$RelativePath) {
    $Item = Get-Item -LiteralPath $Path -Force
    $Acl = Get-Acl -LiteralPath $Path
    return [ordered]@{ relative_path=$RelativePath; exists=$true; is_directory=[bool]$Item.PSIsContainer; is_reparse_point=[bool]($Item.Attributes -band [IO.FileAttributes]::ReparsePoint); owner_sid=Get-SidValue (New-Object System.Security.Principal.NTAccount($Acl.Owner)); inheritance_protected=[bool]$Acl.AreAccessRulesProtected; entries=@($Acl.Access | ForEach-Object { [ordered]@{ sid=Get-SidValue $_.IdentityReference; access_type=$_.AccessControlType.ToString().ToLowerInvariant(); rights=[int]$_.FileSystemRights; inheritance_flags=[int]$_.InheritanceFlags; propagation_flags=[int]$_.PropagationFlags; is_inherited=[bool]$_.IsInherited } }) }
}

if ($ValidateOnly) {
    $OutputLines = @(& $PythonExe $Validator --validate-contract 2>&1); $ExitCode = $LASTEXITCODE
} else {
    if (-not (Test-Path -LiteralPath $CanonicalRoot -PathType Container)) { throw "Evidence root does not exist." }
    $Nodes=@(); $Roots=@()
    foreach($RelativeName in @(".", "staging", "published", "quarantine")) {
        $NodePath = if($RelativeName -eq ".") { $CanonicalRoot } else { Join-Path $CanonicalRoot $RelativeName }
        if (-not (Test-Path -LiteralPath $NodePath -PathType Container)) { throw "Required evidence-root directory is missing." }
        $FullNodePath=[IO.Path]::GetFullPath($NodePath); $Roots += [IO.Path]::GetPathRoot($FullNodePath); $Nodes += Get-AclNode $FullNodePath $RelativeName
    }
    $RootItem=Get-Item -LiteralPath $CanonicalRoot -Force
    $Snapshot=[ordered]@{ schema_version=1; platform="windows"; target=[ordered]@{ root_fingerprint_sha256=Get-Sha256Text $CanonicalRoot; is_absolute=$true; outside_project_root=$true; exists=$true; is_directory=[bool]$RootItem.PSIsContainer; is_reparse_point=[bool]($RootItem.Attributes -band [IO.FileAttributes]::ReparsePoint); same_volume=(@($Roots | Select-Object -Unique).Count -eq 1) }; nodes=$Nodes }
    $OutputLines=@(($Snapshot | ConvertTo-Json -Depth 8 -Compress) | & $PythonExe $Validator --snapshot - --load-supervisor-environment 2>&1); $ExitCode=$LASTEXITCODE
}
$OutputText=($OutputLines -join [Environment]::NewLine).Trim()
if (-not $ValidateOnly) {
    $CanonicalResult=[IO.Path]::GetFullPath($ResultPath); $ResultParent=Split-Path -Parent $CanonicalResult
    if (-not (Test-Path -LiteralPath $ResultParent -PathType Container)) { throw "ResultPath parent directory does not exist." }
    [IO.File]::WriteAllText($CanonicalResult, $OutputText + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false)))
}
Write-Output $OutputText
exit $ExitCode
