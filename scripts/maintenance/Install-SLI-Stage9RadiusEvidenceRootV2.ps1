#requires -version 5.1
[CmdletBinding()]
param([switch]$ValidateOnly, [string]$Confirmation, [string]$ResultPath)

$ErrorActionPreference="Stop"; Set-StrictMode -Version Latest
$ProjectRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
$PythonExe=Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$EvidenceRoot="C:\SLI"; $RequiredDirectories=@("staging", "published", "quarantine")
$ApplyConfirmation="CREATE-STAGE9-RADIUS-EVIDENCE-ROOT-C-SLI"
$ReadbackScript=Join-Path $PSScriptRoot "Invoke-SLI-Stage9RadiusEvidenceRootV2.ps1"
if (-not $ResultPath) { $ResultPath=Join-Path $ProjectRoot "artifacts\stage9\evidence\radius-evidence-root-acl-readback.json" }
if (-not (Test-Path -LiteralPath $PythonExe -PathType Leaf)) { throw "Project Python runtime is missing." }
if (-not (Test-Path -LiteralPath $ReadbackScript -PathType Leaf)) { throw "Evidence-root readback gate is missing." }
Push-Location -LiteralPath $ProjectRoot
try {
    $IdentityJson = & $PythonExe -c "import json; from server.sli.ops.worker_supervisor_secrets import load_supervisor_environment; from server.sli.sources.windows_runtime_identity import expected_collection_identity,verify_collection_identity; load_supervisor_environment(); principal,sid=expected_collection_identity(); print(json.dumps({'principal':principal,'sid':sid,'status':verify_collection_identity().get('status')}))"
    if ($LASTEXITCODE -ne 0) { throw "Collection identity preflight failed." }
    $Identity = $IdentityJson | ConvertFrom-Json
} finally {
    Pop-Location
}
if (-not $Identity.principal -or -not $Identity.sid -or $Identity.status -ne "ok") { throw "Configured collection identity is not current token." }
if ($ValidateOnly) { & $ReadbackScript -RootPath $EvidenceRoot -ValidateOnly; exit $LASTEXITCODE }
if ($Confirmation -ne $ApplyConfirmation) { throw "Apply requires exact confirmation." }
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw "Elevation required." }
if (Test-Path -LiteralPath $ResultPath) { throw "Accepted ACL readback evidence already exists." }
if (Test-Path -LiteralPath $EvidenceRoot) { throw "C:\SLI already exists; refusing to replace or repair it." }
$CreatedRoot=$false
try {
    $null=New-Item -ItemType Directory -Path $EvidenceRoot; $CreatedRoot=$true
    $Security=New-Object Security.AccessControl.DirectorySecurity; $Security.SetAccessRuleProtection($true,$false)
    $AdminSid=New-Object Security.Principal.SecurityIdentifier("S-1-5-32-544"); $SystemSid=New-Object Security.Principal.SecurityIdentifier("S-1-5-18"); $WorkerSid=New-Object Security.Principal.SecurityIdentifier($Identity.sid)
    $Security.SetOwner($AdminSid); $Inheritance=[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit; $Propagation=[Security.AccessControl.PropagationFlags]::None; $Allow=[Security.AccessControl.AccessControlType]::Allow
    foreach($Sid in @($SystemSid,$AdminSid,$WorkerSid)) { $Security.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($Sid,[Security.AccessControl.FileSystemRights]::FullControl,$Inheritance,$Propagation,$Allow))) }
    Set-Acl -LiteralPath $EvidenceRoot -AclObject $Security
    foreach($Name in $RequiredDirectories) { $null=New-Item -ItemType Directory -Path (Join-Path $EvidenceRoot $Name) }
} catch { if($CreatedRoot -and (Test-Path -LiteralPath $EvidenceRoot) -and @((Get-ChildItem -LiteralPath $EvidenceRoot -Force)).Count -eq 0) { Remove-Item -LiteralPath $EvidenceRoot -Force }; throw }
& $ReadbackScript -RootPath $EvidenceRoot -ResultPath $ResultPath
exit $LASTEXITCODE
