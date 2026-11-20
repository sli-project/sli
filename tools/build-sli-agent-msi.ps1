# SPDX-License-Identifier: Apache-2.0
# PowerShell 5.1. Build inputs contain no enrollment material or service keys.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$InputDirectory,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [ValidatePattern('^\d+\.\d+\.\d+$')][string]$ProductVersion,
    [switch]$DownloadToolchain
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$repo = Split-Path -Parent $PSScriptRoot
$buildVersion = [IO.File]::ReadAllText((Join-Path $repo 'VERSION')).Trim()
function ConvertTo-AgentMsiVersion([string]$Version) {
    if ($Version -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') { throw 'invalid_build_version' }
    $parts = @($Version.Split('.') | ForEach-Object { [int]$_ })
    # Calendar releases use YYYY.minor.patch; MSI limits major/minor to 255.
    if ($parts[0] -ge 2000 -and $parts[0] -le 2255) { $parts[0] -= 2000 }
    if ($parts[0] -gt 255 -or $parts[1] -gt 255 -or $parts[2] -gt 65535) { throw 'invalid_msi_version' }
    return $parts -join '.'
}
$derivedVersion = ConvertTo-AgentMsiVersion $buildVersion
if ($ProductVersion -and $ProductVersion -cne $derivedVersion) { throw 'msi_build_version_mismatch' }
$ProductVersion = $derivedVersion
$lockPath = Join-Path $PSScriptRoot 'msi/toolchain.lock.json'
$lock = Get-Content -LiteralPath $lockPath -Raw | ConvertFrom-Json
if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitProcess) {
    throw 'Build requires 64-bit Windows PowerShell in an x64 MSVC developer environment.'
}
if (-not $env:VCToolsVersion -or -not $env:WindowsSDKVersion -or
    $env:VCToolsVersion.TrimEnd('\') -ne $lock.msvc_tools_version -or
    $env:WindowsSDKVersion.TrimEnd('\') -ne $lock.windows_sdk_version -or
    $env:VSCMD_ARG_TGT_ARCH -ne 'x64') {
    throw 'Use the MSVC tools and Windows SDK versions declared in msi/toolchain.lock.json (x64 target).'
}
$inputRoot = [IO.Path]::GetFullPath($InputDirectory)
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
[void][IO.Directory]::CreateDirectory($inputRoot)
[void][IO.Directory]::CreateDirectory($outputRoot)
# Never recursively delete caller-selected paths. Each build uses a fresh child.
$work = Join-Path $outputRoot ('work-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($work)
function Verified-Input($entry, [bool]$allowDownload) {
    $path = Join-Path $inputRoot $entry.filename
    if (-not [IO.File]::Exists($path)) {
        if (-not $allowDownload) { throw ('Missing locked offline input: ' + $entry.filename) }
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -UseBasicParsing -Uri $entry.url -OutFile $path
    }
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.sha256) {
        throw ('SHA-256 mismatch for locked input: ' + $entry.filename)
    }
    return $path
}
Add-Type -AssemblyName System.IO.Compression.FileSystem
function Extract-Zip([string]$archive, [string]$destination) {
    # Embeddable runtime/toolchain archives are hash verified before extraction.
    [IO.Compression.ZipFile]::ExtractToDirectory($archive, $destination)
}
$pythonZip = Verified-Input $lock.python ([bool]$DownloadToolchain)
$wixZip = Verified-Input $lock.wix ([bool]$DownloadToolchain)
$runtime = Join-Path $work 'payload'
$wix = Join-Path $work 'wix'
Extract-Zip $pythonZip $runtime
Extract-Zip $wixZip $wix
$site = Join-Path $runtime 'Lib/site-packages'
[void][IO.Directory]::CreateDirectory($site)
foreach ($wheel in $lock.wheels) {
    # Wheels must be provisioned separately. The build never contacts PyPI.
    $path = Verified-Input $wheel $false
    $expanded = Join-Path $work $wheel.filename
    Extract-Zip $path $expanded
    Get-ChildItem -LiteralPath $expanded | ForEach-Object {
        if ($_.Name -like '*.data') {
            foreach ($area in @('purelib', 'platlib')) {
                $areaPath = Join-Path $_.FullName $area
                if (Test-Path -LiteralPath $areaPath) {
                    Get-ChildItem -LiteralPath $areaPath | Copy-Item -Destination $site -Recurse
                }
            }
        } else { Copy-Item -LiteralPath $_.FullName -Destination $site -Recurse }
    }
}
# No site import or .pth execution. pywin32 is laid out explicitly, and its
# native DLLs live next to python.exe so SCM needs no user PATH or postinstall.
Get-ChildItem -LiteralPath (Join-Path $site 'pywin32_system32') -Filter '*.dll' |
    ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $runtime }
$paths = "python313.zip`r`n.`r`nLib/site-packages`r`nLib/site-packages/win32`r`nLib/site-packages/win32/lib`r`nLib/site-packages/Pythonwin`r`n"
[IO.File]::WriteAllText((Join-Path $runtime 'python313._pth'), $paths, [Text.UTF8Encoding]::new($false))
foreach ($package in @('sli_agent', 'sli_collect')) {
    $target = Join-Path $runtime $package
    [void][IO.Directory]::CreateDirectory($target)
    Get-ChildItem -LiteralPath (Join-Path $repo $package) -Filter '*.py' |
        ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $target }
}
# Runtime check-ins report the full build version, not the MSI calendar mapping.
$agentVersionPath = Join-Path $runtime 'sli_agent/__init__.py'
$agentVersionSource = [IO.File]::ReadAllText($agentVersionPath)
$agentVersionSource = [regex]::Replace($agentVersionSource, '(?m)^__version__ = "[^"]+"', ('__version__ = "' + $buildVersion + '"'))
[IO.File]::WriteAllText($agentVersionPath, $agentVersionSource, [Text.UTF8Encoding]::new($false))
# Explicit dependency closure: do not copy backend runtime, settings or data.
foreach ($file in @('server/__init__.py', 'server/sli/__init__.py', 'server/sli/storage/__init__.py',
    'server/sli/storage/xml_safety.py', 'server/sli/release_package.py', 'config/event_catalog.json', 'config/workstations_event_catalog.json',
    'config/source_packs/dc.json', 'config/source_packs/workstations.json', 'config/source_packs/ad_context.json',
    'config/source_packs/radius.json', 'config/source_packs/file_audit.json', 'config/stage9_radius_runtime_contract_v1.json', 'sli_agent/LICENSE',
    'sli_agent/ad_snapshot.ps1', 'sli_agent/gpo_snapshot.ps1', 'sli_agent/gpo_writer.ps1', 'scripts/ad_context/GpoReportContract.psm1')) {
    $target = Join-Path $runtime $file
    [void][IO.Directory]::CreateDirectory((Split-Path -Parent $target))
    Copy-Item -LiteralPath (Join-Path $repo $file) -Destination $target
}
Copy-Item -LiteralPath $lockPath -Destination (Join-Path $runtime 'toolchain.lock.json')
# Windows PowerShell 5.1 otherwise decodes non-ASCII UTF-8 as the ANSI codepage.
# Normalize only the staged payload; source files and runtime state are untouched.
foreach ($scriptFile in Get-ChildItem -LiteralPath $runtime -Recurse -File | Where-Object { $_.Extension -in '.ps1', '.psm1' }) {
    [IO.File]::WriteAllText($scriptFile.FullName, [IO.File]::ReadAllText($scriptFile.FullName), [Text.UTF8Encoding]::new($true))
    $scriptTokens = $null; $scriptErrors = $null
    $null = [Management.Automation.Language.Parser]::ParseFile($scriptFile.FullName, [ref]$scriptTokens, [ref]$scriptErrors)
    if (@($scriptErrors).Count) { throw 'agent_msi_powershell_payload_invalid' }
}
$python = Join-Path $runtime 'python.exe'
& $python -I -B -c 'import ssl, cryptography, cffi, win32api, win32crypt, win32evtlog, win32security, win32service, win32serviceutil, servicemanager; import sli_agent.service, sli_agent.msi, sli_agent.ad_dc, sli_agent.workstations, sli_agent.launcher; from sli_agent.ad_dc import event_identities; assert event_identities(); import json; from sli_agent.probe import PACK_ROOT; from sli_agent.modules import RIGHTS_REGISTRY; packs = [json.loads((PACK_ROOT / profile.source_pack).read_text(encoding=\"utf-8\")) for profile in RIGHTS_REGISTRY.values() if profile.source_pack]; assert packs and all(isinstance(pack[\"channels\"], list) for pack in packs)'
if ($LASTEXITCODE -ne 0) { throw 'Import smoke check failed: embedded Python/native DLL dependency closure is incomplete.' }
$actionDll = Join-Path $work 'AgentCustomAction.dll'
$actionObject = Join-Path $work 'AgentCustomAction.obj'
& cl.exe /nologo /std:c++17 /EHsc /O2 /MT /LD /W4 (Join-Path $PSScriptRoot 'msi/custom_action.cpp') "/Fo$actionObject" /link "/OUT:$actionDll" "/IMPLIB:$(Join-Path $work 'AgentCustomAction.lib')" msi.lib shell32.lib ole32.lib advapi32.lib
if ($LASTEXITCODE -ne 0) { throw 'Native MSI action compilation failed.' }
# Generate one deterministic x64 component per payload file. python.exe is the
# ServiceInstall keypath in the authored WiX source, never harvested twice.
$namespace = 'http://schemas.microsoft.com/wix/2006/wi'
$document = [xml]('<Wix xmlns="' + $namespace + '"><Fragment><DirectoryRef Id="INSTALLFOLDER" /></Fragment><Fragment><ComponentGroup Id="AgentPayload" /></Fragment></Wix>')
$directories = @{ '' = $document.Wix.Fragment[0].DirectoryRef }
$group = $document.Wix.Fragment[1].ComponentGroup
$files = Get-ChildItem -LiteralPath $runtime -Recurse -File | Sort-Object FullName
foreach ($file in $files) {
    $relative = $file.FullName.Substring($runtime.Length + 1)
    if ($relative -eq 'python.exe') { continue }
    $parent = Split-Path -Parent $relative
    $parts = @()
    if ($parent) { $parts = $parent.Split('\') }
    $key = ''
    foreach ($part in $parts) {
        $previous = $key
        if ($key) { $key += '\' }
        $key += $part
        if (-not $directories.ContainsKey($key)) {
            $node = $document.CreateElement('Directory', $namespace)
            $node.SetAttribute('Id', ('D' + $directories.Count))
            $node.SetAttribute('Name', $part)
            [void]$directories[$previous].AppendChild($node)
            $directories[$key] = $node
        }
    }
    $hash = [Security.Cryptography.SHA256]::Create()
    try { $id = 'F' + ([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($relative))).Replace('-', '').Substring(0, 32)) }
    finally { $hash.Dispose() }
    $component = $document.CreateElement('Component', $namespace)
    $component.SetAttribute('Id', $id)
    $component.SetAttribute('Guid', '*')
    $component.SetAttribute('Win64', 'yes')
    $node = $document.CreateElement('File', $namespace)
    $node.SetAttribute('Id', $id + '_file')
    $node.SetAttribute('Source', $file.FullName)
    $node.SetAttribute('KeyPath', 'yes')
    [void]$component.AppendChild($node)
    [void]$directories[$key].AppendChild($component)
    $reference = $document.CreateElement('ComponentRef', $namespace)
    $reference.SetAttribute('Id', $id)
    [void]$group.AppendChild($reference)
}
$payloadSource = Join-Path $work 'Payload.wxs'
$document.Save($payloadSource)
$objectDir = $work + '\'
& (Join-Path $wix 'candle.exe') -nologo -arch x64 "-dPayloadRoot=$runtime" "-dCustomActionDll=$actionDll" "-dProductVersion=$ProductVersion" -out $objectDir (Join-Path $PSScriptRoot 'msi/SLIAgent.wxs') $payloadSource
if ($LASTEXITCODE -ne 0) { throw 'WiX source compilation failed.' }
$msi = Join-Path $outputRoot ('SLI-Agent-' + $ProductVersion + '-x64.msi')
& (Join-Path $wix 'light.exe') -nologo -out $msi (Join-Path $work 'SLIAgent.wixobj') (Join-Path $work 'Payload.wixobj')
if ($LASTEXITCODE -ne 0) { throw 'WiX link/Windows Installer validation failed.' }
$digest = (Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText(($msi + '.sha256'), ($digest + '  ' + [IO.Path]::GetFileName($msi) + "`n"), [Text.UTF8Encoding]::new($false))
Write-Output $msi
