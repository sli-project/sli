param(
    [string]$OutputRoot = (Join-Path $PSScriptRoot '../../artifacts/agent-dotnet'),
    [ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version = '0.3.5',
    [switch]$NoRestore,
    [string]$MsvcRoot = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207',
    [string]$WindowsSdkRoot = 'C:\Program Files (x86)\Windows Kits\10',
    [string]$WindowsSdkVersion = '10.0.26100.0'
)
$ErrorActionPreference = 'Stop'
$dotnet = if ($env:DOTNET_HOST_PATH) { $env:DOTNET_HOST_PATH } else { 'dotnet' }
$env:DOTNET_GENERATE_ASPNET_CERTIFICATE = 'false'
$env:DOTNET_ADD_GLOBAL_TOOLS_TO_PATH = 'false'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
if (-not $IsWindows -and $PSVersionTable.PSEdition -eq 'Core') { throw 'MSI linking requires Windows; Linux CI cross-publishes the payload.' }
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$output = [IO.Path]::GetFullPath($OutputRoot)
New-Item -ItemType Directory -Force $output | Out-Null
$publish = Join-Path $output 'publish'
$native = Join-Path $output 'native/RegistrationCA.dll'
& (Join-Path $PSScriptRoot 'Build-RegistrationCA.ps1') -OutputFile $native `
    -MsvcRoot $MsvcRoot -WindowsSdkRoot $WindowsSdkRoot -WindowsSdkVersion $WindowsSdkVersion
$utilExtension = 'WixToolset.Util.wixext/5.0.2'
Push-Location $projectRoot
try {
    if (-not $NoRestore) {
        & $dotnet tool restore
        if ($LASTEXITCODE -ne 0) { throw 'WiX restore failed' }
        & $dotnet tool run wix -- extension add $utilExtension
        if ($LASTEXITCODE -ne 0) { throw 'WiX Util restore failed' }
    }
    $restoreArgs = @()
    if ($NoRestore) { $restoreArgs += '--no-restore' }
    & $dotnet publish src/Sli.Agent.Service -c Release -r win-x64 --self-contained -p:Version=$Version -o $publish @restoreArgs
    if ($LASTEXITCODE -ne 0) { throw 'Publish failed' }
    $entries = @(Get-ChildItem -LiteralPath $publish -File -Recurse | Where-Object { $_.Name -ne 'SliAgent.exe' } | Sort-Object FullName | ForEach-Object {
        $relative = [IO.Path]::GetRelativePath($publish, $_.FullName)
        $path = [Security.SecurityElement]::Escape($_.FullName)
        $name = [Security.SecurityElement]::Escape($relative)
        "<Component Directory=`"INSTALLFOLDER`" Guid=`"*`"><File Source=`"$path`" Name=`"$name`" KeyPath=`"yes`" /></Component>"
    })
    # The current self-contained output is flat. Fail if a future dependency needs directories.
    if (Get-ChildItem -LiteralPath $publish -Directory) { throw 'Nested publish directories require explicit MSI authoring' }
    $harvest = Join-Path $output 'PublishedFiles.wxs'
    [IO.File]::WriteAllText($harvest, '<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs"><Fragment><ComponentGroup Id="PublishedFiles">' + ($entries -join '') + '</ComponentGroup></Fragment></Wix>')
    $responseFile = Join-Path $output 'build.rsp'
    $arguments = @('build', ('"' + (Join-Path $projectRoot 'installer/SliAgent.wxs') + '"'), ('"' + (Join-Path $projectRoot 'installer/Registration.wxs') + '"'), ('"' + $harvest + '"'),
        '-arch x64', ('-ext ' + $utilExtension), '-wx1149', ('-d "RegistrationCaPath=' + $native + '"'), ('-d "PublishDir=' + $publish + '"'), ('-d "ProductVersion=' + $Version + '"'), ('-o "' + (Join-Path $output 'SliAgent.msi') + '"'))
    [IO.File]::WriteAllText($responseFile, ($arguments -join ' '))
    & $dotnet tool run wix -- "@$responseFile"
    if ($LASTEXITCODE -ne 0) { throw 'MSI build failed' }
    Get-FileHash -LiteralPath (Join-Path $output 'SliAgent.msi') -Algorithm SHA256
}
finally { Pop-Location }
