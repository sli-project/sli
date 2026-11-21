# Run on a trusted Windows build machine. Copy the resulting MSI and manifest
# to the trusted Debian kit input cache (SLI_BETA_KIT_DEBS_DIR on the runner).
#Requires -Version 7.3
param(
    [Parameter(Mandatory)][string]$Cache,
    [string]$Commit = 'HEAD',
    [string]$MsvcRoot,
    [string]$WindowsSdkRoot
)
$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'The beta kit MSI must be built on Windows.' }
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$sourceCommit = git -C $repo rev-parse --verify --end-of-options "$Commit^{commit}"
if ($LASTEXITCODE -ne 0 -or $sourceCommit -cnotmatch '\A[a-f0-9]{40}\z') {
    throw 'Could not resolve the agent MSI source commit.'
}
$shallow = git -C $repo rev-parse --is-shallow-repository
if ($LASTEXITCODE -ne 0 -or $shallow -ne 'false') { throw 'The beta kit MSI requires the full source history.' }
$build = git -C $repo rev-list --first-parent --count $sourceCommit
if ($LASTEXITCODE -ne 0) { throw 'Could not determine the agent build number.' }
$cachePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Cache)
$work = [IO.Directory]::CreateTempSubdirectory('sli-beta-msi-').FullName
$name = "SliAgent-$sourceCommit.msi"
$stagedMsi = Join-Path $cachePath "$name.$([IO.Path]::GetFileName($work)).tmp"
$stagedManifest = "$stagedMsi.json"
try {
    $archive = Join-Path $work 'source.tar'
    $source = Join-Path $work 'source'
    $output = Join-Path $work 'output'
    New-Item -ItemType Directory -Path $source | Out-Null
    git -C $repo archive --format=tar "--output=$archive" $sourceCommit
    if ($LASTEXITCODE -ne 0) { throw "Could not export $sourceCommit." }
    & (Join-Path $env:SystemRoot 'System32/tar.exe') -xf $archive -C $source
    if ($LASTEXITCODE -ne 0) { throw "Could not extract $sourceCommit." }

    $tools = Join-Path $source 'agent-dotnet/tools'
    $version = & (Join-Path $PSScriptRoot 'Get-MsiVersion.ps1') -BuildNumber $build -ReleaseFile (Join-Path $source 'VERSION')
    $buildArgs = @{ OutputRoot = $output; Version = $version }
    if ($MsvcRoot) { $buildArgs.MsvcRoot = $MsvcRoot }
    if ($WindowsSdkRoot) { $buildArgs.WindowsSdkRoot = $WindowsSdkRoot }
    Push-Location $source
    try {
        & (Join-Path $tools 'Build-Msi.ps1') @buildArgs
        $msi = Join-Path $output 'SliAgent.msi'
        & (Join-Path $PSHOME 'pwsh.exe') -NoProfile -File (Join-Path $tools 'Test-MsiTables.ps1') `
            -Msi $msi -PublishDirectory (Join-Path $output 'publish') -ExpectedVersion $version
        if ($LASTEXITCODE -ne 0) { throw 'MSI table and payload verification failed.' }
    }
    finally { Pop-Location }

    [IO.Directory]::CreateDirectory($cachePath) | Out-Null
    Copy-Item -LiteralPath $msi -Destination $stagedMsi
    $digest = (Get-FileHash -LiteralPath $stagedMsi -Algorithm SHA256).Hash.ToLowerInvariant()
    $manifest = @{ source_commit = $sourceCommit; sha256 = $digest; product_version = $version } | ConvertTo-Json
    [IO.File]::WriteAllText($stagedManifest, $manifest + "`n")
    Move-Item -LiteralPath $stagedMsi -Destination (Join-Path $cachePath $name) -Force
    Move-Item -LiteralPath $stagedManifest -Destination (Join-Path $cachePath "$name.json") -Force
    Write-Output (Join-Path $cachePath $name)
}
finally {
    Remove-Item -LiteralPath $stagedMsi, $stagedManifest -ErrorAction SilentlyContinue
    [IO.Directory]::Delete($work, $true)
}
