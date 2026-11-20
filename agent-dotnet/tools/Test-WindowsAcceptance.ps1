# Stage 2 only: run in an elevated PowerShell on the disposable Win10 VM.
# This exercises the published executable; Linux cross-publication cannot replace it.
param([string]$OutputRoot = (Join-Path $env:TEMP ('sli-agent-acceptance-' + [guid]::NewGuid())))
$ErrorActionPreference = 'Stop'
# Resolve the caller's relative path before changing to the SDK-pinned directory.
$OutputRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputRoot)
if (Test-Path -LiteralPath $OutputRoot) { throw 'OutputRoot must not already exist' }
Push-Location (Join-Path $PSScriptRoot '..')
try {
    $sdk = dotnet --version
    if ($LASTEXITCODE -ne 0) { throw 'SDK selection failed' }
    if ($sdk -ne '10.0.113') { throw 'Expected .NET SDK 10.0.113' }
    New-Item -ItemType Directory -Path $OutputRoot | Out-Null
    $publish = Join-Path $OutputRoot 'sli-agent-publish'
    dotnet publish src/Sli.Agent.Service -c Release -r win-x64 --self-contained -o $publish
    if ($LASTEXITCODE -ne 0) { throw 'publish failed' }
    $state = Join-Path $OutputRoot 'sli-agent-state'
    $output = & (Join-Path $publish 'SliAgent.exe') prepare "--Agent:StateDir=$state"
    if ($LASTEXITCODE -ne 0) { throw 'prepare failed' }
    $identity = $output | ConvertFrom-Json
    if ($identity.host_id -notmatch '^[0-9a-f-]{36}$' -or $identity.key_fingerprint -notmatch '^[0-9a-f]{64}$') { throw 'unexpected prepare output' }
    $key = Get-Content (Join-Path $state 'identity-key.json') -Raw | ConvertFrom-Json
    if ($key.protection -ne 'dpapi_local_machine') { throw "key is not DPAPI-protected: $($key.protection)" }
    "published $((Get-ChildItem $publish -Recurse -File | Measure-Object Length -Sum).Sum) bytes; key protection $($key.protection)"
}
finally {
    Pop-Location
}
