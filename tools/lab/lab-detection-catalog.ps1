# Replay synthetic Windows events in the .NET detector and local test database.
# Run after building server-dotnet/Sli.Server.slnx with the local .NET environment loaded.
$ErrorActionPreference = 'Stop'
$repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$project = Join-Path $repo 'server-dotnet/tests/Sli.Server.Tests'
$dotnet = if ($env:DOTNET_HOST_PATH) { $env:DOTNET_HOST_PATH } else { 'dotnet' }

$checks = @(
    @{ Catalog = '01-03'; Filter = '-method'; Name = 'Sli.Server.Tests.Reporting.SecurityProblemsV2Tests.PasswordSeriesShowCatalogFactsInQueueAndHomeWithoutDuplicateRows' }
    @{ Catalog = '04-05'; Filter = '-class'; Name = 'Sli.Server.Tests.Semantic.KerberosDetectionTests' }
    @{ Catalog = '06-08'; Filter = '-class'; Name = 'Sli.Server.Tests.Problems.AdminGroupLogAuditTests' }
    @{ Catalog = '09'; Filter = '-class'; Name = 'Sli.Server.Tests.Semantic.AgentStopDetectionTests' }
)

$results = foreach ($check in $checks) {
    & $dotnet run --project $project --no-build -- $check.Filter $check.Name -failSkips | Out-Host
    [pscustomobject]@{
        Catalog = $check.Catalog
        SyntheticReplay = if ($LASTEXITCODE -eq 0) { 'passed' } else { 'failed' }
    }
}
$results | Format-Table -AutoSize
if ($results.SyntheticReplay -contains 'failed') { exit 1 }
