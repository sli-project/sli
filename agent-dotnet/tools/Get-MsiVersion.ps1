param(
    [Parameter(Mandatory)][ValidateRange(1, 16776959)][int]$BuildNumber,
    [string]$ReleaseFile = (Join-Path $PSScriptRoot '../../VERSION')
)
$ErrorActionPreference = 'Stop'
$release = (Get-Content -LiteralPath $ReleaseFile -Raw).Trim()
if ($release -cnotmatch '\A([0-9]{4})\.[0-9]{2}\.[0-9]{2}\z') { throw 'Expected a calendar release in VERSION.' }
$major = [int]$Matches[1] - 2000
if ($major -lt 1 -or $major -gt 255) { throw 'VERSION year is outside the MSI product version range.' }
# Windows Installer compares three fields. The .NET assembly version also
# carries this number and reserves 65535, so carry one count earlier.
'{0}.{1}.{2}' -f $major, [Math]::Floor($BuildNumber / 65535), ($BuildNumber % 65535)
