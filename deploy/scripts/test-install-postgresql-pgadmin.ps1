$target = Join-Path $PSScriptRoot 'install-postgresql-pgadmin.ps1'
if (-not (Test-Path -LiteralPath $target)) {
    throw "Target script is missing: $target"
}

$content = Get-Content -LiteralPath $target -Raw
$required = @(
    'postgresql.org/download/windows'
    'pgadmin.org'
    '--mode'
    '--unattended'
    '--prefix'
    '--datadir'
    'postgresql'
    'pgAdmin'
)

foreach ($needle in $required) {
    if ($content -notmatch [regex]::Escape($needle)) {
        throw "Required native-install marker is missing: $needle"
    }
}

if ($content -match '(?i)docker|docker\.exe|compose') {
    throw 'The native PostgreSQL/pgAdmin installer must not depend on Docker.'
}

'NATIVE_INSTALL_SCRIPT_TEST_OK'
