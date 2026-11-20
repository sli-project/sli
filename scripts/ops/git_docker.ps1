param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$GitArgs
)

$ErrorActionPreference = "Stop"

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$DockerImage = "alpine/git:latest"

if (-not $GitArgs -or $GitArgs.Count -eq 0) {
    Write-Host "Usage: powershell -NoProfile -ExecutionPolicy Bypass -File scripts\ops\git_docker.ps1 <git args>"
    Write-Host "Example: powershell -NoProfile -ExecutionPolicy Bypass -File scripts\ops\git_docker.ps1 status --short"
    exit 2
}

$dockerPath = $ProjectRoot -replace "\\", "/"
if ($dockerPath -match "^([A-Za-z]):/(.*)$") {
    $dockerPath = "/$($Matches[1].ToLower())/$($Matches[2])"
}

docker run --rm `
    -v "${dockerPath}:/repo" `
    -w /repo `
    $DockerImage `
    @GitArgs

exit $LASTEXITCODE
