#requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$ValidateOnly,
    [string]$ProjectRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-SLIFailureEvidence {
    param(
        [Parameter(Mandatory = $true)] [string]$Path,
        [Parameter(Mandatory = $true)] [string]$Reason
    )

    $directory = [System.IO.Path]::GetDirectoryName($Path)
    [System.IO.Directory]::CreateDirectory($directory) | Out-Null
    $payload = [ordered]@{
        status = 'failed'
        action = if ($ValidateOnly) { 'validate' } else { 'ensure' }
        failure_reason = $Reason
        script_version = 'v1'
        recorded_at = [DateTimeOffset]::Now.ToString('o')
        credential_values_exposed = $false
    }
    $temporaryPath = "$Path.$PID.tmp"
    [System.IO.File]::WriteAllText(
        $temporaryPath,
        ($payload | ConvertTo-Json -Depth 5),
        (New-Object System.Text.UTF8Encoding($false))
    )
    Move-Item -LiteralPath $temporaryPath -Destination $Path -Force
    $payload | ConvertTo-Json -Depth 5 -Compress
}

$ScriptPath = [System.IO.Path]::GetFullPath($MyInvocation.MyCommand.Path)
$ScriptDirectory = [System.IO.Path]::GetDirectoryName($ScriptPath)
$ResolvedProjectRoot = if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
    [System.IO.Path]::GetFullPath((Join-Path -Path $ScriptDirectory -ChildPath '..\..'))
}
else {
    [System.IO.Path]::GetFullPath($ProjectRoot)
}
$PythonPath = [System.IO.Path]::GetFullPath((Join-Path -Path $ResolvedProjectRoot -ChildPath '.venv\Scripts\python.exe'))
$WebServerControl = [System.IO.Path]::GetFullPath((Join-Path -Path $ResolvedProjectRoot -ChildPath 'scripts\maintenance\web_server_control.py'))
$EvidencePath = [System.IO.Path]::GetFullPath((Join-Path -Path $ResolvedProjectRoot -ChildPath 'data\maintenance\web-server-autostart.json'))

if (-not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) {
    Write-SLIFailureEvidence -Path $EvidencePath -Reason 'project_virtualenv_python_missing'
    exit 1
}
if (-not (Test-Path -LiteralPath $WebServerControl -PathType Leaf)) {
    Write-SLIFailureEvidence -Path $EvidencePath -Reason 'web_server_control_missing'
    exit 1
}

# All paths are absolute before the current directory changes.  The Python
# wrapper loads the DPAPI-protected runtime environment in-process and writes
# the only persistent startup evidence file.
Set-Location -LiteralPath $ResolvedProjectRoot
$action = if ($ValidateOnly) { 'validate' } else { 'ensure' }
& $PythonPath $WebServerControl --result-file $EvidencePath $action
exit $LASTEXITCODE
