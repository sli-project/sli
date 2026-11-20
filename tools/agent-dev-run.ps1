# Console-only workstation rehearsal. Does not change Windows audit policy.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Directory,
    [Parameter(Mandatory)][string]$CaBundle,
    [string]$ServerUrl = 'https://localhost:8443',
    [string]$PythonExecutable = 'python'
)
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this helper in an elevated PowerShell console: the workstation module must read the Windows Security log. Audit policy remains unchanged.'
}
$repo = Split-Path -Parent $PSScriptRoot
$root = [IO.Path]::GetFullPath($Directory)
$ca = (Resolve-Path -LiteralPath $CaBundle -ErrorAction Stop).Path
if (-not (Test-Path -LiteralPath $ca -PathType Leaf)) { throw 'agent_dev_ca_bundle_invalid' }
$uri = [Uri]$ServerUrl
if ($uri.Scheme -ne 'https' -or $uri.UserInfo -or $uri.Query -or $uri.Fragment -or $uri.AbsolutePath -ne '/') {
    throw 'agent_dev_server_url_invalid'
}
# Use a new directory so existing state, junctions and permissions are untouched.
if (Test-Path -LiteralPath $root) { throw 'agent_dev_directory_must_be_new' }
$taskParent = Split-Path -Parent $root
while ($taskParent) {
    $parentItem = Get-Item -LiteralPath $taskParent -Force -ErrorAction Stop
    if ($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'agent_dev_reparse_path_rejected' }
    $nextParent = Split-Path -Parent $taskParent
    if ($nextParent -eq $taskParent) { break }
    $taskParent = $nextParent
}
[IO.Directory]::CreateDirectory($root) | Out-Null
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetAccessRuleProtection($true, $false)
$inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
foreach ($sid in @($identity.User, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
    $rule = [Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', $inherit,
        [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $root -AclObject $acl
if (-not (Get-Acl -LiteralPath $root).AreAccessRulesProtected) { throw 'agent_dev_acl_not_protected' }
$venv = Join-Path $root 'venv'
& $PythonExecutable -m venv $venv
if ($LASTEXITCODE -ne 0) { throw 'agent_dev_venv_failed' }
$python = Join-Path $venv 'Scripts\python.exe'
& $python -m pip install --disable-pip-version-check -r (Join-Path $repo 'sli_agent\requirements.txt')
if ($LASTEXITCODE -ne 0) { throw 'agent_dev_dependencies_failed' }
$state = Join-Path $root 'state'
[IO.Directory]::CreateDirectory($state) | Out-Null
Set-Acl -LiteralPath $state -AclObject $acl
$configPath = Join-Path $root 'agent.json'
# collection_enabled controls the legacy single-channel module. Workstations is
# enabled exclusively by the owner's server assignment, fetched over mTLS.
$config = @{ server_url = $ServerUrl; ca_bundle = $ca; state_dir = $state;
    collection_enabled = $false; interval_seconds = 10 }
[IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
$previousPythonPath = $env:PYTHONPATH
try {
    $env:PYTHONPATH = $repo
    & $python -m sli_agent --config $configPath prepare
    if ($LASTEXITCODE -ne 0) { throw 'agent_dev_prepare_failed' }
    Write-Output 'Owner: approve the printed host UUID and public key fingerprint, then issue the one-time enrollment token through the owner API.'
    Read-Host 'Press Enter when the owner has approved the key and issued a token' | Out-Null
    # The Python CLI prompts with getpass; no token in arguments, config or logs.
    & $python -m sli_agent --config $configPath enroll
    if ($LASTEXITCODE -ne 0) { throw 'agent_dev_enrollment_failed' }
    Write-Output 'Owner: assign sli.workstations to this agent and enable its server plugin as described in docs/agent-enrollment.md. Until then only heartbeat runs. Ctrl+C stops the console run.'
    & $python -m sli_agent --config $configPath run
    if ($LASTEXITCODE -ne 0) { throw 'agent_dev_run_failed' }
} finally {
    $env:PYTHONPATH = $previousPythonPath
}
