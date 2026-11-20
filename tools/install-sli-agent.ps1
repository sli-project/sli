# SLI agent Windows service installation and read-only rights diagnostics.
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$PythonExecutable,
    [Parameter(Mandatory)][string]$ConfigPath,
    [string]$UpdateTrustStore,
    [string]$InitialVersion,
    [ValidatePattern('^[a-z0-9][a-z0-9_-]{0,47}$')][string]$Instance,
    [switch]$Install,
    [switch]$AllowMissingRights
)
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'agent_install_requires_administrator'
}
if (-not (Test-Path -LiteralPath $PythonExecutable -PathType Leaf) -or
    -not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    throw 'agent_install_paths_invalid'
}
$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
if ($Instance -and $Instance -cnotmatch '^[a-z0-9][a-z0-9_-]{0,47}$') {
    throw 'agent_install_instance_invalid'
}
if (($Instance -and $config.instance_name -cne $Instance) -or
    (-not $Instance -and $null -ne $config.instance_name)) {
    throw 'agent_install_instance_mismatch'
}
$agentRoot = Join-Path $env:ProgramData 'SLI\Agent'
$serviceName = 'SLIAgent'
$statePath = $config.state_dir
$releaseRoot = $config.update_root
$targetConfig = Join-Path $agentRoot 'agent.json'
if ($Instance) {
    $hostId = [guid]::Empty
    if (-not [guid]::TryParse($config.host_id, [ref]$hostId)) { throw 'agent_install_host_id_invalid' }
    $serviceName = 'SLI-Agent-' + $Instance
    $instanceRoot = Join-Path (Join-Path $agentRoot 'instances') $serviceName
    $targetConfig = Join-Path $instanceRoot 'agent.json'
    # Config uses the base state path; Python derives the same instance subtree.
    if ([IO.Path]::GetFullPath($config.state_dir) -ne [IO.Path]::GetFullPath((Join-Path $agentRoot 'state'))) {
        throw 'agent_install_instance_state_path_invalid'
    }
    $statePath = Join-Path (Join-Path $config.state_dir 'instances') $serviceName
    if ($config.update_root) {
        $releaseRoot = Join-Path (Join-Path $config.update_root 'instances') $serviceName
    }
}
if ([IO.Path]::GetFullPath($ConfigPath) -ne [IO.Path]::GetFullPath($targetConfig)) {
    throw 'agent_install_requires_machine_config_path'
}
if ($config.collection_enabled -ne $false) { throw 'agent_install_collection_must_be_disabled' }
if (-not (Test-Path -LiteralPath $config.ca_bundle -PathType Leaf)) { throw 'agent_install_ca_missing' }
$choice = Read-Host 'Service account: 1 = LocalSystem, 2 = an operator-selected account'
if ($choice -notin @('1', '2')) { throw 'agent_install_account_choice_invalid' }
if ($choice -eq '2') {
    $account = Read-Host 'Chosen Windows service account (used only to resolve its SID)'
    try {
        $accountSid = ([Security.Principal.NTAccount]::new($account)).Translate([Security.Principal.SecurityIdentifier])
    } catch { throw 'agent_install_account_invalid' }
    # No password prompt, persistence or command-line secret. Configure the chosen
    # identity and Log on as a service through Windows Services after registration.
    Write-Output 'Configure the chosen account in Windows Services; restrict state and config ACLs to that account and SYSTEM. The service remains stopped.'
} else {
    $accountSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
}
if (-not (Test-Path -LiteralPath $statePath -PathType Container)) {
    throw 'agent_install_state_missing'
}
$stateAcl = Get-Acl -LiteralPath $statePath
if (-not $stateAcl.AreAccessRulesProtected) { throw 'agent_install_state_acl_must_be_protected' }
$hasAccountAccess = $false
foreach ($rule in $stateAcl.Access) {
    try { $ruleSid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]) }
    catch { throw 'agent_install_state_acl_invalid' }
    if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
        $ruleSid -ne $accountSid -and $ruleSid.Value -ne 'S-1-5-18') {
        throw 'agent_install_state_acl_unexpected_principal'
    }
    if ($ruleSid -eq $accountSid) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Deny) {
            throw 'agent_install_state_acl_denied'
        }
        $requiredRights = [Security.AccessControl.FileSystemRights]::Modify
        if (($rule.FileSystemRights -band $requiredRights) -eq $requiredRights) { $hasAccountAccess = $true }
    }
}
if (-not $hasAccountAccess) { throw 'agent_install_account_state_acl_missing' }
if ($config.update_root) {
    # Update signing trust is delivered out of band by the installing operator.
    # It is independent of both the TLS CA and the server's upload trust file.
    if (-not $config.update_trust_store -or -not $UpdateTrustStore -or -not $InitialVersion -or
        -not (Test-Path -LiteralPath $UpdateTrustStore -PathType Leaf)) {
        throw 'agent_install_update_trust_missing'
    }
    if (-not $config.service_python -or
        [IO.Path]::GetFullPath($config.service_python) -ne [IO.Path]::GetFullPath($PythonExecutable)) {
        throw 'agent_install_update_python_mismatch'
    }
    $initialDirectory = "$InitialVersion-initial"
    $initialRoot = Join-Path (Join-Path $releaseRoot 'versions') $initialDirectory
    if (-not (Test-Path -LiteralPath (Join-Path $initialRoot 'sli_agent\runtime.py') -PathType Leaf)) {
        throw 'agent_install_initial_release_missing'
    }
    $updateAcl = Get-Acl -LiteralPath $releaseRoot
    if (-not $updateAcl.AreAccessRulesProtected) { throw 'agent_install_update_acl_must_be_protected' }
    $updateAccess = $false
    foreach ($rule in $updateAcl.Access) {
        $ruleSid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier])
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            $ruleSid -ne $accountSid -and $ruleSid.Value -notin @('S-1-5-18', 'S-1-5-32-544')) {
            throw 'agent_install_update_acl_invalid'
        }
        if ($ruleSid -eq $accountSid -and $rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Modify) -eq [Security.AccessControl.FileSystemRights]::Modify) {
            $updateAccess = $true
        }
    }
    if (-not $updateAccess) { throw 'agent_install_account_update_acl_missing' }
    # Python validates disjoint state/update/trust paths before any copy.
    & $PythonExecutable -I -c 'import sys; from pathlib import Path; from sli_agent.config import AgentConfig; import sli_agent.launcher; c=AgentConfig.load(Path(sys.argv[1])); assert not Path(sli_agent.launcher.__file__).resolve().is_relative_to(c.update_root.resolve())' $ConfigPath
    if ($LASTEXITCODE -ne 0) { throw 'agent_install_update_config_invalid' }
}
if (-not $Install) {
    & $PythonExecutable -m sli_agent probe --config $ConfigPath --service-identity-sid $accountSid.Value
    if ($LASTEXITCODE -notin @(0, 2)) { throw 'agent_rights_probe_failed' }
    Write-Output 'Skeleton check complete. Use -Install after reviewing the account, paths and permissions.'
    return
}
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    throw 'agent_service_already_registered'
}
if ($PSCmdlet.ShouldProcess($serviceName, 'Register stopped Windows service')) {
    # Persist only the intended SID and explicit override, never a password.
    # Write without a UTF-8 BOM so the same JSON is readable by Python.
    $config | Add-Member -NotePropertyName service_identity_sid -NotePropertyValue $accountSid.Value -Force
    $config | Add-Member -NotePropertyName allow_missing_rights -NotePropertyValue ([bool]$AllowMissingRights) -Force
    [IO.File]::WriteAllText($ConfigPath, ($config | ConvertTo-Json -Depth 32), [Text.UTF8Encoding]::new($false))
    if ($config.update_root) {
        if (Test-Path -LiteralPath $config.update_trust_store) { throw 'agent_install_update_trust_exists' }
        Copy-Item -LiteralPath $UpdateTrustStore -Destination $config.update_trust_store
        $trustAcl = Get-Acl -LiteralPath $config.update_trust_store
        $trustAcl.SetAccessRuleProtection($true, $false)
        $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
        $adminSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
        foreach ($sid in @($systemSid, $adminSid)) {
            $trustAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'Allow'))
        }
        if ($accountSid -ne $systemSid) {
            $trustAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($accountSid, 'ReadAndExecute', 'Allow'))
        }
        Set-Acl -LiteralPath $config.update_trust_store -AclObject $trustAcl
        & $PythonExecutable -I -m sli_agent.updates --config $ConfigPath --version $InitialVersion --directory $initialDirectory
        if ($LASTEXITCODE -ne 0) { throw 'agent_install_update_initialization_failed' }
    }
    # Installed Python must expose this source package (PYTHONPATH is not inherited
    # from an interactive user's shell by SCM). pywin32 registration does not start
    # the service and stores no account password in agent files.
    $instanceArgs = @()
    if ($Instance) { $instanceArgs = @('--instance', $Instance) }
    if ($choice -eq '2') {
        # Leave the service disabled until its identity is set in Windows
        # Services, so it cannot accidentally start under LocalSystem.
        & $PythonExecutable -m sli_agent.service @instanceArgs --startup disabled install
    } else {
        & $PythonExecutable -m sli_agent.service @instanceArgs --startup manual install
    }
    if ($LASTEXITCODE -ne 0) { throw 'agent_service_registration_failed' }
    if ($config.update_root) {
        & $PythonExecutable -I -c 'import sys; from sli_agent.service import grant_restart_access; grant_restart_access(sys.argv[1], (sys.argv[2] or None) if len(sys.argv) > 2 else None)' $accountSid.Value "$Instance"
        if ($LASTEXITCODE -ne 0) { throw 'agent_install_restart_access_failed' }
    }
    # This process may be an administrator rather than the service account.
    # A mismatch is explicitly unverified; it never proves service read rights.
    $probeJson = & $PythonExecutable -m sli_agent probe --config $ConfigPath --json
    $probeExit = $LASTEXITCODE
    if ($probeExit -notin @(0, 2)) { throw 'agent_rights_probe_failed' }
    try { $probe = ($probeJson -join "`n") | ConvertFrom-Json }
    catch { throw 'agent_rights_probe_failed' }
    if ($probe.contract -ne 'sli.agent-rights-probe.v1' -or
        $null -eq $probe.ready -or $null -eq $probe.identity_verified -or -not $probe.checks) {
        throw 'agent_rights_probe_failed'
    }
    $probe.checks | Select-Object module_id, label, status, text_ru, remedy_ru | Format-Table -Wrap -AutoSize
    if (-not $probe.ready -and -not $AllowMissingRights) {
        Write-Output 'Обязательные права не подтверждены. Служба установлена и остановлена; повторите probe от имени службы. Override: -AllowMissingRights.'
        return
    }
    if (-not $probe.ready) {
        Write-Output 'Оператор разрешил запуск с неподтверждёнными правами. Служба повторит probe под своей учёткой; несовпадение учётки блокирует сбор.'
    }
    Write-Output 'Служба установлена и остановлена. Настройте выбранную учётку и права; для ручного запуска выполните:'
    Write-Output "sc.exe start $serviceName"
}
