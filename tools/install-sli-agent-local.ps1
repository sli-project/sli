#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$MsiPath = 'C:\SLI-Build\artifacts\SLI-Agent-1.0.0-x64.msi',
    [string]$ServerUrl = '',
    [string]$Container = 'sli-api-1',
    [switch]$Upgrade,
    [ValidatePattern('^[a-fA-F0-9]{64}$')][string]$MsiSha256,
    [string]$PreviousMsiPath,
    [ValidatePattern('^[a-fA-F0-9]{64}$')][string]$PreviousMsiSha256
)

$ErrorActionPreference = 'Stop'

function ConvertTo-ProcessArgument([string]$Value) {
    if ($Value.Contains([char]0)) { throw 'invalid_process_argument' }
    # Windows CommandLineToArgvW quoting, including trailing backslashes.
    return '"' + [regex]::Replace([regex]::Replace($Value, '(\\*)"', '$1$1\"'), '(\\+)$', '$1$1') + '"'
}

function ConvertTo-MsiArgument([string]$Value) {
    if ($Value.Contains([char]0)) { throw 'invalid_process_argument' }
    # Windows Installer quotes property values, not switches or property names.
    # Its quoted strings preserve backslashes and double embedded quotes.
    if ($Value.StartsWith('/')) { return $Value }
    if ($Value -cmatch '^([A-Z_][A-Z0-9_]*)=(.*)$') {
        return $Matches[1] + '="' + $Matches[2].Replace('"', '""') + '"'
    }
    return '"' + $Value.Replace('"', '""') + '"'
}

function Invoke-LocalProcess([string]$FilePath, [string[]]$Arguments, [int]$TimeoutSeconds = 120) {
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $FilePath
    if ([IO.Path]::GetFileName($FilePath) -ieq 'msiexec.exe') {
        $info.Arguments = ($Arguments | ForEach-Object { ConvertTo-MsiArgument $_ }) -join ' '
    } else {
        $info.Arguments = ($Arguments | ForEach-Object { ConvertTo-ProcessArgument $_ }) -join ' '
    }
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $info
    try {
        if (-not $process.Start()) { throw 'process_start_failed' }
        # Capture both streams without a console pipeline, transcript or log.
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill()
            throw 'process_timeout'
        }
        # A descendant can keep inherited pipe handles open after this process exits.
        if (-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout, $stderr), 5000)) {
            throw 'process_timeout'
        }
        $null = $stderr.GetAwaiter().GetResult()
        return [pscustomobject]@{ ExitCode = $process.ExitCode; Stdout = $stdout.GetAwaiter().GetResult() }
    } finally { $process.Dispose() }
}

function Assert-LocalPath([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    if ($full.StartsWith('\\')) { throw 'local_path_required' }
    $current = $full
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            if ((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'reparse_path_rejected'
            }
        }
        $current = [IO.Path]::GetDirectoryName($current)
    }
    return $full
}

function New-RestrictedSecurity([bool]$Directory) {
    $type = if ($Directory) { 'System.Security.AccessControl.DirectorySecurity' } else { 'System.Security.AccessControl.FileSecurity' }
    $acl = New-Object $type
    $acl.SetAccessRuleProtection($true, $false)
    $admins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $acl.SetOwner($admins)
    foreach ($sidText in @('S-1-5-18', 'S-1-5-32-544')) {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($sidText)
        $inherit = if ($Directory) { [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit' } else { [Security.AccessControl.InheritanceFlags]::None }
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', $inherit, 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    return $acl
}

function Initialize-LocalAgentParent {
    $parent = Assert-LocalPath (Join-Path $env:ProgramData 'SLI')
    $acl = New-RestrictedSecurity $true
    $null = [IO.Directory]::CreateDirectory($parent, $acl)
    # MSI checks the CA and state ancestors, including this owner-created folder.
    # Set-Acl propagates changes to existing children. SetFileSecurityW applies
    # only to the parent, preserving the pilot archive's owner and entire DACL.
    if (-not ('SliLocalInstaller.NativeSecurity' -as [type])) {
        Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
namespace SliLocalInstaller {
    public static class NativeSecurity {
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetFileSecurityW(string path, uint information, byte[] descriptor);
        public static bool SetDirectorySecurity(string path, byte[] descriptor) {
            // OWNER | DACL | PROTECTED_DACL; no changes to existing children.
            return SetFileSecurityW(path, 0x80000005u, descriptor);
        }
    }
}
'@
    }
    $null = Assert-LocalPath $parent
    if (-not [SliLocalInstaller.NativeSecurity]::SetDirectorySecurity($parent, $acl.GetSecurityDescriptorBinaryForm())) {
        throw 'agent_parent_acl_failed'
    }
}

function Write-EnrollmentToken([string]$Path, [string]$Token) {
    if ($Token -cnotmatch '^[A-Za-z0-9_-]{43}$') { throw 'invalid_token_response' }
    $null = Assert-LocalPath $Path
    # CreateNew rejects existing files/hard links; restrictive ACL exists before bytes.
    $acl = New-RestrictedSecurity $false
    $stream = New-Object System.IO.FileStream($Path, [IO.FileMode]::CreateNew,
        [Security.AccessControl.FileSystemRights]::Write, [IO.FileShare]::None,
        4096, [IO.FileOptions]::WriteThrough, $acl)
    try {
        $bytes = [Text.Encoding]::ASCII.GetBytes($Token)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } catch {
        $stream.Dispose()
        Remove-Item -LiteralPath $Path -Force
        throw
    } finally { $stream.Dispose() }
}

function Test-LocalAdministrator {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Stop-LocalAgentService {
    $service = Get-Service -Name 'SLIAgent'
    try {
        if ($service.Status -notin @([ServiceProcess.ServiceControllerStatus]::Stopped, [ServiceProcess.ServiceControllerStatus]::StopPending)) { $service.Stop() }
        # A live cycle may finish several bounded network/LDAP reads before
        # observing the stop event. Keep the state untouched until SCM confirms.
        $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(180))
    } finally { $service.Dispose() }
}

function Start-LocalAgentService {
    $service = Get-Service -Name 'SLIAgent'
    try {
        if ($service.Status -ne [ServiceProcess.ServiceControllerStatus]::Running) { $service.Start() }
        $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
    } finally { $service.Dispose() }
}

function Get-SliRelatedMsiProducts {
    # Read-only Windows Installer inventory; Win32_Product triggers repairs.
    $installer = New-Object -ComObject WindowsInstaller.Installer
    try { return @($installer.RelatedProducts('{D6836D37-49FA-4AB6-BDFD-10B07ED51973}')) }
    finally { $null = [Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer) }
}

function Get-InstalledAgentMsi {
    $products = @(Get-SliRelatedMsiProducts)
    $key = 'HKLM:\SOFTWARE\SLI\Agent'
    $stored = if (Test-Path -LiteralPath $key) { Get-ItemProperty -LiteralPath $key } else { $null }
    if (-not $products.Count -and -not $stored) { return $null }
    # Early MSI builds stored ServiceAccount without ProductCode. The unique
    # related product supplies its code; a later registry marker must agree.
    if ($products.Count -ne 1 -or
        [string]$products[0] -notmatch '^\{[0-9a-fA-F-]{36}\}$' -or
        ($stored -and $stored.ProductCode -and $products[0] -ine $stored.ProductCode)) { throw 'agent_msi_inventory_mismatch' }
    $code = [Guid]::Parse($products[0])
    if ($code -eq [Guid]::Empty) { throw 'agent_msi_inventory_mismatch' }
    return $code.ToString('B').ToUpperInvariant()
}

function Get-AgentMsiProductCode([string]$Msi) {
    $installer = $null
    $database = $null
    $view = $null
    $record = $null
    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $database = $installer.OpenDatabase($Msi, 0)
        $view = $database.OpenView("SELECT ``Value`` FROM ``Property`` WHERE ``Property`` = 'ProductCode'")
        $null = $view.Execute()
        $record = $view.Fetch()
        $code = [Guid]::Parse([string]$record.StringData(1))
        if ($code -eq [Guid]::Empty) { throw 'agent_msi_inventory_mismatch' }
        return $code.ToString('B').ToUpperInvariant()
    } finally {
        foreach ($item in @($record, $view, $database, $installer)) {
            if ($null -ne $item) { $null = [Runtime.InteropServices.Marshal]::FinalReleaseComObject($item) }
        }
    }
}

function Get-AgentMsiMetadata([string]$Msi) {
    $installer = $null
    $database = $null
    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $database = $installer.OpenDatabase($Msi, 0)
        $values = @{}
        foreach ($name in @('ProductCode', 'UpgradeCode', 'ProductVersion', 'ProductName')) {
            $view = $null
            $record = $null
            try {
                $view = $database.OpenView("SELECT ``Value`` FROM ``Property`` WHERE ``Property`` = '$name'")
                $null = $view.Execute()
                $record = $view.Fetch()
                $values[$name] = [string]$record.StringData(1)
            } finally {
                foreach ($item in @($record, $view)) {
                    if ($null -ne $item) { $null = [Runtime.InteropServices.Marshal]::FinalReleaseComObject($item) }
                }
            }
        }
        if ($values.UpgradeCode -ine '{D6836D37-49FA-4AB6-BDFD-10B07ED51973}' -or
            $values.ProductName -cne 'SLI Agent' -or $values.ProductVersion -notmatch '^\d+\.\d+\.\d+$' -or
            [Guid]::Parse($values.ProductCode) -eq [Guid]::Empty) { throw 'agent_msi_inventory_mismatch' }
        return [pscustomobject]$values
    } finally {
        foreach ($item in @($database, $installer)) {
            if ($null -ne $item) { $null = [Runtime.InteropServices.Marshal]::FinalReleaseComObject($item) }
        }
    }
}

function Get-InstalledAgentMsiVersion([string]$Product) {
    $installer = New-Object -ComObject WindowsInstaller.Installer
    try { return [string]$installer.ProductInfo($Product, 'VersionString') }
    finally { $null = [Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer) }
}

function Assert-AgentServiceHealthy {
    Start-LocalAgentService
    $service = Get-Service -Name 'SLIAgent'
    try {
        # SCM can report Running before Python has initialized. Observe beyond
        # startup; an immediate crash must roll back even with MSI exit code 0.
        for ($attempt = 0; $attempt -lt 15; $attempt++) {
            Start-Sleep -Seconds 2
            $service.Refresh()
            if ($service.Status -ne [ServiceProcess.ServiceControllerStatus]::Running) { throw 'agent_upgrade_service_failed' }
        }
    } finally { $service.Dispose() }
}

function Get-AgentRegistrationHashes([string]$Root) {
    # Compare only immutable registration material; a running agent can advance
    # cursors and deliver buffered packets during the service health observation.
    $paths = @('agent.json', 'server-ca.pem', '.msi-owned', 'state\identity.json', 'state\identity-key.json', 'state\host.json')
    $paths += @(Get-ChildItem -LiteralPath (Join-Path $Root 'state') -Recurse -Force -File |
        Where-Object { $_.Name -in @('certificate.pem', 'key.pem') } |
        ForEach-Object { $_.FullName.Substring($Root.Length + 1) })
    $values = @{}
    foreach ($relative in $paths) {
        $path = Assert-LocalPath (Join-Path $Root $relative)
        if (Test-Path -LiteralPath $path -PathType Leaf) { $values[$relative] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash }
    }
    return $values
}

function Assert-AgentRegistrationHashes([string]$Root, [hashtable]$Expected) {
    $actual = Get-AgentRegistrationHashes $Root
    if ($actual.Count -ne $Expected.Count) { throw 'agent_upgrade_identity_changed' }
    foreach ($name in $Expected.Keys) {
        if ($actual[$name] -cne $Expected[$name]) { throw 'agent_upgrade_identity_changed' }
    }
}

function Invoke-RegisteredAgentUpgrade([string]$Msi, [string]$InstalledProduct) {
    if (-not $MsiSha256 -or -not $PreviousMsiPath -or -not $PreviousMsiSha256) { throw 'agent_upgrade_previous_msi_required' }
    $mutex = New-Object Threading.Mutex($false, 'Global\SLI-Agent-MSI-Upgrade')
    $locked = $false
    try {
        try { $locked = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $locked = $true }
        if (-not $locked) { throw 'agent_upgrade_busy' }
        $root = Assert-LocalPath (Join-Path $env:ProgramData 'SLI\Agent')
        $config = Get-Content -LiteralPath (Join-Path $root 'agent.json') -Raw | ConvertFrom-Json
        $url = [string]$config.server_url
        if ($ServerUrl -and $ServerUrl.TrimEnd('/') -ine $url.TrimEnd('/')) { throw 'installed_config_mismatch' }
        if (-not (Test-AgentEnrollmentState $root $url) -or $config.update_root -or
            (Test-Path -LiteralPath (Join-Path $root '.msi-pending'))) { throw 'agent_msi_state_unrecognized' }
        $installedVersion = Get-InstalledAgentMsiVersion $InstalledProduct
        # Stage complete packages with restrictive ACLs before stopping a service.
        # Windows Installer's LocalPackage is stripped of the embedded cabinet;
        # it cannot replace the previous full distribution for rollback.
        $work = Assert-LocalPath (Join-Path (Split-Path -Parent $root) ('Agent.upgrade-work-' + [Guid]::NewGuid().ToString('N')))
        $null = [IO.Directory]::CreateDirectory($work, (New-RestrictedSecurity $true))
        $targetPath = Join-Path $work 'target.msi'
        $previousPath = Join-Path $work 'previous.msi'
        Copy-Item -LiteralPath (Assert-LocalPath $Msi) -Destination $targetPath
        Copy-Item -LiteralPath (Assert-LocalPath $PreviousMsiPath) -Destination $previousPath
        foreach ($path in @($targetPath, $previousPath)) { Set-Acl -LiteralPath $path -AclObject (New-RestrictedSecurity $false) }
        if ((Get-FileHash -LiteralPath $targetPath -Algorithm SHA256).Hash -ine $MsiSha256 -or
            (Get-FileHash -LiteralPath $previousPath -Algorithm SHA256).Hash -ine $PreviousMsiSha256) { throw 'msi_hash_mismatch' }
        $target = Get-AgentMsiMetadata $targetPath
        $previous = Get-AgentMsiMetadata $previousPath
        if ($previous.ProductCode -ine $InstalledProduct -or $previous.ProductVersion -cne $installedVersion -or
            $target.ProductCode -ieq $InstalledProduct -or [version]$target.ProductVersion -le [version]$installedVersion) {
            throw 'agent_upgrade_version_invalid'
        }
        if ((Get-InstalledAgentMsi) -ine $InstalledProduct) { throw 'agent_msi_inventory_mismatch' }
        $snapshot = Assert-LocalPath (Join-Path (Split-Path -Parent $root) ('Agent.upgrade-' + [Guid]::NewGuid().ToString('N')))
        $exe = Join-Path $env:WINDIR 'System32\msiexec.exe'
        $stateMoved = $false
        try {
            Stop-LocalAgentService
            $null = Test-AgentEnrollmentState $root $url
            $hashes = Get-AgentRegistrationHashes $root
            # Hide state from legacy MSI RemoveAgent (which otherwise revokes and
            # erases it). Rename preserves the entire tree and its security.
            [IO.Directory]::Move($root, $snapshot)
            $stateMoved = $true
            $result = Invoke-LocalProcess $exe @('/i', $targetPath, '/qn', '/norestart', "RESTORE_STATE=$snapshot",
                'MSIRESTARTMANAGERCONTROL=Disable', '/L*v', (Join-Path $work 'upgrade.log')) 600
            if ($result.ExitCode -notin @(0, 3010)) { throw 'agent_upgrade_install_failed' }
            if ((Get-InstalledAgentMsi) -ine $target.ProductCode) { throw 'agent_msi_inventory_mismatch' }
            Assert-AgentRegistrationHashes $root $hashes
            Assert-AgentServiceHealthy
            Write-Host 'Агент обновлён; регистрация и состояние сохранены.'
            if ($result.ExitCode -eq 3010) { Write-Host 'Для завершения обновления Windows может потребоваться перезагрузка.' }
        } catch {
            if (-not $stateMoved) {
                Start-LocalAgentService
                throw
            }
            # Killing the msiexec client does not prove that its privileged
            # server transaction finished. Never race legacy cleanup by moving
            # identity back while that transaction could still be in progress.
            if ($_.Exception.Message -eq 'process_timeout') { throw 'agent_upgrade_transaction_pending' }
            # Prefer the live state if the new service advanced cursors or spooled
            # packets; rolling back binaries must not roll back durable data.
            try {
                $service = Get-Service -Name 'SLIAgent' -ErrorAction SilentlyContinue
                if ($service) { $service.Dispose(); Stop-LocalAgentService }
                if (Test-Path -LiteralPath $root) {
                    if (Test-Path -LiteralPath $snapshot) { throw 'agent_upgrade_state_ambiguous' }
                    Assert-NoReparseTree $root
                    [IO.Directory]::Move($root, $snapshot)
                }
                $current = Get-InstalledAgentMsi
                if ($current -and $current -ine $InstalledProduct) {
                    if ($current -ine $target.ProductCode) { throw 'agent_msi_inventory_mismatch' }
                    $remove = Invoke-LocalProcess $exe @('/x', $current, '/qn', '/norestart', 'PRESERVE_STATE=1',
                        '/L*v', (Join-Path $work 'rollback-remove.log')) 600
                    if ($remove.ExitCode -ne 0) { throw 'agent_upgrade_rollback_failed' }
                    $current = Get-InstalledAgentMsi
                }
                if ($current -eq $InstalledProduct) {
                    # MSI's transactional rollback retained the previous product.
                    [IO.Directory]::Move($snapshot, $root)
                    $restore = Invoke-LocalProcess $exe @('/fomus', $InstalledProduct, '/qn', '/norestart',
                        '/L*v', (Join-Path $work 'rollback-repair.log')) 600
                } elseif (-not $current) {
                    # The old MSI provisions only temporary, unenrolled state.
                    # There is no token and the preserved identity stays hidden.
                    $ca = Join-Path $snapshot 'server-ca.pem'
                    $caProperty = if (Test-Path -LiteralPath $ca) { "CA_FILE=$ca" } else { "CA_FINGERPRINT=$($config.ca_fingerprint)" }
                    $restore = Invoke-LocalProcess $exe @('/i', $previousPath, '/qn', '/norestart', "SERVER_URL=$url", $caProperty,
                        '/L*v', (Join-Path $work 'rollback-install.log')) 600
                    if ($restore.ExitCode -notin @(0, 3010)) { throw 'agent_upgrade_rollback_failed' }
                    Stop-LocalAgentService
                    $python = Join-Path $env:ProgramFiles 'SLI\Agent\python.exe'
                    if (Test-AgentEnrollmentState $root $url) { throw 'agent_upgrade_state_ambiguous' }
                    $cleanup = Invoke-LocalProcess $python @('-I', '-B', '-m', 'sli_agent.msi', 'remove') 120
                    if ($cleanup.ExitCode -ne 0 -or (Test-Path -LiteralPath $root)) { throw 'agent_upgrade_rollback_failed' }
                    [IO.Directory]::Move($snapshot, $root)
                } else { throw 'agent_upgrade_rollback_failed' }
                if ($restore.ExitCode -notin @(0, 3010) -or (Get-InstalledAgentMsi) -ine $InstalledProduct) { throw 'agent_upgrade_rollback_failed' }
                Assert-AgentRegistrationHashes $root $hashes
                Assert-AgentServiceHealthy
            } catch { throw 'agent_upgrade_rollback_failed' }
            throw 'agent_upgrade_rolled_back'
        }
    } finally {
        if ($locked) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
}

function Test-AgentEnrollmentState([string]$Root, [string]$Url) {
    $root = Assert-LocalPath $Root
    Assert-NoReparseTree $root
    $marker = Assert-LocalPath (Join-Path $root '.msi-owned')
    if (-not (Test-Path -LiteralPath $marker) -or
        [IO.File]::ReadAllText($marker) -cne 'sli-agent-msi-v1') { throw 'agent_msi_state_unrecognized' }
    $configPath = Assert-LocalPath (Join-Path $root 'agent.json')
    $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    $state = Assert-LocalPath (Join-Path $root 'state')
    # Only the MSI-owned default instance is eligible for automatic replacement.
    if (-not [IO.Path]::IsPathRooted([string]$config.state_dir) -or
        [IO.Path]::GetFullPath([string]$config.state_dir) -ine $state -or $config.instance_name -or
        $config.service_identity_sid -ne 'S-1-5-18' -or
        ([string]$config.server_url).TrimEnd('/') -ine $Url.TrimEnd('/')) { throw 'installed_config_mismatch' }
    if (-not (Test-Path -LiteralPath $state -PathType Container)) { throw 'agent_msi_state_unrecognized' }
    # identity-key.json/host.json are also created by prepare before enrollment.
    # Any identity file (even malformed) or orphan TLS certificate forbids deletion.
    $identity = Assert-LocalPath (Join-Path $state 'identity.json')
    if (Test-Path -LiteralPath $identity) { return $true }
    return @((Get-ChildItem -LiteralPath $state -Recurse -Force -File) |
        Where-Object { $_.Name -eq 'certificate.pem' }).Count -gt 0
}

function Invoke-AgentMsiInstall([string]$Msi, [string]$Url, [string]$CaPath, [string]$InstalledProduct) {
    $exe = Join-Path $env:WINDIR 'System32\msiexec.exe'
    $logRoot = [IO.Path]::GetDirectoryName($Msi)
    $root = Assert-LocalPath (Join-Path $env:ProgramData 'SLI\Agent')
    if ($InstalledProduct) {
        # Inspect before stopping a working agent, then recheck after it has stopped.
        $enrolled = Test-AgentEnrollmentState $root $Url
        $targetProduct = Get-AgentMsiProductCode $Msi
        if ($enrolled -and $targetProduct -ine $InstalledProduct) {
            Invoke-RegisteredAgentUpgrade $Msi $InstalledProduct
            return
        }
        Stop-LocalAgentService
        $enrolled = Test-AgentEnrollmentState $root $Url
        if ($enrolled) {
            if ($targetProduct -ine $InstalledProduct) {
                Start-LocalAgentService
                Invoke-RegisteredAgentUpgrade $Msi $InstalledProduct
                return
            }
            Write-Host 'Агент уже зарегистрирован. Восстанавливаем установленный MSI, сохраняя регистрацию.'
            $log = Assert-LocalPath (Join-Path $logRoot 'agent-repair.log')
            $repair = Invoke-LocalProcess $exe @('/fomus', $InstalledProduct, '/qn', '/norestart', '/L*v', $log) 600
            if ($repair.ExitCode -notin @(0, 3010)) { throw 'msi_repair_failed' }
            if ($repair.ExitCode -eq 3010) { Write-Host 'Для завершения восстановления Windows может потребоваться перезагрузка.' }
            return
        }
        Write-Host 'Прежний агент не зарегистрирован. Удаляем его MSI перед новой установкой.'
        $log = Assert-LocalPath (Join-Path $logRoot 'agent-remove.log')
        $remove = Invoke-LocalProcess $exe @('/x', $InstalledProduct, '/qn', '/norestart', '/L*v', $log) 600
        if ($remove.ExitCode -eq 3010) { throw 'msi_remove_reboot_required' }
        if ($remove.ExitCode -ne 0) { throw 'msi_remove_failed' }
        if (Get-InstalledAgentMsi) { throw 'msi_remove_incomplete' }
        if (Test-Path -LiteralPath $root) { throw 'msi_remove_incomplete' }
    } elseif (Test-Path -LiteralPath $root) {
        throw 'agent_msi_inventory_mismatch'
    }
    Write-Host 'Устанавливаем новый агент. Затем начнётся регистрация.'
    $log = Assert-LocalPath (Join-Path $logRoot 'agent-install.log')
    $install = Invoke-LocalProcess $exe @('/i', $Msi, '/qn', '/norestart', "SERVER_URL=$Url", "CA_FILE=$CaPath", '/L*v', $log) 600
    if ($install.ExitCode -notin @(0, 3010)) { throw 'msi_install_failed' }
    if ($install.ExitCode -eq 3010) { Write-Host 'Для завершения установки Windows может потребоваться перезагрузка.' }
}

function Assert-NoReparseTree([string]$Root) {
    $null = Assert-LocalPath $Root
    $pending = New-Object 'System.Collections.Generic.Stack[string]'
    $pending.Push($Root)
    while ($pending.Count) {
        $directory = $pending.Pop()
        foreach ($item in Get-ChildItem -LiteralPath $directory -Force) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'reparse_path_rejected' }
            if ($item.PSIsContainer) { $pending.Push($item.FullName) }
        }
    }
}

function Get-PilotAgentId([string]$Root, [string]$OriginalRoot) {
    $configPath = Assert-LocalPath (Join-Path $Root 'agent.json')
    $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    $state = [string]$config.state_dir
    if (-not [IO.Path]::IsPathRooted($state)) { throw 'invalid_pilot_state' }
    $state = [IO.Path]::GetFullPath($state)
    # A state directory inside the pilot tree moved along with the configuration.
    if ($Root -ne $OriginalRoot) {
        if ($state -ieq $OriginalRoot) { $state = $Root }
        elseif ($state.StartsWith($OriginalRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
            $state = Join-Path $Root $state.Substring($OriginalRoot.Length + 1)
        }
    }
    $identityPath = Assert-LocalPath (Join-Path $state 'identity.json')
    if (-not (Test-Path -LiteralPath $identityPath)) { return $null }
    $identity = Get-Content -LiteralPath $identityPath -Raw | ConvertFrom-Json
    $id = [Guid]::Parse([string]$identity.agent_id)
    if ($id -eq [Guid]::Empty) { throw 'invalid_pilot_state' }
    return $id.ToString()
}

function Move-PilotAgentState {
    $root = Assert-LocalPath (Join-Path $env:ProgramData 'SLI\Agent')
    if (Test-Path -LiteralPath $root) {
        $marker = Assert-LocalPath (Join-Path $root '.msi-owned')
        if (-not (Test-Path -LiteralPath $marker)) {
            Assert-NoReparseTree $root
            $pilotId = Get-PilotAgentId $root $root
            $archive = Assert-LocalPath ($root + '.pilot-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff') + '-' + [Guid]::NewGuid().ToString('N'))
            if (Test-Path -LiteralPath $archive) { throw 'pilot_archive_exists' }
            # Same-volume directory rename retains every file and its DACL.
            [IO.Directory]::Move($root, $archive)
            Write-Host "Каталог пилота сохранён: $archive"
            return $pilotId
        }
        if ([IO.File]::ReadAllText($marker) -cne 'sli-agent-msi-v1') { throw 'invalid_pilot_state' }
    }
    # Retry after an MSI/enrollment/revocation failure uses the preserved pilot.
    $parent = Split-Path -Parent $root
    if (Test-Path -LiteralPath $parent) {
        $archive = Get-ChildItem -LiteralPath $parent -Filter 'Agent.pilot-*' -Directory -Force | Sort-Object Name -Descending | Select-Object -First 1
        if ($archive) {
            Assert-NoReparseTree $archive.FullName
            return Get-PilotAgentId $archive.FullName $root
        }
    }
    return $null
}

function Invoke-ElevatedInstall([string]$PsExe, [string]$ScriptPath, [string]$Msi) {
    $resultPath = Assert-LocalPath (Join-Path ([IO.Path]::GetTempPath()) ('sli-install-' + [Guid]::NewGuid().ToString('N') + '.txt'))
    $acl = New-RestrictedSecurity $false
    $caller = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl.SetOwner($caller)
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($caller, 'FullControl', 'Allow')))
    $stream = New-Object System.IO.FileStream($resultPath, [IO.FileMode]::CreateNew,
        [Security.AccessControl.FileSystemRights]::Write, [IO.FileShare]::None,
        4096, [IO.FileOptions]::WriteThrough, $acl)
    $stream.Dispose()
    try {
        $command = ". '" + $ScriptPath.Replace("'", "''") + "' -MsiPath '" + $Msi.Replace("'", "''") + "' -ServerUrl '" + $ServerUrl.Replace("'", "''") + "' -Container '" + $Container.Replace("'", "''") + "'"
        if ($Upgrade) { $command += ' -Upgrade' }
        foreach ($entry in @(@('MsiSha256', $MsiSha256), @('PreviousMsiPath', $PreviousMsiPath), @('PreviousMsiSha256', $PreviousMsiSha256))) {
            if ($entry[1]) { $command += ' -' + $entry[0] + " '" + $entry[1].Replace("'", "''") + "'" }
        }
        $command += '; '
        # Relay only the installer's safe Write-Host messages to the original console.
        $command += '$result = @(Install-SliAgentLocal *>&1); $code = [int]$result[-1]; $messages = @($result | Where-Object { $_ -is [Management.Automation.InformationRecord] } | ForEach-Object { [string]$_.MessageData }); '
        $command += "[IO.File]::WriteAllLines((Assert-LocalPath '" + $resultPath.Replace("'", "''") + "'), [string[]]`$messages, [Text.Encoding]::UTF8); exit `$code"
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
        $child = Start-Process -FilePath $PsExe -Verb RunAs -WindowStyle Hidden -ArgumentList @('-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encoded) -PassThru
        try {
            # Cache the process handle on PS 5.1 so ExitCode survives process exit.
            $null = $child.Handle
            # Start-Process -Wait waits for all descendants. Their lifetime does
            # not define installation completion; wait only for this installer.
            $child.WaitForExit()
            foreach ($message in [IO.File]::ReadAllLines($resultPath, [Text.Encoding]::UTF8)) { Write-Host $message }
            return $child.ExitCode
        } finally { $child.Dispose() }
    } finally { Remove-Item -LiteralPath $resultPath -Force }
}

function Install-SliAgentLocal {
    $stage = 'проверка прав'
    $tokenPath = $null
    $tokenWritten = $false
    $caPath = $null
    $caWritten = $false
    $rawToken = $null
    try {
        $msi = Assert-LocalPath $MsiPath
        if (-not (Test-LocalAdministrator) -or -not [Environment]::Is64BitProcess) {
            $psExe = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
            if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {
                $psExe = Join-Path $env:WINDIR 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
            }
            if (-not [Environment]::Is64BitOperatingSystem) { throw 'x64_required' }
            return Invoke-ElevatedInstall $psExe $PSCommandPath $msi
        }

        $stage = 'проверка MSI'
        $expectedHash = if ($MsiSha256) { $MsiSha256 } else { 'afc08f33a706103be5280dc3daa04b4e3f2c841abc9910bba1a7ea62f5591dd1' }
        if ((Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash -ine $expectedHash) {
            throw 'msi_hash_mismatch'
        }
        if ($Upgrade) {
            $stage = 'обновление зарегистрированного агента'
            $installedProduct = Get-InstalledAgentMsi
            if (-not $installedProduct) { throw 'agent_msi_inventory_mismatch' }
            Invoke-RegisteredAgentUpgrade $msi $installedProduct
            return 0
        }
        $docker = (Get-Command docker.exe -CommandType Application).Source
        $stage = 'получение публичного CA локального сервера'
        $publicCode = @'
import json, os
from pathlib import Path
from urllib.parse import urlsplit
u = urlsplit(os.environ['SLI_HEALTH_URL'])
print(json.dumps({'server_url': u.scheme + '://' + u.netloc, 'ca': Path(os.environ['SLI_TLS_CA_FILE']).read_text(encoding='ascii')}))
'@
        $publicResult = Invoke-LocalProcess $docker @('exec', $Container, 'python', '-c', $publicCode) 30
        if ($publicResult.ExitCode -ne 0) { throw 'server_public_ca_failed' }
        $public = $publicResult.Stdout | ConvertFrom-Json
        $url = if ($ServerUrl) { $ServerUrl } else { [string]$public.server_url }
        $uri = [Uri]$url
        if (-not $uri.IsAbsoluteUri -or $uri.Scheme -ne 'https' -or $uri.UserInfo -or $uri.AbsolutePath -ne '/' -or $uri.Query -or $uri.Fragment) {
            throw 'invalid_server_url'
        }
        if ($public.ca -notmatch '-----BEGIN CERTIFICATE-----' -or $public.ca -match 'PRIVATE KEY') { throw 'invalid_public_ca' }

        $stage = 'проверка установленного MSI'
        $installedProduct = Get-InstalledAgentMsi
        if ($installedProduct) {
            $root = Assert-LocalPath (Join-Path $env:ProgramData 'SLI\Agent')
            $enrolled = Test-AgentEnrollmentState $root $url
            if ($enrolled -and (Get-AgentMsiProductCode $msi) -ine $installedProduct) {
                Invoke-RegisteredAgentUpgrade $msi $installedProduct
                return 0
            }
        }
        $stage = 'остановка пилотного задания'
        $task = Get-ScheduledTask -TaskName 'SLI Agent' -ErrorAction SilentlyContinue
        if ($task) {
            $task | Disable-ScheduledTask | Out-Null
            $task | Stop-ScheduledTask
            $stopWatch = [Diagnostics.Stopwatch]::StartNew()
            while ((Get-ScheduledTask -TaskName 'SLI Agent').State -eq 'Running') {
                if ($stopWatch.Elapsed.TotalSeconds -ge 30) { throw 'pilot_task_stop_timeout' }
                Start-Sleep -Milliseconds 200
            }
        }
        $stage = 'сохранение состояния пилота'
        $pilotId = Move-PilotAgentState
        $stage = 'защита родительского каталога агента'
        Initialize-LocalAgentParent
        $stage = 'установка MSI'
        $bootstrap = Assert-LocalPath (Join-Path $env:ProgramData 'SLI\LocalBootstrap')
        $null = [IO.Directory]::CreateDirectory($bootstrap, (New-RestrictedSecurity $true))
        Set-Acl -LiteralPath $bootstrap -AclObject (New-RestrictedSecurity $true)
        $caPath = Join-Path $bootstrap 'server-ca.pem'
        $null = Assert-LocalPath $caPath
        if (Test-Path -LiteralPath $caPath) { throw 'bootstrap_ca_already_exists' }
        [IO.File]::WriteAllText($caPath, $public.ca, [Text.Encoding]::ASCII)
        $caWritten = $true
        Invoke-AgentMsiInstall $msi $url $caPath $installedProduct

        $stage = 'подготовка identity агента'
        Stop-LocalAgentService
        $root = Assert-LocalPath (Join-Path $env:ProgramData 'SLI\Agent')
        $configPath = Join-Path $root 'agent.json'
        $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
        if ($config.service_identity_sid -ne 'S-1-5-18' -or $config.server_url.TrimEnd('/') -ne $url.TrimEnd('/')) {
            throw 'installed_config_mismatch'
        }
        $python = Join-Path $env:ProgramFiles 'SLI\Agent\python.exe'
        $prepared = Invoke-LocalProcess $python @('-I', '-B', '-m', 'sli_agent', '--config', $configPath, 'prepare') 30
        if ($prepared.ExitCode -ne 0) { throw 'agent_prepare_failed' }
        $identity = $prepared.Stdout | ConvertFrom-Json
        $hostId = [Guid]::Parse($identity.host_id).ToString()
        $keyFingerprint = [string]$identity.key_fingerprint
        if ($keyFingerprint -cnotmatch '^[0-9a-f]{64}$') { throw 'invalid_prepare_response' }
        $state = Assert-LocalPath ([string]$config.state_dir)
        $identityPath = Join-Path $state 'identity.json'
        $tokenPath = Join-Path $root 'enrollment.token'
        if (-not (Test-Path -LiteralPath $identityPath)) {
            $stage = 'выпуск одноразового токена с аудитом'
            $actor = [Security.Principal.WindowsIdentity]::GetCurrent().Name
            $issued = Invoke-LocalProcess $docker @('exec', $Container, 'python', '-m', 'server.sli.agents.issue_token', '--host-id', $hostId, '--key-fingerprint', $keyFingerprint, '--ttl', '900', '--actor', $actor) 30
            if ($issued.ExitCode -ne 0) { throw 'issue_token_failed' }
            $rawToken = $issued.Stdout.Trim()
            $issued = $null
            $stage = 'сохранение защищённого токена'
            Write-EnrollmentToken $tokenPath $rawToken
            $tokenWritten = $true
            $rawToken = $null
        }

        $stage = 'ожидание регистрации'
        Start-LocalAgentService
        $checkCode = @'
import sys
from server.sli.core.postgres_runtime_pipeline import connect
with connect() as conn, conn.cursor() as cur:
    cur.execute("select 1 from sli_agents a join sli_agent_certificates c on c.agent_id=a.id where a.host_id=%s and a.key_fingerprint=%s and a.status='active' and c.revoked_at is null and c.not_after>clock_timestamp() limit 1", (sys.argv[1], sys.argv[2]))
    print('registered' if cur.fetchone() else 'pending')
'@
        $watch = [Diagnostics.Stopwatch]::StartNew()
        $reason = 'таймаут регистрации; проверьте Docker, HTTPS и CA'
        while ($watch.Elapsed.TotalSeconds -lt 120) {
            if ((Get-Service -Name 'SLIAgent').Status -eq 'Stopped') {
                $reason = 'служба SLIAgent остановилась'
                break
            }
            if (Test-Path -LiteralPath $identityPath) {
                $remaining = [Math]::Max(1, [Math]::Min(10, [int](120 - $watch.Elapsed.TotalSeconds)))
                $check = Invoke-LocalProcess $docker @('exec', $Container, 'python', '-c', $checkCode, $hostId, $keyFingerprint) $remaining
                if ($check.ExitCode -eq 0 -and $check.Stdout.Trim() -ceq 'registered') {
                    if ($pilotId) {
                        $stage = 'отзыв старого пилота'
                        $actor = [Security.Principal.WindowsIdentity]::GetCurrent().Name
                        $revoked = Invoke-LocalProcess $docker @('exec', $Container, 'python', '-m', 'server.sli.agents.revoke_agent', '--agent-id', $pilotId, '--replacement-host-id', $hostId, '--replacement-key-fingerprint', $keyFingerprint, '--actor', $actor) 30
                        if ($revoked.ExitCode -ne 0 -or $revoked.Stdout.Trim() -cne 'revoked') { throw 'pilot_revoke_failed' }
                        Write-Host 'старый пилот отозван'
                    }
                    Write-Host "Агент зарегистрирован: $hostId"
                    return 0
                }
            }
            $statusPath = Join-Path $state 'status.json'
            if (Test-Path -LiteralPath $statusPath) {
                $status = Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json
                # Only known safe codes; never echo arbitrary content from files.
                if ($status.error_code -in @('bootstrap_rejected', 'bootstrap_expired', 'bootstrap_trust_failed', 'enrollment_failed')) {
                    $reason = 'регистрация отклонена: ' + $status.error_code + '; проверьте HTTPS/CA и повторите команду для нового токена'
                }
            }
            Start-Sleep -Seconds 2
        }
        Write-Host "Агент не зарегистрирован: $reason"
        return 1
    } catch {
        # Exception text may contain process output, paths or private input.
        $reasons = @{
            'msi_hash_mismatch' = 'SHA-256 MSI не совпадает с закреплённым значением'
            'server_public_ca_failed' = 'локальный сервер Docker не вернул публичный CA'
            'invalid_server_url' = 'требуется HTTPS origin без credentials, пути и query'
            'invalid_public_ca' = 'сервер не вернул публичный PEM CA'
            'bootstrap_ca_already_exists' = 'bootstrap-файл CA уже существует; проверьте его перед повтором'
            'msi_install_failed' = 'Windows Installer отклонил установку MSI'
            'msi_remove_failed' = 'Windows не смогла удалить прежний агент; новая установка не началась. Подробности в agent-remove.log'
            'msi_remove_reboot_required' = 'для удаления прежнего агента нужна перезагрузка Windows; перезагрузите ПК и повторите команду'
            'msi_remove_incomplete' = 'удаление прежнего агента не завершено; новая установка не началась. Подробности в agent-remove.log'
            'msi_repair_failed' = 'Windows не смогла восстановить установленный агент. Подробности в agent-repair.log'
            'agent_msi_inventory_mismatch' = 'не удалось однозначно определить установленный MSI агента; автоматическая замена остановлена'
            'agent_msi_state_unrecognized' = 'не удалось подтвердить состояние прежнего агента; его данные сохранены'
            'agent_upgrade_previous_msi_required' = 'для обновления укажите хэш нового MSI, прежний полный MSI и его хэш'
            'agent_upgrade_version_invalid' = 'нужны другой ProductCode, тот же UpgradeCode и более высокая версия; прежний MSI должен совпадать с установленным'
            'agent_upgrade_busy' = 'другое обновление агента уже выполняется'
            'agent_upgrade_rolled_back' = 'обновление не прошло проверку; прежний MSI восстановлен, служба работает, регистрация сохранена'
            'agent_upgrade_rollback_failed' = 'автоматический откат не завершён; защищённое состояние и оба MSI сохранены в ProgramData для восстановления'
            'agent_upgrade_transaction_pending' = 'Windows Installer не завершился за отведённое время; состояние и оба MSI сохранены. Перед восстановлением дождитесь завершения MSI-транзакции'
            'installed_config_mismatch' = 'существующая конфигурация не соответствует URL или LocalSystem'
            'agent_prepare_failed' = 'установленный Python не выполнил prepare'
            'issue_token_failed' = 'сервер не выпустил токен с аудитом; проверьте версию сервера и БД'
            'invalid_token_response' = 'сервер вернул некорректный ответ выпуска токена'
            'process_timeout' = 'истекло время ожидания процесса'
            'reparse_path_rejected' = 'обнаружен небезопасный reparse point'
            'agent_parent_acl_failed' = 'не удалось защитить родительский каталог агента; повторите запуск от администратора'
            'local_path_required' = 'требуется локальный путь'
            'x64_required' = 'требуется 64-разрядная Windows'
            'invalid_pilot_state' = 'состояние пилота не распознано; данные сохранены'
            'pilot_revoke_failed' = 'новый агент зарегистрирован, но сервер не подтвердил отзыв пилота; повторите запуск'
            'pilot_task_stop_timeout' = 'пилотное задание не остановилось; каталог не перенесён'
        }
        $reason = 'проверьте доступность Docker, MSI, защищённые пути и службу SLIAgent'
        if ($reasons.ContainsKey($_.Exception.Message)) { $reason = $reasons[$_.Exception.Message] }
        Write-Host "Установка не завершена: $stage; $reason."
        return 1
    } finally {
        $rawToken = $null
        if ($tokenWritten -and (Test-Path -LiteralPath $tokenPath)) { Remove-Item -LiteralPath $tokenPath -Force }
        if ($caWritten -and (Test-Path -LiteralPath $caPath)) { Remove-Item -LiteralPath $caPath -Force }
    }
}

# Dot-sourcing exposes functions for tests without installing anything.
if ($MyInvocation.InvocationName -ne '.') { exit (Install-SliAgentLocal) }
