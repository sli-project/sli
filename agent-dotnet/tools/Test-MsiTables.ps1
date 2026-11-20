param(
    [Parameter(Mandatory)][string]$Msi,
    [Parameter(Mandatory)][string]$PublishDirectory,
    [ValidatePattern('^\d+\.\d+\.\d+$')][string]$ExpectedVersion = '0.3.4'
)
$ErrorActionPreference = 'Stop'
# OpenDatabase mode 0 is read-only. This does not install, register or execute the package.
$installer = New-Object -ComObject WindowsInstaller.Installer
$database = $installer.OpenDatabase((Resolve-Path -LiteralPath $Msi).Path, 0)
$view = $database.OpenView('SELECT `Property`, `Value` FROM `Property`')
$null = $view.Execute()
$package = @{}
while ($null -ne ($entry = $view.Fetch())) { $package[$entry.StringData(1)] = $entry.StringData(2) }
$null = $view.Close()
if ($package['ProductVersion'] -ne $ExpectedVersion) { throw 'Unexpected MSI ProductVersion' }
if ($package['UpgradeCode'] -ne '{BE66EC86-AE25-4D3F-8C60-B191F3B0E20D}') { throw 'UpgradeCode must remain compatible with 0.2.0' }
$view = $database.OpenView('SELECT `Name`, `StartType`, `StartName` FROM `ServiceInstall`')
$null = $view.Execute()
$service = $view.Fetch()
if ($null -eq $service -or $service.StringData(1) -ne 'SLIAgentNet' -or $service.IntegerData(2) -ne 2 -or $service.StringData(3) -ne 'LocalSystem') { throw 'Unexpected service configuration' }
if ($null -ne $view.Fetch()) { throw 'MSI must install exactly one service' }
$null = $view.Close()
$view = $database.OpenView('SELECT `Name`, `Event`, `Wait`, `Component_` FROM `ServiceControl`')
$null = $view.Execute()
$control = $view.Fetch()
# MSI ServiceControl flags: start on install 1; stop on install/uninstall 2/32; delete on uninstall 128.
if ($null -eq $control -or $control.StringData(1) -ne 'SLIAgentNet' -or
    ($control.IntegerData(2) -band 163) -ne 163 -or ($control.IntegerData(2) -band 24) -ne 0 -or
    $control.IntegerData(3) -ne 1 -or $control.StringData(4) -ne 'AgentService') {
    throw 'Service must start on install and wait for stop before upgrade/uninstall deletion'
}
if ($null -ne $view.Fetch()) { throw 'Unexpected additional service control' }
$null = $view.Close()
$view = $database.OpenView('SELECT `Action`, `Condition`, `Sequence` FROM `InstallExecuteSequence`')
$null = $view.Execute()
$actions = @{}
while ($null -ne ($action = $view.Fetch())) {
    $actions[$action.StringData(1)] = @{ Condition = $action.StringData(2); Sequence = $action.IntegerData(3) }
}
$null = $view.Close()
foreach ($chain in @(
    @('StopServices', 'DeleteServices', 'RemoveFiles'),
    @('InstallInitialize', 'RemoveExistingProducts', 'ProcessComponents'),
    @('InstallFiles', 'InstallServices', 'StartServices', 'InstallFinalize')
)) {
    for ($i = 1; $i -lt $chain.Count; $i++) {
        if (-not $actions.ContainsKey($chain[$i - 1]) -or -not $actions.ContainsKey($chain[$i]) -or
            $actions[$chain[$i - 1]].Sequence -ge $actions[$chain[$i]].Sequence) {
            throw "Unsafe MSI action order: $($chain -join ' -> ')"
        }
    }
}
# Evaluate the compiled conditions with Windows Installer, rather than matching WiX source text.
# OpenPackage option 1 ignores the installed machine state; no installation actions are executed.
$session = $installer.OpenPackage((Resolve-Path -LiteralPath $Msi).Path, 1)
try {
$registrationActions = @('ValidateRegistrationFile', 'PrepareRegistrationData', 'RollbackRegistration', 'StageRegistration', 'CommitRegistration')
foreach ($scenario in @('fresh', 'upgrade', 'repair', 'uninstall', 'upgrade-removal')) {
    $session.Property('Installed') = $(if ($scenario -in @('repair', 'uninstall', 'upgrade-removal')) { '1' } else { '' })
    $session.Property('WIX_UPGRADE_DETECTED') = $(if ($scenario -eq 'upgrade') { '{00000000-0000-0000-0000-000000000001}' } else { '' })
    $session.Property('REINSTALL') = $(if ($scenario -eq 'repair') { 'ALL' } else { '' })
    $session.Property('REMOVE') = $(if ($scenario -in @('uninstall', 'upgrade-removal')) { 'ALL' } else { '' })
    $session.Property('UPGRADINGPRODUCTCODE') = $(if ($scenario -eq 'upgrade-removal') { '{00000000-0000-0000-0000-000000000002}' } else { '' })
    $session.Property('REGISTRATION_SNAPSHOT') = 'synthetic.snapshot'
    foreach ($name in $registrationActions) {
        if (-not $actions.ContainsKey($name)) { throw "Missing registration action: $name" }
        $expected = if ($scenario -eq 'fresh') { 1 } else { 0 }
        if ($session.EvaluateCondition($actions[$name].Condition) -ne $expected) {
            throw "Registration action $name must run only on fresh installation ($scenario)"
        }
    }
}
$view = $database.OpenView('SELECT `Condition` FROM `LaunchCondition`')
$null = $view.Execute()
$launchConditions = @()
while ($null -ne ($entry = $view.Fetch())) { $launchConditions += $entry.StringData(1) }
$null = $view.Close()
foreach ($scenario in @('missing-bootstrap', 'token', 'token-file', 'upgrade', 'repair', 'uninstall', 'downgrade')) {
    $session.Property('Installed') = $(if ($scenario -in @('repair', 'uninstall')) { '1' } else { '' })
    $session.Property('REMOVE') = $(if ($scenario -eq 'uninstall') { 'ALL' } else { '' })
    $session.Property('REINSTALL') = ''
    $session.Property('WIX_UPGRADE_DETECTED') = $(if ($scenario -eq 'upgrade') { '{00000000-0000-0000-0000-000000000001}' } else { '' })
    $session.Property('WIX_DOWNGRADE_DETECTED') = $(if ($scenario -eq 'downgrade') { '{00000000-0000-0000-0000-000000000002}' } else { '' })
    $session.Property('SAVED_SERVER_URL') = ''
    $session.Property('SERVER_URL') = $(if ($scenario -in @('token', 'token-file', 'downgrade')) { 'https://sli.example.test' } else { '' })
    $session.Property('ENROLL_TOKEN') = $(if ($scenario -in @('token', 'downgrade')) { 'synthetic-bootstrap' } else { '' })
    $session.Property('TOKEN_FILE') = $(if ($scenario -eq 'token-file') { 'synthetic.token' } else { '' })
    $results = @($launchConditions | ForEach-Object { $session.EvaluateCondition($_) })
    if ($results -contains 3) { throw "Invalid MSI launch condition ($scenario)" }
    $allowed = $results -notcontains 0
    if ($allowed -ne ($scenario -notin @('missing-bootstrap', 'downgrade'))) {
        throw "Unexpected MSI launch permission ($scenario)"
    }
}
}
finally { $null = [Runtime.InteropServices.Marshal]::FinalReleaseComObject($session) }
$view = $database.OpenView('SELECT `Component`, `Attributes`, `Condition` FROM `Component`')
$null = $view.Execute()
$components = @{}
while ($null -ne ($component = $view.Fetch())) {
    $components[$component.StringData(1)] = @{ Attributes = $component.IntegerData(2); Condition = $component.StringData(3) }
}
$null = $view.Close()
foreach ($name in @('PrivateState', 'Bootstrap', 'EnrollmentBootstrap')) {
    if (-not $components.ContainsKey($name) -or ($components[$name].Attributes -band 16) -eq 0) { throw "$name must survive upgrade/uninstall" }
}
if (($components['Bootstrap'].Attributes -band 128) -eq 0) { throw 'Connection settings must not be overwritten on reinstall' }
if (($components['EnrollmentBootstrap'].Attributes -band 128) -ne 0 -or $components['EnrollmentBootstrap'].Condition -ne 'ENROLL_TOKEN OR TOKEN_FILE') {
    throw 'An explicitly supplied fresh bootstrap must replace the previous token'
}
$view = $database.OpenView('SELECT `Name`, `Value`, `Component_` FROM `Registry` WHERE `Root` = 2 AND `Key` = ''SOFTWARE\SLI\AgentNet''')
$null = $view.Execute()
$settings = @{}
while ($null -ne ($setting = $view.Fetch())) { $settings[$setting.StringData(1)] = @{ Value = $setting.StringData(2); Component = $setting.StringData(3) } }
$null = $view.Close()
if ($settings['StateDirectory'].Value -ne '[AgentDataFolder]state' -or $settings['StateDirectory'].Component -ne 'PrivateState') { throw 'Machine-wide state directory missing' }
foreach ($name in @('EnrollmentToken', 'TokenFile')) {
    if ($settings[$name].Component -ne 'EnrollmentBootstrap') { throw 'Bootstrap refresh must be independent of preserved connection settings' }
}
$view = $database.OpenView('SELECT `Name` FROM `_Tables`')
$null = $view.Execute()
$tables = @()
while ($null -ne ($table = $view.Fetch())) {
    $tables += $table.StringData(1)
    if ($table.StringData(1) -in @('MsiServiceConfig', 'MsiServiceConfigFailureActions')) { throw 'Native MSI service configuration must be replaced with WiX Util' }
}
$null = $view.Close()
if ($tables -contains 'RemoveFile') {
    $view = $database.OpenView('SELECT `DirProperty` FROM `RemoveFile`')
    $null = $view.Execute()
    while ($null -ne ($removal = $view.Fetch())) {
        if ($removal.StringData(1) -in @('CommonAppDataFolder', 'SLIDataFolder', 'AgentDataFolder')) { throw 'MSI must not remove runtime identity data' }
    }
    $null = $view.Close()
}
$view = $database.OpenView('SELECT `Component_`, `NewService`, `FirstFailureActionType`, `SecondFailureActionType`, `ThirdFailureActionType`, `ResetPeriodInDays`, `RestartServiceDelayInSeconds` FROM `Wix4ServiceConfig` WHERE `ServiceName` = ''SLIAgentNet''')
$null = $view.Execute()
$recovery = $view.Fetch()
if ($null -eq $recovery -or $recovery.StringData(1) -ne 'AgentService' -or $recovery.IntegerData(2) -ne 1 -or
    $recovery.StringData(3) -ne 'restart' -or $recovery.StringData(4) -ne 'restart' -or $recovery.StringData(5) -ne 'restart' -or
    $recovery.IntegerData(6) -ne 1 -or $recovery.IntegerData(7) -ne 60) { throw 'Unexpected WiX Util service recovery configuration' }
$null = $view.Close()
$view = $database.OpenView('SELECT `Name`, `Value` FROM `Registry` WHERE `Root` = 2 AND `Key` = ''SYSTEM\CurrentControlSet\Services\SLIAgentNet'' AND `Component_` = ''AgentService''')
$null = $view.Execute()
$serviceSettings = @{}
while ($null -ne ($setting = $view.Fetch())) { $serviceSettings[$setting.StringData(1)] = $setting.StringData(2) }
$null = $view.Close()
if ($serviceSettings['DelayedAutoStart'] -ne '#1' -or $serviceSettings['FailureActionsOnNonCrashFailures'] -ne '#1') { throw 'Delayed auto-start and recovery on non-crash failures must be preserved' }
$view = $database.OpenView('SELECT `Value` FROM `Property` WHERE `Property` = ''MsiHiddenProperties''')
$null = $view.Execute()
$property = $view.Fetch()
if ($null -eq $property -or -not ($property.StringData(1).Split(';') -contains 'ENROLL_TOKEN')) { throw 'Enrollment property must be hidden' }
$null = $view.Close()
$view = $database.OpenView('SELECT `File` FROM `File`')
$null = $view.Execute()
$count = 0
while ($null -ne $view.Fetch()) { $count++ }
$null = $view.Close()
if ($count -ne @(Get-ChildItem -LiteralPath $PublishDirectory -File).Count) { throw 'MSI does not contain the complete published payload' }
$view = $database.OpenView('SELECT `UpgradeCode`, `VersionMax`, `Attributes` FROM `Upgrade` WHERE `ActionProperty` = ''WIX_UPGRADE_DETECTED''')
$null = $view.Execute()
$upgrade = $view.Fetch()
if ($null -eq $upgrade -or $upgrade.StringData(1) -ne $package['UpgradeCode'] -or $upgrade.StringData(2) -ne $ExpectedVersion) { throw 'Major upgrade must detect earlier versions' }
if (($upgrade.IntegerData(3) -band 514) -ne 0) { throw 'Earlier versions must be removed; same-version packages must not be major upgrades' }
$null = $view.Close()
foreach ($file in @((Join-Path $PSScriptRoot '../../README.md'), (Join-Path $PSScriptRoot '../INSTALL.md'))) {
    $document = [IO.File]::ReadAllText([IO.Path]::GetFullPath($file))
    $commands = @([regex]::Matches($document, '(?s)```powershell\s*(.*?)```') | Where-Object { $_.Groups[1].Value -match 'msiexec(?:\.exe)?' -and $_.Groups[1].Value -match '/i' })
    if (-not $commands.Count) { throw "No MSI install command in $file" }
    foreach ($command in $commands) {
        $properties = @([regex]::Matches($command.Groups[1].Value, '\b([A-Z][A-Z_]+)=') | ForEach-Object { $_.Groups[1].Value })
        foreach ($name in $properties) {
            if (-not $package.ContainsKey($name) -and $name -notin $package['SecureCustomProperties'].Split(';')) {
                throw "Unsupported documented MSI property: $name in $file"
            }
        }
    }
}
[PSCustomObject]@{ ProductVersion = $package['ProductVersion']; UpgradeCode = $package['UpgradeCode']; PayloadFiles = $count; Service = 'SLIAgentNet'; HiddenEnrollmentToken = $true; MajorUpgrade = $true; UtilServiceRecovery = $true; RestartDelaySeconds = 60; ResetPeriodDays = 1; DelayedAutoStart = $true; RecoveryOnNonCrashFailures = $true; NativeServiceConfig = $false; PersistentMachineState = $true; FreshBootstrapOnReinstall = $true }
