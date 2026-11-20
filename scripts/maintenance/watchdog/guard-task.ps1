param([ValidateSet('Install', 'Uninstall', 'Validate')][string]$Action = 'Install')
$ErrorActionPreference = 'Stop'
$taskName = 'SLI Watchdog Guard'
$stage = 'preflight'
try {
    if ($Action -eq 'Uninstall') {
        Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false
        Write-Output 'SLI Watchdog Guard removed.'
        exit 0
    }
    $bash = (Get-Command bash.exe).Source
    foreach ($file in @('guard.sh', 'launch.vbs', 'watchdog_pipeline.py', 'snapshot.ps1', 'processes.ps1', 'repair-identity.ps1')) {
        if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot $file) -PathType Leaf)) { throw 'Missing guard file.' }
    }
    $arguments = '//B //Nologo "{0}" "{1}" "{2}"' -f (Join-Path $PSScriptRoot 'launch.vbs'), $bash, (Join-Path $PSScriptRoot 'guard.sh')
    $exec = [Security.SecurityElement]::Escape((Join-Path $env:SystemRoot 'System32/wscript.exe'))
    $arguments = [Security.SecurityElement]::Escape($arguments)
    $directory = [Security.SecurityElement]::Escape($PSScriptRoot)
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $start = (Get-Date).AddMinutes(15).ToString('yyyy-MM-ddTHH:mm:ss')
    $xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><TimeTrigger><Repetition><Interval>PT15M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition><StartBoundary>$start</StartBoundary><Enabled>true</Enabled></TimeTrigger></Triggers>
  <Principals><Principal id="CurrentUser"><UserId>$sid</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><Enabled>true</Enabled><Hidden>true</Hidden><ExecutionTimeLimit>PT3M</ExecutionTimeLimit></Settings>
  <Actions Context="CurrentUser"><Exec><Command>$exec</Command><Arguments>$arguments</Arguments><WorkingDirectory>$directory</WorkingDirectory></Exec></Actions>
</Task>
"@
    $scheduler = New-Object -ComObject 'Schedule.Service'
    $stage = 'validate XML'
    $scheduler.Connect()
    $null = $scheduler.GetFolder('\').RegisterTask($taskName, $xml, 1, $null, $null, 3, $null)
    if ($Action -eq 'Validate') { Write-Output 'Guard XML validated; no registration.'; exit 0 }
    $stage = 'register task'
    $null = Register-ScheduledTask -TaskName $taskName -TaskPath '\' -Xml $xml -Force
    $stage = 'readback'
    [xml]$installed = Export-ScheduledTask -TaskName $taskName
    $registered = Get-ScheduledTask -TaskName $taskName
    $ns = [Xml.XmlNamespaceManager]::new($installed.NameTable)
    $ns.AddNamespace('t', 'http://schemas.microsoft.com/windows/2004/02/mit/task')
    # Scheduler omits XML elements equal to their defaults (including network=false).
    if ($installed.SelectSingleNode('//t:Interval', $ns).InnerText -ne 'PT15M' -or $registered.Settings.RunOnlyIfNetworkAvailable -or -not $registered.Settings.Hidden -or [int]$registered.Principal.RunLevel -ne 0 -or [int]$registered.Principal.LogonType -ne 3) { throw 'Guard readback mismatch.' }
    Write-Output 'SLI Watchdog Guard installed and read back: 15 minutes, hidden, offline.'
} catch {
    Write-Output ('Guard task {0} failed: {1}, HRESULT=0x{2:X8}.' -f $stage, $_.Exception.GetType().Name, $_.Exception.HResult)
    exit 1
}
