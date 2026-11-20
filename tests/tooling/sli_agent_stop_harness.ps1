#Requires -Version 5.1
param([string]$SourcePath)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.ServiceProcess
. $SourcePath
$script:events = New-Object Collections.Generic.List[string]
function Get-Service {
    $service=[pscustomobject]@{Status=$script:initial}
    $service|Add-Member ScriptMethod Stop {$script:events.Add('stop')}
    $service|Add-Member ScriptMethod WaitForStatus {
        param($target,$timeout)
        if($target -ne [ServiceProcess.ServiceControllerStatus]::Stopped -or $timeout.TotalSeconds -lt 65 -or $timeout.TotalSeconds -gt 180){throw 'bounded_stop_wait_invalid'}
        $script:events.Add('wait')
        if($script:timeout){throw 'synthetic_stop_timeout'}
    }
    $service|Add-Member ScriptMethod Dispose {$script:events.Add('dispose')}
    return $service
}
foreach($status in @('Running','StopPending','Stopped')){
    $script:initial=[ServiceProcess.ServiceControllerStatus]$status
    $script:timeout=$false;$script:events.Clear()
    Stop-LocalAgentService
    $expected=if($status -eq 'Running'){'stop,wait,dispose'}else{'wait,dispose'}
    if(($script:events -join ',') -ne $expected){throw 'stop_transition_invalid'}
}
$script:initial=[ServiceProcess.ServiceControllerStatus]::StopPending
$script:timeout=$true;$script:events.Clear()
try{Stop-LocalAgentService;throw 'timeout_not_propagated'}catch{if($_.Exception.Message -notmatch 'synthetic_stop_timeout'){throw}}
if(($script:events -join ',') -ne 'wait,dispose'){throw 'timeout_disposal_invalid'}
'PowerShell 5.1 stop checks passed'
