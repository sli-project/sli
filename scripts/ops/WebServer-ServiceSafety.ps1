#requires -Version 5.1
# Function definitions only: safe to load in the synthetic test harness.
function New-SLIServiceElevationCommand {
    param([string]$ScriptPath, [System.Collections.IDictionary]$BoundParameters)
    # Serialize data, never interpolate caller-controlled text into executable code.
    $parameters = @{}
    foreach ($key in $BoundParameters.Keys) { $parameters[$key] = $BoundParameters[$key] }
    $payload = [System.Management.Automation.PSSerializer]::Serialize(@{
        ScriptPath = $ScriptPath
        Parameters = $parameters
    }, 5)
    $data = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload))
    $command = @'
try {
    $payload = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__PAYLOAD__'))
    $request = [System.Management.Automation.PSSerializer]::Deserialize($payload)
    $parameters = $request.Parameters
    & $request.ScriptPath @parameters
    if (-not $?) { exit 1 }
} catch { Write-Error $_; exit 1 }
'@
    [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command.Replace('__PAYLOAD__', $data)))
}

function Get-SLIWebListeners {
    # Query all connections so an empty port is not confused with a failed query.
    @(Get-NetTCPConnection -ErrorAction Stop | Where-Object { $_.LocalPort -eq 8080 -and $_.State -eq 'Listen' })
}

function Get-OwnedSLIWebService {
    param([string]$ProjectRoot)
    $services = @(Get-CimInstance -ClassName Win32_Service -Filter "Name='SLIWebServer'" -ErrorAction Stop)
    if ($services.Count -eq 0) { return $null }
    if ($services.Count -ne 1) { throw 'Ambiguous SLIWebServer service identity.' }
    $service = $services[0]
    $hostPath = Join-Path $ProjectRoot '.venv\pythonservice.exe'
    # Exact registered executable (no arguments) and Python class/root binding.
    if ($service.PathName -ine ('"' + $hostPath + '"') -and $service.PathName -ine $hostPath) {
        throw 'SLIWebServer is registered to a different executable; refusing to modify it.'
    }
    $class = Get-Item -LiteralPath 'HKLM:\System\CurrentControlSet\Services\SLIWebServer\PythonClass' -ErrorAction Stop
    if ($class.GetValue('') -cne 'server.service.sli_web_service.SLIWebServerService' -or
        ([string]$class.GetValue('PythonPath')).Split(';')[0] -ine $ProjectRoot) {
        throw 'Cannot verify SLIWebServer Python class and project root.'
    }
    if ($service.State -ne 'Stopped') {
        if ($service.State -ne 'Running' -or $service.ProcessId -le 4) {
            throw 'SLIWebServer is in an uncertain transition state; retry after it settles.'
        }
        $hostProcess = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$($service.ProcessId)" -ErrorAction Stop
        if (-not $hostProcess -or $hostProcess.ExecutablePath -ine $hostPath -or -not $hostProcess.CreationDate) {
            throw 'Cannot verify the SLIWebServer host process.'
        }
        $service | Add-Member -NotePropertyName HostCreationDate -NotePropertyValue $hostProcess.CreationDate
    }
    return $service
}

function Assert-SLIWebListenerOwnership {
    param($Service, $Listeners)
    foreach ($connection in $Listeners) {
        if (-not $Service -or $Service.State -ne 'Running') {
            throw 'Port 8080 has an unowned listener. Stop it with its own controller before installing.'
        }
        $processId = [long]$connection.OwningProcess
        $seen = @{}
        $childCreated = $null
        $owned = $false
        for ($depth = 0; $depth -lt 32 -and $processId -gt 4; $depth++) {
            if ($seen.ContainsKey($processId)) { break }
            $seen[$processId] = $true
            $process = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$processId" -ErrorAction Stop
            if (-not $process -or -not $process.CreationDate) { break }
            if ($null -ne $childCreated -and $process.CreationDate -gt $childCreated) { break }
            if ($processId -eq $Service.ProcessId) {
                $owned = $process.CreationDate -eq $Service.HostCreationDate
                break
            }
            $childCreated = $process.CreationDate
            $processId = [long]$process.ParentProcessId
        }
        if (-not $owned) { throw 'Port 8080 has a foreign or uncertain listener; no process was stopped.' }
    }
}

function Stop-OwnedSLIWebService {
    param([string]$ProjectRoot)
    $service = Get-OwnedSLIWebService -ProjectRoot $ProjectRoot
    Assert-SLIWebListenerOwnership -Service $service -Listeners @(Get-SLIWebListeners)
    if ($service -and $service.State -eq 'Running') {
        # Revalidate registration and creation identity immediately before SCM stop.
        $current = Get-OwnedSLIWebService -ProjectRoot $ProjectRoot
        if (-not $current -or $current.State -ne 'Running' -or
            $current.ProcessId -ne $service.ProcessId -or $current.HostCreationDate -ne $service.HostCreationDate) {
            throw 'SLIWebServer identity changed during preflight.'
        }
        Assert-SLIWebListenerOwnership -Service $current -Listeners @(Get-SLIWebListeners)
        Stop-Service -Name SLIWebServer -ErrorAction Stop
        $controller = Get-Service -Name SLIWebServer -ErrorAction Stop
        $controller.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    if (@(Get-SLIWebListeners).Count -ne 0) {
        throw 'Port 8080 is still occupied after service preflight; refusing installation.'
    }
}
