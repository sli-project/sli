#requires -Version 5.1
[CmdletBinding()]
param(
    [bool]$Start = $true,
    [ValidateSet('auto', 'manual', 'disabled', 'delayed')]
    [string]$StartupType = "auto"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'WebServer-ServiceSafety.ps1')

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location -LiteralPath $ProjectRoot

$logDir = Join-Path $ProjectRoot "data\logs"
[System.IO.Directory]::CreateDirectory($logDir) | Out-Null
$logFile = Join-Path $logDir "service_install.log"

try {
    Start-Transcript -Path $logFile -Append -Force | Out-Null
} catch {}

try {
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  SLI Web Server - Регистрация и запуск службы Windows" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan

    # Elevation check
    $WindowsPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $WindowsPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "Запрос прав администратора для регистрации службы Windows..." -ForegroundColor Yellow
        $encodedCommand = New-SLIServiceElevationCommand -ScriptPath $PSCommandPath -BoundParameters $PSBoundParameters
        $argumentList = "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encodedCommand"
        $elevatedProcess = Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argumentList -Wait -PassThru
        exit $elevatedProcess.ExitCode
    }

    $Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
    $ServiceScript = Join-Path $ProjectRoot "server\service\sli_web_service.py"
    $EvidencePath = Join-Path $ProjectRoot "data\maintenance\web-server-service-install.json"

    if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
        throw "Project python virtual environment was not found at $Python"
    }
    if (-not (Test-Path -LiteralPath $ServiceScript -PathType Leaf)) {
        throw "Service script was not found at $ServiceScript"
    }

    # Refuse foreign/unknown listeners before any service or scheduled-task mutation.
    Stop-OwnedSLIWebService -ProjectRoot $ProjectRoot

    # 1. Disable legacy task scheduler task if still present
    try {
        $existingTask = Get-ScheduledTask -TaskName "SLI Web Server" -ErrorAction SilentlyContinue
        if ($existingTask) {
            Disable-ScheduledTask -TaskName "SLI Web Server" -ErrorAction SilentlyContinue | Out-Null
            Write-Host "Отключена устаревшая задача планировщика 'SLI Web Server'." -ForegroundColor Yellow
        }
    } catch {}

    # 3. Prepare Python DLLs and host executable in .venv root
    $pyBasePrefix = (& $Python -c "import sys; print(sys.base_prefix)").Trim()
    $venvSitePackages = Join-Path $ProjectRoot ".venv\Lib\site-packages"
    $win32Dir = Join-Path $venvSitePackages "win32"
    $win32Lib = Join-Path $win32Dir "lib"
    $baseLib = Join-Path $pyBasePrefix "Lib"
    $targetPythonService = Join-Path $ProjectRoot ".venv\pythonservice.exe"

    Write-Host "Копирование необходимых системных библиотек в корень .venv..." -ForegroundColor Cyan
    Copy-Item "$pyBasePrefix\python3*.dll" "$ProjectRoot\.venv\" -Force -ErrorAction SilentlyContinue
    Copy-Item "$win32Dir\pywintypes3*.dll" "$ProjectRoot\.venv\" -Force -ErrorAction SilentlyContinue
    Copy-Item "$win32Dir\pythoncom3*.dll" "$ProjectRoot\.venv\" -Force -ErrorAction SilentlyContinue

    if (Test-Path -LiteralPath (Join-Path $win32Dir "pythonservice.exe") -PathType Leaf) {
        Copy-Item (Join-Path $win32Dir "pythonservice.exe") $targetPythonService -Force -ErrorAction SilentlyContinue
    }

    # 4. Register or update Windows Service
    Write-Host "Регистрация службы Windows 'SLIWebServer'..." -ForegroundColor Cyan
    $existingSvc = Get-Service -Name "SLIWebServer" -ErrorAction SilentlyContinue
    if ($existingSvc) {
        & $Python $ServiceScript --startup $StartupType update
    } else {
        & $Python $ServiceScript --startup $StartupType install
    }

    if ($LASTEXITCODE -ne 0) { throw "Service registration failed with exit code $LASTEXITCODE" }

    # Configure Service Registry settings
    $svcRegPath = 'HKLM:\System\CurrentControlSet\Services\SLIWebServer'
    if (Test-Path -LiteralPath $svcRegPath) {
        Set-ItemProperty -Path $svcRegPath -Name 'ImagePath' -Value "`"$targetPythonService`"" -Type String

        $envVars = @(
            "PYTHONHOME=$pyBasePrefix",
            "PYTHONPATH=$ProjectRoot;$venvSitePackages;$win32Dir;$win32Lib;$baseLib"
        )
        Set-ItemProperty -Path $svcRegPath -Name 'Environment' -Value $envVars -Type MultiString

        $pythonClassKey = Join-Path $svcRegPath "PythonClass"
        if (-not (Test-Path -LiteralPath $pythonClassKey)) {
            New-Item -Path $pythonClassKey -Force | Out-Null
        }
        Set-ItemProperty -Path $pythonClassKey -Name '(default)' -Value "server.service.sli_web_service.SLIWebServerService" -Type String

        $pythonPathValue = "$ProjectRoot;$venvSitePackages;$win32Dir;$win32Lib;$baseLib"
        Set-ItemProperty -Path $pythonClassKey -Name 'PythonPath' -Value $pythonPathValue -Type String
    }

    # 5. Verify registration in Service Control Manager
    $service = Get-Service -Name "SLIWebServer" -ErrorAction Stop
    Write-Host "Служба успешно зарегистрирована: $($service.DisplayName) [Состояние: $($service.Status)]" -ForegroundColor Green

    $registration = Get-CimInstance -ClassName Win32_Service -Filter "Name='SLIWebServer'" -ErrorAction Stop
    $expectedStartMode = @{ auto = 'Auto'; delayed = 'Auto'; manual = 'Manual'; disabled = 'Disabled' }[$StartupType]
    if (-not $registration -or $registration.StartMode -ne $expectedStartMode) {
        throw "Service startup mode does not match requested $StartupType"
    }
    if ($StartupType -eq 'delayed' -and
        (Get-ItemPropertyValue -LiteralPath $svcRegPath -Name DelayedAutoStart -ErrorAction Stop) -ne 1) {
        throw 'Delayed automatic start was not applied.'
    }
    if (-not $Start -and $service.Status -ne 'Stopped') {
        throw 'Service must remain stopped when Start is false.'
    }

    # 6. Start service if requested
    if ($Start) {
        Write-Host "Запуск службы 'SLIWebServer'..." -ForegroundColor Cyan
        Start-Service -Name "SLIWebServer" -ErrorAction Stop
        $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
        $service.Refresh()
        if ($service.Status -ne 'Running') { throw 'Service did not reach Running state.' }

        Write-Host "Текущее состояние службы: $($service.Status)" -ForegroundColor Green

        # Verify health
        $HealthUrl = "https://127.0.0.1:8080/api/health"
        $maxAttempts = 15
        $healthOk = $false
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        for ($i = 1; $i -le $maxAttempts; $i++) {
            try {
                $wc = New-Object System.Net.WebClient
                $res = $wc.DownloadString($HealthUrl)
                if ($res -match "ad-log-reports" -or $res -match "ok") {
                    $healthOk = $true
                    Write-Host "Веб-сервер успешно отвечает на $HealthUrl (HTTP 200)" -ForegroundColor Green
                    break
                }
            } catch {}
            Start-Sleep -Seconds 1
        }

        if (-not $healthOk) {
            Write-Warning "Служба запущена, но эндпоинт $HealthUrl пока не ответил 200. Проверьте data\logs\sli_web_service.log"
        }
    }

    # 7. Write evidence
    $evidenceDir = Split-Path -Parent $EvidencePath
    [System.IO.Directory]::CreateDirectory($evidenceDir) | Out-Null
    $evidence = [ordered]@{
        status = "registered"
        service_name = "SLIWebServer"
        display_name = $service.DisplayName
        service_status = [string]$service.Status
        startup_type = $StartupType
        registered_at = [DateTimeOffset]::Now.ToString("o")
        session_zero_isolated = $true
        no_console_window = $true
    }
    $evidence | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $EvidencePath -Encoding UTF8
    Write-Host "Готово! Служба SLI Web Server зарегистрирована. Состояние: $($service.Status)." -ForegroundColor Green

} catch {
    Write-Error "Ошибка при установке службы: $_"
    throw $_
} finally {
    try {
        Stop-Transcript | Out-Null
    } catch {}
}
