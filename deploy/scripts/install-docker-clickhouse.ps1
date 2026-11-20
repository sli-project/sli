#requires -Version 5.1

[CmdletBinding()]
param(
    [string]$Root = 'D:\Docker',
    [string]$ClickHouseVersion = 'latest',
    [switch]$SkipPostgresCheck
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Step([string]$Message) {
    Write-Host "`n==> $Message" -ForegroundColor Cyan
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Administrator {
    if (Test-IsAdministrator) {
        return
    }

    if (-not $PSCommandPath) {
        throw 'Сохраните этот текст в .ps1-файл и запустите файл от имени администратора.'
    }

    Write-Host 'Перезапускаю скрипт с правами администратора...' -ForegroundColor Yellow
    $argumentList = @(
        '-NoProfile'
        '-ExecutionPolicy', 'Bypass'
        '-File', "`"$PSCommandPath`""
        '-Root', "`"$Root`""
        '-ClickHouseVersion', "`"$ClickHouseVersion`""
    )
    if ($SkipPostgresCheck) {
        $argumentList += '-SkipPostgresCheck'
    }
    $elevatedProcess = Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argumentList -Wait -PassThru
    exit $elevatedProcess.ExitCode
}

function Test-PostgresPresent {
    $service = Get-Service -Name 'postgresql*' -ErrorAction SilentlyContinue
    if ($service) {
        return $true
    }

    $process = Get-Process -Name 'postgres' -ErrorAction SilentlyContinue
    if ($process) {
        return $true
    }

    return $false
}

function Ensure-Wsl2Features {
    $featureNames = @(
        'Microsoft-Windows-Subsystem-Linux'
        'VirtualMachinePlatform'
    )
    $restartRequired = $false

    foreach ($featureName in $featureNames) {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName $featureName
        if ($feature.State -ne 'Enabled') {
            Write-Host "Включаю компонент Windows: $featureName" -ForegroundColor Yellow
            $result = Enable-WindowsOptionalFeature -Online -FeatureName $featureName -All -NoRestart
            if ($result.RestartNeeded) {
                $restartRequired = $true
            }
        }
    }

    if ($restartRequired) {
        throw 'Для WSL 2 требуется перезагрузка Windows. Перезагрузите компьютер и повторно запустите этот скрипт.'
    }
}

function Get-DockerCli {
    $command = Get-Command 'docker.exe' -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    $candidates = @(
        (Join-Path $Root 'DockerDesktop\resources\bin\docker.exe'),
        (Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin\docker.exe'),
        (Join-Path $env:LOCALAPPDATA 'Programs\Docker\Docker\resources\bin\docker.exe'),
        (Join-Path $env:LOCALAPPDATA 'Programs\Docker\resources\bin\docker.exe')
    )

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            $candidateDir = Split-Path -Parent $candidate
            $env:Path = "$candidateDir;$env:Path"
            return $candidate
        }
    }

    return $null
}

function Find-DockerDesktop {
    $candidates = @(
        (Join-Path $Root 'DockerDesktop\Docker Desktop.exe'),
        (Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'),
        (Join-Path $env:LOCALAPPDATA 'Programs\Docker\Docker\Docker Desktop.exe'),
        (Join-Path $env:LOCALAPPDATA 'Programs\DockerDesktop\Docker Desktop.exe')
    )

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    return $null
}

function Invoke-Docker([string[]]$Arguments) {
    $docker = Get-DockerCli
    if (-not $docker) {
        throw 'docker.exe не найден.'
    }

    & $docker @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Команда Docker завершилась с кодом ${LASTEXITCODE}: docker $($Arguments -join ' ')"
    }
}

function Wait-DockerEngine {
    param([int]$TimeoutSeconds = 300)

    $docker = Get-DockerCli
    if (-not $docker) {
        throw 'После установки docker.exe не найден. Перезапустите PowerShell и повторите скрипт.'
    }

    $end = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        & $docker info *> $null
        if ($LASTEXITCODE -eq 0) {
            return
        }
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $end)

    throw 'Docker Engine не запустился за 5 минут. Откройте Docker Desktop, примите лицензию и повторите скрипт.'
}

function Ensure-DockerDesktop {
    $docker = Get-DockerCli
    $desktop = Find-DockerDesktop
    if ($docker -and $desktop) {
        Write-Host "Docker Desktop уже найден: $desktop" -ForegroundColor Green
        return
    }

    Write-Step 'Скачивание Docker Desktop'
    $installer = Join-Path $Root 'Docker Desktop Installer.exe'
    New-Item -ItemType Directory -Path $Root -Force | Out-Null

    if (-not (Test-Path -LiteralPath $installer)) {
        $url = 'https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe'
        Invoke-WebRequest -Uri $url -OutFile $installer -UseBasicParsing
    }

    if ((Get-Item -LiteralPath $installer).Length -lt 50MB) {
        throw "Файл установщика Docker выглядит неполным: $installer"
    }

    Write-Step 'Установка Docker Desktop на D:'
    $installArguments = @(
        'install'
        "--installation-dir=$Root\DockerDesktop"
        "--wsl-default-data-root=$Root\wsl"
        '--backend=wsl-2'
    )
    $process = Start-Process -FilePath $installer -ArgumentList $installArguments -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "Установщик Docker завершился с кодом $($process.ExitCode)."
    }
}

function Ensure-ClickHouseCompose {
    param(
        [string]$ComposeDir,
        [string]$Version
    )

    $compose = Join-Path $ComposeDir 'docker-compose.yml'
    $envFile = Join-Path $ComposeDir '.env'
    $credentials = Join-Path $ComposeDir 'connection.txt'

    New-Item -ItemType Directory -Path $ComposeDir -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $ComposeDir 'data') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $ComposeDir 'logs') -Force | Out-Null

    if (-not (Test-Path -LiteralPath $compose)) {
        $bytes = New-Object byte[] 24
        [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
        $password = [Convert]::ToBase64String($bytes).Replace('+', 'A').Replace('/', 'B').Replace('=', '')

        @(
            "CLICKHOUSE_VERSION=$Version"
            'CLICKHOUSE_USER=default'
            "CLICKHOUSE_PASSWORD=$password"
            'CLICKHOUSE_DB=default'
        ) | Set-Content -LiteralPath $envFile -Encoding ASCII

        @"
services:
  clickhouse:
    image: clickhouse/clickhouse-server:`${CLICKHOUSE_VERSION}
    container_name: clickhouse
    restart: unless-stopped
    ulimits:
      nofile:
        soft: 262144
        hard: 262144
    ports:
      - "127.0.0.1:8123:8123"
      - "127.0.0.1:9000:9000"
    environment:
      CLICKHOUSE_USER: `${CLICKHOUSE_USER}
      CLICKHOUSE_PASSWORD: `${CLICKHOUSE_PASSWORD}
      CLICKHOUSE_DB: `${CLICKHOUSE_DB}
    volumes:
      - "${ComposeDir.Replace('\', '/')}/data:/var/lib/clickhouse"
      - "${ComposeDir.Replace('\', '/')}/logs:/var/log/clickhouse-server"
"@ | Set-Content -LiteralPath $compose -Encoding UTF8

        "ClickHouse user: default`nPassword: $password`nHTTP: http://localhost:8123`nNative: localhost:9000" |
            Set-Content -LiteralPath $credentials -Encoding UTF8
        attrib +h $envFile
        attrib +h $credentials
    }

    return @{ Compose = $compose; Env = $envFile; Credentials = $credentials }
}

Assert-Administrator

Write-Step 'Проверка компонентов WSL 2'
Ensure-Wsl2Features

Write-Step 'Проверка PostgreSQL'
$postgresPresent = if ($SkipPostgresCheck) { $false } else { Test-PostgresPresent }
if ($postgresPresent) {
    Write-Warning 'PostgreSQL уже обнаружен. Docker будет установлен при необходимости, но ClickHouse запускаться не будет.'
}

Ensure-DockerDesktop

$desktopPath = Find-DockerDesktop
if (-not $desktopPath) {
    throw 'Docker Desktop не найден после установки.'
}

Write-Step 'Запуск Docker Desktop'
Start-Process -FilePath $desktopPath | Out-Null
Wait-DockerEngine
Write-Host 'Docker Engine готов.' -ForegroundColor Green

if (-not $postgresPresent) {
    $dockerPostgres = & (Get-DockerCli) ps -a --format '{{.Image}} {{.Names}}' 2>$null |
        Select-String -Pattern '(?i)(^|[ :/])postgres([:@ ]|$)'
    if ($dockerPostgres) {
        $postgresPresent = $true
        Write-Warning 'В Docker уже найден контейнер PostgreSQL. ClickHouse запускаться не будет.'
    }
}

if ($postgresPresent) {
    Write-Host 'Работа завершена: ClickHouse пропущен, потому что PostgreSQL уже найден.' -ForegroundColor Yellow
    exit 0
}

Write-Step 'Развёртывание ClickHouse'
$clickhouseDir = Join-Path $Root 'clickhouse'
$files = Ensure-ClickHouseCompose -ComposeDir $clickhouseDir -Version $ClickHouseVersion

$existing = & (Get-DockerCli) ps -a --filter 'name=^clickhouse$' --format '{{.Names}}' 2>$null
if ($existing -and -not (Test-Path -LiteralPath $files.Compose)) {
    throw 'Контейнер clickhouse уже существует, но compose-файл отсутствует; остановка во избежание изменения существующей конфигурации.'
}

Invoke-Docker @('compose', '--env-file', $files.Env, '-f', $files.Compose, 'up', '-d')

$end = (Get-Date).AddMinutes(2)
do {
    try {
        $passwordLine = Select-String -LiteralPath $files.Env -Pattern '^CLICKHOUSE_PASSWORD=(.*)$'
        $password = $passwordLine.Matches.Groups[1].Value
        $result = & (Get-DockerCli) exec clickhouse clickhouse-client --user default --password $password --query 'SELECT 1' 2>$null
        if ($LASTEXITCODE -eq 0 -and $result -match '1') {
            Write-Host 'ClickHouse успешно запущен и отвечает на SELECT 1.' -ForegroundColor Green
            Write-Host "Данные: $clickhouseDir\data" -ForegroundColor Green
            Write-Host "Учётные данные: $($files.Credentials)" -ForegroundColor Green
            exit 0
        }
    } catch {
        # Контейнер может ещё запускаться; повторяем проверку.
    }
    Start-Sleep -Seconds 5
} while ((Get-Date) -lt $end)

Write-Host 'ClickHouse не подтвердил готовность. Последние логи контейнера:' -ForegroundColor Yellow
& (Get-DockerCli) logs --tail 100 clickhouse
throw 'Развёртывание ClickHouse не завершилось успешно.'
