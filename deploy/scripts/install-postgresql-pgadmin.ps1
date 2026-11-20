#requires -Version 5.1

[CmdletBinding()]
param(
    [int]$PostgreSQLMajor = 18,
    [int]$PostgreSQLPort = 5432,
    [string]$PostgreSQLRoot = 'D:\PostgreSQL',
    [string]$PgAdminRoot = 'D:\pgAdmin4',
    [string]$InstallerRoot = 'D:\Installers\PostgreSQL',
    [string]$PostgreSQLInstallerUrl,
    [string]$PgAdminInstallerUrl
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

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
        '-PostgreSQLMajor', $PostgreSQLMajor
        '-PostgreSQLPort', $PostgreSQLPort
        '-PostgreSQLRoot', "`"$PostgreSQLRoot`""
        '-PgAdminRoot', "`"$PgAdminRoot`""
        '-InstallerRoot', "`"$InstallerRoot`""
    )
    if ($PostgreSQLInstallerUrl) {
        $argumentList += @('-PostgreSQLInstallerUrl', "`"$PostgreSQLInstallerUrl`"")
    }
    if ($PgAdminInstallerUrl) {
        $argumentList += @('-PgAdminInstallerUrl', "`"$PgAdminInstallerUrl`"")
    }

    $elevatedProcess = Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argumentList -Wait -PassThru
    exit $elevatedProcess.ExitCode
}

function New-SafePassword([int]$Length = 28) {
    $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#%^_-'
    $bytes = New-Object byte[] $Length
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        $rng.Dispose()
    }

    $result = New-Object System.Text.StringBuilder
    foreach ($byte in $bytes) {
        [void]$result.Append($alphabet[$byte % $alphabet.Length])
    }
    return $result.ToString()
}

function Get-Page([string]$Url) {
    return (Invoke-WebRequest -Uri $Url -UseBasicParsing).Content
}

function Get-LatestPostgreSQLUrl {
    if ($PostgreSQLInstallerUrl) {
        return $PostgreSQLInstallerUrl
    }

    $page = Get-Page 'https://www.postgresql.org/download/windows/'
    $links = [regex]::Matches($page, 'https?://[^"\s<>]+\.exe') |
        ForEach-Object { $_.Value } |
        Where-Object { $_ -match '(?i)postgresql-\d+\.\d+-\d+-windows-x64\.exe' }

    $candidates = foreach ($link in ($links | Select-Object -Unique)) {
        if ($link -match '(?i)postgresql-(\d+\.\d+)-(\d+)-windows-x64\.exe') {
            [pscustomobject]@{
                Url = $link
                Major = [int]($Matches[1].Split('.')[0])
                Version = [version]$Matches[1]
                Build = [int]$Matches[2]
            }
        }
    }

    $selected = $candidates |
        Where-Object { $_.Major -eq $PostgreSQLMajor } |
        Sort-Object Version, Build -Descending |
        Select-Object -First 1

    if (-not $selected) {
        throw "На официальной странице не найден установщик PostgreSQL $PostgreSQLMajor. Передайте -PostgreSQLInstallerUrl вручную."
    }
    return $selected.Url
}

function Get-LatestPgAdminUrl {
    if ($PgAdminInstallerUrl) {
        return $PgAdminInstallerUrl
    }

    $page = Get-Page 'https://www.pgadmin.org/download/pgadmin-4-windows/'
    $links = [regex]::Matches($page, 'https?://[^"\s<>]+\.exe') |
        ForEach-Object { $_.Value } |
        Where-Object { $_ -match '(?i)pgadmin4-\d+(\.\d+)+-x64\.exe' }

    $candidates = foreach ($link in ($links | Select-Object -Unique)) {
        if ($link -match '(?i)pgadmin4-(\d+(?:\.\d+)+)-x64\.exe') {
            [pscustomobject]@{
                Url = $link
                Version = [version]$Matches[1]
            }
        }
    }

    $selected = $candidates | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $selected) {
        throw 'На официальной странице не найден установщик pgAdmin 4. Передайте -PgAdminInstallerUrl вручную.'
    }
    return $selected.Url
}

function Download-Installer([string]$Url, [string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Host "Скачиваю $Url"
        Invoke-WebRequest -Uri $Url -OutFile $Path -UseBasicParsing
    }

    $file = Get-Item -LiteralPath $Path
    if ($file.Length -lt 10MB) {
        throw "Файл установщика выглядит неполным: $Path"
    }

    $signature = Get-AuthenticodeSignature -FilePath $Path
    if ($signature.Status -ne 'Valid') {
        throw "Проверка цифровой подписи не пройдена для ${Path}: $($signature.Status)"
    }
}

function Find-PostgreSQLService {
    return Get-Service -Name 'postgresql*' -ErrorAction SilentlyContinue |
        Sort-Object Name |
        Select-Object -First 1
}

function Get-PostgreSQLBin {
    $service = Find-PostgreSQLService
    if ($service) {
        $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)"
        $imagePath = (Get-ItemProperty -Path $serviceKey -Name ImagePath -ErrorAction SilentlyContinue).ImagePath
        if ($imagePath -match '^(?:"(?<path>[^"]+)|(?<path>[^ ]+))') {
            $postgresExe = $Matches.path
            if ($postgresExe -match '\\bin\\postgres\.exe$') {
                return (Split-Path -Parent $postgresExe)
            }
        }
    }

    $candidate = Get-ChildItem -LiteralPath $PostgreSQLRoot -Filter 'psql.exe' -File -Recurse -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($candidate) {
        return $candidate.DirectoryName
    }
    return $null
}

function Wait-ForPostgreSQL([string]$BinDir) {
    $pgIsReady = Join-Path $BinDir 'pg_isready.exe'
    if (-not (Test-Path -LiteralPath $pgIsReady)) {
        throw "pg_isready.exe не найден в $BinDir"
    }

    $deadline = (Get-Date).AddMinutes(2)
    do {
        & $pgIsReady -h 127.0.0.1 -p $PostgreSQLPort *> $null
        if ($LASTEXITCODE -eq 0) {
            return
        }
        Start-Sleep -Seconds 3
    } while ((Get-Date) -lt $deadline)

    throw "PostgreSQL не начал отвечать на порту $PostgreSQLPort."
}

function Add-PostgreSQLToSystemPath([string]$BinDir) {
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $parts = @($machinePath -split ';' | Where-Object { $_ })
    if ($parts -notcontains $BinDir) {
        [Environment]::SetEnvironmentVariable('Path', (($parts + $BinDir) -join ';'), 'Machine')
    }
    $env:Path = "$BinDir;$env:Path"
}

function Install-PostgreSQL {
    $existingService = Find-PostgreSQLService
    $binDir = Get-PostgreSQLBin
    if ($existingService -and $binDir) {
        Write-Host "PostgreSQL уже установлен: служба $($existingService.Name)" -ForegroundColor Green
        return @{ BinDir = $binDir; Password = $null; Installed = $false }
    }

    $installerUrl = Get-LatestPostgreSQLUrl
    $installerPath = Join-Path $InstallerRoot 'postgresql-installer.exe'
    Download-Installer -Url $installerUrl -Path $installerPath

    $versionRoot = Join-Path $PostgreSQLRoot ([string]$PostgreSQLMajor)
    $dataDir = Join-Path $PostgreSQLRoot 'data'
    $password = New-SafePassword
    New-Item -ItemType Directory -Path $versionRoot,$dataDir -Force | Out-Null

    Write-Step "Установка PostgreSQL $PostgreSQLMajor на D:"
    $arguments = @(
        '--mode', 'unattended'
        '--unattendedmodeui', 'none'
        '--prefix', $versionRoot
        '--datadir', $dataDir
        '--serverport', [string]$PostgreSQLPort
        '--superaccount', 'postgres'
        '--superpassword', $password
        '--serviceaccount', 'postgres'
        '--servicepassword', $password
        '--enable-components', 'server,commandlinetools'
        '--create_shortcuts', '0'
    )
    $process = Start-Process -FilePath $installerPath -ArgumentList $arguments -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "Установщик PostgreSQL завершился с кодом $($process.ExitCode)."
    }

    $binDir = Join-Path $versionRoot 'bin'
    if (-not (Test-Path -LiteralPath (Join-Path $binDir 'psql.exe'))) {
        throw "После установки PostgreSQL не найден: $binDir"
    }

    Add-PostgreSQLToSystemPath -BinDir $binDir
    return @{ BinDir = $binDir; Password = $password; Installed = $true }
}

function Install-PgAdmin {
    $existing = @(
        (Join-Path $PgAdminRoot 'pgAdmin4.exe'),
        (Join-Path $env:ProgramFiles 'pgAdmin 4\v9\pgAdmin4.exe'),
        (Join-Path $env:ProgramFiles 'pgAdmin 4\v8\pgAdmin4.exe')
    ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

    if ($existing) {
        Write-Host "pgAdmin 4 уже установлен: $existing" -ForegroundColor Green
        return $existing
    }

    $installerUrl = Get-LatestPgAdminUrl
    $installerPath = Join-Path $InstallerRoot 'pgadmin4-installer.exe'
    Download-Installer -Url $installerUrl -Path $installerPath

    Write-Step 'Установка pgAdmin 4 на D:'
    $arguments = @('/S', "/D=$PgAdminRoot")
    $process = Start-Process -FilePath $installerPath -ArgumentList $arguments -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "Установщик pgAdmin 4 завершился с кодом $($process.ExitCode)."
    }

    $installed = Get-ChildItem -LiteralPath $PgAdminRoot -Filter 'pgAdmin4.exe' -File -Recurse -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not $installed) {
        throw "После установки pgAdmin 4 не найден в $PgAdminRoot. Возможно, установщик не поддержал параметр /D."
    }
    return $installed.FullName
}

Assert-Administrator
New-Item -ItemType Directory -Path $InstallerRoot -Force | Out-Null

Write-Step 'Установка нативного PostgreSQL'
$postgres = Install-PostgreSQL
$binDir = $postgres.BinDir
Add-PostgreSQLToSystemPath -BinDir $binDir

$service = Find-PostgreSQLService
if (-not $service) {
    throw 'Служба PostgreSQL не найдена после установки.'
}
if ($service.Status -ne 'Running') {
    Start-Service -Name $service.Name
}
Wait-ForPostgreSQL -BinDir $binDir

Write-Step 'Установка нативного pgAdmin 4'
$pgAdminExe = Install-PgAdmin

$credentialsPath = Join-Path $PostgreSQLRoot 'connection.txt'
if (-not (Test-Path -LiteralPath $credentialsPath)) {
    $passwordText = if ($postgres.Password) { $postgres.Password } else { '<пароль существующей установки PostgreSQL>' }
    @(
        'PostgreSQL native Windows installation'
        'Host=127.0.0.1'
        "Port=$PostgreSQLPort"
        'Database=postgres'
        'User=postgres'
        "Password=$passwordText"
        "pgAdmin=$pgAdminExe"
    ) | Set-Content -LiteralPath $credentialsPath -Encoding UTF8
    attrib +h $credentialsPath
}

Write-Host "`nГотово." -ForegroundColor Green
Write-Host "PostgreSQL: 127.0.0.1:$PostgreSQLPort" -ForegroundColor Green
Write-Host "pgAdmin: $pgAdminExe" -ForegroundColor Green
Write-Host "Данные PostgreSQL: $PostgreSQLRoot\data" -ForegroundColor Green
Write-Host "Подключение: $credentialsPath" -ForegroundColor Green
