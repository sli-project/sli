<#
.SYNOPSIS
    Полный файловый бэкап проекта БЕЗ базы данных.

.DESCRIPTION
    Копирует рабочее дерево проекта (включая .git) во внешний timestamped каталог.
    PostgreSQL не затрагивается: подключения не открываются, pg_dump не вызывается,
    runtime не останавливается. Это файловый снимок исходников, конфигурации,
    миграций, artifacts и истории Git.

    Исключается только регенерируемое и заведомо нечитаемое:
      .venv          - пересоздаётся из requirements.txt
      node_modules   - пересоздаётся из lock-файла
      __pycache__    - байткод

    Каждое исключение записывается в манифест честно, а не объявляется отсутствующим.

.PARAMETER ValidateOnly
    Ничего не копирует. Показывает источник, назначение, исключения и
    предполагаемый объём. Используйте перед реальным запуском.

.EXAMPLE
    .\scripts\ops\Backup-ProjectSource-NoDb.ps1 -ValidateOnly
    .\scripts\ops\Backup-ProjectSource-NoDb.ps1
#>

[CmdletBinding()]
param(
    [string]$ProjectRoot  = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),
    [string]$BackupRoot   = (Join-Path (Split-Path -Parent $ProjectRoot) ((Split-Path -Leaf $ProjectRoot) + '_backup')),
    [switch]$ValidateOnly
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Test-SourceBackupContainment {
    param([string]$SourcePath, [string]$DestinationPath)

    # Lexical Windows paths only: GetFullPath collapses '..' and separators,
    # but does not resolve junction/symlink aliases in existing path components.
    $separators = [char[]]@([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $source = [IO.Path]::GetFullPath($SourcePath).TrimEnd($separators)
    $destination = [IO.Path]::GetFullPath($DestinationPath).TrimEnd($separators)
    $comparison = [StringComparison]::OrdinalIgnoreCase
    return ($destination.Equals($source, $comparison) -or
        $destination.StartsWith($source + [IO.Path]::DirectorySeparatorChar, $comparison))
}

# --- Абсолютные пути до любого Set-Location (правило forgtp) ---------------
$ProjectRoot = (Resolve-Path -LiteralPath $ProjectRoot).Path
$backupProvider = $null
$backupDrive = $null
$BackupRoot  = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($BackupRoot, [ref]$backupProvider, [ref]$backupDrive)
if ($backupProvider.Name -ne "FileSystem") {
    throw "BackupRoot must use the FileSystem provider."
}
$stamp       = Get-Date -Format "yyyyMMdd_HHmmss"
$dest        = [IO.Path]::GetFullPath((Join-Path $BackupRoot $stamp))

$excludeDirs = @(".venv", "node_modules", "__pycache__", ".pytest_cache")
$excludeTree = @((Join-Path $ProjectRoot "data\tmp"))

Write-Host "=== Backup project source (no DB) ===" -ForegroundColor Cyan
Write-Host "Источник:   $ProjectRoot"
Write-Host "Назначение: $dest"
Write-Host "Исключено:  $($excludeDirs -join ', '), data\tmp"
Write-Host "PostgreSQL: НЕ ЗАТРАГИВАЕТСЯ (файловый снимок)" -ForegroundColor Yellow

# --- Защита: назначение не должно находиться внутри источника -------------
if (Test-SourceBackupContainment -SourcePath $ProjectRoot -DestinationPath $dest) {
    throw "Каталог бэкапа находится внутри проекта — рекурсивное копирование. Прервано."
}

if ($ValidateOnly) {
    Write-Host "`n-- ValidateOnly: подсчёт объёма --" -ForegroundColor Cyan
    $files = Get-ChildItem -LiteralPath $ProjectRoot -Recurse -File -Force -ErrorAction SilentlyContinue |
        Where-Object {
            $p = $_.FullName
            -not ($excludeDirs | Where-Object { $p -like "*\$_\*" }) -and
            -not ($excludeTree  | Where-Object { $p -like "$_\*"    })
        }
    $count = @($files).Count
    $bytes = ($files | Measure-Object -Property Length -Sum).Sum
    Write-Host ("Будет скопировано: {0:N0} файлов, {1:N2} ГБ" -f $count, ($bytes / 1GB))
    Write-Host "Реальное копирование не выполнялось." -ForegroundColor Yellow
    return
}

New-Item -ItemType Directory -Path $dest -Force | Out-Null
$log = Join-Path $dest "_robocopy.log"

# /XJ  - не идти по junction/symlink (исключает петли внутри .venv)
# /R:1 /W:1 - не залипать на нечитаемых файлах
# /COPY:DAT - данные, атрибуты, таймстемпы; ACL не переносим намеренно
$roboArgs = @(
    $ProjectRoot, $dest, "/E", "/XJ", "/COPY:DAT", "/R:1", "/W:1",
    "/NFL", "/NDL", "/NP", "/TEE", "/LOG:$log"
)
foreach ($d in $excludeDirs) { $roboArgs += @("/XD", $d) }
foreach ($t in $excludeTree) { $roboArgs += @("/XD", $t) }

Write-Host "`n-- robocopy --" -ForegroundColor Cyan
& robocopy @roboArgs | Out-Null
$rc = $LASTEXITCODE

# robocopy: 0-7 успех (8+ = отказы копирования)
if ($rc -ge 8) {
    Write-Host "robocopy завершился с кодом $rc — бэкап НЕ подтверждён." -ForegroundColor Red
    Write-Host "Журнал: $log"
    exit 1
}

# --- Манифест: без него бэкап недоказуем ----------------------------------
$copied = Get-ChildItem -LiteralPath $dest -Recurse -File -Force -ErrorAction SilentlyContinue
$copiedCount = @($copied).Count
$copiedBytes = ($copied | Measure-Object -Property Length -Sum).Sum

$manifest = [ordered]@{
    created_utc       = (Get-Date).ToUniversalTime().ToString("o")
    project_root      = $ProjectRoot
    backup_path       = $dest
    robocopy_exitcode = $rc
    files_copied      = $copiedCount
    bytes_copied      = $copiedBytes
    excluded_dirs     = $excludeDirs
    excluded_trees    = $excludeTree
    database_included = $false
    database_note     = "PostgreSQL runtime не выгружался. Это файловый бэкап исходников, а не бэкап данных."
    git_included      = (Test-Path -LiteralPath (Join-Path $dest ".git"))
}
$manifestPath = Join-Path $dest "_backup_manifest.json"
$manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

Write-Host "`n=== Готово ===" -ForegroundColor Green
Write-Host ("Скопировано: {0:N0} файлов, {1:N2} ГБ" -f $copiedCount, ($copiedBytes / 1GB))
Write-Host "robocopy exit code: $rc (0-7 = успех)"
Write-Host "Манифест: $manifestPath"
Write-Host "Журнал:   $log"
Write-Host "`nБаза данных в бэкап НЕ входит." -ForegroundColor Yellow
