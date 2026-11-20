param(
    [string]$Action = "menu",
    [string]$Package,
    [string]$ReportName = "collector-health",
    [switch]$Json,
    [switch]$Deep
)

$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $ProjectRoot
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$Python = if (Test-Path ".\.venv\Scripts\python.exe") {
    ".\.venv\Scripts\python.exe"
} else {
    "python"
}

function Invoke-PythonTool {
    param([string[]]$Arguments)

    Write-Host ""
    Write-Host "> $Python $($Arguments -join ' ')" -ForegroundColor DarkCyan
    & $Python @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Команда завершилась с кодом $LASTEXITCODE"
    }
}

function Invoke-ProjectCommand {
    param(
        [string]$Executable,
        [string[]]$Arguments
    )

    Write-Host ""
    Write-Host "> $Executable $($Arguments -join ' ')" -ForegroundColor DarkCyan
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Команда завершилась с кодом $LASTEXITCODE"
    }
}

function Confirm-Operation {
    param([string]$Question)

    $answer = Read-Host "$Question [д/Н]"
    return $answer -match "^[ДдYy]$"
}

function Show-Title {
    param([string]$Title)

    Clear-Host
    Write-Host "============================================================" -ForegroundColor DarkBlue
    Write-Host " SLI — единый центр управления" -ForegroundColor Cyan
    Write-Host " $Title" -ForegroundColor White
    Write-Host "============================================================" -ForegroundColor DarkBlue
}

function Show-ActionHelp {
    Write-Host "Доступные прямые действия:" -ForegroundColor Cyan
    Write-Host "  status                  состояние рабочего HTTPS runtime"
    Write-Host "  http-status             состояние проверочной HTTP-копии"
    Write-Host "  http-restart            безопасный перезапуск HTTP-копии"
    Write-Host "  diagnostics             быстрая диагностика"
    Write-Host "  diagnostics-deep        расширенная диагностика"
    Write-Host "  capture-report          снимок отчёта или экрана"
    Write-Host "  self-test               автономная проверка проекта"
    Write-Host "  ui-navigation           проверка навигации"
    Write-Host "  ui-acceptance           полная приёмка SLI v4"
    Write-Host "  baseline-acceptance     единая приёмка точной версии"
    Write-Host "  storage-health          состояние хранилища"
    Write-Host "  storage-cleanup-plan    только план очистки"
    Write-Host "  pytest-cleanup-plan     план очистки старых тестовых циклов"
    Write-Host "  pytest-cleanup          удалить старые тестовые циклы с подтверждением"
    Write-Host "  postgres-readiness      готовность PostgreSQL"
    Write-Host "  db-status               подробные метрики PostgreSQL"
    Write-Host "  docs-check              актуальность документации"
    Write-Host "  repository-audit        актуальность файлов и контуров"
    Write-Host "  export-analyst          handoff аналитику/разработчику"
    Write-Host "  source-backup           резервная копия исходников без БД"
    Write-Host "  apply-update            применить пакет, нужен -Package"
    Write-Host "  rollback-plan           показать план отката"
    Write-Host "  supervisor-status       состояние задачи рабочих процессов"
    Write-Host "  supervisor-disable      остановить и отключить задачу"
    Write-Host "  git-status              состояние Git через Docker"
    Write-Host ""
    Write-Host "Команды запуска сбора намеренно отсутствуют: процессы управляются вручную, autostart отложен владельцем." -ForegroundColor Yellow
}

function Invoke-ControlAction {
    param([string]$Name)

    switch ($Name.ToLowerInvariant()) {
        "status" {
            Invoke-PythonTool @("scripts\maintenance\server_control.py", "--json", "status", "--insecure")
        }
        "http-status" {
            Invoke-PythonTool @("scripts\maintenance\http_copy_control.py", "status")
        }
        "http-restart" {
            Invoke-PythonTool @("scripts\maintenance\http_copy_control.py", "restart")
        }
        "diagnostics" {
            Invoke-PythonTool @("scripts\maintenance\collect_diagnostics.py")
        }
        "collect-diag" {
            Invoke-ControlAction "diagnostics"
        }
        "collect-diag-fast" {
            Invoke-ControlAction "diagnostics"
        }
        "diagnostics-deep" {
            Invoke-PythonTool @("scripts\maintenance\collect_diagnostics.py", "--deep")
        }
        "collect-diag-deep" {
            Invoke-ControlAction "diagnostics-deep"
        }
        "capture-report" {
            $arguments = @("scripts\maintenance\capture_report.py", "--name", $ReportName)
            if ($Json) { $arguments += "--json" }
            Invoke-PythonTool $arguments
        }
        "self-test" {
            Invoke-PythonTool @("scripts\maintenance\self_test.py", "--offline")
        }
        "ui-navigation" {
            Invoke-PythonTool @("scripts\maintenance\ui_nav_check.py")
        }
        "ui-nav-check" {
            Invoke-ControlAction "ui-navigation"
        }
        "ui-acceptance" {
            Invoke-ProjectCommand "npm.cmd" @("run", "beta:menu-walk", "--", "--results", "artifacts/acceptance/beta-menu")
        }
        "baseline-acceptance" {
            Invoke-PythonTool @(
                "scripts\maintenance\current_baseline_gate.py",
                "--live-url",
                "http://127.0.0.1:18082",
                "--json"
            )
        }
        "storage-health" {
            Invoke-PythonTool @("scripts\maintenance\storage_cleanup.py", "--health", "--json", "--summary-only")
        }
        "storage-cleanup-plan" {
            Invoke-PythonTool @("scripts\maintenance\storage_cleanup.py", "--dry-run", "--json", "--summary-only")
        }
        "storage-cleanup" {
            Invoke-ControlAction "storage-cleanup-plan"
        }
        "pytest-cleanup-plan" {
            Invoke-PythonTool @(
                "scripts\maintenance\storage_cleanup.py",
                "--pytest-runs-only",
                "--dry-run",
                "--json",
                "--summary-only"
            )
        }
        "pytest-cleanup" {
            Invoke-PythonTool @(
                "scripts\maintenance\storage_cleanup.py",
                "--pytest-runs-only",
                "--apply",
                "--confirm-apply",
                "--json",
                "--summary-only"
            )
        }
        "postgres-readiness" {
            $arguments = @("scripts\maintenance\postgres_readiness.py")
            if ($Json) { $arguments += "--json" }
            Invoke-PythonTool $arguments
        }
        "pg-readiness" {
            Invoke-ControlAction "postgres-readiness"
        }
        "db-status" {
            Invoke-PythonTool @("scripts\maintenance\postgres_status.py")
        }
        "docs-check" {
            $arguments = @("scripts\maintenance\md_freshness_check.py")
            if ($Json) { $arguments += "--json" }
            Invoke-PythonTool $arguments
        }
        "repository-audit" {
            $arguments = @("scripts\maintenance\repository_relevance_audit.py")
            if ($Json) { $arguments += "--json" }
            Invoke-PythonTool $arguments
        }
        "md-check" {
            Invoke-ControlAction "docs-check"
        }
        "export-analyst" {
            $arguments = @("scripts\maintenance\export_dev_handoff.py")
            if ($Json) { $arguments += "--json" }
            Invoke-PythonTool $arguments
        }
        "export-dev" {
            Invoke-ControlAction "export-analyst"
        }
        "source-backup" {
            & (Join-Path $ProjectRoot "scripts\ops\Backup-ProjectSource-NoDb.ps1")
            if ($LASTEXITCODE -ne 0) {
                throw "Резервное копирование завершилось с кодом $LASTEXITCODE"
            }
        }
        "apply-update" {
            if (-not $Package) {
                throw "Укажите пакет: -Package <путь-к-zip>"
            }
            Invoke-PythonTool @("scripts\maintenance\apply_update.py", "--package", $Package)
        }
        "rollback-plan" {
            Invoke-PythonTool @("scripts\maintenance\rollback_update.py", "--dry-run")
        }
        "supervisor-status" {
            $task = Get-ScheduledTask -TaskName "SLI Worker Supervisor" -ErrorAction SilentlyContinue
            if (-not $task) {
                Write-Host "Задача SLI Worker Supervisor не установлена." -ForegroundColor Yellow
                return
            }
            [pscustomobject]@{
                Задача = $task.TaskName
                Состояние = [string]$task.State
                Включена = [bool]$task.Settings.Enabled
            } | Format-List
        }
        "supervisor-disable" {
            & (Join-Path $ProjectRoot "scripts\ops\Disable-SLIWorkerSupervisor.ps1")
            if ($LASTEXITCODE -ne 0) {
                throw "Отключение supervisor завершилось с кодом $LASTEXITCODE"
            }
        }
        "git-status" {
            & (Join-Path $ProjectRoot "scripts\ops\git_docker.ps1") status --short
            if ($LASTEXITCODE -ne 0) {
                throw "Git через Docker завершился с кодом $LASTEXITCODE"
            }
        }
        "service-status" {
            $service = Get-Service -Name "SLIWebServer" -ErrorAction SilentlyContinue
            if (-not $service) {
                Write-Host "Служба Windows 'SLIWebServer' не зарегистрирована." -ForegroundColor Yellow
                return
            }
            [pscustomobject]@{
                Имя = $service.Name
                ОтображаемоеИмя = $service.DisplayName
                Состояние = [string]$service.Status
                ТипЗапуска = [string]$service.StartType
            } | Format-List
        }
        "service-install" {
            & (Join-Path $ProjectRoot "scripts\ops\Install-SLIWebServer-Service.ps1")
        }
        "service-uninstall" {
            & (Join-Path $ProjectRoot "scripts\ops\Uninstall-SLIWebServer-Service.ps1")
        }
        "help" {
            Show-ActionHelp
        }
        default {
            throw "Неизвестное действие: $Name. Используйте -Action help."
        }
    }
}

function Pause-Menu {
    Write-Host ""
    Read-Host "Нажмите Enter, чтобы вернуться в меню" | Out-Null
}

function Show-StateMenu {
    while ($true) {
        Show-Title "Состояние системы"
        Write-Host "1. Рабочий HTTPS runtime"
        Write-Host "2. Проверочная HTTP-копия"
        Write-Host "3. PostgreSQL"
        Write-Host "4. Задача рабочих процессов"
        Write-Host "5. Служба Windows (SLI Web Server)"
        Write-Host "0. Назад"
        switch (Read-Host "Выберите пункт") {
            "1" { Invoke-ControlAction "status"; Pause-Menu }
            "2" { Invoke-ControlAction "http-status"; Pause-Menu }
            "3" { Invoke-ControlAction "postgres-readiness"; Pause-Menu }
            "4" { Invoke-ControlAction "supervisor-status"; Pause-Menu }
            "5" { Invoke-ControlAction "service-status"; Pause-Menu }
            "0" { return }
            default { Write-Host "Неизвестный пункт." -ForegroundColor Yellow; Start-Sleep -Milliseconds 700 }
        }
    }
}

function Show-DiagnosticsMenu {
    while ($true) {
        Show-Title "Диагностика"
        Write-Host "1. Быстрая диагностика"
        Write-Host "2. Расширенная диагностика"
        Write-Host "3. Снимок отчёта"
        Write-Host "4. Автономная проверка"
        Write-Host "5. Проверка навигации"
        Write-Host "0. Назад"
        switch (Read-Host "Выберите пункт") {
            "1" { Invoke-ControlAction "diagnostics"; Pause-Menu }
            "2" { Invoke-ControlAction "diagnostics-deep"; Pause-Menu }
            "3" {
                $selected = Read-Host "Имя отчёта (по умолчанию collector-health)"
                if ($selected) { $script:ReportName = $selected }
                Invoke-ControlAction "capture-report"
                Pause-Menu
            }
            "4" { Invoke-ControlAction "self-test"; Pause-Menu }
            "5" { Invoke-ControlAction "ui-navigation"; Pause-Menu }
            "0" { return }
            default { Write-Host "Неизвестный пункт." -ForegroundColor Yellow; Start-Sleep -Milliseconds 700 }
        }
    }
}

function Show-VerificationMenu {
    while ($true) {
        Show-Title "Проверка интерфейса и документации"
        Write-Host "1. Состояние HTTP-копии"
        Write-Host "2. Перезапустить HTTP-копию"
        Write-Host "3. Проверить документацию"
        Write-Host "4. Проверить актуальность файлов и контуров"
        Write-Host "5. Полная приёмка SLI v4"
        Write-Host "6. Единая приёмка точной версии"
        Write-Host "0. Назад"
        switch (Read-Host "Выберите пункт") {
            "1" { Invoke-ControlAction "http-status"; Pause-Menu }
            "2" {
                if (Confirm-Operation "Перезапустить только loopback HTTP-копию?") {
                    Invoke-ControlAction "http-restart"
                }
                Pause-Menu
            }
            "3" { Invoke-ControlAction "docs-check"; Pause-Menu }
            "4" { Invoke-ControlAction "repository-audit"; Pause-Menu }
            "5" {
                if (Confirm-Operation "Запустить полную приёмку интерфейса?") {
                    Invoke-ControlAction "ui-acceptance"
                }
                Pause-Menu
            }
            "6" {
                if (Confirm-Operation "Запустить единый gate текущей версии?") {
                    Invoke-ControlAction "baseline-acceptance"
                }
                Pause-Menu
            }
            "0" { return }
            default { Write-Host "Неизвестный пункт." -ForegroundColor Yellow; Start-Sleep -Milliseconds 700 }
        }
    }
}

function Show-StorageMenu {
    while ($true) {
        Show-Title "Хранилище и PostgreSQL"
        Write-Host "1. Состояние хранилища"
        Write-Host "2. План очистки без изменений"
        Write-Host "3. План очистки старых pytest-циклов"
        Write-Host "4. Очистить старые pytest-циклы"
        Write-Host "5. Готовность подключения PostgreSQL"
        Write-Host "6. Метрики PostgreSQL (только чтение)"
        Write-Host "0. Назад"
        switch (Read-Host "Выберите пункт") {
            "1" { Invoke-ControlAction "storage-health"; Pause-Menu }
            "2" { Invoke-ControlAction "storage-cleanup-plan"; Pause-Menu }
            "3" { Invoke-ControlAction "pytest-cleanup-plan"; Pause-Menu }
            "4" {
                if (Confirm-Operation "Удалить только старые generated pytest-runs?") {
                    Invoke-ControlAction "pytest-cleanup"
                }
                Pause-Menu
            }
            "5" { Invoke-ControlAction "postgres-readiness"; Pause-Menu }
            "6" { Invoke-ControlAction "db-status"; Pause-Menu }
            "0" { return }
            default { Write-Host "Неизвестный пункт." -ForegroundColor Yellow; Start-Sleep -Milliseconds 700 }
        }
    }
}

function Show-DeliveryMenu {
    while ($true) {
        Show-Title "Передача и обслуживание проекта"
        Write-Host "1. Собрать handoff аналитику/разработчику"
        Write-Host "2. Резервная копия исходников без БД"
        Write-Host "3. Применить пакет обновления"
        Write-Host "4. Показать план отката"
        Write-Host "5. Git status через Docker"
        Write-Host "0. Назад"
        switch (Read-Host "Выберите пункт") {
            "1" { Invoke-ControlAction "export-analyst"; Pause-Menu }
            "2" { Invoke-ControlAction "source-backup"; Pause-Menu }
            "3" {
                $selected = Read-Host "Полный путь к ZIP-пакету"
                if ($selected -and (Confirm-Operation "Применить указанный пакет?")) {
                    $script:Package = $selected
                    Invoke-ControlAction "apply-update"
                }
                Pause-Menu
            }
            "4" { Invoke-ControlAction "rollback-plan"; Pause-Menu }
            "5" { Invoke-ControlAction "git-status"; Pause-Menu }
            "0" { return }
            default { Write-Host "Неизвестный пункт." -ForegroundColor Yellow; Start-Sleep -Milliseconds 700 }
        }
    }
}

function Show-LocalControlMenu {
    while ($true) {
        Show-Title "Локальные процессы"
        Write-Host "1. Состояние supervisor"
        Write-Host "2. Остановить и отключить supervisor"
        Write-Host "3. Служба Windows (SLI Web Server): состояние"
        Write-Host "4. Установить службу Windows (SLI Web Server)"
        Write-Host "5. Удалить службу Windows (SLI Web Server)"
        Write-Host "0. Назад"
        Write-Host ""
        Write-Host "Запуск сбора из меню запрещён текущим решением владельца." -ForegroundColor Yellow
        switch (Read-Host "Выберите пункт") {
            "1" { Invoke-ControlAction "supervisor-status"; Pause-Menu }
            "2" {
                if (Confirm-Operation "Остановить и отключить SLI Worker Supervisor?") {
                    Invoke-ControlAction "supervisor-disable"
                }
                Pause-Menu
            }
            "3" { Invoke-ControlAction "service-status"; Pause-Menu }
            "4" { Invoke-ControlAction "service-install"; Pause-Menu }
            "5" {
                if (Confirm-Operation "Удалить службу Windows SLI Web Server?") {
                    Invoke-ControlAction "service-uninstall"
                }
                Pause-Menu
            }
            "0" { return }
            default { Write-Host "Неизвестный пункт." -ForegroundColor Yellow; Start-Sleep -Milliseconds 700 }
        }
    }
}

function Show-MainMenu {
    while ($true) {
        Show-Title "Главное меню"
        Write-Host "1. Состояние системы"
        Write-Host "2. Диагностика"
        Write-Host "3. Интерфейс и документация"
        Write-Host "4. Хранилище и PostgreSQL"
        Write-Host "5. Передача и обслуживание проекта"
        Write-Host "6. Локальные процессы"
        Write-Host "7. Справка по прямым действиям"
        Write-Host "0. Выход"
        Write-Host ""
        Write-Host "Сбор событий и AD Context остановлен. Команд запуска в меню нет." -ForegroundColor DarkYellow
        switch (Read-Host "Выберите раздел") {
            "1" { Show-StateMenu }
            "2" { Show-DiagnosticsMenu }
            "3" { Show-VerificationMenu }
            "4" { Show-StorageMenu }
            "5" { Show-DeliveryMenu }
            "6" { Show-LocalControlMenu }
            "7" { Show-Title "Справка"; Show-ActionHelp; Pause-Menu }
            "0" { return }
            default { Write-Host "Неизвестный раздел." -ForegroundColor Yellow; Start-Sleep -Milliseconds 700 }
        }
    }
}

if ($Action.ToLowerInvariant() -eq "menu") {
    Show-MainMenu
} else {
    Invoke-ControlAction $Action
}
