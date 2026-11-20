[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$targetPath = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host "  SLI Platform - Очистка заблокированных папок pytest и tmp" -ForegroundColor Cyan
Write-Host "  (Удаление с текущими правами без изменения владельца и разрешений)" -ForegroundColor DarkGray
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host ""

$dirs = Get-ChildItem -Path $targetPath -Force -Directory -ErrorAction Stop | Where-Object {
    $_.Name -like ".pytest*" -or $_.Name -like ".tmp*" -or $_.Name -like ".pt*" -or $_.Name -eq ".testtmp"
}

if ($dirs.Count -eq 0) {
    Write-Host "Отлично! В папке $targetPath нет заблокированных временных папок." -ForegroundColor Green
    exit 0
}

Write-Host "Найдено папок для очистки: $($dirs.Count)" -ForegroundColor Yellow
Write-Host ""

$successCount = 0
$failCount = 0

foreach ($d in $dirs) {
    Write-Host "Обработка $($d.Name)... " -NoNewline

    # Не меняем владельца и разрешения: неудалённые файлы сохраняют защиту.
    $remaining = $true
    try {
        Remove-Item -LiteralPath $d.FullName -Recurse -Force -ErrorAction SilentlyContinue
        $remaining = Test-Path -LiteralPath $d.FullName -ErrorAction Stop
        if ($remaining) {
            # Резервная попытка с теми же правами; результат проверяем отдельно.
            cmd.exe /c "rmdir /s /q `"$($d.FullName)`"" 2>&1 | Out-Null
            $remaining = Test-Path -LiteralPath $d.FullName -ErrorAction Stop
        }
    } catch {
        # Ошибка проверки не доказывает, что папка удалена.
        $remaining = $true
    }
    if (-not $remaining) {
        Write-Host "[УДАЛЕНО]" -ForegroundColor Green
        $successCount++
    } else {
        Write-Host "[НЕ УДАЛЕНО: проверьте права и блокировки]" -ForegroundColor Red
        $failCount++
    }
}

$color = "Green"
if ($failCount -gt 0) { $color = "Yellow" }

Write-Host ""
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host "Итог: Успешно удалено: $successCount, Не удалено: $failCount" -ForegroundColor $color
Write-Host "====================================================================" -ForegroundColor Cyan

if ($failCount -gt 0) { exit 1 }
exit 0
