@echo off
echo ============================================================
echo   SLI Platform - Перенос и очистка заблокированных tmp/pytest
echo ============================================================
echo Требуются права Администратора для сброса прав изолированных песочниц.
echo.

set "TARGET=%TEMP%\sli_tmp_pytest_archive"
if not exist "%TARGET%" mkdir "%TARGET%"

cd /d "%~dp0..\.."

echo [1/3] Снятие блокировок и смена владельца...
for /d %%D in (.pytest-tmp* .tmp-* .pt-* .testtmp .pytest-nps .pytest-replay .pytest-vpn-source-review .pytest_cache .pytest_tmp) do (
    if exist "%%D" (
        echo Разблокировка %%D...
        takeown /f "%%D" /r /d y >nul 2>&1
        icacls "%%D" /grant "%USERNAME%":(OI)(CI)F /t /c /q >nul 2>&1
        icacls "%%D" /grant *S-1-5-32-544:(OI)(CI)F /t /c /q >nul 2>&1
    )
)

echo [2/3] Перенос в %TARGET%...
for /d %%D in (.pytest-tmp* .tmp-* .pt-* .testtmp .pytest-nps .pytest-replay .pytest-vpn-source-review .pytest_cache .pytest_tmp) do (
    if exist "%%D" (
        move /y "%%D" "%TARGET%\" >nul 2>&1
        if exist "%%D" (
            echo Прямой перенос %%D не удался, попытка rmdir...
            rmdir /s /q "%%D" >nul 2>&1
        ) else (
            echo Перенесено: %%D
        )
    )
)

echo [3/3] Завершено успешно!
echo Нажмите любую клавишу для выхода...
pause >nul
