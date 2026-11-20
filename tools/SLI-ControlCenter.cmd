@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0sli-control-center.ps1" %*
exit /b %ERRORLEVEL%
