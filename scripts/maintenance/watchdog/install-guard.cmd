@echo off
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0guard-task.ps1" -Action Install
exit /b %errorlevel%
