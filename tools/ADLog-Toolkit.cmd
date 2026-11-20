@echo off
setlocal
chcp 65001 >nul
title SLI - единый центр управления
cd /d "%~dp0\.."
powershell -NoProfile -ExecutionPolicy Bypass -File "%CD%\tools\adlog-tool.ps1"
