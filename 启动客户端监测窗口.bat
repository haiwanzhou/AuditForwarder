@echo off
chcp 65001 >nul
title AuditForwarder Client Monitor
cd /d "%~dp0"

set "EXE=build\Release\auditforwarder-client.exe"
if not exist "%EXE%" set "EXE=friend-client\auditforwarder-client.exe"
if not exist "%EXE%" (
    echo [ERROR] no client exe found. Build it first:
    echo         cmake --build build --config Release
    pause
    exit /b 1
)

echo ========================================
echo   AuditForwarder Client Monitor
echo   config : config\client_windows.yaml
echo   exe    : %EXE%
echo   stop   : Ctrl+C
echo ========================================
echo.

"%EXE%" -c config\client_windows.yaml

echo.
echo [Client exited] errorlevel=%ERRORLEVEL%
pause
