@echo off
rem AuditForwarder GUI client launcher
rem Working directory must be the repo root so that config/client_windows.yaml resolves.
cd /d "%~dp0"
if not exist "build_v120\Release\auditforwarder-client-gui.exe" (
    echo [ERROR] build_v120\Release\auditforwarder-client-gui.exe not found. Build it first.
    pause
    exit /b 1
)
start "" "build_v120\Release\auditforwarder-client-gui.exe"
exit /b 0
