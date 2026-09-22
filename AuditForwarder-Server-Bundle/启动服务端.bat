@echo off
title AuditForwarder Server - DO NOT CLOSE
cd /d "%~dp0"

echo ============================================================
echo   AuditForwarder Server
echo   Keep this window OPEN. You can minimize it.
echo   Closing this window STOPS the server.
echo ============================================================
echo.

:loop
"build\Release\auditforwarderd.exe" -c config/server_windows.yaml -d data/server
echo.
echo Server exited. Restarting in 2 seconds...
ping 127.0.0.1 -n 3 >nul
goto loop
