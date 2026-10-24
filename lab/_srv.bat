@echo off
cd /d "%~dp0.."
"build\Release\auditforwarder-server.exe" -d data\server --listen 0.0.0.0:8443 > data\lab_server.log 2>&1
