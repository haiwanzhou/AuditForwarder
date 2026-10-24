@echo off
cd /d "%~dp0.."
"build\Release\auditforwarder-client.exe" -c config\client_lab.yaml > data\lab_client.log 2>&1
