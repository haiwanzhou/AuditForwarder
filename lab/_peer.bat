@echo off
cd /d "%~dp0.."
"build\Release\auditforwarder-client.exe" -c config\client_lab_peer.yaml -d data\client2 > data\lab_client2.log 2>&1
