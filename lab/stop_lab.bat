@echo off
REM 停止合谋实验环境（服务端 / 图书系统 / 采集客户端）
taskkill /F /IM auditforwarder-server.exe >nul 2>&1
taskkill /F /IM auditforwarder-client.exe >nul 2>&1
REM 只杀监听 18080 的 python，避免误杀其他 python 进程
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":18080" ^| findstr "LISTENING"') do taskkill /F /PID %%p >nul 2>&1
echo 实验环境已停止。
