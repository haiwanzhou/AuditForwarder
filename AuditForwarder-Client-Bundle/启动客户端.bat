@echo off
cd /d "%~dp0"
title AuditForwarder Client Launcher

echo ============================================================
echo    AuditForwarder 客户端
echo    主机ID : zyh-yxy-001
echo    服务端 : http://26.17.173.34:8443
echo ============================================================
echo.

net session >nul 2>&1
if not "%errorlevel%"=="0" (
  echo [警告] 当前不是管理员身份运行。
  echo [警告] Windows 安全日志 ^(ETW^) 将无法采集，其余 5 个采集器正常。
  echo [警告] 建议关闭本窗口，右键本文件 -^> 以管理员身份运行。
  echo.
)

if not exist "data\client" mkdir "data\client"

echo [1/2] 正在启动客户端 ...
start "AuditForwarder Client" /min "%~dp0auditforwarder-client.exe" -c "config/client_windows.yaml" -L info
echo.

echo [2/2] 等待 12 秒，然后显示日志尾部 ...
timeout /t 12 /nobreak >nul
echo.

echo ---------------- data\client\client.log ^(tail 25^) ----------------
if exist "data\client\client.log" (
  powershell -NoProfile -Command "Get-Content -LiteralPath 'data\client\client.log' -Tail 25"
) else (
  echo    client.log 尚未生成，客户端可能启动失败。
)
echo -----------------------------------------------------------
echo.
echo 客户端已在最小化的那个窗口里持续运行。
echo 想停止客户端，关闭那个最小化窗口即可。
echo.
echo 按任意键关闭本窗口（不会停止客户端）。
pause >nul
