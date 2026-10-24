@echo off
chcp 936 >nul
setlocal enabledelayedexpansion
title 9 - 状态检查
cd /d "%~dp0.."

cls
echo ============================================================
echo   现在的运行状态
echo ============================================================
echo.

set "BAD="

call :chk 监管服务端    8443  /health
call :chk 图书管理系统  18080 /
call :chk 采集客户端A   8888  8888
call :chk 采集客户端B   8889  8889

echo.
echo ------------------------------------------------------------
echo   告警计数
echo ------------------------------------------------------------
curl -sf --noproxy "*" -m 3 http://127.0.0.1:8443/collusion/overview >nul 2>&1
if errorlevel 1 (
    echo   服务端没起来，读不到计数。
) else (
    curl -s --noproxy "*" -m 3 http://127.0.0.1:8443/collusion/overview | findstr /i "event_counts pending_review profile_operators"
)

echo.
echo ------------------------------------------------------------
if defined BAD (
    echo   有组件没起来，对照下面处理：
    echo.
    echo     监管服务端   双击「1-启动服务端.bat」
    echo     图书管理系统 双击「2-启动图书管理系统.bat」
    echo     采集客户端A  双击「3-启动采集客户端A.bat」
    echo     采集客户端B  双击「4-启动采集客户端B.bat」 单人演示可以不启动
    echo.
    echo   如果双击后提示「端口被占用」，说明有残留进程，
    echo   先双击「6-一键全部停止.bat」再重新启动。
) else (
    echo   四个组件全部在线。
)
echo ------------------------------------------------------------
echo.
pause
exit /b 0

rem ---------- 子过程 ----------
:chk
set "NAME=%~1"
set "PORT=%~2"
set "PATHCHK=%~3"

echo %PATHCHK% | findstr "^/" >nul 2>&1
if errorlevel 1 (
    set "LISTEN="
    for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":%PORT%" ^| findstr "LISTENING"') do set "LISTEN=%%p"
    if defined LISTEN (
        echo   [在线] %NAME%
    ) else (
        echo   [离线] %NAME%
        set "BAD=1"
    )
) else (
    curl -sf --noproxy "*" -m 3 -o NUL "http://127.0.0.1:%PORT%%PATHCHK%" >nul 2>&1
    if errorlevel 1 (
        echo   [离线] %NAME%
        set "BAD=1"
    ) else (
        echo   [在线] %NAME%
    )
)
exit /b 0
