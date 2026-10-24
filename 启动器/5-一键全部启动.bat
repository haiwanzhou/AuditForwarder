@echo off
chcp 936 >nul
setlocal
title 5 - 一键启动全部
cd /d "%~dp0.."
set "HERE=%~dp0"

cls
echo ============================================================
echo   一键启动全部组件
echo   服务端 -> 图书系统 -> 采集客户端 A -> 采集客户端 B
echo ============================================================
echo.

call "%HERE%1-启动服务端.bat" quiet
if errorlevel 1 (
    echo.
    echo [中断] 服务端没起来，后面的组件就不用启动了。
    echo.
    pause
    exit /b 1
)
echo.

call "%HERE%2-启动图书管理系统.bat" quiet
if errorlevel 1 (
    echo.
    echo [中断] 图书管理系统没起来。
    echo        如果只是想跑采集和检测，可以手动双击「3-启动采集客户端A.bat」。
    echo.
    pause
    exit /b 1
)
echo.

call "%HERE%3-启动采集客户端A.bat" quiet
echo.

call "%HERE%4-启动采集客户端B.bat" quiet
echo.

rem ---------- 汇总 ----------
echo ============================================================
echo   启动结果
echo ============================================================

call :chk 服务端        8443  /health
call :chk 图书管理系统  18080 /
call :chk 采集客户端A   8888  8888
call :chk 采集客户端B   8889  8889

echo.
echo ------------------------------------------------------------
echo   监管界面  http://127.0.0.1:8443/ui      admin / admin123
echo   操作台    http://127.0.0.1:18080/console
echo ------------------------------------------------------------
echo.
echo   提示：
echo     - 每个组件都在自己的黑窗口里跑，关掉对应的窗口就停止那个组件
echo     - 想全部停止，双击「6-一键全部停止.bat」
echo     - 账号密码见「使用说明.txt」
echo.

rem ---------- 打开网页 ----------
set "CHROME=%ProgramFiles%\Google\Chrome\Application\chrome.exe"
if not exist "%CHROME%" set "CHROME=%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"
if not exist "%CHROME%" set "CHROME=%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"

if exist "%CHROME%" (
    echo 正在打开业务页面（走 8888 代理，操作会被采集）...
    start "" "%CHROME%" --proxy-server="127.0.0.1:8888" --proxy-bypass-list="<-loopback>" --user-data-dir="%LOCALAPPDATA%\af-lab-browser-8888" --no-first-run --no-default-browser-check "http://127.0.0.1:18080/console" "http://127.0.0.1:18080/app" "http://127.0.0.1:18080/admin"
    echo 正在打开监管界面（不走代理）...
    ping -n 3 127.0.0.1 >nul
    start "" "http://127.0.0.1:8443/ui#collusion"
) else (
    echo 没找到 Chrome 或 Edge，请手动打开这两个地址：
    echo   http://127.0.0.1:18080/console
    echo   http://127.0.0.1:8443/ui
)

echo.
pause
exit /b 0

rem ---------- 子过程：检查一个端口 ----------
:chk
set "NAME=%~1"
set "PORT=%~2"
set "PATHCHK=%~3"

rem 第三个参数以 / 开头就走 HTTP 健康检查，否则只看端口有没有在听
echo %PATHCHK% | findstr "^/" >nul 2>&1
if errorlevel 1 (
    netstat -ano | findstr ":%PORT%" | findstr "LISTENING" >nul 2>&1
    if errorlevel 1 (
        echo   [离线] %NAME%
    ) else (
        echo   [在线] %NAME%
    )
) else (
    curl -sf --noproxy "*" -m 3 -o NUL "http://127.0.0.1:%PORT%%PATHCHK%" >nul 2>&1
    if errorlevel 1 (
        echo   [离线] %NAME%
    ) else (
        echo   [在线] %NAME%
    )
)
exit /b 0
