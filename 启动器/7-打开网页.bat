@echo off
chcp 936 >nul
setlocal
title 7 - 打开网页
cd /d "%~dp0.."

set "QUIET="
if /i "%~1"=="quiet" set "QUIET=1"

cls
echo ============================================================
echo   打开实验用的网页
echo ============================================================
echo.

rem ---------- 先看服务有没有起来 ----------
set "BOOKOK="
curl -sf --noproxy "*" -m 2 -o NUL http://127.0.0.1:18080/ >nul 2>&1
if not errorlevel 1 set "BOOKOK=1"

set "SRVOK="
curl -sf --noproxy "*" -m 2 -o NUL http://127.0.0.1:8443/health >nul 2>&1
if not errorlevel 1 set "SRVOK=1"

if not defined BOOKOK (
    echo [提示] 图书管理系统 18080 现在打不开。
    echo        先双击「2-启动图书管理系统.bat」。
    echo.
)
if not defined SRVOK (
    echo [提示] 监管服务端 8443 现在打不开。
    echo        先双击「1-启动服务端.bat」。
    echo.
)

set "CHROME=%ProgramFiles%\Google\Chrome\Application\chrome.exe"
if not exist "%CHROME%" set "CHROME=%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"
if not exist "%CHROME%" set "CHROME=%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"

if not exist "%CHROME%" (
    echo 没找到 Chrome 或 Edge，请手动打开下面这些地址：
    echo.
    echo   操作台    http://127.0.0.1:18080/console
    echo   业务界面  http://127.0.0.1:18080/app
    echo   运维界面  http://127.0.0.1:18080/admin
    echo   监管界面  http://127.0.0.1:8443/ui
    echo.
    if not defined QUIET pause
    exit /b 0
)

echo 第一组：三个业务页面，走 8888 代理，操作会被采集
echo   操作台    http://127.0.0.1:18080/console
echo   业务界面  http://127.0.0.1:18080/app
echo   运维界面  http://127.0.0.1:18080/admin
echo.
start "" "%CHROME%" --proxy-server="127.0.0.1:8888" --proxy-bypass-list="<-loopback>" --user-data-dir="%LOCALAPPDATA%\af-lab-browser-8888" --no-first-run --no-default-browser-check "http://127.0.0.1:18080/console" "http://127.0.0.1:18080/app" "http://127.0.0.1:18080/admin"

ping -n 3 127.0.0.1 >nul

echo 第二组：监管界面，不走代理
echo   http://127.0.0.1:8443/ui
echo.
start "" "http://127.0.0.1:8443/ui#collusion"

echo.
echo ------------------------------------------------------------
echo   为什么分两组：
echo     业务页面必须走 8888 代理才会被采集到。
echo     监管界面走代理会把服务端自己的请求也记进去，反而看不清。
echo.
echo   如果三个业务页面显示不正常，在那个窗口按一次 Ctrl + F5。
echo ------------------------------------------------------------
echo.
if not defined QUIET pause
exit /b 0
