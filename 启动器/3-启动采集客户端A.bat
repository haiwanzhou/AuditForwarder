@echo off
chcp 936 >nul
setlocal
title 3 - 启动采集客户端 A
cd /d "%~dp0.."

set "QUIET="
if /i "%~1"=="quiet" set "QUIET=1"

cls
echo ============================================================
echo   采集客户端 A
echo   主机标识 lab-pc    代理端口 8888    操作员 admin
echo ============================================================
echo.

set "EXE=build\Release\auditforwarder-client.exe"
if not exist "%EXE%" (
    echo [失败] 找不到采集客户端程序：%EXE%
    echo.
    if not defined QUIET pause
    exit /b 1
)
if not exist "config\client_lab.yaml" (
    echo [失败] 找不到配置文件：config\client_lab.yaml
    echo.
    if not defined QUIET pause
    exit /b 1
)

rem ---------- 检查是否已经在跑 ----------
set "OLDPID="
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":8888" ^| findstr "LISTENING"') do set "OLDPID=%%p"

if defined OLDPID (
    echo [成功] 采集客户端 A 本来就在运行，不需要重复启动。
    echo.
    echo        进程号 %OLDPID%，代理地址 127.0.0.1:8888
    echo.
    set "PAGE_URL=http://127.0.0.1:18080/console"
    set "PAGE_PROXY=8888"
    curl -sf --noproxy "*" -m 2 -o NUL http://127.0.0.1:18080/ >nul 2>&1
    if errorlevel 1 (
        echo    提示：图书管理系统 18080 还没启动，操作台暂时打不开。
        echo          先双击「2-启动图书管理系统.bat」，再回来双击本文件。
        echo.
    ) else (
        echo    正在打开操作台（走 8888 代理，操作会被采集）...
        echo.
        call :open_page
    )
    if not defined QUIET ping -n 5 127.0.0.1 >nul
    exit /b 0
)

rem ---------- 提醒服务端 ----------
curl -sf --noproxy "*" -m 2 -o NUL http://127.0.0.1:8443/health >nul 2>&1
if errorlevel 1 (
    echo [警告] 服务端 8443 现在连不上。
    echo        客户端能启动，但日志传不上去，监管界面会显示离线。
    echo        建议先双击「1-启动服务端.bat」。
    echo.
)

rem ---------- 启动 ----------
echo [1/2] 正在启动采集客户端 A ...
start "采集客户端A - 关闭此窗口即停止采集" /D "%~dp0.." cmd /k "chcp 65001>nul & %EXE% -c config\client_lab.yaml"

echo [2/2] 等待 8888 端口就绪 ...
set "N=0"

:wait_cli
set /a N+=1
set "LISTEN="
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":8888" ^| findstr "LISTENING"') do set "LISTEN=%%p"
if defined LISTEN goto cli_ok
if %N% geq 15 goto cli_fail
ping -n 2 127.0.0.1 >nul
goto wait_cli

:cli_ok
echo.
echo [成功] 采集客户端 A 已就绪，代理端口 127.0.0.1:8888
echo.
echo    现在浏览器里的请求要经过 8888 才会被采集。
echo    接下来会自动打开操作台，那个窗口已经配好代理了。
echo.
echo    新弹出的那个黑窗口就是采集端本身，关掉它就停止采集。
echo.
set "PAGE_URL=http://127.0.0.1:18080/console"
set "PAGE_PROXY=8888"
curl -sf --noproxy "*" -m 2 -o NUL http://127.0.0.1:18080/ >nul 2>&1
if errorlevel 1 (
    echo    提示：图书管理系统 18080 还没启动，操作台暂时打不开。
    echo          先双击「2-启动图书管理系统.bat」，再回来双击本文件。
    echo.
) else (
    echo    正在打开操作台（走 8888 代理，操作会被采集）...
    echo.
    call :open_page
)
if not defined QUIET pause
exit /b 0

:cli_fail
echo.
echo [失败] 8888 端口没有起来。
echo.
echo    可能是配置文件有问题，或者 8888 被别的程序占用。
echo    看一下新弹出的那个黑窗口里的报错。
echo.
if not defined QUIET pause
exit /b 1

rem ============================================================
rem   打开网页（子过程，正常流程执行不到这里）
rem   调用前先设置两个变量：
rem     PAGE_URL     要打开的网址
rem     PAGE_PROXY   走哪个代理端口；留空表示不走代理
rem   quiet 模式直接返回，免得被其它脚本调用时弹出一堆浏览器
rem ============================================================
:open_page
if defined QUIET exit /b 0
if not defined PAGE_URL exit /b 0

set "PAGE_BR="
if exist "%ProgramFiles%\Google\Chrome\Application\chrome.exe" set "PAGE_BR=%ProgramFiles%\Google\Chrome\Application\chrome.exe"
if not defined PAGE_BR if exist "%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe" set "PAGE_BR=%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"
if not defined PAGE_BR if exist "%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe" set "PAGE_BR=%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"
if not defined PAGE_BR if exist "%ProgramFiles%\Microsoft\Edge\Application\msedge.exe" set "PAGE_BR=%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"
if not defined PAGE_BR if exist "%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe" set "PAGE_BR=%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"

if not defined PAGE_PROXY (
    rem 不走代理：交给系统默认浏览器，收藏夹、密码、登录状态都在
    start "" "%PAGE_URL%"
    exit /b 0
)

if not defined PAGE_BR (
    echo    [提示] 没找到 Chrome 或 Edge，改用默认浏览器打开。
    echo           这样打开的页面不经过代理，操作不会被采集到。
    echo.
    start "" "%PAGE_URL%"
    exit /b 0
)

rem 每个代理端口用独立的浏览器配置目录：
rem 同一目录只能有一套代理设置，分开才能让 8888 和 8889 各开各的窗口。
start "" "%PAGE_BR%" --proxy-server="127.0.0.1:%PAGE_PROXY%" --proxy-bypass-list="<-loopback>" --user-data-dir="%LOCALAPPDATA%\af-lab-browser-%PAGE_PROXY%" --no-first-run --no-default-browser-check "%PAGE_URL%"
exit /b 0
