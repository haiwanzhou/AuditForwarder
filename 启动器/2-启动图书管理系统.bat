@echo off
chcp 936 >nul
setlocal enabledelayedexpansion

rem 有的电脑上装了开发工具，会把 Python 的输出编码固定成 UTF-8，
rem 而这个黑窗口是 GBK 代码页，两边对不上中文就会变乱码。
rem 清掉这两个变量，让 Python 用系统默认编码，跟窗口保持一致。
set "PYTHONIOENCODING="
set "PYTHONUTF8="
title 2 - 启动图书管理系统
cd /d "%~dp0.."

set "QUIET="
if /i "%~1"=="quiet" set "QUIET=1"

cls
echo ============================================================
echo   图书管理系统  Library Inventory System
echo   端口 18080     本机演示用的业务系统
echo ============================================================
echo.

rem ---------- 找 Python ----------
rem 不写死版本号：WorkBuddy 升级 Python 之后路径里的 3.13.12 会变，
rem 所以这里按目录扫，取扫到的最后一个。
set "PY="
for /d %%d in ("%USERPROFILE%\.workbuddy\binaries\python\versions\*") do (
    if exist "%%d\python.exe" set "PY=%%d\python.exe"
)
if not defined PY (
    for /d %%d in ("E:\WorkBuddyData\.workbuddy\binaries\python\versions\*") do (
        if exist "%%d\python.exe" set "PY=%%d\python.exe"
    )
)
if not defined PY (
    for %%c in (python.exe) do (
        if not "%%~$PATH:c"=="" set "PY=%%~$PATH:c"
    )
)

if not defined PY (
    echo [失败] 这台电脑上找不到 Python。
    echo.
    echo    图书管理系统是 Python 写的，需要 Python 3 才能运行。
    echo    只启动采集端和服务端的话不需要它。
    echo.
    if not defined QUIET pause
    exit /b 1
)

if not exist "lab\book_system\backend\app.py" (
    echo [失败] 找不到图书系统程序：lab\book_system\backend\app.py
    echo.
    if not defined QUIET pause
    exit /b 1
)

rem ---------- 检查是否已经在跑 ----------
set "OLDPID="
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":18080" ^| findstr "LISTENING"') do set "OLDPID=%%p"

if defined OLDPID (
    curl -sf --noproxy "*" -m 3 -o NUL http://127.0.0.1:18080/ >nul 2>&1
    if not errorlevel 1 (
        echo [成功] 图书管理系统本来就在运行，不需要重复启动。
        echo.
        echo        正在打开业务界面 ...
        echo.
        set "PAGE_URL=http://127.0.0.1:18080/app"
        set "PAGE_PROXY="
        netstat -ano | findstr ":8888" | findstr "LISTENING" >nul 2>&1
        if not errorlevel 1 set "PAGE_PROXY=8888"
        call :open_page
        if not defined QUIET ping -n 5 127.0.0.1 >nul
        exit /b 0
    )
    echo [警告] 18080 端口被进程 %OLDPID% 占着但没响应，自动结束它重新启动。
    taskkill /F /PID %OLDPID% >nul 2>&1
    ping -n 3 127.0.0.1 >nul
)

rem ---------- 启动 ----------
echo [1/2] 正在启动图书管理系统 ...
echo        使用 Python：!PY!
start "图书管理系统 - 关闭此窗口即停止服务" /D "%~dp0.." cmd /k "chcp 65001>nul & "!PY!" lab\book_system\backend\app.py"

echo [2/2] 等待服务就绪 ...
set "N=0"

:wait_book
set /a N+=1
curl -sf --noproxy "*" -m 2 -o NUL http://127.0.0.1:18080/ >nul 2>&1
if not errorlevel 1 goto book_ok
if %N% geq 25 goto book_fail
ping -n 2 127.0.0.1 >nul
goto wait_book

:book_ok
echo.
echo [成功] 图书管理系统已就绪，用时约 %N% 秒。
echo.
echo    入口页面：http://127.0.0.1:18080/
echo.
echo    三个界面：
echo      图书业务界面  http://127.0.0.1:18080/app
echo      系统运维界面  http://127.0.0.1:18080/admin
echo      实验操作台    http://127.0.0.1:18080/console
echo.
echo    账号密码见「使用说明.txt」。
echo    新弹出的那个黑窗口是图书系统本身，关掉它就停了。
echo.
echo    正在打开业务界面 ...
echo.
set "PAGE_URL=http://127.0.0.1:18080/app"
set "PAGE_PROXY="
netstat -ano | findstr ":8888" | findstr "LISTENING" >nul 2>&1
if not errorlevel 1 (
    set "PAGE_PROXY=8888"
) else (
    echo    注意：采集客户端 A 还没启动，现在打开的这个页面
    echo          操作不会被记录下来，只能看界面。
    echo          想用带采集的浏览器打开，双击「5-一键全部启动.bat」
    echo          或「7-打开网页.bat」；也可以先启动 3 再回来双击本文件。
    echo.
)
call :open_page
if not defined QUIET pause
exit /b 0

:book_fail
echo.
echo [失败] 等了 25 秒，图书管理系统还是没有响应。
echo.
echo    请看一下新弹出的那个黑窗口里的报错。
echo    最常见的原因是 18080 端口被占用，或者 Python 缺少依赖包。
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
