@echo off
chcp 936 >nul
setlocal
title 1 - 启动监管服务端
cd /d "%~dp0.."

set "QUIET="
if /i "%~1"=="quiet" set "QUIET=1"

cls
echo ============================================================
echo   监管服务端  AuditForwarder Server
echo   端口 8443     数据目录 data\server
echo ============================================================
echo.

set "EXE=build\Release\auditforwarder-server.exe"

if not exist "%EXE%" (
    echo [失败] 找不到服务端程序
    echo        期望位置：%EXE%
    echo.
    echo   可能原因：
    echo     - 整个 AuditForwarder 文件夹没有完整复制过来
    echo     - 程序还没有编译
    echo.
    if not defined QUIET pause
    exit /b 1
)

rem ---------- 第一步：检查是不是已经有一个在跑了 ----------
set "OLDPID="
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":8443" ^| findstr "LISTENING"') do set "OLDPID=%%p"

if defined OLDPID (
    echo [提示] 8443 端口已经被占用，进程号 %OLDPID%
    echo.
    curl -sf --noproxy "*" -m 3 -o NUL http://127.0.0.1:8443/health >nul 2>&1
    if not errorlevel 1 (
        echo [成功] 服务端本来就在运行，不需要重复启动。
        echo.
        echo        正在打开监管界面 ...
        echo.
        set "PAGE_URL=http://127.0.0.1:8443/ui#collusion"
        set "PAGE_PROXY="
        call :open_page
        if not defined QUIET ping -n 5 127.0.0.1 >nul
        exit /b 0
    )
    echo [警告] 这个进程不响应健康检查，多半是上次异常退出留下的残留。
    echo        现在自动结束它，然后重新启动。
    echo.
    taskkill /F /PID %OLDPID% >nul 2>&1
    ping -n 3 127.0.0.1 >nul
)

rem ---------- 第二步：启动 ----------
echo [1/2] 正在启动服务端 ...
start "监管服务端 - 关闭此窗口即停止服务" /D "%~dp0.." cmd /k "chcp 65001>nul & %EXE% -d data\server --listen 0.0.0.0:8443"

echo [2/2] 等待服务端就绪 ...
set "N=0"

:wait_srv
set /a N+=1
curl -sf --noproxy "*" -m 2 -o NUL http://127.0.0.1:8443/health >nul 2>&1
if not errorlevel 1 goto srv_ok
if %N% geq 25 goto srv_fail
ping -n 2 127.0.0.1 >nul
goto wait_srv

:srv_ok
echo.
echo [成功] 服务端已就绪，用时约 %N% 秒。
echo.
echo    监管界面：http://127.0.0.1:8443/ui
echo    登录账号：admin        密码：admin123
echo.
echo    新弹出的那个黑窗口才是服务端本身，
echo    关掉它服务就停了。现在这个窗口可以关。
echo.
echo    正在打开监管界面 ...
echo.
set "PAGE_URL=http://127.0.0.1:8443/ui#collusion"
set "PAGE_PROXY="
call :open_page
if not defined QUIET pause
exit /b 0

:srv_fail
echo.
echo [失败] 等了 25 秒，服务端还是没有响应。
echo.
echo    请看一下新弹出的那个黑窗口里写了什么，
echo    或者打开日志文件：data\server\server.log
echo.
echo    常见原因：
echo     - 8443 端口被别的程序占着
echo     - 杀毒软件拦住了这个程序
echo     - data\server 目录被设成只读
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
