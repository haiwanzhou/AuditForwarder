@echo off
chcp 936 >nul
setlocal enabledelayedexpansion

rem 有的电脑上装了开发工具，会把 Python 的输出编码固定成 UTF-8，
rem 而这个黑窗口是 GBK 代码页，两边对不上中文就会变乱码。
rem 清掉这两个变量，让 Python 用系统默认编码，跟窗口保持一致。
set "PYTHONIOENCODING="
set "PYTHONUTF8="
title 8 - 清空告警数据
cd /d "%~dp0.."

cls
echo ============================================================
echo   清空告警数据（回到干净基线）
echo ============================================================
echo.
echo   会把监管端里的告警记录、待复核、操作员画像全部清掉，
echo   让你下一次演示时数字从 0 开始跳。
echo.
echo   注意：会重启一次服务端，采集客户端不受影响。
echo.
set "ANS="
set /p "ANS=确定要清空吗？输入 Y 回车继续，直接回车取消："
if /i not "%ANS%"=="Y" (
    echo.
    echo 已取消，什么都没动。
    echo.
    pause
    exit /b 0
)

rem ---------- 找 Python ----------
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
    echo.
    echo [失败] 找不到 Python，没法运行清空脚本。
    echo.
    pause
    exit /b 1
)

if not exist "lab\clear_alerts.py" (
    echo.
    echo [失败] 找不到 lab\clear_alerts.py
    echo.
    pause
    exit /b 1
)

echo.
echo 正在清空，大约需要 20 到 60 秒，请稍等 ...
echo.

"!PY!" lab\clear_alerts.py

echo.
echo ------------------------------------------------------------
echo 正在打开监管界面，稍等一下就能看到数字归零 ...
echo ------------------------------------------------------------
echo.
set "PAGE_URL=http://127.0.0.1:8443/ui#collusion"
set "PAGE_PROXY="
call :open_page
pause
exit /b 0

rem ============================================================
rem   打开网页（子过程，正常流程执行不到这里）
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

start "" "%PAGE_BR%" --proxy-server="127.0.0.1:%PAGE_PROXY%" --proxy-bypass-list="<-loopback>" --user-data-dir="%LOCALAPPDATA%\af-lab-browser-%PAGE_PROXY%" --no-first-run --no-default-browser-check "%PAGE_URL%"
exit /b 0
