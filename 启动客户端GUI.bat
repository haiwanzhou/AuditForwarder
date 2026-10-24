@echo off
chcp 936 >nul
rem 启动 GUI 版采集客户端（图形界面那个，不是实验环境用的命令行版）
rem 工作目录必须是仓库根目录，config\client_windows.yaml 才能被找到
cd /d "%~dp0"

set "EXE=build\Release\auditforwarder-client-gui.exe"
if not exist "%EXE%" (
    echo [失败] 找不到 GUI 客户端：%EXE%
    echo.
    echo 可能原因：
    echo   1. 程序还没有编译
    echo   2. 整个文件夹没有完整复制过来
    echo.
    pause
    exit /b 1
)

if not exist "config\client_windows.yaml" (
    echo [失败] 找不到配置文件：config\client_windows.yaml
    echo.
    pause
    exit /b 1
)

echo 正在启动 GUI 采集客户端 ...
start "" "%EXE%"
exit /b 0
