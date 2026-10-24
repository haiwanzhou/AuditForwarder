@echo off
chcp 936 >nul
setlocal enabledelayedexpansion
title 6 - 一键全部停止
cd /d "%~dp0.."

cls
echo ============================================================
echo   停止全部组件
echo ============================================================
echo.

set "FOUND="

rem ---------- 服务端 ----------
tasklist /FI "IMAGENAME eq auditforwarder-server.exe" 2>nul | findstr /i "auditforwarder-server.exe" >nul
if not errorlevel 1 (
    echo [停止] 监管服务端 ...
    taskkill /F /IM auditforwarder-server.exe >nul 2>&1
    set "FOUND=1"
)

rem ---------- 采集客户端 ----------
tasklist /FI "IMAGENAME eq auditforwarder-client.exe" 2>nul | findstr /i "auditforwarder-client.exe" >nul
if not errorlevel 1 (
    echo [停止] 采集客户端 ...
    taskkill /F /IM auditforwarder-client.exe >nul 2>&1
    set "FOUND=1"
)

rem ---------- 图书系统：只杀监听 18080 的 python，不碰别的 python ----------
set "BOOKPID="
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":18080" ^| findstr "LISTENING"') do set "BOOKPID=%%p"
if defined BOOKPID (
    echo [停止] 图书管理系统，进程号 !BOOKPID! ...
    taskkill /F /PID !BOOKPID! >nul 2>&1
    set "FOUND=1"
)

rem ---------- 有些版本的引导进程杀完还会留一个监听 ----------
ping -n 3 127.0.0.1 >nul
for %%P in (8443 18080 8888 8889) do (
    set "LEFT="
    for /f "tokens=5" %%q in ('netstat -ano ^| findstr ":%%P" ^| findstr "LISTENING"') do set "LEFT=%%q"
    if defined LEFT (
        echo [补刀] 端口 %%P 还被进程 !LEFT! 占着，一并结束
        taskkill /F /PID !LEFT! >nul 2>&1
    )
)

if not defined FOUND (
    echo 四个组件本来就没有在运行。
) else (
    echo.
    echo 已全部停止。
)

echo.
pause
exit /b 0
