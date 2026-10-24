@echo off
setlocal
cd /d "%~dp0.."

REM =====================================================================
REM  LAN version of open_lab.bat
REM
REM  Use this on an ADMIN machine (M1 / M2). It opens the book console
REM  through the LOCAL collector proxy, so every click is captured.
REM
REM  Usage:
REM      open_lan.bat 192.168.1.50            (book+server machine IP)
REM      open_lan.bat 192.168.1.50 8888       (IP + local proxy port)
REM
REM  Or set BOOKIP below and just double-click this file.
REM =====================================================================

set "BOOKIP=%~1"
if "%BOOKIP%"=="" set "BOOKIP=10.4.55.6"
set "PROXYPORT=%~2"
if "%PROXYPORT%"=="" set "PROXYPORT=8888"

echo ============================================================
echo   book console : http://%BOOKIP%:18080/console
echo   local proxy  : 127.0.0.1:%PROXYPORT%
echo ============================================================
echo.

set "CHROME=%ProgramFiles%\Google\Chrome\Application\chrome.exe"
if not exist "%CHROME%" set "CHROME=%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"
if not exist "%CHROME%" set "CHROME=%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"
if not exist "%CHROME%" goto nobrowser

REM Dedicated browser profile + explicit proxy.
REM The console must go THROUGH the proxy, otherwise nothing is captured
REM and the server will never see this machine's operations.
start "" "%CHROME%" --proxy-server="127.0.0.1:%PROXYPORT%" --proxy-bypass-list="<-loopback>" --user-data-dir="%LOCALAPPDATA%\af-lab-browser" --no-first-run --no-default-browser-check "http://%BOOKIP%:18080/console"

ping -n 3 127.0.0.1 >nul

REM Manager UI is opened WITHOUT the proxy on purpose: watching alerts
REM should not itself produce collected traffic.
start "" "http://%BOOKIP%:8443/ui#collusion"

echo.
echo ------------------------------------------------------------
echo   Manager UI login : admin / admin123
echo   Book console     : pick your account on the left, then click a step
echo.
echo   If the console shows nothing, run: python lab\verify_lan.py
echo ------------------------------------------------------------
echo.
pause
goto :eof

:nobrowser
echo Chrome / Edge not found.
echo Set your browser HTTP proxy to 127.0.0.1:%PROXYPORT% and open
echo   http://%BOOKIP%:18080/console
pause
goto :eof
