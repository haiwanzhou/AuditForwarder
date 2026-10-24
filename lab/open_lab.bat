@echo off
setlocal
cd /d "%~dp0.."

echo ============================================================
echo   AuditForwarder lab  -  open the two windows
echo ============================================================
echo.

set "CHROME=%ProgramFiles%\Google\Chrome\Application\chrome.exe"
if not exist "%CHROME%" set "CHROME=%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"
if not exist "%CHROME%" set "CHROME=%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"
if not exist "%CHROME%" goto nobrowser

echo   [1/2] book console  http://127.0.0.1:18080/console   (proxy 8888)
start "" "%CHROME%" --proxy-server="127.0.0.1:8888" --proxy-bypass-list="<-loopback>" --user-data-dir="%LOCALAPPDATA%\af-lab-browser" --no-first-run --no-default-browser-check "http://127.0.0.1:18080/console"

ping -n 3 127.0.0.1 >nul

echo   [2/2] manager UI    http://127.0.0.1:8443/ui
start "" "http://127.0.0.1:8443/ui#collusion"

echo.
echo ------------------------------------------------------------
echo   Manager UI login : admin / admin123
echo   The console window uses a SEPARATE browser profile,
echo   so it never touches your daily browser.
echo.
echo   Nothing captured? You are using a normal browser window.
echo   Always open the console through this file.
echo ------------------------------------------------------------
echo.
pause
goto :eof

:nobrowser
echo Chrome / Edge not found. Open these two URLs manually:
echo   http://127.0.0.1:18080/console
echo   http://127.0.0.1:8443/ui
pause
goto :eof
