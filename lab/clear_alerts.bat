@echo off
REM ===========================================================================
REM 清空合谋告警，让实验从 0 开始
REM   不清图书业务数据（账号、图书、卷状态都保留），只清告警与画像。
REM   清完自动重启服务端与采集端，因为服务端把事件读在内存里、客户端不会自动重连。
REM   想连业务数据一起恢复出厂：clear_alerts.bat --hard
REM ===========================================================================
chcp 65001 >nul
cd /d "%~dp0.."
set "PY=%USERPROFILE%\.workbuddy\binaries\python\versions\3.13.12\python.exe"
if not exist "%PY%" (
  echo 找不到 Python 解释器：%PY%
  pause
  exit /b 1
)
"%PY%" lab\clear_alerts.py %*
echo.
pause
