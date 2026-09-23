@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ============================================
echo   AuditForwarder Client 启动
echo ============================================
echo.
echo 工作目录: %CD%
echo 配置文件: config\client_windows.yaml
echo.
auditforwarder-client.exe -c config\client_windows.yaml -L info
echo.
echo 客户端已退出，按任意键关闭...
pause >nul
