@echo off
rem 统一入口：真正干活的是 ..\启动器\3-启动采集客户端A.bat
rem 保留这个文件是为了兼容 clear_alerts.py / reset_lab.py / start_lab.bat 的调用，
rem 它们不用改，自动用上新的预检、端口占用检测和健康检查。
call "%~dp0..\启动器\3-启动采集客户端A.bat" quiet
