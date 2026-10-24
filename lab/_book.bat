@echo off
cd /d "%~dp0.."
"%USERPROFILE%\.workbuddy\binaries\python\versions\3.13.12\python.exe" lab\book_system\backend\app.py > data\lab_book.log 2>&1
