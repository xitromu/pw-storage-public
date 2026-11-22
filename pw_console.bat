@echo off
rem Opens the broker with the demo vault (test_data). The main vault uses:
rem   .venv\Scripts\python.exe -X utf8 -m pw_storage.broker --profile main
chcp 65001 >nul
cd /d "%~dp0"
.venv\Scripts\python.exe -X utf8 -m pw_storage.broker --profile test
echo.
pause
