@echo off
rem Owner modes launcher. Keep this file ASCII with CRLF line endings:
rem cmd parses batch files byte by byte, and the Russian menu is printed by
rem tools\owner_menu.py after the console is switched to UTF-8.
rem Arguments are passed through, so "pw_menu.bat --profile test" opens the demo vault menu.
chcp 65001 >nul
cd /d "%~dp0"
.venv\Scripts\python.exe -X utf8 tools\owner_menu.py %*
if errorlevel 1 (
  echo.
  echo PW_STORAGE not started. Check that .venv\Scripts\python.exe exists.
  pause
)
