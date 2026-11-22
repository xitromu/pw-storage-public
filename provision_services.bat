@echo off
rem Re-issues the secret packages of services and restarts them. Run elevated:
rem packages live in ProgramData and a service is controlled through the SCM.
rem Usage: provision_services.bat [deploy\services\my_service.json ...]
chcp 65001 >nul
cd /d "%~dp0"
.venv\Scripts\python.exe -X utf8 tools\provision_services.py %*
if errorlevel 1 (
  echo.
  echo Read the message above, then close this window.
  pause
)
