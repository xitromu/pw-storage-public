@echo off
rem Gives a Windows service account read+execute access to this virtualenv.
rem A service runs as NT SERVICE\<name>, which cannot read a normal user profile,
rem so the packages directory must be opened for it explicitly. Windows creates
rem that account when the service is registered: install the service first, then
rem run this. Elevated (right-click -> Run as administrator).
rem Usage: grant_service_read.bat PW_MYBOT [path	o\.venv]
setlocal
cd /d "%~dp0"
if "%~1"=="" (
  echo Usage: grant_service_read.bat SERVICE_NAME [VENV_PATH]
  exit /b 1
)
set VENV=%~dp0.venv
if not "%~2"=="" set VENV=%~2
net session >nul 2>nul
if errorlevel 1 (
  echo This window is NOT elevated. Right-click and choose "Run as administrator".
  pause
  exit /b 1
)
echo Granting NT SERVICE\%~1 read access to %VENV%
icacls "%VENV%" /grant "NT SERVICE\%~1:(OI)(CI)RX" /T /C /Q
if errorlevel 1 (
  echo Failed. Is the service installed? If Windows resolves the name poorly, grant the
  echo SID instead: powershell -Command "(New-Object Security.Principal.NTAccount('NT SERVICE\%~1')).Translate([Security.Principal.SecurityIdentifier]).Value"
  pause
  exit /b 1
)
echo Done. Check it with:  .venv\Scripts\python.exe -X utf8 -m pw_storage.service_host status --name %~1
pause
exit /b 0
