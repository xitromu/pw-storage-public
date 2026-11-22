@echo off
rem Builds the virtualenv and installs the pinned dependencies (hashes verified).
rem Requires Python 3.11 or newer on PATH. Override with:  set PY_EXE=py -3.12
setlocal
cd /d "%~dp0"
if "%PY_EXE%"=="" set PY_EXE=python
%PY_EXE% -V
%PY_EXE% -c "import sys;sys.exit(0 if sys.version_info[:2] >= (3, 11) else 1)"
if errorlevel 1 (
  echo Python 3.11 or newer is required. See docs\install.md.
  pause
  exit /b 1
)
%PY_EXE% -m venv .venv
if errorlevel 1 goto fail
.venv\Scripts\python.exe -m pip install --upgrade pip
if errorlevel 1 goto fail
.venv\Scripts\python.exe -m pip install --require-hashes -r requirements.txt
if errorlevel 1 goto fail
echo.
echo Dependencies installed. Next:  pw_menu.bat --profile test   (menu item N creates the demo vault)
pause
exit /b 0

:fail
echo.
echo Installation stopped. See the messages above and docs\install.md.
pause
exit /b 1
