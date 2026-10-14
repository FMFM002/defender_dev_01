@echo off
title PC Guardian
chcp 65001 >nul 2>&1
cd /d "%~dp0.."
if errorlevel 1 (
    echo [ERROR] Cannot enter project directory: %~dp0..
    echo Press any key to exit...
    pause >nul
    exit /b 1
)

set "VENV_PY=%USERPROFILE%\.workbuddy\binaries\python\envs\pc-guardian\Scripts\python.exe"
set "PY=%VENV_PY%"
if not exist "%VENV_PY%" set "PY=py"

echo.
echo   ============================================
echo    PC Guardian  -  local backend
echo    Address : http://127.0.0.1:7890
echo    Python  : %PY%
echo    Stop    : run scripts\stop.bat
echo   ============================================
echo.

"%PY%" -m src.guardian.main
set "RC=%errorlevel%"
echo.
echo   PC Guardian stopped ^(exit code = %RC%^)
echo   Press any key to close this window...
pause >nul
