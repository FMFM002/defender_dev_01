@echo off
title PC Guardian - ASR Rules
chcp 65001 >nul 2>&1
setlocal
cd /d "%~dp0.."

REM --- self-elevate to administrator ---
net session >nul 2>&1
if not "%errorlevel%"=="0" (
    echo [info] Requesting administrator privileges...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo.
echo   PC Guardian - ASR rule tool ^(running as administrator^)
echo.

set "VENV_PY=%USERPROFILE%\.workbuddy\binaries\python\envs\pc-guardian\Scripts\python.exe"
set "PY=%VENV_PY%"
if not exist "%VENV_PY%" set "PY=python"

set "ARGS=%*"
if "%ARGS%"=="" set "ARGS=--p1"

"%PY%" -m src.guardian.tools.apply_asr %ARGS%
set "RC=%errorlevel%"

echo.
echo   Done ^(exit code = %RC%^)
echo   Press any key to close this window...
pause >nul
endlocal
