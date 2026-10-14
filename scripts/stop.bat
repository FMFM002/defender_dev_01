@echo off
title PC Guardian - stop
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion
echo   Stopping PC Guardian ^(freeing port 7890^)...
set "FOUND="
for /f "tokens=5" %%p in ('netstat -ano -p tcp ^| findstr ":7890" ^| findstr "LISTENING"') do (
    set "FOUND=1"
    echo   Killing PID %%p
    taskkill /F /PID %%p >nul 2>&1
)
if not defined FOUND echo   No listener found on port 7890.
echo   Done.
echo   Press any key to close...
pause >nul
endlocal
