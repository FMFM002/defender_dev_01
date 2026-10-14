@echo off
REM PC Guardian - 停止本地后台服务（释放端口 7890）
REM
REM 用法：双击此文件即可。会查找占用 7890 端口的进程并结束它。

setlocal enabledelayedexpansion
set PORT=7890

echo.
echo =^> 查找占用端口 %PORT% 的进程...

set PID=
for /f "tokens=5" %%a in ('netstat -ano -p TCP ^| findstr ":%PORT% " ^| findstr "LISTENING"') do (
    set PID=%%a
)

if "%PID%"=="" (
    echo     没有进程占用端口 %PORT%，服务可能未在运行。
    goto :end
)

echo     发现进程 PID=%PID%
echo     正在结束...
taskkill /F /PID %PID% >nul 2>&1

if %errorlevel% equ 0 (
    echo     已结束 PID=%PID%，端口 %PORT% 已释放。
) else (
    echo     结束失败，请手动在任务管理器结束 PID=%PID%。
)

:end
echo.
pause
endlocal