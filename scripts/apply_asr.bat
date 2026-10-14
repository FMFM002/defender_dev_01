@echo off
REM PC Guardian — ASR 规则启用工具（自动请求管理员权限）
REM
REM 用法：双击此文件，自动以管理员身份运行 apply_asr.py
REM 等价命令：python -m src.guardian.tools.apply_asr --p1

setlocal
cd /d "%~dp0\.."

REM 自提升：检测管理员权限，没有则用 PowerShell 提权后重启本脚本
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [info] 正在请求提升权限...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo.
echo =^> PC Guardian ASR 规则启用工具
echo.

REM 尝试用 venv 的 Python，否则 fallback 系统 Python
set "PY=%~dp0..\venv\Scripts\python.exe"
if not exist "%PY%" set "PY=python"

"%PY%" -m src.guardian.tools.apply_asr %*
endlocal