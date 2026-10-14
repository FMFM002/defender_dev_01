@echo off
REM PC Guardian - 启动本地后台服务
REM
REM 用法：双击此文件，或在本目录打开终端执行 scripts\start.bat
REM 停止服务：运行 scripts\stop.bat

setlocal
REM 切到项目根目录（%~dp0 = scripts\）
cd /d "%~dp0.."

REM 优先使用本项目 venv 的 Python（依赖齐全）
set "VENV_PY=%USERPROFILE%\.workbuddy\binaries\python\envs\pc-guardian\Scripts\python.exe"
if exist "%VENV_PY%" (
    set "PY=%VENV_PY%"
) else (
    set "PY=py"
)

echo.
echo =^> 启动 PC Guardian（端口 7890）...
echo     使用解释器: %PY%
echo     停止服务请运行 scripts\stop.bat
echo.

"%PY%" -m src.guardian.main
endlocal