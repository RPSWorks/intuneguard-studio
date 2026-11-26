@echo off
setlocal
title IntuneGuard Studio (Zero-Docker Local Launcher)
cd /d "%~dp0"

where py >nul 2>&1
if %errorlevel%==0 (
    set "PYCMD=py"
) else (
    where python >nul 2>&1
    if %errorlevel%==0 (
        set "PYCMD=python"
    ) else (
        echo [ERROR] Python 3.12+ was not found on PATH. Install Python 3.12+ and re-run.
        pause
        exit /b 1
    )
)

echo Starting IntuneGuard Studio at http://127.0.0.1:8095 ...
start "" cmd /c "timeout /t 2 /nobreak >nul && start http://127.0.0.1:8095"
%PYCMD% app.py
pause
