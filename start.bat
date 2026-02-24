@echo off
REM ============================================================
REM  SOSreport Analyzer V7 – Windows Launcher
REM
REM  Launches the full stack via WSL2.
REM  Prerequisites: WSL2 with an Ubuntu distro installed.
REM
REM  Double-click this file or run from a Command Prompt.
REM ============================================================

echo.
echo ===================================================
echo  SOSreport Analyzer V7 – Starting via WSL2
echo ===================================================
echo.

REM --- Convert the Windows path of this script to a WSL path -----------
set "WIN_DIR=%~dp0"
REM Remove trailing backslash
if "%WIN_DIR:~-1%"=="\" set "WIN_DIR=%WIN_DIR:~0,-1%"

REM --- Run setup.sh inside WSL ----------------------------------------
echo [1/2] Launching WSL and running setup.sh ...
wsl -e bash -c "cd \"$(wslpath '%WIN_DIR%')\" && chmod +x setup.sh && ./setup.sh"

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Something went wrong. Check the output above.
    pause
    exit /b 1
)

echo.
echo ===================================================
echo  All services are running!
echo.
echo   Streamlit App : http://localhost:8501
echo   InfluxDB      : http://localhost:8086
echo   Grafana       : http://localhost:3000
echo     user: admin   pass: sosreport2026
echo ===================================================
echo.

REM Open the browser automatically
start http://localhost:8501

pause
