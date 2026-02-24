# ============================================================
#  SOSreport Analyzer V7 – Windows Launcher (PowerShell)
#
#  Run from PowerShell:
#    .\start.ps1
# ============================================================

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host " SOSreport Analyzer V7 – Starting via WSL2"         -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host ""

# Convert script directory to WSL path
$winDir = $PSScriptRoot
$wslDir = wsl wslpath "$winDir"

Write-Host "[1/2] Launching WSL and running setup.sh ..." -ForegroundColor Yellow
wsl -e bash -c "cd '$wslDir' && chmod +x setup.sh && ./setup.sh"

if ($LASTEXITCODE -ne 0) {
    Write-Host "`n[ERROR] Something went wrong. Check the output above." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host ""
Write-Host "===================================================" -ForegroundColor Green
Write-Host " All services are running!"                          -ForegroundColor Green
Write-Host ""
Write-Host "   Streamlit App : http://localhost:8501"
Write-Host "   InfluxDB      : http://localhost:8086"
Write-Host "   Grafana       : http://localhost:3000"
Write-Host "     user: admin   pass: sosreport2026"
Write-Host "===================================================" -ForegroundColor Green
Write-Host ""

# Open browser
Start-Process "http://localhost:8501"

Read-Host "Press Enter to exit"
