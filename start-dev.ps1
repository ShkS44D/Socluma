
# VigilantAI Full Development Environment Startup Script
# Starts backend (port 8001), then frontend (port 3000)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  VigilantAI Development Environment" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Start backend in background job
Write-Host "[1/2] Starting backend on port 8001..." -ForegroundColor Yellow
$backendJob = Start-Job -ScriptBlock {
    Set-Location $using:PWD\backend
    .\start.ps1
}
Write-Host "Backend started (Job ID: $($backendJob.Id))" -ForegroundColor Green
Start-Sleep -Seconds 4

# Start frontend in current terminal
Write-Host "[2/2] Starting frontend on port 3000..." -ForegroundColor Yellow
Write-Host ""
Set-Location frontend
.\start.ps1
