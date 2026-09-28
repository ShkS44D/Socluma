
# VigilantAI Backend Startup Script
# Ensures backend always starts on port 8001 by cleaning up any existing process first

Write-Host "=== VigilantAI Backend Startup ===" -ForegroundColor Cyan

$PORT = 8001

# Step 1: Check for existing process on the configured port
Write-Host "Checking for existing process on port $PORT..." -ForegroundColor Yellow
$portProcess = Get-NetTCPConnection -LocalPort $PORT -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -First 1

if ($portProcess) {
    Write-Host "Found process with PID $portProcess using port $PORT. Stopping it..." -ForegroundColor Red
    try {
        Stop-Process -Id $portProcess -Force -ErrorAction Stop
        Start-Sleep -Seconds 2  # Wait a bit for port to free up
        Write-Host "Process stopped successfully!" -ForegroundColor Green
    } catch {
        Write-Warning "Warning: Could not stop process $portProcess - trying to proceed anyway..."
    }
} else {
    Write-Host "No existing process found on port $PORT." -ForegroundColor Green
}

# Step 2: Start the backend with uvicorn
Write-Host "Starting backend on http://0.0.0.0:$PORT with reload..." -ForegroundColor Cyan
Write-Host "Press Ctrl+C to stop the backend." -ForegroundColor Gray

python -m uvicorn src.main:app --reload --host 0.0.0.0 --port $PORT
