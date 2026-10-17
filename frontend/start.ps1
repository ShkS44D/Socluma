
# Socluma Frontend Startup Script
# Ensures frontend always starts on port 3000

Write-Host "=== Socluma Frontend Startup ===" -ForegroundColor Cyan

$PORT = 3000

# Step 1: Check for existing process on port 3000 (optional cleanup)
Write-Host "Checking for existing process on port $PORT..." -ForegroundColor Yellow
$portProcess = Get-NetTCPConnection -LocalPort $PORT -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -First 1

if ($portProcess) {
    Write-Host "Found process with PID $portProcess using port $PORT. Stopping it..." -ForegroundColor Red
    try {
        Stop-Process -Id $portProcess -Force -ErrorAction Stop
        Start-Sleep -Seconds 2
        Write-Host "Process stopped successfully!" -ForegroundColor Green
    } catch {
        Write-Warning "Warning: Could not stop process $portProcess - trying to proceed anyway..."
    }
} else {
    Write-Host "No existing process found on port $PORT." -ForegroundColor Green
}

# Step 2: Start frontend dev server
Write-Host "Starting frontend on http://localhost:$PORT..." -ForegroundColor Cyan
Write-Host "Press Ctrl+C to stop the frontend." -ForegroundColor Gray

npm run dev
