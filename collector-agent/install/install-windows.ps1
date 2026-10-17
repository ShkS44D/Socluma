param(
  [Parameter(Mandatory=$true)][string]$EnrollmentToken,
  [Parameter(Mandatory=$true)][string]$BackendUrl,
  [string]$InstallDirectory = "$env:ProgramData\Socluma\Collector"
)
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $InstallDirectory | Out-Null
Write-Host "Install the signed collector package into $InstallDirectory, then enroll it once:"
Write-Host "python main.py --enrollment-token <redacted> --backend-url $BackendUrl"
Write-Host "Store the returned credential using Windows service credentials or DPAPI; never place it in logs."
Write-Host "Create a restricted Windows service account and configure automatic restart in Services."
