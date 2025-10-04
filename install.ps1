# install.ps1 - INSTALLER SIMPLIFICADO
Write-Host "=== Go-Tweak Lite Installer ===" -ForegroundColor Cyan

# Check admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: Run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click PowerShell -> Run as Administrator" -ForegroundColor Yellow
    pause
    exit 1
}

# Create folder
$installPath = "$env:USERPROFILE\Desktop\Go-Tweak-Lite"
if (Test-Path $installPath) { 
    Remove-Item -Path "$installPath\*" -Recurse -Force 
} else { 
    New-Item -Path $installPath -ItemType Directory -Force | Out-Null 
}

Set-Location $installPath

Write-Host "Downloading Go-Tweak Lite..." -ForegroundColor Cyan
$repoUrl = "https://github.com/GoDY4u/Go-Tweak-Lite/archive/main.zip"
$zipFile = "$installPath\Go-Tweak-Lite.zip"

try {
    # Download and extract
    Invoke-WebRequest -Uri $repoUrl -OutFile $zipFile -UseBasicParsing
    Expand-Archive -Path $zipFile -DestinationPath $installPath -Force
    
    # Fix folder structure
    $extractedFolder = Get-ChildItem -Path $installPath -Directory | Where-Object { $_.Name -like "Go-Tweak*" } | Select-Object -First 1
    if ($extractedFolder) {
        Write-Host "Organizing files..." -ForegroundColor Cyan
        Get-ChildItem -Path $extractedFolder.FullName | Move-Item -Destination $installPath -Force
        Remove-Item -Path $extractedFolder.FullName -Recurse -Force
    }
    
    Remove-Item -Path $zipFile -Force
    
    # Create missing folders
    $foldersToCreate = @(
        "content\scripts\othertweaks",
        "content\scripts\ms-apps"
    )
    
    foreach ($folder in $foldersToCreate) {
        $fullPath = Join-Path $installPath $folder
        if (-not (Test-Path $fullPath)) {
            New-Item -Path $fullPath -ItemType Directory -Force | Out-Null
        }
    }
    
    Write-Host "SUCCESS: Installation complete!" -ForegroundColor Green
    Write-Host "Location: $installPath" -ForegroundColor Cyan
    
    # Auto-run
    Write-Host "Starting Go-Tweak..." -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    
    if (Test-Path "Go-Tweak.ps1") {
        PowerShell -ExecutionPolicy Bypass -File "Go-Tweak.ps1"
    } else {
        Write-Host "ERROR: Go-Tweak.ps1 not found" -ForegroundColor Red
        Write-Host "Please download manually from GitHub" -ForegroundColor Yellow
    }
    
} catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Please download manually from GitHub" -ForegroundColor Yellow
    pause
}