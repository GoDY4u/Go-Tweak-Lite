# install.ps1 - Go-Tweak Lite Installer (FIXED VERSION)
Write-Host "🚀 Go-Tweak Lite Installer" -ForegroundColor Magenta
Write-Host "==========================================" -ForegroundColor Cyan

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "❌ Please run as Administrator!" -ForegroundColor Red
    Write-Host "   Right-click -> Run as Administrator" -ForegroundColor Yellow
    pause
    exit 1
}

# Create folder on Desktop
$desktopPath = [Environment]::GetFolderPath("Desktop")
$installPath = Join-Path $desktopPath "Go-Tweak-Lite"

Write-Host "📁 Creating folder on Desktop: Go-Tweak-Lite" -ForegroundColor Cyan

if (Test-Path $installPath) {
    Write-Host "⚠️  Folder already exists. Cleaning..." -ForegroundColor Yellow
    Remove-Item -Path "$installPath\*" -Recurse -Force
} else {
    New-Item -Path $installPath -ItemType Directory -Force | Out-Null
}

# Download repository
Write-Host "📥 Downloading Go-Tweak Lite..." -ForegroundColor Cyan
$repoUrl = "https://github.com/GoDY4u/Go-Tweak-Lite/archive/main.zip"
$zipFile = Join-Path $installPath "Go-Tweak-Lite.zip"

try {
    # Download zip
    Invoke-RestMethod -Uri $repoUrl -OutFile $zipFile
    
    # Extract files
    Write-Host "📦 Extracting files..." -ForegroundColor Cyan
    Expand-Archive -Path $zipFile -DestinationPath $installPath -Force
    
    # FIX: Move files from the subfolder to main folder
    Write-Host "🗂️  Organizing files..." -ForegroundColor Cyan
    $subFolder = Get-ChildItem -Path $installPath -Directory | Where-Object { $_.Name -like "Go-Tweak-Lite*" } | Select-Object -First 1
    
    if ($subFolder) {
        Write-Host "📁 Moving files from: $($subFolder.Name)" -ForegroundColor Cyan
        Move-Item -Path "$($subFolder.FullName)\*" -Destination $installPath -Force
        Remove-Item -Path $subFolder.FullName -Recurse -Force
    }
    
    Remove-Item -Path $zipFile -Force
    
    Write-Host "✅ Installation complete!" -ForegroundColor Green
    Write-Host "📍 Location: $installPath" -ForegroundColor Cyan
    
    # Verify structure
    Write-Host "📋 Verifying structure..." -ForegroundColor Cyan
    if (Test-Path "$installPath\content\scripts") {
        Write-Host "✅ Scripts folder found!" -ForegroundColor Green
    } else {
        Write-Host "❌ Scripts folder missing!" -ForegroundColor Red
    }
    
    # AUTO-RUN after installation
    Write-Host "🎯 Auto-starting Go-Tweak..." -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    Set-Location $installPath
    & "$installPath\Go-Tweak.ps1"
    
} catch {
    Write-Host "❌ Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "📋 Please download manually from:" -ForegroundColor Yellow
    Write-Host "   https://github.com/GoDY4u/Go-Tweak-Lite" -ForegroundColor Cyan
    pause
}
