# install.ps1 - Go-Tweak Lite Installer
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

# Change to installation directory
Set-Location $installPath

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
    
    # Move files to main folder (organized)
    Write-Host "🗂️  Organizing files..." -ForegroundColor Cyan
    $tempFolder = Join-Path $installPath "Go-Tweak-Lite-main"
    if (Test-Path $tempFolder) {
        Move-Item -Path "$tempFolder\*" -Destination $installPath -Force
        Remove-Item -Path $tempFolder -Recurse -Force
    }
    Remove-Item -Path $zipFile -Force
    
    Write-Host "✅ Installation complete!" -ForegroundColor Green
    Write-Host "📍 Location: $installPath" -ForegroundColor Cyan
    
    # AUTO-RUN after installation
    Write-Host "🎯 Auto-starting Go-Tweak..." -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    Clear-Host
    & "$installPath\Go-Tweak.ps1"
    
} catch {
    Write-Host "❌ Download failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "📋 Please download manually from:" -ForegroundColor Yellow
    Write-Host "   https://github.com/GoDY4u/Go-Tweak-Lite" -ForegroundColor Cyan
    pause
}
