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

# Download repository
Write-Host "📥 Downloading Go-Tweak Lite..." -ForegroundColor Cyan
$repoUrl = "https://github.com/GoDY4u/Go-Tweak-Lite/archive/main.zip"
$zipFile = "Go-Tweak-Lite.zip"

try {
    # Download zip
    Invoke-RestMethod -Uri $repoUrl -OutFile $zipFile
    
    # Extract files
    Write-Host "📦 Extracting files..." -ForegroundColor Cyan
    Expand-Archive -Path $zipFile -DestinationPath . -Force
    
    # Move files to current directory
    Move-Item -Path "Go-Tweak-Lite-main\*" -Destination . -Force
    Remove-Item -Path "Go-Tweak-Lite-main" -Recurse -Force
    Remove-Item -Path $zipFile -Force
    
    Write-Host "✅ Installation complete!" -ForegroundColor Green
    Write-Host "🎯 Run: .\Go-Tweak.ps1" -ForegroundColor Yellow
    
} catch {
    Write-Host "❌ Download failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "📋 Please download manually from:" -ForegroundColor Yellow
    Write-Host "   https://github.com/GoDY4u/Go-Tweak-Lite" -ForegroundColor Cyan
}

pause