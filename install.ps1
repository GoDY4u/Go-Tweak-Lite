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

# Create dedicated folder
$installPath = "C:\Go-Tweak-Lite"
Write-Host "📁 Creating installation folder: $installPath" -ForegroundColor Cyan

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
$zipFile = "$installPath\Go-Tweak-Lite.zip"

try {
    # Download zip
    Invoke-RestMethod -Uri $repoUrl -OutFile $zipFile
    
    # Extract files
    Write-Host "📦 Extracting files..." -ForegroundColor Cyan
    Expand-Archive -Path $zipFile -DestinationPath $installPath -Force
    
    # Move files to main folder (organized)
    Write-Host "🗂️  Organizing files..." -ForegroundColor Cyan
    Move-Item -Path "$installPath\Go-Tweak-Lite-main\*" -Destination $installPath -Force
    Remove-Item -Path "$installPath\Go-Tweak-Lite-main" -Recurse -Force
    Remove-Item -Path $zipFile -Force
    
    Write-Host "✅ Installation complete!" -ForegroundColor Green
    Write-Host "📍 Location: $installPath" -ForegroundColor Cyan
    Write-Host "🎯 Run: .\Go-Tweak.ps1" -ForegroundColor Yellow
    Write-Host "" 
    Write-Host "📋 Quick commands:" -ForegroundColor Magenta
    Write-Host "   cd $installPath" -ForegroundColor White
    Write-Host "   .\Go-Tweak.ps1" -ForegroundColor White
    
} catch {
    Write-Host "❌ Download failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "📋 Please download manually from:" -ForegroundColor Yellow
    Write-Host "   https://github.com/GoDY4u/Go-Tweak-Lite" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
pause
