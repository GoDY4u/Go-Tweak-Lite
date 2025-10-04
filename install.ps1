# install.ps1 - VERSIÓN SIMPLIFICADA
Write-Host "🚀 Go-Tweak Lite Installer" -ForegroundColor Magenta
Write-Host "==========================================" -ForegroundColor Cyan

# Check admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "❌ Run as Administrator!" -ForegroundColor Red
    Write-Host "   Right-click -> Run as Administrator" -ForegroundColor Yellow
    pause
    exit 1
}

# Create folder directly in Desktop
$installPath = "$env:USERPROFILE\Desktop\Go-Tweak-Lite"
if (Test-Path $installPath) { 
    Remove-Item -Path "$installPath\*" -Recurse -Force 
} else { 
    New-Item -Path $installPath -ItemType Directory -Force | Out-Null 
}

Set-Location $installPath

Write-Host "📥 Downloading Go-Tweak Lite..." -ForegroundColor Cyan
$repoUrl = "https://github.com/GoDY4u/Go-Tweak-Lite/archive/main.zip"
$zipFile = "$installPath\Go-Tweak-Lite.zip"

try {
    # Descargar y extraer
    Invoke-WebRequest -Uri $repoUrl -OutFile $zipFile -UseBasicParsing
    Expand-Archive -Path $zipFile -DestinationPath $installPath -Force
    
    # Mover archivos a la ubicación correcta
    $extractedFolder = Get-ChildItem -Path $installPath -Directory | Where-Object { $_.Name -like "Go-Tweak*" } | Select-Object -First 1
    if ($extractedFolder) {
        Get-ChildItem -Path $extractedFolder.FullName | Move-Item -Destination $installPath -Force
        Remove-Item -Path $extractedFolder.FullName -Recurse -Force
    }
    
    Remove-Item -Path $zipFile -Force
    
    Write-Host "✅ Installation complete!" -ForegroundColor Green
    Write-Host "📍 Location: $installPath" -ForegroundColor Cyan
    
    # Auto-run
    Write-Host "🎯 Starting Go-Tweak..." -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    PowerShell -ExecutionPolicy Bypass -File "Go-Tweak.ps1"
    
} catch {
    Write-Host "❌ Error: $($_.Exception.Message)" -ForegroundColor Red
    pause
}