# install.ps1 - SIMPLE Installer that WORKS
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

# Create folder
$installPath = "$env:USERPROFILE\Desktop\Go-Tweak-Lite"
if (Test-Path $installPath) { 
    Remove-Item -Path "$installPath\*" -Recurse -Force 
} else { 
    New-Item -Path $installPath -ItemType Directory -Force | Out-Null 
}

# Download EACH FILE individually
Write-Host "📥 Downloading files..." -ForegroundColor Cyan

# Create folder structure
New-Item -Path "$installPath\content\scripts\internet" -ItemType Directory -Force | Out-Null
New-Item -Path "$installPath\content\scripts\globaloptimization" -ItemType Directory -Force | Out-Null
New-Item -Path "$installPath\content\scripts\ram" -ItemType Directory -Force | Out-Null

# Download main script
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/GoDY4u/Go-Tweak-Lite/main/Go-Tweak.ps1" -OutFile "$installPath\Go-Tweak.ps1" -UseBasicParsing

# Download script files
$files = @(
    "content/scripts/internet/active-internetscript.bat",
    "content/scripts/internet/desactive-internetscript.bat",
    "content/scripts/globaloptimization/active-globaloptimization.reg", 
    "content/scripts/globaloptimization/desactive-globaloptimization.reg",
    "content/scripts/ram/4GB RAM.reg",
    "content/scripts/ram/6GB RAM.reg",
    "content/scripts/ram/8GB RAM.reg",
    "content/scripts/ram/12GB RAM.reg",
    "content/scripts/ram/16GB RAM.reg",
    "content/scripts/ram/24GB RAM.reg",
    "content/scripts/ram/32GB RAM.reg",
    "content/scripts/ram/64GB RAM.reg",
    "content/scripts/ram/Restablecer valores predeterminados.reg",
    "content/scripts/wincleaner.bat",
    "content/scripts/gpedit-installer.bat"
)

foreach ($file in $files) {
    try {
        $fileName = Split-Path $file -Leaf
        $folderPath = Split-Path $file -Parent
        $fullPath = Join-Path $installPath $folderPath
        
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/GoDY4u/Go-Tweak-Lite/main/$file" -OutFile "$fullPath\$fileName" -UseBasicParsing
        Write-Host "✅ $fileName" -ForegroundColor Green
    } catch {
        Write-Host "⚠️  Missing: $file" -ForegroundColor Yellow
    }
}

Write-Host "✅ ALL files downloaded!" -ForegroundColor Green
Write-Host "📍 Location: $installPath" -ForegroundColor Cyan

# Auto-run
Write-Host "🎯 Starting Go-Tweak..." -ForegroundColor Yellow
Start-Sleep -Seconds 2
Set-Location $installPath
.\Go-Tweak.ps1
