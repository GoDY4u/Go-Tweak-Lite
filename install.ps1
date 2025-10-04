# install.ps1 - INSTALLER CON EMOJIS VISUALES
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "           GO-TWEAK LITE INSTALLER" -ForegroundColor Magenta
Write-Host "==========================================" -ForegroundColor Cyan

# Check admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "❌ Run as Administrator!" -ForegroundColor Red
    Write-Host "   Right-click PowerShell -> Run as Administrator" -ForegroundColor Yellow
    pause
    exit 1
}

# Create folder
$installPath = "$env:USERPROFILE\Desktop\Go-Tweak-Lite"
if (Test-Path $installPath) { 
    Write-Host "🗑️  Cleaning old installation..." -ForegroundColor Yellow
    Remove-Item -Path "$installPath\*" -Recurse -Force 
} else { 
    New-Item -Path $installPath -ItemType Directory -Force | Out-Null 
}

Set-Location $installPath

Write-Host "📥 Downloading Go-Tweak Lite..." -ForegroundColor Cyan
$repoUrl = "https://github.com/GoDY4u/Go-Tweak-Lite/archive/main.zip"
$zipFile = "$installPath\Go-Tweak-Lite.zip"

try {
    # Download and extract
    Invoke-WebRequest -Uri $repoUrl -OutFile $zipFile -UseBasicParsing
    Write-Host "📦 Extracting files..." -ForegroundColor Cyan
    Expand-Archive -Path $zipFile -DestinationPath $installPath -Force
    
    # Fix folder structure
    $extractedFolder = Get-ChildItem -Path $installPath -Directory | Where-Object { $_.Name -like "Go-Tweak*" } | Select-Object -First 1
    if ($extractedFolder) {
        Write-Host "📁 Organizing files..." -ForegroundColor Cyan
        Get-ChildItem -Path $extractedFolder.FullName | Move-Item -Destination $installPath -Force
        Remove-Item -Path $extractedFolder.FullName -Recurse -Force
    }
    
    Remove-Item -Path $zipFile -Force
    
    # Create missing folders
    Write-Host "📁 Creating directories..." -ForegroundColor Cyan
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
    
    # DOWNLOAD OTHER TWEAKS FILES
    Write-Host "📥 Downloading additional files..." -ForegroundColor Cyan
    $otherTweaksFiles = @(
        "other-tweaks.ps1",
        "revert-tweaks.ps1"
    )
    
    foreach ($file in $otherTweaksFiles) {
        try {
            $fileUrl = "https://raw.githubusercontent.com/GoDY4u/Go-Tweak-Lite/main/content/scripts/othertweaks/$file"
            $filePath = Join-Path $installPath "content\scripts\othertweaks\$file"
            Invoke-WebRequest -Uri $fileUrl -OutFile $filePath -UseBasicParsing
            Write-Host "✅ $file" -ForegroundColor Green
        } catch {
            Write-Host "⚠️  $file" -ForegroundColor Yellow
        }
    }
    
    # DOWNLOAD MS-APPS FILES
    Write-Host "📥 Downloading MS Apps files..." -ForegroundColor Cyan
    $msAppsFiles = @(
        "remove-ms-apps.ps1",
        "restore-ms-apps.ps1"
    )
    
    foreach ($file in $msAppsFiles) {
        try {
            $fileUrl = "https://raw.githubusercontent.com/GoDY4u/Go-Tweak-Lite/main/content/scripts/ms-apps/$file"
            $filePath = Join-Path $installPath "content\scripts\ms-apps\$file"
            Invoke-WebRequest -Uri $fileUrl -OutFile $filePath -UseBasicParsing
            Write-Host "✅ $file" -ForegroundColor Green
        } catch {
            Write-Host "⚠️  $file" -ForegroundColor Yellow
        }
    }
    
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "✅ Installation complete!" -ForegroundColor Green
    Write-Host "📍 Location: $installPath" -ForegroundColor Cyan
    
    # Show final structure
    Write-Host "📋 Installed structure:" -ForegroundColor Cyan
    Get-ChildItem -Path $installPath -Recurse -Directory | ForEach-Object {
        Write-Host "   📁 $($_.FullName.Replace($installPath, ''))" -ForegroundColor White
    }
    Get-ChildItem -Path $installPath -File | ForEach-Object {
        Write-Host "   📄 $($_.Name)" -ForegroundColor Gray
    }
    
    # Auto-run
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "🎯 Starting Go-Tweak..." -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    
    if (Test-Path "Go-Tweak.ps1") {
        PowerShell -ExecutionPolicy Bypass -File "Go-Tweak.ps1"
    } else {
        Write-Host "❌ Go-Tweak.ps1 not found" -ForegroundColor Red
        Write-Host "📋 Check installation folder" -ForegroundColor Yellow
        Write-Host "   Press any key to open folder..." -ForegroundColor Gray
        pause
        Invoke-Item $installPath
    }
    
} catch {
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "❌ Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "📋 Download manually from GitHub" -ForegroundColor Yellow
    Write-Host "   Press any key to exit..." -ForegroundColor Gray
    pause
}