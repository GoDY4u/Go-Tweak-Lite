# install.ps1 - INSTALLER DEFINITIVO

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

# Download repository
Write-Host "📥 Downloading Go-Tweak Lite..." -ForegroundColor Cyan
$repoUrl = "https://github.com/GoDY4u/Go-Tweak-Lite/archive/main.zip"
$zipFile = "$installPath\Go-Tweak-Lite.zip"

try {
    # Download zip
    Invoke-WebRequest -Uri $repoUrl -OutFile $zipFile -UseBasicParsing
    
    # Extract files
    Write-Host "📦 Extracting files..." -ForegroundColor Cyan
    Expand-Archive -Path $zipFile -DestinationPath $installPath -Force
    
    # Handle double folder structure
    Write-Host "🔧 Fixing folder structure..." -ForegroundColor Cyan
    $extractedFolders = Get-ChildItem -Path $installPath -Directory | Where-Object { $_.Name -like "Go-Tweak*" }
    
    if ($extractedFolders.Count -gt 0) {
        $mainExtractedFolder = $extractedFolders[0].FullName
        Write-Host "📁 Moving files from: $($extractedFolders[0].Name)" -ForegroundColor Cyan
        Get-ChildItem -Path $mainExtractedFolder | ForEach-Object {
            Move-Item -Path $_.FullName -Destination $installPath -Force
        }
        Remove-Item -Path $mainExtractedFolder -Recurse -Force
    }
    
    # Remove zip file
    Remove-Item -Path $zipFile -Force
    
    # FIX ERRORS IN MAIN SCRIPT
    Write-Host "🔧 Fixing errors in Go-Tweak.ps1..." -ForegroundColor Cyan
    $mainScriptPath = Join-Path $installPath "Go-Tweak.ps1"

    if (Test-Path $mainScriptPath) {
        $content = Get-Content -Path $mainScriptPath -Raw

        # Fix regex (line ~255)
        $content = $content -replace "if\s*\(\s*\$existingPlan\s*-and\s*\$existingPlan\s*-match\s*'.*?'\s*\)", "if (`$existingPlan -and `$existingPlan -match '(\{[a-fA-F0-9\-]+\})')"

        # Fix corrupted Write-Host (line ~829)
        $content = $content -replace 'âŒ Invalid option\. Try again\.', '❌ Invalid option. Try again.'

        # Save with proper UTF-8 encoding
        Set-Content -Path $mainScriptPath -Value $content -Encoding UTF8 -Force
        Write-Host "✅ Script errors fixed" -ForegroundColor Green
    }

    Write-Host "✅ Installation complete!" -ForegroundColor Green
    Write-Host "📍 Location: $installPath" -ForegroundColor Cyan
    
    # Verify final structure
    Write-Host "📋 Final structure:" -ForegroundColor Cyan
    Get-ChildItem -Path $installPath | ForEach-Object {
        Write-Host "   $($_.Name)" -ForegroundColor White
    }
    
    # AUTO-RUN
    Write-Host "🎯 Starting Go-Tweak..." -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    
    if (Test-Path $mainScriptPath) {
        PowerShell -ExecutionPolicy Bypass -File "Go-Tweak.ps1"
    } else {
        Write-Host "❌ Main script not found: Go-Tweak.ps1" -ForegroundColor Red
        Write-Host "📋 Check the installation folder" -ForegroundColor Yellow
        Write-Host "📋 Files in folder:" -ForegroundColor Cyan
        Get-ChildItem -Path $installPath | ForEach-Object {
            Write-Host "   - $($_.Name)" -ForegroundColor White
        }
    }

} catch {
    Write-Host "❌ Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "📋 Download manually from GitHub" -ForegroundColor Yellow
    pause
}
