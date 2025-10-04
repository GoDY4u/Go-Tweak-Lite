# install.ps1 - INSTALLER DEFINITIVO CON MS-APPS
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
    
    # FIX: Handle the double folder structure
    Write-Host "🔧 Fixing folder structure..." -ForegroundColor Cyan
    
    # Find the actual extracted folder
    $extractedFolders = Get-ChildItem -Path $installPath -Directory | Where-Object { $_.Name -like "Go-Tweak*" }
    
    if ($extractedFolders.Count -gt 0) {
        $mainExtractedFolder = $extractedFolders[0].FullName
        
        # Move ALL contents from the extracted folder to the main install path
        Write-Host "📁 Moving files from: $($extractedFolders[0].Name)" -ForegroundColor Cyan
        Get-ChildItem -Path $mainExtractedFolder | ForEach-Object {
            Move-Item -Path $_.FullName -Destination $installPath -Force
        }
        
        # Remove the empty extracted folder
        Remove-Item -Path $mainExtractedFolder -Recurse -Force
    }
    
    # Remove zip file
    Remove-Item -Path $zipFile -Force
    
    # FIX: Move files from nested "Go-Tweak" folder if it exists
    $nestedFolder = Join-Path $installPath "Go-Tweak"
    if (Test-Path $nestedFolder) {
        Write-Host "📁 Fixing nested folder structure..." -ForegroundColor Cyan
        Get-ChildItem -Path $nestedFolder | ForEach-Object {
            Move-Item -Path $_.FullName -Destination $installPath -Force
        }
        Remove-Item -Path $nestedFolder -Recurse -Force
    }
    
    # CREATE OTHER TWEAKS FOLDER IF IT DOESN'T EXIST
    $otherTweaksPath = Join-Path $installPath "content\scripts\othertweaks"
    if (-not (Test-Path $otherTweaksPath)) {
        Write-Host "📁 Creating othertweaks folder..." -ForegroundColor Cyan
        New-Item -Path $otherTweaksPath -ItemType Directory -Force | Out-Null
    }
    
    # CREATE MS-APPS FOLDER IF IT DOESN'T EXIST
    $msAppsPath = Join-Path $installPath "content\scripts\ms-apps"
    if (-not (Test-Path $msAppsPath)) {
        Write-Host "📁 Creating ms-apps folder..." -ForegroundColor Cyan
        New-Item -Path $msAppsPath -ItemType Directory -Force | Out-Null
    }
    
    # DOWNLOAD OTHER TWEAKS FILES
    Write-Host "📥 Downloading other tweaks files..." -ForegroundColor Cyan
    $otherTweaksFiles = @(
        "other-tweaks.ps1",
        "revert-tweaks.ps1"
    )
    
    foreach ($file in $otherTweaksFiles) {
        try {
            $fileUrl = "https://raw.githubusercontent.com/GoDY4u/Go-Tweak-Lite/main/content/scripts/othertweaks/$file"
            $filePath = Join-Path $otherTweaksPath $file
            Invoke-WebRequest -Uri $fileUrl -OutFile $filePath -UseBasicParsing
            Write-Host "✅ $file" -ForegroundColor Green
        } catch {
            Write-Host "⚠️  Missing: $file" -ForegroundColor Yellow
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
            $filePath = Join-Path $msAppsPath $file
            Invoke-WebRequest -Uri $fileUrl -OutFile $filePath -UseBasicParsing
            Write-Host "✅ $file" -ForegroundColor Green
        } catch {
            Write-Host "⚠️  Missing: $file" -ForegroundColor Yellow
        }
    }
    
    # DESCARGAR EL SCRIPT PRINCIPAL CON CODIFICACIÓN UTF-8 CORRECTA
    Write-Host "🔧 Downloading Go-Tweak.ps1 with proper encoding..." -ForegroundColor Cyan
    $mainScriptPath = Join-Path $installPath "Go-Tweak.ps1"
    
    # Primero eliminar el archivo corrupto si existe
    if (Test-Path $mainScriptPath) {
        Remove-Item -Path $mainScriptPath -Force
    }
    
    # Descargar usando .NET WebClient para preservar UTF-8
    try {
        $webClient = New-Object System.Net.WebClient
        $webClient.Encoding = [System.Text.Encoding]::UTF8
        $scriptUrl = "https://raw.githubusercontent.com/GoDY4u/Go-Tweak-Lite/main/Go-Tweak.ps1"
        $scriptContent = $webClient.DownloadString($scriptUrl)
        
        # Guardar con codificación UTF-8 con BOM
        $utf8WithBom = New-Object System.Text.UTF8Encoding($true)
        [System.IO.File]::WriteAllText($mainScriptPath, $scriptContent, $utf8WithBom)
        
        Write-Host "✅ Go-Tweak.ps1 downloaded with correct UTF-8 encoding" -ForegroundColor Green
    } catch {
        Write-Host "❌ Failed to download with proper encoding, using fallback..." -ForegroundColor Red
        
        # Fallback: descargar normal y arreglar caracteres
        try {
            Invoke-WebRequest -Uri $scriptUrl -OutFile $mainScriptPath -UseBasicParsing
            
            # Arreglar caracteres corruptos
            if (Test-Path $mainScriptPath) {
                $content = Get-Content -Path $mainScriptPath -Raw
                
                # Reemplazar caracteres corruptos comunes
                $replacements = @{
                    'âœˆ' = '✨'
                    'ðŸš€' = '🚀'
                    'ðŸŽ§' = '🧠'
                    'ðŸŽ®' = '🎮'
                    'ðŸŽ¹' = '🌐'
                    'âš¡' = '⚡'
                    'ðŸ’©' = '📊'
                    'ðŸ’¡' = '🔧'
                    'ðŸ”´' = '🛡️'
                    'ðŸš•' = '🗑️'
                    'ðŸ’¦' = '📦'
                    'ðŸ”³' = '🔌'
                    'âž¡ï¸' = '↩️'
                    'ðŸšš' = '📥'
                    'ðŸšª' = '🚪'
                    'âœ…' = '✅'
                    'âš–ï¸' = '❌'
                    'âš–' = '❌'
                    '⚠ï¸' = '⚠️'
                    'â„¹ï¸' = 'ℹ️'
                    'â€' = '─'
                    'â”' = '┐'
                    'â”œ' = '┌'
                    'â”' = '┘'
                    'â”¬' = '└'
                    'â”‚' = '│'
                }
                
                foreach ($corrupted in $replacements.Keys) {
                    $content = $content -replace $corrupted, $replacements[$corrupted]
                }
                
                # Guardar con UTF-8 BOM
                $utf8WithBom = New-Object System.Text.UTF8Encoding($true)
                [System.IO.File]::WriteAllText($mainScriptPath, $content, $utf8WithBom)
                
                Write-Host "✅ Characters fixed manually" -ForegroundColor Green
            }
        } catch {
            Write-Host "❌ Completely failed to download main script" -ForegroundColor Red
        }
    }
    
    Write-Host "✅ Installation complete!" -ForegroundColor Green
    Write-Host "📍 Location: $installPath" -ForegroundColor Cyan
    
    # Verify final structure
    Write-Host "📋 Final structure:" -ForegroundColor Cyan
    Get-ChildItem -Path $installPath -Recurse -Directory | ForEach-Object {
        Write-Host "   📁 $($_.FullName.Replace($installPath, ''))" -ForegroundColor White
    }
    Get-ChildItem -Path $installPath -Recurse -File | ForEach-Object {
        Write-Host "   📄 $($_.FullName.Replace($installPath, ''))" -ForegroundColor Gray
    }
    
    # AUTO-RUN
    Write-Host "🎯 Starting Go-Tweak..." -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    
    # Ejecutar el script principal
    if (Test-Path $mainScriptPath) {
        # Verificar que los emojis estén bien
        $testContent = Get-Content -Path $mainScriptPath -Raw -Encoding UTF8
        if ($testContent -match '🚀|🧠|🎮|⚡|📊') {
            Write-Host "✅ Emojis verified successfully!" -ForegroundColor Green
        } else {
            Write-Host "⚠️  Some emojis may not display correctly" -ForegroundColor Yellow
        }
        
        # Ejecutar el script
        Write-Host "🚀 Launching Go-Tweak.ps1..." -ForegroundColor Green
        PowerShell -ExecutionPolicy Bypass -File "Go-Tweak.ps1"
    } else {
        Write-Host "❌ Main script not found: Go-Tweak.ps1" -ForegroundColor Red
        Write-Host "📋 Check the installation folder" -ForegroundColor Yellow
    }
    
} catch {
    Write-Host "❌ Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "📋 Download manually from GitHub" -ForegroundColor Yellow
    pause
}