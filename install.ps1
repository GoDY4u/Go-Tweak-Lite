# install.ps1 - INSTALLER DEFINITIVO CON OTHER TWEAKS
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
        Write-Host "📁 Moving files from: $($extractedFolders[0).Name)" -ForegroundColor Cyan
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
    
    # CORREGIR ERRORES EN EL ARCHIVO PRINCIPAL
    Write-Host "🔧 Fixing errors in Go-Tweak.ps1..." -ForegroundColor Cyan
    $mainScriptPath = Join-Path $installPath "Go-Tweak.ps1"
    
    if (Test-Path $mainScriptPath) {
        # Leer el contenido del archivo
        $content = Get-Content -Path $mainScriptPath -Raw
        
        # CORREGIR ERROR 1: Expresión regular mal formada (línea ~254)
        $content = $content -replace '\(\{\[a-fA-F0-9\\-\]\+\}\)', '(\{[a-fA-F0-9\-]+\})'
        
        # CORREGIR ERROR 2: Caracteres corruptos en Write-Host (línea ~828)
        $content = $content -replace 'Write-Host "âŒ Invalid option. Try again."', 'Write-Host "❌ Invalid option. Try again."'
        
        # Guardar el archivo corregido
        Set-Content -Path $mainScriptPath -Value $content -Force
        Write-Host "✅ Script errors fixed" -ForegroundColor Green
    }
    
    Write-Host "✅ Installation complete!" -ForegroundColor Green
    Write-Host "📍 Location: $installPath" -ForegroundColor Cyan
    
    # Verify final structure
    Write-Host "📋 Final structure:" -ForegroundColor Cyan
    Get-ChildItem -Path $installPath | ForEach-Object {
        Write-Host "   $($_.Name)" -ForegroundColor White
    }
    
    # AUTO-RUN - CORREGIDO: Sin el punto y barra invertida extra
    Write-Host "🎯 Starting Go-Tweak..." -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    
    # Ejecutar el script principal - FORMA CORRECTA
    if (Test-Path $mainScriptPath) {
        # Cambiar al directorio de instalación primero
        Set-Location $installPath
        # Ejecutar el script
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
