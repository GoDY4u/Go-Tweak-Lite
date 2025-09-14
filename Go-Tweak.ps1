# Go-Tweak.ps1 - Windows Optimization Tool
# Requires administrator execution

param(
    [switch]$GUI,
    [switch]$Quiet,
    [string]$LogPath = ".\logs\go-tweak.log"
)

# Path configuration according to defined structure
$script:BasePath = $PSScriptRoot
$script:ContentPath = Join-Path $BasePath "content"
$script:ScriptsPath = Join-Path $ContentPath "scripts"
$script:RAMPath = Join-Path $ScriptsPath "ram"
$script:InternetPath = Join-Path $ScriptsPath "internet"
$script:GlobalOptimizationPath = Join-Path $ScriptsPath "globaloptimization"
$script:OtherTweaksPath = Join-Path $ScriptsPath "othertweaks"

# Check execution policy
if ((Get-ExecutionPolicy) -eq "Restricted") {
    Write-Host "SCRIPT EXECUTION DISABLED" -ForegroundColor Red
    Write-Host "==================================" -ForegroundColor Red
    Write-Host "To fix this issue, choose an option:" -ForegroundColor Yellow
    Write-Host "1. Run PowerShell as Administrator and use: Set-ExecutionPolicy RemoteSigned -Force" -ForegroundColor Cyan
    Write-Host "2. Or run this command: powershell.exe -ExecutionPolicy Bypass -File `"Go-Tweak.ps1`"" -ForegroundColor Cyan
    Write-Host "3. Or run temporarily: Set-ExecutionPolicy RemoteSigned -Scope Process -Force" -ForegroundColor Cyan
    exit 1
}

# Function to initialize folder structure
function Initialize-ProjectStructure {
    # Create logs folder if it doesn't exist
    $logDir = Split-Path $LogPath -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        Write-Host "Logs folder created: $logDir" -ForegroundColor Green
    }
    
    # Check if essential project folders exist
    $essentialFolders = @($ScriptsPath, $RAMPath, $InternetPath, $GlobalOptimizationPath, $OtherTweaksPath)
    foreach ($folder in $essentialFolders) {
        if (-not (Test-Path $folder)) {
            Write-Host "WARNING: Folder not found: $folder" -ForegroundColor Yellow
        }
    }
}

# Logging function
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    if (-not $Quiet) {
        # Display in different colors based on level
        switch ($Level) {
            "ERROR" { Write-Host $logEntry -ForegroundColor Red }
            "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
            "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
            default { Write-Host $logEntry -ForegroundColor White }
        }
    }
    
    Add-Content -Path $LogPath -Value $logEntry
}

# Check administrator execution
function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to create restore point (VERSIÓN SIMPLE)
function Create-RestorePoint {
    Write-Log "Opening System Restore creation tool..."
    
    try {
        # Abrir directamente la herramienta de crear punto de restauración
        Start-Process "systempropertiesprotection.exe"
        Write-Log "System Protection settings opened successfully" "SUCCESS"
        
        Write-Host "✅ Herramienta de puntos de restauración abierta" -ForegroundColor Green
        Write-Host "📋 Sigue estos pasos:" -ForegroundColor Cyan
        Write-Host "   1. Haz clic en 'Crear...'" -ForegroundColor White
        Write-Host "   2. Usa el nombre: 'Go-Tweak $(Get-Date -Format 'yyyy-MM-dd HH:mm')'" -ForegroundColor Yellow
        Write-Host "   3. Sigue las instrucciones" -ForegroundColor White
        Write-Host "   4. Cierra la ventana cuando termines" -ForegroundColor White
        
        return $true
    } catch {
        Write-Log "Error opening System Protection: $($_.Exception.Message)" "ERROR"
        Write-Host "❌ No se pudo abrir la herramienta de restauración" -ForegroundColor Red
        Write-Host "💡 Abre manualmente: Panel de Control → Sistema → Protección del sistema" -ForegroundColor Yellow
        return $false
    }
}

# Function to run Windows cleanup script
function Invoke-WindowsCleanup {
    Write-Log "Running Windows cleanup script..."
    
    $cleanupScript = Join-Path $ScriptsPath "wincleaner.bat"
    
    if (Test-Path $cleanupScript) {
        try {
            Write-Log "Executing Windows cleanup script..."
            Start-Process -FilePath $cleanupScript -Wait -Verb RunAs
            Write-Log "Windows cleanup completed successfully" "SUCCESS"
            return $true
        } catch {
            Write-Log "Error running cleanup script: $($_.Exception.Message)" "ERROR"
            return $false
        }
    } else {
        Write-Log "Cleanup script not found: $cleanupScript" "ERROR"
        return $false
    }
}

# Function to optimize RAM based on system memory
function Optimize-RAM {
    param([string]$RAMSize)
    
    Write-Log "Optimizing RAM for $RAMSize..."
    
    $ramScript = Join-Path $RAMPath "$RAMSize.reg"
    
    if (Test-Path $ramScript) {
        try {
            # Import registry file
            reg import $ramScript 2>&1 | Out-Null
            Write-Log "RAM optimized for $RAMSize successfully" "SUCCESS"
            
            # Restart Explorer to apply changes
            Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            Start-Process explorer.exe
            
            return $true
        } catch {
            Write-Log "Error optimizing RAM: $($_.Exception.Message)" "ERROR"
            return $false
        }
    } else {
        Write-Log "RAM optimization script not found: $ramScript" "ERROR"
        return $false
    }
}

# Function to show RAM optimization submenu
function Show-RAMMenu {
    Clear-Host
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "        RAM OPTIMIZATION" -ForegroundColor Magenta
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1. 4GB RAM" -ForegroundColor Yellow
    Write-Host "2. 6GB RAM" -ForegroundColor Yellow
    Write-Host "3. 8GB RAM" -ForegroundColor Yellow
    Write-Host "4. 12GB RAM" -ForegroundColor Yellow
    Write-Host "5. 16GB RAM" -ForegroundColor Yellow
    Write-Host "6. 24GB RAM" -ForegroundColor Yellow
    Write-Host "7. 32GB RAM" -ForegroundColor Yellow
    Write-Host "8. 64GB RAM" -ForegroundColor Yellow
    Write-Host "9. Restore Default Values" -ForegroundColor Green
    Write-Host "10. Return to main menu" -ForegroundColor Cyan
    Write-Host ""
}

# Function to execute optimization scripts (with enable/disable option)
function Invoke-OptimizationScript {
    param(
        [string]$ScriptCategory,
        [string]$ScriptName,
        [bool]$Enable,
        [string]$FriendlyName
    )
    
    $scriptFile = if ($Enable) {
        "active-$ScriptName"
    } else {
        "desactive-$ScriptName"
    }
    
    $scriptPath = Join-Path $ScriptsPath $ScriptCategory
    $scriptPath = Join-Path $scriptPath $scriptFile
    
    if (Test-Path $scriptPath) {
        Write-Log "Executing script: $scriptFile for $FriendlyName"
        try {
            if ($scriptPath.EndsWith(".reg")) {
                # Import registry
                reg import $scriptPath 2>&1 | Out-Null
                Write-Log "$FriendlyName $(if($Enable){'enabled'}else{'disabled'}) successfully" "SUCCESS"
            } elseif ($scriptPath.EndsWith(".bat")) {
                # Execute batch
                Start-Process -FilePath $scriptPath -Wait -Verb RunAs
                Write-Log "$FriendlyName $(if($Enable){'enabled'}else{'disabled'}) successfully" "SUCCESS"
            }
            return $true
        } catch {
            Write-Log "Error executing script ${scriptFile}: $($_.Exception.Message)" "ERROR"
            return $false
        }
    } else {
        Write-Log "Script not found: $scriptPath" "ERROR"
        return $false
    }
}

# Function to install GPEdit on Windows Home
function Install-GPEdit {
    Write-Log "Installing GPEdit (Group Policy Editor)..."
    
    $gpeditScript = Join-Path $ScriptsPath "gpedit-installer.bat"
    
    if (Test-Path $gpeditScript) {
        try {
            Write-Log "Executing GPEdit installer..."
            Start-Process -FilePath $gpeditScript -Wait -Verb RunAs
            Write-Log "GPEdit installed successfully" "SUCCESS"
            
            # Verify if installation was successful
            $gpeditExists = Test-Path "$env:Windir\System32\gpedit.msc"
            if ($gpeditExists) {
                Write-Log "GPEdit.msc is now available on your system" "SUCCESS"
                return $true
            } else {
                Write-Log "GPEdit installation may not have been completed" "WARNING"
                return $false
            }
        } catch {
            Write-Log "Error installing GPEdit: $($_.Exception.Message)" "ERROR"
            return $false
        }
    } else {
        Write-Log "GPEdit installer not found: $gpeditScript" "ERROR"
        return $false
    }
}

# Function to configure MAXIMUM performance power plan
function Set-MaxPerformancePowerPlan {
    Write-Log "Configuring MAXIMUM performance power plan..."
    
    try {
        $planName = "MaxPerformance From GoTweak"
        $planDescription = "Maximum performance power plan optimized by Go-Tweak for gaming and high FPS"
        
        # First check if our custom plan already exists
        $powerPlans = powercfg -list
        $existingPlan = $powerPlans | Where-Object { $_ -like "*$planName*" }
        
        # EXPRESIÓN REGULAR CORREGIDA
        if ($existingPlan -and $existingPlan -match '(\{[a-fA-F0-9\-]+\})') {
            # If exists, activate it
            $existingGuid = $matches[1]
            powercfg -setactive $existingGuid 2>&1 | Out-Null
            Write-Log "Existing maximum performance plan activated: $existingGuid" "SUCCESS"
            return $true
        }
        
        # If not exists, create from maximum performance plan
        Write-Log "Creating new MAXIMUM performance plan..."
        
        # GUID of Windows maximum performance plan
        $sourceGuid = "e9a42b02-d5df-448d-aa00-03f14749eb61"
        
        # Generate new GUID for our plan
        $newGuid = [guid]::NewGuid().ToString()
        
        # Duplicate the maximum performance plan
        $duplicateResult = powercfg -duplicatescheme $sourceGuid $newGuid 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Error duplicating plan: $duplicateResult" "ERROR"
            return $false
        }
        
        # Change name and description
        powercfg -changename $newGuid "$planName" "$planDescription" 2>&1 | Out-Null
        
        # Configure aggressive settings for maximum performance
        powercfg -setactive $newGuid 2>&1 | Out-Null
        powercfg -setdcvalueindex $newGuid SUB_PROCESSOR PROCTHROTTLEMAX 100 2>&1 | Out-Null
        powercfg -setacvalueindex $newGuid SUB_PROCESSOR PROCTHROTTLEMAX 100 2>&1 | Out-Null
        powercfg -setdcvalueindex $newGuid SUB_PROCESSOR PERFBOOSTMODE 2 2>&1 | Out-Null
        powercfg -setacvalueindex $newGuid SUB_PROCESSOR PERFBOOSTMODE 2 2>&1 | Out-Null
        
        # Force update of plan list
        $powerPlans = powercfg -list
        
        # Verify it was created correctly
        $createdPlan = $powerPlans | Where-Object { $_ -like "*$newGuid*" -and $_ -like "*$planName*" }
        
        if ($createdPlan) {
            Write-Log "MAXIMUM performance plan '$planName' created and activated successfully" "SUCCESS"
            Write-Log "New plan GUID: $newGuid" "INFO"
            return $true
        } else {
            Write-Log "Could not verify plan creation" "WARNING"
            return $true
        }
        
    } catch {
        Write-Log "Error configuring power plan: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Function to install Visual C++ and DirectX components via official Microsoft links
function Install-VisualsAndDirectX {
    Write-Log "Opening official Microsoft download pages..."
    
    try {
        # Abrir TODOS los enlaces necesarios
        $downloadLinks = @(
            "https://aka.ms/vs/16/release/vc_redist.x64.exe",
            "https://download.microsoft.com/download/1/7/1/1718CCC4-6315-4D8E-9543-8E28A4E18C4C/dxwebsetup.exe",
            "https://www.microsoft.com/en-us/download/details.aspx?id=8109"
        )
        
        foreach ($link in $downloadLinks) {
            Write-Log "Opening: $link"
            Start-Process $link
            Start-Sleep -Milliseconds 500  # Pequeña pausa entre enlaces
        }
        
        Write-Host "`n✅ Download pages opened successfully!" -ForegroundColor Green
        Write-Host "`n📥 Please download and install:" -ForegroundColor Cyan
        Write-Host "   1. Visual C++ Redistributable (vc_redist.x64.exe)" -ForegroundColor Yellow
        Write-Host "   2. DirectX Web Installer (dxwebsetup.exe)" -ForegroundColor Yellow
        Write-Host "   3. Run both installers as Administrator" -ForegroundColor Red
        Write-Host "`n⚡ These are essential for gaming and applications!" -ForegroundColor Magenta
        
        return $true
    } catch {
        Write-Log "Error opening browser: $($_.Exception.Message)" "ERROR"
        Write-Host "`n❌ Error opening browser" -ForegroundColor Red
        Write-Host "📋 Please manually visit these links:" -ForegroundColor Yellow
        Write-Host "   Visual C++: https://aka.ms/vs/16/release/vc_redist.x64.exe" -ForegroundColor Cyan
        Write-Host "   DirectX: https://download.microsoft.com/download/1/7/1/1718CCC4-6315-4D8E-9543-8E28A4E18C4C/dxwebsetup.exe" -ForegroundColor Cyan
        return $false
    }
}

# Function to open Keyboard Properties
function Open-KeyboardProperties {
    Write-Log "Opening keyboard properties..."
    try {
        # Open keyboard properties via Control Panel
        Start-Process "control.exe" -ArgumentList "keyboard"
        Write-Log "Keyboard properties opened successfully" "SUCCESS"
        return $true
    } catch {
        Write-Log "Error opening keyboard properties: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Function to open Mouse Properties
function Open-MouseProperties {
    Write-Log "Opening mouse properties..."
    try {
        # Open mouse properties via Control Panel
        Start-Process "control.exe" -ArgumentList "mouse"
        Write-Log "Mouse properties opened successfully" "SUCCESS"
        return $true
    } catch {
        Write-Log "Error opening mouse properties: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Function to open Performance Options
function Open-PerformanceOptions {
    Write-Log "Opening performance options..."
    try {
        # Run command to open performance options
        Start-Process "SystemPropertiesPerformance.exe"
        Write-Log "Performance options opened successfully" "SUCCESS"
        return $true
    } catch {
        Write-Log "Error opening performance options: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Function to open Device Manager
function Open-DeviceManager {
    Write-Log "Opening Device Manager..."
    try {
        Start-Process "devmgmt.msc"
        Write-Log "Device Manager opened successfully" "SUCCESS"
        return $true
    } catch {
        Write-Log "Error opening Device Manager: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Function to open Network Connections
function Open-NetworkConnections {
    Write-Log "Opening network connections..."
    try {
        Start-Process "ncpa.cpl"
        Write-Log "Network connections opened successfully" "SUCCESS"
        return $true
    } catch {
        Write-Log "Error opening network connections: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Function to apply other tweaks
function Invoke-OtherTweaks {
    Write-Log "Applying other system tweaks..."
    
    $otherTweaksScript = Join-Path $OtherTweaksPath "other-tweaks.ps1"
    
    if (Test-Path $otherTweaksScript) {
        try {
            Write-Log "Executing other tweaks script..."
            
            # Cambiar temporalmente la política de ejecución
            $originalPolicy = Get-ExecutionPolicy
            Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue
            
            & $otherTweaksScript
            
            # Restaurar la política original
            Set-ExecutionPolicy -ExecutionPolicy $originalPolicy -Scope Process -Force -ErrorAction SilentlyContinue
            
            Write-Log "Other tweaks applied successfully" "SUCCESS"
            return $true
        } catch {
            Write-Log "Error applying other tweaks: $($_.Exception.Message)" "ERROR"
            return $false
        }
    } else {
        Write-Log "Other tweaks script not found: $otherTweaksScript" "ERROR"
        return $false
    }
}

# Function to revert tweaks
function Invoke-RevertTweaks {
    Write-Log "Reverting system tweaks..."
    
    $revertScript = Join-Path $OtherTweaksPath "revert-tweaks.ps1"
    
    if (Test-Path $revertScript) {
        try {
            Write-Log "Executing revert tweaks script..."
            
            # Cambiar temporalmente la política de ejecución
            $originalPolicy = Get-ExecutionPolicy
            Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue
            
            & $revertScript
            
            # Restaurar la política original
            Set-ExecutionPolicy -ExecutionPolicy $originalPolicy -Scope Process -Force -ErrorAction SilentlyContinue
            
            Write-Log "Tweaks reverted successfully" "SUCCESS"
            return $true
        } catch {
            Write-Log "Error reverting tweaks: $($_.Exception.Message)" "ERROR"
            return $false
        }
    } else {
        Write-Log "Revert script not found: $revertScript" "ERROR"
        return $false
    }
}

# Show options menu
function Show-Menu {
    Clear-Host
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "           GO-TWEAK OPTIMIZER" -ForegroundColor Magenta
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "0. Create Restore Point" -ForegroundColor Green
    Write-Host "1. Windows Cleanup" -ForegroundColor Yellow
    Write-Host "2. RAM Optimization" -ForegroundColor Yellow
    Write-Host "3. Optimize FPS" -ForegroundColor Yellow
    Write-Host "4. Apply Other Tweaks" -ForegroundColor Yellow
    Write-Host "5. Optimize Internet" -ForegroundColor Yellow
    Write-Host "6. Install GPEdit (Windows Home)" -ForegroundColor Yellow
    Write-Host "7. Power Plan: Maximum Performance" -ForegroundColor Yellow
    Write-Host "8. Install Visual C++ & DirectX" -ForegroundColor Yellow
    Write-Host "9. Keyboard Properties" -ForegroundColor Cyan
    Write-Host "10. Mouse Properties" -ForegroundColor Cyan
    Write-Host "11. Performance Options" -ForegroundColor Cyan
    Write-Host "12. Device Manager" -ForegroundColor Cyan
    Write-Host "13. Network Connections" -ForegroundColor Cyan
    Write-Host "14. Disable Optimizations" -ForegroundColor Red
    Write-Host "15. Exit" -ForegroundColor Red
    Write-Host ""
}

# Function to show disable submenu
function Show-DisableMenu {
    Clear-Host
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "     DISABLE GO-TWEAK OPTIMIZATIONS" -ForegroundColor Red
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1. Disable FPS Optimization" -ForegroundColor Yellow
    Write-Host "2. Disable Internet Optimization" -ForegroundColor Yellow
    Write-Host "3. Revert Other Tweaks" -ForegroundColor Yellow
    Write-Host "4. Return to main menu" -ForegroundColor Green
    Write-Host ""
}

# Main function
function Main {
    # Initialize folder structure
    Initialize-ProjectStructure
    
    # Check administrator permissions
    if (-not (Test-Admin)) {
        Write-Log "This script must be run as administrator" "ERROR"
        Write-Host "Please run PowerShell as Administrator" -ForegroundColor Red
        exit 1
    }
    
    Write-Log "Starting Go-Tweak - Windows Optimizer" "SUCCESS"
    
    if ($GUI) {
        # Launch graphical interface
        Write-Log "Starting graphical interface..."
        Write-Host "GUI mode not yet implemented" -ForegroundColor Yellow
    } else {
        # Interactive console mode
        do {
            Show-Menu
            $choice = Read-Host "Select an option (0-15)"
            
            switch ($choice) {
                "0" { 
                    Write-Log "Opening restore point creation tool..."
                    $result = Create-RestorePoint
                    Read-Host "Press Enter to continue..."
                }
                "1" { 
                    Write-Log "Running Windows cleanup..."
                    $result = Invoke-WindowsCleanup
                    if ($result) {
                        Write-Host "✅ Windows cleanup completed successfully" -ForegroundColor Green
                    } else {
                        Write-Host "❌ Error running Windows cleanup" -ForegroundColor Red
                    }
                    Read-Host "Press Enter to continue..."
                }
                "2" { 
                    # RAM Optimization submenu
                    do {
                        Show-RAMMenu
                        $ramChoice = Read-Host "Select your RAM size (1-10)"
                        
                        switch ($ramChoice) {
                            "1" { 
                                Write-Log "Applying 4GB RAM optimization..."
                                $result = Optimize-RAM -RAMSize "4GB RAM"
                                if ($result) {
                                    Write-Host "✅ 4GB RAM optimization applied successfully" -ForegroundColor Green
                                } else {
                                    Write-Host "❌ Error applying 4GB RAM optimization" -ForegroundColor Red
                                }
                                Read-Host "Press Enter to continue..."
                            }
                            "2" { 
                                Write-Log "Applying 6GB RAM optimization..."
                                $result = Optimize-RAM -RAMSize "6GB RAM"
                                if ($result) {
                                    Write-Host "✅ 6GB RAM optimization applied successfully" -ForegroundColor Green
                                } else {
                                    Write-Host "❌ Error applying 6GB RAM optimization" -ForegroundColor Red
                                }
                                Read-Host "Press Enter to continue..."
                            }
                            "3" { 
                                Write-Log "Applying 8GB RAM optimization..."
                                $result = Optimize-RAM -RAMSize "8GB RAM"
                                if ($result) {
                                    Write-Host "✅ 8GB RAM optimization applied successfully" -ForegroundColor Green
                                } else {
                                    Write-Host "❌ Error applying 8GB RAM optimization" -ForegroundColor Red
                                }
                                Read-Host "Press Enter to continue..."
                            }
                            "4" { 
                                Write-Log "Applying 12GB RAM optimization..."
                                $result = Optimize-RAM -RAMSize "12GB RAM"
                                if ($result) {
                                    Write-Host "✅ 12GB RAM optimization applied successfully" -ForegroundColor Green
                                } else {
                                    Write-Host "❌ Error applying 12GB RAM optimization" -ForegroundColor Red
                                }
                                Read-Host "Press Enter to continue..."
                            }
                            "5" { 
                                Write-Log "Applying 16GB RAM optimization..."
                                $result = Optimize-RAM -RAMSize "16GB RAM"
                                if ($result) {
                                    Write-Host "✅ 16GB RAM optimization applied successfully" -ForegroundColor Green
                                } else {
                                    Write-Host "❌ Error applying 16GB RAM optimization" -ForegroundColor Red
                                }
                                Read-Host "Press Enter to continue..."
                            }
                            "6" { 
                                Write-Log "Applying 24GB RAM optimization..."
                                $result = Optimize-RAM -RAMSize "24GB RAM"
                                if ($result) {
                                    Write-Host "✅ 24GB RAM optimization applied successfully" -ForegroundColor Green
                                } else {
                                    Write-Host "❌ Error applying 24GB RAM optimization" -ForegroundColor Red
                                }
                                Read-Host "Press Enter to continue..."
                            }
                            "7" { 
                                Write-Log "Applying 32GB RAM optimization..."
                                $result = Optimize-RAM -RAMSize "32GB RAM"
                                if ($result) {
                                    Write-Host "✅ 32GB RAM optimization applied successfully" -ForegroundColor Green
                                } else {
                                    Write-Host "❌ Error applying 32GB RAM optimization" -ForegroundColor Red
                                }
                                Read-Host "Press Enter to continue..."
                            }
                            "8" { 
                                Write-Log "Applying 64GB RAM optimization..."
                                $result = Optimize-RAM -RAMSize "64GB RAM"
                                if ($result) {
                                    Write-Host "✅ 64GB RAM optimization applied successfully" -ForegroundColor Green
                                } else {
                                    Write-Host "❌ Error applying 64GB RAM optimization" -ForegroundColor Red
                                }
                                Read-Host "Press Enter to continue..."
                            }
                            "9" { 
                                Write-Log "Restoring default RAM values..."
                                $result = Optimize-RAM -RAMSize "Restablecer valores predeterminados"
                                if ($result) {
                                    Write-Host "✅ Default RAM values restored successfully" -ForegroundColor Green
                                } else {
                                    Write-Host "❌ Error restoring default RAM values" -ForegroundColor Red
                                }
                                Read-Host "Press Enter to continue..."
                            }
                            "10" { 
                                # Return to main menu
                                break
                            }
                            default {
                                Write-Host "❌ Invalid option. Try again." -ForegroundColor Red
                                Start-Sleep -Seconds 1
                            }
                        }
                    } while ($ramChoice -ne "10")
                }
                "3" { 
                    Write-Log "Applying FPS optimization..."
                    $result = Invoke-OptimizationScript -ScriptCategory "globaloptimization" -ScriptName "globaloptimization.reg" -Enable $true -FriendlyName "FPS Optimization"
                    if ($result) {
                        Write-Host "✅ FPS optimization enabled successfully" -ForegroundColor Green
                    } else {
                        Write-Host "❌ Error enabling FPS optimization" -ForegroundColor Red
                    }
                    Read-Host "Press Enter to continue..."
                }
                "4" { 
                    Write-Log "Applying other system tweaks..."
                    $result = Invoke-OtherTweaks
                    if ($result) {
                        Write-Host "✅ Other tweaks applied successfully" -ForegroundColor Green
                    } else {
                        Write-Host "❌ Error applying other tweaks" -ForegroundColor Red
                    }
                    Read-Host "Press Enter to continue..."
                }
                "5" { 
                    Write-Log "Applying internet optimization..."
                    $result = Invoke-OptimizationScript -ScriptCategory "internet" -ScriptName "internetscript.bat" -Enable $true -FriendlyName "Internet Optimization"
                    if ($result) {
                        Write-Host "✅ Internet optimization enabled successfully" -ForegroundColor Green
                    } else {
                        Write-Host "❌ Error enabling internet optimization" -ForegroundColor Red
                    }
                    Read-Host "Press Enter to continue..."
                }
                "6" { 
                    Write-Log "Installing GPEdit..."
                    $result = Install-GPEdit
                    if ($result) {
                        Write-Host "✅ GPEdit installed successfully" -ForegroundColor Green
                    } else {
                        Write-Host "❌ Error installing GPEdit" -ForegroundColor Red
                    }
                    Read-Host "Press Enter to continue..."
                }
                "7" { 
                    Write-Log "Configuring maximum performance power plan..."
                    $result = Set-MaxPerformancePowerPlan
                    if ($result) {
                        Write-Host "✅ MAXIMUM performance power plan configured successfully" -ForegroundColor Green
                    } else {
                        Write-Host "❌ Error configuring power plan" -ForegroundColor Red
                    }
                    Read-Host "Press Enter to continue..."
                }
                "8" { 
                    Write-Log "Installing components..."
                    $result = Install-VisualsAndDirectX
                    if ($result) {
                        Write-Host "✅ Microsoft download pages opened successfully!" -ForegroundColor Green
                        Write-Host "📥 Please check your browser for download links" -ForegroundColor Cyan
                    } else {
                        Write-Host "❌ Error opening browser" -ForegroundColor Red
                    }
                    Read-Host "Press Enter to continue..."
                }
                "9" { 
                    Write-Log "Opening keyboard properties..."
                    $result = Open-KeyboardProperties
                    if ($result) {
                        Write-Host "✅ Keyboard properties opened" -ForegroundColor Green
                    } else {
                        Write-Host "❌ Error opening keyboard properties" -ForegroundColor Red
                    }
                    Read-Host "Press Enter to continue..."
                }
                "10" { 
                    Write-Log "Opening mouse properties..."
                    $result = Open-MouseProperties
                    if ($result) {
                        Write-Host "✅ Mouse properties opened" -ForegroundColor Green
                    } else {
                        Write-Host "❌ Error opening mouse properties" -ForegroundColor Red
                    }
                    Read-Host "Press Enter to continue..."
                }
                "11" { 
                    Write-Log "Opening performance options..."
                    $result = Open-PerformanceOptions
                    if ($result) {
                        Write-Host "✅ Performance options opened" -ForegroundColor Green
                    } else {
                        Write-Host "❌ Error opening performance options" -ForegroundColor Red
                    }
                    Read-Host "Press Enter to continue..."
                }
                "12" { 
                    Write-Log "Opening Device Manager..."
                    $result = Open-DeviceManager
                    if ($result) {
                        Write-Host "✅ Device Manager opened" -ForegroundColor Green
                    } else {
                        Write-Host "❌ Error opening Device Manager" -ForegroundColor Red
                    }
                    Read-Host "Press Enter to continue..."
                }
                "13" { 
                    Write-Log "Opening network connections..."
                    $result = Open-NetworkConnections
                    if ($result) {
                        Write-Host "✅ Network connections opened" -ForegroundColor Green
                    } else {
                        Write-Host "❌ Error opening network connections" -ForegroundColor Red
                    }
                    Read-Host "Press Enter to continue..."
                }
                "14" { 
                    # Submenu to disable optimizations
                    do {
                        Show-DisableMenu
                        $disableChoice = Read-Host "Select an option (1-4)"
                        
                        switch ($disableChoice) {
                            "1" { 
                                Write-Log "Disabling FPS optimization..."
                                $result = Invoke-OptimizationScript -ScriptCategory "globaloptimization" -ScriptName "globaloptimization.reg" -Enable $false -FriendlyName "FPS Optimization"
                                if ($result) {
                                    Write-Host "✅ FPS optimization disabled successfully" -ForegroundColor Green
                                } else {
                                    Write-Host "❌ Error disabling FPS optimization" -ForegroundColor Red
                                }
                                Read-Host "Press Enter to continue..."
                            }
                            "2" { 
                                Write-Log "Disabling internet optimization..."
                                $result = Invoke-OptimizationScript -ScriptCategory "internet" -ScriptName "internetscript.bat" -Enable $false -FriendlyName "Internet Optimization"
                                if ($result) {
                                    Write-Host "✅ Internet optimization disabled successfully" -ForegroundColor Green
                                } else {
                                    Write-Host "❌ Error disabling internet optimization" -ForegroundColor Red
                                }
                                Read-Host "Press Enter to continue..."
                            }
                            "3" { 
                                Write-Log "Reverting other tweaks..."
                                $result = Invoke-RevertTweaks
                                if ($result) {
                                    Write-Host "✅ Other tweaks reverted successfully" -ForegroundColor Green
                                } else {
                                    Write-Host "❌ Error reverting other tweaks" -ForegroundColor Red
                                }
                                Read-Host "Press Enter to continue..."
                            }
                            "4" { 
                                # Return to main menu
                                break
                            }
                            default {
                                Write-Host "❌ Invalid option. Try again." -ForegroundColor Red
                                Start-Sleep -Seconds 1
                            }
                        }
                    } while ($disableChoice -ne "4")
                }
                "15" { 
                    Write-Log "Exiting Go-Tweak" "SUCCESS"
                    Write-Host "Goodbye! 👋" -ForegroundColor Green
                    exit 0
                }
                default {
                    Write-Host "❌ Invalid option. Try again." -ForegroundColor Red
                    Start-Sleep -Seconds 1
                }
            }
        } while ($true)
    }
}

# Script entry point
Main
