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
$script:MSAppsPath = Join-Path $ScriptsPath "ms-apps"

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
    $essentialFolders = @($ScriptsPath, $RAMPath, $InternetPath, $GlobalOptimizationPath, $OtherTweaksPath, $MSAppsPath)
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

# Function to get detailed system information
function Get-DetailedSystemInfo {
    try {
        $cpu = (Get-CimInstance Win32_Processor).Name
        $gpu = (Get-CimInstance Win32_VideoController).Name
        $motherboard = (Get-CimInstance Win32_BaseBoard).Product
        $ramBytes = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
        $ramGB = [math]::Round($ramBytes / 1GB, 2)
        $windowsEdition = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ProductName
        $drives = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
        
        $systemInfo = @{
            CPU = if ($cpu) { $cpu.Split('@')[0].Trim() } else { "Unknown" }
            GPU = if ($gpu) { $gpu } else { "Unknown" }
            Motherboard = if ($motherboard) { $motherboard } else { "Unknown" }
            RAM_GB = $ramGB
            WindowsEdition = $windowsEdition
            Drives = $drives | ForEach-Object { 
                "$($_.DeviceID) $([math]::Round($_.Size/1GB, 0))GB ($([math]::Round(($_.Size - $_.FreeSpace)/$_.Size*100, 0))% used)" 
            }
        }
        return $systemInfo
    } catch {
        return @{
            CPU = "Unknown"
            GPU = "Unknown"
            Motherboard = "Unknown"
            RAM_GB = "Unknown"
            WindowsEdition = "Windows"
            Drives = @("Unknown")
        }
    }
}

# Function to show enhanced main menu
function Show-EnhancedMenu {
    Clear-Host
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║               🚀 GO-TWEAK OPTIMIZER             ║" -ForegroundColor Magenta
    Write-Host "║           Ultimate Windows Optimization         ║" -ForegroundColor Yellow
    Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    # Show detailed system info
    $systemInfo = Get-DetailedSystemInfo
    Write-Host "💻 SYSTEM INFORMATION:" -ForegroundColor White
    Write-Host "   CPU: $($systemInfo.CPU)" -ForegroundColor Gray
    Write-Host "   GPU: $($systemInfo.GPU)" -ForegroundColor Gray
    Write-Host "   Motherboard: $($systemInfo.Motherboard)" -ForegroundColor Gray
    Write-Host "   RAM: $($systemInfo.RAM_GB) GB" -ForegroundColor Gray
    Write-Host "   Windows: $($systemInfo.WindowsEdition)" -ForegroundColor Gray
    Write-Host "   Drives: $($systemInfo.Drives -join ', ')" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "┌──────────────────────────────────────────────────┐" -ForegroundColor DarkGray
    Write-Host "│  1. 🛡️  Create Restore Point                   │" -ForegroundColor Cyan
    Write-Host "└──────────────────────────────────────────────────┘" -ForegroundColor DarkGray
    Write-Host ""
    
    Write-Host "🔧 MAIN OPTIMIZATIONS" -ForegroundColor Green
    Write-Host "┌──────────────────────────────────────────────────┐" -ForegroundColor DarkGray
    Write-Host "│  2. 🗑️  Windows Cleanup                        │" -ForegroundColor Yellow
    Write-Host "│  3. 🧠 RAM Optimization                         │" -ForegroundColor Yellow
    Write-Host "│  4. 🎮 Optimize FPS (Gaming)                    │" -ForegroundColor Yellow
    Write-Host "│  5. 📦 Remove Microsoft Apps                    │" -ForegroundColor Yellow
    Write-Host "│  6. ⚡ Apply Other Tweaks                       │" -ForegroundColor Yellow
    Write-Host "│  7. 🌐 Optimize Internet                        │" -ForegroundColor Yellow
    Write-Host "│  8. 🔧 Install GPEdit (Windows Home)            │" -ForegroundColor Yellow
    Write-Host "│  9. ⚡ Power Plan: Maximum Performance          │" -ForegroundColor Yellow
    Write-Host "│ 10. 📥 Install Visual C++ & DirectX             │" -ForegroundColor Yellow
    Write-Host "└──────────────────────────────────────────────────┘" -ForegroundColor DarkGray
    
    Write-Host ""
    Write-Host "⚙️  CONFIGURATION TOOLS" -ForegroundColor Magenta
    Write-Host "┌──────────────────────────────────────────────────┐" -ForegroundColor DarkGray
    Write-Host "│ 11. ⌨️  Keyboard Properties                     │" -ForegroundColor White
    Write-Host "│ 12. 🖱️  Mouse Properties                       │" -ForegroundColor White
    Write-Host "│ 13. 📊 Performance Options                      │" -ForegroundColor White
    Write-Host "│ 14. 🔌 Device Manager                           │" -ForegroundColor White
    Write-Host "│ 15. 🌐 Network Connections                      │" -ForegroundColor White
    Write-Host "└──────────────────────────────────────────────────┘" -ForegroundColor DarkGray
    
    Write-Host ""
    Write-Host "🔄 OPTIMIZATION MANAGEMENT" -ForegroundColor Red
    Write-Host "┌──────────────────────────────────────────────────┐" -ForegroundColor DarkGray
    Write-Host "│ 16. ↩️  Disable Optimizations                   │" -ForegroundColor Red
    Write-Host "└──────────────────────────────────────────────────┘" -ForegroundColor DarkGray
    
    Write-Host ""
    Write-Host "┌──────────────────────────────────────────────────┐" -ForegroundColor DarkGray
    Write-Host "│ 17. 🚪 Exit Program                            │" -ForegroundColor Red
    Write-Host "└──────────────────────────────────────────────────┘" -ForegroundColor DarkGray
    Write-Host ""
}

# Function to show enhanced RAM menu
function Show-EnhancedRAMMenu {
    Clear-Host
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                 🧠 RAM OPTIMIZATION             ║" -ForegroundColor Magenta
    Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "💡 Select your system RAM amount:" -ForegroundColor White
    Write-Host ""
    Write-Host "┌──────────────────────────────────────────────────┐" -ForegroundColor DarkGray
    Write-Host "│  1. 4GB RAM                                     │" -ForegroundColor Yellow
    Write-Host "│  2. 6GB RAM                                     │" -ForegroundColor Yellow
    Write-Host "│  3. 8GB RAM                                     │" -ForegroundColor Yellow
    Write-Host "│  4. 12GB RAM                                    │" -ForegroundColor Yellow
    Write-Host "│  5. 16GB RAM                                    │" -ForegroundColor Yellow
    Write-Host "│  6. 24GB RAM                                    │" -ForegroundColor Yellow
    Write-Host "│  7. 32GB RAM                                    │" -ForegroundColor Yellow
    Write-Host "│  8. 64GB RAM                                    │" -ForegroundColor Yellow
    Write-Host "└──────────────────────────────────────────────────┘" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "┌──────────────────────────────────────────────────┐" -ForegroundColor DarkGray
    Write-Host "│  9. 🔄 Restore Default Values                   │" -ForegroundColor Green
    Write-Host "│ 10. ↩️  Return to Main Menu                     │" -ForegroundColor Cyan
    Write-Host "└──────────────────────────────────────────────────┘" -ForegroundColor DarkGray
    Write-Host ""
}

# Function to show enhanced disable menu
function Show-EnhancedDisableMenu {
    Clear-Host
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║           🔄 DISABLE OPTIMIZATIONS              ║" -ForegroundColor Red
    Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "⚠️  Select optimization to disable:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "┌──────────────────────────────────────────────────┐" -ForegroundColor DarkGray
    Write-Host "│  1. ❌ Disable FPS Optimization                 │" -ForegroundColor Red
    Write-Host "│  2. ❌ Disable Internet Optimization            │" -ForegroundColor Red
    Write-Host "│  3. 🔄 Revert Other Tweaks                      │" -ForegroundColor Yellow
    Write-Host "│  4. 📦 Restore Microsoft Apps                   │" -ForegroundColor Yellow
    Write-Host "└──────────────────────────────────────────────────┘" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "┌──────────────────────────────────────────────────┐" -ForegroundColor DarkGray
    Write-Host "│  5. ↩️  Return to Main Menu                     │" -ForegroundColor Green
    Write-Host "└──────────────────────────────────────────────────┘" -ForegroundColor DarkGray
    Write-Host ""
}

# Function to show loading animation
function Show-LoadingAnimation {
    param([string]$Message, [int]$Seconds = 2)
    
    $chars = @('|', '/', '-', '\')
    $endTime = (Get-Date).AddSeconds($Seconds)
    
    while ((Get-Date) -lt $endTime) {
        foreach ($char in $chars) {
            Write-Host "`r$Message $char" -NoNewline -ForegroundColor Cyan
            Start-Sleep -Milliseconds 100
        }
    }
    Write-Host "`r$Message ✓" -ForegroundColor Green
}

# Function to show notification
function Show-Notification {
    param([string]$Title, [string]$Message, [string]$Type = "Info")
    
    $icon = switch ($Type) {
        "Success" { "✅" }
        "Warning" { "⚠️" }
        "Error" { "❌" }
        default { "ℹ️" }
    }
    
    Write-Host "`n$icon $Title" -ForegroundColor $(switch ($Type) {
        "Success" { "Green" }
        "Warning" { "Yellow" }
        "Error" { "Red" }
        default { "Cyan" }
    })
    Write-Host "   $Message" -ForegroundColor White
    Write-Host ""
}

# Function to create restore point
function Create-RestorePoint {
    Write-Log "Opening System Restore creation tool..."
    
    try {
        # Open system protection directly
        Start-Process "systempropertiesprotection.exe"
        Write-Log "System Protection settings opened successfully" "SUCCESS"
        
        Show-Notification "Restore Point Tool Opened" "Follow these steps in the opened window:" "Info"
        Write-Host "   1. Click 'Create...'" -ForegroundColor White
        Write-Host "   2. Use name: 'Go-Tweak $(Get-Date -Format 'yyyy-MM-dd HH:mm')'" -ForegroundColor Yellow
        Write-Host "   3. Follow the instructions" -ForegroundColor White
        Write-Host "   4. Close the window when done" -ForegroundColor White
        
        return $true
    } catch {
        Write-Log "Error opening System Protection: $($_.Exception.Message)" "ERROR"
        Show-Notification "Error" "Could not open restore point tool" "Error"
        Write-Host "   Open manually: Control Panel → System → System Protection" -ForegroundColor Yellow
        return $false
    }
}

# Function to run Windows cleanup script
function Invoke-WindowsCleanup {
    Write-Log "Running Windows cleanup script..."
    Show-LoadingAnimation "Cleaning up Windows files..." 2
    
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
    Show-LoadingAnimation "Applying RAM optimization..." 2
    
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
        Show-LoadingAnimation "Applying $FriendlyName..." 2
        
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
    Show-LoadingAnimation "Installing Group Policy Editor..." 3
    
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
    Write-Log "Configuring MAXIMUM performance power plan..." "INFO"
    Show-LoadingAnimation "Configuring power plan for maximum performance..." 3
    
    try {
        $planName = "MaxPerformance From GoTweak"
        $planDescription = "Maximum performance power plan optimized by Go-Tweak for gaming and high FPS"
        
        # First check if our custom plan already exists
        $powerPlans = powercfg -list
        $existingPlan = $powerPlans | Where-Object { $_ -like "*$planName*" }
        
        if ($existingPlan -and $existingPlan -match '{.*}') {
            # If exists, activate it
            $existingGuid = $matches[0]
            powercfg -setactive $existingGuid 2>&1 | Out-Null
            Write-Log "Existing maximum performance plan activated: $existingGuid" "SUCCESS"
            
            # Apply advanced optimizations to existing plan
            Apply-AdvancedPowerOptimizations -planGuid $existingGuid
            return $true
        }
        
        # If not exists, create from maximum performance plan
        Write-Log "Creating new MAXIMUM performance plan..." "INFO"
        
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
        
        # Apply ALL advanced optimizations
        Apply-AdvancedPowerOptimizations -planGuid $newGuid
        
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

function Apply-AdvancedPowerOptimizations {
    param([string]$planGuid)
    
    Write-Log "Applying advanced power optimizations..." "INFO"
    
    try {
        # Configure processor for maximum performance (100% in both AC and DC)
        powercfg -setdcvalueindex $planGuid SUB_PROCESSOR PROCTHROTTLEMAX 100 2>&1 | Out-Null
        powercfg -setacvalueindex $planGuid SUB_PROCESSOR PROCTHROTTLEMAX 100 2>&1 | Out-Null
        
        # Disable USB selective suspend (keep USB devices always active)
        powercfg -setdcvalueindex $planGuid 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0 2>&1 | Out-Null
        powercfg -setacvalueindex $planGuid 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0 2>&1 | Out-Null
        
        # Configure PCI Express for maximum performance (off = maximum performance)
        powercfg -setdcvalueindex $planGuid 501a4d13-42af-4429-9fd1-a8218c268e20 ee12f906-d277-404b-b6da-e5fa1a576df5 0 2>&1 | Out-Null
        powercfg -setacvalueindex $planGuid 501a4d13-42af-4429-9fd1-a8218c268e20 ee12f906-d277-404b-b6da-e5fa1a576df5 0 2>&1 | Out-Null
        
        # Configure processor performance boost
        powercfg -setdcvalueindex $planGuid 54533251-82be-4824-96c1-47b60b740d00 893dee8e-2bef-41e0-89c6-b55d0929964c 100 2>&1 | Out-Null
        powercfg -setacvalueindex $planGuid 54533251-82be-4824-96c1-47b60b740d00 893dee8e-2bef-41e0-89c6-b55d0929964c 100 2>&1 | Out-Null
        powercfg -setdcvalueindex $planGuid 54533251-82be-4824-96c1-47b60b740d00 bc5038f7-23e0-4960-96da-33abaf5935ec 100 2>&1 | Out-Null
        powercfg -setacvalueindex $planGuid 54533251-82be-4824-96c1-47b60b740d00 bc5038f7-23e0-4960-96da-33abaf5935ec 100 2>&1 | Out-Null
        
        # Apply all changes
        powercfg -setactive $planGuid 2>&1 | Out-Null
        
        Write-Log "Advanced power optimizations applied successfully" "SUCCESS"
        return $true
        
    } catch {
        Write-Log "Error applying advanced power optimizations: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Function to install Visual C++ and DirectX components via official Microsoft links
function Install-VisualsAndDirectX {
    Write-Log "Opening official Microsoft download pages..."
    
    try {
        # Open ALL necessary links
        $downloadLinks = @(
            "https://aka.ms/vs/16/release/vc_redist.x64.exe",
            "https://download.microsoft.com/download/1/7/1/1718CCC4-6315-4D8E-9543-8E28A4E18C4C/dxwebsetup.exe",
            "https://www.microsoft.com/en-us/download/details.aspx?id=8109"
        )
        
        foreach ($link in $downloadLinks) {
            Write-Log "Opening: $link"
            Start-Process $link
            Start-Sleep -Milliseconds 500  # Small pause between links
        }
        
        Show-Notification "Download Pages Opened" "Please download and install the following components:" "Success"
        Write-Host "   1. Visual C++ Redistributable (vc_redist.x64.exe)" -ForegroundColor Yellow
        Write-Host "   2. DirectX Web Installer (dxwebsetup.exe)" -ForegroundColor Yellow
        Write-Host "   3. Run both installers as Administrator" -ForegroundColor Red
        Write-Host "`n⚡ These are essential for gaming and applications!" -ForegroundColor Magenta
        
        return $true
    } catch {
        Write-Log "Error opening browser: $($_.Exception.Message)" "ERROR"
        Show-Notification "Error" "Could not open browser automatically" "Error"
        Write-Host "   Please manually visit these links:" -ForegroundColor Yellow
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
    Show-LoadingAnimation "Applying system tweaks..." 3
    
    $otherTweaksScript = Join-Path $OtherTweaksPath "other-tweaks.ps1"
    
    if (Test-Path $otherTweaksScript) {
        try {
            Write-Log "Executing other tweaks script..."
            
            # Temporarily change execution policy
            $originalPolicy = Get-ExecutionPolicy
            Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue
            
            & $otherTweaksScript
            
            # Restore original policy
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
    Show-LoadingAnimation "Reverting system tweaks..." 3
    
    $revertScript = Join-Path $OtherTweaksPath "revert-tweaks.ps1"
    
    if (Test-Path $revertScript) {
        try {
            Write-Log "Executing revert tweaks script..."
            
            # Temporarily change execution policy
            $originalPolicy = Get-ExecutionPolicy
            Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue
            
            & $revertScript
            
            # Restore original policy
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

# Function to remove Microsoft Apps
function Remove-MSApps {
    Write-Log "Removing Microsoft Apps..."
    Show-LoadingAnimation "Removing Microsoft Apps..." 3
    
    $removeScript = Join-Path $MSAppsPath "remove-ms-apps.ps1"
    
    if (Test-Path $removeScript) {
        try {
            Write-Log "Executing Microsoft Apps removal script..."
            
            # Temporarily change execution policy
            $originalPolicy = Get-ExecutionPolicy
            Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue
            
            & $removeScript
            
            # Restore original policy
            Set-ExecutionPolicy -ExecutionPolicy $originalPolicy -Scope Process -Force -ErrorAction SilentlyContinue
            
            Write-Log "Microsoft Apps removed successfully" "SUCCESS"
            return $true
        } catch {
            Write-Log "Error removing Microsoft Apps: $($_.Exception.Message)" "ERROR"
            return $false
        }
    } else {
        Write-Log "Remove MS Apps script not found: $removeScript" "ERROR"
        return $false
    }
}

# Function to restore Microsoft Apps
function Restore-MSApps {
    Write-Log "Restoring Microsoft Apps..."
    Show-LoadingAnimation "Restoring Microsoft Apps..." 3
    
    $restoreScript = Join-Path $MSAppsPath "restore-ms-apps.ps1"
    
    if (Test-Path $restoreScript) {
        try {
            Write-Log "Executing Microsoft Apps restoration script..."
            
            # Temporarily change execution policy
            $originalPolicy = Get-ExecutionPolicy
            Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue
            
            & $restoreScript
            
            # Restore original policy
            Set-ExecutionPolicy -ExecutionPolicy $originalPolicy -Scope Process -Force -ErrorAction SilentlyContinue
            
            Write-Log "Microsoft Apps restored successfully" "SUCCESS"
            return $true
        } catch {
            Write-Log "Error restoring Microsoft Apps: $($_.Exception.Message)" "ERROR"
            return $false
        }
    } else {
        Write-Log "Restore MS Apps script not found: $restoreScript" "ERROR"
        return $false
    }
}

# Main function
function Main {
    # Initialize folder structure
    Initialize-ProjectStructure
    
    # Check administrator permissions
    if (-not (Test-Admin)) {
        Write-Log "This script must be run as administrator" "ERROR"
        Show-Notification "Administrator Rights Required" "Please run PowerShell as Administrator" "Error"
        exit 1
    }
    
    Write-Log "Starting Go-Tweak - Windows Optimizer" "SUCCESS"
    Show-Notification "Go-Tweak Started" "Windows optimization tool initialized successfully" "Success"
    
    if ($GUI) {
        # Launch graphical interface
        Write-Log "Starting graphical interface..."
        Write-Host "GUI mode not yet implemented" -ForegroundColor Yellow
    } else {
        # Interactive console mode
        do {
            Show-EnhancedMenu
            $choice = Read-Host "Select an option (1-17)"
            
            switch ($choice) {
                "1" { 
                    Write-Log "Creating restore point..."
                    $result = Create-RestorePoint
                    Read-Host "Press Enter to continue..."
                }
                "2" { 
                    Write-Log "Running Windows cleanup..."
                    $result = Invoke-WindowsCleanup
                    if ($result) {
                        Show-Notification "Windows Cleanup Complete" "Temporary files and cache cleared successfully" "Success"
                    } else {
                        Show-Notification "Cleanup Error" "There was an error during Windows cleanup" "Error"
                    }
                    Read-Host "Press Enter to continue..."
                }
                "3" { 
                    # RAM Optimization submenu
                    do {
                        Show-EnhancedRAMMenu
                        $ramChoice = Read-Host "Select your RAM size (1-10)"
                        
                        switch ($ramChoice) {
                            "1" { 
                                Write-Log "Applying 4GB RAM optimization..."
                                $result = Optimize-RAM -RAMSize "4GB RAM"
                                if ($result) {
                                    Show-Notification "RAM Optimized" "4GB RAM optimization applied successfully" "Success"
                                } else {
                                    Show-Notification "Optimization Error" "Error applying 4GB RAM optimization" "Error"
                                }
                                Read-Host "Press Enter to continue..."
                            }
                            "2" { 
                                Write-Log "Applying 6GB RAM optimization..."
                                $result = Optimize-RAM -RAMSize "6GB RAM"
                                if ($result) {
                                    Show-Notification "RAM Optimized" "6GB RAM optimization applied successfully" "Success"
                                } else {
                                    Show-Notification "Optimization Error" "Error applying 6GB RAM optimization" "Error"
                                }
                                Read-Host "Press Enter to continue..."
                            }
                            "3" { 
                                Write-Log "Applying 8GB RAM optimization..."
                                $result = Optimize-RAM -RAMSize "8GB RAM"
                                if ($result) {
                                    Show-Notification "RAM Optimized" "8GB RAM optimization applied successfully" "Success"
                                } else {
                                    Show-Notification "Optimization Error" "Error applying 8GB RAM optimization" "Error"
                                }
                                Read-Host "Press Enter to continue..."
                            }
                            "4" { 
                                Write-Log "Applying 12GB RAM optimization..."
                                $result = Optimize-RAM -RAMSize "12GB RAM"
                                if ($result) {
                                    Show-Notification "RAM Optimized" "12GB RAM optimization applied successfully" "Success"
                                } else {
                                    Show-Notification "Optimization Error" "Error applying 12GB RAM optimization" "Error"
                                }
                                Read-Host "Press Enter to continue..."
                            }
                            "5" { 
                                Write-Log "Applying 16GB RAM optimization..."
                                $result = Optimize-RAM -RAMSize "16GB RAM"
                                if ($result) {
                                    Show-Notification "RAM Optimized" "16GB RAM optimization applied successfully" "Success"
                                } else {
                                    Show-Notification "Optimization Error" "Error applying 16GB RAM optimization" "Error"
                                }
                                Read-Host "Press Enter to continue..."
                            }
                            "6" { 
                                Write-Log "Applying 24GB RAM optimization..."
                                $result = Optimize-RAM -RAMSize "24GB RAM"
                                if ($result) {
                                    Show-Notification "RAM Optimized" "24GB RAM optimization applied successfully" "Success"
                                } else {
                                    Show-Notification "Optimization Error" "Error applying 24GB RAM optimization" "Error"
                                }
                                Read-Host "Press Enter to continue..."
                            }
                            "7" { 
                                Write-Log "Applying 32GB RAM optimization..."
                                $result = Optimize-RAM -RAMSize "32GB RAM"
                                if ($result) {
                                    Show-Notification "RAM Optimized" "32GB RAM optimization applied successfully" "Success"
                                } else {
                                    Show-Notification "Optimization Error" "Error applying 32GB RAM optimization" "Error"
                                }
                                Read-Host "Press Enter to continue..."
                            }
                            "8" { 
                                Write-Log "Applying 64GB RAM optimization..."
                                $result = Optimize-RAM -RAMSize "64GB RAM"
                                if ($result) {
                                    Show-Notification "RAM Optimized" "64GB RAM optimization applied successfully" "Success"
                                } else {
                                    Show-Notification "Optimization Error" "Error applying 64GB RAM optimization" "Error"
                                }
                                Read-Host "Press Enter to continue..."
                            }
                            "9" { 
                                Write-Log "Restoring default RAM values..."
                                $result = Optimize-RAM -RAMSize "Restablecer valores predeterminados"
                                if ($result) {
                                    Show-Notification "Defaults Restored" "Default RAM values restored successfully" "Success"
                                } else {
                                    Show-Notification "Restore Error" "Error restoring default RAM values" "Error"
                                }
                                Read-Host "Press Enter to continue..."
                            }
                            "10" { 
                                # Return to main menu
                                break
                            }
                            default {
                                Show-Notification "Invalid Option" "Please select a valid option (1-10)" "Error"
                                Start-Sleep -Seconds 1
                            }
                        }
                    } while ($ramChoice -ne "10")
                }
                "4" { 
                    Write-Log "Applying FPS optimization..."
                    $result = Invoke-OptimizationScript -ScriptCategory "globaloptimization" -ScriptName "globaloptimization.reg" -Enable $true -FriendlyName "FPS Optimization"
                    if ($result) {
                        Show-Notification "FPS Optimization Enabled" "Gaming performance optimizations applied successfully" "Success"
                    } else {
                        Show-Notification "Optimization Error" "Error enabling FPS optimization" "Error"
                    }
                    Read-Host "Press Enter to continue..."
                }
                "5" { 
                    Write-Log "Removing Microsoft Apps..."
                    $result = Remove-MSApps
                    if ($result) {
                        Show-Notification "Apps Removed" "Microsoft Apps removed successfully" "Success"
                    } else {
                        Show-Notification "Removal Error" "Error removing Microsoft Apps" "Error"
                    }
                    Read-Host "Press Enter to continue..."
                }
                "6" { 
                    Write-Log "Applying other system tweaks..."
                    $result = Invoke-OtherTweaks
                    if ($result) {
                        Show-Notification "Tweaks Applied" "System tweaks applied successfully" "Success"
                    } else {
                        Show-Notification "Tweak Error" "Error applying system tweaks" "Error"
                    }
                    Read-Host "Press Enter to continue..."
                }
                "7" { 
                    Write-Log "Applying internet optimization..."
                    $result = Invoke-OptimizationScript -ScriptCategory "internet" -ScriptName "internetscript.bat" -Enable $true -FriendlyName "Internet Optimization"
                    if ($result) {
                        Show-Notification "Internet Optimized" "Network optimizations applied successfully" "Success"
                    } else {
                        Show-Notification "Optimization Error" "Error enabling internet optimization" "Error"
                    }
                    Read-Host "Press Enter to continue..."
                }
                "8" { 
                    Write-Log "Installing GPEdit..."
                    $result = Install-GPEdit
                    if ($result) {
                        Show-Notification "GPEdit Installed" "Group Policy Editor installed successfully" "Success"
                    } else {
                        Show-Notification "Installation Error" "Error installing GPEdit" "Error"
                    }
                    Read-Host "Press Enter to continue..."
                }
                "9" { 
                    Write-Log "Configuring maximum performance power plan..."
                    $result = Set-MaxPerformancePowerPlan
                    if ($result) {
                        Show-Notification "Power Plan Configured" "Maximum performance power plan activated successfully" "Success"
                    } else {
                        Show-Notification "Configuration Error" "Error configuring power plan" "Error"
                    }
                    Read-Host "Press Enter to continue..."
                }
                "10" { 
                    Write-Log "Opening Visual C++ and DirectX download pages..."
                    $result = Install-VisualsAndDirectX
                    Read-Host "Press Enter to continue..."
                }
                "11" { 
                    Write-Log "Opening keyboard properties..."
                    $result = Open-KeyboardProperties
                    if ($result) {
                        Show-Notification "Keyboard Properties" "Keyboard settings opened successfully" "Success"
                    } else {
                        Show-Notification "Error" "Error opening keyboard properties" "Error"
                    }
                    Read-Host "Press Enter to continue..."
                }
                "12" { 
                    Write-Log "Opening mouse properties..."
                    $result = Open-MouseProperties
                    if ($result) {
                        Show-Notification "Mouse Properties" "Mouse settings opened successfully" "Success"
                    } else {
                        Show-Notification "Error" "Error opening mouse properties" "Error"
                    }
                    Read-Host "Press Enter to continue..."
                }
                "13" { 
                    Write-Log "Opening performance options..."
                    $result = Open-PerformanceOptions
                    if ($result) {
                        Show-Notification "Performance Options" "Performance settings opened successfully" "Success"
                    } else {
                        Show-Notification "Error" "Error opening performance options" "Error"
                    }
                    Read-Host "Press Enter to continue..."
                }
                "14" { 
                    Write-Log "Opening Device Manager..."
                    $result = Open-DeviceManager
                    if ($result) {
                        Show-Notification "Device Manager" "Device Manager opened successfully" "Success"
                    } else {
                        Show-Notification "Error" "Error opening Device Manager" "Error"
                    }
                    Read-Host "Press Enter to continue..."
                }
                "15" { 
                    Write-Log "Opening network connections..."
                    $result = Open-NetworkConnections
                    if ($result) {
                        Show-Notification "Network Connections" "Network settings opened successfully" "Success"
                    } else {
                        Show-Notification "Error" "Error opening network connections" "Error"
                    }
                    Read-Host "Press Enter to continue..."
                }
                "16" { 
                    # Disable optimizations submenu
                    do {
                        Show-EnhancedDisableMenu
                        $disableChoice = Read-Host "Select option to disable (1-5)"
                        
                        switch ($disableChoice) {
                            "1" { 
                                Write-Log "Disabling FPS optimization..."
                                $result = Invoke-OptimizationScript -ScriptCategory "globaloptimization" -ScriptName "globaloptimization.reg" -Enable $false -FriendlyName "FPS Optimization"
                                if ($result) {
                                    Show-Notification "FPS Optimization Disabled" "Gaming optimizations reverted successfully" "Success"
                                } else {
                                    Show-Notification "Disable Error" "Error disabling FPS optimization" "Error"
                                }
                                Read-Host "Press Enter to continue..."
                            }
                            "2" { 
                                Write-Log "Disabling internet optimization..."
                                $result = Invoke-OptimizationScript -ScriptCategory "internet" -ScriptName "internetscript.bat" -Enable $false -FriendlyName "Internet Optimization"
                                if ($result) {
                                    Show-Notification "Internet Optimization Disabled" "Network optimizations reverted successfully" "Success"
                                } else {
                                    Show-Notification "Disable Error" "Error disabling internet optimization" "Error"
                                }
                                Read-Host "Press Enter to continue..."
                            }
                            "3" { 
                                Write-Log "Reverting other tweaks..."
                                $result = Invoke-RevertTweaks
                                if ($result) {
                                    Show-Notification "Tweaks Reverted" "System tweaks reverted successfully" "Success"
                                } else {
                                    Show-Notification "Revert Error" "Error reverting system tweaks" "Error"
                                }
                                Read-Host "Press Enter to continue..."
                            }
                            "4" { 
                                Write-Log "Restoring Microsoft Apps..."
                                $result = Restore-MSApps
                                if ($result) {
                                    Show-Notification "Apps Restored" "Microsoft Apps restored successfully" "Success"
                                } else {
                                    Show-Notification "Restore Error" "Error restoring Microsoft Apps" "Error"
                                }
                                Read-Host "Press Enter to continue..."
                            }
                            "5" { 
                                # Return to main menu
                                break
                            }
                            default {
                                Show-Notification "Invalid Option" "Please select a valid option (1-5)" "Error"
                                Start-Sleep -Seconds 1
                            }
                        }
                    } while ($disableChoice -ne "5")
                }
                "17" { 
                    Write-Log "Exiting Go-Tweak" "INFO"
                    Show-Notification "Thank You" "Thanks for using Go-Tweak Optimizer!" "Success"
                    exit 0
                }
                default {
                    Show-Notification "Invalid Option" "Please select a valid option (1-17)" "Error"
                    Start-Sleep -Seconds 1
                }
            }
        } while ($choice -ne "17")
    }
}

# Script execution
if ($MyInvocation.InvocationName -ne '.') {
    Main
}