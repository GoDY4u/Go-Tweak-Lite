function Write-Status {
    param([string]$Types, [string]$Status)
    $color = switch -Wildcard ($Types) {
        "*+*" { "Green" }
        "*-*" { "Yellow" }
        "*@*" { "Cyan" }
        "*?*" { "Magenta" }
        default { "White" }
    }
    Write-Host "[$Types] $Status" -ForegroundColor $color
}

function Set-ItemPropertyVerified {
    param([string]$Path, [string]$Name, $Value, [string]$Type = "DWord")
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -ErrorAction Stop | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Remove-ItemPropertyVerified {
    param([string]$Path, [string]$Name)
    try {
        if (Test-Path $Path) {
            Remove-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue | Out-Null
            return $true
        }
        return $false
    } catch {
        return $false
    }
}

function Set-ServiceStartup {
    param([string[]]$ServiceNames, [string]$StartupType = "Automatic")
    foreach ($service in $ServiceNames) {
        try {
            if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
                Set-Service -Name $service -StartupType $StartupType -ErrorAction SilentlyContinue | Out-Null
            }
        } catch {
            # Ignore errors
        }
    }
}

function Set-ScheduledTaskState {
    param([string[]]$TaskNames, [string]$State = "Enable")
    foreach ($task in $TaskNames) {
        try {
            if ($State -eq "Enable") {
                Enable-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue | Out-Null
            } else {
                Disable-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue | Out-Null
            }
        } catch {
            # Ignore errors
        }
    }
}

# ========== REVERT HYPER-V ==========
function Enable-HyperV {
    Write-Status -Types "+" -Status "Re-enabling Hyper-V..."
    
    # Habilitar características Hyper-V
    $HyperVFeatures = @(
        "Microsoft-Hyper-V-All",
        "Microsoft-Hyper-V",
        "Microsoft-Hyper-V-Tools-All",
        "Microsoft-Hyper-V-Hypervisor",
        "Microsoft-Hyper-V-Services"
    )
    
    foreach ($feature in $HyperVFeatures) {
        try {
            $featureExists = Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction SilentlyContinue
            if ($featureExists -and $featureExists.State -eq "Disabled") {
                Enable-WindowsOptionalFeature -Online -FeatureName $feature -All -NoRestart | Out-Null
                Write-Status -Types "+" -Status "Enabled Hyper-V feature: $feature"
            }
        } catch {
            # Ignorar si no existe
        }
    }
    
    # Habilitar servicios relacionados con Hyper-V
    $HyperVServices = @(
        "HvHost",
        "vmickvpexchange",
        "vmicguestinterface",
        "vmicshutdown",
        "vmicheartbeat",
        "vmicvmsession",
        "vmicrdv",
        "vmictimesync"
    )
    
    foreach ($service in $HyperVServices) {
        try {
            if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
                Set-Service -Name $service -StartupType Manual -ErrorAction SilentlyContinue
                Start-Service -Name $service -ErrorAction SilentlyContinue
            }
        } catch {
            # Ignorar errores
        }
    }
    
    # Habilitar Hyper-V en el arranque
    try {
        bcdedit /set hypervisorlaunchtype auto 2>$null
        Write-Status -Types "+" -Status "Hyper-V launch enabled in boot configuration"
    } catch {
        Write-Status -Types "?" -Status "Could not modify boot configuration"
    }
    
    Write-Status -Types "+" -Status "Hyper-V re-enabled"
}

# ========== REVERT SSD AND SYSTEM OPTIMIZATIONS ==========
function Revert-SSDOptimizations {
    Write-Status -Types "@" -Status "Reverting SSD optimizations..."
    fsutil behavior set DisableLastAccess 0 | Out-Null
    fsutil behavior set EncryptPagingFile 1 | Out-Null
    Write-Status -Types "+" -Status "SSD optimizations reverted"
}

function Enable-Hibernate {
    Write-Status -Types "+" -Status "Re-enabling hibernation..."
    powercfg -Hibernate on | Out-Null
    Write-Status -Types "+" -Status "Hibernation re-enabled"
}

function Enable-PageFile {
    Write-Status -Types "+" -Status "Re-enabling page file..."
    $CurrentPageFile = Get-WmiObject -Class Win32_ComputerSystem
    $CurrentPageFile.AutomaticManagedPagefile = $true
    $CurrentPageFile.Put()
    Write-Status -Types "+" -Status "Page file re-enabled"
}

# ========== REVERT SERVICES ==========
function Enable-IntelLMS {
    Write-Status -Types "+" -Status "Re-enabling Intel LMS..."
    try {
        Set-Service -Name "LMS" -StartupType Automatic -ErrorAction SilentlyContinue | Out-Null
        Start-Service -Name "LMS" -ErrorAction SilentlyContinue | Out-Null
    } catch {
        # Ignore errors
    }
    Write-Status -Types "+" -Status "Intel LMS re-enabled"
}

function Revert-AdobeServices {
    Write-Status -Types "+" -Status "Reverting Adobe services block..."
    $CCPath = "C:\Program Files (x86)\Common Files\Adobe\Adobe Desktop Common\ADS\Adobe Desktop Service.exe.old"
    $NewPath = "C:\Program Files (x86)\Common Files\Adobe\Adobe Desktop Common\ADS\Adobe Desktop Service.exe"
    
    if (Test-Path $CCPath) {
        try {
            Rename-Item -Path $CCPath -NewName "Adobe Desktop Service.exe" -Force
            Write-Status -Types "+" -Status "Adobe Desktop Service restored"
        } catch {
            Write-Status -Types "?" -Status "Could not restore Adobe Desktop Service"
        }
    }
}

function Enable-TeredoIPv6 {
    Write-Status -Types "+" -Status "Re-enabling Teredo and IPv6..."
    netsh interface teredo set state default
    Enable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6
    Write-Status -Types "+" -Status "Teredo and IPv6 re-enabled"
}

function Revert-Services {
    Write-Status -Types "@" -Status "Reverting service configurations..."
    
    # Services to re-enable
    $ServicesToEnable = @(
        "DiagTrack", "diagnosticshub.standardcollector.service", "HomeGroupListener", 
        "HomeGroupProvider", "MapsBroker", "RemoteAccess", "WSearch", "XblAuthManager",
        "XblGameSave", "XboxGipSvc", "XboxNetApiSvc", "WpnService", "BITS", "PhoneSvc"
    )
    
    Set-ServiceStartup -ServiceNames $ServicesToEnable -StartupType "Automatic"
    Write-Status -Types "+" -Status "Services configuration reverted"
}

# ========== REVERT PRIVACY SETTINGS ==========
function Enable-Diagnostics {
    Write-Status -Types "+" -Status "Re-enabling diagnostics and telemetry..."
    
    # Restore telemetry settings
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry"
    
    # Enable diagnostic services
    Set-Service -Name "DiagTrack" -StartupType Manual -ErrorAction SilentlyContinue
    Set-Service -Name "dmwappushservice" -StartupType Manual -ErrorAction SilentlyContinue
    
    # Enable error reporting
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "DisableWindowsErrorReporting"
    
    Write-Status -Types "+" -Status "Diagnostics and telemetry re-enabled"
}

function Enable-Cortana {
    Write-Status -Types "+" -Status "Re-enabling Cortana..."
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch"
    Write-Status -Types "+" -Status "Cortana re-enabled"
}

function Enable-ActivityHistory {
    Write-Status -Types "+" -Status "Re-enabling Activity History..."
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities"
    Write-Status -Types "+" -Status "Activity history re-enabled"
}

function Enable-LocationTracking {
    Write-Status -Types "+" -Status "Re-enabling location tracking..."
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting"
    Write-Status -Types "+" -Status "Location tracking re-enabled"
}

# ========== REVERT WINDOWS UPDATE ==========
function Set-WindowsUpdateDefault {
    Write-Status -Types "@" -Status "Restoring Windows Update to default settings..."
    
    # Remove update restrictions
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "NoAutoRebootWithLoggedOnUsers"
    
    # Re-enable automatic driver updates
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Value 1
    
    Write-Status -Types "+" -Status "Windows Update settings restored to default"
}

# ========== REVERT PERFORMANCE SETTINGS ==========
function Revert-PerformanceSettings {
    Write-Status -Types "@" -Status "Reverting performance settings..."
    
    # Restore visual effects
    Remove-ItemPropertyVerified -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting"
    
    # Restore animations
    Set-ItemPropertyVerified -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Value "1"
    
    # Restore transparency
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value 1
    
    Write-Status -Types "+" -Status "Performance settings reverted"
}

# ========== REVERT EXPLORER SETTINGS ==========
function Revert-ExplorerSettings {
    Write-Status -Types "@" -Status "Reverting File Explorer settings..."
    
    # Restore default Explorer settings
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 1
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 2
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Value 2
    
    Write-Status -Types "+" -Status "File Explorer settings reverted"
}

# ========== REVERT TASKBAR SETTINGS ==========
function Revert-TaskbarSettings {
    Write-Status -Types "@" -Status "Reverting Taskbar settings..."
    
    # Restore default taskbar settings
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Value 0
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Value 1
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 1
    
    Write-Status -Types "+" -Status "Taskbar settings reverted"
}

# ========== REVERT POWER SETTINGS ==========
function Set-PowerDefault {
    Write-Status -Types "@" -Status "Restoring default power plan..."
    powercfg -setactive 381b4222-f694-41f0-9685-ff5bb260df2e  # Balanced plan
    Write-Status -Types "+" -Status "Default power plan restored"
}

# ========== REINSTALL UWP APPS ==========
function Reinstall-UWPApps {
    Write-Status -Types "+" -Status "Reinstalling essential UWP apps..."
    
    $EssentialApps = @(
        "Microsoft.WindowsStore",
        "Microsoft.WindowsCalculator",
        "Microsoft.WindowsCamera",
        "Microsoft.WindowsMaps",
        "Microsoft.ScreenSketch",
        "Microsoft.Paint",
        "Microsoft.WindowsNotepad"
    )
    
    foreach ($app in $EssentialApps) {
        try {
            Get-AppxPackage -AllUsers | Where-Object {$_.Name -like "*$app*"} | ForEach-Object {
                Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -ErrorAction SilentlyContinue
            }
        } catch {
            # Ignore errors
        }
    }
    
    Write-Status -Types "+" -Status "Essential UWP apps reinstalled"
}

# ========== REVERT SCHEDULED TASKS ==========
function Enable-ScheduledTasks {
    Write-Status -Types "+" -Status "Re-enabling scheduled tasks..."
    
    $TasksToEnable = @(
        "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
        "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
        "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        "\Microsoft\Windows\Customer Experience Improvement Program\Uploader",
        "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
    )
    
    Set-ScheduledTaskState -TaskNames $TasksToEnable -State "Enable"
    Write-Status -Types "+" -Status "Scheduled tasks re-enabled"
}

# ========== REVERT FIREWALL SETTINGS ==========
function Revert-FirewallSettings {
    Write-Status -Types "@" -Status "Reverting firewall settings..."
    
    # Remove custom firewall rules
    $FirewallRules = @("BlockSMBv1", "BlockNetBIOS", "BlockLLMNR")
    
    foreach ($rule in $FirewallRules) {
        try {
            Remove-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue
        } catch {
            # Ignore if rule doesn't exist
        }
    }
    
    Write-Status -Types "+" -Status "Firewall settings reverted"
}

# ========== REVERT DNS SETTINGS ==========
function Revert-DNSSettings {
    Write-Status -Types "@" -Status "Reverting DNS settings..."
    
    # Restore automatic DNS
    $Interfaces = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
    foreach ($Interface in $Interfaces) {
        try {
            Set-DnsClientServerAddress -InterfaceIndex $Interface.InterfaceIndex -ResetServerAddresses -ErrorAction SilentlyContinue
        } catch {
            # Ignore errors
        }
    }
    
    Write-Status -Types "+" -Status "DNS settings reverted"
}

# ========== REMOVE GOD MODE ==========
function Remove-GodMode {
    Write-Status -Types "@" -Status "Removing God Mode..."
    $DesktopPath = [Environment]::GetFolderPath("Desktop")
    $GodModePath = "$DesktopPath\GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}"
    
    try {
        if (Test-Path $GodModePath) {
            Remove-Item -Path $GodModePath -Recurse -Force -ErrorAction SilentlyContinue
            Write-Status -Types "+" -Status "God Mode removed from desktop"
        }
    } catch {
        Write-Status -Types "?" -Status "Could not remove God Mode"
    }
}

# ========== MAIN REVERT FUNCTION ==========
function Start-FullRevert {
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "    WINDOWS OPTIMIZATION REVERT" -ForegroundColor Cyan
    Write-Host "    REVERSING ALL CHANGES" -ForegroundColor Cyan
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Check administrator permissions
    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Host "ERROR: This script requires Administrator permissions" -ForegroundColor Red
        Write-Host "Run PowerShell as Administrator and try again" -ForegroundColor Yellow
        pause
        exit 1
    }
    
    # Final confirmation before starting
    Write-Host "This script will revert all changes made by the optimization script:" -ForegroundColor Yellow
    Write-Host "• Re-enable Hyper-V and related services" -ForegroundColor White
    Write-Host "• Restore default service configurations" -ForegroundColor White
    Write-Host "• Re-enable telemetry and diagnostics" -ForegroundColor White
    Write-Host "• Restore privacy settings" -ForegroundColor White
    Write-Host "• Revert performance and UI settings" -ForegroundColor White
    Write-Host "• Restore Windows Update to default" -ForegroundColor White
    Write-Host ""
    Write-Host "Are you sure you want to continue? (y/n)" -ForegroundColor Yellow
    $confirm = Read-Host
    
    if ($confirm -ne 'y' -and $confirm -ne 'Y') {
        Write-Host "Execution cancelled by user" -ForegroundColor Red
        exit 0
    }
    
    # EXECUTE ALL REVERTS
    Write-Host ""
    Write-Host "STARTING REVERT PROCESS..." -ForegroundColor Green
    Write-Host "================================================" -ForegroundColor Green
    Write-Host ""
    
    # 1. Hyper-V Re-enable
    Write-Host "=== HYPER-V ===" -ForegroundColor Cyan
    Enable-HyperV
    
    # 2. System optimizations revert
    Write-Host "`n=== SYSTEM OPTIMIZATIONS ===" -ForegroundColor Cyan
    Revert-SSDOptimizations
    Enable-Hibernate
    Enable-PageFile
    Set-PowerDefault
    
    # 3. Services revert
    Write-Host "`n=== SERVICES ===" -ForegroundColor Cyan
    Enable-IntelLMS
    Revert-AdobeServices
    Enable-TeredoIPv6
    Revert-Services
    
    # 4. Privacy and diagnostics revert
    Write-Host "`n=== PRIVACY AND DIAGNOSTICS ===" -ForegroundColor Cyan
    Enable-Diagnostics
    Enable-Cortana
    Enable-ActivityHistory
    Enable-LocationTracking
    
    # 5. Windows Update revert
    Write-Host "`n=== WINDOWS UPDATE ===" -ForegroundColor Cyan
    Set-WindowsUpdateDefault
    
    # 6. Performance settings revert
    Write-Host "`n=== PERFORMANCE SETTINGS ===" -ForegroundColor Cyan
    Revert-PerformanceSettings
    
    # 7. UI settings revert
    Write-Host "`n=== USER INTERFACE ===" -ForegroundColor Cyan
    Revert-ExplorerSettings
    Revert-TaskbarSettings
    
    # 8. Network settings revert
    Write-Host "`n=== NETWORK SETTINGS ===" -ForegroundColor Cyan
    Revert-FirewallSettings
    Revert-DNSSettings
    
    # 9. Reinstall apps and features
    Write-Host "`n=== APPLICATIONS ===" -ForegroundColor Cyan
    Reinstall-UWPApps
    
    # 10. Scheduled tasks revert
    Write-Host "`n=== SCHEDULED TASKS ===" -ForegroundColor Cyan
    Enable-ScheduledTasks
    
    # 11. Remove utilities
    Write-Host "`n=== UTILITIES ===" -ForegroundColor Cyan
    Remove-GodMode
    
    # FINAL SUMMARY
    Write-Host ""
    Write-Host "================================================" -ForegroundColor Green
    Write-Host "    REVERT PROCESS COMPLETED!" -ForegroundColor Green
    Write-Host "================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "SUMMARY OF REVERTED CHANGES:" -ForegroundColor Yellow
    Write-Host "  ✓ Hyper-V re-enabled" -ForegroundColor Green
    Write-Host "  ✓ SSD optimizations reverted" -ForegroundColor Green
    Write-Host "  ✓ Hibernation and page file restored" -ForegroundColor Green
    Write-Host "  ✓ Services configuration restored" -ForegroundColor Green
    Write-Host "  ✓ Telemetry and diagnostics re-enabled" -ForegroundColor Green
    Write-Host "  ✓ Privacy settings restored" -ForegroundColor Green
    Write-Host "  ✓ Windows Update restored to default" -ForegroundColor Green
    Write-Host "  ✓ Performance settings reverted" -ForegroundColor Green
    Write-Host "  ✓ UI settings restored" -ForegroundColor Green
    Write-Host "  ✓ Network settings reverted" -ForegroundColor Green
    Write-Host "  ✓ Essential UWP apps reinstalled" -ForegroundColor Green
    Write-Host "  ✓ Scheduled tasks re-enabled" -ForegroundColor Green
    Write-Host "  ✓ God Mode removed" -ForegroundColor Green
    Write-Host ""
    Write-Host "Some changes require restart to fully apply!" -ForegroundColor Yellow
    Write-Host ""
    
    $reboot = Read-Host "Do you want to restart now? (y/n)"
    if ($reboot -eq 'y' -or $reboot -eq 'Y') {
        Write-Host "Restarting in 5 seconds..." -ForegroundColor Yellow
        Start-Sleep 5
        Restart-Computer -Force
    } else {
        Write-Host "Remember to restart manually to apply all changes" -ForegroundColor Yellow
        Write-Host "Press any key to exit..." -ForegroundColor Gray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}

# Execute the revert process
Start-FullRevert
