# ========== SCRIPT DE REVERSIÓN ==========
# Deshace todos los cambios del script de optimización

function Write-Status {
    param([string]$Types, [string]$Status)
    $color = switch -Wildcard ($Types) {
        "*+*" { "Green" }
        "*-*" { "Yellow" }
        "*@*" { "Cyan" }
        default { "White" }
    }
    Write-Host "[$Types] $Status" -ForegroundColor $color
}

function Remove-ItemPropertyVerified {
    param([string]$Path, [string]$Name)
    try {
        if (Test-Path $Path) {
            Remove-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
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
                Set-Service -Name $service -StartupType $StartupType -ErrorAction SilentlyContinue
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
                Enable-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
            } else {
                Disable-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
            }
        } catch {
            # Ignore errors
        }
    }
}

# ========== REVERT HYPER-V ==========
function Enable-HyperV {
    Write-Status -Types "+" -Status "Re-enabling Hyper-V..."
    
    # Habilitar Hyper-V en el arranque
    try {
        bcdedit /set hypervisorlaunchtype auto 2>$null
        Write-Status -Types "+" -Status "Hyper-V launch enabled in boot configuration"
    } catch {
        Write-Status -Types "?" -Status "Could not modify boot configuration"
    }
    
    Write-Status -Types "+" -Status "Hyper-V re-enabled"
}

# ========== REVERT SSD OPTIMIZATIONS ==========
function Revert-SSDOptimizations {
    Write-Status -Types "+" -Status "Reverting SSD optimizations..."
    fsutil behavior set DisableLastAccess 0 | Out-Null
    fsutil behavior set EncryptPagingFile 1 | Out-Null
    Write-Status -Types "+" -Status "SSD optimizations reverted"
}

function Enable-Hibernate {
    Write-Status -Types "+" -Status "Enabling hibernation..."
    powercfg -Hibernate on | Out-Null
    Write-Status -Types "+" -Status "Hibernation enabled"
}

# ========== REVERT SERVICES ==========
function Enable-IntelLMS {
    Write-Status -Types "+" -Status "Enabling Intel LMS..."
    Set-Service -Name "LMS" -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name "LMS" -ErrorAction SilentlyContinue
    Write-Status -Types "+" -Status "Intel LMS enabled"
}

function Revert-AdobeServices {
    Write-Status -Types "+" -Status "Reverting Adobe services block..."
    $CCPath = "C:\Program Files (x86)\Common Files\Adobe\Adobe Desktop Common\ADS\Adobe Desktop Service.exe.old"
    if (Test-Path $CCPath) {
        Rename-Item -Path $CCPath -NewName "Adobe Desktop Service.exe" -Force
        Write-Status -Types "+" -Status "Adobe Desktop Service restored"
    }
    
    # Limpiar hosts file
    $hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
    $adobeDomains = @(
        "0.0.0.0 cc-api-data.adobe.io",
        "0.0.0.0 ic.adobe.io", 
        "0.0.0.0 p13n.adobe.io",
        "0.0.0.0 prod.adobegenuine.com"
    )
    
    $content = Get-Content $hostsFile -ErrorAction SilentlyContinue
    $newContent = $content | Where-Object { $adobeDomains -notcontains $_ }
    Set-Content -Path $hostsFile -Value $newContent -ErrorAction SilentlyContinue
    
    Write-Status -Types "+" -Status "Adobe domains unblocked"
}

function Enable-TeredoIPv6 {
    Write-Status -Types "+" -Status "Enabling Teredo and IPv6..."
    netsh interface teredo set state default
    Enable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6
    Write-Status -Types "+" -Status "Teredo and IPv6 enabled"
}

function Revert-Services {
    Write-Status -Types "+" -Status "Reverting service changes..."
    
    # Services to re-enable
    $ServicesToEnable = @(
        "DiagTrack", "dmwappushservice", "MapsBroker", "RemoteAccess", 
        "RemoteRegistry", "WSearch", "XblAuthManager", "XblGameSave", 
        "XboxGipSvc", "XboxNetApiSvc", "WpnService"
    )
    
    Set-ServiceStartup -ServiceNames $ServicesToEnable -StartupType "Automatic"
    
    # Start essential services
    $ServicesToStart = @("DiagTrack", "WSearch", "WpnService")
    foreach ($service in $ServicesToStart) {
        try {
            Start-Service -Name $service -ErrorAction SilentlyContinue
        } catch { }
    }
    
    Write-Status -Types "+" -Status "Services reverted to default"
}

# ========== REVERT PRIVACY SETTINGS ==========
function Enable-Diagnostics {
    Write-Status -Types "+" -Status "Re-enabling diagnostics..."
    
    # Remover políticas restrictivas
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry"
    
    # Re-enable error reporting
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "DisableWindowsErrorReporting"
    
    # Re-enable services
    Set-Service -Name "DiagTrack" -StartupType Automatic -ErrorAction SilentlyContinue
    Set-Service -Name "dmwappushservice" -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name "DiagTrack" -ErrorAction SilentlyContinue
    Start-Service -Name "dmwappushservice" -ErrorAction SilentlyContinue
    
    Write-Status -Types "+" -Status "Diagnostics re-enabled"
}

function Enable-Cortana {
    Write-Status -Types "+" -Status "Enabling Cortana..."
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWeb"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch"
    Write-Status -Types "+" -Status "Cortana enabled"
}

function Enable-ActivityHistory {
    Write-Status -Types "+" -Status "Enabling Activity History..."
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities"
    Write-Status -Types "+" -Status "Activity history enabled"
}

function Enable-LocationTracking {
    Write-Status -Types "+" -Status "Enabling location tracking..."
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableWindowsLocationProvider"
    Write-Status -Types "+" -Status "Location tracking enabled"
}

function Enable-OnlineSpeechRecognition {
    Write-Status -Types "+" -Status "Enabling online speech recognition..."
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization"
    Write-Status -Types "+" -Status "Online speech recognition enabled"
}

function Enable-ClipboardHistory {
    Write-Status -Types "+" -Status "Enabling clipboard history..."
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowClipboardHistory"
    Remove-ItemPropertyVerified -Path "HKCU:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory"
    Write-Status -Types "+" -Status "Clipboard history enabled"
}

function Enable-FeedbackNotifications {
    Write-Status -Types "+" -Status "Enabling feedback notifications..."
    Remove-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications"
    Write-Status -Types "+" -Status "Feedback notifications enabled"
}

function Enable-AdvertisingID {
    Write-Status -Types "+" -Status "Enabling advertising ID..."
    Remove-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy"
    Write-Status -Types "+" -Status "Advertising ID enabled"
}

function Enable-WindowsSpotlight {
    Write-Status -Types "+" -Status "Enabling Windows Spotlight..."
    Remove-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures"
    Remove-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightOnActionCenter"
    Remove-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightOnSettings"
    Remove-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightWindowsWelcomeExperience"
    
    # Restaurar valores por defecto
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Value 1 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Value 1 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Value 1 -ErrorAction SilentlyContinue
    
    Write-Status -Types "+" -Status "Windows Spotlight enabled"
}

function Enable-BackgroundApps {
    Write-Status -Types "+" -Status "Enabling background apps..."
    Remove-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled"
    Remove-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BackgroundAppGlobalToggle"
    Write-Status -Types "+" -Status "Background apps enabled"
}

# ========== REVERT WINDOWS UPDATE ==========
function Set-WindowsUpdateAuto {
    Write-Status -Types "+" -Status "Setting Windows Update to automatic..."
    
    # Remover políticas
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "NoAutoRebootWithLoggedOnUsers"
    
    # Re-enable P2P
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode"
    
    Write-Status -Types "+" -Status "Windows Update set to automatic"
}

# ========== REVERT FIREWALL ==========
function Revert-Firewall {
    Write-Status -Types "+" -Status "Reverting firewall changes..."
    
    # Remover reglas personalizadas
    $FirewallRules = @("BlockSMBv1", "BlockNetBIOS", "BlockLLMNR")
    
    foreach ($rule in $FirewallRules) {
        try {
            Remove-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue
        } catch {
            # Ignore if rule doesn't exist
        }
    }
    
    Write-Status -Types "+" -Status "Firewall changes reverted"
}

# ========== REVERT EXPLORER ==========
function Revert-Explorer {
    Write-Status -Types "+" -Status "Reverting File Explorer changes..."
    
    # Ocultar extensiones de archivo
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 1 -ErrorAction SilentlyContinue
    
    # Ocultar archivos ocultos
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 2 -ErrorAction SilentlyContinue
    
    Write-Status -Types "+" -Status "File Explorer settings reverted to default"
}

# ========== REVERT SCHEDULED TASKS ==========
function Enable-ScheduledTasks {
    Write-Status -Types "+" -Status "Re-enabling scheduled tasks..."
    
    $TasksToEnable = @(
        "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
        "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
        "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask",
        "\Microsoft\Windows\Customer Experience Improvement Program\Uploader"
    )
    
    Set-ScheduledTaskState -TaskNames $TasksToEnable -State "Enable"
    Write-Status -Types "+" -Status "Scheduled tasks re-enabled"
}

# ========== MAIN REVERT FUNCTION ==========
function Start-RevertAll {
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "    REVERT WINDOWS OPTIMIZATIONS" -ForegroundColor Cyan
    Write-Host "    Deshacer todos los cambios" -ForegroundColor Cyan
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Check administrator permissions
    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Host "ERROR: This script requires Administrator permissions" -ForegroundColor Red
        Write-Host "Run PowerShell as Administrator and try again" -ForegroundColor Yellow
        pause
        exit 1
    }
    
    Write-Host "This will revert ALL optimizations to Windows defaults." -ForegroundColor Yellow
    Write-Host "Continue? (y/n)" -ForegroundColor Yellow
    $confirm = Read-Host
    
    if ($confirm -ne 'y' -and $confirm -ne 'Y') {
        Write-Host "Reversion cancelled" -ForegroundColor Red
        exit 0
    }
    
    Write-Host ""
    Write-Host "REVERTING CHANGES..." -ForegroundColor Yellow
    Write-Host "================================================" -ForegroundColor Yellow
    
    # 1. Hyper-V
    Write-Host "`n=== HYPER-V ===" -ForegroundColor Cyan
    Enable-HyperV
    
    # 2. System optimizations
    Write-Host "`n=== SYSTEM OPTIMIZATIONS ===" -ForegroundColor Cyan
    Revert-SSDOptimizations
    Enable-Hibernate
    
    # 3. Services
    Write-Host "`n=== SERVICES ===" -ForegroundColor Cyan
    Enable-IntelLMS
    Revert-AdobeServices
    Enable-TeredoIPv6
    Revert-Services
    
    # 4. Privacy
    Write-Host "`n=== PRIVACY ===" -ForegroundColor Cyan
    Enable-Diagnostics
    Enable-Cortana
    Enable-ActivityHistory
    Enable-LocationTracking
    Enable-OnlineSpeechRecognition
    Enable-ClipboardHistory
    Enable-FeedbackNotifications
    Enable-AdvertisingID
    Enable-WindowsSpotlight
    Enable-BackgroundApps
    
    # 5. Windows Update
    Write-Host "`n=== WINDOWS UPDATE ===" -ForegroundColor Cyan
    Set-WindowsUpdateAuto
    
    # 6. Firewall
    Write-Host "`n=== FIREWALL ===" -ForegroundColor Cyan
    Revert-Firewall
    
    # 7. Explorer
    Write-Host "`n=== FILE EXPLORER ===" -ForegroundColor Cyan
    Revert-Explorer
    
    # 8. Scheduled tasks
    Write-Host "`n=== SCHEDULED TASKS ===" -ForegroundColor Cyan
    Enable-ScheduledTasks

    # FINAL SUMMARY
    Write-Host ""
    Write-Host "================================================" -ForegroundColor Green
    Write-Host "    REVERSION COMPLETED!" -ForegroundColor Green
    Write-Host "================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "All optimizations have been reverted:" -ForegroundColor Yellow
    Write-Host "  - Hyper-V re-enabled" -ForegroundColor White
    Write-Host "  - Services restored to default" -ForegroundColor White
    Write-Host "  - Privacy settings reset" -ForegroundColor White
    Write-Host "  - Windows Update set to automatic" -ForegroundColor White
    Write-Host "  - Firewall rules removed" -ForegroundColor White
    Write-Host "  - File Explorer settings reset" -ForegroundColor White
    Write-Host "  - Scheduled tasks re-enabled" -ForegroundColor White
    Write-Host ""
    Write-Host "Some changes require restart to fully apply." -ForegroundColor Yellow
    
    $reboot = Read-Host "`nRestart now? (y/n)"
    if ($reboot -eq 'y' -or $reboot -eq 'Y') {
        Write-Host "Restarting in 5 seconds..." -ForegroundColor Yellow
        Start-Sleep 5
        Restart-Computer -Force
    } else {
        Write-Host "Reversion completed. Restart when convenient." -ForegroundColor Green
        pause
    }
}

# Execute the reversion
Start-RevertAll