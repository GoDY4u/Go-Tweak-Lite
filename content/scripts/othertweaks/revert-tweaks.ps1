# Script de Reversión - Windows Optimization Revert
# Revierte los cambios realizados por el script de optimización

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
        "Microsoft-Hyper-V-Services",
        "VirtualMachinePlatform"
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
    
    # Revertir características de seguridad
    Remove-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity"
    Remove-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "RequirePlatformSecurityFeatures"
    Remove-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "LsaCfgFlags"
    
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
    $NewPath = "C:\Program Files (x86)\Common Files\Adobe\Adobe Adobe Desktop Common\ADS\Adobe Desktop Service.exe"
    
    if (Test-Path $CCPath) {
        try {
            Rename-Item -Path $CCPath -NewName "Adobe Desktop Service.exe" -Force
            Write-Status -Types "+" -Status "Adobe Desktop Service restored"
        } catch {
            Write-Status -Types "?" -Status "Could not restore Adobe Desktop Service"
        }
    }
    
    # Limpiar hosts file de bloqueos Adobe
    $hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
    $adobeDomains = @(
        "cc-api-data.adobe.io",
        "ic.adobe.io", 
        "p13n.adobe.io",
        "prod.adobegenuine.com",
        "assets.adobedtm.com",
        "auth.services.adobe.com",
        "licensing.adobe.io"
    )
    
    if (Test-Path $hostsFile) {
        $content = Get-Content $hostsFile
        $newContent = $content | Where-Object { 
            $line = $_.Trim()
            -not ($line.StartsWith("0.0.0.0") -and $adobeDomains -contains $line.Split()[1])
        }
        Set-Content -Path $hostsFile -Value $newContent -Force
    }
    
    Write-Status -Types "+" -Status "Adobe services restrictions removed"
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
        "DiagTrack", "diagnosticshub.standardcollector.service", "dmwappushservice",
        "HomeGroupListener", "HomeGroupProvider", "MapsBroker", "RemoteAccess", 
        "WSearch", "XblAuthManager", "XblGameSave", "XboxGipSvc", "XboxNetApiSvc", 
        "WpnService", "BITS", "PhoneSvc", "WMPNetworkSvc", "iphlpsvc"
    )
    
    Set-ServiceStartup -ServiceNames $ServicesToEnable -StartupType "Automatic"
    Write-Status -Types "+" -Status "Services configuration reverted"
}

# ========== REVERT WINDOWS FEATURES ==========
function Enable-WindowsFeatures {
    Write-Status -Types "@" -Status "Re-enabling Windows features..."
    
    $FeaturesToEnable = @(
        "Containers-DisposableClientVM",  # Windows Sandbox
        "Microsoft-Windows-Subsystem-Linux",  # WSL (Linux)
        "FaxServicesClientPackage",
        "Internet-Explorer-Optional-amd64",
        "MediaPlayback"
    )
    
    foreach ($feature in $FeaturesToEnable) {
        try {
            $featureExists = Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction SilentlyContinue
            if ($featureExists -and $featureExists.State -eq "Disabled") {
                Enable-WindowsOptionalFeature -Online -FeatureName $feature -All -NoRestart | Out-Null
            }
        } catch {
            # Ignore errors for features that don't exist
        }
    }
    
    Write-Status -Types "+" -Status "Windows features re-enabled"
}

# ========== REVERT PRIVACY SETTINGS ==========
function Enable-Diagnostics {
    Write-Status -Types "+" -Status "Re-enabling diagnostics and telemetry..."
    
    # Restore telemetry settings
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowDeviceNameInTelemetry"
    
    # Enable diagnostic services
    Set-Service -Name "DiagTrack" -StartupType Manual -ErrorAction SilentlyContinue
    Set-Service -Name "dmwappushservice" -StartupType Manual -ErrorAction SilentlyContinue
    
    # Enable error reporting
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "DisableWindowsErrorReporting"
    
    # Enable personalized experiences
    Remove-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled"
    Remove-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData"
    
    # Enable handwriting and typing collection
    Remove-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection"
    Remove-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection"
    Remove-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts"
    Remove-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Input\TIPC" -Name "Enabled"
    
    # Enable AutoLogger
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" -Name "Start" -Value 1
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" -Name "Start" -Value 1
    
    # Enable CEIP and connected experiences
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableUAR"
    
    Write-Status -Types "+" -Status "Diagnostics and telemetry re-enabled"
}

function Enable-Cortana {
    Write-Status -Types "+" -Status "Re-enabling Cortana..."
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWeb"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch"
    Write-Status -Types "+" -Status "Cortana re-enabled"
}

function Enable-ActivityHistory {
    Write-Status -Types "+" -Status "Re-enabling Activity History..."
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities"
    Write-Status -Types "+" -Status "Activity history re-enabled"
}

function Enable-LocationTracking {
    Write-Status -Types "+" -Status "Re-enabling location tracking..."
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableWindowsLocationProvider"
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Value 1
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Value 1
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Allow"
    Write-Status -Types "+" -Status "Location tracking re-enabled"
}

function Enable-OnlineSpeechRecognition {
    Write-Status -Types "+" -Status "Re-enabling online speech recognition..."
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization"
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "HasAccepted" -Value 1
    Write-Status -Types "+" -Status "Online speech recognition re-enabled"
}

function Enable-ClipboardHistory {
    Write-Status -Types "+" -Status "Re-enabling clipboard history..."
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowClipboardHistory" -Value 1
    Set-ItemPropertyVerified -Path "HKCU:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory" -Value 1
    Write-Status -Types "+" -Status "Clipboard history re-enabled"
}

function Enable-FeedbackNotifications {
    Write-Status -Types "+" -Status "Re-enabling feedback notifications..."
    Remove-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications"
    Write-Status -Types "+" -Status "Feedback notifications re-enabled"
}

function Enable-AdvertisingID {
    Write-Status -Types "+" -Status "Re-enabling advertising ID..."
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 1
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy"
    Write-Status -Types "+" -Status "Advertising ID re-enabled"
}

function Enable-WindowsSpotlight {
    Write-Status -Types "+" -Status "Re-enabling Windows Spotlight..."
    Remove-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures"
    Remove-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightOnActionCenter"
    Remove-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightOnSettings"
    Remove-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightWindowsWelcomeExperience"
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Value 1
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Value 1
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Value 1
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Value 1
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Value 1
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Value 1
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Value 1
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Value 1
    Write-Status -Types "+" -Status "Windows Spotlight re-enabled"
}

function Enable-BackgroundApps {
    Write-Status -Types "+" -Status "Re-enabling background apps..."
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Value 0
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BackgroundAppGlobalToggle" -Value 1
    Write-Status -Types "+" -Status "Background apps re-enabled"
}

# ========== REVERT WINDOWS UPDATE ==========
function Set-WindowsUpdateDefault {
    Write-Status -Types "@" -Status "Restoring Windows Update to default settings..."
    
    # Remove update restrictions
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "NoAutoRebootWithLoggedOnUsers"
    
    # Re-enable P2P
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode"
    
    # Re-enable automatic driver updates
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Value 1
    
    # Remove update policies
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "SetPowerPolicyForFeatureUpdates"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\OSUpgrade" -Name "ReservationsAllowed"
    
    Write-Status -Types "+" -Status "Windows Update settings restored to default"
}

# ========== REVERT PERFORMANCE SETTINGS ==========
function Revert-PerformanceSettings {
    Write-Status -Types "@" -Status "Reverting performance settings..."
    
    # Restore visual effects
    Remove-ItemPropertyVerified -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting"
    
    # Restore animations
    Set-ItemPropertyVerified -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Value "1"
    Set-ItemPropertyVerified -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Value "1"
    Set-ItemPropertyVerified -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Value "400"
    
    # Restore transparency
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value 1
    
    # Restore system performance settings
    Remove-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "WaitToKillServiceTimeout"
    Set-ItemPropertyVerified -Path "HKCU:\Control Panel\Desktop" -Name "AutoEndTasks" -Value 0
    Set-ItemPropertyVerified -Path "HKCU:\Control Panel\Desktop" -Name "WaitToKillAppTimeout" -Value 20000
    Set-ItemPropertyVerified -Path "HKCU:\Control Panel\Desktop" -Name "LowLevelHooksTimeout" -Value 5000
    
    Write-Status -Types "+" -Status "Performance settings reverted"
}

# ========== REVERT SYSTEM PERFORMANCE ==========
function Revert-SystemPerformance {
    Write-Status -Types "@" -Status "Reverting system performance optimizations..."
    
    # Restore system priorities
    Remove-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation"
    
    # Restore system cache
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "LargeSystemCache" -Value 0
    
    # Restore I/O settings
    Remove-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "IOPageLockLimit"
    
    # Restore Prefetcher and Superfetch to default
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnableSuperfetch" -Value 3
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnablePrefetcher" -Value 3
    
    Write-Status -Types "+" -Status "System performance settings reverted"
}

# ========== REVERT NETWORK SETTINGS ==========
function Revert-NetworkSettings {
    Write-Status -Types "@" -Status "Reverting network settings..."
    
    # Restore TCP/IP settings to default
    Remove-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnablePMTUDiscovery"
    Remove-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnablePMTUBHDetect"
    Remove-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "SackOpts"
    Remove-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "Tcp1323Opts"
    Remove-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpWindowSize"
    Remove-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DefaultTTL"
    Remove-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpMaxDupAcks"
    
    # Restore DNS cache settings
    Remove-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "MaxCacheTtl"
    Remove-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "MaxNegativeCacheTtl"
    
    # Restore network performance settings
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Psched" -Name "NonBestEffortLimit"
    
    Write-Status -Types "+" -Status "Network settings reverted"
}

# ========== REVERT EXPLORER SETTINGS ==========
function Revert-ExplorerSettings {
    Write-Status -Types "@" -Status "Reverting File Explorer settings..."
    
    # Restore default Explorer settings
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 1
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 2
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Value 1
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Value 2
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowPreviewHandlers" -Value 1
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowStatusBar" -Value 1
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneShowAllFolders" -Value 0
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneExpandToCurrentFolder" -Value 0
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ConfirmFileDelete" -Value 1
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "FullPath" -Value 0
    
    Write-Status -Types "+" -Status "File Explorer settings reverted"
}

# ========== REVERT TASKBAR SETTINGS ==========
function Revert-TaskbarSettings {
    Write-Status -Types "@" -Status "Reverting Taskbar settings..."
    
    # Restore default taskbar settings
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Value 0
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Value 1
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 1
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Value 1
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Value 1
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSecondsInSystemClock" -Value 0
    
    Write-Status -Types "+" -Status "Taskbar settings reverted"
}

# ========== REVERT START MENU SETTINGS ==========
function Revert-StartMenuSettings {
    Write-Status -Types "@" -Status "Reverting Start Menu settings..."
    
    # Restore Start Menu settings
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Value 1
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Value 1
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Value 1
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Value 0
    Remove-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_NumRows"
    
    Write-Status -Types "+" -Status "Start Menu settings reverted"
}

# ========== REVERT SCHEDULED TASKS ==========
function Enable-ScheduledTasks {
    Write-Status -Types "+" -Status "Re-enabling scheduled tasks..."
    
    $TasksToEnable = @(
        "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
        "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
        "\Microsoft\Windows\Application Experience\StartupAppTask",
        "\Microsoft\Windows\Autochk\Proxy",
        "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask",
        "\Microsoft\Windows\Customer Experience Improvement Program\Uploader",
        "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
        "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
        "\Microsoft\Windows\Location\Notifications",
        "\Microsoft\Windows\Location\WindowsActionDialog",
        "\Microsoft\Windows\Maps\MapsToastTask",
        "\Microsoft\Windows\Maps\MapsUpdateTask",
        "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem"
    )
    
    Set-ScheduledTaskState -TaskNames $TasksToEnable -State "Enable"
    Write-Status -Types "+" -Status "Scheduled tasks re-enabled"
}

# ========== REVERT APPLICATION SETTINGS ==========
function Revert-EdgeSettings {
    Write-Status -Types "@" -Status "Reverting Microsoft Edge settings..."
    
    $EdgePaths = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\Edge",
        "HKCU:\SOFTWARE\Policies\Microsoft\Edge"
    )
    
    foreach ($path in $EdgePaths) {
        if (Test-Path $path) {
            Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    
    Write-Status -Types "+" -Status "Microsoft Edge settings reverted"
}

function Revert-ChromeSettings {
    Write-Status -Types "@" -Status "Reverting Google Chrome settings..."
    
    $ChromePaths = @(
        "HKLM:\SOFTWARE\Policies\Google\Chrome",
        "HKCU:\SOFTWARE\Policies\Google\Chrome"
    )
    
    foreach ($path in $ChromePaths) {
        if (Test-Path $path) {
            Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    
    Write-Status -Types "+" -Status "Google Chrome settings reverted"
}

# ========== REVERT GAMING SETTINGS ==========
function Revert-GamingSettings {
    Write-Status -Types "@" -Status "Reverting gaming settings..."
    
    # Restore Game Mode
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\GameBar" -Name "AllowAutoGameMode" -Value 0
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Value 0
    
    # Restore GPU settings
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "GPU Priority"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category"
    
    # Restore GPU hardware acceleration
    Remove-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "HwSchMode"
    
    Write-Status -Types "+" -Status "Gaming settings reverted"
}

# ========== REVERT AUDIO SETTINGS ==========
function Revert-AudioSettings {
    Write-Status -Types "@" -Status "Reverting audio settings..."
    
    # Restore audio enhancements
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Audio" -Name "DisableProtectedAudioDG"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio" -Name "DisableSampleRateConversion"
    
    # Restore audio quality
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Audio" -Name "AudioSampleRate"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Audio" -Name "AudioSampleSize"
    
    # Restore system sounds
    Remove-ItemPropertyVerified -Path "HKCU:\AppEvents\Schemes\Apps\.Default" -Name "(Default)"
    
    Write-Status -Types "+" -Status "Audio settings reverted"
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
    
    # Restore firewall logging
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log"
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogMaxSizeKilobytes 4096
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed False
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogBlocked False
    
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
    
    # Restore DNS cache settings
    Remove-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "MaxCacheTtl"
    Remove-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "MaxNegativeCacheTtl"
    Remove-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "NetFailureCacheTime"
    Remove-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "NegativeSOACacheTime"
    
    Write-Status -Types "+" -Status "DNS settings reverted"
}

# ========== REVERT MAINTENANCE SETTINGS ==========
function Revert-MaintenanceSettings {
    Write-Status -Types "@" -Status "Reverting maintenance settings..."
    
    # Enable automatic maintenance
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name "MaintenanceDisabled" -Value 0
    
    # Restore cleanup settings
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Update Cleanup" -Name "StateFlags"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Files" -Name "StateFlags"
    
    # Enable automatic defragmentation
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Dfrg\BootOptimizeFunction" -Name "Enable" -Value "Y"
    
    Write-Status -Types "+" -Status "Maintenance settings reverted"
}

# ========== REVERT REGISTRY SETTINGS ==========
function Revert-RegistrySettings {
    Write-Status -Types "@" -Status "Reverting registry settings..."
    
    # Restore registry size limit
    Remove-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "RegistrySizeLimit"
    
    # Restore low disk space notifications
    Remove-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "DiskSpaceThreshold"
    
    # Restore group policies
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus"
    
    # Restore memory for services
    Remove-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB"
    
    Write-Status -Types "+" -Status "Registry settings reverted"
}

# ========== REVERT SECURITY SETTINGS ==========
function Revert-SecuritySettings {
    Write-Status -Types "@" -Status "Reverting security settings..."
    
    # Restore AutoRun
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun"
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun"
    
    # Restore anonymous access
    Remove-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous"
    Remove-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM"
    Remove-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "EveryoneIncludesAnonymous"
    
    # Restore audit policies
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled"
    
    # Restore LLMNR
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast"
    
    # Restore WPAD
    Remove-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableNetbios"
    Remove-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableICARedirect"
    
    Write-Status -Types "+" -Status "Security settings reverted"
}

# ========== REVERT USER EXPERIENCE SETTINGS ==========
function Revert-UserExperienceSettings {
    Write-Status -Types "@" -Status "Reverting user experience settings..."
    
    # Restore light theme
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 1
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 1
    
    # Restore Windows suggestions
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Value 1
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Value 1
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Value 1
    
    # Restore notifications
    Remove-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NUI_Ghosting_Enabled"
    
    # Restore animations
    Set-ItemPropertyVerified -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Value "1"
    Remove-ItemPropertyVerified -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask"
    
    Write-Status -Types "+" -Status "User experience settings reverted"
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
    Write-Host "- Re-enable Hyper-V and related services" -ForegroundColor White
    Write-Host "- Restore default service configurations" -ForegroundColor White
    Write-Host "- Re-enable telemetry and diagnostics" -ForegroundColor White
    Write-Host "- Restore privacy settings" -ForegroundColor White
    Write-Host "- Revert performance and UI settings" -ForegroundColor White
    Write-Host "- Restore Windows Update to default" -ForegroundColor White
    Write-Host "- Revert network and security settings" -ForegroundColor White
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
    
    # 3. Services revert
    Write-Host "`n=== SERVICES ===" -ForegroundColor Cyan
    Enable-IntelLMS
    Revert-AdobeServices
    Enable-TeredoIPv6
    Revert-Services
    
    # 4. Windows Features revert
    Write-Host "`n=== WINDOWS FEATURES ===" -ForegroundColor Cyan
    Enable-WindowsFeatures
    
    # 5. Privacy and diagnostics revert
    Write-Host "`n=== PRIVACY AND DIAGNOSTICS ===" -ForegroundColor Cyan
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
    
    # 6. Windows Update revert
    Write-Host "`n=== WINDOWS UPDATE ===" -ForegroundColor Cyan
    Set-WindowsUpdateDefault
    
    # 7. Performance settings revert
    Write-Host "`n=== PERFORMANCE SETTINGS ===" -ForegroundColor Cyan
    Revert-PerformanceSettings
    Revert-SystemPerformance
    
    # 8. Network settings revert
    Write-Host "`n=== NETWORK SETTINGS ===" -ForegroundColor Cyan
    Revert-NetworkSettings
    
    # 9. UI settings revert
    Write-Host "`n=== USER INTERFACE ===" -ForegroundColor Cyan
    Revert-ExplorerSettings
    Revert-TaskbarSettings
    Revert-StartMenuSettings
    
    # 10. Scheduled tasks revert
    Write-Host "`n=== SCHEDULED TASKS ===" -ForegroundColor Cyan
    Enable-ScheduledTasks
    
    # 11. Application settings revert
    Write-Host "`n=== APPLICATIONS ===" -ForegroundColor Cyan
    Revert-EdgeSettings
    Revert-ChromeSettings
    
    # 12. Specialized settings revert
    Write-Host "`n=== SPECIALIZED SETTINGS ===" -ForegroundColor Cyan
    Revert-GamingSettings
    Revert-AudioSettings
    Revert-FirewallSettings
    Revert-DNSSettings
    Revert-MaintenanceSettings
    Revert-RegistrySettings
    Revert-SecuritySettings
    Revert-UserExperienceSettings
    
    # 13. Remove utilities
    Write-Host "`n=== UTILITIES ===" -ForegroundColor Cyan
    Remove-GodMode
    
    # FINAL SUMMARY
    Write-Host ""
    Write-Host "================================================" -ForegroundColor Green
    Write-Host "    REVERT PROCESS COMPLETED!" -ForegroundColor Green
    Write-Host "================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "SUMMARY OF REVERTED CHANGES:" -ForegroundColor Yellow
    Write-Host "  - Hyper-V re-enabled" -ForegroundColor Green
    Write-Host "  - SSD optimizations reverted" -ForegroundColor Green
    Write-Host "  - Hibernation and page file restored" -ForegroundColor Green
    Write-Host "  - Services configuration restored" -ForegroundColor Green
    Write-Host "  - Windows features re-enabled" -ForegroundColor Green
    Write-Host "  - Telemetry and diagnostics re-enabled" -ForegroundColor Green
    Write-Host "  - Privacy settings restored" -ForegroundColor Green
    Write-Host "  - Windows Update restored to default" -ForegroundColor Green
    Write-Host "  - Performance settings reverted" -ForegroundColor Green
    Write-Host "  - Network settings reverted" -ForegroundColor Green
    Write-Host "  - UI settings restored" -ForegroundColor Green
    Write-Host "  - Scheduled tasks re-enabled" -ForegroundColor Green
    Write-Host "  - Application settings reverted" -ForegroundColor Green
    Write-Host "  - Specialized settings restored" -ForegroundColor Green
    Write-Host "  - God Mode removed" -ForegroundColor Green
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
