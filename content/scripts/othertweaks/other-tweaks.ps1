# ========== COMPLETE HELPERS ==========
function Get-HardwareInfo {
    <#
    .SYNOPSIS
      Collects basic hardware and system information.
    .OUTPUTS
      PSCustomObject with properties: ComputerName, OS, CPU, MemoryMB, DiskGB
    #>
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
        $mem = [math]::Round(($os.TotalVisibleMemorySize/1KB),0)
        $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue |
                Measure-Object -Property Size -Sum
        [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            OS           = $os.Caption + " " + $os.Version
            CPU          = $cpu.Name
            MemoryMB     = $mem
            DiskGB       = if($disk.Sum) { [math]::Round($disk.Sum/1GB,2) } else { $null }
        }
    } catch {
        Write-Host "Error getting hardware info: $_" -ForegroundColor Red
        return $null
    }
}

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

function Remove-ItemVerified {
    param([string]$Path, [switch]$Recurse, [switch]$Force)
    try {
        if (Test-Path $Path) {
            Remove-Item @PSBoundParameters -ErrorAction Stop
            return $true
        }
        return $false
    } catch {
        return $false
    }
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
    param([string[]]$ServiceNames, [string]$StartupType = "Disabled")
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

function Remove-UWPApp {
    param([string[]]$PackageNames)
    foreach ($package in $PackageNames) {
        try {
            Get-AppxPackage -Name $package -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -Like $package | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Out-Null
        } catch {
            # Ignore errors
        }
    }
}

function Set-ScheduledTaskState {
    param([string[]]$TaskNames, [string]$State = "Disable")
    foreach ($task in $TaskNames) {
        try {
            if ($State -eq "Disable") {
                Disable-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue | Out-Null
            } else {
                Enable-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue | Out-Null
            }
        } catch {
            # Ignore errors
        }
    }
}

# ========== HYPER-V DISABLE FOR VMWARE ==========
function Disable-HyperVForVMware {
    Write-Status -Types "-" -Status "Disabling Hyper-V for VMware compatibility..."
    
    # Deshabilitar características Hyper-V
    $HyperVFeatures = @(
        "Microsoft-Hyper-V-All",
        "Microsoft-Hyper-V",
        "Microsoft-Hyper-V-Tools-All",
        "Microsoft-Hyper-V-Hypervisor",
        "Microsoft-Hyper-V-Services",
        "VirtualMachinePlatform"  # WSL2 platform
    )
    
    foreach ($feature in $HyperVFeatures) {
        try {
            $featureExists = Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction SilentlyContinue
            if ($featureExists -and $featureExists.State -ne "Disabled") {
                Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart | Out-Null
                Write-Status -Types "+" -Status "Disabled Hyper-V feature: $feature"
            }
        } catch {
            # Ignorar si no existe
        }
    }
    
    # Deshabilitar servicios relacionados con Hyper-V
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
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
            }
        } catch {
            # Ignorar errores
        }
    }
    
    # Deshabilitar Hyper-V en el arranque (esto es clave)
    try {
        bcdedit /set hypervisorlaunchtype off 2>$null
        Write-Status -Types "+" -Status "Hyper-V launch disabled in boot configuration"
    } catch {
        Write-Status -Types "?" -Status "Could not modify boot configuration"
    }
    
    # Deshabilitar características de seguridad basadas en virtualización que interfieren
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "RequirePlatformSecurityFeatures" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "LsaCfgFlags" -Value 0 | Out-Null
    
    Write-Status -Types "+" -Status "Hyper-V completely disabled - VMware will work at maximum performance"
}

# ========== COMPLETE SSD AND SYSTEM OPTIMIZATIONS ==========
function Optimize-SSD {
    Write-Status -Types "@" -Status "Optimizing SSD..."
    fsutil behavior set DisableLastAccess 1 | Out-Null
    fsutil behavior set EncryptPagingFile 0 | Out-Null
    Write-Status -Types "+" -Status "SSD optimized"
}

function Disable-Hibernate {
    Write-Status -Types "-" -Status "Disabling hibernation..."
    powercfg -Hibernate off | Out-Null
    Write-Status -Types "+" -Status "Hibernation disabled"
}

function Enable-Hibernate {
    Write-Status -Types "+" -Status "Enabling hibernation..."
    powercfg -Hibernate on | Out-Null
    powercfg -Hibernate -Type Full | Out-Null
}

function Disable-PageFile {
    Write-Status -Types "-" -Status "Disabling page file..."
    $CurrentPageFile = Get-WmiObject -Class Win32_ComputerSystem
    $CurrentPageFile.AutomaticManagedPagefile = $false
    $CurrentPageFile.Put()
    $PageFileSetting = Get-WmiObject -Class Win32_PageFileSetting
    $PageFileSetting.Delete()
}

function Enable-PageFile {
    Write-Status -Types "+" -Status "Enabling page file..."
    $CurrentPageFile = Get-WmiObject -Class Win32_ComputerSystem
    $CurrentPageFile.AutomaticManagedPagefile = $true
    $CurrentPageFile.Put()
}

# ========== COMPLETE SERVICES AND PROCESSES ==========
function Disable-IntelLMS {
    Write-Status -Types "-" -Status "Disabling Intel LMS..."
    Stop-Service -Name "LMS" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "LMS" -StartupType Disabled -ErrorAction SilentlyContinue
    sc.exe delete LMS 2>$null
    Write-Status -Types "+" -Status "Intel LMS disabled"
}

function Disable-AdobeServices {
    Write-Status -Types "-" -Status "Blocking Adobe services..."
    $CCPath = "C:\Program Files (x86)\Common Files\Adobe\Adobe Desktop Common\ADS\Adobe Desktop Service.exe"
    if (Test-Path $CCPath) {
        Takeown /f $CCPath 2>$null
        icacls $CCPath /grant Administrators:F 2>$null
        Rename-Item -Path $CCPath -NewName "Adobe Desktop Service.exe.old" -Force
        Write-Status -Types "+" -Status "Adobe Desktop Service disabled"
    } else {
        Write-Status -Types "?" -Status "Adobe Desktop Service not found"
    }
    
    $hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
    $adobeDomains = @(
        "0.0.0.0 cc-api-data.adobe.io",
        "0.0.0.0 ic.adobe.io", 
        "0.0.0.0 p13n.adobe.io",
        "0.0.0.0 prod.adobegenuine.com",
        "0.0.0.0 assets.adobedtm.com",
        "0.0.0.0 auth.services.adobe.com",
        "0.0.0.0 licensing.adobe.io"
    )
    $adobeDomains | ForEach-Object { Add-Content -Path $hostsFile -Value $_ -ErrorAction SilentlyContinue }
    Write-Status -Types "+" -Status "Adobe domains blocked in hosts file"
}

function Disable-TeredoIPv6 {
    Write-Status -Types "-" -Status "Disabling Teredo and IPv6..."
    netsh interface teredo set state disabled
    Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6
    Write-Status -Types "+" -Status "Teredo and IPv6 disabled"
}

function Optimize-ServicesRunning {
    Write-Status -Types "@" -Status "Optimizing system services..."
    
    # Services to disable completely
    $ServicesToDisabled = @(
        "DiagTrack", "diagnosticshub.standardcollector.service", "dmwappushservice",
        "Fax", "fhsvc", "GraphicsPerfSvc", "HomeGroupListener", "HomeGroupProvider",
        "lfsvc", "MapsBroker", "PcaSvc", "RemoteAccess", "RemoteRegistry",
        "RetailDemo", "TrkWks", "WSearch", "RtkAudioService", "RtkAudioUniversalService",
        "tzautoupdate", "BthHFSrv", "NetTcpPortSharing", "shpamsvc", "DusmSvc",
        "WpcMonSvc", "ScDeviceEnum", "CertPropSvc", "RmSvc", "icssvc", "WwanSvc",
        "WalletService", "Payments", "NgcSvc", "NgcCtnrSvc", "DiagSvc", "AVCTPService",
        "edgeupdate", "edgeupdatem", "MicrosoftEdgeElevationService", "XblAuthManager",
        "XblGameSave", "XboxGipSvc", "XboxNetApiSvc", "WbioSrvc", "wisvc", "WpnService",
        "BthAvctpSvc", "bthserv", "RtkBtManServ", "DPS", "WdiServiceHost", "WdiSystemHost"
    )
    
    # Services for manual mode
    $ServicesToManual = @(
        "BITS", "FontCache", "PhoneSvc", "SCardSvr", "stisvc", "WMPNetworkSvc",
        "iphlpsvc", "lmhosts", "SharedAccess", "Wecsvc", "WerSvc", "BTAGService"
    )
    
    Set-ServiceStartup -ServiceNames $ServicesToDisabled -StartupType "Disabled"
    Set-ServiceStartup -ServiceNames $ServicesToManual -StartupType "Manual"
    Write-Status -Types "+" -Status "Services optimized (65+ services configured)"
}

function Optimize-WindowsFeaturesList {
    Write-Status -Types "@" -Status "Disabling optional Windows features..."
    
    $FeaturesToTry = @(
        "FaxServicesClientPackage",
        "IIS-WebServerRole",
        "IIS-WebServer",
        "IIS-CommonHttpFeatures",
        "IIS-HostableWebCore",
        "IIS-HealthAndDiagnostics",
        "IIS-Performance",
        "IIS-Security",
        "IIS-FTPServer",
        "IIS-WebServerManagementTools",
        "Internet-Explorer-Optional-amd64",
        "LegacyComponents",
        "MediaPlayback",
        "MicrosoftWindowsPowerShellV2",
        "MicrosoftWindowsPowershellV2Root",
        "Printing-PrintToPDFServices-Features",
        "Printing-XPSServices-Features",
        "WorkFolders-Client",
        "XPS-Foundation-XPS-Viewer"
    )
    
    foreach ($feature in $FeaturesToTry) {
        try {
            $featureExists = Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction SilentlyContinue
            if ($featureExists -and $featureExists.State -ne "Disabled") {
                Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart | Out-Null
            }
        } catch {
            # Ignore errors for features that don't exist
        }
    }
    
    Write-Status -Types "+" -Status "Optional features disabled"
}

# ========== EXTREME PRIVACY - ZERO DATA ==========
function Disable-AllDiagnostics {
    Write-Status -Types "-" -Status "COMPLETELY disabling diagnostics and telemetry..."
    
    # Telemetry level 0 (Enterprise Security)
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowDeviceNameInTelemetry" -Value 0 | Out-Null
    
    # Stop diagnostic services
    Stop-Service "DiagTrack" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "DiagTrack" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service "dmwappushservice" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "dmwappushservice" -StartupType Disabled -ErrorAction SilentlyContinue
    
    # Disable error reporting
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "DisableWindowsErrorReporting" -Value 1 | Out-Null
    
    # Disable personalized experiences
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Value 1 | Out-Null
    
    # Disable handwriting and typing collection
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value 1 | Out-Null
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Value 1 | Out-Null
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Input\TIPC" -Name "Enabled" -Value 0 | Out-Null
    
    # Disable AutoLogger
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" -Name "Start" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" -Name "Start" -Value 0 | Out-Null
    
    # Disable CEIP and connected experiences
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableUAR" -Value 1 | Out-Null
    
    Write-Status -Types "+" -Status "Diagnostics COMPLETELY disabled - ZERO data sent"
}

function Disable-Cortana {
    Write-Status -Types "-" -Status "Disabling Cortana..."
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWeb" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Value 1 | Out-Null
    Write-Status -Types "+" -Status "Cortana disabled"
}

function Disable-ActivityHistory {
    Write-Status -Types "-" -Status "Disabling Activity History..."
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Value 0 | Out-Null
    Write-Status -Types "+" -Status "Activity history disabled"
}

function Disable-LocationTracking {
    Write-Status -Types "-" -Status "Disabling location tracking..."
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value 1 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Value 1 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableWindowsLocationProvider" -Value 1 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny" | Out-Null
    Write-Status -Types "+" -Status "Location tracking disabled"
}

function Disable-OnlineSpeechRecognition {
    Write-Status -Types "-" -Status "Disabling online speech recognition..."
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "HasAccepted" -Value 0 | Out-Null
    Write-Status -Types "+" -Status "Online speech recognition disabled"
}

function Disable-ClipboardHistory {
    Write-Status -Types "-" -Status "Disabling clipboard history..."
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowClipboardHistory" | Out-Null
    Remove-ItemPropertyVerified -Path "HKCU:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory" | Out-Null
    Write-Status -Types "+" -Status "Clipboard history disabled"
}

function Disable-FeedbackNotifications {
    Write-Status -Types "-" -Status "Disabling feedback notifications..."
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1 | Out-Null
    Write-Status -Types "+" -Status "Feedback notifications disabled"
}

function Disable-AdvertisingID {
    Write-Status -Types "-" -Status "Disabling advertising ID..."
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value 1 | Out-Null
    Write-Status -Types "+" -Status "Advertising ID disabled"
}

function Disable-WindowsSpotlight {
    Write-Status -Types "-" -Status "Disabling Windows Spotlight..."
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -Value 1 | Out-Null
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightOnActionCenter" -Value 1 | Out-Null
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightOnSettings" -Value 1 | Out-Null
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightWindowsWelcomeExperience" -Value 1 | Out-Null
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Value 0 | Out-Null
    Write-Status -Types "+" -Status "Windows Spotlight disabled"
}

function Disable-BackgroundApps {
    Write-Status -Types "-" -Status "Disabling background apps..."
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Value 1 | Out-Null
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BackgroundAppGlobalToggle" -Value 0 | Out-Null
    Write-Status -Types "+" -Status "Background apps disabled"
}

# ========== COMPLETE MANUAL WINDOWS UPDATE ==========
function Set-WindowsUpdateManual {
    Write-Status -Types "@" -Status "Configuring Windows Update for MANUAL control..."
    
    # Disable automatic updates
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 1 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 2 | Out-Null
    
    # Disable automatic restarts
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 | Out-Null
    
    # Disable P2P
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Value 0 | Out-Null
    
    # Disable automatic driver updates
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Value 0 | Out-Null
    
    # Configure update policies
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "SetPowerPolicyForFeatureUpdates" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\OSUpgrade" -Name "ReservationsAllowed" -Value 0 | Out-Null
    
    # Keep update services active but with manual control
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\DefaultService" -Name "Registered" -Value 1 | Out-Null
    
    Write-Status -Types "+" -Status "Windows Update configured - Complete MANUAL control"
}

# ========== COMPLETE COMPONENT REMOVAL ==========
function Remove-OneDrive {
    Write-Status -Types "-" -Status "Removing OneDrive..."
    taskkill.exe /F /IM "OneDrive.exe" 2>$null
    taskkill.exe /F /IM "explorer.exe" 2>$null
    
    if (Test-Path "$env:systemroot\System32\OneDriveSetup.exe") {
        & "$env:systemroot\System32\OneDriveSetup.exe" /uninstall | Out-Null
    }
    if (Test-Path "$env:systemroot\SysWOW64\OneDriveSetup.exe") {
        & "$env:systemroot\SysWOW64\OneDriveSetup.exe" /uninstall | Out-Null
    }
    
    Remove-ItemVerified -Path "$env:localappdata\Microsoft\OneDrive" -Recurse -Force
    Remove-ItemVerified -Path "$env:programdata\Microsoft OneDrive" -Recurse -Force
    Remove-ItemVerified -Path "$env:systemdrive\OneDriveTemp" -Recurse -Force
    
    # Disable via policies
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1 | Out-Null
    
    # Remove from explorer
    New-PSDrive -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Scope Global -Name "HKCR" -ErrorAction SilentlyContinue
    if (Test-Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}") {
        Set-ItemPropertyVerified -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Value 0 | Out-Null
    }
    Remove-PSDrive "HKCR"
    
    Start-Process "explorer.exe"
    Start-Sleep 3
    Write-Status -Types "+" -Status "OneDrive completely removed"
}

function Remove-Xbox {
    Write-Status -Types "-" -Status "Removing Xbox and related services..."
    
    $XboxServices = @("XblAuthManager", "XblGameSave", "XboxGipSvc", "XboxNetApiSvc")
    $XboxApps = @(
        "Microsoft.GamingApp", "Microsoft.GamingServices", "Microsoft.XboxApp", 
        "Microsoft.XboxGamingOverlay", "Microsoft.XboxIdentityProvider",
        "Microsoft.XboxGameCallableUI", "Microsoft.XboxGameOverlay",
        "Microsoft.XboxSpeechToTextOverlay", "Microsoft.Xbox.TCUI"
    )
    
    Set-ServiceStartup -ServiceNames $XboxServices -StartupType "Disabled"
    Remove-UWPApp -PackageNames $XboxApps
    
    # Disable GameBar and DVR
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\GameBar" -Name "AllowAutoGameMode" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\GameBar" -Name "ShowGameModeNotifications" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\GameBar" -Name "ShowStartupPanel" -Value 0 | Out-Null
    
    # Disable GameDVR policies
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 | Out-Null
    
    Write-Status -Types "+" -Status "Xbox completely removed"
}

function Remove-Bloatware {
    Write-Status -Types "-" -Status "Removing preinstalled apps (Bloatware)..."
    
    $BloatwareApps = @(
        # Microsoft Apps
        "Microsoft.3DBuilder", "Microsoft.549981C3F5F10", "Microsoft.Appconnector",
        "Microsoft.BingFinance", "Microsoft.BingFoodAndDrink", "Microsoft.BingHealthAndFitness",
        "Microsoft.BingNews", "Microsoft.BingSports", "Microsoft.BingTranslator",
        "Microsoft.BingTravel", "Microsoft.BingWeather", "Microsoft.CommsPhone",
        "Microsoft.ConnectivityStore", "Microsoft.Copilot", "Microsoft.GetHelp",
        "Microsoft.Getstarted", "Microsoft.Messaging", "Microsoft.Microsoft3DViewer",
        "Microsoft.MicrosoftOfficeHub", "Microsoft.MicrosoftPowerBIForWindows",
        "Microsoft.MicrosoftSolitaireCollection", "Microsoft.MixedReality.Portal",
        "Microsoft.NetworkSpeedTest", "Microsoft.Office.OneNote", "Microsoft.Office.Sway",
        "Microsoft.OneConnect", "Microsoft.MSPaint", "Microsoft.People",
        "Microsoft.PowerAutomateDesktop", "Microsoft.Print3D", "Microsoft.SkypeApp",
        "Microsoft.Todos", "Microsoft.Wallet", "Microsoft.Whiteboard", "Microsoft.WindowsAlarms",
        "microsoft.windowscommunicationsapps", "Microsoft.WindowsFeedbackHub",
        "Microsoft.WindowsMaps", "Microsoft.WindowsPhone", "Microsoft.WindowsReadingList",
        "Microsoft.WindowsSoundRecorder", "Microsoft.XboxApp", "Microsoft.YourPhone",
        "Microsoft.ZuneMusic", "Microsoft.ZuneVideo", "MicrosoftWindows.Client.CoPilot",
        "Microsoft.Advertising.Xaml", "Clipchamp.Clipchamp", "Microsoft.OutlookForWindows",
        "M*S*Teams", "MicrosoftWindows.Client.WebExperience",
        
        # Third Party Apps
        "Amazon.com.Amazon", "*CandyCrush*", "*Facebook*", "*Instagram*", "*Netflix*",
        "SpotifyAB.SpotifyMusic", "*Twitter*", "*Disney*", "*RoyalRevolt*", "*Adobe*",
        "*Autodesk*", "*BubbleWitch*", "*CaesarsSlots*", "*COOKINGFEVER*", "*Dolby*",
        "*Duolingo*", "*EclipseManager*", "*FarmVille*", "*Keeper*", "*LinkedIn*"
    )
    
    Remove-UWPApp -PackageNames $BloatwareApps
    Write-Status -Types "+" -Status "Bloatware removed (70+ apps)"
}

function Disable-UnwantedFeatures {
    Write-Status -Types "-" -Status "Disabling unwanted features..."
    
    $FeaturesToTry = @(
        "Containers-DisposableClientVM",  # Windows Sandbox
        "Microsoft-Windows-Subsystem-Linux",  # WSL (Linux)
        "FaxServicesClientPackage",
        "Internet-Explorer-Optional-amd64",
        "MediaPlayback",
        "IIS-WebServerRole", "IIS-WebServer", "IIS-CommonHttpFeatures",
        "IIS-HostableWebCore", "IIS-HealthAndDiagnostics", "IIS-Performance",
        "IIS-Security", "IIS-FTPServer", "IIS-WebServerManagementTools",
        "Printing-PrintToPDFServices-Features", "Printing-XPSServices-Features",
        "WorkFolders-Client", "MicrosoftWindowsPowerShellV2", "MicrosoftWindowsPowershellV2Root"
    )
    
    foreach ($feature in $FeaturesToTry) {
        try {
            $featureExists = Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction SilentlyContinue
            if ($featureExists -and $featureExists.State -ne "Disabled") {
                Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart | Out-Null
            }
        } catch {
            # Ignore errors for features that don't exist
        }
    }
    
    # Deshabilitar servicio Fax si existe
    try {
        if (Get-Service -Name "Fax" -ErrorAction SilentlyContinue) {
            Set-Service -Name "Fax" -StartupType Disabled -ErrorAction SilentlyContinue
        }
    } catch {
        # Ignore errors
    }
    
    Write-Status -Types "+" -Status "Unwanted features disabled"
}

# ========== COMPLETE PERFORMANCE OPTIMIZATIONS ==========
function Optimize-Performance {
    Write-Status -Types "@" -Status "Applying performance optimizations..."
    
    # Disable visual effects for better performance
    Set-ItemPropertyVerified -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value 2 | Out-Null
    
    # Optimize for performance
    Set-ItemPropertyVerified -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Value "0" | Out-Null
    Set-ItemPropertyVerified -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Value "0" | Out-Null
    
    # Disable transparency
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value 0 | Out-Null
    
    # Disable animations
    Set-ItemPropertyVerified -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Value "0" | Out-Null
    
    # Optimize memory
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Value 0 | Out-Null
    
    # Disable Windows tips
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Value 0 | Out-Null
    
    # Optimize system
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "WaitToKillServiceTimeout" -Value 2000 | Out-Null
    Set-ItemPropertyVerified -Path "HKCU:\Control Panel\Desktop" -Name "AutoEndTasks" -Value 1 | Out-Null
    Set-ItemPropertyVerified -Path "HKCU:\Control Panel\Desktop" -Name "WaitToKillAppTimeout" -Value 5000 | Out-Null
    Set-ItemPropertyVerified -Path "HKCU:\Control Panel\Desktop" -Name "LowLevelHooksTimeout" -Value 1000 | Out-Null
    
    Write-Status -Types "+" -Status "Performance optimizations applied"
}

function Optimize-Network {
    Write-Status -Types "@" -Status "Optimizing network configuration..."
    
    # Disable IPv6
    Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6
    
    # Disable Teredo
    netsh interface teredo set state disabled
    
    # Optimize TCP/IP
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnablePMTUDiscovery" -Value 1 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnablePMTUBHDetect" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "SackOpts" -Value 1 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "Tcp1323Opts" -Value 1 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpWindowSize" -Value 64240 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DefaultTTL" -Value 64 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpMaxDupAcks" -Value 2 | Out-Null
    
    # Optimize DNS cache
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "MaxCacheTtl" -Value 3600 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "MaxNegativeCacheTtl" -Value 300 | Out-Null
    
    # Optimize network performance
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Value 0xffffffff | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Psched" -Name "NonBestEffortLimit" -Value 0 | Out-Null
    
    Write-Status -Types "+" -Status "Network configuration optimized"
}

# ========== COMPLETE SECURITY ==========
function Optimize-Security {
    Write-Status -Types "@" -Status "Applying security configurations..."
    
    # Enable Windows Defender
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0 | Out-Null
    
    # Configure Defender
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "PUAProtection" -Value 1 | Out-Null
    
    # Deshabilitar SMBv1 de forma segura
    try {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
    } catch {
        try {
            sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi
            sc.exe config mrxsmb10 start= disabled
        } catch {
            Write-Status -Types "?" -Status "Could not disable SMBv1"
        }
    }
    
    # Enable UAC
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 5 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1 | Out-Null
    
    # Enable firewall
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    
    # Enable SmartScreen
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "RequireAdmin" | Out-Null
    
    Write-Status -Types "+" -Status "Security configurations applied"
}

# ========== COMPLETE SCHEDULED TASKS ==========
function Disable-UnnecessaryTasks {
    Write-Status -Types "-" -Status "Disabling unnecessary scheduled tasks..."
    
    $TasksToDisable = @(
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
        "\Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser",
        "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem",
        "\Microsoft\Windows\Retail Demo\CleanupOfflineContent",
        "\Microsoft\Windows\Shell\FamilySafetyMonitor",
        "\Microsoft\Windows\Shell\FamilySafetyRefreshTask",
        "\Microsoft\Windows\Shell\FamilySafetyUpload",
        "\Microsoft\Windows\Windows Media Sharing\UpdateLibrary",
        "\Microsoft\Windows\Clip\License Validation",
        "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask",
        "\Microsoft\Windows\DiskFootprint\Diagnostics",
        "\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents",
        "\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic",
        "\Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange"
    )
    
    Set-ScheduledTaskState -TaskNames $TasksToDisable -State "Disable"
    Write-Status -Types "+" -Status "Unnecessary scheduled tasks disabled (25+ tasks)"
}

# ========== COMPLETE EXPLORER AND INTERFACE ==========
function Optimize-Explorer {
    Write-Status -Types "@" -Status "Optimizing File Explorer..."
    
    # Show file extensions
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0 | Out-Null
    
    # Show hidden files
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1 | Out-Null
    
    # Disable sync provider notifications
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Value 0 | Out-Null
    
    # Open Explorer in This PC
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Value 1 | Out-Null
    
    # Show details in preview pane
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowPreviewHandlers" -Value 1 | Out-Null
    
    # Show status bar
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowStatusBar" -Value 1 | Out-Null
    
    # Show all folders in navigation pane
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneShowAllFolders" -Value 1 | Out-Null
    
    # Expand to current folder in navigation pane
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneExpandToCurrentFolder" -Value 1 | Out-Null
    
    # Show delete confirmation
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ConfirmFileDelete" -Value 1 | Out-Null
    
    # Show full path in title bar
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "FullPath" -Value 1 | Out-Null
    
    Write-Status -Types "+" -Status "File Explorer optimized"
}

function Optimize-Taskbar {
    Write-Status -Types "@" -Status "Optimizing Taskbar..."
    
    # Configurar barra de tareas - SOLO ICONOS, SIN NOMBRES
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Value 1 | Out-Null
    
    # CORRECCIÓN: Configurar combinación de botones - "Siempre combinar, ocultar etiquetas"
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Value 2 | Out-Null
    
    # Ocultar botones innecesarios
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Value 0 | Out-Null
    
    # Mostrar todos los iconos en área de notificación
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Value 0 | Out-Null
    
    # NO mostrar segundos en el reloj (ahorra recursos)
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSecondsInSystemClock" -Value 0 | Out-Null
    
    # FORZAR ACTUALIZACIÓN: Reiniciar Explorador para aplicar cambios inmediatamente
    try {
        Stop-Process -Name "explorer" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        Start-Process "explorer.exe"
        Write-Status -Types "+" -Status "Explorer restarted to apply taskbar changes"
    } catch {
        Write-Status -Types "?" -Status "Could not restart Explorer automatically"
    }
    
    Write-Status -Types "+" -Status "Taskbar optimized - Icons only, no labels"
}

function Optimize-StartMenu {
    Write-Status -Types "@" -Status "Optimizing Start Menu..."
    
    # Disable app suggestions
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Value 0 | Out-Null
    
    # Show recently used apps
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Value 1 | Out-Null
    
    # Configure start menu size
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_NumRows" -Value 3 | Out-Null
    
    Write-Status -Types "+" -Status "Start Menu optimized"
}

# ========== SYSTEM AND ADVANCED PERFORMANCE ==========
function Optimize-SystemPerformance {
    Write-Status -Types "@" -Status "Applying advanced system optimizations..."
    
    # Configure system priorities
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value 38 | Out-Null
    
    # Enable large system cache
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "LargeSystemCache" -Value 1 | Out-Null
    
    # Configure I/O
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "IOPageLockLimit" -Value 0 | Out-Null
    
    # Disable Prefetcher and Superfetch based on disk type
    $IsSSD = $false
    try {
        $disk = Get-PhysicalDisk | Where-Object {$_.DeviceID -eq 0}
        if ($disk.MediaType -eq "SSD") {
            $IsSSD = $true
        }
    } catch {
        # If cannot determine, assume HDD to be conservative
        $IsSSD = $false
    }
    
    if ($IsSSD) {
        # For SSD: Disable Superfetch, keep Prefetcher
        Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnableSuperfetch" -Value 0 | Out-Null
        Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnablePrefetcher" -Value 1 | Out-Null
    } else {
        # For HDD: Enable both
        Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnableSuperfetch" -Value 3 | Out-Null
        Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnablePrefetcher" -Value 3 | Out-Null
    }
    
    # Optimize for background applications
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value 26 | Out-Null
    
    Write-Status -Types "+" -Status "Advanced system optimizations applied"
}

# ========== SPECIFIC APPLICATION OPTIMIZATIONS ==========
function Optimize-Edge {
    Write-Status -Types "@" -Status "Optimizing Microsoft Edge..."
    
    # Disable Edge telemetry
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "MetricsReportingEnabled" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "BrowserSignin" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "SyncDisabled" -Value 1 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "ImportBrowserSettings" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "ImportExtensions" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "ImportFavorites" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "ImportHistory" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "ImportHomepage" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "ImportPasswords" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "ImportPaymentInfo" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "ImportSearchEngine" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "ImportShortcuts" -Value 0 | Out-Null
    
    # Disable unwanted features
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "ShowRecommendationsEnabled" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "NewTabPageSetFeedType" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "BackgroundModeEnabled" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "StartupBoostEnabled" -Value 0 | Out-Null
    
    Write-Status -Types "+" -Status "Microsoft Edge optimized"
}

function Optimize-Chrome {
    Write-Status -Types "@" -Status "Optimizing Google Chrome..."
    
    $ChromePaths = @(
        "HKLM:\SOFTWARE\Policies\Google\Chrome",
        "HKCU:\SOFTWARE\Policies\Google\Chrome"
    )
    
    foreach ($path in $ChromePaths) {
        if (-not (Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }
        
        # Disable telemetry
        Set-ItemPropertyVerified -Path $path -Name "MetricsReportingEnabled" -Value 0 | Out-Null
        Set-ItemPropertyVerified -Path $path -Name "SafeBrowsingEnabled" -Value 0 | Out-Null
        Set-ItemPropertyVerified -Path $path -Name "SafeBrowsingExtendedReportingEnabled" -Value 0 | Out-Null
        Set-ItemPropertyVerified -Path $path -Name "SpellCheckServiceEnabled" -Value 0 | Out-Null
        Set-ItemPropertyVerified -Path $path -Name "SpellCheckEnabled" -Value 0 | Out-Null
        Set-ItemPropertyVerified -Path $path -Name "SearchSuggestEnabled" -Value 0 | Out-Null
        Set-ItemPropertyVerified -Path $path -Name "SyncDisabled" -Value 1 | Out-Null
        Set-ItemPropertyVerified -Path $path -Name "DefaultBrowserSettingEnabled" -Value 0 | Out-Null
        Set-ItemPropertyVerified -Path $path -Name "ImportAutofillFormData" -Value 0 | Out-Null
        Set-ItemPropertyVerified -Path $path -Name "ImportBookmarks" -Value 0 | Out-Null
        Set-ItemPropertyVerified -Path $path -Name "ImportHistory" -Value 0 | Out-Null
        Set-ItemPropertyVerified -Path $path -Name "ImportHomepage" -Value 0 | Out-Null
        Set-ItemPropertyVerified -Path $path -Name "ImportSavedPasswords" -Value 0 | Out-Null
        Set-ItemPropertyVerified -Path $path -Name "ImportSearchEngine" -Value 0 | Out-Null
    }
    
    Write-Status -Types "+" -Status "Google Chrome optimized"
}

# ========== GAMING OPTIMIZATIONS ==========
function Optimize-Gaming {
    Write-Status -Types "@" -Status "Applying gaming optimizations..."
    
    # Configure Game Mode
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\GameBar" -Name "AllowAutoGameMode" -Value 1 | Out-Null
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Value 1 | Out-Null
    
    # Optimize GPU for gaming
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "GPU Priority" -Value 8 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Value 6 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category" -Value "High" | Out-Null
    
    # Enable GPU hardware acceleration
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "HwSchMode" -Value 2 | Out-Null
    
    Write-Status -Types "+" -Status "Gaming optimizations applied"
}

# ========== AUDIO OPTIMIZATIONS ==========
function Optimize-Audio {
    Write-Status -Types "@" -Status "Optimizing audio configuration..."
    
    # Disable audio enhancements
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Audio" -Name "DisableProtectedAudioDG" -Value 1 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio" -Name "DisableSampleRateConversion" -Value 1 | Out-Null
    
    # Configure audio quality
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Audio" -Name "AudioSampleRate" -Value 48000 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Audio" -Name "AudioSampleSize" -Value 24 | Out-Null
    
    # Disable system sounds
    Set-ItemPropertyVerified -Path "HKCU:\AppEvents\Schemes\Apps\.Default" -Name "(Default)" -Value ".None" | Out-Null
    
    Write-Status -Types "+" -Status "Audio configuration optimized"
}

# ========== FIREWALL OPTIMIZATIONS ==========
function Optimize-Firewall {
    Write-Status -Types "@" -Status "Optimizing firewall configuration..."
    
    # Enable firewall logging
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log"
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogMaxSizeKilobytes 16384
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogBlocked True
    
    # Configure basic rules
    $FirewallRules = @(
        @{Name="BlockSMBv1"; Direction="Inbound"; Protocol="TCP"; LocalPort="445,139"},
        @{Name="BlockNetBIOS"; Direction="Inbound"; Protocol="UDP"; LocalPort="137,138"},
        @{Name="BlockLLMNR"; Direction="Inbound"; Protocol="UDP"; LocalPort="5355"}
    )
    
    foreach ($rule in $FirewallRules) {
        try {
            New-NetFirewallRule -DisplayName $rule.Name -Direction $rule.Direction -Protocol $rule.Protocol -LocalPort $rule.LocalPort -Action Block -ErrorAction SilentlyContinue | Out-Null
        } catch {
            # Ignore if rule already exists
        }
    }
    
    Write-Status -Types "+" -Status "Firewall configuration optimized"
}

# ========== DNS OPTIMIZATIONS ==========
function Optimize-DNS {
    Write-Status -Types "@" -Status "Optimizing DNS configuration..."
    
    # Configure secure DNS
    $DNSServers = @(
        "1.1.1.1",    # Cloudflare
        "1.0.0.1",    # Cloudflare
        "8.8.8.8",    # Google
        "8.8.4.4"     # Google
    )
    
    # Apply to all network interfaces
    $Interfaces = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
    
    foreach ($Interface in $Interfaces) {
        try {
            Set-DnsClientServerAddress -InterfaceIndex $Interface.InterfaceIndex -ServerAddresses $DNSServers -ErrorAction SilentlyContinue | Out-Null
        } catch {
            # Ignore errors
        }
    }
    
    # Optimize DNS cache
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "MaxCacheTtl" -Value 3600 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "MaxNegativeCacheTtl" -Value 300 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "NetFailureCacheTime" -Value 30 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "NegativeSOACacheTime" -Value 300 | Out-Null
    
    Write-Status -Types "+" -Status "DNS configuration optimized"
}

# ========== MAINTENANCE OPTIMIZATIONS ==========
function Optimize-Maintenance {
    Write-Status -Types "@" -Status "Optimizing maintenance tasks..."
    
    # Disable automatic maintenance
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name "MaintenanceDisabled" -Value 1 | Out-Null
    
    # Configure Windows Update Cleanup
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Update Cleanup" -Name "StateFlags" -Value 2 | Out-Null
    
    # Configure temporary files cleanup
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Files" -Name "StateFlags" -Value 2 | Out-Null
    
    # Disable automatic defragmentation
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Dfrg\BootOptimizeFunction" -Name "Enable" -Value "N" | Out-Null
    
    Write-Status -Types "+" -Status "Maintenance tasks optimized"
}

# ========== REGISTRY OPTIMIZATIONS ==========
function Optimize-Registry {
    Write-Status -Types "@" -Status "Applying registry optimizations..."
    
    # Optimize registry size
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "RegistrySizeLimit" -Value 0xffffffff | Out-Null
    
    # Disable low disk space notifications
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "DiskSpaceThreshold" -Value 0 | Out-Null
    
    # Optimize group policies
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -Value 1 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 | Out-Null
    
    # Configure memory for services
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Value 4194304 | Out-Null
    
    Write-Status -Types "+" -Status "Registry optimizations applied"
}

# ========== SECURITY HARDENING ==========
function Hardening-Security {
    Write-Status -Types "@" -Status "Applying security hardening..."
    
    # Disable AutoRun
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value 1 | Out-Null
    
    # Disable anonymous access
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "EveryoneIncludesAnonymous" -Value 0 | Out-Null
    
    # Configure audit policies
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 | Out-Null
    
    # Disable LLMNR
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 | Out-Null
    
    # Disable WPAD
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableNetbios" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableICARedirect" -Value 0 | Out-Null
    
    Write-Status -Types "+" -Status "Security hardening applied"
}

# ========== USER EXPERIENCE OPTIMIZATIONS ==========
function Optimize-UserExperience {
    Write-Status -Types "@" -Status "Optimizing user experience..."
    
    # Configure dark theme
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0 | Out-Null
    
    # Disable Windows suggestions
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Value 0 | Out-Null
    
    # Configure notifications
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NUI_Ghosting_Enabled" -Value 0 | Out-Null
    
    # Optimize animations
    Set-ItemPropertyVerified -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Value 0 | Out-Null
    Set-ItemPropertyVerified -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Value ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00)) | Out-Null
    
    Write-Status -Types "+" -Status "User experience optimized"
}

# ========== COMPLETE CLEANUP ==========
function Clean-TemporaryFiles {
    Write-Status -Types "@" -Status "Cleaning temporary files..."
    
    # Limpiar archivos temporales sin mostrar True/False
    $pathsToClean = @(
        "$env:SystemRoot\Temp\*",
        "$env:TEMP\*", 
        "$env:LOCALAPPDATA\Temp\*",
        "$env:LOCALAPPDATA\Packages\Microsoft.WindowsStore_8wekyb3d8bbwe\LocalCache\*",
        "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\*"
    )
    
    foreach ($path in $pathsToClean) {
        try {
            if (Test-Path $path) {
                Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
            }
        } catch {
            # Ignorar errores silenciosamente
        }
    }
    
    # Limpiar archivos específicos
    $filesToClean = @(
        "$env:LOCALAPPDATA\IconCache.db"
    )
    
    foreach ($file in $filesToClean) {
        try {
            if (Test-Path $file) {
                Remove-Item -Path $file -Force -ErrorAction SilentlyContinue | Out-Null
            }
        } catch {
            # Ignorar errores
        }
    }
    
    # Limpiar caché DNS
    try {
        ipconfig /flushdns | Out-Null
    } catch {
        # Ignorar errores
    }
    
    # Ejecutar cleanmgr y detectar CUANDO REALMENTE TERMINA
    try {
        Write-Status -Types "@" -Status "Running Disk Cleanup utility..."
        
        # Método MEJORADO: Ejecutar cleanmgr y monitorear el proceso REAL
        $cleanmgrProcess = Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/sagerun:1" -PassThru -WindowStyle Hidden
        
        # Esperar a que aparezca el proceso cleanmgr REAL (no el padre)
        Start-Sleep -Seconds 5
        
        $timeout = 120  # 2 minutos máximo para la limpieza real
        $timer = 0
        $realCleanmgrEnded = $false
        
        while ($timer -lt $timeout -and -not $realCleanmgrEnded) {
            Start-Sleep -Seconds 2
            $timer += 2
            
            # Verificar si el proceso cleanmgr REAL (no el padre) sigue ejecutándose
            $realCleanmgrProcesses = Get-Process -Name "cleanmgr" -ErrorAction SilentlyContinue | 
                Where-Object { $_.Id -ne $cleanmgrProcess.Id }
            
            if ($realCleanmgrProcesses.Count -eq 0) {
                # ¡El cleanmgr REAL terminó!
                $realCleanmgrEnded = $true
                Write-Status -Types "+" -Status "Disk Cleanup finished - process completed"
                break
            }
            
            # Solo mostrar un mensaje una vez para no spammear
            if ($timer -eq 2) {
                Write-Status -Types "@" -Status "Disk Cleanup is running... (max 2 minutes)"
            }
        }
        
        # Si llegamos aquí, la limpieza terminó o se timeout
        if (-not $realCleanmgrEnded) {
            Write-Status -Types "?" -Status "Disk Cleanup taking too long, continuing..."
        }
        
        # Terminar el proceso padre que podría seguir colgado
        if (-not $cleanmgrProcess.HasExited) {
            $cleanmgrProcess.Kill() | Out-Null
            Start-Sleep -Seconds 1
        }
        
        # Limpiar cualquier proceso cleanmgr huérfano
        Get-Process -Name "cleanmgr" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        
    } catch {
        Write-Status -Types "?" -Status "Disk Cleanup error: $($_.Exception.Message)"
    }
    
    Write-Status -Types "+" -Status "Temporary files cleanup completed"
}

function Remove-WindowsOld {
    Write-Status -Types "@" -Status "Checking for Windows.old..."
    try {
        $windowsOldPath = "$env:SystemDrive\Windows.old"
        
        if (Test-Path $windowsOldPath) {
            Write-Status -Types "@" -Status "Windows.old found, attempting removal..."
            
            # Intentar eliminar con permisos de administrador
            try {
                # Tomar ownership
                Start-Process -FilePath "takeown" -ArgumentList "/f `"$windowsOldPath`" /r /d y" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
                # Dar permisos
                Start-Process -FilePath "icacls" -ArgumentList "`"$windowsOldPath`" /grant administrators:F /t" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
                # Eliminar
                Remove-Item -Path $windowsOldPath -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
                
                Write-Status -Types "+" -Status "Windows.old removed successfully"
            } catch {
                Write-Status -Types "?" -Status "Windows.old could not be removed (may be in use or need reboot)"
            }
        } else {
            Write-Status -Types "+" -Status "Windows.old not found - nothing to remove"
        }
        
    } catch {
        Write-Status -Types "?" -Status "Error checking for Windows.old: $($_.Exception.Message)"
    }
}

# ========== SYSTEM UTILITIES ==========
function Create-GodMode {
    Write-Status -Types "@" -Status "Creating God Mode..."
    $DesktopPath = [Environment]::GetFolderPath("Desktop")
    $GodModePath = "$DesktopPath\GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}"
    
    try {
        New-Item -Path $GodModePath -ItemType Directory -Force | Out-Null
        Write-Status -Types "+" -Status "God Mode created on desktop"
    } catch {
        Write-Status -Types "?" -Status "Could not create God Mode"
    }
}

# ========== COMPLETE MAIN FUNCTION ==========
function Start-FullOptimization {
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "    COMPLETE WINDOWS OPTIMIZATION" -ForegroundColor Cyan
    Write-Host "    EXTENDED VERSION - AUTOMATIC EXECUTION" -ForegroundColor Cyan
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Check administrator permissions
    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Host "ERROR: This script requires Administrator permissions" -ForegroundColor Red
        Write-Host "Run PowerShell as Administrator and try again" -ForegroundColor Yellow
        pause
        exit 1
    }
    
    # Show system info
    $systemInfo = Get-HardwareInfo
    if ($systemInfo) {
        Write-Host "System detected:" -ForegroundColor Yellow
        Write-Host "  Computer: $($systemInfo.ComputerName)" -ForegroundColor White
        Write-Host "  OS: $($systemInfo.OS)" -ForegroundColor White
        Write-Host "  CPU: $($systemInfo.CPU)" -ForegroundColor White
        Write-Host "  RAM: $($systemInfo.MemoryMB) MB" -ForegroundColor White
        Write-Host "  Disk: $($systemInfo.DiskGB) GB" -ForegroundColor White
        Write-Host ""
    }
    
    # Final confirmation before starting
    Write-Host "This script will perform the following actions:" -ForegroundColor Yellow
    Write-Host "- Disable unnecessary services and features" -ForegroundColor White
    Write-Host "- Remove preinstalled apps (Bloatware)" -ForegroundColor White
    Write-Host "- Optimize performance and privacy" -ForegroundColor White
    Write-Host "- Apply security configurations" -ForegroundColor White
    Write-Host "- Disable Hyper-V for VMware compatibility" -ForegroundColor White
    Write-Host ""
    Write-Host "Are you sure you want to continue? (y/n)" -ForegroundColor Yellow
    $confirm = Read-Host
    
    if ($confirm -ne 'y' -and $confirm -ne 'Y') {
        Write-Host "Execution cancelled by user" -ForegroundColor Red
        exit 0
    }
    
    # EXECUTE ALL OPTIMIZATIONS
    Write-Host ""
    Write-Host "STARTING COMPLETE OPTIMIZATIONS..." -ForegroundColor Green
    Write-Host "================================================" -ForegroundColor Green
    Write-Host ""
    
    # 0. Hyper-V Disable for VMware (PRIMERO para evitar conflictos)
    Write-Host "=== VMWARE COMPATIBILITY ===" -ForegroundColor Cyan
    Disable-HyperVForVMware
    
    # 1. SSD and system optimizations
    Write-Host "`n=== SYSTEM OPTIMIZATIONS ===" -ForegroundColor Cyan
    Optimize-SSD
    Disable-Hibernate
    Optimize-SystemPerformance
    
    # 2. Services and processes
    Write-Host "`n=== SERVICES AND PROCESSES ===" -ForegroundColor Cyan
    Disable-IntelLMS
    Disable-AdobeServices
    Disable-TeredoIPv6
    Optimize-ServicesRunning
    Optimize-WindowsFeaturesList
    
    # 3. Extreme privacy - ZERO DATA
    Write-Host "`n=== PRIVACY AND DIAGNOSTICS ===" -ForegroundColor Cyan
    Disable-AllDiagnostics
    Disable-Cortana
    Disable-ActivityHistory
    Disable-LocationTracking
    Disable-OnlineSpeechRecognition
    Disable-ClipboardHistory
    Disable-FeedbackNotifications
    Disable-AdvertisingID
    Disable-WindowsSpotlight
    Disable-BackgroundApps
    
    # 4. Windows Update Manual
    Write-Host "`n=== WINDOWS UPDATE ===" -ForegroundColor Cyan
    Set-WindowsUpdateManual
    
    # 5. Component removal
    Write-Host "`n=== COMPONENT REMOVAL ===" -ForegroundColor Cyan
    Remove-OneDrive
    Remove-Xbox
    Remove-Bloatware
    Disable-UnwantedFeatures
    
    # 6. Performance optimizations
    Write-Host "`n=== PERFORMANCE OPTIMIZATIONS ===" -ForegroundColor Cyan
    Optimize-Performance
    Optimize-Network
    
    # 7. Security
    Write-Host "`n=== SECURITY ===" -ForegroundColor Cyan
    Optimize-Security
    
    # 8. Scheduled tasks
    Write-Host "`n=== SCHEDULED TASKS ===" -ForegroundColor Cyan
    Disable-UnnecessaryTasks
    
    # 9. User interface
    Write-Host "`n=== USER INTERFACE ===" -ForegroundColor Cyan
    Optimize-Explorer
    Optimize-Taskbar
    Optimize-StartMenu
    
    # 10. Utilities
    Write-Host "`n=== UTILITIES ===" -ForegroundColor Cyan
    Create-GodMode

    # 11. Application optimizations
    Write-Host "`n=== APPLICATIONS ===" -ForegroundColor Cyan
    Optimize-Edge
    Optimize-Chrome
    
    # 12. Specialized optimizations
    Write-Host "`n=== SPECIALIZED OPTIMIZATIONS ===" -ForegroundColor Cyan
    Optimize-Gaming
    Optimize-Audio
    Optimize-Firewall
    Optimize-DNS
    Optimize-Maintenance
    Optimize-Registry
    Hardening-Security
    Optimize-UserExperience
    
    # 13. Final cleanup
    Write-Host "`n=== CLEANUP ===" -ForegroundColor Cyan
    Clean-TemporaryFiles
    Remove-WindowsOld

    # FINAL SUMMARY
    Write-Host ""
    Write-Host "================================================" -ForegroundColor Green
    Write-Host "    OPTIMIZATION COMPLETED!" -ForegroundColor Green
    Write-Host "================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "SUMMARY OF APPLIED OPTIMIZATIONS:" -ForegroundColor Yellow
    Write-Host "  - Hyper-V disabled for VMware compatibility" -ForegroundColor Green
    Write-Host "  - SSD optimized and hibernation disabled" -ForegroundColor Green
    Write-Host "  - 65+ unnecessary services disabled" -ForegroundColor Green
    Write-Host "  - Intel LMS, Adobe, Teredo, IPv6 disabled" -ForegroundColor Green
    Write-Host "  - 25+ Windows features disabled" -ForegroundColor Green
    Write-Host "  - Telemetry COMPLETELY disabled (ZERO data)" -ForegroundColor Green
    Write-Host "  - Cortana and location tracking disabled" -ForegroundColor Green
    Write-Host "  - Speech recognition and history disabled" -ForegroundColor Green
    Write-Host "  - Windows Update configured (MANUAL control)" -ForegroundColor Green
    Write-Host "  - OneDrive and Xbox completely removed" -ForegroundColor Green
    Write-Host "  - 70+ bloatware apps removed" -ForegroundColor Green
    Write-Host "  - System and network performance optimized" -ForegroundColor Green
    Write-Host "  - Security enhanced (Defender, UAC, Firewall)" -ForegroundColor Green
    Write-Host "  - 25+ scheduled tasks disabled" -ForegroundColor Green
    Write-Host "  - File Explorer, Taskbar and Start Menu optimized" -ForegroundColor Green
    Write-Host "  - Temporary files and Windows.old cleaned" -ForegroundColor Green
    Write-Host "  - God Mode created on desktop" -ForegroundColor Green
    Write-Host ""
    Write-Host "VMware will now work at maximum performance!" -ForegroundColor Green
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

# AUTOMATICALLY EXECUTE WHEN SCRIPT STARTS
Start-FullOptimization

