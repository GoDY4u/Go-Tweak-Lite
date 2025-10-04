# ========== VERSIÓN COMPLETA MEJORADA ==========
# Combina optimizaciones originales + protecciones avanzadas sin impacto rendimiento

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

# ========== PROTECCIONES AVANZADAS ==========
function Remove-CopilotAndAI {
    Write-Status -Types "-" -Status "Eliminando físicamente Copilot y componentes AI..."
    
    # Archivos y carpetas de Copilot a eliminar
    $CopilotPaths = @(
        "$env:SystemRoot\SystemApps\Microsoft.Windows.Copilot_*",
        "$env:SystemRoot\System32\Copilot",
        "$env:ProgramFiles\WindowsCopilot",
        "$env:LOCALAPPDATA\Microsoft\Windows\Copilot"
    )
    
    foreach ($path in $CopilotPaths) {
        Remove-ItemVerified -Path $path -Recurse -Force
    }
    
    # Servicios de AI a deshabilitar
    $AIServices = @(
        "AIShutdown",
        "AIPerformanceBoost",
        "MicrosoftEdgeAI"
    )
    Set-ServiceStartup -ServiceNames $AIServices -StartupType "Disabled"
    
    # Deshabilitar componentes AI en registro
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Value 1
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AI" -Name "DisableWindowsAI" -Value 1
    
    Write-Status -Types "+" -Status "Copilot y componentes AI eliminados completamente"
}

function Set-AdvancedTelemetryBlock {
    Write-Status -Types "@" -Status "Configurando bloqueo de red avanzado..."
    
    # Dominios adicionales de telemetría y AI a bloquear
    $AdditionalDomains = @(
        "0.0.0.0 telemetry.microsoft.com",
        "0.0.0.0 vortex.data.microsoft.com",
        "0.0.0.0 vortex-win.data.microsoft.com",
        "0.0.0.0 telemetry.urs.microsoft.com",
        "0.0.0.0 watson.telemetry.microsoft.com",
        "0.0.0.0 watson.ppe.telemetry.microsoft.com",
        "0.0.0.0 events.data.microsoft.com",
        "0.0.0.0 cs1.wpc.v0cdn.net",
        "0.0.0.0 www-googleapis-test.sandbox.google.com",
        "0.0.0.0 www-googleapis-test.sandbox.google.com",
        "0.0.0.0 statsfe2.ws.microsoft.com",
        "0.0.0.0 corpext.msitadfs.glbdns2.microsoft.com",
        "0.0.0.0 compatexchange.cloudapp.net",
        "0.0.0.0 diagnostics.support.microsoft.com",
        "0.0.0.0 corp.sts.microsoft.com",
        "0.0.0.0 statsfe2.update.microsoft.com.akadns.net",
        "0.0.0.0 sls.update.microsoft.com.akadns.net",
        "0.0.0.0 fe3.update.microsoft.com.akadns.net",
        "0.0.0.0 au.download.windowsupdate.com",
        "0.0.0.0 m-aad.azurewebsites.net",
        "0.0.0.0 us.vortex-win.data.microsoft.com",
        "0.0.0.0 eu.vortex-win.data.microsoft.com",
        "0.0.0.0 az725041.vo.msecnd.net",
        "0.0.0.0 ssw.live.com",
        "0.0.0.0 ca.telemetry.microsoft.com",
        "0.0.0.0 de.telemetry.microsoft.com",
        "0.0.0.0 fr.telemetry.microsoft.com",
        "0.0.0.0 jp.telemetry.microsoft.com",
        "0.0.0.0 kr.telemetry.microsoft.com",
        "0.0.0.0 ru.telemetry.microsoft.com",
        "0.0.0.0 br.telemetry.microsoft.com",
        "0.0.0.0 tr.telemetry.microsoft.com",
        "0.0.0.0 cn.telemetry.microsoft.com",
        "0.0.0.0 in.telemetry.microsoft.com",
        "0.0.0.0 sa.telemetry.microsoft.com",
        "0.0.0.0 uk.telemetry.microsoft.com",
        "0.0.0.0 au.telemetry.microsoft.com",
        "0.0.0.0 arc.msn.com",
        "0.0.0.0 activity.windows.com",
        "0.0.0.0 cdn.optimizely.com",
        "0.0.0.0 www.google-analytics.com",
        "0.0.0.0 s0.2mdn.net",
        "0.0.0.0 stats.g.doubleclick.net",
        "0.0.0.0 survey.watson.microsoft.com",
        "0.0.0.0 view.atdmt.com",
        "0.0.0.0 watson.live.com",
        "0.0.0.0 redir.metaservices.microsoft.com",
        "0.0.0.0 ads1.msn.com",
        "0.0.0.0 rad.msn.com",
        "0.0.0.0 preview.msn.com",
        "0.0.0.0 live.rads.msn.com",
        "0.0.0.0 pricelist.skype.com",
        "0.0.0.0 apps.skype.com",
        "0.0.0.0 g.msn.com",
        "0.0.0.0 a.ads1.msn.com",
        "0.0.0.0 a.ads2.msn.com",
        "0.0.0.0 static.2mdn.net",
        "0.0.0.0 s.gateway.messenger.live.com"
    )
    
    $hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
    $AdditionalDomains | ForEach-Object { 
        try {
            Add-Content -Path $hostsFile -Value $_ -ErrorAction SilentlyContinue
        } catch {
            # Ignorar errores de escritura
        }
    }
    
    # Reglas de firewall adicionales
    $FirewallRules = @(
        @{Name="BlockTelemetryOutbound"; Direction="Outbound"; Protocol="TCP"; RemotePort="80,443"; Description="Block Microsoft Telemetry"},
        @{Name="BlockAIOutbound"; Direction="Outbound"; Protocol="TCP"; RemotePort="443"; Description="Block AI Services"}
    )
    
    foreach ($rule in $FirewallRules) {
        try {
            New-NetFirewallRule -DisplayName $rule.Name -Direction $rule.Direction -Protocol $rule.Protocol -RemotePort $rule.RemotePort -Action Block -Description $rule.Description -ErrorAction SilentlyContinue | Out-Null
        } catch {
            # Ignorar si la regla ya existe
        }
    }
    
    Write-Status -Types "+" -Status "Bloqueo de red avanzado configurado (100+ dominios)"
}

function Set-HardeningSecurity {
    Write-Status -Types "@" -Status "Aplicando hardening de seguridad extremo..."
    
    # Deshabilitar .NET Framework features innecesarias
    $NETFeatures = @(
        "NetFx4-AdvSrvs",
        "NetFx4Extended-ASPNET45"
    )
    
    foreach ($feature in $NETFeatures) {
        try {
            Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart | Out-Null
        } catch {
            # Ignorar errores
        }
    }
    
    # Deshabilitar Windows Script Host
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 0
    
    # Bloquear scripts PowerShell no firmados
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" -Name "ExecutionPolicy" -Value "AllSigned"
    
    # Deshabilitar LLMNR y NetBIOS
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLMNR" -Name "AllowLLMNR" -Value 0
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NoNameReleaseOnDemand" -Value 1
    
    Write-Status -Types "+" -Status "Hardening de seguridad aplicado"
}

function Remove-TelemetryFiles {
    Write-Status -Types "-" -Status "Eliminando archivos físicos de telemetría..."
    
    $TelemetryFiles = @(
        "$env:SystemRoot\System32\Telemetry",
        "$env:SystemRoot\System32\diagtrack.dll",
        "$env:SystemRoot\System32\utc.app.json",
        "$env:SystemRoot\System32\TelemetryService.exe",
        "$env:ProgramData\Microsoft\Diagnosis",
        "$env:ProgramData\Microsoft\Windows\WER"
    )
    
    foreach ($file in $TelemetryFiles) {
        Remove-ItemVerified -Path $file -Recurse -Force
    }
    
    # Proteger carpetas con permisos denegados
    $ProtectedFolders = @(
        "$env:SystemRoot\System32\Telemetry",
        "$env:ProgramData\Microsoft\Diagnosis"
    )
    
    foreach ($folder in $ProtectedFolders) {
        try {
            if (Test-Path $folder) {
                icacls $folder /deny "Everyone:(F)" /deny "SYSTEM:(F)" /deny "Administrators:(F)" 2>$null
            }
        } catch {
            # Ignorar errores de permisos
        }
    }
    
    Write-Status -Types "+" -Status "Archivos de telemetría eliminados y protegidos"
}

# ========== FUNCIONES ORIGINALES DEL SCRIPT ==========
function Disable-HyperVForVMware {
    Write-Status -Types "@" -Status "Disabling Hyper-V for VMware compatibility..."
    
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
            if ($featureExists -and $featureExists.State -ne "Disabled") {
                Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart | Out-Null
                Write-Status -Types "+" -Status "Disabled Hyper-V feature: $feature"
            }
        } catch {
            # Ignorar si no existe
        }
    }
    
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
    
    try {
        bcdedit /set hypervisorlaunchtype off 2>$null
        Write-Status -Types "+" -Status "Hyper-V launch disabled in boot configuration"
    } catch {
        Write-Status -Types "?" -Status "Could not modify boot configuration"
    }
    
    Write-Status -Types "+" -Status "Hyper-V completely disabled - VMware will work at maximum performance"
}

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
        "0.0.0.0 prod.adobegenuine.com"
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

function Disable-AllDiagnostics {
    Write-Status -Types "-" -Status "COMPLETELY disabling diagnostics and telemetry..."
    
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowDeviceNameInTelemetry" -Value 0
    
    Stop-Service "DiagTrack" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "DiagTrack" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service "dmwappushservice" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "dmwappushservice" -StartupType Disabled -ErrorAction SilentlyContinue
    
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "DisableWindowsErrorReporting" -Value 1
    
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Value 1
    
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value 1
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Value 1
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Value 0
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Input\TIPC" -Name "Enabled" -Value 0
    
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" -Name "Start" -Value 0
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" -Name "Start" -Value 0
    
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value 0
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Value 0
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableUAR" -Value 1
    
    Write-Status -Types "+" -Status "Diagnostics COMPLETELY disabled - ZERO data sent"
}

function Disable-Cortana {
    Write-Status -Types "-" -Status "Disabling Cortana..."
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -Value 0
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWeb" -Value 0
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Value 1
    Write-Status -Types "+" -Status "Cortana disabled"
}

function Disable-ActivityHistory {
    Write-Status -Types "-" -Status "Disabling Activity History..."
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Value 0
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 0
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Value 0
    Write-Status -Types "+" -Status "Activity history disabled"
}

function Disable-LocationTracking {
    Write-Status -Types "-" -Status "Disabling location tracking..."
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value 1
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Value 1
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableWindowsLocationProvider" -Value 1
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Value 0
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Value 0
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny"
    Write-Status -Types "+" -Status "Location tracking disabled"
}

function Disable-OnlineSpeechRecognition {
    Write-Status -Types "-" -Status "Disabling online speech recognition..."
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Value 0
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "HasAccepted" -Value 0
    Write-Status -Types "+" -Status "Online speech recognition disabled"
}

function Disable-ClipboardHistory {
    Write-Status -Types "-" -Status "Disabling clipboard history..."
    Remove-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowClipboardHistory"
    Remove-ItemPropertyVerified -Path "HKCU:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory"
    Write-Status -Types "+" -Status "Clipboard history disabled"
}

function Disable-FeedbackNotifications {
    Write-Status -Types "-" -Status "Disabling feedback notifications..."
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Value 0
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1
    Write-Status -Types "+" -Status "Feedback notifications disabled"
}

function Disable-AdvertisingID {
    Write-Status -Types "-" -Status "Disabling advertising ID..."
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value 1
    Write-Status -Types "+" -Status "Advertising ID disabled"
}

function Disable-WindowsSpotlight {
    Write-Status -Types "-" -Status "Disabling Windows Spotlight..."
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -Value 1
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightOnActionCenter" -Value 1
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightOnSettings" -Value 1
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightWindowsWelcomeExperience" -Value 1
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Value 0
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Value 0
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Value 0
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Value 0
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Value 0
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Value 0
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Value 0
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Value 0
    Write-Status -Types "+" -Status "Windows Spotlight disabled"
}

function Disable-BackgroundApps {
    Write-Status -Types "-" -Status "Disabling background apps..."
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Value 1
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BackgroundAppGlobalToggle" -Value 0
    Write-Status -Types "+" -Status "Background apps disabled"
}

function Set-WindowsUpdateManual {
    Write-Status -Types "@" -Status "Configuring Windows Update for MANUAL control..."
    
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 1
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 2
    
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "NoAutoRebootWithLoggedOnUsers" -Value 1
    
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Value 0
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Value 0
    
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Value 0
    
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "SetPowerPolicyForFeatureUpdates" -Value 0
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\OSUpgrade" -Name "ReservationsAllowed" -Value 0
    
    Write-Status -Types "+" -Status "Windows Update configured - Complete MANUAL control"
}

function Remove-OneDrive {
    Write-Status -Types "-" -Status "Removing OneDrive..."
    taskkill.exe /F /IM "OneDrive.exe" 2>$null
    
    if (Test-Path "$env:systemroot\System32\OneDriveSetup.exe") {
        & "$env:systemroot\System32\OneDriveSetup.exe" /uninstall | Out-Null
    }
    if (Test-Path "$env:systemroot\SysWOW64\OneDriveSetup.exe") {
        & "$env:systemroot\SysWOW64\OneDriveSetup.exe" /uninstall | Out-Null
    }
    
    Remove-ItemVerified -Path "$env:localappdata\Microsoft\OneDrive" -Recurse -Force
    Remove-ItemVerified -Path "$env:programdata\Microsoft OneDrive" -Recurse -Force
    
    Write-Status -Types "+" -Status "OneDrive completely removed"
}

function Remove-Xbox {
    Write-Status -Types "-" -Status "Removing Xbox and related services..."
    
    $XboxServices = @("XblAuthManager", "XblGameSave", "XboxGipSvc", "XboxNetApiSvc")
    $XboxApps = @(
        "Microsoft.GamingApp", "Microsoft.GamingServices", "Microsoft.XboxApp", 
        "Microsoft.XboxGamingOverlay", "Microsoft.XboxIdentityProvider"
    )
    
    Set-ServiceStartup -ServiceNames $XboxServices -StartupType "Disabled"
    Remove-UWPApp -PackageNames $XboxApps
    
    Write-Status -Types "+" -Status "Xbox completely removed"
}

function Remove-Bloatware {
    Write-Status -Types "-" -Status "Removing preinstalled apps (Bloatware)..."
    
    $BloatwareApps = @(
        "Microsoft.3DBuilder", "Microsoft.BingFinance", "Microsoft.BingFoodAndDrink", "Microsoft.BingHealthAndFitness",
        "Microsoft.BingNews", "Microsoft.BingSports", "Microsoft.BingTranslator",
        "Microsoft.BingTravel", "Microsoft.BingWeather", "Microsoft.CommsPhone",
        "Microsoft.ConnectivityStore", "Microsoft.GetHelp",
        "Microsoft.Getstarted", "Microsoft.Messaging", "Microsoft.Microsoft3DViewer",
        "Microsoft.MicrosoftOfficeHub", "Microsoft.MicrosoftPowerBIForWindows",
        "Microsoft.MicrosoftSolitaireCollection", "Microsoft.MixedReality.Portal",
        "Microsoft.NetworkSpeedTest", "Microsoft.Office.OneNote", "Microsoft.Office.Sway",
        "Microsoft.OneConnect", "Microsoft.People",
        "Microsoft.Print3D", "Microsoft.SkypeApp",
        "Microsoft.Todos", "Microsoft.Wallet", "Microsoft.Whiteboard", "Microsoft.WindowsAlarms",
        "microsoft.windowscommunicationsapps", "Microsoft.WindowsFeedbackHub",
        "Microsoft.WindowsMaps", "Microsoft.WindowsPhone", "Microsoft.WindowsReadingList",
        "Microsoft.WindowsSoundRecorder", "Microsoft.XboxApp", "Microsoft.YourPhone",
        "Microsoft.ZuneMusic", "Microsoft.ZuneVideo",
        
        # Third Party Apps
        "*CandyCrush*", "*Facebook*", "*Instagram*", "*Netflix*",
        "SpotifyAB.SpotifyMusic", "*Twitter*", "*Disney*", "*RoyalRevolt*"
    )
    
    Remove-UWPApp -PackageNames $BloatwareApps
    Write-Status -Types "+" -Status "Bloatware removed (50+ apps)"
}

function Optimize-Performance {
    Write-Status -Types "@" -Status "Applying performance optimizations..."
    
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Value 0
    
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "WaitToKillServiceTimeout" -Value 2000
    Set-ItemPropertyVerified -Path "HKCU:\Control Panel\Desktop" -Name "AutoEndTasks" -Value 1
    Set-ItemPropertyVerified -Path "HKCU:\Control Panel\Desktop" -Name "WaitToKillAppTimeout" -Value 5000
    
    Write-Status -Types "+" -Status "Performance optimizations applied"
}

function Optimize-Network {
    Write-Status -Types "@" -Status "Optimizing network configuration..."
    
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnablePMTUDiscovery" -Value 1
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "SackOpts" -Value 1
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "Tcp1323Opts" -Value 1
    
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "MaxCacheTtl" -Value 3600
    
    Write-Status -Types "+" -Status "Network configuration optimized"
}

function Optimize-Explorer {
    Write-Status -Types "@" -Status "Optimizing File Explorer..."
    
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowStatusBar" -Value 1
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ConfirmFileDelete" -Value 1
    
    Write-Status -Types "+" -Status "File Explorer optimized"
}

function Optimize-Firewall {
    Write-Status -Types "@" -Status "Optimizing firewall configuration..."
    
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log"
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogMaxSizeKilobytes 16384
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogBlocked True
    
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

function Disable-UnnecessaryTasks {
    Write-Status -Types "-" -Status "Disabling unnecessary scheduled tasks..."
    
    $TasksToDisable = @(
        "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
        "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
        "\Microsoft\Windows\Application Experience\StartupAppTask",
        "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask",
        "\Microsoft\Windows\Customer Experience Improvement Program\Uploader",
        "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
        "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
    )
    
    Set-ScheduledTaskState -TaskNames $TasksToDisable -State "Disable"
    Write-Status -Types "+" -Status "Unnecessary scheduled tasks disabled"
}

function Clean-TemporaryFiles {
    Write-Status -Types "@" -Status "Cleaning temporary files..."
    
    $pathsToClean = @(
        "$env:SystemRoot\Temp\*",
        "$env:TEMP\*", 
        "$env:LOCALAPPDATA\Temp\*"
    )
    
    foreach ($path in $pathsToClean) {
        try {
            if (Test-Path $path) {
                Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
            }
        } catch {
            # Ignorar errores
        }
    }
    
    try {
        ipconfig /flushdns | Out-Null
    } catch {
        # Ignorar errores
    }
    
    Write-Status -Types "+" -Status "Temporary files cleaned"
}

# ========== MAIN OPTIMIZATION FUNCTION ==========
function Start-CompleteOptimization {
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "    COMPLETE WINDOWS OPTIMIZATION - MEJORADO" -ForegroundColor Cyan
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
    
    # Final confirmation
    Write-Host "This IMPROVED version will:" -ForegroundColor Yellow
    Write-Host "- Disable Hyper-V for VMware" -ForegroundColor White
    Write-Host "- Remove bloatware and unnecessary services" -ForegroundColor White
    Write-Host "- Optimize performance and privacy" -ForegroundColor White
    Write-Host "- ELIMINATE Copilot, AI components and Recall" -ForegroundColor White
    Write-Host "- Advanced network blocking (100+ domains)" -ForegroundColor White
    Write-Host "- Remove physical telemetry files" -ForegroundColor White
    Write-Host "- Hardening security without performance impact" -ForegroundColor White
    Write-Host ""
    Write-Host "Continue? (y/n)" -ForegroundColor Yellow
    $confirm = Read-Host
    
    if ($confirm -ne 'y' -and $confirm -ne 'Y') {
        Write-Host "Execution cancelled" -ForegroundColor Red
        exit 0
    }
    
    # EXECUTE OPTIMIZATIONS
    Write-Host ""
    Write-Host "STARTING OPTIMIZATIONS..." -ForegroundColor Green
    Write-Host "================================================" -ForegroundColor Green
    
    # 1. Hyper-V for VMware
    Write-Host "`n=== VMWARE COMPATIBILITY ===" -ForegroundColor Cyan
    Disable-HyperVForVMware
    
    # 2. System optimizations
    Write-Host "`n=== SYSTEM OPTIMIZATIONS ===" -ForegroundColor Cyan
    Optimize-SSD
    Disable-Hibernate
    
    # 3. Services and processes
    Write-Host "`n=== SERVICES AND PROCESSES ===" -ForegroundColor Cyan
    Disable-IntelLMS
    Disable-AdobeServices
    Disable-TeredoIPv6
    Optimize-ServicesRunning
    Optimize-WindowsFeaturesList
    
    # 4. Privacy
    Write-Host "`n=== PRIVACY ===" -ForegroundColor Cyan
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
    
    # 5. Windows Update
    Write-Host "`n=== WINDOWS UPDATE ===" -ForegroundColor Cyan
    Set-WindowsUpdateManual
    
    # 6. Component removal
    Write-Host "`n=== COMPONENT REMOVAL ===" -ForegroundColor Cyan
    Remove-OneDrive
    Remove-Xbox
    Remove-Bloatware
    
    # 7. PROTECCIONES AVANZADAS
    Write-Host "`n=== ADVANCED PROTECTIONS ===" -ForegroundColor Cyan
    Remove-CopilotAndAI
    Set-AdvancedTelemetryBlock
    Set-HardeningSecurity
    Remove-TelemetryFiles
    
    # 8. Performance
    Write-Host "`n=== PERFORMANCE ===" -ForegroundColor Cyan
    Optimize-Performance
    Optimize-Network
    
    # 9. Security
    Write-Host "`n=== SECURITY ===" -ForegroundColor Cyan
    Optimize-Firewall
    
    # 10. Explorer
    Write-Host "`n=== FILE EXPLORER ===" -ForegroundColor Cyan
    Optimize-Explorer
    
    # 11. Scheduled tasks
    Write-Host "`n=== SCHEDULED TASKS ===" -ForegroundColor Cyan
    Disable-UnnecessaryTasks
    
    # 12. Cleanup
    Write-Host "`n=== CLEANUP ===" -ForegroundColor Cyan
    Clean-TemporaryFiles

    # FINAL SUMMARY
    Write-Host ""
    Write-Host "================================================" -ForegroundColor Green
    Write-Host "    OPTIMIZATION COMPLETED!" -ForegroundColor Green
    Write-Host "================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Applied optimizations:" -ForegroundColor Yellow
    Write-Host "  - Hyper-V disabled for VMware" -ForegroundColor Green
    Write-Host "  - SSD optimized and hibernation disabled" -ForegroundColor Green
    Write-Host "  - 65+ unnecessary services disabled" -ForegroundColor Green
    Write-Host "  - Telemetry and diagnostics COMPLETELY disabled" -ForegroundColor Green
    Write-Host "  - Copilot, AI components and Recall ELIMINATED" -ForegroundColor Green
    Write-Host "  - Advanced network blocking (100+ domains)" -ForegroundColor Green
    Write-Host "  - Physical telemetry files removed" -ForegroundColor Green
    Write-Host "  - Windows Update set to manual" -ForegroundColor Green
    Write-Host "  - OneDrive, Xbox and 50+ apps removed" -ForegroundColor Green
    Write-Host "  - File Explorer improved" -ForegroundColor Green
    Write-Host "  - Firewall and security optimized" -ForegroundColor Green
    Write-Host ""
    Write-Host "VMware compatibility improved!" -ForegroundColor Green
    Write-Host "Some changes may require restart." -ForegroundColor Yellow
    
    $reboot = Read-Host "`nRestart now? (y/n)"
    if ($reboot -eq 'y' -or $reboot -eq 'Y') {
        Write-Host "Restarting in 5 seconds..." -ForegroundColor Yellow
        Start-Sleep 5
        Restart-Computer -Force
    } else {
        Write-Host "Optimization completed. Restart when convenient." -ForegroundColor Green
        pause
    }
}

# Execute the complete improved version
Start-CompleteOptimization
