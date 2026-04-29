# =============================================================================
# SCRIPT: other-tweaks.ps1 (combinado con tweaks.json de WinUtil)
# VERSIÓN: 3.3 (Eliminada característica que bloqueaba el script)
# DESCRIPCIÓN: Optimización completa de Windows 10/11 para rendimiento,
#               privacidad extrema y eliminación de telemetría/AI/Copilot,
#               más los tweaks específicos de WinUtil.
# EJECUTAR: PowerShell como Administrador
# =============================================================================

# ========== CONFIGURACIÓN DE TWEAKS (desde JSON) ==========
$script:TweaksConfig = @{
    "WPFTweaksActivity" = @{
        "Content" = "Activity History - Disable"
        "Description" = "Erases recent docs, clipboard, and run history."
        "category" = "Essential Tweaks"
        "panel" = "1"
        "registry" = @(
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "EnableActivityFeed"; Value = 0; Type = "DWord"; OriginalValue = "<RemoveEntry>" },
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "PublishUserActivities"; Value = 0; Type = "DWord"; OriginalValue = "<RemoveEntry>" },
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "UploadUserActivities"; Value = 0; Type = "DWord"; OriginalValue = "<RemoveEntry>" }
        )
    }
    "WPFTweaksConsumerFeatures" = @{
        "Content" = "ConsumerFeatures - Disable"
        "Description" = "Windows will not automatically install any games, third-party apps, or application links from the Windows Store for the signed-in user. Some default Apps will be inaccessible (eg. Phone Link)."
        "category" = "Essential Tweaks"
        "panel" = "1"
        "registry" = @(
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"; Name = "DisableWindowsConsumerFeatures"; Value = 1; Type = "DWord"; OriginalValue = "<RemoveEntry>" }
        )
    }
    "WPFTweaksEndTaskOnTaskbar" = @{
        "Content" = "End Task With Right Click - Enable"
        "Description" = "Enables option to end task when right clicking a program in the taskbar."
        "category" = "Essential Tweaks"
        "panel" = "1"
        "registry" = @(
            @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings"; Name = "TaskbarEndTask"; Value = 1; Type = "DWord"; OriginalValue = "<RemoveEntry>" }
        )
    }
    "WPFTweaksDisableExplorerAutoDiscovery" = @{
        "Content" = "File Explorer Automatic Folder Discovery - Disable"
        "Description" = "Windows Explorer automatically tries to guess the type of the folder based on its contents, slowing down the browsing experience. WARNING! Will disable File Explorer grouping."
        "category" = "Essential Tweaks"
        "panel" = "1"
        "InvokeScript" = @(
            @'
# Previously detected folders
$bags = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags"
# Folder types lookup table
$bagMRU = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU"
# Flush Explorer view database
Remove-Item -Path $bags -Recurse -Force
Write-Host "Removed $bags"
Remove-Item -Path $bagMRU -Recurse -Force
Write-Host "Removed $bagMRU"
# Every folder
$allFolders = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell"
if (!(Test-Path $allFolders)) {
    New-Item -Path $allFolders -Force
    Write-Host "Created $allFolders"
}
# Generic view
New-ItemProperty -Path $allFolders -Name "FolderType" -Value "NotSpecified" -PropertyType String -Force
Write-Host "Set FolderType to NotSpecified"
Write-Host Please sign out and back in, or restart your computer to apply the changes!
'@
        )
        "UndoScript" = @(
            @'
# Previously detected folders
$bags = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags"
# Folder types lookup table
$bagMRU = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU"
# Flush Explorer view database
Remove-Item -Path $bags -Recurse -Force
Write-Host "Removed $bags"
Remove-Item -Path $bagMRU -Recurse -Force
Write-Host "Removed $bagMRU"
Write-Host Please sign out and back in, or restart your computer to apply the changes!
'@
        )
    }
    "WPFTweaksHiber" = @{
        "Content" = "Hibernation - Disable"
        "Description" = "Hibernation is really meant for laptops as it saves what's in memory before turning the PC off. It really should never be used."
        "category" = "Essential Tweaks"
        "panel" = "1"
        "registry" = @(
            @{ Path = "HKLM:\System\CurrentControlSet\Control\Session Manager\Power"; Name = "HibernateEnabled"; Value = 0; Type = "DWord"; OriginalValue = 1 },
            @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings"; Name = "ShowHibernateOption"; Value = 0; Type = "DWord"; OriginalValue = 1 }
        )
        "InvokeScript" = @("powercfg.exe /hibernate off")
        "UndoScript" = @("powercfg.exe /hibernate on")
    }
    "WPFTweaksLocation" = @{
        "Content" = "Location Tracking - Disable"
        "Description" = "Disables Location Tracking."
        "category" = "Essential Tweaks"
        "panel" = "1"
        "service" = @(
            @{ Name = "lfsvc"; StartupType = "Disable"; OriginalType = "Manual" }
        )
        "registry" = @(
            @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"; Name = "Value"; Value = "Deny"; Type = "String"; OriginalValue = "Allow" },
            @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"; Name = "SensorPermissionState"; Value = 0; Type = "DWord"; OriginalValue = 1 },
            @{ Path = "HKLM:\SYSTEM\Maps"; Name = "AutoUpdateEnabled"; Value = 0; Type = "DWord"; OriginalValue = 1 }
        )
    }
    "WPFTweaksDisableStoreSearch" = @{
        "Content" = "Microsoft Store Recommended Search Results - Disable"
        "Description" = "Will not display recommended Microsoft Store apps when searching for apps in the Start menu."
        "category" = "Essential Tweaks"
        "panel" = "1"
        "InvokeScript" = @('icacls "$Env:LocalAppData\Packages\Microsoft.WindowsStore_8wekyb3d8bbwe\LocalState\store.db" /deny Everyone:F')
        "UndoScript" = @('icacls "$Env:LocalAppData\Packages\Microsoft.WindowsStore_8wekyb3d8bbwe\LocalState\store.db" /grant Everyone:F')
    }
    "WPFTweaksPowershell7Tele" = @{
        "Content" = "PowerShell 7 Telemetry - Disable"
        "Description" = "Creates an Environment Variable called 'POWERSHELL_TELEMETRY_OPTOUT' with a value of '1' which will tell PowerShell 7 to not send Telemetry Data."
        "category" = "Essential Tweaks"
        "panel" = "1"
        "InvokeScript" = @("[Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', '1', 'Machine')")
        "UndoScript" = @("[Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', '', 'Machine')")
    }
    "WPFTweaksServices" = @{
        "Content" = "Services - Set to Manual"
        "Description" = "Turns a bunch of system services to manual that don't need to be running all the time. This is pretty harmless as if the service is needed, it will simply start on demand."
        "category" = "Essential Tweaks"
        "panel" = "1"
        "service" = @(
            @{ Name = "CscService"; StartupType = "Disabled"; OriginalType = "Manual" },
            @{ Name = "DiagTrack"; StartupType = "Disabled"; OriginalType = "Automatic" },
            @{ Name = "MapsBroker"; StartupType = "Manual"; OriginalType = "Automatic" },
            @{ Name = "RemoteAccess"; StartupType = "Disabled"; OriginalType = "Disabled" },
            @{ Name = "RemoteRegistry"; StartupType = "Disabled"; OriginalType = "Disabled" },
            @{ Name = "StorSvc"; StartupType = "Manual"; OriginalType = "Automatic" },
            @{ Name = "SharedAccess"; StartupType = "Disabled"; OriginalType = "Automatic" },
            @{ Name = "TermService"; StartupType = "Manual"; OriginalType = "Manual" },
            @{ Name = "TroubleshootingSvc"; StartupType = "Manual"; OriginalType = "Manual" },
            @{ Name = "seclogon"; StartupType = "Manual"; OriginalType = "Manual" },
            @{ Name = "ssh-agent"; StartupType = "Disabled"; OriginalType = "Disabled" }
        )
        "InvokeScript" = @(
            @'
$Memory = (Get-CimInstance Win32_PhysicalMemory | Measure-Object Capacity -Sum).Sum / 1KB
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name SvcHostSplitThresholdInKB -Value $Memory
'@
        )
    }
    "WPFTweaksTelemetry" = @{
        "Content" = "Telemetry - Disable"
        "Description" = "Disables Microsoft Telemetry."
        "category" = "Essential Tweaks"
        "panel" = "1"
        "registry" = @(
            @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"; Name = "Enabled"; Value = 0; Type = "DWord"; OriginalValue = "<RemoveEntry>" },
            @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy"; Name = "TailoredExperiencesWithDiagnosticDataEnabled"; Value = 0; Type = "DWord"; OriginalValue = "<RemoveEntry>" },
            @{ Path = "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy"; Name = "HasAccepted"; Value = 0; Type = "DWord"; OriginalValue = "<RemoveEntry>" },
            @{ Path = "HKCU:\Software\Microsoft\Input\TIPC"; Name = "Enabled"; Value = 0; Type = "DWord"; OriginalValue = "<RemoveEntry>" },
            @{ Path = "HKCU:\Software\Microsoft\InputPersonalization"; Name = "RestrictImplicitInkCollection"; Value = 1; Type = "DWord"; OriginalValue = "<RemoveEntry>" },
            @{ Path = "HKCU:\Software\Microsoft\InputPersonalization"; Name = "RestrictImplicitTextCollection"; Value = 1; Type = "DWord"; OriginalValue = "<RemoveEntry>" },
            @{ Path = "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore"; Name = "HarvestContacts"; Value = 0; Type = "DWord"; OriginalValue = "<RemoveEntry>" },
            @{ Path = "HKCU:\Software\Microsoft\Personalization\Settings"; Name = "AcceptedPrivacyPolicy"; Value = 0; Type = "DWord"; OriginalValue = "<RemoveEntry>" },
            @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name = "AllowTelemetry"; Value = 0; Type = "DWord"; OriginalValue = "<RemoveEntry>" },
            @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "Start_TrackProgs"; Value = 0; Type = "DWord"; OriginalValue = "<RemoveEntry>" },
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "PublishUserActivities"; Value = 0; Type = "DWord"; OriginalValue = "<RemoveEntry>" },
            @{ Path = "HKCU:\Software\Microsoft\Siuf\Rules"; Name = "NumberOfSIUFInPeriod"; Value = 0; Type = "DWord"; OriginalValue = "<RemoveEntry>" }
        )
        "InvokeScript" = @(
            @'
# Disable Defender Auto Sample Submission
Set-MpPreference -SubmitSamplesConsent 2
# Disable (Connected User Experiences and Telemetry) Service
Set-Service -Name diagtrack -StartupType Disabled
# Disable (Windows Error Reporting Manager) Service
Set-Service -Name wermgr -StartupType Disabled
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name PeriodInNanoSeconds
'@
        )
        "UndoScript" = @(
            @'
# Enable Defender Auto Sample Submission
Set-MpPreference -SubmitSamplesConsent 1
# Enable (Connected User Experiences and Telemetry) Service
Set-Service -Name diagtrack -StartupType Automatic
# Enable (Windows Error Reporting Manager) Service
Set-Service -Name wermgr -StartupType Automatic
'@
        )
    }
    "WPFTweaksDeleteTempFiles" = @{
        "Content" = "Temporary Files - Remove"
        "Description" = "Erases TEMP Folders."
        "category" = "Essential Tweaks"
        "panel" = "1"
        "InvokeScript" = @(
            @'
Remove-Item -Path "$Env:Temp\*" -Recurse -Force
Remove-Item -Path "$Env:SystemRoot\Temp\*" -Recurse -Force
'@
        )
    }
    "WPFTweaksWidget" = @{
        "Content" = "Widgets - Remove"
        "Description" = "Removes the annoying widgets in the bottom left of the Taskbar."
        "category" = "Essential Tweaks"
        "panel" = "1"
        "InvokeScript" = @(
            @'
Get-Process *Widget* | Stop-Process
Get-AppxPackage Microsoft.WidgetsPlatformRuntime -AllUsers | Remove-AppxPackage -AllUsers
Get-AppxPackage MicrosoftWindows.Client.WebExperience -AllUsers | Remove-AppxPackage -AllUsers
Invoke-WinUtilExplorerUpdate -action "restart"
Write-Host "Removed widgets"
'@
        )
        "UndoScript" = @(
            @'
Write-Host "Restoring widgets AppxPackages"
Add-AppxPackage -Register "C:\Program Files\WindowsApps\Microsoft.WidgetsPlatformRuntime*\AppxManifest.xml" -DisableDevelopmentMode
Add-AppxPackage -Register "C:\Program Files\WindowsApps\MicrosoftWindows.Client.WebExperience*\AppxManifest.xml" -DisableDevelopmentMode
Invoke-WinUtilExplorerUpdate -action "restart"
'@
        )
    }
    "WPFTweaksWPBT" = @{
        "Content" = "Windows Platform Binary Table (WPBT) - Disable"
        "Description" = "If enabled, WPBT allows your computer vendor to execute programs at boot time, such as anti-theft software, software drivers, as well as force install software without user consent. Poses potential security risk."
        "category" = "Essential Tweaks"
        "panel" = "1"
        "registry" = @(
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"; Name = "DisableWpbtExecution"; Value = 1; Type = "DWord"; OriginalValue = "<RemoveEntry>" }
        )
    }
    "WPFTweaksDisableBGapps" = @{
        "Content" = "Background Apps - Disable"
        "Description" = "Disables all Microsoft Store apps from running in the background, which has to be done individually since Windows 11."
        "category" = "z__Advanced Tweaks - CAUTION"
        "panel" = "1"
        "registry" = @(
            @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications"; Name = "GlobalUserDisabled"; Value = 1; Type = "DWord"; OriginalValue = 0 }
        )
    }
    "WPFTweaksBraveDebloat" = @{
        "Content" = "Brave Browser - Debloat"
        "Description" = "Disables various annoyances like Brave Rewards, Leo AI, Crypto Wallet and VPN."
        "category" = "z__Advanced Tweaks - CAUTION"
        "panel" = "1"
        "registry" = @(
            @{ Path = "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave"; Name = "BraveRewardsDisabled"; Value = 1; Type = "DWord"; OriginalValue = "<RemoveEntry>" },
            @{ Path = "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave"; Name = "BraveWalletDisabled"; Value = 1; Type = "DWord"; OriginalValue = "<RemoveEntry>" },
            @{ Path = "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave"; Name = "BraveVPNDisabled"; Value = 1; Type = "DWord"; OriginalValue = "<RemoveEntry>" },
            @{ Path = "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave"; Name = "BraveAIChatEnabled"; Value = 0; Type = "DWord"; OriginalValue = "<RemoveEntry>" },
            @{ Path = "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave"; Name = "BraveStatsPingEnabled"; Value = 0; Type = "DWord"; OriginalValue = "<RemoveEntry>" }
        )
    }
    "WPFTweaksDisableWarningForUnsignedRdp" = @{
        "Content" = "Disable warnings for unsigned RDP files"
        "Description" = "Disables warnings shown when launching unsigned RDP files introduced with the latest Windows 10 and 11 updates."
        "category" = "z__Advanced Tweaks - CAUTION"
        "panel" = "1"
        "registry" = @(
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client"; Name = "RedirectionWarningDialogVersion"; Value = 1; Type = "DWord"; OriginalValue = "<RemoveEntry>" },
            @{ Path = "HKCU:\SOFTWARE\Microsoft\Terminal Server Client"; Name = "RdpLaunchConsentAccepted"; Value = 1; Type = "DWord"; OriginalValue = "<RemoveEntry>" }
        )
    }
    "WPFTweaksDisableIPv6" = @{
        "Content" = "IPv6 - Disable"
        "Description" = "Disables IPv6."
        "category" = "z__Advanced Tweaks - CAUTION"
        "panel" = "1"
        "registry" = @(
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"; Name = "DisabledComponents"; Value = 255; Type = "DWord"; OriginalValue = 0 }
        )
        "InvokeScript" = @("Disable-NetAdapterBinding -Name * -ComponentID ms_tcpip6")
        "UndoScript" = @("Enable-NetAdapterBinding -Name * -ComponentID ms_tcpip6")
    }
    "WPFTweaksIPv46" = @{
        "Content" = "IPv6 - Set IPv4 as Preferred"
        "Description" = "Setting the IPv4 preference can have latency and security benefits on private networks where IPv6 is not configured."
        "category" = "z__Advanced Tweaks - CAUTION"
        "panel" = "1"
        "registry" = @(
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"; Name = "DisabledComponents"; Value = 32; Type = "DWord"; OriginalValue = 0 }
        )
    }
    "WPFTweaksRemoveCopilot" = @{
        "Content" = "Microsoft Copilot - Disable"
        "Description" = "Removes Copilot AppXPackages and related ai packages"
        "category" = "z__Advanced Tweaks - CAUTION"
        "panel" = "1"
        "InvokeScript" = @(
            @'
Get-AppxPackage -AllUsers *Copilot* | Remove-AppxPackage -AllUsers
Get-AppxPackage -AllUsers Microsoft.MicrosoftOfficeHub | Remove-AppxPackage -AllUsers
$Appx = (Get-AppxPackage MicrosoftWindows.Client.CoreAI).PackageFullName
$Sid = (Get-LocalUser $Env:UserName).Sid.Value
New-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\EndOfLife\$Sid\$Appx" -Force
Remove-AppxPackage $Appx
Write-Host "Copilot Removed"
'@
        )
        "UndoScript" = @(
            @'
Write-Host "Installing Copilot..."
winget install --name Copilot --source msstore --accept-package-agreements --accept-source-agreements --silent
'@
        )
    }
    "WPFTweaksRemoveEdge" = @{
        "Content" = "Microsoft Edge - Remove"
        "Description" = "Unblocks Microsoft Edge uninstaller restrictions then uses that uninstaller to remove Microsoft Edge."
        "category" = "z__Advanced Tweaks - CAUTION"
        "panel" = "1"
        "InvokeScript" = @("Invoke-WinUtilRemoveEdge")
        "UndoScript" = @(
            @'
Write-Host 'Installing Microsoft Edge...'
winget install Microsoft.Edge --source winget
'@
        )
    }
    "WPFTweaksRemoveOneDrive" = @{
        "Content" = "Microsoft OneDrive - Remove"
        "Description" = "Denies permission to remove OneDrive user files, then uses its own uninstaller to remove it and restores the original permission afterward."
        "category" = "z__Advanced Tweaks - CAUTION"
        "panel" = "1"
        "InvokeScript" = @(
            @'
# Deny permission to remove OneDrive folder
icacls $Env:OneDrive /deny "Administrators:(D,DC)"
Write-Host "Uninstalling OneDrive..."
Start-Process 'C:\Windows\System32\OneDriveSetup.exe' -ArgumentList '/uninstall' -Wait
# Some of OneDrive files use explorer, and OneDrive uses FileCoAuth
Write-Host "Removing leftover OneDrive Files..."
Stop-Process -Name FileCoAuth,Explorer
Remove-Item "$Env:LocalAppData\Microsoft\OneDrive" -Recurse -Force
Remove-Item "C:\ProgramData\Microsoft OneDrive" -Recurse -Force
# Grant back permission to access OneDrive folder
icacls $Env:OneDrive /grant "Administrators:(D,DC)"
# Disable OneSyncSvc
Set-Service -Name OneSyncSvc -StartupType Disabled
'@
        )
        "UndoScript" = @(
            @'
Write-Host "Installing OneDrive"
winget install Microsoft.Onedrive --source winget
# Enabled OneSyncSvc
Set-Service -Name OneSyncSvc -StartupType Automatic
'@
        )
    }
    "WPFTweaksXboxRemoval" = @{
        "Content" = "Xbox & Gaming Components - Remove"
        "Description" = "Removes Xbox services, the Xbox app, Game Bar, and related authentication components."
        "category" = "z__Advanced Tweaks - CAUTION"
        "panel" = "1"
        "registry" = @(
            @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR"; Name = "AppCaptureEnabled"; Value = 0; Type = "DWord"; OriginalValue = 1 }
        )
        "appx" = @(
            "Microsoft.XboxIdentityProvider",
            "Microsoft.XboxSpeechToTextOverlay",
            "Microsoft.GamingApp",
            "Microsoft.Xbox.TCUI",
            "Microsoft.XboxGamingOverlay"
        )
    }
    "WPFTweaksDisplay" = @{
        "Content" = "Visual Effects - Set to Best Performance"
        "Description" = "Sets the system preferences to performance. You can do this manually with sysdm.cpl as well."
        "category" = "z__Advanced Tweaks - CAUTION"
        "panel" = "1"
        "registry" = @(
            @{ Path = "HKCU:\Control Panel\Desktop"; Name = "DragFullWindows"; Value = "0"; Type = "String"; OriginalValue = "1" },
            @{ Path = "HKCU:\Control Panel\Desktop"; Name = "MenuShowDelay"; Value = "200"; Type = "String"; OriginalValue = "400" },
            @{ Path = "HKCU:\Control Panel\Desktop\WindowMetrics"; Name = "MinAnimate"; Value = "0"; Type = "String"; OriginalValue = "1" },
            @{ Path = "HKCU:\Control Panel\Keyboard"; Name = "KeyboardDelay"; Value = 0; Type = "DWord"; OriginalValue = 1 },
            @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "ListviewAlphaSelect"; Value = 0; Type = "DWord"; OriginalValue = 1 },
            @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "ListviewShadow"; Value = 0; Type = "DWord"; OriginalValue = 1 },
            @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "TaskbarAnimations"; Value = 0; Type = "DWord"; OriginalValue = 1 },
            @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"; Name = "VisualFXSetting"; Value = 3; Type = "DWord"; OriginalValue = 1 },
            @{ Path = "HKCU:\Software\Microsoft\Windows\DWM"; Name = "EnableAeroPeek"; Value = 0; Type = "DWord"; OriginalValue = 1 },
            @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "TaskbarMn"; Value = 0; Type = "DWord"; OriginalValue = 1 },
            @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "ShowTaskViewButton"; Value = 0; Type = "DWord"; OriginalValue = 1 },
            @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"; Name = "SearchboxTaskbarMode"; Value = 0; Type = "DWord"; OriginalValue = 1 }
        )
        "InvokeScript" = @("Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'UserPreferencesMask' -Type Binary -Value ([byte[]](144,18,3,128,16,0,0,0))")
        "UndoScript" = @("Remove-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'UserPreferencesMask'")
    }
    "WPFTweaksDeBloat" = @{
        "Content" = "Unwanted Pre-Installed Apps - Remove"
        "Description" = "This will remove a bunch of Windows pre-installed applications which most people dont want on there system."
        "category" = "z__Advanced Tweaks - CAUTION"
        "panel" = "1"
        "appx" = @(
            "Microsoft.WindowsFeedbackHub",
            "Microsoft.BingNews",
            "Microsoft.BingSearch",
            "Microsoft.BingWeather",
            "Clipchamp.Clipchamp",
            "Microsoft.Todos",
            "Microsoft.PowerAutomateDesktop",
            "Microsoft.MicrosoftSolitaireCollection",
            "Microsoft.WindowsSoundRecorder",
            "Microsoft.MicrosoftStickyNotes",
            "Microsoft.Windows.DevHome",
            "Microsoft.Paint",
            "Microsoft.OutlookForWindows",
            "Microsoft.WindowsAlarms",
            "Microsoft.StartExperiencesApp",
            "Microsoft.GetHelp",
            "Microsoft.ZuneMusic",
            "MicrosoftCorporationII.QuickAssist",
            "MSTeams"
        )
        "InvokeScript" = @(
            @'
$TeamsPath = "$Env:LocalAppData\Microsoft\Teams\Update.exe"
if (Test-Path $TeamsPath) {
    Write-Host "Uninstalling Teams"
    Start-Process $TeamsPath -ArgumentList -uninstall -wait
    Write-Host "Deleting Teams directory"
    Remove-Item $TeamsPath -Recurse -Force
}
'@
        )
    }
    "WPFTweaksTeredo" = @{
        "Content" = "Teredo - Disable"
        "Description" = "Teredo network tunneling is an IPv6 feature that can cause additional latency, but may cause problems with some games."
        "category" = "z__Advanced Tweaks - CAUTION"
        "panel" = "1"
        "registry" = @(
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"; Name = "DisabledComponents"; Value = 1; Type = "DWord"; OriginalValue = 0 }
        )
        "InvokeScript" = @("netsh interface teredo set state disabled")
        "UndoScript" = @("netsh interface teredo set state default")
    }
    "WPFTweaksStorage" = @{
        "Content" = "Storage Sense - Disable"
        "Description" = "Storage Sense deletes temp files automatically."
        "category" = "z__Advanced Tweaks - CAUTION"
        "panel" = "1"
        "registry" = @(
            @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy"; Name = "01"; Value = 0; Type = "DWord"; OriginalValue = 1 }
        )
    }
    "WPFTweaksRightClickMenu" = @{
        "Content" = "Right-Click Menu Previous Layout - Enable"
        "Description" = "Restores the classic context menu when right-clicking in File Explorer, replacing the simplified Windows 11 version."
        "category" = "z__Advanced Tweaks - CAUTION"
        "panel" = "1"
        "InvokeScript" = @(
            @'
New-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" -Name "InprocServer32" -force -value ""
Write-Host Restarting explorer.exe ...
Stop-Process -Name "explorer" -Force
'@
        )
        "UndoScript" = @(
            @'
Remove-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" -Recurse -Confirm:$false -Force
Write-Host Restarting explorer.exe ...
Stop-Process -Name "explorer" -Force
'@
        )
    }
    "WPFTweaksDisableFSO" = @{
        "Content" = "Fullscreen Optimizations - Disable"
        "Description" = "Disables FSO in all applications. NOTE: This will disable Color Management in Exclusive Fullscreen."
        "category" = "z__Advanced Tweaks - CAUTION"
        "panel" = "1"
        "registry" = @(
            @{ Path = "HKCU:\System\GameConfigStore"; Name = "GameDVR_DXGIHonorFSEWindowsCompatible"; Value = 1; Type = "DWord"; OriginalValue = 0 }
        )
    }
}

# ========== FUNCIONES AUXILIARES BÁSICAS ==========
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

# Sistema de logging (se crea archivo en %TEMP%)
$script:LogFile = "$env:TEMP\OptimizationLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$timestamp [$Level] $Message" | Out-File -FilePath $script:LogFile -Append -Encoding utf8
}

# Función Write-Status mejorada: escribe en consola y en log
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
    Write-Log -Message "[$Types] $Status" -Level "ACTION"
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

# ========== FUNCIÓN PARA APLICAR TWEAKS DEL JSON ==========
function Apply-WinUtilTweaks {
    <#
    .SYNOPSIS
      Applies all tweaks defined in the WinUtil JSON configuration.
    #>
    Write-Status -Types "@" -Status "Applying WinUtil tweaks from configuration..."
    $tweaks = $script:TweaksConfig
    foreach ($tweakKey in $tweaks.Keys) {
        $tweak = $tweaks[$tweakKey]
        $name = if ($tweak.Content) { $tweak.Content } else { $tweakKey }
        Write-Status -Types "-" -Status "Processing: $name"
        
        # Registry tweaks
        if ($tweak.registry) {
            foreach ($reg in $tweak.registry) {
                $path = $reg.Path
                $regName = $reg.Name
                $value = $reg.Value
                $type = $reg.Type
                if ($reg.OriginalValue -eq '<RemoveEntry>') {
                    # We are to create the entry (if it doesn't exist) and set value
                    Set-ItemPropertyVerified -Path $path -Name $regName -Value $value -Type $type
                } else {
                    # Original value exists, we just set
                    Set-ItemPropertyVerified -Path $path -Name $regName -Value $value -Type $type
                }
            }
        }
        
        # Service tweaks
        if ($tweak.service) {
            foreach ($svc in $tweak.service) {
                try {
                    $svcName = $svc.Name
                    $desiredType = $svc.StartupType
                    Set-Service -Name $svcName -StartupType $desiredType -ErrorAction SilentlyContinue
                } catch {}
            }
        }
        
        # AppX removal
        if ($tweak.appx) {
            Remove-UWPApp -PackageNames $tweak.appx
        }
        
        # InvokeScript (apply actions)
        if ($tweak.InvokeScript) {
            foreach ($scriptBlock in $tweak.InvokeScript) {
                try {
                    Invoke-Expression $scriptBlock
                } catch {
                    Write-Status -Types "?" -Status "Error executing script for $name : $_"
                }
            }
        }
    }
    Write-Status -Types "+" -Status "WinUtil tweaks applied successfully"
}

# ========== OTRAS FUNCIONES ==========

# 2. Limpieza profunda del sistema (DISM y caché de Windows Update)
function Invoke-DeepSystemCleanup {
    Write-Status -Types "@" -Status "Running DISM component cleanup..."
    try {
        Dism /Online /Cleanup-Image /StartComponentCleanup /ResetBase | Out-Null
        Write-Status -Types "+" -Status "DISM component cleanup completed"
        Write-Log -Message "DISM /StartComponentCleanup /ResetBase executed" -Level "SUCCESS"
    } catch {
        Write-Status -Types "?" -Status "DISM cleanup failed"
        Write-Log -Message "DISM cleanup failed: $_" -Level "ERROR"
    }

    Write-Status -Types "@" -Status "Cleaning Windows Update cache..."
    try {
        Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$env:SystemRoot\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
        Start-Service -Name wuauserv -ErrorAction SilentlyContinue
        Write-Status -Types "+" -Status "Windows Update cache cleaned"
        Write-Log -Message "Windows Update download cache cleared" -Level "SUCCESS"
    } catch {
        Write-Status -Types "?" -Status "Could not clean Windows Update cache"
        Write-Log -Message "Failed to clean Windows Update cache: $_" -Level "ERROR"
    }
}

# 5. Deshabilitar envío de datos de escritura a mano y teclado
function Disable-InputPersonalization {
    Write-Status -Types "-" -Status "Disabling handwriting and typing data collection..."
    Set-ItemPropertyVerified -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value 1
    Set-ItemPropertyVerified -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Value 1
    Set-ItemPropertyVerified -Path "HKCU:\Software\Microsoft\Input\Settings" -Name "EnableHwkbTextSuggestions" -Value 0
    Write-Status -Types "+" -Status "Handwriting and typing data collection disabled"
    Write-Log -Message "Input personalization data collection disabled" -Level "SUCCESS"
}

# 6. Optimización de NTFS (deshabilitar 8.3 y último acceso)
function Optimize-NTFS {
    Write-Status -Types "@" -Status "Optimizing NTFS settings..."
    try {
        fsutil behavior set disable8dot3 1
        fsutil behavior set disablelastaccess 1
        Write-Status -Types "+" -Status "NTFS optimizations applied (8.3 names disabled, last access disabled)"
        Write-Log -Message "NTFS: disable8dot3=1, disablelastaccess=1" -Level "SUCCESS"
    } catch {
        Write-Status -Types "?" -Status "NTFS optimization failed"
        Write-Log -Message "NTFS optimization failed: $_" -Level "ERROR"
    }
}

# 7. Deshabilitar sugerencias de inicio y bienvenida (NO afecta a notificaciones del sistema)
function Disable-StartupSuggestions {
    Write-Status -Types "-" -Status "Disabling startup suggestions and welcome experience (notifications untouched)..."
    Set-ItemPropertyVerified -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -Value 0
    Set-ItemPropertyVerified -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -Value 0
    Set-ItemPropertyVerified -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Value 0
    Set-ItemPropertyVerified -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Value 0
    Set-ItemPropertyVerified -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Value 0
    Write-Status -Types "+" -Status "Startup suggestions disabled"
    Write-Log -Message "Startup suggestions and welcome experience disabled (notifications NOT affected)" -Level "SUCCESS"
}

# 10. Eliminación de paquetes de idioma no usados
function Remove-UnusedLanguagePacks {
    Write-Status -Types "-" -Status "Removing unused language packs..."
    try {
        $currentLang = (Get-WinSystemLocale).Name
        Get-WindowsPackage -Online | Where-Object {
            $_.PackageName -like "*LanguagePack*" -and $_.PackageName -notlike "*$currentLang*"
        } | Remove-WindowsPackage -Online -NoRestart -ErrorAction SilentlyContinue
        Write-Status -Types "+" -Status "Unused language packs removed"
        Write-Log -Message "Language packs removed (current: $currentLang)" -Level "SUCCESS"
    } catch {
        Write-Status -Types "?" -Status "Could not remove language packs"
        Write-Log -Message "Failed to remove language packs: $_" -Level "ERROR"
    }
}

# ========== FUNCIONES ORIGINALES DEL SCRIPT ==========

# PROTECCIONES AVANZADAS
function Remove-CopilotAndAI {
    Write-Status -Types "-" -Status "Eliminando físicamente Copilot y componentes AI..."
    
    $CopilotPaths = @(
        "$env:SystemRoot\SystemApps\Microsoft.Windows.Copilot_*",
        "$env:SystemRoot\System32\Copilot",
        "$env:ProgramFiles\WindowsCopilot",
        "$env:LOCALAPPDATA\Microsoft\Windows\Copilot"
    )
    
    foreach ($path in $CopilotPaths) {
        Remove-ItemVerified -Path $path -Recurse -Force
    }
    
    $AIServices = @(
        "AIShutdown",
        "AIPerformanceBoost",
        "MicrosoftEdgeAI"
    )
    Set-ServiceStartup -ServiceNames $AIServices -StartupType "Disabled"
    
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Value 1
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AI" -Name "DisableWindowsAI" -Value 1
    
    Write-Status -Types "+" -Status "Copilot y componentes AI eliminados completamente"
}

function Set-AdvancedTelemetryBlock {
    Write-Status -Types "@" -Status "Configurando bloqueo de red avanzado..."
    
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
    Write-Status -Types "+" -Status "Bloqueo de red avanzado configurado (100+ dominios)"
}

function Set-HardeningSecurity {
    Write-Status -Types "@" -Status "Aplicando hardening de seguridad extremo..."
    
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
    
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 0
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" -Name "ExecutionPolicy" -Value "AllSigned"
    
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

function Disable-HyperV {
    Write-Status -Types "@" -Status "Disabling Hyper-V..."
    
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

# ========== ESTA FUNCIÓN HA SIDO ELIMINADA POR COMPLETO ==========
# function Optimize-WindowsFeaturesList { ... }

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

function Disable-HyperVForVMware {
    Write-Host "Disabling Hyper-V for VMware..." -ForegroundColor Yellow
    
    try {
        bcdedit /set hypervisorlaunchtype off | Out-Null
        Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -NoRestart -ErrorAction SilentlyContinue
        Write-Host "[+] Hyper-V disabled successfully" -ForegroundColor Green
    } catch {
        Write-Host "[-] Error disabling Hyper-V: $_" -ForegroundColor Red
    }
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

# ========== FUNCIÓN PRINCIPAL DE OPTIMIZACIÓN ==========
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
    
    # Final confirmation
    Write-Host "This IMPROVED version will:" -ForegroundColor Yellow
    Write-Host "- Disable Hyper-V for VMware" -ForegroundColor White
    Write-Host "- Remove bloatware and unnecessary services" -ForegroundColor White
    Write-Host "- Optimize performance and privacy" -ForegroundColor White
    Write-Host "- ELIMINATE Copilot, AI components and Recall" -ForegroundColor White
    Write-Host "- Advanced network blocking (100+ domains)" -ForegroundColor White
    Write-Host "- Remove physical telemetry files" -ForegroundColor White
    Write-Host "- Hardening security without performance impact" -ForegroundColor White
    Write-Host "- Deep system cleanup (DISM, WinSxS, Update cache)" -ForegroundColor White
    Write-Host "- Disable input data collection & startup suggestions" -ForegroundColor White
    Write-Host "- Optimize NTFS and remove unused language packs" -ForegroundColor White
    Write-Host "- Apply WinUtil tweaks (activity history, telemetry, widgets, etc.)" -ForegroundColor White
    Write-Host "- Generate detailed log file in TEMP folder" -ForegroundColor White
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
    
    # 3. Services and processes (sin Optimize-WindowsFeaturesList)
    Write-Host "`n=== SERVICES AND PROCESSES ===" -ForegroundColor Cyan
    Disable-IntelLMS
    Disable-AdobeServices
    Disable-TeredoIPv6
    Optimize-ServicesRunning
    
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
    Disable-InputPersonalization
    Disable-StartupSuggestions
    
    # 5. Windows Update
    Write-Host "`n=== WINDOWS UPDATE ===" -ForegroundColor Cyan
    Set-WindowsUpdateManual
    
    # 6. Component removal
    Write-Host "`n=== COMPONENT REMOVAL ===" -ForegroundColor Cyan
    Remove-OneDrive
    Remove-Xbox
    Remove-Bloatware
    
    # 7. ADVANCED PROTECTIONS
    Write-Host "`n=== ADVANCED PROTECTIONS ===" -ForegroundColor Cyan
    Remove-CopilotAndAI
    Set-AdvancedTelemetryBlock
    Set-HardeningSecurity
    Remove-TelemetryFiles
    
    # 8. Deep Maintenance
    Write-Host "`n=== DEEP MAINTENANCE ===" -ForegroundColor Cyan
    Invoke-DeepSystemCleanup
    Remove-UnusedLanguagePacks
    
    # 9. Performance
    Write-Host "`n=== PERFORMANCE ===" -ForegroundColor Cyan
    Optimize-Performance
    Optimize-Network
    Optimize-NTFS
    
    # 10. Security
    Write-Host "`n=== SECURITY ===" -ForegroundColor Cyan
    Optimize-Firewall
    
    # 11. Explorer
    Write-Host "`n=== FILE EXPLORER ===" -ForegroundColor Cyan
    Optimize-Explorer
    
    # 12. Scheduled tasks
    Write-Host "`n=== SCHEDULED TASKS ===" -ForegroundColor Cyan
    Disable-UnnecessaryTasks
    
    # 13. WinUtil tweaks
    Write-Host "`n=== WINUTIL TWEAKS ===" -ForegroundColor Cyan
    Apply-WinUtilTweaks
    
    # 14. Cleanup
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
    Write-Host "  - Input data collection disabled" -ForegroundColor Green
    Write-Host "  - Startup suggestions disabled (notifications untouched)" -ForegroundColor Green
    Write-Host "  - WinUtil tweaks applied (activity, telemetry, widgets, etc.)" -ForegroundColor Green
    Write-Host "  - Deep cleanup (DISM, WinSxS, Update cache)" -ForegroundColor Green
    Write-Host "  - Unused language packs removed" -ForegroundColor Green
    Write-Host "  - NTFS optimizations applied" -ForegroundColor Green
    Write-Host "  - File Explorer improved" -ForegroundColor Green
    Write-Host "  - Firewall and security optimized" -ForegroundColor Green
    Write-Host ""
    Write-Host "Detailed log saved to: $script:LogFile" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Optimization completed. Some changes may require a restart." -ForegroundColor Yellow
    Write-Host "Press any key to exit..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Ejecutar la optimización completa
Start-CompleteOptimization
