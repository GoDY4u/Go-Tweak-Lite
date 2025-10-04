# ========== SCRIPT DE REVERSIÓN ==========
# Revierte la mayoría de cambios del script de optimización

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

function Enable-ServiceStartup {
    param([string[]]$ServiceNames, [string]$StartupType = "Automatic")
    foreach ($service in $ServiceNames) {
        try {
            if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
                Set-Service -Name $service -StartupType $StartupType -ErrorAction SilentlyContinue | Out-Null
                Write-Status -Types "+" -Status "Servicio $service configurado como $StartupType"
            }
        } catch {
            Write-Status -Types "?" -Status "No se pudo configurar servicio $service"
        }
    }
}

function Restore-HyperV {
    Write-Status -Types "@" -Status "Restaurando Hyper-V..."
    
    try {
        bcdedit /set hypervisorlaunchtype auto 2>$null
        Write-Status -Types "+" -Status "Hyper-V habilitado en configuración de arranque"
    } catch {
        Write-Status -Types "?" -Status "No se pudo modificar configuración de arranque"
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
    
    Enable-ServiceStartup -ServiceNames $HyperVServices -StartupType "Manual"
    Write-Status -Types "+" -Status "Servicios Hyper-V restaurados"
}

function Enable-Hibernate {
    Write-Status -Types "+" -Status "Habilitando hibernación..."
    powercfg -Hibernate on | Out-Null
    Write-Status -Types "+" -Status "Hibernación habilitada"
}

function Restore-SSDDefaults {
    Write-Status -Types "@" -Status "Restaurando configuración SSD por defecto..."
    fsutil behavior set DisableLastAccess 0 | Out-Null
    fsutil behavior set EncryptPagingFile 1 | Out-Null
    Write-Status -Types "+" -Status "Configuración SSD restaurada"
}

function Restore-Services {
    Write-Status -Types "@" -Status "Restaurando servicios del sistema..."
    
    # Servicios para habilitar en Automático
    $ServicesToAuto = @(
        "DiagTrack", "dmwappushservice", "WSearch",
        "FontCache", "BITS", "PhoneSvc", "WMPNetworkSvc"
    )
    
    # Servicios para habilitar en Manual
    $ServicesToManual = @(
        "Fax", "fhsvc", "GraphicsPerfSvc", "HomeGroupListener", 
        "HomeGroupProvider", "lfsvc", "MapsBroker", "PcaSvc",
        "RemoteAccess", "RemoteRegistry", "TrkWks", "XblAuthManager",
        "XblGameSave", "XboxGipSvc", "XboxNetApiSvc"
    )
    
    Enable-ServiceStartup -ServiceNames $ServicesToAuto -StartupType "Automatic"
    Enable-ServiceStartup -ServiceNames $ServicesToManual -StartupType "Manual"
    Write-Status -Types "+" -Status "Servicios del sistema restaurados"
}

function Restore-PrivacySettings {
    Write-Status -Types "@" -Status "Restaurando configuración de privacidad..."
    
    # Restaurar telemetría
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -ErrorAction SilentlyContinue
    
    # Restaurar Cortana
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -ErrorAction SilentlyContinue
    
    # Restaurar ubicación
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -ErrorAction SilentlyContinue
    
    # Restaurar reporte de errores
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -ErrorAction SilentlyContinue
    
    # Restaurar experiencias personalizadas
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -ErrorAction SilentlyComplete
    
    Write-Status -Types "+" -Status "Configuración de privacidad restaurada"
}

function Restore-WindowsUpdate {
    Write-Status -Types "@" -Status "Restaurando Windows Update automático..."
    
    # Eliminar políticas de update
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "NoAutoRebootWithLoggedOnUsers" -ErrorAction SilentlyContinue
    
    # Restaurar búsqueda de drivers
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -ErrorAction SilentlyContinue
    
    Write-Status -Types "+" -Status "Windows Update automático restaurado"
}

function Restore-NetworkSettings {
    Write-Status -Types "@" -Status "Restaurando configuración de red..."
    
    # Habilitar IPv6
    Enable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6
    
    # Restaurar Teredo
    netsh interface teredo set state type=default
    
    # Limpiar reglas de firewall personalizadas
    $CustomFirewallRules = @("BlockSMBv1", "BlockNetBIOS", "BlockLLMNR", "BlockTelemetryOutbound", "BlockAIOutbound")
    foreach ($rule in $CustomFirewallRules) {
        try {
            Remove-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue
        } catch {
            # Ignorar si no existe
        }
    }
    
    Write-Status -Types "+" -Status "Configuración de red restaurada"
}

function Restore-ExplorerSettings {
    Write-Status -Types "@" -Status "Restaurando File Explorer por defecto..."
    
    # Ocultar extensiones de archivo
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 1 -ErrorAction SilentlyContinue
    
    # Ocultar archivos ocultos
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 0 -ErrorAction SilentlyContinue
    
    # Restaurar confirmación de eliminación
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ConfirmFileDelete" -Value 1 -ErrorAction SilentlyContinue
    
    Write-Status -Types "+" -Status "File Explorer restaurado"
}

function Enable-ScheduledTasks {
    Write-Status -Types "@" -Status "Habilitando tareas programadas..."
    
    $TasksToEnable = @(
        "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
        "\Microsoft\Windows\Application Experience\ProgramDataUpdater", 
        "\Microsoft\Windows\Application Experience\StartupAppTask",
        "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask",
        "\Microsoft\Windows\Customer Experience Improvement Program\Uploader",
        "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
        "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
    )
    
    foreach ($task in $TasksToEnable) {
        try {
            Enable-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue | Out-Null
        } catch {
            # Ignorar errores
        }
    }
    
    Write-Status -Types "+" -Status "Tareas programadas habilitadas"
}

function Restore-PerformanceSettings {
    Write-Status -Types "@" -Status "Restaurando configuración de rendimiento..."
    
    # Restaurar timeout de servicios
    Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "WaitToKillServiceTimeout" -ErrorAction SilentlyContinue
    
    # Restaurar configuración de memoria
    Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -ErrorAction SilentlyContinue
    
    Write-Status -Types "+" -Status "Configuración de rendimiento restaurada"
}

function Restore-SecuritySettings {
    Write-Status -Types "@" -Status "Restaurando configuración de seguridad..."
    
    # Restaurar Windows Script Host
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -ErrorAction SilentlyContinue
    
    # Restaurar política de ejecución PowerShell
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" -Name "ExecutionPolicy" -ErrorAction SilentlyContinue
    
    Write-Status -Types "+" -Status "Configuración de seguridad restaurada"
}

function Clear-HostsFile {
    Write-Status -Types "@" -Status "Limpiando archivo hosts..."
    
    $hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
    $backupHosts = "$env:SystemRoot\System32\drivers\etc\hosts.backup"
    
    try {
        # Crear backup si no existe
        if (-not (Test-Path $backupHosts)) {
            Copy-Item $hostsFile $backupHosts -Force
        }
        
        # Restaurar hosts original (solo líneas esenciales)
        $originalContent = @"
# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#	127.0.0.1       localhost
#	::1             localhost
"@
        Set-Content -Path $hostsFile -Value $originalContent -Force
        Write-Status -Types "+" -Status "Archivo hosts limpiado"
    } catch {
        Write-Status -Types "?" -Status "No se pudo limpiar archivo hosts"
    }
}

function Restore-WindowsFeatures {
    Write-Status -Types "@" -Status "Restaurando características de Windows..."
    
    $FeaturesToEnable = @(
        "Internet-Explorer-Optional-amd64",
        "MediaPlayback",
        "XPS-Foundation-XPS-Viewer"
    )
    
    foreach ($feature in $FeaturesToEnable) {
        try {
            Enable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart | Out-Null
        } catch {
            # Ignorar errores
        }
    }
    
    Write-Status -Types "+" -Status "Características de Windows restauradas"
}

function Restore-DefaultSettings {
    Write-Status -Types "@" -Status "Restaurando configuraciones por defecto..."
    
    # Restaurar Adobe services
    $CCPath = "C:\Program Files (x86)\Common Files\Adobe\Adobe Desktop Common\ADS\Adobe Desktop Service.exe.old"
    $CCNewPath = "C:\Program Files (x86)\Common Files\Adobe\Adobe Desktop Common\ADS\Adobe Desktop Service.exe"
    if (Test-Path $CCPath) {
        try {
            Rename-Item -Path $CCPath -NewName "Adobe Desktop Service.exe" -Force
            Write-Status -Types "+" -Status "Adobe Desktop Service restaurado"
        } catch {
            Write-Status -Types "?" -Status "No se pudo restaurar Adobe Desktop Service"
        }
    }
    
    # Restaurar Intel LMS
    try {
        Set-Service -Name "LMS" -StartupType "Automatic" -ErrorAction SilentlyContinue
        Start-Service -Name "LMS" -ErrorAction SilentlyContinue
    } catch {
        # Ignorar errores
    }
    
    Write-Status -Types "+" -Status "Configuraciones por defecto restauradas"
}

# ========== FUNCIÓN PRINCIPAL ==========
function Start-CompleteRestoration {
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "    RESTAURACIÓN DE CONFIGURACIÓN WINDOWS" -ForegroundColor Cyan
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Verificar permisos de administrador
    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Host "ERROR: Este script requiere permisos de Administrador" -ForegroundColor Red
        Write-Host "Ejecuta PowerShell como Administrador e intenta nuevamente" -ForegroundColor Yellow
        pause
        exit 1
    }
    
    # Confirmación final
    Write-Host "Este script revertirá:" -ForegroundColor Yellow
    Write-Host "- Configuración de Hyper-V y virtualización" -ForegroundColor White
    Write-Host "- Servicios del sistema y tareas programadas" -ForegroundColor White
    Write-Host "- Configuración de privacidad y telemetría" -ForegroundColor White
    Write-Host "- Windows Update automático" -ForegroundColor White
    Write-Host "- Configuración de red y firewall" -ForegroundColor White
    Write-Host "- File Explorer por defecto" -ForegroundColor White
    Write-Host ""
    Write-Host "NOTA: Algunos cambios (apps eliminadas) pueden requerir reinstalación manual" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "¿Continuar? (y/n)" -ForegroundColor Yellow
    $confirm = Read-Host
    
    if ($confirm -ne 'y' -and $confirm -ne 'Y') {
        Write-Host "Restauración cancelada" -ForegroundColor Red
        exit 0
    }
    
    # EJECUTAR RESTAURACIÓN
    Write-Host ""
    Write-Host "INICIANDO RESTAURACIÓN..." -ForegroundColor Green
    Write-Host "================================================" -ForegroundColor Green
    
    # 1. Hyper-V
    Write-Host "`n=== HYPER-V ====" -ForegroundColor Cyan
    Restore-HyperV
    
    # 2. Sistema
    Write-Host "`n=== SISTEMA ====" -ForegroundColor Cyan
    Enable-Hibernate
    Restore-SSDDefaults
    Restore-PerformanceSettings
    
    # 3. Servicios
    Write-Host "`n=== SERVICIOS ====" -ForegroundColor Cyan
    Restore-Services
    Restore-DefaultSettings
    
    # 4. Privacidad
    Write-Host "`n=== PRIVACIDAD ====" -ForegroundColor Cyan
    Restore-PrivacySettings
    
    # 5. Windows Update
    Write-Host "`n=== WINDOWS UPDATE ====" -ForegroundColor Cyan
    Restore-WindowsUpdate
    
    # 6. Red
    Write-Host "`n=== RED ====" -ForegroundColor Cyan
    Restore-NetworkSettings
    Clear-HostsFile
    
    # 7. Seguridad
    Write-Host "`n=== SEGURIDAD ====" -ForegroundColor Cyan
    Restore-SecuritySettings
    
    # 8. Explorer
    Write-Host "`n=== FILE EXPLORER ====" -ForegroundColor Cyan
    Restore-ExplorerSettings
    
    # 9. Tareas programadas
    Write-Host "`n=== TAREAS PROGRAMADAS ====" -ForegroundColor Cyan
    Enable-ScheduledTasks
    
    # 10. Características Windows
    Write-Host "`n=== CARACTERÍSTICAS WINDOWS ====" -ForegroundColor Cyan
    Restore-WindowsFeatures

    # RESUMEN FINAL
    Write-Host ""
    Write-Host "================================================" -ForegroundColor Green
    Write-Host "    RESTAURACIÓN COMPLETADA!" -ForegroundColor Green
    Write-Host "================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Configuraciones restauradas:" -ForegroundColor Yellow
    Write-Host "  - Hyper-V y virtualización habilitados" -ForegroundColor Green
    Write-Host "  - Servicios del sistema restaurados" -ForegroundColor Green
    Write-Host "  - Telemetría y privacidad por defecto" -ForegroundColor Green
    Write-Host "  - Windows Update automático" -ForegroundColor Green
    Write-Host "  - Configuración de red restaurada" -ForegroundColor Green
    Write-Host "  - File Explorer por defecto" -ForegroundColor Green
    Write-Host ""
    Write-Host "NOTA: Para restaurar completamente:" -ForegroundColor Magenta
    Write-Host "  - Algunas apps eliminadas pueden requerir reinstalación manual" -ForegroundColor White
    Write-Host "  - OneDrive puede necesitar reinstalación desde Microsoft" -ForegroundColor White
    Write-Host "  - Xbox apps pueden requerir reinstalación desde Microsoft Store" -ForegroundColor White
    Write-Host ""
    
    $reboot = Read-Host "¿Reiniciar ahora? (y/n)"
    if ($reboot -eq 'y' -or $reboot -eq 'Y') {
        Write-Host "Reiniciando en 5 segundos..." -ForegroundColor Yellow
        Start-Sleep 5
        Restart-Computer -Force
    } else {
        Write-Host "Restauración completada. Reinicia cuando sea conveniente." -ForegroundColor Green
        pause
    }
}

# Ejecutar restauración
Start-CompleteRestoration
