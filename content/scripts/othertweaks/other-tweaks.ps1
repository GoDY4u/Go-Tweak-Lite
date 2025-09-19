# REQUIERE EJECUTAR COMO ADMINISTRADOR

Write-Host "=== APLICANDO TWEAKS COMPLEMENTARIOS ===" -ForegroundColor Cyan

# 2. WPFTweaksHiber - Disable Hibernation COMPLETO
Write-Host "Deshabilitando Hibernacion..." -ForegroundColor Yellow
powercfg.exe /hibernate off
Write-Host "Hibernacion deshabilitada y archivo hiberfil.sys eliminado." -ForegroundColor Green

# 24. WPFTweaksDisableLMS1 - Disable Intel LMS (vPro)
Write-Host "Deshabilitando Intel LMS (vPro)..." -ForegroundColor Yellow
$serviceName = "LMS"
Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
Set-Service -Name $serviceName -StartupType Disabled -ErrorAction SilentlyContinue
sc.exe delete $serviceName 2>$null
Write-Host "Servicio LMS detenido, deshabilitado y eliminado." -ForegroundColor Green

# 26. WPFTweaksRemoveOnedrive - Remove OneDrive COMPLETO
Write-Host "Desinstalando OneDrive..." -ForegroundColor Yellow
$OneDrivePath = "${env:SystemRoot}\SysWOW64\OneDriveSetup.exe"
if (Test-Path $OneDrivePath) {
    Start-Process -FilePath $OneDrivePath -ArgumentList "/uninstall" -Wait -NoNewWindow
    Write-Host "OneDrive desinstalado." -ForegroundColor Green
} else {
    Write-Host "OneDriveSetup.exe no encontrado. OneDrive podria no estar instalado." -ForegroundColor Red
}

# 29. WPFTweaksDebloatAdobe - CCStopper (Adobe)
Write-Host "Aplicando CCStopper para Adobe..." -ForegroundColor Yellow
$CCPath = "C:\Program Files (x86)\Common Files\Adobe\Adobe Desktop Common\ADS\Adobe Desktop Service.exe"
if (Test-Path $CCPath) {
    Takeown /f $CCPath
    icacls $CCPath /grant Administrators:F
    Rename-Item -Path $CCPath -NewName "Adobe Desktop Service.exe.old" -Force
    Write-Host "Adobe Desktop Service deshabilitado." -ForegroundColor Green
} else {
    Write-Host "Adobe Desktop Service no encontrado." -ForegroundColor Yellow
}

# 30. WPFTweaksBlockAdobeNet - Block Adobe Networks (Hosts file)
Write-Host "Bloqueando dominios de Adobe en el archivo hosts..." -ForegroundColor Yellow
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
Write-Host "Dominios de Adobe añadidos al bloqueo." -ForegroundColor Green

# 33. WPFTweaksDeleteTempFiles - Delete Temp Files
Write-Host "Eliminando archivos temporales..." -ForegroundColor Yellow
Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "Archivos temporales eliminados." -ForegroundColor Green

# 36. WPFTweaksTeredo - Disable Teredo
Write-Host "Deshabilitando Teredo..." -ForegroundColor Yellow
netsh interface teredo set state disabled
Write-Host "Teredo deshabilitado." -ForegroundColor Green

# 37. WPFTweaksDisableIPv6 - Disable IPv6 en adaptadores
Write-Host "Deshabilitando IPv6 en adaptadores de red..." -ForegroundColor Yellow
Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6
Write-Host "IPv6 deshabilitado en todos los adaptadores." -ForegroundColor Green

# NUEVA SECCIÓN: Desactivar Servicios innecesarios
Write-Host "`nDesactivando servicios innecesarios..." -ForegroundColor Yellow

$Servicios = @(
    # Cola de impresión
    "Spooler",

    # Servicios de búsqueda y rendimiento
    "WSearch",                  # Windows Search
    "SysMain",                  # SysMain / Superfetch

    # Realtek Audio (si no lo usas)
    "RtkAudioService",
    "RtkAudioUniversalService",

    "tzautoupdate",             # Actualizador de zona horaria automática
    "CDPUserSvc",               # Datos de contactos
    "RemoteAccess",             # Enrutamiento y acceso remoto
    "DiagTrack",                # Experiencias de usuario y telemetría
    "diagnosticshub.standardcollector.service", # Host del servicio de diagnóstico
    "ssh-agent",                # OpenSSH Authentication Agent
    "RemoteRegistry",           # Registro remoto
    "diagnosticshub.standardcollector.service", # Servicio de directivas de diagnóstico
    "BthHFSrv",                 # Servicio de soporte técnico de Bluetooth
    "NetTcpPortSharing",        # Servicio de uso compartido de puertos TCP
    "BcastDVRUserService",      # GameDVR
    "shpamsvc",                 # Shared PC Account Manager
    "FontCache",                # Windows Presentation Foundation Font Cache

    "DusmSvc",                  # Uso de datos
    "WpcMonSvc",                # Control parental
    "SCardSvr",                 # Tarjeta inteligente
    "ScDeviceEnum",             # Enumeración de tarjetas inteligentes
    "CertPropSvc",              # Propagación de certificados de tarjetas inteligentes
    "Fax",                      # Servicio de Fax
    "PrintNotify",              # Extensiones y notificaciones de impresora
    "RmSvc",                    # Servicio de administración de radio
    "icssvc",                   # Compartir red móvil
    "WwanSvc",                  # Cobertura inalámbrica móvil
    "WalletService",            # Servicio Wallet
    "Payments",                 # Administración de pagos y NFC/SE
    "NgcSvc",                   # Microsoft Passport
    "NgcCtnrSvc",               # Contenedor de Microsoft Passport
    "DiagSvc",                  # Servicio de ejecución de diagnóstico
    "lfsvc",                    # Servicio de geolocalización
    "wisvc",                    # Servicio de Windows Insider
    "dmwappushservice"          # Servicio de enrutamiento de mensajes WAP
)

foreach ($Servicio in $Servicios) {
    Write-Host "Desactivando servicio: $Servicio" -ForegroundColor DarkYellow
    Stop-Service -Name $Servicio -ErrorAction SilentlyContinue
    Set-Service -Name $Servicio -StartupType Disabled -ErrorAction SilentlyContinue
}

Write-Host "Servicios innecesarios desactivados. Reinicia el sistema para aplicar cambios." -ForegroundColor Green

Write-Host "`n=== TODOS LOS TWEAKS COMPLEMENTARIOS APLICADOS ===" -ForegroundColor Green
Write-Host "Por favor, ejecuta el archivo .reg para completar la configuración." -ForegroundColor Cyan
Write-Host "Algunos cambios requieren reinicio para surtir efecto completo." -ForegroundColor Yellow
