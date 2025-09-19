# ==========================================
# SCRIPT COMPLETO DE TWEAKS + SERVICIOS + EDGE + MOVILES
# REQUIERE EJECUTAR COMO ADMINISTRADOR
# ==========================================

Write-Host "=== APLICANDO TWEAKS COMPLEMENTARIOS Y AJUSTES DE SERVICIOS ===" -ForegroundColor Cyan

# ----------------------------
# 1. HIBERNACIÓN
# ----------------------------
Write-Host "Deshabilitando Hibernación..." -ForegroundColor Yellow
powercfg.exe /hibernate off
Write-Host "Hibernación deshabilitada y archivo hiberfil.sys eliminado." -ForegroundColor Green

# ----------------------------
# 2. INTEL LMS
# ----------------------------
Write-Host "Deshabilitando Intel LMS (vPro)..." -ForegroundColor Yellow
$serviceName = "LMS"
Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
Set-Service -Name $serviceName -StartupType Disabled -ErrorAction SilentlyContinue
sc.exe delete $serviceName 2>$null
Write-Host "Servicio LMS detenido, deshabilitado y eliminado." -ForegroundColor Green

# ----------------------------
# 3. ONEDRIVE
# ----------------------------
Write-Host "Desinstalando OneDrive..." -ForegroundColor Yellow
$OneDrivePath = "${env:SystemRoot}\SysWOW64\OneDriveSetup.exe"
if (Test-Path $OneDrivePath) {
    Start-Process -FilePath $OneDrivePath -ArgumentList "/uninstall" -Wait -NoNewWindow
    Write-Host "OneDrive desinstalado." -ForegroundColor Green
} else {
    Write-Host "OneDriveSetup.exe no encontrado. OneDrive podría no estar instalado." -ForegroundColor Red
}

# ----------------------------
# 4. ADOBE
# ----------------------------
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

# ----------------------------
# 5. TEMP FILES
# ----------------------------
Write-Host "Eliminando archivos temporales..." -ForegroundColor Yellow
Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "Archivos temporales eliminados." -ForegroundColor Green

# ----------------------------
# 6. TEREDO
# ----------------------------
Write-Host "Deshabilitando Teredo..." -ForegroundColor Yellow
netsh interface teredo set state disabled
Write-Host "Teredo deshabilitado." -ForegroundColor Green

# ----------------------------
# 7. IPV6
# ----------------------------
Write-Host "Deshabilitando IPv6 en adaptadores de red..." -ForegroundColor Yellow
Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6
Write-Host "IPv6 deshabilitado en todos los adaptadores." -ForegroundColor Green

# ----------------------------
# 8. SERVICIOS INNECESARIOS (DESHABILITAR)
# ----------------------------
Write-Host "`nDesactivando servicios innecesarios..." -ForegroundColor Yellow
$ServiciosDeshabilitar = @(
    "PhoneSvc", "ClipboardUserService_706a9", "Spooler", "PrintNotify", "Fax",
    "WSearch", "SysMain", "RtkAudioService", "RtkAudioUniversalService",
    "tzautoupdate", "CDPUserSvc", "RemoteAccess", 
    "DiagTrack", "diagnosticshub.standardcollector.service", 
    "ssh-agent", "RemoteRegistry", "BthHFSrv", 
    "NetTcpPortSharing", "BcastDVRUserService",
    "shpamsvc", "FontCache", "DusmSvc", "WpcMonSvc", 
    "SCardSvr", "ScDeviceEnum", "CertPropSvc", "RmSvc",
    "icssvc", "WwanSvc", "WalletService", "Payments",
    "NgcSvc", "NgcCtnrSvc", "DiagSvc", "AVCTPService"
)

foreach ($Servicio in $ServiciosDeshabilitar) {
    Write-Host "Desactivando servicio: $Servicio" -ForegroundColor DarkYellow
    Stop-Service -Name $Servicio -Force -ErrorAction SilentlyContinue
    Set-Service -Name $Servicio -StartupType Disabled -ErrorAction SilentlyContinue
}

# ----------------------------
# 9. SERVICIOS EN MANUAL (Windows Update)
# ----------------------------
Write-Host "`nConfigurando servicios de actualización en manual..." -ForegroundColor Yellow
$ServiciosManual = @("wuauserv", "UsoSvc")
foreach ($Servicio in $ServiciosManual) {
    Write-Host "Configurando en manual: $Servicio" -ForegroundColor DarkYellow
    Set-Service -Name $Servicio -StartupType Manual -ErrorAction SilentlyContinue
    Stop-Service -Name $Servicio -Force -ErrorAction SilentlyContinue
}

# ----------------------------
# 10. SERVICIO DE DISPOSITIVOS MÓVILES (CrossDeviceService / Your Phone)
# ----------------------------
Write-Host "`nDeshabilitando servicio de dispositivos móviles y eliminando Your Phone..." -ForegroundColor Yellow
$servicioMovil = Get-Service | Where-Object { $_.DisplayName -like "*dispositivos*" -or $_.DisplayName -like "*Cross*" }
if ($servicioMovil) {
    foreach ($svc in $servicioMovil) {
        Write-Host "Deteniendo servicio: $($svc.DisplayName) ($($svc.Name))" -ForegroundColor DarkYellow
        Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
        Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction SilentlyContinue
    }
}

# Eliminar la app Your Phone
$packages = Get-AppxPackage | Where-Object { $_.Name -like "*YourPhone*" }
if ($packages) {
    foreach ($pkg in $packages) {
        Write-Host "Eliminando paquete: $($pkg.Name)" -ForegroundColor DarkYellow
        Remove-AppxPackage -Package $pkg.PackageFullName -ErrorAction SilentlyContinue
    }
    Write-Host "Aplicación Your Phone eliminada." -ForegroundColor Green
} else {
    Write-Host "Aplicación Your Phone no encontrada." -ForegroundColor Green
}

# ----------------------------
# 11. DESINSTALAR MICROSOFT EDGE (conservar WebView2)
# ----------------------------
Write-Host "`nEliminando Microsoft Edge (conservando WebView2)..." -ForegroundColor Yellow
$EdgePath = "$env:ProgramFiles (x86)\Microsoft\Edge\Application\msedge.exe"
if (Test-Path $EdgePath) {
    $EdgeSetup = "$env:ProgramFiles (x86)\Microsoft\Edge\Application\$(Get-ChildItem "$env:ProgramFiles (x86)\Microsoft\Edge\Application" | Sort-Object Name -Descending | Select-Object -First 1)\Installer\setup.exe"
    if (Test-Path $EdgeSetup) {
        Start-Process -FilePath $EdgeSetup -ArgumentList "--uninstall --system-level --verbose-logging --force-uninstall" -Wait -NoNewWindow
        Write-Host "Microsoft Edge desinstalado." -ForegroundColor Green
    } else {
        Write-Host "No se encontró el instalador de Edge." -ForegroundColor Red
    }
} else {
    Write-Host "Microsoft Edge no encontrado." -ForegroundColor Green
}

# ----------------------------
# 12. DESACTIVAR EDGE UPDATE
# ----------------------------
Write-Host "`nDeshabilitando servicios de actualización de Edge..." -ForegroundColor Yellow
$EdgeUpdateServices = @("edgeupdate", "edgeupdatem")
foreach ($svc in $EdgeUpdateServices) {
    if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
        Write-Host "Deteniendo y deshabilitando servicio: $svc" -ForegroundColor DarkYellow
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
    }
}

Write-Host "`n=== TODOS LOS TWEAKS Y AJUSTES APLICADOS ===" -ForegroundColor Green
Write-Host "Algunos cambios requieren reinicio para surtir efecto completo." -ForegroundColor Yellow
