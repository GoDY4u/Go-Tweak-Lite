# ==========================================
# SCRIPT DE REVERT DE TWEAKS Y SERVICIOS
# REQUIERE EJECUTAR COMO ADMINISTRADOR
# ==========================================

Write-Host "=== REVERT DE TWEAKS Y SERVICIOS ===" -ForegroundColor Cyan

# ----------------------------
# 1. HIBERNACIÓN
# ----------------------------
Write-Host "Rehabilitando hibernación..." -ForegroundColor Yellow
powercfg.exe /hibernate on
Write-Host "Hibernación habilitada." -ForegroundColor Green

# ----------------------------
# 2. INTEL LMS
# ----------------------------
Write-Host "Revisar si Intel LMS necesita reinstalarse manualmente..." -ForegroundColor Yellow
# LMS se eliminó con sc.exe delete, no se puede revertir automáticamente.

# ----------------------------
# 3. ONEDRIVE
# ----------------------------
Write-Host "Revisar si OneDrive necesita reinstalarse manualmente..." -ForegroundColor Yellow
# OneDrive se desinstaló, reinstalar desde Microsoft si se requiere.

# ----------------------------
# 4. ADOBE
# ----------------------------
Write-Host "Revertir cambios Adobe..." -ForegroundColor Yellow
$CCPathOld = "C:\Program Files (x86)\Common Files\Adobe\Adobe Desktop Common\ADS\Adobe Desktop Service.exe.old"
$CCPathNew = "C:\Program Files (x86)\Common Files\Adobe\Adobe Desktop Common\ADS\Adobe Desktop Service.exe"
if (Test-Path $CCPathOld) {
    Rename-Item -Path $CCPathOld -NewName "Adobe Desktop Service.exe" -Force
    Write-Host "Adobe Desktop Service restaurado." -ForegroundColor Green
}

Write-Host "Opcional: eliminar entradas de Adobe en hosts manualmente si es necesario." -ForegroundColor Yellow

# ----------------------------
# 5. TEMP FILES
# ----------------------------
Write-Host "No es necesario revertir archivos temporales." -ForegroundColor Yellow

# ----------------------------
# 6. TEREDO
# ----------------------------
Write-Host "Rehabilitando Teredo..." -ForegroundColor Yellow
netsh interface teredo set state default
Write-Host "Teredo restaurado a estado por defecto." -ForegroundColor Green

# ----------------------------
# 7. IPV6
# ----------------------------
Write-Host "Rehabilitando IPv6 en adaptadores de red..." -ForegroundColor Yellow
Enable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6
Write-Host "IPv6 habilitado en todos los adaptadores." -ForegroundColor Green

# ----------------------------
# 8. SERVICIOS DESHABILITADOS
# ----------------------------
Write-Host "`nRestaurando servicios a su estado por defecto..." -ForegroundColor Yellow
$ServiciosRestaurar = @(
    "PhoneSvc", "ClipboardUserService_706a9", "Spooler", "PrintNotify", "Fax",
    "WSearch", "SysMain", "RtkAudioService", "RtkAudioUniversalService",
    "tzautoupdate", "CDPUserSvc", "RemoteAccess", "DiagTrack", 
    "diagnosticshub.standardcollector.service", "ssh-agent", "RemoteRegistry",
    "BthHFSrv", "NetTcpPortSharing", "BcastDVRUserService",
    "shpamsvc", "FontCache", "DusmSvc", "WpcMonSvc", "SCardSvr", 
    "ScDeviceEnum", "CertPropSvc", "RmSvc", "icssvc", "WwanSvc", 
    "WalletService", "Payments", "NgcSvc", "NgcCtnrSvc", "DiagSvc",
    "AVCTPService", "StorSvc", "BDESVC", "lfsvc", "SensorService"
)

foreach ($Servicio in $ServiciosRestaurar) {
    Write-Host "Restaurando servicio: $Servicio" -ForegroundColor DarkYellow
    try {
        Set-Service -Name $Servicio -StartupType Manual -ErrorAction SilentlyContinue
        Start-Service -Name $Servicio -ErrorAction SilentlyContinue
    } catch {
        Write-Host "No se pudo restaurar: $Servicio (posiblemente eliminado o no existe)" -ForegroundColor Red
    }
}

# ----------------------------
# 9. SERVICIOS DE ACTUALIZACIÓN
# ----------------------------
Write-Host "`nConfigurando Windows Update en automático..." -ForegroundColor Yellow
$ServiciosUpdate = @("wuauserv", "UsoSvc")
foreach ($Servicio in $ServiciosUpdate) {
    Set-Service -Name $Servicio -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name $Servicio -ErrorAction SilentlyContinue
}

Write-Host "`n=== REVERT COMPLETADO ===" -ForegroundColor Green
Write-Host "Algunos cambios requieren reinicio para surtir efecto completo." -ForegroundColor Yellow
