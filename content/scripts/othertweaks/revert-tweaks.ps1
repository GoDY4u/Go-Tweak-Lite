# ==========================================
# SCRIPT DE REVERT DE TWEAKS Y SERVICIOS
# REQUIERE EJECUTAR COMO ADMINISTRADOR
# ==========================================

Write-Host "=== REVERTIENDO TWEAKS Y SERVICIOS ===" -ForegroundColor Cyan

# ----------------------------
# 1. HIBERNACIÓN
# ----------------------------
Write-Host "Habilitando hibernación..." -ForegroundColor Yellow
powercfg.exe /hibernate on
Write-Host "Hibernación habilitada." -ForegroundColor Green

# ----------------------------
# 2. INTEL LMS
# ----------------------------
Write-Host "Restaurando Intel LMS (vPro)..." -ForegroundColor Yellow
$serviceName = "LMS"
if (!(Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {
    sc.exe create $serviceName binPath= "C:\Windows\System32\LMS.exe" start= auto
}
Set-Service -Name $serviceName -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service -Name $serviceName -ErrorAction SilentlyContinue
Write-Host "Servicio LMS restaurado." -ForegroundColor Green

# ----------------------------
# 3. IPV6
# ----------------------------
Write-Host "Habilitando IPv6 en adaptadores de red..." -ForegroundColor Yellow
Enable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6
Write-Host "IPv6 habilitado en todos los adaptadores." -ForegroundColor Green

# ----------------------------
# 4. SERVICIOS DESHABILITADOS
# ----------------------------
Write-Host "`nRestaurando servicios deshabilitados..." -ForegroundColor Yellow
$ServiciosRestaurar = @(
    "PhoneSvc", "ClipboardUserService_706a9", "Spooler", "PrintNotify", "Fax",
    "WSearch", "SysMain", "RtkAudioService", "RtkAudioUniversalService",
    "tzautoupdate", "CDPUserSvc", "RemoteAccess", 
    "DiagTrack", "diagnosticshub.standardcollector.service", 
    "ssh-agent", "RemoteRegistry", "BthHFSrv", 
    "NetTcpPortSharing", "BcastDVRUserService",
    "shpamsvc", "FontCache", "DusmSvc", "WpcMonSvc", 
    "SCardSvr", "ScDeviceEnum", "CertPropSvc", "RmSvc",
    "icssvc", "WwanSvc", "WalletService", "Payments",
    "NgcSvc", "NgcCtnrSvc", "DiagSvc", "AVCTPService",
    "edgeupdate", "edgeupdatem"
)

foreach ($Servicio in $ServiciosRestaurar) {
    if (Get-Service -Name $Servicio -ErrorAction SilentlyContinue) {
        Write-Host "Restaurando servicio: $Servicio" -ForegroundColor DarkYellow
        Set-Service -Name $Servicio -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name $Servicio -ErrorAction SilentlyContinue
    }
}

# ----------------------------
# 5. SERVICIOS EN MANUAL (Windows Update)
# ----------------------------
Write-Host "`nRestaurando servicios de actualización a automático..." -ForegroundColor Yellow
$ServiciosUpdate = @("wuauserv", "UsoSvc")
foreach ($Servicio in $ServiciosUpdate) {
    Set-Service -Name $Servicio -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name $Servicio -ErrorAction SilentlyContinue
    Write-Host "Servicio $Servicio configurado en automático." -ForegroundColor Green
}

# ----------------------------
# 6. TEREDO
# ----------------------------
Write-Host "Habilitando Teredo..." -ForegroundColor Yellow
netsh interface teredo set state default
Write-Host "Teredo habilitado." -ForegroundColor Green

Write-Host "`n=== REVERT COMPLETADO ===" -ForegroundColor Green
Write-Host "Reinicia el sistema para aplicar todos los cambios." -ForegroundColor Yellow
