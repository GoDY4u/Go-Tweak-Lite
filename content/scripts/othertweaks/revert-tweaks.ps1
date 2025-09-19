# REQUIERE EJECUTAR COMO ADMINISTRADOR

Write-Host "=== REVERTIENDO TWEAKS COMPLEMENTARIOS ===" -ForegroundColor Cyan

# 1. Revertir Hibernación
Write-Host "Reactivando Hibernacion..." -ForegroundColor Yellow
powercfg.exe /hibernate on
Write-Host "Hibernacion habilitada." -ForegroundColor Green

# 2. Reactivar Intel LMS (vPro)
Write-Host "Restaurando Intel LMS (vPro)..." -ForegroundColor Yellow
sc.exe create LMS binPath= "C:\Windows\System32\LMS.exe" start= auto DisplayName= "Intel(R) Management and Security Application Local Management Service" 2>$null
Set-Service -Name "LMS" -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service -Name "LMS" -ErrorAction SilentlyContinue
Write-Host "Intel LMS restaurado." -ForegroundColor Green

# 3. Restaurar OneDrive
Write-Host "Restaurando OneDrive..." -ForegroundColor Yellow
$OneDrivePath = "${env:SystemRoot}\SysWOW64\OneDriveSetup.exe"
if (Test-Path $OneDrivePath) {
    Start-Process -FilePath $OneDrivePath -ArgumentList "/install" -Wait -NoNewWindow
    Write-Host "OneDrive restaurado." -ForegroundColor Green
} else {
    Write-Host "No se encontró instalador de OneDrive en el sistema." -ForegroundColor Red
}

# 4. Restaurar Adobe Desktop Service
Write-Host "Restaurando Adobe Desktop Service..." -ForegroundColor Yellow
$CCPath = "C:\Program Files (x86)\Common Files\Adobe\Adobe Desktop Common\ADS\Adobe Desktop Service.exe.old"
if (Test-Path $CCPath) {
    Rename-Item -Path $CCPath -NewName "Adobe Desktop Service.exe" -Force
    Write-Host "Adobe Desktop Service restaurado." -ForegroundColor Green
} else {
    Write-Host "No se encontró Adobe Desktop Service renombrado." -ForegroundColor Yellow
}

# 5. Quitar dominios bloqueados de Adobe en el hosts
Write-Host "Revirtiendo bloqueo de dominios Adobe en hosts..." -ForegroundColor Yellow
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
(Get-Content $hostsFile) | Where-Object {$_ -notin $adobeDomains} | Set-Content $hostsFile
Write-Host "Dominios Adobe desbloqueados." -ForegroundColor Green

# 6. Reactivar Teredo
Write-Host "Reactivando Teredo..." -ForegroundColor Yellow
netsh interface teredo set state type=default
Write-Host "Teredo reactivado." -ForegroundColor Green

# 7. Reactivar IPv6
Write-Host "Reactivando IPv6 en adaptadores de red..." -ForegroundColor Yellow
Enable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6
Write-Host "IPv6 reactivado en todos los adaptadores." -ForegroundColor Green

# 8. Restaurar servicios deshabilitados
Write-Host "`nRestaurando servicios deshabilitados..." -ForegroundColor Yellow

$Servicios = @(
    "Spooler","PhoneSvc","NgcSvc","WSearch","SysMain",
    "RtkAudioService","RtkAudioUniversalService",
    "tzautoupdate","CDPUserSvc","RemoteAccess","DiagTrack",
    "diagnosticshub.standardcollector.service","ssh-agent",
    "RemoteRegistry","BthHFSrv","NetTcpPortSharing",
    "BcastDVRUserService","shpamsvc","FontCache","DusmSvc",
    "WpcMonSvc","SCardSvr","ScDeviceEnum","CertPropSvc",
    "Fax","PrintNotify","RmSvc","icssvc","WwanSvc",
    "WalletService","Payments","NgcCtnrSvc","DiagSvc",
    "lfsvc","wisvc","dmwappushservice"
)

foreach ($Servicio in $Servicios) {
    Write-Host "Restaurando servicio: $Servicio" -ForegroundColor DarkYellow
    try {
        Set-Service -Name $Servicio -StartupType Manual -ErrorAction SilentlyContinue
        Start-Service -Name $Servicio -ErrorAction SilentlyContinue
    } catch {
        Write-Host "No se pudo restaurar el servicio $Servicio (puede no existir en este sistema)" -ForegroundColor Red
    }
}

Write-Host "Servicios restaurados (modo Manual)." -ForegroundColor Green

Write-Host "`n=== TODOS LOS TWEAKS HAN SIDO REVERTIDOS ===" -ForegroundColor Green
Write-Host "Es posible que necesites reiniciar para aplicar todos los cambios." -ForegroundColor Yellow
