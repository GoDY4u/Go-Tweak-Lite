# REQUIERE EJECUTAR COMO ADMINISTRADOR

Write-Host "=== APLICANDO TWEAKS COMPLEMENTARIOS ===" -ForegroundColor Cyan

# 2. WPFTweaksHiber - Disable Hibernation COMPLETO
Write-Host "Deshabilitando Hibernación..." -ForegroundColor Yellow
powercfg.exe /hibernate off
Write-Host "Hibernación deshabilitada y archivo hiberfil.sys eliminado." -ForegroundColor Green

# 24. WPFTweaksDisableLMS1 - Disable Intel LMS (vPro) - LO MÁS AGresivo
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
    Write-Host "OneDriveSetup.exe no encontrado. OneDrive podría no estar instalado." -ForegroundColor Red
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

# 37. WPFTweaksDisableipsix - Disable IPv6 en adaptadores
Write-Host "Deshabilitando IPv6 en adaptadores de red..." -ForegroundColor Yellow
Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6
Write-Host "IPv6 deshabilitado en todos los adaptadores." -ForegroundColor Green

Write-Host "`n=== TODOS LOS TWEAKS COMPLEMENTARIOS APLICADOS ===" -ForegroundColor Green
Write-Host "Por favor, ejecuta el archivo .reg para completar la configuración." -ForegroundColor Cyan
Write-Host "Algunos cambios requieren reinicio para surtir efecto completo." -ForegroundColor Yellow