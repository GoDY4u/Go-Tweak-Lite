# REQUIERE EJECUTAR COMO ADMINISTRADOR

Write-Host "=== REVERTIENDO TWEAKS COMPLEMENTARIOS ===" -ForegroundColor Cyan

# 2. WPFTweaksHiber - REVERTIR Hibernation
Write-Host "Reactivando Hibernación..." -ForegroundColor Yellow
powercfg.exe /hibernate on
Write-Host "Hibernación reactivada." -ForegroundColor Green

# 24. WPFTweaksDisableLMS1 - REVERTIR Intel LMS (vPro) 
Write-Host "Intentando revertir Intel LMS (vPro)..." -ForegroundColor Yellow
Write-Host "NOTA: Para revertir completamente, necesitas reinstalar Intel ME desde la web del fabricante." -ForegroundColor Red
# Esto al menos intentará restablecer el servicio si existe
Set-Service -Name "LMS" -StartupType Manual -ErrorAction SilentlyContinue
Write-Host "Servicio LMS configurado como Manual (debes reinstalar drivers)." -ForegroundColor Green

# 26. WPFTweaksRemoveOnedrive - REVERTIR OneDrive
Write-Host "Reinstalando OneDrive..." -ForegroundColor Yellow
winget install --id Microsoft.OneDrive -e --accept-package-agreements --accept-source-agreements
Write-Host "OneDrive reinstalado." -ForegroundColor Green

# 29. WPFTweaksDebloatAdobe - REVERTIR CCStopper (Adobe)
Write-Host "Revirtiendo CCStopper para Adobe..." -ForegroundColor Yellow
$CCPath = "C:\Program Files (x86)\Common Files\Adobe\Adobe Desktop Common\ADS\Adobe Desktop Service.exe.old"
$NewPath = "C:\Program Files (x86)\Common Files\Adobe\Adobe Desktop Common\ADS\Adobe Desktop Service.exe"
if (Test-Path $CCPath) {
    Rename-Item -Path $CCPath -NewName "Adobe Desktop Service.exe" -Force
    Write-Host "Adobe Desktop Service restaurado." -ForegroundColor Green
} else {
    Write-Host "Adobe Desktop Service.old no encontrado (nada que revertir)." -ForegroundColor Yellow
}

# 30. WPFTweaksBlockAdobeNet - REVERTIR Block Adobe Networks (Hosts file)
Write-Host "Limpiando bloqueos de Adobe del archivo hosts..." -ForegroundColor Yellow
$hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
$hostsContent = Get-Content $hostsFile
# Filtrar líneas que NO contengan dominios de Adobe
$adobeKeywords = @("adobe", "adobegenuine", "adobedtm")
$cleanContent = $hostsContent | Where-Object {
    $line = $_
    $isAdobeLine = $false
    foreach ($keyword in $adobeKeywords) {
        if ($line -match $keyword) { $isAdobeLine = $true; break }
    }
    -not $isAdobeLine
}
Set-Content -Path $hostsFile -Value $cleanContent
Write-Host "Bloqueos de Adobe eliminados del archivo hosts." -ForegroundColor Green

# 33. WPFTweaksDeleteTempFiles - REVERTIR Temp Files
Write-Host "Los archivos temporales se regenerarán automáticamente. Nada que revertir." -ForegroundColor Yellow

# 36. WPFTweaksTeredo - REVERTIR Teredo
Write-Host "Reactivando Teredo..." -ForegroundColor Yellow
netsh interface teredo set state default
Write-Host "Teredo reactivado (estado default)." -ForegroundColor Green

# 37. WPFTweaksDisableipsix - REVERTIR IPv6 en adaptadores
Write-Host "Reactivando IPv6 en adaptadores de red..." -ForegroundColor Yellow
Enable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6
Write-Host "IPv6 reactivado en todos los adaptadores." -ForegroundColor Green

Write-Host "`n=== TWEAKS COMPLEMENTARIOS REVERTIDOS ===" -ForegroundColor Green
Write-Host "Ahora ejecuta el archivo .reg de 'DESHACER' para revertir la parte del registro." -ForegroundColor Cyan
Write-Host "Algunos cambios requieren reinicio para surtir efecto completo." -ForegroundColor Yellow