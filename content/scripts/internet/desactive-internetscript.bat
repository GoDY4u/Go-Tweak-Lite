@echo off
title Revertir Optimizacion de Red a Valores Por Defecto
cls

echo ===============================
echo   OBLIGATORIO "PERMISOS DE ADMINISTRADOR", este script aplicara cambios en la red. 
echo   Presiona ENTER para continuar o CTRL+C para cancelar.
set /p dummy= 

echo ===============================
echo   REVERTIR CAMBIOS DE OPTIMIZACION DE RED
echo ===============================
echo.

:: Revertir ajustes TCPNoDelay, TcpAckFrequency y TcpDelAckTicks a valores por defecto (0 o sin valor)
echo Revirtiendo ajustes TCP en todas las interfaces...
for /f "tokens=3*" %%i in (
    'reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards" /f "ServiceName" /s ^| findstr /i /l "ServiceName"'
) do (
    echo - Revirtiendo interface %%i
    reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v TCPNoDelay /f >nul 2>&1
    reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v TcpAckFrequency /f >nul 2>&1
    reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v TcpDelAckTicks /f >nul 2>&1
)
echo Ajustes revertidos.
echo.

:: Configurar autotuning TCP a nivel DEFAULT (normal)
echo Configurando autotuning TCP a nivel DEFAULT (normal)...
netsh int tcp set global autotuninglevel=normal >nul
echo Hecho.
echo.

:: Habilitar Receive Side Scaling (RSS) a estado por defecto (enabled)
echo Configurando RSS (Receive Side Scaling) a estado por defecto (enabled)...
netsh int tcp set global rss=enabled >nul
echo Hecho.
echo.

:: Revertir temporizador de plataforma y ticks a valores por defecto (deshabilitado)
echo Revirtiendo configuracion de temporizador de plataforma y ticks...
bcdedit /set useplatformtick no >nul 2>&1
bcdedit /set disabledynamictick no >nul 2>&1
bcdedit /set tscsyncpolicy Default >nul 2>&1
echo Ajustes revertidos.
echo.

echo ==================================================
echo Se han revertido todos los ajustes a valores por defecto.
echo Recuerda reiniciar el equipo para aplicar los cambios.
echo ==================================================

pause
exit /b
