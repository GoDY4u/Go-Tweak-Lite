@echo off
title Optimización de Red para Windows - Script Unificado
cls

echo ===============================
echo   OBLIGATORIO "PERMISOS DE ADMINISTRADOR", este script aplicara cambios en la red. 
echo   Presiona ENTER para continuar o CTRL+C para cancelar.
set /p dummy= 

echo ===============================
echo   Optimizacion de red Windows
echo ===============================
echo.

:: Deshabilitar algoritmo Nagle y ajustar ACK para mejorar latencia TCP
echo Aplicando ajustes TCPNoDelay, TcpAckFrequency y TcpDelAckTicks en todas las interfaces...
for /f "tokens=3*" %%i in (
    'reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards" /f "ServiceName" /s ^| findstr /i /l "ServiceName"'
) do (
    echo - Configurando interface %%i
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v TCPNoDelay /t REG_DWORD /d 1 /f >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v TcpAckFrequency /t REG_DWORD /d 1 /f >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v TcpDelAckTicks /t REG_DWORD /d 0 /f >nul
)
echo Ajustes aplicados.
echo.

:: Configurar TCP autotuning (nivel recomendado para conexiones PLC estables)
echo Configurando autotuning TCP a nivel NORMAL...
netsh int tcp set global autotuninglevel=normal >nul
echo Hecho.
echo.

:: Habilitar Receive Side Scaling (RSS)
echo Habilitando RSS (Receive Side Scaling)...
netsh int tcp set global rss=enabled >nul
echo Hecho.
echo.

:: Mostrar estado actual de parámetros TCP
echo Estado actual de parámetros TCP:
netsh int tcp show global
echo.

:: Configurar temporizador de plataforma y ticks para mejorar precisión y latencia
echo Configurando temporizador de plataforma y ticks (requiere reinicio para aplicar)...
bcdedit /set disabledynamictick yes >nul
bcdedit /set tscsyncpolicy Enhanced >nul
echo Ajustes aplicados.
echo.

:: Limpiar caché DNS para mejorar resolución de nombres
echo Limpiando cache DNS...
ipconfig /flushdns >nul
echo Cache DNS limpiada.
echo.

echo ==================================================
echo Todos los ajustes se han realizado correctamente.
echo Recuerda reiniciar el equipo para aplicar todos los cambios.
echo ==================================================

pause
exit /b
