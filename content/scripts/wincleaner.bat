@echo off
setlocal enabledelayedexpansion

:: Script de limpieza del sistema combinado
:: Combina funcionalidades de todos los scripts proporcionados

title Limpieza Completa del Sistema - By Adamx & Links & xHybrid
color 0A

echo ================================================
echo    LIMPIEZA COMPLETA DEL SISTEMA WINDOWS
echo ================================================
echo.

:: Verificar permisos de administrador
call :checkPermissions

echo Ejecutando limpieza completa...
echo Esto puede tomar unos minutos...
echo.

:: 1. Limpieza de archivos temporales
echo [1/5] Limpiando archivos temporales...
RD /S /Q "%temp%" 2>nul
MKDIR "%temp%" 2>nul
takeown /f "%temp%" /r /d y 2>nul
takeown /f "C:\Windows\Temp" /r /d y 2>nul
RD /S /Q C:\Windows\Temp 2>nul
MKDIR C:\Windows\Temp 2>nul

DEL /S /Q "%TMP%\*.*" 2>nul
DEL /S /Q "%TEMP%\*.*" 2>nul
DEL /S /Q "%WINDIR%\Temp\*.*" 2>nul
DEL /S /Q "%USERPROFILE%\Local Settings\Temp\*.*" 2>nul
DEL /S /Q "%LOCALAPPDATA%\Temp\*.*" 2>nul

:: Limpieza adicional de archivos temporales
rd /s /f /q c:\windows\temp\*.* 2>nul
rd /s /q c:\windows\temp 2>nul
md c:\windows\temp 2>nul
del /s /f /q C:\WINDOWS\Prefetch\*.* 2>nul
deltree /y c:\windows\tempor~1 2>nul
deltree /y c:\windows\tmp 2>nul
deltree /y c:\windows\ff*.tmp 2>nul
deltree /y c:\windows\history 2>nul
deltree /y c:\windows\cookies 2>nul
deltree /y c:\windows\recent 2>nul
deltree /y c:\windows\spool\printers 2>nul
del c:\WIN386.SWP 2>nul

:: 2. Limpieza de archivos de registro (.log)
echo [2/5] Eliminando archivos de registro...
cd / 2>nul
del *.log /a /s /q /f 2>nul

:: 3. Limpieza de caché de actualización de Windows
echo [3/5] Limpiando caché de actualizaciones de Windows...
net stop wuauserv 2>nul
net stop UsoSvc 2>nul
timeout /t 3 /nobreak >nul
rd /s /q C:\Windows\SoftwareDistribution 2>nul
md C:\Windows\SoftwareDistribution 2>nul
net start wuauserv 2>nul
net start UsoSvc 2>nul

:: 4. Limpieza de logs del sistema con wevtutil
echo [4/5] Limpiando logs del sistema...
for /F "tokens=*" %%G in ('wevtutil.exe el 2^>nul') DO (
    echo Limpiando log: %%G
    wevtutil.exe cl "%%G" 2>nul
)

:: 5. Limpieza de papelera de reciclaje
echo [5/5] Vaciamdo papelera de reciclaje...
PowerShell -Command "Clear-RecycleBin -Confirm:$false" 2>nul

echo.
echo ================================================
echo    LIMPIEZA COMPLETADA EXITOSAMENTE!
echo ================================================
echo.
echo Operaciones realizadas:
echo - Archivos temporales eliminados
echo - Archivos de registro (.log) eliminados
echo - Caché de actualizaciones de Windows limpiado
echo - Logs del sistema limpiados
echo - Papelera de reciclaje vaciada
echo.
echo Presione cualquier tecla para salir...
pause >nul
exit

:checkPermissions
:: Verificar si se ejecuta como administrador
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Este script requiere permisos de administrador
    echo Por favor, ejecute como administrador
    echo.
    echo Presione cualquier tecla para salir...
    pause >nul
    exit /b 1
)
exit /b 0