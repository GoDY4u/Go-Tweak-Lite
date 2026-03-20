@echo off
setlocal enabledelayedexpansion

title MAXIMUM CLEANUP - SPACE REPORT
color 0C

echo ============================================
echo        MAXIMUM SYSTEM CLEANUP
echo       WITH SPACE LIBERATION REPORT
echo ============================================
echo.

:: Admin check
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Run as Administrator!
    pause
    exit
)

:: ================================
:: FUNCTION: Get folder size
:: ================================
:GetFolderSize
set sizeTemp=0
for /f "usebackq" %%S in (`PowerShell -Command "(Get-ChildItem -Recurse -Force '%~1' | Measure-Object -Property Length -Sum).Sum"`) do set sizeTemp=%%S
set "%~2=%sizeTemp%"
exit /b

:: ================================
:: FOLDERS TO CLEAN
:: ================================
set folders=%TEMP% %TMP% %LOCALAPPDATA%\Temp C:\Windows\Temp C:\Windows\Logs C:\Windows\LiveKernelReports C:\Windows\System32\winevt\Logs C:\Windows\Downloaded Program Files C:\Windows\CSC C:\Windows\SoftwareDistribution\DeliveryOptimization\Cache C:\Windows\SoftwareDistribution\Download %USERPROFILE%\AppData\Local\Packages C:\Windows\System32\FxsTmp C:\Windows\System32\spool\PRINTERS

:: ================================
:: 1. CALCULATE SIZE BEFORE CLEANUP
:: ================================
set totalBefore=0
for %%F in (%folders%) do (
    if exist "%%F" (
        call :GetFolderSize "%%F" size
        set /a totalBefore+=!size!
    )
)

:: ================================
:: 2. CLEAN FOLDERS
:: ================================
echo Cleaning temp, logs, caches, mini-dumps, thumbnails...
for %%F in (%folders%) do (
    if exist "%%F" (
        echo Cleaning: %%F
        del /s /f /q "%%F\*" >nul 2>&1
        for /d %%D in ("%%F\*") do rd /s /q "%%D" >nul 2>&1
    )
)

:: Prefetch
echo Cleaning Prefetch...
del /s /f /q C:\Windows\Prefetch\* >nul 2>&1

:: Windows Update
echo Resetting Windows Update...
net stop wuauserv >nul 2>&1
net stop bits >nul 2>&1
rd /s /q C:\Windows\SoftwareDistribution >nul 2>&1
md C:\Windows\SoftwareDistribution >nul 2>&1
net start wuauserv >nul 2>&1
net start bits >nul 2>&1

:: Icon & Thumbnail cache
echo Cleaning icon and thumbnail cache...
del /s /f /q "%LocalAppData%\Microsoft\Windows\Explorer\thumbcache_*.db" >nul 2>&1
del /s /f /q "%LocalAppData%\Microsoft\Windows\Explorer\iconcache_*.db" >nul 2>&1

:: Hibernation
echo Disabling hibernation...
powercfg -h off >nul 2>&1

:: Windows Store cache
echo Resetting Windows Store cache...
start /wait wsreset.exe

:: RAM cleanup
echo Clearing RAM cache...
PowerShell -Command "Clear-RecycleBin -Confirm:$false" >nul 2>&1
PowerShell -Command "Try {Add-Type -AssemblyName System.Runtime.InteropServices; $code = '[DllImport(""ntdll.dll"")] public static extern uint NtSetSystemInformation(int SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength);'; $ntdll = Add-Type -MemberDefinition $code -Name Ntdll -Namespace Win32 -PassThru; $ntdll::NtSetSystemInformation(80, [IntPtr]::Zero, 0)} Catch {}" >nul 2>&1

:: DISM + SFC
echo Running DISM cleanup...
dism /online /cleanup-image /startcomponentcleanup /quiet
echo Running SFC scan...
sfc /scannow >nul

:: Flush DNS + Network reset
echo Flushing DNS and resetting network...
ipconfig /flushdns >nul
netsh int ip reset >nul
netsh winsock reset >nul

:: Browser caches
echo Cleaning browser caches...
set browsers=%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cache %LOCALAPPDATA%\Google\Chrome\User Data\Default\Cache %LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Cache
for %%B in (%browsers%) do (
    if exist "%%B" rd /s /q "%%B" >nul 2>&1
)
for /d %%F in ("%APPDATA%\Mozilla\Firefox\Profiles\*") do (
    if exist "%%F\cache2" rd /s /q "%%F\cache2" >nul 2>&1
)

:: Mini-dumps
echo Deleting mini-dumps...
del /s /f /q C:\Windows\Minidump\* >nul 2>&1

:: ================================
:: 3. CALCULATE SIZE AFTER CLEANUP
:: ================================
set totalAfter=0
for %%F in (%folders%) do (
    if exist "%%F" (
        call :GetFolderSize "%%F" size
        set /a totalAfter+=!size!
    )
)

:: ================================
:: 4. REPORT
:: ================================
set /a freed=totalBefore-totalAfter
set /a freedMB=freed/1048576
set /a freedGB=freed/1073741824

echo.
echo ============================================
echo        CLEANUP COMPLETED
echo ============================================
echo Total space freed: !freedMB! MB (~!freedGB! GB)
echo.
echo Press any key to exit...
pause >nul
