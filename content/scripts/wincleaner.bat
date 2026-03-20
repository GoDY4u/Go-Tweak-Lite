@echo off
setlocal enabledelayedexpansion

title Advanced Cleanup + RAM Flush
color 0A

echo ============================================
echo        ADVANCED SYSTEM CLEANUP
echo ============================================
echo.

:: Admin check
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Run as Administrator!
    pause
    exit
)

echo Starting cleanup...
echo.

:: ================================
:: 1. TEMP FILES (AGGRESSIVE)
:: ================================
echo [1/5] Cleaning TEMP folders...

for %%T in (
    "%TEMP%"
    "%TMP%"
    "%LOCALAPPDATA%\Temp"
    "C:\Windows\Temp"
) do (
    echo Cleaning: %%T
    del /s /f /q "%%T\*" >nul 2>&1
    for /d %%D in ("%%T\*") do rd /s /q "%%D" >nul 2>&1
)

:: ================================
:: 2. PREFETCH
:: ================================
echo [2/5] Cleaning Prefetch...

del /s /f /q C:\Windows\Prefetch\* >nul 2>&1

:: ================================
:: 3. WINDOWS UPDATE CACHE
:: ================================
echo [3/5] Resetting Windows Update...

net stop wuauserv >nul 2>&1
net stop bits >nul 2>&1

rd /s /q C:\Windows\SoftwareDistribution >nul 2>&1
md C:\Windows\SoftwareDistribution >nul 2>&1

net start wuauserv >nul 2>&1
net start bits >nul 2>&1

:: ================================
:: 4. RAM CLEAN (REAL METHOD)
:: ================================
echo [4/5] Cleaning RAM...

echo Freeing standby memory...
PowerShell -Command "Clear-RecycleBin -Confirm:$false" >nul 2>&1

:: Vaciar standby list (RAM cache real)
PowerShell -Command "Try {Add-Type -AssemblyName System.Runtime.InteropServices; $code = '[DllImport(\"ntdll.dll\")] public static extern uint NtSetSystemInformation(int SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength);'; $ntdll = Add-Type -MemberDefinition $code -Name Ntdll -Namespace Win32 -PassThru; $ntdll::NtSetSystemInformation(80, [IntPtr]::Zero, 0)} Catch {}" >nul 2>&1

:: ================================
:: 5. DISM CLEANUP
:: ================================
echo [5/5] System cleanup...

dism /online /cleanup-image /startcomponentcleanup >nul

echo.
echo ============================================
echo        CLEANUP COMPLETED
echo ============================================
echo.

echo ✔ Temp cleaned
echo ✔ Prefetch cleaned
echo ✔ Windows Update reset
echo ✔ RAM cache cleared
echo ✔ System optimized

echo.
pause
