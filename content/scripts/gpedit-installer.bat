@echo off
title Install Group Policy Editor (Fixed)
color 0A

echo ============================================
echo   Installing Group Policy Editor (gpedit)
echo ============================================
echo.

:: Comprobar permisos de admin
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Run this as Administrator!
    pause
    exit
)

echo [1/4] Starting services...
sc config trustedinstaller start= auto >nul 2>&1
net start trustedinstaller >nul 2>&1

echo [2/4] Installing ClientTools...
for %%F in ("%SystemRoot%\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientTools-Package~*.mum") do (
    echo Installing: %%~nxF
    dism /online /norestart /add-package:"%%F" >nul
)

echo [3/4] Installing ClientExtensions...
for %%F in ("%SystemRoot%\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientExtensions-Package~*.mum") do (
    echo Installing: %%~nxF
    dism /online /norestart /add-package:"%%F" >nul
)

echo [4/4] Finishing...
echo.

echo ============================================
echo   DONE! Reboot your PC
echo ============================================

pause
