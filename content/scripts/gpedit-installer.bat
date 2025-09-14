@echo off
pushd "%~dp0"
dir /b %SystemRoot%\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientTools-Package~3*.mum >gp.txt
dir /b %SystemRoot%\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientExtensions-Package~3*.mum >>gp.txt
for /f %%i in ('findstr /i . gp.txt') do dism /online /norestart /add-package:"%SystemRoot%\servicing\Packages\%%i"
pause
