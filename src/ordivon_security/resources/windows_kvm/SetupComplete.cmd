@echo off
setlocal EnableExtensions
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\ProgramData\Ordivon\base-finalize.ps1
if errorlevel 1 exit /b 1
shutdown.exe /s /t 0 /f
exit /b 0
