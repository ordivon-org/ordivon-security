@echo off
setlocal EnableExtensions
set "ORDIVON_LOG=C:\ProgramData\Ordivon\base-finalize.log"
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\ProgramData\Ordivon\base-finalize.ps1 > "%ORDIVON_LOG%" 2>&1
set "ORDIVON_EXIT=%ERRORLEVEL%"
if not "%ORDIVON_EXIT%"=="0" exit /b %ORDIVON_EXIT%
shutdown.exe /s /t 0 /f
exit /b 0
