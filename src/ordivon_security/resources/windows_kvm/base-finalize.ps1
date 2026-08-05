$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

powercfg.exe /hibernate off | Out-Null
schtasks.exe /Create /TN 'OrdivonGuestRunner' /SC ONSTART /RU SYSTEM /RL HIGHEST /TR 'powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\ProgramData\Ordivon\guest-runner.ps1' /F | Out-Null
net.exe user OrdivonBootstrap /active:no | Out-Null
Remove-Item -LiteralPath 'C:\Windows\Panther\unattend.xml' -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath 'C:\Windows\Panther\Unattend.xml' -Force -ErrorAction SilentlyContinue
Remove-Item -Path 'C:\Windows\Panther\UnattendGC\*' -Force -ErrorAction SilentlyContinue

$volume = Get-Volume -FileSystemLabel 'ORDIVON_BUILD' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($null -eq $volume -or $null -eq $volume.DriveLetter) {
    throw 'ORDIVON_BUILD result volume is missing.'
}
$resultPath = "$($volume.DriveLetter):\base-ready.json"
$result = [ordered]@{
    schemaVersion = 1
    kind = 'ordivon.security.windows-kvm-base-ready'
    status = 'ready'
    computerName = $env:COMPUTERNAME
    windowsBuild = [Environment]::OSVersion.Version.ToString()
    guestRunner = 'C:\ProgramData\Ordivon\guest-runner.ps1'
    networkRequired = $false
}
[System.IO.File]::WriteAllText(
    $resultPath,
    ($result | ConvertTo-Json -Compress) + "`n",
    [System.Text.UTF8Encoding]::new($false)
)
Start-Sleep -Seconds 2
