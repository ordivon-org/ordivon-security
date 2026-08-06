$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$programRoot = 'C:\ProgramData\Ordivon'
$statusPath = Join-Path $programRoot 'base-finalize-status.json'

try {
    powercfg.exe /hibernate off | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "powercfg failed with exit code $LASTEXITCODE."
    }

    schtasks.exe /Create /TN 'OrdivonGuestRunner' /SC ONSTART /RU SYSTEM /RL HIGHEST /TR 'powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\ProgramData\Ordivon\guest-runner.ps1' /F | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "schtasks failed with exit code $LASTEXITCODE."
    }

    Remove-Item -LiteralPath 'C:\Windows\Panther\unattend.xml' -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath 'C:\Windows\Panther\Unattend.xml' -Force -ErrorAction SilentlyContinue
    Remove-Item -Path 'C:\Windows\Panther\UnattendGC\*' -Force -ErrorAction SilentlyContinue

    $volume = Get-Volume -FileSystemLabel 'ORDIVONBLD' -ErrorAction Stop |
        Where-Object { $null -ne $_.DriveLetter } |
        Select-Object -First 1
    if ($null -eq $volume) {
        throw 'ORDIVONBLD result volume has no drive letter.'
    }

    $resultRoot = "$($volume.DriveLetter):\"
    $probePath = Join-Path $resultRoot '.ordivon-write-probe'
    [System.IO.File]::WriteAllText(
        $probePath,
        "probe`n",
        [System.Text.UTF8Encoding]::new($false)
    )
    Remove-Item -LiteralPath $probePath -Force

    net.exe user OrdivonBootstrap /active:no | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "net user failed with exit code $LASTEXITCODE."
    }

    $resultPath = Join-Path $resultRoot 'base-ready.json'
    $result = [ordered]@{
        schemaVersion = 1
        kind = 'ordivon.security.windows-kvm-base-ready'
        status = 'ready'
        computerName = $env:COMPUTERNAME
        windowsBuild = [Environment]::OSVersion.Version.ToString()
        guestRunner = 'C:\ProgramData\Ordivon\guest-runner.ps1'
        p1Observer = 'C:\ProgramData\Ordivon\p1-observer.ps1'
        networkRequired = $false
    }
    [System.IO.File]::WriteAllText(
        $resultPath,
        ($result | ConvertTo-Json -Compress) + "`n",
        [System.Text.UTF8Encoding]::new($false)
    )
    [System.IO.File]::WriteAllText(
        $statusPath,
        ($result | ConvertTo-Json -Compress) + "`n",
        [System.Text.UTF8Encoding]::new($false)
    )
    Start-Sleep -Seconds 2
}
catch {
    $failure = [ordered]@{
        schemaVersion = 1
        kind = 'ordivon.security.windows-kvm-base-finalize-status'
        status = 'failed'
        errorType = $_.Exception.GetType().FullName
        errorMessage = $_.Exception.Message
    }
    [System.IO.File]::WriteAllText(
        $statusPath,
        ($failure | ConvertTo-Json -Compress) + "`n",
        [System.Text.UTF8Encoding]::new($false)
    )
    throw
}
