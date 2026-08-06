$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$paths = @(
    'C:\Program Files\厂商B Design\目标产品B Resolve\Resolve.exe',
    'C:\Program Files\厂商B Design\目标产品B Resolve\intl.dll'
)
$files = @()
foreach ($path in $paths) {
    if (-not (Test-Path -LiteralPath $path)) { continue }
    $item = Get-Item -LiteralPath $path
    $signature = Get-AuthenticodeSignature -LiteralPath $path
    $files += [ordered]@{
        path = $path
        byteLength = [int64]$item.Length
        sha256 = 'sha256:' + (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        fileVersion = $item.VersionInfo.FileVersion
        productVersion = $item.VersionInfo.ProductVersion
        companyName = $item.VersionInfo.CompanyName
        signatureStatus = [string]$signature.Status
        signerSubject = if ($null -ne $signature.SignerCertificate) {
            [string]$signature.SignerCertificate.Subject
        } else { $null }
    }
}

$uninstall = @()
foreach ($root in @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)) {
    Get-ItemProperty $root -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like '*目标产品B Resolve*' } |
        ForEach-Object {
            $uninstall += [ordered]@{
                displayName = [string]$_.DisplayName
                displayVersion = [string]$_.DisplayVersion
                publisher = [string]$_.Publisher
                installLocation = [string]$_.InstallLocation
                uninstallString = [string]$_.UninstallString
                registryPath = [string]$_.PSPath
            }
        }
}

$result = [ordered]@{
    schemaVersion = 1
    kind = 'ordivon.security.windows-host-caseb-free-baseline'
    capturedAtUtc = [DateTime]::UtcNow.ToString('o')
    computerName = $env:COMPUTERNAME
    osVersion = [Environment]::OSVersion.Version.ToString()
    files = $files
    uninstallEntries = $uninstall
    runningProcesses = @(Get-Process -Name Resolve -ErrorAction SilentlyContinue | ForEach-Object {
        [ordered]@{ id = [int]$_.Id; path = [string]$_.Path }
    })
    readOnly = $true
    hostModified = $false
}
$result | ConvertTo-Json -Depth 8 -Compress
