$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$paths = @(
    'C:\Program Files\厂商B\目标产品B \.exe',
    'C:\Program Files\厂商B\目标产品B \intl.dll'
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
        fileVersion = [string]$item.VersionInfo.FileVersion
        productVersion = [string]$item.VersionInfo.ProductVersion
        companyName = [string]$item.VersionInfo.CompanyName
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
        Where-Object { $_.DisplayName -like '*目标产品B *' } |
        ForEach-Object {
            $uninstall += [ordered]@{
                displayName = [string]$_.DisplayName
                displayVersion = [string]$_.DisplayVersion
                publisher = [string]$_.Publisher
                installLocation = [string]$_.InstallLocation
                registryPath = [string]$_.PSPath
            }
        }
}

$services = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '厂商B|目标产品B' -or $_.DisplayName -match '厂商B|目标产品B' } |
    Select-Object Name, DisplayName, State, StartMode, PathName, StartName)

$result = [ordered]@{
    schemaVersion = 1
    kind = 'ordivon.security.windows-host-caseb-free-baseline'
    capturedAtUtc = [DateTime]::UtcNow.ToString('o')
    computerName = $env:COMPUTERNAME
    osVersion = [Environment]::OSVersion.Version.ToString()
    editionClaim = 'free-user-declared'
    editionLimitation = 'The collector binds installed identities but does not infer paid-feature state from UI behavior.'
    files = $files
    uninstallEntries = $uninstall
    relatedServices = $services
    runningProcesses = @(Get-Process -Name  -ErrorAction SilentlyContinue | ForEach-Object {
        [ordered]@{ id = [int]$_.Id; path = [string]$_.Path }
    })
    readOnly = $true
    hostModified = $false
}
$result | ConvertTo-Json -Depth 8 -Compress
