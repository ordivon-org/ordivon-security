param(
    [Parameter(Mandatory = $true)][ValidateSet('pre','post')][string]$Phase,
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [string[]]$FileRoots = @('C:\Program Files\Blackmagic Design\DaVinci Resolve'),
    [int]$MaxFileEntries = 20000,
    [int]$MaxEventEntries = 4000
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Get-FileSnapshot {
    $records = @()
    foreach ($root in $FileRoots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        Get-ChildItem -LiteralPath $root -Force -Recurse -File -ErrorAction SilentlyContinue |
            Select-Object -First $MaxFileEntries |
            ForEach-Object {
                $records += [ordered]@{
                    path = $_.FullName
                    byteLength = [int64]$_.Length
                    modifiedUtc = $_.LastWriteTimeUtc.ToString('o')
                    sha256 = 'sha256:' + (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                }
            }
    }
    return $records
}

function Get-UninstallEntries {
    $values = @()
    foreach ($root in @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )) {
        Get-ItemProperty $root -ErrorAction SilentlyContinue | ForEach-Object {
            if ($null -ne $_.DisplayName) {
                $values += [ordered]@{
                    displayName = [string]$_.DisplayName
                    displayVersion = [string]$_.DisplayVersion
                    publisher = [string]$_.Publisher
                    uninstallString = [string]$_.UninstallString
                    registryPath = [string]$_.PSPath
                }
            }
        }
    }
    return $values
}

function Get-RegistryStartupEntries {
    $values = @()
    foreach ($path in @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )) {
        if (Test-Path $path) {
            $item = Get-ItemProperty $path
            $values += [ordered]@{ path = $path; values = $item | Select-Object * }
        }
    }
    return $values
}

function Get-EventSlice {
    param([string]$LogName)
    try {
        return @(Get-WinEvent -LogName $LogName -MaxEvents $MaxEventEntries -ErrorAction Stop | ForEach-Object {
            [ordered]@{
                logName = $_.LogName
                id = [int]$_.Id
                level = [int]$_.Level
                provider = [string]$_.ProviderName
                recordId = [int64]$_.RecordId
                timeCreatedUtc = if ($null -ne $_.TimeCreated) { $_.TimeCreated.ToUniversalTime().ToString('o') } else { $null }
                message = [string]$_.Message
            }
        })
    } catch { return @() }
}

$bits = try { @(Get-BitsTransfer -AllUsers -ErrorAction Stop | Select-Object DisplayName, JobId, JobState, OwnerAccount, TransferType) } catch { @() }
$defender = try { Get-MpComputerStatus | Select-Object * } catch { $null }
$threats = try { @(Get-MpThreatDetection | Select-Object *) } catch { @() }
$certificates = @(Get-ChildItem Cert:\LocalMachine\Root, Cert:\LocalMachine\My -ErrorAction SilentlyContinue | ForEach-Object {
    [ordered]@{ subject=$_.Subject; issuer=$_.Issuer; thumbprint=$_.Thumbprint; notAfter=$_.NotAfter.ToUniversalTime().ToString('o') }
})

$result = [ordered]@{
    schemaVersion = 1
    kind = 'ordivon.security.windows-installer-observation'
    phase = $Phase
    capturedAtUtc = [DateTime]::UtcNow.ToString('o')
    computerName = $env:COMPUTERNAME
    files = Get-FileSnapshot
    registry = [ordered]@{ startupEntries = Get-RegistryStartupEntries }
    services = @(Get-CimInstance Win32_Service | Select-Object Name, State, StartMode, PathName, StartName)
    drivers = @(Get-CimInstance Win32_SystemDriver | Select-Object Name, State, StartMode, PathName, ServiceType)
    scheduledTasks = @(Get-ScheduledTask | Select-Object TaskName, TaskPath, State, Author, Description)
    bitsJobs = $bits
    startupEntries = Get-RegistryStartupEntries
    installedProducts = Get-UninstallEntries
    usersGroups = [ordered]@{
        users = @(Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordRequired, PrincipalSource)
        groups = @(Get-LocalGroup | Select-Object Name, Description, PrincipalSource)
    }
    certificates = $certificates
    defender = [ordered]@{ status = $defender; threats = $threats }
    eventLogs = [ordered]@{
        powershell = Get-EventSlice 'Microsoft-Windows-PowerShell/Operational'
        taskScheduler = Get-EventSlice 'Microsoft-Windows-TaskScheduler/Operational'
        defender = Get-EventSlice 'Microsoft-Windows-Windows Defender/Operational'
        system = Get-EventSlice 'System'
        application = Get-EventSlice 'Application'
    }
    networkAdapters = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Select-Object Name, InterfaceDescription, Status, MacAddress)
    readOnlyObserver = $true
}
$temporary = "$OutputPath.partial"
[System.IO.File]::WriteAllText($temporary, ($result | ConvertTo-Json -Depth 12 -Compress) + "`n", [System.Text.UTF8Encoding]::new($false))
Move-Item -LiteralPath $temporary -Destination $OutputPath -Force
