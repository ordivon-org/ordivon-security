param(
    [Parameter(Mandatory = $true)][ValidateSet('pre','post')][string]$Phase,
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [string[]]$FileRoots = @('C:\Program Files\Blackmagic Design\DaVinci Resolve'),
    [int]$MaxFileEntries = 20000,
    [int]$MaxEventEntries = 4000
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$channelErrors = @()

function Get-OptionalProperty {
    param(
        [Parameter(Mandatory = $true)]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name
    )
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    return $property.Value
}

function Add-ChannelError {
    param(
        [Parameter(Mandatory = $true)][string]$Channel,
        [Parameter(Mandatory = $true)]$ErrorRecord
    )
    $script:channelErrors += [ordered]@{
        channel = $Channel
        errorType = $ErrorRecord.Exception.GetType().FullName
        errorMessage = $ErrorRecord.Exception.Message
        scriptStackTrace = $ErrorRecord.ScriptStackTrace
    }
}

function Invoke-Channel {
    param(
        [Parameter(Mandatory = $true)][string]$Channel,
        [Parameter(Mandatory = $true)][scriptblock]$Body,
        $DefaultValue
    )
    try {
        return & $Body
    } catch {
        Add-ChannelError -Channel $Channel -ErrorRecord $_
        return $DefaultValue
    }
}

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
            $displayName = Get-OptionalProperty -InputObject $_ -Name 'DisplayName'
            if ($null -ne $displayName) {
                $values += [ordered]@{
                    displayName = [string]$displayName
                    displayVersion = [string](Get-OptionalProperty -InputObject $_ -Name 'DisplayVersion')
                    publisher = [string](Get-OptionalProperty -InputObject $_ -Name 'Publisher')
                    uninstallString = [string](Get-OptionalProperty -InputObject $_ -Name 'UninstallString')
                    registryPath = [string](Get-OptionalProperty -InputObject $_ -Name 'PSPath')
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
    param([string]$Channel, [string]$LogName)
    try {
        return @(Get-WinEvent -LogName $LogName -MaxEvents $MaxEventEntries -ErrorAction Stop | ForEach-Object {
            [ordered]@{
                logName = [string](Get-OptionalProperty -InputObject $_ -Name 'LogName')
                id = [int](Get-OptionalProperty -InputObject $_ -Name 'Id')
                level = [int](Get-OptionalProperty -InputObject $_ -Name 'Level')
                provider = [string](Get-OptionalProperty -InputObject $_ -Name 'ProviderName')
                recordId = [int64](Get-OptionalProperty -InputObject $_ -Name 'RecordId')
                timeCreatedUtc = if ($null -ne $_.TimeCreated) { $_.TimeCreated.ToUniversalTime().ToString('o') } else { $null }
                message = [string](Get-OptionalProperty -InputObject $_ -Name 'Message')
            }
        })
    } catch {
        Add-ChannelError -Channel $Channel -ErrorRecord $_
        return @()
    }
}

$files = Invoke-Channel -Channel 'files' -DefaultValue @() -Body { @(Get-FileSnapshot) }
$registryStartup = Invoke-Channel -Channel 'registry-startup' -DefaultValue @() -Body { @(Get-RegistryStartupEntries) }
$services = Invoke-Channel -Channel 'services' -DefaultValue @() -Body {
    @(Get-CimInstance Win32_Service | Select-Object Name, State, StartMode, PathName, StartName)
}
$drivers = Invoke-Channel -Channel 'drivers' -DefaultValue @() -Body {
    @(Get-CimInstance Win32_SystemDriver | Select-Object Name, State, StartMode, PathName, ServiceType)
}
$scheduledTasks = Invoke-Channel -Channel 'scheduled-tasks' -DefaultValue @() -Body {
    @(Get-ScheduledTask | Select-Object TaskName, TaskPath, State, Author, Description)
}
$bits = Invoke-Channel -Channel 'bits' -DefaultValue @() -Body {
    @(Get-BitsTransfer -AllUsers | Select-Object DisplayName, JobId, JobState, OwnerAccount, TransferType)
}
$installedProducts = Invoke-Channel -Channel 'installed-products' -DefaultValue @() -Body { @(Get-UninstallEntries) }
$users = Invoke-Channel -Channel 'local-users' -DefaultValue @() -Body {
    @(Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordRequired, PrincipalSource)
}
$groups = Invoke-Channel -Channel 'local-groups' -DefaultValue @() -Body {
    @(Get-LocalGroup | Select-Object Name, Description, PrincipalSource)
}
$certificates = Invoke-Channel -Channel 'certificates' -DefaultValue @() -Body {
    @(Get-ChildItem Cert:\LocalMachine\Root, Cert:\LocalMachine\My -ErrorAction Stop | ForEach-Object {
        [ordered]@{
            subject = [string](Get-OptionalProperty -InputObject $_ -Name 'Subject')
            issuer = [string](Get-OptionalProperty -InputObject $_ -Name 'Issuer')
            thumbprint = [string](Get-OptionalProperty -InputObject $_ -Name 'Thumbprint')
            notAfter = if ($null -ne $_.NotAfter) { $_.NotAfter.ToUniversalTime().ToString('o') } else { $null }
        }
    })
}
$defenderStatus = Invoke-Channel -Channel 'defender-status' -DefaultValue $null -Body {
    Get-MpComputerStatus | Select-Object *
}
$defenderThreats = Invoke-Channel -Channel 'defender-threats' -DefaultValue @() -Body {
    @(Get-MpThreatDetection | Select-Object *)
}
$networkAdapters = Invoke-Channel -Channel 'network-adapters' -DefaultValue @() -Body {
    @(Get-NetAdapter -IncludeHidden | Select-Object Name, InterfaceDescription, Status, MacAddress)
}

$result = [ordered]@{
    schemaVersion = 1
    kind = 'ordivon.security.windows-installer-observation'
    phase = $Phase
    capturedAtUtc = [DateTime]::UtcNow.ToString('o')
    computerName = $env:COMPUTERNAME
    files = $files
    registry = [ordered]@{ startupEntries = $registryStartup }
    services = $services
    drivers = $drivers
    scheduledTasks = $scheduledTasks
    bitsJobs = $bits
    startupEntries = $registryStartup
    installedProducts = $installedProducts
    usersGroups = [ordered]@{ users = $users; groups = $groups }
    certificates = $certificates
    defender = [ordered]@{ status = $defenderStatus; threats = $defenderThreats }
    eventLogs = [ordered]@{
        powershell = Get-EventSlice 'event-powershell' 'Microsoft-Windows-PowerShell/Operational'
        taskScheduler = Get-EventSlice 'event-task-scheduler' 'Microsoft-Windows-TaskScheduler/Operational'
        defender = Get-EventSlice 'event-defender' 'Microsoft-Windows-Windows Defender/Operational'
        system = Get-EventSlice 'event-system' 'System'
        application = Get-EventSlice 'event-application' 'Application'
    }
    networkAdapters = $networkAdapters
    channelErrors = @($channelErrors)
    degradedChannelCount = [int]$channelErrors.Count
    readOnlyObserver = $true
}

$temporary = "$OutputPath.partial"
[System.IO.File]::WriteAllText(
    $temporary,
    ($result | ConvertTo-Json -Depth 12 -Compress) + "`n",
    [System.Text.UTF8Encoding]::new($false)
)
Move-Item -LiteralPath $temporary -Destination $OutputPath -Force
