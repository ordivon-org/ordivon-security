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
$maxRecordEntries = [Math]::Min([Math]::Max($MaxEventEntries, 1), 1024)
$maxTextChars = 8192

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

function Convert-BoundedText {
    param($Value, [int]$MaxChars = 8192)
    if ($null -eq $Value) { return $null }
    $text = [string]$Value
    if ($text.Length -le $MaxChars) { return $text }
    return $text.Substring(0, $MaxChars)
}

function Add-ChannelError {
    param(
        [Parameter(Mandatory = $true)][string]$Channel,
        [Parameter(Mandatory = $true)]$ErrorRecord
    )
    $script:channelErrors += [ordered]@{
        channel = $Channel
        errorType = $ErrorRecord.Exception.GetType().FullName
        errorMessage = Convert-BoundedText $ErrorRecord.Exception.Message 2048
        scriptStackTrace = Convert-BoundedText $ErrorRecord.ScriptStackTrace 4096
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
        $remaining = $MaxFileEntries - $records.Count
        if ($remaining -le 0) { break }
        Get-ChildItem -LiteralPath $root -Force -Recurse -File -ErrorAction SilentlyContinue |
            Select-Object -First $remaining |
            ForEach-Object {
                $records += [ordered]@{
                    path = Convert-BoundedText $_.FullName 32768
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
        foreach ($item in @(Get-ItemProperty $root -ErrorAction SilentlyContinue)) {
            if ($values.Count -ge $maxRecordEntries) { break }
            $displayName = Get-OptionalProperty -InputObject $item -Name 'DisplayName'
            if ($null -ne $displayName) {
                $values += [ordered]@{
                    displayName = Convert-BoundedText $displayName 2048
                    displayVersion = Convert-BoundedText (Get-OptionalProperty $item 'DisplayVersion') 1024
                    publisher = Convert-BoundedText (Get-OptionalProperty $item 'Publisher') 2048
                    uninstallString = Convert-BoundedText (Get-OptionalProperty $item 'UninstallString') 4096
                    registryPath = Convert-BoundedText (Get-OptionalProperty $item 'PSPath') 4096
                }
            }
        }
        if ($values.Count -ge $maxRecordEntries) { break }
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
        if (-not (Test-Path $path)) { continue }
        $item = Get-ItemProperty $path
        $properties = [ordered]@{}
        foreach ($property in $item.PSObject.Properties) {
            if ($property.Name -like 'PS*') { continue }
            $properties[$property.Name] = Convert-BoundedText $property.Value 4096
        }
        $values += [ordered]@{ path = $path; values = $properties }
    }
    return $values
}

function Get-EventSlice {
    param([string]$Channel, [string]$LogName)
    try {
        return @(Get-WinEvent -LogName $LogName -MaxEvents $MaxEventEntries -ErrorAction Stop | ForEach-Object {
            $created = Get-OptionalProperty -InputObject $_ -Name 'TimeCreated'
            [ordered]@{
                logName = Convert-BoundedText (Get-OptionalProperty $_ 'LogName') 1024
                id = [int](Get-OptionalProperty $_ 'Id')
                level = [int](Get-OptionalProperty $_ 'Level')
                provider = Convert-BoundedText (Get-OptionalProperty $_ 'ProviderName') 2048
                recordId = [int64](Get-OptionalProperty $_ 'RecordId')
                timeCreatedUtc = if ($null -ne $created) { $created.ToUniversalTime().ToString('o') } else { $null }
                message = Convert-BoundedText (Get-OptionalProperty $_ 'Message') $maxTextChars
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
    @(Get-CimInstance Win32_Service | Select-Object -First $maxRecordEntries | ForEach-Object {
        [ordered]@{
            name = Convert-BoundedText (Get-OptionalProperty $_ 'Name') 1024
            state = Convert-BoundedText (Get-OptionalProperty $_ 'State') 256
            startMode = Convert-BoundedText (Get-OptionalProperty $_ 'StartMode') 256
            pathName = Convert-BoundedText (Get-OptionalProperty $_ 'PathName') 4096
            startName = Convert-BoundedText (Get-OptionalProperty $_ 'StartName') 1024
        }
    })
}
$drivers = Invoke-Channel -Channel 'drivers' -DefaultValue @() -Body {
    @(Get-CimInstance Win32_SystemDriver | Select-Object -First $maxRecordEntries | ForEach-Object {
        [ordered]@{
            name = Convert-BoundedText (Get-OptionalProperty $_ 'Name') 1024
            state = Convert-BoundedText (Get-OptionalProperty $_ 'State') 256
            startMode = Convert-BoundedText (Get-OptionalProperty $_ 'StartMode') 256
            pathName = Convert-BoundedText (Get-OptionalProperty $_ 'PathName') 4096
            serviceType = Convert-BoundedText (Get-OptionalProperty $_ 'ServiceType') 256
        }
    })
}
$scheduledTasks = Invoke-Channel -Channel 'scheduled-tasks' -DefaultValue @() -Body {
    @(Get-ScheduledTask | Select-Object -First $maxRecordEntries | ForEach-Object {
        [ordered]@{
            taskName = Convert-BoundedText (Get-OptionalProperty $_ 'TaskName') 2048
            taskPath = Convert-BoundedText (Get-OptionalProperty $_ 'TaskPath') 4096
            state = Convert-BoundedText (Get-OptionalProperty $_ 'State') 256
            author = Convert-BoundedText (Get-OptionalProperty $_ 'Author') 2048
            description = Convert-BoundedText (Get-OptionalProperty $_ 'Description') 4096
        }
    })
}
$bits = Invoke-Channel -Channel 'bits' -DefaultValue @() -Body {
    @(Get-BitsTransfer -AllUsers | Select-Object -First $maxRecordEntries | ForEach-Object {
        [ordered]@{
            displayName = Convert-BoundedText (Get-OptionalProperty $_ 'DisplayName') 2048
            jobId = Convert-BoundedText (Get-OptionalProperty $_ 'JobId') 256
            jobState = Convert-BoundedText (Get-OptionalProperty $_ 'JobState') 256
            ownerAccount = Convert-BoundedText (Get-OptionalProperty $_ 'OwnerAccount') 1024
            transferType = Convert-BoundedText (Get-OptionalProperty $_ 'TransferType') 256
        }
    })
}
$installedProducts = Invoke-Channel -Channel 'installed-products' -DefaultValue @() -Body { @(Get-UninstallEntries) }
$users = Invoke-Channel -Channel 'local-users' -DefaultValue @() -Body {
    @(Get-LocalUser | Select-Object -First $maxRecordEntries | ForEach-Object {
        [ordered]@{
            name = Convert-BoundedText (Get-OptionalProperty $_ 'Name') 1024
            enabled = [bool](Get-OptionalProperty $_ 'Enabled')
            lastLogon = Convert-BoundedText (Get-OptionalProperty $_ 'LastLogon') 1024
            passwordRequired = [bool](Get-OptionalProperty $_ 'PasswordRequired')
            principalSource = Convert-BoundedText (Get-OptionalProperty $_ 'PrincipalSource') 512
        }
    })
}
$groups = Invoke-Channel -Channel 'local-groups' -DefaultValue @() -Body {
    @(Get-LocalGroup | Select-Object -First $maxRecordEntries | ForEach-Object {
        [ordered]@{
            name = Convert-BoundedText (Get-OptionalProperty $_ 'Name') 1024
            description = Convert-BoundedText (Get-OptionalProperty $_ 'Description') 4096
            principalSource = Convert-BoundedText (Get-OptionalProperty $_ 'PrincipalSource') 512
        }
    })
}
$certificates = Invoke-Channel -Channel 'certificates' -DefaultValue @() -Body {
    @(Get-ChildItem Cert:\LocalMachine\Root, Cert:\LocalMachine\My -ErrorAction Stop |
        Select-Object -First $maxRecordEntries | ForEach-Object {
            $notAfter = Get-OptionalProperty -InputObject $_ -Name 'NotAfter'
            [ordered]@{
                subject = Convert-BoundedText (Get-OptionalProperty $_ 'Subject') 4096
                issuer = Convert-BoundedText (Get-OptionalProperty $_ 'Issuer') 4096
                thumbprint = Convert-BoundedText (Get-OptionalProperty $_ 'Thumbprint') 256
                notAfter = if ($null -ne $notAfter) { $notAfter.ToUniversalTime().ToString('o') } else { $null }
            }
        })
}
$defenderStatus = Invoke-Channel -Channel 'defender-status' -DefaultValue $null -Body {
    $status = Get-MpComputerStatus
    [ordered]@{
        amServiceEnabled = [bool](Get-OptionalProperty $status 'AMServiceEnabled')
        antivirusEnabled = [bool](Get-OptionalProperty $status 'AntivirusEnabled')
        antispywareEnabled = [bool](Get-OptionalProperty $status 'AntispywareEnabled')
        behaviorMonitorEnabled = [bool](Get-OptionalProperty $status 'BehaviorMonitorEnabled')
        ioavProtectionEnabled = [bool](Get-OptionalProperty $status 'IoavProtectionEnabled')
        nisEnabled = [bool](Get-OptionalProperty $status 'NISEnabled')
        realTimeProtectionEnabled = [bool](Get-OptionalProperty $status 'RealTimeProtectionEnabled')
        antivirusSignatureVersion = Convert-BoundedText (Get-OptionalProperty $status 'AntivirusSignatureVersion') 1024
        antivirusSignatureLastUpdated = Convert-BoundedText (Get-OptionalProperty $status 'AntivirusSignatureLastUpdated') 1024
        quickScanAge = [int](Get-OptionalProperty $status 'QuickScanAge')
        fullScanAge = [int](Get-OptionalProperty $status 'FullScanAge')
    }
}
$defenderThreats = Invoke-Channel -Channel 'defender-threats' -DefaultValue @() -Body {
    @(Get-MpThreatDetection | Select-Object -First $maxRecordEntries | ForEach-Object {
        $resources = Get-OptionalProperty -InputObject $_ -Name 'Resources'
        [ordered]@{
            initialDetectionTime = Convert-BoundedText (Get-OptionalProperty $_ 'InitialDetectionTime') 1024
            threatId = Convert-BoundedText (Get-OptionalProperty $_ 'ThreatID') 256
            threatStatusId = Convert-BoundedText (Get-OptionalProperty $_ 'ThreatStatusID') 256
            actionSuccess = [bool](Get-OptionalProperty $_ 'ActionSuccess')
            resources = Convert-BoundedText (($resources | ForEach-Object { [string]$_ }) -join ';') $maxTextChars
        }
    })
}
$networkAdapters = Invoke-Channel -Channel 'network-adapters' -DefaultValue @() -Body {
    @(Get-NetAdapter -IncludeHidden | Select-Object -First $maxRecordEntries | ForEach-Object {
        [ordered]@{
            name = Convert-BoundedText (Get-OptionalProperty $_ 'Name') 1024
            interfaceDescription = Convert-BoundedText (Get-OptionalProperty $_ 'InterfaceDescription') 2048
            status = Convert-BoundedText (Get-OptionalProperty $_ 'Status') 256
            macAddress = Convert-BoundedText (Get-OptionalProperty $_ 'MacAddress') 256
        }
    })
}

$result = [ordered]@{
    schemaVersion = 1
    kind = 'ordivon.security.windows-installer-observation'
    phase = $Phase
    capturedAtUtc = [DateTime]::UtcNow.ToString('o')
    computerName = $env:COMPUTERNAME
    limits = [ordered]@{
        maxFileEntries = $MaxFileEntries
        maxEventEntries = $MaxEventEntries
        maxRecordEntries = $maxRecordEntries
        maxTextChars = $maxTextChars
    }
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
    ($result | ConvertTo-Json -Depth 8 -Compress) + "`n",
    [System.Text.UTF8Encoding]::new($false)
)
Move-Item -LiteralPath $temporary -Destination $OutputPath -Force
