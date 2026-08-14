param(
    [Parameter(Mandatory = $true)][string]$ResultPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$observerPath = 'C:\ProgramData\Ordivon\p1-observer.ps1'
$observerDigest = 'sha256:f66834322288251407cf50dc1f8c0986cb7bb6228f139d69cc128aa8fb421399'
$observerBytes = 14517
$observerOutput = "$ResultPath.observer.json"
$stagingRoot = Join-Path $env:TEMP '目标产品B '
$nestedRoot = Join-Path $stagingRoot 'nested'

$result = [ordered]@{
    schemaVersion = 1
    kind = 'ordivon.security.p1-observer-runtime-probe-result'
    fixtureId = 'ordivon-p1-observer-runtime-probe-v1'
    observerPath = $observerPath
    observerDigest = $null
    observerByteLength = $null
    observerIdentityVerified = $false
    phase = 'pre'
    fileRoots = @($stagingRoot, 'C:\ProgramData\Ordivon')
    maxFileEntries = 512
    maxEventEntries = 128
    stage = 'created'
    stageHistory = @('created')
    preflightErrors = @()
    observerInvoked = $false
    observerOutputPresent = $false
    observerOutputDigest = $null
    observerOutputByteLength = $null
    observerSchemaVerified = $false
    observerDegradedChannelCount = $null
    networkRequested = $false
    thirdPartySampleExecuted = $false
    completed = $false
    errorType = $null
    errorMessage = $null
    scriptStackTrace = $null
}

function Get-Sha256 {
    param([string]$Path)
    return 'sha256:' + (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Write-ProbeState {
    param([string]$Stage)
    $result.stage = $Stage
    $result.stageHistory = @($result.stageHistory) + $Stage
    $json = $result | ConvertTo-Json -Depth 10 -Compress
    [System.IO.File]::WriteAllText(
        $ResultPath,
        $json + "`n",
        [System.Text.UTF8Encoding]::new($false)
    )
}

function Invoke-Preflight {
    param(
        [Parameter(Mandatory = $true)][string]$Channel,
        [Parameter(Mandatory = $true)][scriptblock]$Body
    )
    Write-ProbeState -Stage ("preflight-" + $Channel)
    try {
        & $Body | Out-Null
    } catch {
        $result.preflightErrors = @($result.preflightErrors) + [ordered]@{
            channel = $Channel
            errorType = $_.Exception.GetType().FullName
            errorMessage = $_.Exception.Message
            scriptStackTrace = $_.ScriptStackTrace
        }
    }
    Write-ProbeState -Stage ("preflight-" + $Channel + "-complete")
}

try {
    Write-ProbeState -Stage 'verifying-observer-identity'
    if (-not (Test-Path -LiteralPath $observerPath -PathType Leaf)) {
        throw 'Sealed P1 Observer is missing.'
    }
    $item = Get-Item -LiteralPath $observerPath
    $result.observerByteLength = [int64]$item.Length
    $result.observerDigest = Get-Sha256 $observerPath
    if (
        $result.observerByteLength -ne $observerBytes -or
        $result.observerDigest -ne $observerDigest
    ) {
        throw 'Sealed P1 Observer identity differs.'
    }
    $result.observerIdentityVerified = $true
    Write-ProbeState -Stage 'observer-identity-verified'

    Remove-Item -LiteralPath $stagingRoot -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $nestedRoot -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $stagingRoot 'probe.txt') -Value 'observer-probe' -Encoding ASCII -Force

    Invoke-Preflight -Channel 'files' -Body {
        Get-ChildItem -LiteralPath $stagingRoot -Force -Recurse -File -ErrorAction Stop |
            Select-Object -First 1 | ForEach-Object {
                Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256 | Out-Null
            }
    }
    Invoke-Preflight -Channel 'registry-uninstall' -Body {
        Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' `
            -ErrorAction Stop | Select-Object -First 1 | Out-Null
    }
    Invoke-Preflight -Channel 'registry-startup' -Body {
        Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' `
            -ErrorAction Stop | Select-Object -First 1 | Out-Null
    }
    Invoke-Preflight -Channel 'services' -Body {
        Get-CimInstance Win32_Service -ErrorAction Stop | Select-Object -First 1 | Out-Null
    }
    Invoke-Preflight -Channel 'drivers' -Body {
        Get-CimInstance Win32_SystemDriver -ErrorAction Stop | Select-Object -First 1 | Out-Null
    }
    Invoke-Preflight -Channel 'scheduled-tasks' -Body {
        Get-ScheduledTask -ErrorAction Stop | Select-Object -First 1 | Out-Null
    }
    Invoke-Preflight -Channel 'bits' -Body {
        Get-BitsTransfer -AllUsers -ErrorAction Stop | Select-Object -First 1 | Out-Null
    }
    Invoke-Preflight -Channel 'local-users' -Body {
        Get-LocalUser -ErrorAction Stop | Select-Object -First 1 | Out-Null
    }
    Invoke-Preflight -Channel 'local-groups' -Body {
        Get-LocalGroup -ErrorAction Stop | Select-Object -First 1 | Out-Null
    }
    Invoke-Preflight -Channel 'certificates' -Body {
        Get-ChildItem Cert:\LocalMachine\Root -ErrorAction Stop | Select-Object -First 1 | Out-Null
    }
    Invoke-Preflight -Channel 'defender-status' -Body {
        Get-MpComputerStatus -ErrorAction Stop | Select-Object -First 1 | Out-Null
    }
    Invoke-Preflight -Channel 'defender-threats' -Body {
        Get-MpThreatDetection -ErrorAction Stop | Select-Object -First 1 | Out-Null
    }
    Invoke-Preflight -Channel 'network-adapters' -Body {
        Get-NetAdapter -IncludeHidden -ErrorAction Stop | Select-Object -First 1 | Out-Null
    }
    Invoke-Preflight -Channel 'event-powershell' -Body {
        Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 1 `
            -ErrorAction Stop | Out-Null
    }
    Invoke-Preflight -Channel 'event-task-scheduler' -Body {
        Get-WinEvent -LogName 'Microsoft-Windows-TaskScheduler/Operational' -MaxEvents 1 `
            -ErrorAction Stop | Out-Null
    }
    Invoke-Preflight -Channel 'event-defender' -Body {
        Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -MaxEvents 1 `
            -ErrorAction Stop | Out-Null
    }
    Invoke-Preflight -Channel 'event-system' -Body {
        Get-WinEvent -LogName 'System' -MaxEvents 1 -ErrorAction Stop | Out-Null
    }
    Invoke-Preflight -Channel 'event-application' -Body {
        Get-WinEvent -LogName 'Application' -MaxEvents 1 -ErrorAction Stop | Out-Null
    }

    $arguments = @{
        Phase = 'pre'
        OutputPath = $observerOutput
        FileRoots = @($stagingRoot, 'C:\ProgramData\Ordivon')
        MaxFileEntries = 512
        MaxEventEntries = 128
    }
    $result.observerInvoked = $true
    Write-ProbeState -Stage 'observer-invoked'
    & $observerPath @arguments

    $result.observerOutputPresent = Test-Path -LiteralPath $observerOutput -PathType Leaf
    if (-not $result.observerOutputPresent) {
        throw 'P1 Observer returned without an output file.'
    }
    $outputItem = Get-Item -LiteralPath $observerOutput
    $result.observerOutputByteLength = [int64]$outputItem.Length
    $result.observerOutputDigest = Get-Sha256 $observerOutput
    $observation = Get-Content -LiteralPath $observerOutput -Raw -Encoding UTF8 | ConvertFrom-Json
    $result.observerSchemaVerified = [bool](
        $observation.schemaVersion -eq 1 -and
        $observation.kind -eq 'ordivon.security.windows-installer-observation' -and
        $observation.phase -eq 'pre' -and
        $observation.readOnlyObserver -eq $true
    )
    $result.observerDegradedChannelCount = [int]$observation.degradedChannelCount
    if (-not $result.observerSchemaVerified) {
        throw 'P1 Observer output schema is invalid.'
    }
    $result.completed = $true
    Write-ProbeState -Stage 'completed'
} catch {
    $result.errorType = $_.Exception.GetType().FullName
    $result.errorMessage = $_.Exception.Message
    $result.scriptStackTrace = $_.ScriptStackTrace
    Write-ProbeState -Stage 'error'
}

if (-not $result.completed) {
    exit 71
}
exit 0
