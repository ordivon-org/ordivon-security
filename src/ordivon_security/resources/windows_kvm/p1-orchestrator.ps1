param(
    [Parameter(Mandatory = $true)][string]$Manifest,
    [Parameter(Mandatory = $true)][string]$Result,
    [Parameter(Mandatory = $true)][string]$RunId,
    [Parameter(Mandatory = $true)][string]$BindingDigest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$observerPath = 'C:\ProgramData\Ordivon\p1-observer.ps1'
$controlCanaryPath = 'C:\ProgramData\Ordivon\acceptance\p1-execution-control-canary.exe'
$controlCanaryDigest = 'sha256:d29becd1409bab42bbba885b3e6db5623cedaf61d83d6c3b01ed7111e347d655'
$controlCanaryBytes = 27648
$allowedRoot = 'C:\ProgramData\Ordivon\P1OrchestratorAllowed'
$stagingRoot = Join-Path $env:TEMP 'DaVinci Resolve'
$nestedRoot = Join-Path $stagingRoot 'nested'
$allowedExe = Join-Path $allowedRoot 'allowed-child.exe'
$blockedExe = Join-Path $stagingRoot 'blocked-child.exe'
$nestedBlockedExe = Join-Path $nestedRoot 'nested-blocked-child.exe'
$allowedMarker = Join-Path $allowedRoot 'allowed.marker'
$blockedMarker = Join-Path $stagingRoot 'blocked.marker'
$nestedBlockedMarker = Join-Path $nestedRoot 'nested-blocked.marker'
$rootWriteProbe = Join-Path $stagingRoot 'write-probe.txt'
$nestedWriteProbe = Join-Path $nestedRoot 'nested-write-probe.txt'
$preObserverPath = "$Result.pre-observer.json"
$postObserverPath = "$Result.post-observer.json"
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$currentSid = $identity.User.Value

$resultState = [ordered]@{
    schemaVersion = 1
    kind = 'ordivon.security.p1-orchestrator-result'
    runId = $RunId
    action = $null
    bindingDigest = $BindingDigest
    bindingDigestVerified = $false
    manifestRunIdVerified = $false
    manifestSchemaVerified = $false
    currentIdentityName = $identity.Name
    currentUserSid = $currentSid
    systemIdentityVerified = $false
    observerPath = $observerPath
    observerIdentityVerified = $false
    executionControlPath = $controlCanaryPath
    executionControlIdentityVerified = $false
    aclApplied = $false
    rootWriteProbeSucceeded = $false
    nestedWriteProbeSucceeded = $false
    blockedFileDenyObserved = $false
    nestedBlockedFileDenyObserved = $false
    preObserverCompleted = $false
    preObserverDigest = $null
    allowedChildCompleted = $false
    allowedChildExitCode = $null
    allowedMarkerPresent = $false
    blockedChildStartDenied = $false
    blockedChildCompleted = $false
    blockedChildExitCode = $null
    blockedMarkerPresent = $false
    nestedBlockedChildStartDenied = $false
    nestedBlockedChildCompleted = $false
    nestedBlockedChildExitCode = $null
    nestedBlockedMarkerPresent = $false
    postObserverCompleted = $false
    postObserverDigest = $null
    selectiveExecutionControl = $false
    observationSequenceVerified = $false
    networkRequested = $false
    thirdPartySampleExecuted = $false
    completed = $false
    errorType = $null
    errorMessage = $null
}

function Write-AtomicJson {
    param([string]$Path, $Value)
    $temporary = "$Path.partial"
    $json = $Value | ConvertTo-Json -Depth 8 -Compress
    [System.IO.File]::WriteAllText(
        $temporary,
        $json + "`n",
        [System.Text.UTF8Encoding]::new($false)
    )
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Get-Sha256 {
    param([string]$Path)
    return 'sha256:' + (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Test-ExecuteDeny {
    param([string]$Path)
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $rules = $acl.GetAccessRules(
        $true,
        $true,
        [System.Security.Principal.SecurityIdentifier]
    )
    foreach ($rule in $rules) {
        if (
            $rule.IdentityReference.Value -eq $currentSid -and
            $rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny -and
            (($rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::ExecuteFile) -ne 0)
        ) {
            return $true
        }
    }
    return $false
}

function Invoke-BoundedChild {
    param(
        [string]$Path,
        [string]$MarkerPath
    )
    $outcome = [ordered]@{
        startDenied = $false
        started = $false
        completed = $false
        exitCode = $null
    }
    try {
        $process = Start-Process -FilePath $Path `
            -ArgumentList @('--marker', ('"' + $MarkerPath + '"')) `
            -PassThru -WindowStyle Hidden -ErrorAction Stop
        $outcome.started = $true
        $outcome.completed = $process.WaitForExit(10000)
        if ($outcome.completed) {
            $outcome.exitCode = [int]$process.ExitCode
        } else {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
    } catch {
        $outcome.startDenied = $true
    }
    return $outcome
}

function Invoke-Observer {
    param(
        [ValidateSet('pre','post')][string]$Phase,
        [string]$OutputPath
    )
    $arguments = @{
        Phase = $Phase
        OutputPath = $OutputPath
        FileRoots = @($stagingRoot, 'C:\ProgramData\Ordivon')
        MaxFileEntries = 512
        MaxEventEntries = 128
    }
    & $observerPath @arguments
    $observation = Get-Content -LiteralPath $OutputPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (
        $observation.schemaVersion -ne 1 -or
        $observation.kind -ne 'ordivon.security.windows-installer-observation' -or
        $observation.phase -ne $Phase -or
        $observation.readOnlyObserver -ne $true
    ) {
        throw "Observer $Phase result is invalid."
    }
    return Get-Sha256 $OutputPath
}

try {
    if ($BindingDigest -notmatch '^sha256:[0-9a-f]{64}$') {
        throw 'Controller binding digest format is invalid.'
    }
    if (-not (Test-Path -LiteralPath $Manifest -PathType Leaf)) {
        throw 'Bound orchestrator manifest is missing.'
    }
    $actualManifestDigest = Get-Sha256 $Manifest
    if ($actualManifestDigest -ne $BindingDigest) {
        throw 'Orchestrator manifest differs from the Controller binding digest.'
    }
    $resultState.bindingDigestVerified = $true

    $manifestValue = Get-Content -LiteralPath $Manifest -Raw -Encoding UTF8 | ConvertFrom-Json
    if (
        $manifestValue.schemaVersion -ne 1 -or
        $manifestValue.kind -ne 'ordivon.security.p1-orchestrator-manifest' -or
        $manifestValue.action -ne 'maintained-control-self-test'
    ) {
        throw 'Orchestrator manifest schema or action is not admitted.'
    }
    if ([string]$manifestValue.runId -ne $RunId) {
        throw 'Orchestrator manifest runId differs from the Controller runId.'
    }
    if (
        $manifestValue.networkMode -ne 'deny-all-at-hypervisor' -or
        $manifestValue.stagingExecutionControl -ne 'ntfs-inherited-execute-deny' -or
        $manifestValue.executionControlDigest -ne $controlCanaryDigest -or
        $manifestValue.thirdPartySampleExecution -ne $false
    ) {
        throw 'Orchestrator manifest control boundary is not admitted.'
    }
    $resultState.action = [string]$manifestValue.action
    $resultState.manifestRunIdVerified = $true
    $resultState.manifestSchemaVerified = $true

    if ($currentSid -ne 'S-1-5-18') {
        throw 'P1 orchestrator requires the accepted SYSTEM execution identity.'
    }
    $resultState.systemIdentityVerified = $true
    if (-not (Test-Path -LiteralPath $observerPath -PathType Leaf)) {
        throw 'Sealed P1 Observer is missing.'
    }
    $resultState.observerIdentityVerified = $true
    if (-not (Test-Path -LiteralPath $controlCanaryPath -PathType Leaf)) {
        throw 'Sealed execution-control canary is missing.'
    }
    $controlItem = Get-Item -LiteralPath $controlCanaryPath
    if (
        [int64]$controlItem.Length -ne $controlCanaryBytes -or
        (Get-Sha256 $controlCanaryPath) -ne $controlCanaryDigest
    ) {
        throw 'Sealed execution-control canary identity differs.'
    }
    $resultState.executionControlIdentityVerified = $true

    New-Item -ItemType Directory -Path $allowedRoot -Force | Out-Null
    Remove-Item -LiteralPath $stagingRoot -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $stagingRoot -Force | Out-Null
    Remove-Item -LiteralPath $allowedMarker -Force -ErrorAction SilentlyContinue

    $sid = [System.Security.Principal.SecurityIdentifier]::new($currentSid)
    $inheritance = (
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    )
    $denyRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
        $sid,
        [System.Security.AccessControl.FileSystemRights]::ExecuteFile,
        $inheritance,
        [System.Security.AccessControl.PropagationFlags]::InheritOnly,
        [System.Security.AccessControl.AccessControlType]::Deny
    )
    $rootAcl = Get-Acl -LiteralPath $stagingRoot -ErrorAction Stop
    $null = $rootAcl.AddAccessRule($denyRule)
    Set-Acl -LiteralPath $stagingRoot -AclObject $rootAcl -ErrorAction Stop
    $resultState.aclApplied = $true

    Set-Content -LiteralPath $rootWriteProbe -Value 'root-write-ok' -Encoding ASCII -Force
    $resultState.rootWriteProbeSucceeded = Test-Path -LiteralPath $rootWriteProbe
    New-Item -ItemType Directory -Path $nestedRoot -Force | Out-Null
    Set-Content -LiteralPath $nestedWriteProbe -Value 'nested-write-ok' -Encoding ASCII -Force
    $resultState.nestedWriteProbeSucceeded = Test-Path -LiteralPath $nestedWriteProbe

    $resultState.preObserverDigest = Invoke-Observer -Phase pre -OutputPath $preObserverPath
    $resultState.preObserverCompleted = $true

    Copy-Item -LiteralPath $controlCanaryPath -Destination $allowedExe -Force
    Copy-Item -LiteralPath $controlCanaryPath -Destination $blockedExe -Force
    Copy-Item -LiteralPath $controlCanaryPath -Destination $nestedBlockedExe -Force
    $resultState.blockedFileDenyObserved = Test-ExecuteDeny $blockedExe
    $resultState.nestedBlockedFileDenyObserved = Test-ExecuteDeny $nestedBlockedExe

    $allowed = Invoke-BoundedChild -Path $allowedExe -MarkerPath $allowedMarker
    $resultState.allowedChildCompleted = $allowed.completed
    $resultState.allowedChildExitCode = $allowed.exitCode
    $resultState.allowedMarkerPresent = Test-Path -LiteralPath $allowedMarker

    $blocked = Invoke-BoundedChild -Path $blockedExe -MarkerPath $blockedMarker
    $resultState.blockedChildStartDenied = $blocked.startDenied
    $resultState.blockedChildCompleted = $blocked.completed
    $resultState.blockedChildExitCode = $blocked.exitCode
    $resultState.blockedMarkerPresent = Test-Path -LiteralPath $blockedMarker

    $nestedBlocked = Invoke-BoundedChild -Path $nestedBlockedExe -MarkerPath $nestedBlockedMarker
    $resultState.nestedBlockedChildStartDenied = $nestedBlocked.startDenied
    $resultState.nestedBlockedChildCompleted = $nestedBlocked.completed
    $resultState.nestedBlockedChildExitCode = $nestedBlocked.exitCode
    $resultState.nestedBlockedMarkerPresent = Test-Path -LiteralPath $nestedBlockedMarker

    $resultState.postObserverDigest = Invoke-Observer -Phase post -OutputPath $postObserverPath
    $resultState.postObserverCompleted = $true

    $blockedPrevented = $resultState.blockedChildStartDenied -or (
        $resultState.blockedChildCompleted -and
        $null -ne $resultState.blockedChildExitCode -and
        $resultState.blockedChildExitCode -ne 0
    )
    $nestedBlockedPrevented = $resultState.nestedBlockedChildStartDenied -or (
        $resultState.nestedBlockedChildCompleted -and
        $null -ne $resultState.nestedBlockedChildExitCode -and
        $resultState.nestedBlockedChildExitCode -ne 0
    )
    $resultState.selectiveExecutionControl = [bool](
        $resultState.aclApplied -and
        $resultState.rootWriteProbeSucceeded -and
        $resultState.nestedWriteProbeSucceeded -and
        $resultState.blockedFileDenyObserved -and
        $resultState.nestedBlockedFileDenyObserved -and
        $resultState.allowedChildCompleted -and
        $resultState.allowedChildExitCode -eq 0 -and
        $resultState.allowedMarkerPresent -and
        $blockedPrevented -and
        -not $resultState.blockedMarkerPresent -and
        $nestedBlockedPrevented -and
        -not $resultState.nestedBlockedMarkerPresent
    )
    $resultState.observationSequenceVerified = [bool](
        $resultState.preObserverCompleted -and $resultState.postObserverCompleted
    )
    $resultState.completed = [bool](
        $resultState.bindingDigestVerified -and
        $resultState.manifestRunIdVerified -and
        $resultState.manifestSchemaVerified -and
        $resultState.systemIdentityVerified -and
        $resultState.observerIdentityVerified -and
        $resultState.executionControlIdentityVerified -and
        $resultState.selectiveExecutionControl -and
        $resultState.observationSequenceVerified
    )
} catch {
    $resultState.errorType = $_.Exception.GetType().FullName
    $resultState.errorMessage = $_.Exception.Message
} finally {
    try { Write-AtomicJson -Path $Result -Value $resultState } catch {}
}

if (-not $resultState.completed) {
    exit 71
}
exit 0
