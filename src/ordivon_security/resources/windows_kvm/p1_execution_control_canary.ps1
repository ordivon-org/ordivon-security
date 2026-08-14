param(
    [Parameter(Mandatory = $true)][string]$SelfPath,
    [Parameter(Mandatory = $true)][string]$ResultPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$allowedRoot = 'C:\ProgramData\Ordivon\P1PolicyAllowed'
$blockedRoot = Join-Path $env:TEMP '目标产品B '
$nestedRoot = Join-Path $blockedRoot 'nested'
$allowedExe = Join-Path $allowedRoot 'allowed-child.exe'
$blockedExe = Join-Path $blockedRoot 'blocked-child.exe'
$nestedBlockedExe = Join-Path $nestedRoot 'nested-blocked-child.exe'
$allowedMarker = Join-Path $allowedRoot 'allowed.marker'
$blockedMarker = Join-Path $blockedRoot 'blocked.marker'
$nestedBlockedMarker = Join-Path $nestedRoot 'nested-blocked.marker'
$rootWriteProbe = Join-Path $blockedRoot 'write-probe.txt'
$nestedWriteProbe = Join-Path $nestedRoot 'nested-write-probe.txt'
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$currentSid = $identity.User.Value

$result = [ordered]@{
    schemaVersion = 1
    kind = 'ordivon.security.p1-execution-control-canary-result'
    fixtureId = 'ordivon-p1-execution-control-canary-v1'
    controlMechanism = 'ntfs-inherited-execute-deny'
    targetSurface = '%TEMP%\目标产品B \**\PE'
    phase = 'created'
    phaseHistory = @('created')
    currentIdentityName = $identity.Name
    currentUserSid = $currentSid
    currentGroupSids = @($identity.Groups | ForEach-Object { $_.Value } | Sort-Object)
    aclApplied = $false
    rootWriteProbeSucceeded = $false
    nestedWriteProbeSucceeded = $false
    blockedFileDenyObserved = $false
    nestedBlockedFileDenyObserved = $false
    allowedChildStarted = $false
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
    selectiveExecutionControl = $false
    networkRequested = $false
    completed = $false
    errorType = $null
    errorMessage = $null
}

function Write-Progress([string]$Phase) {
    $result['phase'] = $Phase
    $result['phaseHistory'] = @($result['phaseHistory']) + $Phase
    $json = $result | ConvertTo-Json -Depth 6 -Compress
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($json + "`n")
    $stream = [System.IO.FileStream]::new(
        $ResultPath,
        [System.IO.FileMode]::Create,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::Read
    )
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally {
        $stream.Dispose()
    }
}

function Test-ExecuteDeny([string]$Path) {
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

function Invoke-BoundedChild([string]$Path, [string]$MarkerPath) {
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

Write-Progress 'started'

try {
    New-Item -ItemType Directory -Path $allowedRoot -Force | Out-Null
    Remove-Item -LiteralPath $blockedRoot -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $blockedRoot -Force | Out-Null
    Remove-Item -LiteralPath $allowedMarker -Force -ErrorAction SilentlyContinue
    Write-Progress 'roots-created'

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
    $rootAcl = Get-Acl -LiteralPath $blockedRoot -ErrorAction Stop
    $null = $rootAcl.AddAccessRule($denyRule)
    Set-Acl -LiteralPath $blockedRoot -AclObject $rootAcl -ErrorAction Stop
    $result.aclApplied = $true
    Write-Progress 'acl-applied'

    Set-Content -LiteralPath $rootWriteProbe -Value 'root-write-ok' -Encoding ASCII -Force
    $result.rootWriteProbeSucceeded = (Test-Path -LiteralPath $rootWriteProbe)
    New-Item -ItemType Directory -Path $nestedRoot -Force | Out-Null
    Set-Content -LiteralPath $nestedWriteProbe -Value 'nested-write-ok' -Encoding ASCII -Force
    $result.nestedWriteProbeSucceeded = (Test-Path -LiteralPath $nestedWriteProbe)
    Write-Progress 'write-probes-completed'

    Copy-Item -LiteralPath $SelfPath -Destination $allowedExe -Force
    Copy-Item -LiteralPath $SelfPath -Destination $blockedExe -Force
    Copy-Item -LiteralPath $SelfPath -Destination $nestedBlockedExe -Force
    $result.blockedFileDenyObserved = Test-ExecuteDeny $blockedExe
    $result.nestedBlockedFileDenyObserved = Test-ExecuteDeny $nestedBlockedExe
    Write-Progress 'fixtures-staged'

    $allowed = Invoke-BoundedChild $allowedExe $allowedMarker
    $result.allowedChildStarted = $allowed.started
    $result.allowedChildCompleted = $allowed.completed
    $result.allowedChildExitCode = $allowed.exitCode
    $result.allowedMarkerPresent = Test-Path -LiteralPath $allowedMarker
    Write-Progress 'allowed-child-observed'

    $blocked = Invoke-BoundedChild $blockedExe $blockedMarker
    $result.blockedChildStartDenied = $blocked.startDenied
    $result.blockedChildCompleted = $blocked.completed
    $result.blockedChildExitCode = $blocked.exitCode
    $result.blockedMarkerPresent = Test-Path -LiteralPath $blockedMarker
    Write-Progress 'blocked-child-observed'

    $nestedBlocked = Invoke-BoundedChild $nestedBlockedExe $nestedBlockedMarker
    $result.nestedBlockedChildStartDenied = $nestedBlocked.startDenied
    $result.nestedBlockedChildCompleted = $nestedBlocked.completed
    $result.nestedBlockedChildExitCode = $nestedBlocked.exitCode
    $result.nestedBlockedMarkerPresent = Test-Path -LiteralPath $nestedBlockedMarker
    Write-Progress 'nested-blocked-child-observed'

    $blockedPrevented = $result.blockedChildStartDenied -or (
        $result.blockedChildCompleted -and
        $null -ne $result.blockedChildExitCode -and
        $result.blockedChildExitCode -ne 0
    )
    $nestedBlockedPrevented = $result.nestedBlockedChildStartDenied -or (
        $result.nestedBlockedChildCompleted -and
        $null -ne $result.nestedBlockedChildExitCode -and
        $result.nestedBlockedChildExitCode -ne 0
    )
    $result.selectiveExecutionControl = [bool](
        $result.aclApplied -and
        $result.rootWriteProbeSucceeded -and
        $result.nestedWriteProbeSucceeded -and
        $result.blockedFileDenyObserved -and
        $result.nestedBlockedFileDenyObserved -and
        $result.allowedChildStarted -and
        $result.allowedChildCompleted -and
        $result.allowedChildExitCode -eq 0 -and
        $result.allowedMarkerPresent -and
        $blockedPrevented -and
        -not $result.blockedMarkerPresent -and
        $nestedBlockedPrevented -and
        -not $result.nestedBlockedMarkerPresent
    )
    $result.completed = $result.selectiveExecutionControl
    Write-Progress 'completed'
} catch {
    $result.errorType = $_.Exception.GetType().FullName
    $result.errorMessage = $_.Exception.Message
    Write-Progress 'error'
}

if (-not $result.completed) {
    exit 71
}
exit 0
