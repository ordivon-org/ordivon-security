param(
    [Parameter(Mandatory = $true)][string]$ResultPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$observerPath = 'C:\ProgramData\Ordivon\p1-observer.ps1'
$observerDigest = 'sha256:efeb283d513bfa9f59b4869b1b3385dad881013d64cfe65d3344c864879753d0'
$observerBytes = 5527
$observerOutput = "$ResultPath.observer.json"
$stagingRoot = Join-Path $env:TEMP 'DaVinci Resolve'
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
    observerInvoked = $false
    observerOutputPresent = $false
    observerOutputDigest = $null
    observerOutputByteLength = $null
    observerSchemaVerified = $false
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

try {
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

    Remove-Item -LiteralPath $stagingRoot -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $nestedRoot -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $stagingRoot 'probe.txt') -Value 'observer-probe' -Encoding ASCII -Force

    $arguments = @{
        Phase = 'pre'
        OutputPath = $observerOutput
        FileRoots = @($stagingRoot, 'C:\ProgramData\Ordivon')
        MaxFileEntries = 512
        MaxEventEntries = 128
    }
    $result.observerInvoked = $true
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
    if (-not $result.observerSchemaVerified) {
        throw 'P1 Observer output schema is invalid.'
    }
    $result.completed = $true
} catch {
    $result.errorType = $_.Exception.GetType().FullName
    $result.errorMessage = $_.Exception.Message
    $result.scriptStackTrace = $_.ScriptStackTrace
} finally {
    $json = $result | ConvertTo-Json -Depth 8 -Compress
    [System.IO.File]::WriteAllText(
        $ResultPath,
        $json + "`n",
        [System.Text.UTF8Encoding]::new($false)
    )
}

if (-not $result.completed) {
    exit 71
}
exit 0
