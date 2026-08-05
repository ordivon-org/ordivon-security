$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Write-AtomicUtf8Json {
    param([string]$Path, $Value)
    $temporary = "$Path.partial"
    $json = $Value | ConvertTo-Json -Depth 8 -Compress
    [System.IO.File]::WriteAllText($temporary, $json + "`n", [System.Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Get-OrdivonVolumeRoot {
    param([string]$Label)
    for ($attempt = 0; $attempt -lt 120; $attempt++) {
        $volume = Get-Volume -FileSystemLabel $Label -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -ne $volume -and $null -ne $volume.DriveLetter) {
            return "$($volume.DriveLetter):\"
        }
        Start-Sleep -Seconds 1
    }
    return $null
}

$runRoot = Get-OrdivonVolumeRoot -Label 'ORDIVON_RUN'
if ($null -eq $runRoot) {
    shutdown.exe /s /t 0 /f
    exit 20
}

$logPath = Join-Path $runRoot 'guest-runner.log'
$resultPath = Join-Path $runRoot 'ordivon-result.json'
$manifestPath = Join-Path $runRoot 'ordivon-run.json'
$fixturePath = Join-Path $runRoot 'fixture.exe'
$fixtureResultPath = Join-Path $runRoot 'fixture-result.json'
$manifest = $null

try {
    [System.IO.File]::WriteAllText($logPath, "guest-runner-started`n", [System.Text.UTF8Encoding]::new($false))
    $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($manifest.kind -ne 'ordivon.security.windows-kvm-run' -or $manifest.schemaVersion -ne 1) {
        throw 'Run manifest schema is unsupported.'
    }
    if ($manifest.action -ne 'execute-benign-fixture') {
        throw 'Run action is not admitted by the benign fixture runner.'
    }
    $actualDigest = 'sha256:' + (Get-FileHash -LiteralPath $fixturePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualDigest -ne $manifest.sampleDigest) {
        throw 'Fixture digest differs from the admitted Sample.'
    }

    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Select-Object Name, InterfaceDescription, Status, MacAddress)
    $startedAt = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    $process = Start-Process -FilePath $fixturePath -ArgumentList @('--result', $fixtureResultPath) -PassThru -WindowStyle Hidden
    $completed = $process.WaitForExit([int]$manifest.maxRuntimeMs)
    if (-not $completed) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        throw 'Fixture exceeded the admitted runtime.'
    }
    $endedAt = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    $fixtureResult = Get-Content -LiteralPath $fixtureResultPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($process.ExitCode -ne 0 -or $fixtureResult.completed -ne $true) {
        throw "Fixture failed with exit code $($process.ExitCode)."
    }
    $fixtureResultDigest = 'sha256:' + (Get-FileHash -LiteralPath $fixtureResultPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $result = [ordered]@{
        schemaVersion = 1
        kind = 'ordivon.security.windows-kvm-result'
        runId = [string]$manifest.runId
        sampleDigest = [string]$manifest.sampleDigest
        action = [string]$manifest.action
        status = 'completed'
        processId = [int]$process.Id
        exitCode = [int]$process.ExitCode
        startedAtMs = [int64]$startedAt
        endedAtMs = [int64]$endedAt
        durationMs = [int64]($endedAt - $startedAt)
        networkAdapterCount = [int]$adapters.Count
        networkAdapters = $adapters
        fixtureResultDigest = $fixtureResultDigest
        fixtureResult = $fixtureResult
    }
    Write-AtomicUtf8Json -Path $resultPath -Value $result
    Add-Content -LiteralPath $logPath -Value 'fixture-completed' -Encoding UTF8
    Start-Sleep -Seconds 2
    shutdown.exe /s /t 0 /f
    exit 0
} catch {
    $failure = [ordered]@{
        schemaVersion = 1
        kind = 'ordivon.security.windows-kvm-result'
        runId = if ($null -ne $manifest) { [string]$manifest.runId } else { $null }
        sampleDigest = if ($null -ne $manifest) { [string]$manifest.sampleDigest } else { $null }
        action = if ($null -ne $manifest) { [string]$manifest.action } else { $null }
        status = 'failed'
        errorType = $_.Exception.GetType().FullName
        errorMessage = $_.Exception.Message
    }
    try { Write-AtomicUtf8Json -Path $resultPath -Value $failure } catch {}
    try { Add-Content -LiteralPath $logPath -Value ("failure: " + $_.Exception.Message) -Encoding UTF8 } catch {}
    Start-Sleep -Seconds 2
    shutdown.exe /s /t 0 /f
    exit 1
}
