$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$volume = Get-Volume -FileSystemLabel 'ORDIVONCFG' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($null -eq $volume -or $null -eq $volume.DriveLetter) {
    throw 'ORDIVONCFG configuration volume is missing.'
}
$sourceRoot = "$($volume.DriveLetter):\"
$programRoot = 'C:\ProgramData\Ordivon'
$setupRoot = 'C:\Windows\Setup\Scripts'
New-Item -ItemType Directory -Path $programRoot -Force | Out-Null
New-Item -ItemType Directory -Path $setupRoot -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $sourceRoot 'guest-runner.ps1') -Destination (Join-Path $programRoot 'guest-runner.ps1') -Force
Copy-Item -LiteralPath (Join-Path $sourceRoot 'base-finalize.ps1') -Destination (Join-Path $programRoot 'base-finalize.ps1') -Force
Copy-Item -LiteralPath (Join-Path $sourceRoot 'SetupComplete.cmd') -Destination (Join-Path $setupRoot 'SetupComplete.cmd') -Force
