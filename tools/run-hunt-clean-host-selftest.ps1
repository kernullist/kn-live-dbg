param(
    [string]$Root = (Get-Location).Path
)

$ErrorActionPreference = "Stop"

$rootPath = (Resolve-Path -LiteralPath $Root).Path
$runner = Join-Path $rootPath "tools\run-hunt-clean-host.ps1"
$outputPath = Join-Path $rootPath ".build\hunt-clean-host-runner-selftest"
$jsonPath = Join-Path $outputPath "hunt-clean-quick-01.json"
$logPath = Join-Path $outputPath "hunt-clean-quick-01.log"
$commandPath = Join-Path $outputPath "hunt-clean-quick-01.commands.txt"
$outerLog = Join-Path $outputPath "runner-output.log"
$preflightLog = Join-Path $outputPath "deep-ti-preflight.log"
$contentionOutputPath = Join-Path $rootPath ".build\hunt-clean-host-runner-contention-selftest"
$contentionLog = Join-Path $contentionOutputPath "contention.log"
$machineMutexName = "Global\KnLiveDbg-Hunt-Runner-v1"

if ($null -ne (Get-Service -Name "KnLiveDbg" -ErrorAction SilentlyContinue))
{
    throw "self-test requires no pre-existing KnLiveDbg service"
}

New-Item -ItemType Directory -Force -Path $outputPath | Out-Null
Remove-Item -LiteralPath $jsonPath, $logPath, $commandPath, $outerLog, $preflightLog -Force -ErrorAction SilentlyContinue

# Seed the exact file the run would produce.  cmd.exe consumes the command
# stream and exits successfully without creating hunt JSON, so accepting this
# file would prove a stale-artifact false pass.
'{"schema":"stale-sentinel"}' | Set-Content -LiteralPath $jsonPath -Encoding UTF8

$exitCode = 0
try
{
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $runner `
        -Root $rootPath `
        -Executable $env:ComSpec `
        -OutputDirectory $outputPath `
        -Mode Quick `
        -Count 1 `
        -TimeoutSeconds 60 *> $outerLog
    $exitCode = $LASTEXITCODE
}
catch
{
    $exitCode = 1
    $_ | Out-String | Add-Content -LiteralPath $outerLog -Encoding UTF8
}

if ($exitCode -eq 0)
{
    throw "clean-host runner unexpectedly accepted a process that wrote no hunt JSON"
}
if (Test-Path -LiteralPath $jsonPath)
{
    throw "clean-host runner left or accepted the seeded stale hunt JSON: $jsonPath"
}
if (-not (Test-Path -LiteralPath $logPath -PathType Leaf))
{
    throw "clean-host runner did not write its failure log: $logPath"
}
if (-not (Test-Path -LiteralPath $commandPath -PathType Leaf))
{
    throw "clean-host runner did not write its command audit: $commandPath"
}
if ($null -ne (Get-Service -Name "KnLiveDbg" -ErrorAction SilentlyContinue))
{
    throw "clean-host runner self-test left a KnLiveDbg service registered"
}

$preflightExitCode = 0
try
{
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $runner `
        -Root $rootPath `
        -Executable $env:ComSpec `
        -OutputDirectory $outputPath `
        -Mode Deep `
        -Count 1 `
        -TimeoutSeconds 60 `
        -RequireClean `
        -NoElevation *> $preflightLog
    $preflightExitCode = $LASTEXITCODE
}
catch
{
    $preflightExitCode = 1
    $_ | Out-String |
        Add-Content -LiteralPath $preflightLog -Encoding UTF8
}

$preflightOutput =
    Get-Content -LiteralPath $preflightLog -Raw
if ($preflightExitCode -eq 0 -or
    $preflightOutput -notmatch
        "requires -EnableThreatIntel")
{
    throw "clean-host runner did not fail fast when deep clean validation lacked active TI"
}

$esetRunnerText =
    Get-Content -LiteralPath (Join-Path $rootPath "tools\run-eset-hunt-e2e.ps1") -Raw
if ($esetRunnerText -notmatch [regex]::Escape($machineMutexName))
{
    throw "ESET and clean-host runners do not share the machine-wide hunt mutex"
}

New-Item -ItemType Directory -Force -Path $contentionOutputPath | Out-Null
Remove-Item -LiteralPath $contentionLog -Force -ErrorAction SilentlyContinue
$machineMutex = [System.Threading.Mutex]::new($false, $machineMutexName)
$machineMutexOwned = $false
try
{
    try
    {
        $machineMutexOwned = $machineMutex.WaitOne(0)
    }
    catch [System.Threading.AbandonedMutexException]
    {
        $machineMutexOwned = $true
    }
    if (-not $machineMutexOwned)
    {
        throw "self-test could not acquire the machine-wide hunt mutex"
    }

    try
    {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $runner `
            -Root $rootPath `
            -Executable $env:ComSpec `
            -OutputDirectory $contentionOutputPath `
            -Mode Quick `
            -Count 1 `
            -TimeoutSeconds 60 *> $contentionLog
        $contentionExitCode = $LASTEXITCODE
    }
    catch
    {
        $contentionExitCode = 1
        $_ | Out-String |
            Add-Content -LiteralPath $contentionLog -Encoding UTF8
    }
}
finally
{
    if ($machineMutexOwned)
    {
        [void]$machineMutex.ReleaseMutex()
    }
    $machineMutex.Dispose()
}

$contentionOutput = Get-Content -LiteralPath $contentionLog -Raw
if ($contentionExitCode -eq 0 -or
    $contentionOutput -notmatch
        "another KnLiveDbg hunt runner is active")
{
    throw "clean-host runner did not fail closed on machine-wide hunt runner contention"
}

Write-Host "[hunt-clean-runner.selftest] PASS stale JSON was deleted and missing output failed closed"
Write-Host "[hunt-clean-runner.selftest] PASS deep clean validation requires active TI before launch"
Write-Host "[hunt-clean-runner.selftest] PASS clean/ESET runners share a machine-wide contention gate"
Write-Host "[hunt-clean-runner.selftest] log=$logPath"
Write-Host "[hunt-clean-runner.selftest] runner_output=$outerLog"
exit 0
