param(
    [string]$Root = (Get-Location).Path,

    [string]$Executable = "",

    [string]$OutputDirectory = "",

    [ValidateSet("Quick", "Default", "Deep")]
    [string]$Mode = "Deep",

    [ValidateRange(1, 20)]
    [int]$Count = 1,

    [ValidateRange(60, 3600)]
    [int]$TimeoutSeconds = 1200,

    [switch]$EnableThreatIntel,

    [switch]$RequireClean,

    [switch]$NoElevation,

    [string]$ElevationStatusPath = ""
)

$ErrorActionPreference = "Stop"

trap
{
    if ($NoElevation -and
        -not [string]::IsNullOrWhiteSpace(
            $ElevationStatusPath))
    {
        try
        {
            @(
                "status=failed",
                "message=$($_.Exception.Message)",
                "position=$($_.InvocationInfo.PositionMessage)"
            ) | Set-Content -LiteralPath $ElevationStatusPath -Encoding UTF8
        }
        catch
        {
        }
    }
    exit 1
}

function Test-IsAdministrator
{
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Quote-ProcessArgument
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    if ($Value -notmatch '[\s"]')
    {
        return $Value
    }

    return '"' + ($Value -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"'
}

function Enter-KnLiveDbgHuntRunnerMutex
{
    $mutex = $null
    try
    {
        $mutex = [System.Threading.Mutex]::new(
            $false,
            "Global\KnLiveDbg-Hunt-Runner-v1")
        $acquired = $false
        try
        {
            $acquired = $mutex.WaitOne(0)
        }
        catch [System.Threading.AbandonedMutexException]
        {
            $acquired = $true
        }

        if (-not $acquired)
        {
            throw "another KnLiveDbg hunt runner is active on this machine"
        }

        return $mutex
    }
    catch
    {
        if ($null -ne $mutex)
        {
            $mutex.Dispose()
        }
        throw
    }
}

function Exit-KnLiveDbgHuntRunnerMutex
{
    param(
        [Parameter(Mandatory = $true)]
        [System.Threading.Mutex]$Mutex
    )

    try
    {
        [void]$Mutex.ReleaseMutex()
    }
    finally
    {
        $Mutex.Dispose()
    }
}

function Remove-KnLiveDbgService
{
    $service = Get-Service -Name "KnLiveDbg" -ErrorAction SilentlyContinue
    if ($null -eq $service)
    {
        return
    }

    Write-Warning "[hunt-clean] exact cleanup for KnLiveDbg service state=$($service.Status)"
    if ($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped)
    {
        & sc.exe stop KnLiveDbg | Out-Host
    }
    & sc.exe delete KnLiveDbg | Out-Host

    for ($attempt = 0; $attempt -lt 100; ++$attempt)
    {
        if ($null -eq (Get-Service -Name "KnLiveDbg" -ErrorAction SilentlyContinue))
        {
            return
        }
        Start-Sleep -Milliseconds 100
    }

    throw "KnLiveDbg service could not be removed by exact cleanup"
}

if ($RequireClean -and
    $Mode -eq "Deep" -and
    -not $EnableThreatIntel)
{
    throw "-RequireClean with -Mode Deep requires -EnableThreatIntel"
}

$rootPath = (Resolve-Path -LiteralPath $Root).Path
if ([string]::IsNullOrWhiteSpace($Executable))
{
    $Executable = Join-Path $rootPath "x64\Release\KnLiveDbg.exe"
}
elseif (-not [System.IO.Path]::IsPathRooted($Executable))
{
    $Executable = Join-Path $rootPath $Executable
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory))
{
    $OutputDirectory = Join-Path $rootPath ".build\hunt-clean-host"
}
elseif (-not [System.IO.Path]::IsPathRooted($OutputDirectory))
{
    $OutputDirectory = Join-Path $rootPath $OutputDirectory
}

$executablePath = [System.IO.Path]::GetFullPath($Executable)
$outputPath = [System.IO.Path]::GetFullPath($OutputDirectory)

if (-not (Test-IsAdministrator))
{
    if ($NoElevation)
    {
        throw "administrator rights are required"
    }

    New-Item -ItemType Directory -Force -Path $outputPath |
        Out-Null
    $elevationStatusPath = Join-Path $outputPath "elevation-status.log"
    Remove-Item -LiteralPath $elevationStatusPath -Force -ErrorAction SilentlyContinue

    $arguments = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", (Quote-ProcessArgument -Value $PSCommandPath),
        "-Root", (Quote-ProcessArgument -Value $rootPath),
        "-Executable", (Quote-ProcessArgument -Value $executablePath),
        "-OutputDirectory", (Quote-ProcessArgument -Value $outputPath),
        "-Mode", $Mode,
        "-Count", [string]$Count,
        "-TimeoutSeconds", [string]$TimeoutSeconds,
        "-NoElevation",
        "-ElevationStatusPath", (Quote-ProcessArgument -Value $elevationStatusPath)
    )
    if ($EnableThreatIntel)
    {
        $arguments += "-EnableThreatIntel"
    }
    if ($RequireClean)
    {
        $arguments += "-RequireClean"
    }

    Write-Host "[hunt-clean] requesting UAC elevation"
    $child = Start-Process -FilePath "powershell.exe" `
        -ArgumentList ($arguments -join " ") `
        -Verb RunAs `
        -WindowStyle Hidden `
        -Wait `
        -PassThru
    try
    {
        $child.WaitForExit()
        $childExitCode = [int]$child.ExitCode
    }
    finally
    {
        $child.Dispose()
    }
    if ($childExitCode -ne 0 -and
        (Test-Path -LiteralPath $elevationStatusPath -PathType Leaf))
    {
        Write-Host "[hunt-clean] elevated child failure:"
        Write-Host (
            Get-Content `
                -LiteralPath $elevationStatusPath `
                -Raw)
    }
    exit $childExitCode
}

if (-not (Test-Path -LiteralPath $executablePath))
{
    throw "KnLiveDbg executable not found: $executablePath"
}

New-Item -ItemType Directory -Force -Path $outputPath | Out-Null
$runnerLockPath = Join-Path $outputPath ".runner.lock"
$runnerLock = $null
try
{
    $runnerLock = [System.IO.File]::Open(
        $runnerLockPath,
        [System.IO.FileMode]::OpenOrCreate,
        [System.IO.FileAccess]::ReadWrite,
        [System.IO.FileShare]::None)
}
catch
{
    throw "another clean-host runner owns the output directory: $outputPath"
}

$machineRunMutex = $null
try
{
    $machineRunMutex = Enter-KnLiveDbgHuntRunnerMutex
}
catch
{
    $runnerLock.Dispose()
    $runnerLock = $null
    throw
}

try
{
$validator = Join-Path $rootPath "tools\validate-hunt-clean-host.ps1"
$modeArgument = ""
if ($Mode -eq "Quick")
{
    $modeArgument = " /quick"
}
elseif ($Mode -eq "Deep")
{
    $modeArgument = " /deep"
}

$preexistingService = Get-Service -Name "KnLiveDbg" -ErrorAction SilentlyContinue
if ($null -ne $preexistingService)
{
    throw "refusing to start while a pre-existing KnLiveDbg service is registered: state=$($preexistingService.Status)"
}
$preexistingProcesses = @(
    Get-Process -Name "KnLiveDbg" -ErrorAction SilentlyContinue
)
if ($preexistingProcesses.Count -ne 0)
{
    $processIds =
        @($preexistingProcesses | ForEach-Object { $_.Id }) -join ","
    throw "refusing to start while a pre-existing KnLiveDbg process is running: process_ids=$processIds"
}

for ($run = 1; $run -le $Count; ++$run)
{
    $runText = "{0:D2}" -f $run
    $jsonPath = Join-Path $outputPath "hunt-clean-$($Mode.ToLowerInvariant())-$runText.json"
    $logPath = Join-Path $outputPath "hunt-clean-$($Mode.ToLowerInvariant())-$runText.log"
    $commandPath = Join-Path $outputPath "hunt-clean-$($Mode.ToLowerInvariant())-$runText.commands.txt"
    Remove-Item -LiteralPath $jsonPath, $logPath, $commandPath -Force -ErrorAction SilentlyContinue

    $commands = [System.Collections.Generic.List[string]]::new()
    if ($EnableThreatIntel)
    {
        $commands.Add("write on")
        $commands.Add("set-ppl-antimalware")
        $commands.Add("!ti start")
    }
    $commands.Add("write off")
    $commands.Add("!hunt$modeArgument /summary /json `"$jsonPath`"")
    if ($EnableThreatIntel)
    {
        $commands.Add("!ti stop")
    }
    $commands.Add("unload")
    $commands.Add("exit")
    $commands | Set-Content -LiteralPath $commandPath -Encoding UTF8

    Write-Host "[hunt-clean] start run=$run mode=$Mode ti=$([bool]$EnableThreatIntel)"

    $process = $null
    $stdoutTask = $null
    $stderrTask = $null
    $stdout = ""
    $stderr = ""
    $exitCode = $null
    $exitCodeUnavailable = $false
    $waitCompleted = $false
    $timedOut = $false
    try
    {
        $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $executablePath
        $startInfo.WorkingDirectory = Split-Path -Parent $executablePath
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardInput = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true

        $process = [System.Diagnostics.Process]::new()
        $process.StartInfo = $startInfo
        if (-not $process.Start())
        {
            throw "failed to start KnLiveDbg"
        }

        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        foreach ($command in $commands)
        {
            $process.StandardInput.WriteLine($command)
        }
        $process.StandardInput.Close()

        $waitCompleted =
            $process.WaitForExit($TimeoutSeconds * 1000)
        $timedOut = -not $waitCompleted
        if ($timedOut)
        {
            try
            {
                if (-not $process.HasExited)
                {
                    $process.Kill()
                }
            }
            catch [System.InvalidOperationException]
            {
            }
            $waitCompleted = $process.WaitForExit(10000)
            if (-not $waitCompleted)
            {
                throw "KnLiveDbg remained alive for 10 seconds after exact-PID termination; run=$run log=$logPath"
            }
            throw "KnLiveDbg timed out after $TimeoutSeconds seconds; run=$run log=$logPath"
        }

        try
        {
            $exitCode = [int]$process.ExitCode
        }
        catch
        {
            if (-not $EnableThreatIntel)
            {
                throw
            }
            # set-ppl-antimalware can make the unprotected runner lose
            # PROCESS_QUERY_INFORMATION on the already-started child.  In
            # that case WaitForExit, fresh JSON validation, and exact service
            # cleanup remain the completion gates.
            $exitCodeUnavailable = $true
            Write-Warning "[hunt-clean] exit code unavailable after PPL transition; using artifact and cleanup gates"
        }
        if ($null -ne $exitCode -and $exitCode -ne 0)
        {
            throw "KnLiveDbg failed with exit code $exitCode; log=$logPath"
        }
        if (-not (Test-Path -LiteralPath $jsonPath -PathType Leaf))
        {
            throw "hunt JSON was not created; log=$logPath"
        }

        $serviceRemoved = $false
        for ($attempt = 0; $attempt -lt 50; ++$attempt)
        {
            if ($null -eq (Get-Service -Name "KnLiveDbg" -ErrorAction SilentlyContinue))
            {
                $serviceRemoved = $true
                break
            }
            Start-Sleep -Milliseconds 100
        }
        if (-not $serviceRemoved)
        {
            throw "KnLiveDbg service still exists after run=$run; log=$logPath"
        }

        if ($RequireClean)
        {
            $validatorArguments = @(
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-File", $validator,
                "-HuntJson", $jsonPath,
                "-RequireMode", $Mode
            )
            if ($EnableThreatIntel)
            {
                $validatorArguments +=
                    "-RequireThreatIntelActive"
            }
            & powershell.exe @validatorArguments
            if ($LASTEXITCODE -ne 0)
            {
                throw "clean-host validation failed; json=$jsonPath log=$logPath"
            }
        }

        $document = Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json
        Write-Host "[hunt-clean] complete run=$run findings=$($document.summary.findings) coverage_complete=$($document.summary.coverage_complete)"
        Write-Host "[hunt-clean] json=$jsonPath"
        Write-Host "[hunt-clean] log=$logPath"
    }
    finally
    {
        $cleanupFailures = [System.Collections.Generic.List[string]]::new()
        $canCaptureOutput = $false
        if ($null -ne $process)
        {
            try
            {
                if (-not $waitCompleted -and
                    -not $process.HasExited)
                {
                    Write-Warning "[hunt-clean] stopping exact KnLiveDbg process pid=$($process.Id)"
                    $process.Kill()
                    $waitCompleted =
                        $process.WaitForExit(10000)
                    if (-not $waitCompleted)
                    {
                        throw "process did not exit within 10 seconds"
                    }
                }
                if (-not $waitCompleted)
                {
                    $process.WaitForExit()
                    $waitCompleted = $true
                }
                if ($null -eq $exitCode -and
                    -not $exitCodeUnavailable)
                {
                    try
                    {
                        $exitCode = [int]$process.ExitCode
                    }
                    catch
                    {
                        if (-not $EnableThreatIntel)
                        {
                            throw
                        }
                        $exitCodeUnavailable = $true
                    }
                }
                $canCaptureOutput = $true
            }
            catch
            {
                $cleanupFailures.Add("KnLiveDbg process cleanup failed: $($_.Exception.Message)")
                try
                {
                    $canCaptureOutput = $process.HasExited
                }
                catch
                {
                    $canCaptureOutput = $false
                }
            }

            try
            {
                if ($canCaptureOutput -and $null -ne $stdoutTask)
                {
                    $stdout = $stdoutTask.GetAwaiter().GetResult()
                }
                if ($canCaptureOutput -and $null -ne $stderrTask)
                {
                    $stderr = $stderrTask.GetAwaiter().GetResult()
                }
            }
            catch
            {
                $cleanupFailures.Add("KnLiveDbg output capture failed: $($_.Exception.Message)")
            }

            try
            {
                $process.Dispose()
            }
            catch
            {
                $cleanupFailures.Add("KnLiveDbg process handle disposal failed: $($_.Exception.Message)")
            }
        }

        try
        {
            $loggedExitCode = if ($exitCodeUnavailable) { "<unavailable-ppl>" } elseif ($null -eq $exitCode) { "<unavailable>" } else { [string]$exitCode }
            @(
                "exit_code=$loggedExitCode",
                "timed_out=$timedOut",
                "mode=$Mode",
                "threat_intel=$([bool]$EnableThreatIntel)",
                "",
                "[stdout]",
                $stdout,
                "",
                "[stderr]",
                $stderr
            ) | Set-Content -LiteralPath $logPath -Encoding UTF8
        }
        catch
        {
            $cleanupFailures.Add("run log write failed: $($_.Exception.Message)")
        }

        try
        {
            if ($null -ne (Get-Service -Name "KnLiveDbg" -ErrorAction SilentlyContinue))
            {
                Remove-KnLiveDbgService
            }
        }
        catch
        {
            $cleanupFailures.Add("KnLiveDbg service cleanup failed: $($_.Exception.Message)")
        }

        if ($cleanupFailures.Count -ne 0)
        {
            throw ($cleanupFailures -join "; ")
        }
    }
}
}
finally
{
    try
    {
        if ($null -ne $runnerLock)
        {
            $runnerLock.Dispose()
            $runnerLock = $null
        }
    }
    finally
    {
        if ($null -ne $machineRunMutex)
        {
            Exit-KnLiveDbgHuntRunnerMutex -Mutex $machineRunMutex
            $machineRunMutex = $null
        }
    }
}

Write-Host "[hunt-clean] all runs completed"
if ($NoElevation -and
    -not [string]::IsNullOrWhiteSpace(
        $ElevationStatusPath))
{
    @(
        "status=success",
        "runs=$Count",
        "mode=$Mode",
        "threat_intel=$([bool]$EnableThreatIntel)"
    ) | Set-Content -LiteralPath $ElevationStatusPath -Encoding UTF8
}
exit 0
