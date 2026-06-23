param(
    [string]$Root = (Get-Location).Path,

    [string]$Configuration = "Release",

    [int]$Seconds = 300,

    [int]$KnLiveDbgTimeoutSeconds = 180,

    [int]$TargetLifetimePaddingSeconds = 60,

    [switch]$Build,

    [switch]$ReuseExistingTarget,

    [string]$ExistingStopEventName = "",

    [string]$ArticleHtml = "",

    [string]$ArticleUrl = "",

    [string]$ArticleOutPath = ""
)

$ErrorActionPreference = "Stop"
$script:EsetHuntE2ERunnerContract = "e2e-auto-knlivedbg-article-currentness-v2"
$script:EsetHuntE2EExpectedScenarios = 35
$script:RunnerLogPath = $null

function Write-RunnerMessage
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host $Message
    if (-not [string]::IsNullOrWhiteSpace($script:RunnerLogPath))
    {
        Add-Content -LiteralPath $script:RunnerLogPath -Encoding UTF8 -Value $Message
    }
}

function Test-IsAdministrator
{
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function New-DirectoryIfMissing
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path))
    {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
}

function ConvertTo-ProcessArgument
{
    param(
        [AllowNull()]
        [string]$Value
    )

    if ($null -eq $Value)
    {
        return '""'
    }
    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]')
    {
        return $Value
    }

    $escaped = $Value -replace '(\\*)"', '$1$1\"'
    $escaped = $escaped -replace '(\\+)$', '$1$1'
    return '"' + $escaped + '"'
}

function ConvertTo-ProcessArguments
{
    param(
        [string[]]$Arguments = @()
    )

    $escaped = @()
    foreach ($argument in $Arguments)
    {
        $escaped += ConvertTo-ProcessArgument -Value $argument
    }

    return ($escaped -join ' ')
}

function Wait-JsonScenarioCount
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [int]$ExpectedCount,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutSeconds,

        [object]$MonitoredProcess,

        [string]$MonitoredProcessName = "process"
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $lastCount = -1
    $lastError = ""
    $lastProgressUtc = [DateTime]::MinValue
    while ([DateTime]::UtcNow -lt $deadline)
    {
        if ($null -ne $MonitoredProcess)
        {
            try
            {
                $MonitoredProcess.Refresh()
                if ($MonitoredProcess.HasExited)
                {
                    throw "$MonitoredProcessName exited before manifest reached $ExpectedCount scenarios: exit_code=$($MonitoredProcess.ExitCode) path=$Path last_count=$lastCount last_error=$lastError"
                }
            }
            catch
            {
                if ($_.Exception.Message -like "$MonitoredProcessName exited before manifest*")
                {
                    throw
                }
            }
        }

        if (Test-Path -LiteralPath $Path)
        {
            try
            {
                $doc = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
                $count = @($doc.scenarios).Count
                if ($count -ne $lastCount)
                {
                    Write-RunnerMessage "[eset-hunt-e2e] manifest_progress scenarios=$count expected=$ExpectedCount path=$Path"
                    $lastProgressUtc = [DateTime]::UtcNow
                }
                $lastCount = $count
                if ($count -eq $ExpectedCount)
                {
                    return
                }
                if ($count -gt $ExpectedCount)
                {
                    throw "manifest has more scenarios than expected: count=$count expected=$ExpectedCount path=$Path"
                }
            }
            catch
            {
                if ($_.Exception.Message -like "manifest has more scenarios than expected*")
                {
                    throw
                }
                $lastError = $_.Exception.Message
                if ([DateTime]::UtcNow -gt $lastProgressUtc.AddSeconds(5))
                {
                    Write-RunnerMessage "[eset-hunt-e2e] manifest_progress error=$lastError path=$Path"
                    $lastProgressUtc = [DateTime]::UtcNow
                }
            }
        }

        Start-Sleep -Milliseconds 250
    }

    $hint = ""
    if ($lastCount -eq ($ExpectedCount - 1))
    {
        $hint = " hint=manifest_stopped_one_short; check that the VM uses the latest bundle and latest KnLiveDbgHuntTarget.exe"
    }

    throw "manifest did not reach $ExpectedCount scenarios within $TimeoutSeconds seconds: $Path last_count=$lastCount last_error=$lastError$hint"
}

function Write-BundleInfoStatus
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$RootPath,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedRunnerContract
    )

    $bundleInfoPath = Join-Path $RootPath "BUNDLE-INFO.json"
    if (-not (Test-Path -LiteralPath $bundleInfoPath))
    {
        Write-RunnerMessage "[eset-hunt-e2e] bundle_info=missing path=$bundleInfoPath"
        return
    }

    $bundleInfo = $null
    try
    {
        $bundleInfo = Get-Content -LiteralPath $bundleInfoPath -Raw | ConvertFrom-Json
    }
    catch
    {
        throw "failed to parse BUNDLE-INFO.json: $bundleInfoPath error=$($_.Exception.Message)"
    }

    $bundleContract = [string]$bundleInfo.bundle_contract
    $runnerContract = [string]$bundleInfo.runner_contract
    $gitCommit = [string]$bundleInfo.git_commit
    Write-RunnerMessage "[eset-hunt-e2e] bundle_info=present bundle_contract=$bundleContract runner_contract=$runnerContract git_commit=$gitCommit"

    if ([string]::IsNullOrWhiteSpace($runnerContract))
    {
        throw "BUNDLE-INFO.json has no runner_contract: $bundleInfoPath"
    }
    if ($runnerContract -ne $ExpectedRunnerContract)
    {
        throw "BUNDLE-INFO runner_contract mismatch: bundle=$runnerContract script=$ExpectedRunnerContract path=$bundleInfoPath"
    }
}

function Write-TextFileTail
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Label,

        [int]$Lines = 80
    )

    if (Test-Path -LiteralPath $Path)
    {
        Write-RunnerMessage "[eset-hunt-e2e] tail $Label path=$Path"
        Get-Content -LiteralPath $Path -Tail $Lines -ErrorAction SilentlyContinue | Out-Host
    }
    else
    {
        Write-RunnerMessage "[eset-hunt-e2e] tail $Label path=$Path missing=yes"
    }
}

function Write-ProcessSnapshot
{
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Names
    )

    foreach ($name in $Names)
    {
        $processes = @(Get-Process -Name $name -ErrorAction SilentlyContinue)
        if ($processes.Count -eq 0)
        {
            Write-RunnerMessage "[eset-hunt-e2e] process_snapshot name=$name count=0"
            continue
        }

        foreach ($process in $processes)
        {
            $path = ""
            try
            {
                $path = [string]$process.Path
            }
            catch
            {
                $path = "<unavailable>"
            }

            Write-RunnerMessage "[eset-hunt-e2e] process_snapshot name=$name pid=$($process.Id) path=$path"
        }
    }
}

function Start-ProcessWithRedirects
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [string[]]$Arguments = @(),

        [string]$StandardInputPath,

        [Parameter(Mandatory = $true)]
        [string]$StandardOutputPath,

        [Parameter(Mandatory = $true)]
        [string]$StandardErrorPath
    )

    $argumentText = ConvertTo-ProcessArguments -Arguments $Arguments
    $startParams = @{
        FilePath = $FilePath
        WorkingDirectory = Split-Path -Parent $FilePath
        RedirectStandardOutput = $StandardOutputPath
        RedirectStandardError = $StandardErrorPath
        WindowStyle = "Hidden"
        PassThru = $true
    }

    if (-not [string]::IsNullOrWhiteSpace($argumentText))
    {
        $startParams["ArgumentList"] = $argumentText
    }

    if (-not [string]::IsNullOrWhiteSpace($StandardInputPath))
    {
        $startParams["RedirectStandardInput"] = $StandardInputPath
    }

    $process = Start-Process @startParams
    if ($null -eq $process)
    {
        throw "failed to start process: $FilePath"
    }

    return [pscustomobject]@{
        Process = $process
        OutputWriter = $null
        ErrorWriter = $null
    }
}

function Close-ProcessHandle
{
    param(
        [object]$Handle
    )

    if ($null -eq $Handle)
    {
        return
    }

    if ($null -ne $Handle.Process)
    {
        try
        {
            if ($Handle.Process.HasExited)
            {
                $Handle.Process.WaitForExit()
            }
        }
        catch
        {
        }
    }

    if ($null -ne $Handle.OutputWriter)
    {
        $Handle.OutputWriter.Dispose()
    }
    if ($null -ne $Handle.ErrorWriter)
    {
        $Handle.ErrorWriter.Dispose()
    }
    if ($null -ne $Handle.Process)
    {
        $Handle.Process.Dispose()
    }
}

function Resolve-OptionalRootedPath
{
    param(
        [string]$RootPath,

        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path))
    {
        return ""
    }

    if ([System.IO.Path]::IsPathRooted($Path))
    {
        return $Path
    }

    return (Join-Path $RootPath $Path)
}

$rootPath = (Resolve-Path -LiteralPath $Root).Path
$useArticleCurrentnessValidation = (-not [string]::IsNullOrWhiteSpace($ArticleHtml)) -or (-not [string]::IsNullOrWhiteSpace($ArticleUrl))
$resolvedArticleHtml = Resolve-OptionalRootedPath -RootPath $rootPath -Path $ArticleHtml
$resolvedArticleOutPath = Resolve-OptionalRootedPath -RootPath $rootPath -Path $ArticleOutPath

$outputDir = Join-Path $rootPath ".build\eset-hunt-e2e"
New-DirectoryIfMissing -Path $outputDir
if ($useArticleCurrentnessValidation -and
    -not [string]::IsNullOrWhiteSpace($ArticleUrl) -and
    [string]::IsNullOrWhiteSpace($resolvedArticleHtml) -and
    [string]::IsNullOrWhiteSpace($resolvedArticleOutPath))
{
    $resolvedArticleOutPath = Join-Path $outputDir "eset-article-current.html"
}

$manifest = Join-Path $outputDir "hunt-target-manifest.json"
$huntJson = Join-Path $outputDir "hunt.json"
$targetOut = Join-Path $outputDir "target.stdout.log"
$targetErr = Join-Path $outputDir "target.stderr.log"
$knOut = Join-Path $outputDir "knlivedbg.stdout.log"
$knErr = Join-Path $outputDir "knlivedbg.stderr.log"
$commands = Join-Path $outputDir "knlivedbg.commands.txt"
$validatorLog = Join-Path $outputDir "validator.log"
$articleValidatorLog = Join-Path $outputDir "article-validator.log"
$runnerLog = Join-Path $outputDir "runner.log"
$script:RunnerLogPath = $runnerLog

if ($ReuseExistingTarget)
{
    Remove-Item -LiteralPath $huntJson, $knOut, $knErr, $commands, $validatorLog, $articleValidatorLog, $runnerLog -Force -ErrorAction SilentlyContinue
}
else
{
    Remove-Item -LiteralPath $manifest, $huntJson, $targetOut, $targetErr, $knOut, $knErr, $commands, $validatorLog, $articleValidatorLog, $runnerLog -Force -ErrorAction SilentlyContinue
}

$isAdministrator = Test-IsAdministrator
Write-RunnerMessage "[eset-hunt-e2e] runner_contract=$script:EsetHuntE2ERunnerContract"
Write-RunnerMessage "[eset-hunt-e2e] root=$rootPath configuration=$Configuration reuse_existing_target=$($ReuseExistingTarget.IsPresent) elevated=$isAdministrator powershell=$($PSVersionTable.PSVersion)"
Write-RunnerMessage "[eset-hunt-e2e] output_dir=$outputDir runner_log=$runnerLog"
Write-RunnerMessage "[eset-hunt-e2e] expected_scenarios=$script:EsetHuntE2EExpectedScenarios"
Write-BundleInfoStatus -RootPath $rootPath -ExpectedRunnerContract $script:EsetHuntE2ERunnerContract
if ($useArticleCurrentnessValidation)
{
    Write-RunnerMessage "[eset-hunt-e2e] article_currentness=enabled article_url=$ArticleUrl article_html=$resolvedArticleHtml article_out=$resolvedArticleOutPath"
}

if (-not $isAdministrator)
{
    if ($ReuseExistingTarget)
    {
        $adminError = "administrator rights are required for -ReuseExistingTarget because the live KnLiveDbg hunt must open the kernel driver device"
        Write-RunnerMessage "[eset-hunt-e2e] failed: $adminError"
        throw $adminError
    }

    $adminError = "administrator rights are required for the live ESET hunt E2E because the driver-service fixture creates SCM SERVICE_KERNEL_DRIVER records and KnLiveDbg must open the kernel driver device"
    Write-RunnerMessage "[eset-hunt-e2e] failed: $adminError"
    throw $adminError
}

if (-not $ReuseExistingTarget -and $Seconds -lt 30)
{
    throw "-Seconds must be at least 30 so KnLiveDbg can start, scan, and validate while the target remains alive"
}

if ($KnLiveDbgTimeoutSeconds -lt 30)
{
    throw "-KnLiveDbgTimeoutSeconds must be at least 30"
}

if (-not $ReuseExistingTarget -and $TargetLifetimePaddingSeconds -lt 15)
{
    throw "-TargetLifetimePaddingSeconds must be at least 15"
}

$minimumTargetSeconds = $KnLiveDbgTimeoutSeconds + $TargetLifetimePaddingSeconds
if (-not $ReuseExistingTarget -and $Seconds -lt $minimumTargetSeconds)
{
    throw "-Seconds must be at least KnLiveDbgTimeoutSeconds + TargetLifetimePaddingSeconds ($minimumTargetSeconds) so the target remains alive throughout !hunt"
}

if ($Build)
{
    & (Join-Path $rootPath "tools\build.ps1") -Configuration $Configuration
    if ($LASTEXITCODE -ne 0)
    {
        throw "build failed with exit code $LASTEXITCODE"
    }
}

$knLiveDbg = Join-Path $rootPath "x64\$Configuration\KnLiveDbg.exe"
$huntTarget = Join-Path $rootPath "x64\$Configuration\tools\KnLiveDbgHuntTarget.exe"
$artifactValidator = Join-Path $rootPath "tools\validate-eset-hunt-e2e-artifacts.ps1"
$iocValidator = Join-Path $rootPath "tools\validate-eset-hunt-iocs.ps1"

if (-not (Test-Path -LiteralPath $knLiveDbg))
{
    throw "KnLiveDbg executable not found: $knLiveDbg"
}
if (-not $ReuseExistingTarget -and -not (Test-Path -LiteralPath $huntTarget))
{
    throw "hunt target executable not found: $huntTarget"
}
if (-not (Test-Path -LiteralPath $artifactValidator))
{
    throw "ESET hunt E2E artifact validator not found: $artifactValidator"
}
if ($useArticleCurrentnessValidation -and -not (Test-Path -LiteralPath $iocValidator))
{
    throw "ESET hunt IOC validator not found: $iocValidator"
}

$stopEventName = ""
$targetStopEvent = $null
if (-not $ReuseExistingTarget)
{
    $stopEventName = "Local\KnLiveDbgHuntE2E-$PID-$([Guid]::NewGuid().ToString('N'))"
    $stopEventCreated = $false
    $targetStopEvent = [System.Threading.EventWaitHandle]::new(
        $false,
        [System.Threading.EventResetMode]::ManualReset,
        $stopEventName,
        [ref]$stopEventCreated)
}

Set-Content -LiteralPath $commands -Encoding ASCII -Value @(
    "!hunt /deep /summary /json `"$huntJson`"",
    "exit"
)

$targetArgs = @(
    "/edr-killer-suffix-name",
    "/oxideharvest-cli",
    "/edr-killer-driver-service",
    "/seconds",
    [string]$Seconds,
    "/stop-event",
    $stopEventName,
    "/manifest",
    $manifest
)
Write-RunnerMessage "[eset-hunt-e2e] commands=$commands"
if (-not $ReuseExistingTarget)
{
    Write-RunnerMessage "[eset-hunt-e2e] target_args=$(ConvertTo-ProcessArguments -Arguments $targetArgs)"
}

$targetHandle = $null
$knHandle = $null
try
{
    if ($ReuseExistingTarget)
    {
        Write-RunnerMessage "[eset-hunt-e2e] reuse existing target manifest=$manifest expected_scenarios=$script:EsetHuntE2EExpectedScenarios"
        if (-not [string]::IsNullOrWhiteSpace($ExistingStopEventName))
        {
            Write-RunnerMessage "[eset-hunt-e2e] existing_stop_event=$ExistingStopEventName"
        }
        else
        {
            Write-RunnerMessage "[eset-hunt-e2e] existing_stop_event=<not provided>; target cleanup remains manual"
        }
    }
    else
    {
        Write-RunnerMessage "[eset-hunt-e2e] start target"
        Write-RunnerMessage "[eset-hunt-e2e] target_seconds=$Seconds kn_timeout_seconds=$KnLiveDbgTimeoutSeconds target_padding_seconds=$TargetLifetimePaddingSeconds"
        Write-RunnerMessage "[eset-hunt-e2e] stop_event=$stopEventName"
        Write-RunnerMessage "[eset-hunt-e2e] target_exe=$huntTarget"
        $targetHandle = Start-ProcessWithRedirects `
            -FilePath $huntTarget `
            -Arguments $targetArgs `
            -StandardOutputPath $targetOut `
            -StandardErrorPath $targetErr
        Write-RunnerMessage "[eset-hunt-e2e] target_pid=$($targetHandle.Process.Id)"
        Write-RunnerMessage "[eset-hunt-e2e] wait target manifest=$manifest expected_scenarios=$script:EsetHuntE2EExpectedScenarios"
    }

    $manifestMonitorProcess = if ($null -ne $targetHandle) { $targetHandle.Process } else { $null }
    Wait-JsonScenarioCount `
        -Path $manifest `
        -ExpectedCount $script:EsetHuntE2EExpectedScenarios `
        -TimeoutSeconds 30 `
        -MonitoredProcess $manifestMonitorProcess `
        -MonitoredProcessName "hunt target"
    Write-RunnerMessage "[eset-hunt-e2e] target ready scenarios=$script:EsetHuntE2EExpectedScenarios"

    Write-RunnerMessage "[eset-hunt-e2e] run KnLiveDbg scripted hunt"
    $knHandle = Start-ProcessWithRedirects `
        -FilePath $knLiveDbg `
        -StandardInputPath $commands `
        -StandardOutputPath $knOut `
        -StandardErrorPath $knErr

    $knProcess = $knHandle.Process
    if (-not $knProcess.WaitForExit($KnLiveDbgTimeoutSeconds * 1000))
    {
        Stop-Process -Id $knProcess.Id -Force -ErrorAction SilentlyContinue
        $knProcess.WaitForExit()
        throw "KnLiveDbg did not exit within $KnLiveDbgTimeoutSeconds seconds; stdout=$knOut stderr=$knErr"
    }
    $knProcess.WaitForExit()
    $knExitCode = $knProcess.ExitCode
    Close-ProcessHandle -Handle $knHandle
    $knHandle = $null

    if ($knExitCode -ne 0)
    {
        Get-Content -LiteralPath $knOut -Tail 80 -ErrorAction SilentlyContinue | Out-Host
        Get-Content -LiteralPath $knErr -Tail 80 -ErrorAction SilentlyContinue | Out-Host
        throw "KnLiveDbg exited with code $knExitCode; stdout=$knOut stderr=$knErr"
    }
    if (-not (Test-Path -LiteralPath $huntJson))
    {
        throw "hunt JSON was not written: $huntJson"
    }

    Write-RunnerMessage "[eset-hunt-e2e] validate ESET hunt artifacts"
    & $artifactValidator `
        -Root $rootPath `
        -Manifest $manifest `
        -HuntJson $huntJson `
        -Stdout $knOut `
        -RunnerLog $runnerLog `
        -ValidatorLog $validatorLog
    if ($LASTEXITCODE -ne 0)
    {
        throw "ESET hunt artifact validation failed with exit code $LASTEXITCODE; validator_log=$validatorLog"
    }

    if ($useArticleCurrentnessValidation)
    {
        Write-RunnerMessage "[eset-hunt-e2e] validate ESET article currentness"
        $articleValidatorArgs = @("-Root", $rootPath)
        if (-not [string]::IsNullOrWhiteSpace($resolvedArticleHtml))
        {
            $articleValidatorArgs += @("-ArticleHtml", $resolvedArticleHtml)
        }
        if (-not [string]::IsNullOrWhiteSpace($ArticleUrl))
        {
            $articleValidatorArgs += @("-ArticleUrl", $ArticleUrl)
        }
        if (-not [string]::IsNullOrWhiteSpace($resolvedArticleOutPath))
        {
            $articleValidatorArgs += @("-ArticleOutPath", $resolvedArticleOutPath)
        }

        & $iocValidator @articleValidatorArgs *> $articleValidatorLog
        if ($LASTEXITCODE -ne 0)
        {
            throw "ESET article currentness validation failed with exit code $LASTEXITCODE; article_validator_log=$articleValidatorLog"
        }
        Write-TextFileTail -Path $articleValidatorLog -Label "article-validator" -Lines 20
    }
}
catch
{
    Write-RunnerMessage "[eset-hunt-e2e] failed: $($_.Exception.Message)"
    Write-RunnerMessage "[eset-hunt-e2e] artifacts output_dir=$outputDir manifest=$manifest hunt_json=$huntJson"
    Write-ProcessSnapshot -Names @("KnLiveDbg", "KnLiveDbgHuntTarget")
    Write-TextFileTail -Path $targetOut -Label "target.stdout"
    Write-TextFileTail -Path $targetErr -Label "target.stderr"
    Write-TextFileTail -Path $knOut -Label "knlivedbg.stdout"
    Write-TextFileTail -Path $knErr -Label "knlivedbg.stderr"
    Write-TextFileTail -Path $validatorLog -Label "validator"
    Write-TextFileTail -Path $articleValidatorLog -Label "article-validator"
    throw
}
finally
{
    if ($null -ne $knHandle)
    {
        Close-ProcessHandle -Handle $knHandle
    }

    $targetProcess = if ($null -ne $targetHandle) { $targetHandle.Process } else { $null }
    if ($null -ne $targetProcess -and -not $targetProcess.HasExited)
    {
        if ($null -ne $targetStopEvent)
        {
            Write-RunnerMessage "[eset-hunt-e2e] signal target cleanup"
            [void]$targetStopEvent.Set()
        }

        Write-RunnerMessage "[eset-hunt-e2e] waiting for target cleanup"
        if (-not $targetProcess.WaitForExit(30000))
        {
            Write-Warning "target process did not exit in time; services may require manual cleanup. pid=$($targetProcess.Id)"
            if (-not [string]::IsNullOrWhiteSpace($script:RunnerLogPath))
            {
                Add-Content -LiteralPath $script:RunnerLogPath -Encoding UTF8 -Value "[eset-hunt-e2e] target cleanup timeout pid=$($targetProcess.Id)"
            }
        }
    }
    if ($null -ne $targetHandle)
    {
        Close-ProcessHandle -Handle $targetHandle
    }
    if ($null -ne $targetStopEvent)
    {
        $targetStopEvent.Dispose()
        $targetStopEvent = $null
    }
    if ($ReuseExistingTarget -and -not [string]::IsNullOrWhiteSpace($ExistingStopEventName))
    {
        $existingStopEvent = $null
        try
        {
            Write-RunnerMessage "[eset-hunt-e2e] signal existing target cleanup"
            $existingStopEvent = [System.Threading.EventWaitHandle]::OpenExisting($ExistingStopEventName)
            [void]$existingStopEvent.Set()
        }
        catch
        {
            Write-RunnerMessage "[eset-hunt-e2e] warning: failed to signal existing stop event: $($_.Exception.Message)"
        }
        finally
        {
            if ($null -ne $existingStopEvent)
            {
                $existingStopEvent.Dispose()
            }
        }
    }
}

Write-RunnerMessage "[eset-hunt-e2e] passed"
Write-RunnerMessage "[eset-hunt-e2e] manifest=$manifest"
Write-RunnerMessage "[eset-hunt-e2e] hunt_json=$huntJson"
Write-RunnerMessage "[eset-hunt-e2e] validator_log=$validatorLog"
if ($useArticleCurrentnessValidation)
{
    Write-RunnerMessage "[eset-hunt-e2e] article_validator_log=$articleValidatorLog"
}
Write-RunnerMessage "[eset-hunt-e2e] runner_log=$runnerLog"
exit 0
