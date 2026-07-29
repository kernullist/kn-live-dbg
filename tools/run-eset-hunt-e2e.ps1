param(
    [string]$Root = (Get-Location).Path,

    [string]$Configuration = "Release",

    [ValidateRange(30, 86400)]
    [int]$Seconds = 300,

    [ValidateRange(30, 3600)]
    [int]$KnLiveDbgTimeoutSeconds = 180,

    [ValidateRange(15, 3600)]
    [int]$TargetLifetimePaddingSeconds = 60,

    [switch]$Build,

    [switch]$ReuseExistingTarget,

    [string]$ExistingStopEventName = "",

    [string]$OutputDirectory = "",

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

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.WorkingDirectory = Split-Path -Parent $FilePath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.RedirectStandardInput = -not [string]::IsNullOrWhiteSpace($StandardInputPath)
    $argumentText = ConvertTo-ProcessArguments -Arguments $Arguments
    if (-not [string]::IsNullOrWhiteSpace($argumentText))
    {
        $startInfo.Arguments = $argumentText
    }

    $process = [System.Diagnostics.Process]::new()
    $handle = $null
    try
    {
        $process.StartInfo = $startInfo
        if (-not $process.Start())
        {
            throw "failed to start process: $FilePath"
        }

        $handle = [pscustomobject]@{
            Process = $process
            OutputTask = $process.StandardOutput.ReadToEndAsync()
            ErrorTask = $process.StandardError.ReadToEndAsync()
            StandardOutputPath = $StandardOutputPath
            StandardErrorPath = $StandardErrorPath
            OutputCaptured = $false
        }
        if ($startInfo.RedirectStandardInput)
        {
            $process.StandardInput.Write(
                [System.IO.File]::ReadAllText(
                    $StandardInputPath,
                    [System.Text.Encoding]::ASCII))
            $process.StandardInput.Close()
        }

        return $handle
    }
    catch
    {
        $startException = $_
        if ($null -ne $handle)
        {
            try
            {
                Stop-ProcessHandle -Handle $handle -Name ([System.IO.Path]::GetFileName($FilePath))
            }
            catch
            {
            }
        }
        else
        {
            $process.Dispose()
        }
        throw $startException
    }
}

function Complete-ProcessOutput
{
    param(
        [object]$Handle
    )

    if ($null -eq $Handle -or $Handle.OutputCaptured)
    {
        return
    }

    $stdout = $Handle.OutputTask.GetAwaiter().GetResult()
    $stderr = $Handle.ErrorTask.GetAwaiter().GetResult()
    $utf8 = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($Handle.StandardOutputPath, $stdout, $utf8)
    [System.IO.File]::WriteAllText($Handle.StandardErrorPath, $stderr, $utf8)
    $Handle.OutputCaptured = $true
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

    if ($null -ne $Handle.Process)
    {
        if (-not $Handle.Process.HasExited)
        {
            throw "refusing to dispose a live process handle: pid=$($Handle.Process.Id)"
        }
        try
        {
            Complete-ProcessOutput -Handle $Handle
        }
        finally
        {
            $Handle.Process.Dispose()
        }
    }
}

function Stop-ProcessHandle
{
    param(
        [object]$Handle,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [int]$TimeoutMilliseconds = 10000
    )

    if ($null -eq $Handle -or $null -eq $Handle.Process)
    {
        return
    }

    $process = $Handle.Process
    if (-not $process.HasExited)
    {
        $processId = $process.Id
        Write-RunnerMessage "[eset-hunt-e2e] force_stop name=$Name pid=$processId"
        try
        {
            $process.Kill()
        }
        catch [System.InvalidOperationException]
        {
        }
        if (-not $process.WaitForExit($TimeoutMilliseconds))
        {
            throw "$Name process did not exit after exact-PID termination: pid=$processId"
        }
    }
    $process.WaitForExit()
    Close-ProcessHandle -Handle $Handle
}

function Remove-KnLiveDbgService
{
    $service = Get-Service -Name "KnLiveDbg" -ErrorAction SilentlyContinue
    if ($null -eq $service)
    {
        return $false
    }

    Write-RunnerMessage "[eset-hunt-e2e] exact_service_cleanup name=KnLiveDbg state=$($service.Status)"
    if ($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped)
    {
        & sc.exe stop KnLiveDbg | Out-Null
    }
    & sc.exe delete KnLiveDbg | Out-Null

    for ($attempt = 0; $attempt -lt 100; ++$attempt)
    {
        if ($null -eq (Get-Service -Name "KnLiveDbg" -ErrorAction SilentlyContinue))
        {
            return $true
        }
        Start-Sleep -Milliseconds 100
    }
    throw "KnLiveDbg service could not be removed by exact cleanup"
}

function Test-OwnedHuntTargetProcessPath
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$RelativePath,

        [Parameter(Mandatory = $true)]
        [int]$TargetProcessId
    )

    $pidText = [regex]::Escape([string]$TargetProcessId)
    $pattern =
        "^knhunt-$pidText-(GentlemenCollection|WeakVendorControl|SystemCopyControl)\\[^\\]+$"
    return [regex]::IsMatch(
        $RelativePath,
        $pattern,
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
            [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
}

function Test-OwnedHuntTargetEntryPath
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$RelativePath,

        [Parameter(Mandatory = $true)]
        [int]$TargetProcessId
    )

    $pidText = [regex]::Escape([string]$TargetProcessId)
    $pattern =
        "^knhunt-$pidText-(GentlemenCollection|WeakVendorControl|SystemCopyControl)$|" +
        "^knhunt-$pidText-(secimg|stpimg)-[0-9]+-[0-9]+\.dll$"
    return [regex]::IsMatch(
        $RelativePath,
        $pattern,
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
            [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
}

function Remove-OwnedHuntTargetArtifacts
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManifestPath,

        [Parameter(Mandatory = $true)]
        [int]$TargetProcessId
    )

    $cleanupActions = 0
    $cleanupErrors = [System.Collections.Generic.List[string]]::new()
    $manifestDocument = $null
    $ownedPrefix = "knhunt-$TargetProcessId-"
    $servicePrefix = "KnLiveDbgHuntTargetEdrSvc$TargetProcessId" + "_"
    $tempRoot = [System.IO.Path]::GetFullPath(
        [System.IO.Path]::GetTempPath())
    if ($tempRoot.Length -gt 3)
    {
        $tempRoot = $tempRoot.TrimEnd('\')
    }
    $tempRootPrefix = if ($tempRoot.EndsWith('\'))
    {
        $tempRoot
    }
    else
    {
        $tempRoot + "\"
    }

    if (Test-Path -LiteralPath $ManifestPath -PathType Leaf)
    {
        try
        {
            $manifestDocument = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
        }
        catch
        {
            $cleanupErrors.Add("fixture manifest parse failed during cleanup: $($_.Exception.Message)")
        }
    }

    $serviceNames = @()
    if ($null -ne $manifestDocument)
    {
        $serviceNames += @(
            $manifestDocument.scenarios |
                ForEach-Object { [string]$_.expected_evidence.service_name }
        )
    }
    $serviceNames += @(
        Get-Service -Name "$servicePrefix*" -ErrorAction SilentlyContinue |
            ForEach-Object { [string]$_.Name }
    )
    $servicePattern = '^' + [regex]::Escape($servicePrefix) + '[0-9]+$'
    $serviceNames = @(
        $serviceNames |
            Where-Object { $_ -match $servicePattern } |
            Sort-Object -Unique
    )
    foreach ($serviceName in $serviceNames)
    {
        try
        {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($null -eq $service)
            {
                continue
            }

            Write-RunnerMessage "[eset-hunt-e2e] exact_fixture_service_cleanup name=$serviceName state=$($service.Status)"
            if ($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped)
            {
                & sc.exe stop $serviceName | Out-Null
            }
            & sc.exe delete $serviceName | Out-Null
            for ($attempt = 0; $attempt -lt 100; ++$attempt)
            {
                if ($null -eq (Get-Service -Name $serviceName -ErrorAction SilentlyContinue))
                {
                    break
                }
                Start-Sleep -Milliseconds 100
            }
            if ($null -ne (Get-Service -Name $serviceName -ErrorAction SilentlyContinue))
            {
                throw "fixture service could not be removed: $serviceName"
            }
            ++$cleanupActions
        }
        catch
        {
            $cleanupErrors.Add("fixture service cleanup failed name=$serviceName error=$($_.Exception.Message)")
        }
    }

    $childIds = @()
    if ($null -ne $manifestDocument)
    {
        $childIds += @(
            $manifestDocument.scenarios |
                ForEach-Object { $_.pid } |
                Where-Object { $_ -is [int] -or $_ -is [long] } |
                ForEach-Object { [int]$_ }
        )
    }
    foreach ($candidate in @(Get-Process -ErrorAction SilentlyContinue))
    {
        $candidatePath = ""
        try
        {
            $candidatePath = [System.IO.Path]::GetFullPath([string]$candidate.Path)
        }
        catch
        {
        }
        $relativeCandidate = if ($candidatePath.StartsWith($tempRootPrefix, [StringComparison]::OrdinalIgnoreCase))
        {
            $candidatePath.Substring($tempRootPrefix.Length)
        }
        else
        {
            ""
        }
        if (-not [string]::IsNullOrWhiteSpace($relativeCandidate) -and
            (Test-OwnedHuntTargetProcessPath `
                -RelativePath $relativeCandidate `
                -TargetProcessId $TargetProcessId))
        {
            $childIds += [int]$candidate.Id
        }
    }
    $childIds = @(
        $childIds |
            Where-Object { $_ -gt 0 -and $_ -ne $TargetProcessId } |
            Sort-Object -Unique
    )
    foreach ($childId in $childIds)
    {
        try
        {
            $child = Get-Process -Id $childId -ErrorAction SilentlyContinue
            if ($null -eq $child)
            {
                continue
            }

            $childPath = ""
            try
            {
                $childPath = [System.IO.Path]::GetFullPath([string]$child.Path)
            }
            catch
            {
            }
            $relativeChild = if ($childPath.StartsWith($tempRootPrefix, [StringComparison]::OrdinalIgnoreCase))
            {
                $childPath.Substring($tempRootPrefix.Length)
            }
            else
            {
                ""
            }
            if ([string]::IsNullOrWhiteSpace($relativeChild) -or
                -not (Test-OwnedHuntTargetProcessPath `
                    -RelativePath $relativeChild `
                    -TargetProcessId $TargetProcessId))
            {
                Write-RunnerMessage "[eset-hunt-e2e] skip_reused_manifest_pid pid=$childId path=$childPath"
                continue
            }

            Write-RunnerMessage "[eset-hunt-e2e] exact_fixture_child_cleanup pid=$childId path=$childPath"
            Stop-Process -Id $childId -Force -ErrorAction Stop
            Wait-Process -Id $childId -Timeout 10 -ErrorAction SilentlyContinue
            if ($null -ne (Get-Process -Id $childId -ErrorAction SilentlyContinue))
            {
                throw "fixture child process could not be stopped: pid=$childId"
            }
            ++$cleanupActions
        }
        catch
        {
            $cleanupErrors.Add("fixture child cleanup failed pid=$childId error=$($_.Exception.Message)")
        }
    }

    $ownedEntries = @(
        Get-ChildItem -LiteralPath $tempRoot -Filter "$ownedPrefix*" -Force -ErrorAction SilentlyContinue
    )
    foreach ($entry in $ownedEntries)
    {
        try
        {
            $fullPath = [System.IO.Path]::GetFullPath($entry.FullName)
            $relativePath = if ($fullPath.StartsWith($tempRootPrefix, [StringComparison]::OrdinalIgnoreCase))
            {
                $fullPath.Substring($tempRootPrefix.Length)
            }
            else
            {
                ""
            }
            if ([string]::IsNullOrWhiteSpace($relativePath) -or
                -not (Test-OwnedHuntTargetEntryPath `
                    -RelativePath $relativePath `
                    -TargetProcessId $TargetProcessId))
            {
                throw "refusing to remove an artifact outside the exact fixture naming contract: $fullPath"
            }
            if (($entry.Attributes -band
                    [System.IO.FileAttributes]::ReparsePoint) -ne 0)
            {
                throw "refusing to recursively remove a fixture reparse point: $fullPath"
            }

            Write-RunnerMessage "[eset-hunt-e2e] exact_fixture_artifact_cleanup path=$fullPath"
            Remove-Item -LiteralPath $fullPath -Recurse -Force -ErrorAction Stop
            ++$cleanupActions
        }
        catch
        {
            $cleanupErrors.Add("fixture artifact cleanup failed path=$($entry.FullName) error=$($_.Exception.Message)")
        }
    }

    if ($cleanupErrors.Count -ne 0)
    {
        throw ($cleanupErrors -join "; ")
    }
    return $cleanupActions
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
if (-not $ReuseExistingTarget -and
    -not [string]::IsNullOrWhiteSpace($ExistingStopEventName))
{
    throw "-ExistingStopEventName is valid only with -ReuseExistingTarget"
}

$useArticleCurrentnessValidation = (-not [string]::IsNullOrWhiteSpace($ArticleHtml)) -or (-not [string]::IsNullOrWhiteSpace($ArticleUrl))
$resolvedArticleHtml = Resolve-OptionalRootedPath -RootPath $rootPath -Path $ArticleHtml
$resolvedArticleOutPath = Resolve-OptionalRootedPath -RootPath $rootPath -Path $ArticleOutPath

$outputDir = if ([string]::IsNullOrWhiteSpace($OutputDirectory))
{
    Join-Path $rootPath ".build\eset-hunt-e2e"
}
else
{
    Resolve-OptionalRootedPath `
        -RootPath $rootPath `
        -Path $OutputDirectory
}
$outputDir = [System.IO.Path]::GetFullPath($outputDir)
New-DirectoryIfMissing -Path $outputDir
$runnerLockPath = Join-Path $outputDir ".runner.lock"
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
    throw "another ESET hunt E2E runner owns the output directory: $outputDir"
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

$targetStopEvent = $null
try
{
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

$preexistingKnLiveDbgService = Get-Service -Name "KnLiveDbg" -ErrorAction SilentlyContinue
if ($null -ne $preexistingKnLiveDbgService)
{
    throw "refusing to start while a pre-existing KnLiveDbg service is registered: state=$($preexistingKnLiveDbgService.Status)"
}
$preexistingKnLiveDbgProcesses = @(
    Get-Process -Name "KnLiveDbg" -ErrorAction SilentlyContinue
)
if ($preexistingKnLiveDbgProcesses.Count -ne 0)
{
    $processIds =
        @($preexistingKnLiveDbgProcesses |
            ForEach-Object { $_.Id }) -join ","
    throw "refusing to start while a pre-existing KnLiveDbg process is running: process_ids=$processIds"
}
if (-not $ReuseExistingTarget)
{
    $preexistingFixtureServices = @(
        Get-Service `
            -Name "KnLiveDbgHuntTargetEdrSvc*" `
            -ErrorAction SilentlyContinue
    )
    $preexistingFixtureProcesses = @(
        Get-Process `
            -Name "KnLiveDbgHuntTarget" `
            -ErrorAction SilentlyContinue
    )
    if ($preexistingFixtureServices.Count -ne 0 -or
        $preexistingFixtureProcesses.Count -ne 0)
    {
        $serviceNames = @(
            $preexistingFixtureServices |
                ForEach-Object { $_.Name }
        ) -join ","
        $processIds = @(
            $preexistingFixtureProcesses |
                ForEach-Object { $_.Id }
        ) -join ","
        throw "refusing to start with pre-existing hunt fixture state: services=$serviceNames process_ids=$processIds"
    }
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
$targetProcessId = 0
$knProcessStarted = $false
$runCompleted = $false
$cleanupFailures = [System.Collections.Generic.List[string]]::new()
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
        $targetProcessId = [int]$targetHandle.Process.Id
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
    $knProcessStarted = $true

    $knProcess = $knHandle.Process
    if (-not $knProcess.WaitForExit($KnLiveDbgTimeoutSeconds * 1000))
    {
        Stop-ProcessHandle -Handle $knHandle -Name "KnLiveDbg"
        $knHandle = $null
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
    $runCompleted = $true
}
catch
{
    Write-RunnerMessage "[eset-hunt-e2e] failed: $($_.Exception.Message)"
    Write-RunnerMessage "[eset-hunt-e2e] artifacts output_dir=$outputDir manifest=$manifest hunt_json=$huntJson"
    Write-ProcessSnapshot -Names @("KnLiveDbg", "KnLiveDbgHuntTarget")
    throw
}
finally
{
    if ($null -ne $knHandle)
    {
        try
        {
            if ($knHandle.Process.HasExited)
            {
                Close-ProcessHandle -Handle $knHandle
            }
            else
            {
                Stop-ProcessHandle -Handle $knHandle -Name "KnLiveDbg"
            }
        }
        catch
        {
            $cleanupFailures.Add("KnLiveDbg process cleanup failed: $($_.Exception.Message)")
        }
        $knHandle = $null
    }

    if ($knProcessStarted)
    {
        try
        {
            $serviceWasPresent = $null -ne (Get-Service -Name "KnLiveDbg" -ErrorAction SilentlyContinue)
            if ($serviceWasPresent)
            {
                [void](Remove-KnLiveDbgService)
                if ($runCompleted)
                {
                    $cleanupFailures.Add("KnLiveDbg left its service registered after a successful run")
                }
            }
        }
        catch
        {
            $cleanupFailures.Add("KnLiveDbg service cleanup failed: $($_.Exception.Message)")
        }
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
        if (-not $targetProcess.WaitForExit(60000))
        {
            $targetTimeoutPid = $targetProcess.Id
            try
            {
                Stop-ProcessHandle -Handle $targetHandle -Name "hunt target"
                $targetHandle = $null
            }
            catch
            {
                $cleanupFailures.Add("hunt target forced cleanup failed: $($_.Exception.Message)")
            }
            $cleanupFailures.Add("hunt target did not exit within 60 seconds after the stop event: pid=$targetTimeoutPid")
        }
    }
    if ($null -ne $targetHandle)
    {
        try
        {
            $targetHandle.Process.WaitForExit()
            $targetHandle.Process.Refresh()
            $targetExitCode = [int]$targetHandle.Process.ExitCode
            Close-ProcessHandle -Handle $targetHandle
            if ($runCompleted -and $targetExitCode -ne 0)
            {
                $cleanupFailures.Add("hunt target exited with code $targetExitCode during cleanup")
            }
        }
        catch
        {
            $cleanupFailures.Add("hunt target output/handle cleanup failed: $($_.Exception.Message)")
        }
        $targetHandle = $null
    }
    if (-not $ReuseExistingTarget -and $targetProcessId -gt 0)
    {
        try
        {
            $targetCleanupActions = Remove-OwnedHuntTargetArtifacts -ManifestPath $manifest -TargetProcessId $targetProcessId
            if ($runCompleted -and $targetCleanupActions -ne 0)
            {
                $cleanupFailures.Add("hunt target left $targetCleanupActions owned service/process/file artifact(s) after a successful run")
            }
        }
        catch
        {
            $cleanupFailures.Add("hunt target artifact cleanup failed: $($_.Exception.Message)")
        }
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
            $cleanupFailures.Add("failed to signal existing target stop event: $($_.Exception.Message)")
        }
        finally
        {
            if ($null -ne $existingStopEvent)
            {
                $existingStopEvent.Dispose()
            }
        }
    }

    if (-not $runCompleted)
    {
        Write-TextFileTail -Path $targetOut -Label "target.stdout"
        Write-TextFileTail -Path $targetErr -Label "target.stderr"
        Write-TextFileTail -Path $knOut -Label "knlivedbg.stdout"
        Write-TextFileTail -Path $knErr -Label "knlivedbg.stderr"
        Write-TextFileTail -Path $validatorLog -Label "validator"
        Write-TextFileTail -Path $articleValidatorLog -Label "article-validator"
    }

    foreach ($cleanupFailure in $cleanupFailures)
    {
        Write-RunnerMessage "[eset-hunt-e2e] cleanup_failure=$cleanupFailure"
    }
}

if ($cleanupFailures.Count -ne 0)
{
    throw "ESET hunt E2E cleanup failed: $($cleanupFailures -join '; ')"
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
}
finally
{
    try
    {
        if ($null -ne $targetStopEvent)
        {
            $targetStopEvent.Dispose()
            $targetStopEvent = $null
        }
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
exit 0
