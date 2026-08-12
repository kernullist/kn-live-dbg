[CmdletBinding()]
param(
    [string]$Root = "",
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    [string]$OutputDirectory = ".build\process-vad-e2e",
    [ValidateRange(60, 1200)]
    [int]$TimeoutSeconds = 300,
    [switch]$Elevated
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Test-IsAdministrator
{
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Quote-NativeArgument
{
    param([Parameter(Mandatory = $true)][string]$Value)

    if ($Value -notmatch '[\s"]')
    {
        return $Value
    }
    return '"' + ($Value -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"'
}

function Resolve-UnderRoot
{
    param(
        [Parameter(Mandatory = $true)][string]$RootPath,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $candidate = if ([IO.Path]::IsPathRooted($Path))
    {
        [IO.Path]::GetFullPath($Path)
    }
    else
    {
        [IO.Path]::GetFullPath((Join-Path $RootPath $Path))
    }
    $rootPrefix = $RootPath.TrimEnd('\') + '\'
    if (-not $candidate.StartsWith(
            $rootPrefix,
            [StringComparison]::OrdinalIgnoreCase))
    {
        throw "path must remain under repository root: $candidate"
    }
    return $candidate
}

function Read-JsonFile
{
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf))
    {
        throw "required JSON file missing: $Path"
    }
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Assert-True
{
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )

    if (-not $Condition)
    {
        throw $Message
    }
}

function Get-HexUInt64
{
    param([Parameter(Mandatory = $true)][string]$Text)

    $value = $Text.Trim()
    if ($value.StartsWith("0x", [StringComparison]::OrdinalIgnoreCase))
    {
        $value = $value.Substring(2)
    }
    return [Convert]::ToUInt64($value, 16)
}

function Invoke-KnLiveDbgSession
{
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Commands,
        [Parameter(Mandatory = $true)][string]$LogPath,
        [Parameter(Mandatory = $true)][int]$Timeout
    )

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $Executable
    $startInfo.WorkingDirectory = Split-Path -Parent $Executable
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start())
    {
        throw "failed to start KnLiveDbg"
    }

    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    foreach ($command in $Commands)
    {
        $process.StandardInput.WriteLine($command)
    }
    $process.StandardInput.Close()

    if (-not $process.WaitForExit($Timeout * 1000))
    {
        $process.Kill()
        $process.WaitForExit()
        throw "KnLiveDbg timed out after $Timeout seconds"
    }
    $process.WaitForExit()
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    [IO.File]::WriteAllText(
        $LogPath,
        $stdout + "`r`n[stderr]`r`n" + $stderr,
        [Text.UTF8Encoding]::new($false))
    if ($process.ExitCode -ne 0)
    {
        throw "KnLiveDbg exited with code $($process.ExitCode); log=$LogPath"
    }
}

$scriptPath = [IO.Path]::GetFullPath($MyInvocation.MyCommand.Path)
if ([string]::IsNullOrWhiteSpace($Root))
{
    $scriptDirectory = Split-Path -Parent $scriptPath
    $Root = Split-Path -Parent $scriptDirectory
}
$rootPath = [IO.Path]::GetFullPath($Root)
$outputPath = Resolve-UnderRoot -RootPath $rootPath -Path $OutputDirectory
$statusPath = Join-Path $outputPath "elevation-status.log"

if (-not (Test-IsAdministrator))
{
    if ($Elevated)
    {
        throw "elevated process does not have an administrator token"
    }

    New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
    $arguments = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", (Quote-NativeArgument -Value $scriptPath),
        "-Root", (Quote-NativeArgument -Value $rootPath),
        "-Configuration", $Configuration,
        "-OutputDirectory", (Quote-NativeArgument -Value $outputPath),
        "-TimeoutSeconds", $TimeoutSeconds,
        "-Elevated"
    )
    Write-Host "[process-vad] requesting UAC elevation"
    $child = Start-Process -FilePath "powershell.exe" `
        -ArgumentList ($arguments -join " ") `
        -Verb RunAs `
        -WindowStyle Hidden `
        -Wait `
        -PassThru
    $child.WaitForExit()
    if ($child.ExitCode -ne 0)
    {
        if (Test-Path -LiteralPath $statusPath)
        {
            Get-Content -LiteralPath $statusPath
        }
        exit $child.ExitCode
    }
    Get-Content -LiteralPath $statusPath
    exit 0
}

New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
$knownFiles = @(
    "manifest.json",
    "target.stdout.log",
    "target.stderr.log",
    "pid-session.log",
    "eprocess-session.log",
    "legacy-pid.json",
    "summary-pid.json",
    "exec-limit-pid.json",
    "private-pid.json",
    "wx-pid.json",
    "pe-pid.json",
    "hiddenpte-pid.json",
    "scan-pid.json",
    "modules-pid.json",
    "mappedpe-alias-pid.json",
    "scan-eprocess.json",
    "modules-eprocess.json",
    "evidence-summary.json",
    "elevation-status.log"
)
foreach ($name in $knownFiles)
{
    Remove-Item -LiteralPath (Join-Path $outputPath $name) `
        -Force -ErrorAction SilentlyContinue
}

$executable = Join-Path $rootPath "x64\$Configuration\KnLiveDbg.exe"
$targetExecutable = Join-Path $rootPath "x64\$Configuration\tools\KnLiveDbgHuntTarget.exe"
if (-not (Test-Path -LiteralPath $executable -PathType Leaf) -or
    -not (Test-Path -LiteralPath $targetExecutable -PathType Leaf))
{
    throw "build outputs are missing; run tools\build.ps1 first"
}

$preexisting = @(Get-Process -Name "KnLiveDbg" -ErrorAction SilentlyContinue)
if ($preexisting.Count -ne 0)
{
    throw "refusing to run while KnLiveDbg is already active"
}
$preexistingTargets = @(
    Get-Process -Name "KnLiveDbgHuntTarget" -ErrorAction SilentlyContinue)
if ($preexistingTargets.Count -ne 0)
{
    throw "refusing to run while KnLiveDbgHuntTarget is already active"
}
$preexistingService = Get-Service -Name "KnLiveDbg" -ErrorAction SilentlyContinue
if ($null -ne $preexistingService)
{
    throw "refusing to run while the KnLiveDbg service already exists"
}

$manifestPath = Join-Path $outputPath "manifest.json"
$stopEventName = "Local\KnLiveDbgProcessVad-" +
    [Guid]::NewGuid().ToString("N")
$preexistingTempArtifacts = @{}
foreach ($artifact in @(Get-ChildItem -LiteralPath $env:TEMP `
        -Filter "knhunt-*" -File -ErrorAction SilentlyContinue))
{
    $preexistingTempArtifacts[$artifact.FullName] = $true
}
$targetStart = [Diagnostics.ProcessStartInfo]::new()
$targetStart.FileName = $targetExecutable
$targetStart.WorkingDirectory = Split-Path -Parent $targetExecutable
$targetStart.UseShellExecute = $false
$targetStart.CreateNoWindow = $true
$targetStart.RedirectStandardOutput = $true
$targetStart.RedirectStandardError = $true
$targetArguments = @(
    "/private-exec",
    "/rwx",
    "/large-private-exec",
    "/pe-like",
    "/wiped-pe",
    "/section-image-map",
    "/image-rwx-section",
    "/seconds", ($TimeoutSeconds + 120).ToString(),
    "/stop-event", $stopEventName,
    "/manifest", $manifestPath
)
$targetStart.Arguments = ($targetArguments | ForEach-Object {
    Quote-NativeArgument -Value $_
}) -join " "

$target = [Diagnostics.Process]::new()
$target.StartInfo = $targetStart
$targetStarted = $false
$targetStdoutTask = $null
$targetStderrTask = $null
$machineRunMutex = $null
$machineRunMutexOwned = $false

try
{
    $machineRunMutex = [Threading.Mutex]::new(
        $false,
        "Global\KnLiveDbg-Hunt-Runner-v1")
    try
    {
        $machineRunMutexOwned = $machineRunMutex.WaitOne(0)
    }
    catch [Threading.AbandonedMutexException]
    {
        $machineRunMutexOwned = $true
    }
    if (-not $machineRunMutexOwned)
    {
        throw "another KnLiveDbg hunt/fixture runner owns the machine-wide mutex"
    }

    if (-not $target.Start())
    {
        throw "failed to start VAD positive-control target"
    }
    $targetStarted = $true
    $targetStdoutTask = $target.StandardOutput.ReadToEndAsync()
    $targetStderrTask = $target.StandardError.ReadToEndAsync()

    $deadline = [DateTime]::UtcNow.AddSeconds(45)
    while (-not (Test-Path -LiteralPath $manifestPath) -and
           [DateTime]::UtcNow -lt $deadline)
    {
        if ($target.HasExited)
        {
            throw "VAD target exited before writing its manifest"
        }
        Start-Sleep -Milliseconds 100
    }
    $manifest = Read-JsonFile -Path $manifestPath
    Assert-True `
        -Condition ($manifest.schema -eq "kn-live-dbg.hunt-target-manifest.v1") `
        -Message "unexpected target manifest schema"
    Assert-True `
        -Condition ([int]$manifest.pid -eq $target.Id) `
        -Message "target PID does not match manifest"

    $targetPid = [int]$manifest.pid
    $json = @{}
    foreach ($name in @(
        "legacy-pid", "summary-pid", "exec-limit-pid", "private-pid",
        "wx-pid", "pe-pid", "hiddenpte-pid", "scan-pid", "modules-pid",
        "mappedpe-alias-pid", "scan-eprocess", "modules-eprocess"))
    {
        $json[$name] = Join-Path $outputPath ($name + ".json")
    }

    $pidCommands = @(
        "write off",
        "!vad $targetPid /json `"$($json['legacy-pid'])`"",
        "!vad $targetPid /summary /json `"$($json['summary-pid'])`"",
        "!vad $targetPid /exec /limit 1 /json `"$($json['exec-limit-pid'])`"",
        "!vad $targetPid /private /json `"$($json['private-pid'])`"",
        "!vad $targetPid /wx /json `"$($json['wx-pid'])`"",
        "!vad $targetPid /pe /json `"$($json['pe-pid'])`"",
        "!vad $targetPid /hiddenpte /limit 1 /json `"$($json['hiddenpte-pid'])`"",
        "!vad scan $targetPid /json `"$($json['scan-pid'])`"",
        "!vad modules $targetPid /json `"$($json['modules-pid'])`"",
        "!vad mappedpe $targetPid /json `"$($json['mappedpe-alias-pid'])`"",
        "unload",
        "exit"
    )
    Invoke-KnLiveDbgSession `
        -Executable $executable `
        -Commands $pidCommands `
        -LogPath (Join-Path $outputPath "pid-session.log") `
        -Timeout $TimeoutSeconds

    $legacy = Read-JsonFile -Path $json["legacy-pid"]
    $eprocess = [string]$legacy.target.eprocess
    Assert-True `
        -Condition ((Get-HexUInt64 -Text $eprocess) -ne 0) `
        -Message "PID scan did not resolve EPROCESS"

    $eprocessCommands = @(
        "write off",
        "!vad scan $eprocess /json `"$($json['scan-eprocess'])`"",
        "!vad modules $eprocess /json `"$($json['modules-eprocess'])`"",
        "unload",
        "exit"
    )
    Invoke-KnLiveDbgSession `
        -Executable $executable `
        -Commands $eprocessCommands `
        -LogPath (Join-Path $outputPath "eprocess-session.log") `
        -Timeout $TimeoutSeconds

    $summary = Read-JsonFile -Path $json["summary-pid"]
    $execLimit = Read-JsonFile -Path $json["exec-limit-pid"]
    $private = Read-JsonFile -Path $json["private-pid"]
    $wx = Read-JsonFile -Path $json["wx-pid"]
    $pe = Read-JsonFile -Path $json["pe-pid"]
    $hidden = Read-JsonFile -Path $json["hiddenpte-pid"]
    $scanPid = Read-JsonFile -Path $json["scan-pid"]
    $modulesPid = Read-JsonFile -Path $json["modules-pid"]
    $mappedPeAliasPid = Read-JsonFile -Path $json["mappedpe-alias-pid"]
    $scanEprocess = Read-JsonFile -Path $json["scan-eprocess"]
    $modulesEprocess = Read-JsonFile -Path $json["modules-eprocess"]

    foreach ($document in @($legacy, $summary, $execLimit, $private, $wx, $pe, $hidden, $scanPid, $scanEprocess))
    {
        Assert-True `
            -Condition ($document.schema -eq "kn-live-dbg.vad.v1") `
            -Message "unexpected VAD JSON schema"
        Assert-True `
            -Condition ([bool]$document.summary.coverage_complete) `
            -Message "VAD scan coverage is incomplete"
        Assert-True `
            -Condition ([bool]$document.summary.effective_protection_coverage_complete) `
            -Message "VAD effective-protection coverage is incomplete"
    }
    foreach ($document in @($modulesPid, $mappedPeAliasPid, $modulesEprocess))
    {
        Assert-True `
            -Condition ($document.schema -eq "kn-live-dbg.process-pe.v1") `
            -Message "unexpected mapped PE JSON schema"
        Assert-True `
            -Condition ([bool]$document.summary.vad_coverage_complete) `
            -Message "mapped PE VAD coverage is incomplete"
        Assert-True `
            -Condition ([bool]$document.summary.loader_coverage_complete) `
            -Message "mapped PE loader coverage is incomplete"
        Assert-True `
            -Condition ([bool]$document.summary.header_probe_coverage_complete) `
            -Message "mapped PE header-probe coverage is incomplete"
        Assert-True `
            -Condition ([bool]$document.summary.mapped_path_coverage_complete) `
            -Message "mapped PE path coverage is incomplete"
        Assert-True `
            -Condition ([bool]$document.summary.coverage_complete) `
            -Message "mapped PE aggregate coverage is incomplete"
    }

    Assert-True `
        -Condition ([int64]$legacy.summary.total_records -gt 1) `
        -Message "legacy VAD scan returned only one record"
    Assert-True `
        -Condition ([int64]$summary.summary.total_records -eq [int64]$legacy.summary.total_records) `
        -Message "/summary changed scan coverage"
    Assert-True `
        -Condition (@($summary.records).Count -eq [int64]$summary.summary.matching_records) `
        -Message "/summary changed JSON record inventory"
    Assert-True `
        -Condition (@($execLimit.records).Count -eq 1) `
        -Message "/limit 1 did not cap rendered VAD records"
    Assert-True `
        -Condition ([int64]$execLimit.summary.matching_records -gt 1) `
        -Message "/limit stopped VAD traversal after the first match"
    Assert-True `
        -Condition ([int64]$execLimit.summary.total_records -eq [int64]$legacy.summary.total_records) `
        -Message "/limit changed total VAD traversal coverage"
    Assert-True `
        -Condition ([bool]$execLimit.summary.truncated) `
        -Message "/limit truncation was not reported"
    Assert-True `
        -Condition ((@($private.records | Where-Object { -not $_.private })).Count -eq 0 -and @($private.records).Count -gt 1) `
        -Message "/private returned a non-private VAD or stopped after one"
    Assert-True `
        -Condition ((@($wx.records | Where-Object { -not $_.writable_executable })).Count -eq 0 -and @($wx.records).Count -ge 1) `
        -Message "/wx filter did not return only W+X VADs"
    Assert-True `
        -Condition ((@($pe.records | Where-Object { -not $_.pe_like })).Count -eq 0 -and @($pe.records).Count -ge 2) `
        -Message "/pe did not enumerate both intact and wiped private PE mappings"
    Assert-True `
        -Condition ([bool]$hidden.summary.hidden_pte_scan_enabled) `
        -Message "/hiddenpte did not enable the page-table cross-view"
    Assert-True `
        -Condition ([int64]$hidden.summary.total_records -eq [int64]$legacy.summary.total_records) `
        -Message "/hiddenpte changed VAD traversal coverage"

    foreach ($scan in @($scanPid, $scanEprocess))
    {
        Assert-True `
            -Condition ($scan.mode -eq "scan" -and [bool]$scan.summary.injection_scan) `
            -Message "injection scan mode was not preserved"
        Assert-True `
            -Condition ([bool]$scan.summary.hidden_pte_scan_enabled) `
            -Message "injection scan did not enable executable hidden-PTE coverage"
        Assert-True `
            -Condition ([int64]$scan.summary.matching_records -gt 1) `
            -Message "injection scan stopped after one finding"
        Assert-True `
            -Condition ([int64]$scan.summary.private_executable -ge 3) `
            -Message "injection scan missed private executable controls"
        Assert-True `
            -Condition ([int64]$scan.summary.wx -ge 1) `
            -Message "injection scan missed W+X control"
        Assert-True `
            -Condition ([int64]$scan.summary.pe_like -ge 2) `
            -Message "injection scan missed PE/manual-map controls"
    }

    $pidScanBases = @($scanPid.records | ForEach-Object { ([string]$_.start).ToLowerInvariant() } | Sort-Object -Unique)
    $eprocessScanBases = @($scanEprocess.records | ForEach-Object { ([string]$_.start).ToLowerInvariant() } | Sort-Object -Unique)
    Assert-True `
        -Condition (($pidScanBases -join ',') -eq ($eprocessScanBases -join ',')) `
        -Message "PID and EPROCESS injection scans returned different VAD sets"

    $scenarioByName = @{}
    foreach ($scenario in @($manifest.scenarios))
    {
        $scenarioByName[[string]$scenario.name] = $scenario
    }
    foreach ($required in @("pe-like", "wiped-pe", "section-image-map"))
    {
        Assert-True `
            -Condition $scenarioByName.ContainsKey($required) `
            -Message "target manifest is missing $required"
        $expectedBase = ([string]$scenarioByName[$required].address).ToLowerInvariant()
        $mapped = @($modulesPid.records | Where-Object {
            ([string]$_.base).ToLowerInvariant() -eq $expectedBase
        })
        Assert-True `
            -Condition ($mapped.Count -eq 1) `
            -Message "mapped PE inventory missed $required at $expectedBase"
        Assert-True `
            -Condition ([bool]$mapped[0].memory_header_visible) `
            -Message "mapped PE inventory did not recover the $required header"
    }
    foreach ($required in @("pe-like", "wiped-pe"))
    {
        $expectedBase = ([string]$scenarioByName[$required].address).ToLowerInvariant()
        $mapped = @($modulesPid.records | Where-Object {
            ([string]$_.base).ToLowerInvariant() -eq $expectedBase
        })[0]
        Assert-True `
            -Condition (-not [bool]$mapped.loader_visible -and [bool]$mapped.private_mapping) `
            -Message "$required was not classified as loader-invisible private PE"
    }
    $sectionBase = ([string]$scenarioByName["section-image-map"].address).ToLowerInvariant()
    $sectionRecord = @($modulesPid.records | Where-Object {
        ([string]$_.base).ToLowerInvariant() -eq $sectionBase
    })[0]
    Assert-True `
        -Condition (-not [bool]$sectionRecord.loader_visible -and
                    [bool]$sectionRecord.image_backed -and
                    [bool]$sectionRecord.virtual_image_mapping -and
                    @($sectionRecord.sources) -contains "virtual_query_image") `
        -Message "SEC_IMAGE control was not classified through the independent MEM_IMAGE view"

    Assert-True `
        -Condition ([int64]$modulesPid.summary.candidate_mappings -gt 1 -and [int64]$modulesPid.summary.loader_visible -gt 1) `
        -Message "mapped PE inventory returned only one module"
    $pidModuleBases = @($modulesPid.records | ForEach-Object { ([string]$_.base).ToLowerInvariant() } | Sort-Object -Unique)
    $mappedPeAliasBases = @($mappedPeAliasPid.records | ForEach-Object { ([string]$_.base).ToLowerInvariant() } | Sort-Object -Unique)
    $eprocessModuleBases = @($modulesEprocess.records | ForEach-Object { ([string]$_.base).ToLowerInvariant() } | Sort-Object -Unique)
    Assert-True `
        -Condition (($pidModuleBases -join ',') -eq ($mappedPeAliasBases -join ',') -and
                    [int64]$modulesPid.summary.candidate_mappings -eq
                        [int64]$mappedPeAliasPid.summary.candidate_mappings) `
        -Message "mappedpe alias and modules mode inventories differ"
    Assert-True `
        -Condition (($pidModuleBases -join ',') -eq ($eprocessModuleBases -join ',')) `
        -Message "PID and EPROCESS mapped PE inventories differ"

    $evidence = [ordered]@{
        schema = "kn-live-dbg.process-vad-e2e.v1"
        status = "passed"
        pid = $targetPid
        eprocess = $eprocess
        target_scenarios = @($manifest.scenarios).Count
        vad_total_records = [int64]$legacy.summary.total_records
        exec_matching_records = [int64]$execLimit.summary.matching_records
        scan_matching_records = [int64]$scanPid.summary.matching_records
        scan_private_executable = [int64]$scanPid.summary.private_executable
        scan_wx = [int64]$scanPid.summary.wx
        scan_pe_like = [int64]$scanPid.summary.pe_like
        mapped_pe_candidates = [int64]$modulesPid.summary.candidate_mappings
        mapped_pe_loader_visible = [int64]$modulesPid.summary.loader_visible
        mapped_pe_memory_only = [int64]$modulesPid.summary.memory_only
        pid_eprocess_scan_equal = $true
        pid_eprocess_modules_equal = $true
        mappedpe_alias_equal = $true
        coverage_complete = $true
    }
    $evidence | ConvertTo-Json -Depth 8 | Set-Content `
        -LiteralPath (Join-Path $outputPath "evidence-summary.json") `
        -Encoding UTF8
    @(
        "status=success",
        "pid=$targetPid",
        "eprocess=$eprocess",
        "vad_records=$($legacy.summary.total_records)",
        "scan_matches=$($scanPid.summary.matching_records)",
        "mapped_pe_candidates=$($modulesPid.summary.candidate_mappings)",
        "coverage_complete=true"
    ) | Set-Content -LiteralPath $statusPath -Encoding UTF8
}
catch
{
    @(
        "status=failure",
        "error=$($_.Exception.Message)"
    ) | Set-Content -LiteralPath $statusPath -Encoding UTF8
    throw
}
finally
{
    $cleanupFailures = [Collections.Generic.List[string]]::new()
    if ($targetStarted)
    {
        if (-not $target.HasExited)
        {
            try
            {
                $stopEvent = [Threading.EventWaitHandle]::OpenExisting(
                    $stopEventName)
                try
                {
                    $stopEvent.Set() | Out-Null
                }
                finally
                {
                    $stopEvent.Dispose()
                }
            }
            catch
            {
                # A startup failure may precede creation of the named event.
            }
            if (-not $target.WaitForExit(10000))
            {
                $target.Kill()
                $target.WaitForExit()
            }
        }
        if ($target.ExitCode -ne 0)
        {
            $cleanupFailures.Add(
                "VAD positive-control target exited with code $($target.ExitCode)")
        }
        if ($targetStdoutTask -ne $null)
        {
            [IO.File]::WriteAllText(
                (Join-Path $outputPath "target.stdout.log"),
                $targetStdoutTask.GetAwaiter().GetResult(),
                [Text.UTF8Encoding]::new($false))
        }
        if ($targetStderrTask -ne $null)
        {
            [IO.File]::WriteAllText(
                (Join-Path $outputPath "target.stderr.log"),
                $targetStderrTask.GetAwaiter().GetResult(),
                [Text.UTF8Encoding]::new($false))
        }
    }

    foreach ($artifact in @(Get-ChildItem -LiteralPath $env:TEMP `
            -Filter "knhunt-*" -File -ErrorAction SilentlyContinue))
    {
        if (-not $preexistingTempArtifacts.ContainsKey($artifact.FullName))
        {
            try
            {
                Remove-Item -LiteralPath $artifact.FullName `
                    -Force -ErrorAction Stop
            }
            catch
            {
                $cleanupFailures.Add(
                    "could not remove target temp artifact $($artifact.FullName): $($_.Exception.Message)")
            }
        }
    }
    foreach ($leftover in @(Get-Process -Name "KnLiveDbg" -ErrorAction SilentlyContinue))
    {
        try
        {
            Stop-Process -Id $leftover.Id -Force -ErrorAction Stop
            $leftover.WaitForExit(5000) | Out-Null
        }
        catch
        {
            $cleanupFailures.Add(
                "could not stop leftover KnLiveDbg pid=$($leftover.Id): $($_.Exception.Message)")
        }
    }

    if ($null -ne (Get-Service -Name "KnLiveDbg" -ErrorAction SilentlyContinue))
    {
        & sc.exe stop KnLiveDbg *> $null
        & sc.exe delete KnLiveDbg *> $null
        $serviceGone = $false
        for ($attempt = 0; $attempt -lt 100; ++$attempt)
        {
            if ($null -eq (Get-Service -Name "KnLiveDbg" -ErrorAction SilentlyContinue))
            {
                $serviceGone = $true
                break
            }
            Start-Sleep -Milliseconds 50
        }
        if (-not $serviceGone)
        {
            $cleanupFailures.Add(
                "KnLiveDbg service remained registered after cleanup")
        }
    }

    if ($machineRunMutexOwned -and $null -ne $machineRunMutex)
    {
        try
        {
            $machineRunMutex.ReleaseMutex()
            $machineRunMutexOwned = $false
        }
        catch
        {
            $cleanupFailures.Add(
                "machine-wide runner mutex release failed: $($_.Exception.Message)")
        }
    }
    if ($null -ne $machineRunMutex)
    {
        try
        {
            $machineRunMutex.Dispose()
            $machineRunMutex = $null
        }
        catch
        {
            $cleanupFailures.Add(
                "machine-wide runner mutex disposal failed: $($_.Exception.Message)")
        }
    }

    if ($cleanupFailures.Count -ne 0)
    {
        @(
            "status=failure",
            "error=$($cleanupFailures -join '; ')"
        ) | Set-Content -LiteralPath $statusPath -Encoding UTF8
        throw ($cleanupFailures -join "; ")
    }
}

$evidencePath = Join-Path $outputPath "evidence-summary.json"
$completedEvidence = Read-JsonFile -Path $evidencePath
$completedEvidence | Add-Member -NotePropertyName cleanup_complete `
    -NotePropertyValue $true -Force
$completedEvidence | ConvertTo-Json -Depth 8 | Set-Content `
    -LiteralPath $evidencePath -Encoding UTF8
Add-Content -LiteralPath $statusPath -Value "cleanup_complete=true" `
    -Encoding UTF8
Get-Content -LiteralPath $statusPath
