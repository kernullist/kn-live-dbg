[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release',
    [string]$OutputDirectory = '',
    [ValidateRange(60, 600)][int]$ObserveSeconds = 150,
    [switch]$ProbeDriver,
    [switch]$RequireQueueHealth
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'owned-process-wait.ps1')
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this live driver validation from an elevated PowerShell session.'
}
if (Get-Service KnLiveDbg,KnLiveDbgProbe -ErrorAction SilentlyContinue) {
    throw 'An existing KnLiveDbg test service must be stopped by its owner before this run.'
}
$exe = Join-Path $repo "x64\$Configuration\KnLiveDbg.exe"
$fixture = Join-Path $repo "x64\$Configuration\tools\KnLiveDbgKmonTarget.exe"
foreach ($path in @($exe, $fixture)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Build the solution first: $path" }
}
if (-not $OutputDirectory) {
    $OutputDirectory = '.build\kmon-live\' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fff')
}
if (-not [IO.Path]::IsPathRooted($OutputDirectory)) { $OutputDirectory = Join-Path $repo $OutputDirectory }
$output = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $output) { throw "Use a new evidence directory: $output" }
New-Item -ItemType Directory -Path $output | Out-Null
$children = [Collections.Generic.List[Diagnostics.Process]]::new()
$monitor = $null
$handle = $null
$outFile = $null
$errFile = $null
$outTask = $null
$errTask = $null
$failure = ''
$runs = @()
$started = [DateTime]::UtcNow
$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
function Get-KmonEventLayer($Event)
{
    # Coverage and finding records do not all carry a layer field.
    $evidence = $Event.PSObject.Properties['evidence']
    if ($null -eq $evidence -or $null -eq $evidence.Value) { return '' }
    $layer = $evidence.Value.PSObject.Properties['layer']
    if ($null -eq $layer) { return '' }
    return [string]$layer.Value
}
try {
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $exe
    $info.WorkingDirectory = Split-Path $exe
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $monitor = [Diagnostics.Process]::new()
    $monitor.StartInfo = $info
    if (-not $monitor.Start()) { throw 'Console start failed' }
    # Retain the creation handle before !kmon raises its own PPL protection.
    $handle = $monitor.SafeHandle
    # A buffered destination can hide the readiness line until after timeout.
    $outFile = [IO.FileStream]::new("$output\console.stdout.log", [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite, 1, $true)
    $errFile = [IO.FileStream]::new("$output\console.stderr.log", [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite, 1, $true)
    $outTask = $monitor.StandardOutput.BaseStream.CopyToAsync($outFile)
    $errTask = $monitor.StandardError.BaseStream.CopyToAsync($errFile)
    $monitor.StandardInput.WriteLine('write on')
    $monitor.StandardInput.WriteLine("!kmon start /name KnLiveDbgKmonTarget.exe /background /log `"$output`"")
    $monitor.StandardInput.WriteLine('!kmon status')
    $deadline = [DateTime]::UtcNow.AddSeconds(90)
    do {
        Start-Sleep -Milliseconds 250
        $text = Get-Content -LiteralPath "$output\console.stdout.log" -Raw
        $errors = Get-Content -LiteralPath "$output\console.stderr.log" -Raw
        if ((Wait-KnOwnedProcessExit $handle 0) -or $errors -match '!kmon start.*(failed|requires)') {
            throw "KMON startup failed: $errors"
        }
    } while ($text -notmatch '\[kmon\] started\.' -and [DateTime]::UtcNow -lt $deadline)
    if ($text -notmatch '\[kmon\] started\.') { throw 'KMON startup timeout' }
    if ($ProbeDriver) { $monitor.StandardInput.WriteLine('probe load') }

    foreach ($mode in @('hold', 'mapped-readonly', 'overwrite', 'orphan-mapped-rx', 'orphan-private', 'orphan-image')) {
        $child = Start-Process -FilePath $fixture -ArgumentList @('/child', $mode, '/seconds', ($ObserveSeconds + 240)) `
            -WindowStyle Hidden -PassThru -RedirectStandardOutput "$output\fixture-$mode.stdout.log" `
            -RedirectStandardError "$output\fixture-$mode.stderr.log"
        $children.Add($child)
        $readyDeadline = [DateTime]::UtcNow.AddSeconds(10)
        do {
            Start-Sleep -Milliseconds 100
            $ready = Get-Content -LiteralPath "$output\fixture-$mode.stdout.log" -Raw
        } while ($ready -notmatch "KMON_FIXTURE pid=$($child.Id) scenario=$mode " -and
            -not $child.HasExited -and [DateTime]::UtcNow -lt $readyDeadline)
        if ($ready -notmatch "KMON_FIXTURE pid=$($child.Id) scenario=$mode " -or $child.HasExited) {
            throw "Fixture readiness failed: $mode"
        }
        $runs += [ordered]@{scenario=$mode; pid=$child.Id; started_utc=$child.StartTime.ToUniversalTime().ToString('o')}
        $runs | ConvertTo-Json | Set-Content -LiteralPath "$output\fixtures.json" -Encoding UTF8
        $monitor.StandardInput.WriteLine("!kmon add /pid $($child.Id)")
    }
    'observing' | Set-Content -LiteralPath "$output\status.txt"
    $deadline = [DateTime]::UtcNow.AddSeconds($ObserveSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        if (Wait-KnOwnedProcessExit $handle 0) { throw 'Console exited during observation' }
        foreach ($child in $children) { if ($child.HasExited) { throw "Fixture exited early: $($child.Id)" } }
        $monitor.StandardInput.WriteLine('!kmon status')
        Start-Sleep -Seconds 5
    }
    foreach ($run in $runs) {
        $monitor.StandardInput.WriteLine("!kmon cases /pid $($run.pid) /save `"$output\cases-$($run.scenario).json`"")
        $monitor.StandardInput.WriteLine("!kmon layouts /pid $($run.pid) /save `"$output\layouts-$($run.scenario).json`"")
    }
    if ($ProbeDriver) {
        $monitor.StandardInput.WriteLine('!driver integrity KnLiveDbgProbe')
        $monitor.StandardInput.WriteLine('!module integrity KnLiveDbgProbe.sys /summary')
        $monitor.StandardInput.WriteLine('probe unload')
    }
    foreach ($command in @('!kmon stop', '!ti stop', 'set-ppl-antimalware off', 'write off', 'exit')) {
        $monitor.StandardInput.WriteLine($command)
    }
    $monitor.StandardInput.Close()
    if (-not (Wait-KnOwnedProcessExit $handle 180000)) { throw 'Console shutdown timeout' }
    $outTask.GetAwaiter().GetResult()
    $errTask.GetAwaiter().GetResult()
    $code = Get-KnOwnedProcessExitCode $handle
    $code | Set-Content -LiteralPath "$output\exit.txt"
    if ($code -ne 0) { throw "Console exit code: $code" }
} catch {
    $failure = $_ | Out-String
} finally {
    foreach ($child in $children) {
        try {
            if (-not $child.HasExited) {
                $child.Kill()
                if (-not $child.WaitForExit(5000)) { throw "Fixture cleanup timeout: $($child.Id)" }
            }
        } catch { $failure += "Fixture cleanup failed: $_ " }
        finally { $child.Dispose() }
    }
    if ($handle -and -not (Wait-KnOwnedProcessExit $handle 0)) {
        try {
            foreach ($command in @('probe unload', '!kmon stop', '!ti stop', 'set-ppl-antimalware off', 'write off', 'exit')) {
                $monitor.StandardInput.WriteLine($command)
            }
            $monitor.StandardInput.Close()
        } catch {}
        if (-not (Wait-KnOwnedProcessExit $handle 60000)) {
            Stop-KnOwnedProcess $handle
            Wait-KnOwnedProcessExit $handle 10000 | Out-Null
            $failure += 'Console required forced termination; graceful cleanup was not verified.'
        }
    }
    foreach ($copyTask in @($outTask, $errTask)) {
        if ($copyTask) {
            try { $copyTask.GetAwaiter().GetResult() }
            catch { $failure += "Console log copy failed: $_ " }
        }
    }
    if ($outFile) { $outFile.Dispose() }
    if ($errFile) { $errFile.Dispose() }
    if ($monitor) { $monitor.Dispose() }
    # Only services absent at entry can belong to this harness's failed run.
    foreach ($name in @('KnLiveDbgProbe', 'KnLiveDbg')) {
        if (Get-Service $name -ErrorAction SilentlyContinue) {
            & sc.exe stop $name > "$output\cleanup-$name.log" 2>&1
            & sc.exe delete $name >> "$output\cleanup-$name.log" 2>&1
            $failure += "Service $name required fallback cleanup. "
        }
    }
}

try {
    $events = @(Get-ChildItem -LiteralPath $output -Filter 'kmon-events.*.jsonl' | Sort-Object Name |
        ForEach-Object { Get-Content -LiteralPath $_.FullName | ForEach-Object { $_ | ConvertFrom-Json } })
    $results = @(foreach ($run in $runs) {
        $own = @($events | Where-Object { $_.pid -eq $run.pid })
        $referenceObservations = @($own | Where-Object { $_.kind -eq 'coverage.user_references' }).Count
        $expected = @(switch ($run.scenario) {
            'overwrite' { $own | Where-Object { $_.kind -eq 'finding.code_modified' } }
            'orphan-mapped-rx' { $own | Where-Object { $_.kind -eq 'process.implant' -and (Get-KmonEventLayer $_) -eq 'mapped_exec' } }
            'orphan-private' { $own | Where-Object { $_.kind -eq 'process.hollow' -and (Get-KmonEventLayer $_) -eq 'exe_orphan_private' } }
            'orphan-image' { $own | Where-Object { $_.kind -eq 'process.hollow' -and (Get-KmonEventLayer $_) -eq 'exe_orphan_image' } }
        })
        $unexpected = @($own | Where-Object {
            ($run.scenario -in @('hold', 'mapped-readonly') -and $_.kind -match '^finding\.|^process\.(hollow|implant)$') -or
            ($run.scenario -eq 'orphan-image' -and (Get-KmonEventLayer $_) -in @('private_exec_pe', 'private_exec_wiped'))
        })
        $negative = $run.scenario -in @('hold', 'mapped-readonly')
        [ordered]@{
            scenario=$run.scenario; pid=$run.pid; user_reference_observations=$referenceObservations; expected_events=$expected.Count
            unexpected_events=$unexpected.Count
            passed=($referenceObservations -gt 0 -and ($negative -or $expected.Count -gt 0) -and $unexpected.Count -eq 0)
            first_detection_seconds=$(if ($expected.Count) { ([DateTime]$expected[0].ts - [DateTime]$run.started_utc).TotalSeconds } else { $null })
        }
    })
    $driverEvents = @($events | Where-Object {
        $_.kind -in @('driver.drop_load', 'driver.official_load', 'driver.image_only') -and
        ($_.driver -match 'KnLiveDbgProbe' -or $_.image -match 'KnLiveDbgProbe' -or $_.summary -match 'KnLiveDbgProbe')
    }).Count
    foreach ($run in $runs) {
        $cases = Get-Content -LiteralPath "$output\cases-$($run.scenario).json" -Raw | ConvertFrom-Json
        $layouts = Get-Content -LiteralPath "$output\layouts-$($run.scenario).json" -Raw | ConvertFrom-Json
        if ($cases.schema -ne 'kmon.hunt.v1' -or $cases.filter_pid -ne $run.pid -or
            $layouts.schema -ne 'kmon.layouts.v1' -or $layouts.filter_pid -ne $run.pid -or
            @($layouts.processes).Count -ne 1 -or $layouts.processes[0].pid -ne $run.pid) {
            throw "Case/layout export identity mismatch: $($run.scenario)"
        }
    }
    $captures = @($events | Where-Object {
        $_.kind -eq 'coverage.capture' -and
        $null -ne $_.evidence.PSObject.Properties['persistence'] -and $_.evidence.persistence -eq 'complete'
    })
    $captureRoot = Join-Path $output 'captures\'
    [long]$captureBytes = 0
    foreach ($event in $captures) {
        $evidence = $event.evidence
        $path = [IO.Path]::GetFullPath($evidence.capture_path)
        if (-not $path.StartsWith($captureRoot, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Capture path is outside this evidence directory.'
        }
        $file = Get-Item -LiteralPath $path
        if ($file.Length -ne [long]$evidence.capture_bytes -or
            (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $evidence.capture_sha256) {
            throw "Capture content does not match its event: $path"
        }
        $captureBytes += $file.Length
    }
    $pipeline = @($events | Where-Object { $_.kind -eq 'coverage.pipeline' } | Select-Object -Last 1)
    $finalPipeline = if ($pipeline.Count) { $pipeline[0].evidence } else { $null }
    $queueHealth = $null -ne $finalPipeline
    $queueHealthFields = @('lost_events', 'layout_dropped', 'execution_references_dropped',
        'capture_queue_dropped', 'persistence_queue_dropped', 'diagnostic_queue_dropped',
        'catalog_queue_dropped', 'reference_cursor_evicted')
    foreach ($field in $queueHealthFields) {
        if ($null -eq $finalPipeline -or $null -eq $finalPipeline.PSObject.Properties[$field] -or
            [long]$finalPipeline.$field -ne 0) { $queueHealth = $false }
    }
    $services = @(Get-Service KnLiveDbg,KnLiveDbgProbe -ErrorAction SilentlyContinue)
    $sameBoot = $boot -eq (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
    $passed = -not $failure -and $results.Count -eq 6 -and @($results | Where-Object { -not $_.passed }).Count -eq 0 -and
        (-not $ProbeDriver -or $driverEvents -gt 0) -and $services.Count -eq 0 -and $sameBoot -and
        $captures.Count -gt 0 -and $null -ne $finalPipeline -and $finalPipeline.final_drain -eq 'true' -and
        (-not $RequireQueueHealth -or $queueHealth)
    [ordered]@{
        schema='kn-live-dbg.kmon-live-validation.v1'; passed=$passed
        started_utc=$started.ToString('o'); completed_utc=[DateTime]::UtcNow.ToString('o')
        binary_sha256=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
        fixture_sha256=(Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash
        observe_seconds=$ObserveSeconds; scenarios=$results; event_count=$events.Count
        probe_requested=[bool]$ProbeDriver; probe_lifecycle_events=$driverEvents
        capture_chunks_verified=$captures.Count; capture_bytes_verified=$captureBytes
        case_exports_verified=$runs.Count; layout_exports_verified=$runs.Count
        final_pipeline=$finalPipeline
        queue_health_required=[bool]$RequireQueueHealth; queue_health_passed=$queueHealth
        coverage_claim='bounded fixture observations only; inspect sensor and coverage records for gaps'
        same_boot=$sameBoot; remaining_services=$services.Count; error=$failure
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath "$output\validation.json" -Encoding UTF8
    $(if ($passed) { 'complete' } else { 'failed' }) | Set-Content -LiteralPath "$output\status.txt"
    if (-not $passed) { throw "Live validation did not pass: $output\validation.json" }
    Write-Output "[kmon.live] scenarios=$($results.Count) passed=$passed evidence=$output"
} catch {
    $_ | Out-String | Set-Content -LiteralPath "$output\validation-error.txt" -Encoding UTF8
    'failed' | Set-Content -LiteralPath "$output\status.txt"
    throw
}
