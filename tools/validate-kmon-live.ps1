[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release',
    [string]$OutputDirectory = '',
    [ValidateRange(60, 600)][int]$ObserveSeconds = 150,
    [switch]$ProbeDriver,
    [switch]$RequireQueueHealth,
    [switch]$RequireCompletedWork,
    [switch]$ImageSweepFixtures,
    [switch]$RequireImageCompletion,
    [switch]$ImageStressFixtures,
    [switch]$AllProcessLayouts,
    [string]$MonitorExecutablePath = ''
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
if ($MonitorExecutablePath) { $exe = (Resolve-Path -LiteralPath $MonitorExecutablePath).Path }
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
    $startScope = if ($AllProcessLayouts) { '' } else { '/name KnLiveDbgKmonTarget.exe ' }
    $monitor.StandardInput.WriteLine("!kmon start ${startScope}/background /log `"$output`"")
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
    # Starting without a filter latches all-process layout collection. Adding
    # the controls afterwards selects hostility checks without narrowing it.
    if ($AllProcessLayouts) { $monitor.StandardInput.WriteLine('!kmon add /name KnLiveDbgKmonTarget.exe') }
    if ($ProbeDriver) { $monitor.StandardInput.WriteLine('probe load') }

    $modes = @('hold', 'mapped-readonly', 'overwrite', 'orphan-mapped-rx', 'orphan-private', 'orphan-image')
    if ($ImageSweepFixtures) { $modes += 'overwrite-tail' }
    if ($ImageStressFixtures) { $modes = @('large-clean', 'large-tail', 'rel32-clean', 'rel32-invalid') }
    foreach ($mode in $modes) {
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
    if ($AllProcessLayouts) { $monitor.StandardInput.WriteLine("!kmon layouts /json /save `"$output\layouts-inventory.json`"") }
    foreach ($run in $runs) {
        $monitor.StandardInput.WriteLine("!kmon cases /pid $($run.pid) /save `"$output\cases-$($run.scenario).json`"")
        $monitor.StandardInput.WriteLine("!kmon layouts /pid $($run.pid) /save `"$output\layouts-$($run.scenario).json`"")
    }
    if ($ProbeDriver) {
        $monitor.StandardInput.WriteLine('!driver integrity KnLiveDbgProbe')
        $monitor.StandardInput.WriteLine('!module integrity KnLiveDbgProbe.sys /summary')
        $monitor.StandardInput.WriteLine('probe unload')
    }
    $stopCommands = @('!kmon stop')
    if ($AllProcessLayouts) { $stopCommands += "!kmon layouts /json /save `"$output\layouts-final.json`"" }
    $stopCommands += @('!ti stop', 'set-ppl-antimalware off', 'write off', 'exit')
    foreach ($command in $stopCommands) {
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
    # Full sweeps can emit tens of thousands of page observations. Stream
    # their unique addresses instead of retaining every PSObject in memory.
    $events = [Collections.Generic.List[object]]::new()
    $comparedPagesByPid = @{}
    foreach ($run in $runs) { $comparedPagesByPid[[long]$run.pid] = [Collections.Generic.HashSet[string]]::new() }
    $eventCount = 0
    [long]$layoutVerificationRecords = 0
    [long]$layoutCompletionRecords = 0
    foreach ($file in @(Get-ChildItem -LiteralPath $output -Filter 'kmon-events.*.jsonl' | Sort-Object Name)) {
        foreach ($line in [IO.File]::ReadLines($file.FullName)) {
            ++$eventCount
            $event = $line | ConvertFrom-Json
            if ($event.kind -eq 'coverage.layout_verification') { ++$layoutVerificationRecords }
            if ($event.kind -eq 'coverage.layout' -and $event.task -in @('initial_observation', 'complete')) { ++$layoutCompletionRecords }
            if ($event.kind -eq 'coverage.region') {
                if ($comparedPagesByPid.ContainsKey([long]$event.pid) -and $event.evidence.source -eq 'executable_page_compare' -and
                    [long]$event.evidence.compared_bytes -gt 0) {
                    foreach ($span in ([string]$event.evidence.compared_ranges -split ',')) {
                        if ($span -notmatch '^(\d+):(\d+)$') { throw 'Invalid compared range' }
                        $begin = [uint64]$Matches[1]; $length = [uint64]$Matches[2]
                        if ($length -eq 0 -or $length -gt 65536 -or $begin -gt [uint64]::MaxValue - $length) { throw 'Invalid compared span' }
                        for ($address = $begin - ($begin % 4096); $address -lt $begin + $length; $address += 4096) {
                            [void]$comparedPagesByPid[[long]$event.pid].Add([string]$address)
                        }
                    }
                }
            } elseif ($event.kind -match '^finding\.|^process\.(hollow|implant)$|^driver\.(drop_load|official_load|image_only)$' -or
                $event.kind -in @('coverage.user_references', 'coverage.image', 'coverage.capture',
                    'coverage.capture_result', 'coverage.pipeline', 'coverage.shutdown_event')) {
                $events.Add($event)
            }
        }
    }
    $results = @(foreach ($run in $runs) {
        $own = @($events | Where-Object { $_.pid -eq $run.pid })
        $referenceObservations = @($own | Where-Object { $_.kind -eq 'coverage.user_references' }).Count
        $comparedPages = $comparedPagesByPid[[long]$run.pid].Count
        $controlledName = ''; $controlledPath = ''; $controlledRva = 0
        if ($ImageStressFixtures) {
            $marker = Get-Content -LiteralPath "$output\fixture-$($run.scenario).stdout.log" -Raw
            if ($marker -notmatch 'KMON_IMAGE path=(.+) rva=(\d+) size=(\d+) dynamic=([01])') { throw 'Missing controlled image identity' }
            $controlledPath = $Matches[1]; $controlledName = [IO.Path]::GetFileName($controlledPath); $controlledRva = [long]$Matches[2]
        }
        $expected = @(switch ($run.scenario) {
            'overwrite' { $own | Where-Object { $_.kind -eq 'finding.code_modified' -and $_.image -match 'KnLiveDbgKmonTarget\.exe$' } }
            'overwrite-tail' {
                $marker = Get-Content -LiteralPath "$output\fixture-overwrite-tail.stdout.log" -Raw
                if ($marker -notmatch 'KMON_TAIL rva=(\d+) bytes=16') { throw 'Missing tail patch identity' }
                $tailRva = [long]$Matches[1]
                $own | Where-Object { $_.kind -eq 'finding.code_modified' -and
                    $_.image -match 'KnLiveDbgKmonTarget\.exe$' -and
                    [long]$_.evidence.rva -eq ($tailRva -band -4096) }
            }
            'orphan-mapped-rx' { $own | Where-Object { $_.kind -eq 'process.implant' -and (Get-KmonEventLayer $_) -eq 'mapped_exec' } }
            'orphan-private' { $own | Where-Object { $_.kind -eq 'process.hollow' -and (Get-KmonEventLayer $_) -eq 'exe_orphan_private' } }
            'orphan-image' { $own | Where-Object { $_.kind -eq 'process.hollow' -and (Get-KmonEventLayer $_) -eq 'exe_orphan_image' } }
            { $_ -in @('large-tail', 'rel32-invalid') } {
                $own | Where-Object { $_.kind -eq 'finding.code_modified' -and
                    [IO.Path]::GetFileName($_.image) -eq $controlledName -and
                    [long]$_.evidence.rva -eq ($controlledRva -band -4096) }
            }
        })
        # Loading this exact generated DLL from Temp intentionally satisfies
        # the separate drop-path lead rule. Require its explicit non-verdict
        # classification; no byte-comparison finding is exempted.
        $expectedLoadLeads = @($own | Where-Object { $ImageStressFixtures -and $_.kind -eq 'process.implant' -and
            (Get-KmonEventLayer $_) -eq 'drop_module' -and $_.evidence.notes -eq $controlledPath -and
            $_.evidence.event_category -eq 'lead' -and $_.evidence.maliciousness -eq 'not_established' -and
            [long]$_.evidence.compared_bytes -eq 0 })
        $unexpected = @($own | Where-Object {
            ($run.scenario -in @('hold', 'mapped-readonly', 'large-clean', 'rel32-clean') -and $_.kind -match '^finding\.|^process\.(hollow|implant)$' -and
                -not ($_.kind -eq 'finding.layout_change' -and $_.evidence.event_category -eq 'observation') -and
                $_ -notin $expectedLoadLeads) -or
            ($run.scenario -eq 'orphan-image' -and (Get-KmonEventLayer $_) -in @('private_exec_pe', 'private_exec_wiped'))
        })
        $negative = $run.scenario -in @('hold', 'mapped-readonly', 'large-clean', 'rel32-clean')
        # Assess the known fixture and its three imported images, not merely
        # whichever subset the monitor happened to discover. Deleted SEC_IMAGE
        # controls have no readable file reference and are reported separately.
        $imageNames = @('KnLiveDbgKmonTarget.exe', 'KERNEL32.DLL', 'KERNELBASE.dll', 'ntdll.dll')
        if ($ImageStressFixtures) { $imageNames += $controlledName }
        $imageCompletions = @(foreach ($name in $imageNames) {
            $completed = @($own | Where-Object { $_.kind -eq 'coverage.image' -and
                [IO.Path]::GetFileName($_.image) -ieq $name -and $_.summary -in @('cycle_complete', 'cycle_complete_with_gaps') })
            $best = @($completed | Sort-Object { [long]$_.evidence.compared_bytes } -Descending | Select-Object -First 1)
            $completeBytes = $best.Count -eq 1 -and $best[0].evidence.coverage_status -eq 'complete'
            $traversedWithoutErrors = $best.Count -eq 1 -and [long]$best[0].evidence.failed_bytes -eq 0 -and
                [long]$best[0].evidence.requested_bytes -eq ([long]$best[0].evidence.compared_bytes + [long]$best[0].evidence.skipped_bytes)
            [ordered]@{image=$name; traversed=$completed.Count -gt 0; bytes_complete=$completeBytes
                traversed_without_errors=$traversedWithoutErrors
                compared_bytes=$(if ($best.Count) { [long]$best[0].evidence.compared_bytes } else { 0 })
                failed_bytes=$(if ($best.Count) { [long]$best[0].evidence.failed_bytes } else { 0 })
                function_override_compared_bytes=$(if ($best.Count -and $best[0].evidence.PSObject.Properties['function_override_compared_bytes']) { [long]$best[0].evidence.function_override_compared_bytes } else { 0 })
                skipped_bytes=$(if ($best.Count) { [long]$best[0].evidence.skipped_bytes } else { 0 })}
        })
        $imagesComplete = @($imageCompletions | Where-Object { -not $_.traversed_without_errors }).Count -eq 0 -and
            $imageCompletions[0].bytes_complete
        if ($ImageStressFixtures) { $imagesComplete = $imagesComplete -and $imageCompletions[-1].bytes_complete }
        [ordered]@{
            scenario=$run.scenario; pid=$run.pid; user_reference_observations=$referenceObservations; expected_events=$expected.Count
            unique_image_pages_compared=$comparedPages
            unexpected_events=$unexpected.Count
            expected_drop_path_leads=$expectedLoadLeads.Count
            layout_change_observations=@($own | Where-Object { $_.kind -eq 'finding.layout_change' -and $_.evidence.event_category -eq 'observation' }).Count
            image_completions=$imageCompletions; image_sweeps_completed=$imagesComplete
            passed=($referenceObservations -gt 0 -and ($negative -or $expected.Count -gt 0) -and $unexpected.Count -eq 0 -and
                (-not $RequireImageCompletion -or $imagesComplete))
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
    $allProcessScope = $false
    $layoutProcessCount = 0
    if ($AllProcessLayouts) {
        $inventory = Get-Content -LiteralPath "$output\layouts-inventory.json" -Raw | ConvertFrom-Json
        $layoutProcessCount = @($inventory.processes).Count
        $allProcessScope = $inventory.schema -eq 'kmon.layouts.v1' -and $inventory.scope -eq 'all_processes' -and
            $inventory.filter_pid -eq 0 -and $inventory.inventory_complete -and
            $inventory.processes_over_cap -eq 0 -and $layoutProcessCount -gt $runs.Count
        if (-not $allProcessScope) { throw 'Full-process layout scope was not verified' }
        $finalLayout = Get-Content -LiteralPath "$output\layouts-final.json" -Raw | ConvertFrom-Json
        if ($finalLayout.scope -ne 'all_processes' -or $finalLayout.collection_active -or
            $finalLayout.notices_pending -ne 0 -or $finalLayout.verification_changes_pending -ne 0 -or
            $finalLayout.verification_pending -ne 0) { throw 'Layout shutdown left retained work' }
    }
    $queueHealth = $null -ne $finalPipeline
    $queueHealthFields = @('lost_events', 'layout_dropped', 'execution_references_dropped',
        'capture_queue_dropped', 'persistence_queue_dropped', 'diagnostic_queue_dropped',
        'catalog_queue_dropped', 'reference_cursor_evicted')
    foreach ($field in $queueHealthFields) {
        if ($null -eq $finalPipeline -or $null -eq $finalPipeline.PSObject.Properties[$field] -or
            [long]$finalPipeline.$field -ne 0) { $queueHealth = $false }
    }
    if ($AllProcessLayouts -and ($null -eq $finalPipeline -or $null -eq $finalPipeline.PSObject.Properties['layout_changes_abandoned'] -or
        [long]$finalPipeline.layout_changes_abandoned -ne 0)) { $queueHealth = $false }
    $layoutLedger = -not $AllProcessLayouts
    if ($AllProcessLayouts -and $null -ne $finalPipeline) {
        $layoutLedger = $true
        foreach ($field in @('layout_submitted', 'layout_checked', 'layout_rejected', 'layout_coalesced', 'layout_pending', 'layout_completed')) {
            if ($null -eq $finalPipeline.PSObject.Properties[$field]) { $layoutLedger = $false }
        }
        if ($layoutLedger) {
            $layoutLedger = [long]$finalPipeline.layout_submitted -eq (
                [long]$finalPipeline.layout_checked + [long]$finalPipeline.layout_rejected +
                [long]$finalPipeline.layout_coalesced + [long]$finalPipeline.layout_pending) -and
                [long]$finalPipeline.layout_rejected -eq $layoutVerificationRecords -and
                [long]$finalPipeline.layout_completed -eq $layoutCompletionRecords
        }
    }
    if (-not $layoutLedger) { $queueHealth = $false }
    $captureResults = @($events | Where-Object { $_.kind -eq 'coverage.capture_result' })
    $captureLedger = @{}
    foreach ($event in $captures) {
        $id = [string]$event.evidence.capture_id
        if (-not $captureLedger.ContainsKey($id)) { $captureLedger[$id] = [long]0 }
        $captureLedger[$id] += [long]$event.evidence.capture_bytes
    }
    $completedWork = $null -ne $finalPipeline -and $captureResults.Count -gt 0
    foreach ($event in $captureResults) {
        $e = $event.evidence
        $persisted = if ($captureLedger.ContainsKey([string]$e.capture_id)) { $captureLedger[[string]$e.capture_id] } else { 0 }
        if ([long]$e.requested_bytes -ne ([long]$e.compared_bytes + [long]$e.failed_bytes + [long]$e.skipped_bytes) -or
            $persisted -ne [long]$e.compared_bytes) { throw "Capture accounting mismatch: $($e.capture_id)" }
        if ($e.read_completion -ne 'true' -or [long]$e.unvisited_bytes -ne 0) { $completedWork = $false }
    }
    foreach ($field in @('analysis_pending', 'layout_pending', 'execution_references_pending', 'capture_pending', 'shutdown_events_unanalyzed')) {
        if ($null -eq $finalPipeline -or $null -eq $finalPipeline.PSObject.Properties[$field] -or
            [long]$finalPipeline.$field -ne 0) { $completedWork = $false }
    }
    if ($AllProcessLayouts -and ($null -eq $finalPipeline -or $null -eq $finalPipeline.PSObject.Properties['layout_source_pending'] -or
        [long]$finalPipeline.layout_source_pending -ne 0)) { $completedWork = $false }
    if ($AllProcessLayouts -and ($null -eq $finalPipeline -or $null -eq $finalPipeline.PSObject.Properties['layout_notices_pending'] -or
        [long]$finalPipeline.layout_notices_pending -ne 0)) { $completedWork = $false }
    if ($null -eq $finalPipeline -or $null -eq $finalPipeline.PSObject.Properties['capture_requests_queued'] -or
        [long]$finalPipeline.capture_requests_queued -ne $captureResults.Count) { $completedWork = $false }
    $shutdownUnanalyzed = @($events | Where-Object { $_.kind -eq 'coverage.shutdown_event' }).Count
    if ($shutdownUnanalyzed -ne 0) { $completedWork = $false }
    $services = @(Get-Service KnLiveDbg,KnLiveDbgProbe -ErrorAction SilentlyContinue)
    $sameBoot = $boot -eq (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
    $passed = -not $failure -and $results.Count -eq $modes.Count -and @($results | Where-Object { -not $_.passed }).Count -eq 0 -and
        (-not $ProbeDriver -or $driverEvents -gt 0) -and $services.Count -eq 0 -and $sameBoot -and
        $captures.Count -gt 0 -and $null -ne $finalPipeline -and $finalPipeline.final_drain -eq 'true' -and
        (-not $RequireQueueHealth -or $queueHealth) -and (-not $RequireCompletedWork -or $completedWork)
    [ordered]@{
        schema='kn-live-dbg.kmon-live-validation.v1'; passed=$passed
        started_utc=$started.ToString('o'); completed_utc=[DateTime]::UtcNow.ToString('o')
        binary_sha256=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
        fixture_sha256=(Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash
        observe_seconds=$ObserveSeconds; scenarios=$results; event_count=$eventCount
        probe_requested=[bool]$ProbeDriver; probe_lifecycle_events=$driverEvents
        capture_chunks_verified=$captures.Count; capture_bytes_verified=$captureBytes
        case_exports_verified=$runs.Count; layout_exports_verified=$runs.Count
        final_pipeline=$finalPipeline
        queue_health_required=[bool]$RequireQueueHealth; queue_health_passed=$queueHealth
        completed_work_required=[bool]$RequireCompletedWork; completed_work_passed=$completedWork
        image_completion_required=[bool]$RequireImageCompletion; image_sweep_fixtures=[bool]$ImageSweepFixtures
        image_stress_fixtures=[bool]$ImageStressFixtures
        all_process_layouts=[bool]$AllProcessLayouts; all_process_scope_verified=$allProcessScope
        layout_process_count=$layoutProcessCount
        layout_admission_ledger_passed=$layoutLedger; layout_verification_records=$layoutVerificationRecords
        layout_completion_records=$layoutCompletionRecords
        capture_results_verified=$captureResults.Count
        shutdown_events_unanalyzed=$shutdownUnanalyzed
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
