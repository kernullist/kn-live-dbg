# Count examined metadata from the retained fixture instance within its live
# observation window. A coverage event alone can describe an unavailable source.
function Get-KmonReferenceCoverage($Events, [uint32]$ProcessId, [datetime]$StartedUtc, [datetime]$UntilUtc)
{
    $start = $StartedUtc.ToUniversalTime()
    $end = $UntilUtc.ToUniversalTime()
    if ($end -lt $start) { throw 'Reference observation window ends before process creation.' }
    $created = $start.ToFileTimeUtc().ToString()
    $records = @($Events | Where-Object { $_.kind -eq 'coverage.user_references' -and $_.pid -eq $ProcessId })
    $times = [Collections.Generic.List[datetime]]::new()
    $complete = 0
    foreach ($event in $records) {
        $e = $event.PSObject.Properties['evidence']
        if ($null -eq $e -or $null -eq $e.Value) { continue }
        $e = $e.Value
        $valid = $true
        foreach ($key in @('source_status', 'thread_records', 'process_create_time', 'boot_id', 'thread_inventory_complete')) {
            if ($null -eq $e.PSObject.Properties[$key]) { $valid = $false }
        }
        if (-not $valid -or $e.source_status -ne 'partial' -or
            $e.process_create_time -cne $created -or [string]::IsNullOrWhiteSpace($e.boot_id)) { continue }
        [uint64]$threads = 0
        if (-not [uint64]::TryParse([string]$e.thread_records, [ref]$threads) -or $threads -eq 0) { continue }
        if ($null -eq $event.PSObject.Properties['ts']) { continue }
        [datetime]$at = [datetime]::MinValue
        if ($event.ts -is [datetime]) { $at = $event.ts }
        elseif (-not [datetime]::TryParse([string]$event.ts, [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind, [ref]$at)) { continue }
        $at = $at.ToUniversalTime()
        if ($at -lt $start -or $at -gt $end) { continue }
        $times.Add($at)
        if ($e.thread_inventory_complete -eq 'true') { ++$complete }
    }
    $ordered = @($times | Sort-Object)
    $previous = $start
    $maxGap = 0.0
    foreach ($at in $ordered) {
        $maxGap = [Math]::Max($maxGap, ($at - $previous).TotalSeconds)
        $previous = $at
    }
    $maxGap = [Math]::Max($maxGap, ($end - $previous).TotalSeconds)
    return [pscustomobject]@{
        observations=$records.Count
        examined_observations=$times.Count
        unexamined_observations=($records.Count - $times.Count)
        complete_thread_inventories=$complete
        first_examined_seconds=$(if ($ordered.Count) { ($ordered[0] - $start).TotalSeconds } else { $null })
        max_gap_seconds=$maxGap
    }
}
