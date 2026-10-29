$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'kmon-reference-coverage.ps1')
$start = [datetime]'2026-01-01T00:00:00Z'
$end = $start.AddSeconds(60)
function New-ReferenceEvent([int]$Seconds, [string]$Status = 'partial') {
    [pscustomobject]@{kind='coverage.user_references'; pid=10; ts=$start.AddSeconds($Seconds).ToString('o')
        evidence=[pscustomobject]@{source_status=$Status; thread_records='1'; boot_id='synthetic-boot'
            process_create_time=$start.ToFileTimeUtc().ToString(); thread_inventory_complete='true'}}
}
function Assert-Reference($Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
$empty = Get-KmonReferenceCoverage @() 10 $start.ToString('o') $end
Assert-Reference ($empty.examined_observations -eq 0 -and $null -eq $empty.first_examined_seconds -and
    $empty.max_gap_seconds -eq 60) 'An absent source must retain the whole observation gap.'
$valid = Get-KmonReferenceCoverage @((New-ReferenceEvent 40), (New-ReferenceEvent 10)) 10 $start.ToString('o') $end
Assert-Reference ($valid.examined_observations -eq 2 -and $valid.complete_thread_inventories -eq 2 -and
    $valid.first_examined_seconds -eq 10 -and $valid.max_gap_seconds -eq 30) 'Unordered visits must include both window edges.'
$invalid = @((New-ReferenceEvent 1 'unavailable'), (New-ReferenceEvent 2 'failed'), (New-ReferenceEvent -1), (New-ReferenceEvent 61))
$reused = New-ReferenceEvent 5; $reused.evidence.process_create_time = $start.AddSeconds(1).ToFileTimeUtc().ToString(); $invalid += $reused
$zero = New-ReferenceEvent 5; $zero.evidence.thread_records = '0'; $invalid += $zero
$malformed = New-ReferenceEvent 5; $malformed.evidence.thread_records = '18446744073709551616'; $invalid += $malformed
$missing = New-ReferenceEvent 5; $missing.evidence.PSObject.Properties.Remove('source_status'); $invalid += $missing
$noBoot = New-ReferenceEvent 5; $noBoot.evidence.boot_id = ''; $invalid += $noBoot
$badTime = New-ReferenceEvent 5; $badTime.ts = 'invalid'; $invalid += $badTime
$unexamined = Get-KmonReferenceCoverage $invalid 10 $start.ToString('o') $end
Assert-Reference ($unexamined.examined_observations -eq 0 -and $unexamined.unexamined_observations -eq $invalid.Count -and
    $unexamined.max_gap_seconds -eq 60) 'Unavailable, wrong-instance and out-of-window rows cannot satisfy coverage.'
$wrongPid = New-ReferenceEvent 5; $wrongPid.pid = 11
$wrongKind = New-ReferenceEvent 5; $wrongKind.kind = 'coverage.user_callbacks'
$partial = New-ReferenceEvent 30; $partial.evidence.thread_inventory_complete = 'false'
$mixed = Get-KmonReferenceCoverage @($wrongPid, $wrongKind, $partial) 10 $start.ToString('o') $end
Assert-Reference ($mixed.observations -eq 1 -and $mixed.examined_observations -eq 1 -and
    $mixed.complete_thread_inventories -eq 0 -and $mixed.max_gap_seconds -eq 30) 'A bounded visit is distinct from thread inventory completion.'
# PowerShell 7 deserializes ISO timestamps as DateTime; Windows PowerShell
# keeps strings. Preserve subsecond identity and UTC in either representation.
$start = [datetime]'2026-01-01T00:00:00.1234567Z'
$roundTrip = [pscustomobject]@{started=$start.ToString('o'); event=(New-ReferenceEvent 10)} | ConvertTo-Json -Depth 4 | ConvertFrom-Json
$restored = Get-KmonReferenceCoverage @($roundTrip.event) 10 $roundTrip.started $start.AddSeconds(60)
Assert-Reference ($restored.examined_observations -eq 1 -and $restored.first_examined_seconds -eq 10 -and
    $restored.max_gap_seconds -eq 50) 'JSON timestamp conversion must preserve UTC and process identity precision.'
$rejected = $false
try { Get-KmonReferenceCoverage @() 10 $start.ToString('o') $start.AddSeconds(-1) | Out-Null }
catch { $rejected = $true }
Assert-Reference $rejected 'Reversed observation windows must fail.'
Write-Output '[kmon.reference-coverage] counterexamples passed'
