# Validate a metadata-only observation of the inert fixture's exact code page.
# This is a test expectation, not a production allowlist or a byte-finding exemption.
function Test-KmonSecondaryPageObservation($Event, $Mappings, [uint64]$SecondaryBase,
    [uint64]$RelocationBase, [string]$Scenario, [string]$StartedUtc, [string]$OutputDirectory)
{
    if ($Event.kind -ne 'finding.executable_memory' -or $Scenario -notmatch '^alias(32|64)-(clean|code|reloc)$') { return $false }
    $width = if ($Matches[1] -eq '32') { 4 } else { 8 }
    $mode = $Matches[2]
    $e = $Event.evidence
    foreach ($key in @('event_category', 'maliciousness', 'execution_observed', 'reference_role', 'termination',
        'hop_0_address', 'hop_0_target', 'hop_0_bytes_read', 'hop_0_capture_id', 'hop_0_hunt_reference',
        'process_create_time', 'compared_bytes')) {
        if (-not $e.PSObject.Properties[$key]) { return $false }
    }
    if ($e.event_category -ne 'observation' -or $e.maliciousness -ne 'not_established' -or
        $e.execution_observed -ne 'false' -or [long]$e.compared_bytes -ne 0 -or
        $e.reference_role -notin @('user_page_candidate', 'image_page_candidate') -or
        $e.termination -ne 'executable_page_checked; no_execution_reference' -or
        $e.hop_0_target -ne '0' -or $e.hop_0_bytes_read -ne '4096' -or $e.PSObject.Properties['hop_1_address'] -or
        [uint64]$e.process_create_time -ne ([datetime]$StartedUtc).ToUniversalTime().ToFileTimeUtc()) { return $false }
    [uint64]$address = $e.hop_0_address
    $bases = @($Mappings.Keys | Where-Object { $address -eq $_ + 4096 -or $address -eq $_ + 8192 })
    if ($bases.Count -ne 1 -or $e.hop_0_capture_id -notmatch '^\d+$') { return $false }
    $reference = $e.hop_0_hunt_reference | ConvertFrom-Json
    if ($reference.pid -ne $Event.pid -or $reference.create_time -ne $e.process_create_time -or
        [uint64]$reference.address -ne $address -or $reference.execution_observed -ne $false -or
        $reference.page_executable_verified -ne $true -or $reference.page_comparable -ne $false) { return $false }
    $files = @(Get-ChildItem -LiteralPath (Join-Path $OutputDirectory 'captures') -Filter "capture-*-$($e.hop_0_capture_id)-0.bin")
    if ($files.Count -ne 1) { return $false }
    $captured = [IO.File]::ReadAllBytes($files[0].FullName)
    # Keep this explicit oracle independent of the production PE normalizer.
    # tools/secondary-image-fixture.h defines two relocated pointers in 8 KiB of NOPs.
    [byte[]]$expected = @(0x90) * 8192
    $pointer = [BitConverter]::GetBytes([uint64]($RelocationBase + 0x1800))
    [Array]::Copy($pointer, 0, $expected, 0x100, $width)
    [Array]::Copy($pointer, 0, $expected, (0x1000 - ($width / 2)), $width)
    if ([uint64]$bases[0] -eq $SecondaryBase -and $mode -ne 'clean') {
        $at = if ($mode -eq 'reloc') { 0x100 } else { 0x200 }
        $expected[$at] = $expected[$at] -bxor 1
    }
    [byte[]]$page = New-Object byte[] 4096
    [Array]::Copy($expected, [int]($address - [uint64]$bases[0] - 4096), $page, 0, 4096)
    $hash = [Security.Cryptography.SHA256]::Create()
    try { $digest = [BitConverter]::ToString($hash.ComputeHash($captured)).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
    return $captured.Length -eq 4096 -and $digest -eq $reference.page_sha256 -and
        [Convert]::ToBase64String($captured) -ceq [Convert]::ToBase64String($page)
}
