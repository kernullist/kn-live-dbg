param(
    [string]$Root = (Get-Location).Path
)

$ErrorActionPreference = "Stop"

$rootPath = (Resolve-Path -LiteralPath $Root).Path
$analyzer = Join-Path $rootPath "tools\analyze-hunt-clean-host.ps1"
$outputDirectory = Join-Path $rootPath ".build\hunt-clean-host-analysis-selftest"
New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null

function Get-FileSha256
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $stream =
        [IO.File]::Open(
            $Path,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read)
    $sha256 =
        [Security.Cryptography.SHA256]::Create()
    try
    {
        $hashBytes =
            $sha256.ComputeHash($stream)
    }
    finally
    {
        $sha256.Dispose()
        $stream.Dispose()
    }

    return (
        [BitConverter]::ToString(
            $hashBytes)).Replace("-", "")
}

function New-Finding
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Reason,

        [Parameter(Mandatory = $true)]
        [string]$Image,

        [Parameter(Mandatory = $true)]
        [int]$ProcessId,

        [Parameter(Mandatory = $true)]
        [string]$Address
    )

    return [ordered]@{
        risk = "low"
        confidence = "medium"
        class = "mapped_code"
        title = "synthetic finding"
        pid = $ProcessId
        eprocess = "0xffff000000000000"
        address = $Address
        image = $Image
        module = ""
        reasons = @($Reason)
        evidence = [ordered]@{
            vad = $Address
            semantic = $Reason
        }
        followups = @()
    }
}

function New-HuntDocument
{
    param(
        [object[]]$Findings = @(),
        [bool]$CoverageComplete = $true,
        [string]$Timestamp = "2026-07-28T00:00:00.000Z"
    )

    return [ordered]@{
        schema = "kn-live-dbg.hunt.v1"
        timestamp_utc = $Timestamp
        mode = "default"
        summary = [ordered]@{
            kernel_processes = 100
            system_process_information_processes = 100
            toolhelp_processes = 100
            system_process_information_threads = 500
            toolhelp_threads = 500
            scanned_processes = 100
            findings = $Findings.Count
            high = 0
            medium = 0
            low = $Findings.Count
            info = 0
            wfp_filters = 0
            suspicious_wfp_filters = 0
            qos_policies = 0
            suspicious_qos_policies = 0
            bindflt_global_mappings = 0
            suspicious_bindflt_global_mappings = 0
            bindflt_process_bindings = 0
            cloudfiles_placeholder_images = 0
            suspicious_cloudfiles_images = 0
            wfp_filter_coverage_incomplete = $false
            qos_policy_coverage_incomplete = $false
            bindflt_global_coverage_incomplete = $false
            bindflt_process_correlation_coverage_incomplete = $false
            bindflt_silo_coverage_unsupported = $true
            cloudfiles_placeholder_coverage_incomplete = $false
            cloudfiles_protection_correlation_incomplete = $false
            process_inventory_incomplete = $false
            cid_table_full_enumeration = $true
            cid_table_full_process_enumeration = $true
            cid_table_direct_entry_enumeration = $true
            cid_table_full_thread_enumeration = $true
            cid_table_thread_cross_view_complete = $true
            cid_table_lookup_only = $false
            cid_table_anchor = "0xfffff80000001000"
            cid_table_address = "0xfffff80000002000"
            cid_table_code = "0xfffff80000003001"
            cid_table_level = 1
            cid_table_next_handle = 2048
            cid_table_allocated_leaves = 2
            cid_table_allocated_handle_capacity = 2048
            cid_table_probes = 511
            cid_table_processes = 100
            cid_table_discovered_processes = 0
            cid_table_direct_entries = 101
            cid_table_direct_processes = 100
            cid_table_direct_threads = 1
            cid_table_unclassified_entries = 0
            cid_table_thread_findings = 0
            cid_table_persistent_thread_view_misses = 0
            cid_table_probe_failures = 0
            cid_table_persistent_api_misses = 0
            process_triage_coverage_incomplete = -not $CoverageComplete
            deep_image_comparison_coverage_incomplete = $false
            driver_service_coverage_incomplete = $false
            threat_intel_active = $false
            threat_intel_available = $false
            threat_intel_correlation_incomplete = $false
            coverage_complete = $CoverageComplete
        }
        warnings = @()
        findings = $Findings
        cloudfiles_images = @()
        cid_threads = @(
            [ordered]@{
                tid = 8
                pid = 4
                object_header = "0xfffff80000004000"
                ethread = "0xfffff80000004030"
                eprocess = "0xfffff80000005000"
                create_time = "0x0000000000000001"
                exit_time = "0x0000000000000000"
                terminated = $false
                direct_cid_seen = $true
                executive_thread_list_seen = $true
                scheduler_thread_list_seen = $true
                system_process_information_seen = $true
                toolhelp_seen = $true
                identity_revalidated = $true
                views_revalidated = $true
                lifecycle_changed = $false
                suspicious = $false
                reasons = @()
                warnings = @()
            }
        )
        processes = @()
    }
}

function Invoke-AnalyzerFailureCase
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [object]$Document,

        [switch]$RequireThreatIntelActive
    )

    $path = Join-Path $outputDirectory "$Name.json"
    $reportPath = Join-Path $outputDirectory "$Name-report.json"
    $Document |
        ConvertTo-Json -Depth 12 |
        Set-Content -LiteralPath $path -Encoding UTF8
    Remove-Item -LiteralPath $reportPath -Force -ErrorAction SilentlyContinue

    $failed = $false
    try
    {
        if ($RequireThreatIntelActive)
        {
            & $analyzer -HuntJson $path -OutputJson $reportPath -RequireThreatIntelActive *> $null
        }
        else
        {
            & $analyzer -HuntJson $path -OutputJson $reportPath *> $null
        }
    }
    catch
    {
        $failed = $true
    }
    if (-not $failed)
    {
        throw "$Name expected analyzer failure"
    }
    if (Test-Path -LiteralPath $reportPath)
    {
        throw "$Name wrote a report for rejected input"
    }
    Write-Host "[hunt-clean-analyzer-selftest] pass case=$Name"
}

$sharedRun1 = New-Finding -Reason "shared_reason" -Image "C:\Windows\clean.exe" -ProcessId 1001 -Address "0x1000"
$sharedRun2 = New-Finding -Reason "shared_reason" -Image "D:\Different\CLEAN.EXE" -ProcessId 2002 -Address "0x9000"
$intermittent = New-Finding -Reason "intermittent_reason" -Image "other.exe" -ProcessId 1002 -Address "0x2000"

$run1Path = Join-Path $outputDirectory "findings-run-01.json"
$run2Path = Join-Path $outputDirectory "findings-run-02.json"
$reportPath = Join-Path $outputDirectory "findings-report.json"
New-HuntDocument -Findings @($sharedRun1, $intermittent) |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $run1Path -Encoding UTF8
New-HuntDocument -Findings @($sharedRun2) -Timestamp "2026-07-28T00:01:00.000Z" |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $run2Path -Encoding UTF8

& $analyzer -HuntJson @($run1Path, $run2Path) -OutputJson $reportPath
$report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
if ([int]$report.summary.run_count -ne 2 -or
    [int]$report.summary.total_findings -ne 3 -or
    [int]$report.summary.unique_fingerprints -ne 2 -or
    [int]$report.summary.deterministic_fingerprints -ne 1 -or
    [int]$report.summary.intermittent_fingerprints -ne 1 -or
    [bool]$report.summary.all_clean_complete)
{
    throw "finding recurrence analysis contract failed"
}

$deterministic = @($report.finding_groups | Where-Object { $_.recurrence -eq "deterministic" })
if ($deterministic.Count -ne 1 -or
    [int]$deterministic[0].run_hits -ne 2 -or
    [string]$deterministic[0].image -ne "clean.exe")
{
    throw "semantic fingerprint did not normalize PID/address/path differences"
}

$cleanRun1Path = Join-Path $outputDirectory "clean-run-01.json"
$cleanRun2Path = Join-Path $outputDirectory "clean-run-02.json"
$cleanReportPath = Join-Path $outputDirectory "clean-report.json"
New-HuntDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $cleanRun1Path -Encoding UTF8
New-HuntDocument -Timestamp "2026-07-28T00:02:00.000Z" |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $cleanRun2Path -Encoding UTF8

$cleanWildcard = Join-Path $outputDirectory "clean-run-*.json"
& $analyzer -HuntJson @($cleanWildcard, $cleanRun1Path) -OutputJson $cleanReportPath
$cleanReport = Get-Content -LiteralPath $cleanReportPath -Raw | ConvertFrom-Json
if (-not [bool]$cleanReport.summary.all_clean_complete -or
    [int]$cleanReport.summary.unique_fingerprints -ne 0 -or
    [int]$cleanReport.summary.run_count -ne 2)
{
    throw "clean wildcard/deduplication analysis contract failed"
}

$threatIntelRunPath = Join-Path $outputDirectory "threat-intel-run.json"
$threatIntelReportPath = Join-Path $outputDirectory "threat-intel-report.json"
$threatIntelRun = New-HuntDocument
$threatIntelRun.summary.threat_intel_active = $true
$threatIntelRun.summary.threat_intel_available = $true
$threatIntelRun |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $threatIntelRunPath -Encoding UTF8
& $analyzer -HuntJson $threatIntelRunPath -OutputJson $threatIntelReportPath -RequireThreatIntelActive
if (-not (Test-Path -LiteralPath $threatIntelReportPath))
{
    throw "required threat-intel analyzer case did not write a report"
}

$incompleteRunPath = Join-Path $outputDirectory "incomplete-run.json"
$incompleteReportPath = Join-Path $outputDirectory "incomplete-report.json"
New-HuntDocument -CoverageComplete $false |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $incompleteRunPath -Encoding UTF8
& $analyzer -HuntJson @($cleanRun1Path, $incompleteRunPath) -OutputJson $incompleteReportPath
$incompleteReport = Get-Content -LiteralPath $incompleteReportPath -Raw | ConvertFrom-Json
if ([bool]$incompleteReport.summary.all_clean_complete -or
    [int]$incompleteReport.summary.complete_runs -ne 1)
{
    throw "incomplete coverage was incorrectly promoted to clean"
}

$wrongBoolean = New-HuntDocument
$wrongBoolean.summary.coverage_complete = "false"
Invoke-AnalyzerFailureCase -Name "wrong-boolean-type" -Document $wrongBoolean

$wrongInteger = New-HuntDocument
$wrongInteger.summary.findings = "0"
Invoke-AnalyzerFailureCase -Name "wrong-integer-type" -Document $wrongInteger

$riskMismatch = New-HuntDocument
$riskMismatch.summary.high = 1
Invoke-AnalyzerFailureCase -Name "risk-count-mismatch" -Document $riskMismatch

$coverageConflict = New-HuntDocument
$coverageConflict.summary.process_inventory_incomplete = $true
Invoke-AnalyzerFailureCase -Name "coverage-flag-conflict" -Document $coverageConflict

$threatIntelConflict = New-HuntDocument
$threatIntelConflict.summary.threat_intel_correlation_incomplete = $true
Invoke-AnalyzerFailureCase -Name "threat-intel-coverage-conflict" -Document $threatIntelConflict

$wfpConflict = New-HuntDocument
$wfpConflict.summary.wfp_filter_coverage_incomplete = $true
Invoke-AnalyzerFailureCase -Name "wfp-coverage-conflict" -Document $wfpConflict

$qosConflict = New-HuntDocument
$qosConflict.summary.qos_policy_coverage_incomplete = $true
Invoke-AnalyzerFailureCase -Name "qos-coverage-conflict" -Document $qosConflict

$bindConflict = New-HuntDocument
$bindConflict.summary.bindflt_global_coverage_incomplete = $true
Invoke-AnalyzerFailureCase -Name "bind-coverage-conflict" -Document $bindConflict

$bindProcessConflict = New-HuntDocument
$bindProcessConflict.summary.bindflt_process_correlation_coverage_incomplete = $true
Invoke-AnalyzerFailureCase -Name "bind-process-coverage-conflict" -Document $bindProcessConflict

$cloudMetadataConflict = New-HuntDocument
$cloudMetadataConflict.summary.cloudfiles_placeholder_coverage_incomplete = $true
Invoke-AnalyzerFailureCase -Name "cloud-metadata-coverage-conflict" -Document $cloudMetadataConflict

$cloudProtectionConflict = New-HuntDocument
$cloudProtectionConflict.summary.cloudfiles_protection_correlation_incomplete = $true
Invoke-AnalyzerFailureCase -Name "cloud-protection-coverage-conflict" -Document $cloudProtectionConflict

$cloudCountMismatch = New-HuntDocument
$cloudCountMismatch.summary.cloudfiles_placeholder_images = 1
Invoke-AnalyzerFailureCase -Name "cloud-observation-count-mismatch" -Document $cloudCountMismatch

$newCounterWrongType = New-HuntDocument
$newCounterWrongType.summary.bindflt_global_mappings = "0"
Invoke-AnalyzerFailureCase -Name "new-counter-wrong-type" -Document $newCounterWrongType

$wfpDetectorCountMismatch = New-HuntDocument
$wfpDetectorCountMismatch.summary.wfp_filters = 1
$wfpDetectorCountMismatch.summary.suspicious_wfp_filters = 1
Invoke-AnalyzerFailureCase -Name "wfp-detector-count-mismatch" -Document $wfpDetectorCountMismatch

$qosDetectorCountMismatch = New-HuntDocument
$qosDetectorCountMismatch.summary.qos_policies = 1
$qosDetectorCountMismatch.summary.suspicious_qos_policies = 1
Invoke-AnalyzerFailureCase -Name "qos-detector-count-mismatch" -Document $qosDetectorCountMismatch

$bindDetectorCountMismatch = New-HuntDocument
$bindDetectorCountMismatch.summary.bindflt_global_mappings = 1
$bindDetectorCountMismatch.summary.suspicious_bindflt_global_mappings = 1
Invoke-AnalyzerFailureCase -Name "bind-detector-count-mismatch" -Document $bindDetectorCountMismatch

$bindProcessCountMismatch = New-HuntDocument
$bindProcessCountMismatch.summary.bindflt_process_bindings = 1
Invoke-AnalyzerFailureCase -Name "bind-process-count-mismatch" -Document $bindProcessCountMismatch

$cloudDetectorCountMismatch = New-HuntDocument
$cloudDetectorCountMismatch.summary.cloudfiles_placeholder_images = 1
$cloudDetectorCountMismatch.summary.suspicious_cloudfiles_images = 1
$cloudDetectorCountMismatch.cloudfiles_images = @(
    [ordered]@{
        suspicious = $true
    }
)
Invoke-AnalyzerFailureCase -Name "cloud-detector-count-mismatch" -Document $cloudDetectorCountMismatch

$siloWrongType = New-HuntDocument
$siloWrongType.summary.bindflt_silo_coverage_unsupported = "true"
Invoke-AnalyzerFailureCase -Name "silo-flag-wrong-type" -Document $siloWrongType

$cidFallback = New-HuntDocument
$cidFallback.summary.cid_table_full_process_enumeration = $false
$cidFallback.summary.cid_table_lookup_only = $true
Invoke-AnalyzerFailureCase -Name "cid-fallback-complete" -Document $cidFallback

$cidOverclaim = New-HuntDocument
$cidOverclaim.summary.cid_table_full_enumeration = $false
Invoke-AnalyzerFailureCase -Name "cid-whole-table-overclaim" -Document $cidOverclaim

$cidFlagConflict = New-HuntDocument
$cidFlagConflict.summary.cid_table_lookup_only = $true
Invoke-AnalyzerFailureCase -Name "cid-full-and-lookup-only" -Document $cidFlagConflict

$cidTopologyMismatch = New-HuntDocument
$cidTopologyMismatch.summary.cid_table_allocated_handle_capacity = 4096
Invoke-AnalyzerFailureCase -Name "cid-topology-mismatch" -Document $cidTopologyMismatch

$cidProbeShort = New-HuntDocument
$cidProbeShort.summary.cid_table_probes = 510
Invoke-AnalyzerFailureCase -Name "cid-probe-short" -Document $cidProbeShort

$cidZeroAnchor = New-HuntDocument
$cidZeroAnchor.summary.cid_table_anchor = "0x0000000000000000"
Invoke-AnalyzerFailureCase -Name "cid-zero-anchor" -Document $cidZeroAnchor

$cidPersistentApiMiss = New-HuntDocument
$cidPersistentApiMiss.summary.cid_table_persistent_api_misses = 1
Invoke-AnalyzerFailureCase -Name "cid-persistent-api-miss" -Document $cidPersistentApiMiss

$cidDirectEntryIncomplete = New-HuntDocument
$cidDirectEntryIncomplete.summary.cid_table_direct_entry_enumeration = $false
Invoke-AnalyzerFailureCase -Name "cid-direct-entry-incomplete" -Document $cidDirectEntryIncomplete

$cidThreadIncomplete = New-HuntDocument
$cidThreadIncomplete.summary.cid_table_full_thread_enumeration = $false
Invoke-AnalyzerFailureCase -Name "cid-thread-incomplete" -Document $cidThreadIncomplete

$cidCrossViewIncomplete = New-HuntDocument
$cidCrossViewIncomplete.summary.cid_table_thread_cross_view_complete = $false
Invoke-AnalyzerFailureCase -Name "cid-thread-cross-view-incomplete" -Document $cidCrossViewIncomplete

$cidUnclassified = New-HuntDocument
$cidUnclassified.summary.cid_table_unclassified_entries = 1
Invoke-AnalyzerFailureCase -Name "cid-unclassified-entry" -Document $cidUnclassified

$cidDirectCountMismatch = New-HuntDocument
$cidDirectCountMismatch.summary.cid_table_direct_entries = 102
Invoke-AnalyzerFailureCase -Name "cid-direct-count-mismatch" -Document $cidDirectCountMismatch

$cidThreadsMissing = New-HuntDocument
$cidThreadsMissing.Remove("cid_threads")
Invoke-AnalyzerFailureCase -Name "cid-threads-missing" -Document $cidThreadsMissing

$cidThreadIdentityUnstable = New-HuntDocument
$cidThreadIdentityUnstable.cid_threads[0].identity_revalidated = $false
Invoke-AnalyzerFailureCase -Name "cid-thread-identity-unstable" -Document $cidThreadIdentityUnstable

$activeUnavailable = New-HuntDocument
$activeUnavailable.summary.threat_intel_active = $true
Invoke-AnalyzerFailureCase -Name "threat-intel-active-unavailable" -Document $activeUnavailable

$inactiveAvailable = New-HuntDocument
$inactiveAvailable.summary.threat_intel_available = $true
Invoke-AnalyzerFailureCase -Name "threat-intel-inactive-required" -Document $inactiveAvailable -RequireThreatIntelActive

$nonArray = New-HuntDocument
$nonArray.findings = [ordered]@{}
Invoke-AnalyzerFailureCase -Name "findings-not-array" -Document $nonArray

$scalarReasonsFinding =
    New-Finding `
        -Reason "shared_reason" `
        -Image "clean.exe" `
        -ProcessId 1001 `
        -Address "0x1000"
$scalarReasonsFinding.reasons =
    "shared_reason"
$scalarReasons =
    New-HuntDocument `
        -Findings @($scalarReasonsFinding)
Invoke-AnalyzerFailureCase `
    -Name "finding-reasons-not-array" `
    -Document $scalarReasons

$inputHashBefore =
    Get-FileSha256 -Path $cleanRun1Path
$inputCollisionRejected = $false
try
{
    & $analyzer `
        -HuntJson $cleanRun1Path `
        -OutputJson $cleanRun1Path *> $null
}
catch
{
    $inputCollisionRejected = $true
}
$inputHashAfter =
    Get-FileSha256 -Path $cleanRun1Path
if (-not $inputCollisionRejected -or
    $inputHashBefore -ne $inputHashAfter)
{
    throw "analyzer did not reject an output path that aliases its input"
}
Write-Host "[hunt-clean-analyzer.selftest] pass case=input-output-path-collision"

$sharedOutputPath = Join-Path $outputDirectory "shared-output-path.json"
Remove-Item -LiteralPath $sharedOutputPath -Force -ErrorAction SilentlyContinue
$outputCollisionRejected = $false
try
{
    & $analyzer `
        -HuntJson $cleanRun1Path `
        -OutputJson $sharedOutputPath `
        -OutputMarkdown $sharedOutputPath *> $null
}
catch
{
    $outputCollisionRejected = $true
}
if (-not $outputCollisionRejected -or
    (Test-Path -LiteralPath $sharedOutputPath))
{
    throw "analyzer did not reject colliding JSON and Markdown outputs before writing"
}
Write-Host "[hunt-clean-analyzer.selftest] pass case=report-output-path-collision"

Write-Host "hunt clean-host analyzer self-test passed"
exit 0
