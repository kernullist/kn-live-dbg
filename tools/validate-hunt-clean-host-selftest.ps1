param(
    [string]$Root = (Get-Location).Path
)

$ErrorActionPreference = "Stop"

$rootPath = (Resolve-Path -LiteralPath $Root).Path
$validator = Join-Path $rootPath "tools\validate-hunt-clean-host.ps1"
$outputDirectory = Join-Path $rootPath ".build\hunt-clean-host-validator-selftest"
New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null

function New-HuntDocument
{
    param(
        [bool]$CoverageComplete = $true,
        [object[]]$Findings = @()
    )

    $riskCounts = @{
        high = @($Findings | Where-Object { $_.risk -eq "high" }).Count
        medium = @($Findings | Where-Object { $_.risk -eq "medium" }).Count
        low = @($Findings | Where-Object { $_.risk -eq "low" }).Count
        info = @($Findings | Where-Object { $_.risk -eq "info" }).Count
    }

    return [ordered]@{
        schema = "kn-live-dbg.hunt.v1"
        timestamp_utc = "2026-07-28T00:00:00.000Z"
        mode = "deep"
        summary = [ordered]@{
            kernel_processes = 100
            system_process_information_processes = 100
            toolhelp_processes = 100
            system_process_information_threads = 500
            toolhelp_threads = 500
            scanned_processes = 100
            findings = $Findings.Count
            high = $riskCounts.high
            medium = $riskCounts.medium
            low = $riskCounts.low
            info = $riskCounts.info
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
            process_triage_coverage_incomplete = $false
            deep_image_comparison_coverage_incomplete = $false
            driver_service_coverage_incomplete = $false
            threat_intel_active = $true
            threat_intel_available = $true
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

function Invoke-ValidatorCase
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [bool]$ExpectSuccess,

        [ValidateSet("Any", "Quick", "Default", "Deep")]
        [string]$RequireMode = "Deep",

        [switch]$RequireThreatIntelActive
    )

    $logPath = Join-Path $outputDirectory "$Name.log"
    $validatorArguments = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $validator,
        "-HuntJson", $Path,
        "-RequireMode", $RequireMode
    )
    if ($RequireThreatIntelActive)
    {
        $validatorArguments +=
            "-RequireThreatIntelActive"
    }
    & powershell.exe @validatorArguments *> $logPath
    $exitCode = $LASTEXITCODE

    if ($ExpectSuccess -and $exitCode -ne 0)
    {
        Get-Content -LiteralPath $logPath | Out-Host
        throw "$Name expected success, exit=$exitCode"
    }
    if (-not $ExpectSuccess -and $exitCode -eq 0)
    {
        Get-Content -LiteralPath $logPath | Out-Host
        throw "$Name expected failure"
    }

    Write-Host "[hunt-clean-selftest] pass case=$Name exit=$exitCode"
}

$cleanPath = Join-Path $outputDirectory "clean.json"
$findingPath = Join-Path $outputDirectory "finding.json"
$incompletePath = Join-Path $outputDirectory "incomplete.json"
$wrongTypePath = Join-Path $outputDirectory "wrong-type.json"
$wrongIntegerPath = Join-Path $outputDirectory "wrong-integer.json"
$invalidModePath = Join-Path $outputDirectory "invalid-mode.json"
$nonArrayPath = Join-Path $outputDirectory "non-array.json"
$riskMismatchPath = Join-Path $outputDirectory "risk-mismatch.json"
$coverageConflictPath = Join-Path $outputDirectory "coverage-conflict.json"
$threatIntelConflictPath = Join-Path $outputDirectory "threat-intel-conflict.json"
$threatIntelUnavailablePath = Join-Path $outputDirectory "threat-intel-unavailable.json"
$threatIntelInactivePath = Join-Path $outputDirectory "threat-intel-inactive.json"
$wfpIncompletePath = Join-Path $outputDirectory "wfp-incomplete.json"
$qosIncompletePath = Join-Path $outputDirectory "qos-incomplete.json"
$bindGlobalIncompletePath = Join-Path $outputDirectory "bind-global-incomplete.json"
$bindProcessIncompletePath = Join-Path $outputDirectory "bind-process-incomplete.json"
$cloudMetadataIncompletePath = Join-Path $outputDirectory "cloud-metadata-incomplete.json"
$cloudProtectionIncompletePath = Join-Path $outputDirectory "cloud-protection-incomplete.json"
$newCounterWrongTypePath = Join-Path $outputDirectory "new-counter-wrong-type.json"
$suspiciousWfpPath = Join-Path $outputDirectory "suspicious-wfp.json"
$suspiciousQosPath = Join-Path $outputDirectory "suspicious-qos.json"
$suspiciousBindPath = Join-Path $outputDirectory "suspicious-bind.json"
$bindProcessPath = Join-Path $outputDirectory "bind-process.json"
$cloudCountMismatchPath = Join-Path $outputDirectory "cloud-count-mismatch.json"
$siloWrongTypePath = Join-Path $outputDirectory "silo-wrong-type.json"
$cidFallbackPath = Join-Path $outputDirectory "cid-fallback.json"
$cidOverclaimPath = Join-Path $outputDirectory "cid-overclaim.json"
$cidTopologyMismatchPath = Join-Path $outputDirectory "cid-topology-mismatch.json"
$cidProbeFailurePath = Join-Path $outputDirectory "cid-probe-failure.json"
$cidProbeShortPath = Join-Path $outputDirectory "cid-probe-short.json"
$cidZeroAnchorPath = Join-Path $outputDirectory "cid-zero-anchor.json"
$cidPersistentApiMissPath = Join-Path $outputDirectory "cid-persistent-api-miss.json"
$cidDirectEntryIncompletePath = Join-Path $outputDirectory "cid-direct-entry-incomplete.json"
$cidThreadIncompletePath = Join-Path $outputDirectory "cid-thread-incomplete.json"
$cidCrossViewIncompletePath = Join-Path $outputDirectory "cid-cross-view-incomplete.json"
$cidUnclassifiedPath = Join-Path $outputDirectory "cid-unclassified.json"
$cidDirectCountMismatchPath = Join-Path $outputDirectory "cid-direct-count-mismatch.json"
$cidThreadsMissingPath = Join-Path $outputDirectory "cid-threads-missing.json"
$cidThreadIdentityUnstablePath = Join-Path $outputDirectory "cid-thread-identity-unstable.json"
$malformedPath = Join-Path $outputDirectory "malformed.json"

New-HuntDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $cleanPath -Encoding UTF8

$finding = [ordered]@{
    risk = "medium"
    confidence = "medium"
    class = "process_identity"
    title = "synthetic false positive"
    pid = 1234
    eprocess = "0x0000000000000000"
    address = "0x0000000000000000"
    image = "clean.exe"
    module = ""
    reasons = @("synthetic_reason")
    evidence = [ordered]@{ source = "selftest" }
    followups = @()
}
New-HuntDocument -Findings @($finding) |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $findingPath -Encoding UTF8

New-HuntDocument -CoverageComplete $false |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $incompletePath -Encoding UTF8

$wrongTypeDocument = New-HuntDocument
$wrongTypeDocument.summary.coverage_complete = "true"
$wrongTypeDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $wrongTypePath -Encoding UTF8

$wrongIntegerDocument = New-HuntDocument
$wrongIntegerDocument.summary.findings = "0"
$wrongIntegerDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $wrongIntegerPath -Encoding UTF8

$invalidModeDocument = New-HuntDocument
$invalidModeDocument.mode = "anything"
$invalidModeDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $invalidModePath -Encoding UTF8

$nonArrayDocument = New-HuntDocument
$nonArrayDocument.findings = [ordered]@{}
$nonArrayDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $nonArrayPath -Encoding UTF8

$riskMismatchDocument = New-HuntDocument
$riskMismatchDocument.summary.high = 1
$riskMismatchDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $riskMismatchPath -Encoding UTF8

$coverageConflictDocument = New-HuntDocument
$coverageConflictDocument.summary.process_inventory_incomplete = $true
$coverageConflictDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $coverageConflictPath -Encoding UTF8

$threatIntelConflictDocument = New-HuntDocument
$threatIntelConflictDocument.summary.threat_intel_correlation_incomplete = $true
$threatIntelConflictDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $threatIntelConflictPath -Encoding UTF8

$threatIntelUnavailableDocument = New-HuntDocument
$threatIntelUnavailableDocument.summary.threat_intel_active = $false
$threatIntelUnavailableDocument.summary.threat_intel_available = $false
$threatIntelUnavailableDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $threatIntelUnavailablePath -Encoding UTF8

$threatIntelInactiveDocument = New-HuntDocument
$threatIntelInactiveDocument.summary.threat_intel_active = $false
$threatIntelInactiveDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $threatIntelInactivePath -Encoding UTF8

$wfpIncompleteDocument = New-HuntDocument
$wfpIncompleteDocument.summary.wfp_filter_coverage_incomplete = $true
$wfpIncompleteDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $wfpIncompletePath -Encoding UTF8

$qosIncompleteDocument = New-HuntDocument
$qosIncompleteDocument.summary.qos_policy_coverage_incomplete = $true
$qosIncompleteDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $qosIncompletePath -Encoding UTF8

$bindGlobalIncompleteDocument = New-HuntDocument
$bindGlobalIncompleteDocument.summary.bindflt_global_coverage_incomplete = $true
$bindGlobalIncompleteDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $bindGlobalIncompletePath -Encoding UTF8

$bindProcessIncompleteDocument = New-HuntDocument
$bindProcessIncompleteDocument.summary.bindflt_process_correlation_coverage_incomplete = $true
$bindProcessIncompleteDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $bindProcessIncompletePath -Encoding UTF8

$cloudMetadataIncompleteDocument = New-HuntDocument
$cloudMetadataIncompleteDocument.summary.cloudfiles_placeholder_coverage_incomplete = $true
$cloudMetadataIncompleteDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $cloudMetadataIncompletePath -Encoding UTF8

$cloudProtectionIncompleteDocument = New-HuntDocument
$cloudProtectionIncompleteDocument.summary.cloudfiles_protection_correlation_incomplete = $true
$cloudProtectionIncompleteDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $cloudProtectionIncompletePath -Encoding UTF8

$newCounterWrongTypeDocument = New-HuntDocument
$newCounterWrongTypeDocument.summary.qos_policies = "0"
$newCounterWrongTypeDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $newCounterWrongTypePath -Encoding UTF8

$suspiciousWfpDocument = New-HuntDocument
$suspiciousWfpDocument.summary.wfp_filters = 1
$suspiciousWfpDocument.summary.suspicious_wfp_filters = 1
$suspiciousWfpDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $suspiciousWfpPath -Encoding UTF8

$suspiciousQosDocument = New-HuntDocument
$suspiciousQosDocument.summary.qos_policies = 1
$suspiciousQosDocument.summary.suspicious_qos_policies = 1
$suspiciousQosDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $suspiciousQosPath -Encoding UTF8

$suspiciousBindDocument = New-HuntDocument
$suspiciousBindDocument.summary.bindflt_global_mappings = 1
$suspiciousBindDocument.summary.suspicious_bindflt_global_mappings = 1
$suspiciousBindDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $suspiciousBindPath -Encoding UTF8

$bindProcessDocument = New-HuntDocument
$bindProcessDocument.summary.bindflt_process_bindings = 1
$bindProcessDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $bindProcessPath -Encoding UTF8

$cloudCountMismatchDocument = New-HuntDocument
$cloudCountMismatchDocument.summary.cloudfiles_placeholder_images = 1
$cloudCountMismatchDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $cloudCountMismatchPath -Encoding UTF8

$siloWrongTypeDocument = New-HuntDocument
$siloWrongTypeDocument.summary.bindflt_silo_coverage_unsupported = "true"
$siloWrongTypeDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $siloWrongTypePath -Encoding UTF8

$cidFallbackDocument = New-HuntDocument
$cidFallbackDocument.summary.cid_table_full_process_enumeration = $false
$cidFallbackDocument.summary.cid_table_lookup_only = $true
$cidFallbackDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $cidFallbackPath -Encoding UTF8

$cidOverclaimDocument = New-HuntDocument
$cidOverclaimDocument.summary.cid_table_full_enumeration = $false
$cidOverclaimDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $cidOverclaimPath -Encoding UTF8

$cidTopologyMismatchDocument = New-HuntDocument
$cidTopologyMismatchDocument.summary.cid_table_allocated_handle_capacity = 4096
$cidTopologyMismatchDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $cidTopologyMismatchPath -Encoding UTF8

$cidProbeFailureDocument = New-HuntDocument
$cidProbeFailureDocument.summary.cid_table_probe_failures = 1
$cidProbeFailureDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $cidProbeFailurePath -Encoding UTF8

$cidProbeShortDocument = New-HuntDocument
$cidProbeShortDocument.summary.cid_table_probes = 510
$cidProbeShortDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $cidProbeShortPath -Encoding UTF8

$cidZeroAnchorDocument = New-HuntDocument
$cidZeroAnchorDocument.summary.cid_table_anchor = "0x0000000000000000"
$cidZeroAnchorDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $cidZeroAnchorPath -Encoding UTF8

$cidPersistentApiMissDocument = New-HuntDocument
$cidPersistentApiMissDocument.summary.cid_table_persistent_api_misses = 1
$cidPersistentApiMissDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $cidPersistentApiMissPath -Encoding UTF8

$cidDirectEntryIncompleteDocument = New-HuntDocument
$cidDirectEntryIncompleteDocument.summary.cid_table_direct_entry_enumeration = $false
$cidDirectEntryIncompleteDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $cidDirectEntryIncompletePath -Encoding UTF8

$cidThreadIncompleteDocument = New-HuntDocument
$cidThreadIncompleteDocument.summary.cid_table_full_thread_enumeration = $false
$cidThreadIncompleteDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $cidThreadIncompletePath -Encoding UTF8

$cidCrossViewIncompleteDocument = New-HuntDocument
$cidCrossViewIncompleteDocument.summary.cid_table_thread_cross_view_complete = $false
$cidCrossViewIncompleteDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $cidCrossViewIncompletePath -Encoding UTF8

$cidUnclassifiedDocument = New-HuntDocument
$cidUnclassifiedDocument.summary.cid_table_unclassified_entries = 1
$cidUnclassifiedDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $cidUnclassifiedPath -Encoding UTF8

$cidDirectCountMismatchDocument = New-HuntDocument
$cidDirectCountMismatchDocument.summary.cid_table_direct_entries = 102
$cidDirectCountMismatchDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $cidDirectCountMismatchPath -Encoding UTF8

$cidThreadsMissingDocument = New-HuntDocument
$cidThreadsMissingDocument.Remove("cid_threads")
$cidThreadsMissingDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $cidThreadsMissingPath -Encoding UTF8

$cidThreadIdentityUnstableDocument = New-HuntDocument
$cidThreadIdentityUnstableDocument.cid_threads[0].identity_revalidated = $false
$cidThreadIdentityUnstableDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $cidThreadIdentityUnstablePath -Encoding UTF8

Set-Content -LiteralPath $malformedPath -Value "{not-json" -Encoding UTF8

Invoke-ValidatorCase -Name "clean" -Path $cleanPath -ExpectSuccess $true -RequireThreatIntelActive
Invoke-ValidatorCase -Name "finding" -Path $findingPath -ExpectSuccess $false
Invoke-ValidatorCase -Name "incomplete" -Path $incompletePath -ExpectSuccess $false
Invoke-ValidatorCase -Name "wrong-type" -Path $wrongTypePath -ExpectSuccess $false
Invoke-ValidatorCase -Name "wrong-integer" -Path $wrongIntegerPath -ExpectSuccess $false
Invoke-ValidatorCase -Name "invalid-mode" -Path $invalidModePath -ExpectSuccess $false -RequireMode Any
Invoke-ValidatorCase -Name "non-array" -Path $nonArrayPath -ExpectSuccess $false
Invoke-ValidatorCase -Name "risk-mismatch" -Path $riskMismatchPath -ExpectSuccess $false
Invoke-ValidatorCase -Name "coverage-conflict" -Path $coverageConflictPath -ExpectSuccess $false
Invoke-ValidatorCase -Name "threat-intel-conflict" -Path $threatIntelConflictPath -ExpectSuccess $false
Invoke-ValidatorCase -Name "threat-intel-unavailable" -Path $threatIntelUnavailablePath -ExpectSuccess $false
Invoke-ValidatorCase -Name "threat-intel-inactive-optional" -Path $threatIntelInactivePath -ExpectSuccess $true
Invoke-ValidatorCase -Name "threat-intel-inactive-required" -Path $threatIntelInactivePath -ExpectSuccess $false -RequireThreatIntelActive
Invoke-ValidatorCase -Name "wfp-incomplete" -Path $wfpIncompletePath -ExpectSuccess $false
Invoke-ValidatorCase -Name "qos-incomplete" -Path $qosIncompletePath -ExpectSuccess $false
Invoke-ValidatorCase -Name "bind-global-incomplete" -Path $bindGlobalIncompletePath -ExpectSuccess $false
Invoke-ValidatorCase -Name "bind-process-incomplete" -Path $bindProcessIncompletePath -ExpectSuccess $false
Invoke-ValidatorCase -Name "cloud-metadata-incomplete" -Path $cloudMetadataIncompletePath -ExpectSuccess $false
Invoke-ValidatorCase -Name "cloud-protection-incomplete" -Path $cloudProtectionIncompletePath -ExpectSuccess $false
Invoke-ValidatorCase -Name "new-counter-wrong-type" -Path $newCounterWrongTypePath -ExpectSuccess $false
Invoke-ValidatorCase -Name "suspicious-wfp" -Path $suspiciousWfpPath -ExpectSuccess $false
Invoke-ValidatorCase -Name "suspicious-qos" -Path $suspiciousQosPath -ExpectSuccess $false
Invoke-ValidatorCase -Name "suspicious-bind" -Path $suspiciousBindPath -ExpectSuccess $false
Invoke-ValidatorCase -Name "bind-process" -Path $bindProcessPath -ExpectSuccess $false
Invoke-ValidatorCase -Name "cloud-count-mismatch" -Path $cloudCountMismatchPath -ExpectSuccess $false
Invoke-ValidatorCase -Name "silo-wrong-type" -Path $siloWrongTypePath -ExpectSuccess $false
Invoke-ValidatorCase -Name "cid-fallback" -Path $cidFallbackPath -ExpectSuccess $false
Invoke-ValidatorCase -Name "cid-overclaim" -Path $cidOverclaimPath -ExpectSuccess $false
Invoke-ValidatorCase -Name "cid-topology-mismatch" -Path $cidTopologyMismatchPath -ExpectSuccess $false
Invoke-ValidatorCase -Name "cid-probe-failure" -Path $cidProbeFailurePath -ExpectSuccess $false
Invoke-ValidatorCase -Name "cid-probe-short" -Path $cidProbeShortPath -ExpectSuccess $false
Invoke-ValidatorCase -Name "cid-zero-anchor" -Path $cidZeroAnchorPath -ExpectSuccess $false
Invoke-ValidatorCase -Name "cid-persistent-api-miss" -Path $cidPersistentApiMissPath -ExpectSuccess $false
Invoke-ValidatorCase -Name "cid-direct-entry-incomplete" -Path $cidDirectEntryIncompletePath -ExpectSuccess $false
Invoke-ValidatorCase -Name "cid-thread-incomplete" -Path $cidThreadIncompletePath -ExpectSuccess $false
Invoke-ValidatorCase -Name "cid-cross-view-incomplete" -Path $cidCrossViewIncompletePath -ExpectSuccess $false
Invoke-ValidatorCase -Name "cid-unclassified" -Path $cidUnclassifiedPath -ExpectSuccess $false
Invoke-ValidatorCase -Name "cid-direct-count-mismatch" -Path $cidDirectCountMismatchPath -ExpectSuccess $false
Invoke-ValidatorCase -Name "cid-threads-missing" -Path $cidThreadsMissingPath -ExpectSuccess $false
Invoke-ValidatorCase -Name "cid-thread-identity-unstable" -Path $cidThreadIdentityUnstablePath -ExpectSuccess $false
Invoke-ValidatorCase -Name "malformed" -Path $malformedPath -ExpectSuccess $false

Write-Host "hunt clean-host validator self-test passed"
exit 0
