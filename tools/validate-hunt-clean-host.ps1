param(
    [Parameter(Mandatory = $true)]
    [string]$HuntJson,

    [ValidateSet("Any", "Quick", "Default", "Deep")]
    [string]$RequireMode = "Any",

    [switch]$RequireThreatIntelActive
)

$ErrorActionPreference = "Stop"

function Add-Failure
{
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]]$Failures,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $Failures.Add($Message)
}

function Test-JsonInteger
{
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value)
    {
        return $false
    }

    switch ([Type]::GetTypeCode($Value.GetType()))
    {
        ([TypeCode]::SByte) { return $true }
        ([TypeCode]::Byte) { return $true }
        ([TypeCode]::Int16) { return $true }
        ([TypeCode]::UInt16) { return $true }
        ([TypeCode]::Int32) { return $true }
        ([TypeCode]::UInt32) { return $true }
        ([TypeCode]::Int64) { return $true }
        default { return $false }
    }
}

function Test-JsonNonzeroHex64
{
    param(
        [AllowNull()]
        [object]$Value
    )

    return $Value -is [string] -and
        [string]$Value -match '^0x[0-9a-fA-F]{16}$' -and
        [string]$Value -notmatch '^0x0{16}$'
}

function Get-FindingFingerprint
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$Finding
    )

    $reasonText = (@($Finding.reasons) | Sort-Object) -join ","
    $evidenceParts = @()
    if ($null -ne $Finding.evidence)
    {
        foreach ($property in @($Finding.evidence.PSObject.Properties | Sort-Object Name))
        {
            $evidenceParts += "$($property.Name)=$([string]$property.Value)"
        }
    }

    return "risk=$($Finding.risk) confidence=$($Finding.confidence) class=$($Finding.class) " +
        "pid=$($Finding.pid) image=$($Finding.image) module=$($Finding.module) " +
        "reasons=[$reasonText] evidence=[$($evidenceParts -join ';')]"
}

$failures = [System.Collections.Generic.List[string]]::new()
$resolvedPath = ""
$document = $null

try
{
    $resolvedPath = (Resolve-Path -LiteralPath $HuntJson).Path
    $document = Get-Content -LiteralPath $resolvedPath -Raw | ConvertFrom-Json
}
catch
{
    Add-Failure -Failures $failures -Message "unable to read valid JSON: $($_.Exception.Message)"
}

if ($null -ne $document)
{
    if ([string]$document.schema -ne "kn-live-dbg.hunt.v1")
    {
        Add-Failure -Failures $failures -Message "unsupported schema '$($document.schema)'"
    }

    if ([string]::IsNullOrWhiteSpace([string]$document.timestamp_utc))
    {
        Add-Failure -Failures $failures -Message "timestamp_utc is missing"
    }

    $validModes = @("quick", "default", "deep")
    $actualMode = ([string]$document.mode).ToLowerInvariant()
    if ($validModes -notcontains $actualMode)
    {
        Add-Failure -Failures $failures -Message "mode must be quick, default, or deep; actual='$($document.mode)'"
    }
    if ($RequireMode -ne "Any" -and
        $actualMode -ne $RequireMode.ToLowerInvariant())
    {
        Add-Failure -Failures $failures -Message "mode mismatch expected=$($RequireMode.ToLowerInvariant()) actual=$($document.mode)"
    }

    if ($null -eq $document.summary)
    {
        Add-Failure -Failures $failures -Message "summary is missing"
    }
    else
    {
        $requiredSummaryFields = @(
            "kernel_processes",
            "system_process_information_processes",
            "toolhelp_processes",
            "system_process_information_threads",
            "toolhelp_threads",
            "scanned_processes",
            "findings",
            "high",
            "medium",
            "low",
            "info",
            "wfp_filters",
            "suspicious_wfp_filters",
            "qos_policies",
            "suspicious_qos_policies",
            "bindflt_global_mappings",
            "suspicious_bindflt_global_mappings",
            "bindflt_process_bindings",
            "cloudfiles_placeholder_images",
            "suspicious_cloudfiles_images",
            "wfp_filter_coverage_incomplete",
            "qos_policy_coverage_incomplete",
            "bindflt_global_coverage_incomplete",
            "bindflt_process_correlation_coverage_incomplete",
            "bindflt_silo_coverage_unsupported",
            "cloudfiles_placeholder_coverage_incomplete",
            "cloudfiles_protection_correlation_incomplete",
            "process_inventory_incomplete",
            "cid_table_full_enumeration",
            "cid_table_full_process_enumeration",
            "cid_table_direct_entry_enumeration",
            "cid_table_full_thread_enumeration",
            "cid_table_thread_cross_view_complete",
            "cid_table_lookup_only",
            "cid_table_anchor",
            "cid_table_address",
            "cid_table_code",
            "cid_table_level",
            "cid_table_next_handle",
            "cid_table_allocated_leaves",
            "cid_table_allocated_handle_capacity",
            "cid_table_probes",
            "cid_table_processes",
            "cid_table_discovered_processes",
            "cid_table_direct_entries",
            "cid_table_direct_processes",
            "cid_table_direct_threads",
            "cid_table_unclassified_entries",
            "cid_table_thread_findings",
            "cid_table_persistent_thread_view_misses",
            "cid_table_probe_failures",
            "cid_table_persistent_api_misses",
            "process_triage_coverage_incomplete",
            "deep_image_comparison_coverage_incomplete",
            "driver_service_coverage_incomplete",
            "threat_intel_active",
            "threat_intel_available",
            "threat_intel_correlation_incomplete",
            "coverage_complete"
        )
        foreach ($field in $requiredSummaryFields)
        {
            if ($null -eq $document.summary.PSObject.Properties[$field])
            {
                Add-Failure -Failures $failures -Message "summary.$field is missing"
            }
        }

        $numericSummaryFields = @(
            "kernel_processes",
            "system_process_information_processes",
            "toolhelp_processes",
            "system_process_information_threads",
            "toolhelp_threads",
            "scanned_processes",
            "findings",
            "high",
            "medium",
            "low",
            "info",
            "wfp_filters",
            "suspicious_wfp_filters",
            "qos_policies",
            "suspicious_qos_policies",
            "bindflt_global_mappings",
            "suspicious_bindflt_global_mappings",
            "bindflt_process_bindings",
            "cloudfiles_placeholder_images",
            "suspicious_cloudfiles_images",
            "cid_table_level",
            "cid_table_next_handle",
            "cid_table_allocated_leaves",
            "cid_table_allocated_handle_capacity",
            "cid_table_probes",
            "cid_table_processes",
            "cid_table_discovered_processes",
            "cid_table_direct_entries",
            "cid_table_direct_processes",
            "cid_table_direct_threads",
            "cid_table_unclassified_entries",
            "cid_table_thread_findings",
            "cid_table_persistent_thread_view_misses",
            "cid_table_probe_failures",
            "cid_table_persistent_api_misses"
        )
        foreach ($field in $numericSummaryFields)
        {
            if ($null -ne $document.summary.PSObject.Properties[$field] -and
                -not (Test-JsonInteger -Value $document.summary.$field))
            {
                Add-Failure -Failures $failures -Message "summary.$field must be a JSON integer"
            }
            elseif ($null -ne $document.summary.PSObject.Properties[$field] -and
                [int64]$document.summary.$field -lt 0)
            {
                Add-Failure -Failures $failures -Message "summary.$field must be nonnegative"
            }
        }

        foreach ($pair in @(
            @("suspicious_wfp_filters", "wfp_filters"),
            @("suspicious_qos_policies", "qos_policies"),
            @("suspicious_bindflt_global_mappings", "bindflt_global_mappings"),
            @("suspicious_cloudfiles_images", "cloudfiles_placeholder_images")
        ))
        {
            $subset = $pair[0]
            $total = $pair[1]
            if ((Test-JsonInteger -Value $document.summary.$subset) -and
                (Test-JsonInteger -Value $document.summary.$total) -and
                [int64]$document.summary.$subset -gt
                    [int64]$document.summary.$total)
            {
                Add-Failure -Failures $failures -Message (
                    "summary.$subset=$($document.summary.$subset) exceeds " +
                    "summary.$total=$($document.summary.$total)")
            }
        }

        foreach ($field in @(
            "suspicious_wfp_filters",
            "suspicious_qos_policies",
            "suspicious_bindflt_global_mappings",
            "bindflt_process_bindings",
            "suspicious_cloudfiles_images"
        ))
        {
            if ((Test-JsonInteger -Value $document.summary.$field) -and
                [int64]$document.summary.$field -ne 0)
            {
                Add-Failure -Failures $failures -Message (
                    "summary.$field=$($document.summary.$field), expected 0")
            }
        }

        foreach ($field in @(
            "kernel_processes",
            "system_process_information_processes",
            "toolhelp_processes",
            "system_process_information_threads",
            "toolhelp_threads",
            "scanned_processes"
        ))
        {
            if ($null -ne $document.summary.PSObject.Properties[$field] -and
                (Test-JsonInteger -Value $document.summary.$field) -and
                [int64]$document.summary.$field -le 0)
            {
                Add-Failure -Failures $failures -Message "summary.$field must be greater than zero"
            }
        }

        foreach ($field in @(
            "coverage_complete",
            "process_inventory_incomplete",
            "process_triage_coverage_incomplete",
            "deep_image_comparison_coverage_incomplete",
            "driver_service_coverage_incomplete",
            "wfp_filter_coverage_incomplete",
            "qos_policy_coverage_incomplete",
            "bindflt_global_coverage_incomplete",
            "bindflt_process_correlation_coverage_incomplete",
            "bindflt_silo_coverage_unsupported",
            "cloudfiles_placeholder_coverage_incomplete",
            "cloudfiles_protection_correlation_incomplete",
            "cid_table_full_enumeration",
            "cid_table_full_process_enumeration",
            "cid_table_direct_entry_enumeration",
            "cid_table_full_thread_enumeration",
            "cid_table_thread_cross_view_complete",
            "cid_table_lookup_only",
            "threat_intel_active",
            "threat_intel_available",
            "threat_intel_correlation_incomplete"
        ))
        {
            if ($null -ne $document.summary.PSObject.Properties[$field] -and
                $document.summary.$field -isnot [bool])
            {
                Add-Failure -Failures $failures -Message "summary.$field must be a JSON boolean"
            }
        }

        if ($document.summary.coverage_complete -is [bool] -and
            -not $document.summary.coverage_complete)
        {
            Add-Failure -Failures $failures -Message "summary.coverage_complete is false"
        }
        foreach ($field in @(
            "cid_table_anchor",
            "cid_table_address",
            "cid_table_code"
        ))
        {
            if ($null -ne $document.summary.PSObject.Properties[$field] -and
                -not (Test-JsonNonzeroHex64 -Value $document.summary.$field))
            {
                Add-Failure -Failures $failures -Message "summary.$field must be a nonzero 16-digit hexadecimal string"
            }
        }
        if ($document.summary.cid_table_full_enumeration -is [bool] -and
            -not $document.summary.cid_table_full_enumeration)
        {
            Add-Failure -Failures $failures -Message (
                "complete direct process-and-thread CID enumeration is required")
        }
        if ($document.summary.cid_table_full_process_enumeration -is [bool] -and
            -not $document.summary.cid_table_full_process_enumeration)
        {
            Add-Failure -Failures $failures -Message "full bounded process-CID enumeration is required"
        }
        foreach ($field in @(
            "cid_table_direct_entry_enumeration",
            "cid_table_full_thread_enumeration",
            "cid_table_thread_cross_view_complete"
        ))
        {
            if ($document.summary.$field -is [bool] -and
                -not $document.summary.$field)
            {
                Add-Failure -Failures $failures -Message "summary.$field must be true"
            }
        }
        if ($document.summary.cid_table_lookup_only -is [bool] -and
            $document.summary.cid_table_lookup_only)
        {
            Add-Failure -Failures $failures -Message "known-PID-only CID lookup cannot satisfy the clean-host gate"
        }
        if ((Test-JsonInteger -Value $document.summary.cid_table_level) -and
            ([int64]$document.summary.cid_table_level -lt 0 -or
             [int64]$document.summary.cid_table_level -gt 2))
        {
            Add-Failure -Failures $failures -Message "summary.cid_table_level must be 0, 1, or 2"
        }
        if ((Test-JsonInteger -Value $document.summary.cid_table_next_handle) -and
            ([int64]$document.summary.cid_table_next_handle -lt 8 -or
             ([int64]$document.summary.cid_table_next_handle % 4) -ne 0))
        {
            Add-Failure -Failures $failures -Message "summary.cid_table_next_handle must be an aligned allocated CID bound"
        }
        if ((Test-JsonInteger -Value $document.summary.cid_table_allocated_leaves) -and
            [int64]$document.summary.cid_table_allocated_leaves -le 0)
        {
            Add-Failure -Failures $failures -Message "summary.cid_table_allocated_leaves must be greater than zero"
        }
        if ((Test-JsonInteger -Value $document.summary.cid_table_next_handle) -and
            (Test-JsonInteger -Value $document.summary.cid_table_allocated_handle_capacity) -and
            [int64]$document.summary.cid_table_next_handle -ne
                [int64]$document.summary.cid_table_allocated_handle_capacity)
        {
            Add-Failure -Failures $failures -Message "CID NextHandle and allocated-leaf capacity disagree"
        }
        if ((Test-JsonInteger -Value $document.summary.cid_table_next_handle) -and
            (Test-JsonInteger -Value $document.summary.cid_table_probes) -and
            [int64]$document.summary.cid_table_next_handle -ge 8 -and
            [int64]$document.summary.cid_table_probes -lt
                (([int64]$document.summary.cid_table_next_handle / 4) - 1))
        {
            Add-Failure -Failures $failures -Message "summary.cid_table_probes does not cover every aligned CID below the validated bound"
        }
        if ((Test-JsonInteger -Value $document.summary.cid_table_processes) -and
            [int64]$document.summary.cid_table_processes -le 0)
        {
            Add-Failure -Failures $failures -Message "summary.cid_table_processes must be greater than zero"
        }
        if ((Test-JsonInteger -Value $document.summary.cid_table_discovered_processes) -and
            (Test-JsonInteger -Value $document.summary.cid_table_processes) -and
            [int64]$document.summary.cid_table_discovered_processes -gt
                [int64]$document.summary.cid_table_processes)
        {
            Add-Failure -Failures $failures -Message "summary.cid_table_discovered_processes exceeds the enumerated process count"
        }
        foreach ($field in @(
            "system_process_information_threads",
            "toolhelp_threads",
            "cid_table_direct_entries",
            "cid_table_direct_processes",
            "cid_table_direct_threads"
        ))
        {
            if ((Test-JsonInteger -Value $document.summary.$field) -and
                [int64]$document.summary.$field -le 0)
            {
                Add-Failure -Failures $failures -Message "summary.$field must be greater than zero"
            }
        }
        if ((Test-JsonInteger -Value $document.summary.cid_table_direct_entries) -and
            (Test-JsonInteger -Value $document.summary.cid_table_direct_processes) -and
            (Test-JsonInteger -Value $document.summary.cid_table_direct_threads) -and
            [int64]$document.summary.cid_table_direct_entries -ne
                ([int64]$document.summary.cid_table_direct_processes +
                 [int64]$document.summary.cid_table_direct_threads))
        {
            Add-Failure -Failures $failures -Message "direct CID entry count does not equal typed process plus thread entries"
        }
        foreach ($field in @(
            "cid_table_unclassified_entries",
            "cid_table_thread_findings",
            "cid_table_persistent_thread_view_misses"
        ))
        {
            if ((Test-JsonInteger -Value $document.summary.$field) -and
                [int64]$document.summary.$field -ne 0)
            {
                Add-Failure -Failures $failures -Message "summary.$field must be zero"
            }
        }
        if ((Test-JsonInteger -Value $document.summary.cid_table_probe_failures) -and
            [int64]$document.summary.cid_table_probe_failures -ne 0)
        {
            Add-Failure -Failures $failures -Message "summary.cid_table_probe_failures must be zero"
        }
        if ((Test-JsonInteger -Value $document.summary.cid_table_persistent_api_misses) -and
            [int64]$document.summary.cid_table_persistent_api_misses -ne 0)
        {
            Add-Failure -Failures $failures -Message "summary.cid_table_persistent_api_misses must be zero"
        }
        foreach ($field in @(
            "process_inventory_incomplete",
            "process_triage_coverage_incomplete",
            "deep_image_comparison_coverage_incomplete",
            "driver_service_coverage_incomplete",
            "wfp_filter_coverage_incomplete",
            "qos_policy_coverage_incomplete",
            "bindflt_global_coverage_incomplete",
            "bindflt_process_correlation_coverage_incomplete",
            "cloudfiles_placeholder_coverage_incomplete",
            "cloudfiles_protection_correlation_incomplete",
            "threat_intel_correlation_incomplete"
        ))
        {
            if ($document.summary.$field -is [bool] -and
                $document.summary.$field)
            {
                Add-Failure -Failures $failures -Message "summary.$field is true"
            }
        }
        if ($document.summary.threat_intel_active -is [bool] -and
            $document.summary.threat_intel_available -is [bool] -and
            $document.summary.threat_intel_active -and
            -not $document.summary.threat_intel_available)
        {
            Add-Failure -Failures $failures -Message "summary.threat_intel_active conflicts with unavailable TI coverage"
        }
        if ($RequireThreatIntelActive)
        {
            if ($document.summary.threat_intel_active -is [bool] -and
                -not $document.summary.threat_intel_active)
            {
                Add-Failure -Failures $failures -Message "active threat-intel collection is required"
            }
            if ($document.summary.threat_intel_available -is [bool] -and
                -not $document.summary.threat_intel_available)
            {
                Add-Failure -Failures $failures -Message "available threat-intel correlation is required"
            }
        }
        if ($actualMode -eq "deep" -and
            $document.summary.threat_intel_available -is [bool] -and
            -not $document.summary.threat_intel_available)
        {
            Add-Failure -Failures $failures -Message "deep clean-host validation requires available threat-intel correlation"
        }

        if ($null -ne $document.summary.PSObject.Properties["coverage_complete"] -and
            $document.summary.coverage_complete -is [bool] -and
            $document.summary.coverage_complete -and
            (($null -ne $document.summary.PSObject.Properties["process_inventory_incomplete"] -and
                    $document.summary.process_inventory_incomplete -is [bool] -and
                    $document.summary.process_inventory_incomplete) -or
                ($null -ne $document.summary.PSObject.Properties["process_triage_coverage_incomplete"] -and
                    $document.summary.process_triage_coverage_incomplete -is [bool] -and
                    $document.summary.process_triage_coverage_incomplete) -or
                ($null -ne $document.summary.PSObject.Properties["deep_image_comparison_coverage_incomplete"] -and
                    $document.summary.deep_image_comparison_coverage_incomplete -is [bool] -and
                    $document.summary.deep_image_comparison_coverage_incomplete) -or
                ($null -ne $document.summary.PSObject.Properties["driver_service_coverage_incomplete"] -and
                    $document.summary.driver_service_coverage_incomplete -is [bool] -and
                    $document.summary.driver_service_coverage_incomplete) -or
                ($null -ne $document.summary.PSObject.Properties["wfp_filter_coverage_incomplete"] -and
                    $document.summary.wfp_filter_coverage_incomplete -is [bool] -and
                    $document.summary.wfp_filter_coverage_incomplete) -or
                ($null -ne $document.summary.PSObject.Properties["qos_policy_coverage_incomplete"] -and
                    $document.summary.qos_policy_coverage_incomplete -is [bool] -and
                    $document.summary.qos_policy_coverage_incomplete) -or
                ($null -ne $document.summary.PSObject.Properties["bindflt_global_coverage_incomplete"] -and
                    $document.summary.bindflt_global_coverage_incomplete -is [bool] -and
                    $document.summary.bindflt_global_coverage_incomplete) -or
                ($null -ne $document.summary.PSObject.Properties["bindflt_process_correlation_coverage_incomplete"] -and
                    $document.summary.bindflt_process_correlation_coverage_incomplete -is [bool] -and
                    $document.summary.bindflt_process_correlation_coverage_incomplete) -or
                ($null -ne $document.summary.PSObject.Properties["cloudfiles_placeholder_coverage_incomplete"] -and
                    $document.summary.cloudfiles_placeholder_coverage_incomplete -is [bool] -and
                    $document.summary.cloudfiles_placeholder_coverage_incomplete) -or
                ($null -ne $document.summary.PSObject.Properties["cloudfiles_protection_correlation_incomplete"] -and
                    $document.summary.cloudfiles_protection_correlation_incomplete -is [bool] -and
                    $document.summary.cloudfiles_protection_correlation_incomplete) -or
                ($null -ne $document.summary.PSObject.Properties["threat_intel_correlation_incomplete"] -and
                    $document.summary.threat_intel_correlation_incomplete -is [bool] -and
                    $document.summary.threat_intel_correlation_incomplete)))
        {
            Add-Failure -Failures $failures -Message "summary.coverage_complete conflicts with an incomplete coverage flag"
        }
    }

    $cidThreads = @()
    if ($null -eq $document.PSObject.Properties["cid_threads"])
    {
        Add-Failure -Failures $failures -Message "cid_threads array is missing"
    }
    elseif ($document.cid_threads -isnot [System.Array])
    {
        Add-Failure -Failures $failures -Message "cid_threads must be a JSON array"
    }
    else
    {
        $cidThreads = @($document.cid_threads)
        $seenThreadIds =
            [System.Collections.Generic.HashSet[uint32]]::new()
        $directThreadRecords = 0
        $suspiciousThreadRecords = 0
        foreach ($record in $cidThreads)
        {
            if ($null -eq $record)
            {
                Add-Failure -Failures $failures -Message "cid_threads contains a null item"
                continue
            }

            foreach ($field in @(
                "tid",
                "pid",
                "object_header",
                "ethread",
                "eprocess",
                "terminated",
                "direct_cid_seen",
                "executive_thread_list_seen",
                "scheduler_thread_list_seen",
                "system_process_information_seen",
                "toolhelp_seen",
                "identity_revalidated",
                "views_revalidated",
                "lifecycle_changed",
                "suspicious",
                "reasons",
                "warnings"
            ))
            {
                if ($null -eq $record.PSObject.Properties[$field])
                {
                    Add-Failure -Failures $failures -Message "cid_threads.$field is missing"
                }
            }

            if (-not (Test-JsonInteger -Value $record.tid) -or
                [int64]$record.tid -le 0 -or
                [int64]$record.tid -gt [uint32]::MaxValue)
            {
                Add-Failure -Failures $failures -Message "cid_threads.tid must be a positive 32-bit JSON integer"
            }
            elseif (-not $seenThreadIds.Add([uint32]$record.tid))
            {
                Add-Failure -Failures $failures -Message "cid_threads contains duplicate tid=$($record.tid)"
            }
            if (-not (Test-JsonInteger -Value $record.pid) -or
                [int64]$record.pid -lt 0 -or
                [int64]$record.pid -gt [uint32]::MaxValue)
            {
                Add-Failure -Failures $failures -Message "cid_threads.pid must be a nonnegative 32-bit JSON integer"
            }
            foreach ($field in @(
                "object_header",
                "ethread",
                "eprocess"
            ))
            {
                if ($record.$field -isnot [string] -or
                    [string]$record.$field -notmatch '^0x[0-9a-fA-F]{16}$')
                {
                    Add-Failure -Failures $failures -Message "cid_threads.$field must be a 16-digit hexadecimal string"
                }
            }
            foreach ($field in @(
                "terminated",
                "direct_cid_seen",
                "executive_thread_list_seen",
                "scheduler_thread_list_seen",
                "system_process_information_seen",
                "toolhelp_seen",
                "identity_revalidated",
                "views_revalidated",
                "lifecycle_changed",
                "suspicious"
            ))
            {
                if ($null -ne $record.PSObject.Properties[$field] -and
                    $record.$field -isnot [bool])
                {
                    Add-Failure -Failures $failures -Message "cid_threads.$field must be a JSON boolean"
                }
            }
            foreach ($field in @("reasons", "warnings"))
            {
                if ($null -ne $record.PSObject.Properties[$field] -and
                    $record.$field -isnot [System.Array])
                {
                    Add-Failure -Failures $failures -Message "cid_threads.$field must be a JSON array"
                }
            }

            if ($record.direct_cid_seen -is [bool] -and
                $record.direct_cid_seen)
            {
                ++$directThreadRecords
            }
            if ($record.suspicious -is [bool] -and
                $record.suspicious)
            {
                ++$suspiciousThreadRecords
            }
            if ($record.identity_revalidated -is [bool] -and
                -not $record.identity_revalidated)
            {
                Add-Failure -Failures $failures -Message "clean cid_threads record lacks identity revalidation for tid=$($record.tid)"
            }
            if ($record.views_revalidated -is [bool] -and
                -not $record.views_revalidated)
            {
                Add-Failure -Failures $failures -Message "clean cid_threads record lacks view revalidation for tid=$($record.tid)"
            }
            if ($record.suspicious -is [bool] -and
                $record.suspicious)
            {
                Add-Failure -Failures $failures -Message "clean cid_threads record is suspicious for tid=$($record.tid)"
            }
        }

        if ($null -ne $document.summary -and
            (Test-JsonInteger -Value $document.summary.cid_table_direct_threads) -and
            $cidThreads.Count -lt
                [int64]$document.summary.cid_table_direct_threads)
        {
            Add-Failure -Failures $failures -Message "cid_threads omits one or more directly decoded thread entries"
        }
        if ($null -ne $document.summary -and
            (Test-JsonInteger -Value $document.summary.cid_table_direct_threads) -and
            $directThreadRecords -ne
                [int64]$document.summary.cid_table_direct_threads)
        {
            Add-Failure -Failures $failures -Message "direct_cid_seen record count does not match summary.cid_table_direct_threads"
        }
        if ($null -ne $document.summary -and
            (Test-JsonInteger -Value $document.summary.cid_table_thread_findings) -and
            $suspiciousThreadRecords -ne
                [int64]$document.summary.cid_table_thread_findings)
        {
            Add-Failure -Failures $failures -Message "suspicious cid_threads count does not match summary.cid_table_thread_findings"
        }
        if ($null -ne $document.summary -and
            (Test-JsonInteger -Value $document.summary.cid_table_persistent_thread_view_misses) -and
            $suspiciousThreadRecords -ne
                [int64]$document.summary.cid_table_persistent_thread_view_misses)
        {
            Add-Failure -Failures $failures -Message "suspicious cid_threads count does not match persistent thread-view misses"
        }
    }

    $cloudFileImages = @()
    if ($null -eq $document.PSObject.Properties["cloudfiles_images"])
    {
        Add-Failure -Failures $failures -Message "cloudfiles_images array is missing"
    }
    elseif ($document.cloudfiles_images -isnot [System.Array])
    {
        Add-Failure -Failures $failures -Message "cloudfiles_images must be a JSON array"
    }
    else
    {
        $cloudFileImages = @($document.cloudfiles_images)
        $suspiciousCloudFileImages = 0
        foreach ($record in $cloudFileImages)
        {
            if ($null -eq $record)
            {
                Add-Failure -Failures $failures -Message "cloudfiles_images contains a null item"
                continue
            }
            $suspiciousProperty =
                $record.PSObject.Properties["suspicious"]
            if ($null -eq $suspiciousProperty)
            {
                Add-Failure -Failures $failures -Message "cloudfiles_images.suspicious is missing"
            }
            elseif ($suspiciousProperty.Value -isnot [bool])
            {
                Add-Failure -Failures $failures -Message "cloudfiles_images.suspicious must be a JSON boolean"
            }
            elseif ($suspiciousProperty.Value)
            {
                ++$suspiciousCloudFileImages
            }
        }

        if ($null -ne $document.summary -and
            (Test-JsonInteger -Value $document.summary.cloudfiles_placeholder_images) -and
            [int64]$document.summary.cloudfiles_placeholder_images -ne
                $cloudFileImages.Count)
        {
            Add-Failure -Failures $failures -Message (
                "summary.cloudfiles_placeholder_images=$($document.summary.cloudfiles_placeholder_images) " +
                "does not match cloudfiles_images count=$($cloudFileImages.Count)")
        }
        if ($null -ne $document.summary -and
            (Test-JsonInteger -Value $document.summary.suspicious_cloudfiles_images) -and
            [int64]$document.summary.suspicious_cloudfiles_images -ne
                $suspiciousCloudFileImages)
        {
            Add-Failure -Failures $failures -Message (
                "summary.suspicious_cloudfiles_images=$($document.summary.suspicious_cloudfiles_images) " +
                "does not match suspicious cloudfiles_images count=$suspiciousCloudFileImages")
        }
    }

    if ($null -eq $document.PSObject.Properties["findings"])
    {
        Add-Failure -Failures $failures -Message "findings array is missing"
        $findings = @()
    }
    else
    {
        if ($document.findings -isnot [System.Array])
        {
            Add-Failure -Failures $failures -Message "findings must be a JSON array"
            $findings = @()
        }
        else
        {
            $findings = @($document.findings)
        }
    }

    $actualRiskCounts = @{
        high = 0
        medium = 0
        low = 0
        info = 0
    }
    foreach ($finding in $findings)
    {
        if ($null -eq $finding)
        {
            Add-Failure -Failures $failures -Message "findings contains a null item"
            continue
        }

        $risk = ([string]$finding.risk).ToLowerInvariant()
        if ($actualRiskCounts.ContainsKey($risk))
        {
            $actualRiskCounts[$risk] = [int]$actualRiskCounts[$risk] + 1
        }
        else
        {
            Add-Failure -Failures $failures -Message "finding has unsupported risk '$($finding.risk)'"
        }
    }

    if ($null -ne $document.summary)
    {
        if ($null -ne $document.summary.PSObject.Properties["findings"] -and
            (Test-JsonInteger -Value $document.summary.findings) -and
            [int64]$document.summary.findings -ne $findings.Count)
        {
            Add-Failure -Failures $failures -Message "summary.findings=$($document.summary.findings) does not match findings array count=$($findings.Count)"
        }

        foreach ($risk in @("high", "medium", "low", "info"))
        {
            if ($null -ne $document.summary.PSObject.Properties[$risk] -and
                (Test-JsonInteger -Value $document.summary.$risk) -and
                [int64]$document.summary.$risk -ne [int64]$actualRiskCounts[$risk])
            {
                Add-Failure -Failures $failures -Message "summary.$risk=$($document.summary.$risk) does not match findings risk count=$($actualRiskCounts[$risk])"
            }
            if ($null -ne $document.summary.PSObject.Properties[$risk] -and
                (Test-JsonInteger -Value $document.summary.$risk) -and
                [int64]$document.summary.$risk -ne 0)
            {
                Add-Failure -Failures $failures -Message "summary.$risk=$($document.summary.$risk), expected 0"
            }
        }
    }

    if ($findings.Count -ne 0)
    {
        Add-Failure -Failures $failures -Message "clean host emitted $($findings.Count) finding(s)"
    }
}
else
{
    $findings = @()
}

Write-Host "hunt clean-host validation"
Write-Host "  json=$resolvedPath"
if ($null -ne $document)
{
    Write-Host "  mode=$($document.mode)"
    if ($null -ne $document.summary)
    {
        Write-Host "  scanned_processes=$($document.summary.scanned_processes)"
        Write-Host "  findings=$($document.summary.findings)"
        Write-Host "  coverage_complete=$($document.summary.coverage_complete)"
        Write-Host "  warnings=$(@($document.warnings).Count)"
    }
}

if ($findings.Count -ne 0)
{
    Write-Host "finding fingerprints"
    foreach ($finding in $findings)
    {
        Write-Host "  $(Get-FindingFingerprint -Finding $finding)"
    }
}

if ($failures.Count -ne 0)
{
    Write-Host "validation failed"
    foreach ($failure in $failures)
    {
        Write-Host "  fail $failure"
    }
    exit 1
}

Write-Host "validation passed"
exit 0
