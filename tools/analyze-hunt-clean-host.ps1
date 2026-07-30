param(
    [Parameter(Mandatory = $true)]
    [string[]]$HuntJson,

    [string]$OutputJson = "",

    [string]$OutputMarkdown = "",

    [switch]$RequireThreatIntelActive
)

$ErrorActionPreference = "Stop"

function Get-Sha256Prefix
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try
    {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
        $hash = $algorithm.ComputeHash($bytes)
        return ([System.BitConverter]::ToString($hash).Replace("-", "").ToLowerInvariant()).Substring(0, 16)
    }
    finally
    {
        $algorithm.Dispose()
    }
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

function Get-RequiredJsonInteger
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$Container,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    $property = $Container.PSObject.Properties[$Name]
    if ($null -eq $property)
    {
        throw "$Context.$Name is missing"
    }
    if (-not (Test-JsonInteger -Value $property.Value))
    {
        throw "$Context.$Name must be a JSON integer"
    }

    $result = [int64]$property.Value
    if ($result -lt 0)
    {
        throw "$Context.$Name must be nonnegative"
    }
    return $result
}

function Get-RequiredJsonBoolean
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$Container,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    $property = $Container.PSObject.Properties[$Name]
    if ($null -eq $property)
    {
        throw "$Context.$Name is missing"
    }
    if ($property.Value -isnot [bool])
    {
        throw "$Context.$Name must be a JSON boolean"
    }
    return [bool]$property.Value
}

function Get-RequiredJsonNonzeroHex64
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$Container,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    $property = $Container.PSObject.Properties[$Name]
    if ($null -eq $property)
    {
        throw "$Context.$Name is missing"
    }
    if ($property.Value -isnot [string] -or
        [string]$property.Value -notmatch '^0x[0-9a-fA-F]{16}$' -or
        [string]$property.Value -match '^0x0{16}$')
    {
        throw "$Context.$Name must be a nonzero 16-digit hexadecimal string"
    }
    return [string]$property.Value
}

function Get-NormalizedLeaf
{
    param(
        [AllowNull()]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value))
    {
        return ""
    }

    return [System.IO.Path]::GetFileName(($Value -replace "/", "\")).ToLowerInvariant()
}

function Get-FindingIdentity
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$Finding
    )

    $reasons = @($Finding.reasons | ForEach-Object { ([string]$_).ToLowerInvariant() } | Sort-Object -Unique)
    $canonical = @(
        ([string]$Finding.class).ToLowerInvariant(),
        ([string]$Finding.risk).ToLowerInvariant(),
        ([string]$Finding.confidence).ToLowerInvariant(),
        ([string]$Finding.title).ToLowerInvariant(),
        (Get-NormalizedLeaf -Value ([string]$Finding.image)),
        (Get-NormalizedLeaf -Value ([string]$Finding.module)),
        ($reasons -join ",")
    ) -join "|"

    return [pscustomobject]@{
        Canonical = $canonical
        Fingerprint = Get-Sha256Prefix -Value $canonical
        Reasons = $reasons
    }
}

function Convert-EvidenceToOrderedMap
{
    param(
        [AllowNull()]
        [object]$Evidence
    )

    $result = [ordered]@{}
    if ($null -eq $Evidence)
    {
        return $result
    }

    foreach ($property in @($Evidence.PSObject.Properties | Sort-Object Name))
    {
        $result[$property.Name] = [string]$property.Value
    }
    return $result
}

$resolvedInputs = [System.Collections.Generic.List[string]]::new()
$seenInputs = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
foreach ($path in $HuntJson)
{
    $matches = @(Resolve-Path -Path $path)
    foreach ($match in $matches)
    {
        $resolved = $match.ProviderPath
        if (-not [System.IO.File]::Exists($resolved))
        {
            throw "hunt JSON input must resolve to a file: $resolved"
        }
        if ($seenInputs.Add($resolved))
        {
            $resolvedInputs.Add($resolved)
        }
    }
}
if ($resolvedInputs.Count -eq 0)
{
    throw "at least one hunt JSON path is required"
}

$runs = [System.Collections.Generic.List[object]]::new()
$groups = [System.Collections.Generic.Dictionary[string, object]]::new(
    [System.StringComparer]::Ordinal)

for ($runIndex = 0; $runIndex -lt $resolvedInputs.Count; ++$runIndex)
{
    $path = $resolvedInputs[$runIndex]
    $document = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    if ([string]$document.schema -ne "kn-live-dbg.hunt.v1")
    {
        throw "unsupported hunt schema in $path`: $($document.schema)"
    }
    if ($null -eq $document.summary)
    {
        throw "hunt summary is missing: $path"
    }
    $validModes = @("quick", "default", "deep")
    $mode = ([string]$document.mode).ToLowerInvariant()
    if ($validModes -notcontains $mode)
    {
        throw "invalid hunt mode in $path`: '$($document.mode)'"
    }
    if ($null -eq $document.PSObject.Properties["findings"] -or
        $document.findings -isnot [System.Array])
    {
        throw "findings must be a JSON array: $path"
    }

    $findings = @($document.findings)
    $kernelProcesses = Get-RequiredJsonInteger -Container $document.summary -Name "kernel_processes" -Context "summary"
    $systemProcesses = Get-RequiredJsonInteger -Container $document.summary -Name "system_process_information_processes" -Context "summary"
    $toolhelpProcesses = Get-RequiredJsonInteger -Container $document.summary -Name "toolhelp_processes" -Context "summary"
    $systemThreads = Get-RequiredJsonInteger -Container $document.summary -Name "system_process_information_threads" -Context "summary"
    $toolhelpThreads = Get-RequiredJsonInteger -Container $document.summary -Name "toolhelp_threads" -Context "summary"
    $scannedProcesses = Get-RequiredJsonInteger -Container $document.summary -Name "scanned_processes" -Context "summary"
    $summaryFindings = Get-RequiredJsonInteger -Container $document.summary -Name "findings" -Context "summary"
    $summaryHigh = Get-RequiredJsonInteger -Container $document.summary -Name "high" -Context "summary"
    $summaryMedium = Get-RequiredJsonInteger -Container $document.summary -Name "medium" -Context "summary"
    $summaryLow = Get-RequiredJsonInteger -Container $document.summary -Name "low" -Context "summary"
    $summaryInfo = Get-RequiredJsonInteger -Container $document.summary -Name "info" -Context "summary"
    $wfpFilters = Get-RequiredJsonInteger -Container $document.summary -Name "wfp_filters" -Context "summary"
    $suspiciousWfpFilters = Get-RequiredJsonInteger -Container $document.summary -Name "suspicious_wfp_filters" -Context "summary"
    $qosPolicies = Get-RequiredJsonInteger -Container $document.summary -Name "qos_policies" -Context "summary"
    $suspiciousQosPolicies = Get-RequiredJsonInteger -Container $document.summary -Name "suspicious_qos_policies" -Context "summary"
    $bindMappings = Get-RequiredJsonInteger -Container $document.summary -Name "bindflt_global_mappings" -Context "summary"
    $suspiciousBindMappings = Get-RequiredJsonInteger -Container $document.summary -Name "suspicious_bindflt_global_mappings" -Context "summary"
    $bindProcessBindings = Get-RequiredJsonInteger -Container $document.summary -Name "bindflt_process_bindings" -Context "summary"
    $cloudFileImages = Get-RequiredJsonInteger -Container $document.summary -Name "cloudfiles_placeholder_images" -Context "summary"
    $suspiciousCloudFileImages = Get-RequiredJsonInteger -Container $document.summary -Name "suspicious_cloudfiles_images" -Context "summary"
    $cidFullEnumeration = Get-RequiredJsonBoolean -Container $document.summary -Name "cid_table_full_enumeration" -Context "summary"
    $cidFullProcessEnumeration = Get-RequiredJsonBoolean -Container $document.summary -Name "cid_table_full_process_enumeration" -Context "summary"
    $cidDirectEntryEnumeration = Get-RequiredJsonBoolean -Container $document.summary -Name "cid_table_direct_entry_enumeration" -Context "summary"
    $cidFullThreadEnumeration = Get-RequiredJsonBoolean -Container $document.summary -Name "cid_table_full_thread_enumeration" -Context "summary"
    $cidThreadCrossViewComplete = Get-RequiredJsonBoolean -Container $document.summary -Name "cid_table_thread_cross_view_complete" -Context "summary"
    $cidLookupOnly = Get-RequiredJsonBoolean -Container $document.summary -Name "cid_table_lookup_only" -Context "summary"
    $cidAnchor = [string]$document.summary.cid_table_anchor
    $cidTableAddress = [string]$document.summary.cid_table_address
    $cidTableCode = [string]$document.summary.cid_table_code
    $cidLevel = Get-RequiredJsonInteger -Container $document.summary -Name "cid_table_level" -Context "summary"
    $cidNextHandle = Get-RequiredJsonInteger -Container $document.summary -Name "cid_table_next_handle" -Context "summary"
    $cidAllocatedLeaves = Get-RequiredJsonInteger -Container $document.summary -Name "cid_table_allocated_leaves" -Context "summary"
    $cidAllocatedCapacity = Get-RequiredJsonInteger -Container $document.summary -Name "cid_table_allocated_handle_capacity" -Context "summary"
    $cidProbes = Get-RequiredJsonInteger -Container $document.summary -Name "cid_table_probes" -Context "summary"
    $cidProcesses = Get-RequiredJsonInteger -Container $document.summary -Name "cid_table_processes" -Context "summary"
    $cidDiscoveredProcesses = Get-RequiredJsonInteger -Container $document.summary -Name "cid_table_discovered_processes" -Context "summary"
    $cidDirectEntries = Get-RequiredJsonInteger -Container $document.summary -Name "cid_table_direct_entries" -Context "summary"
    $cidDirectProcesses = Get-RequiredJsonInteger -Container $document.summary -Name "cid_table_direct_processes" -Context "summary"
    $cidDirectThreads = Get-RequiredJsonInteger -Container $document.summary -Name "cid_table_direct_threads" -Context "summary"
    $cidUnclassifiedEntries = Get-RequiredJsonInteger -Container $document.summary -Name "cid_table_unclassified_entries" -Context "summary"
    $cidThreadFindings = Get-RequiredJsonInteger -Container $document.summary -Name "cid_table_thread_findings" -Context "summary"
    $cidPersistentThreadViewMisses = Get-RequiredJsonInteger -Container $document.summary -Name "cid_table_persistent_thread_view_misses" -Context "summary"
    $cidProbeFailures = Get-RequiredJsonInteger -Container $document.summary -Name "cid_table_probe_failures" -Context "summary"
    $cidPersistentApiMisses = Get-RequiredJsonInteger -Container $document.summary -Name "cid_table_persistent_api_misses" -Context "summary"
    $coverageComplete = Get-RequiredJsonBoolean -Container $document.summary -Name "coverage_complete" -Context "summary"
    $inventoryIncomplete = Get-RequiredJsonBoolean -Container $document.summary -Name "process_inventory_incomplete" -Context "summary"
    $triageIncomplete = Get-RequiredJsonBoolean -Container $document.summary -Name "process_triage_coverage_incomplete" -Context "summary"
    $deepImageIncomplete = Get-RequiredJsonBoolean -Container $document.summary -Name "deep_image_comparison_coverage_incomplete" -Context "summary"
    $driverServiceIncomplete = Get-RequiredJsonBoolean -Container $document.summary -Name "driver_service_coverage_incomplete" -Context "summary"
    $wfpIncomplete = Get-RequiredJsonBoolean -Container $document.summary -Name "wfp_filter_coverage_incomplete" -Context "summary"
    $qosIncomplete = Get-RequiredJsonBoolean -Container $document.summary -Name "qos_policy_coverage_incomplete" -Context "summary"
    $bindGlobalIncomplete = Get-RequiredJsonBoolean -Container $document.summary -Name "bindflt_global_coverage_incomplete" -Context "summary"
    $bindProcessIncomplete = Get-RequiredJsonBoolean -Container $document.summary -Name "bindflt_process_correlation_coverage_incomplete" -Context "summary"
    $bindSiloUnsupported = Get-RequiredJsonBoolean -Container $document.summary -Name "bindflt_silo_coverage_unsupported" -Context "summary"
    $cloudMetadataIncomplete = Get-RequiredJsonBoolean -Container $document.summary -Name "cloudfiles_placeholder_coverage_incomplete" -Context "summary"
    $cloudProtectionIncomplete = Get-RequiredJsonBoolean -Container $document.summary -Name "cloudfiles_protection_correlation_incomplete" -Context "summary"
    $threatIntelActive = Get-RequiredJsonBoolean -Container $document.summary -Name "threat_intel_active" -Context "summary"
    $threatIntelAvailable = Get-RequiredJsonBoolean -Container $document.summary -Name "threat_intel_available" -Context "summary"
    $threatIntelIncomplete = Get-RequiredJsonBoolean -Container $document.summary -Name "threat_intel_correlation_incomplete" -Context "summary"

    $cidThreadsProperty =
        $document.PSObject.Properties["cid_threads"]
    if ($null -eq $cidThreadsProperty -or
        $cidThreadsProperty.Value -isnot [System.Array])
    {
        throw "cid_threads must be a JSON array in $path"
    }
    $cidThreads = @($cidThreadsProperty.Value)
    $seenThreadIds =
        [System.Collections.Generic.HashSet[uint32]]::new()
    $directThreadRecords = 0
    $suspiciousThreadRecords = 0
    foreach ($record in $cidThreads)
    {
        if ($null -eq $record)
        {
            throw "cid_threads contains a null item in $path"
        }
        $threadId = Get-RequiredJsonInteger -Container $record -Name "tid" -Context "cid_threads"
        $processId = Get-RequiredJsonInteger -Container $record -Name "pid" -Context "cid_threads"
        if ($threadId -le 0 -or
            $threadId -gt [uint32]::MaxValue -or
            $processId -gt [uint32]::MaxValue)
        {
            throw "cid_threads has an out-of-range TID or PID in $path"
        }
        if (-not $seenThreadIds.Add([uint32]$threadId))
        {
            throw "cid_threads contains duplicate tid=$threadId in $path"
        }

        $directSeen = Get-RequiredJsonBoolean -Container $record -Name "direct_cid_seen" -Context "cid_threads"
        $identityRevalidated = Get-RequiredJsonBoolean -Container $record -Name "identity_revalidated" -Context "cid_threads"
        $viewsRevalidated = Get-RequiredJsonBoolean -Container $record -Name "views_revalidated" -Context "cid_threads"
        $lifecycleChanged = Get-RequiredJsonBoolean -Container $record -Name "lifecycle_changed" -Context "cid_threads"
        $suspicious = Get-RequiredJsonBoolean -Container $record -Name "suspicious" -Context "cid_threads"
        foreach ($field in @(
            "terminated",
            "executive_thread_list_seen",
            "scheduler_thread_list_seen",
            "system_process_information_seen",
            "toolhelp_seen"
        ))
        {
            $null = Get-RequiredJsonBoolean -Container $record -Name $field -Context "cid_threads"
        }
        foreach ($field in @(
            "object_header",
            "ethread",
            "eprocess"
        ))
        {
            $property = $record.PSObject.Properties[$field]
            if ($null -eq $property -or
                $property.Value -isnot [string] -or
                [string]$property.Value -notmatch '^0x[0-9a-fA-F]{16}$')
            {
                throw "cid_threads.$field must be a 16-digit hexadecimal string in $path"
            }
        }
        foreach ($field in @("reasons", "warnings"))
        {
            $property = $record.PSObject.Properties[$field]
            if ($null -eq $property -or
                $property.Value -isnot [System.Array])
            {
                throw "cid_threads.$field must be a JSON array in $path"
            }
        }

        if ($directSeen)
        {
            ++$directThreadRecords
        }
        if ($suspicious)
        {
            ++$suspiciousThreadRecords
        }
        if ($cidThreadCrossViewComplete -and
            (-not $identityRevalidated -or
             -not $viewsRevalidated))
        {
            throw "complete CID thread cross-view contains an unstable identity for tid=$threadId in $path"
        }
    }
    if (($cidFullThreadEnumeration -or
         $cidThreadCrossViewComplete) -and
        ($cidThreads.Count -lt $cidDirectThreads -or
         $directThreadRecords -ne $cidDirectThreads))
    {
        throw "cid_threads does not cover every direct CID thread entry in $path"
    }
    if ($suspiciousThreadRecords -ne $cidThreadFindings -or
        $suspiciousThreadRecords -ne
            $cidPersistentThreadViewMisses)
    {
        throw "CID thread finding, persistent-miss, and suspicious-record counts disagree in $path"
    }
    $threadCrossViewFindings =
        @($findings | Where-Object {
            [string]$_.class -eq "thread_cross_view"
        }).Count
    if ($threadCrossViewFindings -ne $cidThreadFindings)
    {
        throw "CID thread finding count does not match thread_cross_view findings in $path"
    }

    if ($coverageComplete -and
        ($inventoryIncomplete -or $triageIncomplete -or
            $deepImageIncomplete -or $driverServiceIncomplete -or
            $wfpIncomplete -or $qosIncomplete -or
            $bindGlobalIncomplete -or
            $bindProcessIncomplete -or $cloudMetadataIncomplete -or
            $cloudProtectionIncomplete -or
            $threatIntelIncomplete))
    {
        throw "summary coverage flags are inconsistent in $path"
    }
    if ($coverageComplete -and
        (-not $cidFullEnumeration -or
         -not $cidFullProcessEnumeration -or
         -not $cidDirectEntryEnumeration -or
         -not $cidFullThreadEnumeration -or
         -not $cidThreadCrossViewComplete))
    {
        throw "complete coverage requires direct process-and-thread CID enumeration with a complete thread cross-view in $path"
    }
    if ($cidLookupOnly -and
        ($cidFullEnumeration -or
         $cidFullProcessEnumeration -or
         $cidDirectEntryEnumeration -or
         $cidFullThreadEnumeration -or
         $cidThreadCrossViewComplete))
    {
        throw "lookup-only CID mode conflicts with full/direct CID coverage flags in $path"
    }
    if ($cidFullEnumeration -or
        $cidFullProcessEnumeration -or
        $cidDirectEntryEnumeration -or
        $cidFullThreadEnumeration -or
        $cidThreadCrossViewComplete)
    {
        $cidAnchor = Get-RequiredJsonNonzeroHex64 -Container $document.summary -Name "cid_table_anchor" -Context "summary"
        $cidTableAddress = Get-RequiredJsonNonzeroHex64 -Container $document.summary -Name "cid_table_address" -Context "summary"
        $cidTableCode = Get-RequiredJsonNonzeroHex64 -Container $document.summary -Name "cid_table_code" -Context "summary"
        if ($cidLevel -lt 0 -or $cidLevel -gt 2)
        {
            throw "summary.cid_table_level must be 0, 1, or 2 in $path"
        }
        if ($cidNextHandle -lt 8 -or ($cidNextHandle % 4) -ne 0)
        {
            throw "summary.cid_table_next_handle is not an aligned allocated CID bound in $path"
        }
        if ($cidAllocatedLeaves -le 0 -or
            $cidAllocatedCapacity -ne $cidNextHandle)
        {
            throw "CID allocated-leaf topology is inconsistent in $path"
        }
        if ($cidProbes -lt (($cidNextHandle / 4) - 1))
        {
            throw "CID probe count does not cover the validated range in $path"
        }
        if ($cidProcesses -le 0 -or
            $cidDiscoveredProcesses -gt $cidProcesses)
        {
            throw "CID process counts are inconsistent in $path"
        }
        if ($cidProbeFailures -ne 0)
        {
            throw "CID probe failures are nonzero in $path"
        }
        if ($cidPersistentApiMisses -ne 0)
        {
            throw "persistent API-visible CID misses are nonzero in $path"
        }
        if ($cidDirectEntryEnumeration -and
            ($cidDirectEntries -le 0 -or
            $cidDirectProcesses -le 0 -or
             $cidDirectThreads -le 0))
        {
            throw "direct CID typed inventory is empty in $path"
        }
        if ($cidDirectEntryEnumeration -and
            $cidDirectEntries -ne
                ($cidDirectProcesses + $cidDirectThreads))
        {
            throw "direct CID entry count does not equal typed process plus thread entries in $path"
        }
        if ($cidDirectEntryEnumeration -and
            $cidUnclassifiedEntries -ne 0)
        {
            throw "direct CID enumeration has unclassified entries in $path"
        }
        if (($cidFullThreadEnumeration -or
             $cidThreadCrossViewComplete) -and
            ($systemThreads -le 0 -or
             $toolhelpThreads -le 0 -or
             $cidDirectThreads -le 0))
        {
            throw "complete CID thread cross-view has an empty API or direct thread inventory in $path"
        }
    }
    if ($threatIntelActive -and -not $threatIntelAvailable)
    {
        throw "active threat-intel collection is marked unavailable in $path"
    }
    if ($RequireThreatIntelActive -and
        (-not $threatIntelActive -or
         -not $threatIntelAvailable))
    {
        throw "active and available threat-intel coverage is required in $path"
    }
    if ($mode -eq "deep" -and
        $coverageComplete -and
        -not $threatIntelAvailable)
    {
        throw "complete deep hunt lacks threat-intel correlation coverage in $path"
    }
    if ($coverageComplete -and
        ($kernelProcesses -eq 0 -or $systemProcesses -eq 0 -or
            $toolhelpProcesses -eq 0 -or $scannedProcesses -eq 0))
    {
        throw "complete hunt has an empty process inventory in $path"
    }
    if ($summaryFindings -ne $findings.Count)
    {
        throw "summary/findings count mismatch in $path"
    }
    if ($suspiciousWfpFilters -gt $wfpFilters)
    {
        throw "suspicious WFP filter count exceeds total in $path"
    }
    if ($suspiciousQosPolicies -gt $qosPolicies)
    {
        throw "suspicious QoS policy count exceeds total in $path"
    }
    if ($suspiciousBindMappings -gt $bindMappings)
    {
        throw "suspicious bindflt mapping count exceeds total in $path"
    }
    if ($suspiciousCloudFileImages -gt $cloudFileImages)
    {
        throw "suspicious CloudFiles image count exceeds total in $path"
    }
    if ($null -eq $document.PSObject.Properties["cloudfiles_images"] -or
        $document.cloudfiles_images -isnot [System.Array])
    {
        throw "cloudfiles_images must be a JSON array: $path"
    }
    $cloudFileRecords = @($document.cloudfiles_images)
    $actualSuspiciousCloudFileImages = 0
    foreach ($record in $cloudFileRecords)
    {
        if ($null -eq $record)
        {
            throw "null CloudFiles observation in $path"
        }
        $suspiciousProperty =
            $record.PSObject.Properties["suspicious"]
        if ($null -eq $suspiciousProperty -or
            $suspiciousProperty.Value -isnot [bool])
        {
            throw "CloudFiles observation suspicious flag is missing or invalid in $path"
        }
        if ($suspiciousProperty.Value)
        {
            ++$actualSuspiciousCloudFileImages
        }
    }
    if ($cloudFileImages -ne $cloudFileRecords.Count -or
        $suspiciousCloudFileImages -ne
            $actualSuspiciousCloudFileImages)
    {
        throw "CloudFiles observation counts do not match summary in $path"
    }

    $runId = "{0:D2}:{1}" -f ($runIndex + 1), [System.IO.Path]::GetFileName($path)
    $actualRiskCounts = @{
        high = 0
        medium = 0
        low = 0
        info = 0
    }
    $actualSuspiciousWfpFilters = 0
    $actualSuspiciousQosPolicies = 0
    $actualSuspiciousBindMappings = 0
    $actualBindProcessBindings = 0
    $actualCloudFileFindings = 0

    foreach ($finding in $findings)
    {
        if ($null -eq $finding)
        {
            throw "null finding in $path"
        }
        $reasonsProperty =
            $finding.PSObject.Properties["reasons"]
        if ($null -eq $reasonsProperty -or
            $reasonsProperty.Value -isnot
                [System.Array])
        {
            throw "finding reasons must be a JSON array in $path"
        }
        foreach ($reason in
            @($reasonsProperty.Value))
        {
            if ($reason -isnot [string] -or
                [string]::IsNullOrWhiteSpace(
                    [string]$reason))
            {
                throw "finding reasons must contain non-empty strings in $path"
            }
        }

        $risk = ([string]$finding.risk).ToLowerInvariant()
        if (-not $actualRiskCounts.ContainsKey($risk))
        {
            throw "unsupported finding risk '$($finding.risk)' in $path"
        }
        $actualRiskCounts[$risk] = [int]$actualRiskCounts[$risk] + 1

        $reasonCodes = @($finding.reasons)
        if (($reasonCodes -contains
                "wfp_security_product_block_filter") -or
            ($reasonCodes -contains
                "wfp_anticheat_block_filter"))
        {
            ++$actualSuspiciousWfpFilters
        }
        if ($reasonCodes -contains
            "qos_security_product_throttle_policy")
        {
            ++$actualSuspiciousQosPolicies
        }
        if ($reasonCodes -contains
            "bind_link_process_binding_state")
        {
            ++$actualBindProcessBindings
        }
        elseif ($reasonCodes -contains
            "bindflt_active_global_mapping")
        {
            ++$actualSuspiciousBindMappings
        }
        if ([string]$finding.class -eq
            "cloudfiles_false_file_immutability")
        {
            ++$actualCloudFileFindings
        }

        $identity = Get-FindingIdentity -Finding $finding
        if (-not $groups.ContainsKey($identity.Canonical))
        {
            $groups[$identity.Canonical] = [pscustomobject]@{
                Fingerprint = $identity.Fingerprint
                Canonical = $identity.Canonical
                Risk = [string]$finding.risk
                Confidence = [string]$finding.confidence
                ClassName = [string]$finding.class
                Title = [string]$finding.title
                Image = Get-NormalizedLeaf -Value ([string]$finding.image)
                Module = Get-NormalizedLeaf -Value ([string]$finding.module)
                Reasons = $identity.Reasons
                Occurrences = 0
                RunIds = [System.Collections.Generic.HashSet[string]]::new(
                    [System.StringComparer]::Ordinal)
                Samples = [System.Collections.Generic.List[object]]::new()
            }
        }

        $group = $groups[$identity.Canonical]
        ++$group.Occurrences
        [void]$group.RunIds.Add($runId)
        if ($group.Samples.Count -lt 5)
        {
            $group.Samples.Add([pscustomobject][ordered]@{
                run_id = $runId
                pid = [int64]$finding.pid
                eprocess = [string]$finding.eprocess
                address = [string]$finding.address
                image = [string]$finding.image
                module = [string]$finding.module
                evidence = Convert-EvidenceToOrderedMap -Evidence $finding.evidence
            })
        }
    }

    if ($suspiciousWfpFilters -ne
            $actualSuspiciousWfpFilters -or
        $suspiciousQosPolicies -ne
            $actualSuspiciousQosPolicies -or
        $suspiciousBindMappings -ne
            $actualSuspiciousBindMappings -or
        $bindProcessBindings -ne
            $actualBindProcessBindings -or
        $suspiciousCloudFileImages -ne
            $actualCloudFileFindings)
    {
        throw "detector summary counters do not match findings in $path"
    }

    foreach ($risk in @("high", "medium", "low", "info"))
    {
        $summaryRisk = switch ($risk)
        {
            "high" { $summaryHigh }
            "medium" { $summaryMedium }
            "low" { $summaryLow }
            "info" { $summaryInfo }
        }
        if ($summaryRisk -ne [int64]$actualRiskCounts[$risk])
        {
            throw "summary.$risk does not match findings risk count in $path"
        }
    }

    $runs.Add([pscustomobject][ordered]@{
        run_id = $runId
        path = $path
        timestamp_utc = [string]$document.timestamp_utc
        mode = $mode
        kernel_processes = $kernelProcesses
        system_process_information_processes = $systemProcesses
        toolhelp_processes = $toolhelpProcesses
        system_process_information_threads = $systemThreads
        toolhelp_threads = $toolhelpThreads
        scanned_processes = $scannedProcesses
        findings = $summaryFindings
        high = $summaryHigh
        medium = $summaryMedium
        low = $summaryLow
        info = $summaryInfo
        wfp_filters = $wfpFilters
        suspicious_wfp_filters = $suspiciousWfpFilters
        wfp_filter_coverage_incomplete = $wfpIncomplete
        qos_policies = $qosPolicies
        suspicious_qos_policies = $suspiciousQosPolicies
        qos_policy_coverage_incomplete = $qosIncomplete
        bindflt_global_mappings = $bindMappings
        suspicious_bindflt_global_mappings = $suspiciousBindMappings
        bindflt_process_bindings = $bindProcessBindings
        bindflt_global_coverage_incomplete = $bindGlobalIncomplete
        bindflt_process_correlation_coverage_incomplete = $bindProcessIncomplete
        bindflt_silo_coverage_unsupported = $bindSiloUnsupported
        cloudfiles_placeholder_images = $cloudFileImages
        suspicious_cloudfiles_images = $suspiciousCloudFileImages
        cloudfiles_placeholder_coverage_incomplete = $cloudMetadataIncomplete
        cloudfiles_protection_correlation_incomplete = $cloudProtectionIncomplete
        cid_table_full_enumeration = $cidFullEnumeration
        cid_table_full_process_enumeration = $cidFullProcessEnumeration
        cid_table_direct_entry_enumeration = $cidDirectEntryEnumeration
        cid_table_full_thread_enumeration = $cidFullThreadEnumeration
        cid_table_thread_cross_view_complete = $cidThreadCrossViewComplete
        cid_table_lookup_only = $cidLookupOnly
        cid_table_anchor = $cidAnchor
        cid_table_address = $cidTableAddress
        cid_table_code = $cidTableCode
        cid_table_level = $cidLevel
        cid_table_next_handle = $cidNextHandle
        cid_table_allocated_leaves = $cidAllocatedLeaves
        cid_table_allocated_handle_capacity = $cidAllocatedCapacity
        cid_table_probes = $cidProbes
        cid_table_processes = $cidProcesses
        cid_table_discovered_processes = $cidDiscoveredProcesses
        cid_table_direct_entries = $cidDirectEntries
        cid_table_direct_processes = $cidDirectProcesses
        cid_table_direct_threads = $cidDirectThreads
        cid_table_unclassified_entries = $cidUnclassifiedEntries
        cid_table_thread_findings = $cidThreadFindings
        cid_table_persistent_thread_view_misses = $cidPersistentThreadViewMisses
        cid_table_probe_failures = $cidProbeFailures
        cid_table_persistent_api_misses = $cidPersistentApiMisses
        process_inventory_incomplete = $inventoryIncomplete
        process_triage_coverage_incomplete = $triageIncomplete
        deep_image_comparison_coverage_incomplete = $deepImageIncomplete
        driver_service_coverage_incomplete = $driverServiceIncomplete
        threat_intel_active = $threatIntelActive
        threat_intel_available = $threatIntelAvailable
        threat_intel_correlation_incomplete = $threatIntelIncomplete
        coverage_complete = $coverageComplete
        warnings = @($document.warnings)
    })
}

$groupRecords = [System.Collections.Generic.List[object]]::new()
foreach ($group in @($groups.Values | Sort-Object Risk, ClassName, Image, Fingerprint))
{
    $recurrence = if ($group.RunIds.Count -eq $runs.Count) { "deterministic" } else { "intermittent" }
    $groupRecords.Add([pscustomobject][ordered]@{
        fingerprint = $group.Fingerprint
        recurrence = $recurrence
        run_hits = $group.RunIds.Count
        run_count = $runs.Count
        occurrences = $group.Occurrences
        risk = $group.Risk
        confidence = $group.Confidence
        class = $group.ClassName
        title = $group.Title
        image = $group.Image
        module = $group.Module
        reasons = $group.Reasons
        run_ids = @($group.RunIds | Sort-Object)
        samples = @($group.Samples)
    })
}

$completeRuns = @($runs | Where-Object { $_.coverage_complete }).Count
$totalFindings = [int64](($runs | Measure-Object -Property findings -Sum).Sum)
$deterministicGroups = @($groupRecords | Where-Object { $_.recurrence -eq "deterministic" }).Count
$intermittentGroups = @($groupRecords | Where-Object { $_.recurrence -eq "intermittent" }).Count
$allCleanComplete = $completeRuns -eq $runs.Count -and $totalFindings -eq 0

$report = [pscustomobject][ordered]@{
    schema = "kn-live-dbg.hunt-clean-analysis.v1"
    generated_at_utc = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    summary = [pscustomobject][ordered]@{
        run_count = $runs.Count
        complete_runs = $completeRuns
        total_findings = $totalFindings
        unique_fingerprints = $groupRecords.Count
        deterministic_fingerprints = $deterministicGroups
        intermittent_fingerprints = $intermittentGroups
        all_clean_complete = $allCleanComplete
    }
    runs = @($runs)
    finding_groups = @($groupRecords)
}

$jsonOutputPath = ""
$markdownOutputPath = ""
if (-not [string]::IsNullOrWhiteSpace($OutputJson))
{
    $jsonOutputPath = [System.IO.Path]::GetFullPath($OutputJson)
}
if (-not [string]::IsNullOrWhiteSpace($OutputMarkdown))
{
    $markdownOutputPath =
        [System.IO.Path]::GetFullPath($OutputMarkdown)
}

foreach ($outputPath in @(
        $jsonOutputPath,
        $markdownOutputPath))
{
    if (-not [string]::IsNullOrWhiteSpace($outputPath) -and
        $seenInputs.Contains($outputPath))
    {
        throw "report output must not overwrite a hunt JSON input: $outputPath"
    }
}
if (-not [string]::IsNullOrWhiteSpace($jsonOutputPath) -and
    -not [string]::IsNullOrWhiteSpace($markdownOutputPath) -and
    [string]::Equals(
        $jsonOutputPath,
        $markdownOutputPath,
        [System.StringComparison]::OrdinalIgnoreCase))
{
    throw "JSON and Markdown report outputs must use different paths"
}

if (-not [string]::IsNullOrWhiteSpace($jsonOutputPath))
{
    $jsonOutputDirectory = Split-Path -Parent $jsonOutputPath
    if (-not [string]::IsNullOrWhiteSpace($jsonOutputDirectory))
    {
        New-Item -ItemType Directory -Force -Path $jsonOutputDirectory | Out-Null
    }
    $report | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $jsonOutputPath -Encoding UTF8
}

if (-not [string]::IsNullOrWhiteSpace($markdownOutputPath))
{
    $markdownOutputDirectory = Split-Path -Parent $markdownOutputPath
    if (-not [string]::IsNullOrWhiteSpace($markdownOutputDirectory))
    {
        New-Item -ItemType Directory -Force -Path $markdownOutputDirectory | Out-Null
    }

    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add("# KnLiveDbg hunt clean-host analysis")
    $lines.Add("")
    $lines.Add("- Runs: $($runs.Count)")
    $lines.Add("- Complete runs: $completeRuns")
    $lines.Add("- Total findings: $totalFindings")
    $lines.Add("- Unique fingerprints: $($groupRecords.Count)")
    $lines.Add("- Deterministic fingerprints: $deterministicGroups")
    $lines.Add("- Intermittent fingerprints: $intermittentGroups")
    $lines.Add("- All clean and complete: $($allCleanComplete.ToString().ToLowerInvariant())")
    $lines.Add("")
    $lines.Add("| Fingerprint | Recurrence | Risk | Class | Image | Reasons |")
    $lines.Add("| --- | --- | --- | --- | --- | --- |")
    foreach ($group in $groupRecords)
    {
        $reasonText = @($group.reasons) -join ", "
        $lines.Add("| $($group.fingerprint) | $($group.recurrence) ($($group.run_hits)/$($group.run_count)) | $($group.risk) | $($group.class) | $($group.image) | $reasonText |")
    }
    $lines | Set-Content -LiteralPath $markdownOutputPath -Encoding UTF8
}

Write-Host "hunt clean-host analysis"
Write-Host "  runs=$($runs.Count) complete_runs=$completeRuns"
Write-Host "  findings=$totalFindings unique=$($groupRecords.Count)"
Write-Host "  deterministic=$deterministicGroups intermittent=$intermittentGroups"
Write-Host "  all_clean_complete=$($allCleanComplete.ToString().ToLowerInvariant())"
foreach ($group in $groupRecords)
{
    Write-Host "  fingerprint=$($group.fingerprint) recurrence=$($group.recurrence) hits=$($group.run_hits)/$($group.run_count) class=$($group.class) image=$($group.image) reasons=$(@($group.reasons) -join ',')"
}
