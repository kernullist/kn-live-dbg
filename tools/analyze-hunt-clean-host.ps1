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
    $scannedProcesses = Get-RequiredJsonInteger -Container $document.summary -Name "scanned_processes" -Context "summary"
    $summaryFindings = Get-RequiredJsonInteger -Container $document.summary -Name "findings" -Context "summary"
    $summaryHigh = Get-RequiredJsonInteger -Container $document.summary -Name "high" -Context "summary"
    $summaryMedium = Get-RequiredJsonInteger -Container $document.summary -Name "medium" -Context "summary"
    $summaryLow = Get-RequiredJsonInteger -Container $document.summary -Name "low" -Context "summary"
    $summaryInfo = Get-RequiredJsonInteger -Container $document.summary -Name "info" -Context "summary"
    $coverageComplete = Get-RequiredJsonBoolean -Container $document.summary -Name "coverage_complete" -Context "summary"
    $inventoryIncomplete = Get-RequiredJsonBoolean -Container $document.summary -Name "process_inventory_incomplete" -Context "summary"
    $triageIncomplete = Get-RequiredJsonBoolean -Container $document.summary -Name "process_triage_coverage_incomplete" -Context "summary"
    $deepImageIncomplete = Get-RequiredJsonBoolean -Container $document.summary -Name "deep_image_comparison_coverage_incomplete" -Context "summary"
    $driverServiceIncomplete = Get-RequiredJsonBoolean -Container $document.summary -Name "driver_service_coverage_incomplete" -Context "summary"
    $threatIntelActive = Get-RequiredJsonBoolean -Container $document.summary -Name "threat_intel_active" -Context "summary"
    $threatIntelAvailable = Get-RequiredJsonBoolean -Container $document.summary -Name "threat_intel_available" -Context "summary"
    $threatIntelIncomplete = Get-RequiredJsonBoolean -Container $document.summary -Name "threat_intel_correlation_incomplete" -Context "summary"
    if ($coverageComplete -and
        ($inventoryIncomplete -or $triageIncomplete -or
            $deepImageIncomplete -or $driverServiceIncomplete -or
            $threatIntelIncomplete))
    {
        throw "summary coverage flags are inconsistent in $path"
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

    $runId = "{0:D2}:{1}" -f ($runIndex + 1), [System.IO.Path]::GetFileName($path)
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
            throw "null finding in $path"
        }

        $risk = ([string]$finding.risk).ToLowerInvariant()
        if (-not $actualRiskCounts.ContainsKey($risk))
        {
            throw "unsupported finding risk '$($finding.risk)' in $path"
        }
        $actualRiskCounts[$risk] = [int]$actualRiskCounts[$risk] + 1

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
        scanned_processes = $scannedProcesses
        findings = $summaryFindings
        high = $summaryHigh
        medium = $summaryMedium
        low = $summaryLow
        info = $summaryInfo
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
