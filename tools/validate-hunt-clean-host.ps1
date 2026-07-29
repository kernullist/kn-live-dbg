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
            "scanned_processes",
            "findings",
            "high",
            "medium",
            "low",
            "info",
            "process_inventory_incomplete",
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
            "scanned_processes",
            "findings",
            "high",
            "medium",
            "low",
            "info"
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

        foreach ($field in @(
            "kernel_processes",
            "system_process_information_processes",
            "toolhelp_processes",
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
            "process_inventory_incomplete",
            "process_triage_coverage_incomplete",
            "deep_image_comparison_coverage_incomplete",
            "driver_service_coverage_incomplete",
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
                ($null -ne $document.summary.PSObject.Properties["threat_intel_correlation_incomplete"] -and
                    $document.summary.threat_intel_correlation_incomplete -is [bool] -and
                    $document.summary.threat_intel_correlation_incomplete)))
        {
            Add-Failure -Failures $failures -Message "summary.coverage_complete conflicts with an incomplete coverage flag"
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
