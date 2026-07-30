param(
    [Parameter(Mandatory = $true)]
    [string]$HuntJson,

    [Parameter(Mandatory = $true)]
    [ValidateSet("InSyncNegative", "ModifiedPositive")]
    [string]$Scenario,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$ProcessId,

    [Parameter(Mandatory = $true)]
    [string]$ImagePath
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

function Test-RequiredIntegerProperty
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$Container,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]]$Failures,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    $property = $Container.PSObject.Properties[$Name]
    if ($null -eq $property)
    {
        Add-Failure -Failures $Failures -Message "$Context.$Name is missing"
        return $false
    }
    if (-not (Test-JsonInteger -Value $property.Value))
    {
        Add-Failure -Failures $Failures -Message "$Context.$Name must be a JSON integer"
        return $false
    }
    return $true
}

function Test-RequiredBooleanProperty
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$Container,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]]$Failures,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    $property = $Container.PSObject.Properties[$Name]
    if ($null -eq $property)
    {
        Add-Failure -Failures $Failures -Message "$Context.$Name is missing"
        return $false
    }
    if ($property.Value -isnot [bool])
    {
        Add-Failure -Failures $Failures -Message "$Context.$Name must be a JSON boolean"
        return $false
    }
    return $true
}

$failures = [System.Collections.Generic.List[string]]::new()
$document = $null
$resolvedJson = ""
$resolvedImage = ""

try
{
    $resolvedJson = (Resolve-Path -LiteralPath $HuntJson).Path
    $resolvedImage = [IO.Path]::GetFullPath($ImagePath)
    $document =
        Get-Content -LiteralPath $resolvedJson -Raw |
        ConvertFrom-Json
}
catch
{
    Add-Failure -Failures $failures -Message "unable to read validation inputs: $($_.Exception.Message)"
}

if ($null -ne $document)
{
    if ([string]$document.schema -ne "kn-live-dbg.hunt.v1")
    {
        Add-Failure -Failures $failures -Message "unsupported schema '$($document.schema)'"
    }
    if ($null -eq $document.summary)
    {
        Add-Failure -Failures $failures -Message "summary is missing"
    }
    else
    {
        $placeholderCountValid =
            Test-RequiredIntegerProperty `
                -Container $document.summary `
                -Name "cloudfiles_placeholder_images" `
                -Failures $failures `
                -Context "summary"
        $suspiciousCountValid =
            Test-RequiredIntegerProperty `
                -Container $document.summary `
                -Name "suspicious_cloudfiles_images" `
                -Failures $failures `
                -Context "summary"
        foreach ($field in @(
            "cloudfiles_placeholder_coverage_incomplete",
            "cloudfiles_protection_correlation_incomplete"
        ))
        {
            if (Test-RequiredBooleanProperty `
                    -Container $document.summary `
                    -Name $field `
                    -Failures $failures `
                    -Context "summary")
            {
                if ($document.summary.$field)
                {
                    Add-Failure -Failures $failures -Message "summary.$field is true"
                }
            }
        }
    }

    $observations = @()
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
        $observations = @($document.cloudfiles_images)
    }

    $actualSuspicious =
        @($observations | Where-Object {
            $_.PSObject.Properties["suspicious"] -and
            $_.suspicious -is [bool] -and
            $_.suspicious
        }).Count
    if ($null -ne $document.summary)
    {
        if ($placeholderCountValid -and
            [int64]$document.summary.cloudfiles_placeholder_images -ne
                $observations.Count)
        {
            Add-Failure -Failures $failures -Message (
                "summary.cloudfiles_placeholder_images=$($document.summary.cloudfiles_placeholder_images) " +
                "does not match cloudfiles_images count=$($observations.Count)")
        }
        if ($suspiciousCountValid -and
            [int64]$document.summary.suspicious_cloudfiles_images -ne
                $actualSuspicious)
        {
            Add-Failure -Failures $failures -Message (
                "summary.suspicious_cloudfiles_images=$($document.summary.suspicious_cloudfiles_images) " +
                "does not match suspicious observation count=$actualSuspicious")
        }
    }

    foreach ($observation in $observations)
    {
        foreach ($field in @(
            "pid",
            "module_size",
            "on_disk_data_size",
            "validated_data_size",
            "modified_data_size",
            "properties_size",
            "pin_state",
            "in_sync_state",
            "file_identity_length"
        ))
        {
            [void](Test-RequiredIntegerProperty `
                -Container $observation `
                -Name $field `
                -Failures $failures `
                -Context "cloudfiles_images")
        }
        foreach ($field in @(
            "cloud_reparse_tag_observed",
            "placeholder_info_identification_fallback_used",
            "process_protection_resolved",
            "deep_mismatch_correlated",
            "suspicious"
        ))
        {
            [void](Test-RequiredBooleanProperty `
                -Container $observation `
                -Name $field `
                -Failures $failures `
                -Context "cloudfiles_images")
        }
        if ($null -eq $observation.PSObject.Properties["reasons"] -or
            $observation.reasons -isnot [System.Array])
        {
            Add-Failure -Failures $failures -Message "cloudfiles_images.reasons must be a JSON array"
        }
    }

    $matchingObservations = @(
        $observations |
        Where-Object {
            (Test-JsonInteger -Value $_.pid) -and
            [int64]$_.pid -eq $ProcessId -and
            [string]::Equals(
                [string]$_.normalized_backing_path,
                $resolvedImage,
                [StringComparison]::OrdinalIgnoreCase)
        }
    )
    if ($matchingObservations.Count -ne 1)
    {
        Add-Failure -Failures $failures -Message (
            "expected exactly one CloudFiles observation for pid=$ProcessId " +
            "path='$resolvedImage'; actual=$($matchingObservations.Count)")
    }
    else
    {
        $observation = $matchingObservations[0]
        if ([string]$observation.placeholder_info_query_status -ne "0x00000000")
        {
            Add-Failure -Failures $failures -Message (
                "fixture placeholder query status is '$($observation.placeholder_info_query_status)'")
        }
        if ($observation.process_protection_resolved -is [bool] -and
            -not $observation.process_protection_resolved)
        {
            Add-Failure -Failures $failures -Message "fixture process protection was not resolved"
        }

        if ($Scenario -eq "InSyncNegative")
        {
            if ($observation.suspicious -is [bool] -and
                $observation.suspicious)
            {
                Add-Failure -Failures $failures -Message "in-sync fixture observation was marked suspicious"
            }
            if ((Test-JsonInteger -Value $observation.modified_data_size) -and
                [int64]$observation.modified_data_size -ne 0)
            {
                Add-Failure -Failures $failures -Message "in-sync fixture ModifiedDataSize is not zero"
            }
            if ((Test-JsonInteger -Value $observation.in_sync_state) -and
                [int64]$observation.in_sync_state -ne 1)
            {
                Add-Failure -Failures $failures -Message "in-sync fixture InSyncState is not IN_SYNC"
            }
            if (@($observation.reasons).Count -ne 0)
            {
                Add-Failure -Failures $failures -Message "in-sync fixture observation contains finding reasons"
            }
        }
        else
        {
            if ($observation.suspicious -is [bool] -and
                -not $observation.suspicious)
            {
                Add-Failure -Failures $failures -Message "modified fixture observation was not marked suspicious"
            }
            if ((Test-JsonInteger -Value $observation.modified_data_size) -and
                [int64]$observation.modified_data_size -le 0)
            {
                Add-Failure -Failures $failures -Message "modified fixture ModifiedDataSize is not positive"
            }
            if ((Test-JsonInteger -Value $observation.in_sync_state) -and
                [int64]$observation.in_sync_state -ne 0)
            {
                Add-Failure -Failures $failures -Message "modified fixture InSyncState is not NOT_IN_SYNC"
            }
            if (@($observation.reasons) -notcontains
                "cloudfiles_placeholder_modified_data")
            {
                Add-Failure -Failures $failures -Message "modified fixture observation lacks the modified-data reason"
            }
        }
    }

    $findings = @()
    if ($null -eq $document.PSObject.Properties["findings"])
    {
        Add-Failure -Failures $failures -Message "findings array is missing"
    }
    elseif ($document.findings -isnot [System.Array])
    {
        Add-Failure -Failures $failures -Message "findings must be a JSON array"
    }
    else
    {
        $findings = @($document.findings)
    }
    $fixtureFindings = @(
        $findings |
        Where-Object {
            (Test-JsonInteger -Value $_.pid) -and
            [int64]$_.pid -eq $ProcessId -and
            [string]$_.class -eq "cloudfiles_false_file_immutability"
        }
    )
    if ($Scenario -eq "InSyncNegative")
    {
        if ($fixtureFindings.Count -ne 0)
        {
            Add-Failure -Failures $failures -Message "in-sync fixture emitted a CloudFiles finding"
        }
    }
    else
    {
        $matchingFindings = @(
            $fixtureFindings |
            Where-Object {
                [string]$_.confidence -eq "high" -and
                @($_.reasons) -contains
                    "cloudfiles_placeholder_modified_data" -and
                $null -ne $_.evidence -and
                [string]::Equals(
                    [string]$_.evidence.normalized_backing_path,
                    $resolvedImage,
                    [StringComparison]::OrdinalIgnoreCase)
            }
        )
        if ($matchingFindings.Count -ne 1)
        {
            Add-Failure -Failures $failures -Message (
                "expected exactly one modified-data CloudFiles finding for the fixture; " +
                "actual=$($matchingFindings.Count)")
        }
    }

    $processes = @()
    if ($null -eq $document.PSObject.Properties["processes"] -or
        $document.processes -isnot [System.Array])
    {
        Add-Failure -Failures $failures -Message "processes must be a JSON array"
    }
    else
    {
        $processes = @($document.processes)
        $matchingProcesses = @(
            $processes |
            Where-Object {
                (Test-JsonInteger -Value $_.pid) -and
                [int64]$_.pid -eq $ProcessId
            }
        )
        if ($matchingProcesses.Count -ne 1)
        {
            Add-Failure -Failures $failures -Message (
                "expected exactly one process record for pid=$ProcessId; " +
                "actual=$($matchingProcesses.Count)")
        }
    }
}

if ($failures.Count -ne 0)
{
    Write-Host "CloudFiles hunt E2E validation failed"
    foreach ($failure in $failures)
    {
        Write-Host "  - $failure"
    }
    exit 1
}

Write-Host "CloudFiles hunt E2E validation passed"
Write-Host "  scenario=$Scenario pid=$ProcessId"
Write-Host "  image=$resolvedImage"
Write-Host "  hunt_json=$resolvedJson"
exit 0
