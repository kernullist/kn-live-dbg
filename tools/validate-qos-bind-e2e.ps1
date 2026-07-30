[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$HuntJson,

    [Parameter(Mandatory = $true)]
    [string]$PolicyName,

    [Parameter(Mandatory = $true)]
    [string]$QosTargetPath,

    [Parameter(Mandatory = $true)]
    [string]$FileVirtualPath,

    [Parameter(Mandatory = $true)]
    [string]$FileBackingPath,

    [Parameter(Mandatory = $true)]
    [string]$ProcessVirtualPath,

    [Parameter(Mandatory = $true)]
    [string]$ProcessBackingPath,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$ProcessId,

    [ValidateSet("Default", "Deep")]
    [string]$RequireMode = "Default"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-RequiredProperty
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$Object,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    if ($null -eq $Object)
    {
        throw "$Context is null"
    }
    $property =
        $Object.PSObject.Properties[$Name]
    if ($null -eq $property)
    {
        throw "$Context is missing property '$Name'"
    }
    # Unary comma preserves an empty JSON array without wrapping scalar
    # strings in List<object> on PowerShell 7 (Write-Output -NoEnumerate
    # behaves differently there than in Windows PowerShell 5.1).
    return ,$property.Value
}

function Get-RequiredString
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$Object,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Context,

        [switch]$AllowEmpty
    )

    $value =
        Get-RequiredProperty `
            -Object $Object `
            -Name $Name `
            -Context $Context
    if ($value -isnot [string] -or
        (-not $AllowEmpty -and
         [string]::IsNullOrWhiteSpace($value)))
    {
        throw "$Context property '$Name' must be a string"
    }
    return [string]$value
}

function Get-RequiredBoolean
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$Object,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    $value =
        Get-RequiredProperty `
            -Object $Object `
            -Name $Name `
            -Context $Context
    if ($value -isnot [bool])
    {
        throw "$Context property '$Name' must be a JSON boolean"
    }
    return [bool]$value
}

function Get-RequiredCount
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$Object,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    $value =
        Get-RequiredProperty `
            -Object $Object `
            -Name $Name `
            -Context $Context
    $integerTypes = @(
        [byte],
        [sbyte],
        [int16],
        [uint16],
        [int32],
        [uint32],
        [int64],
        [uint64]
    )
    $isInteger =
        $false
    foreach ($integerType in $integerTypes)
    {
        if ($value -is $integerType)
        {
            $isInteger = $true
            break
        }
    }
    if (-not $isInteger)
    {
        throw "$Context property '$Name' must be a JSON integer"
    }
    try
    {
        return [Convert]::ToUInt64($value)
    }
    catch
    {
        throw "$Context property '$Name' must be a non-negative integer"
    }
}

function Get-EvidenceString
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$Finding,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Context,

        [switch]$AllowEmpty
    )

    $evidence =
        Get-RequiredProperty `
            -Object $Finding `
            -Name "evidence" `
            -Context $Context
    return Get-RequiredString `
        -Object $evidence `
        -Name $Name `
        -Context "$Context evidence" `
        -AllowEmpty:$AllowEmpty
}

function Test-HasReason
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$Finding,

        [Parameter(Mandatory = $true)]
        [string]$Reason
    )

    $reasons =
        Get-RequiredProperty `
            -Object $Finding `
            -Name "reasons" `
            -Context "finding"
    if ($reasons -isnot [array])
    {
        throw "finding reasons must be a JSON array"
    }
    foreach ($candidate in @($reasons))
    {
        if ($candidate -isnot [string])
        {
            throw "finding reasons must contain only strings"
        }
        if ([string]::Equals(
                $candidate,
                $Reason,
                [System.StringComparison]::OrdinalIgnoreCase))
        {
            return $true
        }
    }
    return $false
}

function Normalize-FixturePath
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $value =
        $Path.Trim().Trim('"').Replace("/", "\")
    foreach ($prefix in @(
            "\\?\",
            "\??\"))
    {
        if ($value.StartsWith(
                $prefix,
                [System.StringComparison]::OrdinalIgnoreCase))
        {
            $value =
                $value.Substring($prefix.Length)
            break
        }
    }
    if ($value -match '^[A-Za-z]:\\')
    {
        try
        {
            $value =
                [System.IO.Path]::GetFullPath($value)
        }
        catch
        {
            throw "invalid fixture path: $Path"
        }
    }
    return $value.TrimEnd("\").ToLowerInvariant()
}

function Test-PathEqual
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Left,

        [Parameter(Mandatory = $true)]
        [string]$Right
    )

    $leftPath =
        Normalize-FixturePath $Left
    $rightPath =
        Normalize-FixturePath $Right
    if ($leftPath -eq $rightPath)
    {
        return $true
    }

    $leftDriveQualified =
        $leftPath -match '^[a-z]:\\'
    $rightDriveQualified =
        $rightPath -match '^[a-z]:\\'
    $leftRootRelative =
        $leftPath.StartsWith("\") -and
        -not $leftPath.StartsWith("\\")
    $rightRootRelative =
        $rightPath.StartsWith("\") -and
        -not $rightPath.StartsWith("\\")

    if ($leftDriveQualified -and
        $rightRootRelative)
    {
        return $leftPath.Substring(2) -eq
            $rightPath
    }
    if ($rightDriveQualified -and
        $leftRootRelative)
    {
        return $leftPath -eq
            $rightPath.Substring(2)
    }
    return $false
}

function Assert-FindingIdentity
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$Finding,

        [Parameter(Mandatory = $true)]
        [string]$Risk,

        [Parameter(Mandatory = $true)]
        [string]$Confidence,

        [Parameter(Mandatory = $true)]
        [string]$Class,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    foreach ($expected in @(
            [pscustomobject]@{
                Name = "risk"
                Value = $Risk
            },
            [pscustomobject]@{
                Name = "confidence"
                Value = $Confidence
            },
            [pscustomobject]@{
                Name = "class"
                Value = $Class
            }))
    {
        $actual =
            Get-RequiredString `
                -Object $Finding `
                -Name $expected.Name `
                -Context $Context
        if (-not [string]::Equals(
                $actual,
                $expected.Value,
                [System.StringComparison]::OrdinalIgnoreCase))
        {
            throw "$Context $($expected.Name) mismatch: $actual"
        }
    }
}

if (-not (Test-Path -LiteralPath $HuntJson -PathType Leaf))
{
    throw "hunt JSON is missing: $HuntJson"
}

try
{
    $document =
        Get-Content -LiteralPath $HuntJson -Raw |
        ConvertFrom-Json
}
catch
{
    throw "hunt JSON is malformed: $($_.Exception.Message)"
}

$schema =
    Get-RequiredString `
        -Object $document `
        -Name "schema" `
        -Context "hunt"
if ($schema -ne "kn-live-dbg.hunt.v1")
{
    throw "hunt schema mismatch: $schema"
}
$mode =
    Get-RequiredString `
        -Object $document `
        -Name "mode" `
        -Context "hunt"
if (-not [string]::Equals(
        $mode,
        $RequireMode,
        [System.StringComparison]::OrdinalIgnoreCase))
{
    throw "hunt mode mismatch: expected=$RequireMode actual=$mode"
}

$summary =
    Get-RequiredProperty `
        -Object $document `
        -Name "summary" `
        -Context "hunt"
foreach ($coverageName in @(
        "qos_policy_coverage_incomplete",
        "bindflt_global_coverage_incomplete",
        "bindflt_process_correlation_coverage_incomplete"))
{
    if (Get-RequiredBoolean `
            -Object $summary `
            -Name $coverageName `
            -Context "summary")
    {
        throw "fixture coverage is incomplete: $coverageName"
    }
}
if (-not (Get-RequiredBoolean `
        -Object $summary `
        -Name "bindflt_silo_coverage_unsupported" `
        -Context "summary"))
{
    throw "Silo-Binding must remain explicitly unsupported"
}

$findingsProperty =
    Get-RequiredProperty `
        -Object $document `
        -Name "findings" `
        -Context "hunt"
if ($findingsProperty -isnot [array])
{
    throw "hunt findings must be a JSON array"
}
$findings =
    @($findingsProperty)
$findingCount =
    Get-RequiredCount `
        -Object $summary `
        -Name "findings" `
        -Context "summary"
if ($findingCount -ne [uint64]$findings.Count)
{
    throw "summary finding count does not match the raw finding array"
}
foreach ($risk in @(
        "high",
        "medium",
        "low",
        "info"))
{
    $actual =
        @(
            $findings |
                Where-Object {
                    $candidate =
                        Get-RequiredString `
                            -Object $_ `
                            -Name "risk" `
                            -Context "finding"
                    [string]::Equals(
                        $candidate,
                        $risk,
                        [System.StringComparison]::OrdinalIgnoreCase)
                }
        ).Count
    $expected =
        Get-RequiredCount `
            -Object $summary `
            -Name $risk `
            -Context "summary"
    if ([uint64]$actual -ne $expected)
    {
        throw "summary risk count mismatch: $risk"
    }
}

$warnings =
    Get-RequiredProperty `
        -Object $document `
        -Name "warnings" `
        -Context "hunt"
if ($warnings -isnot [array])
{
    throw "hunt warnings must be a JSON array"
}
foreach ($warning in @($warnings))
{
    if ($warning -isnot [string])
    {
        throw "hunt warnings must contain only strings"
    }
    if ($warning -match '(?i)\b(qos|bindflt|bind filter)\b')
    {
        throw "hunt contains a fixture-domain warning: $warning"
    }
}

$qosMatches =
    @(
        $findings |
            Where-Object {
                if (-not (Test-HasReason `
                        -Finding $_ `
                        -Reason "qos_security_product_throttle_policy"))
                {
                    return $false
                }
                $policy =
                    Get-EvidenceString `
                        -Finding $_ `
                        -Name "policy_name" `
                        -Context "QoS finding"
                return [string]::Equals(
                    $policy,
                    $PolicyName,
                    [System.StringComparison]::OrdinalIgnoreCase)
            }
    )
if ($qosMatches.Count -ne 1)
{
    throw "expected exactly one QoS fixture finding"
}
$qosFinding =
    $qosMatches[0]
Assert-FindingIdentity `
    -Finding $qosFinding `
    -Risk "high" `
    -Confidence "high" `
    -Class "network_policy_tampering" `
    -Context "QoS finding"
if (-not (Test-HasReason `
        -Finding $qosFinding `
        -Reason "security_tool_communication_throttling") -or
    -not (Test-HasReason `
        -Finding $qosFinding `
        -Reason "edrchoker_state"))
{
    throw "QoS fixture finding is missing required reason codes"
}
$qosPath =
    Get-EvidenceString `
        -Finding $qosFinding `
        -Name "app_path" `
        -Context "QoS finding"
if (-not (Test-PathEqual `
        $qosPath `
        $QosTargetPath))
{
    throw "QoS fixture target path mismatch"
}
if ((Get-EvidenceString `
        -Finding $qosFinding `
        -Name "throttle_rate_bytes_per_second" `
        -Context "QoS finding") -ne "8" -or
    (Get-EvidenceString `
        -Finding $qosFinding `
        -Name "throttle_rate_bits_per_second" `
        -Context "QoS finding") -ne "64" -or
    (Get-EvidenceString `
        -Finding $qosFinding `
        -Name "active_store" `
        -Context "QoS finding") -ne "true")
{
    throw "QoS fixture rate or ActiveStore evidence mismatch"
}

function Get-ExactGlobalMapping
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$VirtualPath,

        [Parameter(Mandatory = $true)]
        [string]$BackingPath,

        [Parameter(Mandatory = $true)]
        [string]$RequiredReason
    )

    return @(
        $findings |
            Where-Object {
                if (-not (Test-HasReason `
                        -Finding $_ `
                        -Reason "bindflt_active_global_mapping") -or
                    -not (Test-HasReason `
                        -Finding $_ `
                        -Reason $RequiredReason))
                {
                    return $false
                }
                $pidValue =
                    Get-RequiredCount `
                        -Object $_ `
                        -Name "pid" `
                        -Context "global bind finding"
                if ($pidValue -ne 0)
                {
                    return $false
                }
                $virtual =
                    Get-EvidenceString `
                        -Finding $_ `
                        -Name "resolved_virtual_root" `
                        -Context "global bind finding"
                $targets =
                    Get-EvidenceString `
                        -Finding $_ `
                        -Name "resolved_target_roots" `
                        -Context "global bind finding"
                $targetValues =
                    @(
                        $targets.Split(
                            @(";"),
                            [System.StringSplitOptions]::RemoveEmptyEntries)
                    )
                return (Test-PathEqual `
                            $virtual `
                            $VirtualPath) -and
                    $targetValues.Count -eq 1 -and
                    (Test-PathEqual `
                        $targetValues[0] `
                        $BackingPath)
            }
    )
}

$fileMapping =
    @(
        Get-ExactGlobalMapping `
            -VirtualPath $FileVirtualPath `
            -BackingPath $FileBackingPath `
            -RequiredReason "bind_link_security_artifact_path"
    )
if ($fileMapping.Count -ne 1)
{
    throw "expected exactly one file-binding fixture finding"
}
$processMapping =
    @(
        Get-ExactGlobalMapping `
            -VirtualPath $ProcessVirtualPath `
            -BackingPath $ProcessBackingPath `
            -RequiredReason "bind_link_security_product_path"
    )
if ($processMapping.Count -ne 1)
{
    throw "expected exactly one global Process-Binding mapping finding"
}
foreach ($mapping in @(
        $fileMapping[0],
        $processMapping[0]))
{
    Assert-FindingIdentity `
        -Finding $mapping `
        -Risk "high" `
        -Confidence "high" `
        -Class "filesystem_virtualization_tampering" `
        -Context "global bind finding"
    if ((Get-EvidenceString `
            -Finding $mapping `
            -Name "target_count" `
            -Context "global bind finding") -ne "1" -or
        (Get-EvidenceString `
            -Finding $mapping `
            -Name "global_mapping" `
            -Context "global bind finding") -ne "true" -or
        (Get-EvidenceString `
            -Finding $mapping `
            -Name "silo_mapping_coverage" `
            -Context "global bind finding") -ne "unsupported")
    {
        throw "global bind fixture raw evidence mismatch"
    }
}

$processBindingMatches =
    @(
        $findings |
            Where-Object {
                if (-not (Test-HasReason `
                        -Finding $_ `
                        -Reason "bind_link_process_binding_state") -or
                    -not (Test-HasReason `
                        -Finding $_ `
                        -Reason "bind_link_process_backing_correlation"))
                {
                    return $false
                }
                $pidValue =
                    Get-RequiredCount `
                        -Object $_ `
                        -Name "pid" `
                        -Context "Process-Binding finding"
                if ($pidValue -ne
                    [uint64]$ProcessId)
                {
                    return $false
                }
                $virtual =
                    Get-EvidenceString `
                        -Finding $_ `
                        -Name "resolved_virtual_root" `
                        -Context "Process-Binding finding"
                $target =
                    Get-EvidenceString `
                        -Finding $_ `
                        -Name "resolved_target_root" `
                        -Context "Process-Binding finding"
                return (Test-PathEqual `
                        $virtual `
                        $ProcessVirtualPath) -and
                    (Test-PathEqual `
                        $target `
                        $ProcessBackingPath)
            }
    )
if ($processBindingMatches.Count -ne 1)
{
    throw "expected exactly one correlated Process-Binding finding"
}
$processBinding =
    $processBindingMatches[0]
Assert-FindingIdentity `
    -Finding $processBinding `
    -Risk "high" `
    -Confidence "high" `
    -Class "filesystem_virtualization_tampering" `
    -Context "Process-Binding finding"
foreach ($pathName in @(
        "main_section_backing_path",
        "section_backing_path"))
{
    $backing =
        Get-EvidenceString `
            -Finding $processBinding `
            -Name $pathName `
            -Context "Process-Binding finding"
    if (-not (Test-PathEqual `
            $backing `
            $ProcessBackingPath))
    {
        throw "Process-Binding independent backing path mismatch: $pathName"
    }
}
foreach ($stateName in @(
        "main_section_backing_state",
        "section_backing_state"))
{
    if ((Get-EvidenceString `
            -Finding $processBinding `
            -Name $stateName `
            -Context "Process-Binding finding") -ne "resolved")
    {
        throw "Process-Binding backing state is not resolved: $stateName"
    }
}
if ((Get-EvidenceString `
        -Finding $processBinding `
        -Name "independent_backing_views_agree" `
        -Context "Process-Binding finding") -ne "true" -or
    (Get-EvidenceString `
        -Finding $processBinding `
        -Name "global_mapping" `
        -Context "Process-Binding finding") -ne "true" -or
    (Get-EvidenceString `
        -Finding $processBinding `
        -Name "silo_mapping_coverage" `
        -Context "Process-Binding finding") -ne "unsupported" -or
    [string]::IsNullOrWhiteSpace(
        (Get-EvidenceString `
            -Finding $processBinding `
            -Name "visible_source_views" `
            -Context "Process-Binding finding")))
{
    throw "Process-Binding correlation evidence is incomplete"
}

$minimums =
    [ordered]@{
        qos_policies = 1
        suspicious_qos_policies = 1
        bindflt_global_mappings = 2
        suspicious_bindflt_global_mappings = 2
        bindflt_process_bindings = 1
    }
foreach ($item in $minimums.GetEnumerator())
{
    $actual =
        Get-RequiredCount `
            -Object $summary `
            -Name $item.Key `
            -Context "summary"
    if ($actual -lt
        [uint64]$item.Value)
    {
        throw "summary counter is below the fixture minimum: $($item.Key)"
    }
}

Write-Host (
    "[qos-bind-e2e] passed policy={0} pid={1} file_virtual={2} process_virtual={3}" -f
        $PolicyName,
        $ProcessId,
        $FileVirtualPath,
        $ProcessVirtualPath)
