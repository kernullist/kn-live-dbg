[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BaselinePath,

    [Parameter(Mandatory = $true)]
    [string]$DetachedPath,

    [Parameter(Mandatory = $true)]
    [string]$ReattachedPath,

    [Parameter(Mandatory = $true)]
    [string]$PositiveDiffLogPath,

    [Parameter(Mandatory = $true)]
    [string]$RecoveryDiffLogPath,

    [Parameter(Mandatory = $true)]
    [string]$FilterName,

    [Parameter(Mandatory = $true)]
    [string]$InstanceName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Read-JsonDocument
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf))
    {
        throw "$Name artifact is missing: $Path"
    }

    $artifact =
        Get-Item -LiteralPath $Path -Force
    if ($artifact.Length -gt 268435456)
    {
        throw "$Name artifact exceeds the 256 MiB validation limit: $Path"
    }

    try
    {
        $json =
            [System.IO.File]::ReadAllText(
                $artifact.FullName)
        if ($PSVersionTable.PSVersion.Major -le 5)
        {
            # Windows PowerShell 5.1 ConvertFrom-Json uses a fixed legacy
            # parser limit and rejects valid full snapshots around 4 MiB.
            Add-Type -AssemblyName System.Web.Extensions
            $serializer =
                New-Object `
                    System.Web.Script.Serialization.JavaScriptSerializer
            $serializer.MaxJsonLength =
                [int]::MaxValue
            $serializer.RecursionLimit = 256
            return $serializer.DeserializeObject(
                $json)
        }
        return $json | ConvertFrom-Json
    }
    catch
    {
        throw "$Name artifact is not valid JSON: $Path"
    }
}

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

    if ($Object -is
        [System.Collections.IDictionary])
    {
        $dictionary =
            [System.Collections.IDictionary]$Object
        $hasProperty = $false
        foreach ($key in $dictionary.Keys)
        {
            if ([string]::Equals(
                    [string]$key,
                    $Name,
                    [System.StringComparison]::Ordinal))
            {
                $hasProperty = $true
                break
            }
        }
        if (-not $hasProperty)
        {
            throw "$Context is missing property '$Name'"
        }
        return $dictionary[$Name]
    }

    $property =
        $Object.PSObject.Properties[$Name]
    if ($null -eq $property)
    {
        throw "$Context is missing property '$Name'"
    }
    return $property.Value
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

    $value = Get-RequiredProperty `
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

    $value = Get-RequiredProperty `
        -Object $Object `
        -Name $Name `
        -Context $Context
    if ($value -isnot [bool])
    {
        throw "$Context property '$Name' must be a JSON boolean"
    }
    return [bool]$value
}

function Get-MetadataString
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$Document,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    $metadata = Get-RequiredProperty `
        -Object $Document `
        -Name "metadata" `
        -Context $Context
    return Get-RequiredString `
        -Object $metadata `
        -Name $Name `
        -Context "$Context metadata"
}

function Get-EvidenceString
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$Record,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Context,

        [switch]$AllowEmpty
    )

    $evidence = Get-RequiredProperty `
        -Object $Record `
        -Name "evidence" `
        -Context $Context
    return Get-RequiredString `
        -Object $evidence `
        -Name $Name `
        -Context "$Context evidence" `
        -AllowEmpty:$AllowEmpty
}

function Test-RecordTag
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$Record,

        [Parameter(Mandatory = $true)]
        [string]$Tag
    )

    $tags = Get-RequiredProperty `
        -Object $Record `
        -Name "tags" `
        -Context "snapshot record"
    foreach ($candidate in @($tags))
    {
        if ($candidate -isnot [string])
        {
            throw "snapshot record tags must contain strings"
        }
        if ([string]::Equals(
                [string]$candidate,
                $Tag,
                [System.StringComparison]::OrdinalIgnoreCase))
        {
            return $true
        }
    }
    return $false
}

function Test-TextEqual
{
    param(
        [AllowEmptyString()]
        [string]$Left,

        [AllowEmptyString()]
        [string]$Right
    )

    return [string]::Equals(
        $Left,
        $Right,
        [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-DomainRecords
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$Document,

        [Parameter(Mandatory = $true)]
        [string]$Domain
    )

    $records = Get-RequiredProperty `
        -Object $Document `
        -Name "records" `
        -Context "snapshot"
    return @(
        @($records) |
            Where-Object {
                $candidateDomain =
                    Get-RequiredString `
                        -Object $_ `
                        -Name "domain" `
                        -Context "snapshot record"
                Test-TextEqual $candidateDomain $Domain
            }
    )
}

function Convert-MetadataCount
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$Document,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    $text = Get-MetadataString `
        -Document $Document `
        -Name $Name `
        -Context $Context
    [uint64]$value = 0
    if (-not [uint64]::TryParse(
            $text,
            [System.Globalization.NumberStyles]::None,
            [System.Globalization.CultureInfo]::InvariantCulture,
            [ref]$value))
    {
        throw "$Context metadata '$Name' is not an unsigned decimal string"
    }
    return $value
}

function Assert-SnapshotContract
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$Document,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    $schema = Get-RequiredString `
        -Object $Document `
        -Name "schema" `
        -Context $Context
    if ($schema -ne "kn-live-dbg.snapshot.v1")
    {
        throw "$Context schema mismatch: $schema"
    }
    if (-not (Get-RequiredBoolean `
            -Object $Document `
            -Name "same_boot_only" `
            -Context $Context))
    {
        throw "$Context does not declare same-boot-only evidence"
    }

    foreach ($coverageName in @(
            "minifilter_attachments_coverage_complete",
            "callbacks_coverage_complete"))
    {
        if ((Get-MetadataString `
                -Document $Document `
                -Name $coverageName `
                -Context $Context) -ne "true")
        {
            throw "$Context coverage is incomplete: $coverageName"
        }
    }

    $records = @(
        Get-DomainRecords `
            -Document $Document `
            -Domain "minifilter-attachments"
    )
    $attachments = @(
        $records |
            Where-Object {
                Test-RecordTag $_ "minifilter-attachment"
            }
    )
    $volumes = @(
        $records |
            Where-Object {
                Test-RecordTag $_ "minifilter-volume"
            }
    )
    $detached = @(
        $attachments |
            Where-Object {
                (Get-EvidenceString `
                    -Record $_ `
                    -Name "detached_volume" `
                    -Context "$Context attachment") -eq "true"
            }
    )

    $expectedAttachmentCount =
        Convert-MetadataCount `
            -Document $Document `
            -Name "minifilter_attachment_record_count" `
            -Context $Context
    $expectedVolumeCount =
        Convert-MetadataCount `
            -Document $Document `
            -Name "minifilter_attachment_volume_count" `
            -Context $Context
    $expectedDetachedCount =
        Convert-MetadataCount `
            -Document $Document `
            -Name "minifilter_attachment_detached_count" `
            -Context $Context
    if ($expectedAttachmentCount -ne
            [uint64]$attachments.Count -or
        $expectedVolumeCount -ne
            [uint64]$volumes.Count -or
        $expectedDetachedCount -ne
            [uint64]$detached.Count)
    {
        throw "$Context minifilter metadata counters do not match raw records"
    }

    $identities = @(
        @($Document.records) |
            ForEach-Object {
                (Get-RequiredString `
                    -Object $_ `
                    -Name "domain" `
                    -Context "$Context record") +
                "`0" +
                (Get-RequiredString `
                    -Object $_ `
                    -Name "identity" `
                    -Context "$Context record")
            }
    )
    if (@(
            $identities |
                Group-Object |
                Where-Object Count -gt 1
        ).Count -ne 0)
    {
        throw "$Context contains duplicate record identities"
    }

    $warnings = Get-RequiredProperty `
        -Object $Document `
        -Name "domain_warnings" `
        -Context $Context
    $minifilterWarnings = $null
    $hasMinifilterWarnings = $false
    if ($warnings -is
        [System.Collections.IDictionary])
    {
        $warningDictionary =
            [System.Collections.IDictionary]$warnings
        foreach ($key in $warningDictionary.Keys)
        {
            if ([string]::Equals(
                    [string]$key,
                    "minifilter-attachments",
                    [System.StringComparison]::Ordinal))
            {
                $hasMinifilterWarnings =
                    $true
                break
            }
        }
        if ($hasMinifilterWarnings)
        {
            $minifilterWarnings =
                $warningDictionary[
                    "minifilter-attachments"]
        }
    }
    else
    {
        $warningProperty =
            $warnings.PSObject.Properties[
                "minifilter-attachments"]
        if ($null -ne $warningProperty)
        {
            $hasMinifilterWarnings = $true
            $minifilterWarnings =
                $warningProperty.Value
        }
    }
    if ($hasMinifilterWarnings -and
        @($minifilterWarnings).Count -ne 0)
    {
        throw "$Context contains minifilter attachment warnings"
    }
}

function Get-FixtureAttachments
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$Document,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedFilter,

        [string]$ExpectedInstance = "",

        [string]$ExpectedVolume = "",

        [switch]$RequireClean
    )

    return @(
        Get-DomainRecords `
            -Document $Document `
            -Domain "minifilter-attachments" |
            Where-Object {
                if (-not (Test-RecordTag $_ "minifilter-attachment"))
                {
                    return $false
                }
                $kind = Get-EvidenceString `
                    -Record $_ `
                    -Name "kind" `
                    -Context "fixture attachment"
                $filter = Get-EvidenceString `
                    -Record $_ `
                    -Name "filter_name" `
                    -Context "fixture attachment"
                $instance = Get-EvidenceString `
                    -Record $_ `
                    -Name "instance_name" `
                    -Context "fixture attachment" `
                    -AllowEmpty
                $volume = Get-EvidenceString `
                    -Record $_ `
                    -Name "volume_name" `
                    -Context "fixture attachment"
                $isMatch =
                    (Test-TextEqual $kind "minifilter") -and
                    (Test-TextEqual $filter $ExpectedFilter) -and
                    ([string]::IsNullOrEmpty($ExpectedInstance) -or
                     (Test-TextEqual $instance $ExpectedInstance)) -and
                    ([string]::IsNullOrEmpty($ExpectedVolume) -or
                     (Test-TextEqual $volume $ExpectedVolume))
                if ($isMatch -and $RequireClean)
                {
                    $isMatch =
                        (Get-EvidenceString `
                            -Record $_ `
                            -Name "detached_volume" `
                            -Context "fixture attachment") -eq "false"
                }
                return $isMatch
            }
    )
}

$baseline = Read-JsonDocument `
    -Path $BaselinePath `
    -Name "baseline"
$detached = Read-JsonDocument `
    -Path $DetachedPath `
    -Name "detached"
$reattached = Read-JsonDocument `
    -Path $ReattachedPath `
    -Name "reattached"

Assert-SnapshotContract `
    -Document $baseline `
    -Context "baseline"
Assert-SnapshotContract `
    -Document $detached `
    -Context "detached"
Assert-SnapshotContract `
    -Document $reattached `
    -Context "reattached"

$bootId = Get-RequiredString `
    -Object $baseline `
    -Name "boot_id" `
    -Context "baseline"
foreach ($item in @(
        [pscustomobject]@{
            Name = "detached"
            Document = $detached
        },
        [pscustomobject]@{
            Name = "reattached"
            Document = $reattached
        }))
{
    $candidateBootId = Get-RequiredString `
        -Object $item.Document `
        -Name "boot_id" `
        -Context $item.Name
    if ($candidateBootId -ne $bootId)
    {
        throw "snapshot boot IDs do not match"
    }
}

$baselineFixture = @(
    Get-FixtureAttachments `
        -Document $baseline `
        -ExpectedFilter $FilterName `
        -ExpectedInstance $InstanceName `
        -RequireClean
)
if ($baselineFixture.Count -ne 1)
{
    throw "baseline must contain exactly one clean fixture attachment"
}
$baselineIdentity = Get-RequiredString `
    -Object $baselineFixture[0] `
    -Name "identity" `
    -Context "baseline fixture attachment"
$volumeName = Get-EvidenceString `
    -Record $baselineFixture[0] `
    -Name "volume_name" `
    -Context "baseline fixture attachment"

$detachedFixture = @(
    Get-FixtureAttachments `
        -Document $detached `
        -ExpectedFilter $FilterName `
        -ExpectedVolume $volumeName
)
if ($detachedFixture.Count -ne 0)
{
    throw "detached snapshot still contains the fixture attachment"
}

$currentVolume = @(
    Get-DomainRecords `
        -Document $detached `
        -Domain "minifilter-attachments" |
        Where-Object {
            (Test-RecordTag $_ "minifilter-volume") -and
            (Test-TextEqual `
                (Get-EvidenceString `
                    -Record $_ `
                    -Name "volume_name" `
                    -Context "detached volume") `
                $volumeName)
        }
)
if ($currentVolume.Count -ne 1)
{
    throw "detached snapshot does not preserve the exact fixture volume"
}

$registeredCallbacks = @(
    Get-DomainRecords `
        -Document $detached `
        -Domain "callbacks" |
        Where-Object {
            (Test-TextEqual `
                (Get-EvidenceString `
                    -Record $_ `
                    -Name "kind" `
                    -Context "detached callback") `
                "minifilter") -and
            (Test-TextEqual `
                (Get-EvidenceString `
                    -Record $_ `
                    -Name "target" `
                    -Context "detached callback") `
                $FilterName)
        }
)
if ($registeredCallbacks.Count -lt 1)
{
    throw "detached snapshot does not preserve the registered fixture filter cross-view"
}

$reattachedFixture = @(
    Get-FixtureAttachments `
        -Document $reattached `
        -ExpectedFilter $FilterName `
        -ExpectedInstance $InstanceName `
        -ExpectedVolume $volumeName `
        -RequireClean
)
if ($reattachedFixture.Count -ne 1)
{
    throw "reattached snapshot must restore exactly one clean fixture attachment"
}

foreach ($log in @(
        [pscustomobject]@{
            Name = "positive diff"
            Path = $PositiveDiffLogPath
        },
        [pscustomobject]@{
            Name = "recovery diff"
            Path = $RecoveryDiffLogPath
        }))
{
    if (-not (Test-Path -LiteralPath $log.Path -PathType Leaf))
    {
        throw "$($log.Name) log is missing: $($log.Path)"
    }
}

$positiveLog =
    Get-Content -LiteralPath $PositiveDiffLogPath -Raw
if ($positiveLog -notmatch
        '(?m)^(?:knkd>\s*)?\[diff\].*\bsameBoot=yes\b' -or
    $positiveLog -notmatch
        '(?m)^(?:knkd>\s*)?\[diff\.minifilter-attachments\].*\bremoved=([1-9][0-9]*)\b.*\bmedium=([1-9][0-9]*)\b' -or
    $positiveLog -notmatch
        ('(?m)^\s+identity=' +
         [regex]::Escape($baselineIdentity) +
         '\s*$') -or
    $positiveLog -match
        'minifilter attachment removal comparison skipped')
{
    throw "positive diff log does not prove the fixture removal finding"
}

$recoveryLog =
    Get-Content -LiteralPath $RecoveryDiffLogPath -Raw
if ($recoveryLog -notmatch
        '(?m)^(?:knkd>\s*)?\[diff\].*\bsameBoot=yes\b' -or
    $recoveryLog -match
        ('(?m)^\s+identity=' +
         [regex]::Escape($baselineIdentity) +
         '\s*$') -or
    $recoveryLog -match
        '(?m)^(?:knkd>\s*)?\[diff\.minifilter-attachments\].*\bremoved=([1-9][0-9]*)\b' -or
    $recoveryLog -match
        'minifilter attachment removal comparison skipped')
{
    throw "recovery diff log contradicts clean semantic reattachment"
}

Write-Host (
    "[minifilter-detach-e2e] passed filter={0} instance={1} volume={2} identity={3}" -f
        $FilterName,
        $InstanceName,
        $volumeName,
        $baselineIdentity)
