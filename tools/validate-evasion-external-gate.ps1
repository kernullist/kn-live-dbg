[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ManifestPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

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

function Read-JsonDocument
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf))
    {
        throw "$Context is missing: $Path"
    }
    try
    {
        return Get-Content -LiteralPath $Path -Raw |
            ConvertFrom-Json
    }
    catch
    {
        throw "$Context is not valid JSON: $Path"
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
        [string]$Context
    )

    $value =
        Get-RequiredProperty `
            -Object $Object `
            -Name $Name `
            -Context $Context
    if ($value -isnot [string] -or
        [string]::IsNullOrWhiteSpace($value))
    {
        throw "$Context.$Name must be a non-empty JSON string"
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
        throw "$Context.$Name must be a JSON boolean"
    }
    return [bool]$value
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
    switch ([Type]::GetTypeCode(
            $Value.GetType()))
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

function Get-RequiredInteger
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
    if (-not (Test-JsonInteger -Value $value))
    {
        throw "$Context.$Name must be a JSON integer"
    }
    return [int64]$value
}

function Assert-StringEquals
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Actual,

        [Parameter(Mandatory = $true)]
        [string]$Expected,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    if (-not $Actual.Equals(
            $Expected,
            [StringComparison]::Ordinal))
    {
        throw (
            "$Context mismatch: expected='$Expected' actual='$Actual'")
    }
}

function Assert-ExactPath
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Actual,

        [Parameter(Mandatory = $true)]
        [string]$Expected,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    $actualPath =
        [IO.Path]::GetFullPath($Actual)
    $expectedPath =
        [IO.Path]::GetFullPath($Expected)
    if (-not $actualPath.Equals(
            $expectedPath,
            [StringComparison]::OrdinalIgnoreCase))
    {
        throw (
            "$Context must reference the exact gate artifact: " +
            "expected='$expectedPath' actual='$actualPath'")
    }
}

function Assert-FileExists
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf))
    {
        throw "$Context is missing: $Path"
    }
}

function Assert-PassedChildManifest
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$Document,

        [Parameter(Mandatory = $true)]
        [string]$Schema,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    Assert-StringEquals `
        -Actual (
            Get-RequiredString `
                -Object $Document `
                -Name "schema" `
                -Context $Context) `
        -Expected $Schema `
        -Context "$Context.schema"
    Assert-StringEquals `
        -Actual (
            Get-RequiredString `
                -Object $Document `
                -Name "status" `
                -Context $Context) `
        -Expected "passed" `
        -Context "$Context.status"
    Assert-StringEquals `
        -Actual (
            Get-RequiredString `
                -Object $Document `
                -Name "cleanup" `
                -Context $Context) `
        -Expected "passed" `
        -Context "$Context.cleanup"
}

$resolvedManifest =
    (Resolve-Path -LiteralPath $ManifestPath).Path
$gateRoot =
    Split-Path -Parent $resolvedManifest
$manifest =
    Read-JsonDocument `
        -Path $resolvedManifest `
        -Context "external gate manifest"

Assert-StringEquals `
    -Actual (
        Get-RequiredString `
            -Object $manifest `
            -Name "schema" `
            -Context "external gate manifest") `
    -Expected "kn-live-dbg.evasion-external-gate.v1" `
    -Context "external gate manifest.schema"
Assert-StringEquals `
    -Actual (
        Get-RequiredString `
            -Object $manifest `
            -Name "status" `
            -Context "external gate manifest") `
    -Expected "passed" `
    -Context "external gate manifest.status"
Assert-StringEquals `
    -Actual (
        Get-RequiredString `
            -Object $manifest `
            -Name "cleanup" `
            -Context "external gate manifest") `
    -Expected "passed" `
    -Context "external gate manifest.cleanup"
if (-not (Get-RequiredBoolean `
        -Object $manifest `
        -Name "elevated" `
        -Context "external gate manifest"))
{
    throw "external gate manifest.elevated must be true"
}
Assert-StringEquals `
    -Actual (
        Get-RequiredString `
            -Object $manifest `
            -Name "configuration" `
            -Context "external gate manifest") `
    -Expected "Release" `
    -Context "external gate manifest.configuration"
$gateVolume =
    Get-RequiredString `
        -Object $manifest `
        -Name "volume" `
        -Context "external gate manifest"
if (-not (Get-RequiredBoolean `
        -Object $manifest `
        -Name "threat_intel_required" `
        -Context "external gate manifest"))
{
    throw (
        "external gate manifest.threat_intel_required must be true")
}
if (-not (Get-RequiredBoolean `
        -Object $manifest `
        -Name "silo_binding_coverage_unsupported" `
        -Context "external gate manifest"))
{
    throw (
        "external gate must preserve unsupported Silo-Binding coverage")
}
$cleanRunCount =
    Get-RequiredInteger `
        -Object $manifest `
        -Name "clean_run_count" `
        -Context "external gate manifest"
if ($cleanRunCount -lt 3 -or
    $cleanRunCount -gt 10)
{
    throw (
        "external gate clean_run_count must be between 3 and 10")
}

$artifacts =
    Get-RequiredProperty `
        -Object $manifest `
        -Name "artifacts" `
        -Context "external gate manifest"
$hashes =
    Get-RequiredProperty `
        -Object $manifest `
        -Name "artifact_sha256" `
        -Context "external gate manifest"
$artifactDefinitions = @(
    [pscustomobject]@{
        Name = "qos_bind_manifest"
        Relative = "qos-bind\manifest.json"
    },
    [pscustomobject]@{
        Name = "cloudfiles_in_sync_manifest"
        Relative =
            "cloudfiles-in-sync\cloudfiles-fixture-manifest.json"
    },
    [pscustomobject]@{
        Name = "cloudfiles_modified_manifest"
        Relative =
            "cloudfiles-modified\cloudfiles-fixture-manifest.json"
    },
    [pscustomobject]@{
        Name = "minifilter_manifest"
        Relative = "minifilter\manifest.json"
    },
    [pscustomobject]@{
        Name = "clean_host_analysis"
        Relative = "clean-host\analysis.json"
    }
)
$artifactPaths = @{}
foreach ($definition in $artifactDefinitions)
{
    $actualPath =
        Get-RequiredString `
            -Object $artifacts `
            -Name $definition.Name `
            -Context "external gate manifest.artifacts"
    $expectedPath =
        Join-Path $gateRoot $definition.Relative
    Assert-ExactPath `
        -Actual $actualPath `
        -Expected $expectedPath `
        -Context (
            "external gate manifest.artifacts." +
            $definition.Name)
    Assert-FileExists `
        -Path $actualPath `
        -Context (
            "external gate artifact " +
            $definition.Name)
    $expectedHash =
        Get-RequiredString `
            -Object $hashes `
            -Name $definition.Name `
            -Context "external gate manifest.artifact_sha256"
    if ($expectedHash -notmatch '^[0-9A-Fa-f]{64}$')
    {
        throw (
            "external gate artifact hash has invalid format: " +
            $definition.Name)
    }
    $actualHash =
        Get-FileSha256 `
            -Path $actualPath
    if (-not $actualHash.Equals(
            $expectedHash,
            [StringComparison]::OrdinalIgnoreCase))
    {
        throw (
            "external gate artifact hash mismatch: " +
            $definition.Name)
    }
    $artifactPaths[$definition.Name] =
        [IO.Path]::GetFullPath($actualPath)
}

$qos =
    Read-JsonDocument `
        -Path $artifactPaths.qos_bind_manifest `
        -Context "QoS/Bind manifest"
Assert-PassedChildManifest `
    -Document $qos `
    -Schema "kn-live-dbg.qos-bind-e2e.v1" `
    -Context "QoS/Bind manifest"
$qosHunt =
    Get-RequiredString `
        -Object $qos `
        -Name "hunt_json" `
        -Context "QoS/Bind manifest"
$qosValidatorLog =
    Get-RequiredString `
        -Object $qos `
        -Name "validator_log" `
        -Context "QoS/Bind manifest"
Assert-ExactPath `
    -Actual $qosHunt `
    -Expected (
        Join-Path $gateRoot (
            "qos-bind\hunt\hunt-clean-default-01.json")) `
    -Context "QoS/Bind manifest.hunt_json"
Assert-ExactPath `
    -Actual $qosValidatorLog `
    -Expected (
        Join-Path $gateRoot (
            "qos-bind\validator.log")) `
    -Context "QoS/Bind manifest.validator_log"
Assert-FileExists `
    -Path $qosHunt `
    -Context "QoS/Bind hunt JSON"
Assert-FileExists `
    -Path $qosValidatorLog `
    -Context "QoS/Bind validator log"
if ((Get-RequiredInteger `
        -Object $qos `
        -Name "process_id" `
        -Context "QoS/Bind manifest") -le 0)
{
    throw "QoS/Bind manifest.process_id must be positive"
}
$qosPolicyName =
    Get-RequiredString `
        -Object $qos `
        -Name "policy_name" `
        -Context "QoS/Bind manifest"
if ($qosPolicyName -notmatch
        '^KnLiveDbg-Qos-Fixture-[0-9a-f]{32}$')
{
    throw (
        "QoS/Bind manifest.policy_name is outside the fixture namespace")
}
Assert-StringEquals `
    -Actual (
        Get-RequiredString `
            -Object $qos `
            -Name "qos_target" `
            -Context "QoS/Bind manifest") `
    -Expected (
        Get-RequiredString `
            -Object $qos `
            -Name "process_virtual" `
            -Context "QoS/Bind manifest") `
    -Context "QoS/Bind policy/process target"

foreach ($cloudDefinition in @(
        [pscustomobject]@{
            Key = "cloudfiles_in_sync_manifest"
            Directory = "cloudfiles-in-sync"
            Scenario = "InSyncNegative"
        },
        [pscustomobject]@{
            Key = "cloudfiles_modified_manifest"
            Directory = "cloudfiles-modified"
            Scenario = "ModifiedPositive"
        }))
{
    $cloud =
        Read-JsonDocument `
            -Path $artifactPaths[$cloudDefinition.Key] `
            -Context (
                "CloudFiles " +
                $cloudDefinition.Scenario +
                " manifest")
    $cloudContext =
        "CloudFiles " +
        $cloudDefinition.Scenario +
        " manifest"
    Assert-PassedChildManifest `
        -Document $cloud `
        -Schema "kn-live-dbg.cloudfiles-fixture-e2e.v1" `
        -Context $cloudContext
    Assert-StringEquals `
        -Actual (
            Get-RequiredString `
                -Object $cloud `
                -Name "scenario" `
                -Context $cloudContext) `
        -Expected $cloudDefinition.Scenario `
        -Context "$cloudContext.scenario"
    Assert-StringEquals `
        -Actual (
            Get-RequiredString `
                -Object $cloud `
                -Name "hunt_mode" `
                -Context $cloudContext) `
        -Expected "Deep" `
        -Context "$cloudContext.hunt_mode"
    if ((Get-RequiredInteger `
            -Object $cloud `
            -Name "process_id" `
            -Context $cloudContext) -le 0)
    {
        throw "$cloudContext.process_id must be positive"
    }
    $cloudImage =
        Get-RequiredString `
            -Object $cloud `
            -Name "image_path" `
            -Context $cloudContext
    if (-not [IO.Path]::GetFileName(
            $cloudImage).Equals(
                "CloudFilesFixture.exe",
                [StringComparison]::OrdinalIgnoreCase))
    {
        throw (
            "$cloudContext.image_path has an unexpected leaf")
    }
    $cloudHunt =
        Get-RequiredString `
            -Object $cloud `
            -Name "hunt_json" `
            -Context $cloudContext
    Assert-ExactPath `
        -Actual $cloudHunt `
        -Expected (
            Join-Path $gateRoot (
                $cloudDefinition.Directory +
                "\hunt-clean-deep-01.json")) `
        -Context "$cloudContext.hunt_json"
    Assert-FileExists `
        -Path $cloudHunt `
        -Context "$cloudContext hunt JSON"
}

$minifilter =
    Read-JsonDocument `
        -Path $artifactPaths.minifilter_manifest `
        -Context "minifilter manifest"
Assert-PassedChildManifest `
    -Document $minifilter `
    -Schema "kn-live-dbg.minifilter-detach-e2e.v1" `
    -Context "minifilter manifest"
Assert-StringEquals `
    -Actual (
        Get-RequiredString `
            -Object $minifilter `
            -Name "filter" `
            -Context "minifilter manifest") `
    -Expected "KnLiveDbgMiniFilterFixture" `
    -Context "minifilter manifest.filter"
Assert-StringEquals `
    -Actual (
        Get-RequiredString `
            -Object $minifilter `
            -Name "instance" `
            -Context "minifilter manifest") `
    -Expected "KnLiveDbgMiniFilterFixture.Instance" `
    -Context "minifilter manifest.instance"
Assert-StringEquals `
    -Actual (
        Get-RequiredString `
            -Object $minifilter `
            -Name "volume" `
            -Context "minifilter manifest") `
    -Expected $gateVolume `
    -Context "minifilter manifest.volume"
foreach ($minifilterArtifact in @(
        [pscustomobject]@{
            Name = "attached_snapshot"
            Relative = "minifilter\attached.json"
        },
        [pscustomobject]@{
            Name = "detached_snapshot"
            Relative = "minifilter\detached.json"
        },
        [pscustomobject]@{
            Name = "reattached_snapshot"
            Relative = "minifilter\reattached.json"
        },
        [pscustomobject]@{
            Name = "positive_diff_log"
            Relative = "minifilter\positive-diff.stdout.log"
        },
        [pscustomobject]@{
            Name = "recovery_diff_log"
            Relative = "minifilter\recovery-diff.stdout.log"
        },
        [pscustomobject]@{
            Name = "validator_log"
            Relative = "minifilter\validator.log"
        }))
{
    $artifactPath =
        Get-RequiredString `
            -Object $minifilter `
            -Name $minifilterArtifact.Name `
            -Context "minifilter manifest"
    Assert-ExactPath `
        -Actual $artifactPath `
        -Expected (
            Join-Path $gateRoot (
                $minifilterArtifact.Relative)) `
        -Context (
            "minifilter manifest." +
            $minifilterArtifact.Name)
    Assert-FileExists `
        -Path $artifactPath `
        -Context (
            "minifilter artifact " +
            $minifilterArtifact.Name)
}

$cleanStatusPath =
    Join-Path $gateRoot (
        "clean-host\status.txt")
Assert-FileExists `
    -Path $cleanStatusPath `
    -Context "clean-host status"
$cleanStatus =
    Get-Content -LiteralPath $cleanStatusPath -Raw
foreach ($requiredLine in @(
        "status=success",
        "runs=$cleanRunCount",
        "mode=Deep",
        "threat_intel=True"))
{
    if ($cleanStatus -notmatch (
            "(?m)^" +
            [regex]::Escape($requiredLine) +
            "\s*$"))
    {
        throw (
            "clean-host status is missing '$requiredLine'")
    }
}
for ($run = 1; $run -le $cleanRunCount; ++$run)
{
    $huntPath =
        Join-Path $gateRoot (
            "clean-host\hunt-clean-deep-{0:D2}.json" -f
                $run)
    Assert-FileExists `
        -Path $huntPath `
        -Context (
            "clean-host run $run JSON")
}

$analysis =
    Read-JsonDocument `
        -Path $artifactPaths.clean_host_analysis `
        -Context "clean-host analysis"
Assert-StringEquals `
    -Actual (
        Get-RequiredString `
            -Object $analysis `
            -Name "schema" `
            -Context "clean-host analysis") `
    -Expected "kn-live-dbg.hunt-clean-analysis.v1" `
    -Context "clean-host analysis.schema"
$summary =
    Get-RequiredProperty `
        -Object $analysis `
        -Name "summary" `
        -Context "clean-host analysis"
foreach ($countContract in @(
        [pscustomobject]@{
            Name = "run_count"
            Expected = $cleanRunCount
        },
        [pscustomobject]@{
            Name = "complete_runs"
            Expected = $cleanRunCount
        },
        [pscustomobject]@{
            Name = "total_findings"
            Expected = 0
        },
        [pscustomobject]@{
            Name = "unique_fingerprints"
            Expected = 0
        },
        [pscustomobject]@{
            Name = "deterministic_fingerprints"
            Expected = 0
        },
        [pscustomobject]@{
            Name = "intermittent_fingerprints"
            Expected = 0
        }))
{
    $actual =
        Get-RequiredInteger `
            -Object $summary `
            -Name $countContract.Name `
            -Context "clean-host analysis.summary"
    if ($actual -ne $countContract.Expected)
    {
        throw (
            "clean-host analysis.summary.{0} mismatch: " +
            "expected={1} actual={2}" -f
                $countContract.Name,
                $countContract.Expected,
                $actual)
    }
}
if (-not (Get-RequiredBoolean `
        -Object $summary `
        -Name "all_clean_complete" `
        -Context "clean-host analysis.summary"))
{
    throw (
        "clean-host analysis.summary.all_clean_complete must be true")
}

$runs =
    Get-RequiredProperty `
        -Object $analysis `
        -Name "runs" `
        -Context "clean-host analysis"
$findingGroups =
    Get-RequiredProperty `
        -Object $analysis `
        -Name "finding_groups" `
        -Context "clean-host analysis"
if ($runs -isnot [Array] -or
    @($runs).Count -ne $cleanRunCount)
{
    throw (
        "clean-host analysis.runs must be a JSON array with " +
        "$cleanRunCount entries")
}
if ($findingGroups -isnot [Array] -or
    @($findingGroups).Count -ne 0)
{
    throw (
        "clean-host analysis.finding_groups must be an empty JSON array")
}

Write-Host (
    "evasion external gate validation passed")
Write-Host (
    "  manifest=$resolvedManifest")
Write-Host (
    "  clean_runs=$cleanRunCount findings=0 complete=true")
Write-Host (
    "  silo_binding_coverage_unsupported=true")
