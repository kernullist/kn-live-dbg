[CmdletBinding()]
param(
    [string]$Root = "",

    [string]$LedgerPath = "",

    [string]$AsOfDate = "",

    [string]$ReportPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($Root))
{
    $Root =
        Split-Path -Parent $PSScriptRoot
}

$rootPath =
    (Resolve-Path -LiteralPath $Root).Path
if ([string]::IsNullOrWhiteSpace(
        $LedgerPath))
{
    $LedgerPath =
        Join-Path $rootPath (
            "research\evasion-research-ledger.json")
}

function Get-FullPath
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return [IO.Path]::GetFullPath($Path)
}

function Assert-UnderPath
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Parent,

        [Parameter(Mandatory = $true)]
        [string]$Child,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    $firstColon =
        $Child.IndexOf([char]":")
    $lastColon =
        $Child.LastIndexOf([char]":")
    if ($Child.Contains([char]0) -or
        ($firstColon -ge 0 -and
            ($firstColon -ne 1 -or
                $lastColon -ne $firstColon -or
                -not [char]::IsLetter($Child[0]))))
    {
        throw "$Context must not use NUL or an alternate data stream"
    }

    $parentPath =
        (Get-FullPath -Path $Parent).
            TrimEnd(
                [IO.Path]::DirectorySeparatorChar,
                [IO.Path]::AltDirectorySeparatorChar)
    $childPath =
        Get-FullPath -Path $Child
    $prefix =
        $parentPath +
        [IO.Path]::DirectorySeparatorChar
    if (-not $childPath.StartsWith(
            $prefix,
            [StringComparison]::OrdinalIgnoreCase))
    {
        throw "$Context escapes its required parent: $childPath"
    }

    return $childPath
}

function Get-SafeRepositoryRelativePath
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or
        $Path.Contains([char]0) -or
        [IO.Path]::IsPathRooted($Path))
    {
        throw "$Context must be a safe repository-relative path"
    }

    $normalized =
        $Path.Replace(
            "/",
            [IO.Path]::DirectorySeparatorChar)
    $segments =
        @($normalized.Split(
            [char[]]@(
                [IO.Path]::DirectorySeparatorChar),
            [StringSplitOptions]::None))
    if ($segments.Count -eq 0)
    {
        throw "$Context must be a safe repository-relative path"
    }

    foreach ($segment in $segments)
    {
        if ([string]::IsNullOrWhiteSpace($segment) -or
            $segment -eq "." -or
            $segment -eq ".." -or
            $segment -ne $segment.Trim() -or
            $segment.EndsWith(
                ".",
                [StringComparison]::Ordinal) -or
            $segment -match
                '[<>:"/\\|?*\x00-\x1F]')
        {
            throw "$Context must be a safe repository-relative path"
        }

        $deviceBase =
            $segment.Split([char]".")[0]
        if ($deviceBase -match
            '^(?i:CON|PRN|AUX|NUL|CLOCK\$|CONIN\$|CONOUT\$|COM(?:[1-9]|\u00B9|\u00B2|\u00B3)|LPT(?:[1-9]|\u00B9|\u00B2|\u00B3))$')
        {
            throw "$Context uses a reserved Windows device name"
        }
    }

    return $normalized
}

function Assert-NoReparsePointPath
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root,

        [Parameter(Mandatory = $true)]
        [string]$RelativePath,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    $current =
        Get-FullPath -Path $Root
    $segments =
        @($RelativePath.Split(
            [char[]]@(
                [IO.Path]::DirectorySeparatorChar),
            [StringSplitOptions]::None))
    foreach ($segment in $segments)
    {
        $current =
            Join-Path $current $segment
        if (-not (Test-Path -LiteralPath $current))
        {
            return
        }

        $item =
            Get-Item `
                -LiteralPath $current `
                -Force
        if (($item.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0)
        {
            throw "$Context traverses a reparse point: $current"
        }
    }
}

function Read-Utf8FileSnapshot
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    $stream =
        [IO.File]::Open(
            $Path,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read)
    try
    {
        if ($stream.Length -le 0 -or
            $stream.Length -gt (4 * 1024 * 1024))
        {
            throw "$Context size is outside the accepted range"
        }

        $bytes =
            [byte[]]::new(
                [int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length)
        {
            $read =
                $stream.Read(
                    $bytes,
                    $offset,
                    $bytes.Length - $offset)
            if ($read -le 0)
            {
                throw "$Context could not be read completely"
            }
            $offset += $read
        }
    }
    finally
    {
        $stream.Dispose()
    }

    try
    {
        $encoding =
            [Text.UTF8Encoding]::new(
                $false,
                $true)
        $text =
            $encoding.GetString($bytes)
    }
    catch
    {
        throw "$Context must use valid UTF-8"
    }
    if ($text.Length -ne 0 -and
        $text[0] -eq [char]0xFEFF)
    {
        $text =
            $text.Substring(1)
    }

    $sha256 =
        [Security.Cryptography.SHA256]::Create()
    try
    {
        $hashBytes =
            $sha256.ComputeHash($bytes)
    }
    finally
    {
        $sha256.Dispose()
    }
    $hash =
        ([BitConverter]::ToString(
            $hashBytes)).Replace("-", "")

    return [pscustomobject]@{
        Text = $text
        Sha256 = $hash
    }
}

function Assert-JsonObject
{
    param(
        [AllowNull()]
        [object]$Value,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    if ($null -eq $Value -or
        $Value -isnot [pscustomobject])
    {
        throw "$Context must be a JSON object"
    }
}

function Assert-ObjectProperties
{
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Value,

        [Parameter(Mandatory = $true)]
        [string[]]$Required,

        [Parameter(Mandatory = $true)]
        [string[]]$Allowed,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    $names =
        @($Value.PSObject.Properties.Name)
    foreach ($name in $Required)
    {
        if ($name -notin $names)
        {
            throw "$Context is missing required property '$name'"
        }
    }
    foreach ($name in $names)
    {
        if ($name -notin $Allowed)
        {
            throw "$Context contains unsupported property '$name'"
        }
    }
}

function Get-RequiredString
{
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Container,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Context,

        [switch]$AllowEmpty
    )

    $property =
        $Container.PSObject.Properties[$Name]
    if ($null -eq $property -or
        $property.Value -isnot [string])
    {
        throw "$Context.$Name must be a JSON string"
    }
    $value =
        [string]$property.Value
    if (-not $AllowEmpty -and
        [string]::IsNullOrWhiteSpace($value))
    {
        throw "$Context.$Name must not be empty"
    }

    return $value
}

function Get-RequiredBoolean
{
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Container,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    $property =
        $Container.PSObject.Properties[$Name]
    if ($null -eq $property -or
        $property.Value -isnot [bool])
    {
        throw "$Context.$Name must be a JSON boolean"
    }

    return [bool]$property.Value
}

function Get-RequiredInteger
{
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Container,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Context,

        [int64]$Minimum =
            [int64]::MinValue,

        [int64]$Maximum =
            [int64]::MaxValue
    )

    $property =
        $Container.PSObject.Properties[$Name]
    if ($null -eq $property -or
        $property.Value -is [bool] -or
        ($property.Value -isnot [byte] -and
         $property.Value -isnot [int16] -and
         $property.Value -isnot [int32] -and
         $property.Value -isnot [int64] -and
         $property.Value -isnot [uint16] -and
         $property.Value -isnot [uint32]))
    {
        throw "$Context.$Name must be a JSON integer"
    }
    $value =
        [int64]$property.Value
    if ($value -lt $Minimum -or
        $value -gt $Maximum)
    {
        throw (
            "$Context.$Name=$value is outside " +
            "[$Minimum,$Maximum]")
    }

    return $value
}

function Get-RequiredArray
{
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Container,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    $property =
        $Container.PSObject.Properties[$Name]
    if ($null -eq $property -or
        $property.Value -isnot [Array])
    {
        throw "$Context.$Name must be a JSON array"
    }

    return ,@($property.Value)
}

function Convert-RequiredIsoDate
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    $parsed =
        [DateTime]::MinValue
    if (-not [DateTime]::TryParseExact(
            $Value,
            "yyyy-MM-dd",
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::None,
            [ref]$parsed))
    {
        throw "$Context must use exact yyyy-MM-dd format"
    }

    return $parsed.Date
}

function Get-RequiredDate
{
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Container,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    $text =
        Get-RequiredString `
            -Container $Container `
            -Name $Name `
            -Context $Context
    return Convert-RequiredIsoDate `
        -Value $text `
        -Context "$Context.$Name"
}

function Get-NullableDate
{
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Container,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    $property =
        $Container.PSObject.Properties[$Name]
    if ($null -eq $property)
    {
        throw "$Context is missing required property '$Name'"
    }
    if ($null -eq $property.Value)
    {
        return $null
    }
    if ($property.Value -isnot [string])
    {
        throw "$Context.$Name must be a date string or null"
    }
    return Convert-RequiredIsoDate `
        -Value ([string]$property.Value) `
        -Context "$Context.$Name"
}

function Assert-Identifier
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    if ($Value -notmatch
        '^[a-z0-9]+(?:-[a-z0-9]+)*$')
    {
        throw "$Context has invalid identifier '$Value'"
    }
}

function Assert-HttpsUrl
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    $uri = $null
    if (-not [Uri]::TryCreate(
            $Value,
            [UriKind]::Absolute,
            [ref]$uri) -or
        $null -eq $uri -or
        $uri.Scheme -ne "https" -or
        [string]::IsNullOrWhiteSpace(
            $uri.DnsSafeHost) -or
        -not [string]::IsNullOrEmpty(
            $uri.UserInfo))
    {
        throw "$Context must be an absolute HTTPS URL without user info"
    }
}

function Assert-StringArray
{
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Values,

        [Parameter(Mandatory = $true)]
        [string]$Context,

        [switch]$AllowEmpty
    )

    if (-not $AllowEmpty -and
        $Values.Count -eq 0)
    {
        throw "$Context must contain at least one item"
    }

    $seen =
        [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase)
    foreach ($value in $Values)
    {
        if ($value -isnot [string] -or
            [string]::IsNullOrWhiteSpace(
                [string]$value))
        {
            throw "$Context must contain only non-empty strings"
        }
        if (-not $seen.Add([string]$value))
        {
            throw "$Context contains duplicate '$value'"
        }
    }
}

function Assert-AnchorArray
{
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Anchors,

        [Parameter(Mandatory = $true)]
        [string]$Context,

        [Parameter(Mandatory = $true)]
        [string]$RepositoryRoot,

        [Parameter(Mandatory = $true)]
        [Collections.Generic.Dictionary[string,string]]$FileCache,

        [switch]$RequireNonEmpty
    )

    if ($RequireNonEmpty -and
        $Anchors.Count -eq 0)
    {
        throw "$Context must contain at least one anchor"
    }

    $seen =
        [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::Ordinal)
    for ($index = 0;
         $index -lt $Anchors.Count;
         ++$index)
    {
        $anchor =
            $Anchors[$index]
        $anchorContext =
            "$Context[$index]"
        Assert-JsonObject `
            -Value $anchor `
            -Context $anchorContext
        Assert-ObjectProperties `
            -Value $anchor `
            -Required @("path", "contains") `
            -Allowed @("path", "contains") `
            -Context $anchorContext
        $relativePath =
            Get-RequiredString `
                -Container $anchor `
                -Name "path" `
                -Context $anchorContext
        $needle =
            Get-RequiredString `
                -Container $anchor `
                -Name "contains" `
                -Context $anchorContext
        $relativePath =
            Get-SafeRepositoryRelativePath `
                -Path $relativePath `
                -Context "$anchorContext.path"
        if ($needle.Contains(
                [char]0) -or
            $needle.Contains("`r") -or
            $needle.Contains("`n"))
        {
            throw "$anchorContext.contains must be one non-NUL line"
        }

        $candidate =
            Join-Path $RepositoryRoot (
                $relativePath.Replace(
                    "/",
                    [IO.Path]::DirectorySeparatorChar))
        $resolved =
            Assert-UnderPath `
                -Parent $RepositoryRoot `
                -Child $candidate `
                -Context "$anchorContext.path"
        Assert-NoReparsePointPath `
            -Root $RepositoryRoot `
            -RelativePath $relativePath `
            -Context "$anchorContext.path"
        if (-not (Test-Path `
                -LiteralPath $resolved `
                -PathType Leaf))
        {
            throw "$anchorContext.path does not exist: $relativePath"
        }

        $key =
            $relativePath + [char]0 + $needle
        if (-not $seen.Add($key))
        {
            throw "$Context contains a duplicate anchor for '$relativePath'"
        }

        $text = ""
        if (-not $FileCache.TryGetValue(
                $resolved,
                [ref]$text))
        {
            $text =
                Get-Content `
                    -LiteralPath $resolved `
                    -Raw
            $FileCache[$resolved] =
                $text
        }
        if ($text.IndexOf(
                $needle,
                [StringComparison]::Ordinal) -lt 0)
        {
            throw (
                "$anchorContext literal was not found in " +
                "'$relativePath': $needle")
        }
    }
}

function Assert-ValidationCommands
{
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Commands,

        [Parameter(Mandatory = $true)]
        [string]$Context,

        [switch]$RequireNonEmpty
    )

    Assert-StringArray `
        -Values $Commands `
        -Context $Context `
        -AllowEmpty:(-not $RequireNonEmpty)
    foreach ($command in $Commands)
    {
        $text =
            [string]$command
        if ($text.Length -gt 512 -or
            $text -match '[\r\n;&|`]' -or
            -not $text.StartsWith(
                ".\",
                [StringComparison]::Ordinal))
        {
            throw "$Context contains an unsafe validation command: $text"
        }
    }
}

$ledgerFullPath =
    Assert-UnderPath `
        -Parent $rootPath `
        -Child $LedgerPath `
        -Context "ledger path"
$rootPrefix =
    $rootPath.TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar) +
    [IO.Path]::DirectorySeparatorChar
$ledgerRelativePath =
    $ledgerFullPath.Substring(
        $rootPrefix.Length)
$ledgerRelativePath =
    Get-SafeRepositoryRelativePath `
        -Path $ledgerRelativePath `
        -Context "ledger path"
Assert-NoReparsePointPath `
    -Root $rootPath `
    -RelativePath $ledgerRelativePath `
    -Context "ledger path"
if (-not (Test-Path `
        -LiteralPath $ledgerFullPath `
        -PathType Leaf))
{
    throw "research ledger was not found: $ledgerFullPath"
}

if ([string]::IsNullOrWhiteSpace(
        $AsOfDate))
{
    $AsOfDate =
        (Get-Date).ToString("yyyy-MM-dd")
}
$asOf =
    Convert-RequiredIsoDate `
        -Value $AsOfDate `
        -Context "AsOfDate"

$ledgerSnapshot =
    Read-Utf8FileSnapshot `
        -Path $ledgerFullPath `
        -Context "research ledger"
try
{
    $document =
        $ledgerSnapshot.Text |
        ConvertFrom-Json
}
catch
{
    throw (
        "research ledger is not valid JSON: " +
        $_.Exception.Message)
}

Assert-JsonObject `
    -Value $document `
    -Context "ledger"
Assert-ObjectProperties `
    -Value $document `
    -Required @(
        "schema",
        "title",
        "reviewed_through",
        "scope",
        "refresh_policy",
        "sources",
        "techniques",
        "completion_gate") `
    -Allowed @(
        "schema",
        "title",
        "reviewed_through",
        "scope",
        "refresh_policy",
        "sources",
        "techniques",
        "completion_gate") `
    -Context "ledger"

$schema =
    Get-RequiredString `
        -Container $document `
        -Name "schema" `
        -Context "ledger"
if ($schema -ne
    "kn-live-dbg.evasion-research-ledger.v1")
{
    throw "unsupported research ledger schema '$schema'"
}
[void](Get-RequiredString `
    -Container $document `
    -Name "title" `
    -Context "ledger")
$reviewedThrough =
    Get-RequiredDate `
        -Container $document `
        -Name "reviewed_through" `
        -Context "ledger"
if ($reviewedThrough -gt $asOf)
{
    throw (
        "ledger.reviewed_through is in the future " +
        "relative to AsOfDate")
}

$scope =
    $document.scope
Assert-JsonObject `
    -Value $scope `
    -Context "ledger.scope"
Assert-ObjectProperties `
    -Value $scope `
    -Required @(
        "platform",
        "start_date",
        "interpretation",
        "exclusions") `
    -Allowed @(
        "platform",
        "start_date",
        "interpretation",
        "exclusions") `
    -Context "ledger.scope"
[void](Get-RequiredString `
    -Container $scope `
    -Name "platform" `
    -Context "ledger.scope")
$scopeStart =
    Get-RequiredDate `
        -Container $scope `
        -Name "start_date" `
        -Context "ledger.scope"
if ($scopeStart -gt $reviewedThrough)
{
    throw "ledger.scope.start_date is after reviewed_through"
}
[void](Get-RequiredString `
    -Container $scope `
    -Name "interpretation" `
    -Context "ledger.scope")
$scopeExclusions =
    Get-RequiredArray `
        -Container $scope `
        -Name "exclusions" `
        -Context "ledger.scope"
Assert-StringArray `
    -Values $scopeExclusions `
    -Context "ledger.scope.exclusions"

$refresh =
    $document.refresh_policy
Assert-JsonObject `
    -Value $refresh `
    -Context "ledger.refresh_policy"
Assert-ObjectProperties `
    -Value $refresh `
    -Required @(
        "max_review_age_days",
        "max_source_verification_age_days",
        "minimum_source_types",
        "discovery_endpoints") `
    -Allowed @(
        "max_review_age_days",
        "max_source_verification_age_days",
        "minimum_source_types",
        "discovery_endpoints") `
    -Context "ledger.refresh_policy"
$maxReviewAge =
    Get-RequiredInteger `
        -Container $refresh `
        -Name "max_review_age_days" `
        -Context "ledger.refresh_policy" `
        -Minimum 1 `
        -Maximum 365
$maxSourceAge =
    Get-RequiredInteger `
        -Container $refresh `
        -Name "max_source_verification_age_days" `
        -Context "ledger.refresh_policy" `
        -Minimum 1 `
        -Maximum 365
$reviewAge =
    ($asOf - $reviewedThrough).Days
if ($reviewAge -gt $maxReviewAge)
{
    throw (
        "research ledger is stale: reviewed_through=" +
        $reviewedThrough.ToString("yyyy-MM-dd") +
        " as_of=" +
        $asOf.ToString("yyyy-MM-dd") +
        " age_days=$reviewAge max=$maxReviewAge")
}

$minimumSourceTypes =
    Get-RequiredArray `
        -Container $refresh `
        -Name "minimum_source_types" `
        -Context "ledger.refresh_policy"
Assert-StringArray `
    -Values $minimumSourceTypes `
    -Context "ledger.refresh_policy.minimum_source_types"
$allowedSourceTypes =
    @(
        "vendor-research",
        "academic-paper",
        "official-doc",
        "open-test",
        "detection-strategy",
        "reference-source")
foreach ($sourceType in $minimumSourceTypes)
{
    if ([string]$sourceType -notin
        $allowedSourceTypes)
    {
        throw (
            "minimum_source_types contains unsupported " +
            "'$sourceType'")
    }
}

$endpoints =
    Get-RequiredArray `
        -Container $refresh `
        -Name "discovery_endpoints" `
        -Context "ledger.refresh_policy"
if ($endpoints.Count -lt 5)
{
    throw "at least five independent discovery endpoints are required"
}
$endpointIds =
    [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
$endpointUrls =
    [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
for ($index = 0;
     $index -lt $endpoints.Count;
     ++$index)
{
    $endpoint =
        $endpoints[$index]
    $context =
        "ledger.refresh_policy.discovery_endpoints[$index]"
    Assert-JsonObject `
        -Value $endpoint `
        -Context $context
    Assert-ObjectProperties `
        -Value $endpoint `
        -Required @(
            "id",
            "url",
            "last_checked_on") `
        -Allowed @(
            "id",
            "url",
            "last_checked_on") `
        -Context $context
    $id =
        Get-RequiredString `
            -Container $endpoint `
            -Name "id" `
            -Context $context
    Assert-Identifier `
        -Value $id `
        -Context "$context.id"
    if (-not $endpointIds.Add($id))
    {
        throw "duplicate discovery endpoint id '$id'"
    }
    $url =
        Get-RequiredString `
            -Container $endpoint `
            -Name "url" `
            -Context $context
    Assert-HttpsUrl `
        -Value $url `
        -Context "$context.url"
    if (-not $endpointUrls.Add($url))
    {
        throw "duplicate discovery endpoint URL '$url'"
    }
    $lastChecked =
        Get-RequiredDate `
            -Container $endpoint `
            -Name "last_checked_on" `
            -Context $context
    if ($lastChecked -gt $reviewedThrough -or
        ($reviewedThrough - $lastChecked).Days -gt
            $maxSourceAge)
    {
        throw "$context.last_checked_on is outside the freshness window"
    }
}

$sources =
    Get-RequiredArray `
        -Container $document `
        -Name "sources" `
        -Context "ledger"
if ($sources.Count -eq 0)
{
    throw "ledger.sources must not be empty"
}
$sourceById =
    [Collections.Generic.Dictionary[string,object]]::new(
        [StringComparer]::Ordinal)
$sourceUrls =
    [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
$observedSourceTypes =
    [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
for ($index = 0;
     $index -lt $sources.Count;
     ++$index)
{
    $source =
        $sources[$index]
    $context =
        "ledger.sources[$index]"
    Assert-JsonObject `
        -Value $source `
        -Context $context
    Assert-ObjectProperties `
        -Value $source `
        -Required @(
            "id",
            "title",
            "publisher",
            "published_on",
            "verified_on",
            "url",
            "source_type",
            "primary",
            "version_note",
            "primitive") `
        -Allowed @(
            "id",
            "title",
            "publisher",
            "published_on",
            "verified_on",
            "url",
            "source_type",
            "primary",
            "version_note",
            "primitive") `
        -Context $context
    $id =
        Get-RequiredString `
            -Container $source `
            -Name "id" `
            -Context $context
    Assert-Identifier `
        -Value $id `
        -Context "$context.id"
    if ($sourceById.ContainsKey($id))
    {
        throw "duplicate source id '$id'"
    }
    $sourceById.Add(
        $id,
        $source)
    [void](Get-RequiredString `
        -Container $source `
        -Name "title" `
        -Context $context)
    [void](Get-RequiredString `
        -Container $source `
        -Name "publisher" `
        -Context $context)
    $publishedOn =
        Get-NullableDate `
            -Container $source `
            -Name "published_on" `
            -Context $context
    if ($null -ne $publishedOn -and
        $publishedOn -gt $reviewedThrough)
    {
        throw "$context.published_on is after reviewed_through"
    }
    $verifiedOn =
        Get-RequiredDate `
            -Container $source `
            -Name "verified_on" `
            -Context $context
    if ($verifiedOn -gt $reviewedThrough -or
        ($reviewedThrough - $verifiedOn).Days -gt
            $maxSourceAge)
    {
        throw "$context.verified_on is outside the freshness window"
    }
    $url =
        Get-RequiredString `
            -Container $source `
            -Name "url" `
            -Context $context
    Assert-HttpsUrl `
        -Value $url `
        -Context "$context.url"
    if (-not $sourceUrls.Add($url))
    {
        throw "duplicate source URL '$url'"
    }
    $sourceType =
        Get-RequiredString `
            -Container $source `
            -Name "source_type" `
            -Context $context
    if ($sourceType -notin
        $allowedSourceTypes)
    {
        throw "$context.source_type '$sourceType' is unsupported"
    }
    [void]$observedSourceTypes.Add(
        $sourceType)
    $primary =
        Get-RequiredBoolean `
            -Container $source `
            -Name "primary" `
            -Context $context
    if (-not $primary)
    {
        throw "$context.primary must be true"
    }
    [void](Get-RequiredString `
        -Container $source `
        -Name "version_note" `
        -Context $context)
    [void](Get-RequiredString `
        -Container $source `
        -Name "primitive" `
        -Context $context)
}
foreach ($requiredType in
         $minimumSourceTypes)
{
    if (-not $observedSourceTypes.Contains(
            [string]$requiredType))
    {
        throw (
            "required source type is absent: " +
            $requiredType)
    }
}

$techniques =
    Get-RequiredArray `
        -Container $document `
        -Name "techniques" `
        -Context "ledger"
if ($techniques.Count -eq 0)
{
    throw "ledger.techniques must not be empty"
}
$techniqueById =
    [Collections.Generic.Dictionary[string,object]]::new(
        [StringComparer]::Ordinal)
$referencedSourceIds =
    [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
$fileCache =
    [Collections.Generic.Dictionary[string,string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
$statusCounts =
    [ordered]@{
        covered = 0
        partial = 0
        missing = 0
        out_of_scope = 0
    }
$releaseGateCounts =
    [ordered]@{
        satisfied = 0
        external_pending = 0
        backlog = 0
        not_applicable = 0
    }
$statusToClaim =
    @{
        covered = "supported"
        partial = "bounded"
        missing = "unsupported"
        out_of_scope = "unsupported"
    }
$allowedReleaseGates =
    @(
        "satisfied",
        "external_pending",
        "backlog",
        "not_applicable")
for ($index = 0;
     $index -lt $techniques.Count;
     ++$index)
{
    $technique =
        $techniques[$index]
    $context =
        "ledger.techniques[$index]"
    Assert-JsonObject `
        -Value $technique `
        -Context $context
    $techniqueProperties =
        @(
            "id",
            "title",
            "family",
            "status",
            "claim",
            "priority",
            "release_gate",
            "source_ids",
            "observable",
            "detector_anchors",
            "positive_controls",
            "negative_controls",
            "validation_commands",
            "limitations",
            "next_action")
    Assert-ObjectProperties `
        -Value $technique `
        -Required $techniqueProperties `
        -Allowed $techniqueProperties `
        -Context $context
    $id =
        Get-RequiredString `
            -Container $technique `
            -Name "id" `
            -Context $context
    Assert-Identifier `
        -Value $id `
        -Context "$context.id"
    if ($techniqueById.ContainsKey($id))
    {
        throw "duplicate technique id '$id'"
    }
    $techniqueById.Add(
        $id,
        $technique)
    [void](Get-RequiredString `
        -Container $technique `
        -Name "title" `
        -Context $context)
    [void](Get-RequiredString `
        -Container $technique `
        -Name "family" `
        -Context $context)
    $status =
        Get-RequiredString `
            -Container $technique `
            -Name "status" `
            -Context $context
    if (-not $statusToClaim.ContainsKey(
            $status))
    {
        throw "$context.status '$status' is unsupported"
    }
    $statusCounts[$status] =
        1 + [int]$statusCounts[$status]
    $claim =
        Get-RequiredString `
            -Container $technique `
            -Name "claim" `
            -Context $context
    if ($claim -ne
        $statusToClaim[$status])
    {
        throw (
            "$context.claim '$claim' contradicts " +
            "status '$status'")
    }
    $priority =
        Get-RequiredString `
            -Container $technique `
            -Name "priority" `
            -Context $context
    if ($priority -notmatch '^P[0-3]$')
    {
        throw "$context.priority '$priority' is unsupported"
    }
    $releaseGate =
        Get-RequiredString `
            -Container $technique `
            -Name "release_gate" `
            -Context $context
    if ($releaseGate -notin
        $allowedReleaseGates)
    {
        throw "$context.release_gate '$releaseGate' is unsupported"
    }
    $releaseGateCounts[$releaseGate] =
        1 + [int]$releaseGateCounts[$releaseGate]
    if ($status -eq "covered" -and
        $releaseGate -ne "satisfied")
    {
        throw "$context covered status requires a satisfied release_gate"
    }
    if ($status -eq "missing" -and
        $releaseGate -ne "backlog")
    {
        throw "$context missing status requires a backlog release_gate"
    }
    if ($status -eq "out_of_scope" -and
        $releaseGate -ne "not_applicable")
    {
        throw "$context out_of_scope status requires not_applicable"
    }
    if ($status -eq "partial" -and
        $releaseGate -eq "not_applicable")
    {
        throw "$context partial status cannot use not_applicable"
    }

    $sourceIds =
        Get-RequiredArray `
            -Container $technique `
            -Name "source_ids" `
            -Context $context
    Assert-StringArray `
        -Values $sourceIds `
        -Context "$context.source_ids"
    foreach ($sourceId in
             $sourceIds)
    {
        $sourceIdText =
            [string]$sourceId
        if (-not $sourceById.ContainsKey(
                $sourceIdText))
        {
            throw (
                "$context references unknown source " +
                "'$sourceIdText'")
        }
        [void]$referencedSourceIds.Add(
            $sourceIdText)
    }
    [void](Get-RequiredString `
        -Container $technique `
        -Name "observable" `
        -Context $context)
    $detectorAnchors =
        Get-RequiredArray `
            -Container $technique `
            -Name "detector_anchors" `
            -Context $context
    $positiveControls =
        Get-RequiredArray `
            -Container $technique `
            -Name "positive_controls" `
            -Context $context
    $negativeControls =
        Get-RequiredArray `
            -Container $technique `
            -Name "negative_controls" `
            -Context $context
    $validationCommands =
        Get-RequiredArray `
            -Container $technique `
            -Name "validation_commands" `
            -Context $context
    $limitations =
        Get-RequiredArray `
            -Container $technique `
            -Name "limitations" `
            -Context $context
    Assert-StringArray `
        -Values $limitations `
        -Context "$context.limitations" `
        -AllowEmpty
    $nextAction =
        Get-RequiredString `
            -Container $technique `
            -Name "next_action" `
            -Context $context `
            -AllowEmpty

    $implemented =
        $status -eq "covered" -or
        $status -eq "partial"
    Assert-AnchorArray `
        -Anchors $detectorAnchors `
        -Context "$context.detector_anchors" `
        -RepositoryRoot $rootPath `
        -FileCache $fileCache `
        -RequireNonEmpty:$implemented
    Assert-AnchorArray `
        -Anchors $positiveControls `
        -Context "$context.positive_controls" `
        -RepositoryRoot $rootPath `
        -FileCache $fileCache `
        -RequireNonEmpty:$implemented
    Assert-AnchorArray `
        -Anchors $negativeControls `
        -Context "$context.negative_controls" `
        -RepositoryRoot $rootPath `
        -FileCache $fileCache `
        -RequireNonEmpty:$implemented
    Assert-ValidationCommands `
        -Commands $validationCommands `
        -Context "$context.validation_commands" `
        -RequireNonEmpty:$implemented

    if ($status -eq "covered")
    {
        if ($limitations.Count -ne 0 -or
            -not [string]::IsNullOrEmpty(
                $nextAction))
        {
            throw (
                "$context covered status cannot carry " +
                "limitations or a next_action")
        }
    }
    else
    {
        if ($limitations.Count -eq 0 -or
            [string]::IsNullOrWhiteSpace(
                $nextAction))
        {
            throw (
                "$context non-covered status requires " +
                "limitations and next_action")
        }
    }
    if (-not $implemented -and
        ($detectorAnchors.Count -ne 0 -or
         $positiveControls.Count -ne 0 -or
         $negativeControls.Count -ne 0 -or
         $validationCommands.Count -ne 0))
    {
        throw (
            "$context missing/out_of_scope status cannot " +
            "carry implementation or validation evidence")
    }
}

foreach ($sourceId in
         $sourceById.Keys)
{
    if (-not $referencedSourceIds.Contains(
            $sourceId))
    {
        throw "source '$sourceId' is not referenced by any technique"
    }
}

$completionGate =
    $document.completion_gate
Assert-JsonObject `
    -Value $completionGate `
    -Context "ledger.completion_gate"
Assert-ObjectProperties `
    -Value $completionGate `
    -Required @(
        "required_technique_ids",
        "external_gate_required",
        "external_gate_schema",
        "minimum_clean_runs") `
    -Allowed @(
        "required_technique_ids",
        "external_gate_required",
        "external_gate_schema",
        "minimum_clean_runs") `
    -Context "ledger.completion_gate"
$requiredTechniqueIds =
    Get-RequiredArray `
        -Container $completionGate `
        -Name "required_technique_ids" `
        -Context "ledger.completion_gate"
Assert-StringArray `
    -Values $requiredTechniqueIds `
    -Context "ledger.completion_gate.required_technique_ids"
$requiredExternalPending = 0
foreach ($techniqueId in
         $requiredTechniqueIds)
{
    $id =
        [string]$techniqueId
    if (-not $techniqueById.ContainsKey(
            $id))
    {
        throw (
            "completion gate references unknown technique " +
            "'$id'")
    }
    $technique =
        $techniqueById[$id]
    if ([string]$technique.status -eq "missing" -or
        [string]$technique.status -eq "out_of_scope")
    {
        throw (
            "completion-gate technique '$id' has " +
            "unsupported status '$($technique.status)'")
    }
    if ([string]$technique.release_gate -eq
        "external_pending")
    {
        ++$requiredExternalPending
    }
    elseif ([string]$technique.release_gate -ne
           "satisfied")
    {
        throw (
            "completion-gate technique '$id' has " +
            "non-releasable gate '$($technique.release_gate)'")
    }
}
$externalGateRequired =
    Get-RequiredBoolean `
        -Container $completionGate `
        -Name "external_gate_required" `
        -Context "ledger.completion_gate"
if (-not $externalGateRequired)
{
    throw "ledger.completion_gate.external_gate_required must remain true"
}
$externalSchema =
    Get-RequiredString `
        -Container $completionGate `
        -Name "external_gate_schema" `
        -Context "ledger.completion_gate"
if ($externalSchema -ne
    "kn-live-dbg.evasion-external-gate.v1")
{
    throw (
        "unsupported completion external gate schema " +
        "'$externalSchema'")
}
$minimumCleanRuns =
    Get-RequiredInteger `
        -Container $completionGate `
        -Name "minimum_clean_runs" `
        -Context "ledger.completion_gate" `
        -Minimum 3 `
        -Maximum 10

$ledgerHash =
    $ledgerSnapshot.Sha256
$claimGateState =
    if ($requiredExternalPending -gt 0)
    {
        "external_pending"
    }
    else
    {
        "external_evidence_required"
    }
$summary =
    [ordered]@{
        sources =
            $sources.Count
        techniques =
            $techniques.Count
        covered =
            [int]$statusCounts.covered
        partial =
            [int]$statusCounts.partial
        missing =
            [int]$statusCounts.missing
        out_of_scope =
            [int]$statusCounts.out_of_scope
        release_satisfied =
            [int]$releaseGateCounts.satisfied
        release_external_pending =
            [int]$releaseGateCounts.external_pending
        release_backlog =
            [int]$releaseGateCounts.backlog
        release_not_applicable =
            [int]$releaseGateCounts.not_applicable
        completion_required =
            $requiredTechniqueIds.Count
        completion_external_pending =
            $requiredExternalPending
        minimum_clean_runs =
            $minimumCleanRuns
        claim_gate_state =
            $claimGateState
    }

if (-not [string]::IsNullOrWhiteSpace(
        $ReportPath))
{
    $buildRoot =
        Join-Path $rootPath ".build"
    Assert-NoReparsePointPath `
        -Root $rootPath `
        -RelativePath ".build" `
        -Context "report root"
    if (-not (Test-Path `
            -LiteralPath $buildRoot `
            -PathType Container))
    {
        New-Item `
            -ItemType Directory `
            -Path $buildRoot |
            Out-Null
    }
    Assert-NoReparsePointPath `
        -Root $rootPath `
        -RelativePath ".build" `
        -Context "report root"
    $reportFullPath =
        Assert-UnderPath `
            -Parent $buildRoot `
            -Child $ReportPath `
            -Context "report path"
    $reportRelativePath =
        $reportFullPath.Substring(
            $rootPrefix.Length)
    $reportRelativePath =
        Get-SafeRepositoryRelativePath `
            -Path $reportRelativePath `
            -Context "report path"
    Assert-NoReparsePointPath `
        -Root $rootPath `
        -RelativePath $reportRelativePath `
        -Context "report path"
    $reportParent =
        Split-Path -Parent $reportFullPath
    if (-not (Test-Path `
            -LiteralPath $reportParent `
            -PathType Container))
    {
        New-Item `
            -ItemType Directory `
            -Path $reportParent `
            -Force |
            Out-Null
    }
    [ordered]@{
        schema =
            "kn-live-dbg.evasion-research-ledger-validation.v1"
        validated_at =
            (Get-Date).ToString("o")
        as_of =
            $asOf.ToString("yyyy-MM-dd")
        ledger_path =
            $ledgerFullPath
        ledger_sha256 =
            $ledgerHash
        reviewed_through =
            $reviewedThrough.ToString("yyyy-MM-dd")
        summary =
            $summary
    } |
        ConvertTo-Json -Depth 8 |
        Set-Content `
            -LiteralPath $reportFullPath `
            -Encoding UTF8
}

Write-Host "evasion research ledger validation passed"
Write-Host (
    "  reviewed_through={0} age_days={1} sources={2} techniques={3}" -f
        $reviewedThrough.ToString("yyyy-MM-dd"),
        $reviewAge,
        $sources.Count,
        $techniques.Count)
Write-Host (
    "  covered={0} partial={1} missing={2} out_of_scope={3}" -f
        $statusCounts.covered,
        $statusCounts.partial,
        $statusCounts.missing,
        $statusCounts.out_of_scope)
Write-Host (
    "  completion_required={0} external_pending={1} clean_runs={2} state={3}" -f
        $requiredTechniqueIds.Count,
        $requiredExternalPending,
        $minimumCleanRuns,
        $claimGateState)
Write-Host "  ledger_sha256=$ledgerHash"

exit 0
