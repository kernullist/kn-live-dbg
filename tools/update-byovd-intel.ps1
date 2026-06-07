param(
    [Parameter(Mandatory = $true)]
    [string]$OutputDir,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$microsoftZipUrl = "https://aka.ms/VulnerableDriverBlockList"
$lolHashBase = "https://raw.githubusercontent.com/magicsword-io/LOLDrivers/main/detections/hashes"
$lolYaraBase = "https://raw.githubusercontent.com/magicsword-io/LOLDrivers/main/detections/yara"

$hashFeeds = @(
    @{ Url = "$lolHashBase/samples_vulnerable.md5"; Type = "md5"; Category = "loldrivers_vulnerable" },
    @{ Url = "$lolHashBase/samples_vulnerable.sha1"; Type = "sha1"; Category = "loldrivers_vulnerable" },
    @{ Url = "$lolHashBase/samples_vulnerable.sha256"; Type = "sha256"; Category = "loldrivers_vulnerable" },
    @{ Url = "$lolHashBase/samples_malicious.md5"; Type = "md5"; Category = "loldrivers_malicious" },
    @{ Url = "$lolHashBase/samples_malicious.sha1"; Type = "sha1"; Category = "loldrivers_malicious" },
    @{ Url = "$lolHashBase/samples_malicious.sha256"; Type = "sha256"; Category = "loldrivers_malicious" },
    @{ Url = "$lolHashBase/LoadsDespiteHVCI.samples_vulnerable.md5"; Type = "md5"; Category = "loldrivers_vulnerable_loads_despite_hvci" },
    @{ Url = "$lolHashBase/LoadsDespiteHVCI.samples_vulnerable.sha1"; Type = "sha1"; Category = "loldrivers_vulnerable_loads_despite_hvci" },
    @{ Url = "$lolHashBase/LoadsDespiteHVCI.samples_vulnerable.sha256"; Type = "sha256"; Category = "loldrivers_vulnerable_loads_despite_hvci" },
    @{ Url = "$lolHashBase/LoadsDespiteHVCI.samples_malicious.md5"; Type = "md5"; Category = "loldrivers_malicious_loads_despite_hvci" },
    @{ Url = "$lolHashBase/LoadsDespiteHVCI.samples_malicious.sha1"; Type = "sha1"; Category = "loldrivers_malicious_loads_despite_hvci" },
    @{ Url = "$lolHashBase/LoadsDespiteHVCI.samples_malicious.sha256"; Type = "sha256"; Category = "loldrivers_malicious_loads_despite_hvci" }
)

$yaraFeeds = @(
    @{ Url = "$lolYaraBase/yara-rules_vuln_drivers_strict.yar"; Name = "yara-rules_vuln_drivers_strict.yar" },
    @{ Url = "$lolYaraBase/yara-rules_mal_drivers.yar"; Name = "yara-rules_mal_drivers.yar" }
)

function New-Directory
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path))
    {
        New-Item -ItemType Directory -Force -Path $Path | Out-Null
    }
}

function Clean-Field
{
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value)
    {
        return ""
    }

    return ([string]$Value) -replace "[`t`r`n]+", " "
}

function Add-CatalogEntry
{
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]]$Lines,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.HashSet[string]]$Seen,
        [Parameter(Mandatory = $true)]
        [string]$Source,
        [Parameter(Mandatory = $true)]
        [string]$Category,
        [Parameter(Mandatory = $true)]
        [string]$MatchType,
        [AllowEmptyString()]
        [string]$Value,
        [AllowEmptyString()]
        [string]$Name,
        [AllowEmptyString()]
        [string]$MinimumVersion,
        [AllowEmptyString()]
        [string]$MaximumVersion,
        [AllowEmptyString()]
        [string]$Description
    )

    $sourceText = (Clean-Field $Source).ToLowerInvariant()
    $categoryText = (Clean-Field $Category).ToLowerInvariant()
    $matchText = (Clean-Field $MatchType).ToLowerInvariant()
    $valueText = (Clean-Field $Value).ToLowerInvariant()
    $nameText = (Clean-Field $Name).ToLowerInvariant()
    $minText = Clean-Field $MinimumVersion
    $maxText = Clean-Field $MaximumVersion
    $descText = Clean-Field $Description

    if ([string]::IsNullOrWhiteSpace($matchText))
    {
        return
    }

    if ([string]::IsNullOrWhiteSpace($valueText) -and [string]::IsNullOrWhiteSpace($nameText))
    {
        return
    }

    $key = "$sourceText`t$categoryText`t$matchText`t$valueText`t$nameText`t$minText`t$maxText"
    if (-not $Seen.Add($key))
    {
        return
    }

    $Lines.Add("$sourceText`t$categoryText`t$matchText`t$valueText`t$nameText`t$minText`t$maxText`t$descText") | Out-Null
}

function Get-HashTypeFromValue
{
    param(
        [string]$Hash
    )

    $length = $Hash.Length
    if ($length -eq 32)
    {
        return "md5"
    }
    if ($length -eq 40)
    {
        return "sha1"
    }
    if ($length -eq 64)
    {
        return "sha256"
    }

    return ""
}

function Get-FileSha256
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $stream = $null
    $sha256 = $null

    try
    {
        $stream = [System.IO.File]::OpenRead($Path)
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $bytes = $sha256.ComputeHash($stream)
        return (($bytes | ForEach-Object { $_.ToString("x2") }) -join "")
    }
    finally
    {
        if ($null -ne $sha256)
        {
            $sha256.Dispose()
        }
        if ($null -ne $stream)
        {
            $stream.Dispose()
        }
    }
}

function Expand-ZipFile
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$DestinationPath
    )

    $expandArchive = Get-Command -Name Expand-Archive -ErrorAction SilentlyContinue
    if ($null -ne $expandArchive)
    {
        Expand-Archive -LiteralPath $Path -DestinationPath $DestinationPath -Force
        return
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    if (Test-Path -LiteralPath $DestinationPath)
    {
        Remove-Item -LiteralPath $DestinationPath -Recurse -Force
    }
    New-Directory -Path $DestinationPath

    [System.IO.Compression.ZipFile]::ExtractToDirectory($Path, $DestinationPath)
}

function Add-MicrosoftPolicyEntries
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$XmlPath,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]]$Lines,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.HashSet[string]]$Seen
    )

    [xml]$policy = Get-Content -LiteralPath $XmlPath -Raw

    foreach ($deny in $policy.SiPolicy.FileRules.Deny)
    {
        $hash = ([string]$deny.Hash).Trim()
        if ([string]::IsNullOrWhiteSpace($hash))
        {
            continue
        }

        $hashType = Get-HashTypeFromValue -Hash $hash
        if ([string]::IsNullOrWhiteSpace($hashType))
        {
            continue
        }

        Add-CatalogEntry `
            -Lines $Lines `
            -Seen $Seen `
            -Source "microsoft_blocklist" `
            -Category "microsoft_hash_deny" `
            -MatchType $hashType `
            -Value $hash `
            -Name "" `
            -MinimumVersion "" `
            -MaximumVersion "" `
            -Description ([string]$deny.FriendlyName)
    }

    foreach ($attrib in $policy.SiPolicy.FileRules.FileAttrib)
    {
        $name = [string]$attrib.FileName
        if ([string]::IsNullOrWhiteSpace($name))
        {
            $name = [string]$attrib.InternalName
        }
        if ([string]::IsNullOrWhiteSpace($name))
        {
            continue
        }

        Add-CatalogEntry `
            -Lines $Lines `
            -Seen $Seen `
            -Source "microsoft_blocklist" `
            -Category "microsoft_file_attribute" `
            -MatchType "file_version" `
            -Value "" `
            -Name $name `
            -MinimumVersion ([string]$attrib.MinimumFileVersion) `
            -MaximumVersion ([string]$attrib.MaximumFileVersion) `
            -Description ([string]$attrib.FriendlyName)
    }
}

function Add-LolDriversHashFeed
{
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Feed,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]]$Lines,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.HashSet[string]]$Seen
    )

    $content = (Invoke-WebRequest -Uri $Feed.Url -UseBasicParsing).Content
    $expectedLength = switch ($Feed.Type)
    {
        "md5" { 32 }
        "sha1" { 40 }
        "sha256" { 64 }
        default { 0 }
    }

    foreach ($rawLine in ($content -split "`n"))
    {
        $line = $rawLine.Trim()
        if ([string]::IsNullOrWhiteSpace($line))
        {
            continue
        }

        $candidate = ($line -split "\s+")[0].Trim()
        if ($candidate.Length -ne $expectedLength)
        {
            continue
        }
        if ($candidate -notmatch "^[0-9a-fA-F]+$")
        {
            continue
        }

        Add-CatalogEntry `
            -Lines $Lines `
            -Seen $Seen `
            -Source "loldrivers" `
            -Category $Feed.Category `
            -MatchType $Feed.Type `
            -Value $candidate `
            -Name "" `
            -MinimumVersion "" `
            -MaximumVersion "" `
            -Description $Feed.Url
    }
}

$resolvedOutputDir = [System.IO.Path]::GetFullPath($OutputDir)
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("kn-live-dbg-byovd-" + [Guid]::NewGuid().ToString("N"))
$tempExtract = Join-Path $tempRoot "extract"
$tempData = Join-Path $tempRoot "data"
$tempYara = Join-Path $tempData "yara"
$catalogTemp = Join-Path $tempData "byovd_catalog.tsv"
$manifestTemp = Join-Path $tempData "manifest.json"

New-Directory -Path $resolvedOutputDir
New-Directory -Path $tempExtract
New-Directory -Path $tempYara

$lines = [System.Collections.Generic.List[string]]::new()
$seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$sourceStats = [ordered]@{}
$downloaded = [System.Collections.Generic.List[object]]::new()

try
{
    $zipPath = Join-Path $tempRoot "VulnerableDriverBlockList.zip"
    Invoke-WebRequest -Uri $microsoftZipUrl -OutFile $zipPath -UseBasicParsing
    $downloaded.Add([pscustomobject]@{
        source = "microsoft_blocklist"
        url = $microsoftZipUrl
        sha256 = Get-FileSha256 -Path $zipPath
    }) | Out-Null

    Expand-ZipFile -Path $zipPath -DestinationPath $tempExtract
    $xml = Get-ChildItem -LiteralPath $tempExtract -Recurse -Filter "DriverPolicy_Enforced.xml" -File |
        Select-Object -First 1
    if ($null -eq $xml)
    {
        throw "DriverPolicy_Enforced.xml was not found in Microsoft blocklist zip"
    }

    Add-MicrosoftPolicyEntries -XmlPath $xml.FullName -Lines $lines -Seen $seen

    foreach ($feed in $hashFeeds)
    {
        Add-LolDriversHashFeed -Feed $feed -Lines $lines -Seen $seen
        $downloaded.Add([pscustomobject]@{
            source = "loldrivers"
            url = $feed.Url
            sha256 = ""
        }) | Out-Null
    }

    foreach ($feed in $yaraFeeds)
    {
        $destination = Join-Path $tempYara $feed.Name
        Invoke-WebRequest -Uri $feed.Url -OutFile $destination -UseBasicParsing
        if ((Get-Item -LiteralPath $destination).Length -le 0)
        {
            throw "Downloaded YARA file is empty: $($feed.Url)"
        }
        $downloaded.Add([pscustomobject]@{
            source = "loldrivers_yara"
            url = $feed.Url
            sha256 = Get-FileSha256 -Path $destination
        }) | Out-Null
    }

    foreach ($line in $lines)
    {
        $source = ($line -split "`t", 2)[0]
        if (-not $sourceStats.Contains($source))
        {
            $sourceStats[$source] = 0
        }
        $sourceStats[$source]++
    }

    $header = @(
        "# schema=kn-live-dbg.byovd-catalog.v1",
        "# columns=source category match_type value name minimum_version maximum_version description"
    )
    Set-Content -LiteralPath $catalogTemp -Encoding utf8 -Value ($header + ($lines | Sort-Object))

    $manifest = [pscustomobject]@{
        schema = "kn-live-dbg.byovd-manifest.v1"
        generated_at = (Get-Date).ToString("o")
        catalog_entries = $lines.Count
        sources = $sourceStats
        downloads = $downloaded
        freshness_policy_hours = 24
    }
    $manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestTemp -Encoding utf8

    if ($lines.Count -le 0)
    {
        throw "No BYOVD catalog entries were generated"
    }

    $catalogFinal = Join-Path $resolvedOutputDir "byovd_catalog.tsv"
    $manifestFinal = Join-Path $resolvedOutputDir "manifest.json"
    $yaraFinal = Join-Path $resolvedOutputDir "yara"

    Move-Item -LiteralPath $catalogTemp -Destination $catalogFinal -Force
    Move-Item -LiteralPath $manifestTemp -Destination $manifestFinal -Force

    if (Test-Path -LiteralPath $yaraFinal)
    {
        Remove-Item -LiteralPath $yaraFinal -Recurse -Force
    }
    Move-Item -LiteralPath $tempYara -Destination $yaraFinal -Force

    Write-Host "BYOVD catalog updated: $catalogFinal"
    Write-Host "BYOVD manifest: $manifestFinal"
    Write-Host "BYOVD entries: $($lines.Count)"
}
finally
{
    if (Test-Path -LiteralPath $tempRoot)
    {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}
