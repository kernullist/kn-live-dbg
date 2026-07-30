param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    [switch]$SkipBuild,
    [switch]$NoVersionBump
)

$ErrorActionPreference = "Stop"

$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$buildScript = Join-Path $PSScriptRoot "build.ps1"
$outputDir = Join-Path $repo "x64\$Configuration"
$releaseDir = Join-Path $repo "release"
$stagingRoot = Join-Path $releaseDir "staging"
$statePath = Join-Path $repo ".build\version-state.json"
$sourceExe = Join-Path $outputDir "KnLiveDbg.exe"
$researchLedger =
    Join-Path $repo (
        "research\evasion-research-ledger.json")
$researchLedgerValidator =
    Join-Path $repo (
        "tools\validate-evasion-research-ledger.ps1")
$researchLedgerValidationReport =
    Join-Path $repo (
        ".build\release-evasion-research-ledger-validation.json")

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

function Get-FullPath
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return [System.IO.Path]::GetFullPath($Path)
}

function Assert-UnderPath
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,
        [Parameter(Mandatory = $true)]
        [string]$ChildPath
    )

    $firstColon =
        $ChildPath.IndexOf([char]":")
    $lastColon =
        $ChildPath.LastIndexOf([char]":")
    if ($ChildPath.Contains([char]0) -or
        ($firstColon -ge 0 -and
            ($firstColon -ne 1 -or
                $lastColon -ne $firstColon -or
                -not [char]::IsLetter($ChildPath[0]))))
    {
        throw (
            "Refusing NUL or alternate data stream path: " +
            $ChildPath)
    }

    $base = (Get-FullPath -Path $BasePath).TrimEnd("\")
    $child = Get-FullPath -Path $ChildPath
    $prefix = "$base\"

    if (-not $child.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase))
    {
        throw "Refusing to modify path outside expected directory: $child"
    }
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

function Assert-NoReparsePointTree
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    $rootItem =
        Get-Item `
            -LiteralPath $Path `
            -Force `
            -ErrorAction Stop
    if (-not $rootItem.PSIsContainer)
    {
        throw "$Context must be a directory: $Path"
    }
    if (($rootItem.Attributes -band
            [IO.FileAttributes]::ReparsePoint) -ne 0)
    {
        throw "$Context is a reparse point: $Path"
    }

    $pending =
        [Collections.Generic.Stack[
            IO.DirectoryInfo]]::new()
    $pending.Push(
        [IO.DirectoryInfo]$rootItem)
    while ($pending.Count -ne 0)
    {
        $directory =
            $pending.Pop()
        foreach ($child in
            $directory.EnumerateFileSystemInfos())
        {
            if (($child.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0)
            {
                throw (
                    "$Context contains a reparse point: " +
                    $child.FullName)
            }
            if (($child.Attributes -band
                    [IO.FileAttributes]::Directory) -ne 0)
            {
                $pending.Push(
                    [IO.DirectoryInfo]$child)
            }
        }
    }
}

function Normalize-VersionText
{
    param(
        [string]$VersionText
    )

    if ([string]::IsNullOrWhiteSpace($VersionText))
    {
        return "dev"
    }

    $normalized =
        ($VersionText.Trim() -replace "\s.*$", "")
    if ($normalized -notmatch
        '^\d+\.\d+\.\d+(?:\.\d+)?$')
    {
        throw "Invalid numeric PE version: $VersionText"
    }
    $parts = $normalized.Split(".")
    if ($parts.Length -ge 3)
    {
        return ("{0}.{1}.{2}" -f $parts[0], $parts[1], $parts[2])
    }

    return $normalized
}

function Get-ReleaseVersion
{
    if (Test-Path $sourceExe)
    {
        $fileVersion = (Get-Item -LiteralPath $sourceExe).VersionInfo.FileVersion
        if (-not [string]::IsNullOrWhiteSpace($fileVersion))
        {
            return Normalize-VersionText -VersionText $fileVersion
        }
    }

    if (Test-Path $statePath)
    {
        $state = Get-Content $statePath -Raw | ConvertFrom-Json
        if ($state.current_version)
        {
            return Normalize-VersionText -VersionText ([string]$state.current_version)
        }
    }

    return "dev"
}

function Copy-PackageFile
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourcePath,
        [Parameter(Mandatory = $true)]
        [string]$DestinationDir,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.HashSet[string]]$Copied,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$Entries
    )

    $sourceItem =
        Get-Item `
            -LiteralPath $SourcePath `
            -Force `
            -ErrorAction Stop
    if (-not $sourceItem.Exists -or
        $sourceItem.PSIsContainer)
    {
        throw "Package source is not a file: $SourcePath"
    }
    if (($sourceItem.Attributes -band
            [IO.FileAttributes]::ReparsePoint) -ne 0)
    {
        throw "Package source is a reparse point: $SourcePath"
    }

    $destination =
        Join-Path $DestinationDir $sourceItem.Name
    $sourceHash =
        Get-FileSha256 `
            -Path $sourceItem.FullName
    if ($Copied.Contains($sourceItem.Name))
    {
        if (-not (Test-Path `
                -LiteralPath $destination `
                -PathType Leaf))
        {
            throw (
                "Recorded package file is missing: " +
                $sourceItem.Name)
        }
        $destinationItem =
            Get-Item `
                -LiteralPath $destination `
                -Force
        $destinationHash =
            Get-FileSha256 `
                -Path $destination
        if ($destinationItem.Length -ne
                $sourceItem.Length -or
            $destinationHash -ne $sourceHash)
        {
            throw (
                "Package filename collision has different bytes: " +
                $sourceItem.Name)
        }
        return
    }

    if (Test-Path -LiteralPath $destination)
    {
        $destinationExisting =
            Get-Item `
                -LiteralPath $destination `
                -Force
        if (($destinationExisting.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0)
        {
            throw (
                "Package destination is a reparse point: " +
                $destination)
        }
    }
    Copy-Item `
        -LiteralPath $sourceItem.FullName `
        -Destination $destination `
        -Force
    $destinationItem =
        Get-Item `
            -LiteralPath $destination `
            -Force
    $destinationHash =
        Get-FileSha256 `
            -Path $destination
    if ($destinationItem.Length -ne
            $sourceItem.Length -or
        $destinationHash -ne $sourceHash)
    {
        throw "Package copy verification failed: $destination"
    }
    $Copied.Add($sourceItem.Name) | Out-Null
    $Entries.Add([pscustomobject]@{
        name   = $sourceItem.Name
        size   = $sourceItem.Length
        sha256 = $sourceHash
    }) | Out-Null
}

function Copy-PackageRelativeFile
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourceRoot,

        [Parameter(Mandatory = $true)]
        [string]$DestinationRoot,

        [Parameter(Mandatory = $true)]
        [string]$RelativePath,

        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[object]]$Entries
    )

    $normalized =
        Get-SafeRepositoryRelativePath `
            -Path $RelativePath `
            -Context "package evidence path"

    $source =
        Get-FullPath -Path (
            Join-Path $SourceRoot $normalized)
    $destination =
        Get-FullPath -Path (
            Join-Path $DestinationRoot $normalized)
    Assert-UnderPath `
        -BasePath $SourceRoot `
        -ChildPath $source
    Assert-UnderPath `
        -BasePath $DestinationRoot `
        -ChildPath $destination
    Assert-NoReparsePointPath `
        -Root $SourceRoot `
        -RelativePath $normalized `
        -Context "package evidence source"
    Assert-NoReparsePointPath `
        -Root $DestinationRoot `
        -RelativePath $normalized `
        -Context "package evidence destination"
    if (-not (Test-Path `
            -LiteralPath $source `
            -PathType Leaf))
    {
        throw "Research anchor source was not found: $source"
    }

    $manifestName =
        $normalized.Replace("\", "/")
    $sourceItem =
        Get-Item -LiteralPath $source
    $sourceHash =
        Get-FileSha256 `
            -Path $source
    $existingEntry =
        @($Entries | Where-Object {
                [string]$_.name -eq
                    $manifestName
            })
    if ($existingEntry.Count -gt 1)
    {
        throw "Duplicate release manifest entry: $manifestName"
    }
    if ($existingEntry.Count -eq 1)
    {
        if (-not (Test-Path `
                -LiteralPath $destination `
                -PathType Leaf))
        {
            throw "Manifest entry has no staged file: $manifestName"
        }
        $destinationItem =
            Get-Item -LiteralPath $destination
        $destinationHash =
            Get-FileSha256 `
                -Path $destination
        if ($destinationItem.Length -ne
                $sourceItem.Length -or
            $destinationHash -ne $sourceHash)
        {
            throw "Staged evidence file differs from source: $manifestName"
        }
        return
    }

    $destinationDirectory =
        Split-Path -Parent $destination
    New-Item `
        -ItemType Directory `
        -Force `
        -Path $destinationDirectory |
        Out-Null
    Copy-Item `
        -LiteralPath $source `
        -Destination $destination `
        -Force
    $destinationItem =
        Get-Item `
            -LiteralPath $destination `
            -Force
    $destinationHash =
        Get-FileSha256 `
            -Path $destination
    if ($destinationItem.Length -ne
            $sourceItem.Length -or
        $destinationHash -ne $sourceHash)
    {
        throw "Package copy verification failed: $manifestName"
    }
    $Entries.Add([pscustomobject]@{
        name = $manifestName
        size = $sourceItem.Length
        sha256 = $sourceHash
    }) | Out-Null
}

function New-ZipFromDirectory
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourceDir,
        [Parameter(Mandatory = $true)]
        [string]$ZipPath
    )

    Assert-NoReparsePointTree `
        -Path $SourceDir `
        -Context "release staging tree"

    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $zip = [System.IO.Compression.ZipFile]::Open($ZipPath, [System.IO.Compression.ZipArchiveMode]::Create)
    try
    {
        $sourceRoot = (Get-FullPath -Path $SourceDir).TrimEnd("\")
        $files = Get-ChildItem -LiteralPath $SourceDir -Recurse -File | Sort-Object FullName
        foreach ($file in $files)
        {
            $relativePath = $file.FullName.Substring($sourceRoot.Length).TrimStart("\")
            $entryName = $relativePath.Replace("\", "/")
            [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $file.FullName, $entryName) | Out-Null
        }
    }
    finally
    {
        $zip.Dispose()
    }
}

if (-not (Test-Path $buildScript))
{
    throw "Build script was not found: $buildScript"
}

if (-not (Test-Path `
        -LiteralPath $researchLedger `
        -PathType Leaf))
{
    throw "Required research ledger was not found: $researchLedger"
}
if (-not (Test-Path `
        -LiteralPath $researchLedgerValidator `
        -PathType Leaf))
{
    throw (
        "Required research ledger validator was not found: " +
        $researchLedgerValidator)
}

$ledgerValidationArguments =
    @(
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        $researchLedgerValidator,
        "-Root",
        $repo,
        "-LedgerPath",
        $researchLedger,
        "-ReportPath",
        $researchLedgerValidationReport
    )
$ledgerValidationStartedAt =
    [DateTime]::UtcNow
& powershell.exe @ledgerValidationArguments
$ledgerValidationExitCode =
    [int]$LASTEXITCODE
if ($ledgerValidationExitCode -ne 0)
{
    throw (
        "Research ledger validation failed before packaging " +
        "(exit=$ledgerValidationExitCode)")
}
if (-not (Test-Path `
        -LiteralPath $researchLedgerValidationReport `
        -PathType Leaf))
{
    throw (
        "Research ledger validation did not emit its report: " +
        $researchLedgerValidationReport)
}
$ledgerValidationReport =
    Get-Content `
        -LiteralPath $researchLedgerValidationReport `
        -Raw |
    ConvertFrom-Json
$ledgerValidatedAt =
    [DateTime]::MinValue
if ([string]$ledgerValidationReport.schema -ne
        "kn-live-dbg.evasion-research-ledger-validation.v1" -or
    -not [DateTime]::TryParse(
        [string]$ledgerValidationReport.validated_at,
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind,
        [ref]$ledgerValidatedAt) -or
    $ledgerValidatedAt.ToUniversalTime() -lt
        $ledgerValidationStartedAt.AddSeconds(-2) -or
    $ledgerValidatedAt.ToUniversalTime() -gt
        [DateTime]::UtcNow.AddMinutes(1) -or
    [IO.Path]::GetFullPath(
        [string]$ledgerValidationReport.ledger_path) -ne
        [IO.Path]::GetFullPath($researchLedger) -or
    [string]$ledgerValidationReport.ledger_sha256 -notmatch
        '^[0-9A-F]{64}$')
{
    throw "Research ledger validation report is inconsistent"
}
$validatedResearchLedgerHash =
    [string]$ledgerValidationReport.ledger_sha256
$currentResearchLedgerHash =
    Get-FileSha256 `
        -Path $researchLedger
if ($currentResearchLedgerHash -ne
        $validatedResearchLedgerHash)
{
    throw "Research ledger changed after validation"
}

if (-not $SkipBuild)
{
    if ($NoVersionBump)
    {
        & $buildScript -Configuration $Configuration
    }
    else
    {
        & $buildScript -Configuration $Configuration -BumpVersion
    }
    if ($LASTEXITCODE -ne 0)
    {
        exit $LASTEXITCODE
    }
}

if (-not (Test-Path $outputDir))
{
    throw "Build output directory was not found: $outputDir"
}
Assert-NoReparsePointPath `
    -Root $repo `
    -RelativePath (
        "x64\" + $Configuration) `
    -Context "build output path"

if (-not (Test-Path $sourceExe))
{
    throw "KnLiveDbg.exe was not found. Run tools\build.ps1 first."
}

$version = Get-ReleaseVersion
$packageId = "KnLiveDbg-$version-$Configuration-x64"
$stagingDir = Join-Path $stagingRoot $packageId
$zipPath = Join-Path $releaseDir "$packageId.zip"

Assert-NoReparsePointPath `
    -Root $repo `
    -RelativePath "release" `
    -Context "release directory"
New-Item -ItemType Directory -Force -Path $releaseDir | Out-Null
Assert-NoReparsePointPath `
    -Root $repo `
    -RelativePath "release" `
    -Context "release directory"
Assert-NoReparsePointPath `
    -Root $repo `
    -RelativePath "release\staging" `
    -Context "release staging root"
New-Item -ItemType Directory -Force -Path $stagingRoot | Out-Null
Assert-NoReparsePointPath `
    -Root $repo `
    -RelativePath "release\staging" `
    -Context "release staging root"

Assert-UnderPath -BasePath $stagingRoot -ChildPath $stagingDir
Assert-UnderPath -BasePath $releaseDir -ChildPath $zipPath
if (Test-Path $stagingDir)
{
    Assert-NoReparsePointTree `
        -Path $stagingDir `
        -Context "existing release staging tree"
    Remove-Item -LiteralPath $stagingDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $stagingDir | Out-Null

if (Test-Path $zipPath)
{
    $zipItem =
        Get-Item `
            -LiteralPath $zipPath `
            -Force
    if (($zipItem.Attributes -band
            [IO.FileAttributes]::ReparsePoint) -ne 0)
    {
        throw "Release ZIP is a reparse point: $zipPath"
    }
    Remove-Item -LiteralPath $zipPath -Force
}

$requiredFiles = @(
    "KnLiveDbg.exe",
    "KnLiveDbg.sys",
    "KnLiveDbgProbe.sys",
    "amdryzenmasterdriver.sys",
    "KnLiveDbgMiniFilterFixture.sys",
    "KnLiveDbgBindFixture.exe",
    "dbghelp.dll",
    "dbgeng.dll",
    "dbgcore.dll",
    "DbgModel.dll",
    "msdia140.dll",
    "symsrv.dll",
    "srcsrv.dll",
    "symsrv.yes"
)

$copied = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$entries = [System.Collections.Generic.List[object]]::new()

foreach ($name in $requiredFiles)
{
    $source = Join-Path $outputDir $name
    if (-not (Test-Path $source))
    {
        throw "Required release file was not found: $source"
    }

    Copy-PackageFile -SourcePath $source -DestinationDir $stagingDir -Copied $copied -Entries $entries
}

$optionalPatterns = @("*.pdb", "*.cer", "*.cat")
foreach ($pattern in $optionalPatterns)
{
    $items = Get-ChildItem -LiteralPath $outputDir -Filter $pattern -File -ErrorAction SilentlyContinue | Sort-Object Name
    foreach ($item in $items)
    {
        Copy-PackageFile -SourcePath $item.FullName -DestinationDir $stagingDir -Copied $copied -Entries $entries
    }
}

$readmePath = Join-Path $repo "README.md"
if (Test-Path $readmePath)
{
    Copy-PackageFile -SourcePath $readmePath -DestinationDir $stagingDir -Copied $copied -Entries $entries
}

$vendorManifest = Join-Path $repo "vendor\debugging-tools\x64\MANIFEST.md"
if (Test-Path $vendorManifest)
{
    Assert-NoReparsePointPath `
        -Root $repo `
        -RelativePath (
            "vendor\debugging-tools\x64\MANIFEST.md") `
        -Context "debugging tools manifest"
    $manifestDestination = Join-Path $stagingDir "debugging-tools-runtime-MANIFEST.md"
    Copy-Item -LiteralPath $vendorManifest -Destination $manifestDestination -Force
    $manifestItem = Get-Item -LiteralPath $manifestDestination
    $manifestSourceItem =
        Get-Item `
            -LiteralPath $vendorManifest `
            -Force
    $manifestSourceHash =
        Get-FileSha256 `
            -Path $vendorManifest
    $manifestDestinationHash =
        Get-FileSha256 `
            -Path $manifestDestination
    if ($manifestItem.Length -ne
            $manifestSourceItem.Length -or
        $manifestDestinationHash -ne
            $manifestSourceHash)
    {
        throw (
            "Debugging tools manifest copy verification failed")
    }
    $entries.Add([pscustomobject]@{
        name   = $manifestItem.Name
        size   = $manifestItem.Length
        sha256 = $manifestDestinationHash
    }) | Out-Null
}

$toolScripts = @(
    "update-byovd-intel.ps1",
    "run-hunt-clean-host.ps1",
    "validate-hunt-clean-host.ps1",
    "validate-hunt-clean-host-selftest.ps1",
    "analyze-hunt-clean-host.ps1",
    "analyze-hunt-clean-host-selftest.ps1",
    "run-cloudfiles-placeholder-fixture.ps1",
    "validate-cloudfiles-hunt-e2e.ps1",
    "validate-cloudfiles-hunt-e2e-selftest.ps1",
    "run-qos-bind-e2e.ps1",
    "validate-qos-bind-e2e.ps1",
    "validate-qos-bind-e2e-selftest.ps1",
    "run-minifilter-detach-e2e.ps1",
    "validate-minifilter-detach-e2e.ps1",
    "validate-minifilter-detach-e2e-selftest.ps1",
    "run-evasion-external-gate.ps1",
    "validate-evasion-external-gate.ps1",
    "validate-evasion-external-gate-selftest.ps1",
    "validate-evasion-research-ledger.ps1",
    "validate-evasion-research-ledger-selftest.ps1"
)
foreach ($toolScriptName in $toolScripts)
{
    Copy-PackageRelativeFile `
        -SourceRoot $repo `
        -DestinationRoot $stagingDir `
        -RelativePath (
            "tools\$toolScriptName") `
        -Entries $entries
}

Copy-PackageRelativeFile `
    -SourceRoot $repo `
    -DestinationRoot $stagingDir `
    -RelativePath (
        "research\evasion-research-ledger.json") `
    -Entries $entries
$researchLedgerDestination =
    Join-Path $stagingDir (
        "research\evasion-research-ledger.json")
$stagedResearchLedgerHash =
    Get-FileSha256 `
        -Path $researchLedgerDestination
if ($stagedResearchLedgerHash -ne
        $validatedResearchLedgerHash)
{
    throw (
        "Staged research ledger differs from the validated " +
        "ledger")
}

$researchDocument =
    Get-Content `
        -LiteralPath $researchLedgerDestination `
        -Raw |
    ConvertFrom-Json
$researchAnchorPaths =
    @(
        foreach ($technique in
            @($researchDocument.techniques))
        {
            foreach ($collectionName in @(
                    "detector_anchors",
                    "positive_controls",
                    "negative_controls"))
            {
                foreach ($anchor in
                    @($technique.$collectionName))
                {
                    [string]$anchor.path
                }
            }
        }
    ) |
    Where-Object {
        -not [string]::IsNullOrWhiteSpace($_)
    } |
    Sort-Object -Unique
foreach ($researchAnchorPath in
    $researchAnchorPaths)
{
    Copy-PackageRelativeFile `
        -SourceRoot $repo `
        -DestinationRoot $stagingDir `
        -RelativePath $researchAnchorPath `
        -Entries $entries
}

$versionManifestPath = Join-Path $stagingDir "kn-live-dbg-version.json"
$versionManifest = [pscustomobject]@{
    name          = "KnLiveDbg"
    version       = $version
    configuration = $Configuration
    platform      = "x64"
    created_at    = (Get-Date).ToString("o")
    files         = $entries
}
$versionManifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $versionManifestPath -Encoding ascii

New-ZipFromDirectory -SourceDir $stagingDir -ZipPath $zipPath

Write-Host "Prepared release package:"
Write-Host " - staging: $stagingDir"
Write-Host " - zip: $zipPath"
Write-Host " - version: $version"
