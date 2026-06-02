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

    $base = (Get-FullPath -Path $BasePath).TrimEnd("\")
    $child = Get-FullPath -Path $ChildPath
    $prefix = "$base\"

    if (-not $child.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase))
    {
        throw "Refusing to modify path outside expected directory: $child"
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

    $normalized = ($VersionText.Trim() -replace "\s.*$", "")
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

    $sourceItem = Get-Item -LiteralPath $SourcePath -ErrorAction Stop
    if (-not $sourceItem.Exists)
    {
        throw "Package source was not found: $SourcePath"
    }

    if ($Copied.Contains($sourceItem.Name))
    {
        return
    }

    $destination = Join-Path $DestinationDir $sourceItem.Name
    Copy-Item -LiteralPath $sourceItem.FullName -Destination $destination -Force
    $Copied.Add($sourceItem.Name) | Out-Null
    $Entries.Add([pscustomobject]@{
        name   = $sourceItem.Name
        size   = $sourceItem.Length
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $sourceItem.FullName).Hash
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

if (-not (Test-Path $sourceExe))
{
    throw "KnLiveDbg.exe was not found. Run tools\build.ps1 first."
}

$version = Get-ReleaseVersion
$packageId = "KnLiveDbg-$version-$Configuration-x64"
$stagingDir = Join-Path $stagingRoot $packageId
$zipPath = Join-Path $releaseDir "$packageId.zip"

New-Item -ItemType Directory -Force -Path $releaseDir | Out-Null
New-Item -ItemType Directory -Force -Path $stagingRoot | Out-Null

Assert-UnderPath -BasePath $stagingRoot -ChildPath $stagingDir
if (Test-Path $stagingDir)
{
    Remove-Item -LiteralPath $stagingDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $stagingDir | Out-Null

if (Test-Path $zipPath)
{
    Remove-Item -LiteralPath $zipPath -Force
}

$requiredFiles = @(
    "KnLiveDbg.exe",
    "KnLiveDbg.sys",
    "KnLiveDbgProbe.sys",
    "amdryzenmasterdriver.sys",
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
    $manifestDestination = Join-Path $stagingDir "debugging-tools-runtime-MANIFEST.md"
    Copy-Item -LiteralPath $vendorManifest -Destination $manifestDestination -Force
    $manifestItem = Get-Item -LiteralPath $manifestDestination
    $entries.Add([pscustomobject]@{
        name   = $manifestItem.Name
        size   = $manifestItem.Length
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $manifestDestination).Hash
    }) | Out-Null
}

$byovdUpdateScript = Join-Path $repo "tools\update-byovd-intel.ps1"
if (Test-Path $byovdUpdateScript)
{
    $toolsDestination = Join-Path $stagingDir "tools"
    New-Item -ItemType Directory -Force -Path $toolsDestination | Out-Null
    $scriptDestination = Join-Path $toolsDestination "update-byovd-intel.ps1"
    Copy-Item -LiteralPath $byovdUpdateScript -Destination $scriptDestination -Force
    $scriptItem = Get-Item -LiteralPath $scriptDestination
    $entries.Add([pscustomobject]@{
        name   = "tools/update-byovd-intel.ps1"
        size   = $scriptItem.Length
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $scriptDestination).Hash
    }) | Out-Null
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
