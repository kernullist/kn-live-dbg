param(
    [string]$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,

    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",

    [string]$OutputZip = "",

    [string]$StagingRoot = "",

    [switch]$SkipReadiness
)

$ErrorActionPreference = "Stop"
$bundleContract = "eset-hunt-e2e-vm-bundle-v1"
$runnerContract = "e2e-auto-knlivedbg-article-currentness-v2"

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
        [string]$ChildPath,

        [switch]$AllowSame
    )

    $base = (Get-FullPath -Path $BasePath).TrimEnd("\")
    $child = (Get-FullPath -Path $ChildPath).TrimEnd("\")
    $prefix = "$base\"

    if ($child.Equals($base, [System.StringComparison]::OrdinalIgnoreCase))
    {
        if ($AllowSame)
        {
            return
        }

        throw "Refusing to use root path as child path: $child"
    }

    if (-not $child.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase))
    {
        throw "Refusing to modify path outside expected directory: $child"
    }
}

function New-DirectoryIfMissing
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path))
    {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
}

function New-ParentDirectoryIfMissing
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent))
    {
        New-DirectoryIfMissing -Path $parent
    }
}

function Copy-RelativeFile
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$RootPath,

        [Parameter(Mandatory = $true)]
        [string]$StagePath,

        [Parameter(Mandatory = $true)]
        [string]$RelativePath,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$Entries,

        [switch]$Required
    )

    $source = Join-Path $RootPath $RelativePath
    if (-not (Test-Path -LiteralPath $source))
    {
        if ($Required)
        {
            throw "bundle source file not found: $source"
        }

        return
    }

    $item = Get-Item -LiteralPath $source
    if ($item.PSIsContainer)
    {
        throw "bundle source is a directory, expected file: $source"
    }

    $destination = Join-Path $StagePath $RelativePath
    New-ParentDirectoryIfMissing -Path $destination
    Copy-Item -LiteralPath $source -Destination $destination -Force

    $hash = Get-FileHash -Algorithm SHA256 -LiteralPath $destination
    $Entries.Add([ordered]@{
        path = $RelativePath.Replace("\", "/")
        size = $item.Length
        sha256 = $hash.Hash
    }) | Out-Null
}

function Invoke-GitText
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$RootPath,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    try
    {
        $output = & git -C $RootPath @Arguments 2>$null
        if ($LASTEXITCODE -eq 0)
        {
            return ($output -join "`n")
        }
    }
    catch
    {
    }

    return ""
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

    if (Test-Path -LiteralPath $ZipPath)
    {
        Remove-Item -LiteralPath $ZipPath -Force
    }

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

$rootPath = (Resolve-Path -LiteralPath $Root).Path
$buildRoot = Join-Path $rootPath ".build"
New-DirectoryIfMissing -Path $buildRoot

if ([string]::IsNullOrWhiteSpace($StagingRoot))
{
    $StagingRoot = Join-Path $buildRoot "eset-hunt-e2e-vm-bundle-root"
}
if ([string]::IsNullOrWhiteSpace($OutputZip))
{
    $OutputZip = Join-Path $buildRoot "eset-hunt-e2e-vm-bundle.zip"
}
if (-not [System.IO.Path]::IsPathRooted($StagingRoot))
{
    $StagingRoot = Join-Path $rootPath $StagingRoot
}
if (-not [System.IO.Path]::IsPathRooted($OutputZip))
{
    $OutputZip = Join-Path $rootPath $OutputZip
}

$stageRoot = Get-FullPath -Path $StagingRoot
$zipPath = Get-FullPath -Path $OutputZip

Assert-UnderPath -BasePath $rootPath -ChildPath $stageRoot
Assert-UnderPath -BasePath $rootPath -ChildPath $zipPath

if (Test-Path -LiteralPath $stageRoot)
{
    Remove-Item -LiteralPath $stageRoot -Recurse -Force
}
New-DirectoryIfMissing -Path $stageRoot
New-ParentDirectoryIfMissing -Path $zipPath

$entries = [System.Collections.Generic.List[object]]::new()

$requiredFiles = @(
    "README.md",
    "docs\ARCHITECTURE.md",
    "docs\HUNT_TEST_TARGET.md",
    "docs\WINDBG_COMMAND_COVERAGE.md",
    "hunt_test_target\KnLiveDbgHuntTarget.cpp",
    "user\UserModeHunter.cpp",
    "user\UserModeHunter.h",
    "user\main.cpp",
    "tools\run-eset-hunt-e2e.ps1",
    "tools\validate-eset-hunt-e2e-artifacts.ps1",
    "tools\validate-eset-hunt-iocs.ps1",
    "tools\validate-hunt-readiness.ps1",
    "tools\validate-hunt-target.ps1",
    "tools\make-eset-hunt-e2e-vm-bundle.ps1",
    "x64\$Configuration\KnLiveDbg.exe",
    "x64\$Configuration\KnLiveDbg.sys",
    "x64\$Configuration\KnLiveDbgProbe.sys",
    "x64\$Configuration\dbghelp.dll",
    "x64\$Configuration\dbgeng.dll",
    "x64\$Configuration\dbgcore.dll",
    "x64\$Configuration\DbgModel.dll",
    "x64\$Configuration\msdia140.dll",
    "x64\$Configuration\srcsrv.dll",
    "x64\$Configuration\symsrv.dll",
    "x64\$Configuration\symsrv.yes",
    "x64\$Configuration\tools\KnLiveDbgHuntTarget.exe",
    "x64\$Configuration\tools\KnLiveDbgHuntTargetDll.dll"
)

$optionalFiles = @(
    "x64\$Configuration\KnLiveDbg.pdb",
    "x64\$Configuration\KnLiveDbg.cer",
    "x64\$Configuration\KnLiveDbgProbe.pdb",
    "x64\$Configuration\KnLiveDbgProbe.cer",
    "x64\$Configuration\amdryzenmasterdriver.sys",
    "x64\$Configuration\amdryzenmasterdriver.pdb",
    "x64\$Configuration\amdryzenmasterdriver.cer",
    "x64\$Configuration\tools\KnLiveDbgHuntTarget.pdb",
    "x64\$Configuration\tools\KnLiveDbgHuntTargetDll.pdb",
    "x64\$Configuration\tools\KnLiveDbgHuntTargetDll.exp",
    "x64\$Configuration\tools\KnLiveDbgHuntTargetDll.lib"
)

foreach ($relativePath in $requiredFiles)
{
    Copy-RelativeFile -RootPath $rootPath -StagePath $stageRoot -RelativePath $relativePath -Entries $entries -Required
}
foreach ($relativePath in $optionalFiles)
{
    Copy-RelativeFile -RootPath $rootPath -StagePath $stageRoot -RelativePath $relativePath -Entries $entries
}

$gitCommit = Invoke-GitText -RootPath $rootPath -Arguments @("rev-parse", "HEAD")
$gitStatus = Invoke-GitText -RootPath $rootPath -Arguments @("status", "--short")
$bundleInfo = [ordered]@{
    schema = "kn-live-dbg.eset-hunt-e2e-vm-bundle.v1"
    bundle_contract = $bundleContract
    runner_contract = $runnerContract
    created_utc = [DateTime]::UtcNow.ToString("o")
    source_root = $rootPath
    configuration = $Configuration
    git_commit = $gitCommit
    git_status_short = @($gitStatus -split "`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    recommended_vm_command = "powershell -ExecutionPolicy Bypass -File .\tools\run-eset-hunt-e2e.ps1 -Seconds 300 -KnLiveDbgTimeoutSeconds 180 -TargetLifetimePaddingSeconds 60"
    expected_startup_needles = @(
        "runner_contract=$runnerContract",
        "elevated=True",
        "target ready scenarios=35",
        "run KnLiveDbg scripted hunt",
        "passed"
    )
    files = @($entries)
}

$bundleInfoPath = Join-Path $stageRoot "BUNDLE-INFO.json"
$bundleInfo | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $bundleInfoPath -Encoding UTF8
$bundleInfoItem = Get-Item -LiteralPath $bundleInfoPath
$bundleInfoHash = Get-FileHash -Algorithm SHA256 -LiteralPath $bundleInfoPath
$entries.Add([ordered]@{
    path = "BUNDLE-INFO.json"
    size = $bundleInfoItem.Length
    sha256 = $bundleInfoHash.Hash
}) | Out-Null

if (-not $SkipReadiness)
{
    & (Join-Path $stageRoot "tools\validate-eset-hunt-iocs.ps1") -Root $stageRoot
    if ($LASTEXITCODE -ne 0)
    {
        throw "staged ESET IOC validation failed with exit code $LASTEXITCODE"
    }

    & (Join-Path $stageRoot "tools\validate-hunt-readiness.ps1") -Root $stageRoot -SkipSmoke
    if ($LASTEXITCODE -ne 0)
    {
        throw "staged hunt readiness validation failed with exit code $LASTEXITCODE"
    }
}

New-ZipFromDirectory -SourceDir $stageRoot -ZipPath $zipPath
$zipHash = Get-FileHash -Algorithm SHA256 -LiteralPath $zipPath

Write-Host "[eset-hunt-bundle] bundle_contract=$bundleContract runner_contract=$runnerContract"
Write-Host "[eset-hunt-bundle] stage_root=$stageRoot"
Write-Host "[eset-hunt-bundle] zip=$zipPath"
Write-Host "[eset-hunt-bundle] sha256=$($zipHash.Hash)"
Write-Host "[eset-hunt-bundle] payload_files=$(@($bundleInfo.files).Count) total_files=$($entries.Count)"
