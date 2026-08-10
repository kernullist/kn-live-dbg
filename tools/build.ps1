param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    [switch]$BumpVersion
)

$ErrorActionPreference = "Stop"

$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$solution = Join-Path $repo "kn-live-dbg.sln"
$exePath = Join-Path $repo "x64\$Configuration\KnLiveDbg.exe"
$sysPath = Join-Path $repo "x64\$Configuration\KnLiveDbg.sys"
$probeSysPath = Join-Path $repo "x64\$Configuration\KnLiveDbgProbe.sys"
$byovdFixtureSysPath = Join-Path $repo "x64\$Configuration\amdryzenmasterdriver.sys"
$minifilterFixtureSysPath = Join-Path $repo "x64\$Configuration\KnLiveDbgMiniFilterFixture.sys"
$bindFixtureExePath = Join-Path $repo "x64\$Configuration\KnLiveDbgBindFixture.exe"
$outputDir = Join-Path $repo "x64\$Configuration"
$vendorDebuggersDir = Join-Path $repo "vendor\debugging-tools\x64"
$stateDir = Join-Path $repo ".build"
$statePath = Join-Path $stateDir "version-state.json"
$generatedDir = Join-Path $stateDir "generated"
$versionHeaderPath = Join-Path $generatedDir "KnLiveDbgVersion.h"

function Get-VsWherePath
{
    $paths = @(
        (Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"),
        (Join-Path $env:ProgramFiles "Microsoft Visual Studio\Installer\vswhere.exe")
    )

    foreach ($path in $paths)
    {
        if (-not [string]::IsNullOrWhiteSpace($path) -and (Test-Path $path))
        {
            return $path
        }
    }

    return $null
}

function Get-VisualStudioInstallations
{
    $installations = [System.Collections.Generic.List[string]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $vswhere = Get-VsWherePath

    if (-not [string]::IsNullOrWhiteSpace($vswhere))
    {
        $json = & $vswhere -products * -requires Microsoft.Component.MSBuild -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -sort -format json
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($json))
        {
            $instances = $json | ConvertFrom-Json
            foreach ($instance in $instances)
            {
                $path = [string]$instance.installationPath
                if (-not [string]::IsNullOrWhiteSpace($path) -and (Test-Path $path))
                {
                    $resolved = (Resolve-Path $path).Path
                    if ($seen.Add($resolved))
                    {
                        $installations.Add($resolved)
                    }
                }
            }
        }
    }

    $roots = @(
        (Join-Path $env:ProgramFiles "Microsoft Visual Studio"),
        (Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio")
    )

    foreach ($root in $roots)
    {
        if ([string]::IsNullOrWhiteSpace($root) -or -not (Test-Path $root))
        {
            continue
        }

        $paths = Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending |
            ForEach-Object {
                Get-ChildItem -LiteralPath $_.FullName -Directory -ErrorAction SilentlyContinue |
                    Sort-Object Name
            }

        foreach ($path in $paths)
        {
            if (Test-Path (Join-Path $path.FullName "MSBuild"))
            {
                $resolved = (Resolve-Path $path.FullName).Path
                if ($seen.Add($resolved))
                {
                    $installations.Add($resolved)
                }
            }
        }
    }

    return $installations
}

function Find-MSBuild
{
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$VisualStudioInstallations
    )

    foreach ($installation in $VisualStudioInstallations)
    {
        $candidates = @(
            (Join-Path $installation "MSBuild\Current\Bin\MSBuild.exe"),
            (Join-Path $installation "MSBuild\15.0\Bin\MSBuild.exe")
        )

        foreach ($candidate in $candidates)
        {
            if (Test-Path $candidate)
            {
                return (Resolve-Path $candidate).Path
            }
        }
    }

    throw "MSBuild was not found in installed Visual Studio instances"
}

function Find-DiaSdk
{
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$VisualStudioInstallations
    )

    foreach ($installation in $VisualStudioInstallations)
    {
        $diaRoot = Join-Path $installation "DIA SDK"
        $include = Join-Path $diaRoot "include\dia2.h"
        $library = Join-Path $diaRoot "lib\amd64\diaguids.lib"
        if ((Test-Path $include) -and (Test-Path $library))
        {
            return (Resolve-Path $diaRoot).Path
        }
    }

    throw "DIA SDK was not found. Install the Visual Studio C++ DIA SDK component."
}

function Find-DebuggingToolsDir
{
    $roots = @(
        (Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\Debuggers\x64"),
        (Join-Path $env:ProgramFiles "Windows Kits\10\Debuggers\x64")
    )

    foreach ($root in $roots)
    {
        if ((Test-Path (Join-Path $root "dbghelp.dll")) -and
            (Test-Path (Join-Path $root "symsrv.dll")))
        {
            return (Resolve-Path $root).Path
        }
    }

    return $null
}

function Find-DebuggingToolsBuildLayout
{
    param(
        [string]$DebuggersDir
    )

    if (-not [string]::IsNullOrWhiteSpace($DebuggersDir))
    {
        $debuggersRoot = Split-Path -Parent $DebuggersDir
        $includeDir = Join-Path $debuggersRoot "inc"
        $libDir = Join-Path $debuggersRoot "lib\x64"
        if ((Test-Path (Join-Path $includeDir "DbgEng.h")) -and
            (Test-Path (Join-Path $libDir "DbgEng.Lib")))
        {
            return [pscustomobject]@{
                IncludeDir = $includeDir
                LibDir = $libDir
            }
        }
    }

    $kitRoots = @(
        (Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10"),
        (Join-Path $env:ProgramFiles "Windows Kits\10")
    )

    foreach ($kitRoot in $kitRoots)
    {
        $includeRoot = Join-Path $kitRoot "Include"
        if (-not (Test-Path $includeRoot))
        {
            continue
        }

        $versions = Get-ChildItem -LiteralPath $includeRoot -Directory -ErrorAction SilentlyContinue |
            Sort-Object { [version]$_.Name } -Descending
        foreach ($version in $versions)
        {
            $includeDir = Join-Path $version.FullName "um"
            $libDir = Join-Path $kitRoot ("Lib\{0}\um\x64" -f $version.Name)
            if ((Test-Path (Join-Path $includeDir "DbgEng.h")) -and
                (Test-Path (Join-Path $libDir "DbgEng.Lib")))
            {
                return [pscustomobject]@{
                    IncludeDir = $includeDir
                    LibDir = $libDir
                }
            }
        }
    }

    throw "DbgEng headers and x64 import library were not found in the Windows SDK"
}

function Parse-VersionParts
{
    param(
        [string]$VersionText
    )

    if ([string]::IsNullOrWhiteSpace($VersionText))
    {
        return @(0, 0, 0)
    }

    $normalized = ($VersionText.Trim() -replace "\s.*$", "")
    $parts = $normalized.Split(".")
    if ($parts.Length -lt 3 -or $parts.Length -gt 4)
    {
        throw "Invalid version format: $VersionText"
    }

    $result = @()
    for ($index = 0; $index -lt 3; $index++)
    {
        [int]$value = 0
        if (-not [int]::TryParse($parts[$index], [ref]$value))
        {
            throw "Invalid version segment '$($parts[$index])' in $VersionText"
        }

        if ($value -lt 0 -or $value -gt 65535)
        {
            throw "Version segment is outside PE range: $value"
        }

        $result += $value
    }

    return $result
}

function Format-Version
{
    param(
        [Parameter(Mandatory = $true)]
        [int[]]$Parts
    )

    return ("{0}.{1}.{2}" -f $Parts[0], $Parts[1], $Parts[2])
}

function Increment-Version
{
    param(
        [Parameter(Mandatory = $true)]
        [int[]]$Parts
    )

    $next = @($Parts[0], $Parts[1], $Parts[2])
    $next[2]++
    if ($next[2] -gt 65535)
    {
        $next[2] = 0
        $next[1]++
        if ($next[1] -gt 65535)
        {
            $next[1] = 0
            $next[0]++
            if ($next[0] -gt 65535)
            {
                throw "PE version range exhausted"
            }
        }
    }

    return $next
}

function Add-VersionCandidate
{
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$Candidates,
        [Parameter(Mandatory = $true)]
        [string]$VersionText,
        [Parameter(Mandatory = $true)]
        [string]$Source
    )

    $parts = Parse-VersionParts -VersionText $VersionText
    $score =
        ([Convert]::ToUInt64($parts[0]) * 4294967296) +
        ([Convert]::ToUInt64($parts[1]) * 65536) +
        [Convert]::ToUInt64($parts[2])
    $Candidates.Add([pscustomobject]@{
        version = Format-Version -Parts $parts
        source  = $Source
        score   = $score
    }) | Out-Null
}

function Get-BaselineVersion
{
    $candidates = [System.Collections.Generic.List[object]]::new()

    if (Test-Path $statePath)
    {
        $state = Get-Content $statePath -Raw | ConvertFrom-Json
        if ($state.current_version)
        {
            Add-VersionCandidate `
                -Candidates $candidates `
                -VersionText ([string]$state.current_version) `
                -Source "version state"
        }
    }

    if (Test-Path $exePath)
    {
        $fileVersion = (Get-Item -LiteralPath $exePath).VersionInfo.FileVersion
        if (-not [string]::IsNullOrWhiteSpace($fileVersion))
        {
            Add-VersionCandidate `
                -Candidates $candidates `
                -VersionText ([string]$fileVersion) `
                -Source "existing PE"
        }
    }

    $gitCommand = Get-Command git -ErrorAction SilentlyContinue
    if ($null -ne $gitCommand)
    {
        $reachableTags =
            & $gitCommand.Source `
                -C $repo `
                tag `
                --merged HEAD `
                --list "v[0-9]*" 2>$null
        if ($LASTEXITCODE -eq 0)
        {
            foreach ($tag in @($reachableTags))
            {
                if ([string]$tag -match '^v([0-9]+\.[0-9]+\.[0-9]+)$')
                {
                    Add-VersionCandidate `
                        -Candidates $candidates `
                        -VersionText $Matches[1] `
                        -Source "reachable Git tag $tag"
                }
            }
        }
    }

    if ($candidates.Count -eq 0)
    {
        return "0.0.0"
    }

    $baseline = $candidates | Sort-Object score -Descending | Select-Object -First 1
    Write-Host "PE version baseline: $($baseline.version) ($($baseline.source))"
    return [string]$baseline.version
}

function Write-VersionHeader
{
    param(
        [Parameter(Mandatory = $true)]
        [int[]]$Parts
    )

    New-Item -ItemType Directory -Force -Path $generatedDir | Out-Null

    $versionText = Format-Version -Parts $Parts
    $lines = @(
        "#pragma once",
        "",
        "#define KN_LIVE_DBG_VERSION_MAJOR $($Parts[0])",
        "#define KN_LIVE_DBG_VERSION_MINOR $($Parts[1])",
        "#define KN_LIVE_DBG_VERSION_PATCH $($Parts[2])",
        "#define KN_LIVE_DBG_VERSION_BUILD 0",
        "#define KN_LIVE_DBG_VERSION_TEXT ""$versionText"""
    )

    Set-Content -LiteralPath $versionHeaderPath -Value $lines -Encoding ascii
}

function Assert-PEVersion
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [int[]]$Parts
    )

    if (-not (Test-Path $Path))
    {
        throw "PE output was not found: $Path"
    }

    $fileVersion = (Get-Item -LiteralPath $Path).VersionInfo.FileVersion
    $fileParts = Parse-VersionParts -VersionText $fileVersion
    if ($fileParts[0] -ne $Parts[0] -or $fileParts[1] -ne $Parts[1] -or $fileParts[2] -ne $Parts[2])
    {
        throw "PE version mismatch for $Path. expected=$(Format-Version -Parts $Parts) actual=$fileVersion"
    }

    $name = Split-Path -Path $Path -Leaf
    Write-Host "$name PE version: $fileVersion"
}

function Save-VersionState
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Version
    )

    New-Item -ItemType Directory -Force -Path $stateDir | Out-Null

    $state = [pscustomobject]@{
        current_version = $Version
        updated_at      = (Get-Date).ToString("o")
    }
    $state | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding ascii
}

function Assert-DriverSignature
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path $Path))
    {
        throw "Driver output was not found: $Path"
    }

    $signature = Get-AuthenticodeSignature -FilePath $Path
    if ($null -eq $signature.SignerCertificate)
    {
        throw "Driver test signing failed: signer certificate was not found"
    }

    if ($signature.Status -eq "NotSigned" -or $signature.Status -eq "HashMismatch")
    {
        throw "Driver test signing failed: status=$($signature.Status)"
    }

    $name = Split-Path -Path $Path -Leaf
    Write-Host "$name signature: $($signature.Status) signer-thumbprint=$($signature.SignerCertificate.Thumbprint)"
    if ($signature.Status -ne "Valid")
    {
        Write-Host "$name signature trust: $($signature.Status)"
    }
}

function Assert-ByovdFixtureMetadata
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path $Path))
    {
        throw "BYOVD fixture driver output was not found: $Path"
    }

    $item = Get-Item -LiteralPath $Path
    $fileVersion = [string]$item.VersionInfo.FileVersion
    $originalName = [string]$item.VersionInfo.OriginalFilename
    if ($fileVersion -ne "1.0.0.0" -and $fileVersion -ne "1.0.0")
    {
        throw "BYOVD fixture PE version mismatch for $Path. expected=1.0.0.0 actual=$fileVersion"
    }

    if ($originalName -ne "amdryzenmasterdriver.sys")
    {
        throw "BYOVD fixture original filename mismatch for $Path. actual=$originalName"
    }

    Write-Host "amdryzenmasterdriver.sys BYOVD fixture metadata: FileVersion=$fileVersion OriginalFilename=$originalName"
}

function Copy-DebuggingToolsRuntime
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourceDir,
        [Parameter(Mandatory = $true)]
        [string]$DestinationDir,
        [string]$FallbackDir
    )

    if (-not (Test-Path $SourceDir))
    {
        Write-Warning "Debugging Tools runtime directory was not found: $SourceDir"
        return
    }

    $runtimeFiles = @(
        "dbghelp.dll",
        "dbgeng.dll",
        "dbgcore.dll",
        "DbgModel.dll",
        "msdia140.dll",
        "symsrv.dll",
        "srcsrv.dll",
        "symsrv.yes"
    )

    foreach ($name in $runtimeFiles)
    {
        $source = Join-Path $SourceDir $name
        if (-not (Test-Path $source))
        {
            $fallback = $null
            if (-not [string]::IsNullOrWhiteSpace($FallbackDir))
            {
                $fallback = Join-Path $FallbackDir $name
            }

            if ($SourceDir -ne $FallbackDir -and
                -not [string]::IsNullOrWhiteSpace($fallback) -and
                (Test-Path $fallback))
            {
                $source = $fallback
                Write-Warning "Debugging Tools runtime file was not found in vendor source; using installed fallback: $name"
            }
            else
            {
                Write-Warning "Debugging Tools runtime file was not found: $source"
                continue
            }
        }

        Copy-Item -LiteralPath $source -Destination $DestinationDir -Force
        Write-Host "Runtime: copied $name"
    }

    $destinationSymsrv = Join-Path $DestinationDir "symsrv.dll"
    $destinationConsent = Join-Path $DestinationDir "symsrv.yes"
    if (Test-Path $destinationSymsrv)
    {
        Set-Content -LiteralPath $destinationConsent -Value "yes" -NoNewline -Encoding ascii
        Write-Host "Runtime: normalized symsrv.yes"
    }
}

function Copy-ByovdUpdaterScript
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$DestinationDir
    )

    $source = Join-Path $repo "tools\update-byovd-intel.ps1"
    if (-not (Test-Path $source))
    {
        Write-Warning "BYOVD updater script was not found: $source"
        return
    }

    $toolsDir = Join-Path $DestinationDir "tools"
    New-Item -ItemType Directory -Force -Path $toolsDir | Out-Null

    $destination = Join-Path $toolsDir "update-byovd-intel.ps1"
    Copy-Item -LiteralPath $source -Destination $destination -Force
    Write-Host "BYOVD: copied update-byovd-intel.ps1"
}

function Copy-McpBridgeScript
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$DestinationDir
    )

    $source = Join-Path $repo "tools\mcp-bridge.ps1"
    if (-not (Test-Path $source))
    {
        Write-Warning "MCP bridge script was not found: $source"
        return
    }

    $toolsDir = Join-Path $DestinationDir "tools"
    New-Item -ItemType Directory -Force -Path $toolsDir | Out-Null
    Copy-Item -LiteralPath $source -Destination (Join-Path $toolsDir "mcp-bridge.ps1") -Force
    Write-Host "MCP: copied mcp-bridge.ps1"
}

$visualStudioInstallations = Get-VisualStudioInstallations
if ($visualStudioInstallations.Count -eq 0)
{
    throw "No Visual Studio installation with MSBuild was found"
}

$msbuild = Find-MSBuild -VisualStudioInstallations $visualStudioInstallations
$diaSdkDir = Find-DiaSdk -VisualStudioInstallations $visualStudioInstallations
$debuggersDir = Find-DebuggingToolsDir
$debuggingToolsBuildLayout = Find-DebuggingToolsBuildLayout -DebuggersDir $debuggersDir
$diaIncludeDir = Join-Path $diaSdkDir "include"
$diaLibDir = Join-Path $diaSdkDir "lib\amd64"
$debuggersIncludeDir = $debuggingToolsBuildLayout.IncludeDir
$debuggersLibDir = $debuggingToolsBuildLayout.LibDir

Write-Host "MSBuild: $msbuild"
Write-Host "DIA SDK: $diaSdkDir"
Write-Host "DbgEng include: $debuggersIncludeDir"
Write-Host "DbgEng library: $debuggersLibDir"
if (-not [string]::IsNullOrWhiteSpace($debuggersDir))
{
    Write-Host "Installed Debugging Tools runtime: $debuggersDir"
}
else
{
    Write-Host "Installed Debugging Tools runtime: not found; using the bundled runtime"
}

$baselineVersion = Get-BaselineVersion
$versionParts = Parse-VersionParts -VersionText $baselineVersion
if ($BumpVersion)
{
    $versionParts = Increment-Version -Parts $versionParts
}
$buildVersion = Format-Version -Parts $versionParts
Write-VersionHeader -Parts $versionParts
if ($BumpVersion)
{
    Write-Host "PE version: $baselineVersion -> $buildVersion"
}
else
{
    Write-Host "PE version: $buildVersion"
}

$msbuildArgs = @(
    $solution,
    "/m",
    "/p:Configuration=$Configuration",
    "/p:Platform=x64",
    "/p:DiaSdkIncludeDir=$diaIncludeDir",
    "/p:DiaSdkLibDir=$diaLibDir",
    "/p:DebuggingToolsIncludeDir=$debuggersIncludeDir",
    "/p:DebuggingToolsLibDir=$debuggersLibDir",
    "/v:minimal"
)

& $msbuild @msbuildArgs

if ($LASTEXITCODE -ne 0)
{
    exit $LASTEXITCODE
}

Assert-PEVersion -Path $exePath -Parts $versionParts
Assert-PEVersion -Path $sysPath -Parts $versionParts
Assert-PEVersion -Path $probeSysPath -Parts $versionParts
Assert-PEVersion -Path $minifilterFixtureSysPath -Parts $versionParts
Assert-PEVersion -Path $bindFixtureExePath -Parts $versionParts
Assert-ByovdFixtureMetadata -Path $byovdFixtureSysPath

Assert-DriverSignature -Path $sysPath
Assert-DriverSignature -Path $probeSysPath
Assert-DriverSignature -Path $byovdFixtureSysPath
Assert-DriverSignature -Path $minifilterFixtureSysPath

$runtimeSourceDir = $vendorDebuggersDir
if (-not (Test-Path (Join-Path $runtimeSourceDir "dbghelp.dll")) -or
    -not (Test-Path (Join-Path $runtimeSourceDir "symsrv.dll")))
{
    if ([string]::IsNullOrWhiteSpace($debuggersDir))
    {
        throw "The bundled Debugging Tools runtime is incomplete and no installed runtime fallback was found"
    }

    Write-Warning "Vendor Debugging Tools runtime is incomplete; falling back to installed Windows Kits runtime"
    $runtimeSourceDir = $debuggersDir
}

Write-Host "Runtime source: $runtimeSourceDir"
Copy-DebuggingToolsRuntime -SourceDir $runtimeSourceDir -DestinationDir $outputDir -FallbackDir $debuggersDir
Copy-ByovdUpdaterScript -DestinationDir $outputDir
Copy-McpBridgeScript -DestinationDir $outputDir

if ($BumpVersion)
{
    Save-VersionState -Version $buildVersion
}

Write-Host "EXE: $exePath"
Write-Host "SYS: $sysPath"
Write-Host "PROBE SYS: $probeSysPath"
Write-Host "BYOVD FIXTURE SYS: $byovdFixtureSysPath"
Write-Host "MINIFILTER FIXTURE SYS: $minifilterFixtureSysPath"
Write-Host "BIND FIXTURE EXE: $bindFixtureExePath"
Write-Host "Version state: $statePath"
