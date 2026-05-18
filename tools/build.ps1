param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"

$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$solution = Join-Path $repo "kn-live-dbg.sln"
$msbuild = "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe"
$exePath = Join-Path $repo "x64\$Configuration\KnLiveDbg.exe"
$sysPath = Join-Path $repo "x64\$Configuration\KnLiveDbg.sys"
$probeSysPath = Join-Path $repo "x64\$Configuration\KnLiveDbgProbe.sys"
$outputDir = Join-Path $repo "x64\$Configuration"
$vendorDebuggersDir = Join-Path $repo "vendor\debugging-tools\x64"
$debuggersDir = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64"
$stateDir = Join-Path $repo ".build"
$statePath = Join-Path $stateDir "version-state.json"
$generatedDir = Join-Path $stateDir "generated"
$versionHeaderPath = Join-Path $generatedDir "KnLiveDbgVersion.h"

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

function Get-BaselineVersion
{
    if (Test-Path $statePath)
    {
        $state = Get-Content $statePath -Raw | ConvertFrom-Json
        if ($state.current_version)
        {
            return [string]$state.current_version
        }
    }

    if (Test-Path $exePath)
    {
        $fileVersion = (Get-Item -LiteralPath $exePath).VersionInfo.FileVersion
        if (-not [string]::IsNullOrWhiteSpace($fileVersion))
        {
            return [string]$fileVersion
        }
    }

    return "0.0.0"
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

function Copy-DebuggingToolsRuntime
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourceDir,
        [Parameter(Mandatory = $true)]
        [string]$DestinationDir
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
            $fallback = Join-Path $debuggersDir $name
            if ($SourceDir -ne $debuggersDir -and (Test-Path $fallback))
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

if (-not (Test-Path $msbuild))
{
    throw "MSBuild was not found at $msbuild"
}

$baselineVersion = Get-BaselineVersion
$nextParts = Increment-Version -Parts (Parse-VersionParts -VersionText $baselineVersion)
$nextVersion = Format-Version -Parts $nextParts
Write-VersionHeader -Parts $nextParts
Write-Host "PE version: $baselineVersion -> $nextVersion"

& $msbuild $solution /m /p:Configuration=$Configuration /p:Platform=x64 /v:minimal

if ($LASTEXITCODE -ne 0)
{
    exit $LASTEXITCODE
}

Assert-PEVersion -Path $exePath -Parts $nextParts
Assert-PEVersion -Path $sysPath -Parts $nextParts
Assert-PEVersion -Path $probeSysPath -Parts $nextParts

Assert-DriverSignature -Path $sysPath
Assert-DriverSignature -Path $probeSysPath

$runtimeSourceDir = $vendorDebuggersDir
if (-not (Test-Path (Join-Path $runtimeSourceDir "dbghelp.dll")) -or
    -not (Test-Path (Join-Path $runtimeSourceDir "symsrv.dll")))
{
    Write-Warning "Vendor Debugging Tools runtime is incomplete; falling back to installed Windows Kits runtime"
    $runtimeSourceDir = $debuggersDir
}

Write-Host "Runtime source: $runtimeSourceDir"
Copy-DebuggingToolsRuntime -SourceDir $runtimeSourceDir -DestinationDir $outputDir

Save-VersionState -Version $nextVersion

Write-Host "EXE: $exePath"
Write-Host "SYS: $sysPath"
Write-Host "PROBE SYS: $probeSysPath"
Write-Host "Version state: $statePath"
