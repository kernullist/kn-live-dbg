param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"

$repo = Resolve-Path (Join-Path $PSScriptRoot "..")
$solution = Join-Path $repo "kn-live-dbg.sln"
$msbuild = "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe"
$exePath = Join-Path $repo "x64\$Configuration\KnLiveDbg.exe"
$sysPath = Join-Path $repo "x64\$Configuration\KnLiveDbg.sys"
$probeSysPath = Join-Path $repo "x64\$Configuration\KnLiveDbgProbe.sys"
$outputDir = Join-Path $repo "x64\$Configuration"
$vendorDebuggersDir = Join-Path $repo "vendor\debugging-tools\x64"
$debuggersDir = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64"

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
            Write-Warning "Debugging Tools runtime file was not found: $source"
            continue
        }

        Copy-Item -LiteralPath $source -Destination $DestinationDir -Force
        Write-Host "Runtime: copied $name"
    }

    $destinationSymsrv = Join-Path $DestinationDir "symsrv.dll"
    $destinationConsent = Join-Path $DestinationDir "symsrv.yes"
    if ((Test-Path $destinationSymsrv) -and -not (Test-Path $destinationConsent))
    {
        [System.IO.File]::WriteAllBytes($destinationConsent, [byte[]](0x20))
        Write-Host "Runtime: created symsrv.yes"
    }
}

if (-not (Test-Path $msbuild))
{
    throw "MSBuild was not found at $msbuild"
}

& $msbuild $solution /m /p:Configuration=$Configuration /p:Platform=x64 /v:minimal

if ($LASTEXITCODE -ne 0)
{
    exit $LASTEXITCODE
}

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

Write-Host "EXE: $exePath"
Write-Host "SYS: $sysPath"
Write-Host "PROBE SYS: $probeSysPath"
