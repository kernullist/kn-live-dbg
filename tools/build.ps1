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

    Write-Host "SYS signature: $($signature.Status) signer-thumbprint=$($signature.SignerCertificate.Thumbprint)"
    if ($signature.Status -ne "Valid")
    {
        Write-Host "SYS signature trust: $($signature.Status)"
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

Write-Host "EXE: $exePath"
Write-Host "SYS: $sysPath"
