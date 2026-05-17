param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"

$repo = Resolve-Path (Join-Path $PSScriptRoot "..")
$solution = Join-Path $repo "kn-live-dbg.sln"
$msbuild = "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe"

if (-not (Test-Path $msbuild))
{
    throw "MSBuild was not found at $msbuild"
}

& $msbuild $solution /m /p:Configuration=$Configuration /p:Platform=x64 /v:minimal

if ($LASTEXITCODE -ne 0)
{
    exit $LASTEXITCODE
}

Write-Host "EXE: $(Join-Path $repo "x64\$Configuration\KnLiveDbg.exe")"
Write-Host "SYS: $(Join-Path $repo "x64\$Configuration\KnLiveDbg.sys")"
