param(
    [string]$Configuration = "Release",

    [string]$ExePath = ""
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")
if ([string]::IsNullOrWhiteSpace($ExePath))
{
    $ExePath = Join-Path $repoRoot ("x64\{0}\KnLiveDbg.exe" -f $Configuration)
}

if (-not (Test-Path -LiteralPath $ExePath))
{
    throw "KnLiveDbg.exe not found: $ExePath. Run tools\build.ps1 first."
}

Write-Host "[mcp.selftest] exe=$ExePath"
& $ExePath --self-test mcp-tools
if ($LASTEXITCODE -ne 0)
{
    throw "MCP tool catalog self-test failed with exit code $LASTEXITCODE"
}
