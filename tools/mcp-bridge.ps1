# KnLiveDbg MCP stdio bridge.
#
# Register this script ONCE in Claude Code / Cursor / Codex / Grok Build.
# On every connect it reads the live endpoint file written by `mcp on` and
# attaches with the current bearer token -- no per-session token paste.
#
# Prerequisite: KnLiveDbg is running with `mcp on`.
#
# One-time registration examples are printed by:
#   knkd> mcp client-setup

[CmdletBinding()]
param(
    [string]$EndpointPath = "",
    [switch]$PreferRemote,
    [switch]$PrintEndpoint
)

$ErrorActionPreference = "Stop"

# Keep npm/npx quiet so package-manager chatter cannot corrupt MCP stdio JSON-RPC
# on stdout. stderr is fine for diagnostics.
$env:npm_config_loglevel = "error"
$env:npm_config_fund = "false"
$env:npm_config_update_notifier = "false"
$env:NPM_CONFIG_UPDATE_NOTIFIER = "false"

function Resolve-EndpointPath
{
    param([string]$Explicit)

    if (-not [string]::IsNullOrWhiteSpace($Explicit))
    {
        return $Explicit
    }
    if (-not [string]::IsNullOrWhiteSpace($env:KNLIVEDBG_MCP_ENDPOINT))
    {
        return $env:KNLIVEDBG_MCP_ENDPOINT
    }

    $candidates = @()
    if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA))
    {
        $candidates += (Join-Path $env:LOCALAPPDATA "kn-live-dbg\mcp-endpoint.json")
    }

    $scriptDir = Split-Path -Parent $PSCommandPath
    $candidates += (Join-Path $scriptDir "mcp-endpoint.json")
    $candidates += (Join-Path $scriptDir "..\x64\Release\.kn-live-dbg\mcp-endpoint.json")
    $candidates += (Join-Path $scriptDir "..\.kn-live-dbg\mcp-endpoint.json")
    $candidates += (Join-Path (Get-Location) ".kn-live-dbg\mcp-endpoint.json")

    foreach ($path in $candidates)
    {
        if (Test-Path -LiteralPath $path)
        {
            return (Resolve-Path -LiteralPath $path).Path
        }
    }

    if ($candidates.Count -gt 0)
    {
        return $candidates[0]
    }
    return ""
}

function Get-JsonStringProperty
{
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $Object)
    {
        return ""
    }

    $prop = $Object.PSObject.Properties[$Name]
    if ($null -eq $prop -or $null -eq $prop.Value)
    {
        return ""
    }
    return [string]$prop.Value
}

$endpointPath = Resolve-EndpointPath -Explicit $EndpointPath
if ([string]::IsNullOrWhiteSpace($endpointPath) -or -not (Test-Path -LiteralPath $endpointPath))
{
    throw @"
KnLiveDbg MCP endpoint file not found: $endpointPath

Start the server first on the analysis machine:
  knkd> mcp on

Then reconnect this bridge. The endpoint file is written automatically by mcp on.
"@
}

try
{
    $raw = Get-Content -LiteralPath $endpointPath -Raw -Encoding UTF8
    $endpoint = $raw | ConvertFrom-Json
}
catch
{
    throw "Failed to parse MCP endpoint file '$endpointPath': $($_.Exception.Message)"
}

$token = (Get-JsonStringProperty -Object $endpoint -Name "token").Trim()
$loopUrl = (Get-JsonStringProperty -Object $endpoint -Name "url").Trim()
$remoteUrl = (Get-JsonStringProperty -Object $endpoint -Name "remote_url").Trim()
$clientUrl = (Get-JsonStringProperty -Object $endpoint -Name "client_url").Trim()
$tokenSource = (Get-JsonStringProperty -Object $endpoint -Name "token_source").Trim()
$port = Get-JsonStringProperty -Object $endpoint -Name "port"
$write = Get-JsonStringProperty -Object $endpoint -Name "write"

if ([string]::IsNullOrWhiteSpace($token) -or $token.Length -lt 16)
{
    throw "Invalid MCP endpoint token in '$endpointPath' (empty or too short)."
}

# Prefer loopback for same-box agents. Use remote only when requested or when
# loopback url is missing and client_url/remote_url is set.
$url = $loopUrl
if ($PreferRemote)
{
    if (-not [string]::IsNullOrWhiteSpace($remoteUrl) -and $remoteUrl -notlike "*<this-host-ip>*")
    {
        $url = $remoteUrl
    }
    elseif (-not [string]::IsNullOrWhiteSpace($clientUrl) -and $clientUrl -notlike "*127.0.0.1*" -and $clientUrl -notlike "*localhost*")
    {
        $url = $clientUrl
    }
}
if ([string]::IsNullOrWhiteSpace($url))
{
    $url = $clientUrl
}
if ([string]::IsNullOrWhiteSpace($url))
{
    throw "Invalid MCP endpoint file (missing url): $endpointPath"
}

if ($PrintEndpoint)
{
    # Diagnostic mode only -- never used as the MCP stdio entrypoint by agents.
    Write-Output ("url={0}" -f $url)
    Write-Output ("token_source={0}" -f $tokenSource)
    Write-Output ("port={0}" -f $port)
    Write-Output ("write={0}" -f $write)
    Write-Output ("path={0}" -f $endpointPath)
    exit 0
}

$header = "Authorization: Bearer $token"

$npx = Get-Command npx.cmd -ErrorAction SilentlyContinue
if (-not $npx)
{
    $npx = Get-Command npx -ErrorAction SilentlyContinue
}
if (-not $npx)
{
    throw @"
npx was not found on PATH. Install Node.js LTS, then reconnect.

Endpoint is ready at:
  $url
  endpoint file: $endpointPath

Grok Build can also use native HTTP (see 'mcp client-setup grok') without npx.
"@
}

$npxPath = $npx.Source
if ([string]::IsNullOrWhiteSpace($npxPath))
{
    $npxPath = $npx.Path
}

# mcp-remote: stdio JSON-RPC <-> Streamable HTTP. Inherit stdin/stdout for MCP.
& $npxPath -y mcp-remote $url --header $header
exit $LASTEXITCODE
