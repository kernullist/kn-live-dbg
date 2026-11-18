param(
    [string]$BridgePath = ""
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($BridgePath))
{
    $BridgePath = Join-Path $repoRoot "tools\mcp-bridge.ps1"
}
$BridgePath = (Resolve-Path -LiteralPath $BridgePath).Path

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ("knlivedbg-mcp-bridge-{0}" -f [Guid]::NewGuid().ToString("N"))
$endpointPath = Join-Path $testRoot "mcp-endpoint.json"
$capturePath = Join-Path $testRoot "npx-args.txt"
$fakeNpxPath = Join-Path $testRoot "npx.cmd"
$remoteStdoutPath = Join-Path $testRoot "remote-stdout.txt"
$remoteStderrPath = Join-Path $testRoot "remote-stderr.txt"
$oldPath = $env:PATH
$oldCapture = $env:KNLIVEDBG_BRIDGE_CAPTURE
$oldBearer = $env:KNLIVEDBG_TOKEN

try
{
    New-Item -ItemType Directory -Path $testRoot | Out-Null
    @"
{
  "schema": "kn-live-dbg.mcp-endpoint.v1",
  "url": "http://127.0.0.1:51766/mcp",
  "remote_url": "",
  "client_url": "http://127.0.0.1:51766/mcp",
  "token": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "token_source": "new",
  "port": 51766,
  "write": false
}
"@ | Set-Content -LiteralPath $endpointPath -Encoding UTF8

    @"
@echo off
echo %* > "%KNLIVEDBG_BRIDGE_CAPTURE%"
exit /b 0
"@ | Set-Content -LiteralPath $fakeNpxPath -Encoding ASCII

    $env:PATH = "$testRoot;$oldPath"
    $env:KNLIVEDBG_BRIDGE_CAPTURE = $capturePath

    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $BridgePath -EndpointPath $endpointPath
    if ($LASTEXITCODE -ne 0)
    {
        throw "MCP bridge exited with code $LASTEXITCODE"
    }
    if (-not (Test-Path -LiteralPath $capturePath))
    {
        throw "fake npx did not capture bridge arguments"
    }

    $captured = Get-Content -LiteralPath $capturePath -Raw
    $required = @(
        "-y mcp-remote@0.1.38",
        "http://127.0.0.1:51766/mcp",
        "--allow-http",
        "--transport http-only",
        "--silent",
        "--header",
        "Authorization: Bearer 0123456789abcdef"
    )
    foreach ($needle in $required)
    {
        if ($captured -notlike ("*{0}*" -f $needle))
        {
            throw "bridge argument missing: $needle`ncaptured: $captured"
        }
    }

    $wildcardJson = Get-Content -LiteralPath $endpointPath -Raw
    $wildcardJson = $wildcardJson.Replace(
        '"remote_url": "",',
        '"remote_url": "http://<this-host-ip>:51766/mcp",')
    $wildcardJson = $wildcardJson.Replace(
        '"client_url": "http://127.0.0.1:51766/mcp",',
        '"client_url": "http://<this-host-ip>:51766/mcp",')
    Set-Content -LiteralPath $endpointPath -Value $wildcardJson -Encoding UTF8

    $remoteProcess = Start-Process -FilePath powershell.exe -ArgumentList @(
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        ('"{0}"' -f $BridgePath),
        "-EndpointPath",
        ('"{0}"' -f $endpointPath),
        "-PreferRemote"
    ) -Wait -PassThru -NoNewWindow -RedirectStandardOutput $remoteStdoutPath -RedirectStandardError $remoteStderrPath
    if ($remoteProcess.ExitCode -eq 0)
    {
        throw "wildcard remote endpoint was accepted as a concrete URL"
    }

    @"
{
  "schema": "kn-live-dbg.mcp-endpoint.v1",
  "url": "http://127.0.0.1:51766/mcp",
  "remote_url": "http://<this-host-ip>:51766/mcp",
  "client_url": "http://<this-host-ip>:51766/mcp",
  "password": "lab1",
  "token": "lab1",
  "listen_ips": ["127.0.0.1", "192.0.2.10"],
  "token_source": "password",
  "port": 51766,
  "write": false
}
"@ | Set-Content -LiteralPath $endpointPath -Encoding UTF8
    Remove-Item -LiteralPath $capturePath -ErrorAction SilentlyContinue

    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $BridgePath -EndpointPath $endpointPath -PreferRemote
    if ($LASTEXITCODE -ne 0)
    {
        throw "MCP bridge with listen_ips exited with code $LASTEXITCODE"
    }
    $capturedListen = Get-Content -LiteralPath $capturePath -Raw
    if ($capturedListen -notlike "*http://192.0.2.10:51766/mcp*")
    {
        throw "bridge did not use listen_ips LAN address`ncaptured: $capturedListen"
    }
    if ($capturedListen -notlike "*Authorization: Bearer lab1*")
    {
        throw "bridge did not use session password`ncaptured: $capturedListen"
    }

    $principalEndpoint = Get-Content -LiteralPath $endpointPath -Raw | ConvertFrom-Json
    $principalEndpoint.token_source = 'principal'
    $principalEndpoint | ConvertTo-Json | Set-Content -LiteralPath $endpointPath -Encoding UTF8
    $env:KNLIVEDBG_TOKEN = [Guid]::NewGuid().ToString('N') + [Guid]::NewGuid().ToString('N')
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $BridgePath -EndpointPath $endpointPath
    $captured = Get-Content -LiteralPath $capturePath -Raw
    if ($LASTEXITCODE -ne 0 -or !$captured.Contains('Authorization:${KNLIVEDBG_BRIDGE_AUTH}') -or
        $captured.Contains($env:KNLIVEDBG_TOKEN) -or $captured.Contains('lab1'))
    {
        throw 'Source-scoped bridge exposed or selected the wrong credential argument.'
    }
    foreach ($case in 'remote', 'missing-bearer', 'foreign-url')
    {
        $bridgeArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $BridgePath), '-EndpointPath', ('"{0}"' -f $endpointPath))
        if ($case -eq 'remote') { $bridgeArgs += '-PreferRemote' }
        if ($case -eq 'missing-bearer') { $env:KNLIVEDBG_TOKEN = $null }
        if ($case -eq 'foreign-url')
        {
            $env:KNLIVEDBG_TOKEN = 'a' * 64
            $principalEndpoint.url = 'http://192.0.2.10:51766/mcp'
            $principalEndpoint | ConvertTo-Json | Set-Content -LiteralPath $endpointPath -Encoding UTF8
        }
        Remove-Item -LiteralPath $capturePath -ErrorAction SilentlyContinue
        $denied = Start-Process powershell.exe -ArgumentList $bridgeArgs -Wait -PassThru -NoNewWindow -RedirectStandardOutput $remoteStdoutPath -RedirectStandardError $remoteStderrPath
        if ($denied.ExitCode -eq 0 -or (Test-Path -LiteralPath $capturePath)) { throw "Scoped bridge accepted $case" }
    }
    Write-Host "[mcp.bridge.selftest] PASS pinned HTTP-only arguments, wildcard-remote rejection, listen_ips, source-scoped credentials"
}
finally
{
    $env:PATH = $oldPath
    $env:KNLIVEDBG_BRIDGE_CAPTURE = $oldCapture
    $env:KNLIVEDBG_TOKEN = $oldBearer
    if (Test-Path -LiteralPath $testRoot)
    {
        $resolvedTest = (Resolve-Path -LiteralPath $testRoot).Path
        $resolvedTemp = (Resolve-Path -LiteralPath ([IO.Path]::GetTempPath())).Path.TrimEnd('\')
        if ([IO.Path]::GetDirectoryName($resolvedTest) -ne $resolvedTemp -or
            [IO.Path]::GetFileName($resolvedTest) -notmatch '^knlivedbg-mcp-bridge-[0-9a-f]{32}$') { throw 'Unexpected bridge fixture path' }
        Remove-Item -LiteralPath $resolvedTest -Recurse -Force
    }
}
