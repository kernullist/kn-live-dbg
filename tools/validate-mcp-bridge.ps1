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
        $BridgePath,
        "-EndpointPath",
        $endpointPath,
        "-PreferRemote"
    ) -Wait -PassThru -NoNewWindow -RedirectStandardOutput $remoteStdoutPath -RedirectStandardError $remoteStderrPath
    if ($remoteProcess.ExitCode -eq 0)
    {
        throw "wildcard remote endpoint was accepted as a concrete URL"
    }

    Write-Host "[mcp.bridge.selftest] PASS pinned HTTP-only arguments and wildcard-remote rejection"
}
finally
{
    $env:PATH = $oldPath
    $env:KNLIVEDBG_BRIDGE_CAPTURE = $oldCapture
    if (Test-Path -LiteralPath $testRoot)
    {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}
