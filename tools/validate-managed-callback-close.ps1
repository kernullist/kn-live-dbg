param([switch]$BuildOnly)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
. (Join-Path $PSScriptRoot 'msvc-validation-environment.ps1')
$environment = Get-MsvcValidationEnvironment
$output = Join-Path $repo '.build\managed-close-selftest'
New-Item -ItemType Directory -Path $output -Force | Out-Null
$exe = Join-Path $output 'managed-callback-close-selftest.exe'
$sources = @((Join-Path $PSScriptRoot 'managed-callback-close-selftest.cpp'), (Join-Path $repo 'user\DeviceClient.cpp'))
$sourceArguments = ($sources | ForEach-Object { '"' + $_ + '"' }) -join ' '
$command = 'call "{0}" >nul && cl /nologo /std:c++17 /EHsc /W4 /WX /DWIN32_LEAN_AND_MEAN /DNOMINMAX /O2 /MD {1} /Fe:"{2}" /Fo:"{3}/" /link FltLib.lib /INCREMENTAL:NO' -f $environment.VcVarsPath, $sourceArguments, $exe, $output
$batch = Join-Path $output 'compile.cmd'
Set-Content -LiteralPath $batch -Value ("@echo off`r`n" + $command + "`r`nexit /b %errorlevel%") -Encoding ascii
& $batch
if ($LASTEXITCODE -ne 0) { throw "managed callback close test compilation failed: $LASTEXITCODE" }
if (-not $BuildOnly) {
    & $exe
    if ($LASTEXITCODE -ne 0) { throw "managed callback close test failed: $LASTEXITCODE" }
}
Write-Output $exe
