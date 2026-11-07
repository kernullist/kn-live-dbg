param([switch]$Sanitize, [string]$Cli)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
. (Join-Path $PSScriptRoot 'msvc-validation-environment.ps1')
$validationEnvironment = Get-MsvcValidationEnvironment -Sanitize:$Sanitize
$variant = if ($Sanitize) { 'Release-asan' } else { 'Release' }
$output = Join-Path $repo ('.build\temporal-facts\' + $variant)
New-Item -ItemType Directory -Force -Path $output | Out-Null
$program = Join-Path $output 'temporal-facts-selftest.exe'
$flags = '/O2 /MD'
if ($Sanitize) {
    $flags += ' /fsanitize=address /Zi'
    Copy-Item -LiteralPath $validationEnvironment.AsanRuntimePath -Destination $output -Force
}
$sources = @('tools\temporal-facts-selftest.cpp', 'user\TemporalFactStore.cpp', 'user\EvidenceBundle.cpp', 'user\AnalystSnapshot.cpp') |
    ForEach-Object { '"' + (Join-Path $repo $_) + '"' }
$command = 'call "{0}" >nul && cl /nologo /std:c++17 /EHsc /W4 /WX /DWIN32_LEAN_AND_MEAN /DNOMINMAX {1} {2} /Fe:"{3}" /Fo:"{4}" /Fd:"{4}temporal.pdb" /link /INCREMENTAL:NO' -f $validationEnvironment.VcVarsPath, $flags, ($sources -join ' '), $program, ($output.Replace('\', '/') + '/')
$batch = Join-Path $output 'compile.cmd'
Set-Content -LiteralPath $batch -Value (@('@echo off', $command, 'exit /b %errorlevel%') -join [Environment]::NewLine) -Encoding ascii
& $batch
if ($LASTEXITCODE -ne 0) { throw "Temporal facts compilation failed: $LASTEXITCODE" }
$oracleArgs = @((Join-Path $PSScriptRoot 'test-temporal-facts.py'), '--exe', $program, '--output', $output)
if ($Cli) { $oracleArgs += @('--cli', (Resolve-Path -LiteralPath $Cli).Path) }
& python @oracleArgs
if ($LASTEXITCODE -ne 0) { throw "Temporal facts validation failed: $LASTEXITCODE" }
