param([switch]$Sanitize)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
. (Join-Path $PSScriptRoot 'msvc-validation-environment.ps1')
$validationEnvironment = Get-MsvcValidationEnvironment -Sanitize:$Sanitize
$variant = 'Release'
if ($Sanitize)
{
    $variant += '-asan'
}
$output = Join-Path $repo ('.build\hidden-process\' + $variant)
New-Item -ItemType Directory -Force -Path $output | Out-Null
$exe = Join-Path $output 'hidden-process-selftest.exe'
$flags = '/O2 /MD'
if ($Sanitize)
{
    $flags += ' /fsanitize=address /Zi'
    Copy-Item -LiteralPath $validationEnvironment.AsanRuntimePath -Destination $output -Force
}
$sources = @('tools\hidden-process-selftest.cpp', 'user\HiddenProcessPolicy.cpp', 'user\HiddenProcessPolicyTests.cpp', 'user\HiddenProcessReport.cpp')
$quotedSources = ($sources | ForEach-Object { '"' + (Join-Path $repo $_) + '"' }) -join ' '
$command = 'call "{0}" >nul && cl /nologo /std:c++17 /EHsc /W4 /WX /DWIN32_LEAN_AND_MEAN /DNOMINMAX {1} {2} /Fe:"{3}" /Fo:"{4}" /Fd:"{4}compiler.pdb" /link /INCREMENTAL:NO' -f $validationEnvironment.VcVarsPath, $flags, $quotedSources, $exe, ($output.Replace('\', '/') + '/')
$batch = Join-Path $output 'compile.cmd'
Set-Content -LiteralPath $batch -Value ("@echo off`r`n" + $command + "`r`nexit /b %errorlevel%") -Encoding ascii
& $batch
if ($LASTEXITCODE -ne 0)
{
    throw "hidden-process compilation failed: $LASTEXITCODE"
}
& $exe
if ($LASTEXITCODE -ne 0)
{
    throw "hidden-process controls failed: $LASTEXITCODE"
}
& python (Join-Path $PSScriptRoot 'test-hidden-process-report.py') --exe $exe
if ($LASTEXITCODE -ne 0)
{
    throw "hidden-process JSON oracle failed: $LASTEXITCODE"
}
