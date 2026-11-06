param([switch]$Sanitize)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
. (Join-Path $PSScriptRoot 'msvc-validation-environment.ps1')
$validationEnvironment = Get-MsvcValidationEnvironment -Sanitize:$Sanitize
$variant = if ($Sanitize) { 'Release-asan' } else { 'Release' }
$output = Join-Path $repo ('.build\image-retention\' + $variant)
New-Item -ItemType Directory -Force -Path $output | Out-Null
$exe = Join-Path $output 'image-retention-selftest.exe'
$flags = '/O2 /MD'
if ($Sanitize) {
    $flags += ' /fsanitize=address /Zi'
    Copy-Item -LiteralPath $validationEnvironment.AsanRuntimePath -Destination $output -Force
}
$command = 'call "{0}" >nul && cl /nologo /std:c++17 /EHsc /W4 /WX /DWIN32_LEAN_AND_MEAN /DNOMINMAX {1} "{2}" /Fe:"{3}" /Fo:"{4}" /Fd:"{4}retention.pdb" /link /INCREMENTAL:NO' -f $validationEnvironment.VcVarsPath, $flags, (Join-Path $repo 'tools\image-retention-selftest.cpp'), $exe, ($output.Replace('\', '/') + '/')
$batch = Join-Path $output 'compile.cmd'
Set-Content -LiteralPath $batch -Value (@('@echo off', $command, 'exit /b %errorlevel%') -join [Environment]::NewLine) -Encoding ascii
& $batch
if ($LASTEXITCODE -ne 0) { throw "Image retention compilation failed: $LASTEXITCODE" }
& python (Join-Path $PSScriptRoot 'test-image-retention.py') --exe $exe
if ($LASTEXITCODE -ne 0) { throw "Image retention validation failed: $LASTEXITCODE" }
