param([switch]$Sanitize)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
. (Join-Path $PSScriptRoot 'msvc-validation-environment.ps1')
$validationEnvironment = Get-MsvcValidationEnvironment -Sanitize:$Sanitize
$variant = if ($Sanitize) { 'Release-asan' } else { 'Release' }
$output = Join-Path $repo ('.build\evidence-privacy\' + $variant)
New-Item -ItemType Directory -Force -Path $output | Out-Null
$exe = Join-Path $output 'evidence-privacy-selftest.exe'
$flags = '/O2 /MD'
if ($Sanitize) {
    $flags += ' /fsanitize=address /Zi'
    Copy-Item -LiteralPath $validationEnvironment.AsanRuntimePath -Destination $output -Force
}
$sources = @('tools\evidence-privacy-selftest.cpp', 'user\EvidencePrivacy.cpp', 'user\AnalystSnapshot.cpp') |
    ForEach-Object { '"' + (Join-Path $repo $_) + '"' }
$command = 'call "{0}" >nul && cl /nologo /std:c++17 /EHsc /W4 /WX /DWIN32_LEAN_AND_MEAN /DNOMINMAX {1} {2} /Fe:"{3}" /Fo:"{4}" /Fd:"{4}privacy.pdb" /link /INCREMENTAL:NO' -f $validationEnvironment.VcVarsPath, $flags, ($sources -join ' '), $exe, ($output.Replace('\', '/') + '/')
$batch = Join-Path $output 'compile.cmd'
Set-Content -LiteralPath $batch -Value (@('@echo off', $command, 'exit /b %errorlevel%') -join [Environment]::NewLine) -Encoding ascii
& $batch
if ($LASTEXITCODE -ne 0) { throw "Evidence privacy compilation failed: $LASTEXITCODE" }
& python (Join-Path $PSScriptRoot 'test-evidence-privacy.py') --exe $exe --fixtures $output
if ($LASTEXITCODE -ne 0) { throw "Evidence privacy validation failed: $LASTEXITCODE" }
