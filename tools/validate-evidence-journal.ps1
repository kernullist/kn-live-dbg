param([switch]$Sanitize)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
. (Join-Path $PSScriptRoot 'msvc-validation-environment.ps1')
$validationEnvironment = Get-MsvcValidationEnvironment -Sanitize:$Sanitize
$variant = if ($Sanitize) { 'Release-asan' } else { 'Release' }
$output = Join-Path $repo ('.build\evidence-journal\' + $variant)
New-Item -ItemType Directory -Force -Path $output | Out-Null
$exe = Join-Path $output 'evidence-journal-selftest.exe'
$flags = '/O2 /MD'
if ($Sanitize) {
    $flags += ' /fsanitize=address /Zi'
    Copy-Item -LiteralPath $validationEnvironment.AsanRuntimePath -Destination $output -Force
}
$sources = @('tools\evidence-journal-selftest.cpp', 'user\EvidenceJournal.cpp', 'user\AnalystSnapshot.cpp') |
    ForEach-Object { '"' + (Join-Path $repo $_) + '"' }
$command = 'call "{0}" >nul && cl /nologo /std:c++17 /EHsc /W4 /WX /DWIN32_LEAN_AND_MEAN /DNOMINMAX {1} {2} /Fe:"{3}" /Fo:"{4}" /Fd:"{4}journal.pdb" /link /INCREMENTAL:NO' -f $validationEnvironment.VcVarsPath, $flags, ($sources -join ' '), $exe, ($output.Replace('\', '/') + '/')
$batch = Join-Path $output 'compile.cmd'
Set-Content -LiteralPath $batch -Value (@('@echo off', $command, 'exit /b %errorlevel%') -join [Environment]::NewLine) -Encoding ascii
& $batch
if ($LASTEXITCODE -ne 0) { throw "Evidence journal compilation failed: $LASTEXITCODE" }
$fixtures = Join-Path $output ('run-' + [Guid]::NewGuid().ToString('N'))
& $exe $fixtures
if ($LASTEXITCODE -ne 0) { throw "Evidence journal controls failed: $LASTEXITCODE; fixtures=$fixtures" }
& python (Join-Path $PSScriptRoot 'test-evidence-journal.py') --exe $exe --fixtures $fixtures
if ($LASTEXITCODE -ne 0) { throw "Evidence journal independent validation failed: $LASTEXITCODE; fixtures=$fixtures" }
& python (Join-Path $PSScriptRoot 'test-evidence-store.py') --exe $exe --fixtures $output
if ($LASTEXITCODE -ne 0) { throw "Evidence store independent validation failed: $LASTEXITCODE" }
& python (Join-Path $PSScriptRoot 'test-evidence-gc.py') --exe $exe --fixtures $output
if ($LASTEXITCODE -ne 0) { throw "Evidence GC independent validation failed: $LASTEXITCODE" }
Write-Output "[journal.validation] fixtures=$fixtures"
