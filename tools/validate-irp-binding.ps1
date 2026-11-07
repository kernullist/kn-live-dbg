param([switch]$Sanitize)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
. (Join-Path $PSScriptRoot 'msvc-validation-environment.ps1')
$environment = Get-MsvcValidationEnvironment -Sanitize:$Sanitize
$variant = if ($Sanitize) { 'Release-asan' } else { 'Release' }
$output = Join-Path $repo ('.build\irp-binding\' + $variant + '\run-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $output | Out-Null
$dia = Join-Path $environment.InstallPath 'DIA SDK'
Copy-Item -LiteralPath (Join-Path $dia 'bin\amd64\msdia140.dll') -Destination $output
$flags = '/O2 /MD'
if ($Sanitize) {
    $flags += ' /fsanitize=address /Zi'
    Copy-Item -LiteralPath $environment.AsanRuntimePath -Destination $output
}
$program = Join-Path $output 'irp-binding-selftest.exe'
$sources = @('tools\irp-binding-selftest.cpp', 'user\PendingIrpBinding.cpp', 'user\PendingIrpEvidence.cpp', 'user\PendingIrpClaims.cpp', 'user\BrokeredTypeLayouts.cpp',
    'user\ObservationReadRoutingJson.cpp', 'user\ImageRecipeReadSet.cpp', 'user\ExecutableImage.cpp', 'user\ExecutableImageVerifier.cpp', 'user\TypeSchema.cpp',
    'user\TypeSchemaGenerator.cpp', 'user\TypeSchemaBroker.cpp', 'user\TypeSchemaCommand.cpp',
    'user\ParserWorkerProcess.cpp', 'user\AnalystSnapshot.cpp', 'user\ReferenceArtifact.cpp') |
    ForEach-Object { '"' + (Join-Path $repo $_) + '"' }
$base = Join-Path $output 'fixture'
$commands = @('@echo off', ('call "{0}" >nul' -f $environment.VcVarsPath))
$commands += 'cl /nologo /std:c++17 /EHsc /W4 /WX /Z7 /O2 /MD "{0}" /Fe:"{1}.exe" /Fo:"{1}.obj" /link /DEBUG:FULL /INCREMENTAL:NO /PDB:"{1}.pdb"' -f
    (Join-Path $repo 'tools\irp-binding-fixture.cpp'), $base
$commands += 'if errorlevel 1 exit /b %errorlevel%'
$commands += 'cl /nologo /std:c++17 /EHsc /W4 /WX /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX /D_WIN32_WINNT=0x0A00 /I"{0}" {1} {2} /Fe:"{3}" /Fo:"{4}" /Fd:"{4}binding.pdb" /link /INCREMENTAL:NO /LIBPATH:"{5}" diaguids.lib ole32.lib oleaut32.lib' -f
    (Join-Path $dia 'include'), $flags, ($sources -join ' '), $program, ($output.Replace('\', '/') + '/'), (Join-Path $dia 'lib\amd64')
$commands += 'exit /b %errorlevel%'
$batch = Join-Path $output 'compile.cmd'
Set-Content -LiteralPath $batch -Value ($commands -join [Environment]::NewLine) -Encoding ascii
& $batch
if ($LASTEXITCODE -ne 0) { throw 'IRP binding compilation failed' }
& $program $output
if ($LASTEXITCODE -ne 0) { throw 'IRP binding controls failed' }
& python (Join-Path $PSScriptRoot 'test-irp-binding-capture.py') $output
if ($LASTEXITCODE -ne 0) { throw 'Independent IRP capture oracle failed' }
& python (Join-Path $PSScriptRoot 'test-irp-replay.py') $program $output
if ($LASTEXITCODE -ne 0) { throw 'IRP replay mutation controls failed' }
Write-Output "[irp.binding.validation] fixtures=$output"
