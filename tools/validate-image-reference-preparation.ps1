param([ValidateSet('Debug', 'Release')][string]$Configuration = 'Release')
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
. (Join-Path $PSScriptRoot 'msvc-validation-environment.ps1')
$environment = Get-MsvcValidationEnvironment
$output = Join-Path $repo ('.build\image-reference-preparation\' + $Configuration)
New-Item -ItemType Directory -Force -Path $output | Out-Null
$flags = if ($Configuration -eq 'Debug') { '/Od /Zi /MDd' } else { '/O2 /MD' }
$program = Join-Path $output 'image-reference-preparation-selftest.exe'
$sources = @('tools\image-reference-preparation-selftest.cpp', 'user\ImageReferencePreparation.cpp',
    'user\ExecutableImage.cpp', 'user\ExecutableImageVerifier.cpp', 'user\ReferenceArtifact.cpp') |
    ForEach-Object { '"' + (Join-Path $repo $_) + '"' }
$commands = @('@echo off', ('call "{0}" >nul' -f $environment.VcVarsPath),
    ('cl /nologo /std:c++17 /EHsc /W4 /WX /DWIN32_LEAN_AND_MEAN /DNOMINMAX {0} {1} /Fe:"{2}" /Fo:"{3}" /Fd:"{3}preparation.pdb" /link /INCREMENTAL:NO' -f $flags, ($sources -join ' '), $program, ($output.Replace('\', '/') + '/')),
    'exit /b %errorlevel%')
$batch = Join-Path $output 'compile.cmd'
Set-Content -LiteralPath $batch -Value ($commands -join [Environment]::NewLine) -Encoding ascii
& $batch
if ($LASTEXITCODE -ne 0) { throw 'Reference preparation harness compilation failed' }
& python (Join-Path $PSScriptRoot 'test-image-reference-preparation.py') --core-exe $program
if ($LASTEXITCODE -ne 0) { throw "Reference preparation validation failed: $LASTEXITCODE" }
