param([switch]$Sanitize)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
. (Join-Path $PSScriptRoot 'msvc-validation-environment.ps1')
$environment = Get-MsvcValidationEnvironment -Sanitize:$Sanitize
$variant = if ($Sanitize) { 'Release-asan' } else { 'Release' }
$output = Join-Path $repo ('.build\dump-source\' + $variant)
New-Item -ItemType Directory -Force -Path $output | Out-Null
$flags = '/O2 /MD'
if ($Sanitize) {
    $flags += ' /fsanitize=address /Zi'
    Copy-Item -LiteralPath $environment.AsanRuntimePath -Destination $output -Force
}
$program = Join-Path $output 'dump-source-selftest.exe'
$sources = @('tools\dump-source-selftest.cpp', 'user\DumpObservationSource.cpp') |
    ForEach-Object { '"' + (Join-Path $repo $_) + '"' }
$commands = @('@echo off', ('call "{0}" >nul' -f $environment.VcVarsPath),
    ('cl /nologo /std:c++17 /EHsc /W4 /WX /DWIN32_LEAN_AND_MEAN /DNOMINMAX /I"{0}" /I"{1}" {2} {3} /Fe:"{4}" /Fo:"{5}" /Fd:"{5}dump.pdb" /link /INCREMENTAL:NO' -f
        (Join-Path $repo 'shared'), (Join-Path $environment.InstallPath 'DIA SDK\include'), $flags,
        ($sources -join ' '), $program, ($output.Replace('\', '/') + '/')),
    'exit /b %errorlevel%')
$batch = Join-Path $output 'compile.cmd'
Set-Content -LiteralPath $batch -Value ($commands -join [Environment]::NewLine) -Encoding ascii
& $batch
if ($LASTEXITCODE -ne 0) { throw 'Dump source harness compilation failed' }
$fixtures = Join-Path $output ('run-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixtures | Out-Null
& $program $fixtures
if ($LASTEXITCODE -ne 0) { throw 'Dump source controls failed' }
Write-Output "[dump.source.validation] fixtures=$fixtures"
