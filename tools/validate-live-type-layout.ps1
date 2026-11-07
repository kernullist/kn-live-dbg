param([switch]$Sanitize)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
. (Join-Path $PSScriptRoot 'msvc-validation-environment.ps1')
$environment = Get-MsvcValidationEnvironment -Sanitize:$Sanitize
$variant = if ($Sanitize) { 'Release-asan' } else { 'Release' }
$output = Join-Path $repo ('.build\live-type-layout\' + $variant + '\run-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $output | Out-Null
$dia = Join-Path $environment.InstallPath 'DIA SDK'
Copy-Item -LiteralPath (Join-Path $dia 'bin\amd64\msdia140.dll') -Destination $output
$flags = '/O2 /MD'
if ($Sanitize) {
    $flags += ' /fsanitize=address /Zi'
    Copy-Item -LiteralPath $environment.AsanRuntimePath -Destination $output
}
$program = Join-Path $output 'live-type-layout-selftest.exe'
$sources = @('tools\live-type-layout-selftest.cpp', 'user\SymbolEngine.cpp', 'user\BrokeredTypeLayouts.cpp',
    'user\SymbolArtifactResolver.cpp', 'user\ExecutableImage.cpp', 'user\TypeSchema.cpp',
    'user\TypeSchemaGenerator.cpp', 'user\TypeSchemaBroker.cpp', 'user\TypeSchemaCommand.cpp',
    'user\ParserWorkerProcess.cpp', 'user\AnalystSnapshot.cpp', 'user\ReferenceArtifact.cpp') |
    ForEach-Object { '"' + (Join-Path $repo $_) + '"' }
$commands = @('@echo off', ('call "{0}" >nul' -f $environment.VcVarsPath))
foreach ($item in @(@('a', 1), @('b', 2))) {
    $base = Join-Path $output ('fixture-' + $item[0])
    $commands += 'cl /nologo /std:c++17 /EHsc /W4 /WX /Z7 /O2 /MD /DFIXTURE_VARIANT={0} "{1}" /Fe:"{2}.exe" /Fo:"{2}.obj" /link /DEBUG:FULL /INCREMENTAL:NO /PDB:"{2}.pdb"' -f
        $item[1], (Join-Path $repo 'tools\live-type-fixture.cpp'), $base
    $commands += 'if errorlevel 1 exit /b %errorlevel%'
}
$commands += 'cl /nologo /std:c++17 /EHsc /W4 /WX /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX /D_WIN32_WINNT=0x0A00 /I"{0}" {1} {2} /Fe:"{3}" /Fo:"{4}" /Fd:"{4}live.pdb" /link /INCREMENTAL:NO /LIBPATH:"{5}" diaguids.lib ole32.lib oleaut32.lib' -f
    (Join-Path $dia 'include'), $flags, ($sources -join ' '), $program, ($output.Replace('\', '/') + '/'), (Join-Path $dia 'lib\amd64')
$commands += 'exit /b %errorlevel%'
$batch = Join-Path $output 'compile.cmd'
Set-Content -LiteralPath $batch -Value ($commands -join [Environment]::NewLine) -Encoding ascii
& $batch
if ($LASTEXITCODE -ne 0) { throw 'Live type layout compilation failed' }
try { New-Item -ItemType Junction -Path (Join-Path $output 'junction') -Target $output | Out-Null }
catch { Write-Output '[live.type.validation] junction_skipped=1' }
& $program $output
if ($LASTEXITCODE -ne 0) { throw 'Live type layout controls failed' }
Write-Output "[live.type.validation] fixtures=$output"
