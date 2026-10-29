param([switch]$Sanitize)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
. (Join-Path $PSScriptRoot 'msvc-validation-environment.ps1')
$environment = Get-MsvcValidationEnvironment -Sanitize:$Sanitize
$variant = if ($Sanitize) { 'Release-asan' } else { 'Release' }
$output = Join-Path $repo ('.build\pdb-identity\' + $variant + '\run-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $output | Out-Null
$dia = Join-Path $environment.InstallPath 'DIA SDK'
$provider = Join-Path $dia 'bin\amd64\msdia140.dll'
if (-not (Test-Path -LiteralPath $provider -PathType Leaf)) { throw 'DIA provider unavailable' }
$flags = '/O2 /MD'
if ($Sanitize) {
    $flags += ' /fsanitize=address /Zi'
    Copy-Item -LiteralPath $environment.AsanRuntimePath -Destination $output -Force
}
$program = Join-Path $output 'pdb-identity-selftest.exe'
$fixture = Join-Path $repo 'tools\pdb-identity-fixture.cpp'
$sources = @('tools\pdb-identity-selftest.cpp', 'user\ExecutableImage.cpp') |
    ForEach-Object { '"' + (Join-Path $repo $_) + '"' }
$commands = @('@echo off', ('call "{0}" >nul' -f $environment.VcVarsPath))
foreach ($item in @(@('a', 1), @('b', 2))) {
    $base = Join-Path $output ('fixture-' + $item[0])
    $commands += 'cl /nologo /std:c++17 /EHsc /W4 /WX /Z7 /O2 /MD /DFIXTURE_VARIANT={0} "{1}" /Fe:"{2}.exe" /Fo:"{2}.obj" /link /DEBUG:FULL /INCREMENTAL:NO /PDB:"{2}.pdb"' -f $item[1], $fixture, $base
    $commands += 'if errorlevel 1 exit /b %errorlevel%'
}
$commands += 'cl /nologo /std:c++17 /EHsc /W4 /WX /DWIN32_LEAN_AND_MEAN /DNOMINMAX /I"{0}" {1} {2} /Fe:"{3}" /Fo:"{4}" /Fd:"{4}identity.pdb" /link /INCREMENTAL:NO /LIBPATH:"{5}" diaguids.lib ole32.lib oleaut32.lib' -f
    (Join-Path $dia 'include'), $flags, ($sources -join ' '), $program, ($output.Replace('\', '/') + '/'), (Join-Path $dia 'lib\amd64')
$commands += 'exit /b %errorlevel%'
$batch = Join-Path $output 'compile.cmd'
Set-Content -LiteralPath $batch -Value ($commands -join [Environment]::NewLine) -Encoding ascii
& $batch
if ($LASTEXITCODE -ne 0) { throw 'PDB identity controls compilation failed' }
& $program $provider $output
if ($LASTEXITCODE -ne 0) { throw 'PDB identity controls failed' }
Write-Output "[pdb.identity.validation] fixtures=$output"
