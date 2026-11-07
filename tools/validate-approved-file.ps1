param([switch]$Sanitize)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
. (Join-Path $PSScriptRoot 'msvc-validation-environment.ps1')
$environment = Get-MsvcValidationEnvironment -Sanitize:$Sanitize
$variant = if ($Sanitize) { 'Release-asan' } else { 'Release' }
$output = Join-Path $repo ('.build\approved-file\' + $variant + '\run-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $output | Out-Null
$flags = '/O2 /MD'
if ($Sanitize) {
    $flags += ' /fsanitize=address /Zi'
    Copy-Item -LiteralPath $environment.AsanRuntimePath -Destination $output
}
$program = Join-Path $output 'approved-file-selftest.exe'
$sources = @('tools\approved-file-selftest.cpp', 'user\ExecutableImage.cpp', 'user\AnalystSnapshot.cpp', 'user\ReferenceArtifact.cpp') |
    ForEach-Object { '"' + (Join-Path $repo $_) + '"' }
$commands = @('@echo off', ('call "{0}" >nul' -f $environment.VcVarsPath),
    ('cl /nologo /std:c++17 /EHsc /W4 /WX /Z7 /O2 /MD /DFIXTURE_VARIANT=1 "{0}" /Fe:"{1}\fixture.exe" /Fo:"{1}\fixture.obj" /link /DEBUG:FULL /INCREMENTAL:NO /PDB:"{1}\fixture.pdb"' -f
        (Join-Path $repo 'tools\pdb-identity-fixture.cpp'), $output),
    'if errorlevel 1 exit /b %errorlevel%',
    ('cl /nologo /std:c++17 /EHsc /W4 /WX /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX /D_WIN32_WINNT=0x0A00 {0} {1} /Fe:"{2}" /Fo:"{3}" /Fd:"{3}approved-file.pdb" /link /INCREMENTAL:NO' -f
        $flags, ($sources -join ' '), $program, ($output.Replace('\', '/') + '/')),
    'exit /b %errorlevel%')
Set-Content -LiteralPath (Join-Path $output 'compile.cmd') -Value ($commands -join [Environment]::NewLine) -Encoding ascii
& (Join-Path $output 'compile.cmd')
if ($LASTEXITCODE -ne 0) { throw 'Approved-file compilation failed' }
& $program $output
if ($LASTEXITCODE -ne 0) { throw 'Approved-file controls failed' }
Write-Output "[approved.file.validation] fixtures=$output"
