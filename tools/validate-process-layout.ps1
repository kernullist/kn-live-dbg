param(
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release',
    [switch]$Sanitize
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
. (Join-Path $PSScriptRoot 'msvc-validation-environment.ps1')
$validationEnvironment = Get-MsvcValidationEnvironment -Sanitize:$Sanitize
$variant = $Configuration
if ($Sanitize)
{
    $variant += '-asan'
}
$output = Join-Path $repo ('.build\process-layout\' + $variant)
New-Item -ItemType Directory -Force -Path $output | Out-Null
$vcvars = $validationEnvironment.VcVarsPath
$flags = '/O2 /MD'
if ($Configuration -eq 'Debug')
{
    $flags = '/Od /Zi /MDd'
}
if ($Sanitize)
{
    $flags += ' /fsanitize=address /Zi'
    Copy-Item -LiteralPath $validationEnvironment.AsanRuntimePath -Destination $output -Force
}
$program = Join-Path $output 'process-layout-selftest.exe'
$sources = @('tools\process-layout-selftest.cpp', 'user\ProcessLayoutMonitor.cpp',
    'user\AnalystSnapshot.cpp', 'user\ExecutableImage.cpp', 'user\ExecutableImageVerifier.cpp') |
    ForEach-Object { '"' + (Join-Path $repo $_) + '"' }
$commands = @(
    '@echo off',
    ('call "{0}" >nul' -f $vcvars),
    ('cl /nologo /std:c++17 /EHsc /W4 /WX /DWIN32_LEAN_AND_MEAN /DNOMINMAX {0} {1} /Fe:"{2}" /Fo:"{3}" /Fd:"{3}layout.pdb" /link /INCREMENTAL:NO' -f $flags, ($sources -join ' '), $program, ($output.Replace('\', '/') + '/')),
    'exit /b %errorlevel%'
)
$batch = Join-Path $output 'compile.cmd'
Set-Content -LiteralPath $batch -Value ($commands -join [Environment]::NewLine) -Encoding ascii
& $batch
if ($LASTEXITCODE -ne 0)
{
    throw 'Layout harness compilation failed'
}
$evidence = Join-Path $output ('run-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $evidence | Out-Null
& $program $evidence
if ($LASTEXITCODE -ne 0)
{
    throw 'Layout harness validation failed'
}
Write-Output "[layout.validation] evidence=$evidence"
