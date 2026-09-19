param(
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release',
    [switch]$Sanitize
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$install = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $install)
{
    $fallback = Get-Item "$env:ProgramFiles\Microsoft Visual Studio\*\*\VC\Auxiliary\Build\vcvars64.bat" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $fallback)
    {
        throw 'Visual C++ tools were not found'
    }
    $install = Split-Path (Split-Path (Split-Path (Split-Path $fallback.FullName)))
}
$variant = $Configuration
if ($Sanitize)
{
    $variant += '-asan'
}
$output = Join-Path $repo ('.build\process-layout\' + $variant)
New-Item -ItemType Directory -Force -Path $output | Out-Null
$vcvars = Join-Path $install 'VC\Auxiliary\Build\vcvars64.bat'
$flags = '/O2 /MD'
if ($Configuration -eq 'Debug')
{
    $flags = '/Od /Zi /MDd'
}
if ($Sanitize)
{
    $flags += ' /fsanitize=address /Zi'
    $runtime = Get-Item (Join-Path $install 'VC\Tools\MSVC\*\bin\Hostx64\x64\clang_rt.asan_dynamic-x86_64.dll') |
        Sort-Object FullName -Descending | Select-Object -First 1
    Copy-Item -LiteralPath $runtime.FullName -Destination $output -Force
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
