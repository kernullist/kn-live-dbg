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
        throw 'Visual C++ build tools were not found'
    }
    $install = Split-Path (Split-Path (Split-Path (Split-Path $fallback.FullName)))
}
$variant = $Configuration
if ($Sanitize)
{
    $variant += '-asan'
}
$output = Join-Path $repo ('.build\kmon-core\' + $variant)
New-Item -ItemType Directory -Force -Path $output | Out-Null
$vcvars = Join-Path $install 'VC\Auxiliary\Build\vcvars64.bat'
$source = Join-Path $PSScriptRoot 'kmon-core-selftest.cpp'
$exe = Join-Path $output "kmon-core-$Configuration.exe"
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
    if ($null -eq $runtime)
    {
        throw 'The x64 AddressSanitizer runtime was not found'
    }
    Copy-Item -LiteralPath $runtime.FullName -Destination $output -Force
}
$sources = @($source, (Join-Path $repo 'user\ExecutableImage.cpp'), (Join-Path $repo 'user\ExecutableImageVerifier.cpp'), (Join-Path $repo 'user\CodeTargetResolver.cpp'), (Join-Path $repo 'user\GameBuildManifest.cpp'))
$quotedSourceList = foreach ($item in $sources)
{
    '"' + $item + '"'
}
$quotedSources = $quotedSourceList -join ' '
$command = 'call "{0}" >nul && cl /nologo /std:c++17 /EHsc /W4 /WX /DWIN32_LEAN_AND_MEAN /DNOMINMAX {1} {2} /Fe:"{3}" /Fo:"{4}" /link /INCREMENTAL:NO' -f $vcvars, $flags, $quotedSources, $exe, ($output.Replace('\', '/') + '/')
$batch = Join-Path $output 'compile.cmd'
Set-Content -LiteralPath $batch -Value ("@echo off`r`n" + $command + "`r`nexit /b %errorlevel%") -Encoding ascii
& $batch
if ($LASTEXITCODE -ne 0)
{
    throw "kmon core compilation failed: $LASTEXITCODE"
}
& $exe
if ($LASTEXITCODE -ne 0)
{
    throw "kmon core self-test failed: $LASTEXITCODE"
}
