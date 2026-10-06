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
$output = Join-Path $repo ('.build\kmon-core\' + $variant)
New-Item -ItemType Directory -Force -Path $output | Out-Null
$vcvars = $validationEnvironment.VcVarsPath
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
    Copy-Item -LiteralPath $validationEnvironment.AsanRuntimePath -Destination $output -Force
}
$sources = @($source, (Join-Path $repo 'user\ExecutableImage.cpp'), (Join-Path $repo 'user\ExecutableImageVerifier.cpp'), (Join-Path $repo 'user\CodeTargetResolver.cpp'), (Join-Path $repo 'user\GameBuildManifest.cpp'))
$quotedSourceList = foreach ($item in $sources)
{
    '"' + $item + '"'
}
$quotedSources = $quotedSourceList -join ' '
$command = 'call "{0}" >nul && cl /nologo /std:c++17 /EHsc /W4 /WX /DWIN32_LEAN_AND_MEAN /DNOMINMAX {1} {2} /Fe:"{3}" /Fo:"{4}" /Fd:"{4}compiler.pdb" /link /INCREMENTAL:NO' -f $vcvars, $flags, $quotedSources, $exe, ($output.Replace('\', '/') + '/')
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
