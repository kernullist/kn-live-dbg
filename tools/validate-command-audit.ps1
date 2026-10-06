param(
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release',
    [switch]$Sanitize,
    [string]$Executable
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
$output = Join-Path $repo ('.build\command-audit\' + $variant)
New-Item -ItemType Directory -Force -Path $output | Out-Null
$vcvars = $validationEnvironment.VcVarsPath
$source = Join-Path $PSScriptRoot 'command-parser-selftest.cpp'
$parser = Join-Path $output 'command-parser-selftest.exe'
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
$command = 'call "{0}" >nul && cl /nologo /std:c++17 /EHsc /W4 /WX /DWIN32_LEAN_AND_MEAN /DNOMINMAX {1} "{2}" /Fe:"{3}" /Fo:"{4}" /Fd:"{4}parser.pdb" /link /INCREMENTAL:NO' -f $vcvars, $flags, $source, $parser, ($output.Replace('\', '/') + '/')
$batch = Join-Path $output 'compile.cmd'
Set-Content -LiteralPath $batch -Value ("@echo off`r`n" + $command + "`r`nexit /b %errorlevel%") -Encoding ascii
& $batch
if ($LASTEXITCODE -ne 0)
{
    throw "command parser compilation failed: $LASTEXITCODE"
}
& $parser
if ($LASTEXITCODE -ne 0)
{
    throw "command parser self-test failed: $LASTEXITCODE"
}
$completion = Join-Path $output 'completion-selftest.exe'
$completionSources = @(
    (Join-Path $PSScriptRoot 'completion-selftest.cpp'),
    (Join-Path $repo 'user\CompletionHints.cpp'),
    (Join-Path $repo 'user\CommandRegistry.cpp'),
    (Join-Path $repo 'user\AiModelCatalog.cpp')
)
$sourceArguments = ($completionSources | ForEach-Object { '"' + $_ + '"' }) -join ' '
$command = 'call "{0}" >nul && cl /nologo /std:c++17 /EHsc /W4 /WX /DWIN32_LEAN_AND_MEAN /DNOMINMAX {1} {2} /Fe:"{3}" /Fo:"{4}" /Fd:"{4}completion.pdb" /link /INCREMENTAL:NO' -f $vcvars, $flags, $sourceArguments, $completion, ($output.Replace('\', '/') + '/')
$batch = Join-Path $output 'compile-completion.cmd'
Set-Content -LiteralPath $batch -Value ("@echo off`r`n" + $command + "`r`nexit /b %errorlevel%") -Encoding ascii
& $batch
if ($LASTEXITCODE -ne 0)
{
    throw "completion compilation failed: $LASTEXITCODE"
}
& $completion
if ($LASTEXITCODE -ne 0)
{
    throw "completion self-test failed: $LASTEXITCODE"
}
if (-not $Executable)
{
    $Executable = Join-Path $repo "x64\$Configuration\KnLiveDbg.exe"
}
if (-not (Test-Path -LiteralPath $Executable -PathType Leaf))
{
    throw "Build the $Configuration executable first: $Executable"
}
& $Executable --self-test commands
if ($LASTEXITCODE -ne 0)
{
    throw "command integration self-test failed: $LASTEXITCODE"
}
