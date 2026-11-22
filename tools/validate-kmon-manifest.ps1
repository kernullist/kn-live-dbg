param([string]$Executable = (Join-Path $PSScriptRoot '..\x64\Release\KnLiveDbg.exe'), [switch]$Sanitize)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
. (Join-Path $PSScriptRoot 'msvc-validation-environment.ps1')
$compiler = Get-MsvcValidationEnvironment -Sanitize:$Sanitize
$output = Join-Path $repo ('.build\kmon-manifest\' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $output | Out-Null
$fixture = Join-Path $output 'ordinary-game-fixture.exe'
$pdb = Join-Path $output 'ordinary-game-fixture.pdb'
$layout = Join-Path $output 'object-layout.txt'
$manifest = Join-Path $output ('build-' + [guid]::NewGuid().ToString('N') + '.knmanifest')
$source = Join-Path $PSScriptRoot 'kmon-manifest-fixture.cpp'
$batch = Join-Path $output 'compile.cmd'
$extraFlags = ''
if ($Sanitize)
{
    $extraFlags = '/fsanitize=address'
    Copy-Item -LiteralPath $compiler.AsanRuntimePath -Destination $output
}
$command = 'call "{0}" >nul && cl /nologo /std:c++17 /EHsc /W4 /WX /Od /Zi /MD /DWIN32_LEAN_AND_MEAN /DNOMINMAX {1} "{2}" "{3}" "{4}" /Fo:"{5}" /Fd:"{6}" /Fe:"{7}" /link /DEBUG:FULL /INCREMENTAL:NO /PDB:"{8}"' -f $compiler.VcVarsPath, $extraFlags, $source, (Join-Path $repo 'user\GameBuildManifest.cpp'), (Join-Path $repo 'user\ExecutableImage.cpp'), ($output.Replace('\', '/') + '/'), (Join-Path $output 'compiler.pdb'), $fixture, $pdb
Set-Content -LiteralPath $batch -Value ("@echo off`r`n" + $command + "`r`nexit /b %errorlevel%") -Encoding ascii
& $batch
if ($LASTEXITCODE -ne 0)
{
    throw 'Manifest fixture compilation failed'
}
& $fixture $layout
if ($LASTEXITCODE -ne 0)
{
    throw 'Fixture layout extraction failed'
}
& $Executable --game-manifest create $fixture $pdb $layout $manifest
if ($LASTEXITCODE -ne 0)
{
    throw 'Exact binary/PDB manifest generation failed'
}
& $Executable --game-manifest verify $manifest $fixture
if ($LASTEXITCODE -ne 0)
{
    throw 'Exact build verification failed'
}
$wrongImage = Join-Path $output 'wrong-build.exe'
$bytes = [IO.File]::ReadAllBytes($fixture)
$bytes[$bytes.Length - 1] = $bytes[$bytes.Length - 1] -bxor 1
[IO.File]::WriteAllBytes($wrongImage, $bytes)
& $Executable --game-manifest verify $manifest $wrongImage
if ($LASTEXITCODE -eq 0)
{
    throw 'Wrong image SHA256 was accepted'
}
$malformed = Join-Path $output 'malformed.knmanifest'
[IO.File]::WriteAllText($malformed, ([IO.File]::ReadAllText($manifest) + 'trailing_token'))
& $Executable --game-manifest verify $malformed $fixture
if ($LASTEXITCODE -eq 0)
{
    throw 'Malformed manifest was accepted'
}
$wrongPdbManifest = Join-Path $output ('wrong-pdb-' + [guid]::NewGuid().ToString('N') + '.knmanifest')
$otherPdb = [IO.Path]::ChangeExtension((Resolve-Path -LiteralPath $Executable).Path, '.pdb')
& $Executable --game-manifest create $fixture $otherPdb $layout $wrongPdbManifest
if ($LASTEXITCODE -eq 0)
{
    throw 'Mismatched PDB was accepted'
}
& $Executable --game-manifest self-test
if ($LASTEXITCODE -ne 0)
{
    throw 'Manifest reader and KMON event publication self-test failed'
}
& python (Join-Path $PSScriptRoot 'test-game-object-lifetime.py') --exe $Executable --fixture $fixture --legacy $manifest
if ($LASTEXITCODE -ne 0)
{
    throw 'Owned game-object lifetime validation failed'
}
Write-Output '[kmon.manifest] native binary/PDB generation, secondary vptr and mismatch controls: PASS'
Write-Output "[kmon.manifest] $manifest"
exit 0
