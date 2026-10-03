param([string]$Executable = (Join-Path $PSScriptRoot '..\x64\Release\KnLiveDbg.exe'))

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$vcvars = Get-Item "$env:ProgramFiles\Microsoft Visual Studio\*\*\VC\Auxiliary\Build\vcvars64.bat" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($null -eq $vcvars)
{
    throw 'Visual C++ build tools were not found'
}
$output = Join-Path $repo '.build\kmon-manifest'
New-Item -ItemType Directory -Force -Path $output | Out-Null
$fixture = Join-Path $output 'ordinary-game-fixture.exe'
$pdb = Join-Path $output 'ordinary-game-fixture.pdb'
$layout = Join-Path $output 'object-layout.txt'
$manifest = Join-Path $output ('build-' + [guid]::NewGuid().ToString('N') + '.knmanifest')
$source = Join-Path $PSScriptRoot 'kmon-manifest-fixture.cpp'
$batch = Join-Path $output 'compile.cmd'
$command = 'call "{0}" >nul && cl /nologo /std:c++17 /EHsc /W4 /WX /Od /Zi /MD /DWIN32_LEAN_AND_MEAN /DNOMINMAX "{1}" /Fo:"{2}" /Fd:"{3}" /Fe:"{4}" /link /DEBUG:FULL /INCREMENTAL:NO /PDB:"{5}"' -f $vcvars.FullName, $source, (Join-Path $output 'fixture.obj'), (Join-Path $output 'compiler.pdb'), $fixture, $pdb
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
Write-Output '[kmon.manifest] native binary/PDB generation, secondary vptr and mismatch controls: PASS'
Write-Output "[kmon.manifest] $manifest"
exit 0
