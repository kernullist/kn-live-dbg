param([switch]$Sanitize)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
. (Join-Path $PSScriptRoot 'msvc-validation-environment.ps1')
$validationEnvironment = Get-MsvcValidationEnvironment -Sanitize:$Sanitize
$variant = if ($Sanitize) { 'Release-asan' } else { 'Release' }
$variantRoot = Join-Path $repo ('.build\image-slice\' + $variant)
$runId = [Guid]::NewGuid().ToString('N')
$output = Join-Path $variantRoot ('build-' + $runId)
New-Item -ItemType Directory -Force -Path $output | Out-Null
$exe = Join-Path $output 'image-slice-selftest.exe'
$flags = '/O2 /MD'
if ($Sanitize)
{
    $flags += ' /fsanitize=address /Zi'
    Copy-Item -LiteralPath $validationEnvironment.AsanRuntimePath -Destination $output -Force
}
$sources = @('tools\image-slice-selftest.cpp', 'user\ReferenceArtifact.cpp', 'user\ImageRecipeJson.cpp',
    'user\ImageVerificationRecipe.cpp', 'user\ImageRecipeReadSet.cpp', 'user\ImageSliceRecipe.cpp', 'user\ImageScopeClaims.cpp',
    'user\ImageSweepManifest.cpp', 'user\ImageSweepReplay.cpp',
    'user\ImageSweepGraph.cpp', 'user\EvidenceGraphQuery.cpp',
    'user\ObservationReadRoutingJson.cpp', 'user\ImageProof.cpp', 'user\ExecutableImage.cpp',
    'user\ExecutableImageVerifier.cpp', 'user\AnalystSnapshot.cpp') | ForEach-Object { '"' + (Join-Path $repo $_) + '"' }
$command = 'call "{0}" >nul && cl /nologo /std:c++17 /EHsc /W4 /WX /DWIN32_LEAN_AND_MEAN /DNOMINMAX {1} {2} /Fe:"{3}" /Fo:"{4}" /Fd:"{4}slice.pdb" /link /INCREMENTAL:NO' -f $validationEnvironment.VcVarsPath, $flags, ($sources -join ' '), $exe, ($output.Replace('\', '/') + '/')
$batch = Join-Path $output 'compile.cmd'
Set-Content -LiteralPath $batch -Value (@('@echo off', $command, 'exit /b %errorlevel%') -join [Environment]::NewLine) -Encoding ascii
& $batch
if ($LASTEXITCODE -ne 0) { throw "Image slice compilation failed: $LASTEXITCODE" }
$fixtures = Join-Path $variantRoot ('run-' + $runId)
& $exe $fixtures
if ($LASTEXITCODE -ne 0) { throw "Image slice validation failed: $LASTEXITCODE; fixtures=$fixtures" }
& python (Join-Path $PSScriptRoot 'test-image-slice.py') --exe $exe --fixtures $fixtures
if ($LASTEXITCODE -ne 0) { throw "Image slice independent validation failed: $LASTEXITCODE; fixtures=$fixtures" }
& python (Join-Path $PSScriptRoot 'test-image-sweep.py') --exe $exe --fixtures $fixtures
if ($LASTEXITCODE -ne 0) { throw "Image sweep independent validation failed: $LASTEXITCODE; fixtures=$fixtures" }
& python (Join-Path $PSScriptRoot 'test-image-sweep-graph.py') --exe $exe --fixtures $fixtures
if ($LASTEXITCODE -ne 0) { throw "Image sweep graph validation failed: $LASTEXITCODE; fixtures=$fixtures" }
Write-Output "[image.slice.validation] exe=$exe fixtures=$fixtures"
