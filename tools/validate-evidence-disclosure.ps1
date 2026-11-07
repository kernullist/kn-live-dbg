param(
    [switch]$Sanitize,
    [Parameter(Mandatory=$true)][string]$ImageSliceFixtures,
    [Parameter(Mandatory=$true)][string]$ImageRecipeFixtures,
    [string]$Cli
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
. (Join-Path $PSScriptRoot 'msvc-validation-environment.ps1')
$validationEnvironment = Get-MsvcValidationEnvironment -Sanitize:$Sanitize
$variant = if ($Sanitize) { 'Release-asan' } else { 'Release' }
$output = Join-Path $repo ('.build\evidence-disclosure\' + $variant)
New-Item -ItemType Directory -Force -Path $output | Out-Null
$exe = Join-Path $output 'evidence-disclosure-selftest.exe'
$flags = '/O2 /MD'
if ($Sanitize)
{
    $flags += ' /fsanitize=address /Zi'
    Copy-Item -LiteralPath $validationEnvironment.AsanRuntimePath -Destination $output -Force
}
$sources = @('tools\evidence-disclosure-selftest.cpp', 'user\EvidenceDisclosure.cpp', 'user\EvidenceDisclosureFacts.cpp',
    'user\EvidencePrivacy.cpp', 'user\AiProvider.cpp', 'user\AiModelCatalog.cpp',
    'user\ReferenceArtifact.cpp', 'user\ImageRecipeJson.cpp', 'user\ImageVerificationRecipe.cpp',
    'user\ImageRecipeReadSet.cpp', 'user\ImageSliceRecipe.cpp', 'user\ImageScopeClaims.cpp', 'user\ImageSweepManifest.cpp', 'user\ImageSweepReplay.cpp',
    'user\ObservationReadRoutingJson.cpp', 'user\ImageProof.cpp', 'user\ExecutableImage.cpp',
    'user\ExecutableImageVerifier.cpp', 'user\AnalystSnapshot.cpp') | ForEach-Object { '"' + (Join-Path $repo $_) + '"' }
$command = 'call "{0}" >nul && cl /nologo /std:c++17 /EHsc /W4 /WX /DWIN32_LEAN_AND_MEAN /DNOMINMAX {1} {2} /Fe:"{3}" /Fo:"{4}" /Fd:"{4}disclosure.pdb" /link /INCREMENTAL:NO winhttp.lib ws2_32.lib crypt32.lib shell32.lib' -f $validationEnvironment.VcVarsPath, $flags, ($sources -join ' '), $exe, ($output.Replace('\', '/') + '/')
$batch = Join-Path $output 'compile.cmd'
Set-Content -LiteralPath $batch -Value (@('@echo off', $command, 'exit /b %errorlevel%') -join [Environment]::NewLine) -Encoding ascii
& $batch
if ($LASTEXITCODE -ne 0) { throw "Evidence disclosure compilation failed: $LASTEXITCODE" }
$oracleArgs = @((Join-Path $PSScriptRoot 'test-evidence-disclosure.py'), '--exe', $exe, '--output', $output,
    '--slices', $ImageSliceFixtures, '--recipes', $ImageRecipeFixtures)
if (-not [string]::IsNullOrWhiteSpace($Cli)) { $oracleArgs += @('--cli', (Resolve-Path -LiteralPath $Cli).Path) }
& python @oracleArgs
if ($LASTEXITCODE -ne 0) { throw "Evidence disclosure validation failed: $LASTEXITCODE" }
