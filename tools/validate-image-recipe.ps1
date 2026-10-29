param([switch]$Sanitize)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
. (Join-Path $PSScriptRoot 'msvc-validation-environment.ps1')
$environment = Get-MsvcValidationEnvironment -Sanitize:$Sanitize
$variant = if ($Sanitize)
{
    'Release-asan'
}
else
{
    'Release'
}
$output = Join-Path $repo ('.build\image-recipe\' + $variant + '\run-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $output | Out-Null
$flags = '/O2 /MD'
if ($Sanitize)
{
    $flags += ' /fsanitize=address /Zi'
    Copy-Item -LiteralPath $environment.AsanRuntimePath -Destination $output -Force
}
$program = Join-Path $output 'image-recipe-selftest.exe'
$sources = foreach ($source in @('tools\image-recipe-selftest.cpp', 'user\ReferenceArtifact.cpp', 'user\ImageRecipeJson.cpp',
    'user\ImageVerificationRecipe.cpp', 'user\ImageProof.cpp', 'user\ExecutableImage.cpp',
    'user\ExecutableImageVerifier.cpp', 'user\AnalystSnapshot.cpp'))
{
    '"' + (Join-Path $repo $source) + '"'
}
$commands = @('@echo off', ('call "{0}" >nul' -f $environment.VcVarsPath),
    ('cl /nologo /std:c++17 /EHsc /W4 /WX /DWIN32_LEAN_AND_MEAN /DNOMINMAX {0} {1} /Fe:"{2}" /Fo:"{3}" /Fd:"{3}recipe.pdb" /link /INCREMENTAL:NO' -f
        $flags, ($sources -join ' '), $program, ($output.Replace('\', '/') + '/')),
    'exit /b %errorlevel%')
$batch = Join-Path $output 'compile.cmd'
Set-Content -LiteralPath $batch -Value ($commands -join [Environment]::NewLine) -Encoding ascii
& $batch
if ($LASTEXITCODE -ne 0)
{
    throw 'Image recipe harness compilation failed'
}
& $program $output
if ($LASTEXITCODE -ne 0)
{
    throw 'Image recipe controls failed'
}
$published = 0
$absent = 0
foreach ($delay in @(1, 25, 100, 250, 500, 1500))
{
    $target = Join-Path $output ('interrupt-' + $delay)
    New-Item -ItemType Directory -Path $target | Out-Null
    $process = Start-Process -FilePath $program -ArgumentList @('--publish', ('"' + $target + '"')) -WindowStyle Hidden -PassThru
    try
    {
        Start-Sleep -Milliseconds $delay
        $terminated = -not $process.HasExited
        if ($terminated)
        {
            $process.Kill()
        }
        $process.WaitForExit()
        if (-not $terminated -and $process.ExitCode -ne 0)
        {
            throw 'Image publication failed before interruption'
        }
        $case = Join-Path $target 'case'
        if (Test-Path -LiteralPath (Join-Path $case 'recipe.knverify'))
        {
            & $program --replay $case
            if ($LASTEXITCODE -ne 0)
            {
                throw 'Interrupted image publication exposed an invalid final recipe'
            }
            ++$published
        }
        else
        {
            ++$absent
        }
    }
    finally
    {
        $process.Dispose()
    }
}
Write-Output "[image.recipe.publication] interrupted=6 valid=$published absent=$absent"
Write-Output "[image.recipe.validation] fixtures=$output"
