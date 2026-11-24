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
New-Item -ItemType Directory -Path $output | Out-Null
$flags = '/O2 /MD'
if ($Sanitize)
{
    $flags += ' /fsanitize=address /Zi'
    Copy-Item -LiteralPath $environment.AsanRuntimePath -Destination $output -Force
}
$program = Join-Path $output 'image-recipe-selftest.exe'
$sources = foreach ($source in @('tools\image-recipe-selftest.cpp', 'tools\process-image-mapping-selftest.cpp', 'user\ReferenceArtifact.cpp', 'user\ImageRecipeJson.cpp', 'user\ImageClaimPublication.cpp', 'user\ImageScopeClaimPublication.cpp',
    'user\ImageVerificationRecipe.cpp', 'user\ImageRecipeReadSet.cpp', 'user\ImageProcessMappings.cpp', 'user\ImageSliceRecipe.cpp', 'user\ImageScopeClaims.cpp', 'user\ImageSweepManifest.cpp', 'user\ImageSweepReplay.cpp',
    'user\ImageCaptureCollection.cpp', 'user\ImageAuthorizedChanges.cpp', 'user\ImageApprovalCollection.cpp', 'user\ImageScopeApprovalCollection.cpp', 'user\EvidenceJournal.cpp', 'user\EvidenceStoreCatalog.cpp', 'user\EvidenceStoreFiles.cpp', 'user\CollectionRetentionBudget.cpp', 'user\ImageArchiveDependencies.cpp', 'user\ProcessImageSourceReceipt.cpp', 'user\EvidencePrivacy.cpp',
    'user\ObservationReadRoutingJson.cpp', 'user\ImageProof.cpp', 'user\ExecutableImage.cpp',
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
& python (Join-Path $PSScriptRoot 'test-image-claims.py') --exe $program --fixtures $output
if ($LASTEXITCODE -ne 0)
{
    throw 'Image claim original-evidence oracle failed'
}
& python (Join-Path $PSScriptRoot 'test-process-image-mappings.py') --exe $program --fixtures $output
if ($LASTEXITCODE -ne 0)
{
    throw 'Native process mapping evidence oracle failed'
}
& python (Join-Path $PSScriptRoot 'test-image-claim-publication.py') --exe $program --fixtures $output
if ($LASTEXITCODE -ne 0)
{
    throw 'Original image claim publication/replay controls failed'
}
& python (Join-Path $PSScriptRoot 'test-image-authorized-changes.py') --exe $program --fixtures $output
if ($LASTEXITCODE -ne 0)
{
    throw 'Pinned image approval and exact change controls failed'
}
foreach ($format in @('v1', 'v2'))
{
    $published = 0
    $absent = 0
    $publishOption = if ($format -eq 'v1') { '--publish' } else { '--publish-observed' }
    foreach ($delay in @(1, 25, 100, 250, 500, 1500))
    {
        $target = Join-Path $output ('interrupt-' + $format + '-' + $delay)
        New-Item -ItemType Directory -Path $target | Out-Null
        $process = Start-Process -FilePath $program -ArgumentList @($publishOption, ('"' + $target + '"')) -WindowStyle Hidden -PassThru
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
            $directory = [IO.DirectoryInfo]::new($target)
            while ($directory.FullName -ne $repo)
            {
                if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $null -eq $directory.Parent)
                {
                    throw 'Image publication fixture is outside its expected directory tree'
                }
                $directory = $directory.Parent
            }
            $case = Join-Path $target 'case'
            $hasRecipe = Test-Path -LiteralPath (Join-Path $case 'recipe.knverify')
            if (-not $terminated -and -not $hasRecipe)
            {
                throw 'Completed image publication produced no recipe'
            }
            # Only the child writes input.exe in this fresh trial. Replay must use the retained case.
            [IO.File]::Delete((Join-Path $target 'input.exe'))
            if ($hasRecipe)
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
            if (-not $process.HasExited) { $process.Kill(); $process.WaitForExit() }
            $process.Dispose()
        }
    }
    Write-Output "[image.recipe.publication] format=$format interrupted=6 valid=$published absent=$absent"
}
Write-Output "[image.recipe.validation] fixtures=$output"
