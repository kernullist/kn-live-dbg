param([switch]$Sanitize)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
. (Join-Path $PSScriptRoot 'msvc-validation-environment.ps1')
$environment = Get-MsvcValidationEnvironment -Sanitize:$Sanitize
$variant = if ($Sanitize) { 'Release-asan' } else { 'Release' }
$output = Join-Path $repo ('.build\evidence-bundle\' + $variant)
New-Item -ItemType Directory -Force -Path $output | Out-Null
$flags = '/O2 /MD'
if ($Sanitize) {
    $flags += ' /fsanitize=address /Zi'
    Copy-Item -LiteralPath $environment.AsanRuntimePath -Destination $output -Force
}
$program = Join-Path $output 'evidence-bundle-selftest.exe'
$sources = @('tools\evidence-bundle-selftest.cpp', 'user\EvidenceBundle.cpp', 'user\EvidenceInvestigation.cpp',
    'user\CodeTargetResolver.cpp', 'user\AnalystSnapshot.cpp') |
    ForEach-Object { '"' + (Join-Path $repo $_) + '"' }
$commands = @('@echo off', ('call "{0}" >nul' -f $environment.VcVarsPath),
    ('cl /nologo /std:c++17 /EHsc /W4 /WX /DWIN32_LEAN_AND_MEAN /DNOMINMAX {0} {1} /Fe:"{2}" /Fo:"{3}" /Fd:"{3}evidence.pdb" /link /INCREMENTAL:NO' -f
        $flags, ($sources -join ' '), $program, ($output.Replace('\', '/') + '/')),
    'exit /b %errorlevel%')
$batch = Join-Path $output 'compile.cmd'
Set-Content -LiteralPath $batch -Value ($commands -join [Environment]::NewLine) -Encoding ascii
& $batch
if ($LASTEXITCODE -ne 0) { throw 'Evidence bundle harness compilation failed' }
$evidence = Join-Path $output ('run-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $evidence | Out-Null
& $program $evidence
if ($LASTEXITCODE -ne 0) { throw 'Evidence bundle controls failed' }
& $program --read (Join-Path $evidence 'restart.kncase')
if ($LASTEXITCODE -ne 0) { throw 'Fresh process could not recover saved bytes' }
$published = 0
$absent = 0
foreach ($delay in @(1, 10, 50, 100, 250, 500, 1500, 4000)) {
    $target = Join-Path $evidence ('interrupt-' + $delay + '.kncase')
    $process = Start-Process -FilePath $program -ArgumentList @('--publish', ('"' + $target + '"')) -WindowStyle Hidden -PassThru
    try {
        Start-Sleep -Milliseconds $delay
        $terminated = -not $process.HasExited
        if ($terminated) { $process.Kill() }
        $process.WaitForExit()
        if (-not $terminated -and $process.ExitCode -ne 0) { throw 'Publication failed before interruption' }
        if (Test-Path -LiteralPath $target) {
            & $program --read $target
            if ($LASTEXITCODE -ne 0) { throw 'Interrupted writer exposed an invalid final bundle' }
            ++$published
        } else { ++$absent }
    } finally { $process.Dispose() }
}
& $program --publish (Join-Path $evidence 'completed.kncase')
if ($LASTEXITCODE -ne 0) { throw 'Full-size bundle publication failed' }
& $program --read (Join-Path $evidence 'completed.kncase')
if ($LASTEXITCODE -ne 0) { throw 'Full-size bundle restart read failed' }
Write-Output "[evidence.publication] interrupted_runs=8 valid_final=$published absent_final=$absent restart=passed"
Write-Output "[evidence.validation] evidence=$evidence"
