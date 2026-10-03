param(
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release',
    [switch]$Sanitize,
    [string]$PeSieve = ''
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$vswhere = Join-Path ([Environment]::GetEnvironmentVariable('ProgramFiles(x86)')) 'Microsoft Visual Studio\Installer\vswhere.exe'
$install = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $install)
{
    $fallback = Get-Item "$env:ProgramFiles\Microsoft Visual Studio\*\*\VC\Auxiliary\Build\vcvars64.bat" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $fallback)
    {
        throw 'Visual C++ tools were not found'
    }
    $install = Split-Path (Split-Path (Split-Path (Split-Path $fallback.FullName)))
}
$variant = $Configuration
if ($Sanitize)
{
    $variant += '-asan'
}
$output = Join-Path $repo ('.build\kmon-hunting\' + $variant)
New-Item -ItemType Directory -Force -Path $output | Out-Null
$vcvars = Join-Path $install 'VC\Auxiliary\Build\vcvars64.bat'
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
    Copy-Item -LiteralPath $runtime.FullName -Destination $output -Force
}
$replay = Join-Path $output 'kmon-hunting-replay.exe'
$fixture = Join-Path $output 'kmon-hunting-fixture.exe'
$replaySources = @('tools\kmon-hunting-replay.cpp', 'user\ExecutableImage.cpp', 'user\ExecutableImageVerifier.cpp') |
    ForEach-Object { '"' + (Join-Path $repo $_) + '"' }
$commands = @(
    '@echo off',
    ('call "{0}" >nul' -f $vcvars),
    ('cl /nologo /std:c++17 /EHsc /W4 /WX /DWIN32_LEAN_AND_MEAN /DNOMINMAX {0} {1} /Fe:"{2}" /Fo:"{3}" /link /INCREMENTAL:NO' -f $flags, ($replaySources -join ' '), $replay, ($output.Replace('\', '/') + '/')),
    'if errorlevel 1 exit /b %errorlevel%',
    ('cl /nologo /std:c++17 /EHsc /W4 /WX /O2 /MD "{0}" /Fe:"{1}" /Fo:"{2}" /link /INCREMENTAL:NO' -f (Join-Path $repo 'tools\kmon-hunting-fixture.cpp'), $fixture, ($output.Replace('\', '/') + '/')),
    'exit /b %errorlevel%'
)
$batch = Join-Path $output 'compile.cmd'
Set-Content -LiteralPath $batch -Value ($commands -join [Environment]::NewLine) -Encoding ascii
& $batch
if ($LASTEXITCODE -ne 0)
{
    throw 'Hunting harness compilation failed'
}
& $replay --self-test
if ($LASTEXITCODE -ne 0)
{
    throw 'Hunting reducer self-test failed'
}
$synthetic = Join-Path $output 'synthetic-references.jsonl'
& $replay --fixture $synthetic
if ($LASTEXITCODE -ne 0)
{
    throw 'Synthetic evidence creation failed'
}
$replayJson = & $replay --replay $synthetic
if ($LASTEXITCODE -ne 0)
{
    throw 'Synthetic evidence replay failed'
}
$replayed = $replayJson | ConvertFrom-Json
if ($replayed.cases[0].kind -ne 'cross_domain_content' -or $replayed.communication_proven)
{
    throw 'Unexpected replay relation or inflated claim'
}
$invalid = Join-Path $output 'invalid.jsonl'
$rows = @(Get-Content -LiteralPath $synthetic)
$badRows = @(
    '{}',
    '{"pid":1,"pid":2}',
    $rows[1].Replace('"pid":45', '"pid":4294967296'),
    $rows[1].Replace('"observed_ms":101', '"observed_ms":18446744073709551616'),
    $rows[1].Replace('"session_id":0', '"session_id":4294967296'),
    $rows[1].Replace('"session_known":false', '"session_known":"false"'),
    $rows[1].Replace('"page_executable_verified":false', '"page_executable_verified":1'),
    ('x' * 8193)
)
foreach ($bad in $badRows)
{
    Set-Content -LiteralPath $invalid -Value $bad -Encoding utf8
    # Windows PowerShell 5.1 promotes redirected native stderr to an error.
    # Capture the expected diagnostic separately and check the actual exit code.
    $invalidRun = Start-Process -FilePath $replay `
        -ArgumentList @('--replay', ('"' + $invalid + '"')) `
        -WindowStyle Hidden -Wait -PassThru `
        -RedirectStandardOutput (Join-Path $output 'invalid-stdout.txt') `
        -RedirectStandardError (Join-Path $output 'invalid-stderr.txt')
    try
    {
        if ($invalidRun.ExitCode -ne 2)
        {
            throw 'Malformed replay input was not rejected'
        }
    }
    finally
    {
        $invalidRun.Dispose()
    }
}
Write-Output "[kmon.replay] malformed_inputs=$($badRows.Count) rejected=$($badRows.Count)"
$baselineHash = ''
if ($PeSieve)
{
    $PeSieve = (Resolve-Path -LiteralPath $PeSieve).Path
    $baselineHash = (Get-FileHash -LiteralPath $PeSieve -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($baselineHash -ne '9f3ff2884a2c61006cd0a92b7572a815b8dc17012be7747a6abd6ca07c503a3b')
    {
        throw 'Expected official PE-sieve v0.4.1.1 x64 release digest'
    }
}
$runs = @()
foreach ($mode in @('clean', 'modified', 'text', 'jit'))
{
    $ready = Join-Path $output ($mode + '-' + [Guid]::NewGuid().ToString('N') + '.json')
    $child = Start-Process -FilePath $fixture -ArgumentList @($mode, ('"' + $ready + '"')) -WindowStyle Hidden -PassThru
    try
    {
        $deadline = [DateTime]::UtcNow.AddSeconds(10)
        while (-not (Test-Path -LiteralPath $ready) -and [DateTime]::UtcNow -lt $deadline -and -not $child.HasExited)
        {
            Start-Sleep -Milliseconds 50
        }
        if (-not (Test-Path -LiteralPath $ready))
        {
            throw 'Owned fixture did not become ready'
        }
        $identity = Get-Content -LiteralPath $ready -Raw | ConvertFrom-Json
        if ($identity.pid -ne $child.Id)
        {
            throw 'Owned fixture PID mismatch'
        }
        $probe = & $replay --image $child.Id $fixture $identity.base
        if ($LASTEXITCODE -ne 0)
        {
            throw 'Kmon executable-page probe failed'
        }
        $kn = $probe | ConvertFrom-Json
        if (-not $kn.complete -or (($kn.modified_pages -gt 0) -ne ($mode -in @('modified', 'text'))))
        {
            throw 'Unexpected image comparison result'
        }
        $baseline = $null
        $baselineExit = $null
        if ($PeSieve)
        {
            $raw = & $PeSieve /pid $child.Id /quiet /json /ofilter 2 /shellc 3 /iat 3 /report 7
            $baselineExit = $LASTEXITCODE
            $rawText = $raw -join [Environment]::NewLine
            Set-Content -LiteralPath (Join-Path $output ('pe-sieve-' + $mode + '.json')) -Value $rawText -Encoding utf8
            $baseline = $rawText | ConvertFrom-Json
        }
        $runs += [ordered]@{
            mode = $mode
            ground_truth = $(if ($mode -eq 'modified') { 'one_byte_executable_data_section_change' } elseif ($mode -eq 'text') { 'one_byte_text_function_change' } elseif ($mode -eq 'jit') { 'benign_private_rx' } else { 'clean_image' })
            malicious_sample = $false
            kmon_component = $kn
            baseline_exit = $baselineExit
            baseline = $baseline
        }
    }
    finally
    {
        if (-not $child.HasExited)
        {
            $child.Kill()
            $child.WaitForExit()
        }
        $child.Dispose()
    }
}
$report = [ordered]@{
    schema = 'kmon.hunting.validation.v1'
    configuration = $Configuration
    sanitizer = [bool]$Sanitize
    source_revision = (& git -C $repo rev-parse HEAD)
    source_dirty = [bool](& git -C $repo status --porcelain)
    generated_utc = [DateTime]::UtcNow.ToString('o')
    fixture_sha256 = (Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash.ToLowerInvariant()
    replay_sha256 = (Get-FileHash -LiteralPath $replay -Algorithm SHA256).Hash.ToLowerInvariant()
    synthetic_replay_sha256 = (Get-FileHash -LiteralPath $synthetic -Algorithm SHA256).Hash.ToLowerInvariant()
    baseline_version = $(if ($PeSieve) { 'pe-sieve 0.4.1.1 x64 (2025-09-13)' } else { 'not_run' })
    baseline_sha256 = $baselineHash
    baseline_arguments = '/pid <owned_fixture_pid> /quiet /json /ofilter 2 /shellc 3 /iat 3 /report 7'
    comparison_scope = 'owned user fixture; Kmon main-image executable-page component versus PE-sieve full-process output; not a detection-rate comparison'
    real_cheat_samples = 0
    independent_analyst_audit = $false
    live_kernel_channels_tested = $false
    competitive_ranking_supported = $false
    runs = $runs
}
$reportPath = Join-Path $output 'validation.json'
$report | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath $reportPath -Encoding utf8
Write-Output ('[kmon.hunting] PASS report=' + $reportPath)
