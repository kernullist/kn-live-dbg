param(
    [string]$PythonExecutable = "python",
    [switch]$KeepFixtures
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot "release.ps1"), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw "release.ps1 has syntax errors" }
# Load real packaging functions without executing builds or changing release assets.
foreach ($function in $ast.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst]
        }, $false))
{
    Invoke-Expression $function.Extent.Text
}
$validator = Join-Path $PSScriptRoot "validate-public-content.py"
$packagePathRules = Get-PackagePathRules -PythonExecutable $PythonExecutable -ValidatorPath $validator
$buildRoot = Join-Path $repo ".build"
$fixtureName = "release-privacy-selftest-" + [Guid]::NewGuid().ToString("N")
$fixtureRelative = Join-Path ".build" $fixtureName
$testRoot = Join-Path $buildRoot $fixtureName
$sourceRoot = Join-Path $testRoot "source"
$destinationRoot = Join-Path $testRoot "package"
$contentRoot = Join-Path $testRoot "content-control"
$fixtureFiles = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$fixtureDirs = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($directory in @($sourceRoot, $destinationRoot, $contentRoot)) { [void]$fixtureDirs.Add($directory) }

function Get-FixtureFile
{
    param([string]$Directory, [string]$Name)
    $path = Get-FullPath -Path (Join-Path $Directory $Name)
    Assert-UnderPath -BasePath $testRoot -ChildPath $path
    if (-not $fixtureFiles.Contains($path))
    {
        if (Test-Path -LiteralPath $path) { throw "Fixture output already exists: $path" }
        [void]$fixtureFiles.Add($path)
    }
    $parent = [IO.Path]::GetDirectoryName($path)
    while ($parent -ne $testRoot -and $fixtureDirs.Add($parent))
    {
        $parent = [IO.Path]::GetDirectoryName($parent)
    }
    return $path
}

function Remove-FixtureFiles
{
    Assert-UnderPath -BasePath $buildRoot -ChildPath $testRoot
    Assert-NoReparsePointPath -Root $repo -RelativePath $fixtureRelative -Context "release privacy fixture cleanup"
    Assert-NoReparsePointTree -Path $testRoot -Context "release privacy fixture cleanup"
    foreach ($file in $fixtureFiles)
    {
        if ([IO.File]::Exists($file)) { [IO.File]::Delete($file) }
    }
    # Nonrecursive removal preserves any unregistered file, including inside a fixture directory.
    foreach ($directory in $fixtureDirs | Sort-Object Length -Descending)
    {
        if ([IO.Directory]::Exists($directory)) { [IO.Directory]::Delete($directory) }
    }
}

Assert-UnderPath -BasePath $buildRoot -ChildPath $testRoot
Assert-NoReparsePointPath -Root $repo -RelativePath $fixtureRelative -Context "release privacy fixtures"
# Acquire a new directory. A collision must fail before the cleanup boundary.
New-Item -ItemType Directory -Path $testRoot -ErrorAction Stop | Out-Null
$runLease = $null
$validationError = $null
try
{
    $runLease = [IO.FileStream]::new((Join-Path $testRoot ".fixture-owner"), [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write, [IO.FileShare]::None, 4096, [IO.FileOptions]::DeleteOnClose)
    New-Item -ItemType Directory -Path $sourceRoot, $destinationRoot -Force | Out-Null
    $IncludePrivateSymbols = $false
    $copied = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $entries = [Collections.Generic.List[object]]::new()
    $checks = 0

    function Assert-RejectedCopy
    {
        param([string]$Name, [switch]$Relative)
        $path = Get-FixtureFile $sourceRoot $Name
        New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force | Out-Null
        [IO.File]::WriteAllText($path, "synthetic fixture")
        $before = $entries.Count
        $copiedBefore = $copied.Count
        $destinationName = if ($Relative) { $Name } else { Split-Path -Leaf $Name }
        $destination = Join-Path $destinationRoot $destinationName
        $rejected = $false
        try
        {
            if ($Relative)
            {
                Copy-PackageRelativeFile -SourceRoot $sourceRoot -DestinationRoot $destinationRoot `
                    -RelativePath $Name -Entries $entries
            }
            else
            {
                Copy-PackageFile -SourceRoot $sourceRoot -SourcePath $path -DestinationDir $destinationRoot -Copied $copied -Entries $entries
            }
        }
        catch
        {
            if ($_.Exception.Message -notin @("Private directory cannot be packaged", "Private input cannot be packaged",
                    "Private symbols require -IncludePrivateSymbols")) { throw }
            $rejected = $true
        }
        if (-not $rejected -or $entries.Count -ne $before -or $copied.Count -ne $copiedBefore -or
            (Test-Path -LiteralPath $destination))
        {
            throw "Private input was not rejected before copy"
        }
        $script:checks++
    }

    foreach ($name in @(".env", ".env.production", "auth.json", "mcp-endpoint.json",
            "signing.pfx", "signing.pem", "capture.dmp", "session.log", "KnLiveDbg.pdb"))
    {
        Assert-RejectedCopy -Name $name
    }
    foreach ($name in @("docs\.env.local", "research\signing.key", ".build\evidence.json",
            "logs\capture.json", ".kn-live-dbg\state.json", "tools\target.pdb"))
    {
        Assert-RejectedCopy -Name $name -Relative
    }
    # Use the declared extensions as inputs, independent of how the scanner turns them into patterns.
    $extensions = @(& $PythonExecutable -B -c "import runpy,sys; print(*sorted(runpy.run_path(sys.argv[1])['PRIVATE_EXTENSIONS']), sep=chr(10))" $validator)
    if ($LASTEXITCODE -ne 0 -or ".kncase" -notin $extensions -or ".etl" -notin $extensions) { throw "Missing test extensions" }
    foreach ($extension in $extensions)
    {
        foreach ($relative in @($false, $true))
        {
            Assert-RejectedCopy -Name ("attachments/record" + $extension.ToUpperInvariant()) -Relative:$relative
            if ($extension.StartsWith(".kn"))
            {
                Assert-RejectedCopy -Name ("attachments/record" + $extension + ".PENDING-7.part") -Relative:$relative
            }
        }
    }
    foreach ($name in @("samples/session.log.ll", "source.etl.zip", "system.evtx.zip", "ops.knmcpjournal.tmp.3", "ops.knmcpjournal",
            "truth.kncampaign-wal", "input.kncampaign-shm", "input.kncampaign-journal", "case.kncampaign", "report.knruns",
            ".knbench-owned.tmp", "logs/private.txt", ".knbench-etl-owned/rows.txt", ".kniat-replay-owned/fragment.bin", "docs/SYMBOLS/note.txt", ".pem"))
    {
        Assert-RejectedCopy -Name $name
        Assert-RejectedCopy -Name $name -Relative
    }
    foreach ($name in @("docs/case.kncase.md", "docs/.knbench-etl-notes.txt", "docs/environment.example", "docs/guide [v2].txt"))
    {
        $path = Get-FixtureFile $sourceRoot $name
        $flatCopy = Get-FixtureFile $destinationRoot (Split-Path -Leaf $name)
        $relativeCopy = Get-FixtureFile $destinationRoot $name
        [IO.File]::WriteAllText($path, "public fixture")
        Copy-PackageFile -SourceRoot $sourceRoot -SourcePath $path -DestinationDir $destinationRoot -Copied $copied -Entries $entries
        Copy-PackageRelativeFile -SourceRoot $sourceRoot -DestinationRoot $destinationRoot -RelativePath $name -Entries $entries
        foreach ($packageFile in @($flatCopy, $relativeCopy))
        {
            if ([IO.File]::ReadAllText($packageFile) -cne "public fixture") { throw "Public copy changed" }
            $checks++
        }
    }

    $examplePath = Get-FixtureFile $sourceRoot ".env.example"
    $exampleCopy = Get-FixtureFile $destinationRoot ".env.example"
    [IO.File]::WriteAllText($examplePath, "API_KEY=sk-replace-me")
    Copy-PackageFile -SourceRoot $sourceRoot -SourcePath $examplePath -DestinationDir $destinationRoot -Copied $copied -Entries $entries
    if (-not (Test-Path -LiteralPath $exampleCopy)) { throw "Example was lost" }
    $checks++
    $IncludePrivateSymbols = $true
    $null = Get-FixtureFile $destinationRoot "KnLiveDbg.pdb"
    $null = Get-FixtureFile $destinationRoot "tools\target.pdb"
    Copy-PackageFile -SourceRoot $sourceRoot -SourcePath (Join-Path $sourceRoot "KnLiveDbg.pdb") -DestinationDir $destinationRoot -Copied $copied -Entries $entries
    Copy-PackageRelativeFile -SourceRoot $sourceRoot -DestinationRoot $destinationRoot -RelativePath "tools\target.pdb" -Entries $entries
    $checks += 2
    $IncludePrivateSymbols = $false

    # Generate a disposable certificate in memory; do not touch machine/user stores.
    $disguised = Get-FixtureFile $sourceRoot "private-container.cer"
    $rsa = [Security.Cryptography.RSACng]::new(2048)
    $certificate = $null
    try
    {
        $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
            "CN=KnLiveDbg Publication Test", $rsa,
            [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $certificate = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-1), [DateTimeOffset]::UtcNow.AddHours(1))
        $public = Get-FixtureFile $sourceRoot "public.cer"
        $null = Get-FixtureFile $destinationRoot "public.cer"
        $disguisedCopy = Join-Path $destinationRoot "private-container.cer"
        [IO.File]::WriteAllBytes($public, $certificate.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert))
        Copy-PackageFile -SourceRoot $sourceRoot -SourcePath $public -DestinationDir $destinationRoot -Copied $copied -Entries $entries
        $checks++
        [IO.File]::WriteAllBytes($disguised, $certificate.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pfx))
        foreach ($relative in @($false, $true))
        {
            $rejected = $false
            try
            {
                if ($relative)
                {
                    Copy-PackageRelativeFile -SourceRoot $sourceRoot -DestinationRoot $destinationRoot `
                        -RelativePath "private-container.cer" -Entries $entries
                }
                else
                {
                    Copy-PackageFile -SourceRoot $sourceRoot -SourcePath $disguised -DestinationDir $destinationRoot -Copied $copied -Entries $entries
                }
            }
            catch { $rejected = $true }
            if (-not $rejected -or (Test-Path -LiteralPath $disguisedCopy))
            {
                throw "A renamed private-key container entered the package"
            }
            $checks++
        }
    }
    finally
    {
        try
        {
            if (Test-Path -LiteralPath $disguised) { Remove-Item -LiteralPath $disguised -Force }
        }
        finally
        {
            if ($null -ne $certificate) { $certificate.Dispose() }
            $rsa.Dispose()
        }
    }
    # Exercise the same final content check and ZIP writer with an owned package.
    $reportPath = Get-FixtureFile $testRoot "inspection.json"
    $null = & $PythonExecutable -B $validator --tree --root $destinationRoot --report $reportPath --allow-private-symbols
    if ($LASTEXITCODE -ne 0) { throw "Public fixture tree failed its final inspection" }
    $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    if (-not $report.passed -or $report.files -ne $entries.Count -or $report.findings.Count) { throw "Incorrect package report" }
    $zipPath = Get-FixtureFile $testRoot "fixture.zip"
    New-ZipFromDirectory -SourceDir $destinationRoot -ZipPath $zipPath
    $archive = [IO.Compression.ZipFile]::OpenRead($zipPath)
    $zipHash = $null
    try
    {
        $zipHash = [Security.Cryptography.SHA256]::Create()
        if ($archive.Entries.Count -ne $entries.Count) { throw "ZIP entry count changed" }
        foreach ($item in $entries)
        {
            $entry = $archive.GetEntry($item.name)
            if ($null -eq $entry -or $entry.Length -ne $item.size) { throw "ZIP member changed" }
            $stream = $entry.Open()
            try { $digest = [BitConverter]::ToString($zipHash.ComputeHash($stream)).Replace("-", "") }
            finally { $stream.Dispose() }
            if ($digest -cne $item.sha256) { throw "ZIP digest changed" }
            $checks++
        }
    }
    finally
    {
        if ($null -ne $zipHash) { $zipHash.Dispose() }
        $archive.Dispose()
    }

    # A public name can still contain private bytes. A first relative copy must work with an empty manifest.
    New-Item -ItemType Directory -Path $contentRoot | Out-Null
    [IO.File]::WriteAllText((Get-FixtureFile $sourceRoot "renamed.txt"), "sk-" + ("x" * 32))
    $null = Get-FixtureFile $contentRoot "renamed.txt"
    $contentEntries = [Collections.Generic.List[object]]::new()
    Copy-PackageRelativeFile -SourceRoot $sourceRoot -DestinationRoot $contentRoot -RelativePath "renamed.txt" -Entries $contentEntries
    if ($contentEntries.Count -ne 1) { throw "First relative copy missing" }
    $null = & $PythonExecutable -B $validator --tree --root $contentRoot --report $reportPath
    if ($LASTEXITCODE -ne 1) { throw "Final inspection missed private content under a public name" }
    $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    if ($report.passed -or $report.files -ne 1 -or $report.findings.rule -notcontains "provider-token") { throw "Incorrect private-content result" }
    $checks++

    $fixtureValidator = Get-FixtureFile $testRoot "fixture-validator.py"
    foreach ($program in @("raise SystemExit(2)", "print('not json')", "print('{}')",
            "import json; print(json.dumps(dict(schema='old', directory='x', file='y')))",
            "import json; print(json.dumps(dict(schema='kn.publication_path_rules.v1', directory='', file='y')))",
            "import json; print(json.dumps(dict(schema='kn.publication_path_rules.v1', directory='[', file='y')))"))
    {
        [IO.File]::WriteAllText($fixtureValidator, $program)
        $denied = $false
        try { $null = Get-PackagePathRules -PythonExecutable $PythonExecutable -ValidatorPath $fixtureValidator }
        catch { $denied = $true }
        if (-not $denied) { throw "Invalid path rule output was accepted" }
        $checks++
    }
}
catch
{
    $validationError = $_
    throw
}
finally
{
    try
    {
        try
        {
            if (-not $KeepFixtures -and $null -ne $runLease) { Remove-FixtureFiles }
        }
        finally
        {
            if ($null -ne $runLease) { $runLease.Dispose() }
        }
        if ($KeepFixtures) { Write-Host "Kept release privacy fixtures in $fixtureRelative" }
        else
        {
            Assert-NoReparsePointPath -Root $repo -RelativePath $fixtureRelative -Context "release privacy fixture cleanup"
            [IO.Directory]::Delete($testRoot)
        }
    }
    catch
    {
        if ($null -eq $validationError) { throw }
        Write-Warning ("Release privacy fixture cleanup failed. " + $_.Exception.Message)
    }
}
Write-Host "Release privacy checks passed: $checks"
