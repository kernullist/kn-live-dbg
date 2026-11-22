param([string]$PythonExecutable = "python")

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
$testRoot = Join-Path $repo (".build\release-privacy-selftest-" + [Guid]::NewGuid().ToString("N"))
Assert-UnderPath -BasePath (Join-Path $repo ".build") -ChildPath $testRoot
$sourceRoot = Join-Path $testRoot "source"
$destinationRoot = Join-Path $testRoot "package"
New-Item -ItemType Directory -Path $sourceRoot, $destinationRoot -Force | Out-Null
$IncludePrivateSymbols = $false
$copied = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$entries = [Collections.Generic.List[object]]::new()
$checks = 0

function Assert-RejectedCopy
{
    param([string]$Name, [switch]$Relative)
    $path = Join-Path $sourceRoot $Name
    New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force | Out-Null
    [IO.File]::WriteAllText($path, "synthetic fixture")
    $before = $entries.Count
    $copiedBefore = $copied.Count
    $destinationName = if ($Relative) { $Name } else { Split-Path -Leaf $Name }
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
        (Test-Path -LiteralPath (Join-Path $destinationRoot $destinationName)))
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
foreach ($name in @("samples/session.log.ll", "source.etl.zip", "ops.knmcpjournal.tmp.3", "ops.knmcpjournal",
        "truth.kncampaign-wal", "input.kncampaign-shm", "input.kncampaign-journal", "case.kncampaign", "report.knruns",
        ".knbench-owned.tmp", "logs/private.txt", ".knbench-etl-owned/rows.txt", "docs/SYMBOLS/note.txt", ".pem"))
{
    Assert-RejectedCopy -Name $name
    Assert-RejectedCopy -Name $name -Relative
}
foreach ($name in @("docs/case.kncase.md", "docs/.knbench-etl-notes.txt", "docs/environment.example", "docs/guide [v2].txt"))
{
    $path = Join-Path $sourceRoot $name
    [IO.File]::WriteAllText($path, "public fixture")
    Copy-PackageFile -SourceRoot $sourceRoot -SourcePath $path -DestinationDir $destinationRoot -Copied $copied -Entries $entries
    Copy-PackageRelativeFile -SourceRoot $sourceRoot -DestinationRoot $destinationRoot -RelativePath $name -Entries $entries
    foreach ($packageName in @((Split-Path -Leaf $name), $name))
    {
        if ([IO.File]::ReadAllText((Join-Path $destinationRoot $packageName)) -cne "public fixture") { throw "Public copy changed" }
        $checks++
    }
}

$examplePath = Join-Path $sourceRoot ".env.example"
[IO.File]::WriteAllText($examplePath, "API_KEY=sk-replace-me")
Copy-PackageFile -SourceRoot $sourceRoot -SourcePath $examplePath -DestinationDir $destinationRoot -Copied $copied -Entries $entries
if (-not (Test-Path -LiteralPath (Join-Path $destinationRoot ".env.example"))) { throw "Example was lost" }
$checks++
$IncludePrivateSymbols = $true
Copy-PackageFile -SourceRoot $sourceRoot -SourcePath (Join-Path $sourceRoot "KnLiveDbg.pdb") -DestinationDir $destinationRoot -Copied $copied -Entries $entries
Copy-PackageRelativeFile -SourceRoot $sourceRoot -DestinationRoot $destinationRoot -RelativePath "tools\target.pdb" -Entries $entries
$checks += 2
$IncludePrivateSymbols = $false

# Generate a disposable certificate in memory; do not touch machine/user stores.
$rsa = [Security.Cryptography.RSACng]::new(2048)
$certificate = $null
$disguised = Join-Path $sourceRoot "private-container.cer"
try
{
    $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
        "CN=KnLiveDbg Publication Test", $rsa,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $certificate = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-1), [DateTimeOffset]::UtcNow.AddHours(1))
    $public = Join-Path $sourceRoot "public.cer"
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
        if (-not $rejected -or (Test-Path -LiteralPath (Join-Path $destinationRoot "private-container.cer")))
        {
            throw "A renamed private-key container entered the package"
        }
        $checks++
    }
}
finally
{
    if (Test-Path -LiteralPath $disguised) { Remove-Item -LiteralPath $disguised -Force }
    if ($null -ne $certificate) { $certificate.Dispose() }
    $rsa.Dispose()
}
# Exercise the same final content check and ZIP writer with an owned package.
$reportPath = Join-Path $testRoot "inspection.json"
$null = & $PythonExecutable -B $validator --tree --root $destinationRoot --report $reportPath --allow-private-symbols
if ($LASTEXITCODE -ne 0) { throw "Public fixture tree failed its final inspection" }
$report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
if (-not $report.passed -or $report.files -ne $entries.Count -or $report.findings.Count) { throw "Incorrect package report" }
$zipPath = Join-Path $testRoot "fixture.zip"
New-ZipFromDirectory -SourceDir $destinationRoot -ZipPath $zipPath
$archive = [IO.Compression.ZipFile]::OpenRead($zipPath)
try
{
    if ($archive.Entries.Count -ne $entries.Count) { throw "ZIP entry count changed" }
    foreach ($item in $entries)
    {
        $entry = $archive.GetEntry($item.name)
        if ($null -eq $entry -or $entry.Length -ne $item.size) { throw "ZIP member changed" }
        $stream = $entry.Open()
        try { $digest = (Get-FileHash -Algorithm SHA256 -InputStream $stream).Hash }
        finally { $stream.Dispose() }
        if ($digest -cne $item.sha256) { throw "ZIP digest changed" }
        $checks++
    }
}
finally { $archive.Dispose() }

# A public name can still contain private bytes. A first relative copy must work with an empty manifest.
$contentRoot = Join-Path $testRoot "content-control"
New-Item -ItemType Directory -Path $contentRoot | Out-Null
[IO.File]::WriteAllText((Join-Path $sourceRoot "renamed.txt"), "sk-" + ("x" * 32))
$contentEntries = [Collections.Generic.List[object]]::new()
Copy-PackageRelativeFile -SourceRoot $sourceRoot -DestinationRoot $contentRoot -RelativePath "renamed.txt" -Entries $contentEntries
if ($contentEntries.Count -ne 1) { throw "First relative copy missing" }
$null = & $PythonExecutable -B $validator --tree --root $contentRoot --report $reportPath
if ($LASTEXITCODE -ne 1) { throw "Final inspection missed private content under a public name" }
$report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
if ($report.passed -or $report.files -ne 1 -or $report.findings.rule -notcontains "provider-token") { throw "Incorrect private-content result" }
$checks++

$fixtureValidator = Join-Path $testRoot "fixture-validator.py"
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
Write-Host "Release privacy checks passed: $checks"
