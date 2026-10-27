param()

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
            Copy-PackageFile -SourcePath $path -DestinationDir $destinationRoot -Copied $copied -Entries $entries
        }
    }
    catch { $rejected = $true }
    if (-not $rejected -or $entries.Count -ne $before -or
        (Test-Path -LiteralPath (Join-Path $destinationRoot $Name)))
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

$examplePath = Join-Path $sourceRoot ".env.example"
[IO.File]::WriteAllText($examplePath, "API_KEY=sk-replace-me")
Copy-PackageFile -SourcePath $examplePath -DestinationDir $destinationRoot -Copied $copied -Entries $entries
if (-not (Test-Path -LiteralPath (Join-Path $destinationRoot ".env.example"))) { throw "Example was lost" }
$checks++
$IncludePrivateSymbols = $true
Copy-PackageFile -SourcePath (Join-Path $sourceRoot "KnLiveDbg.pdb") -DestinationDir $destinationRoot -Copied $copied -Entries $entries
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
    Copy-PackageFile -SourcePath $public -DestinationDir $destinationRoot -Copied $copied -Entries $entries
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
                Copy-PackageFile -SourcePath $disguised -DestinationDir $destinationRoot -Copied $copied -Entries $entries
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
Write-Host "Release privacy checks passed: $checks"
