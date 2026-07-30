[CmdletBinding()]
param(
    [string]$Root = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($Root))
{
    $Root =
        Split-Path -Parent $PSScriptRoot
}

$rootPath =
    (Resolve-Path -LiteralPath $Root).Path
$buildRoot =
    Join-Path $rootPath ".build"
$validator =
    Join-Path $rootPath (
        "tools\validate-evasion-research-ledger.ps1")
$sourceLedger =
    Join-Path $rootPath (
        "research\evasion-research-ledger.json")
$testRoot =
    Join-Path $buildRoot (
        "evasion-research-ledger-selftest-" +
        [Guid]::NewGuid().ToString("N"))

function Copy-Document
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$Document
    )

    return $Document |
        ConvertTo-Json -Depth 20 |
        ConvertFrom-Json
}

function Write-Json
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$Document,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $Document |
        ConvertTo-Json -Depth 20 |
        Set-Content `
            -LiteralPath $Path `
            -Encoding UTF8
}

function Get-Sha256
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $stream =
        [IO.File]::Open(
            $Path,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read)
    $sha256 =
        [Security.Cryptography.SHA256]::Create()
    try
    {
        $hashBytes =
            $sha256.ComputeHash($stream)
    }
    finally
    {
        $sha256.Dispose()
        $stream.Dispose()
    }

    return (
        [BitConverter]::ToString(
            $hashBytes)).Replace("-", "")
}

function Get-Technique
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$Document,

        [Parameter(Mandatory = $true)]
        [string]$Id
    )

    $matches =
        @($Document.techniques |
            Where-Object {
                [string]$_.id -eq $Id
            })
    if ($matches.Count -ne 1)
    {
        throw (
            "self-test fixture expected one technique " +
            "'$Id', found $($matches.Count)")
    }

    return $matches[0]
}

function Invoke-ValidatorCase
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [object]$Document,

        [Parameter(Mandatory = $true)]
        [string]$AsOfDate,

        [Parameter(Mandatory = $true)]
        [int]$ExpectedExit,

        [string]$ExpectedPattern = "",

        [string]$ReportPath = "",

        [AllowNull()]
        [byte[]]$RawBytes = $null
    )

    $ledgerPath =
        Join-Path $testRoot (
            "ledger-$Name.json")
    $logPath =
        Join-Path $testRoot (
            "validator-$Name.log")
    if ($null -eq $RawBytes)
    {
        Write-Json `
            -Document $Document `
            -Path $ledgerPath
    }
    else
    {
        [IO.File]::WriteAllBytes(
            $ledgerPath,
            $RawBytes)
    }

    $arguments =
        @(
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            $validator,
            "-Root",
            $rootPath,
            "-LedgerPath",
            $ledgerPath,
            "-AsOfDate",
            $AsOfDate
        )
    if (-not [string]::IsNullOrWhiteSpace(
            $ReportPath))
    {
        $arguments +=
            @(
                "-ReportPath",
                $ReportPath
            )
    }

    $savedErrorPreference =
        $ErrorActionPreference
    try
    {
        $ErrorActionPreference = "Continue"
        & powershell.exe @arguments *> $logPath
        $exitCode =
            [int]$LASTEXITCODE
    }
    finally
    {
        $ErrorActionPreference =
            $savedErrorPreference
    }

    $log =
        Get-Content `
            -LiteralPath $logPath `
            -Raw
    if ($exitCode -ne $ExpectedExit)
    {
        throw (
            "case '$Name' exit mismatch: " +
            "expected=$ExpectedExit actual=$exitCode log=$log")
    }
    if (-not [string]::IsNullOrWhiteSpace(
            $ExpectedPattern) -and
        $log -notmatch $ExpectedPattern)
    {
        throw (
            "case '$Name' did not emit pattern " +
            "'$ExpectedPattern': $log")
    }

    Write-Host (
        "[evasion-research-ledger-selftest] " +
        "pass case={0} exit={1}" -f
            $Name,
            $exitCode)
}

if (-not (Test-Path `
        -LiteralPath $validator `
        -PathType Leaf))
{
    throw "validator not found: $validator"
}
if (-not (Test-Path `
        -LiteralPath $sourceLedger `
        -PathType Leaf))
{
    throw "research ledger not found: $sourceLedger"
}

New-Item `
    -ItemType Directory `
    -Path $testRoot `
    -Force |
    Out-Null

try
{
    $baseline =
        Get-Content `
            -LiteralPath $sourceLedger `
            -Raw |
        ConvertFrom-Json
    $reviewedThrough =
        [DateTime]::ParseExact(
            [string]$baseline.reviewed_through,
            "yyyy-MM-dd",
            [Globalization.CultureInfo]::InvariantCulture)
    $asOfDate =
        $reviewedThrough.ToString("yyyy-MM-dd")
    $validReport =
        Join-Path $testRoot "valid-report.json"

    Invoke-ValidatorCase `
        -Name "valid" `
        -Document (Copy-Document $baseline) `
        -AsOfDate $asOfDate `
        -ExpectedExit 0 `
        -ExpectedPattern (
            "research ledger validation passed") `
        -ReportPath $validReport
    if (-not (Test-Path `
            -LiteralPath $validReport `
            -PathType Leaf))
    {
        throw "valid case did not emit its validation report"
    }
    $report =
        Get-Content `
            -LiteralPath $validReport `
            -Raw |
        ConvertFrom-Json
    $reportedLedgerPath =
        [IO.Path]::GetFullPath(
            [string]$report.ledger_path)
    $reportedLedgerPrefix =
        [IO.Path]::GetFullPath(
            $testRoot).TrimEnd(
                [IO.Path]::DirectorySeparatorChar,
                [IO.Path]::AltDirectorySeparatorChar) +
        [IO.Path]::DirectorySeparatorChar
    if (-not $reportedLedgerPath.StartsWith(
            $reportedLedgerPrefix,
            [StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-Path `
            -LiteralPath $reportedLedgerPath `
            -PathType Leaf))
    {
        throw "valid case report referenced an unsafe ledger path"
    }
    $reportedLedgerHash =
        Get-Sha256 `
            -Path $reportedLedgerPath
    if ([string]$report.schema -ne
            "kn-live-dbg.evasion-research-ledger-validation.v1" -or
        [string]$report.as_of -ne $asOfDate -or
        [string]$report.ledger_sha256 -ne
            $reportedLedgerHash -or
        [int]$report.summary.techniques -ne
            @($baseline.techniques).Count)
    {
        throw "valid case emitted an inconsistent report"
    }

    Invoke-ValidatorCase `
        -Name "invalid-utf8" `
        -Document (Copy-Document $baseline) `
        -AsOfDate $asOfDate `
        -ExpectedExit 1 `
        -ExpectedPattern "valid UTF-8" `
        -RawBytes (
            [byte[]]@(
                0x7B,
                0x22,
                0xFF,
                0x22,
                0x7D))

    $staleAsOf =
        $reviewedThrough.AddDays(
            1 +
            [int]$baseline.refresh_policy.
                max_review_age_days).
            ToString("yyyy-MM-dd")
    Invoke-ValidatorCase `
        -Name "stale" `
        -Document (Copy-Document $baseline) `
        -AsOfDate $staleAsOf `
        -ExpectedExit 1 `
        -ExpectedPattern "research ledger is stale"

    $futureAsOf =
        $reviewedThrough.AddDays(-1).
            ToString("yyyy-MM-dd")
    Invoke-ValidatorCase `
        -Name "future-review" `
        -Document (Copy-Document $baseline) `
        -AsOfDate $futureAsOf `
        -ExpectedExit 1 `
        -ExpectedPattern "reviewed_through is in the future"

    $case =
        Copy-Document $baseline
    $case.sources[1].id =
        [string]$case.sources[0].id
    Invoke-ValidatorCase `
        -Name "duplicate-source-id" `
        -Document $case `
        -AsOfDate $asOfDate `
        -ExpectedExit 1 `
        -ExpectedPattern "duplicate source id"

    $case =
        Copy-Document $baseline
    $case.techniques[0].source_ids[0] =
        "not-a-real-source"
    Invoke-ValidatorCase `
        -Name "dangling-source" `
        -Document $case `
        -AsOfDate $asOfDate `
        -ExpectedExit 1 `
        -ExpectedPattern "references unknown source"

    $case =
        Copy-Document $baseline
    (Get-Technique `
        -Document $case `
        -Id "callback-registration-removal").
            positive_controls =
                @()
    Invoke-ValidatorCase `
        -Name "covered-without-positive" `
        -Document $case `
        -AsOfDate $asOfDate `
        -ExpectedExit 1 `
        -ExpectedPattern "must contain at least one anchor"

    $case =
        Copy-Document $baseline
    (Get-Technique `
        -Document $case `
        -Id "stateful-in-memory-evasion").
            limitations =
                @()
    Invoke-ValidatorCase `
        -Name "partial-without-limitations" `
        -Document $case `
        -AsOfDate $asOfDate `
        -ExpectedExit 1 `
        -ExpectedPattern (
            "non-covered status requires")

    $case =
        Copy-Document $baseline
    $missingTechnique =
        Get-Technique `
            -Document $case `
            -Id "poolparty-dormant-threadpool-objects"
    $coveredTechnique =
        Get-Technique `
            -Document $case `
            -Id "callback-registration-removal"
    $missingTechnique.detector_anchors =
        @(
            Copy-Document (
                $coveredTechnique.
                    detector_anchors[0])
        )
    Invoke-ValidatorCase `
        -Name "missing-with-detector" `
        -Document $case `
        -AsOfDate $asOfDate `
        -ExpectedExit 1 `
        -ExpectedPattern (
            "cannot carry implementation")

    $case =
        Copy-Document $baseline
    (Get-Technique `
        -Document $case `
        -Id "callback-registration-removal").
            detector_anchors[0].path =
                "..\README.md"
    Invoke-ValidatorCase `
        -Name "anchor-path-escape" `
        -Document $case `
        -AsOfDate $asOfDate `
        -ExpectedExit 1 `
        -ExpectedPattern "safe repository-relative path"

    $case =
        Copy-Document $baseline
    (Get-Technique `
        -Document $case `
        -Id "callback-registration-removal").
            detector_anchors[0].path =
                "user\UserModeHunter.cpp:forged"
    Invoke-ValidatorCase `
        -Name "anchor-path-ads" `
        -Document $case `
        -AsOfDate $asOfDate `
        -ExpectedExit 1 `
        -ExpectedPattern "safe repository-relative path"

    $case =
        Copy-Document $baseline
    (Get-Technique `
        -Document $case `
        -Id "callback-registration-removal").
            detector_anchors[0].path =
                "user\CON.cpp"
    Invoke-ValidatorCase `
        -Name "anchor-path-device" `
        -Document $case `
        -AsOfDate $asOfDate `
        -ExpectedExit 1 `
        -ExpectedPattern "reserved Windows device name"

    $case =
        Copy-Document $baseline
    (Get-Technique `
        -Document $case `
        -Id "callback-registration-removal").
            detector_anchors[0].contains =
                "definitely-not-present-" +
                [Guid]::NewGuid().ToString("N")
    Invoke-ValidatorCase `
        -Name "missing-anchor-literal" `
        -Document $case `
        -AsOfDate $asOfDate `
        -ExpectedExit 1 `
        -ExpectedPattern "literal was not found"

    $case =
        Copy-Document $baseline
    $case.techniques[0].claim =
        "unsupported"
    Invoke-ValidatorCase `
        -Name "claim-status-mismatch" `
        -Document $case `
        -AsOfDate $asOfDate `
        -ExpectedExit 1 `
        -ExpectedPattern "contradicts status"

    $case =
        Copy-Document $baseline
    $case.sources[0].primary =
        $false
    Invoke-ValidatorCase `
        -Name "non-primary-source" `
        -Document $case `
        -AsOfDate $asOfDate `
        -ExpectedExit 1 `
        -ExpectedPattern "primary must be true"

    $case =
        Copy-Document $baseline
    $case.sources[0].url =
        "http://example.invalid/research"
    Invoke-ValidatorCase `
        -Name "non-https-source" `
        -Document $case `
        -AsOfDate $asOfDate `
        -ExpectedExit 1 `
        -ExpectedPattern "absolute HTTPS URL"

    $case =
        Copy-Document $baseline
    $case.completion_gate.required_technique_ids[0] =
        "not-a-real-technique"
    Invoke-ValidatorCase `
        -Name "unknown-completion-technique" `
        -Document $case `
        -AsOfDate $asOfDate `
        -ExpectedExit 1 `
        -ExpectedPattern (
            "references unknown technique")

    $case =
        Copy-Document $baseline
    (Get-Technique `
        -Document $case `
        -Id "stateful-in-memory-evasion").
            release_gate =
                "not_applicable"
    Invoke-ValidatorCase `
        -Name "partial-not-applicable" `
        -Document $case `
        -AsOfDate $asOfDate `
        -ExpectedExit 1 `
        -ExpectedPattern (
            "partial status cannot use not_applicable")

    $case =
        Copy-Document $baseline
    (Get-Technique `
        -Document $case `
        -Id "callback-registration-removal").
            validation_commands[0] =
                ".\tool.ps1; Remove-Item x"
    Invoke-ValidatorCase `
        -Name "unsafe-command" `
        -Document $case `
        -AsOfDate $asOfDate `
        -ExpectedExit 1 `
        -ExpectedPattern "unsafe validation command"

    $escapedReport =
        Join-Path $rootPath (
            "evasion-research-ledger-" +
            [Guid]::NewGuid().ToString("N") +
            ".json")
    Invoke-ValidatorCase `
        -Name "report-path-escape" `
        -Document (Copy-Document $baseline) `
        -AsOfDate $asOfDate `
        -ExpectedExit 1 `
        -ExpectedPattern "escapes its required parent" `
        -ReportPath $escapedReport

    $adsReport =
        Join-Path $buildRoot (
            "evasion-research-ledger-report.json:forged")
    Invoke-ValidatorCase `
        -Name "report-path-ads" `
        -Document (Copy-Document $baseline) `
        -AsOfDate $asOfDate `
        -ExpectedExit 1 `
        -ExpectedPattern "alternate data stream" `
        -ReportPath $adsReport

    Write-Host (
        "evasion research ledger self-test passed")
}
finally
{
    if (Test-Path `
            -LiteralPath $testRoot `
            -PathType Container)
    {
        $resolvedTestRoot =
            (Resolve-Path `
                -LiteralPath $testRoot).Path
        $resolvedBuildRoot =
            (Resolve-Path `
                -LiteralPath $buildRoot).Path
        $expectedPrefix =
            $resolvedBuildRoot.
                TrimEnd(
                    [IO.Path]::DirectorySeparatorChar,
                    [IO.Path]::AltDirectorySeparatorChar) +
            [IO.Path]::DirectorySeparatorChar
        $leaf =
            Split-Path `
                -Leaf $resolvedTestRoot
        if (-not $resolvedTestRoot.StartsWith(
                $expectedPrefix,
                [StringComparison]::OrdinalIgnoreCase) -or
            -not $leaf.StartsWith(
                "evasion-research-ledger-selftest-",
                [StringComparison]::Ordinal))
        {
            throw (
                "refusing unsafe self-test cleanup: " +
                $resolvedTestRoot)
        }
        Remove-Item `
            -LiteralPath $resolvedTestRoot `
            -Recurse `
            -Force
    }
}

exit 0
