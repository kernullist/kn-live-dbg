param(
    [string]$Root = (Get-Location).Path
)

$ErrorActionPreference = "Stop"

$rootPath = (Resolve-Path -LiteralPath $Root).Path
$analyzer = Join-Path $rootPath "tools\analyze-hunt-clean-host.ps1"
$outputDirectory = Join-Path $rootPath ".build\hunt-clean-host-analysis-selftest"
New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null

function New-Finding
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Reason,

        [Parameter(Mandatory = $true)]
        [string]$Image,

        [Parameter(Mandatory = $true)]
        [int]$ProcessId,

        [Parameter(Mandatory = $true)]
        [string]$Address
    )

    return [ordered]@{
        risk = "low"
        confidence = "medium"
        class = "mapped_code"
        title = "synthetic finding"
        pid = $ProcessId
        eprocess = "0xffff000000000000"
        address = $Address
        image = $Image
        module = ""
        reasons = @($Reason)
        evidence = [ordered]@{
            vad = $Address
            semantic = $Reason
        }
        followups = @()
    }
}

function New-HuntDocument
{
    param(
        [object[]]$Findings = @(),
        [bool]$CoverageComplete = $true,
        [string]$Timestamp = "2026-07-28T00:00:00.000Z"
    )

    return [ordered]@{
        schema = "kn-live-dbg.hunt.v1"
        timestamp_utc = $Timestamp
        mode = "default"
        summary = [ordered]@{
            kernel_processes = 100
            system_process_information_processes = 100
            toolhelp_processes = 100
            scanned_processes = 100
            findings = $Findings.Count
            high = 0
            medium = 0
            low = $Findings.Count
            info = 0
            process_inventory_incomplete = $false
            process_triage_coverage_incomplete = -not $CoverageComplete
            deep_image_comparison_coverage_incomplete = $false
            driver_service_coverage_incomplete = $false
            threat_intel_active = $false
            threat_intel_available = $false
            threat_intel_correlation_incomplete = $false
            coverage_complete = $CoverageComplete
        }
        warnings = @()
        findings = $Findings
        processes = @()
    }
}

function Invoke-AnalyzerFailureCase
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [object]$Document,

        [switch]$RequireThreatIntelActive
    )

    $path = Join-Path $outputDirectory "$Name.json"
    $reportPath = Join-Path $outputDirectory "$Name-report.json"
    $Document |
        ConvertTo-Json -Depth 12 |
        Set-Content -LiteralPath $path -Encoding UTF8
    Remove-Item -LiteralPath $reportPath -Force -ErrorAction SilentlyContinue

    $failed = $false
    try
    {
        if ($RequireThreatIntelActive)
        {
            & $analyzer -HuntJson $path -OutputJson $reportPath -RequireThreatIntelActive *> $null
        }
        else
        {
            & $analyzer -HuntJson $path -OutputJson $reportPath *> $null
        }
    }
    catch
    {
        $failed = $true
    }
    if (-not $failed)
    {
        throw "$Name expected analyzer failure"
    }
    if (Test-Path -LiteralPath $reportPath)
    {
        throw "$Name wrote a report for rejected input"
    }
    Write-Host "[hunt-clean-analyzer-selftest] pass case=$Name"
}

$sharedRun1 = New-Finding -Reason "shared_reason" -Image "C:\Windows\clean.exe" -ProcessId 1001 -Address "0x1000"
$sharedRun2 = New-Finding -Reason "shared_reason" -Image "D:\Different\CLEAN.EXE" -ProcessId 2002 -Address "0x9000"
$intermittent = New-Finding -Reason "intermittent_reason" -Image "other.exe" -ProcessId 1002 -Address "0x2000"

$run1Path = Join-Path $outputDirectory "findings-run-01.json"
$run2Path = Join-Path $outputDirectory "findings-run-02.json"
$reportPath = Join-Path $outputDirectory "findings-report.json"
New-HuntDocument -Findings @($sharedRun1, $intermittent) |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $run1Path -Encoding UTF8
New-HuntDocument -Findings @($sharedRun2) -Timestamp "2026-07-28T00:01:00.000Z" |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $run2Path -Encoding UTF8

& $analyzer -HuntJson @($run1Path, $run2Path) -OutputJson $reportPath
$report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
if ([int]$report.summary.run_count -ne 2 -or
    [int]$report.summary.total_findings -ne 3 -or
    [int]$report.summary.unique_fingerprints -ne 2 -or
    [int]$report.summary.deterministic_fingerprints -ne 1 -or
    [int]$report.summary.intermittent_fingerprints -ne 1 -or
    [bool]$report.summary.all_clean_complete)
{
    throw "finding recurrence analysis contract failed"
}

$deterministic = @($report.finding_groups | Where-Object { $_.recurrence -eq "deterministic" })
if ($deterministic.Count -ne 1 -or
    [int]$deterministic[0].run_hits -ne 2 -or
    [string]$deterministic[0].image -ne "clean.exe")
{
    throw "semantic fingerprint did not normalize PID/address/path differences"
}

$cleanRun1Path = Join-Path $outputDirectory "clean-run-01.json"
$cleanRun2Path = Join-Path $outputDirectory "clean-run-02.json"
$cleanReportPath = Join-Path $outputDirectory "clean-report.json"
New-HuntDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $cleanRun1Path -Encoding UTF8
New-HuntDocument -Timestamp "2026-07-28T00:02:00.000Z" |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $cleanRun2Path -Encoding UTF8

$cleanWildcard = Join-Path $outputDirectory "clean-run-*.json"
& $analyzer -HuntJson @($cleanWildcard, $cleanRun1Path) -OutputJson $cleanReportPath
$cleanReport = Get-Content -LiteralPath $cleanReportPath -Raw | ConvertFrom-Json
if (-not [bool]$cleanReport.summary.all_clean_complete -or
    [int]$cleanReport.summary.unique_fingerprints -ne 0 -or
    [int]$cleanReport.summary.run_count -ne 2)
{
    throw "clean wildcard/deduplication analysis contract failed"
}

$threatIntelRunPath = Join-Path $outputDirectory "threat-intel-run.json"
$threatIntelReportPath = Join-Path $outputDirectory "threat-intel-report.json"
$threatIntelRun = New-HuntDocument
$threatIntelRun.summary.threat_intel_active = $true
$threatIntelRun.summary.threat_intel_available = $true
$threatIntelRun |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $threatIntelRunPath -Encoding UTF8
& $analyzer -HuntJson $threatIntelRunPath -OutputJson $threatIntelReportPath -RequireThreatIntelActive
if (-not (Test-Path -LiteralPath $threatIntelReportPath))
{
    throw "required threat-intel analyzer case did not write a report"
}

$incompleteRunPath = Join-Path $outputDirectory "incomplete-run.json"
$incompleteReportPath = Join-Path $outputDirectory "incomplete-report.json"
New-HuntDocument -CoverageComplete $false |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $incompleteRunPath -Encoding UTF8
& $analyzer -HuntJson @($cleanRun1Path, $incompleteRunPath) -OutputJson $incompleteReportPath
$incompleteReport = Get-Content -LiteralPath $incompleteReportPath -Raw | ConvertFrom-Json
if ([bool]$incompleteReport.summary.all_clean_complete -or
    [int]$incompleteReport.summary.complete_runs -ne 1)
{
    throw "incomplete coverage was incorrectly promoted to clean"
}

$wrongBoolean = New-HuntDocument
$wrongBoolean.summary.coverage_complete = "false"
Invoke-AnalyzerFailureCase -Name "wrong-boolean-type" -Document $wrongBoolean

$wrongInteger = New-HuntDocument
$wrongInteger.summary.findings = "0"
Invoke-AnalyzerFailureCase -Name "wrong-integer-type" -Document $wrongInteger

$riskMismatch = New-HuntDocument
$riskMismatch.summary.high = 1
Invoke-AnalyzerFailureCase -Name "risk-count-mismatch" -Document $riskMismatch

$coverageConflict = New-HuntDocument
$coverageConflict.summary.process_inventory_incomplete = $true
Invoke-AnalyzerFailureCase -Name "coverage-flag-conflict" -Document $coverageConflict

$threatIntelConflict = New-HuntDocument
$threatIntelConflict.summary.threat_intel_correlation_incomplete = $true
Invoke-AnalyzerFailureCase -Name "threat-intel-coverage-conflict" -Document $threatIntelConflict

$activeUnavailable = New-HuntDocument
$activeUnavailable.summary.threat_intel_active = $true
Invoke-AnalyzerFailureCase -Name "threat-intel-active-unavailable" -Document $activeUnavailable

$inactiveAvailable = New-HuntDocument
$inactiveAvailable.summary.threat_intel_available = $true
Invoke-AnalyzerFailureCase -Name "threat-intel-inactive-required" -Document $inactiveAvailable -RequireThreatIntelActive

$nonArray = New-HuntDocument
$nonArray.findings = [ordered]@{}
Invoke-AnalyzerFailureCase -Name "findings-not-array" -Document $nonArray

$inputHashBefore =
    (Get-FileHash -LiteralPath $cleanRun1Path -Algorithm SHA256).Hash
$inputCollisionRejected = $false
try
{
    & $analyzer `
        -HuntJson $cleanRun1Path `
        -OutputJson $cleanRun1Path *> $null
}
catch
{
    $inputCollisionRejected = $true
}
$inputHashAfter =
    (Get-FileHash -LiteralPath $cleanRun1Path -Algorithm SHA256).Hash
if (-not $inputCollisionRejected -or
    $inputHashBefore -ne $inputHashAfter)
{
    throw "analyzer did not reject an output path that aliases its input"
}
Write-Host "[hunt-clean-analyzer.selftest] pass case=input-output-path-collision"

$sharedOutputPath = Join-Path $outputDirectory "shared-output-path.json"
Remove-Item -LiteralPath $sharedOutputPath -Force -ErrorAction SilentlyContinue
$outputCollisionRejected = $false
try
{
    & $analyzer `
        -HuntJson $cleanRun1Path `
        -OutputJson $sharedOutputPath `
        -OutputMarkdown $sharedOutputPath *> $null
}
catch
{
    $outputCollisionRejected = $true
}
if (-not $outputCollisionRejected -or
    (Test-Path -LiteralPath $sharedOutputPath))
{
    throw "analyzer did not reject colliding JSON and Markdown outputs before writing"
}
Write-Host "[hunt-clean-analyzer.selftest] pass case=report-output-path-collision"

Write-Host "hunt clean-host analyzer self-test passed"
