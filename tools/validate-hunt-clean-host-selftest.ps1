param(
    [string]$Root = (Get-Location).Path
)

$ErrorActionPreference = "Stop"

$rootPath = (Resolve-Path -LiteralPath $Root).Path
$validator = Join-Path $rootPath "tools\validate-hunt-clean-host.ps1"
$outputDirectory = Join-Path $rootPath ".build\hunt-clean-host-validator-selftest"
New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null

function New-HuntDocument
{
    param(
        [bool]$CoverageComplete = $true,
        [object[]]$Findings = @()
    )

    $riskCounts = @{
        high = @($Findings | Where-Object { $_.risk -eq "high" }).Count
        medium = @($Findings | Where-Object { $_.risk -eq "medium" }).Count
        low = @($Findings | Where-Object { $_.risk -eq "low" }).Count
        info = @($Findings | Where-Object { $_.risk -eq "info" }).Count
    }

    return [ordered]@{
        schema = "kn-live-dbg.hunt.v1"
        timestamp_utc = "2026-07-28T00:00:00.000Z"
        mode = "deep"
        summary = [ordered]@{
            kernel_processes = 100
            system_process_information_processes = 100
            toolhelp_processes = 100
            scanned_processes = 100
            findings = $Findings.Count
            high = $riskCounts.high
            medium = $riskCounts.medium
            low = $riskCounts.low
            info = $riskCounts.info
            process_inventory_incomplete = $false
            process_triage_coverage_incomplete = $false
            deep_image_comparison_coverage_incomplete = $false
            driver_service_coverage_incomplete = $false
            threat_intel_active = $true
            threat_intel_available = $true
            threat_intel_correlation_incomplete = $false
            coverage_complete = $CoverageComplete
        }
        warnings = @()
        findings = $Findings
        processes = @()
    }
}

function Invoke-ValidatorCase
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [bool]$ExpectSuccess,

        [ValidateSet("Any", "Quick", "Default", "Deep")]
        [string]$RequireMode = "Deep",

        [switch]$RequireThreatIntelActive
    )

    $logPath = Join-Path $outputDirectory "$Name.log"
    $validatorArguments = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $validator,
        "-HuntJson", $Path,
        "-RequireMode", $RequireMode
    )
    if ($RequireThreatIntelActive)
    {
        $validatorArguments +=
            "-RequireThreatIntelActive"
    }
    & powershell.exe @validatorArguments *> $logPath
    $exitCode = $LASTEXITCODE

    if ($ExpectSuccess -and $exitCode -ne 0)
    {
        Get-Content -LiteralPath $logPath | Out-Host
        throw "$Name expected success, exit=$exitCode"
    }
    if (-not $ExpectSuccess -and $exitCode -eq 0)
    {
        Get-Content -LiteralPath $logPath | Out-Host
        throw "$Name expected failure"
    }

    Write-Host "[hunt-clean-selftest] pass case=$Name exit=$exitCode"
}

$cleanPath = Join-Path $outputDirectory "clean.json"
$findingPath = Join-Path $outputDirectory "finding.json"
$incompletePath = Join-Path $outputDirectory "incomplete.json"
$wrongTypePath = Join-Path $outputDirectory "wrong-type.json"
$wrongIntegerPath = Join-Path $outputDirectory "wrong-integer.json"
$invalidModePath = Join-Path $outputDirectory "invalid-mode.json"
$nonArrayPath = Join-Path $outputDirectory "non-array.json"
$riskMismatchPath = Join-Path $outputDirectory "risk-mismatch.json"
$coverageConflictPath = Join-Path $outputDirectory "coverage-conflict.json"
$threatIntelConflictPath = Join-Path $outputDirectory "threat-intel-conflict.json"
$threatIntelUnavailablePath = Join-Path $outputDirectory "threat-intel-unavailable.json"
$threatIntelInactivePath = Join-Path $outputDirectory "threat-intel-inactive.json"
$malformedPath = Join-Path $outputDirectory "malformed.json"

New-HuntDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $cleanPath -Encoding UTF8

$finding = [ordered]@{
    risk = "medium"
    confidence = "medium"
    class = "process_identity"
    title = "synthetic false positive"
    pid = 1234
    eprocess = "0x0000000000000000"
    address = "0x0000000000000000"
    image = "clean.exe"
    module = ""
    reasons = @("synthetic_reason")
    evidence = [ordered]@{ source = "selftest" }
    followups = @()
}
New-HuntDocument -Findings @($finding) |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $findingPath -Encoding UTF8

New-HuntDocument -CoverageComplete $false |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $incompletePath -Encoding UTF8

$wrongTypeDocument = New-HuntDocument
$wrongTypeDocument.summary.coverage_complete = "true"
$wrongTypeDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $wrongTypePath -Encoding UTF8

$wrongIntegerDocument = New-HuntDocument
$wrongIntegerDocument.summary.findings = "0"
$wrongIntegerDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $wrongIntegerPath -Encoding UTF8

$invalidModeDocument = New-HuntDocument
$invalidModeDocument.mode = "anything"
$invalidModeDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $invalidModePath -Encoding UTF8

$nonArrayDocument = New-HuntDocument
$nonArrayDocument.findings = [ordered]@{}
$nonArrayDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $nonArrayPath -Encoding UTF8

$riskMismatchDocument = New-HuntDocument
$riskMismatchDocument.summary.high = 1
$riskMismatchDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $riskMismatchPath -Encoding UTF8

$coverageConflictDocument = New-HuntDocument
$coverageConflictDocument.summary.process_inventory_incomplete = $true
$coverageConflictDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $coverageConflictPath -Encoding UTF8

$threatIntelConflictDocument = New-HuntDocument
$threatIntelConflictDocument.summary.threat_intel_correlation_incomplete = $true
$threatIntelConflictDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $threatIntelConflictPath -Encoding UTF8

$threatIntelUnavailableDocument = New-HuntDocument
$threatIntelUnavailableDocument.summary.threat_intel_active = $false
$threatIntelUnavailableDocument.summary.threat_intel_available = $false
$threatIntelUnavailableDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $threatIntelUnavailablePath -Encoding UTF8

$threatIntelInactiveDocument = New-HuntDocument
$threatIntelInactiveDocument.summary.threat_intel_active = $false
$threatIntelInactiveDocument |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $threatIntelInactivePath -Encoding UTF8

Set-Content -LiteralPath $malformedPath -Value "{not-json" -Encoding UTF8

Invoke-ValidatorCase -Name "clean" -Path $cleanPath -ExpectSuccess $true -RequireThreatIntelActive
Invoke-ValidatorCase -Name "finding" -Path $findingPath -ExpectSuccess $false
Invoke-ValidatorCase -Name "incomplete" -Path $incompletePath -ExpectSuccess $false
Invoke-ValidatorCase -Name "wrong-type" -Path $wrongTypePath -ExpectSuccess $false
Invoke-ValidatorCase -Name "wrong-integer" -Path $wrongIntegerPath -ExpectSuccess $false
Invoke-ValidatorCase -Name "invalid-mode" -Path $invalidModePath -ExpectSuccess $false -RequireMode Any
Invoke-ValidatorCase -Name "non-array" -Path $nonArrayPath -ExpectSuccess $false
Invoke-ValidatorCase -Name "risk-mismatch" -Path $riskMismatchPath -ExpectSuccess $false
Invoke-ValidatorCase -Name "coverage-conflict" -Path $coverageConflictPath -ExpectSuccess $false
Invoke-ValidatorCase -Name "threat-intel-conflict" -Path $threatIntelConflictPath -ExpectSuccess $false
Invoke-ValidatorCase -Name "threat-intel-unavailable" -Path $threatIntelUnavailablePath -ExpectSuccess $false
Invoke-ValidatorCase -Name "threat-intel-inactive-optional" -Path $threatIntelInactivePath -ExpectSuccess $true
Invoke-ValidatorCase -Name "threat-intel-inactive-required" -Path $threatIntelInactivePath -ExpectSuccess $false -RequireThreatIntelActive
Invoke-ValidatorCase -Name "malformed" -Path $malformedPath -ExpectSuccess $false

Write-Host "hunt clean-host validator self-test passed"
