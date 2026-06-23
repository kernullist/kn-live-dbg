param(
    [string]$Root = (Get-Location).Path,

    [string]$Manifest,

    [string]$HuntJson,

    [string]$Stdout,

    [string]$RunnerLog,

    [string]$ValidatorLog,

    [int]$ExpectedScenarioCount = 35,

    [int]$ExpectedEdrKillerDriverServices = 15,

    [Alias("RequiredHighSignalNeedle")]
    [string]$RequiredAssessmentNeedle = "known defense-evasion tool name",

    [string[]]$RequiredReasons = @(
        "gentlemen_edr_killer_process_name",
        "gentlemen_suffix_normalized_process_name",
        "gentlemen_collection_staging_path",
        "edr_killer_version_info_impersonation_evidence",
        "edr_killer_packer_section_evidence",
        "gentlemen_related_credential_tool_name",
        "oxideharvest_cli_shape",
        "gentlemen_edr_killer_driver_service",
        "driver_service_binary_name_ioc",
        "driver_service_not_running"
    ),

    [switch]$RequireRunnerPassed,

    [switch]$AllowNoHighRisk
)

$ErrorActionPreference = "Stop"

function Resolve-DefaultPath
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$RootPath,

        [AllowNull()]
        [AllowEmptyString()]
        [string]$Value,

        [Parameter(Mandatory = $true)]
        [string]$DefaultRelativePath
    )

    $candidate = $Value
    if (-not [string]::IsNullOrWhiteSpace($Value))
    {
        if ([System.IO.Path]::IsPathRooted($candidate))
        {
            return [System.IO.Path]::GetFullPath($candidate)
        }

        return [System.IO.Path]::GetFullPath((Join-Path $RootPath $candidate))
    }

    return [System.IO.Path]::GetFullPath((Join-Path $RootPath $DefaultRelativePath))
}

function New-ParentDirectoryIfMissing
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $parent = Split-Path -Parent $Path
    if ([string]::IsNullOrWhiteSpace($parent))
    {
        return
    }
    if (-not (Test-Path -LiteralPath $parent))
    {
        New-Item -ItemType Directory -Path $parent | Out-Null
    }
}

function Read-JsonFile
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path))
    {
        throw "file not found: $Path"
    }

    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Assert-TextFileContains
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Needle,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if (-not (Test-Path -LiteralPath $Path))
    {
        throw "file not found: $Path"
    }

    $text = Get-Content -LiteralPath $Path -Raw
    if ($text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -lt 0)
    {
        throw "missing $Name in ${Path}: $Needle"
    }
}

function Assert-TextFileDoesNotContain
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Needle,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if (-not (Test-Path -LiteralPath $Path))
    {
        throw "file not found: $Path"
    }

    $text = Get-Content -LiteralPath $Path -Raw
    if ($text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
    {
        throw "unexpected $Name in ${Path}: $Needle"
    }
}

function Assert-HuntFindingReasonPresent
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$HuntDoc,

        [Parameter(Mandatory = $true)]
        [string]$Reason
    )

    $matches = @($HuntDoc.findings | Where-Object { @($_.reasons) -contains $Reason })
    if ($matches.Count -eq 0)
    {
        throw "hunt JSON does not contain required reason: $Reason"
    }
}

function Normalize-HuntRisk
{
    param(
        [AllowNull()]
        [string]$Risk
    )

    $normalized = [string]$Risk
    $normalized = $normalized.Trim().ToLowerInvariant()
    if ($normalized -ne "high" -and
        $normalized -ne "medium" -and
        $normalized -ne "low")
    {
        return "info"
    }

    return $normalized
}

function Assert-HuntSummaryMatchesFindings
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$HuntDoc
    )

    $findings = @($HuntDoc.findings)
    $high = @($findings | Where-Object { (Normalize-HuntRisk -Risk $_.risk) -eq "high" }).Count
    $medium = @($findings | Where-Object { (Normalize-HuntRisk -Risk $_.risk) -eq "medium" }).Count
    $low = @($findings | Where-Object { (Normalize-HuntRisk -Risk $_.risk) -eq "low" }).Count
    $info = @($findings | Where-Object { (Normalize-HuntRisk -Risk $_.risk) -eq "info" }).Count
    $driverServiceFindings = @($findings | Where-Object {
        $null -ne $_.PSObject.Properties["class"] -and
            [string]$_.PSObject.Properties["class"].Value -eq "edr_killer_driver_service"
    }).Count
    $threatIntelCorrelationFindings = @($findings | Where-Object {
        $null -ne $_.PSObject.Properties["class"] -and
            [string]$_.PSObject.Properties["class"].Value -like "edr_killer_*_telemetry"
    }).Count

    if ([int]$HuntDoc.summary.findings -ne $findings.Count)
    {
        throw "hunt JSON summary.findings=$($HuntDoc.summary.findings) does not match findings array count $($findings.Count)"
    }
    if ([int]$HuntDoc.summary.high -ne $high)
    {
        throw "hunt JSON summary.high=$($HuntDoc.summary.high) does not match high-risk finding count $high"
    }
    if ([int]$HuntDoc.summary.medium -ne $medium)
    {
        throw "hunt JSON summary.medium=$($HuntDoc.summary.medium) does not match medium-risk finding count $medium"
    }
    if ([int]$HuntDoc.summary.low -ne $low)
    {
        throw "hunt JSON summary.low=$($HuntDoc.summary.low) does not match low-risk finding count $low"
    }
    if ($null -ne $HuntDoc.summary.PSObject.Properties["info"] -and [int]$HuntDoc.summary.info -ne $info)
    {
        throw "hunt JSON summary.info=$($HuntDoc.summary.info) does not match info-risk finding count $info"
    }
    if ([int]$HuntDoc.summary.edr_killer_driver_services -ne $driverServiceFindings)
    {
        throw "hunt JSON summary.edr_killer_driver_services=$($HuntDoc.summary.edr_killer_driver_services) does not match EDR-killer driver-service finding count $driverServiceFindings"
    }
    if ($null -ne $HuntDoc.summary.PSObject.Properties["threat_intel_correlations"] -and
        [int]$HuntDoc.summary.threat_intel_correlations -ne $threatIntelCorrelationFindings)
    {
        throw "hunt JSON summary.threat_intel_correlations=$($HuntDoc.summary.threat_intel_correlations) does not match telemetry finding count $threatIntelCorrelationFindings"
    }
}

function Assert-ManifestScenarioPresent
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$ManifestDoc,

        [Parameter(Mandatory = $true)]
        [string]$ScenarioName
    )

    $matches = @($ManifestDoc.scenarios | Where-Object { [string]$_.name -eq $ScenarioName })
    if ($matches.Count -eq 0)
    {
        throw "manifest does not contain required scenario: $ScenarioName"
    }
}

function Assert-ManifestScenarioNames
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$ManifestDoc,

        [Parameter(Mandatory = $true)]
        [string[]]$ExpectedNames,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $actualNames = @($ManifestDoc.scenarios | ForEach-Object { [string]$_.name })
    $missing = @()
    foreach ($expectedName in $ExpectedNames)
    {
        if ($actualNames -notcontains $expectedName)
        {
            $missing += $expectedName
        }
    }

    $unexpected = @()
    foreach ($actualName in $actualNames)
    {
        if ($ExpectedNames -notcontains $actualName)
        {
            $unexpected += $actualName
        }
    }

    $duplicates = @(
        $actualNames |
            Group-Object |
            Where-Object { $_.Count -gt 1 } |
            ForEach-Object { $_.Name }
    )

    if ($missing.Count -ne 0 -or $unexpected.Count -ne 0 -or $duplicates.Count -ne 0)
    {
        throw "$Name scenario set mismatch; missing=$($missing -join ',') unexpected=$($unexpected -join ',') duplicates=$($duplicates -join ',')"
    }
}

function Assert-ManifestScenarioReasonPresent
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$ManifestDoc,

        [Parameter(Mandatory = $true)]
        [string]$ScenarioName,

        [Parameter(Mandatory = $true)]
        [string]$Reason
    )

    $matches = @($ManifestDoc.scenarios | Where-Object {
        [string]$_.name -eq $ScenarioName -and @($_.expected_reasons) -contains $Reason
    })
    if ($matches.Count -eq 0)
    {
        throw "manifest scenario '$ScenarioName' does not require reason: $Reason"
    }
}

function Assert-ManifestScenarioUnexpectedReasonPresent
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$ManifestDoc,

        [Parameter(Mandatory = $true)]
        [string]$ScenarioName,

        [Parameter(Mandatory = $true)]
        [string]$Reason
    )

    $matches = @($ManifestDoc.scenarios | Where-Object {
        [string]$_.name -eq $ScenarioName -and @($_.unexpected_reasons) -contains $Reason
    })
    if ($matches.Count -eq 0)
    {
        throw "manifest scenario '$ScenarioName' does not reject unexpected reason: $Reason"
    }
}

function Invoke-ManifestValidator
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$RootPath,

        [Parameter(Mandatory = $true)]
        [string]$ManifestPath,

        [Parameter(Mandatory = $true)]
        [string]$HuntJsonPath,

        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )

    $validator = Join-Path $RootPath "tools\validate-hunt-target.ps1"
    if (-not (Test-Path -LiteralPath $validator))
    {
        throw "hunt target validator not found: $validator"
    }

    if (Test-Path -LiteralPath $LogPath)
    {
        Remove-Item -LiteralPath $LogPath -Force
    }
    New-ParentDirectoryIfMissing -Path $LogPath

    & $validator -Manifest $ManifestPath -HuntJson $HuntJsonPath *> $LogPath
    if ($LASTEXITCODE -ne 0)
    {
        Get-Content -LiteralPath $LogPath -Tail 100 -ErrorAction SilentlyContinue | Out-Host
        throw "hunt target validation failed with exit code $LASTEXITCODE; log=$LogPath"
    }
}

$rootPath = (Resolve-Path -LiteralPath $Root).Path
$manifestPath = Resolve-DefaultPath -RootPath $rootPath -Value $Manifest -DefaultRelativePath ".build\eset-hunt-e2e\hunt-target-manifest.json"
$huntJsonPath = Resolve-DefaultPath -RootPath $rootPath -Value $HuntJson -DefaultRelativePath ".build\eset-hunt-e2e\hunt.json"
$stdoutPath = Resolve-DefaultPath -RootPath $rootPath -Value $Stdout -DefaultRelativePath ".build\eset-hunt-e2e\knlivedbg.stdout.log"
$runnerLogPath = ""
if (-not [string]::IsNullOrWhiteSpace($RunnerLog))
{
    $runnerLogPath = Resolve-DefaultPath -RootPath $rootPath -Value $RunnerLog -DefaultRelativePath ".build\eset-hunt-e2e\runner.log"
}
elseif ($RequireRunnerPassed)
{
    throw "-RequireRunnerPassed requires -RunnerLog so the final runner pass marker can be verified"
}
$validatorLogPath = Resolve-DefaultPath -RootPath $rootPath -Value $ValidatorLog -DefaultRelativePath ".build\eset-hunt-e2e\validator.log"

$manifestDoc = Read-JsonFile -Path $manifestPath
$huntDoc = Read-JsonFile -Path $huntJsonPath

if ($manifestDoc.schema -ne "kn-live-dbg.hunt-target-manifest.v1")
{
    throw "unexpected manifest schema: $($manifestDoc.schema)"
}
if ($huntDoc.schema -ne "kn-live-dbg.hunt.v1")
{
    throw "unexpected hunt JSON schema: $($huntDoc.schema)"
}

$scenarioCount = @($manifestDoc.scenarios).Count
if ($scenarioCount -ne $ExpectedScenarioCount)
{
    throw "expected $ExpectedScenarioCount manifest scenarios, got $scenarioCount"
}
if ($null -ne $manifestDoc.PSObject.Properties["scenario_count"] -and [int]$manifestDoc.scenario_count -ne $scenarioCount)
{
    throw "manifest scenario_count field $($manifestDoc.scenario_count) does not match actual scenario array count $scenarioCount"
}

$classContractCount = @($manifestDoc.scenarios | Where-Object { $null -ne $_.PSObject.Properties["expected_class"] }).Count
if ($ExpectedScenarioCount -eq 35 -and $classContractCount -ne 32)
{
    throw "expected exactly 32 class/risk/confidence scenario contracts, got $classContractCount"
}
if ($ExpectedScenarioCount -eq 15 -and $classContractCount -ne 15)
{
    throw "expected exactly 15 class/risk/confidence scenario contracts, got $classContractCount"
}

if ([int]$huntDoc.summary.findings -le 0)
{
    throw "hunt JSON summary has no findings"
}
if (-not $AllowNoHighRisk -and [int]$huntDoc.summary.high -le 0)
{
    throw "hunt JSON summary has no high-risk findings"
}
if ([int]$huntDoc.summary.edr_killer_driver_services -ne $ExpectedEdrKillerDriverServices)
{
    throw "hunt JSON summary expected exactly $ExpectedEdrKillerDriverServices EDR-killer driver services, got $($huntDoc.summary.edr_killer_driver_services)"
}
Assert-HuntSummaryMatchesFindings -HuntDoc $huntDoc

$expectedVerdict = "verdict=clean"
if ([int]$huntDoc.summary.high -gt 0)
{
    $expectedVerdict = "verdict=alert"
}
elseif ([int]$huntDoc.summary.medium -gt 0)
{
    $expectedVerdict = "verdict=review"
}
elseif ([int]$huntDoc.summary.low -gt 0)
{
    $expectedVerdict = "verdict=low_signal"
}

Assert-TextFileContains -Path $stdoutPath -Needle "json written:" -Name "hunt JSON write confirmation"
Assert-TextFileContains -Path $stdoutPath -Needle "[hunt.conclusion]" -Name "hunt conclusion line"
Assert-TextFileContains -Path $stdoutPath -Needle $expectedVerdict -Name "hunt risk verdict"
Assert-TextFileContains -Path $stdoutPath -Needle "findings=$($huntDoc.summary.findings) high=$($huntDoc.summary.high) medium=$($huntDoc.summary.medium) low=$($huntDoc.summary.low)" -Name "hunt console risk summary counts"
Assert-TextFileContains -Path $stdoutPath -Needle "[hunt.assessment]" -Name "hunt human assessment section"
Assert-TextFileContains -Path $stdoutPath -Needle "subject=" -Name "hunt human assessment subject"
Assert-TextFileContains -Path $stdoutPath -Needle 'what="' -Name "hunt human assessment action"
Assert-TextFileContains -Path $stdoutPath -Needle 'why="' -Name "hunt human assessment evidence"
Assert-TextFileContains -Path $stdoutPath -Needle 'next="' -Name "hunt human assessment followup"
Assert-TextFileContains -Path $stdoutPath -Needle "[hunt.summary]" -Name "hunt summary line"
if ([int]$huntDoc.summary.edr_killer_driver_services -gt 0)
{
    Assert-TextFileContains -Path $stdoutPath -Needle "driver_service_iocs=" -Name "driver-service IOC count summary"
    Assert-TextFileContains -Path $stdoutPath -Needle "driver_service_iocs=$($huntDoc.summary.edr_killer_driver_services)" -Name "driver-service IOC exact count summary"
}
if ($null -ne $huntDoc.summary.PSObject.Properties["threat_intel_correlations"] -and
    [int]$huntDoc.summary.threat_intel_correlations -gt 0)
{
    Assert-TextFileContains -Path $stdoutPath -Needle "ti_correlations=$($huntDoc.summary.threat_intel_correlations)" -Name "Threat-Intelligence correlation exact count summary"
}
Assert-TextFileContains -Path $stdoutPath -Needle $RequiredAssessmentNeedle -Name "required assessment evidence entry"
Assert-TextFileContains -Path $stdoutPath -Needle "[hunt.detail] suppressed=yes" -Name "summary-mode detail suppression"
Assert-TextFileDoesNotContain -Path $stdoutPath -Needle "[hunt.high_signal]" -Name "summary-mode raw high-signal table"
Assert-TextFileDoesNotContain -Path $stdoutPath -Needle "[hunt.top_processes]" -Name "summary-mode raw top-process table"
Assert-TextFileDoesNotContain -Path $stdoutPath -Needle "[hunt.top_reasons]" -Name "summary-mode raw top-reason table"
Assert-TextFileDoesNotContain -Path $stdoutPath -Needle "edr_killer_services=" -Name "legacy EDR-killer service summary field"
Assert-TextFileDoesNotContain -Path $stdoutPath -Needle "signal=edr_killer" -Name "raw EDR-killer signal label"
Assert-TextFileDoesNotContain -Path $stdoutPath -Needle "signal=eset_" -Name "raw ESET signal label"
Assert-TextFileDoesNotContain -Path $stdoutPath -Needle "signal=gentlemen" -Name "raw Gentlemen signal label"
Assert-TextFileDoesNotContain -Path $stdoutPath -Needle "signal=known_security_product_process_target" -Name "raw security-product signal label"
Assert-TextFileDoesNotContain -Path $stdoutPath -Needle "signal=oxideharvest" -Name "raw OxideHarvest signal label"
Assert-TextFileDoesNotContain -Path $stdoutPath -Needle "top_reason=edr_killer" -Name "raw EDR-killer top reason"
Assert-TextFileDoesNotContain -Path $stdoutPath -Needle "top_reason=eset_" -Name "raw ESET top reason"
Assert-TextFileDoesNotContain -Path $stdoutPath -Needle "top_reason=gentlemen" -Name "raw Gentlemen top reason"
Assert-TextFileDoesNotContain -Path $stdoutPath -Needle "top_reason=known_security_product_process_target" -Name "raw security-product top reason"
Assert-TextFileDoesNotContain -Path $stdoutPath -Needle "top_reason=oxideharvest" -Name "raw OxideHarvest top reason"
Assert-TextFileDoesNotContain -Path $stdoutPath -Needle "reason=edr_killer" -Name "raw EDR-killer top-reason label"
Assert-TextFileDoesNotContain -Path $stdoutPath -Needle "reason=eset_" -Name "raw ESET top-reason label"
Assert-TextFileDoesNotContain -Path $stdoutPath -Needle "reason=gentlemen" -Name "raw Gentlemen top-reason label"
Assert-TextFileDoesNotContain -Path $stdoutPath -Needle "reason=known_security_product_process_target" -Name "raw security-product top-reason label"
Assert-TextFileDoesNotContain -Path $stdoutPath -Needle "reason=oxideharvest" -Name "raw OxideHarvest top-reason label"
Assert-TextFileDoesNotContain -Path $stdoutPath -Needle "finding=defense_evasion" -Name "internal assessment defense-evasion finding label"
Assert-TextFileDoesNotContain -Path $stdoutPath -Needle "finding=published_file_hash_ioc" -Name "internal assessment hash finding label"
Assert-TextFileDoesNotContain -Path $stdoutPath -Needle "finding=credential_collection_tool" -Name "internal assessment credential-tool finding label"
Assert-TextFileDoesNotContain -Path $stdoutPath -Needle "finding=security_product_targeting" -Name "internal assessment security-product finding label"
Assert-TextFileDoesNotContain -Path $stdoutPath -Needle "finding=code_provenance_anomaly" -Name "internal assessment code-provenance finding label"

if (-not [string]::IsNullOrWhiteSpace($runnerLogPath))
{
    Assert-TextFileContains -Path $runnerLogPath -Needle "runner_contract=e2e-auto-knlivedbg-article-currentness-v2" -Name "ESET runner contract"
    Assert-TextFileContains -Path $runnerLogPath -Needle "elevated=True" -Name "ESET runner elevated execution"
    Assert-TextFileContains -Path $runnerLogPath -Needle "expected_scenarios=$ExpectedScenarioCount" -Name "ESET runner expected scenario count"
    Assert-TextFileContains -Path $runnerLogPath -Needle "target ready scenarios=$ExpectedScenarioCount" -Name "ESET runner target-ready scenario count"
    Assert-TextFileContains -Path $runnerLogPath -Needle "run KnLiveDbg scripted hunt" -Name "ESET runner KnLiveDbg launch step"
    Assert-TextFileContains -Path $runnerLogPath -Needle "validate ESET hunt artifacts" -Name "ESET runner artifact validation step"
    if ($RequireRunnerPassed)
    {
        Assert-TextFileContains -Path $runnerLogPath -Needle "[eset-hunt-e2e] passed" -Name "ESET runner final pass marker"
        Assert-TextFileContains -Path $runnerLogPath -Needle "manifest=$manifestPath" -Name "ESET runner final manifest path"
        Assert-TextFileContains -Path $runnerLogPath -Needle "hunt_json=$huntJsonPath" -Name "ESET runner final hunt JSON path"
    }
}

foreach ($reason in $RequiredReasons)
{
    if (-not [string]::IsNullOrWhiteSpace($reason))
    {
        Assert-HuntFindingReasonPresent -HuntDoc $huntDoc -Reason $reason
    }
}

if ($ExpectedScenarioCount -eq 35)
{
    $requiredScenarioNames = @(
        "edr-killer-suffix-name-kasps",
        "edr-killer-suffix-name-kasp",
        "edr-killer-suffix-name-faceit",
        "edr-killer-suffix-name-valorant",
        "edr-killer-suffix-name-eaanticheat",
        "edr-killer-suffix-name-easolo",
        "edr-killer-suffix-name-easolo-2light",
        "edr-killer-suffix-name-bitd",
        "edr-killer-suffix-name-mb",
        "edr-killer-suffix-name-g11",
        "edr-killer-suffix-name-symantec",
        "edr-killer-suffix-name-avast",
        "edr-killer-suffix-name-sent",
        "edr-killer-suffix-name-sophos",
        "edr-killer-weak-vendor-standalone-negative",
        "edr-killer-gentlemen-staging-only-negative",
        "edr-killer-exact-name-deletor",
        "edr-killer-exact-name-hwaudkiller",
        "oxideharvest-cli",
        "oxideharvest-name-only-negative",
        "edr-killer-driver-service-eb",
        "edr-killer-driver-service-nseckrnl",
        "edr-killer-driver-service-vgk",
        "edr-killer-driver-service-gamedriverx64",
        "edr-killer-driver-service-stpm-old",
        "edr-killer-driver-service-stpm-new",
        "edr-killer-driver-service-dmx",
        "edr-killer-driver-service-360netmon-wfp",
        "edr-killer-driver-service-360netmon",
        "edr-killer-driver-service-imfforcedelete",
        "edr-killer-driver-service-poisonx",
        "edr-killer-driver-service-g11",
        "edr-killer-driver-service-googleapiutil64",
        "edr-killer-driver-service-throttleblood",
        "edr-killer-driver-service-havoc"
    )

    Assert-ManifestScenarioNames `
        -ManifestDoc $manifestDoc `
        -ExpectedNames $requiredScenarioNames `
        -Name "full ESET"

    Assert-ManifestScenarioUnexpectedReasonPresent `
        -ManifestDoc $manifestDoc `
        -ScenarioName "edr-killer-weak-vendor-standalone-negative" `
        -Reason "gentlemen_edr_killer_process_name"
    Assert-ManifestScenarioUnexpectedReasonPresent `
        -ManifestDoc $manifestDoc `
        -ScenarioName "edr-killer-gentlemen-staging-only-negative" `
        -Reason "gentlemen_collection_staging_path"
    Assert-ManifestScenarioUnexpectedReasonPresent `
        -ManifestDoc $manifestDoc `
        -ScenarioName "edr-killer-gentlemen-staging-only-negative" `
        -Reason "edr_killer_version_info_impersonation_evidence"
    Assert-ManifestScenarioUnexpectedReasonPresent `
        -ManifestDoc $manifestDoc `
        -ScenarioName "oxideharvest-name-only-negative" `
        -Reason "gentlemen_related_credential_tool_name"
    Assert-ManifestScenarioReasonPresent `
        -ManifestDoc $manifestDoc `
        -ScenarioName "oxideharvest-cli" `
        -Reason "oxideharvest_cli_shape"
    Assert-TextFileContains `
        -Path $stdoutPath `
        -Needle "known defense-evasion driver service" `
        -Name "required defense-evasion driver-service assessment evidence"
    Assert-TextFileContains `
        -Path $stdoutPath `
        -Needle "manipulated version information" `
        -Name "required manipulated version-info assessment evidence"
    Assert-TextFileContains `
        -Path $stdoutPath `
        -Needle "packed or protected PE section" `
        -Name "required packed/protected section assessment evidence"
    Assert-TextFileContains `
        -Path $stdoutPath `
        -Needle "driver_service_iocs=$($huntDoc.summary.edr_killer_driver_services)" `
        -Name "required driver-service IOC summary count"
}
elseif ($ExpectedScenarioCount -eq 15)
{
    $requiredScenarioNames = @(
        "edr-killer-driver-service-eb",
        "edr-killer-driver-service-nseckrnl",
        "edr-killer-driver-service-vgk",
        "edr-killer-driver-service-gamedriverx64",
        "edr-killer-driver-service-stpm-old",
        "edr-killer-driver-service-stpm-new",
        "edr-killer-driver-service-dmx",
        "edr-killer-driver-service-360netmon-wfp",
        "edr-killer-driver-service-360netmon",
        "edr-killer-driver-service-imfforcedelete",
        "edr-killer-driver-service-poisonx",
        "edr-killer-driver-service-g11",
        "edr-killer-driver-service-googleapiutil64",
        "edr-killer-driver-service-throttleblood",
        "edr-killer-driver-service-havoc"
    )

    Assert-ManifestScenarioNames `
        -ManifestDoc $manifestDoc `
        -ExpectedNames $requiredScenarioNames `
        -Name "ESET driver-service"
}

Invoke-ManifestValidator `
    -RootPath $rootPath `
    -ManifestPath $manifestPath `
    -HuntJsonPath $huntJsonPath `
    -LogPath $validatorLogPath

Write-Host "ESET hunt E2E artifact validation passed"
Write-Host "  scenarios=$scenarioCount class_contracts=$classContractCount"
Write-Host "  findings=$($huntDoc.summary.findings) high=$($huntDoc.summary.high) edr_killer_driver_services=$($huntDoc.summary.edr_killer_driver_services)"
Write-Host "  manifest=$manifestPath"
Write-Host "  hunt_json=$huntJsonPath"
Write-Host "  stdout=$stdoutPath"
if (-not [string]::IsNullOrWhiteSpace($runnerLogPath))
{
    Write-Host "  runner_log=$runnerLogPath"
}
Write-Host "  validator_log=$validatorLogPath"
exit 0
