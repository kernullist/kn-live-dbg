param(
    [Parameter(Mandatory = $true)]
    [string]$Manifest,

    [Parameter(Mandatory = $true)]
    [string]$HuntJson,

    [switch]$Strict
)

$ErrorActionPreference = "Stop"

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

function Test-FindingMatchesExpectedScenario
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$Finding,

        [string[]]$ExpectedReasons = @(),

        [string[]]$ExpectedEvidenceKeys = @(),

        [hashtable]$ExpectedEvidence = @{},

        [string]$ExpectedClass = "",

        [string]$ExpectedRisk = "",

        [string]$ExpectedConfidence = ""
    )

    if (-not [string]::IsNullOrWhiteSpace($ExpectedClass))
    {
        if ($null -eq $Finding.PSObject.Properties["class"] -or
            [string]$Finding.PSObject.Properties["class"].Value -ne $ExpectedClass)
        {
            return $false
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($ExpectedRisk))
    {
        if ($null -eq $Finding.PSObject.Properties["risk"] -or
            [string]$Finding.PSObject.Properties["risk"].Value -ne $ExpectedRisk)
        {
            return $false
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($ExpectedConfidence))
    {
        if ($null -eq $Finding.PSObject.Properties["confidence"] -or
            [string]$Finding.PSObject.Properties["confidence"].Value -ne $ExpectedConfidence)
        {
            return $false
        }
    }

    foreach ($reason in $ExpectedReasons)
    {
        if (-not (@($Finding.reasons) -contains $reason))
        {
            return $false
        }
    }

    foreach ($key in $ExpectedEvidenceKeys)
    {
        if ($null -eq $Finding.evidence -or
            $null -eq $Finding.evidence.PSObject.Properties[$key])
        {
            return $false
        }
    }

    foreach ($key in @($ExpectedEvidence.Keys))
    {
        if ($null -eq $Finding.evidence -or
            $null -eq $Finding.evidence.PSObject.Properties[$key] -or
            [string]$Finding.evidence.PSObject.Properties[$key].Value -ne $ExpectedEvidence[$key])
        {
            return $false
        }
    }

    return $true
}

$manifestDoc = Read-JsonFile -Path $Manifest
$huntDoc = Read-JsonFile -Path $HuntJson

if ($manifestDoc.schema -ne "kn-live-dbg.hunt-target-manifest.v1")
{
    throw "unsupported manifest schema: $($manifestDoc.schema)"
}

if ($huntDoc.schema -ne "kn-live-dbg.hunt.v1")
{
    throw "unsupported hunt schema: $($huntDoc.schema)"
}

$targetPid = [int]$manifestDoc.pid
$targetFindings = @($huntDoc.findings | Where-Object { [int]$_.pid -eq $targetPid })
$systemFindings = @($huntDoc.findings | Where-Object { [int]$_.pid -eq 0 })
$scenarios = @($manifestDoc.scenarios)
$failures = New-Object System.Collections.Generic.List[string]
$positiveScenarios = 0
$matchedPositiveScenarios = 0

Write-Host "hunt target validation"
Write-Host "  pid=$targetPid"
Write-Host "  scenarios=$($scenarios.Count)"
Write-Host "  target_findings=$($targetFindings.Count)"
Write-Host "  system_findings=$($systemFindings.Count)"

foreach ($scenario in $scenarios)
{
    $expectedReasons = @($scenario.expected_reasons)
    $unexpectedReasons = @()
    if ($null -ne $scenario.PSObject.Properties["unexpected_reasons"])
    {
        $unexpectedReasons = @($scenario.unexpected_reasons)
    }
    $expectedEvidenceKeys = @()
    if ($null -ne $scenario.PSObject.Properties["expected_evidence_keys"])
    {
        $expectedEvidenceKeys = @($scenario.expected_evidence_keys)
    }
    $expectedEvidence = @{}
    if ($null -ne $scenario.PSObject.Properties["expected_evidence"] -and
        $null -ne $scenario.expected_evidence)
    {
        foreach ($property in $scenario.expected_evidence.PSObject.Properties)
        {
            $expectedEvidence[$property.Name] = [string]$property.Value
        }
    }
    $expectedClass = ""
    if ($null -ne $scenario.PSObject.Properties["expected_class"])
    {
        $expectedClass = [string]$scenario.expected_class
    }
    $expectedRisk = ""
    if ($null -ne $scenario.PSObject.Properties["expected_risk"])
    {
        $expectedRisk = [string]$scenario.expected_risk
    }
    $expectedConfidence = ""
    if ($null -ne $scenario.PSObject.Properties["expected_confidence"])
    {
        $expectedConfidence = [string]$scenario.expected_confidence
    }
    if ($expectedReasons.Count -eq 0 -and
        $unexpectedReasons.Count -eq 0 -and
        $expectedEvidenceKeys.Count -eq 0 -and
        $expectedEvidence.Count -eq 0 -and
        [string]::IsNullOrWhiteSpace($expectedClass) -and
        [string]::IsNullOrWhiteSpace($expectedRisk) -and
        [string]::IsNullOrWhiteSpace($expectedConfidence))
    {
        continue
    }

    $scenarioPid = $targetPid
    if ($null -ne $scenario.PSObject.Properties["pid"])
    {
        $scenarioPid = [int]$scenario.pid
    }
    $scenarioFindings = @($huntDoc.findings | Where-Object { [int]$_.pid -eq $scenarioPid })
    $positiveExpectationCount = $expectedReasons.Count + $expectedEvidenceKeys.Count + $expectedEvidence.Count
    if (-not [string]::IsNullOrWhiteSpace($expectedClass))
    {
        ++$positiveExpectationCount
    }
    if (-not [string]::IsNullOrWhiteSpace($expectedRisk))
    {
        ++$positiveExpectationCount
    }
    if (-not [string]::IsNullOrWhiteSpace($expectedConfidence))
    {
        ++$positiveExpectationCount
    }
    if ($positiveExpectationCount -ne 0)
    {
        ++$positiveScenarios
        $singleFindingMatches = @($scenarioFindings | Where-Object {
            Test-FindingMatchesExpectedScenario `
                -Finding $_ `
                -ExpectedReasons $expectedReasons `
                -ExpectedEvidenceKeys $expectedEvidenceKeys `
                -ExpectedEvidence $expectedEvidence `
                -ExpectedClass $expectedClass `
                -ExpectedRisk $expectedRisk `
                -ExpectedConfidence $expectedConfidence
        })
        if ($singleFindingMatches.Count -eq 0)
        {
            $failures.Add("no single finding satisfies all expected class/risk/confidence/reasons/evidence for scenario '$($scenario.name)' pid=$scenarioPid")
        }
        else
        {
            ++$matchedPositiveScenarios
            Write-Host "  pass scenario=$($scenario.name) pid=$scenarioPid single_finding_match=yes"
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($expectedClass))
    {
        $matches = @($scenarioFindings | Where-Object {
            $null -ne $_.PSObject.Properties["class"] -and
                [string]$_.PSObject.Properties["class"].Value -eq $expectedClass
        })
        if ($matches.Count -eq 0)
        {
            $failures.Add("missing class '$expectedClass' for scenario '$($scenario.name)' pid=$scenarioPid")
        }
        else
        {
            Write-Host "  pass scenario=$($scenario.name) pid=$scenarioPid class=$expectedClass"
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($expectedRisk))
    {
        $matches = @($scenarioFindings | Where-Object {
            $null -ne $_.PSObject.Properties["risk"] -and
                [string]$_.PSObject.Properties["risk"].Value -eq $expectedRisk
        })
        if ($matches.Count -eq 0)
        {
            $failures.Add("missing risk '$expectedRisk' for scenario '$($scenario.name)' pid=$scenarioPid")
        }
        else
        {
            Write-Host "  pass scenario=$($scenario.name) pid=$scenarioPid risk=$expectedRisk"
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($expectedConfidence))
    {
        $matches = @($scenarioFindings | Where-Object {
            $null -ne $_.PSObject.Properties["confidence"] -and
                [string]$_.PSObject.Properties["confidence"].Value -eq $expectedConfidence
        })
        if ($matches.Count -eq 0)
        {
            $failures.Add("missing confidence '$expectedConfidence' for scenario '$($scenario.name)' pid=$scenarioPid")
        }
        else
        {
            Write-Host "  pass scenario=$($scenario.name) pid=$scenarioPid confidence=$expectedConfidence"
        }
    }

    foreach ($reason in $expectedReasons)
    {
        $matches = @($scenarioFindings | Where-Object { @($_.reasons) -contains $reason })
        if ($matches.Count -eq 0)
        {
            $failures.Add("missing reason '$reason' for scenario '$($scenario.name)' pid=$scenarioPid")
        }
        else
        {
            Write-Host "  pass scenario=$($scenario.name) pid=$scenarioPid reason=$reason"
        }
    }

    foreach ($reason in $unexpectedReasons)
    {
        $matches = @($scenarioFindings | Where-Object { @($_.reasons) -contains $reason })
        if ($matches.Count -ne 0)
        {
            $failures.Add("unexpected reason '$reason' for scenario '$($scenario.name)' pid=$scenarioPid")
        }
        else
        {
            Write-Host "  pass scenario=$($scenario.name) pid=$scenarioPid absent_reason=$reason"
        }
    }

    foreach ($key in $expectedEvidenceKeys)
    {
        $matches = @($scenarioFindings | Where-Object {
            $null -ne $_.evidence -and $null -ne $_.evidence.PSObject.Properties[$key]
        })
        if ($matches.Count -eq 0)
        {
            $failures.Add("missing evidence key '$key' for scenario '$($scenario.name)' pid=$scenarioPid")
        }
        else
        {
            Write-Host "  pass scenario=$($scenario.name) pid=$scenarioPid evidence=$key"
        }
    }

    foreach ($key in @($expectedEvidence.Keys | Sort-Object))
    {
        $expectedValue = $expectedEvidence[$key]
        $matches = @($scenarioFindings | Where-Object {
            $null -ne $_.evidence -and
                $null -ne $_.evidence.PSObject.Properties[$key] -and
                [string]$_.evidence.PSObject.Properties[$key].Value -eq $expectedValue
        })
        if ($matches.Count -eq 0)
        {
            $failures.Add("missing evidence value '$key=$expectedValue' for scenario '$($scenario.name)' pid=$scenarioPid")
        }
        else
        {
            Write-Host "  pass scenario=$($scenario.name) pid=$scenarioPid evidence=$key value=$expectedValue"
        }
    }
}

if ($Strict -and $scenarios.Count -eq 0 -and $targetFindings.Count -ne 0)
{
    $failures.Add("strict baseline expected no findings for pid $targetPid, got $($targetFindings.Count)")
}

Write-Host "  positive_scenarios=$positiveScenarios"
Write-Host "  matched_positive_scenarios=$matchedPositiveScenarios"

if ($failures.Count -ne 0)
{
    Write-Host "validation failed"
    foreach ($failure in $failures)
    {
        Write-Host "  fail $failure"
    }
    exit 1
}

Write-Host "validation passed"
exit 0
