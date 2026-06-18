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
$scenarios = @($manifestDoc.scenarios)
$failures = New-Object System.Collections.Generic.List[string]

Write-Host "hunt target validation"
Write-Host "  pid=$targetPid"
Write-Host "  scenarios=$($scenarios.Count)"
Write-Host "  target_findings=$($targetFindings.Count)"

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
    if ($expectedReasons.Count -eq 0 -and
        $unexpectedReasons.Count -eq 0 -and
        $expectedEvidenceKeys.Count -eq 0 -and
        $expectedEvidence.Count -eq 0)
    {
        continue
    }

    $scenarioPid = $targetPid
    if ($null -ne $scenario.PSObject.Properties["pid"])
    {
        $scenarioPid = [int]$scenario.pid
    }
    $scenarioFindings = @($huntDoc.findings | Where-Object { [int]$_.pid -eq $scenarioPid })

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
