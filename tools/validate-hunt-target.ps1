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
    if ($expectedReasons.Count -eq 0)
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
