param(
    [string]$Root = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = "Stop"

$rootPath = (Resolve-Path -LiteralPath $Root).Path
$validator = Join-Path $rootPath "tools\validate-cloudfiles-hunt-e2e.ps1"
$testRoot = Join-Path $rootPath (
    ".build\cloudfiles-hunt-e2e-selftest-" +
    [Guid]::NewGuid().ToString("N"))
$imagePath = Join-Path $testRoot "CloudFilesFixture.exe"
$processId = 4242

function New-Observation
{
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Modified
    )

    $reasons = @()
    if ($Modified)
    {
        $reasons = @(
            "cloudfiles_executable_placeholder_mapping",
            "cloudfiles_placeholder_modified_data"
        )
    }

    return [ordered]@{
        pid = $processId
        module_base = "0x0000000140000000"
        module_size = 45056
        image = "CloudFilesFixture.exe"
        module = "CloudFilesFixture.exe"
        vad_backing_path = "\Device\HarddiskVolume3\CloudFilesFixture.exe"
        normalized_backing_path = $imagePath
        file_attributes = "0x00000020"
        reparse_tag = "0x00000000"
        cloud_reparse_tag_observed = $false
        placeholder_info_identification_fallback_used = $true
        placeholder_info_query_status = "0x00000000"
        placeholder_state = "0x00000001"
        on_disk_data_size = $(if ($Modified) { 45089 } else { 45056 })
        validated_data_size = 45056
        modified_data_size = $(if ($Modified) { 33 } else { 0 })
        properties_size = 0
        pin_state = 0
        in_sync_state = $(if ($Modified) { 0 } else { 1 })
        file_identity_length = 37
        process_protection_resolved = $true
        process_protection = "0x00"
        deep_mismatch_correlated = $false
        suspicious = $Modified
        reasons = $reasons
    }
}

function New-Document
{
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Modified
    )

    $observation = New-Observation -Modified $Modified
    $findings = @()
    if ($Modified)
    {
        $findings = @(
            [ordered]@{
                risk = "medium"
                confidence = "high"
                class = "cloudfiles_false_file_immutability"
                title = "mapped Cloud Files executable placeholder reports modified data"
                pid = $processId
                eprocess = "0x0000000000000000"
                address = "0x0000000140000000"
                image = "CloudFilesFixture.exe"
                module = "CloudFilesFixture.exe"
                reasons = @(
                    "cloudfiles_executable_placeholder_mapping",
                    "cloudfiles_placeholder_modified_data"
                )
                evidence = [ordered]@{
                    normalized_backing_path = $imagePath
                    modified_data_size = "33"
                }
                followups = @()
            }
        )
    }

    return [ordered]@{
        schema = "kn-live-dbg.hunt.v1"
        timestamp_utc = "2026-07-29T00:00:00.000Z"
        mode = "deep"
        summary = [ordered]@{
            cloudfiles_placeholder_images = 1
            suspicious_cloudfiles_images = $(if ($Modified) { 1 } else { 0 })
            cloudfiles_placeholder_coverage_incomplete = $false
            cloudfiles_protection_correlation_incomplete = $false
        }
        warnings = @()
        findings = $findings
        cloudfiles_images = @($observation)
        processes = @(
            [ordered]@{
                pid = $processId
                protection = [ordered]@{
                    raw = "0x00"
                    type = 0
                    audit = 0
                    signer = 0
                }
            }
        )
    }
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
        ConvertTo-Json -Depth 16 |
        Set-Content -LiteralPath $Path -Encoding UTF8
}

function Invoke-Validator
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateSet("InSyncNegative", "ModifiedPositive")]
        [string]$Scenario,

        [Parameter(Mandatory = $true)]
        [bool]$ExpectSuccess
    )

    $logPath = Join-Path $testRoot "$Name.log"
    & powershell.exe `
        -NoProfile `
        -ExecutionPolicy Bypass `
        -File $validator `
        -HuntJson $Path `
        -Scenario $Scenario `
        -ProcessId $processId `
        -ImagePath $imagePath *> $logPath
    $exitCode = $LASTEXITCODE
    if ($ExpectSuccess -and $exitCode -ne 0)
    {
        throw "validator case '$Name' failed unexpectedly; log=$logPath"
    }
    if (-not $ExpectSuccess -and $exitCode -eq 0)
    {
        throw "validator case '$Name' accepted invalid evidence; log=$logPath"
    }
    Write-Host (
        "[cloudfiles-hunt-e2e-selftest] pass case={0} exit={1}" -f
        $Name,
        $exitCode)
}

New-Item -ItemType Directory -Path $testRoot | Out-Null
try
{
    Set-Content -LiteralPath $imagePath -Value "fixture" -Encoding Ascii

    $negativePath = Join-Path $testRoot "negative.json"
    Write-Json `
        -Document (New-Document -Modified $false) `
        -Path $negativePath
    Invoke-Validator `
        -Name "in-sync-negative" `
        -Path $negativePath `
        -Scenario "InSyncNegative" `
        -ExpectSuccess $true

    $positivePath = Join-Path $testRoot "positive.json"
    Write-Json `
        -Document (New-Document -Modified $true) `
        -Path $positivePath
    Invoke-Validator `
        -Name "modified-positive" `
        -Path $positivePath `
        -Scenario "ModifiedPositive" `
        -ExpectSuccess $true

    $suspiciousNegative = New-Document -Modified $false
    $suspiciousNegative.cloudfiles_images[0].suspicious = $true
    $suspiciousNegative.summary.suspicious_cloudfiles_images = 1
    $suspiciousNegativePath =
        Join-Path $testRoot "negative-suspicious.json"
    Write-Json `
        -Document $suspiciousNegative `
        -Path $suspiciousNegativePath
    Invoke-Validator `
        -Name "negative-suspicious" `
        -Path $suspiciousNegativePath `
        -Scenario "InSyncNegative" `
        -ExpectSuccess $false

    $missingReason = New-Document -Modified $true
    $missingReason.cloudfiles_images[0].reasons =
        @("cloudfiles_executable_placeholder_mapping")
    $missingReasonPath =
        Join-Path $testRoot "positive-missing-reason.json"
    Write-Json `
        -Document $missingReason `
        -Path $missingReasonPath
    Invoke-Validator `
        -Name "positive-missing-reason" `
        -Path $missingReasonPath `
        -Scenario "ModifiedPositive" `
        -ExpectSuccess $false

    $countMismatch = New-Document -Modified $true
    $countMismatch.summary.cloudfiles_placeholder_images = 2
    $countMismatchPath =
        Join-Path $testRoot "count-mismatch.json"
    Write-Json `
        -Document $countMismatch `
        -Path $countMismatchPath
    Invoke-Validator `
        -Name "count-mismatch" `
        -Path $countMismatchPath `
        -Scenario "ModifiedPositive" `
        -ExpectSuccess $false

    $incomplete = New-Document -Modified $true
    $incomplete.summary.cloudfiles_placeholder_coverage_incomplete =
        $true
    $incompletePath =
        Join-Path $testRoot "coverage-incomplete.json"
    Write-Json `
        -Document $incomplete `
        -Path $incompletePath
    Invoke-Validator `
        -Name "coverage-incomplete" `
        -Path $incompletePath `
        -Scenario "ModifiedPositive" `
        -ExpectSuccess $false

    $missingObservation = New-Document -Modified $true
    $missingObservation.cloudfiles_images = @()
    $missingObservation.summary.cloudfiles_placeholder_images = 0
    $missingObservation.summary.suspicious_cloudfiles_images = 0
    $missingObservationPath =
        Join-Path $testRoot "missing-observation.json"
    Write-Json `
        -Document $missingObservation `
        -Path $missingObservationPath
    Invoke-Validator `
        -Name "missing-observation" `
        -Path $missingObservationPath `
        -Scenario "ModifiedPositive" `
        -ExpectSuccess $false

    $wrongBoolean = New-Document -Modified $true
    $wrongBoolean.cloudfiles_images[0].suspicious = "true"
    $wrongBoolean.summary.suspicious_cloudfiles_images = 0
    $wrongBooleanPath =
        Join-Path $testRoot "wrong-boolean.json"
    Write-Json `
        -Document $wrongBoolean `
        -Path $wrongBooleanPath
    Invoke-Validator `
        -Name "wrong-boolean" `
        -Path $wrongBooleanPath `
        -Scenario "ModifiedPositive" `
        -ExpectSuccess $false

    Write-Host "CloudFiles hunt E2E validator self-test passed"
}
finally
{
    $resolvedBuildRoot =
        [IO.Path]::GetFullPath(
            (Join-Path $rootPath ".build")).TrimEnd("\") + "\"
    $resolvedTestRoot = [IO.Path]::GetFullPath($testRoot)
    if ($resolvedTestRoot.StartsWith(
            $resolvedBuildRoot,
            [StringComparison]::OrdinalIgnoreCase) -and
        [IO.Path]::GetFileName($resolvedTestRoot).StartsWith(
            "cloudfiles-hunt-e2e-selftest-",
            [StringComparison]::OrdinalIgnoreCase) -and
        (Test-Path -LiteralPath $resolvedTestRoot))
    {
        Remove-Item -LiteralPath $resolvedTestRoot -Recurse -Force
    }
}

exit 0
