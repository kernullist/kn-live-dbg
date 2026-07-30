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

$rootPath = (Resolve-Path -LiteralPath $Root).Path
$validator =
    Join-Path $rootPath "tools\validate-minifilter-detach-e2e.ps1"
$testRoot =
    Join-Path $rootPath (
        ".build\minifilter-detach-e2e-selftest-" +
        [Guid]::NewGuid().ToString("N"))
$filterName = "KnLiveDbgMiniFilterFixture"
$instanceName =
    "KnLiveDbgMiniFilterFixture.Instance"
$volumeName =
    "\Device\HarddiskVolume42"
$attachmentIdentity =
    "minifilter-attachment:fixture-identity"

function New-Record
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,

        [Parameter(Mandatory = $true)]
        [string]$Identity,

        [Parameter(Mandatory = $true)]
        [string[]]$Tags,

        [Parameter(Mandatory = $true)]
        [hashtable]$Evidence
    )

    return [ordered]@{
        domain = $Domain
        identity = $Identity
        display = $Identity
        risk = "low"
        volatile = $false
        tags = $Tags
        evidence = $Evidence
    }
}

function New-Snapshot
{
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Attached", "Detached", "Reattached")]
        [string]$State
    )

    $records =
        [System.Collections.Generic.List[object]]::new()
    $records.Add(
        (New-Record `
            -Domain "minifilter-attachments" `
            -Identity "minifilter-volume:fixture" `
            -Tags @("minifilter-volume") `
            -Evidence @{
                volume_name = $volumeName
            })) |
        Out-Null
    $records.Add(
        (New-Record `
            -Domain "callbacks" `
            -Identity "callback:minifilter:fixture" `
            -Tags @("callback") `
            -Evidence @{
                kind = "minifilter"
                target = $filterName
                function = "0xfffff80000001000"
                function_module =
                    "KnLiveDbgMiniFilterFixture.sys"
            })) |
        Out-Null

    if ($State -ne "Detached")
    {
        $records.Add(
            (New-Record `
                -Domain "minifilter-attachments" `
                -Identity $attachmentIdentity `
                -Tags @(
                    "minifilter-attachment",
                    "minifilter"
                ) `
                -Evidence @{
                    kind = "minifilter"
                    filter_name = $filterName
                    instance_name = $instanceName
                    altitude = "370030.12345"
                    volume_name = $volumeName
                    detached_volume = "false"
                    aggregate_flags = "0x00000001"
                    instance_flags = "0x00000000"
                    frame_id = "0"
                    volume_filesystem_type = "2"
                    supported_features = "0x00000000"
                })) |
            Out-Null
    }

    return [ordered]@{
        schema = "kn-live-dbg.snapshot.v1"
        label = $State.ToLowerInvariant()
        timestamp_utc = "2026-07-29T00:00:00Z"
        same_boot_only = $true
        boot_id = "boot-fixture"
        json_path = ""
        report_path = ""
        metadata = [ordered]@{
            minifilter_attachments_coverage_complete =
                "true"
            minifilter_attachment_record_count =
                $(if ($State -eq "Detached") {
                    "0"
                } else {
                    "1"
                })
            minifilter_attachment_volume_count =
                "1"
            minifilter_attachment_detached_count =
                "0"
            callbacks_coverage_complete =
                "true"
            callbacks_record_count =
                "1"
        }
        domain_warnings = [ordered]@{}
        process_inventory = @()
        records = @($records)
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
        ConvertTo-Json -Depth 12 |
        Set-Content -LiteralPath $Path -Encoding UTF8
}

function Invoke-Case
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [int]$ExpectedExit,

        [scriptblock]$Mutation
    )

    $caseRoot = Join-Path $testRoot $Name
    New-Item -ItemType Directory -Path $caseRoot -Force |
        Out-Null
    $baselinePath = Join-Path $caseRoot "baseline.json"
    $detachedPath = Join-Path $caseRoot "detached.json"
    $reattachedPath = Join-Path $caseRoot "reattached.json"
    $positiveLogPath = Join-Path $caseRoot "positive.log"
    $recoveryLogPath = Join-Path $caseRoot "recovery.log"
    $validatorLogPath = Join-Path $caseRoot "validator.log"

    $baseline = New-Snapshot -State Attached
    $detached = New-Snapshot -State Detached
    $reattached = New-Snapshot -State Reattached
    $positiveLog = @"
[diff] baseline=attached current=detached sameBoot=yes added=0 escalated=0 removed=1 high=0
[diff.minifilter-attachments] added=0 escalated=0 removed=1 high=0 medium=1
  - [medium] minifilter-attachments fixture
    identity=$attachmentIdentity
"@
    $recoveryLog = @"
[diff] baseline=attached current=reattached sameBoot=yes added=0 escalated=0 removed=0 high=0
"@

    if ($null -ne $Mutation)
    {
        & $Mutation `
            ([ref]$baseline) `
            ([ref]$detached) `
            ([ref]$reattached) `
            ([ref]$positiveLog) `
            ([ref]$recoveryLog)
    }

    Write-Json -Document $baseline -Path $baselinePath
    Write-Json -Document $detached -Path $detachedPath
    Write-Json -Document $reattached -Path $reattachedPath
    Set-Content `
        -LiteralPath $positiveLogPath `
        -Value $positiveLog `
        -Encoding UTF8
    Set-Content `
        -LiteralPath $recoveryLogPath `
        -Value $recoveryLog `
        -Encoding UTF8

    $savedErrorPreference =
        $ErrorActionPreference
    try
    {
        $ErrorActionPreference = "Continue"
        & powershell.exe `
            -NoProfile `
            -ExecutionPolicy Bypass `
            -File $validator `
            -BaselinePath $baselinePath `
            -DetachedPath $detachedPath `
            -ReattachedPath $reattachedPath `
            -PositiveDiffLogPath $positiveLogPath `
            -RecoveryDiffLogPath $recoveryLogPath `
            -FilterName $filterName `
            -InstanceName $instanceName *> $validatorLogPath
        $exitCode = $LASTEXITCODE
    }
    finally
    {
        $ErrorActionPreference =
            $savedErrorPreference
    }
    if (($ExpectedExit -eq 0 -and
         $exitCode -ne 0) -or
        ($ExpectedExit -ne 0 -and
         $exitCode -eq 0))
    {
        $output =
            Get-Content -LiteralPath $validatorLogPath -Raw
        throw "case '$Name' returned exit=$exitCode expected=$ExpectedExit output=$output"
    }
    Write-Host (
        "[minifilter-detach-e2e-selftest] pass case={0} exit={1}" -f
            $Name,
            $exitCode)
}

try
{
    New-Item -ItemType Directory -Path $testRoot -Force |
        Out-Null

    Invoke-Case `
        -Name "valid" `
        -ExpectedExit 0
    Invoke-Case `
        -Name "cross-boot" `
        -ExpectedExit 1 `
        -Mutation {
            param($b, $d, $r, $p, $n)
            $d.Value.boot_id = "other-boot"
        }
    Invoke-Case `
        -Name "attachment-incomplete" `
        -ExpectedExit 1 `
        -Mutation {
            param($b, $d, $r, $p, $n)
            $d.Value.metadata.
                minifilter_attachments_coverage_complete =
                    "false"
        }
    Invoke-Case `
        -Name "callback-incomplete" `
        -ExpectedExit 1 `
        -Mutation {
            param($b, $d, $r, $p, $n)
            $d.Value.metadata.
                callbacks_coverage_complete =
                    "false"
        }
    Invoke-Case `
        -Name "volume-missing" `
        -ExpectedExit 1 `
        -Mutation {
            param($b, $d, $r, $p, $n)
            $d.Value.records = @(
                $d.Value.records |
                    Where-Object {
                        -not (@($_.tags) -contains
                            "minifilter-volume")
                    }
            )
            $d.Value.metadata.
                minifilter_attachment_volume_count =
                    "0"
        }
    Invoke-Case `
        -Name "filter-unloaded" `
        -ExpectedExit 1 `
        -Mutation {
            param($b, $d, $r, $p, $n)
            $d.Value.records = @(
                $d.Value.records |
                    Where-Object {
                        $_.domain -ne "callbacks"
                    }
            )
            $d.Value.metadata.callbacks_record_count =
                "0"
        }
    Invoke-Case `
        -Name "still-attached" `
        -ExpectedExit 1 `
        -Mutation {
            param($b, $d, $r, $p, $n)
            $d.Value = New-Snapshot -State Attached
        }
    Invoke-Case `
        -Name "counter-mismatch" `
        -ExpectedExit 1 `
        -Mutation {
            param($b, $d, $r, $p, $n)
            $b.Value.metadata.
                minifilter_attachment_record_count =
                    "2"
        }
    Invoke-Case `
        -Name "positive-log-missing-identity" `
        -ExpectedExit 1 `
        -Mutation {
            param($b, $d, $r, $p, $n)
            $p.Value =
                $p.Value.Replace(
                    $attachmentIdentity,
                    "different-identity")
        }
    Invoke-Case `
        -Name "recovery-removal" `
        -ExpectedExit 1 `
        -Mutation {
            param($b, $d, $r, $p, $n)
            $n.Value = @"
[diff] baseline=attached current=reattached sameBoot=yes added=0 escalated=0 removed=1 high=0
[diff.minifilter-attachments] added=0 escalated=0 removed=1 high=0 medium=1
  - [medium] minifilter-attachments fixture
    identity=$attachmentIdentity
"@
        }

    $malformedRoot = Join-Path $testRoot "malformed"
    New-Item `
        -ItemType Directory `
        -Path $malformedRoot `
        -Force |
        Out-Null
    $malformedBaseline =
        Join-Path $malformedRoot "baseline.json"
    Set-Content `
        -LiteralPath $malformedBaseline `
        -Value "{" `
        -Encoding UTF8
    $validDetached =
        Join-Path $malformedRoot "detached.json"
    $validReattached =
        Join-Path $malformedRoot "reattached.json"
    Write-Json `
        -Document (New-Snapshot -State Detached) `
        -Path $validDetached
    Write-Json `
        -Document (New-Snapshot -State Reattached) `
        -Path $validReattached
    $positiveLog =
        Join-Path $malformedRoot "positive.log"
    $recoveryLog =
        Join-Path $malformedRoot "recovery.log"
    Set-Content `
        -LiteralPath $positiveLog `
        -Value "[diff] sameBoot=yes" `
        -Encoding UTF8
    Set-Content `
        -LiteralPath $recoveryLog `
        -Value "[diff] sameBoot=yes" `
        -Encoding UTF8
    $savedErrorPreference =
        $ErrorActionPreference
    try
    {
        $ErrorActionPreference = "Continue"
        & powershell.exe `
            -NoProfile `
            -ExecutionPolicy Bypass `
            -File $validator `
            -BaselinePath $malformedBaseline `
            -DetachedPath $validDetached `
            -ReattachedPath $validReattached `
            -PositiveDiffLogPath $positiveLog `
            -RecoveryDiffLogPath $recoveryLog `
            -FilterName $filterName `
            -InstanceName $instanceName *> (
                Join-Path $malformedRoot "validator.log")
        $malformedExitCode =
            $LASTEXITCODE
    }
    finally
    {
        $ErrorActionPreference =
            $savedErrorPreference
    }
    if ($malformedExitCode -eq 0)
    {
        throw "malformed JSON case unexpectedly passed"
    }
    Write-Host (
        "[minifilter-detach-e2e-selftest] pass case=malformed exit={0}" -f
            $malformedExitCode)

    Write-Host (
        "minifilter detach E2E validator self-test passed")
}
finally
{
    $resolvedBuildRoot =
        [System.IO.Path]::GetFullPath(
            (Join-Path $rootPath ".build"))
    $resolvedTestRoot =
        [System.IO.Path]::GetFullPath($testRoot)
    if ($resolvedTestRoot.StartsWith(
            $resolvedBuildRoot +
                [System.IO.Path]::DirectorySeparatorChar,
            [System.StringComparison]::OrdinalIgnoreCase) -and
        (Test-Path -LiteralPath $resolvedTestRoot))
    {
        Remove-Item `
            -LiteralPath $resolvedTestRoot `
            -Recurse `
            -Force
    }
}

exit 0
