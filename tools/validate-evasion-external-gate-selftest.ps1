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
$validator =
    Join-Path $rootPath (
        "tools\validate-evasion-external-gate.ps1")
$testRoot =
    Join-Path $rootPath (
        ".build\evasion-external-gate-selftest-" +
        [Guid]::NewGuid().ToString("N"))
$qosRoot =
    Join-Path $testRoot "qos-bind"
$cloudNegativeRoot =
    Join-Path $testRoot "cloudfiles-in-sync"
$cloudPositiveRoot =
    Join-Path $testRoot "cloudfiles-modified"
$minifilterRoot =
    Join-Path $testRoot "minifilter"
$cleanRoot =
    Join-Path $testRoot "clean-host"

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
        Set-Content `
            -LiteralPath $Path `
            -Encoding UTF8
}

function Copy-Document
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$Document
    )

    return $Document |
        ConvertTo-Json -Depth 12 |
        ConvertFrom-Json
}

function Get-FileSha256
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

function Invoke-ValidatorCase
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [object]$Document,

        [Parameter(Mandatory = $true)]
        [int]$ExpectedExit,

        [string]$ExpectedPattern = ""
    )

    $manifestPath =
        Join-Path $testRoot (
            "manifest-$Name.json")
    $logPath =
        Join-Path $testRoot (
            "validator-$Name.log")
    Write-Json `
        -Document $Document `
        -Path $manifestPath

    $savedErrorPreference =
        $ErrorActionPreference
    try
    {
        $ErrorActionPreference = "Continue"
        & powershell.exe `
            -NoProfile `
            -ExecutionPolicy Bypass `
            -File $validator `
            -ManifestPath $manifestPath *> $logPath
        $exitCode =
            $LASTEXITCODE
    }
    finally
    {
        $ErrorActionPreference =
            $savedErrorPreference
    }
    if ($exitCode -ne $ExpectedExit)
    {
        $log =
            Get-Content -LiteralPath $logPath -Raw
        throw (
            "case '$Name' exit mismatch: " +
            "expected=$ExpectedExit actual=$exitCode log=$log")
    }
    if (-not [string]::IsNullOrWhiteSpace(
            $ExpectedPattern))
    {
        $log =
            Get-Content `
                -LiteralPath $logPath `
                -Raw
        if ($log -notmatch $ExpectedPattern)
        {
            throw (
                "case '$Name' did not emit pattern " +
                "'$ExpectedPattern': $log")
        }
    }
    Write-Host (
        "[evasion-external-gate-selftest] pass case={0} exit={1}" -f
            $Name,
            $exitCode)
}

function Invoke-RunnerRejectionCase
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$ScriptPath,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedPattern
    )

    $logPath =
        Join-Path $testRoot (
            "runner-$Name.log")
    $savedErrorPreference =
        $ErrorActionPreference
    try
    {
        $ErrorActionPreference = "Continue"
        & powershell.exe `
            -NoProfile `
            -ExecutionPolicy Bypass `
            -File $ScriptPath @Arguments *> $logPath
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
    if ($exitCode -eq 0 -or
        $log -notmatch $ExpectedPattern)
    {
        throw (
            "runner rejection '$Name' mismatch: " +
            "exit=$exitCode pattern=$ExpectedPattern log=$log")
    }
    Write-Host (
        "[evasion-external-gate-selftest] pass runner-case={0} exit={1}" -f
            $Name,
            $exitCode)
}

New-Item `
    -ItemType Directory `
    -Path @(
        $qosRoot,
        $cloudNegativeRoot,
        $cloudPositiveRoot,
        $minifilterRoot,
        $cleanRoot
    ) `
    -Force |
    Out-Null

try
{
    $runnerDefinitions =
        @(
            [pscustomobject]@{
                Name = "qos"
                Script =
                    Join-Path $rootPath (
                        "tools\run-qos-bind-e2e.ps1")
            },
            [pscustomobject]@{
                Name = "minifilter"
                Script =
                    Join-Path $rootPath (
                        "tools\run-minifilter-detach-e2e.ps1")
            },
            [pscustomobject]@{
                Name = "aggregate"
                Script =
                    Join-Path $rootPath (
                        "tools\run-evasion-external-gate.ps1")
            }
        )
    foreach ($runner in $runnerDefinitions)
    {
        Invoke-RunnerRejectionCase `
            -Name "$($runner.Name)-broad-output" `
            -ScriptPath $runner.Script `
            -Arguments @(
                "-Root",
                $rootPath,
                "-OutputDirectory",
                $rootPath,
                "-NoElevation"
            ) `
            -ExpectedPattern (
                "dedicated child directory")

        $runnerOutput =
            Join-Path $testRoot (
                "runner-output-$($runner.Name)")
        $escapedStatus =
            Join-Path $testRoot (
                "escaped-status-$($runner.Name).txt")
        Invoke-RunnerRejectionCase `
            -Name "$($runner.Name)-status-escape" `
            -ScriptPath $runner.Script `
            -Arguments @(
                "-Root",
                $rootPath,
                "-OutputDirectory",
                $runnerOutput,
                "-NoElevation",
                "-ElevationStatusPath",
                $escapedStatus
            ) `
            -ExpectedPattern (
                "outside the expected parent")
    }

    Invoke-RunnerRejectionCase `
        -Name "cloudfiles-broad-output" `
        -ScriptPath (
            Join-Path $rootPath (
                "tools\run-cloudfiles-placeholder-fixture.ps1")) `
        -Arguments @(
            "-ValidateHunt",
            "-HuntOutputDirectory",
            $rootPath
        ) `
        -ExpectedPattern (
            "dedicated child directory")

    $staleManifestRoot =
        Join-Path $testRoot (
            "runner-stale-minifilter")
    New-Item `
        -ItemType Directory `
        -Path $staleManifestRoot `
        -Force |
        Out-Null
    $staleManifest =
        Join-Path $staleManifestRoot (
            "manifest.json")
    '{"status":"passed"}' |
        Set-Content `
            -LiteralPath $staleManifest `
            -Encoding UTF8
    Invoke-RunnerRejectionCase `
        -Name "minifilter-stale-manifest" `
        -ScriptPath (
            Join-Path $rootPath (
                "tools\run-minifilter-detach-e2e.ps1")) `
        -Arguments @(
            "-Root",
            $rootPath,
            "-OutputDirectory",
            $staleManifestRoot,
            "-Volume",
            "invalid",
            "-NoElevation"
        ) `
        -ExpectedPattern (
            "administrator rights are required|Volume must be a local drive root")
    if (Test-Path -LiteralPath $staleManifest)
    {
        throw (
            "minifilter runner retained a stale passed manifest after preflight failure")
    }

    $qosHunt =
        Join-Path $qosRoot (
            "hunt\hunt-clean-default-01.json")
    New-Item `
        -ItemType Directory `
        -Path (
            Split-Path -Parent $qosHunt) `
        -Force |
        Out-Null
    "{}" |
        Set-Content `
            -LiteralPath $qosHunt `
            -Encoding UTF8
    $qosValidatorLog =
        Join-Path $qosRoot "validator.log"
    "passed" |
        Set-Content `
            -LiteralPath $qosValidatorLog `
            -Encoding UTF8
    $qosManifestPath =
        Join-Path $qosRoot "manifest.json"
    $qosManifest = [ordered]@{
        schema = "kn-live-dbg.qos-bind-e2e.v1"
        status = "passed"
        policy_name =
            "KnLiveDbg-Qos-Fixture-" +
            "0123456789abcdef0123456789abcdef"
        qos_target = "C:\fixture\MsSense.exe"
        file_virtual = "C:\fixture\amsi.dll"
        file_backing = "C:\fixture\backing.dll"
        process_virtual =
            "C:\fixture\MsSense.exe"
        process_backing =
            "C:\fixture\ProcessBindingBacking.exe"
        process_id = 4242
        hunt_json = $qosHunt
        validator_log = $qosValidatorLog
        cleanup = "passed"
    }
    Write-Json `
        -Document $qosManifest `
        -Path $qosManifestPath

    $cloudDefinitions = @(
        [pscustomobject]@{
            Root = $cloudNegativeRoot
            Scenario = "InSyncNegative"
        },
        [pscustomobject]@{
            Root = $cloudPositiveRoot
            Scenario = "ModifiedPositive"
        }
    )
    foreach ($cloud in $cloudDefinitions)
    {
        $huntPath =
            Join-Path $cloud.Root (
                "hunt-clean-deep-01.json")
        "{}" |
            Set-Content `
                -LiteralPath $huntPath `
                -Encoding UTF8
        $cloudManifest = [ordered]@{
            schema =
                "kn-live-dbg.cloudfiles-fixture-e2e.v1"
            status = "passed"
            scenario = $cloud.Scenario
            process_id = 4242
            image_path =
                "C:\fixture\CloudFilesFixture.exe"
            hunt_mode = "Deep"
            hunt_json = $huntPath
            cleanup = "passed"
        }
        Write-Json `
            -Document $cloudManifest `
            -Path (
                Join-Path $cloud.Root (
                    "cloudfiles-fixture-manifest.json"))
    }

    foreach ($name in @(
            "attached.json",
            "detached.json",
            "reattached.json"))
    {
        "{}" |
            Set-Content `
                -LiteralPath (
                    Join-Path $minifilterRoot $name) `
                -Encoding UTF8
    }
    foreach ($name in @(
            "positive-diff.stdout.log",
            "recovery-diff.stdout.log",
            "validator.log"))
    {
        "passed" |
            Set-Content `
                -LiteralPath (
                    Join-Path $minifilterRoot $name) `
                -Encoding UTF8
    }
    $minifilterManifestPath =
        Join-Path $minifilterRoot "manifest.json"
    $minifilterManifest = [ordered]@{
        schema =
            "kn-live-dbg.minifilter-detach-e2e.v1"
        status = "passed"
        filter = "KnLiveDbgMiniFilterFixture"
        instance =
            "KnLiveDbgMiniFilterFixture.Instance"
        altitude = "370030.12345"
        volume = "C:"
        driver =
            "C:\fixture\KnLiveDbgMiniFilterFixture.sys"
        attached_snapshot =
            Join-Path $minifilterRoot "attached.json"
        detached_snapshot =
            Join-Path $minifilterRoot "detached.json"
        reattached_snapshot =
            Join-Path $minifilterRoot "reattached.json"
        positive_diff_log =
            Join-Path $minifilterRoot (
                "positive-diff.stdout.log")
        recovery_diff_log =
            Join-Path $minifilterRoot (
                "recovery-diff.stdout.log")
        validator_log =
            Join-Path $minifilterRoot "validator.log"
        cleanup = "passed"
    }
    Write-Json `
        -Document $minifilterManifest `
        -Path $minifilterManifestPath

    for ($run = 1; $run -le 3; ++$run)
    {
        "{}" |
            Set-Content `
                -LiteralPath (
                    Join-Path $cleanRoot (
                        "hunt-clean-deep-{0:D2}.json" -f
                            $run)) `
                -Encoding UTF8
    }
    @(
        "status=success",
        "runs=3",
        "mode=Deep",
        "threat_intel=True"
    ) |
        Set-Content `
            -LiteralPath (
                Join-Path $cleanRoot "status.txt") `
            -Encoding UTF8
    $analysisPath =
        Join-Path $cleanRoot "analysis.json"
    $analysis = [ordered]@{
        schema =
            "kn-live-dbg.hunt-clean-analysis.v1"
        summary = [ordered]@{
            run_count = 3
            complete_runs = 3
            total_findings = 0
            unique_fingerprints = 0
            deterministic_fingerprints = 0
            intermittent_fingerprints = 0
            all_clean_complete = $true
        }
        runs = [object[]]@(
            [ordered]@{ run = 1 },
            [ordered]@{ run = 2 },
            [ordered]@{ run = 3 }
        )
        finding_groups = [object[]]@()
    }
    Write-Json `
        -Document $analysis `
        -Path $analysisPath

    $artifactPaths = [ordered]@{
        qos_bind_manifest = $qosManifestPath
        cloudfiles_in_sync_manifest =
            Join-Path $cloudNegativeRoot (
                "cloudfiles-fixture-manifest.json")
        cloudfiles_modified_manifest =
            Join-Path $cloudPositiveRoot (
                "cloudfiles-fixture-manifest.json")
        minifilter_manifest =
            $minifilterManifestPath
        clean_host_analysis = $analysisPath
    }
    $artifactHashes = [ordered]@{}
    foreach ($entry in $artifactPaths.GetEnumerator())
    {
        $artifactHashes[$entry.Key] =
            Get-FileSha256 `
                -Path $entry.Value
    }
    $valid = [ordered]@{
        schema =
            "kn-live-dbg.evasion-external-gate.v1"
        status = "passed"
        elevated = $true
        configuration = "Release"
        volume = "C:"
        clean_run_count = 3
        threat_intel_required = $true
        silo_binding_coverage_unsupported =
            $true
        artifacts = $artifactPaths
        artifact_sha256 = $artifactHashes
        cleanup = "passed"
    }

    Invoke-ValidatorCase `
        -Name "valid" `
        -Document $valid `
        -ExpectedExit 0

    & $validator `
        -ManifestPath (
            Join-Path $testRoot "manifest-valid.json") |
        Out-Null
    Write-Host (
        "[evasion-external-gate-selftest] pass case=valid-current-host")

    $cleanupFailure =
        Copy-Document $valid
    $cleanupFailure.cleanup = "failed"
    Invoke-ValidatorCase `
        -Name "cleanup-failure" `
        -Document $cleanupFailure `
        -ExpectedExit 1

    $notElevated =
        Copy-Document $valid
    $notElevated.elevated = $false
    Invoke-ValidatorCase `
        -Name "not-elevated" `
        -Document $notElevated `
        -ExpectedExit 1

    $siloOverclaim =
        Copy-Document $valid
    $siloOverclaim.
        silo_binding_coverage_unsupported =
            $false
    Invoke-ValidatorCase `
        -Name "silo-overclaim" `
        -Document $siloOverclaim `
        -ExpectedExit 1

    $wrongRunType =
        Copy-Document $valid
    $wrongRunType.clean_run_count = "3"
    Invoke-ValidatorCase `
        -Name "wrong-run-type" `
        -Document $wrongRunType `
        -ExpectedExit 1

    $runCountMismatch =
        Copy-Document $valid
    $runCountMismatch.clean_run_count = 2
    Invoke-ValidatorCase `
        -Name "run-count-mismatch" `
        -Document $runCountMismatch `
        -ExpectedExit 1 `
        -ExpectedPattern "between 3 and 10"

    $pathEscape =
        Copy-Document $valid
    $pathEscape.artifacts.
        qos_bind_manifest =
            "C:\outside\manifest.json"
    Invoke-ValidatorCase `
        -Name "path-escape" `
        -Document $pathEscape `
        -ExpectedExit 1

    $hashMismatch =
        Copy-Document $valid
    $hashMismatch.artifact_sha256.
        qos_bind_manifest =
            ("0" * 64)
    Invoke-ValidatorCase `
        -Name "hash-mismatch" `
        -Document $hashMismatch `
        -ExpectedExit 1

    $dirtyAnalysis =
        Copy-Document $analysis
    $dirtyAnalysis.summary.total_findings = 1
    $dirtyAnalysis.summary.
        all_clean_complete = $false
    Write-Json `
        -Document $dirtyAnalysis `
        -Path $analysisPath
    $dirtyGate =
        Copy-Document $valid
    $dirtyGate.artifact_sha256.
        clean_host_analysis =
            Get-FileSha256 `
                -Path $analysisPath
    Invoke-ValidatorCase `
        -Name "dirty-analysis" `
        -Document $dirtyGate `
        -ExpectedExit 1
    Write-Json `
        -Document $analysis `
        -Path $analysisPath

    $malformedPath =
        Join-Path $testRoot (
            "manifest-malformed.json")
    "{ malformed" |
        Set-Content `
            -LiteralPath $malformedPath `
            -Encoding UTF8
    $malformedLog =
        Join-Path $testRoot (
            "validator-malformed.log")
    $savedErrorPreference =
        $ErrorActionPreference
    try
    {
        $ErrorActionPreference = "Continue"
        & powershell.exe `
            -NoProfile `
            -ExecutionPolicy Bypass `
            -File $validator `
            -ManifestPath $malformedPath *> $malformedLog
        $malformedExit =
            $LASTEXITCODE
    }
    finally
    {
        $ErrorActionPreference =
            $savedErrorPreference
    }
    if ($malformedExit -eq 0)
    {
        throw (
            "malformed external gate manifest unexpectedly passed")
    }
    Write-Host (
        "[evasion-external-gate-selftest] pass case=malformed exit=$malformedExit")

    Write-Host (
        "evasion external gate validator self-test passed")
}
finally
{
    $resolvedBuildRoot =
        [IO.Path]::GetFullPath(
            (Join-Path $rootPath ".build"))
    $resolvedTestRoot =
        [IO.Path]::GetFullPath(
            $testRoot)
    if ($resolvedTestRoot.StartsWith(
            $resolvedBuildRoot +
                [IO.Path]::DirectorySeparatorChar,
            [StringComparison]::OrdinalIgnoreCase) -and
        (Test-Path -LiteralPath $resolvedTestRoot))
    {
        Remove-Item `
            -LiteralPath $resolvedTestRoot `
            -Recurse `
            -Force
    }
}

exit 0
