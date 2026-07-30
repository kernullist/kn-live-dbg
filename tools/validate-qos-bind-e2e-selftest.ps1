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
        "tools\validate-qos-bind-e2e.ps1")
$testRoot =
    Join-Path $rootPath (
        ".build\qos-bind-e2e-selftest-" +
        [Guid]::NewGuid().ToString("N"))
$fixtureId =
    "0123456789abcdef0123456789abcdef"
$fixtureRoot =
    "C:\Users\Test\AppData\Local\Temp\" +
    "KnLiveDbgBindFixture-$fixtureId"
$policyName =
    "KnLiveDbg-Qos-Fixture-$fixtureId"
$qosTarget =
    Join-Path $fixtureRoot "MsSense.exe"
$fileVirtual =
    Join-Path $fixtureRoot "amsi.dll"
$fileBacking =
    Join-Path $fixtureRoot "backing.dll"
$processVirtual =
    Join-Path $fixtureRoot "MsSense.exe"
$processBacking =
    Join-Path $fixtureRoot (
        "ProcessBindingBacking.exe")
$processId = 4242

function New-Finding
{
    param(
        [Parameter(Mandatory = $true)]
        [int]$ProcessIdentifier,

        [Parameter(Mandatory = $true)]
        [string[]]$Reasons,

        [Parameter(Mandatory = $true)]
        [hashtable]$Evidence,

        [string]$Class =
            "filesystem_virtualization_tampering"
    )

    return [ordered]@{
        risk = "high"
        confidence = "high"
        class = $Class
        title = "fixture"
        pid = $ProcessIdentifier
        eprocess = "0x0000000000000000"
        address = "0x0000000000000000"
        image = ""
        module = ""
        reasons = [object[]]$Reasons
        evidence = $Evidence
        followups = [object[]]@()
    }
}

function New-ValidDocument
{
    $qos =
        New-Finding `
            -ProcessIdentifier 0 `
            -Class "network_policy_tampering" `
            -Reasons @(
                "qos_security_product_throttle_policy",
                "security_tool_communication_throttling",
                "edrchoker_state"
            ) `
            -Evidence ([ordered]@{
                policy_name = $policyName
                instance_id =
                    "{$fixtureId}\$policyName\ActiveStore"
                owner = "PowerShell / WMI"
                app_path = $qosTarget
                security_product_target =
                    "mssense.exe"
                throttle_rate_bytes_per_second =
                    "8"
                throttle_rate_bits_per_second =
                    "64"
                near_zero_throttle = "true"
                active_store = "true"
                network_profile = "0"
                precedence = "127"
            })
    $fileMap =
        New-Finding `
            -ProcessIdentifier 0 `
            -Reasons @(
                "bindflt_active_global_mapping",
                "bind_link_security_artifact_path"
            ) `
            -Evidence ([ordered]@{
                volume_root = "C:\"
                virtual_root = $fileVirtual
                resolved_virtual_root =
                    $fileVirtual
                target_roots = $fileBacking
                resolved_target_roots =
                    $fileBacking
                target_count = "1"
                mapping_flags = "0x00000000"
                reparse_on_files = "false"
                security_product_target = ""
                global_mapping = "true"
                silo_mapping_coverage =
                    "unsupported"
            })
    $processMap =
        New-Finding `
            -ProcessIdentifier 0 `
            -Reasons @(
                "bindflt_active_global_mapping",
                "bind_link_security_product_path"
            ) `
            -Evidence ([ordered]@{
                volume_root = "C:\"
                virtual_root = $processVirtual
                resolved_virtual_root =
                    $processVirtual
                target_roots = $processBacking
                resolved_target_roots =
                    $processBacking
                target_count = "1"
                mapping_flags = "0x00000000"
                reparse_on_files = "false"
                security_product_target =
                    "mssense.exe"
                global_mapping = "true"
                silo_mapping_coverage =
                    "unsupported"
            })
    $processBinding =
        New-Finding `
            -ProcessIdentifier $processId `
            -Reasons @(
                "bindflt_active_global_mapping",
                "bind_link_process_binding_state",
                "bind_link_process_backing_correlation"
            ) `
            -Evidence ([ordered]@{
                volume_root = "C:\"
                virtual_root = $processVirtual
                resolved_virtual_root =
                    $processVirtual
                matched_target_root =
                    $processBacking
                resolved_target_root =
                    $processBacking
                mapping_flags = "0x00000000"
                global_mapping = "true"
                visible_source_views =
                    "api_image_path;peb_image_path"
                api_image_path = $processVirtual
                peb_image_path = $processVirtual
                disk_path = $processVirtual
                main_section_backing_path =
                    $processBacking
                main_section_backing_state =
                    "resolved"
                section_backing_path =
                    $processBacking
                section_backing_state =
                    "resolved"
                main_section_object =
                    "0x0000000000001000"
                main_section_segment =
                    "0x0000000000002000"
                main_section_control_area =
                    "0x0000000000003000"
                security_product_target =
                    "mssense.exe"
                independent_backing_views_agree =
                    "true"
                silo_mapping_coverage =
                    "unsupported"
            })

    return [ordered]@{
        schema = "kn-live-dbg.hunt.v1"
        timestamp_utc =
            "2026-07-29T00:00:00Z"
        mode = "Default"
        summary = [ordered]@{
            findings = 4
            high = 4
            medium = 0
            low = 0
            info = 0
            qos_policies = 1
            suspicious_qos_policies = 1
            qos_policy_coverage_incomplete =
                $false
            bindflt_global_mappings = 2
            suspicious_bindflt_global_mappings =
                2
            bindflt_process_bindings = 1
            bindflt_global_coverage_incomplete =
                $false
            bindflt_process_correlation_coverage_incomplete =
                $false
            bindflt_silo_coverage_unsupported =
                $true
        }
        warnings = [object[]]@()
        findings = [object[]]@(
            $qos,
            $fileMap,
            $processMap,
            $processBinding
        )
    }
}

function Copy-Document
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$Document
    )

    return $Document |
        ConvertTo-Json -Depth 15 |
        ConvertFrom-Json
}

function Invoke-ValidatorCase
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [object]$Document,

        [Parameter(Mandatory = $true)]
        [int]$ExpectedExit
    )

    $caseRoot =
        Join-Path $testRoot $Name
    New-Item `
        -ItemType Directory `
        -Path $caseRoot `
        -Force |
        Out-Null
    $jsonPath =
        Join-Path $caseRoot "hunt.json"
    $logPath =
        Join-Path $caseRoot "validator.log"
    $Document |
        ConvertTo-Json -Depth 15 |
        Set-Content `
            -LiteralPath $jsonPath `
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
            -HuntJson $jsonPath `
            -PolicyName $policyName `
            -QosTargetPath $qosTarget `
            -FileVirtualPath $fileVirtual `
            -FileBackingPath $fileBacking `
            -ProcessVirtualPath $processVirtual `
            -ProcessBackingPath $processBacking `
            -ProcessId $processId `
            -RequireMode Default *> $logPath
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
            "case '$Name' exit mismatch: expected=$ExpectedExit actual=$exitCode log=$log")
    }
    Write-Host (
        "[qos-bind-e2e-selftest] pass case={0} exit={1}" -f
            $Name,
            $exitCode)
}

New-Item `
    -ItemType Directory `
    -Path $testRoot `
    -Force |
    Out-Null

try
{
    $valid =
        New-ValidDocument
    Invoke-ValidatorCase `
        -Name "valid" `
        -Document $valid `
        -ExpectedExit 0

    & $validator `
        -HuntJson (
            Join-Path $testRoot "valid\hunt.json") `
        -PolicyName $policyName `
        -QosTargetPath $qosTarget `
        -FileVirtualPath $fileVirtual `
        -FileBackingPath $fileBacking `
        -ProcessVirtualPath $processVirtual `
        -ProcessBackingPath $processBacking `
        -ProcessId $processId `
        -RequireMode Default |
        Out-Null
    Write-Host (
        "[qos-bind-e2e-selftest] pass case=valid-current-host")

    $normalizedPolicyName =
        Copy-Document $valid
    $normalizedPolicyName.findings[0].
        evidence.policy_name =
            $policyName.ToLowerInvariant()
    Invoke-ValidatorCase `
        -Name "valid-provider-normalized-policy-name" `
        -Document $normalizedPolicyName `
        -ExpectedExit 0

    $deviceNamespacePaths =
        Copy-Document $valid
    $deviceRoot =
        "\Device\HarddiskVolume3"
    $deviceNamespacePaths.findings[1].
        evidence.virtual_root =
            $deviceRoot +
            $fileVirtual.Substring(2)
    $deviceNamespacePaths.findings[1].
        evidence.target_roots =
            $deviceRoot +
            $fileBacking.Substring(2)
    $deviceNamespacePaths.findings[2].
        evidence.virtual_root =
            $deviceRoot +
            $processVirtual.Substring(2)
    $deviceNamespacePaths.findings[2].
        evidence.target_roots =
            $deviceRoot +
            $processBacking.Substring(2)
    $deviceNamespacePaths.findings[3].
        evidence.virtual_root =
            $deviceRoot +
            $processVirtual.Substring(2)
    $deviceNamespacePaths.findings[3].
        evidence.matched_target_root =
            $deviceRoot +
            $processBacking.Substring(2)
    Invoke-ValidatorCase `
        -Name "valid-device-namespace-raw-paths" `
        -Document $deviceNamespacePaths `
        -ExpectedExit 0

    $rootRelativeBacking =
        Copy-Document $valid
    $rootRelativePath =
        $processBacking.Substring(2)
    $rootRelativeBacking.findings[3].
        evidence.main_section_backing_path =
            $rootRelativePath
    $rootRelativeBacking.findings[3].
        evidence.section_backing_path =
            $rootRelativePath
    Invoke-ValidatorCase `
        -Name "valid-root-relative-backing" `
        -Document $rootRelativeBacking `
        -ExpectedExit 0

    $qosIncomplete =
        Copy-Document $valid
    $qosIncomplete.summary.
        qos_policy_coverage_incomplete =
            $true
    Invoke-ValidatorCase `
        -Name "qos-incomplete" `
        -Document $qosIncomplete `
        -ExpectedExit 1

    $bindIncomplete =
        Copy-Document $valid
    $bindIncomplete.summary.
        bindflt_global_coverage_incomplete =
            $true
    Invoke-ValidatorCase `
        -Name "bind-global-incomplete" `
        -Document $bindIncomplete `
        -ExpectedExit 1

    $processIncomplete =
        Copy-Document $valid
    $processIncomplete.summary.
        bindflt_process_correlation_coverage_incomplete =
            $true
    Invoke-ValidatorCase `
        -Name "bind-process-incomplete" `
        -Document $processIncomplete `
        -ExpectedExit 1

    $siloClaim =
        Copy-Document $valid
    $siloClaim.summary.
        bindflt_silo_coverage_unsupported =
            $false
    Invoke-ValidatorCase `
        -Name "silo-overclaim" `
        -Document $siloClaim `
        -ExpectedExit 1

    $policyMismatch =
        Copy-Document $valid
    $policyMismatch.findings[0].
        evidence.policy_name =
            "other-policy"
    Invoke-ValidatorCase `
        -Name "policy-mismatch" `
        -Document $policyMismatch `
        -ExpectedExit 1

    $fileMappingMissing =
        Copy-Document $valid
    $originalFindings =
        @($fileMappingMissing.findings)
    $fileMappingMissing.findings =
        [object[]]@(
            $originalFindings[0],
            $originalFindings[2],
            $originalFindings[3]
        )
    $fileMappingMissing.summary.findings = 3
    $fileMappingMissing.summary.high = 3
    $fileMappingMissing.summary.
        suspicious_bindflt_global_mappings =
            1
    Invoke-ValidatorCase `
        -Name "file-mapping-missing" `
        -Document $fileMappingMissing `
        -ExpectedExit 1

    $backingMismatch =
        Copy-Document $valid
    $backingMismatch.findings[3].
        evidence.section_backing_path =
            "C:\Windows\System32\notepad.exe"
    Invoke-ValidatorCase `
        -Name "backing-mismatch" `
        -Document $backingMismatch `
        -ExpectedExit 1

    $pidMismatch =
        Copy-Document $valid
    $pidMismatch.findings[3].pid =
        5000
    Invoke-ValidatorCase `
        -Name "pid-mismatch" `
        -Document $pidMismatch `
        -ExpectedExit 1

    $summaryMismatch =
        Copy-Document $valid
    $summaryMismatch.summary.high = 3
    Invoke-ValidatorCase `
        -Name "summary-mismatch" `
        -Document $summaryMismatch `
        -ExpectedExit 1

    $wrongCounterType =
        Copy-Document $valid
    $wrongCounterType.summary.
        bindflt_global_mappings =
            "2"
    Invoke-ValidatorCase `
        -Name "wrong-counter-type" `
        -Document $wrongCounterType `
        -ExpectedExit 1

    $relevantWarning =
        Copy-Document $valid
    $relevantWarning.warnings =
        [object[]]@(
            "bindflt fixture enumeration incomplete")
    Invoke-ValidatorCase `
        -Name "relevant-warning" `
        -Document $relevantWarning `
        -ExpectedExit 1

    $malformedRoot =
        Join-Path $testRoot "malformed"
    New-Item `
        -ItemType Directory `
        -Path $malformedRoot `
        -Force |
        Out-Null
    $malformedPath =
        Join-Path $malformedRoot "hunt.json"
    "{ malformed" |
        Set-Content `
            -LiteralPath $malformedPath `
            -Encoding UTF8
    $malformedLog =
        Join-Path $malformedRoot "validator.log"
    $savedErrorPreference =
        $ErrorActionPreference
    try
    {
        $ErrorActionPreference = "Continue"
        & powershell.exe `
            -NoProfile `
            -ExecutionPolicy Bypass `
            -File $validator `
            -HuntJson $malformedPath `
            -PolicyName $policyName `
            -QosTargetPath $qosTarget `
            -FileVirtualPath $fileVirtual `
            -FileBackingPath $fileBacking `
            -ProcessVirtualPath $processVirtual `
            -ProcessBackingPath $processBacking `
            -ProcessId $processId *> $malformedLog
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
        "[qos-bind-e2e-selftest] pass case=malformed exit={0}" -f
            $malformedExitCode)

    Write-Host (
        "QoS/Bind E2E validator self-test passed")
}
finally
{
    $resolvedBuildRoot =
        [System.IO.Path]::GetFullPath(
            (Join-Path $rootPath ".build"))
    $resolvedTestRoot =
        [System.IO.Path]::GetFullPath(
            $testRoot)
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
