param(
    [string]$Root = (Get-Location).Path,

    [switch]$SkipSmoke
)

$ErrorActionPreference = "Stop"

function Invoke-Step
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Script
    )

    Write-Host "[hunt-readiness] start $Name"
    & $Script
    Write-Host "[hunt-readiness] pass $Name"
}

function Test-IsAdministrator
{
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertTo-ProcessArgument
{
    param(
        [AllowNull()]
        [string]$Value
    )

    if ($null -eq $Value)
    {
        return '""'
    }
    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]')
    {
        return $Value
    }

    $escaped = $Value -replace '(\\*)"', '$1$1\"'
    $escaped = $escaped -replace '(\\+)$', '$1$1'
    return '"' + $escaped + '"'
}

function ConvertTo-ProcessArguments
{
    param(
        [string[]]$Arguments = @()
    )

    $escaped = @()
    foreach ($argument in $Arguments)
    {
        $escaped += ConvertTo-ProcessArgument -Value $argument
    }

    return ($escaped -join ' ')
}

function New-SyntheticHuntAssessment
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Severity,

        [Parameter(Mandatory = $true)]
        [int]$Count,

        [Parameter(Mandatory = $true)]
        [string]$Subject,

        [Parameter(Mandatory = $true)]
        [string]$What,

        [Parameter(Mandatory = $true)]
        [string]$Why,

        [Parameter(Mandatory = $true)]
        [string]$Next
    )

    return [ordered]@{
        severity = $Severity
        count = $Count
        subject = $Subject
        what = $What
        why = $Why
        next = $Next
    }
}

function Get-SyntheticHuntVerdict
{
    param(
        [int]$High,
        [int]$Medium,
        [int]$Low
    )

    if ($High -gt 0)
    {
        return "alert"
    }
    if ($Medium -gt 0)
    {
        return "review"
    }
    if ($Low -gt 0)
    {
        return "low_signal"
    }

    return "clean"
}

function New-SyntheticHuntConsoleStdout
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$HuntJson,

        [Parameter(Mandatory = $true)]
        [int]$Findings,

        [Parameter(Mandatory = $true)]
        [int]$High,

        [Parameter(Mandatory = $true)]
        [int]$Medium,

        [Parameter(Mandatory = $true)]
        [int]$Low,

        [int]$DriverServiceIocs = 0,

        [int]$ThreatIntelCorrelations = 0,

        [object[]]$Assessments = @()
    )

    $verdict = Get-SyntheticHuntVerdict -High $High -Medium $Medium -Low $Low
    $assessmentList = @($Assessments)
    $shownAssessments = @($assessmentList | Select-Object -First 4)
    $summaryLine = "[hunt.summary] scanned=0 findings=$Findings high=$High medium=$Medium low=$Low"
    if ($DriverServiceIocs -gt 0)
    {
        $summaryLine += " driver_service_iocs=$DriverServiceIocs"
    }
    if ($ThreatIntelCorrelations -gt 0)
    {
        $summaryLine += " ti_correlations=$ThreatIntelCorrelations"
    }

    $lines = @(
        "json written: $HuntJson",
        "!hunt mode=deep schema=kn-live-dbg.hunt.v1 timestamp=synthetic",
        "[hunt.conclusion] verdict=$verdict findings=$Findings high=$High medium=$Medium low=$Low warnings=0",
        "[hunt.assessment] showing=$($shownAssessments.Count) total_findings=$Findings"
    )

    if ($shownAssessments.Count -eq 0)
    {
        $lines += "  answer=`"no suspicious hunt findings were emitted for the scanned system view`""
    }

    for ($index = 0; $index -lt $shownAssessments.Count; ++$index)
    {
        $assessment = $shownAssessments[$index]
        $row = $index + 1
        $lines += "  #$row severity=$($assessment.severity) count=$($assessment.count) subject=`"$($assessment.subject)`""
        $lines += "     what=`"$($assessment.what)`""
        $lines += "     why=`"$($assessment.why)`""
        $lines += "     next=`"$($assessment.next)`""
    }

    if ($assessmentList.Count -gt $shownAssessments.Count)
    {
        $lines += "  more_groups=$($assessmentList.Count - $shownAssessments.Count) use /details for raw triage tables or /json for full evidence"
    }

    $lines += $summaryLine
    $lines += "[hunt.detail] suppressed=yes raw_tables=yes total_findings=$Findings use /details for raw triage tables or /json for full evidence"

    return $lines
}

function Invoke-HuntTargetValidatorSummary
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Manifest,

        [Parameter(Mandatory = $true)]
        [string]$HuntJson,

        [Parameter(Mandatory = $true)]
        [string]$Log
    )

    if (Test-Path -LiteralPath $Log)
    {
        Remove-Item -LiteralPath $Log -Force
    }

    & (Join-Path $rootPath "tools\validate-hunt-target.ps1") `
        -Manifest $Manifest `
        -HuntJson $HuntJson *> $Log

    if ($LASTEXITCODE -ne 0)
    {
        Get-Content -LiteralPath $Log | Select-Object -Last 80 | Out-Host
        throw "$Name failed with exit code $LASTEXITCODE; log=$Log"
    }

    $summaryLines = @(
        Get-Content -LiteralPath $Log |
            Where-Object {
                $_ -match "^hunt target validation$" -or
                $_ -match "^\s+pid=" -or
                $_ -match "^\s+scenarios=" -or
                $_ -match "^\s+target_findings=" -or
                $_ -match "^\s+system_findings=" -or
                $_ -match "^\s+positive_scenarios=" -or
                $_ -match "^\s+matched_positive_scenarios=" -or
                $_ -match "^validation passed$"
            }
    )

    foreach ($line in $summaryLines)
    {
        Write-Host "[hunt-readiness] validator $line"
    }

    Write-Host "[hunt-readiness] validator log=$Log"
}

function Invoke-HuntTargetValidatorExpectedFailure
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Manifest,

        [Parameter(Mandatory = $true)]
        [string]$SourceHuntJson,

        [Parameter(Mandatory = $true)]
        [string]$MutatedHuntJson,

        [Parameter(Mandatory = $true)]
        [string]$Log,

        [Parameter(Mandatory = $true)]
        [string]$Property,

        [Parameter(Mandatory = $true)]
        [string]$BadValue
    )

    if (Test-Path -LiteralPath $Log)
    {
        Remove-Item -LiteralPath $Log -Force
    }
    if (Test-Path -LiteralPath $MutatedHuntJson)
    {
        Remove-Item -LiteralPath $MutatedHuntJson -Force
    }

    $doc = Get-Content -LiteralPath $SourceHuntJson -Raw | ConvertFrom-Json
    $findings = @($doc.findings)
    if ($findings.Count -eq 0)
    {
        throw "$Name cannot mutate an empty hunt JSON: $SourceHuntJson"
    }

    $finding = $findings[0]
    if ($null -eq $finding.PSObject.Properties[$Property])
    {
        throw "$Name cannot mutate missing finding property '$Property'"
    }

    $finding.PSObject.Properties[$Property].Value = $BadValue
    $doc | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $MutatedHuntJson -Encoding UTF8

    & (Join-Path $rootPath "tools\validate-hunt-target.ps1") `
        -Manifest $Manifest `
        -HuntJson $MutatedHuntJson *> $Log

    if ($LASTEXITCODE -eq 0)
    {
        throw "$Name unexpectedly accepted mutated $Property=$BadValue; log=$Log"
    }

    $logText = Get-Content -LiteralPath $Log -Raw
    if ($logText.IndexOf("validation failed", [System.StringComparison]::OrdinalIgnoreCase) -lt 0)
    {
        throw "$Name failed without validator failure text; log=$Log"
    }

    Write-Host "[hunt-readiness] validator mutation rejected property=$Property bad_value=$BadValue log=$Log"
}

function Invoke-EsetArtifactValidatorExpectedFailure
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Manifest,

        [Parameter(Mandatory = $true)]
        [string]$HuntJson,

        [Parameter(Mandatory = $true)]
        [string]$Stdout,

        [string]$RunnerLog = "",

        [switch]$RequireRunnerPassed,

        [Parameter(Mandatory = $true)]
        [string]$ValidatorLog,

        [Parameter(Mandatory = $true)]
        [string]$OuterLog
    )

    $exitCode = 0
    try
    {
        $validatorArgs = @(
            "-Root", $rootPath,
            "-Manifest", $Manifest,
            "-HuntJson", $HuntJson,
            "-Stdout", $Stdout
        )
        if (-not [string]::IsNullOrWhiteSpace($RunnerLog))
        {
            $validatorArgs += @("-RunnerLog", $RunnerLog)
        }
        if ($RequireRunnerPassed)
        {
            $validatorArgs += @("-RequireRunnerPassed")
        }
        $validatorArgs += @("-ValidatorLog", $ValidatorLog)

        & (Join-Path $rootPath "tools\validate-eset-hunt-e2e-artifacts.ps1") @validatorArgs *> $OuterLog
        $exitCode = $LASTEXITCODE
    }
    catch
    {
        $exitCode = 1
        $_ | Out-String | Add-Content -LiteralPath $OuterLog -Encoding UTF8
    }

    if ($exitCode -eq 0)
    {
        throw "$Name unexpectedly passed artifact validation"
    }
}

function Get-SyntheticEsetDriverServiceFixtures
{
    return @(
        [pscustomobject]@{ File = "eb.sys"; Leaf = "eb.sys"; Scenario = "edr-killer-driver-service-eb"; Family = "GentleKiller"; Tool = "Kaspersky variant custom rootkit"; Strong = $true },
        [pscustomobject]@{ File = "nseckrnl.sys"; Leaf = "nseckrnl.sys"; Scenario = "edr-killer-driver-service-nseckrnl"; Family = "GentleKiller"; Tool = "NSecsoft NSecKrnl driver"; Strong = $true },
        [pscustomobject]@{ File = "vgk.sys"; Leaf = "vgk.sys"; Scenario = "edr-killer-driver-service-vgk"; Family = "GentleKiller"; Tool = "Tower of Fantasy AntiCheat driver"; Strong = $false },
        [pscustomobject]@{ File = "gamedriverx64.sys"; Leaf = "gamedriverx64.sys"; Scenario = "edr-killer-driver-service-gamedriverx64"; Family = "GentleKiller"; Tool = "Tower of Fantasy AntiCheat driver"; Strong = $false },
        [pscustomobject]@{ File = "stpm_old.sys"; Leaf = "stpm_old.sys"; Scenario = "edr-killer-driver-service-stpm-old"; Family = "GentleKiller"; Tool = "Safetica Process Monitor driver"; Strong = $true },
        [pscustomobject]@{ File = "stpm_new.sys"; Leaf = "stpm_new.sys"; Scenario = "edr-killer-driver-service-stpm-new"; Family = "GentleKiller"; Tool = "Safetica Process Monitor driver"; Strong = $true },
        [pscustomobject]@{ File = "dmx.sys"; Leaf = "dmx.sys"; Scenario = "edr-killer-driver-service-dmx"; Family = "GentleKiller"; Tool = "Zemana WatchDog driver"; Strong = $true },
        [pscustomobject]@{ File = "360netmon_wfp.sys"; Leaf = "360netmon_wfp.sys"; Scenario = "edr-killer-driver-service-360netmon-wfp"; Family = "GentleKiller"; Tool = "Qihoo 360 network monitor driver"; Strong = $false },
        [pscustomobject]@{ File = "360netmon.sys"; Leaf = "360netmon.sys"; Scenario = "edr-killer-driver-service-360netmon"; Family = "GentleKiller"; Tool = "Qihoo 360 network monitor driver"; Strong = $false },
        [pscustomobject]@{ File = "IMFForceDelete"; Leaf = "imfforcedelete"; Scenario = "edr-killer-driver-service-imfforcedelete"; Family = "GentleKiller"; Tool = "IObit IMF ForceDelete filter driver"; Strong = $true },
        [pscustomobject]@{ File = "PoisonX"; Leaf = "poisonx"; Scenario = "edr-killer-driver-service-poisonx"; Family = "GentleKiller"; Tool = "PoisonX rootkit"; Strong = $true },
        [pscustomobject]@{ File = "g11.sys"; Leaf = "g11.sys"; Scenario = "edr-killer-driver-service-g11"; Family = "GentleKiller"; Tool = "PoisonX rootkit"; Strong = $true },
        [pscustomobject]@{ File = "googleapiutil64.sys"; Leaf = "googleapiutil64.sys"; Scenario = "edr-killer-driver-service-googleapiutil64"; Family = "HexKiller"; Tool = "Baidu Antivirus BdApi driver"; Strong = $true },
        [pscustomobject]@{ File = "throttleblood.sys"; Leaf = "throttleblood.sys"; Scenario = "edr-killer-driver-service-throttleblood"; Family = "ThrottleBlood"; Tool = "ThrottleStop driver"; Strong = $true },
        [pscustomobject]@{ File = "havoc.sys"; Leaf = "havoc.sys"; Scenario = "edr-killer-driver-service-havoc"; Family = "HavocKiller"; Tool = "Huawei vulnerable driver"; Strong = $true }
    )
}

function Get-EsetProcessSuffixScenarioNames
{
    return @(
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
        "edr-killer-suffix-name-sophos"
    )
}

function Get-EsetProcessScenarioNames
{
    $names = @()
    $names += Get-EsetProcessSuffixScenarioNames
    $names += @(
        "edr-killer-weak-vendor-standalone-negative",
        "edr-killer-gentlemen-staging-only-negative",
        "edr-killer-exact-name-deletor",
        "edr-killer-exact-name-hwaudkiller",
        "oxideharvest-cli",
        "oxideharvest-name-only-negative"
    )

    return $names
}

function Get-EsetDriverServiceScenarioNames
{
    return @(Get-SyntheticEsetDriverServiceFixtures | ForEach-Object { [string]$_.Scenario })
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

function Assert-ManifestScenarioUnexpectedReason
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

function Get-SyntheticServiceBinaryPath
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$Fixture,

        [Parameter(Mandatory = $true)]
        [int]$Index
    )

    $basePath = "C:\Temp\GentlemenCollection\$($Fixture.File)"
    if (($Fixture.File.IndexOf(".") -lt 0) -and (($Index % 2) -eq 1))
    {
        return "$basePath /hunt-parser-check-unquoted-extensionless"
    }
    if (($Index % 2) -eq 0)
    {
        return "`"$basePath`" /hunt-parser-check"
    }

    return $basePath
}

function Invoke-StopEventTargetSmoke
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetExe
    )

    $smokeDir = Join-Path $rootPath ".build\hunt-readiness-stop-event"
    if (-not (Test-Path -LiteralPath $smokeDir))
    {
        New-Item -ItemType Directory -Path $smokeDir | Out-Null
    }

    $manifest = Join-Path $smokeDir "manifest.json"
    $stdout = Join-Path $smokeDir "target.stdout.log"
    $stderr = Join-Path $smokeDir "target.stderr.log"
    Remove-Item -LiteralPath $manifest, $stdout, $stderr -Force -ErrorAction SilentlyContinue

    $stopEventName = "Local\KnLiveDbgHuntReadinessStop-$PID-$([Guid]::NewGuid().ToString('N'))"
    $created = $false
    $stopEvent = [System.Threading.EventWaitHandle]::new(
        $false,
        [System.Threading.EventResetMode]::ManualReset,
        $stopEventName,
        [ref]$created)

    $process = $null
    try
    {
        $arguments = @(
            "/private-exec",
            "/seconds",
            "30",
            "/stop-event",
            $stopEventName,
            "/manifest",
            $manifest
        )
        $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $TargetExe
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $startInfo.Arguments = ConvertTo-ProcessArguments -Arguments $arguments

        $process = [System.Diagnostics.Process]::new()
        $process.StartInfo = $startInfo
        if (-not $process.Start())
        {
            throw "stop-event smoke failed to start target: $TargetExe"
        }

        $deadline = [DateTime]::UtcNow.AddSeconds(10)
        while ([DateTime]::UtcNow -lt $deadline -and -not (Test-Path -LiteralPath $manifest))
        {
            Start-Sleep -Milliseconds 100
        }
        if (-not (Test-Path -LiteralPath $manifest))
        {
            throw "stop-event smoke manifest missing: $manifest"
        }

        [void]$stopEvent.Set()
        if (-not $process.WaitForExit(10000))
        {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            throw "stop-event smoke target did not exit after signal; log=$stdout"
        }

        $stdoutText = ""
        $stderrText = ""
        if ($null -ne $process.StandardOutput)
        {
            $stdoutText = $process.StandardOutput.ReadToEnd()
        }
        if ($null -ne $process.StandardError)
        {
            $stderrText = $process.StandardError.ReadToEnd()
        }
        Set-Content -LiteralPath $stdout -Encoding UTF8 -Value $stdoutText
        Set-Content -LiteralPath $stderr -Encoding UTF8 -Value $stderrText

        $exitCode = $process.ExitCode
        if ($exitCode -ne 0)
        {
            throw "stop-event smoke target exited with code $exitCode; stdout=$stdout stderr=$stderr"
        }

        Write-Host "[hunt-readiness] stop-event smoke manifest=$manifest"
    }
    finally
    {
        $stopEvent.Dispose()
        if ($null -ne $process)
        {
            $process.Dispose()
        }
    }
}

function New-SyntheticEsetDriverServiceValidationFiles
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Manifest,

        [Parameter(Mandatory = $true)]
        [string]$HuntJson,

        [string]$Stdout
    )

    $scenarios = @()
    $findings = @()
    $fixtures = @(Get-SyntheticEsetDriverServiceFixtures)

    for ($index = 0; $index -lt $fixtures.Count; ++$index)
    {
        $fixture = $fixtures[$index]
        $serviceName = "KnLiveDbgHuntTargetEdrSvc1234_$index"
        $binaryPath = Get-SyntheticServiceBinaryPath -Fixture $fixture -Index $index
        $strong = if ($fixture.Strong) { "true" } else { "false" }
        $risk = if ($fixture.Strong) { "medium" } else { "low" }
        $confidence = if ($fixture.Strong) { "high" } else { "medium" }
        $reasons = @(
            "driver_service_installed",
            "driver_service_binary_name_ioc",
            "gentlemen_edr_killer_driver_service",
            "driver_service_not_running",
            "gentlemen_collection_staging_path"
        )
        if (-not $fixture.Strong)
        {
            $reasons += "name_only_requires_hash_or_staging_correlation"
        }

        $expectedEvidence = [ordered]@{
            service_name = $serviceName
            binary_path = $binaryPath
            expanded_binary_path = $binaryPath
            binary_leaf = $fixture.Leaf
            matched_driver_leaf = $fixture.Leaf
            gentlemen_family = $fixture.Family
            gentlemen_tool = $fixture.Tool
            gentlemen_ioc_driver = $fixture.Leaf
            strong_name_signal = $strong
            gentlemen_collection_path = "true"
        }

        $scenarios += [ordered]@{
            name = $fixture.Scenario
            artifact = "synthetic service"
            pid = 0
            expected_reasons = $reasons
            expected_class = "edr_killer_driver_service"
            expected_risk = $risk
            expected_confidence = $confidence
            expected_evidence_keys = @(
                "service_name",
                "binary_path",
                "expanded_binary_path",
                "binary_leaf",
                "matched_driver_leaf",
                "gentlemen_family",
                "gentlemen_tool",
                "gentlemen_ioc_driver",
                "strong_name_signal",
                "gentlemen_collection_path"
            )
            expected_evidence = $expectedEvidence
        }

        $findings += [ordered]@{
            risk = $risk
            confidence = $confidence
            class = "edr_killer_driver_service"
            title = "driver service matches Gentlemen EDR-killer driver IOC"
            pid = 0
            address = "0x0000000000000000"
            artifact = $fixture.Leaf
            reasons = $reasons
            evidence = [ordered]@{
                service_name = $serviceName
                display_name = "synthetic"
                service_type = "00000001"
                state = "stopped"
                start_type = "demand"
                binary_path = $binaryPath
                expanded_binary_path = $binaryPath
                binary_leaf = $fixture.Leaf
                matched_driver_leaf = $fixture.Leaf
                has_config = "true"
                gentlemen_family = $fixture.Family
                gentlemen_tool = $fixture.Tool
                gentlemen_ioc_driver = $fixture.Leaf
                strong_name_signal = $strong
                gentlemen_collection_path = "true"
            }
        }
    }

    $manifestDoc = [ordered]@{
        schema = "kn-live-dbg.hunt-target-manifest.v1"
        pid = 1234
        scenario_count = $scenarios.Count
        scenarios = $scenarios
    }
    $huntDoc = [ordered]@{
        schema = "kn-live-dbg.hunt.v1"
        summary = [ordered]@{
            findings = $findings.Count
            high = 0
            medium = @($findings | Where-Object { $_.risk -eq "medium" }).Count
            low = @($findings | Where-Object { $_.risk -eq "low" }).Count
            edr_killer_driver_services = $findings.Count
        }
        findings = $findings
    }

    $manifestDoc | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $Manifest -Encoding UTF8
    $huntDoc | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $HuntJson -Encoding UTF8

    if (-not [string]::IsNullOrWhiteSpace($Stdout))
    {
        $mediumCount = @($findings | Where-Object { $_.risk -eq "medium" }).Count
        $lowCount = @($findings | Where-Object { $_.risk -eq "low" }).Count
        $assessment = New-SyntheticHuntAssessment `
            -Severity "medium" `
            -Count $findings.Count `
            -Subject "system" `
            -What "SCM or loaded-driver state exposes a known defense-evasion driver artifact" `
            -Why "known defense-evasion driver service; known driver-service binary name; known tool staging path" `
            -Next "review the SCM service, loaded-driver path, and binary hash in /json"
        Set-Content `
            -LiteralPath $Stdout `
            -Encoding UTF8 `
            -Value (New-SyntheticHuntConsoleStdout `
                -HuntJson $HuntJson `
                -Findings $findings.Count `
                -High 0 `
                -Medium $mediumCount `
                -Low $lowCount `
                -DriverServiceIocs $findings.Count `
                -Assessments @($assessment))
    }
}

function New-SyntheticEsetRunningDriverServiceValidationFiles
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Manifest,

        [Parameter(Mandatory = $true)]
        [string]$HuntJson,

        [Parameter(Mandatory = $true)]
        [string]$Stdout
    )

    $fixture = @(Get-SyntheticEsetDriverServiceFixtures | Where-Object { $_.Strong })[0]
    $serviceName = "KnLiveDbgHuntTargetEdrSvc1234_running"
    $binaryPath = "C:\Temp\GentlemenCollection\$($fixture.File)"
    $reasons = @(
        "driver_service_installed",
        "driver_service_binary_name_ioc",
        "gentlemen_edr_killer_driver_service",
        "driver_service_running",
        "gentlemen_collection_staging_path"
    )
    $expectedEvidence = [ordered]@{
        service_name = $serviceName
        binary_path = $binaryPath
        expanded_binary_path = $binaryPath
        binary_leaf = $fixture.Leaf
        matched_driver_leaf = $fixture.Leaf
        gentlemen_family = $fixture.Family
        gentlemen_tool = $fixture.Tool
        gentlemen_ioc_driver = $fixture.Leaf
        strong_name_signal = "true"
        gentlemen_collection_path = "true"
    }

    $manifestDoc = [ordered]@{
        schema = "kn-live-dbg.hunt-target-manifest.v1"
        pid = 1234
        scenario_count = 1
        scenarios = @(
            [ordered]@{
                name = "edr-killer-driver-service-running-strong"
                artifact = "synthetic running service"
                pid = 0
                expected_reasons = $reasons
                expected_class = "edr_killer_driver_service"
                expected_risk = "high"
                expected_confidence = "high"
                expected_evidence_keys = @(
                    "service_name",
                    "binary_path",
                    "expanded_binary_path",
                    "binary_leaf",
                    "matched_driver_leaf",
                    "gentlemen_family",
                    "gentlemen_tool",
                    "gentlemen_ioc_driver",
                    "strong_name_signal",
                    "gentlemen_collection_path"
                )
                expected_evidence = $expectedEvidence
            }
        )
    }
    $huntDoc = [ordered]@{
        schema = "kn-live-dbg.hunt.v1"
        summary = [ordered]@{
            findings = 1
            high = 1
            medium = 0
            low = 0
            edr_killer_driver_services = 1
        }
        findings = @(
            [ordered]@{
                risk = "high"
                confidence = "high"
                class = "edr_killer_driver_service"
                title = "driver service matches Gentlemen EDR-killer driver IOC"
                pid = 0
                address = "0x0000000000000000"
                artifact = $fixture.Leaf
                reasons = $reasons
                evidence = [ordered]@{
                    service_name = $serviceName
                    display_name = "synthetic running service"
                    service_type = "00000001"
                    state = "running"
                    start_type = "demand"
                    binary_path = $binaryPath
                    expanded_binary_path = $binaryPath
                    binary_leaf = $fixture.Leaf
                    matched_driver_leaf = $fixture.Leaf
                    has_config = "true"
                    gentlemen_family = $fixture.Family
                    gentlemen_tool = $fixture.Tool
                    gentlemen_ioc_driver = $fixture.Leaf
                    strong_name_signal = "true"
                    gentlemen_collection_path = "true"
                }
            }
        )
    }

    $manifestDoc | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $Manifest -Encoding UTF8
    $huntDoc | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $HuntJson -Encoding UTF8
    $assessment = New-SyntheticHuntAssessment `
        -Severity "high" `
        -Count 1 `
        -Subject "system" `
        -What "SCM or loaded-driver state exposes a known defense-evasion driver artifact" `
        -Why "known defense-evasion driver service; known driver-service binary name; known tool staging path" `
        -Next "review the SCM service, loaded-driver path, and binary hash in /json"
    Set-Content `
        -LiteralPath $Stdout `
        -Encoding UTF8 `
        -Value (New-SyntheticHuntConsoleStdout `
            -HuntJson $HuntJson `
            -Findings 1 `
            -High 1 `
            -Medium 0 `
            -Low 0 `
            -DriverServiceIocs 1 `
            -Assessments @($assessment))
}

function New-SyntheticEsetExactHashValidationFiles
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Manifest,

        [Parameter(Mandatory = $true)]
        [string]$HuntJson,

        [Parameter(Mandatory = $true)]
        [string]$Stdout
    )

    $processSha1 = "8ae6bd18b129061f63642531f1b684cf0383c75d"
    $driverSha1 = "ba914fe77b177b45799403b16dd14765c510a074"
    $oxideSha1 = "a5cf917ec4a7dfbdfa43621398604805d860c718"
    $scenarios = @(
        [ordered]@{
            name = "eset-hash-renamed-edr-process"
            artifact = "synthetic renamed process exact SHA1 IOC"
            pid = 7101
            expected_reasons = @("eset_exact_file_sha1_ioc", "edr_killer_exact_file_sha1_ioc")
            expected_class = "edr_killer_file_ioc"
            expected_risk = "high"
            expected_confidence = "high"
            expected_evidence_keys = @("file_hash_path", "file_sha1", "eset_ioc_sha1", "eset_ioc_filename", "eset_ioc_family", "eset_ioc_tool")
            expected_evidence = [ordered]@{
                image_name = "renamed-edr.exe"
                file_sha1 = $processSha1
                eset_ioc_sha1 = $processSha1
                eset_ioc_filename = "Kasps.exe"
                eset_ioc_family = "GentleKiller"
                eset_ioc_tool = "Kaspersky variant"
                eset_ioc_credential_tool = "false"
            }
        },
        [ordered]@{
            name = "eset-hash-renamed-oxideharvest-process"
            artifact = "synthetic renamed OxideHarvest exact SHA1 IOC"
            pid = 7102
            expected_reasons = @("eset_exact_file_sha1_ioc", "oxideharvest_exact_file_sha1_ioc")
            expected_class = "oxideharvest_file_ioc"
            expected_risk = "high"
            expected_confidence = "high"
            expected_evidence_keys = @("file_hash_path", "file_sha1", "eset_ioc_sha1", "eset_ioc_filename", "eset_ioc_family", "eset_ioc_tool")
            expected_evidence = [ordered]@{
                image_name = "renamed-credential.exe"
                file_sha1 = $oxideSha1
                eset_ioc_sha1 = $oxideSha1
                eset_ioc_filename = "buildx641.exe"
                eset_ioc_family = "OxideHarvest"
                eset_ioc_tool = "credential stealer"
                eset_ioc_credential_tool = "true"
            }
        },
        [ordered]@{
            name = "eset-hash-renamed-loaded-driver"
            artifact = "synthetic loaded driver exact SHA1 IOC"
            pid = 0
            expected_reasons = @("loaded_driver_file_hash_ioc", "eset_exact_file_sha1_ioc", "edr_killer_exact_file_sha1_ioc")
            expected_class = "edr_killer_driver_file_ioc"
            expected_risk = "high"
            expected_confidence = "high"
            expected_evidence_keys = @("driver_disk_path", "file_hash_path", "file_sha1", "eset_ioc_sha1", "eset_ioc_filename", "eset_ioc_family", "eset_ioc_tool")
            expected_evidence = [ordered]@{
                driver_image_name = "renameddrv.sys"
                file_sha1 = $driverSha1
                eset_ioc_sha1 = $driverSha1
                eset_ioc_filename = "eb.sys"
                eset_ioc_family = "GentleKiller"
                eset_ioc_tool = "Kaspersky variant custom rootkit"
                eset_ioc_credential_tool = "false"
            }
        },
        [ordered]@{
            name = "eset-hash-renamed-driver-service"
            artifact = "synthetic driver service exact SHA1 IOC"
            pid = 0
            expected_reasons = @("driver_service_installed", "gentlemen_edr_killer_driver_service", "driver_service_file_hash_ioc", "eset_exact_file_sha1_ioc", "edr_killer_exact_file_sha1_ioc")
            expected_class = "edr_killer_driver_service"
            expected_risk = "high"
            expected_confidence = "high"
            expected_evidence_keys = @("service_name", "binary_path", "binary_leaf", "file_hash_path", "file_sha1", "eset_ioc_sha1", "eset_ioc_filename", "eset_ioc_family", "eset_ioc_tool")
            expected_evidence = [ordered]@{
                service_name = "KnLiveDbgHuntTargetEdrSvc1234_hash"
                binary_leaf = "renameddrv.sys"
                file_sha1 = $driverSha1
                eset_ioc_sha1 = $driverSha1
                eset_ioc_filename = "eb.sys"
                eset_ioc_family = "GentleKiller"
                eset_ioc_tool = "Kaspersky variant custom rootkit"
                eset_ioc_credential_tool = "false"
            }
        }
    )
    $findings = @(
        [ordered]@{
            risk = "high"
            confidence = "high"
            class = "edr_killer_file_ioc"
            title = "process image matches ESET Gentlemen EDR-killer SHA1 IOC"
            pid = 7101
            address = "0x0000000000000000"
            artifact = "renamed-edr.exe"
            reasons = @("eset_exact_file_sha1_ioc", "edr_killer_exact_file_sha1_ioc")
            evidence = [ordered]@{
                image_name = "renamed-edr.exe"
                image_path = "C:\Temp\renamed-edr.exe"
                file_hash_path = "C:\Temp\renamed-edr.exe"
                file_sha1 = $processSha1
                eset_ioc_sha1 = $processSha1
                eset_ioc_filename = "Kasps.exe"
                eset_ioc_family = "GentleKiller"
                eset_ioc_tool = "Kaspersky variant"
                eset_ioc_credential_tool = "false"
            }
        },
        [ordered]@{
            risk = "high"
            confidence = "high"
            class = "oxideharvest_file_ioc"
            title = "process image matches ESET OxideHarvest SHA1 IOC"
            pid = 7102
            address = "0x0000000000000000"
            artifact = "renamed-credential.exe"
            reasons = @("eset_exact_file_sha1_ioc", "oxideharvest_exact_file_sha1_ioc")
            evidence = [ordered]@{
                image_name = "renamed-credential.exe"
                image_path = "C:\Temp\renamed-credential.exe"
                file_hash_path = "C:\Temp\renamed-credential.exe"
                file_sha1 = $oxideSha1
                eset_ioc_sha1 = $oxideSha1
                eset_ioc_filename = "buildx641.exe"
                eset_ioc_family = "OxideHarvest"
                eset_ioc_tool = "credential stealer"
                eset_ioc_credential_tool = "true"
            }
        },
        [ordered]@{
            risk = "high"
            confidence = "high"
            class = "edr_killer_driver_file_ioc"
            title = "loaded kernel driver matches ESET Gentlemen EDR-killer SHA1 IOC"
            pid = 0
            address = "0x0000000000001000"
            artifact = "renameddrv.sys"
            reasons = @("loaded_driver_file_hash_ioc", "eset_exact_file_sha1_ioc", "edr_killer_exact_file_sha1_ioc")
            evidence = [ordered]@{
                driver_image_name = "renameddrv.sys"
                driver_image_path = "\SystemRoot\System32\drivers\renameddrv.sys"
                driver_disk_path = "C:\Temp\drivers\renameddrv.sys"
                file_hash_path = "C:\Temp\drivers\renameddrv.sys"
                file_sha1 = $driverSha1
                eset_ioc_sha1 = $driverSha1
                eset_ioc_filename = "eb.sys"
                eset_ioc_family = "GentleKiller"
                eset_ioc_tool = "Kaspersky variant custom rootkit"
                eset_ioc_credential_tool = "false"
            }
        },
        [ordered]@{
            risk = "high"
            confidence = "high"
            class = "edr_killer_driver_service"
            title = "driver service matches Gentlemen EDR-killer driver IOC"
            pid = 0
            address = "0x0000000000000000"
            artifact = "renameddrv.sys"
            reasons = @("driver_service_installed", "gentlemen_edr_killer_driver_service", "driver_service_file_hash_ioc", "eset_exact_file_sha1_ioc", "edr_killer_exact_file_sha1_ioc")
            evidence = [ordered]@{
                service_name = "KnLiveDbgHuntTargetEdrSvc1234_hash"
                display_name = "synthetic hash service"
                service_type = "00000001"
                state = "stopped"
                start_type = "demand"
                binary_path = "C:\Temp\drivers\renameddrv.sys"
                expanded_binary_path = "C:\Temp\drivers\renameddrv.sys"
                binary_leaf = "renameddrv.sys"
                file_hash_path = "C:\Temp\drivers\renameddrv.sys"
                file_sha1 = $driverSha1
                eset_ioc_sha1 = $driverSha1
                eset_ioc_filename = "eb.sys"
                eset_ioc_family = "GentleKiller"
                eset_ioc_tool = "Kaspersky variant custom rootkit"
                eset_ioc_credential_tool = "false"
            }
        }
    )

    $manifestDoc = [ordered]@{
        schema = "kn-live-dbg.hunt-target-manifest.v1"
        pid = 1234
        scenario_count = $scenarios.Count
        scenarios = $scenarios
    }
    $huntDoc = [ordered]@{
        schema = "kn-live-dbg.hunt.v1"
        summary = [ordered]@{
            findings = $findings.Count
            high = $findings.Count
            medium = 0
            low = 0
            edr_killer_driver_services = 1
        }
        findings = $findings
    }

    $manifestDoc | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $Manifest -Encoding UTF8
    $huntDoc | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $HuntJson -Encoding UTF8
    $assessment = New-SyntheticHuntAssessment `
        -Severity "high" `
        -Count 4 `
        -Subject "renamed-edr.exe(7101),renamed-credential.exe(7102),system" `
        -What "process, driver, or service binary matches a published threat file hash" `
        -Why "published file hash IOC; exact defense-evasion file hash; exact credential-tool file hash; known defense-evasion driver service" `
        -Next "isolate the subject and review matched hash paths in /json"
    Set-Content `
        -LiteralPath $Stdout `
        -Encoding UTF8 `
        -Value (New-SyntheticHuntConsoleStdout `
            -HuntJson $HuntJson `
            -Findings 4 `
            -High 4 `
            -Medium 0 `
            -Low 0 `
            -DriverServiceIocs 1 `
            -Assessments @($assessment))
}

function New-SyntheticEsetMetadataEvasionValidationFiles
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Manifest,

        [Parameter(Mandatory = $true)]
        [string]$HuntJson,

        [Parameter(Mandatory = $true)]
        [string]$Stdout
    )

    $reasons = @(
        "gentlemen_edr_killer_process_name",
        "gentlemen_collection_staging_path",
        "edr_killer_invalid_code_signature",
        "edr_killer_version_info_impersonation_evidence",
        "edr_killer_icon_impersonation_evidence",
        "edr_killer_packer_section_evidence"
    )
    $evidence = [ordered]@{
        image_name = "KaspsClear.exe"
        image_path = "C:\Temp\GentlemenCollection\KaspsClear.exe"
        image_metadata_path = "C:\Temp\GentlemenCollection\KaspsClear.exe"
        image_signature_present = "true"
        image_signature_valid = "false"
        image_signature_status = "800B0109"
        image_version_info_present = "true"
        image_version_info_impersonation_match = "kaspersky"
        image_icon_resource_present = "true"
        image_packer_section_hint = "enigma"
        image_packer_section_names = ".enigma"
        gentlemen_collection_path = "true"
        gentlemen_family = "GentleKiller"
        gentlemen_tool = "Kaspersky variant"
        gentlemen_ioc_image = "kasps.exe"
    }
    $manifestDoc = [ordered]@{
        schema = "kn-live-dbg.hunt-target-manifest.v1"
        pid = 1234
        scenario_count = 1
        scenarios = @(
            [ordered]@{
                name = "edr-killer-metadata-evasion-full"
                artifact = "synthetic ESET metadata evasion process profile"
                pid = 7201
                expected_reasons = $reasons
                expected_class = "edr_killer_process_profile"
                expected_risk = "high"
                expected_confidence = "high"
                expected_evidence_keys = @(
                    "image_signature_present",
                    "image_signature_valid",
                    "image_version_info_present",
                    "image_version_info_impersonation_match",
                    "image_icon_resource_present",
                    "image_packer_section_hint",
                    "gentlemen_collection_path"
                )
                expected_evidence = $evidence
            }
        )
    }
    $huntDoc = [ordered]@{
        schema = "kn-live-dbg.hunt.v1"
        summary = [ordered]@{
            findings = 1
            high = 1
            medium = 0
            low = 0
            edr_killer_driver_services = 0
        }
        findings = @(
            [ordered]@{
                risk = "high"
                confidence = "high"
                class = "edr_killer_process_profile"
                title = "process matches Gentlemen EDR-killer masquerade profile"
                pid = 7201
                address = "0x0000000000000000"
                artifact = "KaspsClear.exe"
                reasons = $reasons
                evidence = $evidence
            }
        )
    }

    $manifestDoc | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $Manifest -Encoding UTF8
    $huntDoc | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $HuntJson -Encoding UTF8
    $assessment = New-SyntheticHuntAssessment `
        -Severity "high" `
        -Count 1 `
        -Subject "KaspsClear.exe(7201)" `
        -What "process identity or metadata masquerades as a known defense-evasion tool" `
        -Why "known defense-evasion tool name; known tool staging path; invalid code signature; manipulated version information; manipulated icon resource; packed or protected PE section" `
        -Next "review image path, signature, version info, and staging path in /json"
    Set-Content `
        -LiteralPath $Stdout `
        -Encoding UTF8 `
        -Value (New-SyntheticHuntConsoleStdout `
            -HuntJson $HuntJson `
            -Findings 1 `
            -High 1 `
            -Medium 0 `
            -Low 0 `
            -Assessments @($assessment))
}

function New-SyntheticEsetSecurityProductTelemetryValidationFiles
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Manifest,

        [Parameter(Mandatory = $true)]
        [string]$HuntJson,

        [Parameter(Mandatory = $true)]
        [string]$Stdout
    )

    $reasons = @(
        "ti_process_impairment_event",
        "defense_impairment_telemetry",
        "known_security_product_process_target",
        "gentlekiller_security_target_list"
    )
    $evidence = [ordered]@{
        caller_pid = "6101"
        caller_image = "renamed-tool.exe"
        caller_image_path = "C:\Temp\renamed-tool.exe"
        matched_image_leaf = "renamed-tool.exe"
        gentlemen_collection_path = "false"
        ti_event_count = "2"
        security_product_target_count = "2"
        security_product_targets = "msmpeng.exe;ekrn.exe"
        target_pid_count = "2"
        target_pids = "6201;6202"
    }
    $manifestDoc = [ordered]@{
        schema = "kn-live-dbg.hunt-target-manifest.v1"
        pid = 1234
        scenario_count = 1
        scenarios = @(
            [ordered]@{
                name = "gentlekiller-security-product-target-list-telemetry"
                artifact = "synthetic renamed caller repeatedly targeting ESET Table 2 security products"
                pid = 6101
                expected_reasons = $reasons
                expected_class = "edr_killer_security_product_impairment_telemetry"
                expected_risk = "medium"
                expected_confidence = "medium"
                expected_evidence_keys = @(
                    "caller_pid",
                    "caller_image",
                    "security_product_target_count",
                    "security_product_targets",
                    "target_pid_count",
                    "target_pids"
                )
                expected_evidence = $evidence
            }
        )
    }
    $huntDoc = [ordered]@{
        schema = "kn-live-dbg.hunt.v1"
        summary = [ordered]@{
            findings = 1
            high = 0
            medium = 1
            low = 0
            edr_killer_driver_services = 0
            threat_intel_correlations = 1
        }
        findings = @(
            [ordered]@{
                risk = "medium"
                confidence = "medium"
                class = "edr_killer_security_product_impairment_telemetry"
                title = "Threat-Intelligence events show repeated control of known security-product processes"
                pid = 6101
                address = "0x0000000000000000"
                artifact = "synthetic renamed caller"
                reasons = $reasons
                evidence = $evidence
            }
        )
    }

    $manifestDoc | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $Manifest -Encoding UTF8
    $huntDoc | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $HuntJson -Encoding UTF8
    $assessment = New-SyntheticHuntAssessment `
        -Severity "medium" `
        -Count 1 `
        -Subject "renamed-tool.exe(6101)" `
        -What "process repeatedly controlled known security-product processes" `
        -Why "security-product process targeting; known security-product target list" `
        -Next "review recent !ti events and the target process list in /json"
    Set-Content `
        -LiteralPath $Stdout `
        -Encoding UTF8 `
        -Value (New-SyntheticHuntConsoleStdout `
            -HuntJson $HuntJson `
            -Findings 1 `
            -High 0 `
            -Medium 1 `
            -Low 0 `
            -ThreatIntelCorrelations 1 `
            -Assessments @($assessment))
}

function Add-SyntheticEsetProcessScenario
{
    param(
        [System.Collections.ArrayList]$Scenarios,

        [System.Collections.ArrayList]$Findings,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [int]$ScenarioPid,

        [Parameter(Mandatory = $true)]
        [string[]]$Reasons,

        [Parameter(Mandatory = $true)]
        [string]$Class,

        [Parameter(Mandatory = $true)]
        [string]$Risk,

        [Parameter(Mandatory = $true)]
        [string]$Confidence,

        [hashtable]$Evidence = @{}
    )

    $scenarioEvidence = [ordered]@{}
    foreach ($key in @($Evidence.Keys | Sort-Object))
    {
        $scenarioEvidence[$key] = [string]$Evidence[$key]
    }

    [void]$Scenarios.Add([ordered]@{
        name = $Name
        artifact = "synthetic process"
        pid = $ScenarioPid
        expected_reasons = $Reasons
        expected_class = $Class
        expected_risk = $Risk
        expected_confidence = $Confidence
        expected_evidence = $scenarioEvidence
    })

    [void]$Findings.Add([ordered]@{
        risk = $Risk
        confidence = $Confidence
        class = $Class
        title = "synthetic ESET process contract"
        pid = $ScenarioPid
        address = "0x0000000000000000"
        artifact = $Name
        reasons = $Reasons
        evidence = $scenarioEvidence
    })
}

function Add-SyntheticEsetNegativeScenario
{
    param(
        [System.Collections.ArrayList]$Scenarios,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [int]$ScenarioPid,

        [Parameter(Mandatory = $true)]
        [string[]]$UnexpectedReasons
    )

    [void]$Scenarios.Add([ordered]@{
        name = $Name
        artifact = "synthetic negative process"
        pid = $ScenarioPid
        expected_reasons = @()
        unexpected_reasons = $UnexpectedReasons
    })
}

function Add-SyntheticEsetDriverServiceScenario
{
    param(
        [System.Collections.ArrayList]$Scenarios,

        [System.Collections.ArrayList]$Findings,

        [Parameter(Mandatory = $true)]
        [object]$Fixture,

        [Parameter(Mandatory = $true)]
        [int]$Index
    )

    $serviceName = "KnLiveDbgHuntTargetEdrSvc1234_$Index"
    $binaryPath = Get-SyntheticServiceBinaryPath -Fixture $Fixture -Index $Index
    $strong = if ($Fixture.Strong) { "true" } else { "false" }
    $risk = if ($Fixture.Strong) { "medium" } else { "low" }
    $confidence = if ($Fixture.Strong) { "high" } else { "medium" }
    $reasons = @(
        "driver_service_installed",
        "driver_service_binary_name_ioc",
        "gentlemen_edr_killer_driver_service",
        "driver_service_not_running",
        "gentlemen_collection_staging_path"
    )
    if (-not $Fixture.Strong)
    {
        $reasons += "name_only_requires_hash_or_staging_correlation"
    }

    $expectedEvidence = [ordered]@{
        service_name = $serviceName
        binary_path = $binaryPath
        expanded_binary_path = $binaryPath
        binary_leaf = $Fixture.Leaf
        matched_driver_leaf = $Fixture.Leaf
        gentlemen_family = $Fixture.Family
        gentlemen_tool = $Fixture.Tool
        gentlemen_ioc_driver = $Fixture.Leaf
        strong_name_signal = $strong
        gentlemen_collection_path = "true"
    }

    [void]$Scenarios.Add([ordered]@{
        name = $Fixture.Scenario
        artifact = "synthetic service"
        pid = 0
        expected_reasons = $reasons
        expected_class = "edr_killer_driver_service"
        expected_risk = $risk
        expected_confidence = $confidence
        expected_evidence_keys = @(
            "service_name",
            "binary_path",
            "expanded_binary_path",
            "binary_leaf",
            "matched_driver_leaf",
            "gentlemen_family",
            "gentlemen_tool",
            "gentlemen_ioc_driver",
            "strong_name_signal",
            "gentlemen_collection_path"
        )
        expected_evidence = $expectedEvidence
    })

    [void]$Findings.Add([ordered]@{
        risk = $risk
        confidence = $confidence
        class = "edr_killer_driver_service"
        title = "driver service matches Gentlemen EDR-killer driver IOC"
        pid = 0
        address = "0x0000000000000000"
        artifact = $Fixture.Leaf
        reasons = $reasons
        evidence = [ordered]@{
            service_name = $serviceName
            display_name = "synthetic"
            service_type = "00000001"
            state = "stopped"
            start_type = "demand"
            binary_path = $binaryPath
            expanded_binary_path = $binaryPath
            binary_leaf = $Fixture.Leaf
            matched_driver_leaf = $Fixture.Leaf
            has_config = "true"
            gentlemen_family = $Fixture.Family
            gentlemen_tool = $Fixture.Tool
            gentlemen_ioc_driver = $Fixture.Leaf
            strong_name_signal = $strong
            gentlemen_collection_path = "true"
        }
    })
}

function New-SyntheticEsetFullValidationFiles
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Manifest,

        [Parameter(Mandatory = $true)]
        [string]$HuntJson,

        [Parameter(Mandatory = $true)]
        [string]$Stdout
    )

    $scenarios = [System.Collections.ArrayList]::new()
    $findings = [System.Collections.ArrayList]::new()
    $scenarioPid = 5000
    $suffixReasons = @(
        "gentlemen_edr_killer_process_name",
        "gentlemen_suffix_normalized_process_name",
        "gentlemen_collection_staging_path",
        "edr_killer_version_info_impersonation_evidence",
        "edr_killer_packer_section_evidence"
    )
    $suffixScenarios = @(Get-EsetProcessSuffixScenarioNames)

    foreach ($scenarioName in $suffixScenarios)
    {
        ++$scenarioPid
        Add-SyntheticEsetProcessScenario `
            -Scenarios $scenarios `
            -Findings $findings `
            -Name $scenarioName `
            -ScenarioPid $scenarioPid `
            -Reasons $suffixReasons `
            -Class "edr_killer_process_profile" `
            -Risk "high" `
            -Confidence "high" `
            -Evidence @{
                image_version_info_present = "true"
                image_packer_section_hint = "enigma"
                gentlemen_collection_path = "true"
            }
    }

    ++$scenarioPid
    Add-SyntheticEsetNegativeScenario `
        -Scenarios $scenarios `
        -Name "edr-killer-weak-vendor-standalone-negative" `
        -ScenarioPid $scenarioPid `
        -UnexpectedReasons @("gentlemen_edr_killer_process_name", "security_vendor_impersonation_name", "gentlemen_suffix_normalized_process_name")

    ++$scenarioPid
    Add-SyntheticEsetNegativeScenario `
        -Scenarios $scenarios `
        -Name "edr-killer-gentlemen-staging-only-negative" `
        -ScenarioPid $scenarioPid `
        -UnexpectedReasons @("gentlemen_collection_staging_path", "gentlemen_edr_killer_process_name", "edr_killer_version_info_impersonation_evidence", "edr_killer_packer_section_evidence")

    foreach ($scenarioName in @("edr-killer-exact-name-deletor", "edr-killer-exact-name-hwaudkiller"))
    {
        ++$scenarioPid
        Add-SyntheticEsetProcessScenario `
            -Scenarios $scenarios `
            -Findings $findings `
            -Name $scenarioName `
            -ScenarioPid $scenarioPid `
            -Reasons @("gentlemen_edr_killer_process_name", "gentlemen_collection_staging_path", "edr_killer_version_info_impersonation_evidence", "edr_killer_packer_section_evidence") `
            -Class "edr_killer_process_profile" `
            -Risk "high" `
            -Confidence "high" `
            -Evidence @{
                image_version_info_present = "true"
                image_packer_section_hint = "enigma"
                gentlemen_collection_path = "true"
            }
    }

    ++$scenarioPid
    $oxidePid = $scenarioPid
    Add-SyntheticEsetProcessScenario `
        -Scenarios $scenarios `
        -Findings $findings `
        -Name "oxideharvest-cli" `
        -ScenarioPid $scenarioPid `
        -Reasons @("gentlemen_related_credential_tool_name", "oxideharvest_cli_shape") `
        -Class "gentlemen_related_tool" `
        -Risk "medium" `
        -Confidence "high" `
        -Evidence @{
            oxideharvest_cli_options = "-i;-u;-p;-t;-o"
        }

    ++$scenarioPid
    Add-SyntheticEsetNegativeScenario `
        -Scenarios $scenarios `
        -Name "oxideharvest-name-only-negative" `
        -ScenarioPid $scenarioPid `
        -UnexpectedReasons @("gentlemen_related_credential_tool_name", "oxideharvest_cli_shape")

    $fixtures = @(Get-SyntheticEsetDriverServiceFixtures)
    for ($index = 0; $index -lt $fixtures.Count; ++$index)
    {
        Add-SyntheticEsetDriverServiceScenario `
            -Scenarios $scenarios `
            -Findings $findings `
            -Fixture $fixtures[$index] `
            -Index $index
    }

    [void]$Findings.Add([ordered]@{
        risk = "medium"
        confidence = "medium"
        class = "edr_killer_security_product_impairment_telemetry"
        title = "Threat-Intelligence events show repeated control of known security-product processes"
        pid = 6101
        address = "0x0000000000000000"
        artifact = "synthetic renamed caller"
        reasons = @(
            "ti_process_impairment_event",
            "defense_impairment_telemetry",
            "known_security_product_process_target",
            "gentlekiller_security_target_list"
        )
        evidence = [ordered]@{
            caller_pid = "6101"
            caller_image = "renamed-tool.exe"
            caller_image_path = "C:\Temp\renamed-tool.exe"
            matched_image_leaf = "renamed-tool.exe"
            gentlemen_collection_path = "false"
            ti_event_count = "2"
            security_product_target_count = "2"
            security_product_targets = "msmpeng.exe;ekrn.exe"
            target_pid_count = "2"
            target_pids = "6201;6202"
        }
    })

    $highCount = @($findings | Where-Object { $_.risk -eq "high" }).Count
    $mediumCount = @($findings | Where-Object { $_.risk -eq "medium" }).Count
    $lowCount = @($findings | Where-Object { $_.risk -eq "low" }).Count
    $driverMediumCount = @($findings | Where-Object {
        $_.class -eq "edr_killer_driver_service" -and $_.risk -eq "medium"
    }).Count
    $driverLowCount = @($findings | Where-Object {
        $_.class -eq "edr_killer_driver_service" -and $_.risk -eq "low"
    }).Count
    $manifestDoc = [ordered]@{
        schema = "kn-live-dbg.hunt-target-manifest.v1"
        pid = 4321
        scenario_count = $scenarios.Count
        scenarios = $scenarios
    }
    $huntDoc = [ordered]@{
        schema = "kn-live-dbg.hunt.v1"
        summary = [ordered]@{
            findings = $findings.Count
            high = $highCount
            medium = $mediumCount
            low = $lowCount
            edr_killer_driver_services = $fixtures.Count
            threat_intel_correlations = 1
        }
        findings = $findings
    }

    $manifestDoc | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $Manifest -Encoding UTF8
    $huntDoc | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $HuntJson -Encoding UTF8
    $assessments = @(
        (New-SyntheticHuntAssessment `
            -Severity "high" `
            -Count ($suffixScenarios.Count + 2) `
            -Subject "synthetic.exe(5001),synthetic.exe(5002)" `
            -What "process identity or metadata masquerades as a known defense-evasion tool" `
            -Why "known defense-evasion tool name; renamed or suffixed defense-evasion tool name; known tool staging path; manipulated version information; packed or protected PE section" `
            -Next "review image path, signature, version info, and staging path in /json"),
        (New-SyntheticHuntAssessment `
            -Severity "medium" `
            -Count $fixtures.Count `
            -Subject "system" `
            -What "SCM or loaded-driver state exposes a known defense-evasion driver artifact" `
            -Why "known defense-evasion driver service; known driver-service binary name; known tool staging path" `
            -Next "review the SCM service, loaded-driver path, and binary hash in /json"),
        (New-SyntheticHuntAssessment `
            -Severity "medium" `
            -Count 1 `
            -Subject "synthetic.exe($oxidePid)" `
            -What "process identity or command line matches credential-collection tooling" `
            -Why "credential-collection command-line shape; known credential-tool name" `
            -Next "review command line, image path, and file identity in /json"),
        (New-SyntheticHuntAssessment `
            -Severity "medium" `
            -Count 1 `
            -Subject "renamed-tool.exe(6101)" `
            -What "process repeatedly controlled known security-product processes" `
            -Why "security-product process targeting; known security-product target list" `
            -Next "review recent !ti events and the target process list in /json")
    )
    Set-Content `
        -LiteralPath $Stdout `
        -Encoding UTF8 `
        -Value (New-SyntheticHuntConsoleStdout `
            -HuntJson $HuntJson `
            -Findings $findings.Count `
            -High $highCount `
            -Medium $mediumCount `
            -Low $lowCount `
            -DriverServiceIocs $fixtures.Count `
            -ThreatIntelCorrelations 1 `
            -Assessments $assessments)
}

$rootPath = (Resolve-Path -LiteralPath $Root).Path
$releaseTarget = Join-Path $rootPath "x64\Release\tools\KnLiveDbgHuntTarget.exe"
$buildDir = Join-Path $rootPath ".build"

if (-not (Test-Path -LiteralPath $buildDir))
{
    New-Item -ItemType Directory -Path $buildDir | Out-Null
}

Invoke-Step -Name "ESET IOC source coverage" -Script {
    & (Join-Path $rootPath "tools\validate-eset-hunt-iocs.ps1") -Root $rootPath
    if ($LASTEXITCODE -ne 0)
    {
        throw "ESET IOC source coverage failed with exit code $LASTEXITCODE"
    }
}

Invoke-Step -Name "synthetic ESET driver-service validator" -Script {
    $serviceManifest = Join-Path $rootPath ".build\hunt-readiness-service-synthetic-manifest.json"
    $serviceJson = Join-Path $rootPath ".build\hunt-readiness-service-synthetic.json"
    $serviceStdout = Join-Path $rootPath ".build\hunt-readiness-service-synthetic-stdout.log"
    New-SyntheticEsetDriverServiceValidationFiles -Manifest $serviceManifest -HuntJson $serviceJson -Stdout $serviceStdout
    Invoke-HuntTargetValidatorSummary `
        -Name "synthetic ESET driver-service validator" `
        -Manifest $serviceManifest `
        -HuntJson $serviceJson `
        -Log (Join-Path $rootPath ".build\hunt-readiness-service-validator.log")

    Invoke-HuntTargetValidatorExpectedFailure `
        -Name "synthetic ESET driver-service class mutation" `
        -Manifest $serviceManifest `
        -SourceHuntJson $serviceJson `
        -MutatedHuntJson (Join-Path $rootPath ".build\hunt-readiness-service-synthetic-mutated-class.json") `
        -Log (Join-Path $rootPath ".build\hunt-readiness-service-mutated-class-validator.log") `
        -Property "class" `
        -BadValue "mapped_code"

    Invoke-HuntTargetValidatorExpectedFailure `
        -Name "synthetic ESET driver-service risk mutation" `
        -Manifest $serviceManifest `
        -SourceHuntJson $serviceJson `
        -MutatedHuntJson (Join-Path $rootPath ".build\hunt-readiness-service-synthetic-mutated-risk.json") `
        -Log (Join-Path $rootPath ".build\hunt-readiness-service-mutated-risk-validator.log") `
        -Property "risk" `
        -BadValue "high"

    Invoke-HuntTargetValidatorExpectedFailure `
        -Name "synthetic ESET driver-service confidence mutation" `
        -Manifest $serviceManifest `
        -SourceHuntJson $serviceJson `
        -MutatedHuntJson (Join-Path $rootPath ".build\hunt-readiness-service-synthetic-mutated-confidence.json") `
        -Log (Join-Path $rootPath ".build\hunt-readiness-service-mutated-confidence-validator.log") `
        -Property "confidence" `
        -BadValue "low"

    & (Join-Path $rootPath "tools\validate-eset-hunt-e2e-artifacts.ps1") `
        -Root $rootPath `
        -Manifest ".build\hunt-readiness-service-synthetic-manifest.json" `
        -HuntJson ".build\hunt-readiness-service-synthetic.json" `
        -Stdout ".build\hunt-readiness-service-synthetic-stdout.log" `
        -ValidatorLog ".build\hunt-readiness-service-artifact-validator.log" `
        -ExpectedScenarioCount 15 `
        -ExpectedEdrKillerDriverServices 15 `
        -RequiredAssessmentNeedle "known defense-evasion driver service" `
        -RequiredReasons @("gentlemen_edr_killer_driver_service", "driver_service_binary_name_ioc", "driver_service_not_running") `
        -AllowNoHighRisk
    if ($LASTEXITCODE -ne 0)
    {
        throw "synthetic ESET driver-service artifact validator failed with exit code $LASTEXITCODE"
    }

    $defaultRoot = Join-Path $rootPath ".build\hunt-readiness-default-root"
    $defaultRootFull = [System.IO.Path]::GetFullPath($defaultRoot)
    $buildRootFull = [System.IO.Path]::GetFullPath((Join-Path $rootPath ".build\"))
    if (-not $defaultRootFull.StartsWith($buildRootFull, [System.StringComparison]::OrdinalIgnoreCase))
    {
        throw "refusing to clean default artifact smoke root outside .build: $defaultRootFull"
    }
    $defaultRoot = $defaultRootFull
    $defaultToolsDir = Join-Path $defaultRoot "tools"
    $defaultE2eDir = Join-Path $defaultRoot ".build\eset-hunt-e2e"
    if (Test-Path -LiteralPath $defaultRoot)
    {
        Remove-Item -LiteralPath $defaultRoot -Recurse -Force
    }
    New-Item -ItemType Directory -Path $defaultToolsDir | Out-Null
    if (-not (Test-Path -LiteralPath $defaultE2eDir))
    {
        New-Item -ItemType Directory -Path $defaultE2eDir | Out-Null
    }
    Copy-Item `
        -LiteralPath (Join-Path $rootPath "tools\validate-hunt-target.ps1") `
        -Destination (Join-Path $defaultToolsDir "validate-hunt-target.ps1") `
        -Force

    New-SyntheticEsetDriverServiceValidationFiles `
        -Manifest (Join-Path $defaultE2eDir "hunt-target-manifest.json") `
        -HuntJson (Join-Path $defaultE2eDir "hunt.json") `
        -Stdout (Join-Path $defaultE2eDir "knlivedbg.stdout.log")

    & (Join-Path $rootPath "tools\validate-eset-hunt-e2e-artifacts.ps1") `
        -Root $defaultRoot `
        -ExpectedScenarioCount 15 `
        -ExpectedEdrKillerDriverServices 15 `
        -RequiredAssessmentNeedle "known defense-evasion driver service" `
        -RequiredReasons @("gentlemen_edr_killer_driver_service", "driver_service_binary_name_ioc", "driver_service_not_running") `
        -AllowNoHighRisk
    if ($LASTEXITCODE -ne 0)
    {
        throw "synthetic ESET driver-service default-path artifact validator failed with exit code $LASTEXITCODE"
    }

    $runningManifest = Join-Path $rootPath ".build\hunt-readiness-service-running-synthetic-manifest.json"
    $runningJson = Join-Path $rootPath ".build\hunt-readiness-service-running-synthetic.json"
    $runningStdout = Join-Path $rootPath ".build\hunt-readiness-service-running-synthetic-stdout.log"
    New-SyntheticEsetRunningDriverServiceValidationFiles `
        -Manifest $runningManifest `
        -HuntJson $runningJson `
        -Stdout $runningStdout

    & (Join-Path $rootPath "tools\validate-eset-hunt-e2e-artifacts.ps1") `
        -Root $rootPath `
        -Manifest ".build\hunt-readiness-service-running-synthetic-manifest.json" `
        -HuntJson ".build\hunt-readiness-service-running-synthetic.json" `
        -Stdout ".build\hunt-readiness-service-running-synthetic-stdout.log" `
        -ValidatorLog ".build\hunt-readiness-service-running-synthetic-validator.log" `
        -ExpectedScenarioCount 1 `
        -ExpectedEdrKillerDriverServices 1 `
        -RequiredAssessmentNeedle "known defense-evasion driver service" `
        -RequiredReasons @("gentlemen_edr_killer_driver_service", "driver_service_binary_name_ioc", "driver_service_running")
    if ($LASTEXITCODE -ne 0)
    {
        throw "synthetic ESET running driver-service artifact validator failed with exit code $LASTEXITCODE"
    }
    Write-Host "[hunt-readiness] synthetic running driver-service validator=yes"

    $hashManifest = Join-Path $rootPath ".build\hunt-readiness-exact-hash-synthetic-manifest.json"
    $hashJson = Join-Path $rootPath ".build\hunt-readiness-exact-hash-synthetic.json"
    $hashStdout = Join-Path $rootPath ".build\hunt-readiness-exact-hash-synthetic-stdout.log"
    New-SyntheticEsetExactHashValidationFiles `
        -Manifest $hashManifest `
        -HuntJson $hashJson `
        -Stdout $hashStdout

    & (Join-Path $rootPath "tools\validate-eset-hunt-e2e-artifacts.ps1") `
        -Root $rootPath `
        -Manifest ".build\hunt-readiness-exact-hash-synthetic-manifest.json" `
        -HuntJson ".build\hunt-readiness-exact-hash-synthetic.json" `
        -Stdout ".build\hunt-readiness-exact-hash-synthetic-stdout.log" `
        -ValidatorLog ".build\hunt-readiness-exact-hash-synthetic-validator.log" `
        -ExpectedScenarioCount 4 `
        -ExpectedEdrKillerDriverServices 1 `
        -RequiredAssessmentNeedle "published file hash IOC" `
        -RequiredReasons @("eset_exact_file_sha1_ioc", "edr_killer_exact_file_sha1_ioc", "oxideharvest_exact_file_sha1_ioc", "loaded_driver_file_hash_ioc", "driver_service_file_hash_ioc")
    if ($LASTEXITCODE -ne 0)
    {
        throw "synthetic ESET exact-hash artifact validator failed with exit code $LASTEXITCODE"
    }
    Write-Host "[hunt-readiness] synthetic exact-hash validator=yes"

    $metadataManifest = Join-Path $rootPath ".build\hunt-readiness-metadata-evasion-synthetic-manifest.json"
    $metadataJson = Join-Path $rootPath ".build\hunt-readiness-metadata-evasion-synthetic.json"
    $metadataStdout = Join-Path $rootPath ".build\hunt-readiness-metadata-evasion-synthetic-stdout.log"
    New-SyntheticEsetMetadataEvasionValidationFiles `
        -Manifest $metadataManifest `
        -HuntJson $metadataJson `
        -Stdout $metadataStdout

    & (Join-Path $rootPath "tools\validate-eset-hunt-e2e-artifacts.ps1") `
        -Root $rootPath `
        -Manifest ".build\hunt-readiness-metadata-evasion-synthetic-manifest.json" `
        -HuntJson ".build\hunt-readiness-metadata-evasion-synthetic.json" `
        -Stdout ".build\hunt-readiness-metadata-evasion-synthetic-stdout.log" `
        -ValidatorLog ".build\hunt-readiness-metadata-evasion-synthetic-validator.log" `
        -ExpectedScenarioCount 1 `
        -ExpectedEdrKillerDriverServices 0 `
        -RequiredAssessmentNeedle "packed or protected PE section" `
        -RequiredReasons @("edr_killer_invalid_code_signature", "edr_killer_version_info_impersonation_evidence", "edr_killer_icon_impersonation_evidence", "edr_killer_packer_section_evidence")
    if ($LASTEXITCODE -ne 0)
    {
        throw "synthetic ESET metadata-evasion artifact validator failed with exit code $LASTEXITCODE"
    }
    Write-Host "[hunt-readiness] synthetic metadata-evasion validator=yes"

    $telemetryManifest = Join-Path $rootPath ".build\hunt-readiness-security-product-telemetry-synthetic-manifest.json"
    $telemetryJson = Join-Path $rootPath ".build\hunt-readiness-security-product-telemetry-synthetic.json"
    $telemetryStdout = Join-Path $rootPath ".build\hunt-readiness-security-product-telemetry-synthetic-stdout.log"
    New-SyntheticEsetSecurityProductTelemetryValidationFiles `
        -Manifest $telemetryManifest `
        -HuntJson $telemetryJson `
        -Stdout $telemetryStdout

    & (Join-Path $rootPath "tools\validate-eset-hunt-e2e-artifacts.ps1") `
        -Root $rootPath `
        -Manifest ".build\hunt-readiness-security-product-telemetry-synthetic-manifest.json" `
        -HuntJson ".build\hunt-readiness-security-product-telemetry-synthetic.json" `
        -Stdout ".build\hunt-readiness-security-product-telemetry-synthetic-stdout.log" `
        -ValidatorLog ".build\hunt-readiness-security-product-telemetry-synthetic-validator.log" `
        -ExpectedScenarioCount 1 `
        -ExpectedEdrKillerDriverServices 0 `
        -RequiredAssessmentNeedle "security-product process targeting" `
        -RequiredReasons @("known_security_product_process_target", "gentlekiller_security_target_list", "defense_impairment_telemetry") `
        -AllowNoHighRisk
    if ($LASTEXITCODE -ne 0)
    {
        throw "synthetic ESET security-product telemetry artifact validator failed with exit code $LASTEXITCODE"
    }
    Write-Host "[hunt-readiness] synthetic security-product telemetry validator=yes"
}

Invoke-Step -Name "synthetic ESET full artifact validator" -Script {
    $fullManifest = Join-Path $rootPath ".build\hunt-readiness-full-synthetic-manifest.json"
    $fullJson = Join-Path $rootPath ".build\hunt-readiness-full-synthetic.json"
    $fullStdout = Join-Path $rootPath ".build\hunt-readiness-full-synthetic-stdout.log"
    $fullRunnerLog = Join-Path $rootPath ".build\hunt-readiness-full-synthetic-runner.log"
    New-SyntheticEsetFullValidationFiles `
        -Manifest $fullManifest `
        -HuntJson $fullJson `
        -Stdout $fullStdout

    Set-Content -LiteralPath $fullRunnerLog -Encoding UTF8 -Value @(
        "[eset-hunt-e2e] runner_contract=e2e-auto-knlivedbg-article-currentness-v2",
        "[eset-hunt-e2e] root=$rootPath configuration=Release reuse_existing_target=False elevated=True powershell=5.1",
        "[eset-hunt-e2e] expected_scenarios=35",
        "[eset-hunt-e2e] target ready scenarios=35",
        "[eset-hunt-e2e] run KnLiveDbg scripted hunt",
        "[eset-hunt-e2e] validate ESET hunt artifacts",
        "[eset-hunt-e2e] passed",
        "[eset-hunt-e2e] manifest=$fullManifest",
        "[eset-hunt-e2e] hunt_json=$fullJson"
    )

    & (Join-Path $rootPath "tools\validate-eset-hunt-e2e-artifacts.ps1") `
        -Root $rootPath `
        -Manifest ".build\hunt-readiness-full-synthetic-manifest.json" `
        -HuntJson ".build\hunt-readiness-full-synthetic.json" `
        -Stdout ".build\hunt-readiness-full-synthetic-stdout.log" `
        -RunnerLog ".build\hunt-readiness-full-synthetic-runner.log" `
        -RequireRunnerPassed `
        -ValidatorLog ".build\hunt-readiness-full-synthetic-validator.log"
    if ($LASTEXITCODE -ne 0)
    {
        throw "synthetic ESET full artifact validator failed with exit code $LASTEXITCODE"
    }
    & (Join-Path $rootPath "tools\validate-eset-hunt-e2e-artifacts.ps1") `
        -Root $rootPath `
        -Manifest ".\.build\hunt-readiness-full-synthetic-manifest.json" `
        -HuntJson ".\.build\hunt-readiness-full-synthetic.json" `
        -Stdout ".\.build\hunt-readiness-full-synthetic-stdout.log" `
        -RunnerLog ".\.build\hunt-readiness-full-synthetic-runner.log" `
        -RequireRunnerPassed `
        -ValidatorLog ".\.build\hunt-readiness-full-synthetic-dot-relative-validator.log"
    if ($LASTEXITCODE -ne 0)
    {
        throw "synthetic ESET full dot-relative artifact validator failed with exit code $LASTEXITCODE"
    }
    Write-Host "[hunt-readiness] synthetic ESET full dot-relative artifact validator=yes"

    & (Join-Path $rootPath "tools\validate-eset-hunt-e2e-artifacts.ps1") `
        -Root $rootPath `
        -Manifest ".build\hunt-readiness-full-synthetic-manifest.json" `
        -HuntJson ".build\hunt-readiness-full-synthetic.json" `
        -Stdout ".build\hunt-readiness-full-synthetic-stdout.log" `
        -ValidatorLog ".build\hunt-readiness-full-synthetic-security-target-validator.log" `
        -RequiredAssessmentNeedle "security-product process targeting" `
        -RequiredReasons @("known_security_product_process_target", "gentlekiller_security_target_list", "defense_impairment_telemetry")
    if ($LASTEXITCODE -ne 0)
    {
        throw "synthetic ESET full security-product telemetry validator failed with exit code $LASTEXITCODE"
    }

    $mutatedDuplicateManifest = Join-Path $rootPath ".build\hunt-readiness-full-synthetic-mutated-duplicate-scenario.json"
    $duplicateDoc = Get-Content -LiteralPath $fullManifest -Raw | ConvertFrom-Json
    $duplicateDoc.scenarios[$duplicateDoc.scenarios.Count - 1].name = [string]$duplicateDoc.scenarios[0].name
    $duplicateDoc | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $mutatedDuplicateManifest -Encoding UTF8
    Invoke-EsetArtifactValidatorExpectedFailure `
        -Name "synthetic ESET full duplicate scenario mutation" `
        -Manifest ".build\hunt-readiness-full-synthetic-mutated-duplicate-scenario.json" `
        -HuntJson ".build\hunt-readiness-full-synthetic.json" `
        -Stdout ".build\hunt-readiness-full-synthetic-stdout.log" `
        -ValidatorLog ".build\hunt-readiness-full-synthetic-mutated-duplicate-scenario-validator.log" `
        -OuterLog (Join-Path $rootPath ".build\hunt-readiness-full-synthetic-mutated-duplicate-scenario.log")
    Write-Host "[hunt-readiness] artifact mutation rejected duplicate_scenario=yes"

    $mutatedCountManifest = Join-Path $rootPath ".build\hunt-readiness-full-synthetic-mutated-scenario-count.json"
    $countDoc = Get-Content -LiteralPath $fullManifest -Raw | ConvertFrom-Json
    $countDoc.scenario_count = [int]$countDoc.scenario_count + 1
    $countDoc | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $mutatedCountManifest -Encoding UTF8
    Invoke-EsetArtifactValidatorExpectedFailure `
        -Name "synthetic ESET full scenario_count mutation" `
        -Manifest ".build\hunt-readiness-full-synthetic-mutated-scenario-count.json" `
        -HuntJson ".build\hunt-readiness-full-synthetic.json" `
        -Stdout ".build\hunt-readiness-full-synthetic-stdout.log" `
        -ValidatorLog ".build\hunt-readiness-full-synthetic-mutated-scenario-count-validator.log" `
        -OuterLog (Join-Path $rootPath ".build\hunt-readiness-full-synthetic-mutated-scenario-count.log")
    Write-Host "[hunt-readiness] artifact mutation rejected scenario_count=yes"

    $mutatedSummaryJson = Join-Path $rootPath ".build\hunt-readiness-full-synthetic-mutated-summary-high.json"
    $summaryDoc = Get-Content -LiteralPath $fullJson -Raw | ConvertFrom-Json
    $summaryDoc.summary.high = [int]$summaryDoc.summary.high + 1
    $summaryDoc | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $mutatedSummaryJson -Encoding UTF8
    Invoke-EsetArtifactValidatorExpectedFailure `
        -Name "synthetic ESET full summary high mutation" `
        -Manifest ".build\hunt-readiness-full-synthetic-manifest.json" `
        -HuntJson ".build\hunt-readiness-full-synthetic-mutated-summary-high.json" `
        -Stdout ".build\hunt-readiness-full-synthetic-stdout.log" `
        -ValidatorLog ".build\hunt-readiness-full-synthetic-mutated-summary-high-validator.log" `
        -OuterLog (Join-Path $rootPath ".build\hunt-readiness-full-synthetic-mutated-summary-high.log")
    Write-Host "[hunt-readiness] artifact mutation rejected summary_high=yes"

    $mutatedDriverServiceCountJson = Join-Path $rootPath ".build\hunt-readiness-full-synthetic-mutated-driver-service-count.json"
    $driverServiceCountDoc = Get-Content -LiteralPath $fullJson -Raw | ConvertFrom-Json
    $driverServiceCountDoc.summary.edr_killer_driver_services = [int]$driverServiceCountDoc.summary.edr_killer_driver_services + 1
    $driverServiceCountDoc | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $mutatedDriverServiceCountJson -Encoding UTF8
    Invoke-EsetArtifactValidatorExpectedFailure `
        -Name "synthetic ESET full driver-service count mutation" `
        -Manifest ".build\hunt-readiness-full-synthetic-manifest.json" `
        -HuntJson ".build\hunt-readiness-full-synthetic-mutated-driver-service-count.json" `
        -Stdout ".build\hunt-readiness-full-synthetic-stdout.log" `
        -ValidatorLog ".build\hunt-readiness-full-synthetic-mutated-driver-service-count-validator.log" `
        -OuterLog (Join-Path $rootPath ".build\hunt-readiness-full-synthetic-mutated-driver-service-count.log")
    Write-Host "[hunt-readiness] artifact mutation rejected driver_service_count=yes"

    $mutatedClassContractManifest = Join-Path $rootPath ".build\hunt-readiness-full-synthetic-mutated-class-contract-count.json"
    $classContractDoc = Get-Content -LiteralPath $fullManifest -Raw | ConvertFrom-Json
    $negativeScenario = @($classContractDoc.scenarios | Where-Object { [string]$_.name -eq "oxideharvest-name-only-negative" })[0]
    $negativeScenario | Add-Member -NotePropertyName "expected_class" -NotePropertyValue "edr_killer_process_profile" -Force
    $negativeScenario | Add-Member -NotePropertyName "expected_risk" -NotePropertyValue "high" -Force
    $negativeScenario | Add-Member -NotePropertyName "expected_confidence" -NotePropertyValue "high" -Force
    $classContractDoc | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $mutatedClassContractManifest -Encoding UTF8
    Invoke-EsetArtifactValidatorExpectedFailure `
        -Name "synthetic ESET full class-contract count mutation" `
        -Manifest ".build\hunt-readiness-full-synthetic-mutated-class-contract-count.json" `
        -HuntJson ".build\hunt-readiness-full-synthetic.json" `
        -Stdout ".build\hunt-readiness-full-synthetic-stdout.log" `
        -ValidatorLog ".build\hunt-readiness-full-synthetic-mutated-class-contract-count-validator.log" `
        -OuterLog (Join-Path $rootPath ".build\hunt-readiness-full-synthetic-mutated-class-contract-count.log")
    Write-Host "[hunt-readiness] artifact mutation rejected class_contract_count=yes"

    $mutatedUnexpectedReasonJson = Join-Path $rootPath ".build\hunt-readiness-full-synthetic-mutated-unexpected-negative-reason.json"
    $unexpectedReasonDoc = Get-Content -LiteralPath $fullJson -Raw | ConvertFrom-Json
    $unexpectedReasonManifest = Get-Content -LiteralPath $fullManifest -Raw | ConvertFrom-Json
    $stagingOnlyScenario = @($unexpectedReasonManifest.scenarios | Where-Object { [string]$_.name -eq "edr-killer-gentlemen-staging-only-negative" })[0]
    $telemetryFinding = @($unexpectedReasonDoc.findings | Where-Object { @($_.reasons) -contains "known_security_product_process_target" })[0]
    $telemetryFinding.pid = [int]$stagingOnlyScenario.pid
    $telemetryFinding.reasons = @($telemetryFinding.reasons) + "gentlemen_collection_staging_path"
    $unexpectedReasonDoc | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $mutatedUnexpectedReasonJson -Encoding UTF8
    $unexpectedReasonLog = Join-Path $rootPath ".build\hunt-readiness-full-synthetic-mutated-unexpected-negative-reason-validator.log"
    & (Join-Path $rootPath "tools\validate-hunt-target.ps1") `
        -Manifest $fullManifest `
        -HuntJson $mutatedUnexpectedReasonJson *> $unexpectedReasonLog
    if ($LASTEXITCODE -eq 0)
    {
        throw "synthetic ESET full unexpected negative reason mutation unexpectedly passed; log=$unexpectedReasonLog"
    }
    $unexpectedReasonLogText = Get-Content -LiteralPath $unexpectedReasonLog -Raw
    if ($unexpectedReasonLogText.IndexOf("unexpected reason 'gentlemen_collection_staging_path'", [System.StringComparison]::OrdinalIgnoreCase) -lt 0)
    {
        throw "synthetic ESET full unexpected negative reason mutation failed without the expected reason text; log=$unexpectedReasonLog"
    }
    Write-Host "[hunt-readiness] artifact mutation rejected unexpected_negative_reason=yes"

    $mutatedAssessmentStdout = Join-Path $rootPath ".build\hunt-readiness-full-synthetic-mutated-assessment-driver-service.log"
    Get-Content -LiteralPath $fullStdout |
        Where-Object { $_ -notmatch "known defense-evasion driver service" } |
        Set-Content -LiteralPath $mutatedAssessmentStdout -Encoding UTF8
    Invoke-EsetArtifactValidatorExpectedFailure `
        -Name "synthetic ESET full assessment driver-service mutation" `
        -Manifest ".build\hunt-readiness-full-synthetic-manifest.json" `
        -HuntJson ".build\hunt-readiness-full-synthetic.json" `
        -Stdout ".build\hunt-readiness-full-synthetic-mutated-assessment-driver-service.log" `
        -ValidatorLog ".build\hunt-readiness-full-synthetic-mutated-assessment-driver-service-validator.log" `
        -OuterLog (Join-Path $rootPath ".build\hunt-readiness-full-synthetic-mutated-assessment-driver-service-validator-output.log")
    Write-Host "[hunt-readiness] artifact mutation rejected assessment_driver_service=yes"

    $mutatedRunnerLog = Join-Path $rootPath ".build\hunt-readiness-full-synthetic-mutated-runner-elevation.log"
    Get-Content -LiteralPath $fullRunnerLog |
        Where-Object { $_ -notmatch "elevated=True" } |
        Set-Content -LiteralPath $mutatedRunnerLog -Encoding UTF8
    Invoke-EsetArtifactValidatorExpectedFailure `
        -Name "synthetic ESET full runner elevation mutation" `
        -Manifest ".build\hunt-readiness-full-synthetic-manifest.json" `
        -HuntJson ".build\hunt-readiness-full-synthetic.json" `
        -Stdout ".build\hunt-readiness-full-synthetic-stdout.log" `
        -RunnerLog ".build\hunt-readiness-full-synthetic-mutated-runner-elevation.log" `
        -ValidatorLog ".build\hunt-readiness-full-synthetic-mutated-runner-elevation-validator.log" `
        -OuterLog (Join-Path $rootPath ".build\hunt-readiness-full-synthetic-mutated-runner-elevation-validator-output.log")
    Write-Host "[hunt-readiness] artifact mutation rejected runner_log_elevated=yes"

    $mutatedRunnerManifestLog = Join-Path $rootPath ".build\hunt-readiness-full-synthetic-mutated-runner-manifest.log"
    (Get-Content -LiteralPath $fullRunnerLog -Raw).Replace($fullManifest, "$fullManifest.mismatch") |
        Set-Content -LiteralPath $mutatedRunnerManifestLog -Encoding UTF8
    Invoke-EsetArtifactValidatorExpectedFailure `
        -Name "synthetic ESET full runner manifest path mutation" `
        -Manifest ".build\hunt-readiness-full-synthetic-manifest.json" `
        -HuntJson ".build\hunt-readiness-full-synthetic.json" `
        -Stdout ".build\hunt-readiness-full-synthetic-stdout.log" `
        -RunnerLog ".build\hunt-readiness-full-synthetic-mutated-runner-manifest.log" `
        -RequireRunnerPassed `
        -ValidatorLog ".build\hunt-readiness-full-synthetic-mutated-runner-manifest-validator.log" `
        -OuterLog (Join-Path $rootPath ".build\hunt-readiness-full-synthetic-mutated-runner-manifest-validator-output.log")
    Write-Host "[hunt-readiness] artifact mutation rejected runner_log_manifest=yes"

    $missingRunnerOuterLog = Join-Path $rootPath ".build\hunt-readiness-full-synthetic-missing-runner-log-validator-output.log"
    $missingRunnerValidatorLog = Join-Path $rootPath ".build\hunt-readiness-full-synthetic-missing-runner-log-validator.log"
    $missingRunnerExit = 0
    try
    {
        & (Join-Path $rootPath "tools\validate-eset-hunt-e2e-artifacts.ps1") `
            -Root $rootPath `
            -Manifest ".build\hunt-readiness-full-synthetic-manifest.json" `
            -HuntJson ".build\hunt-readiness-full-synthetic.json" `
            -Stdout ".build\hunt-readiness-full-synthetic-stdout.log" `
            -RequireRunnerPassed `
            -ValidatorLog ".build\hunt-readiness-full-synthetic-missing-runner-log-validator.log" *> $missingRunnerOuterLog
        $missingRunnerExit = $LASTEXITCODE
    }
    catch
    {
        $missingRunnerExit = 1
        $_ | Out-String | Add-Content -LiteralPath $missingRunnerOuterLog -Encoding UTF8
    }
    if ($missingRunnerExit -eq 0)
    {
        throw "synthetic ESET full missing runner log mutation unexpectedly passed; log=$missingRunnerValidatorLog"
    }
    Write-Host "[hunt-readiness] artifact mutation rejected runner_log_required=yes"

    $mutatedRunnerPassLog = Join-Path $rootPath ".build\hunt-readiness-full-synthetic-mutated-runner-pass.log"
    Get-Content -LiteralPath $fullRunnerLog |
        Where-Object { $_ -notmatch "\[eset-hunt-e2e\] passed" } |
        Set-Content -LiteralPath $mutatedRunnerPassLog -Encoding UTF8
    $runnerPassOuterLog = Join-Path $rootPath ".build\hunt-readiness-full-synthetic-mutated-runner-pass-validator-output.log"
    $runnerPassValidatorLog = Join-Path $rootPath ".build\hunt-readiness-full-synthetic-mutated-runner-pass-validator.log"
    $runnerPassExit = 0
    try
    {
        & (Join-Path $rootPath "tools\validate-eset-hunt-e2e-artifacts.ps1") `
            -Root $rootPath `
            -Manifest ".build\hunt-readiness-full-synthetic-manifest.json" `
            -HuntJson ".build\hunt-readiness-full-synthetic.json" `
            -Stdout ".build\hunt-readiness-full-synthetic-stdout.log" `
            -RunnerLog ".build\hunt-readiness-full-synthetic-mutated-runner-pass.log" `
            -RequireRunnerPassed `
            -ValidatorLog ".build\hunt-readiness-full-synthetic-mutated-runner-pass-validator.log" *> $runnerPassOuterLog
        $runnerPassExit = $LASTEXITCODE
    }
    catch
    {
        $runnerPassExit = 1
        $_ | Out-String | Add-Content -LiteralPath $runnerPassOuterLog -Encoding UTF8
    }
    if ($runnerPassExit -eq 0)
    {
        throw "synthetic ESET full runner pass mutation unexpectedly passed; log=$runnerPassValidatorLog"
    }
    Write-Host "[hunt-readiness] artifact mutation rejected runner_log_passed=yes"
}

Invoke-Step -Name "git diff whitespace" -Script {
    $gitDir = Join-Path $rootPath ".git"
    if (Test-Path -LiteralPath $gitDir)
    {
        Push-Location $rootPath
        try
        {
            git diff --check
        }
        finally
        {
            Pop-Location
        }
    }
    else
    {
        Write-Host "[hunt-readiness] git diff whitespace skipped: no .git directory in root"
    }
}

if ($SkipSmoke)
{
    Write-Host "[hunt-readiness] skip smoke targets by request"
}
else
{
    if (-not (Test-Path -LiteralPath $releaseTarget))
    {
        throw "release hunt target not found: $releaseTarget"
    }

    Invoke-Step -Name "interactive menu baseline smoke" -Script {
        $manifest = Join-Path $rootPath ".build\hunt-readiness-menu-baseline-manifest.json"
        $log = Join-Path $rootPath ".build\hunt-readiness-menu-baseline.log"
        Remove-Item -LiteralPath $manifest, $log -Force -ErrorAction SilentlyContinue
        $cmdLine = "echo 1| `"$releaseTarget`" /seconds 1 /manifest `"$manifest`""
        & $env:ComSpec /d /c $cmdLine *> $log

        if ($LASTEXITCODE -ne 0)
        {
            Get-Content -LiteralPath $log | Select-Object -Last 80 | Out-Host
            throw "interactive menu baseline smoke failed with exit code $LASTEXITCODE"
        }
        if (-not (Test-Path -LiteralPath $manifest))
        {
            throw "interactive menu baseline manifest missing: $manifest"
        }

        $stdout = Get-Content -LiteralPath $log -Raw
        if ($stdout.IndexOf("Available hunt target experiments:", [System.StringComparison]::OrdinalIgnoreCase) -lt 0)
        {
            throw "interactive menu smoke did not print experiment menu"
        }
        if ($stdout.IndexOf("/baseline - baseline negative control", [System.StringComparison]::OrdinalIgnoreCase) -lt 0)
        {
            throw "interactive menu smoke did not select baseline"
        }

        $doc = Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
        $count = @($doc.scenarios).Count
        if ($count -ne 0)
        {
            throw "expected 0 scenarios for interactive baseline, got $count"
        }

        Write-Host "[hunt-readiness] interactive menu baseline scenarios=$count"
    }

    Invoke-Step -Name "stop-event target cleanup smoke" -Script {
        Invoke-StopEventTargetSmoke -TargetExe $releaseTarget
    }

    Invoke-Step -Name "EDR/Oxide target manifest smoke" -Script {
        $manifest = Join-Path $rootPath ".build\hunt-readiness-edr-oxide-manifest.json"
        $log = Join-Path $rootPath ".build\hunt-readiness-edr-oxide.log"
        & $releaseTarget /edr-killer-suffix-name /oxideharvest-cli /seconds 1 /manifest $manifest *> $log
        if ($LASTEXITCODE -ne 0)
        {
            Get-Content -LiteralPath $log | Select-Object -Last 80 | Out-Host
            throw "EDR/Oxide target smoke failed with exit code $LASTEXITCODE"
        }
        if (-not (Test-Path -LiteralPath $manifest))
        {
            throw "EDR/Oxide target manifest missing: $manifest"
        }

        $doc = Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
        $count = @($doc.scenarios).Count
        if ($count -ne 20)
        {
            throw "expected 20 EDR/Oxide scenarios, got $count"
        }

        Assert-ManifestScenarioNames `
            -ManifestDoc $doc `
            -ExpectedNames @(Get-EsetProcessScenarioNames) `
            -Name "EDR/Oxide target"
        Assert-ManifestScenarioUnexpectedReason `
            -ManifestDoc $doc `
            -ScenarioName "edr-killer-weak-vendor-standalone-negative" `
            -Reason "gentlemen_edr_killer_process_name"
        Assert-ManifestScenarioUnexpectedReason `
            -ManifestDoc $doc `
            -ScenarioName "edr-killer-gentlemen-staging-only-negative" `
            -Reason "gentlemen_collection_staging_path"
        Assert-ManifestScenarioUnexpectedReason `
            -ManifestDoc $doc `
            -ScenarioName "oxideharvest-name-only-negative" `
            -Reason "gentlemen_related_credential_tool_name"

        Write-Host "[hunt-readiness] EDR/Oxide scenarios=$count"
    }

    Invoke-Step -Name "driver-service target availability smoke" -Script {
        $manifest = Join-Path $rootPath ".build\hunt-readiness-service-manifest.json"
        $log = Join-Path $rootPath ".build\hunt-readiness-service.log"
        & $releaseTarget /edr-killer-driver-service /seconds 1 /manifest $manifest *> $log
        if ($LASTEXITCODE -ne 0)
        {
            Get-Content -LiteralPath $log | Select-Object -Last 80 | Out-Host
            throw "driver-service target smoke failed with exit code $LASTEXITCODE"
        }
        if (-not (Test-Path -LiteralPath $manifest))
        {
            throw "driver-service target manifest missing: $manifest"
        }

        $doc = Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
        $count = @($doc.scenarios).Count
        if (Test-IsAdministrator)
        {
            if ($count -ne 15)
            {
                throw "expected 15 driver-service scenarios while elevated, got $count"
            }

            Assert-ManifestScenarioNames `
                -ManifestDoc $doc `
                -ExpectedNames @(Get-EsetDriverServiceScenarioNames) `
                -Name "driver-service target"

            Write-Host "[hunt-readiness] driver-service scenarios=$count"
        }
        else
        {
            if ($count -ne 0)
            {
                throw "expected 0 driver-service scenarios while non-admin, got $count"
            }

            Write-Host "[hunt-readiness] driver-service scenarios=0 non_admin_skip=yes"
        }
    }
}

Write-Host "[hunt-readiness] passed"
exit 0
