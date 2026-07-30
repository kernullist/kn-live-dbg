[CmdletBinding()]
param(
    [string]$Root = "",

    [ValidateSet("Release")]
    [string]$Configuration = "Release",

    [string]$Volume = $env:SystemDrive,

    [string]$OutputDirectory = "",

    [ValidateRange(3, 10)]
    [int]$CleanRunCount = 3,

    [ValidateRange(60, 3600)]
    [int]$TimeoutSeconds = 1200,

    [switch]$NoElevation,

    [string]$ElevationStatusPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($Root))
{
    $Root =
        Split-Path -Parent $PSScriptRoot
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

function Test-IsAdministrator
{
    $identity =
        [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal =
        [Security.Principal.WindowsPrincipal]::new(
            $identity)
    return $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertTo-ProcessArgument
{
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value
    )

    if ($Value -notmatch '[\s"]')
    {
        return $Value
    }
    return '"' +
        ($Value -replace '(\\*)"', '$1$1\"' -replace
            '(\\+)$', '$1$1') +
        '"'
}

function Write-StatusFile
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string[]]$Lines
    )

    if ([string]::IsNullOrWhiteSpace($Path))
    {
        return
    }
    $parent =
        Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace(
            $parent))
    {
        New-Item `
            -ItemType Directory `
            -Path $parent `
            -Force |
            Out-Null
    }
    $Lines |
        Set-Content `
            -LiteralPath $Path `
            -Encoding UTF8
}

function Invoke-RequiredPowerShellScript
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$ScriptPath,

        [string[]]$Arguments = @(),

        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )

    Write-Host (
        "[evasion-external-gate] start $Name log=$LogPath")
    $nativeArguments =
        @(
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            $ScriptPath
        ) +
        $Arguments
    $savedErrorPreference =
        $ErrorActionPreference
    try
    {
        $ErrorActionPreference = "Continue"
        & powershell.exe @nativeArguments 2>&1 |
            Tee-Object `
                -FilePath $LogPath |
            ForEach-Object {
                Write-Host $_.ToString()
            }
        $exitCode =
            [int]$LASTEXITCODE
    }
    finally
    {
        $ErrorActionPreference =
            $savedErrorPreference
    }
    if ($exitCode -ne 0)
    {
        $tail =
            @(
                Get-Content `
                    -LiteralPath $LogPath `
                    -Tail 20 `
                    -ErrorAction SilentlyContinue
            ) -join " | "
        throw (
            "{0} failed with exit={1}: {2}" -f
                $Name,
                $exitCode,
                $tail)
    }
    Write-Host (
        "[evasion-external-gate] pass $Name")
}

function Resolve-BuildOrPackageArtifact
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepositoryRoot,

        [Parameter(Mandatory = $true)]
        [string]$BuildConfiguration,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $candidates = @(
        (Join-Path $RepositoryRoot (
            "x64\$BuildConfiguration\$Name")),
        (Join-Path $RepositoryRoot $Name)
    )
    foreach ($candidate in $candidates)
    {
        if (Test-Path `
                -LiteralPath $candidate `
                -PathType Leaf)
        {
            return [IO.Path]::GetFullPath(
                $candidate)
        }
    }
    return $candidates[0]
}

function Assert-ChildPath
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Parent,

        [Parameter(Mandatory = $true)]
        [string]$Child
    )

    $parentPath =
        [IO.Path]::GetFullPath(
            $Parent).TrimEnd("\")
    $childPath =
        [IO.Path]::GetFullPath(
            $Child)
    if (-not $childPath.StartsWith(
            $parentPath + "\",
            [StringComparison]::OrdinalIgnoreCase))
    {
        throw "path is outside the expected parent: $childPath"
    }
}

function Assert-DedicatedOutputDirectory
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$RepositoryRoot
    )

    $fullPath =
        [IO.Path]::GetFullPath(
            $Path).TrimEnd("\")
    $volumeRoot =
        [IO.Path]::GetPathRoot(
            $fullPath).TrimEnd("\")
    $repositoryPath =
        [IO.Path]::GetFullPath(
            $RepositoryRoot).TrimEnd("\")
    if ($fullPath.Equals(
            $volumeRoot,
            [StringComparison]::OrdinalIgnoreCase) -or
        $fullPath.Equals(
            $repositoryPath,
            [StringComparison]::OrdinalIgnoreCase))
    {
        throw "output directory must be a dedicated child directory: $fullPath"
    }

    if (Test-Path -LiteralPath $fullPath)
    {
        $item =
            Get-Item `
                -LiteralPath $fullPath `
                -Force
        if (-not $item.PSIsContainer -or
            (($item.Attributes -band
              [IO.FileAttributes]::ReparsePoint) -ne 0))
        {
            throw "output directory is not a plain directory: $fullPath"
        }
    }
}

function Read-PassedManifest
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Schema,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    if (-not (Test-Path `
            -LiteralPath $Path `
            -PathType Leaf))
    {
        throw "$Context manifest is missing: $Path"
    }
    try
    {
        $document =
            Get-Content -LiteralPath $Path -Raw |
                ConvertFrom-Json
    }
    catch
    {
        throw "$Context manifest is invalid JSON: $Path"
    }
    foreach ($contract in @(
            [pscustomobject]@{
                Name = "schema"
                Value = $Schema
            },
            [pscustomobject]@{
                Name = "status"
                Value = "passed"
            },
            [pscustomobject]@{
                Name = "cleanup"
                Value = "passed"
            }))
    {
        $property =
            $document.PSObject.Properties[
                $contract.Name]
        if ($null -eq $property -or
            $property.Value -isnot [string] -or
            $property.Value -cne
                $contract.Value)
        {
            throw (
                "$Context manifest contract mismatch: " +
                "$($contract.Name)")
        }
    }
    return $document
}

function Assert-NoRuntimeResidue
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$QosPolicyName
    )

    foreach ($processName in @(
            "KnLiveDbg",
            "KnLiveDbgBindFixture",
            "CloudFilesFixture"))
    {
        $processes =
            @(
                Get-Process `
                    -Name $processName `
                    -ErrorAction SilentlyContinue
            )
        if ($processes.Count -ne 0)
        {
            throw (
                "fixture process residue: name={0} pids={1}" -f
                    $processName,
                    (@($processes.Id) -join ","))
        }
    }
    foreach ($serviceName in @(
            "KnLiveDbg",
            "KnLiveDbgMiniFilterFixture"))
    {
        $service =
            Get-Service `
                -Name $serviceName `
                -ErrorAction SilentlyContinue
        if ($null -ne $service)
        {
            throw (
                "fixture service residue: name={0} state={1}" -f
                    $serviceName,
                    $service.Status)
        }
    }

    $remainingPolicies =
        @(
            Get-NetQosPolicy `
                -PolicyStore ActiveStore `
                -ErrorAction Stop |
                Where-Object {
                    [string]::Equals(
                        [string]$_.Name,
                        $QosPolicyName,
                        [System.StringComparison]::OrdinalIgnoreCase)
                }
        )
    if ($remainingPolicies.Count -ne 0)
    {
        throw (
            "QoS fixture policy residue: $QosPolicyName")
    }
}

$rootPath =
    (Resolve-Path -LiteralPath $Root).Path
if ($Volume -notmatch '^[A-Za-z]:$')
{
    throw "Volume must be a local drive root such as C:"
}
$Volume =
    $Volume.Substring(0, 1).ToUpperInvariant() +
    ":"
if ([string]::IsNullOrWhiteSpace(
        $OutputDirectory))
{
    $outputPath =
        Join-Path $rootPath (
            ".build\evasion-external-gate-{0}-{1}" -f
                [DateTime]::UtcNow.ToString(
                    "yyyyMMddTHHmmssZ"),
                [Guid]::NewGuid().ToString("N"))
}
elseif ([IO.Path]::IsPathRooted(
        $OutputDirectory))
{
    $outputPath =
        [IO.Path]::GetFullPath(
            $OutputDirectory)
}
else
{
    $outputPath =
        [IO.Path]::GetFullPath(
            (Join-Path $rootPath $OutputDirectory))
}
Assert-DedicatedOutputDirectory `
    -Path $outputPath `
    -RepositoryRoot $rootPath
if (Test-Path -LiteralPath $outputPath)
{
    $existing =
        @(
            Get-ChildItem `
                -LiteralPath $outputPath `
                -Force
        )
    if ($existing.Count -ne 0)
    {
        throw (
            "external gate output directory must be empty: $outputPath")
    }
}
else
{
    New-Item `
        -ItemType Directory `
        -Path $outputPath |
        Out-Null
}

if ([string]::IsNullOrWhiteSpace(
        $ElevationStatusPath))
{
    $statusPath =
        Join-Path $outputPath "status.txt"
}
elseif ([IO.Path]::IsPathRooted(
        $ElevationStatusPath))
{
    $statusPath =
        [IO.Path]::GetFullPath(
            $ElevationStatusPath)
}
else
{
    $statusPath =
        [IO.Path]::GetFullPath(
            (Join-Path $rootPath $ElevationStatusPath))
}
Assert-ChildPath `
    -Parent $outputPath `
    -Child $statusPath
$manifestPath =
    Join-Path $outputPath "manifest.json"

if (-not (Test-IsAdministrator))
{
    if ($NoElevation)
    {
        Write-StatusFile `
            -Path $statusPath `
            -Lines @(
                "status=failed",
                "message=administrator rights are required",
                "output=$outputPath"
            )
        Write-Error "administrator rights are required"
        exit 1
    }

    $arguments = @(
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        (ConvertTo-ProcessArgument $PSCommandPath),
        "-Root",
        (ConvertTo-ProcessArgument $rootPath),
        "-Configuration",
        $Configuration,
        "-Volume",
        (ConvertTo-ProcessArgument $Volume),
        "-OutputDirectory",
        (ConvertTo-ProcessArgument $outputPath),
        "-CleanRunCount",
        [string]$CleanRunCount,
        "-TimeoutSeconds",
        [string]$TimeoutSeconds,
        "-NoElevation",
        "-ElevationStatusPath",
        (ConvertTo-ProcessArgument $statusPath)
    )
    Write-Host (
        "[evasion-external-gate] requesting UAC elevation")
    try
    {
        $child =
            Start-Process `
                -FilePath "powershell.exe" `
                -ArgumentList (
                    $arguments -join " ") `
                -Verb RunAs `
                -Wait `
                -PassThru
        $childExitCode =
            [int]$child.ExitCode
    }
    catch
    {
        Write-StatusFile `
            -Path $statusPath `
            -Lines @(
                "status=failed",
                "message=elevation failed: $($_.Exception.Message)",
                "output=$outputPath"
            )
        throw
    }
    if (Test-Path -LiteralPath $statusPath)
    {
        Get-Content -LiteralPath $statusPath |
            ForEach-Object {
                Write-Host (
                    "[evasion-external-gate] $_")
            }
    }
    exit $childExitCode
}

$executable =
    Resolve-BuildOrPackageArtifact `
        -RepositoryRoot $rootPath `
        -BuildConfiguration $Configuration `
        -Name "KnLiveDbg.exe"
$toolRoot =
    Join-Path $rootPath "tools"
$qosRunner =
    Join-Path $toolRoot "run-qos-bind-e2e.ps1"
$cloudRunner =
    Join-Path $toolRoot (
        "run-cloudfiles-placeholder-fixture.ps1")
$minifilterRunner =
    Join-Path $toolRoot (
        "run-minifilter-detach-e2e.ps1")
$cleanRunner =
    Join-Path $toolRoot "run-hunt-clean-host.ps1"
$analyzer =
    Join-Path $toolRoot "analyze-hunt-clean-host.ps1"
$validator =
    Join-Path $toolRoot (
        "validate-evasion-external-gate.ps1")
foreach ($requiredPath in @(
        $executable,
        $qosRunner,
        $cloudRunner,
        $minifilterRunner,
        $cleanRunner,
        $analyzer,
        $validator))
{
    if (-not (Test-Path `
            -LiteralPath $requiredPath `
            -PathType Leaf))
    {
        throw (
            "external gate dependency is missing: $requiredPath")
    }
}

$qosOutput =
    Join-Path $outputPath "qos-bind"
$cloudNegativeOutput =
    Join-Path $outputPath "cloudfiles-in-sync"
$cloudPositiveOutput =
    Join-Path $outputPath "cloudfiles-modified"
$minifilterOutput =
    Join-Path $outputPath "minifilter"
$cleanOutput =
    Join-Path $outputPath "clean-host"
$cleanStatusPath =
    Join-Path $cleanOutput "status.txt"
$analysisPath =
    Join-Path $cleanOutput "analysis.json"
$analysisMarkdownPath =
    Join-Path $cleanOutput "analysis.md"
$analysisLogPath =
    Join-Path $cleanOutput "analysis.log"
$validatorLogPath =
    Join-Path $outputPath "validator.log"
$runnerLockPath =
    Join-Path $outputPath ".runner.lock"

$runnerLock = $null
$mutex = $null
$mutexOwned = $false
$runSucceeded = $false
$failureMessage = ""
$manifestDocument = $null
$cleanupFailures =
    [Collections.Generic.List[string]]::new()

try
{
    $runnerLock =
        [IO.File]::Open(
            $runnerLockPath,
            [IO.FileMode]::OpenOrCreate,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None)
    $mutex =
        [Threading.Mutex]::new(
            $false,
            "Global\KnLiveDbgEvasionExternalGate")
    try
    {
        $mutexOwned =
            $mutex.WaitOne(0)
    }
    catch [Threading.AbandonedMutexException]
    {
        $mutexOwned = $true
    }
    if (-not $mutexOwned)
    {
        throw (
            "another evasion external gate is active")
    }

    Invoke-RequiredPowerShellScript `
        -Name "QoS/Bind live positive" `
        -ScriptPath $qosRunner `
        -Arguments @(
            "-Root",
            $rootPath,
            "-Configuration",
            $Configuration,
            "-OutputDirectory",
            $qosOutput,
            "-TimeoutSeconds",
            [string]$TimeoutSeconds,
            "-NoElevation"
        ) `
        -LogPath (
            Join-Path $outputPath "qos-bind.log")

    Invoke-RequiredPowerShellScript `
        -Name "CloudFiles in-sync negative" `
        -ScriptPath $cloudRunner `
        -Arguments @(
            "-Scenario",
            "InSyncNegative",
            "-HoldSeconds",
            "1",
            "-ValidateHunt",
            "-HuntOutputDirectory",
            $cloudNegativeOutput,
            "-HuntMode",
            "Deep",
            "-HuntTimeoutSeconds",
            [string]$TimeoutSeconds
        ) `
        -LogPath (
            Join-Path $outputPath (
                "cloudfiles-in-sync.log"))

    Invoke-RequiredPowerShellScript `
        -Name "CloudFiles modified-data positive" `
        -ScriptPath $cloudRunner `
        -Arguments @(
            "-Scenario",
            "ModifiedPositive",
            "-HoldSeconds",
            "1",
            "-ValidateHunt",
            "-HuntOutputDirectory",
            $cloudPositiveOutput,
            "-HuntMode",
            "Deep",
            "-HuntTimeoutSeconds",
            [string]$TimeoutSeconds
        ) `
        -LogPath (
            Join-Path $outputPath (
                "cloudfiles-modified.log"))

    Invoke-RequiredPowerShellScript `
        -Name "minifilter detach/reattach positive" `
        -ScriptPath $minifilterRunner `
        -Arguments @(
            "-Root",
            $rootPath,
            "-Configuration",
            $Configuration,
            "-Volume",
            $Volume,
            "-OutputDirectory",
            $minifilterOutput,
            "-TimeoutSeconds",
            [string]$TimeoutSeconds,
            "-NoElevation"
        ) `
        -LogPath (
            Join-Path $outputPath "minifilter.log")

    New-Item `
        -ItemType Directory `
        -Path $cleanOutput `
        -Force |
        Out-Null
    Invoke-RequiredPowerShellScript `
        -Name (
            "repeated elevated clean-host Deep hunt") `
        -ScriptPath $cleanRunner `
        -Arguments @(
            "-Root",
            $rootPath,
            "-Executable",
            $executable,
            "-OutputDirectory",
            $cleanOutput,
            "-Mode",
            "Deep",
            "-Count",
            [string]$CleanRunCount,
            "-TimeoutSeconds",
            [string]$TimeoutSeconds,
            "-EnableThreatIntel",
            "-RequireClean",
            "-NoElevation",
            "-ElevationStatusPath",
            $cleanStatusPath
        ) `
        -LogPath (
            Join-Path $outputPath "clean-host.log")

    $huntJsonPaths =
        @(
            for ($run = 1;
                $run -le $CleanRunCount;
                ++$run)
            {
                $path =
                    Join-Path $cleanOutput (
                        "hunt-clean-deep-{0:D2}.json" -f
                            $run)
                if (-not (Test-Path `
                        -LiteralPath $path `
                        -PathType Leaf))
                {
                    throw (
                        "clean-host run artifact is missing: $path")
                }
                $path
            }
        )
    $analysisOutput =
        @(
            & $analyzer `
                -HuntJson $huntJsonPaths `
                -OutputJson $analysisPath `
                -OutputMarkdown $analysisMarkdownPath `
                -RequireThreatIntelActive 2>&1 |
                ForEach-Object {
                    $_.ToString()
                }
        )
    $analysisOutput |
        Set-Content `
            -LiteralPath $analysisLogPath `
            -Encoding UTF8
    if (-not (Test-Path `
            -LiteralPath $analysisPath `
            -PathType Leaf))
    {
        throw (
            "clean-host analyzer did not create: $analysisPath")
    }

    $qosManifestPath =
        Join-Path $qosOutput "manifest.json"
    $cloudNegativeManifestPath =
        Join-Path $cloudNegativeOutput (
            "cloudfiles-fixture-manifest.json")
    $cloudPositiveManifestPath =
        Join-Path $cloudPositiveOutput (
            "cloudfiles-fixture-manifest.json")
    $minifilterManifestPath =
        Join-Path $minifilterOutput "manifest.json"

    $qosManifest =
        Read-PassedManifest `
            -Path $qosManifestPath `
            -Schema "kn-live-dbg.qos-bind-e2e.v1" `
            -Context "QoS/Bind"
    [void](
        Read-PassedManifest `
            -Path $cloudNegativeManifestPath `
            -Schema (
                "kn-live-dbg.cloudfiles-fixture-e2e.v1") `
            -Context "CloudFiles in-sync")
    [void](
        Read-PassedManifest `
            -Path $cloudPositiveManifestPath `
            -Schema (
                "kn-live-dbg.cloudfiles-fixture-e2e.v1") `
            -Context "CloudFiles modified-data")
    [void](
        Read-PassedManifest `
            -Path $minifilterManifestPath `
            -Schema (
                "kn-live-dbg.minifilter-detach-e2e.v1") `
            -Context "minifilter")

    $policyNameProperty =
        $qosManifest.PSObject.Properties[
            "policy_name"]
    if ($null -eq $policyNameProperty -or
        $policyNameProperty.Value -isnot [string] -or
        [string]::IsNullOrWhiteSpace(
            $policyNameProperty.Value))
    {
        throw (
            "QoS/Bind manifest policy_name is invalid")
    }
    Assert-NoRuntimeResidue `
        -QosPolicyName (
            [string]$policyNameProperty.Value)

    $artifactPaths =
        [ordered]@{
            qos_bind_manifest =
                [IO.Path]::GetFullPath(
                    $qosManifestPath)
            cloudfiles_in_sync_manifest =
                [IO.Path]::GetFullPath(
                    $cloudNegativeManifestPath)
            cloudfiles_modified_manifest =
                [IO.Path]::GetFullPath(
                    $cloudPositiveManifestPath)
            minifilter_manifest =
                [IO.Path]::GetFullPath(
                    $minifilterManifestPath)
            clean_host_analysis =
                [IO.Path]::GetFullPath(
                    $analysisPath)
        }
    $artifactHashes =
        [ordered]@{}
    foreach ($entry in $artifactPaths.GetEnumerator())
    {
        $artifactHashes[$entry.Key] =
            Get-FileSha256 `
                -Path $entry.Value
    }

    $manifestDocument =
        [ordered]@{
            schema =
                "kn-live-dbg.evasion-external-gate.v1"
            status = "passed"
            timestamp_utc =
                [DateTime]::UtcNow.ToString("o")
            elevated = $true
            configuration = $Configuration
            volume = $Volume
            clean_run_count = $CleanRunCount
            threat_intel_required = $true
            silo_binding_coverage_unsupported =
                $true
            artifacts = $artifactPaths
            artifact_sha256 = $artifactHashes
            cleanup = "passed"
        }
    $runSucceeded = $true
}
catch
{
    $failureMessage =
        $_.Exception.Message
}
finally
{
    if ($mutexOwned -and
        $null -ne $mutex)
    {
        try
        {
            $mutex.ReleaseMutex()
            $mutexOwned = $false
        }
        catch
        {
            $cleanupFailures.Add(
                "external gate mutex release failed: $($_.Exception.Message)")
        }
    }
    if ($null -ne $mutex)
    {
        try
        {
            $mutex.Dispose()
        }
        catch
        {
            $cleanupFailures.Add(
                "external gate mutex handle cleanup failed: $($_.Exception.Message)")
        }
    }
    if ($null -ne $runnerLock)
    {
        try
        {
            $runnerLock.Dispose()
            $runnerLock = $null
        }
        catch
        {
            $cleanupFailures.Add(
                "external gate runner lock cleanup failed: $($_.Exception.Message)")
        }
    }
    if ($null -eq $runnerLock -and
        (Test-Path -LiteralPath $runnerLockPath))
    {
        try
        {
            Remove-Item `
                -LiteralPath $runnerLockPath `
                -Force
        }
        catch
        {
            $cleanupFailures.Add(
                "external gate runner lock file cleanup failed: $($_.Exception.Message)")
        }
    }
}

if ($cleanupFailures.Count -ne 0)
{
    $cleanupText =
        $cleanupFailures -join "; "
    if ([string]::IsNullOrWhiteSpace(
            $failureMessage))
    {
        $failureMessage =
            "external gate cleanup failed: $cleanupText"
    }
    else
    {
        $failureMessage +=
            "; external gate cleanup failed: $cleanupText"
    }
    $runSucceeded = $false
}

if (-not $runSucceeded)
{
    Remove-Item `
        -LiteralPath $manifestPath `
        -Force `
        -ErrorAction SilentlyContinue
    Write-StatusFile `
        -Path $statusPath `
        -Lines @(
            "status=failed",
            "message=$failureMessage",
            "output=$outputPath"
        )
    Write-Error $failureMessage
    exit 1
}

try
{
    $manifestDocument |
        ConvertTo-Json -Depth 6 |
        Set-Content `
            -LiteralPath $manifestPath `
            -Encoding UTF8
    Invoke-RequiredPowerShellScript `
        -Name "aggregate artifact validation" `
        -ScriptPath $validator `
        -Arguments @(
            "-ManifestPath",
            $manifestPath
        ) `
        -LogPath $validatorLogPath
}
catch
{
    $failureMessage =
        "aggregate validation failed: $($_.Exception.Message)"
    Remove-Item `
        -LiteralPath $manifestPath `
        -Force `
        -ErrorAction SilentlyContinue
    Write-StatusFile `
        -Path $statusPath `
        -Lines @(
            "status=failed",
            "message=$failureMessage",
            "output=$outputPath"
        )
    Write-Error $failureMessage
    exit 1
}

Write-StatusFile `
    -Path $statusPath `
    -Lines @(
        "status=passed",
        "manifest=$manifestPath",
        "output=$outputPath",
        "cleanup=passed"
    )
Write-Host (
    "[evasion-external-gate] passed manifest=$manifestPath")
