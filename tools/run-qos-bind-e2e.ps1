[CmdletBinding()]
param(
    [string]$Root = "",

    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",

    [string]$OutputDirectory = "",

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

function Invoke-NativeCapture
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [string[]]$Arguments = @()
    )

    $savedErrorPreference =
        $ErrorActionPreference
    try
    {
        $ErrorActionPreference = "Continue"
        $output =
            @(
                & $FilePath @Arguments 2>&1 |
                    ForEach-Object {
                        $_.ToString()
                    }
            )
        $exitCode =
            $LASTEXITCODE
    }
    finally
    {
        $ErrorActionPreference =
            $savedErrorPreference
    }

    return [pscustomobject]@{
        ExitCode = [int]$exitCode
        Output = $output
        Text = (
            $output -join
                [Environment]::NewLine)
    }
}

function Invoke-RequiredNative
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [string[]]$Arguments = @(),

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    $result =
        Invoke-NativeCapture `
            -FilePath $FilePath `
            -Arguments $Arguments
    if ($result.ExitCode -ne 0)
    {
        throw (
            "{0} failed with exit={1}: {2}" -f
                $Context,
                $result.ExitCode,
                $result.Text)
    }
    return $result
}

function Assert-MainDebuggerIdle
{
    $processes =
        @(
            Get-Process `
                -Name "KnLiveDbg" `
                -ErrorAction SilentlyContinue
        )
    if ($processes.Count -ne 0)
    {
        throw (
            "refusing to run while KnLiveDbg.exe is active: pids={0}" -f
                (@($processes.Id) -join ","))
    }
    $service =
        Get-Service `
            -Name "KnLiveDbg" `
            -ErrorAction SilentlyContinue
    if ($null -ne $service)
    {
        throw (
            "refusing to run while the KnLiveDbg service exists: state={0}" -f
                $service.Status)
    }
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

    $candidates =
        @(
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
            return [System.IO.Path]::GetFullPath(
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
        [System.IO.Path]::GetFullPath(
            $Parent).TrimEnd("\")
    $childPath =
        [System.IO.Path]::GetFullPath(
            $Child)
    if (-not $childPath.StartsWith(
            $parentPath + "\",
            [System.StringComparison]::OrdinalIgnoreCase))
    {
        throw "path is outside the expected parent: $childPath"
    }
}

function Assert-PlainDirectoryTreeForRemoval
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Parent,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    Assert-ChildPath `
        -Parent $Parent `
        -Child $Path
    $parentPath =
        [System.IO.Path]::GetFullPath(
            $Parent).TrimEnd("\")
    $targetPath =
        [System.IO.Path]::GetFullPath(
            $Path).TrimEnd("\")
    $parentItem =
        Get-Item `
            -LiteralPath $parentPath `
            -Force `
            -ErrorAction Stop
    if (-not $parentItem.PSIsContainer -or
        (($parentItem.Attributes -band
          [System.IO.FileAttributes]::ReparsePoint) -ne 0))
    {
        throw "$Context parent is not a plain directory: $parentPath"
    }

    $relative =
        $targetPath.Substring(
            $parentPath.Length + 1)
    $current = $parentPath
    foreach ($segment in
        $relative.Split(
            [char]"\",
            [System.StringSplitOptions]::RemoveEmptyEntries))
    {
        $current =
            Join-Path $current $segment
        $item =
            Get-Item `
                -LiteralPath $current `
                -Force `
                -ErrorAction Stop
        if (-not $item.PSIsContainer -or
            (($item.Attributes -band
              [System.IO.FileAttributes]::ReparsePoint) -ne 0))
        {
            throw "$Context traverses a non-directory or reparse point: $current"
        }
    }

    $pending =
        [System.Collections.Generic.Stack[
            System.IO.DirectoryInfo]]::new()
    $pending.Push(
        [System.IO.DirectoryInfo](
            Get-Item `
                -LiteralPath $targetPath `
                -Force `
                -ErrorAction Stop))
    while ($pending.Count -ne 0)
    {
        $directory = $pending.Pop()
        foreach ($child in
            $directory.EnumerateFileSystemInfos())
        {
            if (($child.Attributes -band
                    [System.IO.FileAttributes]::Directory) -eq 0)
            {
                continue
            }
            if (($child.Attributes -band
                    [System.IO.FileAttributes]::ReparsePoint) -ne 0)
            {
                throw (
                    "$Context contains a directory reparse point: " +
                    $child.FullName)
            }
            $pending.Push(
                [System.IO.DirectoryInfo]$child)
        }
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
        [System.IO.Path]::GetFullPath(
            $Path).TrimEnd("\")
    $volumeRoot =
        [System.IO.Path]::GetPathRoot(
            $fullPath).TrimEnd("\")
    $repositoryPath =
        [System.IO.Path]::GetFullPath(
            $RepositoryRoot).TrimEnd("\")
    if ($fullPath.Equals(
            $volumeRoot,
            [System.StringComparison]::OrdinalIgnoreCase) -or
        $fullPath.Equals(
            $repositoryPath,
            [System.StringComparison]::OrdinalIgnoreCase))
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
              [System.IO.FileAttributes]::ReparsePoint) -ne 0))
        {
            throw "output directory is not a plain directory: $fullPath"
        }
    }
}

$rootPath =
    (Resolve-Path -LiteralPath $Root).Path
if ([string]::IsNullOrWhiteSpace(
        $OutputDirectory))
{
    $outputPath =
        Join-Path $rootPath (
            ".build\qos-bind-e2e")
}
elseif ([System.IO.Path]::IsPathRooted(
        $OutputDirectory))
{
    $outputPath =
        [System.IO.Path]::GetFullPath(
            $OutputDirectory)
}
else
{
    $outputPath =
        [System.IO.Path]::GetFullPath(
            (Join-Path $rootPath $OutputDirectory))
}
Assert-DedicatedOutputDirectory `
    -Path $outputPath `
    -RepositoryRoot $rootPath
New-Item `
    -ItemType Directory `
    -Path $outputPath `
    -Force |
    Out-Null

if ([string]::IsNullOrWhiteSpace(
        $ElevationStatusPath))
{
    $statusPath =
        Join-Path $outputPath "status.txt"
}
elseif ([System.IO.Path]::IsPathRooted(
        $ElevationStatusPath))
{
    $statusPath =
        [System.IO.Path]::GetFullPath(
            $ElevationStatusPath)
}
else
{
    $statusPath =
        [System.IO.Path]::GetFullPath(
            (Join-Path $rootPath $ElevationStatusPath))
}
Assert-ChildPath `
    -Parent $outputPath `
    -Child $statusPath

$manifestPath =
    Join-Path $outputPath "manifest.json"
Remove-Item `
    -LiteralPath @(
        $statusPath,
        $manifestPath
    ) `
    -Force `
    -ErrorAction SilentlyContinue

if (-not (Test-IsAdministrator))
{
    if ($NoElevation)
    {
        Write-StatusFile `
            -Path $statusPath `
            -Lines @(
                "status=failed",
                "message=administrator rights are required"
            )
        throw "administrator rights are required"
    }

    $arguments =
        @(
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            (ConvertTo-ProcessArgument $PSCommandPath),
            "-Root",
            (ConvertTo-ProcessArgument $rootPath),
            "-Configuration",
            $Configuration,
            "-OutputDirectory",
            (ConvertTo-ProcessArgument $outputPath),
            "-TimeoutSeconds",
            [string]$TimeoutSeconds,
            "-NoElevation",
            "-ElevationStatusPath",
            (ConvertTo-ProcessArgument $statusPath)
        )
    Write-Host (
        "[qos-bind-e2e] requesting UAC elevation")
    try
    {
        $child =
            Start-Process `
                -FilePath "powershell.exe" `
                -ArgumentList (
                    $arguments -join " ") `
                -Verb RunAs `
                -WindowStyle Hidden `
                -Wait `
                -PassThru
    }
    catch
    {
        Write-StatusFile `
            -Path $statusPath `
            -Lines @(
                "status=failed",
                "message=UAC elevation failed: $($_.Exception.Message)"
            )
        throw
    }
    if (Test-Path -LiteralPath $statusPath)
    {
        Get-Content -LiteralPath $statusPath |
            ForEach-Object {
                Write-Host (
                    "[qos-bind-e2e] $_")
            }
    }
    exit ([int]$child.ExitCode)
}

$executable =
    Resolve-BuildOrPackageArtifact `
        -RepositoryRoot $rootPath `
        -BuildConfiguration $Configuration `
        -Name "KnLiveDbg.exe"
$controller =
    Resolve-BuildOrPackageArtifact `
        -RepositoryRoot $rootPath `
        -BuildConfiguration $Configuration `
        -Name "KnLiveDbgBindFixture.exe"
$huntRunner =
    Join-Path $rootPath (
        "tools\run-hunt-clean-host.ps1")
$validator =
    Join-Path $rootPath (
        "tools\validate-qos-bind-e2e.ps1")
foreach ($required in @(
        $executable,
        $controller,
        $huntRunner,
        $validator))
{
    if (-not (Test-Path `
            -LiteralPath $required `
            -PathType Leaf))
    {
        throw "required fixture artifact is missing: $required"
    }
}

$fixtureId =
    [Guid]::NewGuid().ToString("N")
$temporaryRoot =
    [System.IO.Path]::GetFullPath(
        [System.IO.Path]::GetTempPath()).
            TrimEnd("\")
$fixtureRoot =
    Join-Path $temporaryRoot (
        "KnLiveDbgBindFixture-$fixtureId")
Assert-ChildPath `
    -Parent $temporaryRoot `
    -Child $fixtureRoot

$policyName =
    "KnLiveDbg-Qos-Fixture-$fixtureId"
$fileVirtual =
    Join-Path $fixtureRoot "amsi.dll"
$fileBacking =
    Join-Path $fixtureRoot "backing.dll"
$processVirtual =
    Join-Path $fixtureRoot "MsSense.exe"
$processBacking =
    Join-Path $fixtureRoot (
        "ProcessBindingBacking.exe")
$qosTarget =
    $processVirtual
$huntOutput =
    Join-Path $outputPath "hunt"
Assert-ChildPath `
    -Parent $outputPath `
    -Child $huntOutput
$huntJson =
    Join-Path $huntOutput (
        "hunt-clean-default-01.json")
$validatorLog =
    Join-Path $outputPath "validator.log"
$controllerApplyLog =
    Join-Path $outputPath (
        "controller-apply.log")
$controllerRemoveLog =
    Join-Path $outputPath (
        "controller-remove.log")
$lockPath =
    Join-Path $outputPath ".runner.lock"

$runnerLock = $null
$mutex = $null
$mutexOwned = $false
$fixtureCreated = $false
$mappingAttempted = $false
$mappingRemovalConfirmed = $false
$policyAttempted = $false
$boundProcess = $null
$originalProcessVirtualHash = ""
$processBackingHash = ""
$runSucceeded = $false
$failureMessage = ""
$manifestDocument = $null
$cleanupFailures =
    [System.Collections.Generic.List[string]]::new()

try
{
    $windowsDirectory =
        [Environment]::GetFolderPath(
            [Environment+SpecialFolder]::Windows)
    if ([string]::IsNullOrWhiteSpace(
            $windowsDirectory))
    {
        throw "Windows directory could not be resolved"
    }

    $runnerLock =
        [System.IO.File]::Open(
            $lockPath,
            [System.IO.FileMode]::OpenOrCreate,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::None)
    $mutex =
        [System.Threading.Mutex]::new(
            $false,
            "Global\KnLiveDbgQosBindFixtureE2E")
    try
    {
        $mutexOwned =
            $mutex.WaitOne(0)
    }
    catch [System.Threading.AbandonedMutexException]
    {
        $mutexOwned =
            $true
    }
    if (-not $mutexOwned)
    {
        throw "another QoS/Bind fixture runner is active"
    }

    Assert-MainDebuggerIdle

    Remove-Item `
        -LiteralPath @(
            $validatorLog,
            $controllerApplyLog,
            $controllerRemoveLog
        ) `
        -Force `
        -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $huntOutput)
    {
        Assert-PlainDirectoryTreeForRemoval `
            -Parent $outputPath `
            -Path $huntOutput `
            -Context "prior QoS/Bind hunt output"
        Remove-Item `
            -LiteralPath $huntOutput `
            -Recurse `
            -Force
    }

    New-Item `
        -ItemType Directory `
        -Path $fixtureRoot |
        Out-Null
    $fixtureCreated = $true
    "kn-live-dbg-bind-virtual-$fixtureId" |
        Set-Content `
            -LiteralPath $fileVirtual `
            -Encoding Ascii
    "kn-live-dbg-bind-backing-$fixtureId" |
        Set-Content `
            -LiteralPath $fileBacking `
            -Encoding Ascii
    Copy-Item `
        -LiteralPath (
            Join-Path $windowsDirectory (
                "System32\where.exe")) `
        -Destination $processVirtual
    Copy-Item `
        -LiteralPath (
            Join-Path $windowsDirectory (
                "System32\ping.exe")) `
        -Destination $processBacking

    $originalProcessVirtualHash =
        Get-FileSha256 `
            -Path $processVirtual
    $processBackingHash =
        Get-FileSha256 `
            -Path $processBacking
    if ($originalProcessVirtualHash -eq
        $processBackingHash)
    {
        throw "process fixture endpoints unexpectedly have the same hash"
    }

    $mappingAttempted = $true
    $applyResult =
        Invoke-RequiredNative `
            -FilePath $controller `
            -Arguments @(
                "apply",
                $fixtureRoot
            ) `
            -Context "constrained Bind Filter fixture apply"
    $applyResult.Text |
        Set-Content `
            -LiteralPath $controllerApplyLog `
            -Encoding UTF8

    $mappedText =
        Get-Content `
            -LiteralPath $fileVirtual `
            -Raw
    if ($mappedText -notmatch
        [regex]::Escape(
            "kn-live-dbg-bind-backing-$fixtureId"))
    {
        throw "file-binding fixture did not expose the backing content"
    }
    $mappedProcessHash =
        Get-FileSha256 `
            -Path $processVirtual
    if ($mappedProcessHash -ne
            $processBackingHash -or
        $mappedProcessHash -eq
            $originalProcessVirtualHash)
    {
        throw "Process-Binding fixture did not expose the backing executable"
    }

    $boundProcess =
        Start-Process `
            -FilePath $processVirtual `
            -ArgumentList @(
                "-t",
                "127.0.0.1"
            ) `
            -WindowStyle Hidden `
            -PassThru
    Start-Sleep -Seconds 1
    if ($boundProcess.HasExited)
    {
        throw "Process-Binding fixture process exited before collection"
    }

    $policyAttempted = $true
    New-NetQosPolicy `
        -Name $policyName `
        -AppPathNameMatchCondition $qosTarget `
        -ThrottleRateActionBitsPerSecond 64 `
        -PolicyStore ActiveStore |
        Out-Null

    $visiblePolicies =
        @(
            Get-NetQosPolicy `
                -Name $policyName `
                -PolicyStore ActiveStore `
                -ErrorAction Stop
        )
    if ($visiblePolicies.Count -ne 1)
    {
        throw (
            "QoS fixture was not uniquely visible in ActiveStore: count={0}" -f
                $visiblePolicies.Count)
    }
    $visiblePolicy =
        $visiblePolicies[0]
    if (-not [string]::Equals(
            [string]$visiblePolicy.Name,
            $policyName,
            [System.StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals(
            [string]$visiblePolicy.AppPathNameMatchCondition,
            $qosTarget,
            [System.StringComparison]::OrdinalIgnoreCase) -or
        [UInt64]$visiblePolicy.ThrottleRateAction -ne 64)
    {
        throw "QoS fixture ActiveStore properties do not match the requested policy"
    }

    $huntResult =
        Invoke-NativeCapture `
            -FilePath "powershell.exe" `
            -Arguments @(
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                $huntRunner,
                "-Root",
                $rootPath,
                "-Executable",
                $executable,
                "-OutputDirectory",
                $huntOutput,
                "-Mode",
                "Default",
                "-Count",
                "1",
                "-TimeoutSeconds",
                [string]$TimeoutSeconds,
                "-NoElevation"
            )
    $huntResult.Text |
        Set-Content `
            -LiteralPath (
                Join-Path $outputPath (
                    "hunt-runner.log")) `
            -Encoding UTF8
    if ($huntResult.ExitCode -ne 0)
    {
        throw (
            "hunt runner failed with exit={0}: {1}" -f
                $huntResult.ExitCode,
                $huntResult.Text)
    }
    if (-not (Test-Path `
            -LiteralPath $huntJson `
            -PathType Leaf))
    {
        throw "hunt runner did not create the expected artifact: $huntJson"
    }

    $validatorResult =
        Invoke-NativeCapture `
            -FilePath "powershell.exe" `
            -Arguments @(
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                $validator,
                "-HuntJson",
                $huntJson,
                "-PolicyName",
                $policyName,
                "-QosTargetPath",
                $qosTarget,
                "-FileVirtualPath",
                $fileVirtual,
                "-FileBackingPath",
                $fileBacking,
                "-ProcessVirtualPath",
                $processVirtual,
                "-ProcessBackingPath",
                $processBacking,
                "-ProcessId",
                [string]$boundProcess.Id,
                "-RequireMode",
                "Default"
            )
    $validatorResult.Text |
        Set-Content `
            -LiteralPath $validatorLog `
            -Encoding UTF8
    if ($validatorResult.ExitCode -ne 0)
    {
        throw (
            "independent QoS/Bind evidence validator failed with exit={0}: {1}" -f
                $validatorResult.ExitCode,
                $validatorResult.Text)
    }

    $manifestDocument =
        [ordered]@{
            schema =
                "kn-live-dbg.qos-bind-e2e.v1"
            status = "passed"
            timestamp_utc =
                [DateTime]::UtcNow.ToString("o")
            policy_name = $policyName
            qos_target = $qosTarget
            file_virtual = $fileVirtual
            file_backing = $fileBacking
            process_virtual = $processVirtual
            process_backing = $processBacking
            process_id =
                [int]$boundProcess.Id
            hunt_json = $huntJson
            validator_log = $validatorLog
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
    if ($policyAttempted)
    {
        try
        {
            Remove-NetQosPolicy `
                -Name $policyName `
                -PolicyStore ActiveStore `
                -Confirm:$false `
                -ErrorAction SilentlyContinue
            $remainingPolicies =
                @(
                    Get-NetQosPolicy `
                    -PolicyStore ActiveStore `
                        -ErrorAction Stop |
                        Where-Object {
                            [string]::Equals(
                                [string]$_.Name,
                                $policyName,
                                [System.StringComparison]::OrdinalIgnoreCase)
                        }
                )
            if ($remainingPolicies.Count -ne 0)
            {
                throw "policy remained in ActiveStore"
            }
        }
        catch
        {
            $cleanupFailures.Add(
                "QoS fixture policy cleanup failed: $($_.Exception.Message)")
        }
    }

    if ($null -ne $boundProcess)
    {
        try
        {
            if (-not $boundProcess.HasExited)
            {
                Stop-Process `
                    -Id $boundProcess.Id `
                    -Force `
                    -ErrorAction Stop
                if (-not $boundProcess.WaitForExit(
                        10000))
                {
                    throw "process did not exit within 10 seconds"
                }
            }
        }
        catch
        {
            $cleanupFailures.Add(
                "fixture process cleanup failed: $($_.Exception.Message)")
        }
        finally
        {
            try
            {
                $boundProcess.Dispose()
            }
            catch
            {
                $cleanupFailures.Add(
                    "fixture process handle cleanup failed: $($_.Exception.Message)")
            }
            $boundProcess = $null
        }
    }

    if ($mappingAttempted -and
        $fixtureCreated)
    {
        try
        {
            $removeResult =
                Invoke-NativeCapture `
                    -FilePath $controller `
                    -Arguments @(
                        "remove",
                        $fixtureRoot
                    )
            $removeResult.Text |
                Set-Content `
                    -LiteralPath $controllerRemoveLog `
                    -Encoding UTF8
            if ($removeResult.ExitCode -ne 0)
            {
                throw (
                    "exit=$($removeResult.ExitCode) $($removeResult.Text)")
            }

            $restoredText =
                Get-Content `
                    -LiteralPath $fileVirtual `
                    -Raw
            $restoredProcessHash =
                Get-FileSha256 `
                    -Path $processVirtual
            if ($restoredText -notmatch
                    [regex]::Escape(
                        "kn-live-dbg-bind-virtual-$fixtureId") -or
                $restoredProcessHash -ne
                    $originalProcessVirtualHash)
            {
                throw (
                    "source files did not return to their original identities")
            }
            $mappingRemovalConfirmed =
                $true
        }
        catch
        {
            $cleanupFailures.Add(
                "Bind Filter fixture removal failed: $($_.Exception.Message)")
        }
    }

    if ($fixtureCreated -and
        (-not $mappingAttempted -or
         $mappingRemovalConfirmed) -and
        (Test-Path -LiteralPath $fixtureRoot))
    {
        try
        {
            Assert-PlainDirectoryTreeForRemoval `
                -Parent $temporaryRoot `
                -Path $fixtureRoot `
                -Context "QoS/Bind fixture directory"
            Remove-Item `
                -LiteralPath $fixtureRoot `
                -Recurse `
                -Force
            if (Test-Path -LiteralPath $fixtureRoot)
            {
                throw "fixture directory remains"
            }
        }
        catch
        {
            $cleanupFailures.Add(
                "fixture directory cleanup failed: $($_.Exception.Message)")
        }
    }
    elseif ($fixtureCreated -and
        (Test-Path -LiteralPath $fixtureRoot))
    {
        $cleanupFailures.Add(
            "fixture directory retained because Bind Filter removal was not confirmed: $fixtureRoot")
    }

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
                "fixture mutex release failed: $($_.Exception.Message)")
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
                "fixture mutex handle cleanup failed: $($_.Exception.Message)")
        }
    }
    if ($null -ne $runnerLock)
    {
        try
        {
            $runnerLock.Dispose()
            $runnerLock = $null
            Remove-Item `
                -LiteralPath $lockPath `
                -Force `
                -ErrorAction Stop
        }
        catch
        {
            $cleanupFailures.Add(
                "runner lock cleanup failed: $($_.Exception.Message)")
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
            "fixture cleanup failed: $cleanupText"
    }
    else
    {
        $failureMessage +=
            "; cleanup failed: $cleanupText"
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
        ConvertTo-Json -Depth 4 |
        Set-Content `
            -LiteralPath $manifestPath `
            -Encoding UTF8
}
catch
{
    $failureMessage =
        "could not write the passed manifest after cleanup: $($_.Exception.Message)"
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
    "[qos-bind-e2e] passed manifest=$manifestPath cleanup=passed")
