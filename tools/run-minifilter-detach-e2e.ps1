[CmdletBinding()]
param(
    [string]$Root = "",

    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",

    [string]$Volume = $env:SystemDrive,

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

$serviceName =
    "KnLiveDbgMiniFilterFixture"
$filterName =
    "KnLiveDbgMiniFilterFixture"
$instanceName =
    "KnLiveDbgMiniFilterFixture.Instance"
$altitude =
    "370030.12345"

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
    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent))
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
        $output = @(
            & $FilePath @Arguments 2>&1 |
                ForEach-Object {
                    $_.ToString()
                }
        )
        $exitCode = $LASTEXITCODE
    }
    finally
    {
        $ErrorActionPreference =
            $savedErrorPreference
    }

    return [pscustomobject]@{
        ExitCode = [int]$exitCode
        Output = $output
        Text = ($output -join
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

function Test-FilterRegistered
{
    $result =
        Invoke-NativeCapture `
            -FilePath "fltmc.exe" `
            -Arguments @("filters")
    if ($result.ExitCode -ne 0)
    {
        throw (
            "Filter Manager enumeration failed with exit={0}: {1}" -f
                $result.ExitCode,
                $result.Text)
    }
    return $result.Text -match (
        "(?im)^\s*" +
        [regex]::Escape($filterName) +
        "\s+")
}

function Wait-ServiceAbsent
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [ValidateRange(1, 300)]
        [int]$Seconds = 15
    )

    $deadline =
        [DateTime]::UtcNow.AddSeconds($Seconds)
    do
    {
        if ($null -eq (
                Get-Service `
                    -Name $Name `
                    -ErrorAction SilentlyContinue))
        {
            return $true
        }
        Start-Sleep -Milliseconds 100
    }
    while ([DateTime]::UtcNow -lt $deadline)
    return $false
}

function Assert-MainDebuggerIdle
{
    $deadline =
        [DateTime]::UtcNow.AddSeconds(15)
    $processIds = @()
    $serviceState = ""
    do
    {
        $processIds = @(
            Get-Process `
                -Name "KnLiveDbg" `
                -ErrorAction SilentlyContinue |
                ForEach-Object {
                    $_.Id
                    $_.Dispose()
                }
        )
        $service =
            Get-Service `
                -Name "KnLiveDbg" `
                -ErrorAction SilentlyContinue
        $serviceState =
            if ($null -eq $service)
            {
                ""
            }
            else
            {
                [string]$service.Status
            }
        if ($null -ne $service)
        {
            $service.Dispose()
        }
        if ($processIds.Count -eq 0 -and
            [string]::IsNullOrWhiteSpace(
                $serviceState))
        {
            return
        }
        Start-Sleep -Milliseconds 100
    }
    while ([DateTime]::UtcNow -lt $deadline)

    if ($processIds.Count -ne 0)
    {
        throw (
            "refusing to run while KnLiveDbg.exe remains active after 15 seconds: pids={0}" -f
                ($processIds -join ","))
    }
    throw (
        "refusing to run while the KnLiveDbg service remains registered after 15 seconds: state={0}" -f
            $serviceState)
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

function Invoke-KnLiveDbgScript
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Executable,

        [Parameter(Mandatory = $true)]
        [string[]]$Commands,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [string]$ErrorPath,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    Assert-MainDebuggerIdle

    $startInfo =
        [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $Executable
    $startInfo.WorkingDirectory =
        Split-Path -Parent $Executable
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true

    $process =
        [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start())
    {
        throw "$Context could not start KnLiveDbg.exe"
    }

    $outputTask =
        $process.StandardOutput.ReadToEndAsync()
    $errorTask =
        $process.StandardError.ReadToEndAsync()
    $exitCode = $null
    $operationFailure = ""
    $captureFailures =
        [System.Collections.Generic.List[string]]::new()
    $stdout = ""
    $stderr = ""
    try
    {
        foreach ($command in $Commands)
        {
            $process.StandardInput.WriteLine(
                $command)
        }
        $process.StandardInput.Close()

        if (-not $process.WaitForExit(
                $TimeoutSeconds * 1000))
        {
            try
            {
                if (-not $process.HasExited)
                {
                    $process.Kill()
                }
            }
            catch [System.InvalidOperationException]
            {
            }
            $null = $process.WaitForExit(10000)
            throw (
                "$Context timed out after $TimeoutSeconds seconds; pid=$($process.Id)")
        }
        $process.WaitForExit()
        $exitCode =
            [int]$process.ExitCode
    }
    catch
    {
        $operationFailure =
            $_.Exception.Message
    }
    finally
    {
        try
        {
            if (-not $process.HasExited)
            {
                $process.Kill()
                if (-not $process.WaitForExit(10000))
                {
                    $captureFailures.Add(
                        "child process did not exit after termination")
                }
            }
        }
        catch
        {
            $captureFailures.Add(
                "child termination failed: $($_.Exception.Message)")
        }

        try
        {
            if ($outputTask.Wait(10000))
            {
                $stdout = $outputTask.Result
            }
            else
            {
                $captureFailures.Add(
                    "stdout capture did not complete")
            }
        }
        catch
        {
            $captureFailures.Add(
                "stdout capture failed: $($_.Exception.Message)")
        }
        try
        {
            if ($errorTask.Wait(10000))
            {
                $stderr = $errorTask.Result
            }
            else
            {
                $captureFailures.Add(
                    "stderr capture did not complete")
            }
        }
        catch
        {
            $captureFailures.Add(
                "stderr capture failed: $($_.Exception.Message)")
        }

        try
        {
            $stdout |
                Set-Content `
                    -LiteralPath $OutputPath `
                    -Encoding UTF8
            $stderr |
                Set-Content `
                    -LiteralPath $ErrorPath `
                    -Encoding UTF8
        }
        catch
        {
            $captureFailures.Add(
                "redirected output persistence failed: $($_.Exception.Message)")
        }
        finally
        {
            $process.Dispose()
        }
    }

    if ($captureFailures.Count -ne 0)
    {
        $captureText =
            $captureFailures -join "; "
        if (-not [string]::IsNullOrWhiteSpace(
                $operationFailure))
        {
            throw (
                "$operationFailure; process cleanup/capture failed: $captureText")
        }
        throw (
            "$Context process cleanup/capture failed: $captureText")
    }
    if (-not [string]::IsNullOrWhiteSpace(
            $operationFailure))
    {
        throw $operationFailure
    }

    if ($exitCode -ne 0)
    {
        throw (
            "$Context failed with exit=$exitCode; stdout=$OutputPath stderr=$ErrorPath")
    }
    if (-not (
            Wait-ServiceAbsent `
                -Name "KnLiveDbg" `
                -Seconds 15))
    {
        throw "$Context left the KnLiveDbg service registered"
    }
}

$rootPath =
    (Resolve-Path -LiteralPath $Root).Path
if ([string]::IsNullOrWhiteSpace($OutputDirectory))
{
    $outputPath =
        Join-Path $rootPath (
            ".build\minifilter-detach-e2e")
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

$attachedPath =
    Join-Path $outputPath "attached.json"
$detachedPath =
    Join-Path $outputPath "detached.json"
$reattachedPath =
    Join-Path $outputPath "reattached.json"
$positiveDiffOut =
    Join-Path $outputPath "positive-diff.stdout.log"
$positiveDiffErr =
    Join-Path $outputPath "positive-diff.stderr.log"
$recoveryDiffOut =
    Join-Path $outputPath "recovery-diff.stdout.log"
$recoveryDiffErr =
    Join-Path $outputPath "recovery-diff.stderr.log"
$validatorLog =
    Join-Path $outputPath "validator.log"
$manifestPath =
    Join-Path $outputPath "manifest.json"
$queryAttachedLog =
    Join-Path $outputPath "query-attached.log"
$queryDetachedLog =
    Join-Path $outputPath "query-detached.log"
$queryReattachedLog =
    Join-Path $outputPath "query-reattached.log"
$lockPath =
    Join-Path $outputPath ".runner.lock"

Remove-Item `
    -LiteralPath $manifestPath `
    -Force `
    -ErrorAction SilentlyContinue

$runnerLock = $null
$mutex = $null
$mutexOwned = $false
$serviceCreated = $false
$serviceCreateAttempted = $false
$filterLoaded = $false
$filterLoadStateUnknown = $false
$instanceAttached = $false
$instanceAttachmentStateUnknown = $false
$runSucceeded = $false
$failureMessage = ""
$manifestDocument = $null
$volumeArgument = ""
$executable = ""
$driverPath = ""
$validator = ""
$cleanupFailures =
    [System.Collections.Generic.List[string]]::new()

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

    Remove-Item `
        -LiteralPath $statusPath `
        -Force `
        -ErrorAction SilentlyContinue
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
        "-TimeoutSeconds",
        [string]$TimeoutSeconds,
        "-NoElevation",
        "-ElevationStatusPath",
        (ConvertTo-ProcessArgument $statusPath)
    )
    Write-Host (
        "[minifilter-detach-e2e] requesting UAC elevation")
    $child =
        Start-Process `
            -FilePath "powershell.exe" `
            -ArgumentList ($arguments -join " ") `
            -Verb RunAs `
            -WindowStyle Hidden `
            -Wait `
            -PassThru
    $childExitCode =
        [int]$child.ExitCode
    if (Test-Path -LiteralPath $statusPath)
    {
        Get-Content -LiteralPath $statusPath |
            ForEach-Object {
                Write-Host (
                    "[minifilter-detach-e2e] $_")
            }
    }
    exit $childExitCode
}

try
{
    if ($Volume -notmatch '^[A-Za-z]:\\?$')
    {
        throw "Volume must be a local drive root such as C:"
    }
    $driveLetter =
        $Volume.Substring(0, 1).ToUpperInvariant()
    $volumeArgument =
        $driveLetter + ":"
    $volumeInfo =
        Get-Volume `
            -DriveLetter $driveLetter `
            -ErrorAction Stop
    if ($volumeInfo.FileSystem -notin @("NTFS", "ReFS"))
    {
        throw (
            "fixture volume must use NTFS or ReFS: volume={0} filesystem={1}" -f
                $volumeArgument,
                $volumeInfo.FileSystem)
    }

    $executable =
        Resolve-BuildOrPackageArtifact `
            -RepositoryRoot $rootPath `
            -BuildConfiguration $Configuration `
            -Name "KnLiveDbg.exe"
    $driverPath =
        Resolve-BuildOrPackageArtifact `
            -RepositoryRoot $rootPath `
            -BuildConfiguration $Configuration `
            -Name "KnLiveDbgMiniFilterFixture.sys"
    $validator =
        Join-Path $rootPath (
            "tools\validate-minifilter-detach-e2e.ps1")
    foreach ($required in @(
            $executable,
            $driverPath,
            $validator))
    {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf))
        {
            throw "required fixture artifact is missing: $required"
        }
    }

    $signature =
        Get-AuthenticodeSignature `
            -LiteralPath $driverPath
    if ($null -eq $signature.SignerCertificate -or
        $signature.Status -in @(
            "NotSigned",
            "HashMismatch"))
    {
        throw (
            "fixture driver is not test-signed: status={0}" -f
                $signature.Status)
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
            "Global\KnLiveDbgMiniFilterFixtureE2E")
    try
    {
        $mutexOwned =
            $mutex.WaitOne(0)
    }
    catch [System.Threading.AbandonedMutexException]
    {
        # WaitOne grants ownership when it reports an abandoned mutex.
        $mutexOwned = $true
    }
    if (-not $mutexOwned)
    {
        throw "another minifilter fixture runner is active"
    }

    Assert-MainDebuggerIdle
    if ($null -ne (
            Get-Service `
                -Name $serviceName `
                -ErrorAction SilentlyContinue))
    {
        throw "refusing to replace a pre-existing fixture service"
    }
    if (Test-FilterRegistered)
    {
        throw "refusing to touch a pre-existing fixture filter registration"
    }

    Remove-Item `
        -LiteralPath @(
            $attachedPath,
            $detachedPath,
            $reattachedPath,
            $positiveDiffOut,
            $positiveDiffErr,
            $recoveryDiffOut,
            $recoveryDiffErr,
            $validatorLog,
            $manifestPath,
            $queryAttachedLog,
            $queryDetachedLog,
            $queryReattachedLog,
            $statusPath
        ) `
        -Force `
        -ErrorAction SilentlyContinue

    $serviceCreateAttempted = $true
    $createResult =
        Invoke-RequiredNative `
            -FilePath "sc.exe" `
            -Arguments @(
                "create",
                $serviceName,
                "type=",
                "filesys",
                "start=",
                "demand",
                "error=",
                "normal",
                "binPath=",
                $driverPath,
                "group=",
                "FSFilter Activity Monitor",
                "depend=",
                "FltMgr",
                "DisplayName=",
                "KnLiveDbg Minifilter Fixture"
            ) `
            -Context "fixture service creation"
    $serviceCreated = $true

    $serviceRegistry =
        "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
    foreach ($instancesPath in @(
            (Join-Path $serviceRegistry "Instances"),
            (Join-Path $serviceRegistry "Parameters\Instances")))
    {
        New-Item `
            -Path $instancesPath `
            -Force |
            Out-Null
        New-ItemProperty `
            -Path $instancesPath `
            -Name "DefaultInstance" `
            -Value $instanceName `
            -PropertyType String `
            -Force |
            Out-Null
        $instancePath =
            Join-Path $instancesPath $instanceName
        New-Item `
            -Path $instancePath `
            -Force |
            Out-Null
        New-ItemProperty `
            -Path $instancePath `
            -Name "Altitude" `
            -Value $altitude `
            -PropertyType String `
            -Force |
            Out-Null
        # 0x1 suppresses automatic volume attachment. The runner attaches only
        # this fixture instance to the explicitly selected volume.
        New-ItemProperty `
            -Path $instancePath `
            -Name "Flags" `
            -Value 1 `
            -PropertyType DWord `
            -Force |
            Out-Null
    }
    $parametersPath =
        Join-Path $serviceRegistry "Parameters"
    New-Item `
        -Path $parametersPath `
        -Force |
        Out-Null
    New-ItemProperty `
        -Path $parametersPath `
        -Name "SupportedFeatures" `
        -Value 3 `
        -PropertyType DWord `
        -Force |
        Out-Null

    $filterLoadStateUnknown = $true
    $null =
        Invoke-RequiredNative `
            -FilePath "fltmc.exe" `
            -Arguments @(
                "load",
                $filterName
            ) `
            -Context "fixture filter load"
    $filterLoadStateUnknown = $false
    $filterLoaded = $true
    if (-not (Test-FilterRegistered))
    {
        throw "fixture filter did not remain registered after load"
    }

    $instanceAttachmentStateUnknown = $true
    $null =
        Invoke-RequiredNative `
            -FilePath "fltmc.exe" `
            -Arguments @(
                "attach",
                $filterName,
                $volumeArgument,
                "-i",
                $instanceName,
                "-a",
                $altitude
            ) `
            -Context "fixture instance attach"
    $instanceAttachmentStateUnknown = $false
    $instanceAttached = $true

    $query =
        Invoke-NativeCapture `
            -FilePath $executable `
            -Arguments @(
                "--self-test",
                "minifilter-attachments-query"
            )
    $query.Text |
        Set-Content `
            -LiteralPath $queryAttachedLog `
            -Encoding UTF8
    if ($query.ExitCode -ne 0 -or
        $query.Text -notmatch (
            'filter="' +
            [regex]::Escape($filterName) +
            '".*instance="' +
            [regex]::Escape($instanceName) +
            '".*detached=no'))
    {
        throw (
            "live attachment query did not observe the clean fixture instance; exit={0} log={1}" -f
                $query.ExitCode,
                $queryAttachedLog)
    }

    Invoke-KnLiveDbgScript `
        -Executable $executable `
        -Commands @(
            "write off",
            "!snapshot save `"$attachedPath`" /all /name minifilter-attached",
            "unload",
            "exit"
        ) `
        -OutputPath (
            Join-Path $outputPath "attached.stdout.log") `
        -ErrorPath (
            Join-Path $outputPath "attached.stderr.log") `
        -Context "attached snapshot"
    if (-not (Test-Path -LiteralPath $attachedPath -PathType Leaf))
    {
        throw "attached snapshot was not created"
    }

    $null =
        Invoke-RequiredNative `
            -FilePath "fltmc.exe" `
            -Arguments @(
                "detach",
                $filterName,
                $volumeArgument,
                $instanceName
            ) `
            -Context "fixture instance detach"
    $instanceAttached = $false
    $instanceAttachmentStateUnknown = $false
    if (-not (Test-FilterRegistered))
    {
        throw "fixture filter registration disappeared after instance detach"
    }

    $query =
        Invoke-NativeCapture `
            -FilePath $executable `
            -Arguments @(
                "--self-test",
                "minifilter-attachments-query"
            )
    $query.Text |
        Set-Content `
            -LiteralPath $queryDetachedLog `
            -Encoding UTF8
    if ($query.ExitCode -ne 0 -or
        $query.Text -match (
            'filter="' +
            [regex]::Escape($filterName) +
            '".*instance="' +
            [regex]::Escape($instanceName) +
            '"'))
    {
        throw (
            "live attachment query did not prove fixture detachment; exit={0} log={1}" -f
                $query.ExitCode,
                $queryDetachedLog)
    }

    Invoke-KnLiveDbgScript `
        -Executable $executable `
        -Commands @(
            "write off",
            "!snapshot save `"$detachedPath`" /all /name minifilter-detached",
            "unload",
            "exit"
        ) `
        -OutputPath (
            Join-Path $outputPath "detached.stdout.log") `
        -ErrorPath (
            Join-Path $outputPath "detached.stderr.log") `
        -Context "detached snapshot"
    if (-not (Test-Path -LiteralPath $detachedPath -PathType Leaf))
    {
        throw "detached snapshot was not created"
    }

    $instanceAttachmentStateUnknown = $true
    $null =
        Invoke-RequiredNative `
            -FilePath "fltmc.exe" `
            -Arguments @(
                "attach",
                $filterName,
                $volumeArgument,
                "-i",
                $instanceName,
                "-a",
                $altitude
            ) `
            -Context "fixture instance reattach"
    $instanceAttachmentStateUnknown = $false
    $instanceAttached = $true

    $query =
        Invoke-NativeCapture `
            -FilePath $executable `
            -Arguments @(
                "--self-test",
                "minifilter-attachments-query"
            )
    $query.Text |
        Set-Content `
            -LiteralPath $queryReattachedLog `
            -Encoding UTF8
    if ($query.ExitCode -ne 0 -or
        $query.Text -notmatch (
            'filter="' +
            [regex]::Escape($filterName) +
            '".*instance="' +
            [regex]::Escape($instanceName) +
            '".*detached=no'))
    {
        throw (
            "live attachment query did not prove fixture reattachment; exit={0} log={1}" -f
                $query.ExitCode,
                $queryReattachedLog)
    }

    Invoke-KnLiveDbgScript `
        -Executable $executable `
        -Commands @(
            "write off",
            "!snapshot save `"$reattachedPath`" /all /name minifilter-reattached",
            "unload",
            "exit"
        ) `
        -OutputPath (
            Join-Path $outputPath "reattached.stdout.log") `
        -ErrorPath (
            Join-Path $outputPath "reattached.stderr.log") `
        -Context "reattached snapshot"
    if (-not (Test-Path -LiteralPath $reattachedPath -PathType Leaf))
    {
        throw "reattached snapshot was not created"
    }

    Invoke-KnLiveDbgScript `
        -Executable $executable `
        -Commands @(
            "write off",
            "!diff `"$attachedPath`" `"$detachedPath`" /details /domain minifilter-attachments /risk all /limit 100",
            "unload",
            "exit"
        ) `
        -OutputPath $positiveDiffOut `
        -ErrorPath $positiveDiffErr `
        -Context "positive snapshot diff"

    Invoke-KnLiveDbgScript `
        -Executable $executable `
        -Commands @(
            "write off",
            "!diff `"$attachedPath`" `"$reattachedPath`" /details /domain minifilter-attachments /risk all /limit 100",
            "unload",
            "exit"
        ) `
        -OutputPath $recoveryDiffOut `
        -ErrorPath $recoveryDiffErr `
        -Context "recovery snapshot diff"

    $validatorResult =
        Invoke-NativeCapture `
            -FilePath "powershell.exe" `
            -Arguments @(
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                $validator,
                "-BaselinePath",
                $attachedPath,
                "-DetachedPath",
                $detachedPath,
                "-ReattachedPath",
                $reattachedPath,
                "-PositiveDiffLogPath",
                $positiveDiffOut,
                "-RecoveryDiffLogPath",
                $recoveryDiffOut,
                "-FilterName",
                $filterName,
                "-InstanceName",
                $instanceName
            )
    $validatorResult.Text |
        Set-Content `
            -LiteralPath $validatorLog `
            -Encoding UTF8
    if ($validatorResult.ExitCode -ne 0)
    {
        throw (
            "independent minifilter evidence validator failed with exit={0}: {1}" -f
                $validatorResult.ExitCode,
                $validatorResult.Text)
    }

    $manifestDocument = [ordered]@{
        schema =
            "kn-live-dbg.minifilter-detach-e2e.v1"
        status = "passed"
        timestamp_utc =
            [DateTime]::UtcNow.ToString("o")
        filter = $filterName
        instance = $instanceName
        altitude = $altitude
        volume = $volumeArgument
        driver = $driverPath
        attached_snapshot = $attachedPath
        detached_snapshot = $detachedPath
        reattached_snapshot = $reattachedPath
        positive_diff_log = $positiveDiffOut
        recovery_diff_log = $recoveryDiffOut
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
    if ($filterLoaded -or
        $filterLoadStateUnknown)
    {
        $filterPresent = $true
        try
        {
            $filterPresent =
                Test-FilterRegistered
        }
        catch
        {
            $cleanupFailures.Add(
                "pre-cleanup filter check failed: $($_.Exception.Message)")
        }

        if ($filterPresent)
        {
            $detachFailure = ""
            if (($instanceAttached -or
                 $instanceAttachmentStateUnknown) -and
                -not [string]::IsNullOrWhiteSpace(
                    $volumeArgument))
            {
                $detachResult =
                    Invoke-NativeCapture `
                        -FilePath "fltmc.exe" `
                        -Arguments @(
                            "detach",
                            $filterName,
                            $volumeArgument,
                            $instanceName
                        )
                if ($detachResult.ExitCode -ne 0)
                {
                    $detachFailure =
                        "detach exit=$($detachResult.ExitCode) $($detachResult.Text)"
                }
                else
                {
                    $instanceAttached = $false
                    $instanceAttachmentStateUnknown =
                        $false
                }
            }

            $unloadResult =
                Invoke-NativeCapture `
                    -FilePath "fltmc.exe" `
                    -Arguments @(
                        "unload",
                        $filterName
                    )
            if ($unloadResult.ExitCode -ne 0)
            {
                if (-not [string]::IsNullOrWhiteSpace(
                        $detachFailure))
                {
                    $cleanupFailures.Add(
                        $detachFailure)
                }
                $cleanupFailures.Add(
                    "unload exit=$($unloadResult.ExitCode) $($unloadResult.Text)")
            }
            else
            {
                $filterLoaded = $false
                $filterLoadStateUnknown = $false
                $instanceAttached = $false
                $instanceAttachmentStateUnknown =
                    $false
            }
        }
        else
        {
            $filterLoaded = $false
            $filterLoadStateUnknown = $false
            $instanceAttached = $false
            $instanceAttachmentStateUnknown =
                $false
        }
    }

    if ($serviceCreated -or
        $serviceCreateAttempted)
    {
        try
        {
            $service =
                Get-Service `
                    -Name $serviceName `
                    -ErrorAction SilentlyContinue
            if ($null -ne $service -and
                $service.Status -ne "Stopped")
            {
                $null =
                    Invoke-NativeCapture `
                        -FilePath "sc.exe" `
                        -Arguments @(
                            "stop",
                            $serviceName
                        )
            }
            if ($null -ne $service)
            {
                $deleteResult =
                    Invoke-NativeCapture `
                        -FilePath "sc.exe" `
                        -Arguments @(
                            "delete",
                            $serviceName
                        )
                if ($deleteResult.ExitCode -ne 0)
                {
                    $cleanupFailures.Add(
                        "service-delete exit=$($deleteResult.ExitCode) $($deleteResult.Text)")
                }
                elseif (-not (
                        Wait-ServiceAbsent `
                            -Name $serviceName `
                            -Seconds 15))
                {
                    $cleanupFailures.Add(
                        "fixture service remained registered after delete")
                }
                else
                {
                    $serviceCreated = $false
                }
            }
        }
        catch
        {
            $cleanupFailures.Add(
                "service cleanup failed: $($_.Exception.Message)")
        }
    }

    if ($filterLoaded -or
        $filterLoadStateUnknown -or
        $serviceCreated)
    {
        try
        {
            if (Test-FilterRegistered)
            {
                $cleanupFailures.Add(
                    "fixture filter remained registered")
            }
        }
        catch
        {
            $cleanupFailures.Add(
                "post-cleanup filter check failed: $($_.Exception.Message)")
        }
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
                "mutex release failed: $($_.Exception.Message)")
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
                "mutex disposal failed: $($_.Exception.Message)")
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
    "[minifilter-detach-e2e] passed manifest=$manifestPath cleanup=passed")
