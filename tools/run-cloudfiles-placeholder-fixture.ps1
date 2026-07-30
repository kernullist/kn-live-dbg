[CmdletBinding()]
param(
    [ValidateSet('InSyncNegative', 'ModifiedPositive')]
    [string]$Scenario = 'ModifiedPositive',

    [ValidateRange(1, 60)]
    [int]$HoldSeconds = 20,

    [switch]$ValidateHunt,

    [string]$HuntOutputDirectory = '',

    [ValidateSet('Default', 'Deep')]
    [string]$HuntMode = 'Deep',

    [ValidateRange(60, 3600)]
    [int]$HuntTimeoutSeconds = 1200
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-IsAdministrator
{
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-BuildOrPackageArtifact
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepositoryRoot,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $candidates = @(
        (Join-Path $RepositoryRoot (
            "x64\Release\$Name")),
        (Join-Path $RepositoryRoot $Name)
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return [IO.Path]::GetFullPath($candidate)
        }
    }
    return $candidates[0]
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
            $Path).TrimEnd('\')
    $volumeRoot =
        [IO.Path]::GetPathRoot(
            $fullPath).TrimEnd('\')
    $repositoryPath =
        [IO.Path]::GetFullPath(
            $RepositoryRoot).TrimEnd('\')
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

    $parentPath =
        [IO.Path]::GetFullPath(
            $Parent).TrimEnd('\')
    $targetPath =
        [IO.Path]::GetFullPath(
            $Path).TrimEnd('\')
    if (-not $targetPath.StartsWith(
            $parentPath + '\',
            [StringComparison]::OrdinalIgnoreCase))
    {
        throw "$Context is outside the expected parent: $targetPath"
    }

    $parentItem =
        Get-Item `
            -LiteralPath $parentPath `
            -Force `
            -ErrorAction Stop
    if (-not $parentItem.PSIsContainer -or
        (($parentItem.Attributes -band
          [IO.FileAttributes]::ReparsePoint) -ne 0))
    {
        throw "$Context parent is not a plain directory: $parentPath"
    }

    $relative =
        $targetPath.Substring(
            $parentPath.Length + 1)
    $current = $parentPath
    foreach ($segment in
        $relative.Split(
            [char]'\',
            [StringSplitOptions]::RemoveEmptyEntries))
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
              [IO.FileAttributes]::ReparsePoint) -ne 0))
        {
            throw "$Context traverses a non-directory or reparse point: $current"
        }
    }

    $pending =
        [Collections.Generic.Stack[
            IO.DirectoryInfo]]::new()
    $pending.Push(
        [IO.DirectoryInfo](
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
                    [IO.FileAttributes]::Directory) -eq 0)
            {
                continue
            }
            if (($child.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0)
            {
                throw (
                    "$Context contains a directory reparse point: " +
                    $child.FullName)
            }
            $pending.Push(
                [IO.DirectoryInfo]$child)
        }
    }
}

$repoRoot =
    [IO.Path]::GetFullPath(
        (Split-Path -Parent $PSScriptRoot))
$huntOutputPath = ''
$huntJson = ''
$resultManifestPath = ''
$fixtureProcessId = 0
if ($ValidateHunt) {
    if ([string]::IsNullOrWhiteSpace($HuntOutputDirectory)) {
        $huntOutputPath = Join-Path $repoRoot (
            '.build\cloudfiles-hunt-e2e\' +
            $Scenario.ToLowerInvariant())
    }
    elseif ([IO.Path]::IsPathRooted($HuntOutputDirectory)) {
        $huntOutputPath = [IO.Path]::GetFullPath(
            $HuntOutputDirectory)
    }
    else {
        $huntOutputPath = [IO.Path]::GetFullPath(
            (Join-Path $repoRoot $HuntOutputDirectory))
    }
    Assert-DedicatedOutputDirectory `
        -Path $huntOutputPath `
        -RepositoryRoot $repoRoot
    $resultManifestPath =
        Join-Path $huntOutputPath (
            'cloudfiles-fixture-manifest.json')
    Remove-Item `
        -LiteralPath $resultManifestPath `
        -Force `
        -ErrorAction SilentlyContinue
    if (-not (Test-IsAdministrator)) {
        throw '-ValidateHunt requires an elevated PowerShell session'
    }
}

$huntExe =
    Resolve-BuildOrPackageArtifact `
        -RepositoryRoot $repoRoot `
        -Name 'KnLiveDbg.exe'
if (-not (Test-Path -LiteralPath $huntExe -PathType Leaf)) {
    throw "Release binary not found: $huntExe"
}

$huntRunner = Join-Path $repoRoot 'tools\run-hunt-clean-host.ps1'
$huntValidator =
    Join-Path $repoRoot 'tools\validate-cloudfiles-hunt-e2e.ps1'
if ($ValidateHunt) {
    foreach ($requiredPath in @($huntRunner, $huntValidator)) {
        if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
            throw "CloudFiles hunt validation dependency not found: $requiredPath"
        }
    }
}

$researchRoot = Join-Path $repoRoot '.build\research'
New-Item -ItemType Directory -Path $researchRoot -Force | Out-Null
$fixtureRoot = Join-Path $researchRoot (
    'cloudfiles-fixture-' + [Guid]::NewGuid().ToString('N'))
$fixtureImage = Join-Path $fixtureRoot 'CloudFilesFixture.exe'
$windowsDirectory =
    [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::Windows)
if ([string]::IsNullOrWhiteSpace($windowsDirectory)) {
    throw 'Windows directory could not be resolved'
}
$sourceImage =
    Join-Path $windowsDirectory 'System32\ping.exe'

$interopSource = @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class KnCloudFilesFixtureNative
{
    [StructLayout(LayoutKind.Sequential)]
    public struct CF_HYDRATION_POLICY
    {
        public ushort Primary;
        public ushort Modifier;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CF_POPULATION_POLICY
    {
        public ushort Primary;
        public ushort Modifier;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CF_SYNC_POLICIES
    {
        public uint StructSize;
        public CF_HYDRATION_POLICY Hydration;
        public CF_POPULATION_POLICY Population;
        public uint InSync;
        public uint HardLink;
        public uint PlaceholderManagement;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CF_SYNC_REGISTRATION
    {
        public uint StructSize;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string ProviderName;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string ProviderVersion;
        public IntPtr SyncRootIdentity;
        public uint SyncRootIdentityLength;
        public IntPtr FileIdentity;
        public uint FileIdentityLength;
        public Guid ProviderId;
    }

    [DllImport("cldapi.dll", CharSet = CharSet.Unicode)]
    public static extern int CfRegisterSyncRoot(
        string syncRootPath,
        ref CF_SYNC_REGISTRATION registration,
        ref CF_SYNC_POLICIES policies,
        uint registerFlags);

    [DllImport("cldapi.dll", CharSet = CharSet.Unicode)]
    public static extern int CfUnregisterSyncRoot(
        string syncRootPath);

    [DllImport("cldapi.dll")]
    public static extern int CfConvertToPlaceholder(
        IntPtr fileHandle,
        IntPtr fileIdentity,
        uint fileIdentityLength,
        uint convertFlags,
        IntPtr convertUsn,
        IntPtr overlapped);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr handle);

    public static void ThrowIfFailed(int status, string operation)
    {
        if (status < 0)
        {
            throw new ExternalException(
                operation + " failed",
                status);
        }
    }
}
'@

if (-not ('KnCloudFilesFixtureNative' -as [type])) {
    Add-Type -TypeDefinition $interopSource -Language CSharp
}

$registered = $false
$fixtureProcess = $null
$cleanupFailed = $false
$canRemoveFixture = $true
$operationFailure = $null
$rootIdentity = [Text.Encoding]::UTF8.GetBytes(
    'knlivedbg-cloudfiles-fixture-root-v1')
$fileIdentity = [Text.Encoding]::UTF8.GetBytes(
    'knlivedbg-cloudfiles-fixture-image-v1')
$rootIdentityPointer = [IntPtr]::Zero
$fileIdentityPointer = [IntPtr]::Zero

try {
    $rootIdentityPointer = [Runtime.InteropServices.Marshal]::AllocHGlobal(
        $rootIdentity.Length)
    $fileIdentityPointer = [Runtime.InteropServices.Marshal]::AllocHGlobal(
        $fileIdentity.Length)
    [Runtime.InteropServices.Marshal]::Copy(
        $rootIdentity,
        0,
        $rootIdentityPointer,
        $rootIdentity.Length)
    [Runtime.InteropServices.Marshal]::Copy(
        $fileIdentity,
        0,
        $fileIdentityPointer,
        $fileIdentity.Length)

    New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
    Copy-Item -LiteralPath $sourceImage -Destination $fixtureImage

    $registration =
        New-Object KnCloudFilesFixtureNative+CF_SYNC_REGISTRATION
    $registration.StructSize = [Runtime.InteropServices.Marshal]::SizeOf(
        [type]'KnCloudFilesFixtureNative+CF_SYNC_REGISTRATION')
    $registration.ProviderName = 'KNLiveDbg CloudFiles Fixture'
    $registration.ProviderVersion = '1.0'
    $registration.SyncRootIdentity = $rootIdentityPointer
    $registration.SyncRootIdentityLength = $rootIdentity.Length
    $registration.FileIdentity = $fileIdentityPointer
    $registration.FileIdentityLength = $fileIdentity.Length
    $registration.ProviderId =
        [Guid]'CB91F52D-2183-42ED-ADDD-80F427399B9A'

    $policies =
        New-Object KnCloudFilesFixtureNative+CF_SYNC_POLICIES
    $policies.StructSize = [Runtime.InteropServices.Marshal]::SizeOf(
        [type]'KnCloudFilesFixtureNative+CF_SYNC_POLICIES')
    # ALWAYS_FULL hydration and population keep this fixture fully local. It
    # never registers callbacks and never dehydrates or rehydrates data.
    $hydration =
        New-Object KnCloudFilesFixtureNative+CF_HYDRATION_POLICY
    $hydration.Primary = 3
    $hydration.Modifier = 0
    $policies.Hydration = $hydration
    $population =
        New-Object KnCloudFilesFixtureNative+CF_POPULATION_POLICY
    $population.Primary = 3
    $population.Modifier = 0
    $policies.Population = $population
    $policies.InSync = 0
    $policies.HardLink = 0
    $policies.PlaceholderManagement = 0

    $registerStatus =
        [KnCloudFilesFixtureNative]::CfRegisterSyncRoot(
            $fixtureRoot,
            [ref]$registration,
            [ref]$policies,
            4)
    [KnCloudFilesFixtureNative]::ThrowIfFailed(
        $registerStatus,
        'CfRegisterSyncRoot')
    Write-Verbose (
        'CfRegisterSyncRoot status=0x{0:X8}' -f
        [uint32]$registerStatus)
    $registered = $true

    $genericWrite = [uint32]0x40000000
    $shareReadWriteDelete = [uint32]0x00000007
    $openExisting = [uint32]3
    $normalAttributes = [uint32]0x00000080
    $fileHandle = [KnCloudFilesFixtureNative]::CreateFile(
        $fixtureImage,
        $genericWrite,
        $shareReadWriteDelete,
        [IntPtr]::Zero,
        $openExisting,
        $normalAttributes,
        [IntPtr]::Zero)
    if ($fileHandle -eq [IntPtr](-1)) {
        throw [ComponentModel.Win32Exception]::new(
            [Runtime.InteropServices.Marshal]::GetLastWin32Error(),
            'CreateFile for CfConvertToPlaceholder failed')
    }

    try {
        # MARK_IN_SYNC only. The source data remains fully hydrated because no
        # DEHYDRATE flag is used.
        $convertStatus =
            [KnCloudFilesFixtureNative]::CfConvertToPlaceholder(
                $fileHandle,
                $fileIdentityPointer,
                $fileIdentity.Length,
                0x00000001,
                [IntPtr]::Zero,
                [IntPtr]::Zero)
        [KnCloudFilesFixtureNative]::ThrowIfFailed(
            $convertStatus,
            'CfConvertToPlaceholder')
        Write-Verbose (
            'CfConvertToPlaceholder status=0x{0:X8}' -f
            [uint32]$convertStatus)
    }
    finally {
        [void][KnCloudFilesFixtureNative]::CloseHandle(
            $fileHandle)
    }

    $initialQuery = & $huntExe --self-test cloudfiles-query $fixtureImage 2>&1
    $initialExit = $LASTEXITCODE
    $initialQuery | Write-Host
    if ($initialExit -ne 0) {
        $reparseDiagnostic =
            & fsutil reparsepoint query $fixtureImage 2>&1
        $reparseDiagnostic | Write-Verbose
        throw "Initial CloudFiles query failed with exit code $initialExit"
    }
    $initialText = $initialQuery -join "`n"
    if ($initialText -notmatch 'cloud=yes' -or
        $initialText -notmatch 'metadata_complete=yes' -or
        $initialText -notmatch 'modified_data_size=0' -or
        $initialText -notmatch 'in_sync_state=1') {
        throw 'Initial CloudFiles metadata did not match the in-sync negative contract'
    }

    if ($Scenario -eq 'ModifiedPositive') {
        # Append a harmless PE overlay before execution. This exercises only
        # the detector's ModifiedDataSize branch; it is not an FFI
        # dehydrate/rehydrate or in-use image mutation.
        $marker = [Text.Encoding]::ASCII.GetBytes(
            'KNLIVEDBG_CLOUDFILES_SAFE_FIXTURE')
        $stream = [IO.File]::Open(
            $fixtureImage,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Write,
            [IO.FileShare]::ReadWrite)
        try {
            [void]$stream.Seek(0, [IO.SeekOrigin]::End)
            $stream.Write($marker, 0, $marker.Length)
            $stream.Flush($true)
        }
        finally {
            $stream.Dispose()
        }

        $modifiedQuery = & $huntExe --self-test cloudfiles-query $fixtureImage 2>&1
        $modifiedExit = $LASTEXITCODE
        $modifiedQuery | Write-Host
        if ($modifiedExit -ne 0) {
            throw "Modified CloudFiles query failed with exit code $modifiedExit"
        }
        $modifiedText = $modifiedQuery -join "`n"
        if ($modifiedText -notmatch 'modified_data_size=([1-9][0-9]*)') {
            throw 'CloudFiles metadata did not report a positive ModifiedDataSize'
        }
    }

    $fixtureProcess = Start-Process `
        -FilePath $fixtureImage `
        -ArgumentList @('-t', '127.0.0.1') `
        -WindowStyle Hidden `
        -PassThru
    $fixtureProcessId =
        [int]$fixtureProcess.Id

    Write-Host (
        '[cloudfiles.fixture] scenario={0} pid={1} image="{2}" hold_seconds={3}' -f
        $Scenario,
        $fixtureProcessId,
        $fixtureImage,
        $HoldSeconds)
    if ($ValidateHunt) {
        $huntArguments = @(
            '-NoProfile',
            '-ExecutionPolicy', 'Bypass',
            '-File', $huntRunner,
            '-Root', $repoRoot,
            '-OutputDirectory', $huntOutputPath,
            '-Mode', $HuntMode,
            '-Count', '1',
            '-TimeoutSeconds', [string]$HuntTimeoutSeconds,
            '-NoElevation'
        )
        & powershell.exe @huntArguments
        if ($LASTEXITCODE -ne 0) {
            throw "CloudFiles live hunt failed with exit code $LASTEXITCODE"
        }

        $huntJson = Join-Path $huntOutputPath (
            'hunt-clean-' +
            $HuntMode.ToLowerInvariant() +
            '-01.json')
        $validatorArguments = @(
            '-NoProfile',
            '-ExecutionPolicy', 'Bypass',
            '-File', $huntValidator,
            '-HuntJson', $huntJson,
            '-Scenario', $Scenario,
            '-ProcessId', [string]$fixtureProcessId,
            '-ImagePath', $fixtureImage
        )
        & powershell.exe @validatorArguments
        if ($LASTEXITCODE -ne 0) {
            throw "CloudFiles hunt evidence validation failed with exit code $LASTEXITCODE"
        }
        Write-Host (
            '[cloudfiles.fixture] hunt_validation=passed json="{0}"' -f
            $huntJson)
    }
    else {
        Write-Host (
            '[cloudfiles.fixture] run elevated !hunt during the hold, or use -ValidateHunt; cleanup is automatic')
    }
    Start-Sleep -Seconds $HoldSeconds
}
catch {
    $operationFailure = $_
}
finally {
    if ($null -ne $fixtureProcess) {
        try {
            if (-not $fixtureProcess.HasExited) {
                Stop-Process -Id $fixtureProcess.Id -Force
                if (-not $fixtureProcess.WaitForExit(5000)) {
                    throw (
                        "fixture process pid=$($fixtureProcess.Id) " +
                        'did not exit within 5 seconds')
                }
            }
            if (-not $fixtureProcess.HasExited) {
                throw (
                    "fixture process pid=$($fixtureProcess.Id) " +
                    'remained active after termination')
            }
        }
        catch {
            Write-Warning "fixture process cleanup failed: $($_.Exception.Message)"
            $cleanupFailed = $true
            $canRemoveFixture = $false
        }
        finally {
            try {
                $fixtureProcess.Dispose()
            }
            catch {
                Write-Warning "fixture process handle cleanup failed: $($_.Exception.Message)"
                $cleanupFailed = $true
            }
            $fixtureProcess = $null
        }
    }

    if ($registered) {
        try {
            $unregisterStatus =
                [KnCloudFilesFixtureNative]::CfUnregisterSyncRoot(
                    $fixtureRoot)
            [KnCloudFilesFixtureNative]::ThrowIfFailed(
                $unregisterStatus,
                'CfUnregisterSyncRoot')
        }
        catch {
            Write-Warning "sync-root cleanup failed: $($_.Exception.Message)"
            $cleanupFailed = $true
            $canRemoveFixture = $false
        }
    }

    if ($rootIdentityPointer -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::FreeHGlobal(
            $rootIdentityPointer)
    }
    if ($fileIdentityPointer -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::FreeHGlobal(
            $fileIdentityPointer)
    }

    $resolvedResearchRoot =
        [IO.Path]::GetFullPath($researchRoot).TrimEnd('\') + '\'
    $resolvedFixtureRoot =
        [IO.Path]::GetFullPath($fixtureRoot)
    if ($resolvedFixtureRoot.StartsWith(
            $resolvedResearchRoot,
            [StringComparison]::OrdinalIgnoreCase) -and
        [IO.Path]::GetFileName($resolvedFixtureRoot).StartsWith(
            'cloudfiles-fixture-',
            [StringComparison]::OrdinalIgnoreCase) -and
        $canRemoveFixture -and
        (Test-Path -LiteralPath $resolvedFixtureRoot)) {
        try {
            Assert-PlainDirectoryTreeForRemoval `
                -Parent $researchRoot `
                -Path $resolvedFixtureRoot `
                -Context 'CloudFiles fixture directory'
            Remove-Item `
                -LiteralPath $resolvedFixtureRoot `
                -Recurse `
                -Force
            if (Test-Path -LiteralPath $resolvedFixtureRoot) {
                throw 'fixture directory remains'
            }
        }
        catch {
            Write-Warning "fixture directory cleanup failed: $($_.Exception.Message)"
            $cleanupFailed = $true
        }
    }
}

if ($null -ne $operationFailure) {
    if ($cleanupFailed) {
        throw (
            "$($operationFailure.Exception.Message); " +
            "CloudFiles fixture cleanup was incomplete; retained path: " +
            $resolvedFixtureRoot)
    }
    throw $operationFailure
}
if ($cleanupFailed) {
    throw "CloudFiles fixture cleanup was incomplete; retained path: $resolvedFixtureRoot"
}

if ($ValidateHunt) {
    $manifest = [ordered]@{
        schema =
            'kn-live-dbg.cloudfiles-fixture-e2e.v1'
        status = 'passed'
        timestamp_utc =
            [DateTime]::UtcNow.ToString('o')
        scenario = $Scenario
        process_id = $fixtureProcessId
        image_path = $fixtureImage
        hunt_mode = $HuntMode
        hunt_json = $huntJson
        cleanup = 'passed'
    }
    $manifest |
        ConvertTo-Json -Depth 4 |
        Set-Content `
            -LiteralPath $resultManifestPath `
            -Encoding UTF8
    Write-Host (
        '[cloudfiles.fixture] passed manifest="{0}" cleanup=passed' -f
        $resultManifestPath)
}
