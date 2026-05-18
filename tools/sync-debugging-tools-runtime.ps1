param(
    [string[]]$SearchRoots = @(
        "C:\Program Files (x86)\Windows Kits",
        "C:\Program Files\Windows Kits",
        "C:\Windows\System32",
        "C:\Windows\SysWOW64"
    )
)

$ErrorActionPreference = "Stop"

$repo = Resolve-Path (Join-Path $PSScriptRoot "..")
$destinationDir = Join-Path $repo "vendor\debugging-tools\x64"
$runtimeFiles = @(
    "dbghelp.dll",
    "dbgeng.dll",
    "dbgcore.dll",
    "msdia140.dll",
    "symsrv.dll",
    "srcsrv.dll",
    "symsrv.yes"
)

$diaSearchDirs = @(
    "C:\Program Files\Microsoft Visual Studio\2022\Professional\DIA SDK\bin\amd64",
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\DIA SDK\bin\amd64",
    "C:\Program Files\Microsoft Visual Studio\2022\Community\DIA SDK\bin\amd64",
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\DIA SDK\bin\amd64",
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\DIA SDK\bin\amd64",
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\DIA SDK\bin\amd64"
)

function Get-VersionValue
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $result = [version]"0.0.0.0"

    do
    {
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
        $versionText = $item.VersionInfo.ProductVersion
        if ([string]::IsNullOrWhiteSpace($versionText))
        {
            break
        }

        $versionText = ($versionText -replace " .*", "")
        [version]$parsed = $null
        if ([version]::TryParse($versionText, [ref]$parsed))
        {
            $result = $parsed
        }
    } while ($false)

    return $result
}

function Get-ArchitectureScore
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $score = 0
    $lower = $Path.ToLowerInvariant()

    if ($lower.Contains("\debuggers\x64"))
    {
        $score = 100
    }
    elseif ($lower.Contains("\x64") -or $lower.Contains("\amd64"))
    {
        $score = 50
    }
    elseif ($lower.Contains("\system32"))
    {
        $score = 25
    }

    return $score
}

function New-Manifest
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourceDir,
        [Parameter(Mandatory = $true)]
        [string]$Destination
    )

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("# Debugging Tools x64 Runtime Manifest")
    $lines.Add("")
    $lines.Add("Source directory:")
    $lines.Add("")
    $lines.Add('```text')
    $lines.Add($SourceDir)
    $lines.Add('```')
    $lines.Add("")
    $lines.Add("Selected reason:")
    $lines.Add("")
    $lines.Add('```text')
    $lines.Add("Latest complete x64-compatible Debugging Tools runtime set found by tools\sync-debugging-tools-runtime.ps1.")
    $lines.Add("The selection requires dbghelp.dll and symsrv.dll in the same directory and prefers x64 Debuggers paths.")
    $lines.Add("If symsrv.yes is missing from the selected source, the script creates a one-byte consent marker.")
    $lines.Add("msdia140.dll is selected separately from the newest installed Visual Studio DIA SDK x64 path.")
    $lines.Add('```')
    $lines.Add("")
    $lines.Add("Runtime files:")
    $lines.Add("")
    $lines.Add("| File | Product version | Size | SHA-256 |")
    $lines.Add("| --- | --- | ---: | --- |")

    foreach ($name in ($runtimeFiles | Sort-Object))
    {
        $path = Join-Path $Destination $name
        if (-not (Test-Path $path))
        {
            continue
        }

        $item = Get-Item -LiteralPath $path
        $versionText = "n/a"
        if ($item.Extension -eq ".dll" -and -not [string]::IsNullOrWhiteSpace($item.VersionInfo.ProductVersion))
        {
            $versionText = $item.VersionInfo.ProductVersion -replace " .*", ""
        }

        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash
        $lines.Add("| ``$name`` | ``$versionText`` | $($item.Length) | ``$hash`` |")
    }

    $manifestPath = Join-Path $Destination "MANIFEST.md"
    Set-Content -LiteralPath $manifestPath -Value $lines -Encoding ascii
}

$existingRoots = @()
foreach ($root in $SearchRoots)
{
    if (-not [string]::IsNullOrWhiteSpace($root) -and (Test-Path $root))
    {
        $existingRoots += $root
    }
}

if ($existingRoots.Count -eq 0)
{
    throw "No search roots exist"
}

$candidates = @()
$dbghelpFiles = Get-ChildItem -LiteralPath $existingRoots -Recurse -Filter dbghelp.dll -ErrorAction SilentlyContinue
foreach ($dbghelp in $dbghelpFiles)
{
    $directory = $dbghelp.DirectoryName
    $symsrv = Join-Path $directory "symsrv.dll"
    if (-not (Test-Path $symsrv))
    {
        continue
    }

    $candidates += [pscustomobject]@{
        Directory = $directory
        Version = Get-VersionValue -Path $dbghelp.FullName
        ArchitectureScore = Get-ArchitectureScore -Path $directory
        LastWriteTime = $dbghelp.LastWriteTime
    }
}

if ($candidates.Count -eq 0)
{
    throw "No complete dbghelp.dll + symsrv.dll runtime set was found"
}

$selected = $candidates |
    Sort-Object Version, ArchitectureScore, LastWriteTime -Descending |
    Select-Object -First 1

New-Item -ItemType Directory -Force -Path $destinationDir | Out-Null

foreach ($name in $runtimeFiles)
{
    if ($name -eq "msdia140.dll")
    {
        continue
    }

    $source = Join-Path $selected.Directory $name
    if (-not (Test-Path $source))
    {
        if ($name -eq "symsrv.yes")
        {
            [System.IO.File]::WriteAllBytes((Join-Path $destinationDir $name), [byte[]](0x20))
            Write-Host "Vendor runtime: created $name"
            continue
        }

        Write-Warning "Runtime file was not found in selected source: $source"
        continue
    }

    Copy-Item -LiteralPath $source -Destination (Join-Path $destinationDir $name) -Force
    Write-Host "Vendor runtime: copied $name"
}

$diaCandidates = @()
foreach ($dir in $diaSearchDirs)
{
    $path = Join-Path $dir "msdia140.dll"
    if (Test-Path $path)
    {
        $diaCandidates += [pscustomobject]@{
            Path = $path
            Version = Get-VersionValue -Path $path
            LastWriteTime = (Get-Item -LiteralPath $path).LastWriteTime
        }
    }
}

if ($diaCandidates.Count -gt 0)
{
    $dia = $diaCandidates |
        Sort-Object Version, LastWriteTime -Descending |
        Select-Object -First 1
    Copy-Item -LiteralPath $dia.Path -Destination (Join-Path $destinationDir "msdia140.dll") -Force
    Write-Host "Vendor runtime: copied msdia140.dll"
}
else
{
    Write-Warning "msdia140.dll was not found in known Visual Studio DIA SDK x64 paths"
}

$destinationSymsrv = Join-Path $destinationDir "symsrv.dll"
$destinationConsent = Join-Path $destinationDir "symsrv.yes"
if ((Test-Path $destinationSymsrv) -and -not (Test-Path $destinationConsent))
{
    [System.IO.File]::WriteAllBytes($destinationConsent, [byte[]](0x20))
    Write-Host "Vendor runtime: created symsrv.yes"
}

New-Manifest -SourceDir $selected.Directory -Destination $destinationDir

Write-Host "Vendor runtime source: $($selected.Directory)"
Write-Host "Vendor runtime version: $($selected.Version)"
