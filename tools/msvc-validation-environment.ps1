function Get-MsvcValidationEnvironment
{
    param([switch]$Sanitize)

    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    $candidates = [Collections.Generic.List[string]]::new()
    if (Test-Path -LiteralPath $vswhere)
    {
        $components = @('Microsoft.VisualStudio.Component.VC.Tools.x86.x64')
        if ($Sanitize)
        {
            $components += 'Microsoft.VisualStudio.Component.VC.ASAN'
        }
        $installations = & $vswhere -products '*' -requires $components -sort -property installationPath
        if ($LASTEXITCODE -ne 0)
        {
            throw "Visual Studio discovery failed: $LASTEXITCODE"
        }
        foreach ($installation in $installations)
        {
            if (-not [string]::IsNullOrWhiteSpace($installation))
            {
                $candidates.Add($installation.Trim())
            }
        }
    }

    foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)}))
    {
        if ([string]::IsNullOrWhiteSpace($root))
        {
            continue
        }
        $fallbacks = @(Get-Item (Join-Path $root 'Microsoft Visual Studio\*\*\VC\Auxiliary\Build\vcvars64.bat') `
            -ErrorAction SilentlyContinue | Sort-Object FullName -Descending)
        foreach ($fallback in $fallbacks)
        {
            $candidates.Add((Split-Path (Split-Path (Split-Path (Split-Path $fallback.FullName)))))
        }
    }

    foreach ($installation in $candidates)
    {
        $vcvars = Join-Path $installation 'VC\Auxiliary\Build\vcvars64.bat'
        if (-not (Test-Path -LiteralPath $vcvars))
        {
            continue
        }
        $runtime = $null
        if ($Sanitize)
        {
            $versionPath = Join-Path $installation 'VC\Auxiliary\Build\Microsoft.VCToolsVersion.default.txt'
            if (-not (Test-Path -LiteralPath $versionPath))
            {
                continue
            }
            $version = (Get-Content -LiteralPath $versionPath -Raw).Trim()
            $runtime = Join-Path $installation "VC\Tools\MSVC\$version\bin\Hostx64\x64\clang_rt.asan_dynamic-x86_64.dll"
            if (-not (Test-Path -LiteralPath $runtime -PathType Leaf))
            {
                continue
            }
        }
        return [PSCustomObject]@{
            InstallPath = $installation
            VcVarsPath = $vcvars
            AsanRuntimePath = $runtime
        }
    }

    if ($Sanitize)
    {
        throw 'Visual C++ x64 tools with the matching AddressSanitizer runtime were not found'
    }
    throw 'Visual C++ x64 build tools were not found'
}
