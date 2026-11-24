param(
    [string]$Executable = 'x64/Release/KnLiveDbg.exe',
    [string]$ObjectDirectory = 'x64/Release/user',
    [string]$OpenSsl,
    [switch]$SystemTrace
)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$product = (Resolve-Path -LiteralPath $Executable).Path
$objects = (Resolve-Path -LiteralPath $ObjectDirectory).Path
. (Join-Path $PSScriptRoot 'msvc-validation-environment.ps1')
$environment = Get-MsvcValidationEnvironment
$trial = Join-Path $repo ('.build\image-loader-window\' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $trial | Out-Null
$fixture = Join-Path $trial 'loader-window-selftest.exe'
$units = @('ProcessImageCapture','ProcessImageSourceReceipt', 'ProcessImageSourceReplay','ImageVerificationRecipe','ImageRecipeReadSet','ImageRecipeJson','ImageProcessMappings',
    'ReferenceArtifact','ImageClaimPublication','ImageScopeClaimPublication','ImageSliceRecipe','ImageScopeClaims',
    'ImageSweepManifest','ImageSweepReplay','ObservationReadRoutingJson','ImageProof','ExecutableImage',
    'ExecutableImageVerifier','AnalystSnapshot','EtlProfile','EtlCaptureStatement','CommandRegistry')
$arguments = @('/nologo','/std:c++17','/EHsc','/W4','/WX','/MT','/O2','/Gy','/DUNICODE','/D_UNICODE','/DWIN32_LEAN_AND_MEAN',
    '/DNOMINMAX',('/I"' + $environment.InstallPath + '\DIA SDK\include"'),
    ('"' + (Join-Path $PSScriptRoot 'image-loader-window-selftest.cpp') + '"'),('/Fo"' + $trial + '\fixture.obj"'),('/Fe"' + $fixture + '"'))
foreach ($name in $units) {
    $object = (Resolve-Path -LiteralPath (Join-Path $objects ($name + '.obj'))).Path
    $arguments += '"' + $object + '"'
}
$arguments += @('/link','/LTCG','/OPT:REF','/INCREMENTAL:NO','advapi32.lib','ole32.lib','crypt32.lib','psapi.lib','wintrust.lib')
$rsp = Join-Path $trial 'fixture.rsp'
$build = Join-Path $trial 'compile.cmd'
$versions = @()
$temporary = @($rsp, $build, (Join-Path $trial 'fixture.obj'))
$commands = @('@echo off',('call "{0}" >nul' -f $environment.VcVarsPath),'if errorlevel 1 exit /b 1',
    ('cl @"{0}"' -f $rsp),'if errorlevel 1 exit /b 1')
if ($OpenSsl) {
    foreach ($revision in 1,2) {
        $stem = Join-Path $trial "owned-version-$revision"
        $versions += "$stem.dll"
        $temporary += @("$stem.obj","$stem.lib","$stem.exp")
        $source = Join-Path $PSScriptRoot 'image-loader-version.cpp'
        $commands += ('cl /nologo /LD /Od /W4 /WX /DKN_FIXTURE_VERSION={0} "{1}" /Fo"{2}.obj" /Fe"{2}.dll" /link /NOENTRY /NODEFAULTLIB /FIXED /DYNAMICBASE:NO /BASE:0x567000000 /IMPLIB:"{2}.lib"' -f $revision,$source,$stem)
        $commands += 'if errorlevel 1 exit /b 1'
    }
}
$compiled = $false
try {
    [IO.File]::WriteAllText($rsp, ($arguments -join ' '), [Text.Encoding]::Unicode)
    $commands | Set-Content -Encoding Ascii -LiteralPath $build
    & $build
    if ($LASTEXITCODE) { throw "Could not build loader fixture ($LASTEXITCODE)" }
    $compiled = $true
}
finally {
    if (!$compiled) { $temporary += $versions }
    foreach ($file in $temporary) {
        if ([IO.File]::Exists($file)) { Remove-Item -LiteralPath $file -ErrorAction Stop }
    }
    if (!(Get-ChildItem -Force -LiteralPath $trial)) { [IO.Directory]::Delete($trial, $false) }
}
$test = Join-Path $PSScriptRoot 'test-image-loader-window.py'
try {
    $signing = @()
    if ($OpenSsl) { $signing = @('--openssl', (Resolve-Path -LiteralPath $OpenSsl).Path, '--boot-reader', $fixture) }
    & $fixture --pair-controls
    if ($LASTEXITCODE) { throw "Pair decision checks failed ($LASTEXITCODE)" }
    & python -B $test --exe $product --private-capturer $fixture --root (Join-Path $trial 'private') @signing
    if ($LASTEXITCODE) { throw "Private collector checks failed ($LASTEXITCODE)" }
    if ($OpenSsl) {
        & python -B $test --exe $product --private-capturer $fixture --root (Join-Path $trial 'replacement') --versions @versions @signing
        if ($LASTEXITCODE) { throw "Same-address DLL replacement checks failed ($LASTEXITCODE)" }
    }
    if ($SystemTrace) {
        & python -B $test --exe $product --root (Join-Path $trial 'system') @signing
        if ($LASTEXITCODE) { throw "System loader trace checks failed ($LASTEXITCODE)" }
    }
}
finally {
    foreach ($dll in $versions) {
        if ([IO.File]::Exists($dll)) { Remove-Item -LiteralPath $dll -ErrorAction Stop }
    }
}
