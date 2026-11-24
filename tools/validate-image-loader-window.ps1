param(
    [string]$Executable = 'x64/Release/KnLiveDbg.exe',
    [string]$ObjectDirectory = 'x64/Release/user',
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
$units = @('ProcessImageCapture','ImageVerificationRecipe','ImageRecipeReadSet','ImageRecipeJson','ImageProcessMappings',
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
try {
    [IO.File]::WriteAllText($rsp, ($arguments -join ' '), [Text.Encoding]::Unicode)
    @('@echo off',('call "{0}" >nul' -f $environment.VcVarsPath),('cl @"{0}"' -f $rsp)) | Set-Content -Encoding Ascii -LiteralPath $build
    & $build
    if ($LASTEXITCODE) { throw "Could not build loader fixture ($LASTEXITCODE)" }
}
finally {
    foreach ($file in @($rsp, $build, (Join-Path $trial 'fixture.obj'))) {
        if ([IO.File]::Exists($file)) { Remove-Item -LiteralPath $file -ErrorAction Stop }
    }
    if (!(Get-ChildItem -Force -LiteralPath $trial)) { [IO.Directory]::Delete($trial, $false) }
}
$test = Join-Path $PSScriptRoot 'test-image-loader-window.py'
& python -B $test --exe $product --private-capturer $fixture --root (Join-Path $trial 'private')
if ($LASTEXITCODE) { throw "Private collector checks failed ($LASTEXITCODE)" }
if ($SystemTrace) {
    & python -B $test --exe $product --root (Join-Path $trial 'system')
    if ($LASTEXITCODE) { throw "System loader trace checks failed ($LASTEXITCODE)" }
}
