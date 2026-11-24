param(
    [Parameter(Mandatory=$true)][string]$ImageHarness,
    [Parameter(Mandatory=$true)][string]$JournalHarness,
    [Parameter(Mandatory=$true)][string]$Fixtures,
    [string]$Product,
    [ValidateSet('all','harness','product')][string]$Mode = 'all'
)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$harness = (Resolve-Path -LiteralPath $ImageHarness).Path
$journal = (Resolve-Path -LiteralPath $JournalHarness).Path
$data = (Resolve-Path -LiteralPath $Fixtures).Path
if ($Mode -eq 'product' -and !$Product) { throw '-Mode product requires -Product' }
if ($Mode -ne 'product') {
    & python (Join-Path $PSScriptRoot 'test-image-capture-journal.py') --exe $harness --producer $harness --journal-exe $journal --fixtures $data
    if ($LASTEXITCODE -ne 0) { throw 'Direct capture journal harness controls failed' }
}
if ($Product -and $Mode -ne 'harness') {
    $program = (Resolve-Path -LiteralPath $Product).Path
    & python (Join-Path $PSScriptRoot 'test-image-capture-journal.py') --exe $program --producer $harness --journal-exe $journal --fixtures $data --cli
    if ($LASTEXITCODE -ne 0) { throw 'Direct capture journal product controls failed' }
    . (Join-Path $PSScriptRoot 'msvc-validation-environment.ps1')
    $environment = Get-MsvcValidationEnvironment
    $output = Join-Path $repo ('.build\image-capture-journal\run-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $output | Out-Null
    $dll = Join-Path $output 'owned-image-journal.dll'
    $object = Join-Path $output 'probe.obj'
    $source = Join-Path $PSScriptRoot 'owned-image-journal-fixture.cpp'
    $batch = Join-Path $output 'compile.cmd'
    $compile = 'cl /nologo /std:c++17 /EHsc /W4 /WX /O2 /LD "{0}" /Fo:"{1}" /link /NOENTRY /NODEFAULTLIB /DYNAMICBASE /BASE:0x180000000 /NOIMPLIB /NOEXP /OUT:"{2}"' -f $source, $object, $dll
    Set-Content -LiteralPath $batch -Encoding ascii -Value (@('@echo off', ('call "{0}" >nul' -f $environment.VcVarsPath), $compile, 'exit /b %errorlevel%') -join [Environment]::NewLine)
    try {
        & $batch
        if ($LASTEXITCODE -ne 0) { throw 'Owned MEM_IMAGE fixture compilation failed' }
    } finally {
        [IO.File]::Delete($object)
    }
    & python (Join-Path $PSScriptRoot 'test-mapped-image-journal.py') --exe $program --dll $dll --fixtures $output
    if ($LASTEXITCODE -ne 0) { throw 'Owned MEM_IMAGE capture/archive/replay controls failed' }
    Write-Output "[image.capture.journal.validation] mapped_fixtures=$output"
}
