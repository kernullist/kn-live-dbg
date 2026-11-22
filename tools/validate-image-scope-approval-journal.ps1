param(
    [Parameter(Mandatory=$true)][string]$ImageHarness,
    [Parameter(Mandatory=$true)][string]$JournalHarness,
    [Parameter(Mandatory=$true)][string]$ScopeFixtures,
    [string]$Product,
    [ValidateSet('all','harness','product')][string]$Mode = 'all'
)
$ErrorActionPreference = 'Stop'
$harness = (Resolve-Path -LiteralPath $ImageHarness).Path
$journal = (Resolve-Path -LiteralPath $JournalHarness).Path
$fixtures = (Resolve-Path -LiteralPath $ScopeFixtures).Path
if ($Mode -eq 'product' -and !$Product) { throw '-Mode product requires -Product' }
if ($Mode -ne 'product') {
    & python (Join-Path $PSScriptRoot 'test-image-scope-approval-journal.py') --exe $harness --producer $harness --journal-exe $journal --fixtures $fixtures
    if ($LASTEXITCODE -ne 0) { throw 'Scoped approval journal harness controls failed' }
    & python (Join-Path $PSScriptRoot 'test-image-archive-dependencies.py') --journal-exe $journal --fixtures $fixtures
    if ($LASTEXITCODE -ne 0) { throw 'Image dependency retention harness controls failed' }
}
if ($Product -and $Mode -ne 'harness') {
    $program = (Resolve-Path -LiteralPath $Product).Path
    & python (Join-Path $PSScriptRoot 'test-image-scope-approval-journal.py') --exe $program --producer $harness --journal-exe $journal --fixtures $fixtures --cli
    if ($LASTEXITCODE -ne 0) { throw 'Scoped approval journal product controls failed' }
    & python (Join-Path $PSScriptRoot 'test-image-archive-dependencies.py') --journal-exe $journal --fixtures $fixtures --product $program
    if ($LASTEXITCODE -ne 0) { throw 'Image dependency retention product controls failed' }
}
