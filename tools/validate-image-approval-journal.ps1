param(
    [Parameter(Mandatory=$true)][string]$ImageHarness,
    [Parameter(Mandatory=$true)][string]$JournalHarness,
    [Parameter(Mandatory=$true)][string]$Fixtures,
    [string]$Product,
    [ValidateSet('all','harness','product')][string]$Mode = 'all'
)
$ErrorActionPreference = 'Stop'
$harness = (Resolve-Path -LiteralPath $ImageHarness).Path
$journal = (Resolve-Path -LiteralPath $JournalHarness).Path
$data = (Resolve-Path -LiteralPath $Fixtures).Path
if ($Mode -eq 'product' -and !$Product) { throw '-Mode product requires -Product' }
if ($Mode -ne 'product') {
    & python (Join-Path $PSScriptRoot 'test-image-approval-journal.py') --exe $harness --producer $harness --journal-exe $journal --fixtures $data
    if ($LASTEXITCODE -ne 0) { throw 'Image approval journal harness controls failed' }
}
if ($Product -and $Mode -ne 'harness') {
    $program = (Resolve-Path -LiteralPath $Product).Path
    & python (Join-Path $PSScriptRoot 'test-image-approval-journal.py') --exe $program --producer $harness --journal-exe $journal --fixtures $data --cli
    if ($LASTEXITCODE -ne 0) { throw 'Image approval journal product controls failed' }
}
