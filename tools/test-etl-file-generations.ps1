param([Parameter(Mandatory = $true)][string]$Adapter)

# Drive the packet-history state from the packaged assembly. Event times and
# record numbers are synthetic so that missing and overlapping opens are explicit.
$ErrorActionPreference = 'Stop'
$assembly = [Reflection.Assembly]::LoadFrom((Get-Item -LiteralPath $Adapter).FullName)
$rowType = $assembly.GetType('FileOperationContext+FileRow', $true)
$watchType = $assembly.GetType('FileOperationContext+WatchedPacket', $true)
$hidden = [Reflection.BindingFlags]'Instance, NonPublic'

function Test-Generation($Case, [string[]]$Events, [bool]$Conflict) {
    $watch = [Activator]::CreateInstance($watchType, $true)
    $row = [Activator]::CreateInstance($rowType, $true)
    $rowType.GetField('Opcode', $hidden).SetValue($row, 67)
    $rowType.GetField('Start', $hidden).SetValue($row, [long]10)
    $rowType.GetField('Stop', $hidden).SetValue($row, [long]20)
    $rows = $watchType.GetField('Rows', $hidden).GetValue($watch)
    $rows.Add($row)
    $number = 0
    foreach ($event in $Events) {
        $stream, $op, $at = [int[]]($event -split ',')
        $history = $watchType.GetMethod('Stream', $hidden).Invoke($watch, @($stream))
        if ($op -eq 0) {
            $opaque = $history.GetType().GetMethod('ObserveOpaque', $hidden)
            $opaque.Invoke($history, @($number))
            $opaque.Invoke($history, @($number))
        } else {
            $history.GetType().GetMethod('Observe', $hidden).Invoke($history, @($rows, $op, [long]$at, $number))
        }
        ++$number
    }
    if ($rowType.GetField('Conflict', $hidden).GetValue($row) -ne $Conflict -or
        $rowType.GetField('BeginCount', $hidden).GetValue($row) -ne 1 -or
        $rowType.GetField('EndCount', $hidden).GetValue($row) -ne 1) { throw $Case }
}

$pair = @('1,67,10', '1,76,20')
Test-Generation 'previous use completed' (@('1,68,3', '1,76,4') + $pair) $false
Test-Generation 'previous use still open' (@('1,68,3') + $pair) $true
Test-Generation 'other stream cannot close this use' (@('1,68,3', '2,76,4') + $pair) $true
Test-Generation 'previous use on another stream' (@('2,68,3') + $pair) $false
Test-Generation 'unknown earlier use' (@('1,0,3') + $pair) $true
Test-Generation 'unknown use followed by completion' (@('1,0,3', '1,76,4') + $pair) $false
Test-Generation 'prior known and unknown use with one completion' (@('1,68,2', '1,0,3', '1,76,4') + $pair) $true
Test-Generation 'two opaque records with one completion' (@('1,0,2', '1,0,3', '1,76,4') + $pair) $true
Test-Generation 'second start while pending' @('1,67,10', '1,68,15', '1,76,20') $true
