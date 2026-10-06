$ErrorActionPreference = "Stop"

if ($null -eq ("KnOwnedProcess.Native" -as [type]))
{
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace KnOwnedProcess
{
    public static class Native
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint WaitForSingleObject(SafeProcessHandle process, uint milliseconds);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetExitCodeProcess(SafeProcessHandle process, out uint exitCode);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool TerminateProcess(SafeProcessHandle process, uint exitCode);
    }
}
'@
}

function Wait-KnOwnedProcessExit
{
    param(
        [Parameter(Mandatory = $true)]
        [Microsoft.Win32.SafeHandles.SafeProcessHandle]$Handle,
        [Parameter(Mandatory = $true)]
        [uint32]$TimeoutMilliseconds
    )
    # Use the handle retained at creation; Process.WaitForExit can reopen after PPL.
    $result = [KnOwnedProcess.Native]::WaitForSingleObject($Handle, $TimeoutMilliseconds)
    if ($result -eq 0)
    {
        return $true
    }
    if ($result -eq 258)
    {
        return $false
    }
    throw [ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error())
}

function Get-KnOwnedProcessExitCode
{
    param(
        [Parameter(Mandatory = $true)]
        [Microsoft.Win32.SafeHandles.SafeProcessHandle]$Handle
    )
    if (-not (Wait-KnOwnedProcessExit $Handle 0))
    {
        throw "owned process is still active"
    }
    [uint32]$code = 0
    if (-not [KnOwnedProcess.Native]::GetExitCodeProcess($Handle, [ref]$code))
    {
        throw [ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error())
    }
    return [BitConverter]::ToInt32([BitConverter]::GetBytes($code), 0)
}

function Stop-KnOwnedProcess
{
    param(
        [Parameter(Mandatory = $true)]
        [Microsoft.Win32.SafeHandles.SafeProcessHandle]$Handle
    )
    if (-not [KnOwnedProcess.Native]::TerminateProcess($Handle, 1))
    {
        throw [ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error())
    }
}
