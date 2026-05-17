# Kn Live Dbg

Kn Live Dbg is a Windows kernel live-debugging experiment shaped after the useful part of LiveKD: the kernel driver exposes narrow memory primitives, while the user-mode console owns service lifecycle, symbol loading, type interpretation, and operator UX.

## Shape

```text
kn-live-dbg/
  shared/KnLiveDbgIoctl.h       stable user/kernel ABI
  driver/Driver.cpp             WDM driver with virtual/physical memory IOCTLs
  user/*.cpp                    elevated TUI, SCM lifecycle, DbgHelp symbols
  tools/build.ps1               Release/Debug x64 build helper
```

## Current Capabilities

1. Installs or updates, starts, stops, waits on, and deletes `KnLiveDbg.sys` through SCM.
2. Creates `\\.\KnLiveDbg` with an Administrators/SYSTEM-only device DACL and validates ABI version.
3. Reads kernel virtual memory through `MmCopyMemory`.
4. Translates virtual addresses to physical addresses through an x64 page-table walk.
5. Reads physical memory through `MmCopyMemory`.
6. Writes physical memory with per-handle write mode enabled by default.
7. Writes kernel virtual memory with per-handle write mode enabled by default.
8. Enumerates loaded kernel modules with `NtQuerySystemInformation`.
9. Loads kernel symbols with `DbgHelp` using `SRV*C:\Symbols*https://msdl.microsoft.com/download/symbols`.
10. Provides a WinDbg-compatible command registry for the official base command list.
11. Implements native live-memory support for memory, symbol, module, type, compare, fill, move, search, and explicit disassembly commands.
12. Routes stop-state, parser-heavy, extension, and meta commands through the DbgEng backend.
13. Provides an optional DbgEng backend for raw WinDbg command execution against the local kernel target.
14. Parses kernel PDB types to enumerate object-manager filters, registry callbacks, process creation callbacks, and minifilter callbacks with function/module/context annotations.

## Build

Requirements:

1. Visual Studio 2022.
2. Windows Driver Kit 10.0.26100.0.
3. x64 developer shell or normal PowerShell with MSBuild at the default VS Professional path.

Build:

```powershell
.\tools\build.ps1 -Configuration Release
```

The driver project uses WDK `TestSign` for Debug and Release x64 builds. The build helper now verifies that `KnLiveDbg.sys` has an Authenticode signer and prints the signature status/thumbprint after MSBuild completes.

Expected outputs:

```text
x64\Release\KnLiveDbg.exe
x64\Release\KnLiveDbg.sys
```

## Run

Run from an elevated console:

```powershell
cd .\x64\Release
.\KnLiveDbg.exe
```

The EXE expects `KnLiveDbg.sys` beside it. It resolves the absolute driver path, updates an existing service config when present, creates the service when missing, starts it, and waits for `SERVICE_RUNNING`. `quit` leaves the service loaded. Use `unload` to close the device handle, stop the driver, delete the service, and wait for deletion before exit. Use `drvstatus` to inspect the current SCM state.

## TUI Commands

```text
help
help all
backend [auto|native|dbgeng]
kdinit [connect-options]
kd <windbg-command>
kddetach
version
drvstatus
.sympath [path]
.sympath+ <path>
.reload
lm [filter]
x <module!mask>
ln <symbol|address>
addr <symbol|address>
query <address|symbol> [length]
vtop <address|symbol> [length]
vtop /cr3 <directory-table-base> <address|symbol> [length]
!vtop <address|symbol> [length]
!vtop <directory-table-base> <address|symbol> [length]
d, da, db, dc, dd, dD, df, dp, dq, du, dw, dW, dyb, dyd
dda, ddp, ddu, dpa, dpp, dpu, dqa, dqp, dqu
dds, dps, dqs
phys, pdb, pdw, pdd, pdq
u <address|symbol> [instruction-count]
uf <address|symbol>
dt [-rN] [-v] [-b] <type> [address|symbol] [field-filter...]
dtx [-rN] [-v] [-b] <type> [address|symbol] [field-filter...]
callbacks [all|ob|registry|process|minifilter]
kcallbacks [all|ob|registry|process|minifilter]
cb [all|ob|registry|process|minifilter]
c <address1> <address2> <length>
s [-b|-w|-d|-q] <address> <length> <value...>
f <address> <length> <byte-pattern...>
m <source> <destination> <length>
write on|off
e, ea, eb, ed, eD, ef, ep, eq, eu, ew, eza, ezu
peb, pew, ped, peq
setfield <type> <address|symbol> <field> <value>
unload
q, qq, qd, quit, exit
```

Example:

```text
knkd> reload
knkd> lm nt
knkd> x nt!*Process*
knkd> ln nt!PsLoadedModuleList
knkd> u nt!KiSystemCall64 8
knkd> uf nt!KiSystemCall64
knkd> dq nt!PsLoadedModuleList 4
knkd> vtop nt!PsLoadedModuleList
knkd> pdb <physical-address> 80
knkd> dt nt!_EPROCESS
knkd> dt -r1 nt!_EPROCESS <address> UniqueProcessId ActiveProcessLinks
knkd> callbacks all
knkd> callbacks ob
knkd> callbacks minifilter
```

The registry also knows the standard execution, breakpoint, stack, register, source, exception, I/O port, and script commands. Native live-memory commands stay on the custom driver backend, while stop-state or parser-heavy commands are routed to DbgEng in `auto` or `dbgeng` mode.

`u` and `uf` are explicit disassembly commands. `u` resolves an address or symbol, disassembles a bounded instruction count, and remembers the next offset for a following bare `u`; `uf` uses the DbgEng function disassembler for function-boundary-aware output.

## DbgEng Backend

The default backend mode is `auto`:

1. Native memory/symbol/type commands run through the custom driver and `DbgHelp`.
2. Stop-state WinDbg commands, parser-heavy commands, `!extension` commands, and unknown `.meta` commands are routed to DbgEng after `kdinit` or lazy DbgEng initialization.
3. `backend dbgeng` sends commands directly to `IDebugControl::ExecuteWide`.
4. `backend native` disables automatic DbgEng routing.

Examples:

```text
knkd> kdinit
knkd> !process 0 0
knkd> backend dbgeng
knkd> k
knkd> backend auto
knkd> kddetach
```

DbgEng uses `IDebugClient5::AttachKernelWide(DEBUG_ATTACH_LOCAL_KERNEL, ...)`. It still follows the limits of Windows local kernel debugging; not every KD command has the same behavior as a remote break-in session.

## Native `dt`

Native `dt` now supports both type layout and value display:

```text
dt nt!_EPROCESS
dt nt!_EPROCESS <address>
dt -r1 nt!_EPROCESS <address>
dt -v nt!_EPROCESS <address> UniqueProcessId
```

Supported options:

- `-r` or `-rN`: recursively expand nested UDT fields up to the requested depth.
- `-v`: print internal symbol tag/type id/length diagnostics.
- `-b`: bare output, omitting type names.

Field filters are case-insensitive substring filters applied to field names and type names.

## Kernel Callback Scanner

`callbacks` walks live kernel callback lists using kernel PDB type layouts and the native memory reader:

```text
callbacks all
callbacks ob
callbacks registry
callbacks process
callbacks minifilter
```

The scanner currently covers:

1. Object-manager filters from `_OBJECT_TYPE.CallbackList`. The scanner first discovers `_OBJECT_TYPE` objects through `ObTypeIndexTable` and `_OBJECT_TYPE.Name`, then falls back to `PsProcessType`, `PsThreadType`, and `ExDesktopObjectType` when the table is unavailable.
2. Registry callbacks by enumerating and validating registry callback list-head candidates such as `CmpCallbackListHead`, then walking `_CM_CALLBACK_CONTEXT_BLOCK` entries.
3. Process creation callbacks by enumerating and validating create-process notify routine table candidates such as `PspCreateProcessNotifyRoutine`, then decoding `_EX_CALLBACK_ROUTINE_BLOCK` entries.
4. Minifilter callbacks by discovering `fltmgr!FltGlobals`, validating the frame-list root, walking `FrameList`, each `_FLTP_FRAME.RegisteredFilters`, and each `_FLT_FILTER.Operations` registration array.

Each record prints the discovered root address and source, callback function address, nearest symbol, owning module, object type address and discovery source for object callbacks, minifilter name/altitude/frame/driver object when present, callback/list block addresses, altitude when present, and registration/context pointer. Minifilter output includes operation callbacks, filter unload, instance setup/teardown, name provider, KTM, section, and volume-mount routines when the target build exposes those fields. Context pointers are also annotated with a module and nearest symbol when they point into a loaded kernel image. The implementation is intentionally PDB-driven; if a private structure field is renamed on a target build, the command reports a warning instead of guessing offsets.

## Virtual-To-Physical And Physical Memory

Native physical memory support is intentionally explicit:

```text
vtop nt!PsLoadedModuleList
vtop /cr3 <directory-table-base> <virtual-address> 100
!vtop <virtual-address>
!vtop <directory-table-base> <virtual-address>
pdb <physical-address> 80
pdq <physical-address> 10
write off
peq <physical-address> <qword-value>
```

`vtop` uses the current CR3 when no directory-table base is supplied. The driver walks x64 4-level paging structures through physical reads, reports the PML4E/PDPTE/PDE/PTE chain, handles 4 KB, 2 MB, and 1 GB pages, and returns the number of contiguous bytes remaining in the translated page. Physical writes are routed through page-sized `MmMapIoSpaceEx` mappings. Write mode is enabled by default for each device handle; use `write off` when you want a read-only console session.

## Operational Caveats

1. This is a live kernel memory tool. Bad writes can crash or corrupt the machine.
2. `MmCopyMemory` makes reads fault-tolerant, but it does not make all addresses meaningful.
3. Writes are enabled by default, can be disabled with `write off`, and still require an IOCTL acknowledgment magic.
4. Native VA-to-PA translation currently assumes x64 4-level paging and the supplied or current CR3.
5. Physical memory writes can corrupt page tables, code, pool, device memory, or firmware-owned ranges.
6. Type dumping depends on matching PDBs and the local `DbgHelp` behavior.
7. Callback enumeration depends on internal kernel symbols and type names. Field drift is reported as a warning; Filter Manager callback decoding depends on matching `fltmgr` private type layouts.
8. Do not hard-code kernel structure offsets for production use; resolve them from symbols at runtime.
9. Live loading requires test-signing or another valid code integrity path.
10. Native mode intentionally differs from full WinDbg for commands that stop or control the target. Use `backend dbgeng` for DbgEng-backed command execution, and still expect local-kernel debugging limitations.
