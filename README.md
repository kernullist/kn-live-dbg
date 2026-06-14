# Kn-Live-Dbg

Kn-Live-Dbg is a Windows kernel live-debugging experiment shaped after the useful part of LiveKD: the kernel driver exposes narrow memory primitives, while the user-mode console owns service lifecycle, symbol loading, type interpretation, and operator UX.

## Demo

https://github.com/user-attachments/assets/f3542a85-c960-46f2-a151-fdd23a8294a6

If the embedded video does not render, open the [README-sized demo](demo/kn-live-dbg-demo-readme.mp4) or the [full-resolution demo](demo/kn-live-dbg-demo.mp4).

### AI Command Demo

<video src="demo/kn-live-dbg-demo-ai.mp4" controls muted playsinline width="100%"></video>

If the AI command demo does not render inline, open [demo/kn-live-dbg-demo-ai.mp4](demo/kn-live-dbg-demo-ai.mp4).

## Scope and Signing Notice

This tool is built for defensive Windows security research, anti-cheat research, driver diagnostics, and controlled lab analysis. It is not designed to bypass Windows Code Integrity and does not include Code Integrity bypass functionality. To load the driver, use Windows test-signing mode with the test-signed build, or sign the driver with an appropriate production certificate such as an EV code-signing certificate for real deployment environments.

## Shape

```text
kn-live-dbg/
  shared/KnLiveDbgIoctl.h       stable user/kernel ABI
  shared/KnLiveDbgProbeIoctl.h  positive-control probe ABI
  driver/Driver.cpp             WDM driver with virtual/physical memory IOCTLs
  probe_driver/ProbeDriver.cpp  WDM positive-control test buffer driver
  user/*.cpp                    elevated TUI, SCM lifecycle, DbgHelp symbols
  tools/build.ps1               Release/Debug x64 build helper
  tools/release.ps1             build and zip release package helper
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
9. Loads kernel symbols with `DbgHelp`; the EXE directory and its non-cache subdirectories are searched first, followed by `SRV*<exe-dir>\symbols*https://msdl.microsoft.com/download/symbols`, and the `nt` kernel PDB is downloaded/loaded into that EXE-local cache during startup by default.
10. Provides a WinDbg-compatible command registry for the official base command list.
11. Implements native live-memory support for memory, symbol, module, type, compare, fill, move, search, and explicit disassembly commands.
12. Routes stop-state, parser-heavy, extension, and meta commands through the DbgEng backend.
13. Provides an optional DbgEng backend for raw WinDbg command execution against the local kernel target.
14. Parses kernel PDB types to enumerate object-manager filters, registry callbacks, process/thread/image-load callbacks, and minifilter callbacks with function/module/context annotations.
15. Provides an initial AI assistant provider layer for advisory command planning and result interpretation through Codex CLI, ChatGPT/Codex OAuth, DeepSeek, and OpenRouter.
16. Enforces a single-controller device owner and exposes owner/write-mode state through `drvstatus`.
17. Resolves process DTBs from `_EPROCESS.Pcb.DirectoryTableBase` and optional `UserDirectoryTableBase` for process-aware `vtop`, `d*`, and `e*` commands; native `e*` writes default to the System process context (`pid 4`).
18. Detects active LA57 paging and reports whether translation used PML4 or PML5, including the physical address of each page-table entry that was walked.
19. Supports DbgEng local-kernel and remote-kernel attach modes through `kdinit /local` and `kdinit /remote`.
20. Falls back to DIA SDK type parsing when `DbgHelp` cannot provide enough UDT/field metadata.
21. Builds and manages `KnLiveDbgProbe.sys`, a positive-control test driver with known virtual/physical buffer addresses and a test firmware table provider registration.
22. Enumerates Windows Filtering Platform providers, sublayers, callouts, filters, and layers natively through the user-mode Base Filtering Engine (`fwpuclnt.dll`) with `!wfp`, including layer/provider/sublayer name resolution and decoded action/flag mnemonics.
23. Enumerates ALPC ports natively from live kernel memory with `!alpc`, recursively walking the Object Manager namespace from `nt!ObpRootDirectoryObject`, following `_ALPC_PORT.CommunicationInfo` to discover paired server/client ports, counting queue depths from `MainQueue`/`PendingQueue`/`LargeMessageQueue`/`CanceledQueue`/`WaitQueue`, and grouping records by `ConnectionPort` into client/server families.
24. Reports VBS, HVCI, Secure Kernel, and IUM trustlet status with `!vbs`, `!ci`, and `!securekernel` — decoding `nt!g_CiOptions` flag bits, reading `nt!HvlpVsmVtlCallVa` for VBS active state, scanning `PsLoadedModuleList` for `securekernel.exe`/`skci.dll`, querying CPUID leaves `0x40000000`/`0x40000006` for hypervisor identification, and walking `PsActiveProcessHead` with `_KPROCESS.SecureState` (or known trustlet image-name prefixes when the field is unavailable) for the trustlet list.
25. Detects InfinityHook-style ETW logger tampering with `!etw` and walks the registered NMI handler chain with `!nmi` — reading `nt!EtwpDebuggerData`'s 64 `WMI_LOGGER_CONTEXT*` slots for logger name and GetCpuClock annotation, walking `nt!KiNmiCallbackListHead` through the `KNMI_HANDLER_CALLBACK` singly-linked list, and flagging any callback or GetCpuClock target outside the loaded kernel modules.
26. Enumerates registered firmware table providers with `!fwtable` -- passively walking `nt!ExpFirmwareTableProviderListHead`, decoding `SYSTEM_FIRMWARE_TABLE_HANDLER`-style provider nodes, annotating ProviderSignature, handler module/symbol, and DriverObject owner/name/start/size, and flagging custom signatures, duplicate signatures, corrupt links, non-image handlers, unresolved DriverObject module ownership, and handler/DriverObject owner mismatches without invoking firmware handlers.
27. Checks live module and driver-object integrity with `!module integrity` and `!driver integrity` -- reading live PE headers/sections for loaded modules, validating PE/section invariants with reason codes, flagging static/effective W+X evidence or live SizeOfImage drift, walking `\Driver` objects through Object Manager metadata, and annotating `DRIVER_OBJECT.MajorFunction[]` dispatch targets with module/symbol ownership.
28. Scans loaded kernel modules for BYOVD risk with `byovd` / `!byovd` -- maintaining a local catalog from the Microsoft vulnerable driver blocklist plus LOLDrivers hash/YARA feeds, auto-refreshing it when older than 24 hours, hashing loaded module images on disk, optionally running LOLDrivers YARA rules through an operator-supplied `yara64.exe` / `yara.exe`, and reporting exact hash/YARA matches as `HIGH` confidence plus Microsoft file-name/version blocklist hints as `MEDIUM` confidence. A benign no-op fixture driver (`amdryzenmasterdriver.sys`) can be loaded with `byovd fixture load` to exercise the Microsoft name/version positive-control path without shipping an actual vulnerable driver.
29. Enumerates the kernel big pool with `!pool big` / `!pool find` / `!pool summary` -- snapshotting `nt!PoolBigPageTable` through `NtQuerySystemInformation(SystemBigPoolInformation=0x42)`, filtering by 4-character tag (`/tag`), size band (`/min`/`/max`), containing virtual address (`/addr`), W+X page attributes (`/wx`), or paged/non-paged class, and optionally walking the PML5/PML4/PDPT/PD/PT hierarchy via the driver's `TranslateVirtual` IOCTL with `/annotate` to surface effective R/W/X permissions and `[W+X]` non-paged allocations as BYOVD/payload-staging signals.
30. Captures same-boot session baselines with `!snapshot` and compares them with `!diff` -- keeping the baseline in memory, auto-writing JSON plus Markdown under `.kn-live-dbg`, focusing diff output on records that were absent from the baseline but present later, scanning VAD DKOM hidden-PTE evidence for every newly observed live process, and ordering pool findings so pool-PE suspects, pool-PE hits, W+X NonPaged allocations, and large NonPaged allocations surface first.
31. Dumps kernel memory to file with `dump-raw <address> <length> <path> [/zerofill]` -- chunked 256 KB reads through the driver IOCTL with optional zero-fill on per-chunk failure -- and reconstructs on-disk PE images from running drivers/`ntoskrnl` with `dump-pe <address> <path>`, which parses the in-memory `IMAGE_DOS_HEADER`/`IMAGE_NT_HEADERS` (PE32 and PE32+), copies each section's `SizeOfRawData` bytes from `address + VirtualAddress` to file offset `PointerToRawData`, and zero-fills sections whose reads fail (discarded INIT, paged-out sections) so the dump remains valid for IDA/Ghidra inspection of relocations-applied, IAT-resolved, in-place-patched live images.
32. Hunts PE images stashed in big pool with `pool-scan-pe` -- enumerates big pool entries via `NtQuerySystemInformation(SystemBigPoolInformation)` and runs the same plausibility-gated NT header detector used by `dump-pe` on each entry's first 4 KB, surfacing reflective-loaded modules, unpacker stages, and stomped driver replacements even when the operator has stripped `MZ` / `PE\0\0` / `e_lfanew` to evade signature scanners. Hits are tagged with `WIPED=[MZ,e_lfanew,PE]` markers and can be dumped to disk in one shot via `/dump <directory>` (reusing the dump-pe section walker + signature recovery).
33. Introspects a single virtual address with `!address <va>` -- reports canonicality, kernel vs user half, the live page-table walk (PML5/PML4/PDPTE/PDE/PTE values and addresses), effective R/W/X/U permissions ANDed across every traversed level, large-page detection, the resulting physical address and page offset, and the owning kernel module + nearest symbol. Auto-detects LA57 paging from the driver TranslateVirtual response and adjusts the kernel/user half-space split accordingly.
34. Elevates KnLiveDbg.exe to PPL Antimalware with `set-ppl-antimalware [on|off|status]` -- the driver writes `0x31` (PS_PROTECTION: PPL/Antimalware) into the calling process's `_EPROCESS.Protection` byte. Required prerequisite for subscribing to the Microsoft-Windows-Threat-Intelligence ETW provider, which gates events on the consumer being PPL Antimalware.
35. Subscribes to the Microsoft-Windows-Threat-Intelligence ETW provider with `!ti start [/pid <PID>]... [/name <imageName>]... [/throttle <N>] [/ring <N>] [/log <dir>]` -- creates an own ETW session (StartTraceW + EnableTraceEx2 + ProcessTrace), decodes payloads via TDH with a raw-hex fallback, captures every event into a 1M-event in-memory ring AND a JSONL log file (rotated 100MB x 10), and surfaces only watch-matched events to the TUI (throttled to 50/s). Lazy image-name matching catches processes that aren't running yet at subscribe time; first match auto-promotes the PID to the hot path. Subcommands cover live tail (`!ti watch`), ring stats and histograms (`!ti stats`), per-PID/per-task filtering (`!ti by pid` / `!ti by task`), substring grep (`!ti grep`), and forensic export (`!ti save`). KnLiveDbg.exe events are excluded by default to prevent self-feedback.
36. Decodes Windows Notification Facility (WNF) state names with `!wnf` and walks live `_WNF_NAME_INSTANCE` records via two code paths: the legacy `RTL_AVL_TABLE` traversal from `nt!ExpWnfSiloState` (Win10 / early Win11), and a modern LIST_ENTRY heuristic walker that enumerates instance chains hanging off silo-state structures on Win11 builds that have migrated WNF tracking away from `RTL_AVL_TABLE`. The decoder applies the documented `0x41C64E6DA3BC0074` XOR mask to surface Version/Lifetime/DataScope/PermanentData/Sequence/OwnerTag bit fields and optionally dumps the last-published `WNF_STATE_DATA` payload. Three diagnostic subcommands -- `!wnf candidates`, `!wnf lists`, and the runner-up list reporting in `!wnf instances` -- expose the silo discovery and list-shape detection for manual inspection when automatic mode picks the wrong chain.
37. Inspects the SYSCALL-configuration model-specific registers with `!msrcheck` -- reading `IA32_LSTAR`, `IA32_CSTAR`, `IA32_STAR`, `IA32_FMASK`, and `IA32_EFER` on every active processor through a new read-only `IOCTL_KNDBG_READ_MSR` driver primitive (ABI version 8; the driver permits only a fixed architectural MSR whitelist and pins per-CPU affinity so single-core hooks are visible). It flags `LSTAR` that does not equal `nt!KiSystemCall64`, any per-CPU divergence (the kernel programs these MSRs uniformly), and entry pointers outside the loaded kernel image as possible SYSCALL hooks, while decoding `STAR` selectors and `EFER` bits for inspection. This closes the previously blind SYSCALL-entry attack surface and establishes the read-only CPU-state IOCTL pattern reused by future control-register/IDT/SSDT checks.

## Design Notes

- `docs/ARCHITECTURE.md` describes the driver/user split and backend routing.
- `docs/WINDBG_COMMAND_COVERAGE.md` tracks native and DbgEng-routed WinDbg command coverage.
- `docs/AI_ASSISTED_WORKFLOWS.md` documents the implemented AI intent router, evidence analysis, command planning, write safety, playbooks, reporting, and operator examples.
- `docs/FEATURE_PLAN.md` tracks completed feature slices and remaining high-value work such as richer driver-object/device-stack inspection, WNF stabilization, WFP kernel callout resolution, and probe fixtures.

## Build

Requirements:

1. Visual Studio 2022 with MSBuild, VC++ x64 tools, and the DIA SDK component.
2. Windows Driver Kit 10.0.26100.0.
3. x64 developer shell or normal PowerShell. The build helper discovers MSBuild and DIA SDK paths from installed Visual Studio instances through `vswhere`.
4. Vendored Zydis v4.1.1 amalgamated sources under `third_party\zydis\amalgamated` for native x64 disassembly.

Build:

```powershell
.\tools\build.ps1 -Configuration Release
```

Refresh the pinned Debugging Tools runtime from the newest complete local x64 set:

```powershell
.\tools\sync-debugging-tools-runtime.ps1
```

The driver projects use WDK `TestSign` for Debug and Release x64 builds. The build helper verifies that both `KnLiveDbg.sys` and `KnLiveDbgProbe.sys` have Authenticode signers and prints signature status/thumbprints after MSBuild completes.
Normal scripted builds reuse the current PE version from `.build\version-state.json` or the existing output file and do not increment it. Use `.\tools\build.ps1 -Configuration Release -BumpVersion` only when a new build version should be minted; with no previous state, the baseline is `0.0.0`, so the first bumped build stamps `0.0.1` into `KnLiveDbg.exe`, `KnLiveDbg.sys`, and `KnLiveDbgProbe.sys`. The generated resource header is written under `.build\generated`, while `shared\KnLiveDbgVersion.h` remains a `0.0.0` fallback for direct Visual Studio builds that do not run the helper script.
The build helper also stages the pinned `vendor\debugging-tools\x64` runtime beside the EXE (`dbghelp.dll`, `dbgeng.dll`, `dbgcore.dll`, `DbgModel.dll`, `msdia140.dll`, `symsrv.dll`, `srcsrv.dll`, and `symsrv.yes`) so DbgHelp and DbgEng can use the Microsoft symbol server instead of falling back to the limited System32 runtime. If the vendor pair is missing, the script falls back to the locally installed Windows Kits Debugging Tools copy. DIA include/lib paths are passed to MSBuild from the discovered Visual Studio installation instead of relying on a fixed VS edition path. If `symsrv.dll` is staged but `symsrv.yes` is missing, the sync script, build script, and EXE startup path create `symsrv.yes` before symbol loading. Startup creates `<exe-dir>\symbols` and uses it as the downstream symbol store, so downloaded PDBs stay with the runnable EXE bundle rather than going to `C:\Symbols`. When `msdia140.dll` is staged, startup registers it automatically with `DllRegisterServer` before symbol initialization. The symbol engine also has a no-reg fallback that loads the staged `msdia*.dll` directly and creates `IDiaDataSource` through `DllGetClassObject`, so type fallback can still work when COM registration is unavailable.

Create a release zip:

```powershell
.\tools\release.ps1 -Configuration Release
```

The build helper copies `tools\update-byovd-intel.ps1` into `x64\<Configuration>\tools\` so direct build outputs can refresh the BYOVD catalog. The release helper runs a version-bumped build unless `-SkipBuild` or `-NoVersionBump` is supplied, then creates `release\KnLiveDbg-<version>-Release-x64.zip` containing the built EXE/SYS files, the BYOVD positive-control fixture driver, staged Debugging Tools runtime, PDB/CER/CAT files when present, `README.md`, the vendored runtime manifest when present, `tools\update-byovd-intel.ps1`, and `kn-live-dbg-version.json`. YARA binaries are intentionally not packaged.

Expected outputs:

```text
x64\Release\KnLiveDbg.exe
x64\Release\KnLiveDbg.sys
x64\Release\KnLiveDbgProbe.sys
x64\Release\dbghelp.dll
x64\Release\DbgModel.dll
x64\Release\symsrv.dll
```

## Run

Run from an elevated console:

```powershell
cd .\x64\Release
.\KnLiveDbg.exe
```

The EXE expects `KnLiveDbg.sys` beside it. Keep the staged Debugging Tools DLLs beside the EXE as well when copying the tool to another directory; otherwise Windows may load `C:\Windows\System32\dbghelp.dll` without `symsrv.dll`, and startup can report `symType=0 (SymNone)` while trying to download the kernel PDB. If `symsrv.dll` is present but `symsrv.yes` is missing, startup creates `symsrv.yes` before calling DbgHelp so first-run symbol-server consent does not block noninteractive PDB downloads. Startup creates `<exe-dir>\symbols`, excludes that cache tree from plain local-directory scanning, and then uses `SRV*<exe-dir>\symbols*https://msdl.microsoft.com/download/symbols` as the default Microsoft symbol path. If `msdia140.dll` is present, startup registers DIA COM automatically before DbgHelp/DIA initialization; if registration is not available, DIA type fallback can still instantiate the staged DLL directly without registry state. It resolves the absolute driver path, updates an existing service config when present, creates the service when missing, starts it, and waits for `SERVICE_RUNNING`. Startup, single-instance acquisition, install/update, driver load, device open, ABI verification, automatic EXE-directory symbol path discovery, EXE-local symbol cache setup, symbol initialization, default `nt` kernel PDB download/load, probe load, and unload paths are printed as colored staged `[ .. ]`, `[ OK ]`, `[WARN]`, and `[FAIL]` rows. Only one `KnLiveDbg.exe` instance can run at a time; a second elevated process exits before touching SCM or the driver. On successful startup the console prints a colored welcome banner plus a dashboard with driver, write gate, backend, symbols, AI, probe, and quick-action hints before the `knkd>` prompt. `home` or `dashboard` redraws that screen. `q`, `quit`, `exit`, EOF, Ctrl+C, and `unload` close the device handle, stop the main driver, delete the service, and wait for deletion before exit. If the session loaded `KnLiveDbgProbe.sys` with `probe load`, that probe service is also stopped and deleted during process cleanup. Use `drvstatus` to inspect SCM state plus the active single-controller owner/write-mode state. Use `probe load` when you want the optional positive-control driver loaded from the same output directory.

Interactive command dispatch has a delayed progress watchdog. Silent commands that run longer than about one second print a colored `still running` status line with elapsed time, then a neutral `finished` line when control returns. Once a command starts producing stdout/stderr, the watchdog suppresses further progress rows so status text does not interleave with command output. Console color changes and direct progress writes are serialized so a progress row cannot leave the prompt/output color stuck.

The `knkd>` prompt supports Tab completion for registered commands and context-aware subcommands, plus Up/Down history recall for recent commands. Examples include `callbacks <Tab>` for callback scopes, `callbacks object /module<Tab>` for the module option, `ai <Tab>` for primary AI actions, `ai explain callbacks <Tab>` for callback scopes, `ai config <Tab>` for provider setup, `backend <Tab>`, `probe <Tab>`, `procctx <Tab>`, `write <Tab>`, and option completion such as `dt -<Tab>`, `vtop /<Tab>`, and `db /<Tab>`. Callback completion and parsing use only canonical scope names (`object`, `registry`, `process`, `thread`, `imageload`, `minifilter`) plus `all`, `/module`, and `help`; short aliases are intentionally not accepted. Help is available as both `help <command>` and `<command> help`; nested AI topics also support `ai <subcommand> help` or `ai help <subcommand>`. When a prefix is ambiguous, the prompt prints matching candidates and redraws the current input line without dispatching anything.

Native `<address|symbol>` parameters accept simple arithmetic before dispatching to memory, type, disassembly, translation, and AI-preview helpers. Examples include `dt nt!_PS_PROTECTION 0xffffb40c8c1540c0+5fa`, `dq nt!PsLoadedModuleList+10`, and `u nt!KiSystemCall64-20`.

Interactive output highlights high-signal categories and identifiers with console colors. Callback record tags such as `[ob]`, object type names, modules, symbols, translated physical addresses, module/symbol names, type names, field names, and dump line addresses are colored for scanning, while captured stdout/transcript text remains plain.

## TUI Commands

```text
help
help all
help <command>
<command> help
ai help <subcommand>
help callbacks
callbacks <scope> help
ai <subcommand> help
home
dashboard
cls
backend [auto|native|dbgeng]
kdinit [/local [connect-options]|/remote <connect-options>]
kd <windbg-command>
kddetach
version
drvstatus
probe [status|load [sys-path]|info|reset|unload]
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
vtop /process <process-id> <address|symbol> [length]
d, da, db, dc, dd, dD, df, dp, dq, du, dw, dW, dyb, dyd
d* /process <process-id> <address|symbol> [count]
dda, ddp, ddu, dpa, dpp, dpu, dqa, dqp, dqu
dds, dps, dqs
phys, pdb, pdw, pdd, pdq
!db, !dw, !dd, !dq
procctx [status|clear|<process-id>]
u <address|symbol> [instruction-count]
uf <address|symbol> [max-instructions]
dt [-rN] [-v] [-b] <type|type-pattern> [address|symbol] [field-filter...]
dtx [-rN] [-v] [-b] <type|type-pattern> [address|symbol] [field-filter...]
callbacks [all|object|registry|process|thread|imageload|minifilter] [module]
callbacks [scope] /module <module>
!dml_proc [pid]
!vad <pid|image|eprocess> [/summary] [/exec] [/private] [/wx] [/pe] [/hiddenpte] [/limit <n>] [/json <path>]
!threads <pid|image|eprocess> [/apc] [/stacks] [/limit <n>] [/json <path>]
!wfp [providers|sublayers|callouts|filters|layers]
!wfp callouts /module <name|GUID>
!wfp filters /layer <name|GUID> /provider <name|GUID>
!alpc [ports|port|connections|queues] [/name <pattern>] [/pid <pid>]
!alpc port <address>
!alpc queues <address>
!vbs
!ci [options|policy]
!securekernel
!etw [loggers|logger <index|name>|integrity]
!nmi [callbacks]
!msrcheck
!fwtable [providers|provider <signature>]
!fwtable providers /module <name>
!module integrity [module|all] [/summary] [/verbose] [/headers] [/sections] [/wx] [/mismatch] [/limit <n>] [/json <path>]
!driver integrity [driver|all] [/limit <n>] [/json <path>]
byovd [scan|update|status] [/no-update] [/force-update] [/exact] [/yara] [/yara-path <exe>] [/yara-timeout <seconds>] [/verbose] [/summary] [/limit <n>] [/json <path>]
!byovd [scan|update|status] [/no-update] [/force-update] [/exact] [/yara] [/yara-path <exe>] [/yara-timeout <seconds>] [/verbose] [/summary] [/limit <n>] [/json <path>]
byovd fixture [status|load [sys-path]|unload|path]
!pool [big|find|summary] [/tag <ABCD>] [/min <bytes>] [/max <bytes>] [/addr <va>] [/limit <n>] [/nonpaged|/paged|/any] [/annotate] [/wx]
!snapshot baseline [/all] [/name <label>]
!snapshot save <path> [/all] [/name <label>]
!snapshot show [baseline|<path>] [/domains] [/warnings]
!diff baseline [/summary] [/details] [/domain <name>] [/risk high|all] [/limit <n>]
!diff <old.json> <new.json> [/summary] [/details] [/domain <name>] [/risk high|all] [/limit <n>]
dump-raw <address> <length> <path> [/zerofill]
dump-pe <address> <path>
pool-scan-pe [/tag <ABCD>] [/min <bytes>] [/max <bytes>] [/limit <n>] [/nonpaged|/paged|/any] [/suspicious] [/dump <directory>]
!address <va>
set-ppl-antimalware [on|off|status]
!ti start [/pid <PID>]... [/name <imageName>]... [/throttle <N>] [/ring <N>] [/log <dir>]
!ti stop | status | watch | recent [N] | stats | by pid <PID> | by task <name> | grep <pattern> | save <path> | clear | add /pid|/name <v> | remove /pid|/name <v>
!wnf [decode <hash>|instances|instance <hash|entry-address>|data <hash|entry-address>|candidates|lists]
ai <question>
ai status
ai config [status|providers|provider|policy|model|base-url|effort|auth|test]
ai plan <prompt>
ai explain <read-only-command...>
ai show
ai run <index|all>
ai write <index> [confirm]
ai report <path>
c <address1> <address2> <length>
s [-b|-w|-d|-q] <address> <length> <value...>
f <address> <length> <byte-pattern...>
m <source> <destination> <length>
write on|off
e, ea, eb, ed, eD, ef, ep, eq, eu, ew, eza, ezu
e* <address|symbol> [value...]          # defaults to System(pid 4) context
e* /process <process-id> <address|symbol> [value...]
peb, pew, ped, peq
!eb, !ew, !ed, !eq
pe* <physical-address> [value...]
setfield <type> <address|symbol> <field> <value>
unload
q, qq, qd, quit, exit
```

Help syntax notes:

- `help` shows native/TUI commands; `help all` also lists DbgEng-routed WinDbg commands.
- `help <command>` and `<command> help` print detailed command-family syntax.
- Count arguments are element counts for typed dumps, bytes for range lengths, and instruction counts for `u`/`uf`.
- `nt!` is treated as the loaded kernel image for symbols and PDB type names.
- `d*`, `e*`, and `vtop` support `/process <process-id>` for one command; `procctx <pid>` pins a default context.
- Virtual `e*` writes default to System(pid 4) context for kernel addresses and temporarily restore read-only leaf PTE write bits after patching.
- API-key AI providers load `.env` only from the EXE directory; `ai run` remains read-only and `ai write <index> confirm` is required for write-like plans.

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
knkd> procctx 1234
knkd> db 0000012345678000 80
knkd> db /process 1234 0000012345678000 80
knkd> pdb <physical-address> 80
knkd> !db <physical-address> 80
knkd> !eb <physical-address>
knkd> !eq <physical-address> <value>
knkd> dt nt!_EPROCESS
knkd> dt -r1 nt!_EPROCESS <address> UniqueProcessId ActiveProcessLinks
knkd> callbacks all
knkd> callbacks object
knkd> callbacks imageload
knkd> callbacks minifilter
knkd> callbacks all WdFilter.sys
knkd> callbacks /module WdFilter.sys
knkd> !dml_proc
knkd> !dml_proc 4
knkd> !wfp providers
knkd> !wfp callouts /module tcpip
knkd> !wfp filters /layer ALE_AUTH_CONNECT_V4
knkd> !wfp layers
knkd> !alpc ports
knkd> !alpc connections
knkd> !alpc ports /name OLE
knkd> !alpc queues ffff8a8400000000
knkd> !vbs
knkd> !ci options
knkd> !ci policy
knkd> !securekernel
knkd> !etw loggers
knkd> !etw logger "Circular Kernel Context Logger"
knkd> !etw integrity
knkd> !nmi callbacks
knkd> !msrcheck
knkd> !fwtable providers
knkd> !fwtable providers /module WdFilter
knkd> !fwtable provider ACPI
knkd> !module integrity ntoskrnl
knkd> !module integrity all /verbose /limit 20
knkd> !module integrity all /wx
knkd> !module integrity ntoskrnl /headers /sections
knkd> !driver integrity WdFilter
knkd> !pool big /annotate
knkd> !pool find /tag Wmem /annotate
knkd> !pool find /wx /limit 20
knkd> !pool find /min 0x10000 /annotate
knkd> !pool summary
knkd> !snapshot baseline /name clean-boot
knkd> !diff baseline
knkd> !diff baseline /domain pool /limit 20
knkd> dump-raw nt!KiSystemServiceUser 0x200 .\kiSystemServiceUser.bin
knkd> dump-pe nt .\ntoskrnl-live.exe
knkd> dump-pe Wdf01000 .\wdf01000-live.sys
knkd> pool-scan-pe
knkd> pool-scan-pe /suspicious /dump .\poolpe-hits
knkd> !address nt!ExpWnfSiloState
knkd> !address 0xffffe78fcd778000
knkd> write on
knkd> set-ppl-antimalware
knkd> !ti start /name foo.exe /name bar.exe
knkd> !ti watch
knkd> !ti stats
knkd> !ti save .\ti-snapshot.jsonl
knkd> !wnf decode 0x41c64e6da3bc0075
knkd> !wnf instances
knkd> !wnf instance 0xfffff80300000000
knkd> !wnf data 0xfffff80300000000
knkd> ai config provider openai-codex-cli
knkd> ai config test
knkd> ai a.exe eprocess
knkd> ai pid 1234 dtb
knkd> ai callbacks all WdFilter.sys
knkd> ai check VBS status
knkd> ai !ci options
knkd> ai show
knkd> ai run 1
knkd> ai report .\kn-ai-report.md
knkd> probe load
knkd> probe info
```

The registry also knows the standard execution, breakpoint, stack, register, source, exception, I/O port, and script commands. Native live-memory commands stay on the custom driver backend, while stop-state or parser-heavy commands are routed to DbgEng in `auto` or `dbgeng` mode.

Memory display commands use sparse reads. If part of a requested virtual or physical range cannot be read, the printable dump stays aligned and unknown bytes are shown as `??`, with wider unit displays using `0x????...` for unreadable units.

`u` and `uf` are explicit disassembly commands. `u` resolves an address or symbol, reads code bytes through the loaded driver, disassembles them with the vendored Zydis x64 decoder, and remembers the next offset for a following bare `u`; if the driver device is not open, it falls back to the DbgEng disassembly path. `uf` uses the same driver-backed Zydis path and linearly disassembles from the start address until a function terminal instruction such as `ret`, `iret`, `sysret`, `sysexit`, `hlt`, `ud2`, or `int3`, with an optional instruction cap.

## AI Assistant Providers

The `ai` command is an operator intent layer plus an advisory provider bridge. Prefer `ai <goal>` for day-to-day use: the TUI now auto-routes local read-only tools, exact read-only evidence commands that should be explained, or a validated command plan when no direct local tool fits. It does not execute generated debugger commands automatically, and it does not hide write operations. `ai plan` and `ai explain` remain explicit overrides for operators who want to force a mode.

```text
ai <question>
ai status
ai config [status]
ai config providers
ai config provider <openai-codex-cli|openai-codex-subscription|deepseek|openrouter|off>
ai config policy <allow-remote|local-only|status>
ai config model <model>
ai config base-url <url>
ai config effort <minimal|low|medium|high|xhigh>
ai config auth
ai config test [prompt]
ai plan <prompt>
ai explain <read-only-command...>
ai show
ai run <index|all>
ai write <index> [confirm]
ai report <path>
```

Examples:

```text
ai a.exe pid
ai a.exe eprocess
ai a.exe process eprocess info
ai pid 1234 dtb
ai WdFilter.sys object callbacks
ai callbacks all WdFilter.sys
ai dt nt!_EPROCESS <address> UniqueProcessId ActiveProcessLinks
ai uf nt!PspCreateProcessNotifyRoutine 128
ai check VBS status
ai !ci options
```

See `docs/AI_ASSISTED_WORKFLOWS.md` for the full operator command example catalog, including process, callback, VBS/HVCI/CI, module integrity, driver integrity, WFP/ALPC, VAD/thread, ETW/NMI/pool/WNF/TI, auto-plan, advisory, and explicit override examples.

Provider configuration is loaded from `.env` beside `KnLiveDbg.exe` and can be overridden by real process environment variables. Copy `.env.example` to the EXE directory as `.env` and fill in only the provider you want to use:

```text
KNLIVEDBG_AI_PROVIDER=openrouter
KNLIVEDBG_AI_REMOTE_POLICY=allow-remote
KNLIVEDBG_AI_MODEL=openai/gpt-oss-120b
KNLIVEDBG_OPENROUTER_API_KEY=sk-or-...
```

Or:

```text
KNLIVEDBG_AI_PROVIDER=deepseek
KNLIVEDBG_AI_MODEL=deepseek-chat
KNLIVEDBG_DEEPSEEK_API_KEY=sk-...
```

Supported keys:

1. `KNLIVEDBG_AI_PROVIDER` selects `openai-codex-cli`, `openai-codex-subscription`, `deepseek`, or `openrouter`.
2. `KNLIVEDBG_AI_REMOTE_POLICY` selects `allow-remote` or `local-only`; `local-only` blocks HTTP-backed providers such as ChatGPT/Codex OAuth, DeepSeek, and OpenRouter.
3. `KNLIVEDBG_AI_MODEL` overrides the provider default model.
4. `KNLIVEDBG_AI_BASE_URL` overrides the provider base URL.
5. `KNLIVEDBG_DEEPSEEK_API_KEY` or `DEEPSEEK_API_KEY` supplies the DeepSeek API key.
6. `KNLIVEDBG_OPENROUTER_API_KEY` or `OPENROUTER_API_KEY` supplies the OpenRouter API key.
7. `KNLIVEDBG_CODEX_ACCESS_TOKEN`, `KERNFORGE_CODEX_ACCESS_TOKEN`, `KNLIVEDBG_CODEX_AUTH_FILE`, or `KERNFORGE_CODEX_AUTH_FILE` supplies ChatGPT/Codex OAuth credentials.
8. If no Codex auth file is configured, Kn Live Dbg checks `%USERPROFILE%\.kernforge\codex_auth.json` and `%USERPROFILE%\.codex\auth.json`.
9. `KNLIVEDBG_CODEX_CLI_PATH` overrides the `codex` executable used by `openai-codex-cli`.

Run `codex login` outside Kn Live Dbg when ChatGPT/Codex OAuth credentials are missing or expired. `ai status` shows the loaded `.env` path, remote policy, and credential source. `ai config test` sends a tiny marker request to the selected provider/model and prints transport status, HTTP status when available, elapsed time, and whether the expected marker came back. `ai config policy local-only` can be used during a sensitive session to block HTTP-backed providers without editing `.env`. Legacy direct forms such as `ai policy local-only`, `ai ask`, `ai preview`, `ai analyze callbacks`, `ai annotate`, `ai diagnose`, `ai playbook`, `ai transcript`, and `ai audit` are still accepted for compatibility, but the main help surface groups provider setup under `ai config` and evidence analysis under `ai explain`.

For `ai <question>`, the provider sees the operator prompt plus a capability catalog, not live memory contents. The catalog includes `process.find`, `process.describe`, `type.describe`, `callbacks.list`, `wfp.list`, `alpc.list`, `vad.list`, `threads.list`, `etw.integrity`, `nmi.list`, `fwtable.list`, `pool.find`, `address.inspect`, `wnf.decode`, `wnf.list`, `ti.query`, `module.integrity`, and `driver.integrity`, so prompts such as `ai a.exe process eprocess info` can become a structured tool plan that finds the process through `_EPROCESS.ActiveProcessLinks` and prints PID, EPROCESS, DTB, PEB, or a `dt nt!_EPROCESS` view locally. Callback/WFP/ALPC prompts route through their native scanners with validated scope/filter args. Firmware table provider prompts route through the passive `!fwtable` scanner and never invoke firmware handlers. Requests that ask to list, show, recommend, or suggest commands route to the planner first, so command-advice prompts do not run native scanners immediately. Process memory prompts route through `!vad` or `!threads`, including VAD DKOM prompts that set `hiddenpte=true` and run `!vad <target> /hiddenpte`. Integrity prompts such as `ai any inline ETW hook?`, `ai list NMI callbacks`, `ai list firmware table providers`, `ai show W+X pool allocations`, `ai why is nt!Foo suspicious?`, `ai decode this WNF state name 0x41c64e6da3bc0075`, `ai list live WNF instances`, `ai query recent TI WriteVM events`, `ai inspect module text integrity with headers and sections`, `ai find W+X kernel modules`, and `ai check driver dispatch integrity` route through the corresponding local read-only tool. Exact read-only commands after `ai`, such as `ai callbacks all WdFilter.sys`, `ai dt nt!_EPROCESS <address>`, `ai uf nt!Foo`, `ai !ci options`, `ai !vbs`, or `ai !fwtable providers`, are treated as evidence commands: Kn Live Dbg runs the command, captures stdout/stderr, and asks the selected model to explain the evidence. If neither a local capability nor an evidence command fits but the request looks investigative, `ai <question>` automatically builds a validated `kn-live-dbg.ai-plan.v2` command plan and leaves execution to `ai run`. `module.integrity` accepts validated `target`/`module`/`name`, `limit`, `summary`, `verbose`, `headers`, `sections`, `wx`, and `mismatch` args before the local executor builds the native command. The capability parser rejects unknown tools, unknown fields, unsafe characters, invalid scalars, write-like actions, raw `kd`, nested `ai`, session mutation, unload/shutdown, and command chaining before any native handler is called. The compatibility local process resolver remains as a fallback when the provider is disabled or the tool planner cannot produce a usable local plan.

`ai plan <prompt>` asks the selected model to return a strict `kn-live-dbg.ai-plan.v2` command proposal JSON object, validates proposed commands before storing them, and prints numbered commands with purpose, risk, backend, and expected-output notes. Empty commands, missing purpose metadata, unsupported backend expectations, command chaining, multiline commands, nested `ai`, shutdown/unload commands, backend/session mutation, probe service control, bare `kd`, raw `kd` wrapping of blocked commands, overlong commands, and unknown non-DbgEng commands are rejected; write-like proposals are forced to require confirmation. Conceptual `what`/`how`/`why` questions stay advisory, while investigative requests such as `check`, `show`, `list`, `scan`, `status`, `integrity`, `ci options`, or `module integrity` automatically build a command plan when no direct local tool matches. `ai explain <read-only-command...>` is still available as an explicit evidence-analysis form; it preserves stdout/stderr, adds a deterministic output summary, then asks the selected model for analysis. It has tuned prompts for `callbacks`, `dt`/`dtx`, and `u`/`uf`, so the older `ai analyze callbacks` and `ai annotate` flows are now covered by the shorter explain form and by implicit `ai <read-only-command...>` routing.

`ai run <index|all>` executes only non-write, non-shutdown planned commands. Write-like commands such as `e*`, `pe*`, `setfield`, `f`, `m`, and raw `kd` wrappers around write-like commands are blocked from `ai run`; `ai write <index>` prints a write preview with target class, byte count, backup/read-current command, restore-current command for small ranges, verification command, and safe read-only preflight output. `ai write <index> confirm` re-runs the backup read, dispatches the write-like command, re-runs the verification command, and prints a deterministic before/after stdout/stderr diff for the verification command. `ai transcript <path>` enables JSONL capture of AI events and command stdout/stderr, including backend mode, command class, write-like classification, stdout/stderr character counts, deterministic output summary, raw stdout/stderr, and keep-running state. `ai transcript max <bytes>` rotates long transcript files, `ai transcript redact on` redacts long hex addresses and `sk-...` style tokens from captured stdout/stderr, and `ai audit <path>` writes a separate JSONL record for every write-like command that executes through the normal dispatcher. `ai report <path>` exports a Markdown summary of the current AI session, transcript settings, write-audit path, and plan.

## DbgEng Backend

The default backend mode is `auto`:

1. Native memory/symbol/type commands run through the custom driver and `DbgHelp`.
2. Stop-state WinDbg commands, parser-heavy commands, `!extension` commands, and unknown `.meta` commands are routed to DbgEng after `kdinit` or lazy DbgEng initialization.
3. `backend dbgeng` sends commands directly to `IDebugControl::ExecuteWide`.
4. `backend native` disables automatic DbgEng routing.

Backend mode behavior:

| Mode | Command routing | Best fit | Notes |
| --- | --- | --- | --- |
| `auto` | Native commands use the driver/`DbgHelp` path; DbgEng-only, extension, and unknown meta commands are lazily routed to DbgEng. | Default interactive use. | Keeps live-memory features native while preserving access to WinDbg parser and stop-state commands. |
| `native` | Uses the native command handlers and blocks generic DbgEng fallback. | Driver-backed memory, symbol, type, callback, disassembly, and physical-memory work. | `!extension`, stack/register/breakpoint/execution/source/exception commands are reported as DbgEng-only instead of being executed. Explicit `u` and `uf` stay driver-backed when the device is open. |
| `dbgeng` | Sends most non-session commands directly to DbgEng raw execution. | WinDbg-compatible parser behavior. | Session commands, `callbacks`, `!dml_proc`, `!vad`, `!threads`, `!wfp`, `!alpc`, `!vbs`, `!ci`, `!securekernel`, `!etw`, `!nmi`, `!fwtable`, `!module`, `!driver`, `!pool`, `!snapshot`, `!diff`, `!wnf`, `!address`, `dump-raw`, `dump-pe`, `pool-scan-pe`, native physical bang commands, and explicit `u`/`uf` are still handled by the TUI before the raw DbgEng catch-all. |

`kd <command>` is an explicit raw DbgEng escape hatch and does not depend on the current backend mode.

Examples:

```text
knkd> kdinit
knkd> kdinit /remote net:port=50000,key=1.2.3.4
knkd> !dml_proc
knkd> backend dbgeng
knkd> k
knkd> backend auto
knkd> kddetach
```

DbgEng uses `IDebugClient5::AttachKernelWide(DEBUG_ATTACH_LOCAL_KERNEL, ...)` for local mode and `DEBUG_ATTACH_KERNEL_CONNECTION` for `kdinit /remote <connection-options>`. Local mode still follows the limits of Windows local kernel debugging; not every KD command has the same behavior as a remote break-in session. Use native `!dml_proc` when you need a process list without relying on DbgEng current process/thread state or extension exports.

## Native `dt`

Native `dt` now supports both type layout and value display:

```text
dt nt!_EPROCESS
dt nt!_EPROCESS <address>
dt -r1 nt!_EPROCESS <address>
dt -v nt!_EPROCESS <address> UniqueProcessId
dt nt!*EPROCESS*
dt nt!*
```

Supported options:

- `-r` or `-rN`: recursively expand nested UDT fields up to the requested depth.
- `-v`: print internal symbol tag/type id/length diagnostics.
- `-b`: bare output, omitting type names.

Field filters are case-insensitive substring filters applied to field names and type names.

Wildcard type patterns such as `dt nt!*EPROCESS*` and `dt nt!*` enumerate PDB types through `SymEnumTypesW` and apply the `*`/`?` filter in user mode. If DbgHelp cannot enumerate a loaded module's type stream, the symbol engine falls back to DIA UDT enumeration from either the loaded PDB path or the module image plus symbol path. Wildcard `dt` is list-only; use an exact type name when dumping fields or reading a value at an address.

The native symbol engine treats `nt` as the kernel-image alias and loads `ntoskrnl.exe`/`ntkrnl*` into DbgHelp under the `nt` module name, so commands such as `x nt!*`, `ln nt!PsLoadedModuleList`, and `dt nt!*` do not depend on the on-disk kernel image name.

Exact type layouts first try `SymGetTypeFromNameW`. If that lookup fails for an alias-qualified type such as `nt!_TP_POOL`, the symbol engine reuses `SymEnumTypesW` to find the exact type and dumps the layout by module base plus type id before trying DIA. The enumeration fallback matches module-qualified names, leaf names, and leading-underscore variants, so `nt!_OBJECT_TYPE`, `_OBJECT_TYPE`, `OBJECT_TYPE`, and enumerated `nt!_OBJECT_TYPE` spellings resolve to the same type. DIA fallback uses the same full-enumeration matcher and reports module/PDB/image details when a type is not found.

When `DbgHelp` cannot return a usable UDT layout, the symbol engine tries a DIA SDK fallback against the loaded PDB path or resolves the PDB from the module image plus symbol path. DIA creation first uses registered COM and then falls back to direct `DllGetClassObject` activation from the staged `msdia*.dll`, which makes registration failures distinct from real type lookup failures. The fallback is especially useful for field offsets, bit positions, and private type metadata used by callback scanning and `dt`; recursive expansion still prefers the normal `DbgHelp` type-id path when it is available.

## Native Process Listing

`!dml_proc` is implemented natively so it works even when the optional DbgEng backend does not have a current process/thread or cannot load WinDbg extension exports:

```text
!dml_proc [pid]
```

The command resolves PID 4 through the driver, uses PDB metadata for `_EPROCESS.ActiveProcessLinks`, then walks the active process list from live kernel memory. If a decimal PID argument is supplied, for example `!dml_proc 4`, only records whose process ID matches that value are printed. Output includes EPROCESS, PID, parent PID when available, active thread count, directory-table base, image name, and a ready-to-run `dt nt!_EPROCESS <address>` follow-up.

## Native VAD And Thread Triage

`!vad` and `!threads` add read-only process memory triage without adding new kernel parsing logic:

```text
!vad <pid|image|eprocess> [/summary] [/exec] [/private] [/wx] [/pe] [/hiddenpte] [/limit <n>] [/json <path>]
!threads <pid|image|eprocess> [/apc] [/stacks] [/limit <n>] [/json <path>]
```

Targets can be decimal PID, image name, or EPROCESS address. `!vad` resolves `_EPROCESS.VadRoot` through PDB/DIA type metadata, walks the balanced tree with bounded traversal and cycle detection, decodes VPN range, protection, private-memory, commit, large/no-change, subsection, and PE-like first-page evidence when available, then prints a compact table plus `[vad.summary]`. `/exec`, `/private`, `/wx`, and `/pe` narrow the output; `/pe` probes private VAD first pages with the same PE header detector used by pool PE hunting. `/hiddenpte` also walks the target process page tables from its DTB, subtracts the normalized VAD coverage plus known VAD-less OS shared mappings, and prints `[hidden-pte]` ranges where a present user PTE exists without VAD coverage, which is a DKOM-style hidden memory signal.

`!threads` walks the process thread list, prints ETHREAD/TID/start/Win32StartAddress/TEB/module/VAD annotations, optionally includes stack bounds, and `/apc` surfaces conservative APC queue evidence when ETHREAD/KAPC layouts are available. Both commands support `/json <path>` with stable field names for diffing. Warnings are expected on PDB drift, protected process/module enumeration failures, partial reads, or APC layouts that cannot be interpreted confidently.

## Kernel Callback Scanner

`callbacks` walks live kernel callback lists using kernel PDB type layouts and the native memory reader:

```text
callbacks all
callbacks object
callbacks registry
callbacks process
callbacks thread
callbacks imageload
callbacks minifilter
callbacks object WdFilter.sys
callbacks minifilter UnionFS
```

The scanner currently covers:

1. Object-manager filters from `_OBJECT_TYPE.CallbackList`. The scanner first discovers `_OBJECT_TYPE` objects through `ObTypeIndexTable` and `_OBJECT_TYPE.Name`, then falls back to `PsProcessType`, `PsThreadType`, and `ExDesktopObjectType` when the table is unavailable. Some public nt PDBs expose `_OBJECT_TYPE.CallbackList` but omit the private callback item type; in that expected public-symbol case the scanner uses a guarded x64 item-layout fallback, validates live list pointers, callback-entry pointers, operation masks, and callback routine pointers, and only reports a warning if the PDB exposes a partial/drifted item layout or the live validation fails.
2. Registry callbacks by enumerating and validating registry callback list-head candidates such as `CmpCallbackListHead`, then walking callback context entries with guarded x64 fallback layouts when public nt PDBs omit `_CM_CALLBACK_CONTEXT_BLOCK`.
3. Process creation callbacks by enumerating and validating create-process notify routine table candidates such as `PspCreateProcessNotifyRoutine`, then decoding callback routine blocks with a stable x64 fallback when public nt PDBs omit `_EX_CALLBACK_ROUTINE_BLOCK`. Process notify metadata is decoded into `notifyType`, for example `0x2` becomes `PsSetCreateProcessNotifyRoutineEx`.
4. Thread creation callbacks by enumerating and validating create-thread notify routine table candidates such as `PspCreateThreadNotifyRoutine`, then decoding callback routine blocks with the same stable x64 fallback.
5. Image load callbacks by enumerating and validating load-image notify routine table candidates such as `PspLoadImageNotifyRoutine`, then decoding callback routine blocks with the same stable x64 fallback.
6. Minifilter callbacks by discovering `fltmgr!FltGlobals`, validating the frame-list root, walking `FrameList`, each `_FLTP_FRAME.RegisteredFilters`, and each `_FLT_FILTER.Operations` registration array.

Each record prints the discovered root address and source, callback function address, nearest symbol, owning module, object type name/index/address and discovery source for object callbacks, minifilter name/altitude/frame/driver object when present, callback/list block addresses, altitude when present, and registration/callback context pointer. Object callback rows use `object=<name>` in both the header and detail line so Process, Thread, Desktop, and other object-manager surfaces are visible without interpreting the raw `_OBJECT_TYPE` address. Image-load output uses `function` for the `PLOAD_IMAGE_NOTIFY_ROUTINE` owner and reports the decoded notify block plus raw encoded slot value. Minifilter output includes operation callbacks, filter unload, instance setup/teardown, name provider, KTM, section, and volume-mount routines when the target build exposes those fields. Add a module name after the callback scope, for example `callbacks object WdFilter.sys` or `callbacks minifilter UnionFS`, to print only records whose pre/function or post callback is owned by that module; the match is case-insensitive and treats `WdFilter` and `WdFilter.sys` as the same module stem. Registry callback routines are validated against loaded kernel image ranges before being emitted. Registration and callback context pointers are annotated with a module and nearest symbol only when they point into a loaded kernel image; process creation notify block context values are printed as `notifyType=<decoded-api> metadata=<hex>` because they are internal notify metadata, not callback module pointers. The implementation is PDB-driven where public or private type metadata exists; the expected public-PDB object-callback item fallback is validated against live pointers before records are emitted, while warnings are reserved for partial PDB layouts, structure drift, or failed validation.

## Windows Filtering Platform

`!wfp` enumerates Windows Filtering Platform objects natively through the user-mode Base Filtering Engine (`fwpuclnt.dll`) and does not require the kernel driver to be open:

```text
!wfp providers
!wfp sublayers
!wfp callouts
!wfp callouts /module tcpip
!wfp filters
!wfp filters /layer ALE_AUTH_CONNECT_V4
!wfp filters /provider WdFilter
!wfp layers
```

The scanner opens an engine handle with `FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &engine)`, builds in-memory provider, layer, and sublayer indexes from `FwpmProviderEnum0`, `FwpmLayerEnum0`, and `FwpmSubLayerEnum0`, then enumerates the requested scope through the matching `FwpmXxxCreateEnumHandle0` / `FwpmXxxEnum0` / `FwpmXxxDestroyEnumHandle0` cycle. Each page-sized batch is freed with `FwpmFreeMemory0` before the next page.

Output kinds and decoded fields:

1. `[wfp.provider]` shows provider key GUID, display name, decoded persistent/disabled flag mnemonics, optional service name, and optional description.
2. `[wfp.sublayer]` shows sublayer key GUID, display name, 16-bit weight, owning provider name plus service name when set, and persistent flag mnemonics.
3. `[wfp.callout]` shows callout key GUID, display name, runtime `calloutId`, applicable layer name and GUID, owning provider, and decoded persistent/usesProviderContext/registered flag mnemonics.
4. `[wfp.filter]` shows runtime `filterId`, filter key GUID, action type (`Block`, `Permit`, `CalloutTerminating`, `CalloutInspection`, `CalloutUnknown`, `Continue`, `None`, `NoneNoMatch`, `BitmaskPermit`, `BitmaskBlock`) with optional `calloutKey`, weight rendered from the underlying `FWP_VALUE0`, condition count, layer, sublayer, owning provider, and decoded filter flag mnemonics.
5. `[wfp.layer]` shows layer key GUID, layer name, 16-bit `layerId`, and decoded `kernel|builtin|classifyMostly|buffered` flag mnemonics.

`!wfp callouts /module <name|GUID>` filters callouts by the owning provider's service name (case-insensitive substring), display name, or `providerKey` GUID. `!wfp filters /layer <name|GUID>` filters filters by layer display-name substring or `layerKey` GUID, and `/provider` applies the same provider matching as `/module` for filters.

The user-mode `FWPM_CALLOUT0` shape intentionally does not include kernel-mode callout function pointers, so `!wfp` resolves callout ownership through `providerKey` → provider `serviceName` rather than by matching function pointers against loaded module ranges. Documented kernel-side walking of `netio.sys` internal tables is reserved for a later milestone; the user-mode path requires only that the Base Filtering Engine (`BFE`) service is running.

`wfp.list` is also wired as a local AI capability tool. `ai <question>` planning can choose it with optional `scope` and `module`/`layer` arguments, and the executor runs it through the same shape validation used for plan commands.

## ALPC Port Enumeration

`!alpc` walks live kernel memory through `KnLiveDbg.sys` and PDB type metadata to enumerate ALPC ports, render server/client connection families, and count queue depths:

```text
!alpc ports
!alpc ports /name OLE
!alpc ports /pid 1234
!alpc port ffff8a8400000000
!alpc connections
!alpc queues ffff8a8400000000
```

Discovery flow:

1. `nt!ObTypeIndexTable` is enumerated to find the `ALPC Port` and `Directory` `_OBJECT_TYPE` instances and their type indices.
2. `nt!ObHeaderCookie` is resolved when present; on builds without it the scanner records a warning and falls back to raw `_OBJECT_HEADER.TypeIndex` comparisons.
3. `nt!ObpRootDirectoryObject` is read, then the scanner recurses through `_OBJECT_DIRECTORY.HashBuckets[]` with bounded depth and a visited-directory cycle guard, decoding each entry's `_OBJECT_HEADER.TypeIndex` with the per-object XOR formula (`raw ^ cookie ^ ((header_addr >> 8) & 0xff)`).
4. For each `ALPC Port` body the scanner reads `OwnerProcess`, `ConnectionPort`, `CommunicationInfo`, and `Flags` from PDB-resolved offsets, then follows `_ALPC_COMMUNICATION_INFO.ConnectionPort`, `ServerCommunicationPort`, and `ClientCommunicationPort` to surface paired server/client ports that are not themselves named in the directory tree.
5. Owner annotations resolve `_EPROCESS.UniqueProcessId` and `ImageFileName` for each port whose `OwnerProcess` lies in the kernel canonical range.

Subcommand behavior:

1. `!alpc ports` lists every discovered port with role tag (`connection`/`server`/`client`/`named`), name, owning process, `ConnectionPort`, and `CommunicationInfo` linkage. `/name <pattern>` filters by case-insensitive substring on port name or full directory path, and `/pid <pid>` filters by decimal owning-process PID.
2. `!alpc port <address>` prints the single port whose address matches and includes queue depths.
3. `!alpc connections` groups all discovered ports by `ConnectionPort` to render server/client family graphs, with an explicit `unpaired ports` section for ports that have no `ConnectionPort` set.
4. `!alpc queues <address>` performs bounded `_LIST_ENTRY` walks on `MainQueue`, `PendingQueue`, `LargeMessageQueue`, `CanceledQueue`, and `WaitQueue`. `_KQUEUE` fields (typically `WaitQueue`) are detected by PDB type name and the dispatcher header is skipped before list walking.

The scanner only enumerates ports reachable through the Object Manager directory tree and through `CommunicationInfo` chains hanging off those named ports. Anonymous client ports that never receive a connection through a named server port are intentionally not enumerated; documented handle-table walking is reserved for a later milestone.

`alpc.list` is also wired as a local AI capability tool. `ai <question>` planning can choose it with optional `scope` (`ports` or `connections`), `name` substring, and `pid` decimal arguments, and the executor runs it through the same shape validation used for plan commands.

## VBS / HVCI / Secure Kernel Status

`!vbs`, `!ci`, and `!securekernel` reuse `KnLiveDbg.sys` virtual reads and PDB type metadata to report the state of Virtualization-Based Security, HVCI, the Secure Kernel, and Isolated User Mode (IUM) trustlets:

```text
!vbs
!ci
!ci options
!ci policy
!securekernel
```

Data sources:

1. `nt!g_CiOptions` (or `ci!g_CiOptions`, or legacy `nt!CiOptions`) is read as a `UINT32` and decoded into `CODEINTEGRITY_OPTION_ENABLED`, `TESTSIGN`, `UMCI_ENABLED`, `UMCI_AUDITMODE_ENABLED`, `HVCI_ENFORCED`, `UMCI_EXCLUSIONPATHS_ENABLED`, `TEST_BUILD`, `PREPRODUCTION_BUILD`, `FLIGHT_BUILD`, `HVCI_STRICT_MODE`, and `HVCI_DEBUG_MODE`.
2. `nt!HvlpVsmVtlCallVa` (or the equivalent build-specific alias) is read as a pointer; a non-zero kernel-canonical value indicates VBS is active and the VTL call code page is mapped.
3. `nt!HvcallpVtlCallStub` (or the equivalent alias) is resolved as a secondary VBS marker.
4. `PsLoadedModuleList` is scanned for `securekernel.exe` and `skci.dll` to confirm Secure Kernel runtime presence.
5. User-mode `CPUID` is queried at leaf `0x40000000` (hypervisor vendor signature), and at leaf `0x40000006` when supported (raw implementation hardware features). MBEC enablement cannot be confirmed from user mode because it lives in `IA32_VMX_PROCBASED_CTLS2` bit 22; the report annotates that limitation and treats HVCI enforcement as a proxy.
6. `PsActiveProcessHead` is walked through `_EPROCESS.ActiveProcessLinks`. For each process, `_EPROCESS.SecureState` (or `_KPROCESS.SecureState` when the field is exposed through the embedded `Pcb`) is read; bit 0 (`SecureKernelInProcess`) flags IUM trustlets. When that field is not present in the loaded PDB, the scanner falls back to well-known trustlet image-name prefixes (`lsaiso`, `bioiso`, `securesystem`, `kdcustomization`) which already handle `_EPROCESS.ImageFileName` being truncated to 15 bytes.

Subcommand behavior:

1. `!vbs` prints a `[vbs.core]` summary line, the `[ci.options]` block with raw value and decoded mnemonics, the `[vbs.hypervisor]` block with vendor signature and CPUID leaf info, the `[securekernel.modules]` list, and the `[securekernel.trustlets]` list.
2. `!ci` (or `!ci options`) prints the `[ci.options]` and `[vbs.hypervisor]` blocks; `!ci policy` additionally prints a `[ci.policy]` summary noting that full WDAC policy blob discovery requires private CI internals.
3. `!securekernel` prints the `[securekernel.modules]` and `[securekernel.trustlets]` lists.

WDAC policy blob extraction is intentionally deferred; the doc-listed `CI!g_CiPolicies`/`CiValidateImageHeader` path requires private layouts that the scanner does not yet trust enough to commit to.

## ETW Logger Hooks And NMI Callbacks

`!etw` and `!nmi` provide self-check coverage for two surfaces commonly used by InfinityHook-style rootkits and NMI-based stack inspection drivers:

```text
!etw loggers
!etw logger 0
!etw logger "Circular Kernel Context Logger"
!nmi
!nmi callbacks
```

ETW logger flow (`!etw loggers` / `!etw logger`):

1. `nt!EtwpDebuggerData` is resolved through the loaded kernel PDB, and 64 `WMI_LOGGER_CONTEXT*` pointers are read from offset `0x10`.
2. For each non-null logger context, `_WMI_LOGGER_CONTEXT.LoggerName` (UNICODE_STRING) and `_WMI_LOGGER_CONTEXT.GetCpuClock` (function pointer) are read using PDB-resolved field offsets when the type is exposed, or fallback offsets `0x68` (LoggerName) and `0x28` (GetCpuClock) otherwise. A warning is emitted when the fallback path is taken because those offsets drift across builds.
3. Each `GetCpuClock` target is annotated with its owning module and nearest symbol. Pointers that do not land inside any loaded kernel module are flagged with `[SUSPICIOUS]`, which is the canonical InfinityHook indicator (`GetCpuClock` rewritten to point at attacker-controlled code outside `nt`/`hal`).
4. `!etw logger <index>` accepts a decimal slot index (0..63); `!etw logger <name-substring>` filters by case-insensitive substring on the logger name.

ETW integrity flow (`!etw integrity`):

1. The scanner resolves a fixed list of canonical kernel dispatch targets grouped into four categories:
   - **Core ETW dispatch**: `EtwpReserveTraceBuffer`, `EtwpReserveTraceBufferAtomic`, `EtwpLogKernelEvent`, `EtwpReleaseTraceBuffer`, `EtwpFinalizeTraceBuffer`, `EtwpCommitTraceBuffer`, `EtwSendTraceBuffer`, `EtwpEventDispatcher` (primary modern InfinityHook surface)
   - **Classic cycle-count surface**: `EtwpGetCycleCount`, `EtwpReceiveCycleCount` (older InfinityHook variants)
   - **PMC / HAL**: `HalpCollectPmcCounters`, `HalCollectPmcCounters`, `HalpProcessorPerfCounter`, `HalpInterruptHandle`
   - **Timing sources**: `KeQueryPerformanceCounter`, `KeQuerySystemTimePrecise`, `KeQueryInterruptTimePrecise`, `KeQueryUnbiasedInterruptTimePrecise`, `RtlGetSystemTimePrecise`, `HalpTimerQueryHostPerformanceCounter`
   - **Syscall path**: `KiSystemCall64`, `KiSystemCall64Shadow`, `KiSystemServiceUser` (broader rootkit surface that responds to the same prologue-tampering checks)

   Targets not present in the loaded PDB are reported as `status=unresolved` and skipped without failing the whole scan; this lets a single command sweep multiple build variants.
2. For each resolved target the scanner reads 0x100 bytes through `KnLiveDbg.sys` and decodes up to 16 instructions with the vendored Zydis decoder. The first 24 bytes are surfaced as `head=` hex for triage.
3. Five integrity checks run against the decoded prologue: (a) first-instruction unconditional `jmp` (classic trampoline), (b) first-instruction `int3`/`ud2` (debug-trap replacement), (c) `mov reg, imm64; jmp reg` indirect trampoline, (d) `push imm; ret` 32-bit-target trampoline, (e) any unconditional `call`/`jmp` in the first 16 instructions whose target lies in kernel canonical space but outside any loaded kernel module.
4. Each finding records the instruction index, offset, mnemonic, resolved target with module/symbol annotation, and a human-readable reason. The record status is `clean`, `SUSPICIOUS`, `unresolved`, `read-failed`, or `decode-failed`.
5. A single summary line reports the target count, clean / suspicious / unresolved totals before the per-target detail lines.

InfinityHook on modern Windows no longer lands on `WMI_LOGGER_CONTEXT.GetCpuClock` directly (that field carries a UINT32 mode tag dispatched by a switch statement in the kernel); the hook surface moved to the ETW/PMC dispatch functions themselves. `!etw integrity` covers that updated surface by reading those functions' actual instructions instead of relying on a single field value.

NMI callback flow:

1. `nt!KiNmiCallbackListHead` (with `nt!KiNmiCallbackList` as a fallback alias) is resolved through the loaded kernel PDB and read as a `PKNMI_HANDLER_CALLBACK`.
2. The singly-linked list is walked with bounded iteration and a visited-node cycle guard. Each `KNMI_HANDLER_CALLBACK` node has a fixed layout: `Next` at `0x00`, `Callback` at `0x08`, `Context` at `0x10`, `Handle` at `0x18`.
3. Each `Callback` is annotated with owning module and nearest symbol; targets outside any loaded kernel module are flagged with `[SUSPICIOUS]`.

Discovery is the entire point: any `!etw` GetCpuClock hit outside loaded modules, or any `!nmi` callback in an unfamiliar driver, is a follow-up lead for `u`/`uf` and `dt` triage.

## Firmware Table Providers

`!fwtable` enumerates provider nodes registered through `SystemRegisterFirmwareTableInformationHandler` without calling the registered callbacks:

```text
!fwtable providers
!fwtable providers /module WdFilter
!fwtable provider ACPI
```

Firmware table provider flow:

1. `nt!ExpFirmwareTableProviderListHead` is resolved through the loaded kernel PDB, with `nt!ExpFirmwareTableResource` reported when present.
2. The provider list is walked as `LIST_ENTRY` with a visited-node guard, maximum-entry cap, canonical-pointer checks, guarded reads, and Flink/Blink backlink validation.
3. Node decoding prefers private PDB type metadata when available. When private types are absent, fallback candidates are scored against live nodes; the normal public-symbol fallback is `SYSTEM_FIRMWARE_TABLE_HANDLER` fields first (`ProviderSignature +0x00`, `Register +0x04`, `FirmwareTableHandler +0x08`, `DriverObject +0x10`) with the list entry at `+0x18`.
4. Each record prints the provider signature as hex plus FourCC when printable, the handler address with owning module and nearest symbol, and the DriverObject name/start/size/owner module when `_DRIVER_OBJECT` fields are available.
5. Triage flags include nonstandard providers outside the ACPI/FIRM/RSMB baseline, duplicate signatures, null or nonkernel pointers, handlers outside loaded image ranges, handler/DriverObject owner mismatches, DriverStart values outside loaded modules, and corrupt list links.

Default operation is passive by design. `EnumSystemFirmwareTables`, `GetSystemFirmwareTable`, and `ZwQuerySystemInformation(SystemFirmwareTableInformation)` are not used by the scanner because those paths can execute an attacker-controlled handler registered by a cheat driver.

## Windows Notification Facility

`!wnf` exposes the documented WNF state-name encoding and best-effort live `_WNF_NAME_INSTANCE` walking:

```text
!wnf decode <state-name-hash>
!wnf instances
!wnf instance <state-name-hash|entry-address>
!wnf data <state-name-hash|entry-address>
```

Decoder (`!wnf decode`):

1. The 64-bit raw state-name value is XORed with the documented obfuscation key `0x41C64E6DA3BC0074`.
2. The decoded value's bit fields are parsed per Alex Ionescu's "Out-of-Sight" reference: `Version` (bits 0..3), `NameLifetime` (4..5; `WellKnown`/`Permanent`/`Persistent`/`Temporary`), `DataScope` (6..9; `System`/`Session`/`User`/`Process`/`Machine`/`PhysicalMachine`), `PermanentData` (bit 10), `Sequence` (bits 11..63), and for `WellKnown` lifetime the `OwnerTag` (bits 32..63) is additionally surfaced as a 4-character ASCII component identifier when the bytes are printable.
3. `decode` is standalone and always works on any build.

Live walking (`!wnf instances` / `!wnf instance` / `!wnf data`):

1. The scanner collects silo state candidates by trying the well-known globals `nt!ExpWnfSiloState`, `nt!ExpWnfState`, and `nt!ExpWnfProcess` first, then falling back to anchor-disassembly of `nt!NtQueryWnfStateData` and `nt!NtPublishWnfStateData` with two levels of indirect-call follow and dual interpretation (treat each RIP-relative reference as both a pointer dereference and an inline struct). The union of those candidates feeds both walking modes.
2. **Modern Win11 fast path (LIST_ENTRY heuristic walker)** runs first: for each silo candidate the scanner enumerates `LIST_ENTRY`-shaped heads in the first 0x800 bytes, walks every non-empty chain (bounded at 0x80 entries per list, 0x80 bytes captured per entry), and ranks each list by the number of UNIQUE state-name-shaped 64-bit values it yields after per-entry probe of byte offsets `0x10`..`0x38`. Kernel-canonical pointers and pure-zero slots are rejected explicitly to avoid sentinel/object-pointer pollution. The single most-diverse list is treated as the authoritative `_WNF_NAME_INSTANCE` chain; runner-up lists are surfaced as diagnostics so an operator can spot when the top-1 selection was wrong.
3. **Legacy `RTL_AVL_TABLE` path** is tried only when the LIST_ENTRY walker produces no records. The AVL table is located by trying `NameSet`/`NameSubscriptionTable`/`SubscriptionTable`/`NameInstanceTable`/`NameInstances` fields on `nt!_WNF_SUBSCRIPTION_TABLE`, `nt!_WNF_SILODRIVERSTATE`, and `nt!_WNF_PROCESS_CONTEXT` types from the loaded PDB. The walker performs iterative in-order traversal with bounded depth (64) and node count (16384). Each node's user data starts at offset `+0x20` (past `sizeof(_RTL_BALANCED_LINKS)`); the user data is a `_WNF_NAME_INSTANCE` whose `StateName`, `ChangeStamp`, `DataSize`, and `LastDataBlock` (or `StateData`/`DataBlock`) fields are read via PDB-resolved offsets.
4. `instance <hash|entry-address>` filters the walk to a matching state name or stable LIST_ENTRY-mode entry address. `data <hash|entry-address>` dumps up to 256 bytes of the last-published payload as a classic hex+ASCII view. The legacy AVL path follows PDB-resolved `LastDataBlock`/`StateData` fields, while the modern LIST_ENTRY path heuristically scans the first 0x200 bytes of the matched entry for a kernel-canonical pointer whose dereferenced header matches the documented `_WNF_DATA_BLOCK` shape (`DataSize`, `AllocatedSize`, `ChangeStamp`). If that heuristic fails, diagnostics print a per-pointer header census so the build-specific data slot can be inspected manually.
5. Each surfaced entry annotates the **owning process** recovered from the stable EPROCESS pointer at `node-0x30` of every chained node (entry-level metadata, 100% recovery across entries that carry at least one chained node). Per-entry chain decomposition is printed as `chained_nodes=N subscribers=X resolved=Y other_objects=Z tags={Ntfc:N Wnf:N Sect:N ...}` so an operator immediately sees how many real subscribers exist versus backing kernel objects. The `subscribers` count counts only true subscription tags (`Ntfc` / `Wnf ` / `WnfN`); `resolved` counts how many of any node yielded `pid=N image="..."`. The listing path (`!wnf instances`) emits only resolved subscriber lines per entry; single-entry views (`!wnf instance`, `!wnf data`) still print every node with prefix and body hex dumps so a build's record layout can be characterized. EPROCESS resolution uses a two-path acceptance: classical `_DISPATCHER_HEADER.Type == 0x03` fast-path, or shape-only validation of PDB-resolved `_EPROCESS.UniqueProcessId` (4-aligned, `0 < pid <= 0x100000`) AND `ImageFileName` (`>= 3` printable-ASCII chars). Candidates within `0x200` bytes of the chained node are rejected as same-chunk noise.
6. `log enable` / `log disable` mirrors the entire console session to a timestamped UTF-8 log file (`KnLiveDbg-YYYYMMDD-HHMMSS.log`) in the EXE directory. Useful for capturing voluminous `!wnf instances` output for offline analysis; console coloring is preserved live while the log file receives clean text.

Diagnostic subcommands for builds where automatic detection picks the wrong chain:

- `!wnf candidates` dumps the first 0x100 bytes of every silo-state candidate discovered by the anchor disassembly, with embedded state-name-shape counts and kernel-pointer slot counts per candidate. Use this to spot which candidate looks like the real silo state struct.
- `!wnf lists` walks every `LIST_ENTRY`-shaped head in each silo candidate, dumping each non-empty chain with hex+ASCII per entry and per-entry state-name probe annotations. Use this to identify which head holds the actual `_WNF_NAME_INSTANCE` chain.

When neither walking mode produces records the scanner emits a precise error naming the missing piece and reminds the operator that the `decode` subcommand still works as a complete standalone tool.

## Big Pool Tracking

`!pool` snapshots `nt!PoolBigPageTable` -- the kernel's per-build tracking table for big pool (>= one page) allocations -- and surfaces tag, size, paged/non-paged class, virtual address range, and, on request, the effective R/W/X attributes derived from a live page-table walk:

```text
!pool big                              list every NonPaged big pool entry
!pool big /tag Wmem /annotate          filter by tag and walk PTE for each entry
!pool find /wx /limit 20               hunt effective W+X NonPaged allocations
!pool find /min 0x10000 /annotate      hunt large NonPaged allocations
!pool find /addr 0xffffae8000123000    locate the entry containing a VA
!pool summary                          totals only (no per-entry listing)
```

How it works:

1. The scanner enables `SeDebugPrivilege` on the current token, resolves `ntdll!NtQuerySystemInformation`, and issues a buffer-growing `SystemBigPoolInformation` (class 0x42) query that doubles from 64 KB up to a 64 MB ceiling with at most 16 retries. The kernel returns a snapshot of `_SYSTEM_BIGPOOL_INFORMATION` whose entries pack the virtual address with the `NonPaged` flag in the low bit and report a 4-byte ASCII tag plus byte size.
2. Per-entry filters apply in order: paged class (`/nonpaged` default, `/paged`, or `/any`), 4-character tag (`/tag <ABCD>` with case-sensitive matching; partial tags zero-pad the upper bytes to mirror `ExAllocatePoolWithTag('SG')` literal encoding), size band (`/min`/`/max`), containing address (`/addr`), optional effective W+X filtering (`/wx`), and finally `/limit <n>` truncates the printed list while still counting all matches.
3. `/annotate` issues one `IOCTL_KNDBG_TRANSLATE_VIRTUAL` per kept entry. The driver walks PML5/PML4/PDPTE/PDE/PTE (auto-detecting LA57 via CR4 and reporting the level count) and the scanner ANDs the Writable bit and ORs the NX bit across every traversed level so that effective W/X is correct even when a parent table clears W or sets NX. Large-page short-circuit (`PS=1` at PDPTE or PDE) is honored; the output flags `LargePage` and any combined `[W+X]` non-paged page in red as a BYOVD/staging signal. `/wx` implies `/annotate` and applies `/limit` after the W+X attribute filter so early clean entries do not hide later hits.
4. `!pool summary` prints the totals -- raw `TotalEntries`, `NonPagedCount`, `PagedCount`, kept `MatchingCount`, buffer size finally accepted by the kernel, retry count, and a `(no SeDebugPrivilege)` warning when elevation failed -- without the per-entry listing.

Requirements and caveats:

- The host must be elevated. `NtQuerySystemInformation(SystemBigPoolInformation)` returns `STATUS_ACCESS_DENIED` without `SeDebugPrivilege`; the error path reports the NTSTATUS verbatim.
- Only big pool (>= one page) is tracked by `nt!PoolBigPageTable`. Smaller allocations served from per-CPU lookasides and the segment heap are not visible to this command.
- `/annotate` requires the `KnLiveDbg.sys` device to be open. The TUI auto-disables the flag with a warning when the device is not available. `/wx` requires the device because it cannot classify effective permissions without page-table translation.

## Session Baseline Diffing

`!snapshot` and `!diff` turn the existing native scanners into a same-boot evidence baseline workflow. `!snapshot baseline` captures process inventory plus the high-value domains, stores the baseline in memory, and writes JSON plus a Markdown snapshot report. `!diff baseline` captures a fresh current snapshot, compares it against the in-memory baseline, writes the current JSON plus Markdown reports, and prints a compact new-focused summary.

```text
!snapshot baseline [/all] [/name <label>]
!snapshot save <path> [/all] [/name <label>]
!snapshot show [baseline|<path>] [/domains] [/warnings]
!diff baseline [/summary] [/details] [/domain <name>] [/risk high|all] [/limit <n>]
!diff <old.json> <new.json> [/summary] [/details] [/domain <name>] [/risk high|all] [/limit <n>]
```

Default files are written under the EXE directory's `.kn-live-dbg\snapshots` and `.kn-live-dbg\reports` trees. The JSON schema is `kn-live-dbg.snapshot.v1`; reports are Markdown and are generated automatically for both baseline snapshots and diffs.

The diff is intentionally biased toward what appeared after the baseline:

1. Added records are shown when the identity was absent from the baseline and present in the current snapshot.
2. Escalations are shown when an existing identity becomes high-risk, such as driver dispatch redirection, ETW GetCpuClock tampering, pool records gaining W+X/PE evidence, or VAD DKOM hidden-PTE evidence.
3. Removed records are not shown by default; this keeps launch-time and post-event triage focused on new attack surface.
4. Pool output is ordered as pool-PE suspect first, pool-PE hit second, W+X NonPaged third, then large NonPaged by descending size.
5. `!diff baseline` scans VAD DKOM hidden-PTE evidence for every process that is new since the baseline and still alive at diff time.
6. Low-risk child records implied by a newly added parent, such as a new driver's routine dispatch entries, are folded by default and counted as `hiddenChildren`; add `/details` to expand them.

The `/all` option is accepted for explicitness; the current native baseline captures the full implemented domain set by default: modules, drivers, callbacks, ETW, NMI, firmware-table providers, pool, pool-PE, WFP, ALPC, WNF, VBS/CI, BYOVD, and process inventory. BYOVD catalog auto-update is allowed for `!snapshot baseline` and `!snapshot save`, but `!diff baseline` reuses the local catalog in no-update mode and emits a warning if the catalog fingerprint differs between snapshots. YARA is not run by the snapshot path unless the standalone `byovd scan /yara` command is used.

Typical clean-baseline flow:

```text
knkd> !snapshot baseline /name clean-boot
knkd> !snapshot show baseline /domains /warnings
... launch the workload ...
knkd> !diff baseline /limit 20
knkd> !diff baseline /domain pool /risk high /limit 30
```

Native physical memory support is intentionally explicit:

```text
vtop nt!PsLoadedModuleList
vtop /cr3 <directory-table-base> <virtual-address> 100
vtop /process <process-id> <user-virtual-address> 100
procctx <process-id>
db <user-virtual-address> 80
db /process <process-id> <user-virtual-address> 80
pdb <physical-address> 80
pdq <physical-address> 10
!db <physical-address> 80
!dq <physical-address> 10
write off
!eb <physical-address>
peq <physical-address> <qword-value>
!eq <physical-address> <qword-value>
```

`vtop` uses the current CR3 when no directory-table base is supplied. `vtop /process` asks the driver to resolve the target EPROCESS, reads the DTB offsets from PDB type metadata, and walks that process address space. It prints whether the walk used PML4 or PML5, the physical address of each page-table entry that was read, and the leaf entry kind, physical address, and writable state. `procctx <pid>` stores the same process context for later user VA reads/writes. `d*` commands accept `/process <pid>` for one-shot process-aware access, while native `e*` virtual writes default to the System process context (`pid 4`) and accept `/process <pid>` when a process-specific user VA should be edited. If `e*` is invoked with only an address, the TUI enters a WinDbg-style one-line edit prompt that shows the current value, accepts replacement values, and cancels on an empty line, `.`, `q`, or `quit`. These paths translate each VA range before access. Reads use physical pages, translated user VA writes use physical writes through the selected process context, and kernel VA writes use the original virtual address after any required page-table write-enable step. When a translated leaf PTE/PDE/PDPTE is present but not writable, `e*` temporarily sets the write bit on that leaf entry, flushes the virtual address, performs the edit, restores the write bit to its original state, and flushes again. The driver walks x64 paging structures through physical reads, reports PML5E/PML4E/PDPTE/PDE/PTE entries when applicable, handles 4 KB, 2 MB, and 1 GB pages, and returns the number of contiguous bytes remaining in the translated page. Physical reads are available through both native names (`phys`, `pdb`, `pdw`, `pdd`, `pdq`) and WinDbg-style extension names (`!db`, `!dw`, `!dd`, `!dq`). Physical writes are available through both native names (`peb`, `pew`, `ped`, `peq`) and WinDbg-style extension names (`!eb`, `!ew`, `!ed`, `!eq`), and are routed through page-sized `MmMapIoSpaceEx` mappings with `MmGetVirtualForPhysical` fallback when Windows already has a direct mapping for the PFN. Address-only physical enter commands prompt with the current physical value before writing, matching the native `eb` edit flow. Write mode is enabled by default for each device handle; use `write off` when you want a read-only console session.

## Memory Dumps

Two file-emitting commands turn live kernel memory into on-disk artefacts for offline triage in IDA, Ghidra, or hex editors:

```text
dump-raw <address> <length> <path> [/zerofill]
dump-pe <address> <path>
```

`dump-raw` reads `<length>` bytes starting at `<address>` and writes them verbatim. The read is chunked into 256 KB IOCTL calls (matching the driver's read window). The default behaviour aborts on the first per-chunk failure and reports the failing VA; pass `/zerofill` to fall back to zero-filling the failed chunk and continuing -- useful when sweeping ranges that straddle unmapped or paged-out pages. The total request is capped at 1 GB as a sanity guard.

`dump-pe` rebuilds an on-disk PE image from a kernel-loaded module. It:

1. Reads the first 4 KB at `<address>` and validates `IMAGE_DOS_HEADER.e_magic == 'MZ'`, follows `e_lfanew` to `IMAGE_NT_HEADERS`, and validates the `'PE\0\0'` signature. Both PE32 and PE32+ are supported; the scanner extracts `SizeOfHeaders`, `NumberOfSections`, `SizeOfImage`, `ImageBase`, and `Machine` from whichever optional header is present.
2. Re-reads the headers buffer if `SizeOfHeaders > 4 KB` (rare but possible on builds with hefty `IMAGE_DATA_DIRECTORY` payloads), then locates the `IMAGE_SECTION_HEADER[]` table and computes the output file size as `max(SizeOfHeaders, max_over_sections(PointerToRawData + SizeOfRawData))`.
3. Copies the in-memory headers verbatim to the output (preserving any loader patches), then for each section reads `SizeOfRawData` bytes from `<address> + VirtualAddress` and writes them at file offset `PointerToRawData`, reversing the loader's RVA-to-disk-offset expansion.
4. Sections whose reads fail (typically discarded `INIT` sections in KMDF drivers; sometimes paged-out `.pdata`/`.rdata`) are zero-filled and surfaced as `[ZERO-FILLED]` per-section warnings, so the final file remains a structurally-valid PE that IDA/Ghidra can still load.

**Header recovery**: malware modules (and some kernel-mode loaders) zero out the `MZ` and/or `PE\0\0` signatures, and sometimes the `e_lfanew` pointer too, to evade naive memory scanners. `dump-pe` recovers from this when the rest of the `IMAGE_FILE_HEADER` / `IMAGE_OPTIONAL_HEADER` is intact:

1. **MZ wiped**: if `e_lfanew` still points to a plausible NT header (Machine != 0, NumberOfSections in 1..96, OptionalHeader.Magic == `0x10b`/`0x20b`, SizeOfOptionalHeader matches the Magic), the scanner restores `IMAGE_DOS_SIGNATURE` at offset 0.
2. **PE\\0\\0 wiped**: if `e_lfanew` is correct but the 4-byte signature there is zero (or anything other than `0x00004550`), the scanner accepts the location if the trailing FileHeader/OptionalHeader still looks like a real PE and writes back the canonical `'PE\0\0'`.
3. **e_lfanew corrupted**: the scanner sweeps 4-byte-aligned offsets from `0x40` up to `0x1000`, looking for a region that passes the FileHeader+Magic plausibility test, then rewrites `e_lfanew` to point at the discovered offset (along with restoring `MZ` and `PE\0\0` if also wiped).
4. **DOS header partially or fully wiped, NT headers intact**: handled as a superset of cases 1+3.

Whatever was repaired is surfaced both as per-restore lines in `dump-pe warning:` and as a coloured `recovered=[MZ,e_lfanew,PE]` tag in the final summary line. If the NT headers themselves are also gone (no plausible FileHeader+Magic anywhere in the first 4 KB), the scanner reports `could not locate IMAGE_NT_HEADERS even after attempting signature recovery` rather than guessing.

```text
dump-raw nt!KiSystemServiceUser 0x200 .\kiSystemServiceUser.bin
dump-raw 0xffffae8000123000 0x10000 .\pool-region.bin /zerofill
dump-pe nt .\ntoskrnl-live.exe
dump-pe Wdf01000 .\wdf01000-live.sys
```

Caveats:

- The dumped PE reflects the live image state: relocations are applied (so RVAs in the file body point at `ImageBase + RVA` rather than zero-relative), the IAT slots hold resolved function pointers (not import descriptor RVAs), and any in-place patches by anti-malware, HVCI, or PatchGuard appear in the output. Use this for analysing the running image, not for repackaging an installable binary.
- Paths that contain whitespace are accepted when wrapped in double quotes -- `dump-pe nt "C:\Program Files\Dumps\ntoskrnl-live.exe"` works the same as `dump-pe nt .\ntoskrnl-live.exe`. The argument tokenizer recognises `"..."` as a literal region and supports mixed quoted/unquoted concatenation within a single token. Apostrophes are kept literal in unquoted paths (matching CMD/PowerShell convention) so names like `O'Brien\foo.sys` need no quoting.
- Both commands require the `KnLiveDbg.sys` driver device to be open. Symbol-based addresses (e.g., `nt`, `Wdf01000`, `nt!ExpWnfSiloState`) are resolved through the same symbol path as the rest of the TUI.

## Address Inspection

`!address <va>` is the WinDbg-style introspection for a single virtual address. It answers "what is this pointer, and what can be done to it" in one go:

```text
!address <va>
```

Output breakdown:

1. `[address]` -- canonicality (bits above 47 / 56 must all match), kernel vs user half, `[zero-page]` flag for the first 4 KB, `paging=LA57` when 5-level paging is active.
2. `[address.module]` (when the address falls inside a loaded kernel module range) -- image name, base, size, offset within the module, full image path.
3. `[address.symbol]` (when DbgHelp/DIA can resolve a nearest symbol) -- symbol name plus byte displacement.
4. `[address.translation]` -- live CR3, number of paging levels walked, page size, and per-level PML5E/PML4E/PDPTE/PDE/PTE values along with their physical addresses. Each entry is annotated `(P=W=U=PS=NX=)` so the operator can see exactly where access is gated.
5. `effective:` -- aggregated permissions across every walked level: present = AND of bit 0, writable = AND of bit 1, executable = AND of `(!NX)`, user-accessible = AND of bit 2. A `[W+X]` red tag fires when the page is both writable and executable in the effective state.
6. `[address.physical]` -- resulting physical address, byte offset inside the page, and the byte count guaranteed contiguous by the driver translation pass.

Examples:

```text
knkd> !address nt!ExpWnfSiloState
knkd> !address 0xffffe78fcd778000
knkd> !address WdFilter+0x1234
```

Symbolic forms (`nt!XXX`, `module+0xNN`, hex/decimal values, address expressions) are accepted through the same parser used elsewhere in the TUI. Non-canonical inputs short-circuit before TranslateVirtual and report a warning instead of issuing an IOCTL that would fail deterministically.

## Module And Driver Integrity

`!module integrity` and `!driver integrity` are read-only live integrity checks for common anti-cheat/rootkit surfaces:

```text
!module integrity [module|all] [/summary] [/verbose] [/headers] [/sections]
                  [/wx] [/mismatch] [/limit <n>] [/json <path>]
!driver integrity [driver|all] [/limit <n>] [/json <path>]
```

`!module integrity` reads loaded kernel module PE headers from live memory, validates PE signatures, optional-header bounds, `SizeOfImage`, `SizeOfHeaders`, alignments, data directories, and section ranges, then page-walks executable/`.text` section first/last pages to flag static or effective W+X evidence. Console output stays compact by default; `/summary` suppresses records, `/verbose` shows every reported module and section, `/headers` prints PE header evidence, `/sections` prints all sections, `/wx` filters to W+X evidence, and `/mismatch` filters to size/header/section mismatch evidence. JSON output uses the stable `kn-live-dbg.module-integrity.v1` schema with summary counts, warnings, module reason codes, section reason codes, page-probe state, and notes for baseline diffing. `!driver integrity` walks `\Driver`, decodes `_DRIVER_OBJECT` fields from PDB/DIA metadata, annotates `MajorFunction[]` handlers with module/symbol ownership, and flags dispatch pointers outside loaded modules or redirected into another non-kernel driver image.

Examples:

```text
knkd> !module integrity ntoskrnl
knkd> !module integrity all /summary
knkd> !module integrity all /wx /verbose
knkd> !module integrity ntoskrnl /headers /sections
knkd> !module integrity all /limit 20 /json .\module-integrity.json
knkd> !driver integrity WdFilter
knkd> !driver integrity all /json .\driver-integrity.json
```

## BYOVD Intelligence Scan

`byovd` (also accepted as `!byovd`) scans the currently loaded kernel module list against a local BYOVD catalog. The catalog is generated by `tools\update-byovd-intel.ps1` from the Microsoft vulnerable driver blocklist ZIP/XML plus LOLDrivers hash and YARA feeds. `byovd scan` automatically refreshes the local catalog under `<exe-dir>\data\byovd` when it is missing or older than 24 hours; use `/no-update` to force offline/reproducible mode or `/force-update` to refresh before scanning.

```text
byovd [scan] [/no-update] [/force-update] [/exact] [/verbose] [/summary]
             [/limit <n>] [/json <path>]
!byovd [scan] [/no-update] [/force-update] [/exact] [/verbose] [/summary]
              [/limit <n>] [/json <path>]
byovd scan /yara [/yara-path <exe>] [/yara-timeout <seconds>]
byovd update [/force]
byovd status
byovd fixture [status|load [sys-path]|unload|path]
```

The scanner hashes each loaded module image on disk with MD5/SHA1/SHA256. Exact hash matches against Microsoft or LOLDrivers entries are reported as `HIGH` confidence. Microsoft file-attribute rules are also matched by file name plus PE file version and reported as `MEDIUM` confidence. The scanner reads PE version-info vendor metadata and suppresses third-party file-attribute hints against Microsoft-owned OS binaries, but full WDAC signer/certificate constraints are not yet enforced in this slice. `/exact` suppresses those name/version hints when the operator wants hash-only evidence.

`/yara` additionally runs the downloaded LOLDrivers YARA files under `<exe-dir>\data\byovd\yara` against each loaded module image on disk. YARA execution uses an external `yara64.exe` / `yara.exe`, but release packages intentionally do not include YARA binaries. Install YARA separately, put it on `PATH`, or use `/yara-path <exe>` to pin a specific binary. KnLiveDbg also searches the EXE directory, `tools\`, development parent `tools\` directories, and the current working directory's `tools\` for operator-supplied binaries. `/yara-timeout <seconds>` caps each driver/rule invocation; the default is 30 seconds and accepted range is 1..600 seconds. YARA hits are emitted as `HIGH` confidence with `source=loldrivers_yara` and `match_type=yara`. JSON output uses `kn-live-dbg.byovd-scan.v1` and includes `summary.yara_*`, `yara.executable`, and `yara.rule_files`.
`summary.yara_scans` counts attempted YARA process invocations, while `summary.yara_failures` and `summary.yara_timeouts` split out failed or timed-out attempts.

`byovd fixture load` installs and starts the bundled no-op fixture driver `amdryzenmasterdriver.sys`. The driver creates no device, exposes no IOCTLs, and only sets `DriverUnload`; its file name and fixed PE version `1.0.0.0` are intentionally chosen to satisfy a Microsoft vulnerable-driver file-attribute rule so the scanner should report a `MEDIUM` signer-unverified hit. This fixture is for testing the name/version path only. `HIGH` exact-hash testing should use a test-only local catalog entry for a benign sample hash, not a real vulnerable driver binary.

Positive-control flow:

```text
knkd> byovd update
knkd> byovd fixture load
knkd> byovd scan /no-update /verbose
...
[byovd.hit] image=amdryzenmasterdriver.sys ... version=1.0.0.0 ...
  [byovd.match] confidence=MEDIUM source=microsoft_blocklist category=microsoft_file_attribute type=file_version name=amdryzenmasterdriver.sys versionRange=0.0.0.0..1.5.0.0
knkd> byovd fixture unload
```

If the fixture fails to load before the scan, treat that as a platform policy result first: HVCI, Secure Boot, test-signing state, and the Windows vulnerable-driver blocklist can prevent a driver that intentionally matches a Microsoft blocklist rule from loading. In that case the scanner has no loaded module to report; use a test VM with the intended code-integrity policy, or validate the catalog/status path with `byovd status` and updater tests.

Examples:

```text
knkd> byovd
knkd> byovd scan /exact
knkd> byovd scan /yara
knkd> byovd scan /yara /yara-path C:\Tools\YARA\yara64.exe /yara-timeout 15
knkd> byovd scan /force-update /json .\byovd-scan.json
knkd> byovd update
knkd> byovd status
knkd> byovd fixture load
knkd> byovd scan
knkd> byovd fixture unload
```

## Big Pool PE Hunting

`pool-scan-pe` combines the big pool enumerator with the `dump-pe` plausibility-gated PE header detector to surface hidden / reflectively-loaded modules camped in `nt!PoolBigPageTable` allocations. The detector accepts both intact and signature-wiped PE headers, so the common malware pattern of zeroing `MZ` / `PE\0\0` / `e_lfanew` to evade scanners no longer hides the payload.

```text
pool-scan-pe [/tag <ABCD>] [/min <bytes>] [/max <bytes>] [/limit <n>]
             [/nonpaged|/paged|/any] [/suspicious] [/dump <directory>]
```

How it works:

1. Same enumeration path as `!pool`: enable `SeDebugPrivilege`, call `NtQuerySystemInformation(SystemBigPoolInformation=0x42)`, then iterate big pool entries after applying the paged-class, tag, and size filters.
2. For each kept entry, read the first 4 KB through the driver `ReadMemory` IOCTL on the safe `MmCopyMemory` path and run `ProbeForPeHeader`. The probe tries `e_lfanew` first; on miss it sweeps 4-byte-aligned offsets `0x40..0x1000` looking for a plausible `IMAGE_NT_HEADERS` (Machine != 0, NumberOfSections in `1..96`, SizeOfOptionalHeader `0xF0`/`0xE0`, OptionalHeader.Magic `0x10b`/`0x20b`, SizeOfHeaders in `(0, 0x10000]`, SizeOfImage in `(SizeOfHeaders, 256 MB)`).
3. Each hit is annotated with whether `MZ`, `PE\0\0`, and/or `e_lfanew` were wiped. Hits with any wipe are highlighted in red with a `WIPED=[MZ,e_lfanew,PE]` tag and also counted against `suspicious` in the summary line; intact-header PE images print in the regular `[pool-pe.hit]` form for completeness.
4. With `/dump <directory>`, each hit is written to disk through `DumpKernelPeToFile`, which performs the same signature-recovery and section walking as the standalone `dump-pe` command. The output filename pattern is `poolpe_<tag>_<address>.bin`; the directory is created if missing.

```text
[pool-pe.hit]     address=0xffffae8000123000 size=0x10000 tag=Wmem NonPaged nt=0x100 bits=64 machine=0x8664 sections=5 sizeOfImage=0xa000 imageBase=0x...
[pool-pe.suspect] address=0xffffae8000777000 size=0x18000 tag=Cdat NonPaged nt=0x108 bits=64 machine=0x8664 sections=6 sizeOfImage=0x14000 imageBase=0x0 WIPED=[MZ,e_lfanew,PE]
[pool-pe.summary] total=18324 nonpaged=5012 paged=13312 scanned=4988 readFail=4 hits=2 suspicious=1
```

Notes:

- The probe runs on the first 4 KB only -- enough to cover DOS header + NT header + section table for virtually every PE. Allocations smaller than `sizeof(IMAGE_DOS_HEADER)` are skipped.
- `/suspicious` collapses output to the wiped-header hits, which are the high-signal cases for malware hunting.
- `/dump` failures (e.g. truly torn-down sections inside the payload) leave a partial PE in the output file with `[ZERO-FILLED]` sections, mirroring `dump-pe` behaviour. The hit still appears in the scan output regardless.
- Default size floor is `0x1000` (one page) since PE images take at least one page. Override with `/min`/`/max` when chasing exotic layouts.

## Threat-Intelligence ETW (`!ti`)

`!ti` subscribes to **Microsoft-Windows-Threat-Intelligence** (provider GUID `f4e1897c-bb5d-5668-f1d8-040f4d8dd344`), the kernel-side ETW provider that EDRs use for sensitive events: `VirtualAlloc` with W+X, cross-process `WriteVirtualMemory`, `QueueUserAPC`, `SetThreadContext`, image-load triggers, driver-object operations, and similar. The provider gates its events on the consumer being a **PPL Antimalware** process, so the typical flow is:

```text
knkd> write on                           # arm driver write mode (acknowledge gate)
knkd> set-ppl-antimalware                # flip self _EPROCESS.Protection to 0x31
knkd> !ti start /name foo.exe            # subscribe; live output only for foo.exe
knkd> !ti watch                          # live tail (Esc or Ctrl+C to detach)
```

Default behaviour is **silent forensic mode**: the in-memory ring (1M events, ~256 MB) and the JSONL log (`ti-events-<timestamp>-<ms>-<pid>.jsonl`, 100 MB rotation × 10) capture every received event, but nothing scrolls the TUI until either `/pid`/`/name` is supplied (which auto-promotes matching events to live output) or `!ti watch` is invoked. Note that `!ti watch` with **no** filter set turns into a firehose because the matcher treats "empty watch set" as "match everything" — add `/pid`/`/name` first on a busy system. Subscription is torn down automatically on hard exit (window close / logoff / system shutdown) via the console control handler, in addition to the normal dtor path on Ctrl+C and `exit`.

Architecture:

1. The subscriber creates an own ETW session via `StartTraceW` and enables the TI provider with `EnableTraceEx2(EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0xFFFFFFFFFFFFFFFF)` so every task ID surfaces.
2. A worker thread runs `ProcessTrace` and receives events through `EventRecordCallback`. Per-PID image resolution is cached (16K-entry bounded) so the hot path does not churn `OpenProcess`/`QueryFullProcessImageNameW`.
3. Each event is decoded via TDH (`TdhGetEventInformation` + `TdhGetProperty`) with array indexing and struct-property guarding. Properties TDH cannot decode fall back to a raw-hex prefix in the JSONL `raw` field.
4. Events are pushed into the ring buffer (oldest-evicted-first when full) and written to the JSONL log. The log rotates by file size with index wrap and oldest-file deletion -- it never grows past `LogRotateBytes * LogRotateCount` on disk.
5. Live output uses a separate bounded queue with a per-second throttle counter; over-throttle events are dropped from the live queue but still hit ring + log, and a `[ti.throttle] suppressed N events` line surfaces in `!ti watch`.

Watch matching is lazy: image-name targets compare against the basename of `_EPROCESS.ImagePath`. Processes that did not exist at `!ti start` time are picked up as soon as their first event arrives; once matched, the PID is promoted into a fast O(1) set so subsequent events for the same process never re-scan the name list.

JSONL line schema (one event per line):

```json
{
  "ts": "2026-05-24T06:30:01.123Z",
  "pid": 4567, "tid": 7890,
  "image": "C:\\path\\to\\foo.exe",
  "task_id": 1, "task": "AllocVM",
  "opcode": 0, "level": 4, "keyword": "0x0",
  "version": 0,
  "payload": { "TargetProcessId": "1234", "BaseAddress": "0xffff...", "RegionSize": "4096", "ProtectionMask": "0x40" }
}
```

Subcommand reference:

- `!ti start [/pid <PID>]... [/name <imageName>]... [/throttle <N>] [/ring <N>] [/log <dir>]` -- begin subscription. Repeatable `/pid`/`/name`. Default throttle 50/s, ring 1M, log directory next to KnLiveDbg.exe.
- `!ti stop` -- end subscription. Ring and log files are retained.
- `!ti status` -- live counters: received / kept / dropped / self-excluded / watch-matched / logged / log-bytes / rotations.
- `!ti add /pid <PID>` or `!ti add /name <imageName>` -- extend watch set without restarting subscription.
- `!ti remove /pid <PID>` or `!ti remove /name <imageName>` -- drop watch target. Removing a name clears the promoted-PID set so it can be rebuilt lazily.
- `!ti watch` -- interactive live tail. Throttled at the configured rate. Press Esc, `q`, or Ctrl+C to detach. Live-output preference is restored after exit so a subscriber that started silent goes back to silent.
- `!ti recent [N]` -- print the last N events from the ring (default 50, capped at 10000).
- `!ti stats` -- histogram by task name and by image basename, computed in place without copying the ring.
- `!ti by pid <PID>` / `!ti by task <substr>` -- ring filter.
- `!ti grep <pattern>` -- case-insensitive substring match across image / task / payload field values.
- `!ti save <path>` -- export the current ring snapshot to JSONL. The snapshot is taken under the ring lock then the disk write happens unlocked so the ETW callback is not stalled.
- `!ti clear` -- empty the ring (does not stop subscription or close the log).

Notes:

- The driver's MDL probe-and-lock fallback (introduced in v0.0.6) is opt-in and now guarded by canonical-system-range plus resident-page preflight, so broad scanners do not page in arbitrary pointer candidates.
- KnLiveDbg.exe's own events are excluded by default to prevent feedback loops. The exclusion is keyed on the current process ID at subscribe time.
- The provider is verbose. On an active desktop, expect thousands of events per second. The ring + log capture everything; the TUI stays calm unless you opt in to live output.

### Usage Recipes

The full prerequisite chain runs the driver, makes the TUI a PPL Antimalware consumer, then subscribes to the provider:

```text
# from an elevated shell
sc query KnLiveDbg       # confirm the driver is loaded
KnLiveDbg.exe            # launches the TUI in this elevated shell

knkd> write on           # arm driver write mode (required by set-ppl-antimalware)
knkd> set-ppl-antimalware    # flip own _EPROCESS.Protection to 0x31
knkd> !ti start          # subscribe (silent forensic mode by default)
```

After this, every event lands in the in-memory ring (1M events) and the JSONL log under the EXE directory. **Capture is automatic once `!ti start` succeeds** -- you do not need `!ti watch` to record events. Use the recipes below depending on whether you want to observe events live, or just collect them for post-hoc analysis.

> **`!ti watch` is optional.** It is purely a real-time scroll of matching events to the TUI. The ring + log capture happens regardless. If you are setting up an unattended capture, or you intend to analyse the JSONL externally with jq/ripgrep, you never need to run watch.

#### 1) Silent forensic mode -- "log everything, scroll nothing"

```text
knkd> !ti start
[ti] subscribed to Microsoft-Windows-Threat-Intelligence (all tasks)
     log directory=...  ring=1048576 throttle=50/s
     watch: <none> (silent forensic mode; use '!ti watch' for live tail)

# ... run workload, do other commands, etc ...

knkd> !ti status
knkd> !ti recent 100
knkd> !ti stop
```

The TUI stays usable for other commands while the ring + log fill. Inspect the ring or the JSONL log offline.

#### 2) Watch a known PID

```text
knkd> !ti start /pid 1234
[ti] subscribed to Microsoft-Windows-Threat-Intelligence (all tasks)
     watch: pid=1234
     live output: enabled for matching events (throttled).

# events from pid 1234 stream live; press Esc to leave watch mode
```

Hex PIDs also accepted: `!ti start /pid 0x4D2` (same as 1234).

#### 3) Watch a name that has not started yet -- malware sandbox

```text
knkd> !ti start /name suspicious.exe
[ti] ...
     watch: name=suspicious.exe

# launch the sample in another terminal
> suspicious.exe

# events appear the moment the sample's first ETW event arrives.
# The match works because watch is lazy on the image basename, not the PID.
```

This is the typical sandbox flow: subscribe first, then detonate.

#### 4) Watch by name AND PID -- multiple targets

```text
knkd> !ti start /pid 1234 /name foo.exe /name bar.exe
```

Repeatable `/pid` and `/name`. PID matches go through an O(1) set; name matches scan the (small) name list once, then the matched PID is auto-promoted into the same fast set for subsequent events.

#### 5) Add or remove targets without restarting the subscription

```text
knkd> !ti start             # silent mode
knkd> !ti add /pid 5678     # later, decide to track 5678 live
knkd> !ti add /name dropper.exe
knkd> !ti remove /pid 5678
knkd> !ti remove /name dropper.exe
```

`add` automatically promotes events to the live queue (if live output is on). Removing a name clears the promoted-PID set so the lazy re-match rebuilds.

#### 6) (Optional) live tail an existing subscription

`!ti watch` is purely for real-time observation. It does not start or stop capture -- the ring and log are filling either way.

```text
knkd> !ti start             # silent, no targets, capture is already running
# ... time passes, you want to look at activity ...
knkd> !ti watch
[ti.watch] live tail engaged. press Ctrl+C or Esc to detach (subscription stays up).
[06:42:11.123] AllocVM      pid=4567 image=foo.exe {...}
[06:42:11.456] WriteVM      pid=4567 image=foo.exe {...}
...
[ti.throttle] suppressed 87 events in the last window
# press Esc -> live output preference restored to the pre-watch value
knkd> !ti status
```

`!ti watch` temporarily enables live output for every event (subject to throttle), and `Esc`/`q`/`Ctrl+C` restores the previous live-output setting. Silent subscribers go back to silent after watch exits.

If you never want live scroll, you never have to run `!ti watch`. Use `!ti recent`, `!ti by`, `!ti grep`, `!ti save`, or jq on the JSONL log instead.

#### 7) Reduce noise or expand cap -- throttle adjustment

```text
knkd> !ti start /name chrome.exe /throttle 200      # 200 events/s cap for chrome
knkd> !ti start /name chrome.exe /throttle 5        # very quiet, scannable by eye
```

The ring + log are unaffected; throttle only gates the live print queue.

#### 8) Bigger ring for long-running captures

```text
knkd> !ti start /ring 0x400000   # 4M events (~1 GB RAM)
```

`/ring` accepts hex or decimal. Default 1M (~256 MB). Each ring event holds wide-string fields so memory cost scales with the average payload size.

#### 9) Custom log directory

```text
knkd> !ti start /log "D:\hunts\session-001"
```

The directory is created on demand. Filenames are `ti-events-YYYYMMDD-HHMMSS-mmm-PID.jsonl` for the active file and `ti-events.<N>.jsonl` for rotated slots. Rotation wraps at 100 MB x 10 by default, deleting the oldest before overwriting.

#### 10) Query the ring after the fact

```text
knkd> !ti stop                       # stop subscription, ring + log are preserved
knkd> !ti recent 200                 # last 200 events, newest first
knkd> !ti stats                      # histogram by task and by image basename
knkd> !ti by pid 1234                # ring filter on a specific PID
knkd> !ti by task AllocVM            # ring filter (substring) on task name
knkd> !ti by task WriteVM            # cross-process write events
knkd> !ti by task ProtectVM          # protection-change events
knkd> !ti grep TargetProcessId       # case-insensitive grep across payload
knkd> !ti grep 0x140000              # look for image-base loads
```

`recent` is capped at 10 000 to keep the TUI responsive. `by` / `grep` cap at 200 matches per call.

#### 11) Export a snapshot to a separate file

```text
knkd> !ti save D:\hunts\session-001\snapshot.jsonl
[ti.save] wrote D:\hunts\session-001\snapshot.jsonl
```

The snapshot uses the same JSONL schema as the rotated log. Useful for capturing the current state without waiting for log rotation. Ring lock is released before the disk write so the ETW callback is not stalled.

#### 12) Clear the ring (start fresh without restarting subscription)

```text
knkd> !ti clear              # ring drained; log untouched
```

#### 13) Process injection hunt -- end-to-end

`/name target.exe` catches **both** sides: events the target itself fires AND cross-process operations (`VirtualAllocEx`, `WriteProcessMemory`, `QueueUserAPC`, `SetThreadContext`, ...) fired BY a loader against the target. The matcher walks the payload for `TargetProcessId`-like fields, resolves the basename of the referenced PID through the same cache the callback uses, and matches against `/name`. So you see "loader -> target" injections without having to know the loader's name in advance.

Two valid flows. Pick based on whether you want to watch events live or just collect a trace for offline analysis.

**A. Offline / unattended capture (no watch):**

```text
knkd> write on
knkd> set-ppl-antimalware
knkd> !ti start /name target.exe          # capture begins; nothing scrolls

# in another terminal, run the loader:
> loader.exe target.exe

# back in the TUI, query the ring at any point. Live tail not required.
knkd> !ti status
knkd> !ti by task WriteVM         # cross-process writes into target.exe
knkd> !ti by task SetThreadContext
knkd> !ti by task QueueUserApc
knkd> !ti save .\injection-trace.jsonl
knkd> !ti stop
```

**B. Interactive triage (live watch):**

```text
knkd> write on
knkd> set-ppl-antimalware
knkd> !ti start /name target.exe
knkd> !ti watch                            # live tail; same ring + log fills

# in another terminal, run the loader:
> loader.exe target.exe

# events scroll in the TUI as they fire. Press Esc to detach when done.
knkd> !ti by task WriteVM
knkd> !ti save .\injection-trace.jsonl
knkd> !ti stop
```

Both flows produce the same `injection-trace.jsonl` and the same ring contents. The JSONL has one line per event, jq/ripgrep friendly:

```bash
# from PowerShell / cmd:
type .\injection-trace.jsonl | findstr WriteVM
# or with jq if installed:
jq -c 'select(.task=="WriteVM") | {ts, pid, image, payload}' injection-trace.jsonl
```

#### 13.5) Game-cheat alloc into a victim -- cheatengine -> notepad

The classic ETW demo: open notepad, attach Cheat Engine to it, perform `VirtualAllocEx(notepadPid, ..., PAGE_EXECUTE_READWRITE)`.

```text
knkd> write on
knkd> set-ppl-antimalware
knkd> !ti start /name notepad.exe
knkd> !ti watch                # optional; events also flow to the ring and log

# in a separate shell:
> notepad.exe
> cheatengine.exe -> attach to notepad -> allocate executable buffer

# expected event in the live tail (line wrapped here for readability):
[12:07:27.073] KERNEL_THREATINT_TASK_ALLOCVM
  pid=4892 tid=2968 image=cheatengine.exe
  -> target=notepad.exe(pid=8804)
  {CallingProcessId=4892, ..., TargetProcessId=8804,
   BaseAddress=0x..., RegionSize=4096, ProtectionMask=0x40, +5 more}
```

The header shows `image=cheatengine.exe -> target=notepad.exe(pid=8804)` because the matcher caught the target-side reference even though the ETW event itself fired from Cheat Engine's PID.

#### 14) Cross-process W+X allocation hunt (no watch needed)

```text
knkd> !ti start                       # silent, full capture, no live scroll
# ... run / wait for the suspicious workload ...
knkd> !ti by task AllocVM             # all VirtualAlloc-class events
knkd> !ti grep ProtectionMask=0x40    # PAGE_EXECUTE_READWRITE (RWX)
knkd> !ti save .\wx-trace.jsonl
```

This recipe explicitly skips `!ti watch` -- the silent ring fills in the background while you keep the TUI free for `!pool` / `pool-scan-pe` to chase the resulting allocation in big pool.

#### 15) Cleanup at session end

```text
knkd> !ti stop                  # end ETW subscription, keeps ring + log
knkd> !ti save .\session.jsonl  # optional export
knkd> !ti clear                 # optional drop the ring (frees ~256 MB)
knkd> exit                      # destructor double-checks the session is torn down
```

`exit` (or process termination) also calls the subscriber destructor which invokes `Stop` if the session is still active, so a forgotten `!ti stop` is recovered automatically.

#### Useful task names for `by task` filtering

The provider exposes many task IDs; the most actionable for malware / cheat hunting are:

| Task name (substring OK) | What it captures |
|---|---|
| `AllocVM` | `NtAllocateVirtualMemory` (incl. cross-process via `pid != self`) |
| `ProtectVM` | `NtProtectVirtualMemory` (often the W+X pivot for shellcode) |
| `MapView` | `NtMapViewOfSection` |
| `WriteVM` | `NtWriteVirtualMemory` (classic cross-process injection) |
| `ReadVM` | `NtReadVirtualMemory` |
| `QueueUserApc` | Cross-thread / cross-process APC injection |
| `SetThreadContext` | RIP redirection on a remote thread |
| `Suspend` / `Resume` | Cross-process thread control |
| `Driver` | Driver-object operations |
| `LdrPreload` | LDR-data preload trigger |

Combine with `!ti by task <name>` for filtered ring listings or `!ti grep <name>` for fuzzier searches.

Cross-process events (`AllocVM`, `ProtectVM`, `WriteVM`, `ReadVM`, `MapView`, `QueueUserApc`, `SetThreadContext`, `Suspend`/`Resume`) carry a `TargetProcessId` payload field; `/name <victim>` matches them via the resolved target basename, so a loader injecting into `notepad.exe` is caught by `/name notepad.exe` even though the event fires from the loader's PID. The live-tail header surfaces this as `image=loader.exe -> target=notepad.exe(pid=...)`.

#### Common gotchas

- **Forgot `write on` before `set-ppl-antimalware`**: the driver IOCTL returns `STATUS_ACCESS_DENIED`. Fix: `write on` first.
- **Forgot `set-ppl-antimalware` before `!ti start`**: the pre-check refuses with a clear hint pointing at `set-ppl-antimalware`. Fix: run it, retry.
- **Tried to scroll the prompt while in `!ti watch`**: keystrokes are captured by the watch loop and swallowed. Press `Esc`/`q` first to detach.
- **Same name run multiple times**: each launch gets a new PID, name match auto-promotes each one. Use `!ti by pid <PID>` to disambiguate after the fact.
- **`/name not.exe` does not match `notepad.exe`**: name matching is exact basename, not substring. Use `!ti grep not` for substring search over the ring.
- **`!ti watch` with no filter floods the TUI**: empty watch set means "match everything", so on a busy system the throttle (50/s by default) is constantly engaged and the `[ti.throttle] suppressed N events` banner dominates. Add `/pid` or `/name` filters before watching, or raise the throttle with `/throttle`.
- **Forgot `!ti stop`?** The subscriber's destructor calls Stop on normal exit (`exit`, Ctrl+C), and the console control handler calls Stop on hard exit (window close, logoff, shutdown). A clean teardown happens in every path except `TerminateProcess`. After a TerminateProcess, recover with `logman stop KnLiveDbg-Ti -ets`.

## Positive-Control Probe

`KnLiveDbgProbe.sys` is an optional test driver that exposes a deterministic 4 KB contiguous nonpaged buffer and registers a test firmware table provider with signature `KNFW`. It is intended for smoke tests of virtual reads, VA-to-PA translation, physical reads, physical writes, firmware-table provider detection, and restore flows without guessing at arbitrary kernel memory.

```text
probe load
probe status
probe info
db <probe-virtual-address> 40
pdb <probe-physical-address> 40
probe reset
probe unload
```

The buffer pattern is `(index * 13 + 0x5a) & 0xff`. `probe info` prints both the virtual and physical buffer addresses, firmware provider registration status, and example `db`/`pdb`/`!fwtable` commands. After `probe load`, `!fwtable provider KNFW` should report `KnLiveDbgProbe.sys` as a suspicious nonstandard provider; `probe unload` unregisters it.

## Operational Caveats

1. This is a live kernel memory tool. Bad writes can crash or corrupt the machine.
2. `MmCopyMemory` makes reads fault-tolerant, but it does not make all addresses meaningful.
3. Writes are enabled by default, can be disabled with `write off`, and still require an IOCTL acknowledgment magic.
4. Native VA-to-PA translation supports x64 4-level paging and active LA57 five-level paging, and reports which paging depth was used for each walk.
5. Physical memory writes can corrupt page tables, code, pool, device memory, or firmware-owned ranges.
6. Type dumping depends on matching PDBs and the local `DbgHelp`/DIA behavior.
7. Callback enumeration depends on internal kernel symbols and type names. Field drift is reported as a warning; Filter Manager callback decoding depends on matching `fltmgr` private type layouts.
8. Do not hard-code kernel structure offsets for production use; resolve them from symbols at runtime.
9. Live loading requires test-signing or another valid code integrity path.
10. Native mode intentionally differs from full WinDbg for commands that stop or control the target. Use `backend dbgeng` for DbgEng-backed command execution, and still expect local-kernel debugging limitations.
11. `!wfp` requires a healthy Base Filtering Engine (`BFE`) service for the user-mode `FwpmEngineOpen0` path; it does not enumerate WFP state from a hung BFE or a dead system, and it does not surface kernel-mode callout function pointers because the user-mode `FWPM_CALLOUT0` shape does not expose them.
12. `!alpc` enumerates only ports reachable through the Object Manager namespace and through `_ALPC_PORT.CommunicationInfo` linkage; anonymous client ports that never reach a named server port are not enumerated, and queue counts depend on PDB exposure of the per-port `MainQueue`/`PendingQueue`/`LargeMessageQueue`/`CanceledQueue`/`WaitQueue` fields. PDB drift in `_ALPC_PORT` may produce a warning and reduce the field set rather than aborting the scan.
13. `!vbs` / `!ci` / `!securekernel` rely on `nt!g_CiOptions`, `nt!HvlpVsmVtlCallVa`, and `_KPROCESS.SecureState`. The exact symbol names drift across Windows builds, the trustlet bit field is private PDB territory, and MBEC enablement requires kernel-only MSR reads. The report annotates each missing source as a warning and falls back to well-known trustlet image-name prefixes when the secure-state field cannot be resolved.
14. `!etw` falls back to documented offsets `0x68` (LoggerName) and `0x28` (GetCpuClock) when `_WMI_LOGGER_CONTEXT` is not exposed in the loaded PDB. Those offsets drift between Windows builds; a warning is emitted on the fallback path. `!nmi` requires `nt!KiNmiCallbackListHead` (or `nt!KiNmiCallbackList`) to be resolvable from the PDB; if both fail, signature-based extraction from `KeRegisterNmiCallback` is not yet implemented and the scanner reports the resolution failure as an error.
15. `!fwtable` requires `nt!ExpFirmwareTableProviderListHead` to be resolvable. If private provider-node types are absent, it scores guarded x64 fallback candidates against live nodes and normally selects the `SYSTEM_FIRMWARE_TABLE_HANDLER`-fields-first layout (`ProviderSignature +0x00`, `Register +0x04`, `FirmwareTableHandler +0x08`, `DriverObject +0x10`, `LIST_ENTRY +0x18`). It flags handler addresses outside loaded kernel images and DriverObject owners whose `DriverStart` is unreadable, null, or outside loaded modules. It intentionally does not probe table IDs or call `EnumSystemFirmwareTables` / `GetSystemFirmwareTable` by default because those paths can execute registered provider handlers.
16. `!wnf` live walking depends on the loaded PDB exposing `nt!ExpWnfSiloState` (or alias), an AVL-table field on `_WNF_SUBSCRIPTION_TABLE`/`_WNF_SILODRIVERSTATE`/`_WNF_PROCESS_CONTEXT`, and `_WNF_NAME_INSTANCE.StateName`. Modern Win10/11 PDBs sometimes withhold these private types; when missing, the scanner clearly identifies the missing piece and the `decode` subcommand remains fully functional. `!wnf data` follows `LastDataBlock` and probes common buffer offsets, so a returned payload should still be treated as advisory until the WNF state data layout for that specific build is verified.
17. On Windows builds where Microsoft has migrated WNF subscription tracking away from `RTL_AVL_TABLE` (or moved it into a per-process `_WNF_PROCESS_CONTEXT`), the legacy AVL chain returns zero candidates. The modern LIST_ENTRY heuristic walker handles these builds by enumerating `_WNF_NAME_INSTANCE` chains hanging off the silo state struct, scoring each list by the count of UNIQUE state-name-shaped values, and walking the top-ranked list. The `decode` subcommand remains a fully-working day-to-day utility regardless.
18. **`!wnf` state-name slot in LIST_ENTRY mode is currently transient -- known open issue.** On the modern Win11 layout the walker extracts state names from the first `0x000001030000XXXX` (WNF schema-marker) value found in `+0x10..+0x38` of each `_WNF_NAME_INSTANCE` entry. The 0x103 prefix is correct, but the specific slot we hit is not the canonical immutable state name: re-reading the same entry address returns different values across runs (even for `Permanent` lifetimes that should never change). The data block reference at `+0x88` and the entry address itself are stable; only the printed `state=` field drifts. Open follow-up: reverse-engineer the canonical state-name offset within the modern `_WNF_NAME_INSTANCE` layout (likely past `+0xC0`) and switch extraction to that fixed slot, which will also make symbolic-name DB lookups (Ionescu wnfdump etc.) actionable. Until that lands, prefer entry addresses for stable lookup and `!wnf data` for payload investigation.
19. `!wnf data` on the LIST_ENTRY path heuristically locates the `_WNF_DATA_BLOCK` descriptor by scanning the first `0x200` bytes of the matched entry for kernel-canonical pointers whose dereferenced 16-byte header matches the documented `_WNF_DATA_BLOCK` layout (`DataSize @ +0x00`, `AllocatedSize @ +0x04` with `DataSize <= AllocatedSize` and `AllocatedSize <= 0x1000`, `ChangeStamp @ +0x08` UINT64). The slot is consistently at entry `+0x88` on the Win11 builds tested so far, but the walker probes adaptively and emits a per-pointer census diagnostic when no candidate validates so operators can manually identify the slot on different builds. `AllocatedSize` is treated as the user-requested size (not pool-aligned), so no alignment assumption is enforced.
20. `!wnf` subscriber and owning-process resolution has converged on a working multi-layer view. Each `_WNF_NAME_INSTANCE` exposes a LIST_ENTRY chain at entry `+0x48`; field testing established that this chain is NOT a subscription-only list but a generic per-entry tracked-objects list mixing real WNF subscription records with other process-scope kernel objects (Section / NTFS / SeAt / AlVi / AlRe / PnpY / ObNm / CMNb / DCxx / APpt / DxgK / SLS / Ustm / PcwC / ClfA / SeSd / RvaL / ...). The walker (a) extracts each node's pool tag from `nodeBytes[+0x14]` (POOL_HEADER sits at `+0x10`), (b) classifies nodes by tag (`Ntfc` / `Wnf ` / `WnfN` = real subscriber; everything else = backing/related kernel object), (c) resolves the entry's stable owning EPROCESS from the prefix slot at `node-0x30` (100% recovery rate on entries with at least one chained node in field testing), and (d) attempts shape-only EPROCESS resolution for individual nodes via PDB-resolved `_EPROCESS.UniqueProcessId` (must be 4-aligned, `0 < pid <= 0x100000`) AND `ImageFileName` (must be `>= 3` printable-ASCII chars). Node candidates whose pointer falls within `0x200` bytes of the node itself are rejected to suppress same-chunk false positives. The listing path (`!wnf instances`) prints `chained_nodes=N subscribers=X resolved=Y other_objects=Z tags={Ntfc:N Wnf:N Sect:N ...}` per entry and emits only resolved subscriber lines underneath; single-entry views (`!wnf instance`, `!wnf data`) still print every chained node plus prefix/body hex dumps for deeper RE. Open follow-up: some `Ntfc` / `Wnf ` nodes still fail EPROCESS resolution because their per-record subscriber pointer lives outside the first `0x80` bytes -- the full `_WNF_NAME_SUBSCRIPTION` layout (DeliveryEvent / ContextPointer / callback target slots) is still to be reverse-engineered for `pid=N image="..."` to fire on those records too.
21. `!wnf` symbolic state-name lookup is not yet wired up. With the canonical state-name slot still under investigation (caveat 18), the printed `state=` field reflects whichever `0x000001030000XXXX` candidate the walker found in the entry head and is not yet stable across runs for the same logical state. Cross-referencing against published WNF state-name databases (e.g. Ionescu wnfdump, leaked LMK string tables) is therefore deferred until caveat 18 is closed. Once the canonical slot is locked down, the planned follow-up is to ship a static well-known-state-name table that decodes recognized state-names alongside the raw hash + lifetime/scope fields.
