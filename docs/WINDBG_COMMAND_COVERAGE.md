# WinDbg Command Coverage

This project follows the Microsoft WinDbg command reference as the command registry baseline.

Reference pages:

- `Commands`: https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/commands
- `Local Kernel-Mode Debugging`: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/performing-local-kernel-debugging

## Backend Rule

KnLiveDbg currently has a native live-memory backend, not a KD transport backend. This means commands fall into three groups:

1. Native
   - Can be implemented using the current driver, `DbgHelp`, and local system APIs.
   - Examples: virtual/physical memory display/write/search/compare/fill/move, VA-to-PA translation, module list, symbol lookup, type display, explicit disassembly commands.

2. DbgEng-routed
   - The command exists in the WinDbg command surface, but it needs debugger-engine parser or stop-state semantics.
   - In `auto` or `dbgeng` backend mode, these commands are routed to DbgEng.
   - Examples: execution control, breakpoints, stack walking, registers, source commands, exception commands, I/O port commands.

3. Extension commands
   - Any `!<extension>` command is recognized as an extension command.
   - In `auto` or `dbgeng` backend mode, extension commands are routed to DbgEng.

4. Meta-commands
   - Any unknown `.<command>` is recognized as a WinDbg meta-command.
   - The native backend implements `.sympath`, `.sympath+`, and `.reload`; other meta-commands are routed to DbgEng in `auto` or `dbgeng` mode.

## Backend Commands

```text
backend [auto|native|dbgeng]
kdinit [/local [connect-options]|/remote <connect-options>]
kd <windbg-command>
kddetach
home|dashboard
probe [status|load [sys-path]|info|reset|unload]
ai [status|providers|provider|policy|model|baseurl|effort|auth|preview|ask|plan|analyze|explain|annotate|diagnose|playbook|show|run|write|transcript|audit|report]
```

`auto` is the default. Native commands stay on the custom driver backend, while DbgEng-routed commands and extension/meta commands are sent to DbgEng when possible.

Backend mode differences:

| Mode | Native handlers | DbgEng fallback | Typical use |
| --- | --- | --- | --- |
| `auto` | Enabled for implemented live-memory commands. | Enabled for DbgEng-routed commands, `!extension` commands, and unknown `.meta` commands. | Normal mixed operation. |
| `native` | Enabled. | Disabled except for explicit raw escapes such as `kd`. | Verifying driver-backed behavior without accidental raw WinDbg execution. |
| `dbgeng` | Only session/TUI exceptions run before the raw DbgEng catch-all. | Enabled for most commands through `IDebugControl4::ExecuteWide`. | WinDbg parser, stop-state, extension, breakpoint, register, stack, source, trace, and exception commands. |

The `dbgeng` catch-all intentionally excludes `q`, `qq`, `qd`, `quit`, `exit`, `unload`, `drvstatus`, `home`, `dashboard`, `probe`, `procctx`, `callbacks`, `kcallbacks`, `cb`, and `ai` so shutdown, service control, status/dashboard, probe control, native process context, callback scanning, and AI provider control stay under the TUI. The explicit `u`/`uf` handler also runs before that catch-all. `kd <windbg-command>` always executes a raw DbgEng command regardless of the selected backend mode.

## Native Commands

```text
?, ||, ||s, |, .sympath, .sympath+, .reload
lm, ld, ln, x
d, da, db, dc, dd, dD, df, dp, dq, du, dw, dW, dyb, dyd
dda, ddp, ddu, dpa, dpp, dpu, dqa, dqp, dqu
dds, dps, dqs
vtop, procctx
phys, pdb, pdw, pdd, pdq
peb, pew, ped, peq
dt, dtx
callbacks, kcallbacks, cb
help callbacks
u, uf
ai
e, ea, eb, ed, eD, ef, ep, eq, eu, ew, eza, ezu
c, f, fp, m, s
n, sq
version, vertarget, vercommand, drvstatus, home, dashboard, probe
q, qq, qd
```

## DbgEng-Routed Commands

```text
$<, $><, $$<, $$><, $$>a<
??, #, |s, ~, ~e, ~f, ~u, ~n, ~m, ~s
a, ad, ah, al, as
ba, bc, bd, be, bl, bp, bu, bm, br, bs, bsc
dg, dl, dv, dx
g, gc, gh, gn, gN, gu
ib, iw, id, ob, ow, od
j
k, kb, kc, kp, kP, kv
l+, l-, ls, lsa, lsc, lse, lsf, lsf-, lsp
p, pa, pc, pct, ph, pt
r, rdmsr, rm, wrmsr
so, ss, sx, sxd, sxe, sxi, sxn, sxr, sx-
t, ta, tb, tc, tct, th, tt, wt
up, ur, ux
z
```

## Implementation Notes

1. `x nt!*Mask*` is handled by splitting `module!symbol-mask` and enumerating the matching loaded kernel module. The `nt` module alias maps to `ntoskrnl.exe`/`ntkrnl*` and is loaded into DbgHelp under the `nt` name.
2. `ln` resolves the input as either a number or symbol, then asks `DbgHelp` for the nearest symbol.
3. `dps`, `dqs`, and `dds` annotate pointer-like values with nearest symbols when available.
4. `dpa`, `dpu`, `dqa`, and `dqu` read a pointer value first, then display the referenced string.
5. Write commands start enabled per handle; `write off` disables the driver gate and `write on` re-enables it.
6. Single transfer size is capped by `KNDBG_MAX_TRANSFER_SIZE`.
7. The build helper copies the pinned `vendor\debugging-tools\x64` Debugging Tools runtime DLLs beside the EXE, with Windows Kits as a fallback; this includes `dbghelp.dll`, `dbgeng.dll`, `dbgcore.dll`, `DbgModel.dll`, `msdia140.dll`, `symsrv.dll`, `srcsrv.dll`, and `symsrv.yes`, and is required for reliable symbol-server downloads and DbgEng runtime loading when the tool is moved to another directory.
8. The sync script, build script, and EXE startup path create `symsrv.yes` when `symsrv.dll` is present but the consent marker is missing.
9. Startup registers staged `msdia140.dll` with `DllRegisterServer` before symbol initialization so DIA fallback works without a separate `regsvr32` step in normal elevated runs. If COM registration is unavailable, DIA fallback can still create `IDiaDataSource` directly from the staged `msdia*.dll` through `DllGetClassObject`.
10. Startup creates `<exe-dir>\symbols` and uses `SRV*<exe-dir>\symbols*https://msdl.microsoft.com/download/symbols` as the default Microsoft symbol server path. It then forces the `nt` kernel image symbols to materialize after the driver is loaded and the ABI is verified, so the kernel PDB is downloaded/loaded into the EXE-local symbol cache before the first type-heavy command. If DbgHelp still reports `SymNone`, the warning includes loaded `dbghelp.dll` and `symsrv.dll` diagnostics.
11. Native `dt` supports layout-only output, value output when an address is supplied, recursive UDT expansion with `-rN`, verbose diagnostics with `-v`, bare output with `-b`, field filters, and wildcard type enumeration such as `dt nt!*EPROCESS*` or `dt nt!*`. Exact type layouts use `SymGetTypeFromNameW`, then fall back to `SymEnumTypesW` exact matching to recover module base plus type id before DIA is tried; the fallback accepts module-qualified names, leaf type names, and leading-underscore variants. Wildcard patterns use `SymEnumTypesW` with user-mode `*`/`?` filtering and are list-only, with DIA UDT enumeration as fallback when DbgHelp cannot enumerate the type stream. When `DbgHelp` cannot provide a usable UDT layout, DIA fallback recovers field offsets, lengths, bit positions, and type names from the loaded PDB or from a DIA-resolved PDB using the module image plus symbol path. DIA fallback reports whether activation failed, module matching failed, or the specific type was absent from the PDB.
12. `vtop` translates a virtual address to a physical address using the current CR3, a supplied directory-table base, or `/pid <process-id>`. The output reports whether the walk used PML4 or PML5, prints the physical address of each page-table entry that was read, and includes the leaf page-table entry physical address plus writable state.
13. `procctx <pid>` stores a process DTB context. `d*` can use `/pid <pid>` or the stored context for process-aware user VA physical reads. Native `e*` virtual writes default to the System process context (`pid 4`) and can use `/pid <pid>` for one-shot process-aware user VA writes. Address-only `e*` enters a WinDbg-style one-line edit prompt and cancels on an empty line, `.`, `q`, or `quit`. If the leaf PTE/PDE/PDPTE is read-only, `e*` temporarily sets its write bit for the edit, flushes the VA, writes kernel VAs through the original VA, keeps translated user VAs on the physical-write path, restores the write bit afterward, and flushes again. Display reads are sparse, so unreadable bytes stay visible as `??` instead of aborting the whole dump.
14. `phys`, `pdb`, `pdw`, `pdd`, and `pdq` read physical memory and use the same sparse `??` display for unreadable ranges; `peb`, `pew`, `ped`, and `peq` write physical memory through the same write gate as virtual writes.
15. `probe` manages `KnLiveDbgProbe.sys` and prints a deterministic positive-control virtual/physical test buffer.
16. `callbacks [all|ob|registry|process|thread|minifilter] [module]` and `callbacks [scope] /module <module>` parse kernel PDB type layouts and live memory to list object-manager filters, registry callbacks, process/thread creation callbacks, and minifilter callbacks with module, symbol, altitude, context, root, and object/filter address annotations. The optional module filter is case-insensitive and is applied after scanning; it keeps records whose pre/function or post callback belongs to the requested module name or module stem.
17. Object callback scanning discovers `_OBJECT_TYPE` objects from `ObTypeIndexTable` before walking each `_OBJECT_TYPE.CallbackList`, with documented type globals used only as fallback. Human output includes the object type name and index when available, so Process, Thread, Desktop, and other object-manager surfaces are explicit instead of requiring the operator to interpret the `_OBJECT_TYPE` address. Public nt PDBs can omit `_CALLBACK_ENTRY_ITEM`; when that happens, the scanner uses a guarded x64 object-callback item layout fallback, validates live list links, callback-entry pointers, operation masks, and callback routine pointers, and treats validated fallback records as normal output. Warnings are reserved for partial PDB layouts, structure drift, or failed live validation.
18. Registry, process, and thread callback scanning enumerate candidate root symbols and validate the expected list/table shape before emitting records. Public nt PDBs often omit `_CM_CALLBACK_CONTEXT_BLOCK` and `_EX_CALLBACK_ROUTINE_BLOCK`; those scanners use guarded x64 fallback layouts, validate registry callback routines against loaded kernel image ranges, annotate callback routine addresses with module and symbol ownership, and print process notify block context values as decoded `notifyType` metadata instead of treating them as module pointers.
19. Minifilter scanning discovers `fltmgr!FltGlobals`, validates the frame-list root, walks frames and registered filters, and reports operation, unload, instance, name provider, KTM, section, and volume-mount callbacks. Non-exact globals candidates must produce concrete callback records before they are accepted.
20. `u <address|symbol> [instruction-count]` resolves the address natively, reads up to `instruction-count * 16` code bytes through the driver, disassembles them with vendored Zydis, caps explicit counts at 256 instructions, and remembers the next offset for a following bare `u`. If the driver device is not open, the command falls back to the DbgEng disassembly path.
21. `uf <address|symbol> [max-instructions]` resolves the address natively, reads a bounded code window through the driver, disassembles with vendored Zydis, and stops at common function terminal instructions such as `ret`, `iret`, `sysret`, `sysexit`, `hlt`, `ud2`, or `int3`. If the driver device is not open, the command falls back to DbgEng.
22. `kdinit /remote <connection-options>` attaches DbgEng with `DEBUG_ATTACH_KERNEL_CONNECTION`; plain `kdinit` and `kdinit /local` use local-kernel attach.
23. `ai plan <prompt>` stores model-proposed commands in a parsed in-memory `kn-live-dbg.ai-plan.v2` plan after schema validation rejects empty commands, missing purpose metadata, unsupported backend expectations, command chaining, multiline commands, nested-AI, shutdown/unload, backend/session mutation, probe service control, bare `kd`, raw `kd` blocked-command wrappers, overlong commands, and unknown non-DbgEng commands. `ai run <index|all>` executes only non-write, non-shutdown planned commands through the normal TUI dispatcher.
24. `ai analyze callbacks`, `ai explain dt`, `ai annotate u|uf`, and `ai diagnose` provide evidence-backed AI assistance on top of implemented native command output. Callback analysis uses normal `callbacks <scope> [module]` evidence. Evidence prompts include deterministic stdout/stderr summaries before raw output.
25. `ai playbook <callbacks|minifilter|object|address|driver>` creates repeatable read-only command plans with dry-run output and optional guarded execution.
26. `ai write <index> confirm` is required to dispatch planned write-like commands and performs backup/read-current plus verification preflight when the write form is recognized. It also renders a deterministic before/after diff for verification stdout/stderr. `ai transcript <path>` captures AI events and command output as JSONL, including output summaries and raw stdout/stderr. `ai transcript max` rotates long transcript files, `ai transcript redact` redacts captured stdout/stderr, `ai audit <path>` captures write-command JSONL audit records, and `ai report <path>` exports the current AI session summary.
27. Interactive command dispatch has a delayed progress watchdog. Silent commands that run longer than about one second emit colored elapsed-time status rows directly to the console with `WriteConsoleW`, outside transcript stdout/stderr capture, and print a final elapsed row only if the watchdog became visible. Once stdout/stderr output starts, progress rows are suppressed for that command to avoid interleaving with long listings such as callback scans.
28. Human-readable console output colorizes high-signal tokens for scanning: callback kind tags, object type names, modules, symbols, translated physical addresses, type/field names, and dump line addresses. The same output remains plain text in stdout capture, AI transcript JSONL, and write-audit JSONL records.
29. The `knkd>` prompt supports Tab completion for registered commands and context-aware subcommands/options, including callback scopes, AI subcommands, backend modes, probe/procctx/write actions, `dt` options, `vtop` context options, and `/pid` memory command options. Ambiguous prefixes print matching candidates and redraw the current line without dispatching a command.
30. `tools\build.ps1` stamps `KnLiveDbg.exe`, `KnLiveDbg.sys`, and `KnLiveDbgProbe.sys` with the current PE version without incrementing it by default. `-BumpVersion` increments the patch component, with `0.0.0` as the local baseline and `0.0.1` as the first bumped build. `tools\release.ps1` packages the built PE files, runtime DLLs, symbols/certs when present, and `kn-live-dbg-version.json` into `release\KnLiveDbg-<version>-<configuration>-x64.zip`, using a version-bumped build unless `-NoVersionBump` is supplied.
