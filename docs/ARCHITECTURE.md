# Architecture

## Recommended Split

Kn Live Dbg follows a LiveKD-style split:

1. Kernel driver
   - Owns only privileged memory operations.
   - Creates the device with an Administrators/SYSTEM-only security descriptor.
   - Validates IOCTL buffers and sizes.
   - Uses `MmCopyMemory` for virtual reads.
   - Walks x64 page tables for VA-to-PA translation.
   - Detects active LA57 and includes PML5E in translation responses when five-level paging is enabled.
   - Uses `MmCopyMemory` for physical reads.
   - Uses page-sized `MmMapIoSpaceEx` mappings for physical writes.
   - Keeps write access controlled per open handle, with writes enabled by default.
   - Enforces one active controller PID at a time.

2. User-mode TUI
   - Owns driver install/load/unload through SCM.
   - Acquires a process-wide named mutex before touching SCM so only one `KnLiveDbg.exe` instance can run at a time.
   - Displays colored staged lifecycle output for elevation checks, single-instance acquisition, SCM query/install/start, device open, ABI verification, symbol initialization, probe load, and service unload paths.
   - Automatically closes the device handle, stops the main driver, and deletes the service on normal process exit, EOF, Ctrl+C, `q`, `quit`, `exit`, and `unload`.
   - Tracks `probe load` within the session and automatically stops/deletes the probe service during process cleanup when the session loaded it.
   - Prints a colored startup welcome banner and dashboard with driver, write gate, backend, symbol, AI, probe, and quick-action status before the interactive prompt.
   - Owns kernel module enumeration.
   - Owns symbol path, PDB loading, type lookup, and field offset resolution.
   - Uses DIA SDK as a fallback when `DbgHelp` cannot return complete UDT field metadata.
   - Owns PDB-driven callback list decoding for object, registry, process, and minifilter callbacks.
   - Presents Windbg-like commands.
   - Redraws the dashboard with `home` or `dashboard`.
   - Optionally attaches a DbgEng local-kernel backend for commands that need debugger-engine semantics.

This keeps the driver small and reduces the amount of complex parser/symbol code running in kernel mode.

## IOCTL Contract

The ABI lives in `shared/KnLiveDbgIoctl.h`.

Current calls:

1. `IOCTL_KNDBG_GET_VERSION`
2. `IOCTL_KNDBG_READ_VIRTUAL`
3. `IOCTL_KNDBG_WRITE_VIRTUAL`
4. `IOCTL_KNDBG_SET_WRITE_MODE`
5. `IOCTL_KNDBG_QUERY_ADDRESS`
6. `IOCTL_KNDBG_TRANSLATE_VIRTUAL`
7. `IOCTL_KNDBG_READ_PHYSICAL`
8. `IOCTL_KNDBG_WRITE_PHYSICAL`
9. `IOCTL_KNDBG_GET_SESSION_STATUS`
10. `IOCTL_KNDBG_RESOLVE_PROCESS`

All requests include an explicit `Size` field. Variable read/write payloads use `FIELD_OFFSET(..., Data)` as the header size.

## Physical Memory Flow

1. `vtop` sends a virtual address, optional directory-table base, and requested length to the driver.
2. If the directory-table base is zero, the driver uses the current x64 CR3.
3. `vtop /pid` and `procctx <pid>` resolve process DTBs by asking the driver to read PDB-resolved EPROCESS offsets.
4. The driver reads PML5E when LA57 is active, then PML4E, PDPTE, PDE, and PTE entries with `MmCopyMemory(..., MM_COPY_MEMORY_PHYSICAL)`.
5. The walk supports 4 KB pages plus 2 MB and 1 GB large pages.
6. The response reports CR3, VA, PA, page size, page offset, contiguous translated bytes, and the page-table entries that were used.
7. `d*` and `e*` can use `/pid <pid>` or a stored `procctx` to translate user VAs page-by-page and then perform physical reads/writes.
8. Virtual and physical display commands perform sparse reads for dump output. Readable bytes are printed normally, while unreadable bytes keep the requested layout and are shown as `??` or `0x????...` for wider units.
9. `phys`, `pdb`, `pdw`, `pdd`, and `pdq` read physical memory directly through `IOCTL_KNDBG_READ_PHYSICAL`.
10. `peb`, `pew`, `ped`, and `peq` write physical memory through `IOCTL_KNDBG_WRITE_PHYSICAL`; write mode starts enabled and can be disabled with `write off`.

## Symbol Flow

1. TUI calls `NtQuerySystemInformation(SystemModuleInformation)`.
2. TUI translates `\SystemRoot\...` paths into local Windows paths.
3. The build helper stages the pinned `vendor\debugging-tools\x64` Debugging Tools runtime DLLs beside the EXE so DbgHelp can load `symsrv.dll`, DbgEng can load `DbgModel.dll`, and both can use the Microsoft symbol server instead of the limited System32 runtime. If the vendor runtime is incomplete, it falls back to the locally installed Windows Kits Debugging Tools copy for missing debugger-runtime files.
4. The sync script, build script, and EXE startup path create `symsrv.yes` when `symsrv.dll` is present but the consent marker is missing.
5. Startup registers staged `msdia140.dll` with `DllRegisterServer` before symbol initialization so DIA fallback does not require a separate `regsvr32` step in normal elevated runs.
6. Startup creates `<exe-dir>\symbols`, prepends the EXE directory and its non-cache subdirectories to the DbgHelp/DbgEng symbol path, then appends `SRV*<exe-dir>\symbols*https://msdl.microsoft.com/download/symbols` so downloaded PDBs are managed under the runnable EXE bundle.
7. TUI calls `SymLoadModuleExW` for each loaded kernel image.
8. Kernel images named `ntoskrnl.exe` or `ntkrnl*` are loaded into DbgHelp under the `nt` module alias.
9. After driver load and ABI verification, startup forces the `nt` kernel image symbols to materialize, which downloads the PDB into the configured symbol cache when it is not already present.
10. If forced symbol loading still leaves the module at `SymNone`, the warning includes the loaded `dbghelp.dll` path and `symsrv.dll` load state for runtime diagnosis.
11. `addr` uses `SymFromNameW`.
12. Exact `dt` layouts use `SymGetTypeFromNameW` and `SymGetTypeInfo`.
13. If exact `SymGetTypeFromNameW` lookup fails, the symbol engine reuses `SymEnumTypesW` exact matching to recover module base plus type id before falling back to DIA; the match accepts module-qualified names, leaf type names, and leading-underscore variants.
14. Wildcard `dt` patterns such as `dt nt!*` use `SymEnumTypesW` against matching loaded kernel modules, apply the `*`/`?` filter in user mode, fall back to DIA UDT enumeration when DbgHelp cannot enumerate the type stream, and print list-only type matches.
15. If `DbgHelp` fails to return a usable UDT layout, the user-mode symbol engine opens the loaded PDB with DIA, or asks DIA to resolve the PDB from the module image plus symbol path, and recovers field names, offsets, lengths, bit positions, and type names. DIA activation first uses registered COM, then falls back to creating `IDiaDataSource` directly from the staged `msdia*.dll` through `DllGetClassObject` so COM registration failures are reported separately from PDB/type lookup failures.
16. `callbacks` resolves private callback structure fields from kernel PDBs, discovers object type objects from `ObTypeIndexTable`, discovers registry/process callback roots by enumerating and validating candidate symbols, discovers minifilters from `fltmgr!FltGlobals.FrameList`, walks live list/table roots through the memory reader, and annotates function/context addresses with loaded module ownership.
17. `u` resolves an address or symbol with the native symbol engine, reads bounded code bytes through `IOCTL_KNDBG_READ_VIRTUAL`, and formats x64 instructions with the vendored Zydis decoder. This keeps local live-kernel disassembly independent from DbgEng memory callbacks, which can fail in local-kernel sessions. If the driver device is not open, `u` still falls back to the DbgEng disassembly path.
18. `uf` resolves an address or symbol, reads a bounded code window through the driver, and uses the same Zydis decoder as `u` while stopping at common function terminal instructions. If the driver device is not open, it falls back to the DbgEng command path.
19. `setfield` resolves a field offset in user mode, then sends a byte write to the driver.

## Callback Scanner Flow

1. Object callbacks: resolve `_OBJECT_TYPE.CallbackList`, discover object type objects from `ObTypeIndexTable`, read `_OBJECT_TYPE.Name` and table index, then walk each callback list. Human output and JSON carry the object type name/index alongside the `_OBJECT_TYPE` address. If the target nt PDB exposes `_OBJECT_TYPE` but omits the private callback item type, the scanner falls back to the guarded x64 object-callback item field layout, validates live list pointers, callback-entry pointers, operation masks, and callback routine pointers, and treats that as the normal public-symbol path unless validation fails.
2. Registry callbacks: enumerate `CmpCallbackListHead` and nearby candidate symbols, validate the list-head shape, then walk `_CM_CALLBACK_CONTEXT_BLOCK` records.
3. Process callbacks: enumerate `PspCreateProcessNotifyRoutine` and nearby candidate symbols, validate table slots, decode fast references, then read `_EX_CALLBACK_ROUTINE_BLOCK` records.
4. Minifilter callbacks: resolve `fltmgr!FltGlobals`, validate `FrameList`, walk `_FLTP_FRAME.RegisteredFilters`, decode `_FLT_FILTER` metadata, and enumerate `_FLT_OPERATION_REGISTRATION` entries plus filter-level routines.

## DbgEng Flow

1. `kdinit` or `backend dbgeng` initializes `DbgEngBackend`.
2. The backend calls `DebugCreate(__uuidof(IDebugClient5))`.
3. It installs an `IDebugOutputCallbacksWide` capture sink.
4. It queries `IDebugControl4` and `IDebugSymbols3`.
5. It mirrors the current symbol path into DbgEng.
6. It attaches with `AttachKernelWide(DEBUG_ATTACH_LOCAL_KERNEL, nullptr)` for local mode or `AttachKernelWide(DEBUG_ATTACH_KERNEL_CONNECTION, connectionOptions)` for remote mode.
7. Raw commands are executed with `IDebugControl4::ExecuteWide`.

The DbgEng backend is intentionally isolated from the native memory backend. Native read/write operations still go through `KnLiveDbg.sys`, while DbgEng commands execute through the debugger engine.

`u` and `uf` are deliberately wired as explicit commands instead of falling through the generic command router. Both stay on the driver-backed memory path and use Zydis for instruction decoding when the device is open; DbgEng is only a fallback when the native device is unavailable.

Backend routing is mode-dependent:

1. `auto` is the default. Implemented native commands stay on the driver/`DbgHelp` path, while registered DbgEng commands, `!extension` commands, and unknown dot meta-commands initialize or reuse DbgEng.
2. `native` disables generic DbgEng fallback. Commands that require WinDbg parser, stop-state, extension, breakpoint, register, stack, source, trace, or exception semantics are reported as DbgEng-only instead of being executed.
3. `dbgeng` routes most non-session commands through `IDebugControl4::ExecuteWide`. The TUI still intercepts shutdown/service commands, backend management, native callback scanning, and explicit `u`/`uf`.
4. `kd <command>` is a raw DbgEng escape hatch independent of the selected backend mode.

Interactive command execution is wrapped by a delayed progress watchdog. If a dispatched command runs longer than about one second without producing stdout/stderr, the watchdog writes elapsed-time status rows directly to the console with `WriteConsoleW`, outside stdout/stderr transcript capture, and stops once the command returns. After command output starts, progress rows are suppressed for that command so watchdog text does not split normal output lines. Console color scopes, captured stdout/stderr forwarding, and watchdog writes share a console-output lock so attribute restore cannot race with progress rendering.

Human-readable native command output uses scoped console attributes for high-signal tokens such as callback kind tags, object types, modules, symbols, translated physical addresses, and type/field names. The color layer is applied only while writing to the console stream, so transcript capture and JSON evidence remain plain text.

## Build and Release Flow

1. `tools\build.ps1` is the authoritative scripted build path for versioned artifacts.
2. It reads `.build\version-state.json`, falls back to the existing output PE version, and otherwise starts from `0.0.0`.
3. The next build version increments the patch component by one; the first scripted build is therefore `0.0.1`.
4. The script writes `.build\generated\KnLiveDbgVersion.h`, then MSBuild compiles VERSIONINFO resources into `KnLiveDbg.exe`, `KnLiveDbg.sys`, and `KnLiveDbgProbe.sys` before the WDK TestSign step.
5. After a successful build, the script verifies the stamped PE versions, verifies driver signatures, stages Debugging Tools runtime DLLs beside the EXE, and saves the new version state.
6. `tools\release.ps1` runs the build by default and creates `release\KnLiveDbg-<version>-<configuration>-x64.zip` from the output directory.
7. The release zip includes the runnable EXE/SYS files, staged runtime dependencies, PDB/CER/CAT files when present, README/runtime manifest metadata, and `kn-live-dbg-version.json`.

## AI Provider Flow

1. `AiProviderRuntime` lives entirely in user mode.
2. Provider selection defaults to `.env` plus environment variables and can be changed for the current TUI session with `ai provider`, `ai policy`, `ai model`, `ai baseurl`, and `ai effort`.
3. `openai-codex-cli` executes `codex exec` as an external process and captures stdout/stderr.
4. `openai-codex-subscription` reads Codex OAuth credentials from environment variables or auth files and calls the Codex Responses endpoint.
5. `deepseek` and `openrouter` use OpenAI-compatible chat-completions requests over WinHTTP.
6. `.env` is searched in the current directory, executable directory, and repository root when running from `x64\Debug` or `x64\Release`; real environment variables override `.env` values.
7. AI requests receive only curated session context and the operator prompt. The model cannot call memory IOCTLs or execute generated debugger commands directly.
8. `KNLIVEDBG_AI_REMOTE_POLICY=local-only` or `ai policy local-only` blocks HTTP-backed providers (`openai-codex-subscription`, `deepseek`, and `openrouter`) for private sessions.
9. `ai plan` requires a strict JSON command proposal object, parses it into in-memory plan state, and shows numbered commands with purpose and risk notes.
10. `ai plan` validates each proposed command before storing it: empty commands, nested `ai`, shutdown/unload commands, bare `kd`, overlong commands, and unknown non-DbgEng commands are rejected. Write-like proposals are forced to require explicit confirmation.
11. `ai run` routes approved read-only plan commands back through the normal TUI command dispatcher, so backend mode, DbgEng routing, and native command handling stay consistent.
12. Write-like commands, shutdown commands, unload commands, and nested `ai` commands are blocked from `ai run`.
13. `ai analyze callbacks`, `ai explain dt`, and `ai annotate u|uf` execute read-only evidence commands through the same dispatcher, then send bounded stdout/stderr evidence to the selected model. Callback analysis uses `callbacks json <scope>` so the model receives structured records instead of the human-readable callback view.
14. `ai diagnose` uses current session context plus an operator note to explain symbol, type-layout, DbgEng, or setup failures.
15. `ai playbook` creates deterministic read-only command plans for callback, minifilter, object-callback, address, and suspect-driver investigations. `run` still goes through the guarded `ai run` path.
16. `ai write <index> confirm` is the explicit operator confirmation path for planned write-like commands. The preflight path builds backup/read-current, small-range restore, translation, and verification commands for recognized write forms, then prints a deterministic before/after diff of verification stdout/stderr after the write.
17. `ai transcript` captures AI events and command stdout/stderr as JSONL after it is enabled.
18. `ai transcript max <bytes|off>` rotates long transcript files, and `ai transcript redact <on|off>` controls stdout/stderr redaction for long hex addresses and `sk-...` style tokens.
19. `ai audit <path|off|status>` writes a separate JSONL record for every write-like command that executes through the normal dispatcher.
20. Transcript command records include origin, backend mode, command class, write-like status, stdout/stderr character counts, deterministic output summaries, raw stdout/stderr, and keep-running state.
21. `ai report` writes a Markdown report with session context, provider status, transcript settings, write-audit path, parsed plan, and raw AI plan response.
22. `backend dbgeng` does not swallow `ai`; the TUI handles it before raw DbgEng command routing.

## Hardening Backlog

No large hardening backlog item is currently left open in this document. New work should be added here once it is scoped.

Completed hardening items:

1. JSONL write-command audit logging is implemented with `ai audit <path>`.
2. Transcript rotation and redaction controls are implemented with `ai transcript max` and `ai transcript redact`.
3. Transcript command records now include command-class labels such as `memory-read`, `physical-write`, `type`, `callbacks`, `disassembly`, `symbols`, `dbgeng`, and `session`.
4. Structured callback JSON export is implemented with `callbacks json [scope] [path|-]`.
5. Write verification before/after diff rendering is implemented for confirmed AI write commands.
6. AI plan command schema validation is implemented before plan storage.
7. Local-only AI provider policy is implemented with `ai policy local-only` and `KNLIVEDBG_AI_REMOTE_POLICY=local-only`.
8. Single-controller ownership is implemented in the driver and reported by `drvstatus`.
9. Process DTB resolution is implemented with PDB-resolved EPROCESS offsets and `procctx`/`vtop /pid`.
10. LA57 detection and PML5E reporting are implemented in the page-table walker.
11. DIA fallback is implemented for UDT field metadata when `DbgHelp` fails.
12. `KnLiveDbgProbe.sys` provides a positive-control contiguous virtual and physical test buffer.
13. Remote KD attach is available through `kdinit /remote <connection-options>`.
14. AI command proposal validation is versioned as `kn-live-dbg.ai-plan.v2` and rejects missing purpose metadata, command chaining, session mutation, raw `kd` blocked-command wrappers, and unsupported backend expectations.
15. AI command evidence and transcripts include deterministic output summaries before raw stdout/stderr.
