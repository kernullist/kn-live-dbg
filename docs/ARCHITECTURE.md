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
   - Uses page-sized `MmMapIoSpaceEx` mappings for physical writes, with `MmGetVirtualForPhysical` fallback when the kernel already has a direct mapping for the target PFN.
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
   - Owns PDB-driven callback list decoding for object, registry, process, thread, image-load, and minifilter callbacks.
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
11. `IOCTL_KNDBG_FLUSH_VIRTUAL`

All requests include an explicit `Size` field. Variable read/write payloads use `FIELD_OFFSET(..., Data)` as the header size. ABI version 5 adds `IOCTL_KNDBG_FLUSH_VIRTUAL` plus explicit translation metadata for paging level and page-table entry physical addresses.

## Physical Memory Flow

1. `vtop` sends a virtual address, optional directory-table base, and requested length to the driver.
2. If the directory-table base is zero, the driver uses the current x64 CR3.
3. `vtop /process` and `procctx <pid>` resolve process DTBs by asking the driver to read PDB-resolved EPROCESS offsets.
4. The driver checks CR4.LA57, records whether the walk is PML4 or PML5, reads PML5E when LA57 is active, then reads PML4E, PDPTE, PDE, and PTE entries with `MmCopyMemory(..., MM_COPY_MEMORY_PHYSICAL)`.
5. The walk supports 4 KB pages plus 2 MB and 1 GB large pages.
6. The response reports CR3, VA, PA, paging level, page size, page offset, contiguous translated bytes, the page-table entries that were used, the physical address of each entry, and the leaf PTE/PDE/PDPTE physical address plus writable state.
7. `d*` can use `/process <pid>` or a stored `procctx` to translate user VAs page-by-page for physical reads. Native `e*` virtual writes default to the System process context (`pid 4`) and can use `/process <pid>` for process-specific user VAs. Address-only `e*` first reads the current value through the selected context and opens a one-line replacement prompt before writing. If the translated leaf PTE/PDE/PDPTE is not writable, `e*` writes that leaf entry through physical memory with the write bit set, flushes the VA through `IOCTL_KNDBG_FLUSH_VIRTUAL`, performs kernel-VA edits through the original virtual address, uses physical writes for translated user VAs, restores the original write state, and flushes again before continuing.
8. Virtual and physical display commands perform sparse reads for dump output. Readable bytes are printed normally, while unreadable bytes keep the requested layout and are shown as `??` or `0x????...` for wider units.
9. `phys`, `pdb`, `pdw`, `pdd`, `pdq`, `!db`, `!dw`, `!dd`, and `!dq` read physical memory directly through `IOCTL_KNDBG_READ_PHYSICAL`.
10. `peb`, `pew`, `ped`, `peq`, `!eb`, `!ew`, `!ed`, and `!eq` write physical memory through `IOCTL_KNDBG_WRITE_PHYSICAL`; address-only form prompts with the current physical value before writing, and write mode starts enabled and can be disabled with `write off`.

## Native Process Listing Flow

1. `!dml_proc` stays on the native TUI path, accepts an optional decimal PID filter, and is not routed to DbgEng extension loading.
2. The all-process form resolves PID 4 through `IOCTL_KNDBG_RESOLVE_PROCESS` using PDB-resolved `_KPROCESS.DirectoryTableBase` offsets.
3. User mode resolves `_EPROCESS.ActiveProcessLinks`, `_EPROCESS.UniqueProcessId`, and optional display fields from the loaded kernel PDB.
4. The walker prefers `nt!PsActiveProcessHead` as the list anchor. If that symbol is unavailable, it falls back to PID 4's `ActiveProcessLinks`, prints the System process first, then follows `Flink` with a guard for the hidden list head.
5. Output includes EPROCESS, PID, parent PID when available, active thread count, directory-table base, image name, and a `dt nt!_EPROCESS <address>` follow-up.

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
12. Native address parsing accepts numbers, loaded symbols, WinDbg backtick-separated addresses, and simple `+`/`-` arithmetic before command dispatch. Arithmetic expressions are evaluated in user mode so `dt`, `d*`, `e*`, `vtop`, `u`, `uf`, `setfield`, and AI preview helpers do not hand expression text to DbgHelp as a raw symbol.
13. Exact `dt` layouts use `SymGetTypeFromNameW` and `SymGetTypeInfo`.
14. If exact `SymGetTypeFromNameW` lookup fails, the symbol engine reuses `SymEnumTypesW` exact matching to recover module base plus type id before falling back to DIA; the match accepts module-qualified names, leaf type names, and leading-underscore variants.
15. Wildcard `dt` patterns such as `dt nt!*` use `SymEnumTypesW` against matching loaded kernel modules, apply the `*`/`?` filter in user mode, fall back to DIA UDT enumeration when DbgHelp cannot enumerate the type stream, and print list-only type matches.
16. If `DbgHelp` fails to return a usable UDT layout, the user-mode symbol engine opens the loaded PDB with DIA, or asks DIA to resolve the PDB from the module image plus symbol path, and recovers field names, offsets, lengths, bit positions, and type names. DIA activation first uses registered COM, then falls back to creating `IDiaDataSource` directly from the staged `msdia*.dll` through `DllGetClassObject` so COM registration failures are reported separately from PDB/type lookup failures.
17. `callbacks` resolves private callback structure fields from kernel PDBs, discovers object type objects from `ObTypeIndexTable`, discovers registry/process/thread/image-load callback roots by enumerating and validating candidate symbols, discovers minifilters from `fltmgr!FltGlobals.FrameList`, walks live list/table roots through the memory reader, and annotates callback routine addresses plus image-backed context addresses with loaded module ownership.
18. `u` resolves an address or symbol with the native symbol engine, reads bounded code bytes through `IOCTL_KNDBG_READ_VIRTUAL`, and formats x64 instructions with the vendored Zydis decoder. This keeps local live-kernel disassembly independent from DbgEng memory callbacks, which can fail in local-kernel sessions. If the driver device is not open, `u` still falls back to the DbgEng disassembly path.
19. `uf` resolves an address or symbol, reads a bounded code window through the driver, and uses the same Zydis decoder as `u` while stopping at common function terminal instructions. If the driver device is not open, it falls back to the DbgEng command path.
20. `setfield` resolves a field offset in user mode, then sends a byte write to the driver.

## Callback Scanner Flow

1. Object callbacks: resolve `_OBJECT_TYPE.CallbackList`, discover object type objects from `ObTypeIndexTable`, read `_OBJECT_TYPE.Name` and table index, then walk each callback list. Human output carries the object type name/index alongside the `_OBJECT_TYPE` address. If the target nt PDB exposes `_OBJECT_TYPE` but omits the private callback item type, the scanner falls back to the guarded x64 object-callback item field layout, validates live list pointers, callback-entry pointers, operation masks, and callback routine pointers, and treats that as the normal public-symbol path unless validation fails.
2. Registry callbacks: enumerate `CmpCallbackListHead` and nearby candidate symbols, validate the list-head shape, then walk callback context records. Public nt PDBs can omit `_CM_CALLBACK_CONTEXT_BLOCK`, so the scanner uses guarded x64 fallback layouts and accepts only records whose callback routine fields resolve inside loaded kernel images. Callback context values are module-annotated only when they also point into a loaded kernel image.
3. Process callbacks: enumerate `PspCreateProcessNotifyRoutine` and nearby candidate symbols, validate table slots, decode fast references, then read callback routine blocks. Public nt PDBs can omit `_EX_CALLBACK_ROUTINE_BLOCK`, so the scanner uses the stable x64 function/context fallback layout for this block. The block context value is decoded as `notifyType` metadata and is not module-annotated.
4. Thread callbacks: enumerate `PspCreateThreadNotifyRoutine` and nearby candidate symbols, validate table slots, decode fast references, then read callback routine blocks with the same stable x64 layout.
5. Image-load callbacks: enumerate `PspLoadImageNotifyRoutine` and nearby candidate symbols, validate table slots, decode fast references, then read callback routine blocks with the same stable x64 layout.
6. Minifilter callbacks: resolve `fltmgr!FltGlobals`, validate `FrameList`, walk `_FLTP_FRAME.RegisteredFilters`, decode `_FLT_FILTER` metadata, and enumerate `_FLT_OPERATION_REGISTRATION` entries plus filter-level routines.

## ETW Logger / NMI Callback Flow

1. `!etw` and `!nmi` share the same KnLiveDbg.sys virtual-read primitive used by other native scanners and rely on the loaded kernel PDB for symbol and type information.
2. `EtwScanner::Scan` resolves `nt!EtwpDebuggerData`, reads 64 `WMI_LOGGER_CONTEXT*` pointers from offset `0x10`, and for each non-null logger context reads `LoggerName` (UNICODE_STRING) and `GetCpuClock` (function pointer). PDB-resolved offsets are used when `nt!_WMI_LOGGER_CONTEXT.LoggerName` and `.GetCpuClock` are exposed; otherwise the fallback offsets `0x68` and `0x28` are used and a warning is emitted because those values drift across builds.
3. Each `GetCpuClock` target is annotated with owning module (`KernelModuleInfo` lookup) and nearest symbol (`SymbolEngine::FindNearestSymbol`). Pointers that do not land inside any loaded kernel module are tagged `Suspicious=true` with a `Notes` string — the canonical InfinityHook indicator.
4. `!etw logger <index|name>` reuses the same scan and applies a decimal index filter or a case-insensitive name substring filter in the user-mode pass.
5. `NmiScanner::Scan` resolves `nt!KiNmiCallbackListHead` (or `nt!KiNmiCallbackList` as an alias), reads the head pointer, then walks the `KNMI_HANDLER_CALLBACK` singly-linked list. The node layout is fixed: `Next` at `0x00`, `Callback` at `0x08`, `Context` at `0x10`, `Handle` at `0x18`. Iteration is bounded to 256 nodes with a visited-node cycle guard.
6. Each NMI callback is annotated with module + symbol and flagged suspicious if outside loaded kernel modules.
7. Both scanners check kernel canonical form (`address >= 0xffff800000000000`) at every pointer dereference and tolerate `MmCopyMemory` short reads through the existing `device.ReadMemory` path.
8. Signature-scan extraction of `KiNmiCallbackListHead` from a `KeRegisterNmiCallback` disassembly is documented as a follow-up milestone; this initial pass relies on PDB symbol resolution.

## VBS / HVCI / Secure Kernel Flow

1. `!vbs`, `!ci`, and `!securekernel` share the `VbsScanner` user-mode module that reads from live kernel memory through `KnLiveDbg.sys` and queries CPUID directly from the EXE process.
2. CiOptions resolution walks `nt!g_CiOptions`, `ci!g_CiOptions`, and `nt!CiOptions` in order, reads a `UINT32`, and decodes the documented flag bits (`CODEINTEGRITY_OPTION_ENABLED` 0x01, `TESTSIGN` 0x02, `UMCI_ENABLED` 0x04, `UMCI_AUDITMODE_ENABLED` 0x08, `HVCI_ENFORCED` 0x20, `UMCI_EXCLUSIONPATHS_ENABLED` 0x40, `TEST_BUILD` 0x80, `PREPRODUCTION_BUILD` 0x100, `FLIGHT_BUILD` 0x200, `HVCI_STRICT_MODE` 0x400, `HVCI_DEBUG_MODE` 0x800).
3. VBS activity is reported from `nt!HvlpVsmVtlCallVa` (with `nt!HvlpVtlCallVa` and `nt!HvlVtlCallVa` fallbacks); a non-zero kernel-canonical pointer means the VTL call code page is mapped. `nt!HvcallpVtlCallStub` is resolved as a secondary marker.
4. The scanner scans `SymbolEngine::Modules()` for `securekernel.exe` and `skci.dll` to confirm Secure Kernel runtime presence.
5. CPUID leaves `0x1` (hypervisor-present bit 31 of ECX), `0x40000000` (vendor signature + leaf base), and `0x40000006` (raw implementation hardware features when supported) are queried from user mode for hypervisor identification. MBEC enablement is intentionally not claimed because `IA32_VMX_PROCBASED_CTLS2` bit 22 requires kernel-only MSR access; the report treats HVCI enforcement as a proxy and annotates the limitation in the `[vbs.hypervisor]` block.
6. Trustlet enumeration walks `nt!PsActiveProcessHead` through `_EPROCESS.ActiveProcessLinks` with a bounded visited set, reads `_EPROCESS.UniqueProcessId`, `ImageFileName`, and `_EPROCESS.SecureState` (or `_KPROCESS.SecureState` through the embedded `Pcb`) per record. Bit 0 (`SecureKernelInProcess`) marks IUM trustlets; when the field is absent, the scanner falls back to case-insensitive prefix matches against well-known trustlet image names (`lsaiso`, `bioiso`, `securesystem`, `kdcustomization`) which tolerate the 15-byte `ImageFileName` truncation.
7. `!vbs` prints all five blocks (`[vbs.core]`, `[ci.options]`, `[vbs.hypervisor]`, `[securekernel.modules]`, `[securekernel.trustlets]`). `!ci [options|policy]` prints the CI options + hypervisor blocks plus an optional `[ci.policy]` summary that explicitly notes WDAC policy blob discovery is reserved for a later milestone. `!securekernel` prints the secure kernel module list plus trustlet list.

## ALPC Port Discovery Flow

1. `!alpc` is implemented natively against live kernel memory through the existing `KnLiveDbg.sys` virtual-read path and PDB type metadata.
2. `AlpcScanner::Scan` resolves `nt!ObTypeIndexTable`, enumerates `_OBJECT_TYPE` slots, and locates the `ALPC Port` and `Directory` type entries by reading each type's `_OBJECT_TYPE.Name` (or `TypeName`) `UNICODE_STRING`.
3. `nt!ObHeaderCookie` is resolved when present; if it cannot be found, the scanner records a warning and falls back to raw `_OBJECT_HEADER.TypeIndex` comparisons for pre-cookie kernels.
4. `nt!ObpRootDirectoryObject` is read to get the root `_OBJECT_DIRECTORY`. The scanner recurses through `_OBJECT_DIRECTORY.HashBuckets[]` (bucket count derived from the PDB-resolved array length) following each `_OBJECT_DIRECTORY_ENTRY.ChainLink` and descending into directory-typed children with bounded depth and a visited-directory cycle guard.
5. Each candidate object body has its `_OBJECT_HEADER` computed by subtracting `_OBJECT_HEADER.Body` offset, its `TypeIndex` decoded with the per-object XOR (`raw ^ cookie ^ ((header_addr >> 8) & 0xff)`), and matched against the `ALPC Port` type index.
6. For each port the scanner reads `_ALPC_PORT.OwnerProcess`, `ConnectionPort`, `CommunicationInfo`, and Flags. `_ALPC_COMMUNICATION_INFO.ConnectionPort`, `ServerCommunicationPort`, and `ClientCommunicationPort` are followed to surface paired server/client ports that are not themselves named in the directory tree.
7. Queue depths are computed by bounded `_LIST_ENTRY` walks on `MainQueue`, `PendingQueue`, `LargeMessageQueue`, `CanceledQueue`, and `WaitQueue`. `_KQUEUE` fields (typically `WaitQueue`) are detected by PDB type name and the list head is adjusted past the dispatcher header before walking.
8. Owner annotations resolve `_EPROCESS.UniqueProcessId` and `ImageFileName` for each port whose `OwnerProcess` lies in the kernel canonical range.
9. `!alpc ports`, `!alpc connections`, `!alpc port <addr>`, and `!alpc queues <addr>` reuse the same scanner with different scope/filter combinations. `connections` groups records by `ConnectionPort` to render server/client family graphs; `queues` populates queue counts for a single explicit port address.
10. The `alpc.list` AI capability tool routes back through `HandleAlpcCommand` with scope and optional name/pid arguments validated against the same shape rules used for plan commands.

## Windows Filtering Platform Flow

1. `!wfp` is implemented natively in user mode against the Base Filtering Engine (BFE) through `fwpuclnt.dll`; the kernel driver is not involved and the BFE service must be running.
2. `WfpScanner::Scan` opens an engine handle with `FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &engine)`, then builds in-memory provider, layer, and sublayer indexes by enumerating `FWPM_PROVIDER0`, `FWPM_LAYER0`, and `FWPM_SUBLAYER0` through the standard `FwpmXxxCreateEnumHandle0` / `FwpmXxxEnum0` / `FwpmXxxDestroyEnumHandle0` cycle. Each page-sized batch is freed with `FwpmFreeMemory0` before the next page.
3. The five subcommands `!wfp providers`, `!wfp sublayers`, `!wfp callouts`, `!wfp filters`, and `!wfp layers` reuse those indexes to resolve owning provider names, applicable layer names, and sublayer names, then format each record under `[wfp.provider]`, `[wfp.sublayer]`, `[wfp.callout]`, `[wfp.filter]`, and `[wfp.layer]` headings with key GUIDs, decoded flag mnemonics, and action/weight metadata.
4. Module ownership for callouts comes from `FWPM_CALLOUT0.providerKey` resolved against the provider index and printed as the provider display name plus `serviceName`. Kernel-mode callout function pointers are intentionally not surfaced because user-mode `FWPM_CALLOUT0` does not expose them; documented kernel-side walking is reserved for a later milestone.
5. `!wfp callouts /module <name|GUID>` filters by provider service name (case-insensitive substring), provider display name, or `providerKey` GUID. `!wfp filters /layer <name|GUID>` filters by layer display-name substring or `layerKey` GUID, and `/provider` applies the same provider matching as `/module` for filters.
6. The `wfp.list` AI capability tool routes back through `HandleWfpCommand` with scope and optional module/layer arguments validated against the same shape rules used for plan commands.

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

The interactive prompt uses a console key reader instead of plain line input. Tab completion is built from `CommandRegistry` plus context-specific subcommand tables for `callbacks`, `ai`, `backend`, `kdinit`, `probe`, `procctx`, `write`, `dt`, `vtop`, `s`, and native memory commands. Up/Down recalls recent non-empty commands with a bounded in-memory history; editing a recalled line turns it into the current draft, while blank Enter still repeats the last command for WinDbg-like ergonomics. The same command-family tables feed detailed help routing: `help <command>`, `<command> help`, `callbacks <scope> help`, `ai <subcommand> help`, and `ai help <subcommand>` all stop before command execution and print operator-focused usage for that command family. The top-level help explains state tags (`native`, `alias`, `dbgeng`), symbol/address conventions, `/process` versus `procctx`, count units, sparse-read `??` output, and write-context defaults so operators do not have to infer those rules from examples. The completer replaces the current token with a unique match or the longest common prefix; if the prefix is ambiguous, it prints candidates and redraws the current `knkd>` line.

Human-readable native command output uses scoped console attributes for high-signal tokens such as callback kind tags, object types, modules, symbols, translated physical addresses, and type/field names. The color layer is applied only while writing to the console stream, so transcript capture and JSONL records remain plain text.

## Build and Release Flow

1. `tools\build.ps1` is the authoritative scripted build path for PE-stamped artifacts.
2. It reads `.build\version-state.json`, falls back to the existing output PE version, and otherwise starts from `0.0.0`.
3. Normal builds do not increment the version; `-BumpVersion` increments the patch component by one and saves the new version state after a successful build.
4. The first bumped build is therefore `0.0.1`.
5. The script writes `.build\generated\KnLiveDbgVersion.h`, then MSBuild compiles VERSIONINFO resources into `KnLiveDbg.exe`, `KnLiveDbg.sys`, and `KnLiveDbgProbe.sys` before the WDK TestSign step.
6. After a successful build, the script verifies the stamped PE versions, verifies driver signatures, and stages Debugging Tools runtime DLLs beside the EXE.
7. `tools\release.ps1` runs a version-bumped build by default and creates `release\KnLiveDbg-<version>-<configuration>-x64.zip` from the output directory. `-NoVersionBump` keeps the current version for ad hoc packages.
8. The release zip includes the runnable EXE/SYS files, staged runtime dependencies, PDB/CER/CAT files when present, README/runtime manifest metadata, and `kn-live-dbg-version.json`.

## AI Provider Flow

1. `AiProviderRuntime` lives entirely in user mode.
2. Provider selection defaults to `.env` plus environment variables and can be changed for the current TUI session with `ai config provider`, `ai config policy`, `ai config model`, `ai config base-url`, and `ai config effort`.
3. `openai-codex-cli` executes `codex exec` as an external process and captures stdout/stderr.
4. `openai-codex-subscription` reads Codex OAuth credentials from environment variables or auth files and calls the Codex Responses endpoint.
5. `deepseek` and `openrouter` use OpenAI-compatible chat-completions requests over WinHTTP.
6. `.env` is loaded only from the executable directory; real environment variables override `.env` values.
7. AI requests receive only curated session context and the operator prompt. The model cannot call memory IOCTLs or execute generated debugger commands directly.
8. `ai <question>` uses a strict `kn-live-dbg.ai-capability-plan.v1` tool-router JSON schema. The provider chooses from local read-only tools such as `process.find`, `process.describe`, `type.describe`, `callbacks.list`, `wfp.list`, `alpc.list`, or `assistant.answer`; the C++ executor validates and runs the selected tools locally.
9. `ai config test` performs a real provider/model round-trip with a small marker prompt and reports transport status, HTTP status when available, elapsed time, and marker match result.
10. `KNLIVEDBG_AI_REMOTE_POLICY=local-only` or `ai config policy local-only` blocks HTTP-backed providers (`openai-codex-subscription`, `deepseek`, and `openrouter`) for private sessions.
11. `ai plan` requires a strict JSON command proposal object, parses it into in-memory plan state, and shows numbered commands with purpose and risk notes.
12. `ai plan` validates each proposed command before storing it: empty commands, nested `ai`, shutdown/unload commands, bare `kd`, overlong commands, and unknown non-DbgEng commands are rejected. Write-like proposals are forced to require explicit confirmation.
13. `ai run` routes approved read-only plan commands back through the normal TUI command dispatcher, so backend mode, DbgEng routing, and native command handling stay consistent.
14. Write-like commands, shutdown commands, unload commands, and nested `ai` commands are blocked from `ai run`.
15. `ai analyze callbacks`, `ai explain dt`, and `ai annotate u|uf` execute read-only evidence commands through the same dispatcher, then send bounded stdout/stderr evidence to the selected model. Callback analysis uses `callbacks <scope> [module]` output.
16. `ai diagnose` uses current session context plus an operator note to explain symbol, type-layout, DbgEng, or setup failures.
17. `ai playbook` creates deterministic read-only command plans for callback, minifilter, object-callback, address, and suspect-driver investigations. `run` still goes through the guarded `ai run` path.
18. `ai write <index> confirm` is the explicit operator confirmation path for planned write-like commands. The preflight path builds backup/read-current, small-range restore, translation, and verification commands for recognized write forms, then prints a deterministic before/after diff of verification stdout/stderr after the write.
19. `ai transcript` captures AI events and command stdout/stderr as JSONL after it is enabled.
20. `ai transcript max <bytes|off>` rotates long transcript files, and `ai transcript redact <on|off>` controls stdout/stderr redaction for long hex addresses and `sk-...` style tokens.
21. `ai audit <path|off|status>` writes a separate JSONL record for every write-like command that executes through the normal dispatcher.
20. Transcript command records include origin, backend mode, command class, write-like status, stdout/stderr character counts, deterministic output summaries, raw stdout/stderr, and keep-running state.
21. `ai report` writes a Markdown report with session context, provider status, transcript settings, write-audit path, parsed plan, and raw AI plan response.
22. `backend dbgeng` does not swallow `ai`; the TUI handles it before raw DbgEng command routing.

## Hardening Backlog

No large hardening backlog item is currently left open in this document. New work should be added here once it is scoped.

Completed hardening items:

1. JSONL write-command audit logging is implemented with `ai audit <path>`.
2. Transcript rotation and redaction controls are implemented with `ai transcript max` and `ai transcript redact`.
3. Transcript command records now include command-class labels such as `memory-read`, `physical-write`, `type`, `callbacks`, `disassembly`, `symbols`, `dbgeng`, and `session`.
4. Callback module filtering is implemented with `callbacks [scope] [module]`.
5. Write verification before/after diff rendering is implemented for confirmed AI write commands.
6. AI plan command schema validation is implemented before plan storage.
7. Local-only AI provider policy is implemented with `ai config policy local-only` and `KNLIVEDBG_AI_REMOTE_POLICY=local-only`.
8. Single-controller ownership is implemented in the driver and reported by `drvstatus`.
9. Process DTB resolution is implemented with PDB-resolved EPROCESS offsets and `procctx`/`vtop /process`; native `e*` writes use System (`pid 4`) as the default context.
10. LA57 detection and PML5E reporting are implemented in the page-table walker.
11. DIA fallback is implemented for UDT field metadata when `DbgHelp` fails.
12. `KnLiveDbgProbe.sys` provides a positive-control contiguous virtual and physical test buffer.
13. Remote KD attach is available through `kdinit /remote <connection-options>`.
14. AI command proposal validation is versioned as `kn-live-dbg.ai-plan.v2` and rejects missing purpose metadata, command chaining, session mutation, raw `kd` blocked-command wrappers, and unsupported backend expectations.
15. AI command evidence and transcripts include deterministic output summaries before raw stdout/stderr.
