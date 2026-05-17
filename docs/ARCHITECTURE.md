# Architecture

## Recommended Split

Kn Live Dbg follows a LiveKD-style split:

1. Kernel driver
   - Owns only privileged memory operations.
   - Creates the device with an Administrators/SYSTEM-only security descriptor.
   - Validates IOCTL buffers and sizes.
   - Uses `MmCopyMemory` for virtual reads.
   - Walks x64 page tables for VA-to-PA translation.
   - Uses `MmCopyMemory` for physical reads.
   - Uses page-sized `MmMapIoSpaceEx` mappings for physical writes.
   - Keeps write access controlled per open handle, with writes enabled by default.

2. User-mode TUI
   - Owns driver install/load/unload through SCM.
   - Owns kernel module enumeration.
   - Owns symbol path, PDB loading, type lookup, and field offset resolution.
   - Owns PDB-driven callback list decoding for object, registry, process, and minifilter callbacks.
   - Presents Windbg-like commands.
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

All requests include an explicit `Size` field. Variable read/write payloads use `FIELD_OFFSET(..., Data)` as the header size.

## Physical Memory Flow

1. `vtop` sends a virtual address, optional directory-table base, and requested length to the driver.
2. If the directory-table base is zero, the driver uses the current x64 CR3.
3. The driver reads PML4E, PDPTE, PDE, and PTE entries with `MmCopyMemory(..., MM_COPY_MEMORY_PHYSICAL)`.
4. The walk supports 4 KB pages plus 2 MB and 1 GB large pages.
5. The response reports CR3, VA, PA, page size, page offset, contiguous translated bytes, and the page-table entries that were used.
6. `phys`, `pdb`, `pdw`, `pdd`, and `pdq` read physical memory directly through `IOCTL_KNDBG_READ_PHYSICAL`.
7. `peb`, `pew`, `ped`, and `peq` write physical memory through `IOCTL_KNDBG_WRITE_PHYSICAL`; write mode starts enabled and can be disabled with `write off`.

## Symbol Flow

1. TUI calls `NtQuerySystemInformation(SystemModuleInformation)`.
2. TUI translates `\SystemRoot\...` paths into local Windows paths.
3. TUI calls `SymLoadModuleExW` for each loaded kernel image.
4. `addr` uses `SymFromNameW`.
5. `dt` uses `SymGetTypeFromNameW` and `SymGetTypeInfo`.
6. `callbacks` resolves private callback structure fields from kernel PDBs, discovers object type objects from `ObTypeIndexTable`, discovers registry/process callback roots by enumerating and validating candidate symbols, discovers minifilters from `fltmgr!FltGlobals.FrameList`, walks live list/table roots through the memory reader, and annotates function/context addresses with loaded module ownership.
7. `u` resolves an address or symbol with the native symbol engine, then calls DbgEng `DisassembleWide` directly for bounded instruction output.
8. `uf` is an explicit function-disassembly command that uses DbgEng function-boundary logic.
9. `setfield` resolves a field offset in user mode, then sends a byte write to the driver.

## Callback Scanner Flow

1. Object callbacks: resolve `_OBJECT_TYPE.CallbackList`, discover object type objects from `ObTypeIndexTable`, read `_OBJECT_TYPE.Name`, then walk each callback list.
2. Registry callbacks: enumerate `CmpCallbackListHead` and nearby candidate symbols, validate the list-head shape, then walk `_CM_CALLBACK_CONTEXT_BLOCK` records.
3. Process callbacks: enumerate `PspCreateProcessNotifyRoutine` and nearby candidate symbols, validate table slots, decode fast references, then read `_EX_CALLBACK_ROUTINE_BLOCK` records.
4. Minifilter callbacks: resolve `fltmgr!FltGlobals`, validate `FrameList`, walk `_FLTP_FRAME.RegisteredFilters`, decode `_FLT_FILTER` metadata, and enumerate `_FLT_OPERATION_REGISTRATION` entries plus filter-level routines.

## DbgEng Flow

1. `kdinit` or `backend dbgeng` initializes `DbgEngBackend`.
2. The backend calls `DebugCreate(__uuidof(IDebugClient5))`.
3. It installs an `IDebugOutputCallbacksWide` capture sink.
4. It queries `IDebugControl4` and `IDebugSymbols3`.
5. It mirrors the current symbol path into DbgEng.
6. It attaches with `AttachKernelWide(DEBUG_ATTACH_LOCAL_KERNEL, nullptr)`.
7. Raw commands are executed with `IDebugControl4::ExecuteWide`.

The DbgEng backend is intentionally isolated from the native memory backend. Native read/write operations still go through `KnLiveDbg.sys`, while DbgEng commands execute through the debugger engine.

`u` and `uf` are deliberately wired as explicit commands instead of falling through the generic command router. This keeps unassembly available even when the operator is otherwise using native command mode, while still relying on DbgEng for the instruction decoder and function-boundary semantics.

Backend routing is mode-dependent:

1. `auto` is the default. Implemented native commands stay on the driver/`DbgHelp` path, while registered DbgEng commands, `!extension` commands, and unknown dot meta-commands initialize or reuse DbgEng.
2. `native` disables generic DbgEng fallback. Commands that require WinDbg parser, stop-state, extension, breakpoint, register, stack, source, trace, or exception semantics are reported as DbgEng-only instead of being executed.
3. `dbgeng` routes most non-session commands through `IDebugControl4::ExecuteWide`. The TUI still intercepts shutdown/service commands, backend management, native callback scanning, and explicit `u`/`uf`.
4. `kd <command>` is a raw DbgEng escape hatch independent of the selected backend mode.

## AI Provider Flow

1. `AiProviderRuntime` lives entirely in user mode.
2. Provider selection defaults to `.env` plus environment variables and can be changed for the current TUI session with `ai provider`, `ai model`, `ai baseurl`, and `ai effort`.
3. `openai-codex-cli` executes `codex exec` as an external process and captures stdout/stderr.
4. `openai-codex-subscription` reads Codex OAuth credentials from environment variables or auth files and calls the Codex Responses endpoint.
5. `deepseek` and `openrouter` use OpenAI-compatible chat-completions requests over WinHTTP.
6. `.env` is searched in the current directory, executable directory, and repository root when running from `x64\Debug` or `x64\Release`; real environment variables override `.env` values.
7. AI requests receive only curated session context and the operator prompt. The model cannot call memory IOCTLs or execute generated debugger commands directly.
8. `ai plan` requires a strict JSON command proposal object, parses it into in-memory plan state, and shows numbered commands with purpose and risk notes.
9. `ai run` routes approved read-only plan commands back through the normal TUI command dispatcher, so backend mode, DbgEng routing, and native command handling stay consistent.
10. Write-like commands, shutdown commands, unload commands, and nested `ai` commands are blocked from `ai run`.
11. `ai write <index> confirm` is the explicit operator confirmation path for planned write-like commands.
12. `ai transcript` captures AI events and command stdout/stderr as JSONL after it is enabled.
13. `ai report` writes a Markdown report with session context, provider status, transcript path, parsed plan, and raw AI plan response.
14. `backend dbgeng` does not swallow `ai`; the TUI handles it before raw DbgEng command routing.

## Hardening Backlog

1. Add a global single-controller policy so only one PID can own the device at a time.
2. Add JSONL audit logging for every write command.
3. Add an optional EPROCESS/DirectoryTableBase resolver for process-specific user VA translation.
4. Add LA57 detection if five-level paging becomes a supported target.
5. Add DIA fallback for richer type metadata and bitfield handling.
6. Add a positive-control test driver that exposes known virtual and physical test buffers.
7. Add transcript rotation and redaction controls for long live sessions.
8. Add DbgEng command classification to transcript records beyond the current backend-mode field.
9. Add an optional remote KD connection mode once the local-kernel path is stable.
