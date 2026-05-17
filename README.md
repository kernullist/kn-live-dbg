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
15. Provides an initial AI assistant provider layer for advisory command planning and result interpretation through Codex CLI, ChatGPT/Codex OAuth, DeepSeek, and OpenRouter.

## Design Notes

- `docs/ARCHITECTURE.md` describes the driver/user split and backend routing.
- `docs/WINDBG_COMMAND_COVERAGE.md` tracks native and DbgEng-routed WinDbg command coverage.
- `docs/AI_ASSISTED_WORKFLOWS.md` captures planned AI-assisted command planning, callback analysis, `dt` interpretation, disassembly annotation, write safety, playbooks, and session reporting.

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
ai status
ai provider <openai-codex-cli|openai-codex-subscription|deepseek|openrouter|off>
ai model <model>
ai auth
ai preview <prompt>
ai ask <prompt>
ai plan <prompt>
ai analyze callbacks [all|ob|registry|process|minifilter]
ai explain dt <dt-args...>
ai annotate <u|uf> <address|symbol> [instruction-count]
ai diagnose <prompt>
ai playbook <callbacks|minifilter|object|address|driver> [argument] [run|dry-run]
ai show
ai run <index|all>
ai write <index> [confirm]
ai transcript <path|off|status>
ai report <path>
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
knkd> ai provider openai-codex-cli
knkd> ai preview explain the callback surfaces I pasted above
knkd> ai plan inspect unknown object callbacks
knkd> ai show
knkd> ai run 1
knkd> ai transcript .\kn-ai-session.jsonl
knkd> ai report .\kn-ai-report.md
```

The registry also knows the standard execution, breakpoint, stack, register, source, exception, I/O port, and script commands. Native live-memory commands stay on the custom driver backend, while stop-state or parser-heavy commands are routed to DbgEng in `auto` or `dbgeng` mode.

`u` and `uf` are explicit disassembly commands. `u` resolves an address or symbol, disassembles a bounded instruction count, and remembers the next offset for a following bare `u`; `uf` uses the DbgEng function disassembler for function-boundary-aware output.

## AI Assistant Providers

The `ai` command is an advisory provider bridge. It does not execute generated debugger commands automatically, and it does not hide write operations. Use it to ask for command plans, explain pasted command output, or draft investigation next steps.

```text
ai status
ai providers
ai provider <openai-codex-cli|openai-codex-subscription|deepseek|openrouter|off>
ai model <model>
ai baseurl <url>
ai effort <minimal|low|medium|high|xhigh>
ai auth
ai preview <prompt>
ai ask <prompt>
ai plan <prompt>
ai analyze callbacks [all|ob|registry|process|minifilter]
ai explain dt <dt-args...>
ai annotate <u|uf> <address|symbol> [instruction-count]
ai diagnose <prompt>
ai playbook <callbacks|minifilter|object|address|driver> [argument] [run|dry-run]
ai show
ai run <index|all>
ai write <index> [confirm]
ai transcript <path|off|status>
ai report <path>
```

Provider configuration is loaded from `.env` first and can be overridden by real process environment variables. Kn Live Dbg checks the current directory, the executable directory, and the repository root when running from `x64\Debug` or `x64\Release`. Copy `.env.example` to `.env` and fill in only the provider you want to use:

```text
KNLIVEDBG_AI_PROVIDER=openrouter
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
2. `KNLIVEDBG_AI_MODEL` overrides the provider default model.
3. `KNLIVEDBG_AI_BASE_URL` overrides the provider base URL.
4. `KNLIVEDBG_DEEPSEEK_API_KEY` or `DEEPSEEK_API_KEY` supplies the DeepSeek API key.
5. `KNLIVEDBG_OPENROUTER_API_KEY` or `OPENROUTER_API_KEY` supplies the OpenRouter API key.
6. `KNLIVEDBG_CODEX_ACCESS_TOKEN`, `KERNFORGE_CODEX_ACCESS_TOKEN`, `KNLIVEDBG_CODEX_AUTH_FILE`, or `KERNFORGE_CODEX_AUTH_FILE` supplies ChatGPT/Codex OAuth credentials.
7. If no Codex auth file is configured, Kn Live Dbg checks `%USERPROFILE%\.kernforge\codex_auth.json` and `%USERPROFILE%\.codex\auth.json`.
8. `KNLIVEDBG_CODEX_CLI_PATH` overrides the `codex` executable used by `openai-codex-cli`.

Run `codex login` outside Kn Live Dbg when ChatGPT/Codex OAuth credentials are missing or expired. `ai status` shows the loaded `.env` path and credential source. `ai preview` shows provider, model, credential source, and prompt size without sending a request.

`ai plan <prompt>` asks the selected model to return a strict command proposal JSON object, stores the parsed plan in memory, and prints numbered commands with purpose and risk notes. `ai analyze callbacks`, `ai explain dt`, and `ai annotate u|uf` run a read-only evidence command, preserve stdout/stderr, then ask the selected model for a callback report, structure interpretation, or disassembly annotation. `ai diagnose` produces setup and symbol/backend remediation guidance from an operator note. `ai playbook` loads repeatable read-only command plans for callback, minifilter, object-callback, address, and suspect-driver investigations; `dry-run` is the default, and `run` dispatches the plan through the same guarded executor as `ai run`.

`ai run <index|all>` executes only non-write, non-shutdown planned commands. Write-like commands such as `e*`, `pe*`, `setfield`, `f`, and `m` are blocked from `ai run`; `ai write <index>` prints a write preview with target class, byte count, backup/read-current command, restore-current command for small ranges, verification command, and safe read-only preflight output. `ai write <index> confirm` re-runs the backup read, dispatches the write-like command, then re-runs the verification command. `ai transcript <path>` enables JSONL capture of AI events and command stdout/stderr, including backend mode and write-like classification. `ai report <path>` exports a Markdown summary of the current AI session and plan.

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
| `native` | Uses the native command handlers and blocks generic DbgEng fallback. | Driver-backed memory, symbol, type, callback, and physical-memory work. | `!extension`, stack/register/breakpoint/execution/source/exception commands are reported as DbgEng-only instead of being executed. Explicit `u` and `uf` remain available and may initialize DbgEng for decoding. |
| `dbgeng` | Sends most non-session commands directly to DbgEng raw execution. | WinDbg-compatible parser behavior. | Session commands, `callbacks`, and explicit `u`/`uf` are still handled by the TUI before the raw DbgEng catch-all. |

`kd <command>` is an explicit raw DbgEng escape hatch and does not depend on the current backend mode.

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
