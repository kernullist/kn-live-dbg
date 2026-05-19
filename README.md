# Kn-Live-Dbg

Kn-Live-Dbg is a Windows kernel live-debugging experiment shaped after the useful part of LiveKD: the kernel driver exposes narrow memory primitives, while the user-mode console owns service lifecycle, symbol loading, type interpretation, and operator UX.

## Demo

https://github.com/user-attachments/assets/f3542a85-c960-46f2-a151-fdd23a8294a6

If the embedded video does not render, open the [README-sized demo](demo/kn-live-dbg-demo-readme.mp4) or the [full-resolution demo](demo/kn-live-dbg-demo.mp4).

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
21. Builds and manages `KnLiveDbgProbe.sys`, a positive-control test driver with known virtual and physical buffer addresses.

## Design Notes

- `docs/ARCHITECTURE.md` describes the driver/user split and backend routing.
- `docs/WINDBG_COMMAND_COVERAGE.md` tracks native and DbgEng-routed WinDbg command coverage.
- `docs/AI_ASSISTED_WORKFLOWS.md` captures planned AI-assisted command planning, callback analysis, `dt` interpretation, disassembly annotation, write safety, playbooks, and session reporting.

## Build

Requirements:

1. Visual Studio 2022.
2. Windows Driver Kit 10.0.26100.0.
3. x64 developer shell or normal PowerShell with MSBuild at the default VS Professional path.
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
The build helper also stages the pinned `vendor\debugging-tools\x64` runtime beside the EXE (`dbghelp.dll`, `dbgeng.dll`, `dbgcore.dll`, `DbgModel.dll`, `msdia140.dll`, `symsrv.dll`, `srcsrv.dll`, and `symsrv.yes`) so DbgHelp and DbgEng can use the Microsoft symbol server instead of falling back to the limited System32 runtime. If the vendor pair is missing, the script falls back to the locally installed Windows Kits Debugging Tools copy. If `symsrv.dll` is staged but `symsrv.yes` is missing, the sync script, build script, and EXE startup path create `symsrv.yes` before symbol loading. Startup creates `<exe-dir>\symbols` and uses it as the downstream symbol store, so downloaded PDBs stay with the runnable EXE bundle rather than going to `C:\Symbols`. When `msdia140.dll` is staged, startup registers it automatically with `DllRegisterServer` before symbol initialization. The symbol engine also has a no-reg fallback that loads the staged `msdia*.dll` directly and creates `IDiaDataSource` through `DllGetClassObject`, so type fallback can still work when COM registration is unavailable.

Create a release zip:

```powershell
.\tools\release.ps1 -Configuration Release
```

The release helper runs a version-bumped build unless `-SkipBuild` or `-NoVersionBump` is supplied, then creates `release\KnLiveDbg-<version>-Release-x64.zip` containing the built EXE/SYS files, staged Debugging Tools runtime, PDB/CER/CAT files when present, `README.md`, the vendored runtime manifest when present, and `kn-live-dbg-version.json`.

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

The `knkd>` prompt supports Tab completion for registered commands and context-aware subcommands, plus Up/Down history recall for recent commands. Examples include `callbacks <Tab>` for callback scopes, `callbacks object /module<Tab>` for the module option, `ai <Tab>` for AI actions, `ai analyze callbacks <Tab>` for callback scopes, `backend <Tab>`, `probe <Tab>`, `procctx <Tab>`, `write <Tab>`, and option completion such as `dt -<Tab>`, `vtop /<Tab>`, and `db /<Tab>`. Callback completion and parsing use only canonical scope names (`object`, `registry`, `process`, `thread`, `imageload`, `minifilter`) plus `all`, `/module`, and `help`; short aliases are intentionally not accepted. Help is available as both `help <command>` and `<command> help`; nested AI topics also support `ai <subcommand> help` or `ai help <subcommand>`. When a prefix is ambiguous, the prompt prints matching candidates and redraws the current input line without dispatching anything.

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
ai status
ai providers
ai provider <openai-codex-cli|openai-codex-subscription|deepseek|openrouter|off>
ai policy <allow-remote|local-only|status>
ai model <model>
ai base-url <url>
ai effort <minimal|low|medium|high|xhigh>
ai auth
ai preview <prompt>
ai ask <prompt>
ai plan <prompt>
ai analyze callbacks [all|object|registry|process|thread|imageload|minifilter] [module]
ai explain dt <dt-args...>
ai annotate <u|uf> <address|symbol> [instruction-count]
ai diagnose <prompt>
ai playbook <callbacks|minifilter|object|address|driver> [argument] [run|dry-run]
ai show
ai run <index|all>
ai write <index> [confirm]
ai transcript <path|off|status>
ai transcript max <bytes|off>
ai transcript redact <on|off>
ai audit <path|off|status>
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
- API-key AI providers load `.env` from the current directory, EXE directory, or repo root; `ai run` remains read-only and `ai write <index> confirm` is required for write-like plans.

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
knkd> ai provider openai-codex-cli
knkd> ai preview explain the callback surfaces I pasted above
knkd> ai plan inspect unknown object callbacks
knkd> ai show
knkd> ai run 1
knkd> ai transcript .\kn-ai-session.jsonl
knkd> ai transcript max 10485760
knkd> ai transcript redact on
knkd> ai audit .\kn-write-audit.jsonl
knkd> ai report .\kn-ai-report.md
knkd> probe load
knkd> probe info
```

The registry also knows the standard execution, breakpoint, stack, register, source, exception, I/O port, and script commands. Native live-memory commands stay on the custom driver backend, while stop-state or parser-heavy commands are routed to DbgEng in `auto` or `dbgeng` mode.

Memory display commands use sparse reads. If part of a requested virtual or physical range cannot be read, the printable dump stays aligned and unknown bytes are shown as `??`, with wider unit displays using `0x????...` for unreadable units.

`u` and `uf` are explicit disassembly commands. `u` resolves an address or symbol, reads code bytes through the loaded driver, disassembles them with the vendored Zydis x64 decoder, and remembers the next offset for a following bare `u`; if the driver device is not open, it falls back to the DbgEng disassembly path. `uf` uses the same driver-backed Zydis path and linearly disassembles from the start address until a function terminal instruction such as `ret`, `iret`, `sysret`, `sysexit`, `hlt`, `ud2`, or `int3`, with an optional instruction cap.

## AI Assistant Providers

The `ai` command is an advisory provider bridge. It does not execute generated debugger commands automatically, and it does not hide write operations. Use it to ask for command plans, explain pasted command output, or draft investigation next steps.

```text
ai status
ai providers
ai provider <openai-codex-cli|openai-codex-subscription|deepseek|openrouter|off>
ai policy <allow-remote|local-only|status>
ai model <model>
ai base-url <url>
ai effort <minimal|low|medium|high|xhigh>
ai auth
ai preview <prompt>
ai ask <prompt>
ai plan <prompt>
ai analyze callbacks [all|object|registry|process|thread|imageload|minifilter] [module]
ai explain dt <dt-args...>
ai annotate <u|uf> <address|symbol> [instruction-count]
ai diagnose <prompt>
ai playbook <callbacks|minifilter|object|address|driver> [argument] [run|dry-run]
ai show
ai run <index|all>
ai write <index> [confirm]
ai transcript <path|off|status>
ai transcript max <bytes|off>
ai transcript redact <on|off>
ai audit <path|off|status>
ai report <path>
```

Provider configuration is loaded from `.env` first and can be overridden by real process environment variables. Kn Live Dbg checks the current directory, the executable directory, and the repository root when running from `x64\Debug` or `x64\Release`. Copy `.env.example` to `.env` and fill in only the provider you want to use:

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

Run `codex login` outside Kn Live Dbg when ChatGPT/Codex OAuth credentials are missing or expired. `ai status` shows the loaded `.env` path, remote policy, and credential source. `ai policy local-only` can be used during a sensitive session to block HTTP-backed providers without editing `.env`. `ai preview` shows provider, model, remote policy, credential source, and prompt size without sending a request.

`ai plan <prompt>` asks the selected model to return a strict `kn-live-dbg.ai-plan.v2` command proposal JSON object, validates proposed commands before storing them, and prints numbered commands with purpose, risk, backend, and expected-output notes. Empty commands, missing purpose metadata, unsupported backend expectations, command chaining, multiline commands, nested `ai`, shutdown/unload commands, backend/session mutation, probe service control, bare `kd`, raw `kd` wrapping of blocked commands, overlong commands, and unknown non-DbgEng commands are rejected; write-like proposals are forced to require confirmation. `ai analyze callbacks`, `ai explain dt`, and `ai annotate u|uf` run a read-only evidence command, preserve stdout/stderr, add a deterministic output summary, then ask the selected model for a callback report, structure interpretation, or disassembly annotation. Callback analysis uses normal `callbacks <scope> [module]` output as evidence. `ai diagnose` produces setup and symbol/backend remediation guidance from an operator note. `ai playbook` loads repeatable read-only command plans for callback, minifilter, object-callback, address, and suspect-driver investigations; `dry-run` is the default, and `run` dispatches the plan through the same guarded executor as `ai run`.

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
| `dbgeng` | Sends most non-session commands directly to DbgEng raw execution. | WinDbg-compatible parser behavior. | Session commands, `callbacks`, `!dml_proc`, native physical bang commands, and explicit `u`/`uf` are still handled by the TUI before the raw DbgEng catch-all. |

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

## Virtual-To-Physical And Physical Memory

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

## Positive-Control Probe

`KnLiveDbgProbe.sys` is an optional test driver that exposes a deterministic 4 KB contiguous nonpaged buffer. It is intended for smoke tests of virtual reads, VA-to-PA translation, physical reads, physical writes, and restore flows without guessing at arbitrary kernel memory.

```text
probe load
probe status
probe info
db <probe-virtual-address> 40
pdb <probe-physical-address> 40
probe reset
probe unload
```

The buffer pattern is `(index * 13 + 0x5a) & 0xff`. `probe info` prints both the virtual and physical buffer addresses and example `db`/`pdb` commands.

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
