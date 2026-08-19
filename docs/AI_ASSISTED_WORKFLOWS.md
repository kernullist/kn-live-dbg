# AI-Assisted Workflows

This document captures the implemented AI assistance surface in Kn Live Dbg plus the remaining guardrails for future work. The goal is not to turn the tool into an autonomous kernel editor. The useful direction is an operator assistant that explains live kernel state, proposes commands, highlights risk, and produces repeatable investigation records.

## Design Principles

1. AI assistance should be advisory by default. It can suggest commands and explain results, but command execution should stay visible to the operator.
2. Every generated command should have a preview that shows the exact Kn Live Dbg command line, selected backend expectation, target address or symbol, and expected read/write behavior.
3. Write operations need stronger gates than read operations. Before `e*`, `pe*`, `setfield`, or other write commands, the assistant should show the current value, proposed value, byte width, target VA/PA context when available, backup command, and post-write verification command.
4. Reports should keep raw evidence. AI summaries must include the original commands, relevant output snippets, addresses, symbols, modules, and failure messages used to reach the conclusion.
5. Backend behavior must be explicit. The assistant should know when a request maps to the native backend, DbgEng fallback, or `kd <command>` escape hatch.
6. Sensitive memory and symbol output should be handled through a configurable model provider policy. Offline/local models should be possible for private kernel state.
7. The driver should remain a narrow memory primitive provider. AI parsing, planning, risk scoring, and report generation belong in user mode.

## Current Implementation

The first integration layer is implemented as a user-mode `ai` command and `AiProviderRuntime` module. It is intentionally advisory, but the visible surface is now smaller:

1. `ai <question>` is the default operator entrypoint. It first recognizes exact read-only evidence commands such as `!callbacks`, `dt`, `dtx`, `u`, `uf`, `!ci`, or `!vbs` and runs them through evidence analysis. Requests that ask to list, show, recommend, or suggest commands are treated as planning requests before local capability execution. Otherwise it asks the selected provider to choose from a small read-only capability catalog, then validates and executes the selected local tools in C++. If no direct local tool fits but the request looks investigative, it automatically builds a validated command plan and leaves execution to `ai run`; conceptual `what`/`how`/`why` questions remain advisory instead of being forced into planning. The catalog exposes `process.find`, `process.describe`, `type.describe`, `callbacks.list`, `wfp.list`, `alpc.list`, `vad.list`, `threads.list`, `etw.integrity`, `nmi.list`, `pool.find`, `address.inspect`, `wnf.decode`, `wnf.list`, `ti.query`, `module.integrity`, `driver.integrity`, and `assistant.answer`.
2. `ai status` reports the selected provider, model, base URL, remote policy, credential source, loaded `.env` path, Codex CLI path, reasoning effort, and timeout.
3. `ai config ...` groups provider setup and smoke checks under one visible subcommand. It supports `status`, `providers`, `provider`, `policy`, `model`, `base-url`, `effort`, `auth`, and `test`.
4. `ai plan <prompt>` remains an explicit override that asks the model for a strict command proposal JSON object and stores the parsed command plan in memory.
5. `ai explain <read-only-command...>` remains an explicit override for evidence analysis. The same path is also reached implicitly when the operator types `ai !callbacks ...`, `ai dt ...`, `ai uf ...`, `ai !ci options`, or another recognized read-only evidence command.
6. `ai show` prints the most recent parsed or playbook command plan.
7. `ai run <index|all>` executes only planned commands that are not write-like, shutdown, unload, or nested AI commands.
8. `ai write <index> [confirm]` provides an explicit confirmation path for planned write-like commands. Without `confirm`, it prints target classification, size, backup/read-current, restore-current for small ranges, translation, verification, purpose, risk, and confirmation syntax.
9. `ai report <path>` exports a Markdown report with session context, provider status, transcript settings, write-audit path, the parsed plan, and the raw AI plan response.

The older detailed forms remain accepted for compatibility: `ai providers`, `ai provider`, `ai policy`, `ai model`, `ai base-url`, `ai effort`, `ai auth`, `ai preview`, `ai ask`, `ai analyze !callbacks`, `ai annotate`, `ai diagnose`, `ai playbook`, `ai transcript`, and `ai audit`.

Initial provider support:

1. `openai-codex-cli` shells out to `codex exec`, mirroring KernForge's Codex CLI bridge pattern.
2. `openai-codex-subscription` uses ChatGPT/Codex OAuth-style bearer tokens and the Codex Responses endpoint. It can read `KNLIVEDBG_CODEX_ACCESS_TOKEN`, `KERNFORGE_CODEX_ACCESS_TOKEN`, configured auth files, `%USERPROFILE%\.kernforge\codex_auth.json`, and `%USERPROFILE%\.codex\auth.json`.
3. `deepseek` uses an OpenAI-compatible chat-completions request with DeepSeek defaults and optional reasoning effort.
4. `openrouter` uses an OpenAI-compatible chat-completions request with OpenRouter defaults and metadata headers.

The runtime automatically loads `.env` only from the executable directory. Real process environment variables override `.env` values. `.env.example` documents the common OpenRouter and DeepSeek keys plus `KNLIVEDBG_AI_REMOTE_POLICY`. `.env` and `.env.local` are ignored by Git.

`ai config test [prompt]` is the provider round-trip smoke check. Without a custom prompt, it asks the selected provider/model to return `kn-live-dbg-ai-ok`, then prints the configured provider, model, remote policy, credential status, transport result, HTTP status when available, elapsed time, and marker match result.

The current layer can execute approved read-only model-proposed commands through `ai run`. Write-like commands remain blocked from `ai run` and require `ai write <index> confirm`. Write confirmation now runs deterministic preflight reads before mutation, emits exact byte restore commands for small recognized ranges, runs verification reads afterward when the command can be classified, and prints a deterministic before/after stdout/stderr diff for the verification command. Transcript mode captures full command output after it is enabled, including backend mode, origin, command class, write-like classification, stdout, stderr, keep-running state, output character counts, and deterministic output summaries. Transcript rotation and stdout/stderr redaction are configurable for long live sessions, and the optional write audit log records every write-like command that passes through the normal dispatcher. AI callback analysis now fits under both `ai !callbacks ...` and `ai explain !callbacks ...`, and consumes normal `!callbacks <scope> [module]` evidence. The command proposal JSON is now versioned as `kn-live-dbg.ai-plan.v2`, with stricter command metadata validation for purpose, risk, backend expectation, expected output, command chaining, session mutation, and raw `kd` write/session wrapping.

The main `ai help` output stays focused on the primary workflow. Detailed compatibility topics still have operator help through `ai <subcommand> help` and `ai help <subcommand>`.

## Operator Command Examples

Default rule: prefer `ai <goal>` during normal use. Exact read-only command lines after `ai` are treated as evidence to run and explain, investigative requests can become a validated plan, and conceptual `what`/`how`/`why` questions stay advisory.

Provider and session setup:

```text
ai status
ai config status
ai config provider openrouter
ai config model deepseek/deepseek-r1
ai config policy local-only
ai config test
ai help
```

Process and `_EPROCESS` triage:

```text
ai a.exe pid
ai a.exe eprocess
ai a.exe process eprocess info
ai pid 1234 dtb
ai pid 1234 peb
ai show parent process for pid 1234
ai find process named game.exe
ai describe eprocess 0xffffc10212345080
```

Structure, symbol, and disassembly evidence:

```text
ai dt nt!_EPROCESS 0xffffc10212345080
ai dtx nt!_ETHREAD 0xffffc10222220000
ai uf nt!PspCreateProcessNotifyRoutine 128
ai u fffff80212345678 40
ai ln fffff80212345678
ai x nt!*CreateProcess*
```

Callback analysis:

```text
ai !callbacks all WdFilter.sys
ai !callbacks object WdFilter.sys
ai !callbacks process
ai !callbacks imageload
ai WdFilter.sys object callbacks
ai show process creation callbacks
ai find callbacks owned by unknown modules
ai list minifilter callbacks
```

VBS, HVCI, CI, and Secure Kernel:

```text
ai check VBS status
ai is HVCI on?
ai !vbs
ai !ci options
ai decode CiOptions
ai list IUM trustlets
ai check secure kernel state
ai !securekernel
```

Module and driver integrity:

```text
ai inspect module text integrity
ai inspect module text integrity with headers and sections
ai find W+X kernel modules
ai summarize live module integrity mismatches
ai check driver dispatch integrity
ai inspect driver dispatch table for WdFilter.sys
ai find dispatch handlers outside owning driver image
```

WFP and ALPC:

```text
ai tcpip wfp callouts
ai wfp filters ALE_AUTH_CONNECT_V4
ai list WFP callouts owned by non-Microsoft modules
ai named alpc ports
ai alpc connections owned by lsass
ai inspect ALPC ports related to game.exe
```

VAD and thread triage:

```text
ai show executable private VADs for game.exe
ai find W+X regions in pid 1234
ai scan game.exe for VAD DKOM hidden PTE mappings
ai show suspicious thread starts for game.exe
ai check APC evidence for pid 1234
ai list threads with start addresses outside loaded modules
```

ETW, NMI, pool, WNF, and TI:

```text
ai any inline ETW hook?
ai check ETW dispatch integrity
ai list NMI callbacks
ai check NMI handler chain
ai show W+X pool allocations
ai pool tag Wmem larger than 0x10000
ai find leftover unbacked kernel hook targets
ai scan unloaded mapper remnants
ai show MmUnloadedDrivers and PiDDB leftovers
ai find executable kernel pages outside loaded modules
ai list filesystem minifilters
ai show IRP handlers for filter UnionFS
ai decode WNF state name 0x41c64e6da3bc0075
ai list live WNF instances
ai query recent TI WriteVM events
```

Requests that are good fits for automatic command planning:

```text
ai check VBS and CI configuration
ai scan kernel modules for executable writable sections
ai list commands to inspect suspicious driver callbacks
ai triage this address fffff80212345678
ai verify whether WdFilter.sys owns all its callbacks
ai show a read-only investigation plan for suspicious pool allocations
```

Conceptual questions that should stay advisory:

```text
ai what is HVCI?
ai how does CiOptions affect kernel code integrity?
ai why are W+X kernel pages suspicious?
ai explain why callback addresses outside modules matter
```

Explicit overrides for forcing a mode:

```text
ai explain !callbacks all WdFilter.sys
ai explain dt nt!_EPROCESS 0xffffc10212345080
ai plan check VBS status and decode CI options
ai run all
ai show
ai report .\reports\session-ai.md
```

## Implemented AI Features

### Natural-Language Operator Entry

Implemented entrypoint: `ai <question>`.

The command now behaves like a small tool-using agent and intent router. The operator can usually type `ai <goal>` without deciding between `plan` and `explain`. Exact read-only commands are executed as evidence and explained; local capability matches run through the strict tool catalog; unsupported investigative requests fall through to a validated command plan. The model receives the operator request and the capability catalog, returns a strict `kn-live-dbg.ai-capability-plan.v1` JSON object, and the local executor runs only supported read-only tools. The catalog handles process and `_EPROCESS` questions by walking `_EPROCESS.ActiveProcessLinks` through the same native data path as `!dml_proc`, dispatches callback/WFP/ALPC requests to native scanners, and routes VAD/thread triage through the read-only process scanner:

- "a.exe pid" -> matching PID records from the live process list
- "a.exe eprocess" -> matching `_EPROCESS` addresses
- "pid 1234 dtb" -> kernel and user directory-table base values
- "pid 1234 peb" -> `_EPROCESS.Peb` when the field is available
- "a.exe process eprocess info" -> `process.find` followed by `process.describe` or `type.describe`
- "WdFilter.sys object callbacks" -> `callbacks.list` with `scope=object` and `module=WdFilter.sys`
- "tcpip wfp callouts" -> `wfp.list` with `scope=callouts` and `module=tcpip`
- "wfp filters ALE_AUTH_CONNECT_V4" -> `wfp.list` with `scope=filters` and `layer=ALE_AUTH_CONNECT_V4`
- "named alpc ports" -> `alpc.list` with `scope=ports`
- "alpc connections owned by lsass" -> `alpc.list` with `scope=connections` and `name=lsass`
- "show executable private VADs for game.exe" -> `vad.list` with `image=game.exe`, `exec=true`, and `private=true`
- "find W+X regions in pid 1234" -> `vad.list` with `pid=1234` and `wx=true`
- "scan game.exe for VAD DKOM hidden PTE mappings" -> `vad.list` with `image=game.exe` and `hiddenpte=true`
- "show suspicious thread starts for game.exe" -> `threads.list` with `image=game.exe`
- "check APC evidence for pid 1234" -> `threads.list` with `pid=1234` and `apc=true`
- "any inline ETW hook?" or "ETW dispatch integrity" -> `etw.integrity`
- "list NMI callbacks" or "check NMI handler chain" -> `nmi.list`
- "show W+X pool allocations" -> `pool.find` with `wx=true`
- "pool tag Wmem larger than 0x10000" -> `pool.find` with `tag=Wmem` and `min=0x10000`
- "find leftover unbacked kernel hook targets" -> `payload.scan` (hook-to-body layer)
- "scan unloaded mapper remnants" or "show MmUnloadedDrivers and PiDDB leftovers" -> `mapper.list` (bookkeeping remnants; leftover=0 is not payload absence)
- "find executable kernel pages outside loaded modules" -> `kpage.list` without `deep` (orphan-page layer)
- "kdmapper / manual-map after the driver is gone" -> `mapper.list` then `kpage.list` then `payload.scan`; do not stop at a clean mapper.list
- "list filesystem minifilters" -> `minifilter.list`
- "show IRP handlers for filter UnionFS" -> `minifilter.list` with `filter=UnionFS`
- Disable/enable of minifilter IRP handlers is not on the AI planner. Use the
  console (`!minifilter disable <name> all` / `disable-all`) or MCP
  `minifilter.set_irp` with `irp=all` under `--allow-write`.
- "why is this address suspicious?" -> `address.inspect` with `address=<va-or-symbol>`
- "decode WNF state name 0x41c64e6da3bc0075" -> `wnf.decode` with `hash=0x41c64e6da3bc0075`
- "list live WNF instances" -> `wnf.list` with `scope=instances`
- "recent TI WriteVM events" -> `ti.query` with `action=grep` and `pattern=WriteVM`
- "inspect module text integrity" -> `module.integrity` with `target=all`, `headers=true`, and `sections=true`
- "find W+X kernel modules" -> `module.integrity` with `target=all`, `wx=true`, and `verbose=true`
- "summarize live module integrity mismatches" -> `module.integrity` with `target=all`, `summary=true`, and `mismatch=true`
- "check driver dispatch integrity" -> `driver.integrity` with `target=all`
- "is HVCI on?" or "VBS status" -> automatic command plan for read-only native commands such as `!vbs`
- "decode CiOptions" -> exact evidence command with `ai !ci options` or automatic command plan from the natural-language request
- "list IUM trustlets" -> automatic command plan for `!securekernel`
- "!callbacks all WdFilter.sys" -> implicit evidence analysis, equivalent to `ai explain !callbacks all WdFilter.sys`
- "dt nt!_EPROCESS <address>" -> implicit evidence analysis for structure output
- "uf nt!PspCreateProcessNotifyRoutine 128" -> implicit evidence analysis for disassembly output
- "what is HVCI?" -> advisory answer, not automatic command planning

The model-backed planner remains available through `ai plan <prompt>` when the operator wants to force plan creation:

- "Show object callbacks" -> `!callbacks object`
- "Dump this address as an EPROCESS" -> `dt nt!_EPROCESS <address>`
- "Translate this virtual address and read the physical bytes" -> `vtop <address>` followed by `pdb <physical-address> <length>` or `!db <physical-address> <length>`
- "Disassemble this callback routine" -> `u <address> <count>` or `uf <symbol>`

Implementation notes:

1. Keep the AI-facing catalog small and explicit; adding more tools should be easier than adding more natural-language keyword rules.
2. Send only the request and catalog during tool selection. Live process records, kernel addresses, and structure dumps are produced by the local executor after validation.
3. The capability parser rejects unknown tools, unknown top-level fields, unknown step fields, and unknown per-tool arg fields before any native handler is called.
4. Capability executors reject unsafe characters, command chaining, help tokens, invalid booleans, invalid numeric arguments, write-like actions, raw `kd`, nested `ai`, session mutation, and unload/shutdown routes.
5. Resolve symbols before proposing commands when the request contains a symbol-like token.
6. Prefer `backend auto` unless the requested command clearly needs raw DbgEng parser semantics.
7. Display a command preview and require confirmation before execution for automatic or explicit command proposals.
8. For ambiguous requests, use `assistant.answer` or propose two or three command plans with tradeoffs rather than guessing silently.

### Callback Analysis Report

Implemented entrypoint: `ai explain !callbacks [all|object|registry|process|thread|imageload|minifilter] [module]`.

Compatibility entrypoint: `ai analyze !callbacks [all|object|registry|process|thread|imageload|minifilter] [module]`.

The command post-processes `!callbacks` output into an investigation report:

1. Count object-manager, registry, process creation, thread creation, image-load, and minifilter callbacks.
2. Group records by owning module and callback surface.
3. Flag callback addresses that do not resolve to a loaded module or nearest symbol.
4. Flag addresses outside expected executable image ranges.
5. Highlight modules that own callbacks across multiple surfaces.
6. Highlight unusual minifilter altitudes, missing names, missing unload routines, or duplicate operation handlers.
7. Separate known platform/security drivers from unknown or unsigned modules when signature metadata is available.

The report should include module name, callback address, nearest symbol, callback context, root/list address, object type or filter address, altitude, and confidence notes.

### `dt` and Structure Interpretation

Implemented entrypoint: `ai explain <dt|dtx> <dt-args...>`.

The command layers semantic explanations on top of native `dt` and `dtx` output:

1. Explain important fields for common kernel types such as `_EPROCESS`, `_ETHREAD`, `_DRIVER_OBJECT`, `_DEVICE_OBJECT`, `_OBJECT_TYPE`, `_CALLBACK_ENTRY`, `_CM_CALLBACK_CONTEXT_BLOCK`, `_EX_CALLBACK_ROUTINE_BLOCK`, `_FLT_FILTER`, and `_FLT_OPERATION_REGISTRATION`.
2. Suggest follow-up commands for pointer fields, `LIST_ENTRY` fields, callback routine fields, and object name fields.
3. Detect suspicious or inconsistent values such as null callback routines, self-referential list entries outside the expected head, invalid-looking pool pointers, or module pointers outside loaded image ranges.
4. Preserve raw field offsets and values so the AI explanation can be audited.

### Write Safety Assistant

Implemented entrypoint: `ai write <index> [confirm]`.

Because write mode is enabled by default per device handle, the AI path adds an operator safety layer around planned mutations:

1. Before a write, read and display the current value.
2. Show the exact target range, write width, interpreted type field when available, and whether the write crosses a page boundary.
3. For native `e*` virtual writes, treat the default address-space context as System (`pid 4`) unless the command includes `/process <process-id>`.
4. For virtual writes, offer `vtop` context when useful, including the leaf entry physical address, writable state, and whether a temporary write-bit flip plus VA flush is expected. Kernel VA edits should be described as temporary write-enable plus original-VA write; translated user VA edits should be described as physical writes through the selected process context.
5. For physical writes, warn when the target could be page tables, device memory, or firmware-owned memory.
6. Generate backup and restore commands before applying the write.
7. Re-read the target after the write and show a compact before/after diff.
8. Mark high-risk targets such as list links, reference counts, callback routine pointers, dispatch tables, page table entries, and executable code.

This feature should never hide the exact command being executed.

### Disassembly Annotator

Implemented entrypoint: `ai explain <u|uf> <address|symbol> [instruction-count]`.

Compatibility entrypoint: `ai annotate <u|uf> <address|symbol> [instruction-count]`.

The command adds AI analysis on top of `u` and `uf` output:

1. Summarize the likely purpose of a function.
2. Identify direct and indirect call targets when symbols are available.
3. Classify routines as object callback, registry callback, process callback, thread callback, image-load callback, minifilter operation callback, dispatch routine, or unknown.
4. Highlight suspicious patterns such as indirect calls through writable memory, global list mutation, callback registration, page table access, MSR access, or code patching.
5. Suggest next commands such as `ln`, `x`, `dt`, `dq`, or `uf` on a discovered call target.

The annotator should treat disassembly as evidence, not proof. The output should include uncertainty and the exact instruction ranges used.

### Symbol and Layout Diagnostics

Implemented entrypoint: `ai diagnose <prompt>`.

The command uses AI to explain failures in symbol, type, and backend setup:

1. PDB mismatch, missing private type information, or DIA/DbgHelp failure.
2. Field drift between Windows builds.
3. Missing non-exported symbols used by callback discovery.
4. DbgEng local-kernel attach limitations.
5. Fallback root selection for callback scanners.
6. DbgEng command failures caused by local KD behavior rather than command syntax.

The diagnostic output should recommend concrete remediation steps such as `.sympath`, `.reload`, `backend auto`, `kdinit`, re-running as administrator, or checking the Windows build and symbol cache.

### Investigation Playbooks

Implemented entrypoint: `ai playbook <callbacks|minifilter|object|address|driver> [argument] [run|dry-run]`.

The command packages common multi-command investigations into repeatable workflows:

1. Callback surface audit: `!callbacks all`, module grouping, disassembly of unknown callbacks, report generation.
2. Suspect driver surface map: list modules, enumerate symbols, find callbacks, inspect dispatch table, inspect minifilter registrations.
3. Address provenance: `ln`, module range lookup, `vtop`, `dq/db`, optional `dt`, and disassembly if executable.
4. Minifilter chain review: enumerate filters, sort by altitude, inspect operation callbacks, summarize unload/name-provider/instance routines.
5. Object callback integrity review: discover object types, walk callback lists, inspect pre/post operation routines and contexts.

Each playbook has a dry-run mode that prints the planned command sequence before execution. `run` dispatches the plan through the same guarded executor used by `ai run`.

### Session Report Generation

Implemented entrypoint: `ai report <path>`.

The report command generates a Markdown summary from the current AI session:

1. Session context, backend/provider state, and selected model.
2. Transcript and write-audit paths when enabled.
3. The current parsed command plan, including command purpose, risk, backend expectation, and expected output.
4. The raw AI plan response when one exists.
5. Operator follow-up context needed to reproduce the AI-assisted investigation.

Command stdout/stderr evidence is captured in JSONL by `ai transcript <path>` rather than embedded wholesale in the Markdown report. Write operations are captured separately by `ai audit <path>` and summarized by the report through the configured audit path.

## Suggested Implementation Order

No immediate AI workflow backlog items remain in this document. Larger platform items are tracked in `ARCHITECTURE.md`.

Completed implementation-order items:

1. Transcript/event rotation and redaction controls are implemented with `ai transcript max` and `ai transcript redact`.
2. Write-command JSONL audit logging is implemented with `ai audit <path>`.
3. Callback module filtering is implemented with `!callbacks [scope] [module]`, and `ai explain !callbacks` consumes the same filtered command output as evidence.
4. Deterministic before/after diff rendering is implemented for `ai write <index> confirm` verification output.
5. Model-proposed command plans are validated at ingestion with the v2 schema contract: empty commands, missing purpose metadata, unsupported backend expectations, command chaining, multiline commands, nested `ai`, shutdown/unload commands, backend/session mutation, probe service control, bare `kd`, raw `kd` wrapping of blocked commands, overlong commands, and unknown non-DbgEng commands are rejected before they can be shown as a runnable plan. Write-like proposals, including raw `kd` write-like wrappers, are forced to require confirmation.
6. Command transcript and AI evidence prompts include deterministic output summaries with stdout/stderr character counts, line counts, interesting-line counts, and first/last non-empty lines before raw output.
7. Local/offline provider policy is implemented with `ai config policy local-only` and `KNLIVEDBG_AI_REMOTE_POLICY=local-only`, which block HTTP-backed providers.

## Non-Goals

1. Do not move AI parsing or model execution into the kernel driver.
2. Do not allow hidden autonomous writes.
3. Do not treat AI explanations as authoritative without raw command evidence.
4. Do not require a remote model provider for normal live-kernel use.
