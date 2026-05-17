# AI-Assisted Workflows

This document captures implementation ideas for adding AI assistance to Kn Live Dbg. The goal is not to turn the tool into an autonomous kernel editor. The useful direction is an operator assistant that explains live kernel state, proposes commands, highlights risk, and produces repeatable investigation records.

## Design Principles

1. AI assistance should be advisory by default. It can suggest commands and explain results, but command execution should stay visible to the operator.
2. Every generated command should have a preview that shows the exact Kn Live Dbg command line, selected backend expectation, target address or symbol, and expected read/write behavior.
3. Write operations need stronger gates than read operations. Before `e*`, `pe*`, `setfield`, or other write commands, the assistant should show the current value, proposed value, byte width, target VA/PA context when available, backup command, and post-write verification command.
4. Reports should keep raw evidence. AI summaries must include the original commands, relevant output snippets, addresses, symbols, modules, and failure messages used to reach the conclusion.
5. Backend behavior must be explicit. The assistant should know when a request maps to the native backend, DbgEng fallback, or `kd <command>` escape hatch.
6. Sensitive memory and symbol output should be handled through a configurable model provider policy. Offline/local models should be possible for private kernel state.
7. The driver should remain a narrow memory primitive provider. AI parsing, planning, risk scoring, and report generation belong in user mode.

## Current Implementation

The first integration layer is implemented as a user-mode `ai` command and `AiProviderRuntime` module. It is intentionally advisory:

1. `ai status` reports the selected provider, model, base URL, remote policy, credential source, loaded `.env` path, Codex CLI path, reasoning effort, and timeout.
2. `ai providers` lists the supported provider names.
3. `ai provider <name>` switches between `openai-codex-cli`, `openai-codex-subscription`, `deepseek`, `openrouter`, and `off`.
4. `ai policy <allow-remote|local-only|status>` controls whether HTTP-backed providers are allowed in the current session.
5. `ai model <model>`, `ai baseurl <url>`, and `ai effort <effort>` update the in-memory provider settings for the current session.
6. `ai auth` prints the supported `.env` keys, environment variables, and Codex auth file search paths.
7. `ai preview <prompt>` prints the outbound provider plan without sending a request.
8. `ai ask <prompt>` sends an advisory request. The assistant receives session context such as backend mode, number base, symbol path, loaded module count, and write-safety rules.
9. `ai plan <prompt>` asks the model for a strict command proposal JSON object and stores the parsed command plan in memory.
10. `ai analyze callbacks [scope]` runs `callbacks json <scope>` as read-only structured evidence, then asks the selected model for a callback analysis report.
11. `ai explain dt <dt-args...>` runs native `dt` or `dtx`, preserves raw output, then asks the model for structure-field interpretation and follow-up commands.
12. `ai annotate <u|uf> <address|symbol> [count]` runs disassembly and asks the model for call-target, routine-purpose, and suspicious-pattern annotation.
13. `ai diagnose <prompt>` sends a setup/symbol/backend failure note with current session context and asks for likely root causes and remediation commands.
14. `ai playbook <callbacks|minifilter|object|address|driver> [argument] [run|dry-run]` loads repeatable read-only investigation command plans. Dry-run is the default.
15. `ai show` prints the most recent parsed or playbook command plan.
16. `ai run <index|all>` executes only planned commands that are not write-like, shutdown, unload, or nested AI commands.
17. `ai write <index> [confirm]` provides an explicit confirmation path for planned write-like commands. Without `confirm`, it prints target classification, size, backup/read-current, restore-current for small ranges, translation, verification, purpose, risk, and confirmation syntax.
18. `ai transcript <path|off|status>` controls JSONL transcript capture for AI events and command stdout/stderr.
19. `ai transcript max <bytes|off>` rotates long transcript files, and `ai transcript redact <on|off>` controls stdout/stderr redaction for long hex addresses and `sk-...` style tokens.
20. `ai audit <path|off|status>` controls a separate write-command JSONL audit log.
21. `ai report <path>` exports a Markdown report with session context, provider status, transcript settings, write-audit path, the parsed plan, and the raw AI plan response.

Initial provider support:

1. `openai-codex-cli` shells out to `codex exec`, mirroring KernForge's Codex CLI bridge pattern.
2. `openai-codex-subscription` uses ChatGPT/Codex OAuth-style bearer tokens and the Codex Responses endpoint. It can read `KNLIVEDBG_CODEX_ACCESS_TOKEN`, `KERNFORGE_CODEX_ACCESS_TOKEN`, configured auth files, `%USERPROFILE%\.kernforge\codex_auth.json`, and `%USERPROFILE%\.codex\auth.json`.
3. `deepseek` uses an OpenAI-compatible chat-completions request with DeepSeek defaults and optional reasoning effort.
4. `openrouter` uses an OpenAI-compatible chat-completions request with OpenRouter defaults and metadata headers.

The runtime automatically loads the first `.env` file found in the current directory, executable directory, or repository root when running from `x64\Debug` or `x64\Release`. Real process environment variables override `.env` values. `.env.example` documents the common OpenRouter and DeepSeek keys plus `KNLIVEDBG_AI_REMOTE_POLICY`. `.env` and `.env.local` are ignored by Git.

The current layer can execute approved read-only model-proposed commands through `ai run`. Write-like commands remain blocked from `ai run` and require `ai write <index> confirm`. Write confirmation now runs deterministic preflight reads before mutation, emits exact byte restore commands for small recognized ranges, runs verification reads afterward when the command can be classified, and prints a deterministic before/after stdout/stderr diff for the verification command. Transcript mode captures full command output after it is enabled, including backend mode, origin, command class, write-like classification, stdout, stderr, keep-running state, output character counts, and deterministic output summaries. Transcript rotation and stdout/stderr redaction are configurable for long live sessions, and the optional write audit log records every write-like command that passes through the normal dispatcher. Callback scans can now be exported through `callbacks json [scope] [path|-]`, and AI callback analysis consumes that structured JSON instead of parsing the human-readable callback view. The command proposal JSON is now versioned as `kn-live-dbg.ai-plan.v2`, with stricter command metadata validation for purpose, risk, backend expectation, expected output, command chaining, session mutation, and raw `kd` write/session wrapping.

## Candidate Features

### Natural-Language Command Planner

Translate operator intent into concrete commands:

- "Show object callbacks" -> `callbacks ob`
- "Dump this address as an EPROCESS" -> `dt nt!_EPROCESS <address>`
- "Translate this virtual address and read the physical bytes" -> `vtop <address>` followed by `pdb <physical-address> <length>`
- "Disassemble this callback routine" -> `u <address> <count>` or `uf <symbol>`

Implementation notes:

1. Resolve symbols before proposing commands when the request contains a symbol-like token.
2. Prefer `backend auto` unless the requested command clearly needs raw DbgEng parser semantics.
3. Display a command preview and require confirmation before execution.
4. For ambiguous requests, propose two or three command plans with tradeoffs rather than guessing silently.

### Callback Analysis Report

Implemented entrypoint: `ai analyze callbacks [all|ob|registry|process|minifilter]`.

The command post-processes `callbacks` output into an investigation report:

1. Count object-manager, registry, process creation, and minifilter callbacks.
2. Group records by owning module and callback surface.
3. Flag callback addresses that do not resolve to a loaded module or nearest symbol.
4. Flag addresses outside expected executable image ranges.
5. Highlight modules that own callbacks across multiple surfaces.
6. Highlight unusual minifilter altitudes, missing names, missing unload routines, or duplicate operation handlers.
7. Separate known platform/security drivers from unknown or unsigned modules when signature metadata is available.

The report should include module name, callback address, nearest symbol, callback context, root/list address, object type or filter address, altitude, and confidence notes.

### `dt` and Structure Interpretation

Implemented entrypoint: `ai explain dt <dt-args...>`.

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
3. For virtual writes, offer `vtop` context when useful.
4. For physical writes, warn when the target could be page tables, device memory, or firmware-owned memory.
5. Generate backup and restore commands before applying the write.
6. Re-read the target after the write and show a compact before/after diff.
7. Mark high-risk targets such as list links, reference counts, callback routine pointers, dispatch tables, page table entries, and executable code.

This feature should never hide the exact command being executed.

### Disassembly Annotator

Implemented entrypoint: `ai annotate <u|uf> <address|symbol> [instruction-count]`.

The command adds AI analysis on top of `u` and `uf` output:

1. Summarize the likely purpose of a function.
2. Identify direct and indirect call targets when symbols are available.
3. Classify routines as object callback, registry callback, process callback, minifilter operation callback, dispatch routine, or unknown.
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

1. Callback surface audit: `callbacks all`, module grouping, disassembly of unknown callbacks, report generation.
2. Suspect driver surface map: list modules, enumerate symbols, find callbacks, inspect dispatch table, inspect minifilter registrations.
3. Address provenance: `ln`, module range lookup, `vtop`, `dq/db`, optional `dt`, and disassembly if executable.
4. Minifilter chain review: enumerate filters, sort by altitude, inspect operation callbacks, summarize unload/name-provider/instance routines.
5. Object callback integrity review: discover object types, walk callback lists, inspect pre/post operation routines and contexts.

Each playbook has a dry-run mode that prints the planned command sequence before execution. `run` dispatches the plan through the same guarded executor used by `ai run`.

### Session Report Generation

Generate Markdown or JSONL reports from an operator session:

1. Commands executed, backend used, and timestamps.
2. Driver load/unload and write mode transitions.
3. Symbol path, module baseline, and Windows build information.
4. Callback records and analysis annotations.
5. Write operations with before/after evidence.
6. Errors, partial reads, failed symbol lookups, and fallback paths.

The report format should be stable enough to compare sessions across Windows builds and machines.

## Suggested Implementation Order

No immediate AI workflow backlog items remain in this document. Larger platform items are tracked in `ARCHITECTURE.md`.

Completed implementation-order items:

1. Transcript/event rotation and redaction controls are implemented with `ai transcript max` and `ai transcript redact`.
2. Write-command JSONL audit logging is implemented with `ai audit <path>`.
3. Structured callback JSON export is implemented with `callbacks json [scope] [path|-]`, and `ai analyze callbacks` consumes that JSON evidence.
4. Deterministic before/after diff rendering is implemented for `ai write <index> confirm` verification output.
5. Model-proposed command plans are validated at ingestion with the v2 schema contract: empty commands, missing purpose metadata, unsupported backend expectations, command chaining, multiline commands, nested `ai`, shutdown/unload commands, backend/session mutation, probe service control, bare `kd`, raw `kd` wrapping of blocked commands, overlong commands, and unknown non-DbgEng commands are rejected before they can be shown as a runnable plan. Write-like proposals, including raw `kd` write-like wrappers, are forced to require confirmation.
6. Command transcript and AI evidence prompts include deterministic output summaries with stdout/stderr character counts, line counts, interesting-line counts, and first/last non-empty lines before raw output.
7. Local/offline provider policy is implemented with `ai policy local-only` and `KNLIVEDBG_AI_REMOTE_POLICY=local-only`, which block HTTP-backed providers.

## Non-Goals

1. Do not move AI parsing or model execution into the kernel driver.
2. Do not allow hidden autonomous writes.
3. Do not treat AI explanations as authoritative without raw command evidence.
4. Do not require a remote model provider for normal live-kernel use.
