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

1. `ai status` reports the selected provider, model, base URL, credential source, loaded `.env` path, Codex CLI path, reasoning effort, and timeout.
2. `ai providers` lists the supported provider names.
3. `ai provider <name>` switches between `openai-codex-cli`, `openai-codex-subscription`, `deepseek`, `openrouter`, and `off`.
4. `ai model <model>`, `ai baseurl <url>`, and `ai effort <effort>` update the in-memory provider settings for the current session.
5. `ai auth` prints the supported `.env` keys, environment variables, and Codex auth file search paths.
6. `ai preview <prompt>` prints the outbound provider plan without sending a request.
7. `ai ask <prompt>` sends an advisory request. The assistant receives session context such as backend mode, number base, symbol path, loaded module count, and write-safety rules.
8. `ai plan <prompt>` asks the model for a strict command proposal JSON object and stores the parsed command plan in memory.
9. `ai show` prints the most recent parsed command plan.
10. `ai run <index|all>` executes only planned commands that are not write-like, shutdown, unload, or nested AI commands.
11. `ai write <index> [confirm]` provides an explicit confirmation path for planned write-like commands. Without `confirm`, it prints the command, purpose, risk, and confirmation syntax.
12. `ai transcript <path|off|status>` controls JSONL transcript capture for AI events and command stdout/stderr.
13. `ai report <path>` exports a Markdown report with session context, provider status, transcript path, the parsed plan, and the raw AI plan response.

Initial provider support:

1. `openai-codex-cli` shells out to `codex exec`, mirroring KernForge's Codex CLI bridge pattern.
2. `openai-codex-subscription` uses ChatGPT/Codex OAuth-style bearer tokens and the Codex Responses endpoint. It can read `KNLIVEDBG_CODEX_ACCESS_TOKEN`, `KERNFORGE_CODEX_ACCESS_TOKEN`, configured auth files, `%USERPROFILE%\.kernforge\codex_auth.json`, and `%USERPROFILE%\.codex\auth.json`.
3. `deepseek` uses an OpenAI-compatible chat-completions request with DeepSeek defaults and optional reasoning effort.
4. `openrouter` uses an OpenAI-compatible chat-completions request with OpenRouter defaults and metadata headers.

The runtime automatically loads the first `.env` file found in the current directory, executable directory, or repository root when running from `x64\Debug` or `x64\Release`. Real process environment variables override `.env` values. `.env.example` documents the common OpenRouter and DeepSeek keys, while `.env` and `.env.local` are ignored by Git.

The current layer can execute approved read-only model-proposed commands through `ai run`. Write-like commands remain blocked from `ai run` and require `ai write <index> confirm`. Transcript mode captures full command output after it is enabled, including backend mode, origin, write-like classification, stdout, stderr, and keep-running state. The command proposal JSON is the first structured tool-call contract; richer schema validation and command-output summarization remain future hardening targets.

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

Post-process `callbacks all` output into an investigation report:

1. Count object-manager, registry, process creation, and minifilter callbacks.
2. Group records by owning module and callback surface.
3. Flag callback addresses that do not resolve to a loaded module or nearest symbol.
4. Flag addresses outside expected executable image ranges.
5. Highlight modules that own callbacks across multiple surfaces.
6. Highlight unusual minifilter altitudes, missing names, missing unload routines, or duplicate operation handlers.
7. Separate known platform/security drivers from unknown or unsigned modules when signature metadata is available.

The report should include module name, callback address, nearest symbol, callback context, root/list address, object type or filter address, altitude, and confidence notes.

### `dt` and Structure Interpretation

Layer semantic explanations on top of native `dt` and `dtx` output:

1. Explain important fields for common kernel types such as `_EPROCESS`, `_ETHREAD`, `_DRIVER_OBJECT`, `_DEVICE_OBJECT`, `_OBJECT_TYPE`, `_CALLBACK_ENTRY`, `_CM_CALLBACK_CONTEXT_BLOCK`, `_EX_CALLBACK_ROUTINE_BLOCK`, `_FLT_FILTER`, and `_FLT_OPERATION_REGISTRATION`.
2. Suggest follow-up commands for pointer fields, `LIST_ENTRY` fields, callback routine fields, and object name fields.
3. Detect suspicious or inconsistent values such as null callback routines, self-referential list entries outside the expected head, invalid-looking pool pointers, or module pointers outside loaded image ranges.
4. Preserve raw field offsets and values so the AI explanation can be audited.

### Write Safety Assistant

Because write mode is enabled by default per device handle, AI should add an operator safety layer around mutations:

1. Before a write, read and display the current value.
2. Show the exact target range, write width, interpreted type field when available, and whether the write crosses a page boundary.
3. For virtual writes, offer `vtop` context when useful.
4. For physical writes, warn when the target could be page tables, device memory, or firmware-owned memory.
5. Generate backup and restore commands before applying the write.
6. Re-read the target after the write and show a compact before/after diff.
7. Mark high-risk targets such as list links, reference counts, callback routine pointers, dispatch tables, page table entries, and executable code.

This feature should never hide the exact command being executed.

### Disassembly Annotator

Add AI analysis on top of `u` and `uf` output:

1. Summarize the likely purpose of a function.
2. Identify direct and indirect call targets when symbols are available.
3. Classify routines as object callback, registry callback, process callback, minifilter operation callback, dispatch routine, or unknown.
4. Highlight suspicious patterns such as indirect calls through writable memory, global list mutation, callback registration, page table access, MSR access, or code patching.
5. Suggest next commands such as `ln`, `x`, `dt`, `dq`, or `uf` on a discovered call target.

The annotator should treat disassembly as evidence, not proof. The output should include uncertainty and the exact instruction ranges used.

### Symbol and Layout Diagnostics

Use AI to explain failures in symbol, type, and backend setup:

1. PDB mismatch, missing private type information, or DIA/DbgHelp failure.
2. Field drift between Windows builds.
3. Missing non-exported symbols used by callback discovery.
4. DbgEng local-kernel attach limitations.
5. Fallback root selection for callback scanners.
6. DbgEng command failures caused by local KD behavior rather than command syntax.

The diagnostic output should recommend concrete remediation steps such as `.sympath`, `.reload`, `backend auto`, `kdinit`, re-running as administrator, or checking the Windows build and symbol cache.

### Investigation Playbooks

Package common multi-command investigations into repeatable workflows:

1. Callback surface audit: `callbacks all`, module grouping, disassembly of unknown callbacks, report generation.
2. Suspect driver surface map: list modules, enumerate symbols, find callbacks, inspect dispatch table, inspect minifilter registrations.
3. Address provenance: `ln`, module range lookup, `vtop`, `dq/db`, optional `dt`, and disassembly if executable.
4. Minifilter chain review: enumerate filters, sort by altitude, inspect operation callbacks, summarize unload/name-provider/instance routines.
5. Object callback integrity review: discover object types, walk callback lists, inspect pre/post operation routines and contexts.

Each playbook should have a dry-run mode that prints the planned command sequence before execution.

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

1. Add a transcript/event sink that records commands, backend routing, output, errors, and write operations.
2. Add command preview and confirmation infrastructure for AI-generated commands.
3. Implement callback analysis report generation from structured callback records.
4. Implement `dt` and disassembly annotation as read-only post-processing.
5. Add write safety assistant with backup/readback/diff support.
6. Add investigation playbooks and session report export.
7. Add configurable model provider policy for local/offline and remote model use.

## Non-Goals

1. Do not move AI parsing or model execution into the kernel driver.
2. Do not allow hidden autonomous writes.
3. Do not treat AI explanations as authoritative without raw command evidence.
4. Do not require a remote model provider for normal live-kernel use.
