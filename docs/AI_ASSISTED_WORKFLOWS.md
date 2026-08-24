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

1. `ai <goal>` is the default operator entrypoint. Routing is local-first: exact read-only evidence commands such as `!callbacks`, `dt`, `!hiddenproc`, or `dump-analyze` run and are explained; command-recommendation requests still build a `kn-live-dbg.ai-plan.v2` command plan; known playbooks (callbacks, hidden processes, handles, leftover mapper layers, integrity, VBS, DMA, one-address inspect) and local process field queries run immediately; conceptual `what`/`why` questions stay advisory. Remaining goals ask the selected provider to pick tools from the shared `AiCapabilityCatalog` (`kn-live-dbg.ai-capability-plan.v1`). Cheap tools preview and run, then the model explains the captured output. `hunt.run`, `payload.scan`, `snapshot.capture`, and `kpage.list` with `deep=true` wait for `ai go` / `ai no`. Default `ai <goal>` no longer auto-builds a v2 command plan; use `ai plan` when you want command proposals. Korean and English goals are both accepted. The catalog includes the P0-P2 scanners (`hiddenproc.list`, `handles.list`, `driver.object`, `dump.analyze`, and the rest) plus `assistant.answer`.
2. `ai status` reports ready/blocked health, the selected preset/model, remote policy, credential source, loaded `.env` path, and the next setup step. `ai config status` adds the verbose dump.
3. Daily setup is `ai use <preset|model>`, `ai models [query|refresh]`, `ai test`, and `ai save`. `ai config ...` remains the advanced provider surface (`status`, `providers`, `provider`, `policy`, `model`, `base-url`, `effort`, `auth`, and `test`). Presets are `cloud` (OpenRouter + Claude Opus 5), `cheap` (gpt-oss-120b), `deepseek`, `private` (Codex CLI), `chatgpt`, and `off`. Tab completion includes curated frontier OpenRouter IDs as of 2026-08-24; `ai models refresh` fetches the live OpenRouter catalog.
4. `ai plan <prompt>` remains an explicit override that asks the model for a strict command proposal JSON object and stores the parsed command plan in memory.
5. `ai explain <read-only-command...>` remains an explicit override for evidence analysis. The same path is also reached implicitly when the operator types `ai !callbacks ...`, `ai dt ...`, `ai uf ...`, `ai !ci options`, or another recognized read-only evidence command.
6. `ai show` prints session hints, a pending expensive tool plan, and the loaded command plan. `ai show evidence` reprints the last captured tool or evidence output. `ai go` / `ai no` confirm or cancel a pending expensive tool plan.
7. `ai run [index|all]` executes only planned commands that are not write-like, shutdown, unload, or nested AI commands. If the plan has one read-only command, `ai run` with no index runs it. A single write-like plan item is refused and the operator is sent to `ai write confirm`.
8. `ai write [index] [confirm]` provides an explicit confirmation path for planned write-like commands. If the plan has one write, `ai write` previews it and `ai write confirm` executes it. `[1]` in the listing is that index, not a menu. Without `confirm`, it prints target classification, size, backup/read-current, restore-current for small ranges, translation, verification, purpose, risk, and confirmation syntax.
9. `ai report <path>` exports a Markdown report with session context, provider status, transcript settings, write-audit path, the parsed plan, and the raw AI plan response.

The older detailed forms remain accepted for compatibility: `ai providers`, `ai provider`, `ai policy`, `ai model`, `ai base-url`, `ai effort`, `ai auth`, `ai preview`, `ai ask`, `ai analyze !callbacks`, `ai annotate`, `ai diagnose`, `ai playbook`, `ai transcript`, and `ai audit`.

Initial provider support:

1. `openai-codex-cli` shells out to `codex exec`, mirroring KernForge's Codex CLI bridge pattern.
2. `openai-codex-subscription` uses ChatGPT/Codex OAuth-style bearer tokens and the Codex Responses endpoint. It can read `KNLIVEDBG_CODEX_ACCESS_TOKEN`, `KERNFORGE_CODEX_ACCESS_TOKEN`, configured auth files, `%USERPROFILE%\.kernforge\codex_auth.json`, and `%USERPROFILE%\.codex\auth.json`.
3. `deepseek` uses an OpenAI-compatible chat-completions request with DeepSeek defaults and optional reasoning effort.
4. `openrouter` uses an OpenAI-compatible chat-completions request with OpenRouter defaults and metadata headers. Chat completions send `max_tokens=8192` and `reasoning.exclude=true`. Reasoning is off unless `ai config effort` / `KNLIVEDBG_AI_REASONING_EFFORT` is set. The parser reads `choices[0].message.content` (or Codex `output` / `output_text`) and never prints nested `reasoning` / `reasoning_details`. The TUI prints `ai explain: <provider> / <model>` plus the report; it does not dump the credential path. If `finish_reason` is `length`, it adds `ai note: model hit the token limit`.

The runtime automatically loads `.env` only from the executable directory. Real process environment variables override `.env` values. `.env.example` documents the common OpenRouter and DeepSeek keys plus `KNLIVEDBG_AI_REMOTE_POLICY`. `.env` and `.env.local` are ignored by Git. `.env.local` is not loaded. `ai use`, `ai save`, `ai config provider`, `ai config model`, and `ai config policy` write provider/model/policy back to that EXE-dir `.env` (atomic replace via `.env.tmp`).

`ai test [prompt]` / `ai config test [prompt]` is the provider round-trip smoke check. Without a custom prompt, it asks the selected provider/model to return `kn-live-dbg-ai-ok`, then prints the configured provider, model, remote policy, credential status, transport result, HTTP status when available, elapsed time, and marker match result.

## Provider Presets and Model Catalog

Operator-facing setup is a preset plus an optional OpenRouter model id. The four HTTP/CLI transports stay under `AiProviderRuntime`. `user/AiModelCatalog.cpp` is the name table: presets, aliases, curated frontier IDs, live OpenRouter cache, and resolve/search.

### Daily commands

```text
ai status
ai use <preset|model> [model]
ai models [query]
ai models refresh
ai test [prompt]
ai save
```

`ai status` is a health view (`ready` / `off` / `missing key` / `missing token` / `blocked`) plus the next setup step. `ai config status` prints that health view and then the verbose dump (base URL, Codex CLI path, timeout, live-catalog count).

`ai use` takes one or two tokens only. Extra tokens are rejected. A leading `/` (for example `/verbose`) is not a model id.

`chatgpt` is the ChatGPT/Codex OAuth preset. `gpt` / `gpt-5.5` are OpenRouter model aliases, not that OAuth path.

### Presets

| Preset | Provider | Default model | Data path |
| --- | --- | --- | --- |
| `cloud` | `openrouter` | `anthropic/claude-opus-5` | remote HTTP |
| `cheap` | `openrouter` | `openai/gpt-oss-120b` | remote HTTP |
| `deepseek` | `deepseek` | `deepseek-chat` | remote HTTP |
| `private` | `openai-codex-cli` | CLI default (`codex exec` without `-c model=`) | local process |
| `chatgpt` | `openai-codex-subscription` | `gpt-5.5` | remote HTTP (Codex OAuth) |
| `off` | disabled | empty | none |

`ai use <preset> <model>` keeps the preset's provider and overrides only the model. The override must belong to that provider: DeepSeek native names (`deepseek-chat`, `deepseek-reasoner`) stay on DeepSeek; OpenRouter accepts `vendor/model` ids such as `x-ai/grok-4.6`. `ai use cloud deepseek-chat` and `ai use deepseek grok` are rejected. `ai use off` does not take a model.

Re-selecting the same provider does not reset a custom `base-url` or the current model. Switching providers still applies that provider's defaults.

### Model resolve order

`ai use <spec>` and `ai models <query>` resolve in this order:

1. Exact preset name (`cloud`, `cheap`, `deepseek`, `private`, `chatgpt`, `off`).
2. Exact alias (`opus`, `grok`, `gpt`, `sol`, ...).
3. Exact curated or live catalog id (`anthropic/claude-opus-5`).
4. Unique exact tail (`gpt-5.6-sol` -> `openai/gpt-5.6-sol`, not `...-sol-pro`).
5. Unique substring of id or display name; multiple hits print the matches and tell the operator to run `ai models <query>`.
6. Otherwise a `vendor/model` string is accepted as an OpenRouter id. Names with a leading `/` or a space are invalid.

Bare names without `/` are OpenRouter unless they are the DeepSeek native ids `deepseek-chat` / `deepseek-reasoner`.

### Aliases

| Alias | OpenRouter (or native) id |
| --- | --- |
| `opus`, `opus5`, `claude`, `claude-opus-5` | `anthropic/claude-opus-5` |
| `fable` | `anthropic/claude-fable-5` |
| `sonnet`, `sonnet5` | `anthropic/claude-sonnet-5` |
| `gpt`, `gpt5`, `gpt-5.6`, `sol` | `openai/gpt-5.6-sol` |
| `gpt-5.5` | `openai/gpt-5.5` |
| `grok`, `grok4`, `grok-4.6` | `x-ai/grok-4.6` |
| `grok-4.5` | `x-ai/grok-4.5` |
| `gemini`, `flash` | `google/gemini-3.7-flash` |
| `kimi`, `k3` | `moonshotai/kimi-k3` |
| `glm` | `z-ai/glm-5.3` |
| `qwen` | `qwen/qwen3.8-max` |
| `muse` | `meta/muse-spark-1.2` |
| `oss`, `gpt-oss` | `openai/gpt-oss-120b` |
| `r1` | `deepseek/deepseek-r1` |
| `v4`, `deepseek-v4` | `deepseek/deepseek-v4-pro-0813` |

### Curated OpenRouter snapshot (2026-08-24)

Tab completion and `ai models` always include this offline list. Scores are Artificial Analysis intelligence indexes from OpenRouter at that date, used only for ranking/display.

| Id | Name | Notes |
| --- | --- | --- |
| `anthropic/claude-opus-5` | Claude Opus 5 | `cloud` default |
| `anthropic/claude-fable-5` | Claude Fable 5 | |
| `openai/gpt-5.6-sol` | GPT-5.6 Sol | |
| `x-ai/grok-4.6` | Grok 4.6 | |
| `moonshotai/kimi-k3` | Kimi K3 | |
| `z-ai/glm-5.3` | GLM 5.3 | |
| `qwen/qwen3.8-max` | Qwen3.8 Max | |
| `anthropic/claude-opus-4.8` | Claude Opus 4.8 | |
| `meta/muse-spark-1.2` | Muse Spark 1.2 | |
| `openai/gpt-5.6-terra` | GPT-5.6 Terra | |
| `openai/gpt-5.5` | GPT-5.5 | OpenRouter, not the `chatgpt` preset |
| `google/gemini-3.7-flash` | Gemini 3.7 Flash | |
| `x-ai/grok-4.5` | Grok 4.5 | |
| `anthropic/claude-sonnet-5` | Claude Sonnet 5 | |
| `deepseek/deepseek-v4-pro-0813` | DeepSeek V4 Pro 0813 | |
| `openai/gpt-5.6-luna` | GPT-5.6 Luna | |
| `deepseek/deepseek-v4-flash-0731` | DeepSeek V4 Flash 0731 | |
| `google/gemini-3.6-flash` | Gemini 3.6 Flash | |
| `google/gemini-3.1-pro-preview` | Gemini 3.1 Pro Preview | |
| `anthropic/claude-opus-5-fast` | Claude Opus 5 Fast | |
| `openai/gpt-5.6-sol-pro` | GPT-5.6 Sol Pro | |
| `openai/gpt-oss-120b` | gpt-oss-120b | `cheap` default |
| `deepseek/deepseek-r1` | DeepSeek R1 | legacy |
| `deepseek-chat` | deepseek-chat | DeepSeek native |
| `deepseek-reasoner` | deepseek-reasoner | DeepSeek native |

`ai models refresh` GETs `https://openrouter.ai/api/v1/models` (or the current OpenRouter `base-url` with `/chat/completions` and `/models` stripped, then `/models` appended). Batch, `~` alias, and image/imagine ids are dropped. The live list is a process-lifetime cache; the top intelligence hits are added to Tab after a successful refresh. `local-only` blocks refresh. An OpenRouter API key is optional for the public catalog and is read from the OpenRouter key slots even when the current provider is not OpenRouter.

### Tab completion

| Input | Candidates |
| --- | --- |
| `ai <Tab>` | primary actions including `use`, `models`, `save`, `test` |
| `ai use <Tab>` | presets, aliases, curated ids, live top ids, `help` |
| `ai use cloud <Tab>` | curated/live model ids |
| `ai models <Tab>` | `refresh`, curated/live ids, `help` |
| `ai config model <Tab>` / `ai model <Tab>` | curated/live model ids |

Every completed token has a one-line summary. `ai <subcommand> help` and `ai help <subcommand>` cover `use`, `models`, `save`, and `test`.

### `.env` load and save

1. Search path is only `<KnLiveDbg.exe directory>\.env`. Repo-root `.env` and cwd `.env` are not read.
2. Process environment variables override `.env` keys.
3. `ai use` / `ai save` / `ai config provider|model|policy` merge `KNLIVEDBG_AI_PROVIDER`, `KNLIVEDBG_AI_MODEL`, and `KNLIVEDBG_AI_REMOTE_POLICY` into that file and replace it via `.env.tmp`. Other keys (API keys, `BASE_URL`, effort, timeout) are preserved. Disabled provider is stored as `off`. Empty model is stored so a previous model cannot come back after `ai use off`.
4. `KNLIVEDBG_AI_BASE_URL`, `KNLIVEDBG_AI_REASONING_EFFORT`, and `KNLIVEDBG_AI_TIMEOUT_SECONDS` are load-only unless the operator edits `.env` by hand.
5. Save failure leaves the in-memory session updated and prints `ai note: session updated, but .env was not saved`.

### Remote policy

`allow-remote` is the default. `local-only` (`.env`, process env, or `ai config policy local-only`) blocks HTTP complete and `ai models refresh` without clearing the selected provider. `ai use` of a remote preset fails with `use: ai use private`. Codex CLI (`private`) is not an HTTP provider from this process.

OpenRouter defaults:

1. Model: `anthropic/claude-opus-5` when `KNLIVEDBG_AI_MODEL` is unset.
2. Base URL: `https://openrouter.ai/api/v1`.

The current layer can execute approved read-only model-proposed commands through `ai run`. Write-like commands remain blocked from `ai run` and require `ai write confirm` (or `ai write <index> confirm`). Write confirmation now runs deterministic preflight reads before mutation, emits exact byte restore commands for small recognized ranges, runs verification reads afterward when the command can be classified, and prints a deterministic before/after stdout/stderr diff for the verification command. Transcript mode captures full command output after it is enabled, including backend mode, origin, command class, write-like classification, stdout, stderr, keep-running state, output character counts, and deterministic output summaries. Transcript rotation and stdout/stderr redaction are configurable for long live sessions, and the optional write audit log records every write-like command that passes through the normal dispatcher. AI callback analysis now fits under both `ai !callbacks ...` and `ai explain !callbacks ...`, and consumes normal `!callbacks <scope> [module]` evidence. The command proposal JSON is now versioned as `kn-live-dbg.ai-plan.v2`, with stricter command metadata validation for purpose, risk, backend expectation, expected output, command chaining, session mutation, and raw `kd` write/session wrapping.

The main `ai help` output stays focused on the primary workflow. Detailed compatibility topics still have operator help through `ai <subcommand> help` and `ai help <subcommand>`.

## Operator Command Examples

Default rule: prefer `ai <goal>` during normal use. Exact read-only command lines after `ai` are treated as evidence to run and explain. Known playbooks and process field queries run locally first. Cheap selected tools run after a preview and are explained. Expensive tools wait for `ai go`. Conceptual `what`/`why` questions stay advisory. Use `ai plan` only when you want a stored command proposal. Disable/enable goals and exact write-like commands do not run list playbooks and do not mutate immediately. They stage a write plan. If that plan has one write, `ai write` previews it and `ai write confirm` executes it (`write on` required). `[1]` in the listing is the plan index, not a menu. Use `ai write <index> confirm` when several writes are staged.

Provider and session setup:

```text
ai status
ai use cloud
ai use grok
ai use cloud x-ai/grok-4.6
ai use cheap
ai use private
ai models
ai models refresh
ai models opus
ai test
ai save
ai config policy local-only
ai help use
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
ai 숨은 프로세스 찾아줘
ai 콜백 전수조사
ai go
ai no
ai show evidence
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
ai disable wdfilter minifilter
ai disable wdfilter callbacks
ai disable wdfilter object
ai enable ppl
ai load byovd fixture
ai reset timeline
ai dump-pe nt .\\ntos-live.exe
ai !callbacks disable-all WdFilter
ai write
ai write confirm
ai write 1 confirm
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

The command now behaves like a small tool-using agent and intent router. The operator can usually type `ai <goal>` without knowing command names. Exact read-only commands are executed as evidence and explained. Known Korean/English playbooks and local process field queries run without a model round-trip. Generic playbooks are skipped when the goal already names a `.sys`/`.exe`/`.dll`/`.drv` file, so a prompt such as `WdFilter.sys object callbacks` stays on the tool planner with a module filter instead of running an unfiltered callback dump. They are also skipped for disable/enable goals, which become a write plan instead of a list. Examples:

- `ai disable wdfilter minifilter` -> `!minifilter disable-all wdfilter`
- `ai disable wdfilter callbacks` -> `!callbacks disable-all wdfilter`
- `ai disable wdfilter object` -> `!callbacks disable object wdfilter`
- `ai disable wdfilter process` -> `!callbacks disable process wdfilter`
- `ai enable wdfilter minifilter` -> `!minifilter enable-all wdfilter`
- `ai enable ppl` / `ai disable ppl` -> `set-ppl-antimalware on` / `off`
- `ai load byovd fixture` / `ai unload fixture` -> `!byovd fixture load` / `unload`
- `ai reset timeline` -> `!timeline reset`
- `ai clear ti` -> `!ti clear`
- `ai disable wdfilter` without a surface is rejected (it must not silently disable every callback type)
- Typed write-like lines (`ai !callbacks disable-all WdFilter`, `ai !minifilter disable-all WdFilter /pre`, `ai !ti start`, `ai dump-pe nt .\\ntos-live.exe`) are staged as-is, including flags
- `ai start ti` / `ai stop ti` / `ai timeline live off` / `ai disable timeline live` stage the matching write command
- Session TUI commands stay out of the write plan and print the real command instead: `write on|off`, `log enable|disable`, `mcp on|off`, `probe load|unload`, `backend auto|native|dbgeng`
- `dump-kernel` / `dump-live` stay blocked from AI plans (full-memory dumps)

If the plan has one write, type `ai write` then `ai write confirm`. `[1]` is the index, not a picker. The command does not run until confirm (and `write on`). Otherwise the model receives the operator request plus the shared capability catalog (not live memory), returns a strict `kn-live-dbg.ai-capability-plan.v1` JSON object, and the local executor runs only supported read-only tools. After the tools finish, the model explains the captured output. Expensive tools preview and wait for `ai go`. Every AI subcommand supports `ai help <sub>` / `ai <sub> help` and Tab completion; `ai explain !vad <tab>` reuses `!vad` completion, and `ai explain !vad help` prints `!vad` help. The catalog handles process and `_EPROCESS` questions by walking `_EPROCESS.ActiveProcessLinks` through the same native data path as `!dml_proc`, dispatches callback/WFP/ALPC/hidden-process/handle/DMA requests to native scanners, and routes VAD/thread triage through the read-only process scanner:

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
- Disable/enable of object/registry/process/thread/imageload callbacks is also
  not on the AI planner. Use `!callbacks disable <scope> <module>` /
  `disable-all` or MCP `callbacks.set` under `--allow-write`. Minifilter
  through `!callbacks` reuses the same live CallbackNodes path.
- "why is this address suspicious?" -> `address.inspect` with `address=<va-or-symbol>`
- "decode WNF state name 0x41c64e6da3bc0075" -> `wnf.decode` with `hash=0x41c64e6da3bc0075`
- "list live WNF instances" -> `wnf.list` with `scope=instances`
- "recent TI WriteVM events" -> `ti.query` with `action=grep` and `pattern=WriteVM`
- "inspect module text integrity" -> `module.integrity` with `target=all`, `headers=true`, and `sections=true`
- "find W+X kernel modules" -> `module.integrity` with `target=all`, `wx=true`, and `verbose=true`
- "summarize live module integrity mismatches" -> `module.integrity` with `target=all`, `summary=true`, and `mismatch=true`
- "check driver dispatch integrity" -> `driver.integrity` with `target=all`
- "is HVCI on?" or "VBS status" or "가상화 기반 보안" -> playbook `vbs.scan` (`!vbs`)
- "숨은 프로세스 찾아줘" / "find hidden processes" -> playbook `hiddenproc.list` (`!hiddenproc`)
- "콜백 전수조사" -> playbook `callbacks.list`
- "decode CiOptions" -> exact evidence command with `ai !ci options`
- "!callbacks all WdFilter.sys" -> implicit evidence analysis, equivalent to `ai explain !callbacks all WdFilter.sys`
- "dt nt!_EPROCESS <address>" -> implicit evidence analysis for structure output
- "uf nt!PspCreateProcessNotifyRoutine 128" -> implicit evidence analysis for disassembly output
- "what is HVCI?" -> advisory answer, not tool execution
- whole-system `hunt.run` / `kpage.list` with `deep=true` -> preview, then `ai go` or `ai no`

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

Implemented entrypoint: `ai write [index] [confirm]`. If the plan has one write, `ai write` and `ai write confirm` do not need an index.

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
4. Deterministic before/after diff rendering is implemented for `ai write confirm` / `ai write <index> confirm` verification output.
5. Model-proposed command plans are validated at ingestion with the v2 schema contract: empty commands, missing purpose metadata, unsupported backend expectations, command chaining, multiline commands, nested `ai`, shutdown/unload commands, backend/session mutation, probe service control, bare `kd`, raw `kd` wrapping of blocked commands, overlong commands, and unknown non-DbgEng commands are rejected before they can be shown as a runnable plan. Write-like proposals, including raw `kd` write-like wrappers, are forced to require confirmation.
6. Command transcript and AI evidence prompts include deterministic output summaries with stdout/stderr character counts, line counts, interesting-line counts, and first/last non-empty lines before raw output.
7. Local/offline provider policy is implemented with `ai config policy local-only` and `KNLIVEDBG_AI_REMOTE_POLICY=local-only`. HTTP complete and `ai models refresh` are blocked; the selected provider is not cleared. Use `ai use private` for the local Codex CLI.
8. Provider presets, aliases, curated frontier OpenRouter IDs, live catalog refresh, EXE-dir `.env` merge/save, and health status are implemented in `AiModelCatalog` plus `AiProviderRuntime`. Daily setup is `ai use` / `ai models` / `ai test` / `ai save`.

## Non-Goals

1. Do not move AI parsing or model execution into the kernel driver.
2. Do not allow hidden autonomous writes.
3. Do not treat AI explanations as authoritative without raw command evidence.
4. Do not require a remote model provider for normal live-kernel use.
