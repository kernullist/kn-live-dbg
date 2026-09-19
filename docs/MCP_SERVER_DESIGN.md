> Korean version: [MCP_SERVER_DESIGN.ko.md](./MCP_SERVER_DESIGN.ko.md)

# MCP Server Design (Kn-Live-Dbg)

This document defines a design for adding an **MCP (Model Context Protocol) server** to Kn-Live-Dbg so that external LLM hosts such as Claude Code / Claude Desktop / Cursor can directly leverage this tool's (primarily read-only) kernel forensics / anti-cheat features as MCP tools / resources / prompts.

The core principles carry over directly from the philosophy of the existing `docs/AI_ASSISTED_WORKFLOWS.md`: the AI is advisory by default, no hidden automatic writes, raw evidence is preserved, the driver stays a narrow memory primitive, and sensitive kernel state can be kept local-only. MCP is a **third frontend** that reuses the **same capability catalog + guard layer** as the existing `ai` command (following the REPL and the internal AiProvider).

> Current implementation (2026-09-19): in-process HTTP.sys, default `0.0.0.0:51766`, optional `--loopback`, read-only by default, 12 write tools under `--allow-write`, and a single engine FIFO. Use [MCP_SETUP.md](MCP_SETUP.md) for operation and the [command audit](COMMAND_AUDIT_20260919.md) for evidence. Phased plans and initial scaffold notes below are implementation history; unimplemented features are identified separately.

---

## 1. Purpose and Scope

### 1.1 Purpose

1. Let external LLMs invoke read-only detection features such as `!callbacks`, `!wfp`, `!alpc`, `!vbs`, `!etw`, `!nmi`, `!ssdt`, `!idt`, `!cr`, `!msrcheck`, `!pool`, `!address`, `!byovd`, `!ti`, `module/driver integrity`, and VAD/thread hunting in a structured form.
2. Because this exposes an **elevated (Administrator/SYSTEM)** tool capable of kernel memory read/write to an LLM, minimize the attack surface and audit every action. Writes / kernel mutations are fully blocked in v1.
3. Reuse existing assets (capability catalog, guard functions, `Build*Json`, `ScopedWideStreamCapture`) as much as possible to reduce new code and risk.

### 1.2 Non-Goals

1. Do not move MCP parsing/planning/risk assessment into the driver (the driver stays a narrow primitive).
2. In the **default (read-only) mode**, prevent the LLM from doing kernel write / PPL / dump / raw kd / session changes. In **Lab write mode** (`--allow-write`, isolated VM only -- decision §10-Q1/Q2), open all typed write tools, but forbid raw `kd`/DbgEng passthrough, arbitrary command strings, host-wide global file traversal, and hidden writes without backup/audit in both modes.
3. Do not make the LLM a trust principal via MCP alone -- the human-in-the-loop at the operator console must always remain alive.

---

## 2. Core Constraints (Code Basis)

Every design decision derives from the facts below. All have been verified in code.

| # | Constraint | Basis (function/file) |
|---|------|------------------|
| C1 | **Single controller**: the driver enforces `KNDBG_VERSION_FLAG_SINGLE_CONTROLLER`. User-mode opens `\\.\KnLiveDbg` exclusively via `CreateFileW(... ShareMode=0 ...)`, with one global `DeviceClient`. | `DeviceClient::Open` (`ShareMode=0`), `shared/KnLiveDbgIoctl.h` |
| C2 | **No batch/headless mode**: `wmain` ignores argc/argv. It always enters the interactive REPL (`knkd>`). | `wmain` (`UNREFERENCED_PARAMETER(argc/argv)`), REPL loop `while(!g_StopRequested)` |
| C3 | **Single-threaded command engine**: command dispatch and symbol work are serialized on the main thread. Collector workers have separately synchronized IOCTL paths, including timeline drain; not every `DeviceClient` call runs on the main thread. | `RunMcpEngineLoop`, `TimelineAutoDrainWorker`, `SymbolEngine` |
| C4 | **Output capture already exists**: `ScopedWideStreamCapture` swaps the **process-global rdbuf** of `std::wcout`/`std::wcerr` to a string buffer. Transcript/AI evidence already uses it. | `ScopedWideStreamCapture` (`std::wcout.rdbuf(&outBuffer_)`) |
| C5 | **Driver write is ON by default**: in `IRP_MJ_CREATE` the handle context `WriteEnabled = TRUE`. The kernel-side gate of the write-virtual/physical/SetProcessProtection handlers is only this flag + `KNDBG_WRITE_ACK_MAGIC` (a public compile-time constant). **The entire write-safety pipeline exists only in user-mode.** | `Driver.cpp` (`WriteEnabled = TRUE`), `KnLiveDbgIoctl.h` (`KNDBG_WRITE_ACK_MAGIC`) |
| C6 | **Capability catalog + guards exist**: 20 read-only tools, per-tool argument whitelist, value validation (rejecting `;`/newlines/control chars/help tokens), rejection of write-like/raw-kd/nested-ai/session-change/unload, single execution path. | `IsSupportedAiCapabilityTool`, `ValidateAiCapabilityToolArgKeys`, `ValidateAiCapabilityScalarText`, `ContainsUnsafeAiCommandCharacters`, `ExecuteAiCapabilityPlan` |
| C7 | **Almost every scanner returns a structured struct**, and 5 of them have JSON builders. No external JSON library (direct escaping). | `BuildModuleIntegrityJson`/`BuildDriverIntegrityJson`, `BuildProcessVadJson`/`BuildProcessThreadsJson`, `BuildHuntJson`, `BuildByovdScanJson`, `BuildSnapshotJson` |
| C8 | **Only TiSubscriber is a thread-safe background**: its own `ProcessTrace` thread + `RingMutex` + const query API (`Recent`/`FilterByPid`/`Grep`/`Histogram`). | `ThreatIntelSubscriber.h` (`mutable std::mutex RingMutex`) |
| C9 | **Non-cancelable scanners**: `UserModeHunter::Scan` has no cancel token. `HuntOptions` has no stop handle. A synchronous `DeviceIoControl` cannot be canceled midway. | `UserModeHunter.h` (`Scan` signature) |
| C10 | **A direct console output path exists**: the `ScopedCommandProgress` worker writes directly to `GetStdHandle(STD_OUTPUT_HANDLE)` (`WriteConsoleTuiLineDirect`) -- bypassing the wcout capture. | `ScopedCommandProgress` |

---

## 3. Architecture Decisions

### 3.1 Transport: in-process Streamable HTTP (not stdio)

**Decision**: place a **Streamable HTTP** endpoint (`http://127.0.0.1:<port>/mcp`) inside the already-running elevated controller process. **stdio is not used as the primary transport for the live process.**

Rationale:

1. **stdio is structurally unsuitable**. The MCP stdio transport by definition has *the client spawn the server as a subprocess*. But this process is (a) already running, (b) elevated, (c) holding `\\.\KnLiveDbg` exclusively (C1), and (d) keeping symbol/DbgEng state in memory. If the client launches a second `KnLiveDbg.exe`, it either fails the exclusive `CreateFileW` (C1) or becomes a separate instance with no live operator session.
2. **Claude Desktop is a GUI app, so it cannot spawn an elevated child process without UAC** -- a stdio config of the form `command: KnLiveDbg.exe` will not actually start.
3. **stdout pollution**: the REPL/scanners emit massive output to `std::wcout` (C4), and `ScopedCommandProgress` writes directly to the console handle (C10). stdio JSON-RPC must own stdout for framing, so a single stray byte breaks the session.
4. **HTTP coexists cleanly with the console**: the HTTP listener owns its own socket/thread and never touches the console. The operator REPL stays alive, preserving the human-in-the-loop (security-critical).
5. **Claude Code, Cursor, Codex, and Grok Build natively support Streamable HTTP** (see §8 below), so they connect directly without a transport shim. Claude Desktop supports remote HTTP connectors, but those connections originate in Anthropic's cloud and cannot reach this local loopback/private endpoint; its local `claude_desktop_config.json` path remains stdio. `tools/mcp-bridge.ps1` therefore exists only for Claude Desktop local MCP and legacy stdio-only clients. It pins and constrains the stateless `mcp-remote` bridge, which never touches the device and can be freely spawned.

**Implementation stack**: HTTP Server API (http.sys, `httpapi.lib`). The default URL prefix is `http://+:<port>/mcp/`; `--loopback` registers only loopback prefixes. URL registration rights are required. WinSock below is the rejected alternative.
- Adopted APIs: `HttpInitialize` / `HttpCreateRequestQueue` / `HttpAddUrlToUrlGroup`. HTTP.sys owns HTTP framing.
- Alternative: a small WinSock listener that explicitly `bind()`s to `INADDR_LOOPBACK` -- the only external dependency is `ws2_32`, but HTTP/1.1 parsing must be hand-written.

**POST response mode**: current read/write tools return `application/json`. SSE progress and per-write elicitation are not implemented.

### 3.2 Process Model: in-process, ON/OFF by command, coexisting with the REPL

**Decision**: a subsystem inside `KnLiveDbg.exe`, sharing the device handle, symbol engine, and state (C1). It is OFF by default; `mcp on` prompts for a session password and prints connection details. `mcp off` requests stop but cannot preempt an already-running command.

- The global `g_McpServer` does not listen until `mcp on`.
- When activated, spawn one HTTP listener thread. This thread **never touches the kernel directly** -- it only does HTTP validation (auth/host/origin/size) -> JSON-RPC parsing -> job creation -> push to the engine queue -> waiting on the per-job completion future.
- `RequestStop` wakes listener waits; `Stop` fails queued jobs and joins the listener. Dispatched engine work runs to completion. Write mode on return to the REPL is described in §5.7.

**The operator REPL is retained.** However, in MCP-enabled mode the console input switches to a simple line reader (to avoid the global rdbuf race of §4.2).

### 3.3 Alternatives Compared

| Item | Chosen | Rejected | Rejection reason |
|------|--------|--------|-----------|
| Transport | in-process loopback HTTP | stdio default | Conflicts with C1/C2/C4, Desktop UAC limits, stdout pollution |
| Transport | in-process loopback HTTP | separate bridge process + IPC | C1 forbids a second device handle, symbol/state not shared, IPC adds yet another serialization problem |
| Deployment mode | REPL + HTTP coexisting | `--mcp` headless (REPL removed) | The operator console disappears, losing the human-in-the-loop deny capability (security-fatal) |
| write (default mode) | fully blocked + kernel flag disarmed | always-on | Safe non-lab default. Neutralizes C5 (driver write ON by default) via `SetWriteMode(false)` |
| write (lab mode) | open the full typed write tool set via `--allow-write` | raw kd / hidden write | Analysis fidelity in an isolated VM (decision §10-Q1/Q2). Keep automatic backup/verify/audit + recommend VM snapshots (§5.3.3) |
| raw kd/DbgEng | not exposed in either mode | open in lab | Arbitrary commands = hang/crash/arbitrary execution, a separate axis from the write requirement. Decide separately if needed |

---

## 4. Concurrency Model (Correctness Core)

C3 (single-threaded engine) + C4 (global rdbuf capture) is the subtlest part. A wrong design causes a use-after-free in an elevated process.

### 4.1 Single engine thread + serial job queue

The implementation uses one `McpServer::queue_`, with no separate `EngineQueue` or priority CONSOLE queue. The HTTP thread enqueues requests; `RunMcpEngineLoop` on the main thread waits on `JobReadyEvent`, then calls `TryPopJob` and `DispatchMcpRequest`.

```text
HTTP listener -> validate -> queue_ -> engine dispatch -> ResultPromise
                      30s response wait     one job at a time
```

```cpp
struct McpJob
{
    McpEngineRequest Request;
    std::promise<McpEngineResult> ResultPromise;
};
```

The console reader sends only `off`/`status` control requests. It does not execute engine commands or write to captured streams. The full REPL resumes after MCP stops.

### 4.2 Global rdbuf hazard and mitigation (mandatory)

`ScopedWideStreamCapture` swaps the **process-global** rdbuf of `std::wcout`/`std::wcerr` (C4). If two captures are alive at the same time, the rdbuf pointers race and the LIFO restore breaks, leaving `wcout` pointing at a freed buffer (use-after-free).

Rules (invariants):

1. **`ScopedWideStreamCapture` is created only on the engine thread.** The HTTP listener thread never creates a capture.
2. **At most 1 alive at a time.** Nesting within a single thread is allowed because the LIFO restore holds (e.g., a capability path captures once more internally). **Cross-thread concurrent capture is forbidden.**
3. Preserve engine-thread ownership. Adding thread-ID assertions to every `DeviceClient`/`SymbolEngine` entry point remains a hardening target, not a guarantee implemented across all call sites.
4. **The MCP console is a control-only reader.** It uses `ReadConsoleW` and forwards stop/status flags, without enqueuing CONSOLE jobs. Rich editing remains in the normal REPL.
5. **Console progress bypasses stream capture.** `ScopedCommandProgress` writes directly to the console handle. Remote dispatch disables it; MCP does not have a blanket origin-based disable. MCP uses HTTP, so this console output does not enter JSON-RPC framing. It is not an MCP progress notification.

### 4.3 Backpressure / Cancellation / Lifetime

- **One in-flight**: the engine runs only one job at a time. A long scan (UserModeHunter, !pool pe, full callbacks) blocks all other MCP requests and the operator for that duration -- this is **intentional backpressure**, not to be masked by a false cancellation promise.
- **At most eight pending jobs**: a full queue returns `isError:true` and `engine busy; retry shortly` for `tools/call`. The request was not queued.
- **Operator control**: a separate reader forwards stop/status requests. There is no priority CONSOLE queue, and a running engine command cannot be preempted.
- **Response wait ends**: after 30 seconds or stop, a still-queued request is removed under the queue mutex and returns `engine wait ended; request cancelled before execution`. If dispatch already occurred, it returns `engine wait ended after dispatch; outcome unknown, inspect state before retrying`; execution can continue. Inspect state before retrying mutations. MCP cancellation notifications do not currently cancel jobs.
- **Late-result lifetime**: the `McpJob` is owned by the engine as a `shared_ptr`. Even if the worker abandons the future on timeout, the job/result storage stays alive until the engine sets the promise (never set a promise on freed memory). By the one-in-flight rule, a timeout-but-running job naturally blocks the queue (= normal backpressure, not a hang).
- **No engine-thread reentrancy**: engine-thread code never enqueue-and-waits on its own queue (self-deadlock). Only the transport thread waits on a future. nested-ai/`assistant.answer` is rejected as before, so the reentrant path is closed.

### 4.4 TiSubscriber exception -- not adopted

A "fast path" that serves `ti.query` directly from the worker via a RingMutex-protected ring read (`Recent`/`FilterByPid`/`Histogram`, C8), bypassing the engine queue, is **not adopted.** The ti capability executor can touch, beyond a ring read, PPL self-elevation (`SetProcessProtection` via the lock-free `DeviceClient`) or symbol resolution (DbgHelp), creating a race hazard; and since the RingMutex is uncontended, the queue-hop cost is negligible. **Every tool goes through the engine queue.**

---

## 5. Security Model (Most Important)

Designed on the premise of exposing an elevated kernel-RW tool to a potentially adversarial/injected LLM.

### 5.1 Network

1. **Default bind is all interfaces**: `http://+:<port>/mcp/` (`0.0.0.0`). Multi-NIC hosts must not pin a guessed adapter IP. `--loopback` keeps `127.0.0.1` + `::1` only.
2. **Host header whitelist in `--loopback` only**: reject anything that is not `127.0.0.1` / `[::1]` / `localhost` -> blocks DNS rebinding. Default all-interface bind accepts a remote Host.
3. **Origin validation**: if an Origin **exists** and is not on the whitelist, return 403. (Note: an absent Origin is a normal non-browser client, so allow it. "Reject whenever Origin exists" would break conforming clients.)
4. All-interface bind is not an authentication boundary. Real authentication is the session password.

#### 5.1.1 Network bind

Practical constraint: a lab VM on a **physically separate PC** cannot be reached on loopback. Default all-interface bind covers that without picking a NIC.

1. **Default is `0.0.0.0` / `+`**: one prefix covers every adapter, including loopback. If the strong wildcard cannot be reserved, fall back to registering each local IPv4 plus loopback. Host check is relaxed; Origin rejection stays.
2. **`--loopback`**: register only `127.0.0.1`+`[::1]`, with the strict Host whitelist. Elevated/SYSTEM needs no extra `netsh urlacl`.
3. **`--bind <ipv4>`**: pin a concrete IPv4 (plus loopback). Avoid this on multi-NIC hosts. Origin rejection stays in every bind mode.
4. **The session password is the barrier** (§5.2). Restrict inbound TCP at the firewall on a trusted lab segment. Print every local IPv4 so the operator copies the reachable one.
5. **Threat model**: any host on the lab segment that knows the password can reach elevated kernel RW. Forbid use outside a lab/isolated network (absolutely never on a live EDR/AC box).

### 5.2 Authentication and password handling

1. `mcp on` prompts twice for a temporary session password: 4-128 printable ASCII characters, no spaces. The protected endpoint file stores it for the same-box bridge; it is not reused across restarts and normal stop clears the file secrets.
2. Clients send `Authorization: Bearer <password>` (the raw password is also accepted). Constant-time compare, 401 on mismatch.
3. `mcp on` still writes a protected `mcp-endpoint.json` for the same-box Desktop/legacy stdio bridge. Native clients should use IP + port + password directly. Never commit the password to git.
4. Print listen IPs so the operator can tell a remote client which address to use. Do not mint or reuse a disk token.
5. Optional: bind the password to the loopback peer PID via `GetExtendedTcpTable` (defense-in-depth, though vulnerable to reconnect/PID reuse).

### 5.3 Two modes: read-only (default) vs Lab write mode (updated by decision §10-Q1)

MCP **selects one of two modes via an explicit flag at startup**. Because the analysis box is an isolated lab/VM (decision §10-Q2), opening writes for analysis fidelity is justified. But "opened" does not mean "safety rails removed" -- **the frictionless (non-interactive) automatic rails are retained** (already-existing code, zero cost, protects analysis).

#### 5.3.1 Read-only mode (default, non-lab deployment)

- `mcp on` (no flags): does not register write/mutation tools and **disarms the kernel flag itself** via `DeviceClient.SetWriteMode(false)`. Because in C5 the handle `WriteEnabled` is TRUE by default and the kernel-side gate is only that flag + a public constant (`KNDBG_WRITE_ACK_MAGIC`), while disarmed **the kernel itself** rejects write/PPL IOCTLs with `STATUS_ACCESS_DENIED`. The safe default for any non-lab deployment.

#### 5.3.2 Lab write mode (`mcp on <port> --allow-write`)

Activated only by an explicit flag. When activated:

1. **Register the full write tool surface** (§6.1 write namespace). `WriteEnabled` stays TRUE for the session (no need to momentarily toggle write per operation -- since write is a first-class citizen). PPL allows an **arbitrary target** via `process.set_protection` (lab); self-PPL being that special case, the problem of `IOCTL_KNDBG_SET_PROCESS_PROTECTION`/write-virtual sharing the same `WriteEnabled` naturally disappears.
2. **Memory write checks** follow preflight -> supported backup/restore -> write -> read-back -> audit. Failure to create a required backup aborts the mutation; execution/verification errors return `isError:true`. File/ring operations do not all have memory backups. Backup and read-back do not guarantee automatic recovery from every side effect.
3. **Typed write tools only** (the no-raw-command-string rule still holds). The model calls via validated typed arguments like `memory.write_virtual {address, bytes}`, not a raw string like `eb <addr> <bytes>` -- closing the injection/chaining/parsing surface and letting the model call more precisely.
4. **Per-write elicitation is unimplemented.** `mcp write-confirm on` is not a supported command. For individual confirmation, keep MCP read-only and use local `ai write [index] confirm`.

#### 5.3.3 Residual risks and recommendations for Lab write mode (must be understood)

- **Confused deputy**: process names, paths, and memory under analysis can enter model context and induce an incorrect write. Typed validation, backups, and auditing neither fully prevent this nor guarantee recovery.
- **Recommendations**: take a VM checkpoint and analysis baseline before a write session. Limit network exposure, and keep MCP read-only when individual operator confirmation is required.
- **Raw `kd`/DbgEng passthrough remains separately closed** (§5.4-3). The typed write tools already satisfy the "write" requirement, and a raw command is hang/crash/arbitrary-execution, a far larger door. Decide separately if needed.
- `ti.subscribe` is implemented. `action=status` is read-only; `start`/`stop` require `--allow-write` because they change the ETW session. `ti.query` reads the existing ring.

> Recommended driver hardening (follow-up, ABI bump): for read-only mode correctness, the current structure where `SetWriteMode(false)` closes both PPL and write remains valid. However, if you later want "read-only + self-PPL only" again, add a `WriteEnabled`-independent gate to `IOCTL_KNDBG_SET_PROCESS_PROTECTION`.

### 5.4 Input validation

The request-body cap is 1 MiB and JSON nesting is limited to 64. Validate the complete JSON document, UTF-8, duplicate decoded keys, JSON-RPC envelope, and each tool's required fields, known keys, and exact types. Arrays contain strings only. Hex byte lists are independent of console radix; widths and ranges are checked too. HTTP statuses, error codes, and response waits are documented in [the operator guide §5.2](MCP_SETUP.md#52-request-validation-and-response-waits).

1. Every `tools/call` passes the existing guards **as is**: `IsSupportedAiCapabilityTool` (tool allowlist) + `ValidateAiCapabilityToolArgKeys` (per-tool argument-key whitelist) + per-value `ValidateAiCapabilityScalarText` + `ContainsUnsafeAiCommandCharacters` (rejecting `;`/CR/LF/control chars) + scope enum normalization + `IsHelpToken` rejection.
2. **Never accept a raw command string over MCP (including writes).** Only a `tool` + typed args. In read-only mode, the worst an injected model can do is "select another read scanner with in-range arguments." In Lab write mode, write tools are reachable but go through **typed arguments + value validation + backup/verify/audit**, and raw kd/session-change/unload are not exposed in either mode.
3. **The no-raw-command-passthrough rule still holds** (`kd`/arbitrary `u`/`uf` strings). Lab write mode's write tools are added as **typed new primitives** (`memory.write_virtual` etc., each with its own value-validator), but no path that accepts arbitrary command strings is opened.
4. Tool output (process names, module paths, WNF/ETW strings, attacker-controlled memory) is merely **data** and is never reinterpreted as a command.

### 5.5 Egress redaction

The initial design proposed blanket redaction before transport. The current MCP path preserves analysis fidelity and does not automatically redact every result or audit argument. The `ai transcript` redaction setting is not a blanket MCP guarantee.

### 5.6 Auditing (mandatory, not optional)

Data requests and session starts append JSONL records with `ts`, `session`, `peerPort`, `method`, `tool`, `args` truncated to 512 characters, `decision`, `isError`, `resultBytes`, and `writeArmed`. Argument redaction and logging every transport rejection are not guaranteed. `kn://audit/tail` exposes the last 50 lines.

### 5.7 Kill switch

`off`/`mcp off` stops new work and cancels queued jobs. Already-dispatched work can occupy the engine until completion. On normal return to the REPL, `RunMcpEngineLoop` calls `SetWriteMode(true)` to restore the interactive default. Therefore `mcp off` does not disarm local writes; run `write off` after returning if needed. Process exit follows the separate collector/device cleanup path.

### 5.8 Session pin

`initialize` issues a new `Mcp-Session-Id`. Subsequent session-checked requests must match it; a missing or invalid ID returns JSON-RPC `-32600` over HTTP 200. A new `initialize` currently replaces the prior ID rather than rejecting a second initializer. This is not an exclusive-client ownership guarantee; authentication relies on the session password.

---

## 6. Tool / Resource / Prompt Mapping

Rule: **an action the model performs -> Tool / data the user attaches -> Resource / a workflow the user runs -> Prompt.**

### 6.1 Tools (read-only, a subset of the catalog)

Synthesize each `tools/call` into a single-step `AiCapabilityPlan` (schema `kn-live-dbg.ai-capability-plan.v1`) -> existing validation -> `ExecuteAiCapabilityPlan` dispatch. **Keep the single execution path / single guard layer.** `assistant.answer` is not exposed (the external client is the LLM, and exposing it would create a confused-deputy remote-egress path via the internal `AiProviderRuntime`).

v1 tools (18) and argument schemas (= the existing whitelist, `additionalProperties:false`):

| MCP tool | Args | Mapped scanner |
|----------|------|-------------|
| `process.find` | image\|name\|process, pid, eprocess | live process list |
| `process.describe` | source, pid, eprocess, fields | `_EPROCESS` fields |
| `type.describe` | source, address, type, fields | `dt` structure |
| `callbacks.list` | scope, module | `CallbackScanner` |
| `callbacks.set` | action, module, scope | `KernelCallbackScanner::SetModuleCallbacks` (WRITE) |
| `wfp.list` | scope, module, provider, layer | `WfpScanner` (+ kernel callout pointers) |
| `alpc.list` | scope, name, pid | `AlpcScanner` |
| `vad.list` | source, image, pid, eprocess, exec, private, wx, pe, hiddenpte, dkom, summary, limit | `ProcessTriageScanner::ScanVad` |
| `threads.list` | source, image, pid, eprocess, apc, stacks, limit | `ProcessTriageScanner::ScanThreads` |
| `etw.integrity` | (none) | `EtwScanner::ScanIntegrity` |
| `nmi.list` | scope | `NmiScanner` |
| `fwtable.list` | scope, module, provider, signature | `FirmwareTableScanner` |
| `pool.find` | tag, min, max, addr, limit, paged, annotate, wx | `PoolScanner` |
| `address.inspect` | address, va, symbol | `AddressInspector` |
| `wnf.decode` | hash, state, state_name | `WnfScanner` decoder |
| `wnf.list` | scope | `WnfScanner` |
| `ti.query` | action, count, pid, task, pattern | `ThreatIntelSubscriber` ring (read action only) |
| `module.integrity` | module, target, limit, summary, verbose, headers, sections, wx, mismatch | `IntegrityScanner::ScanModules` |
| `driver.integrity` | driver, target, limit | `IntegrityScanner::ScanDrivers` |

- The inputSchema is generated from the **same constant arrays** the validator uses, eliminating schema/validator drift at the source.
- annotations: all read tools have `readOnlyHint:true`, `openWorldHint:false`. (However, an annotation is only an advisory hint -- the real gate is the server-side guards.)
- Not exposed in either mode: raw `kd`/DbgEng passthrough, session changes (direct toggling of backend/symbol path/write on-off), unload/shutdown, `byovd` YARA arbitrary file path. (The `byovd`/`hunt`/`snapshot` read tools are exposed after being added to the whitelist in the §9 follow-up stage.)

### 6.1.1 Write tool namespace (Lab write mode only, `--allow-write`)

Registered only via `mcp on --allow-write`. All go through **typed arguments + value validation + preflight/backup/verify-diff/audit** (§5.3.2). Common annotations: `readOnlyHint:false`, `destructiveHint:true`.

| MCP tool | Args | Mapping |
|----------|------|------|
| `memory.write_virtual` | address\|symbol, bytes(hex), width?, process? | `e*` (default context System pid 4, change via `process`) |
| `memory.write_physical` | physical_address, bytes(hex) | `pe*` |
| `memory.fill` | address, length, pattern(hex) | `fill` |
| `memory.move` | source, dest, length | `move` |
| `type.set_field` | address, type, field, value | `setfield` (PDB offset + width automatic) |
| `process.set_protection` | pid?(default self), level | direct call to `IOCTL_KNDBG_SET_PROCESS_PROTECTION` (arbitrary target; level->raw byte mapping, PDB offset resolution) |
| `dump.raw` | address, length, path | `dump-raw` (path **required**, traversal prevention) |
| `dump.pe` | address, path | `dump-pe` (path **required**) |

- `bytes`/`pattern` are received as hex strings with length/range validation (driver 1MB cap). No raw command string.
- The `dump.*` path is **required** and rejects traversal (`..`) and unsafe characters (since the implementation does not synthesize a default path, the schema advertises path as required).
- `process.set_protection` calls `DeviceClient::SetProcessProtection(pid, offset, byte)` directly, without going through `set-ppl-antimalware` (the self-only TUI command). The level is mapped via `ParseProtectionByte` to a raw PS_PROTECTION byte (none/ppl-*/pp-*), and the old/readback bytes in the response become the inline backup/verify.
- `idempotentHint`: write_virtual/physical/fill/move/set_field=false, set_protection=true (no-op if already at that level).

### 6.2 Resources (cheap, side-effect-free context)

The `kn://` scheme. Resources that need live kernel data still go through the engine queue. Only cached/static ones are served directly.

| URI | Content |
|-----|------|
| `kn://session/info` | `DriverSessionStatus` (Flags/OwnerPid/CurrentPid/OpenHandleCount) + ABI 12 + `KNDBG_MAX_TRANSFER_SIZE` (1MB) + write-mode/MCP-arm state -> a situational-awareness anchor for the model |
| `kn://session/symbols` | `SymbolEngine.SymbolPath()` + module count + kernel symbol load state (cached on the engine thread) |
| `kn://modules/kernel` | kernel module list (name/base/size) -- a map the model uses for name->module arguments |
| `kn://drivers/status` | `drvstatus` summary |
| `kn://snapshot/current` | the existing `BuildSnapshotJson` (`kn-live-dbg.snapshot.v1`) as is when a baseline exists |
| `kn://ti/stats` | TiSubscriber ring histogram/stats (thread-safe API) |
| `kn://audit/tail` | the most recent N audit lines (redacted) |
| `kn://capabilities` | active tools + argument whitelist + read/write classification manifest |

Note (protocol nuance): resources are **attached by the user/app**, not autonomously pulled by the model (in Claude Code, an `@server:scheme://...` mention). Therefore `capabilities` for the model's self-introduction is also provided via `tools/list` (or a dedicated tool).

### 6.3 Prompts (parameterized playbooks)

Exposed in Claude Code as the `/mcp__knlivedbg__<prompt>` slash command. They only return a **message** guiding a read-only tool sequence, never auto-executing. Each prompt includes the standard guidance "preserve raw evidence, do not propose writes."

1. `callback-audit {module?}` -- enumerate object/registry/process/thread/imageload/minifilter callbacks -> cross-verify non-module/external targets with `address.inspect` + `module.integrity`.
2. `driver-surface-map {driver}` -- `driver.integrity` + `module.integrity` + that driver's callbacks + WFP callouts.
3. `address-provenance {address}` -- `address.inspect` -> `pool.find` for the containing region -> `module.integrity`.
4. `minifilter-review` -- `callbacks.list scope=minifilter` + altitude analysis + per-filter `module.integrity`.
5. `hunt-triage {pid?}` -- `process.find` -> `vad.list` (wx/private/hiddenpte/dkom) + `threads.list` (stacks) + `ti.query` by pid.
6. `etw-infinityhook-check` -- `etw.integrity` + `nmi.list` + `ti.query`.
7. `wfp-surface` -- `wfp.list` providers/sublayers/callouts/filters/layers + `address.inspect` on the kernel callout pointers.

---

## 7. Structured Output Strategy

The current catalog mixes structured results and text-only tools. The sections below retain the output design targets; per-tool `outputSchema`, uniform pagination, and `resource_link` are not blanket guarantees. Use the operator guide §6 and `tools/list` for the current contract.

### 7.1 2-tier

- **Tier A (ships immediately, all 18 tools)**: wrap the existing text executor with `ScopedWideStreamCapture` (C4) to capture `CommandExecutionResult.Output` -> redact -> `{content:[{type:"text", text:<captured>}]}`. With zero scanner changes, all tools work on day 1.
- **Tier B (incremental, per scanner)**: serialize the scanner struct directly -> `structuredContent` + outputSchema. Reuse the existing 5 (`module/driver integrity`, `vad`, `threads`, `hunt`, `byovd`, `snapshot`), and write new builders for the remaining ~12 using the same `std::wstringstream` pattern. Promote text->structured per tool with no MCP contract change.

### 7.2 MCP result shape (contract)

```jsonc
{
  "content": [
    { "type": "text", "text": "<exact serialized JSON, identical to structuredContent>" },
    { "type": "text", "text": "<optional: human-readable summary>" }
  ],
  "structuredContent": { "schema": "kn-live-dbg.callbacks.v1", "...": "..." },
  "isError": false
}
```

- **`content[0].text` must be exactly identical to the serialized JSON**, not a prose summary (so clients without structured support receive the data losslessly). The summary/capture text goes in an additional block.
- Declare a **per-tool `outputSchema`**, and stamp the internal schema id (`kn-live-dbg.*.vN`) as a `structuredContent` field so the client can detect version drift.

### 7.3 Error model (important -- common mistake)

- **Tool argument-validation/execution/`engine busy`/`device busy`/`writes disabled`/scope errors = `isError:true` CallToolResult content** (with a text explanation). So the model self-corrects.
- JSON-RPC protocol errors are only for **unknown tool (-32601) / malformed params (-32602) / parse / invalid request / auth / session**. (No business errors like `-32000`/`-32001` -- that breaks model self-correction and becomes an error oracle.)

### 7.4 Token budget / pagination / large payloads (design targets)

The following are targets for a uniform output contract. Pagination, `resource_link`, and a 64KB/200-record cap are not implemented uniformly across tools. Use `tools/list` and the operator guide §6 for supported arguments.

- All list tools: `offset`+`limit` + a `{total, returned, truncated, next_offset}` envelope. A conservative default cap (e.g., 200 records / 64KB); on overflow `truncated:true` + an explicit hint (never a silent drop). `UserModeHunter`/pool-scan especially have a bounded default.
- Large outputs (snapshot/dump/full pool listing) reference a `kn://` resource via **`resource_link`** instead of inline. (Claude Code warns at ~10k tokens and truncates/persists at ~25k (`MAX_MCP_OUTPUT_TOKENS`).)
- Only the few tools that legitimately need large text raise `_meta["anthropic/maxResultSizeChars"]` (<=500,000).
- Raw reads are bounded by the driver `KNDBG_MAX_TRANSFER_SIZE` (1MB) and offset-chunked.

### 7.5 UTF-8 safety (a real bug)

The existing escapers (`EscapeJsonText`/`HuntJsonEscape` etc.) operate on UTF-16 and **do not handle lone/unpaired surrogates.** Kernel-derived strings (WNF names, module paths, attacker-controlled memory, ETW task) can be ill-formed UTF-16, and `WideCharToMultiByte(CP_UTF8, ...)` produces invalid UTF-8, breaking the JSON-RPC (UTF-8 MUST) stream.

Mitigation: before serialization, sanitize all wide strings against ill-formed UTF-16 (lone surrogate -> U+FFFD or hex escape), and use `WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, ...)` to **fail loudly rather than corrupt silently**. **Consolidate the escape helpers (4+ scattered) into a single audited escaper** and add a JSON-validity self-check in debug builds.

---

## 8. Client Configuration

> The hands-on operational procedure (starting the server, remote `--bind`, connecting Claude, firewall, the full tool/resource/prompt catalog, troubleshooting) is documented in the separate operator guide [`MCP_SETUP.md`](./MCP_SETUP.md). Below is a design-perspective summary.

### 8.1 Protocol version

- baseline **2025-06-18** (includes structuredContent, elicitation, tool annotations, resource_link, broadly supported by Claude Code/Desktop). Negotiate up to **2025-11-25** if the client offers it. Do not depend on experimental async Tasks.
- Over HTTP, require an `MCP-Protocol-Version` header on every request after init: if absent, the server assumes 2025-03-26 (losing structured/elicitation); if an unsupported value, return **HTTP 400**. *(Planned -- the current v0 scaffold does not validate this header, §11.1 (4) follow-up.)*

### 8.2 Claude Code

```bash
# Recommended: native Streamable HTTP. Use the session password from `mcp on`.
claude mcp add --transport http knlivedbg http://127.0.0.1:51766/mcp \
  --header "Authorization: Bearer YOUR_PASSWORD"

# Remote: default `mcp on` already listens on all adapters. Pick a printed listen IP.
claude mcp add --transport http knlivedbg http://192.168.56.10:51766/mcp \
  --header "Authorization: Bearer YOUR_PASSWORD"

# Legacy fallback only (does not directly expose the live process)
claude mcp add --transport stdio knlivedbg-bridge -- \
  npx -y mcp-remote@0.1.38 http://127.0.0.1:51766/mcp --allow-http --transport http-only --silent --header "Authorization: Bearer YOUR_PASSWORD"
```

On a network bind (§5.1.1): the session password is the only barrier, so **allow inbound only from the client IP at the firewall** and use it only on a trusted lab segment.

`.mcp.json` (password via env or a literal header -- no secret in a committable file):

```jsonc
{
  "mcpServers": {
    "knlivedbg": {
      "type": "http",
      "url": "http://127.0.0.1:51766/mcp",
      "headers": { "Authorization": "Bearer ${KNLIVEDBG_TOKEN}" }
    }
  }
}
```

`${KNLIVEDBG_TOKEN}` is the session password. Same-box: `mcp-load-env.ps1` loads it from the live endpoint.

A larger client timeout does not extend the server's 30-second response wait. Dispatched work may continue; use the outcome distinction in §4.3.

### 8.3 Claude Desktop

Claude Desktop's remote connectors support Streamable HTTP, but Claude connects to them from Anthropic's cloud. They cannot reach `127.0.0.1` or a private lab address, and Claude Desktop does not connect to a remote HTTP server declared directly in `claude_desktop_config.json`. For this local KnLiveDbg endpoint, merge the stdio config printed by `mcp client-setup claude-desktop`; it launches `tools/mcp-bridge.ps1`, which reads the protected endpoint once at process startup and forwards stdio to HTTP. Fully restart Desktop after editing or after a new `mcp on` / `mcp off`.

Do not expose the kernel endpoint publicly merely to use a Claude remote connector. Keep it on loopback and use the local bridge. This is the only current first-class client path where the bridge is preferred.

---

## 9. Phased Implementation Plan

| Phase | Content | Deliverable (smallest ship) |
|-------|------|----------------------|
| **0. Plumbing** | http.sys listener (default `+` / 0.0.0.0), `mcp on/off` console command, session-password prompt, Host/Origin validation, `Mcp-Session-Id`/`MCP-Protocol-Version`, JSON-RPC framing (initialize/tools/list/tools/call/resources/*/prompts/*). Expose only `kn://capabilities` + `kn://session/info` (cached). | The client can connect, authenticate, tools/list, and query the session. Zero device access. Proves transport/auth/session before kernel exposure. |
| **1. Read catalog (Tier A)** | Engine queue + console-line-as-job drain loop, 18 read-only tools reusing `ExecuteAiCapabilityPlan` + `ScopedWideStreamCapture` text. origin="mcp" audit. Default read-only mode = `SetWriteMode(false)` disarmed. | The external LLM drives the full read forensics surface under guards/audit. **The first ship with real value.** |
| **2. Structured JSON (Tier B)** | Write/reuse a `Build*Json` per scanner -> `structuredContent` + outputSchema. offset/limit pagination. Unified surrogate-safe escaper. | Promote text->structured per tool with no contract change. |
| **3. Resources + prompts** | `kn://modules`/`drivers`/`snapshot`/`ti/stats`/`audit/tail` + 7 playbook prompts. Large payloads via `resource_link`. | Model self-grounding + slash-command workflows. |
| **4. Lab write mode** | `--allow-write`, supported backup/read-back/audit, and arbitrary-PID `process.set_protection` are implemented. Per-write SSE elicitation remains a follow-up. | OFF by default. Current behavior is documented in the operator guide §3.4 and §6.2. |

Each stage can ship independently, and no later stage weakens the Phase-0 security posture.

---

## 10. Finalized Decisions (2026-06-24)

The 6 open items of the §3 initial design are finalized as below.

1. **Server stack -> http.sys (`httpapi.lib`)**. A hand-rolled HTTP parser in an elevated process is a top-priority EoP surface, so offload to the kernel-audited http.sys. **Administrator/SYSTEM needs no separate `netsh urlacl` reservation for `HttpAddUrlToUrlGroup`**. Default prefix `http://+:<port>/mcp/` (all interfaces). `--loopback` uses `http://127.0.0.1:<port>/mcp` + `http://[::1]:<port>/mcp`. WinSock rejected.
2. **Port -> fixed default + override**. A port scan is trivially available -> the security benefit of randomization is approximately 0 while the cost of breaking the client config every session is large (real authentication is the session password). A fixed default in the private range (e.g., `51766`) + `mcp on <port>` override.
3. **Write exposure -> full open in Lab write mode (Q1, updated 2026-06-24)**. Since it is an isolated lab/VM (Q2), open the full typed write tool set (§6.1.1) via `mcp on --allow-write` for analysis fidelity. But "open != safety rails removed" -- keep frictionless automatic preflight/backup/verify-diff/audit (§5.3.2) and continue to forbid raw kd / arbitrary commands / hidden writes. The non-lab default is read-only + kernel flag disarmed (§5.3.1). VM snapshot recommended before writing (§5.3.3). *(Replaces the earlier "PPL exception only" decision.)*
4. **Client authentication** uses the session password entered at `mcp on`. The protected same-box bridge endpoint stores it, normal stop clears the secrets, and restart does not reuse it.
5. **Execution environment -> centered on an isolated analysis VM (Q2)**. Default all-interface bind is for lab NICs; `--loopback` remains available. (If a need arises to use it on a live EDR/AC box, review the named-pipe option from the backlog.)
6. **Current limits**: response wait 30 seconds, eight pending MCP jobs, request body 1 MiB. The response wait is not an execution deadline. Uniform 64KB/200-record results and full configuration exposure were initial targets; inspect each tool's implemented limits.

Remaining backlog (decide at operation/implementation time): whether to limit the port ACL to the elevated account via http.sys SDDL; the driver hardening (§5.3.1) that adds a gate independent of `WriteEnabled` to `SetProcessProtection` to remove the momentary write window.

---

## 11. Appendix: Reuse/Modification Points (code references)

Line numbers may shift, so treat function names as the primary reference.

**Reuse (almost as is)**
- Catalog/validation: `IsSupportedAiCapabilityTool`, `ValidateAiCapabilityToolArgKeys`, `ValidateAiCapabilityScalarText`, `ContainsUnsafeAiCommandCharacters`, `IsHelpToken`, `ExecuteAiCapabilityPlan` (`user/main.cpp`)
- Output capture: `ScopedWideStreamCapture`, `CommandExecutionResult`, `ExecuteCommandWithTranscript` (`user/main.cpp`)
- JSON builders: `BuildModuleIntegrityJson`/`BuildDriverIntegrityJson` (`IntegrityScanner.cpp`), `BuildProcessVadJson`/`BuildProcessThreadsJson` (`ProcessTriageScanner.cpp`), `BuildHuntJson` (`UserModeHunter.cpp`), `BuildByovdScanJson` (`ByovdScanner.cpp`), `BuildSnapshotJson` (`SnapshotJson.cpp`)
- Redaction: `MaybeRedactTranscriptText` (`user/main.cpp`)
- TI thread-safe queries: `Recent`/`FilterByPid`/`FilterByTask`/`Grep`/`Histogram` (`ThreatIntelSubscriber.h`)
- Device control: `DeviceClient::SetWriteMode`, `QuerySessionStatus` (`DeviceClient`)

**Newly written**
- `McpServer` (http.sys listener + JSON-RPC + auth/host/origin/session), `EngineQueue`/`McpJob` (§4), console-as-job reader switch (§4.2), a unified surrogate-safe JSON escaper (§7.5), `Build*Json` for ~12 scanners (§7.1), MCP audit JSONL (§5.6), `mcp on/off/arm-writes` (follow-up) console commands.

**Watch points**
- Do not add `wmain` argv parsing (headless mode not adopted). Activate only via the `mcp on` console command.
- `ScopedCommandProgress` is disabled in MCP-origin jobs (C10).
- Insert debug TID/capture-singleness asserts at the `DeviceClient`/`SymbolEngine` entry points.

---

## 11.1 Initial Implementation Record (v0 scaffold, historical)

An initial scaffold that implements Phase 0~1 + the write namespace (§6.1.1) all at once is in place.

New files:
- `user/McpJson.h` -- header-only, surrogate-safe JSON escape / UTF-8 conversion / top-level value extraction (transport layer only, no dependency on main.cpp statics).
- `user/McpServer.h` / `user/McpServer.cpp` -- http.sys listener (default `+` / 0.0.0.0, `/mcp`), overlapped receive + stop event, session-password constant-time comparison, Host/Origin validation, single `Mcp-Session-Id` pin, JSON-RPC (initialize/ping/tools.list/tools.call/resources.list+read/prompts.list+get/notifications), static tool/resource/prompt catalog, bounded serial job queue.

main.cpp integration:
- One global `static McpServer g_McpServer;`.
- `HandleMcpCommand` (`mcp on [port] [--allow-write] [--loopback] [--bind <addr>]` / `off` / `status`) -- `HandleCommand` dispatch + `CommandRegistry` registration.
- `DispatchMcpRequest` (engine thread): read tools synthesize a `kn-live-dbg.ai-capability-plan.v1` plan -> `ParseAiCapabilityPlanResponse` -> `ExecuteAiCapabilityPlan` inside a `ScopedWideStreamCapture` (reusing validation + executor). Write tools have `DispatchMcpWriteTool` validate typed arguments (`ContainsUnsafeAiCommandCharacters`/whitespace/hex) -> build a command line -> `BuildWriteSafetyPlan` backup -> `ExecuteCommandWithTranscript` (automatic write-audit) -> verify.
- `RunMcpEngineLoop` (engine thread): polls via `WaitForSingleObject(JobReadyEvent, 200)` and does `TryPopJob` -> `DispatchMcpRequest` -> promise. The console control reader thread (`off`/`status`) uses only `ReadConsoleW` (no wcout access -> avoids the global rdbuf race). On `mcp on`, arm/disarm write mode; restore on exit.
- At the `wmain` REPL loop entry, if `g_McpServer.IsRunning()`, enter `RunMcpEngineLoop` (preserving the read-only-default / single-engine-thread invariants). `g_McpServer.Stop()` on the shutdown path.

vcxproj: added `McpServer.cpp` + headers, linked `Httpapi.lib`.

Validation/limitations (must be understood):
- **Build green**: with `tools/build.ps1`, both Debug/Release x64 compile and link successfully, with 0 MCP-related warnings (the http.sys signatures were cross-checked against SDK 10.0.26100.0 `http.h`). **But runtime/live unverified** -- an actual MCP client round trip after `mcp on` needs confirmation on a test VM.
- Known simplifications of the v0 scaffold: (1) **Tier-B complete** -- all 18 read tools return structuredContent (§11.1.1). (2) During MCP mode the operator console is control-only (`off`/`status`) -- the full REPL resumes after `off`. (3) `process.set_protection` is mapped to self-only (`set-ppl-antimalware`), arbitrary-target PPL is unimplemented. (4) Pagination / `resource_link` / per-tool `outputSchema` / strict `MCP-Protocol-Version` validation / elicitation are follow-ups. (5) Redaction is not applied by default, for lab analysis fidelity.

### 11.1.1 Tier-B structuredContent progress

Divergence-free wiring: an optional `std::wstring* structuredJsonOut = nullptr` out-param is added to the four TUI handlers (`HandleModuleIntegrityCommand`/`HandleDriverIntegrityCommand`/`HandleVadCommand`/`HandleThreadsCommand`) so the existing `Build*Json` is called on the **same `result` struct** the `/json` path already used (no duplicate scan/option parsing). `structuredJsonOut` threads through the capability executors (`ExecuteAiCapability{ModuleIntegrity,DriverIntegrity,VadList,ThreadsList}`) -> `ExecuteAiCapabilityPlan` (new out-param) -> `DispatchMcpRequest`. vad/threads aggregate the per-matched-process JSON into `{"processes":[...]}`. When structuredJson exists, `BuildToolResult` puts it into `content[0].text` and `structuredContent`, and to save tokens does not send the captured TUI text to the model (it is tee'd to the console).

**Complete -- 15 data tools return structuredContent** (Debug/Release build green, 0 warnings):

| Tool | Builder | Location |
|----|------|------|
| `module.integrity` / `driver.integrity` | `BuildModuleIntegrityJson` / `BuildDriverIntegrityJson` | IntegrityScanner (existing) |
| `vad.list` / `threads.list` | `BuildProcessVadJson` / `BuildProcessThreadsJson` (per-process `{"processes":[...]}` aggregation) | ProcessTriageScanner (existing) |
| `callbacks.list` | `BuildCallbacksJson` (`kn-live-dbg.callbacks.v1`) | CallbackScanner.cpp (new) |
| `wfp.list` | `BuildWfpJson` (`kn-live-dbg.wfp.v1`) | WfpScanner.cpp (new) |
| `alpc.list` | `BuildAlpcJson` (`kn-live-dbg.alpc.v1`) | AlpcScanner.cpp (new) |
| `pool.find` | `BuildPoolJson` (`kn-live-dbg.pool.v1`) | PoolScanner.cpp (new) |
| `address.inspect` | `BuildAddressInspectJson` (`kn-live-dbg.address.v1`) | AddressInspector.cpp (new) |
| `etw.integrity` | `BuildEtwIntegrityJson` (`kn-live-dbg.etw-integrity.v1`) | EtwScanner.cpp (new) |
| `nmi.list` | `BuildNmiJson` (`kn-live-dbg.nmi.v1`) | NmiScanner.cpp (new) |
| `fwtable.list` | `BuildFirmwareTableJson` (`kn-live-dbg.fwtable.v1`) | FirmwareTableScanner.cpp (new) |
| `wnf.list` | `BuildWnfInstancesJson` (`kn-live-dbg.wnf.v1`) | WnfScanner.cpp (new) |
| `ti.query` | `BuildMcpTiEventsJson` / `BuildMcpTiStatsJson` (`kn-live-dbg.ti.v1` / `.ti-stats.v1`) -- direct serialization from the thread-safe ring API (`Recent`/`FilterByPid`/`FilterByTask`/`Grep`/`SnapshotStats`), cap 200 / max 5000 | main.cpp (new) |
| `process.find` | `BuildMcpProcessListJson` (`kn-live-dbg.process-list.v1`) | main.cpp (new) |

All new builders reuse the surrogate-safe `mcpjson::` escaper, with a per-file unique hex helper (`WfpJsonHex` etc.). The 8 per-scanner builders were written via a parallel workflow.

**The remaining 3 are also complete** (all 18 read tools structured):
- `process.describe` -- reuses `BuildMcpProcessListJson` (same as process.find).
- `wnf.decode` -- `BuildMcpWnfDecodedJson` (`kn-live-dbg.wnf-decode.v1`), calling `DecodeWnfStateName(parsed)` directly (main.cpp).
- `type.describe` -- `BuildMcpTypeDumpJson` (`kn-live-dbg.type.v1`): receives the `dt` output via a **nested capture** (engine thread, LIFO-safe), parses `+0x<off> <name> : <value>` lines into `fields[]` + preserves raw `text`. Multiple processes aggregate into `{"dumps":[...]}`.

**Tier-B complete: all initial 18 read tools return structuredContent** (Debug/Release build green, 0 warnings).

### 11.1.2 Catalog expansion -- added 9 anti-cheat detections (2026-06-25)

Added kernel anti-cheat detections not in the initial catalog (the 18 tools used by the internal `ai`) as MCP tools. Each tool follows the same pattern: `IsSupportedAiCapabilityTool` allowlist + `ValidateAiCapabilityToolArgKeys` argument whitelist + a new `ExecuteAiCapability*` executor + an `ExecuteAiCapabilityPlan` switch branch + the handler `structuredJsonOut` out-param + an `McpServer.cpp` `kTools` entry + a planner prompt. The internal `ai` command gets the same tools.

| MCP tool | TUI | Builder | Notes |
|----------|-----|------|------|
| `ssdt.scan` | `!ssdt` | `BuildSsdtJson` (`kn-live-dbg.ssdt.v1`) | SSDT/shadow hooks |
| `idt.scan` | `!idt` | `BuildIdtJson` (`.idt.v1`) | IDT hooks + per-CPU divergence |
| `cr.scan` | `!cr` | `BuildCrJson` (`.cr.v1`) | CR0.WP/SMEP/SMAP |
| `msr.check` | `!msrcheck` | `BuildMsrJson` (`.msr.v1`) | SYSCALL MSR hooks |
| `vbs.scan` | `!vbs` | `BuildVbsJson` (`.vbs.v1`) | VBS/HVCI/CI/SecureKernel/trustlet (a single tool covering !ci/!securekernel) |
| `byovd.scan` | `!byovd scan /no-update` | `BuildByovdScanJson` (existing) | `/no-update` forced (blocks network/subprocess) |
| `pool.scan_pe` | `!pool pe` | `BuildPoolPeJson` (`.pool-pe.v1`) | args tag/limit/suspicious; `/dump` not exposed |
| `payload.inspect` | `!payload` | `BuildPayloadTraceJson` (`.payload.v1`) | hook-to-body; args address/va/symbol |
| `payload.scan` | `!payload scan` | `BuildPayloadTraceJson` (`.payload.v1`) | hook-to-body; args limit |
| `mapper.list` | `!mapper` | `BuildMapperJson` (`.mapper.v1`) | bookkeeping remnants; leftover=0 is ledger-clean; args scope/limit |
| `kpage.list` | `!kpage` | `BuildOrphanKernelPageJson` (`.kpage.v1`) | orphan pages; args deep/wx/pe/limit; deep is not default |
| `minifilter.list` | `!minifilter` | `BuildMinifilterIrpJson` (`.minifilter.v1`) | args filter/name |
| `minifilter.set_irp` | `!minifilter disable/enable` | `BuildMinifilterIrpChangeJson` (`.minifilter-irp.v1`) or `BuildMinifilterIrpBatchJson` (`.minifilter-irp-batch.v1`) | WRITE; action enable/disable; `irp=all` batches |
| `callbacks.set` | `!callbacks disable/enable` | `BuildCallbackSetJson` (`.callbacks-set.v1`) | WRITE; action enable/disable/enable-all/disable-all; module required; scope required except *-all |
| `hunt.run` | `!hunt` | `BuildHuntJson` (existing) | args mode (quick/deep); `/summary` forced |
| `snapshot.capture` | `!snapshot baseline` | `BuildSnapshotJson` (existing) | args name; baseline file write (not a kernel write -> allowed in read-only mode) |

The 6 new builders (ssdt/idt/cr/msr/vbs/poolpe) were written via a parallel workflow into each scanner's `.cpp`, using the `mcpjson::` escaper + a per-file unique hex helper. **Result: all 27 MCP read tools return structuredContent**, Debug+Release build green.

Kept unexposed (by design): raw `kd`/DbgEng passthrough, `!ci`/`!securekernel` individually (consolidated into vbs.scan), `dump-raw`/`dump-pe` arbitrary paths, raw memory read/disasm.

### 11.1.3 Resource enrichment -- 8 implemented (2026-06-25)

Implemented all resources of §6.2. Advertised via `BuildResourcesList` (McpServer.cpp) + served via the `ResourceRead` branch of `DispatchMcpRequest` (engine thread):

| Resource | Source | Builder |
|--------|------|------|
| `kn://session/info` | `QuerySessionStatus`+ABI+arm | (inline) |
| `kn://capabilities` | kTools manifest | `BuildCapabilitiesResource` (transport) |
| `kn://modules/kernel` | `SymbolEngine.Modules()` | `BuildMcpModulesJson` (`kn-live-dbg.modules.v1`) |
| `kn://drivers/status` | `DriverService.Query`+session | `BuildMcpDriversJson` (`.drivers.v1`) |
| `kn://session/symbols` | `SymbolPath`/module count/`IsReady` | `BuildMcpSymbolsJson` (`.symbols.v1`) |
| `kn://ti/stats` | `SnapshotStats`/`IsActive` | `BuildMcpTiStatsJson` (existing, `.ti-stats.v1`) |
| `kn://snapshot/current` | `state.SnapshotBaseline` | `BuildSnapshotJson` (existing); `present:false` if absent |
| `kn://audit/tail` | last 50 lines of the `aiState.WriteAuditPath` JSONL | `BuildMcpAuditTailJson` (`.audit-tail.v1`) |

**27 MCP read tools + 8 resources + 7 prompts, all build green (Debug+Release).**

### 11.1.4 MCP automatic audit (2026-06-25)

Satisfies §5.6. `McpServer` owns a dedicated append-only JSONL log -- path `<exeDir>\.kn-live-dbg\mcp-audit-<port>.jsonl`, **always ON when `mcp on`** (independent of the operator's `ai audit` toggle). The listener thread appends one record per `initialize`/`tools/call`/`resources/read`: `ts` (GetSystemTime UTC), `session`, `peerPort` (extracted directly from the sockaddr bytes -- no winsock needed), `method`, `tool`, `args` (512-char truncate), `decision` (ok/unknown-tool/writes-disabled/engine-busy/tool-error/unknown-resource/session-open), `isError`, `resultBytes`, `writeArmed`. Being a single chokepoint (the listener), it captures reads, writes, resources, and denials all at once. `McpServerConfig.AuditPath` + `McpServer::AuditPath()`/`AppendAuditLine` (mutex, append mode) + directory creation in Start. `kn://audit/tail` is switched to read this path (always `enabled:true`).

Side fix: found a bug where the `resources/read` listener handled only `session/info`+`capabilities`, so the 6 new resources of §11.1.3 fell through to `unknown-resource` at runtime -> fixed to forward the entire `kn://` to the engine (`DispatchMcpRequest`) (a runtime routing bug that compiled fine). Debug+Release build green.

- Live verification items: `mcp on` -> `claude mcp add --transport http` connect -> `tools/list`/`resources/list` + round trips of `callbacks.list`/`ssdt.scan`/`kn://modules/kernel` etc. -> the `memory.write_virtual` backup/verify path via `--allow-write` (test VM, after a snapshot).

### 11.1.5 Current catalog and validation (2026-09-19)

The current `kTools` table in `user/McpServer.cpp` contains **67 read tools + 12 write tools = 79 total**. Operator tables are in [MCP_SETUP.md §6](MCP_SETUP.md#6-capability-catalog). `ti.subscribe` start/stop require write mode, and `process.set_protection` accepts an arbitrary PID. Release/Debug passed 75 MCP-tool checks and nine separate HTTP checks per configuration. The [command audit](COMMAND_AUDIT_20260919.md) records parser ASan/queue evidence and live-kernel validation limits.

## 12. Current Implementation Summary

1. The in-process HTTP.sys server is OFF by default, binds `0.0.0.0:51766` by default, and supports `--loopback`.
2. Kernel/symbol work runs on one engine FIFO; stream capture belongs to that thread.
3. Read-only is the default; `--allow-write` exposes 12 write tools.
4. Complete JSON and advertised tool schemas are validated; raw commands are not accepted.
5. Some tools return structured JSON and others text. Uniform pagination and elicitation remain follow-ups.
6. An ended wait cancels only queued jobs. Dispatched outcomes may be unknown; MCP cancellation notifications do not remove jobs.
7. After `mcp off`, the REPL returns to its default write-on mode. Session files, auditing, and authentication follow the implementation contracts above.
