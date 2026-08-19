> Korean version: [MCP_SERVER_DESIGN.ko.md](./MCP_SERVER_DESIGN.ko.md)

# MCP Server Design (Kn-Live-Dbg)

This document defines a design for adding an **MCP (Model Context Protocol) server** to Kn-Live-Dbg so that external LLM hosts such as Claude Code / Claude Desktop / Cursor can directly leverage this tool's (primarily read-only) kernel forensics / anti-cheat features as MCP tools / resources / prompts.

The core principles carry over directly from the philosophy of the existing `docs/AI_ASSISTED_WORKFLOWS.md`: the AI is advisory by default, no hidden automatic writes, raw evidence is preserved, the driver stays a narrow memory primitive, and sensitive kernel state can be kept local-only. MCP is a **third frontend** that reuses the **same capability catalog + guard layer** as the existing `ai` command (following the REPL and the internal AiProvider).

> Conclusion summary (first): **in-process loopback Streamable HTTP**, **read-only v1**, **single-engine-thread serialization**, **100% reuse of the existing catalog/guards**, **kernel write flag disarmed when MCP is enabled**.

---

## 1. Purpose and Scope

### 1.1 Purpose

1. Let external LLMs invoke read-only detection features such as `callbacks`, `!wfp`, `!alpc`, `!vbs`, `!etw`, `!nmi`, `!ssdt`, `!idt`, `!cr`, `!msrcheck`, `!pool`, `!address`, `byovd`, `!ti`, `module/driver integrity`, and VAD/thread hunting in a structured form.
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
| C3 | **Single-threaded engine**: all `HandleCommand` dispatch, all `DeviceClient` IOCTLs, and all `SymbolEngine` (DbgHelp/DIA) calls run only on the main REPL thread. `DeviceClient` has no lock, and DbgHelp/DIA are not thread-safe. | `DeviceClient` (no lock), `SymbolEngine` |
| C4 | **Output capture already exists**: `ScopedWideStreamCapture` swaps the **process-global rdbuf** of `std::wcout`/`std::wcerr` to a string buffer. Transcript/AI evidence already uses it. | `ScopedWideStreamCapture` (`std::wcout.rdbuf(&outBuffer_)`) |
| C5 | **Driver write is ON by default**: in `IRP_MJ_CREATE` the handle context `WriteEnabled = TRUE`. The kernel-side gate of the write-virtual/physical/SetProcessProtection handlers is only this flag + `KNDBG_WRITE_ACK_MAGIC` (a public compile-time constant). **The entire write-safety pipeline exists only in user-mode.** | `Driver.cpp` (`WriteEnabled = TRUE`), `KnLiveDbgIoctl.h` (`KNDBG_WRITE_ACK_MAGIC`) |
| C6 | **Capability catalog + guards exist**: 20 read-only tools, per-tool argument whitelist, value validation (rejecting `;`/newlines/control chars/help tokens), rejection of write-like/raw-kd/nested-ai/session-change/unload, single execution path. | `IsSupportedAiCapabilityTool`, `ValidateAiCapabilityToolArgKeys`, `ValidateAiCapabilityScalarText`, `ContainsUnsafeAiCommandCharacters`, `ExecuteAiCapabilityPlan` |
| C7 | **Almost every scanner returns a structured struct**, and 5 of them have JSON builders. No external JSON library (direct escaping). | `BuildModuleIntegrityJson`/`BuildDriverIntegrityJson`, `BuildProcessVadJson`/`BuildProcessThreadsJson`, `BuildHuntJson`, `BuildByovdScanJson`, `BuildSnapshotJson` |
| C8 | **Only TiSubscriber is a thread-safe background**: its own `ProcessTrace` thread + `RingMutex` + const query API (`Recent`/`FilterByPid`/`Grep`/`Histogram`). | `ThreatIntelSubscriber.h` (`mutable std::mutex RingMutex`) |
| C9 | **Non-cancelable scanners**: `UserModeHunter::Scan` has no cancel token. `HuntOptions` has no stop handle. A synchronous `DeviceIoControl` cannot be canceled midway. | `UserModeHunter.h` (`Scan` signature) |
| C10 | **A direct console output path exists**: the `ScopedCommandProgress` worker writes directly to `GetStdHandle(STD_OUTPUT_HANDLE)` (`WriteConsoleTuiLineDirect`) -- bypassing the wcout capture. | `ScopedCommandProgress` |

---

## 3. Architecture Decisions

### 3.1 Transport: in-process loopback Streamable HTTP (not stdio)

**Decision**: place a **Streamable HTTP** endpoint (`http://127.0.0.1:<port>/mcp`) inside the already-running elevated controller process. **stdio is not used as the primary transport for the live process.**

Rationale:

1. **stdio is structurally unsuitable**. The MCP stdio transport by definition has *the client spawn the server as a subprocess*. But this process is (a) already running, (b) elevated, (c) holding `\\.\KnLiveDbg` exclusively (C1), and (d) keeping symbol/DbgEng state in memory. If the client launches a second `KnLiveDbg.exe`, it either fails the exclusive `CreateFileW` (C1) or becomes a separate instance with no live operator session.
2. **Claude Desktop is a GUI app, so it cannot spawn an elevated child process without UAC** -- a stdio config of the form `command: KnLiveDbg.exe` will not actually start.
3. **stdout pollution**: the REPL/scanners emit massive output to `std::wcout` (C4), and `ScopedCommandProgress` writes directly to the console handle (C10). stdio JSON-RPC must own stdout for framing, so a single stray byte breaks the session.
4. **HTTP coexists cleanly with the console**: the HTTP listener owns its own socket/thread and never touches the console. The operator REPL stays alive, preserving the human-in-the-loop (security-critical).
5. **Claude Code, Cursor, Codex, and Grok Build natively support Streamable HTTP** (see §8 below), so they connect directly without a transport shim. Claude Desktop supports remote HTTP connectors, but those connections originate in Anthropic's cloud and cannot reach this local loopback/private endpoint; its local `claude_desktop_config.json` path remains stdio. `tools/mcp-bridge.ps1` therefore exists only for Claude Desktop local MCP and legacy stdio-only clients. It pins and constrains the stateless `mcp-remote` bridge, which never touches the device and can be freely spawned.

**Implementation stack**: the HTTP server is a new addition (the current project only links the `winhttp.lib` *client*, with no server socket/pipe).
- First choice: **HTTP Server API (http.sys, `httpapi.lib`)** -- `HttpInitialize` / `HttpCreateRequestQueue` / `HttpAddUrlToUrlGroup` (`http://127.0.0.1:<port>/mcp`). This gains kernel-side URL reservation and ACL, and avoids raw socket parsing. A URL reservation (`netsh http add urlacl` or SDDL) may be required (open question §10).
- Alternative: a small WinSock listener that explicitly `bind()`s to `INADDR_LOOPBACK` -- the only external dependency is `ws2_32`, but HTTP/1.1 parsing must be hand-written.

**POST response mode**: synchronous read tools answer with `Content-Type: application/json` (single response, simplest). Tools that need elicitation/progress notifications (future writes) **must** answer with `text/event-stream` (SSE) -- because you cannot embed a server-to-client request inside a single JSON POST response (§7.4).

### 3.2 Process Model: in-process, ON/OFF by command, coexisting with the REPL

**Decision**: not a separate bridge process but a **subsystem inside `KnLiveDbg.exe`**. It shares the single device handle/symbol engine/state (C1). OFF by default; activating it via the operator console command `mcp on <port>` prints a token and an immediately-pasteable client config. `mcp off` stops it instantly.

- Create the `McpServer` object in `wmain` alongside `service/device/symbols/ai/aiState`, but keep it dormant until `mcp on`.
- When activated, spawn one HTTP listener thread. This thread **never touches the kernel directly** -- it only does HTTP validation (auth/host/origin/size) -> JSON-RPC parsing -> job creation -> push to the engine queue -> waiting on the per-job completion future.
- Shutdown path (`mcp off` / Ctrl-C / `wmain` cleanup): stop the listener -> drain the queue and cancel waiting jobs -> `SetWriteMode(false)` -> disarm write -> join the worker -> existing driver cleanup.

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

```text
[HTTP listener thread]                 [engine thread = main thread]
  validate(auth/host/origin/size)     drain loop:
  parse JSON-RPC                        wait(QueueCv) until !Queue.empty()
  build McpJob ----------- push ----->  pop (operator job first)
  future.wait_for(timeout)              if CONSOLE: ExecuteCommandWithTranscript
  serialize result <---- promise -----  if MCP: guard validation + capability dispatch + serialize
                                        set promise
```

Data structures (following the code style):

```cpp
// MCP job marshalled onto the single engine thread.
struct McpJob
{
    McpJobKind Kind;                 // Console or Mcp
    std::vector<std::wstring> Args;  // synthetic command/capability args
    std::wstring OriginalLine;
    std::promise<McpResult> Done;
    std::atomic<bool> Cancelled;
};

class EngineQueue
{
public:
    bool Push(std::shared_ptr<McpJob> job);   // bounded; false => engine busy

    std::shared_ptr<McpJob> Pop();            // operator(Console) jobs first

private:
    std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<std::shared_ptr<McpJob>> consoleJobs_;
    std::deque<std::shared_ptr<McpJob>> mcpJobs_;
    size_t maxMcpPending_ = 8;
};
```

The engine loop (replaces the existing `while(!g_StopRequested) ReadInteractiveCommandLine`):

```cpp
while (!g_StopRequested)
{
    std::shared_ptr<McpJob> job = queue.Pop(); // blocks on cv
    if (job == nullptr)
    {
        continue;
    }

    if (job->Cancelled.load())
    {
        // queued-but-cancelled: drop without touching the engine
        job->Done.set_value(McpResult::Cancelled());
        continue;
    }

    McpResult result = DispatchOnEngineThread(job, state, device, symbols /* ... */);
    job->Done.set_value(std::move(result));
}
```

### 4.2 Global rdbuf hazard and mitigation (mandatory)

`ScopedWideStreamCapture` swaps the **process-global** rdbuf of `std::wcout`/`std::wcerr` (C4). If two captures are alive at the same time, the rdbuf pointers race and the LIFO restore breaks, leaving `wcout` pointing at a freed buffer (use-after-free).

Rules (invariants):

1. **`ScopedWideStreamCapture` is created only on the engine thread.** The HTTP listener thread never creates a capture.
2. **At most 1 alive at a time.** Nesting within a single thread is allowed because the LIFO restore holds (e.g., a capability path captures once more internally). **Cross-thread concurrent capture is forbidden.**
3. In debug builds, grab the engine TID at startup and place `assert(GetCurrentThreadId() == g_EngineTid)` + a `g_CaptureDepth` singleness assert at every entry point of `DeviceClient`/`SymbolEngine` and the capture ctor/dtor. Enforce by code, not by convention.
4. **In MCP-enabled mode, switch console input to a simple line reader.** The live-rendering interactive editor (`ReadInteractiveCommandLine`) renders directly to the console/`wcout` while typing, so if it is alive concurrently with an MCP job capture, it races the global rdbuf. Therefore in MCP mode result output is handled only by the engine thread, and the console reader thread only pushes completed lines as a CONSOLE job. (Rich editing/history inline rendering is reserved for pure REPL mode.)
5. **`ScopedCommandProgress` is disabled in MCP-origin jobs** (`enabled=false`). This worker writes directly to `STD_OUTPUT_HANDLE` (C10), bypassing capture/redirection. In HTTP mode it does not corrupt framing, but it sprays MCP noise onto the operator console and would be a corruption source for a future stdio bridge.

### 4.3 Backpressure / Cancellation / Lifetime

- **One in-flight**: the engine runs only one job at a time. A long scan (UserModeHunter, pool-scan-pe, full callbacks) blocks all other MCP requests and the operator for that duration -- this is **intentional backpressure**, not to be masked by a false cancellation promise.
- **Bounded waiting queue (e.g., MCP 8)**: when full, respond with `isError:true` ("engine busy") (§7.3 -- not a JSON-RPC -32xxx).
- **Operator priority**: pop CONSOLE jobs from the queue before MCP jobs. However, an in-flight job cannot be preempted, so this does not guarantee "the operator always runs immediately" (stated honestly).
- **Cancellation (honest model)**: a cancellation notification removes **only jobs still in the queue**. A dispatched scan runs to completion -- because scanners have no stop token (C9) and `DeviceIoControl` is synchronous. We do not promise "mid-flight cancellation." To keep scans short, enforce `limit`/`count` arguments.
- **Late-result lifetime**: the `McpJob` is owned by the engine as a `shared_ptr`. Even if the worker abandons the future on timeout, the job/result storage stays alive until the engine sets the promise (never set a promise on freed memory). By the one-in-flight rule, a timeout-but-running job naturally blocks the queue (= normal backpressure, not a hang).
- **No engine-thread reentrancy**: engine-thread code never enqueue-and-waits on its own queue (self-deadlock). Only the transport thread waits on a future. nested-ai/`assistant.answer` is rejected as before, so the reentrant path is closed.

### 4.4 TiSubscriber exception -- not adopted

A "fast path" that serves `ti.query` directly from the worker via a RingMutex-protected ring read (`Recent`/`FilterByPid`/`Histogram`, C8), bypassing the engine queue, is **not adopted.** The ti capability executor can touch, beyond a ring read, PPL self-elevation (`SetProcessProtection` via the lock-free `DeviceClient`) or symbol resolution (DbgHelp), creating a race hazard; and since the RingMutex is uncontended, the queue-hop cost is negligible. **Every tool goes through the engine queue.**

---

## 5. Security Model (Most Important)

Designed on the premise of exposing an elevated kernel-RW tool to a potentially adversarial/injected LLM.

### 5.1 Network

1. **Loopback-only bind**: `127.0.0.1` + `::1` only. Never `0.0.0.0`. OFF by default, activated only via `mcp on`.
2. **Host header whitelist**: reject anything that is not `127.0.0.1` / `[::1]` / `localhost` -> blocks DNS rebinding.
3. **Origin validation**: if an Origin **exists** and is not on the whitelist, return 403. (Note: an absent Origin is a normal non-browser client, so allow it. "Reject whenever Origin exists" would break conforming clients.)
4. Loopback is not an authentication boundary (on a multi-user/RDP host, another local user can reach it). Real authentication is handled by the token.

#### 5.1.1 Opt-in network bind (`--bind <addr>`, lab only)

Practical constraint: if the lab test VM is on a **physically separate PC**, an external Claude host cannot reach a loopback-only listener. For this, provide an **explicit opt-in** network exposure -- the default does not change.

1. **The default stays loopback-only** (`BindAddress` empty): only `127.0.0.1`+`[::1]` are registered, with the strict Host whitelist applied. The safe default is preserved.
2. **`mcp on <port> --bind <addr>`**: leave the loopback URL as is and **additionally** register the requested address (`http://<addr>:<port>/mcp/`). `<addr>` is a concrete IP (e.g., `192.168.56.10`) or `0.0.0.0`/`*`/`+` for all interfaces (mapped to http.sys's strong wildcard `+`). Because http.sys reserves the non-loopback prefix, **if running as elevated/SYSTEM no separate `netsh urlacl` is needed** (same as loopback).
3. **Relax the Host check + keep the Origin defense**: in remote mode, accept an arbitrary Host (a remote client's Host is the lab IP), but **keep Origin rejection (403 if an Origin exists and is not a loopback authority)** -> the DNS-rebinding defense remains valid regardless of bind mode (non-browser MCP clients send no Origin, so they pass).
4. **The bearer token becomes the only barrier** (§5.2). Therefore on remote exposure, **allow inbound only from the client IP at the firewall** and print a console warning to use it only on a **trusted lab segment**. When binding `0.0.0.0`, the server cannot know which interface IP the client should connect to, so it prints a `<this-host-ip>` placeholder in the URL.
5. **Threat model change**: with loopback-only, only a local user on the same host could reach it, but remote exposure lets any host on the lab segment reach elevated kernel RW if it knows the token. Forbid use outside a lab/isolated network (absolutely never on a live EDR/AC box).

### 5.2 Authentication and token handling

1. Bearer tokens are **stable by default** across restarts (`%LOCALAPPDATA%\kn-live-dbg\mcp-token`, constant-time compare, 401 + close on mismatch). A fresh 256-bit token is minted only when missing or when the operator passes `--new-token`.
2. `mcp on` writes `mcp-endpoint.json` (url + token). The protected file feeds `mcp-load-env.ps1` for native HTTP clients and the **stdio bridge** (`tools/mcp-bridge.ps1`) used by Claude Desktop local MCP or legacy clients. Native client configs keep only an environment-variable reference, not the bearer token.
3. Server side: print the token source (reused/new/env/override); audit keeps request fingerprints, not the raw secret. Token and endpoint files are atomically replaced with a protected DACL granting full access only to the current user. Token persistence or endpoint persistence failure aborts MCP startup.
4. **Client-side storage is the real leak point**: do **not** paste bearer tokens into committable project configs. Prefer native HTTP with user-scope config + `${KNLIVEDBG_TOKEN}` / `bearer_token_env_var` and `mcp-load-env.ps1`. Use the bridge only for Claude Desktop local MCP or a legacy stdio-only client. Never commit secrets to git.
5. Optional: bind the token to the loopback peer PID via `GetExtendedTcpTable` (defense-in-depth, though vulnerable to reconnect/PID reuse).

### 5.3 Two modes: read-only (default) vs Lab write mode (updated by decision §10-Q1)

MCP **selects one of two modes via an explicit flag at startup**. Because the analysis box is an isolated lab/VM (decision §10-Q2), opening writes for analysis fidelity is justified. But "opened" does not mean "safety rails removed" -- **the frictionless (non-interactive) automatic rails are retained** (already-existing code, zero cost, protects analysis).

#### 5.3.1 Read-only mode (default, non-lab deployment)

- `mcp on` (no flags): does not register write/mutation tools and **disarms the kernel flag itself** via `DeviceClient.SetWriteMode(false)`. Because in C5 the handle `WriteEnabled` is TRUE by default and the kernel-side gate is only that flag + a public constant (`KNDBG_WRITE_ACK_MAGIC`), while disarmed **the kernel itself** rejects write/PPL IOCTLs with `STATUS_ACCESS_DENIED`. The safe default for any non-lab deployment.

#### 5.3.2 Lab write mode (`mcp on <port> --allow-write`)

Activated only by an explicit flag. When activated:

1. **Register the full write tool surface** (§6.1 write namespace). `WriteEnabled` stays TRUE for the session (no need to momentarily toggle write per operation -- since write is a first-class citizen). PPL allows an **arbitrary target** via `process.set_protection` (lab); self-PPL being that special case, the problem of `IOCTL_KNDBG_SET_PROCESS_PROTECTION`/write-virtual sharing the same `WriteEnabled` naturally disappears.
2. **Keep the frictionless automatic safety rails for every write** -- reuse the existing `ai write confirm` machinery but drop only the interactive confirmation: (1) preflight read (current bytes) -> (2) emit backup/restore commands -> (3) write -> (4) post-write read-back **verify-diff** -> (5) write-audit JSONL (`WriteCommandAuditEvent`). These rails prevent **the LLM from silently breaking the live state under analysis and thereby invalidating the analysis itself**, and make every mutation recoverable and auditable.
3. **Typed write tools only** (the no-raw-command-string rule still holds). The model calls via validated typed arguments like `memory.write_virtual {address, bytes}`, not a raw string like `eb <addr> <bytes>` -- closing the injection/chaining/parsing surface and letting the model call more precisely.
4. **Elicitation OFF by default** (lab frictionless). Per-write human confirmation (SSE elicitation, §7.4) can be turned on with `mcp write-confirm on`.

#### 5.3.3 Residual risks and recommendations for Lab write mode (must be understood)

- **Confused deputy (the most realistic threat)**: malware/attacker-controlled kernel data under analysis (process names, module paths, memory contents) can flow into the model context and, via prompt injection, **induce destructive writes**. Typed arguments, value validation, backup/verify, and audit make this recoverable/traceable but **do not fully prevent it**. Opening writes in the same session while reading untrusted memory is an inherent risk.
- **Recommendations**: (1) take a **VM checkpoint/snapshot** before a write session (since it is an isolated VM, instant rollback -- the strongest lab safety net). (2) Capture an analysis baseline with `!snapshot` before writing. (3) Keep loopback + token + single-session pin as is. (4) If unattended trust is a concern, use `mcp write-confirm on`.
- **Raw `kd`/DbgEng passthrough remains separately closed** (§5.4-3). The typed write tools already satisfy the "write" requirement, and a raw command is hang/crash/arbitrary-execution, a far larger door. Decide separately if needed.
- TI **subscription start** (`!ti start`) remains console-only due to the side effect of creating an ETW session/file; `ti.query` only reads the existing ring. If unattended lab TI is desired, `ti.subscribe` can be added under write mode.

> Recommended driver hardening (follow-up, ABI bump): for read-only mode correctness, the current structure where `SetWriteMode(false)` closes both PPL and write remains valid. However, if you later want "read-only + self-PPL only" again, add a `WriteEnabled`-independent gate to `IOCTL_KNDBG_SET_PROCESS_PROTECTION`.

### 5.4 Input guards (sealing prompt injection)

1. Every `tools/call` passes the existing guards **as is**: `IsSupportedAiCapabilityTool` (tool allowlist) + `ValidateAiCapabilityToolArgKeys` (per-tool argument-key whitelist) + per-value `ValidateAiCapabilityScalarText` + `ContainsUnsafeAiCommandCharacters` (rejecting `;`/CR/LF/control chars) + scope enum normalization + `IsHelpToken` rejection.
2. **Never accept a raw command string over MCP (including writes).** Only a `tool` + typed args. In read-only mode, the worst an injected model can do is "select another read scanner with in-range arguments." In Lab write mode, write tools are reachable but go through **typed arguments + value validation + backup/verify/audit**, and raw kd/session-change/unload are not exposed in either mode.
3. **The no-raw-command-passthrough rule still holds** (`kd`/arbitrary `u`/`uf` strings). Lab write mode's write tools are added as **typed new primitives** (`memory.write_virtual` etc., each with its own value-validator), but no path that accepts arbitrary command strings is opened.
4. Tool output (process names, module paths, WNF/ETW strings, attacker-controlled memory) is merely **data** and is never reinterpreted as a command.

### 5.5 Egress redaction

Both the text captured by `ScopedWideStreamCapture` and the serialized JSON are redacted with `MaybeRedactTranscriptText` **before leaving the process (before HTTP UTF-8 conversion)**. The external model is treated as a potentially adversarial principal, and we do not hand over uncurated raw kernel addresses/symbols/paths (KASLR / symbol exposure).

### 5.6 Auditing (mandatory, not optional)

One append-only JSONL record per MCP request: timestamp, peer (loopback port/PID), session id, tool, **redacted args**, decision (allow/deny + which guard fired), result byte size, write-arm state. (A result hash alone is insufficient -- you need size + a redacted snippet of what left.) Expose `kn://audit/tail` as a read-only resource so a monitoring client can observe model behavior.

### 5.7 Kill switch

`mcp off` / Ctrl-C (`ConsoleHandler`) does: stop the listener -> drain the queue + cancel waiting jobs -> `SetWriteMode(false)` (disarm the kernel flag) -> disarm write -> join the worker -> existing driver cleanup. Ensures an abnormal exit does not leave the handle write-enabled.

### 5.8 Session pin

Issue an `Mcp-Session-Id` in the `InitializeResult`, then require it on every subsequent request (400 if absent). **A second concurrent `initialize` is rejected** (single engine / single device -> single MCP session). This keeps the write-arm/elicitation state and audit attribution unambiguous, and prevents two LLMs from interleaving IOCTLs.

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

### 7.4 Token budget / pagination / large payloads

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
# Recommended: native Streamable HTTP. Keep the token in the environment.
# `mcp client-setup claude-code` prints the env-indirected user-scope form.
claude mcp add --transport http knlivedbg http://127.0.0.1:51766/mcp \
  --header "Authorization: Bearer YOUR_TOKEN"

# Remote (lab VM on a separate PC): on the lab host, start it with `mcp on 51766 --bind 192.168.56.10`,
# then connect from the client PC to the lab IP. Use the exact url/token printed by `mcp on`.
claude mcp add --transport http knlivedbg http://192.168.56.10:51766/mcp \
  --header "Authorization: Bearer YOUR_TOKEN"

# Legacy fallback only (does not directly expose the live process)
claude mcp add --transport stdio knlivedbg-bridge -- \
  npx -y mcp-remote@0.1.38 http://127.0.0.1:51766/mcp --allow-http --transport http-only --silent --header "Authorization: Bearer YOUR_TOKEN"
```

On a remote bind (§5.1.1): since the bearer token is the only barrier, **allow inbound only from the client IP at the firewall** and use it only on a trusted lab segment. `--bind 0.0.0.0` opens on all interfaces, so specify a concrete IP if possible.

`.mcp.json` (but with the token via env indirection -- no plaintext in a committable file):

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

Useful knobs: per-server `timeout` (ms, raise it for slow scans -- not extended by progress notifications), `headersHelper` (rotating token at connect time), `alwaysLoad`.

### 8.3 Claude Desktop

Claude Desktop's remote connectors support Streamable HTTP, but Claude connects to them from Anthropic's cloud. They cannot reach `127.0.0.1` or a private lab address, and Claude Desktop does not connect to a remote HTTP server declared directly in `claude_desktop_config.json`. For this local KnLiveDbg endpoint, merge the stdio config printed by `mcp client-setup claude-desktop`; it launches `tools/mcp-bridge.ps1`, which reads the protected endpoint once at process startup and forwards stdio to HTTP. Fully restart Desktop after editing or after changing the endpoint URL/token.

Do not expose the kernel endpoint publicly merely to use a Claude remote connector. Keep it on loopback and use the local bridge. This is the only current first-class client path where the bridge is preferred.

---

## 9. Phased Implementation Plan

| Phase | Content | Deliverable (smallest ship) |
|-------|------|----------------------|
| **0. Plumbing** | http.sys listener (127.0.0.1 bind), `mcp on/off` console command, token issuance/printing, Host/Origin validation, `Mcp-Session-Id`/`MCP-Protocol-Version`, JSON-RPC framing (initialize/tools/list/tools/call/resources/*/prompts/*). Expose only `kn://capabilities` + `kn://session/info` (cached). | The client can connect, authenticate, tools/list, and query the session. Zero device access. Proves transport/auth/session before kernel exposure. |
| **1. Read catalog (Tier A)** | Engine queue + console-line-as-job drain loop, 18 read-only tools reusing `ExecuteAiCapabilityPlan` + `ScopedWideStreamCapture` text. origin="mcp" audit. Default read-only mode = `SetWriteMode(false)` disarmed. | The external LLM drives the full read forensics surface under guards/audit. **The first ship with real value.** |
| **2. Structured JSON (Tier B)** | Write/reuse a `Build*Json` per scanner -> `structuredContent` + outputSchema. offset/limit pagination. Unified surrogate-safe escaper. | Promote text->structured per tool with no contract change. |
| **3. Resources + prompts** | `kn://modules`/`drivers`/`snapshot`/`ti/stats`/`audit/tail` + 7 playbook prompts. Large payloads via `resource_link`. | Model self-grounding + slash-command workflows. |
| **4. Lab write mode** | Register the write namespace (§6.1.1) via `mcp on --allow-write`. `WriteEnabled=TRUE` for the session. Automatic preflight/backup/verify-diff/audit on every write (no interactive confirmation). `process.set_protection` arbitrary target. `dump.*` output root restriction. Optional per-write SSE elicitation via `mcp write-confirm on`. | Isolated lab/VM only (decision §10-Q1/Q2). OFF by default, not registered without `--allow-write`. VM snapshot recommended before writing. |

Each stage can ship independently, and no later stage weakens the Phase-0 security posture.

---

## 10. Finalized Decisions (2026-06-24)

The 6 open items of the §3 initial design are finalized as below.

1. **Server stack -> http.sys (`httpapi.lib`)**. A hand-rolled HTTP parser in an elevated process is a top-priority EoP surface, so offload to the kernel-audited http.sys. **Administrator/SYSTEM needs no separate `netsh urlacl` reservation for `HttpAddUrlToUrlGroup`** -> resolves the URL ACL concern. Loopback-only prefix `http://127.0.0.1:<port>/mcp` + `http://[::1]:<port>/mcp`. WinSock rejected.
2. **Port -> fixed default + override**. A loopback port scan is trivially available -> the security benefit of randomization is approximately 0 while the cost of breaking the client config every session is large (real authentication is the token). A fixed default in the private range (e.g., `51766`) + `mcp on <port>` override.
3. **Write exposure -> full open in Lab write mode (Q1, updated 2026-06-24)**. Since it is an isolated lab/VM (Q2), open the full typed write tool set (§6.1.1) via `mcp on --allow-write` for analysis fidelity. But "open != safety rails removed" -- keep frictionless automatic preflight/backup/verify-diff/audit (§5.3.2) and continue to forbid raw kd / arbitrary commands / hidden writes. The non-lab default is read-only + kernel flag disarmed (§5.3.1). VM snapshot recommended before writing (§5.3.3). *(Replaces the earlier "PPL exception only" decision.)*
4. **Client token -> static (newly issued per `mcp on`) + `${KNLIVEDBG_TOKEN}` env indirection**, with `headersHelper` rotation optional. No project-scope commit. (Works on both Claude Code/Desktop + minimal setup; new per session + idle TTL gives a rotation effect.)
5. **Execution environment -> centered on an isolated analysis VM (Q2)**. Since inbound loopback listener exposure is moot, http.sys loopback alone is sufficient with no additional transport layer such as a named pipe. (If a need arises to use it on a live EDR/AC box, review the named-pipe option from the backlog.)
6. **Timeouts/caps -> adopt starting defaults, tune by measurement on a live VM**. Engine wait 30s (split or bound scans that exceed it; client timeout alone cannot extend it), MCP waiting queue 8, per-result 64KB/200 records, raw read 1MB (driver cap), forced `limit` on hunt/pool-scan. All exposed in config.

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

## 11.1 Implementation Status (v0 scaffold, feature/mcp-server)

An initial scaffold that implements Phase 0~1 + the write namespace (§6.1.1) all at once is in place.

New files:
- `user/McpJson.h` -- header-only, surrogate-safe JSON escape / UTF-8 conversion / top-level value extraction (transport layer only, no dependency on main.cpp statics).
- `user/McpServer.h` / `user/McpServer.cpp` -- http.sys loopback listener (127.0.0.1 + [::1], `/mcp`), overlapped receive + stop event, bearer token (32 bytes per `mcp on`) constant-time comparison, Host/Origin validation, single `Mcp-Session-Id` pin, JSON-RPC (initialize/ping/tools.list/tools.call/resources.list+read/prompts.list+get/notifications), static tool/resource/prompt catalog, bounded serial job queue.

main.cpp integration:
- One global `static McpServer g_McpServer;`.
- `HandleMcpCommand` (`mcp on [port] [--allow-write]` / `off` / `status`) -- `HandleCommand` dispatch + `CommandRegistry` registration.
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
| `byovd.scan` | `byovd scan /no-update` | `BuildByovdScanJson` (existing) | `/no-update` forced (blocks network/subprocess) |
| `pool.scan_pe` | `pool-scan-pe` | `BuildPoolPeJson` (`.pool-pe.v1`) | args tag/limit/suspicious; `/dump` not exposed |
| `payload.inspect` | `!payload` | `BuildPayloadTraceJson` (`.payload.v1`) | hook-to-body; args address/va/symbol |
| `payload.scan` | `!payload scan` | `BuildPayloadTraceJson` (`.payload.v1`) | hook-to-body; args limit |
| `mapper.list` | `!mapper` | `BuildMapperJson` (`.mapper.v1`) | bookkeeping remnants; leftover=0 is ledger-clean; args scope/limit |
| `kpage.list` | `!kpage` | `BuildOrphanKernelPageJson` (`.kpage.v1`) | orphan pages; args deep/wx/pe/limit; deep is not default |
| `minifilter.list` | `!minifilter` | `BuildMinifilterIrpJson` (`.minifilter.v1`) | args filter/name |
| `minifilter.set_irp` | `!minifilter disable/enable` | `BuildMinifilterIrpChangeJson` (`.minifilter-irp.v1`) or `BuildMinifilterIrpBatchJson` (`.minifilter-irp-batch.v1`) | WRITE; action enable/disable; `irp=all` batches |
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

## 12. Design Core 7-line Summary

1. **In-process loopback Streamable HTTP** (not stdio), OFF by default, activated via `mcp on`.
2. Marshal all MCP requests onto a **single engine thread** via a serial queue; the HTTP thread never touches the kernel.
3. `ScopedWideStreamCapture` is **engine-thread-only, one at a time** (prevents the global rdbuf UAF).
4. **Two modes** -- read-only by default (`SetWriteMode(false)` disarms the kernel flag) / **Lab write mode** (`--allow-write`, isolated VM) fully opens typed write tools but keeps automatic backup/verify/audit, forbidding raw kd / hidden writes.
5. Every `tools/call` passes the **existing catalog + guards**, no raw commands / new primitives, egress redaction.
6. Results mirror `structuredContent` + identical JSON text, errors are `isError:true`, large payloads via `resource_link` + pagination.
7. **Cancellation is queue-stage only** (in-flight scans cannot be preempted -- honest), single session pin, mandatory audit, kill switch disarms down to the kernel.
