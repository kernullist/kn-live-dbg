# MCP implementation

[한국어](MCP_SERVER_DESIGN.ko.md) · [Setup](MCP_SETUP.md) · [Catalog](MCP_TOOL_REFERENCE.md)

This describes the current in-process implementation, not the original phased
proposal. `user/McpServer.cpp` owns HTTP.sys, authentication, JSON-RPC framing,
catalogs and a job queue. `RunMcpEngineLoop` / `DispatchMcpRequest` in
`user/main.cpp` own kernel/symbol execution and result construction.

## Execution boundary

```text
HTTP request -> bounded body / auth / session / JSON validation
             -> typed catalog validation -> FIFO -> main engine
             -> result promise -> HTTP response
```

The listener does not call DeviceClient or DbgHelp directly. The engine serializes
work and owns stream capture. While active, the console is control-only (`off`,
`status`). MCP and remote have distinct queues and cannot listen together; there
is no shared priority EngineQueue.

The queue admits at most eight pending jobs. A 30-second response wait can end
before execution, removing the queued job, or after dispatch, reporting unknown
outcome. Running calls are not rolled back. Stop cancels queued work and joins
the listener through the control/engine lifecycle. Cancellation notifications
do not implement general operation cancellation.

Each admitted engine job receives a random 128-bit `operation_id`, independent
of the JSON-RPC request ID. The private `kn.mcp_operation.v1` metadata travels
in tool result `_meta["knlivedbg/operation"]` and an additional text content
item; the original `structuredContent` and first text item are preserved.
Live resource responses carry the same `_meta`; resource errors put the metadata
in `error.data`. The request audit also records the response-time snapshot.
`operations.get {"operation_id":"<returned ID>"}` reads the ledger on the
listener, without waiting for the engine or submitting another job.

States are `queued`, `running`, `cancelled_before_execution`, `succeeded`,
`failed` and `unknown_outcome`. Timeout after dispatch keeps the record active
until the engine returns. An unhandled engine exception ends the operation
with `unknown_outcome`. `operation_finished` includes pre-dispatch cancellation;
`engine_finished` requires an actual dispatch. `succeeded`/`failed` describe
the engine's returned error flag, not independently verified target effects.
Timestamps are decimal-string collector boot ticks, not wall time or target time.

The ledger retains at most 256 metadata records, evicts the oldest finished
record first, and rejects admission if every slot is active. It does not retain
result payloads. Restart clears it; a new initialization on the same running
server does not. Lookup uses the existing shared server password/session, with
no additional per-principal isolation. `not_retained` establishes no outcome.
If the client disconnects before receiving an ID, this interface cannot recover
that job by request ID. There is no automatic retry, idempotent resubmission,
rollback, running-job cancellation, durable journal or standard MCP Tasks API.
The separate remote protocol has no operation lookup adapter yet.

## Transport and permissions

- HTTP `/mcp`, default all-interface port 51766, optional loopback/concrete bind.
  No TLS. MCP protocol 2025-06-18; server identity knlivedbg/0.1.0.
- Session password as a bearer credential, followed by `Mcp-Session-Id` after
  initialization. Secret-bearing helper files use a protected current-user DACL
  and atomic replacement. They are session artifacts, not reusable credentials.
- Read-only mode hides write tools and disarms the kernel gate. `--allow-write`
  enables typed mutations. `ti.subscribe start/stop` also requires it despite
  being an action on a read-catalog entry.
- No raw console/kd tool. Callback mutation remains limited to the cooperative
  fixture; arbitrary PID process-protection control is a separate write tool.
- Current main requires a confirmed kernel write-mode transition before engine
  dispatch. Returning to the local REPL requests write-off; failures report an
  unconfirmed state and never automatically enable writes.

## Parsing and results

Request bodies are capped at 1 MiB. Failed/incomplete bodies return HTTP 400 and
oversized bodies HTTP 413, with JSON-RPC parse errors. Malformed JSON can return
HTTP 200 with a JSON-RPC error. Parsing rejects trailing content, duplicate
decoded keys, invalid UTF-8 and nesting beyond 64. Envelopes and argument schemas
are validated before dispatch; numeric values remain strings where advertised.

Transport errors and tool-result errors are distinct. Some tools return
structured content, others text. Eight resources and seven prompts supplement
the tool catalog. The automatic request audit is separate from write auditing.

Uniform pagination/output schemas, SSE progress, per-write elicitation, and
strict protocol-version header validation are not implemented. Do not advertise
those as current guarantees. The outstanding work is in [FEATURE_PLAN.md](FEATURE_PLAN.md).

## Validation

`--self-test mcp-tools` checks catalog/validation/dispatch contracts without
loading a driver. `tools/validate-mcp-operation.ps1 -Sanitize` checks ledger
retention and timeout/completion races with an independent JSON oracle.
`--self-test mcp-http` separately exercises the loopback
transport and requires HTTP.sys registration rights. Run network fixtures
sequentially; the synthetic operation test deliberately waits for the 30-second
response timeout, then queries while its fake engine is blocked and after its
late completion. Live tool behavior, write verification and host cleanup require
the [manual checklist](MANUAL_TEST_CHECKLIST.md); parser checks do not establish
live kernel compatibility.
