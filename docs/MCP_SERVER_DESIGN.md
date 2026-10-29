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
loading a driver. `--self-test mcp-http` separately exercises the loopback
transport and requires HTTP.sys registration rights. Run network fixtures
sequentially. Live tool behavior, write verification and host cleanup require
the [manual checklist](MANUAL_TEST_CHECKLIST.md); parser checks do not establish
live kernel compatibility.
