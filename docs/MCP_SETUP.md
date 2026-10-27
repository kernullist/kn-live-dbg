# MCP setup

[한국어](MCP_SETUP.ko.md) · [Tool catalog](MCP_TOOL_REFERENCE.md) · [Design](MCP_SERVER_DESIGN.md)

KnLiveDbg hosts MCP inside the elevated controller on the analysis target.
Clients connect to HTTP `/mcp` with a session password. The default bind is all
interfaces on **51766**; `--loopback` limits it to the local machine.
The server advertises protocol **2025-06-18** and server version **0.1.0**;
these are independent of the application release version.

## Start and stop

Keep the complete release bundle on the target, with a loadable matching driver
and runtime DLLs. See [build/start prerequisites](BUILD_AND_RELEASE.md).
Run the console elevated and enter:

```text
mcp on --loopback
```

For a separate lab client, `mcp on` binds all adapters; select a reachable target
IP from the startup output. The grammar is:

```text
mcp on [port] [--allow-write] [--loopback] [--bind <addr>]
mcp status
mcp off
```

`--bind=<addr>` is also accepted. Ports are decimal 1–65535. Duplicate/conflicting
options and missing values are rejected before the password prompt. MCP and
`remote on` cannot listen simultaneously.

Type the temporary password twice. During the MCP engine loop the local prompt
accepts **`off`** and **`status`**; the full REPL resumes after `off`. Each start
requires a new session password. Active endpoint/bridge files can contain session
credentials and are protected for the current user; do not distribute them.

## Connect a client

Use the URL and header printed by the current session:

```text
URL: http://<target-ip>:51766/mcp
Authorization: Bearer <session-password>
```

Prefer a client's native HTTP transport. KnLiveDbg generates client snippets
under `%LOCALAPPDATA%\kn-live-dbg\clients\` for supported clients. Use those from
a separate shell while the engine loop runs. `mcp client-setup` prints saved
setup outside that loop; its supported selectors are shown by help.

For same-machine stdio-only clients, `tools/mcp-bridge.ps1` is a compatibility
bridge. The generated `mcp-load-env.ps1` helper reads the active endpoint and
sets `KNLIVEDBG_TOKEN`. Renew the endpoint/password after restarting the server.
Client configuration formats can change; the live URL, bearer header and MCP
handshake are the server contract. Old client-specific configuration examples
are not maintained as a second copy of each client's documentation.

The transport is cleartext HTTP, including credentials and returned memory.
Use an isolated lab path and scope any required inbound firewall rule to the
intended client. Loopback is sufficient for a same-machine client. MCP does not
provide TLS, arbitrary shell execution, raw `kd`, or an arbitrary command tool.

## Write policy

Default MCP mode omits write tools and disarms the kernel write gate on engine
entry. `mcp on --allow-write` exposes the typed write tools and enables the gate.
`ti.subscribe start/stop` also requires that mode. It does not make unsupported
external callback mutation available; callback controls only manage the owned
cooperative fixture's supported CREATE bodies.

There is no per-write confirmation dialog or `mcp write-confirm` command.
Recognized writes use the dispatcher's preflight/backup/verification path and
audit; this is not a transaction or universal rollback guarantee. After `off`,
the REPL returns to its default **write-on** mode. Use `write off` if needed.

## Results, timeout and audit

Fetch `tools/list`, `resources/list` and `prompts/list` rather than assuming a
catalog from an older release. Argument names/types and required fields are in
the [tool reference](MCP_TOOL_REFERENCE.md). Some tools return JSON and others
text. Inspect error and coverage fields before interpreting an empty result.

The engine admits at most eight pending jobs and waits up to 30 seconds for a
response. A queued timeout can cancel before execution. A timeout after dispatch
means the operation may continue and its outcome is unknown to the client;
inspect state before retrying a mutation. MCP cancellation notifications do not
cancel already dispatched work.

The automatic request audit is independent of `ai audit` and is written under
`<exe-dir>\.kn-live-dbg\mcp-audit-<port>.jsonl`. It records decisions, results and
bounded argument text. It is separate from the write-audit tail resource.

## Verify and troubleshoot

1. Confirm the correct current URL/password and network path. HTTP 401 indicates
   authentication failure; a new start needs a new session.
2. Initialize the protocol and retain `Mcp-Session-Id` for subsequent requests.
3. Read `kn://session/info` and `kn://session/symbols`, then call a simple read
   such as `process.find`. Missing driver/symbol coverage is not a healthy empty scan.
4. Check `writes-disabled`, argument-validation errors, queue/outcome messages
   and the audit separately. Do not fix a read failure by automatically enabling writes.
5. Run `--self-test mcp-tools` without a driver. The separate `--self-test mcp-http`
   requires HTTP.sys registration rights; see the [test checklist](MANUAL_TEST_CHECKLIST.md).
