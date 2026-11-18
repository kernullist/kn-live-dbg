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
mcp on [port] [--observe [--principal <fingerprint> <source>]... [--journal <directory>] | --allow-write] [--loopback] [--bind <addr>]
mcp status
mcp off
```

`--bind=<addr>` is also accepted. Ports are decimal 1–65535. Duplicate/conflicting
options and missing values are rejected before the password prompt. MCP and
`remote on` cannot listen simultaneously.

When a shared-password listener starts, type the temporary password twice.
During the MCP engine loop the local prompt accepts **`off`** and **`status`**.
The full REPL resumes after `off`. Active shared-mode endpoint files can contain
session credentials and have access restricted to the current user.

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

## Give each client one retained source

In the PowerShell process that will launch each client, generate its bearer and
print the SHA-256 fingerprint for the operator. Keep that process open. To reuse
the same grant after restarting the client, restore its bearer from the client's
secret store into `KNLIVEDBG_TOKEN`.

```powershell
$clientBytes = New-Object byte[] 32
$clientRng = [Security.Cryptography.RandomNumberGenerator]::Create()
$clientHash = [Security.Cryptography.SHA256]::Create()
try {
    $clientRng.GetBytes($clientBytes)
    $env:KNLIVEDBG_TOKEN = [BitConverter]::ToString($clientBytes).Replace('-', '').ToLowerInvariant()
    $clientAscii = [Text.Encoding]::ASCII.GetBytes($env:KNLIVEDBG_TOKEN)
    [BitConverter]::ToString($clientHash.ComputeHash($clientAscii)).Replace('-', '').ToLowerInvariant()
} finally {
    $clientHash.Dispose()
    $clientRng.Dispose()
}
```

The operator enters the printed fingerprints at the debugger prompt. For
example, `mcp on --observe --principal <first-fingerprint> ti --principal <second-fingerprint> snapshot`
grants each bearer the corresponding case-sensitive `TimelineEvent.Source`.
Up to 16 distinct fingerprints can each receive one source. Labels start with
an ASCII letter or digit and accept letters, digits, dots, underscores and
hyphens up to 64 characters. Use labels from the retained timeline on this controller.

Connect on loopback with the client's bearer. Read `evidence_source` and
`observe_budget` from `kn://capabilities`, then call `timeline.query`.
Omitting `source` selects the granted label. The local endpoint descriptor
contains connection details and empty credential fields. The bridge and native
client setup read the bearer from the client process environment.

For recovery, add `--journal <directory>` and enter a separate operator unlock
password. Reopen that directory in source-scoped mode with the same Windows
account and unlock password. A client needs its original bearer and source
grant to read its receipts. [Source-scoped observation](MCP_SERVER_DESIGN.md#source-scoped-observation)

## Write policy

On current main, enter `mcp on --observe` to share retained timeline queries
and status with a local client. The server selects loopback and checks the
scope before admitting work. Confirm `scope=observe` in `mcp status` or read
`kn://capabilities`. A client can call `timeline.query` with
`{"limit":"10","order":"newest"}`. Changing scope requires stopping the listener.
Read `observe_budget` in `kn://capabilities` for the remaining calls, records
and payload bytes. Reinitializing a client keeps the same budget.
[Observe listener budget](MCP_SERVER_DESIGN.md#observe-listener-budget)

To keep operation receipts across restarts, enter
`mcp on --observe --journal "case operations"` under an existing local parent.
Use a new directory the first time. Keep the returned operation ID, then reopen
the same directory with the same Windows account and listener password to query
it after a restart. [Private operation recovery](MCP_SERVER_DESIGN.md#private-operation-recovery)

Default MCP mode omits write tools and disarms the kernel write gate on engine
entry. `mcp on --allow-write` exposes the typed write tools and enables the gate.
`ti.subscribe start/stop` also requires that mode. It does not make unsupported
external callback mutation available; callback controls only manage the owned
cooperative fixture's supported CREATE bodies.

There is no per-write confirmation dialog or `mcp write-confirm` command.
Recognized writes use the dispatcher's preflight/backup/verification path and
audit; this is not a transaction or universal rollback guarantee. After `off`,
current main requests **write-off** before returning to the REPL. A failed
transition is reported as unconfirmed. Use `write on` explicitly for lab changes.

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

Retain the returned `_meta["knlivedbg/operation"].operation_id` (also supplied
as an additional tool text item). Call `operations.get` with that string to
query the engine's eventual state without repeating the original request.
Lookup works while the engine is busy, subject to the serial listener finishing
its current response wait. Only the newest retained metadata is available:
256 records, finished records evicted first in memory. The default ledger
clears on restart. An explicitly opened observe journal retains the last 256 admissions.
`not_retained` does not imply success or failure. This API retains no result
payload and does not prove target effects, provide rollback or make repeated
mutations idempotent. See the [operation contract](MCP_SERVER_DESIGN.md#execution-boundary).

The automatic request audit is independent of `ai audit` and is written under
`<exe-dir>\.kn-live-dbg\mcp-audit-<port>.jsonl`. It records decisions, results and
bounded argument text in legacy sessions. Observe audit entries contain
decision and operation metadata and omit argument values and protocol session IDs.

## Verify and troubleshoot

1. Confirm the correct current URL/password and network path. HTTP 401 indicates
   authentication failure; a new start needs a new session.
2. Initialize the protocol and retain `Mcp-Session-Id` for subsequent requests.
3. In observe scope, read `kn://capabilities` and call `timeline.status`.
   In legacy scope, read `kn://session/info` and `kn://session/symbols`, then call a simple read
   such as `process.find`. Missing driver/symbol coverage is not a healthy empty scan.
4. Check `writes-disabled`, argument-validation errors, queue/outcome messages
   and the audit separately. Do not fix a read failure by automatically enabling writes.
5. Run `--self-test mcp-tools` without a driver. The separate `--self-test mcp-http`
   requires HTTP.sys registration rights; see the [test checklist](MANUAL_TEST_CHECKLIST.md).
