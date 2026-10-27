# Remote operator implementation

[Operator setup](REMOTE_SETUP.md) · [한국어 설정](REMOTE_SETUP.ko.md)

The remote session is a thin human console on PC B. The elevated controller on
PC A owns the driver, symbols, collectors, evidence paths and engine. B runs the
same EXE with `--connect <ipv4>:<port>` before local elevation/driver startup.
It does not install a service. This transport is separate from MCP and DbgEng KD.

## Components and flow

| Source | Responsibility |
| --- | --- |
| `user/RemoteProtocol.h` | KNR1 framing, parsing and bounded socket operations |
| `user/RemoteServer.*` | Listener, password/session, FIFO and audit |
| `user/RemoteClient.cpp` | Prompt, local completion, output and connection state |
| `user/RemoteFirewall.*` | Owned inbound firewall rule lifecycle |
| `user/main.cpp` | Engine dispatch and execution-origin restrictions |

Network threads enqueue work; the main engine executes it serially. MCP and
remote have separate FIFOs and mutually exclusive listeners. A shared engine
queue or concurrent DbgHelp execution is not part of this implementation.

## Wire and resource limits

KNR1 is cleartext TCP with an eight-byte magic/length header and UTF-8 JSON.
The default is all IPv4 interfaces on port **51767**. The session password is
5–128 printable ASCII characters without spaces and is not persisted.
There is one authenticated operator session, with peer restrictions available.

| Limit | Current value |
| --- | --- |
| Frame payload | 1 MiB |
| Command | 8,192 characters |
| Result chunk | 64 KiB |
| Inline output truncation | 8 MiB |
| Pending jobs | 4 |
| Heartbeat / dead peer | 15 / 60 seconds |
| Authentication deadline | 10 seconds |

Bounded framing rejects malformed/oversized input. Result framing accounts for
JSON escape expansion. Partial/failed sends close the connection instead of
restarting a half-written frame as a new message. The client strips VT coloring
when stdout is redirected and shares local completion tables with the TUI.

## Execution and shutdown

Commands run under remote-origin policy. Native inspection and explicit writes
follow A's write mode. Address-only edit prompts require inline values remotely.
Session takeover, arbitrary backend/control operations, nested listeners and
shutdown commands are restricted; see the operator guide's supported/blocked
table. A retains local stop/status/write-off controls.

Disconnect/stop removes queued requests that have not begun. An already running
command may complete; a lost response does not mean rollback. Do not blindly
retry a write after disconnection. State and output files belong to A.
Listener shutdown closes sockets, rejects queued work, joins its threads and
removes only its owned firewall rule.

The transport has no encryption or durable operation-result lookup. Password
authentication is not confidentiality. Use the documented isolated lab setup;
future transport/operation work belongs in [FEATURE_PLAN.md](FEATURE_PLAN.md).

## Validation

`--self-test remote-protocol` and `--self-test connect-argv` exercise framing,
authentication/queue/disconnect behavior and startup argument handling without
loading the main driver. Remote loopback fixtures bind port 51767 and must not
run concurrently. Live writes and service/collector teardown require the
[manual checklist](MANUAL_TEST_CHECKLIST.md), not just parser success.
