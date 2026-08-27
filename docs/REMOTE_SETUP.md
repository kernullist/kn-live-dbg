> Korean version: [REMOTE_SETUP.ko.md](./REMOTE_SETUP.ko.md)

# KnLiveDbg Remote Operator Session Setup

This is the **operator procedure** for using an already-running elevated `KnLiveDbg.exe` on PC A from another machine on the same LAN (PC B). Design, protocol, and threat model live in [`REMOTE_OPERATOR_SESSION.md`](./REMOTE_OPERATOR_SESSION.md).

- Transport: plain TCP, `KNR1` length-prefixed JSON. **Cleartext. Isolated lab only.**
- Default listen: **all IPv4 interfaces**, port **51767**
- Auth: a **session password** typed at `remote on` (5-128 printable ASCII, no spaces). Not written to disk.
- Client: the same `KnLiveDbg.exe`, started as `--connect <ipv4>:<port>`. No driver, no elevation, no mutex.

This is **not** `kdinit /remote`. That attaches DbgEng to a KD connection string. This session is a thin `knkd>` on B that submits native commands to A's engine.

This is **not** MCP. MCP (`mcp on`, port 51766) is the LLM tool catalog. `mcp on` and `remote on` cannot run at the same time (listen XOR).

---

## 1. Where to run what

| Role | Machine | Command |
|------|---------|---------|
| Engine + driver | **PC A** (game box / analysis target) | Elevated `KnLiveDbg.exe`, then `knkd> remote on` |
| Thin TUI | **PC B** (analyst workstation) | `KnLiveDbg.exe --connect <A-ipv4>:51767` |

Copy the EXE to B. B never opens `\\.\KnLiveDbg` and never installs the service. Symbols, dumps, TI, timeline, cloak identity, and the exclusive device handle stay on A.

---

## 2. Start the listener (PC A)

A must already be at the `knkd>` prompt with the driver loaded.

```text
knkd> remote on
Set a temporary remote password for this session.
Clients connect with IP, port, and this password.
Remote password: *****
Confirm password: *****
```

Bare `remote on` binds `0.0.0.0:51767`. Other PCs on the LAN can connect. The process adds an inbound Windows Firewall rule named `knlivedbg-remote` after a successful bind (skipped for loopback).

Password rules:

- Type it twice. Mismatch aborts `remote on`.
- **5-128** printable ASCII (`0x21`-`0x7e`), no spaces.
- Session only. `remote off` / process exit wipe it. There is no `remote-endpoint.json`.

Example banner:

```text
[remote] listen 0.0.0.0:51767 cleartext=true
[remote] warning: cleartext kernel-command traffic on the LAN
  127.0.0.1        loopback
  192.168.1.10     Ethernet
  client: KnLiveDbg.exe --connect <ipv4>:51767
[remote] engine active: 0.0.0.0:51767  -- type 'off' then Enter to stop
```

Pick the IPv4 that B can actually reach (physical Ethernet/Wi-Fi, not a Hyper-V/VPN NIC unless that is the path).

### Options

| Flag | Effect |
|------|--------|
| (bare) `remote on` | Bind `0.0.0.0:51767`. Firewall rule added. |
| `remote on 52000` | Same bind, different port. Port **51766 is rejected** (MCP). |
| `--loopback` | Bind `127.0.0.1` only. No firewall rule. Same box or SSH `-L`. |
| `--bind <ipv4>` | Listen on that address only. `127.0.0.1` behaves like `--loopback`. |
| `--peer <ipv4>` | Accept only that client IPv4. Firewall `RemoteAddresses` is pinned too. |

`--lan` and `--allow-write` do not exist. Writes follow the local TUI (`WriteEnabled` stays as it is).

### While A is in the remote engine loop

The A console is a **control plane**, not a second `knkd>`:

| Line on A | Effect |
|-----------|--------|
| `off` / `remote off` | Stop listen, delete the firewall rule, return to local REPL |
| `disconnect` / `remote disconnect` | Drop B, keep listening |
| `status` / `remote status` | Bind + peer |
| `write off` | Disarm kernel writes (same as local; stays off after `remote off`) |
| `q` / `quit` / `exit` / `unload` | Stop listen **and** tear down the process (driver unload on the normal `wmain` path) |

A does not run `!callbacks` locally while the remote loop is up. Stop with `off` first, or type the command on B.

---

## 3. Connect (PC B)

B does not need to be elevated. The `--connect` path runs before cloak, mutex, SCM, and `DeviceClient`.

```powershell
.\KnLiveDbg.exe --connect 192.168.1.10:51767
password: *****
```

Type the password **before** TCP connect (the server's auth deadline is 10s after accept). IPv4 literal only. DNS is not accepted. The port cannot be omitted.

After auth:

```text
connected HOST Windows abi=15 write=on cloak=no cleartext=true
warning: session is cleartext; lab LAN only
knkd>
```

Reconnect is a new session. Type the password again.

### Client prompt

| Input | Behavior |
|-------|----------|
| Tab | Same `CompletionHints` tables as the local TUI (`ApplyTabCompletion`). Ambiguous prefixes print the annotated listing. Does **not** wait on A. |
| color | Command output uses the same colors as A's TUI on a real console. If stdout is a pipe/file, B strips VT and prints plain text. |
| Up / Down | Local history |
| `cls` | Local screen clear. Not sent to A. |
| `disconnect` / `q` / `quit` / `exit` | Protocol disconnect. Exit code 0. B cannot unload A's driver. |
| other lines | `command-submit` to A |

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Graceful disconnect after auth |
| 2 | argv (`--connect` form, non-IPv4) or non-interactive password prompt |
| 4 | `auth-err` (bad password / lockout) |
| 5 | peer drop / connect failure / frame timeout |
| 6 | protocol (`unsupported-v`, unexpected type) |
| 1 | other |

Unknown controller argv (`KnLiveDbg.exe --connect ...` without the `--connect` ladder, or leftover tokens on the engine path) exits 2 **before** opening the device.

---

## 4. What B can and cannot do

B submits raw `knkd>` lines. The contract is a **deny-list**, not the MCP tool catalog.

**Denied from B** (A control plane only, or blocked entirely):

- `q` / `qq` / `qd` / `quit` / `exit` (on B these disconnect the client; they never tear down A)
- `unload`
- `mcp *`
- `remote *`
- `kd` / `kdinit` / `kddetach` / `backend *`
- `probe load` / `probe unload`
- `!byovd fixture load` / `unload`
- `.sympath` with extra args, `.sympath+`
- `log enable|disable|status`
- unknown / DbgEng-only names (`CommandRegistry` miss)

**Allowed from B**, including writes: native scanners, `dt`, `d*`, `e*` / `pe*` **with values on the line**, `dump-*`, `!snapshot`, `!diff`, `!ti`, `!timeline`, `ai`, `write on` / `write off`, `probe status` / `info`, `.sympath` with no args, `.reload`, `home`.

Dumps and snapshots land on **A's filesystem**, at the same paths the local TUI would use. B does not pull multi-GB files.

Address-only `eb ffff...` (no bytes) is rejected with `supply values on the command line`. Put the bytes on the same line (`eb <addr> 90`). There is no interactive write-preview on B yet.

`ai` from B is allowed. On a box with provider keys, prefer `KNLIVEDBG_AI_REMOTE_POLICY=local-only` if B should not spend those keys.

---

## 5. Tab completion

The B prompt uses the same tables as A's `knkd>`:

- Root names (`remote`, `!callbacks`, `ai`, ...)
- Nested scopes (`!callbacks disable`, `ai use`, `remote on --loopback`)
- Annotated listings when several matches remain

On A, `remote <Tab>` offers `on` / `off` / `status` / `disconnect` / `help`. After `remote on`, Tab offers `--loopback` / `--bind` / `--peer`.

The protocol also defines `completion-request` for a server-side pass. The shipped client does not send that for Tab; local completion is enough for the same command surface.

---

## 6. Firewall, XOR, and lab rules

- Non-loopback `remote on` adds inbound TCP `knlivedbg-remote` (DOMAIN|PRIVATE|PUBLIC). `remote off` / process exit deletes it. A leftover rule from a crash is deleted on the next successful Start.
- COM failure prints a warning and still listens. If B times out, add the port by hand or check which IP `remote on` printed.
- Any IPv4 peer is accepted (Tailscale `100.x`, Hamachi, public, RFC1918). Pin a single client with `--peer` if needed.
- Auth lockout is process-lifetime: 5 failures per peer IP, 15 global, then new auth is refused until `remote off`.
- `mcp on` while remote is up (or the reverse) fails: `listen XOR`.
- Isolated lab segment only. Shared office LAN / internet: do not bind `0.0.0.0`. Use `--loopback` plus `ssh -L 51767:127.0.0.1:51767` if the wire must be encrypted. TLS is v2 (Appendix A of the design doc), not this build.

---

## 7. Troubleshooting

| Symptom | Fix |
|---------|-----|
| `remote on failed: MCP server is running` | `mcp off` first |
| `remote on failed: MCP port; use 51767` | Do not pass 51766 |
| `remote password must be 5-128 printable ASCII...` | At least 5 characters, no spaces |
| B `connect failed` | Wrong IP from the printed list; firewall COM warning; `--peer` mismatch |
| B `auth-err: bad-password` | Same session password as A's prompt. A new `remote on` needs a new password |
| B `auth-err: lockout` | Too many failures. `remote off` on A, then `remote on` again |
| B `error: denied` | Session-lifetime / `kd` / `probe load` / unknown name. Run it on A after `off`, or pick an allowed command |
| `supply values on the command line` | Address-only `e*` / `pe*`. Add the bytes on the same line |
| Tab does nothing useful | Client uses local tables. Rebuild B's EXE if it is older than A's command surface |
| A hung in a long `!hunt` | Control plane `off` is queued-outside, but in-flight work runs to completion |

Driver-free checks (no live kernel):

```powershell
.\tools\validate-remote-protocol.ps1 -Configuration Release
```

That runs `KnLiveDbg.exe --self-test remote-protocol` and `--self-test connect-argv` (password min 5, deny-list, `--connect` argv, Tab expands `remote`, loopback listen). It is not part of `--self-test all`.

Same-box smoke (A elevated, driver loaded):

```text
knkd> remote on --loopback
```

```powershell
.\KnLiveDbg.exe --connect 127.0.0.1:51767
```

---

## 8. Quick reference

```text
# PC A (elevated knkd>)
remote on                                # 0.0.0.0:51767, password 5+, firewall rule
remote on --loopback                     # 127.0.0.1 only
remote on --peer 192.168.1.20            # pin B's IPv4
remote status
off                                      # stop listen, back to local REPL

# PC B (no elevation)
KnLiveDbg.exe --connect 192.168.1.10:51767
knkd> dt nt!_EPROCESS
knkd> eb ffff800000000000 90             # values on the line
knkd> disconnect
```
