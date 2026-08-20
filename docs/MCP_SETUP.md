> Korean version: [MCP_SETUP.ko.md](./MCP_SETUP.ko.md)

# KnLiveDbg MCP Server Setup and Connection Guide

This document covers the **operational procedure for actually launching KnLiveDbg's MCP (Model Context Protocol) server and connecting to it from Claude (Claude Code / Claude Desktop)**. For the design rationale and threat model, see [`MCP_SERVER_DESIGN.md`](./MCP_SERVER_DESIGN.md).

- Server name: `knlivedbg`  ·  Server version: `0.1.0`  ·  MCP protocol: `2025-06-18`
- Transport: in-process Streamable HTTP (`http.sys`), endpoint path `/mcp`
- Default port: `51766`  ·  Authentication: a stable 256-bit bearer token, rotated only on request or when no saved token exists
- Default exposure: **loopback only** (`127.0.0.1` + `[::1]`). Network exposure is opt-in via `--bind` only.

---

## 1. Core Concept: Where to Run What

The MCP server runs **in-process inside the elevated KnLiveDbg.exe that owns the driver**. Therefore:

| Command | Where it runs | Form |
|------|-----------|------|
| `mcp on ...` | **Analysis target PC/VM** (where kernel RW happens) | Console command inside KnLiveDbg.exe's `knkd>` prompt |
| `claude mcp add ...` | **Client PC** (where Claude Code runs) | Regular shell command (outside KnLiveDbg) |

> If the server PC and client PC are the same, connect over loopback; if they are physically different machines, expose over the network with `--bind` and connect to the server PC's IP.

---

## 2. Prerequisites (server PC / VM)

### 2.1 Copy the artifact bundle

KnLiveDbg.exe **depends on the files next to it**. When moving it to another PC/VM, place the following in the same folder.

```text
KnLiveDbg.exe            <- executable
KnLiveDbg.sys            <- main driver (required next to the EXE)
KnLiveDbgProbe.sys       <- optional: benign control driver for probe load
dbghelp.dll, dbgeng.dll, dbgcore.dll, DbgModel.dll
msdia140.dll, symsrv.dll, srcsrv.dll, symsrv.yes   <- symbol runtime
```

The simplest approach is to move the entire release zip (from the build PC, not the server PC):

```powershell
.\tools\release.ps1 -Configuration Release
# copy release\KnLiveDbg-<version>-Release-x64.zip to the target PC and extract it
```

> If you omit the symbol DLLs, startup falls back to `symType=0 (SymNone)` and kernel PDB downloads may be blocked.

### 2.2 Enable test signing (for driver load)

The driver is signed with the WDK `TestSign`, so test signing must be enabled on the target PC/VM for it to load (admin console, one-time):

```powershell
bcdedit /set testsigning on
# reboot required
```

### 2.3 Run elevated

```powershell
cd .\x64\Release
.\KnLiveDbg.exe
```

The boot stages proceed with `[ OK ]` (elevation -> single instance -> symbols/DIA -> driver load -> device open -> ABI verify -> symbol init), and the dashboard appears along with the `knkd>` prompt.

---

## 3. Launching the Server (`mcp on`)

Type this at the `knkd>` prompt. Argument order is free.

```text
mcp on [port] [--allow-write] [--bind <addr>]
mcp off        # stop the server (inside the engine loop: off + Enter)
mcp status     # current state
```

### 3.1 Options

| Option | Meaning | Default |
|------|------|--------|
| `<port>` (positional arg) | Listening port. Only `0 < port < 65536` applies; anything else is ignored | `51766` |
| `--allow-write` (or `allow-write`) | Lab write mode. Registers the 10 write tools + arms kernel write | none = read-only |
| `--bind <addr>` | Network exposure. Additionally binds to `<addr>` | none = loopback only |
| `--bind=<addr>` | Same as above (joined form) | none |
| `--token <t>` | Use a fixed 16-512 character printable-ASCII bearer token (persisted), instead of the auto-managed one | auto |
| `--new-token` | Rotate: discard the persisted token and mint a fresh random one | off |

For `<addr>` you can give a concrete IP (e.g. `192.168.56.10`) or, for all interfaces, `0.0.0.0` / `*` / `+` (mapped to the http.sys strong wildcard `+`).

**Recommended reconnect model (no token paste):** `mcp on` refreshes native Streamable HTTP snippets for the actual bind address and port. Use them with Claude Code, Cursor, Codex, or Grok Build. Before launching a client on the same PC, dot-source `%LOCALAPPDATA%\kn-live-dbg\mcp-load-env.ps1`; the configuration reads `KNLIVEDBG_TOKEN` without storing the bearer token in a project file. Claude Desktop local MCP is the exception and uses `tools\mcp-bridge.ps1` because its remote connectors originate in Anthropic's cloud and cannot reach loopback/private endpoints.

**Token stability.** The bearer token is **stable across restarts** (and no longer per-port by default), so a native client config remains valid while the URL is unchanged. Resolution order: `--token <t>` > `KNLIVEDBG_TOKEN` env > `%LOCALAPPDATA%\kn-live-dbg\mcp-token` (legacy per-port files under `<exeDir>\.kn-live-dbg\` are migrated once) > freshly minted random token (persisted). If the port or bind address changes, apply the refreshed client URL. After `--new-token`, native clients must reload `KNLIVEDBG_TOKEN` and reconnect. Claude Desktop/legacy bridges must also be restarted so the new bridge process rereads the endpoint file.

### 3.2 Local (loopback) — same PC

```text
knkd> mcp on
```

Example output:

```text
MCP server started (loopback Streamable HTTP).
  url      : http://127.0.0.1:51766/mcp
  token    : 3f9c... (REUSED)
  tokenFile: %LOCALAPPDATA%\kn-live-dbg\mcp-token
  endpoint : %LOCALAPPDATA%\kn-live-dbg\mcp-endpoint.json  (Desktop/legacy bridge state)
  write    : disabled (read-only)
  audit    : <exeDir>\.kn-live-dbg\mcp-audit-51766.jsonl

  Native HTTP client files refreshed (no npx):
    snippets: %LOCALAPPDATA%\kn-live-dbg\clients
    separate client launch shell: . "$env:LOCALAPPDATA\kn-live-dbg\mcp-load-env.ps1"
```

From this point the console is the **MCP engine loop**. To stop, type `off` + Enter.

### 3.2.1 Client registration (native HTTP preferred)

`mcp on` automatically rewrites the snippets with the live URL. While the MCP engine loop is running, the KnLiveDbg console accepts only `off` and `status`; use the generated files from a **separate PowerShell**. When the normal REPL is active (before `mcp on` or after `off`), `mcp client-setup` prints the last saved setup:

```text
knkd> mcp client-setup
knkd> mcp client-setup claude
knkd> mcp client-setup claude-desktop
knkd> mcp client-setup cursor
knkd> mcp client-setup codex
knkd> mcp client-setup grok
knkd> mcp client-setup legacy
```

Snippets are also written under `%LOCALAPPDATA%\kn-live-dbg\clients\`.

| Agent | One-time command / config |
|------|---------------------------|
| **Claude Code** | Run `clients\claude-code-http.powershell.txt` in PowerShell or use `clients\claude-code-http.json` |
| **Claude Desktop (local)** | Merge `clients\claude-desktop-mcp.json`; this is the stdio bridge exception |
| **Cursor** | Merge the native HTTP `clients\cursor-mcp.json` into user MCP settings |
| **OpenAI Codex** | Run `clients\codex-http.powershell.txt`, or append `clients\codex-config.toml.snippet` |
| **Grok Build** | Run `clients\grok-http.powershell.txt`, or append `clients\grok-config.toml.snippet` |
| **Older stdio-only client** | Merge `clients\legacy-stdio-mcp.json` as a compatibility fallback |

In the separate PowerShell session that will launch the native client:

```powershell
. $env:LOCALAPPDATA\kn-live-dbg\mcp-load-env.ps1
# Start or restart the client from this shell.
```

The stable token means normal restarts at the same URL do not require config edits. A port or bind-address change requires applying the refreshed native URL snippet. After explicit rotation (`mcp on --new-token`), rerun the env loader and restart/reconnect a native client. Restart Claude Desktop or any legacy client too: the bridge reads URL and token once when its process starts, not on each HTTP reconnect.

### 3.3 Remote (`--bind`) — separate PC/VM

On the server PC, first find the LAN IP:

```powershell
ipconfig    # e.g. 192.168.56.10
```

Bind to that IP:

```text
knkd> mcp on 51766 --bind 192.168.56.10
```

The output adds a `remote:` line and a network-exposure warning. The client uses this `remote:` URL and token.

```text
MCP server started (NETWORK Streamable HTTP).
  url   : http://127.0.0.1:51766/mcp
  remote: http://192.168.56.10:51766/mcp
  token : <copy-to-client>
  ...
  WARNING: this elevated kernel read/write endpoint is now reachable over the
           network. The bearer token is the ONLY barrier. Restrict access with a
           firewall rule (allow only the client IP) and use a trusted lab segment.
```

> If you use `--bind 0.0.0.0` (all interfaces), the tool cannot know which interface IP will be used to connect, so it prints a `<this-host-ip>` placeholder in the URL. When possible, **specify a concrete IP**.

### 3.4 Write mode

```text
knkd> mcp on 51766 --allow-write --bind 192.168.56.10
```

- Read-only (default): on engine entry, `SetWriteMode(false)` **disarms the kernel write flag itself**. The write tools are not registered, and when called they are rejected with `writes are disabled; start the MCP server with --allow-write (lab mode)`.
- `--allow-write`: the 10 write tools are exposed and `SetWriteMode(true)` arms kernel writes. Kernel-memory writes use the preflight/backup/verify-diff/audit rails; file/ring operations are still gated, audited, and warned when backup/verify is not meaningful (interactive confirmation is skipped).
- **Mode-switch caveat**: if the server is already running, `mcp on --allow-write` (or `--bind`/port change) is **ignored** (it only prints `MCP server is already running on port N`). To change flags, first stop with `off`+Enter (engine loop) or `mcp off`, then relaunch. The saved token remains valid unless you also pass `--new-token` or change `--token`/`KNLIVEDBG_TOKEN`.
- **Recommendation**: take a VM snapshot before a write session, and capture an analysis baseline (`snapshot.capture`). It is for isolated VMs only; never use it on a live EDR/AC box.

---

## 4. Connecting an MCP client (client PC)

Use the **exact url/token** printed by the server console. The server speaks streamable HTTP, so any MCP client that supports the `http` transport connects directly; clients limited to stdio use the `mcp-remote` bridge.

### 4.1 Claude Code

```bash
# local (same PC)
claude mcp add --transport http knlivedbg http://127.0.0.1:51766/mcp \
  --header "Authorization: Bearer <token-from-server>"

# remote (separate PC/VM) - use the server PC's IP
claude mcp add --transport http knlivedbg http://192.168.56.10:51766/mcp \
  --header "Authorization: Bearer <token-from-server>"
```

Verify the connection:

```bash
claude mcp list
# success if knlivedbg shows as connected
```

If you write `.mcp.json` directly (token via **env indirection**, never commit in plaintext):

```jsonc
{
  "mcpServers": {
    "knlivedbg": {
      "type": "http",
      "url": "http://192.168.56.10:51766/mcp",
      "headers": { "Authorization": "Bearer ${KNLIVEDBG_TOKEN}" }
    }
  }
}
```

> `${KNLIVEDBG_TOKEN}` is read by Claude Code from its launch environment. On the same PC, dot-source `mcp-load-env.ps1` before starting Claude Code. After explicit token rotation, reload the environment and reconnect. The bridge is not needed for current Claude Code builds.

Useful knobs: per-server `timeout` (ms; keep it above the server's 30-second engine limit), `headersHelper` (issue a rotating token on connect), `alwaysLoad`.

### 4.2 Claude Desktop

Claude Desktop's remote connectors support Streamable HTTP, but their traffic originates in Anthropic's cloud. They cannot reach KnLiveDbg on `127.0.0.1` or a private lab network, and Claude Desktop does not connect to a remote HTTP server declared directly in `claude_desktop_config.json`. For **local KnLiveDbg**, use the generated stdio bridge config:

```jsonc
{
  "mcpServers": {
    "knlivedbg": {
      "command": "powershell.exe",
      "args": ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
               "C:\\path\\to\\tools\\mcp-bridge.ps1"]
    }
  }
}
```

`mcp client-setup claude-desktop` writes the exact path to `%LOCALAPPDATA%\kn-live-dbg\clients\claude-desktop-mcp.json`. Merge it into `%APPDATA%\Claude\claude_desktop_config.json`, then fully restart Desktop. Each bridge process reads the protected endpoint once at startup, so the token stays out of Desktop config. Restart Desktop after a URL or token change so it launches a bridge with the new state.

Do not publish the elevated kernel endpoint to the internet merely to make it reachable by a Claude remote connector. Keep this path loopback-only.

Source: [Anthropic custom connector network requirements](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp).

### 4.3 Codex CLI

Codex reads MCP config from `~/.codex/config.toml` (or a trusted project `.codex/config.toml`) and supports streamable-HTTP MCP servers directly.

**HTTP (recommended).** The current CLI registers the URL and bearer-token environment variable directly:

```powershell
codex mcp add knlivedbg --url 'http://192.168.56.10:51766/mcp' --bearer-token-env-var KNLIVEDBG_TOKEN
```

Equivalent `config.toml` (the token is sent as `Authorization: Bearer <env value>`):

```toml
[mcp_servers.knlivedbg]
url = "http://192.168.56.10:51766/mcp"
bearer_token_env_var = "KNLIVEDBG_TOKEN"
tool_timeout_sec = 60    # server returns engine timeout after 30s
```

Then `export KNLIVEDBG_TOKEN=<token>` (PowerShell: `$env:KNLIVEDBG_TOKEN="<token>"`) in the shell that launches Codex. A static header works too:

```toml
[mcp_servers.knlivedbg]
url = "http://192.168.56.10:51766/mcp"
http_headers = { "Authorization" = "Bearer <token-from-server>" }
```

Current Codex clients support Streamable HTTP directly. If an old build rejects `url`, update Codex; use the bridge below only when updating is impossible.

**stdio bridge (legacy fallback).** If an older Codex build cannot use HTTP and cannot be updated, bridge through `mcp-remote`:

```toml
[mcp_servers.knlivedbg]
command = "npx"
args = ["-y", "mcp-remote@0.1.38", "http://192.168.56.10:51766/mcp", "--allow-http", "--transport", "http-only", "--silent", "--header", "Authorization: Bearer ${KNLIVEDBG_TOKEN}"]
env = { KNLIVEDBG_TOKEN = "<token-from-server>" }
```

Notes:
- Use `codex mcp add <name> --url <url> --bearer-token-env-var <env>` for Streamable HTTP. The `--env VAR=VALUE -- <command>` form is only for **stdio** servers.
- Timeouts: `startup_timeout_sec` defaults to 10s and `tool_timeout_sec` to 60s. KnLiveDbg returns `engine timeout` after 30s, so raising only the client timeout cannot make a longer scan finish; narrow or split the scan.
- Codex is a non-browser client (sends no `Origin`) and connects on the bound host, so the bearer token is the only barrier — same as Claude (§5).

> All clients below are non-browser MCP clients, so the bearer token is the only barrier (§5). Watch the **field-name traps**: Gemini uses `httpUrl`, Cline uses `type: "streamableHttp"`, Goose uses `uri` + `streamable_http`, Windsurf uses `serverUrl`. The endpoint is plain `http://` — the token crosses the wire unencrypted, so keep it on a trusted LAN/loopback or front it with TLS / an SSH tunnel.

### 4.4 Cursor

Config: `~/.cursor/mcp.json` (global) or `.cursor/mcp.json` (project — never commit the token; use env interpolation). Also addable via Settings → MCP → "Add new MCP server".

```jsonc
{
  "mcpServers": {
    "knlivedbg": {
      "url": "http://<server-ip>:51766/mcp",
      "headers": { "Authorization": "Bearer ${env:KNLIVEDBG_TOKEN}" }
    }
  }
}
```

- `${env:KNLIVEDBG_TOKEN}` is interpolated; export the variable in the environment Cursor inherits, then restart Cursor (it reads env at launch). After editing, toggle the server off/on in Settings → MCP. No remote-HTTP CLI add command. Source: [cursor.com/docs/mcp](https://cursor.com/docs/mcp).

### 4.5 VS Code (GitHub Copilot agent mode)

Config: `.vscode/mcp.json` (workspace) or Command Palette → "MCP: Open User Configuration". Top-level `servers` key, `type: "http"`. Surfaces in Copilot Chat **agent mode**.

```jsonc
{
  "inputs": [
    { "type": "promptString", "id": "knlivedbg-token", "description": "knlivedbg bearer token", "password": true }
  ],
  "servers": {
    "knlivedbg": {
      "type": "http",
      "url": "http://<server-ip>:51766/mcp",
      "headers": { "Authorization": "Bearer ${input:knlivedbg-token}" }
    }
  }
}
```

- `${input:...}` prompts once and stores the token encrypted; `${env:KNLIVEDBG_TOKEN}` is also supported. CLI add: `code --add-mcp "{\"name\":\"knlivedbg\",\"type\":\"http\",\"url\":\"http://<server-ip>:51766/mcp\",\"headers\":{\"Authorization\":\"Bearer ${env:KNLIVEDBG_TOKEN}\"}}"`. Start/restart from the CodeLens above the entry. Source: [code.visualstudio.com MCP docs](https://code.visualstudio.com/docs/copilot/customization/mcp-servers).

### 4.6 Gemini CLI

```bash
gemini mcp add --transport http --scope user \
  --header "Authorization: Bearer $KNLIVEDBG_TOKEN" \
  knlivedbg http://<server-ip>:51766/mcp
```

Or edit `~/.gemini/settings.json` — use **`httpUrl`** (NOT `url`; `url` is the legacy SSE transport):

```jsonc
{
  "mcpServers": {
    "knlivedbg": {
      "httpUrl": "http://<server-ip>:51766/mcp",
      "headers": { "Authorization": "Bearer ${KNLIVEDBG_TOKEN}" },
      "timeout": 600000
    }
  }
}
```

- `--transport http` is required (otherwise stdio is assumed and `--header` is ignored). The CLI bakes the shell-resolved token literally into settings.json; hand-edit to keep a live `${KNLIVEDBG_TOKEN}` placeholder. No trailing commas in settings.json. Verify with the `/mcp` command in a session. Source: [gemini-cli MCP docs](https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-server.md).

### 4.7 Cline

Config via the Cline panel → MCP Servers → "Remote Servers" tab, or edit `cline_mcp_settings.json` (VS Code: `%APPDATA%\Code\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json`). **`type` must be `"streamableHttp"` (camelCase)** — omitting it or using `"streamable-http"` falls back to SSE and 405s a streamable endpoint.

```jsonc
{
  "mcpServers": {
    "knlivedbg": {
      "type": "streamableHttp",
      "url": "http://<server-ip>:51766/mcp",
      "headers": { "Authorization": "Bearer <paste-token>" },
      "disabled": false,
      "autoApprove": [],
      "timeout": 60
    }
  }
}
```

- Env-var interpolation is **not** supported for remote header values — paste the literal token and treat the file as a secret. Raise `timeout` (seconds) for slow scans. Source: [docs.cline.bot](https://docs.cline.bot/mcp/connecting-to-a-remote-server).

### 4.8 Goose (Block)

Run `goose configure` → Add Extension → "Remote Extension (Streamable HTTP)" → name `knlivedbg`, URI `http://<server-ip>:51766/mcp`, add header `Authorization: Bearer ${KNLIVEDBG_TOKEN}`. Or edit `~/.config/goose/config.yaml` (Windows: `%APPDATA%\Block\goose\config\config.yaml`) — **field is `uri` (not `url`), type is `streamable_http`**:

```yaml
extensions:
  knlivedbg:
    type: streamable_http
    name: knlivedbg
    enabled: true
    uri: http://<server-ip>:51766/mcp
    headers:
      Authorization: "Bearer ${KNLIVEDBG_TOKEN}"
    timeout: 300
```

- `${KNLIVEDBG_TOKEN}` is interpolated from the environment Goose was launched with (export it first); restart the session after editing. `timeout` is in seconds. Source: [block.github.io/goose](https://block.github.io/goose/).

### 4.9 Windsurf (Cascade)

Config: `~/.codeium/windsurf/mcp_config.json` (user scope only) or Settings → Cascade → MCP Servers → "Add custom server". **Field is `serverUrl` (not `url`)** for streamable HTTP.

```jsonc
{
  "mcpServers": {
    "knlivedbg": {
      "serverUrl": "http://<server-ip>:51766/mcp",
      "headers": { "Authorization": "Bearer ${env:KNLIVEDBG_TOKEN}" }
    }
  }
}
```

- `${env:KNLIVEDBG_TOKEN}` is interpolated (restart Windsurf so it inherits the variable). Click the refresh button in the MCP panel after editing. Cascade caps active MCP tools at 100 total — disable unneeded tools to stay under budget. Source: [docs.windsurf.com](https://docs.windsurf.com/plugins/cascade/mcp).

### 4.10 Hermes Agent (Nous Research)

Hermes is configured by a single **YAML** file, not JSON — `config.yaml` under `$HERMES_HOME`. It supports HTTP transport natively (`url` + `headers`), so connect directly — **no `mcp-remote` bridge needed**. The `{command, args, env}` form some UIs show is only the *stdio* sub-schema; do not force our HTTP endpoint through it.

Config locations:

| Platform | Path |
|------|------|
| Windows (native installer) | `%LOCALAPPDATA%\hermes\config.yaml` (i.e. `$HERMES_HOME`) |
| Linux / macOS / WSL | `~/.hermes/config.yaml` |

> On Windows the installer sets `HERMES_HOME=%LOCALAPPDATA%\hermes`. The WebUI may instead look in `~/.hermes\` — if you edit one and Hermes reads the other, the server "is not found". Confirm the live path with `echo %HERMES_HOME%` (PowerShell: `$env:HERMES_HOME`).

Add a top-level `mcp_servers` block. A fresh config ships it as `mcp_servers: {}` (empty mapping = zero servers) — replace the `{}` with an indented block:

```yaml
mcp_servers:
  knlivedbg:
    url: "http://127.0.0.1:51766/mcp"        # remote: http://<server-ip>:51766/mcp
    headers:
      Authorization: "Bearer <token-from-server>"
    timeout: 300        # raise above the 120s default for slow scans (hunt.run, etc.)
    connect_timeout: 60
    # tools:            # optional: expose only what you need (46 read tools is a lot of context)
    #   include: [process.find, vad.list, threads.list, callbacks.list, hunt.run]
```

CLI equivalent (use `--url`/`--header`, not the stdio `--command`/`--args`):

```bash
hermes mcp add knlivedbg --url "http://127.0.0.1:51766/mcp" \
  --header "Authorization: Bearer <token-from-server>"
```

- Hermes reads `config.yaml` once at startup — **restart Hermes** after editing. Verify with `hermes mcp list` (should show `knlivedbg` connected). Header env interpolation is not guaranteed, so the literal token usually lands in the YAML — treat the file as a secret and do not commit it.
- If your build is old enough that it rejects `url`, use `tools/mcp-bridge.ps1`; it pins `mcp-remote` and supplies the explicit local-HTTP and HTTP-only transport flags. On Windows this needs Node/`npx` on PATH. Source: [Hermes MCP config reference](https://hermes-agent.nousresearch.com/docs/reference/mcp-config-reference).

### 4.11 Token handling caveats

- The token authenticates the kernel RW endpoint. **Do not paste it in plaintext into a project-scope `.mcp.json` and commit it.** Use user-scope settings + the `${KNLIVEDBG_TOKEN}` environment variable.
- The token is **stable across restarts** (§3.1): a client registered once keeps working, so you do not re-add the server on every `mcp on`. It changes only when you pass `--new-token` (rotation) or supply a different `--token`/`KNLIVEDBG_TOKEN` — refresh the client only then.
- For end-to-end env-driven stability, set the same `KNLIVEDBG_TOKEN` on **both** the server host (the server reads it, precedence #2) and the client (via `${KNLIVEDBG_TOKEN}`); then no token ever lands on disk.

---

## 5. Security Model (for understanding when a connection is blocked)

Before processing JSON-RPC, the server passes the request through these transport gates:

1. **Bearer token** (constant-time comparison): on `Authorization: Bearer <token>` mismatch, 401. This is the real authentication boundary.
2. **Host check**: in loopback-only mode (default), if Host is not `127.0.0.1`/`localhost`/`[::1]`/`::1`, 403 (DNS-rebinding defense). In `--bind` remote mode, this check is skipped (remote Host accepted).
3. **Origin check**: if the Origin header **is present** but is not a loopback authority, 403. Absent/empty Origin is allowed (non-browser MCP clients do not send Origin). **This check is always applied regardless of bind mode** and stops DNS-rebinding.
4. **Write gate**: without `--allow-write`, the write tools are not exposed and the kernel flag is not armed.

Since the token is the only barrier when exposed remotely, on the server PC firewall it is recommended to **allow inbound only from the client IP** (admin PowerShell):

```powershell
New-NetFirewallRule -DisplayName "knlivedbg-mcp" -Direction Inbound `
  -Protocol TCP -LocalPort 51766 -RemoteAddress <client-ip> -Action Allow
```

### 5.1 Audit log (audit)

Always on while `mcp on` (independent of the `ai audit` toggle). It records every request as a single append-only JSONL line:

- Path: `<exeDir>\.kn-live-dbg\mcp-audit-<port>.jsonl`
- Fields: `ts` (UTC), `session`, `peerPort`, `method`, `tool`, `args` (truncated to 512 chars), `decision`, `isError`, `resultBytes`, `writeArmed`
- `decision` values: `ok` / `unknown-tool` / `writes-disabled` / `engine-busy` / `tool-error` / `unknown-resource` / `session-open`
- The last 50 lines are also exposed via the resource `kn://audit/tail`.

---

## 6. Capability Catalog

### 6.1 Read tools (67, no `--allow-write` needed — except `ti.subscribe` start/stop)

| Tool | Description | Key args (all optional unless noted otherwise) |
|-----|------|----------------------|
| `process.find` | Find a process by image name/PID/EPROCESS | `image`, `pid`, `eprocess` |
| `process.describe` | Describe `_EPROCESS` (PID/DTB/PEB/threads/parent) | `source`, `pid`, `eprocess`, `fields` |
| `type.describe` | Dump a kernel structure from an address/process (dt) | `source`, `address`, `type`, `fields` |
| `callbacks.list` | Enumerate kernel callbacks (object/registry/process/thread/imageload/minifilter) | `scope`, `module` |
| `wfp.list` | Enumerate WFP provider/sublayer/callout/filter/layer | `scope`, `module`, `provider`, `layer` |
| `wfp.kernel_callouts` | Resolve kernel-mode WFP classify/notify/flowDelete pointers from `netio.sys` | (none) |
| `alpc.list` | Enumerate ALPC ports/connections | `scope`, `name`, `pid` |
| `vad.list` | Enumerate VADs (W+X/private/hidden-PTE/DKOM checks) | `pid`, `image`, `eprocess`, `exec`, `private`, `wx`, `pe`, `hiddenpte`, `dkom`, `summary`, `limit` |
| `threads.list` | Thread/start-address/APC/stack evidence | `pid`, `image`, `eprocess`, `apc`, `stacks`, `limit` |
| `etw.integrity` | ETW logger/GetCpuClock integrity (InfinityHook) | (none) |
| `etw.providers` | Heuristic/partial ETW provider registration and enable-callback ownership | (none) |
| `etw.ti_cross` | Correlate active TI subscription reception with silence/drop signals | (none) |
| `nmi.list` | Enumerate registered NMI callbacks | `scope` |
| `minifilter.list` | List filesystem minifilters and IRP registrations | `filter`, `name` |
| `payload.inspect` | Hook-to-body: trace one kernel address (page walk, big pool, PE, disasm) | `address`, `va`, `symbol` |
| `payload.scan` | Hook-to-body: sweep unbacked hook pointers and trace each unique target | `limit` |
| `mapper.list` | Bookkeeping remnants: MmUnloadedDrivers / PiDDB / ci hash. leftover=0 is ledger-clean, not payload-absent | `scope`, `limit` |
| `kpage.list` | Orphan pages: executable kernel VA outside loaded modules (wiped kdmapper payload layer) | `deep`, `wx`, `pe`, `limit` |
| `hal.scan` | HalDispatchTable / HalPrivateDispatchTable function-pointer ownership | (none) |
| `hive.list` | Registry hive GetCellRoutine ownership with validated list links | (none) |
| `token.inspect` | Process token privilege Present/Enabled masks | `pid`, `image`, `eprocess`, `limit` |
| `dpc.list` | Sampled DPC deferred routines; non-image callbacks are high risk | (none) |
| `timer.list` | Kernel timer DPC routines; non-image callbacks are high risk | (none) |
| `fwtable.list` | Enumerate firmware-table providers | `scope`, `module`, `provider`, `signature` |
| `pool.find` | Enumerate kernel big pool allocations (tag/size/addr/W+X) | `tag`, `min`, `max`, `addr`, `limit`, `paged`, `annotate`, `wx` |
| `address.inspect` | Inspect a virtual address (page-table walk/permissions/owning module) | `address`, `va`, `symbol` |
| `wnf.decode` | Decode a WNF state-name hash | `hash`, `state`, `state_name` |
| `wnf.list` | Enumerate live WNF instances/candidates/lists | `scope` |
| `ti.query` | Query the Threat-Intelligence ETW ring (recent/stats/by/grep) | `action`, `count`, `pid`, `task`, `pattern` |
| `timeline.status` | Report in-memory evidence timeline counters and capacity | (none) |
| `timeline.query` | Query ingested timeline events by source/domain/PID/limit/order | `source`, `domain`, `pid`, `limit`, `order` |
| `timeline.export` | Return ingested timeline events as JSONL text without writing to disk | `source`, `domain`, `pid`, `limit`, `order` |
| `timeline.reconcile` | Compare ingested timeline evidence with a snapshot baseline or JSON file | `path`, `snapshot`, `source`, `domain`, `pid`, `limit` |
| `graph.query` | Derive a process/image/domain/source graph from ingested timeline events | `source`, `domain`, `image`, `pid`, `limit`, `order` |
| `module.integrity` | Loaded-module PE/section integrity + W+X + IAT/prologue | `module`, `target`, `limit`, `summary`, `verbose`, `headers`, `sections`, `wx`, `mismatch`, `disk`, `iat`, `prologue` |
| `driver.integrity` | `DRIVER_OBJECT` dispatch-table integrity | `driver`, `target`, `limit` |
| `driver.object` | One `DRIVER_OBJECT` plus device/attached stacks | `driver`, `name`, `target`, `address` |
| `device.stack` | Walk a `DEVICE_OBJECT` AttachedDevice/AttachedTo stack | `address`, `va`, `device` |
| `handles.list` | Process handles with VM/DUP cross-process suspicion | `pid`, `target`, `limit` |
| `hiddenproc.list` | ActiveProcessLinks x SPI x Toolhelp x handle owners | (none) |
| `wdfilter.list` | WdFilter RuntimeDriver leftovers | (none) |
| `inputstack.list` | Keyboard/mouse class attached-device stacks | (none) |
| `dma.posture` | IOMMU firmware + Kernel DMA Protection + removable PCI | (none) |
| `hv.posture` | CPUID/CR4.VMXE/timing hypervisor presence (no FEATURE_CONTROL) | (none) |
| `dump.analyze` | Parse dump-kernel DUMP_HEADER64, runs, and loaded modules (4-level or LA57 5-level VA walk) | `path`, `file` |
| `ssdt.scan` | Detect SSDT/shadow-SSDT syscall hooks | (none) |
| `idt.scan` | IDT interrupt-gate hooks/per-CPU divergence | (none) |
| `cr.scan` | Inspect control registers (CR0.WP/SMEP/SMAP/per-CPU) | (none) |
| `msr.check` | SYSCALL MSR (LSTAR/CSTAR/STAR/FMASK/EFER) hooks | (none) |
| `vbs.scan` | VBS/HVCI/CI/hypervisor/Secure Kernel/trustlet | (none) |
| `byovd.scan` | Compare loaded modules against the local BYOVD/LOLDrivers catalog (no network/subprocess) | (none) |
| `byovd.status` | Report local BYOVD catalog age/source counts/YARA rule availability | (none) |
| `pool.scan_pe` | Hunt PEs staged in kernel big pool (including signature wipe) | `tag`, `limit`, `suspicious` |
| `hunt.run` | Whole-system user-mode anomaly hunt (injection/VAD/PTE/threads/APC/driver/WFP/TI) | `mode` |
| `snapshot.capture` | Capture a same-boot evidence baseline (in-memory, not written to disk) | `name` |
| `snapshot.show` | Show the current snapshot baseline or a snapshot JSON file (summary + structured JSON) | `source`, `path`, `domains`, `warnings` |
| `snapshot.diff` | Compare the session baseline with a live capture (or two snapshot files) | `old`, `new`, `domain`, `risk`, `limit`, `summary` |
| `memory.read_virtual` | Read bytes at a virtual address (db/dq) — hex + unreadable mask (structured) | `address`/`va`/`symbol`, `width` (1/2/4/8), `count`, `process` |
| `memory.read_physical` | Read bytes at a physical address (!db/!dq) — bypasses hooked VA mappings (structured) | `physical_address` (required), `width`, `count` |
| `memory.search` | Search for an integer value/pattern in a VA range (s) | `address` (required), `length` (required), `value` (required), `width` |
| `memory.translate` | VA->PA translation + page-table walk (vtop), per-process DTB | `address`/`va`/`symbol`, `process`/`cr3`, `length` |
| `memory.probe` | Check whether an address is readable/writable (query) | `address`/`va`/`symbol`, `length` |
| `code.disasm` | Disassemble an address/function (u/uf) | `address`/`symbol`, `count`, `function` (bool) |
| `symbol.search` | Enumerate wildcard symbols->addresses (x `mod!mask`) | `mask` (required), `limit` |
| `memory.read_pointers` | Resolve pointer-table slots to nearest symbols (dps/dds/dqs) — hunt call-table/vtable/IAT hooks | `address`/`va`/`symbol`, `width` (4/8), `count` |
| `memory.compare` | Byte-compare two virtual ranges + mismatch offsets (c) — detect inline hooks/patches | `address1` (required), `address2` (required), `length` (required) |
| `ti.subscribe` | Control TI ETW subscription (`action`=start/stop/status) — **start/stop require `--allow-write`** | `action` |

> `snapshot.capture`/`snapshot.diff` **do not write files to disk** on the MCP path (in-memory). Read the baseline via `kn://snapshot/current` or use `snapshot.show` for summary + structuredContent. `memory.read_virtual`/`read_physical`/`symbol.search`/`snapshot.show`/`timeline.status`/`timeline.query`/`timeline.reconcile`/`graph.query` return structuredContent (JSON), and the remaining new tools return text content. `timeline.export` returns JSONL text in the MCP response and does not write a file. `ti.subscribe` is a read category, but because of the side effect of starting/stopping the ETW session, only start/stop require write mode (status is always available, the same data as `kn://ti/stats`).

### 6.2 Write tools (11, `--allow-write` required)

| Tool | Description | Required args | Optional args |
|-----|------|-----------|-----------|
| `memory.write_virtual` | Write bytes to a kernel virtual address (e*) | `address`, `bytes` | `width`, `process` |
| `memory.write_physical` | Write bytes to a physical address (pe*) | `physical_address`, `bytes` | — |
| `memory.fill` | Fill a kernel range with a pattern | `address`, `length`, `pattern` | — |
| `memory.move` | Copy a kernel range (src->dest) | `source`, `dest`, `length` | — |
| `type.set_field` | Set a struct field at an address (setfield) | `address`, `type`, `field`, `value` | — |
| `minifilter.set_irp` | Enable or disable a minifilter IRP pre/post handler (`irp=all` for every slot) | `filter`, `irp`, `action` | `which` (pre/post/both) |
| `process.set_protection` | Set PS_PROTECTION on an arbitrary target (PPL/PP) | `level` (none/ppl-antimalware/ppl-lsa/ppl-windows/ppl-wintcb/pp-windows/pp-wintcb/pp-winsystem) | `pid` (unspecified=self) |
| `ti.export` | Export the current Threat-Intelligence ETW ring to JSONL | `path` | — |
| `ti.clear` | Clear the in-memory Threat-Intelligence ETW ring | — | — |
| `dump.raw` | Dump a kernel range to a given file path | `address`, `length`, `path` | `zerofill` |
| `dump.pe` | Reconstruct an on-disk PE image from memory | `address`, `path` | — |

> **Caution — `process.set_protection` arbitrary target**: with `pid` you can raise the PPL/PP of an arbitrary process (e.g. promote a process to un-killable PP) or strip it (e.g. neutralize a PPL anti-cheat/AV). The driver IOCTL supports arbitrary targets (gated only by write-ack + write mode) and is for `--allow-write` lab mode only. Capturing a target-process baseline and a VM snapshot before the change is recommended. The response includes the before/after/requested bytes + the verification (readback) result.
>
> **`minifilter.set_irp`**: `irp` is a major name (`IRP_MJ_CREATE`, `CREATE`, `0x00`) or `all`. `irp=all` (or `action=disable-all`/`enable-all` with `irp=all`) walks every registered slot on that filter and returns `kn-live-dbg.minifilter-irp-batch.v1`. Enable restores only pointers saved in this session. Inbox names warn and are not blocked.

### 6.3 Resources (8)

| URI | Content |
|-----|------|
| `kn://session/info` | Driver session/ABI/ownership/write-arm state |
| `kn://capabilities` | Active MCP tools and argument schemas (provided directly by the transport side) |
| `kn://modules/kernel` | List of loaded kernel modules (name/base/size) — name->address map |
| `kn://drivers/status` | Driver service status + single-controller session ownership |
| `kn://session/symbols` | Symbol search path/number of loaded modules/engine ready state |
| `kn://ti/stats` | TI ETW ring statistics and active state |
| `kn://snapshot/current` | Current in-memory snapshot baseline (when present) |
| `kn://audit/tail` | Last 50 lines of the write-audit JSONL |

All resources are returned as `application/json`.

### 6.4 Prompts (7)

| Name | Description | Args |
|------|------|------|
| `callback-audit` | Audit the kernel callback surface + flag off-module targets | `module` |
| `driver-surface-map` | Map a single driver's kernel footprint/attack surface | `driver` |
| `address-provenance` | Determine the identity and legitimacy of a kernel pointer | `address` |
| `minifilter-review` | Review minifilter callbacks for malicious filters | (none) |
| `hunt-triage` | Triage a process's user-mode injection/evasion | `pid` |
| `etw-infinityhook-check` | ETW/syscall tampering sweep | (none) |
| `wfp-surface` | Map the Windows Filtering Platform surface | (none) |

---

## 7. Functional Verification / Troubleshooting

Quick round-trip check (client):

```bash
claude mcp list                      # confirm connected
# in a Claude session: list tools -> call callbacks.list -> confirm the structured JSON result
```

| Symptom | Cause / Fix |
|------|-------------|
| Connection 401 | Token mismatch. Native client: reload `KNLIVEDBG_TOKEN` and reconnect. Claude Desktop/legacy client: restart its bridge so it rereads the protected endpoint file. |
| Connection 403 | (local) Connected with a non-loopback Host -> if remote, `--bind` is needed / (both) Browser context where Origin is non-loopback |
| Cannot connect from remote (timeout) | Firewall inbound blocked. Allow the port/client IP with `New-NetFirewallRule`. Confirm the server came up with `--bind <IP>` |
| `writes are disabled` | Read-only mode. **If already running, `mcp on --allow-write` is ignored** (prints `MCP server is already running`) -> first stop with `off`+Enter (engine loop) or `mcp off`, then relaunch with `mcp on <port> --allow-write [--bind <addr>]`. The saved token remains valid unless explicitly rotated or overridden |
| `engine busy; retry shortly` or `engine timeout` | tools/call arrives not as a JSON-RPC error code but as an `isError:true` CallToolResult. On wait-queue (8) saturation, `engine busy` (audit `engine-busy`); on exceeding the 30s engine wait, `engine timeout` (audit `tool-error`). Retry after the queue drains, or shorten/split the scan with `limit`/`count`; a larger client timeout does not extend this server limit. (`-32603` occurs only on the congested `resources/read` path) |
| Driver load failure | Test signing not enabled -> reboot after `bcdedit /set testsigning on` / running non-elevated |
| `symType=0 (SymNone)` | The symbol DLL bundle was not placed next to the EXE (see 2.1) |

---

## 8. Quick Reference

```text
# server (VM/target PC, knkd> prompt)
mcp on                                   # local, read-only
mcp on 51766 --bind 192.168.56.10        # remote, read-only
mcp on 51766 --allow-write --bind 192.168.56.10   # remote, write (VM snapshot recommended)
mcp status
mcp off                                  # or off + Enter in the engine loop

# client (Claude Code)
claude mcp add --transport http knlivedbg http://192.168.56.10:51766/mcp \
  --header "Authorization: Bearer $KNLIVEDBG_TOKEN"
claude mcp list
```

---

## 9. Prompt Recipes

Once connected, Claude auto-discovers the tools. **Just state your intent in natural language** and Claude picks and chains the tools — the real value is not in listing single tools but in the **correlation analysis** that weaves several tools together. Below are practical prompts per anti-cheat/kernel-forensics workflow and the tools brought to bear in each.

### 9.1 Orientation (inject context via resources)

```
I'm connected to the knlivedbg MCP. Read kn://session/info, kn://drivers/status, kn://modules/kernel,
and kn://session/symbols, then summarize the current driver session/ABI/write-arm state, the number of
loaded kernel modules, and whether symbols are ready, and classify the detection tools you can use by
purpose.
```
-> 4 resources + `tools/list`.

### 9.2 Process injection hunt

```
Investigate whether PID 4567 (the game client) shows traces of code injection. Cross-reference W+X /
private executable VADs, threads starting outside any module, queued APCs, and TI events, and lay out
the suspicious regions with their evidence, ordered by severity.
```
-> `process.find` -> `vad.list {wx,private,hiddenpte}` + `threads.list {apc,stacks}` + `ti.query {action:by, pid}`. (Or the `/mcp__knlivedbg__hunt-triage` prompt.)

### 9.3 Full kernel-hook scan

```
Scan SSDT/shadow-SSDT, the IDT, the SYSCALL MSRs (LSTAR etc.), and the control registers
(CR0.WP/SMEP/SMAP) for any hooking or per-CPU divergence, then narrow it down to only the entries
pointing outside the kernel image and attach which module each target belongs to.
```
-> `ssdt.scan` + `idt.scan` + `msr.check` + `cr.scan`, with `address.inspect` for each flagged address.

### 9.3b Leftover mapper / unbacked kernel code

Mapper-family coverage is layered. `mapper.list` leftover=0 means the ledgers
look clean (expected after stock kdmapper wipe), not that the payload is gone.

```
The original cheat driver is gone. Find leftover functional code in nonpaged
pool or independent pages, plus MmUnloadedDrivers / PiDDB / ci hash remnants.
Do not run a PFN walk unless I ask.
```
-> bookkeeping: `mapper.list`; orphan pages: `kpage.list`; hook-to-body:
`payload.scan` then `payload.inspect` on each unbacked address; staged pool PE:
`pool.scan_pe`. Loaded BYOVD while still mapped is `byovd.scan`. Set
`kpage.list` `deep=true` only when the operator asks.

### 9.4 Callback target verification (down to the code)

```
Enumerate the Ob callbacks with callbacks.list object, confirm each callback target address's module
with address.inspect, and if it is off-module or suspicious, decode the instructions at that address
with code.disasm to judge whether it is a normal callback prologue or a trampoline/hook.
```
-> `callbacks.list {scope:object}` -> `address.inspect` -> `code.disasm {address}`. (The earlier UCPD.sys case is now resolved read-only.)

### 9.5 Inline hook / patch detection (live vs clean)

```
Dump the first 32 bytes of nt!NtCreateFile with memory.read_virtual, and compare against the bytes of
the same function in a clean ntoskrnl copy of the same build to judge whether there is an inline hook
(jmp/patch). If both regions are in memory, pull only the mismatch offsets with memory.compare.
```
-> `symbol.search {mask:"nt!NtCreateFile"}` -> `memory.read_virtual` / `memory.compare`.

### 9.6 Call-table / IAT / vtable symbolization

```
From this driver's DRIVER_OBJECT dispatch-table address, resolve each slot to a symbol with
memory.read_pointers. If any slot points outside the nt module, combine it with the driver.integrity
result to judge dispatch hooking.
```
-> `driver.integrity {driver}` + `memory.read_pointers {address, width:8}`.

### 9.7 Locate globals by symbol -> inspect

```
Find the callback-list globals with symbol.search, e.g. x nt!*CallbackList*, then read each global with
memory.read_pointers to resolve the registered callback chain into symbols.
```
-> `symbol.search {mask:"nt!*CallbackList*"}` -> `memory.read_pointers`.

### 9.8 Manually-mapped driver / pool-staged PE

```
Hunt PEs staged in kernel big pool (including signature wipe), and compare loaded modules against the
LOLDrivers catalog with byovd.scan. For suspicious PEs, confirm the allocation context with pool.find,
the permissions with address.inspect, and even the entry bytes with code.disasm.
```
-> `pool.scan_pe {suspicious:true}` + `byovd.scan` + `pool.find` + `address.inspect` + `code.disasm`.

### 9.9 Physical memory / VA aliasing (bypass hooked mappings)

```
Translate this virtual address to a physical address with memory.translate (specify the process
context), then read that physical frame directly with memory.read_physical and compare whether the bytes
match the read via the VA. A mismatch suggests page remapping/copy-on-write evasion.
```
-> `memory.translate {address, pid}` -> compare `memory.read_physical` + `memory.read_virtual`.

### 9.10 EDR/AC callback/minifilter tampering

```
Audit the process/thread/image-load callbacks and minifilters, and flag callbacks not mapped to a
module, callbacks registered by suspicious modules, and abnormal altitudes.
```
-> `/mcp__knlivedbg__minifilter-review` or `callbacks.list` + `module.integrity`.

### 9.11 ETW/InfinityHook + WFP/ALPC/WNF surface

```
Sweep ETW logger/GetCpuClock tampering with etw.integrity and nmi.list, look at non-MS-owned
callouts with wfp.list, resolve kernel callout function pointers with wfp.kernel_callouts,
check csrss/lsass pairings with alpc.list, and suspicious WNF instances with wnf.list.
```
-> `etw.integrity` + `nmi.list` + `wfp.list` + `wfp.kernel_callouts` + `alpc.list` + `wnf.list`.

### 9.12 Threat-intel capture (TI subscription)

```
Start the Threat-Intelligence ETW subscription with ti.subscribe start (requires --allow-write), then
after a moment filter recent events by PID/pattern with ti.query and summarize the suspicious behavior.
When done, ti.subscribe stop.
```
-> `ti.subscribe {action:start}` -> `ti.query {action:recent/by/grep}` -> `ti.subscribe {action:stop}`. (start/stop require write mode; the controller must be PPL Antimalware for the ETW provider to open.)

### 9.13 Baseline -> delta detection

```
Take a clean baseline now with snapshot.capture, then show its current summary with snapshot.show.
(After running the game/cheat) show the callbacks/threads/VADs/pool allocations newly created
relative to the baseline with snapshot.diff, ordered by risk.
```
-> `snapshot.capture` -> `snapshot.show` -> (time passes) -> `snapshot.diff {risk:high}` or compare `kn://snapshot/current`.

### 9.14 Invoke an MCP prompt (playbook) directly

In Claude Code they appear as slash commands, or name them directly:
```
/mcp__knlivedbg__address-provenance   (address)
/mcp__knlivedbg__driver-surface-map   (driver)
/mcp__knlivedbg__hunt-triage          (pid)
/mcp__knlivedbg__callback-audit       (module)
/mcp__knlivedbg__etw-infinityhook-check
/mcp__knlivedbg__wfp-surface
/mcp__knlivedbg__minifilter-review
```
Or: "run the address-provenance prompt on 0xffff...".

### 9.15 Write mode (lab only, caution)

Exposed only when launched with `--allow-write`. **Opening writes while reading untrusted memory is a
confused-deputy risk — a VM snapshot before a write session is mandatory.**

```
# memory patch (analysis purpose)
Patch the 2 bytes at address 0xffff... to 90 90. Back up the original bytes before the change, and after
writing verify with a read-back.
-> memory.write_virtual {address, bytes}

# arbitrary-target PPL manipulation (e.g. PPL anti-cheat analysis)
Promote PID 1234 to ppl-wintcb. Record the PS_PROTECTION before the change and confirm with a readback.
-> process.set_protection {pid:1234, level:"ppl-wintcb"}   # returns before/after/verdict
Strip PID 1234's protection to none.
-> process.set_protection {pid:1234, level:"none"}

# memory dump
Dump 0x1000 bytes starting at 0xffff... to C:\lab\dump.bin, zero-filling unreadable chunks.
-> dump.raw {address, length, path, zerofill:true}

# TI ring export/clear
Export the current Threat-Intelligence ring to C:\lab\ti.jsonl, then clear the in-memory ring.
-> ti.export {path:"C:\\lab\\ti.jsonl"} -> ti.clear {}
```

### 9.16 Tips for getting the most out of Claude

- **Give concrete values**: specifying PID/module name/address makes the arguments precise. If you don't know them, resolve first with `process.find`/`symbol.search`.
- **Ask for cross-correlation**: "combine the VADs, threads, and TI and pull only the evidence pointing at the same region" — you get analysis, not a single listing.
- **Go read->confirm->code**: narrow down with `address.inspect` (identity) -> `memory.read_virtual` (bytes) -> `code.disasm` (instructions).
- **Slow scans**: `hunt.run`/full scans can exceed the 30s engine wait — narrow or split the scope with `limit`/`count`; raising only the client timeout does not extend it.
- **Audit trail**: check what the model called via `kn://audit/tail` or `mcp-audit-<port>.jsonl`.
