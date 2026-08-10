> English version (canonical): [MCP_SETUP.md](./MCP_SETUP.md)

# KnLiveDbg MCP 서버 설정 및 연결 가이드

이 문서는 KnLiveDbg의 MCP(Model Context Protocol) 서버를 **실제로 띄우고 Claude(Claude Code / Claude Desktop)에서 연결하는 운영 절차**를 다룬다. 설계 근거와 위협 모델은 [`MCP_SERVER_DESIGN.ko.md`](./MCP_SERVER_DESIGN.ko.md)를 참고한다.

- 서버 이름: `knlivedbg`  ·  서버 버전: `0.1.0`  ·  MCP 프로토콜: `2025-06-18`
- 전송: 인프로세스 Streamable HTTP(`http.sys`), 엔드포인트 경로 `/mcp`
- 기본 포트: `51766`  ·  인증: 기동 시마다 새로 발급되는 256-bit bearer 토큰
- 기본 노출: **loopback 전용**(`127.0.0.1` + `[::1]`). 네트워크 노출은 `--bind`로만 옵트인.

---

## 1. 핵심 개념: 어디서 무엇을 실행하나

MCP 서버는 **드라이버를 소유한 elevated KnLiveDbg.exe 안에 인프로세스로** 떠 있다. 따라서:

| 명령 | 실행 위치 | 형태 |
|------|-----------|------|
| `mcp on ...` | **분석 대상 PC/VM**(커널 RW가 일어나는 곳) | KnLiveDbg.exe의 `knkd>` 프롬프트 안 콘솔 명령 |
| `claude mcp add ...` | **클라이언트 PC**(Claude Code를 돌리는 곳) | 일반 셸 명령 (KnLiveDbg 밖) |

> 서버 PC와 클라이언트 PC가 같으면 loopback으로, 물리적으로 다른 PC면 `--bind`로 네트워크 노출 후 서버 PC의 IP로 연결한다.

---

## 2. 사전 준비 (서버 PC / VM)

### 2.1 산출물 묶음 복사

KnLiveDbg.exe는 **자신 옆의 파일들에 의존**한다. 다른 PC/VM으로 옮길 때는 다음을 같은 폴더에 둔다.

```text
KnLiveDbg.exe            <- 실행 파일
KnLiveDbg.sys            <- 메인 드라이버 (EXE 옆 필수)
KnLiveDbgProbe.sys       <- 선택: probe load 용 양성 대조 드라이버
dbghelp.dll, dbgeng.dll, dbgcore.dll, DbgModel.dll
msdia140.dll, symsrv.dll, srcsrv.dll, symsrv.yes   <- 심볼 런타임
```

가장 간단한 방법은 릴리스 zip을 통째로 옮기는 것이다(서버 PC가 아니라 빌드 PC에서):

```powershell
.\tools\release.ps1 -Configuration Release
# release\KnLiveDbg-<version>-Release-x64.zip 를 대상 PC로 복사해 압축 해제
```

> 심볼 DLL을 빠뜨리면 시작 시 `symType=0 (SymNone)`으로 떨어지며 커널 PDB 다운로드가 막힐 수 있다.

### 2.2 테스트 서명 활성화 (드라이버 로드용)

드라이버는 WDK `TestSign`으로 서명되므로, 대상 PC/VM에서 테스트 서명을 켜야 로드된다(관리자 콘솔, 1회):

```powershell
bcdedit /set testsigning on
# 재부팅 필요
```

### 2.3 관리자(elevated) 실행

```powershell
cd .\x64\Release
.\KnLiveDbg.exe
```

부팅 단계가 `[ OK ]`로 진행되고(elevation -> 단일 인스턴스 -> 심볼/DIA -> 드라이버 로드 -> device open -> ABI verify -> 심볼 초기화), 대시보드와 함께 `knkd>` 프롬프트가 뜬다.

---

## 3. 서버 띄우기 (`mcp on`)

`knkd>` 프롬프트에서 입력한다. 인자 순서는 자유다.

```text
mcp on [port] [--allow-write] [--bind <addr>]
mcp off        # 서버 중지 (엔진 루프 안에서는 off + Enter)
mcp status     # 현재 상태
```

### 3.1 옵션

| 옵션 | 의미 | 기본값 |
|------|------|--------|
| `<port>` (위치 인자) | 리스닝 포트. `0 < port < 65536`만 적용, 그 외는 무시 | `51766` |
| `--allow-write` (또는 `allow-write`) | Lab write 모드. write 툴 10종 등록 + 커널 write 무장 | 없음 = 읽기 전용 |
| `--bind <addr>` | 네트워크 노출. `<addr>`에 추가로 바인드 | 없음 = loopback 전용 |
| `--bind=<addr>` | 위와 동일(붙여 쓰는 형태) | 없음 |
| `--token <t>` | 고정 bearer 토큰 사용(영속), 자동 관리 토큰 대신 | auto |
| `--new-token` | 회전: 영속 토큰 폐기 후 새 랜덤 토큰 발급 | off |

`<addr>`에는 구체 IP(예: `192.168.56.10`) 또는 전체 인터페이스용 `0.0.0.0` / `*` / `+`(http.sys 강한 와일드카드 `+`로 매핑)를 줄 수 있다.

**권장 재연결 모델 (토큰 붙여넣기 없음):** Claude/Cursor에 `tools\mcp-bridge.ps1`을 **한 번만** 등록(`mcp client-setup`). 이후 세션은 `mcp on`만 하면 된다. 브리지가 `%LOCALAPPDATA%\kn-live-dbg\mcp-endpoint.json`을 읽어 현재 토큰으로 자동 연결한다.

**토큰 안정성.** bearer 토큰은 **재기동·포트 변경에도 유지**(기본은 포트별이 아닌 사용자 단위 파일). 결정 순서: `--token <t>` > `KNLIVEDBG_TOKEN` env > `%LOCALAPPDATA%\kn-live-dbg\mcp-token`(구버전 per-port 파일은 1회 마이그레이션) > 새 랜덤 발급(영속화). 회전은 `--new-token`(브리지가 자동 반영, 에이전트 설정 수정 불필요).

### 3.2 로컬(loopback) — 같은 PC

```text
knkd> mcp on
```

출력 예:

```text
MCP server started (loopback Streamable HTTP).
  url      : http://127.0.0.1:51766/mcp
  token    : 3f9c... (REUSED — AI agent re-register NOT required)
  tokenFile: %LOCALAPPDATA%\kn-live-dbg\mcp-token
  endpoint : %LOCALAPPDATA%\kn-live-dbg\mcp-endpoint.json  (bridge reads this every connect)
  write    : disabled (read-only)

  Preferred (no token paste on reconnect):
    mcp client-setup
```

이 시점부터 콘솔은 **MCP 엔진 루프**다. 중지하려면 `off` + Enter.

### 3.2.1 에이전트 1회 등록 (권장)

```text
knkd> mcp client-setup
knkd> mcp client-setup claude
knkd> mcp client-setup cursor
knkd> mcp client-setup codex
knkd> mcp client-setup grok
```

스니펫은 `%LOCALAPPDATA%\kn-live-dbg\clients\` 에도 기록된다.

| 에이전트 | 1회 등록 |
|------|---------------------------|
| **Claude Code** | `claude mcp add --transport stdio knlivedbg -- powershell.exe ... -File <bridge>` |
| **Cursor** | `clients\cursor-mcp.json` 내용을 Cursor MCP 설정에 병합 |
| **OpenAI Codex** | `codex mcp add knlivedbg -- powershell.exe ... -File <bridge>` 또는 `%USERPROFILE%\.codex\config.toml` 에 `codex-config.toml.snippet` 추가 |
| **Grok Build** | `grok mcp add knlivedbg -- powershell.exe ... -File <bridge>` 또는 `%USERPROFILE%\.grok\config.toml` 에 `grok-config.toml.snippet` 추가 |

이후 분석 세션은:

```text
knkd> mcp on
```

토큰을 에이전트 설정에 다시 넣을 필요 없음. `--new-token` 회전도 브리지가 자동 반영.

**Grok 네이티브 HTTP(선택, npx 불필요):** `grok-http.toml.snippet` + `mcp-load-env.ps1` 로 `${KNLIVEDBG_TOKEN}` 주입. 잦은 재연결은 브리지 권장.

### 3.3 원격(`--bind`) — 분리된 PC/VM

서버 PC에서 LAN IP를 먼저 확인한다:

```powershell
ipconfig    # 예: 192.168.56.10
```

그 IP로 바인드:

```text
knkd> mcp on 51766 --bind 192.168.56.10
```

출력에 `remote:` 줄과 네트워크 노출 경고가 추가로 찍힌다. 클라이언트는 이 `remote:` URL과 토큰을 쓴다.

```text
MCP server started (NETWORK Streamable HTTP).
  url   : http://127.0.0.1:51766/mcp
  remote: http://192.168.56.10:51766/mcp
  token : <복사해서 클라이언트에 사용>
  ...
  WARNING: this elevated kernel read/write endpoint is now reachable over the
           network. The bearer token is the ONLY barrier. Restrict access with a
           firewall rule (allow only the client IP) and use a trusted lab segment.
```

> `--bind 0.0.0.0`(전체 인터페이스)을 쓰면 어느 인터페이스 IP로 접속할지 도구가 알 수 없어 URL에 `<this-host-ip>` 플레이스홀더를 찍는다. 가능하면 **구체 IP를 지정**하라.

### 3.4 Write 모드

```text
knkd> mcp on 51766 --allow-write --bind 192.168.56.10
```

- 읽기 전용(기본): 엔진 진입 시 `SetWriteMode(false)`로 **커널 write 플래그 자체를 비무장**한다. write 툴은 등록되지 않으며, 호출 시 `writes are disabled; start the MCP server with --allow-write (lab mode)`로 거부된다.
- `--allow-write`: write 툴 10종이 노출되고 `SetWriteMode(true)`로 커널 write가 무장된다. 커널 메모리 write는 preflight/backup/verify-diff/audit 레일을 타고, 파일/링 작업은 backup/verify가 의미 없는 경우에도 게이트·감사·경고를 유지한다(인터랙티브 확인은 생략).
- **모드 전환 주의**: 서버가 이미 실행 중이면 `mcp on --allow-write`(또는 `--bind`/포트 변경)는 **무시**된다(`MCP server is already running on port N`만 출력). 플래그를 바꾸려면 먼저 `off`+Enter(엔진 루프) 또는 `mcp off`로 중지한 뒤 다시 띄운다. **토큰이 새로 발급되므로 클라이언트 헤더도 갱신**해야 한다.
- **권고**: write 세션 전 VM 스냅샷을 찍고, 분석 baseline(`snapshot.capture`)을 캡처하라. 격리 VM 전용이며 라이브 EDR/AC 박스에서는 절대 쓰지 않는다.

---

## 4. MCP 클라이언트 연결 (클라이언트 PC)

서버 콘솔이 출력한 **정확한 url/token**을 사용한다. 서버는 streamable HTTP를 쓰므로 `http` 전송을 지원하는 MCP 클라이언트는 바로 붙고, stdio만 지원하는 클라이언트는 `mcp-remote` 브리지를 쓴다.

### 4.1 Claude Code

```bash
# 로컬(같은 PC)
claude mcp add --transport http knlivedbg http://127.0.0.1:51766/mcp \
  --header "Authorization: Bearer <서버가_찍어준_token>"

# 원격(분리된 PC/VM) - 서버 PC의 IP 사용
claude mcp add --transport http knlivedbg http://192.168.56.10:51766/mcp \
  --header "Authorization: Bearer <서버가_찍어준_token>"
```

연결 확인:

```bash
claude mcp list
# knlivedbg 가 connected 로 보이면 성공
```

`.mcp.json`을 직접 쓸 경우(토큰은 **env 인다이렉션**, 평문 커밋 금지):

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

> `${KNLIVEDBG_TOKEN}`은 **클라이언트 측 권장 관례**다(서버가 이 환경변수를 읽지는 않는다 — 토큰은 서버가 매 `mcp on`마다 새로 발급). 클라이언트 셸에서 `export KNLIVEDBG_TOKEN=<token>`(PowerShell은 `$env:KNLIVEDBG_TOKEN="<token>"`)로 주입한다.

유용한 노브: per-server `timeout`(ms, 느린 스캔용 상향 — 진행 알림으로 연장되지 않음), `headersHelper`(접속 시 회전 토큰 발급), `alwaysLoad`.

### 4.2 Claude Desktop

`%APPDATA%\Claude\claude_desktop_config.json`에 동일한 `type: http` 항목을 넣는다. 네이티브 http를 미지원하는 빌드면 stdio 브리지를 쓴다:

```jsonc
{
  "mcpServers": {
    "knlivedbg": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "http://192.168.56.10:51766/mcp",
               "--header", "Authorization: Bearer ${KNLIVEDBG_TOKEN}"]
    }
  }
}
```

편집 후 Desktop을 완전히 재시작한다.

### 4.3 Codex CLI

Codex는 `~/.codex/config.toml`(또는 신뢰된 프로젝트의 `.codex/config.toml`)에서 MCP 설정을 읽고 streamable-HTTP MCP 서버를 직접 지원한다.

**HTTP (권장).** 토큰은 env 인다이렉션(`Authorization: Bearer <env 값>`으로 전송):

```toml
[mcp_servers.knlivedbg]
url = "http://192.168.56.10:51766/mcp"
bearer_token_env_var = "KNLIVEDBG_TOKEN"
tool_timeout_sec = 120   # 느린 스캔(hunt.run 등)을 위해 기본 60s보다 상향
```

그다음 Codex를 띄우는 셸에서 `export KNLIVEDBG_TOKEN=<token>`(PowerShell: `$env:KNLIVEDBG_TOKEN="<token>"`). 정적 헤더도 가능:

```toml
[mcp_servers.knlivedbg]
url = "http://192.168.56.10:51766/mcp"
http_headers = { "Authorization" = "Bearer <token-from-server>" }
```

> Codex 빌드가 HTTP로 연결되지 않으면 `~/.codex/config.toml` 최상위에 `experimental_use_rmcp_client = true`를 추가해 실험적 Rust MCP 클라이언트를 활성화한다.

**stdio 브리지 (범용 폴백).** HTTP를 못 쓰면 `mcp-remote`로 브리지:

```toml
[mcp_servers.knlivedbg]
command = "npx"
args = ["-y", "mcp-remote", "http://192.168.56.10:51766/mcp", "--header", "Authorization: Bearer ${KNLIVEDBG_TOKEN}"]
env = { KNLIVEDBG_TOKEN = "<token-from-server>" }
```

참고:
- `codex mcp add <name> --env VAR=VALUE -- <command>`는 CLI에서 **stdio** 서버를 등록한다. HTTP/`url` 서버는 `config.toml`을 직접 편집해 설정한다.
- 타임아웃: `startup_timeout_sec`(기본 10s), `tool_timeout_sec`(기본 60s). 서버는 단일 요청을 내부적으로 30s로 제한하지만 전체 시스템 `hunt.run`은 Codex tool 타임아웃을 넘길 수 있으니 `tool_timeout_sec`를 올린다.
- Codex는 비브라우저 클라이언트(`Origin` 미전송)이고 바인드 호스트로 접속하므로 bearer 토큰이 유일한 장벽 — Claude와 동일(§5).

> 아래 클라이언트는 모두 비브라우저 MCP 클라이언트라 bearer 토큰이 유일한 장벽(§5). **필드명 함정** 주의: Gemini는 `httpUrl`, Cline은 `type: "streamableHttp"`, Goose는 `uri` + `streamable_http`, Windsurf는 `serverUrl`을 쓴다. 엔드포인트는 평문 `http://`라 토큰이 암호화 없이 전송되니, 신뢰된 LAN/loopback에서만 쓰거나 TLS/SSH 터널로 감싼다.

### 4.4 Cursor

설정: `~/.cursor/mcp.json`(전역) 또는 `.cursor/mcp.json`(프로젝트 — 토큰 커밋 금지, env 보간 사용). Settings → MCP → "Add new MCP server"로도 추가 가능.

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

- `${env:KNLIVEDBG_TOKEN}`이 보간된다. Cursor가 상속하는 환경에 변수를 export한 뒤 Cursor를 재시작(기동 시 env를 읽음). 편집 후 Settings → MCP에서 서버 off/on 토글. 원격 HTTP용 CLI add 명령은 없음. 출처: [cursor.com/docs/mcp](https://cursor.com/docs/mcp).

### 4.5 VS Code (GitHub Copilot agent mode)

설정: `.vscode/mcp.json`(워크스페이스) 또는 Command Palette → "MCP: Open User Configuration". 최상위 `servers` 키, `type: "http"`. Copilot Chat **agent mode**에 노출.

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

- `${input:...}`은 한 번 묻고 토큰을 암호화 저장한다. `${env:KNLIVEDBG_TOKEN}`도 지원. CLI: `code --add-mcp "{\"name\":\"knlivedbg\",\"type\":\"http\",\"url\":\"http://<server-ip>:51766/mcp\",\"headers\":{\"Authorization\":\"Bearer ${env:KNLIVEDBG_TOKEN}\"}}"`. 항목 위 CodeLens에서 Start/Restart. 출처: [code.visualstudio.com MCP 문서](https://code.visualstudio.com/docs/copilot/customization/mcp-servers).

### 4.6 Gemini CLI

```bash
gemini mcp add --transport http --scope user \
  --header "Authorization: Bearer $KNLIVEDBG_TOKEN" \
  knlivedbg http://<server-ip>:51766/mcp
```

또는 `~/.gemini/settings.json` 편집 — **`httpUrl`** 사용(`url` 아님; `url`은 레거시 SSE 전송):

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

- `--transport http`는 필수(없으면 stdio로 간주되어 `--header` 무시). CLI는 셸에서 해석된 토큰을 settings.json에 그대로 박으니, 살아있는 `${KNLIVEDBG_TOKEN}` 플레이스홀더를 원하면 직접 편집. settings.json에 trailing comma 금지. 세션 내 `/mcp` 명령으로 확인. 출처: [gemini-cli MCP 문서](https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-server.md).

### 4.7 Cline

Cline 패널 → MCP Servers → "Remote Servers" 탭, 또는 `cline_mcp_settings.json` 편집(VS Code: `%APPDATA%\Code\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json`). **`type`은 반드시 `"streamableHttp"`(camelCase)** — 누락하거나 `"streamable-http"`로 쓰면 SSE로 폴백되어 streamable 엔드포인트에 405가 난다.

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

- 원격 헤더 값에는 env 보간이 **지원되지 않으니** 리터럴 토큰을 붙여넣고 파일을 비밀로 취급. 느린 스캔용으로 `timeout`(초) 상향. 출처: [docs.cline.bot](https://docs.cline.bot/mcp/connecting-to-a-remote-server).

### 4.8 Goose (Block)

`goose configure` → Add Extension → "Remote Extension (Streamable HTTP)" → 이름 `knlivedbg`, URI `http://<server-ip>:51766/mcp`, 헤더 `Authorization: Bearer ${KNLIVEDBG_TOKEN}` 추가. 또는 `~/.config/goose/config.yaml`(Windows: `%APPDATA%\Block\goose\config\config.yaml`) 편집 — **필드는 `uri`(`url` 아님), 타입은 `streamable_http`**:

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

- `${KNLIVEDBG_TOKEN}`은 Goose가 기동된 환경에서 보간된다(먼저 export). 편집 후 세션 재시작. `timeout`은 초 단위. 출처: [block.github.io/goose](https://block.github.io/goose/).

### 4.9 Windsurf (Cascade)

설정: `~/.codeium/windsurf/mcp_config.json`(유저 스코프 전용) 또는 Settings → Cascade → MCP Servers → "Add custom server". streamable HTTP는 **필드가 `serverUrl`(`url` 아님)**.

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

- `${env:KNLIVEDBG_TOKEN}`이 보간된다(변수 상속 위해 Windsurf 재시작). 편집 후 MCP 패널의 refresh 버튼 클릭. Cascade는 활성 MCP 툴을 총 100개로 제한 — 불필요한 툴은 비활성화. 출처: [docs.windsurf.com](https://docs.windsurf.com/plugins/cascade/mcp).

### 4.10 Hermes Agent (Nous Research)

Hermes는 JSON이 아니라 **YAML** 파일 하나로 설정한다 — `$HERMES_HOME` 아래의 `config.yaml`. HTTP 전송을 네이티브 지원(`url` + `headers`)하므로 바로 붙는다 — **`mcp-remote` 브리지 불필요**. 일부 UI가 보여주는 `{command, args, env}` 폼은 *stdio 전용* 하위 스키마이므로, 우리 HTTP 엔드포인트를 거기 욱여넣지 말 것.

설정 파일 위치:

| 플랫폼 | 경로 |
|------|------|
| Windows (네이티브 설치본) | `%LOCALAPPDATA%\hermes\config.yaml` (= `$HERMES_HOME`) |
| Linux / macOS / WSL | `~/.hermes/config.yaml` |

> Windows 설치본은 `HERMES_HOME=%LOCALAPPDATA%\hermes`로 잡는다. WebUI는 `~/.hermes\`를 볼 수 있어, 한쪽을 편집했는데 Hermes가 다른 쪽을 읽으면 서버를 "못 찾는다". 실제 경로는 `echo %HERMES_HOME%`(PowerShell은 `$env:HERMES_HOME`)로 확인한다.

최상위에 `mcp_servers` 블록을 추가한다. 갓 만든 config는 `mcp_servers: {}`(빈 매핑 = 서버 0개)로 시작하므로, `{}`를 들여쓴 블록으로 펼쳐서 채운다:

```yaml
mcp_servers:
  knlivedbg:
    url: "http://127.0.0.1:51766/mcp"        # 원격: http://<server-ip>:51766/mcp
    headers:
      Authorization: "Bearer <서버가_찍어준_token>"
    timeout: 300        # 느린 스캔(hunt.run 등) 대비 기본 120초보다 상향
    connect_timeout: 60
    # tools:            # 선택: 필요한 것만 노출(read 툴 46개는 컨텍스트를 많이 먹음)
    #   include: [process.find, vad.list, threads.list, callbacks.list, hunt.run]
```

CLI 등가(stdio용 `--command`/`--args`가 아니라 `--url`/`--header` 사용):

```bash
hermes mcp add knlivedbg --url "http://127.0.0.1:51766/mcp" \
  --header "Authorization: Bearer <서버가_찍어준_token>"
```

- Hermes는 시작 시 `config.yaml`을 한 번만 읽으므로 편집 후 **Hermes 재시작**. `hermes mcp list`로 확인(`knlivedbg`가 connected). 헤더 env 보간은 보장되지 않아 보통 토큰 원문이 YAML에 들어가므로, 파일을 비밀로 다루고 커밋하지 말 것.
- 빌드가 오래돼 `url`을 거부하면 stdio `mcp-remote` 브리지로 폴백한다(`command: npx`, `args: [-y, mcp-remote, <url>, --header, "Authorization: Bearer <token>"]`). Windows에서는 PATH에 Node/`npx`가 있어야 하며, 이게 없는 게 "서버 못 찾음"의 흔한 원인이다. 출처: [Hermes MCP config reference](https://hermes-agent.nousresearch.com/docs/reference/mcp-config-reference).

### 4.11 토큰 취급 주의

- 토큰은 커널 RW 엔드포인트를 인증한다. **project-scope `.mcp.json`에 평문으로 붙여넣어 커밋하지 말 것.** user-scope 설정 + `${KNLIVEDBG_TOKEN}` 환경변수를 쓴다.
- 토큰은 **재기동해도 유지**된다(§3.1): 클라이언트를 한 번 등록하면 매 `mcp on`마다 다시 추가할 필요 없다. `--new-token`(회전) 또는 다른 `--token`/`KNLIVEDBG_TOKEN`을 줄 때만 바뀌므로, 그때만 클라이언트를 갱신한다.
- env 기반 end-to-end 안정성을 원하면 **서버 호스트(서버가 읽음, 우선순위 #2)와 클라이언트 양쪽에** 동일한 `KNLIVEDBG_TOKEN`을 설정한다 — 그러면 토큰이 디스크에 전혀 남지 않는다.

---

## 5. 보안 모델 (연결이 막힐 때 이해용)

서버는 JSON-RPC 처리 전에 다음 전송 게이트를 통과시킨다:

1. **Bearer 토큰**(상수 시간 비교): `Authorization: Bearer <token>` 불일치 시 401. 실제 인증 경계.
2. **Host 검사**: loopback 전용 모드(기본)에서는 Host가 `127.0.0.1`/`localhost`/`[::1]`/`::1`이 아니면 403(DNS-rebinding 방어). `--bind` 원격 모드에서는 이 검사를 건너뛴다(원격 Host 수용).
3. **Origin 검사**: Origin 헤더가 **존재하는데** loopback authority가 아니면 403. 부재/빈 Origin은 허용(비브라우저 MCP 클라이언트는 Origin 미전송). **이 검사는 바인드 모드와 무관하게 항상 적용**되어 DNS-rebinding을 막는다.
4. **Write 게이트**: `--allow-write` 없이는 write 툴 미노출 + 커널 플래그 비무장.

원격 노출 시 토큰이 유일한 장벽이므로, 서버 PC 방화벽에서 **클라이언트 IP만 인바운드 허용**을 권장한다(관리자 PowerShell):

```powershell
New-NetFirewallRule -DisplayName "knlivedbg-mcp" -Direction Inbound `
  -Protocol TCP -LocalPort 51766 -RemoteAddress <클라이언트IP> -Action Allow
```

### 5.1 감사 로그(audit)

`mcp on` 동안 항상 켜진다(`ai audit` 토글과 독립). 모든 요청을 append-only JSONL 한 줄로 기록:

- 경로: `<exeDir>\.kn-live-dbg\mcp-audit-<port>.jsonl`
- 필드: `ts`(UTC), `session`, `peerPort`, `method`, `tool`, `args`(512자 절단), `decision`, `isError`, `resultBytes`, `writeArmed`
- `decision` 값: `ok` / `unknown-tool` / `writes-disabled` / `engine-busy` / `tool-error` / `unknown-resource` / `session-open`
- 마지막 50줄은 리소스 `kn://audit/tail`로도 노출된다.

---

## 6. 제공 기능 카탈로그

### 6.1 읽기 툴 (46종, `--allow-write` 불필요 — 단 `ti.subscribe` start/stop 제외)

| 툴 | 설명 | 주요 인자 (별도 표기 외 모두 선택) |
|-----|------|----------------------|
| `process.find` | 이미지명/PID/EPROCESS로 프로세스 찾기 | `image`, `pid`, `eprocess` |
| `process.describe` | `_EPROCESS` 기술(PID/DTB/PEB/threads/parent) | `source`, `pid`, `eprocess`, `fields` |
| `type.describe` | 주소/프로세스에서 커널 구조 덤프(dt) | `source`, `address`, `type`, `fields` |
| `callbacks.list` | 커널 콜백 열거(object/registry/process/thread/imageload/minifilter) | `scope`, `module` |
| `wfp.list` | WFP provider/sublayer/callout/filter/layer 열거 | `scope`, `module`, `provider`, `layer` |
| `wfp.kernel_callouts` | `netio.sys`에서 커널 WFP classify/notify/flowDelete 포인터 해석 | (없음) |
| `alpc.list` | ALPC 포트/연결 열거 | `scope`, `name`, `pid` |
| `vad.list` | VAD 열거(W+X/private/hidden-PTE/DKOM 체크) | `pid`, `image`, `eprocess`, `exec`, `private`, `wx`, `pe`, `hiddenpte`, `dkom`, `summary`, `limit` |
| `threads.list` | 스레드/시작주소/APC/스택 증거 | `pid`, `image`, `eprocess`, `apc`, `stacks`, `limit` |
| `etw.integrity` | ETW logger/GetCpuClock 무결성(InfinityHook) | (없음) |
| `nmi.list` | 등록된 NMI 콜백 열거 | `scope` |
| `fwtable.list` | 펌웨어 테이블 provider 열거 | `scope`, `module`, `provider`, `signature` |
| `pool.find` | 커널 big pool 할당 열거(tag/size/addr/W+X) | `tag`, `min`, `max`, `addr`, `limit`, `paged`, `annotate`, `wx` |
| `address.inspect` | 가상주소 검사(페이지테이블 워크/권한/소유 모듈) | `address`, `va`, `symbol` |
| `wnf.decode` | WNF state-name 해시 디코드 | `hash`, `state`, `state_name` |
| `wnf.list` | 라이브 WNF 인스턴스/후보/리스트 열거 | `scope` |
| `ti.query` | Threat-Intelligence ETW 링 질의(recent/stats/by/grep) | `action`, `count`, `pid`, `task`, `pattern` |
| `timeline.status` | in-memory evidence timeline 카운터와 용량 보고 | (없음) |
| `timeline.query` | 수집된 timeline 이벤트를 source/domain/PID/limit/order로 질의 | `source`, `domain`, `pid`, `limit`, `order` |
| `timeline.export` | 수집된 timeline 이벤트를 디스크 기록 없이 JSONL 텍스트로 반환 | `source`, `domain`, `pid`, `limit`, `order` |
| `timeline.reconcile` | 수집된 timeline 증거를 snapshot baseline 또는 JSON 파일과 비교 | `path`, `snapshot`, `source`, `domain`, `pid`, `limit` |
| `graph.query` | 수집된 timeline 이벤트에서 process/image/domain/source 그래프 파생 | `source`, `domain`, `image`, `pid`, `limit`, `order` |
| `module.integrity` | 로드 모듈 PE/섹션 무결성 + W+X | `module`, `target`, `limit`, `summary`, `verbose`, `headers`, `sections`, `wx`, `mismatch` |
| `driver.integrity` | `DRIVER_OBJECT` 디스패치 테이블 무결성 | `driver`, `target`, `limit` |
| `ssdt.scan` | SSDT/shadow-SSDT 시스템콜 훅 탐지 | (없음) |
| `idt.scan` | IDT 인터럽트 게이트 훅/CPU별 divergence | (없음) |
| `cr.scan` | 컨트롤 레지스터 검사(CR0.WP/SMEP/SMAP/CPU별) | (없음) |
| `msr.check` | SYSCALL MSR(LSTAR/CSTAR/STAR/FMASK/EFER) 훅 | (없음) |
| `vbs.scan` | VBS/HVCI/CI/하이퍼바이저/Secure Kernel/trustlet | (없음) |
| `byovd.scan` | 로드 모듈을 로컬 BYOVD/LOLDrivers 카탈로그와 대조(네트워크/서브프로세스 없음) | (없음) |
| `byovd.status` | 로컬 BYOVD 카탈로그 age/source count/YARA rule 가용성 보고 | (없음) |
| `pool.scan_pe` | 커널 big pool에 스테이징된 PE 헌팅(서명 wipe 포함) | `tag`, `limit`, `suspicious` |
| `hunt.run` | 전체 시스템 유저모드 이상 헌트(인젝션/VAD/PTE/threads/APC/driver/WFP/TI) | `mode` |
| `snapshot.capture` | 동일 부팅 증거 baseline 캡처(in-memory, 디스크 미기록) | `name` |
| `snapshot.show` | 현재 snapshot baseline 또는 snapshot JSON 파일 표시(summary + structured JSON) | `source`, `path`, `domains`, `warnings` |
| `snapshot.diff` | 세션 baseline과 라이브 캡처 비교(또는 두 스냅샷 파일) | `old`, `new`, `domain`, `risk`, `limit`, `summary` |
| `memory.read_virtual` | 가상주소 바이트 읽기(db/dq) — hex + unreadable 마스크(structured) | `address`/`va`/`symbol`, `width`(1/2/4/8), `count`, `process` |
| `memory.read_physical` | 물리주소 바이트 읽기(!db/!dq) — 후킹된 VA 매핑 우회(structured) | `physical_address`(필수), `width`, `count` |
| `memory.search` | VA 범위에서 정수 값/패턴 검색(s) | `address`(필수), `length`(필수), `value`(필수), `width` |
| `memory.translate` | VA→PA 변환 + 페이지테이블 워크(vtop), 프로세스별 DTB | `address`/`va`/`symbol`, `process`/`cr3`, `length` |
| `memory.probe` | 주소 readable/writable 점검(query) | `address`/`va`/`symbol`, `length` |
| `code.disasm` | 주소/함수 디스어셈블(u/uf) | `address`/`symbol`, `count`, `function`(bool) |
| `symbol.search` | 와일드카드 심볼→주소 열거(x `mod!mask`) | `mask`(필수), `limit` |
| `memory.read_pointers` | 포인터 테이블 슬롯을 최근접 심볼로 해석(dps/dds/dqs) — 콜테이블/vtable/IAT 훅 헌팅 | `address`/`va`/`symbol`, `width`(4/8), `count` |
| `memory.compare` | 두 가상 범위 byte 비교 + 불일치 오프셋(c) — 인라인 훅/패치 탐지 | `address1`(필수), `address2`(필수), `length`(필수) |
| `ti.subscribe` | TI ETW 구독 제어(`action`=start/stop/status) — **start/stop은 `--allow-write` 필요** | `action` |

> `snapshot.capture`/`snapshot.diff`는 MCP 경로에서 **디스크에 파일을 쓰지 않는다**(in-memory). baseline은 `kn://snapshot/current`로 읽거나 `snapshot.show`로 summary + structuredContent를 받는다. `memory.read_virtual`/`read_physical`/`symbol.search`/`snapshot.show`/`timeline.status`/`timeline.query`/`timeline.reconcile`/`graph.query`는 structuredContent(JSON)를 반환하고, 나머지 신규 툴은 텍스트 콘텐츠를 반환한다. `timeline.export`는 MCP 응답에 JSONL 텍스트를 반환하며 파일을 쓰지 않는다. `ti.subscribe`는 읽기 카테고리지만 ETW 세션을 시작/중지하는 부수효과 때문에 start/stop만 write 모드를 요구한다(status는 항상 가능, `kn://ti/stats`와 동일 데이터).

### 6.2 Write 툴 (10종, `--allow-write` 필수)

| 툴 | 설명 | 필수 인자 | 선택 인자 |
|-----|------|-----------|-----------|
| `memory.write_virtual` | 커널 가상주소에 바이트 쓰기(e*) | `address`, `bytes` | `width`, `process` |
| `memory.write_physical` | 물리주소에 바이트 쓰기(pe*) | `physical_address`, `bytes` | — |
| `memory.fill` | 커널 범위를 패턴으로 채움 | `address`, `length`, `pattern` | — |
| `memory.move` | 커널 범위 복사(src->dest) | `source`, `dest`, `length` | — |
| `type.set_field` | 주소의 구조체 필드 설정(setfield) | `address`, `type`, `field`, `value` | — |
| `process.set_protection` | 임의 타깃 PS_PROTECTION 설정 (PPL/PP) | `level`(none/ppl-antimalware/ppl-lsa/ppl-windows/ppl-wintcb/pp-windows/pp-wintcb/pp-winsystem) | `pid`(미지정=self) |
| `ti.export` | 현재 Threat-Intelligence ETW 링을 JSONL로 내보내기 | `path` | — |
| `ti.clear` | 인메모리 Threat-Intelligence ETW 링 비우기 | — | — |
| `dump.raw` | 커널 범위를 지정 파일 경로로 덤프 | `address`, `length`, `path` | `zerofill` |
| `dump.pe` | 메모리에서 온디스크 PE 이미지 재구성 | `address`, `path` | — |

> **주의 — `process.set_protection` 임의 타깃**: `pid`로 임의 프로세스의 PPL/PP를 올리거나(예: 프로세스를 un-killable PP로 승격) 벗길 수 있다(예: PPL 안티치트/AV 무력화). 드라이버 IOCTL은 임의 타깃을 지원하며(write-ack + write 모드로만 게이트), `--allow-write` lab 모드 전용이다. 변경 전 대상 프로세스 baseline·VM 스냅샷을 권장한다. 응답에 before/after/requested 바이트 + 검증(readback) 결과가 포함된다.

### 6.3 리소스 (8종)

| URI | 내용 |
|-----|------|
| `kn://session/info` | 드라이버 세션/ABI/소유권/write-arm 상태 |
| `kn://capabilities` | 활성 MCP 툴과 인자 스키마(전송 측에서 직접 제공) |
| `kn://modules/kernel` | 로드 커널 모듈 목록(name/base/size) — name->address 맵 |
| `kn://drivers/status` | 드라이버 서비스 상태 + 단일 컨트롤러 세션 소유권 |
| `kn://session/symbols` | 심볼 검색 경로/로드 모듈 수/엔진 ready 상태 |
| `kn://ti/stats` | TI ETW 링 통계와 활성 상태 |
| `kn://snapshot/current` | 현재 인메모리 snapshot baseline(있을 때) |
| `kn://audit/tail` | write-audit JSONL 마지막 50줄 |

모든 리소스는 `application/json`으로 반환된다.

### 6.4 프롬프트 (7종)

| 이름 | 설명 | 인자 |
|------|------|------|
| `callback-audit` | 커널 콜백 표면 감사 + 모듈 외 타깃 플래그 | `module` |
| `driver-surface-map` | 단일 드라이버의 커널 footprint/공격 표면 매핑 | `driver` |
| `address-provenance` | 커널 포인터의 정체와 정당성 판정 | `address` |
| `minifilter-review` | minifilter 콜백에서 악성 필터 검토 | (없음) |
| `hunt-triage` | 프로세스의 유저모드 인젝션/회피 분류 | `pid` |
| `etw-infinityhook-check` | ETW/시스템콜 변조 스윕 | (없음) |
| `wfp-surface` | Windows Filtering Platform 표면 매핑 | (없음) |

---

## 7. 동작 확인 / 트러블슈팅

빠른 왕복 점검(클라이언트):

```bash
claude mcp list                      # connected 확인
# Claude 세션에서: tools 목록 -> callbacks.list 호출 -> 결과 구조화 JSON 확인
```

| 증상 | 원인 / 해결 |
|------|-------------|
| 연결이 401 | 토큰 불일치. 서버가 새로 찍은 토큰으로 클라이언트 헤더 갱신 |
| 연결이 403 | (로컬) loopback이 아닌 Host로 접속 → 원격이면 `--bind` 필요 / (양쪽) Origin이 비-loopback인 브라우저 컨텍스트 |
| 원격에서 접속 불가(타임아웃) | 방화벽 인바운드 차단. `New-NetFirewallRule`로 포트/클라이언트 IP 허용. 서버가 `--bind <IP>`로 떴는지 확인 |
| `writes are disabled` | 읽기 전용 모드. **이미 실행 중이면 `mcp on --allow-write`는 무시됨**(`MCP server is already running` 출력) → 먼저 `off`+Enter(엔진 루프) 또는 `mcp off`로 중지한 뒤 `mcp on <port> --allow-write [--bind <addr>]`로 재기동. 토큰이 새로 발급되니 클라이언트 헤더도 갱신 |
| `engine busy; retry shortly` 또는 `engine timeout` | tools/call은 JSON-RPC 에러코드가 아니라 `isError:true` CallToolResult로 옴. 대기 큐(8개) 포화 시 `engine busy`(audit `engine-busy`), 30초 요청 타임아웃 초과(긴 스캔) 시 `engine timeout`(audit `tool-error`). 클라이언트 per-server `timeout` 상향 또는 `limit`/`count`로 스캔 단축. (`-32603`은 `resources/read` 혼잡 경로에서만 발생) |
| 드라이버 로드 실패 | 테스트 서명 미활성 → `bcdedit /set testsigning on` 후 재부팅 / 비-elevated 실행 |
| `symType=0 (SymNone)` | 심볼 DLL 묶음을 EXE 옆에 두지 않음(2.1 참고) |

---

## 8. 빠른 참조

```text
# 서버(VM/대상 PC, knkd> 프롬프트)
mcp on                                   # 로컬, 읽기 전용
mcp on 51766 --bind 192.168.56.10        # 원격, 읽기 전용
mcp on 51766 --allow-write --bind 192.168.56.10   # 원격, write (VM 스냅샷 권장)
mcp status
mcp off                                  # 또는 엔진 루프에서 off + Enter

# 클라이언트(Claude Code)
claude mcp add --transport http knlivedbg http://192.168.56.10:51766/mcp \
  --header "Authorization: Bearer $KNLIVEDBG_TOKEN"
claude mcp list
```

---

## 9. 프롬프트 레시피

Claude는 연결되면 도구를 자동 발견한다. **자연어로 의도만 말하면** Claude가 도구를 골라 체이닝한다 — 진짜 가치는 단일 도구 나열이 아니라 여러 도구를 엮은 **상관 분석**에 있다. 아래는 안티치트/커널 포렌식 워크플로별 실전 프롬프트와 그때 동원되는 도구다.

### 9.1 오리엔테이션 (리소스로 맥락 주입)

```
knlivedbg MCP에 연결돼 있어. kn://session/info, kn://drivers/status, kn://modules/kernel,
kn://session/symbols 를 읽어서 지금 드라이버 세션/ABI/write-arm 상태, 로드된 커널 모듈
수, 심볼 ready 여부를 요약하고, 네가 쓸 수 있는 탐지 도구를 용도별로 분류해줘.
```
→ 리소스 4종 + `tools/list`.

### 9.2 프로세스 인젝션 헌트

```
PID 4567(게임 클라이언트)에 코드 인젝션 흔적이 있는지 조사해줘. W+X / private executable
VAD, 모듈 밖에서 시작되는 스레드, 큐된 APC, TI 이벤트를 교차로 보고 의심 영역을 근거와
함께 severity 순으로 정리해줘.
```
→ `process.find` → `vad.list {wx,private,hiddenpte}` + `threads.list {apc,stacks}` + `ti.query {action:by, pid}`. (또는 `/mcp__knlivedbg__hunt-triage` 프롬프트.)

### 9.3 커널 훅 전수 스캔

```
SSDT/shadow-SSDT, IDT, SYSCALL MSR(LSTAR 등), 컨트롤 레지스터(CR0.WP/SMEP/SMAP)에 후킹이나
CPU별 divergence가 있는지 전부 스캔하고, 커널 이미지 밖을 가리키는 항목만 추려서 그 타깃이
어느 모듈인지까지 붙여줘.
```
→ `ssdt.scan` + `idt.scan` + `msr.check` + `cr.scan`, 플래그된 주소마다 `address.inspect`.

### 9.4 콜백 타깃 검증 (코드까지 확인)

```
callbacks.list object 로 Ob 콜백을 열거하고, 각 콜백 타깃 주소를 address.inspect 로 모듈
확인한 뒤, 모듈 밖이거나 의심스러우면 code.disasm 로 그 주소의 명령어를 디코드해서 정상
콜백 프롤로그인지 트램폴린/훅인지 판정해줘.
```
→ `callbacks.list {scope:object}` → `address.inspect` → `code.disasm {address}`. (이전 UCPD.sys 케이스가 이제 read-only로 완결.)

### 9.5 인라인 훅 / 패치 탐지 (라이브 vs 클린)

```
nt!NtCreateFile 의 첫 32바이트를 memory.read_virtual 로 덤프하고, 동일 빌드의 클린 ntoskrnl
사본에서 같은 함수 바이트와 비교해 인라인 훅(jmp/패치) 여부를 판정해줘. 두 영역이 메모리에
있으면 memory.compare 로 불일치 오프셋만 뽑아줘.
```
→ `symbol.search {mask:"nt!NtCreateFile"}` → `memory.read_virtual` / `memory.compare`.

### 9.6 콜테이블 / IAT / vtable 심볼라이즈

```
이 드라이버의 DRIVER_OBJECT 디스패치 테이블 주소에서 memory.read_pointers 로 각 슬롯을
심볼로 해석해줘. nt 모듈 밖을 가리키는 슬롯이 있으면 driver.integrity 결과와 합쳐서
디스패치 후킹을 판정해줘.
```
→ `driver.integrity {driver}` + `memory.read_pointers {address, width:8}`.

### 9.7 심볼로 글로벌 위치 찾기 → 검사

```
x nt!*CallbackList* 같은 식으로 콜백 리스트 글로벌들을 symbol.search 로 찾고, 각 글로벌을
memory.read_pointers 로 읽어 등록된 콜백 체인을 심볼로 풀어줘.
```
→ `symbol.search {mask:"nt!*CallbackList*"}` → `memory.read_pointers`.

### 9.8 수동 매핑 드라이버 / 풀 스테이징 PE

```
커널 big pool에 스테이징된 PE(서명 wipe 포함)를 헌팅하고, byovd.scan 으로 로드된 모듈을
LOLDrivers 카탈로그와 대조해줘. 의심 PE는 pool.find 로 할당 맥락, address.inspect 로 권한,
code.disasm 로 엔트리 바이트까지 확인.
```
→ `pool.scan_pe {suspicious:true}` + `byovd.scan` + `pool.find` + `address.inspect` + `code.disasm`.

### 9.9 물리 메모리 / VA 별칭 (후킹된 매핑 우회)

```
이 가상주소를 memory.translate 로 물리주소로 변환하고(프로세스 컨텍스트 명시), 그 물리
프레임을 memory.read_physical 로 직접 읽어서 VA 경유 read와 바이트가 일치하는지 비교해줘.
불일치면 페이지 리매핑/copy-on-write 회피 의심.
```
→ `memory.translate {address, pid}` → `memory.read_physical` + `memory.read_virtual` 비교.

### 9.10 EDR/AC 콜백·미니필터 변조

```
프로세스/스레드/이미지로드 콜백과 미니필터를 감사해서, 모듈에 매핑되지 않거나 의심 모듈이
등록한 콜백, 비정상 altitude를 플래그해줘.
```
→ `/mcp__knlivedbg__minifilter-review` 또는 `callbacks.list` + `module.integrity`.

### 9.11 ETW/InfinityHook + WFP/ALPC/WNF 표면

```
etw.integrity 와 nmi.list 로 ETW logger/GetCpuClock 변조를 스윕하고, wfp.list 로 비-MS
소유 callout을 보고, wfp.kernel_callouts 로 커널 callout 함수 포인터를 해석하고,
alpc.list 로 csrss/lsass 페어링, wnf.list 로 의심 WNF 인스턴스를 함께 봐줘.
```
→ `etw.integrity` + `nmi.list` + `wfp.list` + `wfp.kernel_callouts` + `alpc.list` + `wnf.list`.

### 9.12 위협 인텔 캡처 (TI 구독)

```
ti.subscribe start 로 Threat-Intelligence ETW 구독을 시작하고(--allow-write 필요), 잠시 후
ti.query 로 최근 이벤트를 PID/패턴으로 필터해서 의심 행위를 요약해줘. 끝나면 ti.subscribe
stop.
```
→ `ti.subscribe {action:start}` → `ti.query {action:recent/by/grep}` → `ti.subscribe {action:stop}`. (start/stop은 write 모드 필요; 컨트롤러가 PPL Antimalware여야 ETW provider가 열림.)

### 9.13 베이스라인 → 델타 탐지

```
지금 snapshot.capture 로 클린 baseline을 잡고 snapshot.show 로 현재 요약을 보여줘.
(게임/치트 실행 후) snapshot.diff 로 baseline 대비 새로 생긴 콜백/스레드/VAD/풀 할당을
risk 순으로 보여줘.
```
→ `snapshot.capture` → `snapshot.show` → (시간 경과) → `snapshot.diff {risk:high}` 또는 `kn://snapshot/current` 대조.

### 9.14 MCP 프롬프트(플레이북) 직접 호출

Claude Code에서 슬래시 커맨드로 뜨거나 이름으로 지목:
```
/mcp__knlivedbg__address-provenance   (address)
/mcp__knlivedbg__driver-surface-map   (driver)
/mcp__knlivedbg__hunt-triage          (pid)
/mcp__knlivedbg__callback-audit       (module)
/mcp__knlivedbg__etw-infinityhook-check
/mcp__knlivedbg__wfp-surface
/mcp__knlivedbg__minifilter-review
```
또는: "address-provenance 프롬프트를 0xffff... 로 돌려줘".

### 9.15 Write 모드 (lab 전용, 주의)

`--allow-write`로 띄운 경우에만 노출된다. **신뢰 못 할 메모리를 읽으며 write를 여는 건
confused-deputy 리스크 — write 세션 전 VM 스냅샷 필수.**

```
# 메모리 패치 (분석 목적)
0xffff... 주소의 2바이트를 90 90 으로 패치해줘. 변경 전 바이트를 백업하고, 쓰고 나서
read-back으로 검증해줘.
→ memory.write_virtual {address, bytes}

# 임의 타깃 PPL 조작 (예: PPL anti-cheat 분석)
PID 1234를 ppl-wintcb 로 승격해줘. 변경 전 PS_PROTECTION을 기록하고 readback으로 확인.
→ process.set_protection {pid:1234, level:"ppl-wintcb"}   # before/after/verdict 반환
PID 1234의 보호를 none 으로 벗겨줘.
→ process.set_protection {pid:1234, level:"none"}

# 메모리 덤프
0xffff... 부터 0x1000 바이트를 C:\lab\dump.bin 으로 뜨고, 읽기 실패 chunk는 zero-fill 해줘.
→ dump.raw {address, length, path, zerofill:true}

# TI 링 export/clear
현재 Threat-Intelligence 링을 C:\lab\ti.jsonl 로 내보낸 뒤 인메모리 링을 비워줘.
→ ti.export {path:"C:\\lab\\ti.jsonl"} → ti.clear {}
```

### 9.16 Claude를 잘 끌어내는 팁

- **구체값을 줘라**: PID/모듈명/주소를 명시하면 인자가 정확해진다. 모르면 `process.find`/`symbol.search`로 먼저 해석.
- **교차 상관을 요구하라**: "VAD와 스레드와 TI를 합쳐 같은 영역을 가리키는 증거만 추려" — 단일 나열이 아닌 분석이 나온다.
- **read→확인→코드 순으로**: `address.inspect`(정체) → `memory.read_virtual`(바이트) → `code.disasm`(명령어)로 좁혀라.
- **느린 스캔**: `hunt.run`/전수 스캔은 30초 요청 타임아웃을 넘길 수 있다 — 클라이언트 `timeout` 상향 또는 `limit`/`count`로 범위 축소.
- **감사 추적**: 모델이 무엇을 호출했는지는 `kn://audit/tail` 또는 `mcp-audit-<port>.jsonl`로 확인.
