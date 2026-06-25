# KnLiveDbg MCP 서버 설정 및 연결 가이드

이 문서는 KnLiveDbg의 MCP(Model Context Protocol) 서버를 **실제로 띄우고 Claude(Claude Code / Claude Desktop)에서 연결하는 운영 절차**를 다룬다. 설계 근거와 위협 모델은 [`MCP_SERVER_DESIGN.md`](./MCP_SERVER_DESIGN.md)를 참고한다.

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
| `--allow-write` (또는 `allow-write`) | Lab write 모드. write 툴 8종 등록 + 커널 write 무장 | 없음 = 읽기 전용 |
| `--bind <addr>` | 네트워크 노출. `<addr>`에 추가로 바인드 | 없음 = loopback 전용 |
| `--bind=<addr>` | 위와 동일(붙여 쓰는 형태) | 없음 |

`<addr>`에는 구체 IP(예: `192.168.56.10`) 또는 전체 인터페이스용 `0.0.0.0` / `*` / `+`(http.sys 강한 와일드카드 `+`로 매핑)를 줄 수 있다.

### 3.2 로컬(loopback) — 같은 PC

```text
knkd> mcp on
```

출력 예:

```text
MCP server started (loopback Streamable HTTP).
  url   : http://127.0.0.1:51766/mcp
  token : 3f9c... (64 hex chars)
  write : disabled (read-only)
  audit : <exeDir>\.kn-live-dbg\mcp-audit-51766.jsonl
  claude code: claude mcp add --transport http knlivedbg http://127.0.0.1:51766/mcp --header "Authorization: Bearer 3f9c..."
  the engine loop starts now; type 'off' + Enter here to stop.
```

이 시점부터 콘솔은 **MCP 엔진 루프**다. 중지하려면 `off` + Enter.

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
- `--allow-write`: write 툴 8종이 노출되고 `SetWriteMode(true)`로 무장된다. 모든 write는 preflight/backup/verify-diff/audit 레일을 거친다(인터랙티브 확인은 생략).
- **모드 전환 주의**: 서버가 이미 실행 중이면 `mcp on --allow-write`(또는 `--bind`/포트 변경)는 **무시**된다(`MCP server is already running on port N`만 출력). 플래그를 바꾸려면 먼저 `off`+Enter(엔진 루프) 또는 `mcp off`로 중지한 뒤 다시 띄운다. **토큰이 새로 발급되므로 클라이언트 헤더도 갱신**해야 한다.
- **권고**: write 세션 전 VM 스냅샷을 찍고, 분석 baseline(`snapshot.capture`)을 캡처하라. 격리 VM 전용이며 라이브 EDR/AC 박스에서는 절대 쓰지 않는다.

---

## 4. Claude 연결 (클라이언트 PC)

서버 콘솔이 출력한 **정확한 url/token**을 사용한다.

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

### 4.3 토큰 취급 주의

- 토큰은 커널 RW 엔드포인트를 인증한다. **project-scope `.mcp.json`에 평문으로 붙여넣어 커밋하지 말 것.** user-scope 설정 + `${KNLIVEDBG_TOKEN}` 환경변수를 쓴다.
- 토큰은 매 `mcp on`마다 바뀐다. 서버를 재기동하면 클라이언트 토큰도 갱신해야 한다.

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

### 6.1 읽기 툴 (38종, `--allow-write` 불필요 — 단 `ti.subscribe` start/stop 제외)

| 툴 | 설명 | 주요 인자 (별도 표기 외 모두 선택) |
|-----|------|----------------------|
| `process.find` | 이미지명/PID/EPROCESS로 프로세스 찾기 | `image`, `pid`, `eprocess` |
| `process.describe` | `_EPROCESS` 기술(PID/DTB/PEB/threads/parent) | `source`, `pid`, `eprocess`, `fields` |
| `type.describe` | 주소/프로세스에서 커널 구조 덤프(dt) | `source`, `address`, `type`, `fields` |
| `callbacks.list` | 커널 콜백 열거(object/registry/process/thread/imageload/minifilter) | `scope`, `module` |
| `wfp.list` | WFP provider/sublayer/callout/filter/layer 열거 | `scope`, `module`, `provider`, `layer` |
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
| `module.integrity` | 로드 모듈 PE/섹션 무결성 + W+X | `module`, `target`, `limit`, `summary`, `verbose`, `headers`, `sections`, `wx`, `mismatch` |
| `driver.integrity` | `DRIVER_OBJECT` 디스패치 테이블 무결성 | `driver`, `target`, `limit` |
| `ssdt.scan` | SSDT/shadow-SSDT 시스템콜 훅 탐지 | (없음) |
| `idt.scan` | IDT 인터럽트 게이트 훅/CPU별 divergence | (없음) |
| `cr.scan` | 컨트롤 레지스터 검사(CR0.WP/SMEP/SMAP/CPU별) | (없음) |
| `msr.check` | SYSCALL MSR(LSTAR/CSTAR/STAR/FMASK/EFER) 훅 | (없음) |
| `vbs.scan` | VBS/HVCI/CI/하이퍼바이저/Secure Kernel/trustlet | (없음) |
| `byovd.scan` | 로드 모듈을 로컬 BYOVD/LOLDrivers 카탈로그와 대조(네트워크/서브프로세스 없음) | (없음) |
| `pool.scan_pe` | 커널 big pool에 스테이징된 PE 헌팅(서명 wipe 포함) | `tag`, `limit`, `suspicious` |
| `hunt.run` | 전체 시스템 유저모드 이상 헌트(인젝션/VAD/PTE/threads/APC/driver/WFP/TI) | `mode` |
| `snapshot.capture` | 동일 부팅 증거 baseline 캡처(in-memory, 디스크 미기록) | `name` |
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

> `snapshot.capture`/`snapshot.diff`는 MCP 경로에서 **디스크에 파일을 쓰지 않는다**(in-memory). baseline은 `kn://snapshot/current`로 읽는다. `memory.read_virtual`/`read_physical`/`symbol.search`는 structuredContent(JSON)를 반환하고, 나머지 신규 툴은 텍스트 콘텐츠를 반환한다. `ti.subscribe`는 읽기 카테고리지만 ETW 세션을 시작/중지하는 부수효과 때문에 start/stop만 write 모드를 요구한다(status는 항상 가능, `kn://ti/stats`와 동일 데이터).

### 6.2 Write 툴 (8종, `--allow-write` 필수)

| 툴 | 설명 | 필수 인자 | 선택 인자 |
|-----|------|-----------|-----------|
| `memory.write_virtual` | 커널 가상주소에 바이트 쓰기(e*) | `address`, `bytes` | `width`, `process` |
| `memory.write_physical` | 물리주소에 바이트 쓰기(pe*) | `physical_address`, `bytes` | — |
| `memory.fill` | 커널 범위를 패턴으로 채움 | `address`, `length`, `pattern` | — |
| `memory.move` | 커널 범위 복사(src->dest) | `source`, `dest`, `length` | — |
| `type.set_field` | 주소의 구조체 필드 설정(setfield) | `address`, `type`, `field`, `value` | — |
| `process.set_protection` | 임의 타깃 PS_PROTECTION 설정 (PPL/PP) | `level`(none/ppl-antimalware/ppl-lsa/ppl-windows/ppl-wintcb/pp-windows/pp-wintcb/pp-winsystem) | `pid`(미지정=self) |
| `dump.raw` | 커널 범위를 지정 파일 경로로 덤프 | `address`, `length`, `path` | — |
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
