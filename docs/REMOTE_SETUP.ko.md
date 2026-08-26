> English version (canonical): [REMOTE_SETUP.md](./REMOTE_SETUP.md)

# KnLiveDbg 원격 운영 세션 설정

이미 떠 있는 elevated `KnLiveDbg.exe`(PC A)를 같은 LAN의 다른 PC(B)에서 `knkd>`로 쓰는 **운영 절차**다. 설계·프로토콜·위협 모델은 [`REMOTE_OPERATOR_SESSION.md`](./REMOTE_OPERATOR_SESSION.md)에 있다.

- 전송: plain TCP, `KNR1` length-prefixed JSON. **평문. 격리된 분석 lab 전용.**
- 기본 listen: **모든 IPv4 인터페이스**, 포트 **51767**
- 인증: `remote on`에서 입력하는 **세션 비밀번호**(5-128자 printable ASCII, 공백 없음). 디스크에 저장하지 않음.
- 클라이언트: 같은 `KnLiveDbg.exe`를 `--connect <ipv4>:<port>`로 실행. 드라이버/elevation/mutex 없음.

이건 **`kdinit /remote`가 아니다.** 그쪽은 DbgEng KD attach다. 이 세션은 B의 thin `knkd>`가 A engine에 native 명령을 넣는 경로다.

이건 **MCP도 아니다.** MCP(`mcp on`, 포트 51766)는 LLM 툴 카탈로그다. `mcp on`과 `remote on`은 동시에 못 켠다(listen XOR).

---

## 1. 어디서 무엇을 실행하나

| 역할 | 머신 | 명령 |
|------|------|------|
| Engine + driver | **PC A** (게임 박스 / 분석 대상) | Elevated `KnLiveDbg.exe`, 그다음 `knkd> remote on` |
| Thin TUI | **PC B** (분석 워크스테이션) | `KnLiveDbg.exe --connect <A-ipv4>:51767` |

B에는 EXE만 복사하면 된다. B는 `\\.\KnLiveDbg`를 열지 않고 서비스도 설치하지 않는다. 심볼, dump, TI, timeline, cloak identity, exclusive device handle은 A에 남는다.

---

## 2. 리스너 시작 (PC A)

A는 드라이버가 로드된 `knkd>` 상태여야 한다.

```text
knkd> remote on
Set a temporary remote password for this session.
Clients connect with IP, port, and this password.
Remote password: *****
Confirm password: *****
```

인자 없는 `remote on`은 `0.0.0.0:51767`에 바인드한다. LAN의 다른 PC가 붙을 수 있다. bind 성공 뒤에 프로세스가 inbound 방화벽 규칙 `knlivedbg-remote`를 추가한다(loopback이면 생략).

비밀번호 규칙:

- 두 번 입력. 불일치면 `remote on` 실패.
- **5-128자** printable ASCII(`0x21`-`0x7e`), 공백 없음.
- 세션 전용. `remote off` / 프로세스 종료 시 지운다. `mcp-endpoint.json` 같은 파일이 없다.

배너 예:

```text
[remote] listen 0.0.0.0:51767 cleartext=true
[remote] warning: cleartext kernel-command traffic on the LAN
  127.0.0.1        loopback
  192.168.1.10     Ethernet
  client: KnLiveDbg.exe --connect <ipv4>:51767
[remote] engine active: 0.0.0.0:51767  -- type 'off' then Enter to stop
```

B가 실제로 도달하는 IPv4를 고른다(물리 Ethernet/Wi-Fi. Hyper-V/VPN NIC가 경로가 아니면 쓰지 말 것).

### 옵션

| 플래그 | 효과 |
|--------|------|
| (bare) `remote on` | `0.0.0.0:51767`. 방화벽 규칙 추가. |
| `remote on 52000` | 같은 bind, 다른 포트. **51766은 거부**(MCP). |
| `--loopback` | `127.0.0.1`만. 방화벽 규칙 없음. 같은 박스 / SSH `-L`. |
| `--bind <ipv4>` | 그 주소만 listen. `127.0.0.1`이면 `--loopback`과 같음. |
| `--peer <ipv4>` | 그 클라이언트 IPv4만 accept. 방화벽 `RemoteAddresses`도 핀. |
| `--allow-public-peer` | RFC1918이 아닌 peer 허용. 기본은 private/loopback/link-local만. |

`--lan` / `--allow-write`는 없다. 쓰기는 로컬 TUI와 같다(`WriteEnabled`를 건드리지 않음).

### A가 remote engine loop에 있을 때

A 콘솔은 **컨트롤 플레인**이지 두 번째 `knkd>`가 아니다.

| A에서 치는 줄 | 효과 |
|---------------|------|
| `off` / `remote off` | listen 중지, 방화벽 규칙 삭제, 로컬 REPL로 복귀 |
| `disconnect` / `remote disconnect` | B만 끊고 listen 유지 |
| `status` / `remote status` | bind + peer |
| `write off` | 커널 쓰기 해제 (로컬과 동일. `remote off` 후에도 유지) |
| `q` / `quit` / `exit` / `unload` | listen 중지 **그리고** 프로세스 종료 (드라이버 unload는 기존 `wmain` cleanup) |

remote loop가 켜져 있는 동안 A에서 `!callbacks`를 로컬로 치지 못한다. 먼저 `off`하거나 B에서 친다.

---

## 3. 접속 (PC B)

B는 elevation이 필요 없다. `--connect`는 cloak / mutex / SCM / `DeviceClient` **이전**에 잘린다.

```powershell
.\KnLiveDbg.exe --connect 192.168.1.10:51767
password: *****
```

비밀번호는 **TCP 연결 전에** 입력한다(서버 auth deadline은 accept 후 10초). IPv4 리터럴만. DNS 없음. 포트 생략 없음.

인증 후:

```text
connected HOST Windows abi=15 write=on cloak=no cleartext=true
warning: session is cleartext; lab LAN only
knkd>
```

재연결은 새 세션이다. 비밀번호를 다시 친다.

### 클라이언트 프롬프트

| 입력 | 동작 |
|------|------|
| Tab | 로컬 TUI와 같은 `CompletionHints` 테이블(`ApplyTabCompletion`). 모호한 prefix는 annotated listing. **A를 기다리지 않음.** |
| Up / Down | 로컬 history |
| `cls` | 로컬 화면 지우기. A로 안 보냄. |
| `disconnect` / `q` / `quit` / `exit` | 프로토콜 disconnect. exit code 0. B는 A 드라이버를 unload하지 못함. |
| 그 외 | A로 `command-submit` |

### Exit code

| Code | 의미 |
|------|------|
| 0 | 인증 후 정상 disconnect |
| 2 | argv(`--connect` 형식, non-IPv4) 또는 비대화형 password prompt |
| 4 | `auth-err` (비밀번호 / lockout) |
| 5 | peer drop / connect 실패 / frame timeout |
| 6 | protocol (`unsupported-v`, unexpected type) |
| 1 | 기타 |

컨트롤러 경로의 unknown argv는 디바이스를 열기 **전에** exit 2다.

---

## 4. B가 할 수 있는 것 / 없는 것

B는 raw `knkd>` 줄을 보낸다. 계약은 **deny-list**이지 MCP 툴 카탈로그가 아니다.

**B에서 거부** (A 컨트롤 플레인 전용, 또는 전부 차단):

- `q` / `qq` / `qd` / `quit` / `exit` (B에서는 클라이언트 disconnect. A를 내리지 않음)
- `unload`
- `mcp *`
- `remote *`
- `kd` / `kdinit` / `kddetach` / `backend *`
- `probe load` / `probe unload`
- `!byovd fixture load` / `unload`
- 인자가 있는 `.sympath`, `.sympath+`
- `log enable|disable|status`
- unknown / DbgEng-only 이름 (`CommandRegistry` miss)

**B에서 허용**, 쓰기 포함: native 스캐너, `dt`, `d*`, 값이 있는 `e*` / `pe*`, `dump-*`, `!snapshot`, `!diff`, `!ti`, `!timeline`, `ai`, `write on` / `write off`, `probe status` / `info`, 인자 없는 `.sympath`, `.reload`, `home`.

dump / snapshot은 **A 디스크**에, 로컬 TUI와 같은 경로로 쓴다. B로 multi-GB pull은 없다.

주소만 있는 `eb ffff...`(바이트 없음)은 `supply values on the command line`으로 거절한다. 같은 줄에 바이트를 붙인다(`eb <addr> 90`). B 쪽 대화형 write-preview는 아직 없다.

B에서 `ai`는 허용이다. A에 프로바이더 키가 있으면 B가 그 키를 쓰지 않게 `KNLIVEDBG_AI_REMOTE_POLICY=local-only`를 권장한다.

---

## 5. Tab 자동완성

B 프롬프트는 A `knkd>`와 **같은 테이블**을 쓴다.

- 루트 이름 (`remote`, `!callbacks`, `ai`, ...)
- 중첩 스코프 (`!callbacks disable`, `ai use`, `remote on --loopback`)
- 매치가 여러 개면 annotated listing

A에서 `remote <Tab>`은 `on` / `off` / `status` / `disconnect` / `help`. `remote on` 다음에는 `--loopback` / `--bind` / `--peer`.

프로토콜에 `completion-request`도 있다. 지금 클라이언트 Tab은 그걸 보내지 않는다. 로컬 completion으로 같은 명령 면을 채운다.

---

## 6. 방화벽, XOR, lab 규칙

- loopback이 아닌 `remote on`은 inbound TCP 규칙 `knlivedbg-remote`(DOMAIN|PRIVATE|PUBLIC)를 추가한다. `remote off` / 프로세스 종료 때 삭제. 크래시 leftover는 다음 Start에서 같은 이름을 지우고 다시 넣는다.
- COM 실패는 경고만 찍고 listen은 유지. B가 timeout이면 `remote on`이 찍은 IP를 확인하고 포트를 수동으로 연다.
- 기본 peer 필터: RFC1918 / loopback / link-local. 공인 IPv4는 `--allow-public-peer` 없으면 reset.
- Auth lockout은 프로세스 수명: peer IP당 5회, 전역 15회 실패면 `remote off`까지 신규 auth 거부.
- remote가 떠 있는 동안 `mcp on`(반대도)은 실패: `listen XOR`.
- 격리 lab 세그먼트만. 공유 사무실 LAN / 인터넷에 `0.0.0.0`을 열지 않는다. 와이어 암호가 필요하면 `--loopback` + `ssh -L 51767:127.0.0.1:51767`. TLS는 설계 문서 Appendix A(v2)이고 이 빌드에는 없다.

---

## 7. 문제 해결

| 증상 | 조치 |
|------|------|
| `remote on failed: MCP server is running` | 먼저 `mcp off` |
| `remote on failed: MCP port; use 51767` | 51766을 넘기지 말 것 |
| `remote password must be 5-128 printable ASCII...` | 최소 5자, 공백 없음 |
| B `connect failed` | 배너 IP가 아님 / 방화벽 COM 경고 / `--peer` 불일치 |
| B `auth-err: bad-password` | A에서 친 세션 비밀번호. `remote on`을 다시 하면 비밀번호가 바뀜 |
| B `auth-err: lockout` | 실패 횟수 초과. A에서 `remote off` 후 다시 `remote on` |
| B `error: denied` | 세션 수명 / `kd` / `probe load` / unknown. A에서 `off` 후 치거나 허용된 명령을 쓴다 |
| `supply values on the command line` | 주소만 있는 `e*` / `pe*`. 같은 줄에 바이트를 붙인다 |
| Tab이 빈약함 | 클라이언트는 로컬 테이블. B EXE가 A보다 오래됐으면 다시 복사 |
| A가 긴 `!hunt`에 멈춘 것처럼 보임 | 컨트롤 플레인 `off`는 큐 밖이지만 in-flight는 끝까지 돈다 |

드라이버 없이 도는 검사:

```powershell
.\tools\validate-remote-protocol.ps1 -Configuration Release
```

`KnLiveDbg.exe --self-test remote-protocol`과 `--self-test connect-argv`를 돌린다(비밀번호 최소 5, deny-list, `--connect` argv, Tab이 `remote`로 확장, loopback listen). `--self-test all`에는 들어 있지 않다.

같은 박스 스모크 (A elevated, 드라이버 로드됨):

```text
knkd> remote on --loopback
```

```powershell
.\KnLiveDbg.exe --connect 127.0.0.1:51767
```

---

## 8. 빠른 참조

```text
# PC A (elevated knkd>)
remote on                                # 0.0.0.0:51767, 비밀번호 5+, 방화벽 규칙
remote on --loopback                     # 127.0.0.1만
remote on --peer 192.168.1.20            # B IPv4 핀
remote status
off                                      # listen 중지, 로컬 REPL

# PC B (elevation 불필요)
KnLiveDbg.exe --connect 192.168.1.10:51767
knkd> dt nt!_EPROCESS
knkd> eb ffff800000000000 90             # 값은 같은 줄
knkd> disconnect
```
