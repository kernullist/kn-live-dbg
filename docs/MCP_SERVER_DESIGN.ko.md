> English version (canonical): [MCP_SERVER_DESIGN.md](./MCP_SERVER_DESIGN.md)

# MCP Server Design (Kn-Live-Dbg)

이 문서는 Kn-Live-Dbg에 **MCP(Model Context Protocol) 서버**를 추가해, Claude Code / Claude Desktop / Cursor 등 외부 LLM 호스트가 이 도구의 (주로 읽기 전용) 커널 포렌식 / 안티치트 기능을 MCP tools / resources / prompts 로 직접 활용할 수 있게 하는 설계를 정의한다.

핵심 원칙은 기존 `docs/AI_ASSISTED_WORKFLOWS.md`의 철학을 그대로 잇는다: AI는 기본적으로 advisory, 숨은 자동 write 금지, raw evidence 보존, 드라이버는 좁은 메모리 primitive로 유지, 민감한 커널 상태는 local-only 가능. MCP는 기존 `ai` 명령과 동일한 **capability 카탈로그 + 가드 레이어**를 재사용하는 **세 번째 프런트엔드**다(REPL, 내부 AiProvider에 이은).

> 결론 요약(먼저): **인프로세스 loopback Streamable HTTP**, **읽기 전용 v1**, **단일 엔진 스레드 직렬화**, **기존 카탈로그/가드 100% 재사용**, **MCP 활성화 시 커널 write 플래그 비무장**.

---

## 1. 목적과 범위

### 1.1 목적

1. 외부 LLM이 `callbacks`, `!wfp`, `!alpc`, `!vbs`, `!etw`, `!nmi`, `!ssdt`, `!idt`, `!cr`, `!msrcheck`, `!pool`, `!address`, `byovd`, `!ti`, `module/driver integrity`, VAD/thread 헌트 등 읽기 전용 탐지 기능을 구조화된 형태로 호출하게 한다.
2. 커널 메모리 read/write가 가능한 **elevated(관리자/SYSTEM)** 도구를 LLM에 노출하는 만큼, 공격 표면을 최소화하고 모든 행위를 감사한다. write/커널 변형은 v1에서 전면 차단한다.
3. 기존 자산(capability 카탈로그, 가드 함수, `Build*Json`, `ScopedWideStreamCapture`)을 최대한 재사용해 신규 코드와 위험을 줄인다.

### 1.2 비범위 (Non-Goals)

1. MCP 파싱/플래닝/리스크 평가를 드라이버로 옮기지 않는다(드라이버는 좁은 primitive 유지).
2. **기본(읽기 전용) 모드**에서는 LLM이 커널 write / PPL / dump / raw kd / 세션 변경을 하지 못하게 한다. **Lab write 모드**(`--allow-write`, 격리 VM 전용 — 결정 §10-Q1/Q2)에서는 타입 있는 write 툴을 전부 열되, raw `kd`/DbgEng 패스스루·임의 명령 문자열·호스트 전역 파일 traversal·backup/audit 없는 숨은 write는 두 모드 모두 금지한다.
3. MCP 단독으로 LLM을 신뢰 주체로 삼지 않는다 — operator 콘솔의 human-in-the-loop는 항상 살아있어야 한다.

---

## 2. 핵심 제약 (코드 근거)

설계의 모든 결정은 아래 사실에서 도출된다. 모두 코드 확인 완료.

| # | 제약 | 근거 (함수/파일) |
|---|------|------------------|
| C1 | **단일 컨트롤러**: 드라이버가 `KNDBG_VERSION_FLAG_SINGLE_CONTROLLER` 강제. user-mode는 `\\.\KnLiveDbg`를 `CreateFileW(... ShareMode=0 ...)` 배타적 개방, 전역 `DeviceClient` 1개. | `DeviceClient::Open` (`ShareMode=0`), `shared/KnLiveDbgIoctl.h` |
| C2 | **배치/헤드리스 모드 없음**: `wmain`이 argc/argv 무시. 항상 대화형 REPL(`knkd>`) 진입. | `wmain` (`UNREFERENCED_PARAMETER(argc/argv)`), REPL 루프 `while(!g_StopRequested)` |
| C3 | **단일 스레드 엔진**: 모든 `HandleCommand` 디스패치, 모든 `DeviceClient` IOCTL, 모든 `SymbolEngine`(DbgHelp/DIA) 호출이 메인 REPL 스레드에서만 실행. `DeviceClient`에 락 없음, DbgHelp/DIA 비스레드안전. | `DeviceClient` (락 부재), `SymbolEngine` |
| C4 | **출력 캡처 이미 존재**: `ScopedWideStreamCapture`가 `std::wcout`/`std::wcerr`의 **프로세스 전역 rdbuf**를 문자열 버퍼로 스왑. transcript/AI evidence가 이미 사용. | `ScopedWideStreamCapture` (`std::wcout.rdbuf(&outBuffer_)`) |
| C5 | **드라이버 write 기본 ON**: `IRP_MJ_CREATE`에서 핸들 컨텍스트 `WriteEnabled = TRUE`. write-virtual/physical/SetProcessProtection 핸들러의 커널측 게이트는 이 플래그 + `KNDBG_WRITE_ACK_MAGIC`(공개 컴파일 상수)뿐. **write 안전 파이프라인 전체가 user-mode에만 존재.** | `Driver.cpp` (`WriteEnabled = TRUE`), `KnLiveDbgIoctl.h` (`KNDBG_WRITE_ACK_MAGIC`) |
| C6 | **capability 카탈로그 + 가드 존재**: 20개 read-only 툴, per-tool 인자 화이트리스트, 값 검증(`;`/개행/제어문자/help token 거부), write-like/raw-kd/nested-ai/세션변경/unload 거부, 단일 실행 경로. | `IsSupportedAiCapabilityTool`, `ValidateAiCapabilityToolArgKeys`, `ValidateAiCapabilityScalarText`, `ContainsUnsafeAiCommandCharacters`, `ExecuteAiCapabilityPlan` |
| C7 | **거의 모든 스캐너가 구조화 struct 반환**, 5종은 JSON 빌더 보유. 외부 JSON 라이브러리 없음(직접 escape). | `BuildModuleIntegrityJson`/`BuildDriverIntegrityJson`, `BuildProcessVadJson`/`BuildProcessThreadsJson`, `BuildHuntJson`, `BuildByovdScanJson`, `BuildSnapshotJson` |
| C8 | **TiSubscriber만 스레드안전 백그라운드**: 자체 `ProcessTrace` 스레드 + `RingMutex` + const 쿼리 API(`Recent`/`FilterByPid`/`Grep`/`Histogram`). | `ThreatIntelSubscriber.h` (`mutable std::mutex RingMutex`) |
| C9 | **취소 불가 스캐너**: `UserModeHunter::Scan`은 cancel token 없음. `HuntOptions`에 stop handle 없음. 동기 `DeviceIoControl`은 중도 취소 불가. | `UserModeHunter.h` (`Scan` 시그니처) |
| C10 | **콘솔 직접 출력 경로 존재**: `ScopedCommandProgress` worker가 `GetStdHandle(STD_OUTPUT_HANDLE)`에 직접 write(`WriteConsoleTuiLineDirect`) — wcout 캡처를 우회. | `ScopedCommandProgress` |

---

## 3. 아키텍처 결정

### 3.1 Transport: 인프로세스 loopback Streamable HTTP (stdio 아님)

**결정**: 이미 실행 중인 elevated 컨트롤러 프로세스 내부에 **Streamable HTTP** 엔드포인트(`http://127.0.0.1:<port>/mcp`)를 둔다. **stdio는 라이브 프로세스의 기본 transport로 쓰지 않는다.**

근거:

1. **stdio는 구조적으로 부적합**. MCP stdio transport는 정의상 *클라이언트가 서버를 서브프로세스로 spawn*한다. 그러나 본 프로세스는 (a) 이미 실행 중이고 (b) elevated이며 (c) `\\.\KnLiveDbg`를 배타적으로 점유(C1)하고 (d) 심볼/DbgEng 상태를 메모리에 들고 있다. 클라이언트가 두 번째 `KnLiveDbg.exe`를 띄우면 배타적 `CreateFileW`에 실패하거나(C1), 라이브 operator 세션 없는 별개 인스턴스가 된다.
2. **Claude Desktop은 GUI 앱이라 UAC 없이 elevated 자식 프로세스를 spawn할 수 없다** — `command: KnLiveDbg.exe` 형태의 stdio 설정은 실제로 기동되지 않는다.
3. **stdout 오염**: REPL/스캐너는 `std::wcout`에 대량 출력(C4)하고, `ScopedCommandProgress`는 콘솔 핸들에 직접 write(C10)한다. stdio JSON-RPC는 stdout을 프레이밍으로 점유해야 하므로 한 바이트만 새도 세션이 깨진다.
4. **HTTP는 콘솔과 깔끔히 공존**: HTTP 리스너는 자체 소켓/스레드를 소유하고 콘솔을 건드리지 않는다. operator REPL이 살아있어 human-in-the-loop가 유지된다(보안상 필수).
5. **Claude Code/Desktop은 `type: http`를 네이티브 지원**한다(아래 §8). 별도 shim 불필요. stdio 전용 호스트만 별도의 무상태 브리지 `npx mcp-remote <url>`로 연결한다(이 브리지는 디바이스를 건드리지 않으므로 자유롭게 spawn 가능).

**구현 스택**: HTTP 서버는 신규 추가다(현재 프로젝트는 `winhttp.lib` *클라이언트*만 링크, 서버 소켓/파이프 없음).
- 1순위: **HTTP Server API(http.sys, `httpapi.lib`)** — `HttpInitialize` / `HttpCreateRequestQueue` / `HttpAddUrlToUrlGroup`(`http://127.0.0.1:<port>/mcp`). 커널측 URL 예약과 ACL을 얻고 raw 소켓 파싱을 피한다. URL 예약(`netsh http add urlacl` 또는 SDDL)이 필요할 수 있음(미해결 §10).
- 대안: `INADDR_LOOPBACK`에 명시 `bind()`하는 소형 WinSock 리스너 — 외부 의존성은 `ws2_32`뿐이나 HTTP/1.1 파싱을 직접 짜야 함.

**POST 응답 모드**: 동기 read 툴은 `Content-Type: application/json`(단일 응답, 가장 단순)으로 답한다. elicitation/진행 알림이 필요한 툴(향후 write)은 **반드시 `text/event-stream`(SSE)** 로 답해야 한다 — 단일 JSON POST 응답에는 서버→클라이언트 요청을 끼워 넣을 수 없기 때문(§7.4).

### 3.2 Process Model: 인프로세스, 명령으로 ON/OFF, REPL 공존

**결정**: 별도 브리지 프로세스가 아니라 `KnLiveDbg.exe` **내부 서브시스템**. 단일 디바이스 핸들/심볼 엔진/상태를 공유한다(C1). 기본 OFF, operator 콘솔 명령 `mcp on <port>`로 활성화하면 토큰과 즉시 붙여넣을 수 있는 클라이언트 설정을 출력한다. `mcp off`로 즉시 정지.

- `McpServer` 객체를 `wmain`에서 `service/device/symbols/ai/aiState`와 함께 생성하되, `mcp on` 전까지 dormant.
- 활성화되면 HTTP 리스너 스레드를 1개 spawn. 이 스레드는 **커널 작업을 절대 직접 하지 않는다** — HTTP 검증(auth/host/origin/size) → JSON-RPC 파싱 → job 생성 → 엔진 큐 push → per-job 완료 future 대기만 한다.
- 종료 경로(`mcp off` / Ctrl-C / `wmain` 정리): 리스너 정지 → 큐 드레인 및 대기 job 취소 → `SetWriteMode(false)` → write 무장 해제 → worker join → 기존 드라이버 정리.

**operator REPL은 유지된다.** 단, MCP 활성화 모드에서는 콘솔 입력을 단순 라인 리더로 전환한다(§4.2의 전역 rdbuf 경쟁 회피).

### 3.3 대안 비교

| 항목 | 채택안 | 기각안 | 기각 사유 |
|------|--------|--------|-----------|
| Transport | 인프로세스 loopback HTTP | stdio 기본 | C1/C2/C4 충돌, Desktop UAC 한계, stdout 오염 |
| Transport | 인프로세스 loopback HTTP | 별도 브리지 프로세스 + IPC | C1로 두 번째 디바이스 핸들 불가, 심볼/상태 비공유, IPC가 직렬화 문제를 한 번 더 만듦 |
| 배포 모드 | REPL + HTTP 공존 | `--mcp` 헤드리스(REPL 제거) | operator 콘솔이 사라져 human-in-the-loop deny 능력 상실(보안 치명) |
| write (기본 모드) | 전면 차단 + 커널 플래그 비무장 | always-on | 비-lab 안전 기본값. C5(커널 write 기본 ON)을 `SetWriteMode(false)`로 무력화 |
| write (lab 모드) | `--allow-write`로 전체 타입 write 툴 개방 | raw kd / 숨은 write | 격리 VM 분석 충실도(결정 §10-Q1/Q2). 자동 backup/verify/audit 유지 + VM 스냅샷 권장(§5.3.3) |
| raw kd/DbgEng | 두 모드 모두 미노출 | lab에서 개방 | 임의 명령 = hang/crash/임의 실행, write 요구와 별개 축. 필요 시 별도 확정 |

---

## 4. 동시성 모델 (정확성 핵심)

C3(단일 스레드 엔진) + C4(전역 rdbuf 캡처)가 가장 미묘한 부분이다. 잘못 설계하면 elevated 프로세스에서 use-after-free가 난다.

### 4.1 단일 엔진 스레드 + 직렬 작업 큐

```text
[HTTP 리스너 스레드]                 [엔진 스레드 = 메인 스레드]
  validate(auth/host/origin/size)     drain 루프:
  parse JSON-RPC                        wait(QueueCv) until !Queue.empty()
  build McpJob ----------- push ----->  pop (operator job 우선)
  future.wait_for(timeout)              if CONSOLE: ExecuteCommandWithTranscript
  serialize result <---- promise -----  if MCP: 가드 검증 + capability 디스패치 + 직렬화
                                        set promise
```

데이터 구조(코드 스타일 준수):

```cpp
// MCP job marshalled onto the single engine thread.
struct McpJob
{
    McpJobKind Kind;                 // Console or Mcp
    std::vector<std::wstring> Args;  // synthetic command/capability args
    std::wstring OriginalLine;
    std::promise<McpResult> Done;
    std::atomic<bool> Cancelled;
};

class EngineQueue
{
public:
    bool Push(std::shared_ptr<McpJob> job);   // bounded; false => engine busy

    std::shared_ptr<McpJob> Pop();            // operator(Console) jobs first

private:
    std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<std::shared_ptr<McpJob>> consoleJobs_;
    std::deque<std::shared_ptr<McpJob>> mcpJobs_;
    size_t maxMcpPending_ = 8;
};
```

엔진 루프(기존 `while(!g_StopRequested) ReadInteractiveCommandLine` 대체):

```cpp
while (!g_StopRequested)
{
    std::shared_ptr<McpJob> job = queue.Pop(); // blocks on cv
    if (job == nullptr)
    {
        continue;
    }

    if (job->Cancelled.load())
    {
        // queued-but-cancelled: drop without touching the engine
        job->Done.set_value(McpResult::Cancelled());
        continue;
    }

    McpResult result = DispatchOnEngineThread(job, state, device, symbols /* ... */);
    job->Done.set_value(std::move(result));
}
```

### 4.2 전역 rdbuf 위험과 완화 (필수)

`ScopedWideStreamCapture`는 **프로세스 전역** `std::wcout`/`std::wcerr`의 rdbuf를 스왑한다(C4). 두 캡처가 동시에 살아있으면 rdbuf 포인터가 경쟁하고 LIFO 복원이 깨져 `wcout`이 해제된 버퍼를 가리킨다(use-after-free).

규칙(불변식):

1. **`ScopedWideStreamCapture`는 엔진 스레드에서만 생성한다.** HTTP 리스너 스레드는 절대 캡처를 만들지 않는다.
2. **동시에 최대 1개만** 살아있는다. 단일 스레드 내 중첩(nested)은 LIFO 복원이 성립하므로 허용(예: capability 경로가 내부적으로 한 번 더 캡처). **스레드 간 동시 캡처는 금지.**
3. 디버그 빌드에서 시작 시 엔진 TID를 잡아두고, `DeviceClient`/`SymbolEngine`의 모든 진입점과 캡처 ctor/dtor에 `assert(GetCurrentThreadId() == g_EngineTid)` + `g_CaptureDepth` 단일성 assert를 둔다. 관례가 아니라 코드로 강제.
4. **MCP 활성화 모드에서는 콘솔 입력을 단순 라인 리더로 전환**한다. 라이브 렌더링 인터랙티브 에디터(`ReadInteractiveCommandLine`)는 타이핑 중 콘솔/`wcout`에 직접 렌더링하므로, MCP job 캡처와 동시에 살아있으면 전역 rdbuf를 경쟁한다. 따라서 MCP 모드에서는 결과 출력은 엔진 스레드만 담당하고, 콘솔 리더 스레드는 완성된 라인을 CONSOLE job으로 push만 한다. (리치 에디팅/히스토리 인라인 렌더링은 순수 REPL 모드 전용.)
5. **`ScopedCommandProgress`는 MCP-origin job에서 비활성화**한다(`enabled=false`). 이 worker는 `STD_OUTPUT_HANDLE`에 직접 write(C10)하여 캡처/리다이렉트를 우회한다. HTTP 모드에선 프레이밍 손상은 아니지만 operator 콘솔에 MCP 노이즈를 뿌리고, 향후 stdio 브리지에서는 손상 원인이 된다.

### 4.3 백프레셔 · 취소 · 수명

- **인플라이트 1개**: 엔진은 한 번에 job 하나만 실행. 긴 스캔(UserModeHunter, pool-scan-pe, full callbacks)은 그 시간 동안 다른 모든 MCP 요청과 operator를 막는다 — 이는 **의도된 백프레셔**이며, 잘못된 취소 약속으로 가리지 않는다.
- **대기 큐 bounded(예: MCP 8)**: 가득 차면 `isError:true`("engine busy")로 응답(§7.3 — JSON-RPC -32xxx 아님).
- **operator 우선순위**: 큐에서 CONSOLE job을 MCP job보다 먼저 꺼낸다. 단, 인플라이트 job은 선점 불가하므로 "operator가 항상 즉시 실행"을 보장하진 않는다(정직하게 명시).
- **취소(정직한 모델)**: cancellation notification은 **큐에 남아있는 job만** 제거한다. 디스패치된 스캔은 끝까지 실행된다 — 스캐너에 stop token이 없고(C9) `DeviceIoControl`이 동기이기 때문. "중도 취소"를 약속하지 않는다. 스캔을 짧게 유지하려면 `limit`/`count` 인자를 강제한다.
- **late-result 수명**: `McpJob`은 엔진이 `shared_ptr`로 소유. worker가 timeout으로 future를 포기해도, job/결과 저장소는 엔진이 promise를 set할 때까지 살아있다(해제된 메모리에 promise set 금지). 인플라이트 1개 규칙상 timeout-but-running job은 자연스럽게 큐를 막는다(= 정상 백프레셔, hang 아님).
- **엔진 스레드 재진입 금지**: 엔진 스레드 코드는 절대 자기 큐에 enqueue-and-wait 하지 않는다(자기 데드락). transport 스레드만 future를 기다린다. nested-ai/`assistant.answer`는 기존대로 거부되므로 재진입 경로가 닫혀 있다.

### 4.4 TiSubscriber 예외 — 채택하지 않음

`ti.query`를 RingMutex 보호 하의 ring read(`Recent`/`FilterByPid`/`Histogram`, C8)로 엔진 큐를 건너뛰어 worker에서 직접 서빙하는 "fast path"는 **채택하지 않는다.** ti capability 실행기가 ring read 외에 PPL self-elevation(`SetProcessProtection` via 락 없는 `DeviceClient`)이나 심볼 해석(DbgHelp)을 건드릴 수 있어 경쟁 위험이 있고, RingMutex는 비경합이라 큐 hop 비용이 무시할 수준이다. **모든 툴은 엔진 큐를 탄다.**

---

## 5. 보안 모델 (가장 중요)

elevated 커널 RW 도구를 잠재적으로 적대적/인젝션된 LLM에 노출한다는 전제로 설계한다.

### 5.1 네트워크

1. **loopback 전용 바인드**: `127.0.0.1` + `::1`만. `0.0.0.0` 절대 금지. 기본 OFF, `mcp on`으로만 활성화.
2. **Host 헤더 화이트리스트**: `127.0.0.1` / `[::1]` / `localhost`가 아니면 거부 → DNS rebinding 차단.
3. **Origin 검증**: Origin이 **존재하고** 화이트리스트에 없으면 403. (주의: Origin 부재는 정상 비브라우저 클라이언트이므로 허용. "Origin 있으면 무조건 거부"는 적합 클라이언트를 깨뜨린다.)
4. loopback은 인증 경계가 아니다(멀티유저/RDP 호스트에서 다른 로컬 사용자가 도달 가능). 실제 인증은 토큰이 담당.

#### 5.1.1 옵트인 네트워크 바인드 (`--bind <addr>`, lab 전용)

실무 제약: lab 테스트 VM이 **물리적으로 분리된 PC**에 있으면 loopback-only 리스너에 외부 Claude 호스트가 도달할 수 없다. 이를 위해 **명시 옵트인** 네트워크 노출을 둔다 — 기본값은 바뀌지 않는다.

1. **기본은 그대로 loopback-only**(`BindAddress` 비어 있음): `127.0.0.1`+`[::1]`만 등록, Host 화이트리스트 엄격 적용. 안전 기본값 유지.
2. **`mcp on <port> --bind <addr>`**: loopback URL은 그대로 두고 요청한 주소(`http://<addr>:<port>/mcp/`)를 **추가** 등록한다. `<addr>`는 구체 IP(예: `192.168.56.10`) 또는 전체 인터페이스용 `0.0.0.0`/`*`/`+`(http.sys 강한 와일드카드 `+`로 매핑). http.sys가 비-loopback prefix를 예약하므로 **elevated/SYSTEM이면 별도 `netsh urlacl` 불필요**(loopback과 동일).
3. **Host 검사 완화 + Origin 방어 유지**: 원격 모드에서는 임의 Host를 수용(원격 클라이언트의 Host가 곧 lab IP)하되, **Origin 거부(존재하는데 loopback authority가 아니면 403)는 그대로 둔다** → DNS-rebinding 방어는 바인드 모드와 무관하게 유효(비브라우저 MCP 클라이언트는 Origin 미전송이라 통과).
4. **bearer 토큰이 유일한 장벽**이 된다(§5.2). 따라서 원격 노출 시 **방화벽으로 클라이언트 IP만 인바운드 허용**하고 **신뢰된 lab 세그먼트**에서만 쓰도록 콘솔에 경고를 출력한다. `0.0.0.0` 바인드 시 클라이언트가 어느 인터페이스 IP로 접속해야 하는지는 알 수 없어 URL에 `<this-host-ip>` 플레이스홀더를 찍는다.
5. **위협 모델 변화**: loopback-only에서는 같은 호스트의 로컬 사용자만 도달 가능했으나, 원격 노출은 lab 세그먼트의 임의 호스트가 토큰만 알면 elevated 커널 RW에 도달 가능해진다. lab/격리망 외 사용 금지(라이브 EDR/AC 박스 절대 금지).

### 5.2 인증과 토큰 취급

1. `mcp on`마다 **256-bit 랜덤 bearer 토큰**을 새로 발급, **상수 시간 비교**, 불일치 시 401+연결 종료.
2. 서버 측: 토큰을 콘솔에 1회만 출력(평문 로깅 금지, audit에는 fingerprint만), 짧은 idle TTL 후 자동 만료.
3. **클라이언트 측 저장이 진짜 누출 지점**: Claude Code는 HTTP 헤더(Authorization 포함)를 설정 파일에 영속화한다. 커널 RW 엔드포인트를 인증하는 토큰을 **committable한 project-scope `.mcp.json`에 붙여넣지 말 것.** user-scope 설정 + `${KNLIVEDBG_TOKEN}` 환경변수 인다이렉션 또는 `headersHelper`(접속 시 회전 토큰 발급)를 강제한다. 절대 git 커밋 금지.
4. 옵션: `GetExtendedTcpTable`로 loopback peer PID에 토큰을 바인딩(방어 심화, 단 재접속/PID 재사용에 취약).

### 5.3 두 모드: 읽기 전용(기본) vs Lab write 모드 (결정 §10-Q1 갱신)

MCP는 **기동 시 명시 플래그로 두 모드 중 하나를 선택**한다. 분석 박스가 격리 lab/VM(결정 §10-Q2)이므로 분석 충실도를 위해 write를 여는 것은 정당하다. 단, "열어둔다"가 "안전 레일 제거"를 뜻하지 않는다 — **마찰 없는(non-interactive) 자동 레일은 유지**한다(이미 있는 코드, 비용 0, 분석 보호).

#### 5.3.1 읽기 전용 모드 (기본, 비-lab 배포)

- `mcp on` (플래그 없이): write/mutation 툴을 등록하지 않고 `DeviceClient.SetWriteMode(false)`로 **커널 플래그 자체를 비무장**한다. C5에서 핸들 `WriteEnabled`가 기본 TRUE이고 커널측 게이트가 그 플래그 + 공개 상수(`KNDBG_WRITE_ACK_MAGIC`)뿐이므로, 비무장 동안에는 **커널 자체가** write/PPL IOCTL을 `STATUS_ACCESS_DENIED`로 거부한다. lab이 아닌 어떤 배포에서도 안전 기본값.

#### 5.3.2 Lab write 모드 (`mcp on <port> --allow-write`)

명시 플래그로만 활성화. 활성화되면:

1. **전체 write 툴 표면 등록**(§6.1 write 네임스페이스). `WriteEnabled`는 세션 동안 TRUE 유지(매 write momentary 토글 불필요 — write가 1급 시민이므로). PPL은 `process.set_protection`으로 **임의 타깃 허용**(lab); self-PPL은 그 특수 케이스라 `IOCTL_KNDBG_SET_PROCESS_PROTECTION`/write-virtual가 동일 `WriteEnabled`를 공유하는 문제가 자연히 사라진다.
2. **모든 write에 마찰 없는 자동 안전 레일 유지** — 기존 `ai write confirm` 머신러리를 재사용하되 인터랙티브 확인만 뺀다: ① preflight read(현재 바이트) → ② backup/restore 커맨드 산출 → ③ write → ④ post-write read-back **verify-diff** → ⑤ write-audit JSONL(`WriteCommandAuditEvent`). 이 레일은 **LLM이 분석 대상 라이브 상태를 조용히 깨먹어 분석 자체를 무효화하는 것**을 막고 모든 변형을 복구 가능·감사 가능하게 한다.
3. **타입 있는 write 툴만**(raw 명령 문자열 금지 유지). 모델은 `eb <addr> <bytes>` 같은 raw 문자열이 아니라 `memory.write_virtual {address, bytes}`처럼 검증된 타입 인자로 호출한다 — 인젝션/체이닝/파싱 표면을 닫고 모델이 더 정확히 호출.
4. **elicitation 기본 OFF**(lab 무마찰). `mcp write-confirm on`으로 per-write 사람 확인(SSE elicitation, §7.4)을 켤 수 있음.

#### 5.3.3 Lab write 모드의 잔여 위험과 권고 (반드시 인지)

- **confused-deputy(가장 현실적인 위협)**: 분석 중인 멀웨어/공격자 제어 커널 데이터(프로세스명·모듈 경로·메모리 내용)가 모델 컨텍스트로 흘러들어가 프롬프트 인젝션으로 **파괴적 write를 유도**할 수 있다. 타입 인자·값 검증·backup/verify·audit가 복구·추적은 가능하게 하지만 **완전히 막진 못한다**. 신뢰할 수 없는 메모리를 읽으면서 같은 세션에 write를 여는 것은 본질적 리스크.
- **권고**: ① write 세션 전 **VM 체크포인트/스냅샷**(격리 VM이므로 즉시 롤백 — lab 최강 안전망). ② write 전 `!snapshot`으로 분석 baseline 캡처. ③ loopback+토큰+단일 세션 핀은 그대로 유지. ④ 무인 신뢰가 걱정되면 `mcp write-confirm on`.
- **raw `kd`/DbgEng 패스스루는 여전히 별개로 닫아둔다**(§5.4-3). 타입 write 툴이 "write" 요구를 이미 충족하고, raw 명령은 hang/crash/임의 실행이라 훨씬 큰 문. 필요하면 별도 확정.
- TI **구독 시작**(`!ti start`)은 ETW 세션/파일 생성 부수효과로 여전히 콘솔 전용; `ti.query`는 기존 링만 읽음. lab 무인 TI를 원하면 write 모드 아래 `ti.subscribe` 추가 가능.

> 권장 드라이버 하드닝(후속, ABI bump): 읽기 전용 모드의 정확성을 위해 `SetWriteMode(false)`가 PPL과 write를 함께 닫는 현 구조는 그대로 유효. 다만 향후 "읽기 전용 + self-PPL만"을 다시 원하면 `IOCTL_KNDBG_SET_PROCESS_PROTECTION`에 `WriteEnabled` 독립 게이트를 추가한다.

### 5.4 입력 가드 (프롬프트 인젝션 봉쇄)

1. 모든 `tools/call`은 기존 가드를 **그대로** 통과한다: `IsSupportedAiCapabilityTool`(툴 allowlist) + `ValidateAiCapabilityToolArgKeys`(per-tool 인자키 화이트리스트) + per-value `ValidateAiCapabilityScalarText` + `ContainsUnsafeAiCommandCharacters`(`;`/CR/LF/제어문자 거부) + scope enum 정규화 + `IsHelpToken` 거부.
2. **raw 명령 문자열을 MCP로 절대 받지 않는다(write 포함).** 오직 `tool` + 타입 있는 args만. 읽기 전용 모드에서 인젝션된 모델의 최악은 "in-range 인자로 다른 read 스캐너 선택". Lab write 모드에서는 write 툴이 도달 가능하지만 **타입 인자 + 값 검증 + backup/verify/audit**를 거치고, raw kd/세션변경/unload는 두 모드 모두에서 미노출.
3. **raw 명령 패스스루 금지 유지**(`kd`/임의 `u`/`uf` 문자열). Lab write 모드의 write 툴은 **타입 있는 신규 primitive**(`memory.write_virtual` 등, 각자 value-validator 보유)로 추가하되, 임의 명령 문자열을 받는 경로는 열지 않는다.
4. 툴 출력(프로세스명, 모듈 경로, WNF/ETW 문자열, 공격자 제어 메모리)은 **데이터**일 뿐 명령으로 재해석되지 않는다.

### 5.5 egress 레드액션

`ScopedWideStreamCapture`로 캡처한 텍스트와 직렬화 JSON 모두 **프로세스를 떠나기 전(HTTP UTF-8 변환 전)** `MaybeRedactTranscriptText`로 레드액션한다. 외부 모델은 잠재적 적대 주체로 간주하며, 큐레이션되지 않은 raw 커널 주소/심볼/경로(KASLR·심볼 노출)를 넘기지 않는다.

### 5.6 감사 (필수, 비옵션)

MCP 요청마다 append-only JSONL 1레코드: timestamp, peer(loopback port/PID), session id, tool, **레드액션된 args**, decision(allow/deny + 어느 가드가 발동), result byte size, write-arm 상태. (결과 hash만으로는 불충분 — 무엇이 빠져나갔는지 size+레드액션 스니펫 필요.) `kn://audit/tail`을 읽기 전용 리소스로 노출해 모니터링 클라이언트가 모델 행위를 관찰.

### 5.7 kill switch

`mcp off` / Ctrl-C(`ConsoleHandler`)는: 리스너 정지 → 큐 드레인 + 대기 job 취소 → `SetWriteMode(false)`(커널 플래그 비무장) → write 무장 해제 → worker join → 기존 드라이버 정리. 비정상 종료가 핸들을 write-enabled로 남기지 않게 한다.

### 5.8 세션 핀

`Mcp-Session-Id`를 `InitializeResult`에 발급, 이후 모든 요청에 요구(없으면 400). **두 번째 동시 `initialize`는 거부**(단일 엔진/단일 디바이스 → 단일 MCP 세션). write-arm/elicitation 상태와 감사 귀속을 모호하지 않게 유지하고, 두 LLM이 IOCTL을 인터리브하지 못하게 한다.

---

## 6. Tool / Resource / Prompt 매핑

규칙: **모델이 수행할 행위 → Tool / 사용자가 첨부하는 데이터 → Resource / 사용자가 실행하는 워크플로 → Prompt.**

### 6.1 Tools (읽기 전용, 카탈로그 부분집합)

각 `tools/call`을 단일 스텝 `AiCapabilityPlan`(schema `kn-live-dbg.ai-capability-plan.v1`)으로 합성 → 기존 검증 → `ExecuteAiCapabilityPlan` 디스패치. **단일 실행 경로/단일 가드 레이어 유지.** `assistant.answer`는 미노출(외부 클라이언트가 LLM이고, 노출 시 내부 `AiProviderRuntime`를 통한 confused-deputy 원격 egress 경로가 생김).

v1 툴(18종)과 인자 스키마(= 기존 화이트리스트, `additionalProperties:false`):

| MCP tool | 인자 | 매핑 스캐너 |
|----------|------|-------------|
| `process.find` | image\|name\|process, pid, eprocess | 라이브 프로세스 목록 |
| `process.describe` | source, pid, eprocess, fields | `_EPROCESS` 필드 |
| `type.describe` | source, address, type, fields | `dt` 구조 |
| `callbacks.list` | scope, module | `CallbackScanner` |
| `wfp.list` | scope, module, provider, layer | `WfpScanner` (+커널 callout 포인터) |
| `alpc.list` | scope, name, pid | `AlpcScanner` |
| `vad.list` | source, image, pid, eprocess, exec, private, wx, pe, hiddenpte, dkom, summary, limit | `ProcessTriageScanner::ScanVad` |
| `threads.list` | source, image, pid, eprocess, apc, stacks, limit | `ProcessTriageScanner::ScanThreads` |
| `etw.integrity` | (없음) | `EtwScanner::ScanIntegrity` |
| `nmi.list` | scope | `NmiScanner` |
| `fwtable.list` | scope, module, provider, signature | `FirmwareTableScanner` |
| `pool.find` | tag, min, max, addr, limit, paged, annotate, wx | `PoolScanner` |
| `address.inspect` | address, va, symbol | `AddressInspector` |
| `wnf.decode` | hash, state, state_name | `WnfScanner` 디코더 |
| `wnf.list` | scope | `WnfScanner` |
| `ti.query` | action, count, pid, task, pattern | `ThreatIntelSubscriber` ring (read action만) |
| `module.integrity` | module, target, limit, summary, verbose, headers, sections, wx, mismatch | `IntegrityScanner::ScanModules` |
| `driver.integrity` | driver, target, limit | `IntegrityScanner::ScanDrivers` |

- inputSchema는 검증기가 쓰는 **동일 상수 배열**에서 생성해 스키마/검증기 drift를 원천 차단.
- annotations: read 툴 전부 `readOnlyHint:true`, `openWorldHint:false`. (단, annotation은 advisory hint일 뿐 — 실제 게이트는 서버측 가드.)
- 두 모드 공통 미노출: raw `kd`/DbgEng 패스스루, 세션 변경(backend/symbol path/write on-off의 직접 토글), unload/shutdown, `byovd` YARA 임의 파일 경로. (`byovd`/`hunt`/`snapshot` read 툴은 §9 후속 단계에서 화이트리스트 추가 후 노출.)

### 6.1.1 Write 툴 네임스페이스 (Lab write 모드 전용, `--allow-write`)

`mcp on --allow-write`로만 등록. 전부 **타입 인자 + 값 검증 + preflight/backup/verify-diff/audit**(§5.3.2) 경유. annotations 공통: `readOnlyHint:false`, `destructiveHint:true`.

| MCP tool | 인자 | 매핑 |
|----------|------|------|
| `memory.write_virtual` | address\|symbol, bytes(hex), width?, process? | `e*` (기본 컨텍스트 System pid 4, `process`로 변경) |
| `memory.write_physical` | physical_address, bytes(hex) | `pe*` |
| `memory.fill` | address, length, pattern(hex) | `fill` |
| `memory.move` | source, dest, length | `move` |
| `type.set_field` | address, type, field, value | `setfield` (PDB 오프셋 + width 자동) |
| `process.set_protection` | pid?(기본 self), level | `IOCTL_KNDBG_SET_PROCESS_PROTECTION` 직접 호출(임의 타깃; level→raw 바이트 매핑, PDB 오프셋 해석) |
| `dump.raw` | address, length, path | `dump-raw` (path **필수**, traversal 방지) |
| `dump.pe` | address, path | `dump-pe` (path **필수**) |

- `bytes`/`pattern`은 hex 문자열로 받아 길이·범위 검증(드라이버 1MB 캡). raw 명령 문자열 불가.
- `dump.*`의 path는 **필수**이고 traversal(`..`)·불안전 문자를 거부한다(구현이 기본 경로를 합성하지 않으므로 스키마가 path를 required로 광고).
- `process.set_protection`은 `set-ppl-antimalware`(self 전용 TUI 명령)을 거치지 않고 `DeviceClient::SetProcessProtection(pid, offset, byte)`를 직접 호출한다. level은 `ParseProtectionByte`로 raw PS_PROTECTION 바이트(none/ppl-*/pp-*)에 매핑되고, 응답의 old/readback 바이트가 인라인 backup/verify가 된다.
- `idempotentHint`: write_virtual/physical/fill/move/set_field=false, set_protection=true(이미 해당 level이면 no-op).

### 6.2 Resources (값싸고 부수효과 없는 컨텍스트)

`kn://` 스킴. 라이브 커널 데이터가 필요한 리소스는 여전히 엔진 큐를 탄다. 캐시/정적인 것만 직접 서빙.

| URI | 내용 |
|-----|------|
| `kn://session/info` | `DriverSessionStatus`(Flags/OwnerPid/CurrentPid/OpenHandleCount) + ABI 10 + `KNDBG_MAX_TRANSFER_SIZE`(1MB) + write-mode/MCP-arm 상태 → 모델의 상황 인식 앵커 |
| `kn://session/symbols` | `SymbolEngine.SymbolPath()` + 모듈 수 + 커널 심볼 로드 상태(엔진 스레드에서 캐시) |
| `kn://modules/kernel` | 커널 모듈 목록(name/base/size) — 모델이 name→module 인자로 쓰는 지도 |
| `kn://drivers/status` | `drvstatus` 요약 |
| `kn://snapshot/current` | baseline 존재 시 기존 `BuildSnapshotJson`(`kn-live-dbg.snapshot.v1`) 그대로 |
| `kn://ti/stats` | TiSubscriber ring histogram/stats(스레드안전 API) |
| `kn://audit/tail` | 최근 N개 감사 라인(레드액션) |
| `kn://capabilities` | 활성 툴 + 인자 화이트리스트 + read/write 분류 매니페스트 |

주의(프로토콜 뉘앙스): 리소스는 **사용자/앱이 첨부**하는 것이지 모델이 자율적으로 pull 하는 게 아니다(Claude Code에선 `@server:scheme://...` 멘션). 따라서 모델 자기소개용 `capabilities`는 `tools/list`(또는 전용 tool)로도 제공한다.

### 6.3 Prompts (파라미터화된 플레이북)

Claude Code에서 `/mcp__knlivedbg__<prompt>` 슬래시 명령으로 노출. 읽기 전용 툴 시퀀스를 안내하는 **메시지**를 반환할 뿐 자동 실행하지 않는다. 각 프롬프트는 "raw evidence 보존, write 제안 금지" 표준 지침을 포함.

1. `callback-audit {module?}` — object/registry/process/thread/imageload/minifilter 콜백 열거 → 비모듈/외부 타깃을 `address.inspect`+`module.integrity`로 교차검증.
2. `driver-surface-map {driver}` — `driver.integrity`+`module.integrity`+해당 드라이버 콜백+WFP callout.
3. `address-provenance {address}` — `address.inspect`→포함 영역 `pool.find`→`module.integrity`.
4. `minifilter-review` — `callbacks.list scope=minifilter` + altitude 분석 + 필터별 `module.integrity`.
5. `hunt-triage {pid?}` — `process.find`→`vad.list`(wx/private/hiddenpte/dkom)+`threads.list`(stacks)+`ti.query` by pid.
6. `etw-infinityhook-check` — `etw.integrity`+`nmi.list`+`ti.query`.
7. `wfp-surface` — `wfp.list` providers/sublayers/callouts/filters/layers + 커널 callout 포인터 `address.inspect`.

---

## 7. 구조화 출력 전략

### 7.1 2-tier

- **Tier A (즉시 출시, 전 18툴)**: 기존 text 실행기를 `ScopedWideStreamCapture`(C4)로 감싸 `CommandExecutionResult.Output` 캡처 → 레드액션 → `{content:[{type:"text", text:<captured>}]}`. 스캐너 변경 0으로 day-1에 전 툴 동작.
- **Tier B (스캐너별 점진)**: 스캐너 struct를 직접 직렬화 → `structuredContent` + outputSchema. 기존 5종(`module/driver integrity`, `vad`, `threads`, `hunt`, `byovd`, `snapshot`) 재사용, 나머지 ~12종은 동일 `std::wstringstream` 패턴으로 신규 빌더 작성. MCP 계약 변경 없이 툴별로 text→structured 승격.

### 7.2 MCP 결과 형태 (계약)

```jsonc
{
  "content": [
    { "type": "text", "text": "<structuredContent와 동일한 정확한 직렬화 JSON>" },
    { "type": "text", "text": "<선택: 사람용 요약>" }
  ],
  "structuredContent": { "schema": "kn-live-dbg.callbacks.v1", "...": "..." },
  "isError": false
}
```

- **`content[0].text`는 프로즈 요약이 아니라 직렬화 JSON과 정확히 동일**해야 한다(structured 미지원 클라이언트가 손실 없이 데이터를 받도록). 요약/캡처 텍스트는 추가 블록.
- 툴별 **`outputSchema` 선언**, 그리고 내부 스키마 id(`kn-live-dbg.*.vN`)를 `structuredContent` 필드로 박아 버전 drift를 클라이언트가 감지하게 한다.

### 7.3 에러 모델 (중요 — 흔한 실수)

- **툴 인자검증/실행/`engine busy`/`device busy`/`writes disabled`/scope 오류 = `isError:true` CallToolResult content**(텍스트 설명 포함). 모델이 self-correct 하도록.
- JSON-RPC 프로토콜 에러는 **unknown tool(-32601) / malformed params(-32602) / parse·invalid request / auth·session** 에만. (`-32000`/`-32001` 같은 비즈니스 에러 금지 — 모델 self-correction을 깨고 에러 오라클이 됨.)

### 7.4 토큰 예산 · 페이지네이션 · 대용량

- 모든 list 툴: `offset`+`limit` + `{total, returned, truncated, next_offset}` 봉투. 보수적 기본 캡(예: 200 레코드 / 64KB), 초과 시 `truncated:true` + 명시적 hint(절대 조용한 누락 금지). `UserModeHunter`/pool-scan은 특히 bounded 기본값.
- 대용량 산출물(snapshot/dump/full pool listing)은 inline 대신 **`resource_link`로 `kn://` 리소스 참조**. (Claude Code는 ~10k 토큰 경고, ~25k(`MAX_MCP_OUTPUT_TOKENS`)에서 truncate/persist.)
- 정당하게 큰 텍스트가 필요한 소수 툴만 `_meta["anthropic/maxResultSizeChars"]`(≤500,000) 상향.
- raw read는 드라이버 `KNDBG_MAX_TRANSFER_SIZE`(1MB)로 묶이고 offset 청크.

### 7.5 UTF-8 안전성 (실제 버그)

기존 escaper(`EscapeJsonText`/`HuntJsonEscape` 등)는 UTF-16에서 동작하며 **lone/unpaired surrogate를 처리하지 않는다.** 커널 유래 문자열(WNF 이름, 모듈 경로, 공격자 제어 메모리, ETW task)은 ill-formed UTF-16일 수 있고, `WideCharToMultiByte(CP_UTF8, ...)`에서 잘못된 UTF-8을 만들어 JSON-RPC(UTF-8 MUST) 스트림을 깨뜨린다.

대응: 직렬화 전 모든 wide 문자열을 ill-formed UTF-16에 대해 sanitize(lone surrogate→U+FFFD 또는 hex escape), `WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, ...)`로 **조용히 망가뜨리지 말고 시끄럽게 실패**. escape 헬퍼(4종 이상 산재)를 **하나의 감사된 escaper로 통합**하고 디버그 빌드에 JSON 유효성 self-check 추가.

---

## 8. 클라이언트 설정

> 실전 운영 절차(서버 기동, 원격 `--bind`, Claude 연결, 방화벽, 전체 툴/리소스/프롬프트 카탈로그, 트러블슈팅)는 별도 운영자 가이드 [`MCP_SETUP.ko.md`](./MCP_SETUP.ko.md)에 정리돼 있다. 아래는 설계 관점의 요약이다.

### 8.1 프로토콜 버전

- baseline **2025-06-18**(structuredContent, elicitation, tool annotations, resource_link 모두 포함, Claude Code/Desktop 광범위 지원). 클라이언트가 제시하면 **2025-11-25**까지 negotiate. 실험적 async Tasks에 의존 금지.
- HTTP에서 init 이후 모든 요청에 `MCP-Protocol-Version` 헤더 요구: 없으면 서버가 2025-03-26으로 가정(structured/elicitation 상실), 미지원 값이면 **HTTP 400**. *(계획 — 현재 v0 스캐폴드는 이 헤더를 검증하지 않음, §11.1 ④ 후속.)*

### 8.2 Claude Code

```bash
# 권장: HTTP + 정적 토큰(이미 실행 중인 서버에 연결)
claude mcp add --transport http knlivedbg http://127.0.0.1:51766/mcp \
  --header "Authorization: Bearer YOUR_TOKEN"

# 원격(분리된 PC의 lab VM): lab 호스트에서 `mcp on 51766 --bind 192.168.56.10`로 띄운 뒤
# 클라이언트 PC에서 lab IP로 연결. `mcp on`이 찍어주는 정확한 url/token을 그대로 사용.
claude mcp add --transport http knlivedbg http://192.168.56.10:51766/mcp \
  --header "Authorization: Bearer YOUR_TOKEN"

# stdio 전용 호스트용 별도 무상태 브리지(라이브 프로세스를 직접 노출하지 않음)
claude mcp add --transport stdio knlivedbg-bridge -- \
  npx -y mcp-remote http://127.0.0.1:51766/mcp --header "Authorization: Bearer YOUR_TOKEN"
```

원격 바인드 시(§5.1.1): bearer 토큰이 유일한 장벽이므로 **방화벽에서 클라이언트 IP만 인바운드 허용**하고 신뢰된 lab 세그먼트에서만 사용. `--bind 0.0.0.0`은 모든 인터페이스에 열리니 가능하면 구체 IP를 지정.

`.mcp.json` (단, 토큰은 env 인다이렉션 — committable 파일에 평문 금지):

```jsonc
{
  "mcpServers": {
    "knlivedbg": {
      "type": "http",
      "url": "http://127.0.0.1:51766/mcp",
      "headers": { "Authorization": "Bearer ${KNLIVEDBG_TOKEN}" }
    }
  }
}
```

유용한 노브: per-server `timeout`(ms, 느린 스캔용 상향 — 진행 알림으로 연장 안 됨), `headersHelper`(접속 시 회전 토큰), `alwaysLoad`.

### 8.3 Claude Desktop

`%APPDATA%\Claude\claude_desktop_config.json` 에 동일한 `type: http` 항목. 네이티브 http 미지원 빌드면 `command: npx, args: ["-y","mcp-remote", ...]` 브리지. 편집 후 Desktop 완전 재시작.

권장: project-scope `.mcp.json` 대신 **user-scope + `${KNLIVEDBG_TOKEN}`** 한 형태로 Claude Code/Desktop 모두 커버.

---

## 9. 단계별 구현 계획

| Phase | 내용 | 산출(가장 작은 출시) |
|-------|------|----------------------|
| **0. 플럼빙** | http.sys 리스너(127.0.0.1 바인드), `mcp on/off` 콘솔 명령, 토큰 발급/출력, Host/Origin 검증, `Mcp-Session-Id`/`MCP-Protocol-Version`, JSON-RPC 프레이밍(initialize/tools/list/tools/call/resources/*/prompts/*). 노출은 `kn://capabilities` + `kn://session/info`(캐시)만. | 클라이언트가 접속·인증·tools/list·session 조회 가능. 디바이스 접근 0. transport/auth/세션을 커널 노출 전에 증명. |
| **1. 읽기 카탈로그(Tier A)** | 엔진 큐 + 콘솔-라인-as-job 드레인 루프, 18개 read-only 툴을 `ExecuteAiCapabilityPlan` 재사용 + `ScopedWideStreamCapture` text. origin="mcp" 감사. 기본 읽기 전용 모드 = `SetWriteMode(false)` 비무장. | 외부 LLM이 전체 읽기 포렌식 표면을 가드/감사 하에 구동. **실질 가치 1차 출시.** |
| **2. 구조화 JSON(Tier B)** | 스캐너별 `Build*Json` 작성/재사용 → `structuredContent`+outputSchema. offset/limit 페이지네이션. 통합 surrogate-safe escaper. | 계약 변경 없이 툴별 text→structured 승격. |
| **3. 리소스+프롬프트** | `kn://modules`/`drivers`/`snapshot`/`ti/stats`/`audit/tail` + 7개 플레이북 프롬프트. 대용량은 `resource_link`. | 모델 자기 그라운딩 + 슬래시 명령 워크플로. |
| **4. Lab write 모드** | `mcp on --allow-write`로 write 네임스페이스(§6.1.1) 등록. 세션 동안 `WriteEnabled=TRUE`. 모든 write에 자동 preflight/backup/verify-diff/audit(인터랙티브 확인 없음). `process.set_protection` 임의 타깃. `dump.*` 출력 루트 제한. `mcp write-confirm on`으로 per-write SSE elicitation 옵션. | 격리 lab/VM 전용(결정 §10-Q1/Q2). 기본 OFF, `--allow-write` 없이는 등록 안 됨. write 전 VM 스냅샷 권장. |

각 단계는 독립 출시 가능하며, 후속 단계가 Phase-0 보안 자세를 약화시키지 않는다.

---

## 10. 확정된 결정 (2026-06-24)

§3 초기 설계의 6개 미해결 항목은 아래와 같이 확정됨.

1. **서버 스택 → http.sys (`httpapi.lib`)**. elevated 프로세스에 hand-rolled HTTP 파서를 두는 것이 최우선 EoP 표면이므로 커널-감사된 http.sys로 오프로드. **관리자/SYSTEM은 `HttpAddUrlToUrlGroup`에 별도 `netsh urlacl` 예약 불필요** → URL ACL 우려 해소. loopback 한정 prefix `http://127.0.0.1:<port>/mcp` + `http://[::1]:<port>/mcp`. WinSock 기각.
2. **포트 → 고정 기본값 + override**. loopback 포트 스캔은 즉시 가능 → 랜덤의 보안 이득 ≈ 0인데 매 세션 클라 설정 깨짐 비용이 큼(실제 인증은 토큰). private 범위 고정 기본값(예: `51766`) + `mcp on <port>` override.
3. **write 노출 → Lab write 모드 전면 개방 (Q1, 2026-06-24 갱신)**. 격리 lab/VM(Q2)이므로 분석 충실도를 위해 `mcp on --allow-write`로 전체 타입 write 툴(§6.1.1)을 연다. 단 "개방 ≠ 안전 레일 제거" — 마찰 없는 자동 preflight/backup/verify-diff/audit를 유지(§5.3.2)하고 raw kd/임의 명령/숨은 write는 계속 금지. 비-lab 기본은 읽기 전용 + 커널 플래그 비무장(§5.3.1). write 전 VM 스냅샷 권장(§5.3.3). *(이전 "PPL 예외만" 결정을 대체.)*
4. **클라이언트 토큰 → 정적(per-`mcp on` 신규 발급) + `${KNLIVEDBG_TOKEN}` env 인다이렉션**, `headersHelper` 회전은 옵션. project-scope 커밋 금지. (Claude Code/Desktop 양쪽 동작 + 최소 셋업; 세션마다 신규 + idle TTL로 회전 효과.)
5. **실행 환경 → 격리 분석 VM 중심 (Q2)**. 인바운드 loopback 리스너 노출이 무관하므로 http.sys loopback 단독, named pipe 등 추가 전송 계층 불필요. (라이브 EDR/AC 박스에서 쓸 일이 생기면 named pipe 옵션을 백로그에서 검토.)
6. **타임아웃/캡 → 시작 기본값 채택, 라이브 VM 실측 튜닝**. 요청 타임아웃 30s(느린 스캔은 클라 per-server `timeout` 상향), MCP 대기 큐 8, per-result 64KB/200 레코드, raw read 1MB(드라이버 캡), hunt/pool-scan 강제 `limit`. 전부 config 노출.

남은 백로그(운영/구현 시 결정): http.sys SDDL로 포트 ACL을 elevated 계정에 한정할지; `SetProcessProtection`에 `WriteEnabled`와 독립된 게이트를 추가하는 드라이버 하드닝(§5.3.1)으로 momentary write window 제거.

---

## 11. 부록: 재사용/수정 지점 (코드 참조)

라인 번호는 변동될 수 있으므로 함수명을 1차 기준으로 본다.

**재사용(거의 그대로)**
- 카탈로그/검증: `IsSupportedAiCapabilityTool`, `ValidateAiCapabilityToolArgKeys`, `ValidateAiCapabilityScalarText`, `ContainsUnsafeAiCommandCharacters`, `IsHelpToken`, `ExecuteAiCapabilityPlan` (`user/main.cpp`)
- 출력 캡처: `ScopedWideStreamCapture`, `CommandExecutionResult`, `ExecuteCommandWithTranscript` (`user/main.cpp`)
- JSON 빌더: `BuildModuleIntegrityJson`/`BuildDriverIntegrityJson` (`IntegrityScanner.cpp`), `BuildProcessVadJson`/`BuildProcessThreadsJson` (`ProcessTriageScanner.cpp`), `BuildHuntJson` (`UserModeHunter.cpp`), `BuildByovdScanJson` (`ByovdScanner.cpp`), `BuildSnapshotJson` (`SnapshotJson.cpp`)
- 레드액션: `MaybeRedactTranscriptText` (`user/main.cpp`)
- TI 스레드안전 쿼리: `Recent`/`FilterByPid`/`FilterByTask`/`Grep`/`Histogram` (`ThreatIntelSubscriber.h`)
- 디바이스 제어: `DeviceClient::SetWriteMode`, `QuerySessionStatus` (`DeviceClient`)

**신규 작성**
- `McpServer`(http.sys 리스너 + JSON-RPC + auth/host/origin/session), `EngineQueue`/`McpJob`(§4), 콘솔-as-job 리더 전환(§4.2), 통합 surrogate-safe JSON escaper(§7.5), ~12개 스캐너용 `Build*Json`(§7.1), MCP 감사 JSONL(§5.6), `mcp on/off/arm-writes`(후속) 콘솔 명령.

**주의 지점**
- `wmain` argv 파싱 추가는 하지 않는다(헤드리스 모드 미채택). `mcp on` 콘솔 명령으로만 활성화.
- `ScopedCommandProgress`는 MCP-origin job에서 비활성화(C10).
- 디버그 TID/캡처 단일성 assert를 `DeviceClient`/`SymbolEngine` 진입점에 삽입.

---

## 11.1 구현 상태 (v0 스캐폴드, feature/mcp-server)

Phase 0~1 + write 네임스페이스(§6.1.1)를 한 번에 구현한 초기 스캐폴드가 들어가 있다.

신규 파일:
- `user/McpJson.h` — header-only, surrogate-safe JSON escape/UTF-8 변환/탑레벨 값 추출(전송 계층 전용, main.cpp static 의존 없음).
- `user/McpServer.h` / `user/McpServer.cpp` — http.sys loopback 리스너(127.0.0.1 + [::1], `/mcp`), 오버랩드 receive + stop 이벤트, bearer 토큰(per-`mcp on` 32바이트) 상수시간 비교, Host/Origin 검증, 단일 `Mcp-Session-Id` 핀, JSON-RPC(initialize/ping/tools.list/tools.call/resources.list+read/prompts.list+get/notifications), 정적 tool/resource/prompt 카탈로그, bounded 직렬 job 큐.

main.cpp 통합:
- `static McpServer g_McpServer;` 전역 1개.
- `HandleMcpCommand`(`mcp on [port] [--allow-write]` / `off` / `status`) — `HandleCommand` 디스패치 + `CommandRegistry` 등록.
- `DispatchMcpRequest`(엔진 스레드): 읽기 툴은 합성 `kn-live-dbg.ai-capability-plan.v1` 플랜 → `ParseAiCapabilityPlanResponse` → `ScopedWideStreamCapture` 안에서 `ExecuteAiCapabilityPlan`(검증+실행기 재사용). 쓰기 툴은 `DispatchMcpWriteTool`가 타입 인자 검증(`ContainsUnsafeAiCommandCharacters`/whitespace/hex) → 명령 라인 빌드 → `BuildWriteSafetyPlan` backup → `ExecuteCommandWithTranscript`(자동 write-audit) → verify.
- `RunMcpEngineLoop`(엔진 스레드): `WaitForSingleObject(JobReadyEvent, 200)`로 폴링하며 `TryPopJob`→`DispatchMcpRequest`→promise. 콘솔 제어 reader 스레드(`off`/`status`)는 `ReadConsoleW`만 사용(wcout 미접근 → 전역 rdbuf 경쟁 회피). `mcp on` 시 write 모드 arm/disarm, 종료 시 복원.
- `wmain` REPL 루프 진입부에서 `g_McpServer.IsRunning()`이면 `RunMcpEngineLoop` 진입(읽기 전용 기본/단일 엔진 스레드 불변식 유지). 종료 경로에서 `g_McpServer.Stop()`.

vcxproj: `McpServer.cpp` + 헤더 추가, `Httpapi.lib` 링크.

검증/한계(반드시 인지):
- **빌드 그린**: `tools/build.ps1`로 Debug/Release x64 모두 컴파일·링크 성공, MCP 관련 경고 0(http.sys 시그니처는 SDK 10.0.26100.0 `http.h`와 대조 완료). **단, 런타임/라이브 미검증** — `mcp on` 후 실제 MCP 클라이언트 왕복은 테스트 VM에서 확인 필요.
- v0 스캐폴드의 알려진 단순화: ① **Tier-B 완료** — 18개 read 툴 전원 structuredContent 반환(§11.1.1). ② MCP 모드 중 operator 콘솔은 제어(`off`/`status`)만 — 전체 REPL은 `off` 후 재개. ③ `process.set_protection`은 self 전용(`set-ppl-antimalware`)로 매핑, 임의-타깃 PPL은 미구현. ④ 페이지네이션/`resource_link`/per-tool `outputSchema`/`MCP-Protocol-Version` 엄격 검증/elicitation은 후속. ⑤ 레드액션은 lab 분석 충실도를 위해 기본 미적용.

### 11.1.1 Tier-B structuredContent 진행 상태

무발산(divergence-free) 배선: 네 TUI 핸들러(`HandleModuleIntegrityCommand`/`HandleDriverIntegrityCommand`/`HandleVadCommand`/`HandleThreadsCommand`)에 선택적 `std::wstring* structuredJsonOut = nullptr` out-param을 추가해, 이미 `/json` 경로가 쓰던 **동일한 `result` 구조체**로 기존 `Build*Json`을 호출한다(중복 스캔/옵션 파싱 없음). `structuredJsonOut`는 capability 실행기(`ExecuteAiCapability{ModuleIntegrity,DriverIntegrity,VadList,ThreadsList}`) → `ExecuteAiCapabilityPlan`(신규 out-param) → `DispatchMcpRequest`까지 관통한다. vad/threads는 매칭 프로세스별 JSON을 `{"processes":[...]}`로 집계. structuredJson이 있으면 `BuildToolResult`가 그것을 `content[0].text`와 `structuredContent`에 싣고, 토큰 절약을 위해 캡처 TUI 텍스트는 모델로 보내지 않는다(콘솔엔 tee됨).

**완료 — 15개 데이터 툴이 structuredContent 반환** (Debug/Release 빌드 그린, 경고 0):

| 툴 | 빌더 | 위치 |
|----|------|------|
| `module.integrity` / `driver.integrity` | `BuildModuleIntegrityJson` / `BuildDriverIntegrityJson` | IntegrityScanner (기존) |
| `vad.list` / `threads.list` | `BuildProcessVadJson` / `BuildProcessThreadsJson` (프로세스별 `{"processes":[...]}` 집계) | ProcessTriageScanner (기존) |
| `callbacks.list` | `BuildCallbacksJson` (`kn-live-dbg.callbacks.v1`) | CallbackScanner.cpp (신규) |
| `wfp.list` | `BuildWfpJson` (`kn-live-dbg.wfp.v1`) | WfpScanner.cpp (신규) |
| `alpc.list` | `BuildAlpcJson` (`kn-live-dbg.alpc.v1`) | AlpcScanner.cpp (신규) |
| `pool.find` | `BuildPoolJson` (`kn-live-dbg.pool.v1`) | PoolScanner.cpp (신규) |
| `address.inspect` | `BuildAddressInspectJson` (`kn-live-dbg.address.v1`) | AddressInspector.cpp (신규) |
| `etw.integrity` | `BuildEtwIntegrityJson` (`kn-live-dbg.etw-integrity.v1`) | EtwScanner.cpp (신규) |
| `nmi.list` | `BuildNmiJson` (`kn-live-dbg.nmi.v1`) | NmiScanner.cpp (신규) |
| `fwtable.list` | `BuildFirmwareTableJson` (`kn-live-dbg.fwtable.v1`) | FirmwareTableScanner.cpp (신규) |
| `wnf.list` | `BuildWnfInstancesJson` (`kn-live-dbg.wnf.v1`) | WnfScanner.cpp (신규) |
| `ti.query` | `BuildMcpTiEventsJson` / `BuildMcpTiStatsJson` (`kn-live-dbg.ti.v1` / `.ti-stats.v1`) — 스레드안전 ring API(`Recent`/`FilterByPid`/`FilterByTask`/`Grep`/`SnapshotStats`) 직접 직렬화, cap 200/최대 5000 | main.cpp (신규) |
| `process.find` | `BuildMcpProcessListJson` (`kn-live-dbg.process-list.v1`) | main.cpp (신규) |

신규 빌더는 전부 surrogate-safe `mcpjson::` escaper 재사용, 파일별 고유 hex 헬퍼(`WfpJsonHex` 등). 스캐너별 빌더 8개는 병렬 워크플로로 작성.

**나머지 3개도 완료** (18개 read 툴 전원 structured):
- `process.describe` — `BuildMcpProcessListJson` 재사용(process.find과 동일).
- `wnf.decode` — `BuildMcpWnfDecodedJson`(`kn-live-dbg.wnf-decode.v1`), `DecodeWnfStateName(parsed)` 직접 호출(main.cpp).
- `type.describe` — `BuildMcpTypeDumpJson`(`kn-live-dbg.type.v1`): `dt` 출력을 **중첩 캡처**(엔진 스레드, LIFO 안전)로 받아 `+0x<off> <name> : <value>` 라인을 `fields[]`로 파싱 + raw `text` 보존. 다중 프로세스는 `{"dumps":[...]}`로 집계.

**Tier-B 완료: 초기 18개 read 툴 전원 structuredContent 반환** (Debug/Release 빌드 그린, 경고 0).

### 11.1.2 카탈로그 확장 — 안티치트 탐지 9종 추가 (2026-06-25)

초기 카탈로그(내부 `ai`가 쓰던 18툴)에 없던 커널 안티치트 탐지를 MCP 툴로 추가. 각 툴은 동일 패턴: `IsSupportedAiCapabilityTool` allowlist + `ValidateAiCapabilityToolArgKeys` 인자 화이트리스트 + 신규 `ExecuteAiCapability*` 실행기 + `ExecuteAiCapabilityPlan` 스위치 분기 + 핸들러 `structuredJsonOut` out-param + `McpServer.cpp` `kTools` 엔트리 + 플래너 프롬프트. 내부 `ai` 명령도 동일 툴을 얻는다.

| MCP tool | TUI | 빌더 | 비고 |
|----------|-----|------|------|
| `ssdt.scan` | `!ssdt` | `BuildSsdtJson`(`kn-live-dbg.ssdt.v1`) | SSDT/shadow 후크 |
| `idt.scan` | `!idt` | `BuildIdtJson`(`.idt.v1`) | IDT 후크 + per-CPU divergence |
| `cr.scan` | `!cr` | `BuildCrJson`(`.cr.v1`) | CR0.WP/SMEP/SMAP |
| `msr.check` | `!msrcheck` | `BuildMsrJson`(`.msr.v1`) | SYSCALL MSR 후크 |
| `vbs.scan` | `!vbs` | `BuildVbsJson`(`.vbs.v1`) | VBS/HVCI/CI/SecureKernel/trustlet (단일 툴로 !ci/!securekernel 포함) |
| `byovd.scan` | `byovd scan /no-update` | `BuildByovdScanJson`(기존) | `/no-update` 강제(네트워크/subprocess 차단) |
| `pool.scan_pe` | `pool-scan-pe` | `BuildPoolPeJson`(`.pool-pe.v1`) | args tag/limit/suspicious; `/dump` 미노출 |
| `hunt.run` | `!hunt` | `BuildHuntJson`(기존) | args mode(quick/deep); `/summary` 강제 |
| `snapshot.capture` | `!snapshot baseline` | `BuildSnapshotJson`(기존) | args name; baseline 파일 write(커널 write 아님 → read-only 모드 허용) |

신규 빌더 6개(ssdt/idt/cr/msr/vbs/poolpe)는 병렬 워크플로로 각 스캐너 `.cpp`에 작성, `mcpjson::` escaper + 파일별 고유 hex 헬퍼. **결과: MCP read 툴 27종 전원 structuredContent**, Debug+Release 빌드 그린.

미노출 유지(설계): raw `kd`/DbgEng 패스스루, `!ci`/`!securekernel` 개별(vbs.scan에 통합), `dump-raw`/`dump-pe` 임의 경로, raw 메모리 read/disasm.

### 11.1.3 리소스 보강 — 8종 구현 (2026-06-25)

§6.2의 리소스를 모두 구현. `BuildResourcesList`(McpServer.cpp) 광고 + `DispatchMcpRequest`의 `ResourceRead` 분기(엔진 스레드)로 서빙:

| 리소스 | 소스 | 빌더 |
|--------|------|------|
| `kn://session/info` | `QuerySessionStatus`+ABI+arm | (인라인) |
| `kn://capabilities` | kTools 매니페스트 | `BuildCapabilitiesResource`(transport) |
| `kn://modules/kernel` | `SymbolEngine.Modules()` | `BuildMcpModulesJson`(`kn-live-dbg.modules.v1`) |
| `kn://drivers/status` | `DriverService.Query`+세션 | `BuildMcpDriversJson`(`.drivers.v1`) |
| `kn://session/symbols` | `SymbolPath`/모듈수/`IsReady` | `BuildMcpSymbolsJson`(`.symbols.v1`) |
| `kn://ti/stats` | `SnapshotStats`/`IsActive` | `BuildMcpTiStatsJson`(기존, `.ti-stats.v1`) |
| `kn://snapshot/current` | `state.SnapshotBaseline` | `BuildSnapshotJson`(기존); 없으면 `present:false` |
| `kn://audit/tail` | `aiState.WriteAuditPath` JSONL 마지막 50줄 | `BuildMcpAuditTailJson`(`.audit-tail.v1`) |

**MCP read 툴 27종 + 리소스 8종 + 프롬프트 7종, 전부 빌드 그린(Debug+Release).**

### 11.1.4 MCP 자동 audit (2026-06-25)

§5.6 충족. `McpServer`가 전용 append-only JSONL 로그를 소유한다 — 경로 `<exeDir>\.kn-live-dbg\mcp-audit-<port>.jsonl`, `mcp on` 시 **항상 ON**(operator의 `ai audit` 토글과 무관). 리스너 스레드가 `initialize`/`tools/call`/`resources/read`마다 1레코드 append: `ts`(GetSystemTime UTC), `session`, `peerPort`(sockaddr 바이트에서 직접 추출 — winsock 불필요), `method`, `tool`, `args`(512자 truncate), `decision`(ok/unknown-tool/writes-disabled/engine-busy/tool-error/unknown-resource/session-open), `isError`, `resultBytes`, `writeArmed`. 단일 chokepoint(리스너)라 읽기·쓰기·리소스·거부를 모두 포착. `McpServerConfig.AuditPath` + `McpServer::AuditPath()`/`AppendAuditLine`(mutex, append 모드) + Start에서 디렉터리 생성. `kn://audit/tail`은 이 경로를 읽도록 전환(항상 `enabled:true`).

부수 수정: `resources/read` 리스너가 `session/info`+`capabilities`만 처리해 §11.1.3의 신규 6개 리소스가 런타임에 `unknown-resource`로 떨어지던 버그 발견 → `kn://` 전체를 엔진(`DispatchMcpRequest`)으로 포워딩하도록 수정(컴파일은 통과하던 런타임 라우팅 버그). Debug+Release 빌드 그린.

- 라이브 검증 항목: `mcp on` → `claude mcp add --transport http` 연결 → `tools/list`/`resources/list` + `callbacks.list`/`ssdt.scan`/`kn://modules/kernel` 등 왕복 → `--allow-write`로 `memory.write_virtual` backup/verify 경로(테스트 VM, 스냅샷 후).

## 12. 설계 핵심 7줄 요약

1. **인프로세스 loopback Streamable HTTP**(stdio 아님), 기본 OFF, `mcp on`으로 활성화.
2. **단일 엔진 스레드**에 모든 MCP 요청을 직렬 큐로 마샬; HTTP 스레드는 커널을 절대 안 건드림.
3. `ScopedWideStreamCapture`는 **엔진 스레드 전용·동시 1개**(전역 rdbuf UAF 방지).
4. **두 모드** — 기본 읽기 전용(`SetWriteMode(false)`로 커널 플래그 비무장) / **Lab write 모드**(`--allow-write`, 격리 VM)는 타입 write 툴 전면 개방하되 자동 backup/verify/audit 유지, raw kd·숨은 write 금지.
5. 모든 `tools/call`은 **기존 카탈로그+가드** 통과, raw 명령/신규 primitive 불가, egress 레드액션.
6. 결과는 `structuredContent`+동일 JSON 텍스트 미러, 에러는 `isError:true`, 대용량은 `resource_link`+페이지네이션.
7. **취소는 큐 단계만**(인플라이트 스캔 선점 불가 — 정직), 단일 세션 핀, 필수 감사, kill switch가 커널까지 비무장.
