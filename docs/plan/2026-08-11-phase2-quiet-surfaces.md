# 작업 계획서: Phase 2 Quiet Kernel Surfaces (완벽 구현)

- 작성일: 2026-08-11
- 상태: 완료
- 관련 문서: `docs/FEATURE_PLAN.md`, `docs/ARCHITECTURE.md`, `docs/WINDBG_COMMAND_COVERAGE.md`
- 프로젝트 사본: 승인 후 `docs/plan/2026-08-11-phase2-quiet-surfaces.md`에 동기화

## 1. 목표 / 배경

**목표:** Phase 2로 제안한 “조용한(persistent / data-oriented) 커널 표면” 4축을 **프로덕션급으로 완전 구현**한다.

| # | 기능 | 조사 가치 |
|---|---|---|
| 1 | Timer / DPC / Work-item 콜백 열거 | 후킹 없이 주기 실행·지연 실행 지속성 |
| 2 | ETW provider DKOM + TI 수신률 교차 뷰 | 텔레메트리 무음화(테이블 zero-out 등) |
| 3 | Token privilege triage → `!hunt` 통합 | 커널 R/W 이후 잔여 권한 상승 상태 |
| 4 | Hive `GetCellRoutine` + HAL dispatch table | 레지스트리 셀 훅 + 고전/현대 플랫폼 테이블 훅 |

**배경:**  
Phase 1(숨은 드라이버, GDT, device stack, prologue)은 꿀보 판단으로 **요즘 공격 벡터 우선순위가 낮음**.  
Phase 2는 후킹 탐지 이후에도 남는 **데이터 구조 조작·비동기 콜백·권한 잔여** 축이며, 현재 코드베이스에 구현이 없다.

**이 작업이 없으면:**  
SSDT/IDT/LSTAR/콜백이 깨끗한 채 **DPC 주기 실행, ETW 무음, 토큰 권한, hive/HAL 테이블** 경로가 사각지대로 남는다.

## 2. 범위

### 포함

1. **`!dpc` / `!timer` (및 선택 `!workitem`)**  
   - 활성/등록 콜백 루틴의 module/symbol 주석  
   - non-image / unexpected-module 플래그  
   - 바운디드 walk + cycle guard + JSON  
2. **`!etw providers` + TI rate cross-view**  
   - 커널 ETW provider/GUID 등록 표면 열거(가능한 범위)  
   - enable/callback 구조 이상(null, non-image)  
   - `!ti` 활성 시 수신률·drop·last-event 와 커널 enable 상태 교차  
3. **`!token` + `!hunt` privilege findings**  
   - `_EPROCESS.Token` → `_TOKEN` / `_SEP_TOKEN_PRIVILEGES`  
   - 고위험 privilege 규칙(보수적)  
   - hunt Default/Deep 통합 + snapshot `process-security` 확장  
4. **`!hive` (GetCellRoutine) + `!hal` (HalDispatchTable[+Private])**  
   - hive list walk, GetCellRoutine(및 가능 시 Free/Release) 소유권  
   - HAL 테이블 슬롯 → module/symbol, outside-image 플래그  
5. **공통 통합**  
   - CommandRegistry, help, completion  
   - SnapshotCollector 도메인  
   - MCP + AI capability tools  
   - README / ARCHITECTURE / FEATURE_PLAN / WINDBG_COMMAND_COVERAGE / MANUAL_TEST_CHECKLIST  
   - driver-free self-test 가능한 단위 로직 + 가능한 positive-control 설계 노트

### 제외 (이번 범위 밖)

- Phase 1: hidden driver cross-view, GDT, `!drvobj`/`!devstack`, module prologue 전체 스캔  
- 드라이버 새 IOCTL (기본: `READ_VIRTUAL`만 사용)  
- Work-item 전체 스레드풀 완전 재구성 (불안정 시 DPC/Timer 우선, workitem은 best-effort 또는 명시 incomplete)  
- ETW provider 트리 100% 빌드 독립 보장 주장 (실패 시 clean fail + coverage flag)  
- 치료/패치/쓰기 경로  
- Silo bindflt, WDAC blob full decode (별 로드맵)

### 전제 / 의존성

- 기존 LiveKD 스플릿: 파싱·판정은 user-mode  
- PDB/DIA 우선 + `LayoutResolver` + live pointer 검증 fallback (fwtable/WFP 패턴)  
- `DeviceClient::ReadMemory`, `SymbolEngine`, process inventory / `ResolveProcess`  
- `TiSubscriber` stats (수신률 교차)  
- x64 only, Windows 10/11 최근 빌드 우선 (구형은 warning + partial)

## 3. 접근안 비교

| 안 | 요약 | 장점 | 단점 | 리스크 |
|---|---|---|---|---|
| A | 4축 전부 신규 스캐너 + 전체 통합(MCP/snapshot/hunt/docs) | “완벽 구현” 목표와 일치, 운영 일관성 | 변경 표면 큼, 레이아웃 리스크 집중 | 중~고 |
| B | 스캐너만 콘솔 명령으로 먼저, 통합은 후속 | 빠른 가시성 | 반쪽 제품, snapshot/hunt/AI 사각 | 중 |
| C | 하드코딩 오프셋 중심 단일 바이너리 스캔 | 구현 단순 | 빌드 드리프트로 거짓 양성/음성, 프로젝트 원칙 위배 | 고 |

**선택: A**

선택 근거:
- 꿀보 요청이 “Phase 2를 **완벽하게** 구현”  
- 기존 FEATURE_PLAN cross-cutting 규칙(JSON, snapshot, help, AI)을 스킵하면 유지보수 부채가 바로 생김  
- B/C는 장기적으로 재작업 비용이 더 큼  

구현 순서는 리스크 역순으로 **안정 축 먼저 → 불안정 축 나중**:

1. `!hal`  
2. `!hive`  
3. `!token` + hunt/snapshot  
4. `!etw providers` + TI cross-view  
5. `!dpc` / `!timer` (+ workitem best-effort)  
6. 통합 회귀·문서 마감

## 4. 아키텍처 / 설계

### 4.1 공통 스캐너 계약

모든 신규 스캐너는 기존 `NmiScanner` / `SsdtScanner` / `FirmwareTableScanner` 패턴을 따른다.

```text
class XxxScanner {
  XxxScanner(DeviceClient&, SymbolEngine&);
  bool Scan(Options, XxxScanResult*, std::wstring* error);
};
std::wstring BuildXxxJson(const XxxScanResult&);
```

규칙:
1. kernel-canonical 포인터 검사  
2. 바운디드 walk + visited set  
3. partial-read → warning, 전체 abort 최소화  
4. `Suspicious`는 **정확한 필드/주소/모듈 근거**와 함께  
5. JSON schema: `kn-live-dbg.<name>.v1`  
6. coverage incomplete 플래그 명시 (clean ≠ full coverage)

### 4.2 기능별 설계

#### A. HAL Dispatch (`user/HalDispatchScanner.*`, cmd `!hal`)

**앵커:**  
- `nt!HalDispatchTable` (필수)  
- `nt!HalPrivateDispatchTable` (있을 때)

**동작:**
1. 심볼 resolve → 테이블 base  
2. 알려진 슬롯 수 또는 PDB type size / 휴리스틱 상한으로 qword 슬롯 읽기  
3. 각 non-null 포인터 → `FindNearestSymbol` + module 소속  
4. outside all modules → `[SUSPICIOUS]`  
5. null 슬롯은 정상일 수 있음 → 의심 아님 (문서화)

**명령:**
```text
!hal
!hal dispatch
!hal private
!hal [/json <path>]
```

**Snapshot:** domain `hal` 또는 `cpu-state` 하위 identity `hal:dispatch:<index>`  
**MCP/AI:** `hal.scan`

#### B. Hive GetCellRoutine (`user/HiveScanner.*`, cmd `!hive`)

**앵커 후보 (우선순위):**
1. PDB: `nt!CmpHiveListHead` / 관련 silo 필드  
2. `_CMHIVE` / `_HHIVE` 필드: `GetCellRoutine`, (가능 시) `ReleaseCellRoutine` / `Free`  
3. 리스트: `HiveList` LIST_ENTRY

**동작:**
1. hive list bounded walk  
2. 각 hive의 GetCellRoutine 읽기  
3. 기대: `nt!HvpGetCell*` 계열 또는 ntoskrnl 내부  
4. non-image / non-nt 모듈 → suspicious  
5. 레이아웃 실패 시 `Resolved=false`, coverage incomplete (날조 금지)

**명령:**
```text
!hive
!hive list
!hive cells
!hive [/json <path>]
```

**Snapshot:** domain `hive`  
**MCP/AI:** `hive.list`

**참고:** Volatility `getcellroutine` 계열 탐지와 동형. 호출(`Cm*`)은 하지 않음 — 수동 읽기만.

#### C. Token privilege (`user/TokenPrivilegeScanner.*`, cmd `!token`)

**경로:**
1. PID / image / EPROCESS resolve (process inventory 재사용)  
2. `_EPROCESS.Token` EX_FAST_REF → object pointer (low bits mask)  
3. PDB: `_TOKEN.Privileges` → `_SEP_TOKEN_PRIVILEGES` Present/Enabled/EnabledByDefault  
4. 선택: Integrity level, TokenFlags, AuthenticationId (있으면)

**의심 규칙 (보수적, 기본 세트):**

| 조건 | Risk | Confidence | 비고 |
|---|---|---|---|
| SeDebugPrivilege / SeLoadDriver / SeTcb / SeCreateToken Enabled on non-system, non-PPL interactive-looking process | high/medium | medium | SYSTEM/services 노이즈 억제 필요 |
| Enabled privileges not in Present | high | high | 구조 손상 신호 |
| Token read fail for live process | — | — | coverage incomplete, not finding |

**노이즈 억제:**
- PID 4, smss, csrss, services, lsass, TrustedInstaller 등 well-known 시스템 이미지 기본 허용  
- “Enabled == 기대 서비스 프로필”이면 finding 아님  
- Default hunt: high-signal only; Deep: 더 넓은 리포트 + JSON detail

**명령:**
```text
!token <pid|image|eprocess>
!token <target> [/priv] [/json <path>]
```

**Hunt 통합:**
- `HuntProcessRecord`에 privilege present/enabled 요약 필드 추가  
- finding class 예: `unexpected_enabled_privilege`, `token_privilege_inconsistency`  
- assessment `what/why/next`에 followup `!token <pid>`

**Snapshot:** `process-security` evidence에 privilege fingerprint (해시/정렬된 이름 목록) — 주소 제외, same-boot diff 가능

#### D. ETW providers + TI cross-view (`EtwScanner` 확장)

**Providers (`!etw providers`):**
1. 공개/후보 심볼로 registration/GUID entry 앵커 탐색  
2. Zydis/심볼 기반 후보 + live shape scoring (WNF/fwtable 패턴)  
3. 레코드: GUID, enable mask/info 요약, callback 포인터(있으면), module/symbol  
4. 플래그: callback non-image, enable 구조 null-but-registered 이상, walk incomplete  

**성공 기준 현실성:**  
전체 ETW 내부 트리 완전 재현이 아니라 **“신뢰 가능한 등록 표면 일부 + 명시적 coverage”**.  
완전 실패 시 decoder-only 수준의 진단 출력(이미 `!wnf` 철학).

**TI cross-view (`!etw ti-cross` 또는 `!etw providers /ti` + hunt deep):**
1. `TiSubscriber::IsActive()` + `SnapshotStats()`  
2. metrics: events/sec, received, dropped, last-event age, keyword mask  
3. 교차 판정:
   - TI session active + PPL ok + elapsed > N sec + received==0 → `ti_silent_while_subscribed` (medium, coverage-aware)  
   - high drop rate → operational note  
   - provider walk이 TI GUID enable 이상을 보이면 escalate  
4. **TI 미시작은 finding이 아님** (incomplete / skipped)

**명령 확장:**
```text
!etw providers [/limit n] [/json path]
!etw ti-cross
!etw integrity   # 기존 유지
!etw loggers     # 기존 유지
```

**MCP/AI:** `etw.providers`, `etw.ti_cross` (또는 `etw.integrity` args 확장 — 카탈로그 명확성을 위해 분리 권장)

#### E. DPC / Timer (`user/DpcTimerScanner.*`, cmd `!dpc` / `!timer`)

**가장 레이아웃 리스크가 큰 축 → “완벽”의 정의:**

| 수준 | 내용 | 이번 목표 |
|---|---|---|
| L1 | PRCB/전역에서 DPC 큐 또는 known list head를 찾아 DeferredRoutine 주석 | **필수** |
| L2 | Timer table entries → Dpc → DeferredRoutine | **필수 (바운디드 샘플/전체 중 빌드 가능 범위)** |
| L3 | Ex work-item / modern threadpool | **best-effort**; 실패 시 `workitem_coverage=incomplete` 명시, 거짓 clean 금지 |

**동작 원칙:**
1. PDB 필드 우선 (`_KDPC.DeferredRoutine`, `_KTIMER.Dpc` 등)  
2. per-processor: 가능하면 active processor 수만큼 PRCB 후보 (심볼 `KiProcessorBlock` / `KeGetPrcb` 관련)  
3. 각 routine → module/symbol; non-image → suspicious  
4. 정상 3rd-party 드라이버 DPC는 **outside-nt 단독으로는 high risk로 올리지 않음** — non-image 또는 unexpected pool-only 주소만 high  
5. 출력: summary + suspicious-only 기본, `/verbose` full

**명령:**
```text
!dpc [/verbose] [/limit n] [/json path]
!timer [/verbose] [/limit n] [/json path]
!workitem   # coverage incomplete 허용
```

**Snapshot:** domain `dpc-timer`  
**MCP/AI:** `dpc.list`, `timer.list`

### 4.3 통합 매트릭스

| 기능 | TUI | Snapshot domain | Hunt | MCP/AI tool | JSON schema |
|---|---|---|---|---|---|
| HAL | `!hal` | `hal` (or cpu-state) | no (optional deep later) | `hal.scan` | `kn-live-dbg.hal.v1` |
| Hive | `!hive` | `hive` | no | `hive.list` | `kn-live-dbg.hive.v1` |
| Token | `!token` | `process-security` 확장 | **yes** | `token.inspect` | `kn-live-dbg.token.v1` |
| ETW providers | `!etw providers` | `etw` 확장 | deep 교차 optional | `etw.providers` | `kn-live-dbg.etw-providers.v1` |
| TI cross | `!etw ti-cross` | optional metrics | deep | `etw.ti_cross` | `kn-live-dbg.etw-ti-cross.v1` |
| DPC/Timer | `!dpc` `!timer` | `dpc-timer` | no | `dpc.list` `timer.list` | `kn-live-dbg.dpc.v1` / `.timer.v1` |

### 4.4 파일 변경 목록

**신규:**
- `user/HalDispatchScanner.h/.cpp`
- `user/HiveScanner.h/.cpp`
- `user/TokenPrivilegeScanner.h/.cpp`
- `user/DpcTimerScanner.h/.cpp` (DPC+Timer 통합; workitem 섹션 포함 가능)
- `docs/plan/2026-08-11-phase2-quiet-surfaces.md` (이 계획 사본)
- 필요 시 `docs/research/phase2-quiet-surfaces.md` (레이아웃 실험 로그)

**수정:**
- `user/EtwScanner.h/.cpp` — providers + ti-cross
- `user/main.cpp` — handlers, help, AI catalog/executors, native-owned set
- `user/CommandRegistry.cpp`
- `user/KnLiveDbg.vcxproj` (+ filters)
- `user/SnapshotCollector.cpp` (+ SnapshotModel identity helpers if needed)
- `user/UserModeHunter.h/.cpp` — token findings
- `user/ThreatIntelSubscriber.*` — rate helper API if missing (SnapshotStats 재사용 우선)
- `user/McpServer.cpp`, `McpSelfTest.cpp`
- `tools/validate-mcp-tool-catalog.ps1`, `validate-console-surface.ps1` (기대값)
- `docs/FEATURE_PLAN.md`, `ARCHITECTURE.md`, `WINDBG_COMMAND_COVERAGE.md`, `README.md`, `MANUAL_TEST_CHECKLIST.md`
- `docs/MCP_SERVER_DESIGN.md` (+ `.ko.md` if 동기화 정책 유지), `AI_ASSISTED_WORKFLOWS.md`
- `docs/CHANGELOG.md` (없으면 생성 여부 오픈 — 프로젝트에 없으면 FEATURE_PLAN 상태 갱신으로 대체)

**드라이버:** 변경 없음 (기본)

### 4.5 코드 스타일 (프로젝트 강제)

- C++ , ASCII comments/logs  
- brace on next line, always braces for if/for/while  
- single-exit `do { ... } while (false)` when practical  
- no placeholder “TODO implement” in merge path

## 5. 구현 단계 (실행 순서)

### Step 0 — 계획 고정
1. 본 계획 승인  
2. `docs/plan/2026-08-11-phase2-quiet-surfaces.md` 기록  
3. FEATURE_PLAN에 Phase 2 섹션 추가 (상태: 진행중)

### Step 1 — HAL (`!hal`)
1. 스캐너 + JSON  
2. TUI handler + registry + help  
3. Snapshot capture  
4. MCP/AI tool  
5. 수동: clean host → 0 suspicious 기대; 문서화

### Step 2 — Hive (`!hive`)
1. list head resolve + layout scoring  
2. GetCellRoutine ownership  
3. Snapshot + MCP  
4. clean host baseline

### Step 3 — Token (`!token` + hunt + process-security)
1. FastRef + privilege decode  
2. standalone command  
3. UserModeHunter findings + noise rules  
4. Snapshot process-security fingerprint  
5. clean-host hunt 회귀 (false positive 금지 검증)

### Step 4 — ETW providers + TI cross
1. provider walk (guarded)  
2. `!etw providers` / `ti-cross`  
3. etw snapshot domain 확장  
4. MCP tools  
5. TI off / TI on 동작 매트릭스 문서화

### Step 5 — DPC / Timer
1. PDB-first structure resolve  
2. bounded multi-CPU sampling  
3. risk policy (non-image only high by default)  
4. snapshot + MCP  
5. coverage incomplete 경로 검증

### Step 6 — 마감
1. console-surface / mcp-tool-catalog self-tests 갱신  
2. README/ARCHITECTURE/WINDBG/MANUAL checklist  
3. FEATURE_PLAN 상태 완료  
4. 진행 로그 갱신  
5. (가능 시) Release 빌드 + 드라이버 로드 수동 smoke 체크리스트 실행

## 6. 위험 및 실패 경로

| 위험 | 증상 | 완화 |
|---|---|---|
| 비공개 구조 드리프트 (ETW provider, timer table, workitem) | empty/wrong walk, BSOD 없음(읽기 전용) but false clean | live scoring + incomplete flag; 실패 시 명시; 날조 금지 |
| DPC/Timer 정상 3rd-party 노이즈 | 과다 suspicious | non-image만 high; loaded driver DPC는 verbose |
| Token privilege 노이즈 (서비스 계정) | hunt 오염 | system image allowlist; Default vs Deep 분리 |
| TI silent finding 오탐 | TI 미설치/미권한/게임 없는 호스트 | active subscription + PPL + elapsed gate |
| Hive list 오탐 (3rd party filter?) | 거의 없음; GetCell 교체만 고신호 | nt 모듈 기대 + notes |
| main.cpp 비대화 | 유지보수 비용 | 핸들러 thin; 로직 스캐너 파일에 |
| MCP catalog drift | self-test fail | validate scripts 동시 수정 |

**롤백:** 기능별 커밋/논리적 분리 — 한 축 실패 시 해당 명령만 비활성/문서 deferred 가능.  
**호환성:** test-signed driver 환경; HVCI 호스트에서도 read-only 스캔 동작 목표.

## 7. 검증 방법

### 자동 (드라이버 불필요 일부)
1. `validate-console-surface.ps1` — 새 명령 help/completion  
2. `validate-mcp-tool-catalog.ps1` — 새 툴  
3. 스캐너 순수 함수 self-test (privilege bit decode, risk rule tables) — `main` 또는 전용 test path에 가능하면 추가

### 수동 / 승격 환경 (드라이버 필요)
1. **Clean host:**  
   - `!hal` / `!hive` / `!dpc` / `!timer` → 0 high suspicious (또는 문서화된 known noise)  
   - `!token 4` → SYSTEM 기대 권한, finding 없음  
   - `!hunt` RequireClean 회귀 유지  
2. **TI matrix:**  
   - TI off → ti-cross = skipped  
   - `set-ppl-antimalware on` + `!ti start` 후 수 초 → received>0 또는 환경 한계 명시  
3. **Snapshot/diff:**  
   - baseline 후 동일 도메인 재캡처 → 안정 identity  
4. **JSON:**  
   - schema version 필드, warnings[], coverage flags 존재

### 성공 기준 (“완벽”의 조작적 정의)

1. 4축 모두 **TUI 명령 + JSON + help + registry** 존재  
2. HAL/Hive/Token/DPC-Timer/ETW-providers 가 **snapshot 도메인에 반영** (또는 문서화된 예외 없음)  
3. Token은 **hunt Default에서 고신호만**, clean-host false positive 0  
4. 레이아웃 실패 시 **clean 위장 없이 incomplete**  
5. MCP/AI 카탈로그 self-test 통과  
6. README/ARCHITECTURE/FEATURE_PLAN/WINDBG 문서 동기화  
7. 드라이버 ABI 변경 없음 (또는 변경 시 별도 승인)

## 8. 오픈 이슈

- [ ] Work-item을 필수 L3로 올릴지, incomplete 허용 best-effort로 둘지 (기본: best-effort)  
- [ ] HAL을 snapshot `cpu-state`에 병합 vs 독립 `hal` 도메인 (기본: 독립 `hal`, diff 단순화)  
- [ ] ETW provider 완전 열거 실패 시 최소 viable: “anchor diagnostics only” 허용 여부 (기본: 허용 + 명시)  
- [ ] Token high-risk privilege 최종 세트 확정 (제안: SeDebug, SeLoadDriver, SeTcb, SeCreateToken, SeRelabel, SeAssignPrimaryToken)  
- [ ] Positive-control fixture를 probe_driver에 넣을지 (권장: 후속; Phase 2 본문은 읽기 스캐너 완성 우선)

## 9. 진행 로그

- 2026-08-11: 코드/문서 조사 완료. Phase 1 제외, Phase 2 4축 완벽 구현 목표로 계획 초안 작성.
- 2026-08-11: 계획 승인 후 구현. 스캐너 4종+ETW 확장, TUI/MCP/AI/snapshot/hunt 통합, Release 빌드 및 console/mcp self-test 통과. 드라이버 ABI 변경 없음.
- 2026-08-11: 적대적 리뷰 후 수정 — SE privilege 비트맵 교정, hunt/snapshot의 SeDebug 오탐 억제, CmpMasterHive 리스트 앵커 제거, HiveList PDB 필수, HAL bound 미검증 시 third-party 오탐 억제, help 자동완성 버그 수정.
