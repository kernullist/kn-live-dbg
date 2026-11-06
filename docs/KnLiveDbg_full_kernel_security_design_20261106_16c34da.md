# KnLiveDbg 전체 커널 분석·보안 조사 플랫폼 고도화 설계

## 최신 구현 재평가와 은닉 코드 탐지·원인 분석의 통합 설계

| 구분 | 기준 |
|---|---|
| 작성·외부 자료 확인일 | **2026-11-06, 한국 표준시 기준** |
| 저장소 | `kernullist/kn-live-dbg` |
| 검토한 main | **`16c34da0e8e66a0d5f1d39ed54b1cd69d89765c3`** |
| 해당 커밋 시각 | 2026-10-29 19:57:54 UTC / **2026-10-30 04:57:54 KST** |
| 직전 검토 기준 | `17991819badb926c7d6e113abee6eded4e5ba0f9`; 현재 기준은 21개 커밋 앞섬 |
| 배포본과 개발본 | 문서가 식별하는 배포 기준은 `v0.0.36 / 6646461`; 아래 평가는 **개발 main**에 대한 것 |
| 목적 | Windows x64 커널 전반의 구조·수명·실행·I/O·장애를 분석하고, 은닉 게임핵·악성코드의 관측과 원인 추적 능력을 강화 |
| 산출물 성격 | 정적 코드·문서 검토, 일차 자료 조사, 제한된 독립 테스트, 구현 가능한 후속 설계 |
| 이번에 수행하지 않은 검증 | Windows 전체 빌드, 드라이버 로드, Driver Verifier, 실게임·실악성코드 실행, 실호스트 LA57·VTL1·VMI 검증 |

커밋과 비교 기준은 연결된 GitHub에서 확인했다. 커밋 날짜, 문서의 한국 날짜, 이번 작성일은 서로 다르다. 과거 보고서나 저장소에 기록된 테스트를 이번 작업에서 다시 실행한 것으로 취급하지 않는다. [R01] [R02] [R03] [R04]

> **핵심 결론**
>
> 이제 가장 중요한 일은 새로운 기능 이름을 늘리는 것이 아니다. 이미 추가한 관측 소스, 주소 모델, 이미지 재검증, 증거 파일, 그래프와 작업 상태를 **라이브 수집 → 판정 근거 보존 → 관계 연결 → 종료 후 재검증**이라는 하나의 실제 조사 경로로 완성해야 한다.
>
> 동시에 “커널의 모든 것”을 명령 개수가 아니라 **각 분석 영역에서 무엇을 발견하고, 어떤 상태와 수명을 확인하며, 실행·변경·장애 원인을 어디까지 설명할 수 있는가**로 정의해야 한다.

---

## 목차

1. [현재 수준과 이번 설계의 결론](#s01)
2. [이전 제안의 반영 상태: 재구현하지 말아야 할 것](#s02)
3. [코드에서 확인한 우선 개선점](#s03)
4. [전체 커널 분석 범위: 22개 영역](#s04)
5. [위협 모델과 관측 신뢰 경계](#s05)
6. [목표 아키텍처와 네 가지 완결 조사 경로](#s06)
7. [대상·객체·주소 공간·시간의 공통 정체성](#s07)
8. [관측 소스와 읽기·변환 증거의 통합](#s08)
9. [타입·심벌·실행 중 객체 검증](#s09)
10. [주장별 증명 정책과 일곱 종류의 검사 범위](#s10)
11. [라이브 이미지 검증과 신뢰 가능한 참조](#s11)
12. [영속 사건 저장소와 시간 관계 그래프](#s12)
13. [공정한 스케줄링과 순간 은닉 관측](#s13)
14. [은닉 커널 코드 탐지 설계](#s14)
15. [은닉 유저 코드·게임핵·악성코드 탐지 설계](#s15)
16. [실제 실행·쓰기 관측: ETW·PT·VMI·TTD](#s16)
17. [I/O·대기·교착·성능·크래시 원인 분석](#s17)
18. [백엔드 통합과 플랫폼 지원 행렬](#s18)
19. [능동적 AI 조사와 도구 자체의 안전성](#s19)
20. [최신 기술 동향과 채택 판단](#s20)
21. [구현 작업 패키지와 의존 관계](#s21)
22. [회귀·대조군·실전 검증 설계](#s22)
23. [독립 비교 평가와 세계 최고 수준의 판단 기준](#s23)
24. [우선 실행 순서와 완료 조건](#s24)
25. [최종 권고](#s25)

부록 A. [이번 독립 테스트의 방법과 결과](#appendix-a)<br>
부록 B. [검토 범위와 근거 관리](#appendix-b)<br>
부록 C. [신규 계약 예시](#appendix-c)<br>
부록 D. [저장소·외부 출처](#appendix-d)

---

<a id="s01"></a>
## 1. 현재 수준과 이번 설계의 결론

### 1.1. 객관적인 현재 위치

현재 KnLiveDbg는 단순한 메모리 덤퍼나 드라이버 목록 검사기가 아니다. 문서와 확인한 코드에는 커널·프로세스 메모리 관측, 이미지 바이트 비교, 다중 뷰 대조, 실행 참조 해석, 증거 보존 및 제한된 오프라인 재생을 연결하는 상당한 기반이 있다. 최신 변경은 기본 쓰기 차단, 주소 폭 전달, 독립적인 관측 소스, 타입 패키지, 이미지 검증 recipe, 단일 증거 그래프와 작업 상태 조회까지 확장했다. [R03] [R05] [R06]

그러나 다음 세 단계는 분리해서 평가해야 한다.

| 단계 | 현재 판단 | 판단 근거 |
|---|---|---|
| 기능·계약의 존재 | 폭넓게 구현됨 | 실제 소스, 공개 CLI 계약, 소유 테스트와 스키마가 존재 |
| 하나의 조사 흐름으로 통합 | **부분 구현** | 일부 라이브 읽기와 fallback은 통합 receipt가 없고, 이미지 recipe·그래프·trace는 각각 제한된 경로로 동작 |
| 다양한 실환경에서의 탐지·원인 분석 우위 | **입증 전** | 최신 checkpoint 상당수는 드라이버를 로드하지 않은 소유·합성 테스트이며, 독립 실표본 비교는 별도 과제 |

이 구분은 프로젝트를 낮게 평가하기 위한 것이 아니다. 테스트 가능한 계약을 만든 진전은 실제로 크다. 다만 계약 하나의 통과를 “커널 전체 분석 완료”나 “실전 은닉 코드 탐지율 향상”으로 합산할 수 없다. 저장소도 이 경계를 명확히 남기고 있다. [R04] [R05]

### 1.2. 가장 가치가 큰 다음 성과

다음 질문을 실제 한 세션에서 답하고, 세션 종료 뒤에도 재현하도록 만드는 것을 목표로 삼는다.

**보안 조사:** “이 드라이버 또는 익명 실행 영역은 어떤 객체에서 참조되며, 어떤 프로세스와 관계가 있고, 관측한 실행·변경은 무엇인가? 그 연결 중 사실과 가설은 각각 무엇인가?”

**커널 진단:** “이 스레드는 왜 진행하지 못하는가? 관련 IRP·장치·잠금·DPC·다른 스레드의 수명이 같은 시간 구간에 존재했는가? 단순 정체인지, 자원 부족인지, 구조 손상인지, 악성 변경인지?”

**증거 재검증:** “당시 읽은 바이트·타입·참조 이미지·정규화 규칙·관측 공백만으로 원래 결론을 재현할 수 있는가? 새 규칙으로 재분석하면 무엇이 달라지는가?”

### 1.3. 우선순위

첫째, `!hiddenproc` 확인 작업의 고정 접두부 문제와 라이브 읽기의 출처 유실부터 해결한다. 둘째, 현재 dump 전용 이미지 recipe를 라이브 sweep에 연결한다. 셋째, 단일 번들의 사실 그래프를 수명과 시간 경계가 있는 다중 관측 그래프로 확장한다. 넷째, 정적 참조로 해결되지 않는 사건에만 실제 실행·쓰기 관측을 추가한다. 마지막으로 동일한 조건의 실표본·정상 워크로드에서 이를 평가한다.

**성능은 단순 편의가 아니라 탐지 품질의 일부다.** 긴 검사로 짧은 실행 영역을 보지 못하거나, 일부 대상만 영구적으로 뒤로 밀리면 기능 자체가 존재해도 목표를 달성하지 못한다. 따라서 정확성·안전성·관측 지연·공정성을 함께 설계한다.

<a id="s02"></a>
## 2. 이전 제안의 반영 상태: 재구현하지 말아야 할 것

현재 `FEATURE_PLAN.md`는 이전 전체 커널 설계를 W01–W15로 채택하고, 부분 구현과 남은 작업을 구별한다. 아래 표는 그 문서만의 요약이 아니라 이번에 읽은 인터페이스·핵심 구현과 대조한 후속 작업 기준이다. [R05]

| 영역 | 현재 확인한 구현 | 아직 끝나지 않은 부분 | 이번 설계의 방향 |
|---|---|---|---|
| W01 Capability | `--capabilities`, 선택된 compiled contract와 command route | 실제 대상에서의 가용성·지원 조합 검증 | 실행 중 probe와 검증 이력 연결 |
| W02 주소·정체성 | `AddressSpaceDescriptor`, 일부 hunting·IRP·replay의 주소 폭 전달 | 모든 scanner, VM/VTL/root epoch, 실 LA57 | 정체성 분리 및 전 경로 전달 |
| W03 관측 소스 | native kernel, 소유 process handle, bundle, full dump | fallback receipt, 다른 user reader, DbgEng, typed translation | 읽기와 변환 전체의 공통 증거 경로 |
| W04 Schema | GUID/age 검사, 해시 기반 타입 패키지, CLI parser child | 라이브 타입 소비자 격리, 객체 불변식, 승인 배포 | 타입 해석과 객체 유효성 검증 연결 |
| W05 Proof | 고유 주소 구간 coverage, 이미지 범위 일치·차이 proof | 일반 객체·cross-view·인과 관계 proof | 주장별 필수 증거 정책 |
| W06 저장소 | `.kncase`, immutable inventory, 두 종류의 continuation | journal, 재개 가능한 index build, 전역 중복·보존 정책 | append-only 사건 저장과 복구 |
| W07 이미지 replay | 보존 PE, 정규화 recipe, 원정책 재생과 현재 재분석 | native sweep publication, secondary view, 참조 승인 | 라이브에서 오프라인까지 완결 |
| W08 Scheduler | capture class urgency와 지연 histogram | image/reference/layout의 통합 기한·실부하 검증 | 전체 단계의 관측 부채와 공정성 |
| W09 Graph | 단일 `.kncase`의 사실·정적 참조 그래프 | cross-bundle join, 객체 계열, 시간 질의 | 수명 한정 관계 그래프 |
| W10 커널 규칙 | 프로세스 수명으로 한정한 cross-view | 후보 공정성, 다른 객체 계열, raw-read replay | 불변식과 효과 기반 탐지 |
| W11 사용자 실행 | X0/X1 구분, PSS 시각·스레드 정보 보존 | thread-pool·WOW64·JIT·게임 객체 수명 | runtime별 검증 어댑터 |
| W12 I/O | 완료 함수 없는 요청도 포함한 단일 IRP 관측 그래프 | dispatch/completion 전이, wait/lock graph | I/O와 대기 원인 분석 |
| W13 Trace/VMI | normalized sample import, code hash·loss·context | raw decoder, live producer, 신뢰·실행 검증 | 선택적 실제 관측 백엔드 |
| W14 안전성 | kernel default-write-off, 확인된 gate 전이, MCP operation ID | observe/collect 분리, TLS·주체별 권한, 영속 operation | 수집·변경을 명시적으로 통제 |
| W15 평가 | family/group/artifact leakage 및 분모 평가 도구 | 실제 허가 corpus, 독립 ground truth, 외부 비교 | 제품 주장과 연결된 실증 평가 |

특히 다음을 다시 미구현으로 쓰면 안 된다. **실행 영역 카탈로그, 모듈 내부 목적지 검사, 게임 메인 이미지 검사, 희소 증거 보존, 필터 후 pagination, process-handle 소유권, 기본 쓰기 차단, normalized trace import는 이미 기반이 존재한다.** 이번의 과제는 적용 범위와 증명·운영 계약을 완성하는 것이다. [R03] [R05] [R06] [R09] [R16]

<a id="s03"></a>
## 3. 코드에서 확인한 우선 개선점

아래에서 **확인된 동작**, **설계상 제한**, **추가 검증할 위험**을 구별한다. 모든 항목을 취약점이나 실제 악성코드 회피 성공으로 해석해서는 안 된다.

### F01. 숨은 프로세스 확인 작업이 PID 접두부에 고정된다 — P0

**확인한 위치:** `HiddenProcessScanner.cpp::HiddenProcessScanner::Scan`, `HiddenProcessScanner.h`.

발견 결과는 PID를 키로 하는 `std::map`에 모인다. 후보 벡터도 이 순서로 만들어지고, 확인 루프는 `i >= 128`이면 `BudgetExceeded`로 남긴다. 클래스에는 다음 스캔으로 이어지는 후보 커서가 없다. 따라서 **같은 후보 집합이 128개를 초과해 계속 유지되면 뒤쪽 후보는 매 스캔에서 확인되지 않는 구조**다. 결과에 unverified를 남기는 것은 올바르지만, 그 공백을 해소할 진행 보장이 없다. [R10] [R11]

이번에 해당 선택 규칙을 모델링했다. 고정 후보 257개, 검사 10회, 회당 128개에서 한 번이라도 선택된 후보는 128개, 한 번도 선택되지 않은 후보는 129개였다. 이는 Windows 실환경에서 후보 257개를 만들었다는 뜻이 아니라 **소스에서 도출한 선택 정책의 재현**이다. 부록 A에 범위를 명시했다.

**수정 설계:** 대상 세대별 pending queue를 유지하고, 확인한 마지막 PID 또는 안정적인 정렬 키에서 다음 batch를 시작한다. 신규·고위험 후보에 우선 몫을 주되 오래 기다린 후보의 몫을 보장한다. 같은 batch 안에서 fresh before → fresh inventories → fresh after를 완수하도록 예산을 예약한다. 전 회차의 before sample을 새 회차의 after와 묶어 동일 수명 검증으로 인정하지 않는다.

현재 5초 예산은 before 표본, fresh inventory, after 표본이 공유한다. before 단계가 예산을 소비한 경우 확인 결과가 모두 unverified로 끝날 가능성도 별도 측정해야 한다. batch 크기를 고정 128로만 두지 말고, 최근 비용에 따라 줄이되 전체 후보의 최장 대기 시간을 보고한다.

**완료 조건:** 고정 257·1,025 후보에서 모든 후보가 순환 선택됨, 생성·종료·PID 재사용 중 stale lifetime 결합 없음, 실패가 반복되는 앞쪽 후보가 정상 후보를 막지 않음, 취소와 예산 부족에도 정확한 미검증 분모 유지.

### F02. 주소 계약의 구현과 범위 문서가 어긋난다 — P1

현재 `KmonHuntIndex::Observe`는 `context.AddressSpace.UserRange/KernelRange`로 admission을 검사한다. 반면 `KMON_DETECTION_COVERAGE.md`의 “현재 사건 주소 모델” 문장은 user/kernel 범위를 LA48 상수로 설명한다. `ARCHITECTURE.md`는 선택된 경로의 descriptor 이관과 남은 전역 검증을 더 정확히 구분한다. [R16] [R17] [R03]

이것은 **모든 LA57 지원이 완료됐다는 증거도, hunting 전체가 아직 LA48 고정이라는 증거도 아니다.** 실제 지원 상태를 기능 × reader × decoder × source × 주소 폭으로 분해해 자동 생성해야 한다. 문서는 그 산출물을 링크하고, legacy 가정과 실제 runtime descriptor를 분리한다.

독립 테스트에서 원본 blob과 일치하는 `AddressSpaceDescriptor.h`의 경계 검사 41개는 통과했다. 이 결과는 헤더의 산술·admission 계약만 검증하며 실제 Windows LA57의 mapping, 심벌, driver, 세션 공간 지원을 입증하지 않는다. [R07]

### F03. 읽기 결과의 구조화가 끝까지 유지되지 않는다 — P0

`ObservationSource.h`는 실패·부분 읽기·미캡처·충돌·정책 거부를 구분한다. 그러나 parser 호환 함수는 다시 `bool + vector<byte>`로 변환한다. 이 안전한 all-or-none parser 계약 자체는 유지해야 한다. 문제는 **그 변환 전에 원본 read receipt를 별도로 보존하지 않는 호출 경로**다. [R08]

`NativeObservationSource`는 장치 epoch와 주소 descriptor를 확인하지만 원래 native status를 얻지 못한다. 새 `ProcessObservationSource`는 소유한 복제 핸들과 Win32 오류를 보존하지만, 현재 통합은 사용자 이미지 읽기의 handle branch에 한정된다. native fallback까지 하나의 원본 관측 이력으로 게시하지는 않는다. `HiddenProcessScanner`의 선택된 reader는 아직 `Device.ReadMemory`를 직접 호출한다. [R09] [R12] [R10] [R03]

**수정 설계:** parser에 전달되는 byte view와 증거용 `ReadReceipt`를 분리한다. 성공·실패·fallback을 모두 같은 Operation ID 아래 기록하되, 서로 다른 소스의 바이트를 하나의 원자적 읽기로 합치지 않는다. `ReadExact`가 false여도 “어느 source에서 어느 범위가 왜 거절됐는가”는 남아야 한다. NTSTATUS·Win32·HRESULT는 각각 domain과 raw code를 보존한다.

### F04. 이미지 재검증은 구현됐지만 라이브 판정과 아직 별개다 — P0

현재 recipe는 정확한 참조 PE, 정규화, 순서가 있는 읽기를 보존하고 원정책 replay와 `/current` 재분석을 구분한다. 이는 중요한 진전이다. 다만 공개 경로는 dump source의 AMD64 direct-mapping 단일 범위 1..4,096바이트이며, native monitor sweep의 자동 publication과 secondary-view recipe는 남은 작업이다. [R13] [R14] [R03]

**수정 설계:** 이미지 변경 판정이 나온 바로 그 읽기 sequence를 수집한다. 판정 뒤 새로 읽은 바이트로 recipe를 재구성하지 않는다. image sweep, reference qualification, normalization, compare 및 재확인의 원래 읽기를 recorder decorator로 기록하고, sweep의 각 결과를 동일 policy version으로 재생한다. 변경 바이트뿐 아니라 일치 판정을 지지한 범위와 제외 구간도 보존한다.

**완료 조건:** 라이브에서 탐지한 변경이 원본 프로세스 종료와 원래 디스크 파일 교체 뒤에도 재현됨. 원본 reference가 빠지면 정상이나 과거 verdict로 대체하지 않고 unmet requirement를 반환함.

### F05. 사실 그래프는 단일 증거 파일 범위다 — P1

`EvidenceGraph`는 단일 `.kncase`에서 process/address-space, memory range, static address reference를 생성한다. node/edge ID와 원본 span 관계가 있으며, 정적 분기를 실행으로 과장하지 않는다. 그러나 여러 번들의 process–driver–device–thread–memory 관계를 join하는 조사 그래프는 아니다. [R15] [R18]

다음 단계는 임의의 동일 주소 연결이 아니라, **대상·수명·시각·source·layout 조건을 충족할 때만 생성하는 관계**다. 우선 같은 boot·같은 process generation·같은 mapping observation epoch의 관측부터 연결하고, cross-source/cross-VM은 별도 인증과 대응표가 있을 때만 허용한다.

### F06. Capability 출력은 코드 목록이지 현장 가용성 판정이 아니다 — P1

현재 출력은 `target_probed=false`, `availability=not_probed`, `inventory_complete=false`를 명시한다. 이 정직한 계약은 유지해야 한다. 여기에 runtime probe와 증거가 없는 상태를 곧바로 `supported=true`로 바꾸면 안 된다. [R06]

새 지원 행렬은 컴파일됨, source 열림, 레이아웃 확인됨, 샘플 읽힘, 의미 검증됨, 해당 환경에서 회귀 통과를 각각 다른 상태로 다룬다. 드라이버 로드 성공 하나가 전체 커널 분석 가용성을 대표하지 않게 한다.

### F07. 시간 정렬과 fresh scope를 대상별로 확장할 필요가 있다 — 검증 과제

`KmonHuntIndex`는 도착 시각과 원본 관측 시각을 나누고 늦은 receipt를 보존한다. 다만 current view의 전역 `LastMs`보다 오래된 관측은 `historical_only`로 내려간다. 현재는 보수적인 정책이지만 서로 다른 소스·대상의 지연이 섞일 때, 다른 대상의 더 최신 관측 때문에 아직 유효한 독립 대상이 current view에서 제외될 수 있다. [R17]

이는 현재 영속 증거가 모두 손실된다는 판정은 아니다. **전역 순서 정책을 다중 source로 확장할 때의 조건부 위험**이다. 시계 도메인별 watermark와 entity/version별 마지막 상태를 분리하고, 동일 entity의 rollback만 막는 테스트를 추가한다. 다른 source tick을 숫자만으로 비교하지 않는다.

### F08. 안전성과 관측 의미가 해결된 부분을 되돌리지 않는다

기본 write-off, MCP operation ID와 late outcome, 저장 RIP·APC·PSS를 X0/X1로 표시하는 변경은 유지해야 한다. 반면 raw `!kmon iotrace`의 publication-before-entry와 unload 수명 문제, 네트워크 전송 보호, fully offline AI의 egress 통제는 아직 별도 문제다. **쓰기 기본값이 고쳐졌다는 이유로 raw interposition이나 원격 서비스 전체가 안전해진 것은 아니다.** [R03] [R19] [R05]

<a id="s04"></a>
## 4. 전체 커널 분석 범위: 22개 영역

“모든 것을 분석”하는 목표를 다음의 확장 가능한 범위로 구체화한다. 아래 신규 목표는 **현재 모두 구현되어 있다는 뜻이 아니다.** 현재 자산은 확인한 command/capability·architecture·coverage의 계열을 재사용하며, P1/P2는 제안 우선순위다. [R03] [R06] [R16]

| ID | 분석 영역 | 재사용할 기반 | 새로 답해야 할 질문·구현 범위 | 주 관측 경로 / 우선순위 |
|---|---|---|---|---|
| D01 | CPU·레지스터·인터럽트 | CR/MSR/IDT·CPU별 검사 | CPU별 문맥과 실행 epoch, ISR/DPC 지연, 실제 지원 레지스터 | native + 정지 KD + 선택적 trace / P1 |
| D02 | 스케줄러·스레드 | thread/CID/APC 관측 | ready·running·waiting 전이, CPU starvation, priority 관계 | ETW + typed snapshot / P1 |
| D03 | 잠금·대기·교착 | 타입·스레드 읽기 | 소유·대기 간선, lock 종류별 의미, 시간상 동시 cycle | 정지 KD 또는 이벤트+스냅샷 / P1 |
| D04 | 가상 메모리 | VAD/PTE/주소 변환 | root epoch, protection 전이, alias, hidden allocation, pagefile 공백 | native/dump typed source / P0 |
| D05 | 물리 메모리·PFN | physical runs/PFN/orphan page | PFN 소유 관계, 재사용·큰 페이지·split·해제 추적 | RAM 한정 read + qualified translation / P1 |
| D06 | Pool·할당 수명 | pool PE·잔재·tag 검사 | allocation provenance, live/free 구분, 손상과 은닉의 대안 해석 | pool schema + 소유 fixture / P1 |
| D07 | Object Manager·핸들 | object·handle·device backref | 객체 종류·수명·참조 관계, 이름 없는 객체와 namespace | typed object graph / P1 |
| D08 | 프로세스·job·silo | hiddenproc·process layout | process generation, namespace 격리, job/silo별 열거 범위 | qualified multi-view / P0→P1 |
| D09 | 드라이버·로더·코드 | module integrity·driver object | load generation, entry/section/dispatch와 코드 provenance | live recipe + image/object graph / P0 |
| D10 | PnP·전원·WDF | device stack·driver 기반 | 장치 관계·상태 전이, remove/power 정체, framework callback 소유 | PnP/Power ETW + build schema / P2 |
| D11 | IRP·Fast I/O·완료 | pending IRP·minifilter | request lifetime, 전송·대기·취소·완료, 장치별 지연 | 이벤트 provider + bounded snapshot / P1 |
| D12 | 파일시스템·필터·캐시 | minifilter·backing·CloudFiles | 파일 identity와 rename/delete/section/cache 관계, 필터 영향 | file/section graph + 승인 수집 / P1 |
| D13 | Registry·hive | hive callback·잔재 | key/value 정책 변화, callback·서비스·driver 연계 | CM 이벤트 + hive typed state / P1 |
| D14 | 네트워크·WFP·NDIS | WFP filter/callout·정책 검사 | flow/endpoint/프로세스·드라이버 연결, 차단 정책 효과 | 공개 WFP/ETW + 선택적 구조 읽기 / P1 |
| D15 | IPC·공유 메모리 | ALPC/WNF·handle·PFN 관계 | endpoint·section·view·요청 관계, 실제 송수신과 단순 공유 구분 | typed graph + 승인 이벤트 / P1 |
| D16 | 예약 실행 | callback/DPC/timer/work item/NMI | pending/registered/executed 구분, callback 제거·정상 unload 설명 | build별 root + execution references / P1 |
| D17 | win32k·입력·그래픽스 | inputstack·graphics pointer | 올바른 session, adapter/context별 callback·present 경로 | session-qualified reader + ETW / P2 |
| D18 | CI·VBS·token·보안 상태 | CI/VBS/token·BYOVD | 정책 버전과 실제 변화, 프로세스 보호·권한의 정당한 수명 | policy events + exact identity / P1 |
| D19 | Hyper-V·VTL·partition | posture·덤프·capability 기반 | 관측 가능한 VTL/partition, VTL0와 다른 신뢰 영역 | 권한 있는 별도 backend / P2 |
| D20 | DMA·장치·펌웨어 | DMA posture·firmware handler | IOMMU 정책·장치 상태와 침해 흔적, firmware 자체의 별도 분석 | read-safe platform metadata + lab adapter / P2 |
| D21 | 크래시·WHEA·자원 장애 | dump·DbgEng·심벌 | crash/hang/누수·메모리압력·디스크 지연 원인과 대안 가설 | KD dump + ETL/TraceProcessor / P1 |
| D22 | 커널에 연결된 사용자 runtime | image/VAD/PTE/TLS/KCT/PSS·manifest | JIT·thread pool·WOW64·게임 객체 수명, 커널↔사용자 관계 | typed runtime adapters + optional trace / P1 |

각 영역의 완성도는 **발견 → 타입/정체성 확인 → 현재 상태 → 수명/시간 변화 → 관계 → 원인 후보 → 재검증**으로 나눈다. 조회 명령만 있으면 “발견·현재 상태” 단계이고, 함수 포인터를 찾았다고 “실행·원인”까지 지원하는 것은 아니다.

범위는 Windows x64를 중심으로 유지한다. x64 커널 아래 WOW64 대상의 포인터 저장 폭은 별도로 다룬다. ARM64/ARM64EC 전체 지원은 향후 backend·decoder·schema의 명시적 확장으로 두고, 현재 x64 코드의 단순 주소 폭 옵션으로 선언하지 않는다.

<a id="s05"></a>
## 5. 위협 모델과 관측 신뢰 경계

### 5.1. 분석 대상과 관측자를 같은 신뢰 수준으로 보지 않는다

| 환경 | 기본 관측 | 그 관측만으로 보증할 수 없는 것 | 설계 대응 |
|---|---|---|---|
| 일반 사용자 코드·인젝션 | kernel/native + 사용자 API + image reference | 모든 짧은 실행을 보았다는 보증 | 이벤트와 시분할 관측, 손실·재방문 시각 표시 |
| 커널 권한 공격자 | 여러 kernel 구조·PTE·이미지·이벤트 | 센서와 모든 view가 함께 조작되지 않았다는 보증 | 종속 그룹 기록, 외부 snapshot/trace와 비교 |
| 하이퍼바이저·다른 VTL | guest가 허용받은 상태 | 실제 fetch와 guest read가 같다는 보증, VTL1 내용 | 권한 있는 별도 신뢰 영역 provider |
| DMA·펌웨어 | OS에 보이는 매핑·정책·후속 변화 | 모든 DMA 접근의 발신자나 SMM/SPI 내용 | 플랫폼 전용 수집과 독립 검증, unsupported 명시 |
| 수집기·분석기 자체 손상 | 저장 hash·로그 | 원본 관측의 진실성 | 보호된 관리면·외부 receipt·독립 재수집 |

Microsoft의 VSM 문서는 VTL에 따른 메모리·권한 분리를 설명한다. 따라서 VTL0의 커널 읽기 기능이 있다고 VTL1이나 더 높은 신뢰 영역을 읽을 수 있다고 가정하지 않는다. [E10]

### 5.2. 독립성·무결성·진실성은 다르다

동일 kernel data structure를 API와 직접 read로 두 번 확인한 것은 서로 다른 관측 경로지만 완전히 독립된 ground truth는 아니다. SHA-256이 일치하면 보존한 바이트의 동일성을 확인할 수 있지만, 악성 수집기가 처음부터 거짓 바이트를 제공하지 않았다는 증거가 되지는 않는다.

외부 VMI도 무조건 신뢰하는 oracle이 아니다. hypervisor·host·acquisition plugin의 정체성, VM snapshot과 VTL 범위, 암호화 메모리의 가시성, 시간 및 code-version 대응을 함께 기록해야 한다. 분석의 한계는 결과의 부록이 아니라 각 claim의 입력 조건이다.

### 5.3. 운영 목표를 두 개로 나눈다

**조사 워크벤치**는 높은 권한, 다양한 backend, 원본 증거, 선택적 실험을 제공한다. **상시 보안 센서**는 최소 권한·안정된 지원 계약·낮은 관측 지연·제한된 부작용을 우선한다. 하나의 바이너리 또는 UI가 두 역할을 제공하더라도, 커널 권한과 동작 모드는 분리해야 한다.

게임 보안에서는 이상 관측을 바로 제재 사유로 사용하지 않는다. 의심·검증된 변조·실행·행위·운영 정책 위반의 수준을 분리하고, 허용된 정상 도구와 오류·호환성 문제를 반증할 경로를 둔다.

<a id="s06"></a>
## 6. 목표 아키텍처와 네 가지 완결 조사 경로

### 6.1. 기존 구현을 유지하며 경계를 정리한다

다음은 **목표 구조**다. 상자 하나가 현재 파일 하나에 대응하거나 전부 새로 필요한 것은 아니다. `ObservationSource`, `ObservationModel`, `ExecutableImageVerifier`, `EvidenceBundle`, `EvidenceGraph`는 이 구조로 점진적으로 옮길 기존 자산이다. [R03] [R05]

```text
Console / typed MCP / authenticated remote / offline CLI
                          |
                Investigation Orchestrator
             capability + policy + operation ledger
                          |
        +-----------------+------------------+
        |                 |                  |
  Native readers     Dump / KD source    ETL / trace / VMI
        +-----------------+------------------+
                          |
               Qualified Observation Broker
           source / identity / budget / sparse receipt
                          |
       +------------------+----------------------+
       |                  |                      |
  Schema broker      Image verifier        Event normalizers
       |                  |                      |
       +---------- Typed facts + raw read sets ---+
                          |
         Durable journal + content-addressed evidence
                          |
           Temporal entity graph + claim policies
                          |
         Explain / refute / next observation / replay
```

커널 드라이버는 WDM 기반의 작고 검증 가능한 privileged primitive와 필요한 문서화된 수집 계약에 집중한다. PE/PDB/JSON/규칙 해석, 관계 분석, AI는 사용자 모드의 격리 가능한 작업자에서 수행한다. 디버거 명령 문자열을 공통 사실 모델 대신 사용하는 것은 임시 호환 경로로 제한한다.

### 6.2. 기능별 완료 대신 조사 경로별 완료를 만든다

**VS1 — 정상 이미지 내부 변경 조사.** 라이브 이미지의 정확한 정체성 확인 → 비교 및 안정성 재확인 → 원래 읽기·정규화·참조 PE 보존 → 참조한 callback/IAT/vptr 연결 → 프로세스 종료 뒤 replay → 허용된 hotpatch 여부와 남은 미확인 요소 설명.

**VS2 — 소유 이미지 없는 커널 실행 영역 조사.** 페이지 발견 → 효과적인 권한·root·소속 범위 검증 → 여러 관측 source의 차이 확인 → callback/driver/device/thread 참조 연결 → 관련 유저 코드와 관계 후보 → 필요한 경우 독립적인 실행 관측 → 같은 증거로 오프라인 보고.

**VS3 — 스레드 정체와 I/O 원인 분석.** 스레드 대기 → 관련 객체·IRP·장치 스택 → 시간상 유효한 pending/dispatch/completion 관측 → owner/wait graph → 병목 또는 교착 가설 → 반증 가능한 설명과 원본 ETL/덤프 근거.

**VS4 — 짧게 나타난 사용자 코드 조사.** 지원되는 event trigger → 먼저 바이트와 mapping identity 보존 → image/private/mapped/JIT 분류 → callback·스레드풀·실행 문맥과 관계 → 손실 구간을 포함한 사건 이력. 이벤트가 없더라도 공정한 주기 검사에서 발견한 영역을 같은 흐름으로 보낸다.

각 VS는 성공 사례와 정상 대조군뿐 아니라 **원본 소멸, identity 변화, 심벌 부재, 큐 초과, 부분 읽기, 종료 중단**에서 올바르게 불완전한 결과를 반환해야 완료다.

### 6.3. 공유 코어와 수집기별 책임

공유 코어가 주소·정체성·읽기·타입·범위·증거·정책을 소유하고, scanner는 domain enumeration과 명시된 불변식만 소유하도록 한다. `!hunt`, `!kmon`, offline 명령이 각각 유사한 PE/identity/coverage 판단을 따로 구현하지 않게 한다.

한 번에 거대한 파일 재배치를 수행하지 않는다. 기존 함수에 recorder와 typed adapter를 붙이고 대조 테스트를 통과한 뒤, 중복 로직을 제거한다. 파일 분리는 기존 결과를 유지하는 회귀 계약이 확보된 기능 단위로 진행한다.

<a id="s07"></a>
## 7. 대상·객체·주소 공간·시간의 공통 정체성

### 7.1. 키와 제약을 분리한다

현재 process key와 optional assertion의 비추이성 처리는 좋은 출발점이다. 향후 여러 source와 VM을 연결할 때 다음 구분을 추가한다. 아래 명칭은 신규 계약 제안이다. [R03] [R17]

| 정체성 | 필수 목적 | 동일성으로 오인하면 안 되는 값 |
|---|---|---|
| `TargetIdentity` | host/VM/boot 또는 정확한 offline snapshot을 식별 | 수집 PC의 PID, 파일 경로, IP |
| `SourceConnectionIdentity` | reader 인스턴스와 연결 교체를 검출 | 대상 boot identity 또는 수집 신뢰 수준 |
| `AddressSpaceIdentity` | 대상·VTL·프로세스·root·관측 epoch | CR3 물리 주소 하나, PID 하나 |
| `ProcessIdentity` | 대상 boot 안의 PID와 생성 세대 | 재사용 가능한 PID, 이미지 이름 |
| `ThreadIdentity` | process generation + TID + 생성 세대 | TID 또는 thread-start 주소 |
| `ObjectObservationIdentity` | 타입·주소·관측 구간·확인한 수명 제약 | pool 주소 또는 object 이름 |
| `MappingIdentity` | AS identity + VA 구간 + 관측한 mapping generation | 같은 VA, 같은 PFN |
| `CodeVersionIdentity` | 유효 범위의 code hash와 매핑·시각 | signer, module basename, 섹션 이름 |
| `LayoutIdentity` | PE/PDB/provider/package 버전과 hash | Windows major version만 일치 |
| `EvidenceIdentity` | 원본 입력과 해석 정책을 식별 | “최근 결과”, 파일 수정 시각만 |

현재 descriptor는 주소의 모양을 다루며 실제 mapping validity를 입증하지 않는다. 호스트 가상 주소 폭, 대상 코드 아키텍처, 구조체의 포인터 저장 폭, physical address width도 서로 다른 값이다. 예를 들어 WOW64의 32비트 callback 슬롯을 x64 시스템 주소 모델로 읽되 슬롯을 8바이트라고 가정해서는 안 된다. [R07] [R03]

### 7.2. cross-source join은 명시적 증거가 필요하다

단순히 `BootId` 문자열이 같거나 PID·생성 시각이 같다고 서로 다른 source를 합치지 않는다. 외부 provider가 주장하는 boot ID는 별도의 issuer namespace 안에 둔다. 같은 대상이라는 대응은 승인된 collector session, VM identity, snapshot manifest 또는 수집 시점에 확보한 대응 receipt로 설정한다.

관계 생성은 세 단계로 한다.

1. **동일성 후보:** 주소·이름·내용 등 검색용 유사성. 사실 간선이 아니다.
2. **한정된 동일성:** 동일 대상·세대·구간에서 일치한 제약. 이 범위에 한해서만 join한다.
3. **수명 기반 동일성:** 실제 object reference, provider 발급 request generation, 정지 epoch 등으로 더 강하게 한정된 관계.

동일성 증거가 약해지면 연결을 삭제하거나 과거 사실을 덮어쓰지 않고, 새 관계의 상태를 보류하고 원래 관측은 유지한다.

### 7.3. 시계 도메인과 시간 구간

모든 사건은 `event_time`, `capture_begin/end`, `arrival_time`, `publication_time`을 구분한다. 각 값에는 clock domain, 변환 근거와 오차 범위를 붙인다. 같은 PC의 QPC·FILETIME과 외부 VM의 TSC를 단순 정수로 정렬해서 인과 관계를 만들지 않는다.

관측 순서가 확정되지 않으면 부분 순서를 유지한다. “A 다음에 B를 저장했다”는 “A가 B를 발생시켰다”가 아니다. ETW sequence 손실, CPU별 buffer ordering, source 재시작, boot 변경은 관계 유효 구간을 끊는다.

### 7.4. ABA와 스냅샷의 한계

전후 포인터가 같다는 검사는 유용하지만, 그 사이에 해제·재할당되어 같은 값이 된 상황을 모두 배제하지 않는다. 두 번의 일치 read를 object reference나 원자적 snapshot으로 표시하지 않는다.

동일한 주소에서 다른 generation의 바이트가 관측되면 과거 간선은 그 당시 구간에 남긴다. 현재 간선을 새 세대에 복사하지 않는다. 멀티페이지 구조가 일관되게 읽혔는지와 객체 수명이 보장됐는지는 별도 필드로 둔다.

<a id="s08"></a>
## 8. 관측 소스와 읽기·변환 증거의 통합

### 8.1. 기존 인터페이스를 버리지 않고 recorder를 붙인다

현재 `IObservationSource`의 4KiB primitive, sparse state, 명시적 residency consent, cancellation 검사, source binding은 유지한다. 여기에 source를 감싸는 `RecordingObservationSource`를 추가하고 모든 성공·실패 요청을 원본 순서로 기록한다. [R08]

`ReadObservationExact/Range`는 parser가 유효한 완전 바이트만 받도록 계속 동작한다. 하지만 반환값이 false일 때도 recorder는 이미 시도한 요청과 실패 이유를 보존한다. **안전한 parser의 all-or-none 의미와 포렌식 증거의 partial 보존을 양립**시키는 방식이다.

### 8.2. 통합해야 할 추가 계약

| 계약 | 입력·출력 | 설계 요점 |
|---|---|---|
| `ReadReceipt` | source/target/AS/operation, range, sparse spans, status, time | 실제 사용한 source를 보존; 실패를 zero bytes로 만들지 않음 |
| `TranslationReceipt` | root identity, walk entries, entry 주소, page size, effective permission, PFN | 중간 page-table read도 증거와 예산에 포함 |
| `FallbackReceipt` | 앞선 실패, 다음 source, 선택 이유, permission | native fallback을 원래 API의 성공처럼 감추지 않음 |
| `ReadSet` | ordered receipts, exact denominator, content versions | 같은 위치의 상충 바이트를 임의로 하나로 합치지 않음 |
| `OperationBudget` | 전체 bytes/I/O/parser time/queue age, cancellation | 개별 read budget을 반복해 전체 한도를 우회하지 못하게 함 |
| `SideEffectReceipt` | residency·세션·probe·일시 정지의 가능성/실제 요청 | read-only와 무부작용을 구분 |

`MmCopyMemory`는 부분 복사와 실패를 반환할 수 있고 가상 읽기가 residency를 바꿀 수 있다. 일반 물리 메모리 읽기와 MMIO/펌웨어 주소 공간도 다르다. 따라서 관측 모드를 단순히 “write IOCTL을 안 보낸다”로 정의하지 않는다. [E11]

### 8.3. 원래 오류와 provenance를 유지한다

`NTSTATUS`, `Win32`, `HRESULT`, parser rejection을 하나의 bool 또는 문자열로 통합하지 않는다. 새 transport DTO에는 `status_domain`, `raw_status`, `requested`, `transferred`, `driver_abi`, `source_epoch`를 둔다. 로그는 ASCII 기반 식별자와 16진 원시 status를 포함해 자동 비교할 수 있게 한다.

기존 ABI 17과의 호환을 고려해 새 필드·IOCTL을 확장할 때 version flag와 구조체 크기를 검증한다. “ABI 숫자가 같음”만으로 의미가 같은지 판정하지 않는다. 현재 default-write-denied flag를 검사하는 접근을 다른 계약 변경에도 적용한다. [R03]

### 8.4. 실제 읽기 집합과 비교 범위를 분리한다

PE 헤더, PDB identity, relocation table, 코드 범위, indirect slot을 읽는 데 사용한 전체 read set과 최종 비교 범위는 다르다. 읽기량·저장량·비교량을 별도로 집계한다. 재확인을 위한 중복 읽기를 비교 완료량에 더하지 않는다.

상위 PTE 하나의 실패는 하위 범위의 출처·권한 해석에 영향을 줄 수 있다. 이 경우 데이터가 읽혔더라도 “주소 번역 미검증” 상태를 유지한다. 반대로 일부 스캔 실패가 별도로 완전히 읽힌 양성 사실까지 지워서는 안 된다.

### 8.5. 단일 API 호출의 중단을 보장하지 않는다

기존 cancellation은 호출 전후에 검사하는 협력적 방식이다. 이후의 budget propagation도 이미 실행 중인 kernel IOCTL을 안전하게 강제 중단한다는 약속으로 확대하지 않는다. 일정 시간 이상 응답하지 않는 작업은 UI·관리면에서 `running_or_unknown`으로 보이고, 격리 가능한 parser·분석 worker는 별도로 종료 가능하게 한다.

source 수명은 RAII 또는 명시적 lease로 관리한다. device close·source 교체·monitor stop이 동시에 발생할 때 recorder, queued read, writer가 어떤 객체를 보유하는지 문서화하고 race 테스트로 검증한다.

<a id="s09"></a>
## 9. 타입·심벌·실행 중 객체 검증

### 9.1. PDB가 맞아도 객체가 맞는 것은 아니다

현재 GUID/age 확인, artifact/provider hash, `.knschema`, CLI parser 격리는 이미 존재한다. 다음 단계는 추출한 필드 배치를 **실제로 읽은 target image와 object observation에 결합하는 것**이다. [R03] [R05]

객체별 schema 계약은 다음을 포함한다.

```text
TypeSchema
  exact image/PDB/provider/package identities
  field path + storage size + bit semantics
  root size + embedded bounds + unsupported paths
  runtime invariants + required anchors
  supported source/build matrix + fixture evidence IDs
```

runtime invariant는 “포인터가 커널 주소처럼 생겼다”보다 강해야 한다. object type 일치, 소유 process/thread generation, reciprocal list 관계, 허용된 state 값, 관련 count와 범위, 동일 관측 구간의 재확인을 사용한다. 서로 다른 OS 빌드에서 같은 필드 이름이 존재하더라도 의미가 같다고 자동 승인하지 않는다.

### 9.2. 객체 계열별 세 단계 결과

`decoded_candidate`는 배치대로 읽은 후보, `qualified_observation`은 필요한 구조 불변식을 통과한 관측, `lifetime_bound`는 해당 방법으로 실제 수명을 한정한 관측이다. PDB 또는 raw hash만으로 마지막 단계로 승격하지 않는다.

일부 필드가 없는 경우 그 필드를 요구하지 않는 검사는 계속 수행한다. 예를 들어 optional cancel/state가 없다고 IRP의 유효한 completion 참조 관측을 통째로 잃지 않도록 한다. 반대로 필수 owner generation이 없으면 그 owner와의 관계는 보류한다.

### 9.3. 모든 신뢰하지 않는 parser의 실행 경계

현재 schema CLI의 restricted child는 유용하지만 모든 live SymbolEngine 소비자가 격리된 것은 아니다. 또 restricted token·low integrity·job object는 filesystem allowlist나 네트워크 차단 그 자체가 아니다. [R03]

최종 구조는 artifact broker가 승인한 파일 핸들이나 content-addressed 사본만 parser에게 제공하도록 한다. parser worker는 네트워크를 사용하지 않고 controller handle·자격 증명·광범위 환경 변수를 상속하지 않는다. child output을 신뢰하지 말고 parent에서 스키마·크기·식별자를 다시 확인한다. worker 실패 시 live reader가 in-process parsing으로 조용히 되돌아가면 안 된다.

### 9.4. 레이아웃 변경 탐지와 테스트 생성

PE/PDB pair마다 주요 타입의 size·field path·bit width를 정규화해 저장하고 이전 승인 버전과 비교한다. 변경이 있는 collector만 `needs_validation`로 내려간다. 소유 fixture는 C++ `offsetof`·`sizeof`와 독립 읽기 oracle을 제공한다.

심벌이 없는 내부 구조를 지원하려면 “추정 layout”을 명시적 후보 provider로 분리한다. 추정 결과는 code candidate 발견에는 사용할 수 있으나, validated callback 채널이나 확정 object membership의 필수 증거로 사용하지 않는다.

<a id="s10"></a>
## 10. 주장별 증명 정책과 일곱 종류의 검사 범위

### 10.1. 기존 image proof를 일반화한다

현재 image recipe proof는 일치·차이에 대해 별도의 필수 조건을 평가한다. 이 접근을 모든 발견으로 확대하되, 처음부터 범용 정리 증명기를 만들 필요는 없다. **버전이 있는 결정적 규칙과 명시적 필수 관측**을 먼저 구현한다. [R03] [R14]

예시 claim은 다음과 같다.

| Claim | 최소 필요 근거 | 이것만으로는 충분하지 않음 |
|---|---|---|
| 관측된 이미지 범위가 참조와 다름 | 정확한 identity·정규화·비교 구간·안정된 차이 | 해시 하나, 파일 이름, 한 번 실패한 read |
| 유효 callback이 해당 코드로 연결됨 | 검증된 slot 의미·원본 slot/read·경로 재확인 | 임의의 포인터 값, module range 포함 여부 |
| 두 process view가 같은 수명에서 불일치 | fresh complete inventories·일치하는 lifecycle 경계 | 다른 시각의 PID 목록 차이 |
| 두 관측이 같은 mapping의 변화임 | target/AS/process/root epoch와 mapping 제약 | 같은 VA/PFN |
| 해당 시점의 CPU 실행 표본 | 인정된 producer·CPU/문맥·시각·code-version 연결 | PSS·저장 RIP·thread start |
| 특정 write가 실제 반영됨 | source가 제공하는 write 관측 계약·전후 상태·대상 identity | 접근 권한, page fault, WriteVM 미관측 |
| 대기 cycle이 교착 원인 후보임 | 동시 유효 wait/owner 간선·lock 의미·해제 가능성 검토 | 과거 스냅샷을 합쳐 만든 순환 |

claim 결과는 `supported`, `contradicted`, `unfulfilled`, `not_applicable`를 가진다. `supported`는 명시한 범위의 주장만 지지한다. 코드 차이가 확인돼도 maliciousness나 writer를 자동 채우지 않는다.

### 10.2. 일곱 ledger를 전체 조사에 적용한다

| Ledger | 핵심 질문 | 집계 규칙 |
|---|---|---|
| Discovery | 후보를 어디서 얼마나 발견했는가? | 열거 집합·제외 대상·hard cap·재개 여부 |
| Address | 어느 주소를 실제로 읽고 비교했는가? | 고유 구간 union, 실패·제외·미방문 분리 |
| Temporal | 어떤 시간 동안 무엇을 관측했는가? | 이벤트 손실 구간, 표본·스캔 재방문 공백, clock domain |
| Semantic | 어떤 타입·정규화·정책 의미가 확인됐는가? | 필수 layout·runtime invariant·exclusion 기록 |
| Persistence | 어떤 원본이 실제로 저장됐는가? | 예약·읽기·저장·검증을 별도 단계로 집계 |
| Replay | 원래 결론을 재현했는가, 새로 분석했는가? | original policy와 current policy 구분 |
| Trust | 원본을 누가 어떤 권한 영역에서 수집했는가? | checksum·인증·외부 trust anchor를 혼동하지 않음 |

바이트 ledger의 완전성은 시간 ledger의 완전성이 아니다. 100MiB를 모두 한 번 읽었더라도 그 뒤의 5분간 발생한 짧은 실행을 관측했다고 볼 수 없다. 반대로 특정 한 페이지에서 정확한 변경을 확인했다면 전체 이미지가 partial이어도 그 구간의 양성 주장은 유지한다.

### 10.3. coverage 계산의 불변식

요청한 고유 주소 집합을 D라 하고 그 안의 비교 성공 C, 실패 F, 제외 S, 미방문 U를 겹치지 않게 정의한다. 동일한 policy 범위에서 다음을 검사한다.

```text
D = C union F union S union U
|D| = |C| + |F| + |S| + |U|
```

여러 read attempt가 같은 바이트를 재확인하면 read traffic은 늘지만 `|C|`는 늘지 않는다. 서로 다른 snapshot·정규화 policy·대상 세대를 합쳐 위 등식을 만들지 않는다. schema와 reader가 같은 분모를 공유해야 한다.

범위 목록이 잘렸는데 카운터가 맞는다고 `complete`를 표시하지 않는다. 빈 범위 또는 관심 없는 대상은 `not_applicable`과 `not_attempted`로 구분한다. 현재의 고유 interval 계산은 유지하고, exact denominator가 없는 legacy artifact는 추가 보증 없이 그대로 해석한다. [R03]

### 10.4. `next_best_observation`의 결정 방식

추가 관측은 위험 점수만으로 고르지 않는다. 현재 가설을 가장 잘 구별하는 정보, source의 독립성, 휘발성, 예상 비용, 권한·부작용을 함께 고려한다. 예를 들어 “참조 파일이 달라서 비교 불가”인 사건에서 더 많은 함수 prologue를 읽는 것보다 정확한 참조 artifact를 확보하는 것이 먼저다.

계획 결과에는 어떤 조건을 해소하려는지, 어떤 대안 가설을 반증하려는지, 허용된 동작 모드와 실패 시 잔여 미확인 항목을 함께 기록한다.

<a id="s11"></a>
## 11. 라이브 이미지 검증과 신뢰 가능한 참조

### 11.1. `LiveVerificationTransaction` 제안

현재 verifier와 recipe를 재사용하는 신규 transaction을 제안한다.

```text
Pin target/source identity and reference artifact
  -> record original qualification reads
  -> record normalized comparison reads
  -> record stability and mapping rechecks
  -> build typed comparison + explicit exclusions
  -> publish immutable read set / reference / recipe
  -> replay with the same policy
  -> expose scoped proof and graph links
```

대상 process handle을 보유하는 동안에도 mapping은 바뀔 수 있다. 따라서 process identity가 일치한다는 이유로 recipe의 여러 읽기를 같은 code version으로 합치지 않는다. 전후 page mapping·code bytes·header identity가 충돌하면 `inconsistent_capture`로 남긴다.

각 slice의 원본을 남긴 뒤 여러 slice를 `SweepManifest`로 묶는다. sweep 전체를 원자적 snapshot이라고 부르지 않으며, slice별 관측 시각과 전체 경과 시간을 표시한다. 대형 PE에서는 CAS reference를 공유해 매 페이지마다 같은 전체 PE를 복제하지 않는다.

### 11.2. 참조의 세 가지 신뢰 수준

| 수준 | 의미 | 가능한 결론 |
|---|---|---|
| R-local | 현재 로컬 파일과 identity가 대응함 | 해당 로컬 참조와의 일치/차이 |
| R-retained | 동일 참조 바이트를 저장하고 hash·policy를 고정함 | 사후 재현 가능한 일치/차이 |
| R-approved | 승인된 배포본·빌드 manifest·서명 정책과 연결됨 | 해당 승인 정책 기준의 변경 여부 |

서명은 해당 파일의 배포자·체인·정책 맥락에 대한 정보이며, 현재 메모리 코드의 정상성이나 그 드라이버의 악용 불가능성을 대신하지 않는다. 공격 후 교체된 로컬 파일과 메모리가 서로 일치하는 경우도 `R-local match`와 `approved match`를 구분해야 한다.

### 11.3. 정규화의 개선 원칙

PE 섹션 RVA와 파일 오프셋, base relocation, loader가 수정하는 영역, 지원된 동적 재배치, IAT/API-set/forwarder의 의미를 정확한 policy로 처리한다. 실행 섹션 이름이 `.text`인지가 아니라 속성과 실제 매핑을 본다. 지원하지 않는 정규화 영역을 넓게 지워 오탐을 줄이는 방식은 허용하지 않는다.

secondary image view는 직접 매핑 기준과 별도 recipe version으로 지원한다. 입력·변환 근거가 없으면 현재 live verifier의 결과를 사후 recipe가 재생했다고 표시하지 않는다. 현재 코드가 direct basis를 명시하고 secondary basis를 보류하는 계약은 보존한다. [R13] [R14] [R03]

### 11.4. hotpatch와 정상 instrumentation

새 `AuthorizedChangeManifest`는 정확한 이미지 hash, policy epoch, 범위, 변경 전후 hash 또는 검증 가능한 변환, 발급자, 만료 조건을 포함하도록 설계한다. “같은 모듈로 점프한다”, “Microsoft 경로다”, “서명돼 있다” 같은 광범위한 허용은 사용하지 않는다.

정상 instrumentation·overlay·JIT에 대해 근거 있는 예외를 적용할 수 있지만, 원본 관측은 유지한다. 예외는 탐지 출력을 조정하는 정책이지 증거 수집을 삭제하는 규칙이 아니다.

<a id="s12"></a>
## 12. 영속 사건 저장소와 시간 관계 그래프

### 12.1. 현재 inventory 확장을 인정한다

현재 `/inventory`는 4,096개 legacy directory 한계를 넘는 immutable membership snapshot을 생성하고 inventory cursor와 result cursor를 구분한다. 따라서 “대용량 조회가 전혀 없다”는 과거 지적은 더 이상 정확하지 않다. 그러나 build는 중단 후 새 디렉터리에서 다시 시작해야 하고, 집계·중복 제거는 query window 범위이며, 원본 파일을 다시 검증하는 계약이다. [R03] [R05]

다음 작업은 숫자 상한을 무제한으로 키우는 것이 아니라 **재개 가능한 publication journal과 index, 전역 membership·보존 정책**이다.

### 12.2. append-only 사건 저장소

새 저장 구조는 다음을 제안한다.

```text
collection/<id>/
  session-manifest
  journal-segments/
  objects/<content-digest>
  readsets/
  recipes/
  facts/
  claims/
  indexes/<generation>/
  closure-manifest
```

`.kncase`, `.knverify`, `.knindex`는 기존 입력 adapter로 계속 읽는다. 새 저장소의 승인된 root manifest가 artifact·readset·정규화·claim 버전을 참조한다. 파일 하나가 존재한다는 이유만으로 publication이 완료됐다고 판단하지 않는다.

**commit 순서:** raw object 저장·검증 → readset/recipe/fact 저장 → journal commit → index 반영. index는 파생 데이터이므로 재구축 가능해야 한다. commit 전의 고아 chunk는 미완료로 남고, 임의로 정상 사건에 포함되지 않는다.

중단 복구 시 이미 완료된 segment의 checksum과 schema를 확인하고 마지막 committed offset부터 재개한다. 파일 시스템 atomic rename을 전원 장애의 모든 저장 보증과 동일시하지 않는다. 실제 매체·flush·crash recovery 조건을 테스트한다.

### 12.3. 보존과 privacy

증거의 보존 예산은 우선순위별로 분리한다. 고위험 원본의 최초 보존, 이미 committed된 사건의 참조 artifact, 검사 실패 분모, 저가치 반복 관측을 동일 FIFO에서 경쟁시키지 않는다. 삭제는 도달 가능한 manifest root와 retention policy를 고려한 GC로 수행하며 삭제 이유와 영향을 남긴다.

메모리·심벌·경로에는 자격 증명과 개인정보·비공개 게임 코드가 들어갈 수 있다. 로컬 암호화, 주체별 접근권한, 외부 전송 전 최소화·승인, redaction 파생본과 원본의 연결을 설계한다. 자동 공개 업로드나 바이너리·메모리의 기본 외부 전송은 하지 않는다.

### 12.4. 관계 그래프의 새 범위

현재 single-bundle `EvidenceGraph`는 유지한다. 그 위에 `TemporalFactStore`와 `JoinPolicyRegistry`를 추가한다. 권장 객체는 process, thread, address space, mapping, code version, driver, device, file, section, callback registration, IRP/request, wait object, policy, evidence다.

관계 종류도 구별한다.

| 간선 | 뜻 | 기본 증거 |
|---|---|---|
| `contains / owns` | 관측 범위에서 구조적으로 소유·포함 | typed fields와 identity |
| `references` | 해당 슬롯·명령 바이트가 주소를 참조 | raw bytes·layout·재확인 |
| `mapped_from` | image/section/file과 mapping의 관계 | qualified backing identity |
| `changed_between` | 같은 정체성의 두 관측 사이 변화 | 양 끝점과 미관측 시간 구간 |
| `observed_executing` | 승인된 execution source의 표본 | CPU·문맥·시각·code version |
| `observed_write` | source 계약이 지지하는 쓰기 관측 | target lifetime·write semantics |
| `temporal_candidate` | 시간상 인접하여 조사 가치가 있음 | clock-qualified intervals |
| `derived_from` | 해석이 어떤 원본에서 나왔는가 | evidence/recipe/policy IDs |

`temporal_candidate`를 `observed_write`로 자동 승격하지 않는다. 동일 hash와 PFN은 내용·물리 페이지 관계이지 통신 방향이나 치트 행위자를 확정하는 근거가 아니다.

### 12.5. 사건의 상태와 설명

사건은 `open → investigating → supported/refuted/inconclusive → archived`로 관리하되 새 반증으로 다시 열 수 있다. 원본 사실은 불변이고 해석은 policy version별로 추가한다. 사용자가 “왜 이 드라이버가 관련됐는가?”를 물으면 경로를 이루는 모든 간선의 evidence ID·시각·신뢰 제약을 반환한다.

그래프의 BFS가 성공했더라도 전체 target coverage가 완전해진 것은 아니다. page 수, graph node 한도, traversal budget은 query scope이고 관측 범위와 별도로 표시한다.

<a id="s13"></a>
## 13. 공정한 스케줄링과 순간 은닉 관측

### 13.1. 기존 capture 정책에서 전체 pipeline으로 확장

현재 capture worker는 첫 캡처·후속 캡처의 urgency와 bounded turns, queue age 및 service histogram을 제공한다. 250ms/1,000ms 같은 값은 정책 임계치이며 측정된 SLO나 hard deadline이 아니다. 이 구분은 유지한다. [R03] [R05]

다음에 통합할 것은 discovery, identity qualification, reference verification, image sweep, page capture, persistence의 전체 지연이다. 각각이 잘 동작해도 앞 단계의 대기 때문에 사건을 놓칠 수 있기 때문이다.

### 13.2. 관측 부채를 스케줄러의 입력으로 사용

대상별로 `first_seen`, `last_success`, `last_attempt`, `pending_since`, `expiry_risk`, `remaining_work`, `failure_class`를 저장한다. 반복 실패를 성공한 재방문처럼 계산하지 않는다. 새로운 observation이 왔다고 오래 기다린 pending의 최초 대기 시각을 계속 뒤로 미루지 않는다.

우선순위는 다음 요인을 함께 사용한다.

- 휘발성: 짧은 이벤트·신규 mapping·callback 변경의 최초 read.
- 증거 가치: 현재 claim의 핵심 부족 입력을 해소하는지.
- 공정성: 오래 보지 못한 process·driver·범위에 최소 service를 보장하는지.
- 비용과 실패: 영구 unsupported와 일시 실패를 구별해 재시도 폭주를 막는지.

신규 고위험 후보가 계속 들어와도 배경 최초 순회와 오래된 미확인 후보가 완전히 굶지 않아야 한다. 반대로 거대한 정상 이미지 tail 때문에 최초 휘발성 바이트 캡처가 밀리지 않아야 한다.

### 13.3. 기한은 대상 관측과 내부 처리로 나눈다

`event→first read`, `candidate admission→qualification`, `read→durable publication`, `image first seen→first sweep`를 각각 측정한다. queue wait만 짧고 target revisit가 긴 상태를 성공으로 보지 않는다. 정상 동작·실패 attempt·종료 drain 통계도 분리한다.

초기 SLO는 특정 host와 고정 부하군에서만 정한다. 예를 들어 “승인된 부하 W에서 첫 페이지 캡처의 P99가 목표 L 이하”처럼 workload·분모·제외 조건을 명시한다. 값을 먼저 정해 보고에서 실패 범위를 제거하는 방식으로 목표를 맞추지 않는다.

### 13.4. 짧은 실행 구간의 검출 확률을 정직하게 해석

이상 상태가 길이 d 동안 유지되고 같은 대상을 주기 Δ마다 한 번 보며 위상이 균등하다는 단순 모델에서, 한 번이라도 만날 확률은 대략 `min(1, d/Δ)`다. 이는 스케줄링과 실행이 독립이라는 가정을 둔 설계 직관이며 실제 회피 상대에 대한 탐지율이 아니다.

따라서 Δ를 조금 줄이는 것만으로 순간 상태를 해결했다고 할 수 없다. 이벤트가 제공되는 행위는 event-triggered capture로, 지속되는 객체·코드는 fair polling으로, 여전히 부족한 고위험 사건은 선택적 실행 trace로 보강한다. 이벤트 손실과 trigger의 관측 범위를 별도 기록한다.

### 13.5. sensor flooding과 정상 대형 부하

소스·프로세스·규칙 계열별 quota를 두어 한 대상이 많은 후보를 만들어 전체 스케줄러를 점유하지 못하게 한다. 제한에 걸린 후보는 숨기지 말고 `admission_deferred`와 정확한 대상 범위를 기록한다. 같은 slot의 빠른 변화는 최신값으로 coalesce할 수 있지만, 최초/마지막값·변화 횟수·보존되지 않은 중간 상태를 구분한다.

안정된 집합, 계속 늘어나는 집합, 삭제·재사용이 많은 집합을 각각 시험한다. F01처럼 “한 번에 N개 제한”을 “모든 항목을 순환 검사”로 오인하는 코드 패턴을 공통 검증기로 잡는다.

<a id="s14"></a>
## 14. 은닉 커널 코드 탐지 설계

현재 커널 PTE/PFN·pool·이미지 비교·callback·DPC·work item 계열은 이미 있다. 아래는 이를 새로 추가하라는 목록이 아니라 **증거 결합과 탐지 의미를 강화하는 규칙 설계**다. [R16]

### K01. 헤더·import·W+X가 없어도 설명되지 않는 실행 영역을 추적

입력은 qualified address-space root에서 관측한 실제 실행 매핑, module/section 소유 정보, pool·PFN 보조 관측, 해당 구간의 원본 바이트다. PE 헤더나 특정 컴파일러 stub은 enrichment일 뿐 admission의 필수 조건으로 되돌리지 않는다.

규칙 결과는 `unowned_executable_region`과 `ownership_unknown`을 구분한다. 완전하지 않은 모듈 inventory에서 “소유자가 없다”고 확정하지 않는다. MMIO·미수집 메모리·세션 정체성 불명은 별도 gap이다. RX이거나 현재 NX라고 해서 과거 실행 여부를 단정하지 않는다.

발견된 범위를 allocation·page별로 순환 검사하고, 해당 범위에 도달하는 callback/dispatch/스레드·작업 큐 참조를 graph에 연결한다. 참조가 없더라도 범위는 보존한다. 반대로 코드처럼 보인다는 이유만으로 실행 관측을 생성하지 않는다.

**차별화 목표:** 같은 익명 영역의 최초 관측, 권한 변화, 내용 버전, 참조 추가·제거, 캡처 성공·실패를 시간축에서 설명한다. 단발 “unbacked” 알림으로 끝내지 않는다.

### K02. 정상 이미지 내부 변경을 이미지·함수·객체 역할과 연결

현재 이미지 전체 sweep과 정적 분기 목적지 해석을 바탕으로, 변경된 code range가 어떤 typed slot 또는 함수 역할에서 사용되는지 연결한다. 동일 모듈 내부 또는 다른 정상 이미지로 향하는 분기도 그 목적지의 비교 상태를 확인한다.

다만 함수 전체의 의미가 보존되는지와 특정 head transfer를 해석하는 것은 다르다. 직접 비교가 지원하는 범위, 분기 해석이 실제로 지나간 범위, 미해결 register target을 분리한다. 임의 bytes를 linear disassembly하여 모든 데이터 포인터를 실행 간선으로 생성하지 않는다.

기본 단계는 정확한 byte provenance이며, 선택적 semantic analysis는 별도 격리 worker에 둔다. 그 worker가 “의미가 악성 같다”고 설명하더라도 원본 코드·해석 제한·반증 후보가 필요하다. 데이터 흐름이나 에뮬레이션 결과를 실제 target 실행으로 표시하지 않는다.

### K03. 프로세스·스레드·드라이버·객체의 lifecycle cross-view

숨은 프로세스의 새 확인 정책은 유지하고 F01의 공정성을 수정한다. 같은 원칙을 thread, driver object, device, handle, callback registration에 확대한다. 각 view에는 완전성·관측 구간·공유 dependency group이 필요하다.

드라이버의 경우 module list, driver object, 장치 역참조, 실행 mapping, code reference를 대조한다. 정상적인 동적 driver object나 장치 없는 드라이버, 정상 unload·이미지 폐기·서비스 제거를 음성 대조군으로 포함한다. loader entry가 없다는 사실 하나로 malicious driver라고 분류하지 않는다.

CID·handle·scheduler·pool 관측을 사용할 때도 “목록에 없음”을 확정하려면 해당 목록을 실제로 끝까지 읽었는지 확인한다. 새 후보를 발견한 원본과 확인 단계의 fresh inventories를 함께 보존해 사후 cross-view 정책을 재실행할 수 있게 한다.

### K04. callback 추가뿐 아니라 제거·무력화도 조사

pointer가 익명 코드로 바뀌는 경우만 보지 않고, 기대한 registration이 없어짐, callback 수나 enable 상태 변화, 이미 등록된 code가 설명되지 않는 바이트로 바뀜을 관측한다. 그러나 기대 registration은 최초 관측만으로 확정하지 않는다. 제품 설치·업데이트·정상 unload와 관련 policy를 포함하는 기준이 필요하다.

정상 상태 manifest가 없으면 `registration_disappeared_between_observations`로 기록한다. “EDR이 무력화됐다”라는 주장은 서비스·정책·실제 관측 효과와 추가 증거가 있을 때 별도 평가한다. 탐지 목적으로 외부 callback을 임의로 호출하거나 바꾸지 않는다.

### K05. 예약 실행·IRP completion·비 IOCTL 채널의 역할 검증

DPC, timer, work item, NMI, pending IRP completion, hive handler, firmware table handler, WFP callout 등의 수집 결과를 공통 `ExecutionReference` 계약으로 넘긴다. 각 source는 root의 범위, layout 신뢰, slot 의미와 수명 제한을 명시한다.

이름이 알려지지 않은 kernel pointer를 발견했다고 해당 포인터를 함수로 호출하지 않는다. “WFP 후보 내부 레이아웃”과 “정확한 PDB로 확인한 함수 슬롯”을 같은 confidence로 합치지 않는다. pending 구조의 재읽기 일치는 lifetime reference를 대신하지 않는다. [R03] [R16]

collector별 root 범위를 문서화해 modern timer/work queue 계열이 어디까지 포함되는지 공개한다. 새 내부 구조가 보이면 collector capability를 `candidate_layout`로 시작하고, build별 소유 fixture와 정상 부하 대조를 통과한 뒤 validated로 승격한다.

### K06. BYOVD를 파일 이름에서 통신 관계와 효과로 확장

드라이버의 존재·서명·취약 버전 정보는 조사 출발점이다. 다음 세 질문을 별도로 평가한다.

**능력:** 해당 정확한 driver artifact가 공개 분석 또는 승인된 시험에서 어떤 기능·위험을 갖는가? 단순 유사 이름이 아니라 hash·버전·출처와 정보의 갱신 시각이 필요하다.

**관계:** 어느 process generation이 어떤 File→Device→Driver 관계를 관측했는가? 핸들 존재와 실제 IOCTL 호출은 다르며, 통신 관측이 없어도 관련 정적 관계는 보존한다.

**효과:** 이후 어떤 승인되지 않은 code/정책/보호 상태 변경 또는 보안 센서의 이상이 관측됐는가? 시간상 가까운 것만으로 특정 process가 쓴 것으로 단정하지 않는다.

Microsoft의 2026년 driver policy 변화는 서명·허용 목록·audit/enforcement 상태를 현장 지원 행렬에 넣어야 한다는 근거다. 이 정책이 모든 host에서 같은 시점에 enforcement라는 가정은 하지 않는다. [E05]

### K07. 데이터만 바뀌는 공격과 보안 상태 변화

코드 바이트를 바꾸지 않는 token·process protection·보안 policy·등록 metadata 변화는 이미지 비교만으로 다루기 어렵다. 대상별 승인된 state transition과 관련 actor/event가 있는지 확인하는 규칙을 추가한다.

예를 들어 권한 변화는 토큰 identity·프로세스 세대·인증/서비스 수명주기와 함께 해석한다. callback·CI 관련 값이 읽히지 않는 것을 “0으로 지웠다”고 표현하지 않는다. 현재 상태가 안전하다고 과거 우회가 없었다고 판단하지 않는다.

데이터 invariant는 제품·OS 동작에 맞는 구체적인 규칙이어야 한다. 임의의 kernel writable data 변화 전체를 악성으로 분류하지 않는다. 정상 보안 제품, 디버거, 업데이트, suspend/resume의 상태 변화를 반드시 포함한다.

### K08. 수집 경로의 건강도와 sensor tampering

source registration 상태, kernel timeline sequence, ETW session loss, module/layout cache freshness, writer backlog, 외부 수신 receipt를 관측한다. 지원되는 소유 fixture에서만 작은 정상 이벤트를 발생시켜 end-to-end 경로를 시험하는 선택적 canary를 둘 수 있다.

canary가 보이지 않는 결과도 resource pressure·provider 비활성·접근 제한일 수 있다. **sensor impairment candidate와 의도적 tampering을 분리**한다. 같은 kernel 권한의 공격자가 센서를 완전히 장악하면 in-guest 자체 검증만으로 이를 배제할 수 없으므로 외부 수집 신뢰를 연결할 수 있어야 한다.

### K09. 세션·그래픽스·입력 경로

기존 graphics data pointer와 input stack 검사를 session ID·adapter/context·driver generation으로 한정한다. 정상 GPU driver 데이터에 kernel-address 모양 값이 있다는 이유만으로 DDI hook으로 표현하지 않는다. 정확한 슬롯 역할을 모르면 candidate로 남긴다.

게임 render/input 이상은 사용자 overlay, win32k session mapping, graphics driver callback, 실제 present/input event를 서로 다른 source로 연결한다. 내용이 일치하거나 PFN이 같다는 사실이 메시지 전달이나 input 생성 주체를 증명하는 것은 아니다.

### K10. DMA·하이퍼바이저 계열을 다른 문제로 취급

CPU 기반 코드 관측은 CPU가 실행하지 않는 외부 DMA 읽기를 직접 관측하지 못할 수 있다. KDP/IOMMU 상태나 CPUID hypervisor bit 하나를 치트 확정 근거로 사용하지 않는다. Microsoft 문서도 DMA remapping과 장치·상태별 보호 범위를 구분한다. [E22]

실제 조사에서는 장치 topology·허용 policy·IOMMU 관련 상태와 host에서 발생한 결과를 보존하고, 외부 장치·firmware 분석은 별도 허가된 acquisition으로 연결한다. 보이지 않는 영역은 명시적으로 남겨 “커널 전체 scan이 깨끗하다”는 잘못된 결론을 피한다.

<a id="s15"></a>
## 15. 은닉 유저 코드·게임핵·악성코드 탐지 설계

### U01. 이미지·VAD·PTE·section을 한 대상 상태로 결합

현재 선택된 모든 프로세스의 EXE/DLL 실행 비교와 재개 가능한 실행 페이지 순회를 유지한다. 다음 단계는 module list, VAD, 실제 PTE, section/control area/file identity가 같은 mapping을 설명하는지 하나의 상태 모델로 만드는 것이다. [R16]

불일치는 `loader_unlisted_image`, `private_executable`, `image_bytes_modified`, `unexpected_permission`, `backing_unverified` 등 관측 사실로 나누고 특정 주입 기법명은 추가 증거가 있을 때만 붙인다. 헤더가 없다는 이유로 버리거나 MEM_IMAGE라는 이유로 정상 처리하지 않는다.

mapping이 존재하지만 실행 permission이 없는 현재 상태와, 과거 execution evidence는 별도로 보존한다. 레이아웃 변화 없이 내용만 바뀌는 경우를 놓치지 않도록 주기적 content 재검사와 이벤트 기반 검사를 병행한다.

### U02. thread-pool은 시작 함수 하나가 아니라 작업 관계로 본다

기존 WorkerFactory 시작 루틴 관측을 “전체 thread-pool 지원”으로 확대하지 않는다. SafeBreach의 원본 연구는 여러 작업 객체·큐 경로가 존재한다는 동기를 제공하지만, 그 연구만으로 현재 Windows 내부 layout을 확정할 수는 없다. [E16]

제안 runtime adapter는 정확한 ntdll/image/schema 조합에서 TP work, timer, wait, I/O completion 및 해당 backend가 확인할 수 있는 다른 작업 계열을 분리해 수집한다. 객체별 상태, callback 슬롯, owner pool, queue membership, 관련 handle/section과 code-version을 관측한다. encode된 값이나 private layout이 확인되지 않으면 그 경로는 unsupported로 남긴다.

작업이 큐에 있다는 사실, 실행 가능 상태라는 사실, 실제 실행 event가 있다는 사실을 다른 fact로 기록한다. 모든 TP 객체를 강제로 활성화하거나 callback을 호출해 시험하지 않는다. 소유 fixture에서 각 작업의 정상 lifecycle과 미실행·취소 상태를 대조한다.

### U03. TLS·VEH·VCH·KCT·instrumentation의 깊이 확장

기존 참조를 공통 code verifier와 recipe에 연결하고, 등록 metadata·root·slot·target을 모두 보존한다. TLS directory 변조와 callback code 변조, 등록과 실행은 별도 claim이다. 2026년 TLSCheck 2.0은 TLS metadata와 code를 함께 조사하는 연구 근거로 참고하되, 논문의 평가치를 KnLiveDbg의 탐지율로 가져오지 않는다. [E17] [R16]

KCT는 native x64 후보 prefix와 전체 길이 미확정 범위를 구분한다. WOW64를 지원하려면 대상 PEB, architecture, pointer width, 정확한 table semantics를 별도로 검증한다. 64개의 후보를 읽었다는 사실을 전체 테이블의 완전성으로 승격하지 않는다.

### U04. 정상 JIT와 악성 익명 코드의 구별

익명 실행 영역은 JIT·동적 instrumentation에서도 나타날 수 있다. runtime별 code publication, method/module identity, generation·invalidation, heap ownership, code-range event를 가능한 범위에서 수집해 출처를 보강한다.

“JIT runtime이 로드되어 있다”는 프로세스 전체의 private RX 허용 사유가 아니다. 특정 range가 runtime의 code generation과 대응하는지 확인한다. runtime 이벤트가 없거나 손실됐으면 `jit_provenance_unknown`으로 남기며, unsigned·entropy·RWX 같은 단일 특성만으로 악성 판정을 만들지 않는다.

.NET과 native game runtime, browser V8 등은 adapter를 분리하고 정확한 버전 지원 범위를 기록한다. 서로 다른 runtime의 예외를 프로세스 이름 기반 allowlist 하나로 합치지 않는다.

### U05. 게임 빌드 manifest에 객체 수명을 추가

이미 있는 `GameBuildManifest` 계열을 다시 만드는 대신, manifest가 설명하는 **객체의 현재 유효성**을 검증하는 adapter를 추가한다. object root와 vptr offset·허용 slot 범위뿐 아니라 object generation, allocator/container membership, destroy/GC 단계, secondary vptr와 상속 subobject 정보를 포함한다. 현재 roadmap도 게임 객체 수명을 별도 미완료 범위로 둔다. [R05]

자체 UE 게임에서는 가능하면 엔진이 승인한 진단 지점이나 읽기 가능한 generation 정보를 사용한다. 외부 프로세스에서 객체를 읽는 경우 전후 generation과 관련 list/container를 재확인하고, 생성·소멸 중인 객체는 보류한다. 단순히 vptr이 달라졌다는 이유로 object lifetime을 무시해서는 안 된다.

이 검사는 서버의 gameplay 검증을 대체하지 않는다. 정상 코드를 사용해 데이터만 읽는 외부 보조 도구는 코드 변조·private RX 없이 동작할 수 있다. 그 경우 허가된 driver-channel 관측, 입력·출력 관계, 서버 측 비정상 행위 근거를 추가하되 독립적인 주장을 섞지 않는다.

### U06. 스레드 시작 주소와 현재 실행을 구분

현재 X0/X1 구분을 보존한다. 시작 주소, queued APC, raw stack word, saved trap context, PSS context는 실행 trace가 아니다. 유효한 unwind metadata로 복원한 frame도 특정 시점의 전체 실제 제어 흐름과 동일하지 않다. [R03] [R16]

새 stack analyzer는 frame별 `unwind_verified`, `heuristic_pointer`, `unknown`, code-version correspondence를 표시한다. 정상 coroutine·fiber·managed runtime·exception·tail call을 음성 대조군으로 넣는다. CET/CFG 관련 metadata가 존재한다고 모든 간접 호출과 데이터가 정상이라고 결론 내리지 않는다.

### U07. 순간 주입·암호화/NX 전이를 시간 사건으로 보존

지원되는 memory/process/thread event가 있으면 identity-bound capture를 우선 예약하고, 전체 프로세스 정밀 스캔 완료를 기다리지 않는다. first bytes, protection, allocation base, 관련 module/section identity를 작은 read set으로 먼저 확보한다. 이후 나머지 범위를 순환 캡처한다.

다음 관측에서 코드가 사라졌다고 사건이 해결됐다고 표시하지 않는다. deallocation·protection 변경·실패·process exit·일시 미관측을 나누고, 관측 간 공백을 유지한다. 특정 sleep-encryption 기법을 모방하는 운영 코드보다, 소유 fixture의 짧은 상태 전이와 정확한 ground-truth time window를 먼저 만든다.

### U08. 악성코드 기능 분석을 보존된 증거 위에 추가

실행 영역·PE·script·설정 후보를 독립 사용자 모드 worker에서 정적 분석한다. YARA-X 같은 규칙 엔진은 source·rule hash·engine version·스캔한 정확한 byte intervals를 기록하는 선택적 enrichment로 사용한다. 누락 페이지를 0으로 메우거나 서로 떨어진 영역을 붙여 가짜 pattern match를 만들지 않는다.

YARA-X v1.23.0은 2026-11-05 게시된 것으로 확인했다. 이 사실은 연계 대상과 회귀 검증 버전을 고정하는 데 의미가 있으며, 그 버전을 사용하면 악성코드 탐지 우위가 확보된다는 뜻은 아니다. [E07]

난독화된 code의 함수·API·문자열·설정 복원은 별도 binary analysis worker와 연결할 수 있다. export 결과는 원본 hash, origin VA/RVA, 복원한 range, 추론과 관측의 구분을 유지한다. 재컴파일·에뮬레이션 결과는 실제 수집한 실행 증거를 대신하지 않는다.

### U09. EDR impairment·persistence·네트워크 행위를 사건으로 연결

ESET의 GentleKiller 원본 분석처럼 보안 기능 무력화는 한 driver 이름보다 넓은 정책·서비스·제품별 효과와 연결된다. 현재 저장소의 특정 이름·목록은 그 당시 snapshot으로 취급하고 자동 최신 threat feed로 간주하지 않는다. [E18] [R03]

관측 가능한 service/driver lifecycle, callback 변화, WFP·필터 정책, 파일·registry persistence, process access·network flow를 target generation으로 연결한다. 지원하지 않는 provider·사라진 과거 이벤트는 unknown으로 유지한다. “보안 제품이 느려졌다”와 “특정 주체가 기능을 무력화했다”의 claim을 구분한다.

<a id="s16"></a>
## 16. 실제 실행·쓰기 관측: ETW·PT·VMI·TTD

### 16.1. 현재 trace importer의 정확한 위치

현재 normalized importer는 producer가 제출한 context·loss·code hash·sample 형식의 일관성을 검증한다. 실제 raw PT/ETW/TTD decoder나 live VMI 수집기가 생긴 것은 아니다. X2로 보고된 sample도 producer authenticity와 runtime mapping이 검증되지 않았다면 **보고된 실행 표본**이지 독립적으로 확인한 실행이 아니다. [R03] [R05] [R06]

이번 확장은 이 importer를 폐기하지 않고 각 실제 producer 앞의 normalization 계약으로 사용한다.

### 16.2. 증거 수준과 신뢰 축을 분리

| 수준 | 의미 | 추가 조건 |
|---|---|---|
| X0 | 등록·포인터·코드의 정적 참조 | 타입·slot 의미·target identity |
| X1 | 저장되거나 조회된 실행 관련 문맥 | process/thread generation·capture interval |
| X2 | 실제 CPU sampling 계약의 실행 표본 | 인정된 producer·CPU/AS/VTL·code-version·손실 |
| X3 | 관측 구간의 제어 흐름 | raw trace decode·sideband·정확한 코드·trace gap |
| X4 | 특정 메모리 동작과 결과의 한정된 관측 | write/read semantics·대상 수명·반영 여부 |

이 수준은 신뢰 점수가 아니다. 출처 미확인 파일이 `X4`라고 주장해도 `reported_level=X4`, `verified_level=unqualified`가 가능해야 한다. 반대로 신뢰할 만한 X0는 유용한 사실이지만 실제 실행을 의미하지 않는다. 행위자·의도는 X4에서도 자동 확정되지 않는다.

### 16.3. ETW 기반 실행·스케줄링 adapter

첫 구현은 지원되는 kernel profile/context-switch/thread/image event와 정확한 source contract를 사용해 타깃의 실행·대기 구간을 얻는 것이다. event schema·keyword·stack capture·권한·손실 상태를 그 실행의 manifest에 기록한다. source가 제공하지 않는 CPU·thread generation·code-version 정보를 추측해 채우지 않는다.

일반 ETW와 ETW-TI를 “모든 kernel API 또는 모든 메모리 접근을 보여 주는 센서”로 취급하지 않는다. 구독 권한과 실제 이벤트 범위가 부족하면 다른 source를 제안하거나 unobserved로 남긴다. 정상 보안 정책을 바꾸는 우회 조치를 자동 실행하지 않는다.

### 16.4. Intel PT adapter

Intel의 libipt는 PT decode를 위한 원본 프로젝트이므로 구현 참고점으로 적절하다. KnLiveDbg에서는 raw stream, decoder version, CPU 정보, ASID/CR3 관련 sideband, image load/unload·code version, loss/discontinuity를 하나의 trace package로 저장하도록 설계한다. [E14]

decoded flow가 가리키는 code bytes는 그 실행 구간에 대응해야 한다. 나중에 읽은 같은 VA의 다른 코드로 decode하면 안 된다. 수집 구간의 변경 코드를 확보하지 못하면 해당 구간을 `code_version_unresolved`로 중단한다.

PT 제어 흐름 해석을 모든 memory operand 값이나 write actor의 완전한 기록으로 확대하지 않는다. API 호출 경로와 특정 데이터 변경의 인과 관계는 추가 데이터·write 관측 또는 trace가 실제로 제공하는 상태에 따라 별도로 평가한다.

### 16.5. AMD 및 다른 CPU의 관측 차이

AMD IBS는 fetch/operation sampling 계열의 정보원이며 PT와 동일한 연속 branch stream으로 취급하지 않는다. CPU별 지원과 활성화 조건을 probe하고 제공하는 증거 수준을 명확히 한다. 같은 UI에서 보여 줄 수 있어도 source capability는 같지 않다. [E15]

특정 CPU 기능이 없는 환경에서도 기본 static/image/object 조사 흐름은 유지한다. hardware backend가 없다는 이유로 모든 분석이 중단되거나, 빈 trace를 정상 실행으로 해석해서는 안 된다.

### 16.6. 선택적 VMI 쓰기 관측

VMI는 이미 발견한 고가치 code·slot·정책 range의 부족 증거를 채우는 옵션으로 시작한다. 전체 RAM의 모든 접근을 무조건 수집하려는 설계는 비용과 안정성 문제를 키운다.

write fault나 trap은 경우에 따라 명령 실행 전 관측일 수 있으므로, 해당 producer가 실제 commit 또는 후속 상태를 확인하는지 명시한다. instruction, privilege/VTL, CPU, AS root, target mapping, old/new bytes를 확보한 범위에서만 `write_observed`를 부여한다. GPU·DMA에 의한 변경은 CPU write trace만으로 주체를 정할 수 없다.

Hyper-V/VBS와 다른 hypervisor의 공존은 추정하지 않는다. 별도 소유 lab VM에서 backend별 지원 조합을 검증한다. HyperDbg·DRAKVUF는 설계 참고 및 비교 대상이지만 현재 host와 동일 기능·보안 상태를 자동 지원한다고 가정하지 않는다. [E09] [E20]

### 16.7. TTD는 사용자 모드 사건의 선택적 재현 경로

Microsoft TTD는 사용자 모드 trace에 대한 경로로 한정한다. 이를 전체 kernel record/replay라고 표현하지 않는다. 승인된 사용자 프로세스의 복잡한 loader/runtime 사건에 대해 WinDbg의 정식 분석 경로를 adapter로 사용하고, trace artifact·query·result·code-version을 연결한다. [E13]

분석을 위해 PPL이나 시스템 보호를 자동으로 낮추지 않는다. 지원되지 않는 protected target은 capability에 명시한다. TTD를 켠 실행 자체가 원래 타이밍을 바꿀 수 있으므로 일반 수집과 별개의 실험 실행으로 기록한다.

### 16.8. 외부 실행 관측의 승인 기준

실제 producer가 연결됐다고 즉시 trusted로 표시하지 않는다. 소유 코드의 알려진 instruction/address sequence, thread migration, module unload/remap, code 변경, buffer overflow, clock skew, VM restart를 포함한 검증이 필요하다. 외부 수집기 인증, 수집 범위의 설명, raw evidence 보존과 독립 decode가 함께 있어야 한다.

<a id="s17"></a>
## 17. I/O·대기·교착·성능·크래시 원인 분석

보안 탐지만 잘해도 “커널의 모든 것을 분석”하는 목표에는 부족하다. 정상 장애와 악성 변경을 구별할 수 있어야 false positive를 줄이고 실제 원인에 접근할 수 있다.

### 17.1. IRP 상태를 이벤트 수명으로 확장

현재 요청 그래프는 단일 관측의 thread/request/stack/reference이며 `UnknownOutcome`을 유지한다. 이 상태는 정확하다. 다음 단계는 provider가 입증하는 request generation과 dispatch/pending/completion 사건을 연결하는 것이다. [R03] [R05]

제안 state machine은 다음과 같다.

```text
RequestObserved
  -> DispatchObserved
  -> PendingObserved
  -> CompletionObserved
  -> RetiredWithKnownOutcome

Any state -> ObservationGap / IdentityConflict / UnknownOutcome
```

모든 요청이 모든 상태를 거칠 필요는 없다. 이벤트가 빠졌다고 가상의 중간 전이를 만들지 않는다. IRP 주소는 재사용되므로 address-only join을 금지한다. `Cancel` flag나 `IoStatus.Status`의 한 번의 관측, 목록에서 사라짐만으로 완료·취소를 확정하지 않는다.

공개 이벤트가 충분하지 않은 세부 경로는 소유 fixture·정식 필터 또는 승인된 lab backend로 확장한다. raw dispatch pointer 교체를 일반 센서의 필수 경로로 삼지 않는다.

### 17.2. wait graph

노드는 thread, wait object, lock, request, device, worker queue다. 간선은 `waits_for`, `owned_by`, `requires_completion`, `scheduled_on`, `blocked_by_policy`처럼 의미를 갖는다. 각 간선은 관측 구간, owner semantics, cancellation/timeout 가능성, evidence ID를 포함한다.

서로 다른 시점의 A→B와 B→A를 합쳐 교착이라고 판정하지 않는다. cycle에 포함된 간선들의 유효 시간 교집합과 객체 수명 조건을 확인해야 한다. recursive lock, shared/exclusive lock, event·semaphore·completion port는 소유·대기 의미가 다르다.

처음 결과는 `potential_wait_cycle`로 두고, 적절한 정지 KD snapshot 또는 반복된 동시성 조건으로 보강한다. 전체 wait graph가 없는 상황에서 일부 cycle 미발견을 “교착 없음”으로 보고하지 않는다.

### 17.3. critical path와 성능 회귀

CPU 사용량만으로 지연 원인을 결정하지 않는다. ready time, blocking time, disk/network I/O, page fault, memory pressure, DPC/ISR, lock contention과 작업의 선후 관계를 조사한다.

Microsoft ETW MCP는 2026-07-21 초기 preview로 구조화된 ETL 질의·집계·비교·critical-path 분석을 제시했고, WPA MCP는 2026-07-30 초기 preview를 발표했다. 이 계층을 모두 자체 재구현하기보다, 버전 고정 ETL/TraceProcessor 결과를 KnLiveDbg의 대상·시간·증거 모델에 수용하는 선택적 adapter가 합리적이다. [E02] [E03]

provider가 출력한 CPU/IO 집계는 자체 코드 무결성 proof와 다른 자료다. 같은 ETL에 대한 독립 query와 table/row identity를 보존하고, LLM의 자연어 요약만 저장하지 않는다. source processing의 손실·symbol 상태·query filter도 함께 남긴다.

### 17.4. 크래시·메모리 손상·누수 진단

Bugcheck parameter, faulting context, stack/unwind 신뢰, module code, pool/allocation 상태, 이전 관측 변화를 연결한다. crash stack의 마지막 driver를 원인으로 자동 지정하지 않는다. 피해자가 뒤늦게 잘못된 메모리를 사용한 경우와 최초 손상 주체가 다른 경우를 분리한다.

memory leak는 snapshot 간 단순 tag 증가만으로 확정하지 않는다. workload, allocation lifetime, 정상 cache/warmup, free 상태를 비교하고 충분한 기간과 동일 부하가 확보됐을 때 후보를 좁힌다. WHEA/hardware 오류는 악성코드 탐지와 별도 원인 가설로 보존한다.

### 17.5. 진단과 탐지의 공동 보고

보고서는 “원인 후보”, “지지 사실”, “반증”, “미관측 범위”, “다음에 필요한 관측”을 갖는다. 보안 사건과 정상 장애가 같은 kernel primitive를 사용하더라도, 악성 의도를 전제하지 않고 동일한 증거에서 서로 다른 가설을 비교한다.

<a id="s18"></a>
## 18. 백엔드 통합과 플랫폼 지원 행렬

### 18.1. 백엔드는 capability로 선택한다

| Backend | 권장 역할 | 반드시 노출할 제한 |
|---|---|---|
| Native WDM + 사용자 API | 일상적인 live 관측·이벤트·메모리·객체 | 같은 OS 신뢰 영역, non-atomic, read side effect |
| Full dump | 원본 고정 분석과 replay | 캡처 당시 공백·포맷·root·paging 근거 |
| Typed DbgEng | 정지 kernel/dump context·정식 debugger data | local/remote/stop 상태별 기능 차이 |
| ETL/TraceProcessor | CPU·I/O·스케줄링·정책 event history | provider별 내용·loss·clock·symbol 범위 |
| PT/CPU sampling | 선택적 실행 흐름 또는 표본 | CPU 기능·code version·수집 손실 |
| Host VMI | VM 외부 관측·선택적 memory event | hypervisor/guest/VBS/암호화 가시성·신뢰 |
| 특수 platform/firmware adapter | 승인된 장치·firmware 조사 | 일반 kernel read와 다른 권한·안전 계약 |

현재 DbgEng는 command-text bridge이고 typed observation source가 아니다. 따라서 `IDebugDataSpaces` 등 정식 backend API를 감싸 주소 read·context·symbol·stop epoch를 명시적으로 반환하는 어댑터를 후속 구현한다. 자동 extension 로딩이나 임의 command 실행을 generic read로 취급하지 않는다. [R06]

Microsoft의 local kernel debugging은 정지·실행 제어와 일부 정보 조회에 제한이 있다. `kdinit` 성공만으로 remote halted KD와 같은 capability를 표시하면 안 된다. [E12]

### 18.2. 실제 지원 행렬의 차원

OS build·revision, kernel/image/PDB hash, CPU vendor/기능, 활성 paging mode, Secure Boot, HVCI/CI policy, VBS/VTL, debugger state, protected target, driver signing·version, symbol provider, source version을 기록한다.

상태는 `compiled`, `not_probed`, `available`, `partial`, `unsupported`, `blocked_by_policy`, `validation_passed_for_scope`로 분리한다. 지원 테스트가 없는 환경을 “동작할 것”이라는 이유만으로 green으로 표시하지 않는다.

현재 릴리즈·개발 문서의 Windows 28000 계열 실측을 사용자 주 대상인 24H2 또는 다른 build의 검증으로 대체하지 않는다. 같은 버전 이름의 누적 업데이트 차이도 exact artifact identity와 함께 기록한다. [R04]

### 18.3. 전체 커널 영역의 확대 방식

범용 타입 explorer와 memory search는 새로운 객체를 조사하는 기반이지만, 모든 객체를 자동으로 해석한다는 뜻은 아니다. domain adapter는 required anchors, schema package, iterator invariant, lifecycle scope, proof policy, replay codec, fixture를 하나의 패키지로 갖추게 한다.

수집 plug-in은 가능한 사용자 모드 격리 프로세스에서 실행하고, kernel 쪽은 고정된 좁은 API만 제공한다. plug-in이 arbitrary kernel write나 callback 호출 권한을 요청하면 일반 분석 모드에서 거부한다. 단순 기능 추가보다 수명·취소·보존·오류 계약이 먼저다.

<a id="s19"></a>
## 19. 능동적 AI 조사와 도구 자체의 안전성

### 19.1. AI는 명령 추천을 넘어 가설을 검증하되 권한을 갖지 않는다

현재 AI 계획·실행 경계와 write 확인은 유지한다. 다음 단계의 `InvestigationPlan`은 목표, 대상 identity, 가설, 지지·반증 evidence, 부족 입력, 허용 source, 예산, 정지 조건을 포함한다. LLM의 자연어 명령을 그대로 privileged dispatcher에 보내지 않는다. [R20]

제안 loop는 다음과 같다.

```text
Question
  -> retrieve typed facts and coverage
  -> enumerate competing hypotheses
  -> select a permitted discriminating observation
  -> execute a typed operation
  -> validate receipts and update claims
  -> stop with supported/refuted/inconclusive result
```

계획의 동작 가능성·권한·수집 비용은 deterministic planner가 확인하고, claim 판정은 해당 proof policy가 한다. LLM은 설명과 다음 조사 제안을 맡는다. 중요한 것은 “AI가 스스로 많이 실행하는가”가 아니라 **사용자의 목표를 증거와 예산 안에서 끝까지 검증하는가**다.

### 19.2. 외부 관측 내용은 명령이나 승인으로 취급하지 않는다

메모리 문자열, 파일명, 심벌, PE metadata, ETL payload, 저장된 JSON 설명에는 의도적으로 agent를 오도하는 내용이 들어갈 수 있다. 이 자료는 모두 untrusted data이며 system instruction·operator approval·tool 권한으로 승격하지 않는다.

typed tool에는 실제 source·target·scope ID와 제한된 parameter만 전달한다. 과거 보고서의 명령 문자열도 실행 허가가 아니다. raw shell·DbgEng command·외부 프로그램 실행은 별도 승인 모드에서만 허용한다. AI가 만든 script는 제한된 offline worker에서 먼저 검증하고, 실행 결과와 script hash를 보존한다.

### 19.3. “private”와 실제 오프라인을 분리

현재 `private` preset은 외부 CLI를 사용하며 `local-only`가 그 자식 프로세스의 네트워크를 차단하는 계약은 아니다. 이 상태를 문서에 명시한 점은 유지해야 한다. [R20]

실제 `offline_inference` 모드는 로컬 모델 provider, 네트워크 egress 차단, child 제한, 승인된 모델·runtime artifact, 민감 데이터 보존 정책을 포함해야 한다. 클라우드 분석은 artifact 자체가 아니라 필요한 최소 facts·redacted byte summary만 내보내는 별도 승인 경로로 둔다. 모델 제품명이나 구독 종류를 보안 속성으로 사용하지 않는다.

### 19.4. 네 가지 운영 모드

아래는 **추가할 권한 모델**이다. 기본 write-off만으로 완료된 것으로 보지 않는다.

| 모드 | 허용 범위 | 기본 금지 |
|---|---|---|
| `offline` | 저장된 evidence/dump/recipe의 read·query·replay | driver load, live target 접근, 자동 네트워크 |
| `observe` | 승인된 live state read, 허용한 residency 영향의 명시 | event subscription 변경, target mutation, raw hook |
| `collect` | 승인된 callback/ETW 수집·capture와 quota | arbitrary write, 외부 callback 교체, 보호 정책 우회 |
| `lab` | 소유·허가된 실험 target의 명시적 변경 | 무승인 범위 확대, 일반 sensor에서 실험 권한 상속 |

장기적으로 배포용 sensor build는 불필요한 write·protection 변경·raw interposition 진입점을 포함하지 않는 구성을 제공하는 편이 좋다. 일반 분석 기능과 lab primitive를 같은 접근 권한으로 노출하지 않는다.

관리자 권한이 이미 target 전체를 제어하는 위협 모델에서 단순 사용자 모드 allow flag는 공격자와의 강한 경계가 아니다. 보호하려는 권한 경계를 실제 배포 구조에 맞게 명시한다. remote credential, controller process, driver session, evidence store 권한은 별도로 보호한다.

### 19.5. 수집기 자신의 변화를 증거에 남긴다

분석기가 event logging을 켜고 callback을 등록하고 process handle을 연 사실도 observer action이다. `observer_action` event에 동작 시각, 대상, 요청·결과, 가능한 부작용을 남겨 타깃의 이상과 구분한다. 의심스러운 callback을 먼저 제거하거나 target을 수정한 뒤 원본을 조사하는 자동 순서는 금지한다.

raw `!kmon iotrace`는 publication-before-entry와 unload 안전 계약이 해결되기 전까지 lab-only/experimental을 유지하거나 배포 sensor에서 제외한다. active-call 카운터가 0이라는 것과 이미 읽힌 함수 포인터로 아직 진입하지 않은 호출이 없다는 것은 다르다. 현재의 협력형 fixture 수명 검증을 외부 driver로 일반화하지 않는다. [R03] [R05] [R06]

### 19.6. 암호화된 원격 전송과 작업 결과

현재 MCP의 operation ledger는 실제 개선이다. 그러나 256개 memory-only metadata, shared password/session, payload 미보존, restart 소멸, no-TLS라는 범위가 남아 있다. [R19]

제안은 local named pipe/stdio와 인증된 TLS remote를 분리하고, 원격 principal별로 target session·operation·evidence 접근 범위를 지정하는 것이다. explicit LAN 사용성을 유지하더라도 평문으로 자동 downgrade하지 않는다. 역할은 조사 read, collect, export, lab mutation으로 나눈다.

영속 operation journal에는 요청 hash, principal, target generation, 승인 범위, admitted/dispatched/engine-returned/effect-verified 시각을 남긴다. 재연결 시 같은 operation의 상태를 조회할 수 있어야 한다. `unknown_outcome`은 자동 재실행의 근거가 아니다. 안전한 재시도는 명령별 idempotency contract가 있을 때만 허용하고, kernel mutation에 대한 보편적인 exactly-once 또는 rollback을 약속하지 않는다.

### 19.7. MCP 프로토콜 업데이트

현재 repository는 protocol `2025-06-18`을 명시한다. 공식 `2026-07-28` 사양은 stateless core, MRTR, header routing, authorization 변경과 Tasks extension을 제시한다. 버전별 호환 adapter와 엄격한 negotiation을 설계하고, 오래된 클라이언트를 조용히 다른 의미로 처리하지 않는다. [R19] [E06]

프로토콜의 stateless화는 **디버깅 target이나 exclusive controller 상태의 제거를 뜻하지 않는다.** 명시적인 opaque target-session handle을 tool argument로 사용하고 principal·target generation·만료에 묶는다. Tasks/operation 조회는 연결할 수 있지만, 프로토콜 task 완료와 실제 target 효과 검증은 다른 상태다.

<a id="s20"></a>
## 20. 최신 기술 동향과 채택 판단

### 20.1. 조사 기준

아래는 2026-11-06에 확인한 일차 자료 중 설계에 직접 영향을 주는 항목이다. 게시일·릴리즈일과 이번 확인일을 구분한다. 최신 공개 자료를 전부 조사했다는 주장이나, 자료의 기능을 직접 실행 검증했다는 주장은 하지 않는다.

| 자료·시점 | 이번 조사에서 확인한 사실 | KnLiveDbg에 대한 채택 판단 |
|---|---|---|
| Microsoft WinDbg MCP, **2026-10-06** | 자연어·MCP와 evidence-based Diagnostician, 안전 경계·감사 흐름 발표 | MCP 존재 자체보다 장기 live evidence와 은닉 조사·재검증이 차별점. KD는 typed adapter로 연계 [E01] |
| Microsoft ETW MCP, **2026-07-21** | headless read-only ETL 질의·비교·critical-path 초기 preview | ETL/TraceProcessor adapter로 성능·대기 분석 보강. preview를 안정 ABI로 가정하지 않음 [E02] |
| Microsoft WPA MCP, **2026-07-30** | WPA trace 분석의 AI-assisted 초기 preview | 자체 모든 진단 UI 재구현보다 원본 ETL·table identity 연계 우선 [E03] |
| Elastic WESP 원본 분석, **2026-10-26** | preview 바이너리의 Microsoft 제공 kernel/user 경계 분석; 미문서화 상태 설명 | 선택적 future provider로만 준비. 검증된 공개 지원 계약 없이 핵심 센서 의존 금지 [E04] |
| Microsoft Windows Driver Policy, **2026-04 업데이트 이후 정책** | in-scope host의 legacy cross-sign 신뢰·audit/enforcement 경계 설명 | 정확한 signing·CI policy 상태를 support matrix에 포함. 보안 기능 해제는 기본 해결책이 아님 [E05] |
| MCP 공식 사양, **2026-07-28** | stateless core·MRTR·authorization·extension 체계 | protocol adapter와 명시적 target handle, 기존 operation ledger의 안전한 확장 [E06] |
| YARA-X **v1.23.0**, **2026-11-05** | 공식 release와 Windows C API artifact 확인 | 고정 버전의 격리된 raw-evidence enrichment. 탐지 verdict를 대체하지 않음 [E07] |
| Volatility 3 **v2.28.2**, 2026년 9월 | 공식 release와 translation 검증 개선 기록 | dump/parser 교차검증·coverage 비교의 독립 구현으로 활용 [E08] |
| HyperDbg **v0.24**, **2026-09-22** | 공식 release 확인 | 선택적 hardware-assisted 실험과 비교 참고. VBS 공존·전체 host 지원은 별도 검증 [E09] |
| TLSCheck 2.0, **2026-04-22** | TLS metadata와 callback code 조사 연구 | 기존 TLS 수집을 lifecycle·code proof와 연결하는 방향의 근거 [E17] |
| ESET GentleKiller 분석, **2026-06-18** | 보안 제품 무력화 기능과 관련 artifact의 원본 분석 | driver 이름뿐 아니라 policy·service·callback·effect 관계를 분석 [E18] |

### 20.2. 오래됐지만 여전히 유효한 기반 자료

Intel libipt, AMD IBS 문서, Microsoft TTD·local KD·VSM·MmCopyMemory 문서, SafeBreach PoolParty, MemProcFS와 DRAKVUF의 원본 프로젝트는 backend의 실제 기능·제약을 이해하는 기준으로 사용했다. 이를 2026년 새로 등장한 기술이라고 표현하지 않는다. [E10] [E11] [E12] [E13] [E14] [E15] [E16] [E19] [E20]

### 20.3. 외부 도구를 이기는 방법을 잘못 정의하지 않는다

| 비교 축 | 참고 도구 | KnLiveDbg가 집중할 차별화 |
|---|---|---|
| 정지 상태 kernel/dump 원인 분석 | WinDbg | live 관측 이력과 보안·객체 사실을 정식 debugger 근거에 연결 |
| dump 기반 memory forensic | Volatility 3, MemProcFS | 동일 evidence를 live와 offline에서 재사용하고 시간·정체성·공백 설명 |
| hardware-assisted 실험 | HyperDbg, DRAKVUF | 특정 부족 증거에 한해 선택적으로 수집하고 현재 사건 graph와 연결 |
| 성능·대기·I/O trace 분석 | WPA/ETW MCP·TraceProcessor | 은닉/변조와 정상 장애의 대안 원인을 함께 비교 |
| byte pattern·artifact 분류 | YARA-X 및 승인된 rule corpus | 정확한 스캔 범위·원본·rule version·결과 재현 |

외부 도구의 이름이나 기능 수를 나열해 세계 순위를 정하지 않는다. 비교 도구는 각자의 강점과 scope가 다르므로 **동일한 질문과 같은 관측 조건**으로 비교해야 한다.

<a id="s21"></a>
## 21. 구현 작업 패키지와 의존 관계

다음 패키지는 기존 W01–W15를 대체하는 새로운 번호 체계가 아니라, **현재 main에서 바로 추진할 통합 작업**이다. `신규`로 표기한 파일명·계약은 제안이며 현재 명령/API라고 주장하지 않는다.

| 패키지 | 우선순위·연결 W | 수정·추가할 위치 | 완료 기준 |
|---|---|---|---|
| P01 후보 확인 공정성 | P0 · W08/W10 | `HiddenProcessScanner.*`, 신규 qualification scheduler | >128 고정 후보와 churn에서 유한한 재방문, fresh lifetime 경계 보존 |
| P02 read·translation receipt | P0 · W02/W03 | `ObservationSource.h`, native/process sources, `DeviceClient.*` | 모든 attempt와 fallback의 원본 status·source·범위 보존, typed translation |
| P03 라이브 verification transaction | P0 · W03/W05/W07 | `ExecutableImageVerifier.*`, `ImageVerificationRecipe.*`, KMON 이미지 경로 | 실제 판정 시 read set으로 recipe 게시, 종료 후 원정책 재현 |
| P04 runtime capability·문서 생성 | P0 · W01/W02 | `SourceCapabilities.h`, command/capability contracts | compiled/available/validated 분리, 주소·backend 문서 drift 회귀 |
| P05 artifact/schema broker 확장 | P1 · W04 | `SymbolEngine.*`, schema·artifact 작업자 | live layout 소비자 격리, target image·runtime invariant binding |
| P06 resumable journal/index | P1 · W06 | `EvidenceBundle.*`, `EvidenceInvestigation.*`, 신규 journal | 중단 복구, 정확한 global retention·dedup·closure 분모 |
| P07 temporal fact graph | P1 · W09 | `EvidenceGraph.*`, region catalog, 신규 join policies | 수명·source·시계 제약을 지키는 cross-bundle 관계 |
| P08 객체·상태 claim 정책 | P1 · W05/W10 | 신규 claim registry, 기존 kernel scanners adapter | list/owner/registration/변경 주장별 proof와 반증·공백 출력 |
| P09 통합 scheduler SLO | P1 · W08 | work queue/capture/image/reference/layout scheduler | 단계별 지연·최장 미관측·고정부하/변동부하 공정성 측정 |
| P10 runtime·게임 lifetime | P1 · W11 | execution surface·process triage·game manifest | TP·WOW64·JIT·vptr 역할·수명 구분과 정상 대조 통과 |
| P11 ETL·CPU sample adapter | P1 · W13/W12 | 신규 ETL/trace provider, normalized import 재사용 | 실제 수집기의 context/loss/code binding, X2 근거 검증 |
| P12 선택적 PT/VMI | P2 · W13 | 외부 provider adapter·capability gate | raw evidence와 code version, compatible lab 환경에서 X3/X4 한정 검증 |
| P13 wait·I/O·crash diagnosis | P1 · W12/W09 | pending IRP, 신규 wait/diagnostic graph, typed DbgEng | request lifecycle·동시 cycle·원인 대안·replay/독립 oracle |
| P14 운영 모드·보호 transport | P0/P1 · W14 | driver policy, MCP/remote, operation ledger | observe/collect/lab 분리, TLS·principal scope·unknown-outcome 복구 |
| P15 증거 검증형 AI | P1 · W14 | AI planner/capability catalog·typed tools | evidence ID 없는 결론 금지, 반증 조사, egress·prompt injection 대조 |
| P16 실 corpus·비교·안전성 | P0부터 지속 · W15 | corpus evaluator·live runners·independent oracle | 실제 artifact·truth 확인, 동일 scope 비교, 실패·비관측 분모 공개 |

### 21.1. 선행 관계

```text
P01 + P04 + P14(기본 경계) + P16(측정 기반)
                         |
                    P02 -> P03
                     |       |
                    P05 ---- P06
                              |
                             P07 -> P08 / P10 / P13
                              |
                             P11 -> P12

P09는 전 단계의 관측 지연과 공정성을 통합한다.
P15는 검증된 typed facts/claims가 생기는 순서대로 확장한다.
```

P12를 먼저 크게 만들기보다 P03의 한 실제 사건을 완결하는 것이 단기 가치가 크다. 반대로 모든 기반 정리가 끝날 때까지 새 탐지를 미뤄서도 안 된다. 각 package가 VS1–VS4 중 하나의 실제 조사 흐름을 개선하도록 묶는다.

### 21.2. 공통 완료 기준

각 패키지는 정상 입력 통과만으로 완료되지 않는다. public contract·help, exact identity, partial/failure 의미, source policy, bounded resources, cleanup, 원본 보존, 독립 oracle, 음성 대조, compatibility 및 changed behavior의 문서가 함께 있어야 한다.

반드시 기능별 **implementation**, **integration**, **validation**, **deployment readiness**를 별도 상태로 관리한다. parser ASan 통과가 native collector 통합이나 HVCI 실환경 통과로 전파되지 않게 한다.

<a id="s22"></a>
## 22. 회귀·대조군·실전 검증 설계

### 22.1. 30개 시험군

모든 제안 시험은 소유 fixture·합법적으로 확보한 분석 대상·격리 lab에서 수행한다. 실제 악성 kernel 동작을 운영 PC에서 재현하는 절차는 기본 검증에 포함하지 않는다. Driver Verifier는 crash 가능성을 전제로 한 테스트 환경에서 사용한다. [E21]

| 시험 | 대상 | 필수 양성·오류 조건 | 정상·반증 대조 및 통과 기준 |
|---|---|---|---|
| T01 | hiddenproc fairness | 257·1,025 고정 후보 | 모든 후보 순환, 앞쪽 실패가 뒤쪽을 막지 않음 |
| T02 | process lifetime | PID/EPROCESS·생성 시각 변화 | exit·auxiliary·정상 reconciliation을 은닉으로 확정하지 않음 |
| T03 | source replacement | device epoch·process handle 교체 | 오래된 source로 새 target read 불가 |
| T04 | sparse read | 중간 hole·short copy·conflict | parser에는 실패, 원본 receipt에는 정확한 공백 |
| T05 | status provenance | NTSTATUS/Win32/HRESULT 오류 | domain과 raw code 보존, fail→zero 변환 없음 |
| T06 | 주소·pointer 폭 | LA48/57 경계·overflow·WOW64 slot | canonical과 실제 mapping 구분, unsupported 정확 |
| T07 | page translation | 큰 페이지·상위 NX/U/S·root 교체 | walk 실패를 실행 권한 또는 물리 관계로 사용하지 않음 |
| T08 | PDB/schema | wrong GUID/age·교체된 cache | 정확한 pair만 승인, missing property는 unknown |
| T09 | parser isolation | timeout·crash·출력 초과·child 잔존 | parent kernel 권한·handle 미상속, partial output 미게시 |
| T10 | live image recipe | 일반 EXE·DLL·kernel image 변경 | actual original read로 종료 후 재생 |
| T11 | normalization | ASLR·mutable·동적 제외·secondary view | 제외 bytes를 verified로 승격하지 않음 |
| T12 | reference trust | 같은 이름의 다른 파일·수정된 참조 | R-local/R-retained/R-approved 구분 |
| T13 | publication crash | 각 commit 단계 중단 | valid final 또는 명시적 incomplete; 기존 evidence 보존 |
| T14 | inventory scale | legacy cap 초과·index 재개·새 파일 | membership 고정, result/inventory cursor 별도 |
| T15 | graph joins | 동일 VA/PFN/PID가 다른 VM/boot/세대 | 잘못된 간선 0, unknown assertion bridge 거부 |
| T16 | clock/order | 늦은 관측·시계 변경·CPU별 loss | unrelated entity 갱신 차단 여부 검사, causal 과장 없음 |
| T17 | scheduler load | 대형 이미지·신규 후보 폭주·churn | 기존 고정 cohort 범위와 최장 미관측 악화 공개 |
| T18 | headerless kernel code | PE/import 없는 소유 실행 fixture | header·W+X 필수화 금지, normal kernel mapping 음성 |
| T19 | in-image modification | 함수 head 외부·다른 실행 section | 같은 모듈 목적지라도 변경 범위 검증 |
| T20 | callback lifecycle | 등록·변경·제거·정상 unload | registration과 execution 구분, stale target retire |
| T21 | driver channel | 일반 파일·control device·재사용 handle | File→Device→Driver 관계와 IOCTL 관측 분리 |
| T22 | user runtime | TP/TLS/KCT/VEH·취소·미실행 작업 | callback 후보를 실제 실행으로 표시하지 않음 |
| T23 | JIT·managed views | 정상 dynamic code·재컴파일·secondary view | process-name 광범위 허용 없이 provenance 검증 |
| T24 | 게임 객체 | 생성·파괴·GC·secondary vptr | 죽은 객체의 다른 vptr을 치트로 오판하지 않음 |
| T25 | 실제 execution source | 알려진 CPU 표본·flow·code remap | imported claim과 verified producer 구분 |
| T26 | write source | pre-execution trap·실제 commit·DMA 후보 | fault만으로 실제 write·actor 확정 금지 |
| T27 | I/O·wait graph | cancel·complete·pending·IRP 재사용 | 사라짐≠완료, 시점 다른 cycle≠교착 |
| T28 | transport·operation | timeout·disconnect·중복 요청·restart | unknown 결과 자동 재실행 없음, principal 격리 |
| T29 | AI·privacy | 악성 memory prompt·외부 CLI egress | 승인 없는 실행/전송 없음, unsupported 사실 조작 없음 |
| T30 | 정상·실표본 비교 | 허가 sample·게임·보안제품·장기 부하 | missed/unavailable/error/FP와 부작용 분모 모두 공개 |

### 22.2. 검증 단계를 섞지 않는다

**단위·속성 검사:** 주소·범위·parser·policy·scheduler의 경계와 불변식. 값의 임의 변형·overflow·중복·상충 입력을 포함한다.

**소유 사용자 모드 통합:** actual Win32 handle/read/JSON/process lifetime/loopback transport를 시험한다. driver-free라고 해서 kernel 동작을 검증했다고 표시하지 않는다.

**소유 커널 fixture 통합:** loader·callback·IRP·device·cleanup을 정확히 알고 있는 대상에서 관측과 실제 상태를 비교한다. 수집기와 oracle이 동일 parser·동일 source만 공유하지 않도록 한다.

**실 host workload:** 게임·정상 overlay·JIT·보안제품·sleep/resume·driver update·대형 프로세스 환경에서 관측 지연·호환성·오탐·자원 사용을 측정한다.

**허가 실표본 및 독립 비교:** sample family별 heldout을 유지하고 운영과 다른 격리 환경에서 비교한다. fixture 개수와 assertion 개수는 악성 표본 수가 아니다.

### 22.3. 초기 실환경 행렬

우선 Windows 10/11 x64의 실제 지원 대상 build를 고르고, Windows 11 24H2를 포함한 선택된 조합마다 exact kernel/PDB/CI policy를 보존한다. Intel·AMD, Hyper-V/VBS/HVCI on/off, Secure Boot, native/dump/KD, 일반·protected process를 각 축으로 한다.

모든 조합을 한 번에 통과했다고 주장하기보다 pairwise·risk-based 조합에서 시작하고, public support matrix에는 실제 통과한 조합만 표시한다. live LA57 hardware가 없으면 synthetic boundary pass와 “실환경 미검증”을 함께 남긴다.

Driver Verifier·재부팅·정상/강제 종료·장치 removal 중 kernel resource 정리와 evidence publication을 시험한다. 버그체크·event log·handle/pool leak·잔존 서비스·미완료 journal은 성공 건수에 묻히지 않게 한다.

### 22.4. 테스트 오라클의 독립성

현재 source 계약 테스트와 corpus evaluator는 좋은 기반이다. 다음에는 저장된 원본을 독립 parser로 해석하거나 소유 fixture가 외부 channel에 남긴 ground truth와 대조한다. 같은 코드가 값을 생성하고 같은 코드가 정상이라고 판정하는 circular test를 줄인다.

최종 보고는 실패한 intermediate run도 보존한다. 성공한 반복 하나를 선택해 전체 검증으로 바꾸지 않는다. 평가 대상 EXE/SYS와 설정 hash를 실행 전후에 고정하고, 실행 중 다른 빌드가 파일을 교체하지 않게 한다.

<a id="s23"></a>
## 23. 독립 비교 평가와 세계 최고 수준의 판단 기준

### 23.1. 현재 evaluator와 실제 검증의 간격

현재 `evaluate-corpus.py`는 선언된 case와 결과의 scope·leakage·분모를 검사한다. 참조된 artifact를 열거나 ground truth를 인증하거나 collector를 실행하지 않는다. 이 구분을 유지하면서 실제 acquisition·artifact 검증·실행 harness를 추가해야 한다. [R21]

`synthetic`, `owned_fixture`, `authorized_sample`, `independent_comparison`을 하나의 탐지율로 합치지 않는다. 같은 계열의 변형·재실행은 independence group으로 묶고, family·group·artifact가 development와 heldout에 걸쳐 누출되지 않게 한다.

### 23.2. 측정 단위

탐지 단위를 case, process, mapping, page, event, claim 중 무엇으로 정했는지 명시한다. 한 sample에서 100개의 modified page를 찾았다고 sample 100개 탐지로 세지 않는다. “변형 바이트 찾기”와 “악성코드 판단”도 다른 task다.

권장 지표는 다음과 같다.

| 지표 | 정의·주의점 |
|---|---|
| End-to-end recall | 전체 positive truth 중 성공. unavailable/error/missing도 분모에 남김 |
| Observable-scope recall | 실제 분석한 positive scope의 성공. 제외된 수집 실패를 별도 공개 |
| Known-truth precision | 알려진 truth를 가진 positive prediction 기준. unknown truth를 정답으로 처리하지 않음 |
| 정상 부하의 조사 알림 부담 | 고유 사건/host-hour 또는 process-hour; 중복 page 알림과 분리 |
| 최초 유효 관측·캡처 지연 | 실패 attempt·time-out·미관측 사례와 같이 보고 |
| Evidence survivability | target 소멸·restart 뒤 필요한 원본을 보존·재생한 비율 |
| Scope completeness | unique address, time windows, semantics, retention을 각각 제시 |
| Diagnosis utility | 전문가가 원인·반증·다음 조사를 검증하는 데 필요한 작업량 |
| Safety·overhead | crash·hang·정리 실패·CPU/RAM/I/O·게임 지연과 수집 부작용 |

모든 비율에는 분자·분모를 남기고 0분모는 null이다. 신뢰구간은 실제 표본 독립성과 sampling scheme을 확보한 뒤 계산한다. 서로 상관된 변형의 수를 독립 N으로 사용해 과도하게 좁은 구간을 만들지 않는다.

### 23.3. 동일 조건의 비교 실험

dump 분석은 같은 dump와 같은 hole map, 동일 symbol/reference 조건으로 비교한다. live 도구는 완전히 같은 순간을 읽을 수 없으므로 재현 가능한 소유 workload나 고정 VM checkpoint·시나리오를 반복하고 그 비동시성 한계를 기록한다.

각 도구의 기본 모드와 튜닝 모드를 따로 기록한다. KnLiveDbg만 exact game manifest를 가진 경우 비교 조건에 명시하고, generic mode와 game-assisted mode를 나누어 평가한다. 외부 도구가 다른 정의의 경고를 출력하면 그대로 FP/FN으로 변환하지 말고 task별 adjudication을 수행한다.

### 23.4. 최고 수준을 주장하기 전 필요한 증거

“모든 kernel object를 지원”은 타입 조회 명령이 있다는 말로 달성되지 않는다. D01–D22의 각 영역에 대해 backend·build·security state별 지원 단계와 실제 회귀 증거가 있어야 한다.

“은닉 코드 탐지가 더 낫다”는 주장에는 헤더 없는 영역, 정상 이미지 변경, callback 제거, data-only, 짧은 실행, 보호된 target, 모든 view가 함께 조작되는 사례에서의 성공·실패가 포함되어야 한다. 관측하지 못한 종류를 평가에서 삭제해 순위를 만들지 않는다.

가장 현실적인 첫 우위는 특정 task에서 입증한다. 예를 들어 **선택된 Windows/게임 환경에서 라이브 이미지 변형과 kernel↔user 참조를 발견하고, target 종료 뒤에도 원래 증거·정책으로 재현하는 조사 성공률**이다. 이 성과를 확보한 뒤 영역을 확장한다.

<a id="s24"></a>
## 24. 우선 실행 순서와 완료 조건

### Gate 0 — 정확한 분모와 안전한 반복 관측

P01, P04, P14의 기본 경계, P16 측정 기반을 먼저 적용한다. 기존 capability·주소 descriptor·write-off를 유지하면서 hiddenproc 후보 재방문, 문서 drift, target/source identity와 미검증 분모를 고친다.

**종료 조건:** 257·1,025 후보의 고정·변동 집합에서 starvation이 없고, 실제 source·정책 거부·실패가 모두 설명되며, 문서·capability가 같은 계약을 가리킨다.

### Gate 1 — 하나의 라이브 보안 판정을 완전히 재생

VS1을 기준으로 P02→P03→P06의 최소 경로를 연결한다. 읽기부터 reference·normalization·claim까지 보존한다. 모든 scanner를 한 번에 이관하지 말고 이미지 변경 한 종류를 실제 end-to-end로 끝낸다.

**종료 조건:** 승인된 자체 프로세스 또는 드라이버의 변경을 live로 수집한 뒤 원본을 종료·제거해도 offline replay가 원래 scoped claim을 재현한다. 실패·중단 사례는 partial로 재현되고, 정상 ASLR/loader 변화가 변형으로 오판되지 않는다.

### Gate 2 — 커널·사용자·객체 관계와 I/O 진단

VS2·VS3에 P05·P07·P08·P10·P13을 연결한다. 익명 실행 영역, 실제 typed 참조, driver/device/process 관계, pending I/O와 wait 상태를 동일 target/time 계약으로 묶는다.

**종료 조건:** 모든 중요한 graph edge에 원본과 수명 제약이 있고, 주소 재사용·다른 VM·다른 시점의 거짓 연결을 거부한다. 코드 참조를 실행으로 표시하지 않으며, I/O 완료 미관측과 실제 완료가 구분된다.

### Gate 3 — 필요한 사건만 실제 실행으로 보강

VS4와 정적 분석이 부족한 사건에서 P11·P12를 적용한다. raw decoder·producer의 실제 환경 검증과 code version 대응을 먼저 확보한다.

**종료 조건:** imported trace claim과 검증된 live execution이 구분되고, loss·code remap·시계 충돌에서 과도한 실행·writer 주장을 하지 않는다. unsupported VBS/CPU 조합을 정상 성공으로 숨기지 않는다.

### Gate 4 — 독립 평가와 운영 준비

P09·P15·P16을 통합해 정상 게임·JIT·보안 제품 부하와 heldout 실표본에서 성능과 조사 품질을 측정한다. TLS·principal·durable operation·evidence retention과 안전한 업그레이드까지 검증한다.

**종료 조건:** 기능 데모가 아니라 원본 artifact·binary/config hash·오류/비관측·알림 부담·독립 truth를 가진 평가 자료가 존재한다. 사용자에게는 해당 범위의 강점과 미지원 영역을 함께 공개한다.

### 이번 다음 변경 묶음의 권고

바로 다음 구현 묶음은 **후보 확인 공정성 → read receipt recorder → 라이브 image recipe → 원본 소멸 후 replay 검증**으로 정하는 것이 좋다. 이 네 가지가 완료되면 기반 클래스가 추가됐다는 수준을 넘어, 실제 은닉 코드 조사 결과를 믿고 재검증할 수 있는 제품 경로가 생긴다.

<a id="s25"></a>
## 25. 최종 권고

최신 main은 이전 설계의 방향을 상당 부분 반영했다. 특히 정확한 범위·정체성·저장된 원본·정책별 재생·기본 write-off를 분리한 것은 계속 발전시켜야 할 강점이다. 이제 부족한 부분을 단순히 “source abstraction 추가”, “graph 추가”, “replay 추가”로 다시 쓰는 것은 프로젝트 진전에 도움이 되지 않는다. [R03] [R05]

앞으로의 핵심은 다음 세 문장을 실제 기능으로 만드는 것이다.

**무엇이 존재하는가:** 코드·객체·매핑·등록·요청을 올바른 대상과 수명으로 발견한다.

**무엇이 일어났는가:** 실제 관측한 변화·실행·I/O와 단순 참조·가설을 구분하고, 보지 못한 구간을 보존한다.

**왜 그렇게 판단하는가:** 모든 중요한 결론을 원본 바이트·타입·시간·참조 파일·정책으로 다시 검증할 수 있게 한다.

이 방향에서 “세계 최고”는 기능 이름이나 자체 테스트 수가 아니라, **어려운 은닉·장애 사례에서 올바른 증거를 남기고 원인을 좁히며, 정상 동작을 오판하지 않고, 다른 분석가가 같은 결론을 재현하는 능력**으로 평가해야 한다.

넓은 커널 분석 범위와 깊은 보안 탐지는 서로 경쟁하는 목표가 아니다. 객체 수명·메모리·I/O·스케줄링을 정확히 이해할수록 악성 변경과 정상 현상을 더 잘 구별할 수 있다. 현재의 기반을 네 가지 완결 조사 경로로 묶는 것이 다음 단계의 가장 높은 우선순위다.

---

<a id="appendix-a"></a>
## 부록 A. 이번 독립 테스트의 방법과 결과

### A.1. 수행 범위

이번 작업에서 Windows 드라이버를 실행하지는 않았다. 다음 두 검사는 Linux 컨테이너에서 수행한 제한된 독립 검사다. 저장소의 기존 self-test 결과와 합산하지 않는다.

| 검사 | 사용한 대상 | 결과 | 입증하지 않는 것 |
|---|---|---|---|
| 주소 판정 경계 | 현 HEAD의 정확한 `AddressSpaceDescriptor.h` | **41 passed / 0 failed** | 실제 Windows LA57, mapping validity, kernel security state |
| 후보 선택 모델 | 현 `HiddenProcessScanner::Scan`에서 도출한 PID 정렬·128개 제한 | **257개 중 128개 선택, 129개 미선택**, 10회 반복 | 실제 Windows 후보 생성, scanner 전체 runtime 결과 |

주소 헤더는 Git blob hash를 계산해 연결된 저장소의 blob과 일치함을 확인했다.

```text
Git blob SHA-1:
aa45996a7ce20dbffe1772f7e72e0948104044d8

Repository revision:
16c34da0e8e66a0d5f1d39ed54b1cd69d89765c3

Path:
user/AddressSpaceDescriptor.h
```

### A.2. 주소 경계 테스트 재현

해당 리비전의 헤더와 아래 코드를 같은 디렉터리에 놓고 테스트할 수 있다. 현재 portable 계약에서 pointer width 4는 지원하지 않으므로 그 입력이 거절되는 것을 확인한다. 이것을 WOW64 프로세스 전체의 미지원 선언으로 확대하지 않는다.

```bash
g++ -std=c++17 -Wall -Wextra -Werror address_test.cpp -o address_test
./address_test
```

실제 출력:

```json
{"scope":"exact_portable_header_boundary_tests","passed":41,"failed":0,"windows_runtime_tested":false}
```

독립 테스트 코드:

```cpp
#include "AddressSpaceDescriptor.h"
#include <iostream>
#include <string>

int main()
{
    int passed = 0;
    int failed = 0;
    auto check = [&](bool ok, const std::string& name)
    {
        if (ok)
        {
            ++passed;
        }
        else
        {
            ++failed;
            std::cerr << "FAIL " << name << '\n';
        }
    };
    for (uint32_t levels : {4u, 5u})
    {
        auto s = AddressSpaceDescriptor::FromPagingLevels(levels);
        const auto sign = uint64_t{1} << (s.VirtualAddressBits - 1);
        const auto high = ~(sign - 1);
        const auto label = std::to_string(levels);
        check(s.Valid(), label + " valid");
        check(!s.LegacyAssumed, label + " declared");
        check(s.Canonical(0), label + " zero");
        check(s.Canonical(sign - 1), label + " last user");
        check(!s.Canonical(sign), label + " lower hole");
        check(!s.Canonical(high - 1), label + " upper hole");
        check(s.Canonical(high), label + " first kernel");
        check(s.UserRange(sign - 4096, 4096), label + " user last page");
        check(!s.UserRange(sign - 4095, 4096), label + " user crosses hole");
        check(s.KernelRange(high, 4096), label + " kernel first page");
        check(!s.KernelRange(high - 1, 2), label + " kernel crosses hole");
        check(!s.KernelRange(UINT64_MAX, 2), label + " overflow");
        check(s.KernelRange(UINT64_MAX, 1), label + " final byte");
        check(!s.UserRange(0x10000, 0), label + " empty");
        s.UserMaximum = 0x7ffff;
        check(s.UserRange(0x7f000, 0x1000), label + " policy user accept");
        check(!s.UserRange(0x80000, 1), label + " policy user reject");
        s.KernelMinimum = high + 4096;
        check(!s.KernelRange(high, 1), label + " policy kernel reject");
        check(s.KernelRange(high + 4096, 1), label + " policy kernel accept");
    }
    check(!AddressSpaceDescriptor::FromPagingLevels(0).Valid(), "unknown paging");
    auto legacy = AddressSpaceDescriptor{};
    check(legacy.Valid() && legacy.LegacyAssumed, "explicit legacy");
    legacy.VirtualAddressBits = 57;
    check(!legacy.Valid(), "legacy LA57 rejection");
    auto invalid = AddressSpaceDescriptor::FromPagingLevels(4);
    invalid.PointerBytes = 4;
    check(!invalid.Valid(), "unsupported pointer width");
    invalid.PointerBytes = 8;
    invalid.PhysicalAddressBits = 53;
    check(!invalid.Valid(), "invalid physical width");
    std::cout << "{\"scope\":\"exact_portable_header_boundary_tests\",\"passed\":" << passed
              << ",\"failed\":" << failed << ",\"windows_runtime_tested\":false}" << '\n';
    return failed == 0 ? 0 : 1;
}
```

### A.3. 고정 후보 선택 모델

다음 코드는 확인된 정책의 선택 부분만 모델링한다. kernel read·fresh inventory·deadline·process 종료는 모사하지 않는다. 따라서 실제 결함의 host 재현이 아니라, **고정 접두부 선택에 재개 상태가 없을 때 진행되지 않는 후보가 생김**을 보여 준다.

```python
candidates = list(range(257))
ever_selected = set()

for _ in range(10):
    for index, candidate in enumerate(candidates):
        if index >= 128:
            continue
        ever_selected.add(candidate)

assert len(ever_selected) == 128
assert len(set(candidates) - ever_selected) == 129
```

실제 저장한 결과:

```json
{
  "scope": "source_derived_stable_candidate_selection_model",
  "candidate_count": 257,
  "passes": 10,
  "per_pass_limit": 128,
  "ever_qualified": 128,
  "never_qualified": 129,
  "deadline_simulated": false,
  "windows_runtime_tested": false
}
```

후속 PR에서는 이 모델만으로 수정을 검증하지 말고 실제 selection helper를 분리해 동일한 테스트와 process generation·비교-window 예산 테스트를 적용해야 한다.

<a id="appendix-b"></a>
## 부록 B. 검토 범위와 근거 관리

### B.1. 이번 검토에서 집중한 범위

최신 main의 architecture·roadmap·validation·coverage·MCP·AI·corpus 문서와 관측 소스·주소 판정·숨은 프로세스 확인·hunting admission·이미지 recipe·증거 graph·capability 구현을 읽었다. 이전 커밋과의 비교는 변경 방향을 파악하는 데 사용했으며, 후속 설계는 최근 diff뿐 아니라 기존 전체 collector 구조와 현재 end-to-end 제약을 대상으로 했다.

소스는 연결된 GitHub를 통해 고정 리비전으로 읽었다. 전체 저장소를 clone하여 모든 translation unit을 컴파일하거나 모든 코드를 행 단위로 감사한 작업은 아니다. 일부 큰 파일은 관련 함수와 인터페이스 범위를 읽었다. 따라서 이 문서는 전체 소스의 무결점 보증이나 종합 취약점 감사 보고서가 아니다.

### B.2. 사실·기록·추론·제안의 구분

| 표기·맥락 | 의미 |
|---|---|
| 확인한 구현 | 이번에 읽은 소스 또는 공개 계약에서 확인한 기능과 조건 |
| 저장소의 실측 기록 | 특정 날짜·EXE/SYS·환경의 작성자 기록. 이번에 재실행한 결과 아님 |
| 이번 독립 검사 | 부록 A의 제한된 코드·모델 실행 |
| 코드에서 도출한 위험 | 특정 입력·상태 조건에서 소스상 발생할 수 있는 문제. 실환경 재현과 구분 |
| 신규 설계·제안 계약 | 앞으로 추가하거나 통합할 내용. 현재 공개 CLI/API라고 주장하지 않음 |
| 미확인·unsupported | 근거 또는 권한·backend가 부족한 영역. 정상 또는 안전으로 간주하지 않음 |

### B.3. 증거 원장에 추가할 메타데이터

각 연구·외부 도구·비교 결과에는 publisher, URL, 게시일, 확인일, artifact/version/hash, 원래 주장 범위, 재현 여부, 영향을 주는 package·rule, support contract와의 관계를 기록하도록 권한다.

문서 refresh가 runtime validation을 갱신하지 않게 한다. 기존 release와 development의 테스트 hash·scope 구분은 유지한다. 특히 2026-10-30 process source checkpoint는 실제 Win32 source 대조를 포함하지만 driver load나 protected target·live native fallback을 검증한 기록은 아니다. [R04]

<a id="appendix-c"></a>
## 부록 C. 신규 계약 예시

아래는 **설계 예시**이며 현재 KnLiveDbg가 받아들이는 schema나 실행 명령이 아니다. 이름과 필드는 실제 ABI 검토 후 확정한다.

### C.1. 관측 receipt

```json
{
  "schema": "proposal.observation_receipt.v2",
  "operation_id": "op-example",
  "target_id": "target-example",
  "source_connection_id": "source-example",
  "address_space_id": "as-example",
  "address_shape": {
    "virtual_address_bits": 48,
    "subject_pointer_bytes": 8,
    "physical_address_bits": null
  },
  "range": {"address": "65536", "length": "4096"},
  "capture_interval": {
    "clock_domain": "collector-boot-example-monotonic",
    "begin": "120000",
    "end": "120003"
  },
  "status": {"domain": "win32", "raw": "0", "state": "complete"},
  "consistency": "handle_bound_single_read",
  "identity_revalidated": true,
  "mapping_lifetime_bound": false,
  "side_effects_possible": true,
  "spans": [
    {"offset": "0", "length": "4096", "state": "valid", "artifact_ref": "example-only"}
  ],
  "fallback_from": null,
  "execution_observed": false
}
```

identity 재확인이 true여도 mapping lifetime은 false일 수 있다. 이 예시는 hash·artifact의 실제 값이 없으므로 증거 파일로 import할 수 있는 유효 publication이 아니다.

### C.2. 주장 계약

```yaml
schema: proposal.claim_policy.v1
claim: observed_callback_references_modified_code
scope:
  target: required
  process_or_kernel_generation: required
  observation_interval: required
requires:
  - qualified_callback_slot_role
  - matching_layout_identity
  - recorded_slot_bytes
  - supported_static_transfer_read_set
  - stable_reference_checks
  - supported_scoped_image_difference
emits:
  - supports
  - contradicts
  - unfulfilled_requirements
  - next_best_observation
never_implies:
  - execution_observed
  - writer_attributed
  - maliciousness_established
  - whole_host_clean
```

### C.3. runtime capability 기록

```yaml
schema: proposal.runtime_capability.v1
operation: typed_kernel_object_read
implementation: compiled
availability: partial
validation: not_performed_for_this_target
requirements:
  driver_contract: satisfied
  address_space: qualified
  symbol_identity: satisfied
  runtime_layout_invariants: unavailable
limits:
  - live_non_atomic
  - object_lifetime_not_bound
  - vtl0_only
```

**이런 상태에서 할 수 있는 일과 할 수 없는 일을 함께 반환**해야 한다. 예를 들어 raw candidate bytes를 저장하고 offline 분석하는 것은 가능할 수 있지만, object membership을 확정하는 claim은 보류해야 한다.

<a id="appendix-d"></a>
## 부록 D. 저장소·외부 출처

### D.1. 저장소 근거

아래 소스 링크는 모두 검토한 커밋에 고정했다. 항목별 파일 안에서 본문에 명시한 함수·계약·절을 확인할 수 있다. GitHub의 최신 `main`이나 과거 문서의 링크가 나중에 변하더라도 본 보고서의 기준은 바뀌지 않는다.

| ID | 근거 | 사용한 범위 |
|---|---|---|
| R01 | [검토 커밋][R01] | HEAD identity·커밋 시각·최신 통합 변경 |
| R02 | [직전 검토와의 비교][R02] | 21개 커밋의 개선 범위 식별 |
| R03 | [ARCHITECTURE.md][R03] | 관측·심벌·증거·이미지 proof·scheduler·운영 계약 |
| R04 | [VALIDATION.md][R04] | 날짜·binary별 기록과 driver-free/live 구분 |
| R05 | [FEATURE_PLAN.md][R05] | W01–W15의 구현과 남은 통합 범위 |
| R06 | [SourceCapabilities.h][R06] | compiled contract·runtime 미탐색·명시적 unsupported |
| R07 | [AddressSpaceDescriptor.h][R07] | 주소 폭·범위 계약, 정확한 portable header 테스트 |
| R08 | [ObservationSource.h][R08] | 공통 read admission, sparse status, bool 호환 함수 |
| R09 | [ProcessObservationSource.h][R09] | 소유 handle·PID/creation 확인·Win32 status |
| R10 | [HiddenProcessScanner.cpp][R10] | PID 순서·128 후보 확인·5초 예산·직접 read |
| R11 | [HiddenProcessScanner.h][R11] | scanner의 상태와 재개 cursor 부재 |
| R12 | [NativeObservationSource.h][R12] | device epoch·descriptor·prefix/실패 처리 |
| R13 | [ImageVerificationRecipe.h][R13] | recipe 범위·read budget·version 계약 |
| R14 | [ImageVerificationRecipe.cpp][R14] | 원본 정규화·qualification·원정책/current 재분석 |
| R15 | [EvidenceGraph.h][R15] | 단일 bundle graph·query interface |
| R16 | [KMON_DETECTION_COVERAGE.md][R16] | 실제 탐지 계열과 제한·주소 문서 drift |
| R17 | [KmonHunting.h][R17] | descriptor admission·receipt·전역 freshness 정책 |
| R18 | [EvidenceGraph.cpp][R18] | 원본 digest·정적 참조·256/512 materialization 범위 |
| R19 | [MCP_SERVER_DESIGN.md][R19] | operation ledger·timeout·권한·no-TLS·protocol 버전 |
| R20 | [AI_ASSISTED_WORKFLOWS.md][R20] | AI 계획·승인·private/local-only의 실제 의미 |
| R21 | [BENCHMARK_CORPUS.md][R21] | 평가 분모·scope·synthetic 및 실제 검증의 경계 |

### D.2. 외부 일차 자료

| ID | 자료 | 설계에 사용한 범위 |
|---|---|---|
| E01 | [Microsoft — Introducing WinDbg MCP][E01] | 2026-10-06 발표, evidence-based 진단과 안전 경계 |
| E02 | [Microsoft — Introducing the ETW MCP][E02] | 2026-07-21 headless ETL 분석 preview |
| E03 | [Microsoft — Introducing WPA MCP][E03] | 2026-07-30 trace 분석 preview |
| E04 | [Elastic — Windows Endpoint Security Platform 분석][E04] | 2026-10-26 preview 바이너리 분석, 공개 계약의 한계 |
| E05 | [Microsoft — The Windows Driver Policy][E05] | 2026년 driver trust와 audit/enforcement 조건 |
| E06 | [MCP — The 2026-07-28 Specification][E06] | protocol 변경과 application state의 분리 |
| E07 | [VirusTotal — YARA-X v1.23.0][E07] | 2026-11-05 공식 release·고정 버전 연계 |
| E08 | [Volatility Foundation — Volatility 3 v2.28.2][E08] | dump 분석·translation 비교의 독립 구현 참고 |
| E09 | [HyperDbg — v0.24][E09] | hardware-assisted lab 분석 참고; 환경 지원 별도 |
| E10 | [Microsoft — Virtual Secure Mode][E10] | VTL별 메모리·신뢰 경계 |
| E11 | [Microsoft — MmCopyMemory][E11] | 부분 읽기·수명·residency·물리 읽기 제약 |
| E12 | [Microsoft — Performing Local Kernel Debugging][E12] | local/정지 kernel 디버깅 기능 차이 |
| E13 | [Microsoft — Time Travel Debugging Overview][E13] | 사용자 모드 기록·재생과 지원 제한 |
| E14 | [Intel — libipt][E14] | 원본 PT decoder 구현 참고 |
| E15 | [AMD — Introduction to IBS][E15] | CPU별 sampling 계약의 차이 |
| E16 | [SafeBreach — PoolParty][E16] | thread-pool의 여러 작업 경로에 대한 기반 연구 |
| E17 | [TLSCheck 2.0, arXiv:2604.20378][E17] | 2026년 TLS metadata·callback 분석 연구; abstract 범위 참고 |
| E18 | [ESET — Gentlemen EDR-killer framework 분석][E18] | 2026-06-18 원본 조사, 보안 무력화의 행위·효과 연결 |
| E19 | [MemProcFS 원본 저장소][E19] | 다양한 memory source·API·forensic 연계 참고 |
| E20 | [DRAKVUF 원본 프로젝트][E20] | VM 외부 분석의 구조와 환경 제약 |
| E21 | [Microsoft — Driver Verifier][E21] | 테스트 환경의 driver 안전성 검증 |
| E22 | [Microsoft — Kernel DMA Protection][E22] | 장치·IOMMU·DMA 보호 범위의 한계 |

외부 자료의 기능·정책은 해당 자료가 설명한 범위만 사용했다. 일부 원문은 검색 도구가 제공한 공식 본문·발췌로 확인했다. 논문 abstract를 참고한 항목은 전체 논문의 실험을 재검증한 것으로 취급하지 않았다. 공개 release 확인도 실행·호환성 시험을 대신하지 않는다.

---

**검토 종료 요약:** 문서·핵심 코드의 고정 리비전 검토와 일차 자료 조사, portable 주소 테스트 및 후보 선택 모델을 수행했다. 저장소 코드나 설정을 수정·push하지 않았다. 본 설계의 완료 조건은 후속 구현·실환경 검증을 위한 제안이며, 현재 제품의 탐지율·안전성·세계 순위 인증이 아니다.


[R01]: https://github.com/kernullist/kn-live-dbg/commit/16c34da0e8e66a0d5f1d39ed54b1cd69d89765c3
[R02]: https://github.com/kernullist/kn-live-dbg/compare/17991819badb926c7d6e113abee6eded4e5ba0f9...16c34da0e8e66a0d5f1d39ed54b1cd69d89765c3
[R03]: https://github.com/kernullist/kn-live-dbg/blob/16c34da0e8e66a0d5f1d39ed54b1cd69d89765c3/docs/ARCHITECTURE.md
[R04]: https://github.com/kernullist/kn-live-dbg/blob/16c34da0e8e66a0d5f1d39ed54b1cd69d89765c3/docs/VALIDATION.md
[R05]: https://github.com/kernullist/kn-live-dbg/blob/16c34da0e8e66a0d5f1d39ed54b1cd69d89765c3/docs/FEATURE_PLAN.md
[R06]: https://github.com/kernullist/kn-live-dbg/blob/16c34da0e8e66a0d5f1d39ed54b1cd69d89765c3/user/SourceCapabilities.h
[R07]: https://github.com/kernullist/kn-live-dbg/blob/16c34da0e8e66a0d5f1d39ed54b1cd69d89765c3/user/AddressSpaceDescriptor.h
[R08]: https://github.com/kernullist/kn-live-dbg/blob/16c34da0e8e66a0d5f1d39ed54b1cd69d89765c3/user/ObservationSource.h
[R09]: https://github.com/kernullist/kn-live-dbg/blob/16c34da0e8e66a0d5f1d39ed54b1cd69d89765c3/user/ProcessObservationSource.h
[R10]: https://github.com/kernullist/kn-live-dbg/blob/16c34da0e8e66a0d5f1d39ed54b1cd69d89765c3/user/HiddenProcessScanner.cpp
[R11]: https://github.com/kernullist/kn-live-dbg/blob/16c34da0e8e66a0d5f1d39ed54b1cd69d89765c3/user/HiddenProcessScanner.h
[R12]: https://github.com/kernullist/kn-live-dbg/blob/16c34da0e8e66a0d5f1d39ed54b1cd69d89765c3/user/NativeObservationSource.h
[R13]: https://github.com/kernullist/kn-live-dbg/blob/16c34da0e8e66a0d5f1d39ed54b1cd69d89765c3/user/ImageVerificationRecipe.h
[R14]: https://github.com/kernullist/kn-live-dbg/blob/16c34da0e8e66a0d5f1d39ed54b1cd69d89765c3/user/ImageVerificationRecipe.cpp
[R15]: https://github.com/kernullist/kn-live-dbg/blob/16c34da0e8e66a0d5f1d39ed54b1cd69d89765c3/user/EvidenceGraph.h
[R16]: https://github.com/kernullist/kn-live-dbg/blob/16c34da0e8e66a0d5f1d39ed54b1cd69d89765c3/docs/KMON_DETECTION_COVERAGE.md
[R17]: https://github.com/kernullist/kn-live-dbg/blob/16c34da0e8e66a0d5f1d39ed54b1cd69d89765c3/user/KmonHunting.h
[R18]: https://github.com/kernullist/kn-live-dbg/blob/16c34da0e8e66a0d5f1d39ed54b1cd69d89765c3/user/EvidenceGraph.cpp
[R19]: https://github.com/kernullist/kn-live-dbg/blob/16c34da0e8e66a0d5f1d39ed54b1cd69d89765c3/docs/MCP_SERVER_DESIGN.md
[R20]: https://github.com/kernullist/kn-live-dbg/blob/16c34da0e8e66a0d5f1d39ed54b1cd69d89765c3/docs/AI_ASSISTED_WORKFLOWS.md
[R21]: https://github.com/kernullist/kn-live-dbg/blob/16c34da0e8e66a0d5f1d39ed54b1cd69d89765c3/docs/BENCHMARK_CORPUS.md
[E01]: https://devblogs.microsoft.com/performance-diagnostics/introducing-windbg-mcp-debug-with-natural-language-grounded-in-evidence/
[E02]: https://devblogs.microsoft.com/performance-diagnostics/etw-mcp-intro/
[E03]: https://devblogs.microsoft.com/performance-diagnostics/introducing-wpa-mcp-early-preview-of-ai-assisted-trace-analysis-in-windows-performance-analyzer/
[E04]: https://www.elastic.co/security-labs/blog/windows-endpoint-security-platform-wesp
[E05]: https://support.microsoft.com/en-us/windows/hardware/drivers/the-windows-driver-policy
[E06]: https://blog.modelcontextprotocol.io/posts/2026-07-28/
[E07]: https://github.com/VirusTotal/yara-x/releases/tag/v1.23.0
[E08]: https://github.com/volatilityfoundation/volatility3/releases/tag/v2.28.2
[E09]: https://github.com/HyperDbg/HyperDbg/releases/tag/v0.24
[E10]: https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/vsm
[E11]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-mmcopymemory
[E12]: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/performing-local-kernel-debugging
[E13]: https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/time-travel-debugging-overview
[E14]: https://github.com/intel/libipt
[E15]: https://docs.amd.com/r/en-US/68658-uProf-getting-started-guide/Introduction-to-IBS-Instruction-Based-Sampling
[E16]: https://www.safebreach.com/blog/process-injection-using-windows-thread-pools/
[E17]: https://arxiv.org/abs/2604.20378
[E18]: https://www.welivesecurity.com/en/eset-research/killing-me-gently-inside-gentlemens-edr-killer-framework/
[E19]: https://github.com/ufrisk/MemProcFS
[E20]: https://drakvuf.com/
[E21]: https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/driver-verifier
[E22]: https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt
