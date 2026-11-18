# Timeline Command Usage

이 문서는 단순화된 `!timeline` 사용 흐름을 정리한다. 목표는 분석가가 외워야 할
명령을 최소화하는 것이다. 보통은 `!timeline`으로 수집/갱신하고,
`!timeline dashboard`에서 시각적으로 살펴보면 된다.

## 기본 흐름

```text
!timeline
!timeline dashboard
```

plain `!timeline`은 일반 운영 경로다. 실행하면 다음을 켤지 물어본다.

1. Threat-Intelligence ETW capture.
2. Kernel live process/image/thread callback.

yes로 답하면 KnLiveDbg가 해당 collector를 자동으로 켠다. TI는 PPL
Antimalware가 필요할 수 있으므로 guided path는 `!ti start` 전에 기존
`set-ppl-antimalware` 흐름을 시도한다. write mode, symbol, driver device가
준비되지 않았으면 실패 이유를 출력하고, 이미 사용 가능한 evidence만 갱신한다.

프롬프트 이후 `!timeline`은 다음 evidence를 갱신한다.

- timeline TI cursor보다 새로운 최근 TI ring record;
- 현재 snapshot baseline이 있으면 baseline evidence;
- live callback이 켜져 있으면 queued live callback event.

live callback을 켜면 user-mode auto-drain worker도 함께 시작된다. 이 worker는
kernel ring을 주기적으로 비워 in-memory timeline store에 넣으므로, 짧게
생겼다가 사라지는 process/thread activity가 다음 수동 refresh까지 driver ring에만
남아 있지 않는다.

`!timeline dashboard`는 고정 self-contained HTML dashboard를 연다. source,
domain, PID, image/driver/DLL, TI task, risk, text filter는 command
parameter가 아니라 dashboard 내부 control로 선택한다. 현재 filter 결과를
JSONL로 보존해야 할 때도 dashboard export 버튼을 사용한다.
dashboard는 HTML을 만들기 직전에 recent TI ring record와 queued kernel-live
event를 한 번 더 timeline store로 복사한다. 그래서 최신 live/TI evidence를 보기
위해 별도 `!timeline update`를 먼저 입력할 필요가 없다. 화면 왼쪽 Analyst Focus는
현재 filter 결과가 baseline뿐인지, TI memory/cross-process/remote-thread evidence가
있는지 먼저 판정한다. dashboard는 생성 시점의 live/auto-drain 상태, matched
live-analysis rule, semantic relationship, 그리고 선택한
process/thread/driver/DLL/TI record, host, file, registry key, service, scheduled
task, WMI entity, memory/VAD transition, snapshot-diff milestone 주변 related event도
함께 보여준다.

## Evidence Family

Timeline ingest는 분석가가 자주 보는 evidence를 안정적인 key와 relationship
edge로 정규화한다. command surface는 늘어나지 않고, 이 family들은 dashboard
filter, relationship row, matched rule, JSONL export, `graph.query`를 통해 보인다.

- P0: process identity(`process_instance_id`)와 cross-process manipulation
  (`cross_process_operation`, source PID to target PID).
- P1: network/DNS endpoint, executable file artifact, registry persistence key.
- P2: service, scheduled task, WMI persistence, executable memory/VAD transition,
  snapshot-diff milestone.

network/DNS activity 자체를 자동으로 악성으로 보지는 않는다. 이미 risk가 붙은
event이거나 더 강한 evidence와 연관된 경우 matched rule로 승격된다. file,
registry, service/task/WMI, memory/VAD, snapshot-diff event는 executable drop,
persistence path, executable memory, high-risk diff와 맞물릴 때 높은 우선순위로
다룬다.

## 주요 명령

```text
!timeline
!timeline dashboard
!timeline reset
```

`!timeline reset`은 user-mode timeline store를 비운다. TI ring은 지우지 않는다.
TI ring 자체를 지우려면 `!ti clear`를 별도로 사용한다.

수동 live callback status/off/clear/drain 제어는 주요 표면에서 숨긴다.
명시적으로 live callback을 제어해야 할 때만 `!timeline help advanced`를 확인한다.

command-line JSONL export도 주요 표면에서 숨긴다. 분석가 주도 export는 dashboard
버튼을 사용하고, script에서는 advanced `!timeline export`를 사용한다.

지속적인 코드·드라이버 관측은 [KMON](KMON_DETECTION_COVERAGE.md)을 사용한다.
[대조군 안내](KMON_TEST_TARGET.md)에서 검증 범위와 제한을 확인한다.
라이브 tail에서 빠져나와도 수집은 계속된다. Timeline은 증거 그래프/대시보드이며,
수집 손실과 비교 공백은 결과 해석에 계속 반영해야 한다.

## Scenario: 빠른 triage

```text
!timeline
!timeline dashboard
```

먼저 dashboard filter를 사용한다. process, DLL, driver, TI task, risk 검토는
이 경로가 가장 단순하다.

아직 snapshot process baseline이 timeline에 없으면 `!timeline dashboard`는 HTML을
생성하기 전에 현재 실행 중인 프로세스 baseline을 가볍게 캡처해서 timeline에 넣는다.
그래서 live callback을 켜기 전에 이미 떠 있던 프로세스도 dashboard에서 확인할 수 있다.
이미 실행 중이던 프로세스에 대한 RWX VAlloc/AllocVM 같은 memory operation은
process/image/thread live callback만으로는 보이지 않는다. 이런 이벤트는 TI ETW가
수신해야 timeline에 들어오며, TI가 active인데 수신 event가 0이면 dashboard 상단
warning과 Analyst Focus에 표시된다.

## Scenario: TI 중심 분석

```text
!timeline

TI를 켤지 묻는 질문에 yes로 답한다.

... 조사 대상 행위를 재현하거나 관찰 ...

!timeline
!timeline dashboard
```

TI event는 TI ring/log를 지우지 않고 timeline으로 복사된다. 반복 recent refresh는
TI cursor를 사용하고, 현재 ring을 의도적으로 다시 훑고 싶을 때만 advanced
`!timeline ingest ti all`을 사용한다. TI risk(`info`/`warning`/`critical`)는
최종 판정이 아니라 triage 우선순위 신호다.
`AllocVM`, `VAlloc`, `ProtectVM`, `WriteVM`, `QueueUserApc`,
`SetThreadContext`처럼 target PID를 동반하는 TI event는 target process filter와
relationship row에서 cross-process/memory pivot으로 보인다.
선택한 TI event의 TDH payload는 dashboard 우측 `Evidence Fields`에
`payload.<field>` / `payload_type.<field>`로 보존되고, 주소/크기/protection/access
같은 공통 field는 `memory_address`, `allocation_size`, `protection`,
`desired_access`, `start_address` 같은 표준 key로도 승격된다.

### 이 컨트롤러의 TI 요청 확인

```text
!timeline ingest observer
!timeline query /source observer /domain observer_action
```

컨트롤러는 구독 시도 전체에 걸쳐 최근 ETW 제어 요청 64개를 보관한다.
대시보드를 새로 고치거나 위 명령을 실행하면 새 기록을 타임라인으로 복사한다.
복사하기 전에 밀려난 기록이 있으면 그 개수를 표시한다. 각 기록에는 컨트롤러
PID와 프로세스 생성 시각, 세션 세대, 요청·반환 시각, Win32 상태 코드와
처리 결과가 담긴다. `possible_observer_effect`는 요청이 일으킬 수 있는 영향을
설명한다. `effect_verified=false`이면 실제 영향은 별도로 측정하지 않았다.

세션 이름이나 GUID가 충돌하면 `collision`을 기록하고 기존 세션은 계속 실행된다.
시작 도중 실패했을 때는 `!ti status`의 `trace_resources`로 정리할 자원이
있는지 확인하고 `!ti stop`으로 정리를 재시도한다. 컨트롤러가 직접 수집한
기록의 출처는 `ingest_origin=local_controller`다. 일반 이벤트 입력 경로로
받은 관찰자 기록에는 `ingest_origin=supplied_record`가 붙는다.

### 라이브 콜백 제어 결과 확인

`!timeline live start`, `stop`, `clear` 실행 뒤 `!timeline ingest observer`와
`!timeline query /source observer /domain observer_action`으로 요청 결과를 읽는다.
컨트롤러는 라이브 제어 요청 64개를 TI와 별도로 보관하고 복사 전에 밀려난
개수를 표시한다. 대시보드 새로 고침과 `!timeline update`도 이 기록을 복사한다.

상세 응답을 지원하는 드라이버에서는 요청 ID, 장치 연결 세대, Win32 전송 결과,
작업 NTSTATUS, 제어 전후 등록 플래그가 한 행에 담긴다. `call.1`, `call.2` 등의
필드는 프로세스·이미지·스레드 콜백의 등록과 해제 시도, 각 호출을 시작하고
반환한 커널 UTC 시각을 롤백까지 순서대로 보존한다. 예를 들어 스레드 콜백 등록이 실패한 뒤 앞서 등록한 프로세스
콜백의 해제도 실패할 수 있다. 이 경우 두 오류와 남은 등록 비트가 함께
보인다. 다음 중지 요청은 남은 등록만 재시도한다.

명시적으로 시작하면 콜백 등록 전에 이벤트 링을 준비한다. 기존 링을 준비할
때는 대기 중인 이벤트를 지우고 시퀀스와 손실 카운터를 초기화한다. 뒤이어
등록에 실패해도 링은 이미 초기화됐을 수 있다. 진행 중인 수집은
`!timeline live status`로 확인한다.

안내형 타임라인과 `!kmon start`는 먼저 상태를 조회한다. 이미 실행 중이면
그 수집을 이어 쓴다. 중지 상태에서는 남은 콜백 등록, 대기 이벤트, 손실이
모두 0이고 다음 시퀀스가 1일 때만 시작한다. 상태를 읽지 못하거나 응답이
맞지 않아도 시작 요청은 보내지 않는다. 이전 기록이나 정리할 콜백이 있으면
`!timeline live status`로 확인할 수 있다. 같은 컨트롤러에서 장치 핸들을
여러 개 열어도 상태 확인과 조건부 시작 사이에 다른 제어 요청이 끼어들지 않는다.

KMON 시작 실패 시 라이브 수집을 자동으로 되돌리려면 같은 장치 연결에서
콜백을 새로 등록한 상세 기록이 있어야 한다. 그사이 이 컨트롤러가 다른 라이브
제어 요청을 보내거나 다른 KMON·타임라인 호출이 진행 중인 수집을 이어 쓰면
자동 롤백을 건너뛴다. 구형 응답을 받았으면 명시적으로 정리하기 전에
`!timeline live status`로 상태를 확인한다.

구형 ABI 17 드라이버의 응답은 `legacy_acknowledged`로 표시한다. 응답 형식이나
요청 ID가 맞지 않으면 `outcome_unconfirmed`로 기록한다. 두 경우 모두 콜백
상태 필드는 비워 둔다. 전송 실패에는 Win32 코드가 남는다. 등록 플래그는
드라이버가 추적하는 상태이고, 요청·반환 시각은 컨트롤러가 측정한 구간이다.
`effect_verified=false`이면 대상 프로세스에 미친 영향은 별도로 측정하지 않았다.
마지막 핸들이 닫히거나 드라이버가 언로드될 때의 정리는 드라이버 안에서
수행되므로 이 큐에 반환되는 컨트롤러 요청 기록은 없다.
최종 언로드에서 콜백 해제가 계속 실패하면 드라이버는 코드를 보존하고
시간 간격을 두어 남은 등록의 해제를 재시도한다.

## Scenario: Live process/thread/image 추적

```text
!timeline

live callback을 켤지 묻는 질문에 yes로 답한다.

... 대상 프로세스 실행, thread activity 생성, 또는 DLL/driver 로드 ...

!timeline
!timeline dashboard
```

live `dropped` counter가 증가하거나 dashboard에 높은 ring pressure가 보이면
timeline은 부분 evidence로 해석한다. 긴 세션에서는 live callback이 꺼질 때까지
auto-drain이 live record를 계속 timeline store로 복사한다. 명시적인 stop/clear/drain이
필요할 때만 advanced live control을 사용한다.

## Scenario: Snapshot 비교

```text
!snapshot baseline /all /name before-test
!timeline

... 조사 대상 행위 재현 ...

!timeline
!timeline dashboard
```

먼저 dashboard로 확인한다. `!diff baseline`을 실행하면 diff finding도
`snapshot-diff` milestone으로 timeline에 복사되므로, 다음 dashboard에서
live/TI evidence 옆에 같이 볼 수 있다.

```text
!diff baseline /domain drivers /limit 50
!timeline dashboard
```

텍스트 finding이 필요할 때만 advanced reconcile을 사용한다.

```text
!timeline reconcile snapshot /domain process /limit 50
!timeline reconcile snapshot /domain image /limit 50
```

## Advanced Compatibility

스크립트, 텍스트 출력, 명시적 source 제어가 필요할 때만 advanced 명령을 확인한다.

```text
!timeline help advanced
```

advanced surface:

```text
!timeline update [recent|all] [/limit <n>] [/snapshot] [/live]
!timeline status
!timeline clear
!timeline ingest ti [recent|all] [/limit <n>]
!timeline ingest observer
!timeline ingest snapshot [baseline|<path>]
!timeline live on|off|status|start|stop|clear|drain [/capacity <n>] [/limit <n>]
!timeline query [/source <name>] [/domain <name>] [/pid <PID>] [/limit <n>] [/oldest|/newest]
!timeline graph [/source <name>] [/domain <name>] [/pid <PID>] [/image <name>] [/limit <n>] [/oldest|/newest]
!timeline reconcile snapshot [baseline|<path>] [/source <name>] [/domain <name>] [/pid <PID>] [/limit <n>]
!timeline export <path> [/jsonl]
```

특별히 script/report/automation이 advanced text output을 요구하지 않으면 simple
surface를 우선 사용한다.
