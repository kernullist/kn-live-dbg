# Timeline Command Usage

이 문서는 `!timeline` 명령을 사용 시나리오 기준으로 정리한다. 목표는 TI ETW 기록, snapshot baseline, 선택적 kernel live callback 이벤트를 하나의 시간순 evidence 모델로 모아 조사 흐름을 단순하게 유지하는 것이다.

## 핵심 모델

`!timeline`은 네 가지 역할로 보면 된다.

1. evidence를 user-mode timeline store로 복사한다.
2. 시간순 event를 source/domain/PID 기준으로 조회한다.
3. process/image/source/domain 관계 graph를 만든다.
4. event를 snapshot baseline 또는 snapshot JSON 파일과 비교한다.

가장 기본 흐름은 아래다.

```text
!timeline status
!timeline update
!timeline query
!timeline graph
```

명시적 source 제어, kernel callback 수집, snapshot 파일 비교, JSONL export가 필요할 때만 고급 subcommand를 사용한다.

## Source 와 Domain

주요 source:

| Source | 의미 |
| --- | --- |
| `ti` | `!ti` ring에서 복사한 Microsoft-Windows-Threat-Intelligence ETW record |
| `snapshot` | session baseline 또는 snapshot JSON 파일에서 복사한 process/domain record |
| `kernel-live` | kernel live callback ring에서 drain한 process create, process exit, image-load record |

주요 domain:

| Domain | 의미 |
| --- | --- |
| `process` | process lifecycle 또는 snapshot process record |
| `image` | image-load evidence |
| `threat-intelligence` | TI provider event |
| snapshot scanner domain | snapshot에서 복사된 pool, module, driver, thread, VAD 등 scanner domain |

현재 세션에 실제로 어떤 source/domain이 있는지는 `!timeline status`의 counter를 보면 된다.

## 기본값과 제한

| 명령 영역 | 기본값 | 제한 |
| --- | --- | --- |
| `update recent` | TI record 200개 | `/limit` 최대 100000 |
| `update all` | TI record 10000개 | `/limit` 최대 100000 |
| `ingest ti recent` | TI record 200개 | `/limit` 최대 100000 |
| `ingest ti all` | TI record 10000개 | `/limit` 최대 100000 |
| `query` | event 50개, newest first | `/limit` 최대 5000 |
| `graph` | event 200개, newest first | `/limit` 최대 5000 |
| `reconcile` | finding 50개 | `/limit` 최대 5000 |
| `live start` | capacity 4096 | `/capacity` 범위 128..16384 |
| `live drain` | event 256개 | `/limit` 최대 1024 |

`!timeline update /live`는 update limit이 더 커도 live event를 최대 1024개까지만 drain한다. 동일 evidence는 timeline store에서 deduplicate되므로 조사 중 `update` 또는 `ingest`를 반복 실행해도 같은 event가 계속 쌓이지 않는다.

## Scenario 1: 빠른 세션 triage

현재 세션에 이미 쌓인 evidence가 있는지 빠르게 확인할 때 사용한다.

```text
!timeline status
!timeline update
!timeline query /limit 50
!timeline graph /limit 200
```

흐름:

1. `status`로 timeline이 비어 있는지, source/domain counter가 무엇인지 확인한다.
2. `update`로 최근 TI record와 현재 snapshot baseline을 timeline으로 복사한다.
3. `query`로 newest event를 확인한다.
4. `graph`로 source, domain, process, image 관계를 요약한다.

`status`에서 `dropped`가 0보다 크면 timeline은 부분 evidence다. 리포트나 판단에는 loss caveat를 유지해야 한다.

## Scenario 2: Snapshot baseline 비교

"기준선과 비교해서 무엇이 달라졌는가?"가 핵심 질문일 때 사용한다.

```text
!snapshot baseline /all /name before-test
!timeline update

... 조사 대상 행위를 실행하거나 재현 ...

!timeline update
!timeline reconcile snapshot
!timeline reconcile snapshot /domain process /limit 50
!timeline reconcile snapshot /domain image /limit 50
```

권장 순서:

1. 행위가 시작되기 전에 snapshot baseline을 캡처한다.
2. `!timeline update`를 한 번 실행해서 baseline을 timeline에 복사한다.
3. 조사 대상 행위를 재현하거나 관찰한다.
4. `!timeline update`를 다시 실행해서 새 TI/snapshot evidence를 복사한다.
5. `reconcile`로 baseline에 없는 timeline event와 timeline에 없는 baseline record를 찾는다.

이 흐름은 같은 부팅 세션에서 baseline을 캡처한 분석에 가장 잘 맞는다.

## Scenario 3: Threat-Intelligence ETW 중심 분석

대상 행위가 process, memory, handle, image operation과 관련 있고 Microsoft-Windows-Threat-Intelligence provider에서 관찰될 가능성이 높을 때 사용한다.

```text
set-ppl-antimalware status
set-ppl-antimalware on

!ti start /name suspect.exe /ring 1048576 /log .\.kn-live-dbg\ti
!ti watch

... 행위 관찰 ...

!timeline update
!timeline query /source ti /limit 100
!timeline query /domain threat-intelligence /limit 100
!timeline query /source ti /pid <PID> /limit 100
!timeline graph /source ti /limit 300
```

운영 메모:

1. TI 구독은 보통 호출 프로세스가 PPL Antimalware여야 한다.
2. `!timeline update`는 TI ring record를 timeline으로 복사하지만 TI ring이나 log를 지우지 않는다.
3. TI만 보고 싶으면 `/source ti`를 사용한다.
4. 다른 source와 무관하게 provider event domain만 보고 싶으면 `/domain threat-intelligence`를 사용한다.

## Scenario 4: Kernel live process/image 추적

process create, process exit, image-load evidence를 kernel notify callback으로 보고 싶을 때 사용한다.

```text
!timeline live status
!timeline live start /capacity 4096

... 프로세스 실행, 드라이버 로드, DLL 로드, 의심 행위 재현 ...

!timeline update /live
!timeline live status
!timeline query /source kernel-live /limit 100
!timeline graph /source kernel-live /limit 300

!timeline live stop
```

중요 동작:

1. `!timeline live start`는 kernel process/image callback을 등록하고 bounded nonpaged ring을 할당한다.
2. `!timeline update`만 실행하면 live callback event는 drain하지 않는다.
3. `!timeline update /live`가 queued live event를 user-mode timeline store로 drain한다.
4. TI/snapshot evidence를 같이 ingest하고 싶지 않으면 `!timeline live drain /limit <n>`을 직접 사용한다.
5. `!timeline live stop`은 callback을 unregister한다.

실행 전후로 `!timeline live status`를 확인한다. `dropped`가 증가했다면 live ring overflow가 있었으므로 reconcile confidence를 낮게 해석해야 한다.

## Scenario 5: PID 중심 조사

이미 의심 PID를 알고 있을 때 사용한다.

```text
!timeline update /live
!timeline query /pid <PID> /limit 100
!timeline graph /pid <PID> /limit 300
!timeline reconcile snapshot /pid <PID> /limit 50
```

이 흐름으로 확인하는 것:

1. 어떤 source가 이 PID를 언급했는가?
2. 어떤 domain evidence가 붙어 있는가?
3. baseline에 없는 image evidence가 있는가?
4. snapshot baseline에는 있는데 timeline event로 관찰되지 않은 process state가 있는가?

대상 프로세스가 매우 빨리 종료된다면 재현 전에 live collection을 먼저 시작한다.

```text
!timeline live start /capacity 4096
... 재현 ...
!timeline live drain /limit 1024
!timeline query /source kernel-live /pid <PID>
```

## Scenario 6: Image 중심 조사

의심 대상이 DLL, driver image path, mapped executable name일 때 사용한다.

```text
!timeline update /live
!timeline graph /image suspect.dll /limit 300
!timeline graph /image C:\Path\To\suspect.dll /limit 300
!timeline query /domain image /limit 100
!timeline reconcile snapshot /domain image /limit 100
```

`graph /image`는 image evidence, entity text, summary text, evidence value에 대해 substring match를 수행한다. 처음에는 basename으로 넓게 보고, noise가 많으면 full path로 좁힌다.

## Scenario 7: Snapshot 파일 비교

baseline이 이전에 저장된 파일이거나 다른 명령 출력에서 온 snapshot JSON일 때 사용한다.

```text
!timeline ingest snapshot .\.kn-live-dbg\before.json
!timeline update
!timeline reconcile snapshot .\.kn-live-dbg\before.json /limit 100
!timeline reconcile snapshot .\.kn-live-dbg\before.json /domain process /limit 100
```

주의점:

1. `ingest snapshot <path>`는 파일의 record를 timeline에 복사한다.
2. `reconcile snapshot <path>`는 현재 timeline event를 그 파일과 비교한다.
3. 파일 ingest는 session baseline을 교체하지 않는다. snapshot-derived timeline event를 추가할 뿐이다.

## Scenario 8: 리포트와 offline review

현재 evidence set을 보존해야 할 때 사용한다.

```text
!timeline status
!timeline export .\.kn-live-dbg\timeline.jsonl /jsonl
```

CLI export는 schema-versioned JSONL을 디스크에 기록한다. 이 명령은 TUI의 session-mutating/file-writing 명령이다.

MCP client에서는 read-only MCP tool을 사용한다.

```text
timeline.export
```

MCP tool은 JSONL text를 응답으로 반환하며 host file을 쓰지 않는다.

## Scenario 9: 실행 사이 reset

새로운 local analysis pass를 깨끗하게 시작할 때 사용한다.

```text
!timeline clear
!timeline live clear
!timeline status
```

각 clear 명령의 범위:

1. `!timeline clear`는 user-mode timeline store를 비운다.
2. `!timeline live clear`는 queued kernel live event를 비운다. user-mode timeline store는 지우지 않는다.
3. `!ti clear`는 별도이며 TI ring을 지운다.

의도한 evidence source에 맞는 가장 좁은 clear 명령을 사용한다.

## Command Reference

```text
!timeline update [recent|all] [/limit <n>] [/snapshot] [/live]
!timeline status
!timeline clear
!timeline ingest ti [recent|all] [/limit <n>]
!timeline ingest snapshot [baseline|<path>]
!timeline live start|stop|status|clear|drain [/capacity <n>] [/limit <n>]
!timeline query [/source <name>] [/domain <name>] [/pid <PID>] [/limit <n>] [/oldest|/newest]
!timeline graph [/source <name>] [/domain <name>] [/pid <PID>] [/image <name>] [/limit <n>] [/oldest|/newest]
!timeline reconcile snapshot [baseline|<path>] [/source <name>] [/domain <name>] [/pid <PID>] [/limit <n>]
!timeline export <path> [/jsonl]
```

`update`의 `/snapshot`은 operator readability를 위해 허용된다. session baseline이 있으면 compact update path에서 snapshot ingest는 이미 수행된다.

## Help 와 Completion

도움말은 두 형태를 모두 지원한다.

```text
help !timeline
!timeline help
```

interactive prompt는 다음에 대해 context-aware Tab completion을 지원한다.

1. `update`, `live`, `query`, `graph`, `reconcile`, `export` 같은 root subcommand.
2. `!timeline live start`, `!timeline live drain` 같은 nested action.
3. `/limit`, `/snapshot`, `/live`, `/source`, `/domain`, `/pid`, `/image`, `/oldest`, `/newest`, `/jsonl` 같은 option.

## 운영 Caveat

1. 관찰해야 하는 행위 전에 live collection을 시작한다. callback ring은 이미 지나간 process/image event를 복구할 수 없다.
2. `/live`는 명시적으로만 사용한다. plain `!timeline update`는 low-surprise path이며 kernel live ring을 mutate하지 않는다.
3. live `dropped` counter는 evidence loss로 해석한다. reconcile output은 이 caveat를 반영하므로 confidence를 과장하지 않는다.
4. 보통 `query` 먼저, 그 다음 `graph`, 마지막에 `reconcile` 순서가 읽기 쉽다.
5. `all`은 ring size와 report size가 정당화될 때만 사용한다. interactive 분석의 기본은 `recent`다.
6. MCP timeline tool은 read-only 자동화에 사용한다. collection, drain, clear, disk export는 TUI에서 수행한다.
