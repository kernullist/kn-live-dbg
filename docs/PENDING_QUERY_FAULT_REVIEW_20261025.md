# 2026-10-25 97a00cd 응답 버퍼·실행기 실패 경합 리뷰

기준 커밋은 `97a00cd`다. 조회 응답 버퍼 변경, 마지막 포트 닫기, 코드 259 소유자
강제 종료, 새 ARM, 인스턴스 분리·재연결, 언로드 및 시험 실행기 실패를 함께 검토했다.
원시 증거는 `C:\git\kn-live-dbg\.build\pending-query-fault-20261025`에 보존한다.
이번 변경은 시험 실행기와 정리 경로다. 커널 소스와 v7 ABI는 변경하지 않았다.

## 발견과 수정

### 부분 생성된 조회 스레드가 생성자 실패 뒤에도 남음

기존 `Readers.__init__`는 조회 스레드를 하나씩 시작한다. 이후 `DuplicateHandle`
또는 스레드 준비가 실패하면 생성자는 예외를 반환하지만 이미 시작한 스레드는
종료 신호를 받지 않는다. 호출자에게 `Readers` 객체가 반환되지 않으므로 caller의
finally에서도 이를 회수할 수 없다. non-daemon 스레드와 복제 포트가 남을 수 있다.

실제 필터를 올리고 두 번째 복제에 실패를 주입했다. 수정 전에는 실패 뒤에도
첫 스레드 1개가 살아서 272회 조회를 수행했다. 수정 후 동일 재현에서는 살아 있는
스레드가 0개였다. 생성자에서 시작한 스레드에 stop을 보내고 join한 뒤 원래 예외를
다시 전달한다. 스레드 시작 자체가 실패하면 아직 이전되지 않은 포트를 닫는다.
증거: `baseline-failures.json`, `fixed-failures.json`.

### 감사·기록 실패가 서비스 삭제를 건너뜀

기존 공통 cleanup은 언로드, 최종 장부 검사, 필터 부재 검사, 서비스 삭제가 하나의
try에 있었다. 실제 언로드 성공 뒤 감사 기록에 예외를 넣으면 뒤의 삭제가 생략됐다.
수정 전에는 필터가 없어지고 `loaded=false`인데도 `sc query`가 성공했다. 수정 후에는
같은 감사 실패가 오류 기록에 남으면서 서비스 조회가 1060을 반환했다.

정리를 단계별로 분리했다. 조회기 종료 검사 실패가 나도 나머지 포트와 자식 프로세스를
회수한다. 원래 시험 예외는 `failure.txt`에 보존하고, 정리 중 예외는 별도로 누적한다.
명령 또는 감사 로그 쓰기 실패도 실제 자원 해제를 막지 않도록 한다. 필터 부재는
명령 실행 결과로 독립 확인하며, 필터가 여전히 등록돼 있으면 서비스 삭제를 거부한다.
성공한 서비스 삭제 뒤에는 소유 상태를 해제해 중복 삭제를 피한다.

## 커널 경로 검토

조회는 `g_Lock` 안에서 client/PID를 검증하고 지역 상태 사본을 만든다. lock을 푼 뒤
client 배열이나 포트 포인터를 다시 참조하지 않는다. 응답 예외 경로도 `QueryActive`를
줄이고 완료/실패 계수를 갱신한다. owner 교체와 topology 변경은 이미 캡처한 사본을
바꾸지 않는다. 응답에 과거 owner/세대가 포함되는 것은 이 프로토콜의 snapshot 의미다.

`OutputBuffer`는 잠기지 않은 사용자 버퍼이며, probe 뒤에도 보호나 매핑이 바뀔 수
있다. 실제 복사를 SEH 안에서 수행해야 한다는
[MessageNotifyCallback 계약](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nc-fltkernel-pflt_message_notify)과
[버퍼 처리 지침](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/buffer-handling)을 대조했다.
복사 실패는 버퍼 일부에 이미 쓰인 데이터까지 원복하는 계약이 아니다. 시험도 실패
시 전체 버퍼의 불변성을 요구하지 않고 오류 코드·반환 길이·범위 밖 손상을 확인한다.

언로드는 서버 포트를 닫고 worker를 join한 뒤 관리 callback 종료와
`FltUnregisterFilter`를 수행한다. 최종 장부는 unregister 뒤에 기록한다.
[서버 포트 종료](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/closing-the-communication-server-port)와
[FltUnregisterFilter](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltunregisterfilter)의 계약을 확인했다.
계수는 rundown의 대체물이 아니다. 이번 재검토에서 추가 커널 수명 결함은 재현하지 못했다.

## 복합 응답 시험

응답 528 bytes가 두 페이지 경계를 가로지르도록 배치하고 앞뒤 64 bytes canary를 둔다.
모든 Message가 500ms gate에 실제 진입한 뒤 다음 변화를 적용한다.

| 변경 | 기대 결과 |
| --- | --- |
| 두 번째 페이지 PAGE_NOACCESS | 998 / 반환 0 bytes, 완료 장부 일치, prefix/suffix 보존 |
| 두 번째 페이지 PAGE_READONLY | 같은 복사 실패 및 경계 검사 |
| 두 번째 페이지 MEM_DECOMMIT | 같은 복사 실패, 살아 있는 첫 페이지 prefix 보존 |
| 전체 해제 후 동일 VA 예약 | 접근 불가 상태 유지, 같은 복사 실패. 다른 Python 할당의 주소 재사용 방지 |
| 응답 영역에 다른 내용 덮어쓰기 | 성공 528 bytes, 캡처 시점의 owner/예약/세대와 일치, prefix/suffix 보존 |

동시에 원본과 마지막 복제 root를 닫고 owner를 259로 종료하며, 새 owner의 ARM 및
실제 READ, 상·하단 인스턴스 재연결, unload를 실행한다. 마지막 닫기와 unload는
조회 gate·복제 조회 완료·버퍼 변경·두 close 시작이 관측된 뒤 수행한다. 핸들 값을
닫은 뒤 다시 재사용해 발생하는 사용자 측 ABA를 경합 성공으로 세지 않는다.

## 실행기 실패 감독

새 `run-pending-query-failure-e2e.py`는 다음 실패를 별도 프로세스에서 주입한다.

| 단계 | 확인 내용 |
| --- | --- |
| reader-start | 조회기 부분 생성 실패 이후 thread/port 회수 |
| after-gates | Message 진입 뒤 actor 시작 전 실패와 barrier 해제 |
| during-race | 버퍼 변경과 마지막 닫기가 시작되고 unload와 조회가 진행 중일 때 예외 |
| reader-error | 원래 실패와 조회기 종료 검증 오류가 겹쳐도 나머지 자원 정리 |
| after-unload | native unload 성공 뒤 시험 본문 실패 |
| audit | 정상 최종 장부 확보 뒤 감사 단계 실패 |
| cleanup-audit | 시험 실패를 처리하는 cleanup 중 감사 실패 |
| cleanup-log | cleanup의 장부/필터/서비스 증거 기록이 계속 실패해도 자원 해제 |
| cleanup-command-log | lifecycle.log를 디렉터리로 바꿔 실제 명령 로그 append 실패를 일으켜도 자원 해제 |
| runner-exit | 살아 있는 조회·버퍼 변경·마지막 close·unload 구간에서 `os._exit(86)` |

일반 실패의 runner는 exit 1, `passed=false`여야 한다. 지정한 오류와 정확히 일치해야
하며, 추가 정리 오류를 허용하지 않는다. 의도한 reader-error 및 cleanup 감사/로그 실패의
정리 오류는 별도 예상값으로 검증한다. 실패를 성공으로 바꾸지 않고, 상위 감독 결과만
`verified_expected_failure=true`로 기록한다.

갑작스러운 실행기 종료는 Python finally를 실행하지 않는다. 감독 프로세스는 시작
event를 열기 전에 runner를 kill-on-close Job에 넣어 모든 자식 helper를 포함한다.
runner가 끝나면 Job을 종료하고 active process 0을 확인한다. 서비스가 남았다면
해당 실행 전에 부재했는지와 정확한 fixture ImagePath를 확인한 다음 최종 장부를
회수하고 unload/delete한다. 다른 서비스나 프로세스를 이름만으로 종료하지 않는다.
감독 프로세스 자체의 강제 종료·OS 정지는 이번 복구 보장 범위에 포함하지 않는다.
Job의 자식 포함과 종료/회계 API는
[Windows Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)의 계약을 따른다.

## 반복 검증 결과

모두 실제 자체 필터를 load/attach한 관리자 실행이다. 아래 주 집계는 성공 검증
**1,034개**, 예상 실패 **50회**, 최종 언로드 장부 **344개**다. 준비용 smoke,
수정 전/후 결함 재현, 감독 결과의 실패 표기 검사 표본은 이 집계에 중복 포함하지 않았다.
모든 결과와 장부를 읽고 불변식을 다시 검사한 집계는 `summary.json`에 있다.

| 실행 | 검증 수 | 언로드 장부 |
| --- | ---: | ---: |
| fault-main: 8 readers, 24 × owner idle/query | 147 | 48 |
| fault-readers2: 2 readers, 8 × idle/query | 51 | 16 |
| fault-readers16: 16 readers, 8 × idle/query | 51 | 16 |
| query-regression: 기존 stress/controls/races, 4회 | 99 | 44 |
| watch-regression: 코드 259 및 대상 감시, 2회 | 179 | 42 |
| rearm-regression: 재연결/늦은 READ/ARM, 2회 | 95 | 40 |
| partial-regression: 8개 중 7개 제출, 2회 | 77 | 30 |
| multiread-regression: 8 READ, 2회 | 57 | 18 |
| legacy-races: 기존 취소/종료 경합, 2회 | 33 | 14 |
| pending-regression: cycles 4 | 136 | 25 |
| read-regression: read-only cycles 4 | 16 | 1 |
| managed-regression: cycles 30 + 동시 close 실행 파일 | 93 | 별도 managed 검사 |
| 실패 감독: 10종 × 5회 (8 readers 3회, 2/16 각 1회) | 예상 실패 50 | 50 |

주 응답 경합은 총 88회이며, 그중 버퍼 변경을 동시에 적용한 경합은 80회다.
버퍼 변경 288건은 noaccess 62, readonly 58, decommit 56, release/reserve 56,
overwrite 56건이다. 실패해야 할 232건은 모두 `0x800703e6`/0 bytes였고, 성공해야 할
56건은 528 bytes와 과거 owner/예약/세대를 정확히 반환했다. 검사 가능한 prefix/suffix
canary 손상은 없었다. 의도한 버퍼 변경 외의 성공/실패 오분류는 관측하지 못했다.

일반 조회기에서 정상 사본 **712,508회**, foreign client 거부 **664,715회**,
허용된 unload 종료 응답 768회를 확인했다. foreign client의 성공은 0회였다.
복제·조회·닫기는 2,143회 수행했다. 새 ARM 이후 실제 제출된 후속 READ 44건 중
43건은 정상 취소(995/0 bytes), 1건은 성공(4096 bytes/내용 일치)이었다.
race의 다른 ARM 시도는 busy 또는 filter 종료 응답으로 분류했다.

전체 344개 최종 장부의 합계:

| 장부 | 합계 |
| --- | ---: |
| QueryStarted = QueryCompleted | 1,230,815 |
| QueryGateEntered = QueryGateCompleted | 558 |
| QueryDenied | 1,136,066 |
| QueryReplyFailures | 330 |
| Created = LogicalCompleted = Freed | 1,155 |
| PreQueued = PreCompleted | 602 |
| PostQueued = PostCompleted | 80 |
| PreCancelled / PostDrained | 447 / 205 |
| InstanceStarts = InstanceCompletes | 865 |

330개 응답 실패에는 일반 버퍼 음성 대조군과 실패 감독 중 의도한 변경/프로세스 종료가
포함된다. 정상 복합 경합에서는 기대한 fault 수와 장부를 건별로 일치시켰다.
모든 장부에서 `QueryActive`, `LiveContexts`, `ActiveWorkers`, `WorkerAlive`,
`QueueDepth`, `LiveInstances`, `Connections`, `OwnerPid`, `ArmedMode`,
`ArmedRemaining`, `ArmedGeneration`, `Violations`가 0이었다.

갑작스러운 runner 종료 5회는 exit 86과 실제 진행 중 조회 기록을 확인했다.
감독 프로세스가 5회 모두 서비스를 회수했고 각 Job의 active process 수는 0이었다.
일반 예외 45회는 runner가 직접 정리를 끝내서 supervisor recovery가 필요하지 않았다.
추가로 recovery 감사 자체에 예외를 넣었을 때 서비스 삭제는 완료하면서 recovery
결과가 `passed=false`로 남는 것도 확인했다(`recovery-report-check`).

## 호스트 감사와 재현

검증 구간은 **2026-10-25 21:02:49.529 ~ 21:25:51.464 KST**다.
Windows build는 `28000.3231`, 부팅 시각은 전후 모두 `09:30:03.500 KST`였다.
해당 구간의 새 System 41/1001, 자체 프로그램 Application 1000/1001, 새 minidump는
없었다. 기존 dump 2개는 보존했다. 최종 자체 driver/service/process는 모두 없었다.
원시 결과는 `host-audit.json`, 종료값 0은 `host-audit.exit`에서 확인할 수 있다.

사용한 fixture SHA-256은 아래와 같으며, 작업 전후 동일하다.

```text
327c851a5abd5a7eff3d3bc08e75f4b20ac7487eef9ac0677699ac3060e3ae00
```

변경한 Python 실행기 3개는 `py_compile`, 변경 파일은 `git diff --check`를 통과했다.
커널 바이너리를 다시 빌드하거나 실행 중 교체하지 않았다.

관리자 콘솔에서 각 명령을 순서대로 실행한다. output은 존재하지 않는 경로여야 한다.

```powershell
python tools/run-pending-query-e2e.py --output .build/query-fault-new --case races --iterations 24 --readers 8 --last-close --reply-change mixed
python tools/run-pending-query-failure-e2e.py --output .build/query-failure-new --iterations 3 --readers 8
```

시험은 해당 호스트와 위 일정에서 관측한 결과다. 임의의 모든 스케줄이나 하드웨어에서
경합이 없다는 증명으로 해석하지 않는다. 실패 주입을 직접 runner에 실행하는 것보다
별도 감독 실행기를 사용해야 갑작스러운 종료 뒤 서비스까지 회수할 수 있다.
