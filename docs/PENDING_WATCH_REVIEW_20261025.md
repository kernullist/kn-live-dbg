# 2026-10-25 621d16e 대상 종료 감시 경합 리뷰

기준 커밋은 `621d16e`다. 종료 코드 259인 대상의 종료 신호와 감시 결과를 중심으로,
새 ARM, 같은 요청자의 재ARM, 다른 요청자로 교체, READ 취소, 소유자/요청자 강제 종료,
인스턴스 분리·재연결, 언로드 사이의 수명을 검토했다. 원시 증거는
`C:\git\kn-live-dbg\.build\pending-watch-20261025`에 보존한다.

## 리뷰 결과와 수정

감시 함수는 `g_Control`을 보유한 채 대상 참조를 얻고 종료 상태를 검사한 뒤 예약을
해제한다. 새 ARM, 소유자 해제, 프로세스 종료 알림, stop은 이 mutex로 직렬화된다.
인스턴스 setup/teardown과 READ에 의한 예약 소비는 `g_Lock`으로 진행하므로 감시
도중에도 기존 예약을 없앨 수 있다. 감시가 별도 프로세스 참조를 유지하고, 다시 spin
lock을 얻은 뒤 `g_Target == snapshot`인지 확인하는 기존 규칙이 이를 보호한다.
새 ARM은 감시의 판정 이후에만 발행되므로 같은 대상 객체로 다시 ARM해도 오래된
판정이 새 예약을 해제할 수 없다. 이 수명 규칙의 추가 결함은 이번 검토에서 발견하지
못했다.

다만 QUERY도 `g_Control`을 기다려 감시 구간 자체를 관측할 수 없었다. 기존 QUERY
직렬화를 유지한 계측 빌드에서 감시 snapshot 뒤를 500ms 고정하자 첫 조회는 진입
전 상태를 반환했고, 다음 조회는 **515.2954ms** 걸려 `WatchGateEntered=1`,
`WatchGateCompleted=1`인 종료 후 상태만 반환했다. `query-serialized-repro`의
의도한 단언 실패와 정리 성공을 보존했다. 이는 고정 지연을 주입한 진단 재현이며,
원래 바이너리에서 자연적으로 500ms 지연이 발생했다는 측정은 아니다.

QUERY는 이제 `g_Lock` 안에서 client ID와 호출 PID를 검사하고 상태를 복사한다.
사용자 버퍼 접근은 lock 밖의 예외 처리 구간에서 수행한다. 변경 요청은 기존처럼
`g_Control`로 직렬화한다. 조회가 owner를 획득하거나 해제하는 동작은 추가하지 않았다.
다른 프로세스가 복제된 owner 포트로 QUERY를 보내면 기존처럼 거부되고, 원래 owner와
예약이 유지되는지도 시험한다. 사용자가 제공하는 버퍼의 처리 계약은
[MessageNotifyCallback](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nc-fltkernel-pflt_message_notify)을 따른다.

종료 코드 259는 `STATUS_PENDING`과 같으므로 종료 코드만으로 생존을 판단하지 않는다.
기존 `ProbeTarget`의 zero-time wait와 명시적 `STATUS_TIMEOUT`/`STATUS_SUCCESS`
구분을 유지했다. [GetExitCodeProcess의 259 주의 사항](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getexitcodeprocess)과
[ZwWaitForSingleObject의 반환값](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwwaitforsingleobject)을 다시 대조했다.

## 시험 구간과 프로토콜

자체 관리자/SYSTEM 시험 포트의 `ARM_RACE`, `DRAIN_PAIR`에 두 gate를 추가했다.

| Reserved | 고정하는 구간 | 관측할 위험 |
| --- | --- | --- |
| 16 | 대상 snapshot 참조 확보 후, 종료 상태 검사 전 | 예약 소비/구성 변경, 새 ARM 및 종료와의 직렬화 |
| 32 | 실패한 종료 상태 검사를 얻은 후, 조건부 예약 해제 전 | 구성 변경으로 무효화된 오래된 실패 결과의 폐기 |

50~500ms만 허용하며 다른 mode, 범위 밖 지연, gate 조합은 거부한다. 고정 대기는
기존 control mutex를 그대로 보유하고 spin lock은 놓은 상태다. 일반 ARM에는 이
지연이 없다. 감시 작업자의 별도 프로세스 참조와 stop의 worker join이 시험 구간도
포함한다. 새 스레드나 별도의 I/O 완료 경로를 커널에 추가하지 않았다.

상태에 감시 횟수, 오래된 결과 폐기 수, gate 진입/완료 및 대상 PID·예약 세대·검사
상태를 추가했다. 프로토콜은 v6, 요청은 32 bytes, 응답은 472 bytes다. 모든 pending
시험 실행기는 같은 ctypes ABI를 가져오며, 기존 ABI와 잘못된 요청 거부 검사도
갱신했다. 최종 수명 장부는 두 watch gate의 진입/완료 일치까지 검사한다.

## 검증 구성

`tools/run-pending-watch-e2e.py`는 다음 조건을 실제 자체 필터에서 검증한다.

- QUERY가 watch gate 완료 전에 반환하고, 복제 포트의 다른 호출 PID는 거부된다.
- 종료 통지의 취소 sweep 뒤, 아직 종료 신호가 설정되지 않은 코드 259 대상에 다시
  ARM한다. 실제 프로세스 종료를 기다리고 실패 결과 gate를 관측한다. 이후 감시가
  예약을 회수하거나, 먼저 재연결로 무효화된 결과를 폐기하는지 구분한다.
- 상위/하위 인스턴스 재연결 중 새 ARM을 보낸다. 같은 대상 재ARM도 포함한다.
  ARM이 기존 감시 뒤에 적용되고 새 세대 예약을 보존하며 실제 새 READ가 예상한
  4096 bytes를 읽는지 확인한다. 살아 있는 이전 요청자의 별도 READ는 새 예약을
  소비하지 않아야 한다.
- release, owner 강제 종료, requester 강제 종료, unload가 감시와 직렬화됨을 확인한다.
  owner 포트 복제 핸들을 유지한 종료도 포함한다. 종료 뒤 새 owner/대상으로 ARM하고
  실제 READ 보류와 취소가 다시 작동하는지 확인한다.
- 감시 작업자가 snapshot gate에 있는 동안 READ를 실제 pending 큐에 넣는다.
  `QueueDepth=1`, `ActiveWorkers=0`을 확인한 뒤 같은 FileObject의 다른 READ와
  다른 요청자의 READ가 정상 완료하고, 지정한 원래 READ만 `ERROR_OPERATION_ABORTED`
  (995), 전송 0 bytes로 완료되는지 검사한다.
- 새 ARM, native 취소, 코드 259 강제 종료, 분리·재연결, 늦은 READ, 언로드를 여섯
  actor로 겹친다. owner/requester/both 종료와 상위/하위 인스턴스를 교차한다.
  취소 응답을 받은 뒤 강제 종료하도록 한 의존성은 자식 응답 파이프 소실로 실제
  CancelIoEx 실행을 오인하지 않기 위한 것이다. actor 시작 순서는 커널 API의
  선형화 순서라고 해석하지 않는다.

snapshot gate의 복합 경합은 실제 pending READ를 취소한다. 실패 결과 gate에서는
이전 요청자가 이미 코드 259로 종료했으므로 대체 요청자의 완료된 READ에 대한 취소가
음성 대조군이다. 이때 `ERROR_NOT_FOUND`(1168)를 허용하며 이를 pending 취소 성공으로
집계하지 않는다. 모든 프로세스와 포트, actor는 500ms 시험 구간 전에 준비한다.

언로드는 worker 종료, 프로세스 알림 제거, `FltUnregisterFilter`, 최종 장부 저장
순서다. 알림 제거의 실행 중 콜백 대기는
[PsSetCreateProcessNotifyRoutineEx](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex),
등록 콜백과 context 제거는
[FltUnregisterFilter](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltunregisterfilter)의 계약에 따른다.
서버 포트 닫기만으로 기존 연결이 사라진다고 가정하지 않으며, 언로드 후 기존 포트의
요청 실패와 `Connections=0`도 검사한다.

## 실행과 결과

Windows `28000.3231`, x64 Release 시험 서명 fixture로 실행했다. 아래 두 빌드를
구분한다. 첫 반복 묶음 이후 컴파일러의 C4701 경고가 남은 QUERY 지역 snapshot을
명시적으로 0 초기화했다. 기존 코드는 허용 분기에서 값을 복사하고 거부 분기는 즉시
반환했으며, 이 마지막 변경은 초기화만 보강한다. 실행 중인 시험과 서비스 정리가
끝난 후 다시 빌드했고, 최종 빌드는 컴파일 경고 없이 아래 재검증을 통과했다.

| 묶음 / 실행 폴더 | 조건 | 통과 항목 | 최종 unload 장부 |
| --- | --- | ---: | ---: |
| 선행 `watch-main` | 전체, READ 8, 6회 | 531 | 126 |
| 선행 `watch-reads2` | 전체, READ 2, 3회 | 267 | 63 |
| 선행 `watch-reads4` | 전체, READ 4, 3회 | 267 | 63 |
| 선행 `watch-races` | 감시 복합 경합, 16회 × 6조건 | 291 | 96 |
| 선행 `rearm-regression` | 기존 ARM/종료 전체, 제출 2/8, 4회 | 187 | 80 |
| 선행 `partial-regression` | 부분 배치 전체, 제출 7/8, 3회 | 114 | 45 |
| 선행 `multiread-regression` | 다중 READ 전체, 3회 | 84 | 27 |
| 선행 `legacy-races` | 기존 identity/취소/종료 경합, 3회 | 48 | 21 |
| 선행 `pending-regression` | CREATE/pending, cycles 8 | 148 | 25 |
| 선행 `read-regression` | READ 전용, cycles 8 | 24 | 1 |
| 선행 `managed-regression` | 관리 콜백 cycles 100 + concurrent close | 93 | 별도 상태 검사 |
| **선행 합계** | | **2,054** | **547** |
| 최종 `clean-watch` | 전체, READ 8, 2회 | 179 | 42 |
| 최종 `clean-query` | 조회/복제 포트 권한, 10회 | 43 | 10 |
| 최종 `clean-races` | 감시 복합 경합, 4회 × 6조건 | 75 | 24 |
| 최종 `clean-pending` | CREATE/pending, cycles 4 | 136 | 25 |
| 최종 `clean-read` | READ 전용, cycles 4 | 16 | 1 |
| 최종 `clean-managed` | 관리 콜백 cycles 20 + concurrent close | 93 | 별도 상태 검사 |
| **최종 합계** | | **542** | **102** |

선행 168회와 최종 36회, 합계 **204회**의 감시 복합 경합이 통과했다. 102회는 실제
pending READ의 native 취소, 나머지 102회는 실패 결과 구간의 완료된 READ 취소 대조다.
경합 중 ARM 성공 20회, busy 거부 16회, stopping 거부 32회, owner 종료로 응답을 받지
못한 경우 136회를 구분해 기록했다. 응답 소실을 ARM 실패 또는 성공으로 추정하지 않는다.
재연결은 156회 성공했고 48회는 unload가 먼저 끝나 filter-not-found로 거부됐다.
강제 종료로 자식 응답이 사라진 I/O는 종료 신호와 커널의 최종 장부로 검사하고,
살아 있는 요청자와 정상 완료 대조군은 반환 크기와 데이터 내용도 대조했다.

두 묶음의 649개 pending unload 장부에서 다음을 확인했다.

- `Created = Freed = LogicalCompleted = 2,402`.
- `PreQueued = PreCompleted = 1,276`, `PostQueued = PostCompleted = 206`.
- `InstanceStarts = InstanceCompletes = 1,583`.
- watch gate 진입/완료 각각 424회, 종료 알림 tail 진입/완료 각각 198회.
- 모든 장부에서 context, queue, active worker, worker thread, instance, connection,
  owner, ARM 예약/세대, violation이 0. 언로드 뒤 기존 시험 포트 요청도 실패했다.

활성 watch gate 안에서 완료한 조회는 선행 348표본에서 중앙값 18.0µs/최대 176.3µs,
최종 76표본에서 중앙값 18.95µs/최대 131.3µs였다. 이는 500ms 시험 hold를 기다리지
않고 조회가 가능함을 확인한 측정이며 일반 성능 벤치마크로 해석하지 않는다.
최종 관리 콜백 시험의 4개 I/O 작업자는 총 145,452회를 오류 없이 완료했다.
초기 smoke 117항목과 의도한 QUERY 음성 재현은 위 성공 합계에서 제외했다.

fixture SHA-256:

| 역할 | 해시 | 보존 폴더 |
| --- | --- | --- |
| 원본 `621d16e` | `a3f0af15775c3a54ebaac1fde2cfbd70e8b51cd744bee4ef51cf01f7c3dd4205` | `baseline-artifacts/` |
| 기존 QUERY를 유지한 계측 재현 | `7d9b660312ff6ad114e67d455d264a0f3ea7a3ac63aab6717547ea25284aad83` | `instrumented-artifacts/` |
| 선행 반복 검증 | `4c6fe8a1fcc6f2b92e0b60a69f4b34f3c6695edccda911d167570cb0c0d642ea` | `final-artifacts/` |
| 최종 초기화 경고 정리/재검증 | `e1e14380b6410009def8cb690f80fbce25b90099302d8f58c8a175c0cdc55fbf` | `clean-artifacts/` |

각 빌드의 `.sys`와 `.pdb`, 명령 인자/seed가 들어 있는 `matrix.ps1`, `finish.ps1`,
각 실행의 `result.json`, `checks.json`, `journal.jsonl`, `unload-audits.json`,
`summary.json`, `summary-clean.json`을 증거 디렉터리에 보존했다. 스크립트들은
같은 서비스명을 사용하므로 순차 실행한다. 최종 빌드의 대표 재실행 명령은 다음과 같다.

```powershell
python tools/run-pending-watch-e2e.py --output .build/pending-watch/new-run --case all --reads 8 --iterations 4 --seed 251025
```

## 호스트 최종 감사

검증 시작은 `2026-10-25 18:02:33.261 +09:00`, 최종 감사는 `18:35:35.782 +09:00`다.
`host-audit.json`과 `host-audit.exit=0`에서 확인한 결과:

- 부팅 시각 `09:30:03.500 +09:00` 유지. 이번 검증 중 재부팅 없음.
- 검증 시작 뒤 System 41/1001, 자체 프로그램 Application 1000/1001, 신규 dump 없음.
- 자체 필터/컨트롤러 드라이버·서비스와 시험 프로세스 잔존 없음.
- 기존 `102426-10593-01.dmp`(706,334 bytes), `102526-9609-01.dmp`(602,892 bytes)는 보존.
  과거 `09:29:45.455 / 0x1A_4477` fixture 사고는 이번 결과에 포함하지 않는다.

최종 변경 소스와 시험 실행기 문법 검사, `git diff --check`도 통과했다. 이 결과는 위
Windows 빌드와 자체 fixture의 명시한 조건에서 얻은 반복 관측이다.
