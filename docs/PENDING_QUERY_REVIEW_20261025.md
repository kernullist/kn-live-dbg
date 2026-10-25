# 2026-10-25 7a210fa 동시 조회·포트 수명 리뷰

기준 커밋은 `7a210fa`다. QUERY가 `g_Control` 없이 상태 사본을 반환하는 경로를
동시 조회, 포트 복제·닫기, 소유자 강제 종료, 새 ARM, 인스턴스 재연결, 언로드와
함께 검토했다. 원시 증거는 `C:\git\kn-live-dbg\.build\pending-query-20261025`에 보존한다.

## 수명 검토

클라이언트 검색, 호출 PID 확인, 상태 복사가 모두 `g_Lock` 안에서 끝나고 이후에는
지역 상태 사본만 사용한다. `Client*`나 `PFLT_PORT`를 응답 경로로 가져가지 않는다.
Disconnect도 같은 lock 아래에서 client 항목을 비운다. 종료된 client의 배열 위치를
새 연결이 재사용하더라도 응답 직전의 조회가 그 항목을 다시 역참조하지 않는다.
변경 요청, owner lease 해제와 stop은 기존 control mutex로 직렬화된다.

조회 응답은 사본을 만든 시점의 상태다. 응답 전 owner 해제, 새 ARM, 재연결이
끝났다면 과거 예약 수/세대가 반환될 수 있다. 이 응답을 현재 상태로 간주하거나
조회가 새 ARM을 되돌렸다고 해석하면 안 된다. 시험은 사본의 과거 세대와 새 예약의
현재 세대를 각각 확인하고, 새 대상의 실제 READ 내용까지 대조한다.

사용자 응답 버퍼는 잠기지 않은 포인터다. 응답 직전에 버퍼가 사라지거나 보호가
바뀔 수 있으므로, `ProbeForWrite` 성공 뒤에도 복사 자체의 예외 처리가 필요하다.
기존 경로는 이를 지키며 조회 실패로 owner를 해제하지 않는다.
[MessageNotifyCallback 계약](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nc-fltkernel-pflt_message_notify)을 다시 대조했다.

포트 핸들 복제는 새 연결을 만드는 동작이 아니다. 원본만 닫아도 복제 핸들이 같은
client를 유지할 수 있다. 반면 다른 프로세스가 복제 포트로 호출하는 QUERY는 기존
호출 PID 검사로 거부돼야 한다. owner 종료 알림은 이런 복제 핸들이 남아 있어도
lease를 해제해야 한다. 마지막 닫기와 언로드 중 callback 수명은 FltMgr가 소유한다.
[DuplicateHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle),
[FltCloseClientPort](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltcloseclientport),
[FltUnregisterFilter](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltunregisterfilter)의 계약과 실제 동작을 함께 확인한다.

이번 검토에서 `7a210fa` QUERY의 추가적인 커널 수명 결함은 재현하지 못했다.
커널 변경은 짧은 응답 구간의 시험 가능성과 최종 조회 장부를 보강하는 내용이다.

## 계측과 응답 검증

자체 관리자/SYSTEM 시험 포트에 `QUERY_RACE`(Action 6)를 추가했다. mode, target PID,
reserved는 0이어야 하고 delay는 50~500ms만 허용한다. 호출자 확인과 상태 복사가 끝난
뒤, 사용자 버퍼에 쓰기 전에 lock 없이 기다린다. 일반 QUERY에는 이 지연이 없다.
다른 프로세스의 복제 포트 호출은 gate에 진입하기 전에 거부한다.

프로토콜은 v7, 요청은 32 bytes, 응답은 528 bytes다. 다음 계수를 추가했다.

- `QueryStarted`, `QueryCompleted`, `QueryActive`: 허용된 조회의 진입/완료/진행 수.
- `QueryDenied`: client/PID 검사에서 거부한 조회 수.
- `QueryGateEntered`, `QueryGateCompleted`: 응답 직전 시험 구간의 진입/완료 수.
- `QueryReplyFailures`: 사본 확보 후 실제 응답 복사에서 발생한 예외 수.

실시간 사본은 자신을 반환하는 조회도 포함한다. 따라서 정상 유휴 조회에서도
`QueryActive=1`일 수 있다. 사본 내에서는 항상
`QueryStarted = QueryCompleted + QueryActive`를 확인하고, `FltUnregisterFilter` 뒤의
최종 장부에서만 `QueryActive=0`, 진입/완료 일치를 요구한다. 계수는 rundown을
대체하는 장치가 아니며, 실제 callback 종료는 등록 소유자인 FltMgr가 처리한다.

기존 pending 시험의 최종 장부 검사도 이 규칙을 사용한다. 잘못된 버전, QUERY_RACE의
mode/PID/reserved와 지연 범위 거부 검사를 추가했고, 정상 경로와 응답 예외 경로 모두
조회 완료 계수를 갱신한다.

## 실제 시험

새 `tools/run-pending-query-e2e.py`는 다음을 실행한다.

| 조건 | 확인 내용 |
| --- | --- |
| 동시 조회 | 2/8/16개 호출자. 절반은 정상 client, 절반은 다른 프로세스에서 복제한 client. 정상 사본의 구조·계수·세대 일관성 및 각 조회자의 계수 단조 증가 |
| 복제·닫기 반복 | 유효한 root에서 핸들을 복제하고 조회 후 닫기. 원본 닫기·정상/코드 259 owner 종료·새 owner/ARM·재연결·언로드와 동시 수행 |
| 응답 지연 중 상태 변경 | 오래된 사본의 예약 8/이전 세대와 새 ARM의 예약 2/새 세대를 구분하고 새 READ 4096 bytes 내용 검증 |
| 원본/마지막 닫기 | 복제본이 유지한 lease와 마지막 닫기로 해제되는 lease를 구분. 진행 중 Message와 마지막 닫기·언로드를 겹침 |
| 응답 버퍼 변동 | 사본 확보 후 PAGE_NOACCESS 또는 VirtualFree. 응답 998/전송 길이 0, owner/ARM 유지, 최종 조회 정리 |
| owner의 진행 중 QUERY 강제 종료 | gate 진입 뒤 코드 259로 종료. 외부 복제 포트는 계속 거부하고 owner/예약 정리 확인 |
| 복합 경합 | 같은 포트의 2~4개 지연 QUERY, 선택적으로 owner의 지연 QUERY, 정상/거부 조회 작업자와 복제·닫기·강제 종료·새 ARM·재연결·언로드 6개 actor |
| 마지막 핸들 경합 | 모든 지연 QUERY의 kernel 진입을 관측한 뒤 원본과 마지막 복제 root의 닫기를 시작. CloseHandle 반환을 기다리지 않고 unload를 겹침 |

복제 source의 핸들 값 재사용 문제를 시험기 오류로 만들지 않도록, 복제 작업자가
소유한 root는 그 작업자의 마지막 DuplicateHandle 뒤에만 닫는다. 진행 중 조회의
핸들을 닫는 시험은 해당 호출의 kernel 진입을 먼저 확인하고 같은 값으로 다시 요청을
보내지 않는다. actor 시작 시각은 API의 kernel 선형화 시점이라고 해석하지 않는다.

## 발견해 수정한 실행기 문제

초기 `query-races` 반복에서 unload가 복제 actor보다 먼저 실행돼 그 actor의 조회
표본이 0개인 경우가 발생했다. 실행기는 작은 시간차만으로 복제 조회가 먼저 진행될
것이라 가정하고 `queries > 0`을 요구했다. 이후 정리는 이미 성공한 unload를 다시
호출해 filter-not-found로 중단됐고 정지 상태의 자체 서비스가 남았다.

실패 당시 등록 해제 후 장부를 별도로 읽어 `failed-unload-audit.json`에 보존했다.
`QueryStarted=QueryCompleted=2,297`, `QueryActive=0`, gate 진입/완료 각각 5,
`Connections=Created=Freed=Violations=0`이었다. 커널 콜백 잔존의 증거는 없었다.
서비스의 정지 상태와 실행 파일 경로, 실제 필터 부재를 확인한 뒤 해당 서비스만
제거했다. 경로 확인은 Windows가 반환한 NT 경로 접두사를 정규화해 수행했다.

복제 조회·닫기 한 회를 실제로 관측한 event를 unload가 기다리도록 고쳤다.
마지막 핸들 시험은 두 닫기 작업이 진행 중 QUERY를 관측한 뒤 시작했음도 확인한다.
unload 성공 즉시 실행기의 loaded 상태를 갱신하고, 다른 actor의 검증 실패 전에도
callback 장부와 actor 결과를 기록하도록 바꿨다. 실패 증거 폴더는 덮어쓰지 않는다.

## 반복 결과와 호스트 감사

Windows `28000.3231`, x64 Release 시험 서명 빌드에서 실행했다. 컴파일 경고 없이
빌드했고, 모든 본검증은 같은 fixture SHA-256을 사용했다.

| 실행 폴더 | 조건 | 통과 항목 | 최종 unload 장부 |
| --- | --- | ---: | ---: |
| `query-main` | 전체, 호출자 8, 12회 | 267 | 132 |
| `query-readers2` | 전체, 호출자 2, 4회 | 91 | 44 |
| `query-readers16` | 전체, 호출자 16, 4회 | 91 | 44 |
| `query-races-fixed` | 실행기 수정 후 복합 경합, 32회 × 2조건 | 131 | 64 |
| `last-close-main` | 마지막 핸들 경합, 호출자 8, 16회 × 2조건 | 67 | 32 |
| `last-close-readers2` | 마지막 핸들 경합, 호출자 2, 4회 × 2조건 | 19 | 8 |
| `last-close-readers16` | 마지막 핸들 경합, 호출자 16, 4회 × 2조건 | 19 | 8 |
| `watch-regression` | 기존 대상 감시 전체, 2회 | 179 | 42 |
| `rearm-regression` | 기존 ARM/종료 전체, 제출 2/8, 2회 | 95 | 40 |
| `partial-regression` | 부분 배치 전체, 제출 7/8, 2회 | 77 | 30 |
| `multiread-regression` | 다중 READ 전체, 2회 | 57 | 18 |
| `legacy-races` | 기존 identity/취소/종료 경합, 2회 | 33 | 14 |
| `pending-regression` | CREATE/pending, cycles 8 | 148 | 25 |
| `read-regression` | READ 전용, cycles 8 | 24 | 1 |
| `managed-regression` | 관리 콜백 cycles 60 + concurrent close | 93 | 별도 상태 검사 |
| **합계** | | **1,391** | **502** |

집중 대조군 160개, 복합 경합 **152회**가 통과했다. 복합 경합 중 48회는 마지막
사용자 핸들 닫기를 포함한다. 조회 작업자가 검사한 정상 사본은 **1,392,945회**,
타 프로세스 복제 포트의 권한 거부는 **1,295,403회**이며 해당 포트의 허용 응답은
0회다. 별도 복제·조회·닫기 반복은 6,797회였다. 언로드 중 조회 작업자의 연결 종료
응답 1,358회는 정상 종료 결과로 구분했다.

경합 중 새 ARM 76회가 성공해 실제 READ를 제출했다. 그중 74회는 취소 995/전송
0 bytes, 2회는 정상 4096 bytes 및 내용 일치로 끝났다. 나머지 ARM 시도는 busy 재시도
또는 unload 중 거부로 끝났으며, 성공한 ARM과 합치지 않았다. 인스턴스 재연결은
145회 성공했고 7회는 unload가 끝나 filter-not-found로 거부됐다.

502개 장부의 합계는 다음과 같다. 각 장부의 잔존 상태도 개별 검사했다.

- `QueryStarted = QueryCompleted = 1,404,603`, 모든 `QueryActive=0`.
- QUERY gate 진입/완료 각각 812회. `QueryReplyFailures=40`은 PAGE_NOACCESS/VirtualFree
  대조군 각 20회의 의도한 예외와 일치한다.
- `Created = Freed = LogicalCompleted = 1,339`.
- `PreQueued = PreCompleted = 719`, `PostQueued = PostCompleted = 128`.
- `InstanceStarts = InstanceCompletes = 1,307`.
- 모든 장부에서 context, worker, queue, instance, connection, owner, ARM 예약/세대,
  violation이 0. 언로드 뒤 기존 포트 요청도 거부됐다.

관리 콜백 시험의 4개 I/O 작업자는 총 139,198회를 오류 없이 완료했다.
원본 `7a210fa`의 8개 동시 호출자·4회 기준 시험은 11항목을 통과했다. 기준 시험,
초기 smoke 30항목, 실패한 `query-races`의 부분 결과는 위 본검증 합계에서 제외한다.

실패 정리의 별도 회귀 시험 `cleanup-injection`은 unload 성공 직후 의도적으로
단언을 실패시켰다. 프로그램 exit 1과 `passed=false`가 예상 결과이며, 실제로
`cleanup_errors=[]`, 필터 부재, 서비스 조회 1060을 확인했다.
`verify-failure-cleanup.exit=0`으로 이 음성 대조의 검증 성공을 기록했다. 이 결과도
정상 기능 통과 항목 합계에 섞지 않았다.

| 바이너리 | SHA-256 | 보존 폴더 |
| --- | --- | --- |
| 원본 `7a210fa` | `e1e14380b6410009def8cb690f80fbce25b90099302d8f58c8a175c0cdc55fbf` | `baseline-artifacts/` |
| 최종 QUERY 계측/본검증 | `327c851a5abd5a7eff3d3bc08e75f4b20ac7487eef9ac0677699ac3060e3ae00` | `final-artifacts/` |

각 폴더의 `.sys`/`.pdb`, 실행 인자와 seed가 있는 `matrix.ps1`, `matrix-continue.ps1`,
`last-close-continue.ps1`, `verify-failure-cleanup.ps1`, 각 실행의 JSON/JSONL 및 최종
`summary.json`을 보존했다. 공유 서비스명 때문에 모든 실행은 순차로 진행한다.

```powershell
python tools/run-pending-query-e2e.py --output .build/pending-query/new-all --case all --readers 8 --iterations 4 --seed 251101
python tools/run-pending-query-e2e.py --output .build/pending-query/new-last --case races --last-close --readers 8 --iterations 8 --seed 251151
```

검증 시작은 `2026-10-25 19:49:51.657 +09:00`, 최종 호스트 감사는
`20:20:21.533 +09:00`다. `host-audit.json`, `host-audit.exit=0`에서 다음을 확인했다.

- 부팅 시각 `09:30:03.500 +09:00` 유지. 이번 검증 중 재부팅 없음.
- 검증 시작 뒤 System 41/1001, 자체 프로그램 Application 1000/1001, 신규 dump 없음.
- 자체 필터/컨트롤러 드라이버·서비스와 시험 프로세스 잔존 없음.
- 기존 dump 2개(706,334 bytes, 602,892 bytes)는 보존. 과거
  `09:29:45.455 / 0x1A_4477` fixture 사고를 이번 검증의 사고로 집계하지 않았다.

변경한 실행기 문법 검사와 `git diff --check`도 통과했다. 이 결과는 위 Windows 빌드와
자체 fixture의 명시한 조건에서 얻은 반복 관측이다.
