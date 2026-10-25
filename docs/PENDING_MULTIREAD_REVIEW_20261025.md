# 2026-10-25 f2202d7 다중 READ·인스턴스 분리 경합 리뷰

기준 커밋은 `f2202d7`이다. 검토 범위는 자체 minifilter fixture의 READ 짝짓기,
소유자/요청자 수명, pre/post context 해제, 취소, 인스턴스 분리와 언로드다.
원시 증거는 `C:\git\kn-live-dbg\.build\pending-multiread-20261025`에 보존한다.

## 검토와 검증 범위 확장

기존 실행기는 한 번에 하나의 I/O만 보류했다. 두 READ의 오연결과 한 pending의
종료/언로드는 검사했지만, 여러 pending과 상·하위 인스턴스의 동시 분리는 다루지 않았다.
이번 변경은 이 검증 공백을 메운다.

- `f2202d7`의 callback-data identity 및 live-owner 검사는 같은 spin lock 안에 유지된다.
  다른 READ는 상위 context를 소비하지 않으며, 소유자 해제 후 하위 context를 새로 만들지 않는다.
- 논리적 pre/post 참조와 작업자 참조를 분리하는 기존 규칙을 검토했다. 즉시 post 완료,
  상위 draining, 하위 pending, 취소와 언로드 모두 완료 책임을 중복시키지 않아야 한다.
  최종 참조를 놓는 중에도 목록 삭제와 해제 순서를 유지하고, 완료한 CallbackData를 다시 읽지 않는다.
- READ의 MDL 고정은 각 요청의 큐 등록 전에 수행한다. 각 context는 별도의 instance/process
  참조를 보유하고, 언로드는 작업자 종료를 기다린 뒤 FltMgr 등록을 해제한다.
- 인스턴스 분리의 실제 시작/종료와 원인을 계수한다. 분리 시작 뒤 신규 보류를 막고 기존
  pending을 끝내야 한다는 [Microsoft teardown 계약](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nc-fltkernel-pflt_instance_teardown_callback)을 기준으로 검사한다.

자체 관리자/SYSTEM 포트에 `ARM_READ_BATCH` 시험 action을 추가했다. 지정한 프로세스의
READ 2~8개만 선점하며, 첫 작업자만 50~500ms 정지시켜 뒤의 요청이 큐에 쌓이게 한다.
이후 요청마다 시험 지연을 반복하지 않는다. 일반 ARM은 기존처럼 한 요청만 선점한다.

arm은 요청자 참조 하나를 보유한다. 마지막 선점 전까지 각 요청은 별도 참조를 얻고,
마지막 요청이 arm의 참조를 넘겨받는다. 소유자/요청자 종료는 미사용 예약을 0으로 만들고
arm의 참조를 해제한다. 이미 등록한 요청은 기존의 단일 완료 경로로 정리한다.
프로토콜은 v3, 요청 32 bytes, 상태 320 bytes다. 이전 버전·잘못된 개수·단계·지연을 거부한다.
managed 콜백 프로토콜은 변경하지 않았다.

## 대조군과 경합 구성

새 실행기 `tools/run-pending-multiread-e2e.py`는 하나의 파일 핸들에서 최대 16개 스레드를
사용한다. READ마다 별도의 버퍼, OVERLAPPED와 완료 event가 있다. 네 offset에 다른 내용을
두고 같은 offset/length의 요청도 섞어, 요청별 완료·취소와 4096 bytes 전체 내용을 확인한다.

대조군은 다음 조건을 독립적으로 확인한다.

1. 8개 READ를 실제 보류하고 추가 8개 READ가 정상 완료되는 동안 한 요청만 취소한다.
   지정한 요청만 995로 끝나고 같은 핸들의 나머지 요청은 정확한 내용으로 완료돼야 한다.
2. 절반만 제출한 뒤 소유자를 정상/강제 종료한다. 제출한 요청은 취소되고 남은 예약은
   사라져야 하며, 다음 일반 READ가 예전 예약에 걸리면 안 된다.
3. 절반만 제출한 뒤 요청자를 강제 종료한다. 소유자는 살아 있는 상태에서 새 프로세스를
   지정할 수 있어야 하며 이전 요청자/예약이 새 ARM을 막으면 안 된다.
4. 상위 인스턴스를 분리해 상위 context 8개가 draining으로 해제되는 동안 하위 pending
   8개가 남아 있음을 관측한다. 그 뒤 하위 READ를 정상 완료하고 재연결을 확인한다.
5. 하위 인스턴스를 분리하면 보류된 READ가 취소되고 양쪽 context가 모두 정리돼야 한다.
   재연결 후에는 정상 READ가 가능해야 한다.

경합은 두 단계에서 실행한다. 첫 단계는 READ 8개/상·하위 context 16개가 실제 큐에
남은 상태다. 두 번째 단계는 상위 pre가 하위에 도착하기 전이며, 같은 핸들의 별도 READ
15개가 상위 context를 오연결하지 않고 완료되는지 먼저 확인한다.

각 단계에서 취소, 소유자 강제 종료, 상위 분리, 하위 분리, 언로드의 다섯 actor를
0/2/4/6/8ms 간격의 섞인 순서로 실행한다. 요청자는 번갈아 생존/강제 종료시키고,
생존 회차에는 소유자 포트의 복제 핸들도 유지한다. 다음 두 방식을 모두 사용한다.

- 수동 분리 우선: 실제 `ManualTeardowns > 0`, `Stopping=0`, gate 미완료를 관측한 뒤
  언로드 actor를 허용한다. 단순 API 호출 시도만 분리와 I/O의 겹침으로 인정하지 않는다.
- 자유 순서: 다섯 actor를 함께 해제한다. 분리의 lookup은 언로드와 경합하므로
  성공 또는 Windows SDK에 정의된 deleting-object/filter-not-found/instance-not-found만 허용한다.
  다른 오류는 실패시킨다. [FilterDetach](https://learn.microsoft.com/en-us/windows/win32/api/fltuser/nf-fltuser-filterdetach),
  [FltDetachVolume의 반환 상태](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltdetachvolume).

각 호출의 시작/종료, READ 결과, 실제 커널 관측값을 남긴다. 모든 native lifecycle 호출은
하나의 프로세스 토큰을 공유하므로 전체 actor 묶음 동안 privilege를 한 번 활성화하고,
모두 끝난 뒤 복구한다. actor마다 활성화/복구하면 다른 actor의 실행 중 privilege를
먼저 제거하는 검사기 경합이 생길 수 있다.

## 초기 검사기 실패

`reads2-smoke`는 커널 자원 장부가 정상인데도 취소 관측 조건에서 실패했다.
두 READ의 사용자 제출 순서와 커널 도착 순서가 달라, 작업자에서 정지한 것은 slot 1이고
명시적으로 취소한 것은 slot 0이었다. 따라서 정상 취소 결과 995와 달리 그 작업자의
`RaceCancelSeen`은 0이었다.

경합 실행은 slot 0의 실제 작업자 정지를 먼저 관측하고 나머지 READ를 섞인 순서로
제출하도록 고쳤다. 선택 취소 대조군은 여러 READ의 자유 도착 순서를 그대로 사용한다.
이 초기 실패는 성공 합계에서 제외하며 원시 장부와 로그를 보존한다.

## 최종 결과

정적 검토와 아래 반복 시험에서 `f2202d7`의 수정에 추가적인 커널 수명 결함은 발견하지
못했다. 변경은 자체 fixture의 다중 READ 시험 모드, teardown 진단, 실행기와 회귀 검사다.
기존 두 짝짓기/소유자 방어 검사는 그대로 유지했다.

Windows x64 `28000.3231`에서 Release fixture 빌드와 테스트서명 로드가 성공했다.
아래 성공 실행은 모두 SHA-256
`51e7d12ca668f0f25c2475158f644a08a88893cb4ee75fbc18cc94757865c103`인 `.sys`를 사용했다.
최종 `.sys`와 `.pdb`는 원시 증거 폴더의 `artifacts/`에 보존했다.

| 실행/검사 | 결과 |
| --- | --- |
| 2개 READ smoke `reads2-ordered` | 49/49, 13.750초 |
| 8개 READ smoke `reads8-smoke` | 49/49, 14.281초 |
| 4개 READ 대조군 `reads4-controls` | 41/41, 9.250초 |
| 8개 READ 전체 반복 `reads8-seed1` | 327/327, 96.047초. seed 20261025 |
| 8개 READ 경합 반복 `reads8-seed2` | 99/99, 41.063초. seed 71025 |
| 기존 두 결함·단일 I/O 경합 `legacy-races` | 63/63, 24.922초 |
| 기존 pending 전체 / READ 집중 회귀 | 160/160, 13.265초 / 32/32, 1.188초 |
| managed 콜백 회귀 | 93/93. 등록 포인터 불변, 자동 복구, rundown, 진입 전 언로드, 동시 파일 I/O와 정리 확인 |
| 전체 단언 | **913/913** |
| 다섯 actor 경합 | 112회. batch pending 56회, 상위 pre 56회. 실제 순서 66가지 관측 |
| 실제 수동 분리 시작 후 언로드 | 56회. gate가 열리기 전 manual 시작 및 Stopping=0 확인 |
| 요청자 강제 종료 | 다섯 actor 경합 중 56회. 다른 56회는 요청자가 살아 있어 결과도 확인 |
| 다섯 actor 경합의 분리 API | 성공 212회, 언로드가 lookup을 먼저 끝낸 FILTER_NOT_FOUND 12회. 다른 오류 없음 |
| 선택 취소 / 상위 draining 대조 | 각각 18회. 특정 요청만 취소되고 다른 READ가 정상 완료됨 |
| 동시에 관측한 최대 상태 | context 16개, 작업자 1개, 큐 7개 |
| 언로드 최종 장부 | 252개 정상. 작업자·큐·context·instance·연결·owner·arm·남은 예약 모두 0 |
| context 수명 합계 | 생성 = 논리 완료 = 해제 = 2,179, Violations=0 |
| pending 완료 합계 | pre 1,137/1,137, post 180/180, draining post 619회 |
| READ 버퍼 | MDL 고정 945회, 고정 실패 주입 2회 |
| 내용 검증 | 원시 결과에서 다시 집계한 정상 READ 1,174건의 내용 일치 |

취소 API의 성공과 실제 I/O 취소는 구별한다. batch 경합의 생존 요청자 28회에서는
명시적 취소 호출이 성공했고, 보류한 READ 212개가 모두 995로 완료됐다. 상위 pre 경합의
생존 요청자 28회에서는 취소 호출이 성공했지만 READ 28개는 정상 완료됐고,
`BeforeLowerCancelSeen`도 0이었다. 이 결과를 I/O 취소 성공으로 집계하지 않는다.
[CancelIoEx 계약](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelioex)은
취소 요청 뒤에도 I/O가 정상 완료될 수 있다고 명시한다. batch 경합은 실제 커널 취소
표식과 stopping을 각각 56회 관측했고, 상위 pre 경합은 stopping 및 teardown을 각각
56회 관측했다.

`verified-results.json`은 종료 코드, 개별 단언, 원시 journal과 최종 장부를 교차 확인한 집계다.
초기 `reads2-smoke` 실패는 위 성공 수에 포함하지 않았다.

최종 호스트 감사는 `2026-10-25 13:18:15 KST`에 수행했다. 검증 구간
`12:58:40~13:18:15 KST`에 새 System 41/1001, 우리 프로그램의 Application 1000/1001,
새 minidump가 없었다. 부팅 시각은 `09:30:03.500 KST` 그대로이며 우리 드라이버/테스트
프로세스도 남지 않았다. 언로드 후 이전 제어 포트는 응답하지 않았다.
이번 범위에서 추가 재부팅이나 콜백 잔존을 관측하지 않았다는 결과다.
이전 `09:29:45.455 KST` crash와 기존 두 dump는 `host-audit.json`에도 기록해 보존했다.

managed 회귀에 사용한 기존 `KnLiveDbg.exe`의 SHA-256은
`9d21f5cd6f8205b3a353c19a01c2da321fa5f4f04008b36456161b471bd80dec`다.

## 재실행

승격된 셸에서 기존 fixture 서비스가 없는 상태로 빌드와 검사를 순차 실행한다.
각 출력 폴더는 새 경로여야 한다.

```powershell
.\tools\build.ps1 -Configuration Release
python .\tools\run-pending-multiread-e2e.py --output .build\multiread\controls --case controls --reads 4 --iterations 2
python .\tools\run-pending-multiread-e2e.py --output .build\multiread\seed1 --reads 8 --iterations 12 --seed 20261025
python .\tools\run-pending-multiread-e2e.py --output .build\multiread\seed2 --case races --reads 8 --iterations 12 --seed 71025
python .\tools\run-pending-io-race-e2e.py --output .build\multiread\legacy --case all --iterations 4
python .\tools\run-pending-io-e2e.py --output .build\multiread\pending --cycles 12
python .\tools\run-pending-io-e2e.py --output .build\multiread\read --cycles 12 --read-only
```

이 검증은 자체 fixture와 해당 Windows 호스트의 시험 범위에 한정한다.
외부 필터의 콜백 포인터 변경이나 그 수명 안전성에 대한 보장으로 일반화하지 않는다.
