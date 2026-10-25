# 2026-10-25 pending I/O 경합 재현과 수정

기준 커밋은 `6232188`이다. 자체 minifilter fixture의 두 결함을 수정 전 바이너리에서
각각 재현했다. 검증 환경은 Windows x64 `28000.3231`이다.
원시 증거는 `C:\git\kn-live-dbg\.build\pending-race-20261025`에 보존한다.
수정 전 재현에는 아래 gate와 계수만 추가한 계측 바이너리를 사용했다.
그 SHA-256은 `819b91c89a9620892b59af30678aea219703ef1200c8b9cf1b7cbb50a28862d6`이며,
두 짝짓기/소유자 검사는 재현이 끝난 뒤 추가했다.

## 소유자 종료 뒤 새 pending 생성

상위 인스턴스가 READ의 completion context를 등록한 뒤, 하위 pre에 도달하기 전에
소유자 프로세스를 종료하면 기존 `ReleaseOwner`는 상위 context만 깨웠다.
하위 pre는 상위 context에 남은 옛 owner를 복사해 깨우지 않은 새 context를 만들었다.
따라서 소유자 종료 처리가 끝난 뒤에도 새로운 READ가 2초 동안 보류됐다.

`repro-stale`에서 소유자 PID가 이미 0인 상태를 확인했지만, 이후 `Created=2`,
`PreQueued=1`이 됐고 READ는 2,507.367ms 뒤 완료됐다. 이 시간에는 재현을 위한
상위 pre의 500ms 정지도 포함된다. 정리와 언로드 장부는 정상으로 회수됐으나
해당 회귀 검사는 실패로 기록했다.

하위 pre가 새 context를 만들기 전에 상위 context의 owner가 현재 owner와 같은지,
종료/취소 신호를 받지 않았는지 확인한다. 확인과 등록을 `ReleaseOwner` 및
process-exit 처리와 같은 spin lock 안에서 수행한다. 이미 취소 순회가 끝났으면
새 pending을 만들지 않고 원래 I/O를 계속 처리한다. 등록이 먼저 이뤄졌으면
기존 종료 순회가 새 context도 깨운다.

## 같은 파일의 다른 READ 오연결

이전 짝짓기는 FileObject와 요청 프로세스만 비교했다. 같은 핸들에서 동시에 발생한
다른 READ도 같은 조건을 만족하므로, 하위 pre에 먼저 도달한 요청이 원래 요청의
상위 context를 차지할 수 있었다.

`repro-identity`는 하나의 파일 핸들에서 같은 offset/length를 읽는 두 스레드를 사용한다.
첫 READ의 상위 pre를 500ms 정지시키고 두 번째 READ를 보냈다. 수정 전에는 두 번째
READ가 잘못 보류돼 400ms 이내 정상 완료 조건을 충족하지 못했고, 실제 하위 pending도
관측됐다. 이 실패 역시 언로드 후 자원을 모두 회수했다.

이제 상위 pre에 들어온 `FLT_CALLBACK_DATA`의 identity도 비교한다.
이 구조체는 [Microsoft 문서상 해당 I/O를 나타낸다](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/ns-fltkernel-_flt_callback_data).
포인터는 비교에만 사용하며, 저장된 주소를 역참조하거나 완료 후 접근하지 않는다.
같은 I/O가 아닌 요청은 상위 context를 소비하지 않고 정상 처리한다.
회귀 검사는 두 번째 READ가 정지 구간 안에서 내용까지 정확하게 완료되는지와,
첫 READ가 이후 원래의 하위 pending 경로를 정상 통과하는지를 각각 확인한다.

## 동시 경합 검사

새 실행기 `tools/run-pending-io-race-e2e.py`는 실제 I/O가 지정 단계에 도달한 것을
커널 계수로 확인한 뒤, 세 actor에서 취소·소유자 강제 종료·FilterUnload를 시작한다.
순서는 seed로 섞고 진입 간격은 0/2/4ms로 둔다. 요청자는 번갈아 생존/강제 종료시키고,
생존 회차에는 소유자 포트의 복제 핸들도 남겨 process-exit 복구를 함께 검사한다.

- 단계: CREATE pre, CREATE post, CREATE 양쪽의 pre/post, 두 인스턴스 READ pre.
- 재현 gate는 자체 관리자/SYSTEM 포트의 별도 action으로만 활성화하며 50~500ms로 제한한다.
  대기 중 lock을 보유하지 않는다. 일반 ARM은 gate를 사용하지 않는다.
- pending 프로토콜만 v2로 변경했다. 요청은 32 bytes, 상태는 256 bytes이며
  이전 ABI, 범위 밖 지연, 잘못된 단계 조합을 거부한다. managed ABI는 그대로다.
- READ 취소는 원래 I/O 프로세스에서 `CancelIoEx`와 해당 요청의 OVERLAPPED를 사용한다.
  각 READ는 별도의 버퍼·OVERLAPPED·완료 event를 보유한다. 완료를 확인하기 전에는 해제하지 않는다.
  [CancelIoEx 계약](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelioex).
- CREATE에는 `CancelSynchronousIo`를 사용한다. 취소 시도와 I/O 결과를 별도로 기록하며,
  이미 완료된 요청의 `ERROR_NOT_FOUND`를 취소 성공으로 집계하지 않는다.
- 커널의 실제 gate 진입/종료, 취소 표식, stopping 관측과 사용자 호출 시각을 함께 검사한다.
  소유자 종료가 언로드 반환 전에 끝나야 한다. 생존 요청자는 실제 취소 API 진입도 확인한다.
  post에서는 이미 나온 하위 결과를 유지하므로 취소 시도가 항상 I/O 취소 결과를 뜻하지 않는다.
- 언로드 후에는 이전 제어 포트의 단절, 작업자·큐·context·instance·owner·연결·arm의 0,
  생성/논리 완료/해제 일치, pre/post 완료 수 일치와 `Violations=0`을 확인한다.
  새 로드 전 이전 최종 장부를 지워 오래된 결과를 재사용하지 않는다.

초기 `fixed-races-seed1`은 검사기의 지나친 반환 순서 조건 때문에 실패했다.
`race-3-1-pre`의 커널은 취소와 stopping을 모두 관측했고 모든 자원도 회수했지만,
취소 API 반환 기록이 언로드 반환보다 0.554ms 늦었다. 사용자 스레드 반환 시각은
스케줄링 영향을 받으므로, 실제 API 진입 시각과 커널 취소 관측으로 검사기를 수정했다.
이 실패 실행은 최종 성공 합계에서 제외하고 원시 자료를 보존했다.

gate 없는 첫 실행에서는 강제 종료와 명령 쓰기가 경합한 뒤 Python stdin을 닫으면서
`EINVAL`이 다시 발생하는 검사기 정리 결함도 확인했다. 종료된 자식의 stdin이며
실제로 스트림이 닫혔을 때만 `EINVAL`/`EPIPE`를 허용한다. 다른 정리 오류는 계속 실패시키고,
정상 종료 요청에는 자식의 종료 코드 0도 확인한다. 해당 초기 실행도 성공 합계에서 제외한다.

## 수정 후 결과

Release fixture 빌드와 테스트서명 로드가 성공했다. 아래 성공 실행은 모두 fixture
SHA-256 `39b08d114a33e98771839ec8c0d8eb7922616ef4420d8f966ffada661f459f54`를 사용했다.
최종 `.sys`와 `.pdb`는 원시 증거 폴더의 `artifacts/`에도 보존했다.
`verified-results.json`은 각 실행의 종료 코드·결과·개별 단언과 언로드 장부를 교차 확인한 집계다.

| 검사 | 결과 |
| --- | --- |
| 두 결함 회귀 smoke / 반복 | 8/8, 63/63. 결함별 13회씩 통과 |
| 소유자 종료 후 READ | `Created=1`, `PreQueued=0`, 거부 계수 1. 중앙값 510.005ms, 최대 526.939ms. 재현용 500ms 정지를 포함하며 추가 2초 pending은 제거됨 |
| 같은 핸들의 별도 READ | 13회 모두 정상 내용, 중앙값 0.203ms, 최대 0.358ms. 원래 READ의 pending/완료도 유지 |
| 동시 경합 smoke | 10회, 23/23 |
| 동시 경합 seed 20261025 / 71025 | 각 60회, 각 123/123. 두 실행 51.921초 / 54.250초 |
| 전체 gate 경합 | 130회. 세 actor의 6가지 순서를 모두 관측. 커널 gate 시작/완료, 취소 표식, stopping 관측 각각 130회 |
| 생존 요청자 대조 | gate 경합의 65회. 실제 취소 API 호출 성공 65회이며 완료 결과는 별도로 확인 |
| 일반 ARM, gate 없음 | 20회, 43/43. 7.890초. 완료가 먼저 이길 수 있어 gate와 같은 겹침을 요구하지 않음 |
| 기존 pending 전체 회귀 | 160/160, 14.000초. 정상/강제 종료, 취소, 직접/서비스 언로드, 주입 오류, 즉시 pre/post 완료 포함 |
| READ 집중 회귀 | 32/32, 1.297초 |
| managed 콜백 회귀 | 93/93. 등록 포인터 불변, 자동 복구, 복제 핸들, rundown 중 종료, 진입 전 언로드, 동시 파일 I/O와 최종 정리 포함 |
| 성공 실행의 단언 합계 | 668/668 |
| pending 언로드 최종 장부 | 202개 모두 통과, 작업자·큐·context·instance·연결·owner·arm 잔존 0 |
| context 수명 | 생성 = 논리 완료 = 해제 = 486, Violations=0 |
| pending 완료 | pre 340/340, post 232/232. draining post 15회 |
| READ 버퍼 | MDL 고정 70회, 고정 실패 주입 2회. 기존 오류 완료/내용 검증 통과 |

호스트 최종 감사 시각은 `2026-10-25 12:48:24 KST`다. 이번 검사 구간
`12:07:04~12:48:24 KST`에 System 41/1001, 우리 프로그램의 Application 1000/1001,
새 minidump가 없었다. 부팅 시각은 `09:30:03.500 KST` 그대로이며 우리 드라이버와
테스트 프로세스도 남지 않았다. 언로드 후 이전 제어 포트의 단절과 등록 해제를 확인했다.
이 결과는 이번 검사 중 추가 재부팅/콜백 잔존을 관측하지 않았다는 의미다.
이전 `09:29:45.455 KST`의 fixture BSOD와 두 기존 dump는 보존했으며,
[이전 crash 분석](PENDING_IO_LIFETIME_VALIDATION_20261025.md)을 대체하지 않는다.
상세 호스트 자료는 `host-audit.json`에 있다.

managed 회귀에 사용한 기존 `KnLiveDbg.exe`의 SHA-256은
`9d21f5cd6f8205b3a353c19a01c2da321fa5f4f04008b36456161b471bd80dec`다.

## 재실행

승격된 셸에서 fixture 서비스가 없는 상태로 빌드 후 순차 실행한다.
출력 폴더는 매 실행마다 새 경로를 지정한다.

```powershell
.\tools\build.ps1 -Configuration Release
python .\tools\run-pending-io-race-e2e.py --output .build\pending-race\regressions --case regressions --iterations 12
python .\tools\run-pending-io-race-e2e.py --output .build\pending-race\seed1 --case races --iterations 12 --seed 20261025
python .\tools\run-pending-io-race-e2e.py --output .build\pending-race\seed2 --case races --iterations 12 --seed 71025
python .\tools\run-pending-io-race-e2e.py --output .build\pending-race\ordinary --case races --iterations 4 --ungated
python .\tools\run-pending-io-e2e.py --output .build\pending-race\full --cycles 12
python .\tools\run-pending-io-e2e.py --output .build\pending-race\read --cycles 12 --read-only
```

기존 MDL 고정, 작업자의 별도 참조, 단일 완료 책임, 작업자 종료 join,
process notification 및 FltMgr 등록 해제 규칙을 유지한다. 검증은 자체 fixture의
해당 경로와 이 호스트에 한정하며, 임의 외부 필터의 수명 안전성을 보장하지 않는다.
