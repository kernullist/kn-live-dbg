# 2026-10-25 73e8947 부분 READ 배치·재연결 경합 리뷰

기준 커밋은 `73e8947`이다. 자체 minifilter fixture에서 READ 배치 일부만 제출한 뒤
취소, 소유자/요청자 강제 종료, 인스턴스 분리·재연결, 언로드가 겹치는 수명을 검토했다.
원시 증거는 `C:\git\kn-live-dbg\.build\pending-partial-20261025`에 보존한다.

## 실제로 재현한 결함

기준 바이너리 SHA-256은
`51e7d12ca668f0f25c2475158f644a08a88893cb4ee75fbc18cc94757865c103`이다.
동일 바이너리와 PDB를 `baseline-artifacts/`에 보존했다.

### 분리·재연결 뒤에 남는 미제출 예약

8개 READ를 예약하고 2개만 제출했다. 상위 또는 하위 인스턴스를 분리해 기존 I/O를
완료한 뒤 같은 인스턴스를 재연결해도 `ArmedRemaining=6`이 남았다. 그 뒤 일반 READ가
이전 예약을 소비하면서 새 context와 pending을 만들고 약 2초 보류됐다.

| 기준 재현 | 재연결 후 예약 | 생성 context / queued pre | 다음 READ 소요 |
| --- | --- | --- | --- |
| `repro-upper` | 6 | 6 / 3 (기대 4 / 2) | 2008.983ms |
| `repro-lower` | 6 | 6 / 3 (기대 4 / 2) | 2011.492ms |

기존 teardown은 해당 인스턴스의 이미 등록한 context만 깨웠다. 아직 제출하지 않은
READ의 전역 arm과 요청자 참조에는 인스턴스 수명 경계가 없었다. 이전 검사에는
부분 배치의 프로세스 종료와 전체 배치의 재연결이 따로 있었지만, 부분 배치의
재연결 조합이 없어서 이 문제가 드러나지 않았다.

### 이전 상위 context와 새 하위 인스턴스의 연결

`repro-pair`에서는 상위 pre를 하위 진입 전에 500ms 정지시킨 동안 하위 인스턴스를
분리·재연결했다. 소유자와 READ identity가 같다는 이유로 이전 상위 context가 새 하위
인스턴스에 연결됐다. 추가 pending 1개가 생겨 READ가 2522.910ms 걸렸다.
미제출 예약은 이미 0이므로 예약 해제만으로는 이 문제를 고칠 수 없다.

세 재현 실행은 의도한 단언 실패로 기록했고, 각각 정리와 언로드는 성공했다.
이 실패들을 수정 후 성공 합계에 포함하지 않는다.

## 수명 경계 수정

인스턴스 구성에 전역 세대 번호를 부여한다. 자체 fixture의 성공한 인스턴스 연결과
분리 시작은 세대를 올리고 아직 소비하지 않은 예약을 해제한다. arm이 갖고 있던
요청자 참조는 spin lock 안에서 한 번만 분리하고 lock 밖에서 놓는다.

상위 context는 선점 당시의 세대를 보존한다. 하위 짝짓기는 READ identity, 살아 있는
소유자, 취소 상태에 더해 현재 세대와의 일치도 확인한다. 따라서 같은 READ여도
이전 구성에서 내려온 상위 context로 새 하위 pending을 만들 수 없다. 이미 선점한
하위 I/O의 context/process/instance 참조와 단일 완료 작업자는 기존 규칙을 유지한다.

새 ARM은 teardown 시작/완료가 불일치하는 동안 BUSY, 인스턴스가 전혀 없으면 NOT_READY로
거부한다. 연결 setup에서도 언로드 stopping을 확인한다. 구성 변경은 소유자 lease를
종료하지 않으므로, 정리가 끝난 뒤 명시적으로 새 ARM을 실행할 수 있다.

이 정책은 fixture 전체에 적용된다. 어느 인스턴스든 연결·분리하면 미사용 예약은
취소된다. 특정 READ 한 건의 native 취소는 구성 변경이 아니므로 같은 세대의 다른
예약을 유지한다. ARM을 상위만 있는 구간에 명시적으로 다시 했더라도 하위를 새로
연결하면 그 예약은 다시 해제된다.

예약 발행·소비·해제와 context 등록은 같은 `g_Lock`을 사용한다. 소유자/요청자 종료와
분리가 동시에 일어나도 arm 참조를 두 번 놓거나, 등록 목록 밖의 context가 취소를
피하는 틈을 만들지 않는다. 언로드는 입장을 닫고 기존 I/O를 깨운 뒤 작업자 종료를
기다리며, FltMgr 등록 해제 후 최종 장부를 기록한다.

프로토콜은 v4, 요청 32 bytes, 상태 368 bytes다. 세대, 예약 세대, 구성 변경 시 해제,
이전 세대 하위 연결 거부, teardown 중 ARM 거부, stopping 중 setup 거부 계수를 추가했다.
기존 pending 실행기도 같은 ABI로 갱신했고 최종 예약 세대 0을 확인한다.

## 반복 검증 방식

새 실행기 `tools/run-pending-partial-e2e.py`는 기존 READ 실행기의 요청별 버퍼,
OVERLAPPED, 완료 event, slot과 전체 내용 검증을 재사용한다. 동일 파일 핸들에서
slot 0의 실제 작업자 gate 진입을 관측한 뒤 다른 READ를 제출한다. 사용자 제출 순서만으로
어떤 READ가 정지했는지 가정하지 않는다.

- 독립 재현: 상위 교체, 하위 교체, 하위 부재 구간에서 새 ARM 후 재연결, 이전 상위와
  새 하위의 연결을 검사한다. 매번 새 ARM이 실제 READ를 보류하는 양성 대조도 수행한다.
- 선택 취소: 한 READ만 CancelIoEx로 취소하고 나머지 미제출 예약이 유효함을 확인한다.
  늦게 제출한 다음 READ가 실제 보류·정상 완료되고 RELEASE 뒤 일반 READ는 보류되지 않아야 한다.
- admission 대조: 실제 하위 teardown 미완료 상태에서 ARM 거부 계수 증가를 확인한다.
  양쪽 인스턴스가 사라진 때도 거부하며, 재연결 후 새 ARM은 성공해야 한다.
- 다섯 actor 경합: 취소, 강제 종료, 분리·재연결, 나머지 READ 제출, 언로드를
  섞인 0/2/4/6/8ms 순서로 실행한다. 소유자만, 요청자만, 양쪽 종료를 각각 검사한다.
  소유자 포트의 복제 핸들을 계속 보유해 원래 프로세스 종료 알림에 의한 정리도 확인한다.
- 재연결 우선 경합에서는 기존 하위 pending이 남고 gate가 열리기 전에 상위 재연결,
  `Stopping=0`, 남은 예약 0을 실제 관측한다. 그 뒤 나머지 READ 제출과 종료/언로드가
  겹친다. 자유 순서에서는 상위 또는 하위 교체 자체가 언로드와 경합한다.

분리 호출은 성공 또는 SDK의 deleting-object/filter-not-found/instance-not-found만,
연결은 성공 또는 deleting-object/filter-not-found만 허용한다. 권한 실패나 다른 오류를
경합 성공으로 처리하지 않는다. 모든 lifecycle actor가 끝날 때까지 공통 프로세스 토큰의
로드 권한을 유지한다.

요청자가 살아 있는 경합에서는 제출한 모든 slot이 정확히 한 번 완료돼야 한다.
기존 pending은 995/0 bytes로 취소되고, 재연결 뒤 새로 제출한 READ는 정확한
4096 bytes로 완료돼야 한다. 요청자를 죽인 회차는 사용자 완료 메시지를 얻을 수 없으므로
커널 장부와 프로세스 종료를 검사한다. 각 회차의 최종 context, 작업자, 큐, instance,
연결, owner, 예약 및 예약 세대는 모두 0이어야 하고, 생성·논리 완료·해제 수가 같아야 한다.

계약 확인에 사용한 문서는 [인스턴스 teardown](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nc-fltkernel-pflt_instance_teardown_callback),
[디버깅용 FilterAttachAtAltitude](https://learn.microsoft.com/en-us/windows/win32/api/fltuser/nf-fltuser-filterattachataltitude),
[CancelIoEx](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelioex)다.
취소 API 성공만으로 I/O 취소를 단정하지 않고 실제 완료 상태와 커널 취소 표식을 구분한다.

## 결과

Windows x64 `28000.3231`에서 Release 빌드와 테스트서명 로드가 성공했다. 아래 성공
실행은 모두 SHA-256
`a11b80d2180fde7a067e65a8dacd336f148752464b10d43750ac402b82c12855`인 fixture를 사용했다.
최종 `.sys`와 `.pdb`는 증거 폴더의 `artifacts/`에 보존했다.

첫 수정 비교 실행 `fixed-regressions-smoke`에서 상위/하위 재연결 후 예약은 모두 0,
생성 context/queued pre는 기대한 4/2였다. 다음 일반 READ는 각각 0.226ms와 0.377ms에
완료됐다. 이전 상위/새 하위 사례는 context 1개, queued pre 0개, 세대 거부 1회로 끝났다.
READ 소요는 513.963ms로 의도한 500ms 시험 gate 외의 2초 pending이 사라졌다.
이 시간은 해당 비교 실행의 측정값이며 일반 성능 보장은 아니다.

| 실행 | 결과 |
| --- | --- |
| 수정 직후 세 재현 `fixed-regressions-smoke` | 12/12, 4.328초 |
| 전체 smoke `partial-all-smoke` | 40/40, 16.344초 |
| 8개 중 1개 제출 `partial-s1` | 151/151, 4회 반복, seed 102501, 60.562초 |
| 8개 중 2개 제출 `partial-s2` | 151/151, 4회 반복, seed 102502, 60.203초 |
| 8개 중 4개 제출 `partial-s4` | 151/151, 4회 반복, seed 102504, 60.407초 |
| 8개 중 7개 제출 `partial-s7` | 151/151, 4회 반복, seed 102507, 62.219초 |
| 2개 중 1개 제출 `partial-reads2` | 77/77, 2회 반복, seed 202502, 32.156초 |
| 4개 중 3개 제출 `partial-reads4` | 77/77, 2회 반복, seed 202504, 34.031초 |
| 기존 다중 READ 회귀 `multiread-regression` | 111/111, 4회 반복, 32.594초 |
| 기존 짝짓기/소유자·단일 I/O 경합 `legacy-races` | 63/63, 4회 반복, 24.437초 |
| pending 전체 / READ 집중 회귀 | 160/160, 13.578초 / 32/32, 1.766초 |
| managed 콜백 회귀 | 93/93. 포인터 유지, 자동 복구, rundown, 정상/강제 종료, 직접/서비스 언로드 검사 |
| 전체 단언 | **1,269/1,269** |

부분 배치의 다섯 actor 경합은 **189회**였다. 재연결 우선, 자유 상위 교체, 자유 하위
교체가 각각 63회이며 소유자만/요청자만/양쪽 강제 종료도 각각 63회다. 실제 호출 시작
순서는 85가지였다. 모든 189회에서 `RaceCancelSeen=RaceStopSeen=1`을 확인했다.
재연결 우선 63회는 기존 I/O가 보류된 상태에서 실제 재연결과 예약 0을 확인했다.

부분 경합의 분리 API는 189회 모두 성공했다. 재연결 API는 성공 90회,
DELETING_OBJECT 37회, FILTER_NOT_FOUND 62회였다. 허용하지 않은 오류는 없었다.
전체 최종 장부에서 구성 변경에 따른 예약 해제 208회, 이전 세대 하위 연결 거부 22회,
teardown 중 ARM 거부 21회, stopping 중 setup 거부 36회를 관측했다.

최종 언로드 장부 **408개**에서 잔여 context·작업자·큐·instance·연결·owner·예약·예약 세대는
모두 0이었다. 생성 = 논리 완료 = 해제는 **3,009**, pre는 **1,565/1,565**,
post는 **180/180**, draining post는 624회였다. MDL 고정 1,373회와 고정 실패 주입
2회를 검사했고 `Violations=0`이었다. 부분 배치 실행기의 저장된 시간/slot으로 중복을
제거한 READ 결과는 정상 내용 일치 360개, 취소 366개다. 종료한 요청자의 사용자 결과나
메시지가 저장되지 않은 대조군 결과는 이 내용 검증 합계에 넣지 않았다.

`verified-results.json`은 종료 코드, 바이너리 해시, 개별 단언, journal과 최종 장부를
교차 확인한 집계다. 초기 PowerShell 배치 실행기는 인수 배열 조합 오류로 Python 파일을
열기 전에 실패했다. fixture 로드 전의 실행기 오류였으며 수정 후 다시 실행했다.
`launcher-initial-error.txt`에 보존했고, 기준 바이너리의 세 실패와 함께 성공 합계에서 제외했다.

최종 호스트 감사는 **2026-10-25 14:06:20 KST**에 수행했다. 검증 구간
**13:39:09~14:06:20 KST**에 새 System 41/1001, 우리 프로그램의 Application 1000/1001,
새 minidump가 없었다. 부팅 시각은 **09:30:03.500 KST** 그대로이고 우리 드라이버와
테스트 프로세스도 남지 않았다. 언로드 후 이전 pending 제어 포트는 응답하지 않았다.
이번 범위에서 추가 재부팅이나 콜백 잔존을 관측하지 않았다.

기존 `09:29:45.455 KST / 0x1A_4477` crash와 두 minidump는 그대로 보존했다.
managed 회귀에 사용한 기존 `KnLiveDbg.exe`의 SHA-256은
`9d21f5cd6f8205b3a353c19a01c2da321fa5f4f04008b36456161b471bd80dec`다.
시험은 자체 fixture와 이 Windows 호스트의 범위에 한정하며 모든 스케줄링 순서나
외부 필터의 콜백 수명에 대한 보장으로 일반화하지 않는다.

## 재실행

기존 자체 fixture 서비스가 없는 상태에서 빌드하고, 승격된 셸에서 각 새 출력 폴더로
순차 실행한다. 같은 fixture를 사용하는 실행기나 빌드를 동시에 실행하지 않는다.

```powershell
.\tools\build.ps1 -Configuration Release
python .\tools\run-pending-partial-e2e.py --output .build\partial\regressions --case regressions --reads 8 --submitted 2 --iterations 4
python .\tools\run-pending-partial-e2e.py --output .build\partial\s1 --case all --reads 8 --submitted 1 --iterations 4 --seed 102501
python .\tools\run-pending-partial-e2e.py --output .build\partial\s2 --case all --reads 8 --submitted 2 --iterations 4 --seed 102502
python .\tools\run-pending-partial-e2e.py --output .build\partial\s4 --case all --reads 8 --submitted 4 --iterations 4 --seed 102504
python .\tools\run-pending-partial-e2e.py --output .build\partial\s7 --case all --reads 8 --submitted 7 --iterations 4 --seed 102507
python .\tools\run-pending-partial-e2e.py --output .build\partial\reads2 --case all --reads 2 --submitted 1 --iterations 2 --seed 202502
python .\tools\run-pending-partial-e2e.py --output .build\partial\reads4 --case all --reads 4 --submitted 3 --iterations 2 --seed 202504
python .\tools\run-pending-multiread-e2e.py --output .build\partial\multi --case all --reads 8 --iterations 4 --seed 102508
python .\tools\run-pending-io-race-e2e.py --output .build\partial\legacy --case all --iterations 4 --seed 102509
python .\tools\run-pending-io-e2e.py --output .build\partial\pending --cycles 12
python .\tools\run-pending-io-e2e.py --output .build\partial\read --cycles 12 --read-only
python .\tools\run-managed-callback-e2e.py --output .build\partial\managed --cycles 100 --close-race-executable .build\managed-close-selftest\managed-callback-close-selftest.exe
```
