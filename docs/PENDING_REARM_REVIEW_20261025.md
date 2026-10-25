# 2026-10-25 0de0043 새 ARM·요청자 종료 경합 리뷰

기준 커밋은 `0de0043`이다. 인스턴스 세대 전환과 새 ARM 발행, 늦은 READ, 취소,
소유자/요청자 강제 종료, 언로드 사이의 수명을 검토했다. 원시 증거는
`C:\git\kn-live-dbg\.build\pending-rearm-20261025`에 보존한다.

## 재현한 결함

`0de0043`의 구성 세대 검사는 미사용 예약을 인스턴스 수명에 맞춰 해제하지만,
새 ARM은 `PsLookupProcessByProcessId` 성공만으로 대상이 살아 있다고 가정했다.
프로세스 객체의 참조 가능 여부와 새 I/O를 제출할 수 있는지는 다르다.

대상 프로세스가 종료된 뒤에도 실행기의 프로세스 핸들을 유지하고 같은 PID로 ARM을
보내면 요청이 성공했다. 실제 READ 없이 `ArmedRemaining=8`, owner와 예약 세대가 남았고
이미 끝난 종료 알림은 새 예약을 다시 정리하지 않았다. 소유자의 다른 ARM도 기존 예약
때문에 막힐 수 있다.

| 기준 바이너리 재현 | 종료 코드 | 결과 |
| --- | --- | --- |
| `repro-dead-normal` | 0 | 새 ARM 성공, 남은 예약 8 |
| `repro-dead-forced` | 1 | 새 ARM 성공, 남은 예약 8 |
| `repro-dead-pending-status` | 259 | 새 ARM 성공, 남은 예약 8 |

기준 fixture SHA-256은
`a11b80d2180fde7a067e65a8dacd336f148752464b10d43750ac402b82c12855`이다.
`.sys`와 `.pdb`를 `baseline-artifacts/`에 보존했다. 세 재현은 의도한 단언 실패로 기록했고
정리 오류는 없었다. 수정 후 성공 합계에서 제외한다.

## 수정과 추가 경계 검토

ARM은 `g_Control`을 획득한 뒤 대상의 종료 상태와 종료 신호를 확인한다.
`PsGetProcessExitStatus`는 APC_LEVEL 이하에서만 호출하므로 spin lock 밖에서 실행한다.
종료 코드 `259`는 `STATUS_PENDING`과 값이 같으므로 코드 검사만으로 충분하지 않다.
프로세스 참조에서 `SYNCHRONIZE` 권한의 커널 핸들을 열고, timeout 0인
`ZwWaitForSingleObject`로 실제 종료 신호도 검사한 뒤 핸들을 즉시 닫는다.
프로세스 종료를 기다리면서 제어 mutex를 보유하지 않는다.

종료 알림의 취소 sweep이 끝난 뒤 마지막 스레드/프로세스가 실제로 신호 상태가 되기
전에도 ARM이 들어올 수 있다. 종료 코드가 259이면 이 순간에는 종료 상태 검사와
zero-time wait 모두 대상이 아직 끝나지 않은 것으로 보인다. 이때 발행된 예약은
종료 알림을 다시 받을 수 없으므로, 기존 작업자가 미사용 예약을 추가로 감시한다.

ARM 발행은 작업자 event를 깨운다. 미사용 예약이 있는 유휴 구간에서 작업자는
100ms 주기로 동일한 대상 검사를 수행한다. 검증이 실패하면 예약을 해제하고 해당
대상의 이미 등록한 작업도 깨운다. 예약이 없으면 기존처럼 event를 기다린다.
새 스레드나 별도 완료 경로를 만들지 않는다.

감시용 프로세스 참조는 spin lock 안에서 별도로 얻는다. 실제 검사는 lock 밖에서
수행하며, 이후 `g_Target == snapshot`인 경우에만 예약을 해제한다. 구성 변경이 검사
도중 예약을 먼저 해제해도 감시 참조가 객체를 유지한다. 새 ARM과 종료 알림은
`g_Control`로 직렬화하고, 예약 참조와 감시 참조는 각각 한 번씩 놓는다.
언로드는 기존 작업자를 join하므로 임시 참조나 핸들이 코드 언로드 뒤에 남지 않는다.

대상 검사에 실패한 ARM은 owner/예약을 만들지 않는다. 대상 종료로 남은 예약을
정리할 때는 살아 있는 owner lease를 유지하여 다른 정상 대상에 다시 ARM할 수 있다.
기존 READ identity, 세대 일치, live-owner 검사와 MDL/단일 완료 규칙은 유지한다.

프로토콜은 v5, 요청 32 bytes, 상태 408 bytes다. 대상 ARM 거부, 작업자의 예약 회수,
종료 알림 시험 gate 진입/완료/stopping 관측 계수를 추가했다. 종료 알림 gate는 자체
관리자/SYSTEM 시험 포트의 `ARM_RACE`, `DRAIN_PAIR`, Reserved=8에서만 허용하며
50~500ms로 제한한다. 이 gate는 기존 취소 sweep 뒤에 lock 없이 기다린다.
`ManagedCallbacksStop`의 프로세스 알림 제거가 실행 중인 알림을 기다린 뒤 FltMgr를
해제하는 순서를 유지한다. 잘못된 mode, 지연, gate와 이전 ABI 거부 검사도 확장했다.

근거 계약은 [PsGetProcessExitStatus](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psgetprocessexitstatus),
[ZwWaitForSingleObject](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwwaitforsingleobject),
[프로세스 종료 알림과 제거 시 대기](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex)다.

## 검사 구성

새 실행기 `tools/run-pending-rearm-e2e.py`는 기존 READ slot, 버퍼, OVERLAPPED,
완료 event와 내용 검증을 재사용한다. 다음 조건을 구분해 확인한다.

- 이미 종료한 대상: 정상 종료, 강제 종료, 종료 코드 259를 모두 거부하고 상태 계수로
  대상 검증 경로가 실행됐음을 확인한다. 이어 살아 있는 새 대상의 ARM과 실제 READ 보류가
  성공하는 양성 대조를 수행한다.
- 종료 알림 직후 재예약: gate 진입, 이전 예약 0, gate 미완료를 관측한 뒤 같은 대상에
  새 ARM을 발행한다. 종료 후 작업자 회수 계수 증가와 남은 예약 0을 확인한다.
- 다른 대상의 재예약: 이전 대상의 종료 알림 tail 중 새 살아 있는 대상에 ARM한다.
  새 READ가 정상 완료되고 나머지 예약이 유지돼야 한다. 이전 대상의 종료가 새 ARM을
  지우면 실패한다.
- 종료 알림 중 언로드: gate가 열린 동안 실제 FilterUnload를 호출한다. 알림 완료와
  stopping 관측, 작업자/예약/연결/instance 0을 확인하고 이전 포트의 응답도 검사한다.
- 재연결과 발행 순서: 부분 배치를 완료하고 한 인스턴스가 없는 구간에서 새 ARM,
  재연결, 늦은 READ 제출의 순서를 섞는다. 인스턴스 연결보다 먼저 발행된 예약은
  해제되고, 이후 남은 예약은 현재 세대여야 한다. 모든 생존 READ의 내용을 확인한다.
- 여섯 actor 경합: 실제 부분 READ 보류를 확인하고 ARM 재요청, 취소, 소유자/요청자/양쪽
  강제 종료, 분리·재연결, 나머지 READ, 언로드를 0/2/4/6/8/10ms 간격으로 섞는다.
  기존 작업이 남은 동안 재요청은 BUSY 또는 언로드에 따른 삭제/닫힌 포트 오류만 허용한다.
  강제 종료 actor는 ARM 응답을 확인한 뒤 진행하므로 단순히 사용자 파이프가 죽어
  ARM이 커널에 도착하지 않은 경우를 이 검사로 계산하지 않는다.
- 발행 자체와 종료의 경합: 기존 예약이 없는 상태에서 ARM, 대상/owner 종료,
  하위 교체, READ 제출, 취소를 겹친다. 이때는 ARM 성공도 가능하다. 드라이버가
  `Stopping=0`인 동안 모든 context와 예약이 정리됨을 먼저 확인하고 마지막에 언로드한다.
  따라서 언로드가 남은 예약을 지워 발행 경합 결함을 가리는 것을 방지한다.

종료된 소유자의 포트 복제 핸들을 유지하는 회차도 포함한다. 살아 있는 요청자의 READ는
slot별 단일 완료, 정상 4096 bytes 전체 내용 또는 취소 995/0 bytes를 검사한다.
요청자를 종료한 회차는 커널 장부와 실제 프로세스 종료로 확인하며 사용자 결과가 없는
READ의 내용 검증을 주장하지 않는다. 실제 보류/알림 gate 관측과 API 호출 시각을 저장한다.

## 초기 실행기 중단과 보완

첫 `rearm-s4`는 종료 알림 중 새 대상에 ARM하는 대조군에서 첫 READ 생성 전에 중단됐다.
정리 장부는 Created/PreQueued 0, gate 진입/완료 1, 최종 잔여 자원 0이었고 정리 오류는
없었다. PowerShell의 strict 오류 정책이 Python stderr의 첫 줄에서 실행을 중단하여
최초 traceback이 보존되지 않았다. 따라서 정확한 최초 단언과 원인을 단정하지 않는다.

이 실행기는 500ms gate 안에서 새 Python 프로세스를 생성하고 있었다. 프로세스 시작
지연은 gate보다 길어질 수 있어 측정 구간을 놓칠 수 있는 구조였다. 새 대상은 gate
진입 전에 준비하도록 바꾸고, gate 중 새 ARM의 응답/상태를 journal에 남겼다.
Python 예외는 정리 전에 `failure.txt`에 기록하고 PowerShell도 전체 stderr와 종료 코드를
남기도록 고쳤다. 이 변경은 시험 구간의 시간 의존성을 제거하며 커널 조건을 완화하지 않는다.

그 뒤 `exit-tail-prepared`에서 세 종료 경계 조건을 각각 8회 실행해 59개 단언을 통과했다.
실패했던 제출 조건은 새 폴더 `rearm-s4-fixed`에서 전체 재실행했다. 초기 `rearm-s4`와
`matrix-initial-error.txt`를 보존하며 성공 합계에서 제외한다.

## 최종 결과

Windows x64 `28000.3231`에서 Release fixture 빌드와 테스트서명 로드가 성공했다.
아래 성공 실행은 모두 SHA-256
`a3f0af15775c3a54ebaac1fde2cfbd70e8b51cd744bee4ef51cf01f7c3dd4205`인 `.sys`를 사용했다.
최종 `.sys`와 `.pdb`를 원시 증거의 `artifacts/`에 보존했다.

| 실행 | 결과 |
| --- | --- |
| 종료 대상 smoke `dead-fixed-smoke` | 12/12, 3.375초 |
| 새 대조군 smoke `new-controls-smoke` | 25/25, 9.594초 |
| 여섯 actor smoke `six-actor-smoke` | 21/21, 8.109초 |
| 발행 경합 smoke `admission-smoke` | 15/15, 2회 반복, 2.281초 |
| 준비된 종료 알림 경계 `exit-tail-prepared` | 59/59, 조건별 8회, 26.656초 |
| 8개 중 1개 제출 `rearm-s1` | 187/187, 4회 반복, seed 251001, 73.703초 |
| 8개 중 2개 제출 `rearm-s2` | 187/187, 4회 반복, seed 251002, 74.203초 |
| 8개 중 4개 제출 `rearm-s4-fixed` | 187/187, 4회 반복, seed 251004, 72.875초 |
| 8개 중 7개 제출 `rearm-s7` | 187/187, 4회 반복, seed 251007, 71.594초 |
| 2개 중 1개 제출 `rearm-reads2` | 95/95, 2회 반복, seed 251022, 36.875초 |
| 4개 중 3개 제출 `rearm-reads4` | 95/95, 2회 반복, seed 251044, 35.969초 |
| 기존 부분 배치 회귀 | 151/151, 4회 반복, 60.906초 |
| 기존 다중 READ 회귀 | 111/111, 4회 반복, 30.891초 |
| 기존 소유자·짝짓기·단일 I/O 경합 | 63/63, 4회 반복, 22.844초 |
| pending 전체 / READ 집중 회귀 | 160/160, 13.109초 / 32/32, 1.281초 |
| managed 콜백 회귀 | 93/93. 포인터 유지, 자동 복구, rundown, 정상/강제 종료, 직접/서비스 언로드 |
| 최종 성공 실행의 전체 단언 | **1,680/1,680** |

여섯 actor 경합은 **189회**이며 동작 구간에 진입한 actor 순서 144가지를 관측했다. 소유자만/요청자만/
양쪽 강제 종료가 각각 63회, 재연결 우선/자유 상위 교체/자유 하위 교체가 각각 63회다.
189회 모두 실제 gate에서 취소와 stopping을 관측했다. 기존 I/O가 보류된 상태의
실제 재연결은 63회 확인했다. ARM 재요청은 BUSY 123회, DELETING_OBJECT 66회였고,
진행 중인 배치를 덮어쓴 ARM은 없었다. 재연결 API는 성공 102회, DELETING_OBJECT 25회,
FILTER_NOT_FOUND 62회였다.

기존 예약 없는 발행 경합 **66회**에서는 ARM이 실제 발행된 경우가 38회, 대상 검증에서
거부된 경우가 7회였다. owner가 먼저 종료하는 경우도 포함하며 모든 회차가 언로드 전에
`Stopping=0`, 잔여 예약/context 0으로 정리됐다. 재연결·ARM·늦은 제출 대조는 **42회**로
세 actor의 진입 순서 6가지를 모두 관측했다. 이 순서는 실행기에서 기록한 시각이며
커널 내부의 모든 선형화 순서를 증명하는 지표로 해석하지 않는다.

이미 끝난 대상의 새 ARM은 **66회** 거부했고 이후 정상 대상에 ARM할 수 있었다.
종료 알림 tail은 **87회** 진입/완료했다. 같은 대상의 늦은 예약 회수, 다른 대상의 새
예약 유지, 알림 중 언로드를 각각 29회 확인했다. 언로드의 stopping 관측도 29회였다.
전체 장부의 대상 검증 거부는 73회, 작업자에 의한 남은 예약 회수는 35회였다.

언로드 최종 장부 **600개**에서 worker·queue·context·instance·connection·owner·예약·예약
세대는 모두 0이었다. 생성 = 논리 완료 = 해제는 **3,312**, pre는 **1,720/1,720**,
post는 **180/180**, draining post는 757회였다. MDL 고정 1,528회와 고정 실패 주입
2회를 검사했고 `Violations=0`이었다. 새 실행기 계열에서 저장된 slot/시각으로 중복을
제거한 READ는 정상 내용 일치 495개, 취소 479개다. 저장하지 않았거나 요청자 종료로
사용자 결과를 얻지 못한 READ는 이 내용 검증 합계에 포함하지 않았다.

`verified-results.json`은 각 실행의 종료 코드, 해시, 개별 단언, journal과 최종 장부를
교차 확인한 집계다. 기준 바이너리의 실패 3회와 초기 `rearm-s4`는 포함하지 않았다.

최종 호스트 감사는 **2026-10-25 14:44:41 KST**에 수행했다. 검증 구간
**14:15:13~14:44:41 KST**에 새 System 41/1001, 우리 프로그램의 Application 1000/1001,
새 minidump가 없었다. 부팅 시각은 **09:30:03.500 KST** 그대로이며 우리 드라이버와
테스트 프로세스도 남지 않았다. 언로드 후 이전 제어 포트는 응답하지 않았다.
이번 검증에서 추가 재부팅이나 콜백 잔존을 관측하지 않았다.

기존 `09:29:45.455 KST / 0x1A_4477` crash와 두 minidump는 보존했다.
managed 회귀에 사용한 기존 `KnLiveDbg.exe`의 SHA-256은
`9d21f5cd6f8205b3a353c19a01c2da321fa5f4f04008b36456161b471bd80dec`다.
결과는 자체 fixture와 이 Windows 호스트의 시험 범위에 한정하며 모든 스케줄링 순서나
외부 필터의 콜백 수명에 대한 보장으로 일반화하지 않는다.

## 재실행

기존 자체 fixture 서비스가 없는 상태에서 빌드하고, 승격된 셸에서 각 새 출력 폴더로
순차 실행한다. fixture 사용 중에는 재빌드하거나 다른 실행기를 동시에 실행하지 않는다.

```powershell
.\tools\build.ps1 -Configuration Release
python .\tools\run-pending-rearm-e2e.py --output .build\rearm\dead --case dead --iterations 4
python .\tools\run-pending-rearm-e2e.py --output .build\rearm\tail --case exit-tail --iterations 8
python .\tools\run-pending-rearm-e2e.py --output .build\rearm\s1 --case all --reads 8 --submitted 1 --iterations 4 --seed 251001
python .\tools\run-pending-rearm-e2e.py --output .build\rearm\s2 --case all --reads 8 --submitted 2 --iterations 4 --seed 251002
python .\tools\run-pending-rearm-e2e.py --output .build\rearm\s4 --case all --reads 8 --submitted 4 --iterations 4 --seed 251004
python .\tools\run-pending-rearm-e2e.py --output .build\rearm\s7 --case all --reads 8 --submitted 7 --iterations 4 --seed 251007
python .\tools\run-pending-rearm-e2e.py --output .build\rearm\reads2 --case all --reads 2 --submitted 1 --iterations 2 --seed 251022
python .\tools\run-pending-rearm-e2e.py --output .build\rearm\reads4 --case all --reads 4 --submitted 3 --iterations 2 --seed 251044
python .\tools\run-pending-partial-e2e.py --output .build\rearm\partial --case all --iterations 4 --seed 251050
python .\tools\run-pending-multiread-e2e.py --output .build\rearm\multi --case all --iterations 4 --seed 251060
python .\tools\run-pending-io-race-e2e.py --output .build\rearm\legacy --case all --iterations 4 --seed 251070
python .\tools\run-pending-io-e2e.py --output .build\rearm\pending --cycles 12
python .\tools\run-pending-io-e2e.py --output .build\rearm\read --cycles 12 --read-only
python .\tools\run-managed-callback-e2e.py --output .build\rearm\managed --cycles 100 --close-race-executable .build\managed-close-selftest\managed-callback-close-selftest.exe
```
