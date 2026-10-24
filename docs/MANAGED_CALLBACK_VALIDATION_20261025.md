# 2026-10-25 협력형 콜백 제어와 커널 수명 검증

## 지원 범위

`1fe96a4`에서 차단한 기능 중 **우리 테스트 필터의 CREATE pre/post 제어**를 복구했다.
`KnLiveDbgMiniFilterFixture`가 자신의 콜백 본체와 제어 상태를 소유한다.
`!minifilter`/`!fltmgr`의 disable/enable/all, `!callbacks`의 minifilter/all,
그리고 두 MCP 도구가 같은 경로를 사용한다. `write on`이 필요하다.
여기서 all은 provider가 제어하는 CREATE 본체 전체다. 수명 관리 및 프로세스 종료 알림은 유지한다.

외부 필터·object/registry/process/thread/image-load 콜백의 포인터 교체는 계속 차단한다.
외부 호출자가 이미 읽어 둔 함수 주소까지 우리 드라이버의 `EX_RUNDOWN_REF`가 보호할 수는 없다.
따라서 이 변경을 범용 raw pointer 변경 기능의 복구로 해석해서는 안 된다.
새 경로에는 임의의 주소에 값을 쓰거나 사용자 제공 함수 포인터를 설치하는 요청이 없다.
요청의 ExpectedFilter 값은 조회한 provider의 정체성을 비교하는 데만 사용한다.

## 수명과 동시성

- FltMgr에 등록한 CREATE pre/post wrapper는 항상 테스트 필터 이미지 안에 있다.
  `KnLiveDbg.sys`의 대체 thunk 주소를 필터에 기록하지 않는다.
- pre/post 본체마다 `EX_RUNDOWN_REF`를 둔다. disable은 spin lock 안에서 새 진입을 막고,
  lock을 놓은 뒤 `ExWaitForRundownProtectionRelease`로 기존 호출 완료를 기다린다.
  enable은 완료된 rundown만 재초기화한 뒤 진입을 연다. 전환은 PASSIVE_LEVEL의 mutex로 직렬화한다.
  acquire 전 상태 확인과 재초기화 사이의 경합도 같은 spin lock으로 막는다.
- 본체는 CREATE 호출 횟수만 센다. I/O를 거부·변경·보류하지 않는다. 시험용 지연은 지정한
  PID의 pre 또는 post 한 번에만 적용되며 최대 500 ms다. rundown을 보유하는 동안 normal APC를 막는다.
- 관리자/SYSTEM 통신 포트의 한 연결만 변경 소유권을 갖는다. 다른 연결은 조회할 수 있으나
  변경 소유권을 빼앗을 수 없다. 연결 cookie는 재사용하지 않는 정수이며, 해제된 메모리 주소가 아니다.
- 연결 해제 때 커널이 본체를 drain하고 기본 활성 상태로 복구한다. 프로세스 종료 알림도 등록해,
  다른 프로세스에 복제한 포트 핸들이 살아 있어도 소유 프로세스의 종료를 감지한다.
  소유 프로세스 객체 참조는 소유권 해제 때 반납한다.
- unload는 새 제어를 막고 본체를 drain한 뒤 서버 포트를 닫고 프로세스 종료 알림을 해제한다.
  mutex를 잡지 않은 상태에서 `FltUnregisterFilter`를 호출해 wrapper·인스턴스·연결의 수명을
  FltMgr가 정리하게 한다. 서비스 중지와 명시적 필터 unload에 같은 경로를 사용한다.
- 입력은 로컬 구조체로 복사하고 버전·크기·mask·필터 정체성을 검증한다. 사용자 버퍼는 SEH로
  보호한다. 상태 변경 후 응답 복사에 실패하면 소유권을 해제하고 기본 상태로 복구한다.
  사용자 모드는 실패한 변경을 자동 재시도하지 않고 해당 연결을 닫는다.
- 사용자 모드의 포트 종료와 장치 종료를 조회와 같은 mutex 안에서 수행한다.
  조회가 종료 중간에 연결을 다시 열어 남기는 경쟁 구간을 막았다.
  커널 조회 응답의 현재/이전 mask도 같은 순간에 복사해, 동시 전환이 조회 자체의 변경으로
  잘못 표시되지 않게 했다. 변경 요청은 실제 전환 전후의 mask를 계속 반환한다.

새 인스턴스도 같은 커널 소유 상태를 사용하므로 pause 중 연결한 인스턴스에 누락이 생기지 않는다.
주소가 같은 새 필터로 재로드되더라도 예전 연결은 FltMgr에서 끊기며 새 연결로 재사용되지 않는다.

## 출력 계약

기존 주소 필드는 등록된 wrapper를 나타낸다. 비활성화해도 주소·등록·live node 수는 그대로다.
`managed.mode`는 `provider-owned-rundown`, `enabledMask`는 pre=1/post=2이며,
진행 중 호출·진입·건너뜀 수와 소유 PID, 자동 복구 횟수를 별도로 제공한다.
`preChanged`/`postChanged`는 포인터 변경 여부이므로 false를 유지한다.
본체 변화는 `managed.preBodyChanged`/`postBodyChanged`로 구분하고,
배치의 changed는 본체 상태가 달라진 지원 operation 수다.
일반 `!callbacks` 조회에도 CREATE 본체 활성 상태를 notes로 표시한다.

## 검증 방법과 증거

실행 환경은 기존 테스트서명이 설정된 Windows x64 28000.3231, VMware 2 CPU였다.
원시 증거는 `C:\git\kn-live-dbg\.build\managed-callback-20261025`에 보존했다.

재현 가능한 실행:

```powershell
.\tools\build.ps1 -Configuration Release
.\tools\validate-managed-callback-close.ps1 -BuildOnly
python .\tools\run-managed-callback-e2e.py --output .build\managed-callback\run1 --close-race-executable .build\managed-close-selftest\managed-callback-close-selftest.exe
.\tools\run-minifilter-detach-e2e.ps1 -CheckMutationGuard
```

승격된 셸에서 실행한다. 하네스는 기존 fixture/controller 서비스가 있으면 중단한다.
자기 fixture 서비스만 만들고, 직접 생성한 프로세스만 종료하며, 마지막에 자기 서비스를 제거한다.
실제 필터의 동작을 조회하며 다음 조건을 확인한다.

- 활성 상태의 pre/post 실제 진입 및 pause 뒤 새 본체 진입 0, skip 증가.
- pre/post/both 반복 전환, 잘못된 요청 및 두 번째 소유자의 변경 거부.
- 반복 전환과 동시에 조회해 한 조회의 두 mask가 같은 시점을 나타내는지 확인.
- 실제 provider 포트와 NUL 장치 핸들로 `DeviceClient` 종료를 100회 경합시킨다.
  네 스레드가 회당 200회씩 조회하며 종료 후 성공한 요청·재연결·소유권 잔존이 없는지 확인한다.
  실제 컨트롤러와 `KnLiveDbg.sys` 종료는 아래의 별도 콘솔 시험으로 검증한다.
- pause 중 인스턴스 분리·재연결에도 같은 상태 적용.
- 실제 pre/post 본체를 400 ms 보유하고 disable이 완료를 기다리는지 확인.
- rundown 대기 중 응답 버퍼를 접근 불가로 바꿔 응답 실패 후 기본 상태 복구 확인.
- 핸들을 복제해 둔 소유 프로세스 종료와 rundown 진행 중 강제 종료.
- 실제 콘솔 정상 종료·강제 종료 각각 3회 및 명시적 controller unload.
- 등록 포인터 불변, 콘솔 alias 및 unsupported scope 거부.
- 동시 파일 I/O 중 FltMgr unload와 서비스 중지 각각 3회. pause 상태뿐 아니라
  pre/post가 실제 실행 중인 상태에서 unload하며, 재로드의 기본 상태도 확인.

초기 검증 `run1`은 600회 전환과 정상/강제 종료·언로드를 통과했다.
확장 검증 `run3`은 66개 항목과 네 작업 스레드의 파일 생성·읽기·삭제 94,617회를 통과했다.
pre/post rundown 대기, 소유 프로세스 종료, 복제 핸들, 응답 실패와 실제 호출 중 unload를 포함한다.
`run2`는 하네스가 `fltmc detach`에 잘못된 `-i` 옵션을 준 실패이며 성공으로 세지 않았다.
위치 인수로 고친 뒤 전체 검증을 다시 실행했다. 이 실패에서도 fixture 정리는 통과했다.

최종 빌드의 EXE SHA-256은
`51366c8f5023c567feec76bd79d86e1a923b4036786c5cd092e993c2ad6db054`,
테스트 필터 SYS SHA-256은
`c88d074c897c62b329200d16f6d63e3ab630160c92e26b7f09cfce742ff8a94c`다.

| 최종 검증 | 결과 |
| --- | --- |
| `run10` / `run11` 전체 반복 | 각각 71/71개 통과, 118.984초 / 110.031초 |
| 반복 pre/post/both 전환 | 두 실행 합계 1,200회 요청 통과 |
| 전환 중 동시 조회 | 526회 + 718회, 합계 1,244회. 조회의 현재/이전 mask 불일치 0 |
| 동시 조회와 장치 종료 | 두 실행 합계 200회 종료 경합, 네 조회 스레드의 요청 160,000회. 종료 뒤 재연결·소유권 잔존·늦은 요청 성공 0 |
| 실제 콘솔 종료 | 정상 종료 6회, 강제 종료 6회, 명시적 컨트롤러 unload 2회 뒤 기본 상태 복구 |
| 필터 unload/reload | FltMgr unload 6회와 서비스 중지 6회 통과. 그중 8회는 실제 pre/post 본체가 진행 중인 상태 |
| 동시 파일 작업 | 네 스레드의 생성·읽기·삭제 묶음 90,939회 + 83,633회, 합계 174,572회. 작업 오류 0 |
| 실제 rundown 대기 | 400 ms 보유 시험의 disable 소요 0.391~0.625초. 응답 시 해당 본체 active=0과 hold 완료 확인 |
| 실제 MCP (`mcp4`) | 인증, 두 변경 도구, unsupported 대상·scope 거부, 상태 조회, 종료 후 복구 11/11개 통과 |
| 통합 자체검사 | timeline 28, MCP 89, console 558, commands 2,961, remote 66 및 connect 인수 4개 통과 |

최종 두 실행은 `preChanged`/`postChanged=false`와 본체별 변경 필드를 함께 단언한다.
MCP 최초 실행에서는 `callbacks.set disable-all`의 사전 조회가 불필요하게 모든 콜백 범위를
검사해 executive PDB 공백 때문에 취소됐다. 협력형 제어의 사전·사후 조회를 실제 대상인
`!minifilter show`로 한정했고, 같은 MCP 실행 전체를 다시 통과했다. 실패 로그 `mcp`도 보존했다.
`run4`~`run9`의 앞선 반복도 통과했으나 위 표는 포트 종료 경합과 조회 스냅샷 수정까지 포함한
최종 바이너리 결과다.

별도 회귀에서는 `-CheckMutationGuard`의 unsupported 요청 10개가 거부되고 등록이 유지됐으며,
실제 분리/재연결과 cleanup을 136.781초에 통과했다. attachment 검증기 자체검사,
명령 파서 ASan 275,002개, completion ASan 25,954개 및 HTTP 자체검사 9개도 통과했다.
비승격 사용자에게 실행 중 provider 포트 연결은 `0x80070005`로 거부됐다.
이 회귀 증거는 앞선 빌드의 `final2-results.json`, `http.log`, `unprivileged-port.json`에 보존했다.

최종 빌드·자체검사·MCP·반복 실행 상태는 `final4-results.json`, 개별 단언은 각 실행의
`checks.json`, 등록 정보는 `normal-*`/`forced-*`의 before/after JSON,
지원 API 검증은 `detach/manifest.json`에 있다.

2026-10-25 02:52:45 KST의 마지막 호스트 점검에서 부팅 시각은 기준값
2026-10-24 21:23:19.500 KST와 같았다. 새 System 41/1001 이벤트, 우리 프로그램의
Application 1000/1001 오류, 새 minidump가 없었고 테스트 드라이버·프로세스도 남지 않았다.
기존 `102426-10593-01.dmp`는 변경 없이 남겨 뒀다. unload 후 기존 포트 요청의 실패,
재로드의 기본 활성 상태, 등록 포인터 불변을 반복 확인했으며 이 시험에서 콜백 잔존은 관측하지 않았다.
세부 호스트 기록과 파일 해시는 `host-audit.json`에 있다.

## 확인한 범위의 한계

검증 결과는 이 호스트와 무해한 CREATE 테스트 provider에 해당한다. 실제 보안 필터를 중지하거나
포인터를 변경하지 않았다. 임의의 콜백 구현, 장시간 I/O, 다른 OS 빌드 및 외부 provider에 대한
안전성 보장이 아니다. provider가 협력하지 않는 범용 변경은 계속 사용 불가다.
MCP 변경 소유권의 주체는 HTTP 클라이언트가 아니라 드라이버 세션을 보유하는 컨트롤러 프로세스다.
500 ms는 시험 지연의 요청 상한이며, OS 스케줄링을 포함한 전체 완료 기한을 보장하지 않는다.

## 일차 자료

- [Run-Down Protection](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/run-down-protection): 보호 구간과 종료 대기, APC 제약.
- [ExReInitializeRundownProtection](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exreinitializerundownprotection): 기존 rundown 완료 뒤 재초기화 계약.
- [Loading and Unloading a Minifilter](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/loading-and-unloading): 실제 호출과 인스턴스 teardown 수명.
- [Closing the Communication Server Port](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/closing-the-communication-server-port): unregister 전 서버 포트 종료와 기존 연결 처리.
- [MessageNotifyCallback](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nc-fltkernel-pflt_message_notify): 잠기지 않은 사용자 버퍼의 예외 처리.
- [DisconnectNotifyCallback](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nc-fltkernel-pflt_disconnect_notify): 마지막 사용자 핸들 종료 및 unload 알림.
- [Writing Postoperation Callback Routines](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/writing-postoperation-callback-routines): CREATE post의 PASSIVE_LEVEL 계약.
