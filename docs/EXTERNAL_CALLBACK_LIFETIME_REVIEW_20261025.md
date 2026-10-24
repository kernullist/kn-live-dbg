# 2026-10-25 외부 필터 콜백 수명 검토

## 판정과 지원 범위

기준 커밋은 `2400f81`이다. **협력하지 않는 외부 미니필터의 콜백 포인터 교체는 복구하지 않았다.**
이 코드와 공개 WDK 계약으로는 외부 dispatch 진입 전부터 pending pre/post 완료까지
동기화할 수 있는 수명 계약을 확보하지 못했다. 우리 드라이버 안에 rundown을 추가하거나
필터 객체를 참조하는 것만으로 이 조건이 충족되지 않는다.

현재 지원하는 변경은 `KnLiveDbgMiniFilterFixture`의 협력형 CREATE 본체 제어다.
등록 wrapper와 상태가 provider 이미지에 있고, 본체 진입은 provider가 직렬화하며,
최종 코드 수명은 FltMgr 등록/해제 절차가 관리한다. 이 방식을 외부 raw write와 혼동하지 않는다.

## 공개 계약과 남는 경쟁 구간

`FltObjectReference`는 opaque filter/instance/volume 객체의 해제를 막는 rundown 참조다.
콜백 dispatch를 중지하거나 callback node 쓰기를 직렬화하는 계약은 아니다.
참조가 남으면 `FltUnregisterFilter`가 기다리므로, 해제 시점을 정의하지 않은 고정은
언로드 정체로 바뀔 수 있다.
근거: [FltObjectReference](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltobjectreference),
[Unregistering the Minifilter](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/unregistering-the-minifilter).

외부 함수 주소를 우리 thunk로 바꾼 뒤 thunk 안에서만 rundown을 획득하면 다음 순서가 남는다.

| 순서 | dispatch 쪽 | 복구/언로드 쪽 |
| --- | --- | --- |
| 1 | 교체된 함수 주소를 읽었지만 아직 진입하지 않음 | |
| 2 | 진입 전 대기 | 원래 주소 복구, local rundown의 참조 0 확인 |
| 3 | | thunk 이미지 언로드 |
| 4 | 앞서 읽은 주소로 진입 | 이미 해제된 코드에 도달할 수 있음 |

이 표는 수명 계약의 반례이며, 해제된 커널 주소를 실제로 호출한 시험은 아니다.
rundown은 접근 전에 획득되어야 한다. 함수 내부에서 획득하는 카운터는 함수 진입 자체의
선행 접근을 보호하지 못한다. 임의의 대기 시간이나 포인터의 원자적 교체도 이 계약을 대신하지 못한다.
근거: [Run-Down Protection](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/run-down-protection).

또한 원래 pre가 만든 completion context, pending I/O와 draining post 처리를 provider 밖에서
임의로 생략할 수 없다. 실행 중인 함수 개수가 0이어도 나중의 post 처리를 기다리는 I/O는 남을 수 있다.
카운트만 하는 테스트 본체의 독립적인 pre/post pause가 일반 필터의 계약을 검증하는 것은 아니다.
근거: [Completion Processing](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/performing-completion-processing-for-an-i-o-operation),
[Instance Teardown](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nc-fltkernel-pflt_instance_teardown_callback).

`FltUnregisterFilter`는 호출한 미니필터 자신만 해제하도록 명시되어 있다. 다른 필터의 포인터로
이를 호출해 drain 장벽으로 사용하는 방법은 지원되지 않는다.
vendor가 제공하는 제어나 정상 `FilterUnload`/`FilterDetach` 경로는 별도 수명 절차이며,
특정 콜백만 일시적으로 바꾸는 동작과 같지 않다. 이번에는 외부 필터를 중지하거나 분리하지 않았다.
근거: [FltUnregisterFilter](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltunregisterfilter),
[Loading and Unloading](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/loading-and-unloading),
[FilterDetach](https://learn.microsoft.com/en-us/windows/win32/api/fltuser/nf-fltuser-filterdetach).

## 변경 사항

- 테스트 provider에 `KNDBG_MANAGED_TEST_HOLD_BEFORE_BODY`를 추가했다. 지정 PID의 CREATE
  pre/post wrapper 한 번을 본체 rundown 획득 전에 최대 500 ms 지연한다. 기존 구조체 ABI는 유지한다.
  이 코드는 이미 FltMgr가 호출한 **등록 wrapper 내부**에서 실행된다. 외부 포인터를 바꾸거나
  해제된 코드를 실행하지 않는다. draining post에는 이 시험 지연을 적용하지 않는다.
- 선택한 본체를 disable한 응답에서 해당 active=0인데도 wrapper 지연이 남는 상황을 직접 확인한다.
  이 상태에서 disable을 wrapper 전체의 완료로 잘못 해석하면 안 된다. 필터 언로드는
  기존의 `FltUnregisterFilter` 단계까지 마쳐 wrapper를 drain해야 한다.
- 이 구간에서 소유 프로세스의 정상/강제 종료 및 실제 `FilterUnload`를 시험한다.
  직접 API를 호출해 외부 명령 프로세스 실행 시간으로 지연 구간을 놓치는 문제를 줄였다.
- 실제 로드된 fixture의 주소를 대상으로 legacy 변경 경로를 요청해 거부와 등록 불변을 확인한다.
  이름이 없는 가상 대상의 거부만으로 검증을 끝내지 않는다.
- 대상 이름의 `_wcsicmp`가 embedded NUL 뒤를 무시해 모호한 문자열을 협력형 대상으로
  분류하던 문제를 수정했다. 전체 길이까지 비교하며, 자체검사와 실제 MCP 요청으로 검증한다.
  공통 거부 메시지에도 진입 전 dispatch와 pending completion의 한계를 명시했다.

## 실행과 결과

승격된 셸에서 빌드하고, 기존 테스트 서비스가 없는 상태에서 실행한다.

```powershell
.\tools\build.ps1 -Configuration Release
.\tools\validate-managed-callback-close.ps1 -BuildOnly
python .\tools\run-managed-callback-e2e.py --output .build\external-callback\run1 --close-race-executable .build\managed-close-selftest\managed-callback-close-selftest.exe
python .\tools\run-managed-callback-e2e.py --output .build\external-callback\run2 --close-race-executable .build\managed-close-selftest\managed-callback-close-selftest.exe
.\tools\run-minifilter-detach-e2e.ps1 -CheckMutationGuard
```

원시 증거: `C:\git\kn-live-dbg\.build\external-callback-20261025`.
실행 환경은 Windows x64 `28000.3231`이다.

| 검증 | 결과 |
| --- | --- |
| 수정 후 전체 반복 `run2` / `run3` | 각각 93/93개 통과, 216.344초 / 131.609초 |
| 본체 rundown 밖의 wrapper 지연 | pre/post 각각 3회씩, 두 실행 합계 12회. disable 응답에서 선택한 active=0과 미완료 wrapper를 함께 관측 |
| 이 구간의 소유 프로세스 종료 | 정상 4회, 강제 4회 뒤 기본 상태 복구와 wrapper 완료 확인 |
| 직접 `FilterUnload` | pre/post 각각 2회, 합계 4회 성공. 관측 직후 호출에서 0.532~0.781초 소요, 기존 포트 단절과 재로드 기본 상태 확인 |
| 전체 필터 언로드/재로드 | FltMgr 명령 6회, 서비스 중지 6회, 직접 API 4회로 총 16회 |
| 기존 실제 콘솔 수명 시험 | 정상 종료 6회, 강제 종료 6회, 명시적 controller unload 2회 뒤 복구 |
| 반복 제어와 조회 | pre/post/both 전환 요청 1,200회, 동시 조회 1,285회 통과 |
| 장치 종료 경합 | 4개 조회 스레드와 close 200회, 늦은 성공·재연결·소유권 잔존 0 |
| 실제 로드된 주소의 변경 거부 | 5개 콘솔 경로를 두 번 시험, 10개 거부 및 등록 포인터/노드 수 불변 |
| 동시 파일 작업 | 185,859회 + 111,793회 = 297,652회 생성·읽기·삭제 묶음, 오류 0 |
| 실제 MCP | 13/13개 통과. 두 변경 API의 embedded NUL 거부와 상태 불변 포함 |
| 기존 분리/재연결 회귀 | 295.625초에 통과. 추가 guard 요청 10개 거부와 등록 불변, 분리 양성·재연결 음성 대조, 독립 검증 및 cleanup 통과 |
| 빌드와 자체검사 | Release 빌드 성공. timeline 28, MCP 89, console 558, commands 2,961, remote 66 및 connect 인수 검사 통과 |

500 ms는 지연 요청의 상한이다. 스케줄링과 teardown을 포함한 벽시계 완료 기한이 아니다.
첫 빌드·MCP·자체검사는 `results.json`, 수정 후 반복은 `reverify-results.json`,
개별 단언은 `run2/checks.json`, `run3/checks.json`, `mcp/checks.json`에 있다.
분리/재연결의 상세 결과는 `detach/manifest.json`과 `detach/validator.log`에 있다.
이 검사는 스냅샷 생성과 독립 검증 단계에서 앞선 실행보다 오래 걸렸으나 모두 완료했다.

2026-10-25 07:13:16 KST의 최종 확인에서 부팅 시각은 기준값인
2026-10-24 21:23:19.500 KST와 같았다. 새 System 41/1001 이벤트, 우리 프로그램의
Application 1000/1001 오류와 새 minidump가 없었다. 테스트 드라이버와 프로세스도 남지 않았다.
기존 crash dump는 보존했다. 등록 포인터 불변, 이전 포트 단절, 재로드의 기본 상태를 확인했으며
이번 시험에서 콜백 잔존은 관측하지 않았다. 세부 부팅·이벤트·자원 확인은 `host-audit.json`에 있다.

두 반복이 사용한 SHA-256:

- `KnLiveDbg.exe`: `c10e40ef17801f87767ca52b311c328963fdbb945a86928e93f001b8379ac0d4`
- `KnLiveDbgMiniFilterFixture.sys`: `b602378ba550f8c54381ebd875d4beb1e729dd4fac0e732a7c1df1120129f9ac`

최초 `run1`은 직접 `FilterUnload` 단계에서 `0x80070522`로 실패했다. 승격된 Python
프로세스에도 `SeLoadDriverPrivilege`가 활성화되어 있지 않았기 때문이다. 성공으로 세지 않았고,
fixture cleanup은 통과했다. 하네스가 직접 호출 동안만 자신의 토큰에 이미 있는 권한을 활성화하고,
`AdjustTokenPrivileges`의 반환값과 last error를 확인하며 `finally`에서 이전 상태로 복구하도록 수정했다.
시스템 정책이나 계정 권한 부여는 변경하지 않는다.
근거: [FilterUnload](https://learn.microsoft.com/en-us/windows/win32/api/fltuser/nf-fltuser-filterunload),
[AdjustTokenPrivileges](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges).

## 외부 provider에 필요한 추가 계약

지원 대상을 확장하려면 provider가 제어 진입점을 제공하고, 등록 전부터 wrapper의 코드 수명을
소유하며, pre/post와 pending I/O의 일관성을 지켜야 한다. 새 instance와 unload를 포함해
제어 소유자 종료와 실패 시 복구도 같은 커널 상태 기계에 참여해야 한다.
이 계약을 갖춘 실제 provider 없이 이름이나 주소만 허용 목록에 추가할 수는 없다.

이번 결과는 이 Windows 호스트와 무해한 테스트 provider에서 확인한 범위다.
외부 raw mutation의 안전성을 입증하거나 그 차단을 해제한 결과가 아니다.
