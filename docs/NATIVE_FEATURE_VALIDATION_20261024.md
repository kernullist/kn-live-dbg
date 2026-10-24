# 2026-10-24~25 네이티브 기능 실호스트 검증과 재부팅 분석

KMON 외의 메모리·심볼·커널 검사·프로세스 탐지·스냅샷·TI·덤프·통신 기능을
실제 실행하고, 원시 출력과 JSON을 대조했다. 도중 우리 미니필터 시험 때문에 발생한
커널 충돌을 덤프로 확인했고, 수명 보장 없는 콜백 포인터 변경 기능을 차단했다.
다른 결함은 정상·양성·실패 대조군으로 재검증했다. 아래의 통과는 명시한 실행 범위의 결과이며,
불완전한 전체 호스트 검사를 clean으로 바꾸지 않았다.

## 환경과 증거

- 시작 revision: `fc3ac13`, `main`, 작업 트리 clean.
- 재부팅 전 Windows x64 `28000.2952`, 재부팅·Windows 업데이트 후 `28000.3231`.
  VMware, 논리 CPU 2개, RAM 약 4 GiB. 업데이트 후 `appid.sys` 자체 버전은 `10.0.28000.3086`이다.
- Release x64 `0.0.35`. 기존 테스트서명 설정에서 실제 드라이버를 로드했다.
- 최종 EXE SHA-256: `fd140788e33e2a06733d00fd86e16cef0e48ad8aa51bd1e21e7cd6d8f25a650e`.
- 원시 증거: `C:\git\kn-live-dbg\.build\feature-audit-20261024`.
  대형 JSON, 덤프, 중간 실패 로그와 세션 구동 Python/PowerShell도 이 경로에 보존했다.
- `baseline/commands.json` 83개, `advanced/commands.json` 122개의 명령 실행에 더해
  `focus`, `proof`, `proof2`, `extra`, `extra2`와 별도 E2E 실행을 수행했다.
  명령 수에는 상태·도움말·실패 입력도 포함되므로 탐지 성공 건수로 사용하지 않는다.

## 재부팅 원인과 조치

**첫 비정상 재부팅은 우리 시험으로 발생했다.** 덤프 시각은 2026-10-24 21:15:13.419 KST이며,
`0xCE DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS`의 실행 주소는
`fffff807671c1000`이다. 언로드 기록의 `KnLiveDbg.sys` 베이스 `fffff807671c0000`에
export RVA `0x1000`을 더한 `KnDbgMinifilterPreCallbackNop` 주소와 정확히 일치한다.
스택은 `FLTMGR!FltpPerformPreCallbacksWorker -> <Unloaded_KnLiveDbg.sys>+0x1000`이다.
`TGitCache.exe`의 일반 파일 조회가 남아 있던 포인터를 호출한 것이며, 이 프로세스를 원인으로 돌리지 않는다.

동시에 실행하던 `mini-ops`는 우리가 만든 무해한 필터에 대해 show/disable/enable을 수행하고
콘솔을 종료하는 시험이었다. 콘솔 종료가 드라이버를 언로드하는 동안 FltMgr의 참조가 남았다.
일부 직전 로그는 재부팅 뒤 NUL로 손상돼 마지막 enable의 실행·성공 여부는 확정할 수 없다.
따라서 특정 복구 분기 하나가 원인이라고 단정하지 않는다. 덤프는 **언로드 후 콜백 호출**을 직접 증명한다.

사용자 모드 백업만으로는 새 인스턴스, 일부 쓰기 실패, 종료·강제 종료, 진행 중인 콜백의 수명을
보장할 수 없다. `!minifilter`/`!fltmgr` 및 `!callbacks`의 disable/enable과 all 변형을
공통 검사에서 쓰기 전에 거부하도록 변경했다. MCP도 동일 경로를 사용한다. 이 변경은 해당
포인터 변경 기능을 복구한 것이 아니라 **사용 불가로 전환한 안전 조치**다. 커널에서 등록 수명과
진행 중 호출의 완료를 관리하기 전에는 다시 활성화해서는 안 된다. 목록·탐지와 정식 FltLib
연결/분리 경로는 유지한다.

- 실제 필터를 연결한 채 3회 실행: 변경 명령 102회 모두 거부, 전후 등록 포인터·활성 콜백 수 동일.
  네 작업 스레드의 파일 생성/읽기/삭제 18,897회 및 세 차례 콘솔·드라이버 종료 후 I/O 통과.
- 비승격/드라이버 미연결 자체검사에서도 단일·전체·pre/post/both 및 모든 callback scope가
  장치 접근 전에 거부되는지 확인했다.
- 재현 가능한 정식 하네스에 `tools/run-minifilter-detach-e2e.ps1 -CheckMutationGuard`를 추가했다.
  구형 바이너리에 위험한 명령을 보내지 않도록 도움말에서 차단 기능을 먼저 확인한다.
- 그 뒤 21:16:40, 21:22:04, 21:23:04에는 `TrustedInstaller.exe`가 별도의 계획된 OS 업그레이드
  재부팅을 요청했다(이벤트 1074, 이유 `0x80020003`). 최종 부팅은 21:23:19였다.
- 덤프 `crash-102426-10593-01.dmp` SHA-256:
  `698406e14e8f4ab3039d437d4056e26750fbb5633750caeeff1f1769a628db14`.
  `crash-analysis.log`, `crash-driver-exports.txt`, `reboot-system-events.json`에 근거를 보존했다.
  앞서 의도적으로 만든 `advanced/os-live.dmp`는 이 충돌 덤프와 별개다.

## 수정한 문제

| 문제와 재현 | 수정 및 확인 |
| --- | --- |
| 대체 콜백을 남긴 채 `KnLiveDbg.sys`가 언로드되어 `0xCE` 재부팅 | 위의 공통 수명 검사로 raw pointer mutation을 쓰기 전에 차단한다. 목록/탐지와 지원 API를 통한 필터 연결·분리는 유지한다. |
| 관리자 토큰에 SeDebugPrivilege가 있어도 비활성 상태면 모듈 주소가 모두 0으로 반환됨 | 모듈 쿼리 전에 자기 프로세스의 권한을 활성화한다. 주소가 여전히 가려졌거나 목록이 잘렸으면 성공으로 저장하지 않는다. 같은 비활성 부모에서 기존 바이너리의 실패와 수정본의 정상 심볼을 재현했다. 권한을 제거한 자식은 명확한 unavailable을 출력하며, 부모 토큰 상태는 바뀌지 않았다. |
| 반복 언로드된 같은 드라이버 이름·주소가 스냅샷 identity를 중복시켜 저장한 파일을 `!diff`가 읽지 못함 | 끝 주소와 언로드 시간을 identity에 포함했다. 링 위치·대소문자는 identity를 바꾸지 않는다. 자체 회귀 및 실제 자기 비교 `added=0 escalated=0 removed=0` 통과. 이전 바이너리로 만든 언로드 기록과 identity 형식이 달라졌으므로 업그레이드 후 baseline을 다시 캡처한다. |
| executive callback의 PDB 부족 때문에, 독립적으로 완전한 minifilter attachment 비교까지 중지됨 | `callbacks_minifilter_coverage_complete`를 추가했다. 구형 스냅샷은 기존 전역 플래그를 사용하고, 명시적인 scoped false는 제거 판정을 막는다. 실제 분리 1건과 재연결 후 제거 0건을 독립 검증기로 확인했다. |
| 세션 시작 뒤 로드한 프로브가 `lm`에 없고, 펌웨어 핸들러가 `<non-image>`로 잘못 분류됨 | `lm`과 펌웨어 검사에서 모듈 목록을 갱신한다. 프로브 로드·언로드 및 KNFW 공급자 등록·해제를 확인했다. 핸들러와 DriverStart가 `KnLiveDbgProbe.sys`로 귀속되며 사용자 정의 공급자 경고만 남는다. |
| HAL private dispatch가 128개 제한에서 잘림 | PDB로 확인한 포인터 필드의 한도를 512개로 늘렸다. 이 호스트에서 164개 슬롯, non-null 156개, suspicious 0, coverage complete. public HAL의 PDB 부재는 여전히 incomplete로 출력한다. |
| 전체 프로세스 hunt가 동일한 VAD PDB 레이아웃을 반복 조회 | 성공한 qualified type layout만 최대 256개 캐시한다. 심볼 경로·모듈 상태 변경 때 무효화하고 실패 결과는 캐시하지 않는다. 기본 바이너리의 360초 제한 실패 뒤 수정본 E2E가 268.531초에 통과했다. 부하가 달랐으므로 정밀한 성능 향상률은 주장하지 않는다. |
| DbgEng가 초기 이벤트 처리 전에 ready를 출력하여 `vertarget`가 버전 0과 잘못된 주소를 표시 | 초기 `WaitForEvent`와 사용 가능한 커널 대상 확인 후 ready를 설정한다. 실제 버전 28000, 커널 및 모듈 목록 주소를 출력했다. |
| 없는 로컬 KD 파이프의 reconnect가 취소 요청 이후에도 대기 | 해당 로컬 파이프 서버의 존재를 먼저 확인해 즉시 오류를 반환한다. 같은 콘솔에서 뒤이어 `kdinit /local`, `kd vertarget` 성공. 일반 원격 전송의 취소 가능성을 보장하는 변경은 아니다. |
| 최신 `appid.sys`가 6.2.28000.2952로 읽혀 과거 취약 버전 범위에 들어감 | Windows 10/11 호환성 manifest를 포함했다. 동일 파일 해시에서 실제 10.0.28000.2952가 읽히고 오탐이 없어졌다. 무해한 `amdryzenmasterdriver.sys` 이름·버전 양성 대조는 유지되고 언로드 뒤 사라졌다. |
| TI `/log` 폴더가 없으면 이벤트를 수집하면서도 디스크 저장이 조용히 실패 | 중첩 폴더 생성과 로그 파일 열기를 구독 성공의 조건으로 삼았다. 쓰기 실패 수와 마지막 오류를 콘솔·MCP 통계에 추가했다. 파일을 디렉터리로 지정하면 시작 실패·inactive, 유효한 새 폴더로 다시 시작하면 저장 성공. |
| SYSTEM 실행에서 PowerShell과 Bind 도우미의 임시 루트가 다름 | 도우미가 동적으로 `GetTempPath2W`를 사용하고 구형 호스트에서는 기존 API로 fallback한다. GUID 직계 자식 경로 제한은 유지했다. SYSTEM의 실제 Bind 매핑·QoS 탐지와 정리까지 통과했다. |

minifilter 독립 검증기는 PowerShell 5.1의 dictionary 형태에서도 scoped metadata를
인식하도록 수정했다. 관련 연구 ledger의 문자열 anchor도 실제 진단과 맞췄다.

## 실제 실행 결과

| 기능군 | 실행과 검증 | 결과 및 범위 |
| --- | --- | --- |
| 메모리 읽기·쓰기 | 프로브의 알려진 4 KiB 패턴, 가상·물리 쓰기, fill/move, typed field, write off, reset | 8개 독립 바이트 비교 통과. `ef`/`eD`의 문서화된 raw-bit 입력도 별도 확인. 소수 문자열 입력은 지원 형식이 아니므로 정상 거부. |
| 심볼·주소·타입·역어셈블 | `lm`, `x`, `addr`, `ln`, `query`, `vtop`, `dt`, `dtx`, `u`, `uf`, `.reload` | 실행 출력 확인. 프로브의 로드 후 표시와 언로드 후 제거를 확인. |
| CPU·보안 상태 | `!ci`, `!vbs`, `!securekernel`, `!msrcheck`, `!cr`, `!ssdt`, `!idt`, `!hv`, `!dma` | 실제 2 CPU 및 플랫폼 출력 확인. VM의 DMA enforcement unknown 등 관측 한계 유지. |
| 커널 수집 | callbacks, ETW loggers/integrity/providers, NMI, firmware, HAL, WFP 모든 목록 및 kernel callouts | 실행 확인. KNFW 프로브 양성·제거 대조 통과. 미해결 PDB/휴리스틱 범위는 아래 한계 참조. |
| 객체·잔존물 | ALPC ports/connections, WNF decode/instances, pool summary/big/tags/PE, hive, token, DPC/timer/workitem, mapper/kpage/payload | 실제 실행. 제한된 출력과 읽기 실패·미지원 레이아웃 경고를 유지. 모든 발견을 악성으로 확정하지 않음. |
| 드라이버·프로세스 검사 | module/driver integrity, driver object/devstack, handles, hiddenproc, WdFilter, inputstack, threads, VAD | JSON과 콘솔 확인. 별도 VAD E2E 7개 시나리오 통과: PID/EPROCESS 및 alias 결과 일치, coverage와 cleanup 통과. |
| 종합 hunt | 35개 시나리오 E2E, `/quick`, Cloud Files full/deep 정상·변조 대조 | 수정본 35개 대조군 통과. Cloud Files 정상·변조 각각 baseline 및 candidate에서 반복 통과. 전체 호스트 coverage는 일부 incomplete. |
| Bind/QoS | 임시 파일·프로세스 매핑과 임시 QoS 정책 | 관리자 실행은 ACCESS_DENIED. 같은 제한 fixture를 SYSTEM에서 실행해 실제 탐지 및 제거 통과, 총 301.188초. |
| 스냅샷·미니필터 | save/show/self-diff, 실제 own fixture attach/detach/reattach | 중복 identity 오류 해소. attachment 제거 1건 및 복구 음성 대조 통과. |
| TI·타임라인 | 자기 프로세스의 PPL on/off, 생성한 자식에만 메모리 할당·쓰기·보호 변경·읽기·해제, live callbacks, query/graph/export | 수정 후 TI 실행에서 416/416건 저장, 반복에서 43/43건 저장. 각 실행의 파일에 own target 이벤트 27건 포함, dropped/ETW lost/log failed 0. 실행 코드는 주입·실행하지 않았다. 커널 타임라인 process/thread/image 이벤트 및 JSONL도 확인. |
| 덤프 | kernel/user `dump-raw`, kernel/user `dump-pe`, `dump-kernel /max 0x4000000`, `dump-analyze`, OS `dump-live` | 사용자 버퍼 4 KiB 바이트 일치, PE 헤더·섹션 출력 확인. 64 MiB 물리 payload의 zero-fill 0. OS live dump 1,332,572,160바이트를 CDB로 열어 실제 커널 버전·nt 모듈 확인. |
| 통신·보조 기능 | MCP HTTP, 실제 MCP/remote 콘솔, bridge, log enable/disable, AI model/provider/status | MCP HTTP 자체검사 9개 통과. ConPTY로 실제 서버와 클라이언트를 실행해 인증·조회·MCP 변경 거부·클라이언트 종료 후 서버 유지 8개 항목 통과. 모두 loopback만 사용했다. 외부 AI 호출 및 별도 PC의 KD 연결은 실행하지 않음. |

## 회귀 검사와 실패 기록

- 최종 Release 빌드 및 `--self-test all`: timeline 28, MCP 89, console 558,
  commands 2,961, remote protocol 66, connect 인수 검사 통과.
- `validate-command-audit.ps1 -Sanitize`: parser 275,002, completion 25,954,
  통합 commands 2,961 통과. ASan 적용 대상은 standalone parser/completion이다.
- analyst ASan 6,560개, process-layout ASan 105,120개 통과.
- minifilter, clean-host analyzer, QoS/Bind, Cloud Files, external gate 및 research ledger
  검증기 자체검사 통과. ledger 본문 검증도 통과.
- 최초 빌드의 실행 중 이미지 잠금과 중간 비승격 빌드의 PowerShell 모듈 로딩 실패는
  성공으로 세지 않았다. 최종 승격 빌드는 통과했다.
- 최초 세션의 `unload`는 정상 종료를 prompt 대기로 오인한 구동기 오류였다.
  TI 파일 검증기 역시 존재하지 않는 최상위 `target_pid`를 요구한 오류가 있어,
  실제 스키마의 `payload.TargetProcessId`로 교정하고 전체 실행을 다시 통과시켰다.
- 원격 파이프 timeout 시험에서 종료한 own controller가 남긴 서비스는 경로·프로세스
  소유를 확인한 뒤 정리했다. 수정 후 `extra2`는 강제 종료 없이 정상 종료했다.
- 업데이트 뒤 첫 `post-reboot-broad`는 종료 코드 0이었지만 모듈 주소 0으로 다수 검사가 실패했다.
  이를 통과로 세지 않았다. 권한 수정 후 `final-broad`의 83개 명령을 다시 확인했고,
  심볼 실패가 사라지며 기존 PDB/coverage 제한만 남았다.
- `proof3`의 버전 단언은 OS UBR과 `appid.sys` 파일 버전이 같다고 가정한 하네스 오류였다.
  실제 파일 버전 `10.0.28000.3086`을 독립 조회한 뒤 `proof4` 10개 항목 전체를 재통과했다.
  PowerShell의 의도된 native stderr를 예외로 취급한 중간 자체검사 래퍼도 성공으로 세지 않았다.
- `proof4`에서는 TI 49건이 모두 파일에 기록됐고, own target 이벤트 27건을 확인했다.
  `extra3`에서 raw-bit 쓰기, 사용자 메모리·PE 덤프 및 KD 실패 뒤 정상 재연결도 재통과했다.
- 실제 MCP 시험은 비대화형 파이프의 비밀번호 입력을 정상 거부했다. 가상 콘솔 구동기의
  표준 핸들 상속과 이전 프롬프트 오인 문제를 교정한 뒤 실제 MCP/remote 전체 8개 항목이 통과했다.
  중간 ConPTY 종료가 남긴 own 드라이버 서비스는 프로세스 부재·정확한 이미지 경로를 확인해 정리했다.
  MCP의 unavailable 오류가 대상 부재에 따른 백업 오류로 가려지지 않도록 백업 전에 공통 검사를 적용했다.
- 최종 바이너리로 `-CheckMutationGuard`를 포함한 미니필터 E2E를 160.562초에 통과했다.
  변경 명령 10개 모두 거부, 전후 등록 정보 동일, 실제 분리 양성·재연결 음성 대조 및 cleanup 통과.
  이어진 hunt E2E는 207.375초에 35개 시나리오를 통과했다. 양성 32개 모두 탐지했으며,
  음성 3개의 검증과 테스트 대상 정리도 통과했다.
- 2026-10-25 00:17:56 KST 최종 호스트 확인: 부팅 시각은 여전히 전날 21:23:19였고,
  이후 System 41/1001 이벤트와 우리 프로그램 관련 Application 1000/1001 이벤트는 0건이었다.
  새 minidump는 없었다. 우리 테스트 프로세스·드라이버 서비스·일반 서비스·예약 작업은 모두 0개였다.

주요 증거는 `candidate-results.json`, `offline2-results.json`,
`minifilter-revalidate.json`, `focus/checks.json`, `proof/revalidated.json`,
`proof2/checks.json`, `system-qos2/manifest.json`, `extra2/checks.json`,
`os-dump-cdb.log`, `post-reboot-results.json`, `final-results.json`,
`symbol-privilege-{old,new,removed}/checks.json`, `post-reboot-guard/checks.json`이다.
최종 빌드·자체검사는 `final5-results.json`, 가상 콘솔 결과는
`final-pty-interfaces/checks.json`과 `remote-responses.json`, 후속 E2E는 `final6-results.json`에 기록했다.
최종 E2E의 독립 검증 로그는 `final-detach/validator.log`, `final-hunt/validator.log`,
호스트 정리 및 오류 기록 확인은 `final-host-audit.json`에 보존했다.
`wrapup2-results.json` 등 재부팅 직전 일부 파일은 손상됐다. 남아 있는 validator/console 근거와
재실행 결과를 사용하며, 초기 실패·손상 증거도 그대로 보존했다.

## 남는 한계

- 미니필터·일반 커널 콜백의 raw pointer 변경 기능은 사용 불가다. 자동 복구만 추가해서
  콜백 수명 문제가 해결됐다고 주장하지 않는다.
- public HAL, executive callbacks, timer/workitem 및 WdFilter 일부 내부 타입은 현재 PDB로
  완전히 해석할 수 없다. ETW provider 열거에도 휴리스틱·미해결 부분이 남는다.
- `nt`의 디스크 비교는 동적 재배치 메타데이터 때문에 일부 incomplete다.
  kpage의 읽기 실패와 제한된 출력, 프로세스별 접근 제한도 완료로 간주하지 않았다.
- BYOVD에서는 디스크 파일 정체성을 확보할 수 없는 `dump_*` 모듈 3건이 남는다.
  외부 YARA 바이너리는 구성하지 않았고 exact 취약 드라이버를 실제로 로드하지 않았다.
- 64 MiB 제한 덤프가 DTB/모듈 목록 페이지를 포함하지 못해 offline module 열거가 0이었다.
  이 파일의 물리 범위 완료와 전체 RAM 덤프 완전성은 다른 주장이다.
- 없는 로컬 KD 파이프를 사전 거부하는 경로와 로컬 연결을 검증했다. 연결 가능한 별도
  KD 대상, 기타 원격 전송, 이미 존재하지만 응답하지 않는 서버의 timeout 보장은 미검증이다.
  DbgEng의 exit-interrupt 동작은 재연결 중인 전송에서 동일하게 보장되지 않았다.
- 외부 AI 모델 응답, 별도 PC 사이의 LAN 연결과 cloak UI는 이 실행으로 검증하지 않았다.

## 참고한 일차 자료

- [Microsoft application manifest의 supportedOS](https://learn.microsoft.com/en-us/windows/win32/sbscs/application-manifests): Windows 10/11 호환성 선언.
- [AttachKernel](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nf-dbgeng-idebugclient-attachkernel) 및 [WaitForEvent](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nf-dbgeng-idebugcontrol-waitforevent): 초기 대상 준비와 live kernel 대기 계약.
- [SetInterrupt](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nf-dbgeng-idebugcontrol3-setinterrupt): 다른 스레드에서의 exit-interrupt 계약. 실제 재연결 시험 결과와 구분했다.
- [GetTempPath2W](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-gettemppath2w) 및 [.NET Path.GetTempPath](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.gettemppath): SYSTEM 임시 루트 선택의 일치.
- [Bug check 0xCE](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0xce--driver-unloaded-without-cancelling-pending-operations): 언로드 뒤 남은 참조의 오류 의미. 실제 원인 귀속은 위의 덤프와 export 대조로 했다.
- [EnumDeviceDrivers](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumdevicedrivers): 최근 Windows의 SeDebugPrivilege 및 NULL ImageBase 계약. 이 프로젝트가 사용하는 NtQuerySystemInformation 경로의 같은 현상은 실제 비활성/제거 토큰 대조로 별도 확인했다.
