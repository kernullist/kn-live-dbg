# 2026-10-23 실호스트 검증

프로젝트 문서·코드와 최신 일차 자료를 검토하고, CI/HVCI 상태 판독 결함과
하이퍼바이저 인터페이스 확인 누락을 수정했다. 테스트서명 Windows 11에서
실제 드라이버를 로드하고 메모리 양성·음성 대조군을 실행했다.
연구 출처와 출력 필드 변경은 [조사 기록](RESEARCH_REFRESH_20261023.md)에 있다.

## 환경과 범위

- 시작 revision: `5481f28ade92b8087f825c80d3a657a75339ec36`, `main`, 작업 트리 변경 없음.
- Windows 11 Pro `10.0.28000`, VMware, 논리 CPU 2개, RAM 약 4GB.
- 테스트서명 활성, VBS 비활성 관측. 관리자 동의값과 보안 데스크톱값은 0.
- 기존 PC에 컴파일러/SDK/WDK가 없어 VS 2022 Build Tools 17.14, x64 MSVC/ASan,
  Windows SDK/WDK `10.0.26100`을 설치했다. 이후에도 빌드 환경은 사용할 수 있다.
- Release x64 `0.0.35`, 기존 버전 유지. WDK가 생성한 테스트 인증서로 드라이버를 서명했다.
  Authenticode 도구의 신뢰 결과는 `UnknownError`였으며, 이 호스트의 실제 드라이버 로드는 성공했다.
- 원본 증거: `C:\git\kn-live-dbg\.build\validation-20261023`.
  추가 ASan fixture 증거는 `.build\kmon-hunting\Release-asan\validation.json`에 있다.

## 수정한 결함

| 문제 | 수정과 검증 |
| --- | --- |
| 내부 `g_CiOptions`를 공개 시스템 정보 비트처럼 해석하고 여러 마스크도 잘못 사용 | `CodeIntegrityState.h`에서 공개 API와 SDK 상수를 사용. VBS/CI, KMON 플랫폼 증거와 CI 이벤트가 공유한다. 수정 전 함수를 추출한 실행 파일에서 HVCI 관련 4개 회귀가 실패했다. |
| HVCI 감사 모드를 디버그로 출력하고 UMCI 감사 상태를 enforced로 표시 | HVCI 활성·감사·엄격·IUM과 CI 디버그를 분리. UMCI 감사 출력도 별도 상태로 변경했다. |
| CI/VBS 조회 불가를 일부 JSON·콘솔·스냅샷에서 false로 출력 | 불완전 API 응답을 거부하고 unknown/null 보존. 실패 응답에 정상처럼 보이는 비트가 있어도 채택하지 않는다. |
| 최대 CPUID leaf만 보고 Microsoft 하이퍼바이저 하드웨어 기능을 해석 | `Hv#1` 인터페이스와 leaf 범위를 모두 확인한다. 미지원 인터페이스·부족한 범위·지원되는 인터페이스를 회귀 검사했다. |

이번 VMware는 `CPUID.40000001.EAX=0x31237648`(`Hv#1`)을 실제로 제공한다.
따라서 이 호스트에서 하드웨어 기능 마스크 `0x0`은 유효한 값으로 남는다.
미지원 인터페이스에서의 오류 방지는 합성 입력으로 검증했으며, 이 VM을 미지원 사례로
잘못 분류하지 않았다.

## 빌드와 회귀 검사

| 검사 | 결과 |
| --- | --- |
| Release 빌드 | 통과. 기존 코드의 C4244 경고는 남아 있다. |
| `--self-test all` | 최종 리뷰 후 통과: timeline 28, MCP catalog 89, console 557, commands 2,961, remote protocol 66 및 connect 인수 검사. |
| `validate-command-audit.ps1 -Sanitize` | 최종 리뷰 후 parser 275,002, completion 25,954, commands 2,961 통과. ASan은 standalone parser/completion 실행 파일에 적용된다. |
| `validate-kmon-core.ps1 -Sanitize` | 통과: hunting 11,326, pages 54, FP 49 및 이미지·주소 정체성·큐 검사. |
| `validate-kmon-hunting.ps1 -Sanitize` | 통과: 합성 회귀, 잘못된 replay 8개 거부 및 아래 4개 실제 자체 프로세스 대조군. |
| `git diff --check` | 통과. |

CI 회귀는 32개 비트의 독립성, 조합, 알 수 없는 옵션 보존, API 부재, 접근 거부,
반환 길이 및 구조체 길이 불일치, JSON null/false 차이, 감사/디버그 출력과
드라이버·PDB 없이 수행하는 CI 명령을 포함한다.

초기 빌드의 기존 필드 참조 누락은 수정 후 재빌드했다. 초기 통합 검사에서는
알 수 없는 옵션 경고까지 stderr가 비어 있어야 한다고 요구한 테스트 한 개가 실패했다.
경고 보존을 허용하면서 API 출처와 장치 독립성을 검사하도록 보정한 뒤 통과했다.
초기 실패 로그도 보존했으며 최종 성공으로 덮어 해석하지 않는다.

## 커밋 전 적대적 리뷰

API 반환 계약, 비트 독립성, 실패 상태, JSON 소비 계약, 콘솔·스냅샷·KMON 호출 경로와
CPUID 조회 순서를 검토했다. 추가로 발견한 문제와 처리 결과는 다음과 같다.

| 우선순위 | 문제와 재현 | 수정 |
| --- | --- | --- |
| P2 | JSON의 bool/hex-string을 nullable 값으로 바꾸고 원시 마스크 출처를 교체하면서 `v1`을 유지했다. 기존 소비자는 같은 버전에서 타입·의미 변경을 구별할 수 없다. | `kn-live-dbg.vbs.v2`로 변경하고 소비자 이전 안내를 추가했다. 활성 상태를 enforcement로 읽게 하는 `hvciEnforced`와 근거 없는 `hvciDebugMode` 필드는 제거했다. |
| P2 | VTL 포인터 읽기가 성공하면 `0x1234` 같은 비영 비커널 값도 `vbsActive=false`, `vbsActiveKnown=true`로 표시했다. | 읽기 성공과 값의 해석 가능성을 분리했다. 비영 미지원 주소는 콘솔·JSON·스냅샷 모두 unknown으로 유지하고 실제 스캐너에서 경고한다. null/커널 포인터는 기존 마커 의미를 유지한다. |
| P3 | README의 세부 설명에는 제거한 HVCI→MBEC 추정이 남아 있었고, VTL 포인터로 페이지 매핑까지 확인한다고 설명했다. | CPUID 인터페이스 조건과 관측 한계를 실제 구현에 맞게 수정했다. |

제품 코드 수정 전에 회귀 검사를 추가했다. `review-red-tests.log`에서 기존 2,891개는
통과하고 새 schema/필드 제거/잘못된 포인터 검사 3개가 실패했다. 수정 후 새 검사를
포함한 2,961개가 모두 통과했다.

- JSON 검사는 전체 문법과 중첩 객체의 정확한 멤버를 파싱한다. 14개 CI 값의
  null/false/true 타입, HVCI 활성·감사 조합, VTL 주소 경계를 확인했다.
- CPUID는 제품 수집 함수에 응답을 주입한다. presence 비트가 없거나 인터페이스 leaf가
  없을 때 조기 종료, Microsoft 공급자 문자열만 있는 비호환 인터페이스 거부, 부족한
  leaf 범위, VMware `Hv#1` 지원, 유효한 0/상위 비트 마스크 및 이전 값 잔류 부재를 검사했다.
  조건 함수 결과뿐 아니라 실제 호출한 leaf 목록도 비교했다.
- 최종 Release 빌드, 전체 self-test, command-audit의 ASan 경로를 재실행했다.
  빌드 경고는 기존 `KernelMonitor.cpp:3338`의 C4244이며 새 경고는 확인되지 않았다.
- 최종 바이너리로 `!ci options`, `!ci policy`, `!vbs`, Probe load/info,
  driver/module integrity 및 unload를 다시 실행했다. driver ABI 호환, 의심 항목 0,
  W+X/불일치 0을 확인했다. PAGE/INIT의 불완전 페이지 관측 경고는 그대로 남는다.
- 새 C# P/Invoke 관측의 `0x280207`과 콘솔·플랫폼 증거가 일치했다. 플랫폼의
  CI/UMCI/HVCI 8개 비트를 별도 마스크로 대조했다. 호스트 CPUID는 여전히
  `VMwareVMware`, 최대 leaf `0x40000010`, `Hv#1`, 유효 마스크 `0x0`이다.
- `review-cleanup-summary.json`에서 부팅 시각·부팅 설정·UAC 값 동일,
  테스트 서비스·프로세스 0개를 확인했다.

재검증 로그는 원본 증거 폴더의 `review-build`, `review-selftest-all`,
`review-command-audit`, `review-smoke` 접두사를 사용한다. 위 범위에서 미해결
리뷰 결함은 발견하지 못했다. 아래의 환경·coverage 한계는 여전히 적용된다.

## 실제 호스트 실행

별도 C# P/Invoke 조회, `!ci`, `!vbs`, `--self-test platform-query`의 CI 관측이 일치했다.

```text
raw                 = 0x280207
CI / testsign / UMCI = enabled
HVCI / audit / strict / IUM / CI debug = disabled
unknown option bits = 0x280000
```

메인 드라이버 ABI 확인, 쓰기 비활성화, Probe load/info, 드라이버 무결성,
모듈 무결성, Probe unload와 자동 메인 드라이버 정리를 실제 실행했다.
최종 Probe driver/module 의심 항목은 모두 0이며 W+X/불일치도 0이다.
PAGE/INIT의 일부 페이지 번역은 불가해 `page_queries_complete=no`와 경고를 보존했다.
이 결과를 전체 이미지 페이지 검증 완료로 해석하지 않는다.

최초 smoke의 `!driver integrity /module ...`은 잘못된 인수로 거부되었다.
정식 구문 `!driver integrity KnLiveDbgProbe`로 다시 실행한 최종 로그를 사용한다.

## 실제 탐지 대조군

`validate-process-vad.ps1`을 관리자 권한으로 실행했다. 자체 프로세스에
private-exec, RWX, large-private-exec, PE-like, wiped-PE, SEC_IMAGE,
image-RWX-section의 7개 시나리오를 생성했다.

- VAD 48개, scan 일치 18개, private executable 5개, W+X 1개.
- PE 후보 15개 중 loader-visible 12개, memory-only 3개.
- PID/EPROCESS 조회와 mappedpe 별칭 결과가 일치했다.
- 해당 VAD 실행의 `coverage_complete=true`, `cleanup_complete=true`.

KMON 이미지 검사 구성요소는 별도 자체 프로세스를 대상으로 실행했다.

| 대조군 | 이미지 변경 페이지 | 수집 완료 |
| --- | ---: | --- |
| 정상 이미지 | 0 | true |
| 실행 속성 데이터 섹션의 1바이트 변경 | 1 | true |
| `.text` 함수의 1바이트 변경 | 1 | true |
| 정상 private RX/JIT 대조군 | 0 | true |

이 표는 이미지 비교 구성요소의 결과다. 전체 KMON 이벤트 스트림, 악성 샘플 탐지율,
JIT 전체에 대한 오탐 부재 또는 외부 PE-sieve와의 비교 결과를 의미하지 않는다.

## 정리와 남은 한계

최종 조회에서 테스트 드라이버/서비스/fixture 프로세스는 0개다.
`cleanup-summary.json`의 `SameBoot`, `SameBootConfiguration`, `SameUac`는 모두 true다.
테스트 바이너리·로그와 빌드 환경은 재현을 위해 보존했다.

실제 MCP 리스너를 열어 `vbs.scan`을 호출하려던 스크립트는 자동 승인 검토에서
실행 전에 거부됐다. 제공된 사유는 `blocked by policy`뿐이다. 그 실행은 우회하지
않았고, 실제 MCP/드라이버 결합 전송 검증을 성공 목록에 포함하지 않는다.
JSON 생성 회귀와 기존 driver-free MCP catalog/remote protocol 검사는 별개로 통과했다.

이번에는 Debug 전체 빌드, HVCI 활성 호스트, Driver Verifier, 외부 KD,
장시간 게임/안티치트 오탐 검사, 실제 악성 샘플, 커널 hide/hook 양성 fixture를
검증하지 않았다. 현재 실행 증거가 모든 기능이나 전체 호스트의 정상 상태를 증명하지 않는다.
