# kmon 오탐 검토와 증거 해석

검토 기준: 2026-09-20, 시작 커밋 `fcae00a`.

`kmon`은 관측한 메모리·등록 정보·이벤트를 조사하는 도구다. 같은 현상이
정상 프로그램과 게임핵 모두에서 나타날 수 있으므로, 단일 징후나 정적
스냅샷으로 악성 여부를 확정하지 않는다. 이 문서의 통과 결과는 명시한
대조군에서 확인한 결과이며, 모든 Windows 빌드와 프로그램에서 오탐·미탐이
없다는 보증이 아니다.

## 수정한 원인

| 경로 | 기존 문제 | 수정 |
|---|---|---|
| 실행 이미지 비교 | 한 번 읽은 변경 바이트가 로더/패치 전환 중 값이어도 변경으로 승격 | 다른 바이트가 보이면 정확한 크기로 다시 읽고 동일성을 확인. 변경 후보 게시 전 PE 식별도 재확인 |
| 폐기 가능한 코드 | 드라이버 `INIT` 등 폐기되는 섹션을 영구 코드 원본처럼 비교 | `IMAGE_SCN_MEM_DISCARDABLE`은 비교 제외 범위로 기록. 깨끗한 코드로 판정하지 않음 |
| 사용자 코드 샘플 비교 | 별도 재배치 파서가 잘린 디렉터리, 창 앞쪽에 걸친 재배치, 로더 쓰기, 다른 버전의 파일을 잘못 비교 | 공통 PE/PDB·파일 식별 및 재배치/동적 재배치 검증기로 통합 |
| IAT | 일반 DLL이 다른 DLL로 export를 전달하는 정상 경로를 모듈 이름만으로 훅으로 집계 | 요청한 이름/ordinal의 export와 전달 체인을 파일·메모리 식별 후 해석. 정확한 최종 주소만 정상 전달로 인정 |
| IAT 읽기 | 전환 중인 슬롯, 이미지 밖 테이블, VA 형식 delay descriptor, 검사 중 교체되는 참조 파일 | 슬롯 재읽기, 이미지 경계, PE 식별, preferred-base VA 정규화 적용. 같은 파일 핸들로 읽고 전후 식별이 다른 결과는 철회 |
| 이미지 파일 조회 | 접근 거부 등 모든 속성 조회 실패를 파일 삭제로 해석 | 파일/경로 없음 오류만 부재로 인정 |
| 매핑 이름 조회 | API 실패와 이후 덮인 `GetLastError`로 파일 없는 매핑을 주장 | 오류를 즉시 보존하고 관측 불가 상태로 기록 |
| 드라이버 지문 | 짧은 헤더/엔트리 읽기 및 폐기된 엔트리를 다른 지문으로 비교 | 고정 길이와 재읽기 확인, 엔트리의 섹션 특성과 이미지 범위 검사 |
| 드라이버 객체 | 읽지 못한 필드의 기본값 `0`을 필드 제거로 해석 | `IdentityFieldsKnown`으로 알려진 0과 읽기 실패를 구분 |
| 반복 확인 | 이미지/객체 필드가 확인 횟수를 공유하거나 다른 바이트·객체·모듈 범위가 이전 횟수를 계승 | 증거별 카운터 분리, 동일 지문/객체 수명/주소 범위/시간 창으로 확인 |
| 재시작·재로드 | 이전 세션/언로드된 객체의 기준값이 남음 | 시작·로드·언로드 경계에서 관련 상태 초기화 |
| 모듈 소유권 | 비어 있지 않은 부분 목록 또는 갱신 실패 후 오래된 목록으로 소유자 부재를 주장 | 범위가 알려진 목록만 부재 판단에 사용. 갱신 실패는 관측 공백 |
| 커널 진입점 | 실제 수집 코드가 `PrologueKnown`을 설정하지 않아 판정기가 항상 중단 | 수집 경로 복구와 동시에 정확한 읽기/반복 확인 적용. 원본 없이 “rewritten”이라고 주장하지 않음 |
| 참조 분기 체인 | 최초 캡처를 재읽기 때도 반환하거나 루트 슬롯만 확인해 중간 코드/간접 슬롯의 전환을 놓침 | 최초 캡처는 한 번만 재사용하고 이후 실제 메모리를 읽음. 게시 직전 각 분기의 바이트와 간접 슬롯 확인 |
| 스레드 목록 | Toolhelp 중간 실패를 정상 종료로 처리하고 재사용된 TID나 식별 실패 뒤에 확인 횟수를 누적 | 열거 종료 코드 확인, ETHREAD/생성 시각 및 EPROCESS/생성 시각으로 확인. 식별 실패 시 관련 확인 상태 제거 |
| 출력 | 정상 로드·핸들·프로세스 생성·레이아웃 변화도 일괄 `finding`, 드라이버 이름은 오류 색 | 출력과 JSONL에 증거 분류를 적용하고 악성 판정이 확정되지 않았음을 명시 |

## 전체 경로 검토 범위

| 계열 | 주요 소스 | 판단 경계 |
|---|---|---|
| TI/live 수집, 드라이버·프로세스 수명주기, 핸들/IOCTL | `KernelMonitor.cpp`, `KmonHandleTracking.h` | 이벤트 사실과 악성 판정 분리. PID 수명, 손실, 미해석 경로는 별도 증거 |
| 모듈 목록/연결/서비스·파일 비대칭, 드라이버 지문/객체 | `KernelMonitor.cpp`, `IntegrityScanner.cpp` | 관측되지 않음과 부재 구분, 정상 언로드/재로드, 객체 읽기 성공, 반복 확인 |
| 인라인 진입점/INT3/분기 | `KernelMonitorInlinePatch.cpp`, `CodeTargetResolver.cpp` | 모양은 조사 단서. 알려진 대상과 안정적인 읽기만 사용하며 원본 변경 여부는 별도 비교 |
| 풀 PE/스텁/고아 페이지 | `KernelMonitorMapperPool.cpp`, `KernelMonitor.cpp` | 실행 가능, 모듈/풀 목록 범위, 읽기 성공, 바이트 패턴을 구분. 풀 목록 부재가 은닉의 증명은 아님 |
| 콜백/입력/그래픽스/SSDT/IDT/MSR/CR/HAL/NMI/DPC/타이머/작업 항목 | `KernelMonitor.cpp`와 각 scanner | 각 필드의 주소 관측과 커널 코드 검증을 연결. CPU 차이나 비정상 주소만으로 게임핵 확정 불가 |
| 펌웨어 테이블/하이브/ETW/WFP | `KernelMonitorHunting.cpp` | PDB 등록 구조와 추정 구조를 구분. 펌웨어 등록은 UEFI/SMM 검사와 다름. 통신·실행의 인과관계 미확정 |
| 숨은 프로세스/스레드 | `KernelMonitor.cpp`, `HiddenProcessScanner.cpp` | 목록 완전성, 앞뒤 열거, 보조 스냅샷 프로세스, 종료·재사용 경쟁을 구분. 교차 목록 차이는 조사 단서 |
| 사용자 EXE/PE/사설 메모리/IAT/vtable | `KernelMonitor.cpp` | JIT/RWX/COW/PE 데이터 매핑/오버레이/디버깅과 구분할 원본 증거 필요. 엔트로피가 코드 실행의 증명은 아님 |
| 실행 이미지·페이지·참조·manifest | `KernelMonitorVerification.cpp`, `ExecutableImageVerifier.cpp` | 식별한 파일, 정확한 읽기, 재배치·로더 변경, PTE/PFN·슬롯·프로세스 수명 재검증 |
| 전체 프로세스 레이아웃 | `KernelMonitorLayout.cpp`, `ProcessLayoutMonitor.cpp`, `ProcessLayoutCore.h` | 초기 상태는 정상 기준이 아님. 변경은 JIT/로더 동작일 수 있고 스냅샷은 비원자적 |
| 캡처/카탈로그/상관분석 | `KernelMonitorPipeline.cpp`, `KernelMonitorCatalog.cpp`, `KmonHunting.h` | 캡처 당시 바이트, 세대/수명, 시간·내용·PFN 관계를 보존. 같은 내용은 통신 증명이 아님 |
| 공통 출력/중복 제거 | `KernelMonitor.cpp`, `KmonEvidencePolicy.h`, `main.cpp` | 종류 식별자는 호환 유지. observation/lead/coverage/sensor를 구분하며 이름·서명으로 무조건 신뢰하지 않음 |

## 출력 계약

콘솔은 `kind [category]` 형식이다. JSONL의 `evidence.event_category`도 같은
정책을 사용한다. `observation`은 사건 또는 차이의 관측, `lead`는 분석가가
검토할 단서, `coverage`는 검사 범위, `sensor`는 관측 실패/상태다.

기존 `kind` 문자열은 유지한다. 예를 들어 `finding.code_modified`는 식별한
파일과 다른 바이트를 관측했다는 뜻이다. 정상 패치도 이 관측을 만들 수
있다. 모든 게시 이벤트에는 `maliciousness=not_established`와
`assessment_policy=evidence_v1`이 들어간다. 자동 차단기가 기존 `finding.*`
접두사를 악성 판정으로 사용해서는 안 된다.

정상 이벤트를 숨기거나 모든 탐지를 끄는 방식으로 검증 결과를 만들지
않는다. 파일 조회 실패, 짧은 읽기, 불안정한 참조는 정상 판정 대신 관측
공백으로 남기고, 실제 변경·유효한 스텁·소유자가 설명되지 않는 실행 메모리
양성 대조군은 계속 검증한다.

## 근거 자료와 운영 한계

Windows는 정상 동작으로도 다른 DLL의 export를 전달하고 IAT를 수정한다.
실행 중인 바이너리에 Hotpatch를 적용할 수도 있다. 드라이버 초기화 코드의
폐기 역시 정상 수명주기다. 따라서 위치·권한·단순 디스크 차이만으로 악성을
확정할 수 없다. 참고: [PE 형식](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format),
[Windows Hotpatch FAQ](https://learn.microsoft.com/en-us/windows/deployment/windows-autopatch/overview/windows-autopatch-faq),
[드라이버 초기화](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nc-wdm-driver_initialize),
[드라이버 페이징과 INIT](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/paging-an-entire-driver).

API-set이나 읽을 수 없는 전달 모듈처럼 export 경로를 완전히 해석하지 못한
경우는 자동 정상 처리하지 않는다. 정상 서명/이름만으로 코드를 제외하지도
않는다. 최신 정상 프로그램·보안 제품·게임 오버레이·디버거·Hotpatch가 적용된
Windows 빌드에 대한 실제 커널 검증은 사용자가 별도로 수행한다.

## 검증 기록

다음 검사는 드라이버를 설치하거나 로드하지 않고 실행했다. 빌드 환경은
Visual Studio 2022의 MSVC 14.44.35207, Windows SDK/WDK 10.0.22621.0이다.
시험 횟수는 assertion 수이며 게임핵 탐지율이나 정상 프로그램 오탐률이 아니다.

```powershell
.\tools\validate-kmon-core.ps1 -Sanitize
.\tools\validate-kmon-core.ps1 -Configuration Debug
.\tools\validate-kmon-hunting.ps1 -PeSieve .build/kmon-hunting/baseline/pe-sieve64.exe
.\tools\validate-process-layout.ps1 -Sanitize
.\tools\build.ps1 -Configuration Release -WindowsTargetPlatformVersion 10.0.22621.0 -TestCertificateThumbprint 8EEA6021C3DA39C71E8F998B8F6E77F572EE054C
.\x64\Release\KnLiveDbg.exe --self-test all
.\tools\build.ps1 -Configuration Debug -WindowsTargetPlatformVersion 10.0.22621.0 -TestCertificateThumbprint 8EEA6021C3DA39C71E8F998B8F6E77F572EE054C
.\x64\Debug\KnLiveDbg.exe --self-test all
```

인증서 지문은 이 시험 호스트의 테스트 서명 인증서다. 다른 호스트에서는 해당
호스트의 인증서를 지정해야 한다. 빌드 성공은 드라이버 로드 시험 성공을 뜻하지 않는다.

| 검사 | 결과 |
|---|---|
| 핵심 엔진 Debug / Release ASan | 각각 7개 묶음 통과 |
| 오탐 원인·증거 분류·export 전달 대조군 | 각 핵심 엔진 실행에서 49 passed / 0 failed |
| 합성 상관분석 / 실행 페이지 | 각각 11,326 / 54 passed, 실패 0 |
| 잘못된 replay 입력 | 8/8 거부 |
| 프로세스 레이아웃 ASan | 105,075 checks / 0 failures |
| 전체 타깃 x64 Release / Debug | 빌드 통과 |
| 전체 자가 검사 Release / Debug | 각 구성 timeline 28, MCP 75, console 524, commands 2,037, remote 52 통과. 명령 261개 등록 |

직접 실행한 자식 프로세스의 메인 이미지 실행 페이지 검사에서는 다음 결과를
확인했다. 각 순회는 완료됐으며, 모든 fixture는 정상 시험 프로그램이다.

| 자체 fixture | 변경 페이지 |
|---|---:|
| 원본 이미지 | 0 |
| 정상 private RX/JIT 영역 추가 | 0 |
| 실행 속성 데이터 섹션의 1바이트 변경 | 1 |
| `.text` 함수의 1바이트 변경 | 1 |

JIT 행의 0은 메인 이미지에 변화가 없다는 뜻이다. private RX 영역을 검사하지
않았다는 뜻이나, 전체 `kmon`에서 조사 단서가 없다는 뜻으로 읽으면 안 된다.
PE-sieve 0.4.1.1 결과도 함께 저장했지만 검사 범위가 다르다. 이 비교로 도구 간
오탐률·재현율의 우열을 주장하지 않는다.

리뷰는 수집/원본 비교, 객체 수명과 반복 확인, 출력/참조 재검증, 최종 변경
대조 순서로 반복했다. 첫 이미지 재읽기 회귀와 중간 분기 변경 회귀는 수정 전
실패를 확인한 뒤 수정 후 통과했다. 다른 수정은 코드 검토와 관련 대조군으로
검증했다. 마지막 변경 대조에서 추가로 확인한 파일 참조와 스레드 식별 상태도
보완했다. 최종 검토 범위에서 추가로 확정한 수정 필요 결함은 남아 있지 않다.

명령 결과, 로그·소스·바이너리 해시와 시험 범위는
[구조화된 검증 기록](../research/kmon-false-positive-validation-20260920.json)에 있다.
로컬 원본 로그는 `.build/kmon-fp-*.log`이며 커밋에 포함하지 않는다.
실제 커널 콜백, 하드웨어, 정상 보안 제품·게임·오버레이의 장시간 실행은 이번
검증 범위에 포함하지 않았다. 그 환경의 오탐 0과 미탐 0은 미입증 상태다.
