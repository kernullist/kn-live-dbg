# 커널·유저 코드 연관 헌팅

`!kmon`은 수동 매핑된 커널 코드와 정상 프로세스 안에 숨은 유저 코드를 조사할 때 실행 바이트와 참조 경로를 함께 남긴다. CI 값, 파일 서명, 프로세스 이름만으로 정상 여부를 결정하지 않는다. 조사 근거는 [연구 문서](KMON_HUNTING_RESEARCH_20260919.md), 기존 페이지 비교·캡처 방식은 [실행 코드 검증](KMON_DETECTION_VERIFICATION.md)에 정리했다.

```text
!kmon start /name game.exe /background
!kmon status
!kmon cases
!kmon cases /json
!kmon save C:\kmon-evidence\session.jsonl
!kmon stop
```

## 수집 경로

| 경로 | 실제 동작 | 제한 |
|---|---|---|
| Windows firmware table handler | PDB로 식별한 등록 노드의 handler 슬롯과 코드 경로 검증 | 링크 검증 실패·fallback 레이아웃은 사건 연결에서 제외. UEFI/SMM 검사가 아님 |
| Registry hive | GetCell, ReleaseCell, Allocate, Free 슬롯 검증 | PDB와 읽기 성공 여부를 기록. 요청의 실제 호출자를 관측한 것은 아님 |
| ETW logger clock | PDB로 찾은 64비트 callback 슬롯 검증 | clock mode와 포인터를 구분. 전체 logger 목록의 완전성은 미확정 |
| ETW provider | 기존 anchor probe의 coverage 진단 | 추정 레이아웃의 후보는 callback finding과 사건 연결에 사용하지 않음 |
| 유저 instrumentation callback | 커널 객체와 프로세스 생성 시각을 확인한 뒤 callback 슬롯 재검증 | native x64 대상. 슬롯은 커널에서, 대상 코드는 해당 프로세스에서 읽음 |
| 스레드·APC | StartAddress, Win32StartAddress, 대기 APC의 NormalRoutine/UserRoutine 후보를 코드 검증기로 전달 | 실행 관측이 아님. APC가 처리되거나 목록이 바뀔 수 있음 |
| ETW 스택 | 최근 이벤트의 반환 주소가 놓인 페이지 비교 | 반환 주소를 함수 시작점으로 디코딩하지 않음. 과거 실행 시점의 코드 내용은 미확정 |

kernel channel source는 분석 루프에서 5초 간격으로 하나씩 돌아간다. 네 source가 있으므로 지연이 없을 때 재방문 간격은 약 20초다. 전체 분석이 늦어지면 간격도 늘어난다. firmware/hive/ETW handler를 호출해서 반응을 확인하지 않는다.

유저 검사 후보는 이름·설치 경로에 관계없이 모든 프로세스를 포함한다. 기존 우선 대상 6개/배경 대상 2개 순환 예산을 유지하므로 동시에 전부 검사하지는 않는다. 스레드 상세 수집은 프로세스 방문당 최대 32개, 루프 경과 예산 100ms, 참조 후보 최대 128개다. 개별 장치 읽기나 PDB 작업을 시간 예산으로 선점할 수는 없다. 재개 위치는 목록 인덱스이므로 계속 생성·종료되는 스레드의 누락 가능성은 coverage로 남는다.

권한 부족, boot ID/생성 시각 확인 실패, 지원하지 않는 아키텍처, 불완전한 모듈 목록은 악성 근거로 쓰지 않는다. 제한된 query 핸들로 정체성을 확인할 수 있으면 드라이버의 프로세스 읽기 경로도 사용한다. query 핸들까지 확보하지 못한 프로세스의 새 참조 수집은 제한된다.

## 사건의 의미

`cases`는 최근 30초의 관측에서 만든 조사 목록이다. 변형 코드 또는 소유 이미지가 확인되지 않은 실행 영역을 참조하는 경우를 보존한다. private RX/JIT 메모리만으로 게임핵 판정을 내리지 않는다.

- `kernel_execution_reference`: 커널 참조 경로의 변형/비소유 실행 영역.
- `user_execution_reference`: 특정 프로세스 인스턴스의 스레드·APC·계측·IAT·vtable·스택 등에서 참조한 영역.
- `cross_domain_content`: 검증된 kernel channel 슬롯의 경로와 유저 참조에서 읽은 **4096바이트 페이지 전체 SHA-256**이 같음. 페이지 내 참조 offset은 다를 수 있다.

교차 연결은 동일 boot ID, 알려진 프로세스 생성 시각과 매핑 세대, 유효한 페이지 hash, 안정적으로 재확인한 kernel 슬롯을 요구한다. zero/NOP/INT3/FF 위주 padding 페이지는 내용 연결에서 제외한다. PFN을 제공한 관측은 1초 이내의 동일 PFN과 내용 일치를 별도로 표시할 수 있다. 현재 참조 경로 수집기는 PFN을 채우지 않으므로 live cases는 주소/내용 관계만 만든다. PFN 처리는 replay 관측에서 검증하며 동시 매핑이나 통신을 증명하지 않는다.

프로토콜, 전송 방향, 치트 행위자, 현재 RIP는 확정하지 않는다. `claim=investigation_leads`, `communication_proven=false`, `execution_observed=false`가 이 경계를 나타낸다. 스택의 원본 이벤트 시각과 현재 코드를 읽은 시각도 별도로 보존한다.

인덱스는 최대 512개 참조, 출력은 최대 128개 사건이다. PID 재사용, 관측한 매핑 세대 교체, 동일 슬롯의 대상 변경과 재검증 실패를 처리한다. 만료된 참조는 조회에서 빠지고 `!kmon clear`는 인덱스도 비운다. 수집 중이면 이후 관측으로 다시 채워질 수 있다. 관측 세대는 실제 allocation ID가 아니므로 관측 사이의 주소 재사용을 모두 배제할 수 없다.

## 원본 기록과 replay

`coverage.channel`은 source별 상태·레이아웃·레코드 수·검증 후보 수를, `coverage.user_references`는 프로세스 인스턴스·스레드/참조 수·재개 위치를 기록한다. 실패 외의 정기 coverage는 기본 화면에서 숨겨지며 JSONL에는 남는다.

`finding.execution_path`의 `hop_N_hunt_reference`는 JSON 문자열로 저장한 관측이다. `hop_N_capture_id`는 비동기 캡처 저장 결과와 연결한다. 저장 완료는 별도 `coverage.capture`에서 확인한다. `cases /json`의 주소·FILETIME은 정밀도 손실을 막기 위해 십진 문자열이다.

```powershell
.\tools\validate-kmon-hunting.ps1 -Sanitize
.\.build\kmon-hunting\Release-asan\kmon-hunting-replay.exe --replay references.jsonl
```

replay는 `hop_N_hunt_reference`를 파싱한 객체 하나를 한 줄에 둔다. `observed_ms` 오름차순, 최대 1MiB/4096행/행당 8192바이트이며 overflow와 중복 키를 거부한다. live와 같은 reducer를 사용하지만 출력은 `input_mode=offline_unverified`다. 입력의 출처나 ground truth까지 검증하지 않으며 원시 crash dump/AFF4 importer도 아니다.

## 재현 검증과 외부 비교

공식 PE-sieve v0.4.1.1 x64의 확인된 SHA-256:

```text
9f3ff2884a2c61006cd0a92b7572a815b8dc17012be7747a6abd6ca07c503a3b
```

```powershell
.\tools\validate-kmon-hunting.ps1 -Sanitize -PeSieve C:\tools\pe-sieve64.exe
.\tools\validate-kmon-hunting.ps1 -Configuration Debug -Sanitize -PeSieve C:\tools\pe-sieve64.exe
python tools\validate-kmon-hunting-evidence.py .build\kmon-hunting\Release-asan\validation.json
```

스크립트는 소유 fixture만 시작하고 정리한다. 드라이버 설치나 kernel callback 변경은 없다. 다음은 Kmon의 **메인 이미지 실행 페이지 비교 컴포넌트**와 PE-sieve main-image `code_scan`의 결과이며 전체 `!kmon` 탐지율 비교가 아니다.

| Ground truth | Kmon 수정 페이지 | PE-sieve code_scan |
|---|---:|---|
| 정상 이미지 | 0 | status 0 |
| 별도 executable data section의 미실행 바이트 1개 변경 | 1 | status 0 |
| 호출하지 않는 `.text` 함수의 바이트 1개 변경 | 1 | status 1 |
| 정상 private RX return stub, 호출하지 않음 | 0 | status 0 |

PE-sieve 옵션은 `/shellc 3 /iat 3 /report 7 /ofilter 2 /quiet /json`이다. 전체 보고서의 다른 DLL IAT 기록을 치트 판정이나 fixture 오탐 수로 계산하지 않는다. 실행 섹션 검사 정책의 차이도 전체 도구의 우위를 뜻하지 않는다. [공식 릴리스](https://github.com/hasherezade/pe-sieve/releases/tag/v0.4.1.1)의 버전·hash와 원본 JSON을 `validation.json`에 보존한다.

ASan 합성 검사는 boot/PID/생성 시각, stale/future 관측, hash/슬롯/세대 변경, padding, capacity와 불완전 근거를 확인한다. 변형과 stress 반복을 독립적인 게임핵 표본으로 세지 않는다.

2026-09-19 실행 결과의 바이너리·보고서 hash와 비교 요약은 [검증 기록](../research/kmon-hunting-validation-20260919.json)에 있다. source hash는 UTF-8/LF로 정규화했다. Release/Debug 각각 합성 assertion 10,275개, 명령 1,992개, 파서 ASan 275,002개를 통과했다. 일반 `--self-test all`의 console 524, timeline 28, MCP 75, remote 52 검사도 통과했다. 이 숫자는 독립적인 악성 표본 수가 아니다.

적대적 리뷰에서는 슬롯 대상 변경 후 이전 사건 잔존, 제한 query 핸들에서의 검사 누락, 포인터 field 폭/overflow, 읽기 실패 시 coverage, firmware 목록 링크 검증, replay·증거 파일 증가 중 입력 상한, 과도한 JSON 중첩, 스택 페이지의 과도한 hex 로그와 cases 자동완성을 수정했다. 수정한 범위의 재검토에서 추가 조치가 필요한 문제는 발견하지 못했으며, 실전 kernel lifetime/OS 호환성은 아래 VM 검증 범위에 남는다.

`validate-kmon-hunting-evidence.py --require-competitive`는 현재 owned-fixture 형식에서 **종료 코드 3**을 반환한다. 이 형식으로 실전 표본 수·독립 감사·kernel trial을 입증했다고 쓰면 입력을 거부한다. 실전 corpus와 동일 조건의 전체 도구 비교가 확보되어야 경쟁력 판정을 확장할 수 있다.

## 실전 검증에 남은 작업

이번 환경에는 실행 중인 KnLiveDbg 서비스나 연결된 VM 실행 도구가 확인되지 않았다. 커널 채널 통합은 빌드·리뷰까지 수행했으며 OS 빌드별 등록 목록 관측은 미실행이다. [공개 memory sample 목록](https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples)의 이전 Windows/범용 악성코드 자료는 현재 Windows 10/11 게임핵의 커널·유저 채널 ground truth를 대신하지 않는다.

1. VM의 커널/PDB/CI/HVCI 상태와 바이너리 SHA-256을 기록하고 정상 시스템의 한 source 순회 이상을 관측한다. coverage와 reference drop도 확인한다.
2. 기존 `KnLiveDbgProbe.sys`의 정상 KNFW provider를 등록/해제하며 `!fwtable`과 `coverage.channel`을 대조한다. 비표준 이름만으로 악성 사건을 만들면 실패다. PDB가 없으면 partial과 withheld slot을 기대한다.
3. 소유 fixture 네 모드의 PID/생성 시각/캡처 hash를 대조하고 시작·종료·PID 재사용 중 stale 연결이 없는지 확인한다.
4. 허가된 실제 게임핵 표본은 acquisition hash, 커널·유저 관계의 analyst label, 정상 대조군, 관측 가능 시간 구간을 갖춰 보관한다. 레이아웃·권한·손실로 관측하지 못한 항목을 정상 또는 탐지 성공으로 집계하지 않는다.
