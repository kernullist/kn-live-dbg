# 커널·유저 코드 연관 헌팅

`!kmon`은 수동 매핑된 커널 코드와 정상 프로세스 안에 숨은 유저 코드를 조사할 때 실행 바이트와 참조 경로를 함께 남긴다. CI 값, 파일 서명, 프로세스 이름만으로 정상 여부를 결정하지 않는다. 조사 근거는 [연구 문서](https://github.com/kernullist/kn-live-dbg/blob/v0.0.35/docs/KMON_HUNTING_RESEARCH_20260919.md), 기법별 관측 범위는 [은닉 코드 관측 범위](KMON_DETECTION_COVERAGE.md), 페이지 비교·캡처 방식은 [실행 코드 검증](KMON_DETECTION_VERIFICATION.md)에 정리했다.

현재 수집에는 TLS 기준 비교, PDB로 확인한 KCT 후보, WorkerFactory 시작 루틴이 포함된다. `!kmon surfaces`, 사건 필터·JSON 저장, `!kmon diff` 사용법과 제한은 [분석가용 가이드](KMON_ANALYST_SURFACES.md)를 참고한다. 메타데이터 차이와 실제 실행은 별도 증거다.

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
| Ps·registry·Ob·minifilter 콜백 | PDB로 확인한 실제 pre/post 함수 슬롯과 코드 경로 검증 | 객체 주소를 함수 슬롯으로 사용하지 않음. fallback 레이아웃은 재검증되지 않은 코드 후보로 구분 |
| WFP callout | classify/notify/flow-delete 후보를 42개 callout씩 순환 코드 검사 | 내부 레이아웃은 추정값. 검증된 채널 슬롯이나 통신 관계로 사용하지 않음 |
| 유저 instrumentation callback | 커널 객체와 프로세스 생성 시각을 확인한 뒤 callback 슬롯 재검증 | native x64 대상. 슬롯은 커널에서, 대상 코드는 해당 프로세스에서 읽음 |
| 스레드·APC | StartAddress, Win32StartAddress, 대기 APC의 NormalRoutine/UserRoutine 후보를 코드 검증기로 전달 | 실행 관측이 아님. APC가 처리되거나 목록이 바뀔 수 있음 |
| ETW 스택 | 최근 이벤트의 반환 주소가 놓인 페이지 비교 | 반환 주소를 함수 시작점으로 디코딩하지 않음. 과거 실행 시점의 코드 내용은 미확정 |

firmware/hive/ETW logger/ETW provider/WFP source는 분석 루프에서 5초 간격으로 하나씩 돌아간다. 다섯 source가 있으므로 지연이 없을 때 재방문 간격은 약 25초다. 전체 분석이 늦어지면 간격도 늘어난다. handler를 호출해서 반응을 확인하지 않는다.

유저 검사 후보는 이름·설치 경로에 관계없이 모든 프로세스를 포함한다. 기존 우선 대상 6개/배경 대상 2개 순환 예산을 유지하므로 동시에 전부 검사하지는 않는다. 스레드 상세 수집은 프로세스 방문당 최대 32개, 루프 경과 예산 100ms, 참조 후보 최대 128개다. 개별 장치 읽기나 PDB 작업을 시간 예산으로 선점할 수는 없다. 재개 위치는 목록 인덱스이므로 계속 생성·종료되는 스레드의 누락 가능성은 coverage로 남는다.

감시 목록의 PID·이름에 대한 참조 수집은 큰 VAD·이미지 검사가 끝나기를 기다리지 않고 분석 작업 사이에서도 순환한다. 한 번에 한 프로세스를 방문하고, 방문이 끝난 뒤 최소 2초가 지나야 다음 대상을 선택한다. 감시 목록 변경과 수집 실패도 같은 순환 예산을 사용하며 지연된 횟수만큼 몰아서 실행하지 않는다. 기존 정밀 검사의 참조 수집과 배경 프로세스 예산은 유지한다. 추가 방문의 콜백 수집은 자체 모듈 목록을 사용하고, 스레드·APC 수집도 비어 있는 목록을 완전한 목록으로 간주하지 않고 모듈 수집을 시도한다. 코드 소유권·바이트 판정은 후속 실행 참조 검증에서 수행한다. 2초는 대상별 완료 기한이 아니며 장치 읽기나 다른 분석 작업이 길어지면 방문 간격도 늘어난다.

추가 방문은 열린 프로세스 핸들의 생성 시각과 현재 감시 조건을 다시 확인한다. 명시적으로 지정한 PID는 기존 숫자 PID 조건을 유지하고, 자동 추가된 자식은 저장된 생성 시각이 일치해야 한다. 이름 조건은 Toolhelp 목록의 이름만 신뢰하지 않고 열린 핸들에서 조회한 현재 실행 파일명과 비교한다. `*.exe`·`*.sys`도 확장자를 비교하며 `*`만 모든 이름을 허용한다. 이름을 확인하지 못했거나 감시 조건이 바뀌었으면 `watch_scope_unavailable_or_changed`로 남기고 참조 수집을 건너뛴다. 새 인스턴스가 현재 이름 조건에 직접 일치하면 그 조건으로 검사할 수 있다.

선택된 모든 프로세스의 EXE/DLL 실행 섹션을 비교하고 VAD/PTE를 대조한다. 감시 이름이나 Windows 기본 프로세스 목록은 비교의 필수 조건이 아니다. PTE 검사는 방문당 테이블 128개와 숨은 범위 32개로 제한하고 PID·생성 시각별 VA 커서를 재개한다. 상위 NX/U/S, 4·5단계 페이징, 1 GiB/2 MiB 큰 페이지, PAT 및 서로 다른 VA가 공유하는 페이지 테이블을 처리한다. 페이징 모드를 확인할 수 없거나 테이블 읽기가 실패하면 해당 패스의 숨은 PTE 증거를 보류한다.

실행 영역은 첫 페이지만 캡처하는 경로에 더해 전체 범위를 4 KiB씩 순환한다. 최대 512개 범위, 분석 반복당 최대 8페이지이며 일반 실행 참조 큐가 64개 이상이면 기다린다. 마지막 관측 후 5분이 지난 범위는 만료하고 한 범위의 예약을 마친 뒤 10초 후 다시 시작한다. 용량이 찼을 때 같은 우선순위의 진행 중인 범위는 유지한다. 아직 시작하지 않았거나 예약을 마친 범위는 마지막 완료 지점 뒤의 후보부터 순환해서 교체한다. 이미지 후보는 비소유 영역 후보를 밀어내지 못하며, 비소유 후보는 진행 중인 이미지 검사도 대체할 수 있다. 반복해서 발견되는 고정된 범위 목록의 순회 진행을 회귀 검사하지만, 계속 바뀌는 목록이나 관측 사이에 사라지는 코드까지 보장하지는 않는다. 예약 횟수는 읽기 성공 횟수가 아니다.

권한 부족, boot ID/생성 시각 확인 실패, 지원하지 않는 아키텍처, 불완전한 모듈 목록은 악성 근거로 쓰지 않는다. query 핸들을 확보하지 못해도 PDB로 EPROCESS·생성 시각·DTB를 확인한 페이지는 드라이버 경로로 읽는다. 페이지 검사는 WOW64에도 적용한다. 스레드 메타데이터와 x64 정적 분기 디코딩은 별도 제약을 유지한다.

페이지 후보는 현재 PTE 권한을 확인한 물리 읽기를 우선 사용한다. 번역을 확보하지 못했지만 query가 가능한 경우 committed executable 영역을 확인하고 프로세스 읽기를 시도한다. guard 페이지의 일반 가상 읽기는 보류한다. 두 번 읽은 페이지 바이트와 캡처 전후 PFN·권한·프로세스 인스턴스를 대조한다. 실제 물리 읽기에 사용한 PFN도 함께 비교하므로 전후 번역만 같고 중간 읽기의 PFN이 다른 경우는 연결에서 제외한다. 사용한 DTB가 교체되면 경로 증거를 보류한다. PE에서 실행으로 선언하지 않은 헤더·데이터 페이지가 실제로 실행 가능한 경우는 별도 권한 증거로 남긴다.

## 사건의 의미

`cases`는 최근 30초의 관측에서 만든 조사 목록이다. 변형 코드 또는 소유 이미지가 확인되지 않은 실행 영역을 참조하는 경우를 보존한다. private RX/JIT 메모리만으로 게임핵 판정을 내리지 않는다.

- `kernel_execution_reference`: 커널 참조 경로의 변형/비소유 실행 영역.
- `user_execution_reference`: 특정 프로세스 인스턴스의 스레드·APC·계측·IAT·vtable·스택 등에서 참조한 영역.
- `kernel_executable_memory`, `user_executable_memory`: 참조가 없어도 페이지 순환에서 발견한 변형/비소유 실행 영역.
- `executable_ownership_unknown`, `executable_image_unverified`: 실행 가능한 현재 페이지를 읽었지만 모듈 목록 또는 원본 이미지 일치를 확인하지 못함.
- `image_executable_permission`: PE에서 실행으로 선언하지 않은 페이지가 실제 실행 권한을 가짐. 바이트 변조 판정과 구분.
- `cross_domain_content`: 검증된 kernel channel 슬롯의 경로와 유저 참조에서 읽은 **4096바이트 페이지 전체 SHA-256**이 같음. 페이지 내 참조 offset은 다를 수 있다.

교차 연결은 동일 boot ID, 알려진 프로세스 생성 시각과 매핑 세대, 유효한 페이지 hash, 안정적으로 재확인한 kernel 슬롯을 요구한다. zero/NOP/INT3/FF 위주 padding 페이지는 내용 연결에서 제외한다. live 수집기는 캡처 전후 번역이 모두 성공하고 PFN·실행 권한이 유지됐을 때 PFN을 남긴다. 두 관측이 1초 이내이고 PFN과 내용이 같으면 물리 페이지 관계를 표시한다. 관측 사이의 재사용, 동시 매핑 또는 통신을 증명하지는 않는다.

프로토콜, 전송 방향, 치트 행위자, 현재 RIP는 확정하지 않는다. `claim=investigation_leads`, `communication_proven=false`, `execution_observed=false`가 이 경계를 나타낸다. 스택의 원본 이벤트 시각과 현재 코드를 읽은 시각도 별도로 보존한다.

인덱스는 최대 512개 참조, 출력은 최대 128개 사건이다. 일반 페이지 후보보다 실행 참조를 먼저 보존·표시한다. 같은 우선순위의 참조는 갱신한 관측부터 표시하므로 기존 참조의 재관측도 출력 상한에 반영된다. PID 재사용, 관측한 매핑 세대 교체, 동일 슬롯의 대상 변경과 재검증 실패를 처리한다. 만료된 참조는 조회에서 빠지고 `!kmon clear`는 인덱스도 비운다. 수집 중이면 이후 관측으로 다시 채워질 수 있다. 관측 세대는 실제 allocation ID가 아니므로 관측 사이의 주소 재사용을 모두 배제할 수 없다.

캡처가 끝난 뒤 포인터 슬롯·프로세스 인스턴스·확보한 EPROCESS/DTB를 다시 확인하고 해당 경로의 참조와 주소 연결을 공개한다. 검사 중 불일치나 읽기 실패를 확인하면 앞서 준비한 참조도 함께 보류하고 이벤트를 `coverage.execution_path`로 낮춘다. 이미 읽은 바이트와 캡처 기록은 과거 관측으로 남을 수 있지만, 그 바이트를 현재 콜백 경로의 유효한 참조로 등록하지 않는다.

## 원본 기록과 replay

`coverage.channel`은 source별 상태·레이아웃·레코드 수·검증 후보 수를, `coverage.user_references`는 프로세스 인스턴스·스레드/참조 수·재개 위치를 기록한다. 실패 외의 정기 coverage는 기본 화면에서 숨겨지며 JSONL에는 남는다.

`coverage.user_reference_schedule`은 추가 방문의 대상·감시 목록 수집 상태·소요 시간을 남긴다. `source_status=attempted`는 수집 함수 호출을 뜻한다. 실제 수집 여부는 `coverage.user_references`와 `coverage.user_callbacks`에서 확인한다. 스레드 목록 순회를 완료했더라도 APC·콜백의 일시적 변화와 후속 코드 읽기 공백이 있으므로 전체 참조 검증 완료로 표시하지 않는다.

후속 실행 참조 검증은 분석 작업 경계에서 새 후보 수집 전후로 진행한다. 한 차례에 최대 128개와 75ms를 배정하고, 대기 참조가 128개 이상이거나 가장 오래된 참조가 5초 이상 기다렸으면 시간 예산을 250ms로 늘린다. 기존 30초 만료 기준은 유지한다. 개별 읽기는 선점할 수 없으므로 실제 소요 시간은 예산을 넘을 수 있다. `coverage.pipeline`의 `execution_references_peak`와 `execution_references_max_queue_wait_ms`는 대기열 최대 크기와 처리·만료 시점까지의 최대 대기 시간을 기록한다.

TI 이벤트는 분석 큐의 남은 공간만큼, 한 차례에 최대 512건을 가져온다. 큐가 가득 찼으면 원본 버퍼의 소비 위치를 유지하고, 공간이 생긴 뒤 이어서 가져온다. 종료 시에는 수집 스레드를 합류한 뒤 원본의 세션 세대와 마지막 시퀀스를 고정하고 기존 5초 반복 예산으로 잔여 이벤트를 처리한다. 개별 분석 호출은 선점하지 않으므로 실제 종료 시간은 이를 넘을 수 있다. 이후 이벤트나 다른 세대로 이 경계를 충족시키지 않는다. 원본 버퍼에서 이미 덮어쓴 이벤트는 수집 손실로, 종료 기한까지 처리하지 못한 원본 구간은 `coverage.shutdown_event`와 `shutdown_events_unanalyzed`로 남긴다.

IAT 검사는 DLL 하나의 모든 import 읽기가 끝날 때까지 다른 분석을 막지 않는다. descriptor·thunk 사이에서 기존 50ms 분석 양보 시점을 확인하고 대기 작업을 처리한다. 중단 시 미확정 hit를 되돌리고, 양보 중 예외가 나더라도 확보한 원본 파일 핸들을 닫는다. 양보 후에도 기존 파일·메모리 동일성 확인을 수행한다.

`coverage.page_candidates`는 범위·페이지 예약·만료·퇴출·거부·참조 큐 압력을, `coverage.user_pages`는 PTE 읽기 실패와 재개 VA를 기록한다. `ranges_deferred`는 현재 범위를 보호하기 위해 수용하지 못한 관측 횟수다. 잘못된 입력을 뜻하는 `ranges_rejected`와 다르며, 고유한 누락 범위 수나 별도 대기열 크기도 아니다. `coverage.image_permissions`는 비실행 PE 페이지의 검사 커서와 번역 실패를 남긴다. `coverage.executable_memory`는 소유권을 확인하지 못한 실행 페이지의 읽기 증거다.

`finding.execution_path`, `finding.executable_memory`, `finding.executable_permission`과 관련 coverage의 `hop_N_hunt_reference`는 JSON 문자열로 저장한 관측이다. `hop_N_capture_id`는 비동기 캡처 저장 결과와 연결한다. 저장 완료는 별도 `coverage.capture`에서 확인한다. `cases /json`의 주소·FILETIME은 정밀도 손실을 막기 위해 십진 문자열이다. session 확인 여부와 페이지 권한 확인 여부도 보존한다.

```powershell
.\tools\validate-kmon-hunting.ps1 -Sanitize
.\.build\kmon-hunting\Release-asan\kmon-hunting-replay.exe --replay references.jsonl
```

replay는 `hop_N_hunt_reference`를 파싱한 객체 하나를 한 줄에 둔다. `observed_ms` 오름차순, 최대 1MiB/4096행/행당 8192바이트이며 overflow와 중복 키를 거부한다. live와 같은 reducer를 사용하지만 출력은 `input_mode=offline_unverified`다. 입력의 출처나 ground truth까지 검증하지 않으며 원시 crash dump/AFF4 importer도 아니다.

## 재현 검증과 외부 비교

```powershell
.\tools\validate-kmon-hunting.ps1 -Sanitize
.\tools\validate-kmon-hunting.ps1 -Sanitize -PeSieve C:\tools\pe-sieve64.exe
python tools\validate-kmon-hunting-evidence.py .build\kmon-hunting\Release-asan\validation.json
```

PE-sieve 경로를 생략하면 외부 비교를 실행한 것이 아니다. 비교할 때는 실제 도구
버전·hash·옵션·원본 JSON과 같은 소유 fixture의 ground truth를 함께 보존한다.
이 비교는 메인 이미지 실행 페이지 컴포넌트 검사이며 전체 KMON 탐지율 순위가 아니다.
초기 비교 수치와 후속 실호스트 결과는 [검증 현황](VALIDATION.md)과 그 원문에 있다.

`validate-kmon-hunting-evidence.py --require-competitive`는 owned-fixture 형식에
**종료 코드 3**을 반환한다. 이 형식만으로 독립 감사·실전 corpus·kernel trial을
입증했다고 표시하면 거부한다. 변형·반복 assertion을 독립적인 악성 표본 수로 세지 않는다.

실제 채널 검증은 OS/PDB/CI 상태·바이너리 hash·관측 시간을 기록하고, 정상
등록/해제·PID 재사용·캡처 hash·슬롯 재검증과 coverage/loss를 확인한다.
기존 probe의 정상 KNFW 등록도 비표준 이름만으로 악성 사건이 되면 안 된다.
보호된 게임, 다른 Windows 빌드, 허가된 실제 표본 및 외부 비교에는 각각 별도
ground truth가 필요하다. 이미 수행한 소유 fixture 실호스트 검증과 이 미검증
범위를 혼동하지 않는다. [현재 체크리스트](MANUAL_TEST_CHECKLIST.md)를 참고한다.
