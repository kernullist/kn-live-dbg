# kmon 실행 코드 검증

`!kmon`은 이름에 관계없이 순환 선택된 모든 프로세스의 메인 EXE와 DLL, 로드된 커널 이미지의 실행 섹션을 페이지 단위로 검사한다. 실행 섹션은 PE 속성으로 선택하며, 파일의 PE/PDB 식별 정보와 재배치를 확인한 뒤 메모리 바이트와 비교한다. 이미지 밖 실행 영역의 전체 페이지와 PE 선언에 없는 실행 권한도 별도 검사한다.

```text
!kmon start /name game.exe /background /log C:\kmon-evidence
!kmon status
!kmon recent 100
!kmon cases /json
!kmon save C:\kmon-evidence\session.jsonl
!kmon stop
```

## 관측과 판정

커널·유저 연관 사건, 비 IOCTL 채널의 검사 범위와 외부 비교 절차는 [연관 헌팅](KMON_CROSS_DOMAIN_HUNTING.md)을 참고한다.

콘솔의 `[category]`와 JSONL의 `evidence.event_category`는 `observation`(관측),
`lead`(조사 단서), `coverage`(검사 범위), `sensor`(수집 상태)를 구분한다.
기존 이벤트 종류는 유지하지만 `finding.*` 접두사 자체는 악성 판정이 아니다.
모든 게시 이벤트에 `maliciousness=not_established`를 기록한다. 정상 패치,
JIT, 로더 동작도 메모리 차이를 만들 수 있다. 구체적인 수정과 대조군 결과는
[오탐 검토 기록](KMON_FALSE_POSITIVE_AUDIT_20260920.md)에 정리했다.

| 기록 | 의미 |
|---|---|
| `finding.code_modified` | 비교 가능한 실행 바이트가 로컬 참조 파일과 다름 |
| `finding.execution_path` | 콜백·디스패치·IAT 등의 분기 경로에 변조 코드 또는 소유 이미지가 확인되지 않은 실행 영역이 있음 |
| `finding.executable_memory` | 전체 영역 페이지 순환에서 변형/비소유 실행 페이지를 확인함. 실행 참조는 요구하지 않음 |
| `finding.executable_permission` | PE에서 비실행으로 선언한 페이지에 실제 실행 권한이 있음 |
| `finding.game_object` | 적용된 빌드 명세와 객체의 vptr 또는 슬롯 대상이 다름 |
| `finding.unexplained_memory` | 관측된 쓰기 이벤트로 설명되지 않는 메모리 상태. 쓰기 방식과 원인은 미확정 |
| `coverage.region` | 실행 영역 후보. PE 헤더, import stub, 쓰기 권한은 등록의 필수 조건이 아님 |
| `coverage.image_cow` | 이미지 페이지의 COW 관측. 이 속성만으로 변조나 악성을 판정하지 않음 |
| `coverage.image`, `coverage.kernel_pages` | 비교·실패·제외 범위, 순회 커서 및 완료 상태 |
| `coverage.capture*`, `coverage.pipeline` | 캡처 예약·저장 결과, 첫 바이트 지연, 큐 초과 및 수집 손실 |
| `coverage.channel`, `coverage.user_references` | firmware/hive/ETW 등록 및 프로세스 실행 참조의 관측 범위 |
| `coverage.page_candidates`, `coverage.user_pages`, `coverage.image_permissions` | 전체 범위 예약·퇴출, 사용자 PTE 재개·실패, PE/PTE 권한 검사 커서 |
| `coverage.executable_memory` | 현재 실행 페이지의 소유 이미지 또는 원본을 검증하지 못함. 읽은 바이트는 조사 자료로 보존 |
| `sensor.*` | 수집 기능의 실패나 제한 상태 |

모듈 범위에 포함된 주소도 `owned_unverified`일 수 있다. `owned_verified`는 **명시된 비교 범위**의 바이트가 일치한다는 뜻이다. 서명·파일 경로·이미지 포함 관계만으로 전체 함수의 정상성을 보증하지 않는다. 참조 파일 자체가 신뢰할 수 있는 배포본인지는 운영 환경에서 관리해야 한다.

다른 바이트를 발견하면 같은 범위를 다시 읽어 안정성을 확인하고, 변경 후보를
게시하기 전에 PE 식별도 재확인한다. 불일치·짧은 읽기·재읽기 실패는 미확인
상태로 남긴다. `INIT` 등 폐기 가능한 실행 섹션은 `discardable_section` 제외
범위이며 정상 바이트로 확인한 범위에 포함하지 않는다. IAT의 정상 export 전달은
요청한 함수 이름/ordinal과 최종 주소가 일치해야 한다. 해석할 수 없는 전달 경로를
정상으로 간주하지 않는다.

정적 분기 추적은 모듈 내부 목적지도 따라간다. 깊이 제한, 순환, 읽기 실패, 페이지 끝에서 잘린 명령, 계산할 수 없는 레지스터 목적지는 종료 이유로 남는다. 현재 분기 디코더는 native x64에 적용하며, WOW64 또는 아키텍처 확인 실패는 coverage로 남긴다. 해당 경우에도 PE 실행 페이지 비교는 계속한다. 콜백이나 vtable의 참조를 현재 RIP 실행 관측으로 표시하지 않는다.

IAT, vtable, CFG 및 그래픽스 데이터의 포인터 슬롯은 경로 검사 전후와 캡처 완료 뒤에 다시 읽는다. 값이 바뀌거나 읽을 수 없으면 해당 경로의 finding을 coverage로 낮추고 준비한 참조와 주소 연결을 보류한다. 프로세스 인스턴스와 확보한 EPROCESS/DTB의 불일치도 같은 방식으로 처리한다. 슬롯을 직접 재검증할 수 없는 참조에는 `reference_consistency=not_revalidated`를 남기며, 원래 관측 이후 생성된 매핑 세대와 연결하지 않는다.

루트 슬롯이 그대로여도 중간 분기 코드나 간접 슬롯은 바뀔 수 있다. 경로 게시
전에는 관측한 각 분기의 바이트와 간접 목적지도 다시 확인한다. 이 재읽기는
검사 도중의 일부 경쟁을 걸러내며, 전체 메모리의 원자적 스냅샷을 보장하지 않는다.

관측에는 boot ID, PID와 생성 시각, 확보한 EPROCESS/session 정보, 출처, 의존 그룹과 시각을 기록한다. 세대는 **관측된 매핑 변경을 구분하는 번호**이다. 관측 사이에서 일어난 할당 해제와 재사용까지 알아냈다는 뜻은 아니다. PFN 관계에는 가까운 관측 시각과 동일한 전체 페이지 SHA-256을 요구하며, 이것도 쓰기 주체나 동시 매핑을 확정하지 않는다.

## 수집, 캡처와 검사 예산

이벤트 수집, 메모리 캡처, 파일 저장, 분석은 별도 스레드에서 실행된다. 심벌 분석은 분석 경로에 남는다. TI와 라이브 타임라인의 도착 순번을 사용하며, 원본 링에서 놓친 구간과 내부 큐의 초과를 기록한다.

캡처는 첫 페이지를 우선 읽고 나머지를 작은 청크로 순환 처리한다. 일반 요청은 기본 256 KiB, 드라이버 이미지 요청은 최대 16 MiB이며, 세션 저장 예산은 256 MiB이다. 저장 파일은 다음 형식이다.

```text
captures\capture-<collector-pid>-<session-tick>-<capture-id>-<offset>.bin
```

`coverage.capture`의 `capture_id`, `chunk_offset`, `address`, `requested_bytes`, `capture_bytes`, `capture_sha256`, `persistence`로 청크를 연결한다. 원본 비교 바이트와 변경된 메모리 바이트는 서로 다른 캡처 ID로 저장한다. 예약 성공은 저장 성공이 아니다. 실패한 읽기, 큐 초과, 종료로 중단된 후속 청크는 부분 캡처로 취급해야 한다.

실행 영역 후보의 첫 캡처가 실패하면 이후 영역 검사에서 최소 5초 간격으로 재시도한다. 같은 세대의 첫 청크가 저장되면 재시도를 멈춘다. 재시도 상태는 최대 16,384개이며, 퇴출된 상태는 다시 캡처될 수 있다. 저장 실패로 예약한 바이트는 세션 예산에 반환한다. 종료 시 영역 메타데이터 큐를 모두 비우고 마지막 손실·검사 지표를 기록한다.

기본 상한은 TI/라이브 분석 큐 각각 2,048건, 우선 캡처와 후속 캡처 각각 256건, 저장 대기 512청크, 실행 참조 1,024건, 영역 카탈로그 16,384건이다. 카탈로그 퇴출과 큐 손실도 상태에 포함된다. 참조 캐시는 최대 2,048개이며, 용량 부족은 coverage 이벤트로 남는다.

핸들은 한 번에 8개 PID를 순환하며, 프로세스별로 128개 변경 기록의 연결을 해석한다. 사용자 정밀 검사는 우선 대상 6개와 배경 대상 2개씩 진행한다. 이미지당 16페이지, 프로세스당 8개 이미지, private heap 64페이지의 커서를 유지한다. 커널 페이지 테이블도 VA 커서로 재개한다. 그래픽스 드라이버의 writable data는 한 번에 최대 4 KiB 또는 후보 포인터 32개까지 살펴보고, 모듈 내부 목적지도 공통 검증기에 전달한다. 데이터 포인터의 존재만으로 실제 실행이나 훅을 단정하지 않는다. 이 수치는 작업량 예산이며 실시간 주기 보장은 아니다. `!kmon status`의 가장 오래 검사하지 못한 대상, 미완료 페이지, 마지막 완료 시각과 지연을 확인해야 한다.

`!kmon stop`은 수집을 멈추고 분석을 합류시킨 뒤 캡처·저장을 정리한다. 이후 iotrace를 drain/disarm하고 장치 참조를 해제한다. disarm 실패 시 장치 참조와 활성 상태를 남겨 재시도를 허용한다.

## 정확한 빌드의 객체 명세

명세는 선택 사항이다. 지정하지 않아도 범용 이미지·참조·영역 검사는 동작한다. 생성기는 x64 PE와 GUID/age가 일치하는 private PDB를 사용한다. 실행 구간, 재배치 목록, 이미지/PDB SHA-256을 저장하고, 객체 타입 크기와 vftable 심벌 및 슬롯의 함수 범위를 DIA로 확인한다. 필요한 심벌을 확인할 수 없으면 생성에 실패한다.

입력 레이아웃은 해당 빌드에서 검사할 수 있는 안정적인 객체 루트와 vptr 위치를 명시한다. 숫자는 16진수이다. `indirect=1`이면 root RVA에 객체 포인터가 들어 있고, `0`이면 객체 자체가 들어 있다. secondary vptr도 같은 객체의 별도 offset으로 지정한다.

```text
# object <name> <root-rva> <object-size> <indirect-0-or-1>
object player 12000 80 1
# vptr <object-name> <vptr-offset> <vftable-rva> <slot-count>
vptr player 0 24000 4
vptr player 20 24040 2
```

위 숫자는 형식 예시이며 실제 게임에 적용할 값이 아니다. 슬롯 허용 범위는 참조 이미지의 vftable 포인터와 PDB 함수 범위에서 생성한다. 런타임에 생성되는 임의의 힙 객체 목록을 자동으로 추정하지 않는다. 루트의 객체 수명은 게임이 보장해야 하며, 검사 중 루트나 vptr가 바뀌면 불완전 관측으로 남긴다.

```powershell
.\x64\Release\KnLiveDbg.exe --game-manifest create game.exe game.pdb layout.txt game.knmanifest
.\x64\Release\KnLiveDbg.exe --game-manifest verify game.knmanifest game.exe
```

레이아웃 대신 `-`를 주면 이미지 정보만 생성한다. 생성기는 기존 출력 파일을 덮어쓰지 않는다. 명세는 버전 1의 엄격한 텍스트 형식이며, 범위 초과·중복 객체/vptr·알 수 없는 후행 토큰을 거부한다.

```text
!kmon start /name game.exe /manifest C:\build\game.knmanifest /background
```

현재 자동 적용 대상은 감시 프로세스의 메인 이미지이다. SHA-256, PDB GUID/age, 실행 구간, 재배치 집합을 확인한 뒤 객체 규칙을 활성화한다. 불일치는 `coverage.manifest`로 남고 범용 검사는 계속한다. 슬롯이 허용 함수 범위 안에 있어도 코드 목적지 검증을 별도로 수행한다. `/manifest`는 첫 start에 지정하며 변경하려면 stop 후 다시 시작한다.

## 재현 가능한 검증

```powershell
.\tools\validate-kmon-core.ps1
.\tools\validate-kmon-core.ps1 -Configuration Debug
.\tools\validate-kmon-core.ps1 -Sanitize
.\tools\validate-kmon-manifest.ps1
.\x64\Release\KnLiveDbg.exe --self-test console
.\x64\Release\KnLiveDbg.exe --self-test timeline
```

핵심 테스트는 네이티브 File 핸들 스냅샷, 25개 PID 순환, 닫힘·재등장·PID 재사용, 장치 스택 대조군, 다중 실행 섹션과 페이지 경계 재배치, 분기 순환/읽기 실패, COW와 매핑 재사용을 검사한다. 자체 EXE의 두 번째 실행 페이지 중간 바이트를 변경했다 복구하는 시험도 포함한다.

콘솔 테스트는 자체 RX 페이지를 캡처한 뒤 원본을 해제하고, 지연시킨 저장 스레드가 원래 바이트를 보존했는지 확인한다. 명세 테스트는 실제 다중 상속 C++ EXE/PDB를 빌드해 primary·secondary vptr 명세를 생성하고, 잘못된 바이너리·PDB·문법을 거부하는지 검사한다.

적대적 리뷰에서 추가한 회귀는 다음 실패 조건을 다룬다.

- 종료 큐에 남은 600개 영역 메타데이터와 마지막 상태 기록의 누락.
- 늦게 도착한 캡처, 영역 중간의 해제, 포함 관계의 오래된 기록, 주소 재사용 후의 잘못된 참조 연결.
- 이미지 식별 실패 후 복구 시 첫 페이지를 건너뛰는 검사 커서와 동일 경로의 참조 파일 교체.
- 저장 실패 시 예산 누수, 실패한 후보 캡처의 재시도, 이미 저장한 세대의 중복 캡처.
- 실행·비실행 섹션 중첩, 짧은 헤더, 파일 밖 raw data 및 헤더와 섹션의 중첩.
- 큰 페이지 내부의 모듈 사이 빈 구간, 그 구간부터 재개하는 순회, 큰 페이지 PAT 비트와 물리 주소의 분리.
- 큰 사용자 페이지에서 VAD 빈 구간과 비실행 VAD가 섞인 경우의 기록 순서. 결과 상한 1개에서도 앞 구간을 반복하지 않고 전체 페이지를 끝까지 처리하는지 확인한다.
- 경로 검사 전 또는 도중에 변경된 포인터 슬롯과 캡처 뒤 늦게 바뀐 슬롯의 재검증.
- 용량 초과 목록에서 미완료 범위가 계속 퇴출되는 꼬리 페이지 누락, PID 재사용 시 다음 순회 차례의 변경.
- 실제 물리 읽기와 전후 번역의 PFN 모순, 상위 PS 예약 비트와 큰 페이지 예약 주소 비트의 실행 권한 오판.
- 다시 관측한 사건이 예전 위치에 남아 제한된 출력에서 빠지는 정렬 오류.
- 한 번만 바뀐 이미지 바이트, 두 번째 읽기의 실패, 폐기된 INIT와 검사 중 바뀐 PE 식별.
- 루트 슬롯은 같지만 중간 분기 코드 또는 RIP 상대 간접 슬롯이 바뀐 경로.
- 정상 export 전달과 다른 함수/ordinal, 순환·잘린 전달 문자열, 파일 조회 오류 및 반복 증거의 수명 경계.

추가로 감시 대상 변경과 종료의 로깅 제어를 직렬화하고, 객체 보고 캐시를 규칙·슬롯 수로 제한했다. 초기 수집 순번부터 링 손실을 계산하며, 명세 생성 중에는 이미지와 PDB가 교체되지 않도록 읽기 핸들을 유지한다.

2026-09-19 초기 실행 코드 검증 단계의 결과(이후 확장 결과는 [별도 기록](../research/kmon-coverage-validation-20260920.json)):

| 항목 | 결과 |
|---|---|
| 사용자 프로그램 및 테스트 타깃 x64 Release / Debug | 빌드 통과 |
| 드라이버 x64 Release / Debug | WDK 22621, `SignMode=Off` 빌드 통과 |
| 콘솔 회귀 | 각 구성 350 passed / 0 failed |
| 타임라인 회귀 | 각 구성 28 passed / 0 failed |
| MCP 회귀 | 각 구성 69 passed / 0 failed |
| 핵심 엔진 검증 | Release / Debug 각각 7개 검증 묶음 통과 |
| AddressSanitizer 핵심 엔진 검증 | x64 Release 7개 검증 묶음 통과 |
| 실제 EXE/PDB 명세 생성 및 음성 대조군 | Release / Debug 모두 통과 |

전체 페이지 순회 확장은 꼬리 페이지, 범위 갱신 시 커서 유지, PID 재사용, 큐 퇴출 우선순위, NX/U/S 상속, 큰 페이지 PAT/예약 비트, VA alias, PTE 읽기 실패, PE 권한 불일치와 소유권 미확정을 검사한다. 2026-09-20 재검토의 재현 조건과 최종 시험 결과는 [적대적 리뷰 기록](KMON_ADVERSARIAL_REVIEW_20260920.md)에 정리했다. 실제 게임, DKOM, 커널 드라이버 장치 수명주기, 세션별 win32k 매핑 및 장시간 오탐률은 사용자가 별도 시험 호스트에서 검증한다. 합성 시험과 자체 프로세스 시험 결과를 실제 게임핵 재현율로 해석하면 안 된다.
