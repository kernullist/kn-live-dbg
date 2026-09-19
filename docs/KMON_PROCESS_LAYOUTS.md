# Kmon 프로세스 메모리 배치 이력

`!kmon`을 `/pid`·`/name` 없이 시작하면 기존 프로세스와 새 프로세스의 가상 메모리 배치를 수집한다. 첫 완전 순회 결과와 최신 결과를 보관하고, 이전 결과와 달라진 할당·상태·보호 속성·매핑 종류를 기록한다. 조사·구현 기준일은 2026-09-20이다.

초기 스냅샷은 **처음 관측한 상태**다. 이미 은닉 코드가 들어간 프로세스를 정상 기준으로 승인하지 않는다. `MEM_IMAGE` 안의 코드가 바뀌면 배치가 그대로일 수 있으므로, 초기·주기적 실행 영역 후보를 기존 이미지·페이지 검증에도 전달한다.

## 사용

```text
!kmon /background
!kmon status
!kmon layouts
!kmon layouts /pid 1234
!kmon layouts /pid 1234 /initial /json /save "D:\evidence\layout-initial.json"
!kmon layouts /pid 1234 /json /save "D:\evidence\layout-current.json"
!kmon layouts /json /save "D:\evidence\layout-inventory.json"
```

PID는 십진수다. `/pid` 없는 `layouts` 출력은 프로세스별 수집 상태와 요약이며, `/pid`를 주면 영역과 직전 비교 결과가 포함된다. 화면은 영역 64개·변화 16개까지 표시한다. JSON에는 해당 프로세스의 보관된 전체 영역과 최대 256개 변화가 들어간다. `/initial`은 `/pid`와 함께 사용한다. 이 옵션에서도 `changes`는 `delta_basis=previous_to_current`에 명시한 최신 비교 결과다.

`/save`는 새 파일을 원자적으로 생성하며 기존 파일을 덮어쓰지 않는다. AI·MCP에서는 호스트 파일 쓰기 명령으로 분류한다. 스키마는 `kmon.layouts.v1`이다. 기존 `!kmon diff`는 `cases`·`surfaces` 스키마용이며 layout 파일을 받지 않는다. layout 변화는 수집기가 비교한 `changes`와 JSONL의 `finding.layout_change`에서 확인한다.

기본 재검사 목표는 각 프로세스의 순회 완료 후 5초다. 처음 시작할 때 `/layout-ms 1000`부터 `/layout-ms 60000`까지 지정할 수 있다. 실행 중 `!kmon start`는 기존 감시 대상을 확장하므로 주기를 바꾸려면 `stop` 후 다시 시작한다.

```text
!kmon /name game.exe /layout-ms 2000 /background
```

명시적 `/pid`·`/name`이 있으면 layout 수집은 현재 감시 PID·이름으로 한정한다. `*`, `*.exe`, `*.sys` 이름 규칙은 기존 감시 규칙과 같다. 전체 프로세스 모드로 시작한 세션에 이름을 추가해도 전체 수집은 유지된다. PID 0·4는 사용자 주소 공간 조사에서 제외한다. 접근할 수 없는 프로세스는 실패 상태로 남긴다.

## 수집과 비교

1. 전용 스레드가 Toolhelp 프로세스 목록을 1초 목표로 갱신한다. 커널 live의 프로세스 생성 이벤트는 다음 발견을 앞당긴다. 이벤트 폭주 시 목록 갱신 간격은 최소 200ms다. 이 수집 스레드는 드라이버·심볼 엔진을 호출하지 않는다.
2. `BootId + PID + creation FILETIME`으로 인스턴스를 구분한다. 각 수집 조각에서 핸들을 열고 생성 시각과 종료 여부를 재확인한다. PID가 재사용되면 이전 기준을 버리고 같은 핸들에서 새 이름을 조회한 뒤 현재 감시 범위와 다시 대조한다. 이름으로만 선택된 항목의 새 인스턴스가 범위 밖이면 `process_outside_scope`로 수집을 거부한다. PID 자체가 감시 범위에 있으면 새 인스턴스도 조사한다. 완전한 프로세스 목록에서 사라진 항목은 제거한다. 불완전한 목록은 종료의 증거로 사용하지 않는다.
3. `VirtualQueryEx`로 예약·커밋 영역을 모두 순회한다. 미할당 영역은 완전 순회 결과의 빈 구간으로 표현한다. `MEM_RESERVE`의 미정의 `Protect`는 0으로 정규화한다. 하나의 조각에서 최대 256회 질의·10ms, 한 tick에서 50ms를 목표로 PID를 순환한다.
4. 부분 순회의 커서를 보관하고 이어 읽는다. 주소 역행·영역 병합으로 커서가 달라졌거나 질의 실패·용량 제한·30초 만료가 발생하면 그 순회를 버리고 이전 완전 스냅샷을 유지한다. 마지막 API 호출이 늦게 끝난 경우도 게시 직전에 만료를 확인하고, core의 스냅샷 유효성 검사에서도 30초를 넘는 관측 구간을 거부한다. `ERROR_INVALID_PARAMETER`를 임의로 주소 공간 끝으로 해석하지 않는다.
5. 구간 단위로 비교한다. 동일한 속성의 영역이 분할·병합된 것만으로 변화를 만들지 않는다. 새 실행 권한, 할당을 유지한 RX→RW/NX 전환, 실행 이미지에서 다른 매핑으로의 교체, 실행 영역의 보호 속성 변경, 관측 가능한 이미지 이름 변경은 조사 후보가 된다. 정상 로더와 JIT도 같은 변화를 만들 수 있다.
6. 변경 후보 최대 4개를 먼저 전달하고 나머지 예산으로 기존 실행 영역을 VA 순서로 순환한다. 총 전달 시도는 프로세스·주기당 최대 8개다. 분석 스레드가 생성 시각·종료 여부·할당·보호 속성을 다시 확인한 후 기존 실행 페이지 스케줄러와 이미지 실행 섹션 비교에 연결한다. 관측한 `PAGE_EXECUTE_WRITECOPY`의 쓰기 가능·COW 속성을 공통 영역 기록에도 보존한다.

이미지 경로는 `GetMappedFileNameW`의 실제 장치 볼륨과 대소문자를 보존해 연다. 경로 분류용 정규화 문자열을 디스크 기준으로 사용하지 않는다. 이름을 확보한 후보는 분석 시점과 후속 메모리 읽기 전후에도 같은 핸들에서 매핑 이름을 다시 조회한다. 이름이 달라졌거나 확인할 수 없으면 이전 경로로 검증하지 않는다. 같은 주소·보호 속성으로 다른 이미지가 매핑되는 경우를 구분하기 위한 검사다. PE/PDB 식별자가 불일치한 경우에는 읽은 메타데이터를 다시 확인하고, 열린 파일의 식별자도 확인한 뒤 `finding.layout_image_identity`를 남긴다. 읽기 실패는 이 finding으로 승격하지 않는다. 이 결과는 현재 경로의 파일과 메모리의 불일치이며, 최초 section을 만든 파일 객체의 출처를 증명하지 않는다.

## 상태와 제한

`!kmon status`는 추적 수, 완료·실패 순회 수, 미완료·접근 불가 수, 가장 오래된 관측의 나이, 검증 대기·유실·재확인·거절 수를 표시한다. JSON의 `verification_mapping_checked`와 화면의 `checked`는 매핑 재확인 횟수이며 모든 이미지 바이트 검증 완료를 뜻하지 않는다. 이미지 검증 완료 여부는 기존 `coverage.image`와 페이지 coverage를 함께 확인한다.

`changes[].flags`는 다음 비트의 조합이다. 제거는 관측 구간의 제거이지 악성 코드 해결 판정이 아니다.

| 비트 | 의미 |
| --- | --- |
| `0x001` / `0x002` | 새 할당 구간 / 이전 구간 제거 |
| `0x004` / `0x008` | AllocationBase 변경 / 커밋·예약 상태 변경 |
| `0x010` / `0x020` | 보호 속성 변경 / MEM_IMAGE·MAPPED·PRIVATE 종류 변경 |
| `0x040` / `0x080` | 실행 가능으로 변경 / 실행 가능 상태에서 벗어남 |
| `0x100` / `0x200` | 이미지 매핑을 다른 할당·종류로 교체 / 양쪽에서 확인한 이미지 이름 변경 |

| 한도 | 값과 초과 시 처리 |
| --- | --- |
| 추적 프로세스 | 최대 4,096개, 초과 수 표시 |
| 단일 순회 영역 | 최대 32,768개, 초과 순회 폐기·이전 결과 유지 |
| 보관 영역 | 초기·최신·진행 중 합계 최대 262,144개, 추가 수집 실패 표시 |
| 이미지 이름 | 인스턴스별 스냅샷 최대 512개, 전체 보관 최대 8,192개, 길이 1,023자까지; 초과·실패 별도 집계 |
| 변화 보관 | 최신 비교 최대 256개, 실행 관련 후보를 우선 보관, `delta_truncated` 표시 |
| 변화 이벤트 | 주기당 최대 16개 후보; 전체 후보 수는 coverage에 보관 |
| 검증 대기열 | 최대 2,048개, 초과 유실 수 표시; 30초보다 오래된 후보 거절 |
| 분석 조각 | 최대 16개 후보·100ms 목표, 개별 API 호출을 강제 중단하지는 않음 |

스냅샷은 프로세스를 정지시키지 않고 얻은 **관측 시간 구간**이다. 동시에 모든 페이지가 그 상태였다는 보장은 없다. `started_ms`·`finished_ms`와 FILETIME `observed_at`을 함께 보관한다. 주소와 생성 시각은 JSON에서 십진 문자열로 내보내 정밀도를 보존한다.

다음 범위는 별도 근거가 필요하다.

- 두 검사 사이에만 존재한 프로세스·매핑·RX 상태와 같은 주소로 복원된 매핑은 놓칠 수 있다. 생성 이벤트와 기존 TI 캡처는 기회를 늘리지만 무손실을 보장하지 않는다.
- Doppelgänging·Herpaderping·Ghosting은 초기 관측 이전에 구성되거나 정상 `MEM_IMAGE` 형태를 유지할 수 있다. layout 차이만으로 이 기법의 이름이나 TxF rollback 이력을 확정하지 않는다.
- 첫 관측과 현재 관측이 같아도 코드 바이트가 같다는 뜻은 아니다. 주기적 실행 영역 후보·이미지 비교를 병행하지만 예산과 대기열 한도 때문에 전체 코드의 즉시 검사로 표현하지 않는다.
- PPL·종료 경쟁·권한 부족·지원하지 않는 주소 공간 질의는 coverage gap이다. layout 수집기는 이를 우회해 완전 결과를 만들지 않는다. WOW64에도 x64 질의를 사용하되 설정한 주소 상한까지 완료하지 못하면 부분 상태로 남긴다. 기존 드라이버 기반 VAD/PTE 검사는 독립적으로 유지한다.
- JIT, hotpatch, 정상 모듈 교체·업데이트, 파일 이름 변경은 분석가가 구분해야 한다. 공유 비트나 디스크 파일 하나만으로 정상·악성을 판정하지 않는다.
- `clear`는 기존 이벤트 ring을 비운다. layout 기준은 유지한다. `stop` 후 결과를 조회·저장할 수 있으며, 새 세션 시작 시 기준은 초기화된다. 종료된 프로세스의 전체 layout은 메모리에서 제거되므로 필요하면 종료 전에 `/save`한다. 이미 기록한 변화 이벤트는 기존 JSONL에 남는다.

## 조사 자료와 적용

모두 2026-09-20에 확인한 일차 자료다. 최신 분석과 오래된 기초 기법을 구분하며, 외부 연구의 탐지율을 이 구현의 성능으로 옮기지 않는다.

| 자료 | 설계에 반영한 내용 |
| --- | --- |
| [Microsoft VirtualQueryEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex), [MEMORY_BASIC_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information) | 영역 분할·보호 속성·미정의 필드를 구분한다. COW 이후에도 `MEM_IMAGE`가 유지될 수 있어 배치와 내용 검증을 분리한다. |
| [Microsoft GetMappedFileNameW](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmappedfilenamew) | 실제 매핑 이름을 수집한다. 읽지 못한 이름을 “파일 없음”으로 단정하지 않는다. |
| [hasherezade, Windows 11 24H2 Hollowing, 2025-01-27](https://hshrzd.wordpress.com/2025/01/27/process-hollowing-on-windows-11-24h2/) | 원저자의 실험은 `MEM_PRIVATE`형 RunPE와 `MEM_IMAGE`형 변형의 차이를 보여 준다. PRIVATE 여부를 탐지의 필수 조건으로 두지 않는다. |
| [Elastic, Call Stacks, 2025-06-12](https://www.elastic.co/security-labs/threat-command/call-stacks-no-more-free-passes-for-malware) | 배치 후보를 기존 실행 참조·메모리 소유권 관측에 연결한다. 스냅샷을 현재 실행 증거로 표시하지 않는다. |
| [Elastic, Immutable Illusion, 2026-02-20](https://www.elastic.co/security-labs/threat-command/immutable-illusion) | 파일 불변성 가정의 실패를 다룬 최신 연구다. 현재 파일 식별자 일치를 서명 신뢰나 최초 section 출처의 증명으로 확장하지 않는다. 이 변경이 FFI 전용 검출기라는 주장은 하지 않는다. |
| [Herpaderping 원저자 분석, 2020](https://github.com/jxy-s/herpaderping) | section 생성 시점과 디스크 내용·프로세스 알림 시점이 어긋날 수 있다. 최초 layout을 정상으로 간주하지 않고 이미지 검증을 수행한다. |
| [Elastic Process Ghosting, 2021](https://www.elastic.co/blog/process-ghosting-a-new-executable-image-tampering-attack), [Microsoft PS_CREATE_NOTIFY_INFO](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_ps_create_notify_info) | 파일 객체와 생성 시점 근거가 있어야 정확한 기법 해석이 가능하다. 이번 주기적 사용자 모드 관측의 경계를 명시한다. |

검증 명령은 `tools/validate-process-layout.ps1 -Sanitize`와 `-Configuration Debug`다. 합성 구간 오라클과 소유한 메모리·자식 프로세스·비실행 이미지 매핑을 사용한다. 실게임핵·VM·커널 동작 검증은 사용자가 수행한다. 상세 결과는 [검증 기록](KMON_PROCESS_LAYOUT_VALIDATION_20260920.md)에 남긴다.
