# Kmon 프로세스 배치 수집 검증 기록

검증 대상은 `40c5739` 이후 추가한 전체 프로세스 layout 수집·변화 비교·이미지 검증 연결이다. 날짜는 2026-09-20이며, [사용·연구 가이드](KMON_PROCESS_LAYOUTS.md)에 수집 범위와 해석을 정리했다. 드라이버 로드나 실게임핵 실행 없이 로컬 빌드, 합성 데이터, 소유한 프로세스와 비실행 이미지 매핑으로 확인했다.

## 초기 구현 검증

다음 표와 원래 산출물 목록은 `5704044` 구현 시 수행한 검사다. 후속 리뷰에서 발견한 문제와 수정 검증은 아래 별도 기록을 따른다.

| 명령 | 결과 |
| --- | --- |
| `tools/validate-process-layout.ps1 -Sanitize` | 105,065 검사, 실패 0, MSVC AddressSanitizer |
| `tools/validate-process-layout.ps1 -Configuration Debug` | 105,065 검사, 실패 0 |
| `tools/validate-analyst-features.ps1 -Sanitize` | 6,560 검사, 실패 0; 공통 JSON 저장과 PE 기준 확인 변경의 회귀 |
| `tools/validate-kmon-core.ps1 -Sanitize` | 핵심 7그룹 통과, hunting 11,326·page 54 검사 통과 |
| `tools/validate-command-audit.ps1 -Sanitize` | 파서 275,002·명령 2,037 검사 통과 |
| `tools/validate-evasion-research-ledger.ps1` | 자료 28개·기법 19개 참조 및 코드/검증 연결 통과 |
| `tools/validate-evasion-research-ledger-selftest.ps1` | 잘못된 참조·상태·경로·명령 거부 회귀 통과 |
| Release·Debug 전체 빌드 | 두 구성 모두 성공, 컴파일러·링커 경고 및 오류 없음 |
| Release·Debug `--self-test all` | 각 구성에서 timeline 28·MCP 75·console 524·명령 2,037·remote 52 검사와 connect 인자 검사 통과, 종료 코드 0 |

Release와 Debug 전체 빌드는 다음 명령으로 수행했다. 버전 증가는 사용하지 않았다. SDK/WDK는 설치된 10.0.22621.0이며 MSVC 14.44.35207을 사용했다.

```powershell
./tools/build.ps1 -Configuration Release -WindowsTargetPlatformVersion 10.0.22621.0 -TestCertificateThumbprint 8EEA6021C3DA39C71E8F998B8F6E77F572EE054C
./tools/build.ps1 -Configuration Debug -WindowsTargetPlatformVersion 10.0.22621.0 -TestCertificateThumbprint 8EEA6021C3DA39C71E8F998B8F6E77F572EE054C
./x64/Release/KnLiveDbg.exe --self-test all
./x64/Debug/KnLiveDbg.exe --self-test all
```

마지막 코드 수정 이후 두 구성을 다시 빌드하고 각각 전체 실행파일 회귀를 통과했다. 테스트 서명된 산출물을 빌드한 것이며 이 검증에서 드라이버를 설치·로드하지 않았다.

## 검사한 동작

- 구간 비교의 독립적인 페이지별 오라클: 3,000개 무작위 배치 쌍에서 각 페이지의 속성 차이와 구간 diff가 일치하는지 확인했다. 합성 데이터의 검사 횟수는 악성 표본 개수가 아니다.
- 동일 배치, 속성이 같은 영역 분할, 크기 오버플로, 겹치는 구간, 다른 주소 상한, 생성 시각·boot identity 변경, 부분 순회와 용량 제한을 검사했다.
- 소유한 메모리의 RW→RX 전환·실제 MBI 분할·해제를 수집했다. 코드 실행 없이 보호 속성만 바꾸었다. RX→RW 전환은 masking 조사 후보, 단순 executable 영역 해제는 일반 제거로 구분했다.
- 새로운 자식 프로세스는 PID를 추가 등록하지 않은 전체 프로세스 모드에서 발견·수집했고, 정상 종료 후 목록에서 제거되는 것을 확인했다.
- 초기 결과가 후속 변화에도 보존되는지, JSON 출력 중 수집이 계속되어도 안전한지, 새 파일 저장·재읽기·덮어쓰기 거부가 동작하는지 확인했다.
- 자체 실행파일을 `SEC_IMAGE_NO_EXECUTE`로 매핑하고 메모리 쪽 PE timestamp만 변경했다. 보호 속성을 복원하면 `MEM_IMAGE`와 배치 속성이 같아도 이미지 식별자 검증에서 불일치했다. 실제 Doppelgänging이나 Herpaderping을 실행한 시험은 아니다.
- 읽을 수 없는 PE와 읽을 수 있지만 식별자가 다른 PE를 구분했다. 현재 매핑과 달라진 후보는 후속 검증에 넘기지 않는다.
- `/layout-ms`, `/pid`, `/initial`, 중복 옵션, 잘못된 숫자, 추가 인자 및 `/save`의 AI·MCP 쓰기 분류를 실제 명령 진입점에서 검사했다.

## 적대적 리뷰와 수정

| 문제 | 수정과 확인 |
| --- | --- |
| JSON 출력이 진행 중인 mutable snapshot의 커서를 공유하면 수집 스레드와 경쟁 | 잠금 안에서 커서를 값으로 복사하고 출력 사본에서 pending 포인터 제거; 완료 스냅샷만 immutable 공유 |
| 분할된 영역을 행 번호로 비교하면 VirtualProtect의 정상 분할을 할당 교체로 오인 | 구간별 속성 비교와 페이지별 무작위 오라클 |
| 이미지 경로 분류용 정규화는 실제 장치 볼륨과 대소문자를 잃음 | 정확한 mapped name으로 GLOBALROOT 파일 참조 생성; 볼륨·대소문자 보존 검사 |
| PE 읽기 실패를 불일치로 취급하면 접근 제한을 tampering으로 오인 | 실패 원인 분리, metadata anchor 재확인, 열린 디스크 파일 식별자 확인 후에만 finding 생성 |
| PID 재사용 시 기존 이름·기준이 새 프로세스에 남을 수 있음 | 생성 시각 비교 후 이력 폐기, 동일 핸들에서 이미지 이름 재조회 |
| 영역 배열 인덱스가 바뀌면 주기적 후보의 순환 위치가 흔들림 | 배열 인덱스 대신 다음 VA로 재개; 변경 후보와 주기적 후보의 예산 분리 |
| MEM_FREE의 미정의 Type·AllocationBase가 이미지 이름 질의에 사용될 수 있음 | 미할당 영역의 속성은 저장·이미지 질의에서 제외 |
| RX→RW/NX 전환이 원시 diff에만 남고 조사 후보에서 빠짐 | 할당이 남는 실행 권한 상실을 후보에 포함; 일반 해제 음성 대조 |
| `/initial` 화면 요약이 최신 영역 수·나이를 표시 | 요약과 영역 목록이 같은 초기 스냅샷을 사용 |

완전 순회가 코드 전체 검증 완료로 표시되지 않도록 별도 queue/counter와 `verification_coverage`를 제공한다. 짧은 실행 구간, 보호 프로세스, 동일한 형태로 되돌아온 매핑 및 센서 자체의 신뢰 한계는 가이드에 남긴 관측 제약이다.

## 후속 적대적 리뷰

`5704044`를 기준으로 수집기와 공통 검증·영역 기록의 연결을 다시 검토했다. 아래 네 문제를 발견했고, 수정 전 코드에 회귀 검사를 먼저 추가해 실패를 확인했다.

| 심각도 | 문제와 영향 | 수정·회귀 근거 |
| --- | --- | --- |
| P1 | 큐에 들어간 뒤 같은 VA가 다른 이미지로 교체되어도 MBI 속성만 같으면 이전 파일 경로로 검증해 이미지 변조 오탐 가능 | `ProcessLayoutCandidateCurrent`가 같은 프로세스 핸들로 현재 mapped name을 확인한다. 검증 읽기 전후에도 재확인한다. 자체 실행파일 영역에 다른 모듈 이름을 붙인 stale 후보는 거부하고, 실제 이름의 후보는 기존 이미지 검증으로 전달한다. |
| P2 | 조각 시작 시에만 만료를 확인해 마지막 질의가 늦게 끝난 30초 초과 순회도 완전 스냅샷으로 승인 가능 | 게시 직전과 `Snapshot::Valid` 양쪽에서 관측 구간을 검사한다. 30,001ms 스냅샷과 초기 이력 승인은 거부하고 30,000ms 경계는 허용한다. |
| P2 | 발견 단계에서 이름으로 선택한 PID가 수집 전에 재사용되면 범위 밖의 새 인스턴스도 수집 가능 | 동일 핸들에서 얻은 이름으로 현재 범위를 다시 검사한다. 생성 시각이 다른 이전 항목을 주입한 fixture로 범위 밖 이름은 거부하고 명시적 PID 선택은 허용함을 확인한다. 실제 OS의 PID 재사용을 강제한 시험은 아니다. |
| P2 | `PAGE_EXECUTE_WRITECOPY`의 COW 속성이 공통 영역 기록에 전달되지 않아 writable/COW 증거가 불일치 | 실제 소유한 page-file 매핑을 `FILE_MAP_COPY | FILE_MAP_EXECUTE`로 열고, 분석 큐를 거친 catalog에서 writable·COW가 모두 보존되는지 확인한다. 해당 메모리의 코드는 실행하지 않는다. |

매핑 이름의 의미와 길이·실패 처리는 [Microsoft의 GetMappedFileNameW 정의](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmappedfilenamew)를 대조했다. 이름 일치는 현재 경로 관측이며 원래 section 파일 객체의 신원을 증명하지는 않는다.

수정 전에는 layout harness의 만료·범위 검사 3개가 실패했고, 실행파일 통합 검사에서는 stale mapped name과 COW 전달 검사가 실패했다. 수정 후에는 정상 이미지, 잘못된 생성 시각, 미래·만료된 후보의 대조 검사도 실행했다. 코드·잠금 순서·스레드 종료·기준 보존·경로 재확인 경계를 다시 검토했고, 이번 범위에서 추가로 재현 가능한 수정 대상은 발견하지 못했다.

| 최종 검증 | 결과 |
| --- | --- |
| Layout ASan·Debug | 각 105,075 검사, 실패 0 |
| Release·Debug 전체 빌드 | 두 구성 성공, 컴파일러·링커 경고 및 오류 없음 |
| Release·Debug `--self-test all` | 각 구성에서 timeline 28·MCP 75·console 524·명령 2,037·remote 52 및 connect 인자 검사 통과, 종료 코드 0 |
| 변경 경계 | `git diff --check`와 문서 상대 링크 확인 통과; 드라이버 로드·실게임핵 실행 없음 |

수정 후 스냅샷 근거는 `.build/process-layout/Release-asan/run-8077960da2b84bc5901132498b8018bf/`와 `.build/process-layout/Debug/run-6c1b06dbc831474bbbfb5ead38339382/`의 `initial.json`·`changed.json`이다.

후속 리뷰 산출물은 `.build/layout-review-before-{layout,build,console}.log`, `.build/layout-review-{asan,debug}.log`, `.build/layout-review-build-{release,debug}.log`, `.build/layout-review-selftest-{release,debug}.log`에 남긴다. 이 파일들은 커밋하지 않는다.

## 로컬 근거

다음 파일은 `.build` 아래의 무시된 검증 산출물이며 커밋하지 않는다.

- `.build/process-layout/Release-asan/run-0d9d221db1ed4358a762d5d38387c876/{initial,changed}.json`
- `.build/process-layout/Debug/run-91d56f1f472849eba7e65e83615ed828/{initial,changed}.json`
- `.build/layout-asan.log`, `.build/layout-debug.log`, `.build/layout-analyst-asan.log`, `.build/layout-kmon-core.log`
- `.build/layout-command-audit.log`, `.build/layout-ledger.log`, `.build/layout-ledger-selftest.log`
- `.build/layout-build-release.log`, `.build/layout-build-debug.log`, `.build/layout-selftest-release.log`, `.build/layout-selftest-debug.log`

달성 수준은 재현 가능한 로컬 검증을 갖춘 구현이다. 실환경 게임핵 탐지율·정상 JIT 오탐률·Windows 빌드별 PPL/WOW64·드라이버 연동 검증은 사용자가 수행한다. 연구 ledger의 전체 외부 검증 gate는 이번 로컬 기능 검증으로 닫지 않는다.
