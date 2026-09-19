# Kmon 프로세스 배치 수집 검증 기록

검증 대상은 `40c5739` 이후 추가한 전체 프로세스 layout 수집·변화 비교·이미지 검증 연결이다. 날짜는 2026-09-20이며, [사용·연구 가이드](KMON_PROCESS_LAYOUTS.md)에 수집 범위와 해석을 정리했다. 드라이버 로드나 실게임핵 실행 없이 로컬 빌드, 합성 데이터, 소유한 프로세스와 비실행 이미지 매핑으로 확인했다.

## 검증 경로

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

수정 후 코드·스레드 수명·실패 경로·export 경계를 다시 검토했고, 이번 검토 범위에서 추가로 재현 가능한 수정 대상은 발견하지 못했다. 완전 순회가 코드 전체 검증 완료로 표시되지 않도록 별도 queue/counter와 `verification_coverage`를 제공한다. 짧은 실행 구간, 보호 프로세스, 동일한 형태로 되돌아온 매핑 및 센서 자체의 신뢰 한계는 가이드에 남긴 관측 제약이다.

## 로컬 근거

다음 파일은 `.build` 아래의 무시된 검증 산출물이며 커밋하지 않는다.

- `.build/process-layout/Release-asan/run-0d9d221db1ed4358a762d5d38387c876/{initial,changed}.json`
- `.build/process-layout/Debug/run-91d56f1f472849eba7e65e83615ed828/{initial,changed}.json`
- `.build/layout-asan.log`, `.build/layout-debug.log`, `.build/layout-analyst-asan.log`, `.build/layout-kmon-core.log`
- `.build/layout-command-audit.log`, `.build/layout-ledger.log`, `.build/layout-ledger-selftest.log`
- `.build/layout-build-release.log`, `.build/layout-build-debug.log`, `.build/layout-selftest-release.log`, `.build/layout-selftest-debug.log`

달성 수준은 재현 가능한 로컬 검증을 갖춘 구현이다. 실환경 게임핵 탐지율·정상 JIT 오탐률·Windows 빌드별 PPL/WOW64·드라이버 연동 검증은 사용자가 수행한다. 연구 ledger의 전체 외부 검증 gate는 이번 로컬 기능 검증으로 닫지 않는다.
