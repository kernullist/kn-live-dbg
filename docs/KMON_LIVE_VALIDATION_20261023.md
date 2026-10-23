# 2026-10-23 KMON 실검증

실제 KMON 이벤트를 확인하는 과정에서 비등록 이미지 탐지 누락과 메모리 종류의
잘못된 분류를 재현하고 수정했다. 자체 테스트뿐 아니라 실행 중인 드라이버,
6개 사용자 프로세스 대조군, 별도 VAD 검사로 결과를 검증했다.

아래 기록에서 남은 큐 포화와 수집 손실은 [후속 개선 및 반복 검증](KMON_QUEUE_VALIDATION_20261023.md)에서 다룬다.

## 환경과 증거

- 시작 revision: `a31b1839abbe1d4fbba6547d07e8ea2123add47c`, 깨끗한 `main`.
- Windows 11 Pro `10.0.28000`, VMware, 논리 CPU 2개, RAM 약 4GB.
- 테스트서명 활성, VBS 비활성. Release x64 `0.0.35`, MSVC 14.44 및 SDK/WDK 26100.
- 증거 루트: `C:\git\kn-live-dbg\.build\kmon-live-20261023`.
- `matrix-a`: 수정 전 150초 관찰. `verified-a`와 `verified-b`: 수정 후 각각
  180초 관찰과 probe 로드. `verified-b`는 캡처·내보내기 검증을 포함한 최종 실행기다.
- `process-vad`: 별도 `!vad`, `!process scan`, `!process modules` 실검증.
- 대조군은 자체 실행 파일의 `/child` 모드로 생성했다. 메모리 변경은 대조군
  자신에게만 적용하며, RX 매핑의 테스트 바이트는 실행하지 않는다.
- raw I/O interposition은 켜지 않았다. 모든 실행 후 소유한 프로세스와 두 테스트
  드라이버 서비스를 정리했으며 재부팅은 없었다.

## 재현한 결함과 수정

### VAD 후보가 로더 소유권을 오염시킴

`ScanUserModeHostility`가 Toolhelp로 만든 모듈 목록에 파일 기반 PE VAD를 직접
추가했다. 이후 orphan 검사도 같은 목록을 사용해, 로더에 등록되지 않은
`SEC_IMAGE`까지 로더 소유로 취급했다. 수정 전 `orphan-image` PID 9036에서는
`exe_orphan_image` 이벤트가 없었다.

로더 목록을 그대로 유지하고 이미지 바이트 검사용 후보 목록만 따로 확장했다.
VAD 전용 이미지의 바이트 비교는 계속하면서, orphan·실행 참조·IAT 등의 로더
소유권 판단에는 원래 목록을 사용한다. 후보 중복, 결과 상한, 데이터 매핑 제외와
로더 목록의 불변성을 회귀 검사에 포함했다.

### 파일 기반 이미지를 private PE로 분류함

수정 전 같은 `SEC_IMAGE`에서 `private_exec_pe`를 기록했다. PE 헤더 단서를
메모리 backing 종류와 구분하지 않은 것이 원인이었다.

현재 매핑의 `MEM_IMAGE`/`MEM_MAPPED`/`MEM_PRIVATE`와 VAD private 속성을
구분한다. 확인 불가 또는 두 관측의 모순은 `section_pe`/`vad_pe` 등으로 남기며
private로 추정하지 않는다. 수정 후 이 대조군은 `image_pe`, `vad_private=0`,
`vm_type=16777216`을 기록했다. PE 단서의 요약도 실행 사실을 단정하지 않는다.

Windows의 [VirtualQueryEx 문서](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex)는
이미지·매핑·private 종류를 구분하며 COW 이후에도 이미지/매핑 종류가 유지될 수
있음을 명시한다. [Module32FirstW](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-module32firstw)의
모듈 스냅샷과 전체 VAD 후보는 서로 다른 관측으로 유지한다.

## 실제 KMON 결과

`verified-a/validation.json`과 `verified-b/validation.json` 모두 6개 대조군이
통과했다. JSONL은 각각 8,340건과 7,262건이다. 아래 시간은 각 실행에서
프로세스 생성부터 첫 기대 이벤트까지의 관측값이며,
성능 보장이나 수정 전후 속도 비교가 아니다.

| 대조군 | 기대 이벤트 | verified-a 첫 관측 | verified-b 첫 관측 |
| --- | --- | --- | --- |
| 정상 `hold` | 관련 finding/hollow/implant 없음 | 180초 관찰 통과 | 180초 관찰 통과 |
| 읽기 전용 `mapped-readonly` | 관련 finding/hollow/implant 없음 | 180초 관찰 통과 | 180초 관찰 통과 |
| 자체 `.text` 변경 `overwrite` | `finding.code_modified` | 0.319초 | 0.394초 |
| 헤더 없는 RX 매핑 | `process.implant / mapped_exec` | 88.511초 | 53.903초 |
| private PE | `process.hollow / exe_orphan_private` | 57.968초 | 85.439초 |
| 비등록 SEC_IMAGE | `process.hollow / exe_orphan_image` | 26.256초 | 24.153초 |

각 프로세스에 사용자 실행 참조 관측이 1~2회 기록됐다. 이 관측 횟수를 전체 코드
검사가 완료된 횟수로 해석하지 않는다. 두 실행 모두 SEC_IMAGE의 잘못된 private 분류는 0건이다.
정상 및 읽기 전용 대조군에는 검사한 `finding.*`, `process.hollow`,
`process.implant` 이벤트가 없었다.

번들 probe 드라이버의 `driver.drop_load`를 기록했다. `!driver integrity`는
matching=1, suspicious=0, `!module integrity`는 matching=1, suspicious=0,
wx/mismatch/iat/prologue=0이었다. 후자의 `PAGE`/`INIT` 주소 번역은 일부 확인할
수 없어 `page_queries_complete=no`와 경고를 보존했다.

첫 실행은 저장 완료 캡처 844개, 합계 3,500,032바이트의 실제 파일 길이와 SHA-256이
모두 이벤트 기록과 일치했다. 최종 실행기는 캡처 686개, 합계 2,862,464바이트와
6개 case 및 6개 layout JSON의 스키마·PID를 자동 검증하고 통과했다.
종료 시점의 case 목록은 30초 보존 기간 때문에 비어 있을 수 있으며, 앞서 발생한
탐지의 판정에는 전체 JSONL을 사용했다.

## 자동 실행기

관리자 PowerShell에서 빌드한 다음 실행한다.

```powershell
.\tools\validate-kmon-live.ps1 -ObserveSeconds 180 -ProbeDriver
```

새 증거 디렉터리에 콘솔 로그, 각 대조군 PID, case/layout, 캡처와
`validation.json`을 저장한다. 기존 테스트 서비스를 발견하면 시작하지 않는다.
PPL 전환 전에 프로세스 핸들을 보존하며, 시작 확인 로그는 즉시 파일로 전달한다.
기대 탐지 누락, 음성 대조군의 관련 탐지, 조기 종료, 캡처 해시 불일치,
내보낸 PID 불일치, 비정상 종료 또는 서비스 정리 실패는 실행 실패다.
최종 pipeline 지표를 함께 보존하며 부분 범위를 전체 성공으로 바꾸지 않는다.

초기 `baseline` 실행은 로그 복사의 버퍼링 때문에 시작 확인이 시간 초과되어
대조군을 실행하지 못했다. `matrix-a`는 실제 탐지 로그를 남겼지만
`Process.WaitForExit`가 PPL 전환 뒤 핸들을 다시 열다가 접근 거부로 실패했다.
두 실행의 실패 상태를 보존했으며, 성공한 자동 검증으로 계산하지 않았다.

## 다른 회귀와 범위 제한

| 검사 | 결과 |
| --- | --- |
| Release 빌드 | 통과. 기존 C4244 경고는 남아 있다. |
| `--self-test all` | timeline 28, MCP catalog 89, console 557, commands 2,961, remote protocol 66 및 connect 인수 검사 통과. |
| `validate-kmon-core.ps1 -Sanitize` | standalone 핵심 엔진 ASan 통과. hunting 11,326, pages 54, FP 49 및 이미지·큐·매핑 정체성 검사 통과. |
| `validate-process-vad.ps1` | 7개 실제 대조군 통과. VAD 47개, scan 일치 17개, private executable 5개, W+X 1개, PE 후보 14개. |
| VAD 교차 조회 | PID/EPROCESS 및 mappedpe 별칭 결과 일치. 로더 가시 11개, memory-only 3개. 해당 fixture의 coverage/cleanup complete=true. |

KMON 전체 호스트 범위는 **부분 관측**이다. 마지막 pipeline의 주요 제한은 다음과 같다.

| 지표 | verified-a | verified-b |
| --- | --- | --- |
| 캡처 실패 | 22 | 18 |
| layout 검증 큐 초과 / 미완료 | 1,204 / 2,032 | 1,225 / 2,048 |
| 실행 참조 용량 초과 | 108,939 | 93,836 |
| collector 손실 / TI 세션 손실 | 0 / 0 | 31 / 0 |
| 첫 캡처 최대 지연 | 3,984ms | 4,099ms |

대조군 탐지 성공으로 이러한 공백을 상쇄하지 않으며, 짧게 나타났다 사라지는
대상이나 모든 프로세스의 검사 완료를 보장하지 않는다. 최종 실행기도 이 수치를
`validation.json.final_pipeline`에 그대로 보존한다.

실제 게임·안티치트 환경의 장시간 오탐률, DKOM 양성 대조군, 숨은 커널 매퍼와
실행 중인 악성코드의 탐지율은 이번 시험으로 검증하지 않았다.
