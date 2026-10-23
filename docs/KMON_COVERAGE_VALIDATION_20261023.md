# KMON 미완료 검사와 읽기 공백 개선 — 2026-10-23

이 문서는 `9e40ce9` 이후 남은 검사와 캡처 공백을 추적한 기록이다.
원본 증거는 `C:\git\kn-live-dbg\.build\kmon-coverage-20261023`에 있다.
이전 비교 기준은 `.build\kmon-queue-20261023\final-b`의 180초 실행이다.
동일한 Windows 11 VMware 호스트, 논리 CPU 2개, RAM 약 4GB에서 실행했다.

## 원인과 변경

1. **드라이버 대체 읽기에 EPROCESS가 없었다.** 이전 14개 실패 요청 중
   13개는 smss/csrss/wininit의 이미지였다. 생성 시각은 있지만 EPROCESS는 0인
   관측 정체성을 전달해 `ReadProcessVirtual`의 필수 인수 검사에서 거절됐다.
   프로세스 주소 문맥을 해석하고 커널 생성 시각이 관측값과 같은지 확인한 뒤
   대체 읽기를 수행한다. 이미지 비교 및 실행 참조의 같은 경로도 수정했다.
   드라이버의 EPROCESS·생성 시각 검증은 유지한다.
2. **16 KiB 묶음의 한 페이지 실패가 뒤쪽 전체를 막았다.** probe 이미지의
   이전 캡처는 RVA `0x5000`에서 중단됐다. 이 묶음에는 PAGE 영역과 INIT가 함께
   있었다. 페이지 경계 안에서 읽고, 일반 읽기 공백 뒤도 계속 방문하도록 했다.
   실제로 PAGE의 `0x5000`, `0x6000`을 추가 수집했다. 정체성이나 관측 매핑이
   바뀌면 계속 읽지 않는다. 확인된 guard/noaccess/미커밋 영역은 읽지 않는다.
3. **종료가 접수된 작업을 남겼다.** 이전 기준 실행은 layout 222개와 실행 참조
   64개를 남겼다. 이번 중간 `candidate-a`에서는 원본 이벤트 1,534개도 분석 없이
   종료 로그에만 보관됐다. 생산자와 분석 스레드가 끝난 뒤 원본 이벤트를 정상
   분석 경로로 처리하고, 최신 정체성·매핑을 재검증하며 layout/참조를 처리한다.
   각 단계의 5초 작업 예산을 넘으면 잔여와 원본을 공개한다. 캡처·저장 스레드를
   기다리는 동안에도 결과 큐를 처리하며, 저장이 밀릴 때 생산 속도를 제한한다.
4. **이미지 비교의 진척을 늘렸다.** layout 방문당 비교 예산을 4페이지에서
   8페이지로 늘렸다. 항목 사이의 25ms 예산과 기존 순환 위치를 유지한다.

`coverage.capture_result`에 요청별 수집·실패·제외·미순회 바이트를 기록한다.
기존 `capture_failures`는 공백이 있는 요청의 집계로 유지했다. 실제 읽기 실패와
알려진 접근 불가는 별도 지표로 분리했다. 실패를 0으로 만들기 위해 공백을
삭제하거나 전체 범위를 완료로 표시하지 않는다.

읽기 범위의 일부가 접근 불가능하면 전체 요청이 실패할 수 있다는 것은
[ReadProcessMemory 문서](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory)와 일치한다.
미커밋 예약 공간의 의미는 [MEMORY_BASIC_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information),
폐기 가능 섹션 플래그는 [PE 형식](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)을 확인했다.
커널 읽기 실패가 반드시 악성 변경을 의미하지 않는다는 점은
[MmCopyMemory 문서](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-mmcopymemory)의 수명·상주성 제약과 함께 해석했다.

## 검증 조건

정상 `hold`, 읽기 전용 매핑 `mapped-readonly`, 자체 `.text` 변경 `overwrite`,
헤더 없는 실행 매핑 `orphan-mapped-rx`, private PE `orphan-private`, 로더 비등록
SEC_IMAGE `orphan-image`를 각각 직접 실행했다. probe 드라이버도 로드·해제했다.
각 실행의 관찰 시간은 180초다.

`-RequireQueueHealth -RequireCompletedWork`로 다음을 검사한다.

- 4개 양성 대조군의 기대 탐지와 2개 정상 대조군의 finding/hollow/implant 부재.
  overwrite는 해당 테스트 실행 파일의 `finding.code_modified`를 요구한다.
- 이벤트 및 내부 큐 탈락, 참조 만료, 커서 퇴출 0.
- 종료 시 원본·layout·참조·캡처 대기 0, 분석 없이 보관한 원본 이벤트 0.
- 요청별 requested = compared + failed + skipped, 미순회 바이트 0.
  요청별 수집 바이트 합계를 실제 저장 청크와 대조한다.
- 모든 저장 완료 청크의 크기·SHA-256, case/layout 내보내기 각 6개의 스키마·PID.
- 콘솔 정상 종료, 테스트 서비스 해제, 동일 부팅 상태.

접수된 작업을 시도했다는 것과 전체 주소 공간을 검증했다는 것은 구분한다.
정체성·매핑 재검증에서 거부된 후보도 별도 집계하며, 알려진 접근 불가 영역은
완료된 순회에도 partial로 남긴다.

## 결과

최종 `final-b`, `final-c`는 동일한 빌드의 반복 실행이다. `candidate-a`와
`final-a`는 종료 원본 이벤트 분석을 추가하기 전의 중간 계측이며 최종 근거에서
제외한다. 두 최종 실행은 기본 대조군과 강화 조건을 모두 통과했다.

| 지표 | 이전 final-b | 최종 B | 최종 C |
| --- | ---: | ---: | ---: |
| 대조군 결과 | 6/6 | 6/6 | 6/6 |
| 서로 다른 대조군 이미지 비교 페이지 합계 | 2,584 | 3,526 | 3,710 |
| 저장 검증 바이트 | 2,269,184 | 11,444,224 | 12,122,112 |
| 저장 검증 청크 | 543 | 2,796 | 2,963 |
| 종료 layout / 참조 대기 | 222 / 64 | 0 / 0 | 0 / 0 |
| 이벤트 및 검사 큐 손실 | 0 | 0 | 0 |
| 종료 원본 이벤트 분석 / 미분석 | 미계측 / 0 | 90 / 0 | 1,333 / 0 |
| 드라이버 대체 읽기 성공 페이지 | 인수 누락으로 실패 | 2,408 | 2,408 |
| 공백이 있는 캡처 요청 | 14 | 14 | 14 |
| 실제 읽기 오류 요청 / 바이트 | 사유 구분 없음 | 1 / 12,288 | 1 / 12,288 |
| 확인된 접근 불가 바이트 | 미계측 | 212,992 | 212,992 |
| 매핑·정체성 재검증 거부 후보 | 0 | 3 | 0 |

페이지 합계는 6개 대조군 각각에서 `coverage.region`의
`source=executable_page_compare`, `compared_bytes>0`인 서로 다른 주소를 세어
합산한다. 같은 페이지의 반복 비교 횟수나 저장 청크 수를 검사 범위로 세지 않는다.
기준보다 각각 36.5%, 43.6% 넓은 이미지 페이지를 비교했다. 결과는 반복마다
선택된 이미지와 스케줄링에 따라 달라지므로 전체 호스트 처리량의 배수로 해석하지 않는다.

| 기대 탐지까지의 시간 | 최종 B | 최종 C |
| --- | ---: | ---: |
| 자체 `.text` 변경 | 0.702초 | 2.206초 |
| 헤더 없는 실행 매핑 | 69.279초 | 107.983초 |
| private PE | 66.722초 | 69.735초 |
| 로더 비등록 SEC_IMAGE | 69.550초 | 70.097초 |

처리 범위가 넓어졌지만 모든 탐지의 지연이 줄었다고 주장하지 않는다.

## 남은 공백

두 최종 실행 각각의 캡처 공백 14개 중 13개는 읽기 가능한 이미지 본문 수집 후 확인된
미커밋 꼬리 영역이다. 각 16 KiB, 총 212,992바이트이며 실제 읽기를 시도하지
않고 제외 범위를 기록했다. 나머지 1개 요청의 3페이지(12,288바이트)는 probe의
RVA `0x7000`, `0x8000`, `0x9000`에서 읽기 오류 998을 반환했다. 이 주소는
바이너리에서 DISCARDABLE 플래그가 있는 INIT, .rsrc, .reloc와 일치한다.
수집 불가능한 바이트를 원본 파일 바이트로 대체해 메모리 증거로 취급하지 않았다.

이미지 캐시에 있는 전체 순환 검사는 계속 partial이다. 최종 B/C의
`image_remaining_pages=198677/198087`은 0이 아니며, 대기열 완료만으로 이 값의 완료를
주장하지 않는다. 대조군 기대 탐지 4개를 관찰했고 정상 대조군의 오탐은 없었으나,
모든 짧은 수명 매핑·경로 및 다른 워크로드의 무누락·무오탐을 보장하지 않는다.

## 회귀 검사와 정리

Release 빌드와 `--self-test all`을 통과했다: timeline 28, MCP catalog 89,
console 557, commands 2,961, remote protocol 66 및 connect 인수 검사.
추가 회귀는 정렬되지 않은 시작 주소, 중간 NOACCESS/guard 페이지 뒤의 바이트
보존과 guard 상태 유지, 종료 시 정상 후보 처리와 오래된 정체성 거부,
한 배치를 넘는 종료 직전 이벤트 513개의 실제 분류를 검사한다.

`validate-kmon-core.ps1 -Sanitize`도 통과했다. ASan을 적용한 standalone
핵심 엔진 7개 묶음, hunting 11,326개, pages 54개, FP 49개를 확인했다.
전체 모니터 바이너리를 ASan으로 실행했다는 뜻은 아니다.

두 최종 EXE의 SHA-256은
`A90925DA8FF2499EC14FE95AC6CD4BD9DD0F1B79D942664BA974F115AE1722A8`로 같다.
요청별 캡처 합계와 최종 지표는 `final-b/validation.json`, `final-c/validation.json`,
비교 집계는 `comparison.json`에 있다. `cleanup-final.json`에서 테스트 서비스와
모니터·fixture 프로세스가 모두 0이고 부팅 시각이 유지된 것을 확인했다.
`git diff --check`도 통과했다.

## 재현

```powershell
.\tools\build.ps1 -Configuration Release
.\x64\Release\KnLiveDbg.exe --self-test all
.\tools\validate-kmon-live.ps1 -ObserveSeconds 180 -ProbeDriver -RequireQueueHealth -RequireCompletedWork
.\tools\validate-kmon-core.ps1 -Sanitize
```
