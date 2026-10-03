# 분석가용 콜백 조사 기능 검증 — 2026-09-20

이 문서는 `ee05c55` 초기 구현의 검증 기록이다. 이후 추가로 발견한 문제와 현재 수정본의 검증 결과는 [후속 적대적 리뷰](KMON_ANALYST_REVIEW_20260920.md)에 기록했다. 아래 수치와 로컬 실행 디렉터리는 초기 구현 당시의 근거로 보존한다.

v0.0.33의 `691cf20e31478bba65ee42ce128b7a76d68d5e78`을 기준으로 TLS·KCT·WorkerFactory 수집, 사건 필터, JSON 저장·비교를 추가했다. 이 기록은 해당 변경 작업 중 수행한 로컬 검증이다. 이전 릴리즈의 실험 결과를 새 수집기의 검증으로 계산하지 않는다. 사용법과 일차 자료는 [분석가용 가이드](KMON_ANALYST_SURFACES.md)에 있다.

초기 구현 제출본은 x64 Release·Debug 빌드와 아래 검사를 통과했다. 당시 반복 코드 검토에서 발견한 문제를 수정하고 관련 회귀를 다시 실행했다. 같은 구현 에이전트가 수행한 적대적 재검토이며 독립 분석가 감사는 아니다.

## 환경과 실행 결과

VS 2022 Professional, MSVC 14.44.35207, MSBuild 17.14.40, 설치된 SDK/WDK 10.0.22621.0을 사용했다. 프로젝트의 기본 SDK 버전을 변경하지 않고 빌드 옵션으로 지정했다. 기존 로컬 테스트 인증서를 사용했으며 드라이버를 로드하거나 테스트 서명·부팅 정책을 변경하지 않았다.

| 검사 | 결과 | 범위 |
| --- | --- | --- |
| x64 Release / Debug 빌드 | 두 구성 성공 | 프로그램과 솔루션의 드라이버·fixture 프로젝트 컴파일·링크 |
| 새 분석가 하네스, Release ASan / Debug | 각각 6,364 passed / 0 failed | PE32·PE32+, 읽기 경합, KCT 접두부, PEB 질의, 스냅샷, 자체 프로세스 수집 |
| `--self-test all`, Release / Debug | 각각 커맨드 2,017, 콘솔 524, 타임라인 28, MCP 75, remote 52 통과 | 커맨드 261개 등록; remote 연결 인자 검사도 통과 |
| 커맨드 파서 ASan | 275,002 passed / 0 failed | 파서 경계 입력; 커맨드 통합 2,017건도 통과 |
| MCP HTTP | 9 passed / 0 failed | 잘못된 JSON·UTF-8·중복 키·본문 크기와 실패 후 복구 |
| Kmon 핵심 ASan | 7개 검증 묶음 통과 | 핸들 ABI·이미지 비교·정적 분기·카탈로그·manifest·대기열 |
| Kmon 헌팅 ASan | 합성 11,326 + 페이지 54 통과, 잘못된 replay 8/8 거부 | 기존 헌팅·페이지 구성요소 회귀 |
| 소유한 이미지 fixture | clean/modified/text/jit의 수정 페이지 0/1/1/0 | 메인 이미지 비교 구성요소; 실제 공격 표본 아님 |
| 연구 원장 | 자료 26개, 기법 18개 검사 통과; validator 회귀 21건 통과 | covered 4, partial 10, missing 3, out_of_scope 1 |

6,364는 서로 다른 공격 기법의 수가 아니다. 결정적 seed로 변형한 PE 입력 6,000건과 잘린 JSON 300건이 포함된 assertion 수다. ASan은 새 분석가 하네스와 명시한 standalone 검사에 적용했다. 전체 `KnLiveDbg.exe`를 ASan 빌드했다고 주장하지 않는다.

새 자체 프로세스 fixture는 정상 TLS 콜백과 정상 스레드풀을 만들고 자신의 메모리를 읽는다. 추가 이미지 후보는 `PAGE_READWRITE`로 할당한 PE 모양의 데이터이며 기존 정상 TLS 함수 주소를 참조한다. 다른 프로세스에 코드를 넣거나 후보 메모리를 실행하지 않는다.

최종 ASan 실행에서 안정적인 TLS 콜백 7개, WorkerFactory 시작 루틴 2개를 읽었고 자체 EXE의 재배치 기준은 일치했다. 기준 불일치는 0개였다. 추가 파일 없는 이미지 후보 1개는 의도대로 `unverified`였다. Debug에서는 TLS 2개·WorkerFactory 2개를 확인했다. 런타임 모듈 구성이 달라 두 구성의 TLS 개수는 같지 않다. 일반 핸들 조회 실패도 포함되므로 두 실행의 WorkerFactory coverage는 `partial_handle_queries`로 남았다.

## 적대적 검토에서 수정한 문제

| 문제 | 재현 또는 검토 근거 | 수정 |
| --- | --- | --- |
| 저장 중 rename 버퍼 끝을 넘는 읽기 | ASan이 `FILE_RENAME_INFO` 경로를 처리하는 Windows 변환 함수의 NUL 탐색에서 heap-buffer-overflow를 보고 | 길이로 센 파일명 뒤에 NUL용 `wchar_t`를 추가하고 0으로 초기화. 저장·재읽기·덮어쓰기 거부 회귀 통과 |
| 옛 배열 슬롯만으로 등록 상태를 인정 | TLS 디렉터리나 KCT 루트를 바꿔도 옛 배열에 동일한 포인터가 남는 합성 입력 | TLS 헤더·디렉터리와 KCT 루트의 출처 바이트를 보존하고 코드 검사 전후 재확인 |
| TLS 앞쪽 NULL이 뒤쪽 콜백을 무효화하는 경우 누락 | PE32·PE32+에서 앞쪽 종료자 삽입과 기존 종료자 제거, 수정 전 4건 모두 실패 | 읽은 배열 접두부·종료자를 추가 anchor로 보존. 동일한 4건과 전체 하네스 통과 |
| 프로세스가 다른 PEB를 가리켜도 옛 PEB의 바이트가 일치 | 프로세스 식별자·PEB 루트·대기열 사이의 데이터 흐름 검토 | 수집 전후와 대기열 검증 전후에 현재 PEB 주소를 다시 질의. 자체 PID 질의와 잘못된 PID 거부 회귀 추가 |
| 파일 비교 도중 살아 있는 TLS가 바뀜 | 파일 기준 비교와 최종 공개 사이의 일관성 검토 | 파일 ID·PE 식별자를 확인하고 쓰기·삭제 공유 없이 파일 유지. 살아 있는 TLS를 다시 파싱해 불일치 시 미검증 처리 |
| 사건의 JSON·콘솔·저장 내용이 서로 다른 시점을 사용 | 모니터가 갱신하는 동안 사건 목록을 두 번 캡처하는 호출 경로 검토 | 같은 잠금 안에서 만든 한 사건 스냅샷을 세 출력에 사용 |
| 갱신 시각·ID나 숫자 표기 차이가 변경으로 계산됨 | 같은 사건의 ID·시각만 변경하거나 64비트 정수 문자열의 앞에 0 추가 | 일시적 ID·시각을 비교에서 제외하고 정수·문자열을 정규화. 부팅 ID·PID·생성 시각은 식별자에 유지 |
| 스캔 재개 구간이 달라도 coverage 차이를 놓침 | 동일 행에서 모듈·핸들 다음 위치만 변경하는 대조 | 시작 위치·예산을 coverage에 기록하고 다음 위치도 diff coverage 비교에 포함 |
| 조회 실패가 완전한 핸들 검사로 보임 | WorkerFactory 질의 실패 분기 검토와 자체 fixture 출력 | 접근 실패·경합·ABI/PID 불일치를 집계하고 `partial_handle_queries` 표시 |
| 연구 원장 회귀가 특정 기법의 영구 미구현을 가정 | PoolParty 상태가 partial로 바뀌자 missing 음성 대조가 유효하지 않음 | 테스트 fixture에서 missing/unsupported/backlog 상태를 명시. validator의 거부 규칙은 유지 |

PEB 교체 자체를 실제 프로세스에서 유발한 시험은 하지 않았다. KCT 루트와 TLS 배열 교체는 합성 reader를 이용했다. 여러 시점의 읽기가 모두 같아도 읽기 사이의 교체·복귀까지 배제할 수 없으므로 원자적 캡처로 표현하지 않는다.

## 재실행과 로컬 근거

```powershell
.\tools\build.ps1 -Configuration Release -WindowsTargetPlatformVersion 10.0.22621.0 -TestCertificateThumbprint <local-test-certificate>
.\tools\build.ps1 -Configuration Debug -WindowsTargetPlatformVersion 10.0.22621.0 -TestCertificateThumbprint <local-test-certificate>
.\tools\validate-analyst-features.ps1 -Sanitize
.\tools\validate-analyst-features.ps1 -Configuration Debug
.\x64\Release\KnLiveDbg.exe --self-test all
.\x64\Debug\KnLiveDbg.exe --self-test all
.\tools\validate-command-audit.ps1 -Sanitize
.\x64\Release\KnLiveDbg.exe --self-test mcp-http
.\tools\validate-kmon-core.ps1 -Sanitize
.\tools\validate-kmon-hunting.ps1 -Sanitize
.\tools\validate-evasion-research-ledger.ps1 -AsOfDate 2026-09-20
.\tools\validate-evasion-research-ledger-selftest.ps1
```

최종 로컬 로그는 `.build/analyst-build-release.log`, `analyst-build-debug.log`, `analyst-selftest.log`, `analyst-selftest-debug.log`, `analyst-release-all.log`, `analyst-debug-all.log`, `analyst-command-audit.log`, `analyst-mcp-http.log`, `analyst-kmon-core.log`, `analyst-kmon-hunting.log`, `analyst-research-ledger.log`, `analyst-research-selftest.log`에 있다. TLS 종료자 수정 전 실패는 `.build/analyst-tls-prefix-before.log`에 보존했다. 이 로컬 로그와 바이너리는 커밋하지 않는다.

최종 새 하네스의 JSON 파일은 `.build/analyst-features/Release-asan/run-3f6bc234a78b4869a58fc5e84c93e001`과 `.build/analyst-features/Debug/run-21cb23d4c683463da63954bb1e7f1002`에 남겼다. 재실행하면 다른 실행 디렉터리를 생성한다. 헌팅 fixture 보고서는 `.build/kmon-hunting/Release-asan/validation.json`에 있다.

## 실환경 검증과 남은 범위

실제 커널·VM·게임핵 검증은 사용자가 별도로 수행한다. 이번 실행에서는 KCT의 일치 PDB를 준비하지 않았으므로 실제 GUI 프로세스의 KCT 열거를 검증하지 않았다. TLS x86은 합성 PE32로 검증했으며 실행 중인 WOW64 표본은 사용하지 않았다. WorkerFactory ABI의 다중 Windows 빌드 호환성, PPL 접근, 매우 큰 모듈·핸들 목록의 실환경 지연도 남아 있다.

휴면 TP_WORK·TP_IO·TP_TIMER·wait·ALPC·job 내부 그래프, GUI 메시지 실행 추적, callback 실행 시점 증명은 지원 범위가 아니다. 외부 악성 표본 탐지율·오탐률·독립 도구 비교를 새 수집기에 대해 측정하지 않았다. 이 작업의 PE-sieve 실행 상태는 `not_run`이다.

연구 원장의 전체 완료 판정은 여전히 `external_evidence_required`다. TLS·KCT·PoolParty 항목을 bounded partial로 갱신했으며 backlog 판정을 유지했다. 위 로컬 검사의 통과를 모든 은닉 코드의 탐지나 전체 연구 목표의 실환경 완료로 해석하지 않는다.
