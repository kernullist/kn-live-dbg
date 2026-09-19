# 분석가용 콜백 수집·스냅샷 기능 적대적 리뷰 — 2026-09-20

`ee05c5529625785f5f4f6c7b8dada0e6ffb3eaee`의 새 기능과 Kmon 연결부를 재검토해 네 종류의 문제를 수정했다. TLS 메모리 영역 경계, 스냅샷 관측 범위 비교, 손상된 Unicode 입력은 수정 전 실패를 재현했다. WorkerFactory 재조회 집계는 오류 분기의 데이터 흐름을 검토해 수정했다. 초기 구현의 시험 결과는 [이전 검증 기록](KMON_ANALYST_VALIDATION_20260920.md)에 따로 보존한다.

## 발견 사항과 수정

| 문제 | 영향과 재현 | 수정 |
| --- | --- | --- |
| P2: TLS 구조의 읽기를 단일 `VirtualQueryEx` 영역으로 제한 | 디렉터리 또는 8바이트 콜백 포인터가 읽기 전용·읽기 쓰기 영역 경계에 걸리면 모두 읽을 수 있어도 수집 실패. 자체 프로세스에서 두 경우 모두 재현 | 요청 범위의 모든 영역에 대해 커밋 상태·보호 속성·끝 범위를 확인한 뒤 정확한 바이트 수를 읽음 |
| P2: 사건 스냅샷의 관측 범위를 필드 이름 없이 연결 | `filter_pid=55`와 `candidate_limit=55`를 같은 범위로 비교. 같은 숫자·문자열의 다른 표기는 변경으로 계산하고 잘못된 선택 필드 자료형도 수용 | 이름을 포함한 객체로 정규화하고 PID·문자열·상한의 자료형과 범위를 검사. 선택 필드가 없는 이전 스냅샷도 지원 |
| P2: 잘못된 Unicode 식별자를 대체 문자로 바꿔 수용 | 공통 JSON helper가 서로 다른 비정상 surrogate 입력을 같은 U+FFFD로 바꿈. 네 가지 입력을 각각 거부해야 하는 회귀가 수정 전 실패 | 정규화 전에 전체 JSON 문자열의 surrogate 쌍을 확인. 파서가 해석하는 객체의 멤버 이름에 NUL이 있으면 거부. 정상 surrogate 쌍·escape 표기는 유지 |
| P2: WorkerFactory 두 번째 조회의 실패·불일치를 집계하지 않음 | 행은 불안정으로 표시되지만 다른 실패가 없으면 coverage가 `handle_snapshot_examined`로 남음 | 두 번째 조회를 검증하지 못한 핸들도 실패 수에 포함해 `partial_handle_queries`로 표시 |

메모리 수정은 [Microsoft의 VirtualQueryEx 계약](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex)과 [ReadProcessMemory 계약](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory)을 대조했다. 전자는 같은 속성을 가진 연속 영역을 반환하며, 후자는 요청 범위 전체가 읽기 가능한지 요구한다. 읽기 가능한 두 영역의 경계를 넘는 것 자체가 읽기 실패 사유는 아니다.

경계 fixture는 자기 프로세스에 실행 권한 없는 메모리를 할당하고 정상 TLS 함수의 주소만 넣는다. 디렉터리는 페이지 끝의 `0xff0`, 포인터는 `0xffc`에 두어 경계를 넘도록 했다. 첫 페이지는 읽기 전용, 다음 페이지는 읽기 쓰기로 바꿨다. 다음 페이지를 Guard 또는 NoAccess로 바꾸는 음성 대조에서는 콜백을 채택하지 않았고 Guard 속성도 유지됐다. 이 시험은 보호 속성의 동시 변경 경쟁을 실제로 발생시킨 결과는 아니다.

Unicode 검증은 공통 MCP JSON helper의 복구 동작을 바꾸지 않고 스냅샷 입력 경계에 추가했다. 손상된 문자열이 관측 식별자로 사용되기 전에 거부한다. 별도로 13개 UTF-16 경계 값의 두 문자 조합 169개를 만들고 `WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS)`의 판정과 대조했다.

## 반복 검토와 결과

| 단계 | 결과 |
| --- | --- |
| TLS 경계·관측 범위 오류 재현 | 6,372 passed / 12 failed |
| 첫 수정 | 6,384 passed / 0 failed |
| 재검토에서 Unicode 오류 재현 | 6,385 passed / 4 failed |
| Unicode 수정과 추가 음성 대조 | 6,391 passed / 0 failed |
| 최종 ASan / Debug 하네스 | 각각 6,560 passed / 0 failed; Unicode 경계 조합 169건 포함 |
| x64 Release / Debug 솔루션 빌드 | 두 구성 성공; C/C++·링커 경고 및 오류 없음 |
| `--self-test all`, Release / Debug | 각각 커맨드 2,017, 콘솔 524, 타임라인 28, MCP 75, remote 52 통과; 연결 인자 검사도 통과 |
| 커맨드 파서 ASan와 통합 검사 | 파서 275,002, 커맨드 2,017 통과 |
| 연구 원장 | 자료 26개·기법 18개 구조 검사 통과; 전체 claim gate는 `external_evidence_required` 유지 |

하네스 수치는 assertion 수다. PE 변형 6,000건과 잘린 JSON 300건이 포함되며 공격 기법 수나 탐지율을 나타내지 않는다. ASan은 standalone 하네스와 파서에 적용했다. 전체 프로그램을 ASan으로 빌드한 결과는 아니다.

수정된 파서·메모리 읽기·실패 집계를 다시 검토하고 최신 하네스, 두 구성의 빌드·통합 검사까지 통과한 뒤 검토 범위에서 추가 조치가 필요한 문제는 찾지 못했다. 단일 구현 에이전트의 반복 검토이며 독립 분석가 감사는 아니다.

## 재실행과 로컬 근거

```powershell
.\tools\validate-analyst-features.ps1 -Sanitize
.\tools\validate-analyst-features.ps1 -Configuration Debug
.\tools\validate-command-audit.ps1 -Sanitize
.\x64\Release\KnLiveDbg.exe --self-test all
.\x64\Debug\KnLiveDbg.exe --self-test all
.\tools\validate-evasion-research-ledger.ps1 -AsOfDate 2026-09-20
```

VS 2022 Professional, MSVC 14.44.35207, SDK/WDK 10.0.22621.0을 사용했다. 빌드에는 `tools/build.ps1`의 `-WindowsTargetPlatformVersion 10.0.22621.0`과 기존 로컬 테스트 인증서를 지정했다. 드라이버를 로드하거나 부팅·서명 정책을 바꾸지 않았다.

로컬 로그는 다음과 같으며 커밋하지 않는다.

- `.build/analyst-review-before.log`: 최초 12개 실패
- `.build/analyst-review-unicode-before.log`: 추가 Unicode 실패 4개
- `.build/analyst-review-asan.log`, `.build/analyst-review-debug.log`: 최종 하네스
- `.build/analyst-review-build-release.log`, `.build/analyst-review-build-debug.log`: 빌드
- `.build/analyst-review-release-all.log`, `.build/analyst-review-debug-all.log`: 프로그램 통합 검사
- `.build/analyst-review-commands.log`: 파서·커맨드 검사
- `.build/analyst-review-ledger.log`: 연구 원장 검사

최종 하네스의 JSON 근거는 `.build/analyst-features/Release-asan/run-fa90b19db627492cab9040bdddf0c9e2`와 `.build/analyst-features/Debug/run-19d4caf005e34b6e977eea7045d3211f`에 있다. 재실행 시 새로운 디렉터리가 생성된다.

실제 커널·VM·게임핵 검증은 사용자에게 남겨 두었다. KCT 실제 PDB 경로·WOW64 프로세스·여러 Windows 빌드에 대한 검증과 휴면 스레드풀 내부 그래프 지원 범위는 [사용 가이드](KMON_ANALYST_SURFACES.md)의 제한을 유지한다. WorkerFactory의 두 번째 native 조회 실패를 실제 커널에서 강제로 유발한 시험은 수행하지 않았다.
