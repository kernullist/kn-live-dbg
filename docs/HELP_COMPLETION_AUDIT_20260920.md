# 도움말·자동완성 점검 — 2026-09-20

기준 커밋은 `4e27256cf0796137efe241306f7127dd1aead66d`다. 등록된 명령 261개
(네이티브 151개, 별칭 17개, DbgEng 경로 93개)의 도움말과 완성 후보를 확인하고,
네이티브 명령의 옵션·하위 명령을 실제 파서와 대조했다. DbgEng 명령은 이 프로젝트의
등록·도움말·전달 경계를 검사했다. 외부 디버거 자체의 명령 구현은 검사 범위에 포함하지 않는다.

## 수정 내용

| 영역 | 확인한 문제와 수정 |
| --- | --- |
| 로컬·원격 일치 | 로컬 TUI의 별도 후보 목록과 원격의 범용 옵션 추가 로직이 달랐다. 두 입력창과 원격 completion-request가 같은 후보 선택·토큰 분석 코드를 사용한다. |
| 문맥 | 하위 명령 뒤에 상위 명령의 동작이나 무관한 `/json`, `/process` 등이 섞였다. 하위 명령별 후보를 구분하고, 숫자·경로·주소를 기다리는 위치에는 다른 옵션을 삽입하지 않는다. |
| 입력 보존 | 공백이 있는 인용 경로와 인용된 AI 질문을 단순 공백 분리로 해석했다. 따옴표가 포함된 현재 토큰은 변경하지 않고, 완료된 인용 인수는 하나의 값으로 처리한다. 커서 범위와 토큰 밖 문자열도 검사한다. |
| `!kmon` | `/manifest`, `/layout-ms`, `cases`, `surfaces`, `layouts`, `diff`의 옵션을 로컬 Tab에서도 제공한다. `/initial`은 `/pid` 뒤에서만 제시하고, 한 번만 받는 분석 옵션은 사용 후 후보에서 제외한다. `/json` 출력과 `/save <path>` 파일 저장을 구분한다. |
| IOCTL 추적 | 활성화 구문은 `!kmon iotrace <driver> on`이다. 해제·조회는 `!kmon iotrace off`와 `!kmon iotrace status`다. 도움말, 사용 오류 메시지, Tab, 관련 문서의 잘못된 드라이버 인수를 수정했다. |
| TI | `watch`, `recent`, `status`에 시작 옵션을 제시하던 오류를 수정했다. `add`·`remove`는 `/pid`와 `/name`을 안내한다. |
| 스냅샷·필터 | `!diff /memory`, `!threads /summary`, VAD·덤프 호환 별칭의 누락을 보완했다. `!snapshot`의 캡처·조회 옵션과 `!driver`의 목록·객체 검사 옵션을 구분한다. 도메인·위험도 값은 해당 옵션의 값 위치에서 제시한다. |
| 도움말 경로 | `!timeline help <Tab>`과 AI 중첩 도움말을 복구했다. 지원되는 네이티브 `명령 하위명령 help`는 드라이버·서버 작업 전에 도움말을 출력한다. `??` 식 평가 구문도 추가했다. |
| 구문·별칭 | `dD`, `dW`, `eD`, `ld`의 canonical 항목을 실제 대상에 맞췄다. 값이 필요한 옵션의 구문과 `u`·`uf`의 주소 필수 여부를 구분하고, 사용자 프로세스 덤프의 `/pid`·`/name`을 상세 도움말에 추가했다. |
| 실행 파일 도움말 | `KnLiveDbg.exe --help`로 시작 모드와 네이티브 명령을 확인할 수 있다. `--help all`은 DbgEng 항목도 표시한다. 이 경로는 드라이버를 로드하거나 리스너를 시작하지 않는다. |

완성 후보와 설명은 `user/CompletionHints.cpp`, 문맥 선택·입력 편집은
`user/CompletionEngine.inl`에서 관리한다. 명령별 상세 설명은 기존 핸들러에 남아 있다.
후속 옵션 추가 시 실제 파서, 설명 테이블, 상세 도움말을 함께 갱신해야 한다.

## 검증

수정 전 재현 검사에서는 281개 조건이 실패했다. 이 수에는 등록 명령별 로컬·원격
불일치가 포함되므로 서로 다른 버그 281개를 의미하지 않는다.

`tools/validate-command-audit.ps1`은 숫자·인수 파서 검사에 더해 실제 완성 엔진을
별도 실행 파일로 빌드한다. 명령·옵션 설명 누락, 인수 위치, 인용 입력,
생성된 문자열의 모든 커서 위치에서 편집 범위를 검사한다. `-Sanitize`는 이 두
독립 실행 파일에 AddressSanitizer를 적용한다. 전체 KnLiveDbg 실행 파일의 ASan
검사를 뜻하지 않는다.

최종 결과와 실행 명령은 [검증 기록](../research/help-completion-validation-20260920.json)에 기록했다.

| 검사 | 결과 |
| --- | --- |
| Release·Debug 빌드 | 성공, 컴파일러 경고 0개 |
| 각 구성의 전체 자체 검사 | timeline 28, MCP 도구 75, console 524, commands 2,336, remote protocol 52 통과 |
| 독립 파서 /W4 /WX + ASan | 275,002개 조건 통과 |
| 독립 완성 엔진 /W4 /WX + ASan | 25,954개 조건 통과; 생성 입력 300개와 각 커서 위치 포함 |
| 시작 도움말 | `--help`, `-h`, `/?`, `--help all` 모두 종료 코드 0 |

명령 검사와 생성 입력 검사를 수정 후 반복했고, 마지막 변경 검토에서 추가 수정 사항을 발견하지 못했다.
실제 드라이버를 로드한 대상 분석과 실제 원격 GUI 입력 검증은 포함하지 않는다.

## 2026-10-06 후속 동기화

아래 내용은 위의 9월 점검 이력 이후 현재 소스에 적용한 갱신이다. 등록 명령은
계속 261개이며, 새로운 명령이나 드라이버 ABI를 추가하지 않았다.

- `dt`·`dtx`의 `-rN`, `-v`, `-b`는 별도 값 없이 타입 앞에서 조합하는 플래그다.
  기존 완성기는 첫 플래그 뒤에서 타입 값을 기다려 다른 플래그를 숨겼다.
  플래그를 연속 완성하고, 타입 뒤에는 플래그를 제시하지 않도록 수정했다.
  `-b` 설명도 실제 bare 이름 출력에 맞췄다.
- `log enable [path]`는 실제로 지원하지 않는 구문이었다. 자동 파일 이름을 쓰는
  `log enable`로 고치고, 실제 파서가 받는 `on`·`off`·`start`·`stop` 별칭을 완성에
  추가했다.
- `!module`은 `integrity`, `!driver`는 `list`·`object`·`integrity`를 먼저 요구한다.
  루트에서 잘못 제시하던 `all`과 검사 옵션을 해당 하위 명령 뒤로 옮겼다.
  객체 검사의 `/dispatch`·`/devices`와 목록·무결성 검사의 옵션 경계도 유지한다.
- `backend dbgeng`에서도 네이티브 소유 명령이 먼저 처리되는 동작을 설명한다.
  bare 타입 조회는 이미 로드한 CodeView/PDB 모듈을 검색하고, `module!type`은
  지정 모듈의 심벌 로드를 요청한다. private 타입이 없으면 미지원 상태로 남는다.
- `!driver` 도움말에 `summary.coverage_complete`, `dispatch_coverage_complete`,
  `fast_io_coverage_complete`를 추가했다. `!hunt /deep`의 기존 TI 재사용과
  불완전 드라이버 검사 전파, `!module integrity /disk`의 제외·비교 실패 근거도 설명한다.
- KMON 도움말·완성 설명에 명시적 감시 우선 배정과 순환 예산을 반영했다.
  README·명령 목록에 `/pid`, `/memory`, `/layout-ms`, `/manifest`, 분석 재개 옵션
  및 실제 하위 명령별 구문을 보완했다.

수정 전 독립 완성 검사에서 타입·로그 동작의 새 회귀 조건 8개가 실패했다.
하위 명령보다 먼저 옵션을 제시하는 문제는 실제 핸들러의 필수 동작 검사와
대조해 확인했다. 회귀 검사는 실제 `ParseDtRequest`의 플래그 조합, 로컬·원격
공통 완성, 상세 도움말의 검사 범위 설명도 검사한다.

재실행 명령:

```powershell
.\tools\build.ps1 -Configuration Release
.\tools\build.ps1 -Configuration Debug
.\x64\Release\KnLiveDbg.exe --self-test all
.\x64\Debug\KnLiveDbg.exe --self-test all
.\tools\validate-command-audit.ps1 -Configuration Release -Sanitize
.\tools\validate-command-audit.ps1 -Configuration Debug -Sanitize
```

최종 검증 결과(각 Release·Debug 구성):

| 검사 | 결과 |
| --- | --- |
| 최종 빌드 | 성공, 컴파일러 경고·오류 0개 |
| 전체 자체 검사 | timeline 28, MCP 도구 89, console 555, commands 2,342, remote protocol 66, connect argv 4 통과 |
| 독립 파서 /W4 /WX + ASan | 275,002개 조건 통과 |
| 독립 완성 엔진 /W4 /WX + ASan | 25,954개 조건 통과 |
| HTTP 검사 | 별도 실행 9개 조건 통과 |
| 시작 도움말 | `--help`, `--help all`, `-h`, `/?` 종료 코드 0, 드라이버 서비스 변화 없음 |
| 문서 링크 | 변경한 문서의 로컬 링크 64개 확인, 누락 0개 |

이 점검은 도움말·완성과 파서를 검증한다. 실제 드라이버 기능의 별도 근거와
미완료 범위는 [2026-10-06 호스트 검증](LIVE_HOST_VALIDATION_20261006.md)에 기록했다.
