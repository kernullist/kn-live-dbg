# Kmon callback 조사와 스냅샷 비교

이 문서는 v0.0.33 이후 `main`에 추가한 기능을 설명한다. 조사 기준일은 2026-09-20이다. `!kmon surfaces`는 프로세스의 TLS 콜백, KernelCallbackTable 후보, WorkerFactory 시작 루틴을 읽는다. `!kmon cases`에는 기존 코드·페이지 검증을 거친 조사 단서가 들어간다. 두 결과 모두 JSON으로 보존하고 `!kmon diff`로 비교할 수 있다.

## 조사 근거와 구현 선택

| 일차 자료 | 확인한 내용과 적용 |
| --- | --- |
| [TLSCheck 2.0, 2026-04-22](https://arxiv.org/abs/2604.20378) | PE32/PE32+ TLS 구조와 콜백 코드를 함께 조사한다. 논문이 언급한 종료 프로세스·미해결 콜백의 한계를 유지하고, 현재 메모리의 참조와 디스크 기준 차이를 별도로 출력한다. 논문의 탐지율을 이 구현에 적용하지 않는다. |
| [Microsoft PE/COFF 형식](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-tls-section) | TLS의 `AddressOfCallBacks`와 배열 원소는 VA이며 배열은 NULL로 끝난다. 포인터 폭, optional-header 크기, 디렉터리 범위와 종료 원소를 검증한다. |
| [MITRE DET0467, 2026-05-12 갱신](https://attack.mitre.org/detectionstrategies/DET0467/) | TLS 메타데이터 변경과 후속 실행은 별도 관측이다. 디스크 비교 불일치는 `finding.tls_metadata`로 기록하되 실행·악성 판정으로 올리지 않는다. |
| [MITRE DET0577, 2026-05-12 갱신](https://attack.mitre.org/detectionstrategies/DET0577/) | PEB 콜백 테이블 변경과 GUI 메시지에 의한 실행을 구분한다. 검증된 PDB 필드로 루트를 읽고, 전체 테이블 크기를 모르는 상태는 후보 접두부 검사로 표시한다. |
| [SafeBreach PoolParty](https://www.safebreach.com/blog/process-injection-using-windows-thread-pools/) | WorkerFactory 시작 루틴과 TP_WORK·TP_IO·TP_TIMER 등은 서로 다른 경로다. 시작 루틴 질의만 추가했다고 휴면 스레드풀 그래프 전체를 지원한다고 표시하지 않는다. |
| [phnt의 고정 리비전](https://github.com/winsiderss/phnt/blob/53fbbdc5b5d2b08761db1c7b26bfa8c820924356/ntexapi.h#L1800-L1898) | x64 `WorkerFactoryBasicInformation`의 크기·필드 위치를 정적 검증하고 반환 길이와 대상 PID를 확인한다. `NtQueryInformationWorkerFactory`만 호출한다. |
| [Elastic 호출 스택 연구, 2025-06-12](https://www.elastic.co/security-labs/threat-command/call-stacks-no-more-free-passes-for-malware) | 복원한 스택은 실행 추적과 다르다. 새 콜백 참조도 현재 RIP나 실행 순서의 증거로 표현하지 않는다. |
| [Elastic 실행 양식 연구, 2025-05-15](https://www.elastic.co/security-labs/threat-command/misbehaving-modalities) | 단일 주소의 이상 여부에 더해 메모리 소유권과 코드 내용을 대조한다. 기존 이미지 검증·정적 코드 경로·페이지 캡처를 재사용한다. |

자료의 게시일과 확인일을 구분한다. 2026년 논문과 탐지 전략을 읽었으며, 2023~2025년 자료는 API와 기법의 기초 근거로 사용했다. 새 수집기의 외부 악성 샘플 탐지율, 논문 구현과의 동등성, 모든 공개·비공개 기법의 포괄성은 측정하지 않았다.

## 사용 순서

PID는 십진수다. 다음 명령은 대상 메모리나 콜백을 수정하지 않는다. `/save`는 호스트 파일을 생성하므로 MCP·AI 경로에서는 쓰기 명령으로 분류된다.

```text
!kmon surfaces 1234
!kmon surfaces 1234 /json /save "D:\evidence\surfaces-before.json"
!kmon surfaces 1234 /json /save "D:\evidence\surfaces-after.json"
!kmon diff "D:\evidence\surfaces-before.json" "D:\evidence\surfaces-after.json" /json

!kmon cases /pid 1234
!kmon cases /pid 1234 /role tls_callback /json
!kmon cases /save "D:\evidence\cases-before.json"
!kmon cases /save "D:\evidence\cases-after.json"
!kmon diff "D:\evidence\cases-before.json" "D:\evidence\cases-after.json"
```

출력 디렉터리는 먼저 만들어야 한다. 파일은 UTF-8 JSON으로 저장하며 기존 파일을 덮어쓰지 않는다. 임시 파일을 완전히 기록한 뒤 이름을 바꾼다. 저장에 실패하면 성공으로 표시하지 않는다. 프로세스 강제 종료 때 남은 `.pending-*` 파일은 완성된 스냅샷이 아니다.

`surfaces`의 기본 시간 예산은 2초, 모듈 예산은 512개, 핸들 예산은 4,096개다. 커널 API 호출 하나의 실행 시간을 강제로 제한하지는 못한다. `next_module`이나 `next_handle`이 0이 아니면 해당 값을 다음 명령에 전달한다.

```text
!kmon surfaces 1234 /module-start 24 /handle-start 1800 /json
```

모듈 인덱스와 핸들 값은 스냅샷 사이에 달라질 수 있다. 여러 번의 결과를 하나의 원자적 전체 목록으로 합쳐 해석하면 안 된다. 전체 행 상한은 32,768개다. 콘솔은 최대 128개 표면 행, diff는 64개 변경 행을 보여 준다. `/json`과 저장 파일에는 해당 호출이 수집한 모든 행이 들어간다.

## 증거 해석

### TLS

`tls_callback_table`은 모듈 단위 상태이고 `tls_callback`은 개별 슬롯이다. PE32와 PE32+를 파싱하며 콜백을 최대 64개 읽는다. 상한 다음 원소가 NULL이면 정확히 64개인 배열도 완료로 처리한다. 비종료 배열·읽기 실패·잘못된 VA·잘린 헤더는 제한 사유를 남긴다.

헤더·TLS 디렉터리·포인터가 서로 다른 보호 속성의 영역에 걸쳐도 전체 범위가 읽기 가능한지 확인해 수집한다. 범위 안에 Guard·NoAccess·미커밋 영역이 있으면 읽지 않는다. 범위를 확인한 뒤에도 보호 속성이 바뀔 수 있으므로 실제 읽기의 성공 여부와 바이트 수를 별도로 검사한다.

`baseline=match|mismatch|unverified`는 파일 기준과의 비교 결과다. 파일 ID와 PE 식별자를 확인하고 재배치가 적용된 기대 바이트에서 TLS 구조를 다시 파싱한다. 비교 중 파일을 쓰기·삭제 공유 없이 열어 두고, 살아 있는 TLS 구조도 다시 확인한다. 파일이 없거나 다른 이미지이거나 필요한 구조를 읽을 수 없으면 `unverified`다. `match`는 신뢰 서명이나 악성 코드 부재를 뜻하지 않는다. 정상 프로그램도 실행 중 메타데이터를 바꿀 수 있다.

백그라운드 Kmon은 기존 로더·VAD 이미지 후보도 TLS 검사에 전달한다. 로더 목록 밖 후보는 파일 경로를 확보하지 못했으면 기준 비교가 미검증으로 남는다. 직접 `surfaces` 명령의 모듈 목록은 Toolhelp 스냅샷이다. 읽기 핸들을 얻지 못한 프로세스의 이 수집기는 `unavailable`을 기록하며, 기존 Kmon의 별도 커널 메모리 검사를 대체하지 않는다.

### KernelCallbackTable

로드된 일치 PDB의 `nt!_PEB.KernelCallbackTable`이 8바이트 필드로 확인된 native x64 프로세스만 다룬다. PDB를 준비하지 않은 독립 실행에서는 이 항목이 미검증이고 TLS·WorkerFactory는 계속 수집할 수 있다. 임의의 PEB 오프셋을 가정하지 않는다.

테이블의 전체 길이를 보증할 수 없어 최대 64개 원소를 `kernel_callback_candidate`로 표시한다. TLS와 달리 NULL 원소에서 중단하지 않는다. 루트의 메모리 종류와 후보 주소의 현재 보호 속성, 로더 목록상 소유 모듈을 함께 기록한다. 소유 모듈 이름은 목록의 주소 범위와 일치한다는 뜻이며 파일 무결성 검증 결과가 아니다. GUI 메시지 발송이나 콜백 호출은 하지 않는다.

### WorkerFactory

대상 프로세스의 핸들 스냅샷에서 조회 권한만 요청해 복제한 핸들을 질의한다. 커널의 객체 종류 검사와 반환 PID·ABI 길이 검증을 통과한 항목만 `worker_factory_start`로 보존한다. 같은 복제 핸들을 두 번 질의해 시작 루틴과 매개변수를 대조한다. 원격 핸들 값은 스냅샷 간 재사용될 수 있으므로 동일 객체의 지속성을 보증하지 않는다.

접근 거부나 핸들 경합은 `worker_handle_queries_unavailable`에 포함한다. 두 번째 조회의 실패·반환 길이·PID·시작 루틴·매개변수 불일치도 포함한다. 일부 질의를 검증할 수 없으면 `partial_handle_queries`다. 일반 핸들에서 조회 권한을 얻지 못해도 이 숫자가 늘 수 있다. `thread_pool_graph=not_collected`는 TP_WORK·TP_IO·TP_TIMER·ALPC·job·wait 내부 그래프를 순회하지 않았다는 뜻이다.

### Kmon 연결과 보존

백그라운드는 프로세스 방문당 모듈 8개·핸들 128개·시간 300ms를 예산으로 사용하며 커서를 보존한다. native x64 참조는 기존 코드 경로 검증과 연결한다. 32비트 TLS를 x64 분기 디코더에 넣지 않는다.

TLS의 PE 헤더·디렉터리·읽은 콜백 배열과 KCT의 PEB 루트를 참조의 출처 바이트로 보관한다. 코드 경로 검사 전후에 이 바이트와 슬롯을 재확인한다. TLS 배열 앞쪽에 NULL 종료자가 생기면 뒤쪽 슬롯이 같아도 등록된 참조로 보존하지 않는다. KCT는 현재 PEB 주소 자체도 다시 질의하므로 옛 PEB에 같은 테이블 포인터가 남아 있는 경우를 걸러낸다. 여러 읽기의 시간차 자체를 제거하는 원자적 캡처는 아니다.

`cases`는 최대 512개 최근 참조에서 최대 256개 후보 사건을 만든 뒤 필터링한다. `/pid`와 `/role`은 동일한 끝점에서 함께 일치해야 한다. 커널·사용자 간 관계는 한쪽이 필터에 맞으면 다른 끝점도 보존한다. 만료는 30초이며 필터나 상한으로 보이지 않는 항목이 있을 수 있다.

## 저장 형식과 diff

- `kmon.surfaces.v1`: 부팅 ID, PID, 생성 시각, 수집 시각, coverage, 재개 위치, 메타데이터 행.
- `kmon.hunt.v1`: 코드 검증 이후의 제한된 최근 사건과 페이지 관계.
- `kmon.diff.v1`: 같은 종류의 두 스냅샷을 비교한 `newly_observed`, `changed`, `no_longer_observed`, `unchanged`.

비교 키에는 부팅 ID·PID·생성 시각과 참조 종류·슬롯/이미지/핸들 식별 정보가 들어간다. PID나 부팅이 바뀌면 서로 다른 관측으로 처리한다. 새 ID와 수집 시각만 달라진 최근 사건은 변경으로 세지 않는다. 64비트 주소·FILETIME·PFN은 부동소수점을 거치지 않는다.

`coverage_changed`와 원본 스냅샷의 coverage를 함께 확인해야 한다. 스캔 시작 위치·예산과 다음 재개 위치도 비교 범위에 포함한다. `no_longer_observed`는 만료, 필터 차이, 예산 부족, 접근 실패 또는 실제 제거 모두에서 발생할 수 있다. `absence_is_resolution=false`를 유지한다. 가져온 파일은 신뢰·인증된 기준으로 취급하지 않으며 `input_trust=unverified_snapshots`로 표시한다. 잘못된 UTF-8, 중복 키·식별자, 다른 스키마, 범위를 넘는 정수와 과대한 파일은 거부한다. 파일당 상한은 32MiB다.

사건 스냅샷의 관측 범위는 필드 이름과 정규화한 값을 함께 비교한다. `filter_pid`는 NULL 또는 32비트 부호 없는 정수, `filter_role`은 최대 128자의 문자열, `candidate_limit`은 1~256으로 제한한다. 이 선택 필드가 없는 이전 `kmon.hunt.v1` 스냅샷도 읽을 수 있다. 짝이 맞지 않는 UTF-16 surrogate escape와 파서가 해석하는 객체의 멤버 이름에 포함된 NUL은 거부하며, 잘못된 식별자를 대체 문자로 바꿔 다른 관측과 합치지 않는다.

## 검증

```powershell
.\tools\validate-analyst-features.ps1 -Sanitize
.\tools\validate-analyst-features.ps1 -Configuration Debug
.\x64\Release\KnLiveDbg.exe --self-test all
.\tools\validate-command-audit.ps1 -Sanitize
.\tools\validate-kmon-core.ps1 -Sanitize
.\tools\validate-kmon-hunting.ps1 -Sanitize
```

하네스는 변형한 PE32/PE32+ 구조, 읽기 실패와 루트 교체, 종료·예산 경계, PID 재사용, 64비트 JSON, 중복·잘린 입력, 원자적 저장과 덮어쓰기 거부를 검사한다. 실제 수집 경로는 자신이 만든 정상 TLS 콜백·스레드풀과 실행 권한이 없는 자체 이미지 후보로 확인한다. 서로 다른 보호 속성의 경계와 Guard·NoAccess 음성 대조, Unicode 경계 조합도 검사한다. 다른 프로세스에 코드를 주입하거나 커널 드라이버를 로드하지 않는다. [초기 검증 기록](KMON_ANALYST_VALIDATION_20260920.md)과 [후속 적대적 리뷰](KMON_ANALYST_REVIEW_20260920.md)에 실행 결과와 수정 내역을 구분해 기록했다. 실환경 커널·VM·게임핵 검증은 사용자가 별도로 수행한다.
