# Kmon callback 조사와 스냅샷 비교

이 가이드는 [문서 인덱스](README.md)의 main 구현을 기준으로 한다.
출시본 v0.0.36 이후의 보존 증거·오프라인 조사 기능도 포함한다.
`!kmon surfaces`는 프로세스의 TLS 콜백, KernelCallbackTable 후보,
WorkerFactory 시작 루틴을 읽는다. `!kmon cases`에는 코드·페이지 검증을 거친
조사 단서가 들어간다. 두 결과 모두 JSON으로 보존하고 `!kmon diff`로 비교한다.
아래 연구 자료의 확인 기준일은 2026-09-20이며 문서 정리가 이를 갱신하지 않는다.

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
!kmon cases /pid 1234 /limit 64 /json
!kmon cases /save "D:\evidence\cases-before.json"
!kmon cases /save "D:\evidence\cases-after.json"
!kmon diff "D:\evidence\cases-before.json" "D:\evidence\cases-after.json"
!kmon evidence "D:\evidence\cases" /pid 1234 /limit 64 /json
!kmon replay "D:\evidence\cases\selected.kncase" /json
!kmon why "D:\evidence\cases\selected.kncase"
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

`cases`는 최대 512개 최근 참조에서 `/pid`와 `/role`이 같은 끝점에 함께 일치하는 사건을 고른 뒤 결과 제한을 적용한다. 커널·사용자 간 관계는 한쪽이 필터에 맞으면 다른 끝점도 보존한다. `/limit 1..256`의 기본값은 256이다. `matched_case_count`는 유지된 신선한 참조에서 일치하는 전체 사건 수, `returned_case_count`는 이번 페이지 수, `omitted_by_budget`는 이번 페이지 뒤에 남은 수다. `page_offset`은 앞 페이지에서 건너온 수를 나타낸다.

`next_cursor`가 있으면 동일한 필터와 `/limit`에 `/cursor <next_cursor>`를 추가한다. 조회 시각을 고정하되 인덱스가 변경·초기화되거나 커서가 30초를 넘으면 `query_status=stale_cursor`로 거부한다. 범위·페이지 크기가 달라지거나 토큰이 잘못되면 `invalid_cursor`다. 이때 일치 수는 `null`이며 빈 정상 조회로 취급하지 않는다. 커서를 빼고 다시 시작해야 한다. 변화가 빈번한 라이브 인덱스에서 모든 페이지를 계속 이어갈 수 있다고 보장하지 않는다.

`complete_within_query_scope`는 유지된 신선한 참조의 일치 사건이 한 응답에 모두 들어왔는지만 나타낸다. 수집 완료나 시스템 전체의 부재 증거가 아니다. 참조의 30초 만료, 용량 제한, `evidence_evicted`·`evidence_rejected`는 그대로 적용되고 `underlying_index_retention`에 조회 기반을 표시한다.

## 저장 형식과 diff

프로세스의 기본 키는 부팅 식별자·PID·생성 시각이다. EPROCESS와 세션은 선택 제약이며, 정보가 없는 관측을 매개로 서로 충돌하는 값을 합치지 않는다. 최신 원본 관측의 미확인 필드는 그대로 남기고 알려진 제약은 인덱스 안에서 별도로 유지한다. 이 제약도 보유 범위를 넘어서 영구 유지되는 것은 아니다.

헌팅 참조를 받으면 원래 `observed_ms`와 별도로 `arrival_ms`·`arrival_sequence`를 기록한다. 순서가 늦거나 선택 식별자가 충돌해 최신 목록에 넣지 못하는 관측도 `kmon.receipt.v1`과 `current_disposition`에 남긴다. `receipt_history`는 최근 2,048개 수신 기록의 보유·퇴거·식별자 충돌 수를 표시한다. 현재 목록의 30초 만료는 유지되며, 이 수신 이력은 아직 메모리 보관이므로 재시작 후 복구를 보장하지 않는다. 구형 호출자의 관측 시각으로 도착 시각을 추정한 경우 `arrival_inferred=true`로 표시한다.

- `kmon.surfaces.v1`: 부팅 ID, PID, 생성 시각, 수집 시각, coverage, 재개 위치, 메타데이터 행.
- `kmon.hunt.v1`: 코드 검증 이후의 제한된 최근 사건과 페이지 관계.
- `kmon.diff.v1`: 같은 종류의 두 스냅샷을 비교한 `newly_observed`, `changed`, `no_longer_observed`, `unchanged`.

비교 키에는 부팅 ID·PID·생성 시각과 참조 종류·슬롯/이미지/핸들 식별 정보가 들어간다. PID나 부팅이 바뀌면 서로 다른 관측으로 처리한다. 새 ID와 수집 시각만 달라진 최근 사건은 변경으로 세지 않는다. 64비트 주소·FILETIME·PFN은 부동소수점을 거치지 않는다.

`coverage_changed`와 원본 스냅샷의 coverage를 함께 확인해야 한다. 스캔 시작 위치·예산과 다음 재개 위치도 비교 범위에 포함한다. `no_longer_observed`는 만료, 필터 차이, 예산 부족, 접근 실패 또는 실제 제거 모두에서 발생할 수 있다. `absence_is_resolution=false`를 유지한다. 가져온 파일은 신뢰·인증된 기준으로 취급하지 않으며 `input_trust=unverified_snapshots`로 표시한다. 잘못된 UTF-8, 중복 키·식별자, 다른 스키마, 범위를 넘는 정수와 과대한 파일은 거부한다. 파일당 상한은 32MiB다.

사건 스냅샷의 관측 범위는 필드 이름과 정규화한 값을 함께 비교한다. `filter_pid`는 NULL 또는 32비트 부호 없는 정수, `filter_role`은 최대 128자의 문자열, `candidate_limit`은 1~256으로 제한한다. 새 응답의 `query_schema=kmon.case_query.v1`은 페이지 위치·반환 수·남은 수·완료 여부도 검증한다. 실패한 조회를 정상 스냅샷으로 저장하지 않는다. 이 선택 필드가 없는 이전 `kmon.hunt.v1` 스냅샷도 읽을 수 있다. 짝이 맞지 않는 UTF-16 surrogate escape와 파서가 해석하는 객체의 멤버 이름에 포함된 NUL은 거부하며, 잘못된 식별자를 대체 문자로 바꿔 다른 관측과 합치지 않는다.

## 영구 증거와 오프라인 조사

실행 중인 콘솔에서는 위 명령을 사용한다. 프로그램을 새로 시작해 조사할 때는 아래처럼 `--offline`을 지정한다. 이 진입점은 관리자 권한, 드라이버, 심볼 초기화 전에 증거 명령만 실행하고 종료한다. 종료 코드는 정상 조회·선언된 범위 재생이면 0, 불완전·접근 실패·손상·커서 오류이면 1, 잘못된 명령이면 2다. 코드 0도 전체 수집 완료나 수집기 신뢰를 뜻하지 않는다.

```powershell
.\KnLiveDbg.exe --offline !kmon evidence "D:\evidence\cases" /pid 1234 /json
.\KnLiveDbg.exe --offline !kmon replay "D:\evidence\cases\selected.kncase" /json
.\KnLiveDbg.exe --offline !kmon why "D:\evidence\cases\selected.kncase"
```

영구 증거 저장 모듈은 `kmon.bundle.v1` 봉투와 `kmon.evidence.v1` 본문을 `.kncase` 한 파일에 저장한다. 수신 기록, 원래 검사 coverage, 수집 경로, 수집 구간과 원본 바이트를 포함하며 최대 128개 구간·구간당 4KiB·파일당 2MiB로 제한한다. 외부 조각 경로를 따라 읽지 않는다. 성공·실패·건너뛴 읽기를 구분하고, 겹치는 바이트가 서로 다르면 해당 읽기를 재구성하지 않는다. `read_set_complete`는 선언된 읽기 집합에만 적용되며 프로세스 전체 검사나 실행 관측을 뜻하지 않는다.

실제 KMON은 참조 재확인에 성공한 수신 기록과 당시 읽은 바이트를 로그 디렉터리의 `cases` 아래에 저장한다. 저장 큐는 64개, 세션당 파일 바이트 예산은 128MiB다. `status`와 `cases /json`의 `bundle_store`에서 대기·성공·실패·손실을 구분한다. 정상 종료는 대기 항목을 처리한 후 `kmon.evidence_session.v1` 형식의 `.knledger`에 접수·저장·실패·큐 손실 수를 남긴다. 강제 종료로 이 기록이 없으면 종료 상태는 미확인이다. 이 범위는 영구 저장을 시도한 헌팅 참조이며, 전체 수집이나 모든 검사 경로를 포함한다는 뜻이 아니다. 세션 간 자동 삭제는 하지 않는다.

`evidence`는 드라이버 없이 `.kncase`와 `.knledger`를 읽는다. 디렉터리 항목 4,096개와 실제 읽기 64MiB를 상한으로 삼고, 검증에 성공한 묶음에서 PID·역할을 적용한 뒤 페이지 제한을 적용한다. 복사한 같은 본문은 해시로 중복 제거한다. 손상 파일·종료 기록과 맞지 않는 파일 수는 `partial_inventory`, 접근할 수 없는 디렉터리는 `unavailable`로 표시한다. `unclosed_collections`와 `unavailable_written_bundles`로 종료 미확인과 기록상 저장됐지만 현재 조회에서 사용할 수 없는 묶음을 구분한다. `next_cursor`는 동일한 필터·제한과 파일 목록 지문에 묶이며 목록 변경 시 다시 조회해야 한다. `collection_complete=false`는 유지한다.

`replay`와 `why`는 저장된 바이트로 슬롯·정적 분기·페이지 해시를 다시 계산한다. 원래 프로세스가 종료됐거나 최신 인덱스가 만료·퇴거된 뒤에도 파일에 남은 사실을 조사할 수 있다. 빈 구간을 0으로 채우거나 간접 분기 대상을 추측하지 않는다. 원래의 소유권 분류는 수신 기록이며, 신뢰 기준 이미지와 정규화 입력 없이 이미지 검사를 재수행한 것으로 표시하지 않는다. 실행 관측, 통신, 행위자 귀속, 수집기 인증은 별도 증거가 필요하며 `unfulfilled_requirements`에 표시한다.

`publication_closure_known`은 유효한 종료 기록과 현재 파일 수의 대조가 끝났는지를 나타낸다. 종료 기록이 없는 빈 디렉터리는 이 값이 false다. 기록의 실패·큐 손실 수와 별도로 읽어야 하며, 서명된 수집 증명은 아니다.

각 구간과 전체 본문의 SHA-256은 저장 내용의 일관성 검사다. 수집기의 신뢰나 공격자 부재를 인증하지 않는다. 임시 파일을 모두 쓰고 flush한 뒤 기존 파일을 덮어쓰지 않는 rename으로 공개한다. 잘린 파일, 메타데이터 모순, 알 수 없는 필드와 `.pending-*` 임시 파일은 정상 증거로 가져오지 않는다. 증거 파일 자체의 reparse point도 열린 핸들에서 거부한다. 강제 종료 시험은 소유한 저장 프로세스에 한정하며 전원 손실·스토리지 장치 장애의 모든 결과를 보증하지 않는다. `.kncase`, `.knledger`와 임시 파일은 Git에서 제외하고 공개 정보 검사에서도 차단한다.

4,096개를 넘는 목록은 먼저 별도 인벤토리를 만든다. 출력 디렉터리는 새 경로여야 하며 기존 스냅샷을 덮어쓰지 않는다.

```powershell
.\KnLiveDbg.exe --offline !kmon inventory "D:\evidence\cases" "D:\evidence\index-001" /json
.\KnLiveDbg.exe --offline !kmon evidence "D:\evidence\cases" /inventory "D:\evidence\index-001" /limit 128 /json
```

스냅샷은 파일 이름·내용 지문·읽은 길이·유효 여부를 고정한다. 원본 파일을 복사하는 기능은 아니므로 원본이 삭제되거나 바뀌면 다음 조회에서 공백으로 표시한다. 이후 추가된 파일은 새 스냅샷을 만들어야 포함된다. 디렉터리 열거는 비원자적이며 수집기 인증을 제공하지 않는다.

조회 창마다 최대 4,096개 파일과 실제 읽기 64MiB를 처리한다. `next_cursor`가 있으면 같은 `inventory_cursor`와 함께 `/cursor`로 전달해 그 창의 결과를 먼저 모두 읽는다. 결과를 다 읽으면 `next_inventory_cursor`가 다음 파일 위치를 알려준다. 이를 `/inventory-cursor`로 전달하고 `/cursor`를 생략한다. 두 next 값이 모두 null이면 선언된 스냅샷 탐색을 마친 것이다. 필터와 `/limit`은 중간에 바꾸지 않는다.

`matched`, 중복 수, 읽기 바이트, 손상 수는 현재 창의 값이다. 창을 넘는 동일 묶음의 중복 제거는 호출자가 `evidence_id`로 수행해야 한다. 여러 창이 필요한 경우 마지막 창도 `partial_inventory`일 수 있으며 종료 기록의 전역 대조를 수행했다고 표시하지 않는다. `publication_closure_evaluated`는 전체 스냅샷을 한 창에서 읽었는지 구분한다. 원본의 변경으로 결과 커서가 오래된 경우 해당 창의 처음부터 다시 조회한다.

생성은 최대 1,048,576개 디렉터리 항목·읽기 8GiB·협력적 제한 시간 120초를 사용한다. 다음 파일의 최대 크기 2MiB를 예약할 여유가 없으면 읽기 전에 멈춘다. 제한·취소·실패 시 남은 조각만으로 정상 스냅샷을 만들지 않으며 새 출력 디렉터리에서 다시 생성해야 한다. 동기 파일 I/O 자체를 즉시 취소하는 계약은 아니다. `.knindex`, `.knchunk`와 임시 파일도 비공개 조사 자료로 Git 및 공개 정보 검사에서 제외한다.

## 원본 이미지 비교 재생

덤프에서 읽은 코드와 정확한 참조 파일을 함께 보존하려면 별도의 이미지 case를 만든다.

```text
KnLiveDbg.exe --offline !kmon verify-image <reference> <dump> <hex-base> <hex-rva> <length> <new-directory> /json
KnLiveDbg.exe --offline !kmon replay-image <directory> /json
KnLiveDbg.exe --offline !kmon replay-image <directory> /current /json
```

생성 시 전체 참조 PE를 SHA-256 이름의 `.knblob`에 저장하고, 읽기 순서·원본 바이트·정규화 입력·비교 결과를 담은 `recipe.knverify`를 마지막에 게시한다. 원래 참조 경로의 파일이나 대상이 사라져도 이 두 파일로 비교를 다시 실행한다. 기존 `.kncase` 재생과는 별도 경로다.

기본 재생은 당시 정책과 읽기 순서를 그대로 요구한다. 참조 손상·누락, 지원하지 않는 과거 정책, 정규화 또는 결과 불일치를 구분한다. `/current`는 현재 정책으로 다시 분석하며 당시 결과와 두 정책 식별자를 별도로 표시한다. 서로 다른 반복 읽기 바이트를 하나의 정상 스냅샷으로 합치지 않으며, loader 제외 범위도 검증 완료 바이트에 포함하지 않는다.

한 번에 AMD64 이미지의 최대 4KiB 범위를 기록한다. 참조는 최대 64MiB, 읽기는 64회·요청 128KiB, 명세는 2MiB다. 제3의 relocation base를 사용하는 alias는 별도 독립 근거가 없어 미검증으로 남긴다. 종료 코드 0은 게시 또는 재생 성공이며, 실제 판정은 `result.ownership`과 coverage를 확인한다. 수집기 인증·서명 승인·실행 관측을 제공하지 않는다. 파서 격리 전에는 신뢰할 수 있는 로컬 참조만 입력한다. case는 자동 삭제되지 않으며 실패 중 남은 파일도 수동 보존·정리 대상이다.

## 검증

```powershell
.\tools\validate-analyst-features.ps1 -Sanitize
.\tools\validate-analyst-features.ps1 -Configuration Debug
.\x64\Release\KnLiveDbg.exe --self-test all
.\tools\validate-command-audit.ps1 -Sanitize
.\tools\validate-kmon-core.ps1 -Sanitize
.\tools\validate-kmon-hunting.ps1 -Sanitize
.\tools\validate-evidence-bundle.ps1 -Sanitize
.\tools\validate-image-recipe.ps1 -Sanitize
# 위 도구가 출력한 run 디렉터리를 지정한다.
python tools\test-evidence-cli.py --executable x64\Release\KnLiveDbg.exe --fixtures <run-directory>
python tools\test-image-recipe-cli.py --exe x64\Release\KnLiveDbg.exe --fixtures <image-recipe-run-directory>
```

하네스는 변형한 PE32/PE32+ 구조, 읽기 실패와 루트 교체, 종료·예산 경계, PID 재사용, 64비트 JSON, 중복·잘린 입력, 원자적 저장과 덮어쓰기 거부를 검사한다. 실제 수집 경로는 자신이 만든 정상 TLS 콜백·스레드풀과 실행 권한이 없는 자체 이미지 후보로 확인한다. 서로 다른 보호 속성의 경계와 Guard·NoAccess 음성 대조, Unicode 경계 조합도 검사한다. 다른 프로세스에 코드를 주입하거나 커널 드라이버를 로드하지 않는다. [초기 검증 기록](https://github.com/kernullist/kn-live-dbg/blob/v0.0.35/docs/KMON_ANALYST_VALIDATION_20260920.md)과 [후속 적대적 리뷰](https://github.com/kernullist/kn-live-dbg/blob/v0.0.35/docs/KMON_ANALYST_REVIEW_20260920.md)에 실행 결과와 수정 내역을 구분해 기록했다. 실호스트 대조군과 별도 미검증 범위는 [검증 현황](VALIDATION.md)에서 구분한다.
