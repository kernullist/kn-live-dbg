# Kmon 은닉 코드 관측 범위

기준일은 2026-09-19다. 실제 게임핵·VM 검증은 사용자가 수행하며, 이 문서는 연구에서 확인한 기법을 현재 코드의 관측 경로와 대조한다. 기법 이름을 식별하는 것과 그 기법으로 숨긴 코드를 발견하는 것은 다르다. 공통 메모리 검사는 후자를 목표로 한다.

## 추가 조사 근거

- [EURECOM·University of Milan의 NDSS 2026 연구 소개](https://www.s3.eurecom.fr/post/2025/10/13/unveiling-byovd-threats-malwares-use-and-abuse-of-kernel-drivers/)는 드라이버 유입·로드·통신·실행·행위를 나눠 분석한다. 서명된 취약 드라이버 목록과 실제 악용 행위를 구분하며, 가상화 기반 외부 관측기를 사용한다. Kmon의 게스트 내부 읽기를 이 외부 관측과 동등하다고 취급하지 않는다.
- [Elastic, 2025-06-12](https://www.elastic.co/security-labs/threat-command/call-stacks-no-more-free-passes-for-malware)는 호출 스택의 탐지 가치와 구조적 한계를 함께 다룬다. 스택의 주소만으로 현재 실행이나 원래 호출자를 확정하지 않는다.
- [Elastic의 ETW 스택 연구](https://www.elastic.co/security-labs/doubling-down-etw-callstacks)는 threadless injection, 이미지 변형, 권한 변동과 스택을 연결한다. 주기적 검사와 이벤트 시점 캡처를 병행해야 짧은 노출 구간을 관측할 기회가 늘어난다.
- [SafeBreach의 Pool Party 원문](https://www.safebreach.com/blog/process-injection-using-windows-thread-pools)은 thread-pool work, wait, ALPC, job, direct 및 timer 객체를 이용한 실행 경로를 설명한다. 새 스레드 시작 주소 검사만으로 이 계열을 다루지 않는다. 해당 연구의 제품 비교 결과를 Kmon의 탐지율로 옮기지 않는다.
- [Microsoft VirtualQueryEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex)는 COW가 일어난 이미지도 MEM_IMAGE로 남을 수 있음을 명시한다. MEM_PRIVATE 분류나 첫 페이지의 Shared 비트만으로 이미지 전체를 판정하지 않는다.
- [Microsoft WFP callout 구조](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-fwps_callout0_)는 classify/notify/flow-delete 경로를 정의한다. 공개 API 구조는 `netio.sys` 내부 테이블의 빌드별 레이아웃을 보증하지 않는다.
- [Intel SDM](https://www.intel.com/content/www/us/en/support/articles/000006715/processors.html)의 페이징 규칙에 따라 상위 단계의 NX·U/S, 큰 페이지와 PAT를 구분한다. PTE 한 개의 NX만 보고 실행 권한을 정하지 않는다.

기존 CI 정책·수동 매핑·펌웨어 인터페이스 조사와 날짜는 [연구 기록](KMON_HUNTING_RESEARCH_20260919.md)에 있다. 오래된 기초 기법을 최신 사건으로 표시하지 않으며, 일반 악성코드 연구를 게임핵 표본 검증으로 계산하지 않는다.

## 기법과 수집 경로

| 기법 계열 | 현재 관측 경로 | 해석과 제한 |
|---|---|---|
| BYOVD, CI 정책·콜백 변형 | 드라이버 수명주기·잔존물, CI 관측, 커널 이미지 비교 | 현재 CI 값과 서명만으로 과거 우회 여부를 결정하지 않음 |
| 수동 매핑, PE 헤더·import 흔적 제거, RX pool 코드 | 커널 PTE/PFN·pool 교차 관측, 실행 영역 전체 페이지 순환 | PE 헤더·W+X·컴파일러 패턴은 필수 조건이 아님 |
| 로더 목록·driver object·pool 흔적 은닉 | 모듈·오브젝트·pool·페이지 관측 대조 | 모든 목록이 동시에 변조되면 페이지 관측과 읽기 실패도 조사 근거 |
| 커널 이미지 덮어쓰기, 코드 동굴, 인라인 분기 | 실행 섹션 전체 비교와 분기 목적지 검증 | 로컬 참조 파일이 신뢰 가능한 원본이라는 별도 운영 조건 |
| 정상 이미지의 헤더·데이터·padding을 실행 가능하게 변경 | PE 실행 선언과 현재 PTE 권한 대조 | `owned_unexpected_executable`; 바이트 변경이나 악성 판정과 구분 |
| Ps process/thread/image, registry, Ob, minifilter 콜백 | 실제 pre/post 함수 슬롯을 전후 재검증하고 코드 확인 | PDB 필드 폭을 확인한 슬롯만 검증된 채널로 연결; fallback은 별도 후보 |
| DPC·timer·work item·NMI·시스템 스레드 | 기존 예약 실행·커널 스레드·CPU 무결성 수집과 코드 검사 | 등록·대기 상태의 참조이며 현재 RIP가 아님 |
| firmware table, hive, ETW logger 통신 경로 | 등록된 함수 슬롯과 코드 경로 검사 | 요청의 발신자·프로토콜은 정적 포인터만으로 확정하지 않음 |
| WFP 네트워크 경로 | classify/notify/flow-delete 후보를 순환 코드 검사 | 내부 레이아웃은 추정값. 검증된 콜백이나 통신 연결로 승격하지 않음 |
| 유저 수동 매핑·raw shellcode·reflection | VAD·VirtualQuery·실제 PTE의 실행 영역 전체 페이지 순환 | 이미지 이름·헤더·신규 스레드·콜백 참조 없이도 수집 |
| 정상 프로세스 위장·정상 DLL 내부 implant | 선택된 모든 프로세스의 EXE/DLL 실행 섹션 비교 | 감시 이름·Windows 기본 프로세스 여부로 비교를 제외하지 않음 |
| hollowing·stomping·ghosted/replaced backing | 이미지 바이트 비교, 매핑 대조, 참조를 검증할 수 없는 실행 페이지 보존 | 정확한 기법명은 별도 분석. 참조 파일/헤더 확인 실패를 정상 일치로 취급하지 않음 |
| VAD unlink·VAD 권한 위장·PTE 직접 매핑 | 모든 선택 프로세스의 재개 가능한 사용자 페이지 테이블 순회 | VAD가 불완전하면 DKOM 확정은 제한되지만 현재 실행 페이지 읽기는 별도 재검증 |
| threadless·APC·thread-pool·TLS·VEH·WNF 기반 실행 | 전체 실행 메모리/이미지 검사, APC·instrumentation·ETW 스택 참조 | 모든 내부 객체의 callback 레이아웃을 해석한다는 뜻은 아님 |
| sleep encryption·NX/RX 변동·짧은 실행 구간 | 기존 이벤트 캡처와 주기적 페이지 검사의 병행 | 스캔 사이에만 복호화되거나 이벤트가 손실된 구간은 미관측 가능 |
| WOW64 payload | 아키텍처에 독립적인 페이지·이미지 검사 | x64 정적 분기 디코더를 x86 반환 주소에 적용하지 않음 |
| PPL·프로세스 query 핸들 제한 | 생성 시각·EPROCESS를 확인한 드라이버 읽기와 물리 페이지 읽기 | 모듈 소유권을 확인하지 못하면 `unknown`을 보존; 일부 스레드 메타데이터 수집은 제한 |
| 공유 section·물리 페이지 alias | 반복 관측한 PFN과 전체 페이지 SHA-256 | 동일 내용·동일 PFN은 통신 방향이나 쓰기 주체를 증명하지 않음 |
| 스택 위조·ROP·정상 코드 재사용 | 원본 스택·참조 경로·이벤트 행위와 변경 코드 대조 | 코드 바이트가 변하지 않는 행위는 메모리 내용 비교만으로 식별할 수 없음 |
| 세션별 win32k·GUI 경로 | 기존 그래픽스 포인터·사용자 이미지 검사, session coverage 기록 | 올바른 세션 주소 공간이 확인되지 않은 커널 페이지는 미검증 |
| 대체 CR3·EPT shadow·악성 하이퍼바이저 | 읽은 주소 공간과 CPU/가상화 관련 관측 | 센서에 제공되는 매핑과 실제 instruction fetch가 다르면 외부 관측 필요 |
| UEFI runtime·SMM·DMA 펌웨어 코드 | Windows에 남은 실행 매핑·후속 변형 및 관련 보안 상태 정보 | Windows firmware table handler 검사는 SPI flash/SMM/장치 펌웨어 검사와 다름 |

## 이번 보강의 구현 근거

전체 페이지 스케줄러는 영역이 다시 발견되어도 진행 위치를 초기화하지 않는다. 큰 영역과 작은 영역을 번갈아 처리하고, 이미지 페이지 재검사가 비소유 실행 영역이나 콜백 증거를 밀어내지 않도록 우선순위를 둔다. 상한 초과·오래된 영역 만료·백프레셔는 `coverage.page_candidates`로 기록한다.

사용자 PTE 순회는 방문당 최대 128개 테이블, hidden range 32개를 처리하고 PID·생성 시각별 VA 커서로 재개한다. 동일 물리 테이블의 다른 VA alias도 순회한다. 읽기 실패·예약 비트 오류·확인되지 않은 페이징 모드는 정상 결과로 처리하지 않는다. 1 GiB/2 MiB 매핑을 4 KiB 캡처와 혼동하지 않는다.

큰 페이지 안의 VAD 빈 구간과 권한 불일치 구간은 VA 오름차순으로 기록한다. 뒤쪽 불일치를 먼저 기록하면 결과 상한에서 재개 VA가 앞쪽으로 돌아가 같은 구간을 반복할 수 있다. 상한을 1개로 둔 통합 회귀에서 빈 구간·비실행 VAD·나머지 구간을 세 번의 패스로 중복 없이 열거하고 물리 offset을 유지하는지 검사한다.

페이지 검증은 현재 실행 권한, 반복 읽기 바이트, 프로세스 인스턴스와 확보한 PFN을 다시 확인한다. 물리 읽기 경로는 PTE가 확인된 페이지에만 적용한다. PAGE_GUARD로 확인된 주소는 일반 유저 가상 읽기를 보류한다. 등록 목록 스냅샷과 실제 읽기는 원자적이지 않으므로 무관측 구간이나 주소 재사용 가능성은 남는다.

합성 검사는 cursor·예산·alias·큰 페이지·NX/U/S·읽기 실패·PID 재사용·우선순위·소유권 미확정을 다룬다. 실전 결과와 구분해 기록하며, 이 표는 무누락 보증이나 탐지율 수치가 아니다.

현재 헌팅 주소 모델은 user VA `< 0x0000800000000000`, kernel VA `>= 0xFFFF800000000000` 범위다. 5단계 PTE를 순회하더라도 이를 벗어나는 확장 VA와 낮은 VA의 supervisor 전용 매핑은 사건 인덱스의 지원 범위가 아니다. 새 주소 범위를 지원하려면 실제 주소 공간과 실행 권한 도메인을 구분하는 모델 확장이 필요하다.
