# 2026-10-13 실호스트 검증

Windows 11 테스트 서명 호스트에서 Release/Debug 빌드, 회귀 검사, 실제 드라이버와
제어 가능한 fixture를 실행했다. 출력에서 확인한 쓰기 계획·복원 명령 오류,
DPC CPU 집계 오류, 드라이버 소유 모듈 캐시 오류, 모듈 페이지 조회 실패의 오탐을 수정했다.
최종 빌드와 영향받은 경로의 재검증은 통과했다. 다만 전체 기능의 완전한 호환성이나
호스트 전체의 정상 상태를 증명한 결과는 아니다.

## 호스트와 증거 범위

- 시작 revision: `6022361` (`v0.0.35`), 작업 트리 변경 없음.
- Windows 11 Pro `10.0.28000`, 커널 build lab `28000.2952`.
- VMware `VMware20,1`, 논리 CPU 2개, RAM 8,588,939,264바이트.
- 테스트 서명 활성화. UAC `EnableLUA=1`, 관리자 동의와 보안 데스크톱 값은 각각 0.
- VBS는 비활성 관측. 활성 HVCI 환경과 Driver Verifier는 이번 실행에 포함하지 않았다.
- 빌드 버전 `0.0.35`, 드라이버 ABI 17. 기존 테스트 인증서를 사용했다.
- 검증 과정에서 재부팅, 부팅/보안 정책 변경 및 외부 게시를 수행하지 않았다.
  후속 복원 경로 검증과 승인된 로컬 커밋의 대상은 아래에 별도로 기록한다.

원본 로그, JSON, fixture 제어 스크립트와 종료 코드는 다음 로컬 디렉터리에 있다.

```text
C:\git\kn-live-dbg\.build\live-validation-20261013-01a1334b
```

**검증 중 부팅이 바뀌었다.** 최초 부팅은 `2026-10-07 16:27:28.5 +09:00`,
현재 부팅은 `2026-10-13 15:37:15.5 +09:00`이다. Event 6008은 이전 비정상 종료를
`12:53:41`로 기록하고, Kernel-Power 41의 `BugcheckCode`와 네 파라미터는 모두 0이다.
같은 부팅 시각에 volmgr 46(덤프 초기화 실패)과 162(덤프 생성 성공)가 모두 기록됐다.
최종 관리자 조회에서 `MEMORY.DMP`, Minidump 및 LiveKernelReports의 덤프 파일은 발견되지
않았다. 이 자료로 종료 원인이나 드라이버와의 인과관계를 확정할 수 없다.

아래에서 최초 부팅의 결과와 현재 부팅의 결과를 구분했다. 이전 날짜의 검증 결과를
이번 실행의 성공 증거로 재사용하지 않았다. `host-before.json`, `host-current.json`,
`host-final-cleanup.json`, `reboot-event-review.json`, `unexpected-shutdown-fields.json`에
호스트 상태와 이벤트 원본을 보관했다.

## 수정한 결함

| 위치 | 실제 증상 또는 재현 | 수정 및 확인 |
| --- | --- | --- |
| `user/DpcTimerScanner.cpp` | CPU 2개에서 큐 4개를 CPU 4개로 집계 | 방문 CPU를 중복 제거. 실제 MCP 결과 `processorsSampled` 4 → 2 |
| `user/main.cpp`, 쓰기 안전 계획 | 32바이트 fill의 backup/verify 명령이 `32`를 16진수로 읽어 50바이트 조회 | 생성한 길이에 `0n` 접두사 적용. 실제 backup/verify가 정확히 32바이트 |
| `user/main.cpp`, 프로세스 선택과 복원 대상 | `f`/`fp`/`m`의 `/process` 인수 위치 및 복원 대상의 컨텍스트 선택이 실제 쓰기와 불일치 | 공통 인수 해석과 실제 쓰기 컨텍스트 선택을 사용. 암묵적 사용자 procctx의 backup은 저장된 세대를 유지 |
| `user/main.cpp`, 바이트 복원 명령 | 기본 진수 10에서 접두사 없는 16진수 복원 바이트를 잘못 해석하거나 거부 | 각 복원 바이트에 `0x` 적용. 진수 10/16 round-trip 회귀 검사 |
| `user/main.cpp`, typed field 복원 | `setfield`의 원본 읽기가 procctx를 사용하지 않아 같은 VA의 콘솔 프로세스 바이트로 복원 명령 생성 | e/f/m과 같은 컨텍스트 캡처 사용. 실제 같은 VA의 서로 다른 두 프로세스에서 원본 선택 및 복원 검증 |
| `user/main.cpp`, 부분 복원 읽기 | IOCTL 성공에 부분 읽기 8/16바이트가 포함되어도 8바이트 복원 명령 생성 | 요청 길이와 읽은 길이가 일치할 때만 생성. bitfield/미지원 field width도 복원 범위에서 거부 |
| `user/IntegrityScanner.cpp`, 소유 모듈 조회 | 초기 심볼 로드 뒤 `probe load`하면 정상 dispatch 28개를 모듈 없음/의심으로 표시 | 여섯 공개 무결성/오브젝트 진입점에서 모듈 목록 갱신. 실제 Probe 소유 모듈 정상, 의심 0 |
| `user/IntegrityScanner.cpp/.h`, 페이지 조회 판정 | 정상 Probe의 PAGE 마지막/INIT 첫 페이지 번역 실패가 모듈 불일치·의심 1건으로 승격 | 조회 불가를 정보 및 수집 공백으로 기록. 실제 의심/불일치 0, 조회 실패 정보 유지 |

마지막 수정은 이미지 이름에 대한 예외 목록으로 탐지를 숨기지 않는다. 확인된 W+X,
권한 불일치, 구조 이상 증거는 유지하고, 번역에 실패한 페이지의 상태는 알 수 없음으로
남긴다. JSON `summary.page_attribute_queries_complete`와 콘솔 `page_queries_complete`는
예정된 샘플 조회의 성공 여부다. 섹션의 첫/마지막 페이지와 최대 8개 내부 페이지를
샘플링하므로, 값이 true여도 이미지 전체 페이지의 무결성을 증명하지 않는다.

새 쓰기 계획/복원 회귀 검사 두 개는 수정 전 실패를 기록한 후 수정본에서 통과했다.
기존 섹션 회귀 검사도 조회 공백이 확인된 양성 증거를 지우지 않는지 확인하도록 갱신했다.
`repro-console.stderr.log`, 최종 native 로그, `final-integrity-verification.json`에 증거가 있다.

## 빌드와 회귀 검사

| 검사 | 관측 결과 |
| --- | --- |
| 최종 x64 Release/Debug 빌드 | 모두 종료 0, 버전 유지 |
| 최종 `--self-test all`, Release/Debug | 모두 종료 0. console 557, commands 2,342/등록 261, timeline 28, MCP 89, remote 66, connect argv 4 |
| 별도 `mcp-http`, Release/Debug | 각각 9개 통과, 종료 0 |
| 최초 `platform-query`, Release/Debug | 실행 종료 0. 수집 완전성은 false |
| 최종 관리자 `platform-query`, Release | CiTool 종료 0/정책 조회 성공. TBS `0x8028400f`, 수집 완전성 false, attestation trusted=false |
| ASan, Release/Debug의 command-audit·kmon-core·kmon-hunting·process-layout·analyst-features | 총 10개 게이트 모두 종료 0 |
| 독립 parser/completion ASan | 구성별 parser 275,002, completion 25,954개 통과 |
| hunting/page/FP 및 analyst 회귀 | hunting 11,326, page 54, FP 49, analyst 6,560개 통과 |
| hunt readiness와 runner/bridge/manifest 추가 게이트 | 통과. 비관리자 driver-service smoke의 명시적 skip은 실제 드라이버 검사와 별도로 기록 |

ASan 검사 대상 소스는 마지막 main/IntegrityScanner 수정에 포함되지 않았다. 수정 후
Release/Debug 통합 회귀와 실제 영향 경로를 다시 실행했다. 동일한 검사 결과를 중복
실행 횟수로 합산하지 않았다. `standalone-results.json`, `native-results-Release.json`,
`native-results-Debug.json`, `extra-gates-results.json`, `finish-validation-results.json`에
실제 종료 코드를 보관했다.

## 실제 실행 결과

| 기능 | 부팅 범위 | 결과와 실용적 한계 |
| --- | --- | --- |
| 드라이버/IOCTL/SCM | 최초 및 현재 | 최종 58/58. VA/PA 읽기·쓰기, 번역, 핸들별 write gate, 짧은 출력 버퍼의 무변경 거부, 소유권 충돌, 프로세스 세대, CPU/MSR/IDT, timeline, 정리 |
| 메모리 CLI | 현재 | `eb/ew/ed/eq`, physical edit, `f/fp/m`, compare/search, setfield, write-off 거부 실행. 4KB 수정/복원 독립 비교 차이 각각 0 |
| 사용자 메모리 컨텍스트 | 현재/최종 | 별도 RW 4KB 할당에서 진수 10으로 MCP 암묵적 procctx 및 명시적 process 쓰기, CLI `/process` fill/move/pattern fill 실행. 8단계 전체 페이지 비교 차이 0, 원본 복원 후 할당 해제 |
| VAD/메모리 PE | 최초 | 7개 target 시나리오, VAD 47, 실행/scan 일치 17, mapped PE 14. PID/EPROCESS/alias 결과 일치, coverage/cleanup complete=true |
| ESET 계열 IOC 양성/음성 | 최초 | 35개 시나리오, 양성 클래스 계약 32개와 음성 계약 통과. 실제 fixture 서비스 사용 |
| Cloud Files | 최초 | InSync 음성 및 Modified 양성 E2E/증거 검증기 통과 |
| CPU/등록/메모리 스캐너 | 최초, 현재 snapshot 및 영향 경로 재검증 | CPU, SSDT/IDT, callbacks/ETW/NMI, firmware, WFP/ALPC/WNF/hive, DPC/timer/workitem, input/pool, mapper/unloaded/PiDDB/CI/hash/payload/kpage/minifilter/BYOVD를 조회. 지원하지 않는 레이아웃과 샘플 공백은 경고로 유지 |
| I/O trace | 현재 | Probe arm·IOCTL 관찰·disarm 실행. 전후 dispatch 28개 주소가 모두 동일. 처음의 소유 모듈 없음 오탐은 캐시 수정으로 해결 |
| 전체 모듈 무결성 | 현재/최종 | 188개 모두 검사, 의심/W+X/불일치 각각 0, 출력 잘림 없음. 327개 섹션의 조회 공백을 경고로 유지하여 page_attribute_queries_complete=false |
| MCP | 현재 | loopback 실제 HTTP, 무인증 401, initialize/session, read-only 도구 67개 및 write 도구 포함 89개 목록 확인. 자원/메모리/번역/심볼/TI/DPC/쓰기 호출 실행 |
| remote | 현재 | loopback 실제 세션, ABI 17, 읽기/번역/driver 조회, 원격 unload 거부, 정상 종료 |
| BYOVD | 현재 | updater/status 및 무해한 메타데이터 fixture load/scan/unload. hint 1개, exact hash 0. 실제 취약 드라이버를 로드한 검사는 아님 |
| snapshot/diff | 현재 | 저장 11,647개 record, 중복 identity 0, 자기 파일 diff 0. domain warnings에 callbacks, Ntfs FastIO, layout/페이지 공백 등 기록 |

메모리 원본은 `(index * 13 + 90) & 255` 패턴이며 복원한 4KB의 SHA-256은
`0D6808443E6B9A4BE01E15B1D973584FDD0308839BCB22F88AE439AB73FC3BC4`다.
MCP의 수정 범위와 나머지 원본 영역도 독립 비교했다. 사용자 메모리 마지막 복원은 fixture
제어 프로세스가 자신의 할당을 원본으로 되돌린 결과이며 AI restore 실행 성공으로 해석하지 않는다.

`!pool pe`에서는 EtwB 할당에 PE 모양 및 지워진 MZ/e_lfanew 후보 1개가 관측됐다.
같은 주소의 `vtop`에서 2MB leaf PDE의 NX 비트가 설정된 것을 확인했다. 실행 이미지나
악성 코드라는 증거가 없으므로 후보로 남겼고, 태그 예외 목록을 추가하거나 결과를 숨기지 않았다.

## Hunt와 실시간 수집

최초 부팅 Deep+TI 3회, 현재 부팅의 캐시 수정 후 3회, 최종 수정 후 3회를 각각 별도
폴더에서 실행했다. 최종 3회의 scan 프로세스 수는 176/177/177개이고, 모두 findings=0,
TI active/available=true, coverage_complete=false다. 엄격한 clean-host 검증기는 모두
종료 1로 거부했고 analyzer의 `all_clean_complete=false`도 확인했다. 이는 정상적인
불완전 증거 거부이며 통과 수에 합산하지 않는다. 최종 공백에는 process triage가 포함된다.
Bind Filter silo의 unsupported 상태도 JSON에 남아 있다.

현재 부팅에서 KMON/TI/timeline을 켜고 10개 사용자 fixture 모드를 실행했다. 9개가 종료 0,
ghost는 delete-pending 상태에서 실제 경로 unlink를 확인하지 못해 종료 1이었다.

| 모드 | 실제 양성 출력 |
| --- | --- |
| overwrite | `finding.code_modified` 2, `process.hollow/exe_text` 1 |
| stamp | `process.hollow/hollow` 1 |
| nomz | `process.hollow/exe_no_mz` 1 |
| orphan-private | `process.hollow/exe_orphan_private` 1 |
| replace-main | `process.hollow/exe_private`, `exe_wx` 각각 1 |
| orphan-image | `process.implant/private_exec_pe`, `watched_unknown_module` 각각 1. `exe_orphan_image` 계약 통과로 주장하지 않음 |
| orphan-mapped-rx | `process.implant/mapped_exec` 1 |
| masquerade | `process.masquerade` 2 |
| mapped-readonly | 실행 orphan/hollow/implant 양성 없음. 수집 공백과 sensor 이벤트는 별도로 존재 |
| ghost | fixture 생성 실패. ghost 탐지 성공 증거 없음 |

이 결과는 제어된 fixture의 관측 증거이며 악성 행위나 실제 코드 실행의 확정 판정이 아니다.
수집 예산 및 검증 큐의 공백 경고도 유지했다. 원본은 `kmon-events.jsonl`, `ti-events.jsonl`,
`timeline-events.jsonl`, 모드별 집계는 `collector-classifications.json`이다.

## 덤프

현재 부팅에서 raw 4KB, live PE, 제한 RAM, 전체 RAM, 소유 프로세스, OS live dump를 생성하고
내장 분석기와 CDB로 확인했다.

| 산출물 | 관측 결과 |
| --- | --- |
| raw/PE | raw 4,096바이트. PE 13,963,264바이트; 메모리 재배치/IAT 적용 상태이며 원본 디스크 이미지와 동일하다는 의미는 아님 |
| 제한 RAM | 268,443,648바이트. 복사 성공, DTB가 포함된 물리 범위 밖이어서 모듈 분석 0; 부분 덤프 |
| 전체 RAM | 8,588,947,456바이트, 5 runs, 32,766 chunks, 복사 실패 0. 내장 분석/CDB의 로드된 커널 모듈 188개 base 모두 일치 |
| 소유 프로세스 | 8,327,254,016바이트, 42 runs. 6개 실패 chunk를 zero-fill, `complete=no`. 병합된 물리 범위에는 추가 커널 RAM도 포함 |
| OS live | 648,896,512바이트, OS API version 2 성공. CDB Kernel Bitmap 형식 인식 |

전체 RAM은 실행 중 스트리밍한 비원자적 덤프이며 헤더에도 inconsistent 표시가 있다.
CDB 사용자 모듈 목록에서 paged-out/corrupt 경고가 발생했다. 커널 모듈 일치와 사용자 목록의
완전성은 구분한다. 큰 전체 RAM/프로세스 파일은 분석 및 해시 기록 후 정확한 두 경로만
삭제했고, 로그·JSON·SHA-256을 `dump-artifacts.json`, `dump-cdb-kernel-comparison.json`에 유지했다.

## 실패 및 미검증 항목

- 미니필터 attach/detach/reattach를 수행했지만 baseline의
  `callbacks_coverage_complete=false`로 독립 E2E 검증기가 실패했다. 전체 detach 계약 통과 아님.
- Bind Filter fixture의 관리자 apply/remove는 `0x80070005`, 별도 SYSTEM remove는
  `0x80070057`이었다. API 제거 성공으로 주장하지 않는다. 최초 apply가 성공하지 않았고,
  완전한 empty global/process mapping inventory 및 원본 marker/hash를 독립 확인한 뒤
  이번 fixture 파일 네 개와 빈 디렉터리만 삭제했다. QoS 단계에는 도달하지 못했다.
- 전체 driver integrity는 의심 0이지만 Ntfs 확장 FastIO tail의 callback coverage가 불완전하다.
- ghost 양성, timer/work queue 및 일부 callback/HAL/ETW 레이아웃, 전체 orphan 페이지 탐지에는
  실제 실행 또는 수집 완전성의 제한이 있다. 해당 unknown 상태를 정상으로 바꾸지 않았다.
- 실제 TPM quote/PCR/AK 검증, 외부 attestation verifier, AI provider의 실제 응답은 미검증이다.
  관리자 CiTool 조회는 성공했지만 TBS 장치 조회는 불가하고 attestation trusted=false다.
- 외부 KD target, 두 PC LAN, 실게임/anti-cheat 장시간 FP soak, HVCI/Verifier 활성 환경,
  고의 재부팅·동시 unload 스트레스와 커널 hide/hook 양성 fixture는 실행하지 않았다.
- 검증 중 발견한 비정상 종료의 원인은 미확정이다.

## 최종 정리

마지막 관리자 audit에서 테스트 드라이버/서비스/프로세스/서비스 레지스트리,
51767–51770 listener, 테스트 예약 작업, KnLiveDbg ETW session/minifilter 및 knhunt 임시 파일은
모두 0이었다. 남았던 stopped 미니필터 fixture 서비스는 초기 부재, literal SYS 경로,
종류/해시를 확인하고 삭제했으며 SCM query 1060을 확인했다.

이번 Bind fixture와 임시 SYSTEM 정리 작업은 제거했다. 이전 세션의 빈 Bind 디렉터리와
기존 KMON fixture 디렉터리는 보존했다. `.build` 안의 검증 증거는 남겼다.
부팅 구성과 UAC 값은 시작 상태와 같고, 최종 추가 검사 동안 부팅은 바뀌지 않았다.
`host-final-cleanup.json`의 `cleanup_complete`, `boot_configuration_unchanged`,
`uac_unchanged`, `current_boot_unchanged`는 모두 true다.

## 후속 복원 경로 검증

사용자가 요청한 적대적 검토에서 위의 `setfield` 컨텍스트와 부분 읽기 결함을 추가로
수정했다. 기존 변경 범위의 파서 경계, 프로세스 선택, 컨텍스트 복사 수명, 모듈 목록
갱신의 잠금/스냅샷, 페이지 조회의 unknown/양성 판정 보존을 다시 검토했다.

두 프로세스에 같은 VA를 각각 할당하고, 대상 원본은 `0x5a`, 콘솔 프로세스 원본은
`0xe1`로 설정했다. 수정 전에는 `eb <va> 0xe1`이 생성됐고, 수정 후에는
`eb /process <target-pid> <va> 0x5a`가 생성됐다. 실제 native `setfield`로 한 바이트를
변경하고 생성된 복원 명령을 실행한 뒤, 별도 제어 프로세스의 4KB 전체 비교에서 차이 0을
확인했다. 콘솔 프로세스의 같은 VA 할당은 변경되지 않았다. Bitfield와 procctx 없는
사용자 주소의 복원 명령은 생략됐다.

물리 RAM 범위 끝의 읽기에서는 요청 16바이트/응답 8바이트의 성공한 부분 IOCTL을
관측했다. 수정 전에는 8바이트짜리 `peb` 명령을 만들었지만 수정 후에는 생성하지 않고
`restore read incomplete; expected 16 bytes, got 8; restore command omitted`를 기록했다.
이 경계에서는 읽기와 복원 계획 생성만 수행했으며 물리 쓰기는 실행하지 않았다.

후속 증거는 `.build\adversarial-review-20261013-01a1334b`에 있다. 수정 전 두 재현은 실패,
수정 후 live harness 17개 검사는 모두 통과했다. 통합 회귀의 기존 range/context 및
restore-byte gate에 컨텍스트 필드 보존, 컨텍스트 부재, 지원 field width/bitfield, 실패·부분·빈
복원 읽기를 추가했다. Release/Debug 빌드와 `--self-test all`(console 557), 실제 MCP 사용자
메모리 8단계 및 IOCTL 58개 검사를 다시 통과했고, 소유한 메모리/서비스를 정리했다.
`source-validation.json`은 검증 동안 main 소스가 바뀌지 않았음을 기록한다.

최종 변경 검토에서 추가로 확인된 결함은 없다. 기존 Deep+TI, Bind/QoS, ghost, TPM,
비정상 종료의 검증 한계는 위 기록대로 남아 있으며 전체 호스트 정상 판정이나 전체 기능
완전 검증의 성공으로 바꾸지 않았다. 커밋 대상은 검증된 코드 수정과 관련 문서이고,
로컬 원본 로그·스크립트·바이너리는 포함하지 않는다.
