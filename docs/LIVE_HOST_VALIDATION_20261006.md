# 2026-10-06 실기 검증과 수정

## 판정 범위

`C:\git\kn-live-dbg`의 소스를 이 PC에서 빌드하고 관리자 작업자로 직접 실행했다.
검증 중 발견한 구현 오류와 정상 Windows 동작에 대한 오탐을 수정했다.
호스트 또는 외부 의존성 때문에 실행할 수 없거나 관측 범위가 부족한 항목은
완전 통과로 처리하지 않는다. 실기 검증과 후속 적대적 리뷰의 재검증 결과를 아래 표에 기록한다.

시작 시 Git 작업 트리는 깨끗했고 HEAD는 `5394611`이었다. 버전은 `0.0.34`,
드라이버 ABI는 `17`을 유지한다. 이후 요청한 적대적 리뷰로 추가 경계 오류를 수정하고
회귀 검증을 갱신했다. 푸시와 릴리스는 수행하지 않았다.

원시 증거는 Git에서 제외되는 다음 디렉터리에 보존한다.

```text
C:\git\kn-live-dbg\.build\live-audit-20261006
```

## 호스트

| 항목 | 관측값 |
|---|---|
| OS | Windows 11 Pro, 10.0.28000 |
| 실행 환경 | VM, 논리 CPU 2개, RAM 약 8 GiB |
| 물리 메모리 | 5개 범위, 8,588,939,264바이트 |
| 테스트 서명 | 활성화, 실제 테스트 드라이버 로드 성공 |
| UAC | EnableLUA=1, ConsentPromptBehaviorAdmin=0, PromptOnSecureDesktop=0 |
| VBS | 실행 상태 0 |
| 도구 | VS 2022, MSVC 14.44.35207, SDK/WDK 10.0.26100.0 |
| 서명 | 기존 테스트 인증서 E269E2D141C692DAA047F0DA14ABB1D7690CD1AF |

인증서 신뢰 설정, 부팅 설정, Driver Verifier 설정은 변경하지 않았다.

## 수정한 오류

| 경로 | 재현과 수정 |
|---|---|
| ASan 검증 스크립트 | 최신 VS Community에는 필요한 x64 ASan DLL이 없어 시작이 실패했다. 기본 MSVC 버전과 같은 DLL을 가진 VS 설치를 선택하도록 공통 검색을 적용했다. |
| SymbolEngine | `dt _EPROCESS Protection`의 필드명 및 존재하지 않는 비공개 타입을 찾다가 무관한 지연 PDB를 연속 다운로드했다. 선택되지 않은 모듈의 암묵적 로드를 제한하고, 모듈을 명시한 타입 검색은 유지했다. CDB 스택으로 재현 경로를 확인했다. |
| IntegrityScanner | `\\SystemRoot\\` 디스크 경로, 부트 로더가 바꾼 ImageBase, 커널 API set의 실제 호스트를 처리하지 못했다. 독립 디스크 헤더를 기준으로 정규화하고 실제 API set 매핑을 반영했다. 해석할 수 없는 동적 재배치와 폐기 가능한 섹션은 미완료로 표시한다. |
| FAST_IO_DISPATCH | 풀에 있는 정상 콜백 테이블 자체를 코드 주소처럼 검사했다. 테이블 크기와 정렬을 검증한 뒤 콜백 목표를 검사한다. 외부 모듈로 벗어난 콜백은 계속 검출한다. 후속 리뷰에서는 지원하는 레이아웃보다 큰 테이블의 꼬리를 검사하지 않고도 완료로 표시한 오류를 수정했다. 알려진 콜백의 의심 증거는 보존하고 알 수 없는 꼬리는 coverage 미완료로 처리한다. |
| 드라이버 JSON | `delegated_to_loaded_module` 불리언 뒤에 불필요한 따옴표가 붙어 전체 JSON이 잘못됐다. 실제 전체 드라이버 출력의 표준 JSON 파싱으로 확인했다. |
| InputStackScanner | Microsoft 하드웨어 서명으로 배포된 VMware `vmusbmouse` 필터를 의심 항목으로 분류했다. 정확한 이름을 추가하고 유사 이름은 허용하지 않는다. |
| ProcessTriageScanner | 커밋되지 않은 예약 VAD를 PE처럼 읽고 읽기 실패를 검사 누락으로 합산했다. 필요한 커밋 영역에만 탐색을 적용했다. |
| UserModeHunter | CFG의 추가 이미지 페이지, CLR의 익명 mapped RX, 검증된 Microsoft 공유 모듈과 WebView 자기 이미지 트램펄린, 관리형 메서드 포인터를 오탐했다. 관측 범위·실행 권한·파일 및 서명·정확한 경로·점프 목적지 조건으로 좁혔다. 수정된 코드, PE, 외부 스레드 및 주입 대조군은 유지했다. |
| 원시 호출 테이블 | 디스크에서도 변하지 않은 정수 값이 우연히 private RX 주소와 같으면 후킹으로 판정했다. 기본 및 동적 재배치 메타데이터가 모두 완전하고 변경 가능 영역과 겹치지 않는 값만 제외한다. 후속 리뷰에서 동적 재배치가 불완전해도 제외될 수 있었던 경로를 회귀 테스트로 재현해 수정했다. 실제 수정된 슬롯과 IAT는 계속 검사한다. |
| 드라이버 검사 완료 판정 | 필드 읽기 실패를 0 포인터로 취급하거나 Fast I/O 미완료를 전체 판정으로 전달하지 않는 경로를 수정했다. identity와 28개 MajorFunction 슬롯, 콜백 필드, Fast I/O, 중단 및 누락 레코드를 함께 확인한다. 드라이버 JSON의 summary.coverage_complete와 Deep의 전체 coverage를 낮춘다. 누락 슬롯을 중복 인덱스로 채운 대조군도 완료로 처리하지 않는다. |
| 패키지 호스트 | `backgroundTaskHost.exe`가 자기 Store 패키지 DLL을 읽는 경우를 외부 주입으로 판정했다. 생성 시각이 일치하는 프로세스의 Windows 패키지 이름과 등록 경로를 소속 근거로 수집한다. 개별 코드·후킹 검사는 계속 수행한다. |
| SnapshotCollector | 같은 경로의 CI 캐시 항목 여러 개에 동일 identity를 부여해 자기 자신과의 비교도 실패했다. 같은 부팅 내 캐시 항목 주소로 구별하고 원시 주소를 증거에 저장한다. |
| I/O 추적 | `IoDriverObjectType`의 간접 포인터 선언이 잘못돼 객체 참조에 실패했다. 선언과 역참조를 수정했다. DeviceClient는 원래 IOCTL 오류를 짧은 응답 오류로 덮어쓰지 않도록 수정했다. |
| 테스트 실행기 | PPL 전환 뒤 `Process.WaitForExit`가 접근 거부로 실패했다. 생성 시 확보한 핸들로 대기·종료 코드 조회·필요시 정확한 소유 프로세스 종료를 수행한다. VAD 검증기의 전역 이름 기반 종료도 소유 Process 객체로 한정했다. |
| 종료 코드 | 종료 코드 259를 실행 중으로 오해하지 않도록 실제 핸들 상태를 확인한다. 소유 자식의 7, 259, -1 종료 코드를 각각 정확히 읽었다. |
| KMON 순환 검사 | 명시적 감시 대상이 다수의 자동 후보와 같은 순환 큐에 들어가 짧은 실행을 놓쳤다. 최대 8개 예산 안에서 명시적 감시 대상을 먼저 검사하고 다른 우선 대상과 배경 대상을 별도로 순환한다. 선택 순서도 실제 검사 순서에 반영한다. |
| KMON VAD 분류 | section PE 탐색에 포함된 정상 DLL을 private PE 후보로 내보냈다. 실제 MEM_IMAGE 할당의 주소와 backing 파일이 완전한 로더 목록의 항목과 일치하는 경우를 구별한다. Private/Mapped 할당, 다른 드라이브·파일, 불명확한 경로는 이 제외 조건을 통과하지 못한다. 코드 페이지·후킹 검사는 유지한다. 마지막 실기 대조 결과를 아래 기록한다. |
| orphan-image fixture | backing 파일을 실행 권한 없이 열어 `NtCreateSection`이 0xc0000022로 실패했다. 실행 권한, 완전한 파일 쓰기, delete-pending 성공을 확인한다. 최소 PE의 entry RVA도 `.text`에 맞췄다. 수정 전후 독립 재현에서 섹션 생성·매핑의 실패/성공을 확인했다. |
| ghost fixture | `GetFileAttributes`의 모든 실패를 파일 부재로 간주하지 않고 파일/경로 없음 오류만 인정한다. 접근 거부는 성공으로 바꾸지 않는다. |

## 회귀 및 실기 증거

| 항목 | 결과와 증거 |
|---|---|
| Release / Debug | 실기 수집의 `build-final12-*` 및 후속 `review-final-build-*` 둘 다 성공. 마지막 `review-final-native-*` all과 앞선 `review-fixed-native-*` HTTP/platform, 관리자 `review-minifilter-admin-*` 모두 종료 코드 0. console 555, commands 261개 등록/2,336개 검사, MCP 89, remote 66, timeline 28을 통과했다. 일반 권한의 minifilter 조회는 0x80070005로 거부됐으며 관리자 재실행으로 성공을 확인했다. |
| ASan | Release / Debug 명령 파서, KMON core/hunting, process layout, analyst 검증 모두 통과. `standalones-Release.json`, `standalones-Debug.json`. 영향 받은 공통 이미지 코드의 6개 추가 검사도 `affected-asan-final.json`에서 통과. |
| 스크립트·증거 게이트 | readiness, manifest, synthetic/replay 및 JSON 변이 검사 통과. 마지막 `final-regression12.json`에서 clean-host validator/runner self-test 모두 종료 코드 0. 변경된 PowerShell 파일 9개의 AST 파싱 오류 0. `powershell-source-parse-final.json`, `owned-process-exit-codes-final.json`. |
| 후속 리뷰 대조 | 수정 전 새 경계 대조군 2개가 `review-repro-native.log`에서 실패했다. 수정 후 Release/Debug 전체 자기 테스트에서 모두 통과했다. `review-readiness.log` 전체 게이트 통과; 비관리자 driver-service smoke는 skip으로 기록하고 이전 실제 드라이버 증거와 구별한다. |
| 소유 핸들 회귀 | 종료 코드 0, 7, 259, -1을 runner self-test에 편입했다. `review-runner-windows-powershell.log`, `review-runner-pwsh.log` 둘 다 종료 코드 0. 변경 PowerShell 파일 10개 AST 파싱 오류 0, `review-powershell-parse.json`. |
| 실제 메인/프로브 드라이버 | 58개 통과. VA/PA 읽기, vtop, 핸들별 쓰기 게이트, 짧은 출력의 무변경, 패치/복구, 정확한 프로세스 생성 시각, CPU/MSR/IDT, 타임라인 수명 및 SCM 정리. `live-driver-probe-final.worker.stdout.log`. |
| 복구 독립 확인 | 프로브 4,096바이트 재비교: 차이 0. SHA-256 `0D6808443E6B9A4BE01E15B1D973584FDD0308839BCB22F88AE439AB73FC3BC4`. `probe-restoration-verified.json`. |
| VAD | 47개 VAD / 17개 일치 / 14개 mapped PE, coverage_complete=true, cleanup_complete=true. `process-vad-final.worker.stdout.log`와 해당 validator 출력. |
| 실기 읽기 스캐너 | CPU, SSDT/IDT, 모듈/드라이버, 콜백/ETW/NMI, 펌웨어, WFP/ALPC/WNF/hive, DPC/timer/workitem, 입력, 풀/mapper, unloaded/PiDDB/CI hash, payload/kpage/minifilter/BYOVD 등을 실행했다. `live-scanners.commands.txt`, `live-scanners.stdout.log`. 부분 관측은 아래 제한을 따른다. |
| 전체 드라이버 JSON | 마지막 `review-final-driver-all.json`에서 158개 드라이버, 4,561개 Major/Fast I/O 콜백 목표, 의심 0을 관측했다. Dispatch 필드 검사 누락은 0이며, Ntfs Fast I/O 1개는 미완료라 summary.coverage_complete=false다. 앞선 빌드가 보고한 Fast I/O 누락 0은 미검사 꼬리를 완료로 계산한 오류였으므로 전체 검사 완료의 증거로 사용하지 않는다. |
| I/O 추적 | 실제 프로브에 arm, IOCTL 관측 2종, disarm, KMON/TI 중지와 서비스 제거 성공. `iotrace-final5.stdout.log`, `iotrace-final5-events.jsonl`. 독립 비교에서 dispatch 포인터 28개 모두 복구, 차이 0. `probe-dispatch-restored.json`. |
| ESET 방식 대조군 | 마지막 `eset-final5`의 35개 시나리오 게이트 통과; 32개 양성 시나리오가 모두 일치하고 음성 대조군을 검증했다. 실제 악성 드라이버는 실행하지 않았다. |
| Cloud Files | InSync 음성 및 Modified 양성 fixture validator 모두 통과. Placeholder API fallback도 관측했다. |
| BYOVD | 공개 카탈로그 9,759개 항목. 테스트 서명 fixture load/scan/unload 성공. 파일명/버전 힌트와 실제 악성 해시 일치를 구별한다. |
| 스냅샷 | `snapshot-final5.json`의 중복 identity 0. 실제 baseline/save/diff와 self-diff 수행. baseline의 정상적인 풀/프로세스 변동은 별도 후보로 남으며 악성 증거를 뜻하지 않는다. |
| 모듈 무결성 | `module-integrity-final5.json`에서 의심, 디스크 mismatch, IAT, prologue 항목 모두 0. 지원되지 않는 동적 재배치의 디스크 비교는 명시적으로 미완료다. |
| Deep + TI | 오탐 수정 후 `deep-ti-final5` 3회 모두 findings=0, TI active/available=true. 3회 모두 coverage_complete=false, all_clean_complete=false. strict validator는 실제 누락을 이유로 각 회 종료 코드 1. `deep-ti-final5-analysis.json`, `deep-ti-final5-strict.jsonl`. |
| 후속 최종 Deep + TI | `review-final-deep-ti` 1회에서 179개 프로세스, findings=0, TI active/available=true를 관측했다. coverage_complete=false이며 driver integrity 미완료 경고도 포함된다. strict validator와 analyzer는 각각 종료 코드 1로 불완전 상태를 확인했다. `review-final-deep-ti.strict.log`, `review-final-deep-ti-analysis.json`. |
| KMON/TI/timeline | `final6`에서 10개 fixture를 실행하고, `final8`에서 orphan-image, mapped RX, 읽기 전용 매핑과 ghost를 재검증했다. `final10`의 120초 MZ 제거 시나리오에서 실제 `exe_no_mz`를 확인했다. 마지막 `final12`의 3개 fixture 및 수집·export·stop·정상 종료는 모두 성공했다. `kmon-final12-validation.json`의 4개 의미 검증도 통과했다. |
| 원격 | 실제 loopback 인증, ABI 17 조회, 커널 읽기·주소 변환, 드라이버 무결성 조회, 세션 중 unload 거부를 확인했다. `live-transports-final6.json`, `remote-live.jsonl`. |
| MCP | 실제 HTTP.sys loopback 서버에서 인증 없는 요청 401, initialize 및 세션 ID 전달, 읽기 도구 67개 목록, 드라이버/심볼 resource, 가상 메모리 읽기·주소 변환·심볼 검색·TI 상태 조회를 확인했다. `live-mcp-final9.json`, `mcp-final9-live-1..8.json`. 정상 종료 코드 0. |

KMON의 마지막 대조에서 다음을 확인했다. 이 이벤트의 `lead`는 조사 근거이며
실제 코드 실행이나 악성을 확정하는 판정은 아니다.

| 시나리오 | 실제 관측 |
|---|---|
| overwrite / stamp / private PE / replace-main / masquerade | 코드 변경, PE identity 차이, `exe_orphan_private`, `exe_private`, 잘못된 Windows 이름/경로를 관측했다. `kmon-final6-events.jsonl`. |
| MZ 제거 | `process.hollow`, `exe_no_mz` 관측. `nomz-final-observations.json`. |
| orphan-image | 최종 PID 10016, 0x180000000의 PE와 `watched_unknown_module` 유지. 이 빌드에서는 커널 PE/외부 모듈 경로로 관측됐으므로 특정 `exe_orphan_image` layer의 성공으로 바꾸지 않는다. |
| mapped RX | 최종 PID 2996, `mapped_exec`, MEM_MAPPED(262144), RX(32), 4,096바이트 관측. |
| 읽기 전용 매핑 | 같은 바이트의 매핑에서 실행 orphan 이벤트가 없고, 정상 DLL의 `private_exec_pe` 후보도 0이었다. |
| 정상 DLL | 이전 대조군에서 나타난 일반 DLL 4개의 private PE 후보가 마지막 대조에서 제거됐다. 다른 드라이브·파일, private·mapped 할당을 제외하지 않는 네이티브 대조군도 통과했다. |
| ghost | fixture가 실행 파일을 delete-pending 상태로만 만들고 경로를 없애지 못해 종료 코드 1. 탐지 성공으로 계산하지 않는다. |

원시 마지막 결과는 `kmon-final12-observations.json`, `kmon-final12-events.jsonl`,
`ti-final12-events.jsonl`, `timeline-final12-events.jsonl`에 보존한다.

## 덤프

| 출력 | 관측 결과 |
|---|---|
| `nt-entry.bin` | 실제 커널 코드 4,096바이트 읽기와 저장 성공 |
| `nt-live-final4.exe` | 실제 NT base를 지정해 13,963,264바이트 PE 저장; 섹션별 결과는 stdout 참조 |
| `ram-capped.dmp` | 256 MiB 범위 1,025개 청크, 읽기 실패 0. 범위 밖 DTB 때문에 모듈 분석 0을 완전 분석으로 취급하지 않는다. |
| `ram-full.dmp` | 8,588,947,456바이트 파일, 물리 payload 8,588,939,264바이트, 32,766개 청크, 실패 0. 네이티브 분석 196개 모듈. |
| `os-live.dmp` | Windows API 압축 커널 live dump, 960,315,392바이트, 생성 성공 |
| `own-process.dmp` | 직접 만든 CLI의 /user 수집, 8,498,675,712바이트. 6개 청크가 zero-fill이라 complete=NO. 읽기 실패를 성공으로 바꾸지 않았다. |

Microsoft CDB가 `ram-full.dmp`를 Kernel Complete Dump, `os-live.dmp`를
Kernel Bitmap Dump로 열고 `vertarget; lm`을 수행해 종료 코드 0을 반환했다.
`cdb-ram-full.log`, `cdb-os-live.log`, `dump-artifact-hashes.json`에 독립 판독과
SHA-256을 저장했다. 라이브 RAM 수집은 실행 중인 시스템의 원자적 스냅샷을 보장하지 않는다.

## 미완료 및 호환성 제한

- Deep의 프로세스 읽기·PE 관측 범위와 일부 보호 프로세스 조회가 부족하다.
  findings=0만으로 clean-complete를 선언하지 않는다. 최종 분석에서도
  `all_clean_complete` 및 개별 `coverage_complete`를 확인한다.
- 콜백 일부 비공개 타입/필드, HAL/NMI 대체 경로, DPC/workitem, WdFilter 보호 영역,
  capped kpage/pool/mapper 범위에는 부분 관측이 남는다.
- Ntfs Fast I/O의 지원하지 않는 부분은 coverage 미완료로 남긴다. 알려진 콜백은
  검사하며, 후속 드라이버 JSON과 Deep 전체 결과도 이 누락을 반영한다.
- 이 커널의 동적 재배치 메타데이터는 공통 파서에서 unsupported로 관측됐다.
  원시 디스크 바이트의 차이를 확정 변조로 승격하지 않고 명시적인 검사 누락으로 기록한다.
  `nt-image-reference-check.log`에 독립 디스크/메모리 PE 비교를 보존했다.
- minifilter detach fixture는 실행했지만 콜백 관측이 부족해 strict validator가 실패했다.
  공개 Filter API 열거의 성공과 탈착 탐지 전체 성공을 구별한다.
- Bind fixture는 첫 `BfSetupFilter(NULL,...)`가 0x80070005로 거부돼 매핑을 적용하지 못했다.
  이 PC에는 공개 `bindlink.dll`도 없었다. 뒤의 QoS positive 단계는 실행하지 못했다.
- 하드웨어 TPM/TBS 경로가 준비되지 않았고, 실제 게임·안티치트 제품·attestation verifier,
  외부 KD 호스트, 실제 AI 공급자 자격 증명, PE-sieve 비교 기준은 제공되지 않았다.
  로컬 DbgEng `ExecuteWide`는 0x80040205를 반환했다. 이 항목들을 완전 통과로 계산하지 않는다.
- Driver Verifier 및 재부팅을 포함한 스트레스 검증은 수행하지 않았다.

MCP를 처음 점검한 보조 실행기는 HTTP.sys의 System PID 4 리스너를 자체 PID로
찾았고 세션 ID를 재전송하지 않았다. 읽기 도구 수와 인자 타입도 실제 catalog로
정정했다. 이 실행기 실패를 제품의 MCP 실패로 계산하지 않았다. 네이티브 결과
파일을 읽던 순간의 공유 잠금으로 첫 `native-final8` 기록이 중단된 사례는 보존하고,
실기 수집이 끝난 뒤 `native-last` 전체 회귀를 다시 실행해 통과와 결과 파일을 확인했다.

## 정리

실기 수집 종료 시 소유 서비스·프로세스·리스너의 관리자 점검은 `final-cleanup-audit12.json`에서 모두 0이었다.
후속 리뷰의 최종 `review-final-cleanup.json`에서도 같은 실행 상태의 정리를 재확인했다.
보호 프로세스 `MsMpEng.exe` PID 3124는 실제 WinDefend 서비스와 Windows Defender 경로로
구별해 보존했다. `live-phase12.json`에서 마지막 회귀·실기·정리 작업자와 각 의미 게이트의
종료 코드는 모두 0이다. MCP 연결 export의 stopped=true, port=0, 비밀번호/토큰 없음 및
환경 파일에 테스트 비밀번호 없음도 `mcp-stopped-export-verified.json`에서 확인했다.
메모리 덤프와 로그는 증거로 보존하며, 재사용한 인증서와 사용자 설정을 바꾸지 않았다.

Bind 테스트가 남긴 다음 폴더의 파일 4개와 빈 폴더를 삭제하려는 작업은 자동 승인
검토에서 두 번 거절됐다. 도구는 구체적인 사유 없이 정책 차단만 반환했다.
다른 방식으로 우회 삭제하지 않았다. 파일 ID가 각각 달라 활성 리디렉션이 없음을
독립 확인했고 `bind-fixture-cleanup-before.json`에 경로·ID·해시를 보존했다.
최종 파일 확인에서는 `amsi.dll`, `backing.dll` 두 개만 남아 있었다. 두 EXE의 부재를
확인했지만 사라진 경위를 별도로 관측하지 않았다. 따라서 임시 파일 정리 전체 완료를
선언하지 않는다. 남은 DLL의 해시는 원래 기록과 일치한다.

```text
C:\Users\dongdog\AppData\Local\Temp\KnLiveDbgBindFixture-2e75236f2b0e451080df0b605e0e8ed4
  amsi.dll
  backing.dll
  MsSense.exe
  ProcessBindingBacking.exe
```

별도로, 실제 fixture 로그로 소유를 확인한 다음 파일 3개와 빈 디렉터리만 삭제하려는
작업도 자동 승인 검토에서 구체적 사유 없이 정책 차단됐다. 삭제를 재시도하거나
우회하지 않았다. `owned-temporary-fixture-cleanup.json`에 원본 경로와 SHA-256을,
`preserved-temporary-fixtures`에 동일 해시의 복사본을 보존했다.

```text
C:\Users\dongdog\AppData\Local\Temp\kn-live-dbg-kmon
  artifact.pid
  ordinary-kmon-target.exe
  notepad.exe
```

최종 잔존 임시 파일은 Bind 2개와 KMON 3개, 총 5개다. 실행 상태의 정리는 완료됐지만,
임시 파일 삭제는 완료되지 않았다. 빌드 결과·덤프·로그·capture는 검증 증거로 보존했다.

## 참고

- Windows 패키지 소속: [GetPackageFullName](https://learn.microsoft.com/en-us/windows/win32/api/appmodel/nf-appmodel-getpackagefullname), [GetPackagePathByFullName](https://learn.microsoft.com/en-us/windows/win32/api/appmodel/nf-appmodel-getpackagepathbyfullname).
- API set의 호스트는 로더가 선택한다: [API set loader operation](https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation). 이 PC의 `.apiset` 관측은 `schema-hosts.json`에 보존했다.
- 객체 참조 계약: [ObReferenceObjectByPointer](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obreferenceobjectbypointer). WDK `wdm.h`의 외부 드라이버용 object-type 글로벌 선언과 실제 arm/disarm 결과를 함께 확인했다.
- 공개 Bind API의 OS/DLL 요구 사항: [CreateBindLink](https://learn.microsoft.com/en-us/windows/win32/api/bindlink/nf-bindlink-createbindlink).
