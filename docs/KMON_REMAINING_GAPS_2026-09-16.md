# !kmon 추가 은닉 탐지 공백 조사

이 문서는 구현 전 조사 기록이다. 후속 변경과 현재 관측 범위는
[구현·검증 문서](KMON_IMPLEMENTATION_2026-09-16.md)를 기준으로 확인한다.

조사 기준일: 2026-09-16. 대상은 `D:\kernullist\kn-live-dbg`, HEAD `b5804bcf873a3218e00bc15d2835cab1812aa5e3` 위의 미커밋 작업본이다. 직전 적대적 리뷰의 source snapshot 40개와 해시가 모두 일치하는 상태에서 조사했다. 이번 작업은 소스·문서·공개 원자료 대조이며 탐지 코드를 수정하거나 게임핵, 테스트 드라이버, 보호된 게임을 실행하지 않았다.

**추가 공백이 있다.** 새 기법의 부재뿐 아니라, 이미 수집한 증거를 자동 검사로 넘기지 않는 연결 문제, 정상으로 분류하는 과도한 조건, 반복해도 뒤쪽 후보를 방문하지 않는 제한이 확인됐다. 아래의 "확정"은 코드 경로가 확인됐다는 뜻이다. 실제 게임핵으로 전체 탐지를 우회했다는 뜻은 아니다.

기존 탐지에는 PEB와 커널 SectionBaseAddress 비교, private/mapped 실행 메모리, orphan PE/PTE, 모듈 목록 대조, 콜백 소유권과 일부 정적 분기, IAT/EAT, 일부 이미지 본문 비교, graphics cloned-vtable, instrumentation callback, TI 원격 주입 이벤트와 콜스택, WFP/minifilter, DPC, NMI 등록 목록이 포함된다. 아래의 공백은 이 기능들이 잡는 변형을 제외한 나머지 범위다.

`P1`은 다음 구현에서 우선 처리할 항목, `P2`는 수집 범위 확장, `P3`는 별도 신뢰 구조가 필요한 항목이다. 보안 취약점 점수는 아니다. 기존 한계의 기준은 [기존 coverage 문서](D:/kernullist/kn-live-dbg/docs/KMON_DETECTION_COVERAGE.md:205)다. 각 항목의 대조 검증은 이번에 실행한 테스트가 아니라 구현 후 필요한 검증이다.

**G01. P1 / 새 결함: DLL 경로에 Windows 디렉터리가 포함되면 일부 검사를 건너뛴다.**

- 근거: [DLL 분류](D:/kernullist/kn-live-dbg/user/KernelMonitor.cpp:15853)는 경로 중간의 `\windows\system32\`, `syswow64`, `winsxs`도 `windowsModule`로 인정한다. [foreign-module 및 text 검사](D:/kernullist/kn-live-dbg/user/KernelMonitor.cpp:15895)는 이 값을 신뢰한다. EXE에 적용한 엄격한 root 판정이 이 분기에는 연결되지 않았다.
- 남는 조건: 감시 중인 게임에 로드된 제3자 DLL의 경로가 정상 Windows 디렉터리처럼 보이는 중간 구성요소를 갖고, 이름이 별도 시스템 DLL 검사 대상도 아니면 일반 DLL 본문 검사와 여러 foreign-module 규칙에서 빠진다. `Program Files` 아래의 합성 경로로 분기를 확인했다. 다른 이벤트·메모리 검사까지 모두 우회한다는 주장은 아니다.
- 개선·검증: rooted 경로 판정을 한 함수로 통일하고 실제 DLL 검사 분기를 회귀 검증한다. 정상 System32/WinSxS, Windows가 중간에 있는 제3자 경로, 경로 별칭을 구분한다. 문자열 분류 이후에도 G16의 파일 실체 검증은 필요하다.

**G02. P1 / 새 연결 공백: 숨은 프로세스 발견이 후속 코드 검사로 이어지지 않는다.**

- 근거: [hidden 결과 처리](D:/kernullist/kn-live-dbg/user/KernelMonitor.cpp:8493)는 이벤트와 EPROCESS 일부 캡처, 수동 후속 명령만 남긴다. [UM 대상 구성](D:/kernullist/kn-live-dbg/user/KernelMonitor.cpp:13885)은 Toolhelp와 [명시적 watch PID](D:/kernullist/kn-live-dbg/user/KernelMonitor.cpp:13984)를 합친다. CID에서 새로 찾은 객체를 자동 후속 큐로 넘기지 않는다.
- 남는 조건: Toolhelp에 없고 기존 watch에도 없는 CID-only 프로세스는 숨었다는 사실이 탐지돼도 VAD·이미지·instrumentation callback 검사를 자동으로 받지 않는다. 별도로 [hostileHost 분류](D:/kernullist/kn-live-dbg/user/KernelMonitor.cpp:14142)와 [커널 fallback 조건](D:/kernullist/kn-live-dbg/user/KernelMonitor.cpp:14340) 때문에 watch/builtin/drop에 속하지 않는 접근 불가 제3자 호스트도 커널 후속 범위에서 빠질 수 있다. 이는 hidden-process 탐지 자체가 없다는 뜻이 아니다.
- 개선·검증: `(PID, EPROCESS, CreateTime)`을 가진 제한된 후속 검사 큐를 만들고, 읽을 때 세대를 다시 확인한다. CID-only 객체, 일반 제3자 보호 프로세스, 정상 종료, PID 재사용, PSS clone을 대조한다. 접근 거부는 악성 판정이 아닌 coverage 상태로 남긴다.

**G03. P1 / 기존 한계 구체화: 정상 커널 이미지 안의 코드·데이터 변경 범위가 넓게 남는다.**

- 근거: [orphan 열거](D:/kernullist/kn-live-dbg/user/OrphanKernelPageScanner.cpp:565)는 loaded-module 범위를 제외한다. [드라이버 baseline](D:/kernullist/kn-live-dbg/user/KernelMonitor.cpp:8694)은 PE header `0x400`과 entry point `0x100`만 비교하며 [로드 이벤트](D:/kernullist/kn-live-dbg/user/KernelMonitor.cpp:9551)에서 생성한다. 시작 전에 로드된 드라이버 전체에 동일 baseline을 만드는 경로는 없다.
- 남는 조건: driver stomping, 이미지 내부 code cave, 실행 권한을 얻은 데이터 영역, 콜백 본문이나 데이터 기반 분기의 변경이 이 좁은 표본과 별도 훅 지점을 건드리지 않을 때다. [콜백 entry 검사](D:/kernullist/kn-live-dbg/user/KernelMonitorInlinePatch.cpp:45)는 32바이트와 [최대 4회 정적 분기](D:/kernullist/kn-live-dbg/user/KernelMonitorInlinePatch.cpp:711)를 처리하며, 같은 이미지 안에 끝나는 변경이나 일반 명령으로 시작하는 본문의 의미를 검증하지 않는다.
- 개선·검증: 시작 시 module inventory를 확보하고 이미지 세대별 실행 섹션 및 실행 가능 데이터 페이지를 순환 비교한다. 독립 `IntegrityScanner::ScanModules`의 기능을 자동 경로에 연결하되 relocation, IAT, 정상 Hotpatch를 정규화해야 한다. entry 밖의 합성 변경, 정상 forwarding, 승인된 패치를 대조한다. 정상 Hotpatch가 실제 운영 기능이라는 점도 반영해야 한다. [Microsoft Hotpatch 문서](https://learn.microsoft.com/en-us/windows/deployment/windows-autopatch/manage/windows-autopatch-hotpatch-updates)

**G04. P1 / 새로 구체화한 제외: 세션 공간의 비 PE 코드는 세 군데에서 빠진다.**

- 근거: [orphan 결과 필터](D:/kernullist/kn-live-dbg/user/KernelMonitor.cpp:12160), [residual 수집기](D:/kernullist/kn-live-dbg/user/KernelMonitorMapperPool.cpp:506), [residual 판정기](D:/kernullist/kn-live-dbg/user/KernelMonitorMapperPool.cpp:437)가 session non-PE를 제외한다. 호출부에서 `IncludeSession=true`여도 이 필터는 적용된다.
- 남는 조건: 코드가 사용하는 session 주소 분류 안의 headerless RX/W+X나 알려진 stub도 residual 검사에 도달하지 않을 수 있다. 세션 PE는 이미 검사한다. 고정 주소 범위가 모든 Windows 빌드의 세션 매핑을 정확히 나타낸다는 보장은 별도로 검증해야 한다.
- 개선·검증: 세션별 정상 owner와 실행 영역 baseline을 만들고 비 PE라는 이유만으로 버리지 않는다. 세 필터를 함께 정리해야 한다. 같은 합성 body의 session/non-session 결과, 정상 win32k 영역, 다중 사용자·RDP 세션을 대조한다.

**G05. P1 / 추가 수집 범위: PTE와 PFN이 같은 단일 CR3에 묶여 있다.**

- 근거: [드라이버 register 수집](D:/kernullist/kn-live-dbg/driver/Driver.cpp:3731)은 IOCTL 요청 스레드를 CPU 0으로 옮긴 뒤 해당 주소 공간의 CR3를 읽는다. [orphan root](D:/kernullist/kn-live-dbg/user/OrphanKernelPageScanner.cpp:459)와 [PFN 재번역](D:/kernullist/kn-live-dbg/user/OrphanKernelPageScanner.cpp:986)은 이 root를 함께 사용한다.
- 남는 조건: 다른 process/session DTB에서만 보이는 매핑, 현재 self-map과 root로 VA 소유 관계를 복원할 수 없는 물리 페이지다. PFN 경로가 독립적인 전 물리 메모리 실행 코드 검사를 제공하는 것은 아니다. 정상 커널 매핑은 많이 공유되므로 모든 MDL/nonpool 할당이 빠진다고 해석하면 안 된다.
- 개선·검증: root identity와 process/session 세대를 보존해 별도 DTB를 검사하고 공유 page-table은 중복 제거한다. 물리 후보의 존재와 특정 VA의 실행 가능 판정을 구분한다. 동일 VA가 서로 다른 DTB에서 다른 PFN을 가리키는 fixture가 필요하다.

**G06. P1 / 기존 한계 구체화: headerless 일반 RX와 NX allocation 내부 PE가 남는다.**

- 근거: [mapper residual](D:/kernullist/kn-live-dbg/user/KernelMonitorMapperPool.cpp:447)은 검증된 특정 stub target이 있어야 판정한다. [일반 결과 선택](D:/kernullist/kn-live-dbg/user/KernelMonitor.cpp:12228)은 PE/W+X/import-stub 중 어느 것도 없으면 버린다. 평상시 import 검사는 nonpaged big-pool 후보에 제한된다. [PoolPeHunter](D:/kernullist/kn-live-dbg/user/PoolPeHunter.cpp:494)는 allocation의 첫 4KB만 검사하고, orphan PTE는 현재 executable인 leaf를 대상으로 한다.
- 남는 조건: 알려진 import wrapper가 없는 RX body, 패턴이 표본 밖에 있는 코드, 현재 NX이고 PE가 allocation 첫 페이지 뒤에 있는 경우다. NX allocation 시작의 PE나 현재 실행 가능한 뒤쪽 PE는 기존 검사에 걸릴 수 있다. small-pool tag 통계는 개별 allocation 주소를 제공하지 않아 이를 메우지 못한다.
- 개선·검증: unowned RX를 저신뢰 관측으로 보존해 실행 출처와 결합하고, pool allocation 내부에도 페이지 cursor를 둔다. PE 위치와 RX/NX 조합, import가 없는 합성 body, 정상 legacy executable pool을 대조한다. 원저자도 import wrapper 방식의 예외를 설명한다. [Tulach, 2024-07-12](https://tulach.cc/detecting-manually-mapped-drivers/)

**G07. P2 / 추가 제외 조건: large page와 고정 PA 구간을 정상 근거로 과신한다.**

- 근거: [LooksLikeSystemWxWindow](D:/kernullist/kn-live-dbg/user/OrphanKernelPageScanner.cpp:276)는 비 PE hardware large leaf의 W+X 위험도를 낮춘다. [LooksLikePciMmioHole](D:/kernullist/kn-live-dbg/user/OrphanKernelPageScanner.cpp:270)은 고정 PA 구간으로 MMIO 가능성을 판정하고, [kmon](D:/kernullist/kn-live-dbg/user/KernelMonitor.cpp:12143)은 `mmio` 결과를 body 검사 전에 건너뛴다.
- 남는 조건: 다른 탐지 패턴이 없는 large-page 코드, 실제 RAM/resource 배치와 고정 PA 가정이 다른 플랫폼이다. 분기는 확정됐지만 후자의 실제 오분류 여부는 플랫폼에 달려 있다.
- 개선·검증: page size를 위험도 보조 정보로만 쓰고, 제외에는 owner 및 실제 RAM/장치 resource 대조를 요구한다. 동일 body의 4KB/2MB leaf, 문제 구간을 RAM으로 선언한 fixture를 대조한다. 실제 physical range 수집 계약은 [Microsoft MmGetPhysicalMemoryRangesEx2](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-mmgetphysicalmemoryrangesex2)를 참고한다.

**G08. P1 / 새 진행 결함: 부분 PFN scan은 같은 watch에서 이어지지 않는다.**

- 근거: PTE table cap은 평상시 32,768/watch 65,536이고 [PFN cap](D:/kernullist/kn-live-dbg/user/OrphanKernelPageScanner.cpp:869)은 기본 4,194,304 entries다. [deep pending 소비](D:/kernullist/kn-live-dbg/user/KernelMonitor.cpp:12084)는 watch당 한 번이며 scanner가 완전히 실패할 때만 복구한다. cap으로 `PfnWalkComplete=false`인 성공 반환은 복구 대상이 아니다.
- 남는 조건: 열거 cap 뒤의 후보는 다음 body-window 순환으로 방문되지 않는다. 저장된 cursor는 이미 발견된 영역의 body에 대한 것이며 PTE 열거 stack/PFN range cursor가 아니다. **부분 coverage 이벤트는 이미 있으므로 silent clean이라고 부르면 부정확하다.** 문제는 표시된 미수집 영역을 계속 진행하지 못한다는 것이다.
- 개선·검증: 열거와 body sampling의 cursor를 따로 두고 root·세대 변화 시 재검증한다. 작은 인공 예산으로 경계 앞뒤 후보, partial read 후 재개, root 교체를 테스트한다.

**G09. P1 / 새 진행·표시 결함: mapper 흔적 출력 cap 뒤의 기록이 반복 탈락한다.**

- 근거: [MapperRemnantScanner](D:/kernullist/kn-live-dbg/user/MapperRemnantScanner.cpp:1492)는 우선순위별 stable partition 후 resize한다. [kmon limit](D:/kernullist/kn-live-dbg/user/KernelMonitor.cpp:10224)은 평상시 64/watch 256이다. [coverage 처리](D:/kernullist/kn-live-dbg/user/KernelMonitor.cpp:10239)는 원본 walk의 complete flag만 보고 출력 제한 warning을 별도로 표시하지 않는다.
- 남는 조건: 같은 우선순위의 안정된 후보가 limit보다 많으면 뒤쪽 PiDDB/CI 등의 기록은 반복 검사해도 반환되지 않는다. 출력 제한이 wipe 오탐을 억제하는 처리는 있지만 빠진 개별 증거를 나중에 보고하지는 않는다.
- 개선·검증: 수집과 보고 예산을 분리하고 identity별 보고 cursor 및 collected/reported/deferred 수를 노출한다. 정확히 256개와 257개인 합성 목록을 여러 pass에 걸쳐 대조한다.

**G10. P1 / 새로 구체화한 gate: 이름 없는 DRIVER_OBJECT가 fallback에서 탈락한다.**

- 근거: [type-list fallback](D:/kernullist/kn-live-dbg/user/IntegrityScanner.cpp:4807)은 directory/device view에 없는 객체를 찾고도 `DriverName`이 `\Driver\...` 형태가 아니면 `UnnamedCandidates`만 증가시키고 버린다.
- 남는 조건: type-list에 남아 있지만 이름이 비어 있거나 읽히지 않는 객체, 이 gate를 통과하지 못하는 `\FileSystem\...` 이름이다. type-list 자체가 유지되지 않는 환경은 별개의 수집 한계다.
- 개선·검증: 실제 객체 타입과 body/field 일관성으로 후보를 검증하고 이름은 별도 unknown으로 남긴다. 정상 이름·빈 이름·읽기 실패·filesystem 이름의 같은 합성 객체를 대조한다. 이름 검증 제거만으로 임의 메모리를 driver로 인정해서는 안 된다.

**G11. P1 / 기존 범위 + 새 표시 결함: callback 등록 이외의 활성 상태와 work-item을 덜 본다.**

- 근거: [CallbackScanner scope](D:/kernullist/kn-live-dbg/user/CallbackScanner.cpp:3147)는 Ob/Cm/Ps/minifilter이며 일반 executive callback object 전체 열거가 아니다. [빈 notify slot](D:/kernullist/kn-live-dbg/user/CallbackScanner.cpp:1897)은 현재 목록에서 건너뛴다. 현재 존재하는 주소만으로 정상 unregister와 제거·전달 차단을 구분하지 못한다.
- 추가 결함: [work-item 경로](D:/kernullist/kn-live-dbg/user/DpcTimerScanner.cpp:829)는 root만 조회하고 항상 `WorkItemCoverageComplete=false`인데 [kmon coverage 조건](D:/kernullist/kn-live-dbg/user/KernelMonitor.cpp:13265)은 DPC와 timer flag만 본다. 두 검사가 성공하면 work-item 미수집은 그 알림에서 사라진다. timer도 지원되는 root/PDB 레이아웃에 제한된다. [DPC의 모듈 소유 주소](D:/kernullist/kn-live-dbg/user/KernelMonitor.cpp:13288)와 NMI routine도 조기 통과하며 G03의 콜백 정적 분기 검사에 연결되지 않는다.
- 개선·검증: 등록·enable 상태·owner 수명을 완전한 이전 snapshot과 비교하고 일반 Ex callback 및 빌드별 queue를 추가한다. 정상 unregister/unload, owner가 살아 있는 상태의 등록 누락, DPC=true/timer=true/work=false를 대조한다. 과거의 private mask 비트 값을 최신 빌드에 그대로 적용해서는 안 된다. [ExRegisterCallback 공식 계약](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exregistercallback)

**G12. P2 / 새 연결 범위: IRP completion, WNF callback, filter attachment·정책 변화.**

- 근거: [driver dispatch](D:/kernullist/kn-live-dbg/user/KernelMonitor.cpp:11781), [WFP callout](D:/kernullist/kn-live-dbg/user/KernelMonitor.cpp:13356), [minifilter pre/post](D:/kernullist/kn-live-dbg/user/KernelMonitor.cpp:13461)는 이미 자동 검사한다. 실제 IRP의 completion 목적지는 다른 실행 연결이며 현재 iotrace에도 없다. [공식 completion 계약](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iosetcompletionroutine)
- 남는 범위: [WnfScanner record](D:/kernullist/kn-live-dbg/user/WnfScanner.h:27)는 owner/subscriber/raw 정보이며 callback 목적지 필드가 없다. kmon 호출도 없다. 별도 minifilter attachment query, WdFilter inventory, WFP 정책 inventory가 자동 callback 검사와 결합되지 않아 정상 주소를 유지한 detach/정책 변경도 별도 상태 비교를 받지 않는다. 모든 WNF/필터가 악성 통로라는 주장은 아니다.
- 개선·검증: IRP 수명이 보장되는 관측 지점, 버전이 검증된 WNF subscription, volume/filter 세대별 attachment·정책 snapshot을 사용한다. 임의 IRP 메모리 순회는 대안이 아니다. 정상 completion/cancel 경쟁, subscription 해제, 정상 volume 제거·filter detach를 대조한다. WNF의 기본 구조 근거는 [Quarkslab 원연구, 2018-10-25](https://blog.quarkslab.com/playing-with-the-windows-notification-facility-wnf.html)이며 현재 레이아웃 검증을 대체하지 않는다.

**G13. P1 / 기존 한계 + 자동 미연결: 정상 시작 주소를 유지한 실행.**

- 근거: [kernel thread 검사](D:/kernullist/kn-live-dbg/user/KernelMonitor.cpp:19867)는 시작 주소와 목록을 비교한다. [NmiScanner](D:/kernullist/kn-live-dbg/user/NmiScanner.cpp:334)는 NMI 등록 목록이며 NMI 시점의 CPU RIP/stack 수집기가 아니다. UM도 [Win32StartAddress](D:/kernullist/kn-live-dbg/user/KernelMonitor.cpp:4960)를 상관 증거로 사용한다.
- 남는 조건: 기존 thread context 재사용, APC 실행, threadpool work/timer/IoCompletion, kernel worker의 실행 목적지가 시작 주소와 다른 경우다. TI 원격 APC/context 이벤트와 콜스택은 이미 있다. 별도 [!hunt APC/stack 경로](D:/kernullist/kn-live-dbg/user/UserModeHunter.cpp:29458) 및 trap-frame 검사는 자동 호출되지 않는다. 큐 검사는 이미 실행돼 제거된 항목을 복원하지 못하고 saved trap frame도 항상 현재 실행 위치를 뜻하지 않는다.
- 개선·검증: 이벤트 시점의 실행 출처와 이미지/VAD 증거를 결합하고, 의심 객체에 한해 bounded APC·검증된 context·TP callback 후속 검사를 수행한다. 정상 I/O APC, threadpool timer, worker, overlay를 대조한다. [PoolParty 원연구, Black Hat Europe 2023](https://www.safebreach.com/blog/process-injection-using-windows-thread-pools/)는 이 범주의 실행 연결을 설명한다. 과거 EDR 실험 결과를 2026년 탐지율로 인용하지 않았다. 스택만의 신뢰에도 한계가 있다. [Elastic, 2025-06-12](https://www.elastic.co/security-labs/threat-command/call-stacks-no-more-free-passes-for-malware)

**G14. P1 / 기존 표본 한계 구체화: UM MEM_IMAGE 내부의 고정 표본 밖 변경.**

- 근거: [PE layout 선택](D:/kernullist/kn-live-dbg/user/KernelMonitor.cpp:637)은 `EXECUTE` 또는 `CNT_CODE` 플래그가 있는 첫 섹션을 택하고, [CompareLoadedModuleText](D:/kernullist/kn-live-dbg/user/KernelMonitor.cpp:2725)는 최초 최대 `0x1000`바이트와 조건부 최대 세 곳의 `0x100`바이트를 검사한다. [DLL 비교 gate](D:/kernullist/kn-live-dbg/user/KernelMonitor.cpp:15911)는 watch/drop 등의 조건을 두며 일반 DLL 16개, 시스템 DLL 16개, builtin 이미지 4개의 별도 예산을 사용한다. loader 소유 이미지에는 orphan 분류가 적용되지 않는다.
- 남는 조건: module stomping/image-backed 코드가 다른 실행 섹션, 표본 사이 또는 반복 방문하지 않는 뒤쪽 DLL에 있을 때다. 첫 페이지, 일부 export/IAT, 일부 main-image CoW 검사는 이미 있다. 별도 `!hunt deep`에도 예산과 일부 고정 표본 한계가 있어 호출만 연결하면 전수 검사가 되는 것은 아니다.
- 개선·검증: 모듈 로드 세대별 실행 페이지 cursor, CoW 후보 우선 비교, relocation/hotpatch 정규화를 결합한다. 두 번째 실행 섹션, 같은 비교 분류에서 16개를 소모한 뒤의 17번째 대상 DLL, 표본 사이의 변경과 정상 ASLR·보안 제품 패치를 대조한다. CoW 후에도 `MEM_IMAGE` 유형이 유지될 수 있다. [Microsoft VirtualQueryEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex)

**G15. P1 / 새 수집·신뢰도 공백: VEH/VCH, guard, HWBP 계열.**

- 근거: [UM 후보 gate](D:/kernullist/kn-live-dbg/user/KernelMonitor.cpp:4468)는 guard 페이지를 제외하며 VEH/VCH handler provenance나 예외 실행의 자동 상관 수집은 없다. instrumentation callback과 graphics cloned-vtable 검사는 이미 있으므로 이것들과 혼동하면 안 된다.
- 별도 검사 결함: [!hunt HWBP](D:/kernullist/kn-live-dbg/user/UserModeHunter.cpp:22636)는 실행 중 스레드에 안정된 snapshot 없이 `GetThreadContext`를 호출하고 이 함수 내 WOW64 처리가 없다. [앞선 PEB 검사](D:/kernullist/kn-live-dbg/user/UserModeHunter.cpp:22606)는 `BeingDebugged`만으로 생략한다. 이 함수를 그대로 자동 이식해서는 신뢰 가능한 전체 검사가 되지 않는다. [Microsoft GetThreadContext](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext)는 실행 중 thread의 유효 context를 얻을 수 없다고 명시한다.
- 개선·검증: 안정성이 검증된 context 관측, 예외 handler의 소유권·코드 무결성, guard 변화와 실행 이벤트를 결합한다. 모든 스레드를 무조건 suspend하는 설계는 피하고 지원하지 않는 대상은 unknown으로 표시한다. debugger, crash handler, Application Verifier, WOW64, 정상 guard 페이지가 대조군이다. TLS callback 배열의 무결성도 후속 조사 대상이며 [TLSCheck 2.0, 2026-04-22 preprint](https://arxiv.org/abs/2604.20378)는 연구 참고다. 이 preprint의 abstract만 검토했으며 제품 검증이나 게임핵 사용 증거로 삼지 않았다.

**G16. P2 / 기존 파일 실체 한계 + 새 생성자 귀속 공백.**

- 근거: 경로·PEB·section base 교차 검사는 있으나 backing FILE_OBJECT, volume/file ID, load 세대를 일관되게 묶는 자동 증거는 부족하다. 별도 [!hunt 파일 정보](D:/kernullist/kn-live-dbg/user/UserModeHunter.cpp:7277) 및 [Bind Filter/Cloud Files 대조](D:/kernullist/kn-live-dbg/user/UserModeHunter.cpp:29622)는 자동 경로에 연결되지 않는다. hardlink/reparse, 파일 교체·삭제를 동반하는 이미지 정체성 문제는 단순 path 비교로 끝나지 않는다.
- 추가 범위: [process notify 기록](D:/kernullist/kn-live-dbg/driver/Driver.cpp:647)은 지정된 `ParentProcessId`를 저장하지만 실제 `CreatingThreadId.UniqueProcess`를 별도로 보존하지 않는다. [ALPC inventory](D:/kernullist/kn-live-dbg/user/AlpcScanner.cpp:1720)도 자동 행위 귀속에 연결되지 않으며 port 소유자만으로 원래 요청자를 증명할 수 없다. 부모·broker의 정상 외관과 실제 작업 주체는 구분해야 한다. [PS_CREATE_NOTIFY_INFO 공식 구분](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_ps_create_notify_info)
- 개선·검증: backing file identity, creator PID/TID와 지정 parent의 각각의 세대, 가능한 broker 요청 상관관계를 따로 기록한다. 정상 hardlink/junction 설치, servicing, UAC·COM/RPC broker, 명시적 parent 지정, PID 재사용을 대조한다. 불일치만으로 악성으로 판정하지 않는다.

**G17. P1 / 새 진행·분류 공백: 기존·복제 핸들과 객체 관계.**

- 근거: [watch handle 대상](D:/kernullist/kn-live-dbg/user/KernelMonitor.cpp:16422)은 정렬한 PID 중 8개만 선택하고 순환하지 않는다. [결과 처리](D:/kernullist/kn-live-dbg/user/KernelMonitor.cpp:16487)는 최초 관측을 silent baseline으로 삼고 학습한 한 타입의 새 handle만 보고한다. scanner의 `Suspicious`, `CoverageComplete`, `Truncated`를 자동 판정에 사용하지 않는다.
- 남는 조건: 9번째 이후 PID, 감시 전부터 존재한 위험 handle, Process/Thread/WorkerFactory/IoCompletion의 권한·대상 관계다. [타입 학습](D:/kernullist/kn-live-dbg/user/DeviceClient.cpp:163)은 자기 `CreateFileW` handle에서 얻으므로 DEVICE_OBJECT 타입 검증이 아니라 FILE_OBJECT 타입이다. 일반 파일도 같은 타입이라 현재 device-handle 메시지의 의미가 과하다. 파일 객체가 장치도 나타낸다는 계약은 [Microsoft ZwCreateFile](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatefile)에 설명돼 있다.
- 개선·검증: process generation·object·권한별 관계를 수집하고 최초 위험 상태도 평가한다. PID 순환과 partial 표시를 추가하며 device와 일반 file을 실제 객체 관계로 구분한다. 8/9 PID 경계, 기존·복제 handle, 정상 debugger/Process Explorer/anti-cheat를 대조한다.

**G18. P2 / 기존 시간 한계 구체화: 짧은 매핑과 local NX/RX 전환 이력.**

- 근거: [UM 기본 간격](D:/kernullist/kn-live-dbg/user/KernelMonitor.cpp:59)은 8초이고 [WorkerLoop](D:/kernullist/kn-live-dbg/user/KernelMonitor.cpp:7611)는 여러 무거운 검사를 직렬로 수행한다. 다음 tick을 완료 뒤에 설정하므로 8초가 전체 재관측 지연의 상한은 아니다. TI local 이벤트가 raw 수신될 수 있어도 [watch task 기록](D:/kernullist/kn-live-dbg/user/KernelMonitor.cpp:8150)이 allocation별 반복 보호·내용·실행 전이 이력을 만들지는 않는다.
- 남는 조건: 표본 사이에 나타났다 사라지는 code/mapping, NX 상태에서 대기하다 짧게 실행하는 body, 잠깐 바뀌는 callback이다. 원격 주입 이벤트와 관측 순간의 RX/PE는 이미 탐지 근거다.
- 개선·검증: `(process generation, allocation generation)`별 이벤트 이력을 만들고 의심 변화에 제한된 즉시 검사를 예약한다. coverage에는 실제 관측 시각·소요 시간·재방문 지연을 남긴다. 무해한 보호 상태 전이, 정상 .NET tiered JIT/Wasm/patcher를 대조한다. 단순 주기를 줄이는 것만으로 연속 관측이 되지는 않는다.

**G19. P2 / 추가 분류 공백: JIT/CLR/Wasm의 주소별 출처.**

- 근거: kmon의 영역 속성·entropy·thread start에는 runtime이 생성한 개별 코드 주소의 출처가 없다. 별도 [!hunt JIT 분류](D:/kernullist/kn-live-dbg/user/UserModeHunter.cpp:5431)는 이름·runtime DLL에 의존하며 [trap RIP](D:/kernullist/kn-live-dbg/user/UserModeHunter.cpp:21952)와 일부 direct-syscall 후보를 생략한다. 이를 광범위한 신뢰 예외로 옮기면 빈틈이 커진다.
- 개선·검증: CLR MethodLoad/rundown의 주소·크기·module ID, 가능한 엔진의 code-cache 정보와 메모리 변경 이력을 대조한다. runtime 안에서 생성됐다는 사실과 코드가 선의라는 판단도 구분한다. DynamicMethod, Unity Mono, WebView2/Wasm을 정상 대조군으로 사용한다. [Microsoft Method ETW Events](https://learn.microsoft.com/en-us/dotnet/framework/performance/method-etw-events)

**G20. P1 / 새 건강 상태 결함: TI가 조용해진 이유와 실제 수신 종료를 알기 어렵다.**

- 근거: [IngestThreatIntel](D:/kernullist/kn-live-dbg/user/KernelMonitor.cpp:7933)은 inactive면 조용히 반환하고 subscriber의 `SnapshotStats()`를 소비하지 않는다. [ProcessTraceThread](D:/kernullist/kn-live-dbg/user/ThreatIntelSubscriber.cpp:582)는 `ProcessTrace` 반환 상태를 기록하거나 `Active`에 반영하지 않는다. 별도 [BuildTiCrossView](D:/kernullist/kn-live-dbg/user/EtwScanner.cpp:2024)는 누적 수신이 0인 경우만 silent라서 과거 한 건을 받은 후 멈춰도 다른 조건이 없으면 healthy에 도달한다.
- 남는 범위: 센서 중단·손실·오래된 관측을 무이벤트 상태와 구별하기 어렵다. `EventsDropped`는 ring eviction 수이므로 모두 kmon 미수신 손실은 아니다. 실제 소비 손실은 sequence gap과 함께 확인해야 한다. standalone ETW provider 검사는 heuristic/partial이므로 그대로 정상 판정에 연결할 수 없다.
- 개선·검증: trace thread 생존·종료 이유, session 설정, 최근 수신 증분, ETW loss, consumer sequence gap을 별도로 노출한다. TI 비활성, 한 건 후 종료, ring overwrite, 정상 idle, 권한 부족을 대조한다. idle 자체를 공격으로 판정하지 말고 필요한 기능의 관측 가능성을 표시한다.

**G21. P1 / 추가 운용 공백: signed/BYOVD 판정의 freshness와 실제 정책 상태.**

- 근거: [자동 BYOVD options](D:/kernullist/kn-live-dbg/user/KernelMonitor.cpp:13639)는 `AutoUpdate=false`, `EnableYara=false`, `CheckAuthenticode=false`다. hash/version 매칭은 있으므로 basename-only 검사는 아니다. 다만 catalog age, file-read 실패 등 진단을 kmon이 충분히 전파하지 않는다. [VBS/CI 소비](D:/kernullist/kn-live-dbg/user/KernelMonitor.cpp:13573)도 CI/test-sign 일부 상태 위주다.
- 남는 조건: 오래된 catalog, 읽지 못한 driver 파일, 새로 악용된 정상 서명 driver, 코드 주입 없이 기존 driver의 기능만 악용하는 경우다. 서명 확인을 켜도 안전성 증명은 되지 않는다. ESET은 2026-03-19에 취약 driver뿐 아니라 정상 anti-rootkit 도구와 driverless 센서 방해가 함께 사용되는 실제 침해 사례를 정리했다. 이는 게임핵 실사용 자료는 아니다. [ESET 원자료](https://www.welivesecurity.com/en/eset-research/edr-killers-explained-beyond-the-drivers/)
- 개선·검증: catalog 버전/나이, hash-read coverage, signer/revocation 결과, CI policy ID와 audit/enforce를 독립 증거로 기록한다. 2026년 4월 Windows Driver Policy 변화도 대상 시스템과 활성 상태에 따라 달라지며 audit에서는 driver가 허용된다. 단일 CI bit로 적용 여부를 단정해서는 안 된다. 정상 서명 취약/비취약 driver, 오래된 catalog, audit/enforce 환경을 대조한다. [Microsoft Windows Driver Policy](https://support.microsoft.com/en-us/windows/hardware/drivers/the-windows-driver-policy)

**G22. P3 / 기존 신뢰 한계 구체화: DMA·pre-boot·하이퍼바이저 아래의 관측.**

- 근거: 별도 [DMA posture](D:/kernullist/kn-live-dbg/user/DmaPostureScanner.cpp:211)는 DMAR/IVRS 및 정책 단서를 사용하고 [hypervisor posture](D:/kernullist/kn-live-dbg/user/HvPostureScanner.cpp:55)는 CPUID/timing 등을 본다. 이것들은 실제 pre-boot IOMMU 강제나 실행 중 EPT 관측의 원격 증명과 다르며 kmon의 외부 신뢰 근거도 아니다.
- 실제 게임 보안 근거: Riot은 2025-12-18에 일부 firmware가 pre-boot DMA 보호를 활성 상태로 보고하면서 IOMMU를 제대로 초기화하지 않는 문제를 공개했다. 따라서 설정·테이블의 존재만으로 방어가 실행됐다고 볼 수 없다. [Riot 원자료](https://www.riotgames.com/en/news/vanguard-security-update-motherboard) Activision은 2025-12-04 공지에서 TPM/Secure Boot와 외부 서버를 통한 Remote Attestation 사용을 설명했다. [Activision 원자료](https://www.callofduty.com/blog/2025/12/call-of-duty-ricochet-anti-cheat-update-season-01)
- 개선·검증: firmware/vendor 상태와 측정 부팅 증거, nonce가 있는 원격 검증, VBS/IOMMU의 실제 적용 범위를 별도 보안 계층으로 설계한다. TPM이나 attestation도 모든 런타임 메모리 변조를 증명하지는 않는다. 정상 Hyper-V/WSL, 지원 불가 장치, audit·enforce 차이를 대조해야 하며 hypervisor 존재만으로 치팅 판정을 내려서는 안 된다.

**B01. P1 / 조사 중 추가 발견한 correctness 결함: NT 경로 변환의 범위 밖 읽기.**

[KmonDevicePathToWin32](D:/kernullist/kn-live-dbg/user/KernelMonitor.cpp:3913)는 prefix 비교 전에 `deviceLower[targetLower.size()]`를 평가한다. 입력 NT 경로가 drive target보다 짧으면 `std::wstring` 범위 밖이다. 길이가 같을 때만 앞 조건으로 보호된다. 길이 및 prefix 일치를 먼저 확인한 후 separator를 읽도록 바꿔야 한다. 짧은 네트워크 NT 경로, 더 긴 DOS-device target, 정확히 같은 경로, 비슷한 volume 이름의 회귀 입력이 필요하다. 정적 코드 결함을 확인했으며 실제 crash는 이번에 재현하지 않았다. 이 항목은 새로운 은닉 기법과 구분한다.

**최근 공개 연구와 게임핵 사용 증거의 구분**

2026-05-22 Elastic의 PHANTOMPULSE 분석에는 이미지 내부 코드 변경과 HWBP/VEH 기반의 prologue 비변조 실행이 나온다. G14/G15를 검사할 필요성을 뒷받침하는 일반 Windows 침해 사례이며 게임핵 표본은 아니다. 해당 분석의 일부 sleep encryption 및 unhooking은 비활성 코드로 구분돼 있으므로 활성 공격 증거로 세지 않았다. [Elastic PHANTOMPULSE 원자료](https://www.elastic.co/security-labs/threat-command/blockchain-c2-phantompulse-rat-sinkhole)

2026-08-14 Kaspersky의 CoolClient 분석도 process/module hiding, callback 및 filter 계열이 결합된 최근 Windows rootkit 사례다. 제공되는 기능과 실제 분석 실행에서 호출된 기능은 구분해야 한다. 이 자료를 특정 게임핵이 동일 기법을 사용한다는 증거로 취급하지 않았다. [Kaspersky 원자료](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028/)

PoolParty와 WNF 등의 원연구는 각각 2023년과 2018년이다. 검색 엔진의 최근 색인 날짜를 새 기법 공개 날짜로 쓰지 않았다. DMA/pre-boot와 attestation은 위 Riot/Activision의 게임 보안 원자료에서 직접 확인한 범주다.

**권장 구현 순서와 완료 판정**

1. **먼저 직접 결함을 닫는다.** G01 DLL 경로, B01 문자열 경계, G08/G09/G17 진행과 partial 표시, G11 work-item coverage, G20 TI 종료·liveness를 수정한다. 작은 합성 입력으로 현재 분기 실패를 고정하고 실제 생산 함수의 회귀를 검증한다.
2. **발견한 대상을 계속 추적한다.** G02 suspect queue, G10 이름 없는 객체, G04/G05 세션·주소 공간 범위, G03/G14 실행 페이지 순환을 연결한다. 객체 세대와 실제 방문 범위가 증거에 남아야 한다.
3. **실행 출처를 넓힌다.** G12/G13/G15/G16/G19의 callback·context·예외·파일/creator·runtime 출처를 지원 빌드별로 검증한다. 독립 명령을 단순 호출하는 것만으로 완료 처리하지 않는다.
4. **운용과 신뢰 계층을 검증한다.** G18 실제 지연, G21 catalog/policy, G22 외부 신뢰를 측정한다. 정상 JIT·overlay·DRM·PPL·Hotpatch·Hyper-V 환경의 오탐 검증과 Windows 빌드별 live 검증이 별도 종료 조건이다.

이 보고서는 누락 조건 22개 묶음과 별도 correctness 결함 1개를 기록한다. callback 미관측, 짧은 실행, 동일 권한에서 여러 view를 함께 조작하는 경우까지 모든 기법을 완전 탐지한다는 보장은 제공하지 않는다. 직전 357/28/44개 self-test 통과는 기존 구현 검증 기록이며, 이번에 발견한 공백의 해결이나 실제 탐지율을 입증하지 않는다. 기존 raw IRP hook의 안전한 언로드를 요구하지 않는 사용자 결정은 이번 조사에서 변경하지 않았다.
