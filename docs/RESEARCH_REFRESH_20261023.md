# 2026-10-23 CI/HVCI 및 메모리 탐지 검토

기존 설계·검증 문서와 현재 소스를 읽은 뒤 관련 일차 자료를 다시 확인했다.
아래는 이번 수정과 테스트 선택에 사용한 범위이며, 전체 연구 ledger의 재검토나
모든 최신 공격 기법의 탐지 지원을 뜻하지 않는다.

| 일차 자료 | 확인 내용과 적용 |
| --- | --- |
| [Microsoft, 2026-09-01 HVCI 적용 확대 안내](https://techcommunity.microsoft.com/blog/windows-itpro-blog/expanding-memory-integrity-protection-across-windows-devices/4551984) 및 [공식 Windows message center](https://learn.microsoft.com/en-us/windows/release-health/windows-message-center) | 2026년 10월부터 적격 장치의 메모리 무결성 적용을 점진적으로 확대하며 기존 관리자·사용자 설정을 존중한다. 따라서 OS 버전이나 설정값만으로 실제 실행 상태를 가정하지 않고 관측 결과를 구분한다. |
| [Microsoft NtQuerySystemInformation](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation#system_codeintegrity_information) | 공개 CI 상태는 `SystemCodeIntegrityInformation`으로 조회한다. HVCI 활성·감사·엄격·IUM 비트는 각각 `0x400/0x800/0x1000/0x2000`, CI 디버그 비트는 `0x80`이다. 비공개 `g_CiOptions`에 이 마스크를 적용하던 경로를 교체했다. |
| [Microsoft Hyper-V TLFS 인터페이스 발견 규약](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/feature-discovery) | CPUID 최대 leaf 값만으로 Microsoft 기능 leaf를 해석할 수 없다. `0x40000001.EAX`의 `Hv#1` 인터페이스 서명으로 호환성을 판단하도록 수정했다. 공급자 이름은 표시용이며 호환성 결정에 사용하지 않는다. |
| [Elastic, PHANTOMPULSE, 2026-05-22](https://www.elastic.co/security-labs/threat-command/blockchain-c2-phantompulse-rat-sinkhole) | 연구는 하드웨어 중단점과 모듈 stomping·수동 매핑을 서로 다른 관측 대상으로 다룬다. 저장소의 디버그 레지스터 수집, 실행 메모리, 이미지 검증 경로를 확인하고 자체 fixture 검증 대상으로 삼았다. 실제 PHANTOMPULSE 샘플을 실행하거나 그 탐지 성공을 주장하지 않는다. |

## 구현

- `CodeIntegrityState.h`의 공통 조회기를 `!ci`/`!vbs`, KMON 플랫폼 증거 및
  CI 상태 이벤트에 적용한다. 반환 상태·반환 바이트 수·구조체 길이가 유효할 때만 판독한다.
- 공개 SDK 상수로 알려진 비트를 해석하고 나머지는 `unknownOptions`에 보존한다.
  비공개 커널 변수로의 대체 조회는 수행하지 않는다.
- HVCI 감사, CI 디버그, UMCI 감사 상태를 구분한다. 실패한 조회는 콘솔·스냅샷에서
  `unknown`, JSON에서 `null`이다. 이 관측은 호스트 API의 응답이며 외부 attestation이 아니다.
- JSON은 `kn-live-dbg.vbs.v2`로 버전을 올린다. `v1`의 bool/hex-string 일부가
  nullable 관측값으로 바뀌고 원시 마스크의 출처도 달라져 같은 스키마로 취급할 수 없다.
  `ciOptions.source`가 API 출처이며 `symbolSource`, `hvciEnforced`, `hvciDebugMode`는
  제거한다. 소비자는 `schema`를 확인하고 `hvciEnabled`, `hvciAuditMode`, `debugMode`,
  `hvciIumEnabled`와 `null`을 처리해야 한다. 활성 비트 하나로 enforcement를 단정하지 않는다.
  문자열 증거를 사용하는 스냅샷의 기존 `hvci_debug` 키는 `unknown`으로 남긴다.
- VBS 포인터를 조회하지 않았거나 읽지 못한 경우, 또는 읽은 비영 포인터가 지원하는
  커널 주소 범위 밖인 경우 `vbsActive=null`, `vbsActiveKnown=false`로 표시한다.
  null 포인터는 비활성 마커로 해석한다. 이 값은 비공개 VTL 포인터에 따른 추정이며
  페이지 매핑 검증이나 외부 attestation이 아니다. CI 조회와는 별도 관측이다.
- 최대 leaf가 `0x40000006` 이상이라는 이유만으로 Hyper-V 하드웨어 기능을 해석하던
  조건을 수정했다. 인터페이스와 leaf 범위를 모두 확인하고, 미지원일 때
  `hypervisor.featuresValid=false`, `hardwareFeatures=null`을 출력한다. 이번 VMware
  호스트는 실제 `Hv#1`을 제공하므로 기능 마스크는 유효하게 남는다. 미지원 인터페이스
  분기는 실제 수집 함수에 CPUID 응답을 주입해 조회 순서와 미지원 leaf 호출 부재까지 검사한다.

실제 빌드, 회귀 검사, 호스트 및 fixture 결과는
[실호스트 검증 기록](LIVE_HOST_VALIDATION_20261023.md)에 기록한다.
