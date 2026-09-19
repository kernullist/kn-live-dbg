# 게임핵 헌팅 연구와 구현 기준

조사 기준일: 2026-09-19. 공개 보고서에서 관측된 공격, 제안 단계 연구, Windows API의 기능을 구분한다. 악성 드라이버를 실행하는 재현 코드는 포함하지 않는다.

NDSS 2026 BYOVD 연구, ETW 스택, Pool Party, WFP와 페이지 권한을 추가 조사한 결과 및 22개 기법 계열의 구현·관측 제한은 [은닉 코드 관측 범위](KMON_COVERAGE_MATRIX_20260919.md)에 정리했다. 실제 표본 검증은 사용자가 수행하며, 구현 진척과 검증된 재현율을 구분한다.

| 근거 | 확인한 내용 | Kmon에 적용할 기준 |
|---|---|---|
| [Tulach, 2024-07-12](https://tulach.cc/detecting-manually-mapped-drivers/) | PE 헤더가 지워진 수동 매핑 코드에도 컴파일러가 남긴 형태가 있을 수 있다. 펌웨어 코드 등 오탐과 작은 코드의 누락도 고려해야 한다. | 헤더 탐지만으로 끝내지 않는다. 실행 페이지, 이미지 내용 비교, 콜백에서 이어지는 분기 경로를 함께 확인한다. 패턴 일치만으로 악성 판정을 내리지 않는다. |
| [Microsoft, 2026-03-26; 06-09 수정](https://techcommunity.microsoft.com/blog/windows-itpro-blog/advancing-windows-driver-security-removing-trust-for-the-cross-signed-driver-pro/4504818/replies/4513460) | 교차 서명 드라이버의 신뢰 정책이 강화되고 있다. | OS 버전이나 서명 존재만으로 실제 CI 정책과 안전성을 추정하지 않는다. 정상 CI 값은 과거 BYOVD나 수동 매핑이 없었다는 증거가 아니다. |
| [Elastic, 2026-07-31](https://security-labs.elastic.co/security-labs/vulnerable-driver-detection-elastic-defend-byovd) | 유효하게 서명된 취약 드라이버의 악용과 계속 갱신되는 드라이버 목록을 설명한다. | 파일 해시·서명·목록 버전을 보존한다. 목록 일치와 메모리에 남은 페이로드 탐지는 별도 관측이다. 제품의 규칙 수를 탐지율로 환산하지 않는다. |
| [ESET, 2026-03-19](https://www.welivesecurity.com/en/eset-research/edr-killers-explained-beyond-the-drivers/) | BYOVD뿐 아니라 보안 도구의 동작·통신을 방해하는 여러 경로를 관측했다. | 이벤트 손실, 수집기 오류, 심볼 실패를 coverage로 기록한다. 이는 게임핵 전용 표본에 대한 검증 결과가 아니다. |
| [RX-INT, 2025-08-05 preprint](https://arxiv.org/abs/2508.03879) | 스레드 생성과 VAD 상태, 메모리 해시를 연결하는 탐지를 제안한다. 주기적 스캔과 헤더 검사에는 시점·내용의 공백이 있다. | 프로세스 생성 시각과 관측 시각을 연결하고 스레드·APC·계측 콜백·스택 참조를 보존한다. 논문의 제한된 비교 실험을 일반적 우위로 해석하지 않는다. |
| [SeqShield, 2026-04-26 preprint](https://arxiv.org/abs/2604.23812) | API 순서 특징과 변형 표본을 이용한 루트킷 분류를 제안한다. | 같은 원본에서 파생한 표본을 독립 표본으로 세지 않는다. 정적 콜백 주소와 실제 API 실행 순서를 혼동하지 않는다. 해당 모델의 정확도를 Kmon에 전용하지 않는다. |
| [Elastic, 2023-05-31](https://security-labs.elastic.co/security-labs/upping-the-ante-detecting-in-memory-threats-with-kernel-call-stacks) | 호출 스택은 코드 주입과 이미지 변형을 조사하는 추가 관측 지점을 제공한다. | 정상 프로세스 이름을 검사 제외 조건으로 쓰지 않는다. ETW 스택 주소는 수집 시점의 참조이며 현재 RIP나 현재 메모리 내용과 동일하다고 단정하지 않는다. |
| [Microsoft GetSystemFirmwareTable](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemfirmwaretable), [ExGetFirmwareEnvironmentVariable](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exgetfirmwareenvironmentvariable) | 펌웨어 테이블 조회와 UEFI 환경 변수 조회는 서로 다른 인터페이스다. | Windows 펌웨어 테이블 handler 검사를 UEFI/SMM 검사로 표시하지 않는다. 임의 provider나 의심 handler를 호출하지 않는다. |
| [PE-sieve 공식 릴리스](https://github.com/hasherezade/pe-sieve/releases) | 사용자 프로세스의 주입·교체 이미지와 셸코드 등 메모리 변형을 조사하는 비교 도구다. | 동일한 소유 테스트 프로세스와 명시적 옵션으로 비교하고 바이너리 해시·버전·출력을 기록한다. 커널 콜백 검사는 비교 범위 밖이다. |

## 판단과 검증 범위

커널의 변형된 함수 포인터와 유저 코드가 같은 시기에 발견되었다는 이유만으로 통신 관계를 확정할 수 없다. Kmon은 포인터 참조, 이미지 바이트 차이, 동일 내용, 동일 물리 페이지, 시간상 근접을 다른 관계로 기록한다. 각 관계에는 부팅 식별자, 프로세스 생성 시각, 관측 시각, 메모리 세대와 수집 출처가 필요하다.

등록된 콜백은 실행 경로 후보다. 실행 가능 private 메모리는 JIT에서도 정상적으로 사용한다. 레이아웃 추정 실패, 슬롯 변경, 접근 거부, WOW64 미지원은 악성 판정의 근거가 아니다. 실제 호출이나 데이터 전달을 관측하지 않았다면 통신 방식과 행위자는 미확정으로 남긴다.

실제 게임핵 표본, 정상 시스템의 장시간 관측, 외부 도구와의 동일 조건 비교, 독립 분석자 검토가 있어야 경쟁력을 평가할 수 있다. 단위 검사와 합성 corpus의 통과는 구현의 결정 규칙을 검증하며 세계 최고 탐지율을 입증하지 않는다.

구현된 수집 경로와 실제 비교 결과는 [연관 헌팅 가이드](KMON_CROSS_DOMAIN_HUNTING.md)에 있다. 공개 corpus도 조사했다. [Volatility의 sample 목록](https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples)은 이전 Windows/범용 악성코드 자료를 제공한다. 이번 조사에서는 현재 게임핵의 kernel callback과 유저 payload 관계를 함께 라벨링한 실시간 검증 입력을 확보하지 못했다. 검색에 나온 Windows 10 AFF4 dataset 논문은 본문 접근이 CAPTCHA로 제한되어 표본을 검증했다고 집계하지 않았다.
