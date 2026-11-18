# MCP 설정

[English](MCP_SETUP.md) · [도구 목록](MCP_TOOL_REFERENCE.md) · [구조](MCP_SERVER_DESIGN.ko.md)

MCP 서버는 분석 대상 PC의 관리자 KnLiveDbg 프로세스 안에서 동작한다.
HTTP `/mcp`와 세션 비밀번호를 사용하며 기본 주소는 모든 인터페이스의
**51766** 포트다. 같은 PC에서만 접속하려면 `--loopback`을 사용한다.
MCP 프로토콜 **2025-06-18**, 서버 버전 **0.1.0**은 프로그램 릴리즈 버전과 별개다.

## 시작과 종료

EXE·일치하는 드라이버·런타임을 포함한 전체 패키지를 준비하고
[실행 조건](BUILD_AND_RELEASE.md)을 확인한다. 관리자 콘솔의 `knkd>`에서:

```text
mcp on --loopback
```

다른 lab PC에서 접속할 때는 기본 `mcp on`으로 모든 어댑터에 바인딩하고,
출력된 주소 중 클라이언트가 접근할 수 있는 IP를 선택한다.

```text
mcp on [port] [--observe [--principal <fingerprint> <source> | --principal-target <fingerprint> ti <boot-id> <pid> <create-filetime>]... [--principal-access <fingerprint> <evidence|operations|both>]... [--target-ttl <seconds>] [--journal <directory>] | --allow-write] [--loopback] [--bind <addr>]
mcp status
mcp off
```

`--bind=<addr>`도 지원한다. 포트는 10진수 1–65535이며, 중복·충돌 옵션과
누락 값은 비밀번호 입력 전에 거부한다. `remote on`과 동시에 실행할 수 없다.

공유 비밀번호 모드에서는 임시 비밀번호를 두 번 입력한다. MCP 엔진 루프의 로컬 콘솔에서는 **`off`**와
**`status`**를 입력한다. `off` 뒤에 일반 REPL로 돌아온다. 공유 모드로 다시 켜면
비밀번호를 다시 입력한다. 활성 endpoint/bridge 파일에는 세션 자격 증명이 포함될
수 있으며 현재 사용자만 접근하도록 보호한다. 이 파일을 배포하지 않는다.

## 클라이언트 연결

현재 세션에서 출력한 URL과 헤더를 사용한다.

```text
URL: http://<target-ip>:51766/mcp
Authorization: Bearer <session-password>
```

클라이언트의 기본 HTTP 연결을 우선 사용한다. 지원 클라이언트용 설정 조각은
`%LOCALAPPDATA%\kn-live-dbg\clients\`에 생성된다. 엔진 루프가 실행되는 동안
별도 셸에서 사용한다. 일반 REPL의 `mcp client-setup`은 저장된 설정을 출력하며,
지원 selector는 도움말에서 확인한다.

같은 PC의 stdio 전용 클라이언트에는 `tools/mcp-bridge.ps1`을 사용한다.
생성된 `mcp-load-env.ps1`은 활성 endpoint를 읽어 `KNLIVEDBG_TOKEN`을 설정한다.
서버를 재시작하면 URL·비밀번호·세션을 다시 확인한다. 클라이언트별 설정 형식은
외부에서 바뀔 수 있으므로 오래된 설정 예제를 복제해 유지하지 않는다.

이 전송은 비밀번호와 메모리를 포함한 **평문 HTTP**다. 격리된 lab 경로를 사용하고
필요한 방화벽 규칙은 해당 클라이언트로 제한한다. 같은 PC에는 loopback이면 충분하다.
TLS, 임의 셸 실행, raw `kd`, 임의 콘솔 명령 전달 도구는 제공하지 않는다.

## 쓰기 권한

현재 `main`에서 보관 중인 타임라인과 상태만 로컬 클라이언트에 제공하려면
`mcp on --observe`를 입력한다. 루프백 주소가 자동 선택된다.
`mcp status`의 `scope=observe` 또는 `kn://capabilities`에서 범위를 확인한다.
최근 10건을 읽으려면 `timeline.query`에 `{"limit":"10","order":"newest"}`를 전달한다.
권한을 바꾸려면 현재 리스너를 종료하고 새로 시작한다. `kn://capabilities`의
`observe_budget`에서 남은 요청 수, 이벤트 수와 결과 바이트를 확인한다.
[조회 세션의 누적 한도](MCP_SERVER_DESIGN.ko.md#조회-세션의-누적-한도)

재시작 뒤에도 작업을 조회하려면 기존 로컬 상위 폴더에서
`mcp on --observe --journal "case operations"`로 시작한다. 처음에는 새
디렉터리를 지정하고 반환된 작업 ID를 보관한다. 같은 Windows 계정과 MCP
비밀번호로 같은 디렉터리를 다시 열면 된다. [작업 기록 복구](MCP_SERVER_DESIGN.ko.md#작업-기록-복구)

클라이언트별로 출처를 제한하려면 각 클라이언트의 PowerShell에서 난수 32바이트로
bearer를 만들고 환경 변수 `KNLIVEDBG_TOKEN`에 보관한다. 운영자에게 전달하는 값은
64자리 소문자 16진수 bearer의 **ASCII 문자열**로 계산한 SHA-256 지문이다.
PowerShell 예제는 지문만 출력한다. 같은 클라이언트를 재시작하려면 비밀 저장소에서
기존 bearer를 복원한다. [자격 증명 생성 예제](MCP_SETUP.md#give-each-client-one-retained-source)

운영자는 예를 들어 `mcp on --observe --principal <첫째-지문> ti --principal <둘째-지문> snapshot`을
입력한다. 최대 16개 지문에 각각 하나의 `TimelineEvent.Source`를 지정할 수 있다.
출처는 영문자 또는 숫자로 시작하는 1~64자이며 영문자, 숫자, 점, 밑줄, 하이픈을 허용한다.
대소문자를 구분하므로 현재 저장된 출처 표기를 사용한다. 각 클라이언트가 루프백으로
접속해 `kn://capabilities`에서 `evidence_source`와 남은 예산을 확인한다.
`timeline.query`에서 출처를 생략하면 허가된 출처를 조회한다. 저널을 함께 쓸 때는
별도의 운영자 암호를 입력한다. 복구 후에도 기존 bearer와 출처가 일치해야 자신의
영수증을 읽을 수 있다. [출처별 조회 권한](MCP_SERVER_DESIGN.ko.md#출처별-조회-권한)

기본 MCP 모드는 쓰기 도구를 노출하지 않고 엔진 진입 시 커널 write gate도 끈다.
`mcp on --allow-write`는 typed 쓰기 도구와 gate를 활성화한다.
`ti.subscribe start/stop`도 이 모드가 필요하다. 외부 콜백 포인터 변경은 여전히
지원하지 않으며, 콜백 제어는 소유한 협력형 fixture의 CREATE 본체에만 적용된다.

개별 쓰기 확인창과 `mcp write-confirm` 명령은 없다. 지원되는 쓰기는 dispatcher의
사전 읽기·백업·검증·감사를 사용하지만 전체 transaction이나 복구를 보장하지 않는다.
현재 main은 `off` 뒤 **write-off**를 요청하고 REPL로 복귀한다. 전환 실패 시
상태 미확인으로 보고한다. 실험 변경에는 명시적으로 `write on`을 실행한다.

### 증거 또는 작업 기록 허용하기

`--principal`이나 `--principal-target`으로 등록한 지문에 `--principal-access`를 지정한다.
아래 예시에서 첫 클라이언트는 보관된 TI 행을 조회한다. 두 번째 클라이언트는 운영자가 같은 암호로
다시 연 저널에서 본인의 과거 작업 영수증을 ID로 읽을 수 있다.

```text
mcp on --observe --journal "case operations" --principal <reader-fingerprint> ti --principal <reviewer-fingerprint> ti --principal-access <reader-fingerprint> evidence --principal-access <reviewer-fingerprint> operations
```

클라이언트는 `kn://capabilities`의 `observe_access`에서 권한을 확인한다. 기본값 `both`는 두 도구를 허용한다.
작업 전용 클라이언트에도 원래 출처가 필요하고, 대상이 지정된 경우 같은 프로세스 수명과 새 대상 핸들이 필요하다.
운영자는 로컬 요청 감사 기록에서 작업 ID를 확인할 수 있다. [권한 모델](MCP_SERVER_DESIGN.ko.md#증거와-작업-기록의-조회-권한)

### 한 프로세스의 기록만 허용하기

디버거에서 `!timeline targets ti <pid>`를 입력하면 보관된 TI 이벤트 헤더에서 검증한
프로세스 수명을 한 번에 최대 64개까지 볼 수 있다. `more`가 참이면 마지막 항목의
값으로 `after <boot-id> <create-filetime>`을 덧붙여 다음 페이지를 읽는다. 원하는 항목의 `boot_id`, `pid`,
10진수 `create_filetime`을 사용한다.

```text
mcp on --observe --principal-target <fingerprint> ti <boot-id> <pid> <create-filetime> --target-ttl 300
```

인증된 클라이언트는 `initialize` 후 `kn://capabilities`에서 `target_session`을 읽는다.
`timeline.query`와 `operations.get`을 호출할 때마다 이 값을 문자열 인자로 전달하고
HTTP 헤더에는 `Mcp-Session-Id`를 보낸다. 유효 기간은 기본 300초로,
`--target-ttl`에서 1~3600초를 지정할 수 있다. 만료되면 리소스에 표시되는 값이
`null`로 바뀐다. 다시 초기화해도 남은 예산은 유지된다. 조회 결과가 비어 있으면
현재 저장된 행 중 일치하는 행이 없다는 뜻이다. [대상별 권한](MCP_SERVER_DESIGN.ko.md#프로세스-수명별-조회-권한)

## 결과·시간 초과·감사

`tools/list`, `resources/list`, `prompts/list`로 활성 목록을 확인한다.
인자 이름·형식·필수 값은 [도구 목록](MCP_TOOL_REFERENCE.md)을 참고한다.
일부 결과는 JSON, 일부는 텍스트다. 빈 결과를 해석하기 전에 오류와 coverage를 확인한다.

엔진은 최대 8개의 대기 작업과 30초 응답 대기를 사용한다. 실행 전 큐에서 취소된
작업은 뒤늦게 실행되지 않는다. 이미 dispatch된 작업의 시간 초과는 실행 중단이나
rollback이 아니다. 결과가 불명확한 쓰기를 다시 보내기 전에 현재 상태를 확인한다.
MCP 취소 알림은 이미 실행 중인 작업을 취소하지 않는다.

응답의 `_meta["knlivedbg/operation"].operation_id`를 보관하고 그 문자열로
`operations.get`을 호출하면 원래 요청을 반복하지 않고 엔진의 후속 상태를 조회한다.
도구 응답은 같은 메타데이터를 추가 텍스트로도 제공한다. 엔진이 실행 중이어도
조회할 수 있지만 직렬 리스너의 현재 응답 대기가 먼저 끝나야 한다.
기본 메모리 기록은 최대 256개이며 종료된 오래된 기록부터 교체하고 서버 재시작 때 지운다.
조회 저널을 지정하면 최근 승인 256건을 재시작 후에도 조회할 수 있다.
`not_retained`는 성공/실패 판정이 아니다. 결과 본문, 부작용 검증, 롤백 또는
반복 변경의 멱등성을 제공하지 않는다. 자세한 내용은
[작업 상태 계약](MCP_SERVER_DESIGN.ko.md#실행-경계)을 참고한다.

자동 요청 감사는 `ai audit`과 별개로
`<exe-dir>\.kn-live-dbg\mcp-audit-<port>.jsonl`에 저장한다.
기존 모드는 판정·결과·길이가 제한된 인자를 기록한다. 조회 세션은 판정과
작업 메타데이터를 남기고 인자 값과 프로토콜 세션 ID는 기록에서 제외한다.

## 확인과 문제 해결

1. 현재 URL·비밀번호·네트워크 경로를 확인한다. HTTP 401은 인증 오류이며
   새 서버 세션에서는 새 비밀번호가 필요하다.
2. 초기화 후 `Mcp-Session-Id`를 후속 요청에 유지한다.
3. 조회 세션은 `kn://capabilities`와 `timeline.status`로 확인한다.
   기존 모드는 `kn://session/info`, `kn://session/symbols`, `process.find` 등으로 확인한다.
   드라이버·심벌 공백을 정상적인 빈 검사로 처리하지 않는다.
4. 쓰기 차단·인자 검증·큐·불확실한 결과와 감사 로그를 구분한다.
   읽기 실패 때문에 자동으로 쓰기 권한을 켜지 않는다.
5. `--self-test mcp-tools`는 드라이버 없이 실행한다. 별도 `mcp-http` 검사는
   HTTP.sys 등록 권한이 필요하다. [시험 체크리스트](MANUAL_TEST_CHECKLIST.md)를 참고한다.
