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
mcp on [port] [--allow-write] [--loopback] [--bind <addr>]
mcp status
mcp off
```

`--bind=<addr>`도 지원한다. 포트는 10진수 1–65535이며, 중복·충돌 옵션과
누락 값은 비밀번호 입력 전에 거부한다. `remote on`과 동시에 실행할 수 없다.

임시 비밀번호를 두 번 입력한다. MCP 엔진 루프의 로컬 콘솔에서는 **`off`**와
**`status`**를 입력한다. `off` 뒤에 일반 REPL로 돌아온다. 서버를 다시 켤 때마다
새 비밀번호가 필요하다. 활성 endpoint/bridge 파일에는 세션 자격 증명이 포함될
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

기본 MCP 모드는 쓰기 도구를 노출하지 않고 엔진 진입 시 커널 write gate도 끈다.
`mcp on --allow-write`는 typed 쓰기 도구와 gate를 활성화한다.
`ti.subscribe start/stop`도 이 모드가 필요하다. 외부 콜백 포인터 변경은 여전히
지원하지 않으며, 콜백 제어는 소유한 협력형 fixture의 CREATE 본체에만 적용된다.

개별 쓰기 확인창과 `mcp write-confirm` 명령은 없다. 지원되는 쓰기는 dispatcher의
사전 읽기·백업·검증·감사를 사용하지만 전체 transaction이나 복구를 보장하지 않는다.
현재 main은 `off` 뒤 **write-off**를 요청하고 REPL로 복귀한다. 전환 실패 시
상태 미확인으로 보고한다. 실험 변경에는 명시적으로 `write on`을 실행한다.

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
기록은 최대 256개이며 종료된 오래된 기록부터 교체하고 서버 재시작 때 지운다.
`not_retained`는 성공/실패 판정이 아니다. 결과 본문, 부작용 검증, 롤백 또는
반복 변경의 멱등성을 제공하지 않는다. 자세한 내용은
[작업 상태 계약](MCP_SERVER_DESIGN.ko.md#실행-경계)을 참고한다.

자동 요청 감사는 `ai audit`과 별개로
`<exe-dir>\.kn-live-dbg\mcp-audit-<port>.jsonl`에 저장한다.
판정·결과·길이가 제한된 인자 기록을 보존하며 write-audit tail 리소스와는 별도다.

## 확인과 문제 해결

1. 현재 URL·비밀번호·네트워크 경로를 확인한다. HTTP 401은 인증 오류이며
   새 서버 세션에서는 새 비밀번호가 필요하다.
2. 초기화 후 `Mcp-Session-Id`를 후속 요청에 유지한다.
3. `kn://session/info`, `kn://session/symbols`, `process.find` 등으로 확인한다.
   드라이버·심벌 공백을 정상적인 빈 검사로 처리하지 않는다.
4. 쓰기 차단·인자 검증·큐·불확실한 결과와 감사 로그를 구분한다.
   읽기 실패 때문에 자동으로 쓰기 권한을 켜지 않는다.
5. `--self-test mcp-tools`는 드라이버 없이 실행한다. 별도 `mcp-http` 검사는
   HTTP.sys 등록 권한이 필요하다. [시험 체크리스트](MANUAL_TEST_CHECKLIST.md)를 참고한다.
