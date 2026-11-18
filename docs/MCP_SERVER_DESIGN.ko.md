# MCP 구현 구조

[English](MCP_SERVER_DESIGN.md) · [설정](MCP_SETUP.ko.md) · [도구 목록](MCP_TOOL_REFERENCE.md)

이 문서는 현재 구현을 설명한다. 이전 단계별 계획과 초기 scaffold 설명은
제거했다. `user/McpServer.cpp`는 HTTP.sys·인증·JSON-RPC·목록·큐를,
`user/main.cpp`의 `RunMcpEngineLoop` / `DispatchMcpRequest`는 커널·심벌
작업과 결과 생성을 담당한다.

## 실행 경계

현재 `main`에서 운영자가 실행 중인 컨트롤러에 `mcp on --observe`를 입력하면
루프백 전용 조회 세션이 열린다. 리스너는 인증과 본문 처리 전에 실제 연결의
양쪽 IP 주소를 확인한다. `mcp status`, endpoint 파일, `kn://capabilities`에서
`observe`, `legacy_write_locked`, `legacy_write_enabled` 중 현재 범위를 확인할 수 있다.

| 조회 세션 | 허용 범위 |
| --- | --- |
| 도구 | `operations.get`, `timeline.status`, `timeline.query`, `graph.query`, `ti.subscribe`의 기본 동작 또는 `status` |
| 리소스 | `kn://capabilities`, `kn://session/info`, `kn://drivers/status`, `kn://ti/stats` |
| 프롬프트 | 빈 목록 |

범위를 벗어난 요청은 큐에 들어가기 전에 거부하므로 작업 ID가 생기지 않는다.
엔진은 실행 직전에도 같은 권한을 검사한다. 타임라인과 그래프는 보관된 이벤트를
직접 조회하며 기본 50건, 최대 64건을 선택한다. 일치 여부를 확인하려면 전체
저장소를 훑을 수 있다. 드라이버 상태는 기존 장치와 서비스에 질의할 수 있다.
조회 세션의 감사 로그에는 요청 인자·미허용 식별자·프로토콜 세션 ID·응답 본문을
기록하지 않는다. 조회 결과에는 보관된 이벤트의 원본 필드가 포함될 수 있다.
이 권한은 리스너를 종료할 때까지 같은 자격 증명을 쓰는 클라이언트에 공통 적용된다.

```text
HTTP 요청 -> 본문 크기 / 인증 / 세션 / JSON 검사
          -> typed 인자 검사 -> FIFO -> 메인 엔진
          -> result promise -> HTTP 응답
```

리스너는 DeviceClient나 DbgHelp를 직접 호출하지 않는다. 엔진이 작업을 직렬화하고
출력 캡처를 소유한다. 활성화 중 로컬 콘솔은 `off`, `status`만 받는다.
MCP와 remote는 별도 큐를 가지며 동시에 listen할 수 없다. 공용 우선순위
EngineQueue를 구현한 것은 아니다.

큐는 대기 작업 8개까지 수용한다. 30초 응답 대기가 실행 전에 끝나면 큐에서
작업을 제거한다. dispatch 뒤에는 작업이 계속될 수 있고 클라이언트의 결과는
불명확하다. 실행 중인 호출을 rollback하지 않는다. stop은 대기 작업을 취소하고
control/engine 종료 경로로 리스너를 join한다. 취소 알림은 범용 작업 취소 기능이 아니다.

엔진 큐에 수용된 작업은 JSON-RPC 요청 ID와 별개인 128비트 `operation_id`를 받는다.
비공개 `kn.mcp_operation.v1` 메타데이터를 도구 응답의
`_meta["knlivedbg/operation"]`와 추가 텍스트 항목으로 반환한다.
기존 `structuredContent`와 첫 텍스트 항목은 유지한다. 리소스 성공 응답은
같은 `_meta`, 오류는 `error.data`에 담고 요청 감사에도 응답 시점 상태를 기록한다.
`operations.get {"operation_id":"<반환된 ID>"}`는 리스너에서 바로 조회하므로
실행 중인 엔진 작업을 기다리거나 재등록하지 않는다.

상태는 `queued`, `running`, `cancelled_before_execution`, `succeeded`,
`failed`, `unknown_outcome`이다. 실행 뒤 시간 초과는 엔진 반환 전까지 활성
기록으로 남으며, 처리되지 않은 엔진 예외는 종료되어도 결과 불명으로 남는다.
`operation_finished`는 실행 전 취소도 포함하지만 `engine_finished`는 실제
dispatch가 있어야 참이다. 성공/실패는 엔진의 오류 플래그이며 대상 부작용을
독립 검증했다는 뜻이 아니다. 시각은 수집기 부팅 기준 밀리초의 10진 문자열이다.

메타데이터는 최대 256개이며 오래된 종료 기록부터 교체한다. 모두 활성 작업이면
새 작업을 거절한다. 결과 본문은 저장하지 않는다. 서버 재시작은 기록을 지우고
같은 서버의 재초기화는 유지한다. 기존 공유 비밀번호/세션으로 조회하며 별도
사용자별 격리는 없다. `not_retained`는 실행 결과를 판정하지 않는다.
ID를 받기 전에 연결이 끊기면 요청 ID로 복구할 수 없다. 자동 재시도·멱등 재전송·
롤백·실행 중 취소·영속 저널·표준 MCP Tasks는 미지원이다. 별도 remote 프로토콜의
작업 조회도 아직 연결되지 않았다.

## 전송과 권한

- HTTP `/mcp`, 기본 모든 인터페이스의 51766, 선택적 loopback/특정 bind.
  TLS는 없다. MCP 프로토콜은 2025-06-18, 서버는 knlivedbg/0.1.0이다.
- 세션 비밀번호 bearer 인증과 초기화 뒤 `Mcp-Session-Id`를 사용한다.
  비밀을 포함한 보조 파일은 현재 사용자 DACL과 원자적 교체를 사용한다.
- 읽기 모드는 쓰기 도구를 숨기고 커널 gate도 끈다. `--allow-write`가 typed
  변경을 허용하며 읽기 목록에 있는 `ti.subscribe`의 start/stop도 이 권한이 필요하다.
- raw 콘솔/kd 도구는 없다. 콜백 변경은 협력형 fixture에만 허용한다.
  별도 process-protection 쓰기 도구는 명시한 PID도 지원한다.
- 현재 main은 커널 쓰기 모드 확인에 성공해야 엔진 작업을 실행한다.
  로컬 REPL 복귀 시 write-off를 요청하며, 실패하면 상태 미확인으로 보고한다.
  자동으로 쓰기를 활성화하지 않는다.

## 파싱과 결과

본문 상한은 1MiB다. 실패/불완전 본문은 HTTP 400, 초과는 413과 JSON-RPC
parse error를 반환한다. 잘못된 JSON은 HTTP 200 안의 JSON-RPC 오류로도 반환한다.
뒤쪽 데이터·해석 후 중복 키·잘못된 UTF-8·64단계를 넘는 중첩을 거부한다.
envelope와 도구 인자를 dispatch 전에 검사하며, schema가 string으로 정한
숫자는 문자열로 전달한다.

전송 오류와 도구 결과 오류를 구분한다. 일부 도구는 structured content,
일부는 텍스트를 반환한다. 기존 모드는 리소스 8개와 프롬프트 7개를 제공한다.
자동 요청 감사와 쓰기 감사는 별개다.

통일된 pagination/output schema, SSE 진행, 개별 쓰기 elicitation,
엄격한 protocol-version 헤더 검사는 미구현이다.
남은 작업은 [FEATURE_PLAN.md](FEATURE_PLAN.md)에 정리한다.

## 검증

`--self-test mcp-tools`는 드라이버 없이 목록·인자·dispatch 계약을 검사한다.
별도 `--self-test mcp-http`는 loopback 전송을 검사하며 HTTP.sys 등록 권한이 필요하다.
`--self-test mcp-observe`는 같은 포트에서 조회 범위, 실행 전 거부, 타임라인 응답과 감사 기록을 확인한다.
네트워크 fixture는 순차 실행한다. 실제 커널 동작·쓰기 검증·정리는
[수동 체크리스트](MANUAL_TEST_CHECKLIST.md)에서 따로 확인한다.
