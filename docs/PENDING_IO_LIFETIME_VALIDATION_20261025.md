# 2026-10-25 pending I/O와 completion context 수명 검증

## 재부팅 원인

기준 커밋은 `1adcbe4`다. 이번 개발 중 **우리 테스트 필터가 실제 BSOD를 일으켰다.**
`2026-10-25 09:29:45.455 KST`의 dump는 `MEMORY_MANAGEMENT 0x1A`, 첫 인자
`0x4477`을 기록했다. 작업자에서 사용자 READ를 재개하기 전에 버퍼를 고정하지 않아,
NTFS가 System 프로세스 문맥에서 원래 사용자 가상 주소를 잠그려다 실패했다.

확인된 스택:

```text
KnLiveDbgMiniFilterFixture!Worker (당시 PendingIo.cpp:222)
FLTMGR!FltCompletePendedPreOperation
NTFS!NtfsNonCachedIo / NtfsPrepareBuffers / NtfsLockUserBuffer
nt!MmProbeAndLockPages
nt!KeBugCheckEx (1a, 4477, 000002b462410000, 2, 0)
```

`0x4477`의 의미는 [Microsoft bugcheck 문서](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x1a--memory-management)와 일치한다.
dump와 private PDB로 Worker의 소스 위치를 확인했다. `full-cancel` 실행은 실패로 분류했다.
마지막 디스크 로그가 요청자 종료 단계에 머문 것은 crash 직전 쓰기가 영속화되지 않았기
때문이며, 실제 실패 경로는 dump의 READ 스택을 근거로 판단했다.

원시 자료는 `.build/pending-callback-20261025/crash/`에 보존했다.

- 원본 dump: `C:\Windows\Minidump\102526-9609-01.dmp`
- dump SHA-256: `1b80d1369ebc9d1512a431ff99ead223b937285bdb81c45e74d8dadebe2fce68`
- 당시 fixture SHA-256: `ad480ff5659c8d6f243aff940235cb7ea7eb81791172e4a09624c0d28ceba7c8`
- `analysis.log`, `system-events.json`, 당시 `.sys`/`.pdb`, `hashes.json`

기존 `102426-10593-01.dmp`도 보존했다. 이 두 crash는 서로 다른 결함이다.
이전 것은 외부 콜백 포인터 교체의 코드 수명 문제이고, 이번 것은 새 테스트 READ의 버퍼 수명 문제다.

## 수정과 수명 규칙

테스트 provider의 별도 관리자/SYSTEM 포트에서 하나의 지정 프로세스 I/O만 선점한다.
CREATE의 pre, post, 양쪽 보류와 비동기 READ의 두 인스턴스 순회를 지원한다.
지연 요청은 최대 2초다. 일반 파일 I/O 전체를 큐에 넣지 않는다. 기존 managed 제어 ABI는 유지한다.

- READ를 보류하기 전에 `FltLockUserBuffer`로 MDL을 준비한다. 실패하면 해당 I/O를 오류로
  완료하고, 고정되지 않은 버퍼를 하위 드라이버나 작업자로 넘기지 않는다.
  작업자에도 MDL 없는 READ를 거부하는 검사를 둔다.
  MDL 해제와 페이지 잠금 해제는 FltMgr/I/O 수명이 관리한다. 직접 버퍼를 읽거나 MDL을 해제하지 않는다.
  [FltLockUserBuffer 계약](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltlockuserbuffer).
- context에는 논리적 pre/post 소유권과 작업자 소유권을 각각 둔다. pre 완료 호출 안에서 post가
  즉시 실행되더라도 작업자 tail이 해제된 context에 접근하지 않는다. 완료 이후 CallbackData를 재사용하지 않는다.
- 취소·소유자 종료·인스턴스 분리·언로드는 작업자를 깨우며, 이미 큐에 들어간 I/O는 작업자만
  완료한다. 소유자 제어 mutex를 잡은 채 I/O 완료를 기다리지 않는다.
- 요청 선점과 context 등록은 같은 spin lock 안에서 이뤄진다. 그 사이 소유자 종료 신호를 놓치거나
  아직 등록하지 않은 요청이 있는 동안 새 ARM이 받아들여지는 구간을 없앴다.
- `CancelSynchronousIo` 성공 후에도 작업자의 cancellable wait만으로는 즉시 깨지 않는 경우를
  실제로 관측했다. 보유 중인 IRP를 `FltIsIoCanceled`로 확인하는 최대 10 ms 단위 대기를 추가했다.
  수정 전 실행은 2.015초 뒤 ERROR_OPERATION_ABORTED를 반환하면서 PreCancelled=0이었다.
  취소 콜백을 추가 등록하지 않아 별도의 취소 함수 수명이나 이중 완료 경로를 만들지 않는다.
  [FltIsIoCanceled](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltisiocanceled),
  [FltCancellableWaitForSingleObject](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltcancellablewaitforsingleobject).
- context 정리는 managed 본체의 enable/disable과 독립적이다. `DRAINING` post는 정리만 하고
  다시 보류하지 않는다. CREATE와 달리 실제 비동기 READ를 아래 인스턴스에서 보류해 이 경로를 검증한다.
  [Completion processing](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/performing-completion-processing-for-an-i-o-operation).
- 언로드는 신규 작업을 차단하고 대기를 깨운 뒤, 커널 작업자 **스레드 종료까지 join**한다.
  이어 process notification과 FltMgr 등록을 해제한다. 카운터 0만으로 코드 수명 종료를 판단하지 않는다.
- FltMgr 등록 해제가 끝난 뒤 서비스 Parameters의 `PendingIoFinalAudit`에 최종 장부를 기록한다.
  매 reload 전에 이전 값을 지워 오래된 성공 결과가 새 실행의 실패를 가리지 못하게 한다.

## 재현 방법

승격된 셸에서 기존 fixture 서비스가 없는 상태로 실행한다. 빌드와 실제 테스트는 순서대로 실행한다.

```powershell
.\tools\build.ps1 -Configuration Release
python .\tools\run-pending-io-e2e.py --output .build\pending-io\read --read-only --cycles 10
python .\tools\run-pending-io-e2e.py --output .build\pending-io\run1 --cycles 12
python .\tools\run-pending-io-e2e.py --output .build\pending-io\run2 --cycles 12
python .\tools\run-managed-callback-e2e.py --output .build\pending-io\managed --close-race-executable .build\managed-close-selftest\managed-callback-close-selftest.exe
```

실행기는 고정된 자체 fixture만 등록/로드/분리/언로드하며 기존 서비스를 덮어쓰지 않는다.
`checks.json`, `journal.jsonl`, `unload-audits.json`, `result.json`을 남긴다.
ARM, 실제 대기 관측, detach와 단언은 `fsync`하는 journal에도 기록한다.
관측한 pending 없이 단순 정상 I/O 성공을 보류 경로의 성공으로 세지 않는다.

각 장부에서 `Created = Freed = LogicalCompleted`, `PreQueued = PreCompleted`,
`PostQueued = PostCompleted`, `Violations = 0`을 확인한다. 언로드 뒤에는 작업자, 큐,
context, instance, 연결, owner와 armed 상태도 모두 0이어야 한다.

## 수정 후 실행 결과

원시 증거: `C:\git\kn-live-dbg\.build\pending-callback-20261025`.
최종 fixture SHA-256은 `9a948e64ef71c00a0c4bede81d921c8f52cd8a5ea975d194ecabdf4b7f94779b`다.
아래 세 실행은 모두 같은 바이너리를 사용했다.

| 검증 | 결과 |
| --- | --- |
| READ 집중 반복 `read-final` | 28/28, 1.391초. 실제 draining 10회, 정상/강제 소유자 종료와 요청자 강제 종료 포함 |
| 전체 반복 `full1` / `full2` | 각각 160/160, 13.406초 / 13.188초 |
| 최종 context 장부 합계 | 498개 생성 = 논리 완료 = 해제. Violations=0 |
| pending 완료 합계 | pre 397/397, post 344/344 |
| 실제 draining post | 합계 16회. 아래 READ가 여전히 pending일 때 위 context만 해제됨을 관측 |
| READ 버퍼 | MDL 고정 37회, 고정 실패 주입 3회. 실패는 1450/0 bytes로 완료, 정상 READ는 4096 bytes와 전체 내용 일치 |
| 동기 I/O 취소 | 두 전체 실행에서 16 ms. 수정 전 2.015초 및 취소 계수 누락과 비교 |
| 언로드 후 장부 | 51개 모두 통과. 작업자·큐·context·instance·연결·owner·arm 잔존 0 |
| 언로드 방법 | 두 전체 실행에서 직접 `FilterUnload` 24회, 서비스 중지 24회, 세 실행의 최종 cleanup 3회 |
| 즉시 pre/post 완료 경합 | 두 전체 실행에서 240회. pre 완료 호출 중 post가 실행되는 경로와 작업자 tail 참조 검증 |
| 기존 managed 콜백 회귀 | 93/93, 152.234초. 본체 전환 600회, 동시 조회 321회, device/port close 경합 100회 포함 |
| 기존 동시 파일 부하 | 4개 스레드의 생성·읽기·삭제 묶음 합계 129,446회, 오류 0 |
| 분리·재연결 회귀 | 246.391초, 통과. 변경 거부 10개와 등록 불변, 분리 양성·복구 음성 대조, 독립 스냅샷 검증과 cleanup 포함 |
| 빌드 | Release 전체 빌드 성공 후 최종 fixture 변경을 같은 솔루션/WDK의 Release 타깃으로 재빌드. 경고·오류 없음, 테스트서명 이미지 로드 성공 |

`full-initial`의 취소 계수 실패와 `full-cancel`의 BSOD는 성공 수에 포함하지 않았다.
MDL 수정 직후 `read-fixed`도 12/12로 통과했으나, 위 합계는 최종 실패 처리와 READ 내용 검증까지
반영한 바이너리/실행기만 집계했다. `verify-results.json`은 실행별 종료 코드와 벽시계 시간을,
각 실행의 `unload-audits.json`은 해제 후 장부 전체를 담는다.

최종 호스트 확인은 `2026-10-25 11:47:40 KST`에 수행했다. 수정 검증 구간
`11:34:19~11:47:40 KST`에는 추가 System 41/1001, 우리 프로그램의 Application 1000/1001,
새 minidump가 없었다. 부팅 시각은 수정 검증 기준인 `2026-10-25 09:30:03.500 KST`와 같고,
테스트 드라이버/프로세스도 없었다. 이는 **수정 후 추가 재부팅이 없었다는 결과**이며,
앞서 확인한 09:29의 우리 fixture crash를 제외하거나 성공으로 바꾼 것이 아니다.
`host-audit.json`에 이전 crash와 두 기존 dump 목록도 함께 기록했다.

회귀 시험의 `KnLiveDbg.exe` SHA-256은
`9d21f5cd6f8205b3a353c19a01c2da321fa5f4f04008b36456161b471bd80dec`다.
등록 포인터 불변, 언로드 후 이전 제어 포트 단절, 재로드 초기 상태와 최종 자원 정리를 확인했고,
수정 후 시험에서 콜백 잔존은 관측하지 않았다.

## 범위

실험은 Windows x64 `28000.3231`의 자체 fixture에 한정된다. 외부 필터의 포인터 교체는
계속 차단하며, 테스트 성공을 협력하지 않는 외부 provider의 안전성으로 일반화하지 않는다.
시험 지연은 스케줄링과 teardown을 포함한 전체 벽시계 완료 기한이 아니다.
