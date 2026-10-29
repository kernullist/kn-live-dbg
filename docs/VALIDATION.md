# Validation status

The released baseline is **v0.0.36 / 6646461**. Development verification of the
retained investigation path was recorded on **2026-10-29**, separately from the
**2026-10-25** release validation. The **2026-10-27** documentation review did not
renew runtime observations. Follow the [manual checklist](MANUAL_TEST_CHECKLIST.md)
to validate another binary or host.

## Release candidate

The [v0.0.36 release notes](RELEASE_NOTES_0.0.36.md#validation-evidence) identify
the freshly versioned Release x64 tests on Windows **28000.3231**:

| Check | Recorded result |
| --- | --- |
| Build, PE versions, signing metadata | Matching 0.0.36 components; BYOVD metadata fixture intentionally 1.0.0.0 |
| Driver-free `--self-test all` | Timeline 28, MCP catalog 89, console 558, commands 2,961, remote protocol 66, connect arguments 4 |
| Standalone AddressSanitizer parser/completion | 275,002 / 25,954 checks |
| KMON component controls | Hunting 11,326, pages 54, false-positive controls 49; malformed replay inputs rejected |
| Evidence validators | Capture accounting, image names, vctip audit, image coverage and minifilter/research-ledger validator checks passed |
| Owned managed/pending/query fixture | 280 ordinary checks, 57 balanced final unload ledgers |
| Failure supervisor | 10 verified expected failure stages, including abrupt child exit |

The final audit covered **2026-10-25 22:00:57–22:09:36 KST**. Boot time was
unchanged and no new bugcheck/reboot events, dumps, or owned service/process
residue were observed in that interval. Raw release evidence was retained under
`.build/release-0.0.36-20261025`; it is local evidence, not a bundled artifact.
The released ZIP and manifest identify distributed files independently.

## Retained investigation path: 2026-10-29

The final Release x64 user executable had SHA-256
`da6481ec96c9f122869fd8153fb8643c109e5d245882daf6400b7075ee8cd014`.
It used the existing test-signed driver; this work did not change driver code
or publish a new release. Stage-specific controls and final integration results
were retained locally under `.build/design-implementation-20261029`.

| Check | Observed result |
| --- | --- |
| Scoped queries and identity | Hunting ASan 11,345, page controls 54 and analyst ASan 6,602 passed; targets beyond 256, cursor changes, delayed receipts and optional-identity conflicts covered |
| Durable query and replay | Evidence ASan 374 passed; expiry/eviction/restart, missing/corrupt spans, closure accounting and read-byte limits covered |
| Interrupted publication | Final run: eight writer interruptions, one valid final file and seven absent final files; completed full-size publication and fresh-process recovery passed |
| Final executable self-tests | Timeline 28, MCP catalog 89, console 558, commands 2,987, remote protocol 66 and connect arguments 4 passed |
| Public offline CLI | Non-admin fresh-process checks: 110 passed, including all six final live bundles; privileged symlink checks: 180 passed, including 14 bundles from an earlier run |
| Focused live controls | One 180-second run with four positive and two negative owned controls passed; all required positive kinds observed, no unexpected fixture findings, six of six evidence bundles published without failures or queue drops |

The live run ended with drained work, unchanged boot time and no owned services
remaining. Original emitted receipts were cross-checked against all 23 bundles
from three runs. Offline replay of 20 bundles from the last two runs reconstructed
their declared stored facts; it did not repeat image-reference verification or
establish execution, communication, collector trust or actor attribution.
The console self-test also covered native writer queue and session-byte limits,
and replayed an owned allocation's saved bytes after that allocation was freed.

Two earlier all-process runs on an intermediate build, lasting 60 and 180 seconds,
**failed the fixture coverage gate** because some reference scans had not run.
Their queue/drain checks passed, with three and 14 bundles respectively committed
without publication loss, and no unexpected fixture findings. These are not
complete all-process passes; the focused pass does not close that coverage gap.
One earlier whole-app self-test also failed an unchanged AI child-process capture
check; the isolated suite and a quiet whole-app rerun passed. Its exact cause was
not established.

The review corrected an offline integration defect: ordinary controller startup
required elevation and loaded a driver before reaching file-only commands.
`--offline !kmon` now returns before live initialization. Imports also enforce
their byte budget and file-reparse policy on the opened handle. The tests do not
cover every power-loss outcome, long-running workload, Windows build or external
malware corpus.

## Earlier development evidence

- The final KMON series used repeated 600-second full-process runs with nine
  positive and four negative controls and the actual x86 vctip System.Data.dll
  image views. It improved observed coverage while retaining incomplete large
  background sweeps and run-to-run variation. Those runs used the binaries
  identified in their reports, not the later version-stamped release package.
- The latest query/runner-failure matrix recorded **1,034 ordinary checks**,
  **50 verified injected failures**, and **344 balanced final unload ledgers**.
  It is separate from the smaller release-candidate matrix; do not add their
  totals or describe them as the same run.
- Two development crashes were attributed to this work: an unloaded raw
  replacement callback (0xCE on 2026-10-24) and an unlocked pending READ buffer
  (0x1A/0x4477 on 2026-10-25). External callback replacement was blocked;
  asynchronous fixture READs gained buffer locking and lifetime fixes. The
  historical dumps/failures remain evidence rather than being reclassified as
  successful tests.

## Remaining scope

- No universal miss/false-positive rate, protected-game compatibility, or
  complete host-clean claim follows from owned controls or a quiet scan.
- Read failures, protected processes, unsupported layouts, dynamic-relocation
  exclusions, finite queues/indexes, large-image partials and observation gaps
  remain visible. Traversal completion is not verification of every byte.
- Raw `!kmon iotrace` has a separate unresolved publication/unload lifetime
  boundary. Managed fixture passes do not validate external dispatch mutation.
- Driver Verifier, reboot stress, arbitrary long schedules, full live LA57
  coverage, and independent real-sample comparisons require separate evidence.
- Earlier Fast I/O/process-read gaps and WinHTTP Event-handle retention are not
  closed by the release. Runner cleanup does not cover supervisor termination
  or an OS stop.

## Git history maintenance

On **2026-10-27**, repository branches and tags were rewritten to remove
developer-local path strings. The v0.0.36 source tag now resolves to
`6646461422125290ade00c74ce5e3e07d617e3a7`. Historical report titles and recorded
`base_commit` / `base_revision` values retain their original identifiers from
before the rewrite. Runtime results and binary hashes were not regenerated,
and published release assets are unchanged.

Use a fresh clone, or rebase local changes onto the rewritten history.
Merging the old history back would restore the removed content.

## Historical reports

The following original reports are pinned to **v0.0.36**. Their old protocols,
commands, hashes and counts describe those source snapshots. Current procedures
are in the manual checklist and fixture guides. Removing duplicated work logs
from the current tree does not erase their Git history or raw local artifacts.

| Report | Original record |
| --- | --- |
| Command audit: 2026-09-19 | [COMMAND_AUDIT_20260919.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/COMMAND_AUDIT_20260919.md) |
| 2026-10-25 외부 필터 콜백 수명 검토 | [EXTERNAL_CALLBACK_LIFETIME_REVIEW_20261025.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/EXTERNAL_CALLBACK_LIFETIME_REVIEW_20261025.md) |
| 도움말·자동완성 점검 — 2026-09-20 | [HELP_COMPLETION_AUDIT_20260920.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/HELP_COMPLETION_AUDIT_20260920.md) |
| !kmon adversarial review, 2026-09-16 | [KMON_ADVERSARIAL_REVIEW.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_ADVERSARIAL_REVIEW.md) |
| Kmon 적대적 코드 리뷰 — 2026-09-20 | [KMON_ADVERSARIAL_REVIEW_20260920.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_ADVERSARIAL_REVIEW_20260920.md) |
| KMON 전체 프로세스 레이아웃 큐 검증 (2026-10-23) | [KMON_ALL_PROCESS_LAYOUT_VALIDATION_20261023.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_ALL_PROCESS_LAYOUT_VALIDATION_20261023.md) |
| 분석가용 콜백 수집·스냅샷 기능 적대적 리뷰 — 2026-09-20 | [KMON_ANALYST_REVIEW_20260920.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_ANALYST_REVIEW_20260920.md) |
| 분석가용 콜백 조사 기능 검증 — 2026-09-20 | [KMON_ANALYST_VALIDATION_20260920.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_ANALYST_VALIDATION_20260920.md) |
| KMON 배경 이미지 완료와 이름 조회 재검증 | [KMON_BACKGROUND_COMPLETION_VALIDATION_20261024.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_BACKGROUND_COMPLETION_VALIDATION_20261024.md) |
| KMON 커널 캡처와 레이아웃 단서의 검사 지연 검증 | [KMON_CAPTURE_LATENCY_VALIDATION_20261024.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_CAPTURE_LATENCY_VALIDATION_20261024.md) |
| Kmon 은닉 코드 관측 범위 | [KMON_COVERAGE_MATRIX_20260919.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_COVERAGE_MATRIX_20260919.md) |
| KMON 미완료 검사와 읽기 공백 개선 — 2026-10-23 | [KMON_COVERAGE_VALIDATION_20261023.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_COVERAGE_VALIDATION_20261023.md) |
| kmon 오탐 검토와 증거 해석 | [KMON_FALSE_POSITIVE_AUDIT_20260920.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_FALSE_POSITIVE_AUDIT_20260920.md) |
| 게임핵 헌팅 연구와 구현 기준 | [KMON_HUNTING_RESEARCH_20260919.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_HUNTING_RESEARCH_20260919.md) |
| 동시 감시 이미지 순회 검증 (2026-10-24) | [KMON_IMAGE_SCHEDULING_VALIDATION_20261024.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_IMAGE_SCHEDULING_VALIDATION_20261024.md) |
| KMON 전체 이미지 순회 검증 — 2026-10-23 | [KMON_IMAGE_SWEEP_VALIDATION_20261023.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_IMAGE_SWEEP_VALIDATION_20261023.md) |
| !kmon: implementation of the September 16 gap review | [KMON_IMPLEMENTATION_2026-09-16.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_IMPLEMENTATION_2026-09-16.md) |
| 대형 배경 이미지와 실행 간 검사 범위 검증 | [KMON_LARGE_BACKGROUND_VALIDATION_20261024.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_LARGE_BACKGROUND_VALIDATION_20261024.md) |
| KMON 대형 이미지와 동적 재배치 검증 (2026-10-23) | [KMON_LARGE_IMAGE_VALIDATION_20261023.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_LARGE_IMAGE_VALIDATION_20261023.md) |
| KMON 후보 유효기간·이미지 이름 수집 검증 (2026-10-23) | [KMON_LAYOUT_FRESHNESS_VALIDATION_20261023.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_LAYOUT_FRESHNESS_VALIDATION_20261023.md) |
| 2026-10-23 KMON 실검증 | [KMON_LIVE_VALIDATION_20261023.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_LIVE_VALIDATION_20261023.md) |
| Kmon 프로세스 배치 수집 검증 기록 | [KMON_PROCESS_LAYOUT_VALIDATION_20260920.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_PROCESS_LAYOUT_VALIDATION_20260920.md) |
| 2026-10-23 KMON 큐 포화 및 손실 개선 | [KMON_QUEUE_VALIDATION_20261023.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_QUEUE_VALIDATION_20261023.md) |
| !kmon 추가 은닉 탐지 공백 조사 | [KMON_REMAINING_GAPS_2026-09-16.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_REMAINING_GAPS_2026-09-16.md) |
| kmon follow-up adversarial review | [KMON_REVIEW_FOLLOWUP_2026-09-16.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_REVIEW_FOLLOWUP_2026-09-16.md) |
| KMON 보조 이미지 뷰 재배치 기준 검증 (2026-10-23) | [KMON_SECONDARY_IMAGE_VALIDATION_20261023.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_SECONDARY_IMAGE_VALIDATION_20261023.md) |
| 실제 vctip의 System.Data 보조 뷰 검증 (2026-10-24) | [KMON_VCTIP_VALIDATION_20261024.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_VCTIP_VALIDATION_20261024.md) |
| 2026-10-06 실기 검증과 수정 | [LIVE_HOST_VALIDATION_20261006.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/LIVE_HOST_VALIDATION_20261006.md) |
| 2026-10-13 실호스트 검증 | [LIVE_HOST_VALIDATION_20261013.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/LIVE_HOST_VALIDATION_20261013.md) |
| 2026-10-23 실호스트 검증 | [LIVE_HOST_VALIDATION_20261023.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/LIVE_HOST_VALIDATION_20261023.md) |
| 2026-10-25 협력형 콜백 제어와 커널 수명 검증 | [MANAGED_CALLBACK_VALIDATION_20261025.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/MANAGED_CALLBACK_VALIDATION_20261025.md) |
| 2026-10-24~25 네이티브 기능 실호스트 검증과 재부팅 분석 | [NATIVE_FEATURE_VALIDATION_20261024.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/NATIVE_FEATURE_VALIDATION_20261024.md) |
| 2026-10-25 pending I/O와 completion context 수명 검증 | [PENDING_IO_LIFETIME_VALIDATION_20261025.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/PENDING_IO_LIFETIME_VALIDATION_20261025.md) |
| 2026-10-25 pending I/O 경합 재현과 수정 | [PENDING_IO_RACE_REVIEW_20261025.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/PENDING_IO_RACE_REVIEW_20261025.md) |
| 2026-10-25 f2202d7 다중 READ·인스턴스 분리 경합 리뷰 | [PENDING_MULTIREAD_REVIEW_20261025.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/PENDING_MULTIREAD_REVIEW_20261025.md) |
| 2026-10-25 73e8947 부분 READ 배치·재연결 경합 리뷰 | [PENDING_PARTIAL_REVIEW_20261025.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/PENDING_PARTIAL_REVIEW_20261025.md) |
| 2026-10-25 97a00cd 응답 버퍼·실행기 실패 경합 리뷰 | [PENDING_QUERY_FAULT_REVIEW_20261025.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/PENDING_QUERY_FAULT_REVIEW_20261025.md) |
| 2026-10-25 7a210fa 동시 조회·포트 수명 리뷰 | [PENDING_QUERY_REVIEW_20261025.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/PENDING_QUERY_REVIEW_20261025.md) |
| 2026-10-25 0de0043 새 ARM·요청자 종료 경합 리뷰 | [PENDING_REARM_REVIEW_20261025.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/PENDING_REARM_REVIEW_20261025.md) |
| 2026-10-25 621d16e 대상 종료 감시 경합 리뷰 | [PENDING_WATCH_REVIEW_20261025.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/PENDING_WATCH_REVIEW_20261025.md) |
| Evasion research ledger refresh - 2026-09-20 | [RESEARCH_REFRESH_20260920.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/RESEARCH_REFRESH_20260920.md) |
| 2026-10-23 CI/HVCI 및 메모리 탐지 검토 | [RESEARCH_REFRESH_20261023.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/RESEARCH_REFRESH_20261023.md) |
