# Manual test checklist

Use a fresh result directory and record the source revision, binary hashes,
configuration, Windows build, and test interval. [Validation status](VALIDATION.md)
contains dated observations; it does not check off a new build or host.
Preserve failed runs, partial coverage and cleanup errors.

## Native session policy

Current main changes native session defaults. In an authorized isolated lab with
the matching EXE/SYS, additionally check a fresh `drvstatus` reports write-off,
mutation requests are denied before `write on`, explicit on/off transitions agree
with `drvstatus`, and exiting MCP leaves write-off. Exercise mismatched older
drivers and failed mode/status replies: startup or engine dispatch must fail
closed. Driver-free fault injection covers the acknowledgment/status decision;
it does not replace these live kernel integration checks.

## Driver-free gates

From the source root, after building the configuration under test, use a shell
that permits the inspected repository scripts. The Windows PowerShell command
below sets its execution policy for that process only.

```powershell
.\x64\Release\KnLiveDbg.exe --help all
.\x64\Release\KnLiveDbg.exe --self-test all
python tools/test-source-capabilities.py --exe x64/Release/KnLiveDbg.exe
.\tools\validate-command-audit.ps1 -Sanitize
.\tools\validate-kmon-core.ps1 -Sanitize
.\tools\validate-kmon-hunting.ps1 -Sanitize
.\tools\validate-analyst-features.ps1 -Sanitize
.\tools\validate-evidence-bundle.ps1 -Sanitize
.\tools\validate-parser-worker.ps1 -Sanitize
.\tools\validate-hidden-process.ps1 -Sanitize
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test-kmon-reference-coverage.ps1
.\tools\validate-minifilter-detach-e2e-selftest.ps1
.\tools\validate-evasion-research-ledger-selftest.ps1
python tools/test-kmon-capture-accounting.py
python tools/test-kmon-layout-names.py
python tools/test-kmon-vctip-audit.py
python tools/test-kmon-image-coverage.py
```

Use the Debug EXE and `-Configuration Debug` on validators that support it when
validating a Debug build. The evidence-bundle validator builds its own Release
or Release-ASan harness.
`--self-test all` runs timeline, MCP catalog, console, command, remote-protocol,
and connect-argument checks before driver/elevation/symbol initialization.
AddressSanitizer applies to the standalone harnesses, not every command run by
the normal EXE. The hunting validator's PE-sieve comparison is separate and
requires `-PeSieve <path>`; omission is not a successful external comparison.

`--self-test mcp-http` is separate and needs HTTP.sys registration rights.
Run network fixtures sequentially: remote loopback uses 51767 and HTTP self-test
uses 51768. These test modes do not create external listeners/firewall rules.
Source validators require their toolchain; the package does not imply every
source-only harness is present.

After grammar/help changes, check startup and scoped help, quoted paths,
unknown/duplicate options, nested help completion, local/remote consistency,
and that invalid input fails before side effects. Query-runner `--help` exits 0;
argument errors exit 2 without driver setup or a traceback.

The hidden-process harness uses synthetic kernel lists and lifecycle reads. It
checks PID/EPROCESS/creation-time reuse, incomplete/changed lists, unread fields,
exit transitions, budget stops and an independent JSON oracle. It does not load
a driver. Native `--self-test all` also exercises the policy and existing SPI
parser controls. Live acceptance, when an authorized lab is available, still
needs ordinary creation/exit churn, snapshot clones, missing layouts and partial
reads on each supported build; retain unverified candidates and distinguish
discovery membership from qualification. Do not infer a live pass from fixtures.

The core validator also checks native execution evidence levels and an independent
JSON oracle. Native command self-tests cover typed user-evidence conversion,
bounded observation export, PE32/PE32+ callback widths and VAD thread/APC/stack
references without an execution claim. These controls do not validate a CPU
trace source or live callback execution.

`tools/validate-pending-irp.ps1 -Sanitize` builds the actual reader independently
of a device or symbol session. It checks LA48/LA57, bounded continuations, request
and owner changes, requests without completions, malformed stack bounds, missing
optional fields and an independent JSON/graph oracle. A final successful status,
cancel bit or empty stack must not produce a completed/cancelled outcome. These
controls do not exercise a live IRP lifetime, driver cancellation or wait graph.

`tools/validate-execution-trace.ps1 -Sanitize` builds the actual importer and
bounded artifact reader. Run `python tools/test-execution-trace.py --exe
x64/Release/KnLiveDbg.exe` after the native build to verify public dispatch,
identity/loss/code-version boundaries, immutable paging, Unicode output and
malformed/capped input. These fixtures do not decode raw trace packets or prove
that the producer observed execution. Shared reference-reader changes also
require `tools/validate-image-recipe.ps1 -Sanitize`.

## Live-host prerequisites

- Use a Windows x64 lab host/VM with the required signing configuration and
  matching binaries. Record boot time and existing dumps/events before testing.
- Build before loading owned drivers. Run fixture suites sequentially, with
  their owned services absent at entry. Do not rebuild or replace a loaded SYS.
- Confirm ABI 17, controller ownership, symbol/type availability and write mode
  at startup. Missing symbols are incomplete coverage, not a normal empty result.
- Use a disposable owned target for writes. Keep process identity and address
  context consistent from backup through readback/restore.

## Native features

| Area | Required observations |
| --- | --- |
| Lifecycle | Startup/ABI/owner checks; orderly `q`; repeated load/unload; no owned service/process residue |
| Memory and types | Probe-known virtual/physical bytes; process-context reads; sparse/short-read display; guarded writes with exact backup/readback/restore; unsupported fields fail before mutation |
| Modules/drivers | Stable module identities, PE/section and dispatch output; incomplete page-attribute samples remain incomplete; independent stored-byte comparison for reported changes |
| Process/VAD/threads | Controlled positive and normal negative cases, PID reuse/exit, inaccessible processes, unknown module ownership, bounded traversal and explicit read failures |
| CPU/platform | LSTAR and KVA-shadow entry handling, zero CSTAR, group-aware IDT coverage, unsupported mitigation notes, CI nulls/public flags and qualified `Hv#1` leaves |
| Callback/quiet surfaces | Symbol-qualified roots and module ownership; failed or heuristic layouts stay partial/candidate; no mutation of external registrations |
| WFP/ALPC/WNF/firmware | Output against independently visible registrations; unreadable/heuristic structures remain qualified; firmware inspection does not invoke handlers |
| BYOVD/remnants/pages | Benign metadata fixture and exact catalog fields; separate loaded-driver, bookkeeping, page and payload scopes; quiet mapper ledger is not payload absence |
| Snapshot/diff | Same-boot identity, complete comparable domains, protection/attachment controls, malformed/partial import rejection; missing rows do not imply removal when coverage is incomplete |
| TI/timeline | Prerequisite failures, collection/loss counters, ring versus persisted JSONL, export/import and capacity eviction; stopped/unavailable subscription is not complete empty evidence |
| Dumps | Known bytes/header/run metadata, explicit read gaps and strict-mode refusal; successful file creation alone is not a validated complete dump |
| MCP/remote/AI | Mode/origin restrictions, queue timeout outcomes, writes and readback only on owned targets, audit output, disconnect and stop behavior |

Use `help <command>` and [command coverage](WINDBG_COMMAND_COVERAGE.md) for routing.
On a known normal workload, investigate each unexpected result against raw
evidence before changing a detector. A nonstandard but legitimate configuration
may explain a finding; suppressing the finding without checking is not validation.

## Whole-host hunt

```powershell
.\tools\validate-hunt-clean-host-selftest.ps1
.\tools\run-hunt-clean-host.ps1 -Mode Default -Count 3 -RequireClean
```

The live runner requires zero findings **and complete required coverage** to
pass `-RequireClean`; inaccessible scopes still fail that gate. It disables
writes for scanning and checks service cleanup. For deep/TI testing use the
runner's documented `-Mode Deep -EnableThreatIntel` path on the lab host;
it temporarily changes protection/collection state before disarming writes.
Group findings with `analyze-hunt-clean-host.ps1` rather than ignoring intermittent
results. [Hunt fixture](HUNT_TEST_TARGET.md) documents the scenario and external
evidence runners; run only the applicable owned controls.

## KMON all-process validation

Use [KMON_TEST_TARGET.md](KMON_TEST_TARGET.md) for fixture setup and actual-vctip
observation. For the six-control reference regression, run both watch policies
sequentially from an elevated shell with the same monitor and fixture binaries:

```powershell
.\tools\validate-kmon-live.ps1 -AllProcessLayouts -ObserveSeconds 180 `
  -RequireQueueHealth -RequireCompletedWork -OutputDirectory .build/kmon-reference-pid-a
.\tools\validate-kmon-live.ps1 -AllProcessLayouts -NameOnlyFixtures -ObserveSeconds 180 `
  -RequireQueueHealth -RequireCompletedWork -OutputDirectory .build/kmon-reference-name-a
```

The first run registers the fixture name and explicit PIDs; the second registers
only the name. Confirm `fixture_watch_policy` and `all_process_scope_verified`
in `validation.json`. Each child needs an examined reference observation bound
to its creation time and a boot identity inside the observation window.
Compare `user_reference_coverage` visit counts, completed thread inventories,
first-visit delay and maximum gaps, together with positive/negative outcomes.
Unavailable, failed or empty-thread rows must not satisfy the gate. The latest
[six-control results](VALIDATION.md#reference-watch-and-ti-queue-review-2026-10-29)
are bounded observations, not a per-target completion deadline.

The native suite separately checks stale/missing watch identities, name and
extension matching, full TI queue/one-slot admission, source-generation changes,
source-eviction accounting and shutdown across multiple batches. Live queue
peaks must be recorded; a passing run need not have reached full capacity.

For the broader 13-control load, including secondary image views:

```powershell
.\tools\validate-kmon-live.ps1 -AllProcessLayouts `
  -ImageSweepFixtures -SecondaryViewFixtures -ObserveSeconds 600 -ProbeDriver `
  -RequireQueueHealth -RequireCompletedWork -RequireImageCompletion `
  -RequireLayoutNameAccounting -RequireFreshLayouts `
  -OutputDirectory .build/kmon-current-a
```

Repeat with fresh directories and the same frozen monitor binaries. Add
`-ObservedProcessId <actual-vctip-pid>` only after independently identifying its
creation time and real System.Data primary/secondary views. Take before/after
snapshots and run `validate-kmon-vctip.py audit`; passing synthetic controls does
not satisfy that separate real-image gate.

Check exact positive address/file/changed-byte evidence, quiet negative controls,
queue losses, capture accounting, image-name failures, partial exclusions and
final pending work. Use `measure-kmon-image-coverage.py --fixed-cohort` for
compared-address variation across runs. A larger completion count alone is not
proof of wider unique coverage, and background images may still be partial.

## Managed callback control

With the owned fixture loaded, test `!minifilter` and `!callbacks` inspection,
then the supported CREATE `/pre`, `/post`, `/both` and all-body controls.
Require write-mode rejection when disarmed, unchanged registered pre/post
pointers, body rundown before disable returns, counting restored after enable,
and owner-close/termination restoration. Unsupported names, pointer/path-shaped
targets, scopes and IRPs must fail without external callback mutation.

## Pending I/O and runner-failure validation

Run from the repository root in an elevated shell with Python 3.11 or newer and
the matching `x64/Release/KnLiveDbgMiniFilterFixture.sys`. Build before loading the
fixture, keep its service absent at the start, and use a fresh output directory
for each run. Build and run the fixture suites sequentially.

Both query runners support `--help` without elevation or fixture setup. Help
must exit 0 without a traceback; missing required arguments and invalid reader
counts must exit 2 before loading a driver.

```powershell
python tools/run-managed-callback-e2e.py --output .build/managed-current --cycles 30
python tools/run-pending-io-e2e.py --output .build/pending-current --cycles 4
python tools/run-pending-query-e2e.py --output .build/query-current --case all --iterations 4 --readers 8 --last-close --reply-change mixed
python tools/run-pending-query-failure-e2e.py --output .build/query-failures-current --iterations 3 --readers 8
```

Repeat the query and supervisor suites with `--readers 2` and `--readers 16`,
changing output paths. Existing batch, partial submission, re-ARM, and target-watch
regressions remain in `run-pending-multiread-e2e.py`, `run-pending-partial-e2e.py`,
`run-pending-rearm-e2e.py`, and `run-pending-watch-e2e.py`; their dated reports record
the exact invocation matrix.

- Confirm the fixture protocol is v7, with a 32-byte request and 528-byte status.
  This does not change the main driver's ABI 17.
- The ordinary query suite must exit 0 and report `passed=true`. Mixed reply
  changes cover PAGE_NOACCESS, PAGE_READONLY, decommit, release/reserve, and content
  overwrite across a page boundary. Expected copy faults return 998 and 0 bytes;
  successful replies preserve the captured snapshot, and readable boundary
  canaries stay intact.
- A live snapshot includes its own query. Require
  `QueryStarted = QueryCompleted + QueryActive` while running. Only the final
  unload ledger requires `QueryActive=0`, all query/gate/context/instance counts
  balanced, `Violations=0`, and zero remaining contexts, workers, connections,
  instances, owner, and reservation.
- The failure supervisor tests ten stages, including partial reader startup,
  exceptions during the race, audit/log errors, and abrupt runner exit. Its root
  result must exit 0, report `passed=true`, and verify `10 * iterations` expected
  failures when `--case all` is selected. Each `verified.json` must contain
  `verified_expected_failure=true`, job active count 0, and no supervisor cleanup
  errors.
- Structured child failures must exit 1 with `passed=false` and the selected
  failure marker. `runner-exit` exits 86 and leaves no child `result.json` because
  it skips Python cleanup; the supervisor must recover the fixture service and
  final audit. Use the supervisor for abrupt-exit testing. Its own termination
  or an OS stop is outside the recorded service-recovery guarantee.
- Check `failure.txt`, `cleanup_errors`, `journal.jsonl`, `unload-audits.json`, and
  supervisor recovery evidence together. An expected test failure is not a
  successful child test, and extra cleanup errors must fail validation. After
  each run, require `sc.exe query KnLiveDbgMiniFilterFixture` to return 1060 and
  the fixture to be absent from `fltmc.exe filters`.
- Record the boot time before and after the test interval and inspect new
  bugcheck/reboot events, dumps, and remaining owned processes/services. Keep
  earlier crashes distinct from new test failures. The
  [latest review](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/PENDING_QUERY_FAULT_REVIEW_20261025.md) preserves the observed
  interval, binary hash, and complete matrix.



## Collector and shutdown lifecycle

- Stop/restart TI, timeline and KMON while the owned workload produces activity.
  Preserve ring/log/queue loss and coverage; detached display is not stopped collection.
- Check `ti_analysis_dropped`, `source_continuity_lost`, reference expiry/drop
  counters and `shutdown_events_unanalyzed` separately. Queue backpressure must
  preserve the source cursor, and shutdown must either process the frozen source
  tail or report the remaining span. Queue drain alone is not complete image
  or callback coverage.
- Exercise queued versus dispatched transport cancellation separately. A lost
  response or client timeout does not prove an in-flight operation was cancelled.
- Confirm normal `q` stops collectors before closing the device/service. Check
  owned handles, helper processes, ports, jobs and service cleanup after failures.
- Raw `!kmon iotrace` is outside the cooperative fixture contract and retains
  unresolved publication/unload safety. Do not count managed-callback tests as
  closing that gap. See [driver interaction](DRIVER_INTERACTION_TRACKING_DESIGN.md).
- Compare boot time and only events/dumps created during this test interval.
  Preserve earlier crashes separately. A reboot, unbalanced final ledger,
  unexpected cleanup error or remaining callback/service fails the test.
