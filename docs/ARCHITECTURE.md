# Architecture

Implementation baseline: v0.0.36. For operator syntax use
[the command guide](COMMAND_REFERENCE.md); for measured behavior use
[validation status](VALIDATION.md).

## Components

| Component | Responsibility |
| --- | --- |
| `driver/Driver.cpp`, `shared/KnLiveDbgIoctl.h` | Administrators/SYSTEM device, exclusive controller, memory/page-table/CPU primitives, process operations, live callbacks and experimental I/O trace |
| `user/DeviceClient.*`, `DriverService.*` | ABI-checked IOCTL client and owned SCM lifecycle |
| `user/main.cpp`, `CommandRegistry.*`, `CommandInput.h`, `CompletionHints.h` | Local dispatch, syntax validation, help, completion, self-tests, execution-origin policy |
| `user/SymbolEngine.*`, `NativeDisassembler.*`, `DbgEngBackend.*` | DbgHelp/DIA types and symbols, Zydis disassembly, optional DbgEng commands |
| `user/*Scanner.*`, `UserModeHunter.*` | Bounded native collectors and cross-view interpretation |
| `KernelMonitor.*`, `KernelMonitorHunting.cpp`, `ProcessLayoutMonitor.*` | Continuous discovery, queues, capture, image traversal and evidence |
| `KmonHunting.h`, `ObservationModel.h`, `ExecutableRegionCatalog.h`, `ExecutableImageVerifier.h` | Observation contracts, bounded case/region indexes, reference-byte verification |
| `ThreatIntelSubscriber.*`, `Timeline*`, `Snapshot*` | Events, persistence, baselines and comparison |
| `McpServer.*`, `RemoteServer.*`, `RemoteClient.cpp` | Separate typed-tool and human-console transports |
| `AiProvider.*`, `AiModelCatalog.*` | Provider execution, model resolution and advisory plans |
| `probe_driver/`, `minifilter_fixture_driver/`, `hunt_test_target/`, `kmon_test_target/`, `bind_fixture_controller/`, `byovd_fixture_driver/` | Owned positive/negative controls with separate contracts |

All `user/` filenames in the table are relative to that directory. Build and
packaging behavior is documented in [BUILD_AND_RELEASE.md](BUILD_AND_RELEASE.md).

## IOCTL and memory contracts

The main ABI is **17**, defined in [KnLiveDbgIoctl.h](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/shared/KnLiveDbgIoctl.h).
Requests carry sizes; variable payloads use their header offset rather than
assuming a fixed trailing-array size. User-mode code validates responses and
preserves short reads as incomplete data. Write-like calls require the
per-handle write mode and their acknowledgment fields. The interactive default
is write-on; MCP disarms it when entering read-only mode.

Virtual and physical reads use `MmCopyMemory`. Page-table translation supports
four/five-level walks and effective permissions across parent entries.
Process-context operations resolve the DTB and identity rather than interpreting
a user VA in the controller's address space. MDL fallback is opt-in and limited
by system-address/residency checks; ordinary scanner read failures stay gaps.
Translation metadata includes walked entry addresses and paging level.

Native writes capture the intended process context for preflight, mutation, and
verification. Small recognized ranges can produce exact-byte restore commands;
short or failed backup reads must not produce a misleading partial restore.
The complete mutation implementation remains in the dispatcher and driver, not
in a documentation recipe.

`dump-kernel` streams physical runs into a complete-dump layout; non-strict
unreadable pages may be zero-filled and are reported. `dump-live` uses the OS
live-dump path, while its selected-process form uses the process page tables.
Neither represents an atomic, fully paused machine snapshot.

## Engine, symbols, and transports

The main engine owns DeviceClient and DbgHelp/DIA operations. Symbols are loaded
from the EXE-local search path and cache. Missing fields or symbols must remain
unsupported/partial; a guessed layout is not a stable Windows ABI.

MCP and remote listeners own transport work and enqueue engine jobs. They have
separate FIFOs and cannot listen simultaneously. Console output capture belongs
to the engine thread. A wait ending before dispatch can remove a queued job;
after dispatch it may leave an unknown outcome while execution continues.
Neither timeout nor socket closure implies rollback.

See [MCP design](MCP_SERVER_DESIGN.md) and [remote design](REMOTE_OPERATOR_SESSION.md)
for bounds, authentication, stop behavior, and audit contracts. Normal shutdown
stops collectors before closing their device and services. Failed I/O-trace
disarm keeps the controller available for retry and can delay driver unload.

## Scanner evidence

Collectors cross-check modules, objects, callbacks, process/VAD/PTE views,
CPU state, and user-mode observations. Read failure, missing layout, exhausted
budget, or an incomplete inventory cannot prove absence. The snapshot/diff path
requires comparable same-boot identities and preserves domain coverage.

CI/HVCI state comes from validated `SystemCodeIntegrityInformation` responses.
The `kn-live-dbg.vbs.v2` output uses null for unknown values, separates CI
debugger mode from HVCI enabled/audit/strict/IUM flags, and qualifies Microsoft
hypervisor feature leaves with `Hv#1` and the reported leaf range. It does not
infer enforcement history from a current flag. Recapture older unloaded-driver
snapshot baselines after the v0.0.36 identity-format change.

`!hunt` combines memory, process, driver, policy and event evidence. Name/path
matches remain distinct from exact hashes and observed effects.
Exact-only public filenames such as `HwAudKiller.exe` are not suffix-normalized.
A `GentlemenCollection` path alone is only supporting context. The source's
GentleKiller target list is a recorded snapshot of
274 unique lower-case image names exposed by public Table 2 HTML, not a newly refreshed threat feed.
TI classification qualifies sensitive cross-process tasks before correlating
them. [Hunt fixture documentation](HUNT_TEST_TARGET.md) describes the controls.

## KMON collection and verification

KMON joins TI and kernel live events with rotating native scans. In full-process
layout mode, discovery is not limited to watch names; watched targets receive
priority shares without eliminating background work. Capture and analysis have
bounded queues, identity checks, explicit loss accounting, and shutdown drain.

Image work keeps cursors by process creation, base and validated file identity.
Dedicated continuation uses bounded page/time budgets, balances watched and
background targets and first/repeated sweeps, and reserves background turns for
general rotation, large-image progress and short remaining work. Completion
means traversal; failed or excluded bytes still prevent full verification.

Byte comparison validates the PE/reference identity and supported relocations.
Secondary image views require an independently supported relocation basis.
Excluded loader/dynamic ranges remain unverified even when their bytes happen
to match. Stored captures and compared-address accounting are separate from
the number of emitted findings.

Typed callback slots and execution references are revalidated around reads.
Candidate layouts, static branches, matching bytes, shared PFNs and temporal
relationships do not establish current execution or the actor that wrote memory.
Cases and executable-region catalogs are finite current-state indexes. Case
queries apply PID and role predicates to the same endpoint before limiting
output, preserve both endpoints of matching relations, and count all matching
cases in the retained fresh scope. Continuations bind the index epoch/revision,
query time, filter and page size; mutation or expiry rejects a stale cursor
instead of silently changing page membership. This is a query-scope contract,
not a claim that collection was complete. JSONL and snapshots do not yet make
every evicted relationship reconstructible; the
[investigation milestone](FEATURE_PLAN.md#investigation-milestone) separates
immutable evidence from the recent view.
Process keys use boot identity, PID and nonzero creation time (the kernel uses
the boot-scoped PID-zero key). Optional EPROCESS/session assertions constrain
that key; their compatibility is not transitive. Hunting and executable-region
reducers keep known constraints separately from the latest raw observation, so
an unknown refresh cannot bridge conflicting known assertions. These constraints
remain bounded by the indexes' retention, not by the lifetime of the whole boot.
Hunting also records up to 2,048 receipts with original event time, arrival time,
arrival sequence and current-view disposition. Delayed/conflicting receipts do
not rewind the current view. This in-memory history reports eviction and is not
yet a durable store; emitted receipt JSON remains subject to log collection loss.
See [coverage](KMON_DETECTION_COVERAGE.md), [verification](KMON_DETECTION_VERIFICATION.md),
[analyst surfaces](KMON_ANALYST_SURFACES.md), and
[process layouts](KMON_PROCESS_LAYOUTS.md).

## Cooperative callbacks and pending I/O

`!callbacks` and `!minifilter` control only the exact cooperative
`KnLiveDbgMiniFilterFixture` target's CREATE bodies, through its control port.
The provider owns rundown, owner restoration and lifecycle callbacks. `all`
selects supported bodies; it does not select arbitrary external registrations.
Registered pre/post pointers remain unchanged. External pointer replacement is
unavailable because entry-time rundown does not protect a pointer fetched before
entry or arbitrary pending completion contexts.

The managed protocol is version 1. The independent pending-I/O protocol is
**7**, with **32-byte requests** and **528-byte status replies**, in
[KnLiveDbgPendingIo.h](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/shared/KnLiveDbgPendingIo.h).

- The fixture locks READ buffers before asynchronous completion and manages
  logical/worker references independently.
- Pairing requires the same callback data, a live owner, and the current
  instance topology generation. Detach/reconnect retires stale reservations.
- Target exit checks use a process reference and termination signaling; exit
  code 259 alone does not establish that a target is still alive. A stale watch
  result cannot retire a new ARM or replacement requestor.
- QUERY authorizes the port cookie/current caller and captures a local status
  snapshot under `g_Lock`. It releases the lock before delay/copy; it retains no
  client/port pointer across that interval. Reply copying is exception-guarded.
- `g_Control` serializes control/owner mutations. QUERY avoids that long path so
  status remains observable during target-watch work. Query counters are
  diagnostics, not a replacement for Filter Manager callback lifetime.
- Stop disarms reservations, wakes/joins workers and releases ownership.
  Unregister drains callbacks and instances before the final audit.
  Only final ledgers require all active counts zero and started/completed pairs
  balanced; a live query includes itself.

Python runners keep independent cleanup steps so a report/log failure does not
skip resource release. The failure supervisor starts a gated child in a
kill-on-close Windows job and recovers only the verified owned fixture service.
Injected child failures remain failures; the parent separately verifies cleanup.
Supervisor termination and OS failure are outside that recovery guarantee.
See the [lifecycle test checklist](MANUAL_TEST_CHECKLIST.md#pending-io-and-runner-failure-validation).

Raw `!kmon iotrace` does not use this cooperative contract. Its separate
[publication and unload limits](DRIVER_INTERACTION_TRACKING_DESIGN.md) remain open.
