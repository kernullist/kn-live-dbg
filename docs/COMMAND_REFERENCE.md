# Command guide

This guide describes workflows and output contracts. `help <command>` and
`<command> help` provide the current grammar; `KnLiveDbg.exe --help all` is
available without elevation, a driver, or symbols. Tab completion uses the same
command definitions in the local and remote consoles.

## Session and memory

```text
drvstatus
write off
.sympath
lm
x nt!PsInitialSystemProcess
dq nt!PsInitialSystemProcess
dt nt!_EPROCESS
help procctx
help vtop
help db
```

Native memory commands accept address expressions and symbols. `d*`, `e*`, and
`vtop` support a process context; kernel writes default to System PID 4.
Keep the process instance/context with saved addresses. An address from an old
mapping or exited PID is not a stable identity. Unreadable display bytes remain
`??`; they are not zero values.

| Family | Purpose |
| --- | --- |
| `db/dw/dd/dq`, `dps/dds/dqs` | Virtual memory and symbolized pointer tables |
| `!db/!dw/!dd/!dq`, `pdb/pdw/pdd/pdq` | Physical memory |
| `vtop`, `procctx`, `!address` | Address translation, selected context, effective permissions and ownership |
| `dt`, `dtx`, `x`, `ln`, `u`, `uf` | Types, fields, symbols and disassembly |
| `e*`, `pe*`, `f`, `m`, `setfield` | Explicit mutations; require write mode |
| `c`, `s` | Compare and search ranges |

Native write mode begins enabled. `write off` disarms it. Address-only native
edit forms can prompt locally; remote edits require values on the command line.
Small recognized writes can show backup/restore and verification evidence.
Do not treat a failed or short backup as a complete restore plan.

## Native investigation

| Question | Commands | Interpretation |
| --- | --- | --- |
| Which processes and mappings exist? | `ps`, `!vad`, `!threads`, `!handles`, `!hiddenproc`, `!hunt` | Cross-view and bounded metadata; inaccessible processes remain gaps |
| Which modules and drivers own code? | `lm`, `!module integrity`, `!driver integrity`, `!driver object`, `!device stack` | Ownership and byte/dispatch evidence; coverage depends on layout and reads |
| Which callbacks and hooks are registered? | `!callbacks`, `!minifilter`, `!ssdt`, `!idt`, `!msrcheck`, `!cr` | Registered/observed state, not proof of current instruction execution |
| What other execution surfaces exist? | `!hal`, `!hive`, `!dpc`, `!timer`, `!etw`, `!nmi`, `!fwtable`, `!inputstack` | Check candidate layouts, sampling and symbol availability |
| What platform policy is visible? | `!vbs`, `!ci`, `!securekernel`, `!hv`, `!dma`, `!token` | Current posture, with unknowns preserved |
| What communication structures exist? | `!wfp`, `!alpc`, `!wnf` | A registered pointer or endpoint is not an attributed communication history |
| Which driver/payload traces remain? | `!byovd`, `!mapper`, `!kpage`, `!pool pe`, `!payload`, `!wdfilter` | Independent layers; one quiet layer does not establish absence in another |

`ps` / `ps -f <image>` is the simple native process list. `!process` and other
WinDbg names have routing-specific behavior; consult the
[coverage table](WINDBG_COMMAND_COVERAGE.md) before assuming native support.

CI/VBS structured output is `kn-live-dbg.vbs.v2`. Unavailable values are `null`;
HVCI flags and CI debugger mode have distinct meanings. The removed v1 fields
`hvciEnforced` and `hvciDebugMode` must not be inferred from renamed booleans.

`!byovd` uses a local catalog, with optional refresh/signature/YARA work in the
console path. Inspect catalog age and source counts with `!byovd status`.
MCP `byovd.scan` does not refresh the network catalog or run a subprocess.
The benign metadata fixture tests a name/version path, not a vulnerable driver.

`!mapper` checks bookkeeping remnants; a clean ledger does not prove payload
absence. `!kpage` checks executable mappings outside known modules, and `/deep`
adds a slower PFN path. `!pool pe` and `!payload` supply independent byte/reference
evidence. Firmware-table inspection reads registrations without invoking handlers.

## Whole-host hunt

```text
help !hunt
!hunt
!hunt /deep
```

Default/deep hunt joins user memory, VAD/PTE, thread/APC, driver/service, WFP,
QoS/Bind, CloudFiles and Filter Manager evidence. Deep collection has additional
prerequisites and budgets; an unavailable TI subscription is incomplete evidence,
not an empty clean ring. Use the JSON coverage fields and domain warnings.

The [hunt fixture guide](HUNT_TEST_TARGET.md) owns the scenario descriptions,
ESET indicator-validation workflow, cleanup procedures, and output expectations.
Its name, permission, exact-hash and observed-effect controls are separate.
No sample detection percentage follows from the fixture count.

## KMON

```text
!kmon start /name game.exe /background /log C:\kmon-evidence
!kmon status
!kmon recent 100
!kmon cases /json
!kmon save C:\kmon-evidence\session.jsonl
!kmon stop
```

Bare `!kmon` starts or reattaches the live tail; `/background` leaves the prompt
available. Esc detaches the display without stopping collection. `/driver` is
a highlight, not an exclusive collection filter. Starting KMON can configure
TI, process logging and live callbacks, so it requires the applicable write
and collection prerequisites.

Name/PID watches prioritize activity. With no named layout restriction,
full-process layout discovery rotates across the host. This is still bounded
work; every image and page need not finish within a single run.

- [Coverage](KMON_DETECTION_COVERAGE.md): supported paths and blind spots.
- [Verification](KMON_DETECTION_VERIFICATION.md): image identity, relocations,
  captures, compared/failed/excluded bytes and traversal progress.
- [Process layouts](KMON_PROCESS_LAYOUTS.md): initial/current maps and changes.
- [Analyst surfaces](KMON_ANALYST_SURFACES.md): TLS, KCT, WorkerFactory and saved diffs.
- [Cross-domain hunting](KMON_CROSS_DOMAIN_HUNTING.md): relationships and replay.
- [Fixture guide](KMON_TEST_TARGET.md): 13-control and real-vctip validation.

`finding.*` describes evidence requiring interpretation. A code difference does
not identify a malicious actor, and a temporal/PFN relationship does not prove
the write mechanism. Inspect loss, name failures, partial capture and remaining
work before judging a quiet run.

## TI and timeline

```text
!ti status
!ti start /name target.exe
!ti recent 100
!ti stats
!ti stop
```

TI access depends on process protection and Windows policy. The console checks
prerequisites; a read-only query cannot silently create a usable subscription.
Starting/stopping collection is a mutation. The ring, console tail and rotating
JSONL log are separate outputs: a quiet display does not imply no retained
events, and failed file output does not make the ring durable. Watch changes
affect live display/selection as documented by `help !ti`; inspect counters and
log state explicitly.

Use [timeline workflows](TIMELINE_COMMAND_USAGE.md) to ingest TI, live kernel
events and snapshots, query evidence families, export JSONL, and reconcile
same-boot baselines. Collection loss and capacity eviction constrain absence
claims.

## Baselines, diffs and dumps

```text
!snapshot baseline /all
!snapshot show baseline /domains /warnings
help !diff
help dump-raw
help dump-pe
help dump-kernel
help dump-live
help dump-analyze
```

Snapshots retain domain coverage and stable process/object identities. Compare
compatible same-boot snapshots; missing rows in an incomplete domain are not
proof of removal. Recapture unloaded-driver baselines after upgrading to
v0.0.36. Snapshot files and reports are stored under the EXE-local
`.kn-live-dbg` directory unless an explicit output path is supplied.

Raw/PE dumps capture selected bytes. Complete physical and OS live dumps have
different acquisition paths and are not atomic paused-machine snapshots.
`dump-kernel /strict` rejects unreadable physical ranges instead of accepting
zero-filled gaps. Inspect the dump metadata and warnings before analysis.

## Callback control

Inspection is available for external registrations. Mutation supports only the
cooperative fixture and its CREATE counting bodies:

```text
!minifilter show KnLiveDbgMiniFilterFixture
!minifilter disable KnLiveDbgMiniFilterFixture CREATE /pre
!minifilter enable-all KnLiveDbgMiniFilterFixture
```

Control requires `write on`. `/pre`, `/post`, `/both`, and `all` select supported
bodies, not arbitrary registrations; registered pointers and mandatory cleanup
stay active. Owner exit/port closure restores the provider lease. See the
[test checklist](MANUAL_TEST_CHECKLIST.md#pending-io-and-runner-failure-validation).
External callback pointer replacement remains unavailable.

`!kmon iotrace` is separate experimental raw IRP dispatch interposition.
It is not covered by the fixture's cooperative lifetime guarantee. Read the
[driver interaction limits](DRIVER_INTERACTION_TRACKING_DESIGN.md) before use.

## Optional execution paths

| Path | Contract |
| --- | --- |
| DbgEng | `backend`, `kdinit /local`, `kdinit /remote`, `kd`; stop-state commands require a suitable backend/target |
| AI | [Provider and guarded-plan guide](AI_ASSISTED_WORKFLOWS.md); remote model availability is external state |
| Human remote console | [Remote setup](REMOTE_SETUP.md); commands execute on the analysis host |
| MCP | [MCP setup](MCP_SETUP.md); typed catalog, no arbitrary command pass-through |

Use `q` for orderly controller exit. Run fixture and collector lifecycle tests
from the [manual checklist](MANUAL_TEST_CHECKLIST.md), with failed cleanup kept
as a failure rather than hidden by a successful command's output.
