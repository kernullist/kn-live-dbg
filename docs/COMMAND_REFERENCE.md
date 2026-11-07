# Command guide

This guide describes workflows and output contracts. `help <command>` and
`<command> help` provide the current grammar; `KnLiveDbg.exe --help all` is
available without elevation, a driver, or symbols. Tab completion uses the same
command definitions in the local and remote consoles.

`KnLiveDbg.exe --capabilities` prints selected compiled source contracts without
opening a target. Add `--probe` to read a known 32-byte range in the command's own
process and query an existing default native device's ABI/session. It never
starts or loads the driver. The JSON reports source open, sample read, layout,
semantic and environment validation separately: the owned read is available only
for that control range, and native connection success remains partial. Unsupported
backends stay unsupported and untested environments remain unvalidated. Exit 0
means the report was produced, including denied/unavailable probe states; invalid
arguments exit 1 before any probe, and output failures exit 2. Redirected JSON is
UTF-8, including localized status text. Native calls have no hard timeout.
Runtime probe JSON contains private process/address metadata and is not a public
support certificate. See [generated address/backend contracts](SUPPORT_MATRIX.md).

The probe's `process_read_set` contains the same read as `process_read`, with
operation/receipt IDs, source/range provenance and shared budget denominators.
`recording_complete` means every attempted read has a completed receipt, including
failed reads; it does not mean the target was fully read or validated. It is
private `kn.read_set.v1` evidence, and its caller-declared target labels are not
an authenticated target identity. `native_read_observation_contract` is null
before successful ABI qualification, otherwise the advertised optional read
feature flag. It does not qualify a native sample. Selected native sources use
the versioned status transport; existing direct collectors and native typed translation
remain separate integration work.

Saved KMON evidence can also be investigated without elevation, driver loading,
or symbols: `KnLiveDbg.exe --offline !kmon evidence <directory> /json`,
`--offline !kmon replay <file.kncase> /json`, or `--offline !kmon why <file.kncase>`.
Use `--offline !kmon inventory <directory> <new-snapshot-directory> /json` to
publish a private inventory, then add `/inventory <snapshot-directory>` to
`evidence`. Its result and inventory cursors have different scopes; follow the
[offline investigation workflow](KMON_ANALYST_SURFACES.md#영구-증거와-오프라인-조사).
See [offline evidence and interpretation limits](KMON_ANALYST_SURFACES.md).

`KnLiveDbg.exe --offline !kmon init-store <new-root> [/acl-only] [/json]`
creates a new private local root under an existing directory. By default it
requires EFS encryption and a protected current-user/SYSTEM ACL. `/acl-only`
explicitly omits the encryption requirement. An existing root is rejected;
an EFS failure never silently downgrades. Failed initialization may leave an
empty or policy-bearing private staging directory, reported as
`temporary_directory`, for manual inspection.

`KnLiveDbg.exe --offline !kmon privacy <root> [/audit] [/json]` verifies the
root's policy, principal, physical identity and protections. `/audit` also checks
the existing descendants within explicit entry/depth/time bounds. Both commands
always emit private `kn.evidence_privacy.v1` JSON; exit 0 means `ready`, 1 means
unavailable/denied/incomplete, 2 means invalid grammar and 3 means output failure.
Redirected JSON is UTF-8. An output failure does not undo an already initialized
root; inspect that explicit path again. These commands do not start a
driver or acquisition session. Windows may activate its EFS service for encryption.

Use `!kmon start /private-log <root>` to require that policy and an initial tree
audit for a KMON session. This option is mutually exclusive with `/log`, applies
only at the first start, and never creates or falls back to an ordinary root.
Stop the session before moving the root or replacing its policy. EFS account
keys must remain available for later replay; the tool does not export or back
them up. Administrator/recovery-agent access, owner changes, exports outside the
root and external transfer/redaction require separate controls. See the
[privacy scope and limits](ARCHITECTURE.md#private-evidence-roots).

`KnLiveDbg.exe --offline !kmon redact-image <recipe-directory|knslice|knsweep>
<new-private-root> [/acl-only] [/json]` replays a saved original and publishes
minimized comparison counts plus a private original-hash linkage. A direct
`recipe.knverify` path is also accepted. The default requires EFS; no target
acquisition or AI provider request occurs. `--offline !kmon disclosure <root> [/json]` inspects
the completed package. Both always emit private `kn.disclosure_package.v1` JSON:
0 means ready, 1 denied/unavailable/incomplete, 2 invalid grammar and 3 output
failure. Publication is create-new; an output failure does not undo it.

In the local console, `ai share preview <root>` displays and pins the exact facts
and HTTP destination without sending. `ai share send <review-id> confirm` approves
that review once; `ai share cancel` revokes it. A private intent must commit before
dispatch. Configuration/payload changes, partial packages and reused approvals
are denied. Failed or uncertain transfers need a new review and explicit decision;
they are not retried automatically. Raw captured output cannot be sent through
`ai explain`/`analyze` or automatic tool explanations. Operator-authored prompts
remain provider requests. See [minimized image disclosure](ARCHITECTURE.md#minimized-image-disclosure)
and the [AI workflow](AI_ASSISTED_WORKFLOWS.md#review-minimized-image-evidence).

`KnLiveDbg.exe --offline !kmon journal <collection-directory> [/index] [/json]`
verifies a stopped `collections/<collection-id>` image collection and returns
private `kn.evidence_journal_recovery.v1` JSON. It reports the committed prefix,
closure/unknown tail, exact collection-scoped byte denominators and committed
sweep paths. File presence alone does not establish membership. A live writer
holds the exclusive collection lock, so recovery reports unavailable while it
is active. `/index` resumes publication of derived chunks and an immutable head;
original files are revalidated even if an index exists. Corrupt existing output
is preserved and reported. No orphan deletion or new target acquisition occurs.
Exit 0 means a verified prefix and, when requested, a ready index; the prefix can
still have an unknown tail. Exit 1 means unavailable/incomplete recovery or index
failure, and 2 means invalid grammar. Pass a returned sweep path relative to the
artifact root to `replay-image` or `graph` for separate policy verification.
See [journal bounds and recovery semantics](ARCHITECTURE.md#image-collection-publication-journal).

`KnLiveDbg.exe --offline !kmon store <artifact-root> [/artifacts] [/json]`
audits stopped image collections together and returns private
`kn.evidence_store_inventory.v1` JSON. It reports closed/open/unresolved roots,
exact member/path/content byte denominators and protected retention classes.
`/artifacts` includes bounded per-path ownership detail with explicit omission
counts. Active participating publishers make the audit unavailable; an exclusive
audit also denies new publication attempts until it releases its lease. Use it
after collection stops. Exit 0 means complete verified membership and artifact
inventory, 1 means partial/unavailable, and 2 means invalid grammar. The returned
report grants no deletion authority. See [scope, coordination and bounds](ARCHITECTURE.md#image-store-membership-inventory).

`KnLiveDbg.exe --offline !kmon gc <artifact-root> <policy.json> [/apply operation-id] [/json]`
preflights an explicit policy by default. Prepare one with
`python tools/new-evidence-gc-policy.py --inventory inventory.json --path image-reads/reads-123-4.knreads --reason "obsolete unpublished observation" --output policy.json`.
The input must be the JSON from `store /artifacts`; when saving it in PowerShell,
use `Set-Content -Encoding utf8`. The helper defaults to a 24-hour minimum file
age and 128 MiB total named bytes. Repeat `--path` for explicit additional members.
Review the generated policy and preflight result before using `/apply` with a
canonical decimal operation ID of at most 20 digits. The same ID resumes that
exact operation; it cannot select a new policy or another physical root.

Exit 0 means planned or historically completed; exit 1 includes denied,
incomplete and unresolved deletion outcomes; exit 2 means invalid grammar.
`deleted_this_call` excludes old receipts and absence after an interrupted
intent. Receipt reuse never deletes a later replacement. This command is
offline-only and does not remove committed roots or failure ledgers. See
[GC policy, audit and interruption semantics](ARCHITECTURE.md#explicit-uncommitted-artifact-gc).

`KnLiveDbg.exe --offline !kmon graph <file.kncase|sweep.knsweep> [/node id] [/depth 0..8] [/limit 1..128] [/cursor token] [/budget-ms 0..5000] [/json]`
returns a private `kn.evidence_graph.v1` fact graph for a retained `.kncase` bundle.
The default root is its evidence node, depth is 2, record limit is 64 and
traversal budget is 1,000 ms. Edges retain their direction, while queries follow
both directions. The record limit counts nodes and edges together; endpoints
can be on another page. Continue with the same file, root, depth and limit.
Changing those inputs invalidates the cursor. A zero budget defers the query.
The time budget applies after bounded file loading and graph materialization.
JSON is returned with or without `/json`. Exit 0 means this query succeeded,
including when the retained evidence has gaps; 1 means unavailable input,
invalid cursor/node or deferred/cancelled traversal, and 2 means invalid grammar.
See [retained fact graph](ARCHITECTURE.md#retained-fact-graph).

For `.knsweep`, the same command first replays the original image policies and
returns `kn.image_sweep_graph.v1`. Its assessment connects to exact manifest,
reference, recipe, raw-archive and range-comparison evidence. Inspect the original
intervals and compared/changed/excluded/unreadable bytes; successful pagination
does not establish a complete sweep. It creates no execution, writer or
cross-bundle lifetime edges. Missing/corrupt declared inputs yield exit 1 without
a graph. Materialization is bounded to 256 nodes, 512 edges and 2 MiB of detail
JSON; `/budget-ms` begins after replay. See
[replayed image sweep graph](ARCHITECTURE.md#replayed-image-sweep-graph).

`KnLiveDbg.exe --offline !kmon dump-read <file.dmp> <hex-address> <length> /json`
reads 1..4,096 bytes through the shared observation source. Supported inputs are
AMD64 PAGE/DU64 full-dump physical runs with a qualified four/five-level root.
Addresses are hexadecimal; lengths are decimal unless explicitly prefixed.
`complete`, `partial`, `not_captured`, `not_present`, `read_failed` and
`unsupported` remain distinct. A nonpresent PTE does not prove that the process
has no virtual allocation. Sparse spans contain bytes only where captured.
The command exits 0 for a complete read, 1 for unavailable/partial/failed reads,
and 2 for invalid grammar. It opens no driver or symbol session.

Add `/receipts` (with or without `/json`) to return `kn.dump_read.v1`, containing
the virtual result, each page-table walk/recheck and the original physical
table/payload reads under one shared budget. This private evidence includes
failures and raw Win32 file status. It covers the requested range after source
opening; initialization probes are not included. Unknown dump CPU features leave
paging permissions null, and matching rechecks do not establish mapping lifetime
or execution. The existing command without `/receipts` keeps its original schema.

`KnLiveDbg.exe --offline !kmon verify-image <reference> <dump> <hex-base> <hex-rva> <length> <new-directory> /json`
captures one 1..4,096-byte executable comparison and its exact reference into a
new private directory. The dump must meet `dump-read` requirements. Base and RVA
are hexadecimal. Supply locally trusted reference files; parsing is not isolated.
The result's ownership and coverage determine the byte-comparison outcome;
`status=recorded` means the case was published, including when reads are partial.

`KnLiveDbg.exe --verify-process-image <pid> <creation-filetime> <reference> <hex-base> <hex-rva> <length> <new-directory> --allow-residency`
captures the same direct comparison from a live process into a v2 case. PID,
creation FILETIME and length are decimal; base and RVA are hexadecimal. The
supplied generation must match the opened handle, and the caller needs process
read/query access. `--allow-residency` is required because reads can affect page
residency. The command always emits `kn.image_capture.v2` JSON and opens no driver
or symbols. It records the original ordered read receipts, consent and Win32
status/copy counts. It supports one AMD64 direct-image range of 1..4,096 bytes,
with a legacy LA48 assumption and the OS user ceiling recorded explicitly.
It has no native fallback or background-monitor capture. Successful publication
may still report an unverified or modified range. Exit 3 means stdout delivery
failed; a case already published before that failure remains on disk.

`KnLiveDbg.exe --offline !kmon replay-image <directory> /json` reruns the recorded
policy against either v1 or v2's retained artifact and ordered raw reads. Add `/current` to
perform current reanalysis instead; both policy identifiers and the original
result remain visible. Missing/corrupt artifacts or unsupported original policy
fail explicitly. Loader exclusions, partial reads and conflicting rereads cannot
become completely verified bytes. No live target or original image path is needed.
Exit 0 means successful publication/replay, not that the image is clean; exit 1
means unavailable/failed work and exit 2 means invalid grammar. See
[exact reference replay](ARCHITECTURE.md#exact-image-reference-replay) for limits.
Successful replay also returns a `proof` object with two scoped match/difference
claims, unmet requirements, evidence references and separate coverage ledgers.
Failed replay returns `proof=null`. A supported comparison claim proves neither
execution nor maliciousness; see [image proof](ARCHITECTURE.md#claim-specific-image-proof).

`KnLiveDbg.exe --self-test capture-scheduler` runs the capture worker using owned
process memory and an absent kernel device. It emits JSON and exits 0 on success
or 1 on failure; extra arguments return 2. No driver is loaded. Runtime
`coverage.pipeline` events expose queue/service distributions through the
`capture_scheduling_json` evidence field. Quantiles are bucket upper bounds,
and urgency thresholds are not latency guarantees. See
[capture scheduling](ARCHITECTURE.md#capture-scheduling-and-latency).

Current-main KMON image comparisons preserve original read attempts for clean,
changed and inconclusive slices in private `image-reads/*.knreads` files. Finding/image
coverage fields `read_operation_id` and `read_set_queued_id` link to publication
events (`coverage.image_reads`); a queued ID alone does not mean the file was
written. Hunt JSON `image_read_store` and `coverage.pipeline` report bounded
queue/store loss. Inspect the final `.knreadledger` after stopping. V3 archives
also report exact reference capture and separate publication status in the
shared `image-references/*.knblob` store. A committed raw archive may still have
a failed or missing reference; check both statuses and the reference counters.
V3 also retains original slice/secondary-view inputs. The raw archive itself is
not accepted by `replay-image`. Eligible AMD64/PE64 slices publish a separate
`.knslice`; check recipe publication status and counters independently.

`KnLiveDbg.exe --offline !kmon replay-image ".\evidence\image-reads\reads-COLLECTION-ID.knslice" /json`
replays the original direct or secondary policy from the recorded reads and
shared reference blob. It returns `kn.image_slice_replay.v1` with the actual
policy and an executed-range `kn.image_slice_proof.v1`. Exit 0 includes faithfully
reproduced inconclusive results; it does not mean the whole image is clean.
Missing or contradictory inputs return exit 1 without successful proof. `/current`
is explicitly unavailable for slice recipes. A containing `.knsweep` supports
the graph command above; cross-bundle associations and native loaded-image
lifetime validation remain open. See
[original slice replay](ARCHITECTURE.md#original-kmon-slice-replay).

`KnLiveDbg.exe --offline !kmon replay-image ".\evidence\image-sweeps\sweep-COLLECTION-ID.knsweep" /json`
replays a temporal sweep manifest and its original slice recipes. The
`kn.image_sweep_replay.v1` envelope identifies the manifest separately from recipe
hashes. Inspect membership, comparison and whole-sweep completion independently:
exit 0 can reproduce an incomplete sweep with a missing head or unknown tail.
Missing/corrupt declared artifacts, conflicting target/range/time membership or
failed slice replay return exit 1 without proof. `/current` remains unavailable.
The match claim is limited to scheduled executable ranges and the recorded time
interval. See [sweep manifests](ARCHITECTURE.md#temporal-image-sweep-manifests).

`KnLiveDbg.exe --schema create <image> <pdb> <exact-type> <new-output>` exports a
private `.knschema` package from a matching local AMD64 PE/PDB and the packaged
DIA provider. Names are case-sensitive. It opens no live device and downloads no
symbols. PE/PDB/DIA parsing runs in a child with a restricted low-integrity
token, private desktop, allowlisted handles/environment, 512 MiB commit limit,
one-process job and 60-second parent timeout. Unsupported containment fails
without an in-process fallback. This is not a filesystem or network sandbox.
`KnLiveDbg.exe --schema inspect <package>` verifies the stored checksum and
bounded field relationships without loading DIA or requiring the original files.
Both return canonical `kn.type_schema.v1` JSON on success (exit 0); invalid input,
missing identity, unsafe paths, budget failure or output collisions exit 1.

The package hash identifies the canonical payload; it does not authenticate the
publisher. Fields have explicit path arrays, root-relative offsets, storage byte
widths, and separate bit widths. Embedded objects expand to a bounded depth;
pointers and arrays are retained as storage values. Gaps retain unsupported or
unavailable layout portions. No runtime field values or kernel-object validity
are claimed. See [schema contracts and limits](ARCHITECTURE.md#local-type-schema-packages).

## Session and memory

Current main starts with the native mutation gate off. Use `write on` explicitly
for an authorized lab change and `write off` afterward. The client requires the
matching driver with the default-write-denied capability flag. Returning from
MCP requests write-off; a failed transition is reported as an unknown write state.

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

Native write mode begins disabled. `write on` explicitly arms it after the
driver confirms the transition; `write off` disarms it. Address-only native
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

`!hiddenproc [/json <path>]` keeps discovery membership separate from a fresh
lifetime-bracketed kernel/SPI/Toolhelp comparison. Its additive
`lifetime-cross-view-v2` policy reports `cross_view_discrepancy`, `unverified`,
`auxiliary`, `terminating` or `reconciled`. Check `qualification.before/after`,
comparison completeness and `reason`; an unread lifecycle value is null there.
`eprocess_scope` distinguishes a qualified object from a discovery hint;
`discovery_eprocess` preserves the original address. Image labels are PID-based
discovery hints and are not an assertion about the confirmed lifetime.
Legacy `suspicious` counts admitted sampled discrepancies, not proven hiding or
actor attribution. SPI and Toolhelp have a shared process-list dependency.
Confirmation rotates a session-bound pending queue, attempting at most 128
candidates per scan with a cooperative five-second budget, excluding initial
discovery. The batch adapts to recent read costs and reserves fresh comparison
time. Failed attempts rotate; cancellation and connection changes preserve
unverified records. `scheduling` reports attempt/deferred counts and queue wait,
which does not measure successful revisits. Remaining candidates stay unverified;
zero suspicious records with incomplete coverage is not a clean bill of health.
The report contains private process evidence and must not be committed.

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

Native user evidence in hunt includes a bounded `native_observations` list under
`execution_evidence`. Each `kn.execution_evidence.v1` record identifies its X0
reference, X1 metadata or unqualified state. PSS/saved RIP, a thread start, a
queued APC and a raw stack value do not assert execution. CPU/code-version
fields remain null. KMON's legacy `process.execution` category carries the same
distinction in `execution_evidence_json`; it is a deduplicated reference stream.
For VAD findings, use `execution_reference_observed`, `wx_reference_observed`
and `permission_range_reference_observed` to inspect the existing correlations.
The old execution booleans remain false for these sources. This is not a trace
importer or a CPU execution/writer sensor.

KMON's `io.request_observation` events include `irp_observation_json`, a bounded
`kn.irp_observation.v1` report. It exposes the observed thread/request/stack
relations, optional cancel/pending/status fields and reference pointers, including
requests without a completion routine. Graph IDs apply only inside that event.
The final outcome stays unknown; addresses and flags do not establish a request
lifetime, a completed/cancelled operation or a deadlock. The normal KMON event
query and JSON log expose these records; routine snapshots do not print live.

Normalized external samples can be inspected without a live target:

```text
KnLiveDbg.exe --offline !kmon trace capture.kntrace /limit 64 /json
KnLiveDbg.exe --offline !kmon trace capture.kntrace /limit 64 /cursor <next_cursor> /json
```

The [trace input contract](TRACE_IMPORT.md) defines required identity, clock,
code-version and loss fields. The importer accepts normalized JSON, not raw
PT/ETL/TTD buffers. Its qualified reported level remains a producer claim;
neither parsing nor a code hash authenticates actual execution. Changed input or
page limits invalidate the cursor. Error exit 1 returns an unavailable result;
invalid command arguments exit 2.

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

Routed image collection exposes its retention class in `coverage.image_reads`.
The hunt JSON `image_read_store.retention`, pipeline `image_retention` evidence
and final `.knreadledger` report separate first-difference, observation-gap and
repeat/clean budgets and outcomes. These fixed session budgets require no new
command option. See [admission, retry and byte-accounting semantics](ARCHITECTURE.md#image-retention-priority).

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

Name/PID watches prioritize activity. Starting without either filter latches
full-process layout discovery; adding watches afterwards does not narrow that
scope. Watched reference metadata also rotates independently of deep image
scans. This is still bounded work; every image, page and reference need not
finish within a single run.

- [Coverage](KMON_DETECTION_COVERAGE.md): supported paths and blind spots.
- [Verification](KMON_DETECTION_VERIFICATION.md): image identity, relocations,
  captures, compared/failed/excluded bytes and traversal progress.
- [Process layouts](KMON_PROCESS_LAYOUTS.md): initial/current maps and changes.
- [Analyst surfaces](KMON_ANALYST_SURFACES.md): TLS, KCT, WorkerFactory, scoped cases,
  retained evidence, offline replay and saved diffs.
- [Cross-domain hunting](KMON_CROSS_DOMAIN_HUNTING.md): relationships and replay.
- [Fixture guide](KMON_TEST_TARGET.md): six-control reference checks, 13-control
  image load and real-vctip validation.

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
