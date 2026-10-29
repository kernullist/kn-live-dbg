# Architecture

## Observation address contract

`AddressSpaceDescriptor` separates x64 canonicality from an optional OS user
ceiling/kernel floor and actual mapping validity. The main driver's ABI version
response supplies the active four/five-level paging mode. An unopened, failed
version query or closed `DeviceClient` has an unavailable descriptor; the native
path does not silently select LA48. Physical address width remains unknown until
a source supplies it.

Hunting admission, executable-page scheduling, selected hunting readers and the
pending-IRP parser use this descriptor. KMON receipts carry it through `.kncase`
publication and offline replay. Legacy v1 receipts without `address_space` use
an explicit `legacy_assumed=true`, LA48 compatibility contract. Parsing still
checks exact canonical serialization and checksums for each supported form;
unknown widths, malformed descriptors and noncanonical spans are rejected.
New files include the additive descriptor and require the updated reader.
Importing a legacy file does not rewrite it; exporting it with the new metadata
produces a different content hash.

These changes do not establish a system-wide LA57 support claim. Other scanners,
source/VM/epoch identity, translation permissions and actual LA57 Windows
compatibility remain separate acceptance work in [W02](FEATURE_PLAN.md#kernel-investigation-platform).

## Comparison coverage

`ObservationCoverage::Complete()` requires a bounded, valid union of compared
intervals equal to both the declared requested byte count and the comparison
counter. Duplicate visits cannot substitute for unvisited bytes. Truncated range
lists, failure/skip intervals, event loss and incomplete traversal prevent a
complete result. `CompleteFor(requestedRanges)` additionally requires equality
with the exact requested address union; the image verifier uses that check before
promoting an unchanged page to `OwnedVerified`. Neither result proves execution,
collector authenticity or whole-system coverage.

Range accumulation coalesces overlaps and out-of-order intervals within the
existing 256-range limit, rejecting overflow without altering retained ranges.
The v1 evidence format preserves original counters and ranges. Replay reports
`original_comparison_coverage` with the recomputed unique byte count and states
that the exact requested address denominator is unavailable in that format.
It does not rewrite historical counters or claim to replay image verification.
Discovery, temporal, semantic, persistence and trust coverage still need separate
ledgers and proof requirements; unique byte accounting alone does not finish W05.

## Bounded observation sources

`IObservationSource` admits at most 4096 bytes per primitive read. Requests bind
to a source ID, address descriptor, byte budget, cancellation token and explicit
residency-change policy. Results retain contiguous sparse spans, timing in the
collector steady-clock domain, consistency scope and possible side effects.
Missing capture, read failure, skipped work, conflicting bytes, policy denial,
identity change, unsupported requests and budget deferral remain distinct.
Only complete reads can enter the existing byte-vector parser adapter. Gaps are
never filled with zeroes. Cancellation is checked before and after a synchronous
read; it does not interrupt an IOCTL already in progress.

`NativeObservationSource` binds a kernel virtual-memory reader to a collector
process creation time and device-open epoch, checks the paging descriptor around
each read, and preserves short reads. This detects connection replacement; it is
not a kernel-object lifetime proof, a boot/VM identity or an atomic snapshot.
The caller still owns the device and serializes its lifecycle with scan work.
Original native status is marked unavailable because the existing DeviceClient
API does not expose it. Pending-IRP parsing uses bounded chunks up to its existing
128 KiB total limit and retains its repeated-read comparison. The kernel virtual
branches of execution-reference parsing use the same interface. Physical-page
and user-process fallbacks retain their existing collectors.

`BundleObservationSource` owns an immutable copy of a validated v1 bundle and
binds its ID to the canonical payload hash, including identity and captured bytes.
Replay uses this source with the existing code-target parser. Conflicting valid
bytes remain conflicts regardless of read order; failed and skipped spans never
override captured bytes. The hash establishes content identity, not acquisition
authenticity. New timing fields measure replay access, not original capture time.

Native virtual reads can change residency, as described by
[MmCopyMemory](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-mmcopymemory).
Migrated collectors explicitly opt in to preserve their prior behavior. This
does not implement the separate driver-enforced observe/collect policy. Dump,
DbgEng, user-process and translation adapters, operation-wide deadlines and
identity revalidation remain open work. The evidence harness exercises the same
target parser on owned current-process memory and stored bytes, alongside sparse,
conflict, budget, cancellation, source-change and multi-chunk failure controls;
that test does not validate a live kernel target.

This describes main at the [documented source revision](README.md), including
changes after v0.0.36. For operator syntax use
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
| `EvidenceBundle.*`, `EvidenceInvestigation.*`, `AnalystSnapshot.*` | Durable reference read sets, bounded offline queries/replay and saved analyst views |
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
per-handle write mode and their acknowledgment fields. New handles on current
main start with writes disabled. The version reply advertises
`KNDBG_VERSION_FLAG_DEFAULT_WRITE_DENIED`; the updated client rejects older
drivers without that flag even when their structure ABI is still 17. Keep the
EXE and SYS together. Explicit `write on` retains the lab mutation workflow.
The shared ACK value is a protocol check, not authentication against an
administrator who already owns the controller session.

Write-mode transitions validate the returned request and then read session status
to confirm the requested gate and controller identity. MCP does not dispatch jobs
after an unconfirmed transition, and leaving MCP requests write-off instead of
automatically arming the REPL. A failed remote-console write-off stops that engine
without publishing a false write-off status. Failure can leave the actual gate
unknown; the error says so. These controls do not split observation from event
collection, constrain every user-mode/DbgEng action, or provide protected remote
transport. Four operating modes and narrower collection rights remain W14 work.

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

Watched reference metadata has its own rotation between deep scans. Each visit
qualifies the retained process handle against the current watch conditions;
implicit child watches require the stored creation time. This avoids inheriting
a stale watch when a PID is reused. Reference verification runs before and after
event ingestion, with a larger bounded budget under queue pressure. IAT walks
yield between descriptors/thunks so a long walk can service waiting work.

TI and live-event collection limit each source read to available analysis queue
space. Full queues retain the upstream cursor; actual source overwrite remains
loss. Shutdown joins the collectors, freezes source tails, and drains through
those boundaries within the event-processing budget. A TI generation change
cannot satisfy the frozen tail. Unprocessed source spans remain visible in
`shutdown_events_unanalyzed`. See the [verification contracts](KMON_DETECTION_VERIFICATION.md)
for budgets, counters and limits; a drained queue does not mean complete image
or callback coverage.

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
[retained investigation path](FEATURE_PLAN.md#retained-investigation-path) separates
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
itself a durable store; emitted receipt JSON remains subject to log collection loss.
`EvidenceBundle` provides the durable boundary:
one private `.kncase` file contains a receipt, acquisition domain, original
coverage, capture interval, and up to 128 sparse read spans of at most 4 KiB each.
The canonical `kmon.bundle.v1` envelope hashes the payload and each raw span;
imports reject inconsistent metadata, damaged bytes and unknown fields. A failed
or skipped span remains an explicit hole. Publication reuses the create-new,
flush and handle-rename path, preserving existing files and excluding pending
files from readers. Confirmed KMON references enter a separate 64-item queue
consumed fairly with raw pages by the existing capture writer. The writer admits
up to 128 MiB of bundles per session, reports rejected/failed publications and
drains admitted work at normal shutdown. A private `.knledger` records closure
and publication accounting; a missing ledger leaves closure unknown.
`evidence` queries bounded file inventories before limiting matching results.
An explicit `inventory` export creates a new immutable membership snapshot of
v1 publications. It streams at most 1,048,576 directory entries and 8 GiB of
source reads within a 120-second cooperative deadline. Each 128-member chunk
records bounded basenames, validated content digests, byte lengths and invalid
members. Content-addressed `.knchunk` files precede atomic publication of
`manifest.knindex`; incomplete builds have no readable final manifest. Chunk
and manifest hashes detect damage, not a malicious collector. Source directory
identity is bound using its volume/file ID, and final reparse points are rejected.
Directory enumeration itself is non-atomic. Interrupted construction must be
restarted in a new output directory; no build-resume claim is made.

With `/inventory`, a query verifies the manifest and consumes at most 4,096
members and 64 MiB of source bytes per window. Metadata reads are separately
bounded by a 2 MiB manifest and 256 KiB chunks. Each source file is reopened and
matched against its recorded content and length. A single-entry parse cache
reuses only exactly equal decoded input after the read, never a pathname alone.
Missing or changed members remain gaps; new files do not alter membership.
`next_cursor` pages results in the same window; only after those results drain
does `next_inventory_cursor` advance the inventory. Cursors bind the snapshot,
query/filter and budgets; a result cursor also binds current-window validity.
Counts and deduplication apply to the current window. Global publication closure
is evaluated only when one window covers the entire snapshot. The legacy query
without `/inventory` retains its original bounded-directory contract.
The `--offline !kmon` entry point runs these file commands before elevation,
driver service or symbol initialization.
`replay` and `why` reconstruct supported static transfers using the original byte
reader, report missing/conflicting spans and verify stored page digests. They do
not reopen a target process, authenticate the collector, redo image normalization
without its reference inputs, or turn static observations into execution claims.
See [coverage](KMON_DETECTION_COVERAGE.md), [verification](KMON_DETECTION_VERIFICATION.md),
[analyst surfaces](KMON_ANALYST_SURFACES.md), and
[process layouts](KMON_PROCESS_LAYOUTS.md).

## PDB identity boundary

Before DIA supplies type data, `SymbolEngine` binds the load to an expected PDB
signature and age from matched DbgHelp module metadata. Unmatched PDB/DBG flags,
different module bases and conflicting known image sizes are rejected. When that
identity is unavailable, the existing PE reader extracts CodeView identity from
the resolved image and checks the known size/timestamp/checksum constraints;
the file identity is checked again after symbol loading.

Direct PDB loads use Microsoft's
[signature-and-age validation API](https://learn.microsoft.com/en-us/visualstudio/debugger/debug-interface-access/idiadatasource-loadandvalidatedatafrompdb?view=visualstudio),
then independently compare the opened session's identity. Image-based DIA loads
also receive the post-load comparison. A missing property is unavailable, not a
zero-valued match. A rejected selected PDB does not become an unchecked fallback
load on the same data-source object. Existing qualified layout caching and the
DbgHelp/DIA serialization lock remain in place.

GUID/age matching prevents ordinary wrong-build and replaced-cache confusion;
it is not a content hash, an approved distribution signature or collector
authentication. Full loaded-image identity binding, isolated untrusted parsing
and symbol acquisition deadlines remain separate work.
`tools/validate-pdb-identity.ps1 -Sanitize` compiles two owned PE/PDB pairs and
checks the actual DIA provider against matching, wrong-age, wrong-PDB and cache
replacement controls without loading a driver or target image.

### Local type schema packages

`--schema create <image> <pdb> <exact-type> <new-output>` exports one AMD64 UDT
as private `kn.type_schema.v1` JSON, normally a `.knschema` file. The operation
runs before controller construction and uses only the supplied local artifacts
and the packaged DIA DLL. It performs no symbol download or live memory read.
`--schema inspect <package>` checks and reconstructs the package without DIA.
Existing successful layout caches and the DbgHelp lock remain in use.

The package records PE/PDB/provider SHA-256, PE machine and image size, canonical
PDB GUID (32 hexadecimal digits) and age, provider file version, root size and
explicit field path arrays. Offsets are bytes from the root; storage sizes are
bytes, while bit positions and widths are bits. Symbol tags and base-type codes
use the DIA contract. Ordinary members have zero bit width. Embedded UDT fields
can expand to eight path components; pointer values and array storage are leaves.
Base classes, unsupported field types and depth limits remain explicit gaps.
Unavailable member properties create a gap on their containing path. Bounds
cover each field's root and embedded parent; unions may intentionally overlap.

`DiaTypeLayout` also serves the existing DIA fallback. It requires `S_OK` for
offset/size properties and uses `LocIsBitField` to distinguish units. Previously,
`SUCCEEDED(get_bitPosition(...))` treated an unavailable `S_FALSE` property as a
bitfield at bit zero. Actual compiler-generated PDB controls reproduce that case
and compare the corrected offsets, storage and bit widths with C++ layout.

Generation holds read-only, no-write/no-delete leases on local regular files,
rejects final reparse points and device/stream paths, and rechecks identities and
content after parsing. Limits are 512 MiB PE, 1 GiB PDB, 64 MiB provider, 8,192
direct DIA data members, 4,096 package fields/gaps, 16 MiB root/type extent and
2 MiB serialized output. Hashing and recursive traversal check cooperative
30-second budgets; an individual synchronous I/O or DIA call is not interruptible.
The existing create-new, flush-and-rename writer preserves output collisions.
Inspection accepts only canonical versioned JSON with its payload SHA-256 and
valid path/extent/expansion relationships; a self-consistent hash is not approval.

These are layout packages, not runtime object validation or authenticated symbol
distribution. Their contract explicitly records `parser_isolated=false`,
`runtime_invariants_checked=false` and `trusted_distribution=false`. Generation
still runs DIA in the offline command process, so only locally trusted artifacts
should be supplied until the isolated broker is implemented. Attaching package
hashes to every typed observation, supported-build fixture attestations and
broker isolation remain open. Files and renamed JSON packages are excluded from
public source publication by the repository's sensitive-content gate.

## Capture scheduling and latency

The capture worker preserves its bounded first/continuation queues and the
four-page kernel quantum. It now chooses between queue classes using oldest
queue wait and urgency thresholds of 250 ms for first capture and 1,000 ms for
continuations. A more overdue continuation can borrow an earlier turn. While
both queues are pending, first captures get at most eight consecutive dispatches
and continuations at most one. These are dispatch bounds; a kernel dispatch can
retain its existing four-page quantum. FIFO order within each queue remains.
The thresholds are initial scheduling policy, not measured SLOs or hard
deadlines, and should be evaluated against the intended workload.

Each continuation updates its queue-admission time while retaining the original
request time. `coverage.pipeline` carries `capture_scheduling_json`, a JSON
string with schema `kn.capture_scheduling.v1`. It reports pending counts,
capacity saturation, oldest queue wait and oldest request age separately.
Saturation refers only to the first/continuation request queues, not the writer
queue or the coverage of the whole pipeline.
Dispatched first/continuation queue waits, first-attempt age, and page-service
duration have sample counts, exact maxima and log2-bucket P50/P95/P99 upper
bounds. Service includes identity/protection checks and capture admission;
it is not just the memory-copy API duration. Failed attempts remain in the
normal service sample population. Acquisition uses `GetTickCount64` and does
not subtract unrelated event wall-clock timestamps.

Dispatches and attempts started during shutdown have separate counters and do
not enter normal latency distributions. Invalid clock order is reported instead
of underflowing an age. Immediate pages within the kernel quantum are service
attempts but are not extra queue dispatches. The worker still cannot preempt a
synchronous kernel/file call, and no real six/thirteen-control or environment
latency target has been validated by the synthetic scheduler tests.

`--self-test capture-scheduler` runs the actual capture worker against owned
user memory, including guard/no-access pages, and an explicitly absent device.
It verifies queue/service accounting, shutdown separation and preservation of
the kernel quantum without loading a driver. The core ASan harness additionally
checks percentile bounds, concurrency, fixed cohorts and sustained churn.
Image/reference/layout scheduling and generic deadline/dependency propagation
remain separate work.

## Exact image reference replay

`--offline !kmon verify-image` now connects the dump observation source to the
existing executable verifier and a private image case. Each case retains the
complete reference PE as `<sha256>.knblob`, then atomically publishes
`recipe.knverify` last. Original file identity/path and capture time remain
provenance; replay opens only the retained content-addressed artifact. Both
files are private local evidence, not public source inputs.

The `kn.image_recipe.v1` payload records the policy version, source identity and
address width, requested image base/RVA/range, ordered read results, sparse raw
spans, clock intervals and the original comparison. Its normalization record
preserves PE/PDB identity, section RVA/file mapping, relocation basis and
overlapping relocations, loader/dynamic exclusions and declared REL32 targets.
The reference artifact supplies the original bytes for all those inputs.
Before and after comparison, mapped PE/PDB identity must qualify and the header
base must remain equal. Missing, unstable, excluded and compared bytes keep
separate coverage; excluded bytes cannot produce a fully verified result.
Every retained byte span must belong to the declared address width, source and
consistency model, including bytes inside a partially available read.

Default `replay-image` uses the recorded policy only when this binary implements
that version. It verifies the artifact hash, recomputes normalization, consumes
the exact original sequence of read requests/results, reruns the verifier and
compares the complete result with the stored one. Missing reference, corrupted
artifact, unavailable policy, changed normalization, read-set mismatch and
result mismatch have distinct failure states. An old stored verdict is never a
substitute for a missing artifact. Future semantic changes to the direct verifier
or reference parser must introduce a new policy version or retain the old engine.

`replay-image /current` explicitly selects current reanalysis. It reports both
policy identifiers and retains the original result separately. Its reader can
combine available recorded spans but rejects contradictory repeated bytes and
overlapping unavailable/cancelled observations. These rereads are historical
data accesses, not new kernel observations. Neither mode proves execution,
collector authenticity, signer approval or an approved original distribution.
Hotpatch epoch is explicitly unavailable.

This path supports AMD64 direct mapping relocation bases and one range of
1..4,096 bytes. A third header relocation base remains unqualified; the live
sweep's independently qualified secondary image view is not silently reproduced
by this recipe version. Limits are 64 MiB reference, 64 ordered reads and 128 KiB
requested read bytes, with a 2 MiB recipe. File reads check a cooperative 30-second
budget; synchronous I/O and PE parsing have no hard cancellation deadline.
Native monitor publication, secondary-view recipes, signed reference distribution
and isolated parsing remain open. Existing `.kncase` replay still reports
`image_verification_replayed=false`; it does not implicitly discover these cases.

Capture requires a new directory and never replaces existing output. A failed
or interrupted capture can leave an unreferenced blob or temporary file, but no
valid final recipe; callers treat the missing final marker as incomplete. Case
directories currently have explicit/manual retention and no automatic expiry or
cross-case deduplication. Use locally trusted reference files until parser
isolation is available.

### Claim-specific image proof

Successful `replay-image` adds a `kn.image_proof.v1` report generated from the
fresh typed verifier result. It does not authorize a claim from the saved
ownership label alone. The proof policy is versioned separately as
`kn.image_proof.direct.v1`; adding the report does not change the recorded
comparison recipe or its original-policy result.

Two scoped claims are implemented. `recorded_range_matches_reference_policy`
requires qualified mapped identity, the direct normalization basis, complete
unique coverage of the requested addresses, actual comparison bytes and a
matching retained read. `recorded_range_differs_reference_policy` requires
validated difference bytes inside compared ranges and at least two distinct
recorded reads that confirm the compared bytes. Its output ranges are absolute
addresses; the verifier's stored change ranges are RVAs. Excluded bytes remain
outside the claim, even when other bytes support a difference. Each claim emits
`supports`, `contradicts`, `unfulfilled_requirements` and
`next_best_observation`, with recipe-hash/read-index evidence references.

The report keeps seven ledgers separate:

| Ledger | Meaning in this implementation |
| --- | --- |
| Discovery | The explicitly requested range; no complete image inventory |
| Address | Unique compared/skipped/failed/unvisited bytes within that range; contradictory or out-of-range accounting is invalid |
| Temporal | Original collector read intervals; no target execution time or continuous target coverage |
| Semantic | Qualified mapped identity and the supported direct comparison policy; hotpatch epoch and full function equivalence remain unproved |
| Persistence | Verified retained artifact, requested read bytes, retained bytes including repeats, and unique retained target bytes; not a full source snapshot |
| Replay | Original result reproduction or explicitly selected current reanalysis, with both policy identifiers |
| Trust | Unauthenticated local evidence; no approved distribution or established security domain |

Failed replay emits `proof=null`. A supported byte-range claim does not prove
execution, writer identity, maliciousness, authorization of a change, whole-image
integrity or continuous observation. These limits apply equally to current
reanalysis; rereading the saved source cannot create another target observation.
This is a selected image proof path. Generic cross-view, object-lifetime,
deadlock, writer-attribution and live temporal policies remain separate work.

## Offline dump observation source

`DumpObservationSource` and the existing dump analyzer share one qualified
LA48/LA57 translation implementation, including 4 KiB, 2 MiB and 1 GiB leaves.
The new offline source validates AMD64 full-dump run counts, physical bounds,
overlap, declared page counts and file extents before admitting reads. It holds
one disk-file handle with writes/deletes denied, rejects final reparse points
and device namespace paths, and serializes file-position operations. Its source
ID identifies the open connection; it is not a durable artifact hash or a trusted
capture identity. File metadata checks cannot authenticate the original memory.

CR4 evidence or a unique reciprocal module-list probe selects the paging depth.
Contradictions and ambiguous/missing evidence fail the new source open. The
existing descriptive analyzer retains its legacy warning-bearing inference.
Payload reads use the common 4 KiB admission/budget/cancellation contract;
page-table metadata is additional bounded work, at most five entries per page
and two pages per primitive read. Synchronous file I/O has no immediate deadline
cancellation guarantee. Missing captured table/data pages, nonpresent PTEs,
unsupported entries and file I/O failures retain different states. A source
change discards all bytes collected in that primitive. Integer and Unicode
parsers consume only complete declared reads through the same interface.

`--offline !kmon dump-read` exposes `kn.observation_read.v1` with sparse bytes,
address width, source and timing. Its output is private capture data; the
publication scanner rejects it even after renaming. The source uses the dump's
declared root only, does not synthesize uncaptured pages and does not establish
live execution, VTL1 access or support for bitmap/triage/minidump formats.
Read ticks describe this collector's file access, not the target's execution time.

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
