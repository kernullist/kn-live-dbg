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

## Runtime source capability probes

The selected source/address contracts in [the generated support matrix](SUPPORT_MATRIX.md)
come from the same `--capabilities` JSON used by clients. The default mode still
opens no device. An explicit `--capabilities --probe` reads a 32-byte known range
in its own process through the owned `ProcessObservationSource`, then attempts
the default existing native device's open, ABI and session-status queries. It
does not create/start services, load a driver, enable collection, change write
mode or fetch symbols. Another controller or a differently named cloaked device
can leave the default device unavailable; this does not imply host-wide absence.

The owned range uses an explicit legacy LA48 shape and does not detect active
paging. Only a successful native version query supplies the native 48/57-bit
descriptor in the probe. Source open, sample read, layout, semantic validation
and environment regression remain separate stages. A successful process probe
marks availability for its control range only; native connection checks are at
most `partial`. Unsupported VTL1/VMI stays unsupported, other backends stay
unprobed, and no result grants a validated OS/CPU/security-state combination.
Handles close before publication; this is a timestamped observation, not a lease
for subsequent commands. The connection/status queries used by this probe do
not expose raw NTSTATUS; it preserves their explanation without inventing one.
`native_read_observation_contract` reports the optional read feature flag only
after a valid version reply; it does not perform or validate a native read.
Runtime reports contain
identity/address evidence and are rejected by the public-content scanner.

The standalone `--capabilities --probe-etl <file> --sha256 <digest>` path
runs the two saved ETL record decoders on one traversal. It holds the file
and its parent directories through the Windows ETW read, checks the file
identity and hashes the retained handle again before using the counts. The
probe reports the SHA-256 measured at open. `source_revalidated` records the
result of the final check and is null if the scan never reached it.

Only the `execution/cpu_profile/etl` and `execution/context_switch/etl` rows
carry `record_evidence`. Their ordinals refer to the same traversal. For each
family with a supported layout, the callback copies its first complete payload
into a fixed 24-byte buffer. The report includes its length and SHA-256. Each
family qualifies its own sampled payload and recognized layout. Unsupported
layouts and absent families stay visible. Buffer count discrepancies, unknown
buffer accounting and reported loss limit both availability claims to
`partial`. The other rows remain unprobed. Process and driver probing require
the separate live invocation. The private saved report records
`target_probed=false` and leaves platform regression and event semantics open.

The standalone `--capabilities --probe-dump` uses one read-only handle to a
local AMD64 full dump. It leases the parent directories and rejects reparse
points and files marked offline or recall-on-access before reading data. It verifies the SHA-256 of the complete 8,192-byte
header before interpreting the physical runs or following a list pointer.
`kn.dump_capability_probe.v1` carries the original initialization receipts
and the paging depth selected from the saved evidence. A mismatch stops after
the header read. The cost of pinning is independent of file size.

The `memory/read_virtual/dump` row describes one subsequent typed read of
1–4,096 bytes. It reports each page walk, sparse span offsets and digests,
physical-read charges and any underlying Win32 read failures. The reader
checks the open file identity again after the sample. A complete sample can
be compared with a caller-supplied digest. In default mode the second read
must also reproduce the 16-byte list head whose forward and backward links
were checked at initialization. When saved context independently qualifies
the paging depth, missing neighbors leave a fully read head inconclusive and
contradictory links fail the check. If depth qualification fails, sampling
stops at initialization. A caller-selected range leaves semantic validation
unprobed. The private report retains `target_probed=false`.
Dump producer authenticity, CPU access permissions and platform regression
require independent evidence.

The owned read also publishes a `process_read_set` from the shared recorder
described below. Its single receipt is the same observation as `process_read`;
the probe does not reread the control range to construct evidence.

`tools/generate-support-matrix.py --exe x64/Release/KnLiveDbg.exe --check`
detects documentation drift without probing a target. The compiled inventory
exposes `probe_contracts` with each standalone invocation, availability scope
and observation. Each operation's `probe_contract` names its entry or is null.
Help, saved-file dispatch and capability qualification share these definitions.
The two live entries use the same invocation. The native entry covers an
existing device connection and its ABI and session queries. An unsupported
operation receives no probe contract or observed source stage. Restricted
observe mode still identifies the launch policy that excluded its native backend.

The generator publishes the catalog and per-operation bindings from unprobed
compiled JSON. It rejects inconsistent or private stage data, dangling
references and duplicate JSON keys before replacing the Markdown output.
Older inventories without a catalog still produce their address and backend
rows with the missing catalog identified.

## Ordered read receipts and operation budgets

`RecordingObservationSource` wraps `IObservationSource` without changing the
4 KiB admission or parser all-or-none contract. A scope begins before admission
and completes for success, sparse reads and every returned admission failure.
Receipt IDs reserve attempt order; concurrent completions may arrive in another
order. Snapshots expose pending, abandoned and unrecorded attempts separately.
Exceptions propagate and mark the reserved receipt abandoned. Failure to reserve
recording capacity prevents source invocation and leaves an explicit gap count.

All wrapped sources in one `ObservationReadOperation` share requested-byte,
source-call, receipt-count, stored-span and elapsed-time limits. Failed delegated
calls consume quota; fresh per-read budgets do not replenish it. Sparse metadata
reserves its worst-case span count before delegation and refunds unused slots
after completion. The elapsed interval includes time between reads, including
parser and queue delays, but does not measure those costs separately. Cancellation
and deadlines are cooperative: an in-flight synchronous call can overrun; its
original bytes/status remain in evidence, later calls stop, and cancellation or
an observed deadline overrun prevents parser consumption. These are delegated
source-call counts, not underlying device or disk I/O counts.

Each receipt retains the request, admitted source/address descriptor, validated
sparse spans, raw status domain/code and source-validation reason. Malformed or
identity-changed bytes are withheld while the original status remains available.
An explicit fallback link must identify a completed failed/partial/unavailable
read of the same range and address domain on another source, with a reason and permission. Cancelled,
identity-changed, policy-denied and budget-deferred reads cannot authorize fallback.
The next source still passes its own admission and residency consent. Receipts
remain separate; their bytes are not combined into an atomic snapshot.

The recorder owns shared operation state. Callers retain source objects and must
serialize source close/replacement with use according to each adapter's contract.
Operation bookkeeping is thread safe; that does not make an arbitrary adapter
concurrent. Target/address-space labels are caller-declared, not independently
qualified by the recorder. `kn.read_set.v1` is private observation JSON, not an
authenticated or durable publication format. Production consumers include the
owned-process capability probe, optional dump read receipts, the live image CLI
and KMON image comparisons below. Other scanner/fallback migration, native typed
translation and durable replay remain P02/P03 work. Native read status
transport is described below; existing direct `DeviceClient` collectors still
require migration to the observation/recording path.

`ObservationReadRouter` binds each serialized parser request to its primary
receipt and the receipt actually selected. An explicitly enabled fallback gets
the same operation budget, range, address descriptor and user/kernel policy;
it keeps its own source ID, consent and raw result. The parser receives only a
complete single-source result. A rejected mapping/identity guard, cancellation
or a deadline reached during a guard leaves the raw result intact and denies
parser input. Source initialization and guard internals are not byte receipts;
guard status does not establish an atomic mapping snapshot.

KMON's initial user/kernel image comparisons and background image continuations
use this router, including handle-to-native fallback. A slice shares limits of
16 MiB requested bytes, 4,096 source calls/receipts, 65,536 spans and five seconds;
the existing 25 ms sweep yield remains cooperative. Clean, changed and inconclusive
slices queue their original attempts and parser selections as `kn.image_reads.v3`
under `image-reads/reads-<collection>-<id>.knreads`. The private payload has a
SHA-256 integrity hash, not collector authentication. The writer uses create-new
atomic publication, with eight admitted/in-flight items, 2 MiB per file and
128 MiB of raw files per session, partitioned by the
[retention policy](#image-retention-priority). Overflow is counted, never
silently replaced by a fresh target read.
`coverage.image_reads` reports publication; `coverage.pipeline` and the hunt
JSON `image_read_store` report counts. A final `.knreadledger` records queued,
written, failed, dropped and pending totals after producer/writer drain. Live
snapshots are not final ledgers. These counters do not alter `.kncase` inventory.

The sweep pins its reference before the first target read. Retention reopens
that exact file object with an independent read pointer, captures up to 64 MiB,
and rechecks its bytes before releasing the lease. Queued snapshots keep the
bytes and original file identity, not a handle that would pin the source file
until publication. The writer publishes or verifies
`image-references/<sha256>.knblob` before committing the referring archive. It
holds a write/delete exclusion lease on the verified blob through that commit.
Existing content must match both hash and bytes; a corrupt blob is never replaced.
The hash is content identity, not an approved reference or collector identity.

New reference blobs have a separate 192 MiB session limit (64 MiB per retention
class); reuse of a verified blob is allowed at its class limit. Admission reserves
up to 64 MiB of reference bytes per class, conservatively charging each queued or
in-flight item even when snapshots share storage. The aggregate reference-memory
charge is at most 192 MiB, allowing every class to hold one largest supported
reference. This is not a total process-memory bound. Capture and publication status,
created/reused/failed/missing counts, new bytes and outstanding reservations stay
separate from raw archive counts. A missing or failed reference does not discard
the raw reads or imply replay readiness. Acquisition/rechecks and existing-blob
verification still read full file contents per slice; caching and reference-stage
latency budgets remain P09 work. The 25 ms yield is not an end-to-end deadline.

V3 raw archives also retain the executed slice schedule and original local
secondary-view reads, including incomplete inputs that cannot form a recipe.
Raw archive publication alone does not establish successful policy replay.
Single-source v2 recipe validation remains strict; routed fallback sets cannot
be substituted into it.

## Image retention priority

KMON routed image publication uses `kn.image_retention_partition.v1`. A first
observed byte difference is a retention candidate, not a maliciousness claim.
Three independent admission lanes keep routine traffic from consuming the
capacity reserved for that candidate or for an observation gap:

| Class | Admitted/in-flight slots | Reference memory | New raw files | New reference blobs | New recipes |
| --- | ---: | ---: | ---: | ---: | ---: |
| `first_difference` | 4 | 64 MiB | 64 MiB | 64 MiB | 64 MiB |
| `observation_gap` | 2 | 64 MiB | 32 MiB | 64 MiB | 32 MiB |
| `repeat_or_clean` | 2 | 64 MiB | 32 MiB | 64 MiB | 32 MiB |

The writer visits nonempty lanes in round-robin order and preserves FIFO order
inside each lane. Admission does not evict an already queued original. Slots and
reference charges remain owned until the final item owner releases them, even
after a dequeue. A class cannot borrow another class's budget. Successful new
physical publications consume their class/stream bytes; verified reference reuse
does not. These are accounting limits, not filesystem space reservations or
hard latency guarantees.

First-difference keys bind exact observed/expected page hashes, reference hash,
RVA/base and relocation basis, route/source IDs, identity assertions and the
collector's image-work episode. There are at most 8,192 keys per recording session
and 256 per read set. Unknown identity or fingerprint failure retains first
priority without a reusable key. A key-capacity refusal is counted explicitly;
it does not silently classify a new difference as routine. These keys neither
prove an atomic mapping lifetime nor join evidence across sessions.

A pending duplicate uses ordinary capacity. A saved key is earned only after
the original read file, required reference and recipe all publish and the
corresponding journal batch commits. A partial batch does not earn that key.
After all unsuccessful pending attempts release their reservations, the next
attempt can use first priority again. Reference requalification or a new
collector image-work episode starts distinct keys. Retention keys are not a
persistent cache: restarting a collection starts new priority accounting.

Unrecorded or rejected parser reads, cancelled/deadline-limited read sets,
missing/unstable references, ineligible recipes and unverified page results use
the gap lane when they do not contain a new difference. Raw originals remain
useful when a reference or recipe cannot be retained. The archive records its
retention class and episode; `coverage.image_reads` exposes the class. Live hunt
and pipeline summaries and the final protected `.knreadledger` include
`kn.image_retention.v1`: per-class attempts, admission refusals, abandoned/finished/
complete outcomes, high-water/in-flight counts and each stream's named bytes.
The final ledger is published outside those data budgets, so exhausted or dropped
work stays in its denominator. Filesystem or closure failure is still reported;
the policy does not reserve physical disk space or guarantee crash-time closure.

This policy applies to the routed image pipeline. Committed artifact protection
continues to come from journal membership and the store's GC rules. Priority
admission for other evidence families, cross-session retention, other-family transfer/redaction
privacy controls and committed-root retirement remain separate P06 requirements.

## Original KMON slice replay

Eligible AMD64/PE64 slices publish a separate `.knslice` beside the raw archive.
`kn.image_slice.v1` records `kn.executable_slice.direct.v1`; `kn.image_slice.v2`
records `kn.executable_slice.secondary.v1`. Both preserve the exact reference
hash, original routed target reads, executed range schedule, previous relocation
basis, per-range normalization and original typed results. Clean ranges are
retained along with changed and inconclusive ranges.

Secondary policy records the original owned `SEC_IMAGE_NO_EXECUTE` view's reads,
mapping-open outcome and selected relocation basis. Those reads use a distinct
source/address space with a 4 MiB, 1,024-call/receipt, 65,536-span, five-second
budget, separate from the target's 16 MiB/4,096-call budget. They do not form an
atomic snapshot with the target. Replay consumes recorded parser selections in
their original order, including failed attempts and explicit fallback links. It
does not read the live target, reopen the original reference path or create a
new secondary image view. It executes the recorded range count rather than
recreating the original cooperative wall-clock yield.

The writer holds the verified reference blob lease through raw and recipe
publication. Recipes have a separate 2 MiB/file and 128 MiB/session limit.
Recipe queued/written/failed/unavailable counts and bytes remain separate from
raw archives and reference blobs in publication events and final ledgers.
Collisions are never overwritten. A raw archive can survive recipe failure.
The hash provides integrity checking, not collector authentication.

`!kmon replay-image <slice.knslice> /json` returns `kn.image_slice_replay.v1`.
It verifies the retained blob and normalization, runs the shared comparison
policy, requires exact receipt consumption and reproduces the recorded results.
Its `kn.image_slice_proof.v1` reports matching/differing ranges and separate
compared/excluded/unreadable byte totals for executed slice ranges. Even a
successfully replayed inconclusive slice does not prove a match. Whole-sweep
completion, approved reference provenance, atomic mapping lifetime and execution
are not established. `/current` explicitly returns unavailable for slice recipes;
existing v1/v2 single-range recipe behavior is unchanged.

Cross-bundle graph associations, image-collector initialization receipts, other KMON reader paths,
crash recovery/global retention, reference caching and native lifecycle validation
remain open. These slices do not complete VS1.

## Temporal image sweep manifests

KMON assigns a distinct ID to each recorded sweep and advances its slice ordinal
before queue admission. It publishes `image-sweeps/sweep-<id>.knsweep` using
`kn.image_sweep.v1`. The manifest binds original raw payload and recipe hashes,
reference identity, executable range indices, declared target identity and
per-slice monotonic observation intervals. FILETIME anchors permit wall-clock
correlation; elapsed observation time uses the collector's steady clock.
Reference replacement and a restarted sweep receive a new ID.

The writer records actual raw/recipe/reference publication outcomes. Missing
ordinals remain missing. On orderly shutdown it publishes an incomplete manifest
for any retained group without a terminal observation; the unobserved tail and
final completion time remain unknown. Traversal completion does not imply that
every byte was compared. Publication alone sets `complete_replay_established=false`.
This is temporal membership, not an atomic mapping or code-version snapshot.

Metadata is bounded to 128 active groups, 8,192 retained entries overall and
2,048 entries per group. Admission and entry losses have separate counters.
Manifests have a 2 MiB/file and 128 MiB/session limit, independent of raw, recipe
and reference budgets. A sweep whose every slice misses the raw queue has no
manifest; session started/terminal-observed counts retain that denominator.
Inspect the final `.knreadledger` after drain, including metadata failures,
publication failures and pending groups. Live counters are not a closure proof.

`!kmon replay-image <sweep.knsweep> /json` verifies the manifest, declared artifacts,
exact shared reference and executable schedule. It binds each recipe to its
target, range and original observation interval, checks raw/recipe agreement,
rejects duplicate or overlapping ranges, and runs each retained original slice
policy. The shared reference lease remains held through the replay. Secondary
observations must fit inside their enclosing target transaction interval.

`kn.image_sweep_replay.v1` reports `kn.image_sweep_proof.v1` with separate missing
entries, unknown tail, unobserved ranges, excluded/unreadable bytes and raw
publication loss. A replayable subset can succeed while whole-sweep completion
remains false. A missing or contradictory artifact declared as published fails
without proof. The match claim covers the scheduled executable ranges only;
it does not cover every PE section or prove execution, approved provenance or
an atomic lifetime. `/current` is explicitly unavailable for manifests.

Replay admits up to 256 MiB of raw/recipe JSON inputs, matching their combined
session limits. Slice replay still performs full reference verification per
slice; shared physical storage does not provide an I/O cache or a latency bound.
The [image collection journal](#image-collection-publication-journal) records
collection membership separately from these files. Retention and cross-bundle
joins remain separate work. Individual atomic file publication is not a
multi-artifact transaction or a power-loss durability guarantee.

## Image collection publication journal

The KMON writer publishes original reference/read/recipe files, then a journal
record under `collections/<collection-id>/journal-segments/`. A sweep root is
committed only after every artifact it declares as published belongs to an earlier
record. IRP captures and their retained references use `irp_capture` transactions;
the final IRP ledger uses `irp_ledger`. When IRP work was admitted, dropped or
unavailable before encoding, the
writer requires that ledger's commit before publishing the read-session closure
with an explicit ledger dependency. A failed IRP ledger leaves the collection
open. The existing `persistence` and file counters describe individual
files; `journal_read_batches_*`, `journal_sweeps_*` and final pipeline
`image_journal_closed`/`image_journal_close_failed` describe collection publication.
A read batch can retain a reference or recipe even when raw-file publication
failed; consult both sets of counters. Closure does not imply complete target
observation or successful comparison/replay.

`session.knsession` (`kn.evidence_session.v1`) fixes the collection ID and
policy. Current KMON writers use `kn.image_irp_claim_collection_journal.v4`, which
also admits `kn.irp_claim_publication.v1`. Image-only v1, image/IRP v2 and
image-claim/IRP v3 sessions remain readable. V3 admits original slice/sweep claim
publications but rejects the new IRP publication; v1/v2 reject both new forms,
and v1 also rejects IRP transaction kinds. A writer cannot reopen a session under
a different policy.
Each create-new `.knjseg` record
(`kn.evidence_journal_segment.v1`) binds its sequence, preceding **physical-file**
SHA-256, transaction ID, members and prior dependencies. Members bind their exact
physical bytes, lengths and original schemas. These hashes differ from canonical
payload/recipe hashes. The writer pins verified files against writes/deletion,
checks local directory components against reparse redirection, and owns an
exclusive collection lock. An exact retry of a committed transaction is
idempotent; conflicting IDs, paths and appends after closure are rejected.
Journal I/O converts validated local paths to normalized extended paths, including
backslash separators, so long temporary/index names do not depend on a system
setting. See the [Windows path contract](https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation).

`!kmon journal <collection-directory> /json` locks the stopped collection and
returns `kn.evidence_journal_recovery.v1`. It validates the session, consecutive
segments, schemas, chain and exact original member files. Missing/corrupt input
stops recovery before that transaction; later files are not included. Pending
segments and unreferenced raw files remain uncommitted and are never deleted or
automatically adopted. Recovery returns the verified prefix, explicit issue and
whether a writer can resume at the next sequence. An absent terminal record is
an unknown tail: the hash chain has no authenticated external anchor proving
that a tail was not removed. Closure is accepted only for an entirely verified
terminal sequence. A successful recovery establishes membership, not replay;
the returned sweep paths can be passed to the existing replay/graph commands.

Indexes are derived. The writer publishes a content-named `.knjindex` chunk after
each journal record, and an immutable head after closure. `/index` reuses exact
completed chunks and publishes missing chunks plus a head for the recovered
prefix. A corrupt existing index is reported without replacement; it does not
invalidate original journal membership. Restart revalidates the entire prefix
and original files, so resumed publication is not an incremental I/O cache.
Legacy `.kncase`, `.knverify` and `.knindex` readers remain unchanged.

This version bounds recovery to 8,192 segments, 16,384 unique member paths,
65,536 member/dependency references, 2 MiB per JSON record except for explicitly
typed IRP capture members (16 MiB), 64 MiB per reference
blob and 1 GiB of total file reads. Writer read accounting lasts for the open
journal; recovery/index accounting lasts for that invocation. The 120-second
deadline is checked between synchronous operations, not an I/O cancellation
guarantee. Index reads share this budget. Logical reference bytes and unique
content bytes cover only the verified collection prefix; they do not measure
physical disk allocation, orphan volume or global cross-collection retention.
The stopped-store inventory and explicit uncommitted GC below cover image and
IRP members. Committed-root retirement, remaining family priorities, large-store
continuation beyond these bounds and media/power-loss testing remain P06 work.
Files are flushed before create-new
rename; the observed-process-interruption tests do not establish power-loss
durability or collector authenticity. All journal/index/recovery artifacts are
private evidence.

## Image store membership inventory

`!kmon store <artifact-root> [/artifacts] /json` returns private
`kn.evidence_store_inventory.v1` for the root's `collections`, `image-reads`,
`image-references` and `image-sweeps` namespaces, plus reserved IRP files directly
under the root. Scope is `image_and_irp_collection_namespace`. Root names starting
with `irp-`, or using `.knirp`/`.knirpledger`, enter this inventory; malformed and
pending entries remain protected. Unrelated root files are outside its scope.
Legacy `.kncase`/`.knverify`
and immutable `.knindex` stores retain their existing adapters and are excluded
from these denominators. This command creates a zero-byte `store.knstorelock`
in an existing local root if needed; it requires write access to that lock.

Participating KMON writers take a shared store lease before publishing any
original/reference/recipe/sweep/ledger file and retain it through closure,
including when journal publication fails. Journal writers/recovery also take a
shared lease. Inventory takes an exclusive lease first, then pins the catalog,
collection journals and exact original files together. A live publisher makes
inventory unavailable (`store_busy`). Conversely, a newly publishing KMON writer
is denied during inventory, counts `store_admission_failed` (final pipeline:
`image_store_admission_failed`) and retains the ordinary file/ledger failure
counts. It does not retry by reacquiring target memory. Inventory is intended for
stopped stores. This coordination is not an ACL, authentication boundary or
protection against an older/nonparticipating publisher.

Each accepted journal prefix contributes original member references. The report
distinguishes reference multiplicity, unique paths per collection, unique paths
across the store and unique content hashes. Shared paths are hashed once while
their immutable leases remain held; equal content at distinct paths is still
read separately. These are named-file byte counts, not allocated disk blocks,
compression, filesystem hard-link accounting or target coverage. Root receipts
and sorted artifact rows have separate canonical JSON hashes; neither is an
authenticated external anchor. Membership/schema/hash verification is not image
policy replay. Index contents do not establish membership.

`membership_complete` requires a complete observed catalog and every root to
verify as closed. An open root, malformed catalog entry or corrupt journal
protects unattributed files; verified non-ledger files receive
`unresolved_membership_protected`. Files
outside accepted prefixes never become committed by discovery. Committed
reference blobs, original observations and failure ledgers have distinct
protected retention reasons. A verified unattributed file under entirely closed
roots remains protected if it is a session failure ledger, including when its
journal was never created. Any other verified unattributed file under closed
roots is only `uncommitted_requires_policy`; unknown, pending, malformed or
unreadable artifacts remain protected and make artifact inventory partial.
`kn.retain_committed_and_unresolved.v1` is an inventory classification policy,
not a GC policy. Reports release all leases on return and always declare
`deletion_authorized:false`. The separate [explicit GC operation](#explicit-uncommitted-artifact-gc)
revalidates its own policy and leases. Committed-root retirement, cross-collection
retention priorities and other-family transfer/redaction controls remain P06 work.
Local ACL/EFS admission is described under [private evidence roots](#private-evidence-roots).

Bounds are 1,024 catalog entries, 65,536 managed artifact paths/observed directory
entries, 262,144 accepted member/dependency references and 8 GiB aggregate reads.
Existing per-collection bounds remain; the separate unattributed-file reader is
also limited to 1 GiB. Root enumeration has a separate 65,536-entry cap, including
entries outside the reserved IRP namespace. The shared 120-second deadline is cooperative between
synchronous operations. Exhaustion yields partial/unavailable status; separate
flags distinguish verified journal membership from an incomplete artifact scan.
`/artifacts` uses a 16 Mi UTF-16 code-unit detail budget and reports
emitted/omitted row counts; the
aggregate counters and complete captured-row digest remain available. Large-store
continuation is still required; this bounded audit does not implement it.

## Explicit uncommitted-artifact GC

`--offline !kmon gc <root> <policy.json>` preflights a private
`kn.evidence_gc_policy.v1` selection. `/apply <operation-id>` applies or resumes
that exact policy. GC is available only through this offline CLI, not the live
controller/MCP command route. `tools/new-evidence-gc-policy.py` creates a policy
from explicitly selected `/artifacts` inventory rows; it performs no deletion,
refuses protected/missing rows and never overwrites an existing policy. The
collector independently revalidates the current store and original bytes.
Its scope is `explicit_uncommitted_image_and_irp_artifacts`. Both image and IRP
failure ledgers are rejected by policy validation even if uncommitted; all
committed captures/references remain protected. Legacy image-only inventory
reports are still accepted by the policy helper, which grants no deletion authority.

Policy `kn.gc_explicit_uncommitted.v1` binds a reason, minimum file age, total
named-byte ceiling and sorted exact path/hash/size/schema members. Policies use
canonical UTF-8 JSON and string-encoded unsigned integers; unknown fields or
schemas are rejected. The helper emits this form. A policy is an operator
selection, not a signature, priority inference or authentication credential.
Bounds are 128 members, 128 KiB policy input and 128 MiB selected bytes, within
the existing store budgets and cooperative deadline.

Every captured collection must verify closed and the complete artifact scan
must succeed. Only `uncommitted_requires_policy` members can be selected;
committed originals/references, all failure ledgers, unknown artifacts and open
or unresolved membership remain protected. All selections are preflighted before
the first deletion. Exact files are held against writes/path replacement, and
apply requests DELETE access on the selected unmatched files during verification.
Read-only files, hard links, missing 128-bit file IDs/creation times, future mtimes and files
younger than policy age are denied. Age uses the filesystem last-write timestamp;
it does not establish acquisition time or trustworthy provenance.

Under the exclusive store lease, GC publishes and verifies
`retention/<operation-id>/operation.kngc`, then `<ordinal>.kngcintent` before each
deletion. The operation binds the exact policy and physical root identity; each
intent binds the selected member, volume/128-bit file ID/creation time, last-write time,
catalog hash and observation time. It marks the same verified handle for
deletion with `FileDispositionInfo`, closes it, observes the named path and
publishes `<ordinal>.kngcreceipt`. Windows requires DELETE access for this
[handle operation](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle).
GC requires `FileIdInfo`; the legacy 64-bit ID is
[not guaranteed unique on ReFS](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/ns-fileapi-by_handle_file_information).
No recursive/path-based cleanup is used. A receipt-publication failure cannot
undo a deletion; the durable intent remains and the result is incomplete.

Resumption verifies immutable operation/intent/receipt bytes and the current
roots. A present original with the same file identity can resume; even an
identical-byte replacement after an intent is preserved. An absent file after an
intent but before a receipt becomes `absent_after_intent`, with deletion actor
unknown. It is not counted as a newly confirmed deletion. Valid terminal receipts
are reused without repeating the operation. `completed` describes the historical
operation, not current path absence: a later replacement is retained. Failed or
unknown outcomes remain explicit and are never silently retried by a completed
receipt. Corrupt or colliding audit files are preserved and block continuation.

Reports and receipts record selected named bytes and deletion reasons; they do
not establish reclaimed disk blocks, secure erasure or power-loss durability.
Uncommitted recipe dependencies are not resolved: explicit removal of an
uncommitted reference can make another uncommitted artifact unusable. This scope
is declared as `uncommitted_dependents_resolved:false`; committed dependencies
stay protected by journal membership. Priority-based GC selection, retirement
of committed roots, full dependency-impact analysis, other-family transfer/redaction controls
and large-store continuation remain required work. All policy/audit/report artifacts
are private evidence; there is no automatic external upload.

## Private evidence roots

Offline `!kmon init-store <new-root>` initializes a local root with a protected
DACL granting inheritable full file access only to the effective current token's
user SID and SYSTEM. EFS is required by default. `/acl-only` explicitly selects
access control without requiring encryption; failed EFS initialization never
downgrades to that policy. Existing roots are neither adopted nor modified.

Only fixed, removable and RAM-disk local drive paths are admitted. UNC/mapped
network roots, alternate streams, device names and ambiguous trailing dots or
spaces are rejected before output creation. Unicode names and spaces within
normal components are supported. Initialization creates a randomly named private
sibling, checks its owner/DACL
and full 128-bit file ID, volume and creation time, enables EFS, then verifies
the encrypted attribute. Only then does it publish `store.knprivacy` with
`kn.evidence_private_store.v1`, the selected policy, principal and physical root
identity. The directory is renamed by its held handle without replacement.
A reader of the newly written policy can temporarily prevent publication.
Access-denied/sharing failures have a two-second retry budget with the same held
directory and parent pins. Existing destinations stop the retry, and the root's ACL/encryption is
rechecked. Persistent failure retains the private staging directory and returns
the Win32 publication failure; permissions are never relaxed. A
collision preserves both outputs; interruption can leave a private staging
directory, whose path is reported on ordinary failure. There is no automatic
recursive cleanup. Directory pins request data/list access as well as metadata
access so that Windows enforces their no-delete sharing. Write sharing remains
necessary for normal child publication. Policy handles deny write/delete sharing.

EFS protects the stored file while Windows exposes the original plaintext to an
authorized reader. Existing original-byte hashes, journals, CAS references and
replay formats therefore stay unchanged. Newly created descendants inherit EFS
and the private DACL. These behaviors follow Windows
[file encryption](https://learn.microsoft.com/en-us/windows/win32/fileio/file-encryption)
and [EncryptFileW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-encryptfilew);
the initializer verifies the resulting metadata instead of treating API success
alone as an encryption guarantee. Filesystem support and the account's EFS key
availability remain prerequisites. No key export, backup or recovery provisioning
is performed.

`!kmon privacy <root>` verifies the canonical policy, current principal, physical
root, protected root DACL and policy file. `/audit` also walks the existing tree,
rejecting reparse points, multiply linked files, extra ACL principals, directories
that do not propagate the private grants, and unencrypted objects when required.
The walk holds active ancestor directories, permits at most 128 descendant levels
and 65,536 entries, and checks a cooperative 120-second deadline. `checked_entries`
counts descendants, including the policy once. A root-only inspection is not a
successful tree audit. Enumeration/permission failures and exhausted bounds remain
explicit failures; there is no partial-success audit.

KMON `/private-log <root>` requires this initialized policy and a successful
initial tree audit before logging or starting acquisition workers. It binds all
session writers to the audited absolute root, retains the root/policy guard
through rotation and worker drain, and validates each opened JSONL file's handle
before writing. The guard is released after stop. A failed subsequent Start call
cannot discard an existing session's guard. `/log` remains available without
privacy admission, and cannot be combined with `/private-log`. The offline init
and audit commands do not start a controller or expose a live/MCP initialization
route.

This is an observed OS access-control boundary. The owner, SYSTEM, administrators
and configured EFS recovery agents are trusted. A privileged actor or the owner
can change security descriptors, encryption and reparse metadata; an audit is
not an atomic snapshot or continuous tamper monitor. Handle-based
[GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo)
does not remove that concurrency limit. Parent directory permissions may also
allow deletion: confidentiality does not establish availability. Ordinary exports,
console logging and copies outside the private root need their own policy. This
does not authenticate the collector, prove power-loss durability or authorize
external transfer. The separate image disclosure path below implements a bounded
minimization/approval workflow; other evidence families, key recovery operations
and broader P06 retention remain open. Reports and
`.knprivacy` files, including pending files, are private evidence; no automatic
external upload is added.

## Minimized image disclosure

Offline `!kmon redact-image <recipe-directory|knslice|knsweep> <new-private-root>`
replays the original policy before creating a derivative. The new root uses the
private-root controls above: EFS is required unless `/acl-only` is explicit.
`facts.knshare` contains canonical `kn.minimized_image_facts.v1` under
`kn.image_counts_redaction.v1`. Its closed vocabulary includes only a random
derivation ID, range/slice/sweep scope, byte denominators and fixed qualification
limits. Paths, addresses, process/source identities, hashes, symbols, timestamps,
raw bytes and source-controlled free text are omitted. Counts cover the recorded
scope only; a zero-byte rejected slice remains unqualified with `changed_bytes`
null. Null also preserves an unestablished direct-range comparison. Zero is not
substituted for unknown. Retained references are not approved distributions, and
no execution, maliciousness, atomic-state or collector-authenticity claim is made.

The private `redaction.knredact` sidecar binds the exact original file hash,
recipe/manifest semantic hash, fresh replay proof hash and derivative hash to the
physical root and current principal. Originals are read under a lease and are
never modified. Facts publish first and the manifest last through create-new,
flushed files. A partial package cannot be reviewed for sending. Inspection can
read a completed historical package without reacquiring a target or reopening
the original; the linkage is not an authenticated collector signature.

`ai share preview <root>` pins the audited root, facts and sidecar, and displays
the exact facts, system instructions, HTTP endpoint/model and OAuth refresh
endpoint when applicable. It sends nothing. `ai share send <review-id> confirm`
requires the pending opaque review and unchanged settings/credentials, publishes
a private `.knsend` intent, and consumes the approval before transport. A failed
intent blocks dispatch. A `.knsendresult` records `not_dispatched`,
`completion_received` or `outcome_unknown`; missing/colliding result records leave
the intent unresolved. No automatic reapproval or application retry follows a
failure. A new preview and confirmation are required. OAuth may refresh and retry
one logical completion at the displayed endpoints; this is not an exactly-once
HTTP delivery guarantee. Recipient processing, storage and deletion remain unknown.

The endpoint must be HTTPS, except numeric loopback HTTP for owned tests. Redirects,
implicit Windows authentication and automatic cookies are disabled using
[WinHTTP request options](https://learn.microsoft.com/en-us/windows/win32/winhttp/option-flags#winhttp_option_disable_feature).
OS proxy/DNS configuration and local administrators remain trusted. HTTP provider
credentials are bound privately and never placed in preview or audit records.
External CLI evidence transfer is rejected because that process's file access
and egress are not confined. `local-only` also blocks reviewed HTTP disclosure.
Approval is console-local: remote console commands and nested AI plans cannot
invoke it, and no MCP approval tool is exposed.

At the provider boundary, collected stdout/stderr and unclassified requests are
denied for every provider, including CLI. Operator-authored questions and planning
prompts remain explicit provider requests; automatic symbol paths, module counts,
last-target hints and session-expanded addresses/dump paths are withheld from
those requests. Local command interpretation can still use the session context.
Model output from disclosure is advisory text and is never executed as a plan.
Both response text and provider errors are escaped on display so terminal control
characters remain data.
This is not offline inference or a general egress sandbox for MCP, remote console,
operator-pasted content, external tools or other evidence families. The owner,
SYSTEM and administrators remain trusted; approval and hashes are not external
authentication. All packages, previews and transfer records remain private,
including renamed JSON and pending files. Approved recipient disclosure does not
make an artifact safe for public publication.

## Replayed image sweep graph

`!kmon graph <sweep.knsweep> /json` projects a successful original-policy replay
as `kn.image_sweep_graph.v1`. It connects the sweep assessment, manifest, declared
target context, exact reference artifact, slice recipes, published read archives,
slice observations and executable-range comparisons. Every node and `derived_from`
edge names a retained artifact digest, a JSON pointer where applicable, the
original slice ordinal and observation interval. Binary references have no JSON
pointer. These are provenance edges; no callback, dispatch, execution or writer
relationship is inferred from an image difference.

Range nodes report compared, changed, excluded and unreadable ranges and byte
totals from newly recomputed comparisons. A failed original reference qualification
cannot become a graph match. Missing slices remain unobserved in the sweep
assessment. A missing raw archive has no retained-archive node, even when a recipe
still contains enough original reads to replay; publication completion remains
separate from comparison completion. Missing/corrupt declared artifacts or failed
replay produce neither a materialized graph nor a successful assessment.

Graph IDs bind the graph policy, exact manifest digest and recomputed proof.
Even a shared reference digest does not merge target nodes across sweeps. The
target identity remains collector-declared, and the monotonic interval describes
observations, not a pinned mapping lifetime. The graph establishes neither
approved distribution provenance nor collector authenticity.

The existing bounded graph query handles both graph kinds. A sweep projection
admits at most 256 nodes, 512 edges and 2 MiB of provenance/detail JSON, in addition
to the replay input limits. Oversized projections fail explicitly; replay remains
available separately. Cursors bind the graph, root, depth and record limit.
`/budget-ms` covers materialized traversal only, not reference I/O or policy
replay. Page/depth completion is unrelated to target or publication coverage.
The legacy `.kncase` graph contract is unchanged. Qualified cross-bundle
process/mapping/code-version joins and relationships to callback/dispatch evidence
remain P07 work; global P06 retention and native lifecycle gates remain open.

## Typed translation receipts

`IObservationSource` distinguishes virtual and physical address domains.
Physical admission uses an explicit 32..52-bit address ceiling and does not apply
virtual canonicality or user/kernel classification to a physical address. A
changed address descriptor, domain, residency policy or other source contract
invalidates the current read even if its source ID stays the same. The caller
must still serialize contract/lifecycle changes; these checks do not create a lease.

`TranslateObservedAddress` reads every PML5/PML4/PDPT/PD/PT entry through one
recorded physical source and operation budget. Its root carries source, target,
address-space, root and epoch identities; the operation's target labels must
match. Each `kn.translation_receipt.v1` contains entry addresses, raw values and
the original read receipts, including failures. The walker supports 4 KiB,
2 MiB and 1 GiB leaves, validates fixed reserved/alignment bits, and applies
MAXPHYADDR, NXE and 1 GiB checks when that target context is known.

Every successful path is read again, in root-to-leaf order, within the same
budget. A changed root/epoch, changed entry, incomplete read, cancellation,
deadline overrun or missing receipt withholds the mapping and permission result.
Both versions of a conflicting entry remain in evidence. Matching rechecks do
not rule out ABA, pin mappings or establish an atomic snapshot.

Paging write/user bits are reduced across all levels; any upper NX bit denies
the paging execute attribute. Unknown architecture context yields nullable
permissions. These are paging-chain attributes, not effective CPU access or
execution evidence: CR0.WP, CR4 features, CPL, protection keys, second-stage
translation and other access controls are not evaluated. The decoder assumes
ordinary IA-32e physical addresses; encrypted-address encodings and EPT/NPT are
not additional supported profiles. See the
[Intel system programming manual, paging and access rights](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html).

The root callback checks retained provider metadata; acquisition that establishes
that context belongs in the provider's own evidence/budget. Native live root
acquisition, lifecycle leases and scanner migration remain open. The current
saved-dump command records either the caller's range (`/receipts`) or both file initialization and that range (`/init-receipts`).

Virtual image-recipe capture rejects physical sources and stops after a source
contract change or deadline overrun. The v1 recipe format refuses an overrun
flag it cannot preserve. Runtime sample availability also requires a completed,
identity-qualified read without cancellation or an observed overrun.

## Native read status transport

ABI 17 retains all existing IOCTLs and layouts. The optional
`KNDBG_VERSION_FLAG_READ_OBSERVATION` advertises `IOCTL_KNDBG_READ_OBSERVATION`
(function 0x818, buffered, read access). Version 1 accepts a fixed 64-byte request
and returns a 96-byte header plus the transferred bytes, at most 4 KiB. Kernel
virtual, identity-qualified process virtual and regular physical reads have
separate kinds. Reserved fields, exact version/size, request echo and returned
length are checked. The collector connection epoch is echoed for correlation;
the driver does not authenticate that client-supplied epoch.

Delivery success means the envelope arrived. Its NTSTATUS remains the original
operation result; partial/failing copies retain their reported transferred count.
Outer failures retain the raw Win32 transport error and an unknown copy count.
The result distinguishes an unknown copy attempt from a known false flag.
Explicit identity-mismatch and policy-denial flags remain `identity_changed`
and `policy_denied`; neither can authorize an alternate-source fallback.
Structurally bound but contradictory success/count pairs retain their raw status
and count while withholding bytes from parsers. Valid partial prefixes remain
sparse evidence and cannot enter an exact parser read.

The WDM handler copies the buffered input before clearing its bounded output.
It checks IRQL before lookup/attach/copy, references the expected process object,
matches PID/EPROCESS/creation, and pairs attach/detach and reference/release on
success, failure and exceptions. The device retains its SYSTEM/Administrators ACL
and the new IOCTL requires read access. No mutation or MDL fallback is introduced.
Virtual reads require explicit residency consent. The existing
[`MmCopyMemory` contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-mmcopymemory)
requires a nonpageable destination and IRQL at most APC_LEVEL, reports bytes copied
on failure, and may make virtual memory resident. Physical reads use that routine's
regular-memory behavior; no MMIO mapping fallback is added.
[`METHOD_BUFFERED`](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/buffer-descriptions-for-i-o-control-codes)
shares one kernel buffer between input and output. The process copy is kept within
a short [`attach/detach` interval](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-kestackattachprocess).

`DeviceClient` must first qualify the driver version. Close or a failed version
query clears the optional contract. A qualified older driver uses the original
IOCTL and explicitly marks raw NTSTATUS unavailable; a legacy failure does not
invent transferred bytes. An advertised extension's failed or malformed reply
does not trigger a legacy retry. `NativeObservationSource` uses this path and
also supports a PID/EPROCESS/creation-bound process source. Existing direct
read/fallback call sites are not automatically migrated. Object identity binding
does not pin virtual mappings, establish a boot/VM identity, authenticate the
kernel, or prove execution. Native driver load/lifecycle validation remains a
separate gate from the transport's synthetic tests and driver build.

## Process cross-view qualification

`!hiddenproc` first discovers PID candidates from ActiveProcessLinks, SPI,
Toolhelp, handle owners and CID entries. Those observations and image labels
remain discovery hints. A second, bounded comparison binds each admitted
candidate to `(PID, EPROCESS, CreateTime)` before and after fresh kernel/SPI/
Toolhelp inventories. Each boundary sample brackets lifecycle reads with repeated
identity reads and CID resolution. No fixed EPROCESS layout or reserved SPI
creation-time offset substitutes for a missing symbol field.

The kernel walk requires unique PIDs, bounded canonical pointers from the active
address descriptor, reciprocal back links, return to the list head and unchanged
head links. A sampled cross-view discrepancy requires all three comparison
inventories to finish, matching lifetime samples, readable ExitTime/ActiveThreads
at both boundaries and no observed exit/delete/rundown transition. Kernel-only
candidates also require stable AuxiliaryProcess state. Confirmed auxiliary
clones, terminating objects and reconciled candidates remain auditable records.
Missing fields, failed reads, identity changes and budgets produce `unverified`.
SPI and Toolhelp share a process-list dependency and do not count as two
independent proofs. Equality of sampled fields is not an atomic snapshot or an
authentication of a potentially compromised kernel.

At most 128 candidates enter confirmation per scan under a cooperative
five-second budget. CLI and KMON each retain a session scheduler across scanner
instances, bound to the device connection epoch. Pending candidates rotate after
each actual attempt, including failures; unattempted selections keep their place.
At least three of four selection slots serve the oldest queue entries; new
API-unlisted candidates may use the fourth. Departed candidates are pruned.
The queue stores PID scheduling hints, never lifetime samples or identity proof.
Every batch starts with fresh before/after state and fresh inventories.

Recent inventory/lifetime costs reduce the batch size and reserve time for the
comparison and after reads. The before phase has its own smaller deadline;
in-flight IOCTLs and API calls are not interrupted, and discovery remains outside
the qualification budget. Cancellation and source replacement leave unfinished
candidates unverified; a source replacement invalidates all claims in that batch.
The additive `scheduling` report retains candidates, selected/attempted/deferred
counts, completed boundary attempts and maximum served/pending queue waits.
These are queue service metrics, not successful lifetime revisit measurements or
an achieved latency SLO. Excess candidates stay in the result. The
additive `lifetime-cross-view-v2` policy in `kn-live-dbg.hidden-process.v1` separates
discovery membership from qualification views, before/after samples and failure
reasons. Unknown lifecycle values are null inside qualification; legacy scalar
fields require their `has_*` flags. `inventory_complete` describes discovery;
`coverage_complete` also requires no unverified candidates. Neither establishes
that every hidden process was discoverable. Raw backing reads, generic proof
ledgers and offline replay for this scanner remain open.

KMON emits admitted discrepancies as `process.hidden` with a sampled-discrepancy
summary, and unverified candidates as `coverage.process_cross_view`. Candidates
without a bound lifetime are emitted per scan; a PID alone cannot deduplicate
them across scans. Only admitted lifetimes enter suspect tracking. A subsequent
raw EPROCESS capture is explicitly outside the qualification window and does not
extend its lifetime guarantee.
No state establishes deliberate hiding, execution, a writer or an actor.

## Native execution evidence levels

The selected native user-evidence adapters now emit `kn.execution_evidence.v1`.
TLS/VEH/VCH registrations, configured debug registers and APC argument candidates
remain X0 references. Thread-start metadata, raw stack values, queued APC routines,
saved trap context and captured PSS context are X1 metadata when their declared
scope is available. Neither grade sets `execution_observed`, `write_observed`,
`control_flow_observed` or `actor_attributed`. Unknown source kinds, process
identity, address formats or required captured-context fields stay `unqualified`.

PSS conversions preserve thread creation time, capture time and pointer storage
width. The [PSS thread entry contract](https://learn.microsoft.com/en-us/windows/win32/api/processsnapshot/ns-processsnapshot-pss_thread_entry)
defines those timestamps and a captured context; it does not supply a current
CPU identifier. The adapter therefore keeps CPU/code-version fields null and
does not promote a saved RIP to an X2 CPU execution sample. Missing context
timestamps and reversed creation/capture order remain unqualified. The selected
native user readers still use their explicit legacy LA48 address format; the
assessment reports that assumption and does not extend their live LA57 support.

Hunt exports up to 128 typed native observations per process with total and
truncation fields. KMON retains the existing `process.execution` event category
for compatibility, but summaries and `execution_evidence_json` identify the
actual reference or metadata kind. These are deduplicated reference records,
not a complete instruction history; known PSS thread generations participate in
the key. VAD correlations use `execution_reference_observed`, `wx_reference_observed`
and `permission_range_reference_observed`; the corresponding legacy execution
booleans are false. Detection heuristics still use those reference correlations.
Trace/VMI producers, X2-X4 validation, additional runtime layouts and game-object
lifetimes remain separate work.

### CLR method ranges in hunt output

The user-mode tracker collects CLR declarations for a watched PID and process creation
time. Runtime method load and unload events use IDs 141–144. Runtime v0
inventory events use IDs 137–140. The separate rundown provider uses IDs
141–144 for start and end inventory. Both inventory directions describe
methods present during enumeration. The decoder checks the provider, task,
opcode, event ID, version and payload length.

| Manifest version | Range identity fields |
| --- | --- |
| v0 | Method ID, module ID, start, size, token and flags |
| v1 | v0 fields and CLR instance ID |
| v2 | v1 fields and ReJIT ID, including an explicit zero |

Hunt JSON keeps the `execution_evidence.runtime_ranges` count and adds
`runtime_method_ranges` for the retained declarations. Each row gives its
provider, event ID, version, load or rundown origin, observation FILETIME
and range identity. Unsupported fields appear as JSON `null`. Addresses
and 64-bit IDs use hex strings. The FILETIME uses a decimal string. The
`jit_flag` field mirrors bit 0x8 of the reported method flags. The output
also gives collection availability, truncation and failure count.

The tracker uses event timestamps to order declarations at a start address.
An older unload leaves a newer observation in place. An unload whose extent,
flags or generation conflicts with the current record fences the cache through
the conflict and requests fresh inventory. Matching unloads retain a
tombstone with the declared identity and extent. Collection loss also
invalidates positive coverage. These rows establish what the CLR declared
during observation. Matching the code bytes to a historical CPU sample
requires separate capture-time evidence.
[.NET runtime event manifest](https://github.com/dotnet/runtime/blob/d7a6547f2a039031d9c29180bb95541a06a86276/src/coreclr/vm/ClrEtwAll.man)

Saved CPU profiles can use the same declaration reader. A sample is attributed
to a reported method only when an actual matching load and unload surround it
within a file-local process generation. The native page preserves both
original method record ordinals and the sample's offset. The normalized
query carries this reported method separately from verified code identity.
[Saved CLR method evidence](TRACE_IMPORT.md#match-a-cpu-sample-to-a-clr-method)

### V8 code records in saved profiles

The offline trace query accepts the Windows V8 text profiler and its x64
binary code log. The original sample PC, logger time and physical record
number remain available even when a JS function cannot be assigned. The
reader tracks range replacement, relocation, deletion and deoptimization.
An optional, independently pinned low-level log supplies the bytes attached
to a matching code-creation record. Matching requires an ordered comparison
of the two files and a compatible function label. The target process creation
time and the original PC capture timestamp remain unknown.
[Saved V8 CPU profiles](TRACE_IMPORT.md#saved-v8-cpu-profiles)

### Game object generations and base subobjects

A game can publish its object registry in the main image using the fixed
x64 slot layout. The build-specific manifest identifies one slot and
expected container per participating root. Its generator checks the slot
fields in the exact private PDB and verifies the outer class, base type,
offset, extent and vftable symbol for each declared subobject.

KMON brackets its existing object and slot reads with two observations of
the publication. Each observation checks the sequence on both sides of
the payload read. A stable, active member can support a structural
comparison for the reported generation. When an address is reused during
a read, the resulting rows retain both publications and the collector's
measurement interval. KMON defers the comparison and any dependent code
checks. Reported membership depends on the cooperative writer. Older
manifests retain their structural rules and identify lifetime as undeclared.
[Game registry layout and event fields](KMON_DETECTION_VERIFICATION.md#game-object-lifetime)

## Pending I/O observation graphs

The native pending-IRP reader retains every admitted request, including requests
with no registered completion. It validates the supplied thread's PID, TID and
creation time, its list window, the packet header and repeated packet/stack
reads. The same reader is compiled into the standalone ASan fixture. Optional
PDB-resolved `Cancel`, `PendingReturned`, `IoStatus.Status`, device and file fields
remain null when unavailable; offsets and pointer targets are not guessed.

KMON emits `io.request_observation` with a private `kn.irp_observation.v1` report
in `irp_observation_json`. These kernel observations enter the ordinary ring/log
independently of process-watch filters; routine snapshots are suppressed from
live console printing. Each report
retains one request, up to 64 inspected stack locations, and a graph of its
observed thread-list membership, stack locations and pointer references. Graph
IDs are local to the enclosing event. A valid address shape does not validate a
device/file object, and equal addresses do not join request lifetimes across
observations. The source defaults to 32 threads/64 requests per bounded turn,
with hard limits of 128 threads/256 requests and 4,096 list visits.

The state is `RequestObserved`, the outcome is `UnknownOutcome`, and the
transition list stays empty. Neither an empty stack nor disappearance proves
completion. A set cancel flag or successful status also does not prove the
final result; the [Windows IRP contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_irp)
does not allow the cancel flag alone to establish cancelled completion.
Collector tick boundaries describe a non-atomic scan interval, not dispatch or
completion latency. Enumeration coverage remains scoped to supplied ETHREADs.
The [bound capture and offline replay](#pending-irp-schema-and-runtime-binding)
preserve the original read evidence. IRP allocation references, cross-observation
joins to kernel dispatch and completion, frozen wait graphs and attribution
of a deadlock remain open.

### Directory I/O request lifetimes

The Windows directory notification provider retains one opened directory,
a unique manual-reset event, a notification buffer and an `OVERLAPPED`
record for each request. It assigns the request a generation within a
fresh provider run and records the issuing process and thread creation
times. Requests for the same directory remain distinct. The shared wait
records its ordered generation list and the native index of the event that
signaled, so completion order can differ from submission order.
[Windows directory change notifications](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readdirectorychangesw)

| Evidence in the journal | State that replay can support |
| --- | --- |
| Directory admitted and request prepared | `RequestObserved` |
| Windows accepted the overlapped request | `SubmissionObserved` |
| Nonblocking result returned `ERROR_IO_INCOMPLETE` | `PendingObserved` |
| Cancellation attempted on the retained handle and operation | `CancellationAttempted` |
| Signaled private event and a successful, aborted or enumeration-required result for that operation | `CompletionObserved` |
| Final result agreed with the earlier witnesses, the final event wait succeeded and both handles closed | `RetiredWithKnownOutcome` |

Replay retains every original query, timeout and cancellation result by
line number. A zero-byte successful result leaves change details unavailable.
`ERROR_NOTIFY_ENUM_DIR` records that Windows requires a directory enumeration.
A failed query can leave `UnknownOutcome` even after both handles close.
An inconsistent byte count or an event observed as unsignaled after its
selection produces `IdentityConflict`. A hash binds the bytes used for
replay. Kernel dispatch, an IRP allocation generation and correspondence
with a KMON snapshot still require another source.
[Windows overlapped results](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-getoverlappedresult)

[Capture and replay a request](COMMAND_REFERENCE.md#trace-an-io-request-through-completion)

### Cooperative kernel I/O request lifetimes

The pending-I/O fixture can record the CREATE and READ requests that its owner
admits on an opted-in Filter Manager connection. The provider assigns a fresh
capture UUID per connection, a request generation at upper admission and an
instance number at attachment. A lower READ inherits the upper generation
only after the callback data, file object, referenced requestor, owner and
topology checks succeed. No process, file, IRP or callback address appears
in the records. Two requests can share every file parameter and still have
different lifetimes.

| Recorded event | Evidence available at that point |
| --- | --- |
| `dispatch_observed` | The cooperative instance admitted this pre-operation callback. |
| `pre_pending` or `post_pending` | The fixture retained a worker reference and queued this operation. |
| `cancel_observed` | Filter Manager reported the held operation's cancellation flag set. |
| `pre_forward_selected` or `pre_complete_selected` | The fixture selected its pre-operation disposition. A local completion records its NTSTATUS. |
| `post_observed` | A normal post callback supplied the operation status. A successful READ can also supply a validated byte count. |
| `draining` | Filter Manager requested completion-context cleanup during detach. The recorder skips the copied I/O status. |
| `post_resume_selected` or `retired` | The worker selected resumption, or the fixture retired its logical reference. |
| `context_unavailable` | Admission was recorded and context allocation failed. Later outcome evidence is unavailable at this layer. |

The optional v1 connection context is 16 bytes. A 40-byte read request returns
a 648-byte page with the capture epoch, QPC frequency, cursor, available range,
loss flags and up to eight events. Each connection retains the latest 128
events across control release and re-ARM. Up to 16 rings can exist, counting
allocation and disconnect in progress. Disconnect releases the nonpaged
ring and its referenced creator process. The ordinary v7 control and status ABI
remains available. A trace query copies its snapshot under the publication
lock and writes to the caller after releasing it. The post-unregister trace
ledger counts ring allocations and frees and trace message entries and exits.
[Filter Manager message buffers](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nc-fltkernel-pflt_message_notify)
and [post-operation draining](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nc-fltkernel-pflt_post_operation_callback).

Offline replay pins the original pages by SHA-256, ends the assessment at
the first reply's high-water mark and cites the byte offset of each event.
The report counts later rows received in the original pages. Overwritten
intervals remain visible, including loss between page reads.
Sequence and generation determine order and membership. QPC measures
per-layer pending and dispatch-to-observed-outcome intervals when their
endpoints survive and the clock is ordered. An upper outcome requires a
consistent upper disposition or normal post and retirement of the observed
layers. A draining upper callback can leave its outcome unknown even when
the lower layer has a result. Host and boot provenance, IRP allocation
history, user completion and joins to other providers require independent
evidence. [Capture and replay the fixture](COMMAND_REFERENCE.md#capture-a-cooperative-kernel-io-trace)

### Windows thread termination waits

Windows Wait Chain Traversal can report a blocked thread followed by a
`WctThreadWaitType` object and a second thread. The replayer emits a
`waits_for_thread_termination` edge when the middle object has
`WctStatusOwned` and both distinct threads belong to the requested process
generation. Each thread's creation time and live handle checks bracket the
same query. The edge cites all three raw nodes and both handle witnesses.
The target thread object becomes signaled on termination.
[Windows wait chain traversal](https://learn.microsoft.com/en-us/windows/win32/debug/wait-chain-traversal)
and [thread termination](https://learn.microsoft.com/en-us/windows/win32/procthread/terminating-a-thread).

A traversal can contain both a mutex owner and a target thread. Replay
keeps their dependency types in the directed cycle signature. Two roots
must agree on the member generations, direction and type of every
dependency before a measured overlap can corroborate the cycle. The
diagnosis identifies a reported termination wait separately from lock
contention. Alternative wait objects, timeout, cancellation, the target's
eventual exit and the wait call's final result require other evidence.
A finite wait can expire after Windows reports a cycle.
[Capture and replay a wait chain](COMMAND_REFERENCE.md#capture-a-windows-wait-chain)

### Evidence-checked wait investigations

The offline WCT replayer evaluates six code-owned claims about the requested
primary process and thread generations. It checks the SHA-256 of the original
file and counts its recorded root views before evaluating the graph. One
single-root receipt costs one view. Each recorded paired round costs two,
including a root whose query was never issued. The coverage ledger retains the
number of issued queries. If the view budget cannot cover the input, the plan
stops before graph evaluation and returns no target, facts or verdicts.

Each derived fact carries pointers into the pinned original. Its evidence ID is
the SHA-256 of the ASCII JSON encoding of `["kn.wait_fact.v1", receipt_sha256, fact]`
with sorted object keys, no extra whitespace and ASCII escapes. Here `fact` is
the diagnosis fact before adding its ID. Replay resolves its pointers before
admitting it. The target pointer identifies the requested generation. The
qualified observations and their handle witnesses determine which claims it supports.

A typed proposal names the policy version, capture digest and target. Every
cited ID must belong to the decisive evidence for the proposed verdict, and at
least one ID must satisfy each required group. Refuting persistence needs two
groups, the observed reference cycle and the matching member or process exit.
A different cycle contributes counterevidence while leaving the persistence
question open. An observed cycle can refute a claim of cycle-free contention
throughout the recording. A single open wait establishes only an observation
within its traversal. The report preserves both sides when evidence is incomplete.
The checker takes its operations from the built-in policy and emits the hash of
the exact submitted proposal bytes. [Command and proposal example](COMMAND_REFERENCE.md#check-a-proposed-wait-claim)

## CPU samples from saved ETLs

The standalone `--etl-profile` route opens a pinned ETL through the Windows
`OpenTraceW` and `ProcessTrace` event-record interface. It requests raw
timestamps and decodes the version-2 PerfInfo sample layout using the pointer
width in the event. An ETL digest and callback ordinal locate each sample
among all returned records. Payload thread ID, header process/thread IDs,
clock, loss counters and buffer-count discrepancies remain separately visible.
The report preserves unknown address space, code version and recording
conditions for later qualification. [Trace inputs](TRACE_IMPORT.md)

With `--thread-evidence` the same scan also decodes classic version-3 thread
start, end and rundown events. TID and original callback order identify the
nearest records on each side of a sample. The raw source row and clock are
available on each side. A reported PID agreement requires compatible
timestamps, consistent thread transitions and an intact bounded index.
Rundown records describe membership at collection time. The association
stays local to the pinned ETL.

`--image-evidence` extends the thread report with classic Image v2/v3 load,
unload and rundown records. The index groups each payload PID and image base
by original event ordinal. A paired thread PID narrows the search to recorded
ranges for that process number. A reported RVA requires one consistent pair
of enclosing image records. The page retains references to contrary records,
including overlapping ranges. Each referenced image carries its original
file name and PE metadata. [ETL image evidence](TRACE_IMPORT.md#locate-image-records-for-a-sampled-ip)

With `--process-evidence` the same scan indexes Process v2–v4 lifetimes and
v2–v5 defunct records by payload PID and callback ordinal. A real start and
end must enclose the qualified thread records in both ordinal and raw clock
order. The start ordinal identifies an instance within the pinned file.
Rundown and defunct records retain their distinct meanings. Combined process
and image evidence checks the loader boundaries for that instance, including
logger ID and clock order. Address-space identity and retained executable
bytes still require another source.
[ETL process evidence](TRACE_IMPORT.md#match-a-sample-to-a-recorded-process-generation)

With `--reference-image` the reader opens a second digest-pinned local file.
The existing PE identity parser consumes its read handle. A sample with a
process-bound image RVA can compare the loader's identifying fields against
that PE and hash a bounded range in a declared executable section. Reports
retain contradictory field values, the reference digest, and the distinction
between sampled addresses and bytes observed on disk. Runtime page contents
and the sample's code version require capture-time evidence.
[Reference file comparison](TRACE_IMPORT.md#compare-a-recorded-image-with-a-pinned-pe)

In build-evidence mode the ETL reader indexes the merger's v2 ImageID and
native RSDS records separately from the original loader records. It locates
each marker by event clock tick, logger, payload PID and image base, retaining
original ordinals on each boundary. Both endpoints must agree before a
sample can be compared to the explicit reference's CodeView identity. The
reference reader checks the declared debug directory and file bounds through
the same lease used for its SHA-256. [Merge-time build comparison](TRACE_IMPORT.md#compare-merge-time-build-identifiers)

`--etl-switches` uses the same pinned input and raw ETW callbacks to page
through Thread/CSwitch v2, v3 and v4. The event header and scheduler payload
retain their own IDs. An original record ordinal locates the switch across
all events in the file and a switch ordinal drives paging. The decoder retains
the wait-mode or flags byte according to the event version. The report exposes
the incoming wait-time value as recorded.
[Saved context switches](TRACE_IMPORT.md#saved-windows-context-switches)

The normalized trace query can consume a saved native CPU profile page.
It retains the report's byte hash, the reported ETL digest and the original
record and sample ordinals. Native page continuation and normalized query
continuation each operate within their own source. The native reader can
also reproduce a full page from a pinned ETL and compare its exact UTF-8
output with the report hash. [Profile import and replay](TRACE_IMPORT.md#query-and-reproduce-a-saved-etl-profile-page)

Both ETL readers can bind a replayed page to an ES256 capture statement.
The operator supplies an authorized role and public key. The verifier
checks the signature and both the length and SHA-256 of the original ETL.
A matching controller statement carries issuer-scoped session identity and
reported settings. A separate archive-witness role covers custody of the
file. [Signed capture statements](TRACE_IMPORT.md#verify-a-signed-capture-statement)

The sample and switch readers share a bounded capture-settings index.
EventTrace group-mask snapshots, PerfInfo sampling-interval records and loss
indications stay in callback order under the ETL digest. A row's file logger,
ordinal and tick delimit candidate witnesses. The sampling interval also
requires a complete timer collection bracket. Separate source settings in a
merged file can share a logger ID. Original session identity and capture
privilege require independent evidence. [Recorded capture settings](TRACE_IMPORT.md#read-recorded-capture-settings)

In interval mode a second pass indexes one preceding switch per CPU and
thread transitions for the TIDs on the page. It follows those TIDs across
CPUs and uses Thread v3 lifetime events to delimit numeric ID reuse.
Thread/ReadyThread v2 can divide an off-CPU span at a recorded ready point.
The report carries the original source ordinals and qualifies durations
against the whole file's clock, continuity and loss evidence. A TID filter
selects the page while replay still examines all switches.
[Interval evidence and limits](TRACE_IMPORT.md#reconstruct-scheduler-intervals)

## Imported execution samples

`--offline !kmon trace` imports the versioned normalized format described in
[the trace contract](TRACE_IMPORT.md). It returns before live driver/symbol
initialization and reads a bounded local file through `ReferenceArtifact`.
The lease denies ordinary writes/deletes; the exact input SHA-256 and page limit
bind continuation cursors. Source/boot/VM/VTL/clock, process/thread generation,
address-space root/epoch, retained code hashes and explicit loss intervals remain
separate fields. Missing context does not borrow the current host's identity.

`qualified_reported_level` describes internally consistent producer metadata:
X0 references, X1 saved context or X2 CPU samples. It is not authenticated
execution. `execution_observed`, independent execution verification, control-flow,
write and actor claims remain false. Conflicting retained code versions or
context mismatches stay unqualified. Hash agreement verifies supplied bytes,
not their original acquisition or runtime mapping. Pagination completion does
not mean continuous or loss-free execution coverage. Raw PT/TTD/ETW decoders,
actual live collection and VMI providers remain unsupported by this adapter.

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

`NativeObservationSource` binds a kernel or qualified process virtual-memory reader to a collector
process creation time and device-open epoch, checks the paging descriptor around
each read, and preserves short reads. This detects connection replacement; it is
not a kernel-object lifetime proof, a boot/VM identity or an atomic snapshot.
The caller still owns the device and serializes its lifecycle with scan work.
Its optional versioned read transport retains raw NTSTATUS and transferred bytes;
qualified older drivers explicitly retain the unavailable raw-status contract.
Pending-IRP parsing uses bounded chunks up to its existing
128 KiB total limit and retains its repeated-read comparison. The kernel virtual
branches of execution-reference parsing use the same interface. Physical-page
and user-process fallbacks retain their existing collectors.

`ProcessObservationSource` now supplies the handle-based branch of the user
image comparison reader. It owns a non-inheritable duplicate of the supplied
process handle, preserves its access rights, and matches the expected PID and
creation time before and after each `ReadProcessMemory` call. Closing the
caller's handle cannot redirect a retained source to a reused handle value.
Its source identity includes the collector and target process generations and
the declared user address shape. It does not qualify target object layouts,
WOW64/JIT semantics, address-space mapping epochs or boot/VM identity.

During an image sweep, the controller records the original open and links the
source's duplicate to that acquisition. When the open identifies a different
process generation, the sweep skips the duplicate. Reference verification
checks the queued generation before querying an expected PEB. Ordinary
user-page capture checks it before querying a region. Diagnostics that carry
an observation use its boot ID, PID and creation time for deduplication and
retain those three fields on the event with `identity_source=supplied_observation`.
Object addresses and session assertions require separate evidence. A PID-only diagnostic records its
limited-query open when looking up the current generation.
[Observer handle records](TIMELINE_COMMAND_USAGE.md#inspect-process-handle-ownership)

This source admits user ranges only, requires explicit residency consent, and
discards every failed or short copy. A failed later chunk also discards the
earlier assembled bytes. Original Win32 read status is retained; the common
read JSON exposes `native_status` as an integer or null when unavailable.
Creation-time matching is not proof that a process remains alive:
[`GetProcessTimes` exit time is undefined for a live process](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes).
The owned handle identifies the object; reads still may fail after exit or
mapping/protection changes, and cancellation cannot interrupt the synchronous
Win32 call. The existing PID/EPROCESS/creation-qualified native fallback remains
separate. These branches do not yet publish a unified per-read receipt or native
verification recipe. Other user-process readers retain their previous paths.

`BundleObservationSource` owns an immutable copy of a validated v1 bundle and
binds its ID to the canonical payload hash, including identity and captured bytes.
Replay uses this source with the existing code-target parser. Conflicting valid
bytes remain conflicts regardless of read order; failed and skipped spans never
override captured bytes. The hash establishes content identity, not acquisition
authenticity. New timing fields measure replay access, not original capture time.

Native virtual reads can change residency, as described by
[MmCopyMemory](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-mmcopymemory).
Migrated collectors explicitly opt in to preserve their prior behavior. This
does not implement the separate driver-enforced observe/collect policy. The
qualified dump adapter is described later in this file. DbgEng, broader
user-process/translation migration, operation-wide deadlines and target-object
lifetime qualification remain open work. The evidence harness exercises the same
target parser on owned current-process memory and stored bytes, alongside sparse,
conflict, budget, cancellation, source-change and multi-chunk failure controls;
that test does not validate a live kernel target.

`tools/validate-process-source.ps1 -Sanitize` exercises the actual Win32 adapter
against owned pages and handles: caller-handle closure, missing access,
identity mismatch, denied collection, cancellation, sparse/protected pages,
discarded partial reads and handle cleanup. Its independent JSON oracle checks
status/identity/side-effect fields without treating test assertions as malware
samples or as evidence of actual LA57, HVCI or protected-process support.

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
| `user/SymbolEngine.*`, `NativeDisassembler.*`, `DbgEngBackend.*` | Brokered symbol/type metadata, Zydis disassembly, optional DbgEng commands |
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
transport.

On current `main`, `wmain` resolves an explicit `--mode` before the generic CLI,
worker, controller and transport entry points. A reserved selector anywhere
else in the argument vector ends the request. The selected path has a closed
operation list and returns directly. It has no dispatcher for command text,
driver startup, collection, MCP or remote sessions. The boundary covers one
process invocation. Principal scopes on an existing controller, kernel-side
collection rights, protected transport and durable operation recovery remain
P14 work.

Inside an existing controller, `mcp on --observe` fixes the listener's scope
for its lifetime. Catalog discovery, queue admission and engine dispatch use
the same allowlist. Retained timeline queries and status are available on
authenticated loopback connections. Requests for collection, export and
mutation are refused before operation allocation. The scope applies to all
clients of that listener. Queue admission, retained-event traversal and result
publication draw from the same listener lifetime. Operation lookup stays on
the control path when a quota is exhausted. [MCP observation quotas](MCP_SERVER_DESIGN.md#observe-listener-budget)

An optional private observe journal records admission and dispatch before the
engine runs, and the engine return before the client receives a terminal
receipt. Reopening the store restores metadata for lookup by operation ID.
[Private operation recovery](MCP_SERVER_DESIGN.md#private-operation-recovery)

An observe listener can bind up to 16 bearer fingerprints to individual
retained source labels. Each grant has its own protocol session. Evidence
readers share the listener budget and receive projected rows. A separate
permission allows lookup of the principal's live or recovered receipts.
The local audit retains correlation IDs for evidence-only calls. A TI grant can further
restrict queries to an event header process identified by boot ID, PID and
creation time. Each tool call in that scope requires an expiring handle.
Other producers and target roles still need authenticated identity evidence.
[Process-lifetime observation](MCP_SERVER_DESIGN.md#process-lifetime-observation)

Offline trace queries take their input from an inherited disk handle. The
reader checks the granted read, attribute and synchronization rights and asks
the I/O manager whether the device is remote before querying the filesystem.
It requires a fixed local volume and skips files marked offline, reparse or
recall-on-access. It reopens the same file object with no-recall and an
independent file pointer. The lease excludes writers and delete access. The
reader repeats the checks before reading and hashing the bounded contents.
It requests the opened name on a volume GUID path. Windows assigns these
paths to local volumes. [Windows handle name contract](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew)

Observation adds a single explicitly consented read of the caller's own
control range through a query/read handle. Its code path cannot open the
native device. The capability response distinguishes a policy exclusion from
a failed native connection and records which probe actions were attempted.
See the [launch syntax and input requirements](COMMAND_REFERENCE.md#restricted-one-shot-launches).

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

The main engine owns DeviceClient and serializes symbol metadata generations.
Approved local image/PDB artifacts are parsed by restricted DIA workers; parent
queries use verified bounded metadata. Missing fields or symbols must remain
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
a stale watch when a PID is reused. Reference verification rotates with event
ingestion under the shared analysis budget, retaining its pressure preference. IAT walks
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

### Local current-view ordering

`kn.local_entity_order.v1` admits an independent process or reference path even
when its observation tick precedes another path's latest tick. The arrival
watermark controls the 30-second freshness window; it is not a global minimum
event time. All ticks admitted by this live reducer must use one collector's
monotonic millisecond clock. Target boot IDs namespace identities, and producer
names describe sources; neither supplies a conversion for foreign clocks.

The reducer keeps up to 16,384 ordering guards separately from its 512 current
references and 2,048 receipts. A pointer path is identified by process generation,
slot and role; a slotless chain uses its root and role. Page guards constrain
conflicting observed mapping-generation labels. They do not establish OS mapping
lifetime. Guards retain known optional identity assertions, survive current-row
eviction and retirement, and expire only when their protected ticks are outside
the arrival freshness window. A late retirement cannot remove a newer reference.
Creation FILETIME is a generation key, not an ordinal clock: a newly observed
generation may have a smaller creation-time value. An observed transition retires
the previously retained generations; a delayed old generation cannot revive them.
A different generation cannot replace a later observation with an earlier event
tick. These constraints remain bounded by retained guards, not the whole boot.

When the guard table is full, a new key receives `current_capacity`; existing
keys can refresh. An observation or retirement that cannot retain its own guard
establishes a reported conservative tick floor. A denied observation withdraws
that process's current rows; a denied generation transition still retires its
known prior generations. This pressure fallback can defer independent observations
at or below the floor. `!kmon cases /json` reports retained/expired states, capacity, deferrals,
arrival watermark and that floor under `ordering`. Saved analyst snapshots retain
and validate these limits as coverage evidence. Legacy snapshots without this
block remain readable with a different coverage scope.

Same-tick changes use arrival order for the bounded display and do not establish
temporal precedence. Within a priority class, current rows are evicted by arrival
sequence; page candidates still cannot evict execution references. Foreign-clock
adapters, per-CPU loss watermarks, source restart correspondence and complete
temporal coverage remain separate requirements. No receipt or bundle format,
driver ABI, execution claim or cross-collector join authority changes here.

### Durable hunt evidence

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

`SymbolEngine` obtains the expected GUID/age from the local image's bounded RSDS
record and checks its size against the module inventory. The restricted worker
opens DIA over approved read-only PDB handles and compares the opened global
scope's GUID/age. A missing property is unavailable, not a zero-valued match.
The parent compares image/PDB/provider content hashes and rechecks the held file
objects before accepting either a layout package or a symbol index. Rejected
artifacts do not trigger an in-process provider fallback.

GUID/age matching prevents ordinary wrong-build and replaced-cache confusion;
it is not a content hash, an approved distribution signature or collector
authentication. Full loaded-image identity binding and approved distribution
remain separate work.
`tools/validate-pdb-identity.ps1 -Sanitize` compiles two owned PE/PDB pairs and
checks the actual DIA provider against matching, wrong-age, wrong-PDB and cache
replacement controls without loading a driver or target image.

### Local type schema packages

`--schema create <image> <pdb> <exact-type> <new-output>` exports one AMD64 UDT
as private `kn.type_schema.v1` JSON, normally a `.knschema` file. The operation
runs before controller construction and uses only the supplied local artifacts
and the packaged DIA DLL. It performs no symbol download or live memory read.
`--schema inspect <package>` checks and reconstructs the package without DIA.
Live metadata caching and its serialization lock remain separate from package inspection.

The package records PE/PDB/provider SHA-256, PE machine and image size, canonical
PDB GUID (32 hexadecimal digits) and age, provider file version, root size and
explicit field path arrays. Offsets are bytes from the root; storage sizes are
bytes, while bit positions and widths are bits. Symbol tags and base-type codes
use the DIA contract. Ordinary members have zero bit width. Embedded UDT fields
can expand to eight path components; pointer values and array storage are leaves.
Base classes, unsupported field types and depth limits remain explicit gaps.
Unavailable member properties create a gap on their containing path. Bounds
cover each field's root and embedded parent; unions may intentionally overlap.

`DiaTypeLayout` supplies the schema worker's member decoder. It requires `S_OK` for
offset/size properties and uses `LocIsBitField` to distinguish units. Previously,
`SUCCEEDED(get_bitPosition(...))` treated an unavailable `S_FALSE` property as a
bitfield at bit zero. Actual compiler-generated PDB controls reproduce that case
and compare the corrected offsets, storage and bit widths with C++ layout.

Generation holds read-only, no-write/no-delete leases on local fixed-drive regular
files, rejects final reparse points and device/stream paths, and rechecks identities
and content after parsing. Limits are 512 MiB PE, 1 GiB PDB, 64 MiB provider, 8,192
direct DIA data members, 4,096 package fields/gaps, 16 MiB root/type extent and
2 MiB serialized output. Hashing and recursive traversal check cooperative
30-second budgets; an individual synchronous I/O or DIA call is not interruptible.
The existing create-new, flush-and-rename writer preserves output collisions.
Inspection accepts only canonical versioned JSON with its payload SHA-256 and
valid path/extent/expansion relationships; a self-consistent hash is not approval.

These are layout packages, not runtime object validation or authenticated symbol
distribution. `runtime_invariants_checked=false` and `trusted_distribution=false`
remain fixed. `parser_isolated` is producer-reported provenance: new CLI exports
record true, direct-library and legacy exports retain false. Inspecting a package
does not authenticate this field or retroactively run its parser in isolation.
Attaching package hashes to typed observations, supported-build fixture
attestations and isolation of other untrusted parsers remain open. Files and
renamed JSON packages are excluded by the sensitive-content gate.

### Schema parser process boundary

The public schema creation command now starts the same executable in an internal
worker mode. The artifact broker opens and hashes the image, PDB and adjacent
installed DIA provider before starting it. The parent also uses the existing
bounded PE decoder's identity-only path to obtain the expected machine, image
size and RSDS GUID/age, stopping before managed-image and relocation tables;
it does not load DIA or parse PDB types. The worker checks its token, private
desktop and job limits before parsing. Parent-side success requires a zero child
exit, strict bounded UTF-8/canonical package parsing, exact requested type and
equality with the parent's image/PDB/provider hashes and PE identity. The parent
rechecks all three original file objects before returning a usable package. Only
the parent publishes the package; timeout,
crash, output overflow or setup failure cannot publish partial child output.
There is no in-process fallback. Existing schema inspection remains a bounded
JSON operation in the command process. Live layout APIs reuse this boundary as
described below; symbol lookup and type enumeration use the bounded index worker.

The broker passes three read-only file handles. The runner reopens each file
object with an independent cursor and includes only those copies in the child
handle list. Inside the worker, readers duplicate those approved handles with
read-only, non-inheritable access; they do not require a second pathname access
check under the reduced token. The parent retains the original leases that deny
writers and deletion. PE decoding uses the approved image handle; DIA receives a bounded
read-only `IStream` over the approved PDB handle, followed by a GUID/age check on
the DIA global scope. It uses neither `loadDataForExe` nor a symbol-search path.
Stream clones have independent cursors and serialize access to their shared
handle. Hashing, PE reads and stream reads use explicit byte offsets, so other
duplicates changing the shared file object's implicit cursor cannot change the
selected bytes. A private completion event also supports overlapped input handles;
the read waits for completion before releasing its operation state. Its event
suppresses [completion-port notification](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-getqueuedcompletionstatus)
so a caller-owned port cannot receive the reader's temporary operation pointer. This remains
synchronous I/O with cooperative outer budgets, not a hard cancellation deadline.
Existing parent-facing APIs reopen by default and preserve the caller's cursor.
Overflowing seeks, writes and truncation fail. This follows the
[DIA stream input contract](https://learn.microsoft.com/en-us/visualstudio/debugger/debug-interface-access/idiadatasource-loaddatafromistream)
and Windows [explicit handle inheritance](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
and [explicit-offset read semantics](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile).

Windows loads the approved provider DLL by pathname from a code-only runtime
under `%LOCALAPPDATA%\KnLiveDbgParserRuntime-v1`. The parent copies the trusted
executable, approved DIA provider and, when present, its adjacent ASan runtime
into a content-addressed directory. Its protected ACL grants the owner and SYSTEM
full access and All Application Packages read/execute access. Every use checks
the exact file list, owner/ACL, content hashes and non-reparse pathname pins.
Unexpected DLLs, changed bytes and writable package grants make setup unavailable.
Image/PDB inputs remain handle-only; their original ACLs are unchanged.
The parent retains source and copy leases plus ancestor pins until child cleanup;
the child verifies that the loader pathname still identifies its inherited provider.
Completed code copies persist for reuse. Interrupted copies are recovered only
after the creating process is proven dead, using checked handles and the exact
known code filenames. The executable and DLL remain trusted runtime inputs;
hashes do not attest provider authenticity or approved distribution.
The public command and `kn.type_schema.v1` format remain compatible. Old packages
can still be inspected, but their producer-reported identities are not converted
into a fresh broker verification by inspection.

The child receives a filtered primary token and a unique zero-capability
AppContainer identity: administrator SID is deny-only,
privileges other than traverse are removed, integrity is low and the inherited
no-write-up policy is checked. Its restricting SID list retains the current user,
standard read-access groups and logon SID needed by the window station. A new
private low-integrity desktop grants access to that AppContainer SID and is
released with the request. These
choices follow the Windows [restricted token contract](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken)
and [mandatory integrity model](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control).
The parent supplies only OS-derived SystemRoot/WINDIR and the profile's
LOCALAPPDATA. Windows adds profile-local TEMP/TMP during AppContainer creation,
as described in the [AppContainer launch contract](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer).
Handle
inheritance is limited to three approved read-only artifact copies, one output
pipe and a NUL input handle; controller,
token and credential environment handles/values are not forwarded.

Before resuming the suspended child, the parent verifies its actual token,
AppContainer SID, empty capability set and assignment to the exact job. It also
requires running BFE and Windows Firewall services and checks that the SID has no
[loopback exemption](https://learn.microsoft.com/en-us/windows/win32/api/networkisolation/nf-networkisolation-networkisolationgetappcontainerconfig).
These checks only read policy; they create no firewall rules or exemptions.
Setup fails closed. The parser has no network capability and cannot use the
parent's artifact acquisition path.

A private owner/SYSTEM receipt under `%LOCALAPPDATA%\KnLiveDbgParserProfiles-v1`
is flushed and published before native profile creation. Its name includes the
parent PID, process creation time and a random nonce. The profile and receipt are
removed before the child resumes. On a later launch, recovery checks the receipt's
owner, ACL, format and contents and requires authoritative owner exit or PID reuse;
it preserves live or uncertain owners. Corrupt published receipts fail closed.
Interrupted unpublished receipts are discarded without assuming a native profile
exists. Profile failures retain the native HRESULT separately from Win32 errors.

Windows 10 or later is required for atomic job assignment through
[PROC_THREAD_ATTRIBUTE_JOB_LIST](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute).
The job allows one process, limits committed memory to 512 MiB and kills its
worker when the final parent job handle closes. A suspended child is resumed
only after these checks and profile cleanup. Parent supervision caps stdout and
stderr together at 2 MiB by default (symbol indexes explicitly allow 32 MiB),
checks cancellation and enforces a 60-second elapsed
budget once process creation returns. Failed cleanup is explicit; synchronous
OS process creation/termination is not a hard real-time deadline. A large PDB
can fail the memory budget even if it passes the input-file size limit. Existing
host job or desktop restrictions can make setup unavailable.

This boundary contains selected parser faults and resource use. It uses an
ordinary AppContainer, not LPAC or an exhaustive filesystem allowlist: ordinary
AppContainer access to shared system resources still applies. Its trust assumptions
include Windows policy enforcement and the parent/runtime owner; it is not a
defense against a hostile host administrator. The dated validation includes owned
IPv4/IPv6 TCP/UDP loopback delivery controls, not an external-network or every-policy
matrix. Runtime object/anchor binding, approved distribution, authenticated parser
attestation and isolation of all untrusted parsers remain open.
Parent artifact hashing has a cooperative 30-second limit per hash; the child
timeout is not a hard deadline for the whole broker operation or synchronous I/O.

### Live type layout broker

`SymbolEngine::GetTypeLayout`, `GetTypeLayoutById`, `GetTypeFields` and `FindField`
now consume broker-accepted schemas. A type request discovers module metadata
without registering its image in DbgHelp. The resolver reads the local image's
bounded RSDS record and uses only the PDB basename, GUID and age to find artifacts.
It checks the module-reported image size; this is not a comparison with bytes read
from the loaded target image. PDB type parsing runs in the restricted worker and
cannot fall back to parent DbgHelp or DIA when unavailable.

Exact type spelling takes priority. Live compatibility lookup can ignore case
and leading underscores only when the bounded UDT search finds a unique match;
the parent checks that the returned canonical type belongs to that alias. Offline
`--schema create` retains exact spelling. `FindField` similarly prefers exact
member spelling, rejects ambiguous case-folded matches and checks the cumulative
offset against the root and each embedded extent. Pointers, arrays and depth-limit
leaves are not traversed. Field descriptions retain ordinary base/pointer/array
names, while bit width and storage size remain distinct.

The cache retains at most 32 roots, 8 MiB of encoded packages and 32,768 layout
nodes. IDs are process-unique opaque references, distinct from the native IDs
displayed by the index-based type-enumeration path. Reset, symbol/module-state
changes, eviction or replacement invalidate IDs; an old ID cannot resolve to a
new node. Nested nodes carry offsets relative to their own object. Schema hashes
are retained on layouts and fields, and unavailable coverage is explicit, including
an unknown count when the package contains only a gap reason. `dt` prints the
schema hash and `runtime_invariants=unchecked`, and shows incomplete field coverage.
These facts do not qualify a runtime object, authorize a distribution or establish
an allocation lifetime. Cached results represent the accepted artifact generation,
not continuous revalidation of disk files or loaded target memory.

The artifact resolver accepts local roots, `cache*<local-root>`,
`srv*<local-root>`, and `srv*[<local-cache>*]https://<server>`. It probes flat
files and SymStore GUID/hex-age paths. Local path spelling is checked before any
filesystem probe; UNC, device, drive-relative, stream, reserved-name and Win32
trailing-dot/space aliases are rejected. Cache ancestors are pinned and reparse
directories are rejected. The SymStore index follows Microsoft's
[symbol reader implementation](https://github.com/microsoft/perfview/blob/main/src/TraceEvent/Symbols/SymbolReader.cs).

Downloads happen in the parent, through direct HTTPS with normal certificate
validation, no proxy, cookies or implicit Windows authentication. URL userinfo is
rejected and at most three HTTPS redirects are allowed. Transfers are capped at
1 GiB with five-second I/O timeouts and a cooperative 60-second acquisition budget.
The downloaded temporary file's original identity is checked, then its read-only
lease stays held through parser validation and create-new cache copying. The
destination is exclusive until flush/close; a copy failure marks that open object
for deletion. A collision preserves the existing file. Temporary cleanup checks
file identity and cannot remove a substituted file. A process/power interruption
or an I/O failure can leave an incomplete cache entry, which must pass a later broker verification;
it is never treated as a valid layout merely because it exists.

Compressed/pointer stores, authenticated servers, proxy configuration, recursive
SymSrv cache chains and automatic replacement of invalid entries are unsupported
by this resolver. The child receives no search path or download request and runs
inside the zero-capability AppContainer boundary above. The pending-IRP consumer
now applies the bounded runtime binding below. Other typed consumers, approved
build/layout validation records and full parser isolation remain open P05 work.

### Pending IRP schema and runtime binding

The live scanner retains the complete parent-accepted `_ETHREAD`, `_IRP` and
`_IO_STACK_LOCATION` schema packages. All three must share the image/PDB/provider
hashes, PDB GUID/age, machine, image size and provider version, and come from the
same reported module base. Required field paths must have one unambiguous,
non-bitfield storage location within their validated embedded/root bounds.
Missing or ambiguous optional cancel/status/device/file fields remain unknown.

Unavailable/cancelled native sources fail before symbol acquisition. Before
reading objects, a fresh read-only image lease must match the schema's
image hash and PE/PDB identity. The actual observation source then supplies the
loaded PE headers and RSDS identity before and after the object scan. The same
source contract and native connection epoch govern the reads. Existing IRP
type/packet/stack/owner checks, reciprocal list checks, repeated packet reads and
thread PID/TID/create-time rechecks still apply. Enabled completion references
must be in the source descriptor's kernel address range.

`qualified_observation` describes these recorded policy invariants only. It does
not establish an approved Windows build, whole-image integrity, process creation
identity, execution or an allocation lifetime. A final image/source/reference
failure preserves decoded candidates and original reads but prevents their
registration as observed completion targets. An initial identity failure stops
object decoding. Equal repeated reads cannot exclude ABA replacement.

One `kn.irp_capture.v2` artifact preserves the three canonical schemas, reference
identity metadata, supplied thread inventory/cursor, results and ordered parser
reads with their original statuses and bytes. It also records the initial source
contract, boot-tick interval, final cancellation/source-contract checks and the
number of captured reference bytes. A bounded image snapshot comes from the same
approved image handle. The PDB file and source-initialization activity are not
retained. The read operation admits at most
256 KiB, 2,048 source calls and 4,096 receipts over five seconds. Input inventory
is capped at 16,384 threads; the existing per-scan object/walk limits still apply.
Encoded capture size is capped at 16 MiB. Incomplete capture/operation state
cannot qualify a result. The boot-tick report interval and the recorder's steady
clock are identified separately.

KMON request events reference the capture SHA-256. The queue and its writer
share four slots and a 240 MiB byte bound through the
[IRP priority partitions](#irp-retention-priority). Each capture is at most
16 MiB and each image at most 64 MiB. This bounds queued and writing artifacts;
the producer's current capture is separate. Partitioned session allowances
limit newly published capture/reference files to 320 MiB, excluding metadata.
New `.knirp` files require an already initialized private evidence store in the
configured log directory. The existing store policy determines ACL-only or EFS
protection; there is no automatic initialization or encryption downgrade. The
writer checks the actual new file handle before writing bytes, flushes and
renames without replacement, and records publication success/failure separately
from queue admission. An `irp-reference-<sha256>.knblob` in the same checked root
is created without replacement or reused only after hash, size and privacy
checks under a read-only lease. Reference failure does not erase the original
capture; its publication event records the gap. A `.knirpledger` records final
queue counts, bytes, pending reservations and reference creation/reuse/failures.
It includes unavailable pre-encoding captures and per-class retention counters;
these failures require a final ledger even when no raw capture was queued.
A missing private policy causes a publication failure,
not a silently successful capture. These formats and pending files are excluded
from source publication even when a JSON artifact is renamed.

`KnLiveDbg.exe --offline !kmon replay-irp <capture.knirp> /json` uses the same
schema resolver, image-identity checks and IRP reader against the saved ordered
calls. Every address, length, accepted/rejected result and final canonical
capture must agree, including counters, graph, optional fields and pagination.
The importer explicitly allows up to 16 MiB; existing generic read importers
retain their 2 MiB default. Incomplete traces, forged summaries, unknown policies
and unused or reordered calls cannot produce a matched replay.

The fixed sibling reference name comes from the validated schema hash, never an
imported pathname. For a bare v2 capture, missing reference bytes allow a reported
metadata replay but cannot reproduce `qualified_observation`. A present
conflicting image rejects replay. Exact image/hash/PE/RSDS validation enables the bounded qualification;
it authenticates neither the collector nor the declared external final state.
The command does not open a live source, download symbols or reparse a PDB.
Legacy v1 files remain intact and report their missing source/final-state inputs
instead of inventing them. Request observation v1 and the native IOCTL ABI are
unchanged.

The writer commits each published capture or claim publication and any successfully
retained reference to the typed journal. `irp_journal_captures_*` and
`irp_journal_ledger_*` distinguish membership from file publication; a published
file can remain uncommitted. The ledger's own `journal_membership:false` is a
prepublication statement: membership comes from the external verified journal.
IRP publication installs the private-root admission check on journal/index
outputs before their first byte, and checks earlier pinned files when joining
an existing image journal. Store inventory, exact-byte deduplication and explicit
uncommitted GC cover these root files without upgrading their replay or source
authenticity claims. Unknown tails and failure ledgers remain protected.

Approved build/schema change handling, real native-driver lifecycle evidence,
committed-root retirement and cross-session retention remain open.
Journal integration controls are recorded in
[validation](VALIDATION.md#irp-journal-and-retention-checkpoint-2026-11-07).
Owned DIA/offset/read-byte and replay controls are recorded in
[validation](VALIDATION.md#pending-irp-offline-replay-checkpoint-2026-11-07).

#### IRP retention priority

`kn.irp_retention_partition.v1` separates `first_observed_state`,
`observation_gap` and `repeat_or_empty`. They have respectively two, one and
one queue/writer slots, with round-robin service across nonempty queues.
Each class has an independent 80 MiB memory bound, enough for one maximum
capture plus reference. A ticket holds both slot and bytes until its last
owner releases it, including the writer's in-flight work. Classes cannot borrow
each other's allowance. The earlier combined 128 MiB bound is replaced by this
240 MiB bound so a maximum-size repeat cannot consume the first/gap reserves.

New capture files have separate 64/32/32 MiB session budgets; references have
64 MiB per class. Thus the maximum newly published raw data is 320 MiB per
session. Already retained references cost zero after exact hash, size and
privacy checks. Newly published bytes remain charged if a later check or
journal commit fails. These limits do not reserve physical disk space or
cover journal/index/event metadata, the producer's current artifact, or prior
sessions. Missing encoded artifacts contribute to the unavailable denominator
without competing for raw-file slots or bytes.

Priority signatures come from the same captured result. They bind the exact
source contract, image base, all three canonical schema packages, thread
PID/TID/address/create-time, IRP address and typed packet/stack fields. Unknown
optional fields remain distinct from zero/false. Scan times, operation IDs,
cursor position and aggregate counts do not change the signature. Coverage
gaps remain a separate flag. A signature identifies recorded state only:
it does not prove object lifetime, exclude address reuse, or classify risk or
maliciousness. First priority is not a high-risk verdict.

An unseen state receives first priority. An identical pending state uses the
repeat/gap class; it cannot occupy another first slot. The state becomes saved
only after the capture and required reference belong to a committed journal
batch. Failed publication remains eligible for first priority after its pending
tickets drain. Up to 8,192 keys are tracked per recording session, with at most
256 keys per capture. New keys denied at that bound are counted, never silently
classified as repeats. Unkeyed states retain first priority; saved keys do not
cross sessions.

The final `kn.irp_retention.v1` report records attempts, admissions, resource/key
denials, unavailable/invalid input, finished/complete/abandoned work, current and
peak reservations, and physical file-byte charges by class. Publication events
identify their selected class. Final ledgers retain these denominators even
after raw-file budgets are exhausted. Actual writer quota, reference-retry and
concurrent admission checks are recorded in
[validation](VALIDATION.md#irp-retention-priority-checkpoint-2026-11-07).

#### IRP claim policies

`kn.claim_registry.v1` supplies code-owned deterministic requirements for seven
IRP claims under `kn.irp_claim_policy.v1`. The adapter consumes the bound
collector's original result or a canonically matched ordered-read replay.
Imported booleans alone are not inputs to the evaluator. The four outcomes are
`supported`, `contradicted`, `unfulfilled` and `not_applicable`.

| Claim | Supported scope or missing evidence |
| --- | --- |
| Thread-list membership observed | Captured reciprocal path and thread checks; no referenced allocation lifetime |
| Packet owner matches thread observed | Typed `IRP.Tail.Overlay.Thread` equals the observed thread after the reader's checks |
| Completion registration observed | Typed stack role, enabled control bits and a nonzero kernel target; disabled bits or a null target contradict this scoped registration |
| Request completion observed | Unfulfilled without provider-bound request generation and a completion event/outcome |
| Request cancellation observed | Unfulfilled without request generation and a cancel completion event/outcome; `Cancel` and `IoStatus` samples do not satisfy them |
| Completion execution observed | Unfulfilled without request generation, an execution event and code-version binding |
| Device-driver ownership observed | Unfulfilled without typed owner fields and referenced device/driver lifetimes; a pointer alone is insufficient |

Every claim first requires original recorded reads, one stable declared source
scope, exact schema/image binding and the reader's request invariants. Missing
reference bytes or a failed final source/image check prevents both positive and
negative qualification. Only within this qualified scope may the absence of an
enabled completion reference, or an explicitly null device pointer, make the
corresponding execution/ownership claim `not_applicable`. This says there is no
applicable subject in that observation; it says nothing about earlier execution.
Missing optional fields remain `unfulfilled` instead of becoming null pointers.

Each result carries capture SHA-256 plus JSON pointers for supporting and
contradicting facts, the unfulfilled requirements and a bounded next-observation
suggestion. The evaluator rejects duplicate/unknown facts, missing evidence
references and mixed-capture evidence. Suggestions identify their required
collection mode and unresolved requirement; they do not authorize or execute
an operation. A supported recorded-state claim never implies execution, a
writer, maliciousness, host cleanliness, request lifetime or deadlock.

`kn.irp_claim_report.v1` separates seven ledgers. Discovery preserves the supplied
thread denominator, limits, cursor and unverified candidates. Address coverage
uses unions of recorded parser-call ranges: requested bytes equal accepted
bytes plus failed-only bytes. Repeated reads increase traffic without increasing
that union. Unvisited addresses outside recorded calls remain unknown; no
compared image bytes are claimed. Temporal coverage names the scan clock and
interval without claiming continuous or atomic observation. Semantic,
persistence, replay and trust ledgers distinguish layout checks, in-memory
encoding, verified files, unchecked journal membership, current-policy analysis
and unauthenticated collector declarations.

Reports emit at most 128 claims and 128 Ki UTF-16 code units. They retain the
exact possible/emitted/omitted denominator when the output bound is reached.
`report_complete` refers only to this claim projection, separately from discovery
coverage. A partial inventory can still support an admitted request's local
claim. An empty or failed inventory never yields a whole-host clean claim.

KMON retains `io.claim_assessment` and `io.request_observation` as kernel
observations independently of process-watch filters; normal live printing is
suppressed while the ring and log retain them. Unavailable assessments emit
`coverage.irp_claims`. Capture-time reports remain derived event metadata outside
the raw capture reservation. `replay-irp` output adds `claim_assessment` only after
canonical replay; invalid captures expose no partial claim result. These offline
reports use `current_policy_on_replayed_observations`; original report reproduction
is a separate outcome described below.
Capture v1/v2 bytes, request observation v1 and the native ABI remain unchanged.

#### Original IRP claim publication

After preserving the fixed sibling reference, the KMON writer recomputes the
capture from its retained ordered reads and evaluates its Capture-mode report.
It writes one canonical `kn.irp_claim_publication.v1` root with `payload.capture`
containing the unchanged v2 capture and `payload.recorded_claim` containing the
frozen report. `publication_sha256` hashes the exact UTF-8 payload, without a
circular self-reference. The whole publication shares the existing 16 MiB file
limit and remaining per-class capture budget. It adds no queued report memory
and performs no new target read, symbol lookup or PDB parse.

If original inputs, report generation or the added byte budget are unavailable,
the writer retains the bare capture and records `original_claim_failure`.
`coverage.irp_capture` distinguishes `original_claim_persistence`, physical file
hash, original capture hash, publication hash and report hash. Its existing
`capture_sha256` continues to identify the raw observation used by request/claim
events; `physical_capture_sha256` identifies the saved file. Final `.knirpledger`
fields `claims_written` and `claims_unavailable` count publication outcomes,
separately from journal membership. Durable byte accounting uses the whole saved
file. Journal v4 binds this physical hash in the filename, transaction ID and
member; a transaction still contains at most the publication and one reference.

Default `replay-irp` first requires the recorded registry/policy, reconstructs
the complete raw capture and regenerates the Capture-mode report. Only exact
report equality gives `original_claim_replay.status: reproduced`. A missing
reference that was used by the original report fails this reproduction. Unknown
policies, changed reports or missing inputs expose no successful summary, current
claim or request result. `/current` explicitly skips original claim reproduction
and reports `not_requested`; it still requires canonical raw replay and reports
unqualified current claims when the reference is missing. Legacy bare captures
report `not_recorded` and retain their prior replay behavior.

In replay JSON, `capture_sha256` is the physical file hash and
`original_capture_sha256` is the embedded raw hash. Claim evidence pointers are
relative to that original capture, not the publication envelope. The separate
`original_claim_replay` includes publication/report hashes and recorded policy
identity. It does not change the frozen report's prepublication persistence or
replay statements. Reproduction neither authenticates the collector nor checks
collection membership. Current `claim_assessment` remains a Replay-mode report;
it is not compared directly to the intentionally different Capture-mode report.

Other scanner adapters, cross-capture qualified joins, request lifecycle providers and native build/
lifetime validation remain open. The bounded IRP policy and publication-routing
controls are recorded in
[validation](VALIDATION.md#original-irp-claim-checkpoint-2026-11-17).

### Live symbol and type index broker

Startup preloading, `ResolveSymbol`, `FindNearestSymbol`, `EnumerateSymbols` and
`EnumerateTypes` now use an internal restricted worker. `Initialize` and module
discovery do not invoke DbgHelp or DIA. A worker enumerates image-relative
functions, data, labels, public aliases and thunks, plus class/struct/union, enum
and typedef name/size metadata. Typedef size lookup can follow at most eight
metadata aliases; an unavailable size remains explicitly unknown.
Type discovery uses the [DIA symbol table](https://learn.microsoft.com/en-us/visualstudio/debugger/debug-interface-access/idiasession-getenumtables)
so nested/local names omitted by global-scope enumeration remain available.
Lexical locals, register locations and absolute constants are outside this
index. Address enumeration follows the [DIA address-order contract](https://learn.microsoft.com/en-us/visualstudio/debugger/debug-interface-access/idiaenumsymbolsbyaddr);
public enumeration preserves decorated aliases. Private function/data names
retain their source scope, while public names use undecoration. Raw linkage
names remain lookup keys; control characters are escaped in display names.

The private `KNSYMIDX` version 1 frame has a 256-byte header containing three
artifact SHA-256 values, RSDS GUID/age, image size, machine and row counts. All
numbers are little-endian and strings are length-prefixed UTF-8. The parent
requires canonical sorted unique rows, strict string round trips, known tags,
explicit size availability, in-image RVAs/extents and exact frame consumption.
It checks artifact identity against its own leases and computes the index digest.
A matching digest identifies metadata; it does not attest provider semantics.
The frame is capped at 32 MiB and 200,000 rows per symbol/type table. Traversal
also has a cooperative 30-second budget and 64 MiB of accounted row data.
Type discovery visits at most 3.2 million provider symbols across its symbol table.
Bounds cause failure rather than silently publishing a truncated index.

The parent retains at most 16 module indexes and 128 MiB of accounted vector/
string capacity, excluding allocator overhead and temporary construction. Name
orders support binary search; address order supports nearest-preceding lookup.
Repeated address queries do not reopen a PDB or start another worker. Different
addresses for one undecorated name are ambiguous; exact linkage names can select
an overload. Unqualified lookup uses previously indexed modules, preserving the
rule that a missing bare field filter cannot download every deferred PDB.
The nearest preceding symbol does not prove that an address lies in its function.

Initialization, symbol-path changes and module refresh invalidate metadata and
failed acquisitions. Failure results are retained for that generation so scanner
hot loops do not repeatedly launch a failing parser. At most 512 successful or
failed module identities are admitted per generation. Enumeration shares a
cooperative 60-second acquisition/query budget, caps returned rows at 200,000
and accounted result data at 32 MiB, and reports unavailable modules and limits.
The CLI and MCP symbol search expose incomplete coverage. Type enumeration's
provider IDs are descriptive metadata, not the opaque IDs used for layout lookup.
Cached metadata represents the accepted disk-artifact generation, not continuous
revalidation or proof about a loaded target's bytes, object invariants or lifetime.
`.knsymidx` files and renamed frames are rejected by the publication scanner.

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
Shared analysis turns, image and layout scheduling are described below. Deadline
propagation through other scanners and native calls remains separate work.

## Shared analysis scheduling

At safe scanner boundaries, the analysis thread rotates through nine stages:
execution references, layout candidates, live events, TI events, I/O trace,
pipeline events, captured regions, watched references and image continuations.
The persistent cursor advances before invoking each stage, including a stage
that throws or exceeds its allowance. A boundary has a shared 250 ms cooperative
budget and dispatches each stage at most once. An allowance is at most 100 ms
and never exceeds the remaining turn budget or the stage's requested slice.
Existing smaller layout, ingestion and image budgets still apply. A later
boundary resumes the cursor; sustained reference/event pressure no longer
vetoes image continuation. Stage returns never renew successful target freshness.

Readiness snapshots use queue counts, due clocks and cheap live-binding checks.
Actual stages still qualify their sources, process instances and mapping/content
fences. Image count means resident work, including work waiting for preparation
or its own cooldown; I/O trace and watched-reference counts describe active
service opportunities. They are not a count of verified or eligible targets.
Snapshots are not atomic across queues. New work for an already visited stage
waits for another boundary. Pipeline events and captured regions have separate
turns. Ingestion pops only the next item being processed, so exhausted budgets
leave remaining items in their original queue.

Native calls, individual event handlers, module inventory, watched-reference
visits, I/O trace batches and mandatory final fences cannot be preempted by this
policy. They can overrun their allowance and the shared budget. Image setup
shares the original comparison clock and retains minimum first-page progress
even after slow preparation; otherwise consistently slow setup could prevent
all image progress. Bulk discovery scanners outside these boundaries and
explicit shutdown drains remain outside this analysis-turn budget. Discovery
has its own resumable group policy described below.

`coverage.pipeline.analysis_scheduling_json` carries private
`kn.analysis_scheduling.v1` diagnostics. It separates pending/dependency state,
first-observed continuous backlog age, dispatch/return/fault counts, budget
deferrals, actual overruns, active-stage time and service/dispatch-gap histograms.
Pending/dependency fields reflect the last scheduler readiness observation,
which can precede the active callback's queue changes.
Turn service includes the last callback even when it exhausts the stage list;
exhausted-turn counts mean the budget was reached at a later selection check.
Budget deferrals count ready unvisited stages at that check. Percentiles are
log2 bucket upper bounds. Invalid clock order halts the turn without wrapped
durations. These are runtime stage diagnostics, not a durable timing journal,
per-item acquisition times, native API latency or whole-source unobserved bounds.

`--self-test analysis-scheduler` exercises the actual dispatcher and budgeted
queues with owned guarded mapping metadata and an absent native binding.
The standalone core and independent Python oracle cover fixed/growing arrivals,
churn, blocked/rejoining stages, due clocks, slow calls, exceptions, stop,
recursive entry, clock reversal and final-stage overruns. They establish the
stated cooperative policy, not measured native workload SLOs or completion of P09.

## Resumable discovery scheduling

The analysis worker schedules 26 scanner phases in ten groups. It preserves
each group's phase order and rotates eligible groups after each scanner, rather
than running a whole mapper/user group before considering other due work.
Readiness uses current local due clocks and cheap native-binding checks. The
runtime subscription needs an open device; other groups also require the symbol
binding. These checks do not qualify a loaded module, layout or target. Each
scanner retains its existing source, identity and evidence checks.

| Group | Ordered scanner phases |
| --- | --- |
| Runtime | Runtime provenance subscription |
| Hidden | Process cross-view qualification |
| Mapper | Remnants, pool images, unbacked driver objects, module inventory, image integrity, driver tamper, callbacks, callback lifecycle, platform evidence, input hooks, graphics dispatch, graphics references |
| Kernel pages | CPU integrity, orphan mapped pages |
| User | Stale-watch pruning, watch logging, process triage, handle tables, handle capabilities |
| Inline | Kernel inline patches |
| Threads | Kernel thread checks |
| Channels | Communication surfaces |
| Kernel images | Executable image discovery |
| Page candidates | Admitted executable-page candidates |

The user discovery phase shares one process observation per PID across name
watches, child watches and logging records during a pruning pass. A recorded
creation-time mismatch, an invalid PID or a reported exit can retire a
promoted entry. An access error alone leaves its status uncertain. Explicit PID
watches retain their independent membership.

The file-handle scanner samples the owner before and after a complete native
snapshot and skips an owner whose exit code indicates termination. The
handle-graph scanner retains its owner handle across the device scan and checks
the process wait state before accepting the result. Both record their process opens and closes in the observer timeline.
A promoted owner must match its recorded creation time. Each watch registration
owns its file history and graph cursor. Removing the watch discards that state.
A scan still in progress can publish its batch only if the same registration
and owner generation pass the final check. [Handle scan receipts](TIMELINE_COMMAND_USAGE.md#trace-a-watched-handle-scan)

KMON holds a limited-query handle for the subject when it attempts to change
process logging. Pruning, manual removal and shutdown can request cleanup only
for a generation with an earlier successful request in this controller.
A known mismatch retires the local record. An unresolved identity produces
a cleanup diagnostic. The handle pins the original process object through the
existing control path. [Windows process ID lifetime](https://devblogs.microsoft.com/oldnewthing/20110107-00/?p=11803)

The observer timeline retains each KMON process logging backend attempt with
the acquisition ID of that identity handle. It records the native return and
the mask submitted for each information class. For a driver call, it checks
the response size, PID, class and reported flags before accepting success.
The client holds the device connection lock from the epoch check through the
return. A request carrying an old epoch cannot act through a replacement handle.
The legacy class can echo the requested mask even though it handles only
read/write VM logging. Verification of the target's previous and final
settings requires a separate observation. [Logging request fields](TIMELINE_COMMAND_USAGE.md#inspect-kmon-process-logging-requests)

An ambiguous enable result stays with the watched process generation.
Subsequent scans can recheck identity but cannot submit another enable for
that generation or take cleanup ownership from that result. Losing query
access preserves this record. Removing the watch or ending the KMON session
retires it. If the same process is watched again, a new uncertain request gets
its own acquisition ID and retry diagnostic. These logging setters require
`STATUS_SUCCESS` for cleanup ownership.
A pending, timeout, informational or warning result keeps its raw status and
leaves completion open. [Microsoft NTSTATUS values](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)

A discovery turn has a 250 ms cooperative budget that includes interleaved
analysis service between scanners. It admits at most one dispatch cycle per
group per turn. The worker first gives analysis its independent turn, then
discovery a turn; 250 ms is therefore not a bound on the entire worker loop.
Scanner-internal loops, nested analysis yields and native calls remain
nonpreemptible and can overrun. The outer policy cannot provide a wall-clock
revisit bound while a scanner itself remains blocked.

Each group retains its phase cursor, original cycle due time and separate
periodic/request clocks. Initial delay values and normal/watch interval values
are retained; the next periodic due time starts at the last scanner's return.
Actual cadence also includes waiting for other groups. Mapper events request both mapper and kernel-page
service; user memory follow-ups retain the two-second initial-phase cooldown.
Duplicate pending requests coalesce to their earliest due time. A request
received after cycle start remains for a later cycle, so urgent arrivals cannot
continually restart the current group's head or erase its unfinished tail.
Periodic rescheduling cannot overwrite that retained request.

Exceptions advance the failing scanner's phase and preserve later phases.
Failed cycles have separate counters/distributions. Analysis and discovery
boundaries handle exceptions independently, so a persistent analysis failure
cannot prevent discovery from being called. The worker observes its existing
50/200 ms idle delay after exceptions as well as returned turns. Stop observed
after selection but before scanner entry returns an explicit cancellation:
the selected phase and original cycle debt remain pending. Stop/reset does not
claim those phases were observed. Reset occurs only after the worker joins.

A scanner can also return `Continued`: its phase and original cycle due time
remain pending, but that group cannot dispatch again in the same turn. Other
groups and interleaved analysis can run. Continuations have separate service
samples and counters; they do not count as returned phases or completed cycles.

`coverage.pipeline.discovery_scheduling_json` carries private
`kn.discovery_scheduling.v1` diagnostics: phase attempts, returns, faults,
cancellations, continuations, actual service/gap distributions, partial cycles, due-to-first
dispatch, due-to-cycle return/failure, queued requests and budget deferrals.
An ordinary scanner return can itself mean unavailable, partial or rejected
target evidence; it is not successful target freshness. Completed worker turns
and completed dispatch cycles are not complete source sweeps. These clocks are
runtime diagnostics, not a durable timing journal or individual native API
latency. Clock reversal across turns cannot wrap a partial cycle's duration.

`--self-test discovery-scheduler` runs the actual worker with an unopened device,
owned requests, observed turn completion and joined cleanup. It verifies
readiness, mapper/follow-up admission, cancellation and restart without dispatching
native discovery phases. Its separate user-inventory fixture performs real
read-only Toolhelp/process queries and verifies snapshot ownership across
continuation, cancellation, restart and Stop. The core harness and independent oracle cover rotating
groups, unfinished tails, flooding, binding churn, mid-cycle requests, repeated
head faults, analysis-yield failure, stop/cancel, continuation and clock reversal. Loaded-native
scanner workloads, further scanner-internal continuation, successful per-target
debt and measured SLOs remain separate acceptance work.

### Resumable user process inventory

`ScanUserModeHostility` retains a worker-owned Toolhelp snapshot and the watch /
suspect input cohort across turns. Inventory work stops after 32 operations or
a cooperative 25 ms allowance, checked between operations. One operation can
read a row and resolve its process generation/path, merge a watch/suspect, or
advance an inventory phase. Snapshot creation, native calls, allocation and
initial input copying can overrun; this is not a hard deadline. No mutex or
borrowed image-reference window crosses the continuation boundary.

Each process query keeps a handle open through generation/path lookup and
PID-based fallback reads. A snapshot name is only a scheduling hint; an unknown
generation cannot inherit it as an image path. Suspect merges reject known
generation disagreement. The existing deep-scan handle/generation fence runs
again before target inspection. Snapshot creation failure, walk failure, caps,
cancellation and faults retain distinct incomplete diagnostics. Completion,
fault, stop after worker join, failed Start and restart close owned snapshots.

Only a completed, uncapped inventory can establish absence for cursor pruning.
An older inventory cannot retire layout leads or image-page state observed
since it started, even when the PID's generation differs. Unknown generations
and missing entries in partial inventories preserve pending layout leads.

`coverage.pipeline.user_inventory_json` carries private `kn.user_inventory.v1`
diagnostics for the latest inventory: original start/elapsed time, phase,
operation/query counts, step limit, completion/cap/cancellation/fault state,
service samples and overruns. Completed diagnostics freeze before deep scanning;
they are not a successful target revisit or a durable timing journal.

### Deep inspection above the process inventory limits

The inventory keeps metadata for up to 4,096 snapshot targets, 8,192 including
extra watched PIDs, and 12,288 including suspects. It reads the snapshot to its
end in the same bounded turns. After the snapshot slots fill, it only needs the
PID and a name hint from each subsequent row to choose a candidate. When the
inputs can exceed a limit, it also ranks the eligible watch and suspect PIDs in
bounded turns. A native end-of-snapshot and complete membership in retained
metadata are separate facts. Absence-based pruning still requires both.

On the first complete inventory that exceeds a limit, the first PID refused a
slot gets a deep inspection slot in its own priority tier. Subsequent capped inventories
choose the next eligible PID above the last reserved callback that actually
started. The upper bound is the highest eligible PID observed when that lap
began. When the interval is empty, selection returns to the smallest current
PID and sets a new upper bound. New PIDs above a lap's bound wait for the next
lap. New PIDs inside its remaining interval can participate. All three input
sources share this rotation. A PID denotes a scheduling position. Each
inspection still qualifies its process generation independently.

If the reserved PID fell outside its source's retained metadata, it takes the
last slot for that source. A later watch or matching suspect can recover the
displaced row with its pinned identity. An older suspect generation cannot
override that identity. The reservation costs one of the existing tier slots
within the eight-target cohort. Up to two urgent watches, four watches total,
six watches plus other priority targets, and two background targets retain
their respective budgets. The ordinary cursor advances past the PIDs it
actually selected. A partial or faulted walk cannot propose a new position.
Stop before the reserved callback preserves the preceding position.

Private inventory diagnostics report the previous and proposed lap positions.
`admission_deferred` counts metadata-capacity encounters in this inventory,
including displacements. Up to 32 scopes identify the input source, PID, known
generation, reason, first and latest step clocks, and event count. The displaced
row keeps a scope even when the sample is full. The unrepresented-event count
covers the rest. Duplicate rows can generate repeated
events, and a later input can admit a previously deferred PID. The deep-cohort
diagnostic records whether the reserved inspection passed its stop check. The
existing `oldest_age_ms` uses attempt times for interesting targets in retained
metadata. Measuring time until a successful observation requires separate
generation-qualified evidence.

### Resumable deep process inspections

After inventory and priority selection, `ScanUserModeHostility` retains the
selected cohort, original generation inventory, watch inputs, urgent-slot
assignment and per-target thread quotas. Selection returns before inspecting
its first target. Each later call dispatches at most one selected target through
`InspectUserTarget`, then yields to discovery and analysis. Native thread IDs
are collected lazily and shared within this cohort; their existing process and
thread identity/liveness fences still apply. A retained thread snapshot does
not establish a fresh, complete view of the running process.

`KmonUserDeepScheduling` records returned, identity-rejected, cancelled and
faulted callbacks separately. A target exception advances only that target,
preserving the remainder and the original selection clock. An exception in
failure reporting cannot discard the remaining cohort. Stop before entry or
during an otherwise returned inspection retains the unfinished target and tail.
Stop after worker join, failed Start and restart release cohort metadata. Native
process/module/thread handles and borrowed reference windows belong to the
individual callback; they do not cross the return boundary. Thread enumeration
and query handles also unwind on C++ exceptions.

Layout leads are consumed only after process generation is checked again after
module enumeration. A rejected generation or stop before that point preserves
the lead. `UserLastScanMs` remains the existing attempt/cooldown clock; consuming
a qualified lead, returning a callback and completing the selected cohort do
not establish successful coverage of all target memory or rules. A returned
discovery phase may contain explicitly recorded target faults or rejections.

Private `coverage.pipeline.user_deep_scheduling_json`
(`kn.user_deep_scheduling.v1`) describes the latest selected cohort: original
selection time, remaining indices, PID/inventory-generation bindings, thread
quotas, per-index attempts/outcomes, selection-to-first-dispatch samples,
outcome-specific service times and calls exceeding 250 ms. Service includes
callback cleanup and failure reporting. Cancellation and invalid clocks remain
visible; invalid durations are excluded. Completed diagnostics freeze before
cohort release. These clocks are neither successful-target debt nor a durable
timing journal. Individual native calls and within-target loops can still block
other work, and whole-source latency/SLO acceptance remains open.

The discovery self-test's `worker_native_phases_dispatched` field describes
only its worker with an absent device binding. Separate nested fixtures report
actual inventory queries, dispatcher generation rejection and owned native
thread queries; they do not validate a complete successful deep inspection.

### Process module observation debt

The user-hostility scheduler tracks Toolhelp module inventories by PID and
process creation time for the current monitor session. Its `GetTickCount64`
clock starts when an inventory or inspection first binds work to that
generation. Rediscovery requests a new observation and preserves the earliest
time that request has been pending. The latest attempt, successful acquisition
and inventory sighting have separate timestamps.

A successful acquisition requires a pinned process, a matching nonzero creation
time before and after enumeration, and a nonempty walk with valid address
ranges that ends with `ERROR_NO_MORE_FILES` within the 1,024-row limit.
Cancellation, a partial walk, access denial, a conflicting generation or a
source fault leaves the work pending. Once the source qualifies, a later
inspection exception preserves the receipt. A PID with unknown creation time
can earn its first receipt after a successful pin binds it to a generation.

Every fourth complete, uncapped census may give one deep inspection slot to
the generation that has waited longest since its last success or first
admission. Ties favor the earliest unexpired suspect hint, then an unattempted
or least recently attempted generation. The hint deadline comes from the
existing suspect retention period. The process lifetime remains unknown.
A failed visit has a 30-second cooldown for this slot. An explicitly unsupported
generation can regain eligibility through a successful ordinary visit. The
existing tier quotas still apply. Partial inventories use ordinary selection,
and capped inventories retain their [population reservation](#deep-inspection-above-the-process-inventory-limits).

Private `coverage.pipeline.user_module_debt_json`
(`kn.user_module_observation_debt.v1`) reports up to 32 generation records,
the omitted count, and outcomes for all attempts. It measures time from
admission to first success, intervals between successful acquisitions of the
same generation, and service time from inspection entry through qualification
or failure. It records
cancellation separately and excludes reversed clocks from duration samples.
The session retains up to 12,288 generations. A pinned inventory replacement
retires its predecessor, and complete absence retires a missing PID. Under
capacity pressure the scheduler preserves current generations, records
evictions or refused admission, and counts outcomes without a retained
generation separately. Only retained generations contribute first-observation
and revisit intervals. This source covers the module inventory. Other sources,
durable timing and host-wide unobserved intervals require separate evidence.

### Measuring module observation intervals on Windows

The [owned workload runner](../tools/test-user-module-workload.py) starts
Windows processes in a private job. Each process announces its own PID,
creation time, executable base and ready clock. The controller confirms its
identity using the process handle and confirms termination after the exit
acknowledgement. A separate observer has query access to the job. It takes
a kernel census of job members, reopens live generations, then uses the
production inventory, tier selector, inspection scheduler, Toolhelp reader
and observation ledger. The runner checks each acquired executable base
against the value supplied by the child. An additional process outside the
job stays alive throughout the measurement to check scope.

The fixed and changing workloads each run 16 censuses, paced at least 25 ms
from the preceding admission. The workload assigns tiers using
`(PID / 4) % 3`. In the changing workload one child exits before the first
census, another exits after selection and three observed children retire
as new processes arrive. The controller records time from child readiness
and first admission to the first successful acquisition, then each interval
between successes. For each generation it also takes the longest interval
including the initial wait and the tail through the exit acknowledgement or
the workload cutoff. A child that exits before observation contributes its
full measured ready-to-exit interval. Surviving processes have a right-censored
tail. All clocks use `GetTickCount64`. The private trace contains generation
identifiers and executable bases. The [dated measurements](VALIDATION.md#owned-windows-process-module-workloads-2026-11-18)
publish aggregate intervals for these workloads.

`tools/validate-kmon-core.ps1` builds the harness and runs the workload.
To repeat the measurement with the same Release harness, run the following
from the repository root. Add `--trace` to include the private per-process
records on standard output.

```powershell
python tools/test-user-module-workload.py --core-exe .build/kmon-core/Release/kmon-core-Release.exe
```

## Layout collection and verification scheduling

The layout worker maintains an explicit process ring. New discoveries join
behind existing waiters instead of extending a PID-sorted scan's unfinished
tail. Ordinary turns rotate the head; at most one turn in four may borrow the
oldest eligible due or source-held work without advancing that ordinary head.
Retirement removes membership, and a later rediscovery joins again. Failed
collection preserves the original observation-due time and previous completed
snapshot; its existing retry cooldown still applies. A completed sweep sets the
next observation due time from its actual finish. First discovery is an
inventory PID observation until the process instance is qualified. With a
PID-only watch, the worker checks current membership before opening a process
left over from the last inventory. Name watches recheck the pinned image name
when the process generation changes.

Collection keeps its existing 256-query/10 ms cooperative slice, 50 ms tick,
30-second sweep window and bounded region/name storage. These budgets include
synchronous work that cannot be forcibly preempted. Complete means a finished
non-atomic `VirtualQueryEx` traversal, not clean code, an atomic inventory or
proof that a mapping could not have been replaced between observations. The
worker performs no shutdown sweeps; shutdown only flushes retained notices and
changed candidates through the existing dependency order.

The verification queue admits 160 candidates globally, 128 in either changed
or periodic/initial class, 16 per process instance and 8 per instance/class.
Each class therefore leaves 32 slots available to the other. Refused candidates
remain with the producer's changed-range batch or periodic cursor. Admitted
subjects rotate through a ring, their two classes rotate independently, and
FIFO order is retained inside each class. A bounded oldest-head loan leaves the
ordinary subject and class cursors intact. New subjects cannot join ahead of
existing waiters. Existing per-sweep candidate budgets remain in force.

A duplicate retains the original candidate, queue time and 30-second expiry.
The verifier checks that window before opening the process and again when it
validates the mapping. Candidates already expired at dispatch still count as
attempts. The [observer timeline](TIMELINE_COMMAND_USAGE.md#inspect-process-handle-ownership)
records the handle calls made by both the collection and verification workers.
Last submitted observation time and rediscovery count are recorded separately;
the count describes repeated submissions, not unseen mapping changes. Equality
requires the same canonical process identity, optional EPROCESS/session
assertion set, mapped name, range, attributes and candidate class. An unknown
assertion cannot merge contradictory known identities. If the original is
already expired, a newer observation stays at the source until that original
has been accounted for, then receives its own admission and validation. In-flight
originals likewise leave new source work pending.

`coverage.pipeline.layout_collection_scheduling_json` carries private
`kn.layout_collection_scheduling.v1` data: discovery/due/attempt/completed-sweep
times, held callbacks, remaining cursor, successful/incomplete service and
discovery/due-to-sweep distributions. It includes up to 64 exact resident scopes
within a 65,536 UTF-16-character detail budget, plus up to 128 deferred discovery
PIDs whose instance identity is explicitly unqualified. Omitted scopes and
incomplete inventories remain visible. Failed attempts never renew a completed
sweep timestamp.

`layout_verification_scheduling_json` carries private
`kn.layout_verification_scheduling.v1` data. It separates queue/source wait,
admission/observation-to-mapping-qualification, complete/incomplete handler
service and normal/shutdown outcomes. Qualification is recorded immediately
after the native identity, age, mapping and mapped-name checks; a later handler
fault remains a fault even if that mapping check succeeded. This success does
not establish a byte read, image verification or mapping lifetime. Histograms
use exact maxima and log2 quantile upper bounds. Resident history is limited to
512 keys, with pending/in-flight keys pinned; deferred detail is limited to 64
keys. Exact report rows and escaped text are bounded, with eviction and omission
counts. Identical mapping reuse between observations remains unresolved.

`--self-test layout-scheduler` exercises owned native mapping/guard/expiry and
identity controls, an actual source sweep, fresh-source retry after original
expiry, and a separate shutdown qualification. Core controls and an independent
model exercise quotas, identity assertion conflicts, original clocks, observed
concurrent reporting, bounded history, stable/growing/flooded/reused populations
and source capacity deferral. They do not establish native workload SLOs,
whole-source maximum unobserved intervals or generic pipeline deadlines.

## Publication scheduling and completion timing

The capture writer selects one admitted job at a time from image read sets,
evidence bundles, IRP captures and byte pages. Three ordinary family turns are
followed by a possible loan to the family with the oldest known queue time. A
loan does not advance the ordinary cursor. With all four families continuously
ready, each receives service within six dispatches. This is a dispatch bound,
not a time bound: synchronous file, replay and journal work cannot be preempted.
Image/IRP retention classes still rotate within their own queues and retain
their existing slot, memory and file budgets. FIFO order inside each class is
preserved. A snapshot sees each queue separately; it is not an atomic inventory
of concurrent admission, dispatch and completion.

The writer exits only after observing the producer-join signal and then taking
a fresh empty queue snapshot. An empty dispatch snapshot taken before that
signal cannot discard the last enqueue. Partial startup failures use the same
producer-join-before-writer-stop order.

Each admitted job carries its local queue timestamp. Actual capture, image,
reference-bundle and IRP producers also pass a `GetTickCount64` acquisition
window around their original acquisition/qualification work. These windows are
collector observations, not individual native read API durations. The writer
never reconstructs them from serialized receipts, wall clocks, the observation
source's separate steady-clock domain, or the time that existing bytes were
queued. Opaque or historical inputs keep an unknown acquisition origin while
still contributing queue and service samples. Failed admission does not become
a publication attempt.

The publisher records primary artifact file API success and journal commit
separately. For image/IRP jobs, the file milestone is the original read/capture
root; reference blobs and recipes keep their existing separate counters. A
failed job can therefore still have preserved dependency blobs.
For byte pages, file success follows the existing write/flush/close path; for
bundles it follows immutable file publication. Those two families have no
per-job collection journal requirement. For image/IRP jobs, complete publication
also requires the existing retention contract's journal and required reference/
recipe members. A raw file surviving a failed journal commit is partial. A
partial or failed job cannot enter complete-service samples. Complete describes
publication of the required artifacts, not semantic qualification of their
contents, a recorded claim's truth, journal indexing, final collection closure
or storage survival under media/power loss.

`coverage.pipeline.publication_scheduling_json` contains the private
`kn.publication_scheduling.v1` report. Each family exposes admissions/rejections,
pending count, oldest known queue age, missing/invalid clocks, outcomes and
normal/shutdown histograms. Queue wait, complete/incomplete service, queue-to-file
and queue-to-journal durations are separate. Known acquisition windows add
start/end-to-file and start/end-to-journal distributions. Per-job receipts
retain both acquisition endpoints; subtracting histogram quantiles cannot
reconstruct an individual acquisition interval. Quantiles are log2 bucket
upper bounds and maxima are exact samples.
An active family and elapsed service/queue wait remain visible during a slow
publication. Shutdown classification is fixed at dispatch; it does not change
when a normal job finishes after a stop request.

Each completed dispatch also queues `coverage.publication` with private
`kn.publication_timing.v1` data linking the original job ID to acquisition,
queue, service, file and journal timestamps. Existing raw files, recipes and
their hashes are unchanged. Receipt-event loss is counted separately; losing
that event cannot undo a file commit. Sweep manifests and final ledgers retain
their original dependency order and remain outside the per-job completion
contract. A job's service can include a triggered sweep manifest, while its
file/journal milestones still describe that job's own artifacts.

`--self-test publication-scheduler` runs the actual writer with owned files,
native owned page/bundle reads and synthetic image/IRP inputs. It removes the
original memory/reference before publication, observes completion before
requesting writer stop, and checks failed shutdown and raw-file-only outcomes.
The core picker tests and independent Python model exercise fixed, growing and
cleared/reused queues. These checks do not establish native workload SLOs,
complete source coverage, generic pipeline deadlines or whole-collection
durability under power loss.

## Collection publication timing

`coverage.pipeline.collection_timing_json` adds the private
`kn.collection_timing.v1` report for one capture-writer session. It retains the
session start, earliest and latest known acquisition endpoints, and the actual
writer-finish time. The writer records each closing phase in dependency order:
sweep-manifest flush, evidence-bundle ledger, optional IRP ledger, then the
image-journal closure. File and journal timestamps are taken only after the
existing publication APIs report success. A live report can expose a closing
phase before it returns; no timing mutex is held across file I/O.

`publication_outcome` is `incomplete` until the writer has drained all admitted
jobs, finished its closing phases and reconciled admissions with attempts.
It then distinguishes `empty`, `complete`, `partial` and `failed`. The separate
`closure_outcome` describes the closing operations. Successful closure does
not erase a failed or rejected job, unavailable IRP capture, failed sweep
publication or lost sweep metadata. Normal and shutdown dispatch counts remain
separate. Successful reference, recipe and sweep publication operations,
including verified reference reuse, also preserve a partial outcome when
primary files and closure fail. Their count is not a distinct-file count.
This outcome concerns required publication, not successful reading of
every target or the truth of a captured claim.

Acquisition endpoints come exclusively from the local caller windows already
attached to processed jobs. Dispatch order cannot replace an earlier endpoint.
Historical bytes and absent or invalid clocks remain unknown; zero is a valid
known tick. `known_subset_start_to_writer_end_ms` measures only that known subset.
`acquisition_to_successful_close_ms` is present only for a complete, nonempty
publication whose admitted jobs all have valid acquisition clocks. Empty,
partial, failed and incomplete collections do not improve this success metric.
Duplicate closure cannot renew the original finish time, and protocol errors
prevent a final success classification.

The report is a runtime diagnostic, not an additional journal member or a
recoverable timing receipt. It can be lost with event logging or a crash;
offline closure still requires the original ledgers and verified journal.
Captured page files still have no collection ledger. Per-file formats, hashes
and dependency requirements are unchanged. The report does not evaluate
source-wide observation coverage, authenticate acquisition clocks, measure a
native workload SLO or prove survival under media/power loss. Its producer-queue
snapshot is not atomic; final accounting is meaningful after producer/writer
join.

The publication self-test compares post-join timing with actual journal
recovery, exercises file-only failed closure and empty sessions, and observes
completed jobs before requesting writer stop. The independent core oracle
covers unknown/invalid clocks, out-of-order acquisition, unprocessed admissions,
rejection, missing IRP, auxiliary losses and repeated closure.

## Image observation scheduling

Each resident image-work key records first/last discovery, pending time, last
attempt, last successfully compared slice, and first/last traversal. A traversal
with gaps does not renew the separate last gap-free traversal. Observation debt
uses that qualified traversal time, or first discovery if none has completed.
A fully compared modified page is a successful observation; it does not mean
the page is clean. Reference failure, read gaps and incidental rediscovery do
not renew successful observation times. Continuations do not refresh discovery
age, so polling an exited process cannot keep its cache entry young.

Replacing a reference resets the comparison cursor and starts a new retention
episode while preserving resident history. Successful-slice and gap-free times
carry their episode IDs, so an older reference's completion remains historical.
These entries describe a bounded cache, not continuous mapping lifetime or
complete source inventory. Eviction drops that entry's debt history.

The existing watched/background and first/repeat shares, process rotation,
large-image cursor progress and bounded-tail turns remain. On one in four
**ordinary** turns within the selected class, the oldest observation debt may
borrow priority. That loan does not advance the ordinary process cursor. A
permanently failing old image therefore cannot consume all ordinary service or
the reserved bulk/tail turns. A failed reference becomes eligible for another
lookup after a 30-second cooldown from preparation completion, even without rediscovery.
Live continuations still require an available source and their due clock. The
shared analysis rotation gives them turns under reference/event queue pressure.

The 25 ms cooperative comparison budget starts before reference lookup and,
for continuations, includes source inventory and routing setup. The
verifier preserves its cursor, allows at least one page after preparation, and
always retains the final target/file identity and retained-content checks.
Those synchronous calls, minimum progress and result handoff can exceed the
budget. PE metadata and sweep-range preparation use the workers described below;
native file identity, retained-content and target checks remain synchronous.
Neither path enforces a hard deadline.

`coverage.pipeline.image_scheduling_json` is a private `kn.image_scheduling.v1`
JSON string. It exposes resident/loaded/pending/evicted counts, admission-deferred
attempts, maximum resident debt, and oldest-debt scope details. Details contain
exact boot/PID/create-time/base/path identities and are bounded to 64 rows and
65,536 UTF-16 units for the serialized rows. A scope that cannot fit is omitted
and counted, never shortened into a different identity. An unavailable reference
has unknown remaining pages. Deferred admission still requires source
rediscovery; its sampled existing diagnostics are not a complete denominator.

Lookup and whole-turn durations include completion application and synchronous
cache identity checks. Asynchronous metadata preparation has its own timing
population. Verifier stages measure reference open/retention, identity/secondary
qualification, page comparison, and final identity/content checks. Successful,
failed, not-due and preparation-pending turns are separated, as are normal and
shutdown samples. The legacy unavailable-lookup counter means no ready reference,
including pending work and admission refusal; it is not a file-failure count.
First parser attempt, exact read, traversal and gap-free traversal ages are
counted once per resident key. A parser request can be rejected before a native
read, so that milestone is not native API latency. Times use `GetTickCount64`,
exact maxima and log2 percentile upper bounds. Durability is outside this turn.

`--self-test image-scheduler` exercises production lookup/comparison/reporting
with owned files and synthetic target bytes, plus controlled-time production
selection for fixed, growing and delete/reuse cohorts. An independent Python
model checks the latter sequence. These controls do not establish native-driver
workload SLOs, all-source maximum unobserved intervals, generic stage
budgets/dependencies or durable publication latency.

## Asynchronous image reference metadata preparation

The analysis worker submits PE metadata parsing and executable sweep-range
construction to two dedicated workers. It keeps the original discovery time,
queue ticket and work episode while preparation is pending. Rediscovery does
not enqueue another copy or renew that age. Pending preparation is distinct from
an attempted file failure and cannot produce a successful target observation.
Different paths share a pending request only after the existing alias-open path
compares their full volume/file IDs; that check does not qualify target bytes.
An actual unavailable/unsupported/budget/fault outcome receives a 30-second
retry cooldown from completion. The image debt and previous successful read
remain intact.

Admission includes queued, running and ready results: 64 total and 8 per
canonical process instance. Subjects rotate through a ring, with FIFO jobs
inside each subject and at most one oldest-head loan per four dispatches.
New subjects join behind existing waiters. Four result slots include running
jobs; an unconsumed completion backlog stops further parsing. Each prepared
payload has a 128 MiB retained-storage estimate limit. Parser intermediates and
allocator overhead remain outside that estimate, so it is not a process memory
limit. Existing PE parser bounds also apply.

Workers receive copied requests and never access the live image-work map or
target readers. The analysis thread applies a result only when its ticket,
work episode, path, base and exact process identity assertions still match.
Eviction abandons the ticket; an obsolete completion is counted and discarded.
A newly prepared reference still passes the native file identity check before
a target read. Replacement between preparation and consumption starts a new
episode. Preparation success is metadata availability, not file trust, a live
mapping lifetime, a byte comparison or execution evidence.

Stop closes admission before cancelling queued work and requesting cancellation
on the dedicated worker threads. It then joins them before final pipeline
reporting. A cancellation request is not completion and may not immediately
interrupt a native operation; see Microsoft's
[CancelSynchronousIo contract](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelsynchronousio).
The parser checks its scoped cancellation flag between file reads and rejects
partial metadata after cancellation. Ordinary parser calls retain their existing
behavior. Partial worker startup also joins every thread that started.

The private `coverage.pipeline.image_reference_preparation_json` field uses
`kn.image_reference_preparation.v1`. It separates queue wait, preparation
service, ready-to-consumer delay and admission-to-ready latency. Prepared,
failed and cancelled service have distinct denominators, and shutdown attempts
are separate from normal attempts. Current and deferred scopes are bounded to
64 each, with a combined 65,536 UTF-16-unit detail budget and explicit omissions.
Image scheduling rows retain the last preparation ticket, admission, attempt,
completion, outcome and successful preparation episode. Cancellation never
rewrites a previous completion or successful-read timestamp.

`--self-test image-preparation` uses owned reference files, controlled worker
gates and a synthetic target. It observes another subject complete while one
worker is held, file replacement after readiness, stale episode rejection,
failure after prior success, and actual monitor stop with queued/running overlap.
The standalone harness also exercises admission/result bounds, loader faults,
generation reuse, native parsing and a dispatch sequence checked by an independent
Python model. Gates synchronize on observed work, not elapsed sleeps.

Recorded comparisons use the separate content preparation stage below. Alias
and rescan identity opens, page reads and final target/content fences remain
synchronous. Preparation workers can still wait inside native calls. Generic
stage budgets/dependencies, native workload SLOs and whole-source maximum
unobserved intervals remain open.

## Asynchronous image reference content preparation

Each recorded image comparison requests a source-file lease, original bytes and
SHA-256 from two dedicated content workers. These workers are separate from the
two metadata workers, so a backlog of ready file leases cannot occupy every
metadata slot. Each pool admits 64 owners, at most 8 per process, and allows four
running or ready results. A content result holds at most the existing 64 MiB
reference snapshot; parser allocations and publication queues have separate
ownership and limits. This is not a total process-memory bound.

The analysis thread retains only a ticket while preparation is pending. It does
not read the target or count that wait as a file failure. Admission attempts
advance scheduler rotation without renewing original observation debt. A ready
lease can be taken only by its exact ticket and matching process/work episode.
The comparison uses that already-open file and snapshot, then closes the source
handles before queueing immutable original evidence for publication. Source
leases are never stored in the long-lived image cache. Unrecorded comparisons
retain their existing behavior; they did not request whole-file retention.

Ready results expire after a cooperative 5,000 ms retention period. Idle content
dispatchers wake every 100 ms to discard expired results; admission/consumer
checks also reclaim them. This is an expiry policy, not a guaranteed native
handle-close deadline. A stale, expired or cancelled result cannot qualify a
new work episode. Stop closes both pools, joins their running workers and clears
active tickets. Cancellation preserves previous completed outcomes and success
timestamps instead of turning removed shutdown tickets into expiry samples.

The original final content re-read and file/target identity checks still run
after comparison. Preparing a lease does not establish file trust, live bytes
or successful retention: files that exceed the retention limit keep the existing
explicitly unretained comparison path. Retention failure and file-open failure
remain distinct. A failed content attempt receives a five-second retry cooldown
and cannot renew a prior target success. The cancellation-aware retention reader
checks between read/hash chunks and publishes no partial snapshot.

`coverage.pipeline.image_content_preparation_json` uses the same private
`kn.image_reference_preparation.v1` schema with `phase: content`. Its success
scope is a prepared file lease, with separate retained-snapshot and unretained-
lease counts. Metadata reports identify `phase: metadata`. Both retain their
own queue, service, application, cancellation and shutdown populations. Image
scheduling rows expose pending/last content tickets, original queue time,
completion, successful episode, expiry count and cancellation separately.
Their `content_preparation` object is null until admission, preserving the
existing detail budget without filling unattempted scopes with empty fields.

The preparation self-test observes another subject complete while a content
worker is held, write exclusion while a native lease is ready, lease release
before original bytes are published, failure after success, stale episodes and
queued/running stop. The standalone harness also observes an unused lease expire
and checks exact-ticket consumption and oversized unretained results. Reference
blob controls compare multi-chunk hashes with an independent Python SHA-256.
These controls do not establish native workload SLOs or close the remaining
whole-pipeline timing and synchronous final-fence work.

## Execution reference scheduling

The analysis thread admits execution references through a bounded queue:
1,024 candidates globally, 64 per process instance, 16 per process instance and
reference role, and 256 per role across instances. A subject is boot ID, PID and
creation time; kernel references share one subject per boot. Optional EPROCESS
or session assertions cannot create extra quota. A role is the producing
scanner's declared reference kind, not an authenticated provider or a separate
operating-system source. Existing scanner backpressure can stop discovery
before this queue; its skipped candidates are outside these counters.

Admitted subjects take turns, with roles taking turns within each subject and
FIFO order within a subject/role. New subjects and roles join after those
already waiting. A busy key's rediscovery increments a counter and last-seen
time while preserving the original pending time, wall-clock observation,
anchors, target and expected PEB. It does not claim to retain intermediate
changes. Failed admission does not evict admitted candidates. Deferred work
requires a later source rediscovery; that rediscovery is not guaranteed.

`coverage.pipeline.reference_scheduling_json` contains a private
`kn.reference_scheduling.v1` JSON string. It records exact deferred scope and
reason for the first 128 distinct scope/reason pairs, coalesces repeated attempts
for those pairs, and counts omitted attempts after that bound. These counts are
admission attempts, not a complete distinct-target denominator. Up to 16,384
admitted-key histories retain first/last discovery, pending time, last attempt,
last successful check and last completed outcome. Completed histories may be
evicted; pending/in-flight histories remain pinned. The report exposes resident
and evicted counts, at most 64 scope details (oldest pending first), and omitted
detail count. Maximum observation debt covers only resident admitted keys,
using last success or first admission when no success exists. It cannot establish
the maximum unobserved interval of all source candidates.

The existing ten-second throttle is explicitly an **attempt cooldown**. Failed
identity, architecture, mapping, read or consistency checks and partial paths do
not advance last success. A successful bounded static check requires revalidated
identity/anchors and either a stable supported head-chain ending without a
recognized transfer, or an accepted page observation. It does not prove execution,
complete control-flow coverage, verified file ownership or durable publication.
Older-than-30-second work expires before qualification and does not advance last
attempt or last success. Shutdown leaves any undrained work visible as pending;
it does not count that work as successfully revisited.

Queue waits include all completed dispatch outcomes. Successful and failed
service distributions are separate; expiry and cancellation have no service
sample. Normal and shutdown distributions are separate. Values use collector
`GetTickCount64` milliseconds, exact maxima and log2-bucket percentile upper
bounds. Invalid clock order is explicit. The drain's elapsed-time budget is
cooperative between candidates; a synchronous call cannot be preempted. The
limits are policy, not measured SLOs or a whole-pipeline budget.

`--self-test reference-scheduler` exercises the actual admission/drain and pipeline
report against owned user memory and an unopened native backend. It also checks
that the live-source wrapper leaves work pending when its source is unavailable.
An independent Python deque model checks fixed, growing, flooded, expired and
PID-reused cohorts emitted by the C++ core harness. Native driver workloads,
other pipeline stages, end-to-end durable latency and workload-specific maximum
unobserved intervals remain open.

## Exact image reference replay

`--offline !kmon verify-image` now connects the dump observation source to the
existing executable verifier and a private image case. Each case retains the
complete reference PE as `<sha256>.knblob`, then atomically publishes
`recipe.knverify` last. New captures use the claim publication root described
below; legacy recipe roots remain readable. Original file identity/path and capture time remain
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

`--verify-process-image` adds a handle-based live transaction, now written as
`kn.image_recipe.v3`. It uses a duplicated handle bound to the requested PID and
creation FILETIME, explicit residency consent and one shared operation budget.
The actual qualifier, comparator and confirmation reads produce the saved
`kn.read_set.v1`; byte receipts are not reconstructed from later reads. Receipts
retain the full source contract, request, consent, original status and reported
copy count, any native transport metadata, and operation/read identifiers.
The recipe reader verifies counters, ordering, source consistency and parser
projection before replay. Pending, abandoned, missing, overrun, cross-source or
fallback receipts cannot become an executable recipe under this single-source
format. A recorded failed or denied read remains a failed or denied parser input.

The live CLI requests `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION` and returns before driver,
service, symbol or monitor initialization. It uses the Win32 user-address ceiling
with an explicitly assumed legacy LA48 shape; it does not infer CR4.LA57. The
default acquisition budget is five seconds, 64 source calls/receipts and 128 KiB
requested bytes; synchronous reads cannot be preempted. Reference opening,
hashing and parsing precede that acquisition budget. V1, v2 and v3 retain the
same direct byte comparison policy and support post-exit replay. V1 remains readable;
its writer refuses new metadata that it cannot represent rather than dropping it.

### Process mapping observations

V3 adds `kn.process_image_mappings.v1` beside the unchanged v2 read-set format.
The owned process handle supplies `VirtualQueryEx` observations immediately
before and after each byte read, then once for every distinct address/length
pair after comparison. All intervals use the collector's steady clock and must
fit the operation snapshot/deadline. At most 64 byte reads produce 192 mapping
observations and 384 native queries; query calls have their own retained count,
separate from the read-set's charged byte-read calls. Each observation covers
at most 4,096 bytes and two native regions. Cancellation, identity failure,
query failure and malformed/partial results remain explicit.

Every query retains its address, returned byte count, failure-only Win32 error,
region extent, state and defined allocation/type/protection fields. Undefined
fields are null: free regions have no allocation/type/protection, and reserved
regions have no current protection. The canonical parser checks source identity,
before/read/after ordering, complete final range coverage and bounded query
progress. The evaluator compares state/type/allocation/protection only where
the queried ranges overlap; unqueried neighboring extent changes are not conflicts.

Observed identity or attribute conflicts produce `inconsistent_capture`;
failed queries and uncommitted ranges produce `unavailable`. Either mapping
fence withholds reference qualification, clears derived differences and places
the requested comparison range in failed coverage while preserving original
read bytes. V3 claims use `kn.image_claim_policy.process_mapping.v1` with an
additional `observed_mapping_consistent` requirement pointing to the original
`/payload/mapping_set`. Exact approved-change assessment and private archives
use the same gated replay. V1/v2 retain their original schemas, results and
`kn.image_claim_policy.direct.v1` evaluation without synthesized mapping facts.

Stable `MEM_PRIVATE`/`MEM_MAPPED` buffers can support scoped byte comparisons.
`native_image_mapping_observed` requires every successful queried region to be
committed `MEM_IMAGE` at the declared image allocation base. It does not prove
sharing or original backing: copy-on-write pages can still report `MEM_IMAGE`.
Equal queries cannot exclude ABA or pin a mapping lifetime, and final queries
are sequential observations rather than an atomic snapshot. Original and
current replay evaluate retained records without querying a live process.
The query contract is the native AMD64 48-byte structure; other query layouts
and native kernel mapping-lifetime providers remain separate work.
See Microsoft's [VirtualQueryEx contract](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex)
and [defined memory-information fields](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information).

### Direct recipe replay

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
requested read bytes, with a 2 MiB inner recipe and a 4 MiB claim publication root.
File reads check a cooperative 30-second
budget; synchronous I/O and PE parsing have no hard cancellation deadline.
Background KMON/native-fallback publication, secondary-view recipes, signed reference distribution
and isolated parsing remain open. Existing `.kncase` replay still reports
`image_verification_replayed=false`; it does not implicitly discover these cases.

Capture requires a new directory and never replaces existing output. A failed
or interrupted capture can leave an unreferenced blob or temporary file, but no
valid final recipe; callers treat the missing final marker as incomplete. Case
directories currently have explicit/manual retention and no automatic expiry or
cross-case deduplication. Use locally trusted reference files until parser
isolation is available.

### Original direct-image claim publication

New dump and process captures publish `kn.image_claim_publication.v1` in
`recipe.knverify`. Its canonical payload contains the selected v1/v2/v3 recipe
envelope and `recorded_claim`, with a SHA-256 over both. The inner recipe retains
its own observation digest, so claim evidence pointers resolve without a circular
hash. The exact reference blob is still a separate content-addressed input.

After collection, the writer replays only the retained reads against the pinned
reference, verifies the recorded comparison and computes the claim report before
publishing the final root. It makes no additional target acquisition. The root
is flushed and renamed without replacement only after both recipe and claim are
ready. Missing final roots, orphan blobs and `.pending-*` files do not constitute
publication. This is the existing filesystem publication contract, not a claim
of power-loss durability or journal membership.

Offline replay validates the canonical root and inner recipe, then independently
recomputes comparison and claims. `original_claim_replay.status=reproduced`
requires the retained registry/policy to be implemented and the complete report
to equal the stored report. It exposes the root and recorded-report hashes and
sets `original_claim_policy_reproduced` and `assessment_matches_current_report`.
An unavailable claim policy or any changed assessment fails original replay with
`recorded_claim_policy_unavailable` or `recorded_claim_assessment_mismatch` and
withholds proof/current-claim output. Stored assertions are never evaluator inputs.
Future semantic changes require a new policy version and a retained old evaluator
to continue reproducing that version.

`/current` deliberately reports `not_requested` for original claim replay and
evaluates the current policy separately. Bare v1/v2/v3, slice and sweep recipes have
`not_recorded`; they cannot acquire an original claim merely by being replayed.
The frozen `recorded_claim` is the evaluation made immediately before publication:
its conservative persistence and original-reproduction fields remain unchanged.
The separate replay outcome carries the later reproduction result. Hashes bind
local artifact contents without authenticating who collected or approved them.
Direct capture and approval archives preserve this root under their dedicated
collection policies. KMON slice/sweep publication uses the contract described below.

### Original slice and sweep claim publication

Eligible KMON `.knslice` and `.knsweep` files contain
`kn.image_scope_claim_publication.v1`. Its payload binds an unchanged canonical
`artifact` envelope and the complete `recorded_claim` under `publication_sha256`.
Recipe/manifest digests and their evidence pointers still identify the embedded
original artifact; the publication digest binds both artifact and claim. The
whole UTF-8 file must fit the existing **2 MiB** file limit and retention budget.

The writer evaluates the original recipe from retained target/secondary reads
against the published reference, without another target read. Sweep evaluation
replays its declared retained children and checks their publication identities
across reopen. It then publishes one immutable root with the existing flushed,
create-new rename path. Replay, bounded graphs and minimized disclosure accept
the new root. Original replay requires a known recorded registry/policy and exact
report equality; unsupported versions or altered assessments withhold proof.
Slice/sweep `/current` remains unavailable.

If original-claim evaluation or its additional byte budget is unavailable, the
writer preserves the legacy recipe/manifest when its existing publication budget
allows. `original_claim_recorded=false` and `original_claim_failure` identify this
outcome in publication events. Hunt/session counters `slice_claims_written`,
`slice_claims_unavailable`, `sweep_claims_written` and `sweep_claims_unavailable`
separate these outcomes from comparison and file counters. Slice claim counters
cover nonempty queued recipes; `slice_recipes_unavailable` separately counts
inputs that were not recipe-eligible. Missing child evidence never creates an
original sweep claim or a successful collection dependency.

Journal v3 and later commit the exact physical publication bytes, including recorded
claims, and requires already committed child/reference paths before a sweep
transaction. Recovery and store retention recognize the new sweep roots.
Appending after closure, conflicting files, absent dependencies and reopening
under another journal policy remain rejected. A file saved before its journal
transaction is an uncommitted artifact even if its claim reproduces. Accordingly,
`original_claim_replay.journal_membership_checked` remains false: use separate
journal recovery to establish collection membership. Neither operation proves
collector authentication, complete observation or power-loss durability.

As with direct publications, stored reports keep their conservative prepublication
persistence/reproduction fields. The separate replay outcome records later exact
reproduction. Other adapters' original claims and qualified lifetime joins remain open.

### Direct image capture collections

`!kmon journal-image <case-directory> <private-store> <collection-id>` archives one
existing direct capture into an initialized private store. It pins and validates
the bounded original `recipe.knverify` and its hash-selected reference before
publication. Bare v1/v2 recipes and `kn.image_claim_publication.v1` roots retain
their exact physical bytes. The operation neither opens a target nor reparses
PDBs. It does not move, delete or change the privacy of the original case.

The dedicated `kn.direct_image_collection_journal.v1` policy admits one
`image_capture` transaction and its dependent closure. Its immutable root is
`image-captures/capture-ID-PHYSICALSHA.kncapture` (at most 4 MiB); its exact
reference is `image-references/SHA.knblob` (at most 64 MiB). The capture transaction
ID is the physical root hash and binds exactly these two members. Existing
image/IRP journal v1-v4 encodings remain unchanged and reject this new family.

Publication holds the shared store barrier, private-root guard, collection lock
and admitted file handles. It retains the reference, retains the root, commits
the capture, publishes `image-captures/session-ID.kncaptureledger`, and commits
closure with both original paths as required dependencies. The ledger schema
`kn.image_capture_session.v1` counts one archived capture and its logical referenced
bytes; it does not reconstruct the original live attempt count or new disk usage.
The separate `kn.image_capture_collection.v1` result reports this invocation's
create/reuse, capture commit, closure and index outcomes.

Exact retries reuse files and transactions, including a closed collection.
Conflicting files or a different capture already committed to the collection
fail without replacement. Interruption can leave uncommitted files, an open
verified prefix or a closed collection; derived-index failure remains an incomplete
archive result even when the original transaction committed. These boundaries
do not establish power-loss durability. Recovery's `committed_direct_capture_paths`
lists verified members, not semantically replayed claims. Store inventory and
explicit GC recognize the new namespace; committed members, final ledgers and
files protected by unresolved membership remain protected.

`replay-image <managed.kncapture>` resolves the shared reference from the fixed
parent store's `image-references` directory. Existing case-directory replay stays
valid. Archival validates structure and physical hashes; original-policy replay
independently evaluates the retained reads and reproduces the original claim.
A structurally valid but false saved assessment can therefore be archived while
failing replay. `redact-image` accepts managed roots only through the same
original-policy replay and private original-hash linkage; archival alone does
not authorize disclosure. Neither operation authenticates the collector or establishes
execution, lifetime continuity, complete capture coverage or approved changes.

### Approved image changes

`!kmon assess-image` evaluates a direct case, managed `.kncapture`, KMON `.knslice`
or temporal `.knsweep` under a
separately supplied approval-policy SHA-256. `kn.image_approval_policy.v1` pins
the exact image hash, manifest file hash and issuer identifier, with a policy
epoch and validity window. `kn.authorized_image_changes.v1` repeats the image,
issuer and epoch and declares sorted, disjoint RVA spans with before/after
SHA-256 hashes. Both documents are bounded to 64 KiB and 128 entries; each change
span is 1..4,096 bytes. They are UTF-8 JSON with exact field sets, lower-case
hashes and canonical decimal strings. Whitespace and object-field order do not
affect parsing, but the policy and manifest pins bind their exact file bytes.

The caller must obtain the policy digest through its approval process, separately
from the capture and manifest. The manifest cannot appoint its own trusted
issuer. The evaluator requires the supplied digest to match the policy, and
that policy to name the manifest/image/issuer tuple at the same epoch. Both
validity windows include their start and exclude their end. They must cover the
recorded capture time and evaluation time; a capture dated after evaluation
fails. CLI evaluation uses the host wall clock. Neither that clock nor the
collector's capture timestamp is authenticated. API callers may supply an
explicit evaluation time, recorded as `caller_supplied_time`.

Successful original-policy replay, including any original claim reproduction,
supplies the typed comparison from the same operation. Bare v1/v2 inputs keep
their claim-not-recorded status. The evaluator verifies each span against
replayed expected and observed bytes, requires full comparison of that span,
and accounts for every observed changed byte separately. The v1 hash basis
`non_fixup_compared_bytes.v1` rejects overlap with base relocations, loader or
dynamic exclusions, and rel32 overrides. Accepted spans receive no load-base
adjustment. Addresses introduced by a patch are not automatically normalized;
their exact observed bytes must match the approved hash.
Ranges outside this one capture remain `outside_capture`; missing or unstable
reads cannot become approved changes. A before hash mismatch, unexpected after
hash or additional difference stays unexplained. An exact original span reports
`not_applied`. Incomplete comparison remains explicit even when every observed
difference is authorized.

`kn.image_change_assessment.v1` returns the unchanged original replay alongside
rule outcomes, authorized/unexplained RVA spans, byte counts and completeness.
`R-approved` means this exact reference is approved by the caller-pinned policy;
it is not an assertion that a publisher signature was verified. A replaced local
reference can match retained memory and still fail that policy. The result
never changes the recipe, original ownership/difference report, or stored claim.
It proves neither current live state, execution, maliciousness, complete-image
approval nor object lifetime. The assessment and its input artifacts remain
private evidence and grant no disclosure authority.

Slice and sweep inputs use `kn.image_scope_change_assessment.v1`; the direct
assessment format stays unchanged. Their manifest pins the root's exact policy:
`kn.executable_slice.direct.v1`, `kn.executable_slice.secondary.v1`, or
`kn.executable_sweep.temporal.v1`. A temporal sweep can retain supported direct
and secondary children; the original sweep replay validates each child's policy,
reference, membership and recorded result before returning typed bytes. The
approval evaluator derives normalization spans from that replay's verified PE
metadata. It checks the opened root's recipe/manifest and original-claim hashes
against the replay, as well as final file identity and contents. A parent-path
replacement cannot bind another replay to the original root hash.

A change may cross page or slice boundaries only when every byte was compared,
the contributing target identities qualify and the exact assembled before/after
hashes match. Each rule lists its recipe hash, ordinal, RVA, length and capture
time per observed part. `spans_recipe_observations` makes a multi-recipe rule
explicit. These are retained observations from separate acquisition intervals;
`atomic_snapshot=false` applies even to an authorized range. Approval windows
must cover evaluation and every declared child capture time, sweep start and row
observation time. The timestamps remain unauthenticated.

Rules outside retained ranges report `outside_observed_ranges`; holes and
uncompared bytes report `not_fully_compared`. A good observed part may be approved
while missing slices, unreadable ranges or extra differences remain explicit.
The result separates scheduled bytes, observed requested bytes, compared bytes,
authorized/unexplained changes, membership and comparison completeness. A single
slice's denominator is its executed ranges; a sweep's is its original schedule.
Zero executed pages never produce a complete comparison. Raw-publication loss
remains in the unchanged original replay and is separate from byte comparison.
The evaluator admits at most 2,048 slices and 16,384 pages; its output is at most
4 MiB. A result over that limit is unavailable and explicitly omits the embedded
replay rather than returning a truncated successful assessment.

This bounded policy path does not provision signed distribution trust, consult
revocation services or join other cases. The approval collections below retain
direct and scoped assessments under separate journal policies. An updated
policy requires its own explicit digest.

### Approved image collections

`!kmon journal-image-approval` archives one direct assessment into an initialized
private store. It accepts a case directory or managed `.kncapture`, the manifest,
the policy, a separate caller policy digest and a collection ID. Original direct
replay and approval assessment must succeed before evidence publication; an
assessment may still contain unexplained differences or incomplete comparison.
Archival does not read a live target or change the source files' privacy.

The dedicated `kn.approved_image_collection_journal.v1` policy admits exactly one
`image_approval` transaction with five members:

| Member | Store-relative path | Limit |
| --- | --- | --- |
| Exact capture/claim root | `image-captures/capture-ID-PHYSICALSHA.kncapture` | 4 MiB |
| Exact reference PE | `image-references/SHA.knblob` | 64 MiB |
| Caller-pinned policy bytes | `image-approvals/policy-SHA.knapproval` | 64 KiB |
| Manifest bytes | `image-approvals/changes-SHA.knchange` | 64 KiB |
| Original assessment | `image-approvals/assessment-ID.knapprovalcase` | 4 MiB |

The canonical `kn.image_approval_publication.v1` root binds the four input hashes,
collection ID, evaluation FILETIME and complete assessment. Its payload checksum
and physical file hash are distinct; the latter is the transaction ID. The final
`image-approvals/session-ID.knapprovalledger` (`kn.image_approval_session.v1`)
counts one archived assessment and the five members' logical bytes. Closure
requires all five previously committed paths. Existing journal policies keep
their original encodings and reject approval transactions. Recovery adds
`committed_approval_paths`; this is membership evidence, not semantic replay.

Publication holds source read leases, the private-root guard, shared store
barrier, collection lock, output directory pins and admitted output leases.
Assessment uses the opened capture's concrete path and checks its recipe and
original-claim hashes, so retargeting the caller's directory alias cannot switch
the evaluated capture after acquisition.
Shared input hashes permit reuse across collections. The assessment's fixed ID
path preserves the first published evaluation time and result, including when
interruption occurs before its journal commit. Exact retries reuse that result
and verify it again at its original time; expiry since then does not replace it.
A changed input, conflicting output or invalid original result fails without
replacement. Index failure preserves a committed prefix and returns an incomplete
archive. Inventory and explicit GC protect committed inputs, assessment roots,
final ledgers and unresolved membership; only eligible uncommitted files may be
removed under a separate exact-member GC policy.

`!kmon replay-image-approval` requires the caller to supply the policy digest
again. The stored digest cannot appoint its own trust. It resolves and pins the
four exact input files, evaluates at the recorded time and requires byte-for-byte
equality with the original assessment. The `kn.image_approval_replay.v1` result
reports `reproduced` only after that equality check. `/current` instead evaluates
the retained policy at the host's current time, keeps the recorded assessment
separate, and reports `reanalyzed`; it does not fetch or select a newer policy.
An expired policy can reproduce historically while current evaluation fails.

The archive wrapper samples host time and supplies it explicitly to the
assessment, so the stored report records `caller_supplied_time`. That historical
clock and the collector timestamp are unauthenticated. Neither membership nor
replay establishes present approval, current live state, issuer signatures,
execution, lifetime continuity, power-loss durability or disclosure authority.
Approval publication, replay results and ledgers remain private evidence.

### Scoped approved image collections

The same commands accept `.knslice`, `.knsweep` and managed `.knscopeapproval`
roots. Scope archival retains the exact root, every declared child recipe and
each raw archive marked as published, including original claim wrappers. A
missing required input makes archival unavailable. An original row with
`raw_written=false` retains its publication-loss evidence without inventing a raw file.
Comparison gaps and unexplained differences can be archived; archival success
does not turn them into approved bytes.

Original scope inputs use `image-scope-inputs/SHA.knscopeblob`, with the physical
content hash as the key. A sorted catalog binds each original logical name to
its hash, schema and byte length. This avoids filename collisions between
different source collections and shares identical bytes across archives. The
reference PE retains the existing `image-references/SHA.knblob` path; policy and
manifest retain their shared approval paths. The catalog permits at most 4,097
logical inputs, 2 MiB each and 256 MiB total. Reference, policy and manifest
limits remain 64 MiB, 64 KiB and 64 KiB respectively. The assessment still has
the 2,048-slice, 16,384-page and 4 MiB limits above.

`image-approvals/scope-assessment-ID.knscopeapproval` is an at-most-8-MiB
`kn.image_scope_approval_publication.v1` root. Its canonical payload records the
collection ID, scope kind, original root/reference/policy/manifest hashes,
catalog, evaluation time and complete assessment. Replay resolves original
logical paths only through the retained catalog. A missing entry or CAS file
never falls back to a nearby original filename. All source artifacts remain
leased, and replay uses their concrete opened paths through publication.

The dedicated `kn.approved_image_scope_collection_journal.v1` policy admits one
`image_scope_approval` transaction containing every unique input CAS file, the
reference, policy, manifest and assessment root. Its ID is the physical root
hash. Membership verification requires exactly the catalog's declared member
set; missing and extra committed members are rejected. Closure requires all
those paths plus the final `scope-session-ID.knscopeledger` member under
`image-approvals`. This `kn.image_scope_approval_session.v1` ledger separates
logical input bytes from unique retained member bytes. Existing journal
policies reject the new transaction kind. Recovery lists its root in
`committed_approval_paths`; CAS sweep files are not standalone replay entry
points in `committed_sweep_paths`.

Private-store admission, directory pins, retained output leases, immutable
retries, prefix recovery and explicit GC apply to this full closure. The fixed
assessment path preserves its first evaluation time/report across interrupted
and closed retries, including later policy expiry. A managed root can supply
the original inputs for retry or a new collection after source removal; a new
collection evaluates the separately supplied policy at its own evaluation time.
Committed inputs and roots, final ledgers and uncertain membership remain
protected from GC. Eligible uncommitted CAS files require exact-member policy.

Scoped archive results use `kn.image_scope_approval_collection.v1`; replay uses
`kn.image_scope_approval_replay.v1`. The caller must supply the policy digest
again. Original replay requires exact assessment equality at the recorded time;
`/current` reevaluates the retained policy at host time. Physical membership can
verify even when a rehashed assessment lies, so semantic replay remains a
separate check. Neither result proves atomic observation, authenticated time,
issuer signatures, native lifetime continuity, current state or power-loss
durability. The direct archive policy and historical report format are unchanged.

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

### Common direct-image claim policies

Successful direct recipe v1/v2 replay also returns `claim_assessment`, with schema
`kn.image_claim_report.v1` and policy `kn.image_claim_policy.direct.v1`. The
adapter uses the same code-owned `kn.claim_registry.v1` evaluator as the IRP
adapter. It recomputes the existing typed image proof after reference verification,
ordered replay or explicit current reanalysis. It never accepts a stored claim
or ownership label as an observation. The original recipe, normalization and
comparison-result bytes remain unchanged.

`image_requested_range_matches_reference` requires the full requested range to
match; a qualified stable difference contradicts it even if other bytes are
excluded or unavailable. `image_compared_range_differs_reference` requires two
recorded reads confirming the changed compared bytes; a qualified full-range
match contradicts it. Missing identity, incompatible accounting, incomplete reads
or missing confirmation leave the claim `unfulfilled`. Excluded/unread bytes
are not `not_applicable` and do not establish a match or absence of changes.
Both policies require the original recipe/reference, an explicitly selected
implemented comparison policy, mapped identity, consistent typed comparison
and completed comparison observations before a positive or negative result.

Each report includes code-owned requirement definitions, support/refutation
references containing the recipe payload SHA and JSON pointer, missing
requirements, exact supported/counterexample address ranges and a bounded next
observation suggestion. The suggestion executes nothing. V1 read pointers resolve
under `/payload/reads`; v2 pointers resolve to original receipts under
`/payload/read_set/reads`. All references belong to one recipe. This is not a
cross-capture identity bridge or proof of authenticated collection.

The seven ledgers retain the existing image proof's independent discovery,
address, temporal, semantic, persistence, replay and trust meanings. Repeated
read traffic is separate from unique requested comparison coverage. The replay
ledger describes the comparison policy; `evaluation` explicitly identifies the
current claim policy on replayed observations, and `original_claim_policy_reproduced`
is false. `/current` also sets `recorded_normalization_reproduced=false` because
the current verifier recomputes normalization from the retained reference.
Those fields describe this evaluation itself. For new direct capture roots,
the separate `original_claim_replay` outcome verifies the preserved evaluation
as described above; journal membership remains unchecked.

There are exactly two claims, bounded to 256 Ki UTF-16 code units, with all
difference ranges preserved for the at-most-4,096-byte direct recipe.
`report_complete` refers only to this two-policy projection. Failed replay emits
`claim_assessment=null`. Slice and sweep use the separate adapters described
below; their existing proofs remain available. A scoped
match/difference does not prove execution, writer, maliciousness, authorization,
whole-image integrity or continuous observation. Other object/image adapters,
their original claim publication/reproduction and qualified cross-capture joins
remain open parts of P08.

### Slice and sweep claim policies

Original-policy slice and sweep replay also emits `kn.image_claim_report.v1`,
using `kn.image_claim_policy.slice.v1` or `kn.image_claim_policy.sweep.v1` with the
common evaluator. Slice claims assess all executed requested ranges or the
existence of a stable difference. Sweep claims assess the declared temporal
schedule or a stable difference within one of its verified member recipes.
Neither reports an atomic image snapshot. Unsupported `/current` comparison
reanalysis still fails explicitly; current claim evaluation is a separate step.

`AssessImageSliceClaims` consumes the freshly replayed typed pages and the exact
recipe. It independently checks disjoint range classification, original expected
and observed byte agreement, the recorded direct/secondary normalization basis,
and original accepted parser calls. A difference witness requires two distinct
returned receipts that agree on compared bytes. Failed primary prefixes and
secondary reference reads cannot substitute for those target observations.
The witness identifies the first stable changed range, both parser calls and
their returned receipts, the normalization entry, and secondary inputs when used.
Counts describe all stable difference bytes/ranges; the witness is an explicit
selection, not a complete changed-range listing. The original recipe and legacy
proof retain the full ranges.

Sweep claims are evaluated only after replay checks the root manifest, each
child recipe digest, exact reference, raw artifact when declared published,
target/address-space labels, range membership and acquisition interval. Claim
facts refer to this verified manifest membership; the witness links onward to
the original child recipe. This bridge binds recorded artifacts under one
declared collection. It does not authenticate the collector or establish a
process/mapping lifetime. Substituting another child's digest, target namespace
or interval prevents assessment.

Complete matching requires nonempty complete membership, qualification of every
range and a full comparison under each range's recorded policy. A stable local
difference contradicts that match claim and supports the difference claim even
when another slice is absent, the tail is unknown, or another page failed.
Missing membership/qualification requirements remain visible beside the
contradiction. Exclusions, an unconfirmed change and an empty/unattempted
comparison stay unfulfilled; they are not not-applicable or evidence of a match.

The address ledger keeps one exact compared/skipped/failed/unvisited partition
per original slice, with its policy, relocation basis, range indices, interval
and reference to replayed original ranges. It explicitly makes no combined
coverage assertion across policies or times. Discovery separately records the
scheduled and replayed range counts, missing entries and unvisited schedule
bytes. Temporal coverage remains acquisition-only, without a known event-loss
denominator or mapping lifetime. Persistence separates original target/secondary
read traffic, stored bytes including repeated/failed attempts, and missing raw
publications. A retained recipe can prove its compared bytes despite a missing
separate raw archive; that loss still prevents the legacy whole-sweep publication
claim. Journal membership and claim-report persistence are not inferred.

Reports contain exactly two claim assessments and all original policy partitions,
bounded to 2 Mi UTF-16 code units and at most 2,048 manifest members.
`report_complete` describes that projection, not whole-image coverage or every
possible difference witness. The remaining semantic, replay and trust ledgers
retain unknown hotpatch epoch, original comparison versus current claim policy,
and unauthenticated/undeclared approval limits. Invalid replay emits no claim
report. Eligible original slice/sweep claims are retained and reproduced through
the publication contract above; other object/lifetime adapters remain P08 work.

## Cross-bundle temporal candidates

`TemporalFactStore` relates an explicit set of 2..32 retained `.kncase` files.
The versioned `kn.local_temporal_candidate.v1` policy keeps every observation
separate and evaluates every pair as `supported`, `contradicted` or `unfulfilled`.
A supported edge means the two recorded observations satisfy this target/clock
policy and are close in that recorded scope. It does not mean they share an object or
mapping lifetime, or that one caused the other.

New KMON reference captures can publish `kmon.bundle.v2` / `kmon.evidence.v2`.
Their original hashed payload includes a random collector namespace, collection
ID, read-session ID, locally observed boot ID, native connection epoch and the
`kn.local_collector_binding.v1` policy. The producer compares the native epoch
before and after capture and requires the recorded target boot to match the
local collector. Unavailable or changed binding inputs do not acquire a binding;
the original evidence can still be retained in the legacy format. Requeuing a
historical bundle through another monitor does not confer a new local binding.
The read-session ID is a label, not an object reference or authentication key.

The join requires matching collector/collection namespaces, target boot and
process generation, native epoch, address contracts and recorded identity
assertions. Known/unknown EPROCESS or session assertions do not match, so an
unknown observation cannot bridge contradictory known observations. Different
collectors, VMs or boots cannot join merely by reusing PID, VA, PFN or a boot-ID
string. Cross-collector calibration and external provider namespaces require a
separate correspondence policy; this policy does not accept an operator-supplied
bridge. Collector-origin fields are unauthenticated retained assertions, not
proof against a malicious collector or owner who forges a bundle.

Capture begin/end, event FILETIME, event tick, arrival tick/sequence and unknown
publication time remain distinct. The policy compares capture intervals in the
recorded `GetTickCount64` domain only. Overlapping intervals stay unordered; late
arrival never changes original event or capture times. Gap thresholds refer to
recorded API ticks, not precise wall-clock intervals. The API's resolution is
limited by the system timer; no FILETIME or external-clock conversion is inferred.
See the [Windows clock contract](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount64).
No continuous observation, intermediate write, execution or causal relation is
established. Equal mapping-generation labels, addresses, PFNs and page hashes are
reported only as similarities, including when a join is denied.

Legacy v1 files retain their existing parser and replay behavior. Missing origin
metadata yields an unfulfilled join, never an inferred namespace. The report
labels its decoded reference representation as `normalized_legacy_compatible`;
legacy address assumptions remain marked separately from original source IDs.
New v2 files require their exact canonical schema and an original address
descriptor; the v1 missing-descriptor fallback cannot supply that requirement.
Old readers can reject that new version
rather than silently discarding its binding. The single-bundle graph below is
unchanged. The temporal report does not rerun image comparison or invent raw
reads, source authentication, mapping continuity or missing collection members.

Input membership is bounded to 32 files / 64 MiB and read under a cooperative
5-second loading budget. An invalid, missing or duplicate observation prevents
publication of partial joins. Query traversal has a separate 0..5,000 ms budget,
1..128 pair decisions per page and a maximum recorded gap of 0..300,000 ms.
Individual synchronous file calls are not interruptible deadlines. All original
observation nodes accompany each page so every relation resolves to its exact
bundle payload and original field location. `ktf1` continuations bind immutable
content membership, policy, gap threshold, limit and canonical pair offset;
path spellings and arrival order do not define identity. Relation IDs also bind
the query interpretation. These are consistency checks, not authorization.

The report is private `kn.temporal_facts.v1`, including renamed JSON. Broader
temporal graph storage, cross-collector receipts, image-sweep/object adapters,
mapping-lifetime change claims, clock calibration and execution/I/O relations
remain separate P07 requirements.

## Retained fact graph

`EvidenceGraph` adapts one validated `.kncase` to evidence, recorded process or
address-space, raw memory-range and address nodes. It preserves missing spans
as missing states. `derived_from` edges identify provenance; `references` edges
require retained bytes reconstructed by the existing slot/head decoder. An
indirect transfer retains both its instruction and slot span references.
Unsupported register targets, inconsistent references, identity conflicts and
future receipts do not create asserted reference targets. Independently valid
static bytes may still yield a reference when other capture spans are missing.

Node/edge IDs bind the policy, original bundle digest and normalized content.
PID, address and PFN alone are never join keys. This version does not join
bundles. Every edge names its original digest, receipt, evidence spans and
shared context: source, dependency group, historical state, collector capture
interval, original comparison coverage and unknown layout/security domain.
The original receipt remains recorded metadata. It is not a new ownership,
execution, writer, whole-system completeness or authenticated collector claim.
Image verification must use its separate recipe/proof path.

Queries run over the materialized graph without acquiring more memory. One
input is limited to 2 MiB/128 spans; materialization rejects more than 256 nodes
or 512 edges. Breadth-first traversal visits both edge directions, with depth
0..8, at most 128 records per page, a cooperative cancellation flag and a
0..5,000 ms traversal budget. File I/O, canonical validation, static replay and
materialization precede that time budget and are not interruptible deadlines.
Original edge direction is retained in output. Records are ordered as visited
nodes followed by selected edges; a page can contain only edges whose endpoints
appeared earlier. Depth zero returns only the root. An edge between two boundary
nodes is not expanded until another depth is allowed.

`kg1` continuations bind graph digest, root, depth, record limit and record
offset. They survive process restart; changed content or query scope rejects
them. The budget can be increased without changing result identity. A cursor is
consistency metadata, not authentication or permission. Failed, cancelled or
deferred queries return no result records and no successful total. `status=ok`
means the bounded query succeeded; gaps and incomplete capture stay explicit.
The output schema is private investigation data and the publication scanner
rejects standalone copies even when renamed. Generic object graphs, qualified
cross-source joins, runtime type layouts and hypothesis/claim graph adapters
remain separate work.

## Offline dump observation source

The ordinary `DumpObservationSource` path and the existing dump analyzer share
their LA48/LA57 translation implementation, including 4 KiB, 2 MiB and 1 GiB leaves.
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

Adding `/receipts` selects the typed walker and returns `kn.dump_read.v1`: the
virtual read, ordered translation receipts and a shared physical read set. PTE
reads, rechecks and payload reads all consume that operation's byte/call/span/
receipt/deadline limits; they are the reads used for the result, not later
evidence-only rereads. Physical file reads retain raw Win32 status and reported
copy counts. A payload hole does not erase a successfully observed translation,
and a failed translation cannot supply payload bytes or permissions. Original
bytes remain usable as evidence after the source handle closes.

This envelope covers the requested virtual range after source initialization.
Header/run validation and paging-depth probes performed while opening the file
are explicitly outside that read set. The physical source's 52-bit ceiling is
the dump format's range limit, not observed target MAXPHYADDR. The dump metadata
does not establish MAXPHYADDR, NXE or 1 GiB feature support, so the receipt's
target fields and paging permissions remain unknown. Its decoded address is
usable for locating captured file bytes, not a verified live CPU translation.
Wider collector migration and durable translation replay remain open.

`dump-read /init-receipts` emits `kn.dump_read.v2`. Its initialization record
belongs to the same deny-write file handle as the requested range. A failed open
returns the decision and any reads already made, with a null range. A successful
open places the existing v1 range observation under `requested_range`. Source
initialization and the requested range have separate operation IDs and budgets.

The initialization record charges each header or physical lookup before it runs.
The fixed ceiling is 45 attempts and 8,544 requested bytes. It covers an 8 KiB
header and the two candidate paging depths, including a list head that crosses
a page boundary. Each logical list read retains the original sparse states and
links to its ordered file attempts. An uncaptured physical range has no file
offset. An actual file call retains the Win32 status and transfer count. File
rows hash only the stable bytes returned by that attempt. The collector issues
no extra reads to populate the log. The depth decision distinguishes a usable
context, a unique list match, disagreement and ambiguity. Collector ticks measure
local access time. Verifying a digest later requires the original saved file.

### Typed crash dump diagnosis

The offline crash command takes an AMD64 Windows kernel dump and a caller
SHA-256 pin. It holds the local input against writes and deletion, reads
the SDK `DUMP_HEADER64` directly, and gives DbgEng its own read handle
to the same file. After DbgEng ends the session, the retained input must
still have its original identity and digest. Both decoders describe the
same artifact. Capture provenance and the occurrence of a host crash
require additional evidence.

The typed client requests a kernel dump target and records the HRESULT
of each issued query. A matching stop code and four matching parameters
support `matched_stop_data`. A failed initial event can still yield the
stored tuple. Stack collection requires a successful initial event and a
debugger break on the dump. Per-frame module membership requires a
reported loaded range containing the instruction offset. A candidate
component also requires the first frame to match the header's saved
instruction and stack pointers. One contradictory selected register prevents
that finding even when its peer is unavailable. Missing register reads and debugger-unwound frames remain
visible. [DbgEng dump handles](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nf-dbgeng-idebugclient4-opendumpfilewide),
[typed bugcheck query](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nf-dbgeng-idebugcontrol-readbugcheckdata),
[debugger stack frames](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/ns-dbgeng-_debug_stack_frame)

The report compares a WHEA stop indication, a component present in the
saved context and possible earlier corruption. A matching `0x124`
tuple in a live-generated, offline-generated or unqualified dump retains
the code and the need for a WHEA error record. A mapped module identifies
a location. Unwind validation, code verification, the first writer,
allocation history and causal attribution require other sources.
The one-shot client uses typed calls with local search paths, module
symbol loading and image mapping disabled. [WHEA stop parameters](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x124---whea-uncorrectable-error)

### Stop-linked WHEA records

The optional WHEA query requires a saved AMD64 kernel target at its
initial break, an ordinary dump with recognized attributes and agreement
between both stop decoders on `0x124` and all four parameters. Parameter 1
must describe a documented AMD64-compatible source. Parameter 2 supplies
the sole starting address. The typed client reads through the same dump
handle session and stops at the declared record extent. [Windows WHEA stop parameters](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x124---whea-uncorrectable-error)

Each `ReadVirtual` request stops at a 4 KiB boundary. Successful short
reads extend the contiguous prefix. An error or zero-byte return ends
acquisition. The report retains request offsets, HRESULTs, byte counts
and the SHA-256 of the successfully read prefix. The limits are 1 MiB,
128 descriptors and 512 calls. Header revision `0x0210` and descriptor
revision `0x0300` use the Windows SDK layouts. Descriptors must name
nonempty, disjoint sections beyond their table. Descriptor order,
padding and trailing capacity are preserved by the full record hash.
[DbgEng virtual reads](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nf-dbgeng-idebugdataspaces-readvirtual),
[UEFI Common Platform Error Record](https://uefi.org/specs/UEFI/2.10/Apx_N_Common_Platform_Error_Record.html)

Memory, generic processor and PCI Express sections expose selected fields
when the producer sets their validity bits. Windows x86/x64 machine-check
section versions 2 through 4 expose the bank status and qualified address
and miscellaneous registers. Version 4 includes the counted extra banks.
Each valid bank can be compared with the two 32-bit halves of the status
in a machine-check stop. Unrecognized sections keep their GUID, extent and
payload digest. [Windows machine-check section](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_whea_xpf_mca_section)

The fatal-error hypothesis checks the header against the most severe
section and retains qualifications such as simulation, recovery, an older
record, a driver-provided source or inconsistent bank status. Missing
bytes and undecodable fields remain explicit. Verifying the crash on a
particular host or attributing it to a device or driver requires evidence
independent of the dump.

### Saved WHEA event comparison

An optional second fixed-drive input holds the XML of one Windows System
event. Its own SHA-256 pin and read lease bind the comparison to the
export's bytes. The command uses XmlLite in document mode with DTDs
prohibited, external resolution disabled and a 32-level depth limit.
Input is bounded to 8 MiB, 4,096 reader nodes and 1 MiB of decoded
payload. The event parser accepts XML namespaces and consumes named
fields only at their Windows Event schema locations. Duplicate identity
or payload fields leave the comparison unresolved. [Windows Event schema](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-eventtype-complextype),
[Windows event rendering](https://learn.microsoft.com/en-us/windows/win32/wes/rendering-events)

The installed WHEA-Logger version-zero templates for IDs 1–3, 16–29
and 40–47 expose `Length` and binary `RawData`. The comparison checks the
System channel, provider name and GUID, event ID and version, record ID,
UTC timestamp and decoded length. If the dump has a linked CPER, the
report compares the complete byte lengths and SHA-256 digests and cites both
observations. A partial dump or unavailable event retains the corresponding
missing evidence. Matching bytes corroborate the representation in the
two inputs. Export provenance, host identity, boot identity and the
cause of the crash remain separate questions.

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
