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

The owned read also publishes a `process_read_set` from the shared recorder
described below. Its single receipt is the same observation as `process_read`;
the probe does not reread the control range to construct evidence.

`tools/generate-support-matrix.py --exe x64/Release/KnLiveDbg.exe --check`
detects documentation drift without probing a target. Generation accepts only
an unprobed compiled inventory and atomically replaces the Markdown output.

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

Cross-bundle graph associations, source-initialization receipts, other KMON reader paths,
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
record. Finally, the writer publishes the read-session ledger and commits its
closure record. The existing `persistence` and file counters describe individual
files; `journal_read_batches_*`, `journal_sweeps_*` and final pipeline
`image_journal_closed`/`image_journal_close_failed` describe collection publication.
A read batch can retain a reference or recipe even when raw-file publication
failed; consult both sets of counters. Closure does not imply complete target
observation or successful comparison/replay.

`session.knsession` (`kn.evidence_session.v1`) fixes the collection ID and
`kn.image_collection_journal.v1` policy. Each create-new `.knjseg` record
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
65,536 member/dependency references, 2 MiB per JSON record, 64 MiB per reference
blob and 1 GiB of total file reads. Writer read accounting lasts for the open
journal; recovery/index accounting lasts for that invocation. The 120-second
deadline is checked between synchronous operations, not an I/O cancellation
guarantee. Index reads share this budget. Logical reference bytes and unique
content bytes cover only the verified collection prefix; they do not measure
physical disk allocation, orphan volume or global cross-collection retention.
GC, retention priorities, large-store continuation beyond these bounds and
media/power-loss testing remain P06 work. Files are flushed before create-new
rename; the observed-process-interruption tests do not establish power-loss
durability or collector authenticity. All journal/index/recovery artifacts are
private evidence.

## Image store membership inventory

`!kmon store <artifact-root> [/artifacts] /json` returns private
`kn.evidence_store_inventory.v1` for the root's `collections`, `image-reads`,
`image-references` and `image-sweeps` namespaces. Legacy `.kncase`/`.knverify`
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
also limited to 1 GiB. The shared 120-second deadline is cooperative between
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
identity. The directory is renamed by its held handle without replacement. A
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
production integration is `dump-read /receipts`, described below.

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

## Pending I/O observation graphs

The native pending-IRP reader retains every admitted request, including requests
with no registered completion. It validates the supplied thread's PID, TID and
creation time, its list window, the packet header and repeated packet/stack
reads. The same reader is compiled into the standalone ASan fixture. Optional
PDB-resolved `Cancel`, `PendingReturned`, `IoStatus.Status`, device and file fields
remain null when unavailable; offsets and pointer targets are not guessed.

KMON emits `io.request_observation` with a private `kn.irp_observation.v1` report
in `irp_observation_json`. The ordinary observation ring/log and watch filters
apply; routine snapshots are suppressed from live console printing. Each report
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
IRP allocation references, cross-observation joins, raw-read replay, dispatch/
completion event providers, wait/lock graphs and deadlock diagnosis remain open.

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
authentication. Full loaded-image identity binding, isolation of live symbol consumers
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
attestations and isolation of live symbol consumers remain open. Files and
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
JSON operation in the command process, and other SymbolEngine consumers are
unchanged.

The broker passes three read-only file handles. The runner reopens each file
object with an independent cursor and includes only those copies in the child
handle list. PE decoding uses the approved image handle; DIA receives a bounded
read-only `IStream` over the approved PDB handle, followed by a GUID/age check on
the DIA global scope. It uses neither `loadDataForExe` nor a symbol-search path.
Stream clones have independent cursors and serialize access to their shared
handle. Out-of-range seeks, writes and truncation fail. This follows the
[DIA stream input contract](https://learn.microsoft.com/en-us/visualstudio/debugger/debug-interface-access/idiadatasource-loaddatafromistream)
and Windows [explicit handle inheritance](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute).

Windows loads the trusted installed provider DLL by pathname. Its lease also
pins non-reparse ancestor directories against rename/delete and verifies the
pathname's file ID before loading. This closes a pathname replacement gap while
the original leased DLL still exists elsewhere. The installed executable and DLL
remain trusted runtime inputs; their hashes do not attest provider authenticity.
The public command and `kn.type_schema.v1` format remain compatible. Old packages
can still be inspected, but their producer-reported identities are not converted
into a fresh broker verification by inspection.

The child receives a filtered primary token: administrator SID is deny-only,
privileges other than traverse are removed, integrity is low and the inherited
no-write-up policy is checked. Its restricting SID list retains the current user,
standard read-access groups and logon SID needed by the window station. A new
private low-integrity desktop is created and released with the request. These
choices follow the Windows [restricted token contract](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken)
and [mandatory integrity model](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control).
The initial environment contains only OS-derived SystemRoot/WINDIR. Handle
inheritance is limited to three approved read-only artifact copies, one output
pipe and a NUL input handle; controller,
token and credential environment handles/values are not forwarded.

Windows 10 or later is required for atomic job assignment through
[PROC_THREAD_ATTRIBUTE_JOB_LIST](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute).
The job allows one process, limits committed memory to 512 MiB and kills its
worker when the final parent job handle closes. A suspended child is resumed
only after creation with those restrictions. Parent supervision caps stdout and
stderr together at 2 MiB, checks cancellation and enforces a 60-second elapsed
budget once process creation returns. Failed cleanup is explicit; synchronous
OS process creation/termination is not a hard real-time deadline. A large PDB
can fail the memory budget even if it passes the input-file size limit. Existing
host job or desktop restrictions can make setup unavailable.

This boundary contains selected parser faults and resource use. It is not an
AppContainer, a filesystem allowlist, an egress policy or authenticated parser
attestation. The child retains some access under the same user, and artifact
hashes/provider paths do not establish approved distribution. Network-denied
execution, live SymbolEngine migration, runtime object/anchor binding and isolation
of all untrusted parsers remain open. No network lookup is requested by this
schema path, but the token/job combination does not enforce a network deny rule.
Parent artifact hashing has a cooperative 30-second limit per hash; the child
timeout is not a hard deadline for the whole broker operation or synchronous I/O.

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

`--verify-process-image` adds a handle-based live transaction in
`kn.image_recipe.v2`. It uses a duplicated handle bound to the requested PID and
creation FILETIME, explicit residency consent and one shared operation budget.
The actual qualifier, comparator and confirmation reads produce the saved
`kn.read_set.v1`; there is no post-verdict acquisition for the recipe. Receipts
retain the full source contract, request, consent, original status and reported
copy count, any native transport metadata, and operation/read identifiers.
The recipe reader verifies counters, ordering, source consistency and parser
projection before replay. Pending, abandoned, missing, overrun, cross-source or
fallback receipts cannot become an executable recipe under this single-source
format. A recorded failed or denied read remains a failed or denied parser input.

The live CLI requests only process read/query access and returns before driver,
service, symbol or monitor initialization. It uses the Win32 user-address ceiling
with an explicitly assumed legacy LA48 shape; it does not infer CR4.LA57. The
default acquisition budget is five seconds, 64 source calls/receipts and 128 KiB
requested bytes; synchronous reads cannot be preempted. Reference opening,
hashing and parsing precede that acquisition budget. Both v1 and v2 retain the
same direct comparison policy and support post-exit replay. V1 remains readable;
its writer refuses new metadata that it cannot represent rather than dropping it.

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
Background KMON/native-fallback publication, secondary-view recipes, signed reference distribution
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
The legacy output and other dump/image collectors retain their existing path;
initialization receipts, wider migration and durable translation replay remain open.

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
