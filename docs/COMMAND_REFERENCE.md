# Command guide

This guide describes workflows and output contracts. `help <command>` and
`<command> help` provide the current grammar; `KnLiveDbg.exe --help all` is
available without elevation, a driver, or symbols. Tab completion uses the same
command definitions in the local and remote consoles.

## Restricted one-shot launches

On current `main`, put `--mode offline` or `--mode observe` first. Each
invocation runs one operation and exits before controller startup. Use
`--mode offline --help` or `--mode observe --help` to list the operations
available in that mode. Both accept `--capabilities` for the compiled
inventory. That inventory describes the binary across all launch paths.

Both modes can query one saved `kn.execution_trace.v1` file or a native
`kn.etl_profile.v1` through `v8` CPU profile page. Redirect a
readable regular file on a fixed local volume to standard input. For example,
in **cmd.exe**, using a saved trace named `saved trace.kntrace` in the working
directory, run

```bat
KnLiveDbg.exe --mode offline trace - /limit 2 < "saved trace.kntrace"
```

The result carries the SHA-256 of the exact bytes read. To continue, pass
`/cursor` with the returned token, the same limit and the same input file.
The 2 MiB input limit also applies here. A pipe, device, metadata-only handle,
conflicting writer, offline file or unqualified volume produces an unavailable
result. The parser accepts only trace data. It never resolves paths from the
record or opens a file named on the command line in these modes.
A restricted launch that rejects a saved ETL reader emits its decision to
a pipe or console. If standard output is a disk file, it returns the denial
or syntax exit code without writing to an input through a hard link.

`KnLiveDbg.exe --mode observe --capabilities --probe --allow-residency` reads
one known 32-byte range in its own process. The consent flag allows the read
to affect page residency. The report includes the process generation, the read
receipt and a `process_handle_timeline` for this invocation. A successful sample
records the open, the source's duplicate, and a close for each acquisition.
It marks native sources as outside
the launch policy. The command exits 1 if it cannot confirm the expected bytes.

A denied operation exits 5 with `blocked_by_policy`. Invalid selector syntax
exits 2. A misplaced or repeated selector fails before other launch options
can run. Controller sessions, capture, evidence-store writes, MCP and remote
connections all require a separate launch. `collect` and `lab` are reserved
and currently return `mode_unavailable`.

## Capability reports and evidence commands

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
support certificate. The compiled report's `probe_contracts` lists each
standalone invocation and what it checks. Match an operation's `probe_contract`
to a catalog ID to find its scope. A null value means the executable declares
no standalone probe for that operation. The generated table includes these
bindings. [Address and backend contracts](SUPPORT_MATRIX.md)

To check what a saved Windows ETL contains, supply the file and its SHA-256 to
the standalone probe. In this example, `case.etl.sha256` contains the 64 hex
digits supplied with the capture. The probe reads the ETL before controller startup.

```powershell
$etl = (Get-Item -LiteralPath .\case.etl).FullName
$pin = (Get-Content -LiteralPath .\case.etl.sha256 -Raw).Trim()
$report = & .\x64\Release\KnLiveDbg.exe --capabilities --probe-etl $etl --sha256 $pin | ConvertFrom-Json
$report.capabilities | Where-Object backend -eq etl | Select-Object operation, availability, record_evidence
```

The probe checks CPU samples, context switches, disk I/O and hard page faults. In a
`saved_etl_probe` report, `record_evidence` gives the decoded and unsupported
counts and the first decoded event's one-based position among all records. Its
payload length and SHA-256 identify the original bytes at that position.
`available` applies to a record family in the supplied file. A family with
unsupported layouts, missing records or a capture coverage gap reports `partial`.
`no_matching_records_observed` means the reader reached the end without seeing
that family. A failed pin or scan gives `unavailable` and null record evidence.
The file hash identifies the bytes. Producer authenticity and the target
environment still require independent evidence.

The ETL probe exits 0 for a stable scan with matching buffer totals and no
reported loss, including a file with zero records in all four families. Exit 1 covers a
coverage gap or an unusable source. Exit 2 covers syntax and output errors,
including a redirected output whose identity cannot be separated from the input.
Restricted launches reject this named-file operation. A rejection with a named
ETL returns its exit code silently when standard output points to disk, since
checking a possible file alias would require opening a named input.

For a saved AMD64 full dump, `--probe-dump` takes the SHA-256 of the first
8,192 bytes. Use the header digest recorded with the capture when available.
The following PowerShell example computes the digest locally for a repeatable
read and checks the 16-byte module list head declared by the header.

```powershell
$dump = (Get-Item -LiteralPath .\case.dmp).FullName
$pin = python -c "import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],'rb').read(8192)).hexdigest())" $dump
$report = & .\x64\Release\KnLiveDbg.exe --capabilities --probe-dump $dump --header-sha256 $pin | ConvertFrom-Json
$report.capabilities | Where-Object { $_.operation -eq 'read_virtual' -and $_.backend -eq 'dump' } |
    Select-Object availability, probe_stages, range_evidence
```

Add `--range <hex-va> <decimal-length>` to read 1 through 4,096 bytes at an
explicit virtual address. The optional trailing `--expect-sha256 <digest>`
compares the complete sample with known bytes. Hex input accepts either case.
The header pin covers the header alone. The sample hash and each span hash
identify bytes read from the selected range. The default list control also
checks reciprocal links using the selected paging depth. An explicit address
has no object semantics, even when its digest matches.

Exit 0 qualifies the selected range. Exit 1 includes a header mismatch,
unusable source, sparse range, incomplete list control or sample digest
mismatch. Exit 2 indicates invalid arguments or an output failure. A range
with holes retains the offset, length and original state for each span.
`range_evidence` is null when the source or default range could not be
qualified for a read. Named dumps use the same restricted-launch and
output-alias protections as named ETLs. These checks apply to writes by the
running command. A shell can truncate its destination before launch. Saved
dump reports are private.

`process_handles_acquired` and `process_handles_closed` count successful
Windows calls during the self-probe. A failed close retains its acquisition
ID and Win32 error in the timeline. `probe_handles_closed` requires equal
counts and a successful close for any native device the probe opened.
`native_close_succeeded` and `native_close_win32_status` are null when the
probe had no native device to close. [Process handle evidence](TIMELINE_COMMAND_USAGE.md#inspect-process-handle-ownership)

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

To build an inventory across processes, include `/resume` on the first
direct offline call and repeat it with the same source and output. For example,
`KnLiveDbg.exe --offline !kmon inventory cases index-001 /resume /chunks 4 /json`
commits up to four new 128-entry chunks per call. Both `checkpointed` and `ok`
return exit 0. Wait for `ok` and a nonempty `snapshot_digest` before using
`/inventory index-001`. Keep the source stopped throughout. A different
membership or file generation needs a fresh output directory.

Add `/verify-entries N` to spread the final read of originals across calls.
For example, repeat `KnLiveDbg.exe --offline !kmon inventory cases index-001 /resume /chunks 4 /verify-entries 64 /json`.
Each call verifies at most 64 additional members once construction is complete.
`verified_entries` counts the entire checked prefix, `reused_verified_entries`
counts rows accepted from the preceding signed record, and `read_bytes`
counts source payload bytes read in this call. Use the same executable and
Windows profile. The first signed record creates a non-exportable signing key
in that user's Windows software key store. Keep the output directory private.
A damaged signature, a different executable, or a key from another profile
returns `invalid_verification_checkpoint`. Use a fresh bounded output or omit
`/verify-entries` to recheck all originals in one call.
After `deadline_exhausted`, the next bounded call can use the last completed
verification record. The full catalog and construction-chain checks still
have to fit within an invocation.

To reconcile publications across all query windows, run
`KnLiveDbg.exe --offline !kmon evidence cases /inventory index-001 /closure /json`.
Supply the source and index on local fixed drives. A reparse point in either
directory path returns `invalid_path`.
The command rereads the valid members of the completed v1 snapshot and reports
unique bundles, duplicate files, conflicting ledgers and missing publications.
Each unambiguous collection ledger is also checked against the canonical UTF-8
byte count of its unique bundles. The ledger's failed and dropped counts
remain visible even when all reported writes can be accounted for.

The default budget is 8 GiB of original payloads with a 120,000 ms cooperative
deadline. Use `/max-bytes N` and `/deadline-ms N` to set positive decimal
limits for one call. Budget exhaustion or an invalid index returns a null
`assessment`. A terminated CLI process can leave no report. Rerun the command
from the beginning. A completed
scan with gaps returns `partial_inventory` and the measured global counts.
Exit 0 indicates reconciled publication counts and bytes, 1 indicates gaps
or an incomplete scan, 2 indicates invalid arguments, and 3 indicates output
failure. The command always writes JSON. Case filters and cursors apply to the
ordinary paged query.

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

`KnLiveDbg.exe --offline !kmon redact-image <recipe-directory|kncapture|knslice|knsweep>
<new-private-root> [/acl-only] [/json]` replays a saved original and publishes
minimized comparison counts plus a private original-hash linkage. A direct
`recipe.knverify` path is also accepted. The default requires EFS; no target
acquisition or AI provider request occurs. `--offline !kmon disclosure <root> [/json]` inspects
the completed package. Both always emit private `kn.disclosure_package.v1` JSON:
0 means ready, 1 denied/unavailable/incomplete, 2 invalid grammar and 3 output
failure. Publication is create-new; an output failure does not undo it.

`KnLiveDbg.exe --offline !kmon redact-irp <capture.knirp> <new-private-root> [/acl-only] [/json]`
creates a private package of historical IRP counts. A raw v2 capture yields
observed counts and a null original-claim field. A capture with an embedded
claim report also yields its outcome and omission counts after exact
reproduction. Use `disclosure <root>` to inspect it and `ai share preview <root>`
to review the minimized facts and destination. EFS is the default. Exit codes
match `redact-image`. [IRP disclosure semantics](ARCHITECTURE.md#minimized-irp-disclosure)

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
verifies a stopped `collections/<collection-id>` image or IRP journal and returns
private `kn.evidence_journal_recovery.v1` JSON. It reports the committed prefix,
closure/unknown tail, exact collection-scoped byte denominators and committed
sweep paths. File presence alone does not establish membership. A live writer
holds the exclusive collection lock, so recovery reports unavailable while it
is active. `/index` resumes publication of derived chunks and an immutable head;
original files are revalidated even if an index exists. Corrupt existing output
is preserved and reported. No orphan deletion or new target acquisition occurs.
Exit 0 means a verified prefix and, when requested, a ready index; the prefix can
still have an unknown tail. Exit 1 means unavailable/incomplete recovery or index
failure, and 2 means invalid grammar. A valid retired journal returns 0 without
`/index` and reports historical manifest membership. It returns 1 with
`/index` and `index_status:retired`. Pass a returned active sweep path relative to the
artifact root to `replay-image` or `graph` for separate policy verification.
See [journal bounds and recovery semantics](ARCHITECTURE.md#image-collection-publication-journal).

`KnLiveDbg.exe --offline !kmon store <artifact-root> /scan-catalog [/limit 1..1024] [/cursor token] [/json]`
checks the original journals and members of a stopped store in collection-name
order. Each call checks up to 64 collections by default. Save its
`next_scan_cursor` locally when the status is `more`, then pass that value to
the next call. After an interruption, retry the last acknowledged cursor. On
`complete`, pass the returned `scan_receipt` to the inventory command below.
Each row reports its own closure, unresolved input or retirement. The page
status describes progress through the catalog.

`KnLiveDbg.exe --offline !kmon store <artifact-root> /scan-files [/limit 1..1024] [/cursor token] [/json]`
reads physical original files in 64 KiB blocks, up to 64 blocks by default.
Each row identifies the path, byte offset, actual length and SHA-256, or
records why the entry could not be included. Save `next_file_cursor` when
the status is `more`. After an interruption, pass the last saved value to
`/cursor` to resume within the file. A locked range can be retried after it
becomes readable. A namespace mismatch requires a fresh scan. On `complete`,
pass `file_receipt` to the full inventory. Keep the ranges and tokens private.

`KnLiveDbg.exe --offline !kmon store <artifact-root> [/scan-receipt token] [/file-receipt token] [/retention] [/artifacts [/limit 1..4096] [/cursor token]] [/json]`
audits stopped image and IRP collections together and returns private
`kn.evidence_store_inventory.v1` JSON. It reports closed/open/unresolved roots,
exact member/path/content byte denominators and protected retention classes.
With `/file-receipt`, the inventory rechecks the range hashes against its
own reads of original files. Loose files can use the remaining 8 GiB
aggregate read budget after journal reads. Pass the same receipts when
requesting the next artifact detail page.
`/artifacts` includes per-path ownership detail. For example,
`store <artifact-root> /artifacts /limit 100` starts a page. When
`artifact_page_status` is `more`, pass its `next_artifact_cursor` to the next
`store <artifact-root> /artifacts /cursor <token>` call. `artifact_row_offset`
counts earlier rows and `artifact_rows_remaining` counts later rows.
Restart from the first page after a cursor mismatch. A loose direct or scoped approval reports `approval_catalog` on its
root. Present declared inputs list `uncommitted_approval_referrers` with the
root path, physical SHA-256 and whether the input matched. The summary counts
unreadable catalogs, missing inputs and mismatched inputs.
For a loose image capture, read, slice or sweep, inspect `image_catalog` on the
root and `uncommitted_image_referrers` on each present input. Referrers report the
physical root hash, expected input hash, digest basis and whether the input
matched. A sweep identifies reads and slices by their unwrapped payload hashes.
Images identify PE references by their file hashes. IRP captures report
`irp_catalog`. A present IRP reference lists each referring capture under
`irp_referrers`, including the expected byte count and whether the capture
belongs to a journal. The inventory counts missing and mismatched IRP
references per capture. Active participating
publishers make the audit unavailable. The exclusive audit lease blocks new
publication attempts until the audit finishes. Use it
after collection stops. Exit 0 means complete verified membership and artifact
inventory and a usable requested page. Exit 1 covers partial or unavailable
inventory, cursor mismatch and a row exceeding the page budget. Exit 2 means
invalid grammar and exit 3 means offline output failure. The returned
report grants no deletion authority. See [scope, coordination and bounds](ARCHITECTURE.md#image-store-membership-inventory).

`KnLiveDbg.exe --offline !kmon retire-collection <artifact-root> <policy.json> [/scan-receipt token] [/file-receipt token] [/apply] [/json]`
ends an identified closed collection's retention. Save a verified store
inventory and prepare the private policy with
`python tools/new-evidence-gc-policy.py --inventory inventory.json --retire-collection 7 --reason "retention period ended" --output retire.json`.
The helper defaults to a 24-hour minimum closure-file age and a 128 MiB limit
on exclusively owned nonledger bytes. Preflight reports the exclusive, shared
and failure-ledger impacts. Adding `/apply` records the policy and those counts
in the collection's retirement receipt. Exit 0 means planned, retired or a
matching receipt was reused. Exit 1 means denied or incomplete, 2 means
invalid grammar and 3 means output failure. Inspect the receipt after an
interrupted apply or output failure. [Retirement semantics](ARCHITECTURE.md#closed-collection-retirement)

For a store with more than 1,024 collections, pass the terminal `scan_receipt`
from `store /scan-catalog` on both preflight and apply. For more than 1 GiB of
loose-file reads, pass the terminal `file_receipt` from `store /scan-files`.
The two options can be combined and also apply to `gc`. Each command reads the
current originals under its own exclusive lease and evaluates the policy only
after the supplied receipts verify. A catalog supports up to 16,384 entries
and the full inspection has an aggregate 8 GiB read budget.

To budget routine originals across closed KMON image, IRP and native image
acquisition collections, save a successful `store <artifact-root> /retention`
report as UTF-8 in a private directory. Each root reports its class and
exclusive routine bytes.
For a native acquisition, `source_copies` on its root lists the original
file digests, the retained collection ID and the number of active copies.
Its exclusive routine bytes count the extra named files that retirement
would release. The class totals cover the whole store even when artifact
detail is paged.
For a 128 MiB target, run
`python tools/new-evidence-gc-policy.py --inventory inventory.json --retire-excess-routine 134217728 --reason "routine archive budget" --output routine.json`.
Use `--minimum-age-seconds` for the minimum closure age and `--byte-limit`
for the maximum exclusive bytes per withdrawal. Preflight with
`KnLiveDbg.exe --offline !kmon retire-collection <artifact-root> routine.json`.
Add `/apply` to publish the retirement receipt. Refresh the inventory before
selecting another collection. A separate file GC policy is required to reclaim
physical files. [Cross-collection routine budget](ARCHITECTURE.md#cross-collection-routine-budget)

`KnLiveDbg.exe --offline !kmon gc <artifact-root> <policy.json> [/scan-receipt token] [/file-receipt token] [/apply operation-id] [/json]`
preflights an explicit policy by default. Prepare one with
`python tools/new-evidence-gc-policy.py --inventory inventory.json --path image-reads/reads-123-4.knreads --reason "obsolete unpublished observation" --output policy.json`.
The input must be a successful `store /artifacts` page containing all selected
paths. When saving it in PowerShell,
use `Set-Content -Encoding utf8`. The helper defaults to a 24-hour minimum file
age and 128 MiB total named bytes. Repeat `--path` for explicit additional members.
Review the generated policy and preflight result before using `/apply` with a
canonical decimal operation ID of at most 20 digits. The same ID resumes that
exact operation; it cannot select a new policy or another physical root.

Retirement changes the catalog recovery rows. Removing a named file changes
the file scan. Before retrying with receipts, repeat the affected scan and
pass its new terminal token with the original policy and, for GC, the same
operation ID. GC checks the durable intent and per-file outcome on that retry.

GC denies removal of inputs held by uncommitted image archives, approvals and IRP captures
on initial preflight and retry. An unreadable declaration protects possible
inputs in its family. To withdraw an eligible loose sweep or approval, select
the root in a separate operation. A later preflight checks whether any
surviving capture, read, slice, sweep, approval or journal still needs the
selected files. An IRP capture in a closed journal can also name a PE that
was absent at publication. Once that PE appears, GC protects it.

To release files after retirement, save a fresh `store /artifacts` inventory.
Use `--from-retired-collection 7` with one or more `--path` arguments to the
same helper and a new policy output. It selects only `retired_requires_policy`
rows owned by that retired collection. GC validates the named retirement
receipt and current dependencies again. The inventory reports historical
membership and distinguishes verified replacements, absent paths and paths
whose current contents or presence could not be established.

Exit 0 means planned or historically completed. Exit 1 covers denial,
incomplete work and unresolved deletion outcomes. Exit 2 means invalid
grammar. Exit 3 means the CLI could not write the result. After an output
failure during apply, inspect the private operation history before retrying.
`deleted_this_call` excludes old receipts and absence after an interrupted
intent. Receipt reuse never deletes a later replacement. This command is
offline-only and does not remove committed roots or failure ledgers. See
[GC policy, audit and interruption semantics](ARCHITECTURE.md#explicit-uncommitted-artifact-gc).

`KnLiveDbg.exe --offline !kmon relate <2..32 file.kncase paths> [/gap-ms 0..300000]
[/limit 1..128] [/cursor token] [/budget-ms 0..5000] [/json]` evaluates temporal
candidates across explicit retained observations. Defaults are a 30,000 ms
recorded gap, 64 pair decisions and a 1,000 ms query budget. The separate input
budget is 5 seconds / 64 MiB. No target acquisition or provider request occurs.

Every pair retains its requirements and contradictions. `supported` requires
matching recorded local-collector, process-generation, source and clock bounds;
legacy or missing origin assertions remain unfulfilled. It does not establish
mapping continuity, execution, writing or causality. All observations and source
digests accompany each page. Continue with the same content membership, gap and
limit; a zero query budget defers the query. Output is private
`kn.temporal_facts.v1` JSON with or without `/json`. Exit 0 means the query ran,
even when no pair is supported; 1 means invalid/unavailable input or cursor,
cancellation or budget deferral; 2 invalid grammar; 3 output failure. This command
is offline-only. See [cross-bundle temporal candidates](ARCHITECTURE.md#cross-bundle-temporal-candidates).

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

Use `/init-receipts` for the evidence used to open the dump. For example, the
four-level fixture from `tools/validate-dump-source.ps1` can be read from its fixture directory:

```text
KnLiveDbg.exe --offline !kmon dump-read probed-4.dmp ffff800000100000 8 /init-receipts /json
```

In `kn.dump_read.v2`, `initialization.decision` explains how the reader accepted
or rejected the dump. The fixture returns `unique_probe` and selects four levels.
Each logical list check identifies its first file-read sequence and count. The
file rows give offsets, requested lengths, SHA-256 of the observed bytes and
native I/O results. A null seek or read status means that call did not run.
If opening fails, `requested_range` is null and the command exits 1. An accepted
source includes the normal `kn.dump_read.v1` range result. Specify one receipt
option per command. The direct v2 command exits 3 if writing the report fails.
When the reader cannot establish that a redirected diagnostic goes to a file
separate from its input, it skips the write and exits 2. Restricted `--mode`
rejects named dump reads and sends its decision to a pipe or console. For a disk
sink it returns the policy or syntax exit code without writing. Both receipt
formats are private evidence.

`KnLiveDbg.exe --offline !kmon verify-image <reference> <dump> <hex-base> <hex-rva> <length> <new-directory> /json`
captures one 1..4,096-byte executable comparison and its exact reference into a
new case directory using its parent's access controls. The dump must meet `dump-read` requirements. Base and RVA
are hexadecimal. Supply locally trusted reference files; parsing is not isolated.
The result's ownership and coverage determine the byte-comparison outcome;
`status=recorded` means the case was published, including when reads are partial.
New cases atomically retain the recipe and its original claim evaluation in
`kn.image_claim_publication.v1`; `original_claim_recorded=true` confirms publication.

`KnLiveDbg.exe --verify-process-image <pid> <creation-filetime> <reference> <hex-base> <hex-rva> <length> <new-directory> --allow-residency [--trace-loader]`
captures the same direct comparison from a live process into a v3 case. PID,
creation FILETIME and length are decimal; base and RVA are hexadecimal. The
supplied generation must match the opened handle, and the caller needs process
`PROCESS_VM_READ | PROCESS_QUERY_INFORMATION` access. `--allow-residency` is required because reads can affect page
residency. The `kn.image_capture.v3` JSON report records the original read
receipts in order, the caller's consent, the Win32 status and the number of
bytes copied. It supports one AMD64 direct-image range of 1..4,096 bytes,
with a legacy LA48 assumption and the OS user ceiling recorded explicitly.
It has no native fallback or background-monitor capture. Successful publication
may still report an unverified or modified range. The command runs before
driver or symbol initialization.

Use a separate file or a pipe for the report. With an inherited disk handle,
the command checks the writing stream against the reference and the requested
case, including hard links to files inside an existing case. An unsafe or
unverifiable destination returns exit 2 without writing to that stream.
Malformed arguments receive the same check before usage goes to disk. If the
command exceeds its nine-operand limit, usage goes only to a pipe or console.
A restricted launch returns its policy exit code and suppresses the disk
diagnostic. Exit 3 indicates delivery failed on an admitted output. A case
published before a delivery failure remains available for replay. These checks
cover writes made by the executable. A shell that truncates the destination
before launch, or writes pipeline output itself, controls that file separately.

In a console, Ctrl+C or Ctrl+Break requests a cooperative stop. If a read or
mapping query observes the stop and the case is published, the command returns
exit 1 with `status=interrupted` and `original_claim_recorded=true`. The case
retains completed reads, the cancelled observations and the original verdict
for the requested range. `replay-image` reports `capture_interrupted=true`
when it reproduces that case, including from a managed archive. A signal
received after the final observation leaves the completed verdict intact. Capture
stdout also includes the original handle actions. [Replay a process image source receipt](#replay-a-process-image-source-receipt)

V3 also retains `VirtualQueryEx` calls before and after each read and a final
query of each distinct read range. `result.mapping` separates consistent
observations, unavailable queries and `inconsistent_capture`; conflicts or
unavailable mapping fences leave the requested comparison bytes failed and
withhold reference qualification and approved changes. Stable private/mapped
buffers can still support byte comparisons; `native_image_mapping_observed`
identifies actual `MEM_IMAGE` observations at the declared allocation base.
Matching queries do not exclude unobserved unmap/remap, prove original backing
or establish execution. Both original and `/current` replay use retained query
records, including after target exit. Existing v1/v2 cases remain readable.

With `--trace-loader`, enable the collector provider before starting capture.
The capture adds the inner `recipe_sha256`, Win32 `loader_marker_status` and
`loader_marker_submitted` to its JSON. When the provider is disabled at startup,
the command exits 1 before the first read. If submission fails after publication,
the original case remains available and the command exits 1.

`KnLiveDbg.exe --etl-image-lifetime <local.etl> --sha256 <etl-digest> --capture <case-directory|managed.kncapture> --recipe-sha256 <recipe-digest>`
replays the original case and checks process and loader events against the
recorded read times. Exit 0 covers a bracketed interval or a recorded transition.
Exit 1 covers incomplete evidence or a digest mismatch. Exit 2 covers grammar
and output errors. [Trace configuration and report fields](TRACE_IMPORT.md#native-loader-intervals-for-image-captures)

To verify a saved loader report, add `--check-page <report-sha256>`.
You can also supply `--capture-statement <statement.jws> <capture_controller|archive_witness> <trusted-p256-point>`.
The receipt identifies the replayed recipe, original claim, claim publication,
retained PE and exact report bytes. A matched report with missing process
boundaries still exits 1. [Verify a retained loader report](TRACE_IMPORT.md#verify-a-retained-loader-report)

`KnLiveDbg.exe --etl-image-lifetime --compare <trusted-controller-point>` takes two
`--observation <etl> <etl-sha256> <case> <recipe-sha256> <report-sha256> <controller-statement>`
groups. Exit 0 returns the ordered raw byte comparison for the same process
generation and image range. Exit 1 returns both endpoint results and the
reason a relation could not be established. [Inputs, examples and timing limits](TRACE_IMPORT.md#compare-two-retained-native-image-observations)

`KnLiveDbg.exe --offline !kmon journal-image <case-directory> <private-store> <collection-id> /json`
archives an existing direct recipe/claim publication and its exact reference into
a store initialized by `init-store`. The collection ID is a canonical decimal
string of 1..20 digits. One collection holds one direct capture operation.
The command returns `kn.image_capture_collection.v1`; `archived` requires the
capture, closure and indexes to succeed. `capture_committed`, `closed`, `indexed`,
`capture_created` and `reference_created` distinguish partial outcomes and reuse.
The returned `capture_path` is relative to the private store. It is a managed
`.kncapture` file that can be passed to `replay-image` after the source case is
removed. `journal <private-store>\collections\<id> /index /json` separately verifies
membership. Replay does not claim that this journal check occurred.

Exact retries reuse the same files and transactions. Different committed input
or a conflicting existing output is rejected; no original is replaced. Exit 0
means archived, 1 means incomplete/unavailable, 2 means invalid arguments, and 3
means JSON delivery failed after any already completed writes. The action also
routes through interactive `!kmon` as a file-writing command without opening a
driver. It preserves the source directory and does not encrypt that old copy.
Root/reference limits are 4 MiB/64 MiB. See
[direct capture collections](ARCHITECTURE.md#direct-image-capture-collections).

`KnLiveDbg.exe --offline !kmon assess-image <directory|managed.kncapture|slice.knslice|sweep.knsweep> <changes.knchange> <policy.knapproval> <policy-sha256> /json`
evaluates authorized changes without new target reads or file writes. The final
argument is the lower-case SHA-256 obtained through the analyst's approval
process, separately from the evidence. Do not derive trust from a digest supplied
by the capture itself. The policy pins the exact manifest bytes, reference image
and issuer at the same epoch. Evaluation requires original replay and validity
at capture and current host time. Scoped input also checks every declared sweep
start and child observation time. There is no `/current` override.

Both input files are UTF-8 JSON (no BOM), at most 64 KiB. Required fields are:

| Document | Fields |
| --- | --- |
| `.knapproval` | `schema="kn.image_approval_policy.v1"`, `policy_id`, `policy_epoch`, `not_before_filetime`, `not_after_filetime`, `approvals` |
| Each approval | `image_sha256`, `manifest_sha256`, `issuer` |
| `.knchange` | `schema="kn.authorized_image_changes.v1"`, `image_sha256`, `issuer`, `policy_epoch`, `not_before_filetime`, `not_after_filetime`, `comparison_policy`, `hash_basis="non_fixup_compared_bytes.v1"`, `changes` |
| Each change | `rva`, `length`, `before_sha256`, `after_sha256` |

Numbers are decimal strings without leading zeros; time values are Windows
[FILETIME](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime)
ticks (100 ns since 1601-01-01 UTC). Validity windows include the start and exclude the end. Arrays contain
1..128 entries; changes are sorted and disjoint, with lengths 1..4,096. Hashes
are 64 lower-case hex digits. Before/after hashes cover exactly that RVA span
in the comparison; fixup and excluded spans cannot be exceptions in v1. Unknown
or duplicate fields, ambiguous scopes and unsupported policies fail explicitly.
The exact file digests include whitespace; changing formatting requires new pins.

`comparison_policy` must match the original root: `kn.executable_page.direct.v1`
for direct captures, `kn.executable_slice.direct.v1` or
`kn.executable_slice.secondary.v1` for slices, and
`kn.executable_sweep.temporal.v1` for sweeps. Scoped results use
`kn.image_scope_change_assessment.v1` and list each rule's contributing recipe,
RVA and capture time. Cross-slice assembly requires all bytes to qualify;
it does not establish an atomic snapshot. Missing observations and unexplained
changes remain separate. Limits are 2,048 slices, 16,384 pages and 4 MiB output;
an oversized result is unavailable with `replay_output_included=false`.

The result preserves the original replay and distinguishes authorized changes,
unexplained changes, no observed change and incomplete comparison. `R-approved`
is relative to this caller-pinned policy; `issuer_signature_verified=false`
remains explicit. Exit 0 means assessment completed, including unexplained or
incomplete results; 1 means unavailable, 2 invalid grammar, and 3 stdout delivery
failure. Interactive `!kmon` uses the same read-only route and transcript. The
approval collection commands below retain direct and scoped inputs and
assessments for later reproduction. See
[approved image changes](ARCHITECTURE.md#approved-image-changes).

For a policy distributed by a TUF publisher, first install the optional
dependencies in the selected Python environment with
`python -m pip install -r tools/requirements-publisher-truth.txt`.
Set `$python` and `$debugger` to that interpreter and the native executable.
Set `$publisherReference` to the retained TUF envelope, `$sourcePolicy`
to the exact published policy file, `$manifest` to the change manifest and
`$reference` to the whole retained PE file or its `.knblob` (up to 64 MiB).
Use the approval authority's independently configured `$trustedRootSha256`
for the initial root and its case-sensitive `$policyTarget`. A v2 reference
can carry up to 32 successive root revisions. A v3 reference also retains
delegated roles for that path. The receipt records the ordered search, and
every consulted role's expiry limits the native approval window.
[Prepare the publisher reference](BENCHMARK_CORPUS.md#verify-a-file-against-a-publishers-release)

Set `$minimumRootVersion` to
the last trusted root version recorded for this authority, or to `$null`
to leave that check unset. Supply `$verificationTime` as UTC in
`YYYYMMDDTHHMMSSZ` form, `$selectedPolicy` as a new filename in a private
directory and `$capture` as the retained native capture to assess.

For a publisher history file, set `$previousCheckpointSha256` to the
predecessor digest from the independent case record and supply the current
observation's recorded time. Set the variable to `$null` for a first
observation or an ordinary reference.
[Create a publisher history file](BENCHMARK_CORPUS.md#check-a-publisher-update-against-a-previous-observation)

Set `$requireWindowsPublisher` to `$true` to require a v2 source policy, or
`$false` to allow v1. A signed v2 policy always enforces its Windows checks.
Set `$catalog` to the retained catalog file for a catalog row and to `$null`
for an embedded or v1 row. The reference and catalog each have a 64 MiB limit.
Choose a new `$receiptPath` inside an initialized private store. The issuer
emits one line of ASCII JSON followed by LF. PowerShell captures the line
without its delimiter, so the example restores that byte before saving it.
Record the resulting receipt digest in your independent case record.

```powershell
$approvalOptions = @()
if ($previousCheckpointSha256) { $approvalOptions += @('--previous-checkpoint-sha256', $previousCheckpointSha256) }
if ($null -ne $minimumRootVersion) { $approvalOptions += @('--minimum-root-version', $minimumRootVersion) }
if ($requireWindowsPublisher) { $approvalOptions += '--require-windows-publisher' }
if ($catalog) { $approvalOptions += @('--catalog', $catalog) }
$receiptJson = & $python -B tools/provision-image-approval.py --publisher-reference $publisherReference `
    --trusted-root-sha256 $trustedRootSha256 --verification-time $verificationTime --policy-target $policyTarget `
    --policy $sourcePolicy --manifest $manifest --reference $reference --out $selectedPolicy @approvalOptions
if ($LASTEXITCODE -ne 0) { throw 'Image approval provisioning failed' }
$receiptBytes = [Text.Encoding]::ASCII.GetBytes($receiptJson + [char]10)
$file = [IO.File]::Open($receiptPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try { $file.Write($receiptBytes, 0, $receiptBytes.Length) } finally { $file.Dispose() }
$receiptSha256 = (Get-FileHash -LiteralPath $receiptPath -Algorithm SHA256).Hash.ToLowerInvariant()
$receipt = $receiptJson | ConvertFrom-Json
& $debugger --offline '!kmon' assess-image $capture $manifest $selectedPolicy $receipt.native_policy_sha256 /json
if ($LASTEXITCODE -ne 0) { throw 'Image assessment failed' }
```

The TUF target can use `kn.image_approval_policy.v2` with the v1 policy fields
and one additional `reference_signature` object on **every** approval row.

| Field in `reference_signature` | Signed value |
| --- | --- |
| `kind` | `embedded` or `catalog` |
| `signer_certificate_sha256` | Lower-case SHA-256 of the file signer's DER certificate |
| `revocation` | `none` or `cached_chain` |
| `catalog_sha256` | Lower-case whole-file SHA-256, required only for `catalog` |

Provisioning exits 0 after publishing one policy row and writing its private
JSON receipt. A signature, target, document or approval mismatch exits 1 with
a rejection reason and a null policy pin. The v2 receipt includes the Windows
check under `windows_publisher`. A missing catalog, unavailable file lease,
over-limit Windows input or failed WinTrust check also exits 1. The receipt
records the WinTrust status in hexadecimal when Windows performed the check.
Use the top-level `provisioned` status and returned policy digest to continue
to native assessment. Invalid arguments, an occupied destination and ordinary
document I/O errors exit 2. The output file is created
before its receipt is delivered. Keep the signed source policy, reference
envelope, original receipt and any catalog for the
[portable approval archive](#portable-publisher-approval-archives). See the
[approval policy design](ARCHITECTURE.md#publisher-signed-image-approval-policies)
and the [Windows publisher validation results](VALIDATION.md#windows-publisher-verification-for-retained-pe-files-on-2026-11-24).

`KnLiveDbg.exe --offline !kmon journal-image-approval <directory|managed.kncapture|slice.knslice|sweep.knsweep|assessment.knscopeapproval> <changes.knchange> <policy.knapproval> <policy-sha256> <private-store> <collection-id> /json`
archives one assessment and its exact inputs into an `init-store` private
root. The policy digest is a separate trust input as for `assess-image`; the ID
is 1..20 canonical decimal digits. Direct results use
`kn.image_approval_collection.v1`, scoped results
`kn.image_scope_approval_collection.v1`. Both use `archived` only after the
complete input transaction, dependent closure and
indexes succeed. `committed`, `closed`, `indexed` and `historical_root_reused`
distinguish partial outcomes and retries. `approval_path` and `capture_path` are
relative to the private store; `capture_path` applies to direct archives.
Scoped results include logical input counts/bytes and unique input files/bytes.
Their exact root, child recipes and declared raw archives use content-addressed
`.knscopeblob` files and an explicit original-path catalog. A missing input
cannot be recovered from an adjacent file with the old name.

Retry with the same ID and exact inputs to finish an interrupted archive. A
published assessment retains its original evaluation time and result, even if
the policy has expired since publication. Changed input or a conflicting file is
rejected without replacement. This is historical retention, not current approval.
The command leaves source copies unchanged. Direct capture/assessment limits
are 4 MiB; scoped inputs are at most 4,097 files, 2 MiB each and 256 MiB total,
with an 8 MiB approval root. Reference is 64 MiB and policy/manifest 64 KiB each.
Scoped assessment limits remain 2,048 slices, 16,384 pages and 4 MiB. A managed
`.knscopeapproval` supplies retained inputs for retry or a new collection, with
the separately supplied policy and manifest. Exit codes are 0 archived,
1 incomplete/unavailable, 2 invalid grammar, 3 JSON delivery failure after any
completed writes. Interactive `!kmon` treats this as a file-writing command.

`KnLiveDbg.exe --offline !kmon replay-image-approval <assessment.knapprovalcase|assessment.knscopeapproval> <policy-sha256> /json`
reproduces the stored assessment from its exact managed capture or scope input
catalog, reference, policy and manifest at the recorded evaluation time. Supply the independently
trusted digest again; the archive does not establish its own authority. Success
requires exact original-report equality and returns `reproduced` with
`original_assessment_reproduced=true`. Add `/current` to evaluate the retained
policy at current host time; this returns `reanalyzed` and keeps
`recorded_assessment` separate from `assessment`. It does not select a newer
policy, and expired approvals remain unavailable in this mode.

Replay is read-only and does not open a target or establish journal membership.
Use `journal <private-store>\collections\<id> /index /json` for that separate check.
Exit codes are 0 reproduced/reanalyzed, 1 unavailable, 2 invalid grammar and
3 JSON delivery failure. Both modes preserve comparison gaps and unexplained
changes; success is not a clean-image or current-state claim. See
[approved image collections](ARCHITECTURE.md#approved-image-collections) and
[scoped collections](ARCHITECTURE.md#scoped-approved-image-collections).

#### Portable publisher approval archives

After `journal-image-approval` closes a collection, use `pack` to retain it
with the evidence that authorized its native policy. Set `$collection` to
the source store's `collections\<id>` directory. Set `$archivePath` to a
new `.knapprovalarchive` filename directly inside an initialized private
store. For replay, set `$privateWorkspace` to an initialized private store
with at least the protection required by the archive. A store created with
`!kmon init-store` requires EFS by default. Use `/acl-only` when that is
the intended evidence protection.

Use the same publisher, target and UTC instant as at issuance. Supply the
original receipt digest from the case record and `$debuggerSha256` from
the trusted installation. Set `$journalHeadSha256` to a separately recorded
closure head, or `$null` to verify membership using the archived chain.
The optional minimum root version also applies at replay. For a delegated
approval, replay verifies the original search and its per-parent signatures
using the metadata inside the archive.

For a history-backed approval, the independently pinned receipt supplies
the original predecessor checkpoint. Set `$previousCheckpointSha256` to
its independently recorded value to require an additional match, or to
`$null` to use the receipt. Both pack and replay return the verified
transition and checkpoint in `publisher_history`.

```powershell
$archiveOptions = @('--debugger', $debugger, '--debugger-sha256', $debuggerSha256,
    '--trusted-root-sha256', $trustedRootSha256, '--receipt-sha256', $receiptSha256,
    '--policy-target', $policyTarget, '--verification-time', $verificationTime)
if ($null -ne $minimumRootVersion) { $archiveOptions += @('--minimum-root-version', $minimumRootVersion) }
if ($previousCheckpointSha256) { $archiveOptions += @('--previous-checkpoint-sha256', $previousCheckpointSha256) }
if ($requireWindowsPublisher) { $archiveOptions += '--require-windows-publisher' }
if ($journalHeadSha256) { $archiveOptions += @('--journal-head-sha256', $journalHeadSha256) }
$catalogOption = @()
if ($catalog) { $catalogOption += @('--catalog', $catalog) }
$packedJson = & $python -B tools/archive-image-approval.py pack @archiveOptions --collection $collection `
    --publisher-reference $publisherReference --policy $sourcePolicy --receipt $receiptPath --out $archivePath @catalogOption
if ($LASTEXITCODE -ne 0) { throw 'Approval archive publication failed' }
$archiveSha256 = ($packedJson | ConvertFrom-Json).archive_sha256
```

Record `$archiveSha256` independently at publication. On a recovery host,
retrieve it and the other trust inputs from that record, and rebuild
`$archiveOptions` as above. Replay only needs the archive, interpreter,
trusted native executable and private workspace.

```powershell
$replayedJson = & $python -B tools/archive-image-approval.py replay @archiveOptions --archive $archivePath `
    --archive-sha256 $archiveSha256 --private-workspace $privateWorkspace
if ($LASTEXITCODE -ne 0) { throw 'Approval archive replay failed' }
$replayedJson | ConvertFrom-Json | Select-Object status, original_assessment_reproduced,
    original_windows_verification, current_windows_verification
```

Both operations return private JSON. Exit 0 reports `archived` or
`reproduced`, 1 rejects the evidence or an I/O operation, and 2 indicates
invalid arguments or an unsafe or unavailable output. For a Windows-signed
policy, inspect the original and current Windows results individually.
Historical reproduction can succeed when the current host cannot verify
the signer. A failed current check supplies no present-day approval.
See the [archive format and trust inputs](ARCHITECTURE.md#portable-publisher-approval-archives).

`KnLiveDbg.exe --offline !kmon replay-image <directory|managed.kncapture> /json` reruns the recorded
policy against either v1 or v2's retained artifact and ordered raw reads, including
recipes embedded in new claim publication roots. Add `/current` to
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

Direct v1/v2 replay also returns `claim_assessment` under
`kn.image_claim_report.v1`: current versioned match/difference policies, exact
original-read references, refutations, missing requirements and seven ledgers.
`original_claim_policy_reproduced=false` separates this derived assessment from
the reproduced comparison. `/current` recomputes comparison normalization and
does not assert that the recorded normalization was reproduced. Failed replay
returns `claim_assessment=null`. See
[direct-image claim policies](ARCHITECTURE.md#common-direct-image-claim-policies).

New direct capture roots also return `original_claim_replay`. Its `reproduced`
status requires the exact recorded registry/policy and complete report equality
after independent replay. Unsupported recorded claim policies or altered reports
fail original replay; `/current` instead reports `not_requested`. Legacy roots
report `not_recorded`. The embedded claim report retains its prepublication
fields; the separate outcome carries the later original-reproduction result and
publication/report hashes. See [original claim publication](ARCHITECTURE.md#original-direct-image-claim-publication).

Successful slice/sweep replay also returns current claim assessments under
`kn.image_claim_policy.slice.v1` or `kn.image_claim_policy.sweep.v1`. They retain
original selected receipts, a stable difference witness, missing requirements
and separate policy/time partitions. A stable local difference survives other
missing or failed ranges; full matching requires the complete scoped evidence.
Slice/sweep `/current` comparison reanalysis remains unsupported. See
[slice and sweep claims](ARCHITECTURE.md#slice-and-sweep-claim-policies).

Eligible new `.knslice`/`.knsweep` files also retain those evaluations in
`kn.image_scope_claim_publication.v1`. `original_claim_replay.status=reproduced`
requires exact recorded policy/report reproduction. Legacy or fallback files
remain `not_recorded`; failed original replay withholds proof and claims. The
2 MiB publication limit includes both the original artifact and report. Publication
events and hunt/session `slice_claims_*` / `sweep_claims_*` counters expose claim
storage failures separately from file and collection outcomes. Journal v3 and later bind
the whole physical file, but replay alone does not check journal membership. See
[slice/sweep publication](ARCHITECTURE.md#original-slice-and-sweep-claim-publication).

`KnLiveDbg.exe --offline !kmon replay-irp <capture.knirp> [/current] [/json]`
replays the original ordered IRP observations. New `kn.irp_claim_publication.v1`
files also require exact original Capture-mode claim reproduction by default.
Unknown claim policies, altered reports or missing original inputs return exit 1
with no matched summary or derived requests/claims. `/current` evaluates current
claims and explicitly leaves original claim reproduction `not_requested`; a
missing reference can then yield bounded, unqualified observations. Bare v2
captures retain their prior behavior and report original claims `not_recorded`.
The JSON separates physical `capture_sha256`, `original_capture_sha256` and
`original_claim_replay` from current `claim_assessment`. Evidence pointers use the
original capture hash. Exit 0 can reproduce negative or inconclusive evidence;
it does not establish execution, lifetime or collection membership. See the
[IRP publication contract](ARCHITECTURE.md#original-irp-claim-publication).

`KnLiveDbg.exe --self-test irp-publication <owned.knirp>` exercises the actual
KMON writer using an existing raw v2 test capture and its fixed sibling reference.
It covers original report publication, capture-budget fallback, unavailable
reference retention, journal closure, counters and temporary-file cleanup. It
does not load a driver. Use a fixture created by `tools/validate-irp-binding.ps1`;
the input files remain unchanged. The command emits JSON and returns 0 on success,
1 on test failure or 2 for invalid argument count.

`KnLiveDbg.exe --self-test capture-scheduler` runs the capture worker using owned
process memory and an absent kernel device. It emits JSON and exits 0 on success
or 1 on failure; extra arguments return 2. No driver is loaded. Runtime
`coverage.pipeline` events expose queue/service distributions through the
`capture_scheduling_json` evidence field. Quantiles are bucket upper bounds,
and urgency thresholds are not latency guarantees. See
[capture scheduling](ARCHITECTURE.md#capture-scheduling-and-latency).

`KnLiveDbg.exe --self-test reference-scheduler` checks execution-reference
admission and the actual drain using owned user memory and an unopened native
backend. It emits JSON and returns 0 on success, 1 on test failure or 2 for extra
arguments. No driver is loaded. `coverage.pipeline.reference_scheduling_json`
reports subject/role quotas, deferred scopes, resident observation debt and
separate successful/failed and normal/shutdown timing. Attempt cooldowns and
failed checks do not count as successful revisits. See
[execution reference scheduling](ARCHITECTURE.md#execution-reference-scheduling)
for retention bounds and unmeasured latency limits.

`KnLiveDbg.exe --self-test image-scheduler` checks production image lookup,
comparison, cursor/debt accounting and scheduling with owned files, synthetic
target bytes and controlled-time cohorts. It emits JSON and returns 0 on
success, 1 on failure or 2 for extra arguments; no driver is loaded. The private
`coverage.pipeline.image_scheduling_json` distinguishes successful slices,
gap-free traversal, failed attempts and pending resident work. Whole-turn and
verifier-stage timing report overruns of the cooperative 25 ms budget, including
minimum page progress and mandatory final checks. See
[image observation scheduling](ARCHITECTURE.md#image-observation-scheduling).

`KnLiveDbg.exe --self-test publication-scheduler` checks the production writer
with owned files and page/bundle reads, synthetic image/IRP inputs, blocked
journal publication and a page byte-budget failure. It emits JSON and returns
0 on success, 1 on failure or 2 for extra arguments; no driver is loaded.
`coverage.pipeline.publication_scheduling_json` reports family rotation, queue
and service timing, explicit local acquisition windows, and separate physical
file/journal outcomes. Per-job `coverage.publication` receipts link those clocks
to the original job ID. Unknown historical acquisition times stay unknown. See
[publication scheduling](ARCHITECTURE.md#publication-scheduling-and-completion-timing).

`KnLiveDbg.exe --self-test layout-scheduler` checks an owned native layout sweep
and mapping qualification, including a guard page, stale identity, original
expiry, a fresh observation retained for retry, and shutdown separation. Its
JSON places the four initial outcomes in `normal.normal.outcomes` and their
handle calls in `verification_handle_timeline.events`. It runs without a
driver and returns 0 on success, 1 on failure or 2 for extra arguments.
Mapping qualification checks the process identity and region metadata. The
private pipeline fields `layout_collection_scheduling_json`
and `layout_verification_scheduling_json` expose original debt, bounded scopes,
quota deferrals, collection/qualification latency and separate failure samples.
See [layout scheduling](ARCHITECTURE.md#layout-collection-and-verification-scheduling).

`KnLiveDbg.exe --self-test image-preparation` exercises asynchronous PE metadata
and comparison-content workers with owned reference files and synthetic target
bytes. It checks progress beside held workers, replacement and stale results,
native file-lease ownership, original-byte preservation, failure after success,
and queued/running shutdown. It emits JSON and returns 0 on success,
1 on failure or 2 for extra arguments; no driver is loaded. The private pipeline
fields `image_reference_preparation_json` and `image_content_preparation_json`
distinguish metadata/content preparation from actual image verification and
report bounded scopes, backpressure and timing. See
[reference metadata preparation](ARCHITECTURE.md#asynchronous-image-reference-metadata-preparation).
The [content preparation stage](ARCHITECTURE.md#asynchronous-image-reference-content-preparation)
retains the existing final file/content/target checks and closes source handles
before immutable evidence reaches publication.

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
symbols. The parent leases and hashes the three artifacts, decodes the bounded
PE identity, and checks the child's result against those exact inputs. The child
reads PE/PDB through approved read-only handles and loads the installed DIA DLL
with its pathname pinned. PDB type parsing runs with a restricted low-integrity
token, private desktop, allowlisted handles/environment, 512 MiB commit limit,
one-process job and 60-second child supervision budget. Parent file hashing has
separate cooperative limits. Unsupported containment or identity mismatch fails
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

Live `dt`/`dtx` layout and scanner field lookups now use the same restricted schema
worker, with parent acquisition from local roots or direct HTTPS SymStore paths.
Exact names take priority; case/leading-underscore aliases and case-insensitive
field paths must be unique. Recursive layout follows embedded members only, up to
the schema's eight-component bound. Unavailable parsing fails without an in-process
fallback. `dt` prints the schema hash, unchecked runtime-invariant status and any
incomplete field coverage. Opaque layout IDs expire when symbol/module state or
the bounded cache changes. See [live layout scope and cache limits](ARCHITECTURE.md#live-type-layout-broker).

Startup symbol preload, `x`, nearest-symbol lookup and wildcard `dt` now query
bounded metadata produced by a restricted symbol-index worker. Exact decorated
names disambiguate overloaded functions; a bare name searches previously indexed
modules. Failed acquisitions remain cached until a symbol-path or module refresh.
`x` and wildcard `dt` report result limits and unavailable modules. Verbose type
lists label `providerTypeId` separately from opaque layout IDs and show the index
hash and unchecked runtime-invariant status. MCP `symbol.search` adds size
availability, index hashes and a coverage note; incomplete results set `truncated`.
See [index scope and limits](ARCHITECTURE.md#live-symbol-and-type-index-broker).

### Replay a process image source receipt

Save the capture command's UTF-8 stdout as a separate file, including on
exit 1. Its `source_initialization` object records the requested PID and
creation FILETIME, each process handle acquisition and close, their Win32
results and the identities returned by the acquired handles. A failed
`OpenProcess` has one attempt. A generation mismatch retains the creation
time observed on the duplicate. A later reference failure can therefore
have a ready source and an unsuccessful image capture. Read counts for a
ready source come from the published read set.

Supply the SHA-256 of the saved report. For a published image also supply
its direct directory or managed `.kncapture` file. The command checks the
recorded handle sequence and reproduces the original image claim before
matching the source, operation, recipe digest and result.

```powershell
$pin = (Get-FileHash -LiteralPath $report -Algorithm SHA256).Hash
& $exe --offline '!kmon' replay-image-source $report $pin $case /json
```

Omit `$case` for a failed capture. Exit 0 then means the acquisition
receipt reproduced, and `capture_status` still reports `failed`. A
published capture with a missing or mismatched case returns exit 1.
Older capture reports return `source_receipt_missing`. Keep the report and
its pin alongside an archived case, or archive the acquisition together.

To check whether the captured code at a named AMD64 export referenced an import
address table (IAT) slot, pass `/iat:export-name` before `/json`. Export names
are case-sensitive. For example, a capture covering the export in `version.dll`
can be queried after the process exits.

```powershell
$page = & $exe --offline '!kmon' replay-image-source $report $pin $case '/iat:GetFileVersionInfoSizeW' /json | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw $page.status }
$page.iat_reference
```

For a managed source report, omit `$case`. An observed result gives the original
instruction bytes and read sequences, the slot RVA, and the imported DLL and
name or ordinal declared in the retained PE. `instruction_reread` records
whether two or more complete reads covered the instruction. The loaded slot
value, execution and mapping lifetime remain unverified. A reproduced claim
can return `iat_reference.status=unavailable` with a reason. A source without
a reproduced image claim returns `iat_reference=null`.

### Read a loaded import slot from a user minidump

Supply one saved AMD64 user-mode minidump, the importing PE, the SHA-256
recorded for each file and the case-sensitive export name. Both files must
be resident local files. The reader accepts up to 8 GiB per dump and 64 MiB
per PE, with up to 256 streams, 4,096 modules and 262,144 memory descriptors.
The export in the reference PE must begin with a supported RIP-relative jump
to an ordinary import slot. The reader requires a matching RSDS build identity
and the complete captured instruction, descriptor and eight-byte slot.

```powershell
$slot = & $exe --offline '!kmon' dump-image-iat $dump $dumpPin $reference $pePin $exportName /json | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw $slot.reason }
$slot | Select-Object import_module, import_name, import_ordinal, owner_status, target_module
```

The three import fields describe the ordinary import declared by the reference
PE. The target module identifies the module-list entry containing the value
saved in that cell. Windows can resolve an import into a different DLL.
The report records offsets into the pinned dump for the instruction and
slot, and a SHA-256 of the eight slot bytes. Keep the report with the private
dump. A null slot or a value outside the module list yields an observed slot
with an empty target. Missing bytes, ambiguous records or an identity mismatch
return exit code 1 and a reason. Invalid arguments return 2.

Add `/declaration` before `/json` to check the import declaration in the dump.
The nested `declaration_check` compares the descriptor, the terminated DLL
name and the lookup cell with the pinned PE. A named import also includes
the two-byte hint and the terminated function name. An ordinal is encoded
in the lookup cell. All locations come from the reference PE.

```powershell
$page = & $exe --offline '!kmon' dump-image-iat $dump $dumpPin $reference $pePin $exportName /declaration /json | ConvertFrom-Json
$page.declaration_check | Select-Object status, reason, coverage
```

`supported` means every requested declaration byte matched. A captured
difference yields `contradicted` even if other bytes are missing. Unreadable
or missing bytes and a lookup cell reused for the loaded IAT can leave the
check `unfulfilled`. Each field includes its PE file offset and digest. The
dump spans identify the exact matching, differing and missing portions.
The command's exit code still describes the slot observation. Inspect
`declaration_check.status` even when the slot could not be read. A complete
declaration can survive that gap, and a readable slot can coexist with a
contradictory declaration.

### Archive a user-minidump import observation

To replay an observation after the standalone files are removed, keep the
original UTF-8 stdout of `dump-image-iat`, including its final newline. Supply
that file, its SHA-256, the original dump and the reference PE to
`tools/archive-minidump-iat.py pack`. The tool checks the two input digests
recorded in the report and runs the named offline reader. Publication requires
the same exit status and identical report bytes. The archive contains the
entire supplied dump, including data outside the selected import.

Run from the repository root with an initialized private store and a new
archive filename. Use a trusted installed reader and its independently verified
digest. In this example `$reportPin` is the digest recorded for the original
stdout file. Retain it and the returned archive digest for replay.

```powershell
$archive = Join-Path $privateStore 'import.kniatarchive'
$readerOptions = @('--debugger', $exe, '--debugger-sha256', $readerPin, '--report-sha256', $reportPin)
$sealed = python -B tools/archive-minidump-iat.py pack @readerOptions --report $report --dump $dump --reference $reference --out $archive | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw $sealed.reason }
$restored = python -B tools/archive-minidump-iat.py replay @readerOptions --archive $archive --archive-sha256 $sealed.archive_sha256 --private-workspace $privateStore | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw $restored.reason }
$restored.observation | Select-Object status, slot_value_observed, declaration_check
```

Archive exit 0 means the recorded native outcome reproduced. A native gap
retains `native_exit_code=1` and its original reason. `/declaration` is
reapplied when the original report contains that check. Encrypted originals
require an EFS private store. An EFS archive requires an EFS replay workspace.
The scratch copies are removed after replay.
[Validation](VALIDATION.md#portable-user-minidump-observations)

### Recover an interrupted minidump archive

If the publisher exits before the final rename, select its
`.kniatarchive.pending-<32 hex digits>` file in the private store. Record its
current SHA-256 after the writer exits. Supply the original report digest and a
trusted reader as for `pack`. Recovery verifies the existing prefix and
reproduces the original native report before appending to the same file.

For example, when the header, report and PE survived and the dump stopped
partway through, supply just the original dump. Here `$pending` is the exact
file selected for this operation and `$archive` is a new name in the same store.

```powershell
$fingerprint = python -B tools/archive-minidump-iat.py hash --input $pending | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw $fingerprint.reason }
$pendingPin = $fingerprint.sha256
$readerOptions = @('--debugger', $exe, '--debugger-sha256', $readerPin, '--report-sha256', $reportPin)
$resumed = python -B tools/archive-minidump-iat.py recover @readerOptions --pending $pending --pending-sha256 $pendingPin --out $archive --dump $dump | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw $resumed.reason }
$resumed | Select-Object status, retained_prefix_bytes, appended_bytes, archive_sha256, native_exit_code
```

The `hash` command holds the selected local file and reports its logical byte
count and SHA-256. It accepts a stopped checkpoint, a finished archive or a
member up to the maximum archive extent. On a sparse file it includes every
zero in the digest and reads the ranges Windows marks as allocated. Compare
the result with an independently retained digest when one is available.
An I/O failure includes the available operating-system error codes.

Supply each incomplete member with `--report`, `--reference` or `--dump`.
A complete pending file needs only the pins. If the 64-byte header is
incomplete, use its original reader and supply all three originals. With a
complete header, a compatible reader can replay the report when
`--packing-reader-sha256` identifies the original verifier. Its digest
defaults to the digest of the reader performing recovery.

After another interruption, inspect the pending file again. A longer prefix
has a new digest. Keep any conflicting destination and choose a fresh name.
If the final name already exists and the reply was lost, use `replay` with
the expected archive digest to verify the published result. A successful
recovery returns exit 0 and carries forward the original native exit code.
If recovery runs out of space, its JSON includes the system error number
when available. Free space in the same private store and hash the surviving
pending file before retrying.
[Recovery tests](VALIDATION.md#interrupted-minidump-publication)

### Archive a process image acquisition

Use an initialized private store and a new collection ID. Supply the
collector's original UTF-8 stdout and its SHA-256. For a recorded or
interrupted capture, include the direct case directory or managed
`.kncapture` file. A failed capture needs only its report.

```powershell
$pin = (Get-FileHash -LiteralPath $report -Algorithm SHA256).Hash
$saved = & $exe --offline '!kmon' journal-image-source $report $pin $store 7 $case /json | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or !$saved.closed) { throw $saved.issue }
$savedReport = Join-Path $store $saved.report_path
& $exe --offline '!kmon' journal (Join-Path $store 'collections/7') /index /json
& $exe --offline '!kmon' replay-image-source $savedReport $pin /json
```

Exit 0 and `closed=true` confirm publication. The archived report retains
its exact bytes. Managed replay locates the case from the collection ID and
the report digest. Replay returns the original failed or interrupted
outcome as recorded. Keep the external pin when transferring the archive.
The journal command independently verifies the file membership and closure.
If delivery of the command result fails, an exact retry uses the same
collection ID and files. A committed ID rejects a different report.
Use `store <artifact-root> /retention /json` to find active copies of the
same acquisition and the collection that protects their original files.

## Trace an I/O request through completion

`KnLiveDbg.exe --io-lifecycle <wait-ms> <local-directory> [directories...]`
issues one asynchronous directory notification per argument. Supply 1–8
existing directories on fixed local volumes and 1–30000 ms of observation
time. Each request watches file and directory name changes in the selected
directory itself. The collector checks non-reparse ancestors with its current
credentials. Unavailable paths have their own admission result. The controller
records counts and Win32 results. Directory
contents, names of changed files and kernel addresses are omitted.

This PowerShell example watches the current directory and saves the original
private JSON Lines journal. Keep the argument order with the SHA-256 to map
each request generation back to its directory.

```powershell
$directory = (Get-Item -LiteralPath .).FullName
$records = & .\x64\Release\KnLiveDbg.exe --io-lifecycle 250 $directory
if ($LASTEXITCODE -ne 0) { throw 'I/O lifecycle capture failed' }
$file = [IO.Path]::GetTempFileName()
[IO.File]::WriteAllLines($file, [string[]]$records, [Text.Encoding]::ASCII)
$pin = python -c "import hashlib, pathlib, sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())" $file
python tools/replay-io-lifecycle.py $file --sha256 $pin
```

A quiet directory normally produces a pending observation, a wait timeout,
a cancellation attempt and a final aborted result. A change can complete
the request while cancellation is in progress. Read `native_final_result`
and `observed_completion` for the outcome of each generation. The wait
budget starts after submissions. Windows controls how long final
cancellation and cleanup take.
[Windows cancellation semantics](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelioex)

Replay returns a private `kn.io_lifetime_assessment.v1` report. Its
`evidence_lines` refer to one-based physical lines in the hashed journal.
A final line cut before its newline remains uncommitted. A missing sequence
ends the qualified prefix. Later records remain visible under
`unjoined_records`. The original plan supplies the denominator even when
a directory was unavailable or a request's final outcome is unknown.
[Request identity and state transitions](ARCHITECTURE.md#directory-io-request-lifetimes)

### Follow requests through an I/O completion port

Use the completion-port mode to determine which outstanding directory request
supplied each packet Windows returned to the issuing thread. The port is
private to one collector run. The journal contains process and thread
creation times, directory IDs and the original user-mode operation addresses.
Keep it with the ordered directory arguments in the private case.

`KnLiveDbg.exe --io-lifecycle --completion-port <wait-ms> <local-directory> [directories...]`

This example observes a quiet directory and replays both the timeout and the
subsequent packet returned while draining cancelled I/O.

```powershell
$directory = (Get-Item -LiteralPath .).FullName
$records = & .\x64\Release\KnLiveDbg.exe --io-lifecycle --completion-port 250 $directory
if ($LASTEXITCODE -ne 0) { throw 'Completion port acquisition failed' }
$journal = [IO.Path]::GetTempFileName()
[IO.File]::WriteAllLines($journal, [string[]]$records, [Text.Encoding]::ASCII)
$pin = (Get-FileHash -Algorithm SHA256 -LiteralPath $journal).Hash.ToLowerInvariant()
$json = python tools/replay-io-lifecycle.py $journal --sha256 $pin --completion-port
if ($LASTEXITCODE -ne 0) { throw 'Completion port replay failed' }
$case = $json | ConvertFrom-Json
$case.waits | Format-Table phase, relation, joined_generation, evidence_line
$case.requests | Format-Table generation, correspondence, packet_outcome
```

Each wait lists the outstanding generations and the original dequeue return.
`timeout_without_packet` leaves those requests outstanding. A later drain
packet can report success if a change completed during cancellation.
`packet_and_result_agree` requires the returned completion key and operation
address to identify one live request and the separate handle result to agree.
Check the case's **status** for coverage, even on replay exit 0. The collector
returns exit 1 if Windows cannot create its port and still writes the native
error when its output stream is available.
[Packet matching and release](ARCHITECTURE.md#completion-port-request-lifetimes)

### Measure directory notification timing

Use the journal and SHA-256 from the capture above.

```powershell
python -I -B tools/replay-io-lifecycle.py $file --sha256 $pin --timing
```

In the private `kn.io_lifetime_timing.v1` report, `signal_window` cites
the original lines for an accepted request and `submission_to_signal_ms`
gives the elapsed range. A null maximum means the recorded prefix ended
without a qualified signal observation. Conflicting records carry
`identity_conflict` with the source lines and leave both timing fields
null. Read `outcome` for the I/O result. A request can have a bounded
signal and an unknown outcome.

`monitor.wait_call_ms` counts each shared wait once across its listed
requests. `signal_order.possible_latest_generations` lists the candidates
that the observed windows allow. The list is null if the journal is
incomplete or any accepted request lacks a qualified signal. An empty
list means the complete journal had no accepted requests. Replay exits
with code 2 for an invalid journal or pin. Use a separate file when
saving the report.
[Timing bounds and clock resolution](ARCHITECTURE.md#directory-notification-timing)

### Observe the issuing thread during an I/O wait

On Windows x64, launch the directory notification collector with an
independent thread-state sampler. This example uses a quiet directory.
A timeout still contains an observation of the issuing thread if Windows
reported its state during the wait.

```powershell
$out = '.\.build\io-thread-wait-example'
New-Item -ItemType Directory -Path $out -ErrorAction Stop | Out-Null
$watched = (New-Item -ItemType Directory -Path "$out\watched").FullName
$exe = (Get-Item .\x64\Release\KnLiveDbg.exe).FullName
$exePin = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
$tool = 'tools/measure-io-waits.py'
$capture = python -B $tool capture --exe $exe --exe-sha256 $exePin --wait-ms 750 --interval-ms 20 --output "$out\capture.json" $watched | ConvertFrom-Json
$query = @('replay', '--capture', "$out\capture.json", '--sha256', $capture.capture_sha256)
$receipt = python -B $tool @query --output "$out\report.json" | ConvertFrom-Json
$report = Get-Content -Raw -LiteralPath "$out\report.json" | ConvertFrom-Json
$report.wait_sets | Select-Object wait_line, wait_result, qualified_selected_generation, scheduler_evidence
python -B $tool @query --check-report $receipt.report_sha256
```

Pass 1–8 directory arguments in handle order. Each wait set lists its
request generations and the original admission, submission, pending probe
and final result lines when present. `waiting_samples` identifies the
Windows state queries strictly inside that call. The capture keeps the
original journal, thread field bytes and native query statuses for offline
replay. `sources_status` describes the two inputs. A complete report
also requires an interior state sample in every recorded wait call.
Exit 1 preserves partial evidence or signals a report digest mismatch.
Exit 2 indicates an invalid input or output operation.
[How the observations are joined](ARCHITECTURE.md#thread-state-evidence-during-directory-io)

## Capture a cooperative kernel I/O trace

On an elevated Windows test host, build the Release fixture and run the
collector from a checkout on `C:`. Give it a new output directory. The runner
loads its own minifilter, admits two concurrent READs through one file handle,
cancels one, then repeats the batch with the upper instance detached. It
checks the child results and the final unload ledgers. The status-only port
and a separate trace connection are also exercised. The runner records the
SHA-256 of each original page stream in `journal.jsonl`.

```powershell
python tools/run-pending-io-trace-e2e.py --output .build/pending-trace-current
```

The following offline example replays the retired batch using the pin the
collector saved. Use `pending.kniotrace` for the earlier two-pending capture
or `drained.kniotrace` for the re-armed batch after upper detach.

```powershell
$folder = '.build/pending-trace-current'
$name = 'retired.kniotrace'
$entries = Get-Content -LiteralPath (Join-Path $folder 'journal.jsonl') | ForEach-Object { $_ | ConvertFrom-Json }
$capture = @($entries | Where-Object { $_.kind -eq 'capture' -and $_.file -eq $name })
if ($capture.Count -ne 1) { throw 'Expected one recorded capture pin' }
python tools/replay-pending-io-trace.py (Join-Path $folder $name) --sha256 $capture[0].sha256
```

The private `kn.pending_io_trace.v1` report identifies the provider, capture
epoch, observed sequence range and overwritten intervals. Each event includes
its byte offset in the original file. `upper_status` is available only for a
qualified, retired upper observation. Layer records preserve their own statuses
and pending intervals in QPC ticks. A hash mismatch, mixed capture or broken
page cursor fails the command. The user-mode protocol and replay tests run
through `tools/validate-pending-io-trace.ps1`. [Evidence and identity rules](ARCHITECTURE.md#cooperative-kernel-io-request-lifetimes)

## Capture a Windows wait chain

Use `--wait-chain <pid> <process-creation-filetime> <tid> <thread-creation-filetime>`
to investigate a particular thread in a live process. All four arguments are
decimal. The controller opens query and synchronize handles, checks both
creation times, and calls Windows Wait Chain Traversal (WCT) with flags zero.
The first traversal discovers same-process threads to pin. The second supplies
the graph. Both calls are synchronous and can block until Windows returns.
The controller uses its existing privileges. Windows may deny the traversal
or return a partial chain. [Windows WCT](https://learn.microsoft.com/en-us/windows/win32/debug/wait-chain-traversal)
and [query results and access limits](https://learn.microsoft.com/en-us/windows/win32/api/wct/nf-wct-getthreadwaitchain).

This PowerShell example captures a thread in the current shell and saves the
ASCII receipt in a new temporary file. Choose the process and thread of
interest when investigating a hang.

```powershell
$target = Get-Process -Id $PID
$thread = $target.Threads | Sort-Object Id | Select-Object -First 1
$pc = $target.StartTime.ToUniversalTime().ToFileTimeUtc()
$tc = $thread.StartTime.ToUniversalTime().ToFileTimeUtc()
$receipt = & .\x64\Release\KnLiveDbg.exe --wait-chain $target.Id $pc $thread.Id $tc
if ($LASTEXITCODE -ne 0) { throw 'Wait-chain capture failed' }
$file = [IO.Path]::GetTempFileName()
Set-Content -LiteralPath $file -Value $receipt -Encoding ascii
$pin = python -c "import hashlib, pathlib, sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())" $file
python tools/replay-wait-chain.py $file --sha256 $pin
```

A successful command writes one receipt, including when access fails or a
generation changes. Inspect `session`, `discovery`, `query` and the handle
witnesses for the original result and Win32 errors. A syntax error exits 2.
The receipt keeps native node types, statuses and thread counters. It omits
object names. Store the private receipt, assessment and pin together to
repeat the analysis on the same bytes after process exit.

Replay derives `waits_for` and `owned_by` edges for mutexes and critical
sections. A `waits_for_thread_termination` edge cites the blocked thread,
the WCT thread-wait object and a distinct target thread with its own
creation time. Both handle checks bracket the query. The capture pin
identifies the original nodes and handle witnesses. Lock identities are
local to that traversal. A `waits_for_message_receiver` edge identifies
the sender and receiver generations in a synchronous window-message wait.
Its `reply_status` remains `unobserved`. A `potential_wait_cycle` requires a Windows cycle flag and a
closed chain of at least two distinct threads whose handles bracket the
query. The report stops interpreting the chain at a foreign or unqualified
thread. A single returned thread can also mean Windows could not observe
the wait. A live traversal leaves simultaneity, duration, timeout,
cancellation and a whole-host diagnosis unresolved. WCT reserves its lock
timeout and alertable fields. [WCT node fields](https://learn.microsoft.com/en-us/windows/win32/api/wct/ns-wct-waitchain_node_info)

### Repeat a wait chain from two threads

Choose two thread generations in the same process and append
`--corroborate <peer-tid> <peer-creation-filetime> <rounds> <pause-ms>`.
Request 2–8 rounds and a pause of 1–5000 ms between rounds. This PowerShell
example uses the current shell. Save every output line together as one
private `kn.wait_series.v1` document and hash the file you will replay.

```powershell
$target = Get-Process -Id $PID
$roots = @($target.Threads | Sort-Object Id | Select-Object -First 2)
if ($roots.Count -ne 2) { throw 'Two target threads are required' }
$pc = $target.StartTime.ToUniversalTime().ToFileTimeUtc()
$left, $right = $roots
$lc = $left.StartTime.ToUniversalTime().ToFileTimeUtc()
$rc = $right.StartTime.ToUniversalTime().ToFileTimeUtc()
$receipt = & .\x64\Release\KnLiveDbg.exe --wait-chain $target.Id $pc $left.Id $lc --corroborate $right.Id $rc 4 100
if ($LASTEXITCODE -ne 0) { throw 'Paired wait-chain capture failed' }
$file = [IO.Path]::GetTempFileName()
[IO.File]::WriteAllLines($file, [string[]]$receipt, [Text.Encoding]::ASCII)
$pin = python -c "import hashlib, pathlib, sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())" $file
python tools/replay-wait-chain.py $file --sha256 $pin
```

Each root has a separate WCT session and one discovery pass. The controller
retains the opened handles, samples them before and after each round, and
queries each eligible root once. A newly seen thread without a retained
identity ends that view's qualified chain. A single eligible root still
produces a view. If both roots become unavailable, capture ends after that
round. `coverage` in the replay counts issued queries and recorded rounds
against the original plan, including the unissued slots. The largest plan
makes two discovery calls and up to 16 measured queries. Windows controls
the duration of each synchronous call.

For each round, inspect `views` for the two findings and their paths to
the original nodes and handles. `timing` describes the intervals sampled
immediately around the Windows calls. The measured overlap must exceed
two QPC ticks and agree with the millisecond witnesses.
This margin accounts for cross-thread clock ordering. A serial fallback
preserves the setup error and both traversal results.
[Windows high-resolution timestamps](https://learn.microsoft.com/en-us/windows/win32/sysinfo/acquiring-high-resolution-time-stamps)

A corroborated round requires both views to close the same directed cycle
through both chosen roots, with matching thread generations and dependency
types. In a mixed cycle, each arc identifies its target as a lock owner,
message receiver or thread whose termination is awaited. `repeated_groups`
lists consecutive corroborated rounds with the same cycle. Each interval between rounds must have a recorded wait
timeout and a measured gap of at least the requested pause. Separate partial
chains cannot close a cycle. `repeated_potential_wait_cycle` describes
repeated observations of that configuration during the series. Earlier
observations stay in the report after a target exits. Inspect the last
recorded round for the evidence available at the end. WCT leaves the instant of
provider execution, the lifetime of each lock and the duration of each
thread's wait unknown. A deadlock diagnosis still requires evidence of the
waits, lock lifetimes and possible exits from the cycle.

### Compare explanations for a recorded wait

Use the file and SHA-256 from either capture example above. The Python
replayer reads the saved bytes and writes a private `kn.wait_diagnosis.v1`
report. The command also works after the target process has exited.

```powershell
python tools/replay-wait-chain.py $file --sha256 $pin --diagnose
```

The diagnosis compares the recorded explanations for the primary thread.

- Could the first observed cycle involving this thread generation have
  persisted until collection ended? The report lists every matching view
  and qualifying repeated group. A different directed cycle is recorded as
  counterevidence. A signaled handle for the same process or an exact member
  generation establishes that the original membership ended by that point.
  The reason the wait ended still requires separate evidence.
- Can the observations be explained by lock contention throughout the
  recording without a reported cycle? A qualified wait with a distinct
  owner and a native cycle flag of false supplies one supporting observation
  when the chain has no repeated thread or scope boundary. A qualified
  cycle involving the primary thread supplies counterevidence. An
  unsupported tail or a missing traversal leaves the question open.
- When WCT reports a generation-bound thread termination wait, the report
  includes `primary_waited_for_thread_termination`. Its facts identify the
  target thread in the original traversal. Establishing how the waiter
  woke requires its wait result and independent target-exit evidence.
- `primary_waited_for_message_receiver` cites the original sender, message
  object, receiver and handle checks. To establish how the wait ended, compare
  the sender's return with the receiver's entry and reply. A receiver can keep
  processing after calling `ReplyMessage`. [Windows message-wait evidence](ARCHITECTURE.md#windows-synchronous-message-waits)

Each entry in `supporting_facts` and `counterevidence` is a zero-based
index into `facts`. Each fact cites JSON pointers into the original file
identified by `receipt_sha256`. An empty JSON pointer refers to the entire
single-root receipt. `unclassified_views` preserves the source
and reason for each view with insufficient evidence. A candidate's
`unobserved` and `next_observation` describe the evidence still needed
to establish a cause. A timeout, cancellation, system-wide deadlock or
malicious intent cannot be inferred from these observations alone.

### Check a proposed wait claim

Use the saved WCT file and SHA-256 from the capture examples above. The first
command returns a private `kn.wait_investigation.v1` report. The default
`kn.wait_claim_policy.v2` evaluates seven hypotheses within `--max-views` (0–16,
default 16). Use `coverage` for the separate issued and unissued query counts.

```powershell
$report = python -I -B tools/replay-wait-chain.py $file --sha256 $pin --investigate --max-views 16 | ConvertFrom-Json
$claim = $report.hypotheses | Where-Object { $_.verdict -in @('supported', 'refuted') } | Select-Object -First 1
if ($null -ne $claim) {
    $ids = @(foreach ($group in $claim.required_evidence_groups) { $group[0] })
    $proposal = [ordered]@{
        schema = 'kn.wait_claim_proposal.v1'
        policy = $report.policy
        receipt_sha256 = $pin
        target = $report.target
        claims = @(@{ claim = $claim.claim; verdict = $claim.verdict; evidence_ids = $ids })
    }
    $proposal | ConvertTo-Json -Depth 8 -Compress | python -I -B tools/replay-wait-chain.py $file --sha256 $pin --check-claims
}
```

The example submits a claim only when replay found decisive witnesses. Supply
a UTF-8 proposal of up to 32 KiB on standard input. Its policy selects up to
seven distinct claims in v2 or six in v1, each with 1–32 distinct evidence IDs.
The checker verifies each proposed `supported` or `refuted` verdict against the original file. It reports
the reason for each rejection, including a missing witness or a citation from
another observation. An unexpected file digest or target generation, unsupported
policy, extra field or unknown claim makes the proposal invalid. No proposal field selects a
command, file or provider.

Use `--investigate --policy kn.wait_claim_policy.v1` to reproduce an earlier
investigation with its original cycle rules. `--check-claims` reads the policy
from the saved proposal. An explicit `--policy` on that command must match it.

Exit 0 means the plan was evaluated and every submitted claim passed. An
investigation without proposals can finish with every hypothesis inconclusive.
Exit 1 means the view budget was insufficient or a claim failed verification.
Exit 2 indicates invalid input or an input/output file collision. Exit 3 indicates
a report write failure. Keep captures, proposals and reports private.
[Evidence semantics](ARCHITECTURE.md#evidence-checked-wait-investigations)

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
code-version and loss fields. The importer also accepts saved CPU profile
JSON from the ETL reader. Reported execution levels retain their source
scope. Changed input or page limits invalidate the cursor. Exit 1 covers an
unavailable result or a partial native page. Invalid arguments return exit 2.

### Query a saved ETL profile page

In a working directory containing `capture.etl`, choose a fresh output name.
The native file redirection below preserves the report's UTF-8 bytes on
Windows PowerShell and PowerShell 7.

```powershell
$pin = (Get-FileHash -LiteralPath .\capture.etl -Algorithm SHA256).Hash
cmd.exe /d /c "KnLiveDbg.exe --etl-profile capture.etl --sha256 $pin --capture-settings --limit 8 > profile-page.json"
$page = & KnLiveDbg.exe --offline '!kmon' trace profile-page.json /limit 4 /json | ConvertFrom-Json
& KnLiveDbg.exe --etl-profile capture.etl --sha256 $pin --capture-settings --limit 8 --check-page $page.file_sha256
```

The final command checks the bytes of the whole native page. The normalized
query's `next_cursor` continues within that page. The ETL reader uses the
separate `source_page.source_next_after` value. [Source and replay fields](TRACE_IMPORT.md#query-and-reproduce-a-saved-etl-profile-page)

### Verify the author of an ETL capture statement

After the saved-page example above, use the recorder's signed statement
and the public point independently provisioned for its capture-controller
role. The point file in this example contains the 130 hexadecimal digits
of the trusted uncompressed P-256 key.

```powershell
$trustedPoint = (Get-Content -Raw -LiteralPath .\approved-recorder-p256.hex).Trim()
& KnLiveDbg.exe --etl-profile capture.etl --sha256 $pin --capture-settings --limit 8 --check-page $page.file_sha256 --capture-statement capture.knetlstatement capture_controller $trustedPoint
```

The same option works with `--etl-switches`, `--etl-disk-io` and `--etl-hard-faults`. Use `archive_witness` for a
key authorized to attest to archived bytes. A matching controller receipt
identifies the signed claims, the original ETL, the regenerated page, the
statement file and the trusted key. It records the role check separately
from the signature check. Image loader reports also require the original
capture and its recipe digest. [Signed statement fields](TRACE_IMPORT.md#verify-a-signed-capture-statement)
[Loader report example](TRACE_IMPORT.md#verify-a-retained-loader-report)

Use `--etl-rotation-set` to verify the order, file identities and any signed
controller stop for a rotating recording. Supply an explicit ordinal for
each file. Missing positions stay in the report. [Rotation inventory format and example](TRACE_IMPORT.md#verify-an-ordered-rotation-inventory)

### Inspect CPU samples from a saved ETL

```powershell
$etl = Get-Item .\capture.etl
$pin = (Get-FileHash -LiteralPath $etl.FullName -Algorithm SHA256).Hash
$page = & KnLiveDbg.exe --etl-profile $etl.FullName --sha256 $pin --limit 64 | ConvertFrom-Json
if ($null -ne $page.next_after) {
    & KnLiveDbg.exe --etl-profile $etl.FullName --sha256 $pin --after $page.next_after --limit 64
}
```

Each sample carries the raw ETW timestamp, CPU, payload thread ID, instruction
pointer and original record ordinal. Check `status`, `buffer_comparison` and
the reported loss counters before interpreting the page. A buffer-count
mismatch returns `partial` and exit 1. [ETL fields and limits](TRACE_IMPORT.md#saved-windows-cpu-samples)

Use `--capture-settings` to inspect the collector records surrounding a
sample. The same option on `--etl-switches` reports the group-mask witnesses
for each switch. A reported timer period uses 100-nanosecond units.

```powershell
$etl = Get-Item .\capture.etl
$pin = (Get-FileHash -LiteralPath $etl.FullName -Algorithm SHA256).Hash
$page = & KnLiveDbg.exe --etl-profile $etl.FullName --sha256 $pin --capture-settings --limit 8 | ConvertFrom-Json
$page.capture_settings.records | Select-Object record_ordinal, kind, opcode, profile_source_name
$page.samples | Select-Object sample_ordinal, @{Name='TimerPeriod100ns'; Expression={$_.capture_setting_evidence.timer_bracket.reported_period_100ns}}
$switches = & KnLiveDbg.exe --etl-switches $etl.FullName --sha256 $pin --capture-settings --limit 8 | ConvertFrom-Json
$switches.switches | Select-Object switch_ordinal, capture_setting_evidence
```

Look up each witness by its original record ordinal in the manifest.
[Capture settings and limits](TRACE_IMPORT.md#read-recorded-capture-settings)

Add `--thread-evidence` to inspect the nearest start, end or rundown records
for each sampled TID. `paired_record_pid` is populated when both source
records agree and coverage permits the comparison.

```powershell
& KnLiveDbg.exe --etl-profile $etl.FullName --sha256 $pin --limit 8 --thread-evidence
```

Use `--image-evidence` to include the thread boundaries and check which
recorded image range contains the sampled IP in the same PID. Look up each
witness ordinal in `image_records`. A null `reported_rva` leaves the
association unresolved. Keep the report private because it carries the
original file names. [Image evidence fields](TRACE_IMPORT.md#locate-image-records-for-a-sampled-ip)

```powershell
& KnLiveDbg.exe --etl-profile $etl.FullName --sha256 $pin --limit 8 --image-evidence
```

Use `--process-evidence` to follow the thread's payload PID to the process
records around a CPU sample. This example also checks whether the loader
records supporting its RVA lie inside the recorded process generation.

```powershell
$page = & KnLiveDbg.exe --etl-profile $etl.FullName --sha256 $pin --process-evidence --image-evidence --limit 64 | ConvertFrom-Json
$sample = $page.samples | Where-Object { $null -ne $_.process_evidence.recorded_generation } | Select-Object -First 1
if ($null -ne $sample) {
    $sample.process_evidence
    $ordinals = @($sample.process_evidence.before_record, $sample.process_evidence.after_record)
    $page.process_records | Where-Object { $_.record_ordinal -in $ordinals }
    $sample.image_process_evidence
}
```

Use the same digest and options with `--after $page.next_after` to continue
when `next_after` has a value.
[Process generation fields and limits](TRACE_IMPORT.md#match-a-sample-to-a-recorded-process-generation)

### Compare a sampled image with an explicit PE file

Pass the local reference path and its SHA-256 together. Use the digest of the
specific build under review and keep the recorded leaf name when copying
the file. The following example lists the samples on one page that have
file-backed reference bytes.

```powershell
$etl = Get-Item .\capture.etl
$pe = Get-Item .\reference\msvcrt.dll
$pin = (Get-FileHash -LiteralPath $etl.FullName -Algorithm SHA256).Hash
$pePin = (Get-FileHash -LiteralPath $pe.FullName -Algorithm SHA256).Hash
$page = & KnLiveDbg.exe --etl-profile $etl.FullName --sha256 $pin --reference-image $pe.FullName $pePin --limit 128 | ConvertFrom-Json
$page.reference_image
$page.samples | Where-Object { $null -ne $_.reference_evidence.reference_window } |
    Select-Object sample_ordinal, reference_evidence
```

Continue with `--after $page.next_after` when the cursor has a value, using
the same reference and ETL. Each window hash belongs to the supplied file.
[Reference comparison fields](TRACE_IMPORT.md#compare-a-recorded-image-with-a-pinned-pe)

To include the build identity recorded by the trace merger, add
`--build-evidence`. With the same ETL, PE and digests as above, the following
page shows which samples have matching RSDS markers at both image boundaries.

```powershell
$page = & KnLiveDbg.exe --etl-profile $etl.FullName --sha256 $pin --build-evidence --reference-image $pe.FullName $pePin --limit 128 | ConvertFrom-Json
$page.reference_build
$page.samples | Where-Object { $_.build_evidence.relation -eq 'paired_merge_build' } |
    Select-Object sample_ordinal, build_evidence, reference_evidence
```

Omit `--reference-image` and its two arguments to inspect the ETL markers
alone. [Merge-time build fields](TRACE_IMPORT.md#compare-merge-time-build-identifiers)

### Inspect disk I/O from a saved ETL

Read a local capture using the SHA-256 supplied with it. The three operation
summaries cover the whole file even when `--limit` selects one event.

```powershell
$etl = (Get-Item -LiteralPath .\case.etl).FullName
$pin = (Get-Content -LiteralPath .\case.etl.sha256 -Raw).Trim()
$page = & KnLiveDbg.exe --etl-disk-io $etl --sha256 $pin --limit 1 | ConvertFrom-Json
$page.operations | Select-Object operation, initiations, completions, transfer_bytes, first_longest_response
```

The longest-response entry identifies the original completion record. Its
counter and the header frequency allow a conversion to milliseconds. Check
`status` and the loss counters before using the totals. [Field definitions, paging and timing example](TRACE_IMPORT.md#read-saved-disk-io-response-times)

### Inspect hard page faults from a saved ETL

Each page includes the total observed read bytes and the first fault with the
longest measured interval across the file. The original event ordinal identifies
the record even when it falls on another page.

```powershell
$etl = Get-Item -LiteralPath '.\case.etl'
$pin = (Get-Content -LiteralPath '.\case.etl.sha256' -Raw).Trim()
$page = & KnLiveDbg.exe --etl-hard-faults $etl.FullName --sha256 $pin --limit 16 | ConvertFrom-Json
$page.fault_summary | Select-Object timed_faults, untimed_faults, read_bytes, longest_fault_ties
$page.hard_faults | Select-Object record_ordinal, faulting_thread_id, byte_count, timing_status, elapsed_qpc_ticks
```

Check `status` and the loss counters when comparing captures. [Event fields and timing units](TRACE_IMPORT.md#read-saved-hard-page-faults)

### Inspect scheduling during one hard page fault

Pass the one-based `fault_ordinal` from a hard-fault row. To inspect the
longest timed fault in the file, use the ordinal in the summary.

```powershell
$longest = $page.fault_summary.first_longest_fault
if ($null -ne $longest) {
    $detail = & KnLiveDbg.exe --etl-hard-faults $etl.FullName --sha256 $pin --schedule-of $longest.fault_ordinal | ConvertFrom-Json
    $detail.fault_schedule | Select-Object status, on_cpu_ticks, off_cpu_ticks
    $detail.fault_schedule.intervals | Select-Object relation, start, end, overlap_ticks, readiness
}
```

`covered` means that the faulting thread's on-CPU and off-CPU intervals
account for the entire reported fault duration. Select a single fault per
call. Paging the ordinary list still uses `--after` and `--limit`.
The detail page also supports `--check-page` and `--capture-statement`.
[Measurement requirements](TRACE_IMPORT.md#scheduling-during-a-hard-page-fault)

### Measure hard faults during a recorded activity

Pass the one-based original ETL record numbers of a Start event and a Stop
event. The following pair is from the pinned TaskbarLatency recording.
[Recording and validation](VALIDATION.md#hard-fault-time-inside-activity-markers-on-2026-11-22)

```powershell
$result = & KnLiveDbg.exe --etl-hard-faults $etl.FullName --sha256 $pin --activity-window 339732 374019 | ConvertFrom-Json
$result.activity_window | Select-Object status, window_ticks, fault_union_ticks, candidate_faults
$result.hard_faults | Select-Object fault_ordinal, record_ordinal, elapsed_qpc_ticks
```

To find the boundaries emitted by the thread from a hard-fault row, page
through its activity markers. The query accepts `--after` and `--limit`.
Use the nested event's `record_ordinal` as an endpoint. Keep the source
file and its pin together throughout the investigation.

```powershell
$faultPage = & KnLiveDbg.exe --etl-hard-faults $etl.FullName --sha256 $pin --after 6 --limit 1 | ConvertFrom-Json
$faultTid = $faultPage.hard_faults[0].faulting_thread_id
$cursor = 0
do {
    $markers = & KnLiveDbg.exe --etl-hard-faults $etl.FullName --sha256 $pin --activity-markers --thread-id $faultTid --after $cursor --limit 128 | ConvertFrom-Json
    $markers.markers | ForEach-Object { $_.event } |
        Select-Object record_ordinal, provider_guid, activity_id, task, opcode, header_process_id, header_thread_id
    $cursor = $markers.next_after
} while ($null -ne $cursor)
```

Use `--check-page` to verify an exact replay. The receipt retains both
requested record numbers. [Window and coverage rules](TRACE_IMPORT.md#hard-faults-inside-an-activity-window)

### Compare an activity across two recordings

Select a Start and Stop in each ETL using the marker query above. Supply the
SHA-256 values retained for the two inputs and the reader. This example uses
the original record numbers from the x64 and x86 PerfView fixtures. Run it
in the repository with Python 3.11 or later and an existing private output
directory. [Fixture pins and measurements](VALIDATION.md#activity-duration-across-two-recordings-on-2026-11-22)

```powershell
$reader = (Get-Item .\x64\Release\KnLiveDbg.exe).FullName
$query = @(
    '--exe', $reader, '--exe-sha256', $readerPin,
    '--baseline', $baselineEtl, $baselinePin, '135036', '135051',
    '--candidate', $candidateEtl, $candidatePin, '122133', '122302'
)
$receipt = python -B tools/compare-etl-activities.py @query --output .\private\activity-pair.json | ConvertFrom-Json
$report = Get-Content -LiteralPath .\private\activity-pair.json -Raw | ConvertFrom-Json
$report.comparison.activity_duration
$report.comparison.observed_hard_fault_union
python -B tools/compare-etl-activities.py @query --check-report $receipt.report_sha256
```

The output path must be new. Exit 0 means both time differences qualified.
Exit 1 retains a limited comparison or indicates a replay digest mismatch.
Check the receipt's `status` and `comparison_status` separately. Exit 2
reports invalid arguments, an unusable reader pin or an output failure.
`--timeout-ms` sets the per-query deadline, with a default of 240,000 ms.
[Comparison fields and scope](TRACE_IMPORT.md#comparing-activity-windows-across-recordings)

### Check the same markers with Microsoft TraceProcessor

In a Visual Studio 2022 Developer PowerShell with MSBuild and NuGet, build the
x64 adapter. Restore uses the committed .NET Framework 4.8 package lock.
Keep the resulting ZIP and its SHA-256 together for replay.

```powershell
MSBuild tools\TraceProcessorMarkers\TraceProcessorMarkers.csproj /restore /t:PackageAdapter /p:Configuration=Release
$adapter = (Get-Item .\.build\traceprocessor-markers\TraceProcessorMarkers.zip).FullName
$adapterPin = (Get-FileHash -LiteralPath $adapter -Algorithm SHA256).Hash
$sdkQuery = @('--traceprocessor', $adapter, $adapterPin)
$checked = python -B tools/compare-etl-activities.py @query @sdkQuery --output .\private\activity-pair-sdk.json | ConvertFrom-Json
$report = Get-Content -LiteralPath .\private\activity-pair-sdk.json -Raw | ConvertFrom-Json
$report.traceprocessor.baseline.correspondence
$report.traceprocessor.candidate.correspondence
python -B tools/compare-etl-activities.py @query @sdkQuery --check-report $checked.report_sha256
```

Use the `$query` from the preceding example. The receipt gives a native
`comparison_status` and a separate `traceprocessor_status`. Exit 0 also
requires both pairs of marker headers to match unique SDK rows. Each
attempt identifies its native page by hash. [SDK table, filters and limits](TRACE_IMPORT.md#traceprocessor-marker-correspondence)

### Measure a caller waiting for a worker

Run this example in an x64 Visual Studio Developer PowerShell at the
repository root. Use a new private output directory and an existing Release
reader. The recorder starts one in-process Windows ETW session per run.

```powershell
New-Item -ItemType Directory -Path .\private\handoff -Force | Out-Null
cl /nologo /std:c++17 /EHsc /O2 /W4 /WX /DUNICODE /D_UNICODE /Fo:private\handoff\recorder.obj /Fe:private\handoff\recorder.exe tools\etl-statement-capture.cpp
$recorder = (Get-Item .\private\handoff\recorder.exe).FullName
$reader = (Get-Item .\x64\Release\KnLiveDbg.exe).FullName
$recorderPin = (Get-FileHash -LiteralPath $recorder -Algorithm SHA256).Hash
$readerPin = (Get-FileHash -LiteralPath $reader -Algorithm SHA256).Hash
$tool = 'tools/measure-etl-handoff.py'
$plan = python -B $tool plan --pairs 8 --steps 20000 --baseline-ms 0 --candidate-ms 25 --recorder-sha256 $recorderPin --exe-sha256 $readerPin --output .\private\handoff\plan.json | ConvertFrom-Json
$capture = python -B $tool capture --plan .\private\handoff\plan.json --plan-sha256 $plan.plan_sha256 --recorder $recorder --output .\private\handoff\originals.zip | ConvertFrom-Json
$query = @('replay', '--package', '.\private\handoff\originals.zip', '--sha256', $capture.package_sha256, '--plan-sha256', $plan.plan_sha256, '--exe', $reader)
$receipt = python -B $tool @query --output .\private\handoff\report.json | ConvertFrom-Json
$report = Get-Content -LiteralPath .\private\handoff\report.json -Raw | ConvertFrom-Json
$report.changes.activity
$report.changes.join_timer_overlap
python -B $tool @query --check-report $receipt.report_sha256
```

Register 2 to 16 pairs. Each thread performs 1 to 1,000,000 iterations per
run. Each timer accepts 0 to 1,000 ms. To measure variation with identical
settings, register a second plan with both timers set to 0. Keep the plan
digest when registering and the archive digest when capturing. Each named
output must be new. The capture receipt counts retained ETLs. Replay reports
planned and measured pairs, signed differences per pair, and medians by
which condition ran first. Exit 1 preserves a partial study or reports a
digest mismatch. Exit 2 reports an admission, argument or output failure.
[Timing fields and interpretation](TRACE_IMPORT.md#paired-timing-of-an-owned-thread-handoff)

### Identify the last prerequisite at a thread join

From an x64 Visual Studio Developer PowerShell at the repository root,
choose a new private output directory. This example compares two worker
timer settings while requesting the same 25 ms pause on the caller.

```powershell
$out = '.\.build\handoff-join-example'
New-Item -ItemType Directory -Path $out -ErrorAction Stop | Out-Null
cl /nologo /std:c++17 /EHsc /O2 /W4 /WX /DUNICODE /D_UNICODE "/Fo:$out\recorder.obj" "/Fe:$out\recorder.exe" tools\etl-statement-capture.cpp
$recorder = (Get-Item "$out\recorder.exe").FullName
$reader = (Get-Item .\x64\Release\KnLiveDbg.exe).FullName
$recorderPin = (Get-FileHash -LiteralPath $recorder -Algorithm SHA256).Hash
$readerPin = (Get-FileHash -LiteralPath $reader -Algorithm SHA256).Hash
$tool = 'tools/measure-etl-handoff.py'
$plan = python -B $tool plan --pairs 8 --steps 20000 --baseline-ms 2 --candidate-ms 80 --caller-delay-ms 25 --recorder-sha256 $recorderPin --exe-sha256 $readerPin --output "$out\plan.json" | ConvertFrom-Json
$capture = python -B $tool capture --plan "$out\plan.json" --plan-sha256 $plan.plan_sha256 --recorder $recorder --output "$out\originals.zip" | ConvertFrom-Json
$query = @('replay', '--package', "$out\originals.zip", '--sha256', $capture.package_sha256, '--plan-sha256', $plan.plan_sha256, '--exe', $reader)
$receipt = python -B $tool @query --output "$out\report.json" | ConvertFrom-Json
$report = Get-Content -LiteralPath "$out\report.json" -Raw | ConvertFrom-Json
$report.join_path_summary.last_prerequisites
$report.join_path_summary.changes.exposed_worker
python -B $tool @query --check-report $receipt.report_sha256
```

Passing `--caller-delay-ms 0` records both probes and skips the caller
pause. The v2 report identifies the original probe rows and bounds the
worker time exposed after caller arrival. Add `--join-path` to a v1
archive's replay command to derive bounds from its original ten events.
The default replay of that archive reproduces the v1 report. [Field definitions](TRACE_IMPORT.md#critical-path-at-a-joined-worker)

### Measure scheduling during a thread join

From an x64 Visual Studio Developer PowerShell at the repository root,
use a new private directory for the plan, original ETLs and report.
This example gives the caller a 30 ms pause and changes the worker's
requested timer from 2 to 180 ms.

```powershell
$out = '.\.build\handoff-scheduling-example'
New-Item -ItemType Directory -Path $out -ErrorAction Stop | Out-Null
cl /nologo /std:c++17 /EHsc /O2 /W4 /WX /DUNICODE /D_UNICODE "/Fo:$out\recorder.obj" "/Fe:$out\recorder.exe" tools\etl-statement-capture.cpp
if ($LASTEXITCODE -ne 0) { throw 'Recorder build failed' }
$recorder = (Get-Item "$out\recorder.exe").FullName
$reader = (Get-Item .\x64\Release\KnLiveDbg.exe).FullName
$recorderPin = (Get-FileHash -LiteralPath $recorder -Algorithm SHA256).Hash
$readerPin = (Get-FileHash -LiteralPath $reader -Algorithm SHA256).Hash
$tool = 'tools/measure-etl-handoff.py'
$plan = python -B $tool plan --observe-scheduling --pairs 4 --steps 20000 --baseline-ms 2 --candidate-ms 180 --caller-delay-ms 30 --recorder-sha256 $recorderPin --exe-sha256 $readerPin --output "$out\plan.json" | ConvertFrom-Json
$capture = python -B $tool capture --plan "$out\plan.json" --plan-sha256 $plan.plan_sha256 --recorder $recorder --output "$out\originals.zip" | ConvertFrom-Json
$query = @('replay', '--package', "$out\originals.zip", '--sha256', $capture.package_sha256, '--plan-sha256', $plan.plan_sha256, '--exe', $reader)
$receipt = python -B $tool @query --output "$out\report.json" | ConvertFrom-Json
$report = Get-Content -LiteralPath "$out\report.json" -Raw | ConvertFrom-Json
$report.timing_status
$report.scheduling_summary.measured_pairs
$report.scheduling_summary.changes.caller_residency
python -B $tool @query --check-report $receipt.report_sha256
```

With `--observe-scheduling`, the caller pause defaults to zero. The
recorder starts a private ETW session and profiles its own two waiting
threads. Each original ETL travels with its recorder outcome in the
archive. Replay returns exit 1 for a partial study and retains the
available wall-time measurements when a dispatch read or wait-chain
query fails. Use `observations[].measurement.scheduling` for the
counter values, Win32 statuses, query intervals and source record numbers.
[How to read the bounds](TRACE_IMPORT.md#scheduler-evidence-at-a-thread-join)

### Retain independent table rows for a thread handoff

Use the variables from the preceding capture in the same x64 Developer
PowerShell. Build the marker adapter once, then keep its ZIP and SHA-256
with the plan and archive. This replay works with v1, v2 and v3 handoff
archives.

```powershell
MSBuild tools\TraceProcessorMarkers\TraceProcessorMarkers.csproj /restore /t:PackageAdapter /p:Configuration=Release
if ($LASTEXITCODE -ne 0) { throw 'Marker adapter build failed' }
$adapter = (Get-Item .\.build\traceprocessor-markers\TraceProcessorMarkers.zip).FullName
$adapterPin = (Get-FileHash -LiteralPath $adapter -Algorithm SHA256).Hash
$sdkArgs = @('--traceprocessor', $adapter, $adapterPin)
$sdkReceipt = python -B $tool @query @sdkArgs --output "$out\report-sdk.json" | ConvertFrom-Json
$sdkReport = Get-Content -LiteralPath "$out\report-sdk.json" -Raw | ConvertFrom-Json
$first = $sdkReport.observations[0].traceprocessor.correspondence
$first.marker_links | Select-Object -First 4 record_ordinal, status, matching_table_rows
$first.phase_intervals.activity
$sdkReport.traceprocessor.changes.activity
python -B $tool @query @sdkArgs --check-report $sdkReceipt.report_sha256
```

The receipt reports the native study status, SDK correspondence and
the number of pairs timed independently. Exit 1 preserves a partial study,
an unconfirmed SDK comparison or a report digest mismatch. Exit 2
reports input admission or output failure. Replay without `--traceprocessor`
keeps the native report format. [Table coordinates, clocks and limits](TRACE_IMPORT.md#independent-table-rows-and-phase-timing-for-a-thread-handoff)

To verify each saved coordinate, run the Windows ETW oracle and query
the SDK again with a separate filter per task.

```powershell
cl /nologo /std:c++17 /EHsc /O2 /W4 /WX "/Fo:$out\oracle.obj" "/Fe:$out\oracle.exe" tools\etl-hard-fault-oracle.cpp
if ($LASTEXITCODE -ne 0) { throw 'ETW reader build failed' }
python -B tools/test-etl-handoff.py --package "$out\originals.zip" --sha256 $capture.package_sha256 --plan-sha256 $plan.plan_sha256 --exe $reader --oracle "$out\oracle.exe" --traceprocessor $adapter $adapterPin --check-marker-report --check-controls
```

### Measure timer pending time at a thread join

Run this example from the repository root in x64 Developer PowerShell.
It compares two worker timer settings with the same fixed work, caller
pause and observer schedule. Use a fresh output directory per study.

```powershell
$out = '.\.build\handoff-timer-example'
New-Item -ItemType Directory -Path $out -ErrorAction Stop | Out-Null
cl /nologo /std:c++17 /EHsc /O2 /W4 /WX /DUNICODE /D_UNICODE "/Fo:$out\recorder.obj" "/Fe:$out\recorder.exe" tools\etl-statement-capture.cpp
if ($LASTEXITCODE -ne 0) { throw 'Recorder build failed' }
$tool = 'tools/measure-etl-handoff.py'
$recorder = (Get-Item "$out\recorder.exe").FullName
$reader = (Get-Item .\x64\Release\KnLiveDbg.exe).FullName
$recorderPin = (Get-FileHash -LiteralPath $recorder -Algorithm SHA256).Hash
$readerPin = (Get-FileHash -LiteralPath $reader -Algorithm SHA256).Hash
$plan = python -B $tool plan --observe-timer --pairs 4 --baseline-ms 2 --candidate-ms 180 --caller-delay-ms 30 --recorder-sha256 $recorderPin --exe-sha256 $readerPin --output "$out\plan.json" | ConvertFrom-Json
$capture = python -B $tool capture --plan "$out\plan.json" --plan-sha256 $plan.plan_sha256 --recorder $recorder --output "$out\originals.zip" | ConvertFrom-Json
$query = @('replay', '--package', "$out\originals.zip", '--sha256', $capture.package_sha256, '--plan-sha256', $plan.plan_sha256, '--exe', $reader)
$receipt = python -B $tool @query --output "$out\report.json" | ConvertFrom-Json
$report = Get-Content -LiteralPath "$out\report.json" -Raw | ConvertFrom-Json
$report.timer_path_summary.changes.timer_pending
python -B $tool @query --check-report $receipt.report_sha256
```

The receipt's `timer_path_pairs` counts pairs with enough evidence in
both arms. The summary gives the lower and upper bounds on the median
candidate-minus-baseline change in nanoseconds. The plan also accepts
`--observe-scheduling` to measure the caller's off-CPU time in the same
run. [Timer bounds and source events](TRACE_IMPORT.md#timer-signal-on-the-callers-join-path)

### Inspect context switches from a saved ETL

```powershell
$etl = Get-Item .\capture.etl
$pin = (Get-FileHash -LiteralPath $etl.FullName -Algorithm SHA256).Hash
$page = & KnLiveDbg.exe --etl-switches $etl.FullName --sha256 $pin --limit 64 | ConvertFrom-Json
if ($null -ne $page.next_after) {
    & KnLiveDbg.exe --etl-switches $etl.FullName --sha256 $pin --after $page.next_after --limit 64
}
```

Each switch identifies the recorded CPU and outgoing and incoming TIDs.
Inspect `version` before interpreting `old_wait_mode` or `thread_flags`.
The raw timestamps and `new_wait_time` have distinct meanings.
[Switch fields and limits](TRACE_IMPORT.md#saved-windows-context-switches)

To read elapsed scheduler ticks, use `--intervals`. A `--thread-id` filter
selects both switch directions and enables the same interval report. This
example follows the first nonidle incoming TID on the page above.

```powershell
$chosen = $page.switches | Where-Object { $_.new_thread_id -gt 0 -and $_.new_thread_id -lt [uint32]::MaxValue } | Select-Object -First 1
if ($null -ne $chosen) {
    $targetTid = $chosen.new_thread_id
    $threadPage = & KnLiveDbg.exe --etl-switches $etl.FullName --sha256 $pin --thread-id $targetTid --limit 64 | ConvertFrom-Json
    $threadPage.switches | Select-Object switch_ordinal, cpu, on_cpu, off_cpu
    if ($null -ne $threadPage.next_after) {
        & KnLiveDbg.exe --etl-switches $etl.FullName --sha256 $pin --thread-id $targetTid --after $threadPage.next_after --limit 64
    }
}
```

[Interval fields, clock and coverage](TRACE_IMPORT.md#reconstruct-scheduler-intervals)

### Measure scheduling inside an activity

Select the original Start and Stop record ordinals from the marker query.
This example follows a TaskbarLatency activity. Each page reports the
totals for the whole activity as well as the switch records for that page.

```powershell
$etl = (Get-Item .\TaskbarLatency.etl).FullName
$reader = (Get-Item .\x64\Release\KnLiveDbg.exe).FullName
$pin = (Get-FileHash -LiteralPath $etl -Algorithm SHA256).Hash
$query = @('--etl-switches', $etl, '--sha256', $pin, '--schedule-activity', '339732', '374019', '--limit', '7')
$page = & $reader @query | ConvertFrom-Json
$page.activity_schedule | Select-Object status, window_ticks, on_cpu_ticks, off_cpu_ticks, after_ready_ticks, unclassified_off_cpu_ticks
$page.activity_schedule.intervals
while ($null -ne $page.next_after) {
    $page = & $reader @query --after $page.next_after | ConvertFrom-Json
    $page.activity_schedule.intervals
}
```

The two selectors use original record ordinals. The continuation cursor
counts intersecting switch intervals. Page size defaults to 64 and accepts
1 to 128. Keep the same ETL digest and selectors throughout. The native
`--check-page` option accepts the SHA-256 of one page's exact output bytes.
Exit 0 means the file was read. Inspect `activity_schedule.status` for
timing coverage. Exit 1 includes partial sources and replay mismatches.
[Timing fields and source requirements](TRACE_IMPORT.md#thread-scheduling-inside-an-activity)

### Find the CPU context of a ReadyThread event

Choose a ReadyThread record from a saved scheduling page. In the public
TaskbarLatency recording, record 369897 belongs to the first off-CPU
interval of the activity above. The command accepts the original ETW
record ordinal. The context-switch and TraceProcessor tables have their
own row numbers.

```powershell
$etl = (Get-Item .\TaskbarLatency.etl).FullName
$reader = (Get-Item .\x64\Release\KnLiveDbg.exe).FullName
$pin = (Get-FileHash -LiteralPath $etl -Algorithm SHA256).Hash
$query = @('--etl-switches', $etl, '--sha256', $pin, '--ready-origin', '369897')
$page = & $reader @query | ConvertFrom-Json
$page.relationship
$page.source_cpu_context
$page.target_dispatch | Select-Object relation, switch_out_to_ready_ticks, ready_to_switch_in_ticks
```

Inspect the source and target relations independently. A DPC can ready a
thread while another thread occupies the CPU. In that case the target
timing can still be measured and the readying PID and TID are null. Exit 1
covers an unavailable selector, a partial source, or a page replay
mismatch. Use the same selector with `--check-page` to verify exact output
bytes. [ReadyThread evidence and timing](TRACE_IMPORT.md#cpu-context-at-a-readythread-event)

To inspect several ready events from the same recording, pass up to 128
increasing original record numbers in one argument, for example
`--ready-origins 369897,373207,373233`. The reader resolves all
selectors in two ETW traversals. The v6 page returns one result per
requested event in order. A selector that names a different event type
or lies outside the recording returns the first failed record.

### Account for waits across one activity

From the repository root, select the two original ETW marker records
for one thread activity. The command writes a new private JSON report
and prints its SHA-256. The example follows the same public TaskbarLatency
activity as the single-event query.

```powershell
$etl = (Get-Item .\TaskbarLatency.etl).FullName
$reader = (Get-Item .\x64\Release\KnLiveDbg.exe).FullName
$pin = (Get-FileHash -LiteralPath $etl -Algorithm SHA256).Hash
$readerPin = (Get-FileHash -LiteralPath $reader -Algorithm SHA256).Hash
$query = @('--exe', $reader, '--exe-sha256', $readerPin, '--etl', $etl, '--sha256', $pin, '--start', '339732', '--stop', '374019')
$report = Join-Path $PWD 'private-activity-waits.json'
$receipt = python -B tools\measure-etl-activity-waits.py @query --output $report | ConvertFrom-Json
(Get-Content -Raw -LiteralPath $report | ConvertFrom-Json).result.summary
python -B tools\measure-etl-activity-waits.py @query --check-report $receipt.report_sha256
```

For an independent CPU-table comparison, build the adapter in a Visual
Studio Developer PowerShell. Supply its archive and digest on both the
measurement and replay commands. Use a fresh output path for this report.

```powershell
MSBuild tools\TraceProcessorReadyTest\TraceProcessorReadyTest.csproj /restore /t:PackageAdapter /p:Configuration=Release
$adapter = (Get-Item .\.build\traceprocessor-ready-test\TraceProcessorCpu.zip).FullName
$sdk = @('--traceprocessor', $adapter, (Get-FileHash -LiteralPath $adapter -Algorithm SHA256).Hash)
$verified = Join-Path $PWD 'private-activity-waits-with-sdk.json'
$receipt = python -B tools\measure-etl-activity-waits.py @query @sdk --output $verified | ConvertFrom-Json
python -B tools\measure-etl-activity-waits.py @query @sdk --check-report $receipt.report_sha256
```

`--page-size` controls the number of switch intervals read at a time
(default 128, range 1–128). The report covers the entire marker window.
Exit 1 covers unavailable timing, an unconfirmed requested SDK comparison
or a report hash mismatch. Invalid arguments, input pins and occupied
output paths return exit 2. [Wait categories and source overlap](TRACE_IMPORT.md#waits-across-one-activity)

### Measure interrupt handling during a thread activity

Use the native reader, marker selection and CPU adapter from the
preceding example. This option writes a v2 activity wait report. The
report links DPC and ISR execution on the selected thread's CPU to
the original switch records and TraceProcessor table rows.

```powershell
$interruptReport = Join-Path $PWD 'private-activity-interrupts.json'
$receipt = python -B tools\measure-etl-activity-waits.py @query @sdk --interrupt-overlap --output $interruptReport | ConvertFrom-Json
$overlap = (Get-Content -Raw -LiteralPath $interruptReport | ConvertFrom-Json).result.interrupt_overlap
$overlap.summary | Select-Object residency_ns, observed_dpc_ns, observed_isr_ns, residency_outside_observed_fragments_ns
python -B tools\measure-etl-activity-waits.py @query @sdk --interrupt-overlap --check-report $receipt.report_sha256
```

The receipt's `interrupt_overlap_status` is `measured` when the
comparison succeeds. Exit 1 retains the report for an unavailable
measurement or a replay mismatch. Omitting the adapter with this option
returns exit 2. [Time and coverage fields](TRACE_IMPORT.md#interrupt-handling-during-a-marked-threads-cpu-residency)

### Measure disk requests during a thread activity

Use the same `$query` from **Account for waits across one activity**.
Build the disk adapter in a Visual Studio 2022 Developer PowerShell with the v143 x64 C++ tools and Windows SDK. The
following commands write a private v3 report and replay its digest.

```powershell
MSBuild tools\TraceProcessorDisk\TraceProcessorDisk.csproj /restore /t:PackageAdapter /p:Configuration=Release
$diskAdapter = (Get-Item .\.build\traceprocessor-disk\TraceProcessorDisk.zip).FullName
$disk = @('--disk-requests', $diskAdapter, (Get-FileHash -LiteralPath $diskAdapter -Algorithm SHA256).Hash)
$diskReport = Join-Path $PWD 'private-activity-disk.json'
$receipt = python -B tools\measure-etl-activity-waits.py @query @disk --output $diskReport | ConvertFrom-Json
$measurement = (Get-Content -Raw -LiteralPath $diskReport | ConvertFrom-Json).result.disk_requests
$measurement.summary | Select-Object request_union_ticks, waiting_before_ready_ticks, on_cpu_ticks
python -B tools\measure-etl-activity-waits.py @query @disk --check-report $receipt.report_sha256
```

The receipt reports `disk_requests_status` as `measured` when all
participating records agree. Exit 1 retains the reason for an unavailable
measurement or a digest mismatch. Invalid pins and occupied output paths
return exit 2. Add the CPU adapter options to the same invocation to
include ReadyThread correspondence or interrupt overlap.
[Request pairing and time fields](TRACE_IMPORT.md#disk-requests-during-a-thread-activity)

### Compare enclosing file operations

Use the same `$query` and `$disk` from the preceding examples. The disk
adapter package now contains a Windows TDH reader alongside TraceProcessor.
Older disk packages still support the v3 disk query. Supply the updated
package for the v4 file comparison and use the same package for replay.

```powershell
$fileReport = Join-Path $PWD 'private-activity-file.json'
$receipt = python -B tools\measure-etl-activity-waits.py @query @disk --file-operations --output $fileReport | ConvertFrom-Json
$files = (Get-Content -Raw -LiteralPath $fileReport | ConvertFrom-Json).result.file_operations
$files.summary.contexts | Select-Object operation, file_start_record, disk_init_record, disk_completion_record, file_end_record, ntstatus, actual_bytes
python -B tools\measure-etl-activity-waits.py @query @disk --file-operations --check-report $receipt.report_sha256
```

`file_operations_status` is `compared` when the selected rows were checked,
or `no_disk_requests` when the disk query measured zero. Exit 1 preserves
the reason for incomplete evidence or a replay mismatch. Exit 2 covers an
invalid package pin, a package missing the native helper or an occupied
output path. [Fields and limits](TRACE_IMPORT.md#file-operations-enclosing-disk-requests)

### Compare hard faults with disk and file reads

Use the same `$query` and `$disk` from the activity wait examples. Build
the current disk adapter for this query. `--fault-io` also collects the
enclosing file operations. The v5 report measures overlap in QPC ticks
and keeps the original fault, disk and file record numbers.

```powershell
$faultReport = Join-Path $PWD 'private-activity-fault-io.json'
$receipt = python -B tools\measure-etl-activity-waits.py @query @disk --fault-io --output $faultReport | ConvertFrom-Json
$io = (Get-Content -Raw -LiteralPath $faultReport | ConvertFrom-Json).result.fault_io
$io.summary.comparisons | Format-Table fault_record, disk_table_row, fault_disk_object_value, disk_read_fields_match
$io.summary.matching_disk_ticks | Format-List total, on_cpu, waiting_before_ready, ready_to_dispatch, other_off_cpu
python -B tools\measure-etl-activity-waits.py @query @disk --fault-io --check-report $receipt.report_sha256
```

In the public TaskbarLatency recording, records 339732 and 374019 bound
two overlapping reads with different object values. Records 397312 and
398477 bound two reads with matching disk fields. A qualified window can
also return zero overlaps. The receipt retains each query's status when
a reader or evidence source is unavailable. [Fields and limits](TRACE_IMPORT.md#hard-faults-and-reads-during-a-thread-activity)

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

`!kmon cases /json` includes an `ordering` block for the local current view:
retained states and their capacity, expiry, deferrals, the arrival watermark and
any conservative transition floor. Independently delayed paths can remain current
within the 30-second window; older observations of the same path cannot roll it
back. `current_capacity` can mean the ordering guard budget was exhausted as well
as the current-reference budget. Saved snapshots preserve these limits. See
[local ordering and clock restrictions](ARCHITECTURE.md#local-current-view-ordering).

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
!timeline ingest observer
!timeline query /source observer /domain observer_action
```

TI access depends on process protection and Windows policy. The console checks
prerequisites; a read-only query cannot silently create a usable subscription.
Starting/stopping collection is a mutation. The ring, console tail and rotating
JSONL log are separate outputs: a quiet display does not imply no retained
events, and failed file output does not make the ring durable. Watch changes
affect live display/selection as documented by `help !ti`; inspect counters and
log state explicitly.

A TI session name collision returns Win32 183 and leaves the existing logger
running. The controller checks the GUID on the handle returned by its own
successful start before requesting a stop. When cleanup is pending, `!ti status`
shows `trace_resources` and `!ti stop` retries. The observer timeline retains
the controller's requests and their original Win32 results. For example,
Win32 `ERROR_MORE_DATA` on a stop means ETW stopped the session and had more
properties to return. [Windows ControlTraceW contract](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-controltracew)

`KnLiveDbg.exe --self-test ti-ownership` exercises the controller with scripted
errors and a provider-free private Windows logger. It checks foreign-session
survival, rollback, same-name replacement and the serialized timeline receipts.

Live callback start, stop and ring clear use the same observer commands. A
matching driver returns ordered callback calls, their raw NTSTATUS values and
the remaining registrations, even when rollback fails. An older driver's
acknowledgment is labeled separately. `KnLiveDbg.exe --self-test callback-ownership`
exercises the control contract and uses an owned Windows pipe for the native
transport rejection. [Live callback control results](TIMELINE_COMMAND_USAGE.md#inspect-live-callback-control-results)

Guided timeline activation and `!kmon start` reuse a running collection. An
automatic start requires a validated, idle status with no event history or
outstanding callback registrations. An explicit `!timeline live start` resets
the event ring. Use `!timeline live status` to inspect its counters beforehand.

For a watched file-handle or graph scan, match the acquisition ID in the KMON
record to the controller's process-handle timeline. [Watched handle scan fields](TIMELINE_COMMAND_USAGE.md#trace-a-watched-handle-scan)

The observer commands also show KMON process logging attempts. The requested
PID and creation time identify the process. Use the identity acquisition ID
to follow the user-mode and driver results for the same request. [Process logging request fields](TIMELINE_COMMAND_USAGE.md#inspect-kmon-process-logging-requests)

Use [timeline workflows](TIMELINE_COMMAND_USAGE.md) to ingest TI, live kernel
events and snapshots, query evidence families, export JSONL, and reconcile
same-boot baselines. Collection loss and capacity eviction constrain absence
claims.

For `!timeline reconcile snapshot [baseline|<path>]`, check `bootComparison`
and `comparedEvents` in structured output. A saved file from another boot or
without a verified local receipt yields zero comparable events. Source counts
distinguish snapshot and diff rows, controller actions, unbound inputs and
local target events. `generationMatches` counts ETW header events whose source
process generation matches the snapshot. Several events can match one process.
`candidateRecords` counts snapshot records with matching endpoint labels.
Both counts precede the finding limit. [Timeline reconciliation](ARCHITECTURE.md#timeline-reconciliation)

## Baselines, diffs and dumps

For two saved captures, run `!diff <old.json> <new.json> /summary /memory`.
The `bootBasis` field gives the evidence for boot-dependent findings.

To compare the same files without starting a live debugger, use the offline
summary. It reads two resident local files of up to 64 MiB each. The JSON
includes both input hashes, the receipt state of each input, `boot_basis`
and the counts of added, escalated, removed and high-risk findings.

```powershell
$result = & $exe --offline '!diff' $baseline $current /summary /json | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw $result.reason }
$result | Select-Object same_boot, boot_basis, baseline_boot_source, current_boot_source, escalated
```

| Value | Interpretation |
| --- | --- |
| `local_boot_receipts` | Both original JSON files verify under the current Windows user and installation and record the same boot GUID. |
| `collector_session` | The baseline and its new observation came from this running collector. |
| `different_local_boots` | The qualified observations record different boot GUIDs. |
| `origin_unverified` | At least one file lacks a verifiable local receipt. This includes earlier snapshots and edited copies. |
| `comparison_disabled` | At least one input disables the same-boot comparison. |

Keep the original JSON produced by `!snapshot save` or a saved baseline.
Structured display output is a projection of the snapshot. A missing or
unreadable receipt still permits ordinary inventory and risk comparisons.
The warning names the receipt state of each input. [Receipt format and scope](ARCHITECTURE.md#boot-evidence-for-snapshot-comparisons)

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

### Diagnose a saved kernel dump

`KnLiveDbg.exe --crash-diagnose <local-kernel-dump> --sha256 <digest>`
compares the AMD64 dump header with the stop code and four parameters
returned by DbgEng. Run it from a shell with the Release controller on
`PATH`. This PowerShell example also prints the status when only the header
could be read.

```powershell
$dump = Get-Item -LiteralPath '.\saved-kernel.dmp'
$pin = (Get-FileHash -LiteralPath $dump.FullName -Algorithm SHA256).Hash
$json = & KnLiveDbg.exe --crash-diagnose $dump.FullName --sha256 $pin
if ($LASTEXITCODE -eq 2) { throw 'Could not read the diagnosis output.' }
$report = $json | ConvertFrom-Json
$report.status
$report.assessment.hypotheses | Select-Object candidate, state
```

Save the digest with the original for later replay. A local regular file
on a fixed drive is required. The size limit is 16 GiB and each hash pass
has a 30-second budget checked between reads. A pinned small kernel dump
may yield a stop tuple even when its saved stack is unavailable. The
report includes native HRESULTs, the debugger version, up to 32 frames
and evidence pointers for each hypothesis. `frame_limit_reached` means the
returned frames filled the buffer.

Exit 0 means the two decoders returned the same tuple. Exit 1 covers a
missing or unsupported input, pin mismatch, header-only observation or
conflict. Exit 2 covers command usage and output failures. Error output
to a disk file is suppressed when it could overwrite the input, including
through a hard link. Keep the dump
and the JSON private. Module ranges, stack coordinates and stop
parameters can identify the target. [Dump diagnosis evidence](ARCHITECTURE.md#typed-crash-dump-diagnosis)

### Read the WHEA record from a saved bugcheck

Add `--whea` to request `kn.crash_diagnosis.v2`. On a qualified `0x124`
dump, the command follows the second stored bugcheck parameter to one
Common Platform Error Record (CPER). The default command continues to
return `kn.crash_diagnosis.v1`.

```powershell
$dump = Get-Item -LiteralPath '.\saved-kernel.dmp'
$pin = (Get-FileHash -LiteralPath $dump.FullName -Algorithm SHA256).Hash
$json = & KnLiveDbg.exe --crash-diagnose $dump.FullName --sha256 $pin --whea
if ($LASTEXITCODE -eq 2) { throw 'Could not read the diagnosis output.' }
$report = $json | ConvertFrom-Json
$report.status
$report.whea_record | Format-List status, captured_bytes, captured_sha256, qualifiers
$report.whea_record.sections | Format-Table type, severity, decode
$report.assessment.hypotheses | Where-Object candidate -eq 'fatal_error_reported_at_stop' |
    Format-List candidate, state, contrary, missing, next
```

Read `whea_record.status` even on exit 0. `linked` means the entire declared
record and its section extents were available. Each section has an offset,
length, GUID and SHA-256. `decode` identifies the fields supported for that
section. `incomplete_read` includes the count and hash of the contiguous
bytes recovered, plus each debugger request and its HRESULT. A malformed
descriptor, unsupported revision or budget limit has its own status.
Input admission failures contain only the diagnosis status.

For a machine-check exception, `matches_stop_status` compares a valid
bank with parameters 3 and 4. A null comparison identifies missing or
inapplicable data. `qualifiers` and the hypothesis's `contrary` and
`missing` evidence distinguish conflicting observations from unavailable
ones. Hardware identifiers, addresses and the report belong with the
original private dump. [WHEA evidence boundaries](ARCHITECTURE.md#stop-linked-whea-records)

### Compare a saved WHEA event with the dump

Use the XML view of **one** System event exported independently of the dump.
Windows Event Viewer and `EventLogRecord.ToXml()` use the Windows Event
namespace. Keep each original and its SHA-256. The command takes the
dump pin and the event pin separately.

```powershell
$dump = Get-Item -LiteralPath '.\saved-kernel.dmp'
$eventXml = Get-Item -LiteralPath '.\whea-event.xml'
$dumpPin = (Get-FileHash -LiteralPath $dump.FullName -Algorithm SHA256).Hash
$eventPin = (Get-FileHash -LiteralPath $eventXml.FullName -Algorithm SHA256).Hash
$json = & KnLiveDbg.exe --crash-diagnose $dump.FullName --sha256 $dumpPin --whea --event-xml $eventXml.FullName --event-sha256 $eventPin
if ($LASTEXITCODE -eq 2) { throw 'Could not read the diagnosis output.' }
$report = $json | ConvertFrom-Json
$report.status
$report.whea_event | Format-List status, same_payload_bytes, payload_sha256, dump_record_sha256
$report.whea_event.event | Format-List event_id, event_record_id, system_time_utc
```

`matching_payload_bytes` means the event payload and the entire linked
dump record have equal lengths and SHA-256 digests. A change in padding
alone produces `different_payload_bytes`. A missing dump page, wrong
event pin, unsupported provider or incomplete event leaves
`same_payload_bytes` null. Exit 0 still means the two dump stop tuples
agree. Use `whea_event.status` for the comparison. The report preserves
the Windows event record ID and the timestamp from the export. Verifying
which host and boot produced them requires independent evidence.
[Event comparison boundaries](ARCHITECTURE.md#saved-whea-event-comparison)

### Compare a reboot event with a saved dump

Add `--reboot-log`, the archive's SHA-256 and an explicit record ID to
`--crash-diagnose` to request `kn.crash_diagnosis.v3`. The input is a local
Windows EVTX archive. In the example, PowerShell selects the most recent
Kernel-Power 41 record in the archive. For a particular investigation,
use the record ID from that incident's evidence.

```powershell
$dump = Get-Item -LiteralPath '.\saved-kernel.dmp'
$log = Get-Item -LiteralPath '.\saved-system.evtx'
$record = Get-WinEvent -FilterHashtable @{Path=$log.FullName; ProviderName='Microsoft-Windows-Kernel-Power'; Id=41} -MaxEvents 1 -ErrorAction Stop
$dumpPin = (Get-FileHash -LiteralPath $dump.FullName -Algorithm SHA256).Hash
$logPin = (Get-FileHash -LiteralPath $log.FullName -Algorithm SHA256).Hash
$json = & KnLiveDbg.exe --crash-diagnose $dump.FullName --sha256 $dumpPin --reboot-log $log.FullName --log-sha256 $logPin --record-id $record.RecordId
if ($LASTEXITCODE -eq 2) { throw 'Could not read the diagnosis output.' }
$report = $json | ConvertFrom-Json
$report.status
$report.reboot_event | Format-List status, requested_record_id, bugcheck_code_decimal, same_stop_code, same_stop_tuple
```

Exit 0 describes agreement between the dump header and the debugger.
Read `reboot_event.status` for the comparison with the archive. A qualified
nonzero dump stop and all five matching event fields give
`matching_stop_tuple`. One differing field gives `different_stop_tuple`.
A version-one event can corroborate or contradict the code alone.
A zero or unavailable code leaves both comparisons null. The event time
belongs to the Windows startup that recorded the earlier unclean shutdown.
The report leaves the cause and host/boot provenance open. WHEA options
can precede `--reboot-log` when both types of evidence are available.
[Reboot event evidence boundaries](ARCHITECTURE.md#saved-reboot-event-comparison)

### Compare dump and reboot times

Append `--compare-time` to the saved Event 41 command to request
`kn.crash_diagnosis.v4`. Use the same dump, archive, pins and selected
record as in the preceding example.

```powershell
$json = & KnLiveDbg.exe --crash-diagnose $dump.FullName --sha256 $dumpPin --reboot-log $log.FullName --log-sha256 $logPin --record-id $record.RecordId --compare-time
if ($LASTEXITCODE -eq 2) { throw 'Could not read the diagnosis output.' }
$report = $json | ConvertFrom-Json
if ($null -eq $report.reboot_timeline) { throw $report.status }
$report.reboot_timeline | Select-Object status, event_minus_dump_100ns, estimated_dump_boot_filetime
$report.assessment.hypotheses | Where-Object candidate -eq 'same_recorded_stop_at_restart'
```

The signed interval `event_minus_dump_100ns` gives the earliest and latest
possible difference between the recorded UTC times. Positive bounds place the
dump before the event. Negative bounds place the dump after it. An event in
the same debugger second leaves the order unresolved. The hypothesis retains
both the matching stop fields and any contrary timing evidence. Check the
host, boot and clock-change history before attributing the restart.
[Clock sources and precision](ARCHITECTURE.md#saved-reboot-event-comparison)

### Read clock changes preceding a reboot event

Use an inclusive range of up to 8,192 System record IDs ending at the selected
Kernel-Power event. Choose the first ID from the same saved EVTX. The example
inspects up to the last 8,192 IDs using the dump, log, pins and record above.

```powershell
$first = [Math]::Max([long]1, [long]$record.RecordId - 8191)
$json = & KnLiveDbg.exe --crash-diagnose $dump.FullName --sha256 $dumpPin --reboot-log $log.FullName --log-sha256 $logPin --record-id $record.RecordId --compare-time --clock-history-from $first
if ($LASTEXITCODE -eq 2) { throw 'Could not read the diagnosis output.' }
$report = $json | ConvertFrom-Json
if ($null -eq $report.clock_history) { throw $report.status }
$report.clock_history | Select-Object status, requested_record_ids, records_read, same_channel_and_computer_records
$report.clock_history.changes | Select-Object record_id, status, clock_delta_100ns
```

In `kn.crash_diagnosis.v5`, a negative `clock_delta_100ns` means the clock
moved backward. A null delta leaves the change unresolved. A filtered export
can preserve a specific adjustment while omitting thousands of intervening
records. Check `saved_window_complete` before interpreting an empty list.
If the endpoint is unavailable, `reboot_event.status` gives the archive or
record lookup result.
The original dump comparison is available in `reboot_timeline`.
[Clock evidence and limits](ARCHITECTURE.md#saved-reboot-clock-changes)

### Compare a dump with the previous boot window

Reuse the pinned dump, System log, Event 41 and first record ID from the
preceding example. Include at least the two most recent OS start records
before Event 41. Windows writes the restart event during the following boot.
[Microsoft's Event 41 guidance](https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/event-id-41-restart)

```powershell
$json = & KnLiveDbg.exe --crash-diagnose $dump.FullName --sha256 $dumpPin --reboot-log $log.FullName --log-sha256 $logPin --record-id $record.RecordId --compare-time --clock-history-from $first --boot-window
if ($LASTEXITCODE -eq 2) { throw 'Could not read the diagnosis output.' }
$report = $json | ConvertFrom-Json
if ($null -eq $report.boot_window) { throw $report.status }
$report.boot_window | Select-Object status, boot_suffix_complete, dump_position, previous_start_in_estimated_boot
$report.assessment.hypotheses | Where-Object candidate -eq 'same_recorded_stop_at_restart'
```

In `kn.crash_diagnosis.v6`, `within_previous_boot_window` places the whole
recorded dump second between the two starts. `at_or_after_receiving_start`
can occur even when the dump precedes Event 41 and all five stop fields
match. A second spanning a boundary leaves placement open. Inspect
`previous_start`, `receiving_start` and the two clock-change counts when
the comparison is unresolved. [Boot window evidence](ARCHITECTURE.md#saved-boot-windows)

### Compare Windows Error Reporting records across saved logs

`--wer-reports` works without a dump. Choose a System Event 1001 from
`Microsoft-Windows-WER-SystemErrorReporting` and an Application Event 1001
from `Windows Error Reporting` whose event name is `BlueScreen`. Each record
ID belongs to its own log. To check a particular reboot, also select its
Kernel-Power Event 41 from the same System export. Windows records the stop
parameters and report ID in the System error report. [Windows reboot events](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)

Set the two file paths and three selected record IDs in the environment
variables below. Omit `--restart-record` and its argument to compare just
the two WER records.

```powershell
$systemLog = Get-Item -LiteralPath $env:KN_SYSTEM_EVTX -ErrorAction Stop
$applicationLog = Get-Item -LiteralPath $env:KN_APPLICATION_EVTX -ErrorAction Stop
$systemPin = (Get-FileHash -LiteralPath $systemLog.FullName -Algorithm SHA256).Hash
$applicationPin = (Get-FileHash -LiteralPath $applicationLog.FullName -Algorithm SHA256).Hash
$json = & KnLiveDbg.exe --wer-reports $systemLog.FullName --sha256 $systemPin --system-record $env:KN_SYSTEM_WER_RECORD --application-log $applicationLog.FullName --application-sha256 $applicationPin --application-record $env:KN_APPLICATION_WER_RECORD --restart-record $env:KN_RESTART_RECORD
if ($LASTEXITCODE -eq 2) { throw 'Could not read the WER comparison output.' }
$report = $json | ConvertFrom-Json
$report.report_pair
$report.restart_interval | Select-Object coverage, records_read, same_reported_stop, restart_report_corroborated
```

Exit 0 means the selected reports agree and any requested reboot comparison
is corroborated. Exit 1 carries the available observations, including
conflicts and missing evidence. Exit 2 indicates invalid arguments or an
output failure. Several Application records can refer to one WER report.
The report ID, stop fields and computer-label comparisons are available
separately. The assessment cites the fields supporting or contradicting
the comparison and identifies missing evidence. [Recorded evidence and limits](ARCHITECTURE.md#cross-channel-windows-error-reports)

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
| MCP | `mcp on --observe` serves retained timeline queries and status over loopback. `--principal <fingerprint> <source>` restricts row and receipt access by source. Use `--principal-access <fingerprint> <access>` to choose what a client may read. To grant one TI process lifetime, run `!timeline targets ti <pid>` and use its boot ID, PID and creation FILETIME with `--principal-target`. Add `--tls --bind <ipv4>` for scoped HTTPS. [MCP setup](MCP_SETUP.md#connect-a-retained-evidence-client-over-https) |

Use `q` for orderly controller exit. Run fixture and collector lifecycle tests
from the [manual checklist](MANUAL_TEST_CHECKLIST.md), with failed cleanup kept
as a failure rather than hidden by a successful command's output.
