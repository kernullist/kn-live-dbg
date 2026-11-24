# Corpus evaluation contract

`tools/evaluate-corpus.py` supports imported case-level declarations, replay
of Windows module-observation workloads, and a paired reading of a saved ETL. An imported
report records the hashes supplied by its author. A [retained corpus](#retain-and-recover-imported-originals)
also checks the bytes behind those hashes and can recover individual originals. The workload adapter reads
the retained files, checks controller and observer records against each other,
and calculates metrics for the two measured populations. The evidence layers
are `synthetic`, `owned_fixture`, `authorized_sample` and `independent_comparison`.

## Replay an owned Windows acquisition

Use Python 3.11 or later on Windows to collect the two workloads. Build the
core with `tools/validate-kmon-core.ps1` first. Choose a new package filename
under `.build` for each run. The runner publishes a completed package and
prints its SHA-256 even when a completed workload misses its coverage gate.
Its exit status reports whether the live gate passed. If two writers choose
the same destination, the first publication owns the file and the other fails.

```powershell
$package = '.build/module-run.knbench'
$run = python tools/test-user-module-workload.py --core-exe .build/kmon-core/Release/kmon-core-Release.exe --benchmark-out $package | ConvertFrom-Json
$acquisitionExit = $LASTEXITCODE
$pin = $run.benchmark_sha256
if (-not $pin) { throw "Acquisition ended without a package (exit $acquisitionExit)" }
python tools/evaluate-corpus.py --owned-module-run $package --sha256 $pin
```

Keep the returned pin separately from the package. Replay needs only Python's
standard library and the two evaluation scripts. It can run after every target
has exited, including on another OS. The evaluator reads the executable images
as data in memory. A mismatched pin, malformed member or
inconsistent witness produces exit 2 with an empty stdout.

The private ZIP stores seven uncompressed members in a fixed order. Collection
holds read handles that deny writing and renaming the executable and controller
inputs. It checks the OS image file identity of each live target and observer
against the held input. The manifest records the measured Windows build, host
architecture, clock, run ID, image file identities and hashes of the six inputs.

| Retained input | What the evaluator checks |
| --- | --- |
| `collector.bin`, `target.bin`, `controller.py` | SHA-256 of the native core, child interpreter and controller bytes |
| `truth.json` | Child readiness, parent handle identity, image binding, census and dispatch request windows, exits, final job counts and interruption witnesses |
| `fixed.jsonl`, `changing.jsonl` | Original observer stdout in order, including census membership, dispatches, generation fences, module counts, executable base, enumeration status and final receipt counts |

Each in-scope child generation contributes one positive ground truth for
observing its own main module. The outside-job child is a scope control. The
fixed cohort contains 12 generations. The changing cohort contains 22,
including the pre-census exit, the exit after selection, six additions and
three replacements. The evaluator checks these transitions against the 16
inventory rounds, including event order when clock ticks coincide.
For every generation in the final census, replay compares first and last
admission, last attempt, last success and failure status against the terminal
ledger. It also reconciles observation, revisit, service and reservation counts.

An observation requires a live generation, matching before/after fences, a
complete walk through normal enumeration end and the executable base reported
by the child. At least one qualifying walk makes a case positive. For a case
with no qualifying walk, a source error takes precedence over unavailable
attempts. A case with no dispatch is missing. All four outcomes contribute to
end-to-end recall. Each case cites its one-based readiness event, the reply
that justified its outcome and the reply used for timing. A missing case has
only a readiness reference. The recorded exit or cutoff closes its window.
Time starts at child readiness and ends at the first qualifying observation or
the last failed dispatch. A generation with no attempt has unknown latency.

`kn.owned_module_evaluation.v1` reports one development group per run and
separate fixed and changing scopes. SHA-256 ties replay to the caller's
retained bytes. The controller supplies the lifetime witnesses. External
authentication, heldout samples, comparative detection performance and host
overhead remain open. Standalone replay metrics cover completed acquisitions.
Use a registered campaign to count attempts that end before package publication.

The package, original transcripts, controller journal and evaluator report
contain private investigation data. The public-content check recognizes the
package header even when a file has been renamed.

## Register and evaluate repeated acquisitions

Register a new directory before the first Windows run. The plan fixes 1–32
numbered slots, a distinct ticket for each slot, the worker deadline and the
SHA-256 of the core, interpreter, controller, campaign and package-format
scripts. Keep the returned plan pin separately. Each slot can be admitted once.

```powershell
$core = '.build/kmon-core/Release/kmon-core-Release.exe'
$series = '.build/module-series'
$plan = (python tools/owned_module_campaign.py create --directory $series --core-exe $core --attempts 2 --timeout-ms 180000 | ConvertFrom-Json).plan_sha256
python tools/test-user-module-workload.py --campaign $series --slot 1 --plan-sha256 $plan --core-exe $core
$snapshot = Join-Path $series 'first.knruns'
$pin = (python tools/owned_module_campaign.py snapshot --directory $series --plan-sha256 $plan --out $snapshot | ConvertFrom-Json).snapshot_sha256
python tools/evaluate-corpus.py --owned-module-campaign $snapshot --sha256 $pin --plan-sha256 $plan
```

This example leaves slot 2 unadmitted. It can be run later with a new snapshot
filename. Each snapshot reads the complete roster and all transitions in one
SQLite transaction. The snapshot and its acknowledged packages can be copied
to another directory for offline replay with both pins. An earlier snapshot
continues to describe the state at its own cutoff.

| Recorded boundary | Evidence |
| --- | --- |
| Unadmitted | The original plan contains the ticket and the frozen registry has no admission |
| Admitted | The supervisor commits the slot, its own process generation and its clock before checking the executable inputs |
| Worker bound | Windows assigned the waiting worker to the supervisor's kill-on-close job. Its original PID and creation time are recorded before the supervisor grants it the ticket |
| Supervisor terminal receipt | The receipt binds to the preceding transition and records the worker's OS exit, cleanup, resource accounting and any acknowledged package pin. Structured worker failures also retain their phase, error domain and available native code |
| Observed owner loss | An independent observer pinned both original processes while live, saw both handles signal and recorded their exit codes while the slot still lacked a terminal receipt |
| Unresolved | An admission lacks both a terminal receipt and an owner-loss witness. Its process-level truth and final job costs are unknown |

For an independent owner-loss witness, run the following in a second console
while the slot's worker is active. Use the same directory and original plan
pin. The observer prints `armed` after opening and checking both live handles.
If the supervisor records its result normally, the observer preserves it.
An observation timeout keeps the last registered state.

```powershell
python tools/test-user-module-workload.py --campaign $series --slot 1 --plan-sha256 $plan --watch-owner --watch-seconds 180
```

The supervisor returns 0 for a published, passing workload with confirmed
cleanup, 1 for a recorded unsuccessful terminal result and 2 for a rejected
invocation or registry error. A crash can leave a durable admission without
a terminal result. Snapshots account for every planned slot, including those
still unadmitted. Starting another attempt requires a fresh slot.

The report shows success per planned slot and per admission. Evidence survival
uses verified packages over acknowledged publications. If an acknowledged
package disappears, becomes unreadable, changes bytes or has invalid source
records, the report keeps its slot and withholds process metrics. Contradictory
plan, transition, ticket or replayed gate evidence fails the evaluation.
Repeated acquisitions share one declared development group. The fixed and
changing process denominators are available for each verified package.

Job receipts include user/kernel CPU time in 100 ns units, transfer bytes,
operation counts, peak job memory in bytes, total processes and the final
active count. The scope includes the assigned worker and its descendants in
the nested jobs. Peak-memory query failures retain their error and a null
value. Admission-to-terminal elapsed time uses the supervisor's
`GetTickCount64` clock. The fixed workload can also measure individual
collector requests against an idle control. [Windows job accounting](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_and_io_accounting_information)
and [peak job memory](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information).

Keep the registry, its SQLite recovery files, snapshots, packages and
reports private. The pins bind the operator's pre-registered plan and chosen
snapshot. Third-party provenance and runs performed outside that registry
remain outside this measurement.

## Measure paired collector costs

Add `--paired-costs` when creating a campaign to require the measurement for
each registered slot. The supervisor passes the registered setting to its
worker. The fixed workload keeps the same 12 target processes alive and uses
the same collector and pipes for both arms. Each census and each module visit
has one matching idle request. The ticket sets the first arm. The order then
alternates separately for censuses and visits. The changing workload continues
to measure process lifetimes.

```powershell
$core = '.build/kmon-core/Release/kmon-core-Release.exe'
$series = '.build/module-cost-series'
$plan = (python tools/owned_module_campaign.py create --directory $series --core-exe $core --attempts 2 --paired-costs | ConvertFrom-Json).plan_sha256
python tools/test-user-module-workload.py --campaign $series --slot 1 --plan-sha256 $plan --core-exe $core
$snapshot = Join-Path $series 'first.knruns'
$pin = (python tools/owned_module_campaign.py snapshot --directory $series --plan-sha256 $plan --out $snapshot | ConvertFrom-Json).snapshot_sha256
python tools/evaluate-corpus.py --owned-module-campaign $snapshot --sha256 $pin --plan-sha256 $plan
```

For a standalone run, add `--paired-costs` to the `--benchmark-out` command.
Both acquisition paths produce a v2 package. Its fixed-scope report contains
`paired_costs.operations.inventory` and `paired_costs.operations.dispatch`.
The source and idle line numbers in `receipts` point into the original
`fixed.jsonl`. The corresponding `truth_event` contains the supervisor's
before and after samples. Replay reads v1 packages with their original
unpaired semantics.

| Metric | Interval and unit |
| --- | --- |
| `native_service_ns` | Time inside the collector from command dispatch through payload construction, converted from performance-counter ticks |
| `roundtrip_ns` | Supervisor interval around one request and its decoded response, including pipe traffic and scheduling |
| `user_100ns`, `kernel_100ns` | Change in cumulative CPU time for the collector process, in 100 ns units |
| I/O operation and byte counts | Change in the collector's read, write and other counters, including its pipe I/O |
| `working_set_change_bytes` | Signed difference between the two sampled working-set sizes, in bytes |

The supervisor samples the same open process handle throughout. Replay checks
the collector PID and creation time, the two reported counter frequencies and
the native interval against its supervisor bracket. Each interval is rounded
down to whole nanoseconds before addition. A metric reports the number of
complete pairs, both totals and their signed difference. A failed counter
query retains its Windows error. If either arm lacks that metric, the pair is
excluded from both totals. Zero usable pairs produce null totals.
[Windows performance-counter ordering](https://learn.microsoft.com/en-us/windows/win32/sysinfo/acquiring-high-resolution-time-stamps),
[process CPU time](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes),
[process I/O](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getprocessiocounters),
[working-set counters](https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-process_memory_counters).

The campaign field `paired_costs_per_planned_run` counts verified measured
packages over all registered slots. Each package reports one controlled
development workload. The measurements cover work during the requests.
Host-wide overhead, game-frame latency, peak memory during a request and
independently sampled performance estimates remain open.

Keep the paired plan, manifest and truth journal private, including extracted
copies. The publication check recognizes their v2 schemas in complete JSON
and in interrupted output that retains the opening schema field. It also
recognizes the compact v2 plan in SQLite recovery pages.
[Publication check results](VALIDATION.md#paired-module-collection-costs-2026-11-21)

## Compare two readers on a saved ETL

On Windows with Python 3.11 or later, point `$trace` at an existing local ETL
and choose a new package path in a private directory. Record the expected
hashes of the trace and the KnLiveDbg executable before running the comparison.
The optional `--tracerpt-sha256` pins the installed Windows reader to an
independently retained hash as well.

```powershell
$trace = '.build/control.etl'
$exe = 'x64/Release/KnLiveDbg.exe'
$package = '.build/etl-reader-pair.knbench'
$tracePin = (Get-FileHash -LiteralPath $trace -Algorithm SHA256).Hash.ToLowerInvariant()
$exePin = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
$receipt = python tools/capture-etl-comparison.py --etl $trace --sha256 $tracePin --exe $exe --exe-sha256 $exePin --output $package | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or !$receipt.package_sha256) { throw 'ETL comparison package unavailable' }
python tools/evaluate-corpus.py --saved-etl-comparison $package --sha256 $receipt.package_sha256
```

To include disk I/O, add `--include-disk-io` at acquisition and choose a new
output path. The v2 manifest registers three families before either reader
starts. Replay reads the scope from the pinned package. The default command
continues to register the original two-family v1 comparison.

```powershell
$diskPackage = '.build/etl-reader-disk-pair.knbench'
$diskReceipt = python tools/capture-etl-comparison.py --etl $trace --sha256 $tracePin --exe $exe --exe-sha256 $exePin --include-disk-io --output $diskPackage | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or !$diskReceipt.package_sha256) { throw 'ETL comparison package unavailable' }
$result = python tools/evaluate-corpus.py --saved-etl-comparison $diskPackage --sha256 $diskReceipt.package_sha256 | ConvertFrom-Json
$result.families.disk_io
```

Acquisition copies the admitted bytes into a fresh working directory. Both
programs read the same file under the name `source.etl`. KnLiveDbg runs its
saved ETL capability probe, then the system copy of `tracerpt.exe` writes a
summary. Read handles protect the input and executable images during both
attempts. The runner compares each started process's Windows image path to
the native path of its pinned executable handle. A missing or different image
path leaves the reader unqualified. The archive retains the source, both binary hashes before and after
execution, the arguments and configuration hash, the reader OS build, and
each program's elapsed time, exit or launch error, stdout and stderr. The
external summary is a separate original output. `--timeout-ms` sets the wait
per reader to 1–600,000 ms and defaults to 240,000. A native launch failure or
timeout still leaves an attempt for the Windows reader.

The private archive accepts a trace up to 512 MiB. It retains up to 1 MiB
each of native stdout and the Windows summary, and 64 KiB per diagnostic
stream, along with the full byte count and full and retained SHA-256 values.
Replay recomputes the package hash, source hash and all retained output hashes.
When a stream exceeds its limit, the complete-stream hash remains an
acquisition record and the affected reader receives no comparison credit.
Keep the package and its pin separately. Replay needs the Python tools and
the package and runs on any supported Python host after the original source
and readers have been removed.

The original two families cover classic PerfInfo SampleProf opcode 46
version 2 and Thread CSwitch opcode 36 versions 2–4. The v2 comparison adds
one DiskIo family covering reads, writes, flushes and their initiations,
opcodes 10 through 15 in versions 2 and 3. It matches the DiskIo provider
GUID and recognizes both Windows names and numeric opcodes. The native count
covers qualified payloads. The external count covers matching descriptors.
Timing and individual requests require per-record evidence. [Disk I/O reader](TRACE_IMPORT.md#read-saved-disk-io-response-times)

Replay reads
English summary columns, retains multiword opcodes, and checks the sum of the
opcode rows against the traversal total. When an event ID table is present,
its provider/version totals must agree with the opcode table. The report
records which tables were present.

| Family verdict | Effect on the comparison |
|---|---|
| `agreed_observed`, `agreed_empty` | Equal positive counts or equal zeros on matching, complete traversals. Both contribute to agreement. |
| `count_disagreement` | Both counts are comparable. The family stays in the comparable denominator. |
| `coverage_limited` | A loss counter, incomplete buffer traversal, unsupported layout or unrecognized opcode name limits the family. The original counts remain visible. |
| `traversal_disagreement` | The programs report different overall record or buffer totals. |
| `native_family_unavailable` | A usable native report supplied the original two families and omitted disk I/O in a v2 comparison. The Windows count stays visible and disk I/O stays in the planned denominator. |
| `reader_unavailable` | At least one attempt lacks a usable original result. Process status and any surviving reader's counts remain available. |

`agreement_per_planned_family` has denominator two for v1 and three for v2.
`agreement_per_comparable_family` has a null value when no family is
comparable. Exit 0 from acquisition records a published pair. Exit 0 from
replay records an intact, evaluated pair, including pairs with failed readers.
An input pin mismatch or malformed package yields exit 2. A supervisor that
stops before publication has no completed pair. To include those attempts in
the denominator, [register a cohort](#register-a-cohort-of-saved-etls) before acquisition.

The two readers share the Windows ETW infrastructure. Their agreement measures
descriptor counts in this saved file. Producer identity, event semantics and
detection ground truth require separate evidence. The archive, extracted
streams, receipt and evaluation report contain private evidence.
[Two-family validation](VALIDATION.md#saved-etl-reader-comparison-on-2026-11-22) · [Three-family disk I/O validation](VALIDATION.md#disk-io-in-paired-etl-evaluations-on-2026-11-22)

## Register a cohort of saved ETLs

Register the source hashes in the order the files will be attempted. A plan
accepts 1–32 slots, pins both readers and fixes the per-reader timeout and
event families before the first attempt. The default families are CPU profile
and context switch. Add `--include-disk-io` to register all three. A repeated
hash counts as another planned attempt and contributes once to
`distinct_source_hashes`.

The example uses two local ETLs and the x64 Release reader. Substitute the
files to be compared. Keep the plan hash from registration for later replay.

```powershell
$traces = @('.build/p11-etl/control.etl', '.build/p11-etl/x64.etl')
$exe = 'x64/Release/KnLiveDbg.exe'
$systemReader = Join-Path $env:SystemRoot 'System32/tracerpt.exe'
$sourcePins = @($traces | ForEach-Object { (Get-FileHash -LiteralPath $_).Hash.ToLowerInvariant() })
$exePin = (Get-FileHash -LiteralPath $exe).Hash.ToLowerInvariant()
$systemPin = (Get-FileHash -LiteralPath $systemReader).Hash.ToLowerInvariant()
$series = Join-Path '.build' ('etl-cohort-' + [guid]::NewGuid().ToString('N'))
$plan = python tools/saved_etl_campaign.py create --directory $series --source-sha256 $sourcePins[0] --source-sha256 $sourcePins[1] --exe-sha256 $exePin --tracerpt-sha256 $systemPin --include-disk-io | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or !$plan.plan_sha256) { throw 'Registration failed' }
for ($i = 0; $i -lt $traces.Count; $i++) {
    python tools/saved_etl_campaign.py run --directory $series --plan-sha256 $plan.plan_sha256 --slot ($i + 1) --etl $traces[$i] --exe $exe | Out-Null
    if ($LASTEXITCODE -gt 1) { throw 'Slot command failed' }
}
$snap = Join-Path $series 'observed.knruns'
$frozen = python tools/saved_etl_campaign.py snapshot --directory $series --plan-sha256 $plan.plan_sha256 --out $snap | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or !$frozen.snapshot_sha256) { throw 'Snapshot failed' }
$report = python tools/evaluate-corpus.py --etl-reader-campaign $snap --sha256 $frozen.snapshot_sha256 --plan-sha256 $plan.plan_sha256 | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'Replay failed' }
$report | Select-Object planned_slots, acquisition_counts, agreement_per_planned_family, agreement_per_comparable_family
```

Each slot has one admission. A run reserves it before opening the ETL or
either reader. Exit 0 records a published comparison, including one with a
failed reader. Exit 1 records an acquisition failure such as a missing file
or a mismatched hash. Exit 2 signals a command or publication error. A later
snapshot counts whichever receipts survived. An issued slot cannot be
retried in place.

| Receipts in the snapshot | How replay accounts for the slot |
| --- | --- |
| No admission or outcome | `unadmitted`. No admission was retained. |
| Admission only | `unresolved`. A package without an acknowledged hash receives no credit. |
| Acquisition failure | The outcome retains the input role and both hashes on a mismatch, the original OS code on a file error or a bounded validation diagnostic. |
| Inconsistent, unreadable or damaged receipt | `unusable_receipts`. The snapshot keeps the read error or up to 2 KiB of each receipt, its size and the prefix hash. A separately valid admission survives. |
| Acknowledged package | Replay verifies its hash, source, plan and slot identities, both reader pins, scope and attempt intervals. A missing or invalid package stays in the planned denominator. |

Snapshotting checks two consecutive scans of the create-once receipts for
agreement. A later snapshot uses a new filename. To replay elsewhere, copy
the frozen snapshot and the ticket-named `.knbench` files together and
retain both expected hashes. Replay opens these files without launching a
reader. Keep plans, receipts, snapshots, packages and detailed reports private.

Agreement per planned family includes every registered file and family.
Agreement per comparable family covers only verified pairs with matching
scope and sufficient coverage. Both ratios include their counts and use
`null` for a zero denominator. The report also counts verified packages per
acknowledged publication and observed readers per planned reader. These
records describe the local controller's observations. Independent provenance
and detection accuracy require other evidence.
[Registered cohort validation](VALIDATION.md#registered-etl-reader-cohort-on-2026-11-22)

## Evaluate development and heldout ETLs separately

Register a private [benchmark corpus](#imported-input-schemas) before either
reader evaluates the heldout files. The campaign checks the complete corpus
for a sample family, independence group or identical artifact assigned to
both partitions. This includes cases outside the requested slots. Two
whole-file cases that share the same bytes must also declare the same sample
family and independence group. Use the same pinned corpus for campaigns
whose split should be comparable.

For each ETL case use layer `independent_comparison`, task
`saved_etl_descriptor_counts` and unit `case`. Set `artifact_sha256` to the
complete file hash and `holes_sha256` to the SHA-256 of the two ASCII bytes
`[]`, with no newline. The reader compares the whole file. The registered
event families determine how many comparisons each file contributes.
The corpus may also contain cases for other tasks. Supply `--case-id` once
per planned slot, in order, to select eligible cases. Repeating an ID
registers another attempt in its original group. Omitting the option selects
the entire corpus in declaration order. A campaign accepts up to 32 slots.

The following example expects a private corpus containing case IDs `control`
and `external` with the corresponding local files below. It registers a
second heldout attempt and leaves it unissued.

```powershell
$inputsDir = '.build/etl-study-example'
$roster = Join-Path $inputsDir 'corpus.json'
$files = @((Join-Path $inputsDir 'development.etl'), (Join-Path $inputsDir 'heldout.etl'))
$exe = 'x64/Release/KnLiveDbg.exe'
$exePin = (Get-FileHash -LiteralPath $exe).Hash.ToLowerInvariant()
$systemPin = (Get-FileHash -LiteralPath (Join-Path $env:SystemRoot 'System32/tracerpt.exe')).Hash.ToLowerInvariant()
$studyPin = (Get-FileHash -LiteralPath $roster).Hash.ToLowerInvariant()
$series = Join-Path '.build' ('study-' + [guid]::NewGuid().ToString('N'))
$plan = python tools/saved_etl_campaign.py create --directory $series --study-corpus $roster --study-sha256 $studyPin --case-id control --case-id external --case-id external --exe-sha256 $exePin --tracerpt-sha256 $systemPin --include-disk-io | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or !$plan.plan_sha256) { throw 'Study registration failed' }
for ($i = 0; $i -lt $files.Count; $i++) {
    python tools/saved_etl_campaign.py run --directory $series --plan-sha256 $plan.plan_sha256 --slot ($i + 1) --etl $files[$i] --exe $exe | Out-Null
    if ($LASTEXITCODE -gt 1) { throw 'Study slot command failed' }
}
$snap = Join-Path $series 'frozen.knruns'
$frozen = python tools/saved_etl_campaign.py snapshot --directory $series --plan-sha256 $plan.plan_sha256 --out $snap | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or !$frozen.snapshot_sha256) { throw 'Study snapshot failed' }
$r = python tools/evaluate-corpus.py --etl-reader-campaign $snap --plan-sha256 $plan.plan_sha256 --sha256 $frozen.snapshot_sha256 --study-sha256 $studyPin | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'Study replay failed' }
$r.partitions.heldout | Select-Object planned_slots, selected_cases_per_eligible, agreement_per_planned_family, agreement_per_planned_group
```

The plan retains the exact corpus bytes and selected IDs. Offline replay
verifies the corpus hash, checks every case again and matches the slot
sources to the selected cases. An independently retained `--study-sha256`
can also be supplied at replay. Store the snapshot alongside its ticket-named
packages as in the [cohort procedure](#register-a-cohort-of-saved-etls).

Read each partition separately. Each reports distinct selected cases over
eligible corpus cases, the IDs of omitted eligible cases, the original slot
numbers and results by sample family and independence group. A group agrees
only when every planned file and event family in it agrees. A group is fully
comparable when all those comparisons are comparable. Each declared group
counts once even when a case runs repeatedly. Failed or unissued
slots stay in the planned group denominator. A pin mismatch against known
bytes from the other partition is recorded in `cross_partition_input_mismatches`.

Partition checks use the declared identities and actual file hashes. The
history outside the pinned corpus, relationships between differently named
workloads and detection ground truth require separate evidence.
[Partitioned evaluation on public traces](VALIDATION.md#partitioned-etl-reader-study-on-2026-11-22)

## Run the synthetic example

Python 3.11 and the standard library are sufficient. From the repository root:

```powershell
# Choose a new directory; existing example directories are not overwritten.
python tools/test-corpus-evaluator.py --example-directory .build/corpus-example
python tools/evaluate-corpus.py --corpus .build/corpus-example/corpus.json --results .build/corpus-example/results.json
```

The example has 14 synthetic cases, seven positive ground truths and two true
positives. End-to-end recall is **2/7**; observable-scope recall is **2/4**.
Unavailable, errored and missing positive cases remain in the first denominator.
Two cases share a declared independence group, so they are not presented as
independent samples. The fixture's hashes identify synthetic declarations, not
real collected binaries or detection evidence. All three schemas below are
private investigation data and the public-content scanner rejects their JSON
artifacts from source commits.

## Imported input schemas

Each input is strict UTF-8 JSON without a BOM, at most 8 MiB and 128 levels deep. Duplicate members,
non-finite constants, unknown/missing fields and unsupported schema versions
fail with exit code 2 and no report on stdout. Each identifier below is 1..128
ASCII letters/digits or `_.:-`, beginning with a letter/digit. Hashes are exactly
64 lowercase hexadecimal characters. Null is allowed only where specified.
Both inputs are read once; the report records their exact SHA-256 hashes.

The corpus root requires `schema="kn.benchmark_corpus.v1"`, `corpus_id`,
`cohort_id`, `environment` and `cases` (1..4096 entries).

| Environment field | Meaning |
| --- | --- |
| `target_id`, `snapshot_id` | Declared target and acquisition identity; use explicit synthetic IDs for fixtures |
| `os_build` | Identifier or null for unknown |
| `architecture` | `amd64`, `arm64`, `x86` or `unknown` |
| `hvci`, `vbs`, `verifier` | Boolean or null; never inferred from a passing parser test |

| Case field | Meaning |
| --- | --- |
| `id` | Unique case identifier |
| `family` | Declared family; not interchangeable with independent sample count |
| `independence_group` | Shared ID for correlated variants/repeats |
| `partition` | `development` or `heldout` |
| `layer` | One of the four evidence layers above |
| `task` | Exact comparison task, such as `image-range-mismatch` |
| `unit` | `case`, `entity`, `page`, `event` or `claim`; assertion counts are not a unit |
| `artifact_sha256`, `holes_sha256` | Declared source artifact and hole-map identities; empty-hole maps also need an identity |
| `truth` | `positive`, `negative` or `unknown` for this task, not a generic maliciousness label |
| `truth_ref_sha256` | Ground-truth reference hash; may be null only for unknown truth |

A family, independence group or identical source artifact may not cross the
development/heldout boundary. This rejects obvious leakage, including renamed
families sharing bytes; it cannot discover undeclared semantic relationships.
Different holes in the same artifact do not make separate heldout material.

The results root requires `schema="kn.benchmark_results.v1"`, `corpus_sha256`
(hash of the exact corpus file bytes), `run_id`, `tool`, and `assessments`.
`tool` requires `name`, `version`, `binary_sha256` and `config_sha256`. These are
declared identities; the evaluator does not inspect those files.

| Assessment field | Meaning |
| --- | --- |
| `case_id` | A known corpus case, at most once per run |
| `artifact_sha256`, `holes_sha256` | Must exactly match that case's declared scope |
| `outcome` | `positive`, `negative`, `abstain`, `unavailable` or `error` |
| `evidence_sha256` | Assessment evidence hash; may be null only for unavailable/error outcomes |
| `elapsed_us` | Reported unsigned 64-bit integer microseconds or null; booleans, fractions and numeric strings are rejected |

There may be zero assessments. Omitted cases become `missing`; extra case IDs
and duplicate assessments fail. Keep repeated runs in separate result files;
the evaluator does not choose the best repeat or merge them into independent
samples. Findings from another scope or another tool policy require a separately
adjudicated assessment, not automatic conversion into false positives.

## Retain and recover imported originals

Keep the SHA-256 of the corpus plan before scoring. Give the evaluator the
two original JSON files, that pin, a new package filename and one `--original`
argument per available file. It hashes each supplied file and accepts bytes
referenced by a case, an assessment or the tool configuration. A shared file
occupies one entry. Omit an unavailable file to keep its absence in the report.
For a long list, pass `--file-list <file>` with a UTF-8 JSON object containing
`schema` set to `kn.benchmark_original_files.v1` and an `original_files`
array of local paths. Relative entries resolve from the list's directory.
The operator selects this input explicitly. Keep it private with the originals.
The publication receipt gives the SHA-256 of the completed package. Store the
two pins separately from the package.

This example starts with the 14-case synthetic corpus from the test suite and
retains the first case's source bytes. Run it in PowerShell from the checkout.

```powershell
$dir = Join-Path (Join-Path $PWD.Path '.build') ('retained-corpus-' + [guid]::NewGuid().ToString('N'))
python -B tools/test-corpus-evaluator.py --example-directory $dir
if ($LASTEXITCODE -ne 0) { throw 'Example corpus creation failed' }
$corpus = Join-Path $dir 'corpus.json'
$results = Join-Path $dir 'results.json'
$archive = Join-Path $dir 'example.knbench'
$source = Join-Path $dir 'case-source.bin'
[IO.File]::WriteAllBytes($source, [Text.Encoding]::ASCII.GetBytes('case-0'))
$plan = (Get-FileHash -Algorithm SHA256 -LiteralPath $corpus).Hash.ToLowerInvariant()
$saved = python -B tools/evaluate-corpus.py --corpus $corpus --results $results --plan-sha256 $plan --write-archive $archive --original $source | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'Corpus publication failed' }
$pin = $saved.package_sha256
$report = python -B tools/evaluate-corpus.py --archive-corpus $archive --sha256 $pin --plan-sha256 $plan | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'Corpus replay failed' }
$report.coverage.case_originals.artifact_sha256
$key = (Get-Content -LiteralPath $corpus -Raw | ConvertFrom-Json).cases[0].artifact_sha256
$copy = Join-Path $dir 'recovered.bin'
python -B tools/evaluate-corpus.py --archive-corpus $archive --sha256 $pin --plan-sha256 $plan --get-original $key --destination $copy
if ($LASTEXITCODE -ne 0 -or (Get-FileHash -Algorithm SHA256 -LiteralPath $copy).Hash -ne $key) { throw 'Original recovery failed' }
```

In this example one of 14 artifact references has verified bytes. The tool
binary, configuration and assessment evidence are absent, so zero assessments
qualify and all seven registered positives remain in the recall denominator.
For a fully retained case, supply its artifact and hole map, its declared truth
reference, the assessment's evidence, and the tool binary and configuration.
An unknown truth can have a null reference. An assessment without an evidence
reference remains visible with its declared outcome and cannot earn a score.

Replay streams every stored original, checks its SHA-256 and verifies both
package and plan pins. The results must bind the exact corpus bytes. The
`kn.benchmark_retained_report.v1` report shows the original outcome and the
status of each role for each case. `coverage.missing_sha256` identifies the
missing distinct files. The scoped and per-family metrics use assessments with
all required originals. Every registered case contributes to the planned count.
Observable-scope rates use the observed subset. The report retains the
submitted labels and timings. Attribution of authorship, independent truth
adjudication and another execution of the tool require separate evidence.

Recovery verifies the entire package before writing the requested bytes to a
new file. A missing digest, inconsistent member, trailing bytes or wrong pin
returns exit 2. Existing destinations keep their contents. Keep packages,
reports, recovery receipts and recovered files in private storage.
If the writer process terminates before publication, a private
`.knbench-*.tmp` file can remain beside the requested destination.

The binary format starts with the eight bytes `KNCORP1\0` and three unsigned
little-endian 32-bit integers giving corpus length, results length and original
count. The two unchanged UTF-8 documents follow. Each original contains a
32-byte SHA-256, an unsigned little-endian 64-bit byte count and the bytes
themselves. Empty originals are valid. The package holds up to 16,386 distinct
originals and 8 GiB overall. Each JSON input retains its 8 MiB limit. The
writer's 8 GiB read budget includes duplicate input files. Archive entries
contain no filesystem paths. [Windows acquisition checks](VALIDATION.md#retained-corpus-originals-on-2026-11-24)

## Imported report semantics

`kn.benchmark_report.v1` is UTF-8 JSON on stdout, capped at 16 MiB. A comparison
scope is `(layer, partition, task, unit)` within the declared cohort/environment.
At most 512 scopes are allowed. Each scope has aggregate and per-family counts;
there is no aggregation across different scopes or environments.

- `end_to_end_recall`: true positives / all declared positive ground truths,
  including abstentions, collection failures, errors and missing results.
- `observable_scope_recall`: true positives / positive ground truths whose
  outcome is positive, negative or abstain. Unavailable/error/missing outcomes
  are outside this denominator and remain visible in the outcome counts.
- `precision_known_truth`: true positives / positive predictions with known
  ground truth. Positive predictions with unknown truth are reported separately
  and are not silently declared correct or false.
- `false_positive_rate_observable`: false positives / observed negative ground
  truths, including abstentions. It does not claim a full-environment FPR.

Each ratio includes its numerator and denominator; a zero denominator produces
null, not zero or 100%. Unknown truth remains unscored and explicitly counted.
Latency summaries include any reported failed attempts and show known/unknown
counts, nearest-rank P50/P95/P99 and maximum, encoded as decimal microsecond
strings to preserve 64-bit values. These are imported timings, not measurements
made by this program; cases without timings do not become zero-latency samples.

Declared independence-group counts and correlated variants are shown. No
uncertainty interval is synthesized from unverified or correlated observations.
Actual independent sampling, uncertainty estimation, authorized corpora, live
collection overhead/safety and broader external-tool comparisons remain separate work.
`ground_truth_authenticated`, `target_probed`, `artifacts_opened` and
`independent_detection_validation` are always false for imported declarations.
