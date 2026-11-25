# Corpus evaluation contract

`tools/evaluate-corpus.py` supports imported case-level declarations, replay
of Windows module-observation workloads, and a paired reading of a saved ETL. An imported
report records the hashes supplied by its author. A retained corpus checks
the bytes behind those hashes and can recover individual originals. For
whole-file cases it can also check the registered label against signed
release metadata. [Original retention](#retain-and-recover-imported-originals)
[Publisher file comparison](#verify-a-file-against-a-publishers-release)

The workload adapter reads
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

The corpus root requires `schema`, `corpus_id`, `cohort_id`, `environment`
and `cases` (1..4096 entries). Use `kn.benchmark_corpus.v1` for the original
case fields. Version 2 also accepts a separately registered publisher file
and capture layout for [file range comparisons](#compare-observed-file-ranges).

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
themselves. Empty originals are valid. A v1 plan and its results can name up to
16,386 distinct originals. With a separate publisher file for each case, v2
can name up to 20,482. The package limit is 8 GiB. Each JSON input retains its 8 MiB limit. The
writer's 8 GiB read budget includes duplicate input files. Archive entries
contain no filesystem paths. [Windows acquisition checks](VALIDATION.md#retained-corpus-originals-on-2026-11-24)

## Verify a file against a publisher's release

For a case with task `publisher-target-bytes-match` and unit `case`, the
evaluator can decide whether the complete retained bytes match a named file in
a publisher's signed TUF targets list. Register the candidate, its acquisition
scope and the publisher reference in the existing corpus before assessment.
Keep the plan pin, the package receipt and a trusted root digest obtained
independently of the corpus. Install the optional verifier into the Python
environment used for this command with
`python -m pip install -r tools/requirements-publisher-truth.txt`.

The truth reference is a UTF-8 document. In `kn.benchmark_tuf_reference.v1`,
each of the four role fields holds the Base64 encoding of an original metadata
file. A `kn.benchmark_tuf_reference.v2` envelope also contains `root_updates`,
an array of 1 to 32 Base64-encoded successor roots in version order. The
`root` field always holds the original independently pinned root. The last
successor supplies the keys for `timestamp`, `snapshot` and `targets`.
Use `kn.benchmark_tuf_reference.v3` when a target is published by a delegated
role. Its `root_updates` array may be empty. Its `delegated_roles` object maps
each retained role name to the Base64 encoding of that original metadata file.
The signed parent determines which roles can authorize a given path.
Several cases can share a reference. The per-case hole map uses
`kn.benchmark_target_scope.v1`. Record the exact, case-sensitive target name,
the acquisition's declared file size in bytes and its sorted, nonoverlapping
missing intervals as pairs of zero-based offsets with an exclusive end.

This PowerShell example writes both inputs for a complete capture to a new
private working directory. Set `$metadata` to the directory containing the
four original JSON files. Use the initial root as `root.json` and the three
other roles from the revision being evaluated. Set `$rootUpdates` to an
ordered array of paths to successive root files, or `@()` for v1. For
example, for a v5 anchor and v16 terminal root in the same metadata directory,
use `$rootUpdates = @(6..16 | ForEach-Object { Join-Path $metadata "$_.root.json" })`.
For delegated verification, set `$delegatedRoles` to a hashtable of role
names and local files. For example, Sigstore's npm role can be supplied with
`$delegatedRoles = @{ 'registry.npmjs.org' = (Join-Path $metadata 'registry.npmjs.org.json') }`.
An empty hashtable or an unset variable keeps the v1/v2 format.
Set `$work` to the empty working directory,
`$targetName` to the signed name and `$capturedSize` to the whole-file size
recorded during acquisition. Use the recorded missing intervals for a capture
with gaps.

```powershell
$roleArgs = @()
if ((Test-Path variable:delegatedRoles) -and $null -ne $delegatedRoles) {
    foreach ($entry in $delegatedRoles.GetEnumerator()) {
        $roleArgs += @('--delegated-role', $entry.Key, $entry.Value)
    }
}
@'
import argparse, base64, json, sys
from pathlib import Path
metadata, work = map(Path, sys.argv[1:3])
def role_bytes(path):
    with path.open("rb") as stream:
        data = stream.read((1 << 20) + 1)
    if not 0 < len(data) <= 1 << 20:
        raise ValueError("role exceeds its size limit or is empty")
    return base64.b64encode(data).decode("ascii")

reference = dict(schema="kn.benchmark_tuf_reference.v1")
for role in ("root", "timestamp", "snapshot", "targets"):
    reference[role] = role_bytes(metadata / (role + ".json"))
parser = argparse.ArgumentParser(allow_abbrev=False)
parser.add_argument("updates", nargs="*")
parser.add_argument("--delegated-role", nargs=2, action="append", default=[])
args = parser.parse_args(sys.argv[5:])
if len(args.updates) > 32 or len(args.delegated_role) > 32:
    raise ValueError("too many root updates or delegated roles")
if args.updates or args.delegated_role:
    reference["schema"] = "kn.benchmark_tuf_reference.v2"
    reference["root_updates"] = [role_bytes(Path(p)) for p in args.updates]
if args.delegated_role:
    reference["schema"] = "kn.benchmark_tuf_reference.v3"
    reference["delegated_roles"] = {name: role_bytes(Path(p)) for name, p in args.delegated_role}
scope = dict(schema="kn.benchmark_target_scope.v1", target_path=sys.argv[3], file_bytes=int(sys.argv[4]), missing=[])
for name, document in (("publisher.json", reference), ("scope.json", scope)):
    encoded = json.dumps(document, separators=(",", ":")).encode("utf-8")
    if len(encoded) > 8 << 20:
        raise ValueError("document exceeds its size limit")
    with (work / name).open("xb") as out:
        out.write(encoded)
'@ | python -B - $metadata $work $targetName $capturedSize @rootUpdates @roleArgs
if ($LASTEXITCODE -ne 0) { throw 'Could not prepare publisher inputs' }
```

Register the SHA-256 of `publisher.json` as `truth_ref_sha256`, that of
`scope.json` as `holes_sha256` and the candidate's SHA-256 as
`artifact_sha256`. Supply these files to the corpus writer alongside any
assessment evidence, tool and configuration. To replay, set `$archive`,
`$pin` and `$plan` as in the retention example above. Set `$trustedRoot` to
the root metadata supplied by your independent trust source. Choose the UTC
instant for expiry checks explicitly. If a trusted source has already recorded
a minimum root version for this publisher, set `$minimumRootVersion` to that
positive decimal integer. Set it to `$null` to use only the pinned anchor and
the presented revisions. The date below is the instant used for the Sigstore study.

```powershell
$anchor = (Get-FileHash -Algorithm SHA256 -LiteralPath $trustedRoot).Hash.ToLowerInvariant()
$rootOptions = @()
if ($null -ne $minimumRootVersion) { $rootOptions += @('--minimum-root-version', $minimumRootVersion) }
$json = python -B tools/evaluate-corpus.py --archive-corpus $archive --sha256 $pin --plan-sha256 $plan --trusted-root-sha256 $anchor --verification-time 20261124T000000Z @rootOptions
$status = $LASTEXITCODE
if ($status -eq 2) { throw 'Publisher evaluation failed' }
$report = $json | ConvertFrom-Json
$report.adjudicated_per_planned_case
$report.coverage.cases | Select-Object case_id, declared_truth, publisher_truth, truth_reason
```

The verifier checks the exact initial root bytes against the independent pin
and verifies its own signature threshold. Every successor must increment the
version by one and meet both its predecessor's root signature threshold and
its own. Expired intermediate roots can still establish signature continuity.
The terminal root and all three release roles must be unexpired at the
selected instant. The timestamp binds the snapshot version and the snapshot
binds the targets version. Any supplied length and SHA-256 or SHA-512 digests
must also match. The report records the actual link fields and the number of
valid key IDs for each role. A version-only link remains visible. For a root
history, `root_rotation` records the starting version, the presented and
verified update counts, and the version and raw SHA-256 of the last root whose
signatures passed. The reference's top-level `status` records whether the
root and release metadata passed. The optional `--minimum-root-version`
applies to all three envelope versions and accepts decimal integers from 1
through 2⁶³−1. To check for rollback across runs, supply the observation
checkpoint described below. Discovering newer revisions and proving
historical publication require independent evidence.
[TUF root update rules](https://theupdateframework.github.io/specification/latest/#update-root)

For v3, read the individual case's `delegation_search` as well. The reader
checks the exact target path in signed order, starting at the top-level role.
It follows matching path patterns, path hash prefixes and succinct hash bins.
A terminating delegation cuts off later alternatives. A missing, invalid or
expired role on the search path suspends that lookup. Other target paths in
the same release can still resolve. The indices in `role_check_indices`
refer to the reference's zero-based `delegated_role_checks` list. Each entry
identifies the parent, child and result. Available evidence includes the raw
metadata digest, snapshot link, role version, signature threshold and expiry.
The lookup accepts 32 retained delegated roles and visits up to 32 per target.
Each role may declare up to 32 explicit children and 256 path selectors in
total. Role names may occupy up to 128 UTF-8 bytes.
[TUF target lookup](https://theupdateframework.github.io/specification/latest/#update-targets)

A positive file matches the signed length and every signed digest. A complete
file that differs is negative. The digest-only comparison returns unknown for
missing originals, unsupported digests, incomplete acquisition scopes and unlisted targets.
The acquisition size and hole map come from the registered case. The
publisher authenticates the target descriptor. Each decoded role and each
hole map may occupy up to 1 MiB. The reference envelope may occupy up to
8 MiB.

`kn.benchmark_publisher_report.v1` keeps every planned case, its registered
truth and imported outcome. A report that processes a v3 reference uses
`kn.benchmark_publisher_report.v2` and includes its target lookups. The
scoped and per-family metrics use the publisher-derived truths and
assessments backed by retained originals.
A missing assessment for a known positive stays in end-to-end recall. The
compact JSON report has a 32 MiB limit and escapes non-ASCII target names.
Exit 0 returns the report, including partial file observations. Exit 1
returns a report with a rejected reference or an incomplete delegation
search caused by missing or invalid metadata or the search bound. Exit 2
indicates invalid arguments, a missing verifier dependency, an archive
integrity failure or an I/O failure. The ordinary replay command continues
to score the submitted labels. [Sigstore file study](VALIDATION.md#publisher-file-comparisons-on-2026-11-24)

## Check a publisher update against a previous observation

Start with a separately trusted root digest and a v1, v2 or v3 reference.
Set `$python` to the interpreter with the publisher dependencies, `$firstReference`
to that file, `$firstTime` to its UTC observation time and `$firstHistory` to
a new private filename ending in `.knpubhistory`. This first observation
establishes the starting point for subsequent comparisons.

```powershell
$issued = & $python -B tools/advance-publisher-reference.py --reference $firstReference --trusted-root-sha256 $anchor --verification-time $firstTime --out $firstHistory
if ($LASTEXITCODE -ne 0) { throw 'First publisher observation failed' }
$firstCheckpoint = ($issued | ConvertFrom-Json).checkpoint_sha256
```

Record `$firstCheckpoint` independently of the distribution. For the next
observation, retrieve that digest as `$previousCheckpointSha256` and the
corresponding history file as `$previousHistory`. Set `$newReference` and
`$verificationTime` to the new release and observation time, and choose a
new output filename for `$publisherReference`.

```powershell
$issued = & $python -B tools/advance-publisher-reference.py --reference $newReference --trusted-root-sha256 $anchor --verification-time $verificationTime --previous $previousHistory --previous-checkpoint-sha256 $previousCheckpointSha256 --out $publisherReference
if ($LASTEXITCODE -ne 0) { throw 'Publisher update failed' }
$observation = $issued | ConvertFrom-Json
$observation.publisher_proof.publisher_history.transition
$nextCheckpoint = $observation.checkpoint_sha256
```

Use `$publisherReference` as the registered truth reference or the input to
image approval. Pass the **previous** checkpoint and the same UTC instant to
`evaluate-corpus.py` or `provision-image-approval.py`. Keep `$nextCheckpoint`
for the following update. Use the separate `publisher_reference_sha256` when
pinning the entire history file. Exit 1 from the issuing command returns a
rejected proof. Exit 2 reports an input, destination or delivery error. To
reproduce a receipt after losing the original inputs or stdout, use the
retained file and the same independently recorded trust inputs.

```powershell
$replayed = & $python -B tools/advance-publisher-reference.py --verify-history $publisherReference --trusted-root-sha256 $anchor --verification-time $verificationTime --previous-checkpoint-sha256 $previousCheckpointSha256
if ($LASTEXITCODE -ne 0) { throw 'Publisher history verification failed' }
($replayed | ConvertFrom-Json).checkpoint_sha256
```

The history file contains the exact previous and current references, each
bounded at 8 MiB. Its 48-byte header starts with the eight ASCII bytes
`KNPUBHS1`, followed by the previous and current time/length pairs.
Each pair holds a 16-byte ASCII UTC instant and a little-endian 32-bit byte
count. The first observation uses zero bytes throughout the previous pair.
The two unmodified references follow in the same order. The checkpoint
is SHA-256 over the ASCII string `kn.publisher.observation.v1`, one zero
byte, the 32-byte initial root digest, the 16-byte observation time and the
32-byte SHA-256 of that observation's exact reference.
The verifier rechecks the previous release at its recorded time, checks the
current release at the caller's time and requires time to move forward or
remain equal. Every update uses the same original root anchor and extends
the previously authenticated root history.

The signed timestamp, snapshot and targets versions may increase or stay
equal. Equal versions must retain the same signed content. Every name in
the previous signed snapshot must remain present at the same or a higher
version, including delegated roles outside the selected target's path.
For supplied delegated files the verifier also checks the snapshot link
and a chain of parent signatures. A role retained in both observations at
the same version must have the same signed content. A version-only link
leaves unobserved delegated bytes unspecified. Target lookup still checks
path, priority and expiry. An unchanged root history and signed timestamp
produce the transition `unchanged`.
[TUF timestamp checks](https://theupdateframework.github.io/specification/latest/#update-timestamp)
[TUF snapshot checks](https://theupdateframework.github.io/specification/latest/#update-snapshot)

A verified successor root can recover from an inflated online version. The
offline verifier resets the timestamp and snapshot floors when that root
withdraws a previous timestamp or snapshot signer's public key and the
previous signatures no longer meet the new quorum. Its proof records the
affected roles under `online_key_recovery`. Changing only key identifiers or
thresholds preserves the floors. Recovery compares decoded Ed25519 or
PEM public keys. An unrecognized representation preserves the floors.
All current signatures, links and expiry
checks still apply. [TUF root recovery](https://theupdateframework.github.io/specification/latest/#update-root)

The v3 publisher report records the observation and its transition. A required
predecessor pin rejects a bare JSON reference, a first observation or a
different predecessor. Keep the latest accepted pin in a trusted record.
Concurrent updates from the same predecessor can produce separate valid
observations. The operator selects which one to carry forward.

## Compare observed file ranges

A difference at one observed offset disproves whole-file equality even when
other bytes are missing. To make that comparison, retain the full publisher
file alongside the capture. The evaluator checks its length and every signed
SHA-256 or SHA-512 digest under the selected TUF target name. The same root,
delegation and predecessor checks used for complete files apply here.
[TUF target verification](https://theupdateframework.github.io/specification/latest/#fetch-target)

Use `kn.benchmark_corpus.v2` for the plan. Set `$capture` to the candidate
file, `$holeMap` to its v1 target scope, `$publisherMetadata` to the signed
metadata reference and `$publisherFile` to a separately obtained complete
copy of that target. The target scope's `file_bytes` is the logical length
of the file. Its missing intervals use original file offsets.

```powershell
$case = [ordered]@{
    id = 'file-range'
    family = 'saved-file'
    independence_group = 'one-acquisition'
    partition = 'development'
    layer = 'independent_comparison'
    task = 'publisher-target-bytes-match'
    unit = 'case'
    truth = 'unknown'
    artifact_sha256 = (Get-FileHash -LiteralPath $capture -Algorithm SHA256).Hash.ToLowerInvariant()
    holes_sha256 = (Get-FileHash -LiteralPath $holeMap -Algorithm SHA256).Hash.ToLowerInvariant()
    truth_ref_sha256 = (Get-FileHash -LiteralPath $publisherMetadata -Algorithm SHA256).Hash.ToLowerInvariant()
    publisher_file_sha256 = (Get-FileHash -LiteralPath $publisherFile -Algorithm SHA256).Hash.ToLowerInvariant()
    artifact_layout = 'packed'
}
```

With `packed`, the capture contains the observed bytes in ascending file
offset order, with every missing interval omitted. With `file_offsets`, the
capture has the full logical length. Bytes at missing offsets contribute
to its archive digest and are excluded from the comparison. Both layouts
require the exact declared size for that representation. Register `$case`
before producing results and include all four originals in the retention
file list. A reference file or capture reused across cases stays in one
development or heldout partition.

Replay the retained package with its independently saved package and plan
digests. Use the UTC observation time for the signed metadata. Set
`$previousCheckpointSha256` to the independently saved predecessor for a
publisher update, or to `$null` for a single release or first observation.

```powershell
$trust = @('--trusted-root-sha256', $anchor, '--verification-time', $verificationTime)
if ($previousCheckpointSha256) { $trust += @('--previous-checkpoint-sha256', $previousCheckpointSha256) }
$json = & $python -B tools/evaluate-corpus.py --archive-corpus $archive --sha256 $pin --plan-sha256 $plan @trust
if ($LASTEXITCODE -eq 2) { throw 'Range evaluation failed' }
$report = $json | ConvertFrom-Json
$report.coverage.cases | Select-Object case_id, publisher_truth, truth_reason, file_range_comparison
$report.range_replay
```

The v4 publisher report separates the registered scope's observed and missing
byte counts from the stored capture size and the bytes actually compared.
Missing capture bytes or rejected metadata leave the registered scope visible.
A missing scope leaves its counts null. A verified comparison gives the
number of differing bytes and the first differing logical offset. An observed difference
yields negative truth. A complete match yields positive truth, including a
verified empty file. If every observed byte agrees and any bytes are missing,
whole-file equality remains unknown. A missing reference, a layout or scope
length mismatch, and an exhausted comparison budget also leave truth unknown.
A reference that contradicts the signed descriptor returns exit 1 and
withholds all difference counts. Changed archive bytes return exit 2.

The publisher authenticates its reference file. For a partial capture,
placing a differing byte in the candidate file relies on the registered
offsets. Those cases count toward the adjudicated total and
`cases_decided_from_partial_captures`. If any verdict depends on such a map,
`ground_truth_authenticated` stays false even when every case has a verdict.

The budget covers 16 GiB of range-comparison reads per replay. Each distinct
comparison charges the size of both stored members before reading them.
Repeated cases can reuse a verified result for the same capture, hole map,
layout, publisher file and signed hashes. The report counts reuse and cases
deferred by the budget. Acquisition provenance and the contents of missing
intervals require other evidence. [Public-file validation](VALIDATION.md#partial-publisher-file-comparisons)

## Record the file offsets Windows actually read

On Windows, `tools/capture-file-ranges.py` reads an ordinary file on a fixed
local volume and signs the results of the individual calls. Use the Python
environment from the publisher verification procedure. Before collection,
the verifier records the case ID, a fresh 32-byte challenge, and the SHA-256
of the trusted controller's 32 raw Ed25519 public-key bytes. Only the
controller needs the private key. It reads an access-controlled Ed25519 PEM
key from `$controllerKey`. Keep the verifier's key pin and challenge independently
of the capture. [Ed25519 key and signature formats](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/)

Set `$candidate` to the local source, `$targetName` to the case-sensitive
publisher target, `$caseId` to the case being registered and `$captureDir`
to a new directory under a private, existing parent. The example asks for
32 bytes at offset zero and 64 at offset 64. Specify 1 through 2,048 ordered,
disjoint ranges. Each request can read up to 1 MiB within the 8 GiB addressable
file extent. Requests may extend past the file's own end.

```powershell
$random = [Security.Cryptography.RandomNumberGenerator]::Create()
$challenge = New-Object byte[] 32
try { $random.GetBytes($challenge) } finally { $random.Dispose() }
$captureNonce = [BitConverter]::ToString($challenge).Replace('-', '').ToLowerInvariant()
$captureJson = & $python -B tools/capture-file-ranges.py --source $candidate --signing-key $controllerKey `
    --case-id $caseId --target-path $targetName --capture-nonce $captureNonce --output $captureDir `
    --range '0+32' --range '64+64'
if ($LASTEXITCODE -ne 0) { throw 'File acquisition failed' }
$captureResult = $captureJson | ConvertFrom-Json
if ($captureResult.collector_key_sha256 -cne $collectorKeySha256) { throw 'Unexpected acquisition key' }
$capture = Join-Path $captureDir 'capture.knblob'
$holeMap = Join-Path $captureDir 'scope.knreads'
```

The collector keeps the source handle open, denies ordinary write and delete
sharing, and checks its size, volume serial, 128-bit file ID and opened name
before and after the reads. It hashes the UTF-16LE volume-GUID path returned by
the handle. The receipt contains the hash, the chosen target name and the local
acquisition start time. Each request records its original offset, requested
and transferred lengths, relative monotonic times and Win32 status. A failed
seek records the seek error. A short read contributes only the returned bytes.
The packed file and receipt appear together when the new directory is renamed
into place. An existing destination causes the command to fail.
[Windows file identity](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info)
[Opened name](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew)
[ReadFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile)

Use these two files in the v2 packed case above, with `id` set to `$caseId`.
Include them in the archive's original file list alongside the complete publisher
file and metadata. To require acquisition evidence on replay, add the verifier's
key pin and challenge to the publisher options. Use the signed metadata's
verification time for `$trust`.

```powershell
$readPolicy = @('--collector-key-sha256', $collectorKeySha256, '--capture-nonce', $captureNonce)
$json = & $python -B tools/evaluate-corpus.py --archive-corpus $archive --sha256 $pin --plan-sha256 $plan @trust @readPolicy
if ($LASTEXITCODE -eq 2) { throw 'Could not replay the retained acquisition' }
$report = $json | ConvertFrom-Json
$report.coverage.cases | Select-Object case_id, publisher_truth, truth_reason, read_acquisition
$report.authenticated_scopes_per_planned_case
```

The v5 report derives missing intervals from successful transfers and checks
the signed packed digest against the retained bytes. An unsigned map, wrong
key or challenge, altered signature, or receipt for another case withholds the
file verdict and returns exit 1 under this policy. Missing captured bytes
remain unknown. A signed receipt also requires an explicit trust policy on
replay. The legacy unsigned procedure continues to produce its v4 report.

The acquisition count includes a verified receipt for a read that returned
zero bytes. Whole-file truth still requires a complete match or a difference
in observed bytes. The signature attests to the trusted controller's reads of
one file handle. An association with a running image, an independent OS trace
and a simultaneous snapshot of all file bytes require separate evidence.
[Windows validation](VALIDATION.md#signed-windows-file-read-receipts)

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
