# Validation status

The released baseline is **v0.0.36 / 6646461**. Development verification of the
retained investigation path and subsequent reference/TI queue fixes was recorded
on **2026-10-29**, through **e73932d**, separately from the **2026-10-25** release
validation. Each section identifies its binary and test scope. Documentation
updates do not renew these observations. Follow the
[manual checklist](MANUAL_TEST_CHECKLIST.md) to validate another binary or host.

## Image archive input retention on 2026-11-23

The preceding x64 Release CLI (`39a54b6df4d2`) planned deletion of the PE
from a loose direct capture and from a loose sweep. In the disposable sweep
store, offline replay succeeded before GC. After GC deleted the PE, replay
reported `sweep_reference_or_schedule_mismatch` although both read archives,
both slice recipes and the sweep manifest were still present.

The updated size-optimized x64 Release CLI (`924a715fd2a7`) denied the same
deletion before creating an intent. The bare and claim-wrapped sweeps still
replayed. The dependency tests derived expected paths and hashes from original
producer files, then compared them to every referring row in the native
inventory. Cases included a producer-declared missing raw, a missing shared
PE, a resealed read with an incorrect PE length, an unreadable publication,
a sweep under the wrong collection name, and loose roots over committed
children. A sweep published after a durable deletion intent also protected
the selected read on retry. The suite passed 128 product checks and 108
harness checks. [Image dependency controls](../tools/test-image-archive-dependencies.py)

Commit and recovery controls omitted or added a sweep dependency, changed
the original payload digest in a resealed sweep and substituted a separately
hashed PE in a direct capture transaction. Recovery stopped at the preceding
verified segment in each case. The previous and updated journal writers each
published bare, wrapped and raw-loss sweeps that the other product recovered
as four-segment closed collections. Both products replayed the complete
bare and wrapped examples. [Journal controls](../tools/test-evidence-journal.py) ·
[Direct capture controls](../tools/test-image-capture-journal.py)

The native journal checks passed 74 cases. The independent journal, store, GC
and IRP suites passed 2,152, 476, 892 and 400 checks respectively. The
product console suite passed 570 checks, including the mixed image/IRP
writer. Verification used offline user-mode tools and disposable stores.
Loose IRP dependencies, committed-root retirement, large-store continuation
and recovery from physical media loss remain open.

## Approval input retention on 2026-11-23

At `6dba4df`, the x64 offline product accepted a GC preflight for all four
inputs of a loose direct approval and all eight physical inputs of a loose
sweep approval. In a separate copy of a closed direct journal, the approval
named a different capture digest. After resealing the publication and journal
segments, recovery still accepted both segments. These controls used copies
of locally generated archive fixtures.

The regression oracle takes two archived approvals with a shared reference.
It checks the input hashes against the original files, the referring root
hashes against the detailed inventory, and the native GC result against the
files and receipts left on disk. It also stops a native GC process after its
durable intent, publishes a referring approval, and retries the same operation.
The direct journal controls substitute each of the four declared inputs
individually. Historical assessment reproduction is tested through the
separate replay command. [Retention oracle](../tools/approval_retention_oracle.py) ·
[Direct journal tests](../tools/test-image-approval-journal.py) ·
[Scoped journal tests](../tools/test-image-scope-approval-journal.py)

The size-optimized x64 Release CLI (`39a54b6df4d2`) passed 683 direct and
1,804 scoped approval checks. The corresponding harness runs passed 669 and
1,793 checks. The scoped suites exercised 11 interruption points. In the
loose-store controls the preflight and apply paths both denied removal of the
four direct inputs and eight sweep inputs. The shared reference survived
withdrawal of one approval and an interrupted deletion retry. The detached
referrer export controls ran in the 39-test public-content suite.

Both the previous and updated product recovered two journal segments and
reproduced the recorded assessment from direct and scoped archives written by
the other version. The native journal harness passed 71 checks. The independent
journal, store, GC and IRP journal suites passed 1,952, 476, 892 and 400 checks
respectively, including nine interrupted GC cases.

The validation covers offline user-mode publication, journal recovery and GC
in disposable local stores. Cross-family dependency resolution, retirement of
committed roots and media power-loss recovery remain open.

## Hard faults and reads during marked waits on 2026-11-23

The public TaskbarLatency recording (`8a59fa63479e`, 10 MHz QPC) had 17
decoded hard faults. Six intersected disk reads in four tested marker
windows. The existing x64 reader (`2bda0417bff9`) and the packaged TDH
helper (`f5b02c59112d`) agreed on their original record numbers, faulting
threads, timestamps, offsets and byte counts. An independent source
reader decoded the fault payloads and replayed the switches and ReadyThread
events to calculate the intersections. [Source recording](#readythread-cpu-context-on-2026-11-22) · [Regression test](../tools/test-etl-fault-io.py)

| Marker records | Hard-fault records | Disk rows | Disk object and byte count | Fault and logical file range | Disk overlap while waiting before ready (ms) |
| --- | --- | --- | --- | --- | ---: |
| 339732, 374019 | 373241, 373299 | 42, 46 | Both differ | Disjoint | 0.8752 |
| 397312, 398477 | 398309, 398375 | 52, 53 | Both match | Equal | 3.8512 |
| 418372, 418976 | 418389 | 55 | Both match | Equal | 3.9345 |
| 451991, 452304 | 452145 | 56 | Both differ | Disjoint | 3.8509 |

All six reads fit inside their respective fault intervals. Of 13.7015 ms
of observed fault time across the four windows, 0.9834 ms fell outside
the marked thread's pending disk reads. The three disk
reads with matching fields overlapped the faults for 7.8750 ms in total,
including 7.7857 ms waiting before ready. The logical file reads reported
different file-object values from the faults in all six cases. A separate
marker window returned zero faults and zero disk reads. An intervening
marker withheld the measurement. The wait object and the effect on
application latency remain open.

On the two PerfView samples the TDH helper reproduced the recorded
thread, QPC endpoints, offset, byte count and pointer width for 394 and
153 faults respectively. Both selected marker windows lacked switch
records. Each retained its independently measured zero-fault window and
reported scheduler overlap as unavailable.

The v4 file report reproduced its previous SHA-256 using its original
adapter. With that older helper, requesting the new comparison preserved
the independently measured disk and file results. [File operation validation](#file-operations-enclosing-disk-requests-on-2026-11-23) · [Fault and I/O query](TRACE_IMPORT.md#hard-faults-and-reads-during-a-thread-activity)

## File operations enclosing disk requests on 2026-11-23

The x64 Release reader (`2bda0417bff9`), TraceProcessor Disk 1.12.10
and the packaged Windows TDH reader (`c167e60858fc`) processed the public TaskbarLatency ETL
(`8a59fa63479e`, 1,093,447 records, 10 MHz QPC). The SDK returned 229,701
file reads, 132 writes and seven flushes. In four marked windows, six file
reads enclosed six disk reads on the issuing thread. The independent TDH
test reader scanned the surrounding records, paired their packet values
within each layer and reproduced all four endpoint times for each pair.
[Source recording](#readythread-cpu-context-on-2026-11-22) · [Regression test](../tools/test-etl-file-operations.py)

| File read row | Disk row | File start → disk init → disk completion → file end (source ordinals) | Requested and completed bytes | Before / after disk (QPC ticks) |
| ---: | ---: | --- | ---: | ---: |
| 114825 | 42 | 373168 → 373169 → 373206 → 373213 | 12,288 | 89 / 238 |
| 114826 | 46 | 373244 → 373246 → 373269 → 373280 | 12,288 | 59 / 182 |
| 114827 | 52 | 397441 → 397446 → 398296 → 398307 | 16,384 | 127 / 235 |
| 114828 | 53 | 398318 → 398322 → 398368 → 398374 | 16,384 | 88 / 182 |
| 114829 | 55 | 418377 → 418378 → 418382 → 418388 | 16,384 | 181 / 344 |
| 114851 | 56 | 452060 → 452067 → 452126 → 452134 | 12,288 | 330 / 866 |

All six file reads completed with NTSTATUS zero. TDH returned `IoFlags`
of `0x60143` or `0x60043`. The SDK reported `0x143` or `0x43`.
Both representations set the paging and synchronous-paging bits.
Every cross-layer packet comparison and file-object comparison returned
`different`. The recording establishes the time ordering on the issuing
thread. The backing file, wait object and critical-path effect remain open.

Separate component queries on the same source reproduced a file write
enclosing two disk writes, two file writes enclosing one disk write, one
enclosing flush and a disk flush with no qualifying file row. The marked
query also exercised a measured zero, an intervening-marker rejection,
two-row pagination, combined CPU and disk options and digest replay.
For the first window, replay with the scripts at `137539d1` and the current
scripts produced byte-identical v1, v2 and v3 reports. The v3 check used
the 52-member disk package rebuilt from that earlier revision.
Synthetic histories exercised packet reuse across loggers and an
outstanding operation followed by an opaque record and a single completion.
[Packet history tests](../tools/test-etl-file-generations.ps1) · [File I/O query and bounds](TRACE_IMPORT.md#file-operations-enclosing-disk-requests)

## Disk requests during marked thread waits on 2026-11-23

The x64 Release reader (`2bda0417bff9`) and the disk adapter
(`f39772040c3d`, TraceProcessor Disk 1.12.10, Toolkit 1.11.0)
processed ten qualified marker windows in the public TaskbarLatency ETL
(`8a59fa63479e`, Windows `10.0.28000`, 10 MHz QPC). An independent
Windows TDH reader paired the original DiskIo records by the named
packet and issuing-thread fields. Its context switches and ReadyThread
records reproduced every reported request intersection and completion-to-ready
gap. Four windows had pending reads from the marked thread. The six
other windows returned a measured zero.
[Source recording](#readythread-cpu-context-on-2026-11-22) · [TDH and replay checks](../tools/test-etl-disk-waits.py)

| Start and Stop records | Reads | Pending (ms) | Pending while waiting before ready (ms) | Pending on CPU (ms) | Completion to ReadyThread (µs) |
| --- | ---: | ---: | ---: | ---: | ---: |
| 339732, 374019 | 2 | 0.9082 | 0.8752 | 0.0330 | 2.0, 1.7 |
| 397312, 398477 | 2 | 3.9082 | 3.8512 | 0.0570 | 3.2, 1.7 |
| 418372, 418976 | 1 | 3.9668 | 3.9345 | 0.0323 | 4.3 |
| 451991, 452304 | 1 | 3.9349 | 3.8509 | 0.0840 | 9.0 |

Across the recording, 241 disk events referenced 23 distinct packet
values. Some values served multiple issuers. All 120 SDK activities
matched TDH endpoint pairs across 19 issuing TIDs (17 reads, 95 writes
and eight flushes). Of these, 102
pairs also fell inside recorded issuer lifetimes. The remaining 18
completed after the issuer's final rundown record. The last write
initiation in the trace had no completion. Neither case supplied a
qualified request duration for the marked thread. A component check
clipped two concurrent requests inside their common interval and
counted that time once.

For the first read in the table, the two endpoint timestamps were 5,635
ticks apart and the storage stack reported 5,632 response ticks. The
report preserves both observations. The six short completion-to-ready
gaps establish ordering on this recording. The wait object and the
contribution to the application's critical path remain unknown.

Replay matched the v3 report digest. The disk result was identical in
two additional runs, one with two-interval paging and one with both
CPU and interrupt queries enabled. An intervening activity boundary,
recorded loss and a non-QPC clock each withheld the measurement. Native-only v1, CPU
v1 and interrupt v2 reports for the first window were byte-identical
to those from `b6a4eee`. [Measurement and replay](COMMAND_REFERENCE.md#measure-disk-requests-during-a-thread-activity)

## Interrupt overlap during thread residency on 2026-11-23

The x64 Release reader (SHA-256 prefix `2bda0417bff9`) and the CPU
adapter (`17d84e2325d4`, Microsoft TraceProcessor 1.12.10, Toolkit 1.11.0)
processed seven marked activities in the public TaskbarLatency ETL
(SHA-256 prefix `8a59fa63479e`) on Windows `10.0.28000`. A separate
Windows TDH reader decoded interrupt entry times by property name and
used event headers for completion times
and processor IDs. It reconstructed the target's scheduled intervals
from context switches. Both calculations used the recording's 10 MHz
clock. [Original ETL](#readythread-cpu-context-on-2026-11-22) · [TDH and replay checks](../tools/test-etl-interrupt-overlap.py)

| Start and Stop records | Target residency (ms) | Observed DPC (µs) | Observed ISR (µs) |
| --- | ---: | ---: | ---: |
| 339732, 374019 | 55.3563 | 5.4 | 0 |
| 738283, 741351 | 6.8381 | 16.5 | 2.4 |
| 87669, 105250 | 5.1738 | 0 | 0 |
| 87258, 87264 | 0.0065 | 0 | 0 |
| 811857, 812141 | 3.4110 | 0 | 0 |
| 191828, 247898 | 0.0341 | 0 | 0 |
| 117201, 117281 | 0.1130 | 0 | 0 |

All 92 native CPU slices matched the SDK's full switch endpoints.
The seven queries returned 198 interrupt fragments on selected CPUs
during the marker windows. Eight intersections fell within target
residency. In the third window all 49 fragments fell outside it.
The two positive measurements establish coincidence on the same CPU.
The contribution to end-to-end application latency remains open.

Across the source, TDH counted 3,814 ordinary DPCs, 470 timer DPCs,
2,123 message-signaled ISRs and 288 other ISRs. These counts reproduce
all 6,695 interrupt activities in the SDK. TDH also observed 72
threaded DPCs outside that table. Subtracting nested intervals from
their enclosing handlers yielded 6,804 exclusive fragments. Two
additional windows exercised nested execution in the SDK, but both
contained intervening application markers and produced no activity
overlap estimate. The full-span SDK query retained 2,048 of 6,804
matching fragments. The report calculation withheld totals for that
projection.

Replaying the first report reproduced its hash. Paging the native
reader two intervals at a time preserved the interrupt result. Tests
also covered capture loss, a non-QPC clock, conflicting CPU slices,
overlapping fragments and a missing interrupt family. With the preceding
adapter archive, exact replay of the v1 report passed both with and
without SDK evidence.
[Measurement and replay](COMMAND_REFERENCE.md#measure-interrupt-handling-during-a-thread-activity) · [Microsoft interrupt table](https://learn.microsoft.com/en-us/dotnet/api/microsoft.windows.eventtracing.cputracesourceextensions.useinterrupthandlingdata)

## Independent marker replay of the 2026-11-22 handoff studies

The x64 marker adapter (executable SHA-256 prefix `d88368b82e1e`,
deployment `1f0aa0ec2eee`) read each original ETL on Windows
`10.0.28000` with Microsoft TraceProcessor Events 1.12.10 and Toolkit
1.11.0. Each native record matched one SDK table row. Separate SDK
queries restricted to one task at a time reproduced the coordinates.
The SDK used its own clock metadata for all three phase durations and
the signed candidate-minus-baseline comparisons.
[Replay commands](COMMAND_REFERENCE.md#retain-independent-table-rows-for-a-thread-handoff) · [Independent checks](../tools/test-etl-handoff.py)

| Source | Runs | Paired comparisons | Matched marker rows | Checked phase intervals |
| --- | ---: | ---: | ---: | ---: |
| Scheduling, three Release studies | 40 | 20 | 914 | 120 |
| Scheduling, checked recorder | 4 | 2 | 100 | 12 |
| Earlier v2 join-probe study | 16 | 8 | 224 | 48 |
| Earlier v1 handoff study | 4 | 2 | 40 | 12 |

In one candidate run, original records 4 and 33 bounded the outer
activity. SDK rows 2 and 31 gave 1,910,458 QPC ticks at 10 MHz, or
191.0458 ms. The median paired activity increase across that eight-pair
study was 147.54375 ms. Exact replay reproduced all six enriched reports.
With the adapter omitted, the same inputs reproduced the native reports
of the preceding implementation.

In a rehashed control, one original ETL declared 7,000,003 Hz and its
recorder receipt still declared 10 MHz. Native replay withheld that
arm's timing. The SDK read the changed frequency, retained its matching
headers and computed the paired differences using each arm's own clock.
Another control removed the recorder receipt's usable content while
retaining the ETL. The independent phase durations survived, with native
correspondence unavailable. Removing the ETL itself kept the pair in
the denominator for planned work and withheld that pair's comparison.
Running the documented capture and SDK replay on a fresh four-pair
study checked another 200 marker coordinates and reproduced its report digest.

The public TaskbarLatency recording supplied 7,329 markers for one
activity in a provider table of 56,702 rows. The 128 returned rows
matched the Windows ETW oracle and extended to table row 1,710. A
second public recording returned rows 6 and 8. Duplicate headers,
uncertain clocks, source loss and reversed phase boundaries exercised
the correspondence and timing checks. The Windows ETW oracle covers
handoff payloads. An exact context-switch timeline requires separate
scheduler events. [Public fixture checks](../tools/test-traceprocessor-markers.py)

## Timer signal during a thread join on 2026-11-23

On Windows `10.0.28000`, the owned recorder completed 32 private ETW
captures in 16 preregistered pairs. An independent Windows reader
checked 1,110 original markers, including 211 zero-time timer probes.
The table reports the change in elapsed time for which the timer was
pending **after the caller reached its join**. Each row bounds the
median paired change. All times in the table are milliseconds.

| Worker timer, baseline → candidate | Caller pause | Pairs | Median change in timer pending time |
| --- | ---: | ---: | ---: |
| 2 → 180 | 30 | 4 | +136.48645 to +151.89150 |
| 2 → 20 | 110 | 4 | 0 to 0 |
| 85 → 85 | 0 | 4 | −20.13965 to +32.85670 |
| 0 → 135, checked recorder | 10 | 2 | +89.89130 to +118.07375 |
| 0 → 1000 | 0 | 2 | +959.81380 to +1009.22070 |

All four exposed pairs showed an increase. In the second row both
timers had signaled by caller arrival in every pair. With identical
settings, all four paired ranges included zero. The equal-timer and
checked runs also recorded per-thread dispatch counts and caller wait
chains. Microsoft TraceProcessor independently matched all 352 markers
in the equal-timer runs to table rows.

Release and runtime-checked x64 builds passed with MSVC warnings treated
as errors. Replay rejected a changed signal descriptor in the original
ETL while retaining the arm's join timing. An exhaustive four-tick
model checked ordered set, signal and exit bounds, including simultaneous
events. Replay reproduced the published report bytes from one archived
study of each earlier schema version, v1 through v4. These measurements
describe the instrumented caller and worker.
Exact dispatcher transitions and application-wide latency remain open.
[Reproduce the study](COMMAND_REFERENCE.md#measure-timer-pending-time-at-a-thread-join) · [Independent checks](../tools/etl_handoff_timer_checks.py)

## Scheduling during a thread join on 2026-11-22

On Windows `10.0.28000`, the x64 Release recorder (SHA-256 prefix
`341ef23fd175`) and reader (`2bda0417bff9`) measured 40 runs of the
owned caller and worker. The table gives bounds on the median paired
change in the caller's off-CPU time inside its final Windows wait.
Counts in the two middle columns are baseline / candidate. A direct
sighting is a wait-chain query inside that wait which observed the
caller blocked on the live worker.
[Acquisition and replay](COMMAND_REFERENCE.md#measure-scheduling-during-a-thread-join) · [Assumptions behind the bounds](TRACE_IMPORT.md#scheduler-evidence-at-a-thread-join)

| Worker timers, caller pause (ms) | Pairs | Caller switches per run | Direct sightings / total queries in each arm | Median off-CPU change (ms) |
| --- | ---: | --- | --- | ---: |
| 2 to 180, caller 30 | 8 | 0 / 1 | 0 of 8 / 48 of 59 | +89.75495 to +148.65195 |
| 2 to 20, caller 110 | 8 | 0 / 0 | 0 of 8 / 0 of 8 | 0 |
| 85 to 85, caller 0 | 4 | 1 / 1 | 22 of 27 / 23 of 27 | −37.12035 to +23.56690 |

In the first study all eight pairs showed an increase. In the second,
both workers in every pair had exited before the caller arrived. In the
equal-timer study the range included zero. The inference assumes that
the thread's 32-bit switch count did not make a full turn between its
own reads. Starting a system logger for context-switch and dispatcher
events under this Windows token returned Win32 error 5. Exact switch
times, ready delays and the impact on a product workload remain open.

An independent Windows ETW reader checked all 914 original marker headers
and the scheduling payloads. Microsoft TraceProcessor Events 1.12.10
with Toolkit 1.11.0 matched all 514 scheduling headers to rows in
`IGenericEventDataSource.Events` using the same ETLs, task and thread
filters and raw QPC timestamps. In one candidate ETL, records 14 and 15
for the first wait-chain query matched SDK rows 12 and 13. The generic
activity comparator returned `thread_bracket_unqualified` for both selected
arms because the private session supplied no system thread-lifetime events.
The handoff study uses the recorder's process and worker lifetime evidence.
Independent calculations checked the
paired bounds and exhaustively compared the possible partitions for up
to eight sightings. An MSVC `/RTC1` recorder added four runs with 100
original markers and 60 scheduling table rows. [Independent checks](../tools/etl_handoff_scheduling_checks.py)

Replacing a caller's successful profiling cleanup with Win32 error 5 in
one rehashed ETL preserved the complete wall-time summary and withheld
that pair's scheduling comparison. Replaying the partial report reproduced
its digest. Earlier v1 and v2 archives, signed capture statements, and
the documented four-pair scheduling example also passed. [Archive controls](../tools/test-etl-handoff.py) · [Signed page checks](../tools/test-etl-capture-statement.py)

## Critical path at a joined worker on 2026-11-22

On Windows `10.0.28000`, the x64 Release recorder (SHA-256 prefix
`8505d57164ba`) recorded 44 private ETLs across three paired studies.
Each run emitted 14 activity markers. The Release reader
(`e83dfa97dacf`) and a separate Windows ETW reader agreed on all 616
original headers, including the outcome of each thread-handle probe.
Independent calculations reproduced the signal bounds, the partition of
each complete activity and the paired differences. The table shows
candidate minus baseline in milliseconds. [ETW and interval checks](../tools/test-etl-handoff.py)

| Worker timers, caller pause (ms) | Pairs | Last prerequisite, baseline / candidate | Median activity change | Median change in worker time after caller arrival |
| --- | ---: | --- | ---: | ---: |
| 2 to 80, caller 25 | 8 | caller / worker in all 8 | +53.2925 | +50.4889 to +50.7701 |
| 2 to 18, caller 90 | 8 | caller / caller in all 8 | −2.9512 | 0 |
| 35 to 35, caller 0 | 6 | worker / worker in all 6 | +3.1886 | +2.9466 to +5.1535 |

Starting the measurement immediately before the final Windows wait
excluded both probes. On that basis the median increase in outstanding
worker time in the first study was 50.4881 to 50.7694 ms.
In the second study the worker timer call grew by a median of 16.7615 ms,
but every worker had already terminated before the caller's join marker.
In the identical-settings study the exposed worker time increased in four
pairs and decreased in two. The measurements describe these acquisitions
of one caller and one joined worker. Scheduler residency and latency
effects in a product workload remain open.

The MSVC `/RTC1` recorder added two pairs and 56 independently checked
headers. Three previously retained v1 reports reproduced their digests.
The optional join analysis of an older eight-pair archive used all 160
original markers. Reversing a probe outcome in a rehashed recorder receipt
withheld that arm's comparison against the original ETL. A session-start
failure across 16 launches retained all eight missing pairs and returned
empty timing estimates. Exact replay, publication checks for private
report fragments and the signed capture-statement regression passed.
[Capture and replay](COMMAND_REFERENCE.md#identify-the-last-prerequisite-at-a-thread-join) · [Timing model](TRACE_IMPORT.md#critical-path-at-a-joined-worker)

## Whole-activity wait accounting on 2026-11-22

On Windows `10.0.28000`, the x64 Release reader (SHA-256 prefix
`e83dfa97dacf`) and the CPU adapter (`94d9da091a40`) processed seven
marked activities in the public TaskbarLatency ETL. An independent
Windows TDH reader reconstructed the marker windows, every target
switch interval, each dispatchable ready event and the source CPU
overlap. All six categories of off-CPU time reconciled to the original
switch intervals. The recording used a 10 MHz QPC clock.
[Recording and source counts](#readythread-cpu-context-on-2026-11-22)

| Start and Stop records | Off-CPU intervals | Off CPU (ms) | Waiting before a thread readied the target (ms) | Last source CPU slice overlapping that wait (ms) | Ready to dispatch (ms) |
| --- | ---: | ---: | ---: | ---: | ---: |
| 339732, 374019 | 5 | 60.8586 | 59.8932 | 0.0877 | 0.0865 |
| 738283, 741351 | 68 | 3.8478 | 3.1172 | 1.8480 | 0.7306 |
| 87669, 105250 | 4 | 111.9171 | 2.1420 | 0.3358 | 0.0704 |
| 87258, 87264 | 0 | 0 | 0 | 0 | 0 |
| 811857, 812141 | 2 | 0.2205 | 0.1566 | 0.0688 | 0.0639 |
| 191828, 247898 | 2 | 109.1727 | 109.1602 | 0.0496 | 0.0079 |
| 117201, 117281 | 4 | 0.1935 | 0.0772 | 0.0204 | 0.1119 |

In the first activity, 0.8789 ms of waiting ended in DPC ready events.
In the third, the source thread's lifetime could not be established for
109.7047 ms of pre-ready waiting. The last two activities retained 46
and 43 ticks of unclassified off-CPU time respectively. The last also
had one pre-ready tick on a thread switched out in a non-waiting state.
The source-overlap column is already included in the preceding column.

The locked Microsoft CPU 1.12.10 adapter corroborated 83 ready events
across the 85 off-CPU intervals. Its tables corroborated the target and
source CPU slice for 78 events and the target dispatch for five more.
Original event 369897 matched ReadyThread row 744, ThreadActivity row
11385 and CpuTimeSlices row 2094. The two remaining intervals had no
ready witness. Each SDK batch recorded the original input digest,
filter, loaded processing modules and table row counts. [Microsoft CPU tables](https://www.nuget.org/packages/Microsoft.Windows.EventTracing.Cpu/1.12.10) · [TDH and replay checks](../tools/test-etl-activity-waits.py)

A 137-interval activity required two native pages. Repeating the first
window with a two-interval page size preserved its totals, and exact
report replay passed with the pinned adapter. Capture loss and a
non-QPC clock withheld the activity summary. Signed batch replay,
shared switch endpoints, the 128-selector limit and prior single-event
queries were also exercised. These observations cover the selected
thread in one recording. The delay attributable to an application-wide
critical path remains open. [Command and replay](COMMAND_REFERENCE.md#account-for-waits-across-one-activity)

## ReadyThread CPU context on 2026-11-22

The x64 Release reader (SHA-256 prefix `232bcf3ffd0e`) was checked on
Windows `10.0.28000` against the public TaskbarLatency ETL. The native
reader and a separate Windows TDH reader counted 1,093,447 ETW records,
62,025 context switches, 33,493 ReadyThread events and 5,086 thread
boundaries. Microsoft TraceProcessor CPU 1.12.10 produced 33,491
ReadyThread rows and 62,017 ThreadActivity rows. The comparison joined
events by target TID, CPU and raw QPC timestamp and retained each table's
one-based row number. [Original recording](https://github.com/randomascii/blogstuff/blob/138aae8b20e78183894612a1a7e98e2c8f293b29/TaskbarLatency/2019-09-08_22-34-56%20explorer%20jumplist%20delays.etl) · [Microsoft CPU reader](https://www.nuget.org/packages/Microsoft.Windows.EventTracing.Cpu/1.12.10)

| Original ready records | Observed result |
| --- | --- |
| 369897, 373233, 373294, 738362, 738466 | The source switch pair and lifetime identified five readying contexts. Both Microsoft CPU tables agreed on source PID and TID. The last two events carried the direct-switch attempt flag. |
| 373207, 373271, 88389, 9013, 1065544, 1093290 | All six events carried the DPC flag. At record 88389 the CPU carried a non-idle thread. The first and last parts of the capture also exercised missing switch endpoints. The attributed source PID and TID were null in all six cases. |
| 104979, 105005 | The Microsoft table named a thread whose recorded exit preceded the ready event. TDH found the same exit and no following lifetime boundary. The reader retained target timing and withheld source attribution. |

Ten target waits had qualified timings. Their switch-out and switch-in
timestamps and destination CPU matched the Microsoft ThreadActivity
table. Original record 369897 matched ReadyThread row 744 and
ThreadActivity row 11385. It fell between switches of TID 24036 on CPU 0.
Target TID 39452 spent 598,311 ticks off CPU before the ready event and
resumed on CPU 5 another 84 ticks later, on a 10 MHz clock.
[Record checks](../tools/test-etl-ready-origin.py) · [Query example](COMMAND_REFERENCE.md#find-the-cpu-context-of-a-readythread-event)

Changing the trace clock or introducing reported loss withheld attribution.
Exact page replay and archive-witness signature checks passed for complete
and partial sources. Eleven earlier query pages, their eleven replay
receipts and one signed v4 receipt matched the preceding Release binary
byte for byte. The activity regression covered 157 switch intervals in
three windows. The hard-fault regression checked all 17 original faults.
The execution-trace suite, V8 controls and MSVC `/RTC1` record checks
passed. This validation covers one saved Windows recording and the
named regression fixtures.

To repeat the comparison from an x64 Visual Studio Developer PowerShell,
set `$etl` to the recording above. The test checks its published digest.
Pass `--openssl` with a local OpenSSL executable to include the archive
witness signature checks.

```powershell
New-Item -ItemType Directory -Force .\.build\ready-origin-test | Out-Null
cl /nologo /EHsc /std:c++17 /O2 /W4 /WX tools\etl-hard-fault-oracle.cpp /Fo".\.build\ready-origin-test\oracle.obj" /Fe:".\.build\ready-origin-test\oracle.exe"
MSBuild tools\TraceProcessorReadyTest\TraceProcessorReadyTest.csproj /restore /t:Build /p:Configuration=Release
python -B tools\test-etl-ready-origin.py --exe .\x64\Release\KnLiveDbg.exe --etl $etl --oracle .\.build\ready-origin-test\oracle.exe --sdk .\.build\traceprocessor-ready-test\bin\TraceProcessorReadyTest.exe
```

## Application activity scheduling on 2026-11-22

On Windows `10.0.28000`, the Release x64 reader (SHA-256 prefix
`a09586e448e0`) measured five marked thread activities in the public
TaskbarLatency ETL. A separate Windows ETW/TDH reader checked both
activity headers, the thread lifetime, every original switch endpoint,
the ready records and the clipped durations. The source contained
1,093,447 records, 62,025 context switches and 33,493 ReadyThread events
on a 10 MHz QPC clock. [Recording and source checks](#scheduling-during-hard-page-faults-on-2026-11-22)

| Start and Stop records | Switch intervals | On CPU (ms) | Off CPU (ms) | Observed ready to switch-in (ms) | Off CPU with unclassified readiness (ms) |
| --- | ---: | ---: | ---: | ---: | ---: |
| 339732, 374019 | 11 | 55.3563 | 60.8586 | 0.0865 | 0 |
| 738283, 741351 | 137 | 6.8381 | 3.8478 | 0.0853 | 2.7715 |
| 87258, 87264 | 1 | 0.0065 | 0 | 0 | 0 |
| 87669, 105250 | 9 | 5.1738 | 111.9171 | 0.0649 | 0.2090 |
| 811857, 812141 | 5 | 3.4110 | 0.2205 | 0.0639 | 0 |

On-CPU and off-CPU time added up to the marker duration in every case.
For the 116.2149 ms activity, all five off-CPU intervals had a dispatchable
ready witness. The captured thread spent 60.7721 ms before those events
after switching out in the Waiting state. The 137-interval activity had
68 off-CPU intervals and seven qualified readiness sequences. Replaying
different page sizes preserved both totals and the original interval order.
The two PerfView CPU recordings retained their measured marker durations
and reported unavailable scheduler totals because neither contained context
switches.

Signed archive-witness replay matched the complete source and a controlled
copy declaring loss. Clock, marker, pagination and late scheduler-conflict
controls passed. Seven existing CPU, disk, fault, marker and switch pages
matched the previous reader byte for byte. The regular record suite and the
MSVC `/RTC1` record checks passed. MSVC AddressSanitizer stopped during
runtime interception before the tests, including in a separate minimal
program. These measurements describe the emitting thread. Cross-thread
dependencies and the cause of an application-wide delay remain open.
[TDH checks](../tools/test-etl-activity-schedule.py) · [Query and pagination](COMMAND_REFERENCE.md#measure-scheduling-inside-an-activity)

## Repeated caller and worker timing on 2026-11-22

On Windows `10.0.28000`, the x64 Release recorder (SHA-256 prefix
`aca9ce50443d`) and native reader (`0218aec46253`) measured two
preregistered studies. Each pair ran both conditions with the same seed
and 20,000 iterations per thread. Consecutive pairs alternated which
condition ran first. Each of the 28 runs used a fresh process and a private
ETW session with system profiling privilege disabled. All 28 ETLs had
12 records, two processed buffers, a 10 MHz QPC clock and zero reported
loss. A separate Windows ETW/TDH reader matched all 280 workload markers
by source record and event header. Independent calculations matched both
thread checksums, all seven timing metrics and the paired medians.

| Worker timer, baseline / candidate | Pairs measured / planned | Activity longer / shorter | Median activity change | Median change in overlapping waits |
| --- | ---: | ---: | ---: | ---: |
| 0 / 25 ms | 8 / 8 | 8 / 0 | +26.03035 ms | +25.74765 ms |
| 0 / 0 ms | 6 / 6 | 4 / 2 | +1.18105 ms | −1.10740 ms |

Both median columns use candidate minus baseline within each pair. With
the 25 ms timer, all eight overlap differences were positive. Activity
increased in both orders, with medians of 25.1210 ms for the four
baseline-first pairs and 32.6334 ms for the four candidate-first pairs.
With identical settings, activity differences ranged from −8.3870 to
+13.0328 ms. These observations quantify variation on this host and one
known dependency on the joined worker. Product regression and kernel
scheduler residency remain open.

Two replays per study reproduced the report digest. The MSVC runtime-check
build also completed two pairs and matched 40 original markers. Additional
tests repeated the same plan with fresh activity IDs, rejected mixed
acquisitions, retained a surviving mate when its pair was incomplete and
reported zero measurable pairs after four real process launch failures.
Other controls covered inconsistent waits, image and source identities,
source ordering, loss, concurrent publication and private output detection.
[Integration checks](../tools/test-etl-handoff.py) · [Build, capture and replay](COMMAND_REFERENCE.md#measure-a-caller-waiting-for-a-worker)

## Microsoft TraceProcessor marker rows on 2026-11-22

On Windows `10.0.28000`, the Release x64 adapter built with Visual Studio
2022 MSBuild and locked NuGet packages. The optional comparison read three
ETLs through both the native reader (SHA-256 prefix `0218aec46253`) and
Microsoft TraceProcessor. All six selected endpoint headers agreed on raw
QPC time, descriptor and recorded identities. Table positions below are
one-based within the SDK's provider-filtered result. [PerfView measurements](#activity-duration-across-two-recordings-on-2026-11-22) · [TaskbarLatency source and independent TDH checks](#hard-fault-time-inside-activity-markers-on-2026-11-22)

| Recording | Native Start, Stop records | SDK provider rows | SDK Start, Stop rows |
| --- | --- | ---: | --- |
| PerfView x64 | 135036, 135051 | 8 | 6, 8 |
| PerfView x86 | 122133, 122302 | 8 | 6, 8 |
| TaskbarLatency | 339732, 374019 | 56,702 | 5,413, 7,465 |

The TaskbarLatency provider contained 7,329 activity markers with the
selected activity ID. The process, thread, task and channel selected 902
markers, and two remained in the time interval. Both SDK endpoints matched
even when the native cross-recording comparison reported incompatible
descriptors. Tests also cover ambiguous matches, unknown clocks, reversed
row order, the 128-row limit, a missing source qualification and package
substitution. The SDK check reads generic event headers. The native reader and TDH
supply the separate hard-fault and scheduler evidence. [Integration checks](../tools/test-traceprocessor-markers.py) · [Build and query](COMMAND_REFERENCE.md#check-the-same-markers-with-microsoft-traceprocessor)

## Activity duration across two recordings on 2026-11-22

On Windows `10.0.28000`, the Release x64 reader (SHA-256 prefix
`0218aec46253`) measured one matching marker pair in each of two public
PerfView ETLs. A separate Windows ETW/TDH program read the original
markers, thread boundaries, hard-fault properties and QPC frequency.
Both readers found task 3, channel 0, Start event 8 version 0 and Stop
event 9 version 1 from the same provider. The activity and thread IDs
differed between the files. [Fixture revision and SHA-256 values](#saved-etl-cpu-profile-validation-on-2026-11-22)

| Recording | Start and Stop record | Elapsed | Observed hard-fault overlap |
| --- | --- | ---: | ---: |
| PerfView x64 | 135036, 135051 | 0.3458 ms | 0 ms |
| PerfView x86 | 122133, 122302 | 2.7762 ms | 0 ms |

The selected x86 window took 2.4304 ms longer. Reversing the inputs
reversed the sign. The evidence covers two individual windows. Repeated
equivalent workloads and the cause of the difference remain unverified.

A separate TaskbarLatency window covered 116.2149 ms with 1.2926 ms of
observed hard faults. A controlled copy with a 7,000,003 Hz header tested
conversion between different clock frequencies. TDH and the comparison
agreed on both exact fractions. The checks also covered large signed
timestamps, loss, missing records and sources, a wrong source pin,
incompatible event descriptors, identical input bytes through a hard link,
concurrent publication and replay of complete and limited reports.
Run the check with `--exe`, `--oracle`, `--x64`, `--x86` and `--taskbar`.
[Comparison checks](../tools/test-etl-activity-comparison.py) · [TDH reader build and TaskbarLatency source](#saved-hard-page-fault-timing-on-2026-11-22)

## Hard fault time inside activity markers on 2026-11-22

On Windows `10.0.28000`, the Release x64 reader (SHA-256 prefix
`0218aec46253`) and a separate Windows event reader agreed on all 7,329
keyed activity markers in the TaskbarLatency recording. The eligibility
check excluded another 720 nonclassic Start and Stop headers. The
comparison checked every paged marker's original ordinal,
header identities, descriptor, logger and raw timestamp. Filtering by the
seventh fault's payload thread returned the same 906 markers in both
readers. Windows `tracerpt` counted 1,093,447 records and 17 hard faults.
[Pinned recording](https://github.com/randomascii/blogstuff/blob/138aae8b20e78183894612a1a7e98e2c8f293b29/TaskbarLatency/2019-09-08_22-34-56%20explorer%20jumplist%20delays.etl)

Four same-thread Win32k marker windows contained six fault intersections.
All four unions and two windows with zero observed overlap matched a
separate calculation using Windows event headers and named TDH properties.
For example, original records 339732 and 374019 enclosed 1,162,149 QPC
ticks. Two faults covered 12,926 ticks, or 1.2926 ms at 10 MHz. The trace
establishes overlap on the reported thread. Its effect on user-visible
response time remains unverified.

Tests covered intervening boundaries, wrong keys, invalid or absent
selectors, paging to the end, system-time and CPU-cycle clocks, zero QPC
frequency, declared buffer loss, a hard-linked output and signed replay of
complete and partial pages. Owned record tests covered nested faults,
clipped endpoints, ambiguous IDs, forwarded and legacy event headers, a fault spanning a lifetime boundary,
missing fault-family evidence, 129 candidates and near-maximum clock
values. The regular checks and MSVC `/RTC1` passed. MSVC AddressSanitizer
stopped during runtime interception before its first test. Six older ETL
pages reproduced their original bytes.

Compile the TDH reader as described under saved hard page fault timing.
Pass `--exe`, `--oracle`, `--etl`, the fixture's `--sha256` and
`--check-controls` to the comparison. Supply `--openssl` to include signed
replay. [Activity window and marker checks](../tools/test-etl-activity-window.py) · [CLI examples](COMMAND_REFERENCE.md#measure-hard-faults-during-a-recorded-activity)

## Scheduling during hard page faults on 2026-11-22

On Windows `10.0.28000`, the Release x64 reader (SHA-256 prefix
`eaa1f2102659`) and a separate Windows TDH reader agreed on all 17 hard
faults in the public TaskbarLatency recording (ETL SHA-256 prefix
`8a59fa63479e`). Windows `tracerpt` counted 1,093,447 records and
62,025 context switches. TDH read the scheduler properties by name and
found 33,493 ReadyThread records and 5,086 thread boundary records.
[Pinned recording](https://github.com/randomascii/blogstuff/blob/138aae8b20e78183894612a1a7e98e2c8f293b29/TaskbarLatency/2019-09-08_22-34-56%20explorer%20jumplist%20delays.etl)

The 17 faults named 10 payload thread IDs. Every header named a different
thread from its payload. All selected windows lay inside matching rundown
brackets. The comparison checked the QPC endpoints and original ordinals
of each switch, the recorded CPU and the outgoing state and wait reason.
Across those windows it found 56 on-CPU and 39 off-CPU intervals. Of the
latter, 23 had a dispatchable ReadyThread witness and 16 had no readiness
record. Each pair of residency totals equaled the corresponding fault
duration. Application critical-path impact remains unverified.

Copies with system time, CPU-cycle time, zero QPC frequency or declared
buffer loss withheld the scheduling totals. A trace with faults and no
switches returned `no_switch_records`. Selecting an absent fault retained
the source's full or partial read status. Owned record tests exercised
TID reuse, conflicting processor history, a switch outside the lifetime,
readiness on either side of the clipped window, and 129 intervals at the
128-interval limit. The regular tests and the MSVC `/RTC1` record checks
passed. The MSVC AddressSanitizer build stopped in runtime interception
before the first record test.

Signed archive-witness replay matched both a complete file and a
one-byte-short file with a partial read. Six previously saved pages across
the hard-fault, switch, disk and CPU readers reproduced their original
bytes. Compile the TDH reader as described below and run the comparison
with `--exe`, `--oracle`, `--etl`, `--sha256` and `--check-controls`.
[Comparison and clock controls](../tools/test-etl-fault-schedule.py) · [Windows TDH reader](../tools/etl-hard-fault-oracle.cpp)

## Saved hard page fault timing on 2026-11-22

On Windows `10.0.28000`, the Release x64 reader (SHA-256 prefix
`ed1d81a44e0c`) and a separate Windows TDH reader agreed on every one of
551 recorded hard page faults. TDH resolved all six MOF properties by name
and reconstructed the first payload hash in each positive trace. Windows
`tracerpt` confirmed the record and descriptor counts. All three readers
use Windows ETW. [Hard page fault fields](https://learn.microsoft.com/en-us/windows/win32/etw/pagefault-hardfault)

| Saved ETL | Records seen | Hard faults | Reported read bytes | Longest measured interval in QPC ticks |
| --- | ---: | ---: | ---: | ---: |
| x64 CPU workload | 179,474 | 153 | 2,722,816 | 1,391,582 |
| x86 CPU workload | 168,298 | 394 | 6,873,088 | 1,803,293 |
| Allocator workload | 418,378 | 4 | 28,672 | 2,047 |
| Scheduler workload | 877,318 | 0 | 0 | — |
| Small control | 23 | 0 | 0 | — |
| One rotating file, partial session | 114 | 0 | 0 | — |

All 551 records used 64-bit pointer fields, including those in the x86
workload. The x86 and x64 builds of the TDH reader returned identical
property rows. The payload TID differed from the header TID in every row. The
three positive files used a 10 MHz performance counter. Pages retained the
first longest fault and its original ordinal across pagination. None of
these captures establishes that the fault delayed a particular application task.

Copies of the x64 workload with system-time or CPU-cycle clocks or zero QPC
frequency preserved the fault and byte counts and withheld every duration.
A copy declaring two lost buffers returned `partial` and retained the
available timings. Owned record tests covered both pointer widths, short
and overlong layouts, equal and reversed timestamps, ties, and byte sums
above 4 GiB. The MSVC AddressSanitizer executable compiled but stopped in
runtime interception before the first test. The regular record tests passed.

The page and capability probe checks used the original file pins. Signed
page replay, partial coverage, hard-link output protection, a sharing
violation and a directory junction were checked separately. A missing file
or parent directory produced the same Windows error in a pipe and a file.
Four earlier CPU, scheduling and disk pages reproduced their prior bytes.
[TDH reader](../tools/etl-hard-fault-oracle.cpp) · [Page and clock checks](../tools/test-etl-hard-faults.py)

To repeat the comparison, compile the TDH reader in a scratch directory
from an MSVC Native Tools prompt with `cl /EHsc /std:c++17 /W4 /WX`
and the path to `tools/etl-hard-fault-oracle.cpp`. Run
`tools/test-etl-hard-faults.py` with `--exe` for KnLiveDbg,
`--oracle` for the compiled test reader, and the ETL's `--etl` path and
`--sha256` pin. Add `--partial` for a rotating member or
`--check-header-controls` for a complete QPC recording containing timed faults.

## Signed ETL rotation inventory on 2026-11-22

On Windows `10.0.28000`, the Release x64 reader (SHA-256 prefix
`c4431364362e`) verified an OpenSSL-signed three-member inventory in signed order when given the paths in order 3, 1,
2. It matched Windows `tracerpt` on 114, 179,474 and 23 records in the
respective files. The first was the public KrabsETW recording. The other
two were copies of saved traces with the rotation header flag set. This
was a test grouping of existing files. The signer supplied the shared
session ID, final ordinal and loss counters. [Public KrabsETW trace](https://github.com/microsoft/krabsetw/blob/43864e67d592779f05cd982b637ca660923e0e09/examples/NativeExamples/powershell.etl)

An archive signature verified order with an unknown end. A failed
controller stop retained Win32 error 5. The reader reported missing
identities, unsupplied positions, a missing directory, substituted bytes,
an unexpected input and a sequential file. It rejected a cross-role
signature, a single-file statement type, repeated identities and a
tampered signature. While a report was blocked on a pipe, Windows rejected
writable opens of the verified member and signed inventory with sharing
violation 32. Both writable opens succeeded after publication. A redirected
report preserved the missing member and its original Windows open error.

MSVC built the owned recorder with warnings as errors. Its in-process
single-file controller test passed. Starting a named three-file rotation
returned Win32 error 5 from
`StartTraceW` on this host. A live three-member capture with independently
counted provider markers and controller stop statistics remains unverified.
[Signed inventory checks](../tools/test-etl-rotation-set.py)

## Rotating ETL member read on 2026-11-22

On Windows `10.0.28000`, the Release x64 user reader and system `tracerpt`
each read 114 records and 26 buffers from the 212,992-byte KrabsETW
`powershell.etl`. Both counted zero CPU samples, context switches and disk
I/O descriptors in the supported layouts. The header mode was `0x9`.
All three KnLiveDbg pages reported `partial`. The new development
comparison retained both readers and three `coverage_limited` verdicts,
with zero comparable families. Replaying the earlier eight-slot study and
ten-slot cohort reproduced their archived report bytes, including the
original heldout result of 0/9 planned and 0/0 comparable families.
[Microsoft KrabsETW fixture](https://github.com/microsoft/krabsetw/blob/43864e67d592779f05cd982b637ca660923e0e09/examples/NativeExamples/powershell.etl)

Two additional controls used copies of recorded traces with the rotation
flag set in the header. KnLiveDbg and `tracerpt` counted 79,528 CPU samples
and 2,462 disk records in the first. In the second they counted 18,556 CPU
samples, 168,474 context switches and 2,307 disk records. The scheduler
page retained its switch records and withheld elapsed intervals.
The member tests covered unrelated numbered neighbors, a literal `%d`
filename, a missing file, a substituted file, page replay and normalized
import. Import rejected a rotating CPU page relabeled `read`.

An attempt to capture a new three-file recording on this host stopped at
`StartTraceW` with Win32 error 5. This run establishes per-file reading.
A controller-confirmed file sequence and session closure still need
independent evidence. [Saved ETL reader](TRACE_IMPORT.md#saved-windows-cpu-samples)

## Partitioned ETL reader study on 2026-11-22

On Windows `10.0.28000`, a corpus registered seven source hashes in two
partitions. Before either reader examined the heldout file, the plan fixed
the corpus hash, both reader hashes, eight ordered slots and three event
families. The native x64 Release reader was built from `ab0d56e`. The
descriptor comparison code matched `c0473ac`.

The development partition selected four of six eligible cases. The two CPU
workloads (x64 and x86) shared one group. The control, its repeat and its
one-byte-short variant shared another. Allocator and scheduler remained in
the corpus as unselected cases. The heldout partition used the 212,992-byte
PowerShell example from Microsoft KrabsETW at revision `43864e6`. Its file
SHA-256 was `da682ce23ce8afe3d81e5a773d2f77ddfd3525e23a3a09178be02f4b29c48051`.
[Microsoft KrabsETW input at the tested revision](https://github.com/microsoft/krabsetw/blob/43864e67d592779f05cd982b637ca660923e0e09/examples/NativeExamples/powershell.etl)

| Partition | Planned slots | Declared groups in those slots | Observed / planned readers | Agreed / planned families | Agreed / comparable families | Fully agreed / planned groups |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Development | 5 | 2 | 10/10 | 12/15 | 12/12 | 1/2 |
| Heldout | 3 | 1 | 1/6 | 0/9 | 0/0, unavailable | 0/1 |

For the first heldout slot, Windows `tracerpt` reported 114 records in 26
buffers and zero matching descriptors for the three families. KnLiveDbg
opened the same file and returned `segmented_source` with exit 1. A separate
Windows SDK `OpenTraceW` check read log mode `0x00000009` and 26 declared
buffers. The rotating-file flag was set on the heldout file and clear on
the development control. That reader rejected the file pending segment
provenance. All three comparisons retained `reader_unavailable`.
For the second slot the harness deliberately supplied the development
control. Acquisition kept both hashes and replay identified the supplied
source as development. The third slot remained unissued.
[Single-file ETL acquisition](TRACE_IMPORT.md#saved-windows-cpu-samples)

Registration rejected partition leakage through an unselected case. Replay
kept a mismatched pair from an earlier plan outside the new study's score.
Regression tests also
checked zero denominators, disagreements on a repeat, an 8 MiB corpus with
32 damaged receipt pairs and replay after removal of the input corpus.
The prior ten-slot campaign reproduced its original report bytes.

The heldout result covers this declared workload and reader build. External
producer authentication, complete rotating-session coverage, detection
accuracy and host-wide overhead remain open.
[Study registration and report fields](BENCHMARK_CORPUS.md#evaluate-development-and-heldout-etls-separately)

## Registered ETL reader cohort on 2026-11-22

A development run on Windows `10.0.28000` registered ten slots before opening
the inputs. The plan pinned the x64 Release reader built from `ab0d56e`, the
installed `tracerpt`, the ETL hash for each slot and three event families.
The slots used six distinct source hashes. Several slots reused the control
hash to exercise different outcomes.

| Registered input or interruption | Slots | Verified pairs | Families agreed / planned |
| --- | ---: | ---: | ---: |
| Five intact ETLs from the [disk comparison](#disk-io-in-paired-etl-evaluations-on-2026-11-22) | 5 | 5 | 15/15 |
| Control with its last byte removed | 1 | 1 | 0/3 |
| Missing file | 1 | 0 | 0/3 |
| Different ETL supplied for the control hash | 1 | 0 | 0/3 |
| Slot left unused | 1 | 0 | 0/3 |
| Supervisor stopped after writing the package and before publishing its outcome | 1 | 0 | 0/3 |
| **Total** | **10** | **6** | **15/30** |

Both readers returned counts for the shortened ETL and reported 22 records.
Its buffer gap excluded all three families from the comparable set. Overall,
15 of 15 comparable families agreed, 12 of 20 planned reader attempts
returned usable counts, and all six acknowledged packages verified. The
missing file retained Windows error 2. The changed input retained the
expected and observed hashes. For the interrupted slot the harness confirmed
the package on disk before the supervisor exited. A second admission failed,
and replay left the slot unresolved. Two freezes of the same receipts gave
identical snapshots and evaluation bytes.

In a separate two-family control, Windows rejected a deliberately invalid
native reader. Direct launch and the retained attempt both reported error
216 on this host. The Windows reader completed. The report credited one of
two readers, zero of two planned families and zero comparable families.
Checks also exercised competing admissions, an outcome published during
snapshotting, malformed receipts, package substitution, missing packages
and replay after moving the evidence. Earlier single-file reports from nine
v1 and six v2 packages reproduced byte for byte.

These measurements cover descriptor counts in saved ETLs on one Windows
build. The registered files share sources and ETW infrastructure. Heldout
detection performance, external producer provenance, host-wide overhead and
persistence through power loss remain unmeasured here.
[Register and replay a cohort](BENCHMARK_CORPUS.md#register-a-cohort-of-saved-etls)

## Disk I/O in paired ETL evaluations on 2026-11-22

The v2 comparison ran the x64 Release reader from `ab0d56e` and the installed
Windows `tracerpt` on a pinned copy of each ETL. Acquisition pinned both
executables. Offline replay verified the archived inputs and tool outputs.
The three families agree when their qualified counts match, including observed
zero counts. The table gives agreement divided by the number of registered
families and the number that could be compared.

| Saved trace | Native disk events | Windows disk descriptors | Agreement / planned | Agreement / comparable |
| --- | ---: | ---: | ---: | ---: |
| Control | 0 | 0 | 3/3 | 3/3 |
| x64 CPU workload | 2,462 | 2,462 | 3/3 | 3/3 |
| x86 CPU workload | 4,786 | 4,786 | 3/3 | 3/3 |
| SimpleAllocator | 1,717 | 1,717 | 3/3 | 3/3 |
| Scheduler | 2,307 | 2,307 | 3/3 | 3/3 |
| Control with one byte removed | 0 | 0 | 0/3 | 0/0, unavailable |

Both readers reported 22 events in the shortened control. Its buffer gap
kept all three families outside the comparable denominator. A failed native
launch retained the Windows counts and the original process error. Synthetic
controls exercised a missing native disk row with a positive Windows count,
unknown names, unsupported versions and distinct provider GUIDs. Replay of
nine existing v1 packages reproduced the original evaluation bytes, including
the two-family denominator and failed-reader results.

The measurements establish agreement on descriptor counts for these files.
Both readers use Windows ETW. Hardware service time, producer authenticity
and independent detection accuracy require separate evidence.
[Acquisition and replay](BENCHMARK_CORPUS.md#compare-two-readers-on-a-saved-etl) · [Per-record response time validation](#saved-disk-io-response-times-on-2026-11-22)

## Saved disk I/O response times on 2026-11-22

An x64 Release build on top of `a4bc8da` read the five saved ETLs below.
The Windows `tracerpt` XML export supplied the original record order and
named fields for the control, CPU workloads and allocator. For the larger
scheduler trace, a compact raw-clock CSV export fit the available temporary
space. Its 877,318 rows and 2,307 supported disk records also matched the
independent Windows summary by provider GUID and version.

| Saved ETL | All records | Disk records | Reads, start / completion | Writes, start / completion | Flushes, start / completion |
| --- | ---: | ---: | ---: | ---: | ---: |
| Control | 23 | 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| x64 CPU workload | 179,474 | 2,462 | 1,208 / 1,208 | 21 / 21 | 2 / 2 |
| x86 CPU workload | 168,298 | 4,786 | 2,339 / 2,339 | 50 / 50 | 4 / 4 |
| SimpleAllocator | 418,378 | 1,717 | 42 / 41 | 817 / 817 | 0 / 0 |
| Scheduler | 877,318 | 2,307 | 0 / 1,573 | 0 / 718 | 0 / 16 |

The readers agreed on the ordinal, timestamp, CPU, operation, phase,
issuing TID and available disk, byte and response fields for all 11,272
disk events. Paging preserved the whole-file byte totals, the first maximum
for each operation and its tie count. The x64 workload reported 19,564,544
bytes read and a longest read of 4,045,865 ticks at 10 MHz (404.5865 ms).
The scheduler's longest read was 188,874 ticks (18.8874 ms), with no read
initiations recorded. These captures establish recorded response intervals.
Device service time and request identity across providers remain open.

The x86 and x64 labels describe the workloads. The observed DiskIo records
in these captures used 64-bit envelopes. Synthetic controls exercised both
pointer widths, versions 2 and 3, all six opcodes, truncated and overlong
records, zero responses, ties and transfer totals above 4 GiB. The shortened
control ETL retained its partial buffer count. Exact-page replay, a mismatched
hash, signed capture statements and redirected output against owned hard
links were checked separately. The probe's first payload fingerprint was
checked against the Windows fields. [Disk I/O command and timing units](TRACE_IMPORT.md#read-saved-disk-io-response-times)

## Directory I/O completion-port packets on 2026-11-23

The x64 user project built on Windows `10.0.28000` with MSVC v143 and
Windows SDK `10.0.26100.0`. The tested executable (SHA-256 prefix
`30c79c662ca1`) used the Release configuration with size optimization and
debug information disabled. Its normal `--io-lifecycle --completion-port`
entry point ran with the caller's existing privileges.

| Workload | Dequeues | Observed outcome |
| --- | ---: | --- |
| Changes in two of three directories | 4 | Requests 2 and 1 each returned 32 bytes. A timeout removed no packet. The drain dequeued a failed packet for request 3 with Win32 error 995 and zero bytes. |
| Two handles watching one directory | 2 | One change produced two 32-byte packets. The directory IDs agreed and the keys, handles and operation pointers distinguished the requests. |
| Change after timeout and before cancellation | 2 | The drain returned a successful 44-byte packet after the cancellation attempt. |
| Missing directory | 0 | Replay retained the planned request and failed admission with partial coverage. |

All six matched packets agreed with a separate result query on the submitted
handle and operation. Independent `FindFirstChangeNotificationW` watches
observed each controlled change in the ordered and shared-directory runs.
The quiet directory stayed unsignaled throughout the ordered run. Closing
the journal reader while I/O was pending produced exit 1 and an exclusive
directory open succeeded after the collector exited.

Replay controls changed the port, file handle, key, operation pointer,
direct result and journal sequence. They retained conflicting inputs, kept
indeterminate fields empty and withheld joins after a gap. A drain without
a packet or quiescent event left the request outcome and release unconfirmed.
An eight-request run drained all eight cancelled operations through one port.
The nine completion-port tests, 15 existing directory I/O tests and four
issuing-thread workloads passed. Four earlier thread-state reports also
replayed to their original SHA-256. These runs cover the owned user-mode
requests. Kernel IRP allocation and packet enqueue time remain open.
[Capture example](COMMAND_REFERENCE.md#follow-requests-through-an-io-completion-port) · [Regression controls](../tools/test-io-completion-port.py)

## Issuing thread state during directory I/O on 2026-11-23

On Windows `10.0.28000` x64, the paired collector sampled the issuing
thread of the existing directory notification executable (SHA-256 prefix
`2bda0417bff9`). In four captures it attempted 220 state queries. Of
these, 211 fell strictly inside one of seven wait-any calls and reported
Waiting. The table counts each query once, including calls that waited on
more than one request.

| Workload | Recorded waits | Waits with an interior sample | Waiting samples | Journal outcome |
| --- | ---: | ---: | ---: | --- |
| Changes in two of three directories | 3 | 3 | 169 | Request 2 selected, then request 1, then timeout and cancellation of request 3 |
| Two requests watching one directory | 2 | 1 | 10 | Both requests completed after one change. The second wait had no interior sample. |
| Three quiet directories | 1 | 1 | 32 | One shared timeout |
| One-sample limit with three quiet directories | 1 | 0 | 0 | The timeout and request results survived the sampling limit. |

The stimulus controller waited for a recorded monitor or release and a
live Waiting observation before creating each change. A separate .NET
process checked the PID, TID and both creation times. Of its 15 views,
13 fell strictly inside the corresponding wait and reported
`Wait / UserRequest`. These are observations at separate instants. The
Windows SDK x64 structures independently confirmed the offsets and sizes
used to extract the original native fields. In a separate run of the
command reference example, the uninstrumented controller observed 24
Waiting samples inside one quiet-directory wait and reproduced the
report digest.

Replay kept calls with no sample, rejected a foreign generation and
withheld links across a journal gap or contradictory thread exit. A
disputed wait selection preserved the native return and the independently
observed thread state. The 15 existing I/O lifecycle regressions passed.
Wait-object identity inside the scheduler, kernel IRP generations and
continuous time off CPU remain open.
[Command and replay](COMMAND_REFERENCE.md#observe-the-issuing-thread-during-an-io-wait) · [Independent checks](../tools/test-io-thread-waits.py)

## Directory notification timing on 2026-11-22

The x64 Release collector from `fd3b28f` recorded four runs against owned
temporary directories. The timing replay read the same retained bytes as
the lifecycle assessment. The table gives clock deltas for this run. A
zero means that the clock did not advance across the measured boundaries.

| Input | Native outcome | Ticks spent in shared wait calls | Latest signal candidates |
|---|---|---:|---|
| Two changed directories, one quiet directory, two unavailable paths | Three requests accepted. Generations 2 and 1 completed, and generation 3 returned `ERROR_OPERATION_ABORTED`. | 3,500 ms | 3 |
| Two requests on one quiet directory | Both returned `ERROR_OPERATION_ABORTED` after one shared timeout. | 63 ms | 1, 2 |
| Two requests on one directory, one file created | Both returned the notification length for the new name. | 0 ms | 1, 2 |
| One change after the timeout and before cancellation | The original result reported a successful completion. | 47 ms | 1 |

For the two separately triggered changes, the controller recorded ticks
before creating each file and after receiving its selection record. Both
independent intervals intersected the corresponding replay bounds. For
the ordered run, the later timeout on the quiet directory established
that its signal followed both completed notifications.

The 15-case lifecycle suite also checked failed and disputed waits, final
quiescence with an unknown result, hard-linked output and a mismatched
hash. An independent enumeration of feasible submission and signal ticks
checked elapsed bounds, including near the unsigned 64-bit limit. Equal
timestamp controls preserved event order when the journal contained
separate positive and clear observations. Replaying all 73 complete-line
prefixes and 65 single-line omissions across the four captures kept every
timing witness within the qualified prefix.

The default assessment matched the previous replayer byte for byte for
these four captures and three archived journals. The 34 public-content
checks passed. Separate checks recognized the actual timing reports,
detached wait and request rows and their bounds in UTF-8 and BOM-less
UTF-16. These tests cover this Windows collector and its observer clock.
Device service time, cross-provider IRP identity and worker scheduling
remain open. [Command and report fields](COMMAND_REFERENCE.md#measure-directory-notification-timing)

## Saved ETL reader comparison on 2026-11-22

The x64 Release executable from `fd3b28f` and the installed Windows
`tracerpt.exe` read five saved traces on reader build 10.0.28000. Each pair
used the same pinned ETL and retained both programs' original outputs.
The started process image paths matched the paths of the pinned executable
handles, and both executable hashes matched before and after each run. Offline
replay verified the archived bytes and recalculated both family counts.

| Saved trace | Records read by each tool | Buffers | CPU samples | Context switches |
|---|---:|---:|---:|---:|
| Control | 23 | 3 | 0 | 0 |
| x64 CPU profile | 179,474 | 360 | 79,528 | 0 |
| x86 CPU profile | 168,298 | 276 | 88,809 | 0 |
| SimpleAllocator | 418,378 | 1,300 | 5,496 | 0 |
| Scheduler | 877,318 | 181 | 18,556 | 168,474 |

All ten file/family comparisons agreed. Five had positive counts and five
had equal zeros. Four additional acquisitions exercised loss and failure.

| Control | Original evidence | Replay |
|---|---|---|
| Final byte removed | Both readers saw 22 records and two of the three declared buffers. Windows emitted an opcode table only. | Both families had limited coverage. |
| Invalid ETL | Native open returned Win32 1392. The Windows reader exited with `0x80070570`. | Both planned families remained in the report with zero comparable families. |
| Invalid collector image | Windows rejected the native launch with error 216 on this host. The external reader still read all 23 control records. | The report retained the launch error and the external counts. |
| One-millisecond deadline | Both attempts timed out on the x64 trace. | Both planned families remained and the comparable agreement value was null. |

The Windows regression removed its original ETL copy and moved the archive
before replay. It also checked wrong admission hashes, an open writer, a
destination collision and the actual OS error from launching the invalid
image. Offline controls covered conflicting counts, ambiguous coverage,
inconsistent summary tables, over-limit outputs, changed executable evidence,
tampered bytes, output hard links and two concurrent publishers. The existing
imported-corpus tests passed, and an earlier paired module campaign replayed
to its original report. Publication checks recognized renamed archives,
summary files and detached report rows in UTF-8 and UTF-16.

This comparison uses one Windows reader build and two classic event families.
Both programs use the Windows ETW infrastructure. Authenticated producer
provenance, heldout detection performance and host-wide safety or overhead
remain open. [Acquisition and replay commands](BENCHMARK_CORPUS.md#compare-two-readers-on-a-saved-etl)

## Compiled probe catalog on 2026-11-22

The Release executable declared four probe contracts across 23 of its 61
selected operation rows. Nineteen native rows shared the connection-only
check. The other four bindings covered the collector's own memory range, a
saved dump range and the two saved ETL event families. The compiled inventory
retained all earlier fields and values. Both restricted launches returned the
same compiled catalog as the standalone command.

Four observed reports exercised the published scopes. The standalone live
probe checked the owned range and attempted the existing device connection.
The restricted observe probe reported the native branch blocked by policy.
The saved full dump supplied a qualified list head. The 23-record ETL control
reported a successful scan and zero decoded records in either event family.
The unsupported VTL1 operation carried no observed source-open stage. All
four observations kept target-environment validation unperformed. A separate
policy fixture supplied a successful native connection to the serializer.
Release and AddressSanitizer both marked the 19 native prerequisites partial
and left the VTL1 row unsupported with no source-open stage. The restricted
mode regression passed 82 CLI checks, including the launch-policy scope for
native rows when the device was never opened.

`tools/test-probe-matrix.py` compared these scopes with the catalog, rendered
a legacy inventory without inferred probe commands and rejected 23 inconsistent
inventories. Duplicate JSON fields, truncated input and a disguised runtime
report each preserved a pre-existing output file. On those paths the generator
issued only the compiled inventory command. The SimpleAllocator ETL report
matched the previous binary's output byte for byte.

```powershell
python tools/generate-support-matrix.py --exe x64/Release/KnLiveDbg.exe --check
python tools/test-probe-matrix.py --exe x64/Release/KnLiveDbg.exe --dump $ownedDump --etl $savedEtl
```

Use the `probed-4.dmp` fixture from the dump-source harness and a saved ETL
with complete buffer accounting for this regression. The catalog records
which checks are implemented. Physical LA57, protected targets and the
Windows build and security-configuration matrix still require environment
evidence.

## Saved dump capability probes on 2026-11-22

At `b7036d9` the x64 Release CLI completed 66 invocations on synthetic AMD64
full dumps.
Independent fixture bytes supplied the expected SHA-256 for every complete
sample, including a list head split across two pages. LA48 and LA57 fixtures
exercised 4 KiB, 2 MiB and 1 GiB mappings. An explicit range crossing into
a missing run retained eight observed bytes and eight missing bytes. A
nonpresent page-table entry, a noncanonical range and a Windows byte-range
lock produced distinct results. The locked read retained Win32 error 33.
Replacing payload bytes while keeping the same header changed the sample
digest. A wrong header digest stopped after exactly one read.

Default list checks covered matched reciprocal links, contradictory links
and missing neighbors. The last two had a complete sample and an independent
saved paging context. An explicit range at the same address qualified only
the bytes. Short headers, ambiguous depth, conflicting context, sharing
violations, a directory junction, a file marked offline and output hard links
also exercised the published CLI. The hard-link tests opened append handles
so the subprocess itself had to preserve each input.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/validate-dump-source.ps1
# Set $fixtures to the run directory printed by the harness.
python tools/test-dump-capabilities.py --exe x64/Release/KnLiveDbg.exe --fixtures $fixtures
```

The dump-source harness passed 166 checks each in Release and AddressSanitizer.
A focused build of the production dump probe passed 40 instrumented CLI calls.
MSVC ASan reported its known unsupported host interceptor and continued with
`ASAN_WIN_CONTINUE_ON_INTERCEPTION_FAILURE=1`. The existing dump CLI passed
227 checks. Its final-file symbolic-link case required a Windows privilege
unavailable to this run. The separate junction test ran. Initialization
receipt and runtime capability regressions passed. The Release link emitted
the existing C4744 warning for `KmonHuntIndex::NextQueryEpoch`.

The compiled inventory and the SimpleAllocator ETL capability report matched
their prechange outputs byte for byte. The 23-record ETL control agreed with
Windows `tracerpt`. Matrix generation matched all 61 compiled contracts and
261 command routes. The linked command and console self-tests passed 3,083
and 570 checks. All 32 public-content test groups passed, including detached
sparse ranges and their translations.

This evidence covers the offline file decoder and its selected ranges. A
header digest establishes the header bytes only. Independent capture
provenance, a real LA57 target, CPU permissions and regression on other
Windows builds or security configurations remain open.

## Evidence-checked wait claims on 2026-11-22

This P15 checkpoint used saved Windows Wait Chain Traversal receipts from
owned processes. The x64 Release collector had SHA-256
`273106753f4137e69a5bbe9046ec83e42ecb9ef0b3c67b71513af255d7c7d839`.
Run `python -I -B tools/test-wait-chain.py --exe x64/Release/KnLiveDbg.exe`
for the native acquisition and offline verification suite. The 21 tests
covered two- and three-thread mutexes, thread termination waits, mixed cycles,
transitions, generation mismatches and post-exit replay.

On 24 original files, the default assessment and diagnosis outputs matched
the replayer from commit `8919023` byte-for-byte in all 48 comparisons. Its
original facts supplied an independent expectation for each of the six typed
claims. Of the 144 verdicts, 29 were supported, 13 refuted and 102 inconclusive.
All 42 decisive results passed proposal verification with citations derived
from those original facts. These counts describe this set of receipts.

A signaled member alone and a closed cycle alone both failed to refute
persistence. Together their witnesses verified the refutation. A different cycle
without an observed reference exit supplied counterevidence and kept persistence
inconclusive. Other controls used IDs from a byte-different encoding of the same
capture, an unrelated authentic fact, a forged ID, a wrong target or policy,
duplicate claims, extra command fields, invalid encodings and exhausted
budgets. A deferred plan issued zero graph evaluations. Proposal verification
ran in an isolated Python process with audit hooks that rejected socket,
subprocess and native-library loading operations.

Redirecting output to a writable hard link of the input previously appended to
the original receipt on assessment and diagnosis, including when the caller
requested only a read. Regression tests check those routes, investigation,
malformed arguments and proposal-input aliases. A read-only output handle
returned exit 3 for the typed report. The documented proposal example passed
in Windows PowerShell and PowerShell 7. All 31 public-content scanner tests
passed, including truncated and detached UTF-8 and UTF-16 evidence.

The replay evaluates a bounded saved capture. Wait completion, object lifetime,
the cause of a hang, authentic collection and general AI provider egress
remain separate validation gates.
[Operator example](COMMAND_REFERENCE.md#check-a-proposed-wait-claim)

## Thread termination in Windows wait chains, 2026-11-22

The Windows x64 Release controller had SHA-256
`5f78c78e831508324da0ae29547c34f69d7c5a2b52f3068d7d8c25ae430f7ae7`.
Two owned threads used Win32 thread handles in a one-way wait, a mutual
wait and a mixed cycle. In the mixed case the first thread held a mutex
while waiting for the second to terminate. In both cycles the first
wait returned `WAIT_TIMEOUT` and the peer's wait returned success. Both
thread handles then signaled. Only the fixture observed these results. The replay retained the original WCT
observations and left the eventual wake reason unknown.

| Paired capture | Successful traversals | Views with a potential cycle | Corroborated rounds |
| --- | ---: | ---: | ---: |
| One-way termination wait | 6/6 | 0 | 0/3 |
| Mutual termination waits | 6/6 | 6 | 3/3 |
| Thread termination and mutex | 6/6 | 6 | 2/3 |

The remaining mixed round lacked a qualifying measured overlap. The
single-root assessments cited the two thread generations, the middle
object and the handle witnesses. Tests removed a pin, changed the object
type or status, supplied a foreign or self target and gave the two roots
different dependency types. The wait suite passed all 18 tests. The 18
previously retained receipts reproduced both their assessments and
diagnoses byte for byte. All 25 publication tests passed, including
detached termination edges, directed relations and diagnosis facts.
[Traverse thread termination waits](ARCHITECTURE.md#windows-thread-termination-waits)

## Cooperative kernel I/O trace, 2026-11-22

The x64 Release solution and Debug minifilter fixture built with WDK
10.0.26100.0. The Release fixture had SHA-256
`e96cdf2e32e4e3b056266a95555bf5960461d274840b14a4a9de71e34b502b52`. Review covered request and instance generation, disconnect
during publication, logical and worker references, output copying and the
draining callback. A nonblocking pool reservation bounds the number of
trace rings through disconnect. The legacy status request and reply still
measure 32 and 528 bytes.

Twelve user-mode tests exercised the production ring and READ byte-count
code, the capture client and the offline decoder. An MSVC x64 host program
produced 18 interleaved events for two request generations in three pages
(1,944 bytes). Python independently checked the wire layout, byte offsets,
opposite completion order and layer intervals. Other cases covered stale
epochs, overwritten pages, integer exhaustion, conflicting identities,
incomplete retirement, a broken pin and interrupted output. The documented
offline replay produced the same assessment in both Windows PowerShell and
PowerShell 7. Nine existing directory I/O tests and all 24 publication
tests passed. [Run the capture or replay](COMMAND_REFERENCE.md#capture-a-cooperative-kernel-io-trace)

The default MSVC AddressSanitizer runtime stopped before `main` at
`interception_win.cpp:193`. Allowing it to skip the unsupported Windows
interception let the instrumented program produce the identical pages
and pass the host suite. Full interceptor coverage remains unverified.

The live runner exited 2 at its elevation check before creating the output
directory. Filter Manager enumeration returned access denied, and the
fixture service was absent. Actual callback delivery, upper detach during
the lower pending interval, and the trace allocation and message ledgers
after unload still require an elevated test host. [Live acceptance checks](MANUAL_TEST_CHECKLIST.md#pending-io-and-runner-failure-validation)

## WHEA event XML comparison, 2026-11-22

The x64 Release controller had SHA-256
`9029964e6b3ee1d3899bbd4cfd53ddee66b4c4906048ddc40e6171558177e012`. A separately rendered
UTF-16 event contained the 2,199 bytes previously extracted from a small
dump by Windows SDK `kd.exe`. Independent .NET XML and SHA-256 operations
in Windows PowerShell and PowerShell 7 reproduced the digest from the
native comparison. Reading the two inputs twice returned byte-identical
JSON. Nine previously retained v1 reports and the retained WHEA v2 report
also matched their original bytes when the event option was omitted.
[Run the comparison](COMMAND_REFERENCE.md#compare-a-saved-whea-event-with-the-dump)

Ten event tests exercised complete and partial CPERs, a padding-only
difference, wrong pins, named fields and namespaces, invalid or duplicate
fields, UTF-8 and both UTF-16 byte orders, file and parser limits, a
reparse directory, a concurrent writer and hard-link redirection. A
1 MiB CPER matched a UTF-16 export at the payload limit. The external
DTD test recorded zero loopback connections. The installed WHEA-Logger
manifest supplied the provider GUID and both payload fields for all 25
version-zero event IDs supported here. A real System event exported by
another provider produced `different_event_source`. Every positive event
comparison used synthetic incident data.

The final controller passed nine WHEA record tests, 11 crash tests,
227 dump CLI checks with one file-symlink control skipped, 15 wait tests,
nine I/O tests, 82 restricted launches, 57 source contracts and 3,081
command checks. The compiled support matrix matched. All three documented
examples ran in both PowerShell editions. The publication tests passed
all 23 cases and the scanner recognized 32 variants of the XML and
private comparison data. From 01:45 to 01:56 KST the host kept the same
boot, with zero new reboot events, bugchecks or crash dumps and no
remaining fixture process, temporary directory or running test driver.
Incident attribution and independent boot or capture provenance remain
open. [Comparison boundaries](ARCHITECTURE.md#saved-whea-event-comparison)

## Stop-linked WHEA records, 2026-11-22

The x64 Release controller had SHA-256
`11f257ec5def58ba01e1033d49b3352e284ae49c299af879d61918274387a72d`.
The production client used DbgEng 10.0.26100.2454. Windows SDK `kd.exe`
10.0.26100.6584 extracted the same 2,199 bytes from an owned small dump
at bugcheck parameter 2. The five section payloads appeared in reverse
descriptor order with gaps and spare capacity. The bytes matched the
original fixture, and their SHA-256 matched the report. Two runs produced
identical v2 output. All nine retained v1 reports matched the output from
the preceding controller byte for byte. [Run the WHEA query](COMMAND_REFERENCE.md#read-the-whea-record-from-a-saved-bugcheck)

Nine WHEA tests covered short reads in the header and body, the 1 MiB
and 128-section limits, invalid and overlapping extents, unsupported
revisions, field validity and opaque sections. Machine-check controls
compared versions 2, 3 and 4, including a match in an extra bank, a
different status, an invalid bank and a matched status with the uncorrected
bit clear. Missing evidence and contradictory evidence resolved to
separate fields. The suite also exercised unsupported stops, dump attributes,
unavailable initial state, input redirection through a hard link and a
wrong digest. Both documented examples ran in Windows PowerShell and
PowerShell 7.

The same controller passed 11 crash diagnosis tests, 227 dump-source CLI
checks, 15 wait-chain tests, nine directory I/O tests, 80 restricted-launch
checks, 57 source contracts and 3,081 command checks. The support matrix
matched. One dump-source file-symlink check was skipped on this host.
All 22 publication tests passed. The scanner flagged 27 original,
renamed, detached or re-encoded variants of the WHEA evidence.

From 01:14 to 01:34 KST the host kept the same boot and recorded zero new
bugcheck or reboot events or crash dumps. No fixture process, temporary
test directory or running test driver remained. All positive WHEA inputs
were synthetic. The host had no saved crash dump or matching System
WHEA-Logger event for an independent incident comparison.
[Evidence limits](ARCHITECTURE.md#stop-linked-whea-records)

## Saved kernel crash diagnosis, 2026-11-22

The x64 Release controller had SHA-256
`ade9aa42412322f635ed3cebf1c069ce2fba6cf45734d7f1f705ec8e6bb08987`.
The typed client loaded DbgEng 10.0.26100.2454. Tests generated small AMD64
kernel dumps with known stop parameters, stack bytes and two module ranges.
A separate Windows SDK `kd.exe` 10.0.26100.6584 session read the same
retained inputs. Across a two-frame and a capped 32-frame stack, all
34 instruction offsets, stack pointers, return offsets and module names
agreed. The SDK and the typed client also returned the four original
64-bit stop parameters. The fixture module containing the first instruction
was reported as a location. Causal attribution stayed unknown.
[Run the diagnosis](COMMAND_REFERENCE.md#diagnose-a-saved-kernel-dump)

Nine retained dumps gave byte-identical JSON on two fresh reads each.
All 26 supporting and contrary references resolved. Live-generated,
offline-generated and unavailable-initial-stop cases retained their
stored WHEA code with limited evidence. A rejected dump body still yielded
the header tuple. A changed file failed the old digest. The boundary
tests covered missing control registers, the exclusive end of a module
range, the frame cap, a reparse ancestor, an existing writer, output
failure and redirects to the source and its hard link. A loopback listener
in the inherited symbol path accepted zero connections.

All 143 native dump controls passed, including a contradicting register
with its peer unavailable and a successful zero register return. All 11
crash tests, 227 dump-source CLI checks, 15 wait-chain tests,
nine directory I/O tests, 78 restricted-launch checks, 57 source contracts,
3,081 command checks and 33 runtime policy checks passed. The existing
dump-source suite skipped its file-symlink control on this host. The
crash suite exercised a real directory junction. The documented example
ran in Windows PowerShell and PowerShell 7. The support matrix matched
the controller. All 21 publication tests passed, and 18 variants of the
original dump, report and detached frame were flagged.

Between 00:36 and 01:04 KST the host recorded zero new reboot or bugcheck
events and zero new crash dumps. No fixture process, temporary test directory
or running test driver remained. The dump corpus was synthetic. Actual host
crash attribution, independently verified unwind and module bytes,
allocation history and WHEA error-record decoding remain open.
[Typed source and evidence limits](ARCHITECTURE.md#typed-crash-dump-diagnosis)

## Overlapped directory I/O lifetimes, 2026-11-22

The Windows x64 Release controller had SHA-256
`b4bc32d8f1067d71e32fa3c7fd9ee9c039dfc5f9f1fcc8429c6c8ae11103e2a9`.
The fixture issued real directory notifications and waited for the collector
to report its outstanding requests before creating files. It created a
file for generation 2 first, then waited for that generation's release
before creating a file for generation 1. The two directory identities
matched the fixture's independent filesystem IDs. Their reported byte
counts matched the lengths of the corresponding notification entries.

| Owned run | Planned / queued | Successful / aborted | Unknown outcomes |
| --- | ---: | ---: | ---: |
| Reverse-order changes, quiet directory, two unavailable paths | 5 / 3 | 2 / 1 | 2 |
| Two requests for the same quiet directory | 2 / 2 | 0 / 2 | 0 |
| Change after the observer's timeout | 1 / 1 | 1 / 0 | 0 |

In the last run a one-byte output pipe held the collector inside its
timeout record while the fixture created the file. `CancelIoEx` then
returned `ERROR_NOT_FOUND` (1168). The final result on the retained
operation reported success and 44 bytes. In the quiet-directory run both
cancellation calls succeeded and both final results were
`ERROR_OPERATION_ABORTED` (995). The three original journals reproduced
their assessments twice after process exit. All 66 state evidence links
resolved to physical lines in the corresponding journal.
[Capture and replay a request](COMMAND_REFERENCE.md#trace-an-io-request-through-completion)

Nine I/O regressions passed, including eight simultaneous generations,
a reader disconnect, exclusive reopening of a rejected file while other
requests were pending, interrupted publication and contradictory result
witnesses. Repinned controls covered missing sequences, generation reuse,
failed submission, notification overflow and unconfirmed handle release.
The same controller passed 15 wait-chain regressions, 76 restricted launch
checks, 56 source contracts, 3,081 command checks and its runtime probe.
The runtime policy suite passed 33 checks. The documented PowerShell example
ran and the support matrix matched the binary. All 20 publication tests
passed. Twelve private variants of the actual journal and assessment were
flagged, including detached lines, reordered JSON fields and UTF-16 logs.

From 23:58 KST on November 21 to 00:19 KST on November 22 the host recorded
zero new reboot or bugcheck events and zero new crash dumps. The final
check found zero remaining fixture processes, temporary fixture directories
or running test drivers. These observations cover the controller's own
Windows I/O. Matching a kernel IRP allocation to its driver dispatch and
completion still requires an independent lifetime source.

## Offline comparison of wait explanations, 2026-11-21

After the owned mutex fixtures exited, the Python replayer diagnosed 18
original single-root and paired WCT captures. Each produced identical
diagnosis bytes on two runs. All 634 evidence pointers resolved in the
corresponding SHA-256-pinned input. The default command reproduced 23
archived assessments byte for byte, including single-root captures from
before paired acquisition was available.

In the one-way capture the primary thread waited on a mutex held by a
different thread. The reciprocal capture supplied evidence of a potential
cycle. In both topology-change captures the diagnostic cited one observed
owned wait and three cycle views involving the primary thread. The exit
series retained eight issued queries out of 16 planned. Round 5 contained a
signaled wait on the same process generation, which ruled out continued
membership at that point. A new request after exit and a request with the
wrong primary thread creation time each yielded insufficient evidence for
both candidates. The observations left the cause of the releases unknown.
[Compare explanations for a recorded wait](COMMAND_REFERENCE.md#compare-explanations-for-a-recorded-wait)

All 15 wait-chain tests and 19 publication tests passed. Repinned inputs
covered a different directed cycle, a cycle excluding the primary thread,
a repeated thread with the native cycle flag clear, an unsupported tail,
a failed handle wait and termination of an unrelated thread or another
generation with the same thread ID. The documented PowerShell invocation
ran against the saved exit series. The scanner flagged six renamed,
truncated or UTF-16 variants of the actual diagnosis. The run used the
x64 Release controller identified in the paired-capture section below.
Between 23:38 and 23:43 KST the host recorded zero new reboot or bugcheck
events and zero new crash dumps. The final check found zero remaining
WCT fixture processes, temporary fixture directories or running test drivers.

## Paired Windows wait-chain observations, 2026-11-21

The Windows x64 Release controller had SHA-256
`14ddd54d49d194e791ac3533d7bec542c0c058aa047b46eb3b1a849b93898dee`.
Two owned fixtures each formed a ring of unnamed Windows mutexes. In each
fixture every worker held one mutex. The last worker entered its timed
wait only after the collector flushed the first one-way round. The parent
checked that the timed wait expired, all other workers acquired their next
mutex, and both processes exited normally.

| Final capture | Issued / planned queries | Individual cycle views | Overlapping query brackets / planned rounds | Rounds meeting both-root test | Consecutive rounds |
| --- | ---: | ---: | ---: | ---: | --- |
| Two threads, one-way wait | 6 / 6 | 0 | 2 / 3 | 0 | None |
| Three threads, one-way chain | 6 / 6 | 0 | 3 / 3 | 0 | None |
| Two-thread cycle | 16 / 16 | 16 | 8 / 8 | 8 | 1–8 |
| Three-thread cycle | 16 / 16 | 16 | 6 / 8 | 6 | 1–4 |

An earlier four-round two-thread run returned a cycle from both roots in
every round. Only rounds 2 and 4 had overlapping query brackets. Replay
kept the finding at `potential_wait_cycle`. In both topology-change runs,
the peer's original discovery lacked a thread that later closed the ring.
Each run retained all eight queries and three individual cycle views, with
zero corroborated rounds.

A wrong peer creation time yielded two issued queries out of four planned.
As the two-thread fixture retired, a longer series recorded five of eight
rounds and eight of 16 planned queries. Rounds 1–3 formed a repeated
group. The fifth round preserved both unavailable roots. A new request
after exit recorded one of four rounds
and zero of eight planned queries. Offline replay reproduced every original
report in this run twice and matched five archived single-root reports byte
for byte. Altered inputs exercised QPC ordering, serial fallback, different
cycle membership or direction, and a timeout after observed termination.
The live tests used mutexes. A frozen wait graph, lock lifetimes and a
persistent deadlock remain unverified.
[Paired capture and replay](COMMAND_REFERENCE.md#repeat-a-wait-chain-from-two-threads)

All 12 wait-chain tests, 74 restricted launch checks, 55 source contracts,
3,081 command checks and 19 public-content tests passed. Both documented
PowerShell examples ran, the runtime capability probe passed, and the support
matrix matched the binary. The scanner flagged all 12 private variants
of the actual output, including detached rounds, truncated logs and UTF-16
text. From 23:03 to 23:26 KST the host recorded zero new reboot or bugcheck
events and zero new crash dumps. The final check found zero remaining WCT
fixture processes, temporary fixture directories or running test drivers.

## Windows user-mode wait chains, 2026-11-21

The Windows x64 Release controller had SHA-256
`979a981bf0fba9a02744ffedf319007aa882bd653118550b592bb9fe1748bd03`.
Two threads in an owned process each acquired a Windows mutex. The controller
first observed one thread waiting on the other's mutex. After the second
thread entered its reciprocal wait, Windows reported a cycle. The second
wait timed out and the first thread acquired the released mutex. The parent
verified both return values and the fixture's normal exit.

| Final Windows traversal | Raw nodes | Replayed edges | Assessment |
| --- | ---: | ---: | --- |
| One-way contention | 3 | 2 | Inconclusive |
| Reciprocal mutex waits | 5 | 4 | Potential wait cycle |

After process exit, the same receipts reproduced both reports byte for byte.
Changed process and thread creation times and a new request for the retired
target produced zero graph edges. Repinned copies exercised an incomplete
traversal, unsupported ownership, terminated or missing thread witnesses,
an apparent recursive self-wait and a closed suffix beyond a foreign thread.
Critical-section rows were tested in replay. The native fixture used mutexes.
These live traversals leave persistent deadlock and kernel wait graphs open.
[Capture and replay a wait chain](COMMAND_REFERENCE.md#capture-a-windows-wait-chain)

The six wait-chain regression tests, 72 restricted launch checks, 54 source
contracts and 3,081 command checks passed. The generated support matrix
matched the binary. All 17 public-content tests passed. The scanner also
recognized renamed, truncated and UTF-16 copies of the actual private
receipt and assessment. Between 22:23 and 22:42 KST the host recorded zero new
reboot or bugcheck events and zero new crash dumps. The final check found
zero remaining wait-chain fixture processes, temporary fixture directories
or running test drivers.

## Paired module collection costs, 2026-11-21

The Windows x64 Release validation core had SHA-256
`43ca5d7c057aa8ff97b0ee1f20c784566e03921fccb1746dc91c8f19e5280f81`.
One of two registered campaign slots ran. Its collector served each real
request and its paired idle request over the same pipes while 12 owned
target processes waited. Each request type ran equally often in both orders.

| Operation | Pairs | Collector time over idle, total (ms) | Supervisor round trip over idle, total (ms) |
| --- | ---: | ---: | ---: |
| Job process census | 16 | 7.2252 | 8.8101 |
| Module visit | 128 | 75.6941 | 78.4712 |

The values are sums of paired differences in one development run. All
128 module visits observed the selected target. After the processes exited,
offline replay reproduced the campaign report byte for byte and retained
the unrun slot in the denominator. The fixture provides no estimate of
game-frame latency or host-wide overhead.
[Measurement procedure and counter definitions](BENCHMARK_CORPUS.md#measure-paired-collector-costs)

The Release core gate passed, including 11 replay tests and six campaign
tests. Altered packages covered a missing idle reply, conflicting collector
identities and clocks, partial counter availability, and an unpaired run
submitted for a paired slot. All 13 imported-corpus evaluator tests also
passed. Between 21:46 and 22:07 KST the host recorded zero new reboot or
bugcheck events and zero new crash dumps. The final check found no remaining
fixture process or running test driver.

The public-content check was also exercised on extracted data from this run.
It flagged all 16 private files, including complete, interrupted and UTF-16
records, the renamed package, database and snapshot, and a SQLite recovery
page containing the registered plan. A format description and an unrelated
JSON document passed. All 19 publication-check regressions passed.

## KMON watched handle scans, 2026-11-21

On `main` at `2f6742f`, the file snapshot probes and the handle graph owner
pin called `OpenProcess` outside the observer journal. The graph scanner
also saved its cursor by PID and creation time after the scan returned, even
if the operator had removed the watch in the meantime.

The Windows x64 Release controller tested here has SHA-256
`eaa2f697d8d4147581a12f9a517f911f6e8ed16afd254d0dd2f7fb3000b072d9`.
Three controllers each ran 12 cases. The parent checked their access masks
and creation times independently. Each also sampled a separate owned process
while it was running. The parent waited for the graph pin, released that
process and confirmed its exit before allowing the scan to finish.

| Access to the fixture controller | Observer rows | File lifecycle rows in the three-pass case |
| --- | ---: | ---: |
| Limited query and synchronize allowed | 58 | 130 |
| Limited query denied | 29 | 0 |
| Synchronize denied | 50 | 130 |

The 129th file in a baseline crossed the 128-record pass limit and retained
the original snapshot's two receipt IDs. The next complete snapshot recorded
its closure. For a pinned owner, failed, partial and complete graph results
carried the owner's identity. The fixture also checked that owner exit, a changed
promotion and removal followed by re-registration could not advance the new
watch cursor. Repeated acquisition IDs across controllers resolved to
distinct controller PIDs and creation times. A second observer ingest added
zero rows. [Reading handle scan receipts](TIMELINE_COMMAND_USAGE.md#trace-a-watched-handle-scan)

Run `python tools/test-process-handle-observer.py --exe x64/Release/KnLiveDbg.exe`
from the repository. Windows supplied the process handles, access denials and
exit signals. The file and graph publication paths consumed fixed records.
The standalone core test located its own open file in a native snapshot.
Live device-backed graph traversal, PDB-based object reads and the kernel
fallback for creation time remain unverified by this run.

The same controller passed the integrated CLI suite and the timeline, MCP
observer, scheduler and source-contract regressions. Between 21:09 and 21:33
KST the host recorded zero new bugchecks, unexpected reboots or dump files.
The final check found no fixture process or running KnLiveDbg test driver.

## KMON process logging results, 2026-11-21

On the previous `main` controller (`4ca32e2`), an owned-process fixture
produced 36 handle rows, including five denied control opens. Observer ingest
produced zero process logging rows. Those handle rows alone could not identify
the logging operation or the backend result. [Reading logging request evidence](TIMELINE_COMMAND_USAGE.md#inspect-kmon-process-logging-requests)

The Windows fixture uses its own controller as the logging subject. For the
access-denial cases the parent independently checks the process creation time
and access masks before releasing the child. Two private local named pipes
exercise transport failure and handle replacement. The fixture checks the
client PID on both pipes. A separate controller exercises the existing native
enable path on itself. Fixed response buffers cover cases that the native
calls and the pipe cannot produce.

The final Windows x64 Release controller had SHA-256
`dbe6cee972614a9bb82302f5cd66bc71feacf95d01f55deea2960fbda4037ec7`.
The parent ran 27 watch cases in each access configuration and compared every
row returned by the interactive observer query with the ingested rows.

| Windows access to the fixture process | Handle rows | Logging rows | Observed result |
| --- | ---: | ---: | --- |
| Limited query allowed, set-information denied | 54 | 11 | Nine user-mode attempts stopped at the control open with Win32 error 5. Two explicitly opened watches each submitted one request to the private pipe. Windows returned error 1 with zero reply bytes. |
| Limited query and set-information denied | 24 | 0 | Identity qualification stopped each request before control. |

Within each of the two watches, a second call to the watch enable path submitted no further control request.
Removing the watch produced no cleanup request. Re-adding the same PID produced
a new acquisition ID and a new retry diagnostic. Replacing the pipe connection
rejected the old epoch before transport. In the separate native run the
control handle opened, and both information classes returned `0xC0000022`.
KMON recorded both results and acquired no cleanup ownership.

Sixteen additional disposable controllers repeated the watch cases under the
two access profiles. Each run checked the two independent watch admissions,
the overlapping manual removal and shutdown, and the observer query output.

Eighteen data-only driver replies and five native status samples covered the
legacy mask, wrong subject, inconsistent lengths or flags, pending status
and other unconfirmed results. An isolated journal retained 64 rows after an
overflow, reported six rows lost between ingests and did not replay an older
snapshot. Actual logging success on a kernel device, final target settings,
ETW delivery and coordination with other logging clients remain unverified.
Run `python tools/test-process-handle-observer.py --exe x64/Release/KnLiveDbg.exe`
with 64-bit Python to reproduce these cases.

On this Release build, the analysis and discovery scheduling oracles passed
6,742 and 70,170 checks. The console passed 570 checks and the command suite
passed 3,081 checks across 261 routes. From 20:47 to 21:01 KST on November 21,
the host logged no new reboot, bugcheck or crash dump. The final check found
zero remaining test processes, test drivers or fixture listeners.

## Watched process identity and logging cleanup, 2026-11-19

The Windows x64 Release controller had SHA-256
`24fb0b9e49ea20ef3b08fa8d542d2e319c070d9fa57bd8b5e98e6f50778de94e`.
A parent ran 23 watch cases per access configuration. It independently
checked the child controller's creation time and Windows access results.
The parent retained a query handle to a second, already-exited process.
The control cases used only the controller itself, with set-information
access denied and an unopened driver device.
[Watch handle sites and cleanup evidence](TIMELINE_COMMAND_USAGE.md#inspect-process-handle-ownership)

| Access to the controller | Timeline and KMON observations |
| --- | --- |
| Limited query allowed | 36 handle rows. Overlapping name, child and logging entries shared one open and close. The original generation qualified for a control attempt. Windows denied the control handle with error 5 and the cleanup event recorded `unconfirmed`. |
| Limited query denied | 17 handle rows. The wildcard watch kept its uncertain entry. A requested release for a known generation reported `open_failed` and `not_attempted`. |

Before the guard, pruning a watch with no successful logging request,
including one with only a failed request, attempted a control open. A
creation-time mismatch and shutdown with an unknown generation did the same.
Windows denied each of those opens in the reproducer. On the final binary,
all four cases made zero control opens. The exited process lost its promoted
membership while its explicit PID watch remained. For a missing PID,
Windows and the handle journal both reported error 87. A successful logging
record for the current generation survived pruning when a failed record for
the same PID named a different generation.

In the event-withdrawal case, the test waited for the monitor to record a
process-create event, withdrew the name watch, then let promotion continue.
The PID stayed outside the watch. Two callers also started manual removal
and shutdown at the same barrier. They consumed one earlier successful
request and produced one cleanup receipt. Sixteen more disposable controllers
repeated both overlap cases across the two access configurations. The fixture
supplied the earlier logging records and synthetic create events. Actual target settings,
driver acknowledgments and independent logging clients remain unverified.

Run `python tools/test-process-handle-observer.py --exe x64/Release/KnLiveDbg.exe`
with 64-bit Python to reproduce the watch cases.

The analysis and discovery scheduling oracles passed 6,742 and 70,170 checks
with the Release controller and a freshly built standalone core. The controller
passed 3,081 command checks across 261 routes and 570 console checks. From
01:43 to 02:20 KST, the host recorded no new reboot or bugcheck events or
crash dumps. The final check found zero remaining test processes, running test
drivers or fixture listeners.

## Process handles during verification and capture, 2026-11-19

The Windows x64 Release controller had SHA-256
`5bd91d5d64d6c31459513fb65a0f214a537c0db37322226c1e1c21f8f07a963c`.
A parent process measured the PID and creation time of each disposable
controller and independently tried both access masks. The controller used its
own process, one ordinary data byte and an unopened driver device.
[Observer handle sites](TIMELINE_COMMAND_USAGE.md#inspect-process-handle-ownership)

| Windows open results for `0x410` and `0x1000` | Timeline rows | Capture of the owned byte |
| --- | ---: | --- |
| Both allowed | 16 | The matching generation returned the original byte. The stale request skipped the region query. |
| VM read denied, limited query allowed | 22 | The matching request attempted the region query and returned zero bytes. The stale request skipped the query. |
| Both denied with Win32 error 5 | 13 | Both requests skipped the region query and returned zero bytes. Both failed opens kept their original errors. |

The totals include the PID-only diagnostic lookup. The parent checked the
access masks, outcomes, acquisition IDs and close order. A matching image
source linked its duplicate to the original open. A mismatched creation time
or two denied opens produced zero duplicates. In the reference verifier,
only a matching process with a usable handle reached the expected-PEB query.

Before the fix, recording two expired and two future-dated references made
eight handle calls. The same diagnostic for two submitted creation times
collapsed into one event with creation time zero. The final binary recorded
four separate time-rejection diagnostics with zero handle calls in each
access case. Two additional identity failures retained their respective
creation times. An explicit identity with an unknown creation time stayed
unknown on repeated submission.

The image, reference and capture scheduling oracles passed 968, 13,039 and
23 checks respectively. The separate handle fixture exercised the production
image-source binding with a declared four-level address space. Driver-delivered image
sweeps, native fallback and effects on other processes remain unverified.
To repeat the access cases, run
`python tools/test-process-handle-observer.py --exe x64/Release/KnLiveDbg.exe`.

The same binary passed 3,081 command checks across 261 routes, 570 console
checks and 28 timeline checks. From 01:01 to 01:29 KST the host recorded no
new reboot or bugcheck events or crash dumps. The post-run check found zero
remaining test processes, running test drivers or fixture listeners.

## Layout collection and verification handles, 2026-11-19

Windows x64 build 28000.3501 ran the Release controller with SHA-256
`8129c33f10c6fc51f50e96285d632d7e9badcc9cd765adac537796ea2167232b`.
The parent supervised a fresh controller for each case, independently tried
both Windows access masks and compared the exported handle rows with the PID
and creation time from its own handle to the child.
[Layout handle sites](TIMELINE_COMMAND_USAGE.md#inspect-process-handle-ownership)

| Access to the controller's own process | Observed collection |
| --- | --- |
| Query and VM read allowed | Two slices completed one sweep. Each opened the process with `0x410` and closed it. |
| VM read denied | Both `0x410` opens returned Win32 error 5. Both `0x400` retries succeeded and closed. The sweep completed. |
| Query denied | Both opens in the first slice returned Win32 error 5. The collector reported `process_query_unavailable` with zero stored regions or closes. |

In each run the parent queried one private guard page before the sweep and
after the collector returned. Its mapping, size and protection matched. The
child then explicitly cleared the guard and the parent observed the change on
the same page. These samples cover the guard flag on that page. The handle
receipts retain `effect_verified=false`.

The verification queue dispatched four candidates. Before the expiry fix,
all four opened and closed the process. With the fix, two current mappings
qualified, one creation-time mismatch was rejected after opening the process,
and one expired candidate made zero handle calls. The standalone test passed
an existing PID entry and an empty PID-only watch to the collector's next
slice. It reported `process_outside_scope` with zero new handle calls.
Boundary checks included the final valid millisecond, the next millisecond
and a future observation.

The Release standalone layout fixture passed 105,120 core checks and 1,017
queue checks. The combined scheduling oracle passed 7,835 checks. The
optional MSVC AddressSanitizer fixture compiled, but its Windows runtime
stopped at `interception_win.cpp:193` before the test body. Instrumented
execution and live driver delivery remain unverified.

The same Release controller passed 3,081 command checks across 261 routes
and 570 console checks. From 00:31 to 00:50 KST the host recorded no new
reboot or bugcheck events or crash dumps. The post-run check found zero
remaining test processes, running test drivers or fixture listeners.

To reproduce the access and guard cases, run
`python tools/test-process-handle-observer.py --exe x64/Release/KnLiveDbg.exe`
with 64-bit Python. The scheduling counts and serialized handle results also
come from `KnLiveDbg.exe --self-test layout-scheduler`.

## Process metadata collector handles, 2026-11-19

Windows x64 build 28000.3501 ran the Release controller with SHA-256
`4dcf5bb5ae31f02ede05e4239b9a59cb7abeddfb8a904b25004565875ec2584e`.
A parent process kept a handle to each test child and read its PID and
creation time. It read the controller's identity separately. The exported
rows identified the controller as the actor and the child as the requested
process.
[Collector sites and access masks](TIMELINE_COMMAND_USAGE.md#inspect-process-handle-ownership)

| Child state and permissions | Observed results |
| --- | --- |
| Running | All eight opens and eight closes succeeded across the TI, KMON and hunt lookups. A hunt request with a different creation time retained both generations in its handle evidence and published no image, session or package. |
| Exited with a reference held by the parent | All eight opens and closes still succeeded for the same child generation. TI returned no image name. Hunt returned no live image, session or package. KMON retained the generation obtained from the handle. |
| Synchronize access denied | The two TI opens and two package opens returned Win32 error 5. KMON and the three public hunt requests opened and closed their limited-query handles. |
| Limited query access denied | All eight opens returned Win32 error 5. Ingest produced eight failed-open rows with zero acquisition IDs, observed target identities or close rows. |

The session timing regression reproduced a PID-based lookup before the
process handle was opened. After the fix, the test observed the qualified
handle still open at each session lookup and compared the session ID with
Windows. The generation-mismatch and access-denial cases made zero session
queries. Actual PID reuse was outside this test.

Forty consecutive lookups of the same live TI image produced 80 open and
close calls. Ingest copied sequences 17 through 80, reported 16 evictions
once, and added zero rows on the second ingest. The target had no registered
package identity. The package lookup's positive result on a packaged target
remains unverified.

The same Release controller passed 3,081 command checks across 261 routes
and 570 console checks. After testing, Windows reported no new reboot or
bugcheck events or crash dumps. The post-run check found no remaining test
processes, running test drivers, fixture directories or fixture listener.

Run `tools/validate-runtime-capabilities.ps1` to build the policy fixture,
then use a standard Windows token to run
`python tools/test-process-handle-observer.py --exe x64/Release/KnLiveDbg.exe --policy-exe .build/runtime-capabilities/Release/runtime-capabilities-selftest.exe`.
The access restrictions applied only to a test child. TI checks exercised its
image resolver without enabling a trace provider. Other direct process
opens, independent target-effect measurements and a loaded driver remain
outside this evidence.

## Process handle ownership, 2026-11-18

Windows x64 build 28000.3501 ran the Release controller with SHA-256
`8eb21accfd421df3938b180f16835fdf7682baaa442193a7d0d49a68641cee7f`.
The checks exercised the restricted self-read, the shared identity lookup and
the handle-backed source. [Reading the handle timeline](TIMELINE_COMMAND_USAGE.md#inspect-process-handle-ownership)

| Check | Observed result |
| --- | --- |
| Consented self-read | The parent obtained the controller PID and creation time from its Windows process handle. Both matched the four timeline rows. The open requested `0x1010`, the duplicate inherited access, and the two successful closes identified their respective acquisitions. The read receipt contained the expected 32 bytes. |
| Access denied | A separate launch gave the child process a security descriptor that denied memory-read opens. The child exited 1. The report contained one failed open with Win32 error 5 and the requested process identity. It recorded zero acquired handles, reads, duplicates or closes. |
| Identity and close failures | A duplicate with the wrong requested creation time and a duplicate of an event object both failed to qualify as a process source. A different requested PID retained the observed PID and skipped its creation-time query. A disposable handle protected against close produced a failed close with the original acquisition ID. The test removed the protection and closed its handle. Borrowing a process handle for an identity lookup produced zero ownership rows. |
| Overlap and retention | Four workers held four observed references at the same time. Across 168 calls, 84 acquisitions and 84 closes succeeded. Ingest retained the latest 64 rows and reported the preceding 104 as evicted. Repeating ingest added zero rows. |
| Timeline interpretation | With an empty snapshot, controller rows produced zero missing-process findings. Adding a target process-create event produced one. A high-risk snapshot record with the controller PID still reported missing target evidence. Reimported rows carried `supplied_record`. A thread with the same PID inherited its image from the target process event even when an intervening observer row supplied another image. |

The independent checker can be run with
`python tools/test-process-handle-observer.py --exe x64/Release/KnLiveDbg.exe`.
To repeat the access-denied case with a standard Windows token, build the
fixture with `tools/validate-runtime-capabilities.ps1` and add
`--policy-exe .build/runtime-capabilities/Release/runtime-capabilities-selftest.exe`.
The command suite passed 3,081 checks across 261 commands, the console suite
passed 570 and the restricted launch suite passed 70. The process-source suite
also checked Windows handle counts before and after successful and rejected
sources. The managed callback close harness compiled. Post-run inspection
found no new reboot or bugcheck events or crash dumps. It found zero running
test drivers, test processes, fixture listeners or temporary test directories.
Other collectors that
open process handles directly, behavior with a loaded driver and independent
measurement of effects on a target remain outside this validation.

## Automatic live timeline startup, 2026-11-18

Windows x64 build 28000.3501 ran the Release controller with SHA-256
`f27afff1dc6dae80fdde5bc1676e6079f87aae7cb1d35c728d6ef5e6fd456088`.
This controller uses the existing timeline status and control requests.
The driver source and wire layout are those from `e338097`.
[Automatic and explicit startup](TIMELINE_COMMAND_USAGE.md#inspect-live-callback-control-results)

| Check | Observed result |
| --- | --- |
| Status before start | An independent hosted check compared 276,480 combinations of status-read success, wire size, flags, capacity, queue count, next sequence, dropped count and activation mode. Three inputs could submit a start. Another 138 could adopt an active collection. Every other input left the send count at zero for that attempt. |
| Two concurrent callers | The first caller read the idle flags and paused before returning them. A second caller requested activation on another device connection in the same controller. Together they issued one start and produced one control receipt. The second caller reused the collection. A separate test confirmed that adopting an active collection revoked the original caller's automatic stop. |
| Retained history and compatibility | The packaged test checked a stopped collection with pending events, a drained collection with a prior sequence, dropped events, and residual registrations. Each kept its history during the automatic start check. An idle collection with initial counters accepted both the legacy acknowledgment and the detailed response. |
| Windows I/O | A private named pipe rejected the status query. The controller returned the Windows error and recorded zero start requests. A subsequent explicit clear reached the pipe and produced its own error receipt. |

The command suite passed 3,081 checks across 261 commands, and the packaged
callback receipt check passed eight consecutive runs. The standalone
native-read and JSON checks passed 139 and 14 cases respectively. Post-run
inspection found zero new bugcheck events, reboot events or crash dumps,
and zero resident test processes, drivers or test listeners. The hosted
matrix uses a scripted device. The named pipe exercises Windows I/O. Running
with a loaded KnLiveDbg driver and tracing independent raw-device clients are
outside this evidence. The optional MSVC AddressSanitizer matrix stopped at
Windows interceptor initialization before evaluating a case.

## Live timeline callback control, 2026-11-18

Windows build 28000.3501 produced the following x64 Release artifacts.

| Artifact | SHA-256 |
| --- | --- |
| `KnLiveDbg.exe` | `5be46fc6139f3a469ed155fa6d22dff777b1290e844b151d0ac2a0a6798cef19` |
| `KnLiveDbg.sys` (WDK) | `65909d3a7dd057cf64b4ab08c14d8b632915626803e6440af5993857a4e9b213` |

The packaged controller and a user-mode fixture exercised the existing
ABI 17 timeline start, stop and clear requests. The extended response
records the driver's own callback registration state. Target process effects
require independent measurement. [Interpreting a control result](TIMELINE_COMMAND_USAGE.md#inspect-live-callback-control-results)

| Check | Observed result |
| --- | --- |
| Registration and cleanup | A scripted start made eight calls. Thread registration failed, then process removal failed during rollback. The exported row preserved both native errors, the call order, each pair of kernel timestamps supplied by the fixture, and the residual process registration. A later stop retried the remaining registration. |
| In-flight delivery | A hosted callback announced entry and held completion. Stop disabled delivery before attempting removal. The removal waited for the held callback, then the test observed the final ownership mask reach zero. |
| State transitions | A separate Release-hosted check exercised 1,179,648 combinations of initial state, requested action and scripted DDI results. It compared the fixture's owned registrations at each transition with the published flags and validated the resulting detailed response. The longest path used eight calls. |
| Caller compatibility | The tests exercised a short buffer, missing acknowledgment, malformed or stale details, legacy acknowledgment, and device close and reopen. Automatic KMON rollback required a verified fresh start on the same device connection. Another live control submitted by the controller invalidated that authority. |
| Windows I/O and CLI | A private local named pipe rejected the controller's clear request with Win32 error 1. Two invocations of `!timeline ingest observer` produced one event with that code and zero returned bytes. Reopening the same pipe path gave the client a new device epoch. A stop submitted with the old epoch produced no additional I/O or receipt. |

Run `KnLiveDbg.exe --self-test callback-ownership` to exercise the packaged
controller. Eight consecutive runs of the JSON check matched the scripted
calls and native failure, and found each temporary directory empty.
[JSON receipt check](../tools/test-timeline-callback-receipts.py)

The command suite passed 3,081 checks across 261 commands. The console passed
569 checks, and the compiled capability contract covered 53 sources.
The standalone native-read regression passed 139 checks and its JSON test
passed 14 observations. The MCP catalog, observe HTTP, legacy HTTP and
timeline suites passed 154, 98, 29 and 28 checks respectively. Restricted
launch checked 70 CLI results. The post-run inspection found zero new
bugcheck or reboot events, crash dumps, resident test processes and test
drivers during this validation window.

The host ran without a loaded KnLiveDbg driver. Live process, thread and
image notification delivery, last-handle cleanup and kernel unload under
load still need a provisioned driver test host. Repeated removal failures
can keep unload pending while the driver owns a registration. Both optional
MSVC AddressSanitizer runs stopped during Windows interceptor initialization
before the first test case.

## Separate MCP evidence and operation access, 2026-11-18

Windows x64 build 28000.3501 ran Release binary SHA-256
`2a81097202345c1af0d50fb4b2f46abcdd8d53ca675271eaf5e0cbd3fe53107d`.
The locally built Release executable for the preceding `main` commit,
`eda1d46`, created a source-scoped receipt in a private journal. The new
binary reopened that journal and ran the following checks through a loopback
HTTP listener with synthetic retained rows.
[Client setup](MCP_SETUP.md#choose-evidence-or-operation-access)

| Check | Observed result |
| --- | --- |
| Three clients | The evidence-only client saw the timeline query, the operation-only client saw the receipt lookup, and the default client saw both. The two evidence readers received 64 calls each. The operation reader received no evidence allocation or source label. |
| Query responses | Target and source evidence readers received the authorized rows. The test checked structured content, text entries and MCP metadata for receipt exposure. Success, a dispatched read past the real HTTP timeout, and a forced journal replacement failure all withheld the operation ID. |
| Recovery | The operation reader recovered its complete pre-upgrade receipt. An independent DPAPI decryptor confirmed the historical record survived subsequent writes. When the operator later granted operation access to the original evidence reader, that client recovered its own completed and unknown-outcome records with a fresh target handle. Access checks rejected another owner, a changed target grant and the previous listener's handle. |
| Local records | The audit retained its correlation ID. New scoped journal entries recorded the access at admission. The audit and decrypted journal checks searched for the original bearer values, fingerprints and target handle. |

The full command suite passed 3,080 checks across 261 commands. The standalone
Release ledger passed 40 checks and the independent JSON oracle passed 12 state
records. The optional MSVC AddressSanitizer runtime stopped in Windows
interceptor initialization before the ledger checks. The integration fixture
used the existing controller's retained store and exercised volatile and
private-journal listeners on loopback.

## Expiring TI process-lifetime grants, 2026-11-18

Windows x64 build 28000.3501 ran Release binary SHA-256
`2fb0933502133884cc9c7fd9124d5f447fd3c5021d1de7513419ba4fb6b40981`.
The fixture used synthetic TI records with the production timeline, HTTP.sys
loopback listener and DPAPI journal. Live TI collection and a loaded debugger
driver were outside this run. [Client setup](MCP_SETUP.md#grant-access-to-one-process-lifetime)

The subscriber test exercised the TI provider GUID, a different provider GUID,
creation-time equality and records with missing or invalid times. The
production decoder grants lifetime provenance only for a matching provider
and a validated creation time at or before the event timestamp.

| Boundary | Observed result |
| --- | --- |
| Evidence identity | The client authorized for the first lifetime received two header rows. A second client with the same PID and a different creation time received one. A different boot, a payload peer, incomplete identities, a predating event and a matching imported label contributed zero rows to the first client's count and scan cost. Eviction and clear removed its entries. |
| Operator discovery | The command dispatcher listed 65 retained lifetimes in pages of 64 and one. It rejected a malformed continuation and returned an empty list after clear. |
| Expiry and renewal | The fixture observed the lease expire while queued, after dequeue and after an actual read. Each caller received `target_session_unavailable` without an operation ID or payload. The first two receipts charged zero examined rows, the last charged one, and all three charged zero payload bytes. Reinitialization rotated both handles and preserved the allowance. |
| Receipt ownership | An independent decryptor reproduced the owner, target-generation and request HMACs. Recovery worked under a new controller generation for the same grant. Changing the boot, PID, creation time or bearer, or reopening with a source-only grant, returned `not_retained`. Audit and journal checks searched for the fixture's original bearer, fingerprints, boot ID and handles. |

The complete command suite passed 3,074 checks across 261 registered commands.
The compiled capability contract covered 53 sources and the support matrix matched.
The standalone Release ledger passed 40 checks and its JSON oracle passed 12
state records. The optional MSVC AddressSanitizer runtime stopped in Windows
interceptor initialization before the ledger tests ran.

## Source-scoped MCP observation, 2026-11-18

The Windows x64 Release checks used an HTTP.sys listener on loopback and a
controller fixture with interleaved retained rows. The fixture exercised the
product's listener configuration, queue, dispatch, timeline store and optional
private journal. It did not open a debugger device or load a driver.
[Client setup](MCP_SETUP.md#give-each-client-one-retained-source)

Windows build 28000.3501 ran Release binary SHA-256
`36a4c9d1f626c6f20062a9877cf459bd3f4cb6dd0454bfca5d059908aba21681`.
The complete suite passed 3,057 command checks across 261 commands. The MCP
catalog, shared observe HTTP, legacy HTTP and timeline suites passed 150,
98, 29 and 28 checks respectively. Restricted launch checked 70 CLI results.

| Boundary | Observed result |
| --- | --- |
| Authentication and discovery | Separate client bearers received distinct protocol sessions. The operator unlock password, a fingerprint presented as a bearer, an unknown bearer and a foreign session failed. Reinitializing one client preserved the other's session and both balances. Discovery exposed two tools and one resource. |
| Evidence and cost | Of five rows across four source labels, the two authorized clients saw two rows and one row respectively. Case and prefix variants were excluded. Scan charges counted only the granted source. Raw evidence, summaries and global event IDs were absent. Capacity shrink, subsequent eviction, duplicate ingestion and clear produced the expected counts. Oversized labels appeared as `null`. |
| Per-client ownership | A valid foreign operation ID returned the same fields as an unknown ID. This held for live and recovered records, including a changed source or replacement credential. Clients sharing one source had independent receipt access. Sixteen grants were accepted and a seventeenth was rejected. Exhausting one client's requested-event budget left the other able to query. |
| Recovery | An independent Python reader decrypted the owned fixture and reproduced each keyed owner ID and request hash. After controlled process termination, only the owner could read the cancelled-before-dispatch or unknown-after-dispatch record. Reordering grants preserved access. Shared and source-scoped journals refused cross-mode opens. The shared-mode regression also recovered 256 of 257 admissions. |

For pre-response interruptions the fixture captured the operation ID at the
queue checkpoint. A client that loses its ID cannot look it up by request ID.
The Windows PowerShell provisioning example generated separate credentials
and printed only their fingerprints. The bridge test used a substitute
`npx` to inspect its argument boundary and rejection paths. The external
package's pinned header substitution example was checked separately.

During validation the existing process-output fixture reached its five-second
deadline before its short lines filled the 64 KiB allowance. A diagnostic
built from the same capture functions distinguished this from the one-second
silent-child timeout. The fixture now emits 2,048-character lines. It keeps
the original limits and assertions. The standalone operation ledger passed
40 Release checks and the independent JSON oracle checked 12 records. The
MSVC AddressSanitizer build stopped during Windows interceptor initialization
before running the ledger tests.

## Private MCP operation recovery, 2026-11-18

The Windows **28000.3501 x64** Release executable had SHA-256
`3df699bc09d9d071b5ccc097e299f82d0c438ac81eca9cccf4197758eaad90d2`.
The process fixture ran the product's authenticated loopback HTTP listener,
queue, journal and retained timeline reader. The test created private
directories under its temporary directory and reopened them across processes.
[Private operation recovery](MCP_SERVER_DESIGN.md#private-operation-recovery)

| Boundary | Observed result |
| --- | --- |
| Abrupt controller exit | After the test observed admission, it terminated the controller. The reopened receipt reported cancellation before dispatch and zero scan and result charges. After a real 30-second HTTP wait and termination following dispatch authorization, lookup by the returned ID reported an unknown outcome with unsettled charges. |
| Return and restart | Completed success and failure receipts survived process restart. A return that arrived after the HTTP timeout was visible in the next process with its original ID, times and charges. A separate handler finished after its listener was stopped and reopened in the same process. The old receipt stayed unknown and the new listener's allowance stayed full. |
| Failed storage | A file handle prevented replacement of the journal during admission, dispatch and return. Each failure reached the client as `journal_unavailable`. The committed image stayed byte-identical. Reopening it recovered the last persisted phase. A second writer, wrong password, missing file, damaged file, hard-linked file and a sealed image copied into another private root all failed to open. |
| Privacy | An independent Python reader decrypted the owned fixture through Windows DPAPI, inspected its metadata and reproduced the request HMAC. Neither the original filter nor the password was present in the decrypted records. The ordinary audit's operation object contained only ID and state. |
| Retention | Three listener lifetimes admitted 257 successful operations. A fourth listener recovered the newest 256 by ID and reported the first as `not_retained`. Those lookups consumed zero engine admissions. The test checked that every fixture port stopped accepting connections and its temporary directory was removed. |

The standalone Release ledger passed 40 checks, including storage exceptions
at admission, cancellation, dispatch and completion. The Python oracle checked
12 serialized records. MSVC AddressSanitizer stopped at
`interception_win.cpp:193` before the ledger harness entered `main`.
Instrumented execution remains unverified on this host. The product linker
also emitted the existing C4744 warning for `KmonHuntIndex::NextQueryEpoch`.

The full product self-test passed, including 3,050 command checks across
261 registered commands. The MCP tool, observe HTTP, legacy HTTP and timeline
suites passed 150, 98, 29 and 28 checks respectively. Restricted launch
passed 70 CLI results. The capability inventory passed 53 contracts and its
support matrix matched. From 11:31 to 12:09 KST the boot timestamp, monitored
services and firewall profiles matched the baseline. There were zero new
bugcheck or unexpected-restart events and zero new crash dumps. The final
host check found no test processes, loaded project drivers, owned temporary
fixtures or HTTP registrations on the regression port.

These tests exercised controller termination on one Windows host.
Physical power loss, hostile restoration of an older file,
separate remote principals and live driver effects require other evidence.

## Cumulative MCP observe budgets, 2026-11-18

On Windows **28000.3501 x64**, the Release `KnLiveDbg.exe` had SHA-256
`9bc72b570cba8b98e4f0ab3112c7f38c77d152a557eaad926326870494cd6c14`.
The fixtures used retained events in memory and an authenticated HTTP.sys
listener on loopback port 51768. [Observe listener budget](MCP_SERVER_DESIGN.md#observe-listener-budget)

| Boundary | Observed result |
| --- | --- |
| Admission | Two concurrent requests asked for the last 64 event slots. One entered the queue. Cancelling it kept its admission charges and settled its scan and result costs at zero. Busy queues and a ledger full of unfinished jobs consumed no allowance. The fixture reached exactly 128 admitted calls. |
| Retained-event scans | Timeline, graph and status queries against a 4,097-event store consumed exactly 65,536 visits. Nonmatches and graph lookahead counted. An incomplete query returned a typed denial and withheld its data, including when the last query had only 4,095 visits left of its 4,096 maximum. |
| Result size | Multibyte UTF-8 fixtures exercised the 64 KiB result limit and the 1 MiB listener limit. An oversized result exposed no original payload and charged zero bytes. A subsequent result fitting the exact remaining balance succeeded. |
| Timeout and lookup | A running request outlived a two-second wait. Its first receipt reported unknown costs. When its oversized result arrived, `operations.get` reported one examined event, zero result bytes and a publication denial. A separate HTTP request finished after its 30-second wait and charged its 16 result bytes once. |
| Listener lifetime | A second `initialize` retained the first client's usage. At 1,024 requested event slots, the next timeline request received a denial before admission and earlier receipts remained readable. A job that finished after stop and restart left the new listener's four counters at zero. |

The MCP tool, observe HTTP and legacy HTTP suites passed 150, 98 and 29
checks respectively. The standalone Release operation ledger passed 35 checks,
and the Python oracle verified 12 serialized records. The MSVC AddressSanitizer
runtime stopped at `interception_win.cpp:193` before the ledger harness entered
`main`. Sanitized ledger execution on this host remains unverified. The Release
linker emitted the existing C4744 warning for `KmonHuntIndex::NextQueryEpoch`.

The full product self-test passed, including 3,048 command checks across
261 registered commands. The restricted-launch suite checked 70 CLI results
and the timeline suite passed 28 checks. The capability inventory passed
53 contracts across 261 command routes and matched the published support matrix.
Between 10:41 and 11:17 KST, the boot timestamp, three monitored services and
three firewall profiles matched the baseline. There were zero new bugcheck or
unexpected-restart events and zero new crash dumps. The final check found zero
listeners or HTTP registrations on port 51768, owned test processes, loaded
project drivers or leftover fixture files in the checked locations.

These checks cover listener accounting and retained queries. Live driver
or service status, kernel collection costs, per-principal authorization and
recovery of operation records across restarts require separate evidence.

## Loopback MCP observe sessions, 2026-11-18

On Windows **28000.3501 x64**, the Release `KnLiveDbg.exe` had SHA-256
`acb7cace985c0c3fcc96061353eb742a2487be5b0ae9711a932437e7229331fc`.
The HTTP fixtures used an authenticated HTTP.sys listener and a WinHTTP
client on loopback port 51768. [Observe session contract](MCP_SERVER_DESIGN.md#observe-sessions-on-current-main)

| Boundary | Observed result |
| --- | --- |
| Discovery and authorization | `--self-test mcp-observe` passed 55 checks. Discovery returned five tools, four resources and an empty prompt list. Requests for capture, export, collection control, unknown names and over-budget queries produced no queue work. The scope survived a repeated start and a stop request before the listener joined. |
| Retained reads | The loopback client received a timeline result and a completed operation receipt. In a separate 70-event store, `mcp-tools` checked default count, oldest/newest selection, filters, graph truncation and the 64-event limit. The event count and next ID stayed stable. The suite passed 139 checks. |
| Audit and transport | A stale session ID was refused. The request audit retained the policy decision and omitted the test argument marker, bearer password and protocol session ID. The legacy HTTP suite passed 29 checks, including its 68-tool and eight-resource discovery contracts. |
| Operation ledger | The standalone Release harness passed 25 checks. A Python oracle verified seven serialized states. The MSVC AddressSanitizer runtime stopped during interceptor initialization before the harness entered its tests. Sanitized execution on this host remains unverified. |
| Regression and cleanup | `--self-test all` passed, including 3,048 command checks across 261 registered commands. The restricted-launch regression checked 70 CLI results. After the tests, port 51768 had zero listeners and HTTP registrations. The owned fixture directories and audit files were gone. The boot timestamp and firewall profile settings matched the baseline. There were zero new bugcheck or unexpected-restart events and zero new crash dumps. |

The HTTP fixtures supplied synthetic engine jobs and used the real retained
timeline reader. Live driver and service status, per-principal isolation,
protected remote transport and cumulative collection budgets require separate
evidence. The Release linker also emitted the existing C4744 alignment warning
for `KmonHuntIndex::NextQueryEpoch`.

## Restricted offline and observe launches, 2026-11-18

On Windows **28000.3501 x64**, the Release `KnLiveDbg.exe` had SHA-256
`55001e7a92e9668d4905fcf99d0cef9be373e0b4178858824954e2e382bb51d2`.
The [launch regression](../tools/test-restricted-launch.py) checked 70 CLI
results through that executable.

| Boundary | Observed result |
| --- | --- |
| Dispatch before startup | Both modes refused the controller, collection, worker, mutation, MCP and remote requests tested. The two remote requests produced zero accepts at the loopback listener. The requested evidence store was absent. A misplaced selector returned a policy diagnostic before a legacy self-test could run. |
| Saved trace | The documented cmd.exe invocation and the inherited-handle query reproduced the legacy page, SHA-256 and cursor. A changed page limit invalidated the cursor. Replacing the pathname after opening the file preserved the original input. The parent's file position stayed at byte 7. |
| Input authority | A metadata-only handle, open writer, alternate stream, offline-marked file, NUL device and silent pipe were refused. A valid trace padded to exactly 2 MiB retained its digest. One extra byte made the same record unavailable. |
| Observe consent | The reported PID matched the launched process. The receipt charged one call for the 32 expected bytes and recorded possible residency effects. The native probe remained unattempted. Omitting consent, adding another argument or requesting the same read in offline mode was denied. |

The legacy trace oracle passed 93 controls. The standalone capability policy
passed 29 checks and reference blobs passed 26 checks plus their SHA-256 oracle.
The unprobed capability inventory reported 52 contracts and 261 command routes.
Its generated support matrix matched the checked-in copy. The full product
self-test passed, including 3,043 command checks across 261 registered routes.
At 09:46 KST the boot time and monitored services and firewall profiles matched
the 09:29 baseline. The system log showed no new bugcheck or unexpected restart.
There were no new dump files or remaining task processes, loaded drivers or
launch fixture directories in the checked locations.

These results cover the selected one-shot CLI operations on this host.
Kernel-side collection authority, authenticated remote sessions and durable
operation recovery remain open. The run used local NTFS fixtures and loopback
connection refusal. Deployment on network or cloud-backed storage and
system-wide egress isolation require separate evidence.

## Registered Windows acquisition attempts, 2026-11-18

On Windows **28000.3501 x64**, a pre-registered campaign reserved six slots.
The frozen snapshot contained five admissions, three job-bound workers and
four terminal outcomes. One admission had an unknown outcome and one slot
had never been admitted.

| Outcome in the frozen registry | Slots | Verified packages |
| --- | ---: | ---: |
| Published and passed | 1 | 1 |
| Executable unavailable before launch | 1 | 0 |
| Executable content differed from the plan | 1 | 0 |
| Supervisor and worker termination independently observed | 1 | 0 |
| Admitted with no terminal receipt or independent witness | 1 | 0 |
| Unadmitted | 1 | 0 |

Success was **1/5 per admission** and **1/6 per planned slot**. Evidence
survival was **1/1 acknowledged package**. That package reproduced 12/12
fixed and 20/22 changing process generations. A copy of the same snapshot
with its package missing still accounted for all six slots and five
admissions. It reported **0/1** evidence survival and withheld process metrics.

The successful run's job accounted for **42 processes**, with zero active
at the final query. It recorded 6.84375 seconds of user CPU, 2.625 seconds of
kernel CPU, 342,085,632 bytes of peak job memory, 99,298,082 bytes read and
1,412,265 bytes written. Admission to the terminal receipt took 19,844 ms.
These figures cover the assigned worker and descendants on this host.
Collector-only cost and incremental overhead require paired measurements.

The interruption controls waited for a live native observer and Python
subject in the worker's tree. Both supervisor terminations released the
pinned worker and descendants. The campaign credited owner loss only for
the slot whose independent observer recorded both original process handles
signaling. A separate 50 ms deadline terminated its job and recorded zero
active processes. An invalid executable retained Win32 **193** in the fixed
workload phase and the worker's OS exit code **3**.

The Release core validation passed. Campaign checks exercised concurrent
admission, a writer killed with an uncommitted SQLite transaction, frozen
snapshots before and after interruption, a valid package from another ticket,
and missing or altered evidence. Existing imported declarations, standalone
package replay and private publication checks passed. The [campaign contract](BENCHMARK_CORPUS.md#register-and-evaluate-repeated-acquisitions)
describes custody, outcome classification and measurement scope.

Core harness SHA-256 `229430912cc9021a9a6d75c234ab2e204b96475472fe6b5f6c11eccd7d744a7e`.
The **09:04 KST** host check found the same boot time as the pre-run baseline,
zero new BugCheck or unexpected restart events, zero new dumps and zero
remaining task processes or drivers. Monitored services and firewall profiles
matched the baseline. The temporary publication files and SQLite recovery
files had been cleaned up.
P16 remains open for calibrated overhead, externally grounded heldout
samples and independent tool comparisons.

## Offline replay of owned Windows module acquisitions, 2026-11-18

On Windows **28000.3501 x64**, a Release core observer recorded two owned
process workloads. After all children and the observer exited, the offline
evaluator opened the package using the pin returned at collection. It verified
the executable and controller bytes, reconciled each readiness witness with
its process handle and matched the two original observer streams to the
controller's request windows.

| Workload | In-scope generations | Admitted | Observed / all | Observed / observable | Unavailable | Missing | Successful walks / attempts |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Fixed | 12 | 12 | 12/12 | 12/12 | 0 | 0 | 128/128 |
| Changing | 22 | 21 | 20/22 | 20/20 | 1 | 1 | 127/128 |

The missing child exited before the first census. The unavailable child
exited between selection and dispatch. Both appear in the end-to-end
denominator. Each workload had one outside-job control, 16 censuses and zero
active job members after cleanup. Separately pinned observer and target
handles both signaled after abrupt controller termination. Repeated replay
of the final package produced byte-identical output.

The Release core validation passed, including the acquisition and replay
gate. Eight replay tests covered altered package contents, file sharing,
concurrent and interrupted writes, evidence ordering, generation fences,
failed attempts, terminal per-generation records and CLI error handling.
The original summary and private trace CLI modes also passed. The imported
evaluator passed 13 tests and the publication checker passed 14. A synthetic change to one fixed generation's
walks produced 11/12 end-to-end and 11/11 observable recall with one error.
The pre-revision JSON parser accepted 1,500 nesting levels on this Python
runtime. The shared decoder now enforces 128.

Core harness SHA-256 `1edbcab7993b61ed23ecead1262c1a302da63c3d45f51d362ff5d926d7be7b46`.
At **08:28 KST** the host retained its previous boot time, with zero new
BugCheck or unexpected restart events, new dumps, running task processes,
running task drivers or benchmark temporary files. The monitored services
and firewall profiles matched the pre-run baseline.
The recorded results cover one correlated owned development run. The
[replay contract](BENCHMARK_CORPUS.md#replay-an-owned-windows-acquisition)
defines the unit, evidence references and failure denominators. External
sample provenance, heldout evaluation, overhead measurements and independent
tool comparisons remain open under P16.

## Owned Windows process module workloads, 2026-11-18

On Windows **28000.3501**, an independent controller measured native Toolhelp
module observations for two private jobs. Each workload ran 16 inventories
with at least 25 ms between an admission and the next census. Child processes
reported their readiness, creation time, executable base and exit. The observer
used the shared module reader and scheduling code. A successful walk matched
the child's executable base and generation and reached normal enumeration end.
The [workload design](ARCHITECTURE.md#measuring-module-observation-intervals-on-windows)
defines the cohort, clock and censoring boundaries.

| Workload | Ready | Admitted | Observed at least once | Successful walks / attempts | Successful revisit intervals |
| --- | ---: | ---: | ---: | ---: | ---: |
| Fixed | 12 | 12 | 12 | 128 / 128 | 116 |
| Changing | 22 | 21 | 20 | 127 / 128 | 107 |

| Workload | Ready to first P99 (ms) | Admission to first P99 (ms) | Revisit P99 / maximum (ms) | Longest interval including lifetime boundaries (ms) |
| --- | ---: | ---: | ---: | ---: |
| Fixed | 3,718 | 63 | 156 / 156 | 3,718 |
| Changing | 5,734 | 875 | 1,375 / 1,375 | 5,734 |

The tables report one recorded run and use nearest-rank percentiles. Ready
time includes the wait while the controller starts the rest of the cohort.
The changing population included one exit before any census and one after
selection but before the scheduled read. Both lifetimes contributed to the
longest-interval calculation. Survivors contributed a right-censored tail
up to the workload cutoff. Three previously observed processes exited during
the changing workload and new processes joined. Each job had zero active
processes after cleanup. When the controller was forcibly terminated with a
cohort pending, an external supervisor confirmed termination of both the
observer and target using their original process handles.

The Release product's isolated `--self-test all` passed **3,043 command checks
across 261 routes**, with fixture cleanup and an empty working directory.
The `/W4 /WX` core suite passed the native workloads and the existing **817**
module-debt assertions. Public-content regression passed **13 tests**,
including renamed and partially written private workload transcripts.

Release product SHA-256 `c0dbb5a25db3c60ce1281ae56b6732409ada3f43470f8ed67072a0ad8679cf7f`. Core harness SHA-256 `601809e7d96200681ab83dd5dc7fb5e084f9c4b73289b83e01abdc6a762bdb24`.
Read-only host checks at **07:43 KST** found the previous boot time, no
new BugCheck or dump, and no running task process or driver. Service and
firewall state matched the baseline. The earlier ASan startup failure on this
host still limits sanitizer coverage.

P09 remains open for end-to-end discovery under host load, durable publication,
other sources and workload-specific SLOs. The observer ran in the core harness
with declared tiers and pacing. These measurements cover that workload.

## Process module observation debt, 2026-11-18

Current main schedules overdue Toolhelp module observations by process
generation. Successful observations require a complete module walk and a
matching generation before and after the walk. The census, acquisition and
retry rules are described in the [scheduler design](ARCHITECTURE.md#process-module-observation-debt).

On Windows **28000.3501**, the Release product and the `/W4 /WX` core harness
passed these checks.

- An independent model passed **817 assertions** on pending work, first
  observation, successful revisit, timing buckets, capacity loss and slot
  selection. It checked the production 12,288-generation ceiling, conflicting
  pins, PID reuse, access denial and cancellation. An unsupported generation
  stayed out of the extra slot after a later failure or invalid clock. A
  successful ordinary visit restored eligibility.
- Each synthetic workload ran **80 inventories and 640 visits**, including
  partial and capped inventories. All 16 offered slots in each run entered an
  inspection within the existing priority quotas. The model independently
  calculated the intervals below from acquisition times.

| Synthetic workload | First observations | Successful revisit intervals | Longest successful revisit (ms) |
| --- | ---: | ---: | ---: |
| Fixed | 24 | 536 | 59,990 |
| Growing | 92 | 481 | 170,000 |

- The product passed **25 native deep-inspection controls** and **21
  independent module-observation checks**. A real Toolhelp snapshot contained
  the test process's executable under the pinned creation time. A second
  acquisition produced one revisit. Mismatched inventory generations received
  no success, and cancellation preserved the prior receipt. Exceptions before
  and after acquisition produced
  the expected source outcomes, and the process handle count returned to its
  starting value.
- Inventory admission, deep scheduling and discovery passed their existing
  core checks. The Release binary passed the support-matrix check and isolated
  `--self-test all`, including **3,043 command checks across 261 routes**.
  The suite cleaned up its fixtures and left its working directory empty.
  Public-content regression passed **12 tests**.

Release product SHA-256 `b3fbcfda903509aa726a57425d8e5cdb0f92877e8cc6d022eb3ad71a26400c7b`. Core harness SHA-256 `8aefa91ae5910387cd5367a2385c584a4cbcb2a0dd907bcbb08a7f9fdef92fc5`.
Read-only host checks at **07:05 KST** found the previous boot time, no new
BugCheck or dump, and no running task driver or process. The service and
firewall settings matched the baseline. The previously recorded ASan startup
failure on this host still limits sanitizer coverage.

The native test covers the owned process. The scheduling intervals above use
a synthetic clock. P09 remains open for source-wide acquisition latency,
durable timing and the maximum unobserved interval on a measured host workload.

## Deep inspection above process inventory capacity, 2026-11-18

Current main reads the full process snapshot in bounded turns. On a complete
capped inventory, one PID from the snapshot, watch or suspect inputs receives
a deep slot within its existing priority quota. The first refused PID receives
that opportunity immediately. Later laps keep their initial upper PID so that
continued growth above it cannot postpone the return to lower PIDs. The cursor
advances when the reserved inspection passes its stop check. See the
[admission and inspection policy](ARCHITECTURE.md#deep-inspection-above-the-process-inventory-limits).

On Windows **28000.3501**, the Release product and the `/W4 /WX` core harness
passed the following checks.

- The independent full-population model passed **37,107 assertions in 12
  scenarios**. Fixed, growing and reordered populations ran for 96 inventories
  each with scaled limits of 8/14/18. The model checks the reserved PID, lap
  bound, eight-slot tier selection, ordinary cursors, PID reuse, partial walks,
  cancellation and faults. A displaced native row retained its pinned identity
  when a later watch or matching suspect admitted it.
- The inventory oracle passed **19,537 assertions**, including the production
  limits of **4,096 / 8,192 / 12,288**. It accounted for capacity events beyond
  the 32 recorded scopes and identified the displaced PID and generation after
  the sample filled. The existing deep and discovery core oracles passed
  **1,523 / 70,151** assertions.
- The product passed **13 native inventory / 17 deep dispatcher controls** and
  **6 / 28 independent checks**. A real Toolhelp walk with a single metadata
  slot returned the owned process with its pinned generation and image path.
  A deliberately rejected process generation spent its reservation on entry.
  An earlier callback and stop before entry preserved the previous position.
  Worker, analysis, reference, compiled-capability and support-matrix checks
  passed on the same binary.
- The isolated `--self-test all` passed, including **3,043 command checks /
  261 routes**. Its fixture cleanup passed and its working directory was empty.
  Public-content regression passed **12 tests**.

Release product SHA-256 `45f3af74edd5508835533bea488b3d0af0eaef72bd9d32ec71e10fa8f8ef7cea`. Core harness SHA-256 `20dd022a937f18422fcae4a1ec9e500c73e0a78a1d6076338ae482853d3d4c0f`.
Read-only host checks at **05:59 KST** found the previous boot time, no new
BugCheck or dump, and no running task driver or process. Service and firewall
settings matched the starting record. The previously recorded ASan startup
failure on this host still limits sanitizer coverage.

The 96-inventory runs used synthetic populations. A native inspection start or
generation rejection supplies an attempt time. Time to a successful observation
for each process generation and a maximum unobserved interval on a measured
host workload still require evidence. P09 remains open.

## Resumable deep process inspection checkpoint: 2026-11-18

After inventory and priority selection, user-hostility inspection now retains
the selected cohort and dispatches **one target per discovery turn**. The first
target waits for a new turn as well. Original selection time, target identities,
thread quotas and remaining work survive each return. Exceptions in a target
or its failure reporter cannot discard the tail. Returned, identity-rejected,
cancelled and faulted callbacks have separate counters and service samples;
none establishes target-qualified success. See
[resumable deep process inspections](ARCHITECTURE.md#resumable-deep-process-inspections).
This completes that implementation slice and does not complete P09 or the full
kernel-security design.

Review also moved layout-lead consumption after the process generation fence
following module enumeration. Rejected generations and earlier cancellation
retain their leads. Thread snapshot/process/thread handles now use automatic
cleanup on C++ exceptions. Stop, failed Start and restart release retained
cohort metadata after worker ownership ends. The existing attempt/cooldown
clock remains explicitly separate from successful target coverage.

Validation used Windows **28000.3501**, MSVC **14.44.35207** and SDK/WDK
**10.0.26100.0**, without loading a task driver or enabling Driver Verifier:

- The `/W4 /WX` shared-core build passed **13 deep-cohort scenarios** plus
  capacity/restart controls. The independent oracle passed **1,523 assertions**
  for exact per-target outcomes, original selection debt, one callback per
  turn, slow/faulting/rejected heads, failure-reporter exceptions, cancellation,
  reentrancy, clock reversal and outcome-specific timing distributions.
- The product passed **14 native controls / 25 independent assertions** using
  the actual discovery dispatcher. Two selected targets with deliberately
  wrong generations of the owned process are rejected in separate calls;
  the tail, original identities and layout leads remain intact between calls.
  Stop/restart and native thread snapshot/query paths leave the owned process's
  handle count unchanged. This checks generation rejection and thread-query
  ownership, not a complete successful deep inspection of a live target.
- Existing core inventory/discovery oracles passed **14,211 / 70,151
  assertions**, and the native inventory fixture passed **11 controls /
  4 independent assertions**. The worker fixture passed **15 controls /
  19 independent assertions**, including the separate native fixtures;
  its absent-binding worker still dispatches no native discovery phase.
  Product oracles passed **20 analysis / 968 image / 73 preparation /
  50 reference / 85 publication / 16 layout / 23 capture assertions** and
  **51 capability contracts / 261 command routes**. The support matrix matches
  compiled contracts. Public-content regression passed **12 tests**, including
  renamed UTF-8/UTF-16 private deep-cohort diagnostics.

The final isolated `--self-test all` passed **28 timeline / 102 MCP /
121 image-read / 319 image-scheduling / 39 preparation / 41 publication /
21 layout / 15 analysis-integration / 15 discovery-integration /
11 native inventory / 14 native deep-target / 564 console /
3,043 command-route / 68 remote / 4 connect-option checks**.
`owned_fixture_cleanup=passed` and the owned working directory was empty.
The final fixture scope field explicitly separates the worker's binding gate
from its nested native queries. Final review found no additional actionable
defects in the reviewed scope.

Final Release product SHA-256:
`06c783ef1c815da34f40d3851a375b0cfc50b3a9fe8c34819633b7ee14a16f8e`.
Shared KMON core harness SHA-256:
`dbc9e8a12e5011bc9efd3ac7860998865556cc645535188e1aa3667f174e8e5f`.
Existing C4244 conversion and C4744 alignment warnings remain. ASan remains
blocked by the previously recorded host startup interception failure; no new
ASan success is claimed.

Read-only host checks at **04:24 KST** found the same boot time and no new
reboot/BugCheck event, dump, task process, task driver, preparation/profile
receipt or owned writer/preparation temporary residue. The 33 completed parser
caches, BFE/mpssvc/EFS service states and firewall profiles match the preceding
checkpoint. No task driver was loaded and no Verifier, reboot or security
setting was changed during this stage.

These runtime diagnostics do not prove successful per-target debt, full native
inspection, individual native API latency, durable timing recovery or power
loss safety. A returned discovery phase can contain recorded target faults or
rejections. Native calls and within-target loops remain nonpreemptible. The
ordered user-group tail waits for its selected cohort, and snapshot admission
above the first 4,096 eligible targets is unchanged. Actual fixed/growing native
workload SLOs and whole-source maximum unobserved intervals remain open.

## Resumable user inventory checkpoint: 2026-11-18

The user-hostility inventory now resumes its owned Toolhelp snapshot, watched
PID queries and suspect merges across discovery turns, with a cooperative
**32-operation / 25 ms** allowance. `Continued` preserves the scanner phase and
original cycle due time while allowing other discovery groups to proceed;
continued service does not count as a returned scanner or completed cycle.
See [resumable user process inventory](ARCHITECTURE.md#resumable-user-process-inventory).
This completes the inventory slice and does not complete P09 or the full design.

Review retained the deep generation fence, pinned generation/path queries to
the same process handle, and prevented stale snapshot names from becoming
generation-bound image paths. It also fixed deletion of layout leads/page state
admitted while an older inventory was paused. Partial or unknown-generation
inventory results cannot retire pending layout leads. Stop, failed Start,
restart and exceptions close the retained snapshot. Truncation diagnostics now
state the actual deep-scan limit of eight targets.

On Windows **28000.3501**, MSVC **14.44.35207**, SDK/WDK **10.0.26100.0**:

- The `/W4 /WX` shared-core build passed, including **14 inventory scenarios**,
  **7 retirement controls** and the existing **369 discovery / 423 analysis /
  32,796 reference / 521 publication / 130 capture / 835 execution** controls.
- The independent inventory oracle passed **14,211 assertions** for exact
  target/generation contents, duplicate/excluded rows, all three capacity
  limits, fast/slow sources, partial walks, faults, cancellation, reversed
  clocks, operation bounds and handle ownership. The discovery oracle passed
  **70,151 assertions** across **17 scenarios**, including ordinary and
  overrunning continuations, exact distributions, original debt and peer work.
- The product passed **11 native inventory controls / 4 independent
  assertions**, using actual Toolhelp snapshots and read-only process queries.
  It verifies the current process's pinned path/generation, retained snapshot
  validity, cancellation, restart and actual Stop cleanup. Forced boundary
  clocks are synthetic; these controls do not establish a native latency SLO.
- The actual worker fixture passed **14 controls / 19 independent assertions**,
  including the separate native inventory fixture. Its absent-binding worker
  still dispatches none of the 26 native discovery phases. Product oracles
  passed **20 analysis / 968 image / 73 preparation / 50 reference /
  85 publication / 16 layout / 23 capture assertions** and **51 capability
  contracts / 261 command routes**. Public-content regression passed **12 tests**,
  including renamed UTF-8/UTF-16 private inventory diagnostics.

The isolated `--self-test all` passed **28 timeline / 102 MCP / 121 image-read /
319 image-scheduling / 39 preparation / 41 publication / 21 layout /
15 analysis-integration / 14 discovery-integration / 11 native inventory /
564 console / 3,043 command-route / 68 remote / 4 connect-option checks**,
with `owned_fixture_cleanup=passed` and an empty owned working directory.
Final review found no additional actionable defects in the reviewed scope.

Final Release product SHA-256:
`21ef24ad75785f674cf0d90ec36f0a22c75df375b69898386e4cd83e38334f02`.
Shared KMON core harness SHA-256:
`852a7c899022ce517dcbfcf3792396f3790409356f454129d6fce711d63be1fb`.
Existing C4244 conversion and C4744 alignment warnings remain. ASan remains
blocked by the previously recorded host startup interception failure; no new
ASan success is claimed.

Read-only host checks at **03:59 KST** found the same boot time and no new
reboot/BugCheck event, dump, task process, task driver, preparation/profile
receipt or owned writer/preparation temporary residue. The 33 completed parser
caches, BFE/mpssvc/EFS service states and firewall profiles match the preceding
checkpoint. No task driver was loaded and no Verifier, reboot or security
setting was changed during this stage.

Private inventory and discovery clocks are runtime diagnostics, not proof of
target-qualified success, individual native API latency, durable recovery or
power loss safety. Native calls and input copying can overrun. The ordered user
tail waits for inventory completion and up to eight synchronous deep scans.
Snapshot admission still favors its first 4,096 eligible targets; fairness above
that cap, finer deep-scan continuation, source-wide timing, fixed/growing native
workload SLOs and maximum unobserved intervals remain open.

## Resumable discovery scheduling checkpoint: 2026-11-18

The worker now rotates 26 scanner phases across ten discovery groups, preserving
each group's order and unfinished cursor. It gives discovery a cooperative
250 ms turn that includes interleaved analysis service, separately from the
initial analysis turn. Periodic due clocks and coalesced urgent requests remain
distinct. A request admitted during an active cycle survives completion, and a
repeatedly failing scanner cannot indefinitely restart its group's head. See
[resumable discovery scheduling](ARCHITECTURE.md#resumable-discovery-scheduling).
This completes that implementation slice; it does not complete P09 or the full
kernel-security design.

Review also isolated the initial analysis and discovery boundaries: a persistent
analysis exception previously prevented discovery from being called. Both
boundaries now run independently and retain the worker's idle delay after
exceptions. Cancellation between selection and actual scanner entry retains the
selected phase and its original cycle debt, instead of counting an unentered
scanner as returned. Clock reversal across turns cannot wrap partial-cycle
durations. Session reset clears the new state after worker join.

Private `kn.discovery_scheduling.v1` runtime diagnostics separate phase
attempts/returns/faults/cancellations, unfinished cycles, requests, due-to-first
dispatch, due-to-cycle return/failure and actual overruns. These are scheduler
clocks, not successful target revisits, native API latency or a durable timing
journal. A scanner can return with unavailable or partial source evidence.
Scanner-internal loops, nested analysis and native calls remain nonpreemptible;
the policy does not enforce a hard deadline or a whole-worker 250 ms bound.

Validation used Windows build **28000.3501**, MSVC **14.44.35207** and SDK/WDK
**10.0.26100.0**, without loading a task driver or enabling Driver Verifier.
The core harness built under `/W4 /WX` and passed **369 discovery checks**.
The independent discovery oracle passed **34,098 assertions** across 15 synthetic
rotation/flood/churn/binding, mid-cycle request, repeated-head-fault, slow-call,
analysis-yield-fault, stop/cancel, reentrant, clock-reversal, final-phase-overrun
and depletion scenarios. It independently reconstructs group/phase queues,
request retention, clocks, exact counters and ordered-sample histograms.

The product's actual worker passed **13 controls** and **19 independent
assertions** with an unopened device and owned mapper/user requests. The fixture
observes an actual completed worker turn before requesting stop and joining;
all 26 native discovery phases remain undispatched at the binding gate. The
actual scanner entry also rejects a raced stop before setup. This validates the
worker/gate boundary, not loaded-native scanner workloads or measured SLOs.
Affected product oracles passed **20 analysis / 968 image / 73 preparation /
50 reference / 85 publication / 16 layout / 23 capture assertions**.

The final isolated `--self-test all` passed **28 timeline / 102 MCP /
121 KMON image-read / 319 image-scheduling / 39 image-preparation /
41 publication-writer / 21 layout-scheduler / 15 analysis-integration /
13 discovery-integration / 564 console / 3,043 command-route / 68 remote /
4 connect-option checks**, with `owned_fixture_cleanup=passed`.
Existing shared-core controls passed, including independent **6,722 analysis /
12,989 reference / 2,394 publication / 10 execution assertions**. Compiled
capabilities passed **51 contracts / 261 command routes** and the support matrix
was refreshed. The public-content scanner regression passed **12 tests**,
including renamed UTF-8/UTF-16 discovery diagnostics.
Final review found no additional actionable defects in the reviewed scope.

Final Release product SHA-256:
`3cd2acad15230eca6acb8846dd1d72cff7686e77965a93292b91adcb44da97f9`.
Shared KMON core harness SHA-256:
`ab4d24e6d8770cc54cf0f65097e424facec3c8909914b84d925b6851b37ac8b7`.
Existing alignment warnings remain. ASan remains blocked by the previously
recorded host startup interception failure; no new ASan success is claimed.
Scanner-internal continuation, successful per-target debt, source-wide timing,
persisted timing recovery, native workloads, maximum unobserved intervals and
durability under media/power loss remain open.

At **03:30 KST**, boot time remained **12:49:00.5 KST on November 17**. No new
reboot/BugCheck events, dump files, task processes/drivers or owned temporary
writer/preparation fixtures remained after validation. The 33 completed parser
caches, firewall profiles and BFE/mpssvc automatic-running and EFS manual-running
service states matched the preceding shared-analysis checkpoint.

## Shared analysis scheduling checkpoint: 2026-11-18

Nine analysis stages now share a cooperative 250 ms turn, at most 100 ms per
requested slice, and a cursor that survives budget exhaustion, exceptions and
slow native calls. Persistent reference/event pressure no longer vetoes image
continuation. Ingestion consumes one item at a time; pipeline events and captured
regions have separate turns. Original target identity/content fences, per-item
debt, source gates and explicit shutdown drains remain in place. See
[shared analysis scheduling](ARCHITECTURE.md#shared-analysis-scheduling).
This completes that implementation slice; it does not complete P09 or the full
kernel-security design.

Private `kn.analysis_scheduling.v1` diagnostics distinguish backlog/dependency,
dispatch/return/fault, service/gap distributions, ready-work deferrals and actual
stage/turn overruns. Backlog age starts at the first scheduler observation of a
continuous backlog. Counts describe service opportunities, not successful target
observations or source-wide freshness. They are runtime diagnostics, not a
durable timing journal. Native calls, individual handlers, final fences, bulk
scanners outside safe boundaries and shutdown can exceed or bypass these normal
cooperative allowances. No hard deadline or native workload SLO is claimed.

Review preserved minimum image progress when native setup has already consumed
the caller's allowance. Otherwise slow setup could repeatedly skip the verifier.
An actual prepared comparison with an expired caller clock still reads its
minimum page, preserves final reference fences and records the original overrun.
Invalid clock order stops later stage dispatch without fabricating a duration;
last-stage overruns are retained even when no further selection occurs.

Validation used Windows build **28000.3501**, MSVC **14.44.35207** and SDK/WDK
**10.0.26100.0**, without loading a task driver or enabling Driver Verifier.
The core harness built under `/W4 /WX` and passed **423 analysis checks**.
The independent analysis oracle passed **6,722 assertions** across 12 synthetic
fixed/growing, churn, blocked/rejoining, due-clock, slow/fault/stop/reentrant,
clock-reversal, final-stage-overrun and depletion scenarios. It checks dispatch
opportunities, remaining allowances, exact counters and independently computed
histograms. These clocks do not represent measured native workload latency.

The product's actual dispatcher passed **15 owned controls** and **20 independent
assertions**: 1,600 live and 1,600 TI records, zero/count-limited allowances,
remaining queue preservation, guard-preserving mapping qualification, unavailable
source gates, actual coverage diagnostics, stop and reset. Product oracles also
passed **968 image / 73 preparation / 50 reference / 85 publication / 16 layout /
23 capture assertions**. Compiled capabilities passed **50 contracts / 261
command routes** and the generated support matrix was refreshed.

The final isolated `--self-test all` passed **28 timeline / 102 MCP /
121 KMON image-read / 319 image-scheduling / 39 image-preparation /
41 publication-writer / 21 layout-scheduler / 15 analysis-integration /
564 console / 3,043 command-route / 68 remote / 4 connect-option checks**, with
`owned_fixture_cleanup=passed`. The shared core also passed the existing capture,
reference, publication, execution, hunting, page, ordering, false-positive and
native image/handle controls, including independent **12,989 reference / 2,394
publication / 10 execution assertions**. The public-content scanner regression
passed **12 tests**, including renamed UTF-8/UTF-16 analysis diagnostics.
Final review found no additional actionable defects in the reviewed scope.

Final Release product SHA-256:
`3ea9efd5144db495af1feb308a4efd9c95c566975b1354c11905b56bdec46b12`.
Shared KMON core harness SHA-256:
`65c5ac537b5811f7b80ac1dba492f5cb64485e6651c0535412b7f82b5bc2be0b`.
Existing alignment warnings remain. ASan remains blocked by the previously
recorded host startup interception failure; no new ASan success is claimed.
Source-wide collection timing, persisted timing recovery, deeper dependency
propagation, native API latency, workload-specific maximum unobserved intervals
and durability under media/power loss remain open.

At **02:52 KST**, boot time remained **12:49:00.5 KST on November 17**. No new
reboot/BugCheck events, dump files, task processes/drivers or owned temporary
writer/preparation fixtures remained after validation. The 33 completed parser
caches, firewall profiles and BFE/mpssvc automatic-running and EFS manual-running
service states matched the preceding collection-timing checkpoint.

## Collection publication timing checkpoint: 2026-11-18

The capture writer now links known local acquisition windows to actual
sweep-flush, evidence-ledger, IRP-ledger and image-journal closing operations.
It distinguishes incomplete, empty, complete, partial and failed collections,
without turning unknown origins or successful closure after failed work into
successful acquisition latency. See
[collection publication timing](ARCHITECTURE.md#collection-publication-timing).
This completes that implementation slice; it does not complete P09 or the full
kernel-security design.

The private `kn.collection_timing.v1` report is a runtime diagnostic, not a new
journal member. Original ledgers, journal recovery, file formats and hashes
retain their contracts. Captured pages still have no collection ledger, and
event loss or a crash can lose timing diagnostics. Source-wide observation
coverage, other stage budgets/dependencies, measured native workload SLOs and
durability under media/power loss remain open.

Validation used Windows build **28000.3501**, MSVC **14.44.35207** and SDK/WDK
**10.0.26100.0**, without loading a task driver or enabling Driver Verifier.
The core harness built under `/W4 /WX`; the independent publication oracle
passed **2,394 assertions**, including 19 collection scenarios. Controls cover
unknown/invalid clocks, zero ticks, out-of-order acquisition, unprocessed or
late admissions, rejection, optional IRP, auxiliary loss and duplicate closure.
The shared suite also passed **521 publication / 32,796 reference / 130 capture /
835 execution / 11,345 hunting checks**, native image/handle/relocation controls,
and independent **12,989 reference / 10 execution assertions**.

Review separated previous job artifacts from closing artifacts, so failed
closure cannot become partial closure merely because an earlier file exists.
Reference/recipe/sweep-only preservation now keeps the whole publication result
partial even when primary files and all closing writes fail. A full-suite run
also exposed a pre-existing preparation-test race: a fast result could be
consumed in its first scan, leaving the test waiting on ticket zero. Per-load
gates now require observed admission before releasing native work; the original
lease, observation, failure and shutdown assertions remain intact.

The final product's publication oracle passed **85 assertions** and the actual
writer passed **41 checks**. Owned controls compare timing with offline journal
recovery, observe completed jobs before writer stop, and exercise empty
collections, successful closure after a failed page, file-only failed closure,
no saved files, and reference-only preservation. The preparation oracle passed
**73 assertions** after the synchronization fix.

The final isolated `--self-test all` passed **28 timeline / 102 MCP /
121 KMON image-read / 319 image-scheduling / 38 image-preparation /
41 publication-writer / 21 layout-scheduler / 564 console /
3,043 command-route / 68 remote / 4 connect-option checks**, with
`owned_fixture_cleanup=passed`. The public-content scanner regression passed
**12 tests**, including renamed UTF-8/UTF-16 collection diagnostics.
Final review found no additional actionable defects in the reviewed scope.

Final Release product SHA-256:
`a3915ff6677b51824b4d2b5064bc1d96d65af1e86a89a5afe8f859a3e72cd588`.
Shared KMON core harness SHA-256:
`47af763b444adb4fea86d8df60cb37962ac7d0cf166ce2dd90005f2f33652ef5`.
Existing alignment warnings remain. ASan remains blocked by the previously
recorded host startup interception failure; no new ASan success is claimed.

At **02:18 KST**, boot time remained **12:49:00.5 KST on November 17**. No new
reboot/BugCheck events, dump files, task processes/drivers or owned temporary
writer/preparation fixtures remained after validation. The 33 completed parser
caches, firewall profiles and BFE/mpssvc automatic-running and EFS manual-running
service states matched the preceding content-preparation checkpoint.

## Image reference content preparation checkpoint: 2026-11-18

Recorded image comparisons now prepare their exact-file lease, original bytes
and hash on dedicated content workers, separately from metadata preparation.
The consumer takes a matching ticket, keeps the original final content and
identity fences, and releases source handles before publication. Unused ready
leases expire cooperatively. See
[reference content preparation](ARCHITECTURE.md#asynchronous-image-reference-content-preparation).
This completes that implementation slice; it does not complete P09 or the full
kernel-security design.

Validation used Windows build **28000.3501**, MSVC **14.44.35207** and SDK/WDK
**10.0.26100.0**, without loading a task driver or enabling Driver Verifier:

- The preparation harness built under `/W4 /WX`; its independent Python oracle
  passed **74 assertions**. New controls cover exact-ticket consumption, native
  file write exclusion, source-handle release while immutable bytes survive,
  oversized unretained leases, cancellation and mode reset. Idle expiry is
  observed through file write availability before querying the engine again.
  Existing admission, dispatch, result-bound and shutdown controls also passed.
- The actual `--self-test image-preparation` passed **36 checks** and its oracle
  passed **73**. Content controls observe another subject's preparation and
  target comparison beside a held worker, original bytes reaching the writer
  queue after the final content fence, source deletion before publication,
  native open failure after success, stale episodes and two-running/six-queued
  shutdown. Metadata controls remain in the same suite.
- Reference blob validation passed **26 native checks** and its independent
  SHA-256/cleanup oracle, including three full read/hash chunks and a final tail.
  Shared-verifier slice controls passed **484 native / 385 slice / 270 sweep /
  1,414 graph / 699 scope-publication / 868 authorized-change checks**. The
  retained-byte assertions were preserved. The harness did not exercise its
  ancestor-switch control; no new claim is made for that race or journal mode.
- Shared KMON core validation passed its image/relocation/coverage, routing,
  scheduling and hunting checks under `/W4 /WX`, including **32,796 reference /
  521 publication / 11,345 hunting checks** and independent **12,989 reference /
  2,284 publication assertions**. Product image/reference/capture/publication/
  layout oracles passed **968 / 50 / 23 / 43 / 16 assertions**.
- The final isolated `--self-test all` passed **28 timeline / 102 MCP /
  121 KMON image-read / 319 image-scheduling / 36 image-preparation /
  30 publication-writer / 21 layout-scheduler / 564 console /
  3,043 command-route / 68 remote / 4 connect-option checks**, and reported
  successful owned pipeline-fixture cleanup. Compiled capabilities expose
  **49 contracts / 261 routes**; the generated support matrix matched.

Review fixed shutdown consumption that could rewrite a prior content success,
and kept tickets removed during stop out of expiry accounting. An initial
diagnostic expansion failed the existing 64-scope control; null content state
before admission restored it without increasing the size limit or weakening
assertions. The final host audit also found that an existing pipeline fixture
removed only top-level files. It now destroys its monitor/store leases before
removing its verified owned tree and fails if cleanup is incomplete. The
pre-fix owned corpus was retained privately for inspection; subsequent validation
removed its newly created temporary tree.

Final review found no additional actionable defects in the reviewed scope.
Final Release product SHA-256:
`744461ec74634f830ace6e60d74e1872f45dcaf601343300107ad5a032ff6e98`.
Preparation harness SHA-256:
`47d77f5434a5642bd145fba711e2ed0d993c3a1c32571fc7cb70a3a215c798e3`.
Reference blob harness SHA-256:
`b67d77f10da1c4fbd1d38635cfc46fa7de8f79913d80c6e587f0f7686f596571`.
Shared KMON core harness SHA-256:
`d413d7bd0a0f0450d4f2e27ea9015aa8ed5b306aff3634155029e465faac1625`.
Shared-verifier slice harness SHA-256:
`6863c95bce1ce5062fe333b7b15211f1af47c4bb75f8c66f80d240d6aebbbf0d`.
The product build retained existing fixture conversion/alignment warnings.
ASan remains blocked by the previously recorded host startup interception
failure; no new ASan success is claimed.

At **01:38 KST**, boot time remained **12:49:00.5 KST on November 17**. No new
reboot/BugCheck events or dump files appeared after the metadata checkpoint.
No task process/driver, owned temporary preparation/writer fixture or parser
preparation/profile residue remained. The 33 completed parser caches,
BFE/mpssvc, firewall profiles and EFS running/manual baseline were unchanged.

These results cover asynchronous content retention and per-comparison source
ownership, not a measured workload SLO. Alias/cache opens, page reads and final
file/content/target fences remain synchronous. Native calls and handle closure
have no hard deadline; blocked native-I/O cancellation latency and native
thread-creation exhaustion were not injected. Generic stage budgets/dependencies,
whole-collection timing and whole-source maximum unobserved intervals remain open.

## Image reference metadata preparation checkpoint: 2026-11-18

PE metadata parsing and executable sweep-range construction now run on two
dedicated workers. Admission includes queued, running and ready work, with
process quotas, fair dispatch and bounded completion slots. Results apply only
to their original ticket, process identity and work episode. See
[reference metadata preparation](ARCHITECTURE.md#asynchronous-image-reference-metadata-preparation).
This completes that implementation slice; it does not complete P09 or the full
kernel-security design.

Validation used Windows build **28000.3501**, MSVC **14.44.35207** and SDK/WDK
**10.0.26100.0**, without loading a task driver or enabling Driver Verifier:

- The preparation harness built under `/W4 /WX`; its independent Python oracle
  passed **56 assertions**. Controls cover 64 admitted owners, per-process
  limits, four completion slots, queued/ready abandonment, native metadata
  parsing, cancellation scope, loader exceptions and process-generation reuse.
  A deque model checks the observed fixed-cohort dispatch order. Shutdown begins
  after observing two active workers and 62 queued jobs, then joins every owner.
- The actual `--self-test image-preparation` passed **21 checks**; its JSON/CLI
  oracle passed **38**. Owned files, explicit worker gates and synthetic target
  bytes exercise progress beside a held worker, pending-path alias sharing,
  replacement after readiness but before a target read, stale episode rejection
  and failure after prior success. Actual monitor stop observes two running and
  six queued requests, then leaves no resident work or active image tickets.
- Review fixed duplicate pending preparation through different paths to the
  same full file ID, retained original admission clocks, and kept cancellation
  separate from the previous completed outcome and success. Allocation rollback
  preserves existing subject queues; reporting reads mutable worker output only
  after publication. Partial-start cleanup closes admission and joins started
  threads; native thread-creation exhaustion was not injected.
- Shared-parser layout validation passed **1,017 scheduling / 105,120 core /
  7,819 independent-model checks**. Existing image/reference/capture/publication/
  layout oracles passed **966 / 50 / 23 / 43 / 16 assertions**. The final isolated
  `--self-test all` passed **28 timeline / 102 MCP / 121 KMON image-read /
  319 image-scheduling / 21 image-preparation / 30 publication-writer /
  21 layout-scheduler / 564 console / 3,043 command-route / 68 remote /
  4 connect-option checks**. Compiled capabilities exposed **48 contracts /
  261 routes**; the generated support matrix matched. Public-content scanner
  tests passed **12**.

Final review found no additional actionable defects in the reviewed scope.
Release product SHA-256:
`d8c9801997e0b1c660e0a48a3176ebb2c79682bab51d9022ce6e32f857168b5a`.
Preparation harness SHA-256:
`b1a45f43b1243692115b8e190f1ffb81306d1c435f2accedc7fd858730009128`.
Shared-parser layout harness SHA-256:
`2fd49bdb573f7b1f508f8e68b5bea89213ed50edaea7bb6d5bba8f4a348a4226`.
The product build retained existing fixture conversion/alignment warnings.
ASan remains blocked by the previously recorded host startup interception
failure; no new ASan success is claimed.

At **00:50 KST**, boot time remained **12:49:00.5 KST on November 17**. No new
reboot/BugCheck events or dump files appeared after the layout checkpoint.
No task process/driver, owned writer fixture, or parser preparation/profile
residue remained. The 33 completed parser caches, BFE/mpssvc, firewall profiles
and EFS running/manual baseline were unchanged.

These results cover metadata preparation, not live byte qualification or
whole-source fairness. Reference content retention/hashing, alias/rescan opens
and final identity/content fences remain synchronous. The prepared-storage
estimate excludes parser intermediates and allocator overhead. Native calls can
still block both workers; cancellation requests have no hard completion bound.
Full asynchronous reference acquisition, generic stage budgets/dependencies,
whole-collection timing, native workload SLOs and maximum unobserved intervals
remain open.

## Layout scheduling checkpoint: 2026-11-17

Layout collection now rotates an explicit process ring with bounded oldest-work
loans. Verification preserves the original observation, queue time and expiry,
uses process/class quotas, and separates mapping qualification from byte reads
and handler completion. See
[layout scheduling](ARCHITECTURE.md#layout-collection-and-verification-scheduling).
This completes that implementation slice; it does not complete P09 or the full
kernel-security design.

Validation used Windows build **28000.3501**, MSVC **14.44.35207** and SDK/WDK
**10.0.26100.0**, without loading a task driver or enabling Driver Verifier:

- The layout harness built and ran under `/W4 /WX`: **1,017 scheduling checks**,
  **105,120 layout-core checks** and **7,819 independent Python assertions**
  passed. Fixed, growing, flooded and removed/reused populations exercise the
  production selectors. The model verifies that later arrivals do not extend
  existing waiters' bounds. Controls cover class/process limits, original
  clocks, observed concurrent reporting, bounded history and escaped details.
- A controlled 4,096-entry source population preserves the first deferred
  discovery until a slot becomes available. A failed collection retains its
  original due time and previous successful snapshot. This is a capacity
  control, not a 4,096-process native workload result.
- The actual `--self-test layout-scheduler` passed **21 checks** and its JSON/CLI
  oracle passed **16**. Owned native mappings exercise guard preservation,
  original expiry, stale identity, source-held fresh retry, normal/shutdown
  separation and a completed layout sweep. Metadata qualification performs no
  byte capture in these controls and does not consume the guard page.
- Adversarial review fixed duplicate replacement that renewed original clocks,
  and retained a newer source observation while its expired original awaits
  accounting. Busy originals also refuse replacement. Exact optional identity
  assertions prevent an unknown assertion from joining contradictory known
  identities. Allocation failure rollback keeps queue membership consistent.
- Existing image/reference/capture/publication scheduling oracles passed
  **966 / 50 / 23 / 43 assertions**. Isolated `--self-test all` reported
  **28 timeline / 102 MCP / 121 KMON image-read / 319 image-scheduling /
  30 publication-writer / 21 layout-scheduler / 564 console / 3,043 command-route /
  68 remote / 4 connect-option checks**, with no reported failures. Compiled
  capabilities exposed **47 contracts / 261 routes**; the generated support
  matrix matched. Public-content scanner tests passed **12**, and mapped-name
  regression tests passed **8**.

Final review found no additional actionable defects in the reviewed scope.
Release product SHA-256:
`e41e0e39d143a499699c1f30ac1dded079b53a7312baf7a075e4f81898df5706`.
Layout harness SHA-256:
`4d2caac93d679308f8510c95f37f6de1d4f9d09758839ec355b8973a01de0274`.
The product build retained existing fixture conversion/alignment warnings.
ASan remains blocked by the previously recorded host startup interception
failure; no new ASan success is claimed.

At **23:42 KST**, boot time remained **12:49:00.5 KST**. No new
reboot/BugCheck events or dump files appeared after the publication checkpoint.
No task process/driver, owned writer fixture, or parser preparation/profile
residue remained. The 33 completed parser caches, BFE/mpssvc, firewall profiles
and EFS running/manual baseline were unchanged.

These results qualify completed non-atomic layout sweeps and mapping metadata,
not mapping lifetimes, unseen identical reuse or code integrity. Cooperative
slices can overrun inside synchronous native calls or callbacks. Asynchronous
reference preparation, generic stage budgets/dependencies, whole-collection
timing, native workload SLOs and whole-source maximum unobserved intervals remain
open. No shutdown source sweep or full P09 completion is claimed.

## Publication scheduling checkpoint: 2026-11-17

The writer now rotates image, evidence, IRP and byte-page families with bounded
oldest-queue loans. It retains original acquisition windows and distinguishes
queue/service time, primary file publication, journal commit, partial/failed
outcomes and shutdown samples. See
[publication scheduling](ARCHITECTURE.md#publication-scheduling-and-completion-timing).
This completes that implementation slice; it does not complete P09 or the full
kernel-security design.

Validation used Windows build **28000.3501**, MSVC **14.44.35207** and SDK/WDK
**10.0.26100.0**, without loading a task driver or enabling Driver Verifier:

- The core harness built and ran under `/W4 /WX`, including **521 publication
  checks** for bounded loans, fairness, unknown/invalid clocks, outcome
  separation, observed reader/writer overlap and reset. An independent Python
  deque model passed **2,284 assertions** over fixed, growing and cleared/reused
  queues. Existing core checks and execution/reference oracles passed. The
  wrapper's Python lookup initially hit the Windows alias; its three oracles
  then passed using the bundled interpreter explicitly, against the same binary.
- The actual `--self-test publication-scheduler` writer passed **30 checks**;
  its independent JSON/CLI oracle passed **43**. Owned native page/bundle reads
  and synthetic image/IRP inputs exercised all four production queues after
  original memory and the reference file were removed. A blocked journal left
  the original file as partial; a page budget failure stayed in the failed
  shutdown population. Completion was observed before normal writer stop.
- Adversarial review fixed a stale empty dispatch snapshot that could miss a
  final enqueue before the producer-stop signal. The writer now observes that
  signal before taking its final empty-queue snapshot. Controls cover pre-join,
  stale-empty and drained states. The partial-start failure path now joins
  producers before stopping the writer; that ordering was traced in code,
  without injecting native thread-creation exhaustion. Receipt ID formatting
  also stays inside guarded diagnostic construction after publication.
- Existing image scheduling passed **966 assertions**, reference scheduling
  **50** and capture scheduling **23**. The isolated product `--self-test all`
  passed **28 timeline / 102 MCP / 121 KMON image-read / 319 image-scheduling /
  30 publication-writer / 564 console / 3,043 command-route / 68 remote /
  4 connect-option checks**. Compiled capabilities exposed **46 contracts /
  261 routes**, the generated support matrix matched, and the public-content
  scanner's **12 tests** passed.

Final review found no additional actionable defects in the reviewed scope.
Release product SHA-256:
`007f139b30f02ea859c1aea8f6532cf7ce101b2c0110946bc2e9ce751575f751`.
Core harness SHA-256:
`c1019d6fbfebfda68829043c1ec6f87f0e67a187bc04d60d253fd05c5cf422c4`.
The product build retained existing fixture conversion/alignment warnings.
ASan remains blocked by the previously recorded host startup interception
failure; no new ASan success is claimed.

At **22:33 KST**, boot time remained **12:49:00.5 KST**. No new
reboot/BugCheck events or dump files appeared after the previous checkpoint.
No task process/driver, owned writer fixture, or parser preparation/profile
residue remained. The 33 completed parser caches, BFE/mpssvc, firewall profiles
and EFS running/manual baseline were unchanged.

These are collector acquisition-window and publication-API observations, not
individual native read latency or media/power-loss guarantees. Image/IRP primary
files and journal members remain distinct from final collection closure and
semantic claim qualification. Layout scheduling, asynchronous reference
preparation, generic pipeline budgets/dependencies, whole-collection timing,
native workloads, measured SLOs and whole-source maximum unobserved intervals
remain open.

## Image observation scheduling checkpoint: 2026-11-17

Image work now preserves discovery/pending ages, separates attempted and
successful slices from gap-free traversals, retries unavailable references after
the existing cooldown, and grants bounded debt-priority turns within ordinary
rotation. The cooperative 25 ms budget includes reference lookup; stage and
whole-turn distributions retain minimum-progress and final-fence overruns.
See [image observation scheduling](ARCHITECTURE.md#image-observation-scheduling).
This completes that implementation slice; it does not complete P09 or the full
kernel-security design.

Validation used Windows build **28000.3501**, MSVC **14.44.35207** and SDK/WDK
**10.0.26100.0**, without loading a task driver or enabling Driver Verifier:

- `tools/validate-kmon-core.ps1` passed under `/W4 /WX`, including new controls
  for an already-spent preparation budget, minimum one-page progress, retained
  content rechecks, cursor continuation and an invalid budget clock. Existing
  reference/capture, execution, image, branch-chain and hunting controls passed.
- `tools/test-image-scheduling.py --exe` passed **966 assertions** against the
  production `--self-test image-scheduler` entry. Its independent model checked
  actual selector sequences for fixed, growing and delete/reuse cohorts with a
  permanently failing oldest entry. Owned file/synthetic target controls covered
  partial progress, failed reads, reference replacement, discovery preservation,
  cooldown/recovery, bounded exact scope details and invalid clocks.
- An initial fixture incorrectly expected a stopped read to succeed. The
  existing router correctly cancelled it. Final controls explicitly require no
  target call or success renewal after cancellation, a reset partial cursor, and
  two newly acquired pages before the replacement episode can complete. The
  production cancellation gate was preserved.
- Existing product reference scheduling passed **50 checks** and capture
  scheduling passed **23**. The isolated final product `--self-test all` passed
  **28 timeline / 102 MCP / 121 KMON image-read / 319 image-scheduling /
  564 console / 3,043 command-route / 68 remote / 4 connect-option checks**.
  Compiled capabilities exposed **45 contracts / 261 routes**; the generated
  support matrix matched and the publication scanner's **12 tests** passed.

Adversarial review also guarded fault/invalid-clock paths against inheriting a
previous completed traversal, kept successful-slice and gap-free episode IDs
separate, and bounded debt loans without advancing the ordinary process cursor.
Timing histograms remain on the heap with a compile-time size bound. No further
actionable defects were found in the reviewed scope.

Final Release product SHA-256:
`f6ed66694f5cb21e96181101a3035b4eea3bae41da0ceb71007a94501f005529`.
Core harness SHA-256:
`d268502371fe38ab9cde0f286d385c71bbf05a5c76991470618f86b0c9240e15`.
The product build retained the existing C4244 fixture conversion and C4744
alignment warnings. ASan remains blocked by the previously recorded startup
interception failure on this host; no new ASan success is claimed.

At **21:46 KST**, boot time remained **12:49:00.5 KST**. There were no new
reboot/BugCheck events or dump files since the previous checkpoint, and no task
process/driver or parser preparation/profile residue. The 33 completed parser
caches, BFE/mpssvc, firewall profiles and EFS running/manual baseline were
unchanged. Native-driver workloads, asynchronous reference preparation, generic
pipeline budgets/dependencies, native first-read and durable publication latency,
measured SLOs and whole-source maximum unobserved intervals remain open. Resident
cache debt and successful comparisons do not establish those broader guarantees.

## Execution reference scheduling checkpoint: 2026-11-17

The analysis queue now enforces subject/role admission quotas, rotates admitted
subjects and roles, and preserves original pending times and anchors on
rediscovery. The private pipeline report separates attempts from successful
static observations, retains bounded deferred scopes and resident debt, and
separates normal/shutdown and successful/failed service timing. See
[execution reference scheduling](ARCHITECTURE.md#execution-reference-scheduling).
This completes that P09 implementation slice; it does not complete P09 or the
full kernel-security design.

Validation used Windows build **28000.3501**, MSVC **14.44.35207** and SDK/WDK
**10.0.26100.0**, without loading a task driver or enabling Driver Verifier:

- `tools/validate-kmon-core.ps1` passed under `/W4 /WX`: the new reference checks
  include pinned history through more than 16,384 completed keys, eviction,
  invalid clocks, bounded anchors, original-work preservation and success/failure
  timing. Its independent Python deque model passed **12,989 assertions** over
  fixed, growing/flooded and full/expired/PID-reused cohorts. All four admission
  limits, omitted deferred scopes and failed-success-revisit separation were
  checked. Existing core, branch-chain, image, capture and hunting checks passed.
- `tools/test-reference-scheduling.py --exe` passed **50 assertions** against
  `--self-test reference-scheduler`. The actual production drain classified
  owned readable, no-access, guard, slot/anchor mismatch, stale identity,
  unavailable mapping and partial indirect-path cases. The absent live source
  left work pending; shutdown samples stayed separate; a quiet role received its
  second turn despite a flood. Guard protection remained set.
- `tools/test-capture-scheduling-cli.py` passed **23 checks**. The isolated
  product `--self-test all` passed **28 timeline / 102 MCP / 121 KMON image-read /
  564 console / 3,043 command-route / 68 remote / 4 connect-option checks**.
  Compiled capabilities exposed **44 contracts / 261 routes**, the generated
  support matrix matched, and the publication scanner's **12 tests** passed.

Adversarial validation found and corrected an unclassified early anchor failure
and a failed exact reader retaining a resized buffer as apparent head bytes.
Full-suite validation also exposed `0xc00000fd` in the nested image-read fixture
path: added histogram storage enlarged already-large monitor stack frames.
Local-symbol debugger evidence identified the path through image publication
and path normalization. Histograms now use one scoped heap allocation, the queue
has a compile-time stack-size bound, and the owned image-read monitor fixtures
use scoped heap allocation. Final validation above includes these fixes. The
two interrupted synthetic fixture roots were verified and cleaned.

Final Release product SHA-256:
`dde3390f511373d7f3631d587798b5883e88a0a788e5ab9999a45fc0e16cab00`.
Core harness SHA-256:
`c61d401a434f514f84362fa7211ba2f16fd4596070d76be81e20804718085be4`.
The Release build retained the existing C4744 warning. Current-host ASan remains
blocked by its previously recorded startup interception failure; no new ASan
success is claimed.

At **21:04 KST**, boot time remained **12:49:00.5 KST**, with no new reboot or
BugCheck event since the preceding checkpoint, no task process/driver or parser
preparation/profile residue, and 33 completed parser caches. BFE/mpssvc, firewall
profiles and the EFS running/manual baseline were unchanged. Native-driver
workloads, whole-source maximum unobserved intervals, other pipeline stages,
durable publication latency and measured workload SLOs remain open. Resident
history debt and dispatch fairness are not whole-pipeline coverage guarantees.

## Process mapping observation checkpoint: 2026-11-17

The live process CLI now publishes v3 recipes with original `VirtualQueryEx`
observations before/after byte reads and at the end of acquisition. Conflicting
or unavailable mapping evidence lowers comparison qualification, original
claims and exact approved-change decisions. Original/current replay and direct
private archives use the retained observations. V1/v2 results and claim policies
remain unchanged. See [mapping observations](ARCHITECTURE.md#process-mapping-observations)
and the [live command](COMMAND_REFERENCE.md).

The Release `/W4 /WX` harness passed **103 native mapping controls**. Owned,
nonexecuting buffers exercised protection changes, final rechecks, free/reserved
regions, same-address private-to-section remapping, equal-attribute ABA, changes
outside queried intersections, two-region reads, cancellation and process exit.
Mutations ran synchronously at observed query boundaries. No scheduling delay
was used to infer that a transition occurred. A retained handle preserved the
exited process identity while its address-space query failed. A handle without
either query right received native access denial and failed source identity
admission. This host allowed limited-query handles; the controls do not assume
that `PROCESS_QUERY_LIMITED_INFORMATION` always denies `VirtualQueryEx`.

An independent Python oracle passed **526 harness / 526 product** checks over
12 native cases. It recomputed queried intersections, native error/null fields,
timing/order, coverage and conflict counts, claim requirements and original
evidence pointers. Rehashed malformed mappings were rejected; valid failure,
partial, cancellation and conflicting observations could not reproduce a stored
success or authorize changed bytes. Original-policy, missing-requirement and
wrong-pointer mutations were rejected. Bare v3 recipes and original claim roots
retained exact query bytes through private collections, original input removal,
historical approval replay and explicit current-policy evaluation.

The final product passed **181 live capture** controls with three owned children
and **77 LoadLibrary/MEM_IMAGE** controls with two children, including relocation,
copy-on-write differences, archive and post-exit replay. All children exited.
The DLL SHA-256 was `694979d629483a1b65e261e96081bc0dbb62ed866ffe189704764c4a3dbb997a`.
Release disclosure checks passed **575 controls / 14 owned-loopback requests**,
including v3 stable/conflicting/exited and bare-recipe inputs. Minimized output
retained failed/unknown counts without publishing raw mapping records.

Compatibility passed **121 C++ recipe**, **34 claim**, **59 publication** and
**448 approval** controls plus v1/v2 interrupted publication. The final product
also passed **59 publication/replay controls on the prior producer's artifacts**.
Slice/sweep regression passed **484 C++**, **385 slice**, **270 sweep**, **1,414
graph**, **699 original-publication** and **868 scoped approval** checks. The
isolated product `--self-test all` passed timeline **28**, MCP **102**, KMON image
integration **121**, console **564**, command audit **3,043 / 261 routes**, remote
**68** and four connection-option controls. Capabilities passed **43 contracts /
261 routes**, the support matrix matched, and public-content tests passed **12**.
No additional actionable defects were found in the reviewed scope.

Artifacts were built with MSVC **14.44.35207**, SDK/WDK **10.0.26100.0**, on
Windows **10.0.28000.3501**. Product SHA-256:
`1877b74b43b4522f7dfdf282cea210694b77773e016643725e5ed4d0209b97b2`.
Recipe/native-mapping harness:
`db8a459370ad7122064665b9120b760fef3687b1ad72711459a6f0d75c306b99`.
Slice harness: `9d828aa09eecb2cb82b39b5d9fbd47dac069913413875fc58ae25ce4b11bd9dd`.
Disclosure harness: `a711f060dba2c69e8185ca6a06685d41ce1c2f108031b354e5d0eb17711550be`.
The product retained the existing C4744 link warning. The post-update ASan
startup interception failure and earlier real-kernel-PDB resource gate remain
open; these Release results do not renew earlier sanitizer evidence.

At **20:11 KST**, the boot remained **12:49 KST**, with no new reboot/BugCheck
events since the prior checkpoint, task processes/drivers, parser receipts,
preparations or AppContainer profile residue. The 33 completed code caches and
BFE/mpssvc/firewall/EFS state matched the prior baseline. No driver was loaded,
Verifier enabled or reboot requested for this stage. The prior EFS stop denial
remains recorded; no bypass was attempted.

This is a bounded P03 step, **not completion of VS1**. Equal mapping queries do
not exclude unobserved ABA, pin mapping lifetime or identify original/physical
backing; `MEM_IMAGE` can remain reported after copy-on-write. Native kernel
mapping/object providers, signed distribution provisioning, cross-bundle
lifetime joins, other architectures and the remaining design packages stay open.

## Scoped approval collection checkpoint: 2026-11-17

Scoped assessments now retain the exact original slice/sweep root, child
recipes, declared raw archives, reference PE, caller policy and manifest.
Content-addressed inputs and an explicit logical-path catalog preserve the
original dependency closure without collisions between source collection names.
The dedicated journal policy requires every declared input before closure;
semantic replay separately requires the original assessment to reproduce at its
recorded time. See [scoped collections](ARCHITECTURE.md#scoped-approved-image-collections)
and the [command contract](COMMAND_REFERENCE.md).

Release validation passed **1,712 harness / 1,723 product** scoped archive checks.
An independent PE/returned-receipt oracle covered bare and original-claim roots,
direct/secondary slices, continuation, unstable/unreadable ranges, partial and
interrupted sweeps, raw-publication loss and a two-byte rule spanning slices.
Original sources, policies and manifests could be removed before replay. Exact
managed retries retained an expired historical assessment; explicit current-time
evaluation rejected its expiry. Another collection could reuse the original
inputs while evaluating its own separately supplied policy.

Observed termination at **11 publication boundaries** retained only complete
journal transactions. Retries preserved the first published assessment time and
report, including a derived-index collision after commit. Controls also covered
concurrent writers, full input/output leases, private ACL admission and default
EFS, conflicting files, caller policy replacement, source-junction retargeting,
catalog order/duplicates/schema/length/path mutations, missing dependencies and
ambient files with original names. Rehashed missing/extra journal members were
rejected. A rehashed false assessment could retain valid physical membership
but failed semantic replay with `recorded_assessment_mismatch`. Explicit GC
removed an eligible uncommitted CAS file while protecting committed inputs,
assessment roots and final ledgers. All observed child processes were drained.
No additional actionable defects were found in the reviewed scope.

Affected slice/sweep compatibility passed **484 C++**, **385 slice**, **270
sweep**, **1,414 graph**, **699 original-publication** and **868 scoped approval**
checks. Direct recipe compatibility passed **120 C++**, **34 claim**, **59
publication** and **448 approval** checks, plus v1/v2 interrupted publication.
Journal regression passed **71 C++**, **1,952 journal**, **476 store**, **892 GC**
and **400 IRP collection** checks. The final product passed **597 direct approval
collection** controls with the prior producer, including expired historical
report equality. The direct approval schema and assessment bytes remain unchanged.

The product's isolated `--self-test all` passed: timeline **28**, MCP **102**,
KMON image integration **121**, console **564**, command audit **3,043 / 261
routes**, remote **68** and four connection-option controls. Capabilities passed
**43 contracts / 261 routes**, the generated support matrix matched, and the
public-content classifier passed **12 tests**, including the new private archive
extensions and renamed JSON schemas.

The product SHA-256 was
`d4caced58781e9c2ac8403ecc78194415508befeb0257a3956ce8ec07c7aebf8`;
the scope-archive harness was
`50e9a3f8d9a7a273058201a366f01a2bd4a7651246bf4f12b0568210533a50c4`;
the journal harness was
`600ebae5385b3269d3ca1ab8687995531a1f08fcb64f19b0e5adb555db07ac96`;
the slice harness was
`a185ede739498cb15c84ae85296818b5ec288f2a85b2667dfadc4a49c6a19417`.
Toolchain/host: MSVC 14.44.35207, SDK/WDK 10.0.26100.0, Windows
10.0.28000.3501. Standalone builds passed `/W4 /WX`; existing product warnings
remain. The updated-host ASan startup failure and earlier real-kernel-PDB ASan
resource gate remain unresolved, without an unchanged retry or bypass.

At **19:12 KST**, boot time remained **12:49**, with no new reboot/BugCheck
events, task processes, loaded task drivers, parser receipts, preparation
directories or AppContainer profiles. The 33 completed parser caches,
BFE/mpssvc, enabled firewall profiles and Running/Manual EFS matched the stage
baseline. The earlier EFS stop-denial limit remains unchanged.

[validate-image-scope-approval-journal.ps1](../tools/validate-image-scope-approval-journal.ps1)
runs the [archive oracle](../tools/test-image-scope-approval-journal.py). Supply
`-ImageHarness` from `validate-image-recipe.ps1`, `-JournalHarness` from
`validate-evidence-journal.ps1`, and `-ScopeFixtures` from a completed
`validate-image-slice.ps1`. Add `-Product` for the offline CLI controls;
`-Mode harness` or `-Mode product` selects one side. The recorded archive tests
used the preceding checkpoint's retained scope fixtures to exercise expired
historical policy windows. No task driver, Driver Verifier or reboot was used.

This increment is not completion of VS1 or P01-P16. Signed distribution and
revocation, native mapping/object lifetimes, cross-bundle associations, broader
native corpora and media power-loss validation remain open. Policy, time and
collector authentication, execution and atomic/current-state claims are not
established by archived comparison or physical journal membership.

## Scoped approved image changes checkpoint: 2026-11-17

`assess-image` now accepts original direct/secondary KMON slices and temporal
sweeps under the caller's separate policy digest. The new
`kn.image_scope_change_assessment.v1` preserves the original replay and records
each approved range's contributing recipe, RVA and capture time. Comparison
holes, missing slices, raw-publication loss and remaining differences stay
visible. Cross-slice assembly does not establish an atomic snapshot. See
[approved image changes](ARCHITECTURE.md#approved-image-changes) and the
[command contract](COMMAND_REFERENCE.md).

Release scoped-approval validation passed **868 harness / 815 product** checks.
The independent oracle reconstructed expected PE bytes and bound observations
to original returned receipts. Controls covered direct and actual local
`SEC_IMAGE_NO_EXECUTE` secondary views, partial/unstable/unreadable observations,
original claim publications, missing and interrupted sweeps, raw-publication
loss, one-byte exceptions, two-byte page/slice seams, a 4,096-byte cross-slice
rule, unexplained extra changes, normalization overlap, policy/scope/issuer/epoch
mismatches, invalid UTF-8 and field sets, 128-entry limits, half-open validity
windows and a future-dated later child. Unicode paths, input preservation,
write-denying leases, CLI grammar and stdout failure were included.

An observed junction-retarget control retained the originally opened modified
capture and its exact approved byte. The root now also binds replayed semantic
and original-claim hashes to the opened bytes. The ancestor-directory
replacement control encountered a filesystem denial while the root lease was
held; its replacement-and-restoration branch was not exercised on this host.
Review kept per-range target qualification distinct from the aggregate slice
identity flag, so a good retained part does not erase unrelated incomplete
coverage. No additional actionable defects were found in the reviewed scope.

The final slice validator passed **484 C++**, **385 slice**, **270 sweep**,
**1,414 graph** and **699 original-publication** checks. Direct recipe
compatibility passed **120 C++**, **34 claim**, **59 publication** and **448
approval** checks, plus v1/v2 interrupted publication. The final product passed
**597 approval-collection** controls using the prior committed image harness as
producer, including exact reproduction and retry of its expired historical
assessment. The direct v1 assessment function and JSON format remain unchanged.

The product's isolated `--self-test all` passed: timeline **28**, MCP **102**,
KMON image integration **121**, console **564**, command audit **3,039 / 261
routes**, remote **68** and four connection-option controls. Capabilities passed
**41 contracts / 261 routes**, the generated support matrix matched, and the
public-content classifier passed **12 tests**, including renamed scoped reports.

The product SHA-256 was
`4d215c9f2ca27139e9b92447a9a679ff6433946775010757fd8d8970b266c982`;
the final slice harness was
`aab0b364434b66804966459c2c7d793d6b7b4737e634a0467449028c668a9a10`;
the direct recipe compatibility harness was
`f1a09c62b08070bb1e0439ca7ca9513fd042760daf1b15ade276e411d1d24ab8`.
The prior producer hash is recorded in the next checkpoint. Toolchain/host:
MSVC 14.44.35207, SDK/WDK 10.0.26100.0, Windows 10.0.28000.3501. Standalone
harnesses passed `/W4 /WX`; existing product link warnings remain. The
updated-host ASan startup failure and earlier real-kernel-PDB ASan resource gate
remain unresolved, without an unchanged retry or interceptor bypass.

At **18:09 KST**, boot time remained **12:49**, with no new reboot/BugCheck
events, task processes, loaded task drivers, parser receipts, preparation
directories or AppContainer profiles. The 33 completed parser caches,
BFE/mpssvc, enabled firewall profiles and Running/Manual EFS matched the stage
baseline. The earlier EFS stop-denial limit remains unchanged.

[validate-image-slice.ps1](../tools/validate-image-slice.ps1) now runs the
[scoped approval oracle](../tools/test-image-scope-authorized-changes.py) after
the original-publication checks. To check a product, pass `--exe`, `--fixtures`
from that completed validator and `--product` to the oracle. These are owned
retained-input controls; no task driver, Driver Verifier or reboot was used.

This increment is not completion of VS1 or P01-P16. Durable scoped-approval
archival, signed distribution/revocation, native mapping/object lifetimes,
cross-bundle associations and larger native corpora remain open. Approval does
not authenticate timestamps, issuers or collectors and makes no execution or
current-state claim. The existing direct approval journal does not yet archive
these new scoped assessments.

## Approved image collection checkpoint: 2026-11-17

Direct assessments now retain the exact capture, reference PE, caller-pinned
policy, manifest and original assessment in one private journal transaction.
Closure requires all five originals. `journal-image-approval` preserves the
first published assessment time/result on exact retries; `replay-image-approval`
requires the caller's policy digest again and distinguishes historical
reproduction from explicit current-time evaluation of the retained policy.
See [approved image collections](ARCHITECTURE.md#approved-image-collections) and
the [command contract](COMMAND_REFERENCE.md).

Final Release approval-collection validation passed **583 harness / 597 product**
checks. An independent PE/read and physical journal oracle checked the five
originals, hash chain, dependent closure, exact original-report reproduction,
shared inputs, bare v1/v2 compatibility, logical byte counts and source removal.
Nine observed writer termination boundaries recovered **0 / 0 / 0 / 0 / 0 / 0 / 1 / 1 / 2** committed
segments; only the final boundary was closed. Retrying each prefix preserved any
already published assessment and completed closure. Expired approval remained
historically reproducible while current evaluation failed.

Controls also covered wrong caller pins, oversized/held inputs, output directory
and original-input leases, uninitialized stores, public-read ACEs on matching
policy/manifest/assessment files, output/index collisions, different closed-input
bindings, malformed roots, missing originals, old-policy rejection and rehashed
invalid transactions/dependencies. Rehashing a forged report can preserve physical
journal membership but cannot reproduce that report semantically. Inventory and
explicit GC removed an eligible owned orphan policy while preserving committed
originals and final ledgers. Product controls included default EFS, a complete
private-root audit, CLI grammar and stdout-delivery failure. Review corrected the
test's reference-PE retention expectation to the existing reference-specific
class and ensured its stdout-failure child is cleaned up on timeout. It also
fixed the archive result so a closed collection's commit/closure flags cannot
be attributed to a different input rejected by that collection.
An observed directory-junction switch exposed a second defect: the original
capture was retained while assessment reopened the caller alias and evaluated a
different capture. The writer and replay now use the opened capture's concrete
path and verify recipe/original-claim hashes. The regression switches the junction
only after source acquisition and requires the archived result to reproduce.

Existing direct-collection compatibility passed **574 harness / 597 product**
checks after sharing the immutable-file publication helper. The owned
`LoadLibrary`/ASLR `MEM_IMAGE` control passed **73 checks** for clean and one-byte
mutation cases. After observed target unload/exit and original DLL/case removal,
it archived approval from the managed capture, removed the external policy and
manifest, and reproduced the historical assessment from the private store. The
independent oracle retained the exact original byte result and separate journal
membership. No probe code was executed; this does not establish native lifetime
or production hotpatch coverage.

Recipe compatibility passed **120 C++**, **34 claim**, **59 publication** and
**448 approval** controls, plus v1/v2 interrupted publication. Journal compatibility
passed **71 C++**, **1,952 journal**, **476 store**, **892 GC** and **400 IRP** checks.
The product's isolated `--self-test all` passed: timeline **28**, MCP **102**,
KMON image integration **121**, console **564**, command audit **3,037 / 261
routes**, remote **68** and four connection-option controls. Compiled capabilities
passed **40 contracts / 261 routes**, generated support documentation matched,
and the public-content classifier passed **12 tests**, including approval
publications, ledgers and renamed result schemas. No additional actionable
defects were found in the reviewed scope.

The product SHA-256 was
`9b458b9d6468f266430bd1734146f0b2054133f449a3d0f4262e86496d999b2a`;
the image harness was
`16adedcc2bc9a89e243ac0172df675666023e96367a97e55c10b9728b11fded5`;
the journal harness was
`3903fe0fc020016fbe9a1ecd32589302a7b355414858e04416e747f23be0d8bb`;
the owned DLL was
`694979d629483a1b65e261e96081bc0dbb62ed866ffe189704764c4a3dbb997a`.
Toolchain/host: MSVC 14.44.35207, SDK/WDK 10.0.26100.0, Windows
10.0.28000.3501. Existing product link warnings remain; standalone harnesses
passed `/W4 /WX`. The updated-host ASan startup failure and prior real-kernel-PDB
ASan resource gate remain open; no interceptor bypass or unchanged failing rerun
was used.

At 17:23 KST the boot time was unchanged, with no new reboot/BugCheck events or
remaining task processes, loaded task drivers, parser profile receipts,
preparation directories or AppContainer profiles. The 33 completed parser caches,
BFE/mpssvc, enabled firewall profiles and Running/Manual EFS matched the stage
baseline. The earlier EFS stop-denial limit remains unchanged.

The [approval collection validator](../tools/validate-image-approval-journal.ps1)
accepts `-ImageHarness`, `-JournalHarness` and `-Fixtures` from the Release
recipe/journal validators, plus `-Product` for the built application. `-Mode
harness` and `-Mode product` select either scope. The
[direct collection validator](../tools/validate-image-capture-journal.ps1) also
runs the extended [mapped-image test](../tools/test-mapped-image-journal.py).

This P03/P06 increment is not completion of VS1 or P01-P16. Historical
reproduction does not assert current approval, live state, authenticated clocks,
collector identity, signatures or power-loss durability. Signed distribution
provisioning/revocation, secondary/sweep approval, cross-bundle associations,
native lifetimes, committed-root retirement and larger corpora remain open.

## Approved image changes checkpoint: 2026-11-17

`assess-image` now checks exact authorized changes in direct recipes and managed
captures under a separately caller-pinned policy. The policy binds image and
manifest hashes, issuer and epoch; both validity windows must cover capture and
evaluation. Original replay, claims, differences and gaps remain unchanged.
Approval applies to observed non-fixup spans with exact before/after hashes.
See [approved image changes](ARCHITECTURE.md#approved-image-changes) and the
[command contract](COMMAND_REFERENCE.md).

Release approval validation passed **448 harness / 424 product** checks against
original PE bytes and retained reads. Controls include exact approval, unchanged
spans, extra unexplained differences, bad before/after hashes, fixup/exclusion
overlap, gaps and unstable reads, bare v1/v2 inputs, forged original claims,
policy/manifest/image/issuer/epoch substitution, validity boundaries, future
capture timestamps, malformed/duplicate/overflow fields, 128/129-entry bounds,
Unicode paths and issuers, observed input write-exclusion leases, CLI grammar
and stdout failure. A forged retained reference matching the observed bytes
successfully replays its compared local range but is rejected by the original
approval policy. That control does not assert complete coverage or authenticated
capture. Review also fixed truncated Unicode output in the new test harness;
the final tests exercise UTF-8 output in both harness and product.

The owned real `LoadLibrary`/ASLR `MEM_IMAGE` path passed **59 checks** for clean
and one-byte-change cases. After child unload/exit and original DLL/case removal,
managed replay and approval identify precisely the allowed byte, preserve the
original replay, and retain separate journal membership and redaction results.
No probe code was executed. This is an owned byte-observation control, not a
production hotpatch corpus or lifetime validation.

Affected recipe compatibility passed **120 C++**, **34 claim**, **59 publication**
controls and v1/v2 interrupted publication. The final product's isolated
`--self-test all` passed: timeline **28**, MCP **102**, KMON image integration
**121**, console **564**, command audit **3,025 / 261 routes**, remote **68** and
four connection-option controls. Compiled capability validation passed **38
contracts / 261 routes** and the generated matrix matched. The public-content
classifier passed **12 tests**, including the new private formats. No additional
actionable defects were found in the reviewed scope.

The product SHA-256 was
`0046b47e7c1b9ca754ec7138adeb577e311b4a50ca5a00379d8eb5f22459f41d`;
the image harness was
`81bdc0a7a902fbb32d8a20ff5833a63bb41e5db61f53091e16aa2e01fc870373`.
The unchanged owned DLL was
`0fd5aea0ae3ce3619adc5e2d0b43c3911f972084f964162c4869379aeb6774bb`.
Toolchain/host: MSVC 14.44.35207, SDK/WDK 10.0.26100.0, Windows
10.0.28000.3501. Existing product link warnings remain; the standalone harness
passed `/W4 /WX`. The updated-host ASan startup failure and prior real-kernel-PDB
ASan resource gate remain open; no interceptor bypass or unchanged failing
ASan rerun was used.

The 16:17 KST cleanup snapshot found the same boot time, no new reboot/BugCheck
events, and no task processes, loaded task drivers, parser profile receipts,
preparation directories or AppContainer profiles. The 33 completed parser caches,
BFE/mpssvc, enabled firewall profiles and Running/Manual EFS matched the stage
baseline. The prior EFS stop-denial limit remains unchanged.

[validate-image-recipe.ps1](../tools/validate-image-recipe.ps1) includes the
[approval oracle](../tools/test-image-authorized-changes.py). To exercise the
product against its resulting fixtures, run
`python tools/test-image-authorized-changes.py --exe x64/Release/KnLiveDbg.exe --fixtures <fixture-directory> --product`.
The [mapped-image test](../tools/test-mapped-image-journal.py), also called by the
direct-collection validator, covers managed post-exit approval.

This is a P03/VS1 increment, not completion of VS1 or P01-P16. Approval is relative
to the caller-pinned policy; issuer signatures, collector timestamps and the host
clock are not authenticated. Signed distribution provisioning/revocation,
journaled approval inputs, secondary/sweep approval, cross-bundle associations,
native lifetimes and broader hotpatch/instrumentation corpora remain open.

## Direct image collection checkpoint: 2026-11-17

Direct dump/process cases can now be archived into initialized private stores
with `journal-image`, retaining the exact recipe/claim root and shared reference.
The dedicated direct-image journal policy supports exact retries, dependent
closure, managed `.kncapture` replay, inventory and conservative GC. Managed
roots also support original-policy count redaction after the source case is
removed. See [direct capture collections](ARCHITECTURE.md#direct-image-capture-collections).

Final Release validation passed **574 harness / 597 product** direct-collection
checks. Independent hashes and final ledgers cover original claims, bare v1/v2
imports, shared-reference reuse, Unicode paths, source removal, malformed or
forged claims, missing/corrupt references, privacy admission and immutable
collisions. Six observed writer-termination boundaries recover **0 / 0 / 0 / 1 /
1 / 2** committed segments, with closure only at the last boundary. Exact retries
close each interrupted collection. Old journal v1-v4 policies reject direct
members; rehashed invalid transactions/dependencies fail, and indexes cannot
substitute for original membership. Open collections protect unattributed files;
explicit GC removes only an eligible owned orphan and preserves committed roots
and ledgers. Product controls also verify default EFS inheritance, complete
private-root auditing, CLI grammar and stdout-delivery failure.

An owned DLL with no entry point supplied a real `LoadLibrary` executable
`MEM_IMAGE` mapping. A self-pointer in its unused probe bytes required DIR64
relocation; reserving the preferred base forced actual relocation. The clean
control and one-byte mutation control passed **49 checks**, including independent
PE normalization, live handle identity/read receipts, original claim reproduction,
private archival, observed child unload/exit, removal of the original DLL/case,
managed replay and original-linked minimized counts. The mutation restored the
page's protection before capture. This is byte-observation evidence; it does not
establish execution or page sharing. Windows continues to report a modified
copy-on-write image page as `MEM_IMAGE`; see
[VirtualQuery](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualquery).

Review corrected a premature `original_claim_recorded` flag on invalid input,
an ineffective metadata-only pin for an empty output directory, and direct JSON
output bypassing the interactive transcript. The regression controls exercise
these boundaries. Product runs also exposed `private_store_publication_failed_5`
during existing private-root initialization. A separate control reproduced that
error by holding a read handle to the policy after its publication. The external
process responsible for the original host occurrence was not identified.
Initialization now uses a two-second retry budget for access-denied/sharing
failures, holding the same root and parent pins, rechecking protection and never
replacing a destination or relaxing permissions. Observed reader release permits
publication; persistent contention preserves private staging and fails closed.
Privacy validation passed **787 harness / 797 product** checks, including EFS,
four interruption boundaries, late collisions and both contention outcomes.

Direct image compatibility passed **120 C++**, **34 claim** and **59 publication**
controls plus v1/v2 interrupted publication. Journal compatibility passed **71
C++**, **1,952 journal**, **476 store**, **892 GC** and **400 IRP** checks. Compiled
capabilities passed **37 contracts / 261 routes**, generated support documentation
matched, and the public classifier passed **12 tests**. The final Release build
and isolated `--self-test all` passed: timeline **28**, MCP **102**, KMON image
integration **121**, console **564**, command audit **3,018 / 261 routes**, and
remote **68** plus four connection-option controls. No additional actionable
defects were found in the reviewed scope.

The product SHA-256 was
`e88d381a0277fb18bf578c31ecf00a57656b9834e554856d06ccd0f9fa6ab880`.
The image harness was
`3efb3d16a5a05735d385635cdb5e46e43d05d88fe40f679abe5cbee41a3f6507`;
the journal harness was
`d7c3f02ce8b90fca819da619ec7c4324f530fb11a27ed13f00bb74199a1d82a8`;
the privacy harness was
`73b5bbb093c75454486329f6006500926675fc6609f627dc288b016c05a917eb`.
The owned DLL was
`0fd5aea0ae3ce3619adc5e2d0b43c3911f972084f964162c4869379aeb6774bb`.
These checks used MSVC 14.44.35207 and SDK/WDK 10.0.26100.0 on Windows
10.0.28000.3501. The existing updated-host ASan startup failure remains unresolved;
no interceptor bypass or unchanged failing ASan rerun was used. See the
[IRP checkpoint](#original-irp-claim-checkpoint-2026-11-17) for its minimal control.
The prior real-kernel-PDB ASan resource gate also remains open.

At 15:43 KST, the boot time was unchanged and no new reboot/BugCheck events or
task processes, drivers, parser profile receipts, preparation directories or
AppContainer profiles remained. The 33 completed parser code caches were
unchanged. BFE/mpssvc and firewall profiles remained enabled. EFS remained
Running/Manual, matching this stage's baseline; the earlier stop-denial limitation
was not bypassed or relabeled as restored.

The [collection validator](../tools/validate-image-capture-journal.ps1) accepts
`-ImageHarness`, `-JournalHarness` and `-Fixtures` from the Release recipe/journal
validators, plus `-Product` for the built application and real mapped-image
controls. `-Mode harness` and `-Mode product` run those scopes independently.
The [privacy validator](../tools/validate-evidence-privacy.ps1) covers initialization
and the observed contention controls.

This stage does not complete VS1 or the wider P01-P16 design. Native mapping and
object lifetime, approved changes, committed-root retirement, large-store
continuation and physical media/power-loss behavior still require their own
evidence. Original case directories retain their existing access controls.

## Original IRP claim checkpoint: 2026-11-17

The KMON writer now preserves an unchanged v2 capture and its original
Capture-mode claim report in `kn.irp_claim_publication.v1`. Default replay
requires exact original report reproduction; `/current` explicitly requests
current claims without asserting original claim reproduction. Journal v4 binds
the whole physical publication. Bare captures, byte-budget fallbacks and missing
reference outcomes remain explicit. See the
[publication contract](ARCHITECTURE.md#original-irp-claim-publication).

Release IRP validation passed **151 C++ controls**, an independent **32-field /
29-read** capture oracle and claim truth/evidence-pointer checks across **21
captures**. Legacy replay controls passed **53 harness / 57 product checks**.
New publication checks passed **730 harness / 738 product checks**, including
independent inner/outer hashes, exact equality with reports saved at capture
time, current-policy field oracles, report/registry/policy mutations, missing
references, duplicate keys, foreign or empty capture hashes, report limits,
immutable collisions and the exact whole-publication budget boundary.
Explicit current evaluation cannot bypass the publication envelope or raw
capture validation.

Observed writer termination at four publication boundaries recovered exactly
**0 / 1 / 2 / 3** committed segments with the expected closure state. Independent
physical hashes matched the journal chain; rehashed report substitution failed
membership verification, and v1/v2/v3 policies rejected the new schema. These
are sampled process-interruption controls, not power-loss or every-instruction
coverage. The actual KMON writer also passed normal original-report publication,
raw fallback when only the capture fits, and reference-retention budget failure.
Its final ledgers, physical filenames, byte counts, membership and owned-file
cleanup matched those outcomes. No target reads or driver load were required.

Release journal compatibility passed **71 C++**, **1,952 journal**, **476 store**,
**892 GC** and **400 IRP** checks. Capability validation passed **36 contracts /
261 routes**, generated support documentation matched, and the public classifier
passed **12 tests**, including the new private schema. Final review fixed empty
digest handling before publication and updated the old `/current` rejection
assertion to cover valid offline routing and duplicate-option rejection.
The final Release build and isolated `--self-test all` passed: timeline **28**,
MCP **102**, KMON image integration **121**, console **564**, command audit
**3,012 / 261 routes**, and remote **68** plus four connection-option controls.
The final product also passed the 738 publication checks. No additional
actionable defects were found in the reviewed scope.

**ASan execution is unresolved on the updated host.** Both IRP and journal ASan
binaries stopped before their test bodies at `interception_win.cpp:193`. A
separate minimal `puts`/`main` program exited 0 normally, while its ASan build
exited 1 with the same interceptor error and no `main` output. No interception
bypass was used: Microsoft documents that continuing past interception failure
can miss reports for that function. See the
[ASan runtime documentation](https://learn.microsoft.com/en-us/cpp/sanitizers/asan-runtime?view=msvc-170).
This stage therefore has Release validation, not a successful ASan run. Earlier
dated ASan evidence and the separate real-kernel PDB resource failure do not
close this gap.

Final host checks found unchanged boot time, zero new reboot/BugCheck events,
and no task process, driver, parser-profile receipt, temporary preparation or
AppContainer profile residue. The 33 completed code caches were retained, up
from 31 at the fresh baseline. BFE, firewall service and profiles were unchanged.
EFS changed from stopped/manual to running/manual during validation and remains
there: it reports `CanStop:false`; the earlier stop attempt was denied with
Win32 5 / `NOT_STOPPABLE`. No permission bypass or service configuration change
was attempted. This is a remaining host-cleanup limitation.

| Checked artifact | SHA-256 |
| --- | --- |
| Final Release product | `eb0f6bab5da2e2a48cfd0402dbae13b31681fa96b0b84cf469401e6a98d18654` |
| IRP binding/publication, Release | `d2bc965f2644b51d7b901dd939f35b4b6ff12b0248c9077ae87a453590408b73` |
| Journal/store, Release | `23e11362267f8984099cff87ac015f02fa415b4a45bb25636a7116cbe88757c9` |

Reproduce with `tools/validate-irp-binding.ps1` and
`tools/validate-evidence-journal.ps1`. Add journal interruption checks with
`tools/test-irp-claim-publication.py --exe <irp-test> --publisher <irp-test>
--fixtures <irp-fixtures> --journal-exe <journal-test>`; use `--exe <product>
--product` for the product path, including the actual KMON writer self-test.
Run the full self-test alone. The host was Windows 11 10.0.28000 / kernel
10.0.28000.3501, MSVC 14.44.35207 and SDK/WDK 10.0.26100.0. Existing C4744
warnings remain. The owned corpus does not establish native IRP lifetime,
completion execution or broader build coverage. Other scanner adapters,
direct-capture journal integration and qualified cross-capture lifetime joins
remain open. This checkpoint does not complete P08 or P01-P16/VS1-VS4.

## Original slice/sweep claim checkpoint: 2026-11-17

Eligible KMON slice/sweep files now retain an unchanged original artifact and
its evaluated claim report in `kn.image_scope_claim_publication.v1`. Original
replay requires the known recorded policy and exact report equality. Journal v3
binds the physical publication and prior dependencies; reproducing a file alone
does not establish collection membership. Legacy inputs and publication-budget
fallbacks remain explicit `not_recorded` cases. See the
[publication contract](ARCHITECTURE.md#original-slice-and-sweep-claim-publication).

The ASan scope harness passed **423 C++ controls**, followed by **385 slice**,
**270 sweep** and **1,414 graph** oracle checks. New original-publication checks
passed **829 ASan / 669 Release checks across 22 cases**; the ASan count includes
creation and collision checks. Both runs independently checked inner/outer
hashes, PE/DIR64/read-receipt evidence, exact stored reports, legacy imports,
changed claims/witnesses/ledgers, unknown registry/policy versions, foreign
bindings, malformed/oversized/pending roots and missing references. An altered
child claim also invalidated the parent replay.

The new tests observed four publication boundaries before terminating the owned
journal writer: files only, committed reads, committed sweep, and closure.
Recovery reported exactly **0 / 2 / 3 / 4** committed segments with the expected
closure state. Independent physical-file hashes and dependency order matched
the verified prefix. Rehashed claim substitution failed journal recovery;
legacy v1/v2 policies rejected the new publication schema. These are sampled
process-interruption controls, not power-loss or every-instruction coverage.

Journal/store compatibility passed **71 C++**, **1,952 journal**, **476 store**,
**892 GC** and **400 IRP** ASan checks. Release compatibility passed **34 direct
claim**, **59 direct publication**, **440 slice**, **312 sweep** and **1,414 graph**
checks. Capability checks passed **36 contracts / 261 routes**, and generated
support documentation matched. The rebuilt disclosure harness passed **506
checks**, including new scope roots and product handlers, **14 owned endpoint
requests** and **zero remaining children**. The public classifier passed **12
tests**, including the new private schema.

Final review fixed a persistence-budget path that replayed retained inputs even
when the original root could no longer fit. The final Release build passed.
KMON integration passed **121 checks**, including original claim reproduction
after source/reference removal, no additional target reads, preservation of a
legacy recipe when the claim exceeds its remaining budget, and a retained
manifest with explicitly unavailable claims when child evidence is missing.
The isolated final `--self-test all` also passed: timeline **28**, MCP **102**,
console **564**, command audit **3,011 / 261 routes**, and remote **68** plus four
connection-option controls. Final review found no additional actionable defects
in the reviewed scope.
Offline replay checks cover unchanged replay code across the final writer-budget
fix; the final KMON/full-suite run checked that changed publication path.

Final host checks found no task process/driver, parser-profile receipt, temporary
preparation directory or AppContainer profile residue. The 31 completed code
caches were retained. Boot time, services and firewall settings match this
stage's baseline. EFS was already running/manual at that baseline; the previous
stage's Win32 5 / `NOT_STOPPABLE` cleanup limitation remains, without another stop
attempt or service configuration change. No driver was loaded by these tests.

| Checked artifact | SHA-256 |
| --- | --- |
| Final Release product | `7df3d0c384338c34278af324f7136a4499850840c486e283363b8075d93436d8` |
| Slice/sweep publication, ASan | `d1559aa9960a90d97fb75e7b467ce290eedce6e835e084235139f1a1d49e56e6` |
| Journal/store, ASan | `a50624ce44abe718beaec2a1edab8cae185d634e59d9f9b7766a8eb224d6b79f` |
| Disclosure, ASan | `7664594f05a3b22b3c0f7c655dcddf2cc667be9229c8e0f97e16f18795f32038` |

Reproduce with `tools/validate-image-slice.ps1 -Sanitize` and
`tools/validate-evidence-journal.ps1 -Sanitize`. The former creates a unique
fixture directory with `scope-claim-publications`. To add the observed journal
interruption checks, run `tools/test-image-scope-publication.py --exe <slice-test>
--fixtures <slice-fixtures> --journal-exe <journal-test>` against that directory;
use `--exe <product> --cli` for the Release replay/recovery paths. Run the full
self-test alone. The host was Windows 11 10.0.28000 / kernel 10.0.28000.3231,
MSVC 14.44.35207 and SDK/WDK 10.0.26100.0. Existing C4744 warnings remain.

The owned/synthetic corpus does not establish native loaded-image or driver
mapping lifetimes. Original IRP/other-adapter claims, direct-capture journal
integration and qualified cross-capture lifetime joins remain open. The earlier
real-kernel PDB ASan resource failure remains unresolved. This checkpoint does
not complete P08, native VS1 or the full P01-P16/VS1-VS4 design.

## Original direct-image claim checkpoint: 2026-11-17

New direct dump/process captures retain an unchanged v1/v2 recipe and the claim
evaluated from its original reads in one `kn.image_claim_publication.v1` root.
Offline original-policy replay recomputes the comparison and complete claim
report, then requires equality with the retained evaluation. Legacy input remains
`not_recorded`; `/current` reports `not_requested` for original claim replay.
See the [publication contract](ARCHITECTURE.md#original-direct-image-claim-publication)
for the two digest scopes, prepublication report fields and remaining limits.

The final ASan harness passed **120 C++ controls**, **34 independent PE/read claim
replays** and **59 publication controls**. The independent oracle checks both
canonical payload hashes, original read/byte evidence, exact report equality and
the distinction between original and current evaluation. Rehashed verdict,
range, ledger and injected-claim changes fail original replay; unknown claim
registry/policy versions require explicit current reanalysis. Foreign recipe or
reference bindings, corrupt inner/outer hashes, missing/oversized reports,
additional root fields, truncated roots and absent references fail explicitly.
Legacy v1/v2 imports remain covered. Mutation cleanup restores the exact original
publication bytes instead of replacing the root with a legacy recipe.

Twelve sampled process interruptions left no final root (**zero committed,
twelve absent**). Separate controls reject an abandoned pending root and partial
final files. These samples do not establish power-loss durability or interruption
at every publication instruction. Normal completed roots reproduce their claims.

The Release product passed the same **34 claim** and **59 publication** controls,
**123 offline CLI checks**, and **34 historical v1/v2 compatibility replays**.
The live runner passed **181 checks** with three owned, nonexecuting PE-buffer
children: clean, changed and unreadable ranges. Each child exited and released its
mapping, then the original reference path was replaced/removed before replay.
The recorded claims remained reproducible and **zero children** remained.
This does not validate real loaded-image or native-driver mapping lifetimes.

Product slice/sweep/graph compatibility passed **440 / 312 / 1,414 checks**.
The rebuilt ASan disclosure harness passed **506 checks**, including the product's
offline/HTTP handler paths, with **14 owned endpoint requests** and **zero child
processes**. Redaction binds the entire new publication root and withholds facts
when original-policy replay fails. The public-content classifier passed **12
tests**, including the new private publication schema.

The Release build and isolated `--self-test all` passed: timeline **28**, MCP
**102**, KMON image integration **119**, console **564**, command audit **3,011 /
261 routes**, and remote **68** plus four connection-option controls. Capability
checks passed **36 contracts / 261 routes** and the generated support matrix
matches the product. Final review found no additional actionable defects in the
reviewed scope.

| Checked artifact | SHA-256 |
| --- | --- |
| Release product | `865d80213de9b1025c72e110b6b45deaaf3447516af5b0ecd9804c2e728d2b50` |
| Direct recipe/claim publication, ASan | `b66e0bb01909e31b3634f120874d5fa5863fac60e13ef330c50b3a681211032e` |
| Disclosure compatibility, ASan | `a0f4e2e6f9813475ba070c44fe147959f05e4c6c2f24ef8042ce736d1543792e` |

Reproduce with `tools/validate-image-recipe.ps1 -Sanitize`, which prints its unique
binary/fixture directory. `test-image-claims.py` and
`test-image-claim-publication.py` accept `--exe <product> --fixtures <directory>
--product`; `test-image-recipe-cli.py` and `test-live-image-recipe.py` use the same
arguments without `--product`. The host was Windows 11 10.0.28000 / kernel
10.0.28000.3231 with MSBuild 17.14.60, MSVC 14.44.35207 and SDK/WDK 10.0.26100.0.
Existing C4744 link warnings remain. Run the full self-test alone.

Final checks found no task process or running task-driver residue. Boot time and
firewall settings match this run's baseline. EFS changed from stopped to running
during validation; service-stop attempts failed with Win32 5 under the current
non-administrator token, and the service reports `NOT_STOPPABLE`. Its running
state remains a cleanup limitation; service configuration was unchanged.

Other adapters' original claim publication, collection-journal membership,
qualified cross-capture lifetime joins and native validation remain open. The
earlier real-kernel PDB ASan resource failure remains unresolved. This checkpoint
does not complete P08, native VS1 validation or the full P01-P16/VS1-VS4 goal.

## Slice and sweep claim checkpoint: 2026-11-07

This P08 step adds common claim adapters for original-policy image slice and
sweep replay. The slice and sweep policy identifiers select their report
variants under `kn.image_claim_report.v1`. Typed range partitions, original
selected target receipts and exact manifest membership qualify the claims.
The [scope claim contract](ARCHITECTURE.md#slice-and-sweep-claim-policies) describes
the temporal scope, first stable difference witness and remaining limits.
Original artifacts, existing proof output and native ABI remain unchanged.

The ASan slice harness passed **423 C++ controls**. Independent Python oracles
passed **385 slice checks / 11 cases**, **270 sweep checks / 11 cases** and
**1,414 graph checks / 8 cases**. The claim oracle reconstructs AMD64 PE/DIR64
expected bytes from the retained reference, resolves original accepted parser
calls and distinct returned receipts, and checks the full range partition,
membership links, exact witness and all seven ledgers. Retained prefixes from
failed primary reads do not count as accepted target observations. Secondary-view inputs
remain separately referenced and do not replace target confirmation reads.

Additional controls preserve a stable changed range when the final slice is
missing, an earlier manifest entry is missing, or a different page is unstable.
The full-match claim is contradicted while the difference remains supported;
missing membership requirements and failed/unvisited address partitions remain
visible. Separate raw-archive publication loss remains explicit even when all
original comparison inputs survive inside the recipes. Empty/rejected slices,
loader exclusions, unconfirmed reads and changed identities cannot become full
matches. Unit controls also reject altered comparison counters/bytes, foreign
recipe digests and substituted child target namespaces/acquisition intervals.

The final product passed **440 slice checks**, **312 sweep checks** and **1,414
graph checks** on the same owned fixtures. Direct-image compatibility passed
the existing **34 claim replay controls** and **122 CLI checks**. The updated
disclosure harness compiled with ASan and passed **506 checks**, including the
product's offline and real handler paths through an owned test endpoint;
**14 requests** were observed and **zero child processes** remained. These are
bounded controls, not native-platform coverage or a detection-accuracy estimate.

The Release build and isolated `--self-test all` passed: timeline **28**, MCP
**102**, KMON image integration **119**, console **564**, command audit **3,011 /
261 routes**, and remote **68** plus four connection-option controls. Capability
checks passed **36 contracts / 261 routes**, the generated support matrix matches
the binary, and the public-content classifier passed **12 tests**. Target
availability remains unprobed. Final review found no additional actionable
defects in the reviewed scope.

| Checked artifact | SHA-256 |
| --- | --- |
| Release product | `c28065e83ffa0c889b10f13552bf5bb391b533cffcce8b8473327f31973bab33` |
| Slice/sweep/graph, ASan | `136ec01c7988c2e8174cd4e29fa5c74a3fb8327ea4977703605c1eb9d1425871` |
| Disclosure compatibility, ASan | `bda8b936468dd3c1cb5f636da1756d39036afa203fa17bfac2d9959ac60c2158` |

Reproduce with `tools/validate-image-slice.ps1 -Sanitize`; the runner emits unique
binary and fixture directories, preserving previous run binaries. The three
`test-image-slice.py`, `test-image-sweep.py` and `test-image-sweep-graph.py` scripts
accept `--exe <product> --fixtures <directory> --cli` for product checks.
`tools/validate-evidence-disclosure.ps1 -Sanitize` takes `-ImageSliceFixtures`,
`-ImageRecipeFixtures` and optional `-Cli` paths. Run `KnLiveDbg.exe --self-test all`
alone. The Windows 11 10.0.28000 / kernel 10.0.28000.3231 host, VS 17.14.60,
MSVC 14.44.35207 and SDK/WDK 10.0.26100.0 environment is unchanged from the
direct-image checkpoint. Existing C4744 link warnings remain.

Final cleanup found no test process, parser profile/receipt/preparation or
running task-driver residue. Services, firewall settings and boot time match
the baseline; no driver was loaded or reboot performed. Completed code caches
and owned fixtures remain. Claim-report persistence, original claim-policy
reproduction, generic cross-capture lifetime joins, other object adapters and
native validation remain open. The earlier real-kernel PDB ASan resource failure
is still unresolved. This does not complete P08 or the full P01-P16/VS1-VS4 goal.

## Direct image claim checkpoint: 2026-11-07

This P08 step connects direct image recipe v1/v2 replay to the common claim
evaluator under `kn.image_claim_policy.direct.v1`. The two policies assess a
complete requested-range match or a stable difference within compared bytes.
Reports retain original SHA/JSON-pointer references, exact support/counterexample
ranges, missing requirements, next-observation suggestions and seven ledgers.
The [direct-image claim contract](ARCHITECTURE.md#common-direct-image-claim-policies)
separates the current claim policy from original comparison replay or explicit
current reanalysis. Original capture bytes and native ABI remain unchanged.

The ASan recipe harness passed **103 controls**. The independent claim runner
passed **34 replay controls**, with **13 supported / 13 contradicted / 30
unfulfilled** assessments across accepted replays. These are test-case counts,
not detection accuracy. The oracle reads the retained AMD64 PE sections and
DIR64 relocations to reconstruct expected compared bytes independently, then
checks original reads, confirmation, exact address partitions, every evidence
pointer and all seven ledgers. It does not accept the emitted claim or legacy
proof verdict as its oracle.

Controls include clean and modified v1/v2 captures, 2,048 separate changed-byte
ranges within the report bound, missing confirmation, sparse and unstable reads,
wrong mapped identity, changed header bases, denied residency consent and zero
acquisition budget. Rehashed unknown policies, substituted normalization, stored
result replacement and injected claim/trust assertions cannot authorize an
original-policy claim. Explicit current reanalysis recomputes its own comparison
without asserting that the original normalization or claim policy was reproduced.
V1 and v2 interruption checks each passed six cases: two complete publications
replayed and four had no final recipe.

The final product passed the same **34** claim replay controls and **122** offline
CLI checks. The live handle-reader test passed **178 checks**, with **three owned
child processes** and zero remaining children. Their nonexecuting PE buffers were
read through the process handle; after process exit and removal of the original
reference path, both replay modes passed the same claim oracle using retained
inputs. This does not exercise native kernel reads or execution tracing.
Slice compatibility passed **440 checks / 11 cases** and eight sweep envelopes
preserved their original proofs with `claim_assessment=null`.

The Release build and isolated `--self-test all` passed: timeline **28**, MCP
**102**, KMON image integration **119**, console **564**, command audit **3,011 /
261 routes**, and remote **68** plus four connection-option controls. Capability
checks passed **36 contracts / 261 routes**, the generated support matrix matches
the binary, and the public-content classifier passed **12 tests**. Target
availability remains unprobed. Final review found no additional actionable
defects in the reviewed scope.

| Checked artifact | SHA-256 |
| --- | --- |
| Release product | `97a2fbe69c413362139cab440b91623787dbbadbe3939320c8474c5abd4be863` |
| Direct recipe/claims, ASan | `efcfc350b09b46dc56270f43a9982befa7065784cabbaf6b0595125e5101a7f7` |

Reproduce with `tools/validate-image-recipe.ps1 -Sanitize`; this now also requires
Python and invokes `tools/test-image-claims.py` with its generated fixture
directory. For the product, run that script with `--exe <product> --fixtures
<directory> --product`, and run `tools/test-image-recipe-cli.py` and
`tools/test-live-image-recipe.py` with the same `--exe` and `--fixtures` options.
Run `KnLiveDbg.exe --self-test all` alone. This host uses the bundled Python
runtime, Windows 11 Pro 10.0.28000, kernel 10.0.28000.3231, VS 17.14.60,
MSVC 14.44.35207 and SDK/WDK 10.0.26100.0. Existing C4744 link warnings remain.

No driver was loaded, service/firewall policy changed or reboot performed.
Final host checks found no test process, parser profile/receipt/preparation or
running task-driver residue; completed code caches and owned fixtures remain.
The policies do not establish execution, writer, maliciousness, authorized
changes, whole-image integrity or continuous observation. Slice/sweep claim
adapters, original claim publication/reproduction, qualified cross-capture joins,
other object/lifecycle providers and native validation remain open. The earlier
real-kernel PDB ASan resource failure is still unresolved. This does not complete
P08 or the full P01-P16/VS1-VS4 objective, which remains active.

## IRP object/state claim checkpoint: 2026-11-07

This P08/P13 step adds the deterministic `kn.irp_claim_policy.v1` registry and
an adapter for original bound IRP captures and canonical ordered-read replay.
Reports distinguish supported, contradicted, unfulfilled and not-applicable
claims, with original evidence references, unmet requirements, next-observation
suggestions and seven separate ledgers. The
[claim contract](ARCHITECTURE.md#irp-claim-policies) defines the bounded meanings.
The existing `replay-irp` command exposes current-policy assessments separately
from the original capture policy. Capture v1/v2 bytes and native ABI are unchanged.

The final ASan binding harness passed **151 controls**. Independent capture
checks passed **32 fields / 29 original reads** and reconstructed the retention
state signature. The claim oracle checked **21 original captures**, including
**25 supported / 31 contradicted / 34 unfulfilled / 65 not-applicable** emitted
assessments. It derives expected results from the original packet/stack fields,
checks the required policy definitions and resolves every evidence hash/JSON
pointer. An independent boundary sweep verifies requested, accepted and
failed-only address unions without counting repeated traffic as new coverage.
These counts describe owned synthetic controls, not detection accuracy.

Controls cover disabled completion flags, null completion targets, cancellation
and status samples without lifecycle events, null versus unavailable device
fields, empty inventories, missing retained images, source/image/owner changes,
partial pages and a 64-stack report that reaches the output bound. Omitted
assessments retain their exact denominator. Evaluator checks reject absent
evidence, mixed captures, duplicate or unknown facts and duplicate requirements;
an unqualified scope cannot yield a negative or not-applicable conclusion.
The ASan replay runner passed **52 controls** and the final product passed
**56 CLI controls**. Invalid or mutated captures expose no partial claim result.

Review found a runtime integration defect: `io.request_observation` was emitted
by the producer but had no retaining branch in `KmonWatchMatches`; the new claim
event would also have been dropped and classified as a lead. Both now enter
the ring/log as kernel observations independently of process-watch filters.
Routine live printing remains suppressed. Actual `RecordEvent` controls verify
retention, exact payload preservation, observation category and unchanged
`maliciousness:not_established`. No additional actionable defects were found
in the reviewed scope after the fix and affected rechecks.

The final Release build and isolated `--self-test all` passed: timeline **28**,
MCP **102**, KMON image integration **119**, console **564**, command audit
**3,011 / 261 routes**, and remote **68** plus four connection-option controls.
Capability checks passed **36 contracts / 261 routes**, the generated matrix
matches the binary, and the expanded public-content classifier passed **12
tests**. Target availability remains unprobed.

| Checked artifact | SHA-256 |
| --- | --- |
| Release product | `eb03296e3b4086de813dc8967caf3b0164fc03361b0cfff8e32c3c5c5f4e6b23` |
| IRP binding/claims/replay, ASan | `e5b12f882b45c6b117327d06d22ef92fd396dd73b5eff7a2fc474c93201c59b2` |

Reproduce with `tools/validate-irp-binding.ps1 -Sanitize`; the runner preserves
owned capture-time claim reports and runs both independent oracles. Its emitted
fixture directory also supports `tools/test-irp-binding-capture.py <directory>`
and `tools/test-irp-replay.py <product-exe> <directory> --product`. Run
`KnLiveDbg.exe --self-test all` alone. This host uses the bundled Python runtime,
Windows 11 Pro 10.0.28000, kernel 10.0.28000.3231, VS 17.14.60, MSVC 14.44.35207
and SDK/WDK 10.0.26100.0. Existing C4744 link warnings remain. No driver was
loaded, service/firewall policy changed or reboot performed. Final cleanup
checks found no test process, parser profile/receipt/preparation or running
task-driver residue; completed code caches and owned fixtures remain deliberately.

The policy supports only captured recorded-state invariants. It does not prove
an approved Windows build, IRP allocation lifetime, completion/cancellation,
execution, device-driver ownership or authenticated collector identity. Original
claim-report persistence and original-policy claim reproduction are not inferred
from raw capture replay. Other scanner/image-change adapters, qualified
cross-capture joins, lifecycle providers and native validation remain open,
along with the earlier real-kernel PDB ASan resource failure. This does not
complete P08/P13 or the full P01-P16/VS1-VS4 objective.

## IRP retention priority checkpoint: 2026-11-07

This P06/P13 step separates first recorded IRP states, observation gaps and
repeated/empty observations in the KMON queue and writer. Four shared in-flight
slots have independent 80 MiB class budgets: 240 MiB total. Separate capture
64/32/32 MiB and reference 64/64/64 MiB budgets allow at most 320 MiB of new raw
files per session. These replace the previous combined 128 MiB allowances;
producer artifacts and journal/event metadata are separate. No physical disk
reservation is claimed. See the [priority contract](ARCHITECTURE.md#irp-retention-priority).

The state signature binds the captured source contract, exact schema packages
and typed request fields. It is a retention key, not an object-lifetime join or
maliciousness verdict. A key becomes saved only after capture/reference/journal
publication succeeds. Missing encoded captures now contribute to a protected
final ledger even when no raw capture enters the queue. Legacy capture v1/v2
bytes, replay policy and native ABI are unchanged.

The ASan retention harness passed **28 controls** and an independent accounting
oracle passed **101 checks**, including **9,000 attempts from nine concurrent
threads**. Controls cover round-robin selection, writer-held reservations,
separate maximum-size artifact capacity, failed-publication retry, pending and
saved repeats, key bounds, abandoned tickets and final zero reservations.
The ASan binding harness passed **101 controls**; the independent oracle checked
**32 fields / 29 original reads** and reconstructed the signature directly from
the saved source/schema/request data. Typed-field, source-epoch and schema
changes produce new keys; time, pagination and coverage counters do not.
Replay passed **46 harness controls** and **50 product CLI controls**, including
original failure outcomes, modified inputs and command usage rejection.

The final Release product passed an isolated `--self-test all`: timeline **28**,
MCP **102**, KMON image integration **119**, console **564**, command audit
**3,011 / 261 routes**, and remote **68** plus four connection-option controls.
Actual KMON writer checks exhaust the repeat file budget, then retain first-state
and gap captures. A first-state reference-budget failure leaves its state
eligible for first priority; the gap class retains the reference, and the retry
reuses it without charging new bytes. Only then does a later identical state
use the repeat class. Final physical hashes, committed journal counts, reference
creation/reuse/failures, embedded retention report and drained reservations agree.
An unavailable-only session also publishes its failure ledger and closes through
the journal. These writer controls use owned ACL-only roots without a driver.

Capability checks passed **35 contracts / 261 routes** and the generated support
matrix matches the binary, with target availability still unprobed. The expanded
public-content classifier passed **12 tests**. Review covered ticket ownership,
allocation rollback, concurrent admission, per-stream byte charging, missing
capture accounting, reference reuse and post-publication retry. No additional
actionable defects were found in the reviewed scope.

| Checked artifact | SHA-256 |
| --- | --- |
| Release product | `4a6420cc19f3e5bd9d9fde10723a96477bf607f12a680ed152ac4898d89dda66` |
| IRP retention, ASan | `4a61b1e3c20f9814ceaffff3cc927b843842d772f51d108254df4824c501ae2d` |
| IRP binding/replay, ASan | `0e8c475a8911c6dab6d8e2b870fada92d39448cac122b5a6a86fbe65ebf8f0de` |

Reproduce with `tools/validate-irp-retention.ps1 -Sanitize`,
`tools/validate-irp-binding.ps1 -Sanitize`, and `KnLiveDbg.exe --self-test all`.
Use the binding harness's emitted fixture directory for
`tools/test-irp-replay.py <product-exe> <owned-fixture-directory> --product`.
The bundled Python runtime is required on this host. Validation used Windows
11 Pro 10.0.28000, kernel 10.0.28000.3231, VS 17.14.60, MSVC 14.44.35207 and
SDK/WDK 10.0.26100.0. Existing C4744 link warnings remain. No driver was loaded,
service/firewall policy changed or reboot performed. Final checks found no
test process, parser profile/receipt/preparation or running task-driver residue;
completed code caches and owned fixtures remain deliberately.

These controls do not establish native request lifetime, address-reuse safety,
approved Windows build coverage or full P05/P06/P13 and VS2/VS3 completion.
Committed-root retirement, other-family priorities/redaction, large-store
continuation, power-loss recovery and the earlier real-kernel PDB ASan resource
failure remain open. The full P01-P16/VS1-VS4 objective remains active.

## IRP journal and retention checkpoint: 2026-11-07

This P06/P13 slice connects private IRP captures, retained references and the
final failure ledger to `kn.image_irp_collection_journal.v2`. Legacy image v1
sessions remain readable with their original policy. IRP transactions bind the
capture's physical hash, collection path, schema and optional retained reference;
the final collection closure requires the committed IRP ledger. Failed ledger
publication leaves an open collection. Store inventory and explicit uncommitted
GC now include the reserved IRP root namespace. Membership does not establish
replay, source authenticity, request lifetime or execution. See the
[journal contract](ARCHITECTURE.md#pending-irp-schema-and-runtime-binding).

The final ASan journal harness passed **71 controls**. Independent checks passed
**1,952 journal / 476 store / 892 GC / 400 IRP integration controls**. The journal
and GC suites include respectively **10** and **9** observed interruption stages;
the IRP suite adds **8** observed publication stages and **9** rehashed malformed
transactions. It independently derives mixed legacy/typed collection hashes,
reference multiplicity, global path/content byte counts and protected ledger
classification. It also checks explicit orphan deletion, idempotent GC receipts,
committed-file/ledger rejection, unknown root entries and recovery of the exact
committed prefix. Synthetic membership fixtures do not assert valid IRP replay.

The final Release product passed **400 IRP / 1,952 journal / 492 store / 898 GC
CLI controls**. An isolated `--self-test all` passed: timeline **28**, MCP **102**,
KMON image integration **119**, console **564**, command audit **3,011 / 261
routes**, and remote **68** plus four connection-option controls. Actual writer
checks use owned ACL-only roots and cover IRP-first publication, later IRP
admission into an image journal, repeated reference reuse, ledger collision,
private-policy rejection, immutable capture collision, bounded queue/byte
reservations and final drain. A ledger collision preserves the existing file
and prevents a closed collection result. Capability checks passed **34 entries /
261 routes**; the generated matrix matches the binary and remains unprobed.
The public-content classifier passed **12 tests**.

The first new interruption oracle omitted image failure ledgers from its expected
protected kinds; the implementation correctly protected them. The oracle now
requires protection for both image and IRP ledgers. Review also removed repeated
whole-journal ACL scans on every IRP capture: the existing-file admission happens
once when IRP joins, with the recovery deadline, while each new input/output
handle still passes the retained private-root check. Output admission occurs
before bytes are written; denied or throwing admission leaves no owned pending
file. Final review found no additional actionable defects in the changed scope.

| Checked artifact | SHA-256 |
| --- | --- |
| Release product | `e99760f4dca76472b11806fd942bd0d9e0a3b23120c87422b675f8afac663c95` |
| Journal/store/GC, ASan | `8223ed791e6f0dbe9b7a90046b29b2cfd0e3334f8b777b967c7f12f1030d0a02` |

This used Windows 11 Pro 10.0.28000, kernel 10.0.28000.3231, VS 17.14.60,
MSVC 14.44.35207 and SDK/WDK 10.0.26100.0. The build retained the existing C4744
link warnings. No driver was loaded, service/firewall policy changed or reboot
performed. Final cleanup checks found no test process, parser profile/receipt/
preparation or running task-driver residue; completed code caches and owned
fixture artifacts remain deliberately. EFS behavior uses the existing policy
and actual-handle validator; the new integrated writer tests used ACL-only roots.

Reproduce with `tools/validate-evidence-journal.ps1 -Sanitize`. Its emitted
fixture directory can be used with `tools/test-evidence-journal.py --cli` and
the product `--exe`, keeping the harness as `--producer`. Store/GC runners use
the same options; `tools/test-irp-journal.py` uses `--product`. All require an
owned `--fixtures` location and the bundled Python runtime on this host.

The native ABI and existing v1 image journal bytes are unchanged. At this
checkpoint, committed-root retirement, IRP-specific priority partitions,
other evidence families, large-store
continuation, power-loss recovery, native request lifetime/build qualification
and the prior real-kernel PDB ASan resource failure remain open. These checks do
not complete P05/P06/P13 or VS2/VS3.

## Pending IRP offline replay checkpoint: 2026-11-07

The next P05/P13 slice adds `kn.irp_capture.v2`, an exact retained image and
`--offline !kmon replay-irp <capture.knirp> /json`. Replay rebuilds the layout
from the three saved packages, consumes ordered original calls, reruns the
image/object checks and compares the entire canonical capture. Its
`qualified_observation_reproduced` field additionally requires the matching
retained image. Missing images permit explicitly limited metadata replay;
conflicting images, forged summaries and incomplete traces cannot qualify.
The [architecture contract](ARCHITECTURE.md#pending-irp-schema-and-runtime-binding)
describes the storage bounds and remaining claims.

The final ASan IRP harness passed **75 controls**, the independent oracle checked
**32 fields and 29 original reads**, and the ASan replay mutation runner passed
**46 controls**. These include two IRPs continued through a nonzero cursor,
mid-read cancellation, owner/source churn, missing optional state and a 3.8 MiB
trace with 2,048 source calls. The generic importer's 2 MiB default remains
enforced; only the bounded IRP path opts into the larger limit. Duplicate keys,
unknown policy/fields, altered counters/graphs/acceptance flags, reordered or
missing calls, schema corruption and reference collision/missing/restoration
are covered. These are owned synthetic observations, not native kernel reads.

Review found excessive repeated JSON validation in the large ASan case. The
initial owned test process was stopped and the importer changed to index each
bounded object once. Complete canonical comparisons and all rejection checks
remain. The final mutation runner passed with its unchanged 60-second
per-process timeout, including the large trace. This is not a latency guarantee
for every 16 MiB capture or host. A subsequent integrated test exposed output
bypassing the interactive transcript; the new command now uses the transcript
stream interactively and the UTF-8 writer at the standalone offline entry.

Common parser regression passed **307 image-slice ASan controls** plus the
independent **369 slice / 233 sweep / 1,414 graph checks**. The legacy image
recipe ASan suite passed **92 controls**; interrupted v1 and v2 publications
each produced two valid complete recipes and four absent recipes across six
termination points. Existing product image CLI checks passed **101 controls**.
The public-content classifier passed **12 tests**, including renamed v2 captures
and replay results. Capability inventory remains explicitly unprobed.

The final Release product passed **50 IRP CLI controls** and an isolated
`--self-test all`: timeline **28**, MCP **102**, KMON image integration **119**,
console **564**, command audit **3,011 / 261 routes**, and remote **68** plus four
connection-option controls. Actual writer tests cover reference creation/reuse,
immutable capture collisions, four-entry and weighted-byte pressure, private
store rejection, reservation refunds, final ledger and privacy audit. Review of
the final changed scope found no additional actionable defects.

| Checked artifact | SHA-256 |
| --- | --- |
| Release product | `11d4ba91e47debf09578ad12cea470a899121672940ad5c30b8bce52e252e6a3` |
| IRP binding/replay, ASan | `4ef1b29d77aad6ccad686a46a854b95dc767342c62d17048c51102072849f6c5` |
| Image slice, ASan | `d15ff113a8decf5b5c2c38d9388d1aa8b280ec7726c7c023ba7eaeca8ac8faeb` |
| Image recipe, ASan | `53526f92c3f399a8622d4356d7add1052ee78316d0e37346059349f8f52b3116` |

This used Windows 11 Pro 10.0.28000, kernel 10.0.28000.3231, VS 17.14.60,
MSVC 14.44.35207 and SDK/WDK 10.0.26100.0. Final checks found no remaining
test processes, parser profile directories/receipts/preparations or running
task drivers. Completed content-addressed code caches and private fixture
artifacts are retained deliberately. No driver was loaded, service/policy
changed or reboot performed; BFE/MpsSvc remained running/automatic, EFS
running/manual and all firewall profiles enabled.

Reproduction commands use `tools/validate-irp-binding.ps1 -Sanitize`,
`tools/validate-image-slice.ps1 -Sanitize`,
`tools/validate-image-recipe.ps1 -Sanitize`, and
`tools/test-irp-replay.py <exe> <owned-fixture-directory> --product`.
Use the bundled Python runtime on this host; the Windows Store `python` alias
does not run these oracles. The fixture directory is emitted by the IRP script.

The native IOCTL ABI and request observation v1 remain unchanged. Legacy
capture v1 lacks the recorded source/final-state inputs and receives an explicit
unavailable result. PDB files, source initialization, collector authentication,
external final-state authentication, whole-image integrity, execution,
referenced lifetimes and Windows-build approval are not established. At this
checkpoint, root IRP captures and images lay outside the image journal/store
inventory; the subsequent typed-journal checkpoint above extends that scope. Broader
P05/P06/P13 and VS2/VS3 completion, native lifecycle evidence and the earlier
real-kernel PDB ASan resource failure remain open.

## Pending IRP runtime binding checkpoint: 2026-11-07

P05 now connects the live pending-IRP consumer's retained schemas to loaded
PE/RSDS identity checks, object invariants and original ordered reads. KMON
admits completion targets only after those checks and separately reports capture
queue admission/publication. See the [bounded contract](ARCHITECTURE.md#pending-irp-schema-and-runtime-binding).
Native IOCTL ABI and existing report fields remain compatible; the report adds
qualification scope and capture references. Build approval remains explicitly
`not_established`, and referenced lifetime/execution remain false.

The owned fixture compiles its own `_ETHREAD`, `_IRP` and
`_IO_STACK_LOCATION` PDB types, obtains them through the actual AppContainer
broker, and maps an owned PE plus synthetic object bytes at declared kernel
addresses. Release and ASan each passed **39 controls**. Independent Python
`ctypes`/JSON/hash checks compared **32 fields and 29 original reads**, including
owner generations, reciprocal links, packet/stack values and both RSDS reads.
These are synthetic source observations, not native kernel reads.

Controls cover mixed image/PDB/provider identities, required-field loss,
ambiguous anonymous paths, missing optional cancellation, initial/final image
failure, owner/source replacement, non-kernel completion addresses, original
read failures, cancellation and the 2,048-call budget. Original candidate/read
evidence survives a final binding failure. Private writer integration exercises
actual file-handle admission before writing, immutable collision handling,
four-entry queue pressure, rejection without a private policy and final drain
counts. An output-admission exception leaves no owned pending file.

Review found that equal packet reads could still admit a non-kernel completion
pointer; the parser now rejects that reference. Final caller review also restored
native availability/cancellation checks before schema acquisition. The first full
linked run
exhausted the default 1 MiB stack. CDB traced the nested pipeline/image-writer
test into the journal reader's stack probe. Pipeline monitor fixtures now use
scoped heap ownership; the final full run passed with the default stack size.
The two interrupted synthetic fixtures were identified by their contents and
removed by exact file/empty-directory cleanup. No additional actionable defects
were found in the reviewed scope.

Final Release EXE SHA-256:
`4149d8090d352e01ec8f75866fe2d53dfe80caa99b6c2d026b217eb36c6220ab`.

| Harness | SHA-256 |
|---|---|
| IRP binding, Release | `33f8ca2bbfce7869954f896d0fe52808dabefaac794a12efe154c3c20525e35b` |
| IRP binding, ASan | `2db6a636dea15b05219457f6399574ea03bbb8efa0b2cda2353f1db5801330e5` |
| Existing IRP parser, ASan | `980b60858a34732deaea5f4b7dd570de8ca7628766cb500705cb13f81109eb22` |
| Image slice, ASan | `84fbc29b9aa7cb2713d15bc109b4479f2e9534dbc97ffc98046d74288258328f` |

The existing IRP harness passed **32 controls** and its six-report oracle. The
shared publication helper passed **307 image-slice controls**, followed by
independent slice/sweep/graph oracles (**369/233/1,414**). The first script reached
a missing Python launcher after the C++ pass; the bundled Python then completed
all three oracles against the same executable and fixtures without rebuilding.
The final isolated `--self-test all` passed timeline **28**, MCP **102**, KMON image
**119**, console **564**, command **3,006 / 261 routes**, and remote **68** plus
four connection-option checks. Compiled capabilities (**33 contracts**) and the
generated support matrix passed. Publication-classifier tests passed **12**.

The Release product also produced all three schemas from the retained kernel
PE/PDB fixture: root sizes **1,944/208/72**, fields **866/85/190**, no reported gaps;
the required consumer paths were present. This is a disk-artifact compatibility
check, not validation of a loaded target. The earlier ASan real-kernel PDB
512 MiB failure was not rerun or resolved here.

Reproduction uses `tools/validate-irp-binding.ps1` with and without `-Sanitize`,
`tools/validate-pending-irp.ps1 -Sanitize`, and
`tools/validate-image-slice.ps1 -Sanitize`, with Python 3 on `PATH`. Validation ran
on the same Windows/VS/SDK environment recorded below. Final checks found no
test processes, parser profile directories/receipts/preparations, running known
Kn drivers or interrupted owned fixture directories. BFE/MpsSvc/EFS states and
firewall profiles were unchanged; **26 completed code-cache directories** remain
intentionally. No driver was loaded and no reboot or service/policy change was
performed.

This closes the bounded IRP binding/capture implementation slice. It does not
close P05, P06, P13 or the full P01-P16/VS1-VS4 goal. Exact build approval and
schema-change gates, other typed consumers, native lifecycle/lifetime evidence,
original image/PDB retention, source-initialization receipts and product offline
IRP replay/journal/retention integration remain open.

## Parser AppContainer checkpoint: 2026-11-07

P05 schema, layout and symbol-index workers now use a unique zero-capability
AppContainer. The parent checks the actual suspended child's token, SID and job,
requires running BFE/Windows Firewall services and no loopback exemption, and
removes the native profile before resuming. Approved code is copied into a
checked content-addressed runtime; image/PDB inputs retain their read-only handle
boundary. See the [process boundary](ARCHITECTURE.md#schema-parser-process-boundary).
Native IOCTL ABI and public schema/index formats are unchanged.

Review found that interruption before worker entry could leave a native profile.
Durable private receipts now precede profile creation, and later launches recover
only proven-dead owners. Tests cover a completed profile, an interrupted receipt
and a partial code copy, while preserving live owners. A corrupted published
receipt rejects launch without deleting its profile; the owned byte is restored
before recovery. Code-copy controls independently establish a distinct file ID
and matching hash before testing altered bytes, extra DLLs and writable file or
directory ACLs. The original executable remains unchanged.

The network oracle checks delivery at owned parent listeners. UDP submission
can report success even when no packet arrives, so `sendto` success is not used
as a delivery result. IPv4/IPv6 TCP and UDP positive controls run before and after
the worker attempts. Lifecycle controls require observed worker entry before
timeout, cancellation or parent interruption. Final review also split process
access attempts into individual rights and changed runtime creation to request
write access alone; a denied combination cannot prove that each right is denied.
No additional actionable defects were found in the reviewed scope.

Final Release EXE SHA-256:
`a91f77833e3da839f3c0deb1f22377a13a820061232d39375be86bf3311a0a0d`.

| Harness | SHA-256 |
|---|---|
| Parser worker, Release | `7b427e5eed24b4775febbd9ca877b074e4fbd495653aadf2783d46a6beb806c5` |
| Parser worker, ASan | `dd8073a37fdd6c24be73a11a2d1a921c99856400a5fbb81202fa41c781d798fe` |
| Schema broker, ASan | `37b3309e30b28bf6707731261adea40f9684693014c17af26c05ee4166ec80f1` |
| Symbol index, ASan | `93760bfce458c9c7ee026d32de1427639aec7db384b69db18cd5358d16a5a0f0` |
| Live layouts, ASan | `2569a8bf716582170576dcc0cb79996c87bfd31bbf7f69326c14941a52b9af71` |

Checks used Windows 11 Pro x64 `10.0.28000`, NTFS, VS 2022 Build Tools 17.14.60,
MSVC 14.44.35207 and SDK/WDK 10.0.26100.0. The Release build passed with the
existing C4744 link warnings. Product sources stayed fixed during the applicable
checks; the final worker-only test strengthening did not change product code.
The worker harnesses ran sequentially. **Run these harnesses without concurrent
broker/product tests:** they deliberately corrupt owned recovery receipts and
code copies before restoring them. The final full self-test ran alone after all
builds and other executable tests finished.

| Check | Result and scope |
|---|---|
| `tools/validate-parser-worker.ps1`, with and without `-Sanitize` | 65 controls passed per mode: actual token/identity, five allowed environment names including Windows-added profile-local TEMP/TMP, argument and handle inheritance, job/memory/output limits, observed timeout/cancellation/parent death, individual parent mutation and peer read/duplicate denial, create-only runtime write denial, owned loopback delivery, interrupted-owner recovery and code-copy integrity |
| `tools/validate-schema-broker.ps1 -Sanitize` | 73 controls passed through the AppContainer worker |
| `tools/validate-symbol-index.ps1 -Sanitize` | 69 controls passed |
| Independent symbol-index oracle | Four PE exports, two private MAP addresses, 263 legacy type names and 131 known name/size pairs matched; 452 symbols and 298 types |
| `tools/validate-live-type-layout.ps1 -Sanitize` | 112 controls passed |
| Actual Release executable workers | Two owned symbol-index, two retained kernel-artifact symbol-index and two layout controls passed, including mismatched-PDB rejection |
| Offline schema CLI | 79 controls passed; one file-symlink case remained skipped |
| Capability/documentation contracts | 33 contracts / 261 routes passed; generated support matrix matched |
| Final `--self-test all` | Timeline 28, MCP 102, KMON image reads 119, console 564, command audit 3,006 over 261 routes, remote 68 and four connection-argument checks passed |

Final checks found no test processes, native profile directories, profile receipts
or unfinished runtime preparations. Completed code-only cache directories remain
for reuse by design. No driver/service load, reboot or firewall policy change was
performed. BFE and MpsSvc remained running/automatic, EFS running/manual, and all
three firewall profiles enabled. Original input and installed runtime ACLs were
not changed.

This is an ordinary AppContainer boundary, **not LPAC or a complete filesystem
allowlist**. The network observations cover owned loopback TCP/UDP on this host;
external routes and disabled or changing firewall policy were not exercised.
The earlier ASan kernel-PDB failure at the 512 MiB process limit remains unresolved
and was not rerun as an ASan kernel test here. Release disk-artifact success does
not establish loaded-image identity, runtime invariants, object lifetime or
approved distribution. Those P05 gates, the full design and the earlier
privacy/process-capture observations remain open.

## Approved inherited file reads checkpoint: 2026-11-07

This P05 prerequisite lets parser consumers read approved inherited file objects
when the child's token cannot reopen their path. Worker hash, PE identity and DIA
stream readers now take read-only, non-inheritable duplicates and use explicit
offsets. Default parent-facing APIs retain reopening and independent file cursors.
The original parent leases still exclude writers and deletion; duplication does
not itself approve an artifact or establish an immutable source. See the
[parser handle boundary](ARCHITECTURE.md#schema-parser-process-boundary).

The owned AppContainer reproducer returned access denied for both pathname open
and handle reopen. The new duplicate path read the same approved bytes without
granting access to the input file's path. Review also corrected the test's writer
coordination: the initial Release test could finish before the cursor-changing
thread ran again. The final test requires observed acknowledgements between read
batches while the writer continues changing the implicit cursor. A further
completion-port reproducer exposed notifications containing the reader's
stack-owned `OVERLAPPED` pointer after return. The private event now suppresses
those notifications; an ordinary-read positive control and the parent port check
cover the correction. No additional actionable defects were found in the
reviewed scope.

Final Release EXE SHA-256:
`00702d118471b8205d8b4ea5aa52d5cd06743b1c0d30353d8c4cfb147469e3c5`.

| Harness | SHA-256 |
|---|---|
| Approved file, ASan | `e5802bbe6cdd88261afbc6356e00acace1053d25ee06a7cdce20cd68ed4406fc` |
| Approved file, Release | `12c9af2f006aeb391f174a8d8fb7ae6d650de3aa73713c76b0fb185af0510397` |
| Schema broker, ASan | `8cb71f5da8cb482b37e2c5f359353d8bd8e6a2773bbbe277a428a0e114f56718` |
| Symbol index, ASan | `7c4b17d04f762a0bba4b7303e69de38ae9122b0b2fd91164a1fa4fe04fe56b63` |
| Live layouts, ASan | `591cb88a399e8cd0182f8c851123dcce64f20643c475e6114f527c5831ad5736` |
| KMON core, ASan | `c95c372fc4fdcd89addf3b1d6789f96d0319a7416bd1790718ad922ecb84f66c` |

Checks used Windows 11 Pro x64 `10.0.28000`, NTFS, VS 2022 Build Tools 17.14.60,
MSVC 14.44.35207 and SDK/WDK 10.0.26100.0. Product sources stayed fixed during
the applicable runs. The final Release build passed with existing C4744 link
warnings. The preceding header rebuild also reported C4244 warnings in unchanged
KernelMonitor code. The final full self-test ran
alone after builds and other executable tests finished.

| Check | Result and scope |
|---|---|
| `tools/validate-approved-file.ps1`, with and without `-Sanitize` | 35 controls passed per mode: 10 in each of two actual AppContainer children using synchronous/overlapped inherited files, plus 15 parent controls. Path/reopen denial, matching hashes and PE identity, read-only/non-inheritable duplicates, independent streams/clones under observed cursor changes, completion-port isolation, invalid handles, offset bounds and profile cleanup were checked |
| `tools/validate-schema-broker.ps1 -Sanitize` | 73 controls passed, including default parent cursor preservation and the actual schema worker path |
| `tools/validate-symbol-index.ps1 -Sanitize` | 69 controls passed through the updated worker readers |
| Independent symbol-index oracle | Four PE exports, two private MAP addresses, 263 legacy type names and 131 known name/size pairs matched; final fixture contained 452 symbols and 298 types |
| `tools/validate-live-type-layout.ps1 -Sanitize` | 112 controls passed |
| KMON core, ASan | PE/relocation/coverage and owned handle controls passed, together with execution 835, scheduling 130, hunting 11,345, ordering 77, pages 54 and false-positive 49 controls; the 10-case JSON oracle passed |
| Actual Release executable workers | Two owned symbol-index, two retained kernel-artifact symbol-index and two layout controls passed, including mismatched-PDB rejection |
| Offline schema CLI | 79 controls passed; one file-symlink case remained skipped |
| Capability/documentation contracts | 33 contracts / 261 routes passed; generated support matrix matched |
| Final `--self-test all` | Timeline 28, MCP 102, KMON image reads 119, console 564, command audit 3,006 over 261 routes, remote 68 and four connection-argument checks passed |

This validates the inherited-read prerequisite, **not a product AppContainer or
network-deny boundary**. Runtime DLL access, profile/environment lifecycle,
pre-resume token verification and network negative controls still need integration
before that claim is available. Provider pathname pinning remains unchanged.
The test grants read/execute access only to its fresh fixture's copied ASan DLL;
input files and installed runtime ACLs are unchanged. Temporary test profiles were
removed after the children exited. No driver/service load, reboot or firewall
policy change was performed; final checks found no test processes or profiles.
The earlier ASan kernel-PDB memory-limit failure remains unresolved and was not
rerun as an ASan kernel test in this checkpoint. Release disk-artifact checks do
not prove loaded-image identity, runtime invariants or object lifetime. The full
P05/design goals and the earlier privacy/process-capture observations remain open.

## Symbol index broker checkpoint: 2026-11-07

This P05/W04 step removes parent DbgHelp/DIA parsing from startup preload,
name/address lookup and symbol/type enumeration. Restricted workers return
bounded artifact-bound indexes; repeated queries use parent metadata caches.
The prior four layout APIs retain their separate schema broker. Native IOCTL ABI
and the existing bare symbol-name return format are unchanged. See the
[index boundary](ARCHITECTURE.md#live-symbol-and-type-index-broker).

Adversarial review fixed private function names being returned as full
prototypes, unsafe display of linker control prefixes, ambiguous overload/address
selection, loss of partial enumeration coverage and a full admission ledger
blocking reacquisition of an evicted existing module. A separate legacy-provider
comparison exposed missing enums, typedefs and six type names omitted by global
DIA enumeration. Bounded symbol-table traversal now includes those names; typedef
size lookup follows at most eight metadata aliases. No additional actionable
defects were found in the reviewed scope.

Final Release EXE SHA-256:
`b6cd0b435cc5ffee792a37dbaa9dc9fecce53136c127cda858683c1be96b5a56`.

| Harness | SHA-256 |
|---|---|
| Symbol index, ASan | `d440c05e86244fb77026b915893bdffc6c5545015881eccd7e6f5db710d0a53a` |
| Symbol index, Release | `96888d609ec6b501a1cf019779ab603cb4c93c6b687e3986702c484aecd25aea` |
| Live layouts, ASan | `3512b3af717aaeecb7593b16a9fb4d8fc9d768e4e7c16751e0f14b07d86d4dcb` |
| Parser worker, ASan | `bd50cea9f4d21110677eb25767fc940a26f0d63ed4bd90bcda3012addae1d535` |
| Schema broker, ASan | `67513e056d180d70c9640c2b74ad80b805a455d4921b23a9c422d2ac8bb5fe85` |

Validation used Windows 11 Pro x64 `10.0.28000`, NTFS, VS 2022 Build Tools
17.14.60, MSVC 14.44.35207 and SDK/WDK 10.0.26100.0. The final Release build
passed with the existing C4744 warnings. Sources and binaries were held fixed
for applicable runs. The final linked self-test ran alone after builds and other
oracles completed.

| Check | Result and scope |
|---|---|
| `tools/validate-symbol-index.ps1`, with and without `-Sanitize` | 69 controls passed in each mode: actual worker/API integration, static/private/exported/overloaded names, compiler enum/typedef/UDT sizes, strict framing and artifact mismatch rejection, parent provider isolation, LRU/reset/failure behavior, synthetic admission-ledger pressure with real reacquisition, partial results and unavailable-module ambiguity |
| `tools/symbol-index-oracle.py <fixture-directory>` | Independent PE/RSDS/hash/framing reader matched four PE exports and two private linker-MAP addresses. The separate owned-fixture DbgHelp oracle's 263 type names and 131 known name/size pairs were all present. Final fixture index contained 452 symbol rows and 298 type rows; seven raw linker control prefixes had escaped display names |
| Real kernel PDB, Release harness | 56,077 symbol rows and 2,669 type rows; six startup-preload, qualified/nearest lookup, type-list, repeated-query and parent-DIA controls passed. Initial acquisition was 4,219 ms and 10,000 cached lookups were 3,496 microseconds in this run; these observations are not a latency SLO |
| Actual Release executable workers | Two owned-fixture index controls, two kernel-artifact index controls and two layout controls passed, including mismatched-PDB rejection |
| `tools/validate-live-type-layout.ps1 -Sanitize` | 112 existing API/layout/read/cache controls passed against the final engine |
| `tools/validate-parser-worker.ps1 -Sanitize` | 22 controls passed, including explicit 3 MiB output, retained default 2 MiB rejection and rejection above the 32 MiB ceiling |
| `tools/validate-schema-broker.ps1 -Sanitize` | 73 approved-handle, identity, protocol and containment controls passed; its exercised code remained unchanged by the later index-only type-discovery fixes |
| Offline schema CLI | 79 controls passed; one file-symlink case skipped. This does not close that environment gate |
| Compiled contracts and documentation | 33 capability contracts / 261 routes passed; generated support matrix matched |
| Final `--self-test all` | Timeline 28, MCP 102, KMON image reads 119, console 564, command audit 3,006 over 261 routes, remote protocol 68 and four connection-argument checks passed |
| Publication classifier | 12 tests passed, including renamed binary symbol indexes |

The real artifact pair was Windows kernel `10.0.28000.3231`, image SHA-256
`0e04b67c16f05f14e046a275097769a29ca88692ce3278eebc39ad476d922a76`,
and the retained 12,136,448-byte PDB with GUID/age
`29542158dc36b6d41d7f2dd8cb7ce68a` / `1`, SHA-256
`c9521a2a2a98793e7165a053be53c3eb425d5379655b72146b24ab638fc5fa51`.
The installed provider SHA-256 was
`9c06a43a03b413fc885bf05faf7974b3bb8f8248507b3b51fda6d9376eb7768b`.
These checks bind disk artifacts, not the currently loaded kernel image.

**The ASan kernel-PDB run remains unavailable.** The final instrumented worker
exited 1 with no accepted rows. A diagnostic copy reported `Failed to mmap`
and peak process commit of 536,858,624 bytes against the unchanged 536,870,912-byte
job limit. Earlier diagnostics also reported failure to commit ASan shadow memory
at that limit. The job limit and sanitizer quarantine were not relaxed. The
successful Release kernel run and owned-fixture ASan checks do not turn this into
a passing ASan kernel test. MSVC ASan also preloaded DbgHelp before `main` in a
minimal independent probe; the ordinary Release probe did not. Parent tests
therefore compare initial DbgHelp state and require DIA to remain unloaded.
The final Release import table contains no DbgHelp symbol-parser imports, and
SymbolEngine source has no parent provider calls.

This completes the bounded SymbolEngine parser migration, not P05 or the full
integration design. Enforced worker egress denial, authenticated distribution,
loaded-image/anchor/runtime-invariant/lifetime binding, propagation into every
typed observation and isolation of other parser families remain open. Enumeration
is bounded metadata discovery, not a complete runtime-object inventory. Only this
host and artifact pair were exercised; the full Release program was not ASan-built.
Existing privacy-initialization and process-capture timing observations below remain
unresolved. No driver/service load, reboot or host security-policy change was
performed. Final targeted checks found no task processes or KnLiveDbg drivers;
EFS remained OS-managed Manual/Running.

## Live type layout broker checkpoint: 2026-11-07

This P05/W04 step migrates `GetTypeLayout`, `GetTypeLayoutById`, `GetTypeFields`
and `FindField` to the artifact broker. PDB acquisition uses the local image's
bounded RSDS identity and approved local/HTTPS search roots without parent PDB
parsing. Restricted workers provide layouts; parent checks bind the result to
the leased image/PDB/provider. Nested offsets, bit storage and coverage survive
conversion into bounded, expiring opaque type IDs. No worker failure triggers an
in-process layout fallback. See the [live layout boundary](ARCHITECTURE.md#live-type-layout-broker).

Adversarial review fixed pre-probe network/device path exposure, the gap between
temporary-file validation and cache publication, ambiguous case-folded field
selection and stale result outputs. A native empty-directory reproducer showed
that `FILE_READ_ATTRIBUTES` alone did not prevent rename; cache pins now include
`FILE_LIST_DIRECTORY`. The regression tests that directory before any child file
exists, separately from file-lease protection. Publication copies from the held
verified lease into an exclusive create-new file, and temporary cleanup checks
the original file ID. Review also prevented oversized bitfields from reaching a
64-bit display shift and made unknown field coverage visible. No additional
actionable defects were found in the reviewed scope.

Final Release EXE SHA-256:
`3312115f0938e202a0bba5283583d167366b18c81342639ce97fc551183d989f`.
Final helper hashes:

| ASan harness | SHA-256 |
|---|---|
| Live type layouts | `917f852bd1be969cbc63894dbbd4b8d23cca75cb9a5c9000ba200bfbb324ea7b` |
| Schema broker | `53c0f538d08ebf601b64722c01e95d6eb4fddd10ae31acdca5540225da6b09dc` |
| PDB identity | `6a62dd5f42cad205e78c315ffff0e26d7d8b8957dcd386339650299481c11a3e` |
| Shared KMON/PE core | `366fab5da16e9e1ad7df67989ae1c1855061bc6c1e2b16275732708b651e3124` |

Validation used Windows 11 Pro x64 `10.0.28000`, NTFS, VS 2022 Build Tools
17.14.60, MSVC 14.44.35207 and SDK/WDK 10.0.26100.0. The final Release build
passed with the existing C4744 warnings. Sources/binaries were frozen during
applicable runs, and the final linked self-test ran alone after builds and other
oracles completed.

| Check | Result and scope |
|---|---|
| `tools/validate-live-type-layout.ps1 -Sanitize` | 112 controls passed through the actual SymbolEngine APIs: compiler `sizeof`/`offsetof`, owned `ReadProcessMemory`, nested and bitfield semantics, unique/ambiguous aliases, pointer/array/depth/inheritance limits, cache eviction and nonreused IDs, concurrent lookup/reset, wrong PDB/module size, missing provider, cleared failure output, parent DIA remaining unloaded, cache collision/copy/cleanup and empty/reparse-directory pins |
| Final Release worker integration | Two controls passed using the actual `KnLiveDbg.exe` live-worker dispatcher: a normalized type alias was accepted, and a mismatched PDB was rejected |
| Direct HTTPS acquisition | A fresh cache received the 12,136,448-byte kernel PDB from the Microsoft public symbol server. An independent Python oracle checked canonical package hash, image/PDB hashes, SDK `_LIST_ENTRY` offsets and absence of pending files |
| Real cached kernel PDB | Ten controls passed: `_LIST_ENTRY`, `_EPROCESS`, `_ETHREAD`, `_IRP`, `_IO_STACK_LOCATION`, `_DRIVER_OBJECT`, `_DEVICE_OBJECT`, SDK list layout, an embedded process field and no parent DIA load. These are artifact-layout checks, not kernel-object observations |
| Existing schema/PDB regressions | 73 broker and 52 PDB identity/layout/package ASan controls passed. Final Release schema CLI passed 79 independent Python checks |
| `tools/validate-kmon-core.ps1 -Sanitize` | Shared PE/relocation controls, 835 execution, 130 scheduling, 11,345 hunting, 77 ordering, 54 page, 49 false-positive controls and ten execution-JSON oracle checks passed |
| Final Release `--self-test all` | Timeline 28, MCP 102, KMON image/read 119, console 564, commands 3,006 across 261 routes, remote 68 and four connection-argument controls passed. Console coverage includes oversized-bitfield rejection and unknown field-coverage display |
| Contracts/publication | 33 compiled capability contracts and 261 routes passed; generated support matrix matched; publication classifier tests passed 11 controls |

The real artifact pair was `ntoskrnl.exe` version `10.0.28000.3231`, image SHA-256
`0e04b67c16f05f14e046a275097769a29ca88692ce3278eebc39ad476d922a76`, with PDB GUID
`29542158dc36b6d41d7f2dd8cb7ce68a`, age 1 and SHA-256
`c9521a2a2a98793e7165a053be53c3eb425d5379655b72146b24ab638fc5fa51`.
The downloaded PDB remains a local validation artifact, not a published package.
The separate CLI file-symlink fixture was skipped by host permissions; the cache
directory-junction rejection case ran successfully. No security policy was
changed to enable either test.

This is a bounded live-layout migration, not completion of P05 or the full design.
Startup symbol preloading, symbol resolution and type enumeration still parse in
the parent. Enforced worker network denial, approved distribution, exact loaded
target image binding, runtime object/anchor invariants, lifetime binding and
propagation into every typed observation remain open. Helpers were ASan-built;
the full Release program was not. Only this host/artifact pair was exercised;
authenticated/proxy/compressed symbol stores, transport interruption, media/power
failure and other filesystems were not validated. HTTPS acquisition and file
hashing have cooperative limits, not a whole-operation hard deadline. Existing
privacy-initialization and process-capture timing observations below remain
unresolved. No driver/service load, reboot or host security-policy change was
performed; final targeted cleanup checks found no task processes or KnLiveDbg
drivers. EFS remained the OS-managed Manual/Running service.

## Schema artifact broker checkpoint: 2026-11-07

This P05/W04 step binds offline schema creation to parent-owned artifact leases.
The parent verifies returned image/PDB/provider hashes, PE machine/image size,
RSDS GUID/age and requested type against its own inputs. The restricted child
receives three read-only file handles; DIA reads a PDB stream rather than opening
its supplied pathname. Provider loading pins its ancestor directories and file
identity. The existing public CLI and `kn.type_schema.v1` format remain unchanged.
See [schema parser boundaries](ARCHITECTURE.md#schema-parser-process-boundary).

Review found that the previous parent accepted any internally consistent package
with the requested type and `parser_isolated=true`, without comparing its artifact
identities to the requested files. Actual hostile-worker controls now return
canonical, checksum-valid mismatches and are rejected. Review also added provider
directory pins and restricted the parent's PE decoder to bounded headers,
sections and RSDS identity. Omitted relocation facts remain incomplete; the parent
does not parse managed-image or relocation tables to obtain a schema identity.
The shared PE reader now closes its file on C++ exception unwinding as well.
No additional actionable defects were found in the reviewed scope.

Final Release EXE SHA-256:
`eb0e3c4d8d91518baf215b852c85ad3af789a8fac51356c6cb1c7fb142c2256e`.
Final ASan harness hashes:

| Harness | SHA-256 |
|---|---|
| Schema broker | `8f535567c0946f7dd945f770e3ee62c589b3c215fb662e74b736600c08e3062a` |
| PDB identity | `9f8ccfebc2f14da28da2d1bd2b06be4d2bef3f6b2b3649409e2cc2fcf1f01c2b` |
| Parser worker | `897b0060bb9a9024b8891be6eb44a3fbfea180eafb959e74565977553a700691` |
| Shared KMON/PE core | `de6bee5c70c44b9cc5a712385ae3914f92d58d3851291e7ecba56ede3221cbc9` |

Validation ran on Windows 11 Pro x64 `10.0.28000`, NTFS, using VS 2022 Build Tools
17.14.60, MSVC 14.44.35207 and SDK/WDK 10.0.26100.0. Sources and binaries were
frozen during each applicable run; the linked `--self-test all` ran after builds
and other oracles had completed.

| Check | Result and scope |
|---|---|
| `tools/validate-schema-broker.ps1 -Sanitize` | 73 controls passed: actual restricted worker, wrong artifact identities/type, unisolated/failed/flooding/hanging child, read-only handles, invalid handle allowlist, file bounds, provider directory pin, stream EOF/seek/overflow/clone concurrency, independent compiler `sizeof`/`offsetof` and owned `ReadProcessMemory` oracle |
| `tools/validate-pdb-identity.ps1 -Sanitize` | 52 existing PDB/layout/package controls passed with stream loading and the identity-only PE path; wrong-build PDB, bitfields, nested paths, inherited gaps and depth limits remain covered |
| `tools/validate-parser-worker.ps1 -Sanitize` | 19 controls passed, including crash/timeout/cancellation, memory/child-process limits, unrelated handle/environment exclusion and observed parent-death cleanup |
| `tools/test-type-schema-cli.py` against the final Release EXE | 79 checks passed: independent Python artifact/package hashes, canonical output, fresh-process inspection, legacy unisolated packages, wrong PDB/type, collisions, malformed metadata and Unicode/space paths |
| `tools/validate-kmon-core.ps1 -Sanitize` | Shared PE/relocation regressions passed; 835 execution, 130 scheduling, 11,345 hunting, 77 ordering, 54 page and 49 false-positive controls passed; independent execution JSON oracle passed 10 controls |
| Final Release `--self-test all` | Timeline 28, MCP 102, KMON image/read 119, console 558, commands 3,006 across 261 routes, remote 68 and four connection-argument controls passed |
| Contracts/publication | 33 compiled capability contracts and 261 routes passed; generated support matrix matched; the publication classifier's 11 controls passed |

The CLI oracle reported `symlink_skipped=1`: this host did not permit creating
the symlink fixture. Final-reparse rejection is implemented but that execution
case remains unvalidated here. No policy was changed to enable it. Final targeted
readbacks found no KnLiveDbg-family drivers or test processes. EFS remained the
OS-managed Manual/Running service observed before testing; it was not stopped.
No driver load, reboot, host clock or security-policy change was requested by
these tests. Existing C4244/C4744 build warnings remain.

This is the offline broker prerequisite, not completion of P05. Live SymbolEngine
consumers, target image/object/anchor binding, supported-build attestations,
runtime invariants and object lifetime remain open. The installed EXE/DLL are
trusted runtime inputs; hashes do not authenticate distribution or attest a
compromised parser's semantic output. The child has no enforced filesystem or
network deny policy. Parent hashing and synchronous I/O are not covered by a
whole-operation hard deadline. ASan covers the helper harnesses, not the complete
Release EXE; allocator fault injection and other OS/filesystem environments were
not validated. Earlier privacy initialization and process-capture timing
observations remain unresolved and are not closed by these passing runs.

## Local hunt ordering checkpoint: 2026-11-07

This F07/P07 step removes the current hunt view's global latest-event gate.
Independent delayed targets and paths can remain current within arrival freshness,
while per-path, mapping-label and process-generation guards prevent rollback of
retained state. The guards survive hot-row eviction and explicit retirement.
Query JSON and saved analyst snapshots report their bounded capacity, deferrals
and conservative transition floor. Receipt/bundle formats and the driver ABI are
unchanged. See [local current-view ordering](ARCHITECTURE.md#local-current-view-ordering).

The original defect was reproduced with PID 55 observed at tick 200 followed by
independent PID 56 observed at 150 and arriving at 210: the second observation
incorrectly became `historical_only`. Further review reproduced rejection of a
new generation with a smaller creation FILETIME and retention of stale current
rows when the new generation's guard could not be stored. The final rules use
observed generation transitions, retire known previous generations even under
guard pressure, and withdraw the affected process's current rows on that denial.
Page zero no longer aliases a retirement marker. The expiry index also prepares
allocating lookups before mutation and removes old entries by saved iterator.

Final Release EXE SHA-256:
`b701430a9c5b1c1ab4784733861d46ab2863b639efe9afeeece345b3bf9bab74`.
Final ASan harness hashes:

| Harness | SHA-256 |
|---|---|
| KMON core | `0afca301c5fb5fb88777ec375b527b6cec08a9fd455c14d6f0391666c70545f5` |
| Analyst features | `1ed6d7c826132cefbaca81e2a4ed2b5ee0c0008353e9ece8a4d4677def150800` |
| Hunting replay | `19c1f74aab074093ca2d88f56c37e94608d9c3de78689c8acee039437c909b78` |
| Evidence bundle | `13868490d808d29c11511154a4f67dff4107bde4068a743db859455e016b23fb` |
| Temporal facts | `23eee99be2aa5a591a7b6ff1ee17525add4b3e893b3b792fdb2354260e49a64b` |

The final core ASan run passed 77 ordering checks, including all 24 permutations
of four observations against independently specified current rows and exact
original histories. Controls cover independent paths, source-label bypasses,
slot retargeting, delayed retirement, eviction, unknown assertion bridges,
backward-valued generation keys, capacity denial, recovery, page zero and
`uint64` boundaries. Existing hunting 11,345, page 54, false-positive 49,
capture scheduling 130 and execution-evidence 835 checks also passed, with ten
independent execution JSON controls. The hunting runner repeated its shared
controls and rejected eight malformed inputs; its four owned process fixtures
(`clean`, `modified`, `text`, `jit`) passed. No external detector comparison ran.

The analyst ASan runner passed 6,612 checks, including preserving ordering limits
as snapshot coverage, legacy snapshots without that block, and rejection of false
clock/loss/capacity claims. The legacy evidence runner passed 522 controls and its
eight existing timed publication interruptions: three valid final files, five
absent final files, successful restart. This is not synchronized v2 publication
or power-loss validation. The temporal ASan oracle passed 147 checks including
the final Release CLI and original v1/v2 bundle compatibility.

```powershell
.\tools\validate-kmon-core.ps1 -Sanitize
.\tools\validate-analyst-features.ps1 -Sanitize
.\tools\validate-kmon-hunting.ps1 -Sanitize
.\tools\validate-evidence-bundle.ps1 -Sanitize
.\tools\validate-temporal-facts.ps1 -Sanitize -Cli .\x64\Release\KnLiveDbg.exe
.\x64\Release\KnLiveDbg.exe --self-test all
```

The final full suite ran after builds and standalone oracles had finished:
timeline 28, MCP 102, KMON image-read 119, console 558, commands 3,006 across
261 routes and remote 68 passed, plus four connection-argument controls. The
KMON pipeline fixture read two owned pointer slots, observed distinct collector
ticks, then delivered them in reverse capture order; both remained queryable.
Capability checks passed for 33 contracts, the generated support matrix matched,
and all 11 publication-classifier tests passed. Final targeted host readback found
zero KnLiveDbg-family drivers and zero task processes. EFS remained OS-managed
Manual/Running, as before the stage; no explicit driver load or service change ran.

Local diagnostic logs are `.build/p07-ordering-transition-{core-asan,build,
analyst-asan,hunting-asan,legacy-asan,temporal-asan,selftests}.log`. The initial
core build exposed a missing `ReferenceArtifact.cpp` dependency in older core,
hunting and analyst scripts; all three lists were repaired and the final runners
completed. VS 2022 BuildTools 17.14.60 / MSVC 14.44.35207 / SDK and WDK
10.0.26100.0 built on Windows 11 Pro x64 10.0.28000 / NTFS. Existing C4244 and
C4744 warnings remain. Earlier 70-check binaries and logs are superseded here.

This validates bounded local-clock reducer behavior and owned user-mode
integration. The Release EXE is not ASan-instrumented. Generation-key reversal
was synthetic; the host system clock was not changed. Foreign-clock adapters,
CPU-specific loss, source-restart correspondence, loaded native-controller
behavior, allocation-failure injection and general lifetime/temporal coverage
remain unvalidated. The earlier privacy-initialization and process-capture timing
observations remain unresolved. Full F07/P07 and P01-P16 / VS1-VS4 remain open.

## Local temporal candidate checkpoint: 2026-11-07

This P07 step adds origin-bound `kmon.bundle.v2` captures and offline
`!kmon relate` over explicit retained bundle membership. The versioned policy
keeps original observations separate, preserves every pair's requirements and
contradictions, and supports only local-collector temporal candidates. Legacy
v1 remains readable without acquiring missing identity or clock assertions.
See [cross-bundle temporal candidates](ARCHITECTURE.md#cross-bundle-temporal-candidates).
Full P07 and P01-P16 / VS1-VS4 completion remains open.

The checked host was Windows 11 Pro x64 **10.0.28000** on NTFS, with VS 2022
Build Tools **17.14.60**, MSVC **14.44.35207** and SDK/WDK **10.0.26100.0**.
The final Release build exited 0. Existing `NextQueryEpoch` C4744 link warnings
remain; the initial broader build also retained the existing C4244 warning in
`KernelMonitor.cpp`. Final SHA-256 values:

| Artifact | SHA-256 |
| --- | --- |
| Release `KnLiveDbg.exe` | `60b1a39947b4ca50540a99bf94b571fab915ba8106d64a6a635fd4cd513ab388` |
| ASan temporal harness | `a9ed0d8fedb86150def9a47c987f55df32207d9109b2f07d6790e06b1deeb168` |
| ASan legacy evidence harness | `ef0b831a602db4a6f4fe36f076dfaec2dcb92493ba723f2d531a815cebc999c8` |

`tools/validate-temporal-facts.ps1 -Sanitize -Cli x64/Release/KnLiveDbg.exe`
compiled the core with `/W4 /WX /fsanitize=address` and passed **147** independent
Python-oracle checks. They cover exact content/query identities, every pair and
source reference, recorded capture order despite late arrival, overlapping
intervals, gap boundaries, collector/boot/process-generation/native-epoch
separation, known/unknown EPROCESS and session assertions, address contracts,
legacy fallback, missing/corrupt/oversized/duplicate inputs, cancellation and
pagination. The 32-input boundary produced exactly **496** distinct pairs;
33 inputs were denied. The actual EXE covered grammar, Unicode paths, v1/v2
single-bundle graph compatibility and broken-output exit 3. Original input bytes
remained unchanged; no target acquisition was needed by the query.

Adversarial review reproduced a v2 file with its address descriptor removed
being accepted through the legacy fallback and producing a supported candidate.
The final parser requires an original descriptor in v2; the negative oracle
now denies that file. V1 fallback remains explicitly marked, and the report
labels its decoded reference representation `normalized_legacy_compatible`.
Invalid user-reader/kernel-origin combinations are also denied. Hash failure
does not create a valid empty-content identity or a partially published relation.
No additional actionable defects were found in the reviewed scope.

The final `tools/validate-evidence-bundle.ps1 -Sanitize` run passed **522**
existing evidence, inventory and graph controls. Its eight existing timed
publication-interruption controls yielded **3** valid final files and **5**
absent final files; fresh-process reconstruction passed. Those are legacy
publication controls, not newly synchronized v2 crash or power-loss tests.
`tools/test-evidence-graph-cli.py` passed **164** checks against the final EXE
and those final fixtures.

The isolated final `--self-test all` exited 0: timeline **28**, MCP **102**,
KMON image **119**, console **558**, command checks **3006** across **261** routes,
and remote protocol **68** passed. Its KMON pipeline fixture performed two actual
owned `ReadProcessMemory` observations, bound and queued both, freed the source
allocation, drained the writer, and required a supported candidate from the
reloaded files. A changed native-epoch binding was denied. This exercises the
user-mode publisher/helper path, not a loaded native driver. Compiled capability
validation passed **33** contracts / **261** routes; the generated support matrix
matched the final EXE, and all **11** public-content classifier tests passed.

Private evidence: `.build/p07-temporal-address-contract-build.log`,
`.build/p07-temporal-origin-gap-repro.log`, `.build/p07-temporal-final-asan.log`,
`.build/p07-temporal-final-legacy-asan.log`, `.build/p07-temporal-final-selftests.log`.
Final temporal fixtures are `run-15a1577268d145da9fbc5eaab584e0ca` under
`.build/temporal-facts/Release-asan`; legacy fixtures are
`run-adf436bf8c8b452cb1e1458adcbd6e0f` under `.build/evidence-bundle/Release-asan`.
Earlier 97/141-check temporal runs and earlier EXE/full-suite results are
superseded by these final observations. Retained synthetic originals remain
private. Targeted host readbacks found zero task processes and zero KnLiveDbg
driver instances. No driver or test service was explicitly loaded or started;
Windows EFS remained OS-managed Manual/Running.

This is core ASan and owned user-mode validation. Real cross-VM/provider
correspondence, calibrated clock conversion, live reducer freshness, native
driver lifetimes, other evidence families, persistent temporal indexing and
mapping-lifetime/execution/write/causal relations remain open. Collector fields
and hashes do not authenticate a collector or hostile evidence owner. The prior
unexplained privacy initialization failure and process-capture timing observation
also remain unresolved; these passes do not establish their causes.

## Minimized image disclosure checkpoint: 2026-11-07

This bounded P06/P15 step adds offline `redact-image`/`disclosure` and console-local
`ai share preview/send/cancel`. Original-policy replay produces closed-vocabulary
image counts in an EFS-default private package with an original/proof/hash linkage.
The provider requires an exact pending review and a committed private intent;
approval is consumed once and unknown outcomes never authorize an automatic retry.
Unclassified and captured raw output are denied, including external CLI requests.
Operator prompts omit hidden symbol paths and session-expanded targets. See
[minimized image disclosure](ARCHITECTURE.md#minimized-image-disclosure).
The full P06/P15 and P01-P16 / VS1-VS4 goals remain open.

The checked environment was Windows 11 Pro x64 **10.0.28000** on NTFS,
VS 2022 Build Tools **17.14.60**, MSVC **14.44.35207**, SDK/WDK **10.0.26100.0**.
The final Release build exited 0; the existing `NextQueryEpoch` C4744 link warnings
remain. Final binary SHA-256 values:

| Artifact | SHA-256 |
| --- | --- |
| Release `KnLiveDbg.exe` | `3ee7c73f2e6fc132b311e2e19d6910623d5ca92fdf0655ed38c5c28c7f4ec02b` |
| ASan disclosure/provider harness | `8407294ad180461da1212bbc98485076a82982d2093d6324d6efde05b9a354be` |

`tools/validate-evidence-disclosure.ps1 -Sanitize -ImageSliceFixtures <retained-slice-fixtures>
-ImageRecipeFixtures <retained-recipe-fixtures> -Cli x64/Release/KnLiveDbg.exe`
builds the core harness with `/W4 /WX /fsanitize=address` and runs the independent
Python oracle. Source fixtures come from `validate-image-slice.ps1` and
`validate-image-recipe.ps1`; this run reused their retained synthetic originals
read-only. The final oracle was also run directly against the final EXE and the
unchanged ASan harness. It passed **506 checks**, observed **14 loopback HTTP
requests**, and ended with **0 owned child processes** and a closed listener.

The final isolated `--self-test all` run exited 0: timeline **28**, MCP **102**,
KMON image **119**, console **558**, command checks **3006** across **261** routes,
and remote protocol **68** passed. The compiled-capability check passed **32**
contracts / **261** routes, the regenerated support matrix matched the final EXE,
and the public-content classifier's **11** tests passed. No additional actionable
defects were found in the reviewed scope.

The oracle checked exact original-file, semantic, fresh replay-proof and derivative
hash links; count partitions for recipe/slice/sweep scopes; null versus zero;
unchanged originals; EFS attributes; canonical field and bound rejection; malformed,
copied, partial and unreplayable packages; no overwrite; immutable reviewed files
and pinned roots. Three publication interruptions and one intent interruption were
synchronized on observed work, without sleep-based ordering. A manifest-last
package recovers only after the manifest is committed. An interrupted intent
remains unresolved and cannot restore an in-memory approval after restart.

Owned receivers verified exact reviewed facts/system/model, intent existence
before receiving the body, and absence of raw output and hidden session canaries.
Tests covered all three HTTP provider adapters with synthetic credentials, unknown
and raw origins, explicit operator text, CLI rejection before process resolution,
wrong/changed/revoked/reused approvals, configuration and credential changes,
header-control injection, redirects, implicit-auth challenges, HTTP failure and
post-send audit collision. The real EXE offline grammar, Unicode paths, output
failure exit 3, and actual preview/send/cancel/chat handlers were exercised before
controller startup. An actual provider-error response containing an ESC sequence
reproduced raw terminal output; the final handler escapes it, records the unknown
outcome and makes no automatic resend. Returned advice is never executed.

The review also corrected rejected zero-range slices being omitted from disclosure
and session-expanded PID/image/address/dump hints being classified as operator
text. Zero-range slices now retain an unqualified empty scope and unknown change
count. Local command interpretation retains its context, while provider requests
use the original operator text. Help checks were updated for the changed behavior.

Private evidence: `.build/p06-disclosure-error-escape-build.log`,
`.build/p06-disclosure-final-asan.log`, `.build/p06-disclosure-final-handler.log`,
`.build/p06-disclosure-complete-selftests.log`;
the final owned fixtures are `disclosure-c1d09f34f4c84b4384cf2cb0cd651790` under
`.build/evidence-disclosure/Release-asan`. Earlier core/CLI passes are superseded
by the final handler oracle where applicable. Packages and receipts were retained;
no real evidence was deleted or sent to an external service.

This is core ASan and owned-loopback validation, not full-EXE ASan, real provider
availability, production HTTPS/proxy configuration, OAuth refresh/retry, loaded
driver/controller startup, other filesystems or power-loss testing. The owner,
SYSTEM and administrators remain trusted. No driver or test service was explicitly
loaded or started. Windows EFS remains OS-managed Manual/Running, as recorded in
the prior privacy checkpoint. Its earlier unexplained initialization failure and
the historical process-capture timing observation remain unresolved observations;
these passing controls do not establish their root causes. General offline
inference/child confinement, MCP/remote egress controls, other evidence adapters,
key recovery and broader retention/native gates remain open.

## Private evidence root checkpoint: 2026-11-07

This P06 step adds offline `init-store`/`privacy` and opt-in KMON `/private-log`.
New roots require a protected current-principal/SYSTEM DACL and EFS by default;
ACL-only mode requires an explicit option. Root identity and canonical policy
admission preserve the existing plaintext hashes, original artifacts and replay
formats. See [private evidence roots](ARCHITECTURE.md#private-evidence-roots).
The rest of P06 and P01-P16 / VS1-VS4 remains open.

The final Release EXE SHA-256 is
`761af60a63fe8ef190ce2456c2d8bdd289940dd54e5c93d8d93f9fab1235b853`.
The standalone privacy ASan harness SHA-256 is
`542a3c41dbac0d060cd2066fb3052f6e50eccad889d3bfd21bc3331c92235ae9`.
`tools/build.ps1 -Configuration Release -WindowsTargetPlatformVersion 10.0.26100.0`
completed with VS 2022 Build Tools 17.14.60, MSVC 14.44.35207 and SDK/WDK
10.0.26100.0, using the existing test certificate. The final build log is
`.build/p06-privacy-utf8-build.log`; existing `NextQueryEpoch` C4744 link warnings
remain. The earlier broader build also reported the existing C4244 fill warning.

`tools/validate-evidence-privacy.ps1 -Sanitize` passed 770 independent Python
checks against the core (`.build/p06-privacy-path-asan.log`). The host was
Windows 11 Pro x64, OS version 10.0.28000, with an NTFS fixture volume. The final EXE
passed 780 CLI checks (`.build/p06-privacy-diagnostic-cli.log`), including Unicode
JSON and broken-output exit status. The independently inspected owned NTFS
fixtures established actual owner/DACL grants, full physical identity, exact
policy hashes, EFS attributes and new-file encryption inheritance. An owned
restricted token with disabled privileges and a World restricting SID was
actually denied the original bytes; no separate Windows account was created.
This is OS metadata/access testing, not a raw-media ciphertext examination.

Controls reject copied/noncanonical/malformed/oversize policies, wrong principal,
widened root/file ACLs, missing directory inheritance, policy hardlinks,
descendant/root junctions, plaintext children under EFS, ambiguous trailing
dot/space names, alternate streams and DOS device names. Unicode and spaced
paths pass. Observed guard lifetime excludes root deletion and policy overwrite;
a second rejected Open retains the first guard. A destination created after
policy publication is preserved when the actual final rename fails. Four
observed initialization interruptions distinguish private staging from a ready
published root. Every child and pipe reader was reaped. These fixtures and
interruption remnants stay private under `.build/evidence-privacy/Release-asan`.

Adversarial review fixed metadata-only directory handles that did not enforce
share exclusion, premature release of an active session guard after a rejected
Start, pre-validation Windows path normalization, Unicode CLI truncation and a
missing pending-policy public-content classification. Descendant inheritance,
single policy counting and guard reentry are also covered. No additional
actionable defects were found in the reviewed scope.

The isolated final `--self-test all` run passed timeline 28, MCP 102, KMON image
integration 119, console 558, command audit 3,006 across 261 routes and remote 66
(`.build/p06-privacy-final-selftests.log`). Actual KMON ACL and EFS roots exercised
JSONL writes/rotation, retained source bytes after the original disappeared,
reference/read/recipe publication, journal closure/recovery, original-policy
replay, stopped-store inventory and handle cleanup. The complete KMON fixture
tree was removed. The capability checks passed 31 contracts; the generated
support matrix matches the final EXE and retains `not_probed`. Public-content
classifier tests passed 11 controls, including renamed and pending privacy data.

One earlier final-binary CLI run stopped on an initialization failure before
publishing its target (`.build/p06-privacy-utf8-cli.log`). The test then did not
retain the exact returned issue, so its cause is unresolved. Inspection found
the retained staging directory and policy valid; a targeted new initialization
and the subsequent diagnostic suite passed. Diagnostics now include status/issue.
This observation is not relabeled as resolved or as an encryption downgrade.
The older concurrent-load process-capture deadline observation likewise remains
separate from this isolated suite pass.

No native driver load or reboot was requested. Windows automatically activated
its Manual-start EFS service; it remained OS-managed and running afterward.
No owned test processes remained. EFS recovery-agent/key backup, hostile owner
or administrator changes, atomic/continuous security monitoring, other filesystems,
large-tree exhaustion, transfer minimization/approval, linked redaction and
media/power-loss guarantees are not established by these checks. Committed-root
retirement, broader retention policies and the remaining architecture gates
remain required work.

## Image retention priority checkpoint: 2026-11-07

This P06 step connects retention priority to the actual KMON routed-image queue,
writer, journal and final failure ledger. First differences, observation gaps
and repeat/clean slices have separate 4/2/2 admission slots. Raw and recipe file
budgets are each partitioned 64/32/32 MiB; each class can retain one 64 MiB
reference. New-reference and outstanding-reference accounting therefore each
have an aggregate 192 MiB ceiling, replacing the previous shared 128 MiB limit.
This is an explicit reference-budget change, not a total process-RAM or reserved
disk-space guarantee. See the [policy contract](ARCHITECTURE.md#image-retention-priority).

Final Release EXE SHA-256:
`1f22327bc80c1ae9a141bc64e7f9614013a23a537c2e00566e4615cfefd74fff`.
ASan policy harness SHA-256:
`2d032c09d17742a81281d70094cb7540d1879d5d42fe182dca4c5a813a4f3970`.
Builds passed with VS 2022 Build Tools 17.14.60 / MSVC 14.44.35207 and
SDK/WDK 10.0.26100.0. Existing C4744 `NextQueryEpoch` warnings remain; the
initial broader rebuild also reproduced the unchanged `KernelMonitor.cpp`
C4244 fill conversion warning.

The ASan harness passed **34 controls** and the independent Python oracle
passed **109 accounting invariants**, including **9,000 concurrent admission
attempts** across the three classes. The oracle checks fixed external expected
byte/count totals, class limits, refusal/admission/finish denominators, zero
outstanding charges and bounded high-water values. Controls exercise queue
ordering, full lanes without eviction, final-owner release, failed-first retry,
pending/saved duplicates, key exhaustion, unknown identities and stream limits.
These are owned policy controls, not malware samples or measured production SLOs.

The final EXE passed **92 KMON image integration checks**. Owned original-read
fixtures fill routine and gap queues, exhaust routine file budgets and still
publish/replay the first changed image range through the real writer and journal.
The final protected ledger preserves both successful and failed class outcomes.
A collision leaves a partial journal batch; the next original attempt retains
first priority. Successful repeats demote, while changed bytes, process lifetime
assertions and a new collector work episode receive new first-priority keys.
All owned fixture files are cleaned by the harness after validation.

Review added collector work/requalification episodes and source IDs to the
fingerprint so a recycled work entry cannot inherit old priority decisions.
Unknown identity or failed hashing does not earn a reusable key. Saved-key
eligibility requires the complete raw/reference/recipe journal batch, and
allocation/preparation failure releases admission ownership. Review also found
that live hunt readers could overlap session policy replacement; replacement
now uses the hunt-reader lock. The final integration controls observe a reader
before performing 100 session resets and verify valid reports throughout.
This bounded overlap is not a race-detector or universal scheduling proof.

An isolated final `--self-test all` passed: timeline **28**, MCP **102**, KMON
image **92**, console **558**, commands **3,000 / 261 routes**, remote **66**.
Compiled capability contracts passed **30 / 261 routes**, the generated support
matrix matched, and the public-content classifier passed **11 tests**. The new
retention capability remains `not_probed`. No owned test processes remained.

No driver was loaded, service started, Verifier enabled, reboot performed or
security policy changed. The image fixtures use owned nonexecuting bytes; they
do not validate native loaded-image/mapping lifetimes or a live kernel support
matrix. Cross-session priority, other evidence families, committed-root retirement,
privacy, large-store continuation and full P01-P16 / VS1-VS4 acceptance remain
open. The historical concurrent-load process-capture deadline failure remains
unresolved separately; this isolated passing suite does not close it.

## Explicit image-artifact GC checkpoint: 2026-11-07

This P06 step adds offline `!kmon gc` preflight/apply/resume and a create-new
policy helper. Explicit canonical policies bind exact uncommitted member bytes,
reason, minimum age and byte ceiling. Current closed-root membership and all
original/selected file leases remain held under the store barrier. A durable
operation and per-file intent precede each handle-based deletion; separate
receipts preserve success, failure and uncertain outcomes. Committed originals,
references and failure ledgers cannot be selected. This does not retire committed
roots or implement automatic retention priorities.

Final Release EXE SHA-256:
`686e3f0d7981e8d9f27c894a1c2e0fc5fc27a8ec05037dea555af0780b663877`.
ASan journal/store/GC harness SHA-256:
`4c87e5643693568d78884bfbf82afea921bb8ead365fae350ae3097faf35b5ae`.
Release and ASan builds passed with VS 2022 Build Tools 17.14.60 / MSVC
14.44.35207 and SDK/WDK 10.0.26100.0. Existing C4744 `NextQueryEpoch` alignment
warnings remain; the initial broader rebuild also reproduced the existing C4244
fill conversion warning in unchanged `KernelMonitor.cpp`.

The final ASan validation passed **42 C++ controls**, **1,952 journal checks**,
**476 store checks** and **892 independent GC checks**. The final EXE passed
**898 GC CLI checks**, **1,952 journal CLI checks** and **492 store CLI checks**.
The GC oracle creates, verifies and deletes only files beneath its own resolved
fixture root. It independently recomputes canonical policy/operation/intent/
receipt hashes and exact selected bytes, checks original committed files remain
unchanged, and compares root/candidate identities with separate Win32
`FileIdInfo` and creation-time queries. The observed fixture volume is NTFS;
this is not a ReFS or filesystem compatibility matrix.

Nine GC interruption cases observe an owned harness child's exact stage before
termination/reaping. The final CLI resumes those recorded operations. They cover
preflight, operation publication, intent, deletion before receipt, completed
receipt, identical-byte replacement, corrupt intent, rehashed unbound receipt
and copied operation/root identity. All owned children were reaped. Absence after
intent remains actor-unknown; completed receipts are reused without deleting a
later replacement. Denied/partial roots, committed references, failure-ledger
policies, pending/unknown artifacts, policy/path/schema/byte errors, overflow,
minimum age, future timestamps, read-only files, hard links and output collisions
retain their explicit failure or preservation states. The policy helper is tested
against actual store output, existing-output collisions and malformed completeness
flags; six invalid CLI grammars return usage status without execution.

Review changed file identity from the legacy 64-bit index to the full 128-bit
identifier with volume and creation time, following the
[Windows identity contract](ARCHITECTURE.md#explicit-uncommitted-artifact-gc).
Unavailable identity/creation information is denied. A deadline check immediately
before disposition also covers a delayed progress callback. The deadline remains
cooperative, not an I/O cancellation or real-time guarantee.

An isolated final `--self-test all` passed: timeline **28**, MCP **102**, KMON
image **75**, console **558**, commands **3,000 / 261 routes**, remote **66**.
Capability contracts passed **29 / 261 routes**, the generated support matrix
matched, and the public-content classifier passed **11 tests**. GC capability
availability remains `not_probed`; the live controller/MCP does not expose apply.

No driver was loaded, service started, Verifier enabled, reboot performed or
security policy changed. No real user evidence was cleaned. These tests establish
bounded owned-file behavior and process-interruption recovery, not secure erasure,
disk reclamation, authenticated storage or media/power-loss durability. Full
uncommitted dependency-impact analysis, committed-root retirement, priority/privacy
policies, large-store continuation and the full P01-P16 / VS1-VS4 gates remain
open. The historical concurrent-load process-capture deadline failure remains
unresolved separately; an isolated suite pass does not close it.

## Coordinated image-store inventory checkpoint: 2026-11-07

This P06 step adds `!kmon store` for exact membership and dedup accounting across
the stopped image-collection namespace. Participating publishers hold a shared
store lease before any original-file publication; inventory holds the exclusive
lease while verifying every captured root and original member. Open or unresolved
roots protect unattributed files. Committed originals/references and session
failure ledgers remain protected, including a ledger whose journal was never
created. This is a retention classification receipt with no deletion authority.

Final Release EXE SHA-256:
`719ebbb424a758212218d4333c088fc930efb5e1a72308e4247cea20353017d0`.
ASan journal/store harness SHA-256:
`58e82ae379b022c84e9d811a685900105d24a2de28f94cce867abf609449b61a`.
Toolchain: VS 2022 Build Tools 17.14.60 / MSVC 14.44.35207, SDK/WDK
10.0.26100.0. Release builds passed with the existing C4744 `NextQueryEpoch`
alignment warning; the broader rebuild also reproduced the existing C4244 fill
conversion warning in unchanged `KernelMonitor.cpp`.

`tools/validate-evidence-journal.ps1 -Sanitize` passed **42 C++ controls**,
**1,952 journal checks** and **476 independent store checks**. The final EXE
passed **492 store CLI checks**, including summary/detail omission and five
invalid grammars. Store controls independently recompute physical hashes,
hash-linked membership, root/artifact receipt hashes, reference multiplicity,
per-collection paths, global named-file bytes, unique content and actual read
bytes. Repeated references within and across collections share one pinned
physical read; equal content at distinct paths remains separately verified.
The final EXE also passed the **1,952-check journal CLI oracle**, including ten
observed-stage interruptions and zero remaining owned children.

Controls cover unknown tails, corrupt shared references, malformed roots,
uncommitted failure ledgers, pending/unmanaged files, lock collisions, NUL input,
root/namespace/collection junctions, case-only filenames, long paths, catalog
limits and bounded detail output. Shared/exclusive publisher tests observe each
child's held-lease signal before making competing calls, then terminate/reap the
owned child and verify lock release. Reports are revalidated after original-byte
changes; a previous report never grants deletion permission. Fixture creation
initially hit Python's Windows path limit; extended syntax was applied only to
fixture creation, with the original unprefixed long path still sent to the product.

The final EXE's isolated `--self-test all` passed: timeline **28**, MCP **102**,
KMON image **75**, console **558**, commands **3,000 / 261 routes**, remote **66**.
KMON controls exercise denial before read/sweep/ledger publication, explicit
failure counts, release on closure and subsequent exact inventory. Review found
and fixed loss of the existing directory-failure reason and clearing of the
manifest budget reason during successful admission. The original failure label
is preserved; the store admission issue is an additional field. Compiled
capability checks passed **28 contracts / 261 routes**, and the public-content
classifier passed **11 tests**. Store availability remains `not_probed`.

All observations use owned storage fixtures and synthetic, nonexecuting image
inputs. No driver was loaded, service started, Verifier enabled, reboot performed
or security policy changed. The [inventory bounds and coordination](ARCHITECTURE.md#image-store-membership-inventory)
exclude legacy stores, nonparticipating publishers, disk allocation, authenticated
provenance, image-policy replay and power-loss durability. GC with deletion
receipts, retention priorities/privacy, large-store continuation and the broader
P01-P16 / VS1-VS4 gates remain open. The earlier concurrent-load process-capture
deadline failure remains unresolved; this isolated pass does not close that gate.

## Image collection journal and recovery checkpoint: 2026-11-07

This bounded P06 step adds a collection journal to the original KMON image
read/reference/recipe/sweep path. Exact physical file hashes and schemas precede
hash-linked commits; dependent sweep roots require earlier committed members.
The final read ledger has its own closure commit. File publication, collection
commit, derived-index readiness and target observation coverage remain distinct.
Recovery verifies the committed prefix and original files, excludes orphan and
pending files, and resumes derived index publication from exact completed chunks.

The final Release EXE SHA-256 is
`14353ae1555af41f6d57d17a22b1d88baef468c39c9f26cc7cf98a32bf72ff52`.
The ASan journal harness SHA-256 is
`5c6f83208bacd4abd61fbb4026df1555def01ca262b06fc3431f58c5fb258c8a`.
Builds used VS 2022 Build Tools 17.14.60 / MSVC 14.44.35207 and SDK/WDK
10.0.26100.0. Existing C4744 `NextQueryEpoch` alignment warnings remain; the
broader rebuild also reproduced C4244 in unchanged `KernelMonitor.cpp` fill code.

`tools/validate-evidence-journal.ps1 -Sanitize` passed **35 C++ controls** and
**1,952 independent Python checks**. The same Python oracle passed **1,952
checks through the final EXE's offline CLI**. Each run interrupted ten owned
children only after observing their exact publication-stage signal, reaped every
child, recovered the expected prefix and checked restart at the next sequence.
Controls cover raw-only orphans, missing/corrupt members and segments, rehashed
schema/sequence/path violations, unknown tails, extra records after closure,
writer exclusion, dependency admission, exact idempotent retries, collection
dedup denominators, corrupt/partial indexes, directory junctions, NUL input,
trailing separators and paths whose final index files exceed MAX_PATH.

The first actual CLI oracle exposed a long temporary-index path failure. The
journal now uses normalized local extended paths, including backslash separators;
the first extended-path revision's separator regression was corrected before
final validation. The original failing input rebuilt successfully without path
shortening or host policy changes. Additional review fixes pin verified index
chunks until head publication, prevent partial counter publication after an
exception and withhold closed status when records follow a closure. A corrupt
index remains a separate failure and is never silently replaced.

The final EXE passed an isolated `--self-test all`: timeline **28**, MCP **102**,
KMON image **70**, console **558**, commands **3,000 / 261 routes**, remote **66**.
KMON controls recover and replay the original comparison after source/reference
removal, retain incomplete sweep coverage inside a closed collection, account for
reference reuse across actual scheduling slices, and distinguish successful raw
files from a blocked journal/closure. Compatibility checks passed **1,414** sweep
graph checks across eight cases, **164** legacy graph checks, **101** legacy image
recipe checks, **27** capability contracts and **11** publication-classifier tests.
Compiled journal support remains `not_probed` for target availability.

These are owned storage fixtures and synthetic nonexecuting image observations.
No driver was loaded, service started, Verifier enabled, reboot performed or
security policy changed. Process termination does not establish media/power-loss
durability. Recovery bounds and whole-prefix revalidation are documented in the
[architecture](ARCHITECTURE.md#image-collection-publication-journal). Counts and
dedup bytes cover one verified collection prefix, not global retention or disk
allocation. Cross-collection retention/GC, large-store continuation, legacy
inventory-build recovery, native loaded-image lifetime, approved-change policy
and the full P01-P16 / VS1-VS4 gates remain open. The earlier load-sensitive
process-capture deadline failure remains separate; isolated passes do not resolve
or validate that concurrent-load timing condition.

## Replayed image sweep graph checkpoint: 2026-11-07

This P03 substep extends the offline graph command to `.knsweep`. Successful
original-policy replay supplies typed range comparisons; the graph connects the
sweep assessment to manifest, reference, recipe, published raw archive and slice
evidence. Each element retains an artifact digest, JSON pointer where applicable
and original observation interval. Failed comparison, excluded bytes, unobserved
ranges and raw publication loss remain separate.

Release x64 EXE SHA-256:
`5c86c9f84f0264feeae753ee384b6630a11493d631ed90a508324cc5a55e6a05`.
ASan slice/sweep/graph harness SHA-256:
`0f66faef0e0fe12ae233d9b991ddb08f48b33336f9236d59bb739f644caaf413`.
The full Release solution built with the P01 VS/MSVC/SDK/WDK configuration.
The existing C4744 `NextQueryEpoch` alignment warnings remain.

The ASan harness passed 307 C++ controls, including typed replay admission bound
to the expected manifest digest and clearing prior results on failure. Independent
slice and sweep oracles passed 369 and 233 checks. The final EXE passed 1,414
graph checks across eight sweep cases: matching, changed, excluded, missing first
slice, unknown tail, actual secondary reference view, unstable comparison and lost
raw archives. The oracle independently verifies provenance pointers, exact ranges
and byte counts, intervals, graph identities, fresh-process pagination and cursor
invalidation. Different boot/generation labels cannot share nodes even with the
same PID, VA and reference bytes. Missing/corrupt files, a rehashed false verdict
and an oversized projection produce no successful graph or assessment.

The existing evidence ASan harness passed 522 controls; eight interrupted
publications left three valid and five absent final files. The extracted graph
traversal function is unchanged. The final EXE also passed 164 legacy graph,
413 slice, 269 sweep, 101 legacy recipe and 168 live recipe CLI checks. All three
owned live PE-buffer children exited. Capability checks covered 26 contracts and
261 command routes without treating compiled support as target validation.
Public-content regressions passed 11 checks, including renamed graph evidence.

An isolated final `--self-test all` passed timeline 28, MCP 102, console 558,
command registry 3,000 and remote 66 checks. KMON integration passed 64 controls,
including changed-range and two-slice graphs from actual comparison/writer output
after the original target and reference were removed. This isolated run does not
resolve the concurrent host-load timeout observation in the earlier checkpoint.

Review bound the graph's manifest preflight to replay before leaf I/O, retained
original reference qualification separately from failed byte comparison, and
made detail-budget failure discard the projection. The independent oracle found
that the new unstable fixture initially matched and therefore never triggered
the candidate confirmation read. The fixture now starts with a difference and
changes during confirmation; the expected 4,096 failed bytes were retained.
No additional defects were found in the reviewed implementation scope.

Targets remain owned synthetic nonexecuting PE bytes, with actual local
`SEC_IMAGE_NO_EXECUTE` reference views. No driver load, service start, Verifier,
reboot or security-policy changes were made. Graph limits are 256 nodes, 512 edges
and 2 MiB of details; traversal time budgets exclude replay and reference I/O.
Cross-bundle mapping lifetimes and callback/dispatch joins, native loaded-image
validation, approved-change policy, reference caching/stage budgets and P06
journal/restart/global retention remain open. The full P01-P16 / VS1-VS4 goal
remains active.

## Temporal image sweep checkpoint: 2026-11-07

This P03 substep publishes bounded `kn.image_sweep.v1` manifests that bind the
original slice recipes, raw payloads, reference identity, target labels, range
indices and observation intervals. Slice ordinals advance before queue admission;
missing entries, missing terminal observations and entirely dropped sweeps stay
visible through manifests or final session denominators. Offline replay verifies
the declared artifacts and shared reference, then reruns each original slice
policy. It separates executable comparison, membership and publication completion.

Release x64 EXE SHA-256:
`b38967e0518269b13a4b1a5d1394f11a553d2ec867fa199bc8de391aa1f7a59e`.
ASan slice/sweep harness SHA-256:
`72c01c0a21bcfef28447f6dc716c2c52dc573db0afe5bcb1ce003ec2326032ae`.
The full Release solution built with the P01 VS/MSVC/SDK/WDK configuration.
The existing C4744 `NextQueryEpoch` alignment warnings remain; the broader
rebuild also emitted the existing C4244 conversion warnings.

`validate-image-slice.ps1 -Sanitize` passed 251 C++ controls, 369 independent
slice checks and 233 independent sweep checks. The six sweep cases cover
matching/modified/excluded ranges, a missing first slice, an unknown tail and
actual owned secondary reference views. All original targets are synthetic
nonexecuting bytes; reference views use `SEC_IMAGE_NO_EXECUTE`. Original reference
paths and target bytes are removed before publication/replay. Hash, temporal
membership and byte-total checks are independent of the C++ implementation.
Negative controls include conflicting process generations, duplicate leaves,
wrong schedules/targets, missing raw/recipe files, corrupt reference bytes,
contradictory terminal/time fields, path escape and bounded metadata loss.

The final EXE passed 269 sweep CLI, 413 slice CLI, 101 existing recipe CLI and
168 live CLI checks. All three owned live PE-buffer children exited.
`validate-image-recipe.ps1 -Sanitize` passed 92 compatibility controls; six
interrupted publications per v1/v2 format left three valid and three absent
final recipes. Public-content regressions passed 11 checks, including renamed
private manifest/replay/proof formats.

The final isolated `--self-test all` passed timeline 28, MCP 102, console 558,
command registry 3,000 and remote 66 checks. Actual KMON comparison/writer
integration passed 62 controls: two scheduling turns with one shared reference,
original raw/recipe/manifest binding, writer stop after only the first slice,
unknown-tail replay, manifest collision/byte limits, complete queue loss,
final session denominators and zero outstanding reference reservations.
An earlier concurrent full-suite run failed the existing bounded process-capture
test; its five-second boundary was inspected. The same binary passed when run
alone, and the final binary passed alone after the closure control was added.
The test was not relaxed. The precise cause of the concurrent failure was not
isolated; behavior under concurrent host load remains unvalidated.

Review tightened terminal/end-time consistency and secondary-observation interval
containment. The proof names executable ranges explicitly instead of implying a
comparison of every PE section. The independent oracle also caught an intentional
fixture byte change left behind when its IAT exclusion was removed; the fixture
was corrected without changing the expected byte totals. No additional defects
were found in the reviewed manifest implementation scope.

Manifests and replay remain temporal, unauthenticated observations. A replayable
subset is not a complete sweep; a completed comparison is not execution,
approved reference provenance or an atomic mapping lifetime. No driver-load,
service-start, Verifier, reboot or security-policy changes were made. Native
loaded-image lifetime, graph associations, approved-change policy, full-file
reference caching/stage budgets and P06 journal/restart/global retention remain
open. The full P01-P16 / VS1-VS4 goal remains active.

## Original KMON slice replay checkpoint: 2026-11-07

This P03 substep retains clean, changed and inconclusive original KMON slices.
Raw `kn.image_reads.v3` includes the original secondary-view inputs even when
recipe publication is unavailable. Eligible AMD64/PE64 slices publish direct
`kn.image_slice.v1` or secondary `kn.image_slice.v2` recipes beside the archive.
Offline replay consumes the original routed reads and retained reference,
recomputes normalization/results and reports executed-range proof and coverage.
It never substitutes a fresh target read or a newly mapped secondary view.
Raw archives, recipes and reference blobs have separate publication counters.

Release x64 EXE SHA-256:
`eb3bfbff4c68de09bfd769b887161ff6e9dfa4a4e435ed6b88f3172374aafab1`.
ASan slice harness SHA-256:
`5f76facf3d29d4239f345384193e43e6e70f14514a9040ea1e3a82a40c4bda1c`.
The full Release solution built with the P01 VS/MSVC/SDK/WDK configuration.
Existing C4744 `NextQueryEpoch` alignment warnings remain; the preceding broader
build also reported the existing C4244 conversion warnings.

`validate-image-slice.ps1 -Sanitize` passed 127 controls and 369 independent
Python checks across 11 cases. The final EXE passed 413 slice CLI/oracle checks.
Cases cover clean/modified/unstable/unreadable inputs, rejected guards, final
identity changes, continuation, ambiguous secondary basis and positive secondary
comparisons. Synthetic targets use two executable pages, a DIR64 relocation and
an explicit IAT exclusion. Secondary reference reads use actual owned
`SEC_IMAGE_NO_EXECUTE` mappings; no fixture code is executed. Original targets
and reference paths are removed before publication/replay. Independent checks
verify hashes, selected receipts, relocation values, matching/differing ranges
and byte denominators. Missing references, unlinked fallback, altered order,
unsupported architecture and rehashed input/normalization/result contradictions
cannot produce successful proof.

`--self-test all` passed timeline 28, MCP 102, console 558, command registry
3,000 and remote 66 checks. Its actual KMON comparison/writer integration passed
49 controls, including clean/modified replay after source removal, incomplete
secondary raw retention, independent recipe/reference byte limits, collisions,
queue drain and final failure ledgers with zero reference reservations.
`validate-image-recipe.ps1 -Sanitize` passed 92 compatibility controls and six
interrupted publications per v1/v2 format (three valid, three absent each).
The final EXE passed 101 existing recipe CLI and 168 live CLI checks; all three
owned nonexecuting PE-buffer children exited. Public-content regressions passed
11 checks, including renamed private slice inputs and proof formats.

Review fixes preserve raw secondary inputs when recipe eligibility fails,
distinguish slice replay schema/policy from single-page replay, and validate
disjoint coverage accounting before issuing proof. Test discovery uses the
published recipe path rather than assuming a capture ID. No additional defects
were found in the reviewed implementation scope.

These controls do not validate an OS-loaded target or native driver lifetime.
No driver-load, service-start, Verifier, reboot or security-policy changes were
made. A faithfully replayed inconclusive slice remains inconclusive; its proof
does not establish whole-sweep completion, approved provenance, atomic mapping
lifetime or execution. Sweep manifests/graph associations, source-initialization
receipts, full-file reference caching/stage budgets, journal recovery/global
retention and the full VS1/P01-P16 goal remain open.

## KMON exact reference retention checkpoint: 2026-11-07

This P03/minimal-P06 substep pins the comparison reference before target reads,
retains bytes from that exact file object, and rechecks content before releasing
the source lease. Changed/inconclusive KMON slices use `kn.image_reads.v2` with
separate capture and publication status. The writer verifies or creates shared
content-addressed reference blobs before publishing the referring archive.
Queue reference reservations and newly published reference bytes each have a
128 MiB limit, separate from the existing raw archive budget. Failed or missing
references remain explicit while original raw reads can still be preserved.

Release x64 EXE SHA-256:
`7c59bf0b0ca56f8996a71e52b9e59f323c614ed50a47ce346966a81f7315794d`.
ASan reference-blob harness SHA-256:
`7d71cbb0711fa0e9c45206fd592c389d825e396dac78ea867e4e41a2df099a0b`.
The full Release solution built with the P01 VS/MSVC/SDK/WDK configuration.
Existing C4244 conversion and C4744 `NextQueryEpoch` alignment warnings remain.

`validate-reference-blobs.ps1 -Sanitize` passed 23 controls and the independent
Python SHA-256/JSON oracle. Real owned-file handles exercise rename/path
replacement, independent read position, write exclusion, source deletion before
publication, exact-byte reuse at zero new-byte budget, forged hashes, corrupt
existing blobs, size limits, invalid/device handles and cleanup. An existing
writable mapped view denied the read-only exclusion lease; this does not test
privileged mutation through an acquired lease.

`--self-test all` passed timeline 28, MCP 102, console 558, command registry
3,000 and remote 66 checks. Its actual KMON comparison/writer integration passed
36 controls, including source/reference removal before publication, unchanged
original routed bytes, exact shared reference, pressure/reservation release,
missing/corrupt/budget-denied references, reference rejection before target reads,
output collisions and final ledger balances with zero reference reservations.
`validate-image-recipe.ps1 -Sanitize` passed 92 v1/v2 controls; six interrupted
publications per format left three valid and three absent final recipes.
The final EXE passed 101 legacy CLI checks and 168 live CLI checks with three
owned nonexecuting PE-buffer children, all exited. Public-content regressions
passed 11 checks, including renamed private v2 read archives.

These are owned user-mode/synthetic comparisons, not OS-loaded module or native
driver lifecycle validation. No driver-load, service-start, Verifier, reboot or
security-policy changes were made. Full reference acquisition/rechecks and blob
verification still run per slice; the 25 ms sweep yield is not an end-to-end
latency guarantee. Caching/stage budgets, clean-only retention, normalization,
secondary-view inputs, complete slice recipes and sweep manifests, journal
restart/global retention and full VS1 remain open. No additional defects were
found in the reviewed implementation scope. The P01–P16 goal remains active.

## KMON original image read archive checkpoint: 2026-11-07

This P02/P03 substep connects KMON's initial user/kernel image comparisons and
background continuations to shared read operations. Failed primary reads,
explicit handle/native fallback and the receipt selected by each parser call
remain distinct. Changed/inconclusive slices publish bounded private `.knreads`
archives with separate queue/store counters and final `.knreadledger` files.
Cancellation/deadline checks also cover guard entry and completion. The archive
does not retain the full reference, secondary-view inputs or normalization and
cannot be replayed as an image recipe. Clean-only retention, complete background
reference/recipe and sweep manifests, native lifecycle and full VS1 remain open.
The P01–P16 design goal is not complete.

Release x64 EXE SHA-256:
`ce7f4e6e99670d74fe66121461f7e35b934cf50eb6237a2ec31819d4185cc411`.
ASan read-routing harness SHA-256:
`0e1afe76ab4d67d06133b7b92a60cf4bf44767fcb4b36da00c9e16976748272d`.
The full Release solution built with the P01 VS/MSVC/SDK/WDK configuration;
the existing C4744 `KmonHuntIndex::NextQueryEpoch` warnings remain.

`validate-read-routing.ps1 -Sanitize` passed 40 controls and an independent
Python oracle over 31 operation snapshots. They cover partial-prefix retention
without byte merging, fallback permission/source/descriptor binding, shared
budgets, source changes, unavailable primary, factory failures, guard rejection,
cancel/deadline before and during guards, parser capacity and abandoned reads.
`validate-read-receipts.ps1 -Sanitize` passed 48 controls and 13-operation/
14-snapshot JSON checks. `validate-native-read.ps1 -Sanitize` passed 139 controls
and 14 JSON observations; the native transport is synthetic and the device
qualification negative opens only NUL.

`--self-test all` passed timeline 28, MCP 102, console 558, command registry
3,000 and remote 66 checks. Its actual `ScanExecutableImage`/capture-writer
integration passed 26 additional checks using owned synthetic PE bytes:
modified/clean/unstable/unreadable comparisons, original header/page/confirmation
receipts and selected bytes, publication after source/reference removal, payload
hash, final ledger, queue pressure, session byte budget, filesystem failure,
create-new collision and fixture cleanup. These are not OS-loaded image or
native driver lifetime tests. The tests made no driver-load, service-start,
Verifier, reboot or security-policy changes. Public-content regression checks
passed 11 tests, including private archive/ledger extensions and renamed schemas.
No additional defects were found in the reviewed implementation scope; the
remaining architecture and native acceptance gates above remain unresolved.

## Handle-based live image transaction checkpoint: 2026-11-07

This P03 substep adds `--verify-process-image` and `kn.image_recipe.v2`.
The selected comparison records its original handle-source reads through one
shared operation, including qualification and confirmation, and retains the
exact reference artifact and normalization. V1 remains readable and the dump
capture command retains its v1 output. Background KMON/native fallback, secondary
image views, real loaded-module lifetime, durable journal integration and full
VS1 completion remain open. The P01–P16 design goal is not complete.

Release x64 EXE SHA-256:
`f4b301822fb886627e36b070a75924f2c3a9b3fc5aaa94dc80191988acd31ff7`.
ASan image-recipe harness SHA-256:
`cf006436464e7afbd6ccfadf0fcd51635cfce0485e6cb5ae10c71c5165e046fe`.
The full Release solution built with the P01 VS/MSVC/SDK/WDK configuration.
Existing C4744 warnings on `KmonHuntIndex::NextQueryEpoch` remain.

`validate-image-recipe.ps1 -Sanitize` passed 92 combined v1/v2 controls, including
original raw metadata, explicit consent, policy/budget denials, receipt gaps,
operation/source mismatch, projection tampering and unchanged replay policy.
Six interrupted publications per format each produced three valid final recipes
and three absent finals; fresh-process replay verified the valid finals.
`test-live-image-recipe.py` passed 168 checks through the actual EXE. Three owned
children held normal, changed and inaccessible PE-buffer ranges. Readiness and
exit were observed through IPC and process completion. After each child exited,
the original reference was replaced and removed; original-policy replay still
matched the actual comparison. Independently rehashed contradictory receipts
were rejected. Output collision preserved existing cases, and failed stdout
delivery returned an error while leaving the published case replayable.
All three children exited; none remained. Their buffers were private RW memory,
not OS-loaded or executed images. The legacy offline image CLI passed 101 checks.

The process-source ASan harness passed 25 controls/six JSON observations;
the recorder passed 48 controls and 13 operations/14 JSON snapshots. Translation
receipt ASan passed 65 controls/13 JSON observations, and the actual dump CLI
passed 227 checks with one symlink-privilege skip. Runtime policy passed 28
controls, and the actual runtime probe, 25 compiled contracts/261 routes,
generated support matrix and 11 publication-scanner regressions passed.
Linked self-tests passed: timeline 28, MCP 102, console 558, commands 3,000 and
remote 66.

Review prevents v1 from silently discarding new metadata and confines runtime
availability to the operation actually probed: a successful owned byte sample
does not advertise image-capture availability. V2 validates the entire receipt
projection, source contract, consent and accounting before it becomes replay
input. Final review found no additional actionable defects in this scope.
Reported copy counts and Win32 errors follow
[ReadProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory);
handle qualification uses the requested creation time from
[GetProcessTimes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes).
These checks do not prove atomicity, mapping lifetime, LA57, native acquisition,
collector authenticity, execution or maliciousness. No driver was loaded,
service started, Verifier enabled, reboot requested or security policy changed
for this substep.

## Saved dump initialization receipts on 2026-11-22

This P02 checkpoint covers the file reads that qualify a saved AMD64 full dump.
The direct `--offline !kmon dump-read` command exposes them through
`/init-receipts`. Both the regular and AddressSanitizer builds of
`tools/validate-dump-source.ps1` passed 160 checks each on owned synthetic files.
Run the CLI check against either harness's reported fixture directory:

```text
python tools/test-dump-initialization.py --executable x64/Release/KnLiveDbg.exe --fixtures <fixture-directory>
```

The CLI check compared file offsets, physical addresses, byte counts and
SHA-256 values to the fixture bytes. Unique four- and five-level probes required
17 and 19 file attempts. A fixture where both candidates matched took 34. A
list head split across two pages at both depths reached the full ceiling of
45 attempts and 8,544 requested bytes. Both ambiguous fixtures returned an
unavailable decision and a null requested range. A missing second page retained
the captured first span. Complete neighbor reads with disagreeing pointer
values recorded the comparison failure and stopped at that neighbor.

Windows returned sharing violation 32 when an existing writer prevented the
file from opening. A byte-range lock over the header or list data allowed
the file to open and produced read error 33 at the locked range. Tests also
covered 13 malformed or conflicting fixtures, stale report reuse, hard-linked
diagnostic sinks, read-only output and truncated private exports in UTF-8
and UTF-16. The Release x64 CLI passed its 227 legacy dump checks. One final
symlink check was skipped because the host lacked symlink creation privilege.

Shared read and translation harnesses passed 48 and 65 checks respectively.
Their JSON checks covered 14 read snapshots across 13 operations and 13
translation observations. Linked command and console self-tests passed 3,083
and 570 checks. The compiled matrix matched 61 source contracts and 261 routes.
The public-content scanner passed 30 regression tests. The Release link retained
the existing C4744 alignment warning for `KmonHuntIndex::NextQueryEpoch`. The
AddressSanitizer runtime reported an interceptor warning and ran with its
continue-on-interception-failure setting.

This checkpoint used saved synthetic inputs. Live root acquisition, real LA57
hardware validation, initialization in other collectors and replay from the
initialization hashes remain open.

## Typed dump translation checkpoint: 2026-11-07

This P02 substep adds a physical address domain, a typed page-table walker and
`--offline !kmon dump-read ... /receipts`. The selected command records the actual
table, recheck and payload reads under one budget. It preserves the original
dump-read schema when the option is absent. Native root acquisition, other
collectors, source-initialization receipts and durable translation replay remain
open; this checkpoint does not complete P02.

Release x64 EXE SHA-256:
`8cbf2a0d508333f4df3c21741c786f18a2993603c3493a52a7ac4a421588c82d`.
ASan translation harness SHA-256:
`061eae5f43123bf93f9d82d46083aa11a5895eec1bfe8711991d52b23b283184`.
ASan dump-source harness SHA-256:
`a019b32013e0fca1b7426a65720525b1eb3a0a0b9499fb4cebabbaa2db912b0d`.
The full Release solution built with the P01 VS/MSVC/SDK/WDK configuration.
Existing compiler/linker warnings remained, including C4744 on the unchanged
`KmonHuntIndex::NextQueryEpoch` atomic field. No driver code changed in this substep.

`validate-translation-receipts.ps1 -Sanitize` passed 65 controls; its independent
Python oracle checked 13 observations. Controls cover LA48/LA57, 4 KiB/2 MiB/1 GiB
leaves, upper RW/U/S/NX restrictions, reserved bits, MAXPHYADDR, unknown features,
root and epoch replacement during initial/recheck reads, conflicting entries,
partial PTE reads, shared budgets, cancellation and receipt exhaustion. No failed
walk returns a usable mapping or permission result. Physical addresses in the
virtual canonical hole are tested without pretending they are virtual addresses.

The dump-source ASan harness passed 139 controls using owned synthetic full-dump
files. The actual EXE passed 227 CLI checks, including original-byte equality,
physical read denominators/status, nonpresent versus uncaptured pages, invalid
grammar and read-only stdout failure. One final-symlink CLI check was skipped
because the host lacked symlink creation privilege. The fixtures also test
concurrent ordinary file reads, write/delete sharing restrictions and retaining
the original bytes after closing the source handle. These are file-source
controls, not a native driver or a real LA57 host validation.

Adversarial review corrected same-number cross-domain fallback, a changed source
address contract retaining the same ID, a range assembled across different
chunk contracts, and a root used with another operation's target labels. It also
prevents parser/fallback use after an observed deadline
overrun while preserving raw evidence, and distinguishes a caller-declared root
from a file-backed root. Virtual image capture rejects physical sources and
overruns instead of omitting those semantics from v1 recipes; capability sample
availability respects the same deadline/cancellation boundary. The final
reviewed scope had no additional actionable defects.

Shared recorder checks passed 48 controls and 13 operations/14 JSON snapshots;
native transport passed 139 controls/14 JSON observations; the owned process
source passed 23 controls/six JSON observations. Evidence-bundle ASan passed 522
controls and eight interrupted publications (three valid finals, five absent,
restart checks passed). Runtime policy passed 27 controls, with the actual CLI
probe also passing. All 24 contracts/261 routes, the generated matrix drift check,
11 publication-scanner regressions and full linked self-tests passed (timeline
28, MCP 102, console 558, commands 3,000, remote 66).

Image-recipe ASan passed 73 controls, including physical-domain rejection,
source-contract replacement and deadline overruns during header/payload reads.
Six interrupted publications produced two valid final recipes and four absent
finals. The final EXE passed 101 image capture/replay CLI checks using owned
fixtures; no live target participated in those tests.

The dump envelope explicitly excludes initialization header/probe reads. Its
52-bit physical admission ceiling is not measured target MAXPHYADDR. Missing
MAXPHYADDR/NXE/1 GiB context leaves permissions unknown; decoded addresses locate
captured file bytes, not verified live CPU mappings. Repeated reads do not pin
mappings or exclude ABA. Effective CPU access, encrypted-address profiles,
EPT/NPT, live root leases, execution and real LA57 remain unvalidated. No driver
was loaded, service started, Verifier enabled, reboot requested or security
policy changed for this checkpoint.

## Native read status transport checkpoint: 2026-11-07

This P02 substep adds an optional ABI 17 read-observation envelope without
changing the existing IOCTLs. The native observation source uses the advertised
contract to retain original NTSTATUS, copy count and outer Win32 transport
status. Qualified old drivers retain their legacy path with an explicitly
unavailable NTSTATUS. Existing direct collectors and typed page-table receipts
still require migration; this checkpoint does not complete P02.

Release x64 EXE SHA-256:
`53df0457247cd25e5da43636b0fc33cd24d0988c9b95bcd95b24613ee722c05f`.
Release x64 driver SHA-256:
`c1534013ffa8561f245579f860b85d3fcd38d5dabacdf0f53e195aff3bae2d3c`.
ASan native-read harness SHA-256:
`b45e59b884a4399f980d0aedbe20e8978146f35cc2c844b4ad12f7edbb23d22a`.
The full Release solution built with the P01 VS/MSVC/SDK/WDK configuration.
The build emitted C4744 on the unchanged `KmonHuntIndex::NextQueryEpoch` atomic
field and C4244 on the unchanged byte-vector fill in `KernelMonitor.cpp`.

`tools/validate-native-read.ps1 -Sanitize` passed 139 checks. An independent
Python JSON oracle checked 14 status/source observations. The controlled
responder exercises the production transport helper and decoder: all three
read kinds, request/response bounds, identity and epoch binding, partial and
failed copies, raw high-bit status values, legacy compatibility, contradictory
status/count pairs and refusal to retry legacy IOCTLs after an advertised
extension fails. The real `DeviceClient` checks open only `NUL`, reject its
version query and verify that closing it clears qualification.

Adversarial review found that process-identity mismatch could be flattened into
an ordinary failure and authorize fallback. Explicit mismatch/policy flags and
typed states now preserve those denials; recorder tests reject an explicit
alternate-source retry. Review also corrected an unqualified source's contract
label, unknown copy-attempt reporting and the direct converter's result state.
The final reviewed scope had no additional actionable defects.

The shared recorder passed 48 ASan checks and 13 operations/14 JSON snapshots;
the owned process source passed 23 checks and six JSON cases. Evidence-bundle
ASan passed 522 controls, with eight interrupted publications producing three
valid and five absent final files; restart checks passed. Runtime policy passed
22 controls. The final EXE passed the actual capability CLI checks, all 24
contracts/261 routes, support-matrix drift check and full linked self-tests
(timeline 28, MCP 102, console 558, commands 3,000, remote 66).

No driver was loaded or service started. Real kernel/process/physical reads,
process-exit overlap, close/reopen/stop overlap, old/new driver interoperability,
Verifier, signing trust and OS/security-state regression remain separate native
lab gates in the [manual checklist](MANUAL_TEST_CHECKLIST.md). Connection-epoch
checks do not supply a lifetime lease: callers must still serialize the native
source and `DeviceClient` lifecycle. The physical transport is not yet a typed
translation source, and these controls do not establish MMIO, LA57 or VTL1 access.

## Ordered read recorder checkpoint: 2026-11-07

The first P02 substep adds the shared recorder and operation-wide budgets to
the actual owned-process capability probe. The recorded bytes come from that
read, with no evidence-only reread. This does not complete P02: image/scanner
migration, native raw status DTOs and typed translation are still open.

Release x64 EXE SHA-256:
`1202859ac3a3ca7a7aa8532d14183870da934be00ab3955f3dcf016d95d67dac`.
ASan recorder harness SHA-256:
`91f6b56c43255b851ca95e7a35a6ef10adc8665217246df4f67e06b14c38e636`.
The full Release solution built with the P01 VS/MSVC/SDK/WDK configuration.
The unchanged `KmonHuntIndex::NextQueryEpoch` atomic field still emitted C4744
alignment warnings. Signing/deployment trust was not established.

`validate-read-receipts.ps1 -Sanitize` passed 48 controls. Its independent Python
oracle checked 13 operations and 14 snapshots, including a pending concurrent
read. Controls cover original partial/error data, denial and cancellation,
explicit fallback permission/source/range links, shared byte/call/span limits,
receipt overflow, elapsed-time overrun, source replacement, malformed spans,
exception unwinding and admission order differing from completion order. The
concurrency test waits for observed source work before releasing the other actor.
The owned Win32 control also compares direct API failure codes, closes the original
caller handle and frees the source allocation before checking retained bytes.

Review corrected three recording gaps: delegated empty denials lost their
specific state, rejecting malformed/replaced-source bytes erased raw status, and
pending/abandoned JSON lacked the requested range. It also added a separate sparse
metadata budget; a byte limit alone did not bound span storage. The final reviewed
scope had no additional actionable defects.

Existing owned process-source ASan checks passed 23 controls and six JSON cases.
Evidence-bundle ASan passed 522 synthetic controls, including the common source
admission/parser regressions; eight interrupted publications produced three valid
final files and five absent finals, with restart checks passing. The runtime
policy harness passed 22 controls, and the actual CLI probe passed the read-set,
Unicode/output-failure and matrix checks. All 24 compiled contracts/261 routes,
the generated support matrix, 11 public-content scanner regressions and full
linked self-tests passed (timeline 28, MCP 102, console 558, commands 3,000,
remote 66).

No driver was loaded. Native connection availability remained unavailable on
this host. Native NTSTATUS recovery, process fallback, page-table receipts,
protected-target access, real LA57, durable replay of this new JSON format and
OS/security-state regression are not established by these controls. Target and
address-space labels remain caller-declared. Budget charging counts delegated
source requests, not physical I/O; elapsed time includes parser/queue delays but
does not measure them separately. In-flight calls are not forcibly cancelled.

## Scoped runtime capability checkpoint: 2026-11-06

The selected P04 probe and generated source/address matrix extend the compiled
inventory. Default `--capabilities` still performs no target probe. The explicit
`--probe` path acquired a known 32-byte owned-process range through the real
Win32 source. Opening the default native device was unavailable on this host;
no driver was loaded or started. The native open/ABI/session success policy was
checked with synthetic inputs, not a successful live driver connection.

Release x64 EXE SHA-256:
`09a97bda2659e09944e9149b48f21002e0f289d3e9c785b832152babfe0a22e5`.
ASan policy harness SHA-256:
`a6a82694d41a3d6d11721d03601d2436d33ce4786b972a1cf40606c0757e24b0`.
The build used the same VS/MSVC/SDK/WDK configuration as the P01 checkpoint below.

`validate-runtime-capabilities.ps1 -Sanitize` passed 22 policy controls for
missing source/ABI/session, sample identity/control bytes, unsupported backends
and refusal to promote connection checks into scanner/environment support.
`test-source-capabilities.py` passed the existing 24 contracts and 261 routes
with the additive stage/scope/address metadata. `test-runtime-capabilities.py`
passed actual owned read, conservative native availability, strict arguments,
public-matrix rejection of runtime reports, atomic generation/stale-check
behavior, Unicode output and read-only stdout failure controls. The generated
[matrix](SUPPORT_MATRIX.md) passed `--check`. Publication scanner regression
tests passed all 11 cases, including renamed/inconsistent runtime reports.

The first runtime CLI test failed because localized Windows status text truncated
wide-stream JSON under the C locale. Explicit UTF-8 redirected writes and Unicode
console writes fixed it; Korean, a supplementary character, quotes/newlines and
output failure now have regression controls. The final reviewed scope had no
additional actionable defects. Full solution build and `--self-test all` passed
(timeline 28, MCP 102, console 558, commands 3,000, remote 66).

These checks do not qualify a native layout, a protected process, another target,
real LA57, VTL1, trace/VMI, or an OS/CPU/security-state support combination. The
probe's owned address shape is explicitly legacy LA48; active native width remains
unknown without the driver response. Other backend/layout probes and authenticated
environment regression evidence remain open P04 work. Runtime reports are private
evidence, and connection handles close before output. Native raw error domains
and operation-wide deadlines were outside this checkpoint; selected operation
budgets are covered above. Signing trust remains unvalidated.

## Hidden-process scheduling checkpoint: 2026-11-06

P01 of the [integration design](FEATURE_PLAN.md#full-kernel-integration-design-2026-11-06)
uses the same qualification orchestrator in native CLI/KMON and owned controls.
The pending queue lives beyond each scanner instance and resets on a changed
device connection epoch. Only scheduling hints persist; every comparison requires
fresh lifetime samples and fresh inventories in its own batch.

Release x64 EXE SHA-256:
`d084d488dcb63c7fabf0c696dd0328aa73b92ac5583cde00e46cd4c4f435db78`.
ASan hidden-process harness SHA-256:
`5114f1d31a3b6d9dfab3aaabfa8c8953d2cd902ce6c6d9ceb7b8f9227c32532e`.
Build inputs were VS 2022 Build Tools, MSVC 14.44.35207 and SDK/WDK
10.0.26100.0, Release x64 without a version bump.

`tools/validate-hidden-process.ps1 -Sanitize` passed 226 existing policy controls
and 1,367 scheduler controls. These execute the production batch selection and
boundary orchestration with an owned source and deterministic clock: all 257 and
1,025 fixed candidates receive service; continuous priority arrivals retain the
old cohort's minimum share; failing prefixes rotate; cost adaptation leaves time
for comparison/after reads. Cancellation, PID generation changes, zero budgets,
source replacement and departed candidates preserve exact unverified scope.
An independent Python JSON oracle checked seven original dispositions and all
257 candidates over three fresh scheduled batches, including no stale samples
on deferred records. These are synthetic acquisition controls, not 1,025 live
hidden processes or a measured host latency SLO.

The full `tools/build.ps1` solution build and `--self-test all` passed. The linked
tests reported timeline 28, MCP 102, console 558, command checks 3,000 and remote
protocol 66; startup/compiled capability validation also passed 24 contracts and
261 routes. The build emitted C4744 alignment warnings for the unchanged
`KmonHuntIndex::NextQueryEpoch` across existing translation units. Driver signing
metadata was present, while the local trust query returned `UnknownError`;
this checkpoint does not establish deployment trust or native load compatibility.

Review corrected queue insertion rollback on allocation failure and preservation
of the before-phase timeout reason. The final reviewed scope had no additional
actionable defects. Working-tree and prospective-index public-content scans passed; raw evidence,
private paths and credentials are excluded from publication inputs.

No driver was loaded, no Driver Verifier or reboot was run, and native candidate
churn, protected targets, live LA57 and multi-host workloads remain unvalidated.
The scheduler does not interrupt an in-flight API, bound initial discovery, retain
raw cross-view reads or measure successful lifetime revisit latency. These limits
remain distinct from the implemented fairness and fresh-batch contract.

## Process-handle observation source checkpoint: 2026-10-30

Release x64 EXE SHA-256:
`cd02b63efc70d9a1320efec8113d4d049e2baba0f6dfa0a4dce7855de8bf00ce`.
The actual Win32 source passed 23 ASan controls and six independent JSON
observations. Owned-page checks cover retained handle ownership after caller
closure, exact PID/creation identity, unchanged access rights, required residency
consent, cancellation, budgets, user-only admission, inaccessible/partial reads,
multi-chunk discard and 512 successful plus 512 rejected constructor lifetimes
without a handle-count increase. The source does not assert current liveness.

Shared-source regressions passed 522 ASan evidence controls and eight interrupted
publications (four valid final bundles, four absent), with restart reads.
The dump source passed 107 ASan controls and 102 public CLI assertions; one
symlink control was skipped by the environment. The additive native-status JSON
field remained compatible with these owned dump inputs. Release and native
suites passed timeline 28, MCP 102, console 558, commands 3,000, remote 66 and
connect arguments. Capabilities passed 24 selected contracts/261 routes.
Publication-scanner regression code and inputs are unchanged from the preceding
ten-test corpus checkpoint; the prospective index is scanned separately.

Review required RAII ownership even if constructor string allocation throws,
rejected kernel addresses before invoking the provider, preserved original
Win32 errors and cleared failed assembled bytes. A first multi-file patch used
a missing project-filter anchor and applied no changes; the corrected patch
was built and tested. No additional actionable defects were found in the
reviewed scope. Logs are under `.build/architecture/w03-process-*`, including
`-source-first`, `-bundle-regression`, `-dump-regression`, `-dump-cli`,
`-build-first`, `-native-all` and `-capabilities`. Existing compiler/LTCG warnings
remain. No driver or external target was used. The selected native image-reader
integration was compiled, but its live scanner/native-fallback behavior,
protected processes, real LA57 and full recipe publication remain unvalidated.

## Corpus evaluator checkpoint: 2026-10-30

The Python 3.11 evaluator passed 13 test groups with independently specified
synthetic denominators, missing/errored/unavailable cases, unknown truth,
correlated variants, family/group/artifact split leakage, exact corpus/scope
identity, duplicate assessments, strict JSON, closed schemas, unsigned latency,
8 MiB inputs, 4,096 cases and 512 comparison scopes. Public CLI success and
failure checks verify valid JSON output and empty stdout on rejected inputs.
The documented fixture example produced end-to-end recall 2/7 and observable
recall 2/4; these are synthetic arithmetic controls, not detection-rate results.

Publication-scanner regressions passed ten tests, including the three private
benchmark schemas. Document links and the executable example passed. No
additional actionable defects were found in the reviewed scope. Logs are
`.build/architecture/w15-corpus-tests-final.log` and
`.build/architecture/w15-corpus-public-tests.log`; the generated example report
remains private under `.build/architecture/`. This stage changed only Python
tooling, publication rules and documents; it did not rebuild or revalidate the
unchanged native binary. No collector, driver or external analysis tool ran.
Imported evidence hashes and ground truth are declarations, not authenticated
artifacts. Independent corpora, sampling uncertainty and live safety remain open.

## MCP operation outcome checkpoint: 2026-10-30

Final Release x64 EXE SHA-256:
`dfa3ea661359379ab8cdde71669af52860af03c6dd3608f45721e5db8729c024`.
The operation ledger passed 25 ASan controls, including 128 concurrent
timeout/completion schedules, with seven independently checked JSON state
records. Queued cancellation cannot dispatch; active unknown outcomes survive
retention pressure; duplicate completion cannot replace the first outcome.
Admission fails when all 256 metadata slots remain active.

The native suite passed timeline 28, MCP 102, console 558, commands 3,000,
remote 66 and connect arguments. This engine build's SHA-256 was
`79746f8f0ea280091054992d7a3ae98e11efd136796de816b8724cba2ad8a33d`;
the final build only extended HTTP resource tests. Final loopback HTTP controls
passed 25 checks, including the real 30-second response wait, lookup while a
fake engine remains blocked, late completion, argument rejection and operation
IDs in tool/resource success/error replies. The fixture executed no kernel
command and changed no URL ACL or firewall rule. It closed its owned listener.

Capabilities passed 23 selected contracts/261 routes; publication-scanner
regressions passed ten tests. The initial capability script invocation omitted
its required `--exe`; the corrected command passed. Document links and the
68 read/12 write catalog counts were checked. Logs are under
`.build/architecture/w14-operation-*`, including `-core-final`, `-native-all`,
`-http-final`, `-capabilities-final` and `-build-final`.

Review preserved the existing payload schema, serialized queue/ledger updates,
rechecked completion at the timeout boundary and separated cancelled operation
completion from actual engine completion. No additional actionable defects were
found in the reviewed scope. Existing compiler/LTCG warnings remain. These are
synthetic engine/transport controls, not driver execution or mutation-effect
validation. No VM or driver load was used. TLS, per-principal authorization,
durable/idempotent operations and the remote protocol adapter remain open.

## Saved ETL capability probes on 2026-11-22

The x64 Release binary scanned each pinned file once per capability invocation.
Windows `tracerpt` supplied independent counts for the two classic event
families. The existing CPU and switch commands supplied the first decoded
ordinal and payload fields. The checker reconstructed the little-endian payload
from those fields and compared its length and SHA-256 with the probe.

| Saved ETL | All records | CPU samples | First sample ordinal | Context switches | First switch ordinal |
| --- | ---: | ---: | ---: | ---: | ---: |
| PerfView x64 | 179,474 | 79,528 | 1,137 | 0 | — |
| PerfView x86 | 168,298 | 88,809 | 1,559 | 0 | — |
| SimpleAllocator | 418,378 | 5,496 | 19 | 0 | — |
| ETWAnalyzer scheduler | 877,318 | 18,556 | 527 | 168,474 | 610 |
| PerfView single-event control | 23 | 0 | — | 0 | — |

All five reported matching sequential buffer totals and zero loss indications.
The control produced a successful source scan and two `partial` rows with zero
records. Removing the last byte from copies of the four populated files left
fewer buffers than declared. Each scan returned exit 1, retained the counts
it could read and limited both families to `partial`.

```powershell
python tools/test-etl-capabilities.py --exe x64/Release/KnLiveDbg.exe --etl $etl --sha256 $pin --check-short-tail
```

The short-tail switch applies to the four populated fixtures. Separate controls
covered a wrong digest, a missing file, an invalid ETL, a read-only output
stream and hard-linked output on both valid and rejected command forms.
Repeated file selectors and mixed live/file probe flags protected every named
ETL from redirected diagnostics.
Six previously saved pages from the scheduler ETL reproduced byte for byte across
CPU profile v1–v3 and context-switch v1–v3 at offset 127, four rows each.
Each original page SHA-256 also matched through `--check-page`.
The public-content scanner detected the report and detached probe records.
The matrix generator accepted only the compiled inventory. The 44 native
capability policy checks passed in Release and ASan, including mixed event
layouts, all three loss counters and unqualified buffer totals. The Windows
ASan runtime emitted its existing interception warnings. This evidence covers
the saved files and decoders tested here. Capture authenticity, event semantics
and live platform compatibility require separate evidence.

## Saved ETL CPU profile validation on 2026-11-22

Windows `tracerpt -rts` decoded three public PerfView test files independently
of the application's PerfInfo payload reader. Both readers use Windows ETW for
file traversal. The test compared every supported sample in 128-row pages,
including its ordinal among all events, raw timestamp, CPU, payload IP and
TID, count, reserved value, header PID/TID and descriptor fields.
[Microsoft PerfView inputs at the tested revision](https://github.com/microsoft/perfview/tree/ea4e78e0e363a0838c963338619221f3e211ddb5/src/TraceEvent/TraceEvent.Tests/inputs)

| Original ETL | SHA-256 of extracted ETL | Event records | CPU samples | Buffers |
| --- | --- | ---: | ---: | ---: |
| `net.4.5.2.x64.etl` | `50da7f725f80f88a7622b37f9826844a790cb0c4f64e351fa1f38cf24916889a` | 179,474 | 79,528 | 360 |
| `net.4.5.2.x86.etl` | `18e62d477308bdc9b01ca6674cbbcbb7c350acf2bf68733ba6361976fac9538d` | 168,298 | 88,809 | 276 |
| `Regression/SelfDescribingSingleEvent.etl` | `4c312c63c7d366e12b908c49769943886c017497183733bc2c93b8d80e932c7c` | 23 | 0 | 3 |

Extract one of the pinned public inputs into a private local directory. Pass
the ETL path, its digest and the sample count from the table to the checker.

```powershell
python tools/test-etl-profile.py --exe x64/Release/KnLiveDbg.exe --etl $etl --sha256 $pin --expect-samples $count --all-pages --check-short-tail
```

Removing the last byte of the x64 ETL left Windows able to read 359 of 360
buffers and 179,022 events. The command returned `partial` and exit 1. The
suite also checks a zero-sample page, a missing or invalid file, incorrect
digest, page boundaries, a writable ancestor and a writable hard link to the input. Both positive
fixtures used 64-bit event pointers. In-memory layout checks cover both widths,
unaligned payloads, differing header and payload TIDs, stack extension counts,
wrong provider, opcode, version, flags, lengths and missing data. Run them with
`tools/validate-execution-trace.ps1`. The standard MSVC AddressSanitizer startup
stopped before the harness on this host. The process-scoped
`ASAN_WIN_CONTINUE_ON_INTERCEPTION_FAILURE=1` run passed the layout and
93 normalized controls with an interceptor warning. The ordinary Release
harness passed without that override. These saved traces provide sampled IPs.
Known owned execution, source authentication, thread/image lifetimes and
exact code-version binding remain open.

### Thread boundary comparison

Running `tools/test-etl-profile.py` on the same three files with
`--thread-evidence --all-pages --check-short-tail` checks each returned
boundary against the Windows `tracerpt` row. Validation includes the original
thread event ordinal, kind, raw timestamp, payload PID and payload TID.

| Source | Thread records | Samples between actual start/end | Samples bracketed using rundown | One boundary | Unusable TID |
| --- | ---: | ---: | ---: | ---: | ---: |
| x64 fixture | 1,358 | 5,126 | 1,075 | 14 | 73,313 |
| x86 fixture | 1,442 | 4,910 | 1,760 | 11 | 82,128 |
| Control | 0 | 0 | 0 | 0 | 0 |

The layout harness also checks pointer widths, unsupported versions, unrelated
opcodes, PID reuse, conflicts, equal or reversed timestamps, a supplied
capture-gap flag and the first event beyond the index limit. Context switches, independently
verified code and cross-file lifetime identity require additional evidence.

### Thread version 3 with a name suffix

The `SimpleAllocator-dotnet6.etl` file has SHA-256
`5876415dbc49e6b86bd96906e77a2237deced01a8841684644f3bd303a1cf812`.
Windows delivered 418,378 events, including 5,496 CPU samples and 8,966
thread boundaries. The native event headers and Windows `tracerpt` both
identified the boundaries as version 3. A comparison of the raw envelope
lengths with the fixed layout exposed the optional terminated name suffix.
[PerfView test archive](https://github.com/microsoft/perfview/blob/ea4e78e0e363a0838c963338619221f3e211ddb5/src/TraceEvent/TraceEvent.Tests/inputs/AutomatedAnalysis/SimpleAllocator-dotnet6.etl.zip)

Use `--expect-samples 5496 --thread-evidence --all-pages` for
this fixture. Windows XML supplied all 5,496 samples as named fields. It
returned `ProcessingErrorData` with the original payload for all 8,966
thread events. The checker decoded their two 32-bit IDs and compared every
sample's boundary ordinals, raw times and payload IDs. Actual start/end
records bracketed 25 samples. Rundown contributed to 4,487 sample brackets. Recorded names stay in the source ETL.
The native harness covers empty and nonempty names, supplementary characters,
missing and embedded terminators, odd lengths, unpaired surrogates and the
largest even payload representable by the ETW length field. Fourteen saved
v1/v2 pages from the earlier fixtures retained their exact UTF-8 contents.

### Image range comparison

On 2026-11-22, the public `--image-evidence` command and Windows
`tracerpt -rts` agreed on all 173,833 sample rows from the four pinned
files above. The checker used TDH's named Image fields and an independent
chronological history for each PID and base. For every referenced record it
compared the original ordinal, raw tick, opcode, version, pointer width,
payload PID, bases, size, PE fields, signature fields and exact file name.

| Source | Image records | Load/unload | With rundown | Identity conflict | No recorded range | No paired thread PID |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| x64 fixture | 3,596 | 0 | 422 | 506 | 5,273 | 73,327 |
| x86 fixture | 3,734 | 2 | 881 | 2,356 | 3,431 | 82,139 |
| SimpleAllocator | 44,895 | 0 | 2,831 | 0 | 1,681 | 984 |
| Control | 0 | 0 | 0 | 0 | 0 | 0 |

Run `tools/test-etl-profile.py` with `--image-evidence --all-pages
--check-short-tail` and the pinned digest and sample count for each file.
The x64 and x86 fixture names describe the workload. Both carried version-2
image events with 64-bit kernel pointers. SimpleAllocator carried version 3.
The two load/unload samples and 4,134 samples bracketed using rundown have a
source-reported RVA. These fixtures supply no independent process generation
or retained code bytes for those samples.

The native harness exercised both pointer widths, remapping at the same
base, overlapping ranges, name and signature disagreement, time ordering,
incomplete coverage, the last representable address and both index limits.
The ordinary Release run and the process-scoped ASan run passed the layout
checks and 93 normalized controls. The latter used the interceptor override
described above and emitted the startup warning. Fourteen saved v1/v2 pages
matched their earlier output byte for byte.

### Process generation and image containment

The `--process-evidence` comparison uses the public PerfView x64 and x86
workloads, the allocator trace above, and the ETWAnalyzer scheduler trace
identified below. Windows `tracerpt -rts` supplied the original process
record ordinals, ticks, opcodes and named fields. The checker reconstructs
each PID's history and checks the two process witnesses for each sampled
thread. With `--image-evidence` it also compares the loader records against
the process interval. It preserves the `ExitTime` field in version-5 defunct
records as an unsigned integer. All tested captures use one native logger
and 64-bit process event headers, including the x86 workload.

```powershell
python tools/test-etl-profile.py --exe x64/Release/KnLiveDbg.exe --etl $etl --sha256 $pin --expect-samples 18556 --process-evidence --image-evidence --all-pages --check-short-tail
```

| Pinned ETL | Samples compared | Process records, including defunct | Samples inside actual process start/end | Samples with image pair inside that process |
| --- | ---: | ---: | ---: | ---: |
| ETWAnalyzer scheduler | 18,556 | 358 | 4,675 | 2,112 |
| PerfView x64 workload | 79,528 | 68 | 5,126 | 0 |
| PerfView x86 workload | 88,809 | 74 | 4,897 | 0 |
| Allocator | 5,496 | 1,303 | 0 | 0 |
| 23-event control | 0 | 0 | 0 | 0 |

A separate callback comparison covered all 1,803 process records, including
798 defunct records. Digests of the reported numeric fields, source ordinals,
ticks and opaque-key presence and equality matched the Windows XML. After
the scheduler file was shortened by one byte, 17 previously qualified samples
on one page retained both original process witnesses. The reader withheld the
generation and process-bound RVA for those samples. Fifty distinct page
hashes from earlier profile and switch formats matched their original values.

The scheduler trace had 69 version-5 defunct records and 818 sample
associations supported by process rundown. All 4,512 process brackets in
the allocator trace used rundown. The checker also exercises a zero-row
page, flag ordering, truncated buffers, output aliases and pinned ancestor
directories. The scheduler export contains non-UTF-8 text from unrelated
providers. In combined mode the comparison requires every selected image
filename to decode without a replacement character.

Release and ASan native checks cover 32-bit and 64-bit event layouts,
WBEM SIDs, all supported opcode/version combinations, malformed strings,
the first process record beyond the retention limit, PID reuse, conflicting
keys and loggers, distinct raw clock conflicts, and process or image
boundaries outside an otherwise plausible pair. The Windows ASan run used
the process-local interception override described in the scheduler checks.
Public ETL process layouts observed here are v4 and v5. V2, v3 and 32-bit
process payload coverage comes from constructed records.
[Process evidence contract](TRACE_IMPORT.md#match-a-sample-to-a-recorded-process-generation)

### Compare a PE reference with original loader records

On 2026-11-22 the five pinned ETLs in the process table supplied 192,389
CPU samples. The ETWAnalyzer scheduler trace provided 18,556 of them. The
independent checker reads the original `tracerpt -rts` loader fields and
uses Python to parse the supplied PE section table and hash its raw bytes.
Microsoft's symbol store serves the tested `msvcrt.dll` with SHA-256
`dd7c8bc34cdbe30ef921395e874909bbf6be53803822164f75f7207e9f085650`.
All 152 samples whose recorded fields agreed with this file yielded the
expected offsets, lengths and window hashes. The trace had 1,960 other
process-bound image samples and 16,444 samples without a process-bound
image. Its `DefaultBase` for the accepted image matched the reported
load base. After a one-byte truncation, all 152 sample ordinals were still
present and every corresponding file window was withheld. None of the
other four ETLs had a process-bound image RVA to compare. [Microsoft reference DLL](https://msdl.microsoft.com/download/symbols/msvcrt.dll/564F9F399e000/msvcrt.dll)

```powershell
$pe = Get-Item .\reference\msvcrt.dll
$pePin = 'dd7c8bc34cdbe30ef921395e874909bbf6be53803822164f75f7207e9f085650'
python tools/test-etl-profile.py --exe x64/Release/KnLiveDbg.exe --etl $etl --sha256 $pin --expect-samples 18556 --reference-image $pe.FullName $pePin --all-pages --expect-reference-windows 152 --check-short-tail
```

A second run used `coreclr.dll` from the official .NET 6.0.0 win-x64
runtime ZIP. The ZIP matched the distribution SHA-512. The DLL's SHA-256
was `b33c50b90daa836a0c33a3a43b117af0c6c1502941d8b83d4029a15cc5e332a7`.
The loader name, size and stamp agreed for 1,252 samples. The recorded
checksum was 5,165,493 and the PE header checksum was 5,128,662. These
samples produced no file windows. Both runs kept the runtime code version
unqualified. [Microsoft .NET 6 release hashes](https://dotnetcli.blob.core.windows.net/dotnet/release-metadata/6.0/releases.json)

The native controls check one-byte section tails, raw padding, zero-fill,
nonexecutables, conflicting fields and missing build information. An owned
test PE contains a known marker in a declared executable section. Its RVA
is obtained inside that test process and compared with the independently
calculated file-window digest using constructed loader fields. The check
passed in PE32 and PE32+ processes and in the x64 ASan harness with the
process-local interception setting documented below. An overlapping read
confirmed that both input files denied write and delete access during the
comparison and released both handles afterwards. Their hashes stayed intact.
All 28 earlier profile and switch pages checked against the parent executable
had byte-identical output. Public ETLs and reference files stay outside
the repository.
[Reference input and report](TRACE_IMPORT.md#compare-a-recorded-image-with-a-pinned-pe)

### Compare merge-time build identity across saved ETLs

On 2026-11-22 the independent checker decoded the ImageID task's binary
payloads from Windows `tracerpt -rts` and compared its source ordinals with
`--build-evidence`. The checker compared all 192,389 CPU samples across the five ETLs in
the process-generation table. It counted 70,018 ImageID records, 69,086
native RSDS records and 846 no-debug-ID markers.
All observed marker layouts used 8-byte pointers, including the x86 workload.
The native harness also exercised 4-byte payloads. Markers and loaders often
had intervening events. Some loader stamps were zero although the corresponding
merge records had a stamp. The report preserves both.

The scheduler trace contained 18,556 samples. Both image endpoints reported
the same merge build for all 2,112 samples with a process-bound image.
Comparing the pinned Microsoft `msvcrt.dll` above gave 152 hash windows.
After removing one byte from an owned trace copy, all 152 sample ordinals
survived and none retained a file window. The .NET reference matched the
merge GUID, unsigned PDB age and merge timestamp for 1,252 same-name samples.
Their original loader checksum differed from the PE header checksum and the
reader withheld every window. These comparisons cover the file inspected by
the merger and the explicitly supplied PE. The memory bytes at sampling time
and the producer's authenticity remain unknown.

```powershell
python tools/test-etl-profile.py --exe x64/Release/KnLiveDbg.exe --etl $etl --sha256 $pin --expect-samples 18556 --build-evidence --reference-image $pe.FullName $pePin --all-pages --expect-reference-windows 152 --check-short-tail
```

The empty ETL control exercises 36 inert PE32 and PE32+ layout cases with a single
mapped or raw-only RSDS, missing or duplicate entries, conflicting offsets,
truncated data, padding and partial section extents. The native harness also
checks logger/PID collisions, record order, loss, index exhaustion, missing
boundaries and changed GUIDs or ages. The native record checks passed in
32-bit and 64-bit Release processes. The x64 ASan harness passed with the
previously documented process-local interceptor setting and startup warnings.
All 45 baseline pages from the older profile and switch schemas matched the
parent executable byte for byte. [Merge-time build report](TRACE_IMPORT.md#compare-merge-time-build-identifiers)

### Recorded capture settings in saved ETLs

On 2026-11-22 the capture-settings checker compared every CPU sample and
context switch in the five pinned ETLs below. Windows `tracerpt -rts`
supplied callback order, raw timestamps and payload fields. A separate
`OpenTraceW` reader checked the native logger ID, header flags, original
record ordinal, CPU and payload length of all 28 setting records.
Each file with settings used logger ID zero. The scheduler file held three
distinct group masks under that ID.

| Pinned ETL | Samples | Samples with matching group masks | Samples with a recorded 1 ms period | Switches | Switches with matching group masks |
| --- | ---: | ---: | ---: | ---: | ---: |
| ETWAnalyzer scheduler | 18,556 | 17,434 | 0 | 168,474 | 157,677 |
| PerfView x64 workload | 79,528 | 79,464 | 79,450 | 0 | 0 |
| PerfView x86 workload | 88,809 | 88,745 | 88,753 | 0 | 0 |
| SimpleAllocator | 5,496 | 4,822 | 4,694 | 0 | 0 |
| 23-event control | 0 | 0 | 0 | 0 | 0 |

The three PerfView workloads contained a timer CollectionStart and
CollectionEnd with source zero and a reported interval of 10,000 in
100-nanosecond units. The scheduler file contained only CollectionEnd.
Its 18,556 samples had no recorded period. All five log headers reported
a timer resolution of 156,250 in the same units. The files supplied
version-2 mask records and version-3 interval records with 64-bit headers.

```powershell
python tools/test-etl-capture-settings.py --exe x64/Release/KnLiveDbg.exe --etl $etl --sha256 $pin --all-pages --check-short-tail --expect-timed-samples 0
```

The command above uses the scheduler ETL. The PerfView x64 workload uses
`--expect-timed-samples 79450`. For each trace containing CPU samples, the
checker removed one byte from a copy. The tested pages still contained
1,075 previously qualified CPU samples and 365 previously qualified switches
at their original ordinals and raw timestamps. Every surviving row on
those pages reported unqualified coverage.

Native tests exercised 32-bit and 64-bit headers, changing intervals,
conflicting boundary records, loss markers, unsupported layouts and both
retention limits. The 32-bit and 64-bit Release checks passed. The x64
ASan run passed with the previously documented process-local interceptor
setting and startup warnings. All 60 baseline reports from the older
profile and switch schemas matched the parent executable byte for byte.
The public files supplied no loss-marker example and do not establish
recording privilege, original session identity or the memory bytes at
sampling time. [Capture settings and interpretation](TRACE_IMPORT.md#read-recorded-capture-settings)

### Normalize and replay saved ETL pages

The 2026-11-22 comparison used the five pinned ETLs in the capture-settings
table above. The trace query consumed saved native profile pages. Windows
`tracerpt -rts` supplied each sample's event ordinal, raw tick, CPU, payload
TID, instruction pointer, raw count and reserved values, header PID/TID and
descriptor fields. Separate comparisons checked the native page's logger,
header flags, pointer width and stack-extension count.

| Source | Original events | CPU samples checked through the normalized query |
| --- | ---: | ---: |
| ETWAnalyzer scheduler | 877,318 | 18,556 |
| PerfView x64 workload | 179,474 | 79,528 |
| PerfView x86 workload | 168,298 | 88,809 |
| SimpleAllocator | 418,378 | 5,496 |
| Empty sample control | 23 | 0 |

The checker used the named trace command and the restricted offline and
observe modes. It exercised all seven native profile schemas, including the
pinned reference PE on the scheduler trace. Its inner cursor advanced
within one saved report. The separate native continuation kept its original
ETL offset. Changing a sample while retaining the reported ETL digest
left the normalized sample unqualified and caused an exact replay mismatch.

```powershell
python tools/test-etl-trace-import.py --exe x64/Release/KnLiveDbg.exe --etl $etl --sha256 $pin --all-pages --adversarial --check-short-tail --reference-image $pe.FullName $pePin
```

This command uses the scheduler ETL and the pinned Microsoft PE above.
On the four traces with samples, a one-byte-short copy returned a partial
page. Replaying its native report reproduced its bytes and retained partial
status, including when the native `--after` offset exceeded the surviving
sample count.
Baseline comparisons covered 32 native profile pages, three scheduler
pages and six earlier normalized query outputs from the parent executable.
The 35 native pages were independently hashed and reproduced with their
original options. The empty sample file also produced an empty normalized
result. Reproduction establishes agreement with the pinned input bytes.
Recording privilege, collector identity and code in memory at sampling
time remain unverified. [Input and replay contract](TRACE_IMPORT.md#query-and-reproduce-a-saved-etl-profile-page)

The Release executable passed 93 existing trace controls and 82 restricted
launch checks. The Win32 and x64 AddressSanitizer trace harnesses each read
32 real sample rows and checked a reversed clock, the minimum signed tick
and an out-of-range tick. The ASan run used the process-local interception
workaround and emitted startup interceptor warnings. The CLI example also
ran under Windows PowerShell 5 and PowerShell 7 on the scheduler and empty
sample files.

### Signed ETL capture statements

On 2026-11-22 the owned recorder started a private in-process ETW session,
enabled its own provider, wrote one event and stopped the session by its
returned handle. Windows `tracerpt -rts` found that provider's event among
three original records. The test controller signed the resulting ETL
digest, size, session ID, capture flags and the queried state of its own
profile privilege. The CPU and context-switch readers verified the ES256
signature using Windows CNG. OpenSSL independently created and verified
each test signature. [Windows private ETW sessions](https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-a-private-logger-session)

The archive-witness controls used the five pinned public ETLs above. They
checked CPU and switch pages, and the scheduler trace also exercised the
pinned reference PE. The four nonempty sample traces retained partial
status on one-byte-short copies. A different signer, a valid signature
for an unauthorized role, altered signing input, mismatched ETL length or
digest and a different page hash each retained their own failure evidence.
An unavailable or aliased statement, malformed JWS, alternate data stream
and unsigned role escalation also failed their applicable checks.

With the Release executable built, compile the recorder from an x64 Native
Tools Command Prompt in the repository root.

```cmd
cl /nologo /std:c++17 /EHsc /W4 /WX /DUNICODE /D_UNICODE tools\etl-statement-capture.cpp /Fo.build\etl-statement-capture.obj /Fe.build\etl-statement-capture.exe
```

In PowerShell, set `$openssl` to an OpenSSL 3 executable. The scheduler
ETL and reference PE variables come from the capture-settings validation
above.

```powershell
python tools/test-etl-capture-statement.py --exe x64/Release/KnLiveDbg.exe --capture-exe .build/etl-statement-capture.exe --openssl $openssl --etl $etl --sha256 $pin --reference-image $pe.FullName $pePin --check-short-tail
```

Compared with the parent executable, 41 native and normalized outputs and
35 complete unsigned replay receipts matched byte for byte. Win32, x64
Release and x64 AddressSanitizer harnesses exercised the shared KMON
signature controls, fresh controller and archive statements, and rejected
keys, roles, encodings and source identities. The ASan run used the
process-local interception workaround and emitted startup warnings.
Windows PowerShell 5 and PowerShell 7 both executed the CLI example.
These tests exercise the local cryptographic and replay contracts. Historical key
distribution, original authorship of the public ETLs and code executing
at sample time remain unverified. [Statement contract](TRACE_IMPORT.md#verify-a-signed-capture-statement)

### Context-switch trace comparison

The ETWAnalyzer test archive with SHA-256
`a9e12312f53036bfab01778fa0de183cbca80362376e2b46fbe525a3b233ed94`
contains a 94,896,128-byte ETL with SHA-256
`b4cf77219bacbe8b7ed9467e2b499962cc679373cf141eaae8c25c23bdc7fb23`.
Windows delivered 877,318 events in 181 sequential buffers, including 168,474
version-4 context switches. The event and buffer loss counters were zero.
[ETWAnalyzer test archives at the tested revision](https://github.com/Siemens-Healthineers/ETWAnalyzer/tree/959689ea85c8a0702add801336c00c3ee0e01052/ETWAnalyzer_uTest/TestData)

```powershell
python tools/test-etl-profile.py --exe x64/Release/KnLiveDbg.exe --etl $etl --sha256 $pin --expect-switches 168474 --all-pages --check-short-tail
```

The 2026-11-22 comparison uses the Windows `tracerpt -rts` named fields.
It checks the callback and switch ordinals, raw tick, CPU, header IDs and
descriptor, version and all 12 scheduler payload fields for each switch.
Some unrelated text in this Windows export used the local code page. For
switch comparisons the checker reads the ASCII identifiers and requires
numeric payloads to be ASCII, preserving the event order. The x64 PerfView
fixture and the 23-event control supply zero-switch comparisons. The native
harness covers all three schema versions, both pointer widths, unaligned
payloads, signed bytes, flags, stack extensions and malformed headers.

The raw switch evidence leaves thread generations, elapsed running or
waiting intervals and cause of a wait unresolved. The public trace comparison
covers version 4. Version 2 and 3 coverage uses constructed records.

### Scheduler interval comparison

The same public ETL contains 92,913 ReadyThread v2 records and 4,801 Thread
v3 start, end and rundown records. The checker reads the Windows XML in
record order, indexes transitions by CPU and TID, and locates ready records
between the original switch events. For each CLI row it compares the reported duration,
relation, original event ordinal, timestamp, CPU, payload fields and
references. Logger ID and the processor-index flag come from the native
envelope. All scheduler switches in this file used one logger and indexed
CPU numbers.

```powershell
python tools/test-etl-profile.py --exe x64/Release/KnLiveDbg.exe --etl $etl --sha256 $pin --expect-switches 168474 --intervals --all-pages --check-short-tail
```

| Result on the public ETL | Count |
| --- | ---: |
| Switches compared | 168,474 |
| Nonidle / idle CPU residency spans | 96,827 / 71,450 |
| CPU spans withheld at a thread start, end or rundown boundary | 189 |
| First switch on each CPU, with no earlier endpoint | 8 |
| Off-CPU spans / spans returning on another CPU | 95,963 / 50,418 |
| Waiting state followed by a qualified ready and switch-in | 80,728 |
| Other outgoing state followed by a qualified ready and switch-in | 892 |
| Off-CPU spans with no ready, unknown ready flags or ambiguous ready time | 5,109 / 9,196 / 38 |

The checker also exercises filtered and unfiltered page boundaries, both
switch roles, a zero-switch control and a shortened final buffer. The
shortened trace retains readable switch rows and suppresses elapsed values.
The 33 saved output hashes from the preceding raw switch and CPU profile
schemas cover default, thread-evidence and image-evidence modes.

The native harness covers ambiguous CPU numbering, mixed loggers, signed
tick extremes, same-row roles, late continuity conflicts, thread reuse,
multiple ready records and deferred readiness. Release and ASan each also
ran 93 normalized-import controls. The Windows ASan run used the
process-local `ASAN_WIN_CONTINUE_ON_INTERCEPTION_FAILURE=1` setting and
reported interception warnings. Public trace coverage is CSwitch v4,
ReadyThread v2 and Thread v3 on this QPC capture. The measured intervals
retain file-local numeric TIDs. Wait-object identity requires another source.

## CLR method range validation on 2026-11-22

The standalone check uses the same range reader as the live CLR tracker.
For every CLR event in the four saved ETLs it looks up the original Windows
TDH property `MethodStartAddress`. For a method declaration it checks the
action against the manifest opcode and compares the start, size, method
and module IDs, token, flags, CLR instance and ReJIT ID by property name.
The two .NET inputs below contain verbose v1 declarations. The x86 file
has ten declarations with the JIT flag clear.
[PerfView fixture revision and input hashes](#saved-etl-cpu-profile-validation-on-2026-11-22)

| Input | All events | Loads | Unloads | Inventory | Field mismatches |
| --- | ---: | ---: | ---: | ---: | ---: |
| .NET 4.5.2 x64 | 179,474 | 290 | 288 | 16,702 | 0 |
| .NET 4.5.2 x86 | 168,298 | 405 | 271 | 13,783 | 0 |
| Allocator trace | 418,378 | 0 | 0 | 0 | 0 |
| Self-describing control | 23 | 0 | 0 | 0 | 0 |

Constructed records cover all 28 published provider/ID/version combinations
with both x86 and x64 event-header flags. Windows TDH independently read
the method ID, token and optional suffix fields from those records. Controls
include compact and verbose inventory, empty and non-ASCII method text,
absent and explicit-zero IDs, a nonzero 64-bit ReJIT ID, every shorter
payload prefix, trailing bytes, an unknown version and unrelated markers.
The native x64 and Win32 checks passed. The x64 AddressSanitizer runs
used `ASAN_WIN_CONTINUE_ON_INTERCEPTION_FAILURE=1` for the host's two
interception warnings.

From a Visual Studio developer shell, supply the extracted x64 and x86
ETL paths in `$trace64` and `$trace86`. The expected count includes all
three actions. The console self-test exercises the tracker and hunt output.

```powershell
cl /nologo /std:c++17 /EHsc /W4 /WX tools/clr-method-event-selftest.cpp /Fo.build/clr-method-event-selftest.obj /Fe.build/clr-method-event-selftest.exe
.build/clr-method-event-selftest.exe $trace64 17280
.build/clr-method-event-selftest.exe $trace86 14459
x64/Release/KnLiveDbg.exe --self-test console
```

A fresh x64 .NET Framework process enabled the CLR JIT keyword in its own
private ETW file session. It prepared and invoked a small managed method
and supplied the method handle and metadata token through reflection. The
reader found the matching load in the same PID, event 143 v1, with a declared
size of 48 bytes and the JIT flag set. Both method loads in the six-record
ETL agreed with TDH. The private session stopped with zero
reported lost events and buffers. The ordinary system-wide tracker returned
`ERROR_ACCESS_DENIED` from `StartTraceW` on this host, so its live collection
path still needs verification with sufficient ETW session permissions.

The ordering controls cover an older unload after a newer ReJIT load, a
later conflicting unload, matching retirement, mismatched extent or flags,
absent versus zero generation fields, and a fresh rundown after the
retention fence. The JSON checks preserve the two observation sources and
64-bit identifiers. The x64 Release build retained 16 existing C4744 link
warnings. All 570 console checks passed in an isolated run. A separate AI
subprocess timeout check failed once while a link was running.

These tests cover runtime declarations. Historical
sample-to-byte correspondence, live ReJIT activation, V8, Wasm and
game-object lifetime validation remain open.

## CPU samples with recorded CLR methods on 2026-11-22

The v8 profile reader matched sampled instruction pointers against CLR method
declarations in two public .NET 4.5.2 ETLs. An independent checker read the
Windows `tracerpt -rts` XML by property name. It first reconstructed the
thread and process boundaries and the explicit CLR load/unload intervals,
then checked every CPU sample, candidate count, method offset and cited
declaration on every page. The two merged files reported logger ID zero for
the relevant events in `OpenTrace`. XML supplies the other method fields.
[Fixture revision and SHA-256 values](#saved-etl-cpu-profile-validation-on-2026-11-22)

| ETL | CPU samples | CLR records | Load/unload pair | Preceding declaration only | No covering declaration | Process generation unavailable |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| .NET x64 | 79,528 | 17,280 | 4,456 | 0 | 670 | 74,402 |
| .NET x86 | 88,809 | 14,459 | 2,440 | 62 | 2,395 | 83,912 |

For example, x64 sample 25,422 lies 0x64 bytes into the declared method.
Its process started at record 29,326, its method loaded at record 36,189 and
its method unloaded at record 120,923. The native page and all three query
modes retain those ordinals. Only the original ETL can establish whether a
saved page matches what the reader actually produced.

```powershell
$exe = 'x64/Release/KnLiveDbg.exe'
$pin64 = '50da7f725f80f88a7622b37f9826844a790cb0c4f64e351fa1f38cf24916889a'
$pin86 = '18e62d477308bdc9b01ca6674cbbcbb7c350acf2bf68733ba6361976fac9538d'
python tools/test-etl-clr-evidence.py --exe $exe --etl $trace64 --sha256 $pin64 --expect-methods 17280 --all-pages --expect-paired 4456 --expect-load-only 0 --check-import --check-short-tail
python tools/test-etl-clr-evidence.py --exe $exe --etl $trace86 --sha256 $pin86 --expect-methods 14459 --all-pages --expect-paired 2440 --expect-load-only 62 --check-import --check-short-tail
```

Constructed records exercise address and PID reuse, overlapping extents,
reversed or equal clocks, mismatched loggers, duplicate loads, multiple
runtime generations, malformed records and the 65,536-record limit. The
normalized page checks include absent, explicit-zero and full-width ReJIT
IDs. A fabricated but internally consistent module ID can still be imported
as a reported field. Exact replay against the original ETL detects the
changed page. A one-byte-short copy of each workload retained the original
sample ordinal and tick, reported partial coverage and withheld the method.

The allocator ETL yielded 5,496 CPU samples and zero CLR witnesses. The
23-record control yielded zero samples and zero CLR witnesses. Checks
against a saved earlier reader reproduced 28 v1–v7 pages and their 28
unsigned replay receipts byte for byte. The signed statement tests also
covered v8 with a private controller session and an archive witness.

The x64 Release build completed with 16 existing C4744 link warnings.
All 570 console checks passed. The native x64 and Win32 range tests and
the 93 execution trace controls passed. The x64 AddressSanitizer run used
`ASAN_WIN_CONTINUE_ON_INTERCEPTION_FAILURE=1` for this host's interceptor
warnings. The observed workload declarations were v1. Capture-time code
bytes, a live ReJIT transition and independently verified execution remain open.

## V8 CPU samples and recorded code bytes on 2026-11-22

On Windows x64, Node.js 24.22.3 (V8 13.6.233.17-node.63) ran a
single-isolate arithmetic workload with CPU profiling, low-level code logging
and disassembly enabled. The Release reader paged through all 274 ticks,
2,564 code creations and 2,564 binary records. It matched 59 sampled PCs
to the recorded bytes of JavaScript functions. Nine of those PCs were in the
workload's `profiledArithmetic` function.

The test compared each tick's PC and original line with the text log, and its
logger timestamp and VM state with Node's tick processor. For all 59 matched
PCs, the processor agreed on the native code kind, creation time and offset
within the function. A separate Python reader checked the complete body's
SHA-256 and the byte window at that offset against the x64 binary log.
All 59 windows also matched the instruction bytes printed by V8's disassembler.
These checks use different representations from the same producer. The tick's
timestamp comes from the logger when it drains its queue. The actual sampling
instant and the code bytes resident at that instant remain unknown.
[V8 log writer](https://github.com/nodejs/node/blob/v24.22.3/deps/v8/src/logging/log.cc) · [V8 tick processor](https://github.com/nodejs/node/blob/v24.22.3/deps/v8/tools/tickprocessor.mjs)

Pairing the text log with a valid binary log from a different Node process
preserved the raw ticks, reported a partial result and returned no code bytes.
Constructed cases covered address reuse, relocation, deoptimization,
interpreter ranges, missing history, truncated records, incorrect file
digests, paging and redirected source/output aliases. The named CLI and
the restricted single-file input route both ran. The two-file example in
the operator guide ran in Windows PowerShell 5.1 and PowerShell 7.
[Saved V8 CPU profiles](TRACE_IMPORT.md#saved-v8-cpu-profiles)

Separate runs of the owned workload exercised the Win32 reader and the x64
AddressSanitizer build. Win32 matched 91 of 239 ticks and the sanitizer build
matched 50 of 256. Every matched byte window in both runs agreed with the
disassembly. The sanitizer used `ASAN_WIN_CONTINUE_ON_INTERCEPTION_FAILURE=1`
for this host's interceptor warnings. The Release build emitted the 16 existing
C4744 link warnings. All 570 console checks, 93 execution trace controls
and the compiled capability inventory (60 contracts, 261 routes) passed.

```powershell
python tools/test-v8-profile.py --exe x64/Release/KnLiveDbg.exe --node node
powershell -NoProfile -ExecutionPolicy Bypass -File tools/validate-execution-trace.ps1
```

This adapter covers the pinned Windows V8 format and x64 binary layout.
Browser builds, other V8 versions, Wasm code identity, live JIT or CLR ReJIT
transitions and process-lifetime attribution remain open.

## Game object lifetime validation on 2026-11-22

The Windows x64 fixture contains a native MSVC object with two nonvirtual base
classes, a direct root and a pointer root. The generator used the fixture's PE
and exact private PDB. A separate invocation observed its own live objects
with the production verifier. The oracle compared the returned subobject
addresses with C++ base casts and checked both vptrs, both table entries and
the complete before/after registry fields.

In the same-address reuse case, a second thread waited until the reader had
read the table entry, then destroyed and reconstructed the object in place.
The reader continued only after the writer finished. The root and both
observed values for the selected vptr were identical. The generation changed
from 4,294,967,297 to 4,294,967,298 and the sequence advanced from 2 to 4.
The original rows retained both publications and produced zero structural
findings. Construction, destruction, GC, a vacant slot and the wrong registry
member each deferred the comparison before the first vptr read. Separate
stable controls detected a mismatched table or function range.

The linked KMON self-test exercises the event ring and reference queue. A
deferred rule queues zero target checks. Repeating a stable publication emits
one observation, and a new generation at the same address emits another.
During review, the generator accepted a different base's real vftable and
the watch filter dropped the healthy generation event. Both paths have
regression checks. The event records the digest of the exact manifest bytes
as well as the image digest.

For one PE/PDB and layout, the previous and current generators produced
all 2,938 bytes of the v1 manifest identically. A mixed v2 manifest kept its undeclared object on the v1
structural path. The file checks include an input held open for writing,
overlapping registry locations, a swapped base table, a wrong image or PDB,
a diagnostic stream hard-linked to an input, and concurrent attempts to
publish the same destination. The native and x64 AddressSanitizer fixtures
each exercised 23 lifecycle scenarios and both paths of a mixed manifest.
The sanitizer run used `ASAN_WIN_CONTINUE_ON_INTERCEPTION_FAILURE=1` for
this host's interceptor warnings. The shared publisher passed 151 IRP
binding checks, 53 replay checks and 641 claim publication checks.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/validate-kmon-manifest.ps1
.\x64\Release\KnLiveDbg.exe --game-manifest self-test
```

The owned workload covers the specified MSVC x64 layout and cooperating
writer. Production game-engine allocation and GC protocols, virtual bases,
independent lifetime evidence and live driver-backed collection remain open.
[Registry contract and field meanings](KMON_DETECTION_VERIFICATION.md#game-object-lifetime)

## Normalized trace import checkpoint: 2026-10-30

Release x64 EXE SHA-256:
`721f291d38edf9ab27b491d3bf15f0635ed0f7f92dccb861038c3716b8f83f9f`.
The actual importer and bounded file reader passed 93 independently generated
CLI controls under ASan, then the same 93 through the public native offline
entry. Controls cover source kinds, unknown context, LA48/LA57, loss/gap
consistency, code hashes/conflicts, immutable cross-process paging, integer
precision, Unicode, invalid schemas, collection limits and the 2 MiB boundary.
An already-cancelled library call clears stale output. The documented input
example also passed through the public native command.

Adversarial Unicode input reproduced truncated redirected JSON from wide-stream
output; explicit UTF-8 output fixed it. Review also rejects unpaired surrogate
identifiers and downgrades conflicting code contexts. No additional actionable
defects were found in the reviewed scope. The shared artifact reader's existing
image-recipe ASan suite passed 68 controls and six interrupted publications
(three valid, three absent). Its default 64 MiB limit is unchanged; the importer
requests a smaller limit before allocation.

Final Release/native gates passed timeline 28, MCP 89, console 558, commands
2,998, remote 66 and connect arguments. Capabilities passed 22 selected
contracts/261 routes; publication-scanner regressions passed ten tests. Logs
are under `.build/architecture/w13-trace-*`, with successful `-core-final`,
`-build-second`, `-native-all`, `-native-cli` and `-recipe-regression` gates.
Existing compiler/LTCG warnings remain. No driver was loaded or host security
policy changed. These tests import synthetic normalized records; they do not
validate a raw trace decoder, producer authenticity, live CPU/VTL collection,
runtime code mapping, execution completeness or writer attribution.

## Pending IRP observation checkpoint: 2026-10-30

Release x64 EXE SHA-256:
`f47a773ccd337c6af2c0d5c613f901bea420b14a186f928c7a9ce142b4d9c03f`.
The standalone ASan build of the actual reader passed 32 new LA48/LA57 snapshot
controls and the existing bounded pagination, churn, packet and owner-generation
controls. Six independently parsed JSON reports verify graph endpoints, absent
optional fields, requests without completions, invalid pointer targets, empty
stacks, export limits and unknown outcomes despite cancel/success fields.

Review preserved successful legacy completion observations when optional fields
are absent, discarded observations after owner/list changes, prevented pointer
shape from becoming object validation, and classified routine snapshots as
observations with quiet console display. The first integration build failed on
an incorrect KmonEvent field name; the field was corrected before the passing
build. No additional actionable defects were found in the reviewed scope.

Final Release/native gates passed timeline 28, MCP 89, console 558, commands
2,998, remote 66 and connect arguments. Capabilities passed 22 selected
contracts/261 routes; publication-scanner regressions passed ten tests. Logs are
under `.build/architecture/w12-irp-*`, using `-core-first`, `-build-second` and
`-native-first` for the successful gates. Existing compiler/LTCG warnings remain.
No driver was loaded or host security policy changed. Actual kernel layouts,
KMON acquisition under target churn, request lifetimes, dispatch/completion
latency and wait/lock diagnosis remain unvalidated; the graph records references
inside one non-atomic observation and does not infer missing lifecycle events.

## Native execution evidence checkpoint: 2026-10-30

Release x64 EXE SHA-256:
`bb26ce2627d29da476e1c7f86e4bb2cf7588beb479af2320d0083c9e090830ec`.
The core ASan harness passed 835 native-evidence controls and an independent
Python JSON oracle checked ten source/missing-context cases. Existing capture
scheduling 130, hunting 11,345, pages 54 and false-positive 49 controls passed.
Native command controls exercise the actual VAD finding producer for thread
starts, queued APCs and stack values, plus PSS metadata conversion, bounded
exports, PE32/PE32+ callback widths and rejection of contradictory machine/magic.

Review corrected references emitted as actual execution, lost PSS lifetime/time
metadata, thread-generation deduplication and unchecked PE architecture pairs.
No additional actionable defects were found in the reviewed scope. Final Release
build and the native suite passed timeline 28, MCP 89, console 558, commands
2,998, remote 66 and connect arguments. Capabilities passed 21 selected
contracts/261 routes. Publication-scanner regressions passed ten tests.

Logs are under `.build/architecture/w11-execution-*`; final build/native gates
use `-commit`, and the core ASan run uses `-core-final`. Existing compiler/LTCG
warnings remain. These are owned synthetic controls, not live PSS/APC execution
acceptance. No driver was loaded or host security policy changed. X2-X4,
CPU/code-version binding, trace/VMI sources and actual actor attribution remain
unsupported by these adapters.

## Process cross-view qualification checkpoint: 2026-10-30

Release x64 EXE SHA-256:
`2dad5f77553c46bb0c6a9925b4304ec0fd1ebc3b64e885dea97fb97fb5dab5f2`.
The standalone ASan harness passed 226 controls covering complete and incomplete
comparisons, PID/object/creation-time changes, unavailable lifecycle and auxiliary
fields, exit/delete/rundown transitions, failed/changed list reads, duplicate PIDs,
cycles, truncation, cooperative stops and LA48/LA57 address-shape separation.
An independent Python JSON oracle checked seven retained outcomes, null unknown
fields, discovery versus qualification scope and legacy object-address projection.

Review fixed escalation without readable lifetime state, loss of unverified
candidates, incomplete-list ambiguity, Toolhelp handle cleanup on allocation
failure, old discovery addresses in qualified reports and PID-only deduplication
of unbound KMON candidates. No additional actionable defects were found in the
reviewed scope. The full native suite passed timeline 28, MCP 89, console 558,
commands 2,998, remote 66 and connect arguments; capabilities passed 20 selected
contracts/261 routes. Publication-scanner regressions passed 10 tests.

Logs are under `.build/architecture/w10-hidden-*`; the final build/native gates
use the `-commit` suffix. Existing C4744 alignment warnings remain, with existing
C4244 conversions also reported when KernelMonitor was rebuilt. These controls
use owned synthetic data and do not execute a live kernel scanner. Target churn,
actual layouts, snapshot clones, the 128-candidate/elapsed-budget acquisition
path and live false-positive behavior remain unvalidated on a target. No driver
was loaded or host security policy changed. Raw-read replay and generic proof
ledgers for this scanner remain open.

## Schema parser containment checkpoint: 2026-10-30

Release x64 EXE SHA-256:
`fde987233571dab5ee623004d8fb9702507e9542ea280bb46adae84146e64fac`.
Actual owned child-process controls passed 19 in both Release and ASan builds.
They cover reduced-token/private-desktop entry, argument quoting, stripped
environment, excluded inheritable handles, denial of parent mutation access,
commit and descendant limits, bounded output, timeout/cancellation, child crash,
nonzero exit and cleanup after the owned supervisor is terminated. The native
crash exits with the access-violation status; ASan intercepts it and exits 1.
Both must discard child output and preserve the supervising test process.

Actual PE/PDB identity and schema controls passed 52 under ASan. The public
schema CLI passed 75 checks, including isolated generation, an independent
Python artifact hash/canonical encoding oracle, old `parser_isolated=false`
packages and rejection of an uncontained direct worker entry. One symbolic-link
control was skipped because this environment could not create that link.

The first restricted worker failed during DLL initialization until its logon
SID was retained in the restricting set. An attempted mandatory-policy change
required an unavailable privilege; the final code validates the inherited
no-write-up policy and fails closed if it is absent. A narrow-string privilege
constant in the non-Unicode harness was corrected to the explicit wide API
literal. These were diagnosed before the passing final controls.

Release build and driver-free timeline 28, MCP 89, console 558, commands 2,998,
remote 66, connect arguments and capabilities 19 contracts/261 routes passed.
Logs are under `.build/architecture/w04-worker-*`. Existing LTCG alignment
warnings remain. No driver was loaded or host security policy changed. This
validates the selected offline schema CLI on this host; live symbol consumers,
filesystem/network sandboxing, approved distribution and target compatibility
remain outside this checkpoint.

## Retained fact graph checkpoint: 2026-10-30

Release x64 EXE SHA-256:
`a6f36a083354fddedd3055e2d909317f861a476173aa5fc8e6b01205a8f939dd`.
The evidence ASan harness passed 521 controls, including 72 graph controls for
scope identity, changed input/query cursors, missing/conflicting reads, indirect
and cyclic references, LA57 qualification, maximum admitted spans, cancellation
and budgets. Eight interrupted publications left three valid final files and
five absent files; fresh-process reads passed.

The public graph CLI passed 164 checks, including cross-process pagination,
resolved evidence references, original coverage, PID reuse, legacy address
normalization, identical file aliases and failed input boundaries. Existing
evidence CLI checks passed 99, with one symbolic-link check skipped because the
environment could not create that link. No live evidence was replayed.

Release build, timeline 28, MCP 89, console 558, commands 2,998, remote 66 and
connect-argument checks passed. Capabilities expose 19 selected contracts/261
routes; publication-scanner regressions passed 10 tests. Full diagnostics are
under `.build/architecture/w09-graph-*`. The first harness compile exposed a
missing serializer include, which was corrected before successful validation.
Review also retained original comparison coverage/capture state in graph context
and made unavailable input report a null context instead of a default receipt.
Existing LTCG alignment warnings remain. No driver was loaded. These checks
cover one retained-bundle adapter, not cross-source joins, generic kernel object
graphs, execution attribution or live-target compatibility.

## Capture scheduling checkpoint: 2026-10-30

Release x64 EXE SHA-256:
`b2dcf028b9024f3a9c7ed5fb8e85a6bcf9d9bf70d716f8a960721ca475df15da`.
The core ASan harness passed 130 capture scheduling controls, including class
fairness, urgency selection, exact percentile bucket boundaries, clock reversal,
concurrent metrics, shutdown separation, completed fixed cohorts and incomplete
churning cohorts. Existing verifier/core controls and hunting 11,345, pages 54
and false-positive controls 49 also passed.

The public capture scheduler CLI passed 23 checks. Its actual worker uses owned
process memory with guard/no-access pages: two first dispatches, five continued
dispatches, seven page attempts and two protected-page failures. The guard
remained set. A separate shutdown attempt did not enter normal distributions.
With an explicitly absent device, two kernel requests retained their four-page
quantum: ten unavailable page attempts, four queue dispatches and six immediate
continuations. No kernel read succeeded and no driver was loaded.

Release build and driver-free checks passed: timeline 28, MCP 89, console 558,
commands 2,998, remote 66 and connect arguments; capabilities 18 selected
contracts/261 routes. Publication-scanner tests passed 10 tests. Logs are under
`.build/architecture/w08-capture-*`; existing compiler/LTCG warnings remain.
The 250/1,000 ms values are scheduling urgency thresholds, not measured SLOs.
Real fixed/churning workloads, current six/thirteen-control runs and other
image/reference/layout schedulers still need their own validation.

## Image proof checkpoint: 2026-10-30

Release x64 EXE SHA-256:
`bf67a2d22b9795cfda1654bb06f59c3c25d790bc4fa6f48c0a313bc8787f32bd`.
The image recipe/proof harness passed 68 ASan checks. Controls reject inflated
duplicate coverage, equal counts at different addresses, overlapping failed and
compared bytes, RVA/absolute-address confusion, excluded or missing difference
bytes, loss, wrong normalization bases, unsupported secondary views, cancelled
reads, missing confirmation and implicit original-policy substitution. Six
interrupted publications left three valid cases and three without a final recipe.

The public CLI passed 101 checks, including independent read-byte accounting,
resolving proof references, separate acquisition/target time, scoped claims,
explicit unmet requirements and `proof=null` after failed replay. Eight replays
of retained fixtures from the preceding W07 checkpoint passed in original and
current modes; original comparisons still matched their saved results. The
recipe format and direct comparison policy were not changed by this stage.

Release build and driver-free checks passed: timeline 28, MCP 89, console 558,
commands 2,998, remote 66 and connect arguments; capabilities 17 selected
contracts/261 routes. Publication-scanner tests passed 10 tests. Logs are under
`.build/architecture/w05-proof-*`. No driver or target image was launched, and
existing compiler/LTCG warnings remain. These controls validate selected offline
image claims, not live temporal coverage, collector trust, execution, writer
attribution or detection rates.

## Exact reference replay checkpoint: 2026-10-30

Release x64 EXE SHA-256:
`283aa3c96305049000405549785e0baf3e53021dc796fb7a5affa8cc56cf7184`.
The image recipe harness passed 49 ASan checks using an owned PE, mapped-byte
source and full-dump fixture. Controls cover cross-page relocation, loader
exclusions, stable modifications, unstable rereads, sparse bytes, wrong mapped
PDB identity, ambiguous or changing header bases, missing/corrupt artifacts,
changed original files, policy selection, canonical address bounds and
recomputed-hash tampering. Review reproduced partial reads accepting mismatched
source/consistency labels; retained bytes now require matching provenance in
either replay mode. Six
interrupted publications left three valid replayable cases and three without a
final recipe. No incomplete final recipe was accepted.

The public offline CLI passed 79 checks, including an independent Python digest
calculation and exact artifact-byte comparison. Shared verifier/core ASan checks
passed, including hunting 11,345, pages 54 and false-positive controls 49. Release
build and driver-free checks passed: timeline 28, MCP 89, console 558, commands
2,998, remote 66 and connect arguments. Capability checks passed with 16 selected
contracts/261 routes; publication-scanner regression tests passed 10 tests.
Logs are under `.build/architecture/w07-recipe-*`. The initial harness compile
failed on its `LARGE_INTEGER` fixture assignment. A later script formatting edit
also caused a PowerShell parameter error before compilation. Both were corrected;
the unchanged substantive assertions and new regression controls passed above.

This validates selected offline direct-mapping cases, not native monitor capture,
secondary image-view reproduction, signer approval, collector authenticity or
live execution. No driver or target image was launched. Existing compiler/LTCG
warnings remain recorded in the build log.

## Type schema checkpoint: 2026-10-30

Release x64 EXE SHA-256:
`a45fb23e4183ab0ec3c376b97e6050efed702c0fe58e2cad47f04d46873fe71d`.
The owned PE/PDB harness passed 52 ASan checks. It reproduces DIA `S_FALSE` for
an ordinary member's unavailable bit position, checks ordinary/bitfield/nested
sizes against compiler layout, and exercises exact image/PDB binding, schema
round trips, create-new collisions, corrupt hashes, invalid extents, inheritance
gaps and bounded recursive value expansion.

The public `--schema` CLI passed 72 checks in fresh processes, including an
independent Python payload/artifact hash calculation and malformed packages with
recomputed hashes. One symlink case was skipped because the host could not create
the test link. The Release build and driver-free suite passed: timeline 28,
MCP 89, console 558, commands 2,998, remote 66 and connect arguments. Capability
validation passed with 14 selected contracts and 261 routes. Publication-scanner
regressions passed 10 tests, including renamed private schema packages.
Logs are under `.build/architecture/w04-schema-*`.

No driver, target image or isolated parser worker was started. The assertions
cover local artifact identity and layout bounds, not live kernel layouts,
trusted distribution or the still-pending parser security boundary. Existing
LTCG alignment warnings and warnings in unchanged scanner code remain visible
in the full build log; the build is not represented as warning-free.

## PDB identity checkpoint: 2026-10-30

Release x64 EXE SHA-256:
`d62a8773b2b500e9e3a011bf91f1fe24ca0a0ce212cc3be5b82a831a8cdebe59`.
The actual installed DIA provider passed 28 ASan harness checks using two owned
PE/PDB pairs. The controls reproduce acceptance of an unrelated PDB through
the old unvalidated API, then verify signature/age rejection, a replaced cache
path, image-based load identity checks, unavailable identity and stale module
base/size checks. No target image was executed or driver loaded by the harness.

Release build and the driver-free suite passed: timeline 28, MCP 89, console 558,
commands 2,998, remote 66 and connect arguments. Capability validation passed
with 13 selected contracts and 261 command routes. Earlier dump/evidence gates
remain evidence for those unchanged components; they were not relabeled as new
runs. Logs are under `.build/architecture/w04-pdb-*`.

This validates the PDB identity boundary, not a live kernel layout, immutable
schema package, trusted symbol distribution or isolated parser process.

## Shared dump source checkpoint: 2026-10-30

Release x64 EXE SHA-256:
`d14a5e4e87a8d561919939b92ba28a04fac598dc8c1d1ee45a8834d67622f9ea`.
This code-only checkpoint adds the offline dump source and routes existing dump
translation/integer/string reads through it. The driver source did not change.

| Check | Observed result |
| --- | --- |
| ASan dump source | 107 checks passed: LA48/LA57, 4 KiB/2 MiB/1 GiB leaves, sparse/nonpresent pages, concurrent readers, file sharing, wrong source IDs, cancellation, malformed runs, paging ambiguity/contradiction and replacement fault injection |
| Public dump CLI | 102 fresh-process checks passed; one final-reparse-point control skipped because symlink creation required a privilege |
| Driver-free EXE | Timeline 28, MCP 89, console 558, commands 2,998, remote 66 and connect arguments passed; includes the existing dump paging controls; capabilities describe 13 selected contracts and 261 routes |
| Shared-source regression | Evidence ASan 449 checks and offline evidence CLI 99 checks passed; one symlink control skipped; no live evidence replayed |
| Publication controls | Eight interrupted bundle writes yielded three valid files and five absent files; completed publication and restart passed; ten publication-scanner regression tests passed |

All dump inputs were generated fixtures. A malformed-CR3 test initially cleared
the field to zero (an unavailable value); it was corrected to a different nonzero
root to test the intended contradiction. No actual LA57 target, crash dump from
a live kernel, driver load or host security change was used. A process-scoped
source ID and file metadata checks do not authenticate capture contents. Logs
are retained under `.build/architecture/w03-dump-*`.

## Inventory continuation checkpoint: 2026-10-30

Release x64 EXE SHA-256:
`bb1fcad6b14f1e90650162b9be9a280e7ddfa54baa5d00dd77281d696a64c951`.
The toolchain matches the architecture checkpoint below. The driver source did
not change in this step, and no driver was loaded.

| Check | Observed result |
| --- | --- |
| Driver-free EXE | Timeline 28, MCP 89, console 558, commands 2,993, remote 66 and connect arguments passed; capabilities remain 12 selected contracts and 261 routes |
| ASan evidence | 449 checks passed, including 4,101-file inventory traversal, distinct result/inventory cursors, byte-budget continuation, stale snapshots, missing members/chunks, resealed path traversal and interrupted construction |
| Fresh-process offline CLI | 99 checks passed, including snapshot creation, result continuation, inventory continuation and two interrupted snapshot builders; one symlink control skipped; no live replay |
| Existing publication controls | Eight interrupted bundle writes yielded four valid publications and four absent files; completed publication and fresh-process recovery passed |
| Publication scanner regression | Ten tests passed, including renamed inventory manifests/chunks and temporary files |

The initial ASan inventory test exceeded the 120-second construction deadline
while repeatedly parsing identical files. A bounded exact-content parse cache
resolved that fixture; each file is still reopened and reread. This is not a
performance claim for arbitrary unique million-file inventories. Construction
budgets remain enforced; resumable construction and global cross-window closure
remain open. Logs are retained locally under `.build/architecture/w06-*`.

## Architecture foundation checkpoint: 2026-10-29

The capability, address descriptor, bounded read-source and unique-coverage work
was followed by a native default-write-denied change. This is a development
checkpoint, with live kernel acceptance still pending. Release x64 was built
with MSVC 14.44 and Windows SDK/WDK 10.0.26100.0, using the process-local
`WDKBuildFolder=10.0.26100.0` workaround for the installed WDK task path.

The resulting EXE SHA-256 is
`a4d4690fe9e2c47935472ba78ab2a1445a9bb3b1dd7693c199f9f733a0e58c41`;
the SYS SHA-256 is
`b54aab7db6c4fe9f4dff87451844441e395bc433417e4d928360e4594ea4e1f9`.
The build signed and staged the lab binaries; it did not load them.

| Check | Observed result |
| --- | --- |
| Final EXE driver-free checks | Timeline 28, MCP 89, console 558, command 2,987 and remote 66 checks passed; compiled capabilities cover 12 selected contracts and 261 command routes |
| Final offline CLI | 56 checks passed; one symlink control skipped; no live evidence replayed |
| ASan core | Address/coverage bitmap controls and write-policy failure injection passed, along with hunting 11,345, page 54 and false-positive 49 controls |
| Evidence source and coverage | 412 checks passed before the write-policy-only change; same target parser on owned user memory and immutable evidence, sparse/conflicting spans, cancellation, source replacement and byte budgets |
| Persistence controls | Eight interrupted writes yielded two valid publications and six absent files; completed publication and fresh-process recovery passed |
| Image/layout integration | 105,120 ASan checks passed on the unique-coverage change, including reference/relocation controls |

Local logs are under `.build/architecture`. No new live driver load/unload,
Driver Verifier, LA57 machine test, security-policy change, external malware/game
corpus, trace/VMI backend or independent detection benchmark was performed.
Fault injection confirms the user-mode transition decision, not the kernel
integration contract. The new default-deny capability requires the matching SYS;
the earlier release's live results do not validate that change. Package-level
acceptance gaps remain in [the roadmap](FEATURE_PLAN.md#kernel-investigation-platform).

## Release candidate

The [v0.0.36 release notes](RELEASE_NOTES_0.0.36.md#validation-evidence) identify
the freshly versioned Release x64 tests on Windows **28000.3231**:

| Check | Recorded result |
| --- | --- |
| Build, PE versions, signing metadata | Matching 0.0.36 components; BYOVD metadata fixture intentionally 1.0.0.0 |
| Driver-free `--self-test all` | Timeline 28, MCP catalog 89, console 558, commands 2,961, remote protocol 66, connect arguments 4 |
| Standalone AddressSanitizer parser/completion | 275,002 / 25,954 checks |
| KMON component controls | Hunting 11,326, pages 54, false-positive controls 49; malformed replay inputs rejected |
| Evidence validators | Capture accounting, image names, vctip audit, image coverage and minifilter/research-ledger validator checks passed |
| Owned managed/pending/query fixture | 280 ordinary checks, 57 balanced final unload ledgers |
| Failure supervisor | 10 verified expected failure stages, including abrupt child exit |

The final audit covered **2026-10-25 22:00:57–22:09:36 KST**. Boot time was
unchanged and no new bugcheck/reboot events, dumps, or owned service/process
residue were observed in that interval. Raw release evidence was retained under
`.build/release-0.0.36-20261025`; it is local evidence, not a bundled artifact.
The released ZIP and manifest identify distributed files independently.

## Retained investigation path: 2026-10-29

The final Release x64 user executable had SHA-256
`da6481ec96c9f122869fd8153fb8643c109e5d245882daf6400b7075ee8cd014`.
It used the existing test-signed driver; this work did not change driver code
or publish a new release. Stage-specific controls and final integration results
were retained locally under `.build/design-implementation-20261029`.

| Check | Observed result |
| --- | --- |
| Scoped queries and identity | Hunting ASan 11,345, page controls 54 and analyst ASan 6,602 passed; targets beyond 256, cursor changes, delayed receipts and optional-identity conflicts covered |
| Durable query and replay | Evidence ASan 374 passed; expiry/eviction/restart, missing/corrupt spans, closure accounting and read-byte limits covered |
| Interrupted publication | Final run: eight writer interruptions, one valid final file and seven absent final files; completed full-size publication and fresh-process recovery passed |
| Final executable self-tests | Timeline 28, MCP catalog 89, console 558, commands 2,987, remote protocol 66 and connect arguments 4 passed |
| Public offline CLI | Non-admin fresh-process checks: 110 passed, including all six final live bundles; privileged symlink checks: 180 passed, including 14 bundles from an earlier run |
| Focused live controls | One 180-second run with four positive and two negative owned controls passed; all required positive kinds observed, no unexpected fixture findings, six of six evidence bundles published without failures or queue drops |

The live run ended with drained work, unchanged boot time and no owned services
remaining. Original emitted receipts were cross-checked against all 23 bundles
from three runs. Offline replay of 20 bundles from the last two runs reconstructed
their declared stored facts; it did not repeat image-reference verification or
establish execution, communication, collector trust or actor attribution.
The console self-test also covered native writer queue and session-byte limits,
and replayed an owned allocation's saved bytes after that allocation was freed.

Two earlier all-process runs on an intermediate build, lasting 60 and 180 seconds,
**failed the fixture coverage gate** because some reference scans had not run.
Their queue/drain checks passed, with three and 14 bundles respectively committed
without publication loss, and no unexpected fixture findings. These are not
complete all-process passes; the focused pass does not close that coverage gap.
The reference-service results below address the six-control observation gap.
One earlier whole-app self-test also failed an unchanged AI child-process capture
check; the isolated suite and a quiet whole-app rerun passed. Its exact cause was
not established.

The review corrected an offline integration defect: ordinary controller startup
required elevation and loaded a driver before reaching file-only commands.
`--offline !kmon` now returns before live initialization. Imports also enforce
their byte budget and file-reparse policy on the opened handle. The tests do not
cover every power-loss outcome, long-running workload, Windows build or external
malware corpus.

## All-process reference service: 2026-10-29

The final Release x64 executable had SHA-256
`a2c0aa5a30997b81d4c4b4139507a1700995934688224ac92d8eb450562e96f1`.
The baseline and both final runs used the same six owned controls and fixture
binary, with a 180-second observation window, `-AllProcessLayouts`,
`-RequireQueueHealth` and `-RequireCompletedWork`.

The baseline missed the read-only control's reference visit entirely. Reference
collection waited behind the deep process quota and memory/image work. A separate
watched rotation improved visitation, but two intermediate candidates still
failed the queue gate with 18 and 16 expired references. One recorded IAT walk
held the analysis thread between service boundaries for 32.7 seconds. The final
change services queued references before and after ingestion, increases their
bounded budget under pressure, and yields between IAT descriptors/thunks without
reducing the walk or extending the 30-second freshness limit.

| Observation | Baseline | Final run A | Final run B |
| --- | --- | --- | --- |
| Examined reference visits per control | 0–2 | 6 | 5–6 |
| Latest first visit | 178.9 s; one control unvisited | 26.9 s | 41.4 s |
| Largest reference gap, including window edges | About 180.6 s | 57.5 s | 70.0 s |
| Maximum queued-reference wait | Not recorded | 5.3 s | 13.1 s |
| Expired/dropped references | 0/0 | 0/0 | 0/0 |
| Required positive kinds / unexpected fixture findings | All observed / 0 | All observed / 0 | All observed / 0 |

The baseline gap uses the last fixture's creation time plus 180 seconds because
the old runner did not record the observation endpoint. Final runs record that
endpoint explicitly. An independent JSONL aggregation matched all final visit
counts, completed thread inventories, first-visit delays and maximum gaps.
Unavailable, failed, empty-thread, wrong-instance and out-of-window rows cannot
satisfy the updated fixture gate. Completed thread inventories do not establish
complete APC/callback coverage or execution.

Both final runs verified all-process layout collection, traversed the fixture,
KERNEL32, KERNELBASE and ntdll images for all six controls, passed the queue and
drain gates, kept the same boot and left no owned services. The whole host was
not fully verified: background image work remained at shutdown, layout/read
failures remained, and detection/visit latency varied between runs.

The final native suite passed: timeline 28, MCP catalog 89, console 558, commands
2,987, remote protocol 66 and connect arguments 4. The IAT regression compared
the exact baseline/serviced slot sequence and hit count, and checked cancellation
and exception cleanup with balanced process handle counts. Scheduling/burst
controls and KMON ASan passed, including hunting 11,345, pages 54 and false-positive
controls 49. PowerShell 5 and 7 coverage counterexamples passed. An earlier native
run again failed the unchanged AI process-capture test; isolated output/limit/
timeout diagnostics and subsequent whole-app tests passed without weakening its
assertions. The earlier failure's exact cause remains unestablished.

Raw evidence is retained locally under `.build/kmon-reference-fairness-20261029`.
These are bounded host/fixture observations, not a general miss/false-positive
rate or a completion guarantee for changing workloads.

## Reference watch and TI queue review: 2026-10-29

The follow-up Release x64 executable had SHA-256
`507e4618cc8cc2a71a97be31957569d6a59fcd94ade277f81d4cca0b855bae1b`.
Review found that the additional reference visits could inherit an old implicit
watch after PID reuse, before the deep scanner pruned promoted watches. Visits
now requalify the retained process handle against an explicit PID, a matching
child creation time, or its current image name. Extension wildcards retain their
suffix condition. Native controls seed stale/missing/matching watch identities;
they do not claim to force actual OS PID reuse.

An intermediate 180-second run examined all six controls and observed the four
positive kinds without unexpected fixture findings, but **failed the queue
gate** with 78 TI analysis drops at the 2,048-record capacity. The collector read
up to 512 source records regardless of queue room and advanced past rejected
records. It now reads only available capacity, retains excess work upstream,
and processes a frozen source generation/sequence tail at shutdown. Actual
source overwrite and work left at the shutdown deadline remain reported gaps.

Two final 180-second runs used the same six controls and fixture binary with
`-AllProcessLayouts -RequireQueueHealth -RequireCompletedWork`. One used the
default PID-and-name watches; the other added `-NameOnlyFixtures` so explicit
PIDs could not mask current-name qualification.

| Observation | PID and name | Name only |
| --- | --- | --- |
| Examined reference visits per control | 5–7 | 5–6 |
| Latest first visit | 29.1 s | 36.0 s |
| Largest reference gap, including window edges | 48.4 s | 54.6 s |
| Maximum queued-reference wait | 3.1 s | 8.2 s |
| TI analysis drops / reported event loss | 0 / 0 | 0 / 0 |
| Expired/dropped references / shutdown unanalyzed events | 0 / 0 / 0 | 0 / 0 / 0 |
| Required positive kinds / unexpected fixture findings | All observed / 0 | All observed / 0 |

Both runs passed the queue, drain and all-process scope gates, traversed the
fixture and three fixed system images for all six controls, kept the same boot,
and left no owned services. Independent JSONL aggregation matched the visit
metrics and confirmed an instance-matched additional scheduled visit for every
control within the observation window. The two final TI queue peaks were 556
and 546; deterministic native controls separately exercised full capacity and
one free slot, exact sequence order, frozen-tail clipping, generation changes,
source-eviction accounting and shutdown across multiple batches.

The final native suite passed: timeline 28, MCP catalog 89, console 558, commands
2,987, remote protocol 66 and connect arguments 4. No new System event 41, 1001
or 6008 was found during this review's live-test interval. Remaining background
image work, 562/619 layout failures and 13/9 capture failures prevent a claim of
complete host verification. These fixture results do not establish a general
miss/false-positive rate or a latency guarantee. Raw evidence remains local under
`.build/kmon-reference-fairness-20261029/review-64f23ef`.

## Earlier development evidence

- The final KMON series used repeated 600-second full-process runs with nine
  positive and four negative controls and the actual x86 vctip System.Data.dll
  image views. It improved observed coverage while retaining incomplete large
  background sweeps and run-to-run variation. Those runs used the binaries
  identified in their reports, not the later version-stamped release package.
- The latest query/runner-failure matrix recorded **1,034 ordinary checks**,
  **50 verified injected failures**, and **344 balanced final unload ledgers**.
  It is separate from the smaller release-candidate matrix; do not add their
  totals or describe them as the same run.
- Two development crashes were attributed to this work: an unloaded raw
  replacement callback (0xCE on 2026-10-24) and an unlocked pending READ buffer
  (0x1A/0x4477 on 2026-10-25). External callback replacement was blocked;
  asynchronous fixture READs gained buffer locking and lifetime fixes. The
  historical dumps/failures remain evidence rather than being reclassified as
  successful tests.

## Remaining scope

- No universal miss/false-positive rate, protected-game compatibility, or
  complete host-clean claim follows from owned controls or a quiet scan.
- Read failures, protected processes, unsupported layouts, dynamic-relocation
  exclusions, finite queues/indexes, large-image partials and observation gaps
  remain visible. Traversal completion is not verification of every byte.
- Raw `!kmon iotrace` has a separate unresolved publication/unload lifetime
  boundary. Managed fixture passes do not validate external dispatch mutation.
- Driver Verifier, reboot stress, arbitrary long schedules, full live LA57
  coverage, and independent real-sample comparisons require separate evidence.
- Earlier Fast I/O/process-read gaps and WinHTTP Event-handle retention are not
  closed by the release. Runner cleanup does not cover supervisor termination
  or an OS stop.

## Git history maintenance

On **2026-10-27**, repository branches and tags were rewritten to remove
developer-local path strings. The v0.0.36 source tag now resolves to
`6646461422125290ade00c74ce5e3e07d617e3a7`. Historical report titles and recorded
`base_commit` / `base_revision` values retain their original identifiers from
before the rewrite. Runtime results and binary hashes were not regenerated,
and published release assets are unchanged.

Use a fresh clone, or rebase local changes onto the rewritten history.
Merging the old history back would restore the removed content.

## Historical reports

The following original reports are pinned to **v0.0.36**. Their old protocols,
commands, hashes and counts describe those source snapshots. Current procedures
are in the manual checklist and fixture guides. Removing duplicated work logs
from the current tree does not erase their Git history or raw local artifacts.

| Report | Original record |
| --- | --- |
| Command audit: 2026-09-19 | [COMMAND_AUDIT_20260919.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/COMMAND_AUDIT_20260919.md) |
| 2026-10-25 외부 필터 콜백 수명 검토 | [EXTERNAL_CALLBACK_LIFETIME_REVIEW_20261025.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/EXTERNAL_CALLBACK_LIFETIME_REVIEW_20261025.md) |
| 도움말·자동완성 점검 — 2026-09-20 | [HELP_COMPLETION_AUDIT_20260920.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/HELP_COMPLETION_AUDIT_20260920.md) |
| !kmon adversarial review, 2026-09-16 | [KMON_ADVERSARIAL_REVIEW.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_ADVERSARIAL_REVIEW.md) |
| Kmon 적대적 코드 리뷰 — 2026-09-20 | [KMON_ADVERSARIAL_REVIEW_20260920.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_ADVERSARIAL_REVIEW_20260920.md) |
| KMON 전체 프로세스 레이아웃 큐 검증 (2026-10-23) | [KMON_ALL_PROCESS_LAYOUT_VALIDATION_20261023.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_ALL_PROCESS_LAYOUT_VALIDATION_20261023.md) |
| 분석가용 콜백 수집·스냅샷 기능 적대적 리뷰 — 2026-09-20 | [KMON_ANALYST_REVIEW_20260920.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_ANALYST_REVIEW_20260920.md) |
| 분석가용 콜백 조사 기능 검증 — 2026-09-20 | [KMON_ANALYST_VALIDATION_20260920.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_ANALYST_VALIDATION_20260920.md) |
| KMON 배경 이미지 완료와 이름 조회 재검증 | [KMON_BACKGROUND_COMPLETION_VALIDATION_20261024.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_BACKGROUND_COMPLETION_VALIDATION_20261024.md) |
| KMON 커널 캡처와 레이아웃 단서의 검사 지연 검증 | [KMON_CAPTURE_LATENCY_VALIDATION_20261024.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_CAPTURE_LATENCY_VALIDATION_20261024.md) |
| Kmon 은닉 코드 관측 범위 | [KMON_COVERAGE_MATRIX_20260919.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_COVERAGE_MATRIX_20260919.md) |
| KMON 미완료 검사와 읽기 공백 개선 — 2026-10-23 | [KMON_COVERAGE_VALIDATION_20261023.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_COVERAGE_VALIDATION_20261023.md) |
| kmon 오탐 검토와 증거 해석 | [KMON_FALSE_POSITIVE_AUDIT_20260920.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_FALSE_POSITIVE_AUDIT_20260920.md) |
| 게임핵 헌팅 연구와 구현 기준 | [KMON_HUNTING_RESEARCH_20260919.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_HUNTING_RESEARCH_20260919.md) |
| 동시 감시 이미지 순회 검증 (2026-10-24) | [KMON_IMAGE_SCHEDULING_VALIDATION_20261024.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_IMAGE_SCHEDULING_VALIDATION_20261024.md) |
| KMON 전체 이미지 순회 검증 — 2026-10-23 | [KMON_IMAGE_SWEEP_VALIDATION_20261023.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_IMAGE_SWEEP_VALIDATION_20261023.md) |
| !kmon: implementation of the September 16 gap review | [KMON_IMPLEMENTATION_2026-09-16.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_IMPLEMENTATION_2026-09-16.md) |
| 대형 배경 이미지와 실행 간 검사 범위 검증 | [KMON_LARGE_BACKGROUND_VALIDATION_20261024.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_LARGE_BACKGROUND_VALIDATION_20261024.md) |
| KMON 대형 이미지와 동적 재배치 검증 (2026-10-23) | [KMON_LARGE_IMAGE_VALIDATION_20261023.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_LARGE_IMAGE_VALIDATION_20261023.md) |
| KMON 후보 유효기간·이미지 이름 수집 검증 (2026-10-23) | [KMON_LAYOUT_FRESHNESS_VALIDATION_20261023.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_LAYOUT_FRESHNESS_VALIDATION_20261023.md) |
| 2026-10-23 KMON 실검증 | [KMON_LIVE_VALIDATION_20261023.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_LIVE_VALIDATION_20261023.md) |
| Kmon 프로세스 배치 수집 검증 기록 | [KMON_PROCESS_LAYOUT_VALIDATION_20260920.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_PROCESS_LAYOUT_VALIDATION_20260920.md) |
| 2026-10-23 KMON 큐 포화 및 손실 개선 | [KMON_QUEUE_VALIDATION_20261023.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_QUEUE_VALIDATION_20261023.md) |
| !kmon 추가 은닉 탐지 공백 조사 | [KMON_REMAINING_GAPS_2026-09-16.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_REMAINING_GAPS_2026-09-16.md) |
| kmon follow-up adversarial review | [KMON_REVIEW_FOLLOWUP_2026-09-16.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_REVIEW_FOLLOWUP_2026-09-16.md) |
| KMON 보조 이미지 뷰 재배치 기준 검증 (2026-10-23) | [KMON_SECONDARY_IMAGE_VALIDATION_20261023.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_SECONDARY_IMAGE_VALIDATION_20261023.md) |
| 실제 vctip의 System.Data 보조 뷰 검증 (2026-10-24) | [KMON_VCTIP_VALIDATION_20261024.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_VCTIP_VALIDATION_20261024.md) |
| 2026-10-06 실기 검증과 수정 | [LIVE_HOST_VALIDATION_20261006.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/LIVE_HOST_VALIDATION_20261006.md) |
| 2026-10-13 실호스트 검증 | [LIVE_HOST_VALIDATION_20261013.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/LIVE_HOST_VALIDATION_20261013.md) |
| 2026-10-23 실호스트 검증 | [LIVE_HOST_VALIDATION_20261023.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/LIVE_HOST_VALIDATION_20261023.md) |
| 2026-10-25 협력형 콜백 제어와 커널 수명 검증 | [MANAGED_CALLBACK_VALIDATION_20261025.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/MANAGED_CALLBACK_VALIDATION_20261025.md) |
| 2026-10-24~25 네이티브 기능 실호스트 검증과 재부팅 분석 | [NATIVE_FEATURE_VALIDATION_20261024.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/NATIVE_FEATURE_VALIDATION_20261024.md) |
| 2026-10-25 pending I/O와 completion context 수명 검증 | [PENDING_IO_LIFETIME_VALIDATION_20261025.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/PENDING_IO_LIFETIME_VALIDATION_20261025.md) |
| 2026-10-25 pending I/O 경합 재현과 수정 | [PENDING_IO_RACE_REVIEW_20261025.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/PENDING_IO_RACE_REVIEW_20261025.md) |
| 2026-10-25 f2202d7 다중 READ·인스턴스 분리 경합 리뷰 | [PENDING_MULTIREAD_REVIEW_20261025.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/PENDING_MULTIREAD_REVIEW_20261025.md) |
| 2026-10-25 73e8947 부분 READ 배치·재연결 경합 리뷰 | [PENDING_PARTIAL_REVIEW_20261025.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/PENDING_PARTIAL_REVIEW_20261025.md) |
| 2026-10-25 97a00cd 응답 버퍼·실행기 실패 경합 리뷰 | [PENDING_QUERY_FAULT_REVIEW_20261025.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/PENDING_QUERY_FAULT_REVIEW_20261025.md) |
| 2026-10-25 7a210fa 동시 조회·포트 수명 리뷰 | [PENDING_QUERY_REVIEW_20261025.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/PENDING_QUERY_REVIEW_20261025.md) |
| 2026-10-25 0de0043 새 ARM·요청자 종료 경합 리뷰 | [PENDING_REARM_REVIEW_20261025.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/PENDING_REARM_REVIEW_20261025.md) |
| 2026-10-25 621d16e 대상 종료 감시 경합 리뷰 | [PENDING_WATCH_REVIEW_20261025.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/PENDING_WATCH_REVIEW_20261025.md) |
| Evasion research ledger refresh - 2026-09-20 | [RESEARCH_REFRESH_20260920.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/RESEARCH_REFRESH_20260920.md) |
| 2026-10-23 CI/HVCI 및 메모리 탐지 검토 | [RESEARCH_REFRESH_20261023.md](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/RESEARCH_REFRESH_20261023.md) |
