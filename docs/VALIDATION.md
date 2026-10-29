# Validation status

The released baseline is **v0.0.36 / 6646461**. Development verification of the
retained investigation path and subsequent reference/TI queue fixes was recorded
on **2026-10-29**, through **e73932d**, separately from the **2026-10-25** release
validation. Each section identifies its binary and test scope. Documentation
updates do not renew these observations. Follow the
[manual checklist](MANUAL_TEST_CHECKLIST.md) to validate another binary or host.

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
