# !kmon: implementation of the September 16 gap review

This document tracks the implementation of G01-G22 and B01 from
[the gap investigation](KMON_REMAINING_GAPS_2026-09-16.md). It supersedes the
older coverage descriptions where those descriptions discuss the changed paths.
The work is on top of HEAD `b5804bcf873a3218e00bc15d2835cab1812aa5e3`, including
the earlier uncommitted hardening. No commit or publication is part of this work.

Subsequent defects and validation are recorded in
[the follow-up adversarial review](KMON_REVIEW_FOLLOWUP_2026-09-16.md).
The validation counts below remain the historical implementation checkpoint.

Detection means an observed inconsistency or execution candidate with its source
and coverage. It does not mean that every game cheat is detectable. A successful
collector call, a signature, a complete local snapshot, and trusted attestation
are different facts.

## Kernel memory and image coverage

- **G01 and B01:** DLL classification uses a rooted Windows directory predicate.
  A Windows directory in the middle of another path no longer skips general
  image inspection. NT device prefixes are length-checked before indexing the
  following separator. Tests include short inputs, sibling volume names,
  traversal, and genuine System32/WinSxS paths.
- **G02:** hidden-process findings populate a bounded follow-up inventory using
  PID, EPROCESS and creation time, before event deduplication. Public process
  enumeration failure does not discard this inventory. The concealed-process
  path rechecks the kernel identity around VAD/PTE inspection and execution
  evidence. Access denial reports missing coverage. Unreferenced object reads
  remain observations; before/after equality does not exclude an ABA change.
- **G03 and G14:** kernel images and selected user images have rotating section
  and page cursors. Executable sections include virtual zero-fill tails and
  pages after the first section. Overlapping windows normalize supported
  relocations, including boundary relocations. An incomplete relocation does
  not silently approve a page. Kernel permission probes use the actual page
  RVA, independently of byte-comparison overlap. Unexpected executable data
  pages produce observations. Module selection uses address anchors so insertion
  and removal ahead of the cursor do not permanently starve later images.
  Positive evidence is rearmed only by a comparable clean observation of the
  same page and comparison mask. Ordinary hotpatches, disk servicing and mutable
  image content still require interpretation; a difference is not a cheat verdict.
  Graphics data slots continue through entire supported sections in page-sized
  reads. Candidate pointees require effective executable permission across the
  paging hierarchy, stable slots and current module identity. An unowned RX
  pointer is evidence for investigation; its dispatch role is not established.
- **G04-G05:** session-space, watched-process and discovered-process roots enter
  the orphan scan. Each CR3/process generation retains independent continuation.
  Body reads, translation checks, event keys and captures carry the selected
  root. One Toolhelp process per observed session supplements the watched and
  concealed candidates. This is a bounded root inventory, not enumeration of
  every possible address space or PFN alias.
- **G06-G07:** unowned executable regions can be reported without a PE or import
  stub signature. Pool PE probes rotate through allocation interior pages,
  including NX pages. Large leaves and fixed physical address intervals are
  no longer blanket reasons to suppress a candidate. Effective permission,
  current mapping and available physical-memory classification remain necessary.
  Encrypted or arbitrary headerless NX bytes cannot be identified as code merely
  by their contents.
- **G08:** a deep-PFN request arms every currently known root. Incomplete passes
  retain their own progress after the mapper-watch interval ends. The next pass
  validates the current mapping rather than trusting a retained page-table PA.
  Root/body cache eviction is visible as lost coverage.
- **G09-G10:** unloaded-driver, PiDDB, hash and anonymous driver-object report
  windows continue past their output caps. Output truncation is separate from
  source traversal truncation. An unnamed DRIVER_OBJECT is eligible only after
  actual object-type decoding, typed layout/body checks and repeated identity
  checks. Unsupported private layouts and the source walk's 2048-node guard
  remain explicit limits.

## Execution, callbacks and process provenance

- **G11-G12:** registration snapshots retain per-surface completeness and known
  enable state. The notification mask is exposed as a raw scalar when its bit
  meanings are unavailable. Executive callbacks and kernel WNF subscriptions
  require matching PDB types/symbols. Work-item queues and pending IRP completion
  routines have bounded continuation. Pending IRPs use repeated packet and
  thread/list checks; they are not lifetime-referenced kernel objects.
- NMI, DPC, timer, work-item, WFP, WNF, IRP and CFG dispatch observations also feed
  the common bounded entry-transfer inspection. A recently observed entry can
  outlive its registration; the event states that its lifetime is not proven.
  Pointer ownership alone does not establish the integrity of the target body.
- Minifilter attachment changes require complete, stable per-volume snapshots.
  WFP filters, callouts, providers and sublayers are collected in a read-only BFE
  transaction. Their visibility is limited by the caller's ACLs. Lifecycle
  evidence reports appearance, change or disappearance from that view, not
  malicious removal. An incomplete snapshot resets absence comparisons.
- **G13-G15:** user execution evidence uses PSS native/WOW64 thread snapshots,
  saved kernel context/APC information where supported, TLS callbacks, and
  typed VEH/VCH layouts. Live `GetThreadContext` results are not treated as a
  stable execution snapshot. Hardware breakpoint decoding retains DR7 condition
  bits so data watchpoints are not described as execution breakpoints. Guard
  pages and debugger flags do not provide a broad skip rule. Loader ownership
  must agree with actual MEM_IMAGE/AllocationBase evidence when queried.
  TLS and handler output cursors continue beyond 32 records; private symbol,
  context and memory-read failures remain unknown.
- **G16:** image-path file evidence includes volume/file ID, creation, write and
  change times, size, final path, link count and reparse observations. Repeated
  identities can reveal path replacement, but they do not establish the file
  backing the original image section. Kernel process creation records preserve
  creating PID/TID separately from the selected parent. The timeline keeps both
  fields and does not label an ordinary process creation as a remote thread.
  Broker/request attribution is not inferred from parent PID or ALPC ownership.
- **G17:** watched handle owners rotate by PID anchor beyond the former first
  eight. The first inventory is evaluated, and process generations invalidate
  earlier comparisons. Process, Thread, File/device, IoCompletion and
  TpWorkerFactory records retain type, rights and available object relations.
  Process VM rights are interpreted only for Process objects. A File handle is
  not called a device handle solely because it shares the monitor's file type
  index. Partial snapshots do not establish absence or duplication origin.
  Each owner's handle-value cursor resumes beyond 4096 candidates. Object
  relationship reads also have a 4096-attempt budget; a record interrupted by
  that budget is retried before the cursor advances. Owner and handle cursors
  are bound to process creation time. The continuation path avoids a second
  full process-list walk solely to enrich display names.
- **G18:** bounded region history joins TI local/remote memory-operation
  observations with effective protection snapshots. Event timestamps, receipt
  time, consumer delay and measured ingest gaps are retained. Generation changes,
  release/reallocation and out-of-order observations cannot manufacture an
  NX-to-RX verdict. Follow-up scans are rate limited; this remains sampled
  monitoring and cannot recover an event that was never delivered.
  Effective-protection snapshots retain the time interval around their actual
  memory query. They are compared within their own source history; delayed
  delivery cannot replace that interval with a later collection-completion time.
  Overlapping query intervals do not establish transition order. Observed
  release and allocation boundaries invalidate earlier region continuity.
  Tied TI wall-clock timestamps do not establish order either; an ambiguous
  protection value cannot become a confirmed baseline for the next transition.
- **G19:** a separate CLR runtime ETW subscription records method load/unload and
  rundown address ranges with runtime/module provenance. Deferred rundown
  requests are retried after throttling. Runtime membership does not suppress
  suspicious code and is not an allowlist. No universal Mono/V8/Wasm code-cache
  parser is claimed. Those engines require a supported provider or versioned
  engine integration before address provenance can be established.
- **G20:** TI session generation, trace-thread exit, loss counters, ring sequence
  gaps and recent receive activity are separate evidence. Inactive subscribers
  are still inspected for exit information. Idle is unknown, receiving is an
  observation, and cumulative historical receive count is not health proof.
  Ring eviction is distinguished from records actually missed by this consumer.

## Policy and platform trust

**G21:** automatic BYOVD inspection now rotates through loaded modules, checks
offline Authenticode evidence, and surfaces catalog age, hash-read failures and
partial coverage. The pathname file identity is compared around collection.
Automatic hashes read only the initial file length, with a 128-MiB byte budget
and a 250-ms budget checked between reads. Size or timestamp changes reject the
digest. Budget and generation failures are explicit coverage counters. A single
synchronous filesystem call is not forcibly timed out by this budget.
This does not bind the on-disk file to all resident image pages or exclude ABA
replacement. Filename/version hints remain lower-confidence catalog evidence.
Offline chain validation does not establish fresh revocation status or benign
behavior.

The platform collector records CI/HVCI raw flags, the vulnerable-driver blocklist
registry configuration and CiTool policy ID/version/IsEnforced observations.
CiTool is launched from the system directory without a shell, with hidden UI,
explicit handle inheritance, process cleanup, a 3-second budget, a 256-KiB output
cap and strict bounded JSON decoding. Registry configuration is not actual
enforcement. See Microsoft's [CI information contract](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation)
and [CiTool interface](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/citool-commands).

**G22:** TBS device data and a bounded boot-log digest are collected separately
from trust. A boot log is not a signed quote. The external-verdict verification
API validates a caller-pinned P-256 verifier key, device and AK binding, a fresh
32-byte nonce, quote digest, expiry and one-time consumption. Its signed payload
is versioned and length-prefixed. Self-test keys are public test fixtures and
are never used as a production trust anchor.

The default collector has no enrolled device, AK or configured verifier, so
`attestation.trusted=false`. A production deployment still needs enrollment,
TPM quote/PCR/certificate validation by its external verifier and transport.
The API verifies that verifier's signed verdict; it does not implement local
raw-quote validation. TBS has bounded data/retry limits but no caller timeout in
the synchronous API. See [TBS log retrieval](https://learn.microsoft.com/en-us/windows/win32/api/tbs/nf-tbs-tbsi_get_tcg_log).

DMA ACPI tables and DmaGuardOptIn are reported as configuration/inventory facts.
They do not set an enforcement-success flag. CPUID, timing and CR4 are likewise
same-OS observations. Neither local collector proves absence of pre-boot DMA or
an untrusted hypervisor. TPM attestation would not prove that all later runtime
memory stayed unchanged either.
BIOS and baseboard strings are retained as local inventory. No vendor firmware
advisory assessment is inferred when a corresponding data source is unconfigured.

## Validation and operating limits

Final Release validation completed on September 16, 2026, with binary version
0.0.32. The final manifest is `.build/kmon-implementation/verification.json`;
it records source, executable and log hashes. All 228 recorded source inputs
matched before the build and after the tests. Earlier checkpoint logs describe
earlier source revisions and do not replace this final evidence.

- The official Release build succeeded. Console tests passed 369/369, timeline
  tests 28/28, and remote-protocol tests 44/44: 441 reported cases, zero failures
  and no reported skips.
- The inert `/orphan-mapped-rx` and `/mapped-readonly` fixture processes both
  exited successfully. These runs establish fixture behavior, not live kernel
  detection by a loaded monitor.
- WDK native analysis succeeded with zero errors and 12 existing warnings:
  five raw DRIVER_OBJECT member-access warnings, six entry/dispatch annotation
  warnings and one nullable-page analysis warning after address preflight.
  No warning suppression was added. Diff whitespace checks and added C++ ASCII
  checks passed.
- A real driver-free `--self-test platform-query` collected CI/HVCI flags,
  blocklist configuration, firmware inventory, TPM device data and a 99,537-byte
  boot log. CiTool returned access denied (`0x80070005`) under the current token.
  The result correctly retained `local_collection_complete=false`, policy
  state unknown and `attestation.trusted=false`. This does not validate a
  successful elevated CiTool policy query.
- Repeated scoped reviews repaired the I01-I26 findings recorded in
  `.build/kmon-implementation/review-ledger.md`. Final independent reviews of
  the repaired hash, handle and temporal paths found no additional actionable
  defect in their reviewed scope. Compilation and regression results above
  include the final repairs.

The normal `!kmon` command automatically consumes these collectors. New
`sensor.coverage`, `sensor.ti`, `sensor.posture`, `hook.lifecycle`,
`memory.transition`, `memory.executable_unowned`, `process.execution`,
`process.provenance` and `driver.integrity` events retain evidence and uncertainty
in the monitor output/log. Platform posture is sampled at five-minute intervals.
There is no new blanket trusted-process or runtime exemption.

No driver load, protected game run, hostile sample execution, live kernel
positive, Windows-build matrix, Driver Verifier run or false-positive soak is
claimed by these tests. Supported private PDB layouts, access rights, process
churn and finite budgets still determine actual live coverage. Repeated review
and regression tests cannot prove absence of every possible bug.

The user-accepted exception for the experimental raw `!kmon iotrace` interposition
remains: safe unload is not guaranteed. The passive pending-completion collector
does not change that exception.

## Implementation entry points

- `user/KernelMonitor.cpp` integrates discovery, fair scheduling, process
  generations, entry/image checks, coverage events and follow-up work.
- `user/OrphanKernelPageScanner.cpp`, `PoolPeHunter.cpp`,
  `MapperRemnantScanner.cpp` and `KernelMonitorMapperPool.cpp` implement memory
  roots, interiors, executable-body evidence and continued traversal.
- `user/KmonUserEvidence.cpp`, `ProcessTriageScanner.cpp` and
  `UserModeHunter.cpp` implement contexts, callback/runtime/file provenance and
  their guarded consumers.
- `user/KmonTemporalEvidence.cpp` holds interval, lifetime and cursor-retention
  rules. `HandleTableScanner.cpp` holds typed relationships and handle budgets.
- `user/CallbackScanner.cpp`, `DpcTimerScanner.cpp`, `WnfScanner.cpp`,
  `WfpCalloutScanner.cpp`, `MinifilterAttachmentScanner.cpp` and
  `PendingIrpScanner.cpp` collect callback and registration observations.
- `user/ThreatIntelSubscriber.cpp` and `EtwScanner.cpp` retain TI consumer and
  cross-view state. `ByovdScanner.cpp`, `DmaPostureScanner.cpp` and
  `KmonPlatformEvidence.cpp` retain file, policy and platform evidence scopes.
- `driver/Driver.cpp` preserves creator PID/TID in process creation telemetry;
  `user/main.cpp` registers the fixtures and the local platform query.
