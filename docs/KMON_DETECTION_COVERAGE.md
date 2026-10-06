# !kmon detection coverage and September 2026 hardening

Historical baseline: the later [G01-G22/B01 implementation contract](KMON_IMPLEMENTATION_2026-09-16.md)
supersedes this document for changed collectors and remaining-gap descriptions.
The validation below belongs to the earlier source snapshot.

Research cutoff: 2026-09-16. The monitor reports observed inconsistencies and
execution candidates. A quiet pass only applies to the views that were actually
read within that pass's budgets. It does not establish that a machine is clean.

Follow-up fixes and the explicit raw I/O hook unload exception are documented
in [the adversarial review](KMON_ADVERSARIAL_REVIEW.md).

## What changed

### Kernel mappings, pool code, and mapper residue

`OrphanKernelPageScanner` now handles the LA57 kernel floor correctly, retains
supervisor leaves below user-accessible parent entries, and excludes the correct
512 GB LA48 self-map window. Large executable leaves have loaded-module spans
subtracted instead of discarding a whole 2 MB or 1 GB mapping after one overlap.
Adjacent big-pool allocations keep their separate identities.

This LA57 repair applies to the orphan-page/PFN scanner. Other pointer
classifiers still use LA48 kernel floors; the full monitor has not been
validated on a live LA57 host.

PFN candidates must translate back to the claimed physical page and have
effective executable permissions through the complete parent chain. Failed
table reads, PFN reads, translation checks, and selected-window revalidation
clear the relevant completeness flag. Missing or malformed module ranges cannot
prove that a target is outside all modules.

`!kmon` requests 16 KB body windows, retaining at most 128 during a mapper watch
or 64 while idle. Selection interleaves one window from each discovered region
before revisiting larger regions, then resumes at the saved logical offset on
later passes. This avoids repeatedly checking only allocation prefixes and
avoids letting one huge mapping monopolize the selected windows. Enumeration
still has table/PFN budgets and a 65,536 retained-region cap; window rotation
does not repair an area never reached by enumeration. Standalone `!kpage`
retains full-region output unless its caller opts into window mode.
Every page start in a selected body window is checked for a PE header; the
reported `peAddress` preserves its actual position inside the window. Custom
body windows are clamped to 64 KB so page probing remains bounded.

The shared mapper decoder accepts validated RIP-relative import slots and
matching `mov rax..r15, imm64; jmp/call` register pairs, with an optional single
NOP. It rejects unrelated intervening bytes, mismatched REX registers, and
overflowing relative targets. At most 32 distinct residual branch targets per
body are checked for mapping and effective execution permission. All targets in
the bounded body are collected, sorted and deduplicated; a per-region cursor
resumes target validation on later visits. The cursor cache holds 4096 regions
and reports eviction as lost continuation coverage. Exceeding the target budget
is partial coverage. Unreadable bytes are not evidence. Short
successful body/header reads retain partial-coverage markers while preserving
verified positive evidence from the readable prefix. Pool PE read failures are
now visible as coverage events and in JSON.

Big-pool parsers validate returned bytes and declared counts before reserving
or indexing memory. A partial table cannot be used to claim an allocation is
absent. Mapper bookkeeping no longer interprets unreadable names, timestamps,
or slots as successful reads of wiped values.

These changes strengthen `pool.hidden`, `mapper.stub`, and
`driver.mapped_residue`. They do not make import-free code, NX-at-rest payloads,
or code that only executes between sampling passes universally detectable.

### Callbacks and kernel execution

The hot-entry inline scanner read bytes successfully but did not mark the
production input `PrologueKnown`, suppressing its verdicts. Production and
regression tests now share the byte-to-input construction. The decoder handles
CET ENDBR64/NOP prefixes, short branches, and immediate branches using R8-R15.

`ScanCallbackInlineTargets` supplements callback-pointer ownership checks.
It samples up to 64 owned callback entry points per pass, revisits each batch
before advancing its cursor, and follows
up to four supported static branch hops, including an in-image code cave and
RIP-relative pointer slot. A terminal target outside a complete loaded-module
view produces `hook.inline layer=callback_redirect` only after two matching
observations. A read failure, changed target, disappeared callback, cycle, or
unresolved transfer cannot inherit a previous confirmation. A normal tail call
into another loaded module is a negative control.
Confirmation capacity is reserved for a whole batch before sampling, preventing
stable populations larger than the cache from starving all second observations.
Capacity resets are reported and retire the corresponding event identities.
Surviving pending entries are revisited after registration changes, and the last
batch address is retained until the next fresh inventory to preserve progress.
Failed attempts, including caught C++ exceptions, clear pending confirmations.

Notify slots, Ob lists, and registry lists distinguish malformed links from
unreadable data. Cycles and broken backlinks no longer look like completed
empty scans. Unreadable records generate coverage notes, not poisoned-pointer
allegations. Notify record identity includes its slot address.

Modern `_KDPC_DATA.DpcList` / `_KDPC_LIST.ListHead` singly linked DPC queues are
resolved from PDB fields alongside the legacy doubly linked layout. The walker
validates NULL termination, tail identity, read completion, cycles, and limits.
Private symbol changes can still make a queue unavailable. Modern timer roots
and work-item queues are not fully covered by this repair.

Kernel thread starts use `_ETHREAD.StartAddress` and, when available,
`_ETHREAD.Win32StartAddress`. Toolhelp completeness requires an actual
`ERROR_NO_MORE_FILES` termination. Comparisons include owning PID, TID, and
kernel object identity; stable `ActiveThreads` values bracket the list walk.
An unavailable or malformed module inventory withholds unbacked-start conclusions while
independent thread-list comparisons remain possible. Failed passes and monitor
restart clear confirmation state, preventing unrelated generations from
combining into two strikes.

The thread report budget counts newly claimed events, so the same 16 deduplicated
findings cannot permanently hide a seventeenth thread or later DKOM finding.
Event keys include kernel object identity, with start address included for
unbacked-start events.

HAL, ETW, hive, and KDBG module lookups returned pointers into temporary vectors
from `SymbolEngine::Modules()`. They now retain owned module values, with
lifetime regression controls for the hive/KDBG helpers. Input-stack driver
selection uses exact names, and incomplete stack/NMI views remain explicit.

### User process identity and hidden executable memory

PEB and loader agreement is compared independently with
`EPROCESS.SectionBaseAddress`. A pair of matching forged user structures no
longer determines the only main-image address inspected.

Executable `MEM_MAPPED` sections are included alongside private code and orphan
PEs. Across scanned hosts, the new `thread_private_exec` and
`thread_mapped_exec` layers require a complete module inventory,
a live thread start within the exact region, matching process creation time,
and readable bytes at that start. Entropy remains a candidate heuristic;
packed data, JIT engines, overlays, and instrumentation need operational
negative controls before treating these events as malware.

Process materialization is capped at 4,096 entries; entries beyond that snapshot
cap are not covered by continuation. Deep process selection is capped at 1,024
hosts. When saturated, 768 places are
reserved for higher-priority hosts and 256 for other hosts; both groups rotate.
Each process resumes its virtual-memory walk using `(PID, CreateTime)` after
the 4,096-region or four-finding budget. Thread corroboration uses one lazy
Toolhelp inventory per pass (65,536 entries), at most 64 thread-start queries
per host, and at most 1,024 queries per pass. Quotas are assigned to selected
hosts before queries begin, and per-generation TID continuation advances only
when a query is attempted. Each sampled thread start is queried directly for
its memory region, independently of the sequential VM cursor. This prevents
process, thread, and VAD slices from repeatedly missing one another. These
limits are reported as partial coverage, not absence of hidden memory. Threads
beyond the global inventory cap are likewise not reached by the TID cursor.

The separate bounded user-inspection sweep now rotates up to four explicit
`/pid` or `/name` watches first within six priority slots, followed by two
background slots. Explicit watches, other priority hosts, and background hosts
have independent cursors. This 2026-10-06 change preserves the total eight-host
budget; it does not guarantee a scan deadline.

A PE allocation is excluded from orphan-image leads only when the current
mapping is `MEM_IMAGE`, the loader inventory is complete, and both the
allocation base and current backing path match the loader entry exactly.
Same-basename paths on another volume, private/mapped PEs, and incomplete
inventories retain their investigation path. Loaded-image byte and execution
checks remain independent. The [live-host record](LIVE_HOST_VALIDATION_20261006.md)
includes the ordinary-DLL negative control and the remaining fixture limits.

`GetFileAttributes` only supports a ghost-file allegation for file/path-not-found
errors. Access denied remains unknown. Failure to query a mapped filename is
not evidence of absent file backing. CoW sampling deduplicates pages and checks
that each page belongs to the same executable `MEM_IMAGE` allocation. A failed
memory read no longer substitutes zero bytes or an entropy verdict. VAD VPN
high-field read failures and invalid/overflowing address ranges are rejected.
Hidden-process completeness includes both before/after SPI and Toolhelp calls.

Inbox path checks are anchored at the path root; embedded `Windows\\System32`
directories, traversal, alternate streams, and an `explorer.exe` directory do
not qualify. A basename such as `csrss.exe` alone no longer suppresses WriteVM
classification. Path classes are lexical policy, not signer or file identity:
other volumes, hard links, and reparse points need separate provenance evidence.

### Monitor lifecycle

Timeline callback registration/removal ran while a fast mutex raised IRQL to
APC_LEVEL even though these callback APIs require PASSIVE_LEVEL. The control
path now uses a kernel mutex and enforces PASSIVE_LEVEL. Ring reset clears
publication metadata under the spin lock; it no longer zeros the entire large
buffer at DISPATCH_LEVEL. Every newly exposed event slot is fully overwritten
before its count is published. The IOCTL ABI is unchanged.

## Validation and how to reproduce it

Build with `tools/build.ps1 -Configuration Release`, then run:

```powershell
.\x64\Release\KnLiveDbg.exe --self-test console
.\x64\Release\KnLiveDbg.exe --self-test timeline
.\x64\Release\KnLiveDbg.exe --self-test remote-protocol
```

The console suite contains independent gates for `kmon-inline-runtime-regression`,
`kmon-lifecycle-regression`, `pool-pe-window-regression`,
`kmon-mapper-stub-regression`, `kmon-thread-classification`,
`kmon-user-memory-regression`, `kmon-dpc-list-regression`,
`kmon-mapped-section-artifact`, mapper residue, orphan pages, VAD traversal,
hidden-process views, callback parsing, hive ownership, and KDBG decoding.
The mapped-section artifact creates an actual anonymous section, samples its
inert RX bytes, then verifies that the same bytes under read-only protection
do not qualify. It never executes the bytes.

The final September 16 adversarial-review run passed the Release solution build, 357 console
checks, 28 timeline checks, and 44 remote-protocol checks. WDK native code
analysis completed with zero errors and 12 warnings: five intentional raw
`DRIVER_OBJECT` inspection warnings, six dispatch/DriverEntry annotation
warnings, and one potential-null warning in resident-range preflight. The last
site is preceded by canonical-system-range validation; the analyzer does not
infer that helper's range constraint. This is not a zero-warning analysis claim.

No test driver or protected game was loaded for this run. Actual kernel callback
redirection, mapper positives, Windows build compatibility, Driver Verifier,
and game/anti-cheat/JIT false-positive soak remain unverified. Test signing
produced a signer certificate, but host Authenticode checking returned
`UnknownError`; build success does not establish driver-load trust.
Use [the fixture guide](KMON_TEST_TARGET.md) and
[the manual checklist](MANUAL_TEST_CHECKLIST.md) for the separate live gate.

## Known detection gaps

1. A kernel attacker can alter several in-OS views together. Module/list/PTE
   agreement from this sensor is not an external ground truth. EPT deception,
   VTL isolation, DMA/firmware mutation, and a compromised collector need a
   separate trusted observation source.
2. Polling can miss short-lived mappings, transient callback changes, NX/RX
   toggling, and code erased between scans. Finite budgets can also delay
   coverage while inventories continually change.
3. Static branch following does not establish semantic integrity of an entire
   function. Same-image patches, no-op callbacks, dynamic indirect dispatch,
   obfuscated/import-free code, and register-only continuations may escape.
   Import slots outside the selected body window may remain unresolved.
4. Ex callback objects, notification-enable masks, all modern timer/work-item
   roots, and removal of an already absent callback need additional exact-layout
   collectors or a trustworthy baseline. This change does not claim them.
5. User thread-start evidence misses hijacked existing threads, APC/thread-pool
   execution that retains a normal start address, and fully spoofed stacks.
   Protected processes and unreadable pages retain coverage gaps.
6. Signed drivers and executable private/mapped regions can be legitimate.
   Signatures, path names, entropy, pool tags, and import counts are evidence
   features, not standalone malware labels. No precision/recall percentage or
   universal detection claim is supported by the local test suite.

## Research used

- Samuel Tulach, 2024-07-12, [Detecting manually mapped drivers](https://tulach.cc/detecting-manually-mapped-drivers/).
  Compiler-generated import wrappers motivate header-independent scanning;
  compiler variation and non-image executable code limit signature-only claims.
- Microsoft, [No-Execute Nonpaged Pool](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/no-execute-nonpaged-pool).
  Nonpaged residency alone does not imply executable memory; effective page
  permissions are checked separately.
- Intel, [5-Level Paging and 5-Level EPT](https://cdrdv2-public.intel.com/671442/5-level-paging-white-paper.pdf).
  Canonical address widths and hierarchy depth must match the actual paging mode.
- Ori Damari, [Dumping DPC Queues](https://repnz.github.io/posts/practical-reverse-engineering/dumping-dpc-queues/).
  The modern DPC queue representation differs from legacy LIST_ENTRY assumptions.
- Elastic, 2025-06-12, [Call Stacks: No More Free Passes for Malware](https://www.elastic.co/security-labs/threat-command/call-stacks-no-more-free-passes-for-malware).
  Callback/proxy execution and stack manipulation motivate corroboration beyond
  process names and initial thread entry points.
- Elastic, 2026-03-19, [SILENTCONNECT delivers ScreenConnect](https://www.elastic.co/security-labs/threat-command/silentconnect-delivers-screenconnect).
  Observed PEB masquerading reinforces checking independent image identity.
- ESET, 2026-03-19, [EDR killers explained: Beyond the drivers](https://www.welivesecurity.com/en/eset-research/edr-killers-explained-beyond-the-drivers/).
  Disabling security components involves more than one signed-driver list.
- Kaspersky, 2026-08-14, [CoolClient backdoor goes deeper: HoneyMyte adds Windows kernel rootkit](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028/).
  Recent rootkit activity combines process/module hiding with callback and
  injection mechanisms, supporting multi-view detection rather than names.
- Microsoft, [VirtualQueryEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex)
  and [NtQueryInformationThread](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationthread).
  CoW image pages retain their mapping type; working-set sharing and thread
  start queries are separate observations.
- Microsoft, [ExAcquireFastMutex](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exacquirefastmutex)
  and [PsSetCreateProcessNotifyRoutineEx](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex).
  These document the APC_LEVEL transition and PASSIVE_LEVEL callback contract.
