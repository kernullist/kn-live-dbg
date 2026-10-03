# !kmon adversarial review, 2026-09-16

This review covers the uncommitted detection hardening based on
`b5804bcf873a3218e00bc15d2835cab1812aa5e3`, its production callers, and regression
tests. Findings require a concrete input or execution sequence. Reviewers rotate
across kernel memory, user memory, callbacks, and lifecycle code so that fixes
receive a separate review.

The final frozen-source cross-review found no additional reproducible actionable
defect in the reviewed paths after R01-R26 were repaired. This is the completion
gate for this review, subject to the explicit unload exception and validation
limits below.

## Reproduced defects and repairs

### Inventory and bounded scans

- A failed forced module refresh could reuse an older nonempty list as current
  evidence. Refresh attempts now have synchronized success/failure state; failed
  refreshes cannot establish that a pointer is unbacked.
- Stable pool PE hits consumed every pass's hit limit, leaving later rows
  unvisited. The monitor now resumes at the next raw row and excludes loaded
  image ranges before applying the hit limit. Standalone scan defaults remain.
- Invalid big-pool ranges and overlapping/duplicate module or pool ranges could
  make a predecessor search falsely report absence. Validate the entire returned
  inventory before selection. Adjacent half-open ranges are valid.
- Reserved large-page and upper-level paging bits could pass executable-mapping
  validation even though the CPU would fault. A common level-specific validator
  is used by kernel translation, page probes and orphan scans; PAT and NX bits
  retain their distinct meanings.
- A 16 KB sample only checked its first page for a PE header. It now probes
  every page start in the selected window and records the actual header address.
  Partial reads still mark coverage incomplete even when another page provides
  a verified positive. Windows are bounded to 64 KB; the monitor requests 16 KB.
- Only the first 32 mapper branch targets were retained, so target 33 was never
  validated. Keep distinct targets from the bounded body and rotate the actual
  32-target validation window. Cache eviction is exposed as partial coverage.

### User process and memory evidence

- Partial FILE_OBJECT name reads could become apparent executable-path
  disagreement. Require exact UNICODE_STRING header/body reads, valid lengths,
  and a valid buffer range; otherwise keep the name unknown.
- Toolhelp termination with ERROR_SUCCESS could be treated as a complete process
  inventory. Only ERROR_NO_MORE_FILES proves normal termination.
- Unknown creation times and partial inventories discarded valid VM/TID scan
  continuations. Preserve unknown generations, prune established replacements
  or absence from a complete inventory, and expose cursor-capacity loss.
- A module snapshot could precede a new process handle for a reused PID when
  initial identity was unknown. Pin the process before collecting the snapshot,
  require a known matching creation time before/after collection, and discard
  stale path metadata. Process and snapshot handles have scope-bound ownership,
  including deferred and exceptional paths. Unavailable identity is a coverage
  gap. The object/PID
  lifetime rule is documented by [Microsoft](https://devblogs.microsoft.com/oldnewthing/20110107-00/?p=11803).
- VAD metadata and PE probe read failures did not reach coverage reporting.
  Count them without deleting already observed VAD records. Private
  MMVAD_SHORT records no longer read the section-backed MMVAD extension.
- Inflated writable loader ranges could exclude private or anonymous section
  code before a memory query. Check the actual memory type and allocation base
  rather than treating an arbitrary loader interval as ownership evidence.
- An instrumentation callback absent from a partial VAD list could be called
  unbacked. Absence now requires a complete untruncated view; a covering row
  requires known ownership metadata, and conflicting overlaps remain unknown.

### Callbacks and device stacks

- Failed scan attempts retained callback/hot-entry confirmation strikes. Failed
  attempts now invalidate pending confirmations. Event identity includes the
  observed hook destination, and resolved/changed observations retire old keys.
- Clearing the callback confirmation cache at capacity could keep a stable
  population above 4096 entries permanently below two observations. Repeat each
  64-entry batch before advancing, identify pending entries by address across
  registration changes, and reserve the whole batch before sampling. Retired
  history and capacity loss are explicit. Regressions cover 8192 candidates,
  exact-capacity and mid-batch boundaries, failures, and registration changes.
- Repeated replacement of one low-address registration exposed a defect in the
  first repair: restarting a partially missing batch held the cursor forever.
  The follow-up keeps surviving pending entries and preserves the previous
  batch's final address until the next fresh inventory. Regressions change one
  entry and alternate two entire prefix populations while requiring eventual
  confirmation of stable later entries. Saving an ordinal from the prior view
  does not satisfy this contract.
- An exception caught by the worker could preserve callback confirmations
  across a failed attempt. Attempt cleanup covers the outer callback collector
  as well as entry sampling; unwinding clears confirmation and dedup state
  without constructing replacement strings.
- The related hot-entry guard started after a possible allocation and allocated
  during destruction. It now guards the whole attempt and uses allocation-free
  failure cleanup. Successful scans still retire changed or resolved identities.
- Duplicate hot-entry events consumed the output cap and hid later findings.
  Only newly claimed events consume that budget.
  The same correction covers module inventory, anonymous driver objects, input
  stacks, SSDT, IDT, WFP, minifilters and data-pointer reports. Already reported
  candidates do not inflate the deferred-event count.
- Partial prologues could clear coverage warnings. A readable positive prefix
  remains useful evidence, while the incomplete sample stays visible.
- Notify unregister/replacement during sampling could appear to be a poisoned
  callback block. Re-read the slot after sampling and require the same decoded
  block; fast-reference count changes alone do not invalidate it.
- Device-chain read failures and limits could masquerade as NULL termination.
  Walkers require successful linkage reads and a verified NULL end and propagate
  partial/cycle/cap warnings to input-stack coverage.

### Monitor lifecycle

- Stop cleared its borrowed device before disarming I/O tracing and ignored the
  cleanup result. Stop now joins the worker, performs cleanup with dependencies
  still available, and preserves retry state on failure.
- A concurrent Start could reset worker state while the old worker was still
  running. Lifecycle operations and public watch mutations now serialize across
  the join boundary. A regression exercises the actual Start/Stop methods.
- Logging cleanup captured its PID set before the worker finished. It now
  captures after join. Process exit stops collectors before closing their device
  and explicitly detaches borrowed dependencies during final shutdown.

## Explicit scope exception

The user explicitly accepted that safe unload of the existing experimental raw
IRP interposition need not be guaranteed. No permanent driver pin, reboot
requirement, ARM disablement or unbounded unload wait is introduced.

The pre-existing dispatch-counter design still cannot synchronize a caller that
has fetched a hook address but has not entered it, or an epilogue after the last
counter decrement. This review does not label that design safe. Normal device
references and outstanding IRPs protect dispatches owned by the driver stack;
they do not provide that contract for a foreign raw function-pointer hook.
See Microsoft's [Unload Routine Environment](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/unload-routine-environment).

## Validation evidence

This is the earlier R01-R26 review. The subsequent implementation and its
validation are recorded in [the G01-G22/B01 contract](KMON_IMPLEMENTATION_2026-09-16.md).

The final Release solution build passed at version 0.0.32. Console checks passed
357/357, timeline checks 28/28, and remote protocol checks 44/44, with no skipped
checks. The inert mapped-RX and mapped-read-only fixture processes both exited
0. Native WDK analysis completed with 0 errors and 12 warnings: five raw
DRIVER_OBJECT inspection warnings, six entry/dispatch annotation warnings, and
one potential-null preflight warning whose helper validates the system range.
These warnings are retained in the evidence, not treated as a zero-warning run.

Review rounds, final logs, source hashes and artifact hashes are retained in
`.build/kmon-adversarial/validation.md` and `verification.json`. Intermediate
failed builds are retained as well. Earlier `.build/kmon-hardening/` logs
describe the preceding revision and are not substituted for the final run.

No driver is loaded and no protected game/sample is run for these checks. Live
Driver Verifier, kernel positives and false-positive soak remain separate from
synthetic regression, user-mode fixtures and WDK build/static-analysis evidence.
Finite review does not prove that every possible defect is absent.
Root page-table/PFN enumeration budgets, unresolvable symbols, cursor-cache
capacity, sampling between mutations and platform-specific paging capabilities
remain explicit coverage limits described in the detection coverage document.
