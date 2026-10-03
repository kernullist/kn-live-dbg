# kmon follow-up adversarial review

This review starts from the integrated 0.0.32 implementation, including its
uncommitted changes. The baseline has 228 hashed source inputs and matches the
previous implementation manifest. Previous R01-R26 and I01-I26 results describe
earlier source states; the new findings below belong to this follow-up review.
The original review did not include publication. On 2026-10-04, the user
authorized integrating these dependencies with the current main branch,
revalidating the result, and committing and pushing the integrated changes.

## Repairs and regression scope

The local finding ledger is `.build/kmon-review-20260916/review-ledger.md`.
Production helpers are exercised by the console self-test; fixtures use inert
memory, synthetic file data, and injected readers rather than a loaded driver.

- **Fair traversal:** DPC/timer/work-item queues, pending IRP lists, WNF process and
  subscription lists, orphan-page body windows, and mapper branch targets retain
  their continuation. Regressions include populations above the per-pass cap,
  alternating earlier entries, removed anchors, link changes and owner changes.
  An incomplete window stays incomplete; continuing does not claim an atomic
  whole-list observation or eliminate object address reuse.
- **Disk comparison:** kmon no longer reads replacement relocation metadata from
  the image being inspected. Disk RVA reads follow raw section boundaries and
  reject incomplete results. Standalone integrity comparison validates complete
  bounded relocation directories before normalization, handles fixups crossing
  a page boundary, and clears a matched result when another page fails. Its
  comparison layout must also be verified against the open disk image.
  A preferred PE base of zero still requires relocation when the loaded base
  differs; it cannot disable normalization.
- **ETW decoding:** stack MatchId bytes are excluded from frame addresses, and
  scalar reads validate their length and event pointer width. Both fixes are
  based on the SDK structure contract. Microsoft's
  [stack extension layout](https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_extended_item_stack_trace64)
  explicitly places MatchId before Address.
  Process names are tied to the current process generation and event time;
  PID reuse cannot preserve an old cached name or name-based watch promotion.
  Classification preserves an unknown collected name instead of filling it
  from a later process that has reused the PID.
  Credscan windows carry both validated process generations and use event time,
  so backlog replay cannot compress hours of reads into a 60-second burst.
- **CLR provenance:** session health queries replace the unused logfile loss
  field. Loss, counter discontinuity, decode failure, or an unavailable health
  query invalidates retained ranges. New epochs and timestamp fences prevent
  queued old events from rebuilding the invalidated view; rundown is retried.
  The monitor retries startup and recovers after consumer exit. The relevant
  contracts are [EVENT_TRACE_LOGFILEW](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_logfilew)
  and [EVENT_TRACE_PROPERTIES](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties).
  Unknown unloads and equal-time load/unload conflicts retain bounded ordering
  evidence instead of reviving an unloaded method as positive provenance.
- **User evidence:** a failed memory query leaves ownership unknown. Actual APC
  dispatch routines and speculative argument candidates have separate evidence
  kinds, and candidates cannot become confirmed execution findings. Queued APC
  records are published only after their content and list links are revalidated.
- **Reliability:** fragmented interval eviction sorts once instead of repeatedly
  scanning all entries. Future or unavailable BYOVD catalog timestamps cannot
  appear fresh. NMI callback positives and execution correlation require the
  exact PDB layout; guessed offsets only support diagnostic observations.
  COM apartment initialization now has scoped cleanup across exceptions.
  Unloaded-driver page-probe uncertainty has its own counter and coverage event,
  separate from unloaded-list completeness.

## Validation

The later local review validated the assembled changes in both Debug and
Release with native code analysis. Each binary passed 544 self-test checks
with zero failures; analysis warnings remain. An independent JSON corpus
covered 20,012 cases. Loopback WinHTTP checks covered ten body/deadline cases
and ten redirects, with no redirected request reaching the destination.
These results are retained in
`.build/adversarial-review-20261003/verification.json` and apply to the
pre-integration source hashes recorded there. Validation of the combined
upstream and local changes must be recorded separately after integration.

The local readiness gate rejected the old research ledger dated 2026-07-30.
No freshness threshold or evidence date was relaxed. Repeated WinHTTP session
creation retained Event handles on this host, including in an independent
synchronous client with closed handles and awaited unload notifications.
Application completion events and handle-close errors did not account for
that growth; its host-level cause remains unresolved.

## Remaining limits

No live kernel positive, Driver Verifier run, Windows/private-PDB compatibility
matrix, protected game, hostile sample, or false-positive soak is claimed.
Synthetic tests establish the repaired helper contracts, not coverage against
every implementation of a hiding technique.

CLR health is polled periodically; event loss is not detected synchronously
  with the lost event. Live session restart/loss recovery needs a separate runtime
test. Access failures, unsupported layouts, churn, finite budgets, and cache
eviction remain coverage limits. Same-OS observations do not establish absence
of an untrusted hypervisor or pre-boot DMA.
The existing 16-entry APC queue and 256-node NMI prefix limits remain partial
surfaces; this review does not add continuation to those two inventories.

The kmon disk relocation reader still treats header-resident directories as
unsupported. Its chunked pathname reads do not establish an immutable single
file generation. Those cases must not be described as a trusted atomic disk
snapshot. The standalone integrity path holds its file handle but does not lock
out concurrent writes by another process.

Experimental raw `!kmon iotrace` retains the user-accepted exception: safe unload
is not guaranteed. This review does not change that contract. A final scoped
review with no additional actionable finding is not proof that all possible bugs
have been eliminated.
