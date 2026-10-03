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
  The Kmon fixture rejects malformed or overflowing `/seconds` values before
  creating a child. Only an explicit zero requests an indefinite hold; the
  maximum finite value is 4,294,967 seconds.

## Validation

The later local review validated the assembled changes in both Debug and
Release with native code analysis. Each binary passed 544 self-test checks
with zero failures; analysis warnings remain. An independent JSON corpus
covered 20,012 cases. Loopback WinHTTP checks covered ten body/deadline cases
and ten redirects, with no redirected request reaching the destination.
These results are retained in
`.build/adversarial-review-20261003/verification.json` and apply to the
pre-integration source hashes recorded there.

The 2026-10-04 integration uses main at `b42afbd` and preserves its executable
verification, process layout monitoring, asynchronous capture, and command
validation. Semantic merge checks corrected 64-bit handle continuation,
repeat-observation state, independent scan cursors, TI session consumption,
and an ingestion-gap statistic shared by the collector and analysis worker.
Both TI capture paths require the event's target process generation to match
the capture owner. Alternate-root captures retain the CR3, process generation,
and page-sized mapping checks across the queue boundary.

The combined Debug and Release solution builds passed with native code
analysis; warnings remain. Each binary passed 3,069 reported self-test checks
and nine live loopback MCP HTTP checks. The standalone Kmon core/hunting,
analyst, and process-layout gates passed in Debug and in Release with ASan.
These include
11,326 hunting, 54 page-coverage, 49 false-positive fixture, 6,560 analyst, and
105,075 layout checks per applicable run. Debug and Release with ASan passed
275,002 parser and 25,954 completion checks. The command integration corpus passed
2,336 checks across 261 entries. Native manifest generation accepted the exact
binary/PDB pair and rejected changed images, malformed input, and a different PDB.
Counts describe fixture assertions, not independent measurements of real-world
detection quality. After the hold-time fix, both fixture builds and both
551-check console suites passed again. The 14 hold-time cases passed through
the readiness gate and under Windows PowerShell 5.1; inert mapped RX and
read-only fixture startup also passed without executing their mapped bytes.

The integrated JSON oracle repeated 20,012 cases without disagreement, and
the ten HTTP body/deadline cases and ten cross-port redirects passed again.
All 43 tool scripts parsed under Windows PowerShell 5.1. The current source
and artifact hashes are retained locally in
`.build/adversarial-review-20261003/integration-verification.json`.

The pre-integration readiness gate rejected the old research ledger dated
2026-07-30. Integrating main supplied its actual 2026-09-20 research update;
the freshness and `validate-hunt-readiness -SkipSmoke` gates now pass.
No freshness threshold or evidence date was relaxed. Repeated WinHTTP session
creation retained Event handles on this host, including in an independent
synchronous client with closed handles and awaited unload notifications.
Application completion events and handle-close errors did not account for
that growth; its host-level cause remains unresolved.

## 2026-10-04 repository follow-up

The next review started from the published `9bd5b94` main. It reconciled the
285 source/build inputs in the integration manifest, revisited failure paths
across the driver, scanners, CLI, transports, persistence and fixture tools,
and repeated review after each repair. It found additional defects outside
the earlier Kmon integration work:

- A raw dump crossing `UINT64_MAX` wrapped into low addresses and reported a
  complete transfer. The shared range reader now rejects it before any read
  or output-file truncation, including when zero-fill is requested.
- Cloak configuration accepted cleanup paths outside its session directory.
  Validation now binds the identity, service/device names and artifact paths,
  rejects malformed or duplicate fields, and bounds the file to 64 KiB.
  Relative configuration arguments and UNC original EXE paths remain usable;
  copied artifacts require local drive paths. A partial build records its
  owned directory before copying, and an existing directory is not reused.
  Startup and cleanup check an existing service's image before changing it.
  Failed stops and artifact removal propagate errors. Missing or conflicting
  cloak arguments no longer fall through into ordinary startup.
- TI export ignored `WriteFile` failure. A fault-injected `ERROR_DISK_FULL`
  returned success before the fix and failure afterward. Partial writes are
  completed, zero progress fails, and flush/close errors are checked. Snapshot
  and cloak text writers also check buffered errors when closing their streams.
- Remote sends could block past the receive deadline when the peer stopped
  reading. Nonblocking sends now share a frame deadline and failed frames
  shut down the connection. The local backpressure fixture returned after
  219 ms with a 200 ms deadline. Both stdout and stderr are chunked at 64 KiB
  each so control-byte JSON escaping stays within the frame budget; oversized
  streams retain a bounded UTF-8 prefix and an explicit truncation marker.
- Firewall helpers failed to balance `CoInitializeEx` returning `S_FALSE`.
  A nested-apartment repro could not initialize MTA after the caller released
  its STA reference; it succeeds after the fix. Rule property failures now
  prevent publication, and the replacement is configured before removing an
  existing rule. The regression uses an unpublished COM rule object and does
  not change firewall policy.

Final Debug and Release builds with native analysis passed; existing warnings
remain. Each final executable passed 3,075 reported self-test checks and nine
loopback MCP HTTP checks, including the new cloak, firewall, backpressure and
stdout/stderr framing regressions. Both missing cloak-path CLI cases exited
with usage status 2 before startup. The dump/cloak boundary oracle also passed
with ASan.

Release ASan gates passed for Kmon core/hunting (11,326 hunting, 54 page and
49 false-positive fixture checks), analyst features (6,560), process layout
(105,075), command parsing (275,002), and completion (25,954). The analyst run
reported 45 unavailable worker-handle queries out of 114 attempted; that is a
coverage limit, not a successful query. The final executable command corpus
passed 2,336 checks across 261 entries. Readiness with `-SkipSmoke`, native
manifest/PDB mismatch controls, and parsing all 43 scripts under Windows
PowerShell 5.1 passed. All 285 frozen source/build hashes still matched after
validation. A fresh review of the final changes found no additional actionable
defect within this scope.

Reproduction logs and the final source/artifact/test manifest are retained in
`.build/adversarial-review-20261004/`. Live kernel and detection-quality limits
below still apply. These fixes do not establish safety against a privileged
process concurrently replacing SCM entries or filesystem namespace components.

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

Kmon's production slice comparison now uses main's qualified executable-image
verifier, including disk relocation metadata and mutable-byte masks. Its disk
identity checks and repeated live reads bound the observation; they do not
establish an immutable atomic snapshot across a full scan. The standalone
integrity path holds its file handle but does not lock out concurrent writes
by another process. Asynchronous capture preserves bytes when the capture
worker reads them. An earlier kernel-object observation does not pin that
object until capture, and cannot establish that it survived unchanged.

Experimental raw `!kmon iotrace` retains the user-accepted exception: safe unload
is not guaranteed. This review does not change that contract. A final scoped
review with no additional actionable finding is not proof that all possible bugs
have been eliminated.
