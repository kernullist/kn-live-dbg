# Remaining work

Scope: the main revision identified in the [documentation index](README.md);
the latest published release is v0.0.36. Implemented features are described in the
[command guide](COMMAND_REFERENCE.md), [architecture](ARCHITECTURE.md), and
[KMON coverage](KMON_DETECTION_COVERAGE.md). Completed implementation plans and
per-commit work logs have been removed from this roadmap.

## Retained investigation path

The implemented investigation path connects admitted hunting receipts to
retained raw bytes, identity, slots and coverage. The offline reader can query
those publications after the recent index expires or the monitor exits, then
explain the stored facts and missing evidence. This covers the declared read
sets of admitted references, not every scanner or every observation.

| Implemented contract | Acceptance evidence |
| --- | --- |
| Scoped queries | Filter each endpoint before the result limit, retain the other endpoint of a matching relation, expose exact retained-scope counts and bounded continuation; test targets beyond 256 global results, paging, and stale cursors |
| Identity and time | Separate a canonical process key from optional identity assertions; keep delayed receipts without rolling the current view backward; test PID/address reuse and conflicting optional fields |
| Durable evidence | Commit bounded, versioned bundles containing raw spans, validity and acquisition receipts; report missing/corrupt chunks and interrupted publication without claiming complete evidence |
| Offline investigation | Query retained history and replay the available original evidence without opening a live device; explain each finding's evidence and unfulfilled requirements after expiry, eviction and restart |

Keep the existing command and observation import contracts through adapters.
Current-state freshness, historical retention, byte verification, execution
observation and actor attribution are separate claims. Hash equality identifies
stored bytes; it does not establish that the original collector was trustworthy.
Raw captures, local paths and private symbols are local investigation artifacts,
not inputs to source commits or automatic public exports.

Trace/VMI adapters, broad thread-pool layouts, approved reference distribution,
encrypted remote transport and independent corpus comparisons remain separate
work packages below. A local fixture or replay pass does not establish those
capabilities or a comparative detection rate.

## Open engineering work

| Area | Remaining work | Evidence required before claiming completion |
| --- | --- | --- |
| KMON coverage under churn | Extend the six-control reference-scheduling and queue improvements to large background images, transient targets and longer workloads | Preserve the six-control PID-and-name/name-only regression; add fixed-cohort compared-address metrics, 13-control all-process runs and independent vctip audit on the new binary, retaining partial/failure results |
| Image reference trust | Stronger provenance for the exact reference bytes and remaining relocation exclusions | Wrong/replaced-file, identity, relocation-only and ordinary-byte controls; no promotion of excluded bytes to verified |
| Address model | Consistent extended virtual-address support across classifiers, catalog, scanners, and replay | Real LA57 coverage plus boundary/large-page/alias tests; a five-level walk alone is insufficient |
| Execution surfaces | Broader typed layouts for thread-pool, WOW64 KCT and other callback roots | Exact layout/identity validation, unsupported-state reporting, owned positives and normal-workload negatives |
| Historical evidence | Extend durable retention to additional scanner families and correlated case graphs; add explicit lifecycle/retention policy across sessions | Reconstruction beyond the current admitted-reference read sets, bounded storage, missing-input and restart controls |
| IRP interposition lifetime | Resolve dispatch publication-before-entry and unload contracts for raw `!kmon iotrace` | A supported lifetime mechanism and isolated live races; an object reference and active-count drain alone do not prove publication safety |
| External callback control | No supported external callback mutation path exists | Provider-owned publication, entry, pending-completion and unload lifetime contract before any restoration |
| Remote/MCP | Authenticated encrypted transport, clearer dispatched-operation outcomes, uniform output/pagination where useful | Compatibility and disconnect/timeout/retry tests; no silent downgrade or duplicate mutation |
| Normal-workload validation | More Windows builds, protected-process/game compatibility, long-running and verifier stress | Independent ground truth with separate misses, false positives, inaccessible scope, and side effects |
| Historical open findings | Fast I/O/process-read gaps and WinHTTP Event-handle retention | Reproduction and closure evidence for the specific observations in the native-feature report |

The latest [reference and queue review](VALIDATION.md#reference-watch-and-ti-queue-review-2026-10-29)
records bounded six-control passes, with background image work and layout/capture
failures still present. Earlier 13-control and vctip observations identify their
own binaries; they are not fresh validation of the newer implementation.

The current `private` AI preset invokes an external CLI; it is not an offline
inference guarantee. A genuinely local/offline provider contract remains
separate from blocking KnLiveDbg's own HTTP requests.

## Validation rules

- Retain the [release and development evidence](VALIDATION.md) as dated,
  binary-specific results. A documentation or research refresh is not a new
  runtime validation.
- Use [owned fixtures](MANUAL_TEST_CHECKLIST.md) for deterministic controls.
  Real samples, protected workloads, and comparison tools need their own scope
  and ground truth; synthetic passes are not a detection-rate estimate.
- Keep failed, deferred, unsupported, excluded, and unread scopes visible.
  Zero findings is not complete coverage.
- Keep proposals distinct from the current command/API catalog. New capabilities
  require help, schemas, cleanup behavior, and applicable validation together.
