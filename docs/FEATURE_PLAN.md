# Remaining work

Baseline: v0.0.36. Implemented features are described in the
[command guide](COMMAND_REFERENCE.md), [architecture](ARCHITECTURE.md), and
[KMON coverage](KMON_DETECTION_COVERAGE.md). Completed implementation plans and
per-commit work logs have been removed from this roadmap.

## Open engineering work

| Area | Remaining work | Evidence required before claiming completion |
| --- | --- | --- |
| KMON coverage under churn | Improve large background image completion and run-to-run coverage without starving watched or transient targets | Fixed-cohort compared-address metrics, 13-control all-process runs, independent vctip audit, and retained partial/failure results |
| Image reference trust | Stronger provenance for the exact reference bytes and remaining relocation exclusions | Wrong/replaced-file, identity, relocation-only and ordinary-byte controls; no promotion of excluded bytes to verified |
| Address model | Consistent extended virtual-address support across classifiers, catalog, scanners, and replay | Real LA57 coverage plus boundary/large-page/alias tests; a five-level walk alone is insufficient |
| Execution surfaces | Broader typed layouts for thread-pool, WOW64 KCT and other callback roots | Exact layout/identity validation, unsupported-state reporting, owned positives and normal-workload negatives |
| Historical evidence | More durable reconstruction of cases and coverage beyond finite in-memory indexes | Replay after eviction/restart, delayed evidence, PID/VA reuse, missing/corrupt capture tests |
| IRP interposition lifetime | Resolve dispatch publication-before-entry and unload contracts for raw `!kmon iotrace` | A supported lifetime mechanism and isolated live races; an object reference and active-count drain alone do not prove publication safety |
| External callback control | No supported external callback mutation path exists | Provider-owned publication, entry, pending-completion and unload lifetime contract before any restoration |
| Remote/MCP | Authenticated encrypted transport, clearer dispatched-operation outcomes, uniform output/pagination where useful | Compatibility and disconnect/timeout/retry tests; no silent downgrade or duplicate mutation |
| Normal-workload validation | More Windows builds, protected-process/game compatibility, long-running and verifier stress | Independent ground truth with separate misses, false positives, inaccessible scope, and side effects |
| Historical open findings | Fast I/O/process-read gaps and WinHTTP Event-handle retention | Reproduction and closure evidence for the specific observations in the native-feature report |

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
