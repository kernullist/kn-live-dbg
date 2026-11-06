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

## Full-kernel integration design: 2026-11-06

The [2026-11-06 design](KnLiveDbg_full_kernel_security_design_20261106_16c34da.md)
is adopted against `16c34da`. Its P01-P16 packages extend W01-W15 below; they do
not replace existing source, identity, recipe, graph or trace contracts. The
design document is the original assessment, not a record of completed changes.
The implementation must cover its D01-D22 domains and K01-K10/U01-U09 rules
through the package dependencies and four investigation paths (VS1-VS4).

| Package | Next implementation and acceptance | Implementation / integration | Validation / deployment |
| --- | --- | --- | --- |
| P01 Candidate fairness | Session-bound pending queue, reserved fresh comparison window, adaptive batch, failure/cancel denominators; 257/1,025 candidates and churn | Implemented in CLI and KMON | Owned ASan/JSON and full linked self-tests passed; live host/deployment unvalidated |
| P02 Read and translation receipts | Ordered attempts/fallbacks, original error domains, operation-wide budgets, typed walk/permission receipts; parser remains all-or-none | Shared recorder, owned probe, optional ABI 17 native status, typed dump reads and KMON image parser/fallback routing implemented; initialization receipts, native root provider and other scanner migration open | Owned source/transport, typed walk/root replacement, dump CLI and actual KMON comparison fixtures; native driver lifecycle, real LA57 and target architecture gates remain open |
| P03 Live verification transaction | Record the reads that decide a native image comparison; retain reference, exclusions, rechecks and policy; secondary-view recipes | Handle-based live CLI/v2 recipes, original direct/secondary KMON slices, temporal sweep manifests/replay and bounded replayed provenance graphs implemented; cross-bundle associations and approved-change policy open | Owned nonexecuting PE-buffer child exit/reference-replacement replay, actual local secondary reference views and KMON multi-slice publication after source removal covered; real loaded-image/native lifetime and full VS1 gates remain open |
| P04 Runtime capability | Separate compiled, source opened, layout/read/semantic checks and scoped regression; generate address/backend docs from contracts | Selected owned-process/native-connection probes and generated matrix implemented; other backend probes and environment evidence remain open | Policy ASan, owned CLI, Unicode/error output and drift controls passed; no environment validation inferred |
| P05 Artifact/schema broker | Isolate live layout consumers; bind target image, schema, required anchors and runtime invariants | Open | Wrong artifact, child failure and owned layout oracles required |
| P06 Journal/index | Append-only publication, content storage, resumable index and global dedup/retention/closure; retain legacy adapters | Image journals/recovery, coordinated membership/dedup, explicit uncommitted GC, partitioned image priority admission and opt-in private roots with ACL/EFS admission implemented; committed-root retirement, other-family priorities, transfer/redaction and large-store continuation remain open | Publication/deletion interruption, exact-byte accounting, publisher admission and replacement preservation covered; image priority and private-root ACL/EFS validation are recorded separately; full dependency-impact, legacy-store and media/power-loss gates remain open |
| P07 Temporal graph | Join multiple publications only with target/source/lifetime/mapping/clock constraints; preserve immutable original facts | Open | Cross-VM, generation, ABA, late-arrival and unknown-bridge negatives required |
| P08 Object/state claims | Versioned claim requirements for membership, ownership, registration and changes; seven ledgers, refutations and next observations | Open | Scanner adapters and raw evidence replay required |
| P09 Pipeline scheduling | Discovery/qualification/reference/image/layout/capture/publication debt, quotas and per-stage latency | Open | Fixed/churning workload scope and maximum unobserved intervals required |
| P10 Runtime/game lifetimes | TP work/timer/wait/I/O, WOW64, JIT and manifest object generation/secondary-vptr adapters | Open | Exact layout fixtures, cancellation/destruction and normal-runtime controls required |
| P11 ETL/CPU samples | Actual producer context, loss, clock and code binding into normalized trace contracts | Open | Known owned execution and independent raw evidence validation required |
| P12 Optional PT/VMI | Raw decoder/provider adapters, exact code versions, authenticity and supported environment gates | Open | Compatible lab validation of scoped X3/X4; unavailable hardware remains open |
| P13 Wait/I/O/crash | Typed DbgEng, request lifecycle, concurrent wait cycles, alternatives and provenance-based diagnosis | Open | Address reuse, nonconcurrent cycles and independent replay/oracle required |
| P14 Modes/transport | Offline/observe/collect/lab authority, observer actions, TLS/principal scopes, durable unknown-outcome operation journal | Open beyond existing write-off/volatile ledger | No silent downgrade/retry; restart, isolation and cleanup controls required |
| P15 Evidence-checked AI | Typed bounded plans, evidence IDs, competing hypotheses, deterministic claim checks and offline egress policy | Open | Untrusted payload and unauthorized transmission/execution controls required |
| P16 Independent evaluation | Artifact/ground-truth verification, collection runners, scope-matched comparisons and safety/overhead denominators | Open beyond existing imported-result evaluator | Owned/authorized/heldout results stay distinct; no comparative claim yet |

Gate 0 connects P01/P04 and the baseline P14/P16 contracts. Gate 1 completes
VS1 through P02 -> P03 -> P06. Gate 2 connects P05/P07/P08/P10/P13 for VS2/VS3.
Gate 3 adds P11/P12 only where actual execution evidence is needed. Gate 4
combines P09/P15/P16 with operational transport, retention and measured workloads.
Every meaningful step is reviewed, corrected, validated and committed separately.

Implementation, integration, validation and deployment readiness are independent
states. A package stays open when its required adapter, raw evidence, compatible
environment or independent truth is missing. Preserve T01-T30 failure, negative,
interruption and compatibility controls from the design. Synthetic and owned
user-mode checks never imply native driver, LA57, VTL1, hardware, game or corpus
validation. Build/toolchain/binary-specific evidence belongs in [validation](VALIDATION.md).

## Open engineering work

## Kernel investigation platform

The 2026-10-29 full-kernel security architecture proposal is adopted as the
following dependency-ordered work packages. Existing observation identity,
catalogs, image verification and v1 evidence remain the migration base. A command
route, successful fixture or supported page-table format alone is not a validated
backend/build/security-state combination.

| Package | Implementation and acceptance scope | Dependencies |
| --- | --- | --- |
| W01 Baseline/capability | Selected compiled source contracts and command routes via `--capabilities`; runtime capability probes and a measured build/security matrix remain open | None |
| W02 Address/identity | Address descriptor now covers hunting admission/page scheduling, pending IRP reads and evidence replay; source/epoch isolation, remaining scanner migration and real LA57 validation remain open | W01 |
| W03 Read-set source | Bounded source interface connects selected native kernel readers, the handle-based user image reader, immutable bundle replay and full-dump reads. The shared recorder supplies explicit fallback links and operation deadlines; selected dump receipts include typed translation reads. DbgEng, remaining collectors, initialization receipts and live root/lifecycle integration remain open | W02 |
| W04 Schema broker | Expected PDB signature/age validation and private type packages preserve artifact/provider hashes, nested paths and gaps. Offline schema CLI parsing now runs in a restricted child with job, time and output limits; live-symbol isolation, runtime observation binding, approved distribution and fixture attestations remain open | W02-W03 |
| W05 Proof/coverage | Unique interval accounting gates complete comparison; selected image replay now evaluates typed range-match/difference claims with seven separate ledgers and resolvable read references. Generic object/cross-view/causal policies and live temporal coverage remain open | W02-W04 |
| W06 Evidence store v2 | Legacy adapters preserved; image collections add journals, derived chunks, coordinated membership/dedup, explicit GC receipts, first-difference/gap/routine budget partitions and protected ACL/EFS roots; committed-root retirement, other-family priorities, transfer approval/redaction, legacy build restart and large-store continuation remain open | W03,W05 |
| W07 Exact reference replay | Offline dump comparisons now retain the complete reference artifact, ordered raw reads and normalization recipe; original-policy replay is distinct from current reanalysis and preserves exclusions. Native sweep publication, secondary-view recipes and approved distribution remain open | W04-W06 |
| W08 Scheduler SLO | Capture worker now uses class urgency and bounded turns with queue/request-age and service histograms; owned-worker and synthetic fixed/churning cohort controls are available. Broader image/reference/layout policies and real six/thirteen-control latency validation remain open | W03,W05 |
| W09 Entity graph | Single-bundle process/address-space, memory and evidence nodes now expose retained static references with provenance, bounded traversal and source/query-bound continuations. Qualified cross-bundle joins, other object families and hypothesis/claim adapters remain open | W03-W06 |
| W10 Kernel rules | Process cross-view candidates now require complete fresh inventories and matching PID/EPROCESS/CreateTime/lifecycle samples; unverified and reconciled records are retained. Other object families, raw-read replay, unowned-code/device-channel and security-state rules remain open | W07-W09 |
| W11 User/runtime | Selected native references now report X0/X1 or unqualified, retain PSS thread/time metadata and separate VAD reference correlation from execution claims. Additional callback/thread-pool/WOW64/JIT layouts and game-object lifetimes remain open | W07-W09 |
| W12 Wait/I/O diagnosis | Selected native IRP snapshots now preserve requests without completions and expose per-observation thread/request/stack/reference graphs, optional state fields and unknown outcomes. Referenced request lifetimes, transition providers, wait/lock graphs and false-cycle controls remain open | W04,W09 |
| W13 Trace/VMI | Bounded offline normalized-sample import now preserves CPU/VM/VTL/clock/loss and hash-checked code bytes, with source-bound paging and qualified producer-reported levels. Raw trace decoders, authenticated live providers, VMI access and compatibility gates remain open | W02-W09 |
| W14 Security/AI | Kernel sessions default to write-off with verified mode transitions; MCP retains bounded operation IDs/states and late engine outcomes without automatic retry. Full offline/observe/collect/lab partition, protected transport, durable/idempotent operations, remote outcome lookup and evidence-checked AI plans remain open | W01 onward |
| W15 Independent validation | Versioned private corpus/result evaluator now checks family/group/artifact partition leakage and reports missing/failed denominators, per-family precision/recall and imported latency by scope. Authorized corpora, authenticated ground truth, independent uncertainty estimates, external-tool comparisons and live safety/overhead remain open | Each package |

Integration proceeds through source/address/proof and observe/collect boundaries,
then durable replay and scheduling, then entity/rule/diagnostic queries, and
finally optional execution adapters. Package completion requires usable public
contracts, capability/error/coverage reporting, bounded lifetime and retention,
negative controls, independent replay or an alternative oracle, and current
help/API documentation. Unsupported external adapters remain explicit gaps.

### Compiled capability inventory

`KnLiveDbg.exe --capabilities` exits before driver, service, symbol or live-monitor
initialization. Its `kn.capabilities.v1` JSON includes the binary version, main
ABI, selected source contracts and command routes generated from the registry.
`inventory_complete=false` means the selected operations are not the entire
product inventory. `implementation` describes code, while default `availability`
remains `not_probed`; OS build, active address width and security state are not inferred.
The output preserves unsupported native VTL1 access and live trace/VMI paths, experimental
dispatch interposition, bounded inventory and incomplete image replay.

Use `python tools/test-source-capabilities.py --exe x64/Release/KnLiveDbg.exe`
after building to check JSON, registry/ABI agreement, unsupported contracts,
strict arguments and startup help. This gate does not establish live support.

Explicit `--capabilities --probe` reports a known owned-process read and an
existing native connection/ABI/session. Availability is restricted to those
observations and never implies layout, semantic or environment validation.
The [generated matrix](SUPPORT_MATRIX.md) follows the compiled address contracts;
`tools/generate-support-matrix.py --exe x64/Release/KnLiveDbg.exe --check` rejects
drift. Remaining source/layout probes grow with their owning packages.

## Remaining domain work

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
