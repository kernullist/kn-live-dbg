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
| P03 Live verification transaction | Record the reads that decide a native image comparison; retain reference, exclusions, rechecks and policy; secondary-view recipes | Handle-based live CLI/v3 recipes with original before/after/final mapping queries and conservative conflict/failure gates, compatible v1/v2 replay, atomic direct/slice/sweep original claim publication/replay, journal v3/v4 and dedicated direct-capture membership, original direct/secondary KMON slices, temporal sweep manifests/replay and bounded replayed provenance graphs implemented. Direct approved-change assessment now pins image/manifest/issuer/epoch and before/after hashes to a separate caller policy digest while preserving original claims. A dedicated private collection retains the exact approval inputs and original assessment, with immutable historical retries and separately pinned original/current replay. Direct/secondary slices and temporal sweeps now evaluate exact approved ranges with per-part recipe/time provenance, preserved gaps and original claims. Scoped approval archives now retain the full original dependency closure, resolve exact content-addressed inputs without ambient fallback, and preserve historical assessment across interrupted retries. Native mapping-lifetime binding, cross-bundle associations and signed distribution provisioning remain open | Native protection/unmap/remap, unobserved ABA and source-exit controls preserve query provenance without lifetime claims. Owned PE/read oracles and LoadLibrary MEM_IMAGE controls cover source exit/removal, managed replay and exact approved/unexplained changes. Expiry, replaced local references, malformed scopes, input leases, interrupted approval collection and policy/manifest removal are covered; actual local secondary views, cross-page/slice approved changes, temporal validity and leased-root substitution controls retain their stated bounds. Native lifetime, broader approval policy and full VS1 gates remain open |
| P04 Runtime capability | Separate compiled, source opened, layout/read/semantic checks and scoped regression; generate address/backend docs from contracts | Selected owned-process/native-connection probes and generated matrix implemented; other backend probes and environment evidence remain open | Policy ASan, owned CLI, Unicode/error output and drift controls passed; no environment validation inferred |
| P05 Artifact/schema broker | Bind remaining typed consumers and validate exact builds/layout changes | AppContainer brokers, approved artifacts and opaque layout IDs implemented. Pending IRP now retains three exact schema packages, checks loaded PE/RSDS identity before/after object invariants, records original reads and gates callback admission. Approved distribution, other runtime bindings and build validation remain open | Owned DIA/offset/read-byte, private writer and parser isolation controls are scoped in VALIDATION; native-driver/build/lifetime evidence and broader policy coverage still required |
| P06 Journal/index | Append-only publication, content storage, resumable index and global dedup/retention/closure; retain legacy adapters | Image and typed IRP journals/recovery, private direct-capture and five-member approval collections with exact restart and managed replay, coordinated membership/dedup, explicit uncommitted GC, partitioned image/IRP priority admission and opt-in private roots with ACL/EFS admission, and original-linked image-count redaction with one-use reviewed HTTP disclosure implemented; committed-root retirement, other-family priorities/redaction and large-store continuation remain open | Publication/deletion interruption, exact-byte accounting, publisher admission and replacement preservation covered; image/IRP priority and private-root ACL/EFS validation are recorded separately; full dependency-impact, legacy-store and media/power-loss gates remain open |
| P07 Temporal graph | Join multiple publications only with target/source/lifetime/mapping/clock constraints; preserve immutable original facts | Origin-bound local temporal candidates and per-entity current-view order guards implemented; cross-collector receipts, other object/image adapters, mapping-lifetime changes and persistent temporal indexing remain open | Independent delayed paths, eviction/retirement rollback and guard pressure covered in the local clock scope; native, cross-VM/provider, calibrated-clock and per-CPU loss gates remain open |
| P08 Object/state claims | Versioned claim requirements for membership, ownership, registration and changes; seven ledgers, refutations and next observations | Deterministic registry/evaluator, IRP adapter and direct/slice/sweep image adapters implemented. Direct, eligible slice/sweep and IRP captures preserve and reproduce original claims through canonical atomic roots. IRP replay distinguishes exact Capture-mode report reproduction from explicit current-policy evaluation. KMON journal v4 binds physical image/IRP claim publications; v1–v3 remain readable. Missing inputs and publication budgets retain explicit raw fallbacks. Direct captures now archive their exact original root/reference under a dedicated private journal policy. Other scanner adapters, their original claim publication/reproduction, qualified cross-capture lifetime joins and lifecycle providers remain open | Owned IRP and image controls, independent field/PE-byte/receipt/interval oracles, report mutations, physical journal binding and writer fallbacks; native build/lifetime and broader claim coverage still required. Current-host ASan startup is blocked after the Windows update; dated prior ASan results do not close that gap |
| P09 Pipeline scheduling | Discovery/qualification/reference/image/layout/capture/publication debt, quotas and per-stage latency | Capture, execution-reference, image, publication and layout scheduling implemented. Dedicated metadata and content workers prepare PE ranges and each recorded comparison's source lease/original bytes/hash with quotas, bounded ready results, expiry and stop/join. Comparisons retain final content/identity fences and release source handles before publication. Capture-writer collection timing separates actual closure from job failures, rejected work and unknown acquisition origins. Nine analysis stages now share a cooperative turn budget and persistent rotation with explicit readiness, original target fences and measured stage overruns. Discovery now rotates 26 resumable phases across ten groups, retaining original cycle due clocks and mid-cycle requests, isolating faults and preserving cancellation debt. User-hostility inventory now resumes its owned Toolhelp/watch/suspect cohort in 32-operation/25ms quanta with pinned generation/path checks, separate continuation accounting and protection for newer leads/page state. The selected deep cohort now resumes one target per discovery turn, preserving its tail through target/reporting exceptions and recording identity rejection, cancellation and service separately. Capped inventories now walk the full snapshot and reserve one deep slot across snapshot, watch and suspect PIDs, with a fixed upper PID per lap and explicit capacity-event scopes. The scheduler now tracks Toolhelp module debt by process generation and can prioritize an overdue observation every fourth complete uncapped census. Qualified acquisitions provide first-observation and successful revisit intervals. Other synchronous reference checks, within-target inspections and scanner-internal walks, source-wide collection timing and deeper dependency/deadline propagation remain open | Owned capture/drain/image/writer/layout/preparation/analysis controls, independent shared-budget, stage-fairness and discovery-cycle/request/failure models, actual absent-binding worker, native Toolhelp/process-query continuation and joined cleanup, inventory cap/partial/fault/stop/generation controls, independent deep-cohort outcome/clock models and actual dispatcher generation-rejection/native-thread handle cleanup, independent module-debt clocks and slot selection plus native module acquisition/cancellation/exception checks, measured fixed and changing Windows job workloads with child-confirmed lifetimes, missed generations and right-censored gaps, journal-recovered closure, native lease expiry/release, independent clock/hash/dispatch/fixed/growing/flood/reuse models; broader native workloads, individual native read latency, measured durability/SLOs and whole-source maximum unobserved intervals remain required |
| P10 Runtime/game lifetimes | TP work/timer/wait/I/O, WOW64, JIT and manifest object generation/secondary-vptr adapters | Open | Exact layout fixtures, cancellation/destruction and normal-runtime controls required |
| P11 ETL/CPU samples | Actual producer context, loss, clock and code binding into normalized trace contracts | Open | Known owned execution and independent raw evidence validation required |
| P12 Optional PT/VMI | Raw decoder/provider adapters, exact code versions, authenticity and supported environment gates | Open | Compatible lab validation of scoped X3/X4; unavailable hardware remains open |
| P13 Wait/I/O/crash | Typed DbgEng, request lifecycle, concurrent wait cycles, alternatives and provenance-based diagnosis | Thread-linked IRP observations bind schema/image/object checks to original read captures; v2 offline replay checks ordered calls and canonical results against retained images. Typed journals retain captures/references and require the final IRP ledger before closure. First-state/gap/repeat partitions preserve separate capacity and unavailable denominators. [Windows wait-chain capture and replay](COMMAND_REFERENCE.md#capture-a-windows-wait-chain) derives potential mutex and critical-section cycles within one generation-fenced traversal. [Paired WCT queries](COMMAND_REFERENCE.md#repeat-a-wait-chain-from-two-threads) corroborate a directed cycle only when both roots observe it within overlapping measurement intervals. Replay retains each original edge and every unissued slot. The [offline wait diagnosis](COMMAND_REFERENCE.md#compare-explanations-for-a-recorded-wait) compares cycle persistence with observed lock contention and cites supporting and contrary facts for the primary thread. [Directory I/O request lifetimes](ARCHITECTURE.md#directory-io-request-lifetimes) preserve submission, pending, completion, cancellation and retirement evidence for operations issued through retained handles. [Saved kernel dump diagnosis](COMMAND_REFERENCE.md#diagnose-a-saved-kernel-dump) compares the pinned header with typed DbgEng stop data, bounded stack frames and module ranges. The [WHEA record query](COMMAND_REFERENCE.md#read-the-whea-record-from-a-saved-bugcheck) binds the stored address to CPER section hashes, severity and available machine-check bank status. The [saved Windows event comparison](COMMAND_REFERENCE.md#compare-a-saved-whea-event-with-the-dump) checks the complete payload against separately pinned WHEA-Logger XML. [Cooperative kernel I/O traces](ARCHITECTURE.md#cooperative-kernel-io-request-lifetimes) bind fixture dispatch, pending and disposition records to request and instance generations. The recorder and replay passed user-mode validation. Live Filter Manager delivery, cross-provider IRP identity, host and boot provenance, incident validation using actual hardware events, frozen wait snapshots, additional wait semantics, verified unwind and allocation history remain open | Owned two- and three-thread mutex rings, topology change after discovery, exit during sampling and generation mismatch, plus IRP read/journal/priority controls. Cross-provider lifetimes and kernel-level wait validation remain open |
| P14 Modes/transport | Operating modes, observer actions, TLS/principal scopes, durable operation outcomes | The [one-shot CLI](COMMAND_REFERENCE.md#restricted-one-shot-launches) reads saved traces and supports a consented self-read. The timeline records [TI controller requests](TIMELINE_COMMAND_USAGE.md#inspect-this-controllers-ti-requests) and [live callback control results](TIMELINE_COMMAND_USAGE.md#inspect-live-callback-control-results), including rollback errors. Automatic callback startup preserves prior event history and reuses active collections. [Process handle records](TIMELINE_COMMAND_USAGE.md#inspect-process-handle-ownership) cover the self-probe, shared identity lookup, handle-backed source, TI image resolution, KMON user inventory, layout collection and verification, image sweeps, reference verification, user-page capture, PID-only diagnostics, watch maintenance, [watched handle scans](TIMELINE_COMMAND_USAGE.md#trace-a-watched-handle-scan), process logging handles, and public image, session and package lookups in hunt. Watch cleanup requires a recorded successful request for the same process generation. [Logging requests](TIMELINE_COMMAND_USAGE.md#inspect-kmon-process-logging-requests) retain native and driver results. An unconfirmed enable holds further attempts for that watch generation. Expired layout and reference candidates retain their outcomes without opening the process. Reference failures keep the queued generation. Retained queries use [evidence and receipt permissions](MCP_SERVER_DESIGN.md#evidence-and-operation-permissions), divided budgets, [process-lifetime grants](MCP_SERVER_DESIGN.md#process-lifetime-observation) and [scoped HTTPS](MCP_SERVER_DESIGN.md#https-for-scoped-observation). Loopback and HTTPS journals have separate protection domains. | Native callback registration and unload under live delivery, direct handle opens in other collectors and target effects beyond the tested guard page need validation. A provisioned native HTTPS handshake and cross-host recovery remain open. Kernel collection rights and I/O budgets, additional producer and target roles and authorization for other resources remain open. |
| P15 Evidence-checked AI | Typed bounded plans, evidence IDs, competing hypotheses, deterministic claim checks and offline egress policy | Provider rejects unreviewed captured output; minimized image facts require exact payload/destination review and durable intent. Full typed plan/claim checks, offline inference and general egress confinement remain open | Owned-loopback disclosure boundary is a bounded P06/P15 slice; malicious payload, competing-hypothesis and broader transport/native gates remain |
| P16 Independent evaluation | Verify source artifacts and truth, compare matching scopes and measure safety and overhead | Imported-result evaluator, pinned module workloads and [registered acquisition runs](BENCHMARK_CORPUS.md#register-and-evaluate-repeated-acquisitions) with job costs, missing-package denominators and [paired collector costs](BENCHMARK_CORPUS.md#measure-paired-collector-costs) | Owned completion, startup failure, timeout and observed supervisor loss exercised. Fixed-job census and visit measurements include paired native time, round trip, CPU, I/O and sampled working-set change. Host-wide overhead, game latency, external provenance, authorized and heldout cohorts and independent comparisons remain open |

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
| W04 Schema broker | Offline/live layout and symbol-index consumers use approved handles, bounded worker output and parent artifact checks. Workers have unique zero-capability AppContainer identities, checked code copies, profile recovery, provider pathname pins and job/time/output limits. Explicit-offset inherited reads and private type packages preserve bytes, nested paths and gaps. Runtime observation binding, approved distribution and fixture attestations remain open | W02-W03 |
| W05 Proof/coverage | Unique interval accounting gates complete comparison; selected image replay now evaluates typed range-match/difference claims with seven separate ledgers and resolvable read references. Generic object/cross-view/causal policies and live temporal coverage remain open | W02-W04 |
| W06 Evidence store v2 | Legacy adapters preserved; image and IRP collections add journals, derived chunks, coordinated membership/dedup and explicit GC receipts. Images also have first-difference/gap/routine budget partitions and original-linked count redaction with one-use HTTP approval. Private roots enforce ACL/EFS admission; committed-root retirement, other-family priorities/redaction, legacy build restart and large-store continuation remain open | W03,W05 |
| W07 Exact reference replay | Direct captures retain reference, ordered reads, normalization and original claims in an atomic publication; original-policy replay is distinct from current reanalysis. KMON direct/secondary slices and sweeps retain eligible original claims with journal v3/v4 membership and explicit claim-publication gaps. Direct captures and their separately pinned approval inputs/results have private journal archival, exact historical retries and managed replay; approved distribution and full native lifetime integration remain open | W04-W06 |
| W08 Scheduler SLO | Capture, reference, image, layout and publication policies retain scoped debt and service diagnostics; nine analysis stages share a cooperative budget and persistent rotation. Discovery groups now retain phase cursors and separate periodic/request due clocks. Scanner-internal continuation, deeper dependency/deadline propagation and real six/thirteen-control latency validation remain open | W03,W05 |
| W09 Entity graph | Single-bundle process/address-space, memory and evidence nodes expose retained static references with provenance. Origin-bound v2 bundles add explicit local-collector temporal candidates and content/query-bound pair continuations. Cross-collector correspondence, mapping lifetime, other object families and hypothesis/claim adapters remain open | W03-W06 |
| W10 Kernel rules | Process cross-view candidates now require complete fresh inventories and matching PID/EPROCESS/CreateTime/lifecycle samples; unverified and reconciled records are retained. Other object families, raw-read replay, unowned-code/device-channel and security-state rules remain open | W07-W09 |
| W11 User/runtime | Selected native references now report X0/X1 or unqualified, retain PSS thread/time metadata and separate VAD reference correlation from execution claims. Additional callback/thread-pool/WOW64/JIT layouts and game-object lifetimes remain open | W07-W09 |
| W12 Wait/I/O diagnosis | Selected native IRP snapshots now preserve requests without completions and expose per-observation thread/request/stack/reference graphs, optional state fields and unknown outcomes. The directory notification provider records request lifetimes through final completion and the paired WCT source replays scoped potential cycles. The offline DbgEng source binds stop tuples and stack locations to a pinned AMD64 dump. Kernel IRP generations, dispatch joins, frozen wait graphs and causal crash attribution remain open | W04,W09 |
| W13 Trace/VMI | Bounded offline normalized-sample import now preserves CPU/VM/VTL/clock/loss and hash-checked code bytes, with source-bound paging and qualified producer-reported levels. Raw trace decoders, authenticated live providers, VMI access and compatibility gates remain open | W02-W09 |
| W14 Security/AI | Kernel sessions default to write-off with verified mode transitions. Optional loopback grants isolate sessions, query budgets and receipts by source or retained TI process lifetime. Evidence queries and operation lookups can be granted independently. Target handles expire and rotate. Full mode isolation, protected transport, scoped remote outcome lookup, command-specific idempotency and evidence-checked AI plans remain open | W01 onward |
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
