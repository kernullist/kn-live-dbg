# Validation status

The released baseline is **v0.0.36 / 6646461**. Development verification of the
retained investigation path and subsequent reference/TI queue fixes was recorded
on **2026-10-29**, through **e73932d**, separately from the **2026-10-25** release
validation. Each section identifies its binary and test scope. Documentation
updates do not renew these observations. Follow the
[manual checklist](MANUAL_TEST_CHECKLIST.md) to validate another binary or host.

## Schema artifact broker checkpoint: 2026-11-07

This P05/W04 step binds offline schema creation to parent-owned artifact leases.
The parent verifies returned image/PDB/provider hashes, PE machine/image size,
RSDS GUID/age and requested type against its own inputs. The restricted child
receives three read-only file handles; DIA reads a PDB stream rather than opening
its supplied pathname. Provider loading pins its ancestor directories and file
identity. The existing public CLI and `kn.type_schema.v1` format remain unchanged.
See [schema parser boundaries](ARCHITECTURE.md#schema-parser-process-boundary).

Review found that the previous parent accepted any internally consistent package
with the requested type and `parser_isolated=true`, without comparing its artifact
identities to the requested files. Actual hostile-worker controls now return
canonical, checksum-valid mismatches and are rejected. Review also added provider
directory pins and restricted the parent's PE decoder to bounded headers,
sections and RSDS identity. Omitted relocation facts remain incomplete; the parent
does not parse managed-image or relocation tables to obtain a schema identity.
The shared PE reader now closes its file on C++ exception unwinding as well.
No additional actionable defects were found in the reviewed scope.

Final Release EXE SHA-256:
`eb0e3c4d8d91518baf215b852c85ad3af789a8fac51356c6cb1c7fb142c2256e`.
Final ASan harness hashes:

| Harness | SHA-256 |
|---|---|
| Schema broker | `8f535567c0946f7dd945f770e3ee62c589b3c215fb662e74b736600c08e3062a` |
| PDB identity | `9f8ccfebc2f14da28da2d1bd2b06be4d2bef3f6b2b3649409e2cc2fcf1f01c2b` |
| Parser worker | `897b0060bb9a9024b8891be6eb44a3fbfea180eafb959e74565977553a700691` |
| Shared KMON/PE core | `de6bee5c70c44b9cc5a712385ae3914f92d58d3851291e7ecba56ede3221cbc9` |

Validation ran on Windows 11 Pro x64 `10.0.28000`, NTFS, using VS 2022 Build Tools
17.14.60, MSVC 14.44.35207 and SDK/WDK 10.0.26100.0. Sources and binaries were
frozen during each applicable run; the linked `--self-test all` ran after builds
and other oracles had completed.

| Check | Result and scope |
|---|---|
| `tools/validate-schema-broker.ps1 -Sanitize` | 73 controls passed: actual restricted worker, wrong artifact identities/type, unisolated/failed/flooding/hanging child, read-only handles, invalid handle allowlist, file bounds, provider directory pin, stream EOF/seek/overflow/clone concurrency, independent compiler `sizeof`/`offsetof` and owned `ReadProcessMemory` oracle |
| `tools/validate-pdb-identity.ps1 -Sanitize` | 52 existing PDB/layout/package controls passed with stream loading and the identity-only PE path; wrong-build PDB, bitfields, nested paths, inherited gaps and depth limits remain covered |
| `tools/validate-parser-worker.ps1 -Sanitize` | 19 controls passed, including crash/timeout/cancellation, memory/child-process limits, unrelated handle/environment exclusion and observed parent-death cleanup |
| `tools/test-type-schema-cli.py` against the final Release EXE | 79 checks passed: independent Python artifact/package hashes, canonical output, fresh-process inspection, legacy unisolated packages, wrong PDB/type, collisions, malformed metadata and Unicode/space paths |
| `tools/validate-kmon-core.ps1 -Sanitize` | Shared PE/relocation regressions passed; 835 execution, 130 scheduling, 11,345 hunting, 77 ordering, 54 page and 49 false-positive controls passed; independent execution JSON oracle passed 10 controls |
| Final Release `--self-test all` | Timeline 28, MCP 102, KMON image/read 119, console 558, commands 3,006 across 261 routes, remote 68 and four connection-argument controls passed |
| Contracts/publication | 33 compiled capability contracts and 261 routes passed; generated support matrix matched; the publication classifier's 11 controls passed |

The CLI oracle reported `symlink_skipped=1`: this host did not permit creating
the symlink fixture. Final-reparse rejection is implemented but that execution
case remains unvalidated here. No policy was changed to enable it. Final targeted
readbacks found no KnLiveDbg-family drivers or test processes. EFS remained the
OS-managed Manual/Running service observed before testing; it was not stopped.
No driver load, reboot, host clock or security-policy change was requested by
these tests. Existing C4244/C4744 build warnings remain.

This is the offline broker prerequisite, not completion of P05. Live SymbolEngine
consumers, target image/object/anchor binding, supported-build attestations,
runtime invariants and object lifetime remain open. The installed EXE/DLL are
trusted runtime inputs; hashes do not authenticate distribution or attest a
compromised parser's semantic output. The child has no enforced filesystem or
network deny policy. Parent hashing and synchronous I/O are not covered by a
whole-operation hard deadline. ASan covers the helper harnesses, not the complete
Release EXE; allocator fault injection and other OS/filesystem environments were
not validated. Earlier privacy initialization and process-capture timing
observations remain unresolved and are not closed by these passing runs.

## Local hunt ordering checkpoint: 2026-11-07

This F07/P07 step removes the current hunt view's global latest-event gate.
Independent delayed targets and paths can remain current within arrival freshness,
while per-path, mapping-label and process-generation guards prevent rollback of
retained state. The guards survive hot-row eviction and explicit retirement.
Query JSON and saved analyst snapshots report their bounded capacity, deferrals
and conservative transition floor. Receipt/bundle formats and the driver ABI are
unchanged. See [local current-view ordering](ARCHITECTURE.md#local-current-view-ordering).

The original defect was reproduced with PID 55 observed at tick 200 followed by
independent PID 56 observed at 150 and arriving at 210: the second observation
incorrectly became `historical_only`. Further review reproduced rejection of a
new generation with a smaller creation FILETIME and retention of stale current
rows when the new generation's guard could not be stored. The final rules use
observed generation transitions, retire known previous generations even under
guard pressure, and withdraw the affected process's current rows on that denial.
Page zero no longer aliases a retirement marker. The expiry index also prepares
allocating lookups before mutation and removes old entries by saved iterator.

Final Release EXE SHA-256:
`b701430a9c5b1c1ab4784733861d46ab2863b639efe9afeeece345b3bf9bab74`.
Final ASan harness hashes:

| Harness | SHA-256 |
|---|---|
| KMON core | `0afca301c5fb5fb88777ec375b527b6cec08a9fd455c14d6f0391666c70545f5` |
| Analyst features | `1ed6d7c826132cefbaca81e2a4ed2b5ee0c0008353e9ece8a4d4677def150800` |
| Hunting replay | `19c1f74aab074093ca2d88f56c37e94608d9c3de78689c8acee039437c909b78` |
| Evidence bundle | `13868490d808d29c11511154a4f67dff4107bde4068a743db859455e016b23fb` |
| Temporal facts | `23eee99be2aa5a591a7b6ff1ee17525add4b3e893b3b792fdb2354260e49a64b` |

The final core ASan run passed 77 ordering checks, including all 24 permutations
of four observations against independently specified current rows and exact
original histories. Controls cover independent paths, source-label bypasses,
slot retargeting, delayed retirement, eviction, unknown assertion bridges,
backward-valued generation keys, capacity denial, recovery, page zero and
`uint64` boundaries. Existing hunting 11,345, page 54, false-positive 49,
capture scheduling 130 and execution-evidence 835 checks also passed, with ten
independent execution JSON controls. The hunting runner repeated its shared
controls and rejected eight malformed inputs; its four owned process fixtures
(`clean`, `modified`, `text`, `jit`) passed. No external detector comparison ran.

The analyst ASan runner passed 6,612 checks, including preserving ordering limits
as snapshot coverage, legacy snapshots without that block, and rejection of false
clock/loss/capacity claims. The legacy evidence runner passed 522 controls and its
eight existing timed publication interruptions: three valid final files, five
absent final files, successful restart. This is not synchronized v2 publication
or power-loss validation. The temporal ASan oracle passed 147 checks including
the final Release CLI and original v1/v2 bundle compatibility.

```powershell
.\tools\validate-kmon-core.ps1 -Sanitize
.\tools\validate-analyst-features.ps1 -Sanitize
.\tools\validate-kmon-hunting.ps1 -Sanitize
.\tools\validate-evidence-bundle.ps1 -Sanitize
.\tools\validate-temporal-facts.ps1 -Sanitize -Cli .\x64\Release\KnLiveDbg.exe
.\x64\Release\KnLiveDbg.exe --self-test all
```

The final full suite ran after builds and standalone oracles had finished:
timeline 28, MCP 102, KMON image-read 119, console 558, commands 3,006 across
261 routes and remote 68 passed, plus four connection-argument controls. The
KMON pipeline fixture read two owned pointer slots, observed distinct collector
ticks, then delivered them in reverse capture order; both remained queryable.
Capability checks passed for 33 contracts, the generated support matrix matched,
and all 11 publication-classifier tests passed. Final targeted host readback found
zero KnLiveDbg-family drivers and zero task processes. EFS remained OS-managed
Manual/Running, as before the stage; no explicit driver load or service change ran.

Local diagnostic logs are `.build/p07-ordering-transition-{core-asan,build,
analyst-asan,hunting-asan,legacy-asan,temporal-asan,selftests}.log`. The initial
core build exposed a missing `ReferenceArtifact.cpp` dependency in older core,
hunting and analyst scripts; all three lists were repaired and the final runners
completed. VS 2022 BuildTools 17.14.60 / MSVC 14.44.35207 / SDK and WDK
10.0.26100.0 built on Windows 11 Pro x64 10.0.28000 / NTFS. Existing C4244 and
C4744 warnings remain. Earlier 70-check binaries and logs are superseded here.

This validates bounded local-clock reducer behavior and owned user-mode
integration. The Release EXE is not ASan-instrumented. Generation-key reversal
was synthetic; the host system clock was not changed. Foreign-clock adapters,
CPU-specific loss, source-restart correspondence, loaded native-controller
behavior, allocation-failure injection and general lifetime/temporal coverage
remain unvalidated. The earlier privacy-initialization and process-capture timing
observations remain unresolved. Full F07/P07 and P01-P16 / VS1-VS4 remain open.

## Local temporal candidate checkpoint: 2026-11-07

This P07 step adds origin-bound `kmon.bundle.v2` captures and offline
`!kmon relate` over explicit retained bundle membership. The versioned policy
keeps original observations separate, preserves every pair's requirements and
contradictions, and supports only local-collector temporal candidates. Legacy
v1 remains readable without acquiring missing identity or clock assertions.
See [cross-bundle temporal candidates](ARCHITECTURE.md#cross-bundle-temporal-candidates).
Full P07 and P01-P16 / VS1-VS4 completion remains open.

The checked host was Windows 11 Pro x64 **10.0.28000** on NTFS, with VS 2022
Build Tools **17.14.60**, MSVC **14.44.35207** and SDK/WDK **10.0.26100.0**.
The final Release build exited 0. Existing `NextQueryEpoch` C4744 link warnings
remain; the initial broader build also retained the existing C4244 warning in
`KernelMonitor.cpp`. Final SHA-256 values:

| Artifact | SHA-256 |
| --- | --- |
| Release `KnLiveDbg.exe` | `60b1a39947b4ca50540a99bf94b571fab915ba8106d64a6a635fd4cd513ab388` |
| ASan temporal harness | `a9ed0d8fedb86150def9a47c987f55df32207d9109b2f07d6790e06b1deeb168` |
| ASan legacy evidence harness | `ef0b831a602db4a6f4fe36f076dfaec2dcb92493ba723f2d531a815cebc999c8` |

`tools/validate-temporal-facts.ps1 -Sanitize -Cli x64/Release/KnLiveDbg.exe`
compiled the core with `/W4 /WX /fsanitize=address` and passed **147** independent
Python-oracle checks. They cover exact content/query identities, every pair and
source reference, recorded capture order despite late arrival, overlapping
intervals, gap boundaries, collector/boot/process-generation/native-epoch
separation, known/unknown EPROCESS and session assertions, address contracts,
legacy fallback, missing/corrupt/oversized/duplicate inputs, cancellation and
pagination. The 32-input boundary produced exactly **496** distinct pairs;
33 inputs were denied. The actual EXE covered grammar, Unicode paths, v1/v2
single-bundle graph compatibility and broken-output exit 3. Original input bytes
remained unchanged; no target acquisition was needed by the query.

Adversarial review reproduced a v2 file with its address descriptor removed
being accepted through the legacy fallback and producing a supported candidate.
The final parser requires an original descriptor in v2; the negative oracle
now denies that file. V1 fallback remains explicitly marked, and the report
labels its decoded reference representation `normalized_legacy_compatible`.
Invalid user-reader/kernel-origin combinations are also denied. Hash failure
does not create a valid empty-content identity or a partially published relation.
No additional actionable defects were found in the reviewed scope.

The final `tools/validate-evidence-bundle.ps1 -Sanitize` run passed **522**
existing evidence, inventory and graph controls. Its eight existing timed
publication-interruption controls yielded **3** valid final files and **5**
absent final files; fresh-process reconstruction passed. Those are legacy
publication controls, not newly synchronized v2 crash or power-loss tests.
`tools/test-evidence-graph-cli.py` passed **164** checks against the final EXE
and those final fixtures.

The isolated final `--self-test all` exited 0: timeline **28**, MCP **102**,
KMON image **119**, console **558**, command checks **3006** across **261** routes,
and remote protocol **68** passed. Its KMON pipeline fixture performed two actual
owned `ReadProcessMemory` observations, bound and queued both, freed the source
allocation, drained the writer, and required a supported candidate from the
reloaded files. A changed native-epoch binding was denied. This exercises the
user-mode publisher/helper path, not a loaded native driver. Compiled capability
validation passed **33** contracts / **261** routes; the generated support matrix
matched the final EXE, and all **11** public-content classifier tests passed.

Private evidence: `.build/p07-temporal-address-contract-build.log`,
`.build/p07-temporal-origin-gap-repro.log`, `.build/p07-temporal-final-asan.log`,
`.build/p07-temporal-final-legacy-asan.log`, `.build/p07-temporal-final-selftests.log`.
Final temporal fixtures are `run-15a1577268d145da9fbc5eaab584e0ca` under
`.build/temporal-facts/Release-asan`; legacy fixtures are
`run-adf436bf8c8b452cb1e1458adcbd6e0f` under `.build/evidence-bundle/Release-asan`.
Earlier 97/141-check temporal runs and earlier EXE/full-suite results are
superseded by these final observations. Retained synthetic originals remain
private. Targeted host readbacks found zero task processes and zero KnLiveDbg
driver instances. No driver or test service was explicitly loaded or started;
Windows EFS remained OS-managed Manual/Running.

This is core ASan and owned user-mode validation. Real cross-VM/provider
correspondence, calibrated clock conversion, live reducer freshness, native
driver lifetimes, other evidence families, persistent temporal indexing and
mapping-lifetime/execution/write/causal relations remain open. Collector fields
and hashes do not authenticate a collector or hostile evidence owner. The prior
unexplained privacy initialization failure and process-capture timing observation
also remain unresolved; these passes do not establish their causes.

## Minimized image disclosure checkpoint: 2026-11-07

This bounded P06/P15 step adds offline `redact-image`/`disclosure` and console-local
`ai share preview/send/cancel`. Original-policy replay produces closed-vocabulary
image counts in an EFS-default private package with an original/proof/hash linkage.
The provider requires an exact pending review and a committed private intent;
approval is consumed once and unknown outcomes never authorize an automatic retry.
Unclassified and captured raw output are denied, including external CLI requests.
Operator prompts omit hidden symbol paths and session-expanded targets. See
[minimized image disclosure](ARCHITECTURE.md#minimized-image-disclosure).
The full P06/P15 and P01-P16 / VS1-VS4 goals remain open.

The checked environment was Windows 11 Pro x64 **10.0.28000** on NTFS,
VS 2022 Build Tools **17.14.60**, MSVC **14.44.35207**, SDK/WDK **10.0.26100.0**.
The final Release build exited 0; the existing `NextQueryEpoch` C4744 link warnings
remain. Final binary SHA-256 values:

| Artifact | SHA-256 |
| --- | --- |
| Release `KnLiveDbg.exe` | `3ee7c73f2e6fc132b311e2e19d6910623d5ca92fdf0655ed38c5c28c7f4ec02b` |
| ASan disclosure/provider harness | `8407294ad180461da1212bbc98485076a82982d2093d6324d6efde05b9a354be` |

`tools/validate-evidence-disclosure.ps1 -Sanitize -ImageSliceFixtures <retained-slice-fixtures>
-ImageRecipeFixtures <retained-recipe-fixtures> -Cli x64/Release/KnLiveDbg.exe`
builds the core harness with `/W4 /WX /fsanitize=address` and runs the independent
Python oracle. Source fixtures come from `validate-image-slice.ps1` and
`validate-image-recipe.ps1`; this run reused their retained synthetic originals
read-only. The final oracle was also run directly against the final EXE and the
unchanged ASan harness. It passed **506 checks**, observed **14 loopback HTTP
requests**, and ended with **0 owned child processes** and a closed listener.

The final isolated `--self-test all` run exited 0: timeline **28**, MCP **102**,
KMON image **119**, console **558**, command checks **3006** across **261** routes,
and remote protocol **68** passed. The compiled-capability check passed **32**
contracts / **261** routes, the regenerated support matrix matched the final EXE,
and the public-content classifier's **11** tests passed. No additional actionable
defects were found in the reviewed scope.

The oracle checked exact original-file, semantic, fresh replay-proof and derivative
hash links; count partitions for recipe/slice/sweep scopes; null versus zero;
unchanged originals; EFS attributes; canonical field and bound rejection; malformed,
copied, partial and unreplayable packages; no overwrite; immutable reviewed files
and pinned roots. Three publication interruptions and one intent interruption were
synchronized on observed work, without sleep-based ordering. A manifest-last
package recovers only after the manifest is committed. An interrupted intent
remains unresolved and cannot restore an in-memory approval after restart.

Owned receivers verified exact reviewed facts/system/model, intent existence
before receiving the body, and absence of raw output and hidden session canaries.
Tests covered all three HTTP provider adapters with synthetic credentials, unknown
and raw origins, explicit operator text, CLI rejection before process resolution,
wrong/changed/revoked/reused approvals, configuration and credential changes,
header-control injection, redirects, implicit-auth challenges, HTTP failure and
post-send audit collision. The real EXE offline grammar, Unicode paths, output
failure exit 3, and actual preview/send/cancel/chat handlers were exercised before
controller startup. An actual provider-error response containing an ESC sequence
reproduced raw terminal output; the final handler escapes it, records the unknown
outcome and makes no automatic resend. Returned advice is never executed.

The review also corrected rejected zero-range slices being omitted from disclosure
and session-expanded PID/image/address/dump hints being classified as operator
text. Zero-range slices now retain an unqualified empty scope and unknown change
count. Local command interpretation retains its context, while provider requests
use the original operator text. Help checks were updated for the changed behavior.

Private evidence: `.build/p06-disclosure-error-escape-build.log`,
`.build/p06-disclosure-final-asan.log`, `.build/p06-disclosure-final-handler.log`,
`.build/p06-disclosure-complete-selftests.log`;
the final owned fixtures are `disclosure-c1d09f34f4c84b4384cf2cb0cd651790` under
`.build/evidence-disclosure/Release-asan`. Earlier core/CLI passes are superseded
by the final handler oracle where applicable. Packages and receipts were retained;
no real evidence was deleted or sent to an external service.

This is core ASan and owned-loopback validation, not full-EXE ASan, real provider
availability, production HTTPS/proxy configuration, OAuth refresh/retry, loaded
driver/controller startup, other filesystems or power-loss testing. The owner,
SYSTEM and administrators remain trusted. No driver or test service was explicitly
loaded or started. Windows EFS remains OS-managed Manual/Running, as recorded in
the prior privacy checkpoint. Its earlier unexplained initialization failure and
the historical process-capture timing observation remain unresolved observations;
these passing controls do not establish their root causes. General offline
inference/child confinement, MCP/remote egress controls, other evidence adapters,
key recovery and broader retention/native gates remain open.

## Private evidence root checkpoint: 2026-11-07

This P06 step adds offline `init-store`/`privacy` and opt-in KMON `/private-log`.
New roots require a protected current-principal/SYSTEM DACL and EFS by default;
ACL-only mode requires an explicit option. Root identity and canonical policy
admission preserve the existing plaintext hashes, original artifacts and replay
formats. See [private evidence roots](ARCHITECTURE.md#private-evidence-roots).
The rest of P06 and P01-P16 / VS1-VS4 remains open.

The final Release EXE SHA-256 is
`761af60a63fe8ef190ce2456c2d8bdd289940dd54e5c93d8d93f9fab1235b853`.
The standalone privacy ASan harness SHA-256 is
`542a3c41dbac0d060cd2066fb3052f6e50eccad889d3bfd21bc3331c92235ae9`.
`tools/build.ps1 -Configuration Release -WindowsTargetPlatformVersion 10.0.26100.0`
completed with VS 2022 Build Tools 17.14.60, MSVC 14.44.35207 and SDK/WDK
10.0.26100.0, using the existing test certificate. The final build log is
`.build/p06-privacy-utf8-build.log`; existing `NextQueryEpoch` C4744 link warnings
remain. The earlier broader build also reported the existing C4244 fill warning.

`tools/validate-evidence-privacy.ps1 -Sanitize` passed 770 independent Python
checks against the core (`.build/p06-privacy-path-asan.log`). The host was
Windows 11 Pro x64, OS version 10.0.28000, with an NTFS fixture volume. The final EXE
passed 780 CLI checks (`.build/p06-privacy-diagnostic-cli.log`), including Unicode
JSON and broken-output exit status. The independently inspected owned NTFS
fixtures established actual owner/DACL grants, full physical identity, exact
policy hashes, EFS attributes and new-file encryption inheritance. An owned
restricted token with disabled privileges and a World restricting SID was
actually denied the original bytes; no separate Windows account was created.
This is OS metadata/access testing, not a raw-media ciphertext examination.

Controls reject copied/noncanonical/malformed/oversize policies, wrong principal,
widened root/file ACLs, missing directory inheritance, policy hardlinks,
descendant/root junctions, plaintext children under EFS, ambiguous trailing
dot/space names, alternate streams and DOS device names. Unicode and spaced
paths pass. Observed guard lifetime excludes root deletion and policy overwrite;
a second rejected Open retains the first guard. A destination created after
policy publication is preserved when the actual final rename fails. Four
observed initialization interruptions distinguish private staging from a ready
published root. Every child and pipe reader was reaped. These fixtures and
interruption remnants stay private under `.build/evidence-privacy/Release-asan`.

Adversarial review fixed metadata-only directory handles that did not enforce
share exclusion, premature release of an active session guard after a rejected
Start, pre-validation Windows path normalization, Unicode CLI truncation and a
missing pending-policy public-content classification. Descendant inheritance,
single policy counting and guard reentry are also covered. No additional
actionable defects were found in the reviewed scope.

The isolated final `--self-test all` run passed timeline 28, MCP 102, KMON image
integration 119, console 558, command audit 3,006 across 261 routes and remote 66
(`.build/p06-privacy-final-selftests.log`). Actual KMON ACL and EFS roots exercised
JSONL writes/rotation, retained source bytes after the original disappeared,
reference/read/recipe publication, journal closure/recovery, original-policy
replay, stopped-store inventory and handle cleanup. The complete KMON fixture
tree was removed. The capability checks passed 31 contracts; the generated
support matrix matches the final EXE and retains `not_probed`. Public-content
classifier tests passed 11 controls, including renamed and pending privacy data.

One earlier final-binary CLI run stopped on an initialization failure before
publishing its target (`.build/p06-privacy-utf8-cli.log`). The test then did not
retain the exact returned issue, so its cause is unresolved. Inspection found
the retained staging directory and policy valid; a targeted new initialization
and the subsequent diagnostic suite passed. Diagnostics now include status/issue.
This observation is not relabeled as resolved or as an encryption downgrade.
The older concurrent-load process-capture deadline observation likewise remains
separate from this isolated suite pass.

No native driver load or reboot was requested. Windows automatically activated
its Manual-start EFS service; it remained OS-managed and running afterward.
No owned test processes remained. EFS recovery-agent/key backup, hostile owner
or administrator changes, atomic/continuous security monitoring, other filesystems,
large-tree exhaustion, transfer minimization/approval, linked redaction and
media/power-loss guarantees are not established by these checks. Committed-root
retirement, broader retention policies and the remaining architecture gates
remain required work.

## Image retention priority checkpoint: 2026-11-07

This P06 step connects retention priority to the actual KMON routed-image queue,
writer, journal and final failure ledger. First differences, observation gaps
and repeat/clean slices have separate 4/2/2 admission slots. Raw and recipe file
budgets are each partitioned 64/32/32 MiB; each class can retain one 64 MiB
reference. New-reference and outstanding-reference accounting therefore each
have an aggregate 192 MiB ceiling, replacing the previous shared 128 MiB limit.
This is an explicit reference-budget change, not a total process-RAM or reserved
disk-space guarantee. See the [policy contract](ARCHITECTURE.md#image-retention-priority).

Final Release EXE SHA-256:
`1f22327bc80c1ae9a141bc64e7f9614013a23a537c2e00566e4615cfefd74fff`.
ASan policy harness SHA-256:
`2d032c09d17742a81281d70094cb7540d1879d5d42fe182dca4c5a813a4f3970`.
Builds passed with VS 2022 Build Tools 17.14.60 / MSVC 14.44.35207 and
SDK/WDK 10.0.26100.0. Existing C4744 `NextQueryEpoch` warnings remain; the
initial broader rebuild also reproduced the unchanged `KernelMonitor.cpp`
C4244 fill conversion warning.

The ASan harness passed **34 controls** and the independent Python oracle
passed **109 accounting invariants**, including **9,000 concurrent admission
attempts** across the three classes. The oracle checks fixed external expected
byte/count totals, class limits, refusal/admission/finish denominators, zero
outstanding charges and bounded high-water values. Controls exercise queue
ordering, full lanes without eviction, final-owner release, failed-first retry,
pending/saved duplicates, key exhaustion, unknown identities and stream limits.
These are owned policy controls, not malware samples or measured production SLOs.

The final EXE passed **92 KMON image integration checks**. Owned original-read
fixtures fill routine and gap queues, exhaust routine file budgets and still
publish/replay the first changed image range through the real writer and journal.
The final protected ledger preserves both successful and failed class outcomes.
A collision leaves a partial journal batch; the next original attempt retains
first priority. Successful repeats demote, while changed bytes, process lifetime
assertions and a new collector work episode receive new first-priority keys.
All owned fixture files are cleaned by the harness after validation.

Review added collector work/requalification episodes and source IDs to the
fingerprint so a recycled work entry cannot inherit old priority decisions.
Unknown identity or failed hashing does not earn a reusable key. Saved-key
eligibility requires the complete raw/reference/recipe journal batch, and
allocation/preparation failure releases admission ownership. Review also found
that live hunt readers could overlap session policy replacement; replacement
now uses the hunt-reader lock. The final integration controls observe a reader
before performing 100 session resets and verify valid reports throughout.
This bounded overlap is not a race-detector or universal scheduling proof.

An isolated final `--self-test all` passed: timeline **28**, MCP **102**, KMON
image **92**, console **558**, commands **3,000 / 261 routes**, remote **66**.
Compiled capability contracts passed **30 / 261 routes**, the generated support
matrix matched, and the public-content classifier passed **11 tests**. The new
retention capability remains `not_probed`. No owned test processes remained.

No driver was loaded, service started, Verifier enabled, reboot performed or
security policy changed. The image fixtures use owned nonexecuting bytes; they
do not validate native loaded-image/mapping lifetimes or a live kernel support
matrix. Cross-session priority, other evidence families, committed-root retirement,
privacy, large-store continuation and full P01-P16 / VS1-VS4 acceptance remain
open. The historical concurrent-load process-capture deadline failure remains
unresolved separately; this isolated passing suite does not close it.

## Explicit image-artifact GC checkpoint: 2026-11-07

This P06 step adds offline `!kmon gc` preflight/apply/resume and a create-new
policy helper. Explicit canonical policies bind exact uncommitted member bytes,
reason, minimum age and byte ceiling. Current closed-root membership and all
original/selected file leases remain held under the store barrier. A durable
operation and per-file intent precede each handle-based deletion; separate
receipts preserve success, failure and uncertain outcomes. Committed originals,
references and failure ledgers cannot be selected. This does not retire committed
roots or implement automatic retention priorities.

Final Release EXE SHA-256:
`686e3f0d7981e8d9f27c894a1c2e0fc5fc27a8ec05037dea555af0780b663877`.
ASan journal/store/GC harness SHA-256:
`4c87e5643693568d78884bfbf82afea921bb8ead365fae350ae3097faf35b5ae`.
Release and ASan builds passed with VS 2022 Build Tools 17.14.60 / MSVC
14.44.35207 and SDK/WDK 10.0.26100.0. Existing C4744 `NextQueryEpoch` alignment
warnings remain; the initial broader rebuild also reproduced the existing C4244
fill conversion warning in unchanged `KernelMonitor.cpp`.

The final ASan validation passed **42 C++ controls**, **1,952 journal checks**,
**476 store checks** and **892 independent GC checks**. The final EXE passed
**898 GC CLI checks**, **1,952 journal CLI checks** and **492 store CLI checks**.
The GC oracle creates, verifies and deletes only files beneath its own resolved
fixture root. It independently recomputes canonical policy/operation/intent/
receipt hashes and exact selected bytes, checks original committed files remain
unchanged, and compares root/candidate identities with separate Win32
`FileIdInfo` and creation-time queries. The observed fixture volume is NTFS;
this is not a ReFS or filesystem compatibility matrix.

Nine GC interruption cases observe an owned harness child's exact stage before
termination/reaping. The final CLI resumes those recorded operations. They cover
preflight, operation publication, intent, deletion before receipt, completed
receipt, identical-byte replacement, corrupt intent, rehashed unbound receipt
and copied operation/root identity. All owned children were reaped. Absence after
intent remains actor-unknown; completed receipts are reused without deleting a
later replacement. Denied/partial roots, committed references, failure-ledger
policies, pending/unknown artifacts, policy/path/schema/byte errors, overflow,
minimum age, future timestamps, read-only files, hard links and output collisions
retain their explicit failure or preservation states. The policy helper is tested
against actual store output, existing-output collisions and malformed completeness
flags; six invalid CLI grammars return usage status without execution.

Review changed file identity from the legacy 64-bit index to the full 128-bit
identifier with volume and creation time, following the
[Windows identity contract](ARCHITECTURE.md#explicit-uncommitted-artifact-gc).
Unavailable identity/creation information is denied. A deadline check immediately
before disposition also covers a delayed progress callback. The deadline remains
cooperative, not an I/O cancellation or real-time guarantee.

An isolated final `--self-test all` passed: timeline **28**, MCP **102**, KMON
image **75**, console **558**, commands **3,000 / 261 routes**, remote **66**.
Capability contracts passed **29 / 261 routes**, the generated support matrix
matched, and the public-content classifier passed **11 tests**. GC capability
availability remains `not_probed`; the live controller/MCP does not expose apply.

No driver was loaded, service started, Verifier enabled, reboot performed or
security policy changed. No real user evidence was cleaned. These tests establish
bounded owned-file behavior and process-interruption recovery, not secure erasure,
disk reclamation, authenticated storage or media/power-loss durability. Full
uncommitted dependency-impact analysis, committed-root retirement, priority/privacy
policies, large-store continuation and the full P01-P16 / VS1-VS4 gates remain
open. The historical concurrent-load process-capture deadline failure remains
unresolved separately; an isolated suite pass does not close it.

## Coordinated image-store inventory checkpoint: 2026-11-07

This P06 step adds `!kmon store` for exact membership and dedup accounting across
the stopped image-collection namespace. Participating publishers hold a shared
store lease before any original-file publication; inventory holds the exclusive
lease while verifying every captured root and original member. Open or unresolved
roots protect unattributed files. Committed originals/references and session
failure ledgers remain protected, including a ledger whose journal was never
created. This is a retention classification receipt with no deletion authority.

Final Release EXE SHA-256:
`719ebbb424a758212218d4333c088fc930efb5e1a72308e4247cea20353017d0`.
ASan journal/store harness SHA-256:
`58e82ae379b022c84e9d811a685900105d24a2de28f94cce867abf609449b61a`.
Toolchain: VS 2022 Build Tools 17.14.60 / MSVC 14.44.35207, SDK/WDK
10.0.26100.0. Release builds passed with the existing C4744 `NextQueryEpoch`
alignment warning; the broader rebuild also reproduced the existing C4244 fill
conversion warning in unchanged `KernelMonitor.cpp`.

`tools/validate-evidence-journal.ps1 -Sanitize` passed **42 C++ controls**,
**1,952 journal checks** and **476 independent store checks**. The final EXE
passed **492 store CLI checks**, including summary/detail omission and five
invalid grammars. Store controls independently recompute physical hashes,
hash-linked membership, root/artifact receipt hashes, reference multiplicity,
per-collection paths, global named-file bytes, unique content and actual read
bytes. Repeated references within and across collections share one pinned
physical read; equal content at distinct paths remains separately verified.
The final EXE also passed the **1,952-check journal CLI oracle**, including ten
observed-stage interruptions and zero remaining owned children.

Controls cover unknown tails, corrupt shared references, malformed roots,
uncommitted failure ledgers, pending/unmanaged files, lock collisions, NUL input,
root/namespace/collection junctions, case-only filenames, long paths, catalog
limits and bounded detail output. Shared/exclusive publisher tests observe each
child's held-lease signal before making competing calls, then terminate/reap the
owned child and verify lock release. Reports are revalidated after original-byte
changes; a previous report never grants deletion permission. Fixture creation
initially hit Python's Windows path limit; extended syntax was applied only to
fixture creation, with the original unprefixed long path still sent to the product.

The final EXE's isolated `--self-test all` passed: timeline **28**, MCP **102**,
KMON image **75**, console **558**, commands **3,000 / 261 routes**, remote **66**.
KMON controls exercise denial before read/sweep/ledger publication, explicit
failure counts, release on closure and subsequent exact inventory. Review found
and fixed loss of the existing directory-failure reason and clearing of the
manifest budget reason during successful admission. The original failure label
is preserved; the store admission issue is an additional field. Compiled
capability checks passed **28 contracts / 261 routes**, and the public-content
classifier passed **11 tests**. Store availability remains `not_probed`.

All observations use owned storage fixtures and synthetic, nonexecuting image
inputs. No driver was loaded, service started, Verifier enabled, reboot performed
or security policy changed. The [inventory bounds and coordination](ARCHITECTURE.md#image-store-membership-inventory)
exclude legacy stores, nonparticipating publishers, disk allocation, authenticated
provenance, image-policy replay and power-loss durability. GC with deletion
receipts, retention priorities/privacy, large-store continuation and the broader
P01-P16 / VS1-VS4 gates remain open. The earlier concurrent-load process-capture
deadline failure remains unresolved; this isolated pass does not close that gate.

## Image collection journal and recovery checkpoint: 2026-11-07

This bounded P06 step adds a collection journal to the original KMON image
read/reference/recipe/sweep path. Exact physical file hashes and schemas precede
hash-linked commits; dependent sweep roots require earlier committed members.
The final read ledger has its own closure commit. File publication, collection
commit, derived-index readiness and target observation coverage remain distinct.
Recovery verifies the committed prefix and original files, excludes orphan and
pending files, and resumes derived index publication from exact completed chunks.

The final Release EXE SHA-256 is
`14353ae1555af41f6d57d17a22b1d88baef468c39c9f26cc7cf98a32bf72ff52`.
The ASan journal harness SHA-256 is
`5c6f83208bacd4abd61fbb4026df1555def01ca262b06fc3431f58c5fb258c8a`.
Builds used VS 2022 Build Tools 17.14.60 / MSVC 14.44.35207 and SDK/WDK
10.0.26100.0. Existing C4744 `NextQueryEpoch` alignment warnings remain; the
broader rebuild also reproduced C4244 in unchanged `KernelMonitor.cpp` fill code.

`tools/validate-evidence-journal.ps1 -Sanitize` passed **35 C++ controls** and
**1,952 independent Python checks**. The same Python oracle passed **1,952
checks through the final EXE's offline CLI**. Each run interrupted ten owned
children only after observing their exact publication-stage signal, reaped every
child, recovered the expected prefix and checked restart at the next sequence.
Controls cover raw-only orphans, missing/corrupt members and segments, rehashed
schema/sequence/path violations, unknown tails, extra records after closure,
writer exclusion, dependency admission, exact idempotent retries, collection
dedup denominators, corrupt/partial indexes, directory junctions, NUL input,
trailing separators and paths whose final index files exceed MAX_PATH.

The first actual CLI oracle exposed a long temporary-index path failure. The
journal now uses normalized local extended paths, including backslash separators;
the first extended-path revision's separator regression was corrected before
final validation. The original failing input rebuilt successfully without path
shortening or host policy changes. Additional review fixes pin verified index
chunks until head publication, prevent partial counter publication after an
exception and withhold closed status when records follow a closure. A corrupt
index remains a separate failure and is never silently replaced.

The final EXE passed an isolated `--self-test all`: timeline **28**, MCP **102**,
KMON image **70**, console **558**, commands **3,000 / 261 routes**, remote **66**.
KMON controls recover and replay the original comparison after source/reference
removal, retain incomplete sweep coverage inside a closed collection, account for
reference reuse across actual scheduling slices, and distinguish successful raw
files from a blocked journal/closure. Compatibility checks passed **1,414** sweep
graph checks across eight cases, **164** legacy graph checks, **101** legacy image
recipe checks, **27** capability contracts and **11** publication-classifier tests.
Compiled journal support remains `not_probed` for target availability.

These are owned storage fixtures and synthetic nonexecuting image observations.
No driver was loaded, service started, Verifier enabled, reboot performed or
security policy changed. Process termination does not establish media/power-loss
durability. Recovery bounds and whole-prefix revalidation are documented in the
[architecture](ARCHITECTURE.md#image-collection-publication-journal). Counts and
dedup bytes cover one verified collection prefix, not global retention or disk
allocation. Cross-collection retention/GC, large-store continuation, legacy
inventory-build recovery, native loaded-image lifetime, approved-change policy
and the full P01-P16 / VS1-VS4 gates remain open. The earlier load-sensitive
process-capture deadline failure remains separate; isolated passes do not resolve
or validate that concurrent-load timing condition.

## Replayed image sweep graph checkpoint: 2026-11-07

This P03 substep extends the offline graph command to `.knsweep`. Successful
original-policy replay supplies typed range comparisons; the graph connects the
sweep assessment to manifest, reference, recipe, published raw archive and slice
evidence. Each element retains an artifact digest, JSON pointer where applicable
and original observation interval. Failed comparison, excluded bytes, unobserved
ranges and raw publication loss remain separate.

Release x64 EXE SHA-256:
`5c86c9f84f0264feeae753ee384b6630a11493d631ed90a508324cc5a55e6a05`.
ASan slice/sweep/graph harness SHA-256:
`0f66faef0e0fe12ae233d9b991ddb08f48b33336f9236d59bb739f644caaf413`.
The full Release solution built with the P01 VS/MSVC/SDK/WDK configuration.
The existing C4744 `NextQueryEpoch` alignment warnings remain.

The ASan harness passed 307 C++ controls, including typed replay admission bound
to the expected manifest digest and clearing prior results on failure. Independent
slice and sweep oracles passed 369 and 233 checks. The final EXE passed 1,414
graph checks across eight sweep cases: matching, changed, excluded, missing first
slice, unknown tail, actual secondary reference view, unstable comparison and lost
raw archives. The oracle independently verifies provenance pointers, exact ranges
and byte counts, intervals, graph identities, fresh-process pagination and cursor
invalidation. Different boot/generation labels cannot share nodes even with the
same PID, VA and reference bytes. Missing/corrupt files, a rehashed false verdict
and an oversized projection produce no successful graph or assessment.

The existing evidence ASan harness passed 522 controls; eight interrupted
publications left three valid and five absent final files. The extracted graph
traversal function is unchanged. The final EXE also passed 164 legacy graph,
413 slice, 269 sweep, 101 legacy recipe and 168 live recipe CLI checks. All three
owned live PE-buffer children exited. Capability checks covered 26 contracts and
261 command routes without treating compiled support as target validation.
Public-content regressions passed 11 checks, including renamed graph evidence.

An isolated final `--self-test all` passed timeline 28, MCP 102, console 558,
command registry 3,000 and remote 66 checks. KMON integration passed 64 controls,
including changed-range and two-slice graphs from actual comparison/writer output
after the original target and reference were removed. This isolated run does not
resolve the concurrent host-load timeout observation in the earlier checkpoint.

Review bound the graph's manifest preflight to replay before leaf I/O, retained
original reference qualification separately from failed byte comparison, and
made detail-budget failure discard the projection. The independent oracle found
that the new unstable fixture initially matched and therefore never triggered
the candidate confirmation read. The fixture now starts with a difference and
changes during confirmation; the expected 4,096 failed bytes were retained.
No additional defects were found in the reviewed implementation scope.

Targets remain owned synthetic nonexecuting PE bytes, with actual local
`SEC_IMAGE_NO_EXECUTE` reference views. No driver load, service start, Verifier,
reboot or security-policy changes were made. Graph limits are 256 nodes, 512 edges
and 2 MiB of details; traversal time budgets exclude replay and reference I/O.
Cross-bundle mapping lifetimes and callback/dispatch joins, native loaded-image
validation, approved-change policy, reference caching/stage budgets and P06
journal/restart/global retention remain open. The full P01-P16 / VS1-VS4 goal
remains active.

## Temporal image sweep checkpoint: 2026-11-07

This P03 substep publishes bounded `kn.image_sweep.v1` manifests that bind the
original slice recipes, raw payloads, reference identity, target labels, range
indices and observation intervals. Slice ordinals advance before queue admission;
missing entries, missing terminal observations and entirely dropped sweeps stay
visible through manifests or final session denominators. Offline replay verifies
the declared artifacts and shared reference, then reruns each original slice
policy. It separates executable comparison, membership and publication completion.

Release x64 EXE SHA-256:
`b38967e0518269b13a4b1a5d1394f11a553d2ec867fa199bc8de391aa1f7a59e`.
ASan slice/sweep harness SHA-256:
`72c01c0a21bcfef28447f6dc716c2c52dc573db0afe5bcb1ce003ec2326032ae`.
The full Release solution built with the P01 VS/MSVC/SDK/WDK configuration.
The existing C4744 `NextQueryEpoch` alignment warnings remain; the broader
rebuild also emitted the existing C4244 conversion warnings.

`validate-image-slice.ps1 -Sanitize` passed 251 C++ controls, 369 independent
slice checks and 233 independent sweep checks. The six sweep cases cover
matching/modified/excluded ranges, a missing first slice, an unknown tail and
actual owned secondary reference views. All original targets are synthetic
nonexecuting bytes; reference views use `SEC_IMAGE_NO_EXECUTE`. Original reference
paths and target bytes are removed before publication/replay. Hash, temporal
membership and byte-total checks are independent of the C++ implementation.
Negative controls include conflicting process generations, duplicate leaves,
wrong schedules/targets, missing raw/recipe files, corrupt reference bytes,
contradictory terminal/time fields, path escape and bounded metadata loss.

The final EXE passed 269 sweep CLI, 413 slice CLI, 101 existing recipe CLI and
168 live CLI checks. All three owned live PE-buffer children exited.
`validate-image-recipe.ps1 -Sanitize` passed 92 compatibility controls; six
interrupted publications per v1/v2 format left three valid and three absent
final recipes. Public-content regressions passed 11 checks, including renamed
private manifest/replay/proof formats.

The final isolated `--self-test all` passed timeline 28, MCP 102, console 558,
command registry 3,000 and remote 66 checks. Actual KMON comparison/writer
integration passed 62 controls: two scheduling turns with one shared reference,
original raw/recipe/manifest binding, writer stop after only the first slice,
unknown-tail replay, manifest collision/byte limits, complete queue loss,
final session denominators and zero outstanding reference reservations.
An earlier concurrent full-suite run failed the existing bounded process-capture
test; its five-second boundary was inspected. The same binary passed when run
alone, and the final binary passed alone after the closure control was added.
The test was not relaxed. The precise cause of the concurrent failure was not
isolated; behavior under concurrent host load remains unvalidated.

Review tightened terminal/end-time consistency and secondary-observation interval
containment. The proof names executable ranges explicitly instead of implying a
comparison of every PE section. The independent oracle also caught an intentional
fixture byte change left behind when its IAT exclusion was removed; the fixture
was corrected without changing the expected byte totals. No additional defects
were found in the reviewed manifest implementation scope.

Manifests and replay remain temporal, unauthenticated observations. A replayable
subset is not a complete sweep; a completed comparison is not execution,
approved reference provenance or an atomic mapping lifetime. No driver-load,
service-start, Verifier, reboot or security-policy changes were made. Native
loaded-image lifetime, graph associations, approved-change policy, full-file
reference caching/stage budgets and P06 journal/restart/global retention remain
open. The full P01-P16 / VS1-VS4 goal remains active.

## Original KMON slice replay checkpoint: 2026-11-07

This P03 substep retains clean, changed and inconclusive original KMON slices.
Raw `kn.image_reads.v3` includes the original secondary-view inputs even when
recipe publication is unavailable. Eligible AMD64/PE64 slices publish direct
`kn.image_slice.v1` or secondary `kn.image_slice.v2` recipes beside the archive.
Offline replay consumes the original routed reads and retained reference,
recomputes normalization/results and reports executed-range proof and coverage.
It never substitutes a fresh target read or a newly mapped secondary view.
Raw archives, recipes and reference blobs have separate publication counters.

Release x64 EXE SHA-256:
`eb3bfbff4c68de09bfd769b887161ff6e9dfa4a4e435ed6b88f3172374aafab1`.
ASan slice harness SHA-256:
`5f76facf3d29d4239f345384193e43e6e70f14514a9040ea1e3a82a40c4bda1c`.
The full Release solution built with the P01 VS/MSVC/SDK/WDK configuration.
Existing C4744 `NextQueryEpoch` alignment warnings remain; the preceding broader
build also reported the existing C4244 conversion warnings.

`validate-image-slice.ps1 -Sanitize` passed 127 controls and 369 independent
Python checks across 11 cases. The final EXE passed 413 slice CLI/oracle checks.
Cases cover clean/modified/unstable/unreadable inputs, rejected guards, final
identity changes, continuation, ambiguous secondary basis and positive secondary
comparisons. Synthetic targets use two executable pages, a DIR64 relocation and
an explicit IAT exclusion. Secondary reference reads use actual owned
`SEC_IMAGE_NO_EXECUTE` mappings; no fixture code is executed. Original targets
and reference paths are removed before publication/replay. Independent checks
verify hashes, selected receipts, relocation values, matching/differing ranges
and byte denominators. Missing references, unlinked fallback, altered order,
unsupported architecture and rehashed input/normalization/result contradictions
cannot produce successful proof.

`--self-test all` passed timeline 28, MCP 102, console 558, command registry
3,000 and remote 66 checks. Its actual KMON comparison/writer integration passed
49 controls, including clean/modified replay after source removal, incomplete
secondary raw retention, independent recipe/reference byte limits, collisions,
queue drain and final failure ledgers with zero reference reservations.
`validate-image-recipe.ps1 -Sanitize` passed 92 compatibility controls and six
interrupted publications per v1/v2 format (three valid, three absent each).
The final EXE passed 101 existing recipe CLI and 168 live CLI checks; all three
owned nonexecuting PE-buffer children exited. Public-content regressions passed
11 checks, including renamed private slice inputs and proof formats.

Review fixes preserve raw secondary inputs when recipe eligibility fails,
distinguish slice replay schema/policy from single-page replay, and validate
disjoint coverage accounting before issuing proof. Test discovery uses the
published recipe path rather than assuming a capture ID. No additional defects
were found in the reviewed implementation scope.

These controls do not validate an OS-loaded target or native driver lifetime.
No driver-load, service-start, Verifier, reboot or security-policy changes were
made. A faithfully replayed inconclusive slice remains inconclusive; its proof
does not establish whole-sweep completion, approved provenance, atomic mapping
lifetime or execution. Sweep manifests/graph associations, source-initialization
receipts, full-file reference caching/stage budgets, journal recovery/global
retention and the full VS1/P01-P16 goal remain open.

## KMON exact reference retention checkpoint: 2026-11-07

This P03/minimal-P06 substep pins the comparison reference before target reads,
retains bytes from that exact file object, and rechecks content before releasing
the source lease. Changed/inconclusive KMON slices use `kn.image_reads.v2` with
separate capture and publication status. The writer verifies or creates shared
content-addressed reference blobs before publishing the referring archive.
Queue reference reservations and newly published reference bytes each have a
128 MiB limit, separate from the existing raw archive budget. Failed or missing
references remain explicit while original raw reads can still be preserved.

Release x64 EXE SHA-256:
`7c59bf0b0ca56f8996a71e52b9e59f323c614ed50a47ce346966a81f7315794d`.
ASan reference-blob harness SHA-256:
`7d71cbb0711fa0e9c45206fd592c389d825e396dac78ea867e4e41a2df099a0b`.
The full Release solution built with the P01 VS/MSVC/SDK/WDK configuration.
Existing C4244 conversion and C4744 `NextQueryEpoch` alignment warnings remain.

`validate-reference-blobs.ps1 -Sanitize` passed 23 controls and the independent
Python SHA-256/JSON oracle. Real owned-file handles exercise rename/path
replacement, independent read position, write exclusion, source deletion before
publication, exact-byte reuse at zero new-byte budget, forged hashes, corrupt
existing blobs, size limits, invalid/device handles and cleanup. An existing
writable mapped view denied the read-only exclusion lease; this does not test
privileged mutation through an acquired lease.

`--self-test all` passed timeline 28, MCP 102, console 558, command registry
3,000 and remote 66 checks. Its actual KMON comparison/writer integration passed
36 controls, including source/reference removal before publication, unchanged
original routed bytes, exact shared reference, pressure/reservation release,
missing/corrupt/budget-denied references, reference rejection before target reads,
output collisions and final ledger balances with zero reference reservations.
`validate-image-recipe.ps1 -Sanitize` passed 92 v1/v2 controls; six interrupted
publications per format left three valid and three absent final recipes.
The final EXE passed 101 legacy CLI checks and 168 live CLI checks with three
owned nonexecuting PE-buffer children, all exited. Public-content regressions
passed 11 checks, including renamed private v2 read archives.

These are owned user-mode/synthetic comparisons, not OS-loaded module or native
driver lifecycle validation. No driver-load, service-start, Verifier, reboot or
security-policy changes were made. Full reference acquisition/rechecks and blob
verification still run per slice; the 25 ms sweep yield is not an end-to-end
latency guarantee. Caching/stage budgets, clean-only retention, normalization,
secondary-view inputs, complete slice recipes and sweep manifests, journal
restart/global retention and full VS1 remain open. No additional defects were
found in the reviewed implementation scope. The P01–P16 goal remains active.

## KMON original image read archive checkpoint: 2026-11-07

This P02/P03 substep connects KMON's initial user/kernel image comparisons and
background continuations to shared read operations. Failed primary reads,
explicit handle/native fallback and the receipt selected by each parser call
remain distinct. Changed/inconclusive slices publish bounded private `.knreads`
archives with separate queue/store counters and final `.knreadledger` files.
Cancellation/deadline checks also cover guard entry and completion. The archive
does not retain the full reference, secondary-view inputs or normalization and
cannot be replayed as an image recipe. Clean-only retention, complete background
reference/recipe and sweep manifests, native lifecycle and full VS1 remain open.
The P01–P16 design goal is not complete.

Release x64 EXE SHA-256:
`ce7f4e6e99670d74fe66121461f7e35b934cf50eb6237a2ec31819d4185cc411`.
ASan read-routing harness SHA-256:
`0e1afe76ab4d67d06133b7b92a60cf4bf44767fcb4b36da00c9e16976748272d`.
The full Release solution built with the P01 VS/MSVC/SDK/WDK configuration;
the existing C4744 `KmonHuntIndex::NextQueryEpoch` warnings remain.

`validate-read-routing.ps1 -Sanitize` passed 40 controls and an independent
Python oracle over 31 operation snapshots. They cover partial-prefix retention
without byte merging, fallback permission/source/descriptor binding, shared
budgets, source changes, unavailable primary, factory failures, guard rejection,
cancel/deadline before and during guards, parser capacity and abandoned reads.
`validate-read-receipts.ps1 -Sanitize` passed 48 controls and 13-operation/
14-snapshot JSON checks. `validate-native-read.ps1 -Sanitize` passed 139 controls
and 14 JSON observations; the native transport is synthetic and the device
qualification negative opens only NUL.

`--self-test all` passed timeline 28, MCP 102, console 558, command registry
3,000 and remote 66 checks. Its actual `ScanExecutableImage`/capture-writer
integration passed 26 additional checks using owned synthetic PE bytes:
modified/clean/unstable/unreadable comparisons, original header/page/confirmation
receipts and selected bytes, publication after source/reference removal, payload
hash, final ledger, queue pressure, session byte budget, filesystem failure,
create-new collision and fixture cleanup. These are not OS-loaded image or
native driver lifetime tests. The tests made no driver-load, service-start,
Verifier, reboot or security-policy changes. Public-content regression checks
passed 11 tests, including private archive/ledger extensions and renamed schemas.
No additional defects were found in the reviewed implementation scope; the
remaining architecture and native acceptance gates above remain unresolved.

## Handle-based live image transaction checkpoint: 2026-11-07

This P03 substep adds `--verify-process-image` and `kn.image_recipe.v2`.
The selected comparison records its original handle-source reads through one
shared operation, including qualification and confirmation, and retains the
exact reference artifact and normalization. V1 remains readable and the dump
capture command retains its v1 output. Background KMON/native fallback, secondary
image views, real loaded-module lifetime, durable journal integration and full
VS1 completion remain open. The P01–P16 design goal is not complete.

Release x64 EXE SHA-256:
`f4b301822fb886627e36b070a75924f2c3a9b3fc5aaa94dc80191988acd31ff7`.
ASan image-recipe harness SHA-256:
`cf006436464e7afbd6ccfadf0fcd51635cfce0485e6cb5ae10c71c5165e046fe`.
The full Release solution built with the P01 VS/MSVC/SDK/WDK configuration.
Existing C4744 warnings on `KmonHuntIndex::NextQueryEpoch` remain.

`validate-image-recipe.ps1 -Sanitize` passed 92 combined v1/v2 controls, including
original raw metadata, explicit consent, policy/budget denials, receipt gaps,
operation/source mismatch, projection tampering and unchanged replay policy.
Six interrupted publications per format each produced three valid final recipes
and three absent finals; fresh-process replay verified the valid finals.
`test-live-image-recipe.py` passed 168 checks through the actual EXE. Three owned
children held normal, changed and inaccessible PE-buffer ranges. Readiness and
exit were observed through IPC and process completion. After each child exited,
the original reference was replaced and removed; original-policy replay still
matched the actual comparison. Independently rehashed contradictory receipts
were rejected. Output collision preserved existing cases, and failed stdout
delivery returned an error while leaving the published case replayable.
All three children exited; none remained. Their buffers were private RW memory,
not OS-loaded or executed images. The legacy offline image CLI passed 101 checks.

The process-source ASan harness passed 25 controls/six JSON observations;
the recorder passed 48 controls and 13 operations/14 JSON snapshots. Translation
receipt ASan passed 65 controls/13 JSON observations, and the actual dump CLI
passed 227 checks with one symlink-privilege skip. Runtime policy passed 28
controls, and the actual runtime probe, 25 compiled contracts/261 routes,
generated support matrix and 11 publication-scanner regressions passed.
Linked self-tests passed: timeline 28, MCP 102, console 558, commands 3,000 and
remote 66.

Review prevents v1 from silently discarding new metadata and confines runtime
availability to the operation actually probed: a successful owned byte sample
does not advertise image-capture availability. V2 validates the entire receipt
projection, source contract, consent and accounting before it becomes replay
input. Final review found no additional actionable defects in this scope.
Reported copy counts and Win32 errors follow
[ReadProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory);
handle qualification uses the requested creation time from
[GetProcessTimes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes).
These checks do not prove atomicity, mapping lifetime, LA57, native acquisition,
collector authenticity, execution or maliciousness. No driver was loaded,
service started, Verifier enabled, reboot requested or security policy changed
for this substep.

## Typed dump translation checkpoint: 2026-11-07

This P02 substep adds a physical address domain, a typed page-table walker and
`--offline !kmon dump-read ... /receipts`. The selected command records the actual
table, recheck and payload reads under one budget. It preserves the original
dump-read schema when the option is absent. Native root acquisition, other
collectors, source-initialization receipts and durable translation replay remain
open; this checkpoint does not complete P02.

Release x64 EXE SHA-256:
`8cbf2a0d508333f4df3c21741c786f18a2993603c3493a52a7ac4a421588c82d`.
ASan translation harness SHA-256:
`061eae5f43123bf93f9d82d46083aa11a5895eec1bfe8711991d52b23b283184`.
ASan dump-source harness SHA-256:
`a019b32013e0fca1b7426a65720525b1eb3a0a0b9499fb4cebabbaa2db912b0d`.
The full Release solution built with the P01 VS/MSVC/SDK/WDK configuration.
Existing compiler/linker warnings remained, including C4744 on the unchanged
`KmonHuntIndex::NextQueryEpoch` atomic field. No driver code changed in this substep.

`validate-translation-receipts.ps1 -Sanitize` passed 65 controls; its independent
Python oracle checked 13 observations. Controls cover LA48/LA57, 4 KiB/2 MiB/1 GiB
leaves, upper RW/U/S/NX restrictions, reserved bits, MAXPHYADDR, unknown features,
root and epoch replacement during initial/recheck reads, conflicting entries,
partial PTE reads, shared budgets, cancellation and receipt exhaustion. No failed
walk returns a usable mapping or permission result. Physical addresses in the
virtual canonical hole are tested without pretending they are virtual addresses.

The dump-source ASan harness passed 139 controls using owned synthetic full-dump
files. The actual EXE passed 227 CLI checks, including original-byte equality,
physical read denominators/status, nonpresent versus uncaptured pages, invalid
grammar and read-only stdout failure. One final-symlink CLI check was skipped
because the host lacked symlink creation privilege. The fixtures also test
concurrent ordinary file reads, write/delete sharing restrictions and retaining
the original bytes after closing the source handle. These are file-source
controls, not a native driver or a real LA57 host validation.

Adversarial review corrected same-number cross-domain fallback, a changed source
address contract retaining the same ID, a range assembled across different
chunk contracts, and a root used with another operation's target labels. It also
prevents parser/fallback use after an observed deadline
overrun while preserving raw evidence, and distinguishes a caller-declared root
from a file-backed root. Virtual image capture rejects physical sources and
overruns instead of omitting those semantics from v1 recipes; capability sample
availability respects the same deadline/cancellation boundary. The final
reviewed scope had no additional actionable defects.

Shared recorder checks passed 48 controls and 13 operations/14 JSON snapshots;
native transport passed 139 controls/14 JSON observations; the owned process
source passed 23 controls/six JSON observations. Evidence-bundle ASan passed 522
controls and eight interrupted publications (three valid finals, five absent,
restart checks passed). Runtime policy passed 27 controls, with the actual CLI
probe also passing. All 24 contracts/261 routes, the generated matrix drift check,
11 publication-scanner regressions and full linked self-tests passed (timeline
28, MCP 102, console 558, commands 3,000, remote 66).

Image-recipe ASan passed 73 controls, including physical-domain rejection,
source-contract replacement and deadline overruns during header/payload reads.
Six interrupted publications produced two valid final recipes and four absent
finals. The final EXE passed 101 image capture/replay CLI checks using owned
fixtures; no live target participated in those tests.

The dump envelope explicitly excludes initialization header/probe reads. Its
52-bit physical admission ceiling is not measured target MAXPHYADDR. Missing
MAXPHYADDR/NXE/1 GiB context leaves permissions unknown; decoded addresses locate
captured file bytes, not verified live CPU mappings. Repeated reads do not pin
mappings or exclude ABA. Effective CPU access, encrypted-address profiles,
EPT/NPT, live root leases, execution and real LA57 remain unvalidated. No driver
was loaded, service started, Verifier enabled, reboot requested or security
policy changed for this checkpoint.

## Native read status transport checkpoint: 2026-11-07

This P02 substep adds an optional ABI 17 read-observation envelope without
changing the existing IOCTLs. The native observation source uses the advertised
contract to retain original NTSTATUS, copy count and outer Win32 transport
status. Qualified old drivers retain their legacy path with an explicitly
unavailable NTSTATUS. Existing direct collectors and typed page-table receipts
still require migration; this checkpoint does not complete P02.

Release x64 EXE SHA-256:
`53df0457247cd25e5da43636b0fc33cd24d0988c9b95bcd95b24613ee722c05f`.
Release x64 driver SHA-256:
`c1534013ffa8561f245579f860b85d3fcd38d5dabacdf0f53e195aff3bae2d3c`.
ASan native-read harness SHA-256:
`b45e59b884a4399f980d0aedbe20e8978146f35cc2c844b4ad12f7edbb23d22a`.
The full Release solution built with the P01 VS/MSVC/SDK/WDK configuration.
The build emitted C4744 on the unchanged `KmonHuntIndex::NextQueryEpoch` atomic
field and C4244 on the unchanged byte-vector fill in `KernelMonitor.cpp`.

`tools/validate-native-read.ps1 -Sanitize` passed 139 checks. An independent
Python JSON oracle checked 14 status/source observations. The controlled
responder exercises the production transport helper and decoder: all three
read kinds, request/response bounds, identity and epoch binding, partial and
failed copies, raw high-bit status values, legacy compatibility, contradictory
status/count pairs and refusal to retry legacy IOCTLs after an advertised
extension fails. The real `DeviceClient` checks open only `NUL`, reject its
version query and verify that closing it clears qualification.

Adversarial review found that process-identity mismatch could be flattened into
an ordinary failure and authorize fallback. Explicit mismatch/policy flags and
typed states now preserve those denials; recorder tests reject an explicit
alternate-source retry. Review also corrected an unqualified source's contract
label, unknown copy-attempt reporting and the direct converter's result state.
The final reviewed scope had no additional actionable defects.

The shared recorder passed 48 ASan checks and 13 operations/14 JSON snapshots;
the owned process source passed 23 checks and six JSON cases. Evidence-bundle
ASan passed 522 controls, with eight interrupted publications producing three
valid and five absent final files; restart checks passed. Runtime policy passed
22 controls. The final EXE passed the actual capability CLI checks, all 24
contracts/261 routes, support-matrix drift check and full linked self-tests
(timeline 28, MCP 102, console 558, commands 3,000, remote 66).

No driver was loaded or service started. Real kernel/process/physical reads,
process-exit overlap, close/reopen/stop overlap, old/new driver interoperability,
Verifier, signing trust and OS/security-state regression remain separate native
lab gates in the [manual checklist](MANUAL_TEST_CHECKLIST.md). Connection-epoch
checks do not supply a lifetime lease: callers must still serialize the native
source and `DeviceClient` lifecycle. The physical transport is not yet a typed
translation source, and these controls do not establish MMIO, LA57 or VTL1 access.

## Ordered read recorder checkpoint: 2026-11-07

The first P02 substep adds the shared recorder and operation-wide budgets to
the actual owned-process capability probe. The recorded bytes come from that
read, with no evidence-only reread. This does not complete P02: image/scanner
migration, native raw status DTOs and typed translation are still open.

Release x64 EXE SHA-256:
`1202859ac3a3ca7a7aa8532d14183870da934be00ab3955f3dcf016d95d67dac`.
ASan recorder harness SHA-256:
`91f6b56c43255b851ca95e7a35a6ef10adc8665217246df4f67e06b14c38e636`.
The full Release solution built with the P01 VS/MSVC/SDK/WDK configuration.
The unchanged `KmonHuntIndex::NextQueryEpoch` atomic field still emitted C4744
alignment warnings. Signing/deployment trust was not established.

`validate-read-receipts.ps1 -Sanitize` passed 48 controls. Its independent Python
oracle checked 13 operations and 14 snapshots, including a pending concurrent
read. Controls cover original partial/error data, denial and cancellation,
explicit fallback permission/source/range links, shared byte/call/span limits,
receipt overflow, elapsed-time overrun, source replacement, malformed spans,
exception unwinding and admission order differing from completion order. The
concurrency test waits for observed source work before releasing the other actor.
The owned Win32 control also compares direct API failure codes, closes the original
caller handle and frees the source allocation before checking retained bytes.

Review corrected three recording gaps: delegated empty denials lost their
specific state, rejecting malformed/replaced-source bytes erased raw status, and
pending/abandoned JSON lacked the requested range. It also added a separate sparse
metadata budget; a byte limit alone did not bound span storage. The final reviewed
scope had no additional actionable defects.

Existing owned process-source ASan checks passed 23 controls and six JSON cases.
Evidence-bundle ASan passed 522 synthetic controls, including the common source
admission/parser regressions; eight interrupted publications produced three valid
final files and five absent finals, with restart checks passing. The runtime
policy harness passed 22 controls, and the actual CLI probe passed the read-set,
Unicode/output-failure and matrix checks. All 24 compiled contracts/261 routes,
the generated support matrix, 11 public-content scanner regressions and full
linked self-tests passed (timeline 28, MCP 102, console 558, commands 3,000,
remote 66).

No driver was loaded. Native connection availability remained unavailable on
this host. Native NTSTATUS recovery, process fallback, page-table receipts,
protected-target access, real LA57, durable replay of this new JSON format and
OS/security-state regression are not established by these controls. Target and
address-space labels remain caller-declared. Budget charging counts delegated
source requests, not physical I/O; elapsed time includes parser/queue delays but
does not measure them separately. In-flight calls are not forcibly cancelled.

## Scoped runtime capability checkpoint: 2026-11-06

The selected P04 probe and generated source/address matrix extend the compiled
inventory. Default `--capabilities` still performs no target probe. The explicit
`--probe` path acquired a known 32-byte owned-process range through the real
Win32 source. Opening the default native device was unavailable on this host;
no driver was loaded or started. The native open/ABI/session success policy was
checked with synthetic inputs, not a successful live driver connection.

Release x64 EXE SHA-256:
`09a97bda2659e09944e9149b48f21002e0f289d3e9c785b832152babfe0a22e5`.
ASan policy harness SHA-256:
`a6a82694d41a3d6d11721d03601d2436d33ce4786b972a1cf40606c0757e24b0`.
The build used the same VS/MSVC/SDK/WDK configuration as the P01 checkpoint below.

`validate-runtime-capabilities.ps1 -Sanitize` passed 22 policy controls for
missing source/ABI/session, sample identity/control bytes, unsupported backends
and refusal to promote connection checks into scanner/environment support.
`test-source-capabilities.py` passed the existing 24 contracts and 261 routes
with the additive stage/scope/address metadata. `test-runtime-capabilities.py`
passed actual owned read, conservative native availability, strict arguments,
public-matrix rejection of runtime reports, atomic generation/stale-check
behavior, Unicode output and read-only stdout failure controls. The generated
[matrix](SUPPORT_MATRIX.md) passed `--check`. Publication scanner regression
tests passed all 11 cases, including renamed/inconsistent runtime reports.

The first runtime CLI test failed because localized Windows status text truncated
wide-stream JSON under the C locale. Explicit UTF-8 redirected writes and Unicode
console writes fixed it; Korean, a supplementary character, quotes/newlines and
output failure now have regression controls. The final reviewed scope had no
additional actionable defects. Full solution build and `--self-test all` passed
(timeline 28, MCP 102, console 558, commands 3,000, remote 66).

These checks do not qualify a native layout, a protected process, another target,
real LA57, VTL1, trace/VMI, or an OS/CPU/security-state support combination. The
probe's owned address shape is explicitly legacy LA48; active native width remains
unknown without the driver response. Other backend/layout probes and authenticated
environment regression evidence remain open P04 work. Runtime reports are private
evidence, and connection handles close before output. Native raw error domains
and operation-wide deadlines were outside this checkpoint; selected operation
budgets are covered above. Signing trust remains unvalidated.

## Hidden-process scheduling checkpoint: 2026-11-06

P01 of the [integration design](FEATURE_PLAN.md#full-kernel-integration-design-2026-11-06)
uses the same qualification orchestrator in native CLI/KMON and owned controls.
The pending queue lives beyond each scanner instance and resets on a changed
device connection epoch. Only scheduling hints persist; every comparison requires
fresh lifetime samples and fresh inventories in its own batch.

Release x64 EXE SHA-256:
`d084d488dcb63c7fabf0c696dd0328aa73b92ac5583cde00e46cd4c4f435db78`.
ASan hidden-process harness SHA-256:
`5114f1d31a3b6d9dfab3aaabfa8c8953d2cd902ce6c6d9ceb7b8f9227c32532e`.
Build inputs were VS 2022 Build Tools, MSVC 14.44.35207 and SDK/WDK
10.0.26100.0, Release x64 without a version bump.

`tools/validate-hidden-process.ps1 -Sanitize` passed 226 existing policy controls
and 1,367 scheduler controls. These execute the production batch selection and
boundary orchestration with an owned source and deterministic clock: all 257 and
1,025 fixed candidates receive service; continuous priority arrivals retain the
old cohort's minimum share; failing prefixes rotate; cost adaptation leaves time
for comparison/after reads. Cancellation, PID generation changes, zero budgets,
source replacement and departed candidates preserve exact unverified scope.
An independent Python JSON oracle checked seven original dispositions and all
257 candidates over three fresh scheduled batches, including no stale samples
on deferred records. These are synthetic acquisition controls, not 1,025 live
hidden processes or a measured host latency SLO.

The full `tools/build.ps1` solution build and `--self-test all` passed. The linked
tests reported timeline 28, MCP 102, console 558, command checks 3,000 and remote
protocol 66; startup/compiled capability validation also passed 24 contracts and
261 routes. The build emitted C4744 alignment warnings for the unchanged
`KmonHuntIndex::NextQueryEpoch` across existing translation units. Driver signing
metadata was present, while the local trust query returned `UnknownError`;
this checkpoint does not establish deployment trust or native load compatibility.

Review corrected queue insertion rollback on allocation failure and preservation
of the before-phase timeout reason. The final reviewed scope had no additional
actionable defects. Working-tree and prospective-index public-content scans passed; raw evidence,
private paths and credentials are excluded from publication inputs.

No driver was loaded, no Driver Verifier or reboot was run, and native candidate
churn, protected targets, live LA57 and multi-host workloads remain unvalidated.
The scheduler does not interrupt an in-flight API, bound initial discovery, retain
raw cross-view reads or measure successful lifetime revisit latency. These limits
remain distinct from the implemented fairness and fresh-batch contract.

## Process-handle observation source checkpoint: 2026-10-30

Release x64 EXE SHA-256:
`cd02b63efc70d9a1320efec8113d4d049e2baba0f6dfa0a4dce7855de8bf00ce`.
The actual Win32 source passed 23 ASan controls and six independent JSON
observations. Owned-page checks cover retained handle ownership after caller
closure, exact PID/creation identity, unchanged access rights, required residency
consent, cancellation, budgets, user-only admission, inaccessible/partial reads,
multi-chunk discard and 512 successful plus 512 rejected constructor lifetimes
without a handle-count increase. The source does not assert current liveness.

Shared-source regressions passed 522 ASan evidence controls and eight interrupted
publications (four valid final bundles, four absent), with restart reads.
The dump source passed 107 ASan controls and 102 public CLI assertions; one
symlink control was skipped by the environment. The additive native-status JSON
field remained compatible with these owned dump inputs. Release and native
suites passed timeline 28, MCP 102, console 558, commands 3,000, remote 66 and
connect arguments. Capabilities passed 24 selected contracts/261 routes.
Publication-scanner regression code and inputs are unchanged from the preceding
ten-test corpus checkpoint; the prospective index is scanned separately.

Review required RAII ownership even if constructor string allocation throws,
rejected kernel addresses before invoking the provider, preserved original
Win32 errors and cleared failed assembled bytes. A first multi-file patch used
a missing project-filter anchor and applied no changes; the corrected patch
was built and tested. No additional actionable defects were found in the
reviewed scope. Logs are under `.build/architecture/w03-process-*`, including
`-source-first`, `-bundle-regression`, `-dump-regression`, `-dump-cli`,
`-build-first`, `-native-all` and `-capabilities`. Existing compiler/LTCG warnings
remain. No driver or external target was used. The selected native image-reader
integration was compiled, but its live scanner/native-fallback behavior,
protected processes, real LA57 and full recipe publication remain unvalidated.

## Corpus evaluator checkpoint: 2026-10-30

The Python 3.11 evaluator passed 13 test groups with independently specified
synthetic denominators, missing/errored/unavailable cases, unknown truth,
correlated variants, family/group/artifact split leakage, exact corpus/scope
identity, duplicate assessments, strict JSON, closed schemas, unsigned latency,
8 MiB inputs, 4,096 cases and 512 comparison scopes. Public CLI success and
failure checks verify valid JSON output and empty stdout on rejected inputs.
The documented fixture example produced end-to-end recall 2/7 and observable
recall 2/4; these are synthetic arithmetic controls, not detection-rate results.

Publication-scanner regressions passed ten tests, including the three private
benchmark schemas. Document links and the executable example passed. No
additional actionable defects were found in the reviewed scope. Logs are
`.build/architecture/w15-corpus-tests-final.log` and
`.build/architecture/w15-corpus-public-tests.log`; the generated example report
remains private under `.build/architecture/`. This stage changed only Python
tooling, publication rules and documents; it did not rebuild or revalidate the
unchanged native binary. No collector, driver or external analysis tool ran.
Imported evidence hashes and ground truth are declarations, not authenticated
artifacts. Independent corpora, sampling uncertainty and live safety remain open.

## MCP operation outcome checkpoint: 2026-10-30

Final Release x64 EXE SHA-256:
`dfa3ea661359379ab8cdde71669af52860af03c6dd3608f45721e5db8729c024`.
The operation ledger passed 25 ASan controls, including 128 concurrent
timeout/completion schedules, with seven independently checked JSON state
records. Queued cancellation cannot dispatch; active unknown outcomes survive
retention pressure; duplicate completion cannot replace the first outcome.
Admission fails when all 256 metadata slots remain active.

The native suite passed timeline 28, MCP 102, console 558, commands 3,000,
remote 66 and connect arguments. This engine build's SHA-256 was
`79746f8f0ea280091054992d7a3ae98e11efd136796de816b8724cba2ad8a33d`;
the final build only extended HTTP resource tests. Final loopback HTTP controls
passed 25 checks, including the real 30-second response wait, lookup while a
fake engine remains blocked, late completion, argument rejection and operation
IDs in tool/resource success/error replies. The fixture executed no kernel
command and changed no URL ACL or firewall rule. It closed its owned listener.

Capabilities passed 23 selected contracts/261 routes; publication-scanner
regressions passed ten tests. The initial capability script invocation omitted
its required `--exe`; the corrected command passed. Document links and the
68 read/12 write catalog counts were checked. Logs are under
`.build/architecture/w14-operation-*`, including `-core-final`, `-native-all`,
`-http-final`, `-capabilities-final` and `-build-final`.

Review preserved the existing payload schema, serialized queue/ledger updates,
rechecked completion at the timeout boundary and separated cancelled operation
completion from actual engine completion. No additional actionable defects were
found in the reviewed scope. Existing compiler/LTCG warnings remain. These are
synthetic engine/transport controls, not driver execution or mutation-effect
validation. No VM or driver load was used. TLS, per-principal authorization,
durable/idempotent operations and the remote protocol adapter remain open.

## Normalized trace import checkpoint: 2026-10-30

Release x64 EXE SHA-256:
`721f291d38edf9ab27b491d3bf15f0635ed0f7f92dccb861038c3716b8f83f9f`.
The actual importer and bounded file reader passed 93 independently generated
CLI controls under ASan, then the same 93 through the public native offline
entry. Controls cover source kinds, unknown context, LA48/LA57, loss/gap
consistency, code hashes/conflicts, immutable cross-process paging, integer
precision, Unicode, invalid schemas, collection limits and the 2 MiB boundary.
An already-cancelled library call clears stale output. The documented input
example also passed through the public native command.

Adversarial Unicode input reproduced truncated redirected JSON from wide-stream
output; explicit UTF-8 output fixed it. Review also rejects unpaired surrogate
identifiers and downgrades conflicting code contexts. No additional actionable
defects were found in the reviewed scope. The shared artifact reader's existing
image-recipe ASan suite passed 68 controls and six interrupted publications
(three valid, three absent). Its default 64 MiB limit is unchanged; the importer
requests a smaller limit before allocation.

Final Release/native gates passed timeline 28, MCP 89, console 558, commands
2,998, remote 66 and connect arguments. Capabilities passed 22 selected
contracts/261 routes; publication-scanner regressions passed ten tests. Logs
are under `.build/architecture/w13-trace-*`, with successful `-core-final`,
`-build-second`, `-native-all`, `-native-cli` and `-recipe-regression` gates.
Existing compiler/LTCG warnings remain. No driver was loaded or host security
policy changed. These tests import synthetic normalized records; they do not
validate a raw trace decoder, producer authenticity, live CPU/VTL collection,
runtime code mapping, execution completeness or writer attribution.

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
