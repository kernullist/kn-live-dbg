# Feature Plan

This document tracks high-value feature status for Kn Live Dbg: completed
slices, partially implemented surfaces, and remaining candidates. The common
direction is to keep the driver narrow, grow the user-mode investigation
surface, and produce repeatable evidence that can be compared across runs,
machines, and Windows builds.

## Current Roadmap

Completed core slices:

1. Native VAD and thread/APC triage.
2. AI capability catalog expansion, including implicit `ai <goal>` routing.
3. Module integrity scanning.
4. Driver dispatch integrity.

Remaining priority order:

1. Session baseline snapshots and diffs.
2. Richer driver object, `!drvobj`, and device-stack inspection.
3. WNF stabilization.
4. WFP kernel callout resolver.
5. Positive-control probe expansion.

## Cross-Cutting Rules

1. Keep parsing, symbols, report generation, and AI routing in user mode.
2. Resolve structure offsets from PDB/DIA at runtime. Use fallback layouts only
   when they are guarded, validated against live pointers, and surfaced as
   warnings.
3. Treat every scanner result as evidence, not proof. Suspicious labels should
   include the exact field, pointer, module, symbol, or page attribute that
   triggered the classification.
4. Use bounded walks, cycle guards, integer-overflow checks, and partial-read
   diagnostics for every kernel structure traversal.
5. Add command help, completion entries, README coverage, architecture notes,
   and WinDbg coverage notes with each feature.
6. Prefer stable JSON output for any feature whose output is useful for
   baseline diffing or regression tests.

## 1. Session Baseline Snapshots And Diffs

Add `!snapshot` and `!diff` as a persistent evidence layer over existing
commands.

Target shape:

```text
!snapshot save <path> [/all] [/callbacks] [/wfp] [/alpc] [/etw] [/nmi] [/pool] [/wnf] [/modules]
!snapshot show <path>
!diff <old-snapshot.json> <new-snapshot.json> [/summary] [/details]
```

Implementation notes:

1. Reuse existing scanners instead of creating alternate parsers.
2. Save structured records for modules, callbacks, WFP objects, ALPC ports,
   ETW logger hooks, NMI callbacks, big-pool summary/high-signal records, WNF
   instances, and tool/session metadata.
3. Diff by stable identity first: address, GUID, module name, callback surface,
   pool tag/address, WNF entry address, or command-specific key.
4. Highlight new callback owners, new executable/W+X pool entries, new WFP
   providers/callouts, new ALPC server families, changed ETW GetCpuClock
   targets, and new NMI handlers.
5. Emit a compact console summary plus optional detailed JSON/Markdown output.

Operational value:

1. Compare clean boot vs game launch.
2. Compare pre-update vs post-update anti-cheat surface.
3. Make scanner regressions easier to verify.

## 2. Driver Object And Device Stack Integrity

Add native `!driver`, `!drvobj`, and `!devstack` commands.

Status: initial dispatch-integrity slice is implemented as
`!driver integrity [driver|all] [/limit <n>] [/json <path>]` and exposed to
the AI router as `driver.integrity`. Remaining work is the richer `list`,
`object`, `!drvobj`, and `!devstack` surface.

Target shape:

```text
!driver [list|object <name|address>|integrity] [/module <name>]
!drvobj <driver-name|driver-object-address> [/dispatch] [/devices]
!devstack <device-object-address>
```

Implementation notes:

1. Walk `\Driver` from the Object Manager namespace and decode
   `_DRIVER_OBJECT` through PDB-resolved fields.
2. Print `DriverStart`, `DriverSize`, `DriverSection`, `DeviceObject`,
   `FastIoDispatch`, and the `MajorFunction[]` table.
3. Annotate every dispatch pointer with module and nearest symbol.
4. Flag pointers outside the owning driver image, outside any loaded module, or
   inside writable/executable pool when page attributes are available.
5. Walk `_DEVICE_OBJECT.NextDevice` and attached-device chains with bounds and
   cycle guards.

Operational value:

1. Detect dispatch table patching and device-stack implants.
2. Correlate suspicious callbacks with driver dispatch surfaces.
3. Provide a native alternative to DbgEng-only `!drvobj` / `!devstack` style
   triage when local KD semantics are unreliable.

## 3. Native VAD And Thread/APC Triage

Add a read-only user-mode process memory triage layer.

Status: implemented in `ProcessTriageScanner` with native `!vad`, native
`!threads`, JSON output, command help/completion, AI `vad.list` /
`threads.list` routing, and `/hiddenpte` VAD DKOM detection for present user
PTE ranges that no VAD covers. Remaining hardening should come from field
testing across Windows builds and protected-process edge cases.

Target shape:

```text
!vad <pid|image|eprocess> [/summary] [/exec] [/private] [/wx] [/pe] [/hiddenpte] [/limit <n>] [/json <path>]
!threads <pid|image|eprocess> [/apc] [/stacks] [/limit <n>] [/json <path>]
```

VAD requirements:

1. Resolve the target process by PID, image name, or EPROCESS.
2. Walk `_EPROCESS.VadRoot` across `_RTL_AVL_TREE` / balanced-node style
   layouts with bounded traversal and visited-node protection.
3. Decode start/end VPN, high-bit fields, protection, private memory, commit
   charge, file/image hints, no-change, large-page state, executable state, and
   writable state when fields are available.
4. Highlight executable private VADs, W+X VADs, large executable private
   mappings, private regions whose first page looks like PE/MZ, and
   signature-wiped PE candidates.
5. Reuse the existing PE header probe logic where practical.
6. With `/hiddenpte`, walk the target process page tables from the resolved
   DTB, subtract normalized VAD coverage plus known VAD-less OS shared
   mappings, and report present user PTE ranges that survive as hidden memory
   candidates.
7. Print a compact table and `[vad.summary]` / `[vad.hiddenpte]` counter lines.
8. Support stable JSON output for diffing.

Thread/APC requirements:

1. Enumerate process threads from PDB-resolved process/thread list fields.
2. Print ETHREAD, TID, owning process, start address, Win32StartAddress when
   available, TEB, stack bounds when available, module, and nearest symbol.
3. Flag thread starts in private executable regions, outside known user modules,
   in W+X VADs, or in unexpected kernel/user address ranges.
4. For `/apc`, inspect APC queue/list fields when PDBs expose them. Surface
   queue presence and suspicious kernel/user APC routine pointers, but keep
   findings conservative.
5. Emit warnings when layout drift prevents confident APC interpretation.

AI integration:

1. Add read-only `vad.list` and `threads.list` tools to the AI capability
   router.
2. Validate PID/image/EPROCESS and filters strictly.
3. Route prompts such as "show executable private VADs for game.exe", "find
   W+X regions in pid 1234", "show suspicious thread starts for game.exe", and
   "check APC evidence for pid 1234".

Operational value:

1. Triage injection, reflective loaders, manual maps, private executable
   payloads, thread hijacking, and APC-style execution evidence from one
   console surface.
2. Pair naturally with `!ti` events and `dump-raw` / `dump-pe` follow-ups.

## 4. WNF Stabilization

Close the known WNF gaps in modern LIST_ENTRY mode.

Status: partially implemented. Modern LIST_ENTRY walking runs before the legacy
`RTL_AVL_TABLE` path, `!wnf instance` and `!wnf data` accept either state-name
hashes or stable entry addresses, the walker annotates subscriber/backing-object
chains, and `!wnf data` heuristically probes matched LIST_ENTRY-mode entries for
`_WNF_DATA_BLOCK` pointers. Remaining work is to lock down the canonical state
name slot and symbolic name lookup.

Target shape:

```text
!wnf instance <hash|entry-address>
!wnf data <hash|entry-address>
!wnf names [hash|pattern]
```

Implementation notes:

1. Reverse-engineer and lock down the canonical state-name slot for modern
   `_WNF_NAME_INSTANCE` layouts.
2. Keep the current diagnostic probes until the fixed slot is validated across
   multiple Windows builds.
3. Add a static well-known WNF state-name table only after the canonical slot is
   stable.
4. Improve `_WNF_NAME_SUBSCRIPTION` resolution so more `Ntfc` / `Wnf ` /
   `WnfN` nodes resolve to PID/image evidence.

Operational value:

1. Make WNF output stable across repeated reads.
2. Turn WNF symbolic-name lookup into a reliable day-to-day triage tool.

## 5. AI Capability Catalog Expansion

Expose more existing native scanners through the strict read-only AI tool
router.

Status: implemented. The strict `kn-live-dbg.ai-capability-plan.v1` router now
accepts the expanded read-only catalog, rejects unknown tools and per-tool
unknown args, and dispatches every selected tool through validated local native
handlers instead of raw debugger command generation.

Implemented tools:

```text
etw.integrity
nmi.list
pool.find
address.inspect
wnf.decode
wnf.list
ti.query
module.integrity
vad.list
threads.list
driver.integrity
```

Implementation notes:

1. Keep the catalog explicit and small enough to validate by hand.
2. Reject unknown tools, unknown fields, write-like actions, raw `kd`, nested
   `ai`, session mutation, unload/shutdown, and command chaining.
3. Return local tool evidence first, then optionally ask the provider to
   explain the evidence.
4. Prefer structured local execution over natural-language keyword rules.
5. Use `assistant.answer` only when no local read-only tool fits.

Operational value:

1. Let operators ask practical questions such as "any inline ETW hook?", "why
   is this address suspicious?", or "show W+X pool allocations" without giving
   the model direct command execution power.

## 6. WFP Kernel Callout Resolver

Extend `!wfp` beyond BFE metadata into kernel callout function ownership.

Target shape:

```text
!wfp callouts [/module <name|GUID>] [/kernel]
!wfp kernel-callouts [/provider <name|GUID>] [/layer <name|GUID>]
```

Implementation notes:

1. Keep the current `fwpuclnt.dll` enumeration as the authoritative metadata
   source.
2. Use PDB-first layout resolution for the kernel-side callout tables in
   `netio.sys` / `fwpkclnt` related structures.
3. Join user-mode callout GUID/ID metadata to classify/notify/flowDelete
   function pointers when a reliable key is available.
4. Annotate function pointers with module/symbol and flag non-image or
   unexpected-module targets.
5. Surface clear warnings when private layout drift prevents pointer recovery.

Operational value:

1. Identify network filter drivers whose actual classify functions do not match
   their BFE metadata.
2. Improve anti-cheat and rootkit triage for packet filtering surfaces.

## 7. Module Integrity Scanning

Add a driver/module live-image integrity view.

Status: live-memory PE/section integrity hardening is implemented as
`!module integrity [module|all] [/summary] [/verbose] [/headers] [/sections]
[/wx] [/mismatch] [/limit <n>] [/json <path>]` and exposed to the AI router as
`module.integrity`. It validates PE headers, optional-header bounds,
image/header sizes, alignments, data directories, section metadata, section
ranges/overlaps, and executable-section page permissions. The current slice
emits stable JSON with module/section reason codes plus summary, header,
section, W+X, and mismatch views. Disk/live hashing, IAT checks, and
prologue-trampoline scanning remain future hardening.

Target shape:

```text
!module integrity [module|all] [/summary] [/verbose] [/headers] [/sections]
                  [/wx] [/mismatch] [/limit <n>] [/json <path>]
```

Implemented behavior:

1. Reuses loaded module enumeration and live PE header/section parsing.
2. Keeps malformed modules as partial suspicious records with durable reason
   codes instead of aborting the full scan.
3. Checks section header anomalies, module-list size drift, executable section
   page translation, static W+X characteristics, and effective W+X page
   permissions.
4. Emits stable JSON and concise console modes for summary, verbose, headers,
   sections, W+X-only, and mismatch-only review.

Remaining hardening:

1. Compare live PE headers and section metadata against disk where the image
   path is available.
2. Hash executable sections from live memory in bounded chunks.
3. Add suspicious prologue-trampoline and IAT target checks.
4. Keep failures partial: missing disk file, paged-out sections, or read
   failures should warn without aborting the whole scan.

Operational value:

1. Detect live driver patching, stomped sections, hidden inline hooks, and
   disk/live divergence.
2. Pair with `pool-scan-pe` for hidden images and `!driver integrity` for
   dispatch pointer checks.

## 8. BYOVD Intelligence Scanner

Status: implemented as `byovd [scan|update|status]` and `!byovd`.
`tools\update-byovd-intel.ps1` builds a local catalog from the Microsoft
vulnerable driver blocklist plus LOLDrivers hash/YARA feeds. `scan` refreshes
the catalog automatically when it is older than 24 hours, unless `/no-update`
is supplied.

Implemented behavior:

1. Downloads and extracts the Microsoft blocklist ZIP/XML, normalizing exact
   hash denies and file-name/version file-attribute rules.
2. Downloads LOLDrivers vulnerable/malicious and LoadsDespiteHVCI hash feeds,
   plus the strict vulnerable-driver and malicious-driver YARA rule files.
3. Hashes loaded kernel module images on disk with MD5/SHA1/SHA256 and reports
   exact catalog hits as `HIGH` confidence.
4. Reads PE fixed file versions and reports Microsoft name/version blocklist
   hits as `MEDIUM` confidence signer-unverified triage hints.
5. Emits stable `kn-live-dbg.byovd-scan.v1` JSON and includes the updater
   script in release packages.
6. Runs downloaded LOLDrivers YARA rules over loaded driver images when
   `/yara` is supplied. The scanner uses an external `yara64.exe` / `yara.exe`,
   applies a per-driver per-rule timeout, and reports YARA rule hits as `HIGH`
   confidence with `source=loldrivers_yara`. Release packages intentionally do
   not include YARA binaries; operators provide them separately.
7. Provides a benign no-op positive-control fixture driver named
   `amdryzenmasterdriver.sys` with fixed PE version `1.0.0.0`. `byovd fixture
   load` installs it through SCM so `byovd scan` can verify the Microsoft
   file-name/version `MEDIUM` hit path without using a real vulnerable driver.
   On systems where HVCI or the Windows vulnerable-driver blocklist blocks the
   fixture at load time, the scanner is not expected to report it because it
   never reaches the loaded module list.

Remaining hardening:

1. Validate WDAC signer/certificate constraints for Microsoft file-attribute
   hits before raising them above triage confidence.
2. Add YARA execution over dumped PE/pool artifacts, not only loaded module
   backing files.
3. Add catalog diff output for added/removed rules between updates.
4. Add a test-only catalog overlay for benign `HIGH` exact-hash positive
   controls.

## 9. Positive-Control Probe Expansion

Turn `KnLiveDbgProbe.sys` into a small scanner regression fixture.

Candidate toggles:

```text
probe fixture callbacks [on|off|status]
probe fixture pool-pe [on|off|status]
probe fixture alpc [on|off|status]
probe fixture wnf [on|off|status]
probe fixture thread [on|off|status]
```

Implementation notes:

1. Keep fixtures optional and off by default.
2. Make every fixture deterministic and easy to unload.
3. Keep the existing buffer pattern flow for memory read/write smoke tests.
4. Add fixtures only when they can be implemented without destabilizing normal
   probe load/unload.
5. Document expected scanner output for each fixture.

Operational value:

1. Provide positive controls for callback, pool PE, ALPC, WNF, VAD/thread, and
   memory command regressions.
2. Reduce dependence on arbitrary live-kernel state when verifying scanners.
