# KnLiveDbg v0.0.34

This release adds callback inspection and process memory layout history to `!kmon`, strengthens the checks behind its investigation leads, and unifies command completion across the local and remote consoles. It includes seven implementation commits after [v0.0.33](https://github.com/kernullist/kn-live-dbg/releases/tag/v0.0.33).

## Changes since v0.0.33

- **Callback inspection and saved comparisons:** `!kmon surfaces <pid>` collects TLS callback metadata, a PDB-qualified KernelCallbackTable candidate prefix, and queried WorkerFactory start routines. `/json` and `/save` preserve the observations; `!kmon diff` compares saved `surfaces` or `cases` results with their process identities and coverage. Reads revalidate source metadata and reject unstable references. Snapshot parsing rejects malformed Unicode, duplicate identities and out-of-range values; saved files do not overwrite existing evidence.
- **Process memory layout history:** starting `!kmon` without `/pid` or `/name` tracks existing and newly discovered user processes. Bounded, resumable `VirtualQueryEx` sweeps retain the first complete and latest layouts. `!kmon layouts` exposes collection status, regions and changes, with `/pid`, `/initial`, `/json` and `/save`. The default rescan target is five seconds after a process sweep completes; `/layout-ms` accepts 1,000 to 60,000 milliseconds. Executable candidates also enter the existing image/page verification path.
- **More reliable evidence:** code differences must survive rereading of comparable bytes and revalidation of PE and reference-file identities. Normal loader changes and discardable sections retain separate coverage. IAT checks resolve qualified forwarded exports; unavailable files, partial inventories and failed object reads no longer stand in for proven absence. Driver reloads and reused process/thread identities discard stale confirmation state. Intermediate branch bytes and indirect slots are checked again before publishing references.
- **Explicit event interpretation:** console categories and JSONL `evidence.event_category` distinguish `observation`, `lead`, `coverage` and `sensor`. Existing event kinds remain available. Published events carry `maliciousness=not_established` and `assessment_policy=evidence_v1`; a `finding.*` name is not a maliciousness verdict.
- **Help and completion:** all 261 registered entries were checked at the project boundary. Local input, remote input and server completion requests now share candidate selection and token parsing. Missing options, alias targets, nested help, quoted arguments and cursor handling are corrected. `KnLiveDbg.exe --help`, `-h`, `/?` and `--help all` display help without opening a driver or listener. The documented I/O trace forms are `!kmon iotrace <driver> on`, `!kmon iotrace off` and `!kmon iotrace status`.

## Compatibility and limits

- The user/kernel ABI remains **17**. The package contains matching **0.0.34** EXE/SYS versions; the benign BYOVD metadata fixture intentionally keeps its fixed version.
- The x64 drivers use the existing **lab test certificate**. The ZIP includes `KnLiveDbg-Lab-Test.cer`, not its private key. This is a test-signed lab package, with the same target test-signing requirements as v0.0.33.
- `kmon.layouts.v1` is a separate export format. `!kmon diff` accepts the case and surface formats, not layout exports. Layout changes describe the previous-to-current comparison even when `/initial` selects the initial regions.
- A layout is an observation interval, not an atomic snapshot or a trusted clean baseline. JIT, normal loading and hotpatching can produce investigation leads. Missing permissions, unstable mappings and exhausted budgets remain visible coverage gaps. This release does not establish universal zero false positives, zero misses, or technique attribution from layout differences alone.
- KernelCallbackTable inspection covers a qualified candidate prefix, and WorkerFactory queries cover start routines. Neither represents complete GUI-callback execution tracing or traversal of every dormant thread-pool object.

## Package and validation

`KnLiveDbg-0.0.34-Release-x64.zip` includes the console, main/probe/fixture drivers, Bind controller, Debugging Tools runtime, available PDBs, public test certificates, runnable user-mode fixtures, operator scripts, license notices, and the new guides and review records. Private planning files and keys are excluded. `kn-live-dbg-version.json` records packaged file sizes and SHA-256 hashes. The release also provides `release-validation.json` and `SHA256SUMS.txt`.

Release validation uses Visual Studio 2022 and SDK/WDK **10.0.22621.0**, preserving the project defaults. Standalone AddressSanitizer harnesses exercise the parser, completion, analyst surfaces, layouts, Kmon core and hunting/page code; they do not instrument the entire application. The final release report records the exact build, checks, package hashes and signature status.

| Local gate | Result |
| --- | --- |
| Release and Debug builds | Passed; no compiler warnings |
| Main executable, each configuration | 2,336 command, 524 console, 28 timeline, 75 MCP catalog, 52 remote protocol, 4 connect-argv and 9 HTTP checks passed |
| Standalone parser and completion with ASan | 275,002 parser and 25,954 completion checks passed |
| Analyst surfaces and snapshots with ASan | 6,560 checks passed |
| Process layouts with ASan | 105,075 checks passed |
| Kmon core with ASan | Seven regression groups and 49 evidence-policy/export controls passed |
| Hunting/page corpus with ASan | 11,326 hunting and 54 page checks passed; eight malformed replay inputs rejected |
| Owned user-mode image fixtures | Clean and benign private-RX cases retained unchanged main images; both deliberate one-byte image changes were observed |
| Bind fixture | 10 checks passed |

Actual kernel-driver loading, live remote GUI operation, real game-cheat trials and long-running normal-host false-positive measurements remain operator-owned. The included deterministic checks and owned user-mode fixtures do not substitute for those trials.

Detailed behavior and review evidence:

- [Callback inspection and snapshots](KMON_ANALYST_SURFACES.md) and [analyst review](KMON_ANALYST_REVIEW_20260920.md).
- [Process layout history](KMON_PROCESS_LAYOUTS.md) and [layout validation](KMON_PROCESS_LAYOUT_VALIDATION_20260920.md).
- [False-positive causes and follow-up fixes](KMON_FALSE_POSITIVE_AUDIT_20260920.md).
- [Help and completion audit](HELP_COMPLETION_AUDIT_20260920.md).

[Full comparison: v0.0.33...v0.0.34](https://github.com/kernullist/kn-live-dbg/compare/v0.0.33...v0.0.34)
