# KnLiveDbg v0.0.33

This release expands `!kmon` from entry-point and named-process checks to bounded executable-page inspection and kernel/user evidence correlation. It also includes the driver-hiding layers, capture work and command/transport fixes added since [v0.0.32](https://github.com/kernullist/kn-live-dbg/releases/tag/v0.0.32).

## Changes since v0.0.32

- **Executable-code verification:** compare executable PE sections against qualified local image/PDB identities with relocation handling, inspect PE/PTE permission mismatches, and preserve unknown ownership instead of treating unavailable reference data as a clean result. All selected processes are eligible regardless of name. Whole-range page scheduling and resumable user PTE traversal cover more than the first page, including NX/U/S inheritance, large pages and VA aliases.
- **Kernel/user hunting cases:** `!kmon cases` and `!kmon cases /json` retain recent executable references and matching full-page content. Passive firmware-table, hive, ETW logger, standard callback and instrumentation slots feed the verifier. WFP layout candidates, thread/APC metadata and historical ETW stack addresses keep their distinct evidence status. JSONL references can be replayed offline.
- **Driver-hiding evidence:** correlate host and kernel module views, loader-list links, driver objects and device back-references. New layers cover post-load disappearance/remapping/tampering, bounded driver-object type-list traversal, kernel-thread/list discrepancies, inline patches and mapper-stub/pool remnants. Missing inventories and transient changes withhold findings; service-key-only disappearance on a non-inbox driver needs corroboration.
- **Capture and scheduling:** separate ingestion, analysis, capture reads and storage through bounded queues. Captured bytes survive later unmapping, repeated ranges retain page progress, and status/coverage records expose drops and unfinished work. File-handle lifecycle observations use process creation identities and resolve File/device/driver relationships. Optional build manifests qualify object/vtable rules against an EXE/PDB identity.
- **Command and transport correctness:** harden numeric/expression parsing, native command arity, memory ranges, complete JSON/UTF-8 validation and MCP schemas across the 261-entry registry. Failed prewrite backup prevents writes. MCP/remote queued cancellation and stop no longer leave stale queued work or wait indefinitely for engine drain; a running request still has an unknown outcome after timeout. Collector cleanup precedes device close and driver unload.
- **Evidence-consistency fixes:** prevent over-capacity inventories from repeatedly losing tail pages; retain the PFN actually used for a physical read; withhold an entire path after late slot/process/DTB invalidation; show refreshed references at the correct position; and reject fixed reserved paging bits while allowing legal PAT bits.

## Compatibility and operator changes

- The user/kernel ABI remains **17**, as in v0.0.32. The package contains matching current EXE/SYS files.
- Native commands reject malformed numeric forms, unterminated quotes and ignored trailing arguments. MCP rejects unknown/mistyped arguments and malformed or duplicate-key JSON. Scripts that relied on permissive parsing need correction.
- The executable-section verifier is independent of legacy builtin-specific display rules. Findings describe changed bytes or executable-memory evidence, not an automatic cheat verdict. `cases` does not establish a communication protocol, current instruction pointer or causal attribution.
- I/O-trace unload now waits for active traced dispatches to finish. A stalled target can delay unloading; this change does not establish that arbitrary third-party dispatch interposition is safe.
- The x64 package is **test-signed for lab use**. It includes the new `KnLiveDbg-Lab-Test.cer` public certificate. Its private key is not distributed. The target machine must satisfy the existing test-signing requirements; no production-signing or live-load certification is claimed.
- Build/release helpers now accept `-WindowsTargetPlatformVersion` and `-TestCertificateThumbprint`. The OS build target is explicitly `Windows10`, which is also the WDK target family used for Windows 11. This package uses Visual Studio 2022 and SDK/WDK **10.0.22621.0**; project defaults remain 10.0.26100.0.

## Package contents

`KnLiveDbg-0.0.33-Release-x64.zip` contains the console, main/probe/fixture drivers, Bind controller, pinned Debugging Tools runtime and available PDBs. It now also includes the MCP bridge, runnable hunt/Kmon fixtures, public operator guides, release/review notes, Kmon validation summaries and license notices. Private planning files and keys are excluded.

`kn-live-dbg-version.json` records each staged file's size and SHA-256. The release's `SHA256SUMS.txt` identifies the ZIP and validation report. Developer regression scripts that compile C++ require the source checkout and compiler; the ZIP is the runnable/operator package.

## Review and validation

The comparison was reviewed by subsystem, including the two driver changes: wrapping translation requests are rejected, and unload no longer frees the trampoline after a fixed retry count. Final release testing also exposed a disconnected AI-write preflight that attempted network symbol resolution before its inevitable read failure. Native restore and process-context resolution now reject a closed device before that lookup, with a command regression check. The hunting validator now captures expected malformed-input diagnostics without Windows PowerShell 5.1 treating stderr as a terminating error; it still requires exit code 2.

Final local results:

| Gate | Result |
| --- | --- |
| Release and Debug builds | Passed with SDK/WDK 10.0.22621.0 |
| Main executable, each configuration | 1,993 command, 524 console, 28 timeline, 75 MCP catalog, 52 remote protocol, 4 connect-argv and 9 HTTP checks passed |
| Release parser with AddressSanitizer | 275,002 checks passed |
| Release Kmon core with AddressSanitizer | Core regression groups passed |
| Release hunting/page corpus with AddressSanitizer | 11,326 hunting and 54 page checks passed; eight malformed replay inputs rejected |
| Owned user-mode hunting fixtures | Clean, executable-section change, text change and benign private-RX expectations passed; no real-cheat sample was used |
| Bind fixture self-test | 10 checks passed |
| Research ledger | 22 sources / 18 technique entries validated; known gaps remain explicit |

Detailed evidence and limits:

- [Command audit](COMMAND_AUDIT_20260919.md): shared parsing, dispatcher, transport and shutdown review.
- [Research refresh](RESEARCH_REFRESH_20260920.md): 22 primary-source entries revisited, discovery endpoint results and current implementation limits; the 45-day freshness gate is unchanged.
- [Latest Kmon review](KMON_ADVERSARIAL_REVIEW_20260920.md): repeated adversarial regressions, Release/Debug builds, 11,326 hunting checks and 54 page-coverage checks per ASan run.
- [Execution verification](KMON_DETECTION_VERIFICATION.md), [cross-domain hunting](KMON_CROSS_DOMAIN_HUNTING.md) and [coverage matrix](KMON_COVERAGE_MATRIX_20260919.md): implemented behavior and observation limits.
- The attached `release-validation.json` records the final packaged build, embedded test signer, command/transport checks and ZIP manifest verification. Prior development reports retain their historical binary hashes.

Actual VM/game-cheat trials remain operator-owned, as requested. The local checks do not measure real-cheat recall, long-running normal-host false positives, every OS/PDB layout or live kernel races.

[Full comparison: v0.0.32...v0.0.33](https://github.com/kernullist/kn-live-dbg/compare/v0.0.32...v0.0.33)
