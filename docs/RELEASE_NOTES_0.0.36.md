# KnLiveDbg v0.0.36

This release collects the changes after [v0.0.35](https://github.com/kernullist/kn-live-dbg/releases/tag/v0.0.35). It improves KMON collection and image inspection under sustained load, corrects CI/HVCI and hypervisor evidence, and replaces unsafe callback mutation with cooperative control of the owned test provider. Pending I/O, query replies, and test-runner cleanup have repeated live-host validation.

## Changes since v0.0.35

- **CI/HVCI and CPUID evidence:** CI state comes from validated `SystemCodeIntegrityInformation` responses. HVCI enabled, audit, strict, and IUM flags are decoded independently of CI debugger mode; unavailable values stay unknown. Microsoft hypervisor feature leaves require the `Hv#1` interface and a sufficient leaf range. Invalid VTL pointer values no longer become a known inactive state.
- **KMON queues and collection loss:** bounded scheduling keeps analysis queues draining and preserves deferred layout/image work under full-process load. Process ownership and capture identity survive deferral, stale candidates are reconsidered against current layouts, and failed or truncated image-name queries use bounded retries. Shutdown finishes admitted work while retaining explicit incomplete and loss accounting.
- **Image inspection coverage:** resumable image cursors, file-identity sharing, short-tail completion, watched-image admission, and progress-based scheduling improve large and background image traversal. Exact equal-byte comparison reduces unnecessary page work. Capture recovery validates process identity, and discardable or otherwise unreadable pages remain explicit exclusions rather than successful reads.
- **Secondary views and relocation checks:** auxiliary PE32/PE32+ image views receive independent relocation-basis checks. Bounded dynamic-relocation handling and REL32 target validation expand comparable ranges without treating unsupported bytes as clean. The live matrix includes the actual `vctip` System.Data.dll views alongside 13 clean and modified-code controls.
- **Native diagnostics and saved evidence:** kernel module inventory enables the required debug privilege before reading addresses and preserves unavailable results. Unloaded-driver snapshot identities distinguish repeated loads, and minifilter attachment coverage is independent of unrelated callback metadata gaps. Additional repairs cover BYOVD version reporting, TI log persistence, pointer-table interpretation, and restore plans that retain the selected process and byte radix.
- **Callback lifetime:** raw external callback-pointer replacement is unavailable. The owned `KnLiveDbgMiniFilterFixture` supports pausing its harmless CREATE pre/post counting bodies with kernel-owned rundown, automatic owner restoration, and unchanged registered wrappers. The guard prevents the unload-after-replacement crash reproduced during development. Normal filter inspection and supported attachment APIs remain available.
- **Pending I/O:** asynchronous fixture READs lock their buffers before deferral. Completion contexts retain logical and worker ownership, upper/lower pairing requires the same I/O and instance generation, and owner exit or teardown retires unused reservations. Target admission and watching distinguish a process that exited with code 259 from a running process. Batch, partial-submit, cancellation, termination, reconnection, and unload races are covered by the fixture suites.
- **Query and runner failures:** status snapshots remain observable during target watches and survive concurrent port duplication, last-handle close, owner replacement, and unload. Reply-buffer protection changes, decommit, release, and overwrite are tested across page boundaries. Partially created reader threads are joined; reporting failures no longer skip independent cleanup. A separate supervisor contains helpers in a Windows job and recovers the verified fixture service after abrupt runner exit. Expected failures remain failed child records with separate cleanup verification.
- **Operator guidance:** architecture, callback scope, fixture protocols, and reproduction checklists match the current implementation. Query-runner help exits successfully, while argument errors preserve their standard exit code without a traceback. Release packaging selects the notes matching the built version.

## Compatibility and limits

- The main user/kernel ABI remains **17**. Use the matching **0.0.36** EXE, main driver, and probe from this package. The benign BYOVD metadata fixture retains its intentional **1.0.0.0** version.
- CI/VBS JSON is now **`kn-live-dbg.vbs.v2`**. Consumers must handle unavailable values as `null`, use the documented public CI-mask semantics, and stop depending on the removed `hvciEnforced` and `hvciDebugMode` fields. Recapture snapshot baselines after upgrading because unloaded-driver identity formatting changed.
- `!callbacks` and `!minifilter` mutation commands support only the exact cooperative fixture target and its supported CREATE bodies; `all` does not mean arbitrary external registrations. `write on` does not enable external callback replacement. The separate pending-I/O fixture protocol is **v7**, with 32-byte requests and 528-byte status replies; use the matching source checkout for its Python suites.
- Builds use Visual Studio 2022 and SDK/WDK **10.0.26100.0**. The x64 drivers use this host's test certificate, thumbprint `A9AC395295077F70BF59D244502FA83C321F1131`, which differs from v0.0.35's signer. Public `.cer` files are packaged; private keys are excluded. The certificate is a lab test signer, not a production-trusted signature, and test-signing requirements still apply.
- KMON remains bounded and sampled. Large background sweeps can remain incomplete, capture exclusions and dynamic-relocation gaps remain visible, and observed coverage varies between runs. Zero misses or false positives in the documented controls does not establish complete host coverage or maliciousness of other code differences.
- The dated live results cover the recorded Windows hosts, including build **28000.3231**. They do not establish protected-game compatibility, Driver Verifier/reboot stress, or arbitrary long-running schedules. Supervisor termination and an OS stop are outside the test runner's service-recovery guarantee.
- Experimental raw `!kmon iotrace` retains its documented unload-safety exception. Earlier incomplete Fast I/O/process-read coverage and WinHTTP Event-handle retention observations are not promoted to resolved by this release.

## Validation evidence

The [KMON background-image report](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_LARGE_BACKGROUND_VALIDATION_20261024.md) records repeated full-process runs with 13 controls and actual System.Data.dll views, including the remaining gaps. The [native-feature report](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/NATIVE_FEATURE_VALIDATION_20261024.md) and [pending-I/O lifetime report](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/PENDING_IO_LIFETIME_VALIDATION_20261025.md) preserve the two development crashes, their distinct causes, and the corrections.

The latest [query/runner-failure matrix](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/PENDING_QUERY_FAULT_REVIEW_20261025.md) records **1,034 ordinary checks**, **50 verified injected failures**, and **344 balanced final unload ledgers**. It observed no new reboot, dump, or remaining owned driver/service/process during its stated interval. These are source-development observations on the binaries identified in each report, not a claim that every historical run used the newly versioned release package.

Fresh checks on the **0.0.36 Release x64 binaries**, on Windows build **28000.3231**:

| Check | Result |
| --- | --- |
| Build, PE versions, and driver signatures | Passed; matching 0.0.36 components, with the intentional BYOVD fixture version exception |
| `--self-test all` | Timeline 28, MCP catalog 89, console 558, commands 2,961, remote protocol 66, and connect-argument checks passed |
| Parser and completion with AddressSanitizer | 275,002 parser and 25,954 completion checks passed |
| KMON component checks with AddressSanitizer | Hunting 11,326, pages 54, false-positive controls 49; malformed replay inputs rejected and owned-process controls passed |
| Evidence validators | Minifilter/research-ledger validator self-tests and capture-accounting, image-name, vctip-audit, and image-coverage tests passed |
| Actual managed/pending/query fixture runs | 280 ordinary checks and 57 balanced final unload ledgers, including the failure-supervisor runs |
| Failure supervisor | All 10 expected failure stages verified, including abrupt runner exit and service recovery |

The release-candidate host audit covered **2026-10-25 22:00:57–22:09:36 KST**. Boot time was unchanged, with no new bugcheck/reboot events, minidumps, or remaining owned drivers/services/processes in that interval. These fresh fixture and component tests are separate from the earlier full-process KMON matrix.

## Package

`KnLiveDbg-0.0.36-Release-x64.zip` contains the console, matching main/probe/fixture drivers, Bind controller, Debugging Tools runtime, available PDBs, public certificates, user-mode fixtures, operator scripts, license notices, and public guides. `kn-live-dbg-version.json` records each manifested file's size and SHA-256. `SHA256SUMS.txt` provides the ZIP checksum. Live validation reports and the Python lifecycle race suites remain in the source repository.

Operator guides:

- [KMON evidence and coverage](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_DETECTION_VERIFICATION.md), [callback surfaces](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_ANALYST_SURFACES.md), and [process layout history](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/KMON_PROCESS_LAYOUTS.md).
- [Architecture](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/ARCHITECTURE.md), [current source test checklist](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/MANUAL_TEST_CHECKLIST.md), and [external callback lifetime limits](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/EXTERNAL_CALLBACK_LIFETIME_REVIEW_20261025.md).
- [Remote console](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/REMOTE_OPERATOR_SESSION.md) and [MCP setup](https://github.com/kernullist/kn-live-dbg/blob/v0.0.36/docs/MCP_SETUP.md).

[Full comparison: v0.0.35...v0.0.36](https://github.com/kernullist/kn-live-dbg/compare/v0.0.35...v0.0.36)
