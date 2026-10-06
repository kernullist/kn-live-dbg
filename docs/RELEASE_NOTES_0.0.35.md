# KnLiveDbg v0.0.35

This release collects the changes after [v0.0.34](https://github.com/kernullist/kn-live-dbg/releases/tag/v0.0.34). It integrates the continued KMON collectors, fixes transport and cleanup failure paths, incorporates repairs verified on a test-signed Windows host, and refreshes help, completion and operator documentation.

## Changes since v0.0.34

- **Continued collection and current identities:** bounded kernel-image, orphan-page, mapper, callback, handle, pending-IRP and WNF collection resumes beyond individual pass limits. Deferred observations and captures retain process creation time, native 64-bit handles and address-space identity. PID reuse, driver reloads, stale TI generations, event loss and ambiguous ordering invalidate old evidence. CLR runtime provenance and platform CI/TPM/configuration observations have explicit health and trust limits.
- **Integrity and coverage:** disk comparisons use independently validated PE layouts and relocation metadata. Live-boot image-base differences no longer suppress comparable kernel checks. Fast I/O tables are validated as data before checking their callback targets; unknown table tails remain incomplete. Driver JSON exposes aggregate, dispatch and Fast I/O coverage, and Deep hunt propagates failed or incomplete driver inspection. CI cache entries have distinct identities so self-comparison works.
- **Normal-host findings:** narrow ownership checks distinguish normal CFG image pages, CLR mappings, registered package DLLs and verified Microsoft runtime paths from unexplained executable memory. Unchanged disk scalar values are excluded from raw call-table findings only with complete relocation and mutable-range evidence. KMON no longer labels an ordinary DLL as private PE when its current MEM_IMAGE allocation and backing file match a complete loader inventory. Modified code, IAT changes, private/mapped executable regions and unknown ownership remain checked.
- **Watch scheduling and fixtures:** up to four explicitly watched processes receive the first slots in the six-priority/two-background inspection budget; separate cursors retain progress for other candidates. The orphan-image fixture now verifies executable section creation and complete writes. Ghost fixtures require actual path absence, and malformed or overflowing hold times fail before side effects. Owned-process waits retain the creation handle across PPL transitions and distinguish exit code 259 from a running process.
- **Driver and transport failure paths:** driver/IOCTL ownership, bounds and response handling are tightened, including the `IoDriverObjectType` indirection used by I/O tracing. Remote sends have bounded deadlines, UTF-8 output limits and separately chunked stdout/stderr. MCP/remote JSON rejects malformed framing and inputs. AI HTTP requests keep credentials and bodies at the intended origin by disabling automatic redirects. Firewall COM initialization and property failures are handled consistently.
- **Persistence and cleanup:** wrapping dump ranges fail before output truncation. Cloak configuration binds session identity, service images and owned artifact paths; partial cleanup errors remain visible. TI, snapshot and text exports propagate partial-write, flush and close failures.
- **Help and completion:** `dt`/`dtx` flags, logging aliases and `!module`/`!driver` action scopes follow the actual command grammar. Type lookup uses already loaded PDBs unless a module is explicitly qualified. Help describes driver coverage, KMON budgets and native backend precedence. Startup help includes `platform-query` and retains its driver-free behavior.
- **Matching driver symbols:** the main driver now writes `KnLiveDbgDriver.pdb`, while the console keeps `KnLiveDbg.pdb`. The shared output directory no longer lets one linker overwrite the other's symbols. Both PDBs are required release files.
- **Release contents:** the clean-host runner's `owned-process-wait.ps1` dependency is included. The ZIP contains operator guides and these release notes; validation reports and review records are excluded.

## Compatibility and limits

- The user/kernel ABI remains **17**. Use the matching **0.0.35** EXE, main driver and probe from this package. The benign BYOVD metadata fixture intentionally retains version **1.0.0.0**; its name/version metadata is a positive control, not a malicious driver.
- Builds use Visual Studio 2022 and SDK/WDK **10.0.26100.0**. The x64 drivers use the existing host test certificate, thumbprint `E269E2D141C692DAA047F0DA14ABB1D7690CD1AF`. Matching public `.cer` files are packaged; private keys are excluded. This signer differs from v0.0.34's lab signer. Test-signing requirements still apply, and the package has no production signing claim.
- On Windows 11 Pro **10.0.28000**, unsupported Ntfs Fast I/O and process-read coverage remain incomplete. A zero-finding Deep+TI run is not a complete-clean result; check `coverage_complete` and `all_clean_complete`.
- Minifilter detach, Bind/QoS, TPM/TBS, external KD and AI-provider behavior depend on host capabilities, permissions and configuration. Protected-game compatibility, Driver Verifier/reboot stress and long-running false-positive behavior are not established by this release.
- Experimental raw `!kmon iotrace` retains its documented unload-safety exception. Bounded sampled collection cannot establish complete execution history, universal zero false positives or absence of hidden code. Host-level WinHTTP Event-handle retention remains an unresolved compatibility observation from the earlier review.

## Package

`KnLiveDbg-0.0.35-Release-x64.zip` contains the console, matching main/probe/fixture drivers, Bind controller, Debugging Tools runtime, available PDBs, public certificates, user-mode fixtures, operator scripts, license notices and public guides. `kn-live-dbg-version.json` records each packaged file's size and SHA-256. `SHA256SUMS.txt` provides the ZIP checksum.

Operator guides:

- [KMON evidence and coverage](https://github.com/kernullist/kn-live-dbg/blob/v0.0.35/docs/KMON_DETECTION_VERIFICATION.md), [callback surfaces](https://github.com/kernullist/kn-live-dbg/blob/v0.0.35/docs/KMON_ANALYST_SURFACES.md) and [process layout history](https://github.com/kernullist/kn-live-dbg/blob/v0.0.35/docs/KMON_PROCESS_LAYOUTS.md).
- [Remote console](https://github.com/kernullist/kn-live-dbg/blob/v0.0.35/docs/REMOTE_OPERATOR_SESSION.md) and [MCP setup](https://github.com/kernullist/kn-live-dbg/blob/v0.0.35/docs/MCP_SETUP.md).

[Full comparison: v0.0.34...v0.0.35](https://github.com/kernullist/kn-live-dbg/compare/v0.0.34...v0.0.35)
