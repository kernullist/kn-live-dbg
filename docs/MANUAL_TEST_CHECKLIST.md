# Manual Test Checklist

This document separates driver-free regression gates from live-kernel
validation on a test-signing VM. Parser, dispatch, and transport checks run
without loading the driver. Kernel behavior and false positives still need
observation against a running kernel.

Check an item off only after it passes on a clean machine. A failure on a clean
machine means a false positive (or a layout/assumption bug) and must be fixed
before the feature is trusted.

## Driver-free regression gate (2026-09-20)

```powershell
.\x64\Release\KnLiveDbg.exe --self-test all
.\x64\Debug\KnLiveDbg.exe --self-test all
.\tools\validate-command-audit.ps1 -Sanitize
.\tools\validate-command-audit.ps1 -Configuration Debug -Sanitize
.\x64\Release\KnLiveDbg.exe --self-test mcp-http
.\x64\Debug\KnLiveDbg.exe --self-test mcp-http
.\tools\validate-kmon-core.ps1 -Sanitize
.\tools\validate-kmon-core.ps1 -Configuration Debug -Sanitize
.\tools\validate-kmon-hunting.ps1 -Sanitize -PeSieve C:\tools\pe-sieve64.exe
.\tools\validate-kmon-hunting.ps1 -Configuration Debug -Sanitize -PeSieve C:\tools\pe-sieve64.exe
```

The [command audit](COMMAND_AUDIT_20260919.md) records the initial results; the [Kmon review](KMON_ADVERSARIAL_REVIEW_20260920.md) records the later command/page extensions. Build-time validators require the source tree and compiler. Release artifact checks are listed in the [v0.0.33 release notes](RELEASE_NOTES_0.0.33.md).

| Suite | Checks per Release/Debug configuration |
| --- | ---: |
| `commands` | 1,993 |
| `console` | 524 |
| `timeline` | 28 |
| `mcp-tools` | 75 |
| `remote-protocol` | 52 |
| `connect-argv` | 4 |
| `mcp-http` (separate) | 9 |
| Standalone parser with AddressSanitizer | 275,002 |
| Kmon hunting / page coverage with AddressSanitizer | 11,326 / 54 |
| Kmon core groups with AddressSanitizer | 7 |

`--self-test all` runs the first six suites before elevation, driver loading,
and symbol initialization. `mcp-http` requires HTTP.sys URL registration
rights and runs separately. Run network fixtures sequentially: remote binds
`127.0.0.1:51767`, HTTP binds `127.0.0.1:51768`. Neither opens an external
listener or adds firewall rules. The sanitizer script instruments the
standalone parser; its executable command checks use the normal build.

These results do not check off any live-kernel item below. Live writes,
collector/load/unload races, and an external DbgEng target remain separate
VM or hardware tests.

## Prerequisites

1. Windows 10/11 x64 VM in test-signing mode (`bcdedit /set testsigning on`,
   reboot), or a production-signed driver.
2. Run from an elevated console:
   ```
   cd .\x64\Release
   .\KnLiveDbg.exe
   ```
3. Confirm startup reaches the `knkd>` prompt with the driver loaded, the device
   open, ABI verified (version 17), and `nt` kernel symbols resolved (the
   dashboard shows symbol state; if `symType=0 (SymNone)`, fix the symbol path
   before running symbol-dependent checks).

## Kernel-driver hiding layers (`!kmon`)

These checks need a live kernel, because the layers read kernel memory through
the driver. Synthetic-input coverage lives in the console self-test
(`kmon-thread-classification` and `kmon-classification`); the items below are
the on-machine behavior that the self-test cannot prove.

1. With `!kmon /background` armed on a clean host, confirm the new layers stay
   quiet: no `hook.inline` / `hook.breakpoint`, no `thread.unbacked` /
   `thread.hidden` / `thread.dkom`, and no `pool.hidden` / `mapper.stub` on an
   idle machine with no mapper load.
2. Confirm the deferral path instead of a verdict when a view is unavailable
   (stop the driver or clear symbols mid-run): `scan_failed:thread:*`,
   `scan_failed:patch:*`, `scan_failed:mapperpool:table`, and `scan_failed:mapperpool:modules` each print once,
   the matching verdicts stop instead of firing, and the diagnostics clear once
   the view is restored. `thread.scan`, `hook.scan`, and the
   `coverage:patch:*` markers record a deferred pass, while an unreadable region
   body in the stub layer simply produces no verdict.
3. Confirm the two-pass rule: a mapper/watch window shorter than two scan
   intervals must not produce `thread.hidden`, `thread.dkom`, or a `hook.inline`
   verdict, and an ordinary kernel hotpatch (in-module destination) or an inbox
   win32k forwarder must never print. A thread whose start address no loaded
   module owns prints on its first confirming pass, so that form is expected
   without waiting for a second interval.
4. Confirm `help !kmon` lists `hook.inline`, `hook.breakpoint`, `hook.scan`,
   `thread.unbacked`, `thread.hidden`, `thread.dkom`, `thread.scan`,
   `pool.hidden`, and `mapper.stub`, and that `x64\Release\KnLiveDbg.exe
   --self-test console` passes on the VM too.

## Whole-host hunt negative control

From the repository root, the repeatable clean-host gate is:

```powershell
.\tools\validate-hunt-clean-host-selftest.ps1
.\tools\run-hunt-clean-host.ps1 -Mode Default -Count 3 -RequireClean
```

The first command is driver-free and validates the validator itself. The second
requests elevation, disables the driver write gate before scanning, captures
JSON and transcripts under `.build\hunt-clean-host`, and requires zero findings
with complete process/triage coverage on every run. It also requires the
`KnLiveDbg` service to be absent after each session.

When a baseline emits findings, group repeated and intermittent evidence before
changing a detector:

```powershell
.\tools\analyze-hunt-clean-host.ps1 `
  -HuntJson .\.build\hunt-clean-host\hunt-clean-default-*.json `
  -OutputJson .\.build\hunt-clean-host\analysis.json `
  -OutputMarkdown .\.build\hunt-clean-host\analysis.md
```

For complete `/deep` coverage, use:

```powershell
.\tools\run-hunt-clean-host.ps1 -Mode Deep -EnableThreatIntel -Count 3 -RequireClean
```

`-EnableThreatIntel` temporarily enables writes only to apply
`set-ppl-antimalware` to the KnLiveDbg process and start TI collection. The
runner turns writes off before executing `!hunt`, stops TI, unloads the driver,
and exits. An active, readable TI ring is valid even when a clean interval
contains zero events; an unavailable/inactive subscription still makes deep
coverage incomplete and the clean-host validator rejects the result.

## M2 - CPU-state detection (clean-box expectations)

On a clean machine every command below must report **no `[SUSPICIOUS]`**. A
suspicious row on a clean box is a false positive to fix.

### `!msrcheck`  (commit a92d0fe)
- Expect `msr syscall-config cpus=N` with no `[SUSPICIOUS]`.
- `IA32_LSTAR` -> `module=ntoskrnl.exe symbol=KiSystemCall64` or `KiSystemCall64Shadow` when KVA shadow is active.
- `IA32_EFER` -> `SCE=1`.
- All per-CPU values identical (no `per-cpu:` divergence line).
- Confirm: (a) the active regular or KVA-shadow entry symbol resolves (when neither resolves,
  the module-containment fallback is exercised - still expected clean); (b) `IA32_CSTAR` shows the
  `CSTAR is 0 (compat-mode SYSCALL unused)` note on Intel (no false positive);
  (c) no spurious divergence flag.

### `!cr`  (commit 4be8ca0)
- Expect `control registers cpus=N` with no `[SUSPICIOUS]`.
- `CR0` -> `WP=1`.
- `CR4` -> `SMEP=1 SMAP=1` on modern hardware.
- Confirm: SMEP/SMAP-off on legacy hardware prints only a `note:` (not
  `[SUSPICIOUS]`); no per-CPU divergence flag.

### `!ssdt`  (commit 57e01e6)
- Expect `ssdt tables=1` (or `2` if win32k is loaded) with no `[SUSPICIOUS]`.
- Native table: `count`~`0x1d0`-`0x200`, line `all N service routines resolve
  into ntoskrnl.exe`.
- Confirm: (a) `nt!KeServiceDescriptorTable` resolves and Base/Limit read sanely
  (no absurd count -> descriptor offset fallback OK); (b) the win32k shadow
  table is either walked clean (all routines in `win32k*`) or reports the
  `win32k modules not loaded; shadow SSDT validation skipped` warning - never a
  false-positive storm.

### `!idt`
- Expect `idt cpu=0 base=... entries=256` with no `[SUSPICIOUS]`, plus
  `all present interrupt handlers resolve into loaded kernel modules`.
- Confirm: (a) IDT base reads as a kernel-canonical address and `entries=256`;
  (b) no present gate is flagged on a clean box (handlers live in ntoskrnl/hal).
- Confirm cross-processor comparison across all processor groups. A failed read,
  mismatched processor identity, invalid/different table length, or scan cap at
  256 processors must report incomplete coverage instead of a complete clean scan.

### CPU-state in snapshot / diff
- `!snapshot baseline` on a clean box, then `!snapshot show baseline /domains` shows a
  `cpu-state` domain with info-risk records (MSR values, CR0/CR4, SSDT/IDT
  fingerprints) and no high-risk records.
- `!diff baseline` immediately after (same boot, unchanged) reports no cpu-state
  changes.
- Confirm: a later SSDT/IDT/MSR/CR change within the same boot surfaces in
  `!diff baseline` as a cpu-state escalation (value/fingerprint change), and a
  new hook appears as a high-risk added `cpu-state` record.

## Leftover payload detectors

On a clean machine these commands must not invent a live mapper. Coverage
warnings for unresolved private symbols are acceptable; fabricated hook
bodies or a flood of `SUSPICIOUS` rows are not.

These are separate detection layers. A quiet result on one layer is not a
clean bill on the others:

- `!byovd` = loaded BYOVD (signed exploit driver still mapped)
- `!mapper` = bookkeeping remnants (PiDDB / unload log / ci hash)
- `!kpage` = orphan executable pages (independent-page payload)
- `!payload scan` = hook-to-body (off-module function pointers)
- `!pool pe` = staged pool PE
- `!snapshot` `leftover-mapper` = temporal bookkeeping only; it does not
  run `!kpage` or `!payload scan`

`help !mapper` / `help !payload` / `help !kpage` must name those layers.
`leftover=0` on a clean box is expected and is not "no mapper".

### `!payload` / `!payload scan`
- `help !payload` shows `scan`, `/limit`, `/disasm`, `/json`, `Layer: hook-to-body`,
  and the example `!payload scan`.
- `!payload nt!KiSystemCall64` classifies `inside_module` / risk `low`.
- `!payload scan` may take a while. Expect `unique=0 traced=0` on a clean box,
  or only coverage warnings from an incomplete hook surface. No high-risk
  unbacked PE/`W+X` traces.
- Confirm Tab completion offers `!payload`, `scan`, `/limit`, and
  `help !payload`.

### `!mapper` / `!unloaded` / `!piddb` / `!cihash`
- `help !mapper` mentions `MmUnloadedDrivers`, `PiDDBCacheTable`,
  `ci!g_KernelHashBucketList`, and `Layer: bookkeeping remnants`.
- `!mapper` on a clean box may list historical unload rows (`REUSED` /
  `RELOAD` / `xN`). Boot leftovers explained by the unload log or `dump_*`
  are `EXPECTED` and omitted from default output. `STALE` is a name that is
  still leftover after that filter. `SUSPICIOUS` requires a wiped name,
  TimeDateStamp 0, or an unloaded range that is still present+executable
  and not reused.
- `piddb=.../avl` or `/list` with `leftover=0` and `hash=... leftover=0` is
  the clean-host shape. Do not treat that as mapper-payload absence.
- `!snapshot show baseline /domains` includes `leftover-mapper` after a full
  baseline. It must not include a leftover-pages/`!kpage` domain.

### `!kpage`
- `help !kpage` shows `/deep`, `/wx`, `/pe`, `/session`, `/nosession`, and
  `Layer: orphan executable pages`.
- Bare `!kpage` may emit session-space `low` rows. High-risk requires `W+X`
  or a PE header outside every loaded module.
- Do not treat `/deep` as the default; run it once and confirm it is slower
  and still fail-closed if `_MMPFN.PteAddress` is missing.

## Minifilter IRP control

### `!minifilter`
- `help !minifilter` shows `list`, `show`, `disable`, `disable-all`, `enable-all`,
  `IRP_MJ_CREATE`, `disable UnionFS all`, and `disable-all UnionFS`.
- Tab after `!minifilter` offers `disable-all` / `enable-all`. Tab after
  `!minifilter disable` offers `all` and `IRP_MJ_CREATE`. Tab after
  `help !minifilter` offers `disable-all`.
- `!minifilter` on a clean box lists inbox filters (FileInfo, WdFilter, ...) with
  no crash and `complete=yes` when fltmgr symbols loaded.
- `!minifilter show FileInfo` prints IRP slots; CREATE/CLEANUP should be active.
- `!minifilter disable <lab-filter> CREATE` without `write on` must fail.
- `!minifilter disable-all <lab-filter>` without `write on` must fail the same way.
- After `write on`, disable then enable of a lab/test filter must restore the
  same pre/post pointers. `disable-all` then `enable-all` must restore every
  slot this session disabled. Do not disable WdFilter on a production box.

## WFP kernel callouts

### `!wfp kernelcallouts`
- On a clean box expect `wfp kernel callouts count=N array=... layout=...` with a
  plausible count (tens to low hundreds) and no `[SUSPICIOUS]`; most classify
  pointers resolve into `netio.sys` / `tcpip.sys` / `mpsdrv.sys` / `wfplwfs.sys`
  / `fwpkclnt`-style modules, with callout name/layer/provider metadata joined.
- Confirm: (a) `netio!gWfpGlobal` resolves (netio.sys symbols downloaded); if not,
  the command prints a clean "unresolved" message rather than fabricating; (b)
  the chosen `layout=` matches one of the documented candidates (or the scored
  fallback) and the count/array look sane; (c) no false-positive hooks on a clean
  box. **The netio.sys callout-table offsets are build-dependent** -- if the count
  is absurd or classify pointers do not resolve into modules, the offsets need RE
  refinement for this build (compare `dx @$cursession`/WinDbg against
  `gWfpGlobal` and adjust the candidate layouts in `WfpCalloutScanner.cpp`).
- Cross-reference callout ids with `!wfp callouts` to confirm the metadata join.

## M1 - reliability / security

### Nested `FindField`  (commit 7e102dc)
- `dt nt!_EPROCESS Pcb.DirectoryTableBase` resolves a nested field offset (no
  "Field was not found").
- `!ti start` still passes its PPL-Antimalware precondition gate (it now reuses
  the canonical DTB resolver, which depends on nested-field resolution).

### Provider-agnostic transcript redaction  (commit 7e102dc)
- With `ai transcript redact on`, capture output containing a fake
  `Authorization: Bearer eyJabc.def.ghi` and confirm the token does not appear
  in the transcript JSONL (shows `Authorization: <redacted>` /
  `Bearer <redacted>`), in addition to the existing `sk-` redaction.

### NmiScanner LayoutResolver fallback  (commit ca33c97)
- `!nmi callbacks` still lists NMI handlers with module/symbol annotation.
- On public PDBs (which omit `KNMI_HANDLER_CALLBACK`) expect the one-time
  warning `KNMI_HANDLER_CALLBACK layout resolved from guarded fallback offsets`.

## Kernel-cheat monitor (`!kmon`)

Requires `write on`, an open driver device, and PPL Antimalware (the command
flips it if needed). Bare `!kmon` arms silent TI + kernel live callbacks and
stays on the live tail.

### Clean-box idle

1. `write on` then `!kmon /background`.
2. Wait ~20s (kpage/CPU scan cadence). `!kmon recent 20` should show
   `gap.kernel_rw` once and otherwise stay quiet on a clean idle host.
   Inbox `System32\drivers` loads must not print unless `/verbose`.
3. Esc/q is not needed in background mode. `!kmon` attaches the tail;
   Esc detaches and collection keeps running. `!kmon stop` ends derived
   logging and leaves TI / timeline live up.
4. `!kmon add /name game.exe` before start must be refused. After start,
   `add` / `remove` work; a later `!kmon /name notepad.exe` extends watches.
   `/verbose` on a second start must warn that it applies only on first start.

### User-mode hostility fixture

Build `x64\Release\tools\KnLiveDbgKmonTarget.exe` from the solution, then in a
second console:

```powershell
.\x64\Release\tools\KnLiveDbgKmonTarget.exe /overwrite /seconds 60
```

Attach `!kmon` and expect `process.hollow` with `exe_cow` and/or `exe_text`
within ~8s (`image=notepad.exe` under `%TEMP%\kn-live-dbg-kmon\`). Repeat with
`/masquerade`, `/stamp`, `/nomz`, `/orphan-private`, `/orphan-image`,
`/replace-main`, `/ghost`. Operator steps: `docs/KMON_TEST_TARGET.md`.

The fixture must not touch inbox `notepad.exe` / `svchost.exe`. `/replace-main`
must stay suspended.

### Driver-free gate

```powershell
.\x64\Release\KnLiveDbg.exe --self-test all
```

The combined gate runs timeline, MCP, console, remote-protocol, and connect-argv tests.
It covers malformed JSON/UTF-8, complete bounded HTTP request bodies, AI response
and CLI output limits/deadlines, credential-preserving rejection of HTTP redirects,
dump paging entries, PE header mutations, and
MSR/IDT compatibility boundaries without loading the driver.

`kmon-artifact-primitives` and `kmon-hidden-driver-regression` must pass. The
COW half shares one sled-length contract with the fixture
(`kmon_test_target/KmonTestTargetContract.h`), so a sled shorter than the
contract fails the case instead of silently skipping it, and a skipped
cross-process half prints exactly one reason line (fixture missing,
`CreateProcessW` failed, `OpenProcess` refused, PEB ImageBase unreadable,
contract sled never observed, child exited before the COW sample). That does not replace the live `!kmon` pass.

### Still manual

- In a disposable VM, short output buffers for timeline control, write mode,
  virtual/physical writes, and flush must fail before changing state or memory.
- Open two controller handles: closing the first must preserve tracing; closing
  the last must unregister live callbacks and release ownership after cleanup.
  Concurrent opens during cleanup must fail with `STATUS_DEVICE_BUSY`.
- Exercise MDL fallback under mapping teardown and Driver Verifier in a VM.
  Driver-free tests do not validate kernel races or the raw IRP hook unload limit.
- On an HTTP.sys test host, send headers exceeding the MCP receive buffer both
  before and after the listener starts waiting; both paths must return HTTP 431.

- Game + anti-cheat idle FP soak (Program Files EAC/BE/Vanguard `drop_load` is
  expected; overlay `inject.remote` should stay off until `/name game.exe`).
- Live DKOM `ActiveProcessLinks` unlink (no kernel hide fixture yet).
- Live post-load driver hiding (module-list unlink, a query-filtered module
  view, a cut `\Driver` link, or an anonymous `DRIVER_OBJECT`): the host-side
  diff, the kernel-context cross view, the loader-chain check, and the
  `_OBJECT_TYPE.TypeList` sweep are exercised by the synthetic
  `kmon-hidden-driver-regression` self-test instead of a kernel fixture.

## Positive controls (optional)

- For SYSCALL/IDT/SSDT hook detection there is no built-in benign fixture yet.
  To exercise the suspicious path safely, a future probe-driver fixture could
  install a self-removing hook; until then, validation relies on the clean-box
  negative result plus code review of the suspicion logic.

## Write-path safety (C5/C6)

- **AI/MCP backup failure:** make the intended backup destination unwritable
  in a disposable VM, then attempt a planned memory write. Confirm the command
  fails before mutation and the original bytes remain unchanged. Restore the
  destination and verify the normal backup/write/read-back sequence.
- **MCP response timeout:** queued requests must report cancellation before
  execution and must not run later. Already-dispatched requests report an
  unknown outcome; inspect the target and audit trail before retrying a write.
- **Read-back verification (C5):** a normal `e*` / `eb`/`eq` write to a 4 KB-mapped
  address still succeeds and the value is confirmed (a silent dropped write now
  surfaces as `write verification failed ...`). Smoke test with `write on` then
  e.g. `eb <writable-kernel-or-process-addr> AA` and confirm the byte reads back.
- **Large-page write fail-fast (C6):** writing through a read-only large-page
  (2 MB/1 GB) mapping is refused with `refusing to write through a read-only
  large-page (pde|pdpte) mapping ...` instead of flipping a shared parent
  entry's write bit. (Hard to trigger on demand; verify the message appears if a
  large-page target is hit, and that normal 4 KB writes are unaffected.)

## Remote operator session

Same-box (driver loaded on A):

1. `remote on --loopback`, password `abcde` accepted, `abcd` rejected.
2. From a second console: `KnLiveDbg.exe --connect 127.0.0.1:51767`.
3. B Tab expands `rem` to `remote` and lists `!callbacks` scopes the same way as local `knkd>`.
4. B `dt nt!_EPROCESS` prints type layout. B `q` disconnects without unloading the driver on A.
5. B `unload` / `kd r` / `probe load` / `mcp on` return `denied`.
6. B `eb <addr>` with no bytes returns `supply values on the command line`. `eb <addr> 90` writes when write mode is on.
7. A `off` then Enter returns to local `knkd>`. Firewall rule `knlivedbg-remote` is absent after `--loopback`.

Two-PC LAN:

1. A `remote on` (no extra flags) prints a reachable IPv4 and `cleartext=true`.
2. B `--connect <that-ipv4>:51767` with the session password.
3. Confirm inbound rule `knlivedbg-remote` exists while listening and is gone after `remote off`.

Driver-free: `.\tools\validate-remote-protocol.ps1 -Configuration Release`.
Both remote suites also run in `--self-test all`. The loopback corpus covers
queued cancellation and stop without waiting for the engine to drain the queue.
On a live target, also verify command errors reach B as `command-failed` and
address-only physical edits (`pe*`) fail without waiting for stdin.

## Collector and shutdown lifecycle

- Start `!kmon`, TI, and the timeline collector, then exercise normal `q` and
  `unload` paths in a disposable VM. Collectors must stop before the device
  closes; repeat startup/stop to catch stale handles and worker lifetimes.
- During an I/O-trace disarm failure, confirm the device remains open for a
  retry and normal `q`/`unload` does not report successful cleanup. Resolve the
  failure and retry. Exercise active traced dispatch during driver unload;
  dispatch code must remain resident until those calls finish.
- Toggle `log enable` / `log disable` repeatedly within one second, including
  an executable directory with non-ASCII characters. Each session must retain
  a distinct `KnLiveDbg-YYYYMMDD-HHMMSS-<pid>-<sequence>.log` file.

## Deferred

- 1B `IsValidKernelPointer` retrofits -- assessed low value: the existing
  `>= 0xffff800000000000` canonical check is already correct for LA48, data-
  pointer dereferences fail safely through the driver's MmCopyMemory, and code-
  pointer module containment already exists per-scanner via FindOwningModule. A
  shared helper would be a DRY refactor, not new detection. Revisit only if
  consolidating the duplicated containment checks.
- GDT integrity (`!gdt`); WMI/TraceLogging provider scanner; tool self-protection
  (randomized device/service names, IOCTL session nonce, driver self-integrity).

See also the plan at
`C:\Users\kernulist\.claude\plans\crispy-sauteeing-sky.md`.

## September 2026 kmon live validation gate

These checks are pending for the hardening described in
[KMON_IMPLEMENTATION_2026-09-16.md](KMON_IMPLEMENTATION_2026-09-16.md). Driver-free console,
timeline, protocol, and fixture tests do not satisfy this gate.

1. Use an isolated Windows 10 and Windows 11 test machine with a recoverable
   snapshot. Record OS build, symbol/PDB identities, binary hashes, HVCI state,
   scan budgets, and test-driver identity with each result.
2. Start and stop timeline collection repeatedly under Driver Verifier in the
   test VM. Exercise process/image/thread activity during unregister and verify
   no IRQL or lock diagnostics. Verify reset produces no events from the old
   ring and no old two-strike confirmations after restarting `!kmon`.
3. Use a controlled kernel fixture with ground-truth allocation addresses to
   validate independent pages, nonpaged pool, large-page module overlap, and
   headerless RX bodies beyond the first 16 KB. Confirm eventual window visits,
   correct PFN/effective permissions, and explicit partial coverage under caps
   or unavailable pages. Do not interpret an NX negative as proof of absence.
4. Validate each supported callback family and both available DPC layouts.
   Compare a legitimate in-module target and a legitimate loaded-module tail
   call against a controlled static redirect to fixture-owned orphan code.
   Require two matching redirect observations. Change, remove, or make the
   target unreadable between passes and confirm that previous strikes expire.
5. Run the user fixture modes, including `/orphan-mapped-rx` and the
   `/mapped-readonly` negative control. Save actual emitted events with PID,
   creation time, allocation base, protection, module-view coverage, and bytes
   read. Exercise access-denied and process-exit races; neither is a ghost or
   an automatic implant finding.
6. Stress process, thread, and VAD counts beyond the per-pass budgets. Confirm
   that later targets and thread starts eventually receive work, and that VM
   and thread sampling do not require their independent cursors to coincide.
   Reuse PIDs/TIDs and verify generation changes cannot inherit cursor/strike
   evidence.
7. Run browser/.NET JIT workloads, signed overlays, game anti-cheat, driver
   updates, and normal hotpatch activity as negative controls. Record per-layer
   candidate counts, unexplained alerts, scan latency, and coverage gaps before
   asserting an operational false-positive rate. Keep all unperformed cases
   explicitly marked unverified.
8. Exercise session/CR3 changes, repeated PFN continuation, allocation interiors,
   executable virtual tails, and graphics slot tails with controlled ground
   truth. Remove/reinsert modules before saved cursors and verify remaining
   targets receive work. Record read failures and eviction coverage separately
   from an observed clean page.
9. Collect local/remote TI protection events together with VAD snapshots during
   release/reallocation and delayed delivery. Preserve original event times and
   query intervals; verify that overlapping intervals or new allocation
   lifetimes cannot manufacture an NX-to-RX transition. Restart TI twice during
   an ingest pass and verify generation, loss and receipt-health reporting.
10. Populate more than 4096 handles and more than 32 TLS/VEH/VCH records in a
    controlled process. Exercise budget-boundary retries, owner churn and PID
    reuse. Compare the recorded target object relationships with fixture truth.
11. Compare supported callback/attachment/WFP policy lifecycle events with
    registrations made by controlled fixtures. Revoke access and unload the
    fixture between reads; incomplete snapshots must not prove disappearance.
12. Save `KnLiveDbg.exe --self-test platform-query` output and independently
    compare CI, CiTool and TBS observations. An unconfigured external verifier
    must keep `attestation.trusted=false`. Enrollment, TPM quote/PCR validation,
    device/AK binding and replay controls require a separately configured
    verifier before any trusted platform claim.

## Validation log

- **2026-06-15, Windows 11 (4 logical processors), test-signing VM** -- all
  CPU-state commands returned false-positive 0 on a clean box:
  - `!idt`: 256 entries, all present handlers in loaded modules.
  - `!ssdt`: native 489 routines in ntoskrnl.exe; win32k shadow 1493 in win32k*.
  - `!cr`: CR0.WP=1, CR4 SMEP/SMAP/UMIP=1, LA57=0, no per-CPU divergence.
  - `!msrcheck`: LSTAR=KiSystemCall64 or KiSystemCall64Shadow, CSTAR=KiSystemCall32, EFER SCE=1.
  - `!wfp kernelcallouts`: 86 callouts resolved with classify symbols and
    name/layer/provider metadata (tcpip/Ndu/mpsdrv/wtd/WdNisDrv). The build's
    callout layout was engine=`*gWfpGlobal` (deref), count@+0x198, array@+0x1a0,
    0x60-byte slots, classify@+0x10 -- now pinned as the first documented
    candidate, so subsequent runs hit the fast path without the fallback scan.
