# Manual Test Checklist

This document tracks the live-kernel validation that must be run on a
test-signing VM for the reliability and CPU-state detection work. The build
machine can only confirm that the code compiles and signs; correctness and
false-positive behavior must be observed against a running kernel.

Check an item off only after it passes on a clean machine. A failure on a clean
machine means a false positive (or a layout/assumption bug) and must be fixed
before the feature is trusted.

## Prerequisites

1. Windows 10/11 x64 VM in test-signing mode (`bcdedit /set testsigning on`,
   reboot), or a production-signed driver.
2. Run from an elevated console:
   ```
   cd .\x64\Release
   .\KnLiveDbg.exe
   ```
3. Confirm startup reaches the `knkd>` prompt with the driver loaded, the device
   open, ABI verified (version 10), and `nt` kernel symbols resolved (the
   dashboard shows symbol state; if `symType=0 (SymNone)`, fix the symbol path
   before running symbol-dependent checks).

## M2 - CPU-state detection (clean-box expectations)

On a clean machine every command below must report **no `[SUSPICIOUS]`**. A
suspicious row on a clean box is a false positive to fix.

### `!msrcheck`  (commit a92d0fe)
- Expect `msr syscall-config cpus=N` with no `[SUSPICIOUS]`.
- `IA32_LSTAR` -> `module=ntoskrnl.exe symbol=KiSystemCall64`.
- `IA32_EFER` -> `SCE=1`.
- All per-CPU values identical (no `per-cpu:` divergence line).
- Confirm: (a) `nt!KiSystemCall64` resolves (otherwise the module-containment
  fallback path is exercised - still expected clean); (b) `IA32_CSTAR` shows the
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
- Known limitation: only the boot processor IDT is walked; per-processor
  comparison is a future enhancement.

### CPU-state in snapshot / diff
- `!snapshot baseline` on a clean box, then `!snapshot show baseline /domains` shows a
  `cpu-state` domain with info-risk records (MSR values, CR0/CR4, SSDT/IDT
  fingerprints) and no high-risk records.
- `!diff baseline` immediately after (same boot, unchanged) reports no cpu-state
  changes.
- Confirm: a later SSDT/IDT/MSR/CR change within the same boot surfaces in
  `!diff baseline` as a cpu-state escalation (value/fingerprint change), and a
  new hook appears as a high-risk added `cpu-state` record.

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

## Positive controls (optional)

- For SYSCALL/IDT/SSDT hook detection there is no built-in benign fixture yet.
  To exercise the suspicious path safely, a future probe-driver fixture could
  install a self-removing hook; until then, validation relies on the clean-box
  negative result plus code review of the suspicion logic.

## Deferred (implement, then add tests here)

- C5/C6 kernel write-path: read-back verification and large-page write
  fail-fast (write path - validate in VM as it is implemented).
- 1B `IsValidKernelPointer` retrofits (VAD node / trustlet EPROCESS / WNF).
- Per-processor IDT comparison; control-register `!cr` on >64-logical-processor
  (multi-group) systems; SSDT/MSR coverage on multi-group systems.

See also the plan at
`C:\Users\kernulist\.claude\plans\crispy-sauteeing-sky.md`.
