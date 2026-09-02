# Driver Interaction Tracking — Design (Phase A/B implemented)

Goal: when `!kmon` watches a game-cheat loader by name, show how that loader
(and its auto-promoted children) interact with kernel drivers — which device
handles it acquires, when, and what can be inferred about the communication
channel — without destabilizing the host.

Status: **Phase A and Phase B.1 are implemented** (ABI 17, IOCTL 0x816/0x817).

## Why this is hard (hard constraints)

1. **ETW-TI has no DeviceIoControl.** The Threat Intelligence provider
   exposes process/thread/image/driver-object events and cross-process VM
   operations, not IOCTL traffic. `!kmon` already prints this as
   `gap.kernel_rw`.
2. **ObRegisterCallbacks only supports Process/Thread (and Desktop)
   object types.** A probe driver cannot strip or observe device-handle
   creation through object callbacks; there is no supported notify on
   `\Device\*` handle opens.
3. **Manually mapped drivers have no DRIVER_OBJECT at all.** kdmapper-style
   2nd stages never appear in the driver lists; the loader talks to the
   mapped code through (a) the vulnerable driver's IOCTL channel it used
   for mapping (BYOVD handle), (b) shared physical-memory windows, or
   (c) hooks that fire on their own. "Track the driver" for this class
   really means "track the channel and the effects".

## Phase A — watched-PID handle-table diffing (implemented, no driver change)

Observability without kernel interposition: periodically diff the watched
process's handle table and report new handles whose kernel object is a
Device or Driver.

- Implemented as `KernelMonitor::ScanWatchedHandleTables` on the ~8 s
  user-scan tick: `HandleTableScanner` per watched pid (max 8), silent
  first-pass baseline per pid, then `driver.handle` events for new
  (handle,object) pairs whose `ObjectTypeIndex` equals the Device type
  index learned once per boot from the client's own device handle
  (`DeviceClient::QueryDeviceObjectTypeIndex`; no NtQueryObject name
  queries, which can block on device objects).
- Evidence: handle value, object address, granted access, pid. Handle
  closes are not tracked. Scan failure is a `scan_failed:handles:<pid>`
  coverage note; a non-watched pid never emits.
- Known v1 limits (deliberate): device NAME resolution and BYOVD-list
  cross-referencing are follow-ups; use `!handles` / `!devstack` on the
  reported object address for manual triage. An open+close between two
  ticks is missed.

## Phase B — kernel-side IOCTL observability (B.1 implemented as `!kmon iotrace`)

Opt-in, lab-only: `!kmon iotrace <driver-name> on|off|status` resolves the
named driver's DRIVER_OBJECT via the `\Driver` object-directory walk
(`IntegrityScanner`, user mode — the driver never does name lookups), then
arms the probe driver (ABI 17, `IOCTL_KNDBG_IOTRACE_CONTROL` 0x816 with the
write ACK magic):

- The target's `MajorFunction[IRP_MJ_DEVICE_CONTROL]` is swapped to the
  probe's trampoline after SEH-validating `Type == IO_TYPE_DRIVER` and
  referencing the DRIVER_OBJECT with `ObReferenceObjectByPointer` so the
  target cannot be freed while the hook is live. The trampoline records
  caller pid, IOCTL code, and in/out lengths into a non-paged spinlocked
  ring (1024 records, allocated lazily on first arm) and passes the IRP
  through untouched.
- The kmon worker drains the ring (`IOCTL_KNDBG_IOTRACE_DRAIN` 0x817) and
  prints `driver.ioctl` events, first-seen per (pid, IOCTL code) with a
  256-entry cap, decoded into function/device-type/method plus lengths.
- DISARM restores the original entry, waits (up to ~400 ms, retried on
  unload) for in-flight trampolines to leave, and only then drops the
  reference; `!kmon stop` and driver unload disarm forcibly. If a dispatch
  stays stuck past the wait, disarm reports busy and keeps the reference
  rather than freeing under a live call.
- Risk statement: interposing a dispatch entry tampers with live kernel
  state and can crash the host if the target driver misbehaves; it is
  gated behind an explicit per-driver arm command and is intended for lab
  analysis of a captured loader, not for always-on monitoring.

## Acceptance criteria (Phase A)

- With `!kmon start /name loader.exe` and a loader that opens a device
  handle, a `driver.handle` event appears within one user-scan tick with
  device name and access mask; a BYOVD-listed driver name is highlighted.
- No `driver.handle` events for non-watched processes (watch-gated like
  `loader.activity`).
- Handle-table walk failure surfaces as a coverage note
  (`scan_failed:userhostity:handles:<pid>`), never as silence.
- Self-test: watch-match gating for the new kind plus
  handle-record dedup logic (pure functions).
