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

Watched File handles are parsed with the native pointer-width ABI and followed
through `FILE_OBJECT -> DEVICE_OBJECT -> DRIVER_OBJECT`. PDB field offsets,
object type tags, address bounds, cycle detection and a stack-depth budget
qualify each connection. Filesystem and control-device channels remain
separate; unreadable paths remain unknown.

`DeviceClient::QueryFileObjectTypeIndex` learns the File type index from the
client's own `CreateFile` handle. A shared system handle snapshot is consumed
by a rotating batch of eight watched PIDs. Per-PID pending records retain a
128-record resolution cursor. Evidence includes process creation identity,
full-width handle/access values, File/device/driver addresses, and observation
generation. Complete snapshots produce `present_at_attach`, `opened`, `closed`
and `reappeared` transitions. Closed objects are never dereferenced.

Ordinary filesystem observations are retained in the ring/log while their
console display is quiet. Snapshot or symbol failures are coverage/sensor
records. An open and close wholly between snapshots can still be missed;
`!kmon status` exposes the oldest PID scan age and pending work.

## Phase B — kernel-side IOCTL observability (B.1 implemented as `!kmon iotrace`)

Opt-in, lab-only: `!kmon iotrace <driver-name> on|off|status` resolves the
named driver's DRIVER_OBJECT via the `\Driver` object-directory walk
(`IntegrityScanner`, user mode — the driver never does name lookups), then
arms the main `KnLiveDbg.sys` driver (ABI 17, `IOCTL_KNDBG_IOTRACE_CONTROL` 0x816 with the
write ACK magic):

- The target's `MajorFunction[IRP_MJ_DEVICE_CONTROL]` is swapped to the
  driver's trampoline after SEH-validating `Type == IO_TYPE_DRIVER` and
  referencing the DRIVER_OBJECT with `ObReferenceObjectByPointer` so the
  target cannot be freed while the hook is live. The trampoline records
  caller pid, IOCTL code, and in/out lengths into a non-paged spinlocked
  ring (1024 records, allocated lazily on first arm) and passes the IRP
  through untouched.
- The kmon worker drains the ring (`IOCTL_KNDBG_IOTRACE_DRAIN` 0x817) and
  prints `driver.ioctl` events, first-seen per (pid, IOCTL code) with a
  256-entry cap, decoded into function/device-type/method plus lengths.
- DISARM restores the original entry and waits for active trampolines to
  leave (4,000 waits of nominally 100 us each). If dispatch is still active,
  it reports `STATUS_DEVICE_BUSY` and keeps the target reference. Scheduling
  can make the elapsed wait longer than the nominal 400 ms.
- Normal `q`/`unload` stops kmon, TI, and timeline before closing the device.
  If I/O-trace disarm fails, the controller keeps the device available and
  reports failure so cleanup can be retried. Driver unload retries disarm
  while it is busy, with no fixed retry count; a stuck target dispatch can
  therefore delay unload indefinitely. Active dispatch code must not be
  released just because a timeout expired.
- Risk statement: interposing a dispatch entry tampers with live kernel
  state and can crash the host if the target driver misbehaves; it is
  gated behind an explicit per-driver arm command and is intended for lab
  analysis of a captured loader, not for always-on monitoring.

## Acceptance criteria (Phase A)

The [2026-09-19 command audit](COMMAND_AUDIT_20260919.md) records build and
driver-free regression evidence for the shutdown changes. It does not prove
live dispatch/unload race behavior; those checks remain on the
[manual checklist](MANUAL_TEST_CHECKLIST.md#collector-and-shutdown-lifecycle).

- With `!kmon start /name loader.exe` and a loader that opens a device
  handle, a `driver.handle` event appears after its rotating scan with
  access mask and a qualified connection or an explicit unknown status. Device
  names and BYOVD matching are not required for retaining the observation.
- No `driver.handle` events for non-watched processes (watch-gated like
  `loader.activity`).
- Handle-table walk failure surfaces as a coverage note
  (`scan_failed:userhostity:handles:<pid>`), never as silence.
- Self-test: watch-match gating for the new kind plus
  handle-record dedup logic (pure functions).
