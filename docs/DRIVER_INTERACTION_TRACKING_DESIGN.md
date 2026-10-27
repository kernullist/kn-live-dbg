# Driver interaction tracking

KMON records device-handle relationships for watched processes and exposes a
separate opt-in raw I/O-trace path. Both are implemented, but their lifetime and
evidence guarantees differ. Main ABI **17**, I/O-trace control/drain function
numbers **0x816/0x817**.

## Watched handle observations

Native-width File handles are followed through
`FILE_OBJECT -> DEVICE_OBJECT -> DRIVER_OBJECT`. PDB fields, object types,
address bounds, cycle checks and stack-depth budgets qualify each relationship.
Filesystem and control-device observations remain separate; failed lookups stay
unknown. Manually mapped code may lack a conventional driver object or loader
entry, so this collector is not a complete payload inventory.

`DeviceClient::QueryFileObjectTypeIndex` identifies File handles from an owned
handle. A shared handle snapshot rotates through eight watched PIDs, with a
128-record per-PID resolution cursor. Records retain process creation identity,
full-width handle/access values, object addresses and observation generation.
Complete snapshots support present/opened/closed/reappeared transitions; closed
objects are not dereferenced. Short opens entirely between snapshots can be missed.

The ring/log retains ordinary filesystem observations even when the console
suppresses their display. `!kmon status` exposes scan age and pending work.
Missing snapshots/symbols produce coverage/sensor records. Handle presence is
not proof of a specific IOCTL, memory write, actor or malicious intent. TI is
not used as a universal DeviceIoControl trace; `gap.kernel_rw` preserves that gap.

## Experimental raw I/O trace

`!kmon iotrace <driver-name> on` resolves the driver object in user mode, then
requests a write-gated dispatch interposition. `off` and `status` take no driver
argument. The driver replaces the target's `IRP_MJ_DEVICE_CONTROL` dispatch
entry with a trampoline, records PID/IOCTL/length metadata in a bounded ring,
and forwards the IRP. The ring holds 1,024 records and the first-seen display
tracks at most 256 PID/IOCTL pairs.

The implementation references the target object and tracks entered trampolines.
Disarm restores the entry and waits for active calls, returning
`STATUS_DEVICE_BUSY` while keeping the reference when its bounded wait ends.
Controller shutdown retains the device on failed disarm so cleanup can retry.
Driver unload retries busy disarm without a fixed retry count; a stuck dispatch
can delay unload indefinitely.

**Unresolved lifetime boundary:** a caller can fetch a published function pointer
before entering the trampoline. An object reference and an active-entry counter
alone do not establish a drain contract for that interval. The current code has
no cooperative external-provider publication contract. This is an experimental
raw path with unload-safety limitations, not a generally safe monitoring feature.

The cooperative minifilter CREATE controls and pending-I/O fixture do not use
this raw replacement mechanism. Their passing tests do not validate it.
See [architecture](ARCHITECTURE.md#cooperative-callbacks-and-pending-io) and
[remaining work](FEATURE_PLAN.md).

## Validation

Owned handle controls should verify watch gating, exact process/device identity,
open/close/reuse, scan failures and bounded work. Names and BYOVD catalog matches
are not prerequisites for retaining an observation. Pure-function/command tests
and ordinary handle observations do not prove raw dispatch/unload safety.
Use [validation status](VALIDATION.md) and the
[shutdown checklist](MANUAL_TEST_CHECKLIST.md#collector-and-shutdown-lifecycle)
to keep these scopes separate.
