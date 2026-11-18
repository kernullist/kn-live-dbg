# Timeline Command Usage

This guide documents the simplified `!timeline` workflow. The goal is to keep
operator muscle memory small: use plain `!timeline` to collect/refresh evidence,
then use the dashboard to inspect it visually.

## Simple Workflow

```text
!timeline
!timeline dashboard
```

Plain `!timeline` is the normal operator path. It asks whether to enable:

1. Threat-Intelligence ETW capture.
2. Kernel live process/image/thread callbacks.

If the operator answers yes, KnLiveDbg attempts to enable the requested
collector. TI may require PPL Antimalware; the guided path tries the existing
`set-ppl-antimalware` flow before starting `!ti start`. If write mode, symbols,
or the driver device are unavailable, the command prints the failure and still
refreshes whatever evidence is already available.

After the prompts, `!timeline` refreshes:

- recent TI ring records using the timeline TI cursor;
- the current snapshot baseline when one exists;
- queued live callback events when live callbacks are active.

When live callbacks are enabled, KnLiveDbg also starts a user-mode auto-drain
worker. The worker periodically drains the kernel ring into the in-memory
timeline store so short process/thread activity is not left waiting in the
driver until the next manual refresh.

`!timeline dashboard` opens the fixed self-contained HTML dashboard. Filtering
for source, domain, PID, image/driver/DLL, TI task, risk, and text happens
inside the dashboard, not through command parameters. Use the dashboard export
button when the current filtered view must be preserved as JSONL. The dashboard
refreshes recent TI ring records and queued kernel-live events into the
timeline store immediately before writing the HTML, so a separate
`!timeline update` is not required before opening it. The left-side Analyst
Focus panel first tells the operator whether the current filters show only
baseline rows or contain TI memory, cross-process, or remote-thread evidence.
The dashboard also shows generation-time live/auto-drain status, matched
live-analysis rules, semantic relationships, and nearby related events for the
selected process, thread, driver, DLL, TI record, host, file, registry key,
service, scheduled task, WMI entity, memory/VAD transition, or snapshot-diff
milestone.

## Evidence Families

Timeline ingestion normalizes common analyst evidence into stable keys and
relationship edges. The command surface does not change; these families appear
through dashboard filters, relationship rows, matched rules, JSONL export, and
`graph.query`:

- P0: process identity (`process_instance_id`) and cross-process manipulation
  (`cross_process_operation`, source PID to target PID).
- P1: network/DNS endpoints, executable file artifacts, and registry
  persistence keys.
- P2: service, scheduled task, WMI persistence, executable memory/VAD
  transitions, and snapshot-diff milestones.

Network/DNS activity is not automatically suspicious by itself. It is promoted
to matched rules when the event is already risk-tagged or correlated with
higher-risk evidence. File, registry, service/task/WMI, memory/VAD, and
snapshot-diff events carry higher analyst priority when their normalized keys
match executable drops, persistence paths, executable memory, or high-risk
diffs.

## Main Commands

```text
!timeline
!timeline dashboard
!timeline reset
```

`!timeline reset` clears the user-mode timeline store. It does not clear the TI
ring. Use `!ti clear` separately when the TI ring itself must be cleared.

Manual live callback status/off/clear/drain controls are intentionally kept out
of the main surface. Use `!timeline help advanced` only when explicit live
callback control is required.

Command-line JSONL export is also kept out of the main surface. Use the
dashboard export button for analyst-driven export, or advanced `!timeline export`
for scripts.

For continuous code and driver observations use [KMON](KMON_DETECTION_COVERAGE.md).
Its [fixture guide](KMON_TEST_TARGET.md) documents controls and remaining scope.
Detaching a live tail does not stop collection. Timeline remains the evidence
graph/dashboard; collection and comparison gaps remain visible.

## Scenario: Fast Triage

```text
!timeline
!timeline dashboard
```

Use the dashboard filters first. This is the preferred path for process, DLL,
driver, TI task, and risk review.

When no snapshot process baseline exists yet, `!timeline dashboard` captures a
lightweight current process baseline before generating the HTML. This makes
already-running processes visible even if live callbacks were enabled after the
processes started.
Memory operations such as RWX VAlloc/AllocVM against an already-running process
are not produced by the process/image/thread live callbacks. They require TI
ETW delivery. If TI is active but has received zero events, the dashboard shows
that state as a warning and in Analyst Focus.

## Scenario: TI-Focused Analysis

```text
!timeline

Answer yes to TI when prompted.

... reproduce or observe the activity ...

!timeline
!timeline dashboard
```

TI events are copied without clearing the TI ring or log. Repeated recent
refreshes use the TI cursor, while advanced `!timeline ingest ti all` remains
available for deliberate ring rescans. TI risk is a triage priority
(`info`/`warning`/`critical`), not a final verdict.
TI events such as `AllocVM`, `VAlloc`, `ProtectVM`, `WriteVM`, `QueueUserApc`,
and `SetThreadContext` appear through the target-process filter and relationship
rows as cross-process or memory pivots when the provider emits them.
The selected TI event's TDH payload is preserved in the dashboard detail panel
as `payload.<field>` / `payload_type.<field>`, while common fields such as
address, size, protection, access, and start address are also promoted to stable
keys such as `memory_address`, `allocation_size`, `protection`,
`desired_access`, and `start_address`.

### Inspect this controller's TI requests

```text
!timeline ingest observer
!timeline query /source observer /domain observer_action
```

The controller keeps its latest 64 ETW lifecycle requests across subscription
attempts. Dashboard refresh and explicit ingest copy new receipts to the
timeline. The ingest reports how many requests were evicted before it could
copy them. Each receipt identifies the controller PID and creation time, session
generation, request and return times, native Win32 status and outcome. The
possible effect describes what the request could change. `effect_verified=false`
means the controller did not independently measure that effect.

A session name or GUID collision records `collision` and leaves the existing
logger running. After a partial start, `!ti status` shows whether trace resources
still need cleanup. Use `!ti stop` to retry. Locally captured receipts carry
`ingest_origin=local_controller`. An observer row submitted through generic
event ingestion carries `ingest_origin=supplied_record`.

### Inspect live callback control results

After `!timeline live start`, `stop` or `clear`, use `!timeline ingest observer`
and `!timeline query /source observer /domain observer_action`. The controller
keeps the latest 64 live control requests in a separate queue with its own loss
count. Dashboard refresh and `!timeline update` also copy the receipts.

For a matching driver, each row contains the request ID, device-open epoch,
Win32 transport result, operation NTSTATUS, and registration flags before and
after the control. `call.1`, `call.2` and later fields retain each process,
image or thread registration or removal in order, including its kernel UTC
request and return times and any rollback calls. For
example, a failed thread registration can leave a process callback registered
if its rollback also fails. The row preserves both errors and the residual
mask. A subsequent stop retries the remaining registrations.

An explicit start prepares the event ring before callback registration.
Preparing an existing ring clears queued events and resets its sequence and
drop counters. This can already have happened when registration later fails.
Use `!timeline live status` to inspect an existing collection.

When KMON startup fails after enabling live collection, automatic rollback
requires the detailed receipt for a fresh start on the same device-open epoch.
If this controller submits another live timeline control first, the receipt
expires for rollback. After a legacy acknowledgment, inspect
`!timeline live status` before explicit cleanup.

An older ABI 17 driver can return `legacy_acknowledged`. A malformed reply
records `outcome_unconfirmed`. Callback masks and per-callback statuses are
available only in a validated detailed reply. A transport failure preserves
the Win32 code. The flags describe the driver's own registration state. Host
request and return times bound the transaction. `effect_verified=false` means
the controller did not measure the effect on a target process. Last-handle
close and unload clean up inside the driver and have no returning controller
transaction.

For thread and image removal, Windows defines `STATUS_PROCEDURE_NOT_FOUND` as
an absent registration. The receipt retains that raw code. An unresolved
process removal retains its registration bit. If removal repeatedly fails at
final unload, the driver waits between retries before releasing its code and
ring. [Thread removal](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psremovecreatethreadnotifyroutine)
[Image removal](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psremoveloadimagenotifyroutine)

## Scenario: Live Process/Thread/Image Tracking

```text
!timeline

Answer yes to live callbacks when prompted.

... run the target process, create activity, or load the DLL/driver ...

!timeline
!timeline dashboard
```

If the live `dropped` counter increases or the dashboard shows high ring
pressure, treat the timeline as partial evidence. For long-running sessions,
auto-drain keeps copying live records into the timeline store until live
callbacks are turned off. Use the advanced live controls only when explicit
callback stop/clear/drain is required.

## Scenario: Snapshot Comparison

```text
!snapshot baseline /all /name before-test
!timeline

... reproduce the activity ...

!timeline
!timeline dashboard
```

The dashboard is the first inspection surface. When you run `!diff baseline`,
the diff findings are also copied into the timeline as `snapshot-diff`
milestones, so the next dashboard can show them beside live/TI evidence:

```text
!diff baseline /domain drivers /limit 50
!timeline dashboard
```

Use advanced reconcile only when you need text findings:

```text
!timeline reconcile snapshot /domain process /limit 50
!timeline reconcile snapshot /domain image /limit 50
```

## Advanced Compatibility

Advanced commands remain available for scripting, text output, and explicit
source control:

```text
!timeline help advanced
```

The advanced surface includes:

```text
!timeline update [recent|all] [/limit <n>] [/snapshot] [/live]
!timeline status
!timeline clear
!timeline ingest ti [recent|all] [/limit <n>]
!timeline ingest observer
!timeline ingest snapshot [baseline|<path>]
!timeline live on|off|status|start|stop|clear|drain [/capacity <n>] [/limit <n>]
!timeline query [/source <name>] [/domain <name>] [/pid <PID>] [/limit <n>] [/oldest|/newest]
!timeline graph [/source <name>] [/domain <name>] [/pid <PID>] [/image <name>] [/limit <n>] [/oldest|/newest]
!timeline reconcile snapshot [baseline|<path>] [/source <name>] [/domain <name>] [/pid <PID>] [/limit <n>]
!timeline export <path> [/jsonl]
```

Prefer the simple surface unless a script, report, or automation specifically
needs the advanced text output.
