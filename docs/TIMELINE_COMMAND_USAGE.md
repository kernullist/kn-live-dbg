# Timeline Command Usage

This guide documents how to use `!timeline` by investigation scenario. The command is designed to keep collection simple while still giving operators a time-ordered evidence model for TI ETW records, snapshot baselines, and optional kernel live callbacks.

## Mental Model

`!timeline` has four roles:

1. Copy evidence into the user-mode timeline store.
2. Query time-ordered events with narrow filters.
3. Derive process/image/source/domain graph edges.
4. Reconcile events against a snapshot baseline or snapshot JSON file.

The compact path is:

```text
!timeline status
!timeline update
!timeline query
!timeline graph
```

Use the advanced commands only when you need explicit source control, kernel callback collection, snapshot-file comparison, or JSONL export.

## Sources And Domains

Common sources:

| Source | Meaning |
| --- | --- |
| `ti` | Microsoft-Windows-Threat-Intelligence ETW records copied from the `!ti` ring |
| `snapshot` | Process and domain records copied from the session baseline or a snapshot JSON file |
| `kernel-live` | Process create, process exit, and image-load records drained from the kernel live callback ring |

Common domains:

| Domain | Meaning |
| --- | --- |
| `process` | Process lifecycle or snapshot process records |
| `image` | Image-load evidence |
| `threat-intelligence` | TI provider events |
| snapshot scanner domains | Domains copied from snapshot records, such as pool, module, driver, thread, or VAD evidence |

Use `!timeline status` to see the source/domain counters that exist in the current session.

## Defaults And Limits

| Command area | Default | Limit |
| --- | --- | --- |
| `update recent` | 200 TI records | `/limit` max 100000 |
| `update all` | 10000 TI records | `/limit` max 100000 |
| `ingest ti recent` | 200 TI records | `/limit` max 100000 |
| `ingest ti all` | 10000 TI records | `/limit` max 100000 |
| `query` | 50 events, newest first | `/limit` max 5000 |
| `graph` | 200 events, newest first | `/limit` max 5000 |
| `reconcile` | 50 findings | `/limit` max 5000 |
| `live start` | capacity 4096 | `/capacity` range 128..16384 |
| `live drain` | 256 events | `/limit` max 1024 |

`!timeline update /live` drains at most 1024 live events even if the update limit is larger. Repeated update or ingest commands are safe to run during an investigation because the timeline store deduplicates identical evidence records.

## Scenario 1: Quick Session Triage

Use this when you want to see whether any evidence is already available in the current session.

```text
!timeline status
!timeline update
!timeline query /limit 50
!timeline graph /limit 200
```

Expected use:

1. `status` shows whether the timeline is empty and prints source/domain counters.
2. `update` copies recent TI records and the current snapshot baseline if one exists.
3. `query` prints the newest events.
4. `graph` summarizes relationships between sources, domains, processes, and images.

If `status` reports `dropped` greater than zero, treat the timeline as partial evidence and preserve the loss caveat in any report.

## Scenario 2: Snapshot Baseline Reconciliation

Use this when the important question is "what changed compared with a known baseline?"

```text
!snapshot baseline /all /name before-test
!timeline update

... run or reproduce the activity under investigation ...

!timeline update
!timeline reconcile snapshot
!timeline reconcile snapshot /domain process /limit 50
!timeline reconcile snapshot /domain image /limit 50
```

Recommended order:

1. Capture the snapshot baseline before the behavior starts.
2. Run `!timeline update` once to copy the baseline into the timeline.
3. Reproduce or observe the behavior.
4. Run `!timeline update` again to copy new TI/snapshot evidence.
5. Run `reconcile` to find timeline events that do not match the baseline and baseline records that did not appear in the event stream.

This workflow is best for same-boot analysis where the baseline was captured in the current session.

## Scenario 3: Threat-Intelligence ETW Focus

Use this when the target behavior is likely to touch process, memory, handle, or image operations surfaced by the Microsoft-Windows-Threat-Intelligence provider.

```text
set-ppl-antimalware status
set-ppl-antimalware on

!ti start /name suspect.exe /ring 1048576 /log .\.kn-live-dbg\ti
!ti watch

... observe the activity ...

!timeline update
!timeline query /source ti /limit 100
!timeline query /domain threat-intelligence /limit 100
!timeline query /source ti /pid <PID> /limit 100
!timeline graph /source ti /limit 300
```

Operational notes:

1. TI subscription usually requires the caller to be PPL Antimalware.
2. `!timeline update` copies TI ring records into the timeline without clearing the TI ring or log.
3. Use `/source ti` for TI-only timeline views.
4. Use `/domain threat-intelligence` when you want provider-event records regardless of other sources.

## Scenario 4: Kernel Live Process/Image Tracking

Use this when you need process create, process exit, and image-load evidence from kernel notify callbacks.

```text
!timeline live status
!timeline live start /capacity 4096

... start the process, load the driver, inject the DLL, or reproduce the event ...

!timeline update /live
!timeline live status
!timeline query /source kernel-live /limit 100
!timeline graph /source kernel-live /limit 300

!timeline live stop
```

Important behavior:

1. `!timeline live start` registers kernel process/image callbacks and allocates a bounded nonpaged ring.
2. `!timeline update` does not drain live callback events unless `/live` is present.
3. `!timeline update /live` drains queued live events into the user-mode timeline store.
4. `!timeline live drain /limit <n>` is the explicit drain primitive when you do not want to ingest TI/snapshot evidence at the same time.
5. `!timeline live stop` unregisters the callbacks.

Use `!timeline live status` before and after the run. If `dropped` increases, the live ring overflowed and reconciliation confidence should be lowered.

## Scenario 5: PID-Centric Investigation

Use this when the operator already has a suspicious PID.

```text
!timeline update /live
!timeline query /pid <PID> /limit 100
!timeline graph /pid <PID> /limit 300
!timeline reconcile snapshot /pid <PID> /limit 50
```

This answers:

1. Which sources mention the PID?
2. Which domains are attached to it?
3. Did it load image evidence that is absent from the baseline?
4. Does the snapshot baseline contain process state that timeline evidence did not observe?

If the target process exits quickly, start live collection before reproducing the behavior:

```text
!timeline live start /capacity 4096
... reproduce ...
!timeline live drain /limit 1024
!timeline query /source kernel-live /pid <PID>
```

## Scenario 6: Image-Centric Investigation

Use this when the suspicious object is a DLL, driver image path, or mapped executable name.

```text
!timeline update /live
!timeline graph /image suspect.dll /limit 300
!timeline graph /image C:\Path\To\suspect.dll /limit 300
!timeline query /domain image /limit 100
!timeline reconcile snapshot /domain image /limit 100
```

`graph /image` performs an image substring match over image evidence, entity text, summary text, and evidence values. Start broad with a basename, then narrow with a full path if the graph is noisy.

## Scenario 7: Snapshot File Comparison

Use this when the baseline was captured earlier or comes from another command output file.

```text
!timeline ingest snapshot .\.kn-live-dbg\before.json
!timeline update
!timeline reconcile snapshot .\.kn-live-dbg\before.json /limit 100
!timeline reconcile snapshot .\.kn-live-dbg\before.json /domain process /limit 100
```

Notes:

1. `ingest snapshot <path>` copies records from the file into the timeline.
2. `reconcile snapshot <path>` compares current timeline events against that file.
3. File ingest does not replace the session baseline. It only adds snapshot-derived timeline events.

## Scenario 8: Report And Offline Review

Use this when you need to preserve the current evidence set.

```text
!timeline status
!timeline export .\.kn-live-dbg\timeline.jsonl /jsonl
```

The CLI export writes schema-versioned JSONL to disk. This is a session-mutating/file-writing TUI command.

For MCP clients, use the read-only MCP tool instead:

```text
timeline.export
```

The MCP tool returns JSONL text in the response and does not write a host file.

## Scenario 9: Reset Between Runs

Use this when starting a clean local analysis pass.

```text
!timeline clear
!timeline live clear
!timeline status
```

Scope of each clear command:

1. `!timeline clear` clears the user-mode timeline store.
2. `!timeline live clear` clears queued kernel live events, but does not clear the user-mode timeline store.
3. `!ti clear` is separate and clears the TI ring.

Use the narrowest clear command that matches the evidence source you intend to reset.

## Command Reference

```text
!timeline update [recent|all] [/limit <n>] [/snapshot] [/live]
!timeline status
!timeline clear
!timeline ingest ti [recent|all] [/limit <n>]
!timeline ingest snapshot [baseline|<path>]
!timeline live start|stop|status|clear|drain [/capacity <n>] [/limit <n>]
!timeline query [/source <name>] [/domain <name>] [/pid <PID>] [/limit <n>] [/oldest|/newest]
!timeline graph [/source <name>] [/domain <name>] [/pid <PID>] [/image <name>] [/limit <n>] [/oldest|/newest]
!timeline reconcile snapshot [baseline|<path>] [/source <name>] [/domain <name>] [/pid <PID>] [/limit <n>]
!timeline export <path> [/jsonl]
```

`/snapshot` on `update` is accepted for operator readability, but snapshot ingest is already part of the compact update path when a session baseline exists.

## Help And Completion

Use either help form:

```text
help !timeline
!timeline help
```

The interactive prompt supports context-aware Tab completion for:

1. Root subcommands such as `update`, `live`, `query`, `graph`, `reconcile`, and `export`.
2. Nested actions such as `!timeline live start` and `!timeline live drain`.
3. Options such as `/limit`, `/snapshot`, `/live`, `/source`, `/domain`, `/pid`, `/image`, `/oldest`, `/newest`, and `/jsonl`.

## Operator Caveats

1. Start live collection before the behavior you need to observe. The callback ring cannot recover process or image events that already happened.
2. Keep `/live` explicit. Plain `!timeline update` is the low-surprise path and does not mutate the kernel live ring.
3. Treat live `dropped` counters as evidence loss. Reconcile output propagates that caveat so confidence is not overstated.
4. Prefer `query` first, then `graph`, then `reconcile`. This keeps the workflow readable and avoids jumping straight to a large graph.
5. Use `all` only when the ring size and report size justify it. `recent` is the normal interactive path.
6. Use MCP timeline tools for read-only automation. Use the TUI for collection, drain, clear, and disk export actions.
