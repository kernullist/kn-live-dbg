# Execution trace inputs

## Saved Windows CPU samples

`KnLiveDbg.exe --etl-profile <local.etl> --sha256 <digest> [--after N] [--limit N]`
reads one saved ETL before driver or symbol initialization. Supply the exact
input SHA-256. The default page has 64 samples and the largest has 128.
Use the returned `next_after` and the same digest for the next page.
`after` counts already decoded samples. The command scans the entire file on
every call, including when a page is full. The limits are 512 MiB and 2,000,000
event records. The input must be a resident regular file on a fixed local
volume. The reader retains the file's read lease and the directory chain while
Windows opens the volume-qualified path, then rechecks file identity and bytes.

The `kn.etl_profile.v1` report decodes the classic PerfInfo `SampledProfile`
event, opcode 46, version 2. Pointer width comes from each event header. Each
row identifies the source by the enclosing digest and its one-based
`record_ordinal` across all ETW callbacks. `sample_ordinal` counts accepted
samples. `sampled_thread_id` comes from the payload. The header PID and TID,
CPU field, descriptor, raw timestamp, instruction pointer, 16-bit count and
reserved values remain separately available. `unsupported_profile_records`
counts matching provider/opcode envelopes outside the supported layout.
[Windows sampled profile event](https://learn.microsoft.com/en-us/windows/win32/etw/sampledprofile)

The header supplies the clock type, performance-counter frequency, capture
times and loss counters. `raw_timestamp` stays in the original clock domain.
A stack extension count applies to that event. The recording privilege, stack
policy, exact intervals of lost samples, authenticated process generation,
address space, VTL and code version remain unknown. The reader assigns `unqualified` to the
verified execution level. Thread/image lifetimes and exact code bytes require
separate evidence before an execution claim can be joined to another source.

For a sequential log with a declared buffer count, `buffer_comparison` compares
that count with buffers processed by ETW. A mismatch returns `partial` and
exit 1, with available rows and both counts. `matched` describes only the
buffer count. Circular logs and missing declarations return `not_comparable`.
A successful page returns `read` and exit 0, which includes a valid trace
with zero decoded samples. File, digest, cursor and decoder failures return
exit 1. Malformed arguments and output failures return exit 2.
[Windows trace file header](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-trace_logfile_header)

For a rotating recording (`EVENT_TRACE_FILE_MODE_NEWFILE`), supply the
actual member filename and its SHA-256. Each command reads that file alone.
The CPU, context-switch, disk and hard page fault pages report `partial` and exit 1 even
when both buffer counts agree. The numeric mode is in `log_header.log_mode`.
`--capabilities --probe-etl` adds `rotation_member` with file scope and leaves the
ordinal, set size and session completeness unknown. An inventory from the
recorder or archive is needed to establish order and missing files.
Keep ETLs and JSON reports private.
[Windows ETW log filenames](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_logfilew)

### Verify an ordered rotation inventory

Use `--etl-rotation-set` with a signed inventory, its independently retained
SHA-256, and the trusted signer's role and uncompressed P-256 public point.
Supply the files by recorder ordinal. Their names and argument order are
local choices. For example, this command retains a missing second file
when the controller declared three.

```powershell
& KnLiveDbg.exe --etl-rotation-set .\run.knetlset --sha256 $inventorySha256 --authority capture_controller $trustedPoint --member 3 .\last.etl --member 1 .\first.etl
```

The inventory uses compact JWS with ES256 and protected type
`kn.etl_rotation_inventory.v1+jws`. The protected header has exactly
`alg` and `typ`. The UTF-8 payload has the following fields.
The digest covers the original token file, including an optional final LF
or CRLF. The public point uses SEC 1 hex beginning with `04`.

| Field | Signed value |
| --- | --- |
| `schema` | `kn.etl_rotation_inventory.v1` |
| `role` | `capture_controller` or `archive_witness`, matching the role authorized for the trusted key |
| `session_id` | Controller's nonzero lowercase GUID, or null for an archive witness |
| `members` | Array in increasing ordinal order. Each entry has a JSON integer `ordinal`, a positive decimal **string** `etl_bytes`, and a lowercase `etl_sha256`. Ordinals and byte digests are unique. |
| `stop` | Null for an archive or a controller without a stop observation. A controller can supply `win32_status`, `final_ordinal`, `events_lost` and `log_buffers_lost` in a stop object. A successful stop requires a positive final ordinal and accepts unsigned 32-bit loss counters or null. A failed stop retains its unsigned Win32 code and requires null for the other three fields. |

The reader accepts ordinals 1–32, up to 512 MiB and two million records
per file, and up to 16 KiB for the signed inventory. A successful stop
can declare an end even if all member identities were lost. Every position
through the claimed end is then visible. The reader takes paths only from
the command line. It checks each declared size and digest, traverses the
pinned ETL, confirms rotation mode and rechecks the member leases together
before writing the report.

`closed_controller_inventory` means the supplied files cover every ordinal
through the controller's signed successful stop. `ordered_members_verified`
covers a contiguous archive list or a controller list without a recorded end.
Both return exit 0. A missing declaration, absent file, extra input,
substitution or failed stop returns exit 1 with the observed member statuses.
A failed Windows file or directory open retains its Win32 code. The receipt
keeps that code separate from the ETW reader status and the controller stop.
An untrusted inventory returns exit 1 with a null member list. Invalid
arguments or an unsafe output destination return exit 2.

The stop counters remain controller claims, including any reported loss.
File verification leaves independent session membership, uninterrupted
event coverage and timing across files unverified. Keep the signed inventory
and output private. [Windows rotating log mode](https://learn.microsoft.com/en-us/windows/win32/etw/logging-mode-constants)

### Read recorded capture settings

Add `--capture-settings` to `--etl-profile` or `--etl-switches` for
`kn.etl_profile.v7` or `kn.etl_switches.v3`. A profile that also requests CLR
evidence uses v8. Capture settings work with the other evidence
and paging options. Every page includes the same file-scoped
`capture_settings.records` in original callback order, including when there
are no samples or switches. The enclosing ETL SHA-256 and the one-based
record ordinal locate each witness.

| Record | Retained evidence |
| --- | --- |
| EventTrace Extension / EndExtension, opcodes 5 / 32 | Eight unsigned group-mask words. Versions 0 and 1 have 32 payload bytes. Version 2 adds the kernel event version. |
| PerfInfo SetInterval / CollectionStart / CollectionEnd, opcodes 72 / 73 / 74 | Profile source and raw new and old intervals. Version 2 has 12 payload bytes. Version 3 adds one terminated UTF-16 source name. |
| Lost_Event, opcodes 32 / 33 / 34 | Original loss-indication envelope, including ordinal, tick and opcode. Its position does not identify a lost sample's time or type. |

Each envelope retains the logger ID, raw timestamp, CPU field, original
descriptor (including keyword), header flags and payload length. A recognized
record with an unsupported layout retains its envelope and contributes to the
unsupported count for its family. The reader keeps up to 1,024 setting and
loss records and 65,536 UTF-16 name units. If a record would exceed either
limit, the page reports partial coverage, the retained prefix and totals
across the whole scan.
[Microsoft PerfView kernel parser](https://github.com/microsoft/perfview/blob/ea4e78e0e363a0838c963338619221f3e211ddb5/src/TraceEvent/Parsers/KernelTraceEventParser.cs) · [ETW loss indications](https://learn.microsoft.com/en-us/windows/win32/etw/rt-lostevent)

Each sample or switch points to surrounding group-mask records for its file
logger. `equal_group_snapshots` means a start and an end reported the same
eight words and kernel event version. Merged traces can carry different
original collections under one logger ID. The manifest keeps those snapshots
separate. The original session identity, effective enable flags, stack
capture policy, recording privilege and producer authenticity remain unknown.

For a CPU sample, `timer_bracket` also identifies the nearest timer-source
records and their enclosing CollectionStart and CollectionEnd. Source zero
is the timer. The reader compares the preceding new interval with the
following old interval. The values must agree and be nonzero. At each
collection boundary the old and new values must also agree, including when
a SetInterval divides the collection into segments with distinct periods.
The records must bracket the row in both callback order and raw time,
with a comparable clock, matching layouts and consistent version-3 source
names. Repeated opening or closing boundaries, missing witnesses, loss,
incomplete retention or unsupported records in the relevant family withhold
the derived value. Other profile sources retain their raw units.

`reported_period_100ns` describes the timer setting between witnesses.
`header_timer_resolution_100ns` gives the separate log header value. Neither
measures elapsed execution time for a sample. [Xperf timer interval units](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/start) · [ETW file header](https://learn.microsoft.com/en-us/windows/win32/etw/eventtrace-header)

### Match a CPU sample to thread records

Add `--thread-evidence` to return `kn.etl_profile.v2`. For each page, the
reader indexes up to 65,536 classic Thread version-3 start, end and rundown
events from the same ETL. The payload supplies the PID and TID.
`thread_source` gives the provider, version and decoded, retained and
unsupported record counts for those four opcodes. [Windows thread events](https://learn.microsoft.com/en-us/windows/win32/etw/thread-typegroup1)

A version-3 thread record may end at its fixed fields or append one
NUL-terminated UTF-16LE thread name. The decoder checks the full suffix,
including surrogate pairs and the terminator. The index retains the
record ordinal, timestamp, opcode, logger ID and payload IDs. A malformed suffix counts
as an unsupported event. [PerfView thread parser](https://github.com/microsoft/perfview/blob/ea4e78e0e363a0838c963338619221f3e211ddb5/src/TraceEvent/Parsers/KernelTraceEventParser.cs#L4062)

Each sample's `thread_evidence.before` and `after` locate the closest records
for its TID by ETW callback ordinal. Each available point includes its event
kind, ordinal, raw timestamp, opcode, payload PID and payload TID. A TID of
zero (idle) or all ones has no lookup. `one_boundary` and `no_record` expose
the extent of the available evidence.

`paired_record_pid` reports the PID shared by two enclosing source records.
`start_end` requires an actual start and end. `rundown_bracket` uses at least
one snapshot of threads present during collection. Both require alternating
start/end directions and strictly increasing thread event ticks for that TID,
a sample strictly inside the raw time interval, matching usable PIDs, a
comparable clock, matched sequential buffer counts and no reported loss or
unsupported thread events. Boundary conflicts, a gap or an unknown clock keep
the paired PID null. Exceeding the index limit returns `partial`, keeps the
decoded sample rows and disables lookups across the incomplete index.
Thread creation FILETIME, authenticated process ownership and code version
remain unknown.

### Locate image records for a sampled IP

Add `--image-evidence` to request `kn.etl_profile.v3`. This includes the
thread evidence and uses its `paired_record_pid` to look up classic Image
version-2 and version-3 records in the same ETL. Load (10) and unload (2)
report changes. DCStart (3) and DCEnd (4) report the images present during
collection startup and shutdown. An image range covers its base through the
byte before base plus size. The reader rejects zero or overflowing sizes and
requires a complete, terminated UTF-16LE name field.
[Windows image events](https://learn.microsoft.com/en-us/windows/win32/etw/image-load)

For each PID and base, the reader finds the closest image records before and
after the sample ordinal. `reported_rva` is the sampled IP minus the recorded
base. It requires one candidate, two enclosing records with strictly ordered
raw timestamps, consistent transitions and matching size, pointer width,
preferred base, PE checksum, PE timestamp, version and nonempty file name.
Version-3 signature level and type must also agree. The clock and loss checks
used for thread evidence apply here. `load_unload` identifies two change
events. `rundown_bracket` indicates that at least one endpoint is a snapshot.
One boundary, conflicting records, an unusable paired PID or overlapping
ranges leave the RVA null. A kernel address has no implicit fallback to a
different process. Process generation, authenticated execution and the bytes
at that RVA still require independent evidence.

`image_evidence.candidate_ranges` counts all candidate bases. `witnesses`
holds the before/after record ordinals for up to two candidates, highest base
first. `image_records` contains each referenced record once in original
ordinal order. It preserves raw ticks, payload PID, image and preferred
bases, size, PE metadata, version-3 signature fields and the exact recorded
file name. These names can expose private paths. The reader treats them as
data and never opens them.

`image_source` reports decoded, retained and unsupported counts. An
unsupported image boundary withholds paired RVAs. The index retains at most
65,536 events and 16 MiB of UTF-16 name data. When either limit is exceeded,
`retention` identifies the exhausted limit, the command returns `partial`
and all image lookups report `index_limit`.

### Match a CPU sample to a CLR method

`--etl-profile <local.etl> --sha256 <digest> --clr-evidence` requests
`kn.etl_profile.v8` and includes thread and process evidence. Use `--after`
and `--limit` to select sample ordinals. The reader compares the sampled IP
with half-open address ranges declared by the .NET runtime and rundown
providers. The header PID and original record ordinal locate each declaration
in the ETL. A process start ordinal distinguishes successive uses of a PID.
[CLR method events](https://learn.microsoft.com/en-us/dotnet/framework/performance/method-etw-events) · [ETW record and buffer context](https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_record)

| `clr_evidence.relation` | What can be recovered from the page |
| --- | --- |
| `load_unload` | Exactly one method range contains the IP. A matching load and unload bracket the sample inside its recorded process generation. The row gives the process start ordinal and the byte offset from the declared start. |
| `preceding_declaration`, `unload_only`, `rundown_bracket` | The original records show one boundary or inventory. The method offset and process-start claim are null. |
| `overlapping_ranges`, `conflicting_declarations` | The reader retains the candidate count and witnesses for up to two ranges. Overlapping ranges or inconsistent transitions at a start address within this process generation prevent attribution. |
| `no_covering_declaration`, `process_generation_unavailable` | The examined declarations leave the sample unattributed. The latter also covers samples without usable thread or process boundaries. |

A paired result requires strictly ordered raw timestamps and ordinals, matching
logger IDs, comparable buffer coverage and usable thread and process records.
The declarations must agree on method and module IDs, token, flags, extent
and optional CLR instance and ReJIT IDs. Inventory observed during a matching
load/unload interval preserves those two original endpoints. A malformed CLR
record with a known PID fences its process generation. A missing PID, observed
loss, ambiguous clocks or the 65,536-record limit can withhold associations
across the file. The page reports the corresponding reason and any witnesses.

`clr_source` reports file-wide counts. `clr_records` contains the original
method records cited on this page in ordinal order. Opening the page with
`!kmon trace` preserves the reported relation. A paired row also exposes the
checked method fields under `reported_clr_method`. The code version stays null
and the verified level stays `unqualified`. A CLR declaration supplies an
address range and identity at the time of the event. The ETL inputs used here
carry no runtime method bytes.

### Match a sample to a recorded process generation

Add `--process-evidence` to `--etl-profile` to get a `kn.etl_profile.v4`
page. This includes thread evidence. Add `--image-evidence` to check the
image range in the same process instance. All modes use the original
sample ordinals, digest and pagination.

The reader follows the sampled payload TID to thread records, then looks
up their shared payload PID in classic Process v2, v3 and v4 events.
Opcodes 1 and 2 record process start and end. Opcodes 3 and 4 enumerate
processes at the start and end of collection. Opcode 39 records a defunct
process. Versions 2 through 5 of that event are recognized. A defunct
record encountered at a sample boundary leaves the generation unresolved.
The decoder follows the `Process_V2_TypeGroup1`, `Process_V3_TypeGroup1`,
`Process_V4_TypeGroup1` and `Process_Defunct_TypeGroup1` definitions in
Windows Kit `wmicore.mof`.
[Windows Process events](https://learn.microsoft.com/en-us/windows/win32/etw/process)
[Process event fields](https://learn.microsoft.com/en-us/windows/win32/etw/process-typegroup1)

`process_evidence.before_record` and `after_record` reference the nearest
records for the candidate PID. `process_records` lists the referenced
records once per page in original order. It includes their raw timestamps,
provider version, pointer width, logger ID, payload PID, parent PID, session
and exit status. Version-5 defunct records also preserve the original
unsigned `ExitTime` value in `defunct_exit_time_raw`. The report keeps it
separate from the ETL clock. The decoder checks the extent
of the SID, ANSI image label and UTF-16 strings. It retains numeric fields
and compares opaque process keys within the source. Only the comparison
outcome appears in the report.
[Windows MOF encoding for SIDs](https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-mof-qualifiers)

A `start_end` result requires an actual process start and end that enclose
the sampled thread's two records in both callback order and raw ticks.
The process records must agree on parent PID, session and layout. Two
reported nonzero keys must agree. Missing keys stay visible in
`opaque_key_comparison`. Process and thread witnesses must share the
sample's logger. The digest, payload PID and
`recorded_generation.start_record` identify this instance within the file.
A later process reusing the PID receives its own start ordinal.
`rundown_bracket` preserves an observed snapshot interval and leaves
`recorded_generation` null. A conflicting key, repeated transition, clock
reversal, unsupported boundary or capture gap also withholds the generation.
A structurally matching thread PID can still point to raw process records
when the thread association lacks coverage.

When both evidence options are present, `image_process_evidence` checks the
paired loader records against the qualified process generation. A nonnull
`reported_rva` requires the image load/rundown and unload/rundown endpoints
to lie strictly inside the process endpoints, with consistent loggers and
clocks. `image_evidence` retains the original range comparison for the numeric
PID. Binding these records to an OS creation FILETIME, an authenticated
collector or retained code bytes requires separate evidence.

`process_source` records input versions, decoded and unsupported counts,
defunct count and clock reversals. The process index holds up to 65,536
records. An overflow returns `partial` and `index_limit` for process lookups.
File and event limits also apply. Keep the reports with the private ETL.

### Compare a recorded image with a pinned PE

`--reference-image <local.pe> <pe-sha256>` adds a second, explicitly named
input to the saved CPU profile. It enables process and image evidence and
returns `kn.etl_profile.v5`. Repeat both file names and digests when paging.
The reference must be a resident file on a fixed local volume, up to 64 MiB.
The reader parses its PE headers through a leased file handle, keeps both
directory chains pinned through the scan and checks the reference bytes again
before publishing the page. The report preserves file names from the loader records.

`reference_image` gives the reference SHA-256, size, supplied leaf name, PE
machine, optional-header magic, image size, COFF stamp, header checksum and
preferred base. Each sample's `reference_evidence` starts from the loader
pair admitted by `image_process_evidence`. `loader_fields` compares the
Windows leaf names without case sensitivity, the image sizes, and any usable
stamp or checksum. A zero or all-ones recorded stamp and a zero recorded
checksum each yield `null` for that comparison. The event header's pointer
width describes the event layout.

| Reference relation | Evidence |
| --- | --- |
| `process_image_unavailable` | The trace could not bind a loader pair to the sampled process generation. |
| `loader_field_conflict` | At least one comparable name, size, stamp or checksum differs. |
| `build_fields_unavailable` | Both recorded build fields are unavailable. |
| `default_base_unresolved` | The reported nonzero default base differs from both the recorded load base and the file's preferred base. |
| `recorded_fields_agree` | The comparable fields agree, including at least one build field. |

`default_base_relation` records which base values agree. A loader can report
its load base in the ETL default-base field. When the file comparison
succeeds, `file_location` describes the sampled RVA in the supplied PE.
An RVA in an executable section can yield a `reference_window` with the
file offset, byte count and SHA-256 of up to 32 bytes starting at that RVA.
The window ends at the earlier of the section's declared virtual and raw
extent. Headers, section gaps, raw padding, virtual zero-fill and sections
without execute permission have no window. The digest describes the raw
file before relocation or runtime modification. The page keeps
`qualification.code_version` null and `runtime_bytes_observed` false.

A missing reference, a reference digest mismatch or invalid PE returns exit 1
with a status and no sample rows. A partial ETL still reports its observed
sample rows and withholds their reference windows. [Windows PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) · [ETW image fields](https://learn.microsoft.com/en-us/windows/win32/etw/image-load)

### Compare merge-time build identifiers

Add `--build-evidence` to `--etl-profile` for `kn.etl_profile.v6`. It enables
the process and image evidence used to locate a sample. It works with or
without an explicitly pinned reference PE. The Windows trace merger can add
ImageID and native RSDS records by inspecting files during the merge.
`build_source.origin` records that provenance. Capture-time memory contents,
the producer's authenticity and the sampled code version remain unknown.
[Microsoft PerfView merge-event parser](https://github.com/microsoft/perfview/blob/ea4e78e0e363a0838c963338619221f3e211ddb5/src/TraceEvent/Parsers/SymbolTraceEventParser.cs)

Each returned image record has a `merge_build` object. The reader looks
for one loader at the same raw timestamp, logger, payload PID and image base.
It counts ImageID (opcode 0), the observed v2 no-debug-ID marker (32) and
native RSDS (36) separately. Each role lists up to two original callback
ordinals. `build_records` contains those referenced events once, including
raw image sizes, COFF stamps, RSDS GUIDs and unsigned PDB ages as applicable.
The reader discards the embedded original-image and PDB names. Other opcodes
have a separate count, including managed and portable debug records.

A qualified endpoint requires one ImageID and one native RSDS, matching
pointer widths and image size, consistent available stamps, a nonzero GUID,
and no competing marker. Malformed supported records, conflicting marker
header and payload PIDs, source loss, unusable clocks and incomplete indexes
withhold qualification. The build index retains up to 131,072 decoded
records. A sample receives `paired_merge_build` only when both boundaries
of its process-bound image agree on the merge stamp, GUID and age.

With `--reference-image`, `reference_build` reports whether the supplied
file has one readable RSDS CodeView record. Mapped entries must agree on
their RVA and file offset, and fit within the headers or a section's declared
virtual and raw extents. A raw-only entry may reference data outside the
mapped image. The reader accepts up to 1,024 debug directory entries and up
to 65,536 bytes in the single CodeView record. Multiple CodeView entries,
invalid extents and a missing
usable identity withhold the file window. `build_evidence.reference_comparison`
exposes the GUID, age and available merge-stamp comparisons even if a loader
checksum conflicts. A matching build pair can distinguish the supplied PE
when neither loader checksum nor loader stamp is available. Every comparable
loader field must still agree. [Microsoft PE debug directory](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#debug-directory-image-only)

## Read saved disk I/O response times

Use `--etl-disk-io` to find the read, write and flush completions with the
longest reported response times in a pinned Windows ETL. The reader also
counts the initiation events present in the file. It runs before driver or
symbol initialization.

```powershell
$etl = (Get-Item -LiteralPath .\case.etl).FullName
$pin = (Get-Content -LiteralPath .\case.etl.sha256 -Raw).Trim()
$page = & KnLiveDbg.exe --etl-disk-io $etl --sha256 $pin --limit 8 | ConvertFrom-Json
$page.operations | Select-Object operation, initiations, completions, transfer_bytes, longest_response_ties
$read = ($page.operations | Where-Object operation -eq read).first_longest_response
if ($null -ne $read -and $null -ne $page.response_ticks_per_second) {
    $ms = 1000 * [decimal]$read.high_res_response_ticks / [decimal]$page.response_ticks_per_second
    "Read at record $($read.record_ordinal) reported $ms ms"
}
```

The `kn.etl_disk_io.v1` page accepts classic DiskIo versions 2 and 3.
Opcodes 10 and 11 report reads and writes, and 14 reports flushes.
Opcodes 12, 13 and 15 are the corresponding initiations. Each row gives the
original one-based `record_ordinal`, raw ETW timestamp, CPU, event version
and pointer width. Version 3 supplies a numeric issuing thread ID.
Completion rows carry the disk number and `HighResResponseTime`. Reads and
writes also carry the transfer size in bytes. Initiations have null disk
number, transfer size and duration. Flushes have null transfer size.
[Windows read and write fields](https://learn.microsoft.com/en-us/windows/win32/etw/diskio-typegroup1) · [Initiation fields](https://learn.microsoft.com/en-us/windows/win32/etw/diskio-typegroup2) · [Flush fields](https://learn.microsoft.com/en-us/windows/win32/etw/diskio-typegroup3)

`high_res_response_ticks` measures the response interval reported by the
storage stack. `response_ticks_per_second` comes from the file header's
positive performance-counter frequency. Both are decimal strings. When the
frequency is unavailable, the counter remains readable in ticks. A measured
zero is preserved. The separate event timestamp uses the trace clock.
Queueing, hardware service time, I/O status, a particular waiting thread and
the identity of the request across providers need other evidence.
[Trace header frequency](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-trace_logfile_header) · [WPA disk response and service times](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/optimizing-performance-and-responsiveness-exercise-2)

Each page scans the complete file, up to 512 MiB and two million ETW records.
The per-operation totals count initiations and completions independently.
The longest-response entry points to the first completion at the maximum
counter and gives the number tied there. When there are no completions,
the entry is null and the tie count is zero. These totals remain visible
on the empty final page. `--after` counts decoded disk events, and
`--limit` accepts 1 through 128, with a default of 64. Use `next_after`
to continue and `--check-page` to reproduce the exact bytes of a retained
page. The replay also accepts a signed capture statement.
[Capture statement verification](#verify-a-signed-capture-statement)

Check `status` before interpreting the totals. A buffer mismatch, missing
buffer accounting, a recorded loss or an unsupported DiskIo layout returns
`partial` and exit 1. Totals then describe the records that could be decoded.
A complete scan can return `read` with zero disk events. The capability
probe reports the observed record count, original ordinal and payload hash
for this family. Keep source traces, evidence pages and replay receipts private.
[Validation on saved traces](VALIDATION.md#saved-disk-io-response-times-on-2026-11-22)

## Read saved hard page faults

`--etl-hard-faults <local.etl> --sha256 <digest>` returns a
`kn.etl_hard_faults.v1` page for classic PageFault version 2, opcode 32.
The event's pointer width determines where the payload thread ID and byte
count occur. Each row retains that ID, the read offset, the initial time
in the payload and the raw completion timestamp from the event header.
The header thread ID is a separate field. The source digest and one-based
record ordinal identify the original event. [Windows hard page fault fields](https://learn.microsoft.com/en-us/windows/win32/etw/pagefault-hardfault)

For a QPC log with positive frequency, `elapsed_qpc_ticks` is the raw
completion timestamp minus the positive initial timestamp. Equal endpoints
give zero. An unavailable QPC clock, a nonpositive start, or a reversed
interval leaves the duration null and supplies a reason in `timing_status`.
To obtain milliseconds, multiply the tick difference by 1,000 and divide by
`clock.header_perf_frequency`. The numeric TID and read offset alone cannot
identify a thread generation, a file, a disk request or an application's
critical path. [Microsoft TraceEvent duration calculation](https://github.com/microsoft/perfview/blob/ea4e78e0e363a0838c963338619221f3e211ddb5/src/TraceEvent/Parsers/KernelTraceEventParser.cs#L7413-L7433)

`fault_summary` counts timed and untimed decoded events and adds the
reported bytes from both. Every page retains the first event sharing the
longest measured interval and the total number of ties. The byte sum can
include repeated reads of the same range. Loss, an unsupported hard-fault
layout, or incomplete buffer accounting returns `partial` and exit 1.
The summary then covers the available records. A completed scan with zero
faults returns empty rows, zero bytes and a null longest fault.

When a source file or its parent cannot be opened, `source_unavailable`
includes the measured `win32_status` if Windows returned one. A rejected
path with no Windows error leaves the field null. This diagnostic also
applies to the CPU, switch and disk page readers.

Use `--after` and `--limit` for paging, `--check-page` for exact replay, and
`--capture-statement` with the trusted key and role to verify a signed
statement about the ETL. The capability probe reports the first decoded
payload's digest and extent. Keep the trace, pages and test-reader output
private. [CLI example](COMMAND_REFERENCE.md#inspect-hard-page-faults-from-a-saved-etl)

### Scheduling during a hard page fault

`--schedule-of N` selects one decoded fault by its one-based ordinal and
returns a `kn.etl_hard_faults.v2` page. The reader reopens the pinned
file to find switches for the thread named in the fault payload. The
surrounding classic Thread v3 start/end or rundown records must agree on the
thread ID, process ID and logger. Both the fault window and each contributing
switch pair must fit strictly inside that bracket. A rundown bracket supplies
a file-local association. The original source and event ordinals identify
the witnesses. [Windows hard fault fields](https://learn.microsoft.com/en-us/windows/win32/etw/pagefault-hardfault) · [Context switches](https://learn.microsoft.com/en-us/windows/win32/etw/cswitch)

`fault_schedule.status` is `covered` when consecutive switch intervals
cover the QPC fault window exactly once. The two totals then sum to
`elapsed_qpc_ticks`. Each interval identifies its original enclosing
switches and clips its duration to the fault window. An off-CPU interval
also gives the outgoing thread's recorded state and wait reason. When a
qualified dispatchable ReadyThread event occurs between the switches, the
interval reports how many of the overlapping ticks fell before and after
that event. Missing or ambiguous readiness leaves this split null while
preserving a qualified off-CPU interval. [Windows ReadyThread fields](https://learn.microsoft.com/en-us/windows/win32/etw/readythread)

Missing switches or lifetime records, incompatible loggers, clock conflicts,
loss and incomplete switch coverage leave the full-window totals null. The
reader retains up to 65,536 thread boundary records and 128 intersecting
switch intervals for the selected fault. A limit leaves the reason visible
and withholds the totals. A zero-duration fault has no schedulable interval.
The page's top-level status describes the ETL read. A selector beyond the
observed faults returns exit 1 with `fault_not_observed` and `source_status`.
An observed overlap measures thread scheduling during a fault. Disk-request
identity, the cause of an off-CPU interval and application critical-path
impact still require separate evidence.

### Hard faults inside an activity window

`--activity-markers` produces a `kn.etl_activity_markers.v1` page of
keyed Start and Stop events. Add `--thread-id` to select an emitting
header thread. `marker_ordinal` counts eligible markers across the file.
`--after` counts matches in the selected view. The nested event's
`record_ordinal` identifies the original record across all providers.
The page counts excluded nonclassic, non-string Start and Stop headers.
Missing keys, missing descriptor IDs, XML or legacy Event Log properties
and headers carrying a decoding GUID disqualify a marker. The numeric TID filter applies across
thread lifetimes. The capability probe checks the hard-fault family.
Marker discovery shows which activity boundaries the file contains.

`--activity-window <start-record> <stop-record>` returns a
`kn.etl_hard_faults.v3` page. Select the original record ordinals in the
supplied ETL. The endpoints must have standard Start and Stop opcodes,
nonzero event and task IDs, and matching provider, activity ID, task,
channel, process, thread and logger. The reader uses nonclassic event
headers with a nonzero activity ID. The two event IDs may differ. The page
retains both descriptors and both header timestamps.
[Windows event descriptors](https://learn.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_descriptor) · [Event header activity IDs](https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header)

Both endpoints must fall strictly inside one recorded thread lifetime
bracket with the same process and logger. `thread_evidence` identifies
the bracket at the opening record. The query checks that it still applies
at the closing record. An intervening Start or Stop with the same process
and activity key makes the selection ambiguous, including a boundary on
another thread. A matching boundary with an unknown process also withholds
the measurement. The file-wide boundary count shows how often the same
activity key and numeric PID appear in the recording.

For an ordered QPC window, `overlaps` clips each observed hard fault on the
selected thread to the two marker ticks. A fault can begin before the
opening or complete after the closing record. `fault_union_ticks` counts
each covered tick once, including when one fault interval encloses another.
Divide it by `window_ticks` for the fraction of recorded elapsed time
covered by the observed faults. The file-wide `fault_summary` and each
fault's original duration remain available separately.

A qualified window with evidence of the fault family on its logger can
report zero overlapping ticks. Missing family evidence, unassignable or
untimed candidate faults, conflicting logger or lifetime evidence, and more
than 128 candidates leave the union null. Incomplete buffer coverage,
reported loss, clock conflicts and ambiguous activity boundaries also
withhold the window timing. Missing requested records produce
`activity_record_not_observed` and exit 1. The page describes observations
on a reported thread. Logical work identity across threads, collection
policy and the cause of application latency require additional evidence.
[CLI and marker discovery](COMMAND_REFERENCE.md#measure-hard-faults-during-a-recorded-activity)

### Comparing activity windows across recordings

`tools/compare-etl-activities.py` runs the same pinned executable against
two separately pinned files. Each side of its private JSON report retains the
selected original ordinals, source hash and size, process result, output byte
counts and hashes, and the decoded native page when available. The page includes
the thread bracket, clock, loss counters and fault witnesses. Repeating the
command with `--check-report` checks the digest of the complete comparison.
For a native `read` or `partial` page, the stdout hash can also be used with
the native `--check-page` query.
[Command and replay example](COMMAND_REFERENCE.md#compare-an-activity-across-two-recordings)

For a difference, both windows must qualify in their own trace, the file
hashes must differ, and the provider, channel, task, Start/Stop event IDs and
their respective versions must match. Activity IDs, loggers, PIDs, TIDs and
raw clock origins are local to each capture. Each duration uses that
capture's own QPC frequency. The report expresses nanoseconds and percentage
change as exact fractions. A positive time difference means the candidate
window took longer. A zero baseline leaves the percentage null.

`duration_only` preserves the elapsed-time difference when fault coverage
is insufficient on either side. `same_recording`, `descriptor_mismatch`
and `window_unavailable` retain any measured side and leave both differences
null. A source or reader failure on one side remains visible alongside the
other attempt. The comparison measures one selected pair. Workload
equivalence, run-to-run variability and the cause of any change require
separate evidence. Different file hashes can also describe two edits of one
recording. The query uses recorded headers and fault payloads without symbol
lookup.

### TraceProcessor marker correspondence

The optional `--traceprocessor` query produces a `kn.etl_activity_comparison.v2`
report. It runs Microsoft.Windows.EventTracing.Events 1.12.10 with the x64
Processing.Toolkit 1.11.0. The caller pins the ZIP containing the adapter,
its CLR binding configuration and its dependencies. Acquisition also checks
the 48 runtime files against the locked distribution and keeps the deployed
files open during the query. The helper hashes the ETL and checks the
locations of the loaded managed event assemblies and native processing
modules. Both loss tolerance and time-inversion tolerance are disabled.
[Microsoft TraceProcessor data sources](https://learn.microsoft.com/en-us/windows/apps/trace-processing/tutorial)

The SDK reads the generic events for the selected provider. A one-based
`table_row` identifies the row in its `IGenericEventDataSource.Events`
result. The projection retains counts for the provider, activity Start/Stop
events, process/thread/channel/task filter and inclusive time range. Rows
with an unavailable or partial raw clock remain candidates. At most 128
rows are retained after these filters. The SDK receives the QPC bounds and
reads the event IDs, versions, timestamps and original table positions
from the ETL. [Generic event fields](https://learn.microsoft.com/en-us/dotnet/api/microsoft.windows.eventtracing.events.igenericevent?view=trace-processor-dotnet-1.0)

Each native endpoint must match exactly one SDK row by provider, activity
ID, channel, task, opcode, event ID, version, PID, TID and raw QPC tick.
The Start must precede the Stop in table order. Missing or duplicate rows,
a possible match with an unqualified clock, a row cap or a reader failure
leave the SDK result unconfirmed. Both source-specific outcomes and any
native timing measurements remain available. Agreement covers the selected
headers. The native thread lifetime and hard-fault overlap have separate
witnesses. [Build and replay](COMMAND_REFERENCE.md#check-the-same-markers-with-microsoft-traceprocessor)

## Saved Windows context switches

`KnLiveDbg.exe --etl-switches <local.etl> --sha256 <digest> [--after N] [--limit N]`
reads classic Thread provider opcode 36 from a saved ETL. The
`kn.etl_switches.v1` page uses the same pinned input, raw clock, file and
event limits, buffer accounting and exit codes as the CPU profile reader.
`switch_ordinal` counts decoded switches. `record_ordinal` locates the
original event among all callbacks. Use `next_after` with the same digest to
page in original order. A trace can contain context switches even when CPU
sampling was disabled. [Windows CSwitch class](https://learn.microsoft.com/en-us/windows/win32/etw/cswitch)

The decoder accepts the 24-byte version-2, version-3 and version-4 layouts.
Each row contains the outgoing and incoming thread IDs and priorities,
previous C-state, spare byte, outgoing wait reason, state and ideal processor,
incoming wait-time field and reserved value. Byte 13 is the signed
`old_wait_mode` in version 2 and the raw `thread_flags` byte in versions 3
and 4. The other field is null. The event header supplies CPU, timestamp,
logger ID, descriptor, stack-extension count and separate header PID/TID.

`decoded_switches` and `unsupported_switch_records` count the supported
and unsupported records for this provider and opcode. A valid trace with
zero decoded switches returns an empty page. The raw `new_wait_time` has
no assigned time unit in this report. A thread's wait duration, creation
identity and process generation require more evidence. Keep the ETL and
its switch reports private.

### Reconstruct scheduler intervals

Add `--intervals` to `--etl-switches` for a `kn.etl_switches.v2` page. To
follow a numeric thread ID, use `--thread-id N`. This selects switches where
either the outgoing or incoming TID equals `N` and enables intervals.
`match_ordinal` and `next_after` count matching switches. `switch_ordinal`
and `record_ordinal` retain their positions in the original trace. Keep the
thread filter and input digest when continuing a page.

| Field | Source of the elapsed ticks |
| --- | --- |
| `on_cpu` | The outgoing TID must match the immediately preceding switch-in on this CPU. For a nonzero TID its most recent thread transition must be that same switch-in. TID zero measures idle residency separately on each CPU. |
| `off_cpu` | The incoming nonidle TID must have a preceding switch-out with no intervening switch or decoded lifetime boundary for that TID. Its two endpoints can lie on different CPUs. |
| `off_cpu.readiness` | A classic Thread/ReadyThread v2 record (opcode 50) for the **payload** TID must lie strictly between those endpoints. Exactly one dispatchable record must end the sequence. `switch_out_to_ready_ticks` and `ready_to_switch_in_ticks` measure the two parts. |

`previous_switch`, `previous_thread_event` and `other_thread_event` identify
the original records, including conflicting transitions and thread start,
end or rundown boundaries. `first_ready` and, for sequences of two or more,
`last_ready` preserve the raw ready flags, adjustment fields and reserved
byte. Flag 1 marks a DPC ready. Flag bits 2 and 4 describe swapped-out state
that requires a further ready event. Unknown bits, multiple dispatchable
records, a deferred final record or ambiguous timestamps leave both parts
null. `waiting_ready_switch_in` additionally requires outgoing state 5
(Waiting). Other outgoing states use `ready_switch_in`. The interval identifies
when a recorded TID became ready. The wait object and cause remain unknown.
[Windows ReadyThread definition](https://learn.microsoft.com/en-us/windows/win32/etw/readythread)
[Windows CPU analysis](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/cpu-analysis)

The reader makes two passes over the same leased file and checks file
identity and SHA-256 after each. It tracks all reported processors and the
TIDs appearing on the selected page. Late conflicts can therefore invalidate
an earlier pair. Sequential buffer accounting, reported loss, unsupported
records, CPU numbering, logger identity, thread transitions and clock
ordering qualify the result. Legacy processor numbers with more than 64
reported processors have ambiguous scope. An unsupported readiness record
suppresses subdivision. Unsupported thread boundaries suppress nonidle
durations. A missing ready record leaves a qualified off-CPU interval whole.
The relation on each field gives the reason for a null duration.

Elapsed values and raw timestamps are exact decimal strings. Use
`interval_source.ticks_per_second` for a QPC or system-time clock. Processor
cycle clocks and unknown clock types have no qualified rate here. On-CPU
time measures scheduler residency, which may include interrupt or DPC
activity. Instruction attribution and authenticated thread generations
require separate evidence. The incoming `new_wait_time` payload keeps
its original, unspecified unit. Store both full pages and extracted intervals
with the private trace.

## Saved V8 CPU profiles

The trace query reads the Windows V8 profiler log emitted by Node.js
24.22.3, V8 13.6.233.17-node.63. The optional x64 low-level log contains
the bytes V8 wrote for each code-creation record. Each input has its own
SHA-256. One isolate per log gives the records a common file scope.
[V8 sample-based profiler](https://v8.dev/docs/profile) · [Node's V8 log writer](https://github.com/nodejs/node/blob/v24.22.3/deps/v8/src/logging/log.cc)

From PowerShell, run a single-isolate workload called `workload.js` in the
current directory and pass the two resulting files to KnLiveDbg.

```powershell
node --prof --ll-prof --no-logfile-per-isolate --no-log-source-code --logfile=workload.log .\workload.js
$profilePin = (Get-FileHash .\workload.log -Algorithm SHA256).Hash
$codePin = (Get-FileHash .\workload.log.ll -Algorithm SHA256).Hash
$exe = 'x64/Release/KnLiveDbg.exe'
& $exe --offline '!kmon' trace .\workload.log /v8 $profilePin /code-log .\workload.log.ll $codePin /limit 32 /json
```

Use the same digests and limit with `/cursor <next_cursor>` for the next
page. A query of the text log alone omits `/code-log`. Restricted offline and
observe launches accept a single resident local file redirected to standard
input, for example `KnLiveDbg.exe --mode offline trace - /v8 <sha256>` with
file redirection in `cmd.exe`. The named offline query accepts both files.

| Result field | Meaning |
| --- | --- |
| `sampled_pc`, `logger_time_us`, `record_ordinal` | Original PC, logger elapsed microseconds and one-based physical line. V8 takes this timestamp when its profiler thread drains a queued sample. The row also preserves the VM state, external-callback flag, TOS or callback address, reported stack depth and overflow marker. |
| `log_order_range` | Most recent code-map entry at that PC in file order. It retains the creation and location ordinals, original and mapped addresses, extent, offset, V8 kind, tier marker and reported shared-function-info address at creation. The escaped name is retained up to 1,024 printable bytes. The source line identifies longer names. |
| `code_record_bytes` | SHA-256 and file offset of the complete low-level body plus a separate hash and offset for up to 32 bytes beginning at the sampled PC's offset. A matching binary record supplies the bytes. |
| `range_relation`, `byte_relation` | Why a row has a reported JS range or recorded bytes. External callbacks, interpreter bytecode, reused locations, relocations, deoptimizations, incomplete mapping history and sample overflow retain distinct outcomes. |

The code map applies creation, overlap replacement, move and deletion in
file order. A byte match requires a qualified baseline, Maglev or TurboFan
JS range at its original address. The reader compares the entire ordered
creation/move sequence from both logs and the individual code label. The
binary logger may truncate long names. An unconfirmed label leaves the
hash fields null. Code-creation records can also enumerate existing code.
The producer's authenticity, isolate/process lifetime and the bytes at the
actual sample instant remain unverified. [V8 dynamic code map](https://github.com/nodejs/node/blob/v24.22.3/deps/v8/tools/codemap.mjs)

The query accepts up to 64 MiB per input, one million text lines, 65,536
retained mappings or binary records, and 128 samples per page. An incomplete
final line, missing profiler boundary, unresolved mapping change or mismatched
companion yields `partial` and exit 1 with available rows. Unsupported text
versions, malformed recognized records, exhausted text mapping budgets and
incorrect pins yield `unavailable` and exit 1. A complete page returns
`ok` and exit 0. [V8 validation](VALIDATION.md#v8-cpu-samples-and-recorded-code-bytes-on-2026-11-22)

## Normalized execution trace import

The trace query reads a local normalized trace or a saved CPU profile page.
Use `KnLiveDbg.exe --offline !kmon trace capture.kntrace /limit 64 /json`.
A continuation uses the same file and limit with `/cursor <next_cursor>`.

### Query and reproduce a saved ETL profile page

The trace query accepts the JSON produced by `--etl-profile`, from
`kn.etl_profile.v1` through `v8`, within the same 2 MiB input limit.
The output schema is `kn.execution_trace_query.v2`. Each normalized sample
retains its sampled TID, instruction pointer, CPU field, signed raw tick,
descriptor, stack-extension count, header PID/TID and both original
ordinals. An event's pointer width describes its own header. Timestamp
reversals within a page remain in record order. The log header's FILETIMEs
and event/buffer loss counters stay in their original units.
[Windows sampled profile](https://learn.microsoft.com/en-us/windows/win32/etw/sampledprofile) · [ETW event header](https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header)

`file_sha256` identifies the exact report bytes read by this query.
`source.reported_etl_sha256` identifies the ETL named by digest inside that
report. The query checks the profile event type, envelope layout, record and
sample ordinals, buffer comparison and pagination. Optional evidence tables
remain in the saved report. Its hash and the sample ordinal locate the
original witnesses for thread, process, image, build and capture settings.
For v8, the query also checks the CLR record references, process and thread
boundaries, method identity, extent and offset before exposing a reported
method. Replaying the page against the pinned ETL checks its actual source
records.

`reported_level=X2` describes the CPU sample type reported by the source.
`qualified_reported_level` and `verified_level` remain `unqualified`.
Target, boot, VM, VTL, address space and runtime code identity remain unknown.
The file's decoded sample ordinal supplies no hardware loss sequence.
`records_lost`, `sequence_gaps` and `loss_intervals` are null. A partial native
page retains its rows and returns status `partial` and exit 1.

`next_cursor` continues inside the saved JSON page. `query_complete` marks
its end. Use `source_page.source_next_after` with the original ETL to obtain
the next native page. Both restricted launch modes can read a saved page
from a resident fixed-local file redirected to standard input.

To check the report against the original, repeat the native profile or
switch command with the same ETL digest, options, page boundary, limit and
any pinned PE. Add `--check-page <file_sha256>`. The reader regenerates the
full native page, including optional witnesses, and hashes its UTF-8 bytes
and final LF. The compact `kn.etl_page_replay.v1` receipt returns both hashes.
`matched` records byte-for-byte reproduction under those inputs. A different
digest returns `page_mismatch` and exit 1. A matching partial page retains
`source_status=partial` and exit 1. An unavailable source leaves
`page_bytes_match` null. Formatting, re-encoding or changing the line ending
also changes the digest. Capture-time producer authentication remains open.
[CLI example](COMMAND_REFERENCE.md#query-a-saved-etl-profile-page)

### Verify a signed capture statement

An operator can supply a JWS Compact file, an authorized signer role and a
trusted P-256 public point when replaying a page. The reader verifies the
ES256 signature over the original protected-header and payload segments.
The trusted point comes from the operator's provisioning record. It uses
the uncompressed SEC 1 form, byte `04` followed by 32-byte big-endian X
and Y coordinates, encoded as 130 hex digits. The receipt fingerprints
those 65 bytes with SHA-256. [JWS signing input](https://www.rfc-editor.org/rfc/rfc7515#section-5.2) · [ES256 encoding](https://www.rfc-editor.org/rfc/rfc7518#section-3.4)

The protected header has exactly `alg` (`ES256`) and `typ`
(`kn.etl_capture_statement.v1+jws`). The header and payload are UTF-8
JSON objects starting with an opening brace. The three segments use
unpadded base64url. The file may end with one LF or CRLF. Limits are
8 KiB for the file, 512 bytes for the decoded header and 4 KiB for the
decoded payload. The signature contains 32-byte R and S values.

The payload requires every field below. Unknown fields, duplicate keys
and ambiguous encodings fail verification.

| Field | Signed value |
| --- | --- |
| `schema`, `role` | `kn.etl_capture_statement.v1` and either `capture_controller` or `archive_witness`. The operator must authorize that exact role for this key. |
| `etl_sha256`, `etl_bytes` | Lowercase SHA-256 and the positive file length as a decimal string. Both must match the leased ETL. |
| `session_id`, `target_id`, `boot_id` | Lowercase, nonzero, hyphenated UUIDs in the signer's namespace, or null. A capture controller must identify the session. |
| `se_system_profile_privilege_enabled` | Boolean reporting the controller token's privilege state, or null when unknown. |
| `system_trace_enable_flags` | Unsigned 32-bit ETW enable mask reported by the controller, or null. |
| `sampled_profile_stack_requested`, `context_switch_stack_requested` | Separate boolean requests for the named event classes, or null. Actual stack delivery remains a per-event observation. |

An archive witness signs the identity of saved bytes and supplies null for
all capture context. A controller can sign the settings it used. These
claims stay scoped to the signed artifact, including for a merged ETL.
The reader projects the claims into `kn.etl_page_replay.v2` only when the
signature, authorized role, ETL hash and length, and regenerated page all
match. A partial source keeps its partial status and exit 1. A wrong key,
wrong role or ETL mismatch returns exit 1 with distinct evidence in
`capture_statement`. A stale page hash retains its own comparison result.
The exact statement file digest includes its optional line ending.

The signature covers the ETL identity and the issuer's claims. Local
replay supplies the link from those signed bytes to an individual page.
The signing key identifies the author of the assertion. Historical key
provisioning, independent capture time, OS event origin and runtime code
identity require other evidence. The normalized samples keep their existing
qualification. [CLI example](COMMAND_REFERENCE.md#verify-the-author-of-an-etl-capture-statement)

## Input contract

`kn.execution_trace.v1` has exactly six top-level fields: `schema`, `source`,
`address_spaces`, `code_versions`, `samples` and `loss_intervals`. Member order
and ordinary whitespace are insignificant. Unknown/duplicate fields, malformed
UTF-8, a BOM, unpaired Unicode surrogates, invalid references and over-limit
inputs are rejected. Unsigned integers are decimal **strings**, without a sign,
leading zeroes or exponents. Addresses are decimal strings too. IDs, names and
reasons contain 1..128 UTF-16 code units and no control characters.

Limits are 2 MiB per file, 64 address spaces, 128 code versions, 4,096 samples,
128 loss intervals and 4,096 retained bytes per code version. A result page
contains 1..128 samples (default 64), plus the bounded source/context tables.
The importer requires a regular local file and rejects the final reparse point,
UNC/device/alternate-stream paths and concurrent ordinary writer leases. It is
not a filesystem sandbox; parent-directory redirection and existing mapped
writers are not authenticated by this contract. Hashes identify bytes read.

`source.kind` is `cpu_sample`, `saved_context` or `pointer_reference`.
`architecture` is `amd64`; the normalized address container is 64 bits. Raw
instruction decoding and WOW64-specific context interpretation are not supplied.
Target, boot and VM IDs are required opaque producer identifiers. VTL is `"0"`,
`"1"` or null. A VTL1 label from an imported producer does not grant native VTL1
access. `ticks_per_second` must be nonzero. Capture, sample, code and loss ticks
use the same declared source clock; clocks are not aligned to the local host or
other sources. Process/thread creation times use Windows FILETIME units.

Each address space declares `user` or `kernel`, a PID/creation-time pair,
root identity, acquisition epoch and paging depth 4 or 5. Zero lifetime/root/
epoch values are retained as unknown qualification. No live address format is
inferred from the analysis host. Each code version binds an ID to an address
space, base, nonempty lowercase `bytes_hex`, lowercase SHA-256 and an inclusive
validity interval within the capture. The importer checks the supplied bytes'
hash and range. Runtime mapping and original code acquisition remain producer
claims. The source file retains the bytes; result pages expose their identity
and size without copying the bytes again.

Samples have strictly increasing nonzero sequence numbers and nondecreasing
ticks inside the capture interval. CPU is an unsigned 32-bit decimal string or
null. Code version is a known ID or null. IP must fit the declared address-space
shape. Declared code context that does not cover the sample, or conflicting
retained code bytes at that time, makes its reported grade unqualified. Missing
CPU/VTL for a CPU sample, or unavailable process/thread/root/epoch identity,
also stays unqualified. A missing code version is preserved and cannot support
instruction decoding, even when the CPU sample metadata is consistent.

`records_lost` is an unsigned decimal string or null. It cannot be smaller than
the sequence gaps inside the supplied sample list. Leading/trailing missing
samples cannot be counted from that list. Loss intervals are inclusive, within
the capture, and retain an explicit reason. Overlap with a retained sample is
reported. Neither zero reported loss nor a completed page query establishes a
continuous execution history.

The following is synthetic input for one sample:

```json
{
  "schema": "kn.execution_trace.v1",
  "source": {
    "id": "synthetic-source",
    "producer": "synthetic \"sampler\"",
    "kind": "cpu_sample",
    "target_id": "fixture-target",
    "boot_id": "fixture-boot",
    "vm_id": "fixture-vm",
    "vtl": "0",
    "architecture": "amd64",
    "clock_domain": "fixture-clock",
    "ticks_per_second": "1000",
    "first_tick": "10",
    "last_tick": "10000",
    "records_lost": "0"
  },
  "address_spaces": [
    {
      "id": "as0",
      "domain": "user",
      "pid": "100",
      "process_create_time": "1000",
      "root_identity": "4096",
      "epoch": "1",
      "paging_levels": "4"
    }
  ],
  "code_versions": [
    {
      "id": "c0",
      "space": "as0",
      "base": "1048576",
      "bytes_hex": "909090c3",
      "sha256": "97e3bfad17932f638a894351239ca24cb76467e080c5b268307547d36366fe10",
      "first_tick": "10",
      "last_tick": "10000"
    }
  ],
  "samples": [
    {
      "sequence": "1",
      "tick": "20",
      "cpu": "0",
      "space": "as0",
      "tid": "104",
      "thread_create_time": "1100",
      "ip": "1048576",
      "code_version": "c0"
    }
  ],
  "loss_intervals": []
}
```

## Output and trust

`kn.execution_trace_query.v1` retains source identity, architecture, clock,
address-space tables, checked code hashes and loss fields. Each sample's
`qualified_reported_level` is X0, X1, X2 or `unqualified`, and `qualification`
explains the scope check. These are qualified **producer claims**. The importer
keeps `collector_authenticated`, `execution_independently_verified`,
`execution_observed`, `control_flow_observed`, `write_observed`,
`actor_attributed` and `continuous_execution` false. It cannot emit X3/X4.
Saved contexts and pointer registrations never become X2 samples.

The exact input SHA-256 and page limit bind the cursor. A changed byte, changed
limit, invalid offset or malformed token fails; a new process can continue an
unchanged file. `query_complete` only marks the end of that sample list. Output
uses UTF-8, including redirected output. Exit 0 is a successful page, exit 1
returns an unavailable report, and exit 2 rejects command arguments. Library
cancellation is checked before loading and between bounded parsing stages; it
does not interrupt a synchronous file read or impose a hard elapsed deadline.
No input file is modified and no imported sample is joined to live observations.
Keep actual trace files and query exports private; the publication scanner
rejects `.kntrace` and both trace schemas.

## Verification scope

Run `tools/validate-execution-trace.ps1 -Sanitize`, then
`python tools/test-execution-trace.py --exe x64/Release/KnLiveDbg.exe`.
The tests independently generate source records and SHA-256 values, inspect
UTF-8 output, exercise paging across processes, conflicting code, missing
identity, loss, malformed formats and boundary sizes. The image-recipe harness
covers the shared artifact reader. These tests cover the normalized v1 input. The saved-page comparison in
`tools/test-etl-trace-import.py` uses Windows `tracerpt`, the native ETL reader
and the normalized query on the same pinned file.
[Results for five saved ETLs](VALIDATION.md#normalize-and-replay-saved-etl-pages)
