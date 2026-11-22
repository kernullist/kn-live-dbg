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
exit 1. Malformed arguments and output failures return exit 2. A rotating
multi-file session requires separate segment provenance. Keep ETLs and JSON
reports private. [Windows trace file header](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-trace_logfile_header)

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
