# Normalized execution trace import

This adapter reads local normalized JSON. It does not accept raw PT, ETL, TTD or
hypervisor packet streams, start a recorder, or authenticate the original sensor.
Use `KnLiveDbg.exe --offline !kmon trace capture.kntrace /limit 64 /json`.
A continuation uses the same file and limit with `/cursor <next_cursor>`.

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
covers the shared artifact reader. These tests validate code and synthetic
imports; they do not validate a real trace decoder, live backend or sensor.
