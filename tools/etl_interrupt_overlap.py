"""Intersect exclusive TraceProcessor interrupt fragments with native, thread-bound CPU residency."""
from bisect import bisect_right
from collections import defaultdict

from etl_activity_waits import MAX_RECORDS, tick
from etl_traceprocessor import verify_cpu_modules
from owned_module_benchmark import check, decimal, fields, uint

LIMIT = 2048
DPC, ISR = "DeferredProcedureCall", "InterruptServiceRoutine"
TABLES = ("IInterruptHandlingDataSource.Activity", "IInterruptHandlingDataSource.DeferredProcedureCalls",
          "IInterruptHandlingDataSource.InterruptServiceRoutines")


def native_slices(window, running):
    for interval in window["intervals"]:
        if interval["relation"] == "running_on_cpu" and len(running) <= LIMIT:
            a, b = interval["start"], interval["end"]
            running.append((uint(a["cpu"], 65535), tick(a["raw_timestamp"]), tick(b["raw_timestamp"]),
                            uint(a["record_ordinal"], MAX_RECORDS), uint(b["record_ordinal"], MAX_RECORDS)))


def correlate(doc, pin, size, window, frequency, running):
    fields(doc, "schema source_sha256 source_bytes query_filter loaded_processing_modules clock slice_table_rows activity_table_rows "
           "dpc_table_rows isr_table_rows row_limit matched_slices matched_fragments unresolved_slices unresolved_interrupts slices fragments",
           "interrupt window")
    a, b = window["start"], window["stop"]
    pid, tid = a["header_process_id"], a["header_thread_id"]
    scope = doc["query_filter"]
    fields(scope, "pid tid start_qpc stop_qpc processors", "interrupt filter")
    check(doc["schema"] == "kn.traceprocessor_interrupt_window.v1" and doc["source_sha256"] == pin and
          uint(doc["source_bytes"]) == size and uint(scope["pid"]) == pid and uint(scope["tid"]) == tid and
          (scope["start_qpc"], scope["stop_qpc"]) == (a["raw_timestamp"], b["raw_timestamp"]), "interrupt source or filter mismatch")
    verify_cpu_modules(doc["loaded_processing_modules"])
    check("Microsoft.Windows.EventTracing.Metadata.dll" in doc["loaded_processing_modules"], "missing SDK trace metadata reader")
    clk = doc["clock"]
    fields(clk, "kind reference_qpc reference_ns frequency start_ns stop_ns lost_events lost_buffers", "interrupt clock")
    if (clk["kind"] != "PerformanceCounter" or decimal(clk["frequency"]) != frequency or
            uint(clk["lost_events"]) or uint(clk["lost_buffers"])):
        return "unqualified_clock_or_loss", None
    ref_qpc, ref_ns = tick(clk["reference_qpc"]), tick(clk["reference_ns"])

    def mapped(raw, value):
        qpc, ns = tick(raw), tick(value)
        # Withhold overlap if SDK time cannot be reconciled with the native clock to nanosecond precision.
        check(abs((qpc - ref_qpc) * 1_000_000_000 - (ns - ref_ns) * frequency) < frequency, "incompatible SDK time mapping")
        return ns

    left, right = mapped(scope["start_qpc"], clk["start_ns"]), mapped(scope["stop_qpc"], clk["stop_ns"])
    check(left < right and uint(doc["row_limit"]) == LIMIT, "invalid interrupt query extent")
    slices, fragments = doc["slices"], doc["fragments"]
    total = uint(doc["slice_table_rows"], MAX_RECORDS)
    activities = uint(doc["activity_table_rows"], MAX_RECORDS)
    dpcs, isrs = uint(doc["dpc_table_rows"], activities), uint(doc["isr_table_rows"], activities)
    nslices, nfragments = uint(doc["matched_slices"], total), uint(doc["matched_fragments"])
    check(dpcs + isrs == activities and type(slices) is list and type(fragments) is list and
          len(slices) == min(nslices, LIMIT) and len(fragments) == min(nfragments, LIMIT), "inconsistent interrupt table extent")
    if max(len(running), nslices, nfragments) > LIMIT:
        return "row_limit", None
    if uint(doc["unresolved_slices"]) or uint(doc["unresolved_interrupts"]):
        return "unplaced_table_rows", None
    cpus = sorted({s[0] for s in running})
    check(type(scope["processors"]) is list and [uint(v, 65535) for v in scope["processors"]] == cpus,
          "scheduled processor set differs")
    native = {(cpu, lo, hi): (start, stop) for cpu, lo, hi, start, stop in running}
    check(len(native) == len(running) == nslices, "native and SDK slice counts differ")
    selected = defaultdict(list)
    bindings = []
    resident = last = 0
    for s in slices:
        fields(s, "row cpu pid tid start_qpc stop_qpc start_ns stop_ns", "CPU slice")
        row, cpu = uint(s["row"], total), uint(s["cpu"], 65535)
        start, stop = native.pop((cpu, tick(s["start_qpc"]), tick(s["stop_qpc"])))
        lo, hi = max(left, mapped(s["start_qpc"], s["start_ns"])), min(right, mapped(s["stop_qpc"], s["stop_ns"]))
        check(last < row and lo < hi and uint(s["pid"]) == pid and uint(s["tid"]) == tid, "invalid selected CPU slice")
        bindings.append(dict(cpu_slice_row=row, switch_in_record=start, switch_out_record=stop))
        selected[cpu].append((lo, hi, row))
        resident += hi - lo
        last = row
    ordered = sorted(span for spans in selected.values() for span in spans)
    check(all(first[1] <= second[0] for first, second in zip(ordered, ordered[1:])), "overlapping thread residency")
    ends = {}
    for cpu, spans in selected.items():
        spans.sort()
        ends[cpu] = [hi for lo, hi, row in spans]

    by_cpu = defaultdict(list)
    previous = (0, 0)
    parent = None
    last_stop = None
    for f in fragments:
        fields(f, "row fragment fragment_count cpu kind parent_start_ns parent_stop_ns start_ns stop_ns", "interrupt fragment")
        row, count = uint(f["row"], activities), uint(f["fragment_count"])
        index, cpu, kind = uint(f["fragment"], count), uint(f["cpu"], 65535), f["kind"]
        lo, hi, begin, end = (tick(f[k]) for k in ("start_ns", "stop_ns", "parent_start_ns", "parent_stop_ns"))
        identity = (cpu, kind, begin, end, count)
        check(row and index and previous < (row, index) and (row != previous[0] or (identity == parent and last_stop <= lo)) and
              cpu in selected and kind in (DPC, ISR) and (dpcs if kind == DPC else isrs) and
              begin <= lo < hi <= end and max(left, lo) < min(right, hi), "invalid exclusive interrupt fragment")
        by_cpu[cpu].append((max(left, lo), min(right, hi), row, index, kind))
        previous, parent, last_stop = (row, index), identity, hi
    if not dpcs or not isrs:
        return "interrupt_family_unobserved", None
    amounts = {DPC: 0, ISR: 0}
    overlap = []
    for cpu in sorted(by_cpu):
        previous_end = left
        for lo, hi, row, index, kind in sorted(by_cpu[cpu]):
            check(previous_end <= lo, "exclusive interrupt fragments overlap on one CPU")
            previous_end = hi
            spans = selected[cpu]
            pos = bisect_right(ends[cpu], lo)
            while pos < len(spans) and spans[pos][0] < hi:
                start, stop, slice_row = spans[pos]
                begin, end = max(start, lo), min(stop, hi)
                amounts[kind] += end - begin
                overlap.append(dict(cpu_slice_row=slice_row, interrupt_activity_row=row, fragment=index,
                                    overlap_start_ns=str(begin), overlap_stop_ns=str(end)))
                pos += 1
    outside = resident - sum(amounts.values())
    check(outside >= 0, "interrupt overlap exceeds residency")
    return "measured", dict(residency_ns=str(resident), observed_dpc_ns=str(amounts[DPC]), observed_isr_ns=str(amounts[ISR]),
                            residency_outside_observed_fragments_ns=str(outside), slice_bindings=bindings, overlaps=overlap)
