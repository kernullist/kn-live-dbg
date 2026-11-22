"""Compare fault/disk/file fields and scheduler time against original public ETW records."""
import argparse
from copy import deepcopy
from itertools import pairwise
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile

import etl_fault_io as analysis
from etl_traceprocessor import FILE_RECORD_PROGRAM, unpack

HERE = Path(__file__).resolve().parent
FILE = runpy.run_path(str(HERE / "test-etl-file-operations.py"))
DISK, WAITS, TDH, PIN, call, pin = (FILE[k] for k in ("DISK", "WAITS", "TDH", "PIN", "call", "pin"))
STATES = ("on_cpu", "waiting_before_ready", "ready_to_dispatch", "other_off_cpu")


def original_pairs(oracle, etl, schedule, disks, span, start, stop, result):
    tid = start["header_thread_id"]
    left, right = int(start["raw_timestamp"]), int(stop["raw_timestamp"])
    _, fault_rows, _, bounds, ready, transitions = schedule
    faults = [f for f in fault_rows if f["faulting_thread_id"] == tid and max(left, int(f["initial_time_raw"])) < min(right, int(f["raw_timestamp"]))]
    reads = [(a, b) for a, b in disks[tid] if b["opcode"] == 10 and max(left, int(a["raw_timestamp"])) < min(right, int(b["raw_timestamp"]))]
    s = result["summary"]
    assert s["hard_faults"] == len(faults) and s["disk_reads"] == len(reads)
    lo, hi = span
    if faults:
        hi = max(hi, max(f["record_ordinal"] for f in faults)+1)
    raw = subprocess.check_output([oracle, etl, "--fault-file-window", str(lo), str(hi)], timeout=120)
    *events, footer = [json.loads(line) for line in raw.splitlines()]
    assert footer["records_seen"] == 1093447
    original = {r["record"]: r for r in events}
    pending, files = {}, []
    for e in events:
        if e["op"] == 67:
            assert e["packet"] not in pending
            pending[e["packet"]] = e
        if e["op"] == 76 and e["packet"] in pending:
            files.append((pending.pop(e["packet"]), e))
    actual = {(r["fault_record"], r["disk_init_record"]): r for r in s["comparisons"]}
    assert len(actual) == len(s["comparisons"])
    spans = {key: [] for key in ("disk_overlap_ticks", "matching_disk_ticks", "matching_file_ticks")}
    counted, unpaired = set(), []
    for f in faults:
        fault = original[f["record_ordinal"]]
        TDH["require_private"](fault)
        assert fault["op"] == 32 and (fault["initial"], fault["tick"], fault["offset"], fault["size"], fault["tid"]) == (
            int(f["initial_time_raw"]), int(f["raw_timestamp"]), int(f["read_offset"]), f["byte_count"], tid)
        found = False
        for a, b in reads:
            x = max(left, fault["initial"], int(a["raw_timestamp"]))
            y = min(right, fault["tick"], int(b["raw_timestamp"]))
            if x >= y:
                continue
            found = True
            init, end = (original[v["record_ordinal"]] for v in (a, b))
            c = actual.pop((fault["record"], init["record"]))
            assert c["disk_completion_record"] == end["record"] and init["tid"] == end["tid"] == tid
            assert (int(c["overlap_start_qpc"]), int(c["overlap_stop_qpc"])) == (x, y)
            assert fault["object"] and end["object"] and end["size"] == c["disk_transfer_bytes"]
            equal = fault["object"] == end["object"]
            inside = fault["initial"] <= init["tick"] < end["tick"] <= fault["tick"] and end["record"] < fault["record"]
            match = inside and equal and end["size"] == fault["size"] != 0
            assert c["fault_disk_object_value"] == ("equal" if equal else "different")
            assert c["disk_inside_fault"] == inside and c["disk_read_fields_match"] == match
            counted.add(init["record"])
            spans["disk_overlap_ticks"].append((x, y))
            if match:
                spans["matching_disk_ticks"].append((x, y))
            nested = {r["file_start_record"]: r for r in c["file_reads"]}
            for begin, finish in files:
                if begin["tid"] != tid or not begin["record"] < init["record"] < end["record"] < finish["record"]:
                    continue
                row = nested.pop(begin["record"])
                assert row["file_end_record"] == finish["record"] and finish["status"] == 0 and begin["size"] == finish["extra"]
                address = begin["object"] == fault["object"]
                exact = (begin["offset"], finish["extra"]) == (fault["offset"], fault["size"])
                if not exact:
                    assert begin["offset"]+finish["extra"] <= fault["offset"] or fault["offset"]+fault["size"] <= begin["offset"]
                assert row["file_byte_range"] == ("equal" if exact else "disjoint")
                assert row["fault_file_object_value"] == ("equal" if address else "different")
                file_inside = fault["initial"] <= begin["tick"] < finish["tick"] <= fault["tick"] and finish["record"] < fault["record"]
                file_match = file_inside and address and exact and begin["flags"] & 0x42 == 0x42
                assert row["file_inside_fault"] == file_inside and row["file_read_fields_match"] == file_match
                if file_match:
                    spans["matching_file_ticks"].append((x, y))
            assert not nested
        if not found:
            unpaired.append(fault["record"])
    assert not actual and s["faults_without_disk_overlap"] == unpaired
    fault_spans = [(max(left, int(f["initial_time_raw"])), min(right, int(f["raw_timestamp"]))) for f in faults]
    cuts = sorted({v for pair in fault_spans for v in pair})
    total = sum(y-x for x, y in pairwise(cuts) if any(a <= x < y <= b for a, b in fault_spans))
    assert int(s["fault_union_ticks"]) == total and int(s["fault_ticks_without_disk_read"]) == total-int(s["disk_overlap_ticks"]["total"])
    # All reads intersect a fault in these four windows.
    assert len(counted) == len(reads) and not s["disk_reads_without_fault_overlap"]
    for key, intervals in spans.items():
        expected = dict.fromkeys(STATES, 0)
        for a, b, state, *_ in DISK["scheduler_parts"](start, stop, bounds, ready, transitions):
            points = sorted({a, b, *(v for pair in intervals for v in pair if a < v < b)})
            for x, y in pairwise(points):
                if any(lo <= x < y <= hi for lo, hi in intervals):
                    expected[state] += y-x
        assert {k: int(v) for k, v in s[key].items()} == dict(expected, total=sum(expected.values()))


def controls(report, program, etl):
    x, d, f = (report["result"][key] for key in ("fault_io", "disk_requests", "file_operations"))
    q, native = x["fault_query"], x["native_pages"][0]
    common = report["pages"][0]["schedule"]["page"]
    window = common["activity_schedule"]
    def run(fault=q, saved=native, files=f):
        return analysis.measure(lambda: fault, lambda _: saved, common, window, d, files)
    def live(ns):
        return dict(reader={"exit_code": 0}, page=call([program, etl, PIN, ",".join(map(str, ns)) or "-", "--include-hard-faults"], 0))
    for target, key, value in (("native", "source_sha256", "0"*64), ("native", "decoded_hard_faults", 0),
                               ("fault", "read_offset", "1"), ("fault", "faulting_tid", 0), ("fault", "initial_qpc", "1"),
                               ("disk", "transfer_bytes", 0), ("file", "io_flags", 0), ("file", "file_object_label", None)):
        n = deepcopy(native)
        page = n["page"]
        rows = page["operation_records"]
        target_row = {"native": page, "fault": next(r for r in rows if r["layer"] == "hard_fault"),
                      "disk": next(r for r in rows if r["opcode"] == 10), "file": next(r for r in rows if r["opcode"] == 67)}[target]
        target_row[key] = value
        r = run(saved=n)
        assert r["status"] == "inconsistent_fault_io_evidence" and r["summary"] is None, (key, r["status"])
    for status, context in (("compared", []), ("file_packet_history_unconfirmed", None)):
        files = dict(status=status, summary={"contexts": []} if context is not None else None)
        r = analysis.measure(lambda: q, live, common, window, d, files)
        assert r["status"] == "compared" and r["summary"]["matching_disk_ticks"] == x["summary"]["matching_disk_ticks"]
        assert all(item["file_reads"] == context for item in r["summary"]["comparisons"])
        assert (r["summary"]["matching_file_ticks"] is None) == (context is None)
    empty = dict(status="measured", summary={"requests": [], "overlaps": []}, sdk_query={"page": {"activities": []}})
    r = analysis.measure(lambda: q, live, common, window, empty, dict(status="no_disk_requests", summary={"contexts": []}))
    assert r["summary"]["faults_without_disk_overlap"] == [373241, 373299] and r["summary"]["disk_overlap_ticks"]["total"] == "0"
    bad = deepcopy(q)
    bad["page"]["activity_window"]["thread_evidence"]["before"]["record_ordinal"] += 1
    assert run(fault=bad)["status"] == "inconsistent_fault_io_evidence"
    for private in (x, x["summary"], x["summary"]["disk_overlap_ticks"], x["summary"]["comparisons"][0],
                    x["summary"]["comparisons"][0]["file_reads"][0], native["page"], next(r for r in native["page"]["operation_records"] if r["opcode"] == 32)):
        TDH["require_private"](private)


def arithmetic():
    cases = [(10, 10, 10, 10, "equal"), (10, 10, 12, 5, "file_contains_fault"), (12, 5, 10, 10, "fault_contains_file"),
             (10, 10, 15, 12, "partial_overlap"), (10, 10, 20, 10, "disjoint"), (7, 0, 7, 1, "unavailable"),
             ((1<<64)-1, 1, (1<<64)-1, 1, "equal"), ((1<<64)-1, 2, (1<<64)-1, 1, "unavailable")]
    for a, size, b, count, answer in cases:
        file = dict(file_offset=str(a), actual_bytes=str(size), requested_bytes=str(size), ntstatus=0)
        fault = dict(read_offset=str(b), byte_count=count)
        assert analysis.byte_ranges(file, fault) == answer
        assert analysis.byte_ranges(dict(file, ntstatus=1), fault) == "unavailable"
    pieces = [dict(start_qpc="1", stop_qpc="5", state="on_cpu"), dict(start_qpc="5", stop_qpc="9", state="waiting_before_ready")]
    assert analysis.state_ticks([(2, 5), (2, 5), (4, 7), (7, 8)], pieces) == dict(
        total="6", on_cpu="3", waiting_before_ready="3", ready_to_dispatch="0", other_off_cpu="0")
    f = dict(record_ordinal=1, initial_time_raw="2", raw_timestamp="8")
    d = dict(table_row=1, init_record=2, complete_record=3, start_qpc="3", stop_qpc="5")
    w = dict(start={"raw_timestamp": "1"}, stop={"raw_timestamp": "9"})
    assert analysis.selection([dict(f, initial_time_raw="5")], [d], {}, w)[1:] == ([1], [1])
    partial = dict(f, record_ordinal=3, initial_time_raw="4", raw_timestamp="13")
    long_disk = dict(d, complete_record=4, stop_qpc="16")
    item = analysis.selection([partial], [long_disk], {}, w)[0][0]
    assert item[-1] == (4, 9)
    env = dict(logger_id=1, pointer_bytes=8, issuing_tid=7, packet_label=2, layer="disk")
    native = {2: dict(env, record_ordinal=2, opcode=12, raw_timestamp="3"),
              4: dict(env, record_ordinal=4, opcode=10, raw_timestamp="16", transfer_bytes=4096, file_object_label=3)}
    observed = dict(partial, initial_qpc="4", logger_id=1, pointer_bytes=8, faulting_tid=7, file_object_label=3, byte_count=4096)
    pair = analysis.compare_disk(dict(partial, fault_ordinal=1), observed, long_disk, {"size_bytes": "4096"}, native, item[-1])
    assert not pair["disk_inside_fault"] and pair["disk_read_fields_match"] is False and pair["fault_disk_object_value"] == "equal"
    try:
        analysis.selection([f], [d], {1: [{}]*129}, w)
    except analysis.Unavailable as exc:
        assert str(exc) == "fault_io_comparison_limit"
    else:
        raise AssertionError("comparison limit did not apply")
    work = [(dict(record_ordinal=n), None, None, None) for n in range(1, 134)]
    assert [len(ns) for _, ns in analysis.batches(work)] == [128, 5]


def object_controls(report):
    # Vary only a source-local object value for the two real rows with matching file ranges.
    x, disk, files = (report["result"][k] for k in ("fault_io", "disk_requests", "file_operations"))
    common = report["pages"][0]["schedule"]["page"]
    for mode, disk_match, file_match in (("file", False, True), ("missing", None, None), ("other_width", None, None)):
        q, n = deepcopy(x["fault_query"]), deepcopy(x["native_pages"][0])
        rows = {r["record_ordinal"]: r for r in n["page"]["operation_records"]}
        for c, source in zip(x["summary"]["comparisons"], q["page"]["hard_faults"], strict=True):
            fault = rows[c["fault_record"]]
            assert source["record_ordinal"] == fault["record_ordinal"]
            if mode == "other_width":
                fault["pointer_bytes"] = source["pointer_bytes"] = 4
                fault["file_object_label"] = fault["record_ordinal"]
            else:
                start = rows[c["file_reads"][0]["file_start_record"]]
                fault["file_object_label"] = start["file_object_label"] if mode == "file" else None
        result = analysis.measure(lambda: q, lambda _: n, common, common["activity_schedule"], disk, files)
        s = result["summary"]
        assert result["status"] == "compared" and all(r["disk_read_fields_match"] is disk_match for r in s["comparisons"])
        assert all(r["file_reads"][0]["file_read_fields_match"] is file_match for r in s["comparisons"])
        assert int(s["matching_file_ticks"]["total"]) == (int(s["disk_overlap_ticks"]["total"]) if file_match else 0)
        assert int(s["matching_disk_ticks"]["total"]) == 0


def perfview_faults(oracle, program, traces, exe, options, root):
    pins = ("18e62d477308bdc9b01ca6674cbbcbb7c350acf2bf68733ba6361976fac9538d", "50da7f725f80f88a7622b37f9826844a790cb0c4f64e351fa1f38cf24916889a")
    for path, digest, count, markers in zip(traces, pins, (394, 153), ((122133, 122302), (135036, 135051)), strict=True):
        etl = path.resolve(strict=True)
        assert pin(etl) == digest
        *faults, footer = [json.loads(line) for line in subprocess.check_output([oracle, etl], timeout=120).splitlines()]
        assert len(faults) == count
        for i in range(0, count, 128):
            selected = faults[i:i+128]
            ns = [f["record_ordinal"] for f in selected]
            page = call([program, etl, digest, ",".join(map(str, ns)), "--include-hard-faults"], 0)
            assert page["decoded_hard_faults"] == count and page["records_seen"] == footer["records_seen"]
            assert page["requested_operation_records"] == ns and page["unsupported_hard_fault_records"] == 0
            for r, f in zip(page["operation_records"], selected, strict=True):
                assert r["layer"] == "hard_fault" and r["status"] == "decoded" and r["faulting_tid"] == f["faulting_thread_id"]
                assert r["initial_qpc"] == f["initial_time_raw"] and all(r[k] == f[k] for k in ("record_ordinal", "byte_count", "read_offset", "pointer_bytes", "raw_timestamp"))
        out = root/f"no-switches-{count}.json"
        call([sys.executable, "-B", WAITS["CLI"], "--exe", exe, "--exe-sha256", pin(exe), "--etl", etl, "--sha256", digest,
              "--start", str(markers[0]), "--stop", str(markers[1]), *options, "--output", out], 1)
        result = json.loads(out.read_bytes())["result"]
        observed = result["fault_io"]
        assert result["reason"] == "no_switch_records" and observed["status"] == "native_window_unavailable" and observed["summary"] is None
        fault_page = observed["fault_query"]["page"]
        assert fault_page["decoded_hard_faults"] == count and fault_page["activity_window"]["status"] == "measured"


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("exe", "etl", "oracle", "adapter"):
        p.add_argument("--"+name, type=Path, required=True)
    p.add_argument("--cpu-adapter", type=Path)
    p.add_argument("--perfview", type=Path, nargs=2, metavar=("X86_ETL", "X64_ETL"))
    args = p.parse_args()
    exe, etl, oracle, adapter = (v.resolve(strict=True) for v in (args.exe, args.etl, args.oracle, args.adapter))
    assert pin(etl) == PIN
    arithmetic()
    _, disks = DISK["disk_records"](oracle, etl)
    schedule = TDH["tdh"](oracle, etl)
    _, _, groups, _ = WAITS["SCHED"]["ACTIVITY"]["read_oracle"](oracle, etl)
    markers = {r["record_ordinal"]: r for group in groups.values() for r in group}
    base = [sys.executable, "-B", WAITS["CLI"], "--exe", exe, "--exe-sha256", pin(exe), "--etl", etl, "--sha256", PIN]
    options = ["--disk-requests", adapter, pin(adapter), "--fault-io"]
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root/"wpt"/"Catalog").mkdir(parents=True)
        unpack(adapter, root, disk=True)
        if args.perfview:
            perfview_faults(oracle, root/FILE_RECORD_PROGRAM, args.perfview, exe, options, root)
        for (a, b), span in FILE["WINDOWS"].items():
            query = [*base, "--start", str(a), "--stop", str(b)]
            out = root/f"activity-{a}.json"
            receipt = call([*query, *options, "--output", out], 0)
            report = json.loads(out.read_bytes())
            x = report["result"]["fault_io"]
            assert (report["schema"], receipt["schema"]) == ("kn.etl_activity_waits.v5", "kn.etl_activity_waits_receipt.v5")
            assert receipt["report_sha256"] == pin(out) and receipt["fault_io_status"] == x["status"] == "compared"
            original_pairs(oracle, etl, schedule, disks, span, markers[a], markers[b], x)
            if a == 397312:
                object_controls(report)
            if a != 339732:
                continue
            TDH["require_private"](receipt)
            controls(report, root/FILE_RECORD_PROGRAM, etl)
            assert call([*query, *options, "--check-report", pin(out)], 0)["status"] == "matched"
            assert call([*query, *options, "--check-report", "0"*64], 1)["status"] == "mismatch"
            assert call([*query, *options, "--output", out], 2) is None and pin(out) == receipt["report_sha256"]
            assert call([*query, "--fault-io", "--output", root/"bad.json"], 2) is None and not (root/"bad.json").exists()
            combined = root/"combined.json"
            extra = []
            if args.cpu_adapter:
                cpu = args.cpu_adapter.resolve(strict=True)
                extra = ["--traceprocessor", cpu, pin(cpu), "--interrupt-overlap"]
            r = call([*query, *options, "--file-operations", "--page-size", "2", *extra, "--output", combined], 0)
            assert json.loads(combined.read_bytes())["result"]["fault_io"] == x
            if extra:
                assert r["interrupt_overlap_status"] == "measured" and r["traceprocessor_status"] == "matched"
        for a, b, code, status in ((87258, 87264, 0, "compared"), (726753, 731848, 1, "native_window_unavailable")):
            out = root/f"status-{a}.json"
            receipt = call([*base, "--start", str(a), "--stop", str(b), *options, "--output", out], code)
            x = json.loads(out.read_bytes())["result"]["fault_io"]
            assert receipt["fault_io_status"] == x["status"] == status
            if code:
                assert x["summary"] is None and x["fault_query"]["page"]["activity_window"]["status"] == "intervening_activity_boundary"
                assert not x["native_pages"]
            else:
                assert x["summary"]["hard_faults"] == x["summary"]["disk_reads"] == 0
                assert x["native_pages"][0]["page"]["decoded_hard_faults"] == 17 and x["native_pages"][0]["page"]["operation_records"] == []
    print("Four fault/IO windows matched original records and scheduler partitions. Replay and rejection controls passed.")


if __name__ == "__main__":
    main()
