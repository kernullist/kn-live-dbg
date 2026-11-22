"""Compare SDK interrupt fragments and thread residency with independent Windows TDH records."""
import argparse
from collections import Counter, defaultdict
from copy import deepcopy
import json
from pathlib import Path
import runpy
import struct
import subprocess
import sys
import tempfile

from etl_interrupt_overlap import DPC, ISR, LIMIT, correlate, native_slices
from etl_traceprocessor import CPU_PROGRAM, unpack

WAITS = runpy.run_path(str(Path(__file__).with_name("test-etl-activity-waits.py")))
TDH, PIN, call, pin = (WAITS[k] for k in ("TDH", "PIN", "call", "pin"))


def interrupt_records(oracle, etl):
    output = subprocess.check_output([oracle, etl, "--interrupts"], timeout=240)
    records = list(map(json.loads, output.splitlines()))
    footer = records.pop()
    assert footer["records_seen"] == 1093447 and footer["frequency"] == 10000000 and footer["clock_type"] == 1
    counts = Counter(r["opcode"] for r in records)
    assert counts == {68: 3814, 69: 470, 66: 72, 50: 2123, 67: 288}
    by_cpu = defaultdict(list)
    for r in records:
        if r["opcode"] != 66:  # The pinned SDK table contains ordinary/timer DPCs and ISRs.
            kind = DPC if r["opcode"] in (68, 69) else ISR
            by_cpu[r["cpu"]].append((int(r["initial_qpc"]), int(r["stop_qpc"]), kind))
    parents = {}
    for cpu, intervals in by_cpu.items():
        stack = []
        for lo, hi, kind in sorted(intervals, key=lambda item: (item[0], -item[1])):
            key = (cpu, lo, hi, kind)
            assert lo < hi and key not in parents
            parents[key] = []
            while stack and stack[-1][2] <= lo:
                stack.pop()
            if stack:
                assert hi <= stack[-1][2]
                parents[stack[-1]].append((lo, hi))
            stack.append(key)
    exclusive = {}
    for key, children in parents.items():
        _, start, stop, _ = key
        pieces = []
        for lo, hi in children:
            if start < lo:
                pieces.append((start, lo))
            start = hi
        if start < stop:
            pieces.append((start, stop))
        exclusive[key] = pieces
    assert len(exclusive) == 6695 and sum(len(v) > 1 for v in exclusive.values()) == 89
    return exclusive


def check_fragments(doc, cpus, begin, end, exclusive):
    clk = doc["clock"]
    assert clk["kind"] == "PerformanceCounter" and int(clk["frequency"]) == 10_000_000 and not clk["lost_events"] and not clk["lost_buffers"]
    reference, reference_ns = int(clk["reference_qpc"]), int(clk["reference_ns"])

    def ns(qpc):
        return reference_ns + (qpc-reference)*100

    assert (int(clk["start_ns"]), int(clk["stop_ns"])) == (ns(begin), ns(end))
    assert doc["query_filter"]["processors"] == sorted(cpus)
    assert (doc["dpc_table_rows"], doc["isr_table_rows"], doc["activity_table_rows"]) == (4284, 2411, 6695)
    expected = {}
    for (cpu, lo, hi, kind), pieces in exclusive.items():
        if cpu in cpus:
            for j, (a, b) in enumerate(pieces, 1):
                if max(begin, a) < min(end, b):
                    expected[cpu, kind, ns(lo), ns(hi), j] = (len(pieces), ns(a), ns(b))
    actual = {}
    for f in doc["fragments"]:
        key = (f["cpu"], f["kind"], int(f["parent_start_ns"]), int(f["parent_stop_ns"]), f["fragment"])
        assert key not in actual
        actual[key] = f["fragment_count"], int(f["start_ns"]), int(f["stop_ns"])
    assert actual == expected and len(actual) == doc["matched_fragments"]
    return ns


def check_report(report, markers, bounds, transitions, exclusive):
    a, b = (markers[report[k]] for k in ("requested_start_record", "requested_stop_record"))
    tid, begin, end = a["header_thread_id"], int(a["raw_timestamp"]), int(b["raw_timestamp"])
    _, _, steps = TDH["intervals"](tid, a["record_ordinal"], begin, end, bounds[tid], transitions[tid])
    selected = [(x, y, l, r) for active, x, y, l, r in steps if active]
    result = report["result"]["interrupt_overlap"]
    summary, doc = result["summary"], result["query"]["page"]
    assert result["status"] == "measured"
    ns = check_fragments(doc, {x["cpu"] for x, _, _, _ in selected}, begin, end, exclusive)
    bindings = {x["cpu_slice_row"]: (x["switch_in_record"], x["switch_out_record"]) for x in summary["slice_bindings"]}
    slices = {(s["cpu"], s["start_qpc"], s["stop_qpc"]): s["row"] for s in doc["slices"]}
    coordinates = {(f["cpu"], f["kind"], int(f["parent_start_ns"]), int(f["parent_stop_ns"]), f["fragment"]): f["row"] for f in doc["fragments"]}
    expected, amounts = set(), Counter()
    resident = 0
    for x, y, lo, hi in selected:
        cpu = x["cpu"]
        row = slices.pop((cpu, x["raw_timestamp"], y["raw_timestamp"]))
        assert bindings.pop(row) == (x["record_ordinal"], y["record_ordinal"])
        resident += (hi-lo)*100
        for (processor, start, stop, kind), pieces in exclusive.items():
            if processor != cpu or min(stop, hi) <= max(start, lo):
                continue
            for j, (entry, exit_time) in enumerate(pieces, 1):
                left, right = max(entry, lo), min(exit_time, hi)
                if left < right:
                    parent = coordinates[cpu, kind, ns(start), ns(stop), j]
                    expected.add((row, parent, j, ns(left), ns(right)))
                    amounts[kind] += (right-left)*100
    actual = {(o["cpu_slice_row"], o["interrupt_activity_row"], o["fragment"], int(o["overlap_start_ns"]), int(o["overlap_stop_ns"]))
              for o in summary["overlaps"]}
    assert not slices and not bindings and actual == expected and len(actual) == len(summary["overlaps"])
    assert (int(summary["observed_dpc_ns"]), int(summary["observed_isr_ns"])) == (amounts[DPC], amounts[ISR])
    assert int(summary["residency_ns"]) == resident and int(summary["residency_outside_observed_fragments_ns"]) == resident - sum(amounts.values())
    return amounts[DPC], amounts[ISR]


def projection_controls(report):
    result = report["result"]["interrupt_overlap"]
    doc = result["query"]["page"]
    windows = [p["schedule"]["page"]["activity_schedule"] for p in report["pages"]]
    running = []
    for window in windows:
        native_slices(window, running)

    def outcome(change):
        d = deepcopy(doc)
        change(d)
        try:
            status, summary = correlate(d, PIN, report["source_bytes"], windows[0], 10_000_000, running)
        except (ValueError, KeyError):
            return "invalid"
        assert summary is None
        return status

    assert outcome(lambda d: d["clock"].update(lost_events=1)) == "unqualified_clock_or_loss"
    assert outcome(lambda d: d["clock"].update(frequency="7000003")) == "unqualified_clock_or_loss"
    assert outcome(lambda d: d.update(unresolved_interrupts=1)) == "unplaced_table_rows"
    assert outcome(lambda d: d.update(unresolved_slices=1)) == "unplaced_table_rows"
    assert outcome(lambda d: d.update(fragments=[], matched_fragments=0, activity_table_rows=d["dpc_table_rows"], isr_table_rows=0)) == "interrupt_family_unobserved"
    assert outcome(lambda d: d.update(fragments=[d["fragments"][0]]*LIMIT, matched_fragments=LIMIT+1)) == "row_limit"
    for change in (lambda d: d.update(source_sha256="0"*64), lambda d: d["slices"][0].update(cpu=65535),
                   lambda d: d["clock"].update(reference_ns="1"), lambda d: d["slices"][0].update(tid=0),
                   lambda d: d["slices"][0].update(start_ns=d["slices"][0]["stop_ns"]),
                   lambda d: d["fragments"][0].update(fragment=0), lambda d: d["query_filter"].update(tid=0),
                   lambda d: d["fragments"][0].update(stop_ns=d["fragments"][0]["start_ns"]),
                   lambda d: d["fragments"].__setitem__(1, dict(d["fragments"][0], row=d["fragments"][1]["row"]))):
        assert outcome(change) == "invalid"
    for obj in (report, result["summary"], result["summary"]["slice_bindings"][0], result["summary"]["overlaps"][0],
                doc, doc["clock"], doc["query_filter"], doc["slices"][0], doc["fragments"][0]):
        TDH["require_private"](obj)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("exe", "etl", "oracle", "adapter"):
        parser.add_argument("--" + key, required=True, type=Path)
    args = parser.parse_args()
    exe, etl, oracle, adapter = (p.resolve(strict=True) for p in (args.exe, args.etl, args.oracle, args.adapter))
    assert pin(etl) == PIN
    exclusive = interrupt_records(oracle, etl)
    _, _, groups, _ = WAITS["SCHED"]["ACTIVITY"]["read_oracle"](oracle, etl)
    markers = {r["record_ordinal"]: r for group in groups.values() for r in group}
    _, _, _, bounds, _, transitions = TDH["tdh"](oracle, etl)
    base = [sys.executable, "-B", WAITS["CLI"], "--exe", exe, "--exe-sha256", pin(exe), "--etl", etl, "--sha256", PIN]
    sdk = ["--traceprocessor", adapter, pin(adapter), "--interrupt-overlap"]
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        (root / "wpt" / "Catalog").mkdir(parents=True)
        unpack(adapter, root, cpu=True)
        for i, (a, b) in enumerate(WAITS["WINDOWS"]):
            flags = [*base, "--start", str(a), "--stop", str(b)]
            out = root / f"activity-{i}.json"
            receipt = call([*flags, *sdk, "--output", out], 0)
            assert receipt["interrupt_overlap_status"] == "measured" and receipt["report_sha256"] == pin(out)
            report = json.loads(out.read_bytes())
            amounts = check_report(report, markers, bounds, transitions, exclusive)
            print(a, b, *amounts, flush=True)
            if i == 0:
                projection_controls(report)
                assert call([*flags, *sdk, "--check-report", pin(out)], 0)["status"] == "matched"
                assert call([*flags, *sdk, "--check-report", "0"*64], 1)["status"] == "mismatch"
                small = root / "small.json"
                call([*flags, *sdk, "--page-size", "2", "--output", small], 0)
                assert json.loads(small.read_bytes())["result"]["interrupt_overlap"] == report["result"]["interrupt_overlap"]
                assert call([*flags, "--interrupt-overlap", "--output", root / "missing.json"], 2) is None
                assert call([*flags, *sdk, "--output", out], 2) is None and pin(out) == receipt["report_sha256"]
                TDH["require_private"](receipt)

        # These windows contain nested interrupt handling and also intervening application markers.
        for a, b in ((430650, 430983), (123024, 124132)):
            x, y = markers[a], markers[b]
            out = root / f"intervening-{a}.json"
            call([*base, "--start", str(a), "--stop", str(b), *sdk, "--output", out], 1)
            result = json.loads(out.read_bytes())["result"]
            assert result["reason"] == "intervening_activity_boundary" and result["interrupt_overlap"]["summary"] is None
            doc = call([root / CPU_PROGRAM, etl, "--interrupt-window", str(x["header_process_id"]), str(x["header_thread_id"]),
                        x["raw_timestamp"], y["raw_timestamp"]], 0)
            # Exercise the fragment intersection independently of application marker eligibility.
            tid = x["header_thread_id"]
            _, _, steps = TDH["intervals"](tid, a, int(x["raw_timestamp"]), int(y["raw_timestamp"]), bounds[tid], transitions[tid])
            running = [(u["cpu"], int(u["raw_timestamp"]), int(v["raw_timestamp"]), u["record_ordinal"], v["record_ordinal"])
                       for active, u, v, _, _ in steps if active]
            window = dict(start=x, stop=y)
            status, summary = correlate(doc, PIN, etl.stat().st_size, window, 10_000_000, running)
            assert status == "measured"
            component = dict(requested_start_record=a, requested_stop_record=b, result=dict(
                interrupt_overlap=dict(status=status, summary=summary, query=dict(page=doc))))
            dpc, isr = check_report(component, markers, bounds, transitions, exclusive)
            nested = {f["row"] for f in doc["fragments"] if f["fragment_count"] > 1}
            assert dpc and isr and any(o["interrupt_activity_row"] in nested for o in summary["overlaps"])
            print("CPU interval component", a, b, dpc, isr, flush=True)

        x = markers[339732]
        lo, hi = str(min(k[1] for k in exclusive)), str(max(k[2] for k in exclusive))
        wide = call([root / CPU_PROGRAM, etl, "--interrupt-window", str(x["header_process_id"]), str(x["header_thread_id"]), lo, hi], 0)
        assert wide["matched_fragments"] == sum(map(len, exclusive.values())) == 6804 and len(wide["fragments"]) == LIMIT
        scope = dict(start=dict(x, raw_timestamp=lo), stop=dict(raw_timestamp=hi))
        assert correlate(wide, PIN, etl.stat().st_size, scope, 10_000_000, []) == ("row_limit", None)
        page = json.loads((root / "activity-0.json").read_bytes())["pages"][0]["schedule"]["page"]
        source = etl.read_bytes()
        header = struct.pack("<qqII", 10_000_000, int(page["log_header"]["start_filetime"]), 1, 0)
        assert source[:512].count(header) == 1
        for offset, value in ((16, 2), (20, 1)):
            data = bytearray(source)
            struct.pack_into("<I", data, source[:512].index(header)+offset, value)
            altered = root / "adjusted.etl"
            altered.write_bytes(data)
            out = root / f"limited-{offset}.json"
            flags = list(base)
            flags[flags.index("--etl")+1], flags[flags.index("--sha256")+1] = altered, pin(altered)
            result = call([*flags, "--start", "339732", "--stop", "374019", *sdk, "--output", out], 1)
            assert result["interrupt_overlap_status"] == "native_window_unavailable"
            assert json.loads(out.read_bytes())["result"]["interrupt_overlap"] == dict(query=None, summary=None, status="native_window_unavailable")


if __name__ == "__main__":
    main()
