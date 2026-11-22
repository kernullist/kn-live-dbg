"""Check whole-activity wait accounting against Windows TDH on the public TaskbarLatency recording."""
import argparse
from bisect import bisect_left
from collections import Counter, defaultdict
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import runpy
import struct
import subprocess
import sys
import tempfile
import zipfile

from etl_activity_waits import ActivityWaits
from etl_ready_correspondence import TableBindings, correlate

HERE = Path(__file__).resolve().parent
ORIGIN = runpy.run_path(str(HERE / "test-etl-ready-origin.py"))
SCHED, CAP, PIN = ORIGIN["SCHEDULE"], ORIGIN["CAP"], ORIGIN["PIN"]
TDH = SCHED["SCHED"]
CLI = HERE / "measure-etl-activity-waits.py"
WINDOWS = ((339732, 374019), (738283, 741351), (87669, 105250), (87258, 87264),
           (811857, 812141), (191828, 247898), (117201, 117281))
PARTS = ("thread_wait_ticks", "dpc_wait_ticks", "unattributed_wait_ticks", "other_before_ready_ticks",
         "ready_to_dispatch_ticks", "unclassified_off_cpu_ticks")


def pin(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def call(args, code):
    p = subprocess.run(args, capture_output=True, timeout=240)
    assert p.returncode == code, (p.returncode, p.stdout[:350], p.stderr[-450:])
    return json.loads(p.stdout) if p.stdout else None


def compare(report, start, stop, scheduler):
    footer, switches, bounds, ready, transitions, cpus, cpu_records = scheduler
    tid, n = start["header_thread_id"], start["record_ordinal"]
    _, _, steps = TDH["intervals"](tid, n, int(start["raw_timestamp"]), int(stop["raw_timestamp"]), bounds[tid], transitions[tid])
    pages = report["pages"]
    for page in pages:
        raw = page["schedule"]["page"]
        assert raw["records_seen"] == footer["records_seen"] and raw["decoded_switches"] == len(switches)
        for key, row in (("start", start), ("stop", stop)):
            for k, v in raw["activity_schedule"][key].items():
                assert row[k] == v
    sig = [r for p in pages for r in p["waits"]]
    ints = [r for p in pages for r in p["schedule"]["page"]["activity_schedule"]["intervals"]]
    all_origins = [o for p in pages if p["origins"] for o in p["origins"]["page"]["ready_origins"]]
    origin_by = {o["selected_ready"]["record_ordinal"]: o for o in all_origins}
    assert len(all_origins) == len(origin_by) and len(ints) == len(steps)
    ledger, grouped = Counter(), defaultdict(Counter)
    seen = on_cpu = off_cpu = subset = 0
    for i, (running, a, b, lo, hi) in enumerate(steps):
        assert ints[i]["start"]["record_ordinal"] == a["record_ordinal"] and ints[i]["end"]["record_ordinal"] == b["record_ordinal"]
        if running:
            on_cpu += hi-lo
            continue
        off_cpu += hi-lo
        row = sig[seen]
        seen += 1
        assert row["interval_ordinal"] == i+1
        points = [p for p in ready[tid] if a["record_ordinal"] < p["record_ordinal"] < b["record_ordinal"]]
        measurable = (points and all(not p["ready_flags"] & ~15 and not p["reserved_field"] for p in points)
                      and sum(not (p["ready_flags"] & ~9) for p in points) == 1 and not points[-1]["ready_flags"] & ~9)
        expected = Counter()
        if not measurable:
            expected["unclassified_off_cpu_ticks"] = hi-lo
        else:
            p = points[-1]
            rec, cpu, at = p["record_ordinal"], p["cpu"], int(p["raw_timestamp"])
            origin = origin_by[rec]
            TDH["source_fields"](origin["selected_ready"], p, ORIGIN["READY"])
            assert row["ready_record"] == rec and int(a["raw_timestamp"]) < at < int(b["raw_timestamp"])
            pivot = max(lo, min(at, hi))
            expected["ready_to_dispatch_ticks"] = hi-pivot
            if a["old_state"] != 5:
                label = "other_before_ready_ticks"
            elif p["ready_flags"] & 1:
                label = "dpc_wait_ticks"
                assert row["relationship"] == "dpc_context"
            else:
                k = bisect_left(cpu_records[cpu], rec)
                assert 0 < k < len(cpus[cpu])
                s, e = cpus[cpu][k-1:k+1]
                source = s["new_thread_id"]
                assert e["old_thread_id"] == source and int(s["raw_timestamp"]) < at < int(e["raw_timestamp"])
                low = next((x for x in reversed(bounds[source]) if x["record_ordinal"] < rec), None)
                high = next((x for x in bounds[source] if x["record_ordinal"] > rec), None)
                qualified = (source and source != tid and low and high and low["opcode"] in (1, 3) and high["opcode"] in (2, 4)
                             and low["payload_pid"] == high["payload_pid"] and low["record_ordinal"] < s["record_ordinal"] < e["record_ordinal"] < high["record_ordinal"]
                             and int(low["raw_timestamp"]) < int(s["raw_timestamp"]) < int(e["raw_timestamp"]) < int(high["raw_timestamp"]))
                if qualified:
                    label = "thread_wait_ticks"
                    assert origin["relationship"]["readying_tid"] == source and origin["relationship"]["readying_pid"] == low["payload_pid"]
                    key = (s["logger_id"], source, low["payload_pid"], low["record_ordinal"], high["record_ordinal"])
                    g = grouped[key]
                    g["count"] += 1
                    g["before"] += pivot-lo
                    g["after"] += hi-pivot
                    g.setdefault("first", rec)
                    left, right = max(lo, int(s["raw_timestamp"])), min(at, hi)
                    amount = max(0, right-left)
                    subset += amount
                    g["overlap"] += amount
                    assert int(row["source_running_overlap_ticks"]) == amount
                    assert (row["source_overlap_start_raw"], row["source_overlap_end_raw"]) == ((str(left), str(right)) if amount else (None, None))
                    ORIGIN["switch"](origin["source_cpu_context"]["switch_in"], s, "in")
                    ORIGIN["switch"](origin["source_cpu_context"]["switch_out"], e, "out")
                else:
                    label = "unattributed_wait_ticks"
                    assert origin["relationship"]["readying_tid"] is None
            expected[label] = pivot-lo
        if row["relationship"] != "readying_thread_context":
            assert row["source_running_overlap_ticks"] is None
        for field in PARTS:
            assert int(row[field]) == expected[field], (n, i, field)
        ledger.update(expected)
    result = report["result"]
    summary = result["summary"]
    assert result["status"] == "accounted" and result["reason"] is None and seen == len(sig) == summary["off_cpu_intervals"]
    assert [int(summary[k]) for k in PARTS] == [ledger[k] for k in PARTS]
    assert int(summary["off_cpu_ticks"]) == off_cpu == sum(ledger.values()) and int(summary["on_cpu_ticks"]) == on_cpu
    assert int(summary["window_ticks"]) == on_cpu+off_cpu and int(summary["source_running_overlap_ticks"]) == subset
    assert len(summary["source_lifetimes"]) == len(grouped)
    for g in summary["source_lifetimes"]:
        ref = grouped[tuple(g[k] for k in ("logger_id", "source_tid", "source_pid", "lifetime_start_record", "lifetime_end_record"))]
        assert tuple(int(g[k]) for k in ("ready_transitions", "thread_wait_ticks", "ready_to_dispatch_ticks", "source_running_overlap_ticks", "first_ready_record")) == tuple(ref[k] for k in ("count", "before", "after", "overlap", "first"))
    return ledger


def projection_controls(report):
    page = report["pages"][0]
    origins = page["origins"]["page"]["ready_origins"]
    sdk = page["traceprocessor"]
    assert sdk["status"] == "matched"
    doc = sdk["query"]["page"]
    first = sdk["correspondence"][0]
    assert (first["ready_record"], first["ready_table_rows"], first["activity_table_rows"], first["cpu_slice_rows"]) == (369897, [744], [11385], [2094])

    def confirmed(change):
        copy = deepcopy(doc)
        change(copy)
        return correlate(copy, origins, PIN, report["source_bytes"])[0]["status"] == "matched"

    for change in (lambda d: d.update(source_sha256="0"*64), lambda d: d.update(requested_keys=[]),
                   lambda d: d.update(loaded_processing_modules=["wpt/perfcore.dll"])):
        try:
            confirmed(change)
        except ValueError:
            continue
        raise AssertionError("accepted a different input, filter or CPU runtime")
    bindings = TableBindings()
    matches = sdk["correspondence"]
    bindings.check(doc, origins, matches)
    bindings.check(doc, origins, matches)
    different = deepcopy(origins)
    different[0]["selected_ready"]["record_ordinal"] += 1
    for altered_doc, altered_origins in ((dict(doc, slice_total=1), origins), (doc, different)):
        try:
            bindings.check(altered_doc, altered_origins, matches)
        except ValueError:
            continue
        raise AssertionError("SDK table identity changed across pages")
    assert not confirmed(lambda d: d.update(complete=False))
    assert not confirmed(lambda d: d["cpu_slices"][0].update(switch_out="99"))
    assert not confirmed(lambda d: d["ready_rows"][0].update(source_pid=4))
    assert not confirmed(lambda d: d["cpu_slices"].append(dict(d["cpu_slices"][0], row=1)))
    assert not confirmed(lambda d: d["activity_rows"][0].update(source_exited="1"))

    w = page["schedule"]["page"]["activity_schedule"]
    off = next(i for i in w["intervals"] if i["relation"] == "off_cpu")
    o, r = origins[0], origins[0]["selected_ready"]
    ready_tick = int(r["raw_timestamp"])
    s = int(o["source_cpu_context"]["switch_in"]["raw_timestamp"])
    for lo, hi, expected, position in ((s-20, s-5, 0, "after_overlap"), (s+2, s+7, 5, "after_overlap"),
                                      (ready_tick-3, ready_tick+5, 3, "in_overlap"), (ready_tick+1, ready_tick+8, 0, "before_overlap")):
        agg = ActivityWaits(w)
        projected = agg.wait(off, r, o, lo, hi)
        assert int(projected["source_running_overlap_ticks"]) == expected and projected["ready_position"] == position
        assert sum(int(projected[k]) for k in PARTS) == hi-lo
    for part in (report, report["result"], report["result"]["summary"], report["result"]["summary"]["source_lifetimes"][0],
                 page["waits"][0], first, doc, doc["cpu_slices"][0]):
        TDH["require_private"](part)


def batch_controls(exe, etl, scheduler, folder, openssl):
    flags = ["--etl-switches", etl, "--sha256", PIN]
    ready = sorted(x["record_ordinal"] for rows in scheduler[3].values() for x in rows)
    records = ready[:128]
    numbers = ",".join(map(str, records))
    query = [*flags, "--ready-origins", numbers]
    full, page_pin = SCHED["read"](exe, query)
    assert full["schema"] == "kn.etl_switches.v6" and full["requested_ready_records"] == records and len(full["ready_origins"]) == 128
    for i in (0, 1, 31, 64, 126, 127):
        row = full["ready_origins"][i]
        single, _ = SCHED["read"](exe, [*flags, "--ready-origin", str(records[i])])
        assert row == {k: single[k] for k in row}
    receipt, _ = SCHED["read"](exe, [*query, "--check-page", page_pin])
    assert receipt["page_bytes_match"] and receipt["requested_ready_records"] == records
    if openssl:
        sig = SCHED["ACTIVITY"]["SIGNED"]
        signer = sig["Signer"](openssl, folder/"keys")
        token = folder/"capture.jws"
        token.write_bytes(signer.token(sig["statement"](etl)))
        signed, _ = SCHED["read"](exe, [*query, "--check-page", page_pin, "--capture-statement", token, "archive_witness", signer.point])
        assert signed["capture_statement"]["bound_to_replayed_page"]
    for bad in ("", "0", "1,", ",2", "3,1", "1,1", "01,2", "2,,3", "1,2000001", numbers + "," + str(ready[128])):
        assert not CAP["invoke"](exe, [*flags, "--ready-origins", bad], 2)
    for incompatible in (["--after", "1"], ["--ready-origin", str(records[0])], ["--schedule-activity", "1", "2"]):
        for options in ([*incompatible, "--ready-origins", numbers], ["--ready-origins", numbers, *incompatible]):
            assert not CAP["invoke"](exe, [*flags, *options], 2)
    for values, bad, status in (([1, records[-1]], 1, "not_ready_thread"), ([records[-1], 2000000], 2000000, "ready_record_not_observed")):
        for extra in ([], ["--check-page", page_pin]):
            result, _ = SCHED["read"](exe, [*flags, "--ready-origins", ",".join(map(str, values)), *extra], 1)
            assert result["requested_ready_records"] == values and result["failed_ready_record"] == bad and result["status"] == status


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("exe", "etl", "oracle", "adapter"):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--openssl", type=Path)
    args = p.parse_args()
    etl, exe, oracle, adapter = (x.resolve(strict=True) for x in (args.etl, args.exe, args.oracle, args.adapter))
    assert pin(etl) == PIN
    marker_footer, _, groups, _ = SCHED["ACTIVITY"]["read_oracle"](oracle, etl)
    markers = {r["record_ordinal"]: r for group in groups.values() for r in group}
    footer, _, sw, bounds, ready, trans = TDH["tdh"](oracle, etl)
    assert footer["records_seen"] == marker_footer["records_seen"]
    cpus = defaultdict(list)
    for row in sw:
        cpus[row["cpu"]].append(row)
    sched = footer, sw, bounds, ready, trans, cpus, {k: [r["record_ordinal"] for r in v] for k, v in cpus.items()}
    common = [sys.executable, "-B", CLI, "--exe", exe, "--exe-sha256", pin(exe)]
    optional = ["--traceprocessor", adapter, pin(adapter)]
    all_totals = Counter()
    with tempfile.TemporaryDirectory() as temp:
        folder = Path(temp)
        batch_controls(exe, etl, sched, folder, args.openssl)
        for i, (a, b) in enumerate(WINDOWS):
            flags = [*common, "--etl", etl, "--sha256", PIN, "--start", str(a), "--stop", str(b)]
            path = folder/f"activity-{i}.json"
            receipt = call([*flags, *optional, "--output", path], 0)
            assert receipt["status"] == "written" and receipt["report_sha256"] == pin(path)
            report = json.loads(path.read_bytes())
            ledger = compare(report, markers[a], markers[b], sched)
            all_totals.update(ledger)
            counts = report["result"]["traceprocessor_counts"]
            assert not counts.get("unconfirmed") and sum(counts.values()) == sum(len(pg["origins"]["page"]["ready_origins"]) for pg in report["pages"] if pg["origins"])
            if i == 0:
                projection_controls(report)
                replay = call([*flags, *optional, "--check-report", pin(path)], 0)
                assert replay["status"] == "matched"
                TDH["require_private"](replay)
                filtered = folder/"small.json"
                call([*flags, "--page-size", "2", "--output", filtered], 0)
                small = json.loads(filtered.read_bytes())
                assert small["result"]["summary"] == report["result"]["summary"] and len(small["pages"]) == 6
                mismatch = call([*flags, "--check-report", "0"*64], 1)
                assert mismatch["status"] == "mismatch"
                kept = pin(path)
                call([*flags, "--output", path], 2)
                assert pin(path) == kept
            print(a, b, len(report["pages"]), report["result"]["summary"]["source_running_overlap_ticks"], dict(ledger), counts)
        assert all(all_totals[k] > 0 for k in PARTS)
        source = etl.read_bytes()
        first_page = json.loads((folder/"activity-0.json").read_bytes())["pages"][0]["schedule"]["page"]
        marker = struct.pack("<qqII", int(first_page["clock"]["header_perf_frequency"]), int(first_page["log_header"]["start_filetime"]), 1, 0)
        assert source[:512].count(marker) == 1
        for offset, value, expected in ((16, 2, "clock_unqualified"), (20, 1, "coverage_unqualified")):
            fixed = bytearray(source)
            struct.pack_into("<I", fixed, source[:512].index(marker)+offset, value)
            changed = folder/"adjusted.etl"
            changed.write_bytes(fixed)
            query = [*common, "--etl", changed, "--sha256", pin(changed), "--start", "339732", "--stop", "374019"]
            out = folder/f"limited-{offset}.json"
            receipt = call([*query, "--output", out], 1)
            limited = json.loads(out.read_bytes())["result"]
            assert limited["reason"] == expected and limited["summary"] is None and receipt["activity_waits_status"] == "unavailable"
            assert call([*query, "--check-report", pin(out)], 1)["status"] == "matched"
        for a, b, reason in ((1, 374019, "invalid_start_marker"), (1, 2000000, "activity_record_not_observed")):
            out = folder/f"bad-{b}.json"
            call([*common, "--etl", etl, "--sha256", PIN, "--start", str(a), "--stop", str(b), "--output", out], 1)
            result = json.loads(out.read_bytes())["result"]
            assert result["summary"] is None and result["reason"] == reason
        rejected = folder/"unused.json"
        basic = [*common, "--etl", etl, "--sha256", PIN, "--start", "339732", "--stop", "374019"]
        assert call([*basic, "--page-size", "0", "--output", rejected], 2) is None
        for selected in ("--sha256", "--exe-sha256"):
            wrong = list(basic)
            wrong[wrong.index(selected)+1] = "0"*64
            assert call([*wrong, "--output", rejected], 2) is None
        assert call([*basic, "--traceprocessor", adapter, "0"*64, "--output", rejected], 2) is None
        changed_sdk = folder/"altered-sdk.zip"
        with zipfile.ZipFile(adapter) as original, zipfile.ZipFile(changed_sdk, "w", compression=zipfile.ZIP_DEFLATED) as modified:
            for name in original.namelist():
                data = original.read(name)
                modified.writestr(name, data + b"test" if name == "Microsoft.Windows.EventTracing.Cpu.dll" else data)
        assert call([*basic, "--traceprocessor", changed_sdk, pin(changed_sdk), "--output", rejected], 2) is None
        assert not rejected.exists()
        preserved = pin(changed)
        collision_args = list(basic)
        collision_args[collision_args.index("--etl")+1] = changed
        collision_args[collision_args.index("--sha256")+1] = preserved
        with changed.open("ab") as collision:
            rc = subprocess.run([*collision_args, "--output", rejected], stdout=collision, stderr=subprocess.PIPE, timeout=30)
        assert pin(changed) == preserved
        assert rc.returncode == 2 and not rejected.exists()
        assert pin(etl) == PIN


if __name__ == "__main__":
    main()
